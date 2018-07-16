/*
 *
 *  Wireless daemon for Linux
 *
 *  Copyright (C) 2013-2014  Intel Corporation. All rights reserved.
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2.1 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdlib.h>
#include <linux/rtnetlink.h>
#include <net/if_arp.h>
#include <linux/if.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <arpa/inet.h>
#include <linux/filter.h>
#include <sys/socket.h>
#include <errno.h>
#include <fnmatch.h>

#include <ell/ell.h>

#include "linux/nl80211.h"

#include "src/iwd.h"
#include "src/wiphy.h"
#include "src/ie.h"
#include "src/mpdu.h"
#include "src/eapol.h"
#include "src/handshake.h"
#include "src/crypto.h"
#include "src/device.h"
#include "src/scan.h"
#include "src/netdev.h"
#include "src/wscutil.h"
#include "src/ftutil.h"
#include "src/util.h"
#include "src/watchlist.h"

#ifndef ENOTSUPP
#define ENOTSUPP 524
#endif

struct netdev_handshake_state {
	struct handshake_state super;
	uint32_t pairwise_new_key_cmd_id;
	uint32_t group_new_key_cmd_id;
	uint32_t group_management_new_key_cmd_id;
	uint32_t set_station_cmd_id;
	struct netdev *netdev;
};

struct netdev {
	uint32_t index;
	char name[IFNAMSIZ];
	uint32_t type;
	uint8_t addr[ETH_ALEN];
	struct device *device;
	struct wiphy *wiphy;
	unsigned int ifi_flags;
	uint32_t frequency;

	netdev_event_func_t event_filter;
	netdev_connect_cb_t connect_cb;
	netdev_disconnect_cb_t disconnect_cb;
	netdev_neighbor_report_cb_t neighbor_report_cb;
	void *user_data;
	struct eapol_sm *sm;
	struct handshake_state *handshake;
	uint32_t connect_cmd_id;
	uint32_t disconnect_cmd_id;
	enum netdev_result result;
	struct l_timeout *neighbor_report_timeout;
	struct l_timeout *sa_query_timeout;
	uint16_t sa_query_id;
	uint8_t prev_bssid[ETH_ALEN];
	int8_t rssi_levels[16];
	uint8_t rssi_levels_num;
	uint8_t cur_rssi_level_idx;
	int8_t cur_rssi;
	struct l_timeout *rssi_poll_timeout;
	uint32_t rssi_poll_cmd_id;

	struct watchlist event_watches;

	struct watchlist frame_watches;

	struct l_io *pae_io;  /* for drivers without EAPoL over NL80211 */

	bool connected : 1;
	bool operational : 1;
	bool rekey_offload_support : 1;
	bool pae_over_nl80211 : 1;
	bool in_ft : 1;
	bool cur_rssi_low : 1;
	bool use_4addr : 1;
};

struct netdev_preauth_state {
	netdev_preauthenticate_cb_t cb;
	void *user_data;
	struct netdev *netdev;
};

struct netdev_watch {
	uint32_t id;
	netdev_watch_func_t callback;
	void *user_data;
};

struct netdev_frame_watch {
	uint16_t frame_type;
	uint8_t *prefix;
	size_t prefix_len;
	struct watchlist_item super;
};

static struct l_netlink *rtnl = NULL;
static struct l_genl_family *nl80211;
static struct l_queue *netdev_list;
static char **whitelist_filter;
static char **blacklist_filter;

static void do_debug(const char *str, void *user_data)
{
	const char *prefix = user_data;

	l_info("%s%s", prefix, str);
}

static void netdev_handshake_state_free(struct handshake_state *hs)
{
	struct netdev_handshake_state *nhs =
			container_of(hs, struct netdev_handshake_state, super);

	if (nhs->pairwise_new_key_cmd_id) {
		l_genl_family_cancel(nl80211, nhs->pairwise_new_key_cmd_id);
		nhs->pairwise_new_key_cmd_id = 0;
	}

	if (nhs->group_new_key_cmd_id) {
		l_genl_family_cancel(nl80211, nhs->group_new_key_cmd_id);
		nhs->group_new_key_cmd_id = 0;
	}

	if (nhs->group_management_new_key_cmd_id) {
		l_genl_family_cancel(nl80211,
					nhs->group_management_new_key_cmd_id);
		nhs->group_management_new_key_cmd_id = 0;
	}

	if (nhs->set_station_cmd_id) {
		l_genl_family_cancel(nl80211, nhs->set_station_cmd_id);
		nhs->set_station_cmd_id = 0;
	}

	l_free(nhs);
}

struct handshake_state *netdev_handshake_state_new(struct netdev *netdev)
{
	struct netdev_handshake_state *nhs;

	nhs = l_new(struct netdev_handshake_state, 1);

	nhs->super.ifindex = netdev->index;
	nhs->super.free = netdev_handshake_state_free;

	nhs->netdev = netdev;

	return &nhs->super;
}

struct cb_data {
	netdev_command_func_t callback;
	void *user_data;
};

struct wiphy *netdev_get_wiphy(struct netdev *netdev)
{
	return netdev->wiphy;
}

static void netlink_result(int error, uint16_t type, const void *data,
			uint32_t len, void *user_data)
{
	struct cb_data *cb_data = user_data;

	if (!cb_data)
		return;

	cb_data->callback(error < 0 ? false : true, cb_data->user_data);
}

static size_t rta_add_u8(void *rta_buf, unsigned short type, uint8_t value)
{
	struct rtattr *rta = rta_buf;

	rta->rta_len = RTA_LENGTH(sizeof(uint8_t));
	rta->rta_type = type;
	*((uint8_t *) RTA_DATA(rta)) = value;

	return RTA_SPACE(sizeof(uint8_t));
}

static void netdev_set_linkmode_and_operstate(uint32_t ifindex,
				uint8_t linkmode, uint8_t operstate,
				netdev_command_func_t callback, void *user_data)
{
	struct ifinfomsg *rtmmsg;
	void *rta_buf;
	size_t bufsize;
	struct cb_data *cb_data = NULL;

	bufsize = NLMSG_ALIGN(sizeof(struct ifinfomsg)) +
		RTA_SPACE(sizeof(uint8_t)) + RTA_SPACE(sizeof(uint8_t));

	rtmmsg = l_malloc(bufsize);
	memset(rtmmsg, 0, bufsize);

	rtmmsg->ifi_family = AF_UNSPEC;
	rtmmsg->ifi_index = ifindex;

	rta_buf = (void *) rtmmsg + NLMSG_ALIGN(sizeof(struct ifinfomsg));

	rta_buf += rta_add_u8(rta_buf, IFLA_LINKMODE, linkmode);
	rta_buf += rta_add_u8(rta_buf, IFLA_OPERSTATE, operstate);

	if (callback) {
		cb_data = l_new(struct cb_data, 1);
		cb_data->callback = callback;
		cb_data->user_data = user_data;
	}

	l_netlink_send(rtnl, RTM_SETLINK, 0, rtmmsg,
					rta_buf - (void *) rtmmsg,
					netlink_result, cb_data, l_free);

	l_free(rtmmsg);
}

const uint8_t *netdev_get_address(struct netdev *netdev)
{
	return netdev->addr;
}

uint32_t netdev_get_ifindex(struct netdev *netdev)
{
	return netdev->index;
}

enum netdev_iftype netdev_get_iftype(struct netdev *netdev)
{
	switch (netdev->type) {
	case NL80211_IFTYPE_STATION:
		return NETDEV_IFTYPE_STATION;
	case NL80211_IFTYPE_AP:
		return NETDEV_IFTYPE_AP;
	case NL80211_IFTYPE_ADHOC:
		return NETDEV_IFTYPE_ADHOC;
	default:
		/* cant really do much here */
		l_error("invalid iftype %u", netdev->type);
		return NETDEV_IFTYPE_STATION;
	}
}

const char *netdev_get_name(struct netdev *netdev)
{
	return netdev->name;
}

bool netdev_get_is_up(struct netdev *netdev)
{
	return (netdev->ifi_flags & IFF_UP) != 0;
}

struct handshake_state *netdev_get_handshake(struct netdev *netdev)
{
	return netdev->handshake;
}

struct set_powered_cb_data {
	struct netdev *netdev;
	netdev_set_powered_cb_t callback;
	void *user_data;
	l_netlink_destroy_func_t destroy;
};

static void netdev_set_powered_result(int error, uint16_t type,
					const void *data,
					uint32_t len, void *user_data)
{
	struct set_powered_cb_data *cb_data = user_data;

	if (!cb_data)
		return;

	cb_data->callback(cb_data->netdev, error, cb_data->user_data);
}

static void netdev_set_powered_destroy(void *user_data)
{
	struct set_powered_cb_data *cb_data = user_data;

	if (!cb_data)
		return;

	if (cb_data->destroy)
		cb_data->destroy(cb_data->user_data);

	l_free(cb_data);
}

int netdev_set_powered(struct netdev *netdev, bool powered,
			netdev_set_powered_cb_t callback, void *user_data,
			netdev_destroy_func_t destroy)
{
	struct ifinfomsg *rtmmsg;
	size_t bufsize;
	struct set_powered_cb_data *cb_data = NULL;

	bufsize = NLMSG_ALIGN(sizeof(struct ifinfomsg));

	rtmmsg = l_malloc(bufsize);
	memset(rtmmsg, 0, bufsize);

	rtmmsg->ifi_family = AF_UNSPEC;
	rtmmsg->ifi_index = netdev->index;
	rtmmsg->ifi_change = 0xffffffff;
	rtmmsg->ifi_flags = powered ? (netdev->ifi_flags | IFF_UP) :
		(netdev->ifi_flags & ~IFF_UP);

	if (callback) {
		cb_data = l_new(struct set_powered_cb_data, 1);
		cb_data->netdev = netdev;
		cb_data->callback = callback;
		cb_data->user_data = user_data;
		cb_data->destroy = destroy;
	}

	l_netlink_send(rtnl, RTM_SETLINK, 0, rtmmsg, bufsize,
			netdev_set_powered_result, cb_data,
			netdev_set_powered_destroy);

	l_free(rtmmsg);

	return 0;
}

static void netdev_set_rssi_level_idx(struct netdev *netdev)
{
	uint8_t new_level;

	for (new_level = 0; new_level < netdev->rssi_levels_num; new_level++)
		if (netdev->cur_rssi >= netdev->rssi_levels[new_level])
			break;

	netdev->cur_rssi_level_idx = new_level;
}

static void netdev_rssi_poll_cb(struct l_genl_msg *msg, void *user_data)
{
	struct netdev *netdev = user_data;
	struct l_genl_attr attr, nested;
	uint16_t type, len;
	const void *data;
	bool found;
	uint8_t prev_rssi_level_idx = netdev->cur_rssi_level_idx;

	netdev->rssi_poll_cmd_id = 0;

	if (!l_genl_attr_init(&attr, msg))
		goto done;

	found = false;
	while (l_genl_attr_next(&attr, &type, &len, &data)) {
		if (type != NL80211_ATTR_STA_INFO)
			continue;

		found = true;
		break;
	}

	if (!found || !l_genl_attr_recurse(&attr, &nested))
		goto done;

	found = false;
	while (l_genl_attr_next(&nested, &type, &len, &data)) {
		if (type != NL80211_STA_INFO_SIGNAL_AVG)
			continue;

		if (len != 1)
			continue;

		found = true;
		netdev->cur_rssi = *(const int8_t *) data;
		break;
	}

	if (!found)
		goto done;

	/*
	 * Note we don't have to handle LOW_SIGNAL_THRESHOLD here.  The
	 * CQM single threshold RSSI monitoring should work even if the
	 * kernel driver doesn't support multiple thresholds.  So the
	 * polling only handles the client-supplied threshold list.
	 */
	netdev_set_rssi_level_idx(netdev);
	if (netdev->cur_rssi_level_idx != prev_rssi_level_idx)
		netdev->event_filter(netdev, NETDEV_EVENT_RSSI_LEVEL_NOTIFY,
					netdev->user_data);

done:
	/* Rearm timer */
	l_timeout_modify(netdev->rssi_poll_timeout, 6);
}

static void netdev_rssi_poll(struct l_timeout *timeout, void *user_data)
{
	struct netdev *netdev = user_data;
	struct l_genl_msg *msg;

	msg = l_genl_msg_new_sized(NL80211_CMD_GET_STATION, 64);
	l_genl_msg_append_attr(msg, NL80211_ATTR_IFINDEX, 4, &netdev->index);
	l_genl_msg_append_attr(msg, NL80211_ATTR_MAC, ETH_ALEN,
							netdev->handshake->aa);

	netdev->rssi_poll_cmd_id = l_genl_family_send(nl80211, msg,
							netdev_rssi_poll_cb,
							netdev, NULL);
}

/* To be called whenever operational or rssi_levels_num are updated */
static void netdev_rssi_polling_update(struct netdev *netdev)
{
	if (wiphy_has_ext_feature(netdev->wiphy,
					NL80211_EXT_FEATURE_CQM_RSSI_LIST))
		return;

	if (netdev->operational && netdev->rssi_levels_num > 0) {
		if (netdev->rssi_poll_timeout)
			return;

		netdev->rssi_poll_timeout =
			l_timeout_create(1, netdev_rssi_poll, netdev, NULL);
	} else {
		if (!netdev->rssi_poll_timeout)
			return;

		l_timeout_remove(netdev->rssi_poll_timeout);
		netdev->rssi_poll_timeout = NULL;

		if (netdev->rssi_poll_cmd_id) {
			l_genl_family_cancel(nl80211, netdev->rssi_poll_cmd_id);
			netdev->rssi_poll_cmd_id = 0;
		}
	}
}

static void netdev_linkmode_dormant_cb(bool success, void *user_data)
{
	struct netdev *netdev = user_data;

	l_debug("netdev: %d, success: %d", netdev->index, success);
}

static void netdev_preauth_destroy(void *data)
{
	struct netdev_preauth_state *state = data;

	if (state->cb)
		state->cb(state->netdev, NETDEV_RESULT_ABORTED, NULL,
				state->user_data);

	l_free(state);
}

static void netdev_connect_free(struct netdev *netdev)
{
	if (netdev->sm) {
		eapol_sm_free(netdev->sm);
		netdev->sm = NULL;
	}

	eapol_preauth_cancel(netdev->index);

	if (netdev->handshake) {
		handshake_state_free(netdev->handshake);
		netdev->handshake = NULL;
	}

	if (netdev->neighbor_report_cb) {
		netdev->neighbor_report_cb(netdev, -ENOTCONN, NULL, 0,
						netdev->user_data);
		netdev->neighbor_report_cb = NULL;
		l_timeout_remove(netdev->neighbor_report_timeout);
	}

	if (netdev->sa_query_timeout) {
		l_timeout_remove(netdev->sa_query_timeout);
		netdev->sa_query_timeout = NULL;
	}

	netdev->operational = false;
	netdev->connected = false;
	netdev->connect_cb = NULL;
	netdev->event_filter = NULL;
	netdev->user_data = NULL;
	netdev->result = NETDEV_RESULT_OK;
	netdev->in_ft = false;

	netdev_rssi_polling_update(netdev);

	if (netdev->connect_cmd_id) {
		l_genl_family_cancel(nl80211, netdev->connect_cmd_id);
		netdev->connect_cmd_id = 0;
	} else if (netdev->disconnect_cmd_id) {
		l_genl_family_cancel(nl80211, netdev->disconnect_cmd_id);
		netdev->disconnect_cmd_id = 0;
	}
}

static void netdev_connect_failed(struct l_genl_msg *msg, void *user_data)
{
	struct netdev *netdev = user_data;
	netdev_connect_cb_t connect_cb = netdev->connect_cb;
	netdev_event_func_t event_filter = netdev->event_filter;
	void *connect_data = netdev->user_data;
	enum netdev_result result = netdev->result;

	netdev->disconnect_cmd_id = 0;

	/* Done this way to allow re-entrant netdev_connect calls */
	netdev_connect_free(netdev);

	if (connect_cb)
		connect_cb(netdev, result, connect_data);
	else if (event_filter)
		event_filter(netdev, NETDEV_EVENT_DISCONNECT_BY_SME,
				connect_data);
}

static void netdev_free(void *data)
{
	struct netdev *netdev = data;

	l_debug("Freeing netdev %s[%d]", netdev->name, netdev->index);

	if (netdev->neighbor_report_cb) {
		netdev->neighbor_report_cb(netdev, -ENODEV, NULL, 0,
						netdev->user_data);
		netdev->neighbor_report_cb = NULL;
		l_timeout_remove(netdev->neighbor_report_timeout);
	}

	if (netdev->connected)
		netdev_connect_free(netdev);
	else if (netdev->disconnect_cmd_id) {
		l_genl_family_cancel(nl80211, netdev->disconnect_cmd_id);
		netdev->disconnect_cmd_id = 0;

		if (netdev->disconnect_cb)
			netdev->disconnect_cb(netdev, true, netdev->user_data);

		netdev->disconnect_cb = NULL;
		netdev->user_data = NULL;
	}

	device_remove(netdev->device);
	watchlist_destroy(&netdev->event_watches);
	watchlist_destroy(&netdev->frame_watches);

	l_io_destroy(netdev->pae_io);

	l_free(netdev);
}

static void netdev_shutdown_one(void *data, void *user_data)
{
	struct netdev *netdev = data;

	if (netdev_get_iftype(netdev) == NETDEV_IFTYPE_AP)
		netdev_set_iftype(netdev, NETDEV_IFTYPE_STATION);

	if (netdev_get_is_up(netdev))
		netdev_set_powered(netdev, false, NULL, NULL, NULL);
}

static bool netdev_match(const void *a, const void *b)
{
	const struct netdev *netdev = a;
	uint32_t ifindex = L_PTR_TO_UINT(b);

	return (netdev->index == ifindex);
}

struct netdev *netdev_find(int ifindex)
{
	return l_queue_find(netdev_list, netdev_match, L_UINT_TO_PTR(ifindex));
}

static void netdev_lost_beacon(struct netdev *netdev)
{
	if (!netdev->connected)
		return;

	if (netdev->event_filter)
		netdev->event_filter(netdev, NETDEV_EVENT_LOST_BEACON,
							netdev->user_data);
}

/* -70 dBm is a popular choice for low signal threshold for roaming */
#define LOW_SIGNAL_THRESHOLD	-70

static void netdev_cqm_event_rssi_threshold(struct netdev *netdev,
						uint32_t rssi_event)
{
	int event;

	if (!netdev->connected)
		return;

	if (rssi_event != NL80211_CQM_RSSI_THRESHOLD_EVENT_LOW &&
			rssi_event != NL80211_CQM_RSSI_THRESHOLD_EVENT_HIGH)
		return;

	if (!netdev->event_filter)
		return;

	netdev->cur_rssi_low =
		(rssi_event == NL80211_CQM_RSSI_THRESHOLD_EVENT_LOW);
	event = netdev->cur_rssi_low ? NETDEV_EVENT_RSSI_THRESHOLD_LOW :
		NETDEV_EVENT_RSSI_THRESHOLD_HIGH;

	netdev->event_filter(netdev, event, netdev->user_data);
}

static void netdev_rssi_level_init(struct netdev *netdev)
{
	if (netdev->connected && netdev->rssi_levels_num)
		netdev_set_rssi_level_idx(netdev);
}

static void netdev_cqm_event_rssi_value(struct netdev *netdev, int rssi_val)
{
	bool new_rssi_low;
	uint8_t prev_rssi_level_idx = netdev->cur_rssi_level_idx;

	if (!netdev->connected)
		return;

	if (rssi_val > 127)
		rssi_val = 127;
	else if (rssi_val < -127)
		rssi_val = -127;

	netdev->cur_rssi = rssi_val;

	if (!netdev->event_filter)
		return;

	new_rssi_low = rssi_val < LOW_SIGNAL_THRESHOLD;
	if (netdev->cur_rssi_low != new_rssi_low) {
		int event = new_rssi_low ?
			NETDEV_EVENT_RSSI_THRESHOLD_LOW :
			NETDEV_EVENT_RSSI_THRESHOLD_HIGH;

		netdev->cur_rssi_low = new_rssi_low;
		netdev->event_filter(netdev, event, netdev->user_data);
	}

	if (!netdev->rssi_levels_num)
		return;

	netdev_set_rssi_level_idx(netdev);
	if (netdev->cur_rssi_level_idx != prev_rssi_level_idx)
		netdev->event_filter(netdev, NETDEV_EVENT_RSSI_LEVEL_NOTIFY,
					netdev->user_data);
}

static void netdev_cqm_event(struct l_genl_msg *msg, struct netdev *netdev)
{
	struct l_genl_attr attr;
	struct l_genl_attr nested;
	uint16_t type, len;
	const void *data;
	uint32_t *rssi_event = NULL;
	int32_t *rssi_val = NULL;

	if (!l_genl_attr_init(&attr, msg))
		return;

	while (l_genl_attr_next(&attr, &type, &len, &data)) {
		switch (type) {
		case NL80211_ATTR_CQM:
			if (!l_genl_attr_recurse(&attr, &nested))
				return;

			while (l_genl_attr_next(&nested, &type, &len, &data)) {
				switch (type) {
				case NL80211_ATTR_CQM_BEACON_LOSS_EVENT:
					netdev_lost_beacon(netdev);
					break;

				case NL80211_ATTR_CQM_RSSI_THRESHOLD_EVENT:
					if (len != 4)
						continue;

					rssi_event = (uint32_t *) data;
					break;

				case NL80211_ATTR_CQM_RSSI_LEVEL:
					if (len != 4)
						continue;

					rssi_val = (int32_t *) data;
					break;
				}
			}

			break;
		}
	}

	if (rssi_event) {
		if (rssi_val)
			netdev_cqm_event_rssi_value(netdev, *rssi_val);
		else
			netdev_cqm_event_rssi_threshold(netdev, *rssi_event);
	}
}

static void netdev_rekey_offload_event(struct l_genl_msg *msg,
					struct netdev *netdev)
{
	struct l_genl_attr attr;
	struct l_genl_attr nested;
	uint16_t type, len;
	const void *data;
	uint64_t replay_ctr;

	if (!l_genl_attr_init(&attr, msg))
		return;

	while (l_genl_attr_next(&attr, &type, &len, &data)) {
		if (type != NL80211_ATTR_REKEY_DATA)
			continue;

		if (!l_genl_attr_recurse(&attr, &nested))
			return;

		while (l_genl_attr_next(&nested, &type, &len, &data)) {
			if (type != NL80211_REKEY_DATA_REPLAY_CTR)
				continue;

			if (len != sizeof(uint64_t)) {
				l_warn("Invalid replay_ctr");
				return;
			}

			replay_ctr = *((uint64_t *) data);
			__eapol_update_replay_counter(netdev->index,
							netdev->addr,
							netdev->handshake->aa,
							replay_ctr);
			return;
		}
	}
}

static void netdev_disconnect_event(struct l_genl_msg *msg,
							struct netdev *netdev)
{
	struct l_genl_attr attr;
	uint16_t type, len;
	const void *data;
	uint16_t reason_code = 0;
	bool disconnect_by_ap = false;
	netdev_event_func_t event_filter;
	void *event_data;

	l_debug("");

	if (!netdev->connected || netdev->disconnect_cmd_id > 0 ||
			netdev->in_ft)
		return;

	if (!l_genl_attr_init(&attr, msg)) {
		l_error("attr init failed");
		return;
	}

	while (l_genl_attr_next(&attr, &type, &len, &data)) {
		switch (type) {
		case NL80211_ATTR_REASON_CODE:
			if (len != sizeof(uint16_t))
				l_warn("Invalid reason code attribute");
			else
				reason_code = *((uint16_t *) data);

			break;

		case NL80211_ATTR_DISCONNECTED_BY_AP:
			disconnect_by_ap = true;
			break;
		}
	}

	l_info("Received Deauthentication event, reason: %hu, from_ap: %s",
			reason_code, disconnect_by_ap ? "true" : "false");

	event_filter = netdev->event_filter;
	event_data = netdev->user_data;
	netdev_connect_free(netdev);

	if (!event_filter)
		return;

	if (disconnect_by_ap)
		event_filter(netdev, NETDEV_EVENT_DISCONNECT_BY_AP,
							event_data);
	else
		event_filter(netdev, NETDEV_EVENT_DISCONNECT_BY_SME,
							event_data);
}

static void netdev_cmd_disconnect_cb(struct l_genl_msg *msg, void *user_data)
{
	struct netdev *netdev = user_data;
	void *disconnect_data;
	netdev_disconnect_cb_t disconnect_cb;
	bool r;

	netdev->disconnect_cmd_id = 0;

	if (!netdev->disconnect_cb) {
		netdev->user_data = NULL;
		return;
	}

	disconnect_data = netdev->user_data;
	disconnect_cb = netdev->disconnect_cb;
	netdev->user_data = NULL;
	netdev->disconnect_cb = NULL;

	if (l_genl_msg_get_error(msg) < 0)
		r = false;
	else
		r = true;

	disconnect_cb(netdev, r, disconnect_data);
}

static struct l_genl_msg *netdev_build_cmd_disconnect(struct netdev *netdev,
							uint16_t reason_code)
{
	struct l_genl_msg *msg;

	msg = l_genl_msg_new_sized(NL80211_CMD_DISCONNECT, 64);
	l_genl_msg_append_attr(msg, NL80211_ATTR_IFINDEX, 4, &netdev->index);
	l_genl_msg_append_attr(msg, NL80211_ATTR_REASON_CODE, 2, &reason_code);

	return msg;
}

static void netdev_deauthenticate_event(struct l_genl_msg *msg,
							struct netdev *netdev)
{
	l_debug("");
}

static struct l_genl_msg *netdev_build_cmd_deauthenticate(struct netdev *netdev,
							uint16_t reason_code)
{
	struct l_genl_msg *msg;

	msg = l_genl_msg_new_sized(NL80211_CMD_DEAUTHENTICATE, 128);
	l_genl_msg_append_attr(msg, NL80211_ATTR_IFINDEX, 4, &netdev->index);
	l_genl_msg_append_attr(msg, NL80211_ATTR_REASON_CODE, 2, &reason_code);
	l_genl_msg_append_attr(msg, NL80211_ATTR_MAC, ETH_ALEN,
							netdev->handshake->aa);

	return msg;
}

static struct l_genl_msg *netdev_build_cmd_del_station(struct netdev *netdev,
							const uint8_t *sta,
							uint16_t reason_code,
							bool disassociate)
{
	struct l_genl_msg *msg;
	uint8_t subtype = disassociate ?
			MPDU_MANAGEMENT_SUBTYPE_DISASSOCIATION :
			MPDU_MANAGEMENT_SUBTYPE_DEAUTHENTICATION;

	msg = l_genl_msg_new_sized(NL80211_CMD_DEL_STATION, 64);
	l_genl_msg_append_attr(msg, NL80211_ATTR_IFINDEX, 4, &netdev->index);
	l_genl_msg_append_attr(msg, NL80211_ATTR_MAC, 6, sta);
	l_genl_msg_append_attr(msg, NL80211_ATTR_MGMT_SUBTYPE, 1, &subtype);
	l_genl_msg_append_attr(msg, NL80211_ATTR_REASON_CODE, 2, &reason_code);

	return msg;
}

static void netdev_del_sta_cb(struct l_genl_msg *msg, void *user_data)
{
	if (l_genl_msg_get_error(msg) < 0)
		l_error("DEL_STATION failed: %i", l_genl_msg_get_error(msg));
}

int netdev_del_station(struct netdev *netdev, const uint8_t *sta,
			uint16_t reason_code, bool disassociate)
{
	struct l_genl_msg *msg;

	msg = netdev_build_cmd_del_station(netdev, sta, reason_code,
						disassociate);

	if (!l_genl_family_send(nl80211, msg, netdev_del_sta_cb, NULL, NULL))
		return -EIO;

	return 0;
}

static void netdev_operstate_cb(bool success, void *user_data)
{
	struct netdev *netdev = user_data;

	l_debug("netdev: %d, success: %d", netdev->index, success);
}

static void netdev_connect_ok(struct netdev *netdev)
{
	netdev_set_linkmode_and_operstate(netdev->index, IF_LINK_MODE_DORMANT,
						IF_OPER_UP, netdev_operstate_cb,
						netdev);

	netdev->operational = true;

	if (netdev->connect_cb) {
		netdev->connect_cb(netdev, NETDEV_RESULT_OK, netdev->user_data);
		netdev->connect_cb = NULL;
	}

	netdev_rssi_polling_update(netdev);
}

static void netdev_setting_keys_failed(struct netdev_handshake_state *nhs,
							uint16_t reason_code)
{
	struct netdev *netdev = nhs->netdev;
	struct l_genl_msg *msg;

	/*
	 * Something went wrong with our sequence:
	 * 1. new_key(ptk)
	 * 2. new_key(gtk) [optional]
	 * 3. new_key(igtk) [optional]
	 * 4. set_station
	 *
	 * Cancel all pending commands, then de-authenticate
	 */
	l_genl_family_cancel(nl80211, nhs->pairwise_new_key_cmd_id);
	nhs->pairwise_new_key_cmd_id = 0;

	l_genl_family_cancel(nl80211, nhs->group_new_key_cmd_id);
	nhs->group_new_key_cmd_id = 0;

	l_genl_family_cancel(nl80211, nhs->group_management_new_key_cmd_id);
	nhs->group_management_new_key_cmd_id = 0;

	l_genl_family_cancel(nl80211, nhs->set_station_cmd_id);
	nhs->set_station_cmd_id = 0;

	netdev->result = NETDEV_RESULT_KEY_SETTING_FAILED;

	handshake_event(&nhs->super, HANDSHAKE_EVENT_SETTING_KEYS_FAILED, NULL);

	switch (netdev->type) {
	case NL80211_IFTYPE_STATION:
		msg = netdev_build_cmd_disconnect(netdev, reason_code);
		netdev->disconnect_cmd_id = l_genl_family_send(nl80211, msg,
							netdev_connect_failed,
							netdev, NULL);
		break;
	case NL80211_IFTYPE_AP:
		msg = netdev_build_cmd_del_station(netdev, nhs->super.spa,
				reason_code, false);
		if (!l_genl_family_send(nl80211, msg, NULL, NULL, NULL))
			l_error("error sending DEL_STATION");
	}
}

static void netdev_set_station_cb(struct l_genl_msg *msg, void *user_data)
{
	struct netdev_handshake_state *nhs = user_data;
	struct netdev *netdev = nhs->netdev;
	int err;

	nhs->set_station_cmd_id = 0;

	if (!netdev->connected)
		return;

	err = l_genl_msg_get_error(msg);
	if (err == -ENOTSUPP)
		goto done;

	if (err < 0) {
		l_error("Set Station failed for ifindex %d", netdev->index);
		netdev_setting_keys_failed(nhs,
						MMPDU_REASON_CODE_UNSPECIFIED);
		return;
	}

	handshake_event(&nhs->super, HANDSHAKE_EVENT_COMPLETE, NULL);

done:
	netdev_connect_ok(netdev);
}

static struct l_genl_msg *netdev_build_cmd_set_station(struct netdev *netdev,
							const uint8_t *sta)
{
	struct l_genl_msg *msg;
	struct nl80211_sta_flag_update flags;

	flags.mask = 1 << NL80211_STA_FLAG_AUTHORIZED;
	flags.set = flags.mask;

	msg = l_genl_msg_new_sized(NL80211_CMD_SET_STATION, 512);

	l_genl_msg_append_attr(msg, NL80211_ATTR_IFINDEX, 4, &netdev->index);
	l_genl_msg_append_attr(msg, NL80211_ATTR_MAC, ETH_ALEN, sta);
	l_genl_msg_append_attr(msg, NL80211_ATTR_STA_FLAGS2,
				sizeof(struct nl80211_sta_flag_update), &flags);

	return msg;
}

static void netdev_new_group_key_cb(struct l_genl_msg *msg, void *data)
{
	struct netdev_handshake_state *nhs = data;
	struct netdev *netdev = nhs->netdev;

	nhs->group_new_key_cmd_id = 0;

	if (l_genl_msg_get_error(msg) >= 0)
		return;

	l_error("New Key for Group Key failed for ifindex: %d", netdev->index);
	netdev_setting_keys_failed(nhs, MMPDU_REASON_CODE_UNSPECIFIED);
}

static void netdev_new_group_management_key_cb(struct l_genl_msg *msg,
					void *data)
{
	struct netdev_handshake_state *nhs = data;
	struct netdev *netdev = nhs->netdev;

	nhs->group_management_new_key_cmd_id = 0;

	if (l_genl_msg_get_error(msg) < 0) {
		l_error("New Key for Group Mgmt failed for ifindex: %d",
				netdev->index);
		netdev_setting_keys_failed(nhs, MMPDU_REASON_CODE_UNSPECIFIED);
	}
}

static struct l_genl_msg *netdev_build_cmd_new_key_group(struct netdev *netdev,
					uint32_t cipher, uint8_t key_id,
					const uint8_t *key, size_t key_len,
					const uint8_t *ctr, size_t ctr_len)
{
	struct l_genl_msg *msg;

	msg = l_genl_msg_new_sized(NL80211_CMD_NEW_KEY, 512);

	l_genl_msg_append_attr(msg, NL80211_ATTR_KEY_DATA, key_len, key);
	l_genl_msg_append_attr(msg, NL80211_ATTR_KEY_CIPHER, 4, &cipher);
	l_genl_msg_append_attr(msg, NL80211_ATTR_KEY_SEQ, ctr_len, ctr);

	l_genl_msg_enter_nested(msg, NL80211_ATTR_KEY_DEFAULT_TYPES);
	l_genl_msg_append_attr(msg, NL80211_KEY_DEFAULT_TYPE_MULTICAST,
				0, NULL);
	l_genl_msg_leave_nested(msg);

	l_genl_msg_append_attr(msg, NL80211_ATTR_KEY_IDX, 1, &key_id);
	l_genl_msg_append_attr(msg, NL80211_ATTR_IFINDEX, 4, &netdev->index);

	return msg;
}

static bool netdev_copy_tk(uint8_t *tk_buf, const uint8_t *tk,
				uint32_t cipher, bool authenticator)
{
	switch (cipher) {
	case CRYPTO_CIPHER_CCMP:
		/*
		 * 802.11-2016 12.8.3 Mapping PTK to CCMP keys:
		 * "A STA shall use the temporal key as the CCMP key
		 * for MPDUs between the two communicating STAs."
		 */
		memcpy(tk_buf, tk, 16);
		break;
	case CRYPTO_CIPHER_TKIP:
		/*
		 * 802.11-2016 12.8.1 Mapping PTK to TKIP keys:
		 * "A STA shall use bits 0-127 of the temporal key as its
		 * input to the TKIP Phase 1 and Phase 2 mixing functions.
		 *
		 * A STA shall use bits 128-191 of the temporal key as
		 * the michael key for MSDUs from the Authenticator's STA
		 * to the Supplicant's STA.
		 *
		 * A STA shall use bits 192-255 of the temporal key as
		 * the michael key for MSDUs from the Supplicant's STA
		 * to the Authenticator's STA."
		 */
		if (authenticator) {
			memcpy(tk_buf + NL80211_TKIP_DATA_OFFSET_ENCR_KEY,
					tk, 16);
			memcpy(tk_buf + NL80211_TKIP_DATA_OFFSET_TX_MIC_KEY,
					tk + 16, 8);
			memcpy(tk_buf + NL80211_TKIP_DATA_OFFSET_RX_MIC_KEY,
					tk + 24, 8);
		} else {
			memcpy(tk_buf + NL80211_TKIP_DATA_OFFSET_ENCR_KEY,
					tk, 16);
			memcpy(tk_buf + NL80211_TKIP_DATA_OFFSET_RX_MIC_KEY,
					tk + 16, 8);
			memcpy(tk_buf + NL80211_TKIP_DATA_OFFSET_TX_MIC_KEY,
					tk + 24, 8);
		}
		break;
	default:
		l_error("Unexpected cipher: %x", cipher);
		return false;
	}

	return true;
}

static void netdev_set_gtk(struct handshake_state *hs, uint8_t key_index,
				const uint8_t *gtk, uint8_t gtk_len,
				const uint8_t *rsc, uint8_t rsc_len,
				uint32_t cipher)
{
	struct netdev_handshake_state *nhs =
			container_of(hs, struct netdev_handshake_state, super);
	struct netdev *netdev = nhs->netdev;
	uint8_t gtk_buf[32];
	struct l_genl_msg *msg;

	l_debug("%d", netdev->index);

	if (crypto_cipher_key_len(cipher) != gtk_len) {
		l_error("Unexpected key length: %d", gtk_len);
		netdev_setting_keys_failed(nhs,
					MMPDU_REASON_CODE_INVALID_GROUP_CIPHER);
		return;
	}

	if (!netdev_copy_tk(gtk_buf, gtk, cipher, false)) {
		netdev_setting_keys_failed(nhs,
					MMPDU_REASON_CODE_INVALID_GROUP_CIPHER);
		return;
	}

	msg = netdev_build_cmd_new_key_group(netdev, cipher, key_index,
						gtk_buf, gtk_len,
						rsc, rsc_len);
	nhs->group_new_key_cmd_id =
		l_genl_family_send(nl80211, msg, netdev_new_group_key_cb,
						nhs, NULL);

	if (nhs->group_new_key_cmd_id > 0)
		return;

	l_genl_msg_unref(msg);
	netdev_setting_keys_failed(nhs, MMPDU_REASON_CODE_UNSPECIFIED);
}

static void netdev_set_igtk(struct handshake_state *hs, uint8_t key_index,
				const uint8_t *igtk, uint8_t igtk_len,
				const uint8_t *ipn, uint8_t ipn_len,
				uint32_t cipher)
{
	struct netdev_handshake_state *nhs =
			container_of(hs, struct netdev_handshake_state, super);
	uint8_t igtk_buf[16];
	struct netdev *netdev = nhs->netdev;
	struct l_genl_msg *msg;

	l_debug("%d", netdev->index);

	if (crypto_cipher_key_len(cipher) != igtk_len) {
		l_error("Unexpected key length: %d", igtk_len);
		netdev_setting_keys_failed(nhs,
					MMPDU_REASON_CODE_INVALID_GROUP_CIPHER);
		return;
	}

	switch (cipher) {
	case CRYPTO_CIPHER_BIP:
		memcpy(igtk_buf, igtk, 16);
		break;
	default:
		l_error("Unexpected cipher: %x", cipher);
		netdev_setting_keys_failed(nhs,
					MMPDU_REASON_CODE_INVALID_GROUP_CIPHER);
		return;
	}

	msg = netdev_build_cmd_new_key_group(netdev, cipher, key_index,
						igtk_buf, igtk_len,
						ipn, ipn_len);
	nhs->group_management_new_key_cmd_id =
			l_genl_family_send(nl80211, msg,
				netdev_new_group_management_key_cb,
				nhs, NULL);

	if (nhs->group_management_new_key_cmd_id > 0)
		return;

	l_genl_msg_unref(msg);
	netdev_setting_keys_failed(nhs, MMPDU_REASON_CODE_UNSPECIFIED);
}

static void netdev_new_pairwise_key_cb(struct l_genl_msg *msg, void *data)
{
	struct netdev_handshake_state *nhs = data;
	struct netdev *netdev = nhs->netdev;
	const uint8_t *addr = (netdev->type == NL80211_IFTYPE_STATION) ?
			nhs->super.aa : nhs->super.spa;

	nhs->pairwise_new_key_cmd_id = 0;

	if (l_genl_msg_get_error(msg) < 0) {
		l_error("New Key for Pairwise Key failed for ifindex: %d",
					netdev->index);
		goto error;
	}

	/*
	 * Set the AUTHORIZED flag using a SET_STATION command even if
	 * we're already operational, it will not hurt during re-keying
	 * and is necessary after an FT.
	 */
	msg = netdev_build_cmd_set_station(netdev, addr);

	nhs->set_station_cmd_id =
		l_genl_family_send(nl80211, msg, netdev_set_station_cb,
					nhs, NULL);
	if (nhs->set_station_cmd_id > 0)
		return;

	l_genl_msg_unref(msg);
error:
	netdev_setting_keys_failed(nhs, MMPDU_REASON_CODE_UNSPECIFIED);
}

static struct l_genl_msg *netdev_build_cmd_new_key_pairwise(
							struct netdev *netdev,
							uint32_t cipher,
							const uint8_t *aa,
							const uint8_t *tk,
							size_t tk_len)
{
	uint8_t key_id = 0;
	struct l_genl_msg *msg;

	msg = l_genl_msg_new_sized(NL80211_CMD_NEW_KEY, 512);

	l_genl_msg_append_attr(msg, NL80211_ATTR_KEY_DATA, tk_len, tk);
	l_genl_msg_append_attr(msg, NL80211_ATTR_KEY_CIPHER, 4, &cipher);
	l_genl_msg_append_attr(msg, NL80211_ATTR_MAC, ETH_ALEN, aa);
	l_genl_msg_append_attr(msg, NL80211_ATTR_KEY_IDX, 1, &key_id);
	l_genl_msg_append_attr(msg, NL80211_ATTR_IFINDEX, 4, &netdev->index);

	return msg;
}

static void netdev_set_tk(struct handshake_state *hs,
				const uint8_t *tk, uint32_t cipher)
{
	struct netdev_handshake_state *nhs =
			container_of(hs, struct netdev_handshake_state, super);
	uint8_t tk_buf[32];
	struct netdev *netdev = nhs->netdev;
	struct l_genl_msg *msg;
	enum mmpdu_reason_code rc;
	const uint8_t *addr = (netdev->type == NL80211_IFTYPE_STATION) ?
			nhs->super.aa : nhs->super.spa;

	l_debug("%d", netdev->index);

	rc = MMPDU_REASON_CODE_INVALID_PAIRWISE_CIPHER;
	if (!netdev_copy_tk(tk_buf, tk, cipher, false))
		goto invalid_key;

	rc = MMPDU_REASON_CODE_UNSPECIFIED;
	msg = netdev_build_cmd_new_key_pairwise(netdev, cipher, addr, tk_buf,
						crypto_cipher_key_len(cipher));
	nhs->pairwise_new_key_cmd_id =
		l_genl_family_send(nl80211, msg, netdev_new_pairwise_key_cb,
						nhs, NULL);
	if (nhs->pairwise_new_key_cmd_id > 0)
		return;

	l_genl_msg_unref(msg);
invalid_key:
	netdev_setting_keys_failed(nhs, rc);
}

void netdev_handshake_failed(struct handshake_state *hs, uint16_t reason_code)
{
	struct netdev_handshake_state *nhs =
			container_of(hs, struct netdev_handshake_state, super);
	struct netdev *netdev = nhs->netdev;
	struct l_genl_msg *msg;

	l_error("4-Way handshake failed for ifindex: %d, reason: %u",
				netdev->index, reason_code);

	netdev->sm = NULL;

	netdev->result = NETDEV_RESULT_HANDSHAKE_FAILED;

	switch (netdev->type) {
	case NL80211_IFTYPE_STATION:
		msg = netdev_build_cmd_disconnect(netdev, reason_code);
		netdev->disconnect_cmd_id = l_genl_family_send(nl80211, msg,
							netdev_connect_failed,
							netdev, NULL);
		break;
	case NL80211_IFTYPE_AP:
		msg = netdev_build_cmd_del_station(netdev, nhs->super.spa,
				reason_code, false);
		if (!l_genl_family_send(nl80211, msg, NULL, NULL, NULL))
			l_error("error sending DEL_STATION");
	}
}

static void hardware_rekey_cb(struct l_genl_msg *msg, void *data)
{
	struct netdev *netdev = data;
	int err;

	err = l_genl_msg_get_error(msg);
	if (err < 0) {
		if (err == -EOPNOTSUPP) {
			l_error("hardware_rekey not supported");
			netdev->rekey_offload_support = false;
		}
	}
}

static struct l_genl_msg *netdev_build_cmd_replay_counter(struct netdev *netdev,
					const uint8_t *kek,
					const uint8_t *kck,
					uint64_t replay_ctr)
{
	struct l_genl_msg *msg;

	msg = l_genl_msg_new_sized(NL80211_CMD_SET_REKEY_OFFLOAD, 512);

	l_genl_msg_append_attr(msg, NL80211_ATTR_IFINDEX, 4, &netdev->index);

	l_genl_msg_enter_nested(msg, NL80211_ATTR_REKEY_DATA);
	l_genl_msg_append_attr(msg, NL80211_REKEY_DATA_KEK,
					NL80211_KEK_LEN, kek);
	l_genl_msg_append_attr(msg, NL80211_REKEY_DATA_KCK,
					NL80211_KCK_LEN, kck);
	l_genl_msg_append_attr(msg, NL80211_REKEY_DATA_REPLAY_CTR,
			NL80211_REPLAY_CTR_LEN, &replay_ctr);

	l_genl_msg_leave_nested(msg);

	return msg;
}

static void netdev_set_rekey_offload(uint32_t ifindex,
					const uint8_t *kek,
					const uint8_t *kck,
					uint64_t replay_counter,
					void *user_data)
{
	struct netdev *netdev;
	struct l_genl_msg *msg;

	netdev = netdev_find(ifindex);
	if (!netdev)
		return;

	if (netdev->type != NL80211_IFTYPE_STATION)
		return;

	if (!netdev->rekey_offload_support)
		return;

	l_debug("%d", netdev->index);
	msg = netdev_build_cmd_replay_counter(netdev, kek, kck,
					replay_counter);
	l_genl_family_send(nl80211, msg, hardware_rekey_cb, netdev, NULL);

}

/*
 * Handle the Association Response IE contents either as part of an
 * FT initial Mobility Domain association (12.4) or a Fast Transition
 * (12.8.5).
 */
static bool netdev_handle_associate_resp_ies(struct handshake_state *hs,
					const uint8_t *rsne, const uint8_t *mde,
					const uint8_t *fte, bool transition)
{
	const uint8_t *sent_mde = hs->mde;
	bool is_rsn = hs->own_ie != NULL;

	/*
	 * During a transition in an RSN, check for an RSNE containing the
	 * PMK-R1-Name and the remaining fields same as in the advertised
	 * RSNE.
	 *
	 * 12.8.5: "The RSNE shall be present only if dot11RSNAActivated is
	 * true. If present, the RSNE shall be set as follows:
	 * — Version field shall be set to 1.
	 * — PMKID Count field shall be set to 1.
	 * — PMKID field shall contain the PMKR1Name
	 * — All other fields shall be identical to the contents of the RSNE
	 *   advertised by the target AP in Beacon and Probe Response frames."
	 */
	if (transition && is_rsn) {
		struct ie_rsn_info msg4_rsne;

		if (!rsne)
			return false;

		if (ie_parse_rsne_from_data(rsne, rsne[1] + 2,
						&msg4_rsne) < 0)
			return false;

		if (msg4_rsne.num_pmkids != 1 ||
				memcmp(msg4_rsne.pmkids, hs->pmk_r1_name, 16))
			return false;

		if (!handshake_util_ap_ie_matches(rsne, hs->ap_ie, false))
			return false;
	} else {
		if (rsne)
			return false;
	}

	/* An MD IE identical to the one we sent must be present */
	if (sent_mde && (!mde || memcmp(sent_mde, mde, sent_mde[1] + 2)))
		return false;

	/*
	 * An FT IE is required in an initial mobility domain
	 * association and re-associations in an RSN but not present
	 * in a non-RSN (12.4.2 vs. 12.4.3).
	 */
	if (sent_mde && is_rsn && !fte)
		return false;
	if (!(sent_mde && is_rsn) && fte)
		return false;

	if (fte) {
		struct ie_ft_info ft_info;

		if (ie_parse_fast_bss_transition_from_data(fte, fte[1] + 2,
								&ft_info) < 0)
			return false;

		/* Validate the FTE contents */
		if (transition) {
			/*
			 * In an RSN, check for an FT IE with the same
			 * R0KH-ID, R1KH-ID, ANonce and SNonce that we
			 * received in message 2, MIC Element Count
			 * of 6 and the correct MIC.
			 */
			uint8_t mic[16];

			if (!ft_calculate_fte_mic(hs, 6, rsne, fte, NULL, mic))
				return false;

			if (ft_info.mic_element_count != 3 ||
					memcmp(ft_info.mic, mic, 16))
				return false;

			if (hs->r0khid_len != ft_info.r0khid_len ||
					memcmp(hs->r0khid, ft_info.r0khid,
						hs->r0khid_len) ||
					!ft_info.r1khid_present ||
					memcmp(hs->r1khid, ft_info.r1khid, 6))
				return false;

			if (memcmp(ft_info.anonce, hs->anonce, 32))
				return false;

			if (memcmp(ft_info.snonce, hs->snonce, 32))
				return false;

			if (ft_info.gtk_len) {
				uint8_t gtk[32];

				if (!handshake_decode_fte_key(hs, ft_info.gtk,
								ft_info.gtk_len,
								gtk))
					return false;

				if (ft_info.gtk_rsc[6] != 0x00 ||
						ft_info.gtk_rsc[7] != 0x00)
					return false;

				handshake_state_install_gtk(hs,
							ft_info.gtk_key_id,
							gtk, ft_info.gtk_len,
							ft_info.gtk_rsc, 6);
			}

			if (ft_info.igtk_len) {
				uint8_t igtk[16];

				if (!handshake_decode_fte_key(hs, ft_info.igtk,
							ft_info.igtk_len, igtk))
					return false;

				handshake_state_install_igtk(hs,
							ft_info.igtk_key_id,
							igtk, ft_info.igtk_len,
							ft_info.igtk_ipn);
			}
		} else {
			/* Initial MD association */

			uint8_t zeros[32] = {};

			handshake_state_set_fte(hs, fte);

			/*
			 * 12.4.2: "The FTE shall have a MIC information
			 * element count of zero (i.e., no MIC present)
			 * and have ANonce, SNonce, and MIC fields set to 0."
			 */
			if (ft_info.mic_element_count != 0 ||
					memcmp(ft_info.mic, zeros, 16) ||
					memcmp(ft_info.anonce, zeros, 32) ||
					memcmp(ft_info.snonce, zeros, 32))
				return false;

			handshake_state_set_kh_ids(hs, ft_info.r0khid,
							ft_info.r0khid_len,
							ft_info.r1khid);
		}
	}

	return true;
}

static void netdev_connect_event(struct l_genl_msg *msg,
							struct netdev *netdev)
{
	struct l_genl_attr attr;
	uint16_t type, len;
	const void *data;
	const uint16_t *status_code = NULL;
	const uint8_t *ies = NULL;
	size_t ies_len;
	const uint8_t *rsne = NULL;
	const uint8_t *mde = NULL;
	const uint8_t *fte = NULL;

	l_debug("");

	if (!netdev->connected) {
		l_warn("Unexpected connection related event -- "
				"is another supplicant running?");
		return;
	}

	if (!l_genl_attr_init(&attr, msg)) {
		l_debug("attr init failed");
		goto error;
	}

	while (l_genl_attr_next(&attr, &type, &len, &data)) {
		switch (type) {
		case NL80211_ATTR_TIMED_OUT:
			l_warn("authentication timed out");
			goto error;
		case NL80211_ATTR_STATUS_CODE:
			if (len == sizeof(uint16_t))
				status_code = data;

			break;
		case NL80211_ATTR_RESP_IE:
			ies = data;
			ies_len = len;
			break;
		}
	}

	/* AP Rejected the authenticate / associate */
	if (!status_code || *status_code != 0)
		goto error;

	/* Check 802.11r IEs */
	if (ies) {
		struct ie_tlv_iter iter;

		ie_tlv_iter_init(&iter, ies, ies_len);

		while (ie_tlv_iter_next(&iter)) {
			switch (ie_tlv_iter_get_tag(&iter)) {
			case IE_TYPE_RSN:
				if (rsne)
					goto error;

				rsne = ie_tlv_iter_get_data(&iter) - 2;
				break;

			case IE_TYPE_MOBILITY_DOMAIN:
				if (mde)
					goto error;

				mde = ie_tlv_iter_get_data(&iter) - 2;
				break;

			case IE_TYPE_FAST_BSS_TRANSITION:
				if (fte)
					goto error;

				fte = ie_tlv_iter_get_data(&iter) - 2;
				break;
			}
		}
	}

	if (!netdev_handle_associate_resp_ies(netdev->handshake, rsne, mde, fte,
						netdev->in_ft))
		goto error;

	if (netdev->sm) {
		/*
		 * Start processing EAPoL frames now that the state machine
		 * has all the input data even in FT mode.
		 */
		if (!eapol_start(netdev->sm))
			goto error;

		if (!netdev->in_ft)
			return;
	}

	if (netdev->in_ft) {
		bool is_rsn = netdev->handshake->own_ie != NULL;

		netdev->in_ft = false;

		if (is_rsn) {
			handshake_state_install_ptk(netdev->handshake);
			return;
		}
	}

	netdev_connect_ok(netdev);

	return;

error:
	netdev->result = NETDEV_RESULT_ASSOCIATION_FAILED;
	netdev_connect_failed(NULL, netdev);
}

/*
 * Build an FT Reassociation Request frame according to 12.5.2 / 12.5.4:
 * RSN or non-RSN Over-the-air FT Protocol, and with the IE contents
 * according to 12.8.4: FT authentication sequence: contents of third message.
 */
static struct l_genl_msg *netdev_build_cmd_ft_reassociate(struct netdev *netdev,
						uint32_t frequency,
						const uint8_t *prev_bssid)
{
	struct l_genl_msg *msg;
	struct iovec iov[3];
	int iov_elems = 0;
	struct handshake_state *hs = netdev_get_handshake(netdev);
	bool is_rsn = hs->own_ie != NULL;
	uint8_t *rsne = NULL;

	msg = l_genl_msg_new_sized(NL80211_CMD_ASSOCIATE, 600);
	l_genl_msg_append_attr(msg, NL80211_ATTR_IFINDEX, 4, &netdev->index);
	l_genl_msg_append_attr(msg, NL80211_ATTR_WIPHY_FREQ, 4, &frequency);
	l_genl_msg_append_attr(msg, NL80211_ATTR_MAC, ETH_ALEN, hs->aa);
	l_genl_msg_append_attr(msg, NL80211_ATTR_PREV_BSSID, ETH_ALEN,
				prev_bssid);
	l_genl_msg_append_attr(msg, NL80211_ATTR_SSID, hs->ssid_len, hs->ssid);
	l_genl_msg_append_attr(msg, NL80211_ATTR_SOCKET_OWNER, 0, NULL);

	if (is_rsn) {
		uint32_t nl_cipher;
		uint32_t nl_akm;
		uint32_t wpa_version;
		struct ie_rsn_info rsn_info;

		if (hs->pairwise_cipher == IE_RSN_CIPHER_SUITE_CCMP)
			nl_cipher = CRYPTO_CIPHER_CCMP;
		else
			nl_cipher = CRYPTO_CIPHER_TKIP;

		l_genl_msg_append_attr(msg, NL80211_ATTR_CIPHER_SUITES_PAIRWISE,
					4, &nl_cipher);

		if (hs->group_cipher == IE_RSN_CIPHER_SUITE_CCMP)
			nl_cipher = CRYPTO_CIPHER_CCMP;
		else
			nl_cipher = CRYPTO_CIPHER_TKIP;

		l_genl_msg_append_attr(msg, NL80211_ATTR_CIPHER_SUITE_GROUP,
					4, &nl_cipher);

		if (hs->mfp) {
			uint32_t use_mfp = NL80211_MFP_REQUIRED;
			l_genl_msg_append_attr(msg, NL80211_ATTR_USE_MFP,
								4, &use_mfp);
		}

		if (hs->akm_suite == IE_RSN_AKM_SUITE_FT_OVER_8021X)
			nl_akm = CRYPTO_AKM_FT_OVER_8021X;
		else
			nl_akm = CRYPTO_AKM_FT_USING_PSK;

		l_genl_msg_append_attr(msg, NL80211_ATTR_AKM_SUITES,
							4, &nl_akm);

		wpa_version = NL80211_WPA_VERSION_2;
		l_genl_msg_append_attr(msg, NL80211_ATTR_WPA_VERSIONS,
						4, &wpa_version);

		l_genl_msg_append_attr(msg, NL80211_ATTR_CONTROL_PORT, 0, NULL);

		/*
		 * Rebuild the RSNE to include the PMKR1Name and append
		 * MDE + FTE.
		 *
		 * 12.8.4: "If present, the RSNE shall be set as follows:
		 * — Version field shall be set to 1.
		 * — PMKID Count field shall be set to 1.
		 * — PMKID field shall contain the PMKR1Name.
		 * — All other fields shall be as specified in 8.4.2.27
		 *   and 11.5.3."
		 */
		if (ie_parse_rsne_from_data(hs->own_ie, hs->own_ie[1] + 2,
						&rsn_info) < 0)
			goto error;

		rsn_info.num_pmkids = 1;
		rsn_info.pmkids = hs->pmk_r1_name;

		rsne = alloca(256);
		ie_build_rsne(&rsn_info, rsne);

		iov[iov_elems].iov_base = rsne;
		iov[iov_elems].iov_len = rsne[1] + 2;
		iov_elems += 1;
	}

	/* The MDE advertised by the BSS must be passed verbatim */
	iov[iov_elems].iov_base = (void *) hs->mde;
	iov[iov_elems].iov_len = hs->mde[1] + 2;
	iov_elems += 1;

	if (is_rsn) {
		struct ie_ft_info ft_info;
		uint8_t *fte;

		/*
		 * 12.8.4: "If present, the FTE shall be set as follows:
		 * — ANonce, SNonce, R0KH-ID, and R1KH-ID shall be set to
		 *   the values contained in the second message of this
		 *   sequence.
		 * — The Element Count field of the MIC Control field shall
		 *   be set to the number of elements protected in this
		 *   frame (variable).
		 * [...]
		 * — All other fields shall be set to 0."
		 */

		memset(&ft_info, 0, sizeof(ft_info));

		ft_info.mic_element_count = 3;
		memcpy(ft_info.r0khid, hs->r0khid, hs->r0khid_len);
		ft_info.r0khid_len = hs->r0khid_len;
		memcpy(ft_info.r1khid, hs->r1khid, 6);
		ft_info.r1khid_present = true;
		memcpy(ft_info.anonce, hs->anonce, 32);
		memcpy(ft_info.snonce, hs->snonce, 32);

		fte = alloca(256);
		ie_build_fast_bss_transition(&ft_info, fte);

		if (!ft_calculate_fte_mic(hs, 5, rsne, fte, NULL, ft_info.mic))
			goto error;

		/* Rebuild the FT IE now with the MIC included */
		ie_build_fast_bss_transition(&ft_info, fte);

		iov[iov_elems].iov_base = fte;
		iov[iov_elems].iov_len = fte[1] + 2;
		iov_elems += 1;
	}

	l_genl_msg_append_attrv(msg, NL80211_ATTR_IE, iov, iov_elems);

	return msg;

error:
	l_genl_msg_unref(msg);

	return NULL;
}

static void netdev_cmd_ft_reassociate_cb(struct l_genl_msg *msg,
						void *user_data)
{
	struct netdev *netdev = user_data;

	netdev->connect_cmd_id = 0;

	if (l_genl_msg_get_error(msg) < 0) {
		struct l_genl_msg *cmd_deauth;

		netdev->result = NETDEV_RESULT_ASSOCIATION_FAILED;
		cmd_deauth = netdev_build_cmd_deauthenticate(netdev,
						MMPDU_REASON_CODE_UNSPECIFIED);
		netdev->disconnect_cmd_id = l_genl_family_send(nl80211,
							cmd_deauth,
							netdev_connect_failed,
							netdev, NULL);
	}
}

static void netdev_authenticate_event(struct l_genl_msg *msg,
							struct netdev *netdev)
{
	struct l_genl_msg *cmd_associate, *cmd_deauth;
	struct l_genl_attr attr;
	uint16_t type, len;
	const void *data;
	uint16_t status_code;
	const uint8_t *ies = NULL;
	size_t ies_len;
	const uint8_t *frame = NULL;
	size_t frame_len = 0;
	struct ie_tlv_iter iter;
	const uint8_t *rsne = NULL;
	const uint8_t *mde = NULL;
	const uint8_t *fte = NULL;
	struct handshake_state *hs = netdev->handshake;
	bool is_rsn;

	l_debug("");

	if (!netdev->connected) {
		l_warn("Unexpected connection related event -- "
				"is another supplicant running?");
		return;
	}

	/*
	 * During Fast Transition we use the authenticate event to start the
	 * reassociation step because the FTE necessary before we can build
	 * the FT Associate command is included in the attached frame and is
	 * not available in the Authenticate command callback.
	 */
	if (!netdev->in_ft)
		return;

	if (!l_genl_attr_init(&attr, msg)) {
		l_debug("attr init failed");

		goto auth_error;
	}

	while (l_genl_attr_next(&attr, &type, &len, &data)) {
		switch (type) {
		case NL80211_ATTR_TIMED_OUT:
			l_warn("authentication timed out");

			goto auth_error;

		case NL80211_ATTR_FRAME:
			if (frame)
				goto auth_error;

			frame = data;
			frame_len = len;
			break;
		}
	}

	if (!frame)
		goto auth_error;

	/*
	 * Parse the Authentication Response and validate the contents
	 * according to 12.5.2 / 12.5.4: RSN or non-RSN Over-the-air
	 * FT Protocol.
	 */
	if (!ft_parse_authentication_resp_frame(frame, frame_len,
					netdev->addr, hs->aa, hs->aa, 2,
					&status_code, &ies, &ies_len))
		goto auth_error;

	/* AP Rejected the authenticate / associate */
	if (status_code != 0)
		goto auth_error;

	/* Check 802.11r IEs */
	if (!ies)
		goto ft_error;

	ie_tlv_iter_init(&iter, ies, ies_len);

	while (ie_tlv_iter_next(&iter)) {
		switch (ie_tlv_iter_get_tag(&iter)) {
		case IE_TYPE_RSN:
			if (rsne)
				goto ft_error;

			rsne = ie_tlv_iter_get_data(&iter) - 2;
			break;

		case IE_TYPE_MOBILITY_DOMAIN:
			if (mde)
				goto ft_error;

			mde = ie_tlv_iter_get_data(&iter) - 2;
			break;

		case IE_TYPE_FAST_BSS_TRANSITION:
			if (fte)
				goto ft_error;

			fte = ie_tlv_iter_get_data(&iter) - 2;
			break;
		}
	}

	is_rsn = hs->own_ie != NULL;

	/*
	 * In an RSN, check for an RSNE containing the PMK-R0-Name and
	 * the remaining fields same as in the advertised RSNE.
	 *
	 * 12.8.3: "The RSNE shall be present only if dot11RSNAActivated
	 * is true. If present, the RSNE shall be set as follows:
	 * — Version field shall be set to 1.
	 * — PMKID Count field shall be set to 1.
	 * — PMKID List field shall be set to the value contained in the
	 *   first message of this sequence.
	 * — All other fields shall be identical to the contents of the
	 *   RSNE advertised by the AP in Beacon and Probe Response frames."
	 */
	if (is_rsn) {
		struct ie_rsn_info msg2_rsne;

		if (!rsne)
			goto ft_error;

		if (ie_parse_rsne_from_data(rsne, rsne[1] + 2,
						&msg2_rsne) < 0)
			goto ft_error;

		if (msg2_rsne.num_pmkids != 1 ||
				memcmp(msg2_rsne.pmkids, hs->pmk_r0_name, 16))
			goto ft_error;

		if (!handshake_util_ap_ie_matches(rsne, hs->ap_ie, false))
			goto ft_error;
	} else if (rsne)
		goto ft_error;

	/*
	 * Check for an MD IE identical to the one we sent in message 1
	 *
	 * 12.8.3: "The MDE shall contain the MDID and FT Capability and
	 * Policy fields. This element shall be the same as the MDE
	 * advertised by the target AP in Beacon and Probe Response frames."
	 */
	if (!mde || memcmp(hs->mde, mde, hs->mde[1] + 2))
		goto ft_error;

	/*
	 * In an RSN, check for an FT IE with the same R0KH-ID and the same
	 * SNonce that we sent, and check that the R1KH-ID and the ANonce
	 * are present.  Use them to generate new PMK-R1, PMK-R1-Name and PTK
	 * in handshake.c.
	 *
	 * 12.8.3: "The FTE shall be present only if dot11RSNAActivated is
	 * true. If present, the FTE shall be set as follows:
	 * — R0KH-ID shall be identical to the R0KH-ID provided by the FTO
	 *   in the first message.
	 * — R1KH-ID shall be set to the R1KH-ID of the target AP, from
	 *   dot11FTR1KeyHolderID.
	 * — ANonce shall be set to a value chosen randomly by the target AP,
	 *   following the recommendations of 11.6.5.
	 * — SNonce shall be set to the value contained in the first message
	 *   of this sequence.
	 * — All other fields shall be set to 0."
	 */
	if (is_rsn) {
		struct ie_ft_info ft_info;
		uint8_t zeros[16] = {};

		if (!fte)
			goto ft_error;

		if (ie_parse_fast_bss_transition_from_data(fte, fte[1] + 2,
								&ft_info) < 0)
			goto ft_error;

		if (ft_info.mic_element_count != 0 ||
				memcmp(ft_info.mic, zeros, 16))
			goto ft_error;

		if (hs->r0khid_len != ft_info.r0khid_len ||
				memcmp(hs->r0khid, ft_info.r0khid,
					hs->r0khid_len) ||
				!ft_info.r1khid_present)
			goto ft_error;

		if (memcmp(ft_info.snonce, hs->snonce, 32))
			goto ft_error;

		handshake_state_set_fte(hs, fte);

		handshake_state_set_anonce(hs, ft_info.anonce);

		handshake_state_set_kh_ids(hs, ft_info.r0khid,
						ft_info.r0khid_len,
						ft_info.r1khid);

		handshake_state_derive_ptk(hs);
	} else if (fte)
		goto ft_error;

	cmd_associate = netdev_build_cmd_ft_reassociate(netdev,
							netdev->frequency,
							netdev->prev_bssid);
	if (!cmd_associate)
		goto ft_error;

	netdev->connect_cmd_id = l_genl_family_send(nl80211,
						cmd_associate,
						netdev_cmd_ft_reassociate_cb,
						netdev, NULL);
	if (!netdev->connect_cmd_id) {
		l_genl_msg_unref(cmd_associate);

		goto ft_error;
	}

	if (netdev->sm)
		eapol_register(netdev->sm); /* See netdev_cmd_connect_cb */

	return;

auth_error:
	netdev->result = NETDEV_RESULT_AUTHENTICATION_FAILED;
	netdev_connect_failed(NULL, netdev);
	return;

ft_error:
	netdev->result = NETDEV_RESULT_AUTHENTICATION_FAILED;
	cmd_deauth = netdev_build_cmd_deauthenticate(netdev,
						MMPDU_REASON_CODE_UNSPECIFIED);
	netdev->disconnect_cmd_id = l_genl_family_send(nl80211, cmd_deauth,
							netdev_connect_failed,
							netdev, NULL);
}

static void netdev_associate_event(struct l_genl_msg *msg,
							struct netdev *netdev)
{
	l_debug("");
}

static unsigned int ie_rsn_akm_suite_to_nl80211(enum ie_rsn_akm_suite akm)
{
	switch (akm) {
	case IE_RSN_AKM_SUITE_8021X:
		return CRYPTO_AKM_8021X;
	case IE_RSN_AKM_SUITE_PSK:
		return CRYPTO_AKM_PSK;
	case IE_RSN_AKM_SUITE_FT_OVER_8021X:
		return CRYPTO_AKM_FT_OVER_8021X;
	case IE_RSN_AKM_SUITE_FT_USING_PSK:
		return CRYPTO_AKM_FT_USING_PSK;
	case IE_RSN_AKM_SUITE_8021X_SHA256:
		return CRYPTO_AKM_8021X_SHA256;
	case IE_RSN_AKM_SUITE_PSK_SHA256:
		return CRYPTO_AKM_PSK_SHA256;
	case IE_RSN_AKM_SUITE_TDLS:
		return CRYPTO_AKM_TDLS;
	case IE_RSN_AKM_SUITE_SAE_SHA256:
		return CRYPTO_AKM_SAE_SHA256;
	case IE_RSN_AKM_SUITE_FT_OVER_SAE_SHA256:
		return CRYPTO_AKM_FT_OVER_SAE_SHA256;
	}

	return 0;
}

static void netdev_cmd_connect_cb(struct l_genl_msg *msg, void *user_data)
{
	struct netdev *netdev = user_data;

	netdev->connect_cmd_id = 0;

	/* Wait for connect event */
	if (l_genl_msg_get_error(msg) >= 0) {
		if (netdev->event_filter)
			netdev->event_filter(netdev,
						NETDEV_EVENT_ASSOCIATING,
						netdev->user_data);

		/*
		 * We register the eapol state machine here, in case the PAE
		 * socket receives EAPoL packets before the nl80211 socket
		 * receives the connected event.  The logical sequence of
		 * events can be reversed (e.g. connect_event, then PAE data)
		 * due to scheduling
		 */
		if (netdev->sm)
			eapol_register(netdev->sm);

		return;
	}

	netdev->result = NETDEV_RESULT_ASSOCIATION_FAILED;
	netdev_connect_failed(NULL, netdev);
}

static struct l_genl_msg *netdev_build_cmd_connect(struct netdev *netdev,
						struct scan_bss *bss,
						struct handshake_state *hs,
						const uint8_t *prev_bssid)
{
	uint32_t auth_type = NL80211_AUTHTYPE_OPEN_SYSTEM;
	struct l_genl_msg *msg;
	struct iovec iov[2];
	int iov_elems = 0;
	bool is_rsn = hs->own_ie != NULL;

	msg = l_genl_msg_new_sized(NL80211_CMD_CONNECT, 512);
	l_genl_msg_append_attr(msg, NL80211_ATTR_IFINDEX, 4, &netdev->index);
	l_genl_msg_append_attr(msg, NL80211_ATTR_WIPHY_FREQ,
						4, &bss->frequency);
	l_genl_msg_append_attr(msg, NL80211_ATTR_MAC, ETH_ALEN, bss->addr);
	l_genl_msg_append_attr(msg, NL80211_ATTR_SSID,
						bss->ssid_len, bss->ssid);
	l_genl_msg_append_attr(msg, NL80211_ATTR_AUTH_TYPE, 4, &auth_type);

	if (netdev->pae_over_nl80211)
		l_genl_msg_append_attr(msg,
				NL80211_ATTR_CONTROL_PORT_OVER_NL80211,
				0, NULL);

	if (prev_bssid)
		l_genl_msg_append_attr(msg, NL80211_ATTR_PREV_BSSID, ETH_ALEN,
						prev_bssid);

	if (bss->capability & IE_BSS_CAP_PRIVACY)
		l_genl_msg_append_attr(msg, NL80211_ATTR_PRIVACY, 0, NULL);

	l_genl_msg_append_attr(msg, NL80211_ATTR_SOCKET_OWNER, 0, NULL);

	if (is_rsn) {
		uint32_t nl_cipher;
		uint32_t nl_akm;
		uint32_t wpa_version;

		if (hs->pairwise_cipher == IE_RSN_CIPHER_SUITE_CCMP)
			nl_cipher = CRYPTO_CIPHER_CCMP;
		else
			nl_cipher = CRYPTO_CIPHER_TKIP;

		l_genl_msg_append_attr(msg, NL80211_ATTR_CIPHER_SUITES_PAIRWISE,
					4, &nl_cipher);

		if (hs->group_cipher == IE_RSN_CIPHER_SUITE_CCMP)
			nl_cipher = CRYPTO_CIPHER_CCMP;
		else
			nl_cipher = CRYPTO_CIPHER_TKIP;

		l_genl_msg_append_attr(msg, NL80211_ATTR_CIPHER_SUITE_GROUP,
					4, &nl_cipher);

		if (hs->mfp) {
			uint32_t use_mfp = NL80211_MFP_REQUIRED;
			l_genl_msg_append_attr(msg, NL80211_ATTR_USE_MFP,
								4, &use_mfp);
		}

		nl_akm = ie_rsn_akm_suite_to_nl80211(hs->akm_suite);
		if (nl_akm)
			l_genl_msg_append_attr(msg, NL80211_ATTR_AKM_SUITES,
							4, &nl_akm);

		if (hs->wpa_ie)
			wpa_version = NL80211_WPA_VERSION_1;
		else
			wpa_version = NL80211_WPA_VERSION_2;

		l_genl_msg_append_attr(msg, NL80211_ATTR_WPA_VERSIONS,
						4, &wpa_version);

		l_genl_msg_append_attr(msg, NL80211_ATTR_CONTROL_PORT, 0, NULL);

		iov[iov_elems].iov_base = (void *) hs->own_ie;
		iov[iov_elems].iov_len = hs->own_ie[1] + 2;
		iov_elems += 1;
	}

	if (hs->mde) {
		iov[iov_elems].iov_base = (void *) hs->mde;
		iov[iov_elems].iov_len = hs->mde[1] + 2;
		iov_elems += 1;
	}

	if (iov_elems)
		l_genl_msg_append_attrv(msg, NL80211_ATTR_IE, iov, iov_elems);

	return msg;
}

static int netdev_connect_common(struct netdev *netdev,
					struct l_genl_msg *cmd_connect,
					struct scan_bss *bss,
					struct handshake_state *hs,
					struct eapol_sm *sm,
					netdev_event_func_t event_filter,
					netdev_connect_cb_t cb, void *user_data)
{
	netdev->connect_cmd_id = l_genl_family_send(nl80211, cmd_connect,
							netdev_cmd_connect_cb,
							netdev, NULL);

	if (!netdev->connect_cmd_id) {
		l_genl_msg_unref(cmd_connect);
		return -EIO;
	}

	netdev->event_filter = event_filter;
	netdev->connect_cb = cb;
	netdev->user_data = user_data;
	netdev->connected = true;
	netdev->handshake = hs;
	netdev->sm = sm;
	netdev->frequency = bss->frequency;
	netdev->cur_rssi_low = false; /* Gets udpated on the 1st CQM event */
	netdev->cur_rssi = bss->signal_strength / 100;
	netdev_rssi_level_init(netdev);

	handshake_state_set_authenticator_address(hs, bss->addr);
	handshake_state_set_supplicant_address(hs, netdev->addr);

	return 0;
}

int netdev_connect(struct netdev *netdev, struct scan_bss *bss,
				struct handshake_state *hs,
				netdev_event_func_t event_filter,
				netdev_connect_cb_t cb, void *user_data)
{
	struct l_genl_msg *cmd_connect;
	struct eapol_sm *sm = NULL;
	bool is_rsn = hs->own_ie != NULL;

	if (netdev->connected)
		return -EISCONN;

	cmd_connect = netdev_build_cmd_connect(netdev, bss, hs, NULL);
	if (!cmd_connect)
		return -EINVAL;

	if (is_rsn)
		sm = eapol_sm_new(hs);

	return netdev_connect_common(netdev, cmd_connect, bss, hs, sm,
						event_filter, cb, user_data);
}

int netdev_connect_wsc(struct netdev *netdev, struct scan_bss *bss,
				struct handshake_state *hs,
				netdev_event_func_t event_filter,
				netdev_connect_cb_t cb,
				netdev_eapol_event_func_t eapol_cb,
				void *user_data)
{
	struct l_genl_msg *cmd_connect;
	struct wsc_association_request request;
	uint8_t *pdu;
	size_t pdu_len;
	void *ie;
	size_t ie_len;
	struct eapol_sm *sm;

	if (netdev->connected)
		return -EISCONN;

	cmd_connect = netdev_build_cmd_connect(netdev, bss, hs, NULL);
	if (!cmd_connect)
		return -EINVAL;

	request.version2 = true;
	request.request_type = WSC_REQUEST_TYPE_ENROLLEE_OPEN_8021X;

	pdu = wsc_build_association_request(&request, &pdu_len);
	if (!pdu)
		goto error;

	ie = ie_tlv_encapsulate_wsc_payload(pdu, pdu_len, &ie_len);
	l_free(pdu);

	if (!ie)
		goto error;

	l_genl_msg_append_attr(cmd_connect, NL80211_ATTR_IE, ie_len, ie);
	l_free(ie);

	sm = eapol_sm_new(hs);
	eapol_sm_set_user_data(sm, user_data);
	eapol_sm_set_event_func(sm, eapol_cb);

	return netdev_connect_common(netdev, cmd_connect, bss, hs, sm,
						event_filter, cb, user_data);

error:
	l_genl_msg_unref(cmd_connect);
	return -ENOMEM;
}

int netdev_disconnect(struct netdev *netdev,
				netdev_disconnect_cb_t cb, void *user_data)
{
	struct l_genl_msg *disconnect;

	if (!netdev->connected)
		return -ENOTCONN;

	if (netdev->disconnect_cmd_id)
		return -EINPROGRESS;

	/* Only perform this if we haven't successfully fully associated yet */
	if (!netdev->operational) {
		netdev->result = NETDEV_RESULT_ABORTED;
		netdev_connect_failed(NULL, netdev);
	} else {
		netdev_connect_free(netdev);
	}

	disconnect = netdev_build_cmd_disconnect(netdev,
					MMPDU_REASON_CODE_DEAUTH_LEAVING);
	netdev->disconnect_cmd_id = l_genl_family_send(nl80211, disconnect,
				netdev_cmd_disconnect_cb, netdev, NULL);

	if (!netdev->disconnect_cmd_id) {
		l_genl_msg_unref(disconnect);
		return -EIO;
	}

	netdev->disconnect_cb = cb;
	netdev->user_data = user_data;

	return 0;
}

int netdev_reassociate(struct netdev *netdev, struct scan_bss *target_bss,
			struct scan_bss *orig_bss, struct handshake_state *hs,
			netdev_event_func_t event_filter,
			netdev_connect_cb_t cb, void *user_data)
{
	struct l_genl_msg *cmd_connect;
	struct netdev_handshake_state;
	struct handshake_state *old_hs;
	struct eapol_sm *sm = NULL, *old_sm;
	bool is_rsn = hs->own_ie != NULL;
	int err;

	cmd_connect = netdev_build_cmd_connect(netdev, target_bss, hs,
						orig_bss->addr);
	if (!cmd_connect)
		return -EINVAL;

	if (is_rsn)
		sm = eapol_sm_new(hs);

	old_sm = netdev->sm;
	old_hs = netdev->handshake;

	err = netdev_connect_common(netdev, cmd_connect, target_bss, hs, sm,
					event_filter, cb, user_data);
	if (err < 0)
		return err;

	memcpy(netdev->prev_bssid, orig_bss->addr, ETH_ALEN);

	netdev->operational = false;

	netdev_rssi_polling_update(netdev);

	if (old_sm)
		eapol_sm_free(old_sm);

	if (old_hs)
		handshake_state_free(old_hs);

	return err;
}

/*
 * Build an FT Authentication Request frame according to 12.5.2 / 12.5.4:
 * RSN or non-RSN Over-the-air FT Protocol, with the IE contents
 * according to 12.8.2: FT authentication sequence: contents of first message.
 */
static struct l_genl_msg *netdev_build_cmd_ft_authenticate(
					struct netdev *netdev,
					const struct scan_bss *bss,
					const struct handshake_state *hs)
{
	uint32_t auth_type = NL80211_AUTHTYPE_FT;
	struct l_genl_msg *msg;
	struct iovec iov[3];
	int iov_elems = 0;
	bool is_rsn = hs->own_ie != NULL;
	uint8_t mde[5];

	msg = l_genl_msg_new_sized(NL80211_CMD_AUTHENTICATE, 512);
	l_genl_msg_append_attr(msg, NL80211_ATTR_IFINDEX, 4, &netdev->index);
	l_genl_msg_append_attr(msg, NL80211_ATTR_WIPHY_FREQ,
						4, &bss->frequency);
	l_genl_msg_append_attr(msg, NL80211_ATTR_MAC, ETH_ALEN, bss->addr);
	l_genl_msg_append_attr(msg, NL80211_ATTR_SSID,
						bss->ssid_len, bss->ssid);
	l_genl_msg_append_attr(msg, NL80211_ATTR_AUTH_TYPE, 4, &auth_type);

	if (is_rsn) {
		struct ie_rsn_info rsn_info;
		uint8_t *rsne;

		/*
		 * Rebuild the RSNE to include the PMKR0Name and append
		 * MDE + FTE.
		 *
		 * 12.8.2: "If present, the RSNE shall be set as follows:
		 * — Version field shall be set to 1.
		 * — PMKID Count field shall be set to 1.
		 * — PMKID List field shall contain the PMKR0Name.
		 * — All other fields shall be as specified in 8.4.2.27
		 *   and 11.5.3."
		 */
		if (ie_parse_rsne_from_data(hs->own_ie, hs->own_ie[1] + 2,
						&rsn_info) < 0)
			goto error;

		rsn_info.num_pmkids = 1;
		rsn_info.pmkids = hs->pmk_r0_name;

		rsne = alloca(256);
		ie_build_rsne(&rsn_info, rsne);

		iov[iov_elems].iov_base = rsne;
		iov[iov_elems].iov_len = rsne[1] + 2;
		iov_elems += 1;
	}

	/* The MDE advertised by the BSS must be passed verbatim */
	mde[0] = IE_TYPE_MOBILITY_DOMAIN;
	mde[1] = 3;
	memcpy(mde + 2, bss->mde, 3);

	iov[iov_elems].iov_base = mde;
	iov[iov_elems].iov_len = 5;
	iov_elems += 1;

	if (is_rsn) {
		struct ie_ft_info ft_info;
		uint8_t *fte;

		/*
		 * 12.8.2: "If present, the FTE shall be set as follows:
		 * — R0KH-ID shall be the value of R0KH-ID obtained by the
		 *   FTO during its FT initial mobility domain association
		 *   exchange.
		 * — SNonce shall be set to a value chosen randomly by the
		 *   FTO, following the recommendations of 11.6.5.
		 * — All other fields shall be set to 0."
		 */

		memset(&ft_info, 0, sizeof(ft_info));

		memcpy(ft_info.r0khid, hs->r0khid, hs->r0khid_len);
		ft_info.r0khid_len = hs->r0khid_len;

		memcpy(ft_info.snonce, hs->snonce, 32);

		fte = alloca(256);
		ie_build_fast_bss_transition(&ft_info, fte);

		iov[iov_elems].iov_base = fte;
		iov[iov_elems].iov_len = fte[1] + 2;
		iov_elems += 1;
	}

	l_genl_msg_append_attrv(msg, NL80211_ATTR_IE, iov, iov_elems);

	return msg;

error:
	l_genl_msg_unref(msg);

	return NULL;
}

static void netdev_cmd_authenticate_ft_cb(struct l_genl_msg *msg,
						void *user_data)
{
	struct netdev *netdev = user_data;

	netdev->connect_cmd_id = 0;

	if (l_genl_msg_get_error(msg) < 0) {
		netdev->result = NETDEV_RESULT_AUTHENTICATION_FAILED;
		netdev_connect_failed(NULL, netdev);
	}
}

int netdev_fast_transition(struct netdev *netdev, struct scan_bss *target_bss,
				netdev_connect_cb_t cb)
{
	struct l_genl_msg *cmd_authenticate;
	struct netdev_handshake_state *nhs;
	uint8_t orig_snonce[32];
	int err;

	if (!netdev->operational)
		return -ENOTCONN;

	if (!netdev->handshake->mde || !target_bss->mde_present ||
			l_get_le16(netdev->handshake->mde + 2) !=
			l_get_le16(target_bss->mde))
		return -EINVAL;

	/*
	 * We reuse the handshake_state object and reset what's needed.
	 * Could also create a new object and copy most of the state but
	 * we would end up doing more work.
	 */

	memcpy(orig_snonce, netdev->handshake->snonce, 32);
	handshake_state_new_snonce(netdev->handshake);

	cmd_authenticate = netdev_build_cmd_ft_authenticate(netdev, target_bss,
							netdev->handshake);
	if (!cmd_authenticate) {
		err = -EINVAL;
		goto restore_snonce;
	}

	netdev->connect_cmd_id = l_genl_family_send(nl80211,
						cmd_authenticate,
						netdev_cmd_authenticate_ft_cb,
						netdev, NULL);
	if (!netdev->connect_cmd_id) {
		l_genl_msg_unref(cmd_authenticate);
		err = -EIO;
		goto restore_snonce;
	}

	memcpy(netdev->prev_bssid, netdev->handshake->aa, ETH_ALEN);
	handshake_state_set_authenticator_address(netdev->handshake,
							target_bss->addr);
	handshake_state_set_ap_rsn(netdev->handshake, target_bss->rsne);
	memcpy(netdev->handshake->mde + 2, target_bss->mde, 3);

	if (netdev->sm) {
		eapol_sm_free(netdev->sm);

		netdev->sm = eapol_sm_new(netdev->handshake);
		eapol_sm_set_require_handshake(netdev->sm, false);
	}

	netdev->operational = false;
	netdev->in_ft = true;

	netdev->connect_cb = cb;
	netdev->frequency = target_bss->frequency;

	/*
	 * Cancel commands that could be running because of EAPoL activity
	 * like re-keying, this way the callbacks for those commands don't
	 * have to check if failures resulted from the transition.
	 */
	nhs = container_of(netdev->handshake,
				struct netdev_handshake_state, super);

	if (nhs->group_new_key_cmd_id) {
		l_genl_family_cancel(nl80211, nhs->group_new_key_cmd_id);
		nhs->group_new_key_cmd_id = 0;
	}

	if (nhs->group_management_new_key_cmd_id) {
		l_genl_family_cancel(nl80211,
			nhs->group_management_new_key_cmd_id);
		nhs->group_management_new_key_cmd_id = 0;
	}

	netdev_rssi_polling_update(netdev);

	return 0;

restore_snonce:
	memcpy(netdev->handshake->snonce, orig_snonce, 32);

	return err;
}

static void netdev_preauth_cb(const uint8_t *pmk, void *user_data)
{
	struct netdev_preauth_state *preauth = user_data;
	netdev_preauthenticate_cb_t cb = preauth->cb;

	preauth->cb = NULL;

	cb(preauth->netdev,
		pmk ? NETDEV_RESULT_OK : NETDEV_RESULT_HANDSHAKE_FAILED,
		pmk, preauth->user_data);
}

int netdev_preauthenticate(struct netdev *netdev, struct scan_bss *target_bss,
				netdev_preauthenticate_cb_t cb, void *user_data)
{
	struct netdev_preauth_state *preauth;

	if (!netdev->operational)
		return -ENOTCONN;

	preauth = l_new(struct netdev_preauth_state, 1);

	if (!eapol_preauth_start(target_bss->addr, netdev->handshake,
					netdev_preauth_cb, preauth,
					netdev_preauth_destroy)) {
		l_free(preauth);

		return -EIO;
	}

	preauth->cb = cb;
	preauth->user_data = user_data;
	preauth->netdev = netdev;

	return 0;
}

static uint32_t netdev_send_action_frame(struct netdev *netdev,
					const uint8_t *to,
					const uint8_t *body, size_t body_len,
					l_genl_msg_func_t callback)
{
	struct l_genl_msg *msg;
	const uint16_t frame_type = 0x00d0;
	uint8_t action_frame[24 + body_len];
	uint32_t id;

	memset(action_frame, 0, 24);

	l_put_le16(frame_type, action_frame + 0);
	memcpy(action_frame + 4, to, 6);
	memcpy(action_frame + 10, netdev->addr, 6);
	memcpy(action_frame + 16, netdev->handshake->aa, 6);
	memcpy(action_frame + 24, body, body_len);

	msg = l_genl_msg_new_sized(NL80211_CMD_FRAME, 128 + body_len);

	l_genl_msg_append_attr(msg, NL80211_ATTR_IFINDEX, 4, &netdev->index);
	l_genl_msg_append_attr(msg, NL80211_ATTR_WIPHY_FREQ, 4,
				&netdev->frequency);
	l_genl_msg_append_attr(msg, NL80211_ATTR_FRAME, sizeof(action_frame),
				action_frame);

	id = l_genl_family_send(nl80211, msg, callback, netdev, NULL);

	if (!id)
		l_genl_msg_unref(msg);

	return id;
}

static void netdev_neighbor_report_req_cb(struct l_genl_msg *msg,
						void *user_data)
{
	struct netdev *netdev = user_data;

	if (!netdev->neighbor_report_cb)
		return;

	if (l_genl_msg_get_error(msg) < 0) {
		netdev->neighbor_report_cb(netdev, l_genl_msg_get_error(msg),
						NULL, 0, netdev->user_data);

		netdev->neighbor_report_cb = NULL;

		l_timeout_remove(netdev->neighbor_report_timeout);
	}
}

static void netdev_neighbor_report_timeout(struct l_timeout *timeout,
						void *user_data)
{
	struct netdev *netdev = user_data;

	netdev->neighbor_report_cb(netdev, -ETIMEDOUT, NULL, 0,
					netdev->user_data);

	netdev->neighbor_report_cb = NULL;

	l_timeout_remove(netdev->neighbor_report_timeout);
}

int netdev_neighbor_report_req(struct netdev *netdev,
				netdev_neighbor_report_cb_t cb)
{
	const uint8_t action_frame[] = {
		0x05, /* Category: Radio Measurement */
		0x04, /* Radio Measurement Action: Neighbor Report Request */
		0x01, /* Dialog Token: a non-zero value (unused) */
	};

	if (netdev->neighbor_report_cb || !netdev->connected)
		return -EBUSY;

	if (!netdev_send_action_frame(netdev, netdev->handshake->aa,
					action_frame, sizeof(action_frame),
					netdev_neighbor_report_req_cb))
		return -EIO;

	netdev->neighbor_report_cb = cb;

	/* Set a 3-second timeout */
	netdev->neighbor_report_timeout =
		l_timeout_create(3, netdev_neighbor_report_timeout,
					netdev, NULL);

	return 0;
}

static void netdev_neighbor_report_frame_event(struct netdev *netdev,
					const struct mmpdu_header *hdr,
					const void *body, size_t body_len,
					void *user_data)
{
	if (body_len < 3) {
		l_debug("Neighbor Report frame too short");
		return;
	}

	if (!netdev->neighbor_report_cb)
		return;

	/*
	 * Don't use the dialog token (byte 3), return the first Neighbor
	 * Report Response received.
	 *
	 * Byte 1 is 0x05 for Radio Measurement, byte 2 is 0x05 for
	 * Neighbor Report.
	 */

	netdev->neighbor_report_cb(netdev, 0, body + 3, body_len - 3,
					netdev->user_data);
	netdev->neighbor_report_cb = NULL;

	l_timeout_remove(netdev->neighbor_report_timeout);
}

static void netdev_sa_query_resp_cb(struct l_genl_msg *msg,
		void *user_data)
{
	if (l_genl_msg_get_error(msg) < 0)
		l_debug("error sending SA Query request");
}

static void netdev_sa_query_req_frame_event(struct netdev *netdev,
		const struct mmpdu_header *hdr,
		const void *body, size_t body_len,
		void *user_data)
{
	uint8_t sa_resp[4];
	uint16_t transaction;

	if (body_len < 4) {
		l_debug("SA Query request too short");
		return;
	}

	if (!netdev->connected)
		return;

	/* only care about SA Queries from our connected AP */
	if (memcmp(hdr->address_2, netdev->handshake->aa, 6))
		return;

	transaction = l_get_u16(body + 2);

	sa_resp[0] = 0x08;	/* SA Query */
	sa_resp[1] = 0x01;	/* Response */
	memcpy(sa_resp + 2, &transaction, 2);

	l_info("received SA Query request from "MAC", transaction=%u",
			MAC_STR(hdr->address_2), transaction);

	if (!netdev_send_action_frame(netdev, netdev->handshake->aa,
			sa_resp, sizeof(sa_resp),
			netdev_sa_query_resp_cb)) {
		l_error("error sending SA Query response");
		return;
	}
}

static void netdev_sa_query_resp_frame_event(struct netdev *netdev,
		const struct mmpdu_header *hdr,
		const void *body, size_t body_len,
		void *user_data)
{
	if (body_len < 4) {
		l_debug("SA Query frame too short");
		return;
	}

	l_debug("SA Query src="MAC" dest="MAC" bssid="MAC" transaction=%u",
			MAC_STR(hdr->address_2), MAC_STR(hdr->address_1),
			MAC_STR(hdr->address_3), l_get_u16(body + 2));

	if (!netdev->sa_query_timeout) {
		l_debug("no SA Query request sent");
		return;
	}

	/* check if this is from our connected BSS */
	if (memcmp(hdr->address_2, netdev->handshake->aa, 6)) {
		l_debug("received SA Query from non-connected AP");
		return;
	}

	if (memcmp(body + 2, &netdev->sa_query_id, 2)) {
		l_debug("SA Query transaction ID's did not match");
		return;
	}

	l_info("SA Query response from connected BSS received, "
			"keeping the connection active");

	l_timeout_remove(netdev->sa_query_timeout);
	netdev->sa_query_timeout = NULL;
}

static void netdev_sa_query_req_cb(struct l_genl_msg *msg,
		void *user_data)
{
	struct netdev *netdev = user_data;

	if (l_genl_msg_get_error(msg) < 0) {
		l_debug("error sending SA Query request");

		l_timeout_remove(netdev->sa_query_timeout);
		netdev->sa_query_timeout = NULL;
	}
}

static void netdev_sa_query_timeout(struct l_timeout *timeout,
		void *user_data)
{
	struct netdev *netdev = user_data;
	struct l_genl_msg *msg;

	l_info("SA Query timed out, connection is invalid.  Disconnecting...");

	l_timeout_remove(netdev->sa_query_timeout);
	netdev->sa_query_timeout = NULL;

	msg = netdev_build_cmd_disconnect(netdev,
			MMPDU_REASON_CODE_PREV_AUTH_NOT_VALID);
	netdev->disconnect_cmd_id = l_genl_family_send(nl80211, msg,
			netdev_connect_failed, netdev, NULL);
}

static void netdev_unprot_disconnect_event(struct l_genl_msg *msg,
		struct netdev *netdev)
{
	const struct mmpdu_header *hdr = NULL;
	struct l_genl_attr attr;
	uint16_t type;
	uint16_t len;
	const void *data;
	uint8_t action_frame[4];
	uint8_t reason_code;

	if (!netdev->connected)
		return;

	/* ignore excessive disassociate requests */
	if (netdev->sa_query_timeout)
		return;

	if (!l_genl_attr_init(&attr, msg))
		return;

	while (l_genl_attr_next(&attr, &type, &len, &data)) {
		switch (type) {
		case NL80211_ATTR_FRAME:
			hdr = mpdu_validate(data, len);
			break;
		}
	}

	/* check that ATTR_FRAME was actually included */
	if (!hdr)
		return;

	/* get reason code, first byte of frame */
	reason_code = l_get_u8(mmpdu_body(hdr));

	l_info("disconnect event, src="MAC" dest="MAC" bssid="MAC" reason=%u",
			MAC_STR(hdr->address_2), MAC_STR(hdr->address_1),
			MAC_STR(hdr->address_3), reason_code);

	if (memcmp(hdr->address_2, netdev->handshake->aa, 6)) {
		l_debug("received invalid disassociate frame");
		return;
	}

	if (reason_code != MMPDU_REASON_CODE_CLASS2_FRAME_FROM_NONAUTH_STA &&
			reason_code !=
			MMPDU_REASON_CODE_CLASS3_FRAME_FROM_NONASSOC_STA) {
		l_debug("invalid reason code %u", reason_code);
		return;
	}

	action_frame[0] = 0x08; /* Category: SA Query */
	action_frame[1] = 0x00; /* SA Query Action: Request */

	/* Transaction ID */
	l_getrandom(action_frame + 2, 2);

	if (!netdev_send_action_frame(netdev, netdev->handshake->aa,
			action_frame, sizeof(action_frame),
			netdev_sa_query_req_cb)) {
		l_error("error sending SA Query action frame");
		return;
	}

	netdev->sa_query_id = l_get_u16(action_frame + 2);
	netdev->sa_query_timeout = l_timeout_create(3,
			netdev_sa_query_timeout, netdev, NULL);
}

static void netdev_mlme_notify(struct l_genl_msg *msg, void *user_data)
{
	struct netdev *netdev = NULL;
	struct l_genl_attr attr;
	uint16_t type, len;
	const void *data;
	uint8_t cmd;

	cmd = l_genl_msg_get_command(msg);

	l_debug("MLME notification %u", cmd);

	if (!l_genl_attr_init(&attr, msg))
		return;

	while (l_genl_attr_next(&attr, &type, &len, &data)) {
		switch (type) {
		case NL80211_ATTR_IFINDEX:
			if (len != sizeof(uint32_t)) {
				l_warn("Invalid interface index attribute");
				return;
			}

			netdev = netdev_find(*((uint32_t *) data));
			break;
		}
	}

	if (!netdev) {
		l_warn("MLME notification is missing ifindex attribute");
		return;
	}

	switch (cmd) {
	case NL80211_CMD_AUTHENTICATE:
		netdev_authenticate_event(msg, netdev);
		break;
	case NL80211_CMD_DEAUTHENTICATE:
		netdev_deauthenticate_event(msg, netdev);
		break;
	case NL80211_CMD_ASSOCIATE:
		netdev_associate_event(msg, netdev);
		break;
	case NL80211_CMD_CONNECT:
		netdev_connect_event(msg, netdev);
		break;
	case NL80211_CMD_DISCONNECT:
		netdev_disconnect_event(msg, netdev);
		break;
	case NL80211_CMD_NOTIFY_CQM:
		netdev_cqm_event(msg, netdev);
		break;
	case NL80211_CMD_SET_REKEY_OFFLOAD:
		netdev_rekey_offload_event(msg, netdev);
		break;
	case NL80211_CMD_UNPROT_DEAUTHENTICATE:
	case NL80211_CMD_UNPROT_DISASSOCIATE:
		netdev_unprot_disconnect_event(msg, netdev);
		break;
	}
}

struct frame_prefix_info {
	uint16_t frame_type;
	const uint8_t *body;
	size_t body_len;
};

static bool netdev_frame_watch_match_prefix(const void *a, const void *b)
{
	const struct watchlist_item *item = a;
	const struct netdev_frame_watch *fw =
		container_of(item, struct netdev_frame_watch, super);
	const struct frame_prefix_info *info = b;

	return fw->frame_type == info->frame_type &&
		fw->prefix_len <= info->body_len &&
		!memcmp(fw->prefix, info->body, fw->prefix_len);
}

static void netdev_mgmt_frame_event(struct l_genl_msg *msg,
					struct netdev *netdev)
{
	struct l_genl_attr attr;
	uint16_t type, len, frame_len;
	const void *data;
	const struct mmpdu_header *mpdu = NULL;
	const uint8_t *body;
	struct frame_prefix_info info;

	if (!l_genl_attr_init(&attr, msg))
		return;

	while (l_genl_attr_next(&attr, &type, &len, &data)) {
		switch (type) {
		case NL80211_ATTR_FRAME:
			if (mpdu)
				return;

			mpdu = mpdu_validate(data, len);
			if (!mpdu)
				l_error("Frame didn't validate as MMPDU");

			frame_len = len;
			break;
		}
	}

	if (!mpdu)
		return;

	body = mmpdu_body(mpdu);

	if (memcmp(mpdu->address_1, netdev->addr, 6) &&
			!util_is_broadcast_address(mpdu->address_1))
		return;

	/* Only match the frame type and subtype like the kernel does */
#define FC_FTYPE_STYPE_MASK 0x00fc
	info.frame_type = l_get_le16(mpdu) & FC_FTYPE_STYPE_MASK;
	info.body = (const uint8_t *) body;
	info.body_len = (const uint8_t *) mpdu + frame_len - body;

	WATCHLIST_NOTIFY_MATCHES(&netdev->frame_watches,
					netdev_frame_watch_match_prefix, &info,
					netdev_frame_watch_func_t,
					netdev, mpdu, body, info.body_len);
}

static void netdev_pae_destroy(void *user_data)
{
	struct netdev *netdev = user_data;

	netdev->pae_io = NULL;
}

static bool netdev_pae_read(struct l_io *io, void *user_data)
{
	int fd = l_io_get_fd(io);
	struct sockaddr_ll sll;
	socklen_t sll_len;
	ssize_t bytes;
	uint8_t frame[IEEE80211_MAX_DATA_LEN];

	memset(&sll, 0, sizeof(sll));
	sll_len = sizeof(sll);

	bytes = recvfrom(fd, frame, sizeof(frame), 0,
				(struct sockaddr *) &sll, &sll_len);
	if (bytes <= 0) {
		l_error("EAPoL read socket: %s", strerror(errno));
		return false;
	}

	if (sll.sll_halen != ETH_ALEN)
		return true;

	__eapol_rx_packet(sll.sll_ifindex, sll.sll_addr,
				ntohs(sll.sll_protocol), frame, bytes, false);

	return true;
}

static void netdev_control_port_frame_event(struct l_genl_msg *msg,
							struct netdev *netdev)
{
	struct l_genl_attr attr;
	uint16_t type;
	uint16_t len;
	const void *data;
	const uint8_t *frame = NULL;
	uint16_t frame_len = 0;
	const uint8_t *src = NULL;
	uint16_t proto = 0;
	bool unencrypted = false;

	l_debug("");

	if (!l_genl_attr_init(&attr, msg))
		return;

	while (l_genl_attr_next(&attr, &type, &len, &data)) {
		switch (type) {
		case NL80211_ATTR_FRAME:
			if (frame)
				return;

			frame = data;
			frame_len = len;
			break;
		case NL80211_ATTR_MAC:
			if (src)
				return;

			src = data;
			break;
		case NL80211_ATTR_CONTROL_PORT_ETHERTYPE:
			if (len != sizeof(proto))
				return;

			proto = *((const uint16_t *) data);
			break;
		case NL80211_ATTR_CONTROL_PORT_NO_ENCRYPT:
			unencrypted = true;
			break;
		}
	}

	if (!src || !frame || !proto)
		return;

	__eapol_rx_packet(netdev->index, src, proto,
						frame, frame_len, unencrypted);
}

static struct l_genl_msg *netdev_build_control_port_frame(struct netdev *netdev,
							const uint8_t *to,
							uint16_t proto,
							bool unencrypted,
							const void *body,
							size_t body_len)
{
	struct l_genl_msg *msg;

	msg = l_genl_msg_new_sized(NL80211_CMD_CONTROL_PORT_FRAME,
							128 + body_len);

	l_genl_msg_append_attr(msg, NL80211_ATTR_IFINDEX, 4, &netdev->index);
	l_genl_msg_append_attr(msg, NL80211_ATTR_FRAME, body_len, body);
	l_genl_msg_append_attr(msg, NL80211_ATTR_CONTROL_PORT_ETHERTYPE, 2,
				&proto);
	l_genl_msg_append_attr(msg, NL80211_ATTR_MAC, ETH_ALEN, to);

	if (unencrypted)
		l_genl_msg_append_attr(msg,
				NL80211_ATTR_CONTROL_PORT_NO_ENCRYPT, 0, NULL);

	return msg;
}

static void netdev_control_port_frame_cb(struct l_genl_msg *msg,
							void *user_data)
{
	int err;

	err = l_genl_msg_get_error(msg);

	l_debug("%d", err);

	if (err < 0)
		l_info("CMD_CONTROL_PORT failed: %s", strerror(-err));
}

static int netdev_control_port_write_pae(struct netdev *netdev,
						const uint8_t *dest,
						uint16_t proto,
						const struct eapol_frame *ef,
						bool noencrypt)
{
	int fd = l_io_get_fd(netdev->pae_io);
	struct sockaddr_ll sll;
	size_t frame_size = sizeof(struct eapol_header) +
					L_BE16_TO_CPU(ef->header.packet_len);
	ssize_t r;

	memset(&sll, 0, sizeof(sll));
	sll.sll_family = AF_PACKET;
	sll.sll_ifindex = netdev->index;
	sll.sll_protocol = htons(proto);
	sll.sll_halen = ETH_ALEN;
	memcpy(sll.sll_addr, dest, ETH_ALEN);

	r = sendto(fd, ef, frame_size, 0,
			(struct sockaddr *) &sll, sizeof(sll));
	if (r < 0)
		l_error("EAPoL write socket: %s", strerror(errno));

	return r;
}

static int netdev_control_port_frame(uint32_t ifindex,
					const uint8_t *dest, uint16_t proto,
					const struct eapol_frame *ef,
					bool noencrypt,
					void *user_data)
{
	struct l_genl_msg *msg;
	struct netdev *netdev;
	size_t frame_size;

	netdev = netdev_find(ifindex);
	if (!netdev)
		return -ENOENT;

	frame_size = sizeof(struct eapol_header) +
			L_BE16_TO_CPU(ef->header.packet_len);

	if (!netdev->pae_over_nl80211)
		return netdev_control_port_write_pae(netdev, dest, proto,
							ef, noencrypt);

	msg = netdev_build_control_port_frame(netdev, dest, proto, noencrypt,
						ef, frame_size);
	if (!msg)
		return -ENOMEM;

	if (!l_genl_family_send(nl80211, msg, netdev_control_port_frame_cb,
				netdev, NULL)) {
		l_genl_msg_unref(msg);
		return -EINVAL;
	}

	return 0;
}

static void netdev_unicast_notify(struct l_genl_msg *msg, void *user_data)
{
	struct netdev *netdev = NULL;
	struct l_genl_attr attr;
	uint16_t type, len;
	const void *data;
	uint8_t cmd;

	cmd = l_genl_msg_get_command(msg);
	if (!cmd)
		return;

	l_debug("Unicast notification %u", cmd);

	if (!l_genl_attr_init(&attr, msg))
		return;

	while (l_genl_attr_next(&attr, &type, &len, &data)) {
		switch (type) {
		case NL80211_ATTR_IFINDEX:
			if (len != sizeof(uint32_t)) {
				l_warn("Invalid interface index attribute");
				return;
			}

			netdev = netdev_find(*((uint32_t *) data));
			break;
		}
	}

	if (!netdev) {
		l_warn("Unicast notification is missing ifindex attribute");
		return;
	}

	switch (cmd) {
	case NL80211_CMD_FRAME:
		netdev_mgmt_frame_event(msg, netdev);
		break;
	case NL80211_CMD_CONTROL_PORT_FRAME:
		netdev_control_port_frame_event(msg, netdev);
		break;
	}
}

static struct l_genl_msg *netdev_build_cmd_cqm_rssi_update(
							struct netdev *netdev,
							const int8_t *levels,
							size_t levels_num)
{
	struct l_genl_msg *msg;
	uint32_t hyst = 5;
	int thold_count;
	int32_t thold_list[levels_num + 2];

	if (levels_num == 0) {
		thold_list[0] = LOW_SIGNAL_THRESHOLD;
		thold_count = 1;
	} else {
		/*
		 * Build the list of all the threshold values we care about:
		 *  - the low/high level threshold,
		 *  - the value ranges requested by
		 *    netdev_set_rssi_report_levels
		 */
		unsigned int i;
		bool low_sig_added = false;

		thold_count = 0;
		for (i = 0; i < levels_num; i++) {
			int32_t val = levels[levels_num - i - 1];

			if (i && thold_list[thold_count - 1] >= val)
				return NULL;

			if (val >= LOW_SIGNAL_THRESHOLD && !low_sig_added) {
				thold_list[thold_count++] =
					LOW_SIGNAL_THRESHOLD;
				low_sig_added = true;

				/* Duplicate values are not allowed */
				if (val == LOW_SIGNAL_THRESHOLD)
					continue;
			}

			thold_list[thold_count++] = val;
		}
	}

	msg = l_genl_msg_new_sized(NL80211_CMD_SET_CQM, 32 + thold_count * 4);
	l_genl_msg_append_attr(msg, NL80211_ATTR_IFINDEX, 4, &netdev->index);
	l_genl_msg_enter_nested(msg, NL80211_ATTR_CQM);
	l_genl_msg_append_attr(msg, NL80211_ATTR_CQM_RSSI_THOLD,
				thold_count * 4, thold_list);
	l_genl_msg_append_attr(msg, NL80211_ATTR_CQM_RSSI_HYST, 4, &hyst);
	l_genl_msg_leave_nested(msg);

	return msg;
}

static void netdev_cmd_set_cqm_cb(struct l_genl_msg *msg, void *user_data)
{
	if (l_genl_msg_get_error(msg) < 0)
		l_error("CMD_SET_CQM failed");
}

int netdev_set_rssi_report_levels(struct netdev *netdev, const int8_t *levels,
					size_t levels_num)
{
	struct l_genl_msg *cmd_set_cqm;

	if (levels_num > L_ARRAY_SIZE(netdev->rssi_levels))
		return -ENOSPC;

	if (!wiphy_has_ext_feature(netdev->wiphy,
					NL80211_EXT_FEATURE_CQM_RSSI_LIST))
		goto done;

	cmd_set_cqm = netdev_build_cmd_cqm_rssi_update(netdev, levels,
							levels_num);
	if (!cmd_set_cqm)
		return -EINVAL;

	if (!l_genl_family_send(nl80211, cmd_set_cqm, netdev_cmd_set_cqm_cb,
				NULL, NULL)) {
		l_error("CMD_SET_CQM failed");

		l_genl_msg_unref(cmd_set_cqm);

		return -EIO;
	}

done:
	memcpy(netdev->rssi_levels, levels, levels_num);
	netdev->rssi_levels_num = levels_num;
	netdev_rssi_level_init(netdev);

	netdev_rssi_polling_update(netdev);

	return 0;
}

int netdev_get_rssi_level(struct netdev *netdev)
{
	return netdev->cur_rssi_level_idx;
}

static int netdev_cqm_rssi_update(struct netdev *netdev)
{
	struct l_genl_msg *msg =
		netdev_build_cmd_cqm_rssi_update(netdev,
						netdev->rssi_levels,
						netdev->rssi_levels_num);

	if (!msg)
		return -EINVAL;

	if (!l_genl_family_send(nl80211, msg, netdev_cmd_set_cqm_cb,
				NULL, NULL)) {
		l_error("CMD_SET_CQM failed");

		l_genl_msg_unref(msg);

		return -EIO;
	}

	return 0;
}

int netdev_set_iftype(struct netdev *netdev, enum netdev_iftype type)
{
	struct l_genl_msg *msg;
	uint32_t iftype;

	switch (type) {
	case NETDEV_IFTYPE_AP:
		iftype = NL80211_IFTYPE_AP;
		break;
	case NETDEV_IFTYPE_ADHOC:
		iftype = NL80211_IFTYPE_ADHOC;
		break;
	case NETDEV_IFTYPE_STATION:
		iftype = NL80211_IFTYPE_STATION;
		break;
	default:
		l_error("unsupported iftype %u", type);
		return -EINVAL;
	}

	msg = l_genl_msg_new_sized(NL80211_CMD_SET_INTERFACE, 32);
	l_genl_msg_append_attr(msg, NL80211_ATTR_IFINDEX, 4, &netdev->index);
	l_genl_msg_append_attr(msg, NL80211_ATTR_IFTYPE, 4, &iftype);

	if (!l_genl_family_send(nl80211, msg, NULL, NULL, NULL)) {
		l_error("CMD_SET_INTERFACE failed");

		l_genl_msg_unref(msg);

		return -EIO;
	}

	netdev->type = iftype;

	return 0;
}

static void netdev_bridge_port_event(const struct ifinfomsg *ifi, int bytes,
					bool added)
{
	struct netdev *netdev;
	struct rtattr *attr;
	uint32_t master = 0;

	netdev = netdev_find(ifi->ifi_index);
	if (!netdev)
		return;

	for (attr = IFLA_RTA(ifi); RTA_OK(attr, bytes);
			attr = RTA_NEXT(attr, bytes)) {
		switch (attr->rta_type) {
		case IFLA_MASTER:
			memcpy(&master, RTA_DATA(attr), sizeof(master));
			break;
		}
	}

	l_debug("netdev: %d %s bridge: %d", ifi->ifi_index,
		(added ? "added to" : "removed from"), master);
}

struct set_4addr_cb_data {
	struct netdev *netdev;
	bool value;
	netdev_set_4addr_cb_t callback;
	void *user_data;
	netdev_destroy_func_t destroy;
};

static void netdev_set_4addr_cb(struct l_genl_msg *msg, void *user_data)
{
	struct set_4addr_cb_data *cb_data = user_data;
	int error = l_genl_msg_get_error(msg);

	if (!cb_data)
		return;

	/* cache the value that has just been set */
	if (!error)
		cb_data->netdev->use_4addr = cb_data->value;

	cb_data->callback(cb_data->netdev, error, cb_data->user_data);
}

static void netdev_set_4addr_destroy(void *user_data)
{
	struct set_4addr_cb_data *cb_data = user_data;

	if (!cb_data)
		return;

	if (cb_data->destroy)
		cb_data->destroy(cb_data->user_data);

	l_free(cb_data);
}

int netdev_set_4addr(struct netdev *netdev, bool use_4addr,
			netdev_set_4addr_cb_t cb, void *user_data,
			netdev_destroy_func_t destroy)
{
	struct set_4addr_cb_data *cb_data = NULL;
	uint8_t attr_4addr = (use_4addr ? 1 : 0);
	struct l_genl_msg *msg;

	l_debug("netdev: %d use_4addr: %d", netdev->index, use_4addr);

	msg = l_genl_msg_new_sized(NL80211_CMD_SET_INTERFACE, 32);
	l_genl_msg_append_attr(msg, NL80211_ATTR_IFINDEX, 4, &netdev->index);
	l_genl_msg_append_attr(msg, NL80211_ATTR_4ADDR, 1, &attr_4addr);

	if (cb) {
		cb_data = l_new(struct set_4addr_cb_data, 1);
		cb_data->netdev = netdev;
		cb_data->value = use_4addr;
		cb_data->callback = cb;
		cb_data->user_data = user_data;
		cb_data->destroy = destroy;
	}

	if (!l_genl_family_send(nl80211, msg, netdev_set_4addr_cb, cb_data,
				netdev_set_4addr_destroy)) {
		l_error("CMD_SET_INTERFACE (4addr) failed");

		l_genl_msg_unref(msg);
		l_free(cb_data);

		return -EIO;
	}

	return 0;
}

bool netdev_get_4addr(struct netdev *netdev)
{
	return netdev->use_4addr;
}

static void netdev_newlink_notify(const struct ifinfomsg *ifi, int bytes)
{
	struct netdev *netdev;
	bool old_up, new_up;
	char old_name[IFNAMSIZ];
	uint8_t old_addr[ETH_ALEN];
	struct rtattr *attr;

	if (ifi->ifi_family == AF_BRIDGE) {
		netdev_bridge_port_event(ifi, bytes, true);
		return;
	}

	netdev = netdev_find(ifi->ifi_index);
	if (!netdev)
		return;

	old_up = netdev_get_is_up(netdev);
	strcpy(old_name, netdev->name);
	memcpy(old_addr, netdev->addr, ETH_ALEN);

	netdev->ifi_flags = ifi->ifi_flags;

	for (attr = IFLA_RTA(ifi); RTA_OK(attr, bytes);
			attr = RTA_NEXT(attr, bytes)) {
		switch (attr->rta_type) {
		case IFLA_IFNAME:
			strcpy(netdev->name, RTA_DATA(attr));
			break;
		case IFLA_ADDRESS:
			if (RTA_PAYLOAD(attr) < ETH_ALEN)
				break;

			memcpy(netdev->addr, RTA_DATA(attr), ETH_ALEN);
			break;
		}
	}

	new_up = netdev_get_is_up(netdev);

	if (old_up != new_up)
		WATCHLIST_NOTIFY(&netdev->event_watches, netdev_watch_func_t,
				netdev, new_up ? NETDEV_WATCH_EVENT_UP :
						NETDEV_WATCH_EVENT_DOWN);

	if (strcmp(old_name, netdev->name))
		WATCHLIST_NOTIFY(&netdev->event_watches, netdev_watch_func_t,
				netdev, NETDEV_WATCH_EVENT_NAME_CHANGE);

	if (memcmp(old_addr, netdev->addr, ETH_ALEN))
		WATCHLIST_NOTIFY(&netdev->event_watches, netdev_watch_func_t,
				netdev, NETDEV_WATCH_EVENT_ADDRESS_CHANGE);
}

static void netdev_dellink_notify(const struct ifinfomsg *ifi, int bytes)
{
	struct netdev *netdev;

	if (ifi->ifi_family == AF_BRIDGE) {
		netdev_bridge_port_event(ifi, bytes, false);
		return;
	}

	netdev = l_queue_remove_if(netdev_list, netdev_match,
						L_UINT_TO_PTR(ifi->ifi_index));
	if (!netdev)
		return;

	netdev_free(netdev);
}

static void netdev_initial_up_cb(struct netdev *netdev, int result,
					void *user_data)
{
	if (result != 0) {
		l_error("Error bringing interface %i up: %s", netdev->index,
			strerror(-result));

		if (result != -ERFKILL)
			return;
	}

	netdev_set_linkmode_and_operstate(netdev->index, IF_LINK_MODE_DORMANT,
						IF_OPER_DOWN,
						netdev_linkmode_dormant_cb,
						netdev);

	/*
	 * we don't know the initial status of the 4addr property on this
	 * netdev, therefore we set it to zero by default.
	 */
	netdev_set_4addr(netdev, netdev->use_4addr, NULL, NULL, NULL);

	l_debug("Interface %i initialized", netdev->index);

	netdev->device = device_create(netdev->wiphy, netdev);
}

static void netdev_initial_down_cb(struct netdev *netdev, int result,
					void *user_data)
{
	if (result != 0) {
		l_error("Error taking interface %i down: %s", netdev->index,
			strerror(-result));

		return;
	}

	netdev_set_powered(netdev, true, netdev_initial_up_cb,
				NULL, NULL);
}

static void netdev_getlink_cb(int error, uint16_t type, const void *data,
			uint32_t len, void *user_data)
{
	const struct ifinfomsg *ifi = data;
	unsigned int bytes;
	struct netdev *netdev;

	if (error != 0 || ifi->ifi_type != ARPHRD_ETHER ||
			type != RTM_NEWLINK) {
		l_error("RTM_GETLINK error %i ifi_type %i type %i",
				error, (int) ifi->ifi_type, (int) type);
		return;
	}

	netdev = netdev_find(ifi->ifi_index);
	if (!netdev)
		return;

	bytes = len - NLMSG_ALIGN(sizeof(struct ifinfomsg));

	netdev_newlink_notify(ifi, bytes);

	/*
	 * If the interface is UP, reset it to ensure a clean state,
	 * otherwise just bring it UP.
	 */
	if (netdev_get_is_up(netdev)) {
		netdev_set_powered(netdev, false, netdev_initial_down_cb,
					NULL, NULL);
	} else
		netdev_initial_down_cb(netdev, 0, NULL);
}

static bool netdev_is_managed(const char *ifname)
{
	char *pattern;
	unsigned int i;

	if (!whitelist_filter)
		goto check_blacklist;

	for (i = 0; (pattern = whitelist_filter[i]); i++) {
		if (fnmatch(pattern, ifname, 0) != 0)
			continue;

		goto check_blacklist;
	}

	l_debug("whitelist filtered ifname: %s", ifname);
	return false;

check_blacklist:
	if (!blacklist_filter)
		return true;

	for (i = 0; (pattern = blacklist_filter[i]); i++) {
		if (fnmatch(pattern, ifname, 0) == 0) {
			l_debug("blacklist filtered ifname: %s", ifname);
			return false;
		}
	}

	return true;
}

static void netdev_frame_watch_free(struct watchlist_item *item)
{
	struct netdev_frame_watch *fw =
		container_of(item, struct netdev_frame_watch, super);

	l_free(fw->prefix);
	l_free(fw);
}

static const struct watchlist_ops netdev_frame_watch_ops = {
	.item_free = netdev_frame_watch_free,
};

static void netdev_frame_cb(struct l_genl_msg *msg, void *user_data)
{
	if (l_genl_msg_get_error(msg) < 0)
		l_error("Could not register frame watch type %04x: %i",
			L_PTR_TO_UINT(user_data), l_genl_msg_get_error(msg));
}

uint32_t netdev_frame_watch_add(struct netdev *netdev, uint16_t frame_type,
				const uint8_t *prefix, size_t prefix_len,
				netdev_frame_watch_func_t handler,
				void *user_data)
{
	struct netdev_frame_watch *fw;
	struct l_genl_msg *msg;
	struct frame_prefix_info info = { frame_type, prefix, prefix_len };
	bool registered;
	uint32_t id;

	registered = l_queue_find(netdev->frame_watches.items,
					netdev_frame_watch_match_prefix,
					&info);

	fw = l_new(struct netdev_frame_watch, 1);
	fw->frame_type = frame_type;
	fw->prefix = l_memdup(prefix, prefix_len);
	fw->prefix_len = prefix_len;
	id = watchlist_link(&netdev->frame_watches, &fw->super,
						handler, user_data, NULL);

	if (registered)
		return id;

	msg = l_genl_msg_new_sized(NL80211_CMD_REGISTER_FRAME, 32 + prefix_len);

	l_genl_msg_append_attr(msg, NL80211_ATTR_IFINDEX, 4, &netdev->index);
	l_genl_msg_append_attr(msg, NL80211_ATTR_FRAME_TYPE, 2, &frame_type);
	l_genl_msg_append_attr(msg, NL80211_ATTR_FRAME_MATCH,
				prefix_len, prefix);

	l_genl_family_send(nl80211, msg, netdev_frame_cb,
			L_UINT_TO_PTR(frame_type), NULL);

	return id;
}

bool netdev_frame_watch_remove(struct netdev *netdev, uint32_t id)
{
	/*
	 * There's no way to unregister from notifications but that's not a
	 * problem, we leave them active in the kernel but
	 * netdev_mgmt_frame_event will ignore these events.
	 */
	return watchlist_remove(&netdev->frame_watches, id);
}

static struct l_io *pae_open(uint32_t ifindex)
{
	/*
	 * BPF filter to match skb->dev->type == 1 (ARPHRD_ETHER) and
	 * match skb->protocol == 0x888e (PAE) or 0x88c7 (preauthentication).
	 */
	struct sock_filter pae_filter[] = {
		{ 0x20,  0,  0, 0xfffff008 },	/* ld #ifidx		*/
		{ 0x15,  0,  6, 0x00000000 },	/* jne #0, drop		*/
		{ 0x28,  0,  0, 0xfffff01c },	/* ldh #hatype		*/
		{ 0x15,  0,  4, 0x00000001 },	/* jne #1, drop		*/
		{ 0x28,  0,  0, 0xfffff000 },	/* ldh #proto		*/
		{ 0x15,  1,  0, 0x0000888e },	/* je  #0x888e, keep	*/
		{ 0x15,  0,  1, 0x000088c7 },	/* jne #0x88c7, drop	*/
		{ 0x06,  0,  0, 0xffffffff },	/* keep: ret #-1	*/
		{ 0x06,  0,  0, 0000000000 },	/* drop: ret #0		*/
	};

	const struct sock_fprog pae_fprog = {
		.len = L_ARRAY_SIZE(pae_filter),
		.filter = pae_filter
	};

	struct l_io *io;
	int fd;

	fd = socket(PF_PACKET, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK,
							htons(ETH_P_ALL));
	if (fd < 0)
		return NULL;

	/*
	 * Here we modify the k value in the BPF program above to match the
	 * given ifindex.  We do it this way instead of using bind to attach
	 * to a specific interface index to avoid having to re-open the fd
	 * whenever the device is powered down / up
	 */

	pae_filter[1].k = ifindex;

	if (setsockopt(fd, SOL_SOCKET, SO_ATTACH_FILTER,
					&pae_fprog, sizeof(pae_fprog)) < 0)
		goto error;

	io = l_io_new(fd);
	l_io_set_close_on_destroy(io, true);

	return io;

error:
	close(fd);
	return NULL;
}

static void netdev_create_from_genl(struct l_genl_msg *msg)
{
	struct l_genl_attr attr;
	uint16_t type, len;
	const void *data;
	const char *ifname = NULL;
	uint16_t ifname_len = 0;
	const uint8_t *ifaddr;
	const uint32_t *ifindex = NULL, *iftype = NULL;
	struct netdev *netdev;
	struct wiphy *wiphy = NULL;
	struct ifinfomsg *rtmmsg;
	size_t bufsize;
	const uint8_t action_neighbor_report_prefix[2] = { 0x05, 0x05 };
	const uint8_t action_sa_query_resp_prefix[2] = { 0x08, 0x01 };
	const uint8_t action_sa_query_req_prefix[2] = { 0x08, 0x00 };
	struct l_io *pae_io = NULL;
	const struct l_settings *settings = iwd_get_config();
	bool pae_over_nl80211;

	if (!l_genl_attr_init(&attr, msg))
		return;

	while (l_genl_attr_next(&attr, &type, &len, &data)) {
		switch (type) {
		case NL80211_ATTR_IFINDEX:
			if (len != sizeof(uint32_t)) {
				l_warn("Invalid interface index attribute");
				return;
			}

			ifindex = data;
			break;

		case NL80211_ATTR_IFNAME:
			if (len > IFNAMSIZ) {
				l_warn("Invalid interface name attribute");
				return;
			}

			ifname = data;
			ifname_len = len;
			break;

		case NL80211_ATTR_WIPHY:
			if (len != sizeof(uint32_t)) {
				l_warn("Invalid wiphy attribute");
				return;
			}

			wiphy = wiphy_find(*((uint32_t *) data));
			break;

		case NL80211_ATTR_IFTYPE:
			if (len != sizeof(uint32_t)) {
				l_warn("Invalid interface type attribute");
				return;
			}

			iftype = data;
			break;

		case NL80211_ATTR_MAC:
			if (len != ETH_ALEN) {
				l_warn("Invalid interface address attribute");
				return;
			}

			ifaddr = data;
			break;
		}
	}

	if (!wiphy)
		return;

	if (!iftype) {
		l_warn("Missing iftype attribute");
		return;
	}

	if (!ifindex || !ifaddr | !ifname) {
		l_warn("Unable to parse interface information");
		return;
	}

	if (netdev_find(*ifindex)) {
		l_debug("Skipping duplicate netdev %s[%d]", ifname, *ifindex);
		return;
	}

	if (!netdev_is_managed(ifname)) {
		l_debug("interface %s filtered out", ifname);
		return;
	}

	if (!l_settings_get_bool(settings, "General",
				"ControlPortOverNL80211", &pae_over_nl80211)) {
		pae_over_nl80211 = false;
		l_info("No ControlPortOverNL80211 setting, defaulting to %s",
			pae_over_nl80211 ? "True" : "False");
	}

	if (!wiphy_has_ext_feature(wiphy,
			NL80211_EXT_FEATURE_CONTROL_PORT_OVER_NL80211)) {
		l_debug("No Control Port over NL80211 support for ifindex: %u,"
				" using PAE socket", *ifindex);
		pae_over_nl80211 = false;
	}

	if (!pae_over_nl80211) {
		pae_io = pae_open(*ifindex);
		if (!pae_io) {
			l_error("Unable to open PAE interface");
			return;
		}
	}

	netdev = l_new(struct netdev, 1);
	netdev->index = *ifindex;
	netdev->type = *iftype;
	netdev->rekey_offload_support = true;
	memcpy(netdev->addr, ifaddr, sizeof(netdev->addr));
	memcpy(netdev->name, ifname, ifname_len);
	netdev->wiphy = wiphy;
	netdev->pae_over_nl80211 = pae_over_nl80211;

	if (pae_io) {
		netdev->pae_io = pae_io;
		l_io_set_read_handler(netdev->pae_io, netdev_pae_read, netdev,
							netdev_pae_destroy);
	}

	watchlist_init(&netdev->event_watches, NULL);
	watchlist_init(&netdev->frame_watches, &netdev_frame_watch_ops);

	l_queue_push_tail(netdev_list, netdev);

	l_debug("Created interface %s[%d]", netdev->name, netdev->index);

	/* Query interface flags */
	bufsize = NLMSG_ALIGN(sizeof(struct ifinfomsg));
	rtmmsg = l_malloc(bufsize);
	memset(rtmmsg, 0, bufsize);

	rtmmsg->ifi_family = AF_UNSPEC;
	rtmmsg->ifi_index = *ifindex;

	l_netlink_send(rtnl, RTM_GETLINK, 0, rtmmsg, bufsize,
					netdev_getlink_cb, netdev, NULL);

	l_free(rtmmsg);

	/* Subscribe to Management -> Action -> RM -> Neighbor Report frames */
	netdev_frame_watch_add(netdev, 0x00d0, action_neighbor_report_prefix,
				sizeof(action_neighbor_report_prefix),
				netdev_neighbor_report_frame_event, NULL);

	netdev_frame_watch_add(netdev, 0x00d0, action_sa_query_resp_prefix,
				sizeof(action_sa_query_resp_prefix),
				netdev_sa_query_resp_frame_event, NULL);

	netdev_frame_watch_add(netdev, 0x00d0, action_sa_query_req_prefix,
				sizeof(action_sa_query_req_prefix),
				netdev_sa_query_req_frame_event, NULL);

	/* Set RSSI threshold for CQM notifications */
	netdev_cqm_rssi_update(netdev);
}

static void netdev_get_interface_callback(struct l_genl_msg *msg,
								void *user_data)
{
	netdev_create_from_genl(msg);
}

static void netdev_config_notify(struct l_genl_msg *msg, void *user_data)
{
	struct l_genl_attr attr;
	uint16_t type, len;
	const void *data;
	uint8_t cmd;
	const uint32_t *wiphy_id = NULL;
	const uint32_t *ifindex = NULL;
	struct netdev *netdev;

	cmd = l_genl_msg_get_command(msg);

	if (cmd == NL80211_CMD_NEW_INTERFACE) {
		netdev_create_from_genl(msg);
		return;
	}

	if (cmd != NL80211_CMD_DEL_INTERFACE)
		return;

	if (!l_genl_attr_init(&attr, msg))
		return;

	while (l_genl_attr_next(&attr, &type, &len, &data)) {
		switch (type) {
		case NL80211_ATTR_WIPHY:
			if (len != sizeof(uint32_t)) {
				l_warn("Invalid wiphy attribute");
				return;
			}

			wiphy_id = data;
			break;

		case NL80211_ATTR_IFINDEX:
			if (len != sizeof(uint32_t)) {
				l_warn("Invalid ifindex attribute");
				return;
			}

			ifindex = data;
			break;
		}
	}

	if (!wiphy_id || !ifindex)
		return;

	netdev = l_queue_remove_if(netdev_list, netdev_match,
						L_UINT_TO_PTR(*ifindex));
	if (!netdev)
		return;

	netdev_free(netdev);
}

static void netdev_link_notify(uint16_t type, const void *data, uint32_t len,
							void *user_data)
{
	const struct ifinfomsg *ifi = data;
	unsigned int bytes;

	if (ifi->ifi_type != ARPHRD_ETHER)
		return;

	bytes = len - NLMSG_ALIGN(sizeof(struct ifinfomsg));

	switch (type) {
	case RTM_NEWLINK:
		netdev_newlink_notify(ifi, bytes);
		break;
	case RTM_DELLINK:
		netdev_dellink_notify(ifi, bytes);
		break;
	}
}

uint32_t netdev_watch_add(struct netdev *netdev, netdev_watch_func_t func,
				void *user_data)
{
	return watchlist_add(&netdev->event_watches, func, user_data, NULL);
}

bool netdev_watch_remove(struct netdev *netdev, uint32_t id)
{
	return watchlist_remove(&netdev->event_watches, id);
}

bool netdev_init(struct l_genl_family *in,
				const char *whitelist, const char *blacklist)
{
	struct l_genl_msg *msg;
	struct l_genl *genl = l_genl_family_get_genl(in);

	if (rtnl)
		return false;

	l_debug("Opening route netlink socket");

	rtnl = l_netlink_new(NETLINK_ROUTE);
	if (!rtnl) {
		l_error("Failed to open route netlink socket");
		return false;
	}

	if (getenv("IWD_RTNL_DEBUG"))
		l_netlink_set_debug(rtnl, do_debug, "[RTNL] ", NULL);

	if (!l_netlink_register(rtnl, RTNLGRP_LINK,
				netdev_link_notify, NULL, NULL)) {
		l_error("Failed to register for RTNL link notifications");
		l_netlink_destroy(rtnl);
		return false;
	}

	netdev_list = l_queue_new();

	nl80211 = in;

	if (!l_genl_family_register(nl80211, "config", netdev_config_notify,
								NULL, NULL))
		l_error("Registering for config notification failed");

	msg = l_genl_msg_new(NL80211_CMD_GET_INTERFACE);
	if (!l_genl_family_dump(nl80211, msg, netdev_get_interface_callback,
								NULL, NULL))
		l_error("Getting all interface information failed");

	if (!l_genl_family_register(nl80211, "mlme", netdev_mlme_notify,
								NULL, NULL))
		l_error("Registering for MLME notification failed");

	if (!l_genl_set_unicast_handler(genl, netdev_unicast_notify,
								NULL, NULL))
		l_error("Registering for unicast notification failed");

	__handshake_set_install_tk_func(netdev_set_tk);
	__handshake_set_install_gtk_func(netdev_set_gtk);
	__handshake_set_install_igtk_func(netdev_set_igtk);

	__eapol_set_rekey_offload_func(netdev_set_rekey_offload);
	__eapol_set_tx_packet_func(netdev_control_port_frame);

	if (whitelist)
		whitelist_filter = l_strsplit(whitelist, ',');

	if (blacklist)
		blacklist_filter = l_strsplit(blacklist, ',');

	return true;
}

bool netdev_exit(void)
{
	if (!rtnl)
		return false;

	l_strfreev(whitelist_filter);
	l_strfreev(blacklist_filter);

	nl80211 = NULL;

	l_debug("Closing route netlink socket");
	l_netlink_destroy(rtnl);
	rtnl = NULL;

	return true;
}

void netdev_shutdown(void)
{
	if (!rtnl)
		return;

	l_queue_foreach(netdev_list, netdev_shutdown_one, NULL);

	l_queue_destroy(netdev_list, netdev_free);
	netdev_list = NULL;
}
