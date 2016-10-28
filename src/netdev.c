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
#include "src/crypto.h"
#include "src/device.h"
#include "src/scan.h"
#include "src/netdev.h"
#include "src/wscutil.h"

struct netdev {
	uint32_t index;
	char name[IFNAMSIZ];
	uint32_t type;
	uint8_t addr[ETH_ALEN];
	struct device *device;
	struct wiphy *wiphy;
	unsigned int ifi_flags;

	netdev_event_func_t event_filter;
	netdev_connect_cb_t connect_cb;
	netdev_disconnect_cb_t disconnect_cb;
	void *user_data;
	struct eapol_sm *sm;
	uint8_t remote_addr[ETH_ALEN];
	uint32_t pairwise_new_key_cmd_id;
	uint32_t pairwise_set_key_cmd_id;
	uint32_t group_new_key_cmd_id;
	uint32_t group_management_new_key_cmd_id;
	uint32_t connect_cmd_id;
	uint32_t disconnect_cmd_id;
	enum netdev_result result;

	struct l_queue *watches;
	uint32_t next_watch_id;

	bool connected : 1;
	bool operational : 1;
	bool eapol_active : 1;
	bool rekey_offload_support : 1;
};

struct netdev_watch {
	uint32_t id;
	netdev_watch_func_t callback;
	void *user_data;
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

struct cb_data {
	netdev_command_func_t callback;
	void *user_data;
};

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

	bufsize = sizeof(struct ifinfomsg) +
		RTA_SPACE(sizeof(uint8_t)) + RTA_SPACE(sizeof(uint8_t));

	rtmmsg = l_malloc(bufsize);
	memset(rtmmsg, 0, bufsize);

	rtmmsg->ifi_family = AF_UNSPEC;
	rtmmsg->ifi_index = ifindex;

	rta_buf = rtmmsg + 1;

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

uint32_t netdev_get_iftype(struct netdev *netdev)
{
	return netdev->type;
}

const char *netdev_get_name(struct netdev *netdev)
{
	return netdev->name;
}

bool netdev_get_is_up(struct netdev *netdev)
{
	return (netdev->ifi_flags & IFF_UP) != 0;
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

	cb_data->callback(cb_data->netdev, -error, cb_data->user_data);
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

	bufsize = sizeof(struct ifinfomsg);

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

static void netdev_operstate_dormant_cb(bool success, void *user_data)
{
	struct netdev *netdev = user_data;

	l_debug("netdev: %d, success: %d", netdev->index, success);
}

static void netdev_operstate_down_cb(bool success, void *user_data)
{
	uint32_t index = L_PTR_TO_UINT(user_data);

	l_debug("netdev: %d, success: %d", index, success);
}

static void netdev_connect_free(struct netdev *netdev)
{
	if (netdev->sm) {
		eapol_sm_free(netdev->sm);
		netdev->sm = NULL;
	}

	if (netdev->eapol_active) {
		eapol_cancel(netdev->index);
		netdev->eapol_active = false;
	}

	netdev->operational = false;
	netdev->connected = false;
	netdev->connect_cb = NULL;
	netdev->event_filter = NULL;
	netdev->user_data = NULL;
	netdev->result = NETDEV_RESULT_OK;

	if (netdev->pairwise_new_key_cmd_id) {
		l_genl_family_cancel(nl80211, netdev->pairwise_new_key_cmd_id);
		netdev->pairwise_new_key_cmd_id = 0;
	}

	if (netdev->pairwise_set_key_cmd_id) {
		l_genl_family_cancel(nl80211, netdev->pairwise_set_key_cmd_id);
		netdev->pairwise_set_key_cmd_id = 0;
	}

	if (netdev->group_new_key_cmd_id) {
		l_genl_family_cancel(nl80211, netdev->group_new_key_cmd_id);
		netdev->group_new_key_cmd_id = 0;
	}

	if (netdev->group_management_new_key_cmd_id) {
		l_genl_family_cancel(nl80211,
			netdev->group_management_new_key_cmd_id);
		netdev->group_management_new_key_cmd_id = 0;
	}

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
	void *connect_data = netdev->user_data;
	enum netdev_result result = netdev->result;

	netdev->disconnect_cmd_id = 0;

	/* Done this way to allow re-entract netdev_connect calls */
	netdev_connect_free(netdev);

	if (connect_cb)
		connect_cb(netdev, result, connect_data);
}

static void netdev_free(void *data)
{
	struct netdev *netdev = data;

	l_debug("Freeing netdev %s[%d]", netdev->name, netdev->index);

	if (netdev->connected) {
		netdev->result = NETDEV_RESULT_ABORTED;
		netdev_connect_failed(NULL, netdev);
	} else if (netdev->disconnect_cmd_id) {
		l_genl_family_cancel(nl80211, netdev->disconnect_cmd_id);
		netdev->disconnect_cmd_id = 0;

		if (netdev->disconnect_cb)
			netdev->disconnect_cb(netdev, true, netdev->user_data);

		netdev->disconnect_cb = NULL;
		netdev->user_data = NULL;
	}

	device_remove(netdev->device);

	l_queue_destroy(netdev->watches, l_free);

	l_free(netdev);
}

static void netdev_shutdown_one(void *data, void *user_data)
{
	struct netdev *netdev = data;

	netdev_set_linkmode_and_operstate(netdev->index, 0, IF_OPER_DOWN,
						netdev_operstate_down_cb,
						L_UINT_TO_PTR(netdev->index));

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

	netdev_connect_free(netdev);
}

static void netdev_cqm_event(struct l_genl_msg *msg, struct netdev *netdev)
{
	struct l_genl_attr attr;
	struct l_genl_attr nested;
	uint16_t type, len;
	const void *data;

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
				}
			}

			break;
		}
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
							netdev->remote_addr,
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

	if (!netdev->connected || netdev->disconnect_cmd_id > 0)
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

	if (disconnect_by_ap && event_filter)
		event_filter(netdev, NETDEV_EVENT_DISCONNECT_BY_AP,
							event_data);
}

static void netdev_deauthenticate_event(struct l_genl_msg *msg,
							struct netdev *netdev)
{
	l_debug("");
}

static void netdev_cmd_deauthenticate_cb(struct l_genl_msg *msg,
								void *user_data)
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

static struct l_genl_msg *netdev_build_cmd_deauthenticate(struct netdev *netdev,
							uint16_t reason_code)
{
	struct l_genl_msg *msg;

	msg = l_genl_msg_new_sized(NL80211_CMD_DEAUTHENTICATE, 128);
	l_genl_msg_append_attr(msg, NL80211_ATTR_IFINDEX, 4, &netdev->index);
	l_genl_msg_append_attr(msg, NL80211_ATTR_REASON_CODE, 2, &reason_code);
	l_genl_msg_append_attr(msg, NL80211_ATTR_MAC, ETH_ALEN,
							netdev->remote_addr);

	return msg;
}

static void netdev_operstate_cb(bool success, void *user_data)
{
	struct netdev *netdev = user_data;

	if (!netdev->connected)
		return;

	if (!success) {
		struct l_genl_msg *msg;

		l_error("Setting LinkMode and OperState failed for ifindex: %d",
				netdev->index);

		netdev->result = NETDEV_RESULT_KEY_SETTING_FAILED;
		msg = netdev_build_cmd_deauthenticate(netdev,
						MPDU_REASON_CODE_UNSPECIFIED);
		netdev->disconnect_cmd_id = l_genl_family_send(nl80211, msg,
							netdev_connect_failed,
							netdev, NULL);
		return;
	}

	netdev->operational = true;

	if (netdev->connect_cb) {
		netdev->connect_cb(netdev, NETDEV_RESULT_OK, netdev->user_data);
		netdev->connect_cb = NULL;
	}
}

static void netdev_setting_keys_failed(struct netdev *netdev,
							uint16_t reason_code)
{
	struct l_genl_msg *msg;

	/*
	 * Something went wrong with our new_key, set_key, new_key,
	 * set_station
	 *
	 * Cancel all pending commands, then de-authenticate
	 */
	l_genl_family_cancel(nl80211, netdev->pairwise_new_key_cmd_id);
	netdev->pairwise_new_key_cmd_id = 0;

	l_genl_family_cancel(nl80211, netdev->pairwise_set_key_cmd_id);
	netdev->pairwise_set_key_cmd_id = 0;

	l_genl_family_cancel(nl80211, netdev->group_new_key_cmd_id);
	netdev->group_new_key_cmd_id = 0;

	l_genl_family_cancel(nl80211,
		netdev->group_management_new_key_cmd_id);
	netdev->group_management_new_key_cmd_id = 0;

	netdev->result = NETDEV_RESULT_KEY_SETTING_FAILED;
	msg = netdev_build_cmd_deauthenticate(netdev,
						MPDU_REASON_CODE_UNSPECIFIED);
	netdev->disconnect_cmd_id = l_genl_family_send(nl80211, msg,
							netdev_connect_failed,
							netdev, NULL);
}

static void netdev_set_station_cb(struct l_genl_msg *msg, void *user_data)
{
	struct netdev *netdev = user_data;

	if (!netdev->connected)
		return;

	if (l_genl_msg_get_error(msg) < 0) {
		l_error("Set Station failed for ifindex %d", netdev->index);
		netdev_setting_keys_failed(netdev,
						MPDU_REASON_CODE_UNSPECIFIED);
		return;
	}

	netdev_set_linkmode_and_operstate(netdev->index, 1, IF_OPER_UP,
						netdev_operstate_cb, netdev);
}

static struct l_genl_msg *netdev_build_cmd_set_station(struct netdev *netdev)
{
	struct l_genl_msg *msg;
	struct nl80211_sta_flag_update flags;

	flags.mask = 1 << NL80211_STA_FLAG_AUTHORIZED;
	flags.set = flags.mask;

	msg = l_genl_msg_new_sized(NL80211_CMD_SET_STATION, 512);

	l_genl_msg_append_attr(msg, NL80211_ATTR_IFINDEX, 4, &netdev->index);
	l_genl_msg_append_attr(msg, NL80211_ATTR_MAC,
						ETH_ALEN, netdev->remote_addr);
	l_genl_msg_append_attr(msg, NL80211_ATTR_STA_FLAGS2,
				sizeof(struct nl80211_sta_flag_update), &flags);

	return msg;
}

static void netdev_new_group_key_cb(struct l_genl_msg *msg, void *data)
{
	struct netdev *netdev = data;

	netdev->group_new_key_cmd_id = 0;

	if (l_genl_msg_get_error(msg) < 0) {
		l_error("New Key for Group Key failed for ifindex: %d",
				netdev->index);
		goto error;
	}

	msg = netdev_build_cmd_set_station(netdev);

	if (l_genl_family_send(nl80211, msg, netdev_set_station_cb,
							netdev, NULL) > 0)
		return;

error:
	netdev_setting_keys_failed(netdev, MPDU_REASON_CODE_UNSPECIFIED);
}

static void netdev_new_group_management_key_cb(struct l_genl_msg *msg,
					void *data)
{
	struct netdev *netdev = data;

	netdev->group_management_new_key_cmd_id = 0;

	if (l_genl_msg_get_error(msg) < 0) {
		l_error("New Key for Group Mgmt failed for ifindex: %d",
				netdev->index);
		netdev_setting_keys_failed(netdev,
			MPDU_REASON_CODE_UNSPECIFIED);
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

static void netdev_set_gtk(uint32_t ifindex, uint8_t key_index,
				const uint8_t *gtk, uint8_t gtk_len,
				const uint8_t *rsc, uint8_t rsc_len,
				uint32_t cipher, void *user_data)
{
	uint8_t gtk_buf[32];
	struct netdev *netdev;
	struct l_genl_msg *msg;

	netdev = netdev_find(ifindex);

	l_debug("%d", netdev->index);

	switch (cipher) {
	case CRYPTO_CIPHER_CCMP:
		memcpy(gtk_buf, gtk, 16);
		break;
	case CRYPTO_CIPHER_TKIP:
		/*
		 * Swap the TX and RX MIC key portions for supplicant.
		 * WPA_80211_v3_1_090922 doc's 3.3.4:
		 *   The MIC key used on the Client for transmit (TX) is in
		 *   bytes 24-31, and the MIC key used on the Client for
		 *   receive (RX) is in bytes 16-23 of the PTK.  That is,
		 *   assume that TX MIC and RX MIC referred to in Clause 8.7
		 *   are referenced to the Authenticator. Similarly, on the AP,
		 *   the MIC used for TX is in bytes 16-23, and the MIC key
		 *   used for RX is in bytes 24-31 of the PTK.
		 *
		 * Here apply this to the GTK instead of the PTK.
		 */
		memcpy(gtk_buf, gtk, 16);
		memcpy(gtk_buf + 16, gtk + 24, 8);
		memcpy(gtk_buf + 24, gtk + 16, 8);
		break;
	default:
		l_error("Unexpected cipher: %x", cipher);
		netdev_setting_keys_failed(netdev,
					MPDU_REASON_CODE_INVALID_GROUP_CIPHER);
		return;
	}

	if (crypto_cipher_key_len(cipher) != gtk_len) {
		l_error("Unexpected key length: %d", gtk_len);
		netdev_setting_keys_failed(netdev,
					MPDU_REASON_CODE_INVALID_GROUP_CIPHER);
		return;
	}

	msg = netdev_build_cmd_new_key_group(netdev, cipher, key_index,
						gtk_buf, gtk_len,
						rsc, rsc_len);
	netdev->group_new_key_cmd_id =
		l_genl_family_send(nl80211, msg, netdev_new_group_key_cb,
						netdev, NULL);

	if (netdev->group_new_key_cmd_id > 0)
		return;

	l_genl_msg_unref(msg);
	netdev_setting_keys_failed(netdev, MPDU_REASON_CODE_UNSPECIFIED);
}

static void netdev_set_igtk(uint32_t ifindex, uint8_t key_index,
				const uint8_t *igtk, uint8_t igtk_len,
				const uint8_t *ipn, uint8_t ipn_len,
				uint32_t cipher, void *user_data)
{
	uint8_t igtk_buf[16];
	struct netdev *netdev;
	struct l_genl_msg *msg;

	netdev = netdev_find(ifindex);

	l_debug("%d", netdev->index);

	switch (cipher) {
	case CRYPTO_CIPHER_BIP:
		memcpy(igtk_buf, igtk, 16);
		break;
	default:
		l_error("Unexpected cipher: %x", cipher);
		netdev_setting_keys_failed(netdev,
					MPDU_REASON_CODE_INVALID_GROUP_CIPHER);
		return;
	}

	if (crypto_cipher_key_len(cipher) != igtk_len) {
		l_error("Unexpected key length: %d", igtk_len);
		netdev_setting_keys_failed(netdev,
					MPDU_REASON_CODE_INVALID_GROUP_CIPHER);
		return;
	}

	msg = netdev_build_cmd_new_key_group(netdev, cipher, key_index,
						igtk_buf, igtk_len,
						ipn, ipn_len);
	netdev->group_management_new_key_cmd_id =
			l_genl_family_send(nl80211, msg,
				netdev_new_group_management_key_cb,
				netdev, NULL);

	if (netdev->group_management_new_key_cmd_id > 0)
		return;

	l_genl_msg_unref(msg);
	netdev_setting_keys_failed(netdev, MPDU_REASON_CODE_UNSPECIFIED);
}

static void netdev_set_pairwise_key_cb(struct l_genl_msg *msg, void *data)
{
	struct netdev *netdev = data;

	netdev->pairwise_set_key_cmd_id = 0;

	if (l_genl_msg_get_error(msg) >= 0)
		return;

	l_error("Set Key for Pairwise Key failed for ifindex: %d",
								netdev->index);
	netdev_setting_keys_failed(netdev, MPDU_REASON_CODE_UNSPECIFIED);
}

static struct l_genl_msg *netdev_build_cmd_set_key_pairwise(
							struct netdev *netdev)
{
	uint8_t key_id = 0;
	struct l_genl_msg *msg;

	msg = l_genl_msg_new_sized(NL80211_CMD_SET_KEY, 512);

	l_genl_msg_append_attr(msg, NL80211_ATTR_KEY_IDX, 1, &key_id);
	l_genl_msg_append_attr(msg, NL80211_ATTR_IFINDEX, 4, &netdev->index);

	l_genl_msg_append_attr(msg, NL80211_ATTR_KEY_DEFAULT, 0, NULL);

	l_genl_msg_enter_nested(msg, NL80211_ATTR_KEY_DEFAULT_TYPES);
	l_genl_msg_append_attr(msg, NL80211_KEY_DEFAULT_TYPE_UNICAST, 0, NULL);
	l_genl_msg_leave_nested(msg);

	return msg;
}

static void netdev_new_pairwise_key_cb(struct l_genl_msg *msg, void *data)
{
	struct netdev *netdev = data;

	netdev->pairwise_new_key_cmd_id = 0;

	if (l_genl_msg_get_error(msg) >= 0)
		return;

	l_error("New Key for Pairwise Key failed for ifindex: %d",
								netdev->index);
	netdev_setting_keys_failed(netdev, MPDU_REASON_CODE_UNSPECIFIED);
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

static void netdev_set_tk(uint32_t ifindex, const uint8_t *aa,
				const uint8_t *tk, uint32_t cipher,
				void *user_data)
{
	uint8_t tk_buf[32];
	struct netdev *netdev;
	struct l_genl_msg *msg;

	netdev = netdev_find(ifindex);
	if (!netdev)
		return;

	l_debug("%d", netdev->index);

	if (netdev->event_filter)
		netdev->event_filter(netdev, NETDEV_EVENT_SETTING_KEYS,
					netdev->user_data);

	switch (cipher) {
	case CRYPTO_CIPHER_CCMP:
		memcpy(tk_buf, tk, 16);
		break;
	case CRYPTO_CIPHER_TKIP:
		/*
		 * Swap the TX and RX MIC key portions for supplicant.
		 * WPA_80211_v3_1_090922 doc's 3.3.4:
		 *   The MIC key used on the Client for transmit (TX) is in
		 *   bytes 24-31, and the MIC key used on the Client for
		 *   receive (RX) is in bytes 16-23 of the PTK.  That is,
		 *   assume that TX MIC and RX MIC referred to in Clause 8.7
		 *   are referenced to the Authenticator. Similarly, on the AP,
		 *   the MIC used for TX is in bytes 16-23, and the MIC key
		 *   used for RX is in bytes 24-31 of the PTK.
		 */
		memcpy(tk_buf, tk, 16);
		memcpy(tk_buf + 16, tk + 24, 8);
		memcpy(tk_buf + 24, tk + 16, 8);
		break;
	default:
		l_error("Unexpected cipher: %x", cipher);
		netdev_setting_keys_failed(netdev,
				MPDU_REASON_CODE_INVALID_PAIRWISE_CIPHER);
		return;
	}

	msg = netdev_build_cmd_new_key_pairwise(netdev, cipher, aa,
						tk_buf,
						crypto_cipher_key_len(cipher));
	netdev->pairwise_new_key_cmd_id =
		l_genl_family_send(nl80211, msg, netdev_new_pairwise_key_cb,
						netdev, NULL);
	if (!netdev->pairwise_new_key_cmd_id) {
		l_genl_msg_unref(msg);
		goto error;
	}

	msg = netdev_build_cmd_set_key_pairwise(netdev);

	netdev->pairwise_set_key_cmd_id =
		l_genl_family_send(nl80211, msg, netdev_set_pairwise_key_cb,
						netdev, NULL);
	if (netdev->pairwise_set_key_cmd_id > 0)
		return;

	l_genl_msg_unref(msg);
error:
	netdev_setting_keys_failed(netdev, MPDU_REASON_CODE_UNSPECIFIED);
}

static void netdev_handshake_failed(uint32_t ifindex,
					const uint8_t *aa, const uint8_t *spa,
					uint16_t reason_code, void *user_data)
{
	struct l_genl_msg *msg;
	struct netdev *netdev;

	netdev = netdev_find(ifindex);
	if (!netdev)
		return;

	l_error("4-Way Handshake failed for ifindex: %d", ifindex);

	netdev->eapol_active = false;

	netdev->result = NETDEV_RESULT_HANDSHAKE_FAILED;
	msg = netdev_build_cmd_deauthenticate(netdev, reason_code);
	netdev->disconnect_cmd_id = l_genl_family_send(nl80211, msg,
						netdev_connect_failed,
						netdev, NULL);
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

	if (!netdev->rekey_offload_support)
		return;

	l_debug("%d", netdev->index);
	msg = netdev_build_cmd_replay_counter(netdev, kek, kck,
					replay_counter);
	l_genl_family_send(nl80211, msg, hardware_rekey_cb, netdev, NULL);

}

static void netdev_connect_event(struct l_genl_msg *msg,
							struct netdev *netdev)
{
	struct l_genl_attr attr;
	uint16_t type, len;
	const void *data;
	const uint16_t *status_code = NULL;

	l_debug("");

	if (!netdev->connected)
		return;

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
		}
	}

	/* AP Rejected the authenticate / associate */
	if (!status_code || *status_code != 0)
		goto error;

	if (netdev->eapol_active) {
		/*
		 * Start processing EAPoL frames now that the state machine
		 * has all the input data even in FT mode.
		 */
		eapol_start(netdev->sm);
		netdev->sm = NULL;

		if (netdev->event_filter)
			netdev->event_filter(netdev,
					NETDEV_EVENT_4WAY_HANDSHAKE,
					netdev->user_data);
	} else
		netdev_set_linkmode_and_operstate(netdev->index, 1, IF_OPER_UP,
						netdev_operstate_cb, netdev);

	return;

error:
	netdev->result = NETDEV_RESULT_ASSOCIATION_FAILED;
	netdev_connect_failed(NULL, netdev);
}

static void netdev_authenticate_event(struct l_genl_msg *msg,
							struct netdev *netdev)
{
	l_debug("");
}

static void netdev_associate_event(struct l_genl_msg *msg,
							struct netdev *netdev)
{
	l_debug("");
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
		if (netdev->sm) {
			eapol_register(netdev->index, netdev->sm);
			netdev->eapol_active = true;
		}

		return;
	}

	netdev->result = NETDEV_RESULT_ASSOCIATION_FAILED;
	netdev_connect_failed(NULL, netdev);
}

static struct l_genl_msg *netdev_build_cmd_connect(struct netdev *netdev,
							struct scan_bss *bss,
							struct eapol_sm *sm)
{
	uint32_t auth_type = NL80211_AUTHTYPE_OPEN_SYSTEM;
	struct l_genl_msg *msg;

	msg = l_genl_msg_new_sized(NL80211_CMD_CONNECT, 512);
	l_genl_msg_append_attr(msg, NL80211_ATTR_IFINDEX, 4, &netdev->index);
	l_genl_msg_append_attr(msg, NL80211_ATTR_WIPHY_FREQ,
						4, &bss->frequency);
	l_genl_msg_append_attr(msg, NL80211_ATTR_MAC, ETH_ALEN, bss->addr);
	l_genl_msg_append_attr(msg, NL80211_ATTR_SSID,
						bss->ssid_len, bss->ssid);
	l_genl_msg_append_attr(msg, NL80211_ATTR_AUTH_TYPE, 4, &auth_type);

	if (bss->capability & IE_BSS_CAP_PRIVACY)
		l_genl_msg_append_attr(msg, NL80211_ATTR_PRIVACY, 0, NULL);

	if (sm) {
		uint32_t cipher;
		uint32_t nl_cipher;
		size_t ie_len;
		const uint8_t *ie;

		cipher = eapol_sm_get_pairwise_cipher(sm);
		if (cipher == IE_RSN_CIPHER_SUITE_CCMP)
			nl_cipher = CRYPTO_CIPHER_CCMP;
		else
			nl_cipher = CRYPTO_CIPHER_TKIP;

		l_genl_msg_append_attr(msg, NL80211_ATTR_CIPHER_SUITES_PAIRWISE,
					4, &nl_cipher);

		cipher = eapol_sm_get_group_cipher(sm);
		if (cipher == IE_RSN_CIPHER_SUITE_CCMP)
			nl_cipher = CRYPTO_CIPHER_CCMP;
		else
			nl_cipher = CRYPTO_CIPHER_TKIP;

		l_genl_msg_append_attr(msg, NL80211_ATTR_CIPHER_SUITE_GROUP,
					4, &nl_cipher);

		l_genl_msg_append_attr(msg, NL80211_ATTR_CONTROL_PORT, 0, NULL);

		ie = eapol_sm_get_own_ie(sm, &ie_len);
		if (ie)
			l_genl_msg_append_attr(msg, NL80211_ATTR_IE,
								ie_len, ie);
	}

	return msg;
}

static int netdev_connect_common(struct netdev *netdev,
					struct l_genl_msg *cmd_connect,
					struct scan_bss *bss,
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
	memcpy(netdev->remote_addr, bss->addr, ETH_ALEN);
	netdev->connected = true;
	netdev->sm = sm;

	return 0;

}

int netdev_connect(struct netdev *netdev, struct scan_bss *bss,
				struct eapol_sm *sm,
				netdev_event_func_t event_filter,
				netdev_connect_cb_t cb, void *user_data)
{
	struct l_genl_msg *cmd_connect;

	if (netdev->connected)
		return -EISCONN;

	cmd_connect = netdev_build_cmd_connect(netdev, bss, sm);
	if (!cmd_connect)
		return -EINVAL;

	return netdev_connect_common(netdev, cmd_connect, bss, sm,
						event_filter, cb, user_data);
}

int netdev_connect_wsc(struct netdev *netdev, struct scan_bss *bss,
				struct eapol_sm *sm,
				netdev_event_func_t event_filter,
				netdev_connect_cb_t cb, void *user_data)
{
	struct l_genl_msg *cmd_connect;
	struct wsc_association_request request;
	uint8_t *pdu;
	size_t pdu_len;
	void *ie;
	size_t ie_len;

	if (netdev->connected)
		return -EISCONN;

	cmd_connect = netdev_build_cmd_connect(netdev, bss, NULL);
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

	return netdev_connect_common(netdev, cmd_connect, bss, sm,
						event_filter, cb, user_data);

error:
	l_genl_msg_unref(cmd_connect);
	return -ENOMEM;
}

int netdev_disconnect(struct netdev *netdev,
				netdev_disconnect_cb_t cb, void *user_data)
{
	struct l_genl_msg *deauthenticate;

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

	deauthenticate = netdev_build_cmd_deauthenticate(netdev,
					MPDU_REASON_CODE_DEAUTH_LEAVING);
	netdev->disconnect_cmd_id = l_genl_family_send(nl80211, deauthenticate,
				netdev_cmd_deauthenticate_cb, netdev, NULL);

	if (!netdev->disconnect_cmd_id) {
		l_genl_msg_unref(deauthenticate);
		return -EIO;
	}

	netdev->disconnect_cb = cb;
	netdev->user_data = user_data;

	return 0;
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
	}
}

struct netdev_watch_event_data {
	struct netdev *netdev;
	enum netdev_watch_event type;
};

static void netdev_watch_notify(void *data, void *user_data)
{
	struct netdev_watch *watch = data;
	struct netdev_watch_event_data *event = user_data;

	watch->callback(event->netdev, event->type, watch->user_data);
}

static void netdev_newlink_notify(const struct ifinfomsg *ifi, int bytes)
{
	struct netdev *netdev;
	bool old_up, new_up;
	char old_name[IFNAMSIZ];
	struct rtattr *attr;
	struct netdev_watch_event_data event;

	netdev = netdev_find(ifi->ifi_index);
	if (!netdev)
		return;

	old_up = netdev_get_is_up(netdev);
	strcpy(old_name, netdev->name);

	netdev->ifi_flags = ifi->ifi_flags;

	for (attr = IFLA_RTA(ifi); RTA_OK(attr, bytes);
			attr = RTA_NEXT(attr, bytes)) {
		if (attr->rta_type != IFLA_IFNAME)
			continue;

		strcpy(netdev->name, RTA_DATA(attr));

		break;
	}

	new_up = netdev_get_is_up(netdev);

	if (old_up != new_up) {
		event.netdev = netdev;
		event.type = new_up ? NETDEV_WATCH_EVENT_UP :
						NETDEV_WATCH_EVENT_DOWN;

		l_queue_foreach(netdev->watches, netdev_watch_notify, &event);
	}

	if (strcmp(old_name, netdev->name)) {
		event.netdev = netdev;
		event.type = NETDEV_WATCH_EVENT_NAME_CHANGE;

		l_queue_foreach(netdev->watches, netdev_watch_notify, &event);
	}
}

static void netdev_dellink_notify(const struct ifinfomsg *ifi, int bytes)
{
	struct netdev *netdev;

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

	netdev_set_linkmode_and_operstate(netdev->index, 1,
						IF_OPER_DORMANT,
						netdev_operstate_dormant_cb,
						netdev);

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

	if (!wiphy) {
		l_warn("Missing wiphy attribute or wiphy not found");
		return;
	}

	if (!iftype) {
		l_warn("Missing iftype attribute");
		return;
	}

	if (*iftype != NL80211_IFTYPE_STATION) {
		l_warn("Skipping non-STA interfaces");
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

	netdev = l_new(struct netdev, 1);
	netdev->index = *ifindex;
	netdev->type = *iftype;
	netdev->rekey_offload_support = true;
	memcpy(netdev->addr, ifaddr, sizeof(netdev->addr));
	memcpy(netdev->name, ifname, ifname_len);
	netdev->wiphy = wiphy;

	l_queue_push_tail(netdev_list, netdev);

	if (l_queue_length(netdev_list) == 1)
		eapol_pae_open();

	l_debug("Created interface %s[%d]", netdev->name, netdev->index);

	/* Query interface flags */
	bufsize = sizeof(struct ifinfomsg);
	rtmmsg = l_malloc(bufsize);
	memset(rtmmsg, 0, bufsize);

	rtmmsg->ifi_family = AF_UNSPEC;
	rtmmsg->ifi_index = *ifindex;

	l_netlink_send(rtnl, RTM_GETLINK, 0, rtmmsg, bufsize,
					netdev_getlink_cb, netdev, NULL);

	l_free(rtmmsg);
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

static bool netdev_watch_match(const void *a, const void *b)
{
	const struct netdev_watch *item = a;
	uint32_t id = L_PTR_TO_UINT(b);

	return item->id == id;
}

uint32_t netdev_watch_add(struct netdev *netdev, netdev_watch_func_t func,
				void *user_data)
{
	struct netdev_watch *item;

	item = l_new(struct netdev_watch, 1);
	item->id = ++netdev->next_watch_id;
	item->callback = func;
	item->user_data = user_data;

	if (!netdev->watches)
		netdev->watches = l_queue_new();

	l_queue_push_tail(netdev->watches, item);

	return item->id;
}

bool netdev_watch_remove(struct netdev *netdev, uint32_t id)
{
	struct netdev_watch *item;

	item = l_queue_remove_if(netdev->watches, netdev_watch_match,
					L_UINT_TO_PTR(id));
	if (!item)
		return false;

	l_free(item);

	return true;
}

bool netdev_init(struct l_genl_family *in,
				const char *whitelist, const char *blacklist)
{
	struct l_genl_msg *msg;

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

	__eapol_set_install_tk_func(netdev_set_tk);
	__eapol_set_install_gtk_func(netdev_set_gtk);
	__eapol_set_install_igtk_func(netdev_set_igtk);
	__eapol_set_deauthenticate_func(netdev_handshake_failed);
	__eapol_set_rekey_offload_func(netdev_set_rekey_offload);

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

	eapol_pae_close();
}
