/*
 *
 *  Wireless daemon for Linux
 *
 *  Copyright (C) 2015-2018  Intel Corporation. All rights reserved.
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

#define _GNU_SOURCE
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <time.h>
#include <sys/socket.h>
#include <limits.h>
#include <linux/if.h>
#include <linux/if_ether.h>
#include <ell/ell.h>

#include "linux/nl80211.h"
#include "src/iwd.h"
#include "src/wiphy.h"
#include "src/netdev.h"
#include "src/ie.h"
#include "src/common.h"
#include "src/network.h"
#include "src/knownnetworks.h"
#include "src/util.h"
#include "src/scan.h"

#define SCAN_MAX_INTERVAL 320
#define SCAN_INIT_INTERVAL 10

struct l_queue *scan_contexts = NULL;

static struct l_genl_family *nl80211 = NULL;
uint32_t scan_id = 0;
uint32_t next_scan_request_id = 0;

struct scan_periodic {
	struct l_timeout *timeout;
	uint16_t interval;
	scan_trigger_func_t trigger;
	scan_notify_func_t callback;
	void *userdata;
	bool rearm:1;
	bool retry:1;
	bool triggered:1;
	bool needs_active_scan:1;
	bool passive:1; /* Active or Passive scan? */
	struct l_queue *cmds;
};

struct scan_request {
	uint32_t id;
	scan_trigger_func_t trigger;
	scan_notify_func_t callback;
	void *userdata;
	scan_destroy_func_t destroy;
	bool passive:1; /* Active or Passive scan? */
	bool triggered:1;
	struct l_queue *cmds;
};

struct scan_context {
	uint32_t ifindex;
	enum scan_state state;
	struct scan_periodic sp;
	struct l_queue *requests;
	unsigned int start_cmd_id;
	struct wiphy *wiphy;
};

struct scan_results {
	uint32_t wiphy;
	uint32_t ifindex;
	struct l_queue *bss_list;
	struct scan_freq_set *freqs;
};

static bool start_next_scan_request(struct scan_context *sc);
static void scan_periodic_rearm(struct scan_context *sc);

static bool scan_context_match(const void *a, const void *b)
{
	const struct scan_context *sc = a;
	uint32_t ifindex = L_PTR_TO_UINT(b);

	return (sc->ifindex == ifindex);
}

static bool scan_request_match(const void *a, const void *b)
{
	const struct scan_request *sr = a;
	uint32_t id = L_PTR_TO_UINT(b);

	return sr->id == id;
}

static void scan_request_free(void *data)
{
	struct scan_request *sr = data;

	l_queue_destroy(sr->cmds, (l_queue_destroy_func_t) l_genl_msg_unref);

	l_free(sr);
}

static void scan_request_trigger_failed(struct scan_request *sr, int err)
{
	if (sr->trigger)
		sr->trigger(err, sr->userdata);

	if (sr->destroy)
		sr->destroy(sr->userdata);

	scan_request_free(sr);
}

static struct scan_context *scan_context_new(uint32_t ifindex)
{
	struct netdev *netdev = netdev_find(ifindex);
	struct wiphy *wiphy;
	struct scan_context *sc;

	if (!netdev)
		return NULL;

	wiphy = netdev_get_wiphy(netdev);
	if (!wiphy)
		return NULL;

	sc = l_new(struct scan_context, 1);

	sc->ifindex = ifindex;
	sc->wiphy = wiphy;
	sc->state = SCAN_STATE_NOT_RUNNING;
	sc->requests = l_queue_new();

	return sc;
}

static void scan_context_free(struct scan_context *sc)
{
	l_debug("sc: %p", sc);

	l_queue_destroy(sc->sp.cmds, (l_queue_destroy_func_t) l_genl_msg_unref);

	l_queue_destroy(sc->requests, scan_request_free);

	if (sc->sp.timeout)
		l_timeout_remove(sc->sp.timeout);

	l_free(sc);
}

bool scan_ifindex_add(uint32_t ifindex)
{
	struct scan_context *sc;

	sc = l_queue_find(scan_contexts, scan_context_match,
				L_UINT_TO_PTR(ifindex));

	if (sc)
		return false;

	sc = scan_context_new(ifindex);
	if (!sc)
		return false;

	l_queue_push_head(scan_contexts, sc);

	return true;
}

bool scan_ifindex_remove(uint32_t ifindex)
{
	struct scan_context *sc;

	sc = l_queue_remove_if(scan_contexts, scan_context_match,
				L_UINT_TO_PTR(ifindex));

	if (!sc)
		return false;

	if (sc->start_cmd_id)
		l_genl_family_cancel(nl80211, sc->start_cmd_id);

	l_info("Removing scan context for ifindex: %u", ifindex);
	scan_context_free(sc);

	return true;
}

static unsigned int scan_send_start(struct l_genl_msg **msg,
			scan_func_t callback, void *user_data)
{
	unsigned int id = l_genl_family_send(nl80211, *msg, callback,
						user_data, NULL);

	if (id)
		*msg = NULL;
	else
		l_error("Sending NL80211_CMD_TRIGGER_SCAN failed");

	return id;
}

static void scan_triggered(struct l_genl_msg *msg, void *userdata)
{
	struct scan_context *sc = userdata;
	struct scan_request *sr = l_queue_peek_head(sc->requests);
	int err;

	l_debug("");

	sc->start_cmd_id = 0;

	err = l_genl_msg_get_error(msg);
	if (err < 0) {
		/* Scan in progress, defer */
		if (err == -EBUSY)
			return;

		l_queue_pop_head(sc->requests);
		scan_request_trigger_failed(sr, err);

		l_error("Received error during CMD_TRIGGER_SCAN: %s (%d)",
			strerror(-err), -err);

		start_next_scan_request(sc);

		return;
	}

	sc->state = sr->passive ? SCAN_STATE_PASSIVE : SCAN_STATE_ACTIVE;
	l_debug("%s scan triggered for ifindex: %u",
		sr->passive ? "Passive" : "Active", sc->ifindex);
	sr->triggered = true;

	if (sr->trigger) {
		sr->trigger(0, sr->userdata);

		/*
		 * Reset callback for the consequent scan triggerings of the
		 * multi-segmented scans.
		 */
		sr->trigger = NULL;
	}
}

struct scan_freq_append_data {
	struct l_genl_msg *msg;
	int count;
};

static void scan_freq_append(uint32_t freq, void *user_data)
{
	struct scan_freq_append_data *data = user_data;

	l_genl_msg_append_attr(data->msg, data->count++, 4, &freq);
}

static void scan_build_attr_scan_frequencies(struct l_genl_msg *msg,
						struct scan_freq_set *freqs)
{
	struct scan_freq_append_data append_data = { msg, 0 };

	l_genl_msg_enter_nested(msg, NL80211_ATTR_SCAN_FREQUENCIES);

	scan_freq_set_foreach(freqs, scan_freq_append, &append_data);

	l_genl_msg_leave_nested(msg);
}

static void scan_freq_count(uint32_t freq, void *user_data)
{
	int *count = user_data;

	*count += 1;
}

static struct l_genl_msg *scan_build_cmd(struct scan_context *sc,
					bool ignore_flush_flag,
					const struct scan_parameters *params)
{
	struct l_genl_msg *msg;
	int n_channels = 0;
	uint32_t flags = 0;

	if (params->freqs)
		scan_freq_set_foreach(params->freqs, scan_freq_count,
					&n_channels);

	msg = l_genl_msg_new_sized(NL80211_CMD_TRIGGER_SCAN,
						64 + params->extra_ie_size +
						4 * n_channels);

	l_genl_msg_append_attr(msg, NL80211_ATTR_IFINDEX, 4, &sc->ifindex);

	if (params->extra_ie && params->extra_ie_size)
		l_genl_msg_append_attr(msg, NL80211_ATTR_IE,
						params->extra_ie_size,
						params->extra_ie);

	if (params->freqs)
		scan_build_attr_scan_frequencies(msg, params->freqs);

	if (params->flush && !ignore_flush_flag)
		flags |= NL80211_SCAN_FLAG_FLUSH;

	/*
	 * TODO: Discovery of the hidden networks with randomization flag set
	 * works with real hardware, but fails when used in simulated
	 * environment with mac80211_hwsim. This needs to be investigated.
	 *
	 * if (params->randomize_mac_addr_hint &&
	 *		wiphy_has_feature(sc->wiphy,
	 *				  NL80211_FEATURE_SCAN_RANDOM_MAC_ADDR))
	 *
	 *	Randomizing 46 bits (locally administered 1 and multicast 0
	 *	is assumed).
	 *
	 *	flags |= NL80211_SCAN_FLAG_RANDOM_ADDR;
	*/

	if (flags)
		l_genl_msg_append_attr(msg, NL80211_ATTR_SCAN_FLAGS, 4, &flags);

	return msg;
}

struct scan_cmds_add_data {
	struct scan_context *sc;
	const struct scan_parameters *params;
	struct l_queue *cmds;
	struct l_genl_msg **cmd;
	uint8_t max_ssids_per_scan;
	uint8_t num_ssids_can_append;
};

static bool scan_cmds_add_hidden(const struct network_info *network,
					void *user_data)
{
	struct scan_cmds_add_data *data = user_data;

	if (!network->is_hidden)
		return true;

	l_genl_msg_append_attr(*data->cmd, NL80211_ATTR_SSID,
				strlen(network->ssid), network->ssid);
	data->num_ssids_can_append--;

	if (!data->num_ssids_can_append) {
		l_genl_msg_leave_nested(*data->cmd);
		l_queue_push_tail(data->cmds, *data->cmd);

		data->num_ssids_can_append = data->max_ssids_per_scan;

		/*
		 * Create a consecutive scan trigger in the batch of scans.
		 * The 'flush' flag is ignored, this allows to get the results
		 * of all scans in the batch after the last scan is finished.
		 */
		*data->cmd = scan_build_cmd(data->sc, true, data->params);
		l_genl_msg_enter_nested(*data->cmd, NL80211_ATTR_SCAN_SSIDS);
	}

	return true;
}

static void scan_cmds_add(struct l_queue *cmds, struct scan_context *sc,
				bool passive,
				const struct scan_parameters *params)
{
	struct l_genl_msg *cmd;
	struct scan_cmds_add_data data = {
		sc,
		params,
		cmds,
		&cmd,
		wiphy_get_max_num_ssids_per_scan(sc->wiphy),
	};

	cmd = scan_build_cmd(sc, false, params);

	if (passive) {
		/* passive scan */
		l_queue_push_tail(cmds, cmd);
		return;
	}

	l_genl_msg_enter_nested(cmd, NL80211_ATTR_SCAN_SSIDS);

	if (params->ssid) {
		/* direct probe request scan */
		l_genl_msg_append_attr(cmd, NL80211_ATTR_SSID,
					strlen(params->ssid), params->ssid);
		l_genl_msg_leave_nested(cmd);

		l_queue_push_tail(cmds, cmd);
		return;
	}

	data.num_ssids_can_append = data.max_ssids_per_scan;
	known_networks_foreach(scan_cmds_add_hidden, &data);

	l_genl_msg_append_attr(cmd, NL80211_ATTR_SSID, 0, NULL);
	l_genl_msg_leave_nested(cmd);
	l_queue_push_tail(cmds, cmd);
}

static int scan_request_send_next(struct scan_context *sc,
					struct scan_request *sr)
{
	struct l_genl_msg *cmd = l_queue_pop_head(sr->cmds);
	if (!cmd)
		return -ENOMSG;

	sc->start_cmd_id = scan_send_start(&cmd, scan_triggered, sc);
	if (sc->start_cmd_id) {
		sr->triggered = false;
		return 0;
	}

	l_genl_msg_unref(cmd);
	return -EIO;
}

static uint32_t scan_common(uint32_t ifindex, bool passive,
				const struct scan_parameters *params,
				scan_trigger_func_t trigger,
				scan_notify_func_t notify, void *userdata,
				scan_destroy_func_t destroy)
{
	struct scan_context *sc;
	struct scan_request *sr;

	sc = l_queue_find(scan_contexts, scan_context_match,
				L_UINT_TO_PTR(ifindex));

	if (!sc)
		return 0;

	sr = l_new(struct scan_request, 1);
	sr->trigger = trigger;
	sr->callback = notify;
	sr->userdata = userdata;
	sr->destroy = destroy;
	sr->passive = passive;
	sr->id = ++next_scan_request_id;
	sr->cmds = l_queue_new();

	scan_cmds_add(sr->cmds, sc, passive, params);

	if (l_queue_length(sc->requests) > 0)
		goto done;

	if (sc->state != SCAN_STATE_NOT_RUNNING || sc->start_cmd_id)
		goto done;

	if (!scan_request_send_next(sc, sr))
		goto done;

	scan_request_free(sr);
	return 0;
done:
	l_queue_push_tail(sc->requests, sr);

	return sr->id;
}

uint32_t scan_passive(uint32_t ifindex, scan_trigger_func_t trigger,
			scan_notify_func_t notify, void *userdata,
			scan_destroy_func_t destroy)
{
	struct scan_parameters params = {};

	return scan_common(ifindex, true, &params, trigger, notify,
							userdata, destroy);
}

uint32_t scan_active(uint32_t ifindex, uint8_t *extra_ie, size_t extra_ie_size,
			scan_trigger_func_t trigger,
			scan_notify_func_t notify, void *userdata,
			scan_destroy_func_t destroy)
{
	struct scan_parameters params = {};

	params.extra_ie = extra_ie;
	params.extra_ie_size = extra_ie_size;

	return scan_common(ifindex, false, &params,
					trigger, notify, userdata, destroy);
}

uint32_t scan_active_full(uint32_t ifindex,
			const struct scan_parameters *params,
			scan_trigger_func_t trigger, scan_notify_func_t notify,
			void *userdata, scan_destroy_func_t destroy)
{
	return scan_common(ifindex, false, params,
					trigger, notify, userdata, destroy);
}

bool scan_cancel(uint32_t ifindex, uint32_t id)
{
	struct scan_context *sc;
	struct scan_request *sr;

	sc = l_queue_find(scan_contexts, scan_context_match,
				L_UINT_TO_PTR(ifindex));

	if (!sc)
		return false;

	sr = l_queue_peek_head(sc->requests);
	if (!sr)
		return false;

	if (sr->id == id) {
		/* If we already sent the trigger command, cancel the scan */
		if (!sr->triggered && sc->start_cmd_id) {
			l_genl_family_cancel(nl80211, sc->start_cmd_id);
			sc->start_cmd_id = 0;

			l_queue_pop_head(sc->requests);

			start_next_scan_request(sc);

			goto free;
		}

		/* If already triggered, just zero out the callback */
		sr->callback = NULL;

		if (sr->destroy) {
			sr->destroy(sr->userdata);
			sr->destroy = NULL;
		}

		return true;
	}

	sr = l_queue_remove_if(sc->requests, scan_request_match,
							L_UINT_TO_PTR(id));
	if (!sr)
		return false;

free:
	if (sr->destroy)
		sr->destroy(sr->userdata);

	scan_request_free(sr);

	return true;
}

void scan_sched_start(struct l_genl_family *nl80211, uint32_t ifindex,
			uint32_t scan_interval,
			scan_func_t callback, void *user_data)
{
	struct l_genl_msg *msg;

	scan_interval *= 1000;	/* in kernel the interval is in msecs */

	msg = l_genl_msg_new_sized(NL80211_CMD_START_SCHED_SCAN, 32);
	l_genl_msg_append_attr(msg, NL80211_ATTR_IFINDEX, 4, &ifindex);
	l_genl_msg_append_attr(msg, NL80211_ATTR_SCHED_SCAN_INTERVAL,
							4, &scan_interval);
	l_genl_msg_append_attr(msg, NL80211_ATTR_SOCKET_OWNER, 0, NULL);

	if (!l_genl_family_send(nl80211, msg, callback, user_data, NULL))
		l_error("Starting scheduled scan failed");
}

static void scan_periodic_triggered(struct l_genl_msg *msg, void *user_data)
{
	struct scan_context *sc = user_data;
	int err;

	l_debug("");
	sc->sp.rearm = true;

	sc->start_cmd_id = 0;

	err = l_genl_msg_get_error(msg);
	if (err < 0) {
		/* Scan already in progress */
		if (err != -EBUSY)
			l_warn("Periodic scan could not be triggered: %s (%d)",
				strerror(-err), -err);

		if (!start_next_scan_request(sc))
			scan_periodic_rearm(sc);

		return;
	}

	sc->state = sc->sp.passive ? SCAN_STATE_PASSIVE : SCAN_STATE_ACTIVE;
	l_debug("Periodic %s scan triggered for ifindex: %u", sc->sp.passive ?
				"passive" : "active", sc->ifindex);

	sc->sp.triggered = true;

	if (sc->sp.trigger)
		sc->sp.trigger(0, sc->sp.userdata);
}

static bool scan_periodic_send_start(struct scan_context *sc)
{
	struct l_genl_msg *cmd;
	struct scan_parameters params = {};

	if (sc->sp.needs_active_scan && known_networks_has_hidden()) {
		sc->sp.needs_active_scan = false;
		sc->sp.passive = false;

		params.randomize_mac_addr_hint = true;
	} else {
		sc->sp.passive = true;
	}

	scan_cmds_add(sc->sp.cmds, sc, sc->sp.passive, &params);

	cmd = l_queue_pop_head(sc->sp.cmds);
	if (!cmd)
		return false;

	sc->start_cmd_id = scan_send_start(&cmd, scan_periodic_triggered, sc);
	if (!sc->start_cmd_id) {
		l_genl_msg_unref(cmd);
		return false;
	}

	return true;
}

static bool scan_periodic_is_disabled(void)
{
	const struct l_settings *config = iwd_get_config();
	bool disabled;

	if (!l_settings_get_bool(config, "Scan", "disable_periodic_scan",
								&disabled))
		return false;

	return disabled;
}

void scan_periodic_start(uint32_t ifindex, scan_trigger_func_t trigger,
				scan_notify_func_t func, void *userdata)
{
	struct scan_context *sc;

	if (scan_periodic_is_disabled())
		return;

	sc = l_queue_find(scan_contexts, scan_context_match,
				L_UINT_TO_PTR(ifindex));

	if (!sc) {
		l_error("scan_periodic_start called without scan_ifindex_add");
		return;
	}

	if (sc->sp.interval)
		return;

	l_debug("Starting periodic scan for ifindex: %u", ifindex);

	sc->sp.interval = SCAN_INIT_INTERVAL;
	sc->sp.trigger = trigger;
	sc->sp.callback = func;
	sc->sp.userdata = userdata;
	sc->sp.retry = true;
	sc->sp.rearm = false;
	sc->sp.cmds = l_queue_new();

	start_next_scan_request(sc);
}

bool scan_periodic_stop(uint32_t ifindex)
{
	struct scan_context *sc;

	sc = l_queue_find(scan_contexts, scan_context_match,
				L_UINT_TO_PTR(ifindex));

	if (!sc)
		return false;

	if (!sc->sp.interval)
		return false;

	l_debug("Stopping periodic scan for ifindex: %u", ifindex);

	if (sc->sp.timeout) {
		l_timeout_remove(sc->sp.timeout);
		sc->sp.timeout = NULL;
	}

	sc->sp.interval = 0;
	sc->sp.trigger = NULL;
	sc->sp.callback = NULL;
	sc->sp.userdata = NULL;
	sc->sp.rearm = false;
	sc->sp.retry = false;
	sc->sp.needs_active_scan = false;

	l_queue_destroy(sc->sp.cmds, (l_queue_destroy_func_t) l_genl_msg_unref);
	sc->sp.cmds = NULL;

	return true;
}

static void scan_periodic_timeout(struct l_timeout *timeout, void *user_data)
{
	struct scan_context *sc = user_data;

	l_debug("scan_periodic_timeout: %u", sc->ifindex);

	sc->sp.interval *= 2;

	sc->sp.retry = true;
	start_next_scan_request(sc);
}

static void scan_periodic_rearm(struct scan_context *sc)
{
	l_debug("Arming periodic scan timer: %u", sc->sp.interval);

	if (sc->sp.timeout)
		l_timeout_modify(sc->sp.timeout, sc->sp.interval);
	else
		sc->sp.timeout = l_timeout_create(sc->sp.interval,
					scan_periodic_timeout, sc, NULL);

	sc->sp.rearm = false;
}

static bool start_next_scan_request(struct scan_context *sc)
{
	struct scan_request *sr;

	if (sc->state != SCAN_STATE_NOT_RUNNING || sc->start_cmd_id)
		return true;

	while (!l_queue_isempty(sc->requests)) {
		sr = l_queue_peek_head(sc->requests);

		if (!scan_request_send_next(sc, sr))
			return true;

		l_queue_pop_head(sc->requests);
		scan_request_trigger_failed(sr, -EIO);
	}

	if (sc->sp.retry) {
		if (scan_periodic_send_start(sc)) {
			sc->sp.retry = false;
			return true;
		}
	}

	return false;
}

static bool scan_parse_bss_information_elements(struct scan_bss *bss,
					const void *data, uint16_t len)
{
	struct ie_tlv_iter iter;
	bool have_ssid = false;

	ie_tlv_iter_init(&iter, data, len);

	while (ie_tlv_iter_next(&iter)) {
		uint8_t tag = ie_tlv_iter_get_tag(&iter);

		switch (tag) {
		case IE_TYPE_SSID:
			if (iter.len > 32)
				return false;

			memcpy(bss->ssid, iter.data, iter.len);
			bss->ssid_len = iter.len;
			have_ssid = true;
			break;
		case IE_TYPE_SUPPORTED_RATES:
		case IE_TYPE_EXTENDED_SUPPORTED_RATES:
			if (ie_parse_supported_rates(&iter,
						&bss->supported_rates) < 0)
				l_warn("Unable to parse [Extended] "
					"Supported Rates IE for "
					MAC, MAC_STR(bss->addr));
			break;
		case IE_TYPE_RSN:
			if (!bss->rsne)
				bss->rsne = l_memdup(iter.data - 2,
								iter.len + 2);
			break;
		case IE_TYPE_BSS_LOAD:
			if (ie_parse_bss_load(&iter, NULL, &bss->utilization,
						NULL) < 0)
				l_warn("Unable to parse BSS Load IE for "
					MAC, MAC_STR(bss->addr));
			else
				l_debug("Load: %u/255", bss->utilization);

			break;
		case IE_TYPE_VENDOR_SPECIFIC:
			/* Interested only in WPA IE from Vendor data */
			if (!bss->wpa && is_ie_wpa_ie(iter.data, iter.len))
				bss->wpa = l_memdup(iter.data - 2,
								iter.len + 2);
			break;
		case IE_TYPE_MOBILITY_DOMAIN:
			if (!bss->mde_present && iter.len == 3) {
				memcpy(bss->mde, iter.data, iter.len);
				bss->mde_present = true;
			}

			break;
		case IE_TYPE_RM_ENABLED_CAPABILITIES:
			if (iter.len != 5)
				break;

			/* Only interested in Neighbor Reports */

			bss->cap_rm_neighbor_report =
				(iter.data[0] & IE_RM_CAP_NEIGHBOR_REPORT) > 0;
			break;
		case IE_TYPE_COUNTRY:
			if (bss->cc_present || iter.len < 6)
				break;

			bss->cc[0] = iter.data[0];
			bss->cc[1] = iter.data[1];
			bss->cc[2] = iter.data[2];
			bss->cc_present = true;

			break;
		}
	}

	return have_ssid;
}

static struct scan_bss *scan_parse_attr_bss(struct l_genl_attr *attr)
{
	uint16_t type, len;
	const void *data;
	struct scan_bss *bss;

	bss = l_new(struct scan_bss, 1);
	bss->utilization = 127;

	while (l_genl_attr_next(attr, &type, &len, &data)) {
		switch (type) {
		case NL80211_BSS_BSSID:
			if (len != sizeof(bss->addr))
				goto fail;

			memcpy(bss->addr, data, len);
			break;
		case NL80211_BSS_CAPABILITY:
			if (len != sizeof(uint16_t))
				goto fail;

			bss->capability = *((uint16_t *) data);
			break;
		case NL80211_BSS_FREQUENCY:
			if (len != sizeof(uint32_t))
				goto fail;

			bss->frequency = *((uint32_t *) data);
			break;
		case NL80211_BSS_SIGNAL_MBM:
			if (len != sizeof(int32_t))
				goto fail;

			bss->signal_strength = *((int32_t *) data);
			break;
		case NL80211_BSS_INFORMATION_ELEMENTS:
			if (!scan_parse_bss_information_elements(bss,
								data, len))
				goto fail;

			bss->wsc = ie_tlv_extract_wsc_payload(data, len,
								&bss->wsc_size);

			break;
		}
	}

	return bss;

fail:
	scan_bss_free(bss);
	return NULL;
}

static struct scan_freq_set *scan_parse_attr_scan_frequencies(
						struct l_genl_attr *attr)
{
	uint16_t type, len;
	const void *data;
	struct scan_freq_set *set;

	set = scan_freq_set_new();

	while (l_genl_attr_next(attr, &type, &len, &data)) {
		uint32_t freq;

		if (len != sizeof(uint32_t))
			continue;

		freq = *((uint32_t *) data);
		scan_freq_set_add(set, freq);
	}

	return set;
}

static struct scan_bss *scan_parse_result(struct l_genl_msg *msg,
					uint32_t *out_ifindex,
					uint64_t *out_wdev)
{
	struct l_genl_attr attr, nested;
	uint16_t type, len;
	const void *data;
	uint32_t ifindex;
	uint64_t wdev;
	struct scan_bss *bss = NULL;

	if (!l_genl_attr_init(&attr, msg))
		return NULL;

	while (l_genl_attr_next(&attr, &type, &len, &data)) {
		switch (type) {
		case NL80211_ATTR_IFINDEX:
			if (len != sizeof(uint32_t))
				return NULL;

			ifindex = *((uint32_t *) data);
			break;

		case NL80211_ATTR_WDEV:
			if (len != sizeof(uint64_t))
				return NULL;

			wdev = *((uint64_t *) data);
			break;

		case NL80211_ATTR_BSS:
			if (!l_genl_attr_recurse(&attr, &nested))
				return NULL;

			bss = scan_parse_attr_bss(&nested);
			break;
		}
	}

	if (!bss)
		return NULL;

	if (out_ifindex)
		*out_ifindex = ifindex;

	if (out_wdev)
		*out_wdev = wdev;

	return bss;
}

static void scan_bss_compute_rank(struct scan_bss *bss)
{
	static const double RANK_RSNE_FACTOR = 1.2;
	static const double RANK_WPA_FACTOR = 1.0;
	static const double RANK_OPEN_FACTOR = 0.5;
	static const double RANK_NO_PRIVACY_FACTOR = 0.5;
	static const double RANK_5G_FACTOR = 1.1;
	static const double RANK_HIGH_UTILIZATION_FACTOR = 0.8;
	static const double RANK_LOW_UTILIZATION_FACTOR = 1.2;
	static const double RANK_MIN_SUPPORTED_RATE_FACTOR = 0.8;
	static const double RANK_MAX_SUPPORTED_RATE_FACTOR = 1.1;
	double rank;
	uint32_t irank;

	/*
	 * Signal strength is in mBm (100 * dBm) and is negative.
	 * WiFi range is -0 to -100 dBm
	 */

	/* Heavily slanted towards signal strength */
	rank = 10000 + bss->signal_strength;

	/*
	 * Prefer RSNE first, WPA second.  Open networks are much less
	 * desirable.
	 */
	if (bss->rsne)
		rank *= RANK_RSNE_FACTOR;
	else if (bss->wpa)
		rank *= RANK_WPA_FACTOR;
	else
		rank *= RANK_OPEN_FACTOR;

	/* We prefer networks with CAP PRIVACY */
	if (!(bss->capability & IE_BSS_CAP_PRIVACY))
		rank *= RANK_NO_PRIVACY_FACTOR;

	/* Prefer 5G networks over 2.4G */
	if (bss->frequency > 4000)
		rank *= RANK_5G_FACTOR;

	/* Rank loaded APs lower and lighly loaded APs higher */
	if (bss->utilization >= 192)
		rank *= RANK_HIGH_UTILIZATION_FACTOR;
	else if (bss->utilization <= 63)
		rank *= RANK_LOW_UTILIZATION_FACTOR;

	if (bss->supported_rates) {
		uint8_t max = l_uintset_find_max(bss->supported_rates);
		double factor = RANK_MAX_SUPPORTED_RATE_FACTOR -
					RANK_MIN_SUPPORTED_RATE_FACTOR;

		/*
		 * Maximum rate is 54 Mbps, see DATA_RATE in 802.11-2012,
		 * Section 6.5.5.2
		 */
		factor = factor * max / 108 + RANK_MIN_SUPPORTED_RATE_FACTOR;
		rank *= factor;
	}

	irank = rank;

	if (irank > USHRT_MAX)
		bss->rank = USHRT_MAX;
	else
		bss->rank = irank;
}

void scan_bss_free(struct scan_bss *bss)
{
	l_uintset_free(bss->supported_rates);
	l_free(bss->rsne);
	l_free(bss->wpa);
	l_free(bss->wsc);
	l_free(bss);
}

int scan_bss_get_rsn_info(const struct scan_bss *bss, struct ie_rsn_info *info)
{
	/*
	 * If both an RSN and a WPA elements are present currently
	 * RSN takes priority and the WPA IE is ignored.
	 */
	if (bss->rsne) {
		int res = ie_parse_rsne_from_data(bss->rsne, bss->rsne[1] + 2,
							info);
		if (res < 0) {
			l_debug("Cannot parse RSN field (%d, %s)",
					res, strerror(-res));
			return res;
		}
	} else if (bss->wpa) {
		int res = ie_parse_wpa_from_data(bss->wpa, bss->wpa[1] + 2,
							info);
		if (res < 0) {
			l_debug("Cannot parse WPA IE (%d, %s)",
					res, strerror(-res));
			return res;
		}
	} else
		return -ENOENT;

	return 0;
}

int scan_bss_rank_compare(const void *a, const void *b, void *user_data)
{
	const struct scan_bss *new_bss = a, *bss = b;

	return bss->rank - new_bss->rank;
}

static void get_scan_callback(struct l_genl_msg *msg, void *user_data)
{
	struct scan_results *results = user_data;
	struct scan_bss *bss;
	uint32_t ifindex;

	l_debug("get_scan_callback");

	if (!results->bss_list)
		results->bss_list = l_queue_new();

	bss = scan_parse_result(msg, &ifindex, NULL);
	if (!bss)
		return;

	if (ifindex != results->ifindex) {
		l_warn("ifindex mismatch in get_scan_callback");
		scan_bss_free(bss);
		return;
	}

	scan_bss_compute_rank(bss);
	l_queue_insert(results->bss_list, bss, scan_bss_rank_compare, NULL);
}

static void discover_hidden_network_bsses(struct scan_context *sc,
						struct l_queue *bss_list)
{
	const struct l_queue_entry *bss_entry;

	for (bss_entry = l_queue_get_entries(bss_list); bss_entry;
						bss_entry = bss_entry->next) {
		struct scan_bss *bss = bss_entry->data;

		if (!util_ssid_is_hidden(bss->ssid_len, bss->ssid))
			continue;

		sc->sp.needs_active_scan = true;
	}
}

static void scan_finished(struct scan_context *sc, uint32_t wiphy,
				int err, struct l_queue *bss_list)
{
	struct scan_request *sr;
	scan_notify_func_t callback = NULL;
	void *userdata;
	scan_destroy_func_t destroy = NULL;
	bool new_owner = false;

	sr = l_queue_peek_head(sc->requests);
	if (sr && sr->triggered) {
		callback = sr->callback;
		userdata = sr->userdata;
		destroy = sr->destroy;

		scan_request_free(sr);
		l_queue_pop_head(sc->requests);
	} else if (sc->sp.interval) {
		/*
		 * If we'd called sc.sp->trigger, we must call back now
		 * independent of whether the scan was succesful or was
		 * aborted.  If the scan was successful though we call back
		 * with the scan results even if didn't triggered this scan.
		 */
		if (sc->sp.triggered || bss_list) {
			callback = sc->sp.callback;
			userdata = sc->sp.userdata;
			destroy = NULL;
		}

		sc->sp.triggered = false;

		if (bss_list)
			discover_hidden_network_bsses(sc, bss_list);
	}

	if (callback)
		new_owner = callback(wiphy, sc->ifindex, err,
					bss_list, userdata);

	if (destroy)
		destroy(userdata);

	sc->state = SCAN_STATE_NOT_RUNNING;

	if (!start_next_scan_request(sc) && sc->sp.rearm)
		scan_periodic_rearm(sc);

	if (bss_list && !new_owner)
		l_queue_destroy(bss_list,
				(l_queue_destroy_func_t) scan_bss_free);
}

static void get_scan_done(void *user)
{
	struct scan_results *results = user;
	struct scan_context *sc;

	l_debug("get_scan_done");

	sc = l_queue_find(scan_contexts, scan_context_match,
					L_UINT_TO_PTR(results->ifindex));
	if (sc)
		scan_finished(sc, results->wiphy, 0, results->bss_list);
	else
		l_queue_destroy(results->bss_list,
				(l_queue_destroy_func_t) scan_bss_free);

	if (results->freqs)
		scan_freq_set_free(results->freqs);

	l_free(results);
}

static void scan_parse_new_scan_results(struct l_genl_msg *msg,
					struct scan_results *results)
{
	struct l_genl_attr attr, nested;
	uint16_t type, len;
	const void *data;

	if (!l_genl_attr_init(&attr, msg))
		return;

	while (l_genl_attr_next(&attr, &type, &len, &data)) {
		switch (type) {
		case NL80211_ATTR_SCAN_FREQUENCIES:
			if (!l_genl_attr_recurse(&attr, &nested)) {
				l_warn("Failed to parse ATTR_SCAN_FREQUENCIES");
				break;
			}

			results->freqs =
				scan_parse_attr_scan_frequencies(&nested);
			break;
		}
	}
}

static bool scan_send_next_cmd(struct scan_context *sc)
{
	struct scan_request *sr = l_queue_peek_head(sc->requests);
	int err;

	if (sr && sr->triggered) {
		err = scan_request_send_next(sc, sr);
		if (!err)
			return true;

		/* Nothing left in the scan_request queue, we're done */
		if (err < 0 && err == -ENOMSG)
			return false;

		sr = l_queue_pop_head(sc->requests);
		scan_request_trigger_failed(sr, -EIO);

		/*
		 * The request is destroyed, return 'true' to stop further
		 * processing.
		 */
		return true;
	} else if (sc->sp.triggered) {
		struct l_genl_msg *cmd = l_queue_pop_head(sc->sp.cmds);
		if (!cmd)
			return false;

		sc->sp.triggered = false;

		sc->start_cmd_id = scan_send_start(&cmd,
						scan_periodic_triggered, sc);

		if (!sc->start_cmd_id) {
			l_genl_msg_unref(cmd);
			l_queue_clear(sc->sp.cmds,
				(l_queue_destroy_func_t) l_genl_msg_unref);
		}

		return true;
	}

	return false;
}

static void scan_notify(struct l_genl_msg *msg, void *user_data)
{
	struct l_genl_attr attr;
	uint16_t type, len;
	const void *data;
	uint8_t cmd;
	uint32_t uninitialized_var(attr_ifindex);
	bool have_ifindex;
	uint32_t uninitialized_var(attr_wiphy);
	bool have_wiphy;
	struct scan_context *sc;
	bool active_scan = false;

	cmd = l_genl_msg_get_command(msg);

	l_debug("Scan notification %u", cmd);

	if (!l_genl_attr_init(&attr, msg))
		return;

	while (l_genl_attr_next(&attr, &type, &len, &data)) {
		switch (type) {
		case NL80211_ATTR_WIPHY:
			if (len != sizeof(uint32_t)) {
				l_warn("Invalid wiphy attribute");
				return;
			}

			have_wiphy = true;
			attr_wiphy = *((uint32_t *) data);
			break;
		case NL80211_ATTR_IFINDEX:
			if (len != sizeof(uint32_t)) {
				l_warn("Invalid interface index attribute");
				return;
			}

			have_ifindex = true;
			attr_ifindex = *((uint32_t *) data);
			break;
		case NL80211_ATTR_SCAN_SSIDS:
			active_scan = true;
			break;
		}
	}

	if (!have_wiphy) {
		l_warn("Scan results do not contain wiphy attribute");
		return;
	}

	if (!have_ifindex) {
		l_warn("Scan results do not contain ifindex attribute");
		return;
	}

	sc = l_queue_find(scan_contexts, scan_context_match,
					L_UINT_TO_PTR(attr_ifindex));
	if (!sc)
		return;

	switch (cmd) {
	case NL80211_CMD_NEW_SCAN_RESULTS:
	case NL80211_CMD_SCHED_SCAN_RESULTS:
	{
		struct l_genl_msg *scan_msg;
		struct scan_results *results;

		if (scan_send_next_cmd(sc))
			return;

		results = l_new(struct scan_results, 1);
		results->wiphy = attr_wiphy;
		results->ifindex = attr_ifindex;

		scan_parse_new_scan_results(msg, results);

		scan_msg = l_genl_msg_new_sized(NL80211_CMD_GET_SCAN, 8);
		l_genl_msg_append_attr(scan_msg, NL80211_ATTR_IFINDEX, 4,
						&attr_ifindex);
		l_genl_family_dump(nl80211, scan_msg, get_scan_callback,
					results, get_scan_done);

		break;
	}

	case NL80211_CMD_TRIGGER_SCAN:
		if (active_scan)
			sc->state = SCAN_STATE_ACTIVE;
		else
			sc->state = SCAN_STATE_PASSIVE;

		break;

	case NL80211_CMD_SCAN_ABORTED:
		scan_finished(sc, attr_wiphy, -ECANCELED, NULL);

		break;
	}
}

uint8_t scan_freq_to_channel(uint32_t freq, enum scan_band *out_band)
{
	uint32_t channel = 0;

	if (freq >= 2412 && freq <= 2484) {
		if (freq == 2484)
			channel = 14;
		else {
			channel = freq - 2407;

			if (channel % 5)
				return 0;

			channel /= 5;
		}

		if (out_band)
			*out_band = SCAN_BAND_2_4_GHZ;

		return channel;
	}

	if (freq >= 5005 && freq < 5900) {
		if (channel % 5)
			return 0;

		channel = (freq - 5000) / 5;

		if (out_band)
			*out_band = SCAN_BAND_5_GHZ;

		return channel;
	}

	if (freq >= 4905 && freq < 5000) {
		if (channel % 5)
			return 0;

		channel = (freq - 4000) / 5;

		if (out_band)
			*out_band = SCAN_BAND_5_GHZ;

		return channel;
	}

	return 0;
}

uint32_t scan_channel_to_freq(uint8_t channel, enum scan_band band)
{
	if (band == SCAN_BAND_2_4_GHZ) {
		if (channel >= 1 && channel <= 13)
			return 2407 + 5 * channel;

		if (channel == 14)
			return 2484;
	}

	if (band == SCAN_BAND_5_GHZ) {
		if (channel >= 1 && channel <= 179)
			return 5000 + 5 * channel;

		if (channel >= 181 && channel <= 199)
			return 4000 + 5 * channel;
	}

	return 0;
}

static const char *const oper_class_us_codes[] = {
	"US", "CA"
};

static const char *const oper_class_eu_codes[] = {
	"AL", "AM", "AT", "AZ", "BA", "BE", "BG", "BY", "CH", "CY", "CZ", "DE",
	"DK", "EE", "EL", "ES", "FI", "FR", "GE", "HR", "HU", "IE", "IS", "IT",
	"LI", "LT", "LU", "LV", "MD", "ME", "MK", "MT", "NL", "NO", "PL", "PT",
	"RO", "RS", "RU", "SE", "SI", "SK", "TR", "UA", "UK"
};

/* Annex E, table E-1 */
static const uint8_t oper_class_us_to_global[] = {
	[1]  = 115, [2]  = 118, [3]  = 124, [4]  = 121,
	[5]  = 125, [6]  = 103, [7]  = 103, [8]  = 102,
	[9]  = 102, [10] = 101, [11] = 101, [12] = 81,
	[13] = 94,  [14] = 95,  [15] = 96,  [22] = 116,
	[23] = 119, [24] = 122, [25] = 126, [26] = 126,
	[27] = 117, [28] = 120, [29] = 123, [30] = 127,
	[31] = 127, [32] = 83,  [33] = 84,  [34] = 180,
	/* 128 - 130 is a 1 to 1 mapping */
};

/* Annex E, table E-2 */
static const uint8_t oper_class_eu_to_global[] = {
	[1]  = 115, [2]  = 118, [3]  = 121, [4]  = 81,
	[5]  = 116, [6]  = 119, [7]  = 122, [8]  = 117,
	[9]  = 120, [10] = 123, [11] = 83,  [12] = 84,
	[17] = 125, [18] = 130,
	/* 128 - 130 is a 1 to 1 mapping */
};

/* Annex E, table E-3 */
static const uint8_t oper_class_jp_to_global[] = {
	[1]  = 115, [2]  = 112, [3]  = 112, [4]  = 112,
	[5]  = 112, [6]  = 112, [7]  = 109, [8]  = 109,
	[9]  = 109, [10] = 109, [11] = 109, [12] = 113,
	[13] = 113, [14] = 113, [15] = 113, [16] = 110,
	[17] = 110, [18] = 110, [19] = 110, [20] = 110,
	[21] = 114, [22] = 114, [23] = 114, [24] = 114,
	[25] = 111, [26] = 111, [27] = 111, [28] = 111,
	[29] = 111, [30] = 81,  [31] = 82,  [32] = 118,
	[33] = 118, [34] = 121, [35] = 121, [36] = 116,
	[37] = 119, [38] = 119, [39] = 122, [40] = 122,
	[41] = 117, [42] = 120, [43] = 120, [44] = 123,
	[45] = 123, [46] = 104, [47] = 104, [48] = 104,
	[49] = 104, [50] = 104, [51] = 105, [52] = 105,
	[53] = 105, [54] = 105, [55] = 105, [56] = 83,
	[57] = 84,  [58] = 121, [59] = 180,
	/* 128 - 130 is a 1 to 1 mapping */
};

/* Annex E, table E-4 (only 2.4GHz and 4.9 / 5GHz bands) */
static const enum scan_band oper_class_to_band_global[] = {
	[81 ... 84]   = SCAN_BAND_2_4_GHZ,
	[104 ... 130] = SCAN_BAND_5_GHZ,
};

/* Annex E, table E-5 */
static const uint8_t oper_class_cn_to_global[] = {
	[1]  = 115, [2]  = 118, [3]  = 125, [4]  = 116,
	[5]  = 119, [6]  = 126, [7]  = 81,  [8]  = 83,
	[9]  = 84,
	/* 128 - 130 is a 1 to 1 mapping */
};

enum scan_band scan_oper_class_to_band(const uint8_t *country,
					uint8_t oper_class)
{
	unsigned int i;
	int table = 0;

	if (country && country[2] >= 1 && country[2] <= 5)
		table = country[2];
	else if (country) {
		for (i = 0; i < L_ARRAY_SIZE(oper_class_us_codes); i++)
			if (!memcmp(oper_class_us_codes[i], country, 2)) {
				/* Use table E-1 */
				table = 1;
				break;
			}

		for (i = 0; i < L_ARRAY_SIZE(oper_class_eu_codes); i++)
			if (!memcmp(oper_class_eu_codes[i], country, 2)) {
				/* Use table E-2 */
				table = 2;
				break;
			}

		if (!memcmp("JP", country, 2))
			/* Use table E-3 */
			table = 3;

		if (!memcmp("CN", country, 2))
			/* Use table E-5 */
			table = 5;
	}

	switch (table) {
	case 1:
		if (oper_class < L_ARRAY_SIZE(oper_class_us_to_global))
			oper_class = oper_class_us_to_global[oper_class];
		break;
	case 2:
		if (oper_class < L_ARRAY_SIZE(oper_class_eu_to_global))
			oper_class = oper_class_eu_to_global[oper_class];
		break;
	case 3:
		if (oper_class < L_ARRAY_SIZE(oper_class_jp_to_global))
			oper_class = oper_class_jp_to_global[oper_class];
		break;
	case 5:
		if (oper_class < L_ARRAY_SIZE(oper_class_cn_to_global))
			oper_class = oper_class_cn_to_global[oper_class];
		break;
	}

	if (oper_class < L_ARRAY_SIZE(oper_class_to_band_global))
		return oper_class_to_band_global[oper_class];
	else
		return 0;
}

struct scan_freq_set {
	uint16_t channels_2ghz;
	struct l_uintset *channels_5ghz;
};

struct scan_freq_set *scan_freq_set_new(void)
{
	struct scan_freq_set *ret = l_new(struct scan_freq_set, 1);

	/* 802.11-2012, 8.4.2.10 hints that 200 is the largest channel number */
	ret->channels_5ghz = l_uintset_new_from_range(1, 200);

	return ret;
}

void scan_freq_set_free(struct scan_freq_set *freqs)
{
	l_uintset_free(freqs->channels_5ghz);
	l_free(freqs);
}

bool scan_freq_set_add(struct scan_freq_set *freqs, uint32_t freq)
{
	enum scan_band band;
	uint8_t channel;

	channel = scan_freq_to_channel(freq, &band);
	if (!channel)
		return false;

	switch (band) {
	case SCAN_BAND_2_4_GHZ:
		freqs->channels_2ghz |= 1 << (channel - 1);
		return true;
	case SCAN_BAND_5_GHZ:
		return l_uintset_put(freqs->channels_5ghz, channel);
	}

	return false;
}

bool scan_freq_set_contains(struct scan_freq_set *freqs, uint32_t freq)
{
	enum scan_band band;
	uint8_t channel;

	channel = scan_freq_to_channel(freq, &band);
	if (!channel)
		return false;

	switch (band) {
	case SCAN_BAND_2_4_GHZ:
		return freqs->channels_2ghz & (1 << (channel - 1));
	case SCAN_BAND_5_GHZ:
		return l_uintset_contains(freqs->channels_5ghz, channel);
	}

	return false;
}

uint32_t scan_freq_set_get_bands(struct scan_freq_set *freqs)
{
	uint32_t bands = 0;
	uint32_t max;

	if (freqs->channels_2ghz)
		bands |= SCAN_BAND_2_4_GHZ;

	max = l_uintset_get_max(freqs->channels_5ghz);

	if (l_uintset_find_min(freqs->channels_5ghz) <= max)
		bands |= SCAN_BAND_5_GHZ;

	return bands;
}

void scan_freq_set_foreach(struct scan_freq_set *freqs,
				scan_freq_set_func_t func, void *user_data)
{
	uint8_t channel;
	uint32_t freq;

	for (channel = 1; channel <= 14; channel++)
		if (freqs->channels_2ghz & (1 << (channel - 1))) {
			freq = scan_channel_to_freq(channel, SCAN_BAND_2_4_GHZ);

			func(freq, user_data);
		}

	for (channel = 1; channel <= 200; channel++)
		if (l_uintset_contains(freqs->channels_5ghz, channel)) {
			freq = scan_channel_to_freq(channel, SCAN_BAND_5_GHZ);

			func(freq, user_data);
		}
}

bool scan_init(struct l_genl_family *in)
{
	nl80211 = in;
	scan_id = l_genl_family_register(nl80211, "scan", scan_notify,
						NULL, NULL);

	if (!scan_id) {
		l_error("Registering for scan notification failed");
		return false;
	}

	scan_contexts = l_queue_new();

	return true;
}

bool scan_exit()
{
	bool r;

	l_debug("");

	if (!nl80211)
		return false;

	l_queue_destroy(scan_contexts,
				(l_queue_destroy_func_t) scan_context_free);
	scan_contexts = NULL;

	r = l_genl_family_unregister(nl80211, scan_id);
	scan_id = 0;

	nl80211 = 0;

	return r;
}
