/*
 *
 *  Wireless daemon for Linux
 *
 *  Copyright (C) 2013-2018  Intel Corporation. All rights reserved.
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

#include <stdio.h>
#include <errno.h>
#include <time.h>
#include <linux/if_ether.h>

#include <ell/ell.h>

#include "src/iwd.h"
#include "src/common.h"
#include "src/util.h"
#include "src/ie.h"
#include "src/handshake.h"
#include "src/wiphy.h"
#include "src/scan.h"
#include "src/netdev.h"
#include "src/dbus.h"
#include "src/network.h"
#include "src/knownnetworks.h"
#include "src/device.h"
#include "src/watchlist.h"
#include "src/ap.h"
#include "src/adhoc.h"

struct device_watchlist_item {
	uint32_t id;
	device_watch_func_t added;
	device_watch_func_t removed;
	void *userdata;
	device_destroy_func_t destroy;
};

struct autoconnect_entry {
	uint16_t rank;
	struct network *network;
	struct scan_bss *bss;
};

struct device {
	uint32_t index;
	enum device_state state;
	struct l_queue *bss_list;
	struct l_queue *old_bss_list;
	struct l_dbus_message *scan_pending;
	struct l_hashmap *networks;
	struct l_queue *networks_sorted;
	struct scan_bss *connected_bss;
	struct network *connected_network;
	struct l_queue *autoconnect_list;
	struct l_dbus_message *connect_pending;
	struct l_dbus_message *disconnect_pending;
	uint32_t netdev_watch_id;
	struct watchlist state_watches;
	struct timespec roam_min_time;
	struct l_timeout *roam_trigger_timeout;
	uint32_t roam_scan_id;
	uint8_t preauth_bssid[ETH_ALEN];
	struct signal_agent *signal_agent;
	struct l_dbus_message *start_ap_pending;
	struct l_dbus_message *stop_ap_pending;

	struct wiphy *wiphy;
	struct netdev *netdev;

	bool scanning : 1;
	bool autoconnect : 1;
	bool preparing_roam : 1;
	bool signal_low : 1;
	bool roam_no_orig_ap : 1;
	bool ap_directed_roaming : 1;
	bool seen_hidden_networks : 1;

	uint32_t ap_roam_watch;

	enum device_mode mode;
};

struct signal_agent {
	char *owner;
	char *path;
	unsigned int disconnect_watch;
};

static struct watchlist device_watches;
static struct l_queue *device_list;

static void device_roam_timeout_rearm(struct device *device, int seconds);

static void device_netdev_event(struct netdev *netdev, enum netdev_event event,
					void *user_data);

uint32_t device_watch_add(device_watch_func_t func,
				void *userdata, device_destroy_func_t destroy)
{
	return watchlist_add(&device_watches, func, userdata, destroy);
}

bool device_watch_remove(uint32_t id)
{
	return watchlist_remove(&device_watches, id);
}

void __iwd_device_foreach(iwd_device_foreach_func func, void *user_data)
{
	const struct l_queue_entry *device_entry;

	for (device_entry = l_queue_get_entries(device_list); device_entry;
					device_entry = device_entry->next) {
		struct device *device = device_entry->data;

		func(device, user_data);
	}
}

static const char *iwd_network_get_path(struct device *device,
					const char *ssid,
					enum security security)
{
	static char path[256];
	unsigned int pos, i;

	pos = snprintf(path, sizeof(path), "%s/", device_get_path(device));

	for (i = 0; ssid[i] && pos < sizeof(path); i++)
		pos += snprintf(path + pos, sizeof(path) - pos, "%02x",
								ssid[i]);

	snprintf(path + pos, sizeof(path) - pos, "_%s",
				security_to_str(security));

	return path;
}

static const char *device_state_to_string(enum device_state state)
{
	switch (state) {
	case DEVICE_STATE_OFF:
		return "off";
	case DEVICE_STATE_DISCONNECTED:
		return "disconnected";
	case DEVICE_STATE_AUTOCONNECT:
		return "autoconnect";
	case DEVICE_STATE_CONNECTING:
		return "connecting";
	case DEVICE_STATE_CONNECTED:
		return "connected";
	case DEVICE_STATE_DISCONNECTING:
		return "disconnecting";
	case DEVICE_STATE_ROAMING:
		return "roaming";
	}

	return "invalid";
}

static void device_autoconnect_next(struct device *device)
{
	struct autoconnect_entry *entry;
	int r;

	while ((entry = l_queue_pop_head(device->autoconnect_list))) {
		l_debug("Considering autoconnecting to BSS '%s' with SSID: %s,"
			" freq: %u, rank: %u, strength: %i",
			util_address_to_string(entry->bss->addr),
			network_get_ssid(entry->network),
			entry->bss->frequency, entry->rank,
			entry->bss->signal_strength);

		/* TODO: Blacklist the network from auto-connect */
		r = network_autoconnect(entry->network, entry->bss);
		l_free(entry);

		if (!r)
			return;
	}
}

static void bss_free(void *data)
{
	struct scan_bss *bss = data;
	const char *addr;

	addr = util_address_to_string(bss->addr);
	l_debug("Freeing BSS %s", addr);

	scan_bss_free(bss);
}

static void network_free(void *data)
{
	struct network *network = data;

	network_remove(network, -ESHUTDOWN);
}

static int autoconnect_rank_compare(const void *a, const void *b, void *user)
{
	const struct autoconnect_entry *new_ae = a;
	const struct autoconnect_entry *ae = b;

	return ae->rank - new_ae->rank;
}

static bool process_network(const void *key, void *data, void *user_data)
{
	struct network *network = data;
	struct device *device = user_data;

	if (!network_bss_list_isempty(network)) {
		/* Build the network list ordered by rank */
		network_rank_update(network);

		l_queue_insert(device->networks_sorted, network,
				network_rank_compare, NULL);

		return false;
	}

	/* Drop networks that have no more BSSs in range */
	l_debug("No remaining BSSs for SSID: %s -- Removing network",
			network_get_ssid(network));
	network_remove(network, -ERANGE);

	return true;
}

static bool process_bss(struct device *device, struct scan_bss *bss,
			struct timespec *timestamp)
{
	struct network *network;
	struct ie_rsn_info info;
	int r;
	enum security security;
	const char *path;
	double rankmod;
	struct autoconnect_entry *entry;
	char ssid[33];

	l_debug("Found BSS '%s' with SSID: %s, freq: %u, rank: %u, "
			"strength: %i",
			util_address_to_string(bss->addr),
			util_ssid_to_utf8(bss->ssid_len, bss->ssid),
			bss->frequency, bss->rank, bss->signal_strength);

	if (util_ssid_is_hidden(bss->ssid_len, bss->ssid)) {
		l_debug("Ignoring BSS with hidden SSID");
		device->seen_hidden_networks = true;
		return false;
	}

	if (!util_ssid_is_utf8(bss->ssid_len, bss->ssid)) {
		l_debug("Ignoring BSS with non-UTF8 SSID");
		return false;
	}

	memcpy(ssid, bss->ssid, bss->ssid_len);
	ssid[bss->ssid_len] = '\0';

	memset(&info, 0, sizeof(info));
	r = scan_bss_get_rsn_info(bss, &info);
	if (r < 0) {
		if (r != -ENOENT)
			return false;

		security = security_determine(bss->capability, NULL);
	} else
		security = security_determine(bss->capability, &info);

	path = iwd_network_get_path(device, ssid, security);

	network = l_hashmap_lookup(device->networks, path);
	if (!network) {
		network = network_create(device, ssid, security);

		if (!network_register(network, path)) {
			network_remove(network, -EINVAL);
			return false;
		}

		l_hashmap_insert(device->networks,
					network_get_path(network), network);
		l_debug("Added new Network \"%s\" security %s",
			network_get_ssid(network), security_to_str(security));
	}

	network_bss_add(network, bss);

	if (device->state != DEVICE_STATE_AUTOCONNECT)
		return true;

	/* See if network is autoconnectable (is a known network) */
	if (!network_rankmod(network, &rankmod))
		return true;

	entry = l_new(struct autoconnect_entry, 1);
	entry->network = network;
	entry->bss = bss;
	entry->rank = bss->rank * rankmod;
	l_queue_insert(device->autoconnect_list, entry,
				autoconnect_rank_compare, NULL);

	return true;
}

static bool bss_match(const void *a, const void *b)
{
	const struct scan_bss *bss_a = a;
	const struct scan_bss *bss_b = b;

	return !memcmp(bss_a->addr, bss_b->addr, sizeof(bss_a->addr));
}

/*
 * Used when scan results were obtained; either from passive scan running
 * inside device.c or active scans running in other state machines, e.g. wsc.c
 */
void device_set_scan_results(struct device *device, struct l_queue *bss_list)
{
	struct network *network;
	const struct l_queue_entry *bss_entry;
	struct timespec now;

	clock_gettime(CLOCK_REALTIME, &now);

	device->old_bss_list = device->bss_list;
	device->bss_list = bss_list;

	device->seen_hidden_networks = false;

	while ((network = l_queue_pop_head(device->networks_sorted)))
		network_bss_list_clear(network);

	l_queue_destroy(device->autoconnect_list, l_free);
	device->autoconnect_list = l_queue_new();

	for (bss_entry = l_queue_get_entries(bss_list); bss_entry;
				bss_entry = bss_entry->next) {
		struct scan_bss *bss = bss_entry->data;

		process_bss(device, bss, &now);
	}

	if (device->connected_bss) {
		struct scan_bss *bss;

		bss = l_queue_find(device->bss_list, bss_match,
						device->connected_bss);

		if (!bss) {
			l_warn("Connected BSS not in scan results!");
			device->connected_bss->rank = 0;
			l_queue_push_tail(device->bss_list,
						device->connected_bss);
			network_bss_add(device->connected_network,
						device->connected_bss);
			l_queue_remove(device->old_bss_list,
						device->connected_bss);
		} else
			device->connected_bss = bss;
	}

	l_hashmap_foreach_remove(device->networks, process_network, device);

	l_queue_destroy(device->old_bss_list, bss_free);
	device->old_bss_list = NULL;

	if (device->state == DEVICE_STATE_AUTOCONNECT)
		device_autoconnect_next(device);
}

static bool new_scan_results(uint32_t wiphy_id, uint32_t ifindex, int err,
				struct l_queue *bss_list, void *userdata)
{
	struct device *device = userdata;
	struct l_dbus *dbus = dbus_get_bus();

	if (device->scanning) {
		device->scanning = false;
		l_dbus_property_changed(dbus, device_get_path(device),
					IWD_DEVICE_INTERFACE, "Scanning");
	}

	if (err)
		return false;

	if (device->mode == DEVICE_MODE_AP)
		return false;

	device_set_scan_results(device, bss_list);

	return true;
}

struct network *device_get_connected_network(struct device *device)
{
	return device->connected_network;
}

const char *device_get_path(struct device *device)
{
	static char path[26];

	snprintf(path, sizeof(path), "%s/%u", wiphy_get_path(device->wiphy),
			device->index);
	return path;
}

bool device_is_busy(struct device *device)
{
	if (device->state != DEVICE_STATE_DISCONNECTED &&
			device->state != DEVICE_STATE_AUTOCONNECT &&
			device->state != DEVICE_STATE_OFF)
		return true;

	return false;
}

struct wiphy *device_get_wiphy(struct device *device)
{
	return device->wiphy;
}

struct netdev *device_get_netdev(struct device *device)
{
	return device->netdev;
}

uint32_t device_get_ifindex(struct device *device)
{
	return device->index;
}

const uint8_t *device_get_address(struct device *device)
{
	return netdev_get_address(device->netdev);
}

enum device_state device_get_state(struct device *device)
{
	return device->state;
}

enum device_mode device_get_mode(struct device *device)
{
	return device->mode;
}

static void periodic_scan_trigger(int err, void *user_data)
{
	struct device *device = user_data;
	struct l_dbus *dbus = dbus_get_bus();

	device->scanning = true;
	l_dbus_property_changed(dbus, device_get_path(device),
				IWD_DEVICE_INTERFACE, "Scanning");
}

static void periodic_scan_stop(struct device *device)
{
	struct l_dbus *dbus = dbus_get_bus();

	scan_periodic_stop(device->index);

	if (device->scanning) {
		device->scanning = false;
		l_dbus_property_changed(dbus, device_get_path(device),
					IWD_DEVICE_INTERFACE, "Scanning");
	}
}

uint32_t device_add_state_watch(struct device *device,
					device_state_watch_func_t func,
					void *user_data,
					device_destroy_func_t destroy)
{
	return watchlist_add(&device->state_watches, func, user_data, destroy);
}

bool device_remove_state_watch(struct device *device, uint32_t id)
{
	return watchlist_remove(&device->state_watches, id);
}

struct network *device_network_find(struct device *device, const char *ssid,
					enum security security)
{
	const char *path = iwd_network_get_path(device, ssid, security);

	return l_hashmap_lookup(device->networks, path);
}

static void device_enter_state(struct device *device, enum device_state state)
{
	struct l_dbus *dbus = dbus_get_bus();
	bool disconnected;

	l_debug("Old State: %s, new state: %s",
			device_state_to_string(device->state),
			device_state_to_string(state));

	switch (state) {
	case DEVICE_STATE_OFF:
		periodic_scan_stop(device);
		break;
	case DEVICE_STATE_AUTOCONNECT:
		scan_periodic_start(device->index, periodic_scan_trigger,
					new_scan_results, device);
		break;
	case DEVICE_STATE_DISCONNECTED:
		periodic_scan_stop(device);
		break;
	case DEVICE_STATE_CONNECTED:
		periodic_scan_stop(device);
		break;
	case DEVICE_STATE_CONNECTING:
		break;
	case DEVICE_STATE_DISCONNECTING:
		break;
	case DEVICE_STATE_ROAMING:
		break;
	}

	disconnected = device->state <= DEVICE_STATE_AUTOCONNECT;

	if ((disconnected && state > DEVICE_STATE_AUTOCONNECT) ||
			(!disconnected && state != device->state))
		l_dbus_property_changed(dbus, device_get_path(device),
					IWD_DEVICE_INTERFACE, "State");

	device->state = state;

	WATCHLIST_NOTIFY(&device->state_watches,
					device_state_watch_func_t, state);
}

static void device_reset_connection_state(struct device *device)
{
	struct network *network = device->connected_network;
	struct l_dbus *dbus = dbus_get_bus();

	if (!network)
		return;

	if (device->state == DEVICE_STATE_CONNECTED ||
			device->state == DEVICE_STATE_CONNECTING ||
			device->state == DEVICE_STATE_ROAMING)
		network_disconnected(network);

	l_timeout_remove(device->roam_trigger_timeout);
	device->roam_trigger_timeout = NULL;
	device->preparing_roam = false;
	device->signal_low = false;
	device->roam_min_time.tv_sec = 0;

	if (device->roam_scan_id)
		scan_cancel(device->index, device->roam_scan_id);

	device->connected_bss = NULL;
	device->connected_network = NULL;

	l_dbus_property_changed(dbus, device_get_path(device),
				IWD_DEVICE_INTERFACE, "ConnectedNetwork");
	l_dbus_property_changed(dbus, network_get_path(network),
				IWD_NETWORK_INTERFACE, "Connected");
}

static void device_disassociated(struct device *device)
{
	l_debug("%d", device->index);

	device_reset_connection_state(device);

	device_enter_state(device, DEVICE_STATE_DISCONNECTED);

	if (device->autoconnect)
		device_enter_state(device, DEVICE_STATE_AUTOCONNECT);
}

static void device_disconnect_event(struct device *device)
{
	l_debug("%d", device->index);

	if (device->connect_pending) {
		struct network *network = device->connected_network;

		dbus_pending_reply(&device->connect_pending,
				dbus_error_failed(device->connect_pending));

		network_connect_failed(network);
	}

	device_disassociated(device);
}

static enum ie_rsn_akm_suite device_select_akm_suite(struct network *network,
						struct scan_bss *bss,
						struct ie_rsn_info *info)
{
	enum security security = network_get_security(network);

	/*
	 * If FT is available, use FT authentication to keep the door open
	 * for fast transitions.  Otherwise use SHA256 version if present.
	 */

	if (security == SECURITY_8021X) {
		if ((info->akm_suites & IE_RSN_AKM_SUITE_FT_OVER_8021X) &&
				bss->rsne && bss->mde_present)
			return IE_RSN_AKM_SUITE_FT_OVER_8021X;

		if (info->akm_suites & IE_RSN_AKM_SUITE_8021X_SHA256)
			return IE_RSN_AKM_SUITE_8021X_SHA256;

		if (info->akm_suites & IE_RSN_AKM_SUITE_8021X)
			return IE_RSN_AKM_SUITE_8021X;
	} else if (security == SECURITY_PSK) {
		if (info->akm_suites & IE_RSN_AKM_SUITE_SAE_SHA256)
			return IE_RSN_AKM_SUITE_SAE_SHA256;

		if ((info->akm_suites & IE_RSN_AKM_SUITE_FT_USING_PSK) &&
				bss->rsne && bss->mde_present)
			return IE_RSN_AKM_SUITE_FT_USING_PSK;

		if (info->akm_suites & IE_RSN_AKM_SUITE_PSK_SHA256)
			return IE_RSN_AKM_SUITE_PSK_SHA256;

		if (info->akm_suites & IE_RSN_AKM_SUITE_PSK)
			return IE_RSN_AKM_SUITE_PSK;
	}

	return 0;
}

static void device_handshake_event(struct handshake_state *hs,
					enum handshake_event event,
					void *event_data, void *user_data)
{
	struct device *device = user_data;
	struct network *network = device->connected_network;

	switch (event) {
	case HANDSHAKE_EVENT_STARTED:
		l_debug("Handshaking");
		break;
	case HANDSHAKE_EVENT_SETTING_KEYS:
		l_debug("Setting keys");

		/* If we got here, then our PSK works.  Save if required */
		network_sync_psk(network);
		break;
	case HANDSHAKE_EVENT_FAILED:
		netdev_handshake_failed(hs, l_get_u16(event_data));
		break;
	case HANDSHAKE_EVENT_SETTING_KEYS_FAILED:
	case HANDSHAKE_EVENT_COMPLETE:
		/*
		 * currently we dont care about any other events. The
		 * netdev_connect_cb will notify us when the connection is
		 * complete.
		 */
		break;
	}
}

static struct handshake_state *device_handshake_setup(struct device *device,
						struct network *network,
						struct scan_bss *bss)
{
	enum security security = network_get_security(network);
	struct wiphy *wiphy = device->wiphy;
	struct handshake_state *hs;
	bool add_mde = false;

	hs = netdev_handshake_state_new(device->netdev);

	handshake_state_set_event_func(hs, device_handshake_event, device);

	if (security == SECURITY_PSK || security == SECURITY_8021X) {
		const struct l_settings *settings = iwd_get_config();
		struct ie_rsn_info bss_info;
		uint8_t rsne_buf[256];
		struct ie_rsn_info info;
		const char *ssid;
		uint32_t mfp_setting;

		memset(&info, 0, sizeof(info));

		memset(&bss_info, 0, sizeof(bss_info));
		scan_bss_get_rsn_info(bss, &bss_info);

		info.akm_suites = device_select_akm_suite(network, bss,
								&bss_info);

		if (!info.akm_suites)
			goto not_supported;

		info.pairwise_ciphers = wiphy_select_cipher(wiphy,
						bss_info.pairwise_ciphers);
		info.group_cipher = wiphy_select_cipher(wiphy,
						bss_info.group_cipher);

		if (!info.pairwise_ciphers || !info.group_cipher)
			goto not_supported;

		if (!l_settings_get_uint(settings, "General",
				"ManagementFrameProtection", &mfp_setting))
			mfp_setting = 1;

		if (mfp_setting > 2) {
			l_error("Invalid MFP value, using default of 1");
			mfp_setting = 1;
		}

		switch (mfp_setting) {
		case 0:
			break;
		case 1:
			info.group_management_cipher =
				wiphy_select_cipher(wiphy,
					bss_info.group_management_cipher);
			info.mfpc = info.group_management_cipher != 0;
			break;
		case 2:
			info.group_management_cipher =
				wiphy_select_cipher(wiphy,
					bss_info.group_management_cipher);

			/*
			 * MFP required on our side, but AP doesn't support MFP
			 * or cipher mismatch
			 */
			if (info.group_management_cipher == 0)
				goto not_supported;

			info.mfpc = true;
			info.mfpr = true;
			break;
		}

		if (bss_info.mfpr && !info.mfpc)
			goto not_supported;

		ssid = network_get_ssid(network);
		handshake_state_set_ssid(hs, (void *) ssid, strlen(ssid));

		/* RSN takes priority */
		if (bss->rsne) {
			ie_build_rsne(&info, rsne_buf);
			handshake_state_set_ap_rsn(hs, bss->rsne);
			handshake_state_set_own_rsn(hs, rsne_buf);
		} else {
			ie_build_wpa(&info, rsne_buf);
			handshake_state_set_ap_wpa(hs, bss->wpa);
			handshake_state_set_own_wpa(hs, rsne_buf);
		}

		if (security == SECURITY_PSK)
			handshake_state_set_pmk(hs, network_get_psk(network),
						32);
		else
			handshake_state_set_8021x_config(hs,
						network_get_settings(network));

		if (info.akm_suites & (IE_RSN_AKM_SUITE_FT_OVER_8021X |
					IE_RSN_AKM_SUITE_FT_USING_PSK |
					IE_RSN_AKM_SUITE_FT_OVER_SAE_SHA256))
			add_mde = true;
	}

	if (security == SECURITY_NONE)
		/* Perform FT association if available */
		add_mde = bss->mde_present;

	if (add_mde) {
		uint8_t mde[5];

		/* The MDE advertised by the BSS must be passed verbatim */
		mde[0] = IE_TYPE_MOBILITY_DOMAIN;
		mde[1] = 3;
		memcpy(mde + 2, bss->mde, 3);

		handshake_state_set_mde(hs, mde);
	}

	return hs;

not_supported:
	handshake_state_free(hs);

	return NULL;
}

static void device_roam_failed(struct device *device)
{
	/*
	 * If we're still connected to the old BSS, only clear preparing_roam
	 * and reattempt in 60 seconds if signal level is still low at that
	 * time.  Otherwise (we'd already started negotiating with the
	 * transition target, preparing_roam is false, state is roaming) we
	 * are now disconnected.
	 */

	l_debug("%d", device->index);

	device->preparing_roam = false;
	device->roam_no_orig_ap = false;
	device->ap_directed_roaming = false;

	if (device->state == DEVICE_STATE_ROAMING)
		device_disassociated(device);
	else if (device->signal_low)
		device_roam_timeout_rearm(device, 60);
}

static void device_reassociate_cb(struct netdev *netdev,
					enum netdev_result result,
					void *user_data)
{
	struct device *device = user_data;

	l_debug("%d, result: %d", device->index, result);

	if (device->state != DEVICE_STATE_ROAMING)
		return;

	if (result == NETDEV_RESULT_OK) {
		/*
		 * New signal high/low notification should occur on the next
		 * beacon from new AP.
		 */
		device->signal_low = false;
		device->roam_min_time.tv_sec = 0;
		device->roam_no_orig_ap = false;

		device_enter_state(device, DEVICE_STATE_CONNECTED);
	} else
		device_roam_failed(device);
}

static void device_fast_transition_cb(struct netdev *netdev,
					enum netdev_result result,
					void *user_data)
{
	struct device *device = user_data;

	l_debug("%d, result: %d", device->index, result);

	if (device->state != DEVICE_STATE_ROAMING)
		return;

	if (result == NETDEV_RESULT_OK) {
		/*
		 * New signal high/low notification should occur on the next
		 * beacon from new AP.
		 */
		device->signal_low = false;
		device->roam_min_time.tv_sec = 0;
		device->roam_no_orig_ap = false;

		device_enter_state(device, DEVICE_STATE_CONNECTED);
	} else
		device_roam_failed(device);
}

static void device_transition_reassociate(struct device *device,
						struct scan_bss *bss,
						struct handshake_state *new_hs)
{
	if (netdev_reassociate(device->netdev, bss, device->connected_bss,
				new_hs, device_netdev_event,
				device_reassociate_cb, device) < 0) {
		handshake_state_free(new_hs);

		device_roam_failed(device);
		return;
	}

	device->connected_bss = bss;
	device->preparing_roam = false;
	device_enter_state(device, DEVICE_STATE_ROAMING);
}

static bool bss_match_bssid(const void *a, const void *b)
{
	const struct scan_bss *bss = a;
	const uint8_t *bssid = b;

	return !memcmp(bss->addr, bssid, sizeof(bss->addr));
}

static void device_preauthenticate_cb(struct netdev *netdev,
					enum netdev_result result,
					const uint8_t *pmk, void *user_data)
{
	struct device *device = user_data;
	struct scan_bss *bss;
	struct handshake_state *new_hs;

	l_debug("%d, result: %d", device->index, result);

	if (!device->preparing_roam || result == NETDEV_RESULT_ABORTED)
		return;

	bss = l_queue_find(device->bss_list, bss_match_bssid,
				device->preauth_bssid);
	if (!bss) {
		l_error("Roam target BSS not found");

		device_roam_failed(device);
		return;
	}

	new_hs = device_handshake_setup(device, device->connected_network, bss);
	if (!new_hs) {
		l_error("device_handshake_setup failed");

		device_roam_failed(device);
		return;
	}

	if (result == NETDEV_RESULT_OK) {
		uint8_t pmkid[16];
		uint8_t rsne_buf[300];
		struct ie_rsn_info rsn_info;

		handshake_state_set_pmk(new_hs, pmk, 32);
		handshake_state_set_authenticator_address(new_hs,
					device->preauth_bssid);
		handshake_state_set_supplicant_address(new_hs,
					netdev_get_address(device->netdev));

		/*
		 * Rebuild the RSNE to include the negotiated PMKID.  Note
		 * own_ie can't be a WPA IE here, including because the
		 * WPA IE doesn't have a capabilities field and
		 * target_rsne->preauthentication would have been false in
		 * device_transition_start.
		 */
		ie_parse_rsne_from_data(new_hs->own_ie, new_hs->own_ie[1] + 2,
					&rsn_info);

		handshake_state_get_pmkid(new_hs, pmkid);

		rsn_info.num_pmkids = 1;
		rsn_info.pmkids = pmkid;

		ie_build_rsne(&rsn_info, rsne_buf);
		handshake_state_set_own_rsn(new_hs, rsne_buf);
	}

	device_transition_reassociate(device, bss, new_hs);
}

static void device_transition_start(struct device *device, struct scan_bss *bss)
{
	struct handshake_state *hs = netdev_get_handshake(device->netdev);
	uint16_t mdid;
	struct handshake_state *new_hs;
	struct ie_rsn_info cur_rsne, target_rsne;
	enum security security =
		network_get_security(device->connected_network);

	l_debug("%d, target %s", device->index,
			util_address_to_string(bss->addr));

	/* Reset AP roam flag, at this point the roaming behaves the same */
	device->ap_directed_roaming = false;

	if (hs->mde)
		ie_parse_mobility_domain_from_data(hs->mde, hs->mde[1] + 2,
							&mdid, NULL, NULL);

	/* Can we use Fast Transition? */
	if (hs->mde && bss->mde_present && l_get_le16(bss->mde) == mdid) {
		/*
		 * There's no need to regenerate the RSNE because neither
		 * the AKM nor cipher suite can change:
		 *
		 * 12.5.2: "If the FTO selects a pairwise cipher suite in
		 * the RSNE that is different from the ones used in the
		 * Initial mobility domain association, then the AP shall
		 * reject the Authentication Request with status code 19
		 * (i.e., Invalid Pairwise Cipher)."
		 */
		if (netdev_fast_transition(device->netdev, bss,
					device_fast_transition_cb) < 0) {
			device_roam_failed(device);
			return;
		}

		device->connected_bss = bss;
		device->preparing_roam = false;
		device_enter_state(device, DEVICE_STATE_ROAMING);

		return;
	}

	/* Non-FT transition */

	/*
	 * FT not available, we can try preauthentication if available.
	 * 802.11-2012 section 11.5.9.2:
	 * "A STA shall not use preauthentication within the same mobility
	 * domain if AKM suite type 00-0F-AC:3 or 00-0F-AC:4 is used in
	 * the current association."
	 */
	if (security == SECURITY_8021X &&
			!device->roam_no_orig_ap &&
			scan_bss_get_rsn_info(device->connected_bss,
						&cur_rsne) >= 0 &&
			scan_bss_get_rsn_info(bss, &target_rsne) >= 0 &&
			cur_rsne.preauthentication &&
			target_rsne.preauthentication) {
		/*
		 * Both the current and the target AP support
		 * pre-authentication and we're using 8021x authentication so
		 * attempt to pre-authenticate and reassociate afterwards.
		 * If the pre-authentication fails or times out we simply
		 * won't supply any PMKID when reassociating.
		 * Remain in the preparing_roam state.
		 */
		memcpy(device->preauth_bssid, bss->addr, ETH_ALEN);

		if (netdev_preauthenticate(device->netdev, bss,
						device_preauthenticate_cb,
						device) >= 0)
			return;
	}

	new_hs = device_handshake_setup(device, device->connected_network, bss);
	if (!new_hs) {
		l_error("device_handshake_setup failed in reassociation");

		device_roam_failed(device);
		return;
	}

	device_transition_reassociate(device, bss, new_hs);
}

static void device_roam_scan_triggered(int err, void *user_data)
{
	struct device *device = user_data;

	if (err) {
		device_roam_failed(device);
		return;
	}

	/*
	 * Do not update the Scanning property as we won't be updating the
	 * list of networks.
	 */
}

static bool device_roam_scan_notify(uint32_t wiphy_id, uint32_t ifindex,
					int err, struct l_queue *bss_list,
					void *userdata)
{
	struct device *device = userdata;
	struct network *network = device->connected_network;
	struct handshake_state *hs = netdev_get_handshake(device->netdev);
	struct scan_bss *bss;
	struct scan_bss *best_bss = NULL;
	double best_bss_rank = 0.0;
	static const double RANK_FT_FACTOR = 1.3;
	uint16_t mdid;
	enum security orig_security, security;
	struct timespec now;
	bool seen = false;

	if (err) {
		device_roam_failed(device);

		return false;
	}

	/*
	 * Do not call device_set_scan_results because this may have been
	 * a partial scan.  We could at most update the current networks' BSS
	 * list in its device->networks entry.
	 */

	orig_security = network_get_security(network);

	if (hs->mde)
		ie_parse_mobility_domain_from_data(hs->mde, hs->mde[1] + 2,
							&mdid, NULL, NULL);

	/*
	 * BSSes in the bss_list come already ranked with their initial
	 * association preference rank value.  We only need to add preference
	 * for BSSes that are within the FT Mobility Domain so as to favor
	 * Fast Roaming, if it is supported.
	 */

	while ((bss = l_queue_pop_head(bss_list))) {
		double rank;
		struct ie_rsn_info info;
		int r;

		/* Skip the BSS we are connected to if doing an AP roam */
		if (device->ap_directed_roaming && !memcmp(bss->addr,
				device->connected_bss->addr, 6))
			goto next;

		/* Skip result if it is not part of the ESS */

		if (bss->ssid_len != hs->ssid_len ||
				memcmp(bss->ssid, hs->ssid, hs->ssid_len))
			goto next;

		memset(&info, 0, sizeof(info));
		r = scan_bss_get_rsn_info(bss, &info);
		if (r < 0) {
			if (r != -ENOENT)
				goto next;

			security = security_determine(bss->capability, NULL);
		} else
			security = security_determine(bss->capability, &info);

		if (security != orig_security)
			goto next;

		seen = true;

		if (!wiphy_can_connect(device->wiphy, bss))
			goto next;

		rank = bss->rank;

		if (hs->mde && bss->mde_present && l_get_le16(bss->mde) == mdid)
			rank *= RANK_FT_FACTOR;

		if (rank > best_bss_rank) {
			if (best_bss)
				scan_bss_free(best_bss);

			best_bss = bss;
			best_bss_rank = rank;

			continue;
		}

next:
		scan_bss_free(bss);
	}

	l_queue_destroy(bss_list, NULL);

	if (!seen)
		goto fail_free_bss;

	clock_gettime(CLOCK_REALTIME, &now);

	/* See if we have anywhere to roam to */
	if (!best_bss || bss_match(best_bss, device->connected_bss))
		goto fail_free_bss;

	bss = network_bss_find_by_addr(network, best_bss->addr);
	if (bss) {
		scan_bss_free(best_bss);
		best_bss = bss;
	} else {
		network_bss_add(network, best_bss);
		l_queue_push_tail(device->bss_list, best_bss);
	}

	device_transition_start(device, best_bss);

	return true;

fail_free_bss:
	if (best_bss)
		scan_bss_free(best_bss);

	device_roam_failed(device);

	return true;
}

static void device_roam_scan_destroy(void *userdata)
{
	struct device *device = userdata;

	device->roam_scan_id = 0;
}

static void device_roam_scan(struct device *device,
				struct scan_freq_set *freq_set)
{
	struct scan_parameters params = { .freqs = freq_set, .flush = true };

	if (device->connected_network)
		/* Use direct probe request */
		params.ssid = network_get_ssid(device->connected_network);

	device->roam_scan_id = scan_active_full(device->index, &params,
						device_roam_scan_triggered,
						device_roam_scan_notify, device,
						device_roam_scan_destroy);

	if (!device->roam_scan_id)
		device_roam_failed(device);
}

static uint32_t device_freq_from_neighbor_report(const uint8_t *country,
		struct ie_neighbor_report_info *info, enum scan_band *out_band)
{
	enum scan_band band;
	uint32_t freq;

	if (info->oper_class == 0) {
		/*
		 * Some Cisco APs report all operating class values as 0
		 * in the Neighbor Report Responses.  Work around this by
		 * using the most likely operating class for the channel
		 * number as the 2.4GHz and 5GHz bands happen to mostly
		 * use channels in two disjoint ranges.
		 */
		if (info->channel_num >= 1 && info->channel_num <= 14)
			band = SCAN_BAND_2_4_GHZ;
		else if (info->channel_num >= 36 && info->channel_num <= 169)
			band = SCAN_BAND_5_GHZ;
		else {
			l_debug("Ignored: 0 oper class with an unusual "
				"channel number");

			return 0;
		}
	} else {
		band = scan_oper_class_to_band(country, info->oper_class);
		if (!band) {
			l_debug("Ignored: unsupported oper class");

			return 0;
		}
	}

	freq = scan_channel_to_freq(info->channel_num, band);
	if (!freq) {
		l_debug("Ignored: unsupported channel");

		return 0;
	}

	if (out_band)
		*out_band = band;

	return freq;
}

static void device_neighbor_report_cb(struct netdev *netdev, int err,
					const uint8_t *reports,
					size_t reports_len, void *user_data)
{
	struct device *device = user_data;
	struct ie_tlv_iter iter;
	int count_md = 0, count_no_md = 0;
	struct scan_freq_set *freq_set_md, *freq_set_no_md;
	uint32_t current_freq = 0;
	struct handshake_state *hs = netdev_get_handshake(device->netdev);

	/*
	 * Check if we're still attempting to roam -- if dbus Disconnect
	 * had been called in the meantime we just abort the attempt.
	 */
	if (!device->preparing_roam || err == -ENODEV)
		return;

	if (!reports || err) {
		/* Have to do a full scan */
		device_roam_scan(device, NULL);

		return;
	}

	freq_set_md = scan_freq_set_new();
	freq_set_no_md = scan_freq_set_new();

	ie_tlv_iter_init(&iter, reports, reports_len);

	/* First see if any of the reports contain the MD bit set */
	while (ie_tlv_iter_next(&iter)) {
		struct ie_neighbor_report_info info;
		uint32_t freq;
		enum scan_band band;
		const uint8_t *cc = NULL;

		if (ie_tlv_iter_get_tag(&iter) != IE_TYPE_NEIGHBOR_REPORT)
			continue;

		if (ie_parse_neighbor_report(&iter, &info) < 0)
			continue;

		l_debug("Neighbor report received for %s: ch %i "
				"(oper class %i), %s",
				util_address_to_string(info.addr),
				(int) info.channel_num, (int) info.oper_class,
				info.md ? "MD set" : "MD not set");

		if (device->connected_bss->cc_present)
			cc = device->connected_bss->cc;

		freq = device_freq_from_neighbor_report(cc, &info, &band);
		if (!freq)
			continue;

		/* Skip if the band is not supported */
		if (!(band & wiphy_get_supported_bands(device->wiphy)))
			continue;

		if (!memcmp(info.addr, device->connected_bss->addr, ETH_ALEN)) {
			/*
			 * If this report is for the current AP, don't add
			 * it to any of the lists yet.  We will need to scan
			 * its channel because it may still be the best ranked
			 * or the only visible AP.
			 */
			current_freq = freq;

			continue;
		}

		/* Add the frequency to one of the lists */
		if (info.md && hs->mde) {
			scan_freq_set_add(freq_set_md, freq);

			count_md += 1;
		} else {
			scan_freq_set_add(freq_set_no_md, freq);

			count_no_md += 1;
		}
	}

	if (!current_freq)
		current_freq = device->connected_bss->frequency;

	/*
	 * If there are neighbor reports with the MD bit set then the bit
	 * is probably valid so scan only the frequencies of the neighbors
	 * with that bit set, which will allow us to use Fast Transition.
	 * Some APs, such as those based on hostapd do not set the MD bit
	 * even if the neighbor is within the MD.
	 *
	 * In any case we only select the frequencies here and will check
	 * the IEs in the scan results as the authoritative information
	 * on whether we can use Fast Transition, and rank BSSes based on
	 * that.
	 *
	 * TODO: possibly save the neighbors from outside the MD and if
	 * none of the ones in the MD end up working, try a non-FT
	 * transition to those neighbors.  We should be using a
	 * blacklisting mechanism (for both initial connection and
	 * transitions) so that cound_md would not count the
	 * BSSes already used and when it goes down to 0 we'd
	 * automatically fall back to the non-FT candidates and then to
	 * full scan.
	 */
	if (count_md) {
		scan_freq_set_add(freq_set_md, current_freq);

		device_roam_scan(device, freq_set_md);
	} else if (count_no_md) {
		scan_freq_set_add(freq_set_no_md, current_freq);

		device_roam_scan(device, freq_set_no_md);
	} else
		device_roam_scan(device, NULL);

	scan_freq_set_free(freq_set_md);
	scan_freq_set_free(freq_set_no_md);
}

static void device_roam_trigger_cb(struct l_timeout *timeout, void *user_data)
{
	struct device *device = user_data;

	l_debug("%d", device->index);

	l_timeout_remove(device->roam_trigger_timeout);
	device->roam_trigger_timeout = NULL;

	device->preparing_roam = true;

	/*
	 * If current BSS supports Neighbor Reports, narrow the scan down
	 * to channels occupied by known neighbors in the ESS.  This isn't
	 * 100% reliable as the neighbor lists are not required to be
	 * complete or current.  It is likely still better than doing a
	 * full scan.  10.11.10.1: "A neighbor report may not be exhaustive
	 * either by choice, or due to the fact that there may be neighbor
	 * APs not known to the AP."
	 */
	if (device->connected_bss->cap_rm_neighbor_report &&
			!device->roam_no_orig_ap)
		if (netdev_neighbor_report_req(device->netdev,
						device_neighbor_report_cb) == 0)
			return;

	/* Otherwise do a full scan for target BSS candidates */
	device_roam_scan(device, NULL);
}

static void device_roam_timeout_rearm(struct device *device, int seconds)
{
	struct timespec now, min_timeout;

	clock_gettime(CLOCK_MONOTONIC, &now);

	min_timeout = now;
	min_timeout.tv_sec += seconds;

	if (device->roam_min_time.tv_sec < min_timeout.tv_sec ||
			(device->roam_min_time.tv_sec == min_timeout.tv_sec &&
			 device->roam_min_time.tv_nsec < min_timeout.tv_nsec))
		device->roam_min_time = min_timeout;

	seconds = device->roam_min_time.tv_sec - now.tv_sec +
		(device->roam_min_time.tv_nsec > now.tv_nsec ? 1 : 0);

	device->roam_trigger_timeout =
		l_timeout_create(seconds, device_roam_trigger_cb, device, NULL);
}

#define WNM_REQUEST_MODE_PREFERRED_CANDIDATE_LIST	(1 << 0)
#define WNM_REQUEST_MODE_TERMINATION_IMMINENT		(1 << 3)
#define WNM_REQUEST_MODE_ESS_DISASSOCIATION_IMMINENT	(1 << 4)

static void device_ap_roam_frame_event(struct netdev *netdev,
		const struct mmpdu_header *hdr,
		const void *body, size_t body_len,
		void *user_data)
{
	struct device *device = user_data;
	uint32_t pos = 0;
	uint8_t req_mode;
	uint16_t dtimer;
	uint8_t valid_interval;

	if (device->preparing_roam || device->state == DEVICE_STATE_ROAMING)
		return;

	if (body_len < 7)
		goto format_error;

	/*
	 * First two bytes are checked by the frame watch (WNM category and
	 * WNM action). The third is the dialog token which is not relevant
	 * because we did not send a BSS transition query -- so skip these
	 * first three bytes.
	 */
	pos += 3;

	req_mode = l_get_u8(body + pos);
	pos++;

	/*
	 * TODO: Disassociation timer and validity interval are currently not
	 * used since the BSS transition request is being handled immediately.
	 */
	dtimer = l_get_le16(body + pos);
	pos += 2;
	valid_interval = l_get_u8(body + pos);
	pos++;

	l_debug("BSS transition received from AP: Disassociation Time: %u, "
			"Validity interval: %u", dtimer, valid_interval);

	/* check req_mode for optional values */
	if (req_mode & WNM_REQUEST_MODE_TERMINATION_IMMINENT) {
		if (pos + 12 > body_len)
			goto format_error;

		pos += 12;
	}

	if (req_mode & WNM_REQUEST_MODE_ESS_DISASSOCIATION_IMMINENT ) {
		uint8_t url_len;

		if (pos + 1 > body_len)
			goto format_error;

		url_len = l_get_u8(body + pos);
		pos++;

		if (pos + url_len > body_len)
			goto format_error;

		pos += url_len;
	}

	device->ap_directed_roaming = true;
	device->preparing_roam = true;

	l_timeout_remove(device->roam_trigger_timeout);
	device->roam_trigger_timeout = NULL;

	if (req_mode & WNM_REQUEST_MODE_PREFERRED_CANDIDATE_LIST)
		device_neighbor_report_cb(device->netdev, 0, body + pos,
				body_len - pos, device);
	else
		device_roam_scan(device, NULL);

	return;

format_error:
	l_debug("bad AP roam frame formatting");
}

static void device_lost_beacon(struct device *device)
{
	l_debug("%d", device->index);

	if (device->state != DEVICE_STATE_ROAMING &&
			device->state != DEVICE_STATE_CONNECTED)
		return;

	/*
	 * Tell the roam mechanism to not bother requesting Neighbor Reports,
	 * preauthenticating or performing other over-the-DS type of
	 * authentication to target AP, even while device->connected_bss is
	 * still non-NULL.  The current connection is in a serious condition
	 * and we might wasting our time with those mechanisms.
	 */
	device->roam_no_orig_ap = true;

	if (device->preparing_roam || device->state == DEVICE_STATE_ROAMING)
		return;

	device_roam_trigger_cb(NULL, device);
}

static void device_connect_cb(struct netdev *netdev, enum netdev_result result,
					void *user_data)
{
	struct device *device = user_data;

	l_debug("%d, result: %d", device->index, result);

	if (device->connect_pending) {
		struct l_dbus_message *reply;

		switch (result) {
		case NETDEV_RESULT_ABORTED:
			reply = dbus_error_aborted(device->connect_pending);
			break;
		case NETDEV_RESULT_OK:
			reply = l_dbus_message_new_method_return(
						device->connect_pending);
			l_dbus_message_set_arguments(reply, "");
			break;
		default:
			reply = dbus_error_failed(device->connect_pending);
			break;
		}

		dbus_pending_reply(&device->connect_pending, reply);
	}

	if (result != NETDEV_RESULT_OK) {
		if (result != NETDEV_RESULT_ABORTED) {
			network_connect_failed(device->connected_network);
			device_disassociated(device);
		}

		return;
	}

	network_connected(device->connected_network);
	device_enter_state(device, DEVICE_STATE_CONNECTED);
	device->autoconnect = true;
}

static void device_signal_agent_notify(struct signal_agent *agent,
					const char *device_path, int level)
{
	struct l_dbus_message *msg;
	uint8_t value = level;

	msg = l_dbus_message_new_method_call(dbus_get_bus(),
						agent->owner, agent->path,
						IWD_SIGNAL_AGENT_INTERFACE,
						"SignalLevelChanged");
	l_dbus_message_set_arguments(msg, "oy", device_path, value);
	l_dbus_message_set_no_reply(msg, true);

	l_dbus_send(dbus_get_bus(), msg);
}

static void device_signal_agent_release(struct signal_agent *agent,
					const char *device_path)
{
	struct l_dbus_message *msg;

	msg = l_dbus_message_new_method_call(dbus_get_bus(),
						agent->owner, agent->path,
						IWD_SIGNAL_AGENT_INTERFACE,
						"Release");
	l_dbus_message_set_arguments(msg, "o", device_path);
	l_dbus_message_set_no_reply(msg, true);

	l_dbus_send(dbus_get_bus(), msg);
}

static void device_netdev_event(struct netdev *netdev, enum netdev_event event,
					void *user_data)
{
	struct device *device = user_data;

	switch (event) {
	case NETDEV_EVENT_AUTHENTICATING:
		l_debug("Authenticating");
		break;
	case NETDEV_EVENT_ASSOCIATING:
		l_debug("Associating");
		break;
	case NETDEV_EVENT_LOST_BEACON:
		device_lost_beacon(device);
		break;
	case NETDEV_EVENT_DISCONNECT_BY_AP:
	case NETDEV_EVENT_DISCONNECT_BY_SME:
		device_disconnect_event(device);
		break;
	case NETDEV_EVENT_RSSI_THRESHOLD_LOW:
		if (device->signal_low)
			break;

		device->signal_low = true;

		if (device->preparing_roam ||
				device->state == DEVICE_STATE_ROAMING)
			break;

		/* Set a 5-second initial timeout */
		device_roam_timeout_rearm(device, 5);

		break;
	case NETDEV_EVENT_RSSI_THRESHOLD_HIGH:
		l_timeout_remove(device->roam_trigger_timeout);
		device->roam_trigger_timeout = NULL;

		device->signal_low = false;

		break;
	case NETDEV_EVENT_RSSI_LEVEL_NOTIFY:
		if (device->signal_agent)
			device_signal_agent_notify(device->signal_agent,
					device_get_path(device),
					netdev_get_rssi_level(device->netdev));

		break;
	};
}

bool device_set_autoconnect(struct device *device, bool autoconnect)
{
	if (device->autoconnect == autoconnect)
		return true;

	device->autoconnect = autoconnect;

	if (device->state == DEVICE_STATE_DISCONNECTED && autoconnect)
		device_enter_state(device, DEVICE_STATE_AUTOCONNECT);

	if (device->state == DEVICE_STATE_AUTOCONNECT && !autoconnect)
		device_enter_state(device, DEVICE_STATE_DISCONNECTED);

	return true;
}

int __device_connect_network(struct device *device, struct network *network,
				struct scan_bss *bss)
{
	struct l_dbus *dbus = dbus_get_bus();
	struct handshake_state *hs;
	int r;

	if (device_is_busy(device))
		return -EBUSY;

	hs = device_handshake_setup(device, network, bss);
	if (!hs)
		return -ENOTSUP;

	r = netdev_connect(device->netdev, bss, hs, device_netdev_event,
					device_connect_cb, device);
	if (r < 0) {
		handshake_state_free(hs);
		return r;
	}

	device->connected_bss = bss;
	device->connected_network = network;

	device_enter_state(device, DEVICE_STATE_CONNECTING);

	l_dbus_property_changed(dbus, device_get_path(device),
				IWD_DEVICE_INTERFACE, "ConnectedNetwork");
	l_dbus_property_changed(dbus, network_get_path(network),
				IWD_NETWORK_INTERFACE, "Connected");

	return 0;
}

void device_connect_network(struct device *device, struct network *network,
				struct scan_bss *bss,
				struct l_dbus_message *message)
{
	int err = __device_connect_network(device, network, bss);

	if (err < 0) {
		struct l_dbus *dbus = dbus_get_bus();

		l_dbus_send(dbus, dbus_error_from_errno(err, message));
		return;
	}

	device->connect_pending = l_dbus_message_ref(message);
}

static void device_scan_triggered(int err, void *user_data)
{
	struct device *device = user_data;
	struct l_dbus_message *reply;
	struct l_dbus *dbus = dbus_get_bus();

	l_debug("device_scan_triggered: %i", err);

	if (!device->scan_pending)
		return;

	if (err < 0) {
		dbus_pending_reply(&device->scan_pending,
				dbus_error_failed(device->scan_pending));
		return;
	}

	l_debug("Scan triggered for %s", netdev_get_name(device->netdev));

	device->scanning = true;
	l_dbus_property_changed(dbus, device_get_path(device),
				IWD_DEVICE_INTERFACE, "Scanning");

	reply = l_dbus_message_new_method_return(device->scan_pending);
	l_dbus_message_set_arguments(reply, "");
	dbus_pending_reply(&device->scan_pending, reply);
}

static struct l_dbus_message *device_scan(struct l_dbus *dbus,
						struct l_dbus_message *message,
						void *user_data)
{
	struct device *device = user_data;

	l_debug("Scan called from DBus");

	if (device->scan_pending)
		return dbus_error_busy(message);

	if (device->state == DEVICE_STATE_OFF ||
			device->mode != DEVICE_MODE_STATION)
		return dbus_error_failed(message);

	device->scan_pending = l_dbus_message_ref(message);

	/*
	 * If we're not connected and no hidden networks are seen & configured,
	 * use passive scanning to hide our MAC address
	 */
	if (!device->connected_bss &&
			!(device->seen_hidden_networks &&
				known_networks_has_hidden())) {
		if (!scan_passive(device->index, device_scan_triggered,
						new_scan_results, device, NULL))
			return dbus_error_failed(message);
	} else {
		struct scan_parameters params;

		memset(&params, 0, sizeof(params));

		/* If we're connected, HW cannot randomize our MAC */
		if (!device->connected_bss)
			params.randomize_mac_addr_hint = true;

		if (!scan_active_full(device->index, &params,
					device_scan_triggered,
					new_scan_results, device, NULL))
			return dbus_error_failed(message);
	}

	return NULL;
}

static void device_disconnect_cb(struct netdev *netdev, bool success,
					void *user_data)
{
	struct device *device = user_data;

	l_debug("%d, success: %d", device->index, success);

	if (device->disconnect_pending) {
		struct l_dbus_message *reply;

		if (success) {
			reply = l_dbus_message_new_method_return(
						device->disconnect_pending);
			l_dbus_message_set_arguments(reply, "");
		} else
			reply = dbus_error_failed(device->disconnect_pending);


		dbus_pending_reply(&device->disconnect_pending, reply);

	}

	device_enter_state(device, DEVICE_STATE_DISCONNECTED);

	if (device->autoconnect)
		device_enter_state(device, DEVICE_STATE_AUTOCONNECT);
}

int device_disconnect(struct device *device)
{
	if (device->state == DEVICE_STATE_DISCONNECTING)
		return -EBUSY;

	if (!device->connected_bss)
		return -ENOTCONN;

	if (netdev_disconnect(device->netdev, device_disconnect_cb, device) < 0)
		return -EIO;

	/*
	 * If the disconnect somehow fails we won't know if we're still
	 * connected so we may as well indicate now that we're no longer
	 * connected.
	 */
	device_reset_connection_state(device);

	device_enter_state(device, DEVICE_STATE_DISCONNECTING);

	return 0;
}

static struct l_dbus_message *device_dbus_disconnect(struct l_dbus *dbus,
						struct l_dbus_message *message,
						void *user_data)
{
	struct device *device = user_data;
	int result;

	l_debug("");

	/*
	 * Disconnect was triggered by the user, don't autoconnect. Wait for
	 * the user's explicit instructions to scan and connect to the network
	 */
	device_set_autoconnect(device, false);

	if (device->state == DEVICE_STATE_AUTOCONNECT ||
			device->state == DEVICE_STATE_DISCONNECTED)
		return l_dbus_message_new_method_return(message);

	result = device_disconnect(device);
	if (result < 0)
		return dbus_error_from_errno(result, message);

	device->disconnect_pending = l_dbus_message_ref(message);

	return NULL;
}

static struct l_dbus_message *device_get_networks(struct l_dbus *dbus,
						struct l_dbus_message *message,
						void *user_data)
{
	struct device *device = user_data;
	struct l_dbus_message *reply;
	struct l_dbus_message_builder *builder;
	const struct l_queue_entry *entry;

	reply = l_dbus_message_new_method_return(message);
	builder = l_dbus_message_builder_new(reply);

	l_dbus_message_builder_enter_array(builder, "(osns)");

	for (entry = l_queue_get_entries(device->networks_sorted); entry;
				entry = entry->next) {
		const struct network *network = entry->data;
		enum security security = network_get_security(network);
		int16_t signal_strength = network_get_signal_strength(network);

		l_dbus_message_builder_enter_struct(builder, "osns");
		l_dbus_message_builder_append_basic(builder, 'o',
						network_get_path(network));
		l_dbus_message_builder_append_basic(builder, 's',
						network_get_ssid(network));
		l_dbus_message_builder_append_basic(builder, 'n',
							&signal_strength);
		l_dbus_message_builder_append_basic(builder, 's',
						security_to_str(security));
		l_dbus_message_builder_leave_struct(builder);
	}

	l_dbus_message_builder_leave_array(builder);

	l_dbus_message_builder_finalize(builder);
	l_dbus_message_builder_destroy(builder);

	return reply;
}

static void signal_agent_free(void *data)
{
	struct signal_agent *agent = data;

	l_free(agent->owner);
	l_free(agent->path);
	l_dbus_remove_watch(dbus_get_bus(), agent->disconnect_watch);
	l_free(agent);
}

static void signal_agent_disconnect(struct l_dbus *dbus, void *user_data)
{
	struct device *device = user_data;

	l_debug("signal_agent %s disconnected", device->signal_agent->owner);

	l_idle_oneshot(signal_agent_free, device->signal_agent, NULL);
	device->signal_agent = NULL;

	netdev_set_rssi_report_levels(device->netdev, NULL, 0);
}

static struct l_dbus_message *device_signal_agent_register(struct l_dbus *dbus,
						struct l_dbus_message *message,
						void *user_data)
{
	struct device *device = user_data;
	const char *path, *sender;
	struct l_dbus_message_iter level_iter;
	int8_t levels[16];
	int err;
	int16_t val;
	size_t count = 0;

	if (device->signal_agent)
		return dbus_error_already_exists(message);

	l_debug("signal agent register called");

	if (!l_dbus_message_get_arguments(message, "oan", &path, &level_iter))
		return dbus_error_invalid_args(message);

	while (l_dbus_message_iter_next_entry(&level_iter, &val)) {
		if (count >= L_ARRAY_SIZE(levels) || val > 127 || val < -127)
			return dbus_error_invalid_args(message);

		levels[count++] = val;
	}

	if (count < 1)
		return dbus_error_invalid_args(message);

	err = netdev_set_rssi_report_levels(device->netdev, levels, count);
	if (err == -ENOTSUP)
		return dbus_error_not_supported(message);
	else if (err < 0)
		return dbus_error_failed(message);

	sender = l_dbus_message_get_sender(message);

	device->signal_agent = l_new(struct signal_agent, 1);
	device->signal_agent->owner = l_strdup(sender);
	device->signal_agent->path = l_strdup(path);
	device->signal_agent->disconnect_watch =
		l_dbus_add_disconnect_watch(dbus, sender,
						signal_agent_disconnect,
						device, NULL);

	l_debug("agent %s path %s", sender, path);

	/*
	 * TODO: send an initial notification in a oneshot idle callback,
	 * if state is connected.
	 */

	return l_dbus_message_new_method_return(message);
}

static bool device_remove_network(const void *key, void *data, void *user_data)
{
	struct network *network = data;

	network_remove(network, -ESHUTDOWN);

	return true;
}

static struct l_dbus_message *device_signal_agent_unregister(
						struct l_dbus *dbus,
						struct l_dbus_message *message,
						void *user_data)
{
	struct device *device = user_data;
	const char *path, *sender;

	if (!device->signal_agent)
		return dbus_error_failed(message);

	l_debug("signal agent unregister");

	if (!l_dbus_message_get_arguments(message, "o", &path))
		return dbus_error_invalid_args(message);

	if (strcmp(device->signal_agent->path, path))
		return dbus_error_not_found(message);

	sender = l_dbus_message_get_sender(message);

	if (strcmp(device->signal_agent->owner, sender))
		return dbus_error_not_found(message);

	signal_agent_free(device->signal_agent);
	device->signal_agent = NULL;

	netdev_set_rssi_report_levels(device->netdev, NULL, 0);

	return l_dbus_message_new_method_return(message);
}

static void device_prepare_adhoc_ap_mode(struct device *device)
{
	periodic_scan_stop(device);

	/* Drop all state we can related to client mode */

	if (device->scan_pending)
		dbus_pending_reply(&device->scan_pending,
				dbus_error_aborted(device->scan_pending));

	l_hashmap_foreach_remove(device->networks,
					device_remove_network, device);

	l_queue_destroy(device->autoconnect_list, l_free);
	device->autoconnect_list = l_queue_new();

	l_queue_destroy(device->bss_list, bss_free);
	device->bss_list = l_queue_new();

	l_queue_destroy(device->networks_sorted, NULL);
	device->networks_sorted = l_queue_new();
}

static void device_hidden_network_scan_triggered(int err, void *user_data)
{
	struct device *device = user_data;

	l_debug("");

	if (!err)
		return;

	dbus_pending_reply(&device->connect_pending,
				dbus_error_failed(device->connect_pending));
}

static bool device_hidden_network_scan_results(uint32_t wiphy_id,
						uint32_t ifindex, int err,
						struct l_queue *bss_list,
						void *userdata)
{
	struct device *device = userdata;
	struct network *network_psk;
	struct network *network_open;
	struct network *network;
	const char *ssid;
	uint8_t ssid_len;
	struct l_dbus_message *msg;
	struct timespec now;
	struct scan_bss *bss;

	l_debug("");

	msg = device->connect_pending;
	device->connect_pending = NULL;

	if (err) {
		dbus_pending_reply(&msg, dbus_error_failed(msg));
		return false;
	}

	if (!l_dbus_message_get_arguments(msg, "s", &ssid)) {
		dbus_pending_reply(&msg, dbus_error_invalid_args(msg));
		return false;
	}

	clock_gettime(CLOCK_REALTIME, &now);
	ssid_len = strlen(ssid);

	while ((bss = l_queue_pop_head(bss_list))) {
		if (bss->ssid_len != ssid_len ||
					memcmp(bss->ssid, ssid, ssid_len))
			goto next;

		if (process_bss(device, bss, &now)) {
			l_queue_push_tail(device->bss_list, bss);

			continue;
		}

next:
		scan_bss_free(bss);
	}

	l_queue_destroy(bss_list, NULL);

	network_psk = device_network_find(device, ssid, SECURITY_PSK);
	network_open = device_network_find(device, ssid, SECURITY_NONE);

	if (!network_psk && !network_open) {
		dbus_pending_reply(&msg, dbus_error_not_found(msg));
		return true;
	}

	if (network_psk && network_open) {
		dbus_pending_reply(&msg, dbus_error_service_set_overlap(msg));
		return true;
	}

	network = network_psk ? : network_open;

	network_connect_new_hidden_network(network, msg);
	l_dbus_message_unref(msg);

	return true;
}

static struct l_dbus_message *device_connect_hidden_network(struct l_dbus *dbus,
						struct l_dbus_message *message,
						void *user_data)
{
	struct device *device = user_data;
	const char *ssid;
	struct scan_parameters params = {
		.flush = true,
		.randomize_mac_addr_hint = true,
	};

	l_debug("");

	if (device->state == DEVICE_STATE_OFF)
		return dbus_error_failed(message);

	if (device->connect_pending || device_is_busy(device))
		return dbus_error_busy(message);

	if (!l_dbus_message_get_arguments(message, "s", &ssid))
		return dbus_error_invalid_args(message);

	if (strlen(ssid) > 32)
		return dbus_error_invalid_args(message);

	if (known_networks_find(ssid, SECURITY_PSK) ||
			known_networks_find(ssid, SECURITY_NONE))
		return dbus_error_already_provisioned(message);

	if (device_network_find(device, ssid, SECURITY_PSK) ||
			device_network_find(device, ssid, SECURITY_NONE))
		return dbus_error_not_hidden(message);

	params.ssid = ssid;

	if (!scan_active_full(device->index, &params,
				device_hidden_network_scan_triggered,
				device_hidden_network_scan_results,
				device, NULL))
		return dbus_error_failed(message);

	device->connect_pending = l_dbus_message_ref(message);

	return NULL;
}

static bool device_property_get_name(struct l_dbus *dbus,
					struct l_dbus_message *message,
					struct l_dbus_message_builder *builder,
					void *user_data)
{
	struct device *device = user_data;

	l_dbus_message_builder_append_basic(builder, 's',
					netdev_get_name(device->netdev));
	return true;
}

static bool device_property_get_address(struct l_dbus *dbus,
					struct l_dbus_message *message,
					struct l_dbus_message_builder *builder,
					void *user_data)
{
	struct device *device = user_data;
	const char *str;

	str = util_address_to_string(netdev_get_address(device->netdev));
	l_dbus_message_builder_append_basic(builder, 's', str);

	return true;
}

static bool device_property_get_connected_network(struct l_dbus *dbus,
					struct l_dbus_message *message,
					struct l_dbus_message_builder *builder,
					void *user_data)
{
	struct device *device = user_data;
	if (!device->connected_network)
		return false;

	l_dbus_message_builder_append_basic(builder, 'o',
				network_get_path(device->connected_network));

	return true;
}

static bool device_property_get_powered(struct l_dbus *dbus,
					struct l_dbus_message *message,
					struct l_dbus_message_builder *builder,
					void *user_data)
{
	struct device *device = user_data;
	bool powered = device->state != DEVICE_STATE_OFF;

	l_dbus_message_builder_append_basic(builder, 'b', &powered);

	return true;
}

struct set_generic_cb_data {
	struct device *device;
	struct l_dbus *dbus;
	struct l_dbus_message *message;
	l_dbus_property_complete_cb_t complete;
};

static void set_powered_cb(struct netdev *netdev, int result, void *user_data)
{
	struct set_generic_cb_data *cb_data = user_data;
	struct l_dbus_message *reply = NULL;

	if (result < 0)
		reply = dbus_error_failed(cb_data->message);

	cb_data->complete(cb_data->dbus, cb_data->message, reply);
}

static struct l_dbus_message *device_property_set_powered(struct l_dbus *dbus,
					struct l_dbus_message *message,
					struct l_dbus_message_iter *new_value,
					l_dbus_property_complete_cb_t complete,
					void *user_data)
{
	struct device *device = user_data;
	bool powered;
	struct set_generic_cb_data *cb_data;

	if (!l_dbus_message_iter_get_variant(new_value, "b", &powered))
		return dbus_error_invalid_args(message);

	if (powered == (device->state != DEVICE_STATE_OFF)) {
		complete(dbus, message, NULL);

		return NULL;
	}

	cb_data = l_new(struct set_generic_cb_data, 1);
	cb_data->device = device;
	cb_data->dbus = dbus;
	cb_data->message = message;
	cb_data->complete = complete;

	netdev_set_powered(device->netdev, powered, set_powered_cb, cb_data,
				l_free);

	return NULL;
}

static bool device_property_get_4addr(struct l_dbus *dbus,
					struct l_dbus_message *message,
					struct l_dbus_message_builder *builder,
					void *user_data)
{
	struct device *device = user_data;
	bool use_4addr = netdev_get_4addr(device->netdev);

	l_dbus_message_builder_append_basic(builder, 'b', &use_4addr);

	return true;
}

static void set_4addr_cb(struct netdev *netdev, int result, void *user_data)
{
	struct set_generic_cb_data *cb_data = user_data;
	struct l_dbus_message *reply = NULL;

	if (result < 0)
		reply = dbus_error_failed(cb_data->message);

	cb_data->complete(cb_data->dbus, cb_data->message, reply);

	l_dbus_property_changed(cb_data->dbus, device_get_path(cb_data->device),
				IWD_DEVICE_INTERFACE, "WDS");
}

static struct l_dbus_message *device_property_set_4addr(struct l_dbus *dbus,
					struct l_dbus_message *message,
					struct l_dbus_message_iter *new_value,
					l_dbus_property_complete_cb_t complete,
					void *user_data)
{
	struct set_generic_cb_data *cb_data;
	struct device *device = user_data;
	bool use_4addr;

	if (!l_dbus_message_iter_get_variant(new_value, "b", &use_4addr))
		return dbus_error_invalid_args(message);

	if (use_4addr == netdev_get_4addr(device->netdev)) {
		complete(dbus, message, NULL);

		return NULL;
	}

	cb_data = l_new(struct set_generic_cb_data, 1);
	cb_data->device = device;
	cb_data->dbus = dbus;
	cb_data->message = message;
	cb_data->complete = complete;

	if (netdev_set_4addr(device->netdev, use_4addr, set_4addr_cb, cb_data,
				l_free) < 0)
		return dbus_error_failed(message);

	return NULL;
}

static bool device_property_get_scanning(struct l_dbus *dbus,
					struct l_dbus_message *message,
					struct l_dbus_message_builder *builder,
					void *user_data)
{
	struct device *device = user_data;
	bool scanning = device->scanning;

	l_dbus_message_builder_append_basic(builder, 'b', &scanning);

	return true;
}

static bool device_property_get_state(struct l_dbus *dbus,
					struct l_dbus_message *message,
					struct l_dbus_message_builder *builder,
					void *user_data)
{
	struct device *device = user_data;
	const char *statestr = "unknown";

	/* special case for AP mode */
	if (device->mode == DEVICE_MODE_AP) {
		l_dbus_message_builder_append_basic(builder, 's',
				"accesspoint");
		return true;
	}

	switch (device->state) {
	case DEVICE_STATE_CONNECTED:
		statestr = "connected";
		break;
	case DEVICE_STATE_CONNECTING:
		statestr = "connecting";
		break;
	case DEVICE_STATE_DISCONNECTING:
		statestr = "disconnecting";
		break;
	case DEVICE_STATE_OFF:
	case DEVICE_STATE_DISCONNECTED:
	case DEVICE_STATE_AUTOCONNECT:
		statestr = "disconnected";
		break;
	case DEVICE_STATE_ROAMING:
		statestr = "roaming";
		break;
	}

	l_dbus_message_builder_append_basic(builder, 's', statestr);

	return true;
}

static bool device_property_get_adapter(struct l_dbus *dbus,
					struct l_dbus_message *message,
					struct l_dbus_message_builder *builder,
					void *user_data)
{
	struct device *device = user_data;

	l_dbus_message_builder_append_basic(builder, 'o',
					wiphy_get_path(device->wiphy));

	return true;
}

static bool device_property_get_mode(struct l_dbus *dbus,
					struct l_dbus_message *message,
					struct l_dbus_message_builder *builder,
					void *user_data)
{
	struct device *device = user_data;
	const char *modestr = "unknown";

	switch (device->mode) {
	case DEVICE_MODE_STATION:
		modestr = "station";
		break;
	case DEVICE_MODE_AP:
		modestr = "ap";
		break;
	case DEVICE_MODE_ADHOC:
		modestr = "ad-hoc";
		break;
	}

	l_dbus_message_builder_append_basic(builder, 's', modestr);

	return true;
}

static struct l_dbus_message *device_change_mode(struct device *device,
		struct l_dbus_message *message, enum device_mode mode)
{
	if (device->mode == mode)
		return dbus_error_already_exists(message);

	/* ensure correct connection state in AP/AdHoc mode */
	if ((mode == DEVICE_MODE_AP || mode == DEVICE_MODE_ADHOC) &&
			(device->state != DEVICE_STATE_DISCONNECTED &&
			device->state != DEVICE_STATE_AUTOCONNECT))
		return dbus_error_busy(message);

	switch (mode) {
	case DEVICE_MODE_AP:
		device_prepare_adhoc_ap_mode(device);
		netdev_set_iftype(device->netdev, NETDEV_IFTYPE_AP);
		break;
	case DEVICE_MODE_ADHOC:
		device_prepare_adhoc_ap_mode(device);
		netdev_set_iftype(device->netdev, NETDEV_IFTYPE_ADHOC);
		break;
	case DEVICE_MODE_STATION:
		netdev_set_iftype(device->netdev, NETDEV_IFTYPE_STATION);
		break;
	}

	device->mode = mode;

	WATCHLIST_NOTIFY(&device_watches, device_watch_func_t, device,
				DEVICE_EVENT_MODE_CHANGED);

	return NULL;
}

static struct l_dbus_message *device_property_set_mode(struct l_dbus *dbus,
					struct l_dbus_message *message,
					struct l_dbus_message_iter *new_value,
					l_dbus_property_complete_cb_t complete,
					void *user_data)
{
	struct device *device = user_data;
	struct l_dbus_message *reply;
	const char* mode;
	enum device_mode change;

	if (!l_dbus_message_iter_get_variant(new_value, "s", &mode))
		return dbus_error_invalid_args(message);

	if (!strcmp(mode, "station"))
		change = DEVICE_MODE_STATION;
	else if (!strcmp(mode, "ap"))
		change = DEVICE_MODE_AP;
	else if (!strcmp(mode, "ad-hoc"))
		change = DEVICE_MODE_ADHOC;
	else
		return dbus_error_invalid_args(message);

	reply = device_change_mode(device, message, change);
	if (reply)
		return reply;

	complete(dbus, message, NULL);

	return NULL;
}

static void setup_device_interface(struct l_dbus_interface *interface)
{
	l_dbus_interface_method(interface, "Scan", 0,
				device_scan, "", "");
	l_dbus_interface_method(interface, "Disconnect", 0,
				device_dbus_disconnect, "", "");
	l_dbus_interface_method(interface, "GetOrderedNetworks", 0,
				device_get_networks, "a(osns)", "",
				"networks");
	l_dbus_interface_method(interface, "RegisterSignalLevelAgent", 0,
				device_signal_agent_register,
				"", "oan", "path", "levels");
	l_dbus_interface_method(interface, "UnregisterSignalLevelAgent", 0,
				device_signal_agent_unregister,
				"", "o", "path");
	l_dbus_interface_method(interface, "ConnectHiddenNetwork", 0,
				device_connect_hidden_network, "", "s", "name");
	l_dbus_interface_property(interface, "Name", 0, "s",
					device_property_get_name, NULL);
	l_dbus_interface_property(interface, "Address", 0, "s",
					device_property_get_address, NULL);
	l_dbus_interface_property(interface, "ConnectedNetwork", 0, "o",
					device_property_get_connected_network,
					NULL);
	l_dbus_interface_property(interface, "WDS", 0, "b",
					device_property_get_4addr,
					device_property_set_4addr);
	l_dbus_interface_property(interface, "Powered", 0, "b",
					device_property_get_powered,
					device_property_set_powered);
	l_dbus_interface_property(interface, "Scanning", 0, "b",
					device_property_get_scanning, NULL);
	l_dbus_interface_property(interface, "State", 0, "s",
					device_property_get_state, NULL);
	l_dbus_interface_property(interface, "Adapter", 0, "o",
					device_property_get_adapter, NULL);
	l_dbus_interface_property(interface, "Mode", 0, "s",
					device_property_get_mode,
					device_property_set_mode);
}

static void device_netdev_notify(struct netdev *netdev,
					enum netdev_watch_event event,
					void *user_data)
{
	struct device *device = user_data;
	struct l_dbus *dbus = dbus_get_bus();

	switch (event) {
	case NETDEV_WATCH_EVENT_UP:
		device->autoconnect = true;
		device_enter_state(device, DEVICE_STATE_AUTOCONNECT);

		WATCHLIST_NOTIFY(&device_watches, device_watch_func_t,
						device, DEVICE_EVENT_INSERTED);

		l_dbus_property_changed(dbus, device_get_path(device),
					IWD_DEVICE_INTERFACE, "Powered");
		break;
	case NETDEV_WATCH_EVENT_DOWN:
		device_enter_state(device, DEVICE_STATE_OFF);

		if (device->scan_pending)
			dbus_pending_reply(&device->scan_pending,
				dbus_error_aborted(device->scan_pending));

		if (device->connect_pending)
			dbus_pending_reply(&device->connect_pending,
				dbus_error_aborted(device->connect_pending));

		device_reset_connection_state(device);

		l_hashmap_foreach_remove(device->networks,
						device_remove_network, device);

		l_queue_destroy(device->autoconnect_list, l_free);
		device->autoconnect_list = l_queue_new();

		l_queue_destroy(device->bss_list, bss_free);
		device->bss_list = l_queue_new();

		l_queue_destroy(device->networks_sorted, NULL);
		device->networks_sorted = l_queue_new();

		WATCHLIST_NOTIFY(&device_watches, device_watch_func_t,
						device, DEVICE_EVENT_REMOVED);

		l_dbus_property_changed(dbus, device_get_path(device),
					IWD_DEVICE_INTERFACE, "Powered");
		break;
	case NETDEV_WATCH_EVENT_NAME_CHANGE:
		l_dbus_property_changed(dbus, device_get_path(device),
					IWD_DEVICE_INTERFACE, "Name");
		break;
	case NETDEV_WATCH_EVENT_ADDRESS_CHANGE:
		l_dbus_property_changed(dbus, device_get_path(device),
					IWD_DEVICE_INTERFACE, "Address");
		break;
	}
}

struct device *device_create(struct wiphy *wiphy, struct netdev *netdev)
{
	struct device *device;
	struct l_dbus *dbus = dbus_get_bus();
	uint32_t ifindex = netdev_get_ifindex(netdev);
	const uint8_t action_ap_roam_prefix[2] = { 0x0a, 0x07 };

	device = l_new(struct device, 1);
	device->bss_list = l_queue_new();
	device->networks = l_hashmap_new();
	watchlist_init(&device->state_watches, NULL);
	l_hashmap_set_hash_function(device->networks, l_str_hash);
	l_hashmap_set_compare_function(device->networks,
				(l_hashmap_compare_func_t) strcmp);
	device->networks_sorted = l_queue_new();
	device->index = ifindex;
	device->wiphy = wiphy;
	device->netdev = netdev;
	device->autoconnect = true;

	l_queue_push_head(device_list, device);

	if (!l_dbus_object_add_interface(dbus, device_get_path(device),
					IWD_DEVICE_INTERFACE, device))
		l_info("Unable to register %s interface", IWD_DEVICE_INTERFACE);

	if (!l_dbus_object_add_interface(dbus, device_get_path(device),
					L_DBUS_INTERFACE_PROPERTIES, device))
		l_info("Unable to register %s interface",
				L_DBUS_INTERFACE_PROPERTIES);

	scan_ifindex_add(device->index);

	netdev_set_iftype(device->netdev, NETDEV_IFTYPE_STATION);

	device_netdev_notify(netdev, netdev_get_is_up(netdev) ?
						NETDEV_WATCH_EVENT_UP :
						NETDEV_WATCH_EVENT_DOWN,
						device);
	device->netdev_watch_id =
		netdev_watch_add(netdev, device_netdev_notify, device);

	/*
	 * register for AP roam transition watch
	 */
	device->ap_roam_watch = netdev_frame_watch_add(netdev, 0x00d0,
			action_ap_roam_prefix, sizeof(action_ap_roam_prefix),
			device_ap_roam_frame_event, device);

	return device;
}

static void device_free(void *user)
{
	struct device *device = user;
	struct l_dbus *dbus;

	l_debug("");

	if (device->scan_pending)
		dbus_pending_reply(&device->scan_pending,
				dbus_error_aborted(device->scan_pending));

	if (device->connect_pending)
		dbus_pending_reply(&device->connect_pending,
				dbus_error_aborted(device->connect_pending));

	if (device->signal_agent) {
		device_signal_agent_release(device->signal_agent,
						device_get_path(device));
		signal_agent_free(device->signal_agent);
	}

	if (device->state != DEVICE_STATE_OFF)
		WATCHLIST_NOTIFY(&device_watches, device_watch_func_t,
						device, DEVICE_EVENT_REMOVED);

	watchlist_destroy(&device->state_watches);

	dbus = dbus_get_bus();
	l_dbus_unregister_object(dbus, device_get_path(device));

	l_queue_destroy(device->networks_sorted, NULL);
	l_hashmap_destroy(device->networks, network_free);

	l_queue_destroy(device->bss_list, bss_free);
	l_queue_destroy(device->old_bss_list, bss_free);
	l_queue_destroy(device->autoconnect_list, l_free);

	netdev_watch_remove(device->netdev, device->netdev_watch_id);

	l_timeout_remove(device->roam_trigger_timeout);

	scan_ifindex_remove(device->index);

	netdev_frame_watch_remove(device->netdev, device->ap_roam_watch);

	l_free(device);
}

void device_remove(struct device *device)
{
	if (!l_queue_remove(device_list, device))
		return;

	device_free(device);
}

bool device_init(void)
{
	if (!l_dbus_register_interface(dbus_get_bus(),
					IWD_DEVICE_INTERFACE,
					setup_device_interface,
					NULL, false))
		return false;

	watchlist_init(&device_watches, NULL);
	device_list = l_queue_new();

	return true;
}

bool device_exit(void)
{
	if (!l_queue_isempty(device_list))
		l_warn("device_list isn't empty!");

	l_queue_destroy(device_list, device_free);
	device_list = NULL;

	watchlist_destroy(&device_watches);

	l_dbus_unregister_interface(dbus_get_bus(), IWD_DEVICE_INTERFACE);

	return true;
}
