/*
 *
 *  Wireless daemon for Linux
 *
 *  Copyright (C) 2018  Intel Corporation. All rights reserved.
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

#include "src/util.h"
#include "src/iwd.h"
#include "src/common.h"
#include "src/device.h"
#include "src/watchlist.h"
#include "src/scan.h"
#include "src/netdev.h"
#include "src/dbus.h"
#include "src/wiphy.h"
#include "src/network.h"
#include "src/knownnetworks.h"
#include "src/ie.h"
#include "src/handshake.h"
#include "src/station.h"

static struct l_queue *station_list;

struct wiphy *station_get_wiphy(struct station *station)
{
	return station->wiphy;
}

struct netdev *station_get_netdev(struct station *station)
{
	return station->netdev;
}

struct network *station_get_connected_network(struct station *station)
{
	return station->connected_network;
}

bool station_is_busy(struct station *station)
{
	if (station->state != STATION_STATE_DISCONNECTED &&
			station->state != STATION_STATE_AUTOCONNECT)
		return true;

	return false;
}

struct autoconnect_entry {
	uint16_t rank;
	struct network *network;
	struct scan_bss *bss;
};

static void station_autoconnect_next(struct station *station)
{
	struct autoconnect_entry *entry;
	int r;

	while ((entry = l_queue_pop_head(station->autoconnect_list))) {
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

static int autoconnect_rank_compare(const void *a, const void *b, void *user)
{
	const struct autoconnect_entry *new_ae = a;
	const struct autoconnect_entry *ae = b;

	return ae->rank - new_ae->rank;
}

static void station_add_autoconnect_bss(struct station *station,
					struct network *network,
					struct scan_bss *bss)
{
	double rankmod;
	struct autoconnect_entry *entry;

	/* See if network is autoconnectable (is a known network) */
	if (!network_rankmod(network, &rankmod))
		return;

	entry = l_new(struct autoconnect_entry, 1);
	entry->network = network;
	entry->bss = bss;
	entry->rank = bss->rank * rankmod;
	l_queue_insert(station->autoconnect_list, entry,
				autoconnect_rank_compare, NULL);
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

static bool process_network(const void *key, void *data, void *user_data)
{
	struct network *network = data;
	struct station *station = user_data;

	if (!network_bss_list_isempty(network)) {
		bool connected = network == station->connected_network;

		/* Build the network list ordered by rank */
		network_rank_update(network, connected);

		l_queue_insert(station->networks_sorted, network,
				network_rank_compare, NULL);

		return false;
	}

	/* Drop networks that have no more BSSs in range */
	l_debug("No remaining BSSs for SSID: %s -- Removing network",
			network_get_ssid(network));
	network_remove(network, -ERANGE);

	return true;
}

static const char *iwd_network_get_path(struct station *station,
					const char *ssid,
					enum security security)
{
	static char path[256];
	unsigned int pos, i;

	pos = snprintf(path, sizeof(path), "%s/",
					netdev_get_path(station->netdev));

	for (i = 0; ssid[i] && pos < sizeof(path); i++)
		pos += snprintf(path + pos, sizeof(path) - pos, "%02x",
								ssid[i]);

	snprintf(path + pos, sizeof(path) - pos, "_%s",
				security_to_str(security));

	return path;
}

struct network *station_network_find(struct station *station, const char *ssid,
					enum security security)
{
	const char *path = iwd_network_get_path(station, ssid, security);

	return l_hashmap_lookup(station->networks, path);
}

/*
 * Returns the network object the BSS was added to or NULL if ignored.
 */
static struct network *station_add_seen_bss(struct station *station,
						struct scan_bss *bss)
{
	struct network *network;
	struct ie_rsn_info info;
	int r;
	enum security security;
	const char *path;
	char ssid[33];

	l_debug("Found BSS '%s' with SSID: %s, freq: %u, rank: %u, "
			"strength: %i",
			util_address_to_string(bss->addr),
			util_ssid_to_utf8(bss->ssid_len, bss->ssid),
			bss->frequency, bss->rank, bss->signal_strength);

	if (util_ssid_is_hidden(bss->ssid_len, bss->ssid)) {
		l_debug("Ignoring BSS with hidden SSID");
		station->seen_hidden_networks = true;
		return NULL;
	}

	if (!util_ssid_is_utf8(bss->ssid_len, bss->ssid)) {
		l_debug("Ignoring BSS with non-UTF8 SSID");
		return NULL;
	}

	memcpy(ssid, bss->ssid, bss->ssid_len);
	ssid[bss->ssid_len] = '\0';

	memset(&info, 0, sizeof(info));
	r = scan_bss_get_rsn_info(bss, &info);
	if (r < 0) {
		if (r != -ENOENT)
			return NULL;

		security = security_determine(bss->capability, NULL);
	} else
		security = security_determine(bss->capability, &info);

	path = iwd_network_get_path(station, ssid, security);

	network = l_hashmap_lookup(station->networks, path);
	if (!network) {
		network = network_create(station, ssid, security);

		if (!network_register(network, path)) {
			network_remove(network, -EINVAL);
			return NULL;
		}

		l_hashmap_insert(station->networks,
					network_get_path(network), network);
		l_debug("Added new Network \"%s\" security %s",
			network_get_ssid(network), security_to_str(security));
	}

	network_bss_add(network, bss);

	return network;
}

static bool bss_match(const void *a, const void *b)
{
	const struct scan_bss *bss_a = a;
	const struct scan_bss *bss_b = b;

	return !memcmp(bss_a->addr, bss_b->addr, sizeof(bss_a->addr));
}

/*
 * Used when scan results were obtained; either from passive scan running
 * inside station module or active scans running in other state machines, e.g.
 * wsc
 */
void station_set_scan_results(struct station *station, struct l_queue *bss_list,
					bool add_to_autoconnect)
{
	struct l_queue *old_bss_list = station->bss_list;
	struct network *network;
	const struct l_queue_entry *bss_entry;

	station->bss_list = bss_list;

	station->seen_hidden_networks = false;

	while ((network = l_queue_pop_head(station->networks_sorted)))
		network_bss_list_clear(network);

	l_queue_destroy(station->autoconnect_list, l_free);
	station->autoconnect_list = l_queue_new();

	for (bss_entry = l_queue_get_entries(bss_list); bss_entry;
				bss_entry = bss_entry->next) {
		struct scan_bss *bss = bss_entry->data;
		struct network *network = station_add_seen_bss(station, bss);

		if (network && add_to_autoconnect)
			station_add_autoconnect_bss(station, network, bss);
	}

	if (station->connected_bss) {
		struct scan_bss *bss;

		bss = l_queue_find(station->bss_list, bss_match,
						station->connected_bss);

		if (!bss) {
			l_warn("Connected BSS not in scan results!");
			station->connected_bss->rank = 0;
			l_queue_push_tail(station->bss_list,
						station->connected_bss);
			network_bss_add(station->connected_network,
						station->connected_bss);
			l_queue_remove(old_bss_list, station->connected_bss);
		} else
			station->connected_bss = bss;
	}

	l_hashmap_foreach_remove(station->networks, process_network, station);

	l_queue_destroy(old_bss_list, bss_free);
}

static enum ie_rsn_akm_suite select_akm_suite(struct network *network,
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

static void station_handshake_event(struct handshake_state *hs,
					enum handshake_event event,
					void *event_data, void *user_data)
{
	struct station *station = user_data;
	struct network *network = station->connected_network;

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

struct handshake_state *station_handshake_setup(struct station *station,
						struct network *network,
						struct scan_bss *bss)
{
	enum security security = network_get_security(network);
	struct wiphy *wiphy = station->wiphy;
	struct handshake_state *hs;
	bool add_mde = false;

	hs = netdev_handshake_state_new(station->netdev);

	handshake_state_set_event_func(hs, station_handshake_event, station);

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

		info.akm_suites = select_akm_suite(network, bss, &bss_info);

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
			handshake_state_set_authenticator_rsn(hs, bss->rsne);
			handshake_state_set_supplicant_rsn(hs, rsne_buf);
		} else {
			ie_build_wpa(&info, rsne_buf);
			handshake_state_set_authenticator_wpa(hs, bss->wpa);
			handshake_state_set_supplicant_wpa(hs, rsne_buf);
		}

		if (security == SECURITY_PSK) {
			/* SAE will generate/set the PMK */
			if (info.akm_suites == IE_RSN_AKM_SUITE_SAE_SHA256)
				handshake_state_set_passphrase(hs,
					network_get_passphrase(network));
			else
				handshake_state_set_pmk(hs,
						network_get_psk(network), 32);
		} else
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

static bool new_scan_results(uint32_t wiphy_id, uint32_t ifindex, int err,
				struct l_queue *bss_list, void *userdata)
{
	struct station *station = userdata;
	struct l_dbus *dbus = dbus_get_bus();
	bool autoconnect;

	if (station->scanning) {
		station->scanning = false;
		l_dbus_property_changed(dbus, netdev_get_path(station->netdev),
					IWD_DEVICE_INTERFACE, "Scanning");
	}

	if (err)
		return false;

	autoconnect = station_get_state(station) == STATION_STATE_AUTOCONNECT;
	station_set_scan_results(station, bss_list, autoconnect);

	if (autoconnect)
		station_autoconnect_next(station);

	return true;
}

static void periodic_scan_trigger(int err, void *user_data)
{
	struct station *station = user_data;
	struct l_dbus *dbus = dbus_get_bus();

	station->scanning = true;
	l_dbus_property_changed(dbus, netdev_get_path(station->netdev),
				IWD_DEVICE_INTERFACE, "Scanning");
}

static void periodic_scan_stop(struct station *station)
{
	struct l_dbus *dbus = dbus_get_bus();
	uint32_t index = netdev_get_ifindex(station->netdev);

	scan_periodic_stop(index);

	if (station->scanning) {
		station->scanning = false;
		l_dbus_property_changed(dbus, netdev_get_path(station->netdev),
					IWD_DEVICE_INTERFACE, "Scanning");
	}
}

const char *station_state_to_string(enum station_state state)
{
	switch (state) {
	case STATION_STATE_DISCONNECTED:
		return "disconnected";
	case STATION_STATE_AUTOCONNECT:
		return "autoconnect";
	case STATION_STATE_CONNECTING:
		return "connecting";
	case STATION_STATE_CONNECTED:
		return "connected";
	case STATION_STATE_DISCONNECTING:
		return "disconnecting";
	case STATION_STATE_ROAMING:
		return "roaming";
	}

	return "invalid";
}

void station_enter_state(struct station *station, enum station_state state)
{
	uint32_t index = netdev_get_ifindex(station->netdev);
	struct l_dbus *dbus = dbus_get_bus();
	bool disconnected;

	l_debug("Old State: %s, new state: %s",
			station_state_to_string(station->state),
			station_state_to_string(state));

	disconnected = station->state <= STATION_STATE_AUTOCONNECT;

	if ((disconnected && state > STATION_STATE_AUTOCONNECT) ||
			(!disconnected && state != station->state))
		l_dbus_property_changed(dbus, netdev_get_path(station->netdev),
					IWD_DEVICE_INTERFACE, "State");

	switch (state) {
	case STATION_STATE_AUTOCONNECT:
		scan_periodic_start(index, periodic_scan_trigger,
					new_scan_results, station);
		break;
	case STATION_STATE_DISCONNECTED:
	case STATION_STATE_CONNECTED:
	case STATION_STATE_CONNECTING:
		periodic_scan_stop(station);
		break;
	case STATION_STATE_DISCONNECTING:
	case STATION_STATE_ROAMING:
		break;
	}

	station->state = state;

	WATCHLIST_NOTIFY(&station->state_watches,
					station_state_watch_func_t, state);
}

enum station_state station_get_state(struct station *station)
{
	return station->state;
}

uint32_t station_add_state_watch(struct station *station,
					station_state_watch_func_t func,
					void *user_data,
					station_destroy_func_t destroy)
{
	return watchlist_add(&station->state_watches, func, user_data, destroy);
}

bool station_remove_state_watch(struct station *station, uint32_t id)
{
	return watchlist_remove(&station->state_watches, id);
}

bool station_set_autoconnect(struct station *station, bool autoconnect)
{
	if (station->autoconnect == autoconnect)
		return true;

	station->autoconnect = autoconnect;

	if (station->state == STATION_STATE_DISCONNECTED && autoconnect)
		station_enter_state(station, STATION_STATE_AUTOCONNECT);

	if (station->state == STATION_STATE_AUTOCONNECT && !autoconnect)
		station_enter_state(station, STATION_STATE_DISCONNECTED);

	return true;
}

static void station_roam_state_clear(struct station *station)
{
	l_timeout_remove(station->roam_trigger_timeout);
	station->roam_trigger_timeout = NULL;
	station->preparing_roam = false;
	station->signal_low = false;
	station->roam_min_time.tv_sec = 0;

	if (station->roam_scan_id)
		scan_cancel(netdev_get_ifindex(station->netdev),
						station->roam_scan_id);
}

static void station_roam_timeout_rearm(struct station *station, int seconds);

void station_roamed(struct station *station)
{
	/*
	 * New signal high/low notification should occur on the next
	 * beacon from new AP.
	 */
	station->signal_low = false;
	station->roam_min_time.tv_sec = 0;
	station->roam_no_orig_ap = false;
}

void station_roam_failed(struct station *station)
{
	struct device *device = netdev_get_device(station->netdev);
	/*
	 * If we're still connected to the old BSS, only clear preparing_roam
	 * and reattempt in 60 seconds if signal level is still low at that
	 * time.  Otherwise (we'd already started negotiating with the
	 * transition target, preparing_roam is false, state is roaming) we
	 * are now disconnected.
	 */

	l_debug("%d", netdev_get_ifindex(station->netdev));

	station->preparing_roam = false;
	station->roam_no_orig_ap = false;
	station->ap_directed_roaming = false;

	if (station->state == STATION_STATE_ROAMING)
		device_disassociated(device);
	else if (station->signal_low)
		station_roam_timeout_rearm(station, 60);
}

static void station_roam_scan_triggered(int err, void *user_data)
{
	struct station *station = user_data;

	if (err) {
		station_roam_failed(station);
		return;
	}

	/*
	 * Do not update the Scanning property as we won't be updating the
	 * list of networks.
	 */
}

static bool station_roam_scan_notify(uint32_t wiphy_id, uint32_t ifindex,
					int err, struct l_queue *bss_list,
					void *userdata)
{
	struct station *station = userdata;
	struct device *device = netdev_get_device(station->netdev);
	struct network *network = station->connected_network;
	struct handshake_state *hs = netdev_get_handshake(station->netdev);
	struct scan_bss *bss;
	struct scan_bss *best_bss = NULL;
	double best_bss_rank = 0.0;
	static const double RANK_FT_FACTOR = 1.3;
	uint16_t mdid;
	enum security orig_security, security;
	bool seen = false;

	if (err) {
		station_roam_failed(station);
		return false;
	}

	/*
	 * Do not call station_set_scan_results because this may have been
	 * a partial scan.  We could at most update the current networks' BSS
	 * list in its station->networks entry.
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
		if (station->ap_directed_roaming && !memcmp(bss->addr,
				station->connected_bss->addr, 6))
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

		if (!wiphy_can_connect(station->wiphy, bss))
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

	/* See if we have anywhere to roam to */
	if (!best_bss || scan_bss_addr_eq(best_bss, station->connected_bss))
		goto fail_free_bss;

	bss = network_bss_find_by_addr(network, best_bss->addr);
	if (bss) {
		scan_bss_free(best_bss);
		best_bss = bss;
	} else {
		network_bss_add(network, best_bss);
		l_queue_push_tail(station->bss_list, best_bss);
	}

	device_transition_start(device, best_bss);

	return true;

fail_free_bss:
	if (best_bss)
		scan_bss_free(best_bss);

	station_roam_failed(station);

	return true;
}

static void station_roam_scan_destroy(void *userdata)
{
	struct station *station = userdata;

	station->roam_scan_id = 0;
}

static void station_roam_scan(struct station *station,
				struct scan_freq_set *freq_set)
{
	struct scan_parameters params = { .freqs = freq_set, .flush = true };

	if (station->connected_network)
		/* Use direct probe request */
		params.ssid = network_get_ssid(station->connected_network);

	station->roam_scan_id =
		scan_active_full(netdev_get_ifindex(station->netdev), &params,
					station_roam_scan_triggered,
					station_roam_scan_notify, station,
					station_roam_scan_destroy);

	if (!station->roam_scan_id)
		station_roam_failed(station);
}

static uint32_t station_freq_from_neighbor_report(const uint8_t *country,
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

static void station_neighbor_report_cb(struct netdev *netdev, int err,
					const uint8_t *reports,
					size_t reports_len, void *user_data)
{
	struct station *station = user_data;
	struct ie_tlv_iter iter;
	int count_md = 0, count_no_md = 0;
	struct scan_freq_set *freq_set_md, *freq_set_no_md;
	uint32_t current_freq = 0;
	struct handshake_state *hs = netdev_get_handshake(station->netdev);

	/*
	 * Check if we're still attempting to roam -- if dbus Disconnect
	 * had been called in the meantime we just abort the attempt.
	 */
	if (!station->preparing_roam || err == -ENODEV)
		return;

	if (!reports || err) {
		/* Have to do a full scan */
		station_roam_scan(station, NULL);

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

		if (station->connected_bss->cc_present)
			cc = station->connected_bss->cc;

		freq = station_freq_from_neighbor_report(cc, &info, &band);
		if (!freq)
			continue;

		/* Skip if the band is not supported */
		if (!(band & wiphy_get_supported_bands(station->wiphy)))
			continue;

		if (!memcmp(info.addr,
				station->connected_bss->addr, ETH_ALEN)) {
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
		current_freq = station->connected_bss->frequency;

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

		station_roam_scan(station, freq_set_md);
	} else if (count_no_md) {
		scan_freq_set_add(freq_set_no_md, current_freq);

		station_roam_scan(station, freq_set_no_md);
	} else
		station_roam_scan(station, NULL);

	scan_freq_set_free(freq_set_md);
	scan_freq_set_free(freq_set_no_md);
}

static void station_roam_trigger_cb(struct l_timeout *timeout, void *user_data)
{
	struct station *station = user_data;

	l_debug("%d", netdev_get_ifindex(station->netdev));

	l_timeout_remove(station->roam_trigger_timeout);
	station->roam_trigger_timeout = NULL;
	station->preparing_roam = true;

	/*
	 * If current BSS supports Neighbor Reports, narrow the scan down
	 * to channels occupied by known neighbors in the ESS.  This isn't
	 * 100% reliable as the neighbor lists are not required to be
	 * complete or current.  It is likely still better than doing a
	 * full scan.  10.11.10.1: "A neighbor report may not be exhaustive
	 * either by choice, or due to the fact that there may be neighbor
	 * APs not known to the AP."
	 */
	if (station->connected_bss->cap_rm_neighbor_report &&
			!station->roam_no_orig_ap)
		if (!netdev_neighbor_report_req(station->netdev,
						station_neighbor_report_cb))
			return;

	/* Otherwise do a full scan for target BSS candidates */
	station_roam_scan(station, NULL);
}

static void station_roam_timeout_rearm(struct station *station, int seconds)
{
	struct timespec now, min_timeout;

	clock_gettime(CLOCK_MONOTONIC, &now);

	min_timeout = now;
	min_timeout.tv_sec += seconds;

	if (station->roam_min_time.tv_sec < min_timeout.tv_sec ||
			(station->roam_min_time.tv_sec == min_timeout.tv_sec &&
			 station->roam_min_time.tv_nsec < min_timeout.tv_nsec))
		station->roam_min_time = min_timeout;

	seconds = station->roam_min_time.tv_sec - now.tv_sec +
		(station->roam_min_time.tv_nsec > now.tv_nsec ? 1 : 0);

	station->roam_trigger_timeout =
		l_timeout_create(seconds, station_roam_trigger_cb,
								station, NULL);
}

void station_lost_beacon(struct station *station)
{
	l_debug("%d", netdev_get_ifindex(station->netdev));

	if (station->state != STATION_STATE_ROAMING &&
			station->state != STATION_STATE_CONNECTED)
		return;

	/*
	 * Tell the roam mechanism to not bother requesting Neighbor Reports,
	 * preauthenticating or performing other over-the-DS type of
	 * authentication to target AP, even while station->connected_bss is
	 * still non-NULL.  The current connection is in a serious condition
	 * and we might wasting our time with those mechanisms.
	 */
	station->roam_no_orig_ap = true;

	if (station->preparing_roam || station->state == STATION_STATE_ROAMING)
		return;

	station_roam_trigger_cb(NULL, station);
}

#define WNM_REQUEST_MODE_PREFERRED_CANDIDATE_LIST	(1 << 0)
#define WNM_REQUEST_MODE_TERMINATION_IMMINENT		(1 << 3)
#define WNM_REQUEST_MODE_ESS_DISASSOCIATION_IMMINENT	(1 << 4)

void station_ap_directed_roam(struct station *station,
				const struct mmpdu_header *hdr,
				const void *body, size_t body_len)
{
	uint32_t pos = 0;
	uint8_t req_mode;
	uint16_t dtimer;
	uint8_t valid_interval;

	if (station->preparing_roam || station->state == STATION_STATE_ROAMING)
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

	station->ap_directed_roaming = true;
	station->preparing_roam = true;

	l_timeout_remove(station->roam_trigger_timeout);
	station->roam_trigger_timeout = NULL;

	if (req_mode & WNM_REQUEST_MODE_PREFERRED_CANDIDATE_LIST)
		station_neighbor_report_cb(station->netdev, 0, body + pos,
				body_len - pos,station);
	else
		station_roam_scan(station, NULL);

	return;

format_error:
	l_debug("bad AP roam frame formatting");
}

void station_low_rssi(struct station *station)
{
	if (station->signal_low)
		return;

	station->signal_low = true;

	if (station->preparing_roam ||
			station->state == STATION_STATE_ROAMING)
		return;

	/* Set a 5-second initial timeout */
	station_roam_timeout_rearm(station, 5);
}

void station_ok_rssi(struct station *station)
{
	l_timeout_remove(station->roam_trigger_timeout);
	station->roam_trigger_timeout = NULL;

	station->signal_low = false;
}

void station_reset_connection_state(struct station *station)
{
	struct network *network = station->connected_network;
	struct l_dbus *dbus = dbus_get_bus();

	if (!network)
		return;

	if (station->state == STATION_STATE_CONNECTED ||
			station->state == STATION_STATE_CONNECTING ||
			station->state == STATION_STATE_ROAMING)
		network_disconnected(network);

	station_roam_state_clear(station);

	station->connected_bss = NULL;
	station->connected_network = NULL;

	l_dbus_property_changed(dbus, netdev_get_path(station->netdev),
				IWD_DEVICE_INTERFACE, "ConnectedNetwork");
	l_dbus_property_changed(dbus, network_get_path(network),
				IWD_NETWORK_INTERFACE, "Connected");
}

static void station_hidden_network_scan_triggered(int err, void *user_data)
{
	struct station *station = user_data;

	l_debug("");

	if (!err)
		return;

	dbus_pending_reply(&station->connect_pending,
				dbus_error_failed(station->connect_pending));
}

static bool station_hidden_network_scan_results(uint32_t wiphy_id,
						uint32_t ifindex, int err,
						struct l_queue *bss_list,
						void *userdata)
{
	struct station *station = userdata;
	struct network *network_psk;
	struct network *network_open;
	struct network *network;
	const char *ssid;
	uint8_t ssid_len;
	struct l_dbus_message *msg;
	struct scan_bss *bss;

	l_debug("");

	msg = station->connect_pending;
	station->connect_pending = NULL;

	if (err) {
		dbus_pending_reply(&msg, dbus_error_failed(msg));
		return false;
	}

	if (!l_dbus_message_get_arguments(msg, "s", &ssid)) {
		dbus_pending_reply(&msg, dbus_error_invalid_args(msg));
		return false;
	}

	ssid_len = strlen(ssid);

	while ((bss = l_queue_pop_head(bss_list))) {
		if (bss->ssid_len != ssid_len ||
					memcmp(bss->ssid, ssid, ssid_len))
			goto next;

		if (station_add_seen_bss(station, bss)) {
			l_queue_push_tail(station->bss_list, bss);

			continue;
		}

next:
		scan_bss_free(bss);
	}

	l_queue_destroy(bss_list, NULL);

	network_psk = station_network_find(station, ssid, SECURITY_PSK);
	network_open = station_network_find(station, ssid, SECURITY_NONE);

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

struct l_dbus_message *station_dbus_connect_hidden_network(
						struct l_dbus *dbus,
						struct l_dbus_message *message,
						void *user_data)
{
	struct station *station = user_data;
	uint32_t index = netdev_get_ifindex(station->netdev);
	struct scan_parameters params = {
		.flush = true,
		.randomize_mac_addr_hint = true,
	};
	const char *ssid;

	l_debug("");

	if (station->connect_pending || station_is_busy(station))
		return dbus_error_busy(message);

	if (!l_dbus_message_get_arguments(message, "s", &ssid))
		return dbus_error_invalid_args(message);

	if (strlen(ssid) > 32)
		return dbus_error_invalid_args(message);

	if (known_networks_find(ssid, SECURITY_PSK) ||
			known_networks_find(ssid, SECURITY_NONE))
		return dbus_error_already_provisioned(message);

	if (station_network_find(station, ssid, SECURITY_PSK) ||
			station_network_find(station, ssid, SECURITY_NONE))
		return dbus_error_not_hidden(message);

	params.ssid = ssid;

	if (!scan_active_full(index, &params,
				station_hidden_network_scan_triggered,
				station_hidden_network_scan_results,
				station, NULL))
		return dbus_error_failed(message);

	station->connect_pending = l_dbus_message_ref(message);

	return NULL;
}

static void station_disconnect_cb(struct netdev *netdev, bool success,
					void *user_data)
{
	struct station *station = user_data;

	l_debug("%u, success: %d",
			netdev_get_ifindex(station->netdev), success);

	if (station->disconnect_pending) {
		struct l_dbus_message *reply;

		if (success) {
			reply = l_dbus_message_new_method_return(
						station->disconnect_pending);
			l_dbus_message_set_arguments(reply, "");
		} else
			reply = dbus_error_failed(station->disconnect_pending);


		dbus_pending_reply(&station->disconnect_pending, reply);

	}

	station_enter_state(station, STATION_STATE_DISCONNECTED);

	if (station->autoconnect)
		station_enter_state(station, STATION_STATE_AUTOCONNECT);
}

int station_disconnect(struct station *station)
{
	if (station->state == STATION_STATE_DISCONNECTING)
		return -EBUSY;

	if (!station->connected_bss)
		return -ENOTCONN;

	if (netdev_disconnect(station->netdev,
					station_disconnect_cb, station) < 0)
		return -EIO;

	/*
	 * If the disconnect somehow fails we won't know if we're still
	 * connected so we may as well indicate now that we're no longer
	 * connected.
	 */
	station_reset_connection_state(station);

	station_enter_state(station, STATION_STATE_DISCONNECTING);

	return 0;
}

struct l_dbus_message *station_dbus_disconnect(struct l_dbus *dbus,
						struct l_dbus_message *message,
						void *user_data)
{
	struct station *station = user_data;
	int result;

	l_debug("");

	/*
	 * Disconnect was triggered by the user, don't autoconnect. Wait for
	 * the user's explicit instructions to scan and connect to the network
	 */
	station_set_autoconnect(station, false);

	if (station->state == STATION_STATE_AUTOCONNECT ||
			station->state == STATION_STATE_DISCONNECTED)
		return l_dbus_message_new_method_return(message);

	result = station_disconnect(station);
	if (result < 0)
		return dbus_error_from_errno(result, message);

	station->disconnect_pending = l_dbus_message_ref(message);

	return NULL;
}

struct l_dbus_message *station_dbus_get_networks(struct l_dbus *dbus,
						struct l_dbus_message *message,
						void *user_data)
{
	struct station *station = user_data;
	struct l_dbus_message *reply;
	struct l_dbus_message_builder *builder;
	struct l_queue *sorted = station->networks_sorted;
	const struct l_queue_entry *entry;

	reply = l_dbus_message_new_method_return(message);
	builder = l_dbus_message_builder_new(reply);

	l_dbus_message_builder_enter_array(builder, "(osns)");

	for (entry = l_queue_get_entries(sorted); entry; entry = entry->next) {
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

static void station_dbus_scan_triggered(int err, void *user_data)
{
	struct station *station = user_data;
	struct l_dbus_message *reply;
	struct l_dbus *dbus = dbus_get_bus();

	l_debug("station_scan_triggered: %i", err);

	if (err < 0) {
		reply = dbus_error_from_errno(err, station->scan_pending);
		dbus_pending_reply(&station->scan_pending, reply);
		return;
	}

	l_debug("Scan triggered for %s", netdev_get_name(station->netdev));

	reply = l_dbus_message_new_method_return(station->scan_pending);
	l_dbus_message_set_arguments(reply, "");
	dbus_pending_reply(&station->scan_pending, reply);

	station->scanning = true;
	l_dbus_property_changed(dbus, netdev_get_path(station->netdev),
				IWD_DEVICE_INTERFACE, "Scanning");
}

struct l_dbus_message *station_dbus_scan(struct l_dbus *dbus,
						struct l_dbus_message *message,
						void *user_data)
{
	struct station *station = user_data;
	uint32_t index = netdev_get_ifindex(station->netdev);

	l_debug("Scan called from DBus");

	if (station->scan_pending)
		return dbus_error_busy(message);

	station->scan_pending = l_dbus_message_ref(message);

	/*
	 * If we're not connected and no hidden networks are seen & configured,
	 * use passive scanning to hide our MAC address
	 */
	if (!station->connected_bss &&
			!(station->seen_hidden_networks &&
				known_networks_has_hidden())) {
		if (!scan_passive(index, station_dbus_scan_triggered,
					new_scan_results, station, NULL))
			return dbus_error_failed(message);
	} else {
		struct scan_parameters params;

		memset(&params, 0, sizeof(params));

		/* If we're connected, HW cannot randomize our MAC */
		if (!station->connected_bss)
			params.randomize_mac_addr_hint = true;

		if (!scan_active_full(index, &params,
					station_dbus_scan_triggered,
					new_scan_results, station, NULL))
			return dbus_error_failed(message);
	}

	return NULL;
}

void station_foreach(station_foreach_func_t func, void *user_data)
{
	const struct l_queue_entry *entry;

	for (entry = l_queue_get_entries(station_list); entry;
					entry = entry->next) {
		struct station *station = entry->data;

		func(station, user_data);
	}
}

struct station *station_find(uint32_t ifindex)
{
	const struct l_queue_entry *entry;

	for (entry = l_queue_get_entries(station_list); entry;
				entry = entry->next) {
		struct station *station = entry->data;

		if (netdev_get_ifindex(station->netdev) == ifindex)
			return station;
	}

	return NULL;
}

struct station *station_create(struct wiphy *wiphy, struct netdev *netdev)
{
	struct station *station;

	station = l_new(struct station, 1);
	watchlist_init(&station->state_watches, NULL);

	station->bss_list = l_queue_new();
	station->networks = l_hashmap_new();
	l_hashmap_set_hash_function(station->networks, l_str_hash);
	l_hashmap_set_compare_function(station->networks,
				(l_hashmap_compare_func_t) strcmp);
	station->networks_sorted = l_queue_new();

	station->wiphy = wiphy;
	station->netdev = netdev;

	l_queue_push_head(station_list, station);

	station_set_autoconnect(station, true);

	return station;
}

void station_free(struct station *station)
{
	l_debug("");

	if (!l_queue_remove(station_list, station))
		return;

	periodic_scan_stop(station);

	if (station->connect_pending)
		dbus_pending_reply(&station->connect_pending,
				dbus_error_aborted(station->connect_pending));

	if (station->disconnect_pending)
		dbus_pending_reply(&station->disconnect_pending,
			dbus_error_aborted(station->disconnect_pending));

	if (station->scan_pending)
		dbus_pending_reply(&station->scan_pending,
			dbus_error_aborted(station->scan_pending));

	l_timeout_remove(station->roam_trigger_timeout);

	l_queue_destroy(station->networks_sorted, NULL);
	l_hashmap_destroy(station->networks, network_free);
	l_queue_destroy(station->bss_list, bss_free);
	l_queue_destroy(station->autoconnect_list, l_free);

	watchlist_destroy(&station->state_watches);

	l_free(station);
}

bool station_init(void)
{
	station_list = l_queue_new();
	return true;
}

void station_exit(void)
{
	l_queue_destroy(station_list, NULL);
	station_list = NULL;
}
