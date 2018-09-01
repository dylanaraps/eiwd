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

#include <ell/ell.h>

#include "src/util.h"
#include "src/iwd.h"
#include "src/common.h"
#include "src/scan.h"
#include "src/netdev.h"
#include "src/wiphy.h"
#include "src/network.h"
#include "src/ie.h"
#include "src/handshake.h"
#include "src/station.h"

static struct l_queue *station_list;

struct autoconnect_entry {
	uint16_t rank;
	struct network *network;
	struct scan_bss *bss;
};

void station_autoconnect_next(struct station *station)
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

void station_add_autoconnect_bss(struct station *station,
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
		/* Build the network list ordered by rank */
		network_rank_update(network);

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
struct network *station_add_seen_bss(struct station *station,
						struct scan_bss *bss)
{
	struct device *device = netdev_get_device(station->netdev);
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
		network = network_create(device, ssid, security);

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

struct station *station_create(struct wiphy *wiphy, struct netdev *netdev)
{
	struct station *station;

	station = l_new(struct station, 1);

	station->bss_list = l_queue_new();
	station->networks = l_hashmap_new();
	l_hashmap_set_hash_function(station->networks, l_str_hash);
	l_hashmap_set_compare_function(station->networks,
				(l_hashmap_compare_func_t) strcmp);
	station->networks_sorted = l_queue_new();

	station->wiphy = wiphy;
	station->netdev = netdev;

	l_queue_push_head(station_list, station);

	return station;
}

void station_free(struct station *station)
{
	l_debug("");

	if (!l_queue_remove(station_list, station))
		return;

	l_queue_destroy(station->networks_sorted, NULL);
	l_hashmap_destroy(station->networks, network_free);
	l_queue_destroy(station->bss_list, bss_free);
	l_queue_destroy(station->autoconnect_list, l_free);

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
