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
