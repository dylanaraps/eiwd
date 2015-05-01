/*
 *
 *  Wireless daemon for Linux
 *
 *  Copyright (C) 2015  Intel Corporation. All rights reserved.
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
#include <stdio.h>
#include <errno.h>
#include <sys/socket.h>
#include <linux/if.h>
#include <linux/if_ether.h>
#include <ell/ell.h>

#include "linux/nl80211.h"
#include "src/iwd.h"
#include "src/wiphy.h"
#include "src/ie.h"
#include "src/scan.h"

void scan_start(struct l_genl_family *nl80211, uint32_t ifindex,
		scan_func_t callback, void *user_data)
{
	struct l_genl_msg *msg;

	msg = l_genl_msg_new_sized(NL80211_CMD_TRIGGER_SCAN, 16);
	l_genl_msg_append_attr(msg, NL80211_ATTR_IFINDEX, 4, &ifindex);
	l_genl_family_send(nl80211, msg, callback, user_data, NULL);
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

void scan_get_results(struct l_genl_family *nl80211, uint32_t ifindex,
			scan_func_t callback, scan_done_func_t scan_done,
			void *user_data)
{
	struct l_genl_msg *msg;

	msg = l_genl_msg_new_sized(NL80211_CMD_GET_SCAN, 8);
	l_genl_msg_append_attr(msg, NL80211_ATTR_IFINDEX, 4, &ifindex);
	l_genl_family_dump(nl80211, msg, callback, user_data, scan_done);
}

enum scan_ssid_security scan_get_ssid_security(
					enum ie_bss_capability bss_capability,
					const struct ie_rsn_info *info)
{
	if (info && (info->akm_suites & IE_RSN_AKM_SUITE_PSK ||
			info->akm_suites & IE_RSN_AKM_SUITE_PSK_SHA256 ||
			info->akm_suites & IE_RSN_AKM_SUITE_FT_USING_PSK ||
			info->akm_suites & IE_RSN_AKM_SUITE_SAE_SHA256 ||
			info->akm_suites & IE_RSN_AKM_SUITE_FT_OVER_SAE_SHA256))
		return SCAN_SSID_SECURITY_PSK;

	if (info && (info->akm_suites & IE_RSN_AKM_SUITE_8021X ||
			info->akm_suites & IE_RSN_AKM_SUITE_8021X_SHA256 ||
			info->akm_suites & IE_RSN_AKM_SUITE_FT_OVER_8021X))
		return SCAN_SSID_SECURITY_8021X;

	if (bss_capability & IE_BSS_CAP_PRIVACY)
		return SCAN_SSID_SECURITY_WEP;

	return SCAN_SSID_SECURITY_NONE;
}

static bool scan_parse_bss_information_elements(struct scan_bss *bss,
					const uint8_t **ssid, uint8_t *ssid_len,
					const void *data, uint16_t len)
{
	struct ie_tlv_iter iter;

	ie_tlv_iter_init(&iter, data, len);

	while (ie_tlv_iter_next(&iter)) {
		uint8_t tag = ie_tlv_iter_get_tag(&iter);

		switch (tag) {
		case IE_TYPE_SSID:
			if (iter.len > 32)
				return false;

			*ssid_len = iter.len;
			*ssid = iter.data;
			break;
		case IE_TYPE_RSN:
			if (!bss->rsne)
				bss->rsne = l_memdup(iter.data - 2,
								iter.len + 2);
			break;
		case IE_TYPE_VENDOR_SPECIFIC:
			/* Interested only in WPA IE from Vendor data */
			if (!bss->wpa && is_ie_wpa_ie(iter.data, iter.len))
				bss->wpa = l_memdup(iter.data - 2,
								iter.len + 2);
			break;
		}
	}

	return true;
}

static struct scan_bss *scan_parse_attr_bss(struct l_genl_attr *attr,
						const uint8_t **ssid,
						uint8_t *ssid_len)
{
	uint16_t type, len;
	const void *data;
	struct scan_bss *bss;

	bss = l_new(struct scan_bss, 1);

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
						ssid, ssid_len, data, len))
				goto fail;

			break;
		}
	}

	return bss;

fail:
	scan_bss_free(bss);
	return NULL;
}

struct scan_bss *scan_parse_result(struct l_genl_msg *msg,
					uint32_t *out_ifindex,
					uint64_t *out_wdev,
					const uint8_t **out_ssid,
					uint8_t *out_ssid_len)
{
	struct l_genl_attr attr, nested;
	uint16_t type, len;
	const void *data;
	uint32_t ifindex;
	uint64_t wdev;
	struct scan_bss *bss = NULL;
	const uint8_t *ssid = NULL;
	uint8_t ssid_len = 0;

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

			bss = scan_parse_attr_bss(&nested, &ssid, &ssid_len);
			break;
		}
	}

	if (!bss)
		return NULL;

	if (!ssid) {
		scan_bss_free(bss);
		return NULL;
	}

	if (out_ifindex)
		*out_ifindex = ifindex;

	if (out_wdev)
		*out_wdev = wdev;

	if (out_ssid_len)
		*out_ssid_len = ssid_len;

	if (out_ssid)
		*out_ssid = ssid;

	return bss;
}

void scan_bss_free(struct scan_bss *bss)
{
	l_free(bss->rsne);
	l_free(bss->wpa);
	l_free(bss);
}
