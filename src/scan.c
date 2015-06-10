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
#include <limits.h>
#include <linux/if.h>
#include <linux/if_ether.h>
#include <ell/ell.h>

#include "linux/nl80211.h"
#include "src/iwd.h"
#include "src/wiphy.h"
#include "src/ie.h"
#include "src/scan.h"

#define SCAN_MAX_INTERVAL 320
#define SCAN_INIT_INTERVAL 10

struct l_queue *periodic_scans = NULL;

struct l_genl_family *nl80211 = NULL;
uint32_t scan_id = 0;

scan_notify_func_t notify = NULL;

struct scan_results {
	uint32_t wiphy;
	uint32_t ifindex;
	struct l_queue *bss_list;
};

struct scan_periodic {
	uint32_t ifindex;
	struct l_timeout *timeout;
	uint16_t interval;
	bool triggered:1;
};

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

static struct scan_periodic *scan_periodic_new(uint32_t ifindex)
{
	struct scan_periodic *sp;

	sp = l_new(struct scan_periodic, 1);

	sp->ifindex = ifindex;
	sp->interval = SCAN_INIT_INTERVAL;

	return sp;
}

static void scan_periodic_free(struct scan_periodic *sp)
{
	if (sp->timeout)
		l_timeout_remove(sp->timeout);

	l_free(sp);
}

static void scan_periodic_done(struct l_genl_msg *msg, void *user_data)
{
	struct scan_periodic *sp = user_data;
	int err;

	l_debug("");

	err = l_genl_msg_get_error(msg);
	if (err < 0) {
		/* Scan already in progress */
		if (err != -EBUSY)
			sp->triggered = true;
		else
			l_warn("Periodic scan could not be triggered: %s (%d)",
				strerror(-err), -err);
		return;
	}

	sp->triggered = true;
	l_debug("Periodic scan triggered for ifindex: %u", sp->ifindex);
}

static bool scan_periodic_match(const void *a, const void *b)
{
	const struct scan_periodic *sp = a;
	uint32_t ifindex = L_PTR_TO_UINT(b);

	return (sp->ifindex == ifindex);
}

void scan_periodic_start(uint32_t ifindex)
{
	struct scan_periodic *sp;

	sp = l_queue_find(periodic_scans, scan_periodic_match,
				L_UINT_TO_PTR(ifindex));

	if (sp)
		return;

	l_debug("Starting periodic scan for ifindex: %u", ifindex);

	sp = scan_periodic_new(ifindex);
	l_queue_push_head(periodic_scans, sp);
	scan_start(nl80211, ifindex, scan_periodic_done, sp);
}

bool scan_periodic_stop(uint32_t ifindex)
{
	struct scan_periodic *sp;

	sp = l_queue_remove_if(periodic_scans, scan_periodic_match,
				L_UINT_TO_PTR(ifindex));

	if (!sp)
		return false;

	l_debug("Stopping periodic scan for ifindex: %u", ifindex);

	scan_periodic_free(sp);
	return true;
}

static void scan_periodic_timeout(struct l_timeout *timeout, void *user_data)
{
	struct scan_periodic *sp = user_data;

	l_debug("scan_periodic_timeout: %u", sp->ifindex);

	sp->interval *= 2;
	scan_start(nl80211, sp->ifindex, scan_periodic_done, sp);
}

static void scan_periodic_rearm(struct scan_periodic *sp)
{
	l_debug("Arming periodic scan timer: %u", sp->interval);

	if (sp->timeout)
		l_timeout_modify(sp->timeout, sp->interval);
	else
		sp->timeout = l_timeout_create(sp->interval,
					scan_periodic_timeout, sp, NULL);
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
					"Supported Rates IE");
			break;
		case IE_TYPE_RSN:
			if (!bss->rsne)
				bss->rsne = l_memdup(iter.data - 2,
								iter.len + 2);
			break;
		case IE_TYPE_BSS_LOAD:
			if (ie_parse_bss_load(&iter, NULL, &bss->utilization,
						NULL) < 0)
				l_warn("Unable to parse BSS Load IE");
			else
				l_debug("Load: %u/255", bss->utilization);

			break;
		case IE_TYPE_VENDOR_SPECIFIC:
			/* Interested only in WPA IE from Vendor data */
			if (!bss->wpa && is_ie_wpa_ie(iter.data, iter.len))
				bss->wpa = l_memdup(iter.data - 2,
								iter.len + 2);
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

			break;
		}
	}

	return bss;

fail:
	scan_bss_free(bss);
	return NULL;
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

void scan_bss_compute_rank(struct scan_bss *bss)
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
		bss->rank *= factor;
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
	l_free(bss);
}

void bss_get_supported_ciphers(struct scan_bss *bss,
				uint16_t *pairwise_ciphers,
				uint16_t *group_ciphers)
{
	struct ie_rsn_info ie;

	*pairwise_ciphers = 0;
	*group_ciphers = 0;

	if (bss->rsne) {
		int res = ie_parse_rsne_from_data(bss->rsne, bss->rsne[1] + 2,
							&ie);
		if (res < 0) {
			l_debug("Cannot parse RSN field (%d, %s)",
					res, strerror(-res));
			return;
		}
	} else if (bss->wpa) {
		int res = ie_parse_wpa_from_data(bss->wpa, bss->wpa[1] + 2,
							&ie);
		if (res < 0) {
			l_debug("Cannot parse WPA IE (%d, %s)",
					res, strerror(-res));
			return;
		}
	} else
		return;

	*pairwise_ciphers = ie.pairwise_ciphers;
	*group_ciphers = ie.group_cipher;
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
	l_debug("computed rank: %u", bss->rank);

	l_queue_push_tail(results->bss_list, bss);
}

static void get_scan_done(void *user)
{
	struct scan_results *results = user;
	bool new_owner = false;

	l_debug("get_scan_done");

	if (!results->bss_list)
		goto done;

	if (notify)
		new_owner = notify(results->wiphy, results->ifindex,
					results->bss_list);

	if (!new_owner)
		l_queue_destroy(results->bss_list,
				(l_queue_destroy_func_t) scan_bss_free);

done:
	l_free(results);
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

	if (!notify)
		return;

	switch (cmd) {
	case NL80211_CMD_NEW_SCAN_RESULTS:
	case NL80211_CMD_SCHED_SCAN_RESULTS:
	{
		struct l_genl_msg *msg;
		struct scan_results *results;
		struct scan_periodic *sp;

		results = l_new(struct scan_results, 1);
		results->wiphy = attr_wiphy;
		results->ifindex = attr_ifindex;

		msg = l_genl_msg_new_sized(NL80211_CMD_GET_SCAN, 8);
		l_genl_msg_append_attr(msg, NL80211_ATTR_IFINDEX, 4,
						&attr_ifindex);
		l_genl_family_dump(nl80211, msg, get_scan_callback, results,
					get_scan_done);

		sp = l_queue_find(periodic_scans, scan_periodic_match,
					L_UINT_TO_PTR(attr_ifindex));
		if (sp) {
			if (!sp->triggered) {
				l_debug("Resetting periodic timeout");
				sp->interval = SCAN_INIT_INTERVAL;
			}

			scan_periodic_rearm(sp);
		}

		return;
	}
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
	l_free(freqs->channels_5ghz);
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

bool scan_init(struct l_genl_family *in, scan_notify_func_t func)
{
	nl80211 = in;
	scan_id = l_genl_family_register(nl80211, "scan", scan_notify,
						NULL, NULL);

	if (!scan_id) {
		l_error("Registering for scan notification failed");
		return false;
	}

	notify = func;
	periodic_scans = l_queue_new();

	return true;
}

bool scan_free()
{
	bool r;

	if (!nl80211)
		return false;

	notify = NULL;
	l_queue_destroy(periodic_scans,
				(l_queue_destroy_func_t) scan_periodic_free);
	periodic_scans = NULL;

	r = l_genl_family_unregister(nl80211, scan_id);
	scan_id = 0;

	return r;
}
