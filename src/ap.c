/*
 *
 *  Wireless daemon for Linux
 *
 *  Copyright (C) 2017  Intel Corporation. All rights reserved.
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
#include <linux/if_ether.h>

#include <ell/ell.h>

#include "linux/nl80211.h"

#include "src/iwd.h"
#include "src/scan.h"
#include "src/device.h"
#include "src/wiphy.h"
#include "src/crypto.h"
#include "src/ie.h"
#include "src/mpdu.h"
#include "src/ap.h"

struct ap_state {
	struct device *device;
	char *ssid;
	char *psk;
	ap_event_cb_t event_cb;
	int channel;
	unsigned int ciphers;
	uint32_t beacon_interval;
	struct l_uintset *rates;
	uint32_t start_stop_cmd_id;
};

static struct l_genl_family *nl80211 = NULL;

static struct l_queue *ap_list = NULL;

static void ap_free(void *data)
{
	struct ap_state *ap = data;

	l_free(ap->ssid);
	memset(ap->psk, 0, strlen(ap->psk));
	l_free(ap->psk);

	if (ap->start_stop_cmd_id)
		l_genl_family_cancel(nl80211, ap->start_stop_cmd_id);

	if (ap->rates)
		l_uintset_free(ap->rates);

	l_free(ap);
}

#define CIPHER_SUITE_GROUP_NOT_ALLOWED 0x000fac07

static void ap_set_rsn_info(struct ap_state *ap, struct ie_rsn_info *rsn)
{
	memset(rsn, 0, sizeof(*rsn));
	rsn->akm_suites = IE_RSN_AKM_SUITE_PSK;
	rsn->pairwise_ciphers = ap->ciphers;
	rsn->group_cipher = IE_RSN_CIPHER_SUITE_NO_GROUP_TRAFFIC;
}

/*
 * Build a Beacon frame or a Probe Response frame's header and body until
 * the TIM IE.  Except for the optional TIM IE which is inserted by the
 * kernel when needed, our contents for both frames are the same.
 * See Beacon format in 8.3.3.2 and Probe Response format in 8.3.3.10.
 */
static size_t ap_build_beacon_pr_head(struct ap_state *ap,
					enum mpdu_management_subtype stype,
					const uint8_t *dest, uint8_t *out_buf)
{
	struct mmpdu_header *mpdu = (void *) out_buf;
	size_t len;
	uint16_t capability = IE_BSS_CAP_ESS | IE_BSS_CAP_PRIVACY;
	const uint8_t *bssid = device_get_address(ap->device);
	uint32_t minr, maxr, count, r;

	memset(mpdu, 0, 36); /* Zero out header + non-IE fields */

	/* Header */
	mpdu->fc.protocol_version = 0;
	mpdu->fc.type = MPDU_TYPE_MANAGEMENT;
	mpdu->fc.subtype = stype;
	memcpy(mpdu->address_1, dest, 6);	/* DA */
	memcpy(mpdu->address_2, bssid, 6);	/* SA */
	memcpy(mpdu->address_3, bssid, 6);	/* BSSID */

	/* Body non-IE fields */
	l_put_le16(ap->beacon_interval, out_buf + 32);	/* Beacon Interval */
	l_put_le16(capability, out_buf + 34);		/* Capability Info */
	len = 36;

	/* SSID IE */
	out_buf[len++] = IE_TYPE_SSID;
	out_buf[len++] = strlen(ap->ssid);
	memcpy(out_buf + len, ap->ssid, strlen(ap->ssid));
	len += strlen(ap->ssid);

	/* Supported Rates IE */
	out_buf[len++] = IE_TYPE_SUPPORTED_RATES;

	minr = l_uintset_find_min(ap->rates);
	maxr = l_uintset_find_max(ap->rates);
	count = 0;
	for (r = minr; r <= maxr && count < 8; r++)
		if (l_uintset_contains(ap->rates, r)) {
			uint8_t flag = 0;

			/* Mark only the lowest rate as Basic Rate */
			if (count == 0)
				flag = 0x80;

			out_buf[len + 1 + count++] = r | flag;
		}

	out_buf[len++] = count;
	len += count;

	/* DSSS Parameter Set IE for DSSS, HR, ERP and HT PHY rates */
	out_buf[len++] = IE_TYPE_DSSS_PARAMETER_SET;
	out_buf[len++] = 1;
	out_buf[len++] = ap->channel;

	return len;
}

/* Beacon / Probe Response frame portion after the TIM IE */
static size_t ap_build_beacon_pr_tail(struct ap_state *ap, uint8_t *out_buf)
{
	size_t len;
	struct ie_rsn_info rsn;

	/* TODO: Country IE between TIM IE and RSNE */

	/* RSNE */
	ap_set_rsn_info(ap, &rsn);
	if (!ie_build_rsne(&rsn, out_buf))
		return 0;
	len = 2 + out_buf[1];

	return len;
}

static void ap_stopped(struct ap_state *ap)
{
	ap->event_cb(ap->device, AP_EVENT_STOPPED);

	ap_free(ap);

	l_queue_remove(ap_list, ap);
}

static void ap_start_cb(struct l_genl_msg *msg, void *user_data)
{
	struct ap_state *ap = user_data;

	ap->start_stop_cmd_id = 0;

	if (l_genl_msg_get_error(msg) < 0) {
		l_error("START_AP failed: %i", l_genl_msg_get_error(msg));

		ap_stopped(ap);
	} else {
		l_info("START_AP ok");

		ap->event_cb(ap->device, AP_EVENT_STARTED);
	}
}

static bool ap_match_device(const void *a, const void *b)
{
	const struct ap_state *ap = a;

	return ap->device == b;
}

static struct l_genl_msg *ap_build_cmd_start_ap(struct ap_state *ap)
{
	struct l_genl_msg *cmd;

	uint8_t head[256], tail[256];
	size_t head_len, tail_len;

	uint32_t dtim_period = 3;
	uint32_t ifindex = device_get_ifindex(ap->device);
	uint32_t hidden_ssid = NL80211_HIDDEN_SSID_NOT_IN_USE;
	uint32_t nl_ciphers = ie_rsn_cipher_suite_to_cipher(ap->ciphers);
	uint32_t nl_akm = CRYPTO_AKM_PSK;
	uint32_t wpa_version = NL80211_WPA_VERSION_2;
	uint32_t auth_type = NL80211_AUTHTYPE_OPEN_SYSTEM;
	uint32_t ch_freq = scan_channel_to_freq(ap->channel, SCAN_BAND_2_4_GHZ);
	uint32_t ch_width = NL80211_CHAN_WIDTH_20;

	static const uint8_t bcast_addr[6] = {
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	};

	head_len = ap_build_beacon_pr_head(ap, MPDU_MANAGEMENT_SUBTYPE_BEACON,
						bcast_addr, head);
	tail_len = ap_build_beacon_pr_tail(ap, tail);

	if (!head_len || !tail_len)
		return NULL;

	cmd = l_genl_msg_new_sized(NL80211_CMD_START_AP, 128 + head_len +
					tail_len + strlen(ap->ssid));

	/* SET_BEACON attrs */
	l_genl_msg_append_attr(cmd, NL80211_ATTR_BEACON_HEAD, head_len, head);
	l_genl_msg_append_attr(cmd, NL80211_ATTR_BEACON_TAIL, tail_len, tail);
	l_genl_msg_append_attr(cmd, NL80211_ATTR_IE, 0, "");
	l_genl_msg_append_attr(cmd, NL80211_ATTR_IE_PROBE_RESP, 0, "");
	l_genl_msg_append_attr(cmd, NL80211_ATTR_IE_ASSOC_RESP, 0, "");

	/* START_AP attrs */
	l_genl_msg_append_attr(cmd, NL80211_ATTR_BEACON_INTERVAL, 4,
				&ap->beacon_interval);
	l_genl_msg_append_attr(cmd, NL80211_ATTR_DTIM_PERIOD, 4, &dtim_period);
	l_genl_msg_append_attr(cmd, NL80211_ATTR_IFINDEX, 4, &ifindex);
	l_genl_msg_append_attr(cmd, NL80211_ATTR_SSID, strlen(ap->ssid),
				ap->ssid);
	l_genl_msg_append_attr(cmd, NL80211_ATTR_HIDDEN_SSID, 4,
				&hidden_ssid);
	l_genl_msg_append_attr(cmd, NL80211_ATTR_CIPHER_SUITES_PAIRWISE, 4,
				&nl_ciphers);
	l_genl_msg_append_attr(cmd, NL80211_ATTR_WPA_VERSIONS, 4, &wpa_version);
	l_genl_msg_append_attr(cmd, NL80211_ATTR_AKM_SUITES, 4, &nl_akm);
	l_genl_msg_append_attr(cmd, NL80211_ATTR_AUTH_TYPE, 4, &auth_type);
	l_genl_msg_append_attr(cmd, NL80211_ATTR_WIPHY_FREQ, 4, &ch_freq);
	l_genl_msg_append_attr(cmd, NL80211_ATTR_CHANNEL_WIDTH, 4, &ch_width);

	return cmd;
}

int ap_start(struct device *device, const char *ssid, const char *psk,
		ap_event_cb_t event_cb)
{
	struct wiphy *wiphy = device_get_wiphy(device);
	struct ap_state *ap;
	struct l_genl_msg *cmd;

	if (l_queue_find(ap_list, ap_match_device, device))
		return -EEXIST;

	ap = l_new(struct ap_state, 1);
	ap->device = device;
	ap->ssid = l_strdup(ssid);
	ap->psk = l_strdup(psk);
	ap->event_cb = event_cb;
	/* TODO: Start a Get Survey to decide the channel */
	ap->channel = 6;
	/* TODO: Add all ciphers supported by wiphy */
	ap->ciphers = wiphy_select_cipher(wiphy, 0xffff);
	ap->beacon_interval = 100;
	/* TODO: Use actual supported rates */
	ap->rates = l_uintset_new(200);
	l_uintset_put(ap->rates, 2); /* 1 Mbps*/
	l_uintset_put(ap->rates, 11); /* 5.5 Mbps*/
	l_uintset_put(ap->rates, 22); /* 11 Mbps*/

	cmd = ap_build_cmd_start_ap(ap);
	if (!cmd)
		goto error;

	ap->start_stop_cmd_id = l_genl_family_send(nl80211, cmd, ap_start_cb,
							ap, NULL);
	if (!ap->start_stop_cmd_id) {
		l_genl_msg_unref(cmd);
		goto error;
	}

	if (!ap_list)
		ap_list = l_queue_new();

	l_queue_push_tail(ap_list, ap);

	return 0;

error:
	ap_free(ap);

	return -EIO;
}

static void ap_stop_cb(struct l_genl_msg *msg, void *user_data)
{
	struct ap_state *ap = user_data;

	ap->start_stop_cmd_id = 0;

	if (l_genl_msg_get_error(msg) < 0)
		l_error("STOP_AP failed: %i", l_genl_msg_get_error(msg));
	else
		l_info("STOP_AP ok");

	ap_stopped(ap);
}

static struct l_genl_msg *ap_build_cmd_stop_ap(struct ap_state *ap)
{
	struct l_genl_msg *cmd;
	uint32_t ifindex = device_get_ifindex(ap->device);

	cmd = l_genl_msg_new_sized(NL80211_CMD_STOP_AP, 16);
	l_genl_msg_append_attr(cmd, NL80211_ATTR_IFINDEX, 4, &ifindex);

	return cmd;
}

int ap_stop(struct device *device)
{
	struct l_genl_msg *cmd;
	struct ap_state *ap = l_queue_find(ap_list, ap_match_device, device);

	if (!ap)
		return -ENODEV;

	cmd = ap_build_cmd_stop_ap(ap);
	if (!cmd)
		return -ENOMEM;

	if (ap->start_stop_cmd_id)
		l_genl_family_cancel(nl80211, ap->start_stop_cmd_id);

	ap->start_stop_cmd_id = l_genl_family_send(nl80211, cmd, ap_stop_cb,
							ap, NULL);
	if (!ap->start_stop_cmd_id) {
		l_genl_msg_unref(cmd);
		return -EIO;
	}

	return 0;
}

void ap_init(struct l_genl_family *in)
{
	nl80211 = in;

	/*
	 * TODO: Check wiphy supports AP mode, supported channels,
	 * check wiphy's NL80211_ATTR_TX_FRAME_TYPES.
	 */
}

void ap_exit(void)
{
	l_queue_destroy(ap_list, ap_free);
}
