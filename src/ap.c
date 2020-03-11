/*
 *
 *  Wireless daemon for Linux
 *
 *  Copyright (C) 2017-2019  Intel Corporation. All rights reserved.
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
#include "src/module.h"
#include "src/scan.h"
#include "src/netdev.h"
#include "src/wiphy.h"
#include "src/crypto.h"
#include "src/ie.h"
#include "src/mpdu.h"
#include "src/util.h"
#include "src/eapol.h"
#include "src/handshake.h"
#ifdef HAVE_DBUS
#include "src/dbus.h"
#endif
#include "src/nl80211util.h"
#include "src/frame-xchg.h"

struct ap_state {
	struct netdev *netdev;
	struct l_genl_family *nl80211;
	char *ssid;
	uint8_t channel;
	unsigned int ciphers;
	enum ie_rsn_cipher_suite group_cipher;
	uint32_t beacon_interval;
	struct l_uintset *rates;
	uint8_t pmk[32];
	uint32_t start_stop_cmd_id;
	uint32_t mlme_watch;
	uint8_t gtk[CRYPTO_MAX_GTK_LEN];
	uint8_t gtk_index;

	uint16_t last_aid;
	struct l_queue *sta_states;

	struct l_dbus_message *pending;
	bool started : 1;
	bool gtk_set : 1;
};

struct sta_state {
	uint8_t addr[6];
	bool associated;
	bool rsna;
	uint16_t aid;
	struct mmpdu_field_capability capability;
	uint16_t listen_interval;
	struct l_uintset *rates;
	uint32_t assoc_resp_cmd_id;
	struct ap_state *ap;
	uint8_t *assoc_rsne;
	struct eapol_sm *sm;
	struct handshake_state *hs;
	uint32_t gtk_query_cmd_id;
};

static uint32_t netdev_watch;

#ifdef HAVE_DBUS
static void ap_sta_free(void *data)
{
	struct sta_state *sta = data;
	struct ap_state *ap = sta->ap;

	l_uintset_free(sta->rates);
	l_free(sta->assoc_rsne);

	if (sta->assoc_resp_cmd_id)
		l_genl_family_cancel(ap->nl80211, sta->assoc_resp_cmd_id);

	if (sta->gtk_query_cmd_id)
		l_genl_family_cancel(ap->nl80211, sta->gtk_query_cmd_id);

	if (sta->sm)
		eapol_sm_free(sta->sm);

	if (sta->hs)
		handshake_state_free(sta->hs);

	l_free(sta);
}

static void ap_reset(struct ap_state *ap)
{
	struct netdev *netdev = ap->netdev;

	if (!ap->started)
		return;

	if (ap->pending)
		dbus_pending_reply(&ap->pending,
				dbus_error_aborted(ap->pending));

	l_free(ap->ssid);

	memset(ap->pmk, 0, sizeof(ap->pmk));

	frame_watch_wdev_remove(netdev_get_wdev_id(netdev));

	if (ap->start_stop_cmd_id)
		l_genl_family_cancel(ap->nl80211, ap->start_stop_cmd_id);

	l_queue_destroy(ap->sta_states, ap_sta_free);

	if (ap->rates)
		l_uintset_free(ap->rates);

	ap->started = false;

	l_dbus_property_changed(dbus_get_bus(), netdev_get_path(ap->netdev),
						IWD_AP_INTERFACE, "Started");
}

static void ap_free(void *data)
{
	struct ap_state *ap = data;

	ap_reset(ap);
	l_genl_family_free(ap->nl80211);
	l_free(ap);
}

static void ap_del_station(struct sta_state *sta, uint16_t reason,
				bool disassociate)
{
	struct ap_state *ap = sta->ap;

	netdev_del_station(ap->netdev, sta->addr, reason, disassociate);
	sta->associated = false;
	sta->rsna = false;

	if (sta->gtk_query_cmd_id) {
		l_genl_family_cancel(ap->nl80211, sta->gtk_query_cmd_id);
		sta->gtk_query_cmd_id = 0;
	}

	if (sta->sm)
		eapol_sm_free(sta->sm);

	if (sta->hs)
		handshake_state_free(sta->hs);

	sta->hs = NULL;
	sta->sm = NULL;
}

static bool ap_sta_match_addr(const void *a, const void *b)
{
	const struct sta_state *sta = a;

	return !memcmp(sta->addr, b, 6);
}

static void ap_remove_sta(struct sta_state *sta)
{
	if (!l_queue_remove(sta->ap->sta_states, sta)) {
		l_error("tried to remove station that doesn't exist");
		return;
	}

	ap_sta_free(sta);
}

static void ap_set_sta_cb(struct l_genl_msg *msg, void *user_data)
{
	if (l_genl_msg_get_error(msg) < 0)
		l_error("SET_STATION failed: %i", l_genl_msg_get_error(msg));
}

static void ap_del_key_cb(struct l_genl_msg *msg, void *user_data)
{
	if (l_genl_msg_get_error(msg) < 0)
		l_debug("DEL_KEY failed: %i", l_genl_msg_get_error(msg));
}

static void ap_new_rsna(struct sta_state *sta)
{
	l_debug("STA "MAC" authenticated", MAC_STR(sta->addr));

	sta->rsna = true;
	/*
	 * TODO: Once new AP interface is implemented this is where a
	 * new "ConnectedPeer" property will be added.
	 */
}

static void ap_drop_rsna(struct sta_state *sta)
{
	struct ap_state *ap = sta->ap;
	struct l_genl_msg *msg;
	uint32_t ifindex = netdev_get_ifindex(sta->ap->netdev);
	uint8_t key_id = 0;

	sta->rsna = false;

	msg = nl80211_build_set_station_unauthorized(ifindex, sta->addr);

	l_genl_msg_append_attr(msg, NL80211_ATTR_STA_AID, 2, &sta->aid);

	if (!l_genl_family_send(ap->nl80211, msg, ap_set_sta_cb, NULL, NULL)) {
		l_genl_msg_unref(msg);
		l_error("Issuing SET_STATION failed");
	}

	msg = l_genl_msg_new_sized(NL80211_CMD_DEL_KEY, 64);
	l_genl_msg_append_attr(msg, NL80211_ATTR_IFINDEX, 4, &ifindex);
	l_genl_msg_append_attr(msg, NL80211_ATTR_KEY_IDX, 1, &key_id);
	l_genl_msg_append_attr(msg, NL80211_ATTR_MAC, 6, sta->addr);

	if (!l_genl_family_send(ap->nl80211, msg, ap_del_key_cb, NULL, NULL)) {
		l_genl_msg_unref(msg);
		l_error("Issuing DEL_KEY failed");
	}

	if (sta->sm)
		eapol_sm_free(sta->sm);

	if (sta->hs)
		handshake_state_free(sta->hs);

	sta->hs = NULL;
	sta->sm = NULL;
}

static void ap_set_rsn_info(struct ap_state *ap, struct ie_rsn_info *rsn)
{
	memset(rsn, 0, sizeof(*rsn));
	rsn->akm_suites = IE_RSN_AKM_SUITE_PSK;
	rsn->pairwise_ciphers = ap->ciphers;
	rsn->group_cipher = ap->group_cipher;
}

/*
 * Build a Beacon frame or a Probe Response frame's header and body until
 * the TIM IE.  Except for the optional TIM IE which is inserted by the
 * kernel when needed, our contents for both frames are the same.
 * See Beacon format in 8.3.3.2 and Probe Response format in 8.3.3.10.
 */
static size_t ap_build_beacon_pr_head(struct ap_state *ap,
					enum mpdu_management_subtype stype,
					const uint8_t *dest, uint8_t *out_buf,
					size_t out_len)
{
	struct mmpdu_header *mpdu = (void *) out_buf;
	unsigned int len;
	uint16_t capability = IE_BSS_CAP_ESS | IE_BSS_CAP_PRIVACY;
	const uint8_t *bssid = netdev_get_address(ap->netdev);
	uint32_t minr, maxr, count, r;
	uint8_t *rates;
	struct ie_tlv_builder builder;

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

	ie_tlv_builder_init(&builder, out_buf + 36, out_len - 36);

	/* SSID IE */
	ie_tlv_builder_next(&builder, IE_TYPE_SSID);
	ie_tlv_builder_set_data(&builder, ap->ssid, strlen(ap->ssid));

	/* Supported Rates IE */
	ie_tlv_builder_next(&builder, IE_TYPE_SUPPORTED_RATES);
	rates = ie_tlv_builder_get_data(&builder);

	minr = l_uintset_find_min(ap->rates);
	maxr = l_uintset_find_max(ap->rates);
	count = 0;
	for (r = minr; r <= maxr && count < 8; r++)
		if (l_uintset_contains(ap->rates, r)) {
			uint8_t flag = 0;

			/* Mark only the lowest rate as Basic Rate */
			if (count == 0)
				flag = 0x80;

			*rates++ = r | flag;
		}

	ie_tlv_builder_set_length(&builder, rates -
					ie_tlv_builder_get_data(&builder));

	/* DSSS Parameter Set IE for DSSS, HR, ERP and HT PHY rates */
	ie_tlv_builder_next(&builder, IE_TYPE_DSSS_PARAMETER_SET);
	ie_tlv_builder_set_data(&builder, &ap->channel, 1);

	ie_tlv_builder_finalize(&builder, &len);
	return 36 + len;
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

static uint32_t ap_send_mgmt_frame(struct ap_state *ap,
					const struct mmpdu_header *frame,
					size_t frame_len, bool wait_ack,
					l_genl_msg_func_t callback,
					void *user_data)
{
	struct l_genl_msg *msg;
	uint32_t ifindex = netdev_get_ifindex(ap->netdev);
	uint32_t id;
	uint32_t ch_freq = scan_channel_to_freq(ap->channel, SCAN_BAND_2_4_GHZ);

	msg = l_genl_msg_new_sized(NL80211_CMD_FRAME, 128 + frame_len);

	l_genl_msg_append_attr(msg, NL80211_ATTR_IFINDEX, 4, &ifindex);
	l_genl_msg_append_attr(msg, NL80211_ATTR_WIPHY_FREQ, 4, &ch_freq);
	l_genl_msg_append_attr(msg, NL80211_ATTR_FRAME, frame_len, frame);
	if (!wait_ack)
		l_genl_msg_append_attr(msg, NL80211_ATTR_DONT_WAIT_FOR_ACK,
					0, NULL);

	id = l_genl_family_send(ap->nl80211, msg, callback, user_data, NULL);

	if (!id)
		l_genl_msg_unref(msg);

	return id;
}

static void ap_handshake_event(struct handshake_state *hs,
		enum handshake_event event, void *user_data, ...)
{
	struct sta_state *sta = user_data;
	va_list args;

	va_start(args, user_data);

	switch (event) {
	case HANDSHAKE_EVENT_COMPLETE:
		ap_new_rsna(sta);
		break;
	case HANDSHAKE_EVENT_FAILED:
		netdev_handshake_failed(hs, va_arg(args, int));
		/* fall through */
	case HANDSHAKE_EVENT_SETTING_KEYS_FAILED:
		sta->sm = NULL;
		ap_remove_sta(sta);
	default:
		break;
	}

	va_end(args);
}

static void ap_start_rsna(struct sta_state *sta, const uint8_t *gtk_rsc)
{
	struct ap_state *ap = sta->ap;
	struct netdev *netdev = sta->ap->netdev;
	const uint8_t *own_addr = netdev_get_address(netdev);
	struct scan_bss bss;
	struct ie_rsn_info rsn;
	uint8_t bss_rsne[24];

	memset(&bss, 0, sizeof(bss));

	ap_set_rsn_info(ap, &rsn);
	/*
	 * TODO: This assumes the length that ap_set_rsn_info() requires. If
	 * ap_set_rsn_info() changes then this will need to be updated.
	 */
	ie_build_rsne(&rsn, bss_rsne);

	/* this handshake setup assumes PSK network */
	sta->hs = netdev_handshake_state_new(netdev);

	handshake_state_set_event_func(sta->hs, ap_handshake_event, sta);
	handshake_state_set_ssid(sta->hs, (void *)ap->ssid, strlen(ap->ssid));
	handshake_state_set_authenticator(sta->hs, true);
	handshake_state_set_authenticator_ie(sta->hs, bss_rsne);
	handshake_state_set_supplicant_ie(sta->hs, sta->assoc_rsne);
	handshake_state_set_pmk(sta->hs, ap->pmk, 32);
	handshake_state_set_authenticator_address(sta->hs, own_addr);
	handshake_state_set_supplicant_address(sta->hs, sta->addr);

	if (gtk_rsc)
		handshake_state_set_gtk(sta->hs, ap->gtk, ap->gtk_index,
					gtk_rsc);

	sta->sm = eapol_sm_new(sta->hs);
	if (!sta->sm) {
		handshake_state_free(sta->hs);
		sta->hs = NULL;
		l_error("could not create sm object");
		goto error;
	}

	eapol_sm_set_listen_interval(sta->sm, sta->listen_interval);

	eapol_register(sta->sm);

	return;

error:
	ap_del_station(sta, MMPDU_REASON_CODE_UNSPECIFIED, true);
}

static void ap_gtk_query_cb(struct l_genl_msg *msg, void *user_data)
{
	struct sta_state *sta = user_data;
	const void *gtk_rsc;

	sta->gtk_query_cmd_id = 0;

	gtk_rsc = nl80211_parse_get_key_seq(msg);
	if (!gtk_rsc)
		goto error;

	ap_start_rsna(sta, gtk_rsc);
	return;

error:
	ap_del_station(sta, MMPDU_REASON_CODE_UNSPECIFIED, true);
}

static struct l_genl_msg *ap_build_cmd_del_key(struct ap_state *ap)
{
	uint32_t ifindex = netdev_get_ifindex(ap->netdev);
	struct l_genl_msg *msg;

	msg = l_genl_msg_new_sized(NL80211_CMD_DEL_KEY, 128);

	l_genl_msg_append_attr(msg, NL80211_ATTR_IFINDEX, 4, &ifindex);
	l_genl_msg_enter_nested(msg, NL80211_ATTR_KEY);
	l_genl_msg_append_attr(msg, NL80211_KEY_IDX, 1, &ap->gtk_index);
	l_genl_msg_leave_nested(msg);

	return msg;
}

static struct l_genl_msg *ap_build_cmd_new_station(struct sta_state *sta)
{
	struct l_genl_msg *msg;
	uint32_t ifindex = netdev_get_ifindex(sta->ap->netdev);
	/*
	 * This should hopefully work both with and without
	 * NL80211_FEATURE_FULL_AP_CLIENT_STATE.
	 */
	struct nl80211_sta_flag_update flags = {
		.mask = (1 << NL80211_STA_FLAG_AUTHENTICATED) |
			(1 << NL80211_STA_FLAG_ASSOCIATED) |
			(1 << NL80211_STA_FLAG_AUTHORIZED) |
			(1 << NL80211_STA_FLAG_MFP),
		.set = (1 << NL80211_STA_FLAG_AUTHENTICATED) |
			(1 << NL80211_STA_FLAG_ASSOCIATED),
	};

	msg = l_genl_msg_new_sized(NL80211_CMD_NEW_STATION, 300);

	l_genl_msg_append_attr(msg, NL80211_ATTR_IFINDEX, 4, &ifindex);
	l_genl_msg_append_attr(msg, NL80211_ATTR_MAC, 6, sta->addr);
	l_genl_msg_append_attr(msg, NL80211_ATTR_STA_FLAGS2, 8, &flags);

	return msg;
}

static void ap_gtk_op_cb(struct l_genl_msg *msg, void *user_data)
{
	if (l_genl_msg_get_error(msg) < 0) {
		uint8_t cmd = l_genl_msg_get_command(msg);
		const char *cmd_name =
			cmd == NL80211_CMD_NEW_KEY ? "NEW_KEY" :
			cmd == NL80211_CMD_SET_KEY ? "SET_KEY" :
			"DEL_KEY";

		l_error("%s failed for the GTK: %i",
			cmd_name, l_genl_msg_get_error(msg));
	}
}

static void ap_associate_sta_cb(struct l_genl_msg *msg, void *user_data)
{
	struct sta_state *sta = user_data;
	struct ap_state *ap = sta->ap;

	if (l_genl_msg_get_error(msg) < 0) {
		l_error("NEW_STATION/SET_STATION failed: %i",
			l_genl_msg_get_error(msg));
		return;
	}

	/*
	 * Set up the group key.  If this is our first STA then we have
	 * to add the new GTK to the kernel.  In theory we should be
	 * able to supply our own RSC (e.g. generated randomly) and use it
	 * immediately for our 4-Way Handshake without querying the kernel.
	 * However NL80211_CMD_NEW_KEY only lets us set the receive RSC --
	 * the Rx PN for CCMP and the Rx IV for TKIP -- and the
	 * transmit RSC always starts as all zeros.  There's effectively
	 * no way to set the Tx RSC or query the Rx RSC through nl80211.
	 * So we query the Tx RSC in both scenarios just in case some
	 * driver/hardware uses a different initial Tx RSC.
	 *
	 * Optimally we would get called back by the EAPoL state machine
	 * only when building the step 3 of 4 message to query the RSC as
	 * late as possible but that would complicate EAPoL.
	 */
	if (ap->group_cipher != IE_RSN_CIPHER_SUITE_NO_GROUP_TRAFFIC &&
			!ap->gtk_set) {
		enum crypto_cipher group_cipher =
			ie_rsn_cipher_suite_to_cipher(ap->group_cipher);
		int gtk_len = crypto_cipher_key_len(group_cipher);

		/*
		 * Generate our GTK.  Not following the example derivation
		 * method in 802.11-2016 section 12.7.1.4 because a simple
		 * l_getrandom is just as good.
		 */
		l_getrandom(ap->gtk, gtk_len);
		ap->gtk_index = 1;

		msg = nl80211_build_new_key_group(
						netdev_get_ifindex(ap->netdev),
						group_cipher, ap->gtk_index,
						ap->gtk, gtk_len, NULL,
						0, NULL);

		if (!l_genl_family_send(ap->nl80211, msg, ap_gtk_op_cb, NULL,
					NULL)) {
			l_genl_msg_unref(msg);
			l_error("Issuing NEW_KEY failed");
			goto error;
		}

		msg = nl80211_build_set_key(netdev_get_ifindex(ap->netdev),
						ap->gtk_index);
		if (!l_genl_family_send(ap->nl80211, msg, ap_gtk_op_cb, NULL,
					NULL)) {
			l_genl_msg_unref(msg);
			l_error("Issuing SET_KEY failed");
			goto error;
		}

		/*
		 * Set the flag now because any new associating STA will
		 * just use NL80211_CMD_GET_KEY from now.
		 */
		ap->gtk_set = true;
	}

	if (ap->group_cipher == IE_RSN_CIPHER_SUITE_NO_GROUP_TRAFFIC)
		ap_start_rsna(sta, NULL);
	else {
		msg = nl80211_build_get_key(netdev_get_ifindex(ap->netdev),
					ap->gtk_index);
		sta->gtk_query_cmd_id = l_genl_family_send(ap->nl80211, msg,
								ap_gtk_query_cb,
								sta, NULL);
		if (!sta->gtk_query_cmd_id) {
			l_genl_msg_unref(msg);
			l_error("Issuing GET_KEY failed");
			goto error;
		}
	}

	return;

error:
	ap_del_station(sta, MMPDU_REASON_CODE_UNSPECIFIED, true);
}

static void ap_associate_sta(struct ap_state *ap, struct sta_state *sta)
{
	struct l_genl_msg *msg;
	uint32_t ifindex = netdev_get_ifindex(ap->netdev);

	uint8_t rates[256];
	uint32_t r, minr, maxr, count = 0;
	uint16_t capability = l_get_le16(&sta->capability);

	if (sta->associated)
		msg = nl80211_build_set_station_associated(ifindex, sta->addr);
	else
		msg = ap_build_cmd_new_station(sta);

	sta->associated = true;
	sta->rsna = false;

	minr = l_uintset_find_min(sta->rates);
	maxr = l_uintset_find_max(sta->rates);

	for (r = minr; r <= maxr; r++)
		if (l_uintset_contains(sta->rates, r))
			rates[count++] = r;

	l_genl_msg_append_attr(msg, NL80211_ATTR_STA_AID, 2, &sta->aid);
	l_genl_msg_append_attr(msg, NL80211_ATTR_STA_SUPPORTED_RATES,
				count, &rates);
	l_genl_msg_append_attr(msg, NL80211_ATTR_STA_LISTEN_INTERVAL, 2,
				&sta->listen_interval);
	l_genl_msg_append_attr(msg, NL80211_ATTR_STA_CAPABILITY, 2,
				&capability);

	if (!l_genl_family_send(ap->nl80211, msg, ap_associate_sta_cb,
								sta, NULL)) {
		l_genl_msg_unref(msg);
		if (l_genl_msg_get_command(msg) == NL80211_CMD_NEW_STATION)
			l_error("Issuing NEW_STATION failed");
		else
			l_error("Issuing SET_STATION failed");
	}
}

static bool ap_common_rates(struct l_uintset *ap_rates,
				struct l_uintset *sta_rates)
{
	uint32_t minr = l_uintset_find_min(ap_rates);

	/* Our lowest rate is a Basic Rate so must be supported */
	if (l_uintset_contains(sta_rates, minr))
		return true;

	return false;
}

static void ap_success_assoc_resp_cb(struct l_genl_msg *msg, void *user_data)
{
	struct sta_state *sta = user_data;
	struct ap_state *ap = sta->ap;

	sta->assoc_resp_cmd_id = 0;

	if (l_genl_msg_get_error(msg) < 0) {
		l_error("AP (Re)Association Response not sent or not ACKed: %i",
			l_genl_msg_get_error(msg));

		/* If we were in State 3 or 4 go to back to State 2 */
		if (sta->associated)
			ap_del_station(sta, MMPDU_REASON_CODE_UNSPECIFIED,
					true);

		return;
	}

	/* If we were in State 2, 3 or 4 also go to State 3 */
	ap_associate_sta(ap, sta);

	l_info("AP (Re)Association Response ACK received");
}

static void ap_fail_assoc_resp_cb(struct l_genl_msg *msg, void *user_data)
{
	if (l_genl_msg_get_error(msg) < 0)
		l_error("AP (Re)Association Response with an error status not "
			"sent or not ACKed: %i", l_genl_msg_get_error(msg));
	else
		l_info("AP (Re)Association Response with an error status "
			"delivered OK");
}

static uint32_t ap_assoc_resp(struct ap_state *ap, struct sta_state *sta,
				const uint8_t *dest, uint16_t aid,
				enum mmpdu_reason_code status_code,
				bool reassoc, l_genl_msg_func_t callback)
{
	const uint8_t *addr = netdev_get_address(ap->netdev);
	uint8_t mpdu_buf[128];
	struct mmpdu_header *mpdu = (void *) mpdu_buf;
	struct mmpdu_association_response *resp;
	size_t ies_len = 0;
	uint16_t capability = IE_BSS_CAP_ESS | IE_BSS_CAP_PRIVACY;
	uint32_t r, minr, maxr, count;

	memset(mpdu, 0, sizeof(*mpdu));

	/* Header */
	mpdu->fc.protocol_version = 0;
	mpdu->fc.type = MPDU_TYPE_MANAGEMENT;
	mpdu->fc.subtype = reassoc ?
		MPDU_MANAGEMENT_SUBTYPE_REASSOCIATION_RESPONSE :
		MPDU_MANAGEMENT_SUBTYPE_ASSOCIATION_RESPONSE;
	memcpy(mpdu->address_1, dest, 6);	/* DA */
	memcpy(mpdu->address_2, addr, 6);	/* SA */
	memcpy(mpdu->address_3, addr, 6);	/* BSSID */

	/* Association Response body */
	resp = (void *) mmpdu_body(mpdu);
	l_put_le16(capability, &resp->capability);
	resp->status_code = L_CPU_TO_LE16(status_code);
	resp->aid = L_CPU_TO_LE16(aid | 0xc000);

	/* Supported Rates IE */
	resp->ies[ies_len++] = IE_TYPE_SUPPORTED_RATES;

	minr = l_uintset_find_min(ap->rates);
	maxr = l_uintset_find_max(ap->rates);
	count = 0;
	for (r = minr; r <= maxr && count < 8; r++)
		if (l_uintset_contains(ap->rates, r)) {
			uint8_t flag = 0;

			/* Mark only the lowest rate as Basic Rate */
			if (count == 0)
				flag = 0x80;

			resp->ies[ies_len + 1 + count++] = r | flag;
		}

	resp->ies[ies_len++] = count;
	ies_len += count;

	return ap_send_mgmt_frame(ap, mpdu, resp->ies + ies_len - mpdu_buf,
					true, callback, sta);
}

static int ap_parse_supported_rates(struct ie_tlv_iter *iter,
					struct l_uintset **set)
{
	const uint8_t *rates;
	unsigned int len;
	unsigned int i;

	len = ie_tlv_iter_get_length(iter);

	if (ie_tlv_iter_get_tag(iter) == IE_TYPE_SUPPORTED_RATES && len == 0)
		return -EINVAL;

	rates = ie_tlv_iter_get_data(iter);

	if (!*set)
		*set = l_uintset_new(108);

	for (i = 0; i < len; i++) {
		if (rates[i] == 0xff)
			continue;

		l_uintset_put(*set, rates[i] & 0x7f);
	}

	return 0;
}

/*
 * This handles both the Association and Reassociation Request frames.
 * Association Request is documented in 802.11-2016 9.3.3.6 (frame format),
 * 802.11-2016 11.3.5.3 (MLME/SME) and Reassociation in 802.11-2016
 * 9.3.3.8 (frame format), 802.11-2016 11.3.5.3 (MLME/SME).
 *
 * The difference between Association and Reassociation procedures is
 * documented in 11.3.5.1 "General" but seems inconsistent with specific
 * instructions in 11.3.5.3 vs. 11.3.5.5 and 11.3.5.2 vs. 11.3.5.4.
 * According to 11.3.5.1:
 *  1. Reassociation requires the STA to be already associated in the ESS,
 *     Association doesn't.
 *  2. Unsuccessful Reassociation should not cause a state transition of
 *     the authentication state between the two STAs.
 *
 * The first requirement is not present in 11.3.5.5 which is virtually
 * identical with 11.3.5.3, but we do implement it.  Number 2 is also not
 * reflected in 11.3.5.5 where the state transitions are the same as in
 * 11.3.5.3 and 11.3.5.4 where the state transitions are the same as in
 * 11.3.5.2 including f) "If a Reassociation Response frame is received
 * with a status code other than SUCCESS [...] 1. [...] the state for
 * the AP [...] shall be set to State 2 [...]"
 *
 * For the record here are the apparent differences between 802.11-2016
 * 11.3.5.2 and 11.3.5.4 ignoring the s/Associate/Reassociate/ changes
 * and the special case of Reassociation during a Fast Transition.
 *  o Points c) and d) are switched around.
 *  o On success, the STA is disassociated from all other APs in 11.3.5.2,
 *    and from the previous AP in 11.3.5.4 c).  (Shouldn't make a
 *    difference as there seems to be no way for the STA to become
 *    associated with more than one AP)
 *  o After Association a 4-Way Handshake is always performed, after
 *    Reassociation it is only performed if STA was in State 3 according
 *    to 11.3.5.4 g).  This is not reflected in 11.3.5.5 though.
 *    Additionally 11.3.5.4 and 11.3.5.5 require the STA and AP
 *    respectively to delete current PTKSA/GTKSA/IGTKSA at the beginning
 *    of the procedure independent of the STA state so without a 4-Way
 *    Handshake the two stations end up with no encryption keys.
 *
 * The main difference between 11.3.5.3 and 11.3.5.5 is presence of p).
 */
static void ap_assoc_reassoc(struct sta_state *sta, bool reassoc,
				const struct mmpdu_field_capability *capability,
				uint16_t listen_interval,
				struct ie_tlv_iter *ies)
{
	struct ap_state *ap = sta->ap;
	const char *ssid = NULL;
	const uint8_t *rsn = NULL;
	size_t ssid_len = 0;
	struct l_uintset *rates = NULL;
	struct ie_rsn_info rsn_info;
	int err;

	if (sta->assoc_resp_cmd_id)
		return;

	if (reassoc && !sta->associated) {
		err = MMPDU_REASON_CODE_CLASS3_FRAME_FROM_NONASSOC_STA;
		goto unsupported;
	}

	while (ie_tlv_iter_next(ies))
		switch (ie_tlv_iter_get_tag(ies)) {
		case IE_TYPE_SSID:
			ssid = (const char *) ie_tlv_iter_get_data(ies);
			ssid_len = ie_tlv_iter_get_length(ies);
			break;

		case IE_TYPE_SUPPORTED_RATES:
		case IE_TYPE_EXTENDED_SUPPORTED_RATES:
			if (ap_parse_supported_rates(ies, &rates) < 0) {
				err = MMPDU_REASON_CODE_INVALID_IE;
				goto bad_frame;
			}

			break;

		case IE_TYPE_RSN:
			if (ie_parse_rsne(ies, &rsn_info) < 0) {
				err = MMPDU_REASON_CODE_INVALID_IE;
				goto bad_frame;
			}

			rsn = (const uint8_t *) ie_tlv_iter_get_data(ies) - 2;
			break;
		}

	if (!rates || !ssid || !rsn || ssid_len != strlen(ap->ssid) ||
			memcmp(ssid, ap->ssid, ssid_len)) {
		err = MMPDU_REASON_CODE_INVALID_IE;
		goto bad_frame;
	}

	if (!ap_common_rates(ap->rates, rates)) {
		err = MMPDU_REASON_CODE_UNSPECIFIED;
		goto unsupported;
	}

	if (rsn_info.mfpr && rsn_info.spp_a_msdu_required) {
		err = MMPDU_REASON_CODE_UNSPECIFIED;
		goto unsupported;
	}

	if (!(rsn_info.pairwise_ciphers & ap->ciphers)) {
		err = MMPDU_REASON_CODE_INVALID_PAIRWISE_CIPHER;
		goto unsupported;
	}

	if (rsn_info.akm_suites != IE_RSN_AKM_SUITE_PSK) {
		err = MMPDU_REASON_CODE_INVALID_AKMP;
		goto unsupported;
	}

	if (!sta->associated) {
		/*
		 * Everything fine so far, assign an AID, send response.
		 * According to 802.11-2016 11.3.5.3 l) we will only go to
		 * State 3 (set sta->associated) once we receive the station's
		 * ACK or gave up on resends.
		 */
		sta->aid = ++ap->last_aid;
	}

	sta->capability = *capability;
	sta->listen_interval = listen_interval;

	if (sta->rates)
		l_uintset_free(sta->rates);

	sta->rates = rates;

	if (sta->assoc_rsne)
		l_free(sta->assoc_rsne);

	sta->assoc_rsne = l_memdup(rsn, rsn[1] + 2);

	/* 802.11-2016 11.3.5.3 j) */
	if (sta->rsna)
		ap_drop_rsna(sta);

	sta->assoc_resp_cmd_id = ap_assoc_resp(ap, sta, sta->addr, sta->aid, 0,
						reassoc,
						ap_success_assoc_resp_cb);
	if (!sta->assoc_resp_cmd_id)
		l_error("Sending success (Re)Association Response failed");

	return;

unsupported:
bad_frame:
	/*
	 * TODO: MFP
	 *
	 * 802.11-2016 11.3.5.3 m)
	 * "If the ResultCode in the MLME-ASSOCIATE.response primitive is
	 * not SUCCESS and management frame protection is in use the state
	 * for the STA shall be left unchanged.  If the ResultCode is not
	 * SUCCESS and management frame protection is not in use the state
	 * for the STA shall be set to State 3 if it was State 4."
	 *
	 * For now, we need to drop the RSNA.
	 */
	if (sta->associated && sta->rsna)
		ap_drop_rsna(sta);

	if (rates)
		l_uintset_free(rates);

	if (!ap_assoc_resp(ap, NULL, sta->addr, 0, err, reassoc,
				ap_fail_assoc_resp_cb))
		l_error("Sending error (Re)Association Response failed");
}

/* 802.11-2016 9.3.3.6 */
static void ap_assoc_req_cb(const struct mmpdu_header *hdr, const void *body,
				size_t body_len, int rssi, void *user_data)
{
	struct ap_state *ap = user_data;
	struct sta_state *sta;
	const uint8_t *from = hdr->address_2;
	const struct mmpdu_association_request *req = body;
	const uint8_t *bssid = netdev_get_address(ap->netdev);
	struct ie_tlv_iter iter;

	l_info("AP Association Request from %s", util_address_to_string(from));

	if (memcmp(hdr->address_1, bssid, 6) ||
			memcmp(hdr->address_3, bssid, 6))
		return;

	sta = l_queue_find(ap->sta_states, ap_sta_match_addr, from);
	if (!sta) {
		if (!ap_assoc_resp(ap, NULL, from, 0,
				MMPDU_REASON_CODE_STA_REQ_ASSOC_WITHOUT_AUTH,
				false, ap_fail_assoc_resp_cb))
			l_error("Sending error Association Response failed");

		return;
	}

	ie_tlv_iter_init(&iter, req->ies, body_len - sizeof(*req));
	ap_assoc_reassoc(sta, false, &req->capability,
				L_LE16_TO_CPU(req->listen_interval), &iter);
}

/* 802.11-2016 9.3.3.8 */
static void ap_reassoc_req_cb(const struct mmpdu_header *hdr, const void *body,
				size_t body_len, int rssi, void *user_data)
{
	struct ap_state *ap = user_data;
	struct sta_state *sta;
	const uint8_t *from = hdr->address_2;
	const struct mmpdu_reassociation_request *req = body;
	const uint8_t *bssid = netdev_get_address(ap->netdev);
	struct ie_tlv_iter iter;
	int err;

	l_info("AP Reassociation Request from %s",
		util_address_to_string(from));

	if (memcmp(hdr->address_1, bssid, 6) ||
			memcmp(hdr->address_3, bssid, 6))
		return;

	sta = l_queue_find(ap->sta_states, ap_sta_match_addr, from);
	if (!sta) {
		err = MMPDU_REASON_CODE_STA_REQ_ASSOC_WITHOUT_AUTH;
		goto bad_frame;
	}

	if (memcmp(req->current_ap_address, bssid, 6)) {
		err = MMPDU_REASON_CODE_UNSPECIFIED;
		goto bad_frame;
	}

	ie_tlv_iter_init(&iter, req->ies, body_len - sizeof(*req));
	ap_assoc_reassoc(sta, true, &req->capability,
				L_LE16_TO_CPU(req->listen_interval), &iter);
	return;

bad_frame:
	if (!ap_assoc_resp(ap, NULL, from, 0, err, true, ap_fail_assoc_resp_cb))
		l_error("Sending error Reassociation Response failed");
}

static void ap_probe_resp_cb(struct l_genl_msg *msg, void *user_data)
{
	if (l_genl_msg_get_error(msg) < 0)
		l_error("AP Probe Response not sent: %i",
			l_genl_msg_get_error(msg));
	else
		l_info("AP Probe Response sent OK");
}

/*
 * Parse Probe Request according to 802.11-2016 9.3.3.10 and act according
 * to 802.11-2016 11.1.4.3
 */
static void ap_probe_req_cb(const struct mmpdu_header *hdr, const void *body,
				size_t body_len, int rssi, void *user_data)
{
	struct ap_state *ap = user_data;
	const struct mmpdu_probe_request *req = body;
	const char *ssid = NULL;
	const uint8_t *ssid_list = NULL;
	size_t ssid_len = 0, ssid_list_len = 0, len;
	uint8_t dsss_channel = 0;
	struct ie_tlv_iter iter;
	const uint8_t *bssid = netdev_get_address(ap->netdev);
	bool match = false;
	uint8_t resp[512];

	l_info("AP Probe Request from %s",
		util_address_to_string(hdr->address_2));

	ie_tlv_iter_init(&iter, req->ies, body_len - sizeof(*req));

	while (ie_tlv_iter_next(&iter))
		switch (ie_tlv_iter_get_tag(&iter)) {
		case IE_TYPE_SSID:
			ssid = (const char *) ie_tlv_iter_get_data(&iter);
			ssid_len = ie_tlv_iter_get_length(&iter);
			break;

		case IE_TYPE_SSID_LIST:
			ssid_list = ie_tlv_iter_get_data(&iter);
			ssid_list_len = ie_tlv_iter_get_length(&iter);
			break;

		case IE_TYPE_DSSS_PARAMETER_SET:
			if (ie_tlv_iter_get_length(&iter) != 1)
				return;

			dsss_channel = ie_tlv_iter_get_data(&iter)[0];
			break;
		}

	/*
	 * Check if we should reply to this Probe Request according to
	 * 802.11-2016 section 11.1.4.3.2.
	 */

	if (memcmp(hdr->address_1, bssid, 6) &&
			!util_is_broadcast_address(hdr->address_1))
		match = false;

	if (memcmp(hdr->address_3, bssid, 6) &&
			!util_is_broadcast_address(hdr->address_3))
		match = false;

	if (!ssid || ssid_len == 0) /* Wildcard SSID */
		match = true;
	else if (ssid && ssid_len == strlen(ap->ssid) && /* Specific SSID */
			!memcmp(ssid, ap->ssid, ssid_len))
		match = true;
	else if (ssid_list) { /* SSID List */
		ie_tlv_iter_init(&iter, ssid_list, ssid_list_len);

		while (ie_tlv_iter_next(&iter)) {
			if (ie_tlv_iter_get_tag(&iter) != IE_TYPE_SSID)
				return;

			ssid = (const char *) ie_tlv_iter_get_data(&iter);
			ssid_len = ie_tlv_iter_get_length(&iter);

			if (ssid_len == strlen(ap->ssid) &&
					!memcmp(ssid, ap->ssid, ssid_len)) {
				match = true;
				break;
			}
		}
	}

	if (dsss_channel != 0 && dsss_channel != ap->channel)
		match = false;

	if (!match)
		return;

	len = ap_build_beacon_pr_head(ap,
					MPDU_MANAGEMENT_SUBTYPE_PROBE_RESPONSE,
					hdr->address_2, resp, sizeof(resp));
	len += ap_build_beacon_pr_tail(ap, resp + len);

	ap_send_mgmt_frame(ap, (struct mmpdu_header *) resp, len, false,
				ap_probe_resp_cb, NULL);
}

/* 802.11-2016 9.3.3.5 (frame format), 802.11-2016 11.3.5.9 (MLME/SME) */
static void ap_disassoc_cb(const struct mmpdu_header *hdr, const void *body,
				size_t body_len, int rssi, void *user_data)
{
	struct ap_state *ap = user_data;
	struct sta_state *sta;
	const struct mmpdu_disassociation *disassoc = body;
	const uint8_t *bssid = netdev_get_address(ap->netdev);

	l_info("AP Disassociation from %s, reason %i",
		util_address_to_string(hdr->address_2),
		(int) L_LE16_TO_CPU(disassoc->reason_code));

	if (memcmp(hdr->address_1, bssid, 6) ||
			memcmp(hdr->address_3, bssid, 6))
		return;

	sta = l_queue_find(ap->sta_states, ap_sta_match_addr, hdr->address_2);

	if (sta && sta->assoc_resp_cmd_id) {
		l_genl_family_cancel(ap->nl80211, sta->assoc_resp_cmd_id);
		sta->assoc_resp_cmd_id = 0;
	}

	if (!sta || !sta->associated)
		return;

	ap_del_station(sta, L_LE16_TO_CPU(disassoc->reason_code), true);
}

static void ap_auth_reply_cb(struct l_genl_msg *msg, void *user_data)
{
	if (l_genl_msg_get_error(msg) < 0)
		l_error("AP Authentication frame 2 not sent or not ACKed: %i",
			l_genl_msg_get_error(msg));
	else
		l_info("AP Authentication frame 2 ACKed by STA");
}

static void ap_auth_reply(struct ap_state *ap, const uint8_t *dest,
				enum mmpdu_reason_code status_code)
{
	const uint8_t *addr = netdev_get_address(ap->netdev);
	uint8_t mpdu_buf[64];
	struct mmpdu_header *mpdu = (struct mmpdu_header *) mpdu_buf;
	struct mmpdu_authentication *auth;

	memset(mpdu, 0, sizeof(*mpdu));

	/* Header */
	mpdu->fc.protocol_version = 0;
	mpdu->fc.type = MPDU_TYPE_MANAGEMENT;
	mpdu->fc.subtype = MPDU_MANAGEMENT_SUBTYPE_AUTHENTICATION;
	memcpy(mpdu->address_1, dest, 6);	/* DA */
	memcpy(mpdu->address_2, addr, 6);	/* SA */
	memcpy(mpdu->address_3, addr, 6);	/* BSSID */

	/* Authentication body */
	auth = (void *) mmpdu_body(mpdu);
	auth->algorithm = L_CPU_TO_LE16(MMPDU_AUTH_ALGO_OPEN_SYSTEM);
	auth->transaction_sequence = L_CPU_TO_LE16(2);
	auth->status = L_CPU_TO_LE16(status_code);

	ap_send_mgmt_frame(ap, mpdu, (uint8_t *) auth + 6 - mpdu_buf, true,
				ap_auth_reply_cb, NULL);
}

/*
 * 802.11-2016 9.3.3.12 (frame format), 802.11-2016 11.3.4.3 and
 * 802.11-2016 12.3.3.2 (MLME/SME)
 */
static void ap_auth_cb(const struct mmpdu_header *hdr, const void *body,
			size_t body_len, int rssi, void *user_data)
{
	struct ap_state *ap = user_data;
	const struct mmpdu_authentication *auth = body;
	const uint8_t *from = hdr->address_2;
	const uint8_t *bssid = netdev_get_address(ap->netdev);
	struct sta_state *sta;

	l_info("AP Authentication from %s", util_address_to_string(from));

	if (memcmp(hdr->address_1, bssid, 6) ||
			memcmp(hdr->address_3, bssid, 6))
		return;

	/* Only Open System authentication implemented here */
	if (L_LE16_TO_CPU(auth->algorithm) !=
			MMPDU_AUTH_ALGO_OPEN_SYSTEM) {
		ap_auth_reply(ap, from, MMPDU_REASON_CODE_UNSPECIFIED);
		return;
	}

	if (L_LE16_TO_CPU(auth->transaction_sequence) != 1) {
		ap_auth_reply(ap, from, MMPDU_REASON_CODE_UNSPECIFIED);
		return;
	}

	sta = l_queue_find(ap->sta_states, ap_sta_match_addr, from);

	/*
	 * Figure 11-13 in 802.11-2016 11.3.2 shows a transition from
	 * States 3 / 4 to State 2 on "Successful 802.11 Authentication"
	 * however 11.3.4.2 and 11.3.4.3 clearly say the connection goes to
	 * State 2 only if it was in State 1:
	 *
	 * "c) [...] the state for the indicated STA shall be set to State 2
	 * if it was State 1; the state shall remain unchanged if it was other
	 * than State 1."
	 */
	if (sta)
		goto done;

	/*
	 * Per 12.3.3.2.3 with Open System the state change is immediate,
	 * no waiting for the response to be ACKed as with the association
	 * frames.
	 */
	sta = l_new(struct sta_state, 1);
	memcpy(sta->addr, from, 6);
	sta->ap = ap;

	if (!ap->sta_states)
		ap->sta_states = l_queue_new();

	l_queue_push_tail(ap->sta_states, sta);

	/*
	 * Nothing to do here netlink-wise as we can't receive any data
	 * frames until after association anyway.  We do need to add a
	 * timeout for the authentication and possibly the kernel could
	 * handle that if we registered the STA with NEW_STATION now (TODO)
	 */

done:
	ap_auth_reply(ap, from, 0);
}

/* 802.11-2016 9.3.3.13 (frame format), 802.11-2016 11.3.4.5 (MLME/SME) */
static void ap_deauth_cb(const struct mmpdu_header *hdr, const void *body,
				size_t body_len, int rssi, void *user_data)
{
	struct ap_state *ap = user_data;
	struct sta_state *sta;
	const struct mmpdu_deauthentication *deauth = body;
	const uint8_t *bssid = netdev_get_address(ap->netdev);

	l_info("AP Deauthentication from %s, reason %i",
		util_address_to_string(hdr->address_2),
		(int) L_LE16_TO_CPU(deauth->reason_code));

	if (memcmp(hdr->address_1, bssid, 6) ||
			memcmp(hdr->address_3, bssid, 6))
		return;

	sta = l_queue_remove_if(ap->sta_states, ap_sta_match_addr,
				hdr->address_2);
	if (!sta)
		return;

	ap_del_station(sta, L_LE16_TO_CPU(deauth->reason_code), false);

	ap_sta_free(sta);
}

static void ap_start_cb(struct l_genl_msg *msg, void *user_data)
{
	struct ap_state *ap = user_data;

	ap->start_stop_cmd_id = 0;

	if (!ap->pending)
		return;

	if (l_genl_msg_get_error(msg) < 0) {
		l_error("START_AP failed: %i", l_genl_msg_get_error(msg));

		dbus_pending_reply(&ap->pending,
				dbus_error_invalid_args(ap->pending));
		ap_reset(ap);

		return;
	}

	dbus_pending_reply(&ap->pending,
			l_dbus_message_new_method_return(ap->pending));

	ap->started = true;

	l_dbus_property_changed(dbus_get_bus(), netdev_get_path(ap->netdev),
						IWD_AP_INTERFACE, "Started");
}

static struct l_genl_msg *ap_build_cmd_start_ap(struct ap_state *ap)
{
	struct l_genl_msg *cmd;

	uint8_t head[256], tail[256];
	size_t head_len, tail_len;

	uint32_t dtim_period = 3;
	uint32_t ifindex = netdev_get_ifindex(ap->netdev);
	struct wiphy *wiphy = netdev_get_wiphy(ap->netdev);
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
						bcast_addr, head, sizeof(head));
	tail_len = ap_build_beacon_pr_tail(ap, tail);

	if (!head_len || !tail_len)
		return NULL;

	cmd = l_genl_msg_new_sized(NL80211_CMD_START_AP, 256 + head_len +
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

	if (wiphy_has_ext_feature(wiphy,
			NL80211_EXT_FEATURE_CONTROL_PORT_OVER_NL80211)) {
		l_genl_msg_append_attr(cmd, NL80211_ATTR_SOCKET_OWNER, 0, NULL);
		l_genl_msg_append_attr(cmd,
				NL80211_ATTR_CONTROL_PORT_OVER_NL80211,
				0, NULL);
	}

	return cmd;
}

static void ap_mlme_notify(struct l_genl_msg *msg, void *user_data)
{
	struct ap_state *ap = user_data;
	uint32_t ifindex;

	if (nl80211_parse_attrs(msg, NL80211_ATTR_IFINDEX, &ifindex,
				NL80211_ATTR_UNSPEC) < 0 ||
			ifindex != netdev_get_ifindex(ap->netdev))
		return;

	switch (l_genl_msg_get_command(msg)) {
	case NL80211_CMD_STOP_AP:
		if (ap->start_stop_cmd_id)
			break;

		ap_reset(ap);
		break;
	}
}

static int ap_start(struct ap_state *ap, const char *ssid, const char *psk,
		struct l_dbus_message *message)
{
	struct netdev *netdev = ap->netdev;
	struct wiphy *wiphy = netdev_get_wiphy(netdev);
	struct l_genl_msg *cmd;
	uint64_t wdev_id = netdev_get_wdev_id(netdev);

	ap->ssid = l_strdup(ssid);
	/* TODO: Start a Get Survey to decide the channel */
	ap->channel = 6;
	/* TODO: Add all ciphers supported by wiphy */
	ap->ciphers = wiphy_select_cipher(wiphy, 0xffff);
	ap->group_cipher = wiphy_select_cipher(wiphy, 0xffff);
	ap->beacon_interval = 100;
	/* TODO: Use actual supported rates */
	ap->rates = l_uintset_new(200);
	l_uintset_put(ap->rates, 2); /* 1 Mbps*/
	l_uintset_put(ap->rates, 11); /* 5.5 Mbps*/
	l_uintset_put(ap->rates, 22); /* 11 Mbps*/

	if (crypto_psk_from_passphrase(psk, (uint8_t *) ssid, strlen(ssid),
					ap->pmk) < 0)
		goto error;

	if (!frame_watch_add(wdev_id, 0, 0x0000 |
			(MPDU_MANAGEMENT_SUBTYPE_ASSOCIATION_REQUEST << 4),
			NULL, 0, ap_assoc_req_cb, ap, NULL))
		goto error;

	if (!frame_watch_add(wdev_id, 0, 0x0000 |
			(MPDU_MANAGEMENT_SUBTYPE_REASSOCIATION_REQUEST << 4),
			NULL, 0, ap_reassoc_req_cb, ap, NULL))
		goto error;

	if (!frame_watch_add(wdev_id, 0, 0x0000 |
				(MPDU_MANAGEMENT_SUBTYPE_PROBE_REQUEST << 4),
				NULL, 0, ap_probe_req_cb, ap, NULL))
		goto error;

	if (!frame_watch_add(wdev_id, 0, 0x0000 |
				(MPDU_MANAGEMENT_SUBTYPE_DISASSOCIATION << 4),
				NULL, 0, ap_disassoc_cb, ap, NULL))
		goto error;

	if (!frame_watch_add(wdev_id, 0, 0x0000 |
				(MPDU_MANAGEMENT_SUBTYPE_AUTHENTICATION << 4),
				NULL, 0, ap_auth_cb, ap, NULL))
		goto error;

	if (!frame_watch_add(wdev_id, 0, 0x0000 |
				(MPDU_MANAGEMENT_SUBTYPE_DEAUTHENTICATION << 4),
				NULL, 0, ap_deauth_cb, ap, NULL))
		goto error;

	ap->mlme_watch = l_genl_family_register(ap->nl80211, "mlme",
						ap_mlme_notify, ap, NULL);
	if (!ap->mlme_watch)
		l_error("Registering for MLME notification failed");

	cmd = ap_build_cmd_start_ap(ap);
	if (!cmd)
		goto error;

	ap->start_stop_cmd_id = l_genl_family_send(ap->nl80211, cmd,
							ap_start_cb, ap, NULL);
	if (!ap->start_stop_cmd_id) {
		l_genl_msg_unref(cmd);
		goto error;
	}

	ap->pending = l_dbus_message_ref(message);

	return 0;

error:
	ap_reset(ap);

	return -EIO;
}

static void ap_stop_cb(struct l_genl_msg *msg, void *user_data)
{
	struct ap_state *ap = user_data;

	ap->start_stop_cmd_id = 0;

	if (!ap->pending)
		goto end;

	if (l_genl_msg_get_error(msg) < 0) {
		l_error("STOP_AP failed: %i", l_genl_msg_get_error(msg));
		dbus_pending_reply(&ap->pending,
				dbus_error_failed(ap->pending));
		goto end;
	}

	dbus_pending_reply(&ap->pending,
			l_dbus_message_new_method_return(ap->pending));

end:
	ap_reset(ap);
}

static struct l_genl_msg *ap_build_cmd_stop_ap(struct ap_state *ap)
{
	struct l_genl_msg *cmd;
	uint32_t ifindex = netdev_get_ifindex(ap->netdev);

	cmd = l_genl_msg_new_sized(NL80211_CMD_STOP_AP, 16);
	l_genl_msg_append_attr(cmd, NL80211_ATTR_IFINDEX, 4, &ifindex);

	return cmd;
}

static int ap_stop(struct ap_state *ap, struct l_dbus_message *message)
{
	struct l_genl_msg *cmd;

	cmd = ap_build_cmd_stop_ap(ap);
	if (!cmd)
		return -ENOMEM;

	if (ap->start_stop_cmd_id)
		l_genl_family_cancel(ap->nl80211, ap->start_stop_cmd_id);

	if (ap->mlme_watch)
		l_genl_family_unregister(ap->nl80211, ap->mlme_watch);

	ap->start_stop_cmd_id = l_genl_family_send(ap->nl80211, cmd, ap_stop_cb,
							ap, NULL);
	if (!ap->start_stop_cmd_id) {
		l_genl_msg_unref(cmd);
		return -EIO;
	}

	if (ap->gtk_set) {
		struct l_genl_msg *msg;

		ap->gtk_set = false;

		msg = ap_build_cmd_del_key(ap);
		if (!l_genl_family_send(ap->nl80211, msg, ap_gtk_op_cb, NULL,
					NULL)) {
			l_genl_msg_unref(msg);
			l_error("Issuing DEL_KEY failed");
		}
	}

	ap->pending = l_dbus_message_ref(message);
	return 0;
}

static struct l_dbus_message *ap_dbus_start(struct l_dbus *dbus,
		struct l_dbus_message *message, void *user_data)
{
	struct ap_state *ap = user_data;
	const char *ssid, *wpa2_psk;

	if (ap->pending)
		return dbus_error_busy(message);

	if (ap->started)
		return dbus_error_already_exists(message);

	if (!l_dbus_message_get_arguments(message, "ss", &ssid, &wpa2_psk))
		return dbus_error_invalid_args(message);

	if (ap_start(ap, ssid, wpa2_psk, message) < 0)
		return dbus_error_invalid_args(message);

	return NULL;
}

static struct l_dbus_message *ap_dbus_stop(struct l_dbus *dbus,
		struct l_dbus_message *message, void *user_data)
{
	struct ap_state *ap = user_data;

	if (ap->pending)
		return dbus_error_busy(message);

	/* already stopped, no-op */
	if (!ap->started)
		return l_dbus_message_new_method_return(message);

	if (ap_stop(ap, message) < 0)
		return dbus_error_failed(message);

	return NULL;
}

static bool ap_dbus_property_get_started(struct l_dbus *dbus,
					struct l_dbus_message *message,
					struct l_dbus_message_builder *builder,
					void *user_data)
{
	struct ap_state *ap = user_data;
	bool started = ap->started;

	l_dbus_message_builder_append_basic(builder, 'b', &started);

	return true;
}

static void ap_setup_interface(struct l_dbus_interface *interface)
{
	l_dbus_interface_method(interface, "Start", 0, ap_dbus_start, "",
			"ss", "ssid", "wpa2_psk");
	l_dbus_interface_method(interface, "Stop", 0, ap_dbus_stop, "", "");

	l_dbus_interface_property(interface, "Started", 0, "b",
					ap_dbus_property_get_started, NULL);
}

static void ap_destroy_interface(void *user_data)
{
	struct ap_state *ap = user_data;

	ap_free(ap);
}
#endif

static void ap_add_interface(struct netdev *netdev)
{
	struct ap_state *ap;

	/*
	 * TODO: Check wiphy supported channels and NL80211_ATTR_TX_FRAME_TYPES
	 */

	/* just allocate/set device, Start method will complete setup */
	ap = l_new(struct ap_state, 1);
	ap->netdev = netdev;
	ap->nl80211 = l_genl_family_new(iwd_get_genl(), NL80211_GENL_NAME);

#ifdef HAVE_DBUS
	/* setup ap dbus interface */
	l_dbus_object_add_interface(dbus_get_bus(),
			netdev_get_path(netdev), IWD_AP_INTERFACE, ap);
#endif
}

static void ap_remove_interface(struct netdev *netdev)
{
#ifdef HAVE_DBUS
	l_dbus_object_remove_interface(dbus_get_bus(),
			netdev_get_path(netdev), IWD_AP_INTERFACE);
#endif
}

static void ap_netdev_watch(struct netdev *netdev,
				enum netdev_watch_event event, void *userdata)
{
	switch (event) {
	case NETDEV_WATCH_EVENT_UP:
	case NETDEV_WATCH_EVENT_NEW:
		if (netdev_get_iftype(netdev) == NETDEV_IFTYPE_AP &&
				netdev_get_is_up(netdev))
			ap_add_interface(netdev);
		break;
	case NETDEV_WATCH_EVENT_DOWN:
	case NETDEV_WATCH_EVENT_DEL:
		ap_remove_interface(netdev);
		break;
	default:
		break;
	}
}

static int ap_init(void)
{
	netdev_watch = netdev_watch_add(ap_netdev_watch, NULL, NULL);

#ifdef HAVE_DBUS
	l_dbus_register_interface(dbus_get_bus(), IWD_AP_INTERFACE,
			ap_setup_interface, ap_destroy_interface, false);
#endif

	return 0;
}

static void ap_exit(void)
{
	netdev_watch_remove(netdev_watch);

#ifdef HAVE_DBUS
	l_dbus_unregister_interface(dbus_get_bus(), IWD_AP_INTERFACE);
#endif
}

IWD_MODULE(ap, ap_init, ap_exit)
