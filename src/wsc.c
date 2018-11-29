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

#include <errno.h>
#include <stdio.h>
#include <ell/ell.h>

#include "src/dbus.h"
#include "src/netdev.h"
#include "src/wiphy.h"
#include "src/station.h"
#include "src/scan.h"
#include "src/ie.h"
#include "src/wscutil.h"
#include "src/util.h"
#include "src/handshake.h"
#include "src/eap-wsc.h"
#include "src/crypto.h"
#include "src/common.h"
#include "src/storage.h"
#include "src/iwd.h"
#include "src/network.h"

#define WALK_TIME 120

static uint32_t netdev_watch = 0;

struct wsc {
	struct netdev *netdev;
	struct station *station;
	struct l_dbus_message *pending;
	struct l_dbus_message *pending_cancel;
	uint8_t *wsc_ies;
	size_t wsc_ies_size;
	struct l_timeout *walk_timer;
	uint32_t scan_id;
	struct scan_bss *target;
	uint32_t station_state_watch;
	struct {
		char ssid[33];
		enum security security;
		uint8_t psk[32];
		uint8_t addr[6];
	} creds[3];
	uint32_t n_creds;
	struct l_settings *eap_settings;

	bool wsc_association : 1;
};

static struct l_dbus_message *wsc_error_session_overlap(
						struct l_dbus_message *msg)
{
	return l_dbus_message_new_error(msg,
					IWD_WSC_INTERFACE ".SessionOverlap",
					"Multiple sessions detected");
}

static struct l_dbus_message *wsc_error_no_credentials(
						struct l_dbus_message *msg)
{
	return l_dbus_message_new_error(msg, IWD_WSC_INTERFACE ".NoCredentials",
					"No usable credentials obtained");
}

static struct l_dbus_message *wsc_error_not_reachable(
						struct l_dbus_message *msg)
{
	return l_dbus_message_new_error(msg, IWD_WSC_INTERFACE ".NotReachable",
					"Credentials obtained, but network is "
					"unreachable");
}

static struct l_dbus_message *wsc_error_walk_time_expired(
						struct l_dbus_message *msg)
{
	return l_dbus_message_new_error(msg,
					IWD_WSC_INTERFACE ".WalkTimeExpired",
					"No APs in PushButton mode found in "
					"the alloted time");
}

static struct l_dbus_message *wsc_error_time_expired(struct l_dbus_message *msg)
{
	return l_dbus_message_new_error(msg,
					IWD_WSC_INTERFACE ".TimeExpired",
					"No APs in PIN mode found in "
					"the alloted time");
}
static void wsc_try_credentials(struct wsc *wsc)
{
	unsigned int i;
	struct network *network;
	struct scan_bss *bss;

	for (i = 0; i < wsc->n_creds; i++) {
		network = station_network_find(wsc->station,
						wsc->creds[i].ssid,
						wsc->creds[i].security);
		if (!network)
			continue;

		bss = network_bss_find_by_addr(network, wsc->creds[i].addr);

		if (!bss)
			bss = network_bss_select(network);

		if (!bss)
			continue;

		if (wsc->creds[i].security == SECURITY_PSK &&
				!network_set_psk(network, wsc->creds[i].psk))
			continue;

		station_connect_network(wsc->station, network, bss,
								wsc->pending);
		l_dbus_message_unref(wsc->pending);
		wsc->pending = NULL;

		goto done;
	}

	dbus_pending_reply(&wsc->pending,
					wsc_error_not_reachable(wsc->pending));
	station_set_autoconnect(wsc->station, true);
done:
	memset(wsc->creds, 0, sizeof(wsc->creds));
	wsc->n_creds = 0;
}

static void wsc_store_credentials(struct wsc *wsc)
{
	unsigned int i;

	for (i = 0; i < wsc->n_creds; i++) {
		enum security security = wsc->creds[i].security;
		const char *ssid = wsc->creds[i].ssid;
		struct l_settings *settings = l_settings_new();

		l_debug("Storing credential for '%s(%s)'", ssid,
						security_to_str(security));

		if (security == SECURITY_PSK) {
			char *hex = l_util_hexstring(wsc->creds[i].psk,
						sizeof(wsc->creds[i].psk));

			l_settings_set_value(settings, "Security",
							"PreSharedKey", hex);
			l_free(hex);
		}

		storage_network_sync(security, ssid, settings);
		l_settings_free(settings);

		/*
		 * TODO: Mark this network as known.  We might be getting
		 * multiple credentials from WSC, so there is a possibility
		 * that the network is not known and / or not in scan results.
		 * In both cases, the network should be considered for
		 * auto-connect.  Note, since we sync the settings, the next
		 * reboot will put the network on the known list.
		 */
	}
}

static void wsc_disconnect_cb(struct netdev *netdev, bool success,
							void *user_data)
{
	struct wsc *wsc = user_data;
	struct l_dbus_message *reply;

	l_debug("%p, success: %d", wsc, success);

	wsc->wsc_association = false;

	reply = l_dbus_message_new_method_return(wsc->pending_cancel);
	l_dbus_message_set_arguments(reply, "");
	dbus_pending_reply(&wsc->pending_cancel, reply);

	station_set_autoconnect(wsc->station, true);
}

static void wsc_connect_cb(struct netdev *netdev, enum netdev_result result,
					void *user_data)
{
	struct wsc *wsc = user_data;

	l_debug("%d, result: %d", netdev_get_ifindex(wsc->netdev), result);

	wsc->wsc_association = false;

	l_settings_free(wsc->eap_settings);
	wsc->eap_settings = NULL;

	if (result == NETDEV_RESULT_HANDSHAKE_FAILED && wsc->n_creds > 0) {
		wsc_store_credentials(wsc);
		wsc_try_credentials(wsc);
		return;
	}

	switch (result) {
	case NETDEV_RESULT_ABORTED:
		dbus_pending_reply(&wsc->pending,
					dbus_error_aborted(wsc->pending));
		return;
	case NETDEV_RESULT_HANDSHAKE_FAILED:
		dbus_pending_reply(&wsc->pending,
					wsc_error_no_credentials(wsc->pending));
		break;
	default:
		dbus_pending_reply(&wsc->pending,
					dbus_error_failed(wsc->pending));
		break;
	}

	station_set_autoconnect(wsc->station, true);
}

static void wsc_credential_obtained(struct wsc *wsc,
					const struct wsc_credential *cred)
{
	uint16_t auth_mask;
	unsigned int i;

	l_debug("Obtained credenials for SSID: %s, address: %s",
			util_ssid_to_utf8(cred->ssid_len, cred->ssid),
			util_address_to_string(cred->addr));

	l_debug("auth_type: %02x, encryption_type: %02x",
			cred->auth_type, cred->encryption_type);

	l_debug("Key (%u): %.*s", cred->network_key_len,
				cred->network_key_len, cred->network_key);

	if (wsc->n_creds == L_ARRAY_SIZE(wsc->creds)) {
		l_warn("Maximum number of credentials obtained, ignoring...");
		return;
	}

	if (!util_ssid_is_utf8(cred->ssid_len, cred->ssid)) {
		l_warn("Ignoring Credentials with non-UTF8 SSID");
		return;
	}

	memcpy(wsc->creds[wsc->n_creds].ssid, cred->ssid, cred->ssid_len);
	wsc->creds[wsc->n_creds].ssid[cred->ssid_len] = '\0';

	/* We only support open/personal wpa/personal wpa2 */
	auth_mask = WSC_AUTHENTICATION_TYPE_OPEN |
			WSC_AUTHENTICATION_TYPE_WPA_PERSONAL |
			WSC_AUTHENTICATION_TYPE_WPA2_PERSONAL;
	if ((cred->auth_type & auth_mask) == 0) {
		l_warn("Ignoring Credentials with unsupported auth_type");
		return;
	}

	if (cred->auth_type & WSC_AUTHENTICATION_TYPE_OPEN) {
		auth_mask &= ~WSC_AUTHENTICATION_TYPE_OPEN;

		if (cred->auth_type & auth_mask) {
			l_warn("Ignoring mixed open/wpa credentials");
			return;
		}

		wsc->creds[wsc->n_creds].security = SECURITY_NONE;
	} else
		wsc->creds[wsc->n_creds].security = SECURITY_PSK;

	switch (wsc->creds[wsc->n_creds].security) {
	case SECURITY_NONE:
		if (cred->network_key_len != 0) {
			l_warn("ignoring invalid open key length");
			return;
		}

		break;
	case SECURITY_PSK:
		if (cred->network_key_len == 64) {
			unsigned char *decoded;
			const char *hex = (const char *) cred->network_key;

			decoded = l_util_from_hexstring(hex, NULL);
			if (!decoded) {
				l_warn("Ignoring non-hex network_key");
				return;
			}

			memcpy(wsc->creds[wsc->n_creds].psk, decoded, 32);
			l_free(decoded);
		} else {
			const char *passphrase =
				(const char *) cred->network_key;
			/*
			 * wscutil should memset cred->network_key to 0 prior
			 * to copying in the contents of the passphrase
			 */
			if (crypto_psk_from_passphrase(passphrase,
					cred->ssid, cred->ssid_len,
					wsc->creds[wsc->n_creds].psk) != 0) {
				l_warn("Ignoring invalid passphrase");
				return;
			}
		}

		break;
	default:
		return;
	}

	for (i = 0; i < wsc->n_creds; i++) {
		if (strcmp(wsc->creds[i].ssid, wsc->creds[wsc->n_creds].ssid))
			continue;

		l_warn("Found duplicate credentials for SSID: %s",
				wsc->creds[i].ssid);
		return;
	}

	memcpy(wsc->creds[wsc->n_creds].addr, cred->addr, 6);
	wsc->n_creds += 1;
}

static void wsc_eapol_event(uint32_t event, const void *event_data,
							void *user_data)
{
	struct wsc *wsc = user_data;

	switch (event) {
	case EAP_WSC_EVENT_CREDENTIAL_OBTAINED:
		wsc_credential_obtained(wsc,
				(const struct wsc_credential *) event_data);
		break;
	default:
		l_debug("Got event: %d", event);
	}
}

static void wsc_netdev_event(struct netdev *netdev, enum netdev_event event,
					void *user_data)
{
	struct wsc *wsc = user_data;

	switch (event) {
	case NETDEV_EVENT_AUTHENTICATING:
	case NETDEV_EVENT_ASSOCIATING:
		break;
	case NETDEV_EVENT_LOST_BEACON:
		l_debug("Lost beacon");
		break;
	case NETDEV_EVENT_DISCONNECT_BY_AP:
		l_debug("Disconnect by AP");
		wsc_connect_cb(wsc->netdev,
				NETDEV_RESULT_HANDSHAKE_FAILED, wsc);
		break;
	case NETDEV_EVENT_RSSI_THRESHOLD_LOW:
	case NETDEV_EVENT_RSSI_THRESHOLD_HIGH:
		break;
	default:
		l_debug("Unexpected event: %d", event);
		break;
	};
}

static void wsc_handshake_event(struct handshake_state *hs,
		enum handshake_event event, void *event_data, void *user_data)
{
	switch (event) {
	case HANDSHAKE_EVENT_FAILED:
		netdev_handshake_failed(hs, l_get_u16(event_data));
		break;
	default:
		break;
	}
}

static inline enum wsc_rf_band freq_to_rf_band(uint32_t freq)
{
	enum scan_band band;

	scan_freq_to_channel(freq, &band);

	switch (band) {
	case SCAN_BAND_2_4_GHZ:
		return WSC_RF_BAND_2_4_GHZ;
	case SCAN_BAND_5_GHZ:
		return WSC_RF_BAND_5_0_GHZ;
	}

	return WSC_RF_BAND_2_4_GHZ;
}

static void wsc_connect(struct wsc *wsc)
{
	struct handshake_state *hs;
	struct l_settings *settings = l_settings_new();
	struct scan_bss *bss = wsc->target;

	wsc->target = NULL;

	hs = netdev_handshake_state_new(wsc->netdev);

	l_settings_set_string(settings, "Security", "EAP-Identity",
					"WFA-SimpleConfig-Enrollee-1-0");
	l_settings_set_string(settings, "Security", "EAP-Method", "WSC");

	l_settings_set_uint(settings, "WSC", "RFBand",
					freq_to_rf_band(bss->frequency));
	l_settings_set_uint(settings, "WSC", "ConfigurationMethods",
				WSC_CONFIGURATION_METHOD_VIRTUAL_DISPLAY_PIN |
				WSC_CONFIGURATION_METHOD_VIRTUAL_PUSH_BUTTON |
				WSC_CONFIGURATION_METHOD_KEYPAD);
	l_settings_set_string(settings, "WSC", "PrimaryDeviceType",
					"0-00000000-0");
	l_settings_set_string(settings, "WSC", "EnrolleeMAC",
		util_address_to_string(netdev_get_address(wsc->netdev)));

	if (!strcmp(l_dbus_message_get_member(wsc->pending), "StartPin")) {
		const char *pin;

		if (l_dbus_message_get_arguments(wsc->pending, "s", &pin)) {
			enum wsc_device_password_id dpid;

			if (strlen(pin) == 4 || wsc_pin_is_checksum_valid(pin))
				dpid = WSC_DEVICE_PASSWORD_ID_DEFAULT;
			else
				dpid = WSC_DEVICE_PASSWORD_ID_USER_SPECIFIED;

			l_settings_set_uint(settings, "WSC",
						"DevicePasswordId", dpid);
			l_settings_set_string(settings, "WSC",
						"DevicePassword", pin);
		}
	}

	handshake_state_set_event_func(hs, wsc_handshake_event, wsc);
	handshake_state_set_8021x_config(hs, settings);
	wsc->eap_settings = settings;

	if (netdev_connect_wsc(wsc->netdev, bss, hs,
					wsc_netdev_event, wsc_connect_cb,
					wsc_eapol_event, wsc) < 0) {
		dbus_pending_reply(&wsc->pending,
					dbus_error_failed(wsc->pending));
		return;
	}

	wsc->wsc_association = true;
}

static void station_state_watch(enum station_state state, void *userdata)
{
	struct wsc *wsc = userdata;

	if (state != STATION_STATE_DISCONNECTED)
		return;

	l_debug("%p", wsc);

	station_remove_state_watch(wsc->station, wsc->station_state_watch);
	wsc->station_state_watch = 0;

	wsc_connect(wsc);
}

static void wsc_check_can_connect(struct wsc *wsc, struct scan_bss *target)
{
	l_debug("%p", wsc);

	/*
	 * For now we assign the target pointer directly, since we should not
	 * be triggering any more scans while disconnecting / connecting
	 */
	wsc->target = target;
	station_set_autoconnect(wsc->station, false);

	switch (station_get_state(wsc->station)) {
	case STATION_STATE_DISCONNECTED:
		wsc_connect(wsc);
		return;
	case STATION_STATE_CONNECTING:
	case STATION_STATE_CONNECTED:
		if (station_disconnect(wsc->station) < 0)
			goto error;

		/* fall through */
	case STATION_STATE_DISCONNECTING:
		wsc->station_state_watch =
			station_add_state_watch(wsc->station,
						station_state_watch,
						wsc, NULL);
		return;
	case STATION_STATE_AUTOCONNECT:
	case STATION_STATE_ROAMING:
		l_warn("wsc_check_can_connect: invalid station state");
		break;
	}
error:
	wsc->target = NULL;
	dbus_pending_reply(&wsc->pending, dbus_error_failed(wsc->pending));
}

static void wsc_cancel_scan(struct wsc *wsc)
{
	l_free(wsc->wsc_ies);
	wsc->wsc_ies = 0;

	if (wsc->scan_id > 0) {
		scan_cancel(netdev_get_ifindex(wsc->netdev), wsc->scan_id);
		wsc->scan_id = 0;
	}

	if (wsc->walk_timer) {
		l_timeout_remove(wsc->walk_timer);
		wsc->walk_timer = NULL;
	}
}

static void walk_timeout(struct l_timeout *timeout, void *user_data)
{
	struct wsc *wsc = user_data;

	wsc_cancel_scan(wsc);

	if (wsc->pending)
		dbus_pending_reply(&wsc->pending,
				wsc_error_walk_time_expired(wsc->pending));
}

static void pin_timeout(struct l_timeout *timeout, void *user_data)
{
	struct wsc *wsc = user_data;

	wsc_cancel_scan(wsc);

	if (wsc->pending)
		dbus_pending_reply(&wsc->pending,
					wsc_error_time_expired(wsc->pending));
}

static bool push_button_scan_results(uint32_t wiphy_id, uint32_t ifindex,
					int err, struct l_queue *bss_list,
					void *userdata)
{
	struct wsc *wsc = userdata;
	struct scan_bss *bss_2g;
	struct scan_bss *bss_5g;
	struct scan_bss *target;
	uint8_t uuid_2g[16];
	uint8_t uuid_5g[16];
	const struct l_queue_entry *bss_entry;
	struct wsc_probe_response probe_response;

	if (err) {
		wsc_cancel_scan(wsc);
		dbus_pending_reply(&wsc->pending,
					dbus_error_failed(wsc->pending));

		return false;
	}

	bss_2g = NULL;
	bss_5g = NULL;

	wsc->scan_id = 0;

	for (bss_entry = l_queue_get_entries(bss_list); bss_entry;
				bss_entry = bss_entry->next) {
		struct scan_bss *bss = bss_entry->data;
		enum scan_band band;
		int err;

		l_debug("bss '%s' with SSID: %s, freq: %u",
			util_address_to_string(bss->addr),
			util_ssid_to_utf8(bss->ssid_len, bss->ssid),
			bss->frequency);

		l_debug("bss->wsc: %p, %zu", bss->wsc, bss->wsc_size);

		if (!bss->wsc)
			continue;

		err = wsc_parse_probe_response(bss->wsc, bss->wsc_size,
						&probe_response);
		if (err < 0) {
			l_debug("ProbeResponse parse failed: %s",
							strerror(-err));
			continue;
		}

		l_debug("SelectedRegistar: %s",
			probe_response.selected_registrar ? "true" : "false");

		if (!probe_response.selected_registrar)
			continue;

		if (probe_response.device_password_id !=
				WSC_DEVICE_PASSWORD_ID_PUSH_BUTTON)
			continue;

		scan_freq_to_channel(bss->frequency, &band);

		switch (band) {
		case SCAN_BAND_2_4_GHZ:
			if (bss_2g) {
				l_debug("2G Session overlap error");
				goto session_overlap;
			}

			bss_2g = bss;
			memcpy(uuid_2g, probe_response.uuid_e, 16);
			break;

		case SCAN_BAND_5_GHZ:
			if (bss_5g) {
				l_debug("5G Session overlap error");
				goto session_overlap;
			}

			bss_5g = bss;
			memcpy(uuid_5g, probe_response.uuid_e, 16);
			break;

		default:
			return false;
		}
	}

	if (bss_2g && bss_5g && memcmp(uuid_2g, uuid_5g, 16)) {
		l_debug("Found two PBC APs on different bands");
		goto session_overlap;
	}

	if (bss_5g)
		target = bss_5g;
	else if (bss_2g)
		target = bss_2g;
	else {
		l_debug("No PBC APs found, running the scan again");
		wsc->scan_id = scan_active(netdev_get_ifindex(wsc->netdev),
						wsc->wsc_ies, wsc->wsc_ies_size,
						NULL, push_button_scan_results,
						wsc, NULL);
		return false;
	}

	wsc_cancel_scan(wsc);
	station_set_scan_results(wsc->station, bss_list, false);

	l_debug("Found AP to connect to: %s",
			util_address_to_string(target->addr));
	wsc_check_can_connect(wsc, target);

	return true;

session_overlap:
	wsc_cancel_scan(wsc);
	dbus_pending_reply(&wsc->pending,
				wsc_error_session_overlap(wsc->pending));

	return false;
}

static const char *authorized_macs_to_string(const uint8_t *authorized_macs)
{
	unsigned int i;
	unsigned int offset = 0;
	/* Max of 5 addresses in AuthorizedMacs, 17 bytes / address */
	static char buf[128];

	for (i = 0; i < 5; i++) {
		const uint8_t *addr = authorized_macs + i * 6;

		if (util_mem_is_zero(addr, 6))
			continue;

		offset += sprintf(buf + offset, "%s",
						util_address_to_string(addr));
	}

	return buf;
}

static bool authorized_macs_contains(const uint8_t *authorized_macs,
							const uint8_t *target)
{
	unsigned int i;

	for (i = 0; i < 5; i++) {
		const uint8_t *addr = authorized_macs + i * 6;

		if (!memcmp(addr, target, 6))
			return true;
	}

	return false;
}

static bool pin_scan_results(uint32_t wiphy_id, uint32_t ifindex, int err,
				struct l_queue *bss_list, void *userdata)
{
	static const uint8_t wildcard_address[] =
					{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
	struct wsc *wsc = userdata;
	struct scan_bss *target = NULL;
	const struct l_queue_entry *bss_entry;
	struct wsc_probe_response probe_response;

	if (err) {
		wsc_cancel_scan(wsc);
		dbus_pending_reply(&wsc->pending,
					dbus_error_failed(wsc->pending));

		return false;
	}

	wsc->scan_id = 0;

	for (bss_entry = l_queue_get_entries(bss_list); bss_entry;
				bss_entry = bss_entry->next) {
		struct scan_bss *bss = bss_entry->data;
		const uint8_t *amacs;
		int err;

		l_debug("bss '%s' with SSID: %s, freq: %u",
			util_address_to_string(bss->addr),
			util_ssid_to_utf8(bss->ssid_len, bss->ssid),
			bss->frequency);

		l_debug("bss->wsc: %p, %zu", bss->wsc, bss->wsc_size);

		if (!bss->wsc)
			continue;

		err = wsc_parse_probe_response(bss->wsc, bss->wsc_size,
						&probe_response);
		if (err < 0) {
			l_debug("ProbeResponse parse failed: %s",
							strerror(-err));
			continue;
		}

		if (probe_response.device_password_id !=
					WSC_DEVICE_PASSWORD_ID_DEFAULT &&
				probe_response.device_password_id !=
					WSC_DEVICE_PASSWORD_ID_USER_SPECIFIED)
			continue;

		l_debug("SelectedRegistar: %s",
			probe_response.selected_registrar ? "true" : "false");

		/*
		 * WSC Best Practices v2.0.1, Section 3.4:
		 * In a mixed environment with both WSC 1.0 and WSC 2.0 APs, an
		 * Enrollee should be prepared to run both the WSC 1.0 and
		 * WSC 2.0 forms of discovery. An Enrollee may scan available
		 * channels and then order PIN attempts with prospective APs
		 * as follows:
		 * 1. WSC 2.0 AP with the Selected Registrar attribute TRUE
		 * and the Enrollee’s MAC address in the AuthorizedMACs
		 * sub-element in Beacons and Probe Responses.
		 * 2. WSC 2.0 APs with the Selected Registrar attribute TRUE
		 * and the wildcard MAC address in the AuthorizedMACs
		 * sub-element in Beacons and Probe Responses, ordered by
		 * decreasing RSSI.
		 * 3. WSC 1.0 APs, ordered by decreasing RSSI.
		 * If option 1 is available, options 2 and 3 should be
		 * unnecessary.
		 */
		if (!probe_response.selected_registrar)
			continue;

		amacs = probe_response.authorized_macs;
		l_debug("AuthorizedMacs: %s", authorized_macs_to_string(amacs));

		if (authorized_macs_contains(amacs,
					netdev_get_address(wsc->netdev))) {
			target = bss;
			break;
		} else if (!target && authorized_macs_contains(amacs,
							wildcard_address))
			target = bss;
	}

	if (!target) {
		l_debug("No PIN APs found, running the scan again");
		wsc->scan_id = scan_active(netdev_get_ifindex(wsc->netdev),
						wsc->wsc_ies, wsc->wsc_ies_size,
						NULL, pin_scan_results,
						wsc, NULL);
		return false;
	}

	wsc_cancel_scan(wsc);
	station_set_scan_results(wsc->station, bss_list, false);

	l_debug("Found AP to connect to: %s",
			util_address_to_string(target->addr));
	wsc_check_can_connect(wsc, target);

	return true;
}

static bool wsc_initiate_scan(struct wsc *wsc,
					enum wsc_device_password_id dpid,
					scan_notify_func_t callback)
{
	static const uint8_t wfa_oui[] = { 0x00, 0x50, 0xF2 };
	struct wsc_probe_request req;
	struct wiphy *wiphy = netdev_get_wiphy(wsc->netdev);
	uint32_t bands;
	uint8_t *wsc_data;
	size_t wsc_data_size;

	memset(&req, 0, sizeof(req));

	req.version2 = true;
	req.request_type = WSC_REQUEST_TYPE_ENROLLEE_INFO;

	/* TODO: Grab from configuration file ? */
	req.config_methods = WSC_CONFIGURATION_METHOD_VIRTUAL_PUSH_BUTTON |
				WSC_CONFIGURATION_METHOD_KEYPAD;

	if (!wsc_uuid_from_addr(netdev_get_address(wsc->netdev), req.uuid_e))
		return false;

	/* TODO: Grab from configuration file ? */
	req.primary_device_type.category = 255;
	memcpy(req.primary_device_type.oui, wfa_oui, 3);
	req.primary_device_type.oui_type = 0x04;
	req.primary_device_type.subcategory = 0;

	bands = wiphy_get_supported_bands(wiphy);
	if (bands & SCAN_BAND_2_4_GHZ)
		req.rf_bands |= WSC_RF_BAND_2_4_GHZ;
	if (bands & SCAN_BAND_5_GHZ)
		req.rf_bands |= WSC_RF_BAND_5_0_GHZ;

	req.association_state = WSC_ASSOCIATION_STATE_NOT_ASSOCIATED;
	req.configuration_error = WSC_CONFIGURATION_ERROR_NO_ERROR;
	req.device_password_id = dpid;
	req.request_to_enroll = true;

	wsc_data = wsc_build_probe_request(&req, &wsc_data_size);
	if (!wsc_data)
		return false;

	wsc->wsc_ies = ie_tlv_encapsulate_wsc_payload(wsc_data, wsc_data_size,
							&wsc->wsc_ies_size);
	l_free(wsc_data);

	if (!wsc->wsc_ies)
		return false;

	wsc->scan_id = scan_active(netdev_get_ifindex(wsc->netdev),
					wsc->wsc_ies, wsc->wsc_ies_size,
					NULL, callback, wsc, NULL);
	if (!wsc->scan_id) {
		l_free(wsc->wsc_ies);
		wsc->wsc_ies = NULL;

		return false;
	}

	return true;
}

static struct l_dbus_message *wsc_push_button(struct l_dbus *dbus,
						struct l_dbus_message *message,
						void *user_data)
{
	struct wsc *wsc = user_data;

	l_debug("");

	if (wsc->pending)
		return dbus_error_busy(message);

	wsc->station = station_find(netdev_get_ifindex(wsc->netdev));
	if (!wsc->station)
		return dbus_error_not_available(message);

	if (!wsc_initiate_scan(wsc, WSC_DEVICE_PASSWORD_ID_PUSH_BUTTON,
				push_button_scan_results))
		return dbus_error_failed(message);

	wsc->walk_timer = l_timeout_create(WALK_TIME, walk_timeout, wsc, NULL);
	wsc->pending = l_dbus_message_ref(message);

	return NULL;
}

static struct l_dbus_message *wsc_generate_pin(struct l_dbus *dbus,
						struct l_dbus_message *message,
						void *user_data)
{
	struct wsc *wsc = user_data;
	struct l_dbus_message *reply;
	char pin[9];

	l_debug("");

	if (wsc->pending)
		return dbus_error_busy(message);

	if (!wsc_pin_generate(pin))
		return dbus_error_failed(message);

	reply = l_dbus_message_new_method_return(message);
	l_dbus_message_set_arguments(reply, "s", pin);

	return reply;
}

static struct l_dbus_message *wsc_start_pin(struct l_dbus *dbus,
						struct l_dbus_message *message,
						void *user_data)
{
	struct wsc *wsc = user_data;
	const char *pin;
	enum wsc_device_password_id dpid;

	l_debug("");

	if (wsc->pending)
		return dbus_error_busy(message);

	wsc->station = station_find(netdev_get_ifindex(wsc->netdev));
	if (!wsc->station)
		return dbus_error_not_available(message);

	if (!l_dbus_message_get_arguments(message, "s", &pin))
		return dbus_error_invalid_args(message);

	if (!wsc_pin_is_valid(pin))
		return dbus_error_invalid_format(message);

	if (strlen(pin) == 4 || wsc_pin_is_checksum_valid(pin))
		dpid = WSC_DEVICE_PASSWORD_ID_DEFAULT;
	else
		dpid = WSC_DEVICE_PASSWORD_ID_USER_SPECIFIED;

	if (!wsc_initiate_scan(wsc, dpid, pin_scan_results))
		return dbus_error_failed(message);

	wsc->walk_timer = l_timeout_create(60, pin_timeout, wsc, NULL);
	wsc->pending = l_dbus_message_ref(message);

	return NULL;
}

static struct l_dbus_message *wsc_cancel(struct l_dbus *dbus,
						struct l_dbus_message *message,
						void *user_data)
{
	struct wsc *wsc = user_data;
	struct l_dbus_message *reply;

	l_debug("");

	if (!wsc->pending)
		return dbus_error_not_available(message);

	wsc_cancel_scan(wsc);

	if (wsc->station_state_watch) {
		station_remove_state_watch(wsc->station,
						wsc->station_state_watch);
		wsc->station_state_watch = 0;
		wsc->target = NULL;
	}

	if (wsc->wsc_association) {
		int r;

		r = netdev_disconnect(wsc->netdev, wsc_disconnect_cb, wsc);
		if (r == 0) {
			wsc->pending_cancel = l_dbus_message_ref(message);
			return NULL;
		}

		l_warn("Unable to initiate disconnect: %s", strerror(-r));
		wsc->wsc_association = false;
	}

	dbus_pending_reply(&wsc->pending, dbus_error_aborted(wsc->pending));

	reply = l_dbus_message_new_method_return(message);
	l_dbus_message_set_arguments(reply, "");

	return reply;
}

static void setup_wsc_interface(struct l_dbus_interface *interface)
{
	l_dbus_interface_method(interface, "PushButton", 0,
				wsc_push_button, "", "");
	l_dbus_interface_method(interface, "GeneratePin", 0,
				wsc_generate_pin, "s", "", "pin");
	l_dbus_interface_method(interface, "StartPin", 0,
				wsc_start_pin, "", "s", "pin");
	l_dbus_interface_method(interface, "Cancel", 0,
				wsc_cancel, "", "");
}

static void wsc_free(void *userdata)
{
	struct wsc *wsc = userdata;

	wsc_cancel_scan(wsc);

	if (wsc->station_state_watch) {
		station_remove_state_watch(wsc->station,
						wsc->station_state_watch);
		wsc->station_state_watch = 0;
		wsc->target = NULL;
	}

	if (wsc->pending)
		dbus_pending_reply(&wsc->pending,
					dbus_error_not_available(wsc->pending));

	if (wsc->pending_cancel)
		dbus_pending_reply(&wsc->pending_cancel,
				dbus_error_aborted(wsc->pending_cancel));

	if (wsc->eap_settings)
		l_settings_free(wsc->eap_settings);

	l_free(wsc);
}

static void wsc_add_interface(struct netdev *netdev)
{
	struct l_dbus *dbus = dbus_get_bus();
	struct wsc *wsc;

	wsc = l_new(struct wsc, 1);
	wsc->netdev = netdev;

	if (!l_dbus_object_add_interface(dbus, netdev_get_path(netdev),
						IWD_WSC_INTERFACE,
						wsc)) {
		wsc_free(wsc);
		l_info("Unable to register %s interface", IWD_WSC_INTERFACE);
	}
}

static void wsc_remove_interface(struct netdev *netdev)
{
	struct l_dbus *dbus = dbus_get_bus();

	l_dbus_object_remove_interface(dbus, netdev_get_path(netdev),
					IWD_WSC_INTERFACE);
}

static void wsc_netdev_watch(struct netdev *netdev,
				enum netdev_watch_event event, void *userdata)
{
	switch (event) {
	case NETDEV_WATCH_EVENT_UP:
	case NETDEV_WATCH_EVENT_NEW:
		if (netdev_get_iftype(netdev) == NETDEV_IFTYPE_STATION &&
				netdev_get_is_up(netdev))
			wsc_add_interface(netdev);
		break;
	case NETDEV_WATCH_EVENT_DOWN:
	case NETDEV_WATCH_EVENT_DEL:
		wsc_remove_interface(netdev);
		break;
	default:
		break;
	}
}

bool wsc_init(void)
{
	l_debug("");
	netdev_watch = netdev_watch_add(wsc_netdev_watch, NULL, NULL);
	l_dbus_register_interface(dbus_get_bus(), IWD_WSC_INTERFACE,
					setup_wsc_interface,
					wsc_free, false);
	return true;
}

bool wsc_exit()
{
	l_debug("");
	l_dbus_unregister_interface(dbus_get_bus(), IWD_WSC_INTERFACE);
	netdev_watch_remove(netdev_watch);

	return true;
}
