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
#include <ell/ell.h>

#include "src/dbus.h"
#include "src/netdev.h"
#include "src/device.h"
#include "src/wiphy.h"
#include "src/scan.h"
#include "src/ie.h"
#include "src/wscutil.h"
#include "src/util.h"
#include "src/wsc.h"
#include "src/eapol.h"
#include "src/eap-wsc.h"
#include "src/crypto.h"
#include "src/common.h"
#include "src/storage.h"
#include "src/iwd.h"
#include "src/network.h"

#define WALK_TIME 120

static struct l_genl_family *nl80211 = NULL;
static uint32_t device_watch = 0;

struct wsc {
	struct device *device;
	struct l_dbus_message *pending;
	uint8_t *wsc_ies;
	size_t wsc_ies_size;
	struct l_timeout *walk_timer;
	uint32_t scan_id;
	struct scan_bss *target;
	uint32_t device_state_watch;
	struct {
		char ssid[33];
		enum security security;
		uint8_t psk[32];
		uint8_t addr[6];
	} creds[3];
	uint32_t n_creds;
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

static void wsc_try_credentials(struct wsc *wsc)
{
	unsigned int i;
	struct network *network;
	struct scan_bss *bss;

	for (i = 0; i < wsc->n_creds; i++) {
		network = device_network_find(wsc->device,
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

		device_connect_network(wsc->device, network, bss, wsc->pending);
		l_dbus_message_unref(wsc->pending);
		wsc->pending = NULL;

		goto done;
	}

	dbus_pending_reply(&wsc->pending,
					wsc_error_not_reachable(wsc->pending));
	/* TODO: Go back to auto-connect mode ? */
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

		storage_network_sync(security_to_str(security), ssid, settings);
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

static void wsc_connect_cb(struct netdev *netdev, enum netdev_result result,
					void *user_data)
{
	struct wsc *wsc = user_data;
	struct l_dbus_message *reply;

	l_debug("%d, result: %d", device_get_ifindex(wsc->device), result);

	if (result == NETDEV_RESULT_HANDSHAKE_FAILED) {
		if (wsc->n_creds == 0) {
			dbus_pending_reply(&wsc->pending,
					wsc_error_no_credentials(wsc->pending));
		} else {
			wsc_store_credentials(wsc);
			wsc_try_credentials(wsc);
		}

		return;
	}

	switch (result) {
	case NETDEV_RESULT_ABORTED:
		reply = dbus_error_aborted(wsc->pending);
		break;
	default:
		reply = dbus_error_failed(wsc->pending);
		break;
	}

	dbus_pending_reply(&wsc->pending, reply);
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
	switch (event) {
	case NETDEV_EVENT_AUTHENTICATING:
	case NETDEV_EVENT_ASSOCIATING:
		break;
	case NETDEV_EVENT_4WAY_HANDSHAKE:
		l_info("Running EAP-WSC");
		break;
	case NETDEV_EVENT_LOST_BEACON:
		l_debug("Lost beacon");
		break;
	case NETDEV_EVENT_DISCONNECT_BY_AP:
		l_debug("Disconnect by AP");
		break;
	default:
		l_debug("Unexpected event");
		break;
	};
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
	struct eapol_sm *sm = eapol_sm_new();
	struct l_settings *settings = l_settings_new();
	struct scan_bss *bss = wsc->target;

	wsc->target = NULL;

	eapol_sm_set_authenticator_address(sm, bss->addr);
	eapol_sm_set_supplicant_address(sm, device_get_address(wsc->device));

	eapol_sm_set_user_data(sm, wsc);
	eapol_sm_set_event_func(sm, wsc_eapol_event);

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
		util_address_to_string(device_get_address(wsc->device)));

	eapol_sm_set_8021x_config(sm, settings);
	l_settings_free(settings);

	if (netdev_connect_wsc(device_get_netdev(wsc->device), bss, sm,
					wsc_netdev_event,
					wsc_connect_cb, wsc) == 0)
		return;

	eapol_sm_free(sm);
	dbus_pending_reply(&wsc->pending, dbus_error_failed(wsc->pending));
}

static void device_state_watch(enum device_state state, void *userdata)
{
	struct wsc *wsc = userdata;

	if (state != DEVICE_STATE_DISCONNECTED)
		return;

	l_debug("%p", wsc);

	device_remove_state_watch(wsc->device, wsc->device_state_watch);
	wsc->device_state_watch = 0;

	wsc_connect(wsc);
}

static void wsc_check_can_connect(struct wsc *wsc, struct scan_bss *target)
{
	l_debug("%p", wsc);

	/*
	 * For now we assign the targe pointer directly, since we should not
	 * be triggering any more scans while disconnecting / connecting
	 */
	wsc->target = target;
	device_set_autoconnect(wsc->device, false);

	switch (device_get_state(wsc->device)) {
	case DEVICE_STATE_DISCONNECTED:
		wsc_connect(wsc);
		return;
	case DEVICE_STATE_CONNECTING:
	case DEVICE_STATE_CONNECTED:
		if (device_disconnect(wsc->device) < 0)
			goto error;

		/* fall through */
	case DEVICE_STATE_DISCONNECTING:
		wsc->device_state_watch =
			device_add_state_watch(wsc->device, device_state_watch,
							wsc, NULL);
		return;
	case DEVICE_STATE_AUTOCONNECT:
	case DEVICE_STATE_OFF:
		l_warn("wsc_check_can_connect: invalid device state");
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
		scan_cancel(device_get_ifindex(wsc->device), wsc->scan_id);
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

static bool scan_results(uint32_t wiphy_id, uint32_t ifindex,
				struct l_queue *bss_list, void *userdata)
{
	struct wsc *wsc = userdata;
	struct scan_bss *bss_2g;
	struct scan_bss *bss_5g;
	struct scan_bss *target;
	uint8_t uuid_2g[16];
	uint8_t uuid_5g[16];
	const struct l_queue_entry *bss_entry;
	struct wsc_probe_response probe_response;

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
		wsc->scan_id = scan_active(device_get_ifindex(wsc->device),
						wsc->wsc_ies, wsc->wsc_ies_size,
						NULL, scan_results, wsc, NULL);
		return false;
	}

	wsc_cancel_scan(wsc);
	device_set_scan_results(wsc->device, bss_list);

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

static bool wsc_start_pushbutton(struct wsc *wsc)
{
	static const uint8_t wfa_oui[] = { 0x00, 0x50, 0xF2 };
	struct wsc_probe_request req;
	struct wiphy *wiphy = device_get_wiphy(wsc->device);
	uint32_t bands;
	uint8_t *wsc_data;
	size_t wsc_data_size;

	memset(&req, 0, sizeof(req));

	req.version2 = true;
	req.request_type = WSC_REQUEST_TYPE_ENROLLEE_INFO;

	/* TODO: Grab from configuration file ? */
	req.config_methods = WSC_CONFIGURATION_METHOD_VIRTUAL_PUSH_BUTTON |
				WSC_CONFIGURATION_METHOD_KEYPAD;

	if (!wsc_uuid_from_addr(device_get_address(wsc->device), req.uuid_e))
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

	req.association_state = WSC_ASSOCIATION_STATE_NOT_ASSOCIATED,
	req.configuration_error = WSC_CONFIGURATION_ERROR_NO_ERROR,
	req.device_password_id = WSC_DEVICE_PASSWORD_ID_PUSH_BUTTON,
	req.request_to_enroll = true,

	wsc_data = wsc_build_probe_request(&req, &wsc_data_size);
	if (!wsc_data)
		return false;

	wsc->wsc_ies = ie_tlv_encapsulate_wsc_payload(wsc_data, wsc_data_size,
							&wsc->wsc_ies_size);
	l_free(wsc_data);

	if (!wsc->wsc_ies)
		return false;

	wsc->scan_id = scan_active(device_get_ifindex(wsc->device),
					wsc->wsc_ies, wsc->wsc_ies_size,
					NULL, scan_results, wsc, NULL);
	wsc->walk_timer = l_timeout_create(WALK_TIME, walk_timeout, wsc, NULL);

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

	if (!wsc_start_pushbutton(wsc))
		return dbus_error_failed(message);

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

	if (wsc->device_state_watch) {
		device_remove_state_watch(wsc->device, wsc->device_state_watch);
		wsc->device_state_watch = 0;
		wsc->target = NULL;
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
	l_dbus_interface_method(interface, "Cancel", 0,
				wsc_cancel, "", "");
}

static void wsc_free(void *userdata)
{
	struct wsc *wsc = userdata;

	wsc_cancel_scan(wsc);

	if (wsc->device_state_watch) {
		device_remove_state_watch(wsc->device, wsc->device_state_watch);
		wsc->device_state_watch = 0;
		wsc->target = NULL;
	}

	if (wsc->pending)
		dbus_pending_reply(&wsc->pending,
					dbus_error_not_available(wsc->pending));

	l_free(wsc);
}

static void device_appeared(struct device *device, void *userdata)
{
	struct l_dbus *dbus = dbus_get_bus();
	struct wsc *wsc;

	wsc = l_new(struct wsc, 1);
	wsc->device = device;

	if (!l_dbus_object_add_interface(dbus, device_get_path(device),
						IWD_WSC_INTERFACE,
						wsc)) {
		wsc_free(wsc);
		l_info("Unable to register %s interface", IWD_WSC_INTERFACE);
	}
}

static void device_disappeared(struct device *device, void *userdata)
{
	struct l_dbus *dbus = dbus_get_bus();

	l_dbus_object_remove_interface(dbus, device_get_path(device),
					IWD_WSC_INTERFACE);
}

static void device_event(struct device *device, enum device_event event,
								void *userdata)
{
	switch (event) {
	case DEVICE_EVENT_INSERTED:
		return device_appeared(device, userdata);
	case DEVICE_EVENT_REMOVED:
		return device_disappeared(device, userdata);
	}
}

bool wsc_init(struct l_genl_family *in)
{
	if (!l_dbus_register_interface(dbus_get_bus(), IWD_WSC_INTERFACE,
					setup_wsc_interface,
					wsc_free, false))
		return false;

	device_watch = device_watch_add(device_event, NULL, NULL);
	if (!device_watch)
		return false;

	nl80211 = in;
	return true;
}

bool wsc_exit()
{
	l_debug("");

	if (!nl80211)
		return false;

	l_dbus_unregister_interface(dbus_get_bus(), IWD_WSC_INTERFACE);

	device_watch_remove(device_watch);
	nl80211 = 0;

	return true;
}
