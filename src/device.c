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
#include "src/station.h"

struct device {
	uint32_t index;
	uint8_t preauth_bssid[ETH_ALEN];
	struct signal_agent *signal_agent;

	struct wiphy *wiphy;
	struct netdev *netdev;
	struct station *station;

	bool powered : 1;

	uint32_t ap_roam_watch;
};

struct signal_agent {
	char *owner;
	char *path;
	unsigned int disconnect_watch;
};

static uint32_t netdev_watch;

static void device_netdev_event(struct netdev *netdev, enum netdev_event event,
					void *user_data);

/* TODO: Remove when Station/Device is split */
static bool device_is_busy(struct device *device)
{
	if (!device->powered || !device->station)
		return false;

	return station_is_busy(device->station);
}

static void device_reassociate_cb(struct netdev *netdev,
					enum netdev_result result,
					void *user_data)
{
	struct device *device = user_data;
	struct station *station = device->station;

	l_debug("%d, result: %d", device->index, result);

	if (station->state != STATION_STATE_ROAMING)
		return;

	if (result == NETDEV_RESULT_OK) {
		station_roamed(station);
		station_enter_state(station, STATION_STATE_CONNECTED);
	} else
		station_roam_failed(station);
}

static void device_fast_transition_cb(struct netdev *netdev,
					enum netdev_result result,
					void *user_data)
{
	struct device *device = user_data;
	struct station *station = device->station;

	l_debug("%d, result: %d", device->index, result);

	if (station->state != STATION_STATE_ROAMING)
		return;

	if (result == NETDEV_RESULT_OK) {
		station_roamed(station);
		station_enter_state(station, STATION_STATE_CONNECTED);
	} else
		station_roam_failed(station);
}

static void device_transition_reassociate(struct device *device,
						struct scan_bss *bss,
						struct handshake_state *new_hs)
{
	struct station *station = device->station;

	if (netdev_reassociate(device->netdev, bss, station->connected_bss,
				new_hs, device_netdev_event,
				device_reassociate_cb, device) < 0) {
		handshake_state_free(new_hs);
		station_roam_failed(station);
		return;
	}

	station->connected_bss = bss;
	station->preparing_roam = false;
	station_enter_state(station, STATION_STATE_ROAMING);
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
	struct station *station = device->station;
	struct network *connected = station->connected_network;
	struct scan_bss *bss;
	struct handshake_state *new_hs;

	l_debug("%d, result: %d", device->index, result);

	if (!station->preparing_roam || result == NETDEV_RESULT_ABORTED)
		return;

	bss = l_queue_find(device->station->bss_list, bss_match_bssid,
				device->preauth_bssid);
	if (!bss) {
		l_error("Roam target BSS not found");
		station_roam_failed(station);
		return;
	}

	new_hs = station_handshake_setup(station, connected, bss);
	if (!new_hs) {
		l_error("device_handshake_setup failed");

		station_roam_failed(station);
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
		 * supplicant_ie can't be a WPA IE here, including because
		 * the WPA IE doesn't have a capabilities field and
		 * target_rsne->preauthentication would have been false in
		 * device_transition_start.
		 */
		ie_parse_rsne_from_data(new_hs->supplicant_ie,
					new_hs->supplicant_ie[1] + 2,
					&rsn_info);

		handshake_state_get_pmkid(new_hs, pmkid);

		rsn_info.num_pmkids = 1;
		rsn_info.pmkids = pmkid;

		ie_build_rsne(&rsn_info, rsne_buf);
		handshake_state_set_supplicant_rsn(new_hs, rsne_buf);
	}

	device_transition_reassociate(device, bss, new_hs);
}

void device_transition_start(struct device *device, struct scan_bss *bss)
{
	struct station *station = device->station;
	struct handshake_state *hs = netdev_get_handshake(device->netdev);
	struct network *connected = station->connected_network;
	enum security security = network_get_security(connected);
	uint16_t mdid;
	struct handshake_state *new_hs;
	struct ie_rsn_info cur_rsne, target_rsne;

	l_debug("%d, target %s", device->index,
			util_address_to_string(bss->addr));

	/* Reset AP roam flag, at this point the roaming behaves the same */
	station->ap_directed_roaming = false;

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
			station_roam_failed(station);
			return;
		}

		station->connected_bss = bss;
		station->preparing_roam = false;
		station_enter_state(station, STATION_STATE_ROAMING);

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
			!station->roam_no_orig_ap &&
			scan_bss_get_rsn_info(station->connected_bss,
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

	new_hs = station_handshake_setup(station, connected, bss);
	if (!new_hs) {
		l_error("device_handshake_setup failed in reassociation");
		station_roam_failed(station);
		return;
	}

	device_transition_reassociate(device, bss, new_hs);
}

static void device_ap_roam_frame_event(struct netdev *netdev,
		const struct mmpdu_header *hdr,
		const void *body, size_t body_len,
		void *user_data)
{
	struct device *device = user_data;
	struct station *station = device->station;

	station_ap_directed_roam(station, hdr, body, body_len);
}

static void device_connect_cb(struct netdev *netdev, enum netdev_result result,
					void *user_data)
{
	struct device *device = user_data;
	struct station *station = device->station;

	l_debug("%d, result: %d", device->index, result);

	if (station->connect_pending) {
		struct l_dbus_message *reply;

		switch (result) {
		case NETDEV_RESULT_ABORTED:
			reply = dbus_error_aborted(station->connect_pending);
			break;
		case NETDEV_RESULT_OK:
			reply = l_dbus_message_new_method_return(
						station->connect_pending);
			l_dbus_message_set_arguments(reply, "");
			break;
		default:
			reply = dbus_error_failed(station->connect_pending);
			break;
		}

		dbus_pending_reply(&station->connect_pending, reply);
	}

	if (result != NETDEV_RESULT_OK) {
		if (result != NETDEV_RESULT_ABORTED) {
			network_connect_failed(station->connected_network);
			station_disassociated(station);
		}

		return;
	}

	network_connected(station->connected_network);
	station_enter_state(station, STATION_STATE_CONNECTED);
}

static void device_signal_agent_notify(struct signal_agent *agent,
					const char *device_path, int level)
{
	struct l_dbus_message *msg;
	uint8_t value = level;

	msg = l_dbus_message_new_method_call(dbus_get_bus(),
						agent->owner, agent->path,
						IWD_SIGNAL_AGENT_INTERFACE,
						"Changed");
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
	struct station *station = device->station;

	switch (event) {
	case NETDEV_EVENT_AUTHENTICATING:
		l_debug("Authenticating");
		break;
	case NETDEV_EVENT_ASSOCIATING:
		l_debug("Associating");
		break;
	case NETDEV_EVENT_LOST_BEACON:
		station_lost_beacon(station);
		break;
	case NETDEV_EVENT_DISCONNECT_BY_AP:
	case NETDEV_EVENT_DISCONNECT_BY_SME:
		station_disconnect_event(station);
		break;
	case NETDEV_EVENT_RSSI_THRESHOLD_LOW:
		station_low_rssi(station);
		break;
	case NETDEV_EVENT_RSSI_THRESHOLD_HIGH:
		station_ok_rssi(station);
		break;
	case NETDEV_EVENT_RSSI_LEVEL_NOTIFY:
		if (device->signal_agent)
			device_signal_agent_notify(device->signal_agent,
					netdev_get_path(netdev),
					netdev_get_rssi_level(netdev));

		break;
	};
}

int __device_connect_network(struct device *device, struct network *network,
				struct scan_bss *bss)
{
	struct l_dbus *dbus = dbus_get_bus();
	struct station *station = device->station;
	struct netdev *netdev = station->netdev;
	struct handshake_state *hs;
	int r;

	if (device_is_busy(device))
		return -EBUSY;

	hs = station_handshake_setup(station, network, bss);
	if (!hs)
		return -ENOTSUP;

	r = netdev_connect(device->netdev, bss, hs, device_netdev_event,
					device_connect_cb, device);
	if (r < 0) {
		handshake_state_free(hs);
		return r;
	}

	station->connected_bss = bss;
	station->connected_network = network;

	station_enter_state(station, STATION_STATE_CONNECTING);

	l_dbus_property_changed(dbus, netdev_get_path(netdev),
				IWD_DEVICE_INTERFACE, "ConnectedNetwork");
	l_dbus_property_changed(dbus, network_get_path(network),
				IWD_NETWORK_INTERFACE, "Connected");

	return 0;
}

void device_connect_network(struct device *device, struct network *network,
				struct scan_bss *bss,
				struct l_dbus_message *message)
{
	struct station *station = device->station;
	int err = __device_connect_network(device, network, bss);

	if (err < 0) {
		struct l_dbus *dbus = dbus_get_bus();

		l_dbus_send(dbus, dbus_error_from_errno(err, message));
		return;
	}

	station->connect_pending = l_dbus_message_ref(message);
	station->autoconnect = true;
}

static struct l_dbus_message *device_scan(struct l_dbus *dbus,
						struct l_dbus_message *message,
						void *user_data)
{
	struct device *device = user_data;
	struct station *station = device->station;

	/* TODO: Remove when Device/Station split is done */
	if (netdev_get_iftype(device->netdev) != NETDEV_IFTYPE_STATION)
		return dbus_error_not_available(message);

	if (!device->powered)
		return dbus_error_failed(message);

	return station_dbus_scan(dbus, message, station);
}

static struct l_dbus_message *device_dbus_disconnect(struct l_dbus *dbus,
						struct l_dbus_message *message,
						void *user_data)
{
	struct device *device = user_data;
	struct station *station = device->station;

	if (!device->powered || !device->station)
		return dbus_error_not_available(message);

	return station_dbus_disconnect(dbus, message, station);
}

static struct l_dbus_message *device_get_networks(struct l_dbus *dbus,
						struct l_dbus_message *message,
						void *user_data)
{
	struct device *device = user_data;
	struct station *station = device->station;

	if (!device->powered || !device->station)
		return dbus_error_not_available(message);

	return station_dbus_get_networks(dbus, message, station);
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

static struct l_dbus_message *device_connect_hidden_network(struct l_dbus *dbus,
						struct l_dbus_message *message,
						void *user_data)
{
	struct device *device = user_data;
	struct station *station = device->station;

	if (!device->powered || !device->station)
		return dbus_error_not_available(message);

	return station_dbus_connect_hidden_network(dbus, message, station);
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
	struct station *station = device->station;

	if (!station->connected_network)
		return false;

	l_dbus_message_builder_append_basic(builder, 'o',
				network_get_path(station->connected_network));

	return true;
}

static bool device_property_get_powered(struct l_dbus *dbus,
					struct l_dbus_message *message,
					struct l_dbus_message_builder *builder,
					void *user_data)
{
	struct device *device = user_data;
	bool powered = device->powered;

	l_dbus_message_builder_append_basic(builder, 'b', &powered);

	return true;
}

struct set_generic_cb_data {
	struct device *device;
	struct l_dbus *dbus;
	struct l_dbus_message *message;
	l_dbus_property_complete_cb_t complete;
};

static void set_generic_destroy(void *user_data)
{
	struct set_generic_cb_data *cb_data = user_data;

	/* Message hasn't been replied to, generate an Aborted error */
	if (cb_data->message)
		cb_data->complete(cb_data->dbus, cb_data->message,
					dbus_error_aborted(cb_data->message));

	l_free(cb_data);
}

static void set_powered_cb(struct netdev *netdev, int result, void *user_data)
{
	struct set_generic_cb_data *cb_data = user_data;
	struct l_dbus_message *reply = NULL;

	if (result < 0)
		reply = dbus_error_failed(cb_data->message);

	cb_data->complete(cb_data->dbus, cb_data->message, reply);
	cb_data->message = NULL;
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
	int r;

	if (!l_dbus_message_iter_get_variant(new_value, "b", &powered))
		return dbus_error_invalid_args(message);

	if (powered == device->powered) {
		complete(dbus, message, NULL);

		return NULL;
	}

	cb_data = l_new(struct set_generic_cb_data, 1);
	cb_data->device = device;
	cb_data->dbus = dbus;
	cb_data->message = message;
	cb_data->complete = complete;

	r = netdev_set_powered(device->netdev, powered, set_powered_cb,
					cb_data, set_generic_destroy);
	if (r < 0) {
		l_free(cb_data);
		return dbus_error_from_errno(r, message);
	}

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
	cb_data->message = NULL;

	l_dbus_property_changed(cb_data->dbus,
				netdev_get_path(cb_data->device->netdev),
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

	if (netdev_set_4addr(device->netdev, use_4addr, set_4addr_cb,
				cb_data, set_generic_destroy) < 0)
		return dbus_error_failed(message);

	return NULL;
}

static bool device_property_get_scanning(struct l_dbus *dbus,
					struct l_dbus_message *message,
					struct l_dbus_message_builder *builder,
					void *user_data)
{
	struct device *device = user_data;
	struct station *station = device->station;
	bool scanning = station->scanning;

	l_dbus_message_builder_append_basic(builder, 'b', &scanning);

	return true;
}

static bool device_property_get_state(struct l_dbus *dbus,
					struct l_dbus_message *message,
					struct l_dbus_message_builder *builder,
					void *user_data)
{
	struct device *device = user_data;
	const char *statestr;

	/* TODO: Remove when Device/Station split is done */
	if (netdev_get_iftype(device->netdev) != NETDEV_IFTYPE_STATION) {
		uint32_t iftype = netdev_get_iftype(device->netdev);
		l_dbus_message_builder_append_basic(builder, 's',
						dbus_iftype_to_string(iftype));
		return true;
	}

	if (device->powered == false) {
		l_dbus_message_builder_append_basic(builder,
							's', "disconnected");
		return true;
	}

	statestr = station_state_to_string(device->station->state);

	/* Special case.  For now we treat AUTOCONNECT as disconnected */
	if (device->station->state == STATION_STATE_AUTOCONNECT)
		statestr = "disconnected";

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
	uint32_t iftype = netdev_get_iftype(device->netdev);
	const char *modestr = dbus_iftype_to_string(iftype);

	if (modestr == NULL)
		modestr = "unknown";

	l_dbus_message_builder_append_basic(builder, 's', modestr);

	return true;
}

static void set_mode_cb(struct netdev *netdev, int result, void *user_data)
{
	struct set_generic_cb_data *cb_data = user_data;
	struct l_dbus_message *reply = NULL;

	if (result < 0)
		reply = dbus_error_from_errno(result, cb_data->message);

	cb_data->complete(cb_data->dbus, cb_data->message, reply);
	cb_data->message = NULL;

	l_dbus_property_changed(cb_data->dbus,
				netdev_get_path(cb_data->device->netdev),
				IWD_DEVICE_INTERFACE, "Mode");

	/* TODO: Special case, remove when Device/Station split is made */
	l_dbus_property_changed(cb_data->dbus,
				netdev_get_path(cb_data->device->netdev),
				IWD_DEVICE_INTERFACE, "State");
}

static struct l_dbus_message *device_property_set_mode(struct l_dbus *dbus,
					struct l_dbus_message *message,
					struct l_dbus_message_iter *new_value,
					l_dbus_property_complete_cb_t complete,
					void *user_data)
{
	struct device *device = user_data;
	struct netdev *netdev = device->netdev;
	const char *mode;
	enum netdev_iftype iftype;
	int r;
	struct set_generic_cb_data *cb_data;

	if (!l_dbus_message_iter_get_variant(new_value, "s", &mode))
		return dbus_error_invalid_args(message);

	if (!strcmp(mode, "station"))
		iftype = NETDEV_IFTYPE_STATION;
	else if (!strcmp(mode, "ap"))
		iftype = NETDEV_IFTYPE_AP;
	else if (!strcmp(mode, "ad-hoc"))
		iftype = NETDEV_IFTYPE_ADHOC;
	else
		return dbus_error_invalid_args(message);

	if (iftype == netdev_get_iftype(netdev)) {
		complete(dbus, message, NULL);
		return NULL;
	}

	/* TODO: Special case, remove when Device/Station split is made */
	if (iftype != NETDEV_IFTYPE_STATION && device_is_busy(device))
		return dbus_error_busy(message);

	cb_data = l_new(struct set_generic_cb_data, 1);
	cb_data->device = device;
	cb_data->dbus = dbus;
	cb_data->message = message;
	cb_data->complete = complete;

	r = netdev_set_iftype(device->netdev, iftype, set_mode_cb,
					cb_data, set_generic_destroy);
	if (r < 0) {
		l_free(cb_data);
		return dbus_error_from_errno(r, message);
	}

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
	struct device *device = netdev_get_device(netdev);
	struct l_dbus *dbus = dbus_get_bus();

	if (!device)
		return;

	switch (event) {
	case NETDEV_WATCH_EVENT_UP:
		device->powered = true;
		l_dbus_property_changed(dbus, netdev_get_path(device->netdev),
					IWD_DEVICE_INTERFACE, "Powered");

		/* TODO: Remove when Device/Station split is done */
		if (netdev_get_iftype(device->netdev) != NETDEV_IFTYPE_STATION)
			return;

		device->station = station_create(device->wiphy, device->netdev);
		break;
	case NETDEV_WATCH_EVENT_DOWN:
		if (device->station) {
			station_free(device->station);
			device->station = NULL;
		}

		device->powered = false;

		l_dbus_property_changed(dbus, netdev_get_path(device->netdev),
					IWD_DEVICE_INTERFACE, "Powered");
		break;
	case NETDEV_WATCH_EVENT_NAME_CHANGE:
		l_dbus_property_changed(dbus, netdev_get_path(device->netdev),
					IWD_DEVICE_INTERFACE, "Name");
		break;
	case NETDEV_WATCH_EVENT_ADDRESS_CHANGE:
		l_dbus_property_changed(dbus, netdev_get_path(device->netdev),
					IWD_DEVICE_INTERFACE, "Address");
		break;
	default:
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
	device->index = ifindex;
	device->wiphy = wiphy;
	device->netdev = netdev;

	if (!l_dbus_object_add_interface(dbus, netdev_get_path(device->netdev),
					IWD_DEVICE_INTERFACE, device))
		l_info("Unable to register %s interface", IWD_DEVICE_INTERFACE);

	if (!l_dbus_object_add_interface(dbus, netdev_get_path(device->netdev),
					L_DBUS_INTERFACE_PROPERTIES, device))
		l_info("Unable to register %s interface",
				L_DBUS_INTERFACE_PROPERTIES);

	scan_ifindex_add(device->index);

	/*
	 * register for AP roam transition watch
	 */
	device->ap_roam_watch = netdev_frame_watch_add(netdev, 0x00d0,
			action_ap_roam_prefix, sizeof(action_ap_roam_prefix),
			device_ap_roam_frame_event, device);

	device->powered = netdev_get_is_up(netdev);

	if (device->powered &&
			netdev_get_iftype(netdev) == NETDEV_IFTYPE_STATION)
		device->station = station_create(device->wiphy, device->netdev);

	return device;
}

void device_remove(struct device *device)
{
	struct l_dbus *dbus;

	l_debug("");

	if (device->signal_agent) {
		device_signal_agent_release(device->signal_agent,
					netdev_get_path(device->netdev));
		signal_agent_free(device->signal_agent);
	}


	dbus = dbus_get_bus();
	l_dbus_unregister_object(dbus, netdev_get_path(device->netdev));

	scan_ifindex_remove(device->index);

	netdev_frame_watch_remove(device->netdev, device->ap_roam_watch);

	l_free(device);
}

bool device_init(void)
{
	if (!l_dbus_register_interface(dbus_get_bus(),
					IWD_DEVICE_INTERFACE,
					setup_device_interface,
					NULL, false))
		return false;

	netdev_watch = netdev_watch_add(device_netdev_notify, NULL, NULL);

	return true;
}

void device_exit(void)
{
	netdev_watch_remove(netdev_watch);

	l_dbus_unregister_interface(dbus_get_bus(), IWD_DEVICE_INTERFACE);
}
