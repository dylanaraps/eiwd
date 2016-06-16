/*
 *
 *  Wireless daemon for Linux
 *
 *  Copyright (C) 2013-2016  Intel Corporation. All rights reserved.
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

#include "src/iwd.h"
#include "src/common.h"
#include "src/util.h"
#include "src/ie.h"
#include "src/eapol.h"
#include "src/wiphy.h"
#include "src/scan.h"
#include "src/netdev.h"
#include "src/dbus.h"
#include "src/network.h"
#include "src/device.h"

struct device_watchlist_item {
	uint32_t id;
	device_watch_func_t added;
	device_watch_func_t removed;
	void *userdata;
	device_destroy_func_t destroy;
};

static struct l_queue *device_watches = NULL;
static uint32_t device_next_watch_id = 0;

static struct l_queue *device_list;

static void device_watchlist_item_free(void *userdata)
{
	struct device_watchlist_item *item = userdata;

	if (item->destroy)
		item->destroy(item->userdata);

	l_free(item);
}

static bool device_watchlist_item_match(const void *a, const void *b)
{
	const struct device_watchlist_item *item = a;
	uint32_t id = L_PTR_TO_UINT(b);

	return item->id == id;
}

uint32_t device_watch_add(device_watch_func_t added,
				device_watch_func_t removed,
				void *userdata, device_destroy_func_t destroy)
{
	struct device_watchlist_item *item;

	item = l_new(struct device_watchlist_item, 1);
	item->id = ++device_next_watch_id;
	item->added = added;
	item->removed = removed;
	item->userdata = userdata;
	item->destroy = destroy;

	l_queue_push_tail(device_watches, item);

	return item->id;
}

bool device_watch_remove(uint32_t id)
{
	struct device_watchlist_item *item;

	item = l_queue_remove_if(device_watches, device_watchlist_item_match,
							L_UINT_TO_PTR(id));
	if (!item)
		return false;

	device_watchlist_item_free(item);
	return true;
}

void __device_watch_call_added(struct device *device)
{
	const struct l_queue_entry *e;

	for (e = l_queue_get_entries(device_watches); e; e = e->next) {
		struct device_watchlist_item *item = e->data;

		if (item->added)
			item->added(device, item->userdata);
	}
}

void __device_watch_call_removed(struct device *device)
{
	const struct l_queue_entry *e;

	for (e = l_queue_get_entries(device_watches); e; e = e->next) {
		struct device_watchlist_item *item = e->data;

		if (item->removed)
			item->removed(device, item->userdata);
	}
}

void __iwd_device_foreach(iwd_device_foreach_func func, void *user_data)
{
	const struct l_queue_entry *device_entry;

	for (device_entry = l_queue_get_entries(device_list); device_entry;
					device_entry = device_entry->next) {
		struct device *device = device_entry->data;

		func(device, user_data);
	}
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

struct network *device_get_connected_network(struct device *device)
{
	return device->connected_network;
}

const char *device_get_path(struct device *device)
{
	static char path[12];

	snprintf(path, sizeof(path), "/%u", device->index);
	return path;
}

bool device_is_busy(struct device *device)
{
	if (device->state != DEVICE_STATE_DISCONNECTED &&
			device->state != DEVICE_STATE_AUTOCONNECT)
		return true;

	return false;
}

struct wiphy *device_get_wiphy(struct device *device)
{
	return device->wiphy;
}

uint32_t device_get_ifindex(struct device *device)
{
	return device->index;
}

const uint8_t *device_get_address(struct device *device)
{
	return netdev_get_address(device->netdev);
}

void device_disassociated(struct device *device)
{
	struct network *network = device->connected_network;
	struct l_dbus *dbus = dbus_get_bus();

	if (!network)
		return;

	network_disconnected(network);

	device->connected_bss = NULL;
	device->connected_network = NULL;

	device_enter_state(device, DEVICE_STATE_AUTOCONNECT);

	l_dbus_property_changed(dbus, device_get_path(device),
				IWD_DEVICE_INTERFACE, "ConnectedNetwork");
	l_dbus_property_changed(dbus, network_get_path(network),
				IWD_NETWORK_INTERFACE, "Connected");
}

static void device_lost_beacon(struct device *device)
{
	l_debug("%d", device->index);

	if (device->connect_pending)
		dbus_pending_reply(&device->connect_pending,
				dbus_error_failed(device->connect_pending));

	device_disassociated(device);
}

static void device_disconnect_by_ap(struct device *device)
{
	l_debug("%d", device->index);

	if (device->connect_pending) {
		struct network *network = device->connected_network;

		dbus_pending_reply(&device->connect_pending,
				dbus_error_failed(device->connect_pending));

		network_connect_failed(network);
	}

	device_disassociated(device);
}

static void device_connect_cb(struct netdev *netdev, enum netdev_result result,
					void *user_data)
{
	struct device *device = user_data;

	if (result != NETDEV_RESULT_OK) {
		if (device->connect_pending)
			dbus_pending_reply(&device->connect_pending,
				dbus_error_failed(device->connect_pending));

		device_disassociated(device);
		return;
	}

	if (device->connect_pending) {
		struct l_dbus_message *reply;

		reply = l_dbus_message_new_method_return(
						device->connect_pending);
		l_dbus_message_set_arguments(reply, "");
		dbus_pending_reply(&device->connect_pending, reply);
	}

	network_connected(device->connected_network);
	device_enter_state(device, DEVICE_STATE_CONNECTED);
}

static void device_netdev_event(struct netdev *netdev, enum netdev_event event,
					void *user_data)
{
	struct device *device = user_data;
	struct network *network = device->connected_network;

	switch (event) {
	case NETDEV_EVENT_AUTHENTICATING:
		l_debug("Authenticating");
		break;
	case NETDEV_EVENT_ASSOCIATING:
		l_debug("Associating");
		break;
	case NETDEV_EVENT_4WAY_HANDSHAKE:
		l_debug("Handshaking");
		break;
	case NETDEV_EVENT_SETTING_KEYS:
		l_debug("Setting keys");

		/* If we got here, then our PSK works.  Save if required */
		network_sync_psk(network);

		break;
	case NETDEV_EVENT_LOST_BEACON:
		device_lost_beacon(device);
		break;
	case NETDEV_EVENT_DISCONNECT_BY_AP:
		device_disconnect_by_ap(device);
	};
}

void device_connect_network(struct device *device, struct network *network,
				struct scan_bss *bss,
				struct l_dbus_message *message)
{
	enum security security = network_get_security(network);
	struct wiphy *wiphy = device->wiphy;
	struct l_dbus *dbus = dbus_get_bus();
	struct eapol_sm *sm = NULL;

	if (security == SECURITY_PSK || security == SECURITY_8021X) {
		uint16_t pairwise_ciphers, group_ciphers;
		uint8_t rsne_buf[256];
		struct ie_rsn_info info;

		sm = eapol_sm_new();

		eapol_sm_set_authenticator_address(sm, bss->addr);
		eapol_sm_set_supplicant_address(sm,
				netdev_get_address(device->netdev));

		memset(&info, 0, sizeof(info));

		if (security == SECURITY_PSK)
			info.akm_suites =
				bss->sha256 ? IE_RSN_AKM_SUITE_PSK_SHA256 :
						IE_RSN_AKM_SUITE_PSK;
		else
			info.akm_suites =
				bss->sha256 ? IE_RSN_AKM_SUITE_8021X_SHA256 :
						IE_RSN_AKM_SUITE_8021X;

		bss_get_supported_ciphers(bss,
					&pairwise_ciphers, &group_ciphers);

		info.pairwise_ciphers = wiphy_select_cipher(wiphy,
							pairwise_ciphers);
		info.group_cipher = wiphy_select_cipher(wiphy, group_ciphers);

		/* RSN takes priority */
		if (bss->rsne) {
			ie_build_rsne(&info, rsne_buf);
			eapol_sm_set_ap_rsn(sm, bss->rsne, bss->rsne[1] + 2);
			eapol_sm_set_own_rsn(sm, rsne_buf, rsne_buf[1] + 2);
		} else {
			ie_build_wpa(&info, rsne_buf);
			eapol_sm_set_ap_wpa(sm, bss->wpa, bss->wpa[1] + 2);
			eapol_sm_set_own_wpa(sm, rsne_buf, rsne_buf[1] + 2);
		}

		if (security == SECURITY_PSK)
			eapol_sm_set_pmk(sm, network_get_psk(network));
		else
			eapol_sm_set_8021x_config(sm,
					network_get_settings(network));
	}

	device->connect_pending = l_dbus_message_ref(message);

	if (netdev_connect(device->netdev, bss, sm,
					device_netdev_event,
					device_connect_cb, device) < 0) {
		dbus_pending_reply(&device->connect_pending,
				dbus_error_failed(device->connect_pending));
		return;
	}

	device->connected_bss = bss;
	device->connected_network = network;

	device_enter_state(device, DEVICE_STATE_CONNECTING);

	l_dbus_property_changed(dbus, device_get_path(device),
				IWD_DEVICE_INTERFACE, "ConnectedNetwork");
	l_dbus_property_changed(dbus, network_get_path(network),
				IWD_NETWORK_INTERFACE, "Connected");
}

struct device *device_create(struct wiphy *wiphy, struct netdev *netdev)
{
	struct device *device;
	struct l_dbus *dbus = dbus_get_bus();
	uint32_t ifindex = netdev_get_ifindex(netdev);

	device = l_new(struct device, 1);
	device->bss_list = l_queue_new();
	device->networks = l_hashmap_new();
	l_hashmap_set_hash_function(device->networks, l_str_hash);
	l_hashmap_set_compare_function(device->networks,
				(l_hashmap_compare_func_t) strcmp);
	device->networks_sorted = l_queue_new();
	device->index = ifindex;
	device->wiphy = wiphy;
	device->netdev = netdev;

	l_queue_push_head(device_list, device);

	if (!l_dbus_object_add_interface(dbus, device_get_path(device),
					IWD_DEVICE_INTERFACE, device))
		l_info("Unable to register %s interface", IWD_DEVICE_INTERFACE);

	__device_watch_call_added(device);

	scan_ifindex_add(device->index);
	device_enter_state(device, DEVICE_STATE_AUTOCONNECT);

	return device;
}

static void device_free(void *user)
{
	struct device *device = user;
	struct l_dbus *dbus;

	l_debug("");

	if (device->scan_pending)
		dbus_pending_reply(&device->scan_pending,
				dbus_error_aborted(device->scan_pending));

	if (device->connect_pending)
		dbus_pending_reply(&device->connect_pending,
				dbus_error_aborted(device->connect_pending));

	__device_watch_call_removed(device);

	dbus = dbus_get_bus();
	l_dbus_unregister_object(dbus, device_get_path(device));

	l_queue_destroy(device->networks_sorted, NULL);
	l_hashmap_destroy(device->networks, network_free);

	l_queue_destroy(device->bss_list, bss_free);
	l_queue_destroy(device->old_bss_list, bss_free);
	l_queue_destroy(device->autoconnect_list, l_free);

	scan_ifindex_remove(device->index);
	l_free(device);
}

void device_remove(struct device *device)
{
	if (!l_queue_remove(device_list, device))
		return;

	device_free(device);
}

bool device_init(void)
{
	device_watches = l_queue_new();
	device_list = l_queue_new();

	return true;
}

bool device_exit(void)
{
	l_queue_destroy(device_list, device_free);
	device_list = NULL;

	l_queue_destroy(device_watches, device_watchlist_item_free);

	return true;
}
