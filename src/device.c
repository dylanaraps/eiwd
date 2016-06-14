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

#include <ell/ell.h>

#include "src/common.h"
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
}

static void device_netdev_event(struct netdev *netdev, enum netdev_event event,
					void *user_data)
{
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
		break;
	case NETDEV_EVENT_LOST_BEACON:
		l_debug("Beacon lost");
		break;
	};
}

void device_connect_network(struct device *device, struct network *network,
				struct scan_bss *bss,
				struct l_dbus_message *message)
{
	struct l_dbus *dbus = dbus_get_bus();

	device->connect_pending = l_dbus_message_ref(message);

	if (netdev_connect(device->netdev, bss, NULL,
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

bool device_init(void)
{
	device_watches = l_queue_new();

	return true;
}

bool device_exit(void)
{
	l_queue_destroy(device_watches, device_watchlist_item_free);

	return true;
}
