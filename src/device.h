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

#include <stdbool.h>

struct scan_bss;
struct wiphy;
struct netdev;
struct device;

enum device_state {
	DEVICE_STATE_DISCONNECTED = 0,	/* Disconnected, no auto-connect */
	DEVICE_STATE_AUTOCONNECT,	/* Disconnected, try auto-connect */
	DEVICE_STATE_CONNECTING,	/* Connecting */
	DEVICE_STATE_CONNECTED,
	DEVICE_STATE_DISCONNECTING,
};

typedef void (*device_watch_func_t)(struct device *device, void *userdata);
typedef void (*device_destroy_func_t)(void *userdata);

struct device {
	uint32_t index;
	enum device_state state;
	struct l_queue *bss_list;
	struct l_queue *old_bss_list;
	struct l_dbus_message *scan_pending;
	struct l_hashmap *networks;
	struct l_queue *networks_sorted;
	struct scan_bss *connected_bss;
	struct network *connected_network;
	struct l_queue *autoconnect_list;
	struct l_dbus_message *connect_pending;
	struct l_dbus_message *disconnect_pending;

	struct wiphy *wiphy;
	struct netdev *netdev;
};

uint32_t device_watch_add(device_watch_func_t added,
				device_watch_func_t removed,
				void *userdata, device_destroy_func_t destroy);
bool device_watch_remove(uint32_t id);

void __device_watch_call_added(struct device *device);
void __device_watch_call_removed(struct device *device);

struct network *device_get_connected_network(struct device *device);
const char *device_get_path(struct device *device);
bool device_is_busy(struct device *device);
struct wiphy *device_get_wiphy(struct device *device);
uint32_t device_get_ifindex(struct device *device);
const uint8_t *device_get_address(struct device *device);

void device_enter_state(struct device *device, enum device_state state);
void device_disassociated(struct device *device);
void device_connect_network(struct device *device, struct network *network,
				struct scan_bss *bss,
				struct l_dbus_message *message);

struct device *device_create(struct wiphy *wiphy, struct netdev *netdev);
void device_remove(struct device *device);

bool device_init(void);
bool device_exit(void);
