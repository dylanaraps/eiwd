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

enum security;
struct scan_bss;
struct wiphy;
struct netdev;
struct device;

enum device_state {
	DEVICE_STATE_OFF = 0,		/* Interface down */
	DEVICE_STATE_DISCONNECTED,	/* Disconnected, no auto-connect */
	DEVICE_STATE_AUTOCONNECT,	/* Disconnected, try auto-connect */
	DEVICE_STATE_CONNECTING,	/* Connecting */
	DEVICE_STATE_CONNECTED,
	DEVICE_STATE_DISCONNECTING,
	DEVICE_STATE_ROAMING
};

typedef void (*device_state_watch_func_t)(enum device_state, void *userdata);
typedef void (*device_destroy_func_t)(void *userdata);

struct network *device_get_connected_network(struct device *device);
const char *device_get_path(struct device *device);
bool device_is_busy(struct device *device);
struct wiphy *device_get_wiphy(struct device *device);
struct netdev *device_get_netdev(struct device *device);
enum device_state device_get_state(struct device *device);

uint32_t device_add_state_watch(struct device *device,
					device_state_watch_func_t func,
					void *user_data,
					device_destroy_func_t destroy);
bool device_remove_state_watch(struct device *device, uint32_t id);

void device_set_scan_results(struct device *device, struct l_queue *bss_list);
struct network *device_network_find(struct device *device, const char *ssid,
					enum security security);

bool device_set_autoconnect(struct device *device, bool autoconnect);
int __device_connect_network(struct device *device, struct network *network,
				struct scan_bss *bss);
void device_connect_network(struct device *device, struct network *network,
				struct scan_bss *bss,
				struct l_dbus_message *message);
int device_disconnect(struct device *device);

struct device *device_create(struct wiphy *wiphy, struct netdev *netdev);
void device_remove(struct device *device);
