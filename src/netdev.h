/*
 *
 *  Wireless daemon for Linux
 *
 *  Copyright (C) 2013-2014  Intel Corporation. All rights reserved.
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

struct netdev;

typedef void (*netdev_watch_func_t)(struct netdev *netdev, void *userdata);
typedef void (*netdev_destroy_func_t)(void *userdata);

typedef void (*netdev_command_func_t) (bool result, void *user_data);

enum netdev_state {
	NETDEV_STATE_DISCONNECTED = 0,	/* Disconnected, no auto-connect */
	NETDEV_STATE_AUTOCONNECT,	/* Disconnected, try auto-connect */
	NETDEV_STATE_CONNECTING,	/* Connecting */
	NETDEV_STATE_CONNECTED,
	NETDEV_STATE_DISCONNECTING,
};

void netdev_set_linkmode_and_operstate(uint32_t ifindex,
				uint8_t linkmode, uint8_t operstate,
				netdev_command_func_t cb, void *user_data);

uint32_t netdev_watch_add(netdev_watch_func_t added,
				netdev_watch_func_t removed,
				void *userdata, netdev_destroy_func_t destroy);
bool netdev_watch_remove(uint32_t id);

void __netdev_watch_call_added(struct netdev *netdev);
void __netdev_watch_call_removed(struct netdev *netdev);

uint32_t netdev_get_ifindex(struct netdev *netdev);
const uint8_t *netdev_get_address(struct netdev *netdev);

bool netdev_init(void);
bool netdev_exit(void);
