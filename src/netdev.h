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
struct scan_bss;
struct eapol_sm *sm;

enum netdev_result {
	NETDEV_RESULT_OK,
	NETDEV_RESULT_AUTHENTICATION_FAILED,
	NETDEV_RESULT_ASSOCIATION_FAILED,
	NETDEV_RESULT_HANDSHAKE_FAILED,
	NETDEV_RESULT_KEY_SETTING_FAILED,
};

enum netdev_event {
	NETDEV_EVENT_AUTHENTICATING,
	NETDEV_EVENT_ASSOCIATING,
	NETDEV_EVENT_4WAY_HANDSHAKE,
	NETDEV_EVENT_SETTING_KEYS,
	NETDEV_EVENT_LOST_BEACON,
};

typedef void (*netdev_command_func_t) (bool result, void *user_data);
typedef void (*netdev_connect_cb_t)(struct netdev *netdev,
					enum netdev_result result,
					void *user_data);
typedef void (*netdev_event_func_t)(struct netdev *netdev,
					enum netdev_event event,
					void *user_data);

void netdev_set_linkmode_and_operstate(uint32_t ifindex,
				uint8_t linkmode, uint8_t operstate,
				netdev_command_func_t cb, void *user_data);

const uint8_t *netdev_get_address(struct netdev *netdev);
uint32_t netdev_get_ifindex(struct netdev *netdev);
uint32_t netdev_get_iftype(struct netdev *netdev);
const char *netdev_get_name(struct netdev *netdev);

int netdev_connect(struct netdev *netdev, struct scan_bss *bss,
				struct eapol_sm *sm,
				netdev_event_func_t event_filter,
				netdev_connect_cb_t cb, void *user_data);

struct netdev *netdev_find(int ifindex);

bool netdev_init(struct l_genl_family *in);
bool netdev_exit(void);
