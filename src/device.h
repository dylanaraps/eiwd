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

struct netdev;

typedef void (*device_watch_func_t)(struct netdev *device, void *userdata);
typedef void (*device_destroy_func_t)(void *userdata);

uint32_t device_watch_add(device_watch_func_t added,
				device_watch_func_t removed,
				void *userdata, device_destroy_func_t destroy);
bool device_watch_remove(uint32_t id);

void __device_watch_call_added(struct netdev *device);
void __device_watch_call_removed(struct netdev *device);

struct network *device_get_connected_network(struct netdev *device);
const char *device_get_path(struct netdev *device);

bool device_init(void);
bool device_exit(void);
