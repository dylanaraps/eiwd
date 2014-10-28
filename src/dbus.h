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

#define IWD_MANAGER_INTERFACE "net.connman.iwd.Manager"
#define IWD_DEVICE_INTERFACE "net.connman.iwd.Device"

#define IWD_MANAGER_PATH "/"

struct l_dbus;

struct l_dbus *dbus_get_bus(void);

void dbus_pending_reply(struct l_dbus_message **msg,
				struct l_dbus_message *reply);

void dbus_dict_append_string(struct l_dbus_message_builder *builder,
				const char *key, const char *strval);
void dbus_dict_append_bool(struct l_dbus_message_builder *builder,
				const char *key, bool boolval);

bool dbus_init(void);
bool dbus_exit(void);
