/*
 *
 *  Ethernet daemon for Linux
 *
 *  Copyright (C) 2017-2018  Intel Corporation. All rights reserved.
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

enum l_dbus_bus;
struct l_dbus;

struct l_dbus *dbus_get(void);

typedef void (*dbus_ready_func_t) (struct l_dbus *dbus, void *user_data);
typedef void (*dbus_shutdown_func_t) (struct l_dbus *dbus, void *user_data);

typedef void (*dbus_destroy_func_t) (void *user_data);

int dbus_run(enum l_dbus_bus bus, const char *name,
					dbus_ready_func_t ready_func,
					dbus_shutdown_func_t shutdown_func,
					void *user_data,
					dbus_destroy_func_t destroy);
