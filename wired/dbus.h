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

struct l_dbus *dbus_app_get(void);

typedef void (*dbus_app_destroy_func_t) (void *user_data);

struct dbus_app {
	enum l_dbus_bus bus;
	const char *name;
	void (*ready) (struct l_dbus *dbus, void *user_data);
	void (*shutdown) (struct l_dbus *dbus, void *user_data);
};

void dbus_app_shutdown_complete(void);

int dbus_app_run(const struct dbus_app *app, void *user_data,
					dbus_app_destroy_func_t destroy);
