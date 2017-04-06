/*
 *
 *  Wireless daemon for Linux
 *
 *  Copyright (C) 2017  Intel Corporation. All rights reserved.
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

#include <ell/ell.h>

#include "dbus-proxy.h"
#include "display.h"

#define IWD_SERVICE		"net.connman.iwd"
#define IWD_ROOT_PATH		"/"

static struct l_dbus *dbus;

static struct l_queue *proxy_interfaces;
static struct l_queue *proxy_interface_types;

static bool dbus_message_has_error(struct l_dbus_message *message)
{
	const char *name;
	const char *text;

	if (l_dbus_message_get_error(message, &name, &text)) {
		display_error(text);
		return true;
	}

	return false;
}

static void proxy_interface_create(const char *path,
					struct l_dbus_message_iter *interfaces)
{
}

static void interfaces_added_callback(struct l_dbus_message *message,
								void *user_data)
{
}

static void interfaces_removed_callback(struct l_dbus_message *message,
								void *user_data)
{
}

static void get_managed_objects_callback(struct l_dbus_message *message,
								void *user_data)
{
	struct l_dbus_message_iter objects;
	struct l_dbus_message_iter object;
	const char *path;

	if (dbus_message_has_error(message)) {
		l_error("Failed to retrieve IWD dbus objects");

		return;
	}

	l_dbus_message_get_arguments(message, "a{oa{sa{sv}}}", &objects);

	while (l_dbus_message_iter_next_entry(&objects, &path, &object))
		proxy_interface_create(path, &object);

}

static void service_appeared_callback(struct l_dbus *dbus, void *user_data)
{
	l_dbus_add_signal_watch(dbus, IWD_SERVICE, IWD_ROOT_PATH,
					L_DBUS_INTERFACE_OBJECT_MANAGER,
					"InterfacesAdded", L_DBUS_MATCH_NONE,
					interfaces_added_callback, NULL);

	l_dbus_add_signal_watch(dbus, IWD_SERVICE, IWD_ROOT_PATH,
					L_DBUS_INTERFACE_OBJECT_MANAGER,
					"InterfacesRemoved", L_DBUS_MATCH_NONE,
					interfaces_removed_callback, NULL);

	l_dbus_method_call(dbus, IWD_SERVICE, IWD_ROOT_PATH,
					L_DBUS_INTERFACE_OBJECT_MANAGER,
					"GetManagedObjects", NULL,
					get_managed_objects_callback,
					NULL, NULL);
}

static void service_disappeared_callback(struct l_dbus *dbus,
							void *user_data)
{
}

static void dbus_disconnect_callback(void *user_data)
{
	l_main_quit();
}

static void proxy_interface_destroy(void *data)
{
}

bool dbus_proxy_init(void)
{
	if (dbus)
		return true;

	dbus = l_dbus_new_default(L_DBUS_SYSTEM_BUS);
	if (!dbus)
		return false;

	proxy_interface_types = l_queue_new();
	proxy_interfaces = l_queue_new();

	l_dbus_set_disconnect_handler(dbus, dbus_disconnect_callback, NULL,
									NULL);

	l_dbus_add_service_watch(dbus, IWD_SERVICE, service_appeared_callback,
						service_disappeared_callback,
						NULL, NULL);

	return true;
}

bool dbus_proxy_exit(void)
{
	l_queue_destroy(proxy_interface_types, NULL);
	proxy_interface_types = NULL;

	l_queue_destroy(proxy_interfaces, proxy_interface_destroy);
	proxy_interfaces = NULL;

	l_dbus_destroy(dbus);
	dbus = NULL;

	return true;
}
