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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <ell/ell.h>
#include "src/manager.h"
#include "src/dbus.h"
#include "src/wiphy.h"

static struct l_dbus_message *manager_set_property(struct l_dbus *dbus,
						struct l_dbus_message *message,
						void *user_data)
{
	const char *property;
	struct l_dbus_message_iter variant;

	if (!l_dbus_message_get_arguments(message, "sv", &property, &variant))
		return l_dbus_message_new_error(message,
						"org.test.InvalidArguments",
						"Invalid arguments");

	return l_dbus_message_new_error(message, "org.test.InvalidArguments",
					"Unknown Property %s", property);
}

static struct l_dbus_message *manager_get_properties(struct l_dbus *dbus,
						struct l_dbus_message *message,
						void *user_data)
{
	struct l_dbus_message *reply;

	reply = l_dbus_message_new_method_return(message);
	l_dbus_message_set_arguments(reply, "a{sv}", 0);

	return reply;
}

static void append_device(struct netdev *netdev, void *user_data)
{
	struct l_dbus_message_builder *builder = user_data;

	l_dbus_message_builder_enter_dict(builder, "oa{sv}");
	l_dbus_message_builder_append_basic(builder, 'o',
						iwd_device_get_path(netdev));
	__iwd_device_append_properties(netdev, builder);
	l_dbus_message_builder_leave_dict(builder);
}

static struct l_dbus_message *manager_get_devices(struct l_dbus *dbus,
						struct l_dbus_message *message,
						void *user_data)
{
	struct l_dbus_message *reply;
	struct l_dbus_message_builder *builder;

	reply = l_dbus_message_new_method_return(message);
	builder = l_dbus_message_builder_new(reply);

	l_dbus_message_builder_enter_array(builder, "{oa{sv}}");
	__iwd_device_foreach(append_device, builder);
	l_dbus_message_builder_leave_array(builder);

	l_dbus_message_builder_finalize(builder);
	l_dbus_message_builder_destroy(builder);

	return reply;
}

static void setup_manager_interface(struct l_dbus_interface *interface)
{
	l_dbus_interface_method(interface, "GetProperties", 0,
				manager_get_properties,
				"a{sv}", "", "properties");
	l_dbus_interface_method(interface, "SetProperty", 0,
				manager_set_property,
				"", "sv", "name", "value");

	l_dbus_interface_method(interface, "GetDevices", 0,
				manager_get_devices,
				"a{oa{sv}}", "", "devices");

	l_dbus_interface_signal(interface, "PropertyChanged", 0,
				"sv", "name", "value");
	l_dbus_interface_signal(interface, "DeviceAdded", 0,
				"oa{sv}", "path", "properties");
	l_dbus_interface_signal(interface, "DeviceRemoved", 0,
				"o", "path");
}

bool manager_init(struct l_dbus *dbus)
{
	if (!l_dbus_register_interface(dbus, IWD_MANAGER_PATH,
					IWD_MANAGER_INTERFACE,
					setup_manager_interface, NULL, NULL)) {
		l_info("Unable to register %s interface",
				IWD_MANAGER_INTERFACE);
		return false;
	}

	return true;
}

bool manager_exit(struct l_dbus *dbus)
{
	l_dbus_unregister_interface(dbus, IWD_MANAGER_PATH,
					IWD_MANAGER_INTERFACE);

	return true;
}
