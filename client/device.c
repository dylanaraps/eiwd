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

#include "command.h"
#include "dbus-proxy.h"

struct device {
	bool powered;
	bool scanning;
	char *address;
	char *name;
	char *state;
	const struct proxy_interface *adapter;
	const struct proxy_interface *connected_network;
};

static const void *get_name(const void *data)
{
	const struct device *device = data;

	return device->name;
}

static void set_name(void *data, const void *value)
{
	struct device *device = data;

	l_free(device->name);

	if (value)
		device->name = l_strdup(value);
}

static const void *get_address(const void *data)
{
	const struct device *device = data;

	return device->address;
}

static void set_address(void *data, const void *value)
{
	struct device *device = data;

	l_free(device->address);

	if (value)
		device->address = l_strdup(value);
}

static const void *get_state(const void *data)
{
	const struct device *device = data;

	return device->state;
}

static void set_state(void *data, const void *value)
{
	struct device *device = data;

	l_free(device->state);

	if (value)
		device->state = l_strdup(value);
}

static void set_connected_network(void *data, const void *value)
{
	struct device *device = data;
	const char *path = value;

	device->connected_network = proxy_interface_find(IWD_NETWORK_INTERFACE,
									path);
}

static const void *get_powered(const void *data)
{
	const struct device *device = data;
	void *ptr;

	l_put_u8(device->powered, &ptr);

	return ptr;
}

static void set_powered(void *data, const void *value)
{
	struct device *device = data;

	if (value)
		device->powered = l_get_u8(&value);
	else
		device->powered = false;
}

static const void *get_scanning(const void *data)
{
	const struct device *device = data;
	void *ptr;

	l_put_u8(device->scanning, &ptr);

	return ptr;
}

static void set_scanning(void *data, const void *value)
{
	struct device *device = data;

	if (value)
		device->scanning = l_get_u8(&value);
	else
		device->scanning = false;
}

static void set_adapter(void *data, const void *value)
{
	struct device *device = data;
	const char *path = value;

	device->adapter = proxy_interface_find(IWD_ADAPTER_INTERFACE, path);
}

static const struct proxy_interface_property device_properties[] = {
	{ "Name",     "s", set_name,     get_name },
	{ "Powered",  "b", set_powered,  get_powered, true },
	{ "Adapter",  "o", set_adapter },
	{ "Address",  "s", set_address,  get_address },
	{ "Scanning", "b", set_scanning, get_scanning },
	{ "State",    "s", set_state,    get_state },
	{ "ConnectedNetwork",
			"o", set_connected_network },
	{ }
};

static struct proxy_interface_type device_interface_type = {
	.interface = IWD_DEVICE_INTERFACE,
	.properties = device_properties,
};

static struct command_family device_command_family = {
	.caption = "Devices",
	.name = "device",
};

static int device_command_family_init(void)
{
	command_family_register(&device_command_family);

	return 0;
}

static void device_command_family_exit(void)
{
	command_family_unregister(&device_command_family);
}

COMMAND_FAMILY(device_command_family, device_command_family_init,
						device_command_family_exit)

static int device_interface_init(void)
{
	proxy_interface_type_register(&device_interface_type);

	return 0;
}

static void device_interface_exit(void)
{
	proxy_interface_type_register(&device_interface_type);
}

INTERFACE_TYPE(device_interface_type, device_interface_init,
						device_interface_exit)
