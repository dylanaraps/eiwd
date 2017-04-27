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

struct adapter {
	bool powered;
	char *model;
	char *name;
	char *vendor;
};

static const char *get_name(const void *data)
{
	const struct adapter *adapter = data;

	return adapter->name;
}

static void set_name(void *data, struct l_dbus_message_iter *variant)
{
	struct adapter *adapter = data;
	const char *value;

	l_free(adapter->name);

	if (!l_dbus_message_iter_get_variant(variant, "s", &value)) {
		adapter->name = NULL;

		return;
	}

	adapter->name = l_strdup(value);
}

static void set_vendor(void *data, struct l_dbus_message_iter *variant)
{
	struct adapter *adapter = data;
	const char *value;

	l_free(adapter->vendor);

	if (!l_dbus_message_iter_get_variant(variant, "s", &value)) {
		adapter->vendor = NULL;

		return;
	}

	adapter->vendor = l_strdup(value);
}

static void set_model(void *data, struct l_dbus_message_iter *variant)
{
	struct adapter *adapter = data;
	const char *value;

	l_free(adapter->model);

	if (!l_dbus_message_iter_get_variant(variant, "s", &value)) {
		adapter->model = NULL;

		return;
	}

	adapter->model = l_strdup(value);
}

static const char *get_powered_tostr(const void *data)
{
	const struct adapter *adapter = data;

	return adapter->powered ? "on" : "off";
}

static void set_powered(void *data, struct l_dbus_message_iter *variant)
{
	struct adapter *adapter = data;
	bool value;

	if (!l_dbus_message_iter_get_variant(variant, "b", &value)) {
		adapter->powered = false;

		return;
	}

	adapter->powered = value;
}

static const struct proxy_interface_property adapter_properties[] = {
	{ "Name",     "s", set_name,     get_name },
	{ "Powered",  "b", set_powered,  get_powered_tostr, true },
	{ "Vendor",   "s", set_vendor },
	{ "Model",    "s", set_model },
	{ }
};

static struct proxy_interface_type adapter_interface_type = {
	.interface = IWD_ADAPTER_INTERFACE,
	.properties = adapter_properties,
};

static const struct command adapter_commands[] = {
	{ }
};

static struct command_family adapter_command_family = {
	.caption = "Adapters",
	.name = "adapter",
	.command_list = adapter_commands,
};

static int adapter_command_family_init(void)
{
	command_family_register(&adapter_command_family);

	return 0;
}

static void adapter_command_family_exit(void)
{
	command_family_unregister(&adapter_command_family);
}

COMMAND_FAMILY(adapter_command_family, adapter_command_family_init,
						adapter_command_family_exit)

static int adapter_interface_init(void)
{
	proxy_interface_type_register(&adapter_interface_type);

	return 0;
}

static void adapter_interface_exit(void)
{
	proxy_interface_type_register(&adapter_interface_type);
}

INTERFACE_TYPE(adapter_interface_type, adapter_interface_init,
						adapter_interface_exit)
