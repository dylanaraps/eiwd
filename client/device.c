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
#include "display.h"
#include "network.h"

struct device {
	bool powered;
	bool scanning;
	char *address;
	char *name;
	char *state;
	struct l_queue *ordered_networks;
	const struct proxy_interface *adapter;
	const struct proxy_interface *connected_network;
	const struct proxy_interface *properties;
	const struct proxy_interface *wsc;
};

static void display_device(const struct device *device)
{
}

static const char *get_name(const void *data)
{
	const struct device *device = data;

	return device->name;
}

static void set_name(void *data, struct l_dbus_message_iter *variant)
{
	struct device *device = data;
	const char *value;

	l_free(device->name);

	if (!l_dbus_message_iter_get_variant(variant, "s", &value)) {
		device->name = NULL;

		return;
	}

	device->name = l_strdup(value);
}

static const char *get_address(const void *data)
{
	const struct device *device = data;

	return device->address;
}

static void set_address(void *data, struct l_dbus_message_iter *variant)
{
	struct device *device = data;
	const char *value;

	l_free(device->address);

	if (!l_dbus_message_iter_get_variant(variant, "s", &value)) {
		device->address = NULL;

		return;
	}

	device->address = l_strdup(value);
}

static const char *get_state(const void *data)
{
	const struct device *device = data;

	return device->state;
}

static void set_state(void *data, struct l_dbus_message_iter *variant)
{
	struct device *device = data;
	const char *value;

	l_free(device->state);

	if (!l_dbus_message_iter_get_variant(variant, "s", &value)) {
		device->state = NULL;

		return;
	}

	device->state = l_strdup(value);
}

static void set_connected_network(void *data,
					struct l_dbus_message_iter *variant)
{
	struct device *device = data;
	const char *path;

	if (!l_dbus_message_iter_get_variant(variant, "o", &path)) {
		device->connected_network = NULL;

		return;
	}

	device->connected_network = proxy_interface_find(IWD_NETWORK_INTERFACE,
									path);
}

static const char *get_powered_tostr(const void *data)
{
	const struct device *device = data;

	return device->powered ? "yes" : "no";
}

static void set_powered(void *data, struct l_dbus_message_iter *variant)
{
	struct device *device = data;
	bool value;

	if (!l_dbus_message_iter_get_variant(variant, "b", &value)) {
		device->powered = false;

		return;
	}

	device->powered = value;
}

static const char *get_scanning_tostr(const void *data)
{
	const struct device *device = data;

	return device->scanning ? "scanning" : "";
}

static void set_scanning(void *data, struct l_dbus_message_iter *variant)
{
	struct device *device = data;
	bool value;

	if (!l_dbus_message_iter_get_variant(variant, "b", &value)) {
		device->scanning = false;

		return;
	}

	device->scanning = value;
}

static void set_adapter(void *data, struct l_dbus_message_iter *variant)
{
	struct device *device = data;
	const char *path;

	if (!l_dbus_message_iter_get_variant(variant, "o", &path)) {
		device->adapter = NULL;

		return;
	}

	device->adapter = proxy_interface_find(IWD_ADAPTER_INTERFACE, path);
}

static const struct proxy_interface_property device_properties[] = {
	{ "Name",     "s", set_name,     get_name },
	{ "Powered",  "b", set_powered,  get_powered_tostr, true },
	{ "Adapter",  "o", set_adapter },
	{ "Address",  "s", set_address,  get_address },
	{ "Scanning", "b", set_scanning, get_scanning_tostr },
	{ "State",    "s", set_state,    get_state },
	{ "ConnectedNetwork",
			"o", set_connected_network },
	{ }
};

struct ordered_network {
	char *network_path;
	char *name;
	int16_t signal_strength;
	char *type;
};

static void ordered_networks_destroy(void *data)
{
	struct ordered_network *network = data;

	l_free(network->name);
	l_free(network->network_path);
	l_free(network->type);

	l_free(network);
}

static void ordered_networks_display(struct l_queue *ordered_networks)
{
}

static void ordered_networks_callback(struct l_dbus_message *message,
								void *proxy)
{
	struct device *device = proxy_interface_get_data(proxy);
	struct l_queue *networks = NULL;
	struct ordered_network network;
	struct l_dbus_message_iter iter;

	if (dbus_message_has_error(message))
		return;

	if (!l_dbus_message_get_arguments(message, "a(osns)", &iter)) {
		l_error("Failed to parse ordered networks callback message");

		return;
	}

	l_queue_destroy(device->ordered_networks, ordered_networks_destroy);

	while (l_dbus_message_iter_next_entry(&iter,
						&network.network_path,
						&network.name,
						&network.signal_strength,
						&network.type)) {
		struct ordered_network *net = l_new(struct ordered_network, 1);

		if (!networks)
			networks = l_queue_new();

		net->name = l_strdup(network.name);
		net->network_path = l_strdup(network.network_path);
		net->signal_strength = network.signal_strength;
		net->type = l_strdup(network.type);

		l_queue_push_tail(networks, net);
	}

	device->ordered_networks = networks;

	ordered_networks_display(networks);
}

static void *device_create(void)
{
	return l_new(struct device, 1);
}

static void device_destroy(void *data)
{
	struct device *device = data;

	l_free(device->address);
	l_free(device->name);
	l_free(device->state);

	l_queue_destroy(device->ordered_networks, ordered_networks_destroy);

	device->adapter = NULL;
	device->connected_network = NULL;
	device->properties = NULL;
	device->wsc = NULL;

	l_free(device);
}

static bool device_bind_interface(const struct proxy_interface *proxy,
				const struct proxy_interface *dependency)
{
	return true;
}

static bool device_unbind_interface(const struct proxy_interface *proxy,
				const struct proxy_interface *dependency)
{
	return true;
}

static void display_device_inline(const char *margin, const void *data)
{
	const struct device *device = data;

	display("%s%-*s%-*s%-*s%-*s%-*s\n", margin,
		20, device->name ? : "",
		20, device->address ? : "",
		15, device->state ? : "",
		10, proxy_interface_get_identity_str(device->adapter) ? : "-",
		8, device->scanning ? "scanning" : "");
}

static const char *device_identity(void *data)
{
	const struct device *device = data;

	return device->name;
}

static const struct proxy_interface_type_ops device_ops = {
	.create = device_create,
	.destroy = device_destroy,
	.bind_interface = device_bind_interface,
	.unbind_interface = device_unbind_interface,
	.identity = device_identity,
	.display = display_device_inline,
};

static struct proxy_interface_type device_interface_type = {
	.interface = IWD_DEVICE_INTERFACE,
	.properties = device_properties,
	.ops = &device_ops,
};

static bool match_by_name(const void *a, const void *b)
{
	const struct device *device = a;
	const char *name = b;

	return !strcmp(device->name, name);
}

static bool match_by_partial_name(const void *a, const void *b)
{
	const struct device *device = a;
	const char *text = b;

	return !strncmp(device->name, text, strlen(text));
}

static const struct proxy_interface *get_device_proxy_by_name(
							const char *device_name)
{
	struct l_queue *match;
	struct proxy_interface *proxy = NULL;

	if (!device_name)
		return NULL;

	match = proxy_interface_find_all(device_interface_type.interface,
						match_by_name, device_name);

	if (l_queue_length(match))
		proxy = l_queue_pop_head(match);
	else
		display("Device %s not found", device_name);

	l_queue_destroy(match, NULL);

	return proxy;
}

static enum cmd_status cmd_show(const char *device_name, char *args)
{
	struct device *device;
	const struct proxy_interface *proxy =
					get_device_proxy_by_name(device_name);

	if (!proxy)
		return CMD_STATUS_INVALID_ARGS;

	device = proxy_interface_get_data(proxy);

	display_device(device);

	return CMD_STATUS_OK;
}

static void check_errors_method_callback(struct l_dbus_message *message,
								void *user_data)
{
	dbus_message_has_error(message);
}

static enum cmd_status cmd_scan(const char *device_name, char *args)
{
	const struct proxy_interface *proxy =
					get_device_proxy_by_name(device_name);

	if (!proxy)
		return CMD_STATUS_INVALID_ARGS;

	proxy_interface_method_call(proxy, "Scan", "",
						check_errors_method_callback);

	return CMD_STATUS_OK;
}

static enum cmd_status cmd_disconnect(const char *device_name, char *args)
{
	const struct proxy_interface *proxy =
					get_device_proxy_by_name(device_name);

	if (!proxy)
		return CMD_STATUS_INVALID_ARGS;

	proxy_interface_method_call(proxy, "Disconnect", "",
						check_errors_method_callback);

	return CMD_STATUS_OK;
}

static enum cmd_status cmd_get_networks(const char *device_name, char *args)
{
	const struct proxy_interface *proxy =
					get_device_proxy_by_name(device_name);

	if (!proxy)
		return CMD_STATUS_INVALID_ARGS;

	proxy_interface_method_call(proxy, "GetOrderedNetworks", "",
					ordered_networks_callback);

	return CMD_STATUS_OK;
}

static enum cmd_status cmd_list(const char *device_name, char *args)
{
	display_table_header("Devices", MARGIN "%-*s%-*s%-*s%-*s", 20, "Name",
				20, "Address", 15, "State", 10, "Adapter");

	proxy_interface_display_list(device_interface_type.interface);

	display_table_footer();

	return CMD_STATUS_OK;
}

static enum cmd_status cmd_set_property(const char *device_name, char *args)
{
	return CMD_STATUS_UNSUPPORTED;
}

static enum cmd_status cmd_connect(const char *device_name, char *args)
{
	char **arg_arr;
	const char *network_name;
	const char *network_type;
	struct l_queue *match;
	const struct device *device;
	const struct l_queue_entry *entry;
	struct ordered_network *ordered_network;
	const struct proxy_interface *proxy =
					get_device_proxy_by_name(device_name);

	if (!proxy)
		return CMD_STATUS_INVALID_VALUE;

	arg_arr = l_strsplit(args, ' ');
	if (!arg_arr || !arg_arr[0]) {
		l_strfreev(arg_arr);

		return CMD_STATUS_INVALID_ARGS;
	}

	device = proxy_interface_get_data(proxy);

	if (!device->ordered_networks) {
		display("Use 'get-networks' command to obtain a list of "
						"available networks first\n");
		l_strfreev(arg_arr);

		return CMD_STATUS_OK;
	}

	network_name = arg_arr[0];
	match = NULL;

	for (entry = l_queue_get_entries(device->ordered_networks); entry;
							entry = entry->next) {
		ordered_network = entry->data;

		if (strcmp(ordered_network->name, network_name))
			continue;

		if (!match)
			match = l_queue_new();

		l_queue_push_tail(match, ordered_network);
	}

	if (!match) {
		display("Invalid network name '%s'\n", network_name);
		l_strfreev(arg_arr);

		return CMD_STATUS_INVALID_VALUE;
	}

	if (l_queue_length(match) > 1) {
		if (!arg_arr[1]) {
			display("Provided network name is ambiguous. "
				"Please specify security type.\n");

			l_queue_destroy(match, NULL);
			l_strfreev(arg_arr);

			return CMD_STATUS_INVALID_VALUE;
		}

		network_type = arg_arr[1];
		ordered_network = NULL;

		for (entry = l_queue_get_entries(match); entry;
							entry = entry->next) {
			ordered_network = entry->data;

			if (!strcmp(ordered_network->type, network_type))
				break;
		}
	} else {
		ordered_network = l_queue_pop_head(match);
	}

	l_queue_destroy(match, NULL);
	l_strfreev(arg_arr);

	if (!ordered_network) {
		display("No network with specified parameters was found\n");

		return CMD_STATUS_INVALID_VALUE;
	}

	network_connect(ordered_network->network_path);

	return CMD_STATUS_OK;
}

static const struct command device_commands[] = {
	{ NULL,     "list",     NULL,   cmd_list, "List devices",     true },
	{ "<wlan>", "show",     NULL,   cmd_show, "Show device info", true },
	{ "<wlan>", "scan",     NULL,   cmd_scan, "Scan for networks" },
	{ "<wlan>", "get-networks",
				NULL,   cmd_get_networks,
						"Get networks",       true },
	{ "<wlan>", "set-property",
				"<name> <value>",
					cmd_set_property,
						"Set property",       false },
	{ "<wlan>", "connect",
				"<network name> [security]",
					cmd_connect,
						"Connect to network", false },
	{ "<wlan>", "disconnect",
				NULL,   cmd_disconnect, "Disconnect" },
	{ }
};

static char *family_arg_completion(const char *text, int state)
{
	static bool first_pass;
	static size_t index;
	static size_t len;
	const char *cmd;

	if (!state) {
		index = 0;
		len = strlen(text);
		first_pass = true;
	}

	while ((cmd = device_commands[index].cmd)) {
		if (device_commands[index++].entity)
			continue;

		if (!strncmp(cmd, text, len))
			return l_strdup(cmd);
	}

	if (first_pass) {
		state = 0;
		first_pass = false;
	}

	return proxy_property_str_completion(&device_interface_type,
						match_by_partial_name, "Name",
						text, state);
}

static char *entity_arg_completion(const char *text, int state)
{
	return command_entity_arg_completion(text, state, device_commands);
}

static struct command_family device_command_family = {
	.caption = "Devices",
	.name = "device",
	.command_list = device_commands,
	.family_arg_completion = family_arg_completion,
	.entity_arg_completion = entity_arg_completion,
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
