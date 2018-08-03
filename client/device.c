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
#include "device.h"
#include "display.h"
#include "network.h"
#include "properties.h"

struct device {
	bool powered;
	bool scanning;
	bool wds;
	char *address;
	char *name;
	char *state;
	char *mode;
	const struct proxy_interface *adapter;
	const struct proxy_interface *connected_network;
	const struct proxy_interface *wsc;
	const struct proxy_interface *ap;
	const struct proxy_interface *ad_hoc;
};

static struct proxy_interface *default_device;

static void display_device(const struct proxy_interface *proxy)
{
	const struct device *device = proxy_interface_get_data(proxy);
	char *caption = l_strdup_printf("%s: %s", "Device", device->name);

	proxy_properties_display(proxy, caption, MARGIN, 20, 47);

	l_free(caption);

	if (device->connected_network) {
		display("%s%*s  %-*s%-*s\n", MARGIN, 8, "",
			20, "Connected network",
			47, proxy_interface_get_identity_str(
					device->connected_network) ? : "");
	}

	if (device->adapter) {
		display("%s%*s  %-*s%-*s\n", MARGIN, 8, "", 20, "Adapter", 47,
			proxy_interface_get_identity_str(
						device->adapter) ? : "");
	}

	display_table_footer();
}

static const char *get_name(const void *data)
{
	const struct device *device = data;

	return device->name;
}

static void update_name(void *data, struct l_dbus_message_iter *variant)
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

static const struct property_value_options device_mode_opts[] = {
	{ "ad-hoc",  (void *) "ad-hoc" },
	{ "ap",      (void *) "ap" },
	{ "station", (void *) "station" },
	{ }
};

static const char *get_mode(const void *data)
{
	const struct device *device = data;

	return device->mode;
}

static void update_mode(void *data, struct l_dbus_message_iter *variant)
{
	struct device *device = data;
	const char *value;

	l_free(device->mode);

	if (!l_dbus_message_iter_get_variant(variant, "s", &value)) {
		device->mode = NULL;

		return;
	}

	device->mode = l_strdup(value);
}

static bool builder_append_string_variant(
					struct l_dbus_message_builder *builder,
					const char *value_str)
{
	return l_dbus_message_builder_append_basic(builder, 's', value_str);
}

static const char *get_address(const void *data)
{
	const struct device *device = data;

	return device->address;
}

static void update_address(void *data, struct l_dbus_message_iter *variant)
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

static void update_state(void *data, struct l_dbus_message_iter *variant)
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

static void update_connected_network(void *data,
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

	return device->powered ? "on" : "off";
}

static void update_powered(void *data, struct l_dbus_message_iter *variant)
{
	struct device *device = data;
	bool value;

	if (!l_dbus_message_iter_get_variant(variant, "b", &value)) {
		device->powered = false;

		return;
	}

	device->powered = value;
}

static const char *get_wds_tostr(const void *data)
{
	const struct device *device = data;

	return device->wds ? "on" : "off";
}

static void update_wds(void *data, struct l_dbus_message_iter *variant)
{
	struct device *device = data;
	bool value;

	if (!l_dbus_message_iter_get_variant(variant, "b", &value)) {
		device->wds = false;

		return;
	}

	device->wds = value;
}

static const char *get_scanning_tostr(const void *data)
{
	const struct device *device = data;

	return device->scanning ? "yes" : "no";
}

static void update_scanning(void *data, struct l_dbus_message_iter *variant)
{
	struct device *device = data;
	bool value;

	if (!l_dbus_message_iter_get_variant(variant, "b", &value)) {
		device->scanning = false;

		return;
	}

	device->scanning = value;
}

static void update_adapter(void *data, struct l_dbus_message_iter *variant)
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
	{ "Name",     "s", update_name,     get_name },
	{ "Mode",     "s", update_mode,     get_mode,          true,
		builder_append_string_variant, device_mode_opts },
	{ "Powered",  "b", update_powered,  get_powered_tostr, true,
		properties_builder_append_on_off_variant,
		properties_on_off_opts },
	{ "Adapter",  "o", update_adapter },
	{ "Address",  "s", update_address,  get_address },
	{ "WDS",      "b", update_wds,      get_wds_tostr,     true,
		properties_builder_append_on_off_variant,
		properties_on_off_opts },
	{ "Scanning", "b", update_scanning, get_scanning_tostr },
	{ "State",    "s", update_state,    get_state },
	{ "ConnectedNetwork",
			"o", update_connected_network },
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

static const char *dbms_tostars(int16_t dbms)
{
	if (dbms >= -6000)
		return "****";

	if (dbms >= -6700)
		return "***" COLOR_BOLDGRAY "*" COLOR_OFF;

	if (dbms >= -7500)
		return "**" COLOR_BOLDGRAY "**" COLOR_OFF;

	return "*" COLOR_BOLDGRAY "***" COLOR_OFF;
}

#define RSSI_DBMS "rssi-dbms"
#define RSSI_BARS "rssi-bars"

static const struct {
	const char *option;
} ordered_networks_arg_options[] = {
	{ RSSI_DBMS },
	{ RSSI_BARS },
	{ }
};

static bool display_signal_as_dbms;

static void ordered_networks_display(struct l_queue *ordered_networks)
{
	char *dbms = NULL;
	const struct l_queue_entry *entry;
	bool is_first;

	display_table_header("Available networks", "%s%-*s%-*s%-*s%*s",
					MARGIN, 2, "", 32, "Network name",
					10, "Security", 6, "Signal");

	if (!l_queue_length(ordered_networks)) {
		display("No networks available\n");
		display_table_footer();

		return;
	}

	for (is_first = true, entry = l_queue_get_entries(ordered_networks);
						entry; entry = entry->next) {
		struct ordered_network *network = entry->data;

		if (display_signal_as_dbms)
			dbms = l_strdup_printf("%d", network->signal_strength);

		if (is_first && network_is_connected(network->network_path)) {
			display("%s%-*s%-*s%-*s%-*s\n", MARGIN,
				2, COLOR_BOLDGRAY "> " COLOR_OFF,
				32, network->name, 10, network->type,
				6, display_signal_as_dbms ? dbms :
					dbms_tostars(network->signal_strength));

			l_free(dbms);
			is_first = false;
			continue;
		}

		display("%s%-*s%-*s%-*s%-*s\n", MARGIN, 2, "",
				32, network->name, 10, network->type,
				6, display_signal_as_dbms ? dbms :
					dbms_tostars(network->signal_strength));

		l_free(dbms);
	}

	display_table_footer();
}

static void ordered_networks_callback(struct l_dbus_message *message,
								void *proxy)
{
	struct l_queue *networks = NULL;
	struct ordered_network network;
	struct l_dbus_message_iter iter;

	if (dbus_message_has_error(message))
		return;

	if (!l_dbus_message_get_arguments(message, "a(osns)", &iter)) {
		l_error("Failed to parse ordered networks callback message");

		return;
	}

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

	ordered_networks_display(networks);

	l_queue_destroy(networks, ordered_networks_destroy);
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
	l_free(device->mode);

	device->adapter = NULL;
	device->connected_network = NULL;
	device->wsc = NULL;

	l_free(device);
}

static bool device_bind_interface(const struct proxy_interface *proxy,
				const struct proxy_interface *dependency)
{
	const char *interface = proxy_interface_get_interface(dependency);

	if (!strcmp(interface, IWD_WSC_INTERFACE)) {
		struct device *device = proxy_interface_get_data(proxy);

		device->wsc = dependency;

		return true;
	} else if (!strcmp(interface, IWD_ACCESS_POINT_INTERFACE)) {
		struct device *device = proxy_interface_get_data(proxy);

		device->ap = dependency;

		return true;
	} else if (!strcmp(interface, IWD_AD_HOC_INTERFACE)) {
		struct device *device = proxy_interface_get_data(proxy);

		device->ad_hoc = dependency;

		return true;
	}

	return false;
}

static bool device_unbind_interface(const struct proxy_interface *proxy,
				const struct proxy_interface *dependency)
{
	const char *interface = proxy_interface_get_interface(dependency);

	if (!strcmp(interface, IWD_WSC_INTERFACE)) {
		struct device *device = proxy_interface_get_data(proxy);

		device->wsc = NULL;

		return true;
	} else if (!strcmp(interface, IWD_ACCESS_POINT_INTERFACE)) {
		struct device *device = proxy_interface_get_data(proxy);

		device->ap = NULL;

		return true;
	} else if (!strcmp(interface, IWD_AD_HOC_INTERFACE)) {
		struct device *device = proxy_interface_get_data(proxy);

		device->ad_hoc = NULL;

		return true;
	}

	return false;
}

static void display_device_inline(const char *margin, const void *data)
{
	const struct device *device = data;
	const char *adapter_str;

	if (device->adapter &&
			proxy_interface_get_identity_str(device->adapter))
		adapter_str = proxy_interface_get_identity_str(device->adapter);
	else
		adapter_str = "-";

	display("%s%-*s%-*s%-*s%-*s%-*s\n", margin,
		20, device->name ? : "",
		20, device->address ? : "",
		15, device->state ? : "",
		10, adapter_str,
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

static bool match_by_partial_name_and_wsc(const void *a, const void *b)
{
	const struct device *device = a;

	return match_by_partial_name(a, b) && device->wsc ? true : false;
}

static bool match_by_partial_name_and_ap(const void *a, const void *b)
{
	const struct device *device = a;

	return match_by_partial_name(a, b) && device->ap ? true : false;
}

static bool match_by_partial_name_and_ad_hoc(const void *a, const void *b)
{
	const struct device *device = a;

	return match_by_partial_name(a, b) && device->ad_hoc ? true : false;
}

static bool match_all(const void *a, const void *b)
{
	return true;
}

static void device_set_default(const char *device_name)
{
	struct l_queue *match;

	if (!device_name)
		return;

	match = proxy_interface_find_all(device_interface_type.interface,
						match_by_name, device_name);

	if (!match)
		return;

	default_device = l_queue_pop_head(match);
	l_queue_destroy(match, NULL);
}

static const struct proxy_interface *device_get_default(void)
{
	struct l_queue *match;

	if (default_device)
		return default_device;

	match = proxy_interface_find_all(device_interface_type.interface,
							match_all, NULL);

	if (!match)
		return NULL;

	default_device = l_queue_pop_head(match);
	l_queue_destroy(match, NULL);

	return default_device;
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
		display("Device %s not found.\n", device_name);

	l_queue_destroy(match, NULL);

	return proxy;
}

static enum cmd_status cmd_show(const char *device_name,
						char **argv, int argc)
{
	const struct proxy_interface *proxy =
					get_device_proxy_by_name(device_name);

	if (!proxy)
		return CMD_STATUS_INVALID_ARGS;

	display_device(proxy);

	return CMD_STATUS_OK;
}

static void check_errors_method_callback(struct l_dbus_message *message,
								void *user_data)
{
	dbus_message_has_error(message);
}

static enum cmd_status cmd_scan(const char *device_name,
						char **argv, int argc)
{
	const struct proxy_interface *proxy =
					get_device_proxy_by_name(device_name);

	if (!proxy)
		return CMD_STATUS_INVALID_ARGS;

	proxy_interface_method_call(proxy, "Scan", "",
						check_errors_method_callback);

	return CMD_STATUS_OK;
}

static enum cmd_status cmd_disconnect(const char *device_name,
						char **argv, int argc)
{
	const struct proxy_interface *proxy =
					get_device_proxy_by_name(device_name);

	if (!proxy)
		return CMD_STATUS_INVALID_ARGS;

	proxy_interface_method_call(proxy, "Disconnect", "",
						check_errors_method_callback);

	return CMD_STATUS_OK;
}

static enum cmd_status cmd_get_networks(const char *device_name,
						char **argv, int argc)
{
	const struct proxy_interface *proxy =
					get_device_proxy_by_name(device_name);

	if (!proxy)
		return CMD_STATUS_INVALID_ARGS;

	if (!argc)
		goto proceed;

	if (!strcmp(argv[0], RSSI_DBMS))
		display_signal_as_dbms = true;
	else
		display_signal_as_dbms = false;

proceed:
	proxy_interface_method_call(proxy, "GetOrderedNetworks", "",
					ordered_networks_callback);

	return CMD_STATUS_OK;
}

static enum cmd_status cmd_list(const char *device_name,
						char **argv, int argc)
{
	display_table_header("Devices", MARGIN "%-*s%-*s%-*s%-*s", 20, "Name",
				20, "Address", 15, "State", 10, "Adapter");

	proxy_interface_display_list(device_interface_type.interface);

	display_table_footer();

	return CMD_STATUS_OK;
}

static enum cmd_status cmd_set_property(const char *device_name,
						char **argv, int argc)
{
	const struct proxy_interface *proxy =
					get_device_proxy_by_name(device_name);

	if (!proxy)
		return CMD_STATUS_INVALID_VALUE;

	if (argc != 2)
		return CMD_STATUS_INVALID_ARGS;

	if (!proxy_property_set(proxy, argv[0], argv[1],
						check_errors_method_callback))
		return CMD_STATUS_INVALID_VALUE;

	return CMD_STATUS_OK;
}

static enum cmd_status cmd_connect(const char *device_name,
						char **argv, int argc)
{
	struct network_args network_args;
	struct l_queue *match;
	const struct proxy_interface *network_proxy;
	const struct proxy_interface *device_proxy =
					get_device_proxy_by_name(device_name);

	if (!device_proxy)
		return CMD_STATUS_INVALID_VALUE;

	if (argc < 1)
		return CMD_STATUS_INVALID_ARGS;

	network_args.name = argv[0];
	network_args.type = argc >= 2 ? argv[1] : NULL;

	match = network_match_by_device_and_args(device_proxy, &network_args);
	if (!match) {
		display("Invalid network name '%s'\n", network_args.name);
		return CMD_STATUS_INVALID_VALUE;
	}

	if (l_queue_length(match) > 1) {
		if (!network_args.type) {
			display("Provided network name is ambiguous. "
				"Please specify security type.\n");
		}

		l_queue_destroy(match, NULL);

		return CMD_STATUS_INVALID_VALUE;
	}

	network_proxy = l_queue_pop_head(match);
	l_queue_destroy(match, NULL);
	network_connect(network_proxy);

	return CMD_STATUS_OK;
}

static enum cmd_status cmd_connect_hidden_network(const char *device_name,
							char **argv,
							int argc)
{
	const struct proxy_interface *proxy =
					get_device_proxy_by_name(device_name);

	if (!proxy)
		return CMD_STATUS_INVALID_VALUE;

	if (argc != 1)
		return CMD_STATUS_INVALID_ARGS;

	proxy_interface_method_call(proxy, "ConnectHiddenNetwork", "s",
					check_errors_method_callback,
					argv[0]);

	return CMD_STATUS_OK;
}

static char *get_networks_cmd_arg_completion(const char *text, int state)
{
	static int index;
	static int len;
	const char *arg;

	if (!state) {
		index = 0;
		len = strlen(text);
	}

	while ((arg = ordered_networks_arg_options[index++].option)) {
		if (!strncmp(arg, text, len))
			return l_strdup(arg);
	}

	return NULL;
}

static char *connect_cmd_arg_completion(const char *text, int state)
{
	const struct proxy_interface *device = device_get_default();

	if (!device)
		return NULL;

	return network_name_completion(device, text, state);
}

static char *set_property_cmd_arg_completion(const char *text, int state)
{
	return proxy_property_completion(device_properties, text, state);
}

static const struct command device_commands[] = {
	{ NULL,     "list",     NULL,   cmd_list, "List devices",     true },
	{ "<wlan>", "show",     NULL,   cmd_show, "Show device info", true },
	{ "<wlan>", "scan",     NULL,   cmd_scan, "Scan for networks" },
	{ "<wlan>", "get-networks",
				"[rssi-dbms/rssi-bars]",
					cmd_get_networks,
						"Get networks",       true,
			get_networks_cmd_arg_completion },
	{ "<wlan>", "set-property",
				"<name> <value>",
					cmd_set_property,
						"Set property",       false,
		set_property_cmd_arg_completion },
	{ "<wlan>", "connect",
				"<\"network name\"> [security]",
					cmd_connect,
						"Connect to network", false,
		connect_cmd_arg_completion },
	{ "<wlan>", "connect-hidden",
				"<\"network name\">",
					cmd_connect_hidden_network,
						"Connect to hidden network",
									false },
	{ "<wlan>", "disconnect",
				NULL,   cmd_disconnect, "Disconnect" },
	{ }
};

const struct proxy_interface *device_wsc_get(const char *device_name)
{
	const struct device *device;
	const struct proxy_interface *proxy =
					get_device_proxy_by_name(device_name);

	if (!proxy)
		return NULL;

	device = proxy_interface_get_data(proxy);

	return device->wsc;
}

char *device_wsc_family_arg_completion(const char *text, int state)
{
	return proxy_property_str_completion(&device_interface_type,
						match_by_partial_name_and_wsc,
						"Name", text, state);
}

const struct proxy_interface *device_ap_get(const char *device_name)
{
	const struct device *device;
	const struct proxy_interface *proxy =
					get_device_proxy_by_name(device_name);

	if (!proxy)
		return NULL;

	device = proxy_interface_get_data(proxy);

	return device->ap;
}

char *device_ap_family_arg_completion(const char *text, int state)
{
	return proxy_property_str_completion(&device_interface_type,
						match_by_partial_name_and_ap,
						"Name", text, state);
}

const struct proxy_interface *device_ad_hoc_get(const char *device_name)
{
	const struct device *device;
	const struct proxy_interface *proxy =
					get_device_proxy_by_name(device_name);

	if (!proxy)
		return NULL;

	device = proxy_interface_get_data(proxy);

	return device->ad_hoc;
}

char *device_ad_hoc_family_arg_completion(const char *text, int state)
{
	return proxy_property_str_completion(&device_interface_type,
					match_by_partial_name_and_ad_hoc,
					"Name", text, state);
}

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
	.set_default_entity = device_set_default,
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
	proxy_interface_type_unregister(&device_interface_type);
}

INTERFACE_TYPE(device_interface_type, device_interface_init,
						device_interface_exit)
