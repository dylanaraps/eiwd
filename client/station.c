/*
 *
 *  Wireless daemon for Linux
 *
 *  Copyright (C) 2018  Intel Corporation. All rights reserved.
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

struct station {
	bool scanning;
	char *state;
	const struct proxy_interface *connected_network;
};

static void *station_create(void)
{
	return l_new(struct station, 1);
}

static void station_destroy(void *data)
{
	struct station *station = data;

	l_free(station->state);
	station->connected_network = NULL;

	l_free(station);
}

static const struct proxy_interface_type_ops station_ops = {
	.create = station_create,
	.destroy = station_destroy,
};

static const char *get_scanning_tostr(const void *data)
{
	const struct station *station = data;

	return station->scanning ? "yes" : "no";
}

static void update_scanning(void *data, struct l_dbus_message_iter *variant)
{
	struct station *station = data;
	bool value;

	if (!l_dbus_message_iter_get_variant(variant, "b", &value)) {
		station->scanning = false;
		return;
	}

	station->scanning = value;
}

static const char *get_state(const void *data)
{
	const struct station *station = data;

	return station->state;
}

static void update_state(void *data, struct l_dbus_message_iter *variant)
{
	struct station *station = data;
	const char *value;

	l_free(station->state);

	if (!l_dbus_message_iter_get_variant(variant, "s", &value)) {
		station->state = NULL;
		return;
	}

	station->state = l_strdup(value);
}

static void update_connected_network(void *data,
					struct l_dbus_message_iter *variant)
{
	struct station *station = data;
	const char *path;

	if (!l_dbus_message_iter_get_variant(variant, "o", &path)) {
		station->connected_network = NULL;

		return;
	}

	station->connected_network = proxy_interface_find(IWD_NETWORK_INTERFACE,
									path);
}

static const struct proxy_interface_property station_properties[] = {
	{ "Scanning",  "b", update_scanning,  get_scanning_tostr },
	{ "State",    "s", update_state,    get_state },
	{ "ConnectedNetwork",
			"o", update_connected_network },
	{ }
};

static struct proxy_interface_type station_interface_type = {
	.interface = IWD_STATION_INTERFACE,
	.properties = station_properties,
	.ops = &station_ops,
};

static void check_errors_method_callback(struct l_dbus_message *message,
								void *user_data)
{
	dbus_message_has_error(message);
}

static void display_station_inline(const char *margin, const void *data)
{
	const struct proxy_interface *station_i = data;
	const struct station *station = proxy_interface_get_data(station_i);
	struct proxy_interface *device_i =
		proxy_interface_find(IWD_DEVICE_INTERFACE,
					proxy_interface_get_path(station_i));
	const char *identity;

	if (!device_i)
		return;

	identity = proxy_interface_get_identity_str(device_i);
	if (!identity)
		return;

	display("%s%-*s%-*s%-*s\n", margin,
			20, identity,
			15, station->state ? : "",
			8, station->scanning ? "scanning" : "");
}

static enum cmd_status cmd_list(const char *device_name, char **argv, int argc)
{
	const struct l_queue_entry *entry;
	struct l_queue *match =
		proxy_interface_find_all(IWD_STATION_INTERFACE, NULL, NULL);

	display_table_header("Devices in Station Mode", MARGIN "%-*s%-*s%-*s",
				20, "Name", 15, "State", 8, "Scanning");

	if (!match) {
		display("No devices in Station mode available.\n");
		display_table_footer();

		return CMD_STATUS_DONE;
	}

	for (entry = l_queue_get_entries(match); entry; entry = entry->next) {
		const struct proxy_interface *station = entry->data;
		display_station_inline(MARGIN, station);
	}

	display_table_footer();

	l_queue_destroy(match, NULL);

	return CMD_STATUS_DONE;
}

static enum cmd_status cmd_disconnect(const char *device_name,
						char **argv, int argc)
{
	const struct proxy_interface *station_i =
			device_proxy_find(device_name, IWD_STATION_INTERFACE);

	if (!station_i) {
		display("No station on device: '%s'\n", device_name);
		return CMD_STATUS_INVALID_VALUE;
	}

	proxy_interface_method_call(station_i, "Disconnect", "",
						check_errors_method_callback);

	return CMD_STATUS_TRIGGERED;
}

static enum cmd_status cmd_scan(const char *device_name,
						char **argv, int argc)
{
	const struct proxy_interface *station_i =
			device_proxy_find(device_name, IWD_STATION_INTERFACE);

	if (!station_i) {
		display("No station on device: '%s'\n", device_name);
		return CMD_STATUS_INVALID_VALUE;
	}

	proxy_interface_method_call(station_i, "Scan", "",
						check_errors_method_callback);

	return CMD_STATUS_TRIGGERED;
}

static const struct command station_commands[] = {
	{ NULL, "list", NULL, cmd_list, "List Ad-Hoc devices", true },
	{ "<wlan>", "disconnect",
				NULL,   cmd_disconnect, "Disconnect" },
	{ "<wlan>", "scan",     NULL,   cmd_scan, "Scan for networks" },
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

	while ((cmd = station_commands[index].cmd)) {
		if (station_commands[index++].entity)
			continue;

		if (!strncmp(cmd, text, len))
			return l_strdup(cmd);
	}

	if (first_pass) {
		state = 0;
		first_pass = false;
	}

	return device_station_family_arg_completion(text, state);
}

static char *entity_arg_completion(const char *text, int state)
{
	return command_entity_arg_completion(text, state, station_commands);
}

static struct command_family station_command_family = {
	.caption = "Station",
	.name = "station",
	.command_list = station_commands,
	.family_arg_completion = family_arg_completion,
	.entity_arg_completion = entity_arg_completion,
};

static int station_command_family_init(void)
{
	command_family_register(&station_command_family);

	return 0;
}

static void station_command_family_exit(void)
{
	command_family_unregister(&station_command_family);
}

COMMAND_FAMILY(station_command_family, station_command_family_init,
						station_command_family_exit)

static int station_interface_init(void)
{
	proxy_interface_type_register(&station_interface_type);

	return 0;
}

static void station_interface_exit(void)
{
	proxy_interface_type_unregister(&station_interface_type);
}

INTERFACE_TYPE(station_interface_type,
				station_interface_init, station_interface_exit)
