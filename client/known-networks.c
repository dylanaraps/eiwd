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

#define _XOPEN_SOURCE 700

#include <time.h>
#include <ell/ell.h>

#include "command.h"
#include "dbus-proxy.h"
#include "display.h"
#include "network.h"

struct known_network {
	char *identity;
	char *name;
	char *type;
	char *last_connected;
	bool hidden;
};

static const char *format_iso8601(const char *time_str, const char *format)
{
	struct tm tm;
	time_t time;
	static char buf[255];

	if (!time_str)
		return NULL;

	memset(&tm, 0, sizeof(struct tm));

	strptime(time_str, "%FT%TZ", &tm);

	time = mktime(&tm);

	strftime(buf, sizeof(buf), format, localtime(&time));

	return buf;
}

static void update_name(void *data, struct l_dbus_message_iter *variant)
{
	struct known_network *network = data;
	const char *value;

	l_free(network->name);

	if (!l_dbus_message_iter_get_variant(variant, "s", &value)) {
		network->name = NULL;

		return;
	}

	network->name = l_strdup(value);
}

static void update_type(void *data, struct l_dbus_message_iter *variant)
{
	struct known_network *network = data;
	const char *value;

	l_free(network->type);

	if (!l_dbus_message_iter_get_variant(variant, "s", &value)) {
		network->type = NULL;

		return;
	}

	network->type = l_strdup(value);
}

static void update_last_connected(void *data, struct l_dbus_message_iter *variant)
{
	struct known_network *network = data;
	const char *value;

	l_free(network->last_connected);

	if (!l_dbus_message_iter_get_variant(variant, "s", &value)) {
		network->last_connected = NULL;

		return;
	}

	network->last_connected = l_strdup(value);
}

static void update_hidden(void *data, struct l_dbus_message_iter *variant)
{
	struct known_network *network = data;
	bool value;

	if (!l_dbus_message_iter_get_variant(variant, "b", &value)) {
		network->hidden = false;

		return;
	}

	network->hidden = value;
}

static const char *get_hidden_tostr(const void *data)
{
	const struct known_network *network = data;

	return network->hidden ? "yes" : "";
}

static const struct proxy_interface_property known_network_properties[] = {
	{ "Name",              "s", update_name           },
	{ "Type",              "s", update_type           },
	{ "LastConnectedTime", "s", update_last_connected },
	{ "Hidden",            "b", update_hidden, get_hidden_tostr },
	{ },
};

static void *known_network_create(void)
{
	return l_new(struct known_network, 1);
}

static void known_network_destroy(void *data)
{
	struct known_network *network = data;

	l_free(network->last_connected);
	l_free(network->name);
	l_free(network->type);
	l_free(network->identity);

	l_free(network);
}

static void known_network_display_inline(const char *margin, const void *data)
{
	const struct known_network *network = data;
	char *last_connected =
		l_strdup(format_iso8601(network->last_connected,
						"%b %e, %l:%M %p"));

	display("%s%-*s%-*s%-*s%-*s\n",
		margin, 32, network->name, 11, network->type,
		9, get_hidden_tostr(network), 19, last_connected ? : "-");

	l_free(last_connected);
}

static const char *known_network_identity(void *data)
{
	struct known_network *network = data;

	if (!network->identity)
		network->identity =
			l_strdup_printf("%s %s", network->name, network->type);

	return network->identity;
}

static const struct proxy_interface_type_ops known_network_ops = {
	.create = known_network_create,
	.destroy = known_network_destroy,
	.display = known_network_display_inline,
	.identity = known_network_identity,
};

static struct proxy_interface_type known_network_interface_type = {
	.interface = IWD_KNOWN_NETWORK_INTREFACE,
	.properties = known_network_properties,
	.ops = &known_network_ops,
};

static bool known_network_match(const void *a, const void *b)
{
	const struct known_network *network = a;
	const struct network_args *args = b;

	if (strcmp(network->name, args->name))
		return false;

	if (args->type && strcmp(network->type, args->type))
		return false;

	return true;
}

static void check_errors_method_callback(struct l_dbus_message *message,
								void *user_data)
{
	dbus_message_has_error(message);
}

static enum cmd_status cmd_list(const char *entity, char **args, int argc)
{
	display_table_header("Known Networks", MARGIN "%-*s%-*s%-*s%-*s",
					32, "Name", 11, "Security", 9, "Hidden",
					19, "Last connected");

	proxy_interface_display_list(known_network_interface_type.interface);

	display_table_footer();

	return CMD_STATUS_DONE;
}

static enum cmd_status cmd_forget(const char *entity, char **argv, int argc)
{
	struct network_args network_args;
	struct l_queue *match;
	const struct proxy_interface *known_network_proxy;

	if (argc < 1)
		return CMD_STATUS_INVALID_ARGS;

	network_args.name = argv[0];
	network_args.type = argc >= 2 ? argv[1] : NULL;

	match = proxy_interface_find_all(known_network_interface_type.interface,
						known_network_match,
						&network_args);

	if (!match) {
		display("No network with specified parameters was found\n");
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

	known_network_proxy = l_queue_pop_head(match);
	l_queue_destroy(match, NULL);

	proxy_interface_method_call(known_network_proxy, "Forget", "",
					check_errors_method_callback);

	return CMD_STATUS_TRIGGERED;
}

static const struct command known_networks_commands[] = {
	{ NULL, "list",   NULL, cmd_list,   "List known networks", true },
	{ NULL, "forget", "<\"network name\"> [security]",
				cmd_forget, "Forget known network" },
	{ }
};

static char *family_arg_completion(const char *text, int state)
{
	static size_t index;
	static size_t len;
	const char *cmd;

	if (!state) {
		index = 0;
		len = strlen(text);
	}

	while ((cmd = known_networks_commands[index].cmd)) {
		if (known_networks_commands[index++].entity)
			continue;

		if (strncmp(cmd, text, len))
			continue;

		return l_strdup(cmd);
	}

	return NULL;
}

static struct command_family known_networks_command_family = {
	.caption = "Known Networks",
	.name = "known-networks",
	.command_list = known_networks_commands,
	.family_arg_completion = family_arg_completion,
};

static int known_networks_command_family_init(void)
{
	command_family_register(&known_networks_command_family);

	return 0;
}

static void known_networks_command_family_exit(void)
{
	command_family_unregister(&known_networks_command_family);
}

COMMAND_FAMILY(known_networks_command_family,
		known_networks_command_family_init,
		known_networks_command_family_exit)

static int known_network_interface_init(void)
{
	proxy_interface_type_register(&known_network_interface_type);

	return 0;
}

static void known_network_interface_exit(void)
{
	proxy_interface_type_unregister(&known_network_interface_type);
}

INTERFACE_TYPE(known_network_interface_type, known_network_interface_init,
						known_network_interface_exit)
