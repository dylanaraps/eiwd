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

#define IWD_KNOWN_NETWORKS_PATH	"/"

struct known_network {
	char *name;
	char *type;
	char *last_connected;
};

static void known_network_destroy(void *data)
{
	struct known_network *network = data;

	l_free(network->last_connected);
	l_free(network->name);
	l_free(network->type);

	l_free(network);
}

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

static void known_networks_display(struct l_queue *known_networks)
{
	const struct l_queue_entry *entry;

	display_table_header("Known Networks", " %-*s%-*s%-*s",
					32, "Name", 11, "Security",
					19, "Last connected");

	if (!l_queue_length(known_networks))
		display(MARGIN "No known networks\n");

	for (entry = l_queue_get_entries(known_networks); entry;
							entry = entry->next) {
		struct known_network *network = entry->data;
		char *last_connected =
			l_strdup(format_iso8601(network->last_connected,
							"%b %e, %l:%M %p"));

		display(" %-*s%-*s%-*s"
			"\n", 32, network->name, 11, network->type,
			19, last_connected ? : "-");

		l_free(last_connected);
	}

	display_table_footer();
}

static void update_name(void *data, struct l_dbus_message_iter *variant)
{
	struct known_network *network = data;
	const char *value;

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

	if (!l_dbus_message_iter_get_variant(variant, "s", &value)) {
		network->last_connected = NULL;

		return;
	}

	network->last_connected = l_strdup(value);
}

static const struct proxy_interface_property known_network_properties[] = {
	{ "Name",              "s", update_name           },
	{ "Type",              "s", update_type           },
	{ "LastConnectedTime", "s", update_last_connected },
	{ },
};

static void populate_known_network(struct known_network *network,
				struct l_dbus_message_iter *network_iter)
{
	const char *name;
	size_t i;
	struct l_dbus_message_iter variant;

	while (l_dbus_message_iter_next_entry(network_iter, &name, &variant)) {
		for (i = 0; known_network_properties[i].name; i++) {
			if (strcmp(known_network_properties[i].name, name))
				continue;

			if (!known_network_properties[i].update)
				break;

			known_network_properties[i].update(network, &variant);

			break;
		}
	}
}

static void list_networks_callback(struct l_dbus_message *message, void *proxy)
{
	struct l_queue *known_networks = proxy_interface_get_data(proxy);
	struct l_dbus_message_iter network_iter;
	struct l_dbus_message_iter iter;

	if (dbus_message_has_error(message))
		return;

	if (!l_dbus_message_get_arguments(message, "aa{sv}", &iter)) {
		l_error("Failed to parse 'list known networks' callback "
								"message");

		return;
	}

	l_queue_clear(known_networks, known_network_destroy);

	while (l_dbus_message_iter_next_entry(&iter, &network_iter)) {
		struct known_network *network = l_new(struct known_network, 1);

		populate_known_network(network, &network_iter);

		l_queue_push_tail(known_networks, network);
	}

	known_networks_display(known_networks);
}

static void *known_networks_create(void)
{
	return l_queue_new();
}

static void known_networks_destroy(void *data)
{
	struct l_queue *networks = data;

	l_queue_destroy(networks, known_network_destroy);
}

static const struct proxy_interface_type_ops known_networks_ops = {
	.create = known_networks_create,
	.destroy = known_networks_destroy,
};

static struct proxy_interface_type known_networks_interface_type = {
	.interface = IWD_KNOWN_NETWORKS_INTREFACE,
	.ops = &known_networks_ops,
};

static enum cmd_status cmd_list(const char *entity, char **args, int argc)
{
	struct proxy_interface *proxy =
		proxy_interface_find(IWD_KNOWN_NETWORKS_INTREFACE,
						IWD_KNOWN_NETWORKS_PATH);

	if (!proxy)
		return CMD_STATUS_FAILED;

	proxy_interface_method_call(proxy, "ListKnownNetworks", "",
						list_networks_callback);

	return CMD_STATUS_OK;
}

static enum cmd_status cmd_forget(const char *entity, char **argv, int argc)
{
	const struct l_queue_entry *entry;
	struct known_network *network = NULL;
	struct known_network *net;
	struct l_queue *known_networks;
	struct l_queue *match;
	struct proxy_interface *proxy =
		proxy_interface_find(IWD_KNOWN_NETWORKS_INTREFACE,
						IWD_KNOWN_NETWORKS_PATH);

	if (!proxy)
		return CMD_STATUS_FAILED;

	if (argc < 1)
		return CMD_STATUS_INVALID_ARGS;

	known_networks = proxy_interface_get_data(proxy);
	match = NULL;

	for (entry = l_queue_get_entries(known_networks); entry;
							entry = entry->next) {
		net = entry->data;

		if (strcmp(net->name, argv[0]))
			continue;

		if (!match)
			match = l_queue_new();

		l_queue_push_tail(match, net);
	}

	if (!match) {
		display("Invalid network name '%s'\n", argv[0]);
		return CMD_STATUS_INVALID_VALUE;
	}

	if (l_queue_length(match) > 1) {
		if (argc < 2) {
			display("Provided network name is ambiguous. "
				"Please specify security type.\n");

			l_queue_destroy(match, NULL);
			return CMD_STATUS_INVALID_VALUE;
		}

		for (entry = l_queue_get_entries(match); entry;
							entry = entry->next) {
			net = entry->data;

			if (!strcmp(net->type, argv[1])) {
				network = net;
				break;
			}
		}
	} else {
		network = l_queue_pop_head(match);
	}

	l_queue_destroy(match, NULL);

	if (!network) {
		display("No network with specified parameters was found\n");
		return CMD_STATUS_INVALID_VALUE;
	}

	proxy_interface_method_call(proxy, "ForgetNetwork", "ss", NULL,
						network->name, network->type);

	return CMD_STATUS_OK;
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

static int known_networks_interface_init(void)
{
	proxy_interface_type_register(&known_networks_interface_type);

	return 0;
}

static void known_networks_interface_exit(void)
{
	proxy_interface_type_unregister(&known_networks_interface_type);
}

INTERFACE_TYPE(known_networks_interface_type, known_networks_interface_init,
						known_networks_interface_exit)
