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

struct known_network {
	char *name;
	char *type;
	char *last_seen;
	char *last_connected;
};

static void known_network_destroy(void *data)
{
	struct known_network *network = data;

	l_free(network->last_connected);
	l_free(network->last_seen);
	l_free(network->name);
	l_free(network->type);

	l_free(network);
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

static void cmd_list(const char *entity, char *args)
{
}

static void cmd_forget(const char *entity, char *args)
{
}

static const struct command known_networks_commands[] = {
	{ NULL, "list",   NULL, cmd_list,   "List known networks", true },
	{ NULL, "forget", "<network name> [security]",
				cmd_forget, "Forget known network"},
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
	proxy_interface_type_register(&known_networks_interface_type);
}

INTERFACE_TYPE(known_networks_interface_type, known_networks_interface_init,
						known_networks_interface_exit)
