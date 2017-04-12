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
#include "display.h"

static struct l_queue *command_families;

static void cmd_version(const char *entity, char *arg)
{
	display("IWD version %s\n", VERSION);
}

static void cmd_quit(const char *entity, char *arg)
{
	display_quit();

	l_main_quit();
}

static const struct command command_list[] = {
	{ NULL, "version", NULL, cmd_version, "Display version" },
	{ NULL, "quit",    NULL, cmd_quit,    "Quit program" },
	{ NULL, "exit",    NULL, cmd_quit },
	{ NULL, "help" },
	{ }
};

static bool match_cmd(const char *family, const char *entity, const char *cmd,
				char *args, const struct command *command_list)
{
	return false;
}

static bool match_cmd_family(const char *cmd_family, char *arg)
{
	return false;
}

static void list_commands(const char *command_family,
						const struct command *cmd_list)
{
}

static void list_cmd_families(void)
{
}

void command_process_prompt(char *prompt)
{
	const char *cmd;
	char *arg = NULL;

	cmd = strtok_r(prompt, " ", &arg);
	if (!cmd)
		return;

	if (match_cmd_family(cmd, arg))
		return;

	if (match_cmd(NULL, NULL, cmd, arg, command_list))
		return;

	if (strcmp(cmd, "help")) {
		display("Invalid command\n");
		return;
	}

	display_table_header("Available commands", MARGIN "%-*s%-*s",
					50, "Commands", 28, "Description");

	list_cmd_families();

	display("\n");

	list_commands(NULL, command_list);
}

void command_family_register(const struct command_family *family)
{
	l_queue_push_tail(command_families, (void *) family);
}

void command_family_unregister(const struct command_family *family)
{
	l_queue_remove(command_families, (void *) family);
}

void command_init(void)
{
	command_families = l_queue_new();
}

void command_exit(void)
{
	l_queue_destroy(command_families, NULL);
	command_families = NULL;
}
