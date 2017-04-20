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

#include <stdio.h>
#include <ell/ell.h>
#include <readline/readline.h>

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

static char *cmd_generator(const char *text, int state)
{
	static const struct l_queue_entry *entry;
	static size_t index;
	static size_t len;
	const char *cmd;

	if (!state) {
		len = strlen(text);
		index = 0;
		entry = l_queue_get_entries(command_families);
	}

	while (entry) {
		const struct command_family *family = entry->data;

		entry = entry->next;

		if (strncmp(family->name, text, len))
			continue;

		return l_strdup(family->name);
	}

	while ((cmd = command_list[index].cmd)) {
		index++;

		if (strncmp(cmd, text, len))
			continue;

		return l_strdup(cmd);
	}

	return NULL;
}

static bool cmd_completion_cmd_has_arg(const char *cmd,
					const struct command_family *family)
{
	size_t i;
	char **matches = NULL;
	bool status;

	for (i = 0; family->command_list[i].cmd; i++) {
		if (strcmp(family->command_list[i].cmd, cmd))
			continue;

		return family->command_list[i].arg ? true : false;
	}

	if (!family->family_arg_completion)
		return false;

	matches = rl_completion_matches(cmd, family->family_arg_completion);
	if (!matches)
		return false;

	status = false;

	for (i = 0; matches[i]; i++) {
		if (strcmp(matches[i], cmd))
			continue;

		status = true;

		break;
	}

	l_strfreev(matches);

	return status;
}

static char **cmd_completion_match_entity_cmd(const char *cmd, const char *text,
						const struct command *cmd_list)
{
	char **matches = NULL;
	size_t i;

	for (i = 0; cmd_list[i].cmd; i++) {
		if (strcmp(cmd_list[i].cmd, cmd))
			continue;

		if (!cmd_list[i].completion)
			break;

		matches = rl_completion_matches(text, cmd_list[i].completion);

		break;
	}

	return matches;
}

static char **cmd_completion_match_family_cmd(const char *cmd_family,
						char *args, const char *text,
						bool ends_with_space)
{
	const struct l_queue_entry *entry;
	const char *arg1;
	const char *arg2;
	const char *arg3;
	char **matches = NULL;

	for (entry = l_queue_get_entries(command_families); entry;
							entry = entry->next) {
		const struct command_family *family = entry->data;

		if (strcmp(family->name, cmd_family))
			continue;

		arg1 = strtok_r(NULL, " ", &args);
		if (!arg1) {
			if (!family->family_arg_completion)
				break;

			matches = rl_completion_matches(text,
						family->family_arg_completion);

			break;
		}

		arg2 = strtok_r(NULL, " ", &args);
		if (!arg2 && !ends_with_space) {
			if (!family->family_arg_completion)
				break;

			matches = rl_completion_matches(text,
						family->family_arg_completion);
			break;
		} else if (!arg2 && ends_with_space) {
			if (!cmd_completion_cmd_has_arg(arg1, family))
				break;

			if (!family->entity_arg_completion)
				break;

			matches = rl_completion_matches(text,
						family->entity_arg_completion);
			break;
		}

		arg3 = strtok_r(NULL, " ", &args);
		if (!arg3 && !ends_with_space) {
			if (!family->entity_arg_completion)
				break;

			matches = rl_completion_matches(text,
						family->entity_arg_completion);
			break;
		}

		matches = cmd_completion_match_entity_cmd(arg2, text,
							family->command_list);

		break;
	}

	return matches;
}

char **command_completion(const char *text, int start, int end)
{
	char **matches = NULL;
	const char *family;
	char *args;
	char *prompt = NULL;
	bool ends_with_space = false;

	if (!start) {
		matches = rl_completion_matches(text, cmd_generator);

		goto done;
	}

	prompt = rl_copy_text(0, rl_end);

	family = strtok_r(prompt, " ", &args);
	if (!family)
		goto done;

	if (args) {
		int len = strlen(args);

		if (len > 0 && args[len - 1] == ' ')
			ends_with_space = true;
	}

	matches = cmd_completion_match_family_cmd(family, args, text,
							ends_with_space);

done:
	l_free(prompt);

	if (!matches)
		rl_attempted_completion_over = 1;

	return matches;
}

static void execute_cmd(const char *family, const char *entity,
					const struct command *cmd, char *args)
{
	display_refresh_set_cmd(family, entity, cmd, args);

	cmd->function(entity, args);

	if (cmd->refreshable)
		display_refresh_timeout_set();
}

static bool match_cmd(const char *family, const char *entity, const char *cmd,
				char *args, const struct command *command_list)
{
	size_t i;

	for (i = 0; command_list[i].cmd; i++) {
		if (strcmp(command_list[i].cmd, cmd))
			continue;

		if (!command_list[i].function)
			goto nomatch;

		execute_cmd(family, entity, &command_list[i], args);

		return true;
	}

nomatch:
	return false;
}

static bool match_cmd_family(const char *cmd_family, char *arg)
{
	const struct l_queue_entry *entry;
	const char *arg1;
	const char *arg2;

	for (entry = l_queue_get_entries(command_families); entry;
							entry = entry->next) {
		const struct command_family *family = entry->data;

		if (strcmp(family->name, cmd_family))
			continue;

		arg1 = strtok_r(NULL, " ", &arg);
		if (!arg1)
			goto nomatch;

		if (match_cmd(family->name, NULL, arg1, arg,
							family->command_list))
			return true;

		arg2 = strtok_r(NULL, " ", &arg);
		if (!arg2)
			goto nomatch;

		if (!match_cmd(family->name, arg1, arg2, arg,
							family->command_list))
			goto nomatch;

		return true;
	}

nomatch:
	return false;
}

static void list_commands(const char *command_family,
						const struct command *cmd_list)
{
	size_t i;

	for (i = 0; cmd_list[i].cmd; i++) {
		if (!cmd_list[i].desc)
			continue;

		display_command_line(command_family, &cmd_list[i]);
	}
}

static void list_cmd_families(void)
{
	const struct l_queue_entry *entry;

	for (entry = l_queue_get_entries(command_families); entry;
							entry = entry->next) {
		const struct command_family *family = entry->data;

		display("\n%s:\n", family->caption);
		list_commands(family->name, family->command_list);
	}
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

	display_refresh_reset();

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

extern struct command_family_desc __start___command[];
extern struct command_family_desc __stop___command[];

void command_init(void)
{
	struct command_family_desc *desc;

	command_families = l_queue_new();

	if (__start___command == NULL || __stop___command == NULL)
		return;

	for (desc = __start___command; desc < __stop___command; desc++) {
		if (!desc->init)
			continue;

		desc->init();
	}
}

void command_exit(void)
{
	struct command_family_desc *desc;

	if (__start___command == NULL || __stop___command == NULL)
		return;

	for (desc = __start___command; desc < __stop___command; desc++) {
		if (!desc->exit)
			continue;

		desc->exit();
	}

	l_queue_destroy(command_families, NULL);
	command_families = NULL;
}
