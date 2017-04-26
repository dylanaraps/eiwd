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
#include <readline/history.h>
#include <readline/readline.h>
#include <stdio.h>

#include "command.h"
#include "display.h"

#define IWD_PROMPT COLOR_GREEN "[iwd]" COLOR_OFF "# "
#define LINE_LEN   81

static struct l_io *io;
static char dashed_line[LINE_LEN];
static char empty_line[LINE_LEN];
static struct l_timeout *refresh_timeout;

static struct display_refresh {
	char *family;
	char *entity;
	const struct command *cmd;
	char *args;
	size_t undo_lines;
	struct l_queue *redo_entries;
	bool recording;
} display_refresh;

struct saved_input {
	char *line;
	int point;
};

static struct saved_input *save_input(void)
{
	struct saved_input *input;

	if (RL_ISSTATE(RL_STATE_DONE))
		return NULL;

	input = l_new(struct saved_input, 1);

	input->point = rl_point;
	input->line = rl_copy_text(0, rl_end);
	rl_save_prompt();
	rl_replace_line("", 0);
	rl_redisplay();

	return input;
}

static void restore_input(struct saved_input *input)
{
	if (!input)
		return;

	rl_restore_prompt();
	rl_replace_line(input->line, 0);
	rl_point = input->point;
	rl_forced_update_display();

	l_free(input->line);
	l_free(input);
}

static void display_refresh_undo_lines(void)
{
	size_t num_lines = display_refresh.undo_lines;

	printf("\033[%dA", (int) num_lines);

	do {
		printf("%s\n", empty_line);
	} while (--display_refresh.undo_lines);

	printf("\033[%dA", (int) num_lines);
}

static void display_refresh_redo_lines(void)
{
	const struct l_queue_entry *entry;
	struct saved_input *input;

	input = save_input();

	for (entry = l_queue_get_entries(display_refresh.redo_entries); entry;
							entry = entry->next) {
		char *line = entry->data;

		printf("%s", line);

		display_refresh.undo_lines++;
	}

	restore_input(input);
	display_refresh.recording = true;

	l_timeout_modify(refresh_timeout, 1);
}

void display_refresh_reset(void)
{
	l_free(display_refresh.family);
	display_refresh.family = NULL;

	l_free(display_refresh.entity);
	display_refresh.entity = NULL;

	display_refresh.cmd = NULL;

	l_free(display_refresh.args);
	display_refresh.args = NULL;

	display_refresh.undo_lines = 0;
	display_refresh.recording = false;

	l_queue_clear(display_refresh.redo_entries, l_free);
}

void display_refresh_set_cmd(const char *family, const char *entity,
				const struct command *cmd, char *args)
{
	if (cmd->refreshable) {
		l_free(display_refresh.family);
		display_refresh.family = l_strdup(family);

		l_free(display_refresh.entity);
		display_refresh.entity = l_strdup(entity);

		display_refresh.cmd = cmd;

		l_free(display_refresh.args);
		display_refresh.args = l_strdup(args);

		l_queue_clear(display_refresh.redo_entries, l_free);

		display_refresh.recording = false;
		display_refresh.undo_lines = 0;

		return;
	}

	if (display_refresh.family && !strcmp(display_refresh.family, family)) {
		char *prompt =
			l_strdup_printf(IWD_PROMPT"%s%s%s %s %s\n",
					family ? : "",
					entity ? " " : "", entity ? : "",
					cmd->cmd ? : "", args ? : "");

		l_queue_push_tail(display_refresh.redo_entries, prompt);
		display_refresh.undo_lines++;

		display_refresh.recording = true;
	} else {
		display_refresh_reset();
	}
}

static void timeout_callback(struct l_timeout *timeout, void *user_data)
{
	struct saved_input *input;

	if (!display_refresh.cmd)
		return;

	input = save_input();
	display_refresh_undo_lines();
	restore_input(input);

	display_refresh.recording = false;
	display_refresh.cmd->function(display_refresh.entity,
							display_refresh.args);
}

void display_refresh_timeout_set(void)
{
	if (refresh_timeout)
		l_timeout_modify(refresh_timeout, 1);
	else
		refresh_timeout = l_timeout_create(1, timeout_callback,
							NULL, NULL);
}

static void display_text(const char *text)
{
	struct saved_input *input = save_input();

	printf("%s", text);

	restore_input(input);

	if (!display_refresh.cmd)
		return;

	display_refresh.undo_lines++;

	if (display_refresh.recording)
		l_queue_push_tail(display_refresh.redo_entries, l_strdup(text));
}

void display(const char *fmt, ...)
{
	va_list args;
	char *text;

	va_start(args, fmt);
	text = l_strdup_vprintf(fmt, args);
	va_end(args);

	display_text(text);

	l_free(text);
}

void display_error(const char *error)
{
	char *text = l_strdup_printf(COLOR_RED "%s\n" COLOR_OFF, error);

	display_text(text);

	l_free(text);
}

void display_table_header(const char *caption, const char *fmt, ...)
{
	va_list args;
	char *text;
	char *body;
	int caption_pos =
		(int) ((sizeof(dashed_line) - 1) / 2 + strlen(caption) / 2);

	text = l_strdup_printf("%*s\n", caption_pos, caption);
	display_text(text);
	l_free(text);

	text = l_strdup_printf("%s%s%s\n", COLOR_GRAY, dashed_line, COLOR_OFF);
	display_text(text);
	l_free(text);

	va_start(args, fmt);
	text = l_strdup_vprintf(fmt, args);
	va_end(args);

	body = l_strdup_printf("%s%s%s\n", COLOR_BOLDGRAY, text, COLOR_OFF);
	display_text(body);
	l_free(body);
	l_free(text);

	text = l_strdup_printf("%s%s%s\n", COLOR_GRAY, dashed_line, COLOR_OFF);
	display_text(text);
	l_free(text);
}

void display_table_footer(void)
{
	display_text("\n");

	if (display_refresh.cmd)
		display_refresh_redo_lines();
}

void display_command_line(const char *command_family,
						const struct command *cmd)
{
	char *cmd_line = l_strdup_printf("%s%s%s%s%s %s",
				command_family ? : "",
				command_family ? " " : "",
				cmd->entity ? : "",
				cmd->entity  ? " " : "",
				cmd->cmd,
				cmd->arg ? : "",
				cmd->arg ? " " : "");

	display(MARGIN "%-*s%s\n", 50, cmd_line, cmd->desc ? : "");

	l_free(cmd_line);
}

void display_command(const struct command_family *family, const char *cmd_name)
{
	size_t i;

	for (i = 0; family->command_list[i].cmd; i++) {
		if (!strcmp(family->command_list[i].cmd, cmd_name)) {
			display_command_line(family->name,
						&family->command_list[i]);

			return;
		}
	}
}

static void readline_callback(char *prompt)
{
	HIST_ENTRY *previous_prompt;

	if (!prompt) {
		display_quit();

		l_main_quit();

		return;
	}

	if (!strlen(prompt))
		goto done;

	previous_prompt = current_history();
	if (!previous_prompt ||
			(previous_prompt &&
				strcmp(previous_prompt->line, prompt))) {
		add_history(prompt);
	}

	command_process_prompt(prompt);

done:
	l_free(prompt);
}

static bool read_handler(struct l_io *io, void *user_data)
{
	rl_callback_read_char();

	return true;
}

static void disconnect_callback(struct l_io *io, void *user_data)
{
	l_main_quit();
}

void display_enable_cmd_prompt(void)
{
	io = l_io_new(fileno(stdin));

	l_io_set_read_handler(io, read_handler, NULL, NULL);
	l_io_set_disconnect_handler(io, disconnect_callback, NULL, NULL);

	rl_set_prompt(IWD_PROMPT);

	display("");
}

void display_disable_cmd_prompt(void)
{
	display_refresh_reset();

	rl_set_prompt("Waiting to connect to IWD");
	printf("\r");
	rl_on_new_line();
	rl_redisplay();
}

void display_quit(void)
{
	rl_insert_text("quit");
	rl_redisplay();
	rl_crlf();
}

void display_init(void)
{
	memset(&dashed_line, '-', sizeof(dashed_line) - 1);
	memset(&empty_line, ' ', sizeof(empty_line) - 1);

	display_refresh.redo_entries = l_queue_new();

	setlinebuf(stdout);

	rl_attempted_completion_function = command_completion;

	rl_erase_empty_line = 1;
	rl_callback_handler_install("Waiting for IWD to appear...",
							readline_callback);
	rl_redisplay();
}

void display_exit(void)
{
	l_timeout_remove(refresh_timeout);
	refresh_timeout = NULL;

	l_queue_destroy(display_refresh.redo_entries, l_free);

	rl_callback_handler_remove();

	l_io_destroy(io);
}
