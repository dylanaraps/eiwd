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

#define _GNU_SOURCE
#include <stdio.h>
#include <signal.h>

#include <readline/history.h>
#include <readline/readline.h>
#include <ell/ell.h>

#include "agent.h"
#include "command.h"
#include "display.h"

#define IWD_PROMPT COLOR_GREEN "[iwd]" COLOR_OFF "# "
#define LINE_LEN 81

static struct l_signal *resize_signal;
static struct l_io *io;
static char dashed_line[LINE_LEN] = { [0 ... LINE_LEN - 2] = '-' };
static char empty_line[LINE_LEN] = { [0 ... LINE_LEN - 2] = ' ' };
static struct l_timeout *refresh_timeout;
static struct saved_input *agent_saved_input;

static struct display_refresh {
	char *family;
	char *entity;
	const struct command *cmd;
	char **argv;
	int argc;
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

	l_strfreev(display_refresh.argv);
	display_refresh.argv = NULL;
	display_refresh.argc = 0;

	display_refresh.undo_lines = 0;
	display_refresh.recording = false;

	l_queue_clear(display_refresh.redo_entries, l_free);
}

void display_refresh_set_cmd(const char *family, const char *entity,
				const struct command *cmd,
				char **argv, int argc)
{
	int i;

	if (cmd->refreshable) {
		l_free(display_refresh.family);
		display_refresh.family = l_strdup(family);

		l_free(display_refresh.entity);
		display_refresh.entity = l_strdup(entity);

		display_refresh.cmd = cmd;

		l_strfreev(display_refresh.argv);
		display_refresh.argc = argc;

		display_refresh.argv = l_new(char *, argc + 1);

		for (i = 0; i < argc; i++)
			display_refresh.argv[i] = l_strdup(argv[i]);

		l_queue_clear(display_refresh.redo_entries, l_free);

		display_refresh.recording = false;
		display_refresh.undo_lines = 0;

		return;
	}

	if (display_refresh.family && !strcmp(display_refresh.family, family)) {
		struct l_string *buf = l_string_new(128);
		L_AUTO_FREE_VAR(char *, args);
		char *prompt;

		for (i = 0; i < argc; i++) {
			bool needs_quotes = false;
			char *p = argv[i];

			for (p = argv[i]; *p != '\0'; p++) {
				if (*p != ' ')
					continue;

				needs_quotes = true;
				break;
			}

			if (needs_quotes)
				l_string_append_printf(buf, "\"%s\" ", argv[i]);
			else
				l_string_append_printf(buf, "%s ", argv[i]);
		}

		args = l_string_unwrap(buf);

		prompt = l_strdup_printf(IWD_PROMPT"%s%s%s %s %s\n",
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
						display_refresh.argv,
						display_refresh.argc);
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

static char get_flasher(void)
{
	static char c;

	if (c == ' ')
		c = '*';
	else
		c = ' ';

	return c;
}

void display_table_header(const char *caption, const char *fmt, ...)
{
	va_list args;
	char *text;
	char *body;
	int caption_pos =
		(int) ((sizeof(dashed_line) - 1) / 2 + strlen(caption) / 2);

	text = l_strdup_printf("%*s" COLOR_BOLDGRAY "%*c" COLOR_OFF "\n",
				caption_pos, caption,
				LINE_LEN - 2 - caption_pos,
				display_refresh.cmd ? get_flasher() : ' ');
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
	char *cmd_line = l_strdup_printf("%s%s%s%s%s%s%s",
				command_family ? : "",
				command_family ? " " : "",
				cmd->entity ? : "",
				cmd->entity  ? " " : "",
				cmd->cmd,
				cmd->arg ? " " : "",
				cmd->arg ? : "");

	display(MARGIN "%-*s%s\n", 50, cmd_line, cmd->desc ? : "");

	l_free(cmd_line);
}

static void display_completion_matches(char **matches, int num_matches,
								int max_length)
{
	char *prompt;
	char *entry;
	char line[LINE_LEN];
	size_t index;
	size_t line_used;
	char *input = rl_copy_text(0, rl_end);

	prompt = l_strdup_printf("%s%s\n", IWD_PROMPT, input);
	l_free(input);

	display_text(prompt);
	l_free(prompt);

	for (index = 1, line_used = 0; matches[index]; index++) {
		if ((line_used + max_length) > LINE_LEN) {
			strcpy(&line[line_used], "\n");

			display_text(line);

			line_used = 0;
		}

		entry = l_strdup_printf("%-*s ", max_length, matches[index]);
		strcpy(&line[line_used], entry);
		l_free(entry);

		line_used += max_length + 1;
	}

	strcpy(&line[line_used], "\n");

	display_text(line);
}

#define MAX_PASSPHRASE_LEN 63

static struct masked_input {
	bool use_mask;
	char passphrase[MAX_PASSPHRASE_LEN];
	char mask[MAX_PASSPHRASE_LEN];
} masked_input;

static void mask_input(void)
{
	int point;
	char *line;
	size_t len;

	if (!masked_input.use_mask)
		return;

	line = rl_copy_text(0, rl_end);
	len = strlen(line);

	if (!len)
		goto done;

	point = rl_point;

	if (len > MAX_PASSPHRASE_LEN) {
		point--;
	} else if (strlen(masked_input.passphrase) > len) {
		masked_input.passphrase[len] = 0;
		masked_input.mask[len] = 0;
	} else {
		masked_input.passphrase[len - 1] = line[len - 1];
		masked_input.mask[len - 1] = '*';
	}

	rl_replace_line("", 0);
	rl_redisplay();
	rl_replace_line(masked_input.mask, 0);
	rl_point = point;
	rl_redisplay();

done:
	l_free(line);
}

static void reset_masked_input(void)
{
	memset(masked_input.passphrase, 0, MAX_PASSPHRASE_LEN);
	memset(masked_input.mask, 0, MAX_PASSPHRASE_LEN);
}

static void readline_callback(char *prompt)
{
	char **argv;
	int argc;

	HIST_ENTRY *previous_prompt;

	if (!prompt) {
		display_quit();

		l_main_quit();

		return;
	}

	if (agent_prompt(masked_input.use_mask ?
					masked_input.passphrase : prompt))
		goto done;

	if (!strlen(prompt))
		goto done;

	previous_prompt = history_get(history_base + history_length - 1);
	if (!previous_prompt || strcmp(previous_prompt->line, prompt)) {
		add_history(prompt);
	}

	argv = l_parse_args(prompt, &argc);
	if (!argv) {
		display("Invalid command\n");
		goto done;
	}

	command_process_prompt(argv, argc);

	l_strfreev(argv);
done:
	l_free(prompt);
}

bool display_agent_is_active(void)
{
	if (agent_saved_input)
		return true;

	return false;
}

static bool read_handler(struct l_io *io, void *user_data)
{
	rl_callback_read_char();

	if (display_agent_is_active())
		mask_input();

	return true;
}

static void disconnect_callback(struct l_io *io, void *user_data)
{
	l_main_quit();
}

void display_enable_cmd_prompt(void)
{
	if (!io)
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

void display_agent_prompt(const char *label, bool mask_input)
{
	char *prompt;

	if (agent_saved_input)
		return;

	masked_input.use_mask = mask_input;

	if (mask_input)
		reset_masked_input();

	agent_saved_input = l_new(struct saved_input, 1);

	agent_saved_input->point = rl_point;
	agent_saved_input->line = rl_copy_text(0, rl_end);
	rl_set_prompt("");
	rl_replace_line("", 0);
	rl_redisplay();

	rl_erase_empty_line = 0;

	prompt = l_strdup_printf(COLOR_BLUE "%s " COLOR_OFF, label);
	rl_set_prompt(prompt);
	l_free(prompt);

	rl_forced_update_display();
}

void display_agent_prompt_release(const char *label)
{
	if (!agent_saved_input)
		return;

	if (display_refresh.cmd) {
		char *text = rl_copy_text(0, rl_end);
		char *prompt = l_strdup_printf(COLOR_BLUE "%s " COLOR_OFF
							"%s\n", label, text);
		l_free(text);

		l_queue_push_tail(display_refresh.redo_entries, prompt);
		display_refresh.undo_lines++;
	}

	rl_erase_empty_line = 1;

	rl_replace_line(agent_saved_input->line, 0);
	rl_point = agent_saved_input->point;

	l_free(agent_saved_input->line);
	l_free(agent_saved_input);
	agent_saved_input = NULL;

	rl_set_prompt(IWD_PROMPT);
}

void display_quit(void)
{
	rl_insert_text("quit");
	rl_redisplay();
	rl_crlf();
}

static void signal_handler(void *user_data)
{
	if (display_refresh.cmd)
		display_refresh_reset();
}

void display_init(void)
{
	display_refresh.redo_entries = l_queue_new();

	setlinebuf(stdout);

	resize_signal = l_signal_create(SIGWINCH, signal_handler, NULL, NULL);

	rl_attempted_completion_function = command_completion;
	rl_completion_display_matches_hook = display_completion_matches;

	rl_erase_empty_line = 1;
	rl_callback_handler_install("Waiting for IWD to appear...",
							readline_callback);
	rl_redisplay();
}

void display_exit(void)
{
	if (agent_saved_input) {
		l_free(agent_saved_input->line);
		l_free(agent_saved_input);
		agent_saved_input = NULL;
	}

	l_timeout_remove(refresh_timeout);
	refresh_timeout = NULL;

	l_queue_destroy(display_refresh.redo_entries, l_free);

	rl_callback_handler_remove();

	l_io_destroy(io);

	l_signal_remove(resize_signal);

	display_quit();
}
