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

void display_refresh_timeout_set(void)
{

}

void display_refresh_reset(void)
{

}

void display_refresh_set_cmd(const char *family, const char *entity,
					const struct command *cmd, char *args)
{

}

static void display_text(const char *text)
{
	struct saved_input *input = save_input();

	printf("%s", text);

	restore_input(input);
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
}

void display_disable_cmd_prompt(void)
{
	rl_set_prompt("");
	rl_crlf();
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

	setlinebuf(stdout);

	rl_erase_empty_line = 1;
	rl_callback_handler_install("Waiting for IWD to appear...",
							readline_callback);
	rl_redisplay();
}

void display_exit(void)
{
	rl_callback_handler_remove();

	l_io_destroy(io);
}
