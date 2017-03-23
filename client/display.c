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

#include "display.h"

#define IWD_PROMPT COLOR_GREEN "[iwd]" COLOR_OFF "# "
#define LINE_LEN   81

static struct l_queue *display_types;
static struct l_io *io;
static char dashed_line[LINE_LEN];
static char empty_line[LINE_LEN];

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
	l_main_exit();
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

void display_init(void)
{
	memset(&dashed_line, '-', sizeof(dashed_line) - 1);
	memset(&empty_line, ' ', sizeof(empty_line) - 1);

	display_types = l_queue_new();

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

	l_queue_destroy(display_types, NULL);
	display_types = NULL;
}
