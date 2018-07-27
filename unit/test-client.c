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
#include <string.h>
#include <assert.h>
#include <ell/ell.h>
#include <readline/readline.h>

#include "client/dbus-proxy.h"
#include "client/network.h"
#include "client/command.h"

struct command_line_data {
	const char *command_line;
	const char *token;
	int tokens_to_compare;
	bool found;
};

static const struct command_line_data command_line_data_1[] = {
	{ "Token", "Token", 1, true },
	{ "Token  ", "Token", 1, true },
	{ " Token", "Token", 1, true },
	{ "Token1 Token2", "Token1", 2, true },
	{ "  Token1 Token2  ", "Token1", 2, true },
	{ "Token1 Token2", "Token3", 2, false },
	{ "Token1 Token2", "Token1", 1, false },
	{ }
};

static void command_line_find_tokens_test(const void *data)
{
	const struct command_line_data *validation_list = data;
	size_t i;
	bool found;

	for (i = 0; validation_list[i].command_line; i++) {
		rl_replace_line(validation_list[i].command_line, 0);
		rl_point = strlen(validation_list[i].command_line);

		found = command_line_find_token(validation_list[i].token,
					validation_list[i].tokens_to_compare);

		assert(found == validation_list[i].found);
	}
}

int main(int argc, char *argv[])
{
	l_test_init(&argc, &argv);

	l_test_add("/Command/Find tokens", command_line_find_tokens_test,
							&command_line_data_1);

	return l_test_run();
}
