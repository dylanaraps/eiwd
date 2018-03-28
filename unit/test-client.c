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

#include "client/network.h"

struct network_args_data {
	const char *args;
	const char *name;
	const char *type;
};

static const struct network_args_data network_args_data_1[] = {
	{ "" },
	{ "\0" },
	{ }
};

static const struct network_args_data network_args_data_2[] = {
	{ "network psk", "network", "psk" },
	{ "  network  psk", "network", "psk" },
	{ "network  ", "network"},
	{ "\" psk", "\"", "psk" },
	{ "\"network psk", "\"network", "psk" },
	{ "\"network name\"", "network name" },
	{ "\"network \"name\"", "network \"name" },
	{ "\"network \"psk", "network ", "psk"},
	{ "\"network name\" psk", "network name", "psk" },
	{ }
};

static void network_parse_no_args_test(const void *data)
{
	const struct network_args_data *validation_list = data;
	size_t i;
	struct network_args *network_args;

	for (i = 0; validation_list[i].args; i++) {
		network_args = network_parse_args(validation_list[i].args);
		assert(!network_args);
	}
}

static void network_parse_args_test(const void *data)
{
	const struct network_args_data *validation_list = data;
	size_t i;
	struct network_args *network_args;

	for (i = 0; validation_list[i].args; i++) {
		network_args = network_parse_args(validation_list[i].args);

		assert(network_args);
		assert(!strcmp(network_args->name, validation_list[i].name));

		if (validation_list[i].type)
			assert(!strcmp(network_args->type,
						validation_list[i].type));

		network_args_destroy(network_args);
	}
}

int main(int argc, char *argv[])
{
	l_test_init(&argc, &argv);

	l_test_add("/Network/Parse no args",
			network_parse_no_args_test, &network_args_data_1);
	l_test_add("/Network/Parse args", network_parse_args_test,
							&network_args_data_2);

	return l_test_run();
}
