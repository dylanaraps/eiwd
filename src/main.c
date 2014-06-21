/*
 *
 *  Wireless daemon for Linux
 *
 *  Copyright (C) 2013-2014  Intel Corporation. All rights reserved.
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

#include <stdlib.h>
#include <ell/ell.h>

#include "src/netdev.h"
#include "src/kdbus.h"

static void signal_handler(struct l_signal *signal, uint32_t signo,
							void *user_data)
{
	switch (signo) {
	case SIGINT:
	case SIGTERM:
		l_info("Terminate");
		l_main_quit();
		break;
	}
}

int main(int argc, char *argv[])
{
	struct l_signal *signal;
	sigset_t mask;
	char *bus_name;
	int exit_status;

	sigemptyset(&mask);
	sigaddset(&mask, SIGINT);
	sigaddset(&mask, SIGTERM);

	signal = l_signal_create(&mask, signal_handler, NULL, NULL);

	l_log_set_stderr();
	l_debug_enable("*");

	l_info("Wireless daemon version %s", VERSION);

	if (!kdbus_create_bus()) {
		exit_status = EXIT_FAILURE;
		goto done;
	}

	bus_name = kdbus_lookup_bus();
	if (!bus_name) {
		exit_status = EXIT_FAILURE;
		goto destroy;
	}

	l_debug("Bus location: %s", bus_name);

	if (!kdbus_open_bus(bus_name, "net.connman.iwd", "iwd")) {
		exit_status = EXIT_FAILURE;
		goto destroy;
	}

	if (!netdev_init()) {
		exit_status = EXIT_FAILURE;
		goto destroy;
	}

	l_main_run();

	netdev_exit();

	exit_status = EXIT_SUCCESS;

destroy:
	l_free(bus_name);

	kdbus_destroy_bus();

done:
	l_signal_remove(signal);

	return exit_status;
}
