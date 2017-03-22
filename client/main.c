/*
 *
 *  Wireless daemon for Linux
 *
 *  Copyright (C) 2013-2017  Intel Corporation. All rights reserved.
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
#include <stdio.h>
#include <ell/ell.h>

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

static void signal_message(struct l_dbus_message *message, void *user_data)
{
	const char *path, *interface, *member, *destination, *sender;

	path = l_dbus_message_get_path(message);
	destination = l_dbus_message_get_destination(message);

	l_info("path=%s destination=%s", path, destination);

	interface = l_dbus_message_get_interface(message);
	member = l_dbus_message_get_member(message);

	l_info("interface=%s member=%s", interface, member);

	sender = l_dbus_message_get_sender(message);

	l_info("sender=%s", sender);
}

int main(int argc, char *argv[])
{
	int exit_status;
	struct l_dbus *dbus;
	struct l_signal *signal;
	sigset_t mask;

	if (!l_main_init())
		return EXIT_FAILURE;

	sigemptyset(&mask);
	sigaddset(&mask, SIGINT);
	sigaddset(&mask, SIGTERM);

	signal = l_signal_create(&mask, signal_handler, NULL, NULL);

	l_log_set_stderr();
	l_debug_enable("*");

	dbus = l_dbus_new_default(L_DBUS_SYSTEM_BUS);
	if (!dbus) {
		exit_status = EXIT_FAILURE;
		goto done;
	}

	l_dbus_add_signal_watch(dbus, "net.connman.iwd", NULL, NULL, NULL,
				L_DBUS_MATCH_NONE, signal_message, NULL);

	l_main_run();

	exit_status = EXIT_SUCCESS;

	l_dbus_destroy(dbus);

done:
	l_signal_remove(signal);

	l_main_exit();

	return exit_status;
}
