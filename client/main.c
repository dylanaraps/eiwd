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

#include <errno.h>
#include <signal.h>
#include <ell/ell.h>

#include "command.h"
#include "display.h"
#include "dbus-proxy.h"

static void signal_handler(uint32_t signo, void *user_data)
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
	int exit_status;
	bool interactive;

	if (!l_main_init())
		return EXIT_FAILURE;

	l_log_set_stderr();

	interactive = command_init(argv, argc);

	if (interactive)
		display_init();

	dbus_proxy_init();

	l_main_run_with_signal(signal_handler, NULL);

	dbus_proxy_exit();

	if (interactive)
		display_exit();

	exit_status = command_get_exit_status();
	command_exit();

	l_main_exit();

	return exit_status;
}
