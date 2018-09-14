/*
 *
 *  Ethernet daemon for Linux
 *
 *  Copyright (C) 2017-2018  Intel Corporation. All rights reserved.
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
#include <stdlib.h>
#include <errno.h>
#include <getopt.h>
#include <ell/ell.h>

#include "src/eap.h"
#include "wired/ethdev.h"
#include "wired/network.h"

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

static void request_name_callback(struct l_dbus *dbus, bool success,
						bool queued, void *user_data)
{
	if (!success) {
		l_error("Failed to request D-Bus service Name");
		l_main_quit();
		return;
	}

	if (!l_dbus_object_manager_enable(dbus))
		l_warn("Unable to register ObjectManager interface");
}

static void dbus_ready(void *user_data)
{
	struct l_dbus *dbus = user_data;

	l_dbus_name_acquire(dbus, "net.connman.ead", false, false, true,
						request_name_callback, NULL);
}

static void dbus_disconnected(void *user_data)
{
	l_info("D-Bus disconnected, quitting...");
	l_main_quit();
}

static void usage(void)
{
	printf("ead - Authentication daemon\n"
		"Usage:\n");
	printf("\tead [options]\n");
	printf("Options:\n"
		"\t-i, --interfaces       Interfaces to manage\n"
		"\t-I, --nointerfaces     Interfaces to ignore\n"
		"\t-d, --debug            Enable debug output\n"
		"\t-h, --help             Show help options\n");
}

static const struct option main_options[] = {
	{ "interfaces",   required_argument, NULL, 'i' },
	{ "nointerfaces", required_argument, NULL, 'I' },
	{ "debug",        optional_argument, NULL, 'd' },
	{ "version",	  no_argument,       NULL, 'v' },
	{ "help",         no_argument,       NULL, 'h' },
	{ }
};

int main(int argc, char *argv[])
{
	struct l_signal *signal;
	sigset_t mask;
	int exit_status;
	struct l_dbus *dbus;
	const char *interfaces = NULL;
	const char *nointerfaces = NULL;
	const char *debugopt = NULL;

	for (;;) {
		int opt;

		opt = getopt_long(argc, argv, "i:I:d::vh", main_options, NULL);
		if (opt < 0)
			break;

		switch (opt) {
		case 'i':
			interfaces = optarg;
			break;
		case 'I':
			nointerfaces = optarg;
			break;
		case 'd':
			if (optarg)
				debugopt = optarg;
			else if (argv[optind] && argv[optind][0] != '-')
				debugopt = argv[optind++];
			else
				debugopt = "*";
			break;
		case 'v':
			printf("%s\n", VERSION);
			return EXIT_SUCCESS;
		case 'h':
			usage();
			return EXIT_SUCCESS;
		default:
			return EXIT_FAILURE;
		}
	}

	if (argc - optind > 0) {
		fprintf(stderr, "Invalid command line parameters\n");
		return EXIT_FAILURE;
	}

	l_log_set_stderr();

	if (!l_main_init())
		return EXIT_FAILURE;

	sigemptyset(&mask);
	sigaddset(&mask, SIGINT);
	sigaddset(&mask, SIGTERM);

	signal = l_signal_create(&mask, signal_handler, NULL, NULL);

	if (debugopt)
		l_debug_enable(debugopt);

	l_info("Authentication daemon version %s", VERSION);

	exit_status = EXIT_FAILURE;

	dbus = l_dbus_new_default(L_DBUS_SYSTEM_BUS);
	if (!dbus) {
		l_error("Failed to initialize D-Bus");
		goto done;
	}

	l_dbus_set_ready_handler(dbus, dbus_ready, dbus, NULL);
	l_dbus_set_disconnect_handler(dbus, dbus_disconnected, NULL, NULL);

	eap_init(0);
	network_init();
	ethdev_init(interfaces, nointerfaces);

	exit_status = EXIT_SUCCESS;

	l_main_run();

	ethdev_exit();
	network_exit();
	eap_exit();

	l_dbus_destroy(dbus);

done:
	l_signal_remove(signal);

	l_main_exit();

	return exit_status;
}
