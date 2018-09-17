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
#include "wired/dbus.h"
#include "wired/ethdev.h"
#include "wired/network.h"

struct main_opts {
	const char *interfaces;
	const char *nointerfaces;
};

static void dbus_ready(struct l_dbus *dbus, void *user_data)
{
	struct main_opts *opts = user_data;

	l_info("System ready");

	eap_init(0);
	network_init();
	ethdev_init(opts->interfaces, opts->nointerfaces);
}

static void dbus_shutdown(struct l_dbus *dbus, void *user_data)
{
	l_info("System shutdown");

	ethdev_exit();
	network_exit();
	eap_exit();

	dbus_app_shutdown_complete();
}

static const struct dbus_app app = {
	.bus		= L_DBUS_SYSTEM_BUS,
	.name		= "net.connman.ead",
	.ready		= dbus_ready,
	.shutdown	= dbus_shutdown,
};

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
	struct main_opts opts;
	const char *debugopt = NULL;

	opts.interfaces = NULL;
	opts.nointerfaces = NULL;

	for (;;) {
		int opt;

		opt = getopt_long(argc, argv, "i:I:d::vh", main_options, NULL);
		if (opt < 0)
			break;

		switch (opt) {
		case 'i':
			opts.interfaces = optarg;
			break;
		case 'I':
			opts.nointerfaces = optarg;
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

	if (debugopt)
		l_debug_enable(debugopt);

	l_info("Authentication daemon version %s", VERSION);

	return dbus_app_run(&app, &opts, NULL);
}
