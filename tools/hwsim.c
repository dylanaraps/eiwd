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

#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <ell/ell.h>

enum {
	HWSIM_CMD_UNSPEC,
	HWSIM_CMD_REGISTER,
	HWSIM_CMD_FRAME,
	HWSIM_CMD_TX_INFO_FRAME,
	HWSIM_CMD_CREATE_RADIO,
	HWSIM_CMD_DESTROY_RADIO,
	__HWSIM_CMD_MAX,
};
#define HWSIM_CMD_MAX (_HWSIM_CMD_MAX - 1)

enum {
	HWSIM_ATTR_UNSPEC,
	HWSIM_ATTR_ADDR_RECEIVER,
	HWSIM_ATTR_ADDR_TRANSMITTER,
	HWSIM_ATTR_FRAME,
	HWSIM_ATTR_FLAGS,
	HWSIM_ATTR_RX_RATE,
	HWSIM_ATTR_SIGNAL,
	HWSIM_ATTR_TX_INFO,
	HWSIM_ATTR_COOKIE,
	HWSIM_ATTR_CHANNELS,
	HWSIM_ATTR_RADIO_ID,
	HWSIM_ATTR_REG_HINT_ALPHA2,
	HWSIM_ATTR_REG_CUSTOM_REG,
	HWSIM_ATTR_REG_STRICT_REG,
	HWSIM_ATTR_SUPPORT_P2P_DEVICE,
	HWSIM_ATTR_USE_CHANCTX,
	HWSIM_ATTR_DESTROY_RADIO_ON_CLOSE,
	__HWSIM_ATTR_MAX,
};
#define HWSIM_ATTR_MAX (__HWSIM_ATTR_MAX - 1)

static struct l_genl_family *hwsim;

static bool keep_radios = false;
static bool create_action = false;
static const char *destroy_action = NULL;

static void do_debug(const char *str, void *user_data)
{
	const char *prefix = user_data;

	l_info("%s%s", prefix, str);
}

static void create_callback(struct l_genl_msg *msg, void *user_data)
{
	struct l_genl_attr attr;
	uint32_t radio_id = 0;

	/*
	 * Note that the radio id is returned in the error field of
	 * the returned message.
	 */
	if (!l_genl_attr_init(&attr, msg)) {
		int err = l_genl_msg_get_error(msg);
		if (err < 0) {
			l_warn("Failed to initialize create return attributes"
				" [%d/%s]", -err, strerror(-err));
			goto done;
		}

		radio_id = err;

		l_info("Created new radio with id %u", radio_id);
	} else {
		l_warn("Failed to get create return value");
		goto done;
	}

done:
	l_main_quit();
}

static void destroy_callback(struct l_genl_msg *msg, void *user_data)
{
	struct l_genl_attr attr;
	uint16_t type, len;
	const void *data;

	if (!l_genl_attr_init(&attr, msg)) {
		int err = l_genl_msg_get_error(msg);
		if (err < 0) {
			l_warn("Failed to destroy radio [%d/%s]",
				-err, strerror(-err));
			goto done;
		}

		l_info("Destroyed radio");
	}

	while (l_genl_attr_next(&attr, &type, &len, &data)) {
	}

done:
	l_main_quit();
}

static void hwsim_ready(void *user_data)
{
	struct l_genl_msg *msg;

	if (create_action) {
		msg = l_genl_msg_new_sized(HWSIM_CMD_CREATE_RADIO,
					keep_radios ? 0 : 4);
		if (!keep_radios)
			l_genl_msg_append_attr(msg,
					HWSIM_ATTR_DESTROY_RADIO_ON_CLOSE,
					0, NULL);

		l_genl_family_send(hwsim, msg, create_callback, NULL, NULL);
		l_genl_msg_unref(msg);
		return;
	} else if (destroy_action) {
		uint32_t id = atoi(destroy_action);

		msg = l_genl_msg_new_sized(HWSIM_CMD_DESTROY_RADIO, 8);
		l_genl_msg_append_attr(msg, HWSIM_ATTR_RADIO_ID, 4, &id);
		l_genl_family_send(hwsim, msg, destroy_callback, NULL, NULL);
		l_genl_msg_unref(msg);
	} else
		l_main_quit();
}

static void signal_handler(struct l_signal *signal, uint32_t signo,
							void *user_data)
{
	switch (signo) {
	case SIGINT:
	case SIGTERM:
		l_main_quit();
		break;
	}
}

static void usage(void)
{
	printf("hwsim - Wireless simulator\n"
		"Usage:\n");
	printf("\thwsim [options]\n");
	printf("Options:\n"
		"\t-C, --create           Create new simulated radio\n"
		"\t-D, --destroy <id>     Destroy existing radio\n"
		"\t-k, --keep             Do not destroy radios when "
							"program exits\n"
		"\t-h, --help             Show help options\n");
}

static const struct option main_options[] = {
	{ "create",    no_argument,       NULL, 'C' },
	{ "destroy",   required_argument, NULL, 'D' },
	{ "keep",      no_argument,       NULL, 'k' },
	{ "version",   no_argument,       NULL, 'v' },
	{ "help",      no_argument,       NULL, 'h' },
	{ }
};

int main(int argc, char *argv[])
{
	struct l_signal *signal;
	struct l_genl *genl;
	sigset_t mask;
	int exit_status;

	for (;;) {
		int opt;

		opt = getopt_long(argc, argv, "CD:vhk", main_options, NULL);
		if (opt < 0)
			break;

		switch (opt) {
		case 'C':
			create_action = true;
			break;
		case 'D':
			destroy_action = optarg;
			break;
		case 'k':
			keep_radios = true;
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

	if (create_action && destroy_action) {
		fprintf(stderr, "Only one action can be specified\n");
		return EXIT_FAILURE;
	}

	if (!create_action && !destroy_action) {
		fprintf(stderr, "No action has been specified\n");
		return EXIT_FAILURE;
	}

	sigemptyset(&mask);
	sigaddset(&mask, SIGINT);
	sigaddset(&mask, SIGTERM);

	signal = l_signal_create(&mask, signal_handler, NULL, NULL);

	l_log_set_stderr();

	printf("Wireless simulator ver %s\n", VERSION);

	genl = l_genl_new_default();
	if (!genl) {
		fprintf(stderr, "Failed to initialize generic netlink\n");
		exit_status = EXIT_FAILURE;
		goto done;
	}

	if (getenv("HWSIM_DEBUG"))
		l_genl_set_debug(genl, do_debug, "[GENL] ", NULL);

	hwsim = l_genl_family_new(genl, "MAC80211_HWSIM");
	if (!hwsim) {
		fprintf(stderr, "Failed to create generic netlink family\n");
		l_genl_unref(genl);
		exit_status = EXIT_FAILURE;
		goto done;
	}

	l_genl_family_set_watches(hwsim, hwsim_ready, NULL, NULL, NULL);

	l_main_run();

	l_genl_family_unref(hwsim);
	l_genl_unref(genl);

	exit_status = EXIT_SUCCESS;

done:
	l_signal_remove(signal);

	return exit_status;
}
