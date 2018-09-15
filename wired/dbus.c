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

#include <ell/ell.h>

#include "wired/dbus.h"

static struct l_dbus *dbus = NULL;

struct l_dbus *dbus_get(void)
{
	return dbus;
}

struct dbus_info {
	char *name;
	dbus_ready_func_t ready_func;
	void *user_data;
};

static void request_name_callback(struct l_dbus *dbus, bool success,
						bool queued, void *user_data)
{
	struct dbus_info *info = user_data;

	if (!success) {
		l_error("Failed to request D-Bus service Name");
		l_main_quit();
		return;
	}

	if (!l_dbus_object_manager_enable(dbus))
		l_warn("Unable to register ObjectManager interface");

	if (info->ready_func)
		info->ready_func(dbus, info->user_data);
}

static void dbus_ready(void *user_data)
{
	struct dbus_info *info = user_data;

	l_dbus_name_acquire(dbus, info->name, false, false, true,
						request_name_callback, info);
}

static void dbus_disconnected(void *user_data)
{
	l_info("D-Bus disconnected, quitting...");
	l_main_quit();
}

static void dbus_signal_handler(uint32_t signo, void *user_data)
{
	switch (signo) {
	case SIGINT:
	case SIGTERM:
		l_info("Terminate");
		l_main_quit();
		break;
	}
}

int dbus_run(enum l_dbus_bus bus, const char *name,
					dbus_ready_func_t ready_func,
					dbus_shutdown_func_t shutdown_func,
					void *user_data,
					dbus_destroy_func_t destroy)
{
	struct dbus_info *info;
	int exit_status;

	if (dbus)
		return EXIT_FAILURE;

	if (!l_main_init())
		return EXIT_FAILURE;

	dbus = l_dbus_new_default(bus);
	if (!dbus) {
		l_error("Failed to initialize D-Bus");
		return EXIT_FAILURE;
	}

	info = l_new(struct dbus_info, 1);
	info->name = l_strdup(name);
	info->ready_func = ready_func;
	info->user_data = user_data;

	l_dbus_set_ready_handler(dbus, dbus_ready, info, NULL);
	l_dbus_set_disconnect_handler(dbus, dbus_disconnected, info, NULL);

	exit_status = l_main_run_with_signal(dbus_signal_handler, info);

	if (shutdown_func)
		shutdown_func(dbus, info->user_data);

	l_dbus_destroy(dbus);
	dbus = NULL;

	if (destroy)
		destroy(info->user_data);

	l_free(info->name);
	l_free(info);

	return exit_status;
}
