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

#include <signal.h>
#include <ell/ell.h>

#include "wired/dbus.h"

static struct l_dbus *dbus = NULL;

struct l_dbus *dbus_app_get(void)
{
	return dbus;
}

struct dbus_info {
	const struct dbus_app *app;
	void *user_data;
};

void dbus_app_shutdown_complete(void)
{
	l_main_quit();
}

static void dbus_shutdown(struct dbus_info *info)
{
	static bool terminated = false;

	if (!terminated) {
		terminated = true;

		if (info->app->shutdown)
			info->app->shutdown(dbus, info->user_data);
		else
			l_main_quit();
	}
}

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

	if (info->app->ready)
		info->app->ready(dbus, info->user_data);
}

static void dbus_ready(void *user_data)
{
	struct dbus_info *info = user_data;

	if (info->app->name) {
		l_dbus_name_acquire(dbus, info->app->name, false, false, true,
						request_name_callback, info);
		return;
	}

	if (info->app->ready)
		info->app->ready(dbus, info->user_data);
}

static void dbus_disconnected(void *user_data)
{
	struct dbus_info *info = user_data;

	l_info("D-Bus disconnected");
	dbus_shutdown(info);
}

static void dbus_signal_handler(uint32_t signo, void *user_data)
{
	struct dbus_info *info = user_data;

	switch (signo) {
	case SIGINT:
	case SIGTERM:
		l_info("Termination signal");
		dbus_shutdown(info);
		break;
	}
}

int dbus_app_run(const struct dbus_app *app, void *user_data,
					dbus_app_destroy_func_t destroy)
{
	struct dbus_info *info;
	int exit_status;

	if (dbus || !app)
		return EXIT_FAILURE;

	if (!l_main_init())
		return EXIT_FAILURE;

	dbus = l_dbus_new_default(app->bus);
	if (!dbus) {
		l_error("Failed to initialize D-Bus");
		return EXIT_FAILURE;
	}

	info = l_new(struct dbus_info, 1);
	info->app = app;
	info->user_data = user_data;

	l_dbus_set_ready_handler(dbus, dbus_ready, info, NULL);
	l_dbus_set_disconnect_handler(dbus, dbus_disconnected, info, NULL);

	exit_status = l_main_run_with_signal(dbus_signal_handler, info);

	l_dbus_destroy(dbus);
	dbus = NULL;

	l_main_exit();

	if (destroy)
		destroy(info->user_data);

	l_free(info);

	return exit_status;
}
