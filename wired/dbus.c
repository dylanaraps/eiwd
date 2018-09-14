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

static struct l_dbus *dbus;

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
	l_dbus_name_acquire(dbus, "net.connman.ead", false, false, true,
						request_name_callback, NULL);
}

static void dbus_disconnected(void *user_data)
{
	l_info("D-Bus disconnected, quitting...");
	l_main_quit();
}

bool dbus_init(void)
{
	dbus = l_dbus_new_default(L_DBUS_SYSTEM_BUS);
	if (!dbus) {
		l_error("Failed to initialize D-Bus");
		return false;
	}

	l_dbus_set_ready_handler(dbus, dbus_ready, dbus, NULL);
	l_dbus_set_disconnect_handler(dbus, dbus_disconnected, NULL, NULL);

	return true;
}

void dbus_exit(void)
{
	l_dbus_destroy(dbus);
	dbus = NULL;
}
