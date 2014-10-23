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

#include <ell/ell.h>
#include "src/dbus.h"
#include "src/manager.h"

struct l_dbus *g_dbus = 0;

static void do_debug(const char *str, void *user_data)
{
	const char *prefix = user_data;

	l_info("%s%s", prefix, str);
}

void dbus_dict_append_string(struct l_dbus_message_builder *builder,
				const char *key, const char *strval)
{
	l_dbus_message_builder_enter_dict(builder, "sv");
	l_dbus_message_builder_append_basic(builder, 's', key);
	l_dbus_message_builder_enter_variant(builder, "s");
	l_dbus_message_builder_append_basic(builder, 's', strval);
	l_dbus_message_builder_leave_variant(builder);
	l_dbus_message_builder_leave_dict(builder);
}

static void request_name_callback(struct l_dbus_message *message,
					void *user_data)
{
	const char *error, *text;
	uint32_t result;

	if (l_dbus_message_get_error(message, &error, &text)) {
		l_error("error=%s", error);
		l_error("message=%s", text);
		return;
	}

	if (!l_dbus_message_get_arguments(message, "u", &result))
		return;

	l_info("request name result=%d", result);
}

static void request_name_setup(struct l_dbus_message *message, void *user_data)
{
	const char *name = "net.connman.iwd";

	l_dbus_message_set_arguments(message, "su", name, 0);
}

static void ready_callback(void *user_data)
{
	l_info("ready");
	manager_init(g_dbus);
}

static void disconnect_callback(void *user_data)
{
	l_info("D-Bus disconnected, quitting...");
	l_main_quit();
}

struct l_dbus *dbus_get_bus(void)
{
	return g_dbus;
}

bool dbus_init(void)
{
	g_dbus = l_dbus_new_default(L_DBUS_SYSTEM_BUS);
	l_dbus_set_debug(g_dbus, do_debug, "[DBUS] ", NULL);
	l_dbus_set_ready_handler(g_dbus, ready_callback, g_dbus, NULL);
	l_dbus_set_disconnect_handler(g_dbus, disconnect_callback, NULL, NULL);

	l_dbus_method_call(g_dbus, "org.freedesktop.DBus",
				"/org/freedesktop/DBus",
				"org.freedesktop.DBus", "RequestName",
				request_name_setup,
				request_name_callback, NULL, NULL);

	return true;
}

bool dbus_exit(void)
{
	manager_exit(g_dbus);
	l_dbus_destroy(g_dbus);
	g_dbus = NULL;

	return true;
}
