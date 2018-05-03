/*
 *
 *  Wireless daemon for Linux
 *
 *  Copyright (C) 2017  Intel Corporation. All rights reserved.
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

#include "agent.h"
#include "dbus-proxy.h"
#include "display.h"

#define IWD_AGENT_INTERFACE "net.connman.iwd.Agent"

static struct l_dbus_message *pending_message;

static void setup_agent_interface(struct l_dbus_interface *interface)
{
}

bool agent_prompt(const char *prompt)
{
	return false;
}

bool agent_init(const char *path)
{
	struct l_dbus *dbus = dbus_get_bus();

	if (!l_dbus_register_interface(dbus, IWD_AGENT_INTERFACE,
					setup_agent_interface, NULL, false)) {
		l_info("Unable to register %s interface", IWD_AGENT_INTERFACE);

		return false;
	}

	if (!l_dbus_object_add_interface(dbus, path, IWD_AGENT_INTERFACE,
									NULL)) {
		l_info("Unable to register the agent manager object on '%s'",
								path);
		l_dbus_unregister_interface(dbus, IWD_AGENT_INTERFACE);

		return false;
	}

	return true;
}

bool agent_exit(const char *path)
{
	struct l_dbus *dbus = dbus_get_bus();

	if (pending_message)
		l_dbus_message_unref(pending_message);

	l_dbus_unregister_object(dbus, path);
	l_dbus_unregister_interface(dbus, IWD_AGENT_INTERFACE);

	return true;
}
