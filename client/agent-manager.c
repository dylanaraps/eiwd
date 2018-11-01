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
#include <unistd.h>

#include "agent.h"
#include "dbus-proxy.h"
#include "agent-manager.h"

#define IWD_AGENT_MANAGER_INTERFACE	"net.connman.iwd.AgentManager"
#define IWD_AGENT_MANAGER_PATH		"/"

static void check_errors_method_callback(struct l_dbus_message *message,
								void *user_data)
{
	dbus_message_has_error(message);
}

bool agent_manager_register_agent(void)
{
	const char *path;
	const struct proxy_interface *proxy =
		proxy_interface_find(IWD_AGENT_MANAGER_INTERFACE,
							IWD_AGENT_MANAGER_PATH);

	if (!proxy)
		return false;

	path = proxy_interface_get_data(proxy);
	if (!path)
		return false;

	proxy_interface_method_call(proxy, "RegisterAgent", "o",
					check_errors_method_callback, path);

	return true;
}

bool agent_manager_unregister_agent(void)
{
	const char *path;
	const struct proxy_interface *proxy =
		proxy_interface_find(IWD_AGENT_MANAGER_INTERFACE,
							IWD_AGENT_MANAGER_PATH);

	if (!proxy)
		return false;

	path = proxy_interface_get_data(proxy);
	if (!path)
		return false;

	proxy_interface_method_call(proxy, "UnregisterAgent", "o",
					check_errors_method_callback, path);

	return true;
}

static void *agent_manager_create(void)
{
	char *path = l_strdup_printf("/agent/%i", getpid());

	agent_init(path);

	return path;
}

static void agent_manager_destroy(void *data)
{
	char *path = data;

	agent_exit(path);

	l_free(path);
}

static const struct proxy_interface_type_ops agent_manager_ops = {
	.create = agent_manager_create,
	.destroy = agent_manager_destroy,
};

static struct proxy_interface_type agent_manager_interface_type = {
	.interface = IWD_AGENT_MANAGER_INTERFACE,
	.ops = &agent_manager_ops,
};

static int agent_manager_interface_init(void)
{
	proxy_interface_type_register(&agent_manager_interface_type);

	return 0;
}

static void agent_manager_interface_exit(void)
{
	proxy_interface_type_unregister(&agent_manager_interface_type);
}

INTERFACE_TYPE(agent_manager_interface_type, agent_manager_interface_init,
						agent_manager_interface_exit)
