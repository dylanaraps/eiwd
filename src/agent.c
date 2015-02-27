/*
 *
 *  Wireless daemon for Linux
 *
 *  Copyright (C) 2015  Intel Corporation. All rights reserved.
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

#include <ell/ell.h>
#include "src/dbus.h"
#include "src/agent.h"

struct agent {
	char *owner;
	char *path;
	unsigned int disconnect_watch;
	uint32_t pending_id;
	struct l_timeout *timeout;
	int timeout_secs;
	struct l_queue *requests;
};

static struct agent *default_agent = NULL;

static void agent_free(void *data)
{
	struct agent *agent = data;

	l_debug("agent free %p", agent);

	if (agent->timeout)
		l_timeout_remove(agent->timeout);

	if (agent->disconnect_watch)
		l_dbus_remove_watch(dbus_get_bus(), agent->disconnect_watch);

	l_free(agent->owner);
	l_free(agent->path);
	l_free(agent);

	default_agent = NULL;
}

static void agent_disconnect(struct l_dbus *dbus, void *user_data)
{
	struct agent *agent = user_data;

	l_debug("agent %s disconnected", agent->owner);

	l_idle_oneshot(agent_free, agent, NULL);
}

static struct agent *agent_create(struct l_dbus *dbus, const char *name,
				const char *path)
{
	struct agent *agent;

	agent = l_new(struct agent, 1);

	agent->owner = l_strdup(name);
	agent->path = l_strdup(path);
	agent->requests = l_queue_new();
	agent->disconnect_watch = l_dbus_add_disconnect_watch(dbus, name,
						agent_disconnect,
						agent, NULL);
	return agent;
}

static struct l_dbus_message *agent_register(struct l_dbus *dbus,
						struct l_dbus_message *message,
						void *user_data)
{
	struct l_dbus_message *reply;
	struct agent *agent;
	const char *path;

	if (default_agent)
		return dbus_error_already_exists(message);

	l_debug("agent register called");

	if (!l_dbus_message_get_arguments(message, "o", &path))
		return dbus_error_invalid_args(message);

	agent = agent_create(dbus, l_dbus_message_get_sender(message), path);
	if (!agent)
		return dbus_error_failed(message);

	default_agent = agent;

	l_debug("agent %s path %s", agent->owner, agent->path);

	reply = l_dbus_message_new_method_return(message);

	l_dbus_message_set_arguments(reply, "");

	return reply;
}

static struct l_dbus_message *agent_unregister(struct l_dbus *dbus,
						struct l_dbus_message *message,
						void *user_data)
{
	struct l_dbus_message *reply;
	const char *path, *sender;

	if (!default_agent)
		return dbus_error_failed(message);

	l_debug("agent unregister");

	if (!l_dbus_message_get_arguments(message, "o", &path))
		return dbus_error_invalid_args(message);

	sender = l_dbus_message_get_sender(message);

	if (!strcmp(default_agent->owner, sender))
		return dbus_error_not_found(message);

	agent_free(default_agent);

	reply = l_dbus_message_new_method_return(message);

	l_dbus_message_set_arguments(reply, "");

	return reply;
}

bool agent_setup(struct l_dbus_interface *interface)
{
	l_dbus_interface_method(interface, "RegisterAgent", 0,
				agent_register,
				"", "o", "path");
	l_dbus_interface_method(interface, "UnregisterAgent", 0,
				agent_unregister,
				"", "o", "path");

	return true;
}

bool agent_init(void)
{
	return true;
}

void agent_exit(void)
{
	return;
}
