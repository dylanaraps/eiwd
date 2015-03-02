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

/* Agent dbus request is done from iwd towards the agent */
struct agent_request {
	struct l_dbus_message *message;
	void *user_data;
};

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

static void send_request(struct agent *agent, const char *request)
{
	struct l_dbus_message *message;

	l_debug("send %s request to %s %s", request, agent->owner,
							agent->path);

	message = l_dbus_message_new_method_call(dbus_get_bus(),
						agent->owner,
						agent->path,
						IWD_AGENT_INTERFACE,
						request);

	l_dbus_message_set_arguments(message, "");

	l_dbus_send(dbus_get_bus(), message);
}

static void send_cancel_request(void *user_data)
{
	struct agent *agent = user_data;

	send_request(agent, "Cancel");
}

static void agent_request_free(void *user_data)
{
	struct agent_request *request = user_data;

	l_dbus_message_unref(request->message);

	l_free(request);
}

static void agent_finalize_pending(struct agent *agent,
						struct l_dbus_message *reply)
{
	struct agent_request *pending;

	if (agent->timeout) {
		l_timeout_remove(agent->timeout);
		agent->timeout = NULL;
	}

	pending = l_queue_pop_head(agent->requests);

	agent_request_free(pending);
}

static void agent_free(void *data)
{
	struct agent *agent = data;

	l_debug("agent free %p", agent);

	if (agent->timeout)
		l_timeout_remove(agent->timeout);

	if (agent->pending_id)
		l_dbus_cancel(dbus_get_bus(), agent->pending_id);

	l_queue_destroy(agent->requests, agent_request_free);

	if (agent->disconnect_watch)
		l_dbus_remove_watch(dbus_get_bus(), agent->disconnect_watch);

	l_free(agent->owner);
	l_free(agent->path);
	l_free(agent);

	default_agent = NULL;
}

static void agent_send_next_request(struct agent *agent);

static void request_timeout(struct l_timeout *timeout, void *user_data)
{
	struct agent *agent = user_data;

	l_dbus_cancel(dbus_get_bus(), agent->pending_id);

	send_cancel_request(agent);

	agent_finalize_pending(agent, NULL);

	agent_send_next_request(agent);
}

static void agent_receive_reply(struct l_dbus_message *message,
							void *user_data)
{
	struct agent *agent = user_data;

	l_debug("agent %p request id %u", agent, agent->pending_id);

	agent->pending_id = 0;

	agent_finalize_pending(agent, message);

	agent_send_next_request(agent);
}

static void agent_send_next_request(struct agent *agent)
{
	struct agent_request *pending;

	pending = l_queue_peek_head(agent->requests);
	if (!pending)
		return;

	agent->timeout = l_timeout_create(agent->timeout_secs,
						request_timeout,
						agent, NULL);

	l_debug("send request to %s %s", agent->owner, agent->path);

	agent->pending_id = l_dbus_send_with_reply(dbus_get_bus(),
						pending->message,
						agent_receive_reply,
						agent, NULL);

	pending->message = NULL;

	return;
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
