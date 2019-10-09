/*
 *
 *  Wireless daemon for Linux
 *
 *  Copyright (C) 2019  Intel Corporation. All rights reserved.
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
#include <arpa/inet.h>
#include <sys/stat.h>
#include <stdio.h>
#include <unistd.h>

#include <ell/ell.h>

#include "src/iwd.h"
#include "src/dbus.h"
#include "src/resolve.h"

struct resolve_method_ops {
	void *(*init)(void);
	void (*exit)(void *data);
	void (*add_dns)(uint32_t ifindex, uint8_t type, char **dns_list,
								void *data);
	void (*remove)(uint32_t ifindex, void *data);
};

struct resolve_method {
	void *data;
	const struct resolve_method_ops *ops;
};

static struct resolve_method method;
static char *resolvconf_path;

#define SYSTEMD_RESOLVED_SERVICE           "org.freedesktop.resolve1"
#define SYSTEMD_RESOLVED_MANAGER_PATH      "/org/freedesktop/resolve1"
#define SYSTEMD_RESOLVED_MANAGER_INTERFACE "org.freedesktop.resolve1.Manager"

struct systemd_state {
	uint32_t service_watch;
	bool is_ready:1;
};

static void systemd_link_dns_reply(struct l_dbus_message *message,
								void *user_data)
{
	const char *name;
	const char *text;

	if (!l_dbus_message_is_error(message))
		return;

	l_dbus_message_get_error(message, &name, &text);

	l_error("resolve-systemd: Failed to modify the DNS entries. %s: %s",
								name, text);
}

static bool systemd_builder_add_dns(struct l_dbus_message_builder *builder,
						uint8_t type, const char *dns)
{
	uint8_t buf[16];
	uint8_t buf_size;
	uint8_t i;
	int t = (int) type;

	l_debug("installing DNS: %s %u", dns, type);

	l_dbus_message_builder_append_basic(builder, 'i', &t);
	l_dbus_message_builder_enter_array(builder, "y");

	switch (type) {
	case AF_INET:
		if (inet_pton(AF_INET, dns, buf) < 1)
			return false;

		buf_size = 4;

		break;
	case AF_INET6:
		if (inet_pton(AF_INET6, dns, buf) < 1)
			return false;

		buf_size = 16;

		break;
	default:
		return false;
	}

	for (i = 0; i < buf_size; i++)
		l_dbus_message_builder_append_basic(builder, 'y', &buf[i]);

	l_dbus_message_builder_leave_array(builder);

	return true;
}

static void resolve_systemd_add_dns(uint32_t ifindex, uint8_t type,
						char **dns_list, void *data)
{
	struct systemd_state *state = data;
	struct l_dbus_message_builder *builder;
	struct l_dbus_message *message;

	l_debug("ifindex: %u", ifindex);

	if (!state->is_ready) {
		l_error("resolve-systemd: Failed to add DNS entries. "
				"Is 'systemd-resolved' service running?");

		return;
	}

	message =
		l_dbus_message_new_method_call(dbus_get_bus(),
					SYSTEMD_RESOLVED_SERVICE,
					SYSTEMD_RESOLVED_MANAGER_PATH,
					SYSTEMD_RESOLVED_MANAGER_INTERFACE,
					"SetLinkDNS");

	if (!message)
		return;

	builder = l_dbus_message_builder_new(message);
	if (!builder) {
		l_dbus_message_unref(message);
		return;
	}

	l_dbus_message_builder_append_basic(builder, 'i', &ifindex);

	l_dbus_message_builder_enter_array(builder, "(iay)");

	for (; *dns_list; dns_list++) {
		l_dbus_message_builder_enter_struct(builder, "iay");

		if (systemd_builder_add_dns(builder, type, *dns_list)) {
			l_dbus_message_builder_leave_struct(builder);

			continue;
		}

		l_dbus_message_builder_destroy(builder);
		l_dbus_message_unref(message);

		return;
	}

	l_dbus_message_builder_leave_array(builder);

	l_dbus_message_builder_finalize(builder);
	l_dbus_message_builder_destroy(builder);

	l_dbus_send_with_reply(dbus_get_bus(), message, systemd_link_dns_reply,
								state, NULL);
}

static void resolve_systemd_remove(uint32_t ifindex, void *data)
{
	struct systemd_state *state = data;
	struct l_dbus_message *message;

	l_debug("ifindex: %u", ifindex);

	if (!state->is_ready) {
		l_error("resolve-systemd: Failed to remove DNS entries. "
				"Is 'systemd-resolved' service running?");

		return;
	}

	message =
		l_dbus_message_new_method_call(dbus_get_bus(),
					SYSTEMD_RESOLVED_SERVICE,
					SYSTEMD_RESOLVED_MANAGER_PATH,
					SYSTEMD_RESOLVED_MANAGER_INTERFACE,
					"RevertLink");
	if (!message)
		return;

	l_dbus_message_set_arguments(message, "i", ifindex);

	l_dbus_send_with_reply(dbus_get_bus(), message, systemd_link_dns_reply,
								state, NULL);
}

static void systemd_appeared(struct l_dbus *dbus, void *user_data)
{
	struct systemd_state *state = user_data;

	state->is_ready = true;
}

static void systemd_disappeared(struct l_dbus *dbus, void *user_data)
{
	struct systemd_state *state = user_data;

	state->is_ready = false;
}

static void *resolve_systemd_init(void)
{
	struct systemd_state *state;

	state = l_new(struct systemd_state, 1);

	state->service_watch =
		l_dbus_add_service_watch(dbus_get_bus(),
						SYSTEMD_RESOLVED_SERVICE,
						systemd_appeared,
						systemd_disappeared,
						state, NULL);

	return state;
}

static void resolve_systemd_exit(void *data)
{
	struct systemd_state *state = data;

	l_dbus_remove_watch(dbus_get_bus(), state->service_watch);

	l_free(state);
}

static const struct resolve_method_ops resolve_method_systemd = {
	.init = resolve_systemd_init,
	.exit = resolve_systemd_exit,
	.add_dns = resolve_systemd_add_dns,
	.remove = resolve_systemd_remove,
};

static void resolve_resolvconf_add_dns(uint32_t ifindex, uint8_t type,
						char **dns_list, void *data)
{
	bool *ready = data;
	FILE *resolvconf;
	struct l_string *content;
	int error;
	L_AUTO_FREE_VAR(char *, cmd) = NULL;
	L_AUTO_FREE_VAR(char *, str) = NULL;

	if (!*ready)
		return;

	cmd = l_strdup_printf("%s -a %u", resolvconf_path, ifindex);

	if (!(resolvconf = popen(cmd, "w"))) {
		l_error("resolve: Failed to start %s (%s).", resolvconf_path,
							strerror(errno));
		return;
	}

	content = l_string_new(0);

	for (; *dns_list; dns_list++)
		l_string_append_printf(content, "nameserver %s\n", *dns_list);

	str = l_string_unwrap(content);

	if (fprintf(resolvconf, "%s", str) < 0)
		l_error("resolve: Failed to print into %s stdin.",
							resolvconf_path);

	error = pclose(resolvconf);
	if (error < 0)
		l_error("resolve: Failed to close pipe to %s (%s).",
					resolvconf_path, strerror(errno));
	else if (error > 0)
		l_info("resolve: %s exited with status (%d).", resolvconf_path,
									error);
}

static void resolve_resolvconf_remove(uint32_t ifindex, void *data)
{
	bool *ready = data;
	FILE *resolvconf;
	int error;
	L_AUTO_FREE_VAR(char *, cmd) = NULL;

	if (!*ready)
		return;

	cmd = l_strdup_printf("%s -d %u", resolvconf_path, ifindex);

	if (!(resolvconf = popen(cmd, "r"))) {
		l_error("resolve: Failed to start %s (%s).", resolvconf_path,
							strerror(errno));
		return;
	}

	error = pclose(resolvconf);
	if (error < 0)
		l_error("resolve: Failed to close pipe to %s (%s).",
					resolvconf_path, strerror(errno));
	else if (error > 0)
		l_info("resolve: %s exited with status (%d).", resolvconf_path,
									error);
}

static void *resolve_resolvconf_init(void)
{
	static const char *default_path = "/sbin:/usr/sbin";
	bool *ready;
	const char *path;

	ready = l_new(bool, 1);
	*ready = false;

	l_debug("Trying to find resolvconf in $PATH");
	path = getenv("PATH");
	if (path)
		resolvconf_path = l_path_find("resolvconf", path, X_OK);

	if (!resolvconf_path) {
		l_debug("Trying to find resolvconf in default paths");
		resolvconf_path = l_path_find("resolvconf", default_path, X_OK);
	}

	if (!resolvconf_path) {
		l_error("No usable resolvconf found on system");
		return ready;
	}

	l_debug("resolvconf found as: %s", resolvconf_path);
	*ready = true;
	return ready;
}

static void resolve_resolvconf_exit(void *data)
{
	bool *ready = data;

	l_free(resolvconf_path);
	resolvconf_path = NULL;
	l_free(ready);
}

static const struct resolve_method_ops resolve_method_resolvconf = {
	.init = resolve_resolvconf_init,
	.exit = resolve_resolvconf_exit,
	.add_dns = resolve_resolvconf_add_dns,
	.remove = resolve_resolvconf_remove,
};

void resolve_add_dns(uint32_t ifindex, uint8_t type, char **dns_list)
{
	if (!dns_list || !*dns_list)
		return;

	if (!method.ops || !method.ops->add_dns)
		return;

	method.ops->add_dns(ifindex, type, dns_list, method.data);
}

void resolve_remove(uint32_t ifindex)
{
	if (!method.ops || !method.ops->remove)
		return;

	method.ops->remove(ifindex, method.data);
}

static const struct {
	const char *name;
	const struct resolve_method_ops *method_ops;
} resolve_method_ops_list[] = {
	{ "systemd", &resolve_method_systemd },
	{ "resolvconf", &resolve_method_resolvconf },
	{ }
};

static int resolve_init(void)
{
	const char *method_name;
	bool enabled;
	uint8_t i;

	if (!l_settings_get_bool(iwd_get_config(), "General",
					"enable_network_config", &enabled) ||
								!enabled)
		return 0;

	method_name = l_settings_get_value(iwd_get_config(), "General",
							"dns_resolve_method");

	if (!method_name)
		/* Default to systemd-resolved service. */
		method_name = "systemd";

	for (i = 0; resolve_method_ops_list[i].name; i++) {
		if (strcmp(resolve_method_ops_list[i].name, method_name))
			continue;

		method.ops = resolve_method_ops_list[i].method_ops;

		break;
	}

	if (!method.ops)
		return -EINVAL;

	if (method.ops->init)
		method.data = method.ops->init();

	return 0;
}

static void resolve_exit(void)
{
	if (!method.ops || !method.ops->exit)
		return;

	method.ops->exit(method.data);
}

IWD_MODULE(resolve, resolve_init, resolve_exit)
