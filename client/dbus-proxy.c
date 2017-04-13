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

#include <stdio.h>
#include <ell/ell.h>

#include "dbus-proxy.h"
#include "display.h"

#define IWD_SERVICE		"net.connman.iwd"
#define IWD_ROOT_PATH		"/"

struct proxy_interface {
	void *data;
	char *path;
	const struct proxy_interface_type *type;
};

static struct l_dbus *dbus;

static struct l_queue *proxy_interfaces;
static struct l_queue *proxy_interface_types;

static void proxy_interface_property_set(struct proxy_interface *proxy,
					const char *name,
					struct l_dbus_message_iter *variant)
{
	size_t i;
	const void *value;
	const struct proxy_interface_property *property_table =
							proxy->type->properties;

	for (i = 0; property_table[i].name; i++) {
		if (strcmp(property_table[i].name, name))
			continue;

		if (!property_table[i].set)
			return;

		if (variant)
			l_dbus_message_iter_get_variant(variant,
						property_table[i].type,
						&value);
		else
			value = NULL;

		property_table[i].set(proxy->data, value);

		return;
	}

	l_debug("Unknown property name: %s for interface %s", name,
							proxy->type->interface);
}

static void interface_update_properties(struct proxy_interface *proxy,
					struct l_dbus_message_iter *changed,
					struct l_dbus_message_iter *invalidated)
{
	const char *name;
	struct l_dbus_message_iter variant;

	while (l_dbus_message_iter_next_entry(changed, &name, &variant))
		proxy_interface_property_set(proxy, name, &variant);

	if (!invalidated)
		return;

	while (l_dbus_message_iter_next_entry(invalidated, &name))
		proxy_interface_property_set(proxy, name, NULL);
}

static bool dbus_message_has_error(struct l_dbus_message *message)
{
	const char *name;
	const char *text;

	if (l_dbus_message_get_error(message, &name, &text)) {
		display_error(text);
		return true;
	}

	return false;
}

static bool interface_match_by_type_name(const void *a, const void *b)
{
	const struct proxy_interface_type *type = a;
	const char *interface = b;

	return !strcmp(type->interface, interface);
}

struct proxy_interface *proxy_interface_find(const char *interface,
							const char *path)
{
	const struct l_queue_entry *entry;

	if (!interface || !path)
		return NULL;

	for (entry = l_queue_get_entries(proxy_interfaces); entry;
							entry = entry->next) {
		struct proxy_interface *proxy = entry->data;

		if (strcmp(proxy->path, path))
			continue;

		if (strcmp(proxy->type->interface, interface))
			continue;

		return proxy;
	}

	return NULL;
}

static struct l_queue *proxy_interface_find_by_path(const char *path)
{
	const struct l_queue_entry *entry;
	struct l_queue *match = NULL;

	for (entry = l_queue_get_entries(proxy_interfaces); entry;
							entry = entry->next) {
		struct proxy_interface *proxy = entry->data;

		if (!strcmp(proxy->path, path)) {
			if (!match)
				match = l_queue_new();

			l_queue_push_tail(match, proxy);
		}
	}

	return match;
}

static void proxy_interface_bind_dependencies(const char *path)
{
	const struct l_queue_entry *entry;
	const struct l_queue_entry *inner_entry;
	struct l_queue *match = proxy_interface_find_by_path(path);

	if (l_queue_length(match) < 2)
		goto done;

	for (entry = l_queue_get_entries(match); entry; entry = entry->next) {
		struct proxy_interface *proxy = entry->data;

		if (!proxy->type->ops || !proxy->type->ops->bind_interface)
			continue;

		for (inner_entry = l_queue_get_entries(match); inner_entry;
					inner_entry = inner_entry->next) {
			char *error;
			struct proxy_interface *dependency = inner_entry->data;

			if (!strcmp(proxy->type->interface,
						dependency->type->interface))
				continue;

			if (proxy->type->ops->bind_interface(proxy,
								dependency))
				continue;

			error = l_strdup_printf("Interface %s does not support "
						"dependency %s\n",
						proxy->type->interface,
						dependency->type->interface);
			display_error(error);
			l_free(error);
		}
	}

done:
	l_queue_destroy(match, NULL);
}

static void proxy_interface_unbind_dependencies(
					const struct proxy_interface *proxy)
{
	const struct l_queue_entry *entry;
	struct l_queue *match = proxy_interface_find_by_path(proxy->path);

	if (l_queue_length(match) < 2)
		goto done;

	for (entry = l_queue_get_entries(match); entry; entry = entry->next) {
		struct proxy_interface *dependency = entry->data;
		char *error;

		if (!strcmp(proxy->type->interface,
						dependency->type->interface))
			continue;

		if (!dependency->type->ops ||
				!dependency->type->ops->unbind_interface)
			continue;

		if (dependency->type->ops->unbind_interface(proxy, dependency))
			continue;

		error = l_strdup_printf("Interface %s does not support "
					"dependency %s\n",
					proxy->type->interface,
					dependency->type->interface);
		display_error(error);
		l_free(error);
	}

done:
	l_queue_destroy(match, NULL);
}

static bool is_ignorable(const char *interface)
{
	size_t i;

	static const struct {
		const char *interface;
	} interfaces_to_ignore[] = {
		{ L_DBUS_INTERFACE_OBJECT_MANAGER },
		{ L_DBUS_INTERFACE_INTROSPECTABLE },
		{ }
	};

	for (i = 0; interfaces_to_ignore[i].interface; i++)
		if (!strcmp(interfaces_to_ignore[i].interface, interface))
			return true;

	return false;
}

static void proxy_interface_create(const char *path,
					struct l_dbus_message_iter *interfaces)
{
	const char *interface;
	struct l_dbus_message_iter properties;
	struct proxy_interface *proxy;
	struct proxy_interface_type *interface_type;

	if (!path)
		return;

	while (l_dbus_message_iter_next_entry(interfaces, &interface,
								&properties)) {
		interface_type = l_queue_find(proxy_interface_types,
						interface_match_by_type_name,
						interface);

		if (!interface_type) {
			if (!is_ignorable(interface))
				l_debug("Unknown DBus interface type %s",
								interface);

			continue;
		}

		proxy = proxy_interface_find(interface_type->interface, path);

		if (proxy) {
			interface_update_properties(proxy, &properties, NULL);

			continue;
		}

		proxy = l_new(struct proxy_interface, 1);
		proxy->path = l_strdup(path);
		proxy->type = interface_type;

		if (interface_type->ops->create) {
			proxy->data = interface_type->ops->create();

			interface_update_properties(proxy, &properties, NULL);
		}

		l_queue_push_tail(proxy_interfaces, proxy);
	}

	proxy_interface_bind_dependencies(path);
}

static void proxy_interface_destroy(void *data)
{
	struct proxy_interface *proxy = data;

	l_free(proxy->path);

	if (proxy->type->ops->destroy)
		proxy->type->ops->destroy(proxy->data);

	proxy->type = NULL;

	l_free(proxy);
}

static void interfaces_added_callback(struct l_dbus_message *message,
								void *user_data)
{
	const char *path;
	struct l_dbus_message_iter object;

	if (dbus_message_has_error(message))
		return;

	l_dbus_message_get_arguments(message, "oa{sa{sv}}", &path, &object);

	proxy_interface_create(path, &object);
}

static void interfaces_removed_callback(struct l_dbus_message *message,
								void *user_data)
{
	const char *interface;
	const char *path;
	struct l_dbus_message_iter interfaces;
	struct proxy_interface *proxy;

	if (dbus_message_has_error(message))
		return;

	l_dbus_message_get_arguments(message, "oas", &path, &interfaces);

	while (l_dbus_message_iter_next_entry(&interfaces, &interface)) {
		proxy = proxy_interface_find(interface, path);

		if (!proxy)
			continue;

		proxy_interface_unbind_dependencies(proxy);

		l_queue_remove(proxy_interfaces, proxy);
	}
}

static void get_managed_objects_callback(struct l_dbus_message *message,
								void *user_data)
{
	struct l_dbus_message_iter objects;
	struct l_dbus_message_iter object;
	const char *path;

	if (dbus_message_has_error(message)) {
		l_error("Failed to retrieve IWD dbus objects");

		return;
	}

	l_dbus_message_get_arguments(message, "a{oa{sa{sv}}}", &objects);

	while (l_dbus_message_iter_next_entry(&objects, &path, &object))
		proxy_interface_create(path, &object);

}

static void service_appeared_callback(struct l_dbus *dbus, void *user_data)
{
	l_dbus_add_signal_watch(dbus, IWD_SERVICE, IWD_ROOT_PATH,
					L_DBUS_INTERFACE_OBJECT_MANAGER,
					"InterfacesAdded", L_DBUS_MATCH_NONE,
					interfaces_added_callback, NULL);

	l_dbus_add_signal_watch(dbus, IWD_SERVICE, IWD_ROOT_PATH,
					L_DBUS_INTERFACE_OBJECT_MANAGER,
					"InterfacesRemoved", L_DBUS_MATCH_NONE,
					interfaces_removed_callback, NULL);

	l_dbus_method_call(dbus, IWD_SERVICE, IWD_ROOT_PATH,
					L_DBUS_INTERFACE_OBJECT_MANAGER,
					"GetManagedObjects", NULL,
					get_managed_objects_callback,
					NULL, NULL);
}

static void service_disappeared_callback(struct l_dbus *dbus,
							void *user_data)
{
	l_queue_clear(proxy_interfaces, proxy_interface_destroy);

	display_disable_cmd_prompt();
}

static void dbus_disconnect_callback(void *user_data)
{
	display("D-Bus disconnected, quitting...\n");

	l_main_quit();
}

void proxy_interface_type_register(
			const struct proxy_interface_type *interface_type)
{
	l_queue_push_tail(proxy_interface_types, (void *) interface_type);
}

void proxy_interface_type_unregister(
			const struct proxy_interface_type *interface_type)
{
	l_queue_remove(proxy_interface_types, (void *) interface_type);
}

extern struct interface_type_desc __start___interface[];
extern struct interface_type_desc __stop___interface[];

bool dbus_proxy_init(void)
{
	struct interface_type_desc *desc;

	if (dbus)
		return true;

	dbus = l_dbus_new_default(L_DBUS_SYSTEM_BUS);
	if (!dbus)
		return false;

	proxy_interface_types = l_queue_new();
	proxy_interfaces = l_queue_new();

	if (__start___interface == NULL || __stop___interface == NULL)
		return false;

	for (desc = __start___interface; desc < __stop___interface; desc++) {
		if (!desc->init)
			continue;

		desc->init();
	}

	l_dbus_set_disconnect_handler(dbus, dbus_disconnect_callback, NULL,
									NULL);

	l_dbus_add_service_watch(dbus, IWD_SERVICE, service_appeared_callback,
						service_disappeared_callback,
						NULL, NULL);

	return true;
}

bool dbus_proxy_exit(void)
{
	struct interface_type_desc *desc;

	if (__start___interface == NULL || __stop___interface == NULL)
		return false;

	for (desc = __start___interface; desc < __stop___interface; desc++) {
		if (!desc->exit)
			continue;

		desc->exit();
	}

	l_queue_destroy(proxy_interface_types, NULL);
	proxy_interface_types = NULL;

	l_queue_destroy(proxy_interfaces, proxy_interface_destroy);
	proxy_interfaces = NULL;

	l_dbus_destroy(dbus);
	dbus = NULL;

	return true;
}
