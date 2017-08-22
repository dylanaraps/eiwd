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

void proxy_properties_display(const struct proxy_interface *proxy,
				const char *caption, const char *margin,
				int name_column_width, int value_column_width)
{
	const void *data;
	const struct proxy_interface_property *properties;
	size_t i;

	if (!proxy->type->properties)
		return;

	display_table_header(caption, "%s%-*s  %-*s%-*s", margin,
				8, "Settable",
				name_column_width, "Property",
				value_column_width, "Value");

	data = proxy_interface_get_data(proxy);
	properties = proxy->type->properties;

	for (i = 0; properties[i].name; i++) {
		if (!properties[i].tostr)
			continue;

		display("%s%*s  %-*s%-*s\n", margin,
			8, properties[i].is_read_write ?
				COLOR_BOLDGRAY "       *" COLOR_OFF : "",
			name_column_width, properties[i].name,
			value_column_width, properties[i].tostr(data) ? : "");
	}
}

static const void *proxy_interface_property_tostr(
					const struct proxy_interface *proxy,
					const char *name)
{
	size_t i;
	const struct proxy_interface_property *property_table =
							proxy->type->properties;

	for (i = 0; property_table[i].name; i++) {
		if (strcmp(property_table[i].name, name))
			continue;

		if (!property_table[i].tostr)
			break;

		return property_table[i].tostr(proxy->data);
	}

	return NULL;
}

static void proxy_interface_property_set(struct proxy_interface *proxy,
					const char *name,
					struct l_dbus_message_iter *variant)
{
	size_t i;
	const struct proxy_interface_property *property_table =
							proxy->type->properties;

	for (i = 0; property_table[i].name; i++) {
		if (strcmp(property_table[i].name, name))
			continue;

		if (!property_table[i].set)
			return;

		property_table[i].set(proxy->data, variant);

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

char *proxy_property_str_completion(const struct proxy_interface_type *type,
					proxy_property_match_func_t function,
					const char *property_name,
					const char *value, int state)
{
	static struct l_queue *match;
	static const struct l_queue_entry *entry;

	if (!state) {
		match = proxy_interface_find_all(type->interface, function,
									value);
		if (!match)
			return NULL;

		entry = l_queue_get_entries(match);
	}

	while (entry) {
		const struct proxy_interface *proxy = entry->data;
		const char *str;

		entry = entry->next;

		str = proxy_interface_property_tostr(proxy, property_name);
		if (!str)
			return NULL;

		return l_strdup(str);
	}

	l_queue_destroy(match, NULL);
	match = NULL;
	entry = NULL;

	return NULL;
}

bool dbus_message_has_error(struct l_dbus_message *message)
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

struct l_queue *proxy_interface_find_all(const char *interface,
					proxy_property_match_func_t function,
					const void *value)
{
	const struct l_queue_entry *entry;
	struct l_queue *match = NULL;

	if (!interface || !function)
		return NULL;

	for (entry = l_queue_get_entries(proxy_interfaces); entry;
							entry = entry->next) {
		struct proxy_interface *proxy = entry->data;

		if (!interface_match_by_type_name(proxy->type, interface))
			continue;

		if (!function(proxy->data, value))
			continue;

		if (!match)
			match = l_queue_new();

		l_queue_push_tail(match, proxy);
	}

	return match;
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

static void properties_changed_callback(struct l_dbus_message *message,
								void *data)
{
	struct proxy_interface *proxy;
	const char *path;
	const char *interface;
	struct l_dbus_message_iter changed;
	struct l_dbus_message_iter invalidated;

	if (dbus_message_has_error(message))
		return;

	if (!l_dbus_message_get_arguments(message, "sa{sv}as", &interface,
						&changed, &invalidated)) {
		l_debug("Failed to parse properties changed callback message");

		return;
	}

	path = l_dbus_message_get_path(message);
	if (!path)
		return;

	proxy = proxy_interface_find(interface, path);
	if (!proxy)
		return;

	interface_update_properties(proxy, &changed, &invalidated);
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

		if (dependency->type->ops->unbind_interface(dependency, proxy))
			continue;

		error = l_strdup_printf("Interface %s does not support "
					"dependency %s\n",
					dependency->type->interface,
					proxy->type->interface);
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
		{ L_DBUS_INTERFACE_PROPERTIES },
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

		if (interface_type->ops && interface_type->ops->create) {
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

	if (proxy->type->ops && proxy->type->ops->destroy)
		proxy->type->ops->destroy(proxy->data);

	proxy->type = NULL;

	l_free(proxy);
}

bool proxy_interface_method_call(const struct proxy_interface *proxy,
					const char *name, const char *signature,
					l_dbus_message_func_t callback, ...)
{
	struct l_dbus_message *call;
	va_list args;

	if (!proxy || !name)
		return false;

	call = l_dbus_message_new_method_call(dbus, IWD_SERVICE, proxy->path,
						 proxy->type->interface, name);

	va_start(args, callback);
	l_dbus_message_set_arguments_valist(call, signature, args);
	va_end(args);

	l_dbus_send_with_reply(dbus, call, callback, (void *) proxy, NULL);

	return true;
}

void *proxy_interface_get_data(const struct proxy_interface *proxy)
{
	return proxy->data;
}

const char *proxy_interface_get_interface(const struct proxy_interface *proxy)
{
	return proxy->type->interface;
}

const char *proxy_interface_get_identity_str(
					const struct proxy_interface *proxy)
{
	if (proxy->type->ops && proxy->type->ops->identity)
		return proxy->type->ops->identity(proxy->data);

	return NULL;
}

void proxy_interface_display_list(const char *interface)
{
	const struct l_queue_entry *entry;

	for (entry = l_queue_get_entries(proxy_interfaces); entry;
							entry = entry->next) {
		const struct proxy_interface *proxy = entry->data;

		if (!interface_match_by_type_name(proxy->type, interface))
			continue;

		if (!proxy->type->ops || !proxy->type->ops->display)
			break;

		proxy->type->ops->display(MARGIN, proxy->data);
	}
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

		proxy_interface_destroy(proxy);
	}
}

static void get_managed_objects_callback(struct l_dbus_message *message,
								void *user_data)
{
	struct l_dbus_message_iter objects;
	struct l_dbus_message_iter object;
	const char *path;

	if (dbus_message_has_error(message)) {
		l_error("Failed to retrieve IWD dbus objects, quitting...\n");

		l_main_quit();

		return;
	}

	l_dbus_message_get_arguments(message, "a{oa{sa{sv}}}", &objects);

	while (l_dbus_message_iter_next_entry(&objects, &path, &object))
		proxy_interface_create(path, &object);

	display_enable_cmd_prompt();
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

	l_dbus_add_signal_watch(dbus, IWD_SERVICE, NULL,
					L_DBUS_INTERFACE_PROPERTIES,
					"PropertiesChanged", L_DBUS_MATCH_NONE,
					properties_changed_callback, NULL);

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
