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

#include "command.h"
#include "dbus-proxy.h"
#include "device.h"
#include "display.h"

struct wsc {
	const struct proxy_interface *device;

	/* TODO: Add status */
};

static void *wsc_create(void)
{
	return l_new(struct wsc, 1);
}

static void wsc_destroy(void *data)
{
	struct wsc *wsc = data;

	wsc->device = NULL;

	l_free(wsc);
}

static bool wsc_bind_interface(const struct proxy_interface *proxy,
				const struct proxy_interface *dependency)
{
	const char *interface = proxy_interface_get_interface(dependency);

	if (!strcmp(interface, IWD_DEVICE_INTERFACE)) {
		struct wsc *wsc = proxy_interface_get_data(proxy);

		wsc->device = dependency;

		return true;
	}

	return false;
}

static bool wsc_unbind_interface(const struct proxy_interface *proxy,
				const struct proxy_interface *dependency)
{
	const char *interface = proxy_interface_get_interface(dependency);

	if (!strcmp(interface, IWD_DEVICE_INTERFACE)) {
		struct wsc *wsc = proxy_interface_get_data(proxy);

		wsc->device = NULL;

		return true;
	}

	return false;
}

static const struct proxy_interface_type_ops wsc_ops = {
	.create = wsc_create,
	.destroy = wsc_destroy,
	.bind_interface = wsc_bind_interface,
	.unbind_interface = wsc_unbind_interface,
};

static struct proxy_interface_type wsc_interface_type = {
	.interface = IWD_WSC_INTERFACE,
	.ops = &wsc_ops,
};

static void check_errors_method_callback(struct l_dbus_message *message,
								void *user_data)
{
	dbus_message_has_error(message);
}

static void generate_pin_callback(struct l_dbus_message *message,
								void *user_data)
{
	const struct proxy_interface *proxy = user_data;
	const char *pin;

	if (dbus_message_has_error(message))
		return;

	if (!l_dbus_message_get_arguments(message, "s", &pin)) {
		l_error("Failed to parse 'generate pin' callback message");

		return;
	}

	if (!pin)
		return;

	proxy_interface_method_call(proxy, "StartPin", "s",
					check_errors_method_callback, pin);
}

static bool match_by_device(const void *a, const void *b)
{
	const struct wsc *wsc = a;

	return wsc->device ? true : false;
}

static void display_wsc_inline(const char *margin, const void *data)
{
	const struct wsc *wsc = data;

	if (wsc->device && proxy_interface_get_identity_str(wsc->device))
		display("%s%-*s\n", margin,
			20, proxy_interface_get_identity_str(wsc->device));
}

static enum cmd_status cmd_list(const char *device_name, char *args)
{
	const struct l_queue_entry *entry;
	struct l_queue *match =
		proxy_interface_find_all(IWD_WSC_INTERFACE,
						match_by_device, NULL);

	if (match) {
		display_table_header("WSC-capable Devices",
					MARGIN "%-*s", 20, "Name");
	} else {
		display("No WSC-capable devices available\n");

		return CMD_STATUS_OK;
	}

	for (entry = l_queue_get_entries(match); entry; entry = entry->next) {
		const struct wsc *wsc = proxy_interface_get_data(entry->data);

		display_wsc_inline(MARGIN, wsc);
	}

	display_table_footer();

	l_queue_destroy(match, NULL);

	return CMD_STATUS_OK;
}

static enum cmd_status cmd_push_button(const char *device_name, char *args)
{
	const struct proxy_interface *proxy = device_wsc_get(device_name);

	if (!proxy) {
		display("Invalid device name '%s'\n", device_name);

		return CMD_STATUS_INVALID_VALUE;
	}

	proxy_interface_method_call(proxy, "PushButton", "",
						check_errors_method_callback);

	return CMD_STATUS_OK;
}

static enum cmd_status cmd_start_user_pin(const char *device_name, char *args)
{
	const struct proxy_interface *proxy = device_wsc_get(device_name);

	if (!proxy) {
		display("Invalid device name '%s'\n", device_name);

		return CMD_STATUS_INVALID_VALUE;
	}

	proxy_interface_method_call(proxy, "StartPin", "s",
					check_errors_method_callback, args);

	return CMD_STATUS_OK;
}

static enum cmd_status cmd_start_pin(const char *device_name, char *args)
{
	const struct proxy_interface *proxy = device_wsc_get(device_name);

	if (!proxy) {
		display("Invalid device name '%s'\n", device_name);

		return CMD_STATUS_INVALID_VALUE;
	}

	proxy_interface_method_call(proxy, "GeneratePin", "",
							generate_pin_callback);

	return CMD_STATUS_OK;
}

static enum cmd_status cmd_cancel(const char *device_name, char *args)
{
	const struct proxy_interface *proxy = device_wsc_get(device_name);

	if (!proxy) {
		display("Invalid device name '%s'\n", device_name);

		return CMD_STATUS_INVALID_VALUE;
	}

	proxy_interface_method_call(proxy, "Cancel", "",
						check_errors_method_callback);

	return CMD_STATUS_OK;
}

static const struct command wsc_commands[] = {
	{ NULL, "list", NULL, cmd_list, "List WSC-capable devices", true },
	{ "<wlan>", "push-button", NULL, cmd_push_button, "PushButton mode" },
	{ "<wlan>", "start-user-pin", "<8 digit PIN>", cmd_start_user_pin,
							"PIN mode" },
	{ "<wlan>", "start-pin", NULL, cmd_start_pin,
		"PIN mode with generated\n\t\t\t\t\t\t    8 digit PIN" },
	{ "<wlan>", "cancel", NULL,   cmd_cancel, "Aborts WSC operations" },
	{ }
};

static char *family_arg_completion(const char *text, int state)
{
	static bool first_pass;
	static size_t index;
	static size_t len;
	const char *cmd;

	if (!state) {
		index = 0;
		len = strlen(text);
		first_pass = true;
	}

	while ((cmd = wsc_commands[index].cmd)) {
		if (wsc_commands[index++].entity)
			continue;

		if (!strncmp(cmd, text, len))
			return l_strdup(cmd);
	}

	if (first_pass) {
		state = 0;
		first_pass = false;
	}

	return device_wsc_family_arg_completion(text, state);
}

static char *entity_arg_completion(const char *text, int state)
{
	return command_entity_arg_completion(text, state, wsc_commands);
}

static struct command_family wsc_command_family = {
	.caption = "WiFi Simple Configuration",
	.name = "wsc",
	.command_list = wsc_commands,
	.family_arg_completion = family_arg_completion,
	.entity_arg_completion = entity_arg_completion,
};

static int wsc_command_family_init(void)
{
	command_family_register(&wsc_command_family);

	return 0;
}

static void wsc_command_family_exit(void)
{
	command_family_unregister(&wsc_command_family);
}

COMMAND_FAMILY(wsc_command_family, wsc_command_family_init,
						wsc_command_family_exit)

static int wsc_interface_init(void)
{
	proxy_interface_type_register(&wsc_interface_type);

	return 0;
}

static void wsc_interface_exit(void)
{
	proxy_interface_type_unregister(&wsc_interface_type);
}

INTERFACE_TYPE(wsc_interface_type, wsc_interface_init, wsc_interface_exit)
