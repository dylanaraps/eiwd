/*
 *
 *  Wireless daemon for Linux
 *
 *  Copyright (C) 2018  Intel Corporation. All rights reserved.
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

struct ad_hoc {
	bool started;
	const struct proxy_interface *device;
};

static void *ad_hoc_create(void)
{
	return l_new(struct ad_hoc, 1);
}

static void ad_hoc_destroy(void *data)
{
	struct ad_hoc *ad_hoc = data;

	ad_hoc->device = NULL;

	l_free(ad_hoc);
}

static bool ad_hoc_bind_interface(const struct proxy_interface *proxy,
				const struct proxy_interface *dependency)
{
	const char *interface = proxy_interface_get_interface(dependency);

	if (!strcmp(interface, IWD_DEVICE_INTERFACE)) {
		struct ad_hoc *ad_hoc = proxy_interface_get_data(proxy);

		ad_hoc->device = dependency;

		return true;
	}

	return false;
}

static bool ad_hoc_unbind_interface(const struct proxy_interface *proxy,
				const struct proxy_interface *dependency)
{
	const char *interface = proxy_interface_get_interface(dependency);

	if (!strcmp(interface, IWD_DEVICE_INTERFACE)) {
		struct ad_hoc *ad_hoc = proxy_interface_get_data(proxy);

		ad_hoc->device = NULL;

		return true;
	}

	return false;
}

static const struct proxy_interface_type_ops ad_hoc_ops = {
	.create = ad_hoc_create,
	.destroy = ad_hoc_destroy,
	.bind_interface = ad_hoc_bind_interface,
	.unbind_interface = ad_hoc_unbind_interface,
};

static const char *get_started_tostr(const void *data)
{
	const struct ad_hoc *ad_hoc = data;

	return ad_hoc->started ? "yes" : "no";
}

static void update_started(void *data, struct l_dbus_message_iter *variant)
{
	struct ad_hoc *ad_hoc = data;
	bool value;

	if (!l_dbus_message_iter_get_variant(variant, "b", &value)) {
		ad_hoc->started = false;

		return;
	}

	ad_hoc->started = value;
}

static const struct proxy_interface_property ad_hoc_properties[] = {
	{ "Started",  "b", update_started,  get_started_tostr },
	{ }
};

static struct proxy_interface_type ad_hoc_interface_type = {
	.interface = IWD_AD_HOC_INTERFACE,
	.properties = ad_hoc_properties,
	.ops = &ad_hoc_ops,
};

static void check_errors_method_callback(struct l_dbus_message *message,
								void *user_data)
{
	dbus_message_has_error(message);
}

static bool match_by_device(const void *a, const void *b)
{
	const struct ad_hoc *ad_hoc = a;

	return ad_hoc->device ? true : false;
}

static void display_ad_hoc_inline(const char *margin, const void *data)
{
	const struct ad_hoc *ad_hoc = data;

	if (ad_hoc->device && proxy_interface_get_identity_str(ad_hoc->device))
		display("%s%-*s%-*s\n", margin,
			20, proxy_interface_get_identity_str(ad_hoc->device),
			8, get_started_tostr(ad_hoc));
}

static enum cmd_status cmd_list(const char *device_name, char **argv, int argc)
{
	const struct l_queue_entry *entry;
	struct l_queue *match =
		proxy_interface_find_all(IWD_AD_HOC_INTERFACE,
						match_by_device, NULL);

	display_table_header("Devices in Ad-Hoc Mode", MARGIN "%-*s%-*s",
				20, "Name", 8, "Started");

	if (!match) {
		display("No devices in Ad-Hoc mode available.\n");
		display_table_footer();

		return CMD_STATUS_OK;
	}

	for (entry = l_queue_get_entries(match); entry; entry = entry->next) {
		const struct ad_hoc *ad_hoc =
					proxy_interface_get_data(entry->data);

		display_ad_hoc_inline(MARGIN, ad_hoc);
	}

	display_table_footer();

	l_queue_destroy(match, NULL);

	return CMD_STATUS_OK;
}

static enum cmd_status cmd_start(const char *device_name, char **argv, int argc)
{
	const struct proxy_interface *proxy = device_ad_hoc_get(device_name);

	if (!proxy) {
		display("Invalid device name '%s'\n", device_name);

		return CMD_STATUS_INVALID_VALUE;
	}

	if (argc < 2)
		return CMD_STATUS_INVALID_ARGS;

	if (strlen(argv[0]) > 32) {
		display("Network name cannot exceed 32 characters.\n");

		return CMD_STATUS_INVALID_VALUE;
	}

	if (strlen(argv[1]) < 8) {
		display("Passphrase cannot be shorted than 8 characters.\n");

		return CMD_STATUS_INVALID_VALUE;
	}

	proxy_interface_method_call(proxy, "Start", "ss",
						check_errors_method_callback,
						argv[0], argv[1]);

	return CMD_STATUS_OK;
}

static enum cmd_status cmd_start_open(const char *device_name,
							char **argv, int argc)
{
	const struct proxy_interface *proxy = device_ad_hoc_get(device_name);

	if (!proxy) {
		display("Invalid device name '%s'\n", device_name);

		return CMD_STATUS_INVALID_VALUE;
	}

	if (argc < 1)
		return CMD_STATUS_INVALID_ARGS;

	if (strlen(argv[0]) > 32) {
		display("Network name cannot exceed 32 characters.\n");

		return CMD_STATUS_INVALID_VALUE;
	}

	proxy_interface_method_call(proxy, "Start", "s",
						check_errors_method_callback,
						argv[0]);

	return CMD_STATUS_OK;
}

static enum cmd_status cmd_stop(const char *device_name, char **argv, int argc)
{
	const struct proxy_interface *proxy = device_ad_hoc_get(device_name);

	if (!proxy) {
		display("Invalid device name '%s'\n", device_name);

		return CMD_STATUS_INVALID_VALUE;
	}

	proxy_interface_method_call(proxy, "Stop", "",
						check_errors_method_callback);

	return CMD_STATUS_OK;
}

static const struct command ad_hoc_commands[] = {
	{ NULL, "list", NULL, cmd_list, "List Ad-Hoc devices", true },
	{ "<wlan>", "start", "<\"network name\"> <passphrase>", cmd_start,
		"Start or join an existing\n"
		"\t\t\t\t\t\t    Ad-Hoc network called\n"
		"\t\t\t\t\t\t    \"network name\" with a\n"
		"\t\t\t\t\t\t    passphrase" },
	{ "<wlan>", "start_open", "<\"network name\">", cmd_start_open,
		"Start or join an existing\n"
		"\t\t\t\t\t\t    open Ad-Hoc network called\n"
		"\t\t\t\t\t\t    \"network name\"" },
	{ "<wlan>", "stop", NULL,   cmd_stop, "Leave an Ad-Hoc network" },
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

	while ((cmd = ad_hoc_commands[index].cmd)) {
		if (ad_hoc_commands[index++].entity)
			continue;

		if (!strncmp(cmd, text, len))
			return l_strdup(cmd);
	}

	if (first_pass) {
		state = 0;
		first_pass = false;
	}

	return device_ad_hoc_family_arg_completion(text, state);
}

static char *entity_arg_completion(const char *text, int state)
{
	return command_entity_arg_completion(text, state, ad_hoc_commands);
}

static struct command_family ad_hoc_command_family = {
	.caption = "Ad-Hoc",
	.name = "ad-hoc",
	.command_list = ad_hoc_commands,
	.family_arg_completion = family_arg_completion,
	.entity_arg_completion = entity_arg_completion,
};

static int ad_hoc_command_family_init(void)
{
	command_family_register(&ad_hoc_command_family);

	return 0;
}

static void ad_hoc_command_family_exit(void)
{
	command_family_unregister(&ad_hoc_command_family);
}

COMMAND_FAMILY(ap_command_family, ad_hoc_command_family_init,
						ad_hoc_command_family_exit)

static int ad_hoc_interface_init(void)
{
	proxy_interface_type_register(&ad_hoc_interface_type);

	return 0;
}

static void ad_hoc_interface_exit(void)
{
	proxy_interface_type_unregister(&ad_hoc_interface_type);
}

INTERFACE_TYPE(ap_interface_type, ad_hoc_interface_init, ad_hoc_interface_exit)
