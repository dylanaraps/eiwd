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

static struct proxy_interface_type wsc_interface_type = {
	.interface = IWD_WSC_INTERFACE,
};

static enum cmd_status cmd_push_button(const char *device_name, char *args)
{
	return CMD_STATUS_UNSUPPORTED;
}

static enum cmd_status cmd_start_user_pin(const char *device_name, char *args)
{
	return CMD_STATUS_UNSUPPORTED;
}

static enum cmd_status cmd_start_pin(const char *device_name, char *args)
{
	return CMD_STATUS_UNSUPPORTED;
}

static enum cmd_status cmd_cancel(const char *device_name, char *args)
{
	return CMD_STATUS_UNSUPPORTED;
}

static const struct command wsc_commands[] = {
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
	proxy_interface_type_register(&wsc_interface_type);
}

INTERFACE_TYPE(wsc_interface_type, wsc_interface_init, wsc_interface_exit)
