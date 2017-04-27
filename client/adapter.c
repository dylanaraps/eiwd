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

static struct proxy_interface_type adapter_interface_type = {
	.interface = IWD_ADAPTER_INTERFACE,
};

static const struct command adapter_commands[] = {
	{ }
};

static struct command_family adapter_command_family = {
	.caption = "Adapters",
	.name = "adapter",
	.command_list = adapter_commands,
};

static int adapter_command_family_init(void)
{
	command_family_register(&adapter_command_family);

	return 0;
}

static void adapter_command_family_exit(void)
{
	command_family_unregister(&adapter_command_family);
}

COMMAND_FAMILY(adapter_command_family, adapter_command_family_init,
						adapter_command_family_exit)

static int adapter_interface_init(void)
{
	proxy_interface_type_register(&adapter_interface_type);

	return 0;
}

static void adapter_interface_exit(void)
{
	proxy_interface_type_register(&adapter_interface_type);
}

INTERFACE_TYPE(adapter_interface_type, adapter_interface_init,
						adapter_interface_exit)
