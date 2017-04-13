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

static struct proxy_interface_type device_interface_type = {
	.interface = IWD_DEVICE_INTERFACE,
};

static struct command_family device_command_family = {
	.caption = "Devices",
	.name = "device",
};

static int device_command_family_init(void)
{
	command_family_register(&device_command_family);

	return 0;
}

static void device_command_family_exit(void)
{
	command_family_unregister(&device_command_family);
}

COMMAND_FAMILY(device_command_family, device_command_family_init,
						device_command_family_exit)

static int device_interface_init(void)
{
	proxy_interface_type_register(&device_interface_type);

	return 0;
}

static void device_interface_exit(void)
{
	proxy_interface_type_register(&device_interface_type);
}

INTERFACE_TYPE(device_interface_type, device_interface_init,
						device_interface_exit)
