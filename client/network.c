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

#include "dbus-proxy.h"
#include "display.h"
#include "network.h"

static void check_errors_method_callback(struct l_dbus_message *message,
								void *user_data)
{
	dbus_message_has_error(message);
}

bool network_is_connected(const char *path)
{
	return false;
}

void network_connect(const char *path)
{
	const struct proxy_interface *proxy =
			proxy_interface_find(IWD_NETWORK_INTERFACE, path);

	if (!proxy)
		return;

	proxy_interface_method_call(proxy, "Connect", "",
						check_errors_method_callback);
}

static struct proxy_interface_type network_interface_type = {
	.interface = IWD_NETWORK_INTERFACE,
};

static int network_interface_init(void)
{
	proxy_interface_type_register(&network_interface_type);

	return 0;
}

static void network_interface_exit(void)
{
	proxy_interface_type_register(&network_interface_type);
}

INTERFACE_TYPE(network_interface_type, network_interface_init,
						network_interface_exit)
