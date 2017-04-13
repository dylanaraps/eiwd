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

#include <stdio.h>

struct proxy_interface;

#define IWD_ADAPTER_INTERFACE          "net.connman.iwd.Adapter"
#define IWD_DEVICE_INTERFACE           "net.connman.iwd.Device"
#define IWD_KNOWN_NETWORKS_INTREFACE   "net.connman.iwd.KnownNetworks"
#define IWD_NETWORK_INTERFACE          "net.connman.iwd.Network"
#define IWD_WSC_INTERFACE              "net.connman.iwd.WiFiSimpleConfiguration"

struct proxy_interface_property {
	const char *name;
	const char *type;
	void (*set)(void *data, const void *value);
};

struct proxy_interface_type_ops {
	void *(*create)(void);
	void (*destroy)(void *data);
	bool (*bind_interface)(const struct proxy_interface *proxy,
				const struct proxy_interface *dependency);
	bool (*unbind_interface)(const struct proxy_interface *proxy,
				const struct proxy_interface *dependency);
};

struct proxy_interface_type {
	const char *interface;
	const struct proxy_interface_property *properties;
	const struct proxy_interface_type_ops *ops;
};

struct proxy_interface *proxy_interface_find(const char *interface,
							const char *path);

void proxy_interface_type_register(
			const struct proxy_interface_type *interface_type);
void proxy_interface_type_unregister(
			const struct proxy_interface_type *interface_type);

struct interface_type_desc {
	const char *interface;
	int (*init)(void);
	void (*exit)(void);
} __attribute__((aligned(8)));

#define INTERFACE_TYPE(interface, init, exit)				\
	static struct interface_type_desc __interface_type_ ## interface\
		__attribute__((used, section("__interface"), aligned(8))) = {\
			#interface, init, exit				\
		};							\

bool dbus_proxy_init(void);
bool dbus_proxy_exit(void);
