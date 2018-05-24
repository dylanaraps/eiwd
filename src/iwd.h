/*
 *
 *  Wireless daemon for Linux
 *
 *  Copyright (C) 2013-2014  Intel Corporation. All rights reserved.
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

#define uninitialized_var(x) x = x

struct device;

enum security {
	SECURITY_NONE,
	SECURITY_WEP,
	SECURITY_PSK,
	SECURITY_8021X,
};

typedef void (*iwd_device_foreach_func)(struct device *, void *data);

void __iwd_device_foreach(iwd_device_foreach_func func, void *user_data);

const struct l_settings *iwd_get_config(void);

void iwd_shutdown(void);

void network_init();
void network_exit();
