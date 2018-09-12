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

struct l_genl_family;

const struct l_settings *iwd_get_config(void);

bool netdev_init(const char *whitelist, const char *blacklist);
void netdev_exit(void);
void netdev_set_nl80211(struct l_genl_family *nl80211);
void netdev_shutdown(void);

void network_init();
void network_exit();

void sim_auth_init(void);
void sim_auth_exit(void);

bool wsc_init(void);
bool wsc_exit();

bool known_networks_init(void);
void known_networks_exit(void);

bool device_init(void);
void device_exit(void);

bool station_init(void);
void station_exit(void);
