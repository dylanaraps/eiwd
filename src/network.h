/*
 *
 *  Wireless daemon for Linux
 *
 *  Copyright (C) 2013-2015  Intel Corporation. All rights reserved.
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

#include <stdbool.h>

struct netdev;

struct network {
	char *object_path;
	struct netdev *netdev;
	char ssid[33];
	unsigned char *psk;
	unsigned int agent_request;
	enum security security;
	struct l_queue *bss_list;
	struct l_settings *settings;
	bool update_psk:1;  /* Whether PSK should be written to storage */
	bool ask_psk:1; /* Whether we should force-ask agent for PSK */
};

bool network_seen(uint32_t type, const char *ssid);
bool network_connected(uint32_t type, const char *ssid);
double network_rankmod(uint32_t type, const char *ssid);

const char *network_get_ssid(struct network *network);
struct netdev *network_get_netdev(struct network *network);

void network_init();
void network_exit();
