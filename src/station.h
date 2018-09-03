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

#include <stdbool.h>

struct wiphy;
struct netdev;
enum security;
struct scan_bss;
struct network;

struct station {
	struct scan_bss *connected_bss;
	struct network *connected_network;
	struct l_queue *autoconnect_list;
	struct l_queue *bss_list;
	struct l_hashmap *networks;
	struct l_queue *networks_sorted;

	struct wiphy *wiphy;
	struct netdev *netdev;

	bool seen_hidden_networks : 1;
};

void station_autoconnect_next(struct station *station);
void station_add_autoconnect_bss(struct station *station,
					struct network *network,
					struct scan_bss *bss);

struct network *station_network_find(struct station *station, const char *ssid,
					enum security security);

struct network *station_add_seen_bss(struct station *station,
						struct scan_bss *bss);

void station_set_scan_results(struct station *station, struct l_queue *bss_list,
				bool add_to_autoconnect);

struct handshake_state *station_handshake_setup(struct station *station,
						struct network *network,
						struct scan_bss *bss);

struct station *station_find(uint32_t ifindex);
struct station *station_create(struct wiphy *wiphy, struct netdev *netdev);
void station_free(struct station *station);
