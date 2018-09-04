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

enum station_state {
	STATION_STATE_DISCONNECTED,	/* Disconnected, no auto-connect */
	STATION_STATE_AUTOCONNECT,	/* Disconnected, try auto-connect */
	STATION_STATE_CONNECTING,	/* Connecting */
	STATION_STATE_CONNECTED,
	STATION_STATE_DISCONNECTING,
	STATION_STATE_ROAMING
};

typedef void (*station_state_watch_func_t)(enum station_state, void *userdata);
typedef void (*station_destroy_func_t)(void *userdata);

struct station {
	enum station_state state;
	struct watchlist state_watches;
	struct scan_bss *connected_bss;
	struct network *connected_network;
	struct l_queue *autoconnect_list;
	struct l_queue *bss_list;
	struct l_hashmap *networks;
	struct l_queue *networks_sorted;

	/* Roaming related members */
	struct timespec roam_min_time;
	struct l_timeout *roam_trigger_timeout;
	uint32_t roam_scan_id;

	struct wiphy *wiphy;
	struct netdev *netdev;

	bool seen_hidden_networks : 1;
	bool preparing_roam : 1;
	bool signal_low : 1;
	bool roam_no_orig_ap : 1;
	bool ap_directed_roaming : 1;
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

const char *station_state_to_string(enum station_state state);
void station_enter_state(struct station *station, enum station_state state);
enum station_state station_get_state(struct station *station);
uint32_t station_add_state_watch(struct station *station,
					station_state_watch_func_t func,
					void *user_data,
					station_destroy_func_t destroy);
bool station_remove_state_watch(struct station *station, uint32_t id);

void station_roam_state_clear(struct station *station);
void station_roam_failed(struct station *station);
void station_roamed(struct station *station);
void station_lost_beacon(struct station *station);
void station_ap_directed_roam(struct station *station,
				const struct mmpdu_header *hdr,
				const void *body, size_t body_len);

void station_low_rssi(struct station *station);
void station_ok_rssi(struct station *station);

struct station *station_find(uint32_t ifindex);
struct station *station_create(struct wiphy *wiphy, struct netdev *netdev);
void station_free(struct station *station);
