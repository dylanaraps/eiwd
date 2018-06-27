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
#include <time.h>

struct device;
struct network;
struct scan_bss;

bool network_seen(struct network *network, struct timespec *when);
bool network_connected(struct network *network);
void network_disconnected(struct network *network);
bool network_rankmod(const struct network *network, double *rankmod);

struct network *network_create(struct device *device, const char *ssid,
				enum security security);

const char *network_get_ssid(const struct network *network);
struct device *network_get_device(const struct network *network);
const char *network_get_path(const struct network *network);
enum security network_get_security(const struct network *network);
const uint8_t *network_get_psk(const struct network *network);
struct l_queue *network_get_secrets(const struct network *network);
int network_get_signal_strength(const struct network *network);
struct l_settings *network_get_settings(const struct network *network);

bool network_set_psk(struct network *network, const uint8_t *psk);
void network_sync_psk(struct network *network);

int network_autoconnect(struct network *network, struct scan_bss *bss);
void network_connect_failed(struct network *network);
bool network_bss_add(struct network *network, struct scan_bss *bss);
bool network_bss_list_isempty(struct network *network);
void network_bss_list_clear(struct network *network);
struct scan_bss *network_bss_find_by_addr(struct network *network,
							const uint8_t *addr);
struct scan_bss *network_bss_select(struct network *network);

bool network_register(struct network *network, const char *path);

void network_remove(struct network *network, int reason);

int network_rank_compare(const void *a, const void *b, void *user);
void network_rank_update(struct network *network);

struct network_info {
	char ssid[33];
	enum security type;
	struct timespec connected_time;	/* Time last connected */
	struct timespec seen_time;	/* Time last seen */
	int seen_count;			/* Ref count for network.info */
	bool is_known:1;
};

typedef void (*network_info_foreach_func_t)(const struct network_info *info,
						void *user_data);

bool network_info_add_known(const char *ssid, enum security security);
bool network_info_forget_known(const char *ssid, enum security security);
void network_info_foreach(network_info_foreach_func_t function,
				void *user_data);
bool network_info_has_hidden(void);
