/*
 *
 *  Wireless daemon for Linux
 *
 *  Copyright (C) 2016-2019  Intel Corporation. All rights reserved.
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

enum security;
struct scan_freq_set;
struct network_info;

enum known_networks_event {
	KNOWN_NETWORKS_EVENT_ADDED,
	KNOWN_NETWORKS_EVENT_REMOVED,
};

struct network_info_ops {
	struct l_settings *(*open)(struct network_info *info);
	int (*touch)(struct network_info *info);
	void (*sync)(struct network_info *info, struct l_settings *settings);
	void (*remove)(struct network_info *info);
	void (*free)(struct network_info *info);
	const char *(*get_path)(const struct network_info *info);

	bool (*match_hessid)(const struct network_info *info,
						const uint8_t *hessid);
	bool (*match_roaming_consortium)(const struct network_info *info,
						const uint8_t *rc_ie,
						size_t rc_len);
	bool (*match_nai_realms)(const struct network_info *info,
						const char **nai_realms);
};

struct network_info {
	const struct network_info_ops *ops;
	char ssid[33];
	enum security type;
	struct l_queue *known_frequencies;
	struct timespec connected_time;	/* Time last connected */
	int seen_count;			/* Ref count for network.info */
	bool is_hidden:1;
	bool is_autoconnectable:1;
	bool is_hotspot:1;
};

typedef bool (*known_networks_foreach_func_t)(const struct network_info *info,
						void *user_data);

typedef void (*known_networks_watch_func_t)(enum known_networks_event event,
						const struct network_info *info,
						void *user_data);
typedef void (*known_networks_destroy_func_t)(void *user_data);

struct known_frequency {
	uint32_t frequency;
};

int known_network_offset(const struct network_info *target);
bool known_networks_foreach(known_networks_foreach_func_t function,
				void *user_data);
bool known_networks_has_hidden(void);
struct network_info *known_networks_find(const char *ssid,
						enum security security);

struct scan_freq_set *known_networks_get_recent_frequencies(
						uint8_t num_networks_tosearch);
int known_network_add_frequency(struct network_info *info, uint32_t frequency);

uint32_t known_networks_watch_add(known_networks_watch_func_t func,
					void *user_data,
					known_networks_destroy_func_t destroy);
void known_networks_watch_remove(uint32_t id);

struct l_settings *network_info_open_settings(struct network_info *info);
int network_info_touch(struct network_info *info);
const char *network_info_get_path(const struct network_info *info);

bool network_info_match_hessid(const struct network_info *info,
				const uint8_t *hessid);
bool network_info_match_roaming_consortium(const struct network_info *info,
						const uint8_t *rc,
						size_t rc_len);
bool network_info_match_nai_realm(const struct network_info *info,
						const char **nai_realms);

void known_networks_add(struct network_info *info);
void known_networks_remove(struct network_info *info);
