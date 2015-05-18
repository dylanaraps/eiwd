/*
 *
 *  Wireless daemon for Linux
 *
 *  Copyright (C) 2015  Intel Corporation. All rights reserved.
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

enum scan_ssid_security {
	SCAN_SSID_SECURITY_NONE,
	SCAN_SSID_SECURITY_WEP,
	SCAN_SSID_SECURITY_PSK,
	SCAN_SSID_SECURITY_8021X,
};

typedef void (*scan_func_t)(struct l_genl_msg *msg, void *user_data);
typedef void (*scan_done_func_t)(void *user_data);

struct scan_bss {
	uint8_t addr[6];
	uint32_t frequency;
	int32_t signal_strength;
	uint16_t capability;
	uint8_t *rsne;
	uint8_t *wpa;
};

void scan_start(struct l_genl_family *nl80211, uint32_t ifindex,
		scan_func_t callback, void *user_data);

void scan_sched_start(struct l_genl_family *nl80211, uint32_t ifindex,
			uint32_t scan_interval, scan_func_t callback,
			void *user_data);

void scan_get_results(struct l_genl_family *nl80211, uint32_t ifindex,
			scan_func_t callback, scan_done_func_t scan_done,
			void *user_data);

enum scan_ssid_security scan_get_ssid_security(enum ie_bss_capability bss_cap,
						const struct ie_rsn_info *info);
void scan_bss_free(struct scan_bss *bss);

struct scan_bss *scan_parse_result(struct l_genl_msg *msg,
					uint32_t *out_ifindex,
					uint64_t *out_wdev,
					const uint8_t **out_ssid,
					uint8_t *out_ssid_len);

void bss_get_supported_ciphers(struct scan_bss *bss,
				uint16_t *pairwise_ciphers,
				uint16_t *group_ciphers);
