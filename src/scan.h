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

enum scan_band {
	SCAN_BAND_2_4_GHZ,
	SCAN_BAND_5_GHZ,
};

typedef void (*scan_func_t)(struct l_genl_msg *msg, void *user_data);
typedef bool (*scan_notify_func_t)(uint32_t wiphy, uint32_t ifindex,
					struct l_queue *bss_list);

struct scan_freq_set;
struct ie_rsn_info;
enum ie_bss_capability;

struct scan_bss {
	uint8_t addr[6];
	uint32_t frequency;
	int32_t signal_strength;
	uint16_t capability;
	uint8_t *rsne;
	uint8_t *wpa;
	uint8_t ssid[32];
	uint8_t ssid_len;
	struct l_uintset *supported_rates;
	uint8_t utilization;
	uint16_t rank;
};

void scan_start(struct l_genl_family *nl80211, uint32_t ifindex,
		scan_func_t callback, void *user_data);
void scan_periodic_start(uint32_t ifindex);
bool scan_periodic_stop(uint32_t ifindex);

void scan_sched_start(struct l_genl_family *nl80211, uint32_t ifindex,
			uint32_t scan_interval, scan_func_t callback,
			void *user_data);

enum scan_ssid_security scan_get_ssid_security(enum ie_bss_capability bss_cap,
						const struct ie_rsn_info *info);
void scan_bss_free(struct scan_bss *bss);
void scan_bss_compute_rank(struct scan_bss *bss);
int scan_bss_rank_compare(const void *a, const void *b, void *user);

void bss_get_supported_ciphers(struct scan_bss *bss,
				uint16_t *pairwise_ciphers,
				uint16_t *group_ciphers);

uint8_t scan_freq_to_channel(uint32_t freq, enum scan_band *out_band);

struct scan_freq_set *scan_freq_set_new(void);
void scan_freq_set_free(struct scan_freq_set *freqs);
bool scan_freq_set_add(struct scan_freq_set *freqs, uint32_t freq);
bool scan_freq_set_contains(struct scan_freq_set *freqs, uint32_t freq);

bool scan_init(struct l_genl_family *in, scan_notify_func_t func);
bool scan_exit();
