/*
 *
 *  Wireless daemon for Linux
 *
 *  Copyright (C) 2019  Intel Corporation. All rights reserved.
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

struct wsc_credentials_info {
	char ssid[33];
	enum security security;
	union {
		uint8_t psk[32];
		char passphrase[64];
	};
	uint8_t addr[6];
	bool has_passphrase;
};

struct wsc_enrollee;

typedef void (*wsc_done_cb_t)(int err, struct wsc_credentials_info *creds,
				unsigned int n_creds, void *user_data);

struct wsc_enrollee *wsc_enrollee_new(struct netdev *netdev,
					struct scan_bss *target,
					const char *pin,
					wsc_done_cb_t done_cb, void *user_data);
void wsc_enrollee_cancel(struct wsc_enrollee *wsce, bool defer_cb);
void wsc_enrollee_destroy(struct wsc_enrollee *wsce);
