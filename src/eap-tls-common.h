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

struct databuf {
	uint8_t *data;
	size_t len;
	size_t capacity;
};

struct databuf;
struct databuf *databuf_new(size_t capacity);
void databuf_append(struct databuf *databuf, const uint8_t *data,
							size_t data_len);
void databuf_free(struct databuf *databuf);

enum eap_tls_version {
	EAP_TLS_VERSION_0               = 0x00,
	EAP_TLS_VERSION_1               = 0x01,
	EAP_TLS_VERSION_MASK            = 0x07,
	EAP_TLS_VERSION_NOT_NEGOTIATED  = 0x08,
};

void eap_tls_common_state_free(struct eap_state *eap);

int eap_tls_common_settings_check(struct l_settings *settings,
						struct l_queue *secrets,
						const char *prefix,
						struct l_queue **out_missing);
bool eap_tls_common_settings_load(struct eap_state *eap,
						struct l_settings *settings,
						const char *prefix);
