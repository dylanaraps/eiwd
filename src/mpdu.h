/*
 *
 *  Wireless daemon for Linux
 *
 *  Copyright (C) 2014  Intel Corporation. All rights reserved.
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

#include <stdint.h>
#include <stdbool.h>

enum mpdu_type {
	MPDU_TYPE_MANAGEMENT = 0,
};

enum mpdu_mgmt_type {
	MPDU_MGMT_TYPE_AUTHENTICATION   = 0xB,
	MPDU_MGMT_TYPE_DEAUTHENTICATION = 0xC,
};

enum mpdu_authentication_algorithm_number {
	MPDU_AUTH_ALGO_OPEN = 0,
	MPDU_AUTH_ALGO_SK,
};

struct mpdu_fc {
	union {
		struct {
			uint16_t protocol_version:2;
			uint16_t type:2;
			uint16_t subtype:4;
			uint16_t to_ds:1;
			uint16_t from_ds:1;
			uint16_t more_fragments:1;
			uint16_t retry:1;
			uint16_t power_mgmt:1;
			uint16_t more_data:1;
			uint16_t protected_frame:1;
			uint16_t order:1;
		};
		uint16_t content;
	};
};

struct mpdu_mgmt_header {
	uint16_t duration;
	unsigned char address_1[6];
	unsigned char address_2[6];
	unsigned char address_3[6];
	union {
		struct {
			uint16_t fragment_number:4;
			uint16_t sequence_number:12;
		};
		uint16_t sequence_control;
	};
	uint32_t ht_control; /* ToDo? */
};

struct mpdu_authentication {
	uint16_t algorithm;
	uint16_t transaction_sequence;
	uint16_t status;
	uint8_t challenge_text_len;
	unsigned char challenge_text[253];
	/* ToDo: FT and SAE parts? */
};

struct mpdu_deauthentication {
	uint16_t reason_code;
	/* ToDo: Vendor specific IE? MME? */
};

struct mpdu {
	struct mpdu_fc fc;
	struct mpdu_mgmt_header mgmt_hdr;
	union {
		struct mpdu_authentication auth;
		struct mpdu_deauthentication deauth;
	};
};

bool mpdu_decode(const unsigned char *mpdu, int len, struct mpdu *out);
