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
#include <asm/byteorder.h>
#include <linux/types.h>

/* 802.11, Table 8-1 "Valid type and subtype combinations" */
enum mpdu_type {
	MPDU_TYPE_MANAGEMENT = 0,
};

/* 802.11, Table 8-1 "Valid type and subtype combinations" */
enum mpdu_management_subtype {
	MPDU_MANAGEMENT_SUBTYPE_ASSOCIATION_REQUEST    = 0x0,
	MPDU_MANAGEMENT_SUBTYPE_ASSOCIATION_RESPONSE   = 0x1,
	MPDU_MANAGEMENT_SUBTYPE_REASSOCIATION_REQUEST  = 0x2,
	MPDU_MANAGEMENT_SUBTYPE_REASSOCIATION_RESPONSE = 0x3,
	MPDU_MANAGEMENT_SUBTYPE_PROBE_REQUEST          = 0x4,
	MPDU_MANAGEMENT_SUBTYPE_PROBE_RESPONSE         = 0x5,
	MPDU_MANAGEMENT_SUBTYPE_TIMING_ADVERTISEMENT   = 0x6,
	MPDU_MANAGEMENT_SUBTYPE_BEACON                 = 0x8,
	MPDU_MANAGEMENT_SUBTYPE_ATIM                   = 0x9,
	MPDU_MANAGEMENT_SUBTYPE_DISASSOCIATION         = 0xA,
	MPDU_MANAGEMENT_SUBTYPE_AUTHENTICATION         = 0xB,
	MPDU_MANAGEMENT_SUBTYPE_DEAUTHENTICATION       = 0xC,
};

/* 802.11, Section 8.4.1.1 Authentication Algorithm Number field */
enum mpdu_authentication_algorithm_number {
	MPDU_AUTH_ALGO_OPEN_SYSTEM = 0,
	MPDU_AUTH_ALGO_SHARED_KEY,
};

/* 802.11, Section 8.2.4.1.1, Figure 8-2 */
struct mpdu_fc {
#if defined(__LITTLE_ENDIAN_BITFIELD)
	uint8_t protocol_version:2;
	uint8_t type:2;
	uint8_t subtype:4;
	bool to_ds:1;
	bool from_ds:1;
	bool more_fragments:1;
	bool retry:1;
	bool power_mgmt:1;
	bool more_data:1;
	bool protected_frame:1;
	bool order:1;
#elif defined (__BIG_ENDIAN_BITFIELD)
	uint8_t subtype:4;
	uint8_t type:2;
	uint8_t protocol_version:2;
	bool order:1;
	bool protected_frame:1;
	bool more_data:1;
	bool power_mgmt:1;
	bool retry:1;
	bool more_fragments:1;
	bool from_ds:1;
	bool to_ds:1;
#else
#error  "Please fix <asm/byteorder.h>"
#endif
} __attribute__ ((packed));

/* 802.11, Section 8.3.3.1 */
struct mpdu_mgmt_header {
	__le16 duration;
	unsigned char address_1[6];
	unsigned char address_2[6];
	unsigned char address_3[6];
#if defined(__LITTLE_ENDIAN_BITFIELD)
	uint8_t fragment_number:4;
	uint8_t sequence_number_low:4;
#elif defined (__BIG_ENDIAN_BITFIELD)
	uint8_t sequence_number_low:4;
	uint8_t fragment_number:4;
#else
#error  "Please fix <asm/byteorder.h>"
#endif
	uint8_t sequence_number_high;
	__le32 ht_control; /* ToDo? */
} __attribute__ ((packed));

#define MPDU_MGMT_SEQUENCE_NUMBER(v)		\
	(((v).sequence_number_high << 4) + ((v).sequence_number_low))

/* 802.11, Section 8.4.1.4 */
struct mpdu_field_capability {
#if defined(__LITTLE_ENDIAN_BITFIELD)
	bool ess:1;
	bool ibss:1;
	bool cf_pollable:1;
	bool cf_poll_req:1;
	bool privacy:1;
	bool preamble:1;
	bool pbcc:1;
	bool chanl_agility:1;
	bool spectrum_mgmt:1;
	bool qos:1;
	bool short_time:1;
	bool apsd:1;
	bool radio_mesure:1;
	bool dsss_ofdm:1;
	bool delayed_ack:1;
	bool immediate_ack:1;
#elif defined (__BIG_ENDIAN_BITFIELD)
	bool chanl_agility:1;
	bool pbcc:1;
	bool preamble:1;
	bool privacy:1;
	bool cf_poll_req:1;
	bool cf_pollable:1;
	bool ibss:1;
	bool ess:1;
	bool immediate_ack:1;
	bool delayed_ack:1;
	bool dsss_ofdm:1;
	bool radio_mesure:1;
	bool apsd:1;
	bool short_time:1;
	bool qos:1;
	bool spectrum_mgmt:1;
#else
#error  "Please fix <asm/byteorder.h>"
#endif
} __attribute__ ((packed));

/* 802.11, Section 8.3.3.5 */
struct mpdu_association_request {
	struct mpdu_field_capability capability;
	__le16 listen_interval;
	uint8_t ies[0];
} __attribute__ ((packed));

/* 802.11, Section 8.3.3.6 */
struct mpdu_association_response {
	struct mpdu_field_capability capability;
	__le16 status_code;
	__le16 aid;
	uint8_t ies[0];
} __attribute__ ((packed));

/* 802.11, Section 8.3.3.7 */
struct mpdu_reassociation_request {
	struct mpdu_field_capability capability;
	__le16 listen_interval;
	unsigned char current_ap_address[6];
	uint8_t ies[0];
} __attribute__ ((packed));

/* 802.11, Section 8.3.3.8 */
struct mpdu_reassociation_response {
	struct mpdu_field_capability capability;
	__le16 status_code;
	__le16 aid;
	uint8_t ies[0];
} __attribute__ ((packed));

/* 802.11, Section 8.3.3.4 */
struct mpdu_disassociation {
	__le16 reason_code;
	uint8_t ies[0];
} __attribute__ ((packed));

/* 802.11, Section 8.3.3.9 */
struct mpdu_probe_request {
	uint8_t ies[0];
} __attribute__ ((packed));

/* 802.11, Section 8.3.3.10 */
struct mpdu_probe_response {
	uint8_t timestamp;
	__le16 beacon_interval;
	struct mpdu_field_capability capability;
	uint8_t ies[0];
} __attribute__ ((packed));

/* 802.11, Section 8.3.3.15 */
struct mpdu_timing_advertisement {
	uint8_t timestamp;
	struct mpdu_field_capability capability;
	uint8_t ies[0];
} __attribute__ ((packed));

/* 802.11, Section 8.3.3.2 */
struct mpdu_beacon {
	uint8_t timestamp;
	__le16 beacon_interval;
	struct mpdu_field_capability capability;
	uint8_t ies[0];
} __attribute__ ((packed));

/* 802.11, Section 8.3.3.11 */
struct mpdu_authentication {
	__le16 algorithm;
	__le16 transaction_sequence;
	__le16 status;

	union {
		struct {
			uint8_t element_id;
			uint8_t challenge_text_len;
			unsigned char challenge_text[253];
		} __attribute__ ((packed)) shared_key_23;
	};
	/* ToDo: FT and SAE parts? */
} __attribute__ ((packed));

/* 802.11, Section 8.3.3.12 */
struct mpdu_deauthentication {
	__le16 reason_code;
	uint8_t ies[0];
} __attribute__ ((packed));

struct mpdu {
	struct mpdu_fc fc;
	struct mpdu_mgmt_header mgmt_hdr;
	union {
		struct mpdu_association_request assoc_req;
		struct mpdu_association_response assoc_resp;
		struct mpdu_reassociation_request reassoc_req;
		struct mpdu_reassociation_response reassoc_resp;
		struct mpdu_probe_request probe_req;
		struct mpdu_probe_response probe_resp;
		struct mpdu_timing_advertisement time_advert;
		struct mpdu_beacon beacon;
		struct mpdu_disassociation disassoc;
		struct mpdu_authentication auth;
		struct mpdu_deauthentication deauth;
	};
} __attribute__ ((packed));

const struct mpdu *mpdu_validate(const uint8_t *frame, int len);
