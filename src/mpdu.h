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

/* Std 802.11, Section 8.2.3 */
#define IEEE80211_MAX_DATA_LEN		2304

/* 802.11, Table 8-1 "Valid type and subtype combinations" */
enum mpdu_type {
	MPDU_TYPE_MANAGEMENT = 0,
};

/* 802.11-2016, Table 9-1 "Valid type and subtype combinations" */
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
	MPDU_MANAGEMENT_SUBTYPE_ACTION                 = 0xD,
	MPDU_MANAGEMENT_SUBTYPE_ACTION_NO_ACK          = 0xE,
};

/* 802.11-2016, Section 9.4.1.1 Authentication Algorithm Number field */
enum mmpdu_authentication_algorithm_number {
	MMPDU_AUTH_ALGO_OPEN_SYSTEM = 0,
	MMPDU_AUTH_ALGO_SHARED_KEY,
	MMPDU_AUTH_ALGO_FT,
	MMPDU_AUTH_ALGO_SAE,
};

/*
 * 802.11-2016, Section 9.4.1.7:
 */
enum mmpdu_reason_code {
	MMPDU_REASON_CODE_UNSPECIFIED = 1,
	MMPDU_REASON_CODE_PREV_AUTH_NOT_VALID = 2,
	MMPDU_REASON_CODE_DEAUTH_LEAVING = 3,
	MMPDU_REASON_CODE_DISASSOC_DUE_TO_INACTIVITY = 4,
	MMPDU_REASON_CODE_DISASSOC_AP_BUSY = 5,
	MMPDU_REASON_CODE_CLASS2_FRAME_FROM_NONAUTH_STA = 6,
	MMPDU_REASON_CODE_CLASS3_FRAME_FROM_NONASSOC_STA = 7,
	MMPDU_REASON_CODE_DISASSOC_STA_HAS_LEFT = 8,
	MMPDU_REASON_CODE_STA_REQ_ASSOC_WITHOUT_AUTH = 9,
	/* 802.11h */
	MMPDU_REASON_CODE_DISASSOC_BAD_POWER = 10,
	MMPDU_REASON_CODE_DISASSOC_BAD_SUPP_CHAN = 11,
	/* 802.11i */
	MMPDU_REASON_CODE_INVALID_IE = 13,
	MMPDU_REASON_CODE_MIC_FAILURE = 14,
	MMPDU_REASON_CODE_4WAY_HANDSHAKE_TIMEOUT = 15,
	MMPDU_REASON_CODE_GROUP_KEY_HANDSHAKE_TIMEOUT = 16,
	MMPDU_REASON_CODE_IE_DIFFERENT = 17,
	MMPDU_REASON_CODE_INVALID_GROUP_CIPHER = 18,
	MMPDU_REASON_CODE_INVALID_PAIRWISE_CIPHER = 19,
	MMPDU_REASON_CODE_INVALID_AKMP = 20,
	MMPDU_REASON_CODE_UNSUPP_RSN_VERSION = 21,
	MMPDU_REASON_CODE_INVALID_RSN_IE_CAP = 22,
	MMPDU_REASON_CODE_IEEE8021X_FAILED = 23,
	MMPDU_REASON_CODE_CIPHER_SUITE_REJECTED = 24,
	/* TDLS (802.11z) */
	MMPDU_REASON_CODE_TDLS_TEARDOWN_UNREACHABLE = 25,
	MMPDU_REASON_CODE_TDLS_TEARDOWN_UNSPECIFIED = 26,
	/* 802.11e */
	MMPDU_REASON_CODE_DISASSOC_UNSPECIFIED_QOS = 32,
	MMPDU_REASON_CODE_DISASSOC_QAP_NO_BANDWIDTH = 33,
	MMPDU_REASON_CODE_DISASSOC_LOW_ACK = 34,
	MMPDU_REASON_CODE_DISASSOC_QAP_EXCEED_TXOP = 35,
	MMPDU_REASON_CODE_QSTA_LEAVE_QBSS = 36,
	MMPDU_REASON_CODE_QSTA_NOT_USE = 37,
	MMPDU_REASON_CODE_QSTA_REQUIRE_SETUP = 38,
	MMPDU_REASON_CODE_QSTA_TIMEOUT = 39,
	MMPDU_REASON_CODE_QSTA_CIPHER_NOT_SUPP = 45,
	/* 802.11s */
	MMPDU_REASON_CODE_MESH_PEER_CANCELED = 52,
	MMPDU_REASON_CODE_MESH_MAX_PEERS = 53,
	MMPDU_REASON_CODE_MESH_CONFIG = 54,
	MMPDU_REASON_CODE_MESH_CLOSE = 55,
	MMPDU_REASON_CODE_MESH_MAX_RETRIES = 56,
	MMPDU_REASON_CODE_MESH_CONFIRM_TIMEOUT = 57,
	MMPDU_REASON_CODE_MESH_INVALID_GTK = 58,
	MMPDU_REASON_CODE_MESH_INCONSISTENT_PARAM = 59,
	MMPDU_REASON_CODE_MESH_INVALID_SECURITY = 60,
	MMPDU_REASON_CODE_MESH_PATH_ERROR = 61,
	MMPDU_REASON_CODE_MESH_PATH_NOFORWARD = 62,
	MMPDU_REASON_CODE_MESH_PATH_DEST_UNREACHABLE = 63,
	MMPDU_REASON_CODE_MAC_EXISTS_IN_MBSS = 64,
	MMPDU_REASON_CODE_MESH_CHAN_REGULATORY = 65,
	MMPDU_REASON_CODE_MESH_CHAN = 66,
	MMPDU_REASON_CODE_REJECTED_FOR_SSP_PERMISSION = 67,
	MMPDU_REASON_CODE_REFUSED_UNAUTHENTICATED_ACCESS = 68,
	/* 69 - 71 reserved */
	MMPDU_REASON_CODE_INVALID_RSNE = 72,
	MMPDU_REASON_CODE_U_APSD_COEXISTANCE_NOTSUPP = 73,
	MMPDU_REASON_CODE_U_ASPD_COEX_MODE_NOTSUPP = 74,
	MMPDU_REASON_CODE_BAD_INTERVAL_WITH_U_APSD = 75,
	MMPDU_REASON_CODE_ANTI_CLOGGING_TOKEN_REQ = 76,
	MMPDU_REASON_CODE_UNSUPP_FINITE_CYCLIC_GROUP = 77,
	MMPDU_REASON_CODE_CANNOT_FIND_ALT_TBTT = 78,
	MMPDU_REASON_CODE_TRANSMISSION_FAILURE = 79,
	MMPDU_REASON_CODE_REQUESTED_TCLAS_NOTSUPP = 80,
	MMPDU_REASON_CODE_TCLAS_RESOURCES_EXAUSTED = 81,
	MMPDU_REASON_CODE_REJECTED_WITH_SUGG_BSS_TRANS = 82,
	MMPDU_REASON_CODE_REJECT_WITH_SCHEDULE = 83,
	MMPDU_REASON_CODE_REJECT_NOT_WAKEUP_SPECIFIED = 84,
	MMPDU_REASON_CODE_SUCCESS_POWER_SAVE_MODE = 85,
	MMPDU_REASON_CODE_PENDING_ADMITTING_FST_SESSION = 86,
	MMPDU_REASON_CODE_PERFORMING_FST_NOW = 87,
	MMPDU_REASON_CODE_PENDING_GAP_IN_BA_WINDOW = 88,
	MMPDU_REASON_CODE_REJECT_U_PID_SETTING = 89,
	/* 90 - 91 reserved */
	MMPDU_REASON_CODE_REFUSED_EXTERNAL_REASON = 92,
	MMPDU_REASON_CODE_REFUSED_AP_OUT_OF_MEMORY = 93,
	MMPDU_REASON_CODE_REJECTED_EMERGENCY_SVC_NOTSUPP = 94,
	MMPDU_REASON_CODE_QUERY_RESPONSE_OUTSTANDING = 95,
	MMPDU_REASON_CODE_REJECT_DSE_BAND = 96,
	MMPDU_REASON_CODE_TCLAS_PROCESSING_TERMINATED = 97,
	MMPDU_REASON_CODE_TS_SCHEDULE_CONFLICT = 98,
	MMPDU_REASON_CODE_DENIED_WITH_BAND_CHANNEL = 99,
	MMPDU_REASON_CODE_MCCAOP_RESERVATION_CONFLICT = 100,
	MMPDU_REASON_CODE_MAF_LIMIT_EXCEEDED = 101,
	MMPDU_REASON_CODE_MCCA_TRACK_LIMIT_EXCEEDED = 102,
	MMPDU_REASON_CODE_DENIED_SPECTRUM_MANAGEMENT = 103,
	MMPDU_REASON_CODE_DENIED_VHT_NOTSUPP = 104,
	MMPDU_REASON_CODE_ENABLEMENT_DENIED = 105,
	MMPDU_REASON_CODE_RESTRICTION_FROM_AUTH_GDB = 106,
	MMPDU_REASON_CODE_AUTHORIZATION_DEENABLED = 107,
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
struct mmpdu_header {
	struct mpdu_fc fc;
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

#define MPDU_SEQUENCE_NUMBER(v)		\
	(((v).sequence_number_high << 4) + ((v).sequence_number_low))

/* 802.11, Section 8.4.1.4 */
struct mmpdu_field_capability {
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
struct mmpdu_association_request {
	struct mmpdu_field_capability capability;
	__le16 listen_interval;
	uint8_t ies[0];
} __attribute__ ((packed));

/* 802.11, Section 8.3.3.6 */
struct mmpdu_association_response {
	struct mmpdu_field_capability capability;
	__le16 status_code;
	__le16 aid;
	uint8_t ies[0];
} __attribute__ ((packed));

/* 802.11, Section 8.3.3.7 */
struct mmpdu_reassociation_request {
	struct mmpdu_field_capability capability;
	__le16 listen_interval;
	unsigned char current_ap_address[6];
	uint8_t ies[0];
} __attribute__ ((packed));

/* 802.11, Section 8.3.3.8 */
struct mmpdu_reassociation_response {
	struct mmpdu_field_capability capability;
	__le16 status_code;
	__le16 aid;
	uint8_t ies[0];
} __attribute__ ((packed));

/* 802.11, Section 8.3.3.4 */
struct mmpdu_disassociation {
	__le16 reason_code;
	uint8_t ies[0];
} __attribute__ ((packed));

/* 802.11, Section 8.3.3.9 */
struct mmpdu_probe_request {
	uint8_t ies[0];
} __attribute__ ((packed));

/* 802.11, Section 8.3.3.10 */
struct mmpdu_probe_response {
	uint8_t timestamp;
	__le16 beacon_interval;
	struct mmpdu_field_capability capability;
	uint8_t ies[0];
} __attribute__ ((packed));

/* 802.11, Section 8.3.3.15 */
struct mmpdu_timing_advertisement {
	uint8_t timestamp;
	struct mmpdu_field_capability capability;
	uint8_t ies[0];
} __attribute__ ((packed));

/* 802.11, Section 8.3.3.2 */
struct mmpdu_beacon {
	uint8_t timestamp;
	__le16 beacon_interval;
	struct mmpdu_field_capability capability;
	uint8_t ies[0];
} __attribute__ ((packed));

/* 802.11, Section 8.3.3.11 */
struct mmpdu_authentication {
	__le16 algorithm;
	__le16 transaction_sequence;
	__le16 status;
	uint8_t ies[];
} __attribute__ ((packed));

/* 802.11, Section 8.3.3.12 */
struct mmpdu_deauthentication {
	__le16 reason_code;
	uint8_t ies[0];
} __attribute__ ((packed));

const struct mmpdu_header *mpdu_validate(const uint8_t *frame, int len);
const void *mmpdu_body(const struct mmpdu_header *mpdu);
