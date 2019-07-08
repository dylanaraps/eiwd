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

#include <stdint.h>

/* Wi-Fi P2P Technical Specification v1.7, Section 4.1.1, Table 6 */
enum p2p_attr {
	P2P_ATTR_STATUS = 0,
	P2P_ATTR_MINOR_REASON_CODE = 1,
	P2P_ATTR_P2P_CAPABILITY = 2,
	P2P_ATTR_P2P_DEVICE_ID = 3,
	P2P_ATTR_GO_INTENT = 4,
	P2P_ATTR_CONFIGURATION_TIMEOUT = 5,
	P2P_ATTR_LISTEN_CHANNEL = 6,
	P2P_ATTR_P2P_GROUP_BSSID = 7,
	P2P_ATTR_EXTENDED_LISTEN_TIMING = 8,
	P2P_ATTR_INTENDED_P2P_INTERFACE_ADDR = 9,
	P2P_ATTR_P2P_MANAGEABILITY = 10,
	P2P_ATTR_CHANNEL_LIST = 11,
	P2P_ATTR_NOTICE_OF_ABSENCE = 12,
	P2P_ATTR_P2P_DEVICE_INFO = 13,
	P2P_ATTR_P2P_GROUP_INFO = 14,
	P2P_ATTR_P2P_GROUP_ID = 15,
	P2P_ATTR_P2P_INTERFACE = 16,
	P2P_ATTR_OPERATING_CHANNEL = 17,
	P2P_ATTR_INVITATION_FLAGS = 18,
	P2P_ATTR_OOB_GO_NEGOTIATION_CHANNEL = 19,
	P2P_ATTR_SVC_HASH = 21,
	P2P_ATTR_SESSION_INFO_DATA_INFO = 22,
	P2P_ATTR_CONNECTION_CAPABILITY_INFO = 23,
	P2P_ATTR_ADVERTISEMENT_ID_INFO = 24,
	P2P_ATTR_ADVERTISED_SVC_INFO = 25,
	P2P_ATTR_SESSION_ID_INFO = 26,
	P2P_ATTR_FEATURE_CAPABILITY = 27,
	P2P_ATTR_PERSISTENT_GROUP_INFO = 28,
	P2P_ATTR_VENDOR_SPECIFIC_ATTR = 221,
};

/* Table 8 */
enum p2p_attr_status_code {
	P2P_STATUS_SUCCESS = 0,
	P2P_STATUS_FAIL_INFO_NOT_AVAIL = 1,
	P2P_STATUS_FAIL_INCOMPATIBLE_PARAMS = 2,
	P2P_STATUS_FAIL_LIMIT_REACHED = 3,
	P2P_STATUS_FAIL_INVALID_PARAMS = 4,
	P2P_STATUS_FAIL_UNABLE_TO_ACCOMMODATE_REQUEST = 5,
	P2P_STATUS_FAIL_PREV_PROTOCOL_ERROR = 6,
	P2P_STATUS_FAIL_NO_COMMON_CHANNELS = 7,
	P2P_STATUS_FAIL_UNKNOWN_P2P_GROUP = 8,
	P2P_STATUS_FAIL_INTENT_15_IN_GO_NEGOTIATION = 9,
	P2P_STATUS_FAIL_INCOMPATIBLE_PROVISIONING = 10,
	P2P_STATUS_FAIL_REJECTED_BY_USER = 11,
	P2P_STATUS_SUCCESS_ACCEPTED_BY_USER = 12,
};

/* Table 12 */
enum p2p_device_capability_bitmap {
	P2P_DEVICE_CAP_SVC_DISCOVERY		= 0x01,
	P2P_DEVICE_CAP_CLIENT_DISCOVERABILITY	= 0x02,
	P2P_DEVICE_CAP_CONCURRENT_OP		= 0x04,
	P2P_DEVICE_CAP_INFRASTRUCTURE_MANAGED	= 0x08,
	P2P_DEVICE_CAP_DEVICE_LIMIT		= 0x10,
	P2P_DEVICE_CAP_INVITATION_PROCEDURE	= 0x20,
};

/* Table 13 */
enum p2p_group_capability_bitmap {
	P2P_GROUP_CAP_GO			= 0x01,
	P2P_GROUP_CAP_PERSISTENT_GROUP		= 0x02,
	P2P_GROUP_CAP_GROUP_LIMIT		= 0x04,
	P2P_GROUP_CAP_INTRA_BSS_DISTRIBUTION	= 0x08,
	P2P_GROUP_CAP_CROSS_CONNECT		= 0x10,
	P2P_GROUP_CAP_PERSISTENT_RECONNECT	= 0x20,
	P2P_GROUP_CAP_GROUP_FORMATION		= 0x40,
	P2P_GROUP_CAP_IP_ALLOCATION		= 0x80,
};

/* Table 23 */
enum p2p_manageability_bitmap {
	P2P_MANAGEABILITY_DEVICE_MGMT		= 0x01,
	P2P_MANAGEABILITY_CROSS_CONNECT		= 0x02,
	P2P_MANAGEABILITY_COEXIST_OPTIONAL	= 0x04,
};

/* Table 61 */
enum p2p_public_action_frame_type {
	P2P_ACTION_GO_NEGOTIATION_REQ		= 0,
	P2P_ACTION_GO_NEGOTIATION_RESP		= 1,
	P2P_ACTION_GO_NEGOTIATION_CONFIRM	= 2,
	P2P_ACTION_INVITATION_REQ		= 3,
	P2P_ACTION_INVITATION_RESP		= 4,
	P2P_ACTION_DEVICE_DISCOVERABILITY_REQ	= 5,
	P2P_ACTION_DEVICE_DISCOVERABILITY_RESP	= 6,
	P2P_ACTION_PROVISION_DISCOVERY_REQ	= 7,
	P2P_ACTION_PROVISION_DISCOVERY_RESP	= 8,
};

/* Table 75 */
enum p2p_action_frame_type {
	P2P_ACTION_NOTICE_OF_ABSENCE		= 0,
	P2P_ACTION_PRESENCE_REQ 		= 1,
	P2P_ACTION_PRESENCE_RESP 		= 2,
	P2P_ACTION_GO_DISCOVERABILITY_REQ	= 3,
};

struct p2p_attr_iter {
	const uint8_t *pos;
	const uint8_t *end;
	enum p2p_attr type;
	size_t len;
};

void p2p_attr_iter_init(struct p2p_attr_iter *iter, const uint8_t *pdu,
			size_t len);
bool p2p_attr_iter_next(struct p2p_attr_iter *iter);

static inline enum p2p_attr p2p_attr_iter_get_type(struct p2p_attr_iter *iter)
{
	return iter->type;
}

static inline size_t p2p_attr_iter_get_length(struct p2p_attr_iter *iter)
{
	return iter->len;
}

static inline const uint8_t *p2p_attr_iter_get_data(struct p2p_attr_iter *iter)
{
	return iter->pos + 3;
}
