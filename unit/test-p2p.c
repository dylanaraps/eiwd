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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>
#include <errno.h>
#include <ell/ell.h>

#include "src/p2putil.h"
#include "src/ie.h"

static const uint8_t p2p_attrs1[] = {
	0x02, 0x02, 0x00, 0x25, 0x00, 0x0d, 0x1d, 0x00, 0x00, 0x28, 0xf8, 0xed,
	0x26, 0x57, 0x11, 0x08, 0x00, 0x01, 0x00, 0x50, 0xf2, 0x04, 0x00, 0x01,
	0x00, 0x10, 0x11, 0x00, 0x08, 0x74, 0x65, 0x73, 0x74, 0x64, 0x65, 0x76,
	0x31, 0x0f, 0x15, 0x00, 0x2a, 0xfe, 0xcd, 0x01, 0xbe, 0xa0, 0x44, 0x49,
	0x52, 0x45, 0x43, 0x54, 0x2d, 0x5a, 0x75, 0x2d, 0x41, 0x6e, 0x64, 0x72,
	0x65,
};

static void p2p_test_iter_sanity_check(const void *data)
{
	struct p2p_attr_iter iter;

	p2p_attr_iter_init(&iter, p2p_attrs1, sizeof(p2p_attrs1));

	assert(p2p_attr_iter_next(&iter));
	assert(p2p_attr_iter_get_type(&iter) == P2P_ATTR_P2P_CAPABILITY);
	assert(p2p_attr_iter_get_length(&iter) == 2);

	assert(p2p_attr_iter_next(&iter));
	assert(p2p_attr_iter_get_type(&iter) == P2P_ATTR_P2P_DEVICE_INFO);
	assert(p2p_attr_iter_get_length(&iter) == 29);

	assert(p2p_attr_iter_next(&iter));
	assert(p2p_attr_iter_get_type(&iter) == P2P_ATTR_P2P_GROUP_ID);
	assert(p2p_attr_iter_get_length(&iter) == 21);

	assert(!p2p_attr_iter_next(&iter));
}

typedef bool (*test_queue_cmp_func)(const void *data1, const void *data2);

static bool test_queue_cmp(struct l_queue *q1, struct l_queue *q2,
				test_queue_cmp_func func)
{
	const struct l_queue_entry *entry1 = l_queue_get_entries(q1);
	const struct l_queue_entry *entry2 = l_queue_get_entries(q2);

	while (entry1 && entry2) {
		if (!func(entry1->data, entry2->data))
			return false;

		entry1 = entry1->next;
		entry2 = entry2->next;
	}

	return !entry1 && !entry2;
}

static bool p2p_noa_desc_cmp(const void *data1, const void *data2)
{
	const struct p2p_notice_of_absence_desc *desc1 = data1;
	const struct p2p_notice_of_absence_desc *desc2 = data2;

	if (desc1->count_type != desc2->count_type)
		return false;
	if (desc1->duration != desc2->duration)
		return false;
	if (desc1->interval != desc2->interval)
		return false;
	if (desc1->start_time != desc2->start_time)
		return false;

	return true;
}

/*
 * The attributes in a P2P IE are not explicitly required to be ordered
 * in the same way they're listed in each frame's format specification in
 * Wi-Fi P2P Technical Specification v1.7 and in fact some consumer devices
 * switch some attributes' order in their probe responses.  This compares
 * the contents of two sets of P2P IEs ignoring attribute order and payload
 * segmentation into individual P2P IEs.
 * TODO: Might also want to validate the WSC IEs written by the p2putil.c
 * builder functions.
 */
static bool p2p_payload_cmd(const uint8_t *ies1, size_t ies1_len,
				const uint8_t *ies2, size_t ies2_len)
{
	uint8_t *payload1, *payload2;
	ssize_t payload1_len, payload2_len;
	struct p2p_attr_iter iter1, iter2;
	const uint8_t *attr1_start[P2P_ATTR_PERSISTENT_GROUP_INFO + 1];
	int i;
	bool r = false;

	if (!ies1 || !ies2)
		return false;

	payload1 = ie_tlv_extract_p2p_payload(ies1, ies1_len, &payload1_len);
	payload2 = ie_tlv_extract_p2p_payload(ies2, ies2_len, &payload2_len);

	if (payload1_len < 0 || payload2_len < 0)
		return false;

	p2p_attr_iter_init(&iter1, payload1, payload1_len);
	p2p_attr_iter_init(&iter2, payload2, payload2_len);

	memset(attr1_start, 0, sizeof(attr1_start));

	while (p2p_attr_iter_next(&iter1)) {
		enum p2p_attr type = p2p_attr_iter_get_type(&iter1);
		const uint8_t *start = p2p_attr_iter_get_data(&iter1) - 3;

		if (type >= L_ARRAY_SIZE(attr1_start))
			goto done;	/* Unknown attribute */

		if (attr1_start[type])
			goto done;	/* Duplicate attribute type in @ies1 */

		attr1_start[type] = start;
	}

	while (p2p_attr_iter_next(&iter2)) {
		enum p2p_attr type = p2p_attr_iter_get_type(&iter2);
		const uint8_t *start = p2p_attr_iter_get_data(&iter2) - 3;
		size_t len;

		if ((int) type >= (int) L_ARRAY_SIZE(attr1_start))
			goto done;	/* Unknown attribute */

		if (!attr1_start[type])
			goto done;	/* Not in @ies1 or dupe in @ies2 */

		len = p2p_attr_iter_get_length(&iter2) + 3;

		/*
		 * It's safe to memcmp len bytes because the length is also
		 * encoded in the first 3 bytes of both buffers.
		 */
		if (memcmp(start, attr1_start[type], len))
			goto done;	/* Contents or lengths differ */

		attr1_start[type] = NULL;
	}

	for (i = 0; i < (int) L_ARRAY_SIZE(attr1_start); i++)
		if (attr1_start[i])
			goto done;	/* @ies1 attribute was not in @ies2 */

	r = true;

done:
	l_free(payload1);
	l_free(payload2);
	return r;
}

static const uint8_t p2p_beacon_ies_1[] = {
	0xdd, 0x12, 0x50, 0x6f, 0x9a, 0x09, 0x02, 0x02, 0x00, 0x05, 0xab, 0x03,
	0x06, 0x00, 0x2a, 0xfe, 0xcd, 0x01, 0xbe, 0xa0, 0xdd, 0x4e, 0x00, 0x50,
	0xf2, 0x04, 0x10, 0x4a, 0x00, 0x01, 0x10, 0x10, 0x44, 0x00, 0x01, 0x02,
	0x10, 0x41, 0x00, 0x01, 0x01, 0x10, 0x12, 0x00, 0x02, 0x00, 0x04, 0x10,
	0x53, 0x00, 0x02, 0x43, 0x88, 0x10, 0x49, 0x00, 0x0e, 0x00, 0x37, 0x2a,
	0x00, 0x01, 0x20, 0x01, 0x06, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x10,
	0x11, 0x00, 0x0d, 0x4c, 0x45, 0x58, 0x36, 0x32, 0x36, 0x2d, 0x50, 0x64,
	0x61, 0x4e, 0x65, 0x74, 0x10, 0x54, 0x00, 0x08, 0x00, 0x08, 0x00, 0x50,
	0xf2, 0x04, 0x00, 0x02, 0xdd, 0x16, 0x50, 0x6f, 0x9a, 0x09, 0x0c, 0x0f,
	0x00, 0xe1, 0x00, 0x01, 0xb0, 0xb3, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x7c, 0x45, 0x8f, 0x0c,
};

struct p2p_beacon_data {
	const uint8_t *ies;
	size_t ies_len;
	ssize_t payload_len;
	struct p2p_beacon data;
	const struct p2p_notice_of_absence_desc *noa_descs;
};

static const struct p2p_beacon_data p2p_beacon_data_1 = {
	.ies = p2p_beacon_ies_1,
	.ies_len = L_ARRAY_SIZE(p2p_beacon_ies_1),
	.payload_len = 32,
	.data = {
		.capability = {
			.device_caps = P2P_DEVICE_CAP_SVC_DISCOVERY |
				P2P_DEVICE_CAP_CONCURRENT_OP,
			.group_caps = P2P_GROUP_CAP_GO |
				P2P_GROUP_CAP_PERSISTENT_GROUP |
				P2P_GROUP_CAP_INTRA_BSS_DISTRIBUTION |
				P2P_GROUP_CAP_PERSISTENT_RECONNECT |
				P2P_GROUP_CAP_IP_ALLOCATION,
		},
		.device_addr = { 0x2a, 0xfe, 0xcd, 0x01, 0xbe, 0xa0 },
		.notice_of_absence = {
			.index = 225,
			.opp_ps = false,
			.ct_window = 0,
		},
	},
	.noa_descs = (const struct p2p_notice_of_absence_desc []) {
		[0] = {
			.count_type = 1,
			.duration = 46000,
			.interval = 0,
			.start_time = 210716028,
		},
		[1] = {}
	},
};

static void p2p_test_parse_beacon(const void *data)
{
	const struct p2p_beacon_data *test = data;
	struct p2p_beacon attrs1, attrs2;
	const struct p2p_notice_of_absence_desc *desc = test->noa_descs;
	uint8_t *payload;
	ssize_t payload_len;

	payload = ie_tlv_extract_p2p_payload(test->ies, test->ies_len,
						&payload_len);
	l_free(payload);
	assert(payload_len == test->payload_len);

	memcpy(&attrs2, &test->data, sizeof(attrs2));

	if (desc)
		attrs2.notice_of_absence.descriptors = l_queue_new();

	while (desc && desc->start_time) {
		l_queue_push_tail(attrs2.notice_of_absence.descriptors,
					l_memdup(desc, sizeof(*desc)));
		desc++;
	}

	assert(p2p_parse_beacon(test->ies, test->ies_len, &attrs1) == 0);

	assert(attrs1.capability.device_caps == attrs2.capability.device_caps);
	assert(attrs1.capability.group_caps == attrs2.capability.group_caps);

	assert(!memcmp(attrs1.device_addr, attrs2.device_addr, 6));

	assert(attrs1.notice_of_absence.index ==
		attrs2.notice_of_absence.index);
	assert(attrs1.notice_of_absence.opp_ps ==
		attrs2.notice_of_absence.opp_ps);
	assert(attrs1.notice_of_absence.ct_window ==
		attrs2.notice_of_absence.ct_window);
	assert(test_queue_cmp(attrs1.notice_of_absence.descriptors,
				attrs2.notice_of_absence.descriptors,
				p2p_noa_desc_cmp));

	p2p_free_beacon(&attrs1);
	p2p_free_beacon(&attrs2);
}

static void p2p_test_build_beacon(const void *data)
{
	const struct p2p_beacon_data *test = data;
	struct p2p_beacon attrs2;
	const struct p2p_notice_of_absence_desc *desc = test->noa_descs;
	uint8_t *ies;
	size_t ies_len;

	memcpy(&attrs2, &test->data, sizeof(attrs2));

	if (desc)
		attrs2.notice_of_absence.descriptors = l_queue_new();

	while (desc && desc->start_time) {
		l_queue_push_tail(attrs2.notice_of_absence.descriptors,
					l_memdup(desc, sizeof(*desc)));
		desc++;
	}

	ies = p2p_build_beacon(&attrs2, &ies_len);
	p2p_free_beacon(&attrs2);

	assert(p2p_payload_cmd(ies, ies_len, test->ies, test->ies_len));
	l_free(ies);
}

static const uint8_t p2p_probe_req_ies_1[] = {
	0xdd, 0x73, 0x00, 0x50, 0xf2, 0x04, 0x10, 0x4a, 0x00, 0x01, 0x10, 0x10,
	0x3a, 0x00, 0x01, 0x01, 0x10, 0x08, 0x00, 0x02, 0x31, 0x48, 0x10, 0x47,
	0x00, 0x10, 0x9a, 0xdd, 0x77, 0x82, 0xcb, 0xa6, 0x5e, 0x2d, 0xac, 0xd9,
	0xc0, 0x54, 0x34, 0xd0, 0xd7, 0x29, 0x10, 0x54, 0x00, 0x08, 0x00, 0x01,
	0x00, 0x50, 0xf2, 0x04, 0x00, 0x01, 0x10, 0x3c, 0x00, 0x01, 0x03, 0x10,
	0x02, 0x00, 0x02, 0x00, 0x00, 0x10, 0x09, 0x00, 0x02, 0x00, 0x00, 0x10,
	0x12, 0x00, 0x02, 0x00, 0x00, 0x10, 0x21, 0x00, 0x01, 0x20, 0x10, 0x23,
	0x00, 0x01, 0x20, 0x10, 0x24, 0x00, 0x01, 0x20, 0x10, 0x11, 0x00, 0x08,
	0x74, 0x65, 0x73, 0x74, 0x64, 0x65, 0x76, 0x31, 0x10, 0x49, 0x00, 0x09,
	0x00, 0x37, 0x2a, 0x00, 0x01, 0x20, 0x03, 0x01, 0x01, 0xdd, 0x11, 0x50,
	0x6f, 0x9a, 0x09, 0x02, 0x02, 0x00, 0x25, 0x00, 0x06, 0x05, 0x00, 0x58,
	0x58, 0x04, 0x51, 0x01,
};

struct p2p_probe_req_data {
	const uint8_t *ies;
	size_t ies_len;
	ssize_t payload_len;
	struct p2p_probe_req data;
};

static const struct p2p_probe_req_data p2p_probe_req_data_1 = {
	.ies = p2p_probe_req_ies_1,
	.ies_len = L_ARRAY_SIZE(p2p_probe_req_ies_1),
	.payload_len = 13,
	.data = {
		.capability = {
			.device_caps = P2P_DEVICE_CAP_SVC_DISCOVERY |
				P2P_DEVICE_CAP_CONCURRENT_OP |
				P2P_DEVICE_CAP_INVITATION_PROCEDURE,
			.group_caps = 0,
		},
		.listen_channel = {
			.country = "XX\x04",
			.oper_class = 81,
			.channel_num = 1,
		},
	},
};

static void p2p_test_parse_probe_req(const void *data)
{
	const struct p2p_probe_req_data *test = data;
	uint8_t *payload;
	ssize_t payload_len;
	struct p2p_probe_req attrs;

	payload = ie_tlv_extract_p2p_payload(test->ies, test->ies_len,
						&payload_len);
	l_free(payload);
	assert(payload_len == test->payload_len);

	assert(p2p_parse_probe_req(test->ies, test->ies_len, &attrs) == 0);

	assert(attrs.capability.device_caps ==
		test->data.capability.device_caps);
	assert(attrs.capability.group_caps == test->data.capability.group_caps);

	assert(!memcmp(attrs.device_addr, test->data.device_addr, 6));

	assert(!memcmp(attrs.listen_channel.country,
			test->data.listen_channel.country, 3));
	assert(attrs.listen_channel.oper_class ==
		test->data.listen_channel.oper_class);
	assert(attrs.listen_channel.channel_num ==
		test->data.listen_channel.channel_num);

	assert(attrs.listen_availability.avail_period_ms ==
		test->data.listen_availability.avail_period_ms);
	assert(attrs.listen_availability.avail_interval_ms ==
		test->data.listen_availability.avail_interval_ms);

	assert(!memcmp(attrs.device_info.device_addr,
			test->data.device_info.device_addr, 6));
	assert(attrs.device_info.wsc_config_methods ==
		test->data.device_info.wsc_config_methods);
	assert(attrs.device_info.primary_device_type.category ==
		test->data.device_info.primary_device_type.category);
	assert(!memcmp(attrs.device_info.primary_device_type.oui,
			test->data.device_info.primary_device_type.oui, 3));
	assert(attrs.device_info.primary_device_type.oui_type ==
		test->data.device_info.primary_device_type.oui_type);
	assert(attrs.device_info.primary_device_type.subcategory ==
		test->data.device_info.primary_device_type.subcategory);
	assert(l_queue_length(attrs.device_info.secondary_device_types) ==
		l_queue_length(test->data.device_info.secondary_device_types));
	assert(!strcmp(attrs.device_info.device_name,
			test->data.device_info.device_name));

	assert(!memcmp(attrs.operating_channel.country,
			test->data.operating_channel.country, 3));
	assert(attrs.operating_channel.oper_class ==
		test->data.operating_channel.oper_class);
	assert(attrs.operating_channel.channel_num ==
		test->data.operating_channel.channel_num);

	assert(l_queue_length(attrs.service_hashes) ==
		l_queue_length(test->data.service_hashes));

	p2p_free_probe_req(&attrs);
}

static void p2p_test_build_probe_req(const void *data)
{
	const struct p2p_probe_req_data *test = data;
	uint8_t *ies;
	size_t ies_len;

	ies = p2p_build_probe_req(&test->data, &ies_len);

	assert(p2p_payload_cmd(ies, ies_len, test->ies, test->ies_len));
	l_free(ies);
}

/* Notice of Absence and Device Info in the wrong order */
static const uint8_t p2p_probe_resp_ies_1[] = {
	0xdd, 0xa2, 0x00, 0x50, 0xf2, 0x04, 0x10, 0x4a, 0x00, 0x01, 0x10, 0x10,
	0x44, 0x00, 0x01, 0x02, 0x10, 0x41, 0x00, 0x01, 0x01, 0x10, 0x12, 0x00,
	0x02, 0x00, 0x04, 0x10, 0x53, 0x00, 0x02, 0x43, 0x88, 0x10, 0x3b, 0x00,
	0x01, 0x03, 0x10, 0x47, 0x00, 0x10, 0xb1, 0x7d, 0x6f, 0xc9, 0x4f, 0xd1,
	0x5a, 0x6f, 0xb6, 0x50, 0x53, 0x11, 0x0b, 0x2a, 0xb5, 0x25, 0x10, 0x21,
	0x00, 0x0d, 0x4d, 0x65, 0x64, 0x69, 0x61, 0x54, 0x65, 0x6b, 0x20, 0x49,
	0x6e, 0x63, 0x2e, 0x10, 0x23, 0x00, 0x12, 0x4d, 0x54, 0x4b, 0x20, 0x57,
	0x69, 0x72, 0x65, 0x6c, 0x65, 0x73, 0x73, 0x20, 0x4d, 0x6f, 0x64, 0x65,
	0x6c, 0x10, 0x24, 0x00, 0x03, 0x31, 0x2e, 0x30, 0x10, 0x42, 0x00, 0x03,
	0x32, 0x2e, 0x30, 0x10, 0x54, 0x00, 0x08, 0x00, 0x08, 0x00, 0x50, 0xf2,
	0x04, 0x00, 0x02, 0x10, 0x11, 0x00, 0x0d, 0x4c, 0x45, 0x58, 0x36, 0x32,
	0x36, 0x2d, 0x50, 0x64, 0x61, 0x4e, 0x65, 0x74, 0x10, 0x08, 0x00, 0x02,
	0x41, 0x08, 0x10, 0x49, 0x00, 0x0e, 0x00, 0x37, 0x2a, 0x00, 0x01, 0x20,
	0x01, 0x06, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xdd, 0x27, 0x50, 0x6f,
	0x9a, 0x09, 0x02, 0x02, 0x00, 0x05, 0xab, 0x0d, 0x1b, 0x00, 0x2a, 0xfe,
	0xcd, 0x01, 0xbe, 0xa0, 0x01, 0x88, 0x00, 0x08, 0x00, 0x50, 0xf2, 0x04,
	0x00, 0x02, 0x00, 0x10, 0x11, 0x00, 0x06, 0x4d, 0x6f, 0x62, 0x69, 0x6c,
	0x65, 0xdd, 0x16, 0x50, 0x6f, 0x9a, 0x09, 0x0c, 0x0f, 0x00, 0xe1, 0x00,
	0x01, 0xb0, 0xb3, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x7c, 0x45, 0x8f,
	0x0c,
};

struct p2p_probe_resp_data {
	const uint8_t *ies;
	size_t ies_len;
	ssize_t payload_len;
	struct p2p_probe_resp data;
	const struct p2p_notice_of_absence_desc *noa_descs;
};

static const struct p2p_probe_resp_data p2p_probe_resp_data_1 = {
	.ies = p2p_probe_resp_ies_1,
	.ies_len = L_ARRAY_SIZE(p2p_probe_resp_ies_1),
	.payload_len = 53,
	.data = {
		.capability = {
			.device_caps = P2P_DEVICE_CAP_SVC_DISCOVERY |
				P2P_DEVICE_CAP_CONCURRENT_OP,
			.group_caps = P2P_GROUP_CAP_GO |
				P2P_GROUP_CAP_PERSISTENT_GROUP |
				P2P_GROUP_CAP_INTRA_BSS_DISTRIBUTION |
				P2P_GROUP_CAP_PERSISTENT_RECONNECT |
				P2P_GROUP_CAP_IP_ALLOCATION,
		},
		.notice_of_absence = {
			.index = 225,
			.opp_ps = false,
			.ct_window = 0,
		},
		.device_info = {
			.device_addr = { 0x2a, 0xfe, 0xcd, 0x01, 0xbe, 0xa0 },
			.wsc_config_methods = WSC_CONFIGURATION_METHOD_DISPLAY |
				WSC_CONFIGURATION_METHOD_PUSH_BUTTON |
				WSC_CONFIGURATION_METHOD_KEYPAD,
			.primary_device_type = {
				.category = 8,
				.oui = { 0x00, 0x50, 0xf2 },
				.oui_type = 0x04,
				.subcategory = 2,
			},
			.device_name = "Mobile",
		},
	},
	.noa_descs = (const struct p2p_notice_of_absence_desc []) {
		[0] = {
			.count_type = 1,
			.duration = 46000,
			.interval = 0,
			.start_time = 210716028,
		},
		[1] = {}
	},
};

static const uint8_t p2p_probe_resp_ies_2[] = {
	0xdd, 0x3e, 0x50, 0x6f, 0x9a, 0x09, 0x02, 0x02, 0x00, 0x05, 0x01, 0x0d,
	0x32, 0x00, 0xa2, 0x8c, 0xfd, 0xb9, 0x05, 0xef, 0x5a, 0x88, 0x00, 0x03,
	0x00, 0x50, 0xf2, 0x04, 0x00, 0x01, 0x00, 0x10, 0x11, 0x00, 0x1d, 0x44,
	0x49, 0x52, 0x45, 0x43, 0x54, 0x2d, 0x45, 0x46, 0x2d, 0x48, 0x50, 0x20,
	0x45, 0x4e, 0x56, 0x59, 0x20, 0x34, 0x35, 0x32, 0x30, 0x20, 0x73, 0x65,
	0x72, 0x69, 0x65, 0x73, 0xdd, 0xc1, 0x00, 0x50, 0xf2, 0x04, 0x10, 0x4a,
	0x00, 0x01, 0x10, 0x10, 0x44, 0x00, 0x01, 0x02, 0x10, 0x57, 0x00, 0x01,
	0x01, 0x10, 0x41, 0x00, 0x01, 0x00, 0x10, 0x3b, 0x00, 0x01, 0x03, 0x10,
	0x47, 0x00, 0x10, 0x1c, 0x85, 0x2a, 0x4d, 0xb8, 0x00, 0x1f, 0x08, 0xab,
	0xcd, 0xa0, 0x8c, 0xfd, 0xb9, 0x05, 0xef, 0x10, 0x21, 0x00, 0x02, 0x48,
	0x50, 0x10, 0x23, 0x00, 0x11, 0x45, 0x4e, 0x56, 0x59, 0x20, 0x34, 0x35,
	0x32, 0x30, 0x20, 0x73, 0x65, 0x72, 0x69, 0x65, 0x73, 0x00, 0x10, 0x24,
	0x00, 0x05, 0x34, 0x35, 0x32, 0x37, 0x00, 0x10, 0x42, 0x00, 0x10, 0x54,
	0x48, 0x36, 0x35, 0x4f, 0x33, 0x48, 0x31, 0x58, 0x59, 0x30, 0x36, 0x36,
	0x30, 0x00, 0x00, 0x10, 0x54, 0x00, 0x08, 0x00, 0x03, 0x00, 0x50, 0xf2,
	0x04, 0x00, 0x05, 0x10, 0x11, 0x00, 0x1d, 0x44, 0x49, 0x52, 0x45, 0x43,
	0x54, 0x2d, 0x45, 0x46, 0x2d, 0x48, 0x50, 0x20, 0x45, 0x4e, 0x56, 0x59,
	0x20, 0x34, 0x35, 0x32, 0x30, 0x20, 0x73, 0x65, 0x72, 0x69, 0x65, 0x73,
	0x10, 0x08, 0x00, 0x02, 0x00, 0x00, 0x10, 0x49, 0x00, 0x06, 0x00, 0x37,
	0x2a, 0x00, 0x01, 0x20, 0x10, 0x49, 0x00, 0x17, 0x00, 0x01, 0x37, 0x10,
	0x06, 0x00, 0x10, 0x1c, 0x85, 0x2a, 0x4d, 0xb8, 0x00, 0x1f, 0x08, 0xab,
	0xcd, 0xa0, 0x8c, 0xfd, 0xb9, 0x05, 0xef,
};

static const struct p2p_probe_resp_data p2p_probe_resp_data_2 = {
	.ies = p2p_probe_resp_ies_2,
	.ies_len = L_ARRAY_SIZE(p2p_probe_resp_ies_2),
	.payload_len = 58,
	.data = {
		.capability = {
			.device_caps = P2P_DEVICE_CAP_SVC_DISCOVERY |
				P2P_DEVICE_CAP_CONCURRENT_OP,
			.group_caps = P2P_GROUP_CAP_GO,
		},
		.device_info = {
			.device_addr = { 0xa2, 0x8c, 0xfd, 0xb9, 0x05, 0xef },
			.wsc_config_methods =
				WSC_CONFIGURATION_METHOD_VIRTUAL_PUSH_BUTTON |
				0x0800 | WSC_CONFIGURATION_METHOD_P2P |
				WSC_CONFIGURATION_METHOD_PHYSICAL_DISPLAY_PIN,
			.primary_device_type = {
				.category = 3,
				.oui = { 0x00, 0x50, 0xf2 },
				.oui_type = 0x04,
				.subcategory = 1,
			},
			.device_name = "DIRECT-EF-HP ENVY 4520 series",
		},
	},
};

static void p2p_test_parse_probe_resp(const void *data)
{
	const struct p2p_probe_resp_data *test = data;
	struct p2p_probe_resp attrs1, attrs2;
	const struct p2p_notice_of_absence_desc *desc = test->noa_descs;
	uint8_t *payload;
	ssize_t payload_len;

	payload = ie_tlv_extract_p2p_payload(test->ies, test->ies_len,
						&payload_len);
	l_free(payload);
	assert(payload_len == test->payload_len);

	assert(p2p_parse_probe_resp(test->ies, test->ies_len, &attrs1) == 0);

	memcpy(&attrs2, &test->data, sizeof(attrs2));

	if (desc)
		attrs2.notice_of_absence.descriptors = l_queue_new();

	while (desc && desc->start_time) {
		l_queue_push_tail(attrs2.notice_of_absence.descriptors,
					l_memdup(desc, sizeof(*desc)));
		desc++;
	}

	assert(attrs1.capability.device_caps == attrs2.capability.device_caps);
	assert(attrs1.capability.group_caps == attrs2.capability.group_caps);

	assert(attrs1.listen_availability.avail_period_ms ==
		attrs2.listen_availability.avail_period_ms);
	assert(attrs1.listen_availability.avail_interval_ms ==
		attrs2.listen_availability.avail_interval_ms);

	assert(attrs1.notice_of_absence.index ==
		attrs2.notice_of_absence.index);
	assert(attrs1.notice_of_absence.opp_ps ==
		attrs2.notice_of_absence.opp_ps);
	assert(attrs1.notice_of_absence.ct_window ==
		attrs2.notice_of_absence.ct_window);
	assert(test_queue_cmp(attrs1.notice_of_absence.descriptors,
				attrs2.notice_of_absence.descriptors,
				p2p_noa_desc_cmp));

	assert(!memcmp(attrs1.device_info.device_addr,
			attrs2.device_info.device_addr, 6));
	assert(attrs1.device_info.wsc_config_methods ==
		attrs2.device_info.wsc_config_methods);
	assert(attrs1.device_info.primary_device_type.category ==
		attrs2.device_info.primary_device_type.category);
	assert(!memcmp(attrs1.device_info.primary_device_type.oui,
			attrs2.device_info.primary_device_type.oui, 3));
	assert(attrs1.device_info.primary_device_type.oui_type ==
		attrs2.device_info.primary_device_type.oui_type);
	assert(attrs1.device_info.primary_device_type.subcategory ==
		attrs2.device_info.primary_device_type.subcategory);
	assert(l_queue_length(attrs1.device_info.secondary_device_types) ==
		l_queue_length(attrs2.device_info.secondary_device_types));
	assert(!strcmp(attrs1.device_info.device_name,
			attrs2.device_info.device_name));

	assert(l_queue_length(attrs1.group_clients) ==
		l_queue_length(attrs2.group_clients));

	assert(l_queue_length(attrs1.advertised_svcs) ==
		l_queue_length(attrs2.advertised_svcs));

	p2p_free_probe_resp(&attrs1);
	p2p_free_probe_resp(&attrs2);
}

static void p2p_test_build_probe_resp(const void *data)
{
	const struct p2p_probe_resp_data *test = data;
	struct p2p_probe_resp attrs2;
	const struct p2p_notice_of_absence_desc *desc = test->noa_descs;
	uint8_t *ies;
	size_t ies_len;

	memcpy(&attrs2, &test->data, sizeof(attrs2));

	if (desc)
		attrs2.notice_of_absence.descriptors = l_queue_new();

	while (desc && desc->start_time) {
		l_queue_push_tail(attrs2.notice_of_absence.descriptors,
					l_memdup(desc, sizeof(*desc)));
		desc++;
	}

	ies = p2p_build_probe_resp(&attrs2, &ies_len);
	p2p_free_probe_resp(&attrs2);

	assert(p2p_payload_cmd(ies, ies_len, test->ies, test->ies_len));
	l_free(ies);
}

static const uint8_t p2p_association_req_ies_1[] = {
	0xdd, 0x18, 0x00, 0x50, 0xf2, 0x04, 0x10, 0x4a, 0x00, 0x01, 0x10, 0x10,
	0x3a, 0x00, 0x01, 0x01, 0x10, 0x49, 0x00, 0x06, 0x00, 0x37, 0x2a, 0x00,
	0x01, 0x20, 0xdd, 0x29, 0x50, 0x6f, 0x9a, 0x09, 0x02, 0x02, 0x00, 0x27,
	0x00, 0x0d, 0x1d, 0x00, 0x00, 0x28, 0xf8, 0xed, 0x26, 0x57, 0x11, 0x08,
	0x00, 0x01, 0x00, 0x50, 0xf2, 0x04, 0x00, 0x01, 0x00, 0x10, 0x11, 0x00,
	0x08, 0x74, 0x65, 0x73, 0x74, 0x64, 0x65, 0x76, 0x31,
};

struct p2p_association_req_data {
	const uint8_t *ies;
	size_t ies_len;
	ssize_t payload_len;
	struct p2p_association_req data;
};

static const struct p2p_association_req_data p2p_association_req_data_1 = {
	.ies = p2p_association_req_ies_1,
	.ies_len = L_ARRAY_SIZE(p2p_association_req_ies_1),
	.payload_len = 37,
	.data = {
		.capability = {
			.device_caps = P2P_DEVICE_CAP_SVC_DISCOVERY |
				P2P_DEVICE_CAP_CLIENT_DISCOVERABILITY |
				P2P_DEVICE_CAP_CONCURRENT_OP |
				P2P_DEVICE_CAP_INVITATION_PROCEDURE,
			.group_caps = 0,
		},
		.device_info = {
			.device_addr = { 0x00, 0x28, 0xf8, 0xed, 0x26, 0x57 },
			.wsc_config_methods = WSC_CONFIGURATION_METHOD_DISPLAY |
				WSC_CONFIGURATION_METHOD_KEYPAD |
				WSC_CONFIGURATION_METHOD_P2P,
			.primary_device_type = {
				.category = 1,
				.oui = { 0x00, 0x50, 0xf2 },
				.oui_type = 0x04,
				.subcategory = 1,
			},
			.device_name = "testdev1",
		},
	},
};

static void p2p_test_parse_association_req(const void *data)
{
	const struct p2p_association_req_data *test = data;
	struct p2p_association_req attrs1, attrs2;
	uint8_t *payload;
	ssize_t payload_len;

	payload = ie_tlv_extract_p2p_payload(test->ies, test->ies_len,
						&payload_len);
	l_free(payload);
	assert(payload_len == test->payload_len);

	assert(p2p_parse_association_req(test->ies, test->ies_len, &attrs1) ==
		0);

	memcpy(&attrs2, &test->data, sizeof(attrs2));

	assert(attrs1.capability.device_caps == attrs2.capability.device_caps);
	assert(attrs1.capability.group_caps == attrs2.capability.group_caps);

	assert(attrs1.listen_availability.avail_period_ms ==
		attrs2.listen_availability.avail_period_ms);
	assert(attrs1.listen_availability.avail_interval_ms ==
		attrs2.listen_availability.avail_interval_ms);

	assert(!memcmp(attrs1.device_info.device_addr,
			attrs2.device_info.device_addr, 6));
	assert(attrs1.device_info.wsc_config_methods ==
		attrs2.device_info.wsc_config_methods);
	assert(attrs1.device_info.primary_device_type.category ==
		attrs2.device_info.primary_device_type.category);
	assert(!memcmp(attrs1.device_info.primary_device_type.oui,
			attrs2.device_info.primary_device_type.oui, 3));
	assert(attrs1.device_info.primary_device_type.oui_type ==
		attrs2.device_info.primary_device_type.oui_type);
	assert(attrs1.device_info.primary_device_type.subcategory ==
		attrs2.device_info.primary_device_type.subcategory);
	assert(l_queue_length(attrs1.device_info.secondary_device_types) ==
		l_queue_length(attrs2.device_info.secondary_device_types));
	assert(!strcmp(attrs1.device_info.device_name,
			attrs2.device_info.device_name));

	assert(!memcmp(attrs1.interface.device_addr,
			attrs2.interface.device_addr, 6));
	assert(l_queue_length(attrs1.interface.interface_addrs) ==
		l_queue_length(attrs2.interface.interface_addrs));

	p2p_free_association_req(&attrs1);
	p2p_free_association_req(&attrs2);
}

static void p2p_test_build_association_req(const void *data)
{
	const struct p2p_association_req_data *test = data;
	uint8_t *ies;
	size_t ies_len;

	ies = p2p_build_association_req(&test->data, &ies_len);

	assert(p2p_payload_cmd(ies, ies_len, test->ies, test->ies_len));
	l_free(ies);
}

/* Obligatory P2P IE empty here */
static const uint8_t p2p_association_resp_ies_1[] = {
	0x01, 0x08, 0x8c, 0x12, 0x98, 0x24, 0xb0, 0x48, 0x60, 0x6c, 0x2d, 0x1a,
	0x73, 0x11, 0x03, 0xff, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x3d, 0x16, 0x64, 0x05, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0xdd, 0x04, 0x50, 0x6f, 0x9a, 0x09, 0x7f, 0x08, 0x01, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0xbf, 0x0c, 0x30, 0x71, 0x90, 0x03,
	0xfe, 0xff, 0x00, 0x00, 0xfe, 0xff, 0x00, 0x00, 0xc0, 0x05, 0x00, 0x00,
	0x00, 0xfe, 0xff, 0xdd, 0x18, 0x00, 0x50, 0xf2, 0x02, 0x01, 0x01, 0x80,
	0x01, 0x03, 0xa4, 0x00, 0x00, 0x27, 0xa4, 0x00, 0x00, 0x42, 0x43, 0x5e,
	0x00, 0x62, 0x32, 0x2f, 0x00, 0xdd, 0x07, 0x00, 0x0c, 0xe7, 0x08, 0x00,
	0x00, 0x00,
};

struct p2p_association_resp_data {
	const uint8_t *ies;
	size_t ies_len;
	ssize_t payload_len;
	struct p2p_association_resp data;
};

static const struct p2p_association_resp_data p2p_association_resp_data_1 = {
	.ies = p2p_association_resp_ies_1,
	.ies_len = L_ARRAY_SIZE(p2p_association_resp_ies_1),
	.payload_len = 0,
	.data = {},
};

static void p2p_test_parse_association_resp(const void *data)
{
	const struct p2p_association_resp_data *test = data;
	struct p2p_association_resp attrs1, attrs2;
	uint8_t *payload;
	ssize_t payload_len;

	payload = ie_tlv_extract_p2p_payload(test->ies, test->ies_len,
						&payload_len);
	l_free(payload);
	assert(payload_len == test->payload_len);

	assert(p2p_parse_association_resp(test->ies, test->ies_len, &attrs1) ==
		0);

	memcpy(&attrs2, &test->data, sizeof(attrs2));

	assert(attrs1.status == attrs2.status);

	assert(attrs1.listen_availability.avail_period_ms ==
		attrs2.listen_availability.avail_period_ms);
	assert(attrs1.listen_availability.avail_interval_ms ==
		attrs2.listen_availability.avail_interval_ms);

	p2p_free_association_resp(&attrs1);
	p2p_free_association_resp(&attrs2);
}

static void p2p_test_build_association_resp(const void *data)
{
	const struct p2p_association_resp_data *test = data;
	uint8_t *ies;
	size_t ies_len;

	ies = p2p_build_association_resp(&test->data, &ies_len);

	assert(p2p_payload_cmd(ies, ies_len, test->ies, test->ies_len));
	l_free(ies);
}

static const uint8_t p2p_provision_disc_req_1[] = {
	0x04, 0x09, 0x50, 0x6f, 0x9a, 0x09, 0x07, 0x01, 0xdd, 0x41, 0x50, 0x6f,
	0x9a, 0x09, 0x02, 0x02, 0x00, 0x25, 0x00, 0x0d, 0x1d, 0x00, 0x00, 0x28,
	0xf8, 0xed, 0x26, 0x57, 0x11, 0x08, 0x00, 0x01, 0x00, 0x50, 0xf2, 0x04,
	0x00, 0x01, 0x00, 0x10, 0x11, 0x00, 0x08, 0x74, 0x65, 0x73, 0x74, 0x64,
	0x65, 0x76, 0x31, 0x0f, 0x15, 0x00, 0x2a, 0xfe, 0xcd, 0x01, 0xbe, 0xa0,
	0x44, 0x49, 0x52, 0x45, 0x43, 0x54, 0x2d, 0x5a, 0x75, 0x2d, 0x54, 0x65,
	0x73, 0x74, 0x31, 0xdd, 0x0a, 0x00, 0x50, 0xf2, 0x04, 0x10, 0x08, 0x00,
	0x02, 0x00, 0x80,
};

struct p2p_provision_disc_req_data {
	const uint8_t *frame;
	size_t frame_len;
	ssize_t payload_len;
	struct p2p_provision_discovery_req data;
};

static const struct p2p_provision_disc_req_data p2p_provision_disc_req_data_1 =
{
	.frame = p2p_provision_disc_req_1,
	.frame_len = L_ARRAY_SIZE(p2p_provision_disc_req_1),
	.payload_len = 61,
	.data = {
		.dialog_token = 1,
		.capability = {
			.device_caps = P2P_DEVICE_CAP_SVC_DISCOVERY |
				P2P_DEVICE_CAP_CONCURRENT_OP |
				P2P_DEVICE_CAP_INVITATION_PROCEDURE,
			.group_caps = 0,
		},
		.device_info = {
			.device_addr = { 0x00, 0x28, 0xf8, 0xed, 0x26, 0x57 },
			.wsc_config_methods = WSC_CONFIGURATION_METHOD_DISPLAY |
				WSC_CONFIGURATION_METHOD_KEYPAD |
				WSC_CONFIGURATION_METHOD_P2P,
			.primary_device_type = {
				.category = 1,
				.oui = { 0x00, 0x50, 0xf2 },
				.oui_type = 0x04,
				.subcategory = 1,
			},
			.device_name = "testdev1",
		},
		.group_id = {
			.device_addr = { 0x2a, 0xfe, 0xcd, 0x01, 0xbe, 0xa0 },
			.ssid = "DIRECT-Zu-Test1",
		},
		.status = -1,
		.wsc_config_method = WSC_CONFIGURATION_METHOD_PUSH_BUTTON,
	},
};

static void p2p_test_parse_provision_disc_req(const void *data)
{
	const struct p2p_provision_disc_req_data *test = data;
	struct p2p_provision_discovery_req attrs1, attrs2;
	uint8_t *payload;
	ssize_t payload_len;

	payload = ie_tlv_extract_p2p_payload(test->frame + 8,
						test->frame_len - 8,
						&payload_len);
	l_free(payload);
	assert(payload_len == test->payload_len);

	assert(p2p_parse_provision_disc_req(test->frame + 7,
						test->frame_len - 7,
						&attrs1) == 0);

	memcpy(&attrs2, &test->data, sizeof(attrs2));

	assert(attrs1.dialog_token == attrs2.dialog_token);

	assert(attrs1.capability.device_caps == attrs2.capability.device_caps);
	assert(attrs1.capability.group_caps == attrs2.capability.group_caps);

	assert(!memcmp(attrs1.device_info.device_addr,
			attrs2.device_info.device_addr, 6));
	assert(attrs1.device_info.wsc_config_methods ==
		attrs2.device_info.wsc_config_methods);
	assert(attrs1.device_info.primary_device_type.category ==
		attrs2.device_info.primary_device_type.category);
	assert(!memcmp(attrs1.device_info.primary_device_type.oui,
			attrs2.device_info.primary_device_type.oui, 3));
	assert(attrs1.device_info.primary_device_type.oui_type ==
		attrs2.device_info.primary_device_type.oui_type);
	assert(attrs1.device_info.primary_device_type.subcategory ==
		attrs2.device_info.primary_device_type.subcategory);
	assert(l_queue_length(attrs1.device_info.secondary_device_types) ==
		l_queue_length(attrs2.device_info.secondary_device_types));
	assert(!strcmp(attrs1.device_info.device_name,
			attrs2.device_info.device_name));

	assert(!memcmp(attrs1.group_id.device_addr,
			attrs2.group_id.device_addr, 6));
	assert(!strcmp(attrs1.group_id.ssid, attrs2.group_id.ssid));

	assert(!memcmp(attrs1.intended_interface_addr,
			attrs2.intended_interface_addr, 6));

	assert(attrs1.status == attrs2.status);

	assert(!memcmp(attrs1.operating_channel.country,
			attrs2.operating_channel.country, 3));
	assert(attrs1.operating_channel.oper_class ==
		attrs2.operating_channel.oper_class);
	assert(attrs1.operating_channel.channel_num ==
		attrs2.operating_channel.channel_num);

	assert(!memcmp(attrs1.channel_list.country,
			attrs2.channel_list.country, 3));
	assert(l_queue_length(attrs1.channel_list.channel_entries) ==
		l_queue_length(attrs2.channel_list.channel_entries));

	assert(attrs1.session_info.data_len == attrs2.session_info.data_len);
	assert(!attrs1.session_info.data_len ||
		!memcmp(attrs1.session_info.data, attrs2.session_info.data,
			attrs1.session_info.data_len));

	assert(attrs1.connection_capability == attrs2.connection_capability);

	assert(attrs1.advertisement_id.advertisement_id ==
		attrs2.advertisement_id.advertisement_id);
	assert(!memcmp(attrs1.advertisement_id.service_mac_addr,
			attrs2.advertisement_id.service_mac_addr, 6));

	assert(attrs1.config_timeout.go_config_timeout ==
		attrs2.config_timeout.go_config_timeout);
	assert(attrs1.config_timeout.client_config_timeout ==
		attrs2.config_timeout.client_config_timeout);

	assert(!memcmp(attrs1.listen_channel.country,
			attrs2.listen_channel.country, 3));
	assert(attrs1.listen_channel.oper_class ==
		attrs2.listen_channel.oper_class);
	assert(attrs1.listen_channel.channel_num ==
		attrs2.listen_channel.channel_num);

	assert(attrs1.session_id.session_id == attrs2.session_id.session_id);
	assert(!memcmp(attrs1.session_id.session_mac_addr,
			attrs2.session_id.session_mac_addr, 6));

	assert(attrs1.transport_protocol == attrs2.transport_protocol);

	assert(!memcmp(attrs1.persistent_group_info.device_addr,
			attrs2.persistent_group_info.device_addr, 6));
	assert(!strcmp(attrs1.persistent_group_info.ssid,
			attrs2.persistent_group_info.ssid));

	assert(attrs1.wsc_config_method == attrs2.wsc_config_method);

	p2p_free_provision_disc_req(&attrs1);
	p2p_free_provision_disc_req(&attrs2);
}

static void p2p_test_build_provision_disc_req(const void *data)
{
	const struct p2p_provision_disc_req_data *test = data;
	uint8_t *frame;
	size_t frame_len;

	frame = p2p_build_provision_disc_req(&test->data, &frame_len);

	assert(!memcmp(frame, test->frame, 8));
	assert(p2p_payload_cmd(frame + 8, frame_len - 8,
				test->frame + 8, test->frame_len - 8));
	l_free(frame);
}

/* The optional P2P IE not present here */
static const uint8_t p2p_provision_disc_resp_1[] = {
	0x04, 0x09, 0x50, 0x6f, 0x9a, 0x09, 0x08, 0x01, 0xdd, 0x0a, 0x00, 0x50,
	0xf2, 0x04, 0x10, 0x08, 0x00, 0x02, 0x00, 0x80, 0xdd, 0x0d, 0x50, 0x6f,
	0x9a, 0x0a, 0x00, 0x00, 0x06, 0x00, 0x11, 0x00, 0x00, 0x00, 0x32,
};

struct p2p_provision_disc_resp_data {
	const uint8_t *frame;
	size_t frame_len;
	ssize_t payload_len;
	struct p2p_provision_discovery_resp data;
};

static const struct p2p_provision_disc_resp_data
		p2p_provision_disc_resp_data_1 = {
	.frame = p2p_provision_disc_resp_1,
	.frame_len = L_ARRAY_SIZE(p2p_provision_disc_resp_1),
	.payload_len = -ENOENT,
	.data = {
		.dialog_token = 1,
		.status = -1,
		.wsc_config_method = WSC_CONFIGURATION_METHOD_PUSH_BUTTON,
	},
};

static void p2p_test_parse_provision_disc_resp(const void *data)
{
	const struct p2p_provision_disc_resp_data *test = data;
	struct p2p_provision_discovery_resp attrs1, attrs2;
	uint8_t *payload;
	ssize_t payload_len;

	payload = ie_tlv_extract_p2p_payload(test->frame + 8,
						test->frame_len - 8,
						&payload_len);
	if (payload_len >= 0)
		l_free(payload);

	assert(payload_len == test->payload_len);

	assert(p2p_parse_provision_disc_resp(test->frame + 7,
						test->frame_len - 7,
						&attrs1) == 0);

	memcpy(&attrs2, &test->data, sizeof(attrs2));

	assert(attrs1.dialog_token == attrs2.dialog_token);

	assert(attrs1.status == attrs2.status);

	assert(attrs1.capability.device_caps == attrs2.capability.device_caps);
	assert(attrs1.capability.group_caps == attrs2.capability.group_caps);

	assert(!memcmp(attrs1.device_info.device_addr,
			attrs2.device_info.device_addr, 6));
	assert(attrs1.device_info.wsc_config_methods ==
		attrs2.device_info.wsc_config_methods);
	assert(attrs1.device_info.primary_device_type.category ==
		attrs2.device_info.primary_device_type.category);
	assert(!memcmp(attrs1.device_info.primary_device_type.oui,
			attrs2.device_info.primary_device_type.oui, 3));
	assert(attrs1.device_info.primary_device_type.oui_type ==
		attrs2.device_info.primary_device_type.oui_type);
	assert(attrs1.device_info.primary_device_type.subcategory ==
		attrs2.device_info.primary_device_type.subcategory);
	assert(l_queue_length(attrs1.device_info.secondary_device_types) ==
		l_queue_length(attrs2.device_info.secondary_device_types));
	assert(!strcmp(attrs1.device_info.device_name,
			attrs2.device_info.device_name));

	assert(!memcmp(attrs1.group_id.device_addr,
			attrs2.group_id.device_addr, 6));
	assert(!strcmp(attrs1.group_id.ssid, attrs2.group_id.ssid));

	assert(!memcmp(attrs1.intended_interface_addr,
			attrs2.intended_interface_addr, 6));

	assert(!memcmp(attrs1.operating_channel.country,
			attrs2.operating_channel.country, 3));
	assert(attrs1.operating_channel.oper_class ==
		attrs2.operating_channel.oper_class);
	assert(attrs1.operating_channel.channel_num ==
		attrs2.operating_channel.channel_num);

	assert(!memcmp(attrs1.channel_list.country,
			attrs2.channel_list.country, 3));
	assert(l_queue_length(attrs1.channel_list.channel_entries) ==
		l_queue_length(attrs2.channel_list.channel_entries));

	assert(attrs1.connection_capability == attrs2.connection_capability);

	assert(attrs1.advertisement_id.advertisement_id ==
		attrs2.advertisement_id.advertisement_id);
	assert(!memcmp(attrs1.advertisement_id.service_mac_addr,
			attrs2.advertisement_id.service_mac_addr, 6));

	assert(attrs1.config_timeout.go_config_timeout ==
		attrs2.config_timeout.go_config_timeout);
	assert(attrs1.config_timeout.client_config_timeout ==
		attrs2.config_timeout.client_config_timeout);

	assert(attrs1.session_id.session_id == attrs2.session_id.session_id);
	assert(!memcmp(attrs1.session_id.session_mac_addr,
			attrs2.session_id.session_mac_addr, 6));

	assert(attrs1.transport_protocol == attrs2.transport_protocol);

	assert(!memcmp(attrs1.persistent_group_info.device_addr,
			attrs2.persistent_group_info.device_addr, 6));
	assert(!strcmp(attrs1.persistent_group_info.ssid,
			attrs2.persistent_group_info.ssid));

	assert(attrs1.session_info.data_len == attrs2.session_info.data_len);
	assert(!attrs1.session_info.data_len ||
		!memcmp(attrs1.session_info.data, attrs2.session_info.data,
			attrs1.session_info.data_len));

	assert(attrs1.wsc_config_method == attrs2.wsc_config_method);

	p2p_free_provision_disc_resp(&attrs1);
	p2p_free_provision_disc_resp(&attrs2);
}

int main(int argc, char *argv[])
{
	l_test_init(&argc, &argv);

	l_test_add("/p2p/iter/sanity-check", p2p_test_iter_sanity_check, NULL);

	l_test_add("/p2p/parse/Beacon IEs 1", p2p_test_parse_beacon,
			&p2p_beacon_data_1);

	l_test_add("/p2p/build/Beacon IEs 1", p2p_test_build_beacon,
			&p2p_beacon_data_1);

	l_test_add("/p2p/parse/Probe Request IEs 1", p2p_test_parse_probe_req,
			&p2p_probe_req_data_1);

	l_test_add("/p2p/build/Probe Request IEs 1", p2p_test_build_probe_req,
			&p2p_probe_req_data_1);

	l_test_add("/p2p/parse/Probe Response IEs 1", p2p_test_parse_probe_resp,
			&p2p_probe_resp_data_1);
	l_test_add("/p2p/parse/Probe Response IEs 2", p2p_test_parse_probe_resp,
			&p2p_probe_resp_data_2);

	l_test_add("/p2p/build/Probe Response IEs 1", p2p_test_build_probe_resp,
			&p2p_probe_resp_data_1);
	l_test_add("/p2p/build/Probe Response IEs 2", p2p_test_build_probe_resp,
			&p2p_probe_resp_data_2);

	l_test_add("/p2p/parse/Association Request IEs 1",
			p2p_test_parse_association_req,
			&p2p_association_req_data_1);

	l_test_add("/p2p/build/Association Request IEs 1",
			p2p_test_build_association_req,
			&p2p_association_req_data_1);

	l_test_add("/p2p/parse/Association Response IEs 1",
			p2p_test_parse_association_resp,
			&p2p_association_resp_data_1);

	l_test_add("/p2p/build/Association Response IEs 1",
			p2p_test_build_association_resp,
			&p2p_association_resp_data_1);

	l_test_add("/p2p/parse/Provision Discovery Request 1",
			p2p_test_parse_provision_disc_req,
			&p2p_provision_disc_req_data_1);

	l_test_add("/p2p/build/Provision Discovery Request 1",
			p2p_test_build_provision_disc_req,
			&p2p_provision_disc_req_data_1);

	l_test_add("/p2p/parse/Provision Discovery Response 1",
			p2p_test_parse_provision_disc_resp,
			&p2p_provision_disc_resp_data_1);

	return l_test_run();
}
