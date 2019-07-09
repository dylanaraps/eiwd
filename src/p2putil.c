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

#include <stdbool.h>
#include <stdarg.h>
#include <errno.h>
#include <stdio.h>

#include <ell/ell.h>

#include "src/p2putil.h"
#include "src/ie.h"

void p2p_attr_iter_init(struct p2p_attr_iter *iter, const uint8_t *pdu,
			size_t len)

{
	iter->pos = pdu;
	iter->end = pdu + len;
	iter->type = -1;
}

/* Wi-Fi P2P Technical Specification v1.7 Section 4.1.1 */
bool p2p_attr_iter_next(struct p2p_attr_iter *iter)
{
	if (iter->type != (enum p2p_attr) -1)
		iter->pos += 3 + iter->len;

	if (iter->pos + 3 > iter->end ||
			iter->pos + 3 + l_get_le16(iter->pos + 1) > iter->end)
		return false;

	iter->type = iter->pos[0];
	iter->len = l_get_le16(iter->pos + 1);
	return true;
}

enum attr_flag {
	ATTR_FLAG_REQUIRED  = 0x1,  /* Always required */
};

typedef bool (*attr_handler)(const uint8_t *, size_t, void *);

static bool extract_p2p_byte(const uint8_t *attr, size_t len,
				void *data)
{
	uint8_t *out = data;

	if (len != 1)
		return false;

	*out = attr[0];
	return true;
}

/* Section 4.1.2 */
static bool extract_p2p_status(const uint8_t *attr, size_t len,
				void *data)
{
	enum p2p_attr_status_code *out = data;

	if (len != 1)
		return false;

	*out = attr[0];
	return true;
}

/* Section 4.1.4 */
static bool extract_p2p_capability(const uint8_t *attr, size_t len,
					void *data)
{
	struct p2p_capability_attr *out = data;

	if (len != 2)
		return false;

	out->device_caps = attr[0];
	out->group_caps = attr[1];
	return true;
}

/* Section 4.1.5, 4.1.9, 4.1.11, ... */
static bool extract_p2p_addr(const uint8_t *attr, size_t len,
				void *data)
{
	uint8_t *out = data;

	if (len != 6)
		return false;

	memcpy(out, attr, 6);
	return true;
}

struct p2p_go_intent_attr {
	uint8_t intent;
	bool tie_breaker;
};

/* Section 4.1.6 */
static bool extract_p2p_go_intent(const uint8_t *attr, size_t len,
					void *data)
{
	struct p2p_go_intent_attr *out = data;
	uint8_t intent;

	if (len != 1)
		return false;

	intent = attr[0] >> 1;

	if (intent & ~15)
		return false;

	out->intent = intent;
	out->tie_breaker = attr[0] & 1;

	return true;
}

/* Section 4.1.7 */
static bool extract_p2p_config_timeout(const uint8_t *attr, size_t len,
					void *data)
{
	struct p2p_config_timeout_attr *out = data;

	if (len != 2)
		return false;

	out->go_config_timeout = attr[0];
	out->client_config_timeout = attr[1];
	return true;
}

/* Section 4.1.8, 4.1.19, ... */
static bool extract_p2p_channel(const uint8_t *attr, size_t len,
				void *data)
{
	struct p2p_channel_attr *out = data;

	if (len != 5)
		return false;

	out->country[0] = attr[0];
	out->country[1] = attr[1];
	out->country[2] = attr[2];
	out->oper_class = attr[3];
	out->channel_num = attr[4];
	return true;
}

/* Section 4.1.10 */
static bool extract_p2p_listen_timing(const uint8_t *attr, size_t len,
					void *data)
{
	struct p2p_extended_listen_timing_attr *out = data;

	if (len != 4)
		return false;

	out->avail_period_ms = l_get_le16(attr + 0);
	out->avail_interval_ms = l_get_le16(attr + 2);
	return true;
}

/* Section 4.1.13 */
static bool extract_p2p_channel_list(const uint8_t *attr, size_t len,
					void *data)
{
	struct p2p_channel_list_attr *out = data;

	if (len < 6)
		return false;

	out->country[0] = *attr++;
	out->country[1] = *attr++;
	out->country[2] = *attr++;
	len -= 3;

	out->channel_entries = l_queue_new();

	while (len) {
		struct p2p_channel_entries *entries;

		if (len < 2 || len < (size_t) 2 + attr[1]) {
			l_queue_destroy(out->channel_entries, l_free);
			out->channel_entries = NULL;
			return false;
		}

		entries = l_malloc(sizeof(struct p2p_channel_entries) + attr[1]);
		entries->oper_class = *attr++;
		entries->n_channels = *attr++;
		memcpy(entries->channels, attr, entries->n_channels);
		l_queue_push_tail(out->channel_entries, entries);

		attr += entries->n_channels;
		len -= entries->n_channels;
	}

	return true;
}

/* Section 4.1.14 */
static bool extract_p2p_notice_of_absence(const uint8_t *attr, size_t len,
						void *data)
{
	struct p2p_notice_of_absence_attr *out = data;
	uint8_t index;
	uint8_t ct_window;
	bool opp_ps;

	if (len % 13 != 2)
		return false;

	index = *attr++;
	ct_window = *attr & 127;
	opp_ps = *attr++ >> 7;
	len -= 2;

	if (opp_ps && !ct_window)
		return false;

	out->index = index;
	out->opp_ps = opp_ps;
	out->ct_window = ct_window;
	out->descriptors = l_queue_new();

	while (len) {
		struct p2p_notice_of_absence_desc *desc;

		desc = l_new(struct p2p_notice_of_absence_desc, 1);
		desc->count_type = attr[0];
		desc->duration = l_get_le32(attr + 1);
		desc->interval = l_get_le32(attr + 5);
		desc->start_time = l_get_le32(attr + 9);
		l_queue_push_tail(out->descriptors, desc);

		attr += 13;
		len -= 13;
	}

	return true;
}

/* Section 4.1.15 */
static bool extract_p2p_device_info(const uint8_t *attr, size_t len,
					void *data)
{
	struct p2p_device_info_attr *out = data;
	int r;
	int name_len;
	int i;
	int types_num;

	if (len < 21)
		return false;

	memcpy(out->device_addr, attr + 0, 6);
	out->wsc_config_methods = l_get_be16(attr + 6);

	r = wsc_parse_primary_device_type(attr + 8, 8,
						&out->primary_device_type);
	if (r < 0)
		return false;

	types_num = attr[16];
	if (len < 17u + types_num * 8 + 4)
		return false;

	if (l_get_be16(attr + 17 + types_num * 8) != WSC_ATTR_DEVICE_NAME)
		return false;

	name_len = l_get_be16(attr + 17 + types_num * 8 + 2);
	if (len < 17u + types_num * 8 + 4 + name_len || name_len > 32)
		return false;

	out->secondary_device_types = l_queue_new();

	for (i = 0; i < types_num; i++) {
		struct wsc_primary_device_type *device_type =
			l_new(struct wsc_primary_device_type, 1);

		l_queue_push_tail(out->secondary_device_types, device_type);

		r = wsc_parse_primary_device_type(attr + 17 + i * 8, 8,
							device_type);
		if (r < 0) {
			l_queue_destroy(out->secondary_device_types, l_free);
			out->secondary_device_types = NULL;
			return false;
		}
	}

	memcpy(out->device_name, attr + 17 + types_num * 8 + 4, name_len);

	return true;
}

static void p2p_free_client_info_descriptor(void *data)
{
	struct p2p_client_info_descriptor *desc = data;

	l_queue_destroy(desc->secondary_device_types, l_free);
	l_free(desc);
}

/* Section 4.1.16 */
static bool extract_p2p_group_info(const uint8_t *attr, size_t len,
					void *data)
{
	struct l_queue **out = data;

	while (len) {
		uint8_t desc_len = *attr++;
		struct p2p_client_info_descriptor *desc;
		int r, name_len, i, types_num;

		if (len < 1u + desc_len)
			goto error;

		if (!*out)
			*out = l_queue_new();

		desc = l_new(struct p2p_client_info_descriptor, 1);
		l_queue_push_tail(*out, desc);

		memcpy(desc->device_addr, attr + 0, 6);
		memcpy(desc->interface_addr, attr + 6, 6);
		desc->device_caps = attr[12];
		desc->wsc_config_methods = l_get_be16(attr + 13);

		r = wsc_parse_primary_device_type(attr + 15, 8,
						&desc->primary_device_type);
		if (r < 0)
			goto error;

		types_num = attr[23];
		if (desc_len < 24 + types_num * 8 + 4)
			goto error;

		if (l_get_be16(attr + 24 + types_num * 8) !=
				WSC_ATTR_DEVICE_NAME)
			goto error;

		name_len = l_get_be16(attr + 24 + types_num * 8 + 2);
		if (desc_len < 24 + types_num * 8 + 4 + name_len ||
				name_len > 32)
			goto error;

		desc->secondary_device_types = l_queue_new();

		for (i = 0; i < types_num; i++) {
			struct wsc_primary_device_type *device_type =
				l_new(struct wsc_primary_device_type, 1);

			l_queue_push_tail(desc->secondary_device_types,
						device_type);

			r = wsc_parse_primary_device_type(attr + 24 + i * 8, 8,
								device_type);
			if (r < 0)
				goto error;
		}

		memcpy(desc->device_name, attr + 24 + types_num * 8 + 4,
			name_len);

		attr += 24 + types_num * 8 + 4 + name_len;
		len -= 1 + desc_len;
	}

	return true;

error:
	l_queue_destroy(*out, p2p_free_client_info_descriptor);
	*out = NULL;

	return false;
}

/* Section 4.1.17, 4.1.29, ... */
static bool extract_p2p_group_id(const uint8_t *attr, size_t len,
					void *data)
{
	struct p2p_group_id_attr *out = data;

	if (len < 6 || len > 38)
		return false;

	memcpy(out->device_addr, attr + 0, 6);
	memcpy(out->ssid, attr + 6, len - 6);
	return true;
}

/* Section 4.1.18 */
static bool extract_p2p_interface(const uint8_t *attr, size_t len,
					void *data)
{
	struct p2p_interface_attr *out = data;
	int addr_count;

	if (len < 7)
		return false;

	addr_count = attr[6];

	if (len < 7u + addr_count * 6)
		return false;

	memcpy(out->device_addr, attr + 0, 6);
	out->interface_addrs = l_queue_new();
	attr += 7;

	while (addr_count--) {
		l_queue_push_tail(out->interface_addrs, l_memdup(attr, 6));
		attr += 6;
	}

	return true;
}

/* Section 4.1.20 */
static bool extract_p2p_invitation_flags(const uint8_t *attr, size_t len,
						void *data)
{
	bool *out = data;

	if (len != 1)
		return false;

	*out = attr[0] & 1; /* Invitation Type flag */
	return true;
}

/* Section 4.1.22 */
static bool extract_p2p_service_hashes(const uint8_t *attr, size_t len,
					void *data)
{
	struct l_queue **out = data;

	if (len % 6 != 0)
		return false;

	*out = l_queue_new();

	while (len) {
		l_queue_push_tail(*out, l_memdup(attr, 6));
		attr += 6;
		len -= 6;
	}

	return true;
}

/* Section 4.1.23 */
static bool extract_p2p_session_info(const uint8_t *attr, size_t len,
					void *data)
{
	struct p2p_session_info_data_attr *out = data;

	out->data_len = len;
	memcpy(out->data, data, len);
	return true;
}

/* Section 4.1.25 */
static bool extract_p2p_advertisement_id(const uint8_t *attr, size_t len,
						void *data)
{
	struct p2p_advertisement_id_info_attr *out = data;

	if (len != 10)
		return false;

	out->advertisement_id = l_get_le32(attr + 0);
	memcpy(out->service_mac_addr, attr + 4, 6);
	return true;
}

static void p2p_free_advertised_service_descriptor(void *data)
{
	struct p2p_advertised_service_descriptor *desc = data;

	l_free(desc->service_name);
	l_free(desc);
}

/* Section 4.1.26 */
static bool extract_p2p_advertised_service_info(const uint8_t *attr, size_t len,
						void *data)
{
	struct l_queue **out = data;

	while (len) {
		struct p2p_advertised_service_descriptor *desc;
		int name_len;

		if (len < 7)
			goto error;

		name_len = attr[6];
		if (len < 7u + name_len)
			goto error;

		if (!l_utf8_validate((const char *) attr + 7, name_len, NULL))
			goto error;

		if (!*out)
			*out = l_queue_new();

		desc = l_new(struct p2p_advertised_service_descriptor, 1);
		l_queue_push_tail(*out, desc);

		desc->advertisement_id = l_get_le32(attr + 0);
		desc->wsc_config_methods = l_get_be16(attr + 4);
		desc->service_name = l_strndup((const char *) attr + 7,
						name_len);

		attr += 7 + name_len;
		len -= 7 + name_len;
	}

	return true;

error:
	l_queue_destroy(*out, p2p_free_advertised_service_descriptor);
	return false;
}

/* Section 4.1.27 */
static bool extract_p2p_session_id(const uint8_t *attr, size_t len, void *data)
{
	struct p2p_session_id_info_attr *out = data;

	if (len != 10)
		return false;

	out->session_id = l_get_le32(attr + 0);
	memcpy(out->session_mac_addr, attr + 4, 6);
	return true;
}

/* Section 4.1.28 */
static bool extract_p2p_feature_capability(const uint8_t *attr, size_t len,
						void *data)
{
	enum p2p_asp_coordination_transport_protocol *out = data;

	if (len != 2)
		return false;

	if (attr[0] == 0x01)
		*out = P2P_ASP_TRANSPORT_UDP;
	else
		*out = P2P_ASP_TRANSPORT_UNKNOWN;

	return true;
}

static attr_handler handler_for_type(enum p2p_attr type)
{
	switch (type) {
	case P2P_ATTR_STATUS:
		return extract_p2p_status;
	case P2P_ATTR_MINOR_REASON_CODE:
		return extract_p2p_byte;
	case P2P_ATTR_P2P_CAPABILITY:
		return extract_p2p_capability;
	case P2P_ATTR_P2P_DEVICE_ID:
	case P2P_ATTR_P2P_GROUP_BSSID:
	case P2P_ATTR_INTENDED_P2P_INTERFACE_ADDR:
		return extract_p2p_addr;
	case P2P_ATTR_GO_INTENT:
		return extract_p2p_go_intent;
	case P2P_ATTR_CONFIGURATION_TIMEOUT:
		return extract_p2p_config_timeout;
	case P2P_ATTR_LISTEN_CHANNEL:
	case P2P_ATTR_OPERATING_CHANNEL:
		return extract_p2p_channel;
	case P2P_ATTR_EXTENDED_LISTEN_TIMING:
		return extract_p2p_listen_timing;
	case P2P_ATTR_P2P_MANAGEABILITY:
		break;
	case P2P_ATTR_CHANNEL_LIST:
		return extract_p2p_channel_list;
	case P2P_ATTR_NOTICE_OF_ABSENCE:
		return extract_p2p_notice_of_absence;
	case P2P_ATTR_P2P_DEVICE_INFO:
		return extract_p2p_device_info;
	case P2P_ATTR_P2P_GROUP_INFO:
		return extract_p2p_group_info;
	case P2P_ATTR_P2P_GROUP_ID:
	case P2P_ATTR_PERSISTENT_GROUP_INFO:
		return extract_p2p_group_id;
	case P2P_ATTR_P2P_INTERFACE:
		return extract_p2p_interface;
	case P2P_ATTR_INVITATION_FLAGS:
		return extract_p2p_invitation_flags;
	case P2P_ATTR_OOB_GO_NEGOTIATION_CHANNEL:
		break;
	case P2P_ATTR_SVC_HASH:
		return extract_p2p_service_hashes;
	case P2P_ATTR_SESSION_INFO_DATA_INFO:
		return extract_p2p_session_info;
	case P2P_ATTR_CONNECTION_CAPABILITY_INFO:
		return extract_p2p_byte;
	case P2P_ATTR_ADVERTISEMENT_ID_INFO:
		return extract_p2p_advertisement_id;
	case P2P_ATTR_ADVERTISED_SVC_INFO:
		return extract_p2p_advertised_service_info;
	case P2P_ATTR_SESSION_ID_INFO:
		return extract_p2p_session_id;
	case P2P_ATTR_FEATURE_CAPABILITY:
		return extract_p2p_feature_capability;
	case P2P_ATTR_VENDOR_SPECIFIC_ATTR:
		break;
	}

	return NULL;
}

struct attr_handler_entry {
	enum p2p_attr type;
	unsigned int flags;
	void *data;
	bool present;
};

/*
 * This function may find an error after having parsed part of the message
 * and may have allocated memory so the output needs to be deallocated
 * properly even on error return values.
 */
static int p2p_parse_attrs(const uint8_t *pdu, size_t len, int type, ...)
{
	struct p2p_attr_iter iter;
	uint8_t *p2p_data;
	ssize_t p2p_len;
	struct l_queue *entries;
	va_list args;
	bool have_required = true;
	bool parse_error = false;
	struct attr_handler_entry *entry;
	const struct l_queue_entry *e;

	p2p_data = ie_tlv_extract_p2p_payload(pdu, len, &p2p_len);
	if (!p2p_data)
		return p2p_len;

	p2p_attr_iter_init(&iter, p2p_data, p2p_len);

	va_start(args, type);

	entries = l_queue_new();

	while (type != -1) {
		entry = l_new(struct attr_handler_entry, 1);

		entry->type = type;
		entry->flags = va_arg(args, unsigned int);
		entry->data = va_arg(args, void *);

		type = va_arg(args, enum p2p_attr);
		l_queue_push_tail(entries, entry);
	}

	va_end(args);

	while (p2p_attr_iter_next(&iter)) {
		attr_handler handler;

		for (e = l_queue_get_entries(entries); e; e = e->next) {
			entry = e->data;

			if (p2p_attr_iter_get_type(&iter) == entry->type)
				break;
		}

		if (!e || entry->present) {
			parse_error = true;
			goto done;
		}

		entry->present = true;
		handler = handler_for_type(entry->type);

		if (!handler(p2p_attr_iter_get_data(&iter),
				p2p_attr_iter_get_length(&iter), entry->data)) {
			parse_error = true;
			goto done;
		}
	}

	for (e = l_queue_get_entries(entries); e; e = e->next) {
		entry = e->data;

		if (!entry->present && (entry->flags & ATTR_FLAG_REQUIRED)) {
			parse_error = true;
			goto done;
		}
	}

done:
	l_free(p2p_data);
	l_queue_destroy(entries, l_free);

	if (!have_required)
		return -EINVAL;
	if (parse_error)
		return -EBADMSG;

	return 0;
}

static void p2p_free_channel_list_attr(struct p2p_channel_list_attr *attr)
{
	l_queue_destroy(attr->channel_entries, l_free);
	attr->channel_entries = NULL;
}

static void p2p_free_notice_of_absence_attr(
					struct p2p_notice_of_absence_attr *attr)
{
	l_queue_destroy(attr->descriptors, l_free);
	attr->descriptors = NULL;
}

static void p2p_free_device_info_attr(struct p2p_device_info_attr *attr)
{
	l_queue_destroy(attr->secondary_device_types, l_free);
	attr->secondary_device_types = NULL;
}

static void p2p_free_group_info_attr(struct l_queue **group_clients)
{
	l_queue_destroy(*group_clients, p2p_free_client_info_descriptor);
	*group_clients = NULL;
}

static void p2p_free_interface_attr(struct p2p_interface_attr *attr)
{
	l_queue_destroy(attr->interface_addrs, l_free);
	attr->interface_addrs = NULL;
}

static void p2p_free_svc_hash_attr(struct l_queue **hashes)
{
	l_queue_destroy(*hashes, l_free);
	*hashes = NULL;
}

static void p2p_free_advertised_service_info_attr(struct l_queue **descriptors)
{
	l_queue_destroy(*descriptors, p2p_free_advertised_service_descriptor);
	*descriptors = NULL;
}

void p2p_free_beacon(struct p2p_beacon *data)
{
	p2p_free_notice_of_absence_attr(&data->notice_of_absence);
}

void p2p_free_probe_req(struct p2p_probe_req *data)
{
	p2p_free_device_info_attr(&data->device_info);
	p2p_free_svc_hash_attr(&data->service_hashes);
}

void p2p_free_probe_resp(struct p2p_probe_resp *data)
{
	p2p_free_notice_of_absence_attr(&data->notice_of_absence);
	p2p_free_device_info_attr(&data->device_info);
	p2p_free_group_info_attr(&data->group_clients);
	p2p_free_advertised_service_info_attr(&data->advertised_svcs);
}

void p2p_free_association_req(struct p2p_association_req *data)
{
	p2p_free_device_info_attr(&data->device_info);
	p2p_free_interface_attr(&data->interface);
}

void p2p_free_association_resp(struct p2p_association_resp *data)
{
}

void p2p_free_go_negotiation_req(struct p2p_go_negotiation_req *data)
{
	p2p_free_channel_list_attr(&data->channel_list);
	p2p_free_device_info_attr(&data->device_info);
}

void p2p_free_go_negotiation_resp(struct p2p_go_negotiation_resp *data)
{
	p2p_free_channel_list_attr(&data->channel_list);
	p2p_free_device_info_attr(&data->device_info);
}

void p2p_free_go_negotiation_confirmation(
				struct p2p_go_negotiation_confirmation *data)
{
	p2p_free_channel_list_attr(&data->channel_list);
}

void p2p_free_invitation_req(struct p2p_invitation_req *data)
{
	p2p_free_channel_list_attr(&data->channel_list);
	p2p_free_device_info_attr(&data->device_info);
}

void p2p_free_invitation_resp(struct p2p_invitation_resp *data)
{
	p2p_free_channel_list_attr(&data->channel_list);
}

void p2p_free_provision_disc_req(struct p2p_provision_discovery_req *data)
{
	p2p_free_channel_list_attr(&data->channel_list);
	p2p_free_device_info_attr(&data->device_info);
}

void p2p_free_provision_disc_resp(struct p2p_provision_discovery_resp *data)
{
	p2p_free_channel_list_attr(&data->channel_list);
	p2p_free_device_info_attr(&data->device_info);
}

void p2p_free_notice_of_absence(struct p2p_notice_of_absence *data)
{
	p2p_free_notice_of_absence_attr(&data->notice_of_absence);
}

void p2p_free_presence_req(struct p2p_presence_req *data)
{
	p2p_free_notice_of_absence_attr(&data->notice_of_absence);
}

void p2p_free_presence_resp(struct p2p_presence_resp *data)
{
	p2p_free_notice_of_absence_attr(&data->notice_of_absence);
}
