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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdbool.h>
#include <stdarg.h>
#include <errno.h>

#include <ell/ell.h>

#include "wsc.h"

void wsc_wfa_ext_iter_init(struct wsc_wfa_ext_iter *iter,
				const unsigned char *pdu, unsigned short len)
{
	iter->pdu = pdu;
	iter->max = len;
	iter->pos = 0;
}

bool wsc_wfa_ext_iter_next(struct wsc_wfa_ext_iter *iter)
{
	const unsigned char *start = iter->pdu + iter->pos;
	const unsigned char *end = iter->pdu + iter->max;
	unsigned char type;
	unsigned char len;

	if (iter->pos + 2 >= iter->max)
		return false;

	type = *start;
	start += 1;

	len = *start;
	start += 1;

	if (start + len > end)
		return false;

	iter->type = type;
	iter->len = len;
	iter->data = start;

	iter->pos = start + len - iter->pdu;

	return true;
}

void wsc_attr_iter_init(struct wsc_attr_iter *iter, const unsigned char *pdu,
			unsigned int len)
{
	iter->pdu = pdu;
	iter->max = len;
	iter->pos = 0;
}

bool wsc_attr_iter_next(struct wsc_attr_iter *iter)
{
	const unsigned char *start = iter->pdu + iter->pos;
	const unsigned char *end = iter->pdu + iter->max;
	unsigned short type;
	unsigned short len;

	/* Make sure we have at least type + len fields */
	if (iter->pos + 4 >= iter->max)
		return false;

	type = l_get_be16(start);
	start += 2;

	len = l_get_be16(start);
	start += 2;

	if (start + len > end)
		return false;

	iter->type = type;
	iter->len = len;
	iter->data = start;

	iter->pos = start + len - iter->pdu;

	return true;
}

bool wsc_attr_iter_recurse_wfa_ext(struct wsc_attr_iter *iter,
					struct wsc_wfa_ext_iter *wfa_iter)
{
	static const unsigned char wfa_ext[3] = { 0x00, 0x37, 0x2a };

	if (iter->type != WSC_ATTR_VENDOR_EXTENSION)
		return false;

	if (iter->len < 3)
		return false;

	if (memcmp(iter->data, wfa_ext, sizeof(wfa_ext)))
		return false;

	wsc_wfa_ext_iter_init(wfa_iter, iter->data + 3, iter->len - 3);

	return true;
}

enum attr_flag {
	ATTR_FLAG_REQUIRED,	/* Always required */
	ATTR_FLAG_VERSION2,	/* Included if Version2 is present */
	ATTR_FLAG_REGISTRAR,	/* Included if Selected Registrar is true */
};

typedef bool (*attr_handler)(struct wsc_attr_iter *, void *);

static bool extract_uint8(struct wsc_attr_iter *iter, void *data)
{
	uint8_t *to = data;

	if (wsc_attr_iter_get_length(iter) != 1)
		return false;

	*to = *wsc_attr_iter_get_data(iter);

	return true;
}

static bool extract_uint16(struct wsc_attr_iter *iter, void *data)
{
	uint16_t *to = data;

	if (wsc_attr_iter_get_length(iter) != 2)
		return false;

	*to = l_get_be16(wsc_attr_iter_get_data(iter));

	return true;
}

static bool extract_bool(struct wsc_attr_iter *iter, void *data)
{
	bool *to = data;

	if (wsc_attr_iter_get_length(iter) != 1)
		return false;

	*to = *wsc_attr_iter_get_data(iter) ? true : false;

	return true;
}

static bool extract_ascii_string(struct wsc_attr_iter *iter, void *data,
					unsigned int max_len)
{
	char *out = data;
	const uint8_t *p;
	unsigned int len;
	unsigned int i;

	len = wsc_attr_iter_get_length(iter);
	if (len > max_len)
		return false;

	p = wsc_attr_iter_get_data(iter);

	for (i = 0; i < len; i++) {
		if (!p[i])
			break;

		if (!l_ascii_isprint(p[i]))
			return false;
	}

	memcpy(out, p, i);
	out[i] = '\0';
	return true;
}

static bool extract_utf8_string(struct wsc_attr_iter *iter, void *data,
					unsigned int max_len)
{
	char *out = data;
	const uint8_t *p;
	unsigned int len;
	unsigned int i;

	len = wsc_attr_iter_get_length(iter);
	if (len > max_len)
		return false;

	p = wsc_attr_iter_get_data(iter);

	for (i = 0; i < len; i++) {
		if (!p[i])
			break;
	}

	if (!l_utf8_validate((const char *) p, i, NULL))
		return false;

	memcpy(out, p, i);
	out[i] = '\0';
	return true;
}

static bool extract_device_name(struct wsc_attr_iter *iter, void *data)
{
	return extract_utf8_string(iter, data, 32);
}

static bool extract_device_password_id(struct wsc_attr_iter *iter, void *data)
{
	uint16_t v;
	enum wsc_device_password_id *out = data;

	if (wsc_attr_iter_get_length(iter) != 2)
		return false;

	v = l_get_be16(wsc_attr_iter_get_data(iter));
	if (v > 0x0008)
		return false;

	*out = v;
	return true;
}

static bool extract_manufacturer(struct wsc_attr_iter *iter, void *data)
{
	return extract_ascii_string(iter, data, 64);
}

static bool extract_model_name(struct wsc_attr_iter *iter, void *data)
{
	return extract_ascii_string(iter, data, 32);
}

static bool extract_model_number(struct wsc_attr_iter *iter, void *data)
{
	return extract_ascii_string(iter, data, 32);
}

static bool extract_primary_device_type(struct wsc_attr_iter *iter, void *data)
{
	struct wsc_primary_device_type *out = data;
	const uint8_t *p;
	uint16_t category;

	if (wsc_attr_iter_get_length(iter) != 8)
		return false;

	p = wsc_attr_iter_get_data(iter);
	category = l_get_be16(p);

	if (category > 12 && category != 255)
		return false;

	out->category = category;
	memcpy(out->oui, p + 2, 3);
	out->oui_type = p[5];
	out->subcategory = l_get_be16(p + 6);
	return true;
}

static bool extract_request_type(struct wsc_attr_iter *iter, void *data)
{
	enum wsc_request_type *out = data;
	uint8_t rt;

	if (!extract_uint8(iter, &rt))
		return false;

	/* WSC 2.0.5: Table 42 */
	if (rt > 3)
		return false;

	*out = rt;
	return true;
}

static bool extract_response_type(struct wsc_attr_iter *iter, void *data)
{
	enum wsc_response_type *out = data;
	uint8_t rt;

	if (!extract_uint8(iter, &rt))
		return false;

	/* WSC 2.0.5: Table 43 */
	if (rt > 3)
		return false;

	*out = rt;
	return true;
}

static bool extract_serial_number(struct wsc_attr_iter *iter, void *data)
{
	return extract_ascii_string(iter, data, 32);
}

static bool extract_version(struct wsc_attr_iter *iter, void *data)
{
	uint8_t *out = data;
	uint8_t v;

	if (!extract_uint8(iter, &v))
		return false;

	/*
	 * "This attribute is always set to value 0x10 (version 1.0)
	 * for backwards compatibility"
	 */
	if (v != 0x10)
		return false;

	*out = v;
	return true;
}

static bool extract_wsc_state(struct wsc_attr_iter *iter, void *data)
{
	uint8_t *out = data;
	uint8_t st;

	if (!extract_uint8(iter, &st))
		return false;

	if (st < 1 || st > 2)
		return false;

	*out = st;
	return true;
}

static bool extract_uuid(struct wsc_attr_iter *iter, void *data)
{
	uint8_t *out = data;

	if (wsc_attr_iter_get_length(iter) != 16)
		return false;

	memcpy(out, wsc_attr_iter_get_data(iter), 16);

	return true;
}

static attr_handler handler_for_type(enum wsc_attr type)
{
	switch (type) {
	case WSC_ATTR_AP_SETUP_LOCKED:
		return extract_bool;
	case WSC_ATTR_CONFIGURATION_METHODS:
		return extract_uint16;
	case WSC_ATTR_DEVICE_NAME:
		return extract_device_name;
	case WSC_ATTR_DEVICE_PASSWORD_ID:
		return extract_device_password_id;
	case WSC_ATTR_MANUFACTURER:
		return extract_manufacturer;
	case WSC_ATTR_MODEL_NAME:
		return extract_model_name;
	case WSC_ATTR_MODEL_NUMBER:
		return extract_model_number;
	case WSC_ATTR_PRIMARY_DEVICE_TYPE:
		return extract_primary_device_type;
	case WSC_ATTR_RF_BANDS:
		return extract_uint8;
	case WSC_ATTR_REQUEST_TYPE:
		return extract_request_type;
	case WSC_ATTR_RESPONSE_TYPE:
		return extract_response_type;
	case WSC_ATTR_SELECTED_REGISTRAR:
		return extract_bool;
	case WSC_ATTR_SELECTED_REGISTRAR_CONFIGURATION_METHODS:
		return extract_uint16;
	case WSC_ATTR_SERIAL_NUMBER:
		return extract_serial_number;
	case WSC_ATTR_VERSION:
		return extract_version;
	case WSC_ATTR_WSC_STATE:
		return extract_wsc_state;
	case WSC_ATTR_UUID_E:
		return extract_uuid;
	default:
		break;
	}

	return NULL;
}

struct attr_handler_entry {
	enum wsc_attr type;
	unsigned int flags;
	void *data;
	bool present;
};

static bool verify_version2(struct wsc_wfa_ext_iter *ext_iter)
{
	if (!wsc_wfa_ext_iter_next(ext_iter))
		return false;

	if (wsc_wfa_ext_iter_get_type(ext_iter) != WSC_WFA_EXTENSION_VERSION2)
		return false;

	if (wsc_wfa_ext_iter_get_length(ext_iter) != 1)
		return false;

	return true;
}

static int wsc_parse_attrs(const unsigned char *pdu, unsigned int len,
				bool *out_version2,
				struct wsc_wfa_ext_iter *ext_iter,
				enum wsc_attr type, ...)
{
	struct wsc_attr_iter iter;
	struct l_queue *entries;
	const struct l_queue_entry *e;
	va_list args;
	bool version2 = false;
	bool sr = false;
	bool have_required = true;
	bool parse_error = false;

	wsc_attr_iter_init(&iter, pdu, len);

	va_start(args, type);

	entries = l_queue_new();

	while (type != WSC_ATTR_INVALID) {
		struct attr_handler_entry *entry;

		entry = l_new(struct attr_handler_entry, 1);

		entry->type = type;
		entry->flags = va_arg(args, unsigned int);
		entry->data = va_arg(args, void *);

		type = va_arg(args, enum wsc_attr);
		l_queue_push_tail(entries, entry);
	}

	va_end(args);
	e = l_queue_get_entries(entries);

	while (wsc_attr_iter_next(&iter)) {
		attr_handler handler;
		struct attr_handler_entry *entry;
		const struct l_queue_entry *e2;

		for (e2 = e; e2; e2 = e2->next) {
			entry = e2->data;

			if (wsc_attr_iter_get_type(&iter) == entry->type) {
				entry->present = true;
				break;
			}

			if (entry->flags & ATTR_FLAG_REQUIRED) {
				have_required = false;
				goto done;
			}
		}

		if (e2 == NULL) {
			if (wsc_attr_iter_get_type(&iter)
					!= WSC_ATTR_VENDOR_EXTENSION)
				break;

			if (!wsc_attr_iter_recurse_wfa_ext(&iter, ext_iter))
				break;

			if (!verify_version2(ext_iter)) {
				parse_error = true;
				goto done;
			}

			version2 = true;
			goto check;
		}

		if (entry->type == WSC_ATTR_SELECTED_REGISTRAR)
			sr = true;

		handler = handler_for_type(entry->type);

		if (!handler(&iter, entry->data)) {
			parse_error = true;
			goto done;
		}

		e = e2->next;
	}

	for (; e; e = e->next) {
		struct attr_handler_entry *entry = e->data;

		if (entry->flags & ATTR_FLAG_REQUIRED)
			parse_error = true;
	}

check:
	/*
	 * Check for Version 2.0 required attributes.
	 * If version2 attribute is present in the WFA Vendor field,
	 * then check the required attributes are present.  Mostly relevant
	 * for Probe Request messages according to 8.2.4 in WSC 2.0.5
	 */
	if (version2) {
		struct attr_handler_entry *entry;

		for (e = l_queue_get_entries(entries); e; e = e->next) {
			entry = e->data;

			if (!(entry->flags & ATTR_FLAG_VERSION2))
				continue;

			if (entry->present)
				continue;

			parse_error = true;
			goto done;
		}
	}

	/*
	 * If Selected Registrar is present and true, then certain attributes
	 * must also be present.
	 */
	if (sr) {
		struct attr_handler_entry *entry;

		for (e = l_queue_get_entries(entries); e; e = e->next) {
			entry = e->data;

			if (!(entry->flags & ATTR_FLAG_REGISTRAR))
				continue;

			if (entry->present)
				continue;

			parse_error = true;
			goto done;
		}

	}

done:
	l_queue_destroy(entries, l_free);

	if (!have_required)
		return -EINVAL;
	if (parse_error)
		return -EBADMSG;

	*out_version2 = version2;

	return 0;
}

static bool wfa_extract_authorized_macs(struct wsc_wfa_ext_iter *iter,
								void *data)
{
	uint8_t *to = data;
	unsigned int len = wsc_wfa_ext_iter_get_length(iter);
	unsigned int mod;

	if (!len || len > 30)
		return false;

	mod = len % 6;
	if (mod)
		return false;

	memcpy(to, wsc_wfa_ext_iter_get_data(iter), len);
	return true;
}

static bool wfa_extract_registrar_configuration_methods(
				struct wsc_wfa_ext_iter *iter, void *data)
{
	uint16_t *to = data;

	if (wsc_wfa_ext_iter_get_length(iter) != 2)
		return false;

	*to = l_get_be16(wsc_wfa_ext_iter_get_data(iter));
	return true;
}

int wsc_parse_beacon(const unsigned char *pdu, unsigned int len,
				struct wsc_beacon *out)
{
	int r;
	struct wsc_wfa_ext_iter iter;
	uint8_t version;

	memset(out, 0, sizeof(struct wsc_beacon));

	r = wsc_parse_attrs(pdu, len, &out->version2, &iter,
		WSC_ATTR_VERSION, ATTR_FLAG_REQUIRED, &version,
		WSC_ATTR_WSC_STATE, ATTR_FLAG_REQUIRED, &out->config_state,
		WSC_ATTR_AP_SETUP_LOCKED, 0, &out->ap_setup_locked,
		WSC_ATTR_SELECTED_REGISTRAR, 0, &out->selected_registrar,
		WSC_ATTR_DEVICE_PASSWORD_ID,
			ATTR_FLAG_REGISTRAR, &out->device_password_id,
		WSC_ATTR_SELECTED_REGISTRAR_CONFIGURATION_METHODS,
			ATTR_FLAG_REGISTRAR, &out->selected_reg_config_methods,
		WSC_ATTR_UUID_E, ATTR_FLAG_REQUIRED, &out->uuid_e,
		WSC_ATTR_RF_BANDS, 0, &out->rf_bands,
		WSC_ATTR_INVALID);

	if (r < 0)
		return r;

	if (!wsc_wfa_ext_iter_next(&iter))
		goto done;

	if (wsc_wfa_ext_iter_get_type(&iter) ==
					WSC_WFA_EXTENSION_AUTHORIZED_MACS) {
		if (!wfa_extract_authorized_macs(&iter, &out->authorized_macs))
			return -EBADMSG;

		if (!wsc_wfa_ext_iter_next(&iter))
			goto done;
	}

	if (wsc_wfa_ext_iter_get_type(&iter) ==
			WSC_WFA_EXTENSION_REGISTRAR_CONFIGRATION_METHODS) {
		if (!wfa_extract_registrar_configuration_methods(&iter,
						&out->reg_config_methods))
			return -EBADMSG;

		if (!wsc_wfa_ext_iter_next(&iter))
			goto done;
	}

	return -EINVAL;

done:
	return 0;
}

int wsc_parse_probe_response(const unsigned char *pdu, unsigned int len,
				struct wsc_probe_response *out)
{
	int r;
	struct wsc_wfa_ext_iter iter;
	uint8_t version;

	memset(out, 0, sizeof(struct wsc_probe_response));

	r = wsc_parse_attrs(pdu, len, &out->version2, &iter,
		WSC_ATTR_VERSION, ATTR_FLAG_REQUIRED, &version,
		WSC_ATTR_WSC_STATE, ATTR_FLAG_REQUIRED, &out->config_state,
		WSC_ATTR_AP_SETUP_LOCKED, 0, &out->ap_setup_locked,
		WSC_ATTR_SELECTED_REGISTRAR, 0, &out->selected_registrar,
		WSC_ATTR_DEVICE_PASSWORD_ID,
			ATTR_FLAG_REGISTRAR, &out->device_password_id,
		WSC_ATTR_SELECTED_REGISTRAR_CONFIGURATION_METHODS,
			ATTR_FLAG_REGISTRAR, &out->selected_reg_config_methods,
		WSC_ATTR_RESPONSE_TYPE, ATTR_FLAG_REQUIRED, &out->response_type,
		WSC_ATTR_UUID_E, ATTR_FLAG_REQUIRED, &out->uuid_e,
		WSC_ATTR_MANUFACTURER, ATTR_FLAG_REQUIRED, &out->manufacturer,
		WSC_ATTR_MODEL_NAME, ATTR_FLAG_REQUIRED, &out->model_name,
		WSC_ATTR_MODEL_NUMBER, ATTR_FLAG_REQUIRED, &out->model_number,
		WSC_ATTR_SERIAL_NUMBER, ATTR_FLAG_REQUIRED, &out->serial_number,
		WSC_ATTR_PRIMARY_DEVICE_TYPE,
			ATTR_FLAG_REQUIRED, &out->primary_device_type,
		WSC_ATTR_DEVICE_NAME, ATTR_FLAG_REQUIRED, &out->device_name,
		WSC_ATTR_CONFIGURATION_METHODS,
			ATTR_FLAG_REQUIRED, &out->config_methods,
		WSC_ATTR_RF_BANDS, 0, &out->rf_bands,
		WSC_ATTR_INVALID);

	if (r < 0)
		return r;

	if (!wsc_wfa_ext_iter_next(&iter))
		goto done;

	if (wsc_wfa_ext_iter_get_type(&iter) ==
					WSC_WFA_EXTENSION_AUTHORIZED_MACS) {
		if (!wfa_extract_authorized_macs(&iter, &out->authorized_macs))
			return -EBADMSG;

		if (!wsc_wfa_ext_iter_next(&iter))
			goto done;
	}

	if (wsc_wfa_ext_iter_get_type(&iter) ==
			WSC_WFA_EXTENSION_REGISTRAR_CONFIGRATION_METHODS) {
		if (!wfa_extract_registrar_configuration_methods(&iter,
						&out->reg_config_methods))
			return -EBADMSG;

		if (!wsc_wfa_ext_iter_next(&iter))
			goto done;
	}

	return -EINVAL;

done:
	return 0;
}
