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

static attr_handler handler_for_type(enum wsc_attr type)
{
	switch (type) {
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

	/* TODO: Check Selected Registrar attributes */

done:
	l_queue_destroy(entries, l_free);

	if (!have_required)
		return -EINVAL;
	if (parse_error)
		return -EBADMSG;

	*out_version2 = version2;

	return 0;
}
