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

#include <stdint.h>

#include <ell/ell.h>

#include "erpcache.h"

#define ERP_DEFAULT_KEY_LIFETIME 86400000000

struct erp_cache_entry {
	char *id;
	void *emsk;
	size_t emsk_len;
	void *session_id;
	size_t session_len;
	char *erp_domain;
	char *ssid;
	uint64_t expire_time;
};

static struct l_queue *key_cache;

static void destroy_entry(void *data)
{
	struct erp_cache_entry *entry = data;

	l_free(entry->id);
	l_free(entry->emsk);
	l_free(entry->session_id);
	l_free(entry->ssid);

	if (entry->erp_domain)
		l_free(entry->erp_domain);

	l_free(entry);
}

void erp_add_key(const char *id, const void *session_id,
			size_t session_len, const void *emsk, size_t emsk_len,
			const char *ssid, const char *erp_domain)
{
	struct erp_cache_entry *entry;

	if (!unlikely(id || session_id || emsk))
		return;

	entry = l_new(struct erp_cache_entry, 1);

	entry->id = l_strdup(id);
	entry->emsk = l_memdup(emsk, emsk_len);
	entry->emsk_len = emsk_len;
	entry->session_id = l_memdup(session_id, session_len);
	entry->session_len = session_len;
	entry->ssid = l_strdup(ssid);
	entry->expire_time = l_time_offset(l_time_now(),
					ERP_DEFAULT_KEY_LIFETIME);

	if (erp_domain)
		entry->erp_domain = l_strdup(erp_domain);

	l_queue_push_head(key_cache, entry);
}

static struct erp_cache_entry *find_keycache(const char *id, const char *ssid)
{
	const struct l_queue_entry *entry;

	for (entry = l_queue_get_entries(key_cache); entry;
			entry = entry->next) {
		struct erp_cache_entry *cache = entry->data;

		if (l_time_after(l_time_now(), cache->expire_time)) {
			l_queue_remove(key_cache, cache);
			destroy_entry(cache);
			continue;
		}

		if (id) {
			if (strcmp(cache->id, id))
				continue;
		} else if (ssid) {
			if (strcmp(cache->ssid, ssid))
				continue;
		} else
			return NULL;

		return cache;
	}

	return NULL;
}

void erp_remove_key(const char *id)
{
	struct erp_cache_entry *entry = find_keycache(id, NULL);

	if (!entry)
		return;

	l_queue_remove(key_cache, entry);

	destroy_entry(entry);
}

bool erp_find_key_by_identity(const char *id, void *session,
			size_t *session_len, void *emsk, size_t *emsk_len,
			const char **erp_domain)
{
	struct erp_cache_entry *cache = find_keycache(id, NULL);

	if (!cache)
		return false;

	memcpy(emsk, cache->emsk, cache->emsk_len);
	*emsk_len = cache->emsk_len;
	memcpy(session, cache->session_id, cache->session_len);
	*session_len = cache->session_len;
	*erp_domain = cache->erp_domain;

	return true;
}

bool erp_has_key_for_ssid(const char *ssid)
{
	return find_keycache(NULL, ssid) != NULL;
}

bool erp_has_key_for_identity(const char *id)
{
	return find_keycache(id, NULL) != NULL;
}

void erp_init(void)
{
	key_cache = l_queue_new();
}

void erp_exit(void)
{
	l_queue_destroy(key_cache, destroy_entry);
}
