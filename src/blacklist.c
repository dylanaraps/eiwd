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

#include <ell/ell.h>

#include "src/blacklist.h"
#include "src/util.h"
#include "src/iwd.h"
#include "src/module.h"

/*
 * The current timeout is multiplied by this value after an entry is blacklisted
 * more than once.
 */
#define BLACKLIST_DEFAULT_MULTIPLIER	30

/* Initial timeout for a new blacklist entry */
#define BLACKLIST_DEFAULT_TIMEOUT	60

/* The maximum amount of time a BSS can be blacklisted for */
#define BLACKLIST_DEFAULT_MAX_TIMEOUT	86400

static uint64_t blacklist_multiplier;
static uint64_t blacklist_initial_timeout;
static uint64_t blacklist_max_timeout;

struct blacklist_entry {
	uint8_t addr[6];
	uint64_t added_time;
	uint64_t expire_time;
};

static struct l_queue *blacklist;

static bool check_if_expired(void *data, void *user_data)
{
	struct blacklist_entry *entry = data;
	uint64_t now = l_get_u64(user_data);

	if (l_time_diff(now, entry->added_time) > blacklist_max_timeout) {
		l_debug("Removing entry "MAC" on prune", MAC_STR(entry->addr));
		l_free(entry);
		return true;
	}

	return false;
}

static void blacklist_prune(void)
{
	uint64_t now = l_time_now();

	l_queue_foreach_remove(blacklist, check_if_expired, &now);
}

static bool match_addr(const void *a, const void *b)
{
	const struct blacklist_entry *entry = a;
	const uint8_t *addr = b;

	if (!memcmp(entry->addr, addr, 6))
		return true;

	return false;
}

void blacklist_add_bss(const uint8_t *addr)
{
	struct blacklist_entry *entry;

	blacklist_prune();

	entry = l_queue_find(blacklist, match_addr, addr);

	if (entry) {
		uint64_t offset = l_time_diff(entry->added_time,
							entry->expire_time);

		offset *= blacklist_multiplier;

		if (offset > blacklist_max_timeout)
			offset = blacklist_max_timeout;

		entry->expire_time = l_time_offset(entry->added_time, offset);

		return;
	}

	entry = l_new(struct blacklist_entry, 1);

	entry->added_time = l_time_now();
	entry->expire_time = l_time_offset(entry->added_time,
						blacklist_initial_timeout);
	memcpy(entry->addr, addr, 6);

	l_queue_push_tail(blacklist, entry);
}

bool blacklist_contains_bss(const uint8_t *addr)
{
	bool ret;
	uint64_t time_now;
	struct blacklist_entry *entry;

	blacklist_prune();

	entry = l_queue_find(blacklist, match_addr, addr);

	if (!entry)
		return false;

	time_now = l_time_now();

	ret = l_time_after(time_now, entry->expire_time) ? false : true;

	return ret;
}

void blacklist_remove_bss(const uint8_t *addr)
{
	struct blacklist_entry *entry;

	blacklist_prune();

	entry = l_queue_remove_if(blacklist, match_addr, addr);

	if (!entry)
		return;

	l_free(entry);
}

static int blacklist_init(void)
{
	const struct l_settings *config = iwd_get_config();

	if (!l_settings_get_uint64(config, "Blacklist", "InitialTimeout",
					&blacklist_initial_timeout))
		blacklist_initial_timeout = BLACKLIST_DEFAULT_TIMEOUT;

	/* For easier user configuration the timeout values are in seconds */
	blacklist_initial_timeout *= 1000000;

	if (!l_settings_get_uint64(config, "Blacklist",
					"Multiplier",
					&blacklist_multiplier))
		blacklist_multiplier = BLACKLIST_DEFAULT_MULTIPLIER;

	if (!l_settings_get_uint64(config, "Blacklist",
					"MaximumTimeout",
					&blacklist_max_timeout))
		blacklist_max_timeout = BLACKLIST_DEFAULT_MAX_TIMEOUT;

	blacklist_max_timeout *= 1000000;

	blacklist = l_queue_new();

	return 0;
}

static void blacklist_exit(void)
{
	l_queue_destroy(blacklist, l_free);
}

IWD_MODULE(blacklist, blacklist_init, blacklist_exit)
