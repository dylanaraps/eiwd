/*
 *
 *  Wireless daemon for Linux
 *
 *  Copyright (C) 2013-2016  Intel Corporation. All rights reserved.
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

#include "src/device.h"

struct device_watchlist_item {
	uint32_t id;
	device_watch_func_t added;
	device_watch_func_t removed;
	void *userdata;
	device_destroy_func_t destroy;
};

static struct l_queue *device_watches = NULL;
static uint32_t device_next_watch_id = 0;

static void device_watchlist_item_free(void *userdata)
{
	struct device_watchlist_item *item = userdata;

	if (item->destroy)
		item->destroy(item->userdata);

	l_free(item);
}

static bool device_watchlist_item_match(const void *a, const void *b)
{
	const struct device_watchlist_item *item = a;
	uint32_t id = L_PTR_TO_UINT(b);

	return item->id == id;
}

uint32_t device_watch_add(device_watch_func_t added,
				device_watch_func_t removed,
				void *userdata, device_destroy_func_t destroy)
{
	struct device_watchlist_item *item;

	item = l_new(struct device_watchlist_item, 1);
	item->id = ++device_next_watch_id;
	item->added = added;
	item->removed = removed;
	item->userdata = userdata;
	item->destroy = destroy;

	l_queue_push_tail(device_watches, item);

	return item->id;
}

bool device_watch_remove(uint32_t id)
{
	struct device_watchlist_item *item;

	item = l_queue_remove_if(device_watches, device_watchlist_item_match,
							L_UINT_TO_PTR(id));
	if (!item)
		return false;

	device_watchlist_item_free(item);
	return true;
}

void __device_watch_call_added(struct netdev *device)
{
	const struct l_queue_entry *e;

	for (e = l_queue_get_entries(device_watches); e; e = e->next) {
		struct device_watchlist_item *item = e->data;

		if (item->added)
			item->added(device, item->userdata);
	}
}

void __device_watch_call_removed(struct netdev *device)
{
	const struct l_queue_entry *e;

	for (e = l_queue_get_entries(device_watches); e; e = e->next) {
		struct device_watchlist_item *item = e->data;

		if (item->removed)
			item->removed(device, item->userdata);
	}
}

bool device_init(void)
{
	device_watches = l_queue_new();

	return true;
}

bool device_exit(void)
{
	l_queue_destroy(device_watches, device_watchlist_item_free);

	return true;
}
