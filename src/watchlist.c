/*
 *
 *  Wireless daemon for Linux
 *
 *  Copyright (C) 2016  Intel Corporation. All rights reserved.
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

#include "watchlist.h"

static bool watchlist_item_match(const void *a, const void *b)
{
	const struct watchlist_item *item = a;
	uint32_t id = L_PTR_TO_UINT(b);

	return item->id == id;
}

static void watchlist_item_free(void *data)
{
	struct watchlist_item *item = data;

	if (item->destroy)
		item->destroy(item->notify_data);

	l_free(item);
}

struct watchlist *watchlist_new(void)
{
	struct watchlist *watchlist;

	watchlist = l_new(struct watchlist, 1);
	watchlist->items = l_queue_new();
	return watchlist;
}

void watchlist_init(struct watchlist *watchlist)
{
	watchlist->next_id = 0;
	watchlist->items = l_queue_new();
}

unsigned int watchlist_add(struct watchlist *watchlist, void *notify,
					void *notify_data,
					watchlist_item_destroy_func_t destroy)
{
	struct watchlist_item *item;

	item = l_new(struct watchlist_item, 1);
	item->id = ++watchlist->next_id;
	item->notify = notify;
	item->notify_data = notify_data;
	item->destroy = destroy;

	l_queue_push_tail(watchlist->items, item);

	return item->id;
}

bool watchlist_remove(struct watchlist *watchlist, unsigned int id)
{
	struct watchlist_item *item;

	if (watchlist->in_notify) {
		item = l_queue_find(watchlist->items, watchlist_item_match,
							L_UINT_TO_PTR(id));
		if (!item)
			return false;

		item->id = 0;	/* Mark stale */
		watchlist->stale_items = true;

		return true;
	}

	item = l_queue_remove_if(watchlist->items, watchlist_item_match,
							L_UINT_TO_PTR(id));
	if (!item)
		return false;

	if (item->destroy)
		item->destroy(item->notify_data);

	l_free(item);
	return true;
}

void watchlist_destroy(struct watchlist *watchlist)
{
	l_queue_destroy(watchlist->items, watchlist_item_free);
	watchlist->items = NULL;
}

void watchlist_free(struct watchlist *watchlist)
{
	l_queue_destroy(watchlist->items, watchlist_item_free);
	l_free(watchlist);
}

void __watchlist_prune_stale(struct watchlist *watchlist)
{
	struct watchlist_item *item;

	while ((item = l_queue_remove_if(watchlist->items, watchlist_item_match,
							L_UINT_TO_PTR(0)))) {
		if (item->destroy)
			item->destroy(item->notify_data);

		l_free(item);
	}

	watchlist->stale_items = false;
}
