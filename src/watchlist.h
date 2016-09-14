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

typedef void (*watchlist_item_destroy_func_t)(void *data);

struct watchlist_item {
	unsigned int id;
	void *notify;
	void *notify_data;
	watchlist_item_destroy_func_t destroy;
};

struct watchlist {
	int next_id;
	struct l_queue *items;
};

struct watchlist *watchlist_new(void);
void watchlist_init(struct watchlist *watchlist);
unsigned int watchlist_add(struct watchlist *watchlist, void *notify,
					void *notify_data,
					watchlist_item_destroy_func_t destroy);
bool watchlist_remove(struct watchlist *watchlist, unsigned int id);
void watchlist_destroy(struct watchlist *watchlist);
void watchlist_free(struct watchlist *watchlist);

#define WATCHLIST_NOTIFY(watchlist, type, args...)			\
	do {								\
		const struct l_queue_entry *entry =			\
				l_queue_get_entries((watchlist)->items);\
									\
		for (; entry; entry = entry->next) {			\
			struct watchlist_item *item = entry->data;	\
			type t = item->notify;				\
			t(args, item->notify_data);			\
		}							\
	} while	(false)							\

