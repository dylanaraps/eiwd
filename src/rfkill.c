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

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <linux/rfkill.h>
#include <stdio.h>
#include <unistd.h>

#include <ell/ell.h>

#include "src/iwd.h"
#include "src/common.h"
#include "src/rfkill.h"

#ifdef TEMP_FAILURE_RETRY
#define TFR TEMP_FAILURE_RETRY
#else
#define TFR
#endif

struct rfkill_map_entry {
	unsigned int wiphy_id;
	unsigned int rfkill_id;
	bool soft_state : 1;
	bool hard_state : 1;
};

struct rfkill_watch {
	uint32_t id;
	rfkill_state_cb_t callback;
	void *user_data;
};

static struct l_queue *rfkill_map;
static struct l_io *rfkill_io;

static struct l_queue *rfkill_watches;
static uint32_t next_watch_id;

static bool rfkill_id_match(const void *a, const void *b)
{
	const struct rfkill_map_entry *entry = a;
	uint32_t id = L_PTR_TO_UINT(b);

	return entry->rfkill_id == id;
}

static bool wiphy_id_match(const void *a, const void *b)
{
	const struct rfkill_map_entry *entry = a;
	uint32_t id = L_PTR_TO_UINT(b);

	return entry->wiphy_id == id;
}

static struct rfkill_map_entry *map_wiphy(unsigned int rfkill_id)
{
	int fd, bytes, consumed;
	char *path;
	char buf[32];
	unsigned int wiphy_id;
	struct rfkill_map_entry *entry;

	path = l_strdup_printf("/sys/class/rfkill/rfkill%u/device/index", rfkill_id);

	fd = TFR(open(path, O_RDONLY));

	l_free(path);

	if (fd < 0)
		return NULL;

	bytes = TFR(read(fd, buf, sizeof(buf) - 1));

	close(fd);

	if (bytes <= 0)
		return NULL;

	buf[bytes] = '\0';
	if (sscanf(buf, "%u %n", &wiphy_id, &consumed) != 1 ||
			consumed != bytes)
		return NULL;

	entry = l_new(struct rfkill_map_entry, 1);
	entry->rfkill_id = rfkill_id;
	entry->wiphy_id = wiphy_id;

	return entry;
}

static void rfkill_watch_notify(void *data, void *user_data)
{
	struct rfkill_watch *watch = data;
	struct rfkill_map_entry *entry = user_data;

	watch->callback(entry->wiphy_id, entry->soft_state, entry->hard_state,
			watch->user_data);
}

static bool rfkill_read(struct l_io *io, void *user_data)
{
	int fd = l_io_get_fd(rfkill_io);
	struct rfkill_event e;
	int bytes;
	struct rfkill_map_entry *entry;

	bytes = TFR(read(fd, &e, sizeof(e)));
	if (bytes < (int) sizeof(e)) {
		if (bytes <= 0)
			l_error("rfkill read: %s", strerror(errno));
		else
			l_error("rfkill read of %i bytes", bytes);

		return false;
	}

	if (e.type != RFKILL_TYPE_WLAN)
		return true;

	entry = l_queue_find(rfkill_map, rfkill_id_match, L_UINT_TO_PTR(e.idx));

	if (e.op == RFKILL_OP_ADD) {
		if (entry) {
			l_error("rfkill id %u already known", e.idx);

			return true;
		}

		entry = map_wiphy(e.idx);
		if (!entry) {
			l_error("rfkill id %u can't be matched to a wiphy",
					e.idx);

			return true;
		}

		l_queue_push_tail(rfkill_map, entry);
	} else if (e.op != RFKILL_OP_DEL && e.op != RFKILL_OP_CHANGE)
		return true;

	if (!entry) {
		l_error("rfkill id %u not found in a %s event", e.idx,
				e.op == RFKILL_OP_DEL ? "RFKILL_OP_DEL" :
				"RFKILL_OP_CHANGE");

		return true;
	}

	if (e.op == RFKILL_OP_DEL) {
		l_queue_remove(rfkill_map, entry);

		l_free(entry);

		return true;
	}

	entry->soft_state = e.soft != 0;
	entry->hard_state = e.hard != 0;

	l_queue_foreach(rfkill_watches, rfkill_watch_notify, entry);

	return true;
}

bool rfkill_set_soft_state(unsigned int wiphy_id, bool state)
{
	int fd = l_io_get_fd(rfkill_io);
	struct rfkill_event e;
	struct rfkill_map_entry *entry;
	int bytes;

	entry = l_queue_find(rfkill_map, wiphy_id_match,
				L_UINT_TO_PTR(wiphy_id));
	if (!entry)
		return false;

	memset(&e, 0, sizeof(e));

	e.idx = entry->rfkill_id;
	e.type = RFKILL_TYPE_WLAN;
	e.op = RFKILL_OP_CHANGE;
	e.soft = state ? 1 : 0;

	bytes = TFR(write(fd, &e, sizeof(e)));
	if (bytes < (int) sizeof(e)) {
		if (bytes <= 0)
			l_error("rfkill write: %s", strerror(errno));
		else
			l_error("rfkill write of %i bytes", bytes);

		return false;
	}

	return true;
}

static bool rfkill_watch_match(const void *a, const void *b)
{
	const struct rfkill_watch *item = a;
	uint32_t id = L_PTR_TO_UINT(b);

	return item->id == id;
}

uint32_t rfkill_watch_add(rfkill_state_cb_t func, void *user_data)
{
	struct rfkill_watch *item;

	item = l_new(struct rfkill_watch, 1);
	item->id = ++next_watch_id;
	item->callback = func;
	item->user_data = user_data;

	if (!rfkill_watches)
		rfkill_watches = l_queue_new();

	l_queue_push_tail(rfkill_watches, item);

	return item->id;
}

bool rfkill_watch_remove(uint32_t watch_id)
{
	struct rfkill_watch *item;

	item = l_queue_remove_if(rfkill_watches, rfkill_watch_match,
					L_UINT_TO_PTR(watch_id));
	if (!item)
		return false;

	l_free(item);

	return true;
}

bool rfkill_get_soft_state(unsigned int wiphy_id)
{
	struct rfkill_map_entry *entry;

	entry = l_queue_find(rfkill_map, wiphy_id_match,
				L_UINT_TO_PTR(wiphy_id));

	return entry ? entry->soft_state : false;
}

bool rfkill_get_hard_state(unsigned int wiphy_id)
{
	struct rfkill_map_entry *entry;

	entry = l_queue_find(rfkill_map, wiphy_id_match,
				L_UINT_TO_PTR(wiphy_id));

	return entry ? entry->hard_state : false;
}

int rfkill_init(void)
{
	int fd;

	fd = TFR(open("/dev/rfkill", O_RDWR | O_CLOEXEC));
	if (fd < 0)
		return -errno;

	rfkill_io = l_io_new(fd);
	if (!rfkill_io) {
		close(fd);
		return -EIO;
	}

	l_io_set_close_on_destroy(rfkill_io, true);

	l_io_set_read_handler(rfkill_io, rfkill_read, NULL, NULL);

	rfkill_map = l_queue_new();

	return 0;
}

void rfkill_exit(void)
{
	l_io_destroy(rfkill_io);

	l_queue_destroy(rfkill_map, l_free);

	l_queue_destroy(rfkill_watches, l_free);
}
