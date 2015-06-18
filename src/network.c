/*
 *
 *  Wireless daemon for Linux
 *
 *  Copyright (C) 2013-2015  Intel Corporation. All rights reserved.
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

#include <ell/ell.h>

#include "src/network.h"
#include "src/storage.h"
#include "src/scan.h"

struct network_info {
	char ssid[33];
	uint32_t type;
	struct timespec connected_time;		/* Time last connected */
};

static struct l_queue *networks = NULL;

static int timespec_compare(const void *a, const void *b, void *user_data)
{
	const struct network_info *ni_a = a;
	const struct network_info *ni_b = b;
	const struct timespec *tsa = &ni_a->connected_time;
	const struct timespec *tsb = &ni_b->connected_time;

	if (tsa->tv_sec > tsb->tv_sec)
		return -1;

	if (tsa->tv_sec < tsb->tv_sec)
		return 1;

	if (tsa->tv_nsec > tsb->tv_nsec)
		return -1;

	if (tsa->tv_nsec < tsb->tv_nsec)
		return -1;

	return 0;
}

static bool network_info_match(const void *a, const void *b)
{
	const struct network_info *ni_a = a;
	const struct network_info *ni_b = b;

	if (ni_a->type != ni_b->type)
		return false;

	if (strcmp(ni_a->ssid, ni_b->ssid))
		return false;

	return true;
}

bool network_seen(uint32_t type, const char *ssid)
{
	struct timespec mtim;
	int err;
	struct network_info *info;

	switch(type) {
	case SCAN_SSID_SECURITY_PSK:
		err = storage_network_get_mtime("psk", ssid, &mtim);
		break;
	default:
		return false;
	}

	if (err < 0)
		return false;

	info = l_new(struct network_info, 1);
	info->type = type;
	strncpy(info->ssid, ssid, 32);
	info->ssid[32] = 0;
	memcpy(&info->connected_time, &mtim, sizeof(struct timespec));

	l_queue_insert(networks, info, timespec_compare, NULL);

	return true;
}

bool network_connected(uint32_t type, const char *ssid)
{
	int err;
	struct network_info *info;
	struct network_info search;

	search.type = type;
	strncpy(search.ssid, ssid, 32);
	search.ssid[32] = 0;

	info = l_queue_remove_if(networks, network_info_match, &search);
	if (!info)
		return false;

	switch(type) {
	case SCAN_SSID_SECURITY_PSK:
		err = storage_network_get_mtime("psk", ssid,
					&info->connected_time);
		break;
	default:
		goto fail;
	}

	if (err < 0)
		goto fail;

	l_queue_push_head(networks, info);
	return true;

fail:
	l_free(info);
	return false;
}

void network_init()
{
	networks = l_queue_new();
}

void network_exit()
{
	l_queue_destroy(networks, l_free);
}
