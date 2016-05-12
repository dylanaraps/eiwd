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

#include "src/iwd.h"
#include "src/common.h"
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
	case SECURITY_PSK:
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
	const char *strtype;

	search.type = type;
	strncpy(search.ssid, ssid, 32);
	search.ssid[32] = 0;

	info = l_queue_remove_if(networks, network_info_match, &search);
	if (!info)
		return false;

	strtype = security_to_str(type);
	if (!strtype)
		goto fail;

	err = storage_network_touch(strtype, ssid);
	if (err < 0)
		goto fail;

	err = storage_network_get_mtime(strtype, ssid, &info->connected_time);
	if (err < 0)
		goto fail;

	l_queue_push_head(networks, info);
	return true;

fail:
	l_free(info);
	return false;
}

/* First 64 entries calculated by 1 / pow(n, 0.3) for n >= 1 */
static const double rankmod_table[] = {
	1.0000000000, 0.8122523964, 0.7192230933, 0.6597539554,
	0.6170338627, 0.5841906811, 0.5577898253, 0.5358867313,
	0.5172818580, 0.5011872336, 0.4870596972, 0.4745102806,
	0.4632516708, 0.4530661223, 0.4437850034, 0.4352752816,
	0.4274303178, 0.4201634287, 0.4134032816, 0.4070905315,
	0.4011753236, 0.3956154062, 0.3903746872, 0.3854221125,
	0.3807307877, 0.3762772797, 0.3720410580, 0.3680040435,
	0.3641502401, 0.3604654325, 0.3569369365, 0.3535533906,
	0.3503045821, 0.3471812999, 0.3441752105, 0.3412787518,
	0.3384850430, 0.3357878061, 0.3331812996, 0.3306602598,
	0.3282198502, 0.3258556179, 0.3235634544, 0.3213395618,
	0.3191804229, 0.3170827751, 0.3150435863, 0.3130600345,
	0.3111294892, 0.3092494947, 0.3074177553, 0.3056321221,
	0.3038905808, 0.3021912409, 0.3005323264, 0.2989121662,
	0.2973291870, 0.2957819051, 0.2942689208, 0.2927889114,
	0.2913406263, 0.2899228820, 0.2885345572, 0.2871745887,
};

double network_rankmod(uint32_t type, const char *ssid)
{
	const struct l_queue_entry *entry;
	int n;
	int nmax;

	for (n = 0, entry = l_queue_get_entries(networks); entry;
						entry = entry->next, n += 1) {
		const struct network_info *info = entry->data;

		if (info->type != type)
			continue;

		if (strcmp(info->ssid, ssid))
			continue;

		nmax = L_ARRAY_SIZE(rankmod_table);

		if (n >= nmax)
			n = nmax - 1;

		return rankmod_table[n];
	}

	return 0.0;
}

const char *network_get_ssid(struct network *network)
{
	return network->ssid;
}

struct netdev *network_get_netdev(struct network *network)
{
	return network->netdev;
}

const char *network_get_path(struct network *network)
{
	return network->object_path;
}

void network_init()
{
	networks = l_queue_new();
}

void network_exit()
{
	l_queue_destroy(networks, l_free);
}
