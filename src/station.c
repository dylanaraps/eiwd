/*
 *
 *  Wireless daemon for Linux
 *
 *  Copyright (C) 2018  Intel Corporation. All rights reserved.
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

#include <errno.h>

#include <ell/ell.h>

#include "src/util.h"
#include "src/iwd.h"
#include "src/common.h"
#include "src/scan.h"
#include "src/netdev.h"
#include "src/network.h"
#include "src/station.h"

static struct l_queue *station_list;

struct station *station_create(struct wiphy *wiphy, struct netdev *netdev)
{
	struct station *station;

	station = l_new(struct station, 1);

	station->wiphy = wiphy;
	station->netdev = netdev;

	l_queue_push_head(station_list, station);

	return station;
}

void station_free(struct station *station)
{
	l_debug("");

	if (!l_queue_remove(station_list, station))
		return;

	l_free(station);
}

bool station_init(void)
{
	station_list = l_queue_new();
	return true;
}

void station_exit(void)
{
	l_queue_destroy(station_list, NULL);
	station_list = NULL;
}
