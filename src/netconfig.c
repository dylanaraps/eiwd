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

#include <errno.h>
#include <linux/rtnetlink.h>

#include <ell/ell.h>

#include "src/iwd.h"
#include "src/netconfig.h"

struct netconfig {
	uint32_t ifindex;
};

static struct l_queue *netconfig_list;

static void netconfig_destroy(void *data)
{
	struct netconfig *netconfig = data;

	l_free(netconfig);
}

static bool netconfig_match(const void *a, const void *b)
{
	const struct netconfig *netconfig = a;
	uint32_t ifindex = L_PTR_TO_UINT(b);

	if (netconfig->ifindex == ifindex)
		return true;

	return false;
}

static struct netconfig *netconfig_find(uint32_t ifindex)
{
	const struct l_queue_entry *entry;

	for (entry = l_queue_get_entries(netconfig_list); entry;
							entry = entry->next) {
		struct netconfig *netconfig = entry->data;

		if (netconfig->ifindex != ifindex)
			continue;

		return netconfig;
	}

	return NULL;
}

bool netconfig_ifindex_add(uint32_t ifindex)
{
	struct netconfig *netconfig;

	if (!netconfig_list)
		return false;

	l_debug("Starting netconfig for interface: %d", ifindex);

	netconfig = netconfig_find(ifindex);
	if (netconfig)
		return true;

	netconfig = l_new(struct netconfig, 1);
	netconfig->ifindex = ifindex;

	l_queue_push_tail(netconfig_list, netconfig);

	return true;
}

bool netconfig_ifindex_remove(uint32_t ifindex)
{
	struct netconfig *netconfig;

	if (!netconfig_list)
		return false;

	l_debug();

	netconfig = l_queue_remove_if(netconfig_list, netconfig_match,
							L_UINT_TO_PTR(ifindex));
	if (!netconfig)
		return false;

	netconfig_destroy(netconfig);

	return true;
}

static int netconfig_init(void)
{
	bool enabled;

	if (netconfig_list)
		return -EALREADY;

	if (!l_settings_get_bool(iwd_get_config(), "General",
					"enable_network_config", &enabled) ||
								!enabled) {
		l_warn("netconfig: Network configuration with the IP addresses "
								"is disabled.");
		return false;
	}

	netconfig_list = l_queue_new();

	return 0;
}

static void netconfig_exit(void)
{
	if (!netconfig_list)
		return;

	l_queue_destroy(netconfig_list, netconfig_destroy);
}

IWD_MODULE(netconfig, netconfig_init, netconfig_exit)
