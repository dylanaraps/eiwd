/*
 *
 *  Wireless daemon for Linux
 *
 *  Copyright (C) 2013-2014  Intel Corporation. All rights reserved.
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

#include <stdlib.h>
#include <linux/rtnetlink.h>
#include <net/if_arp.h>
#include <net/if.h>
#include <ell/ell.h>

#include "src/netdev.h"

struct netdev_data {
	uint32_t index;
	uint32_t flags;
	char ifname[IF_NAMESIZE];
};

static struct l_netlink *rtnl = NULL;
static struct l_hashmap *netdev_list = NULL;

static void do_debug(const char *str, void *user_data)
{
	const char *prefix = user_data;

	l_info("%s%s", prefix, str);
}

static void free_netdev_data(void *user_data)
{
	struct netdev_data *netdev = user_data;

	l_free(netdev);
}

static void newlink_notify(const struct ifinfomsg *ifi, int bytes)
{
	struct netdev_data *netdev;
	uint32_t index = ifi->ifi_index;
	struct rtattr *rta;

	netdev = l_hashmap_lookup(netdev_list, L_UINT_TO_PTR(index));
	if (!netdev) {
		netdev = l_new(struct netdev_data, 1);

		netdev->index = index;

		if (!l_hashmap_insert(netdev_list,
					L_UINT_TO_PTR(index), netdev)) {
			free_netdev_data(netdev);
			return;
		}
	}

	netdev->flags = ifi->ifi_flags;

	for (rta = IFLA_RTA(ifi); RTA_OK(rta, bytes);
					rta = RTA_NEXT(rta, bytes)) {
		switch (rta->rta_type) {
		case IFLA_IFNAME:
			if (RTA_PAYLOAD(rta) <= IF_NAMESIZE)
				strcpy(netdev->ifname, RTA_DATA(rta));
			break;
		}
	}
}

static void dellink_notify(const struct ifinfomsg *ifi, int bytes)
{
	struct netdev_data *netdev;
	uint32_t index = ifi->ifi_index;

	netdev = l_hashmap_remove(netdev_list, L_UINT_TO_PTR(index));
	if (!netdev)
		return;

	free_netdev_data(netdev);
}

static void link_notify(uint16_t type, const void *data, uint32_t len,
							void *user_data)
{
	const struct ifinfomsg *ifi = data;
	int bytes;

	if (ifi->ifi_type != ARPHRD_ETHER)
		return;

	bytes = len - NLMSG_ALIGN(sizeof(struct ifinfomsg));

	switch (type) {
	case RTM_NEWLINK:
		newlink_notify(ifi, bytes);
		break;
	case RTM_DELLINK:
		dellink_notify(ifi, bytes);
		break;
	}
}

static void netdev_destroy(void)
{
	/*
	 * The netlink object keeps track of the registered notification
	 * callbacks and their multicast memberships. When destroying the
	 * netlink object, all resources will be freed.
	 */
	l_netlink_destroy(rtnl);
	rtnl = NULL;

	l_hashmap_destroy(netdev_list, free_netdev_data);
	netdev_list = NULL;
}

bool netdev_init(void)
{
	if (rtnl)
		return false;

	l_debug("Opening route netlink socket");

	rtnl = l_netlink_new(NETLINK_ROUTE);
	if (!rtnl) {
		l_error("Failed to open route netlink socket");
		return false;
	}

	if (getenv("IWD_RTNL_DEBUG"))
		l_netlink_set_debug(rtnl, do_debug, "[RTNL] ", NULL);

	netdev_list = l_hashmap_new();

	if (!l_netlink_register(rtnl, RTNLGRP_LINK, link_notify, NULL, NULL)) {
		l_error("Failed to register link notification");
		goto destroy;
	}

	return true;

destroy:
	netdev_destroy();

	return false;
}

bool netdev_exit(void)
{
	if (!rtnl)
		return false;

	l_debug("Closing route netlink socket");

	netdev_destroy();

	return true;
}
