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

#include "src/wiphy.h"
#include "src/netdev.h"

struct netdev_data {
	uint32_t index;
	uint32_t flags;
	char ifname[IF_NAMESIZE];
};

struct netdev_watchlist_item {
	uint32_t id;
	netdev_watch_func_t added;
	netdev_watch_func_t removed;
	void *userdata;
	netdev_destroy_func_t destroy;
};

static struct l_netlink *rtnl = NULL;
static struct l_hashmap *netdev_list = NULL;

static struct l_queue *netdev_watches = NULL;
static uint32_t netdev_next_watch_id = 0;

static void do_debug(const char *str, void *user_data)
{
	const char *prefix = user_data;

	l_info("%s%s", prefix, str);
}

static size_t rta_add_u8(void *rta_buf, unsigned short type, uint8_t value)
{
	struct rtattr *rta = rta_buf;

	rta->rta_len = RTA_LENGTH(sizeof(uint8_t));
	rta->rta_type = type;
	*((uint8_t *) RTA_DATA(rta)) = value;

	return RTA_SPACE(sizeof(uint8_t));
}

struct cb_data {
	netdev_command_func_t callback;
	void *user_data;
};

static void netlink_result(int error, uint16_t type, const void *data,
			uint32_t len, void *user_data)
{
	struct cb_data *cb_data = user_data;

	if (!cb_data)
		return;

	cb_data->callback(error < 0 ? false : true, cb_data->user_data);

	l_free(cb_data);
}

void netdev_set_linkmode_and_operstate(uint32_t ifindex,
				uint8_t linkmode, uint8_t operstate,
				netdev_command_func_t callback, void *user_data)
{
	struct ifinfomsg *rtmmsg;
	void *rta_buf;
	size_t bufsize;
	struct cb_data *cb_data = NULL;

	bufsize = NLMSG_LENGTH(sizeof(struct ifinfomsg)) +
		RTA_SPACE(sizeof(uint8_t)) + RTA_SPACE(sizeof(uint8_t));

	rtmmsg = l_malloc(bufsize);
	memset(rtmmsg, 0, bufsize);

	rtmmsg->ifi_family = AF_UNSPEC;
	rtmmsg->ifi_index = ifindex;

	rta_buf = rtmmsg + 1;

	rta_buf += rta_add_u8(rta_buf, IFLA_LINKMODE, linkmode);
	rta_buf += rta_add_u8(rta_buf, IFLA_OPERSTATE, operstate);

	if (callback) {
		cb_data = l_new(struct cb_data, 1);
		cb_data->callback = callback;
		cb_data->user_data = user_data;
	}

	l_netlink_send(rtnl, RTM_SETLINK, 0, rtmmsg,
					rta_buf - (void *) rtmmsg,
					netlink_result, cb_data, NULL);

	l_free(rtmmsg);
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

	wiphy_notify_dellink(index);

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

static void netdev_watchlist_item_free(void *userdata)
{
	struct netdev_watchlist_item *item = userdata;

	if (item->destroy)
		item->destroy(item->userdata);

	l_free(item);
}

static bool netdev_watchlist_item_match(const void *a, const void *b)
{
	const struct netdev_watchlist_item *item = a;
	uint32_t id = L_PTR_TO_UINT(b);

	return item->id == id;
}

uint32_t netdev_watch_add(netdev_watch_func_t added,
				netdev_watch_func_t removed,
				void *userdata, netdev_destroy_func_t destroy)
{
	struct netdev_watchlist_item *item;

	item = l_new(struct netdev_watchlist_item, 1);
	item->id = ++netdev_next_watch_id;
	item->added = added;
	item->removed = removed;
	item->userdata = userdata;
	item->destroy = destroy;

	l_queue_push_tail(netdev_watches, item);

	return item->id;
}

bool netdev_watch_remove(uint32_t id)
{
	struct netdev_watchlist_item *item;

	item = l_queue_remove_if(netdev_watches, netdev_watchlist_item_match,
							L_UINT_TO_PTR(id));
	if (!item)
		return false;

	netdev_watchlist_item_free(item);
	return true;
}

void __netdev_watch_call_added(struct netdev *netdev)
{
	const struct l_queue_entry *e;

	for (e = l_queue_get_entries(netdev_watches); e; e = e->next) {
		struct netdev_watchlist_item *item = e->data;

		if (item->added)
			item->added(netdev, item->userdata);
	}
}

void __netdev_watch_call_removed(struct netdev *netdev)
{
	const struct l_queue_entry *e;

	for (e = l_queue_get_entries(netdev_watches); e; e = e->next) {
		struct netdev_watchlist_item *item = e->data;

		if (item->removed)
			item->removed(netdev, item->userdata);
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

	netdev_watches = l_queue_new();

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

	l_queue_destroy(netdev_watches, netdev_watchlist_item_free);

	return true;
}
