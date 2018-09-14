/*
 *
 *  Ethernet daemon for Linux
 *
 *  Copyright (C) 2017-2018  Intel Corporation. All rights reserved.
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

#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <fnmatch.h>
#include <linux/rtnetlink.h>
#include <linux/if.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/filter.h>
#include <arpa/inet.h>
#include <net/if_arp.h>
#include <ell/ell.h>

#include "src/eap.h"
#include "wired/network.h"
#include "wired/ethdev.h"

struct ethdev {
	uint32_t index;
	char ifname[IFNAMSIZ];
	uint8_t addr[ETH_ALEN];
	bool active;
	bool lower_up;
	struct l_queue *eapol_sessions;
};

struct eapol {
	struct ethdev *dev;
	uint8_t addr[ETH_ALEN];
	struct eap_state *eap;
	struct l_settings *cred;
};

static struct l_netlink *rtnl = NULL;
static struct l_queue *ethdev_list = NULL;
static char **whitelist_filter;
static char **blacklist_filter;

static struct l_io *pae_io;

struct eapol_hdr {
	uint8_t proto_ver;
	uint8_t pkt_type;
	__be16  pkt_len;
} __attribute__ ((packed));

static const uint8_t eapol_start[] = { 0x02, 0x01, 0x00, 0x00 };
static const uint8_t pae_group_addr[] = { 0x01, 0x80, 0xc2, 0x00, 0x00, 0x03 };

static bool pae_write(struct ethdev *dev, const uint8_t *addr,
					const uint8_t *frame, size_t len)
{
	int fd = l_io_get_fd(pae_io);
	struct sockaddr_ll sll;
	ssize_t res;

	memset(&sll, 0, sizeof(sll));
	sll.sll_family = AF_PACKET;
	sll.sll_ifindex = dev->index;
	sll.sll_protocol = htons(ETH_P_PAE);
	sll.sll_halen = ETH_ALEN;
	memcpy(sll.sll_addr, addr, ETH_ALEN);

	res = sendto(fd, frame, len, 0,
				(struct sockaddr *) &sll, sizeof(sll));
	if (res < 0)
		return false;

	return true;
}

static void eapol_free(void *data)
{
	struct eapol *eapol = data;

	l_debug("Freeing EAPoL session");

	eap_free(eapol->eap);
	l_settings_free(eapol->cred);
	l_free(eapol);
}

static bool eapol_match(const void *a, const void *b)
{
	const struct eapol *eapol = a;

	return !memcmp(eapol->addr, b, ETH_ALEN);
}

static struct eapol *eapol_lookup(struct ethdev *dev, const uint8_t *addr)
{
	return l_queue_find(dev->eapol_sessions, eapol_match, addr);
}

static bool ethdev_match(const void *a, const void *b)
{
	const struct ethdev *dev = a;
	uint32_t index = L_PTR_TO_UINT(b);

	return (dev->index == index);
}

static struct ethdev *ethdev_lookup(uint32_t index)
{
	return l_queue_find(ethdev_list, ethdev_match, L_UINT_TO_PTR(index));
}

static void eap_tx_packet(const uint8_t *eap_data, size_t len, void *user_data)
{
	struct eapol *eapol = user_data;
	uint8_t frame[1500];

	l_put_u8(0x02, frame);
	l_put_u8(0x00, frame + 1);
	l_put_be16(len, frame + 2);
	memcpy(frame + 4, eap_data, len);

	pae_write(eapol->dev, eapol->addr, frame, len + 4);
}

static void eap_complete(enum eap_result result, void *user_data)
{
	struct eapol *eapol = user_data;
	struct ethdev *dev = eapol->dev;

	l_debug("result %u", result);

	l_queue_remove(dev->eapol_sessions, eapol);
	eapol_free(eapol);
}

static void rx_packet(struct ethdev *dev, const uint8_t *addr,
					const void *frame, size_t len)
{
	const struct eapol_hdr *hdr = frame;
	struct eapol *eapol;

	if (len < 4) {
		l_error("Too short EAPoL packet with %zu bytes", len);
		return;
	}

	if (L_BE16_TO_CPU(hdr->pkt_len) != len - 4) {
		l_error("Length mismatch with EAPoL packet");
		return;
	}

	switch (hdr->pkt_type) {
	case 0x00:	/* EAP-Packet */
		eapol = eapol_lookup(dev, addr);
		if (!eapol) {
			eapol = l_new(struct eapol, 1);
			eapol->dev = dev;
			memcpy(eapol->addr, addr, ETH_ALEN);
			eapol->eap = eap_new(eap_tx_packet,
							eap_complete, eapol);
			if (!eapol->eap) {
				l_error("Failed to create EAP instance");
				l_free(eapol);
				return;
			}

			l_debug("Created new EAPoL session");

			l_queue_push_tail(dev->eapol_sessions, eapol);

			eapol->cred = network_lookup_security("default");
			eap_load_settings(eapol->eap, eapol->cred, "EAP-");
		}
		eap_rx_packet(eapol->eap, frame + 4, len - 4);
		break;
	}
}

/*
 * BPF filter to match skb->dev->type == 1 (ARPHRD_ETHER) and
 * match skb->protocol == 0x888e (PAE).
 */
static struct sock_filter pae_filter[] = {
	{ 0x28,  0,  0, 0xfffff01c },	/* ldh #hatype		*/
	{ 0x15,  0,  3, 0x00000001 },	/* jne #1, drop		*/
	{ 0x28,  0,  0, 0xfffff000 },	/* ldh #proto		*/
	{ 0x15,  0,  1, 0x0000888e },	/* jne #0x888e, drop	*/
	{ 0x06,  0,  0, 0xffffffff },	/* keep: ret #-1	*/
	{ 0x06,  0,  0, 0000000000 },	/* drop: ret #0		*/
};

static const struct sock_fprog pae_fprog = { .len = 6, .filter = pae_filter };

static bool pae_read(struct l_io *io, void *user_data)
{
	int fd = l_io_get_fd(io);
	struct ethdev *dev;
	struct sockaddr_ll sll;
	socklen_t sll_len;
	ssize_t bytes;
	uint8_t frame[1500];

	memset(&sll, 0, sizeof(sll));
	sll_len = sizeof(sll);

	bytes = recvfrom(fd, frame, sizeof(frame), 0,
					(struct sockaddr *) &sll, &sll_len);
	if (bytes <= 0) {
		l_error("Reading from PAE socket failed: %s", strerror(errno));
		return false;
	}

	if (sll.sll_halen != ETH_ALEN)
		return true;

	if (ntohs(sll.sll_protocol) != ETH_P_PAE)
		return true;

	dev = ethdev_lookup(sll.sll_ifindex);
	if (!dev)
		return true;

	rx_packet(dev, sll.sll_addr, frame, bytes);

	return true;
}

static void pae_destroy()
{
	pae_io = NULL;
}

static bool pae_open(void)
{
	int fd;

	fd = socket(PF_PACKET, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK,
							htons(ETH_P_ALL));
	if (fd < 0)
		return false;

	if (setsockopt(fd, SOL_SOCKET, SO_ATTACH_FILTER,
					&pae_fprog, sizeof(pae_fprog)) < 0) {
		close(fd);
		return false;
	}

	pae_io = l_io_new(fd);
	l_io_set_close_on_destroy(pae_io, true);

	l_debug("Opened PAE socket");

	l_io_set_read_handler(pae_io, pae_read, NULL, pae_destroy);

	return true;
}

static void pae_close(void)
{
	l_io_destroy(pae_io);
	pae_io = NULL;

	l_debug("Closed PAE socket");
}

static void do_debug(const char *str, void *user_data)
{
	const char *prefix = user_data;

	l_info("%s%s", prefix, str);
}

static char *read_devtype_from_uevent(const char *ifname)
{
	char line[128], *filename, *devtype = NULL;
	FILE *f;

	if (!ifname)
		return NULL;

	filename = l_strdup_printf("/sys/class/net/%s/uevent", ifname);
	f = fopen(filename, "re");
	l_free(filename);

	if (!f)
		return NULL;

	while (fgets(line, sizeof(line), f)) {
		char *pos;

		pos = strchr(line, '\n');
		if (!pos)
			continue;
		pos[0] = '\0';

		if (!strncmp(line, "DEVTYPE=", 8)) {
			devtype = l_strdup(line + 8);
			break;
		}
	}

	fclose(f);

	return devtype;
}

static void ethdev_free(void *data)
{
	struct ethdev *dev = data;

	l_debug("Freeing device %s", dev->ifname);

	l_queue_destroy(dev->eapol_sessions, eapol_free);
	l_free(dev);
}

static bool is_ifname_valid(const char *ifname)
{
	char *pattern;
	unsigned int i;

	if (!whitelist_filter)
		goto check_blacklist;

	for (i = 0; (pattern = whitelist_filter[i]); i++) {
		if (fnmatch(pattern, ifname, 0))
			continue;

		goto check_blacklist;
	}

	return false;

check_blacklist:
	if (!blacklist_filter)
		return true;

	for (i = 0; (pattern = blacklist_filter[i]); i++) {
		if (!fnmatch(pattern, ifname, 0))
			return false;
	}

	return true;
}

static void newlink_notify(const struct ifinfomsg *ifi, int bytes)
{
	uint32_t index = ifi->ifi_index;
	struct ethdev *dev;
	const struct rtattr *attr;
	uint8_t *addr = NULL;
	const char *ifname = NULL;
	uint8_t linkmode = 0, operstate = 0;
	bool active, lower_up;

	if (ifi->ifi_type != ARPHRD_ETHER)
		return;

	active = ifi->ifi_flags & IFF_UP;
	lower_up = ifi->ifi_flags & IFF_LOWER_UP;

	for (attr = IFLA_RTA(ifi); RTA_OK(attr, bytes);
						attr = RTA_NEXT(attr, bytes)) {
		switch (attr->rta_type) {
		case IFLA_ADDRESS:
			if (RTA_PAYLOAD(attr) == ETH_ALEN)
				addr = RTA_DATA(attr);
			break;
		case IFLA_IFNAME:
			ifname = RTA_DATA(attr);
			break;
		case IFLA_LINKMODE:
			linkmode = l_get_u8(RTA_DATA(attr));
			break;
		case IFLA_OPERSTATE:
			operstate = l_get_u8(RTA_DATA(attr));
			break;
		}
	}

	if (!addr || !ifname)
		return;

	l_debug("%s: linkmode %u operstate %u", ifname, linkmode, operstate);

	if (!is_ifname_valid(ifname)) {
		l_debug("Ignoring device with interface name %s", ifname);
		return;
	}

	dev = ethdev_lookup(index);
	if (!dev) {
		char *devtype;

		/*
		 * If there is no existing Ethernet device structure, then
		 * first check uevent if this is wired Ethernet or not.
		 */
		devtype = read_devtype_from_uevent(ifname);
		if (devtype) {
			l_free(devtype);
			return;
		}

		if (l_queue_isempty(ethdev_list)) {
			if (!pae_open()) {
				l_error("Failed to open PAE port");
				return;
			}
		}

		dev = l_new(struct ethdev, 1);
		dev->index = index;
		dev->active = false;
		dev->lower_up = false;
		dev->eapol_sessions = l_queue_new();

		l_debug("Creating device %u", dev->index);

		l_queue_push_tail(ethdev_list, dev);
	}

	if (ifname)
		strcpy(dev->ifname, ifname);

	memcpy(dev->addr, addr, ETH_ALEN);

	if (lower_up && !dev->lower_up)
		pae_write(dev, pae_group_addr,
					eapol_start, sizeof(eapol_start));
	else if (!lower_up && dev->lower_up)
		l_queue_clear(dev->eapol_sessions, eapol_free);

	dev->active = active;
	dev->lower_up = lower_up;
}

static void dellink_notify(const struct ifinfomsg *ifi, int bytes)
{
	uint32_t index = ifi->ifi_index;
	struct ethdev *dev;

	if (ifi->ifi_type != ARPHRD_ETHER)
		return;

	dev = l_queue_remove_if(ethdev_list, ethdev_match,
						L_UINT_TO_PTR(index));
	if (!dev)
		return;

	l_debug("Removing device %u", dev->index);

	ethdev_free(dev);

	if (l_queue_isempty(ethdev_list))
		pae_close();
}

static void link_notify(uint16_t type, const void *data, uint32_t len,
							void *user_data)
{
	const struct ifinfomsg *ifi = data;
	unsigned int bytes;

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

static void getlink_callback(int error, uint16_t type, const void *data,
						uint32_t len, void *user_data)
{
	const struct ifinfomsg *ifi = data;
	unsigned int bytes;

	if (error) {
		l_error("Failure with link information dump (%d)", error);
		return;
	}

	if (type != RTM_NEWLINK)
		return;

	bytes = len - NLMSG_ALIGN(sizeof(struct ifinfomsg));

	newlink_notify(ifi, bytes);
}

bool ethdev_init(const char *whitelist, const char *blacklist)
{
	struct ifinfomsg msg;

	if (rtnl)
		return false;

	l_debug("Opening route netlink socket");

	rtnl = l_netlink_new(NETLINK_ROUTE);
	if (!rtnl) {
		l_error("Failed to open route netlink socket");
		return false;
	}

	if (getenv("EAD_RTNL_DEBUG"))
		l_netlink_set_debug(rtnl, do_debug, "[RTNL] ", NULL);

	if (!l_netlink_register(rtnl, RTNLGRP_LINK, link_notify, NULL, NULL)) {
		l_error("Failed to register for RTNL link notifications");
		l_netlink_destroy(rtnl);
		return false;
	}

	ethdev_list = l_queue_new();

	if (whitelist)
		whitelist_filter = l_strsplit(whitelist, ',');

	if (blacklist)
		blacklist_filter = l_strsplit(blacklist, ',');

	memset(&msg, 0, sizeof(msg));

	l_netlink_send(rtnl, RTM_GETLINK, NLM_F_DUMP, &msg, sizeof(msg),
						getlink_callback, NULL, NULL);

	return true;
}

void ethdev_exit(void)
{
	if (!rtnl)
		return;

	l_queue_destroy(ethdev_list, ethdev_free);
	ethdev_list = NULL;

	pae_close();

	l_strfreev(whitelist_filter);
	l_strfreev(blacklist_filter);

	l_debug("Closing route netlink socket");
	l_netlink_destroy(rtnl);
	rtnl = NULL;
}
