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

#include <sys/socket.h>
#include <linux/rtnetlink.h>
#include <arpa/inet.h>

#include <ell/ell.h>

#include "src/rtnlutil.h"

static size_t rta_add_u8(void *rta_buf, unsigned short type, uint8_t value)
{
	struct rtattr *rta = rta_buf;

	rta->rta_len = RTA_LENGTH(sizeof(uint8_t));
	rta->rta_type = type;
	*((uint8_t *) RTA_DATA(rta)) = value;

	return RTA_SPACE(sizeof(uint8_t));
}

static size_t rta_add_data(void *rta_buf, unsigned short type, void *data,
								size_t data_len)
{
	struct rtattr *rta = rta_buf;

	rta->rta_len = RTA_LENGTH(data_len);
	rta->rta_type = type;
	memcpy(RTA_DATA(rta), data, data_len);

	return RTA_SPACE(data_len);
}

uint32_t rtnl_set_linkmode_and_operstate(struct l_netlink *rtnl, int ifindex,
					uint8_t linkmode, uint8_t operstate,
					l_netlink_command_func_t cb,
					void *user_data,
					l_netlink_destroy_func_t destroy)
{
	struct ifinfomsg *rtmmsg;
	void *rta_buf;
	size_t bufsize;
	uint32_t id;

	bufsize = NLMSG_ALIGN(sizeof(struct ifinfomsg)) +
		RTA_SPACE(sizeof(uint8_t)) + RTA_SPACE(sizeof(uint8_t));

	rtmmsg = l_malloc(bufsize);
	memset(rtmmsg, 0, bufsize);

	rtmmsg->ifi_family = AF_UNSPEC;
	rtmmsg->ifi_index = ifindex;

	rta_buf = (void *) rtmmsg + NLMSG_ALIGN(sizeof(struct ifinfomsg));

	rta_buf += rta_add_u8(rta_buf, IFLA_LINKMODE, linkmode);
	rta_buf += rta_add_u8(rta_buf, IFLA_OPERSTATE, operstate);

	id = l_netlink_send(rtnl, RTM_SETLINK, 0, rtmmsg,
					rta_buf - (void *) rtmmsg,
					cb, user_data, destroy);
	l_free(rtmmsg);

	return id;
}

void rtnl_ifaddr_extract(const struct ifaddrmsg *ifa, int bytes,
				char **label, char **ip, char **broadcast)
{
	struct in_addr in_addr;
	struct rtattr *attr;

	for (attr = IFA_RTA(ifa); RTA_OK(attr, bytes);
						attr = RTA_NEXT(attr, bytes)) {
		switch (attr->rta_type) {
		case IFA_LOCAL:
			if (!ip)
				break;

			in_addr = *((struct in_addr *) RTA_DATA(attr));
			*ip = l_strdup(inet_ntoa(in_addr));

			break;
		case IFA_BROADCAST:
			if (!broadcast)
				break;

			in_addr = *((struct in_addr *) RTA_DATA(attr));
			*broadcast = l_strdup(inet_ntoa(in_addr));

			break;
		case IFA_LABEL:
			if (!label)
				break;

			*label = l_strdup(RTA_DATA(attr));
			break;
		}
	}
}

uint32_t rtnl_ifaddr_get(struct l_netlink *rtnl, l_netlink_command_func_t cb,
					void *user_data,
					l_netlink_destroy_func_t destroy)
{
	struct ifaddrmsg *rtmmsg;
	uint32_t id;

	rtmmsg = l_malloc(sizeof(struct ifaddrmsg));
	explicit_bzero(rtmmsg, sizeof(struct ifaddrmsg));

	rtmmsg->ifa_family = AF_INET;

	id = l_netlink_send(rtnl, RTM_GETADDR, NLM_F_DUMP, rtmmsg,
				sizeof(struct ifaddrmsg), cb, user_data,
				destroy);

	l_free(rtmmsg);

	return id;
}

static uint32_t rtnl_ifaddr_change(struct l_netlink *rtnl, uint16_t nlmsg_type,
					int ifindex, uint8_t prefix_len,
					const char *ip, const char *broadcast,
					l_netlink_command_func_t
					cb, void *user_data,
					l_netlink_destroy_func_t destroy)
{
	struct ifaddrmsg *rtmmsg;
	struct in_addr in_addr;
	void *rta_buf;
	size_t bufsize;
	uint32_t id;

	bufsize = NLMSG_ALIGN(sizeof(struct ifaddrmsg)) +
					RTA_SPACE(sizeof(struct in_addr)) +
					RTA_SPACE(sizeof(struct in_addr));

	rtmmsg = l_malloc(bufsize);
	explicit_bzero(rtmmsg, bufsize);

	rtmmsg->ifa_index = ifindex;
	rtmmsg->ifa_family = AF_INET;
	rtmmsg->ifa_flags = IFA_F_PERMANENT;
	rtmmsg->ifa_scope = RT_SCOPE_UNIVERSE;
	rtmmsg->ifa_prefixlen = prefix_len;

	rta_buf = (void *) rtmmsg + NLMSG_ALIGN(sizeof(struct ifaddrmsg));

	if (inet_pton(AF_INET, ip, &in_addr) < 1) {
		l_free(rtmmsg);
		return 0;
	}

	rta_buf += rta_add_data(rta_buf, IFA_LOCAL, &in_addr,
							sizeof(struct in_addr));

	if (broadcast) {
		if (inet_pton(AF_INET, broadcast, &in_addr) < 1) {
			l_free(rtmmsg);
			return 0;
		}
	} else {
		in_addr.s_addr = in_addr.s_addr |
					htonl(0xFFFFFFFFLU >> prefix_len);
	}

	rta_buf += rta_add_data(rta_buf, IFA_BROADCAST, &in_addr,
							sizeof(struct in_addr));

	id = l_netlink_send(rtnl, nlmsg_type, 0, rtmmsg,
						rta_buf - (void *) rtmmsg, cb,
						user_data, destroy);
	l_free(rtmmsg);

	return id;
}

uint32_t rtnl_ifaddr_add(struct l_netlink *rtnl, int ifindex,
				uint8_t prefix_len, const char *ip,
				const char *broadcast,
				l_netlink_command_func_t cb, void *user_data,
				l_netlink_destroy_func_t destroy)
{
	return rtnl_ifaddr_change(rtnl, RTM_NEWADDR, ifindex, prefix_len, ip,
					broadcast, cb, user_data, destroy);
}

uint32_t rtnl_ifaddr_delete(struct l_netlink *rtnl, int ifindex,
				uint8_t prefix_len, const char *ip,
				const char *broadcast,
				l_netlink_command_func_t cb, void *user_data,
				l_netlink_destroy_func_t destroy)
{
	return rtnl_ifaddr_change(rtnl, RTM_DELADDR, ifindex, prefix_len, ip,
					broadcast, cb, user_data, destroy);
}
