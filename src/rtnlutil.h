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

uint32_t rtnl_set_linkmode_and_operstate(struct l_netlink *rtnl, int ifindex,
					uint8_t linkmode, uint8_t operstate,
					l_netlink_command_func_t cb,
					void *user_data,
					l_netlink_destroy_func_t destroy);

uint32_t rtnl_set_mac(struct l_netlink *rtnl, int ifindex,
					const uint8_t addr[static 6],
					l_netlink_command_func_t cb,
					void *user_data,
					l_netlink_destroy_func_t destroy);

void rtnl_ifaddr_extract(const struct ifaddrmsg *ifa, int bytes,
				char **label, char **ip, char **broadcast);
uint32_t rtnl_ifaddr_get(struct l_netlink *rtnl, l_netlink_command_func_t cb,
				void *user_data,
				l_netlink_destroy_func_t destroy);
uint32_t rtnl_ifaddr_add(struct l_netlink *rtnl, int ifindex,
				uint8_t prefix_len, const char *ip,
				const char *broadcast,
				l_netlink_command_func_t cb, void *user_data,
				l_netlink_destroy_func_t destroy);
uint32_t rtnl_ifaddr_delete(struct l_netlink *rtnl, int ifindex,
				uint8_t prefix_len, const char *ip,
				const char *broadcast,
				l_netlink_command_func_t cb, void *user_data,
				l_netlink_destroy_func_t destroy);
