/*
 *
 *  Wireless daemon for Linux
 *
 *  Copyright (C) 2013-2019  Intel Corporation. All rights reserved.
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

#define uninitialized_var(x) x = x

/*
 * Set a maximum to prevent sending too much data to the kernel when hashing
 * the password (or any other crypto operations involving the password).
 * This value is not tied to IEEE or any RFC's, just chosen to be long enough
 */
#define IWD_MAX_PASSWORD_LEN	2048

struct l_genl;
struct l_genl_family;

const struct l_settings *iwd_get_config(void);
struct l_genl *iwd_get_genl(void);
struct l_netlink *iwd_get_rtnl(void);

void netdev_shutdown(void);

const char *iwd_get_iface_whitelist(void);
const char *iwd_get_iface_blacklist(void);

const char *iwd_get_phy_whitelist(void);
const char *iwd_get_phy_blacklist(void);
