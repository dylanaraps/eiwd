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

#define uninitialized_var(x) x = x

struct l_genl;
struct l_genl_family;

const struct l_settings *iwd_get_config(void);
struct l_genl *iwd_get_genl(void);

bool netdev_init(void);
void netdev_exit(void);
void netdev_set_nl80211(struct l_genl_family *nl80211);
void netdev_shutdown(void);

bool device_init(void);
void device_exit(void);

bool station_init(void);
void station_exit(void);

bool manager_init(struct l_genl_family *in,
			const char *if_whitelist, const char *if_blacklist);
void manager_exit(void);

struct iwd_module_desc {
	const char *name;
	int (*init)(void);
	void (*exit)(void);
	bool active;
} __attribute__((aligned(8)));

#define IWD_MODULE(name, init, exit)					\
	static struct iwd_module_desc __iwd_module_ ## name		\
		__attribute__((used, section("__iwd_module"), aligned(8))) = {\
			#name, init, exit				\
		};
