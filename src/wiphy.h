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

#include <stdint.h>
#include <stdbool.h>

struct wiphy;
struct scan_bss;

enum ie_rsn_cipher_suite wiphy_select_cipher(struct wiphy *wiphy,
							uint16_t mask);

struct wiphy *wiphy_find(int wiphy_id);

const char *wiphy_get_path(struct wiphy *wiphy);
uint32_t wiphy_get_supported_bands(struct wiphy *wiphy);
bool wiphy_can_connect(struct wiphy *wiphy, struct scan_bss *bss);
bool wiphy_get_ext_feature(struct wiphy *wiphy, unsigned int idx);

bool wiphy_init(struct l_genl_family *in, const char *whitelist,
							const char *blacklist);
bool wiphy_exit(void);
