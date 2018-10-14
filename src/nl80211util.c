/*
 *
 *  Wireless daemon for Linux
 *
 *  Copyright (C) 2018 Intel Corporation. All rights reserved.
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

#include <linux/if_ether.h>
#include <ell/ell.h>

#include "linux/nl80211.h"

#include "src/nl80211util.h"

struct l_genl_msg *nl80211_build_new_key_group(uint32_t ifindex, uint32_t cipher,
					uint8_t key_id, const uint8_t *key,
					size_t key_len, const uint8_t *ctr,
					size_t ctr_len, const uint8_t *addr)
{
	struct l_genl_msg *msg;

	msg = l_genl_msg_new_sized(NL80211_CMD_NEW_KEY, 512);

	l_genl_msg_append_attr(msg, NL80211_ATTR_IFINDEX, 4, &ifindex);

	if (addr)
		l_genl_msg_append_attr(msg, NL80211_ATTR_MAC, ETH_ALEN, addr);

	l_genl_msg_enter_nested(msg, NL80211_ATTR_KEY);
	l_genl_msg_append_attr(msg, NL80211_KEY_DATA, key_len, key);
	l_genl_msg_append_attr(msg, NL80211_KEY_CIPHER, 4, &cipher);
	l_genl_msg_append_attr(msg, NL80211_KEY_IDX, 1, &key_id);

	if (ctr)
		l_genl_msg_append_attr(msg, NL80211_KEY_SEQ, ctr_len, ctr);

	if (addr) {
		uint32_t type = NL80211_KEYTYPE_GROUP;

		l_genl_msg_append_attr(msg, NL80211_KEY_TYPE, 4, &type);
		l_genl_msg_enter_nested(msg, NL80211_KEY_DEFAULT_TYPES);
		l_genl_msg_append_attr(msg, NL80211_KEY_DEFAULT_TYPE_MULTICAST,
					0, NULL);
		l_genl_msg_leave_nested(msg);
	}

	l_genl_msg_leave_nested(msg);

	return msg;
}

static struct l_genl_msg *nl80211_build_set_station(uint32_t ifindex,
					const uint8_t *addr,
					struct nl80211_sta_flag_update *flags)
{
	struct l_genl_msg *msg;

	msg = l_genl_msg_new_sized(NL80211_CMD_SET_STATION, 512);

	l_genl_msg_append_attr(msg, NL80211_ATTR_IFINDEX, 4, &ifindex);
	l_genl_msg_append_attr(msg, NL80211_ATTR_MAC, ETH_ALEN, addr);
	l_genl_msg_append_attr(msg, NL80211_ATTR_STA_FLAGS2,
				sizeof(struct nl80211_sta_flag_update), flags);

	return msg;
}

struct l_genl_msg *nl80211_build_set_station_authorized(uint32_t ifindex,
							const uint8_t *addr)
{
	struct nl80211_sta_flag_update flags = {
		.mask = (1 << NL80211_STA_FLAG_AUTHORIZED),
		.set = (1 << NL80211_STA_FLAG_AUTHORIZED),
	};

	return nl80211_build_set_station(ifindex, addr, &flags);
}

struct l_genl_msg *nl80211_build_set_station_associated(uint32_t ifindex,
							const uint8_t *addr)
{
	struct nl80211_sta_flag_update flags = {
		.mask = (1 << NL80211_STA_FLAG_AUTHENTICATED) |
			(1 << NL80211_STA_FLAG_ASSOCIATED),
		.set = (1 << NL80211_STA_FLAG_AUTHENTICATED) |
			(1 << NL80211_STA_FLAG_ASSOCIATED),
	};

	return nl80211_build_set_station(ifindex, addr, &flags);
}

struct l_genl_msg *nl80211_build_set_station_unauthorized(uint32_t ifindex,
							const uint8_t *addr)
{
	struct nl80211_sta_flag_update flags = {
		.mask = (1 << NL80211_STA_FLAG_AUTHORIZED),
		.set = 0,
	};

	return nl80211_build_set_station(ifindex, addr, &flags);
}

struct l_genl_msg *nl80211_build_set_key(uint32_t ifindex, uint8_t key_index)
{
	struct l_genl_msg *msg;

	msg = l_genl_msg_new_sized(NL80211_CMD_SET_KEY, 128);

	l_genl_msg_append_attr(msg, NL80211_ATTR_IFINDEX, 4, &ifindex);

	l_genl_msg_enter_nested(msg, NL80211_ATTR_KEY);
	l_genl_msg_append_attr(msg, NL80211_KEY_IDX, 1, &key_index);
	l_genl_msg_append_attr(msg, NL80211_KEY_DEFAULT, 0, NULL);
	l_genl_msg_enter_nested(msg, NL80211_KEY_DEFAULT_TYPES);
	l_genl_msg_append_attr(msg, NL80211_KEY_DEFAULT_TYPE_MULTICAST,
				0, NULL);
	l_genl_msg_leave_nested(msg);
	l_genl_msg_leave_nested(msg);

	return msg;
}

struct l_genl_msg *nl80211_build_get_key(uint32_t ifindex, uint8_t key_index)
{
	struct l_genl_msg *msg;

	msg = l_genl_msg_new_sized(NL80211_CMD_GET_KEY, 128);

	l_genl_msg_append_attr(msg, NL80211_ATTR_IFINDEX, 4, &ifindex);
	l_genl_msg_append_attr(msg, NL80211_ATTR_KEY_IDX, 1, &key_index);

	return msg;
}

const void *nl80211_parse_get_key_seq(struct l_genl_msg *msg)
{
	struct l_genl_attr attr, nested;
	uint16_t type, len;
	const void *data;

	if (l_genl_msg_get_error(msg) < 0 || !l_genl_attr_init(&attr, msg)) {
		l_error("GET_KEY failed for the GTK: %i",
			l_genl_msg_get_error(msg));
		return NULL;
	}

	while (l_genl_attr_next(&attr, &type, &len, &data)) {
		if (type != NL80211_ATTR_KEY)
			continue;

		break;
	}

	if (type != NL80211_ATTR_KEY || !l_genl_attr_recurse(&attr, &nested)) {
		l_error("Can't recurse into ATTR_KEY in GET_KEY reply");
		return NULL;
	}

	while (l_genl_attr_next(&nested, &type, &len, &data)) {
		if (type != NL80211_KEY_SEQ)
			continue;

		break;
	}

	if (type != NL80211_KEY_SEQ) {
		l_error("KEY_SEQ not returned in GET_KEY reply");
		return NULL;
	}

	if (len != 6) {
		l_error("KEY_SEQ length != 6 in GET_KEY reply");
		return NULL;
	}

	return data;
}
