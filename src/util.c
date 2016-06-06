/*
 *
 *  Wireless daemon for Linux
 *
 *  Copyright (C) 2014  Intel Corporation. All rights reserved.
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

#include <string.h>
#include <stdio.h>

#include <ell/string.h>
#include <ell/genl.h>
#include <ell/util.h>
#include <ell/log.h>

#include "util.h"

const char *util_ssid_to_utf8(size_t len, const uint8_t *ssid)
{
	static char buf[3* 32 + 1];
	size_t i = 0, pos = 0;
	const uint8_t *start = ssid, *end;

	memset(buf, 0, sizeof(buf));

	if (len > 32)
		goto no_ssid;

	while (i < len && !ssid[i])
		i++;

	if (i == len)
		goto no_ssid;

	i = len;

	while (i && (!l_utf8_validate((const char *)start, i,
						(const char **)&end))) {
		const char replacement[] = { 0xEF, 0xBF, 0xBD };
		int bytes = end - start;

		memcpy(&buf[pos], start, bytes);
		pos += bytes;

		memcpy(&buf[pos], replacement, sizeof(replacement));
		pos += sizeof(replacement);

		start = end + 1;
		i -= (bytes + 1);
	}

	if (i) {
		memcpy(&buf[pos], start, i);
		pos += i;
	}

no_ssid:
	buf[pos] = '\0';

	return buf;
}

bool util_ssid_is_utf8(size_t len, const uint8_t *ssid)
{
	if (len > 32)
		return false;

	return l_utf8_validate((const char *)ssid, len, NULL);
}

const char *util_address_to_string(const uint8_t *addr)
{
	static char str[18];

	sprintf(str, "%02x:%02x:%02x:%02x:%02x:%02x",
			addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);

	return str;
}

bool _msg_append_attr(struct l_genl_msg *msg,
			uint16_t type, const char *type_str,
			uint16_t len, const void *value)
{
	bool ret;

	ret = l_genl_msg_append_attr(msg, type, len, value);
	if (!ret)
		l_warn("Cannot append attr %s", type_str);

	return ret;
}
