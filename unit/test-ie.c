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

#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>
#include <ell/ell.h>

#include "src/ie.h"

struct test_data {
	unsigned int num_ie;
	unsigned int len;
	unsigned char *buf;
};

struct ie {
	unsigned char type;
	unsigned char len;
	unsigned char value[];
} __attribute__ ((packed));

static void ie_test(const void *data)
{
	const struct test_data *test = data;
	struct ie_tlv_iter iter;
	struct ie *ie;
	int count = 0, pos = 0;

	ie_tlv_iter_init(&iter, test->buf, test->len);

	while (ie_tlv_iter_next(&iter)) {

		ie = (struct ie *)&test->buf[pos];
		printf("IE %d [%d/%d/%s]\n", count, ie->type, ie->len,
			l_util_hexstring(&test->buf[pos+2], ie->len));

		assert(iter.tag == test->buf[pos++]);
		assert(iter.len == test->buf[pos++]);
		assert(!memcmp(iter.data, test->buf + pos, iter.len));
		pos += ie->len;

		count++;
	}

	assert(count == test->num_ie);
}

static struct ie ie_ssid = {
	.type = IE_TYPE_SSID,
	.len = 10,
	.value = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9' },
};

static struct ie ie_supp_channels = {
	.type = IE_TYPE_SUPPORTED_CHANNELS,
	.len = 2,
	.value = "\x01\x02",
};

static struct ie ie_qos = {
	.type = IE_TYPE_QOS_CAPABILITY,
	.len = 1,
	.value = "\x81",
};

static unsigned char *append_data(unsigned char *buf, struct ie *ie,
				unsigned int *total_len)
{
	unsigned char *ptr;
	unsigned old, len = ie->len + 1 + 1;

	old = *total_len;
	*total_len += len;

	ptr = realloc(buf, *total_len);

	memcpy(ptr + old, ie, len);

	return ptr;
}

int main(int argc, char *argv[])
{
	struct test_data tc1;

	l_test_init(&argc, &argv);

	memset(&tc1, 0, sizeof(tc1));
	tc1.buf = append_data(tc1.buf, &ie_ssid, &tc1.len);
	tc1.num_ie++;
	tc1.buf = append_data(tc1.buf, &ie_supp_channels, &tc1.len);
	tc1.num_ie++;
	tc1.buf = append_data(tc1.buf, &ie_qos, &tc1.len);
	tc1.num_ie++;
	l_test_add("/ie/IE", ie_test, &tc1);

	return l_test_run();
}
