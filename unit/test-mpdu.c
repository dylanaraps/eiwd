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

#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <ell/ell.h>

#include "src/mpdu.h"

struct deauthentication_data {
	const unsigned char *frame;
	size_t frame_len;
	uint16_t duration;
	const unsigned char dest[6];
	const unsigned char src[6];
	const unsigned char bssid[6];
	uint8_t fragment_number;
	uint16_t sequence_number;
};

static const unsigned char deauthentication_data_1[] = {
	0xc0, 0x00, 0x3a, 0x01, 0x00, 0x0f, 0xb5, 0x88,
	0xac, 0x82, 0x00, 0x14, 0x6c, 0x7e, 0x40, 0x80,
	0x00, 0x14, 0x6c, 0x7e, 0x40, 0x80, 0x70, 0x22,
	0x01, 0x00
};

static struct deauthentication_data deauthentication_test_1 = {
	.frame = deauthentication_data_1,
	.frame_len = sizeof(deauthentication_data_1),
	.duration = 314,
	.dest = { 0x00, 0x0f, 0xb5, 0x88, 0xac, 0x82 },
	.src = { 0x00, 0x14, 0x6c, 0x7e, 0x40, 0x80 },
	.bssid = { 0x00, 0x14, 0x6c, 0x7e, 0x40, 0x80 },
	.fragment_number = 0,
	.sequence_number = 551,
};

static void deauthentication_test(const void *data)
{
	const struct deauthentication_data *test = data;
	struct mpdu mpdu;
	bool ret;

	ret = mpdu_decode(test->frame, test->frame_len, &mpdu);
	assert(ret);
	assert(mpdu.fc.type == MPDU_TYPE_MANAGEMENT);
	assert(mpdu.fc.subtype == MPDU_MANAGEMENT_SUBTYPE_DEAUTHENTICATION);
	assert(mpdu.fc.protocol_version == 0x00);

	assert(mpdu.mgmt_hdr.duration == test->duration);
	assert(!memcmp(mpdu.mgmt_hdr.address_1, test->dest, 6));
	assert(!memcmp(mpdu.mgmt_hdr.address_2, test->src, 6));
	assert(!memcmp(mpdu.mgmt_hdr.address_3, test->bssid, 6));
	assert(mpdu.mgmt_hdr.fragment_number == test->fragment_number);
	assert(mpdu.mgmt_hdr.sequence_number == test->sequence_number);
}

int main(int argc, char *argv[])
{
	l_test_init(&argc, &argv);

	l_test_add("/Management Frame/Deathentication Frame 1",
			deauthentication_test, &deauthentication_test_1);

	return l_test_run();
}
