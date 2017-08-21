/*
 *
 *  Wireless daemon for Linux
 *
 *  Copyright (C) 2017  Intel Corporation. All rights reserved.
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

#include "src/simutil.h"

static uint8_t attr_data[] = {
		EAP_SIM_AT_RAND,		/* attribute type */
		0x02,				/* length (4 * 2) == 8 bytes */
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
		EAP_SIM_AT_AUTN,		/* next attribute */
		0x01,
		0x0f, 0x0f,
		EAP_SIM_AT_RES,			/* next attribute */
		0x03,
		0x09, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00
};

static void test_next_attribute(const void *data)
{
	struct eap_sim_tlv_iter iter;
	/* basic attribute iteration */
	uint8_t rand = 0, autn = 0, res = 0;

	eap_sim_tlv_iter_init(&iter, attr_data, sizeof(attr_data));

	while (eap_sim_tlv_iter_next(&iter)) {
		switch (iter.tag) {
		case EAP_SIM_AT_RAND:
			rand = 1;
			break;

		case EAP_SIM_AT_AUTN:
			autn = 1;
			break;

		case EAP_SIM_AT_RES:
			res = 1;
			break;

		default:
			assert(0);
		}
	}

	assert(rand && autn && res);
}

static void test_add_attribute(const void *data)
{
	uint8_t buf[100];
	char test[] = "test data";

	/* test EAP_SIM_PAD_NONE */
	eap_sim_add_attribute(buf, EAP_SIM_AT_RAND, EAP_SIM_PAD_NONE,
			(uint8_t *)test, strlen(test));
	/*
	 * Attribute should look like:
	 *
	 * buf[0] = AT_RAND
	 * buf[1] = 0x03
	 * buf[2 - 10] = "test data"
	 * buf[11] = 0x00	(padding)
	 */

	assert(buf[0] == EAP_SIM_AT_RAND);
	assert(buf[1] == 3);
	assert(!memcmp(buf + 2, test, 9));
	assert(buf[11] == 0);

	/* test EAP_SIM_PAD_ZERO */
	memset(buf, 0, sizeof(buf));
	eap_sim_add_attribute(buf, EAP_SIM_AT_RAND, EAP_SIM_PAD_ZERO,
			(uint8_t *)test, strlen(test));
	/*
	 * Attribute should look like:
	 *
	 * buf[0] = AT_RAND
	 * buf[1] = 0x04
	 * buf[2-3] = 0x0000
	 * buf[4-13] = "test data"
	 * buf[14-16] = 0x000000
	 */
	assert(buf[0] == EAP_SIM_AT_RAND);
	assert(buf[1] == 4);
	assert(buf[2] == 0 && buf[3] == 0);
	assert(!memcmp(buf + 4, test, strlen(test)));
	assert(buf[14] == 0 && buf[15] == 0 && buf[16] == 0);

	/* test EAP_SIM_PAD_LENGTH */
	memset(buf, 0, sizeof(buf));
	eap_sim_add_attribute(buf, EAP_SIM_AT_RAND, EAP_SIM_PAD_LENGTH,
			(uint8_t *)test, strlen(test));
	/*
	 * Attribute should look like:
	 *
	 * buf[0] = AT_RAND
	 * buf[1] = 0x04
	 * buf[2-3] = 0x0009
	 * buf[4-13] = "test data"
	 * buf[14-16] = 0x000000
	 */
	assert(buf[0] == EAP_SIM_AT_RAND);
	assert(buf[1] == 4);
	assert(buf[2] == 0x00 && buf[3] == 0x09);
	assert(!memcmp(buf + 4, test, strlen(test)));
	assert(buf[14] == 0 && buf[15] == 0 && buf[16] == 0);

	/* test EAP_SIM_PAD_LENGTH_BITS */
	memset(buf, 0, sizeof(buf));
	eap_sim_add_attribute(buf, EAP_SIM_AT_RAND, EAP_SIM_PAD_LENGTH_BITS,
			(uint8_t *)test, strlen(test));
	/*
	 * Attribute should look like:
	 *
	 * buf[0] = AT_RAND
	 * buf[1] = 0x04
	 * buf[2-3] = 0x0048
	 * buf[4-13] = "test data"
	 * buf[14-16] = 0x000000
	 */
	assert(buf[0] == EAP_SIM_AT_RAND);
	assert(buf[1] == 4);
	assert(buf[2] == 0x00 && buf[3] == 0x48);
	assert(!memcmp(buf + 4, test, strlen(test)));
	assert(buf[14] == 0 && buf[15] == 0 && buf[16] == 0);
}

static uint8_t ex_pkt[] = {
		0x02, 0x02, 0x00, 0x1c, 0x12, 0x0b, 0x00, 0x00, 0x0b, 0x05,
		0x00, 0x00, 0xf5, 0x6d, 0x64, 0x33, 0xe6, 0x8e, 0xd2, 0x97,
		0x6a, 0xc1, 0x19, 0x37, 0xfc, 0x3d, 0x11, 0x54 };

static uint8_t ex_mac[] = {
		0xf5, 0x6d, 0x64, 0x33, 0xe6, 0x8e, 0xd2, 0x97,
		0x6a, 0xc1, 0x19, 0x37, 0xfc, 0x3d, 0x11, 0x54 };

static uint8_t ex_sres[] = {
		0xd1, 0xd2, 0xd3, 0xd4,
		0xe1, 0xe2, 0xe3, 0xe4,
		0xf1, 0xf2, 0xf3, 0xf4 };

static uint8_t ex_k_aut[] = {
		0x25, 0xaf, 0x19, 0x42, 0xef, 0xcb, 0xf4, 0xbc,
		0x72, 0xb3, 0x94, 0x34, 0x21, 0xf2, 0xa9, 0x74 };

static void test_calc_mac(const void *data)
{
	uint8_t pkt[100];
	uint8_t pos = 0;

	/* header */
	memcpy(pkt, ex_pkt, 8);
	pos += 8;
	/* add MAC attribute */
	pos += eap_sim_add_attribute(pkt + 8, EAP_SIM_AT_MAC, EAP_SIM_PAD_ZERO,
			NULL, EAP_SIM_MAC_LEN);

	memcpy(pkt + pos, ex_sres, 12);

	eap_sim_derive_mac(pkt, sizeof(ex_pkt) + 12, ex_k_aut,
			pkt + pos - EAP_SIM_MAC_LEN);

	assert(!memcmp(ex_mac, pkt + pos - EAP_SIM_MAC_LEN, EAP_SIM_MAC_LEN));
	assert(!memcmp(ex_pkt, pkt, sizeof(ex_pkt)));
}

static uint8_t ex_mk[] = {
		0xe5, 0x76, 0xd5, 0xca, 0x33, 0x2e, 0x99, 0x30, 0x01, 0x8b,
		0xf1, 0xba, 0xee, 0x27, 0x63, 0xc7, 0x95, 0xb3, 0xc7, 0x12 };

static uint8_t ex_keys[] = {
		0x53, 0x6e, 0x5e, 0xbc, 0x44, 0x65, 0x58, 0x2a, 0xa6, 0xa8,
		0xec, 0x99, 0x86, 0xeb, 0xb6, 0x20, 0x25, 0xaf, 0x19, 0x42,
		0xef, 0xcb, 0xf4, 0xbc, 0x72, 0xb3, 0x94, 0x34, 0x21, 0xf2,
		0xa9, 0x74, 0x39, 0xd4, 0x5a, 0xea, 0xf4, 0xe3, 0x06, 0x01,
		0x98, 0x3e, 0x97, 0x2b, 0x6c, 0xfd, 0x46, 0xd1, 0xc3, 0x63,
		0x77, 0x33, 0x65, 0x69, 0x0d, 0x09, 0xcd, 0x44, 0x97, 0x6b,
		0x52, 0x5f, 0x47, 0xd3, 0xa6, 0x0a, 0x98, 0x5e, 0x95, 0x5c,
		0x53, 0xb0, 0x90, 0xb2, 0xe4, 0xb7, 0x37, 0x19, 0x19, 0x6a,
		0x40, 0x25, 0x42, 0x96, 0x8f, 0xd1, 0x4a, 0x88, 0x8f, 0x46,
		0xb9, 0xa7, 0x88, 0x6e, 0x44, 0x88, 0x59, 0x49, 0xea, 0xb0,
		0xff, 0xf6, 0x9d, 0x52, 0x31, 0x5c, 0x6c, 0x63, 0x4f, 0xd1,
		0x4a, 0x7f, 0x0d, 0x52, 0x02, 0x3d, 0x56, 0xf7, 0x96, 0x98,
		0xfa, 0x65, 0x96, 0xab, 0xee, 0xd4, 0xf9, 0x3f, 0xbb, 0x48,
		0xeb, 0x53, 0x4d, 0x98, 0x54, 0x14, 0xce, 0xed, 0x0d, 0x9a,
		0x8e, 0xd3, 0x3c, 0x38, 0x7c, 0x9d, 0xfd, 0xab, 0x92, 0xff,
		0xbd, 0xf2, 0x40, 0xfc, 0xec, 0xf6, 0x5a, 0x2c, 0x93, 0xb9 };

static void test_prng(const void *data)
{
	uint8_t prng_buf[160];

	eap_sim_fips_prf((uint8_t *)ex_mk, 20, prng_buf, sizeof(ex_keys));

	assert(!memcmp(prng_buf, (uint8_t *)ex_keys, sizeof(ex_keys)));
}

int main(int argc, char *argv[])
{
	l_test_init(&argc, &argv);

	l_test_add("EAP-SIM next attribute test", test_next_attribute, NULL);
	l_test_add("EAP-SIM add attribute test", test_add_attribute, NULL);
	l_test_add("EAP-SIM calculate MAC test", test_calc_mac, NULL);
	l_test_add("EAP-SIM PRNG test", test_prng, NULL);

	return l_test_run();
}
