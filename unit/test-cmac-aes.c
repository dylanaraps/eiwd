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

#include "src/crypto.h"

struct cmac_data {
	const void *key;
	size_t key_len;
	const void *msg;
	size_t msg_len;
	const unsigned char *tag;
	size_t tag_len;
};

static void cmac_test(const void *data)
{
	const struct cmac_data *test = data;
	unsigned char tag[test->tag_len];
	char tag_str[test->tag_len * 2 + 1];
	unsigned int i;
	bool result;

	for (i = 0; i < test->tag_len; i++)
		sprintf(tag_str + (i * 2), "%02x", test->tag[i]);

	printf("Tag    = %s (%zu octects)\n", tag_str, test->tag_len);

	result = cmac_aes(test->key, test->key_len,
				test->msg, test->msg_len, tag, test->tag_len);

	assert(result == true);

	for (i = 0; i < test->tag_len; i++)
		sprintf(tag_str + (i * 2), "%02x", tag[i]);

	printf("Result = %s\n", tag_str);

	assert(memcmp(test->tag, tag, test->tag_len) == 0);
}

static const unsigned char key[16] = {
			0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
			0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
};

static const unsigned char msg[64] = {
			0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
			0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
			0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
			0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
			0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11,
			0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
			0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17,
			0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10,
};

static const unsigned char tag_1[16] = {
			0xbb, 0x1d, 0x69, 0x29, 0xe9, 0x59, 0x37, 0x28,
			0x7f, 0xa3, 0x7d, 0x12, 0x9b, 0x75, 0x67, 0x46,
};

static const unsigned char tag_2[16] = {
			0x07, 0x0a, 0x16, 0xb4, 0x6b, 0x4d, 0x41, 0x44,
			0xf7, 0x9b, 0xdd, 0x9d, 0xd0, 0x4a, 0x28, 0x7c,
};

static const unsigned char tag_3[16] = {
			0xdf, 0xa6, 0x67, 0x47, 0xde, 0x9a, 0xe6, 0x30,
			0x30, 0xca, 0x32, 0x61, 0x14, 0x97, 0xc8, 0x27,
};

static const unsigned char tag_4[16] = {
			0x51, 0xf0, 0xbe, 0xbf, 0x7e, 0x3b, 0x9d, 0x92,
			0xfc, 0x49, 0x74, 0x17, 0x79, 0x36, 0x3c, 0xfe,
};

static const struct cmac_data example_1 = {
	.key		= key,
	.key_len	= sizeof(key),
	.msg		= msg,
	.msg_len	= 0,
	.tag		= tag_1,
	.tag_len	= sizeof(tag_1),
};

static const struct cmac_data example_2 = {
	.key		= key,
	.key_len	= sizeof(key),
	.msg		= msg,
	.msg_len	= 16,
	.tag		= tag_2,
	.tag_len	= sizeof(tag_2),
};

static const struct cmac_data example_3 = {
	.key		= key,
	.key_len	= sizeof(key),
	.msg		= msg,
	.msg_len	= 40,
	.tag		= tag_3,
	.tag_len	= sizeof(tag_3),
};

static const struct cmac_data example_4 = {
	.key		= key,
	.key_len	= sizeof(key),
	.msg		= msg,
	.msg_len	= 64,
	.tag		= tag_4,
	.tag_len	= sizeof(tag_4),
};

int main(int argc, char *argv[])
{
	l_test_init(&argc, &argv);

	if (!l_checksum_cmac_aes_supported()) {
		printf("AES-CMAC support missing, skipping...\n");
		goto done;
	}

	l_test_add("/cmac-aes/Example 1", cmac_test, &example_1);
	l_test_add("/cmac-aes/Example 2", cmac_test, &example_2);
	l_test_add("/cmac-aes/Exmaple 3", cmac_test, &example_3);
	l_test_add("/cmac-aes/Exmaple 4", cmac_test, &example_4);

done:
	return l_test_run();
}
