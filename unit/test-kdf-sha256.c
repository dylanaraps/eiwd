/*
 *
 *  Wireless daemon for Linux
 *
 *  Copyright (C) 2013-2016  Intel Corporation. All rights reserved.
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

struct kdf_data {
	const char *key;
	unsigned int key_len;
	const char *prefix;
	unsigned int prefix_len;
	const char *data;
	unsigned int data_len;
	const char *kdf;
};

static void kdf_test(const void *data)
{
	const struct kdf_data *test = data;
	unsigned int kdf_len;
	unsigned char output[512];
	char kdf[128];
	unsigned int i;
	bool result;

	kdf_len = strlen(test->kdf) / 2;

	printf("PRF    = %s (%d octects)\n", test->kdf, kdf_len);

	result = kdf_sha256(test->key, test->key_len, test->prefix,
				test->prefix_len, test->data, test->data_len,
						output, kdf_len);

	assert(result == true);

	for (i = 0; i < kdf_len; i++)
		sprintf(kdf + (i * 2), "%02x", output[i]);

	printf("Result = %s\n", kdf);

	assert(strcmp(test->kdf, kdf) == 0);
}

static const struct kdf_data test_case_1 = {
	.key		= "abc",
	.key_len	= 3,
	.prefix		= "KDF test",
	.prefix_len	= 8,
	.data		= "data",
	.data_len	= 4,
	.kdf		= "9efd6eb02758cb73"
			  "70a86f8a305375d4"
			  "1f8f21c2e47447f5"
			  "84f7d2291143d4d4",
};

int main(int argc, char *argv[])
{
	l_test_init(&argc, &argv);

	if (!l_checksum_is_supported(L_CHECKSUM_SHA256, true)) {
		printf("SHA256 support missing, skipping...\n");
		goto done;
	}

	l_test_add("/kdf-sha256/Test case 1", kdf_test, &test_case_1);

done:
	return l_test_run();
}
