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

struct hmac_data {
	const char *key;
	unsigned int key_len;
	const char *data;
	unsigned int data_len;
	const char *hmac;
};

static void hmac_test(const void *data)
{
	const struct hmac_data *test = data;
	unsigned int hmac_len;
	unsigned char output[512];
	char hmac[128];
	unsigned int i;
	bool result;

	hmac_len = strlen(test->hmac) / 2;

	printf("HMAC   = %s (%d octects)\n", test->hmac, hmac_len);

	result = hmac_sha256(test->key, test->key_len,
				test->data, test->data_len, output, hmac_len);

	assert(result == true);

	for (i = 0; i < hmac_len; i++)
		sprintf(hmac + (i * 2), "%02x", output[i]);

	printf("Result = %s\n", hmac);

	assert(strcmp(test->hmac, hmac) == 0);
}

static const struct hmac_data test_case_1 = {
	.key		= "",
	.key_len	= 0,
	.data		= "",
	.data_len	= 0,
	.hmac		= "b613679a0814d9ec772f95d778c35fc5"
			  "ff1697c493715653c6c712144292c5ad",
};

static const struct hmac_data test_case_2 = {
	.key		= "key",
	.key_len	= 3,
	.data		= "The quick brown fox jumps over the lazy dog",
	.data_len	= 43,
	.hmac		= "f7bc83f430538424b13298e6aa6fb143"
			  "ef4d59a14946175997479dbc2d1a3cd8",
};

int main(int argc, char *argv[])
{
	l_test_init(&argc, &argv);

	if (!l_checksum_is_supported(L_CHECKSUM_SHA256, true)) {
		printf("SHA256 support missing, skipping...\n");
		goto done;
	}

	l_test_add("/hmac-sha256/Test case 1", hmac_test, &test_case_1);
	l_test_add("/hmac-sha256/Test case 2", hmac_test, &test_case_2);

done:
	return l_test_run();
}
