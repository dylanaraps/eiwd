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

#include <string.h>
#include <ell/ell.h>

#include "src/sha1.h"

#define SHA1_MAC_LEN 20

static void __hmac_sha1(struct l_checksum *checksum,
					const void *key, size_t key_len,
					const void *data, size_t data_len,
					void *output, size_t size)
{
	unsigned char ipad[64];
	unsigned char opad[64];
	unsigned char digest[SHA1_MAC_LEN];
	int i;

	/* if key is longer than 64 bytes reset it to key=SHA1(key) */
	if (key_len > 64) {
		l_checksum_update(checksum, key, key_len);
		l_checksum_get_digest(checksum, digest, SHA1_MAC_LEN);

		key = digest;
		key_len = SHA1_MAC_LEN;
	}

	/* start out by storing key in pads */
	memset(ipad, 0, sizeof(ipad));
	memset(opad, 0, sizeof(opad));
	memcpy(ipad, key, key_len);
	memcpy(opad, key, key_len);

	/* XOR key with ipad and opad values */
	for (i = 0; i < 64; i++) {
		ipad[i] ^= 0x36;
		opad[i] ^= 0x5c;
	}

	/* perform inner SHA1 */
	l_checksum_update(checksum, ipad, sizeof(ipad));
	l_checksum_update(checksum, data, data_len);
	l_checksum_get_digest(checksum, digest, SHA1_MAC_LEN);

	/* perform outer SHA1 */
	l_checksum_update(checksum, opad, sizeof(opad));
	l_checksum_update(checksum, digest, SHA1_MAC_LEN);
	l_checksum_get_digest(checksum, output,
				size > SHA1_MAC_LEN ? SHA1_MAC_LEN : size);
}

static void F(struct l_checksum *checksum,
			const char *password, size_t password_len,
			const char *salt, size_t salt_len,
			unsigned int iterations, unsigned int count,
							unsigned char *digest)
{
	unsigned char tmp1[SHA1_MAC_LEN];
	unsigned char tmp2[SHA1_MAC_LEN];
	unsigned char buf[36];
	unsigned int i, j;

	memcpy(buf, salt, salt_len);
	buf[salt_len + 0] = (count >> 24) & 0xff;
	buf[salt_len + 1] = (count >> 16) & 0xff;
	buf[salt_len + 2] = (count >> 8) & 0xff;
	buf[salt_len + 3] = count & 0xff;

	__hmac_sha1(checksum, password, password_len,
					buf, salt_len + 4, tmp1, SHA1_MAC_LEN);
	memcpy(digest, tmp1, SHA1_MAC_LEN);

	for (i = 1; i < iterations; i++) {
		__hmac_sha1(checksum, password, password_len,
					tmp1, SHA1_MAC_LEN, tmp2, SHA1_MAC_LEN);
		memcpy(tmp1, tmp2, SHA1_MAC_LEN);

		for (j = 0; j < SHA1_MAC_LEN; j++)
			digest[j] ^= tmp2[j];
	}
}

bool pbkdf2_sha1(const void *password, size_t password_len,
			const void *salt, size_t salt_len,
			unsigned int iterations, void *output, size_t size)
{
	struct l_checksum *checksum;
	unsigned char *ptr = output;
	unsigned char digest[SHA1_MAC_LEN];
	unsigned int i;

	checksum = l_checksum_new(L_CHECKSUM_SHA1);
	if (!checksum)
		return false;

	for (i = 1; size > 0; i++) {
		size_t len;

		F(checksum, password, password_len, salt, salt_len,
						iterations, i, digest);

		len = size > SHA1_MAC_LEN ? SHA1_MAC_LEN : size;
		memcpy(ptr, digest, len);

		ptr += len;
		size -= len;
	}

	l_checksum_free(checksum);

	return true;
}

bool prf_sha1(const void *key, size_t key_len,
		const void *prefix, size_t prefix_len,
		const void *data, size_t data_len, void *output, size_t size)
{
	struct l_checksum *checksum;
	unsigned char input[1024];
	size_t input_len;
	unsigned int i, offset = 0;

	checksum = l_checksum_new(L_CHECKSUM_SHA1);
	if (!checksum)
		return false;

	memcpy(input, prefix, prefix_len);
	input[prefix_len] = 0;

	memcpy(input + prefix_len + 1, data, data_len);
	input[prefix_len + 1 + data_len] = 0;

	input_len = prefix_len + 1 + data_len + 1;

	for (i = 0; i < (size + 19) / 20; i++) {
		size_t len;

		if (size - offset > SHA1_MAC_LEN)
			len = SHA1_MAC_LEN;
		else
			len = size - offset;

		__hmac_sha1(checksum, key, key_len, input, input_len,
							output + offset, len);

		offset += len;
		input[input_len - 1]++;
	}

	l_checksum_free(checksum);

	return true;
}
