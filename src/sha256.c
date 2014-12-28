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

#include "src/sha256.h"

#define SHA256_MAC_LEN 32

static void __hmac_sha256(struct l_checksum *checksum,
					const void *key, size_t key_len,
					const void *data, size_t data_len,
					void *output, size_t size)
{
	unsigned char ipad[64];
	unsigned char opad[64];
	unsigned char digest[SHA256_MAC_LEN];
	int i;

	/* if key is longer than 64 bytes reset it to key=SHA256(key) */
	if (key_len > 64) {
		l_checksum_update(checksum, key, key_len);
		l_checksum_get_digest(checksum, digest, SHA256_MAC_LEN);

		l_checksum_reset(checksum);

		key = digest;
		key_len = SHA256_MAC_LEN;
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

	/* perform inner SHA256 */
	l_checksum_update(checksum, ipad, sizeof(ipad));
	l_checksum_update(checksum, data, data_len);
	l_checksum_get_digest(checksum, digest, SHA256_MAC_LEN);

	l_checksum_reset(checksum);

	/* perform outer SHA256 */
	l_checksum_update(checksum, opad, sizeof(opad));
	l_checksum_update(checksum, digest, SHA256_MAC_LEN);
	l_checksum_get_digest(checksum, output,
				size > SHA256_MAC_LEN ? SHA256_MAC_LEN : size);

	l_checksum_reset(checksum);
}

bool hmac_sha256(const void *key, size_t key_len,
                const void *data, size_t data_len, void *output, size_t size)
{
	struct l_checksum *checksum;

	checksum = l_checksum_new(L_CHECKSUM_SHA256);

	__hmac_sha256(checksum, key, key_len, data, data_len, output, size);

	l_checksum_free(checksum);

	return true;
}
