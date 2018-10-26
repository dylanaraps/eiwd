/*
 *
 *  Wireless daemon for Linux
 *
 *  Copyright (C) 2018  Intel Corporation. All rights reserved.
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

#include <ell/ell.h>

#include "src/mschaputil.h"

static bool mschap_des_encrypt(const uint8_t *challenge, const uint8_t *key,
							uint8_t *cipher_text)
{
	uint8_t pkey[8], tmp;
	int i;
	struct l_cipher *cipher;
	uint8_t next;

	for (i = 0, next = 0; i < 7; ++i) {
		tmp = key[i];
		pkey[i] = (tmp >> i) | next | 1;
		next = tmp << (7 - i);
	}

	pkey[i] = next | 1;

	cipher = l_cipher_new(L_CIPHER_DES, pkey, 8);
	if (!cipher)
		return false;

	l_cipher_encrypt(cipher, challenge, cipher_text, 8);
	l_cipher_free(cipher);

	return true;
}

bool mschap_challenge_response(const uint8_t *challenge,
				const uint8_t *password_hash, uint8_t *response)
{
	uint8_t buf[21];

	memset(buf, 0, sizeof(buf));
	memcpy(buf, password_hash, 16);

	if (!mschap_des_encrypt(challenge, buf + 0, response + 0))
		return false;

	if (!mschap_des_encrypt(challenge, buf + 7, response + 8))
		return false;

	if (!mschap_des_encrypt(challenge, buf + 14, response + 16))
		return false;

	return true;
}

bool mschap_nt_password_hash(const char *password, uint8_t *password_hash)
{
	size_t size = l_utf8_strlen(password);
	size_t bsize = strlen(password);
	uint16_t buffer[size];
	unsigned int i, pos;
	struct l_checksum *check;

	for (i = 0, pos = 0; i < size; ++i) {
		wchar_t val;

		pos += l_utf8_get_codepoint(password + pos, bsize - pos, &val);

		if (val > 0xFFFF) {
			l_error("Encountered password with value not valid in "
								"ucs-2");
			return false;
		}

		buffer[i] = L_CPU_TO_LE16(val);
	}

	check = l_checksum_new(L_CHECKSUM_MD4);
	if (!check)
		return false;

	l_checksum_update(check, (uint8_t *) buffer, size * 2);
	l_checksum_get_digest(check, password_hash, 16);
	l_checksum_free(check);

	return true;
}
