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

#define _GNU_SOURCE
#include <ell/ell.h>

#include "src/arc4.h"

bool arc4_skip(const uint8_t *key, size_t key_len, size_t skip,
		const uint8_t *in, size_t len, uint8_t *out)
{
	char skip_buf[1024];
	struct l_cipher *cipher;

	cipher = l_cipher_new(L_CIPHER_ARC4, key, key_len);
	if (!cipher)
		return false;

	while (skip > 0) {
		size_t to_skip =
			skip > sizeof(skip_buf) ? sizeof(skip_buf) : skip;

		l_cipher_decrypt(cipher, skip_buf, skip_buf, to_skip);
		skip -= to_skip;
	}

	l_cipher_decrypt(cipher, in, out, len);
	l_cipher_free(cipher);

	return true;
}
