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

#include <stddef.h>
#include <stdbool.h>

enum crypto_cipher {
	CRYPTO_CIPHER_WEP40,
	CRYPTO_CIPHER_WEP104,
	CRYPTO_CIPHER_TKIP,
	CRYPTO_CIPHER_CCMP,
	CRYPTO_CIPHER_BIP,
};

int crypto_cipher_key_len(enum crypto_cipher cipher);
int crypto_cipher_tk_bits(enum crypto_cipher cipher);

int crypto_psk_from_passphrase(const char *passphrase,
				const unsigned char *ssid, size_t ssid_len,
				unsigned char *out_psk);

bool crypto_derive_ptk(const uint8_t *pmk, size_t pmk_len, const char *label,
			const uint8_t *addr1, const uint8_t *addr2,
			const uint8_t *nonce1, const uint8_t *nonce2,
			uint8_t *out_ptk, size_t ptk_len);
