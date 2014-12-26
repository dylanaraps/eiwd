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

#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <linux/if_ether.h>

#include <ell/ell.h>

#include "sha1.h"
#include "crypto.h"

/* 802.11, Section 11.6.2, Table 11-4 */
int crypto_cipher_key_len(enum crypto_cipher cipher)
{
	switch (cipher) {
	case CRYPTO_CIPHER_WEP40:
		return 5;
	case CRYPTO_CIPHER_WEP104:
		return 13;
	case CRYPTO_CIPHER_TKIP:
		return 32;
	case CRYPTO_CIPHER_CCMP:
		return 16;
	case CRYPTO_CIPHER_BIP:
		return 16;
	};

	return 0;
}

int crypto_cipher_tk_bits(enum crypto_cipher cipher)
{
	return crypto_cipher_key_len(cipher) * 8;
}

int crypto_psk_from_passphrase(const char *passphrase,
				const unsigned char *ssid, size_t ssid_len,
				unsigned char *out_psk)
{
	size_t passphrase_len;
	size_t i;
	bool result;
	unsigned char psk[32];

	if (!passphrase)
		return -EINVAL;

	if (!ssid)
		return -EINVAL;

	/*
	 * IEEE 802.11, Annex M, Section M.4.1:
	 * "A pass-phrase is a sequence of between 8 and 63 ASCII-encoded
	 * characters. The limit of 63 comes from the desire to distinguish
	 * between a pass-phrase and a PSK displayed as 64 hexadecimal
	 * characters."
	 */
	passphrase_len = strlen(passphrase);
	if (passphrase_len < 8 || passphrase_len > 63)
		return -ERANGE;

	if (ssid_len == 0 || ssid_len > 32)
		return -ERANGE;

	/* IEEE 802.11, Annex M, Section M.4.1:
	 * "Each character in the pass-phrase must have an encoding in the
	 * range of 32 to 126 (decimal), inclusive."
	 *
	 * This corresponds to printable characters only
	 */
	for (i = 0; i < passphrase_len; i++) {
		if (l_ascii_isprint(passphrase[i]))
			continue;

		return -EINVAL;
	}

	result = pbkdf2_sha1(passphrase, passphrase_len, ssid, ssid_len,
				4096, psk, sizeof(psk));
	if (!result)
		return -ENOKEY;

	if (out_psk)
		memcpy(out_psk, psk, sizeof(psk));

	return 0;
}

/*
 * 802.11, Section 11.6.6.7:
 * PTK = PRF-X(PMK, "Pairwise key expansion", Min(AA, SA) || Max(AA, SA) ||
 *		Min(ANonce, SNonce) || Max(ANonce, SNonce))
 *
 * 802.11, Section 11.6.1.3:
 * The PTK shall be derived from the PMK by
 *  PTK ← PRF-X(PMK, “Pairwise key expansion”, Min(AA,SPA) || Max(AA,SPA) ||
 *		Min(ANonce,SNonce) || Max(ANonce,SNonce))
 * where X = 256 + TK_bits. The value of TK_bits is cipher-suite dependent and
 * is defined in Table 11-4. The Min and Max operations for IEEE 802 addresses
 * are with the address converted to a positive integer treating the first
 * transmitted octet as the most significant octet of the integer. The Min and
 * Max operations for nonces are with the nonces treated as positive integers
 * converted as specified in 8.2.2.
 */
bool crypto_derive_ptk(const uint8_t *pmk, size_t pmk_len, const char *label,
			const uint8_t *addr1, const uint8_t *addr2,
			const uint8_t *nonce1, const uint8_t *nonce2,
			uint8_t *out_ptk, size_t ptk_len)
{
	/* Nonce length is 32 */
	uint8_t data[ETH_ALEN * 2 + 64];
	size_t pos = 0;

	/* Address 1 is less than Address 2 */
	if (memcmp(addr1, addr2, ETH_ALEN) < 0) {
		memcpy(data, addr1, ETH_ALEN);
		memcpy(data + ETH_ALEN, addr2, ETH_ALEN);
	} else {
		memcpy(data, addr2, ETH_ALEN);
		memcpy(data + ETH_ALEN, addr1, ETH_ALEN);
	}

	pos += ETH_ALEN * 2;

	/* Nonce1 is less than Nonce2 */
	if (memcmp(nonce1, nonce2, 32) < 0) {
		memcpy(data + pos, nonce1, 32);
		memcpy(data + pos + 32, nonce2, 32);
	} else {
		memcpy(data + pos, nonce2, 32);
		memcpy(data + pos + 32, nonce1, 32);
	}

	pos += 64;

	return prf_sha1(pmk, pmk_len, label, strlen(label),
			data, sizeof(data), out_ptk, ptk_len);
}
