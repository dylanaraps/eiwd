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

static bool hmac_common(enum l_checksum_type type,
		const void *key, size_t key_len,
                const void *data, size_t data_len, void *output, size_t size)
{
	struct l_checksum *hmac;

	hmac = l_checksum_new_hmac(type, key, key_len);
	if (!hmac)
		return false;

	l_checksum_update(hmac, data, data_len);
	l_checksum_get_digest(hmac, output, size);
	l_checksum_free(hmac);

	return true;
}

bool hmac_md5(const void *key, size_t key_len,
		const void *data, size_t data_len, void *output, size_t size)
{
	return hmac_common(L_CHECKSUM_MD5, key, key_len, data, data_len,
				output, size);
}

bool hmac_sha1(const void *key, size_t key_len,
		const void *data, size_t data_len, void *output, size_t size)
{
	return hmac_common(L_CHECKSUM_SHA1, key, key_len, data, data_len,
				output, size);
}

bool hmac_sha256(const void *key, size_t key_len,
		const void *data, size_t data_len, void *output, size_t size)
{
	return hmac_common(L_CHECKSUM_SHA256, key, key_len, data, data_len,
				output, size);
}

bool cmac_aes(const void *key, size_t key_len,
		const void *data, size_t data_len, void *output, size_t size)
{
	struct l_checksum *cmac_aes;

	cmac_aes = l_checksum_new_cmac_aes(key, key_len);
	if (!cmac_aes)
		return false;

	l_checksum_update(cmac_aes, data, data_len);
	l_checksum_get_digest(cmac_aes, output, size);
	l_checksum_free(cmac_aes);

	return true;
}

/*
 * Implements AES Key-Unwrap from RFC 3394
 *
 * The key is specified using @kek.  @in contains the encrypted data and @len
 * contains its length.  @out will contain the decrypted data.  The result
 * will be (len - 8) bytes.
 *
 * Returns: true on success, false if an IV mismatch has occurred.
 *
 * NOTE: Buffers @in and @out can overlap
 */
bool aes_unwrap(const uint8_t *kek, const uint8_t *in, size_t len,
			uint8_t *out)
{
	uint8_t a[8], b[16];
	uint8_t *r;
	size_t n = (len - 8) >> 3;
	int i, j;
	struct l_cipher *cipher;

	cipher = l_cipher_new(L_CIPHER_AES, kek, 16);
	if (!cipher)
		return false;

	/* Set up */
	memcpy(a, in, 8);
	memmove(out, in + 8, n * 8);

	/* Unwrap */
	for (j = 5; j >= 0; j--) {
		r = out + (n - 1) * 8;

		for (i = n; i >= 1; i--) {
			memcpy(b, a, 8);
			memcpy(b + 8, r, 8);
			b[7] ^= n * j + i;
			l_cipher_decrypt(cipher, b, b, 16);
			memcpy(a, b, 8);
			memcpy(r, b + 8, 8);
			r -= 8;
		}
	}

	l_cipher_free(cipher);

	/* Check IV */
	for (i = 0; i < 8; i++)
		if (a[i] != 0xA6)
			return false;

	return true;
}

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

bool prf_sha1(const void *key, size_t key_len,
		const void *prefix, size_t prefix_len,
		const void *data, size_t data_len, void *output, size_t size)
{
	struct l_checksum *hmac;
	unsigned int i, offset = 0;
	unsigned char empty = '\0';
	unsigned char counter;
	struct iovec iov[4] = {
		[0] = { .iov_base = (void *) prefix, .iov_len = prefix_len },
		[1] = { .iov_base = &empty, .iov_len = 1 },
		[2] = { .iov_base = (void *) data, .iov_len = data_len },
		[3] = { .iov_base = &counter, .iov_len = 1 },
	};

	hmac = l_checksum_new_hmac(L_CHECKSUM_SHA1, key, key_len);
	if (!hmac)
		return false;

	/* PRF processes in 160-bit chunks (20 bytes) */
	for (i = 0, counter = 0; i < (size + 19) / 20; i++, counter++) {
		size_t len;

		if (size - offset > 20)
			len = 20;
		else
			len = size - offset;

		l_checksum_updatev(hmac, iov, 4);
		l_checksum_get_digest(hmac, output + offset, len);

		offset += len;
	}

	l_checksum_free(hmac);

	return true;
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

bool crypto_derive_pairwise_ptk(const uint8_t *pmk,
				const uint8_t *addr1, const uint8_t *addr2,
				const uint8_t *nonce1, const uint8_t *nonce2,
				struct crypto_ptk *out_ptk, size_t ptk_len)
{
	return crypto_derive_ptk(pmk, 32, "Pairwise key expansion",
					addr1, addr2, nonce1, nonce2,
					(uint8_t *) out_ptk, ptk_len);
}
