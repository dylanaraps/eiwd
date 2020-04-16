/*
 *
 *  Wireless daemon for Linux
 *
 *  Copyright (C) 2013-2019  Intel Corporation. All rights reserved.
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

#include "src/missing.h"
#include "src/crypto.h"

/* RFC 3526, Section 2 */
const unsigned char crypto_dh5_prime[] = {
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xc9, 0x0f, 0xda, 0xa2,
	0x21, 0x68, 0xc2, 0x34, 0xc4, 0xc6, 0x62, 0x8b, 0x80, 0xdc, 0x1c, 0xd1,
	0x29, 0x02, 0x4e, 0x08, 0x8a, 0x67, 0xcc, 0x74, 0x02, 0x0b, 0xbe, 0xa6,
	0x3b, 0x13, 0x9b, 0x22, 0x51, 0x4a, 0x08, 0x79, 0x8e, 0x34, 0x04, 0xdd,
	0xef, 0x95, 0x19, 0xb3, 0xcd, 0x3a, 0x43, 0x1b, 0x30, 0x2b, 0x0a, 0x6d,
	0xf2, 0x5f, 0x14, 0x37, 0x4f, 0xe1, 0x35, 0x6d, 0x6d, 0x51, 0xc2, 0x45,
	0xe4, 0x85, 0xb5, 0x76, 0x62, 0x5e, 0x7e, 0xc6, 0xf4, 0x4c, 0x42, 0xe9,
	0xa6, 0x37, 0xed, 0x6b, 0x0b, 0xff, 0x5c, 0xb6, 0xf4, 0x06, 0xb7, 0xed,
	0xee, 0x38, 0x6b, 0xfb, 0x5a, 0x89, 0x9f, 0xa5, 0xae, 0x9f, 0x24, 0x11,
	0x7c, 0x4b, 0x1f, 0xe6, 0x49, 0x28, 0x66, 0x51, 0xec, 0xe4, 0x5b, 0x3d,
	0xc2, 0x00, 0x7c, 0xb8, 0xa1, 0x63, 0xbf, 0x05, 0x98, 0xda, 0x48, 0x36,
	0x1c, 0x55, 0xd3, 0x9a, 0x69, 0x16, 0x3f, 0xa8, 0xfd, 0x24, 0xcf, 0x5f,
	0x83, 0x65, 0x5d, 0x23, 0xdc, 0xa3, 0xad, 0x96, 0x1c, 0x62, 0xf3, 0x56,
	0x20, 0x85, 0x52, 0xbb, 0x9e, 0xd5, 0x29, 0x07, 0x70, 0x96, 0x96, 0x6d,
	0x67, 0x0c, 0x35, 0x4e, 0x4a, 0xbc, 0x98, 0x04, 0xf1, 0x74, 0x6c, 0x08,
	0xca, 0x23, 0x73, 0x27, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
};
size_t crypto_dh5_prime_size = sizeof(crypto_dh5_prime);

const unsigned char crypto_dh5_generator[] = { 0x2 };
size_t crypto_dh5_generator_size = sizeof(crypto_dh5_generator);

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

bool hmac_sha384(const void *key, size_t key_len,
		const void *data, size_t data_len, void *output, size_t size)
{
	return hmac_common(L_CHECKSUM_SHA384, key, key_len, data, data_len,
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
bool aes_unwrap(const uint8_t *kek, size_t kek_len, const uint8_t *in, size_t len,
			uint8_t *out)
{
	uint64_t b[2];
	uint64_t *r;
	size_t n = (len - 8) >> 3;
	int i, j;
	struct l_cipher *cipher;
	uint64_t t = n * 6;

	cipher = l_cipher_new(L_CIPHER_AES, kek, kek_len);
	if (!cipher)
		return false;

	/* Set up */
	memcpy(b, in, 8);
	memmove(out, in + 8, n * 8);

	/* Unwrap */
	for (j = 5; j >= 0; j--) {
		r = (uint64_t *) out + n - 1;

		for (i = n; i >= 1; i--, t--) {
			b[0] ^= L_CPU_TO_BE64(t);
			b[1] = L_GET_UNALIGNED(r);
			l_cipher_decrypt(cipher, b, b, 16);
			L_PUT_UNALIGNED(b[1], r);
			r -= 1;
		}
	}

	l_cipher_free(cipher);
	explicit_bzero(&b[1], 8);

	/* Check IV */
	if (b[0] != 0xa6a6a6a6a6a6a6a6)
		return false;

	return true;
}

/*
 * AES Key-wrap from RFC 3394 for 128-bit key
 *
 * The key is specified using @kek.  @in contains the plaintext data and @len
 * contains its length.  @out will contain the encrypted data.  The result
 * will be (len + 8) bytes.
 *
 * Returns: true on success, false if an IV mismatch has occurred.
 *
 * NOTE: Buffers @in and @out can overlap
 */
bool aes_wrap(const uint8_t *kek, const uint8_t *in, size_t len, uint8_t *out)
{
	uint64_t b[2] = { 0xa6a6a6a6a6a6a6a6, 0 };
	uint64_t *r = (uint64_t *) out + 1;
	size_t n = len >> 3;
	unsigned int i, j;
	uint32_t t = 1;
	struct l_cipher *cipher;

	cipher = l_cipher_new(L_CIPHER_AES, kek, 16);
	if (!cipher)
		return false;

	memmove(r, in, len);

	for (j = 0; j < 6; j++) {
		for (i = 0; i < n; i++, t++) {
			b[1] = L_GET_UNALIGNED(r + i);
			l_cipher_encrypt(cipher, b, b, 16);
			L_PUT_UNALIGNED(b[1], r + i);
			b[0] ^= L_CPU_TO_BE64(t);
		}
	}

	L_PUT_UNALIGNED(b[0], r - 1);

	l_cipher_free(cipher);

	return true;
}

/*
 * RFC 5297 Section 2.3 - Doubling
 */
static void dbl(uint8_t *val)
{
	int i;
	int c = val[0] & (1 << 7);

	/* shift all but last byte (since i + 1 would overflow) */
	for (i = 0; i < 15; i++)
		val[i] = (val[i] << 1) | (val[i + 1] >> 7);

	val[15] <<= 1;

	/*
	 * "The condition under which the xor operation is performed is when the
	 * bit being shifted off is one."
	 */
	if (c)
		val[15] ^= 0x87;
}

static void xor(uint8_t *a, uint8_t *b, size_t len)
{
	size_t i;

	for (i = 0; i < len; i++)
		a[i] ^= b[i];
}

/*
 * RFC 5297 Section 2.4 - S2V
 */
static bool s2v(struct l_checksum *cmac, struct iovec *iov, size_t iov_len,
		uint8_t *v)
{
	uint8_t zero[16] = { 0 };
	uint8_t d[16];
	uint8_t tmp[16];
	size_t i;

	/* AES-CMAC(K, <zero>) */
	if (!l_checksum_update(cmac, zero, sizeof(zero)))
		return false;

	l_checksum_get_digest(cmac, d, sizeof(d));

	/* Last element is treated special */
	for (i = 0; i < iov_len - 1; i++) {
		/* D = dbl(D) */
		dbl(d);

		/* AES-CMAC(K, Si) */
		if (!l_checksum_update(cmac, iov[i].iov_base, iov[i].iov_len))
			return false;

		l_checksum_get_digest(cmac, tmp, sizeof(tmp));
		/* D = D xor AES-CMAC(K, Si) */
		xor(d, tmp, sizeof(tmp));
	}

	if (iov[i].iov_len >= 16) {
		if (!l_checksum_update(cmac, iov[i].iov_base,
					iov[i].iov_len - 16))
			return false;
		/* xorend(d) */
		xor(d, iov[i].iov_base + iov[i].iov_len - 16, 16);
	} else {
		dbl(d);
		xor(d, iov[i].iov_base, iov[i].iov_len);
		/*
		 * pad(X) indicates padding of string X, len(X) < 128, out to
		 * 128 bits by the concatenation of a single bit of 1 followed
		 * by as many 0 bits as are necessary.
		 */
		d[iov[i].iov_len] ^= 0x80;
	}

	if (!l_checksum_update(cmac, d, 16))
		return false;

	l_checksum_get_digest(cmac, v, 16);

	return true;
}

/*
 * RFC 5297 Section 2.6 - SIV Encrypt
 */
bool aes_siv_encrypt(const uint8_t *key, size_t key_len, const uint8_t *in,
			size_t in_len, struct iovec *ad, size_t num_ad,
			uint8_t *out)
{
	struct l_checksum *cmac;
	struct l_cipher *ctr;
	struct iovec iov[num_ad + 1];
	uint8_t v[16];

	memcpy(iov, ad, sizeof(struct iovec) * num_ad);
	iov[num_ad].iov_base = (void *)in;
	iov[num_ad].iov_len = in_len;
	num_ad++;

	/*
	 * key is split into two equal halves... K1 is used for S2V and K2 is
	 * used for CTR
	 */
	cmac = l_checksum_new_cmac_aes(key, key_len / 2);
	if (!cmac)
		return false;

	if (!s2v(cmac, iov, num_ad, v)) {
		l_checksum_free(cmac);
		return false;
	}

	l_checksum_free(cmac);

	memcpy(out, v, 16);

	v[8] &= 0x7f;
	v[12] &= 0x7f;

	ctr = l_cipher_new(L_CIPHER_AES_CTR, key + (key_len / 2), key_len / 2);
	if (!ctr)
		return false;

	if (!l_cipher_set_iv(ctr, v, 16))
		goto free_ctr;

	if (!l_cipher_encrypt(ctr, in, out + 16, in_len))
		goto free_ctr;

	l_cipher_free(ctr);

	return true;

free_ctr:
	l_cipher_free(ctr);
	return false;
}

bool aes_siv_decrypt(const uint8_t *key, size_t key_len, const uint8_t *in,
			size_t in_len, struct iovec *ad, size_t num_ad,
			uint8_t *out)
{
	struct l_checksum *cmac;
	struct l_cipher *ctr;
	struct iovec iov[num_ad + 1];
	uint8_t iv[16];
	uint8_t v[16];

	if (in_len < 16)
		return false;

	memcpy(iov, ad, sizeof(struct iovec) * num_ad);
	iov[num_ad].iov_base = (void *)out;
	iov[num_ad].iov_len = in_len - 16;
	num_ad++;

	if (in_len == 16)
		goto check_cmac;

	memcpy(iv, in, 16);

	iv[8] &= 0x7f;
	iv[12] &= 0x7f;

	ctr = l_cipher_new(L_CIPHER_AES_CTR, key + (key_len / 2), key_len / 2);
	if (!ctr)
		return false;

	if (!l_cipher_set_iv(ctr, iv, 16))
		goto free_ctr;

	if (!l_cipher_decrypt(ctr, in + 16, out, in_len - 16))
		goto free_ctr;

	l_cipher_free(ctr);

check_cmac:
	cmac = l_checksum_new_cmac_aes(key, key_len / 2);
	if (!cmac)
		return false;

	if (!s2v(cmac, iov, num_ad, v)) {
		l_checksum_free(cmac);
		return false;
	}

	l_checksum_free(cmac);

	if (memcmp(v, in, 16))
		return false;

	return true;

free_ctr:
	l_cipher_free(ctr);
	return false;
}

bool arc4_skip(const uint8_t *key, size_t key_len, size_t skip,
		const uint8_t *in, size_t len, uint8_t *out)
{
	char skip_buf[1024];
	struct l_cipher *cipher;
	struct iovec in_vec[2];
	struct iovec out_vec[2];
	bool r;

	cipher = l_cipher_new(L_CIPHER_ARC4, key, key_len);
	if (!cipher)
		return false;

	/* This is not strictly necessary, but keeps valgrind happy */
	memset(skip_buf, 0, sizeof(skip_buf));

	while (skip > sizeof(skip_buf)) {
		size_t to_skip =
			skip > sizeof(skip_buf) ? sizeof(skip_buf) : skip;

		l_cipher_decrypt(cipher, skip_buf, skip_buf, to_skip);
		skip -= to_skip;
	}

	in_vec[0].iov_base = skip_buf;
	in_vec[0].iov_len = skip;
	in_vec[1].iov_base = (void *) in;
	in_vec[1].iov_len = len;

	out_vec[0].iov_base = skip_buf;
	out_vec[0].iov_len = skip;
	out_vec[1].iov_base = out;
	out_vec[1].iov_len = len;

	r = l_cipher_decryptv(cipher, in_vec, 2, out_vec, 2);
	l_cipher_free(cipher);

	return r;
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
	}

	return 0;
}

int crypto_cipher_tk_bits(enum crypto_cipher cipher)
{
	return crypto_cipher_key_len(cipher) * 8;
}

bool crypto_passphrase_is_valid(const char *passphrase)
{
	size_t passphrase_len;
	size_t i;

	/*
	 * IEEE 802.11, Annex M, Section M.4.1:
	 * "A pass-phrase is a sequence of between 8 and 63 ASCII-encoded
	 * characters. The limit of 63 comes from the desire to distinguish
	 * between a pass-phrase and a PSK displayed as 64 hexadecimal
	 * characters."
	 */
	passphrase_len = strlen(passphrase);
	if (passphrase_len < 8 || passphrase_len > 63)
		return false;

	/* IEEE 802.11, Annex M, Section M.4.1:
	 * "Each character in the pass-phrase must have an encoding in the
	 * range of 32 to 126 (decimal), inclusive."
	 *
	 * This corresponds to printable characters only
	 */
	for (i = 0; i < passphrase_len; i++) {
		if (l_ascii_isprint(passphrase[i]))
			continue;

		return false;
	}

	return true;
}

int crypto_psk_from_passphrase(const char *passphrase,
				const unsigned char *ssid, size_t ssid_len,
				unsigned char *out_psk)
{
	bool result;
	unsigned char psk[32];

	if (!passphrase)
		return -EINVAL;

	if (!ssid)
		return -EINVAL;

	if (!crypto_passphrase_is_valid(passphrase))
		return -ERANGE;

	if (ssid_len == 0 || ssid_len > 32)
		return -ERANGE;

	result = l_pkcs5_pbkdf2(L_CHECKSUM_SHA1, passphrase, ssid, ssid_len,
				4096, psk, sizeof(psk));
	if (!result)
		return -ENOKEY;

	if (out_psk)
		memcpy(out_psk, psk, sizeof(psk));

	explicit_bzero(psk, sizeof(psk));
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

bool prf_plus_sha1(const void *key, size_t key_len,
					const void *label, size_t label_len,
					const void *seed, size_t seed_len,
					void *output, size_t size)
{
	/*
	 * PRF+ (K, S, LEN) = T1 | T2 | T3 | T4 | ... where:
	 *
	 * T1 = HMAC-SHA1 (K, S | LEN | 0x01 | 0x00 | 0x00)
	 *
	 * T2 = HMAC-SHA1 (K, T1 | S | LEN | 0x02 | 0x00 | 0x00)
	 *
	 * T3 = HMAC-SHA1 (K, T2 | S | LEN | 0x03 | 0x00 | 0x00)
	 *
	 * T4 = HMAC-SHA1 (K, T3 | S | LEN | 0x04 | 0x00 | 0x00)
	 *
	 * ...
	 */

	static const uint8_t SHA1_MAC_LEN = 20;
	static const uint8_t nil_bytes[2] = { 0, 0 };
	struct l_checksum *hmac;
	uint8_t t[SHA1_MAC_LEN];
	uint8_t counter;
	struct iovec iov[5] = {
		[0] = { .iov_base = (void *) t, .iov_len = 0 },
		[1] = { .iov_base = (void *) label, .iov_len = label_len },
		[2] = { .iov_base = (void *) seed, .iov_len = seed_len },
		[3] = { .iov_base = &counter, .iov_len = 1 },
		[4] = { .iov_base = (void *) nil_bytes, .iov_len = 2 },
	};

	hmac = l_checksum_new_hmac(L_CHECKSUM_SHA1, key, key_len);
	if (!hmac)
		return false;

	/* PRF processes in 160-bit chunks (20 bytes) */
	for (counter = 1;; counter++) {
		size_t len;

		if (size > SHA1_MAC_LEN)
			len = SHA1_MAC_LEN;
		else
			len = size;

		l_checksum_updatev(hmac, iov, 5);
		l_checksum_get_digest(hmac, t, len);

		memcpy(output, t, len);

		size -= len;

		if (!size)
			break;

		output += len;
		iov[0].iov_len = len;
	}

	l_checksum_free(hmac);

	return true;
}

/* Defined in 802.11-2012, Section 11.6.1.7.2 Key derivation function (KDF) */
bool kdf_sha256(const void *key, size_t key_len,
		const void *prefix, size_t prefix_len,
		const void *data, size_t data_len, void *output, size_t size)
{
	struct l_checksum *hmac;
	unsigned int i, offset = 0;
	unsigned int counter;
	uint8_t counter_le[2];
	uint8_t length_le[2];
	struct iovec iov[4] = {
		[0] = { .iov_base = counter_le, .iov_len = 2 },
		[1] = { .iov_base = (void *) prefix, .iov_len = prefix_len },
		[2] = { .iov_base = (void *) data, .iov_len = data_len },
		[3] = { .iov_base = length_le, .iov_len = 2 },
	};

	hmac = l_checksum_new_hmac(L_CHECKSUM_SHA256, key, key_len);
	if (!hmac)
		return false;

	/* Length is denominated in bits, not bytes */
	l_put_le16(size * 8, length_le);

	/* KDF processes in 256-bit chunks (32 bytes) */
	for (i = 0, counter = 1; i < (size + 31) / 32; i++, counter++) {
		size_t len;

		if (size - offset > 32)
			len = 32;
		else
			len = size - offset;

		l_put_le16(counter, counter_le);

		l_checksum_updatev(hmac, iov, 4);
		l_checksum_get_digest(hmac, output + offset, len);

		offset += len;
	}

	l_checksum_free(hmac);

	return true;
}

bool kdf_sha384(const void *key, size_t key_len,
		const void *prefix, size_t prefix_len,
		const void *data, size_t data_len, void *output, size_t size)
{
	struct l_checksum *hmac;
	unsigned int i, offset = 0;
	unsigned int counter;
	uint8_t counter_le[2];
	uint8_t length_le[2];
	struct iovec iov[4] = {
		[0] = { .iov_base = counter_le, .iov_len = 2 },
		[1] = { .iov_base = (void *) prefix, .iov_len = prefix_len },
		[2] = { .iov_base = (void *) data, .iov_len = data_len },
		[3] = { .iov_base = length_le, .iov_len = 2 },
	};

	hmac = l_checksum_new_hmac(L_CHECKSUM_SHA384, key, key_len);
	if (!hmac)
		return false;

	/* Length is denominated in bits, not bytes */
	l_put_le16(size * 8, length_le);

	/* KDF processes in 384-bit chunks (48 bytes) */
	for (i = 0, counter = 1; i < (size + 47) / 48; i++, counter++) {
		size_t len;

		if (size - offset > 48)
			len = 48;
		else
			len = size - offset;

		l_put_le16(counter, counter_le);

		l_checksum_updatev(hmac, iov, 4);
		l_checksum_get_digest(hmac, output + offset, len);

		offset += len;
	}

	l_checksum_free(hmac);

	return true;
}

/*
 * Defined in RFC 5869 - HMAC-based Extract-and-Expand Key Derivation Function
 *
 * Null key equates to a zero key (makes calls in EAP-PWD more convenient)
 */
bool hkdf_extract(enum l_checksum_type type, const uint8_t *key,
				size_t key_len, uint8_t num_args,
				uint8_t *out, ...)
{
	struct l_checksum *hmac;
	struct iovec iov[num_args];
	const uint8_t zero_key[64] = { 0 };
	size_t dlen = l_checksum_digest_length(type);
	const uint8_t *k = key ? key : zero_key;
	size_t k_len = key ? key_len : dlen;
	va_list va;
	int i;
	int ret;

	if (dlen <= 0)
		return false;

	hmac = l_checksum_new_hmac(type, k, k_len);
	if (!hmac)
		return false;

	va_start(va, out);

	for (i = 0; i < num_args; i++) {
		iov[i].iov_base = va_arg(va, void *);
		iov[i].iov_len = va_arg(va, size_t);
	}

	if (!l_checksum_updatev(hmac, iov, num_args)) {
		l_checksum_free(hmac);
		va_end(va);
		return false;
	}

	ret = l_checksum_get_digest(hmac, out, dlen);
	l_checksum_free(hmac);

	va_end(va);
	return (ret == (int) dlen);
}

bool hkdf_expand(enum l_checksum_type type, const uint8_t *key, size_t key_len,
			const char *info, size_t info_len, void *out,
			size_t out_len)
{
	uint8_t *t = out;
	size_t t_len = 0;
	struct l_checksum *hmac;
	uint8_t count = 1;
	uint8_t *out_ptr = out;

	hmac = l_checksum_new_hmac(type, key, key_len);
	if (!hmac)
		return false;

	while (out_len > 0) {
		ssize_t ret;
		struct iovec iov[3];

		iov[0].iov_base = t;
		iov[0].iov_len = t_len;
		iov[1].iov_base = (void *) info;
		iov[1].iov_len = info_len;
		iov[2].iov_base = &count;
		iov[2].iov_len = 1;

		if (!l_checksum_updatev(hmac, iov, 3)) {
			l_checksum_free(hmac);
			return false;
		}

		ret = l_checksum_get_digest(hmac, out_ptr, out_len);
		if (ret < 0) {
			l_checksum_free(hmac);
			return false;
		}

		/*
		 * RFC specifies that T(0) = empty string, so after the first
		 * iteration we update the length for T(1)...T(N)
		 */
		t_len = ret;
		t = out_ptr;
		count++;

		out_len -= ret;
		out_ptr += ret;

		if (out_len)
			l_checksum_reset(hmac);
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
static bool crypto_derive_ptk(const uint8_t *pmk, size_t pmk_len,
				const char *label,
				const uint8_t *addr1, const uint8_t *addr2,
				const uint8_t *nonce1, const uint8_t *nonce2,
				uint8_t *out_ptk, size_t ptk_len,
				enum l_checksum_type type)
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
	if (type == L_CHECKSUM_SHA384)
		return kdf_sha384(pmk, pmk_len, label, strlen(label),
					data, sizeof(data), out_ptk, ptk_len);
	else if (type == L_CHECKSUM_SHA256)
		return kdf_sha256(pmk, pmk_len, label, strlen(label),
					data, sizeof(data), out_ptk, ptk_len);
	else
		return prf_sha1(pmk, pmk_len, label, strlen(label),
					data, sizeof(data), out_ptk, ptk_len);
}

bool crypto_derive_pairwise_ptk(const uint8_t *pmk, size_t pmk_len,
				const uint8_t *addr1, const uint8_t *addr2,
				const uint8_t *nonce1, const uint8_t *nonce2,
				uint8_t *out_ptk, size_t ptk_len,
				enum l_checksum_type type)
{
	return crypto_derive_ptk(pmk, pmk_len, "Pairwise key expansion",
					addr1, addr2, nonce1, nonce2,
					out_ptk, ptk_len,
					type);
}

/* Defined in 802.11-2012, Section 11.6.1.7.3 PMK-R0 */
bool crypto_derive_pmk_r0(const uint8_t *xxkey, size_t xxkey_len,
				const uint8_t *ssid, size_t ssid_len,
				uint16_t mdid,
				const uint8_t *r0khid, size_t r0kh_len,
				const uint8_t *s0khid, bool sha384,
				uint8_t *out_pmk_r0, uint8_t *out_pmk_r0_name)
{
	uint8_t context[512];
	size_t pos = 0;
	uint8_t output[64];
	size_t offset = sha384 ? 48 : 32;
	struct l_checksum *sha;
	bool r = false;
	struct iovec iov[2] = {
		[0] = { .iov_base = "FT-R0N", .iov_len = 6 },
		[1] = { .iov_base = output + offset, .iov_len = 16 },
	};

	context[pos++] = ssid_len;

	memcpy(context + pos, ssid, ssid_len);
	pos += ssid_len;

	l_put_le16(mdid, context + pos);
	pos += 2;

	context[pos++] = r0kh_len;

	memcpy(context + pos, r0khid, r0kh_len);
	pos += r0kh_len;

	memcpy(context + pos, s0khid, ETH_ALEN);
	pos += ETH_ALEN;

	if (sha384) {
		if (!kdf_sha384(xxkey, xxkey_len, "FT-R0", 5, context, pos,
					output, 64))
			goto exit;
	} else {
		if (!kdf_sha256(xxkey, xxkey_len, "FT-R0", 5, context, pos,
					output, 48))
			goto exit;
	}

	sha = l_checksum_new((sha384) ? L_CHECKSUM_SHA384 : L_CHECKSUM_SHA256);
	if (!sha)
		goto exit;

	l_checksum_updatev(sha, iov, 2);
	l_checksum_get_digest(sha, out_pmk_r0_name, 16);

	l_checksum_free(sha);

	memcpy(out_pmk_r0, output, offset);

	r = true;

exit:
	explicit_bzero(context, pos);
	explicit_bzero(output, 64);

	return r;
}

/* Defined in 802.11-2012, Section 11.6.1.7.4 PMK-R1 */
bool crypto_derive_pmk_r1(const uint8_t *pmk_r0,
				const uint8_t *r1khid, const uint8_t *s1khid,
				const uint8_t *pmk_r0_name, bool sha384,
				uint8_t *out_pmk_r1,
				uint8_t *out_pmk_r1_name)
{
	uint8_t context[2 * ETH_ALEN];
	struct l_checksum *sha;
	bool r = false;
	struct iovec iov[3] = {
		[0] = { .iov_base = "FT-R1N", .iov_len = 6 },
		[1] = { .iov_base = (uint8_t *) pmk_r0_name, .iov_len = 16 },
		[2] = { .iov_base = context, .iov_len = sizeof(context) },
	};

	memcpy(context, r1khid, ETH_ALEN);

	memcpy(context + ETH_ALEN, s1khid, ETH_ALEN);

	if (sha384) {
		if (!kdf_sha384(pmk_r0, 48, "FT-R1", 5, context,
					sizeof(context), out_pmk_r1, 48))
			goto exit;
	} else {
		if (!kdf_sha256(pmk_r0, 32, "FT-R1", 5, context,
					sizeof(context), out_pmk_r1, 32))
			goto exit;
	}

	sha = l_checksum_new((sha384) ? L_CHECKSUM_SHA384 : L_CHECKSUM_SHA256);
	if (!sha) {
		explicit_bzero(out_pmk_r1, 48);
		goto exit;
	}

	l_checksum_updatev(sha, iov, 3);
	l_checksum_get_digest(sha, out_pmk_r1_name, 16);

	l_checksum_free(sha);

	r = true;

exit:
	explicit_bzero(context, sizeof(context));

	return r;
}

/* Defined in 802.11-2012, Section 11.6.1.7.5 PTK */
bool crypto_derive_ft_ptk(const uint8_t *pmk_r1, const uint8_t *pmk_r1_name,
				const uint8_t *addr1, const uint8_t *addr2,
				const uint8_t *nonce1, const uint8_t *nonce2,
				bool sha384, uint8_t *out_ptk, size_t ptk_len,
				uint8_t *out_ptk_name)
{
	uint8_t context[ETH_ALEN * 2 + 64];
	struct l_checksum *sha;
	bool r = false;
	struct iovec iov[3] = {
		[0] = { .iov_base = (uint8_t *) pmk_r1_name, .iov_len = 16 },
		[1] = { .iov_base = "FT-PTKN", .iov_len = 7 },
		[2] = { .iov_base = context, .iov_len = sizeof(context) },
	};

	memcpy(context, nonce1, 32);

	memcpy(context + 32, nonce2, 32);

	memcpy(context + 64, addr1, ETH_ALEN);

	memcpy(context + 64 + ETH_ALEN, addr2, ETH_ALEN);

	if (sha384) {
		if (!kdf_sha384(pmk_r1, 48, "FT-PTK", 6, context,
					sizeof(context), out_ptk, ptk_len))
			goto exit;
	} else {
		if (!kdf_sha256(pmk_r1, 32, "FT-PTK", 6, context,
					sizeof(context), out_ptk, ptk_len))
			goto exit;
	}

	sha = l_checksum_new((sha384) ? L_CHECKSUM_SHA384 : L_CHECKSUM_SHA256);
	if (!sha) {
		explicit_bzero(out_ptk, ptk_len);
		goto exit;
	}

	l_checksum_updatev(sha, iov, 3);
	l_checksum_get_digest(sha, out_ptk_name, 16);

	l_checksum_free(sha);

	r = true;

exit:
	explicit_bzero(context, sizeof(context));

	return r;
}

/* Defined in 802.11-2012, Section 11.6.1.3 Pairwise Key Hierarchy */
bool crypto_derive_pmkid(const uint8_t *pmk,
				const uint8_t *addr1, const uint8_t *addr2,
				uint8_t *out_pmkid, bool use_sha256)
{
	uint8_t data[20];

	memcpy(data + 0, "PMK Name", 8);
	memcpy(data + 8, addr2, 6);
	memcpy(data + 14, addr1, 6);

	if (use_sha256)
		return hmac_sha256(pmk, 32, data, 20, out_pmkid, 16);
	else
		return hmac_sha1(pmk, 32, data, 20, out_pmkid, 16);
}
