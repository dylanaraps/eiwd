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
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>

#include <ell/ell.h>

#ifndef PF_ALG
#include <linux/types.h>

struct sockaddr_alg {
	__u16   salg_family;
	__u8    salg_type[14];
	__u32   salg_feat;
	__u32   salg_mask;
	__u8    salg_name[64];
};

#define ALG_SET_KEY                     1

#define PF_ALG		38	/* Algorithm sockets.  */
#define AF_ALG		PF_ALG
#else
#include <linux/if_alg.h>
#endif

#ifndef SOL_ALG
#define SOL_ALG		279
#endif

#include "src/aes.h"

/* Maximum message length that can be passed to aes_cmac */
#define CMAC_MSG_MAX	80

static int cmac_aes_setup(void)
{
	struct sockaddr_alg salg;
	int fd;

	fd = socket(PF_ALG, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
	if (fd < 0)
		return -1;

	memset(&salg, 0, sizeof(salg));
	salg.salg_family = AF_ALG;
	strcpy((char *) salg.salg_type, "hash");
	strcpy((char *) salg.salg_name, "cmac(aes)");

	if (bind(fd, (struct sockaddr *) &salg, sizeof(salg)) < 0) {
		close(fd);
		return -1;
	}

	return fd;
}

static int alg_new(int fd, const void *keyval, socklen_t keylen)
{
	if (setsockopt(fd, SOL_ALG, ALG_SET_KEY, keyval, keylen) < 0)
		return -1;

	return accept4(fd, NULL, 0, SOCK_CLOEXEC);
}

bool cmac_aes(const void *key, size_t key_len,
		const void *msg, size_t msg_len, void *tag, size_t size)
{
	ssize_t len;
	int fd, alg_fd;
	bool result;

	if (msg_len > CMAC_MSG_MAX)
		return false;

	alg_fd = cmac_aes_setup();
	if (alg_fd < 0)
		return false;

	fd = alg_new(alg_fd, key, key_len);
	if (fd < 0) {
		close(alg_fd);
		return false;
	}

	len = send(fd, msg, msg_len, 0);
	if (len < 0) {
		result = false;
		goto done;
	}

	len = read(fd, tag, size);
	if (len < 0) {
		result = false;
		goto done;
	}

	result = true;

done:
	close(fd);
	close(alg_fd);

	return result;
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
