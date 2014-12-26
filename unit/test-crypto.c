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

#include "src/sha1.h"
#include "src/crypto.h"

struct psk_data {
	const char *passphrase;
	const unsigned char *ssid;
	size_t ssid_len;
	const char *psk;
};

static const unsigned char psk_test_case_1_ssid[] = { 'I', 'E', 'E', 'E' };

static const struct psk_data psk_test_case_1 = {
	.passphrase =	"password",
	.ssid =		psk_test_case_1_ssid,
	.ssid_len =	sizeof(psk_test_case_1_ssid),
	.psk =		"f42c6fc52df0ebef9ebb4b90b38a5f90"
			"2e83fe1b135a70e23aed762e9710a12e",
};

static const unsigned char psk_test_case_2_ssid[] = { 'T', 'h', 'i', 's',
					'I', 's', 'A', 'S', 'S', 'I', 'D' };

static const struct psk_data psk_test_case_2 = {
	.passphrase =	"ThisIsAPassword",
	.ssid =		psk_test_case_2_ssid,
	.ssid_len =	sizeof(psk_test_case_2_ssid),
	.psk =		"0dc0d6eb90555ed6419756b9a15ec3e3"
			"209b63df707dd508d14581f8982721af",
};

static const unsigned char psk_test_case_3_ssid[] = {
				'Z', 'Z', 'Z', 'Z', 'Z', 'Z', 'Z', 'Z',
				'Z', 'Z', 'Z', 'Z', 'Z', 'Z', 'Z', 'Z',
				'Z', 'Z', 'Z', 'Z', 'Z', 'Z', 'Z', 'Z',
				'Z', 'Z', 'Z', 'Z', 'Z', 'Z', 'Z', 'Z' };

static const struct psk_data psk_test_case_3 = {
	.passphrase =	"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	.ssid =		psk_test_case_3_ssid,
	.ssid_len =	sizeof(psk_test_case_3_ssid),
	.psk =		"becb93866bb8c3832cb777c2f559807c"
			"8c59afcb6eae734885001300a981cc62",
};

static void psk_test(const void *data)
{
	const struct psk_data *test = data;
	unsigned char output[32];
	char psk[65];
	unsigned int i;
	int result;

	printf("Passphrase  = \"%s\"\n", test->passphrase);
	printf("SSID        = {");
	for (i = 0; i < test->ssid_len; i++)
		printf("%s'%c'", i == 0 ? " " : ", ", test->ssid[i]);
	printf(" }\n");
	printf("SSID Length = %zd\n", test->ssid_len);
	printf("PSK         = %s\n", test->psk);

	result = crypto_psk_from_passphrase(test->passphrase,
						test->ssid, test->ssid_len,
						output);
	assert(result == 0);

	for (i = 0; i < sizeof(output); i++)
		sprintf(psk + (i * 2), "%02x", output[i]);

	printf("Result      = %s\n", psk);

	assert(strcmp(test->psk, psk) == 0);
}

struct ptk_data {
	const unsigned char *pmk;
	const unsigned char *aa;
	const unsigned char *spa;
	const unsigned char *snonce;
	const unsigned char *anonce;
	enum crypto_cipher cipher;
	const unsigned char *kck;
	const unsigned char *kek;
	const unsigned char *tk;
};

static unsigned char pmk_data_1[32] = {
	0x0d, 0xc0, 0xd6, 0xeb, 0x90, 0x55, 0x5e, 0xd6,
	0x41, 0x97, 0x56, 0xb9, 0xa1, 0x5e, 0xc3, 0xe3,
	0x20, 0x9b, 0x63, 0xdf, 0x70, 0x7d, 0xd5, 0x08,
	0xd1, 0x45, 0x81, 0xf8, 0x98, 0x27, 0x21, 0xaf,
};

static unsigned char aa_data_1[6] = {
	0xa0, 0xa1, 0xa1, 0xa3, 0xa4, 0xa5,
};

static unsigned char spa_data_1[6] = {
	0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5,
};

static unsigned char snonce_data_1[32] = {
	0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7,
	0xc8, 0xc9, 0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5,
	0xd6, 0xd7, 0xd8, 0xd9, 0xda, 0xdb, 0xdc, 0xdd,
	0xde, 0xdf, 0xe0, 0xe1, 0xe2, 0xe3, 0xe4, 0xe5,
};

static unsigned char anonce_data_1[32] = {
	0xe0, 0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7,
	0xe8, 0xe9, 0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5,
	0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd,
	0xfe, 0xff, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
};

static unsigned char tk_data_1[] = {
	0xb2, 0x36, 0x0c, 0x79, 0xe9, 0x71, 0x0f, 0xdd,
	0x58, 0xbe, 0xa9, 0x3d, 0xea, 0xf0, 0x65, 0x99,
};

static unsigned char kck_data_2[] = {
	0x37, 0x9f, 0x98, 0x52, 0xd0, 0x19, 0x92, 0x36,
	0xb9, 0x4e, 0x40, 0x7c, 0xe4, 0xc0, 0x0e, 0xc8
};

static unsigned char kek_data_2[] = {
	0x47, 0xc9, 0xed, 0xc0, 0x1c, 0x2c, 0x6e, 0x5b,
	0x49, 0x10, 0xca, 0xdd, 0xfb, 0x3e, 0x51, 0xa7,
};

static unsigned char tk_data_2[] = {
	0xb2, 0x36, 0x0c, 0x79, 0xe9, 0x71, 0x0f, 0xdd,
	0x58, 0xbe, 0xa9, 0x3d, 0xea, 0xf0, 0x65, 0x99,
	0xdb, 0x98, 0x0a, 0xfb, 0xc2, 0x9c, 0x15, 0x28,
	0x55, 0x74, 0x0a, 0x6c, 0xe5, 0xae, 0x38, 0x27,
};

static const struct ptk_data ptk_test_1 = {
	.pmk = pmk_data_1,
	.aa = aa_data_1,
	.spa = spa_data_1,
	.snonce = snonce_data_1,
	.anonce = anonce_data_1,
	.cipher = CRYPTO_CIPHER_CCMP,
	.tk = tk_data_1,
};

static const struct ptk_data ptk_test_2 = {
	.pmk = pmk_data_1,
	.aa = aa_data_1,
	.spa = spa_data_1,
	.snonce = snonce_data_1,
	.anonce = anonce_data_1,
	.cipher = CRYPTO_CIPHER_TKIP,
	.kck = kck_data_2,
	.kek = kek_data_2,
	.tk = tk_data_2,
};

static void ptk_test(const void *data)
{
	const struct ptk_data *test = data;
	struct crypto_ptk *ptk;
	size_t ptk_len;
	bool ret;

	ptk_len = sizeof(struct crypto_ptk) +
			crypto_cipher_key_len(test->cipher);

	ptk = l_malloc(ptk_len);

	ret = crypto_derive_pairwise_ptk(test->pmk, test->aa, test->spa,
					test->anonce, test->snonce,
					ptk, ptk_len);

	assert(ret);

	if (test->kck)
		assert(!memcmp(test->kck, ptk->kck, sizeof(ptk->kck)));

	if (test->kek)
		assert(!memcmp(test->kek, ptk->kek, sizeof(ptk->kek)));

	if (test->tk)
		assert(!memcmp(test->tk, ptk->tk,
				crypto_cipher_key_len(test->cipher)));
}

int main(int argc, char *argv[])
{
	l_test_init(&argc, &argv);

	l_test_add("/Passphrase Generator/PSK Test Case 1",
			psk_test, &psk_test_case_1);
	l_test_add("/Passphrase Generator/PSK Test Case 2",
			psk_test, &psk_test_case_2);
	l_test_add("/Passphrase Generator/PSK Test Case 3",
			psk_test, &psk_test_case_3);

	l_test_add("/PTK Derivation/PTK Test Case 1",
			ptk_test, &ptk_test_1);
	l_test_add("/PTK Derivation/PTK Test Case 2",
			ptk_test, &ptk_test_2);

	return l_test_run();
}
