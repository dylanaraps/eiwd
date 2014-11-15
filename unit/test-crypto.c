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

int main(int argc, char *argv[])
{
	l_test_init(&argc, &argv);

	l_test_add("/Passphrase Generator/PSK Test Case 1",
			psk_test, &psk_test_case_1);
	l_test_add("/Passphrase Generator/PSK Test Case 2",
			psk_test, &psk_test_case_2);
	l_test_add("/Passphrase Generator/PSK Test Case 3",
			psk_test, &psk_test_case_3);

	return l_test_run();
}
