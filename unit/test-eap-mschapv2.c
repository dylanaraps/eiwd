/*
 *
 *  Wireless daemon for Linux
 *
 *  Copyright (C) 2016  Markus Ongyerth. All rights reserved.
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

#include "src/eap-mschapv2.h"

/* The test values here are taken from the RFCs the functions are defined in */

/* https://tools.ietf.org/html/rfc2759 */
const char *user = "User";
const char *nt_password = "clientPass";
const uint8_t password_hash[] = {
	0x44, 0xEB, 0xBA, 0x8D,
	0x53, 0x12, 0xB8, 0xD6,
	0x11, 0x47, 0x44, 0x11,
	0xF5, 0x69, 0x89, 0xAE
};
const uint8_t server_challenge[] = {
	0x5B, 0x5D, 0x7C, 0x7D,
	0x7B, 0x3F, 0x2F, 0x3E,
	0x3C, 0x2C, 0x60, 0x21,
	0x32, 0x26, 0x26, 0x28
};
const uint8_t  peer_challenge[] = {
	0x21, 0x40, 0x23, 0x24,
	0x25, 0x5E, 0x26, 0x2A,
	0x28, 0x29, 0x5F, 0x2B,
	0x3A, 0x33, 0x7C, 0x7E
};
const uint8_t nt_response[] = {
	0x82, 0x30, 0x9E, 0xCD,
	0x8D, 0x70, 0x8B, 0x5E,
	0xA0, 0x8F, 0xAA, 0x39,
	0x81, 0xCD, 0x83, 0x54,
	0x42, 0x33, 0x11, 0x4A,
	0x3D, 0x85, 0xD6, 0xDF
};
const uint8_t password_hash_hash[] = {
	0x41, 0xC0, 0x0C, 0x58,
	0x4B, 0xD2, 0xD9, 0x1C,
	0x40, 0x17, 0xA2, 0xA1,
	0x2F, 0xA5, 0x9F, 0x3F
};
const char *authenticator_response =
	"S=407A5589115FD0D6209F510FE9C04566932CDA56";
/* https://tools.ietf.org/html/draft-ietf-pppext-mschapv2-keys-02 */
const uint8_t master_key[] = {
	0xFD, 0xEC, 0xE3, 0x71,
	0x7A, 0x8C, 0x83, 0x8C,
	0xB3, 0x88, 0xE5, 0x27,
	0xAE, 0x3C, 0xDD, 0x31
};
const uint8_t m_session_key[] = {
	0x8B, 0x7C, 0xDC, 0x14,
	0x9B, 0x99, 0x3A, 0x1B,
	0xA1, 0x18, 0xCB, 0x15,
	0x3F, 0x56, 0xDC, 0xCB
};

static void test_nt_password_hash(const void *data)
{
	uint8_t hash[16];

	assert(mschapv2_nt_password_hash(nt_password, hash));
	assert(!memcmp(hash, password_hash, sizeof(password_hash)));
}

static void test_generate_nt_response(const void *data)
{
	uint8_t nt_resp[24];

	assert(mschapv2_generate_nt_response(password_hash, peer_challenge,
					server_challenge, user, nt_resp));
	assert(!memcmp(nt_resp, nt_response, sizeof(nt_response)));
}

static void test_authenticator_response(const void *data)
{
	char buf[43];
	buf[42] = '\0';

	assert(mschapv2_generate_authenticator_response(password_hash_hash,
						nt_response, peer_challenge,
						server_challenge, user,
						buf));
	assert(!strcmp(buf, authenticator_response));
}

static void test_get_master_key(const void *data)
{
	uint8_t m_key[16];

	assert(mschapv2_get_master_key(password_hash_hash, nt_response, m_key));
	assert(!memcmp(m_key, master_key, sizeof(master_key)));
}

static void test_get_asym_key(const void *data)
{
	uint8_t msk[20];

	assert(mschapv2_get_asymmetric_start_key(master_key, msk, sizeof(msk),
								true, true));
	assert(!memcmp(msk, m_session_key, sizeof(m_session_key)));
}


int main(int argc, char *argv[])
{
	l_test_init(&argc, &argv);

	if (!l_checksum_is_supported(L_CHECKSUM_MD4, false)) {
		printf("MD4 support missing, skipping...\n");
		goto done;
	}

	l_test_add("MSHAPv2 nt_password-hash",
			test_nt_password_hash, NULL);
	l_test_add("MSHAPv2 generate_nt_response",
			test_generate_nt_response, NULL);
	l_test_add("MSHAPv2 get_master_key",
			test_get_master_key, NULL);
	l_test_add("MSHAPv2 get_asym_state_key",
			test_get_asym_key, NULL);
	l_test_add("MSHAPv2 authenticator_response",
			test_authenticator_response, NULL);

done:
	return l_test_run();
}
