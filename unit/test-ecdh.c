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

#include <string.h>
#include <assert.h>
#include <ell/ell.h>

#include "src/ecdh.h"
#include "src/ecc.h"

static bool use_real_getrandom = true;

bool __wrap_l_getrandom(void *buf, size_t len);
bool __real_l_getrandom(void *buf, size_t len);

bool __wrap_l_getrandom(void *buf, size_t len)
{
	static const uint8_t random_buf[] = { 0x75, 0xc5, 0xfe, 0x3e, 0x53,
						0xcc, 0x33, 0x33, 0x64, 0xea,
						0xdd, 0xa1, 0xe6, 0x62, 0x7a,
						0xb1, 0x98, 0xa7, 0xa0, 0x1e,
						0xac, 0x4b, 0x1d, 0xb8, 0x71,
						0x5b, 0x1d, 0x00, 0x36, 0xd0,
						0x0f, 0xde };

	if (use_real_getrandom)
		return __real_l_getrandom(buf, len);

	memcpy(buf, random_buf, len);

	return true;
}

/*
 * Tests the most basic case. Generate two full public keys and use to create
 * two identical shared secrets.
 */
static void test_basic(const void *data)
{
	uint8_t private1[32];
	uint8_t private2[32];

	uint8_t public1[64];
	uint8_t public2[64];

	uint8_t secret1[32];
	uint8_t secret2[32];

	assert(ecdh_generate_key_pair(private1, 32, public1, 64));
	assert(ecdh_generate_key_pair(private2, 32, public2, 64));

	assert(ecdh_generate_shared_secret(private1, public2, 64, secret1, 32));
	assert(ecdh_generate_shared_secret(private2, public1, 64, secret2, 32));

	assert(!memcmp(secret1, secret2, 32));
}

/*
 * Tests public key compliance. When generating the public keys, only specify
 * half their length (32). This requires ECDH to compute the remainder of the
 * public key when generating the shared secret.
 */
static void test_compliant_key(const void *data)
{
	uint8_t private1[32];
	uint8_t private2[32];

	uint8_t public1[32];
	uint8_t public2[32];

	uint8_t secret1[32];
	uint8_t secret2[32];

	assert(ecdh_generate_key_pair(private1, 32, public1, 32));
	assert(ecdh_generate_key_pair(private2, 32, public2, 32));

	assert(ecdh_generate_shared_secret(private1, public2, 32, secret1, 32));
	assert(ecdh_generate_shared_secret(private2, public1, 32, secret2, 32));

	assert(!memcmp(secret1, secret2, 32));
}

/*
 * Test vector from RFC 5114 - 256-bit Random ECP Group
 */
static void test_vectors(const void *data)
{
	uint64_t a_secret[4] = { 0x867B7291D507A3AFull, 0x3FAF432A5ABCE59Eull,
				0xE96A8E337A128499ull, 0x814264145F2F56F2ull };
	struct ecc_point a_public = {
			.x = { 0x5E8D3B4BA83AEB15ull, 0x7165BE50BC42AE4Aull,
				0xC9B5A8D4160D09E9ull, 0x2AF502F3BE8952F2ull },
			.y = { 0xC0F5015ECE5EFD85ull, 0x6795BD4BFF6E6DE3ull,
				0x8681A0F9872D79D5ull, 0xEB0FAF4CA986C4D3ull }
	};
	uint64_t b_secret[4] = { 0xEE1B593761CF7F41ull, 0x19CE6BCCAD562B8Eull,
				0xDB95A200CC0AB26Aull, 0x2CE1788EC197E096ull };
	struct ecc_point b_public = {
			.x = { 0xB3AB0715F6CE51B0ull, 0xAE06AAEA279FA775ull,
				0x5346E8DE6C2C8646ull, 0xB120DE4AA3649279ull },
			.y = { 0x85C34DDE5708B2B6ull, 0x3727027092A84113ull,
				0xD8EC685FA3F071D8ull, 0x9F1B7EECE20D7B5Eull }
	};
	uint64_t shared_secret[4] = { 0x7F80D21C820C2788ull,
					0xF5811E9DC8EC8EEAull,
					0x93310412D19A08F1ull,
					0xDD0F5396219D1EA3ull };

	uint64_t a_shared[4];
	uint64_t b_shared[4];

	use_real_getrandom = false;

	assert(ecdh_generate_shared_secret(a_secret, (const void *)&b_public,
						64, a_shared, 32));
	assert(ecdh_generate_shared_secret(b_secret, (const void *)&a_public,
						64, b_shared, 32));

	assert(!memcmp(a_shared, shared_secret, 32));
	assert(!memcmp(b_shared, shared_secret, 32));

	use_real_getrandom = true;
}

int main(int argc, char *argv[])
{
	l_test_init(&argc, &argv);

	if (l_getrandom_is_supported()) {
		l_test_add("ECDH Basic", test_basic, NULL);
		l_test_add("ECDH Compliant key", test_compliant_key, NULL);
	}

	l_test_add("ECDH test vector", test_vectors, NULL);

	return l_test_run();
}
