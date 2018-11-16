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

int main(int argc, char *argv[])
{
	l_test_init(&argc, &argv);
	l_test_add("ECDH Basic", test_basic, NULL);
	l_test_add("ECDH Compliant key", test_compliant_key, NULL);

	return l_test_run();
}
