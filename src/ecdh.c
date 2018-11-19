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

#include <ell/ell.h>

#include "ecdh.h"
#include "ecc.h"

static struct ecc_point p256_generator = CURVE_G_32;
static uint64_t p256_prime[4] = CURVE_P_32;
/*
 * IETF - Compact representation of an elliptic curve point:
 * https://tools.ietf.org/id/draft-jivsov-ecc-compact-00.xml
 *
 * "min(y,p-y) can be calculated with the help of the pre-calculated value
 *  p2=(p-1)/2. min(y,p-y) is y if y<p2 and p-y otherwise."
 */
static uint64_t p2[4] = { 0xffffffffffffffffull, 0x000000007fffffffull,
				0x8000000000000000ull, 0x7fffffff80000000ull };

/*
 * Some sane maximum for calculating the public key. This *shouldn't* ever be
 * reached in normal conditions.
 */
#define ECDH_MAX_ITERATIONS 20

/*
 * IETF draft-jivsov-ecc-compact-00 Section 4.2.1
 *
 * The following algorithm calculates a key pair {k, Q=k*G=(x,y)}, where k is
 * the private key and Q=(x,y) is the public key.
 *
 * Black box generation:
 *     1. Generate a key pair {k, Q=k*G=(x,y)} with KG
 *     2. if( y != min(y,p-y) ) goto step 1
 *     3. output {k, Q=(x,y)} as a key pair
 */
bool ecdh_generate_key_pair(void *private, size_t priv_len,
				void *public, size_t pub_len)
{
	struct ecc_point pub;
	bool compliant = false;
	int iter = 0;

	if (pub_len > 64)
		return false;

	while (!compliant && iter++ < ECDH_MAX_ITERATIONS) {
		if (!l_getrandom(private, priv_len))
			return false;

		/* private * G(x,y) = public key */
		ecc_point_mult(&pub, &p256_generator,
				(uint64_t *)private, NULL,
				vli_num_bits((uint64_t *)private));

		/* ensure public key is compliant */
		if (vli_cmp(pub.y, p2) >= 0) {
			compliant = true;
			break;
		}
	}

	if (!compliant) {
		l_error("could not generate a compliant public key pair");
		return false;
	}

	memcpy(public, &pub, pub_len);

	return true;
}

/*
 * IETF draft-jivsov-ecc-compact-00 Section 4.1
 * Encoding and decoding of an elliptic curve point
 * ...
 * Decoding:
 * Given the compact representation of Q, return canonical representation
 * of Q=(x,y) as follows:
 *     1. y' = sqrt( x^3 + a*x + b ), where y'>0
 *     2. y = min(y',p-y')
 *     3. Q=(x,y) is the canonical representation of the point
 */
static bool decode_point(const uint64_t *x, struct ecc_point *point)
{
	uint64_t y_min[4];

	if (!ecc_compute_y(y_min, (uint64_t *)x))
		return false;

	if (vli_cmp(y_min, p2) >= 0)
		vli_mod_sub(point->y, p256_prime, y_min, p256_prime);
	else
		memcpy(point->y, y_min, 32);

	memcpy(point->x, x, 32);

	return true;
}

bool ecdh_generate_shared_secret(const void *private, const void *other_public,
					size_t pub_len, void *secret,
					size_t secret_len)
{
	struct ecc_point product;
	struct ecc_point public;
	uint64_t z[4];
	uint64_t x[4];

	if (secret_len > 32)
		return false;

	/*
	 * TODO: Once other ECC groups are added this will need to be modified
	 * to check for 1/2 the full public key lengths
	 */
	if (pub_len == 32) {
		/*
		 * Only half the public key was given, the remainder (Y) must
		 * be decoded.
		 */
		memcpy(x, other_public, 32);

		if (!decode_point(x, &public)) {
			l_error("could not decode compressed public key");
			return false;
		}
	} else if (pub_len == 64) {
		memcpy(&public, other_public, 64);
	} else {
		l_error("unsupported public key length %zu", pub_len);
		return false;
	}

	if (!l_getrandom(z, sizeof(z)))
		return false;

	ecc_point_mult(&product, &public, (uint64_t *)private, z,
				vli_num_bits(private));

	memcpy(secret, product.x, secret_len);

	return true;
}
