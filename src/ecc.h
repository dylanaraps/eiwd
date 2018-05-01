/*
 *
 *  Wireless daemon for Linux
 *
 *  Copyright (C) 2018 Intel Corporation. All rights reserved.
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
#include <ell/ell.h>

/* 256-bit curve */
#define ECC_BYTES 32

/* Number of uint64_t's needed */
#define NUM_ECC_DIGITS (ECC_BYTES / 8)

#define CURVE_P_32 {	0xFFFFFFFFFFFFFFFFull, 0x00000000FFFFFFFFull, \
			0x0000000000000000ull, 0xFFFFFFFF00000001ull }

#define CURVE_G_32 { \
		{	0xF4A13945D898C296ull, 0x77037D812DEB33A0ull,	\
			0xF8BCE6E563A440F2ull, 0x6B17D1F2E12C4247ull }, \
		{	0xCBB6406837BF51F5ull, 0x2BCE33576B315ECEull,	\
			0x8EE7EB4A7C0F9E16ull, 0x4FE342E2FE1A7F9Bull }	\
}

#define CURVE_N_32 {	0xF3B9CAC2FC632551ull, 0xBCE6FAADA7179E84ull,	\
			0xFFFFFFFFFFFFFFFFull, 0xFFFFFFFF00000000ull }

#define CURVE_B_32 {	0x3BCE3C3E27D2604Bull, 0x651D06B0CC53B0F6ull,	\
			0xB3EBBD55769886BCull, 0x5AC635D8AA3A93E7ull }

struct ecc_point {
	uint64_t x[NUM_ECC_DIGITS];
	uint64_t y[NUM_ECC_DIGITS];
};

void ecc_point_mult(struct ecc_point *result, const struct ecc_point *point,
		uint64_t *scalar, uint64_t *initial_z, int num_bits);

void ecc_point_add(struct ecc_point *ret, struct ecc_point *p,
		struct ecc_point *q);

bool ecc_valid_point(struct ecc_point *point);

bool ecc_compute_y(uint64_t *y, uint64_t *x);

void vli_mod_inv(uint64_t *result, const uint64_t *input, const uint64_t *mod);

void vli_mod_sub(uint64_t *result, const uint64_t *left, const uint64_t *right,
		const uint64_t *mod);

void vli_mod_add(uint64_t *result, const uint64_t *left, const uint64_t *right,
		const uint64_t *mod);

uint64_t vli_sub(uint64_t *result, const uint64_t *left, const uint64_t *right);

void vli_mod_mult_fast(uint64_t *result, const uint64_t *left,
		const uint64_t *right);

void vli_mod_exp(uint64_t *result, uint64_t *base, uint64_t *exp,
		const uint64_t *mod);

int vli_cmp(const uint64_t *left, const uint64_t *right);

unsigned int vli_num_bits(const uint64_t *vli);
