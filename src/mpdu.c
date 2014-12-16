/*
 *
 *  Wireless daemon for Linux
 *
 *  Copyright (C) 2014  Intel Corporation. All rights reserved.
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

#include <ell/ell.h>

#include "mpdu.h"

static inline bool next_byte(const unsigned char *mpdu, int len,
					int *offset, unsigned char *holder)
{
	if (len == *offset)
		return false;

	*holder = mpdu[*offset];
	*offset = *offset + 1;

	return true;
}

static inline bool next_2bytes(const unsigned char *mpdu, int len,
					int *offset, uint16_t *holder)
{
	if (len < *offset + 2)
		return false;

	*holder = L_LE16_TO_CPU(*((uint16_t *) mpdu + *offset));
	*offset = *offset + 2;

	return true;
}

static inline bool next_data(const unsigned char *mpdu, int len,
				int *offset, unsigned char *holder, int t_len)
{
	if (len < *offset + t_len)
		return false;

	memcpy(holder, mpdu + *offset, t_len);
	*offset += t_len;

	return true;
}

static bool decode_mgmt_header(const unsigned char *mpdu, int len,
						int *offset, struct mpdu *out)
{
	if (!next_2bytes(mpdu, len, offset, &out->mgmt_hdr.duration))
		return false;

	if (!next_data(mpdu, len, offset, out->mgmt_hdr.address_1, 6))
		return false;

	if (!next_data(mpdu, len, offset, out->mgmt_hdr.address_2, 6))
		return false;

	if (!next_data(mpdu, len, offset, out->mgmt_hdr.address_3, 6))
		return false;

	if (!next_2bytes(mpdu, len, offset, &out->mgmt_hdr.sequence_control))
		return false;

	if (out->fc.order)
		*offset += sizeof(uint32_t); /* Skipping ht_control for now */

	return true;
}

static bool decode_authentication_mgmt_mpdu(const unsigned char *mpdu,
					int len, int *offset, struct mpdu *out)
{
	if (!next_2bytes(mpdu, len, offset, &out->auth.algorithm))
		return false;

	if (!next_2bytes(mpdu, len, offset, &out->auth.transaction_sequence))
		return false;

	if (!next_2bytes(mpdu, len, offset, &out->auth.status))
		return false;

	if (out->auth.algorithm == MPDU_AUTH_ALGO_SK) {
		if (out->auth.transaction_sequence < 2 &&
					out->auth.transaction_sequence > 3)
			return true;

		if (!next_byte(mpdu, len, offset,
					&out->auth.challenge_text_len))
			return false;

		if (!next_data(mpdu, len, offset, out->auth.challenge_text,
						out->auth.challenge_text_len))
			return false;
	}

	return true;
}

static bool decode_deauthentication_mgmt_mpdu(const unsigned char *mpdu,
					int len, int *offset, struct mpdu *out)
{
	return next_2bytes(mpdu, len, offset, &out->deauth.reason_code);
}

static bool decode_mgmt_mpdu(const unsigned char *mpdu, int len,
						int *offset, struct mpdu *out)
{
	if (!decode_mgmt_header(mpdu, len, offset, out))
		return false;

	switch (out->fc.subtype) {
	case MPDU_MGMT_TYPE_AUTHENTICATION:
		return decode_authentication_mgmt_mpdu(mpdu, len, offset, out);
	case MPDU_MGMT_TYPE_DEAUTHENTICATION:
		return decode_deauthentication_mgmt_mpdu(mpdu, len, offset,
								out);
	default:
		return false;
	}

	return true;
}

bool mpdu_decode(const unsigned char *mpdu, int len, struct mpdu *out)
{
	int offset = 0;

	if (!mpdu || !out)
		return false;

	if (!next_2bytes(mpdu, len, &offset, &out->fc.content))
		return false;

	switch (out->fc.type) {
	case MPDU_TYPE_MANAGEMENT:
		return decode_mgmt_mpdu(mpdu, len, &offset, out);
	default:
		return false;
	}

	return true;
}
