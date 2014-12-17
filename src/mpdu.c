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

static inline unsigned char bit_field(unsigned char oct, int start, int num)
{
	unsigned char mask = (1 << num) - 1;

	return (oct >> start) & mask;
}

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

	*holder = L_LE16_TO_CPU(*(uint16_t *)(mpdu + *offset));
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
	uint16_t sequence_control;

	if (!next_2bytes(mpdu, len, offset, &out->mgmt_hdr.duration))
		return false;

	if (!next_data(mpdu, len, offset, out->mgmt_hdr.address_1, 6))
		return false;

	if (!next_data(mpdu, len, offset, out->mgmt_hdr.address_2, 6))
		return false;

	if (!next_data(mpdu, len, offset, out->mgmt_hdr.address_3, 6))
		return false;

	if (!next_2bytes(mpdu, len, offset, &sequence_control))
		return false;

	out->mgmt_hdr.fragment_number = sequence_control & 0x0f;
	out->mgmt_hdr.sequence_number = sequence_control >> 4;

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
	case MPDU_MANAGEMENT_SUBTYPE_AUTHENTICATION:
		return decode_authentication_mgmt_mpdu(mpdu, len, offset, out);
	case MPDU_MANAGEMENT_SUBTYPE_DEAUTHENTICATION:
		return decode_deauthentication_mgmt_mpdu(mpdu, len, offset,
								out);
	default:
		return false;
	}

	return true;
}

bool mpdu_decode(const unsigned char *mpdu, int len, struct mpdu *out)
{
	int offset;

	if (!mpdu || !out)
		return false;

	if (len < 2)
		return false;

	out->fc.protocol_version = bit_field(mpdu[0], 0, 2);
	out->fc.type = bit_field(mpdu[0], 2, 2);
	out->fc.subtype = bit_field(mpdu[0], 4, 4);

	out->fc.to_ds = bit_field(mpdu[1], 0, 1);
	out->fc.from_ds = bit_field(mpdu[1], 1, 1);
	out->fc.more_fragments = bit_field(mpdu[1], 2, 1);
	out->fc.retry = bit_field(mpdu[1], 3, 1);
	out->fc.power_mgmt = bit_field(mpdu[1], 4, 1);
	out->fc.more_data = bit_field(mpdu[1], 5, 1);
	out->fc.protected_frame = bit_field(mpdu[1], 6, 1);
	out->fc.order = bit_field(mpdu[1], 7, 1);

	offset = 2;

	switch (out->fc.type) {
	case MPDU_TYPE_MANAGEMENT:
		return decode_mgmt_mpdu(mpdu, len, &offset, out);
	default:
		return false;
	}

	return true;
}
