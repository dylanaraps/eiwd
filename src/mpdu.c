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

#include "ie.h"
#include "mpdu.h"

static bool validate_mgmt_header(const struct mpdu *mpdu, int len, int *offset)
{
	/* Duration + Address1 + Address 2 + Address 3 + SeqCntrl */
	if (len < *offset + 22)
		return false;

	*offset += 22;

	if (!mpdu->fc.order)
		return true;

	if (len < *offset + 4)
		return false;

	*offset += 4;

	return true;
}

static bool validate_on_ies_start_position_mgmt_mpdu(const struct mpdu *mpdu,
							int len, int *offset,
							int position)
{
	return *offset + position < len;
}

static bool validate_atim_mgmt_mpdu(const struct mpdu *mpdu,
					int len, int *offset)
{
	return *offset == len;
}

static bool validate_disassociation_mgmt_mpdu(const struct mpdu *mpdu,
						int len, int *offset)
{
	*offset += 2;
	return *offset <= len;
}

static bool validate_authentication_mgmt_mpdu(const struct mpdu *mpdu,
						int len, int *offset)
{
	if (len < *offset + 6)
		return false;

	*offset += 6;

	switch (mpdu->auth.algorithm) {
	case MPDU_AUTH_ALGO_OPEN_SYSTEM:
		return *offset <= len;
	case MPDU_AUTH_ALGO_SHARED_KEY:
		if (mpdu->auth.transaction_sequence < 2 ||
				mpdu->auth.transaction_sequence > 3)
			return *offset == len;

		if (len < *offset + 2)
			return false;

		*offset += 2;

		if (mpdu->auth.shared_key_23.element_id !=
				IE_TYPE_CHALLENGE_TEXT)
			return false;

		*offset += mpdu->auth.shared_key_23.challenge_text_len;
		return *offset <= len;
	default:
		return false;
	}

	return false;
}

static bool validate_deauthentication_mgmt_mpdu(const struct mpdu *mpdu,
						int len, int *offset)
{
	*offset += 2;
	return *offset <= len;
}

static bool validate_mgmt_mpdu(const struct mpdu *mpdu, int len, int *offset)
{
	if (!validate_mgmt_header(mpdu, len, offset))
		return false;

	switch (mpdu->fc.subtype) {
	case MPDU_MANAGEMENT_SUBTYPE_ASSOCIATION_REQUEST:
		return validate_on_ies_start_position_mgmt_mpdu(mpdu, len,
								offset, 9);
	case MPDU_MANAGEMENT_SUBTYPE_ATIM:
		return validate_atim_mgmt_mpdu(mpdu, len, offset);
	case MPDU_MANAGEMENT_SUBTYPE_DISASSOCIATION:
		return validate_disassociation_mgmt_mpdu(mpdu, len, offset);
	case MPDU_MANAGEMENT_SUBTYPE_AUTHENTICATION:
		return validate_authentication_mgmt_mpdu(mpdu, len, offset);
	case MPDU_MANAGEMENT_SUBTYPE_DEAUTHENTICATION:
		return validate_deauthentication_mgmt_mpdu(mpdu, len, offset);
	default:
		return false;
	}

	return true;
}

bool mpdu_validate(const unsigned char *frame, int len)
{
	struct mpdu *mpdu;
	int offset;

	if (!frame)
		return false;

	if (len < 2)
		return false;

	offset = 2;
	mpdu = (struct mpdu *) frame;

	switch (mpdu->fc.type) {
	case MPDU_TYPE_MANAGEMENT:
		return validate_mgmt_mpdu(mpdu, len, &offset);
	default:
		return false;
	}

	return true;
}
