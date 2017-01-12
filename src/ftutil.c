/*
 *
 *  Wireless daemon for Linux
 *
 *  Copyright (C) 2017  Intel Corporation. All rights reserved.
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

#include "linux/nl80211.h"

#include <ell/ell.h>

#include "src/ie.h"
#include "src/handshake.h"
#include "src/crypto.h"
#include "src/ftutil.h"

/*
 * Calculate the MIC field of the FTE and write it directly to that FTE,
 * assuming it was all zeros before.  See 12.8.4 and 12.8.5.
 */
bool ft_calculate_fte_mic(struct handshake_state *hs, uint8_t seq_num,
				const uint8_t *rsne, const uint8_t *fte,
				const uint8_t *ric, uint8_t *out_mic)
{
	struct iovec iov[10];
	int iov_elems = 0;
	struct l_checksum *checksum;
	const struct crypto_ptk *ptk = handshake_state_get_ptk(hs);
	uint8_t zero_mic[16] = {};

	iov[iov_elems].iov_base = hs->spa;
	iov[iov_elems++].iov_len = 6;

	iov[iov_elems].iov_base = hs->aa;
	iov[iov_elems++].iov_len = 6;

	iov[iov_elems].iov_base = &seq_num;
	iov[iov_elems++].iov_len = 1;

	if (rsne) {
		iov[iov_elems].iov_base = (void *) rsne;
		iov[iov_elems++].iov_len = rsne[1] + 2;
	}

	iov[iov_elems].iov_base = hs->mde;
	iov[iov_elems++].iov_len = hs->mde[1] + 2;

	if (fte) {
		iov[iov_elems].iov_base = (void *) fte;
		iov[iov_elems++].iov_len = 4;

		iov[iov_elems].iov_base = zero_mic;
		iov[iov_elems++].iov_len = 16;

		iov[iov_elems].iov_base = (void *) (fte + 20);
		iov[iov_elems++].iov_len = fte[1] + 2 - 20;
	}

	if (ric) {
		iov[iov_elems].iov_base = (void *) ric;
		iov[iov_elems++].iov_len = ric[1] + 2;
	}

	checksum = l_checksum_new_cmac_aes(ptk->kck, 16);
	if (!checksum)
		return false;

	l_checksum_updatev(checksum, iov, iov_elems);
	l_checksum_get_digest(checksum, out_mic, 16);
	l_checksum_free(checksum);

	return true;
}

/*
 * Validate the FC, the addresses, Auth Type and authentication sequence
 * number of an FT Authentication Response frame, return status code, and
 * the start of the IE array (RSN, MD, FT, TI and RIC).
 * See 8.3.3.1 for the header and 8.3.3.11 for the body format.
 */
bool ft_parse_authentication_resp_frame(const uint8_t *data, size_t len,
				const uint8_t *addr1, const uint8_t *addr2,
				const uint8_t *addr3, uint16_t auth_seq,
				uint16_t *out_status, const uint8_t **out_ies,
				size_t *out_ies_len)
{
	const uint16_t frame_type = 0x00b0;
	uint16_t status = 0;

	if (len < 30)
		return false;

	/* Check FC == Management Frame -> Authentication */
	if (l_get_le16(data + 0) != frame_type)
		return false;

	if (memcmp(data + 4, addr1, 6))
		return false;
	if (memcmp(data + 10, addr2, 6))
		return false;
	if (memcmp(data + 16, addr3, 6))
		return false;

	/* Check Authentication algorithm number is FT */
	if (l_get_le16(data + 24) != NL80211_AUTHTYPE_FT)
		return false;

	if (l_get_le16(data + 26) != auth_seq)
		return false;

	if (auth_seq == 2 || auth_seq == 4)
		status = l_get_le16(data + 28);

	if (out_status)
		*out_status = status;

	if (status == 0 && out_ies) {
		*out_ies = data + 28;
		*out_ies_len = len - 28;
	}

	return true;
}
