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

#include "crypto.h"
#include "ecc.h"
#include "ecdh.h"
#include "ie.h"
#include "handshake.h"
#include "owe.h"
#include "mpdu.h"

struct owe_sm {
	struct handshake_state *hs;
	uint8_t private[32];
	uint64_t public_key[NUM_ECC_DIGITS * 2];

	owe_tx_authenticate_func_t auth_tx;
	owe_tx_associate_func_t assoc_tx;
	owe_complete_func_t complete;
	void *user_data;
};

struct owe_sm *owe_sm_new(struct handshake_state *hs,
				owe_tx_authenticate_func_t auth,
				owe_tx_associate_func_t assoc,
				owe_complete_func_t complete, void *user_data)
{
	struct owe_sm *owe = l_new(struct owe_sm, 1);

	memset(owe->public_key, 0, sizeof(owe->public_key));
	owe->hs = hs;
	owe->auth_tx = auth;
	owe->assoc_tx = assoc;
	owe->user_data = user_data;
	owe->complete = complete;

	if (!ecdh_generate_key_pair(owe->private, 32, owe->public_key, 64)) {
		l_free(owe);
		return NULL;
	}

	/*
	 * Store our own public key in BE ordering since all future uses
	 * will need it.
	 */
	ecc_native2be(owe->public_key);
	ecc_native2be(owe->public_key + 4);

	return owe;
}

void owe_sm_free(struct owe_sm *owe)
{
	memset(owe->private, 0, sizeof(owe->private));

	l_free(owe);
}

void owe_start(struct owe_sm *owe)
{
	owe->auth_tx(owe->user_data);
}

void owe_rx_authenticate(struct owe_sm *owe)
{
	uint8_t buf[37];
	struct iovec iov[3];
	int iov_elems = 0;

	/*
	 * RFC 8110 Section 4.3
	 * A client wishing to do OWE MUST indicate the OWE AKM in the RSN
	 * element portion of the 802.11 association request ...
	 */
	iov[iov_elems].iov_base = owe->hs->supplicant_ie;
	iov[iov_elems].iov_len = owe->hs->supplicant_ie[1] + 2;
	iov_elems++;

	/*
	 * ... and MUST include a Diffie-Hellman Parameter element to its
	 * 802.11 association request.
	 */
	buf[0] = IE_TYPE_EXTENSION;
	buf[1] = 35; /* length */
	buf[2] = IE_TYPE_OWE_DH_PARAM - 256;
	l_put_le16(19, buf + 3); /* group */
	memcpy(buf + 5, owe->public_key, 32);

	iov[iov_elems].iov_base = (void *) buf;
	iov[iov_elems].iov_len = buf[1] + 2;
	iov_elems++;

	owe->assoc_tx(iov, iov_elems, owe->user_data);
}

/*
 * RFC 8110 Section 4.4 Post Association
 */
static bool owe_compute_keys(struct owe_sm *owe, const void *public_key,
			size_t pub_len)
{
	uint64_t shared_secret[4];
	uint8_t prk[32];
	uint8_t pmk[32];
	uint8_t pmkid[16];
	uint8_t key[32 + 32 + 2];
	uint64_t public_native[4];
	struct iovec iov[2];
	struct l_checksum *sha;

	memcpy(public_native, public_key, 32);
	ecc_be2native(public_native);

	/* z = F(DH(x, Y)) */
	if (!ecdh_generate_shared_secret(owe->private, public_native, pub_len,
						shared_secret, 32))
		return false;

	memcpy(key, owe->public_key, 32);
	memcpy(key + 32, public_key, 32);
	l_put_le16(19, key + 64);

	ecc_native2be(shared_secret);

	/* prk = HKDF-extract(C | A | group, z) */
	if (!hkdf_extract_sha256(key, 66, 1, prk, shared_secret, 32))
		goto failed;

	/* PMK = HKDF-expand(prk, "OWE Key Generation", n) */
	if (!hkdf_expand_sha256(prk, 32, "OWE Key Generation",
				strlen("OWE Key Generation"), pmk, 32))
		goto failed;

	sha = l_checksum_new(L_CHECKSUM_SHA256);

	/* PMKID = Truncate-128(Hash(C | A)) */
	iov[0].iov_base = owe->public_key;
	iov[0].iov_len = 32;
	iov[1].iov_base = (void *) public_key;
	iov[1].iov_len = 32;

	l_checksum_updatev(sha, iov, 2);

	l_checksum_get_digest(sha, pmkid, 16);

	l_checksum_free(sha);

	handshake_state_set_pmk(owe->hs, pmk, 32);
	handshake_state_set_pmkid(owe->hs, pmkid);

	return true;

failed:
	memset(shared_secret, 0, sizeof(shared_secret));
	return false;
}

void owe_rx_associate(struct owe_sm *owe, const uint8_t *frame, size_t len)
{
	const struct mmpdu_header *mpdu = NULL;
	const struct mmpdu_association_response *body;
	struct ie_tlv_iter iter;
	size_t owe_dh_len = 0;
	const uint8_t *owe_dh = NULL;
	struct ie_rsn_info info;
	bool akm_found;
	const void *data;

	mpdu = mpdu_validate(frame, len);
	if (!mpdu) {
		l_error("could not process frame");
		goto owe_failed;
	}

	body = mmpdu_body(mpdu);

	ie_tlv_iter_init(&iter, body->ies, (const uint8_t *) mpdu + len -
				body->ies);

	while (ie_tlv_iter_next(&iter)) {
		uint16_t tag = ie_tlv_iter_get_tag(&iter);

		data = ie_tlv_iter_get_data(&iter);
		len = ie_tlv_iter_get_length(&iter);

		switch (tag) {
		case IE_TYPE_OWE_DH_PARAM:
			owe_dh = data;
			owe_dh_len = len;

			break;
		case IE_TYPE_RSN:
			if (ie_parse_rsne(&iter, &info) < 0) {
				l_error("could not parse RSN IE");
				goto owe_failed;
			}

			/*
			 * RFC 8110 Section 4.2
			 * An AP agreeing to do OWE MUST include the OWE AKM in
			 * the RSN element portion of the 802.11 association
			 * response.
			 */
			if (info.akm_suites != IE_RSN_AKM_SUITE_OWE) {
				l_error("OWE AKM not included");
				goto owe_failed;
			}

			akm_found = true;

			break;
		default:
			continue;
		}
	}

	if (!owe_dh || owe_dh_len < 34 || !akm_found) {
		l_error("associate response did not include proper OWE IE's");
		goto owe_failed;
	}

	if (l_get_le16(owe_dh) != 19) {
		l_error("associate response contained unsupported group %u",
				l_get_le16(owe_dh));
		goto owe_failed;
	}

	if (!owe_compute_keys(owe, owe_dh + 2, owe_dh_len - 2)) {
		l_error("could not compute OWE keys");
		goto owe_failed;
	}

	owe->complete(0, owe->user_data);

	return;

owe_failed:
	owe->complete(MMPDU_REASON_CODE_UNSPECIFIED, owe->user_data);
}
