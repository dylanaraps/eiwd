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
#include "ie.h"
#include "handshake.h"
#include "owe.h"
#include "mpdu.h"

/*
 * TODO: Once other groups are added, this will need to be dynamic. OWE does
 * support retries with different groups, but this is not yet implemented since
 * only group 19 is supported.
 */
#define OWE_DEFAULT_GROUP 19

struct owe_sm {
	struct handshake_state *hs;
	const struct l_ecc_curve *curve;
	struct l_ecc_scalar *private;
	struct l_ecc_point *public_key;

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

	owe->hs = hs;
	owe->auth_tx = auth;
	owe->assoc_tx = assoc;
	owe->user_data = user_data;
	owe->complete = complete;
	owe->curve = l_ecc_curve_get_ike_group(OWE_DEFAULT_GROUP);

	if (!l_ecdh_generate_key_pair(owe->curve, &owe->private,
					&owe->public_key)) {
		l_free(owe);
		return NULL;
	}

	return owe;
}

void owe_sm_free(struct owe_sm *owe)
{
	l_ecc_scalar_free(owe->private);
	l_ecc_point_free(owe->public_key);

	l_free(owe);
}

void owe_start(struct owe_sm *owe)
{
	owe->auth_tx(owe->user_data);
}

void owe_rx_authenticate(struct owe_sm *owe)
{
	uint8_t buf[5 + L_ECC_SCALAR_MAX_BYTES];
	struct iovec iov[3];
	int iov_elems = 0;
	size_t len;

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
	buf[2] = IE_TYPE_OWE_DH_PARAM - 256;
	l_put_le16(OWE_DEFAULT_GROUP, buf + 3); /* group */
	len = l_ecc_point_get_x(owe->public_key, buf + 5,
					L_ECC_SCALAR_MAX_BYTES);
	buf[1] = 3 + len; /* length */

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
	struct l_ecc_scalar *shared_secret;
	uint8_t ss_buf[L_ECC_SCALAR_MAX_BYTES];
	uint8_t prk[32];
	uint8_t pmk[32];
	uint8_t pmkid[16];
	uint8_t key[32 + 32 + 2];
	struct iovec iov[2];
	struct l_checksum *sha;
	struct l_ecc_point *other_public;

	other_public = l_ecc_point_from_data(owe->curve,
						L_ECC_POINT_TYPE_COMPLIANT,
						public_key, pub_len);
	if (!other_public) {
		l_error("AP public key was not valid");
		return false;
	}

	if (!l_ecdh_generate_shared_secret(owe->private, other_public,
						&shared_secret)) {
		return false;
	}

	l_ecc_point_free(other_public);

	l_ecc_scalar_get_data(shared_secret, ss_buf, sizeof(ss_buf));

	l_ecc_scalar_free(shared_secret);

	l_ecc_point_get_x(owe->public_key, key, sizeof(key));
	memcpy(key + 32, public_key, 32);
	l_put_le16(OWE_DEFAULT_GROUP, key + 64);

	/* prk = HKDF-extract(C | A | group, z) */
	if (!hkdf_extract_sha256(key, 66, 1, prk, ss_buf, 32))
		goto failed;

	/* PMK = HKDF-expand(prk, "OWE Key Generation", n) */
	if (!hkdf_expand_sha256(prk, 32, "OWE Key Generation",
				strlen("OWE Key Generation"), pmk, 32))
		goto failed;

	sha = l_checksum_new(L_CHECKSUM_SHA256);

	/* PMKID = Truncate-128(Hash(C | A)) */
	iov[0].iov_base = key; /* first 32 bytes of key are owe->public_key */
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
	memset(ss_buf, 0, sizeof(ss_buf));
	l_ecc_scalar_free(shared_secret);
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
