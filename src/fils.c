/*
 *
 *  Wireless daemon for Linux
 *
 *  Copyright (C) 2019  Intel Corporation. All rights reserved.
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

#include "src/ie.h"
#include "src/fils.h"
#include "src/handshake.h"
#include "src/mpdu.h"
#include "src/crypto.h"
#include "src/util.h"
#include "src/missing.h"
#include "src/erp.h"

#define FILS_NONCE_LEN		16
#define FILS_SESSION_LEN	8

struct fils_sm {
	struct erp_state *erp;
	struct handshake_state *hs;
	void *user_data;

	fils_tx_authenticate_func_t auth;
	fils_tx_associate_func_t assoc;
	fils_complete_func_t complete;

	uint8_t nonce[FILS_NONCE_LEN];
	uint8_t anonce[FILS_NONCE_LEN];
	uint8_t session[FILS_SESSION_LEN];

	uint8_t ick[48];
	size_t ick_len;
	uint8_t kek_and_tk[64 + 16];
	size_t kek_len;
	uint8_t pmk[48];
	size_t pmk_len;
	uint8_t pmkid[16];

	bool in_auth : 1;
};

static void fils_failed(struct fils_sm *fils, uint16_t status, bool ap_reject)
{
	fils->complete(status, fils->in_auth, ap_reject, fils->user_data);
}

static void fils_derive_pmkid(struct fils_sm *fils, const uint8_t *erp_data,
				size_t len)
{
	struct l_checksum *sha;
	enum l_checksum_type type;

	type = (fils->hs->akm_suite == IE_RSN_AKM_SUITE_FILS_SHA256) ?
				L_CHECKSUM_SHA256 : L_CHECKSUM_SHA384;

	sha = l_checksum_new(type);
	l_checksum_update(sha, erp_data, len);
	l_checksum_get_digest(sha, fils->pmkid, sizeof(fils->pmkid));
	l_checksum_free(sha);
}

static void fils_erp_tx_func(const uint8_t *eap_data, size_t len,
				void *user_data)
{
	struct fils_sm *fils = user_data;
	struct ie_tlv_builder builder;
	uint8_t data[256];
	uint8_t *ptr = data;
	unsigned int tlv_len;

	l_getrandom(fils->nonce, 16);
	l_getrandom(fils->session, 8);

	fils_derive_pmkid(fils, eap_data, len);

	/* transaction */
	l_put_le16(1, ptr);
	ptr += 2;
	/* status success */
	l_put_le16(0, ptr);
	ptr += 2;

	ie_tlv_builder_init(&builder, ptr, sizeof(data) - 4);

	ie_tlv_builder_next(&builder, IE_TYPE_FILS_NONCE);
	ie_tlv_builder_set_data(&builder, fils->nonce, sizeof(fils->nonce));

	ie_tlv_builder_next(&builder, IE_TYPE_FILS_SESSION);
	ie_tlv_builder_set_data(&builder, fils->session, sizeof(fils->session));

	ie_tlv_builder_next(&builder, IE_TYPE_FILS_WRAPPED_DATA);
	ie_tlv_builder_set_data(&builder, eap_data, len);

	ie_tlv_builder_finalize(&builder, &tlv_len);

	fils->auth(data, ptr - data + tlv_len, fils->user_data);
}

static int fils_derive_key_data(struct fils_sm *fils)
{
	const void *rmsk;
	size_t rmsk_len;
	struct ie_tlv_builder builder;
	uint8_t key[FILS_NONCE_LEN * 2];
	uint8_t key_data[64 + 48 + 16]; /* largest ICK, KEK, TK */
	uint8_t key_auth[48];
	uint8_t data[44];
	uint8_t *ptr = data;
	size_t hash_len;
	struct iovec iov[2];
	bool sha384;
	unsigned int ie_len;

	rmsk = erp_get_rmsk(fils->erp, &rmsk_len);

	/*
	 * IEEE 802.11ai - Section 12.12.2.5.3
	 */
	if (fils->hs->akm_suite == IE_RSN_AKM_SUITE_FILS_SHA256) {
		sha384 = false;
		hash_len = 32;
	} else {
		sha384 = true;
		hash_len = 48;
	}

	fils->kek_len = handshake_state_get_kek_len(fils->hs);

	/* key is SNonce || ANonce */
	memcpy(key, fils->nonce, sizeof(fils->nonce));
	memcpy(key + FILS_NONCE_LEN, fils->anonce, sizeof(fils->anonce));

	if (sha384)
		hmac_sha384(key, sizeof(key), rmsk, rmsk_len,
				fils->pmk, hash_len);
	else
		hmac_sha256(key, sizeof(key), rmsk, rmsk_len,
				fils->pmk, hash_len);

	fils->pmk_len = hash_len;

	/*
	 * IEEE 802.11ai - 12.12.2.5.3 PTKSA key derivation with FILS
	 * 			authentication
	 *
	 * FILS-Key-Data = PRF-X(PMK, “FILS PTK Derivation”, SPA || AA ||
	 * 					SNonce || ANonce)
	 */
	memcpy(ptr, fils->hs->spa, 6);
	ptr += 6;
	memcpy(ptr, fils->hs->aa, 6);
	ptr += 6;
	memcpy(ptr, fils->nonce, sizeof(fils->nonce));
	ptr += sizeof(fils->nonce);
	memcpy(ptr, fils->anonce, sizeof(fils->anonce));
	ptr += sizeof(fils->anonce);

	if (sha384)
		kdf_sha384(fils->pmk, hash_len, "FILS PTK Derivation",
				strlen("FILS PTK Derivation"), data,
				sizeof(data), key_data,
				hash_len + fils->kek_len + 16);
	else
		kdf_sha256(fils->pmk, hash_len, "FILS PTK Derivation",
				strlen("FILS PTK Derivation"), data,
				sizeof(data), key_data,
				hash_len + fils->kek_len + 16);

	ptr = data;

	/*
	 * IEEE 802.11ai - 12.12.2.6.2 (Re)Association Request for FILS key
	 * 			confirmation
	 *
	 * Key-Auth = HMAC-Hash(ICK, SNonce || ANonce || STA-MAC || AP-BSSID)
	 */
	memcpy(ptr, fils->nonce, sizeof(fils->nonce));
	ptr += sizeof(fils->nonce);
	memcpy(ptr, fils->anonce, sizeof(fils->anonce));
	ptr += sizeof(fils->anonce);
	memcpy(ptr, fils->hs->spa, 6);
	ptr += 6;
	memcpy(ptr, fils->hs->aa, 6);
	ptr += 6;

	memcpy(fils->ick, key_data, hash_len);
	fils->ick_len = hash_len;

	if (sha384)
		hmac_sha384(fils->ick, hash_len, data, ptr - data,
				key_auth, hash_len);
	else
		hmac_sha256(fils->ick, hash_len, data, ptr - data,
				key_auth, hash_len);

	ie_tlv_builder_init(&builder, NULL, 0);

	ie_tlv_builder_next(&builder, IE_TYPE_FILS_KEY_CONFIRMATION);
	ie_tlv_builder_set_data(&builder, key_auth, hash_len);

	ie_tlv_builder_next(&builder, IE_TYPE_FILS_SESSION);
	ie_tlv_builder_set_data(&builder, fils->session, sizeof(fils->session));

	iov[0].iov_base = ie_tlv_builder_finalize(&builder, &ie_len);
	iov[0].iov_len = ie_len;
	iov[1].iov_base = fils->hs->supplicant_ie;
	iov[1].iov_len = fils->hs->supplicant_ie[1] + 2;

	memcpy(data, fils->nonce, sizeof(fils->nonce));
	memcpy(data + sizeof(fils->nonce), fils->anonce, sizeof(fils->anonce));

	memcpy(fils->kek_and_tk, key_data + hash_len, fils->kek_len + 16);

	fils->assoc(iov, 2, fils->kek_and_tk, fils->kek_len, data,
			FILS_NONCE_LEN * 2, fils->user_data);

	fils->in_auth = false;

	return 0;
}

struct fils_sm *fils_sm_new(struct handshake_state *hs,
				fils_tx_authenticate_func_t auth,
				fils_tx_associate_func_t assoc,
				fils_complete_func_t complete, void *user_data)
{
	struct fils_sm *fils;

	fils = l_new(struct fils_sm, 1);

	fils->auth = auth;
	fils->assoc = assoc;
	fils->complete = complete;
	fils->user_data = user_data;
	fils->hs = hs;
	fils->in_auth = true;

	fils->erp = erp_new(hs->erp_cache, fils_erp_tx_func, fils);

	return fils;
}

void fils_sm_free(struct fils_sm *fils)
{
	erp_free(fils->erp);

	explicit_bzero(fils->ick, sizeof(fils->ick));
	explicit_bzero(fils->kek_and_tk, sizeof(fils->kek_and_tk));
	explicit_bzero(fils->pmk, fils->pmk_len);
	explicit_bzero(fils->pmkid, sizeof(fils->pmkid));

	l_free(fils);
}

void fils_start(struct fils_sm *fils)
{
	if (!erp_start(fils->erp))
		fils->complete(MMPDU_STATUS_CODE_UNSPECIFIED, fils->in_auth,
				false, fils->user_data);
}

void fils_rx_authenticate(struct fils_sm *fils, const uint8_t *frame,
				size_t len)
{
	const struct mmpdu_header *hdr = mpdu_validate(frame, len);
	const struct mmpdu_authentication *auth;
	struct ie_tlv_iter iter;
	const uint8_t *anonce = NULL;
	const uint8_t *session = NULL;
	const uint8_t *wrapped = NULL;
	size_t wrapped_len = 0;

	if (!hdr) {
		l_debug("Auth frame header did not validate");
		goto auth_failed;
	}

	auth = mmpdu_body(hdr);

	if (!auth) {
		l_debug("Auth frame body did not validate");
		goto auth_failed;
	}

	if (auth->status != 0) {
		l_debug("invalid status %u", auth->status);
		fils_failed(fils, auth->status, true);
		return;
	}

	if (auth->algorithm != MMPDU_AUTH_ALGO_FILS_SK &&
			auth->algorithm != MMPDU_AUTH_ALGO_FILS_SK_PFS) {
		l_debug("invalid auth algorithm %u", auth->algorithm);
		fils_failed(fils, MMPDU_STATUS_CODE_UNSUP_AUTH_ALG, false);
		return;
	}

	ie_tlv_iter_init(&iter, auth->ies, (const uint8_t *) hdr + len -
				auth->ies);
	while (ie_tlv_iter_next(&iter)) {
		switch (iter.tag) {
		case IE_TYPE_FILS_NONCE:
			if (iter.len != FILS_NONCE_LEN)
				goto auth_failed;

			anonce = iter.data;
			break;
		case IE_TYPE_FILS_SESSION:
			if (iter.len != FILS_SESSION_LEN)
				goto auth_failed;

			session = iter.data;
			break;
		case IE_TYPE_FILS_WRAPPED_DATA:
			wrapped = iter.data;
			wrapped_len = iter.len;
			break;
		default:
			continue;
		}
	}

	if (!anonce || !session || !wrapped) {
		l_debug("Auth did not include required IEs");
		fils_failed(fils, MMPDU_STATUS_CODE_INVALID_ELEMENT, false);
		return;
	}

	memcpy(fils->anonce, anonce, FILS_NONCE_LEN);

	if (erp_rx_packet(fils->erp, wrapped, wrapped_len) < 0)
		goto auth_failed;

	fils_derive_key_data(fils);
	return;

auth_failed:
	fils_failed(fils, MMPDU_REASON_CODE_UNSPECIFIED, false);
}

void fils_rx_associate(struct fils_sm *fils, const uint8_t *frame, size_t len)
{
	const struct mmpdu_header *hdr = mpdu_validate(frame, len);
	const struct mmpdu_association_response *assoc;
	struct ie_tlv_iter iter;
	uint8_t key_rsc[8];
	const uint8_t *gtk = NULL;
	size_t gtk_len;
	uint8_t gtk_key_index;
	const uint8_t *igtk = NULL;
	size_t igtk_len;
	uint8_t igtk_key_index;
	const uint8_t *ap_key_auth = NULL;
	uint8_t expected_key_auth[48];
	bool sha384 = (fils->hs->akm_suite == IE_RSN_AKM_SUITE_FILS_SHA384);
	uint8_t data[44];
	uint8_t *ptr = data;

	if (!hdr) {
		l_debug("Assoc frame header did not validate");
		goto assoc_failed;
	}

	assoc = mmpdu_body(hdr);

	if (!assoc) {
		l_debug("Assoc frame body did not validate");
		goto assoc_failed;;
	}

	if (assoc->status_code != 0) {
		fils_failed(fils, assoc->status_code, true);
		return;
	}

	ie_tlv_iter_init(&iter, assoc->ies, (const uint8_t *) hdr + len -
				assoc->ies);

	while (ie_tlv_iter_next(&iter)) {
		switch (iter.tag) {
		case IE_TYPE_KEY_DELIVERY:
			if (iter.len < 8)
				goto invalid_ies;

			memcpy(key_rsc, iter.data, 8);

			gtk = handshake_util_find_gtk_kde(iter.data + 8,
								iter.len - 8,
								&gtk_len);
			if (!gtk)
				goto invalid_ies;

			gtk_key_index = util_bit_field(gtk[0], 0, 2);
			gtk += 2;
			gtk_len -= 2;

			if (!fils->hs->mfp)
				break;

			igtk = handshake_util_find_igtk_kde(iter.data + 8,
								iter.len - 8,
								&igtk_len);
			if (!igtk)
				goto invalid_ies;

			igtk_key_index = l_get_le16(igtk);;
			igtk += 2;
			igtk_len -= 2;

			break;
		case IE_TYPE_FILS_KEY_CONFIRMATION:
			if (sha384 && iter.len != 48)
				goto invalid_ies;

			if (!sha384 && iter.len != 32)
				goto invalid_ies;

			ap_key_auth = iter.data;
		}
	}

	if (!ap_key_auth) {
		l_debug("Associate did not include KeyAuth IE");
		goto invalid_ies;
	}

	ptr = data;

	memcpy(ptr, fils->anonce, sizeof(fils->anonce));
	ptr += sizeof(fils->anonce);
	memcpy(ptr, fils->nonce, sizeof(fils->nonce));
	ptr += sizeof(fils->nonce);
	memcpy(ptr, fils->hs->aa, 6);
	ptr += 6;
	memcpy(ptr, fils->hs->spa, 6);
	ptr += 6;

	if (sha384)
		hmac_sha384(fils->ick, fils->ick_len, data, ptr - data,
				expected_key_auth, fils->ick_len);
	else
		hmac_sha256(fils->ick, fils->ick_len, data, ptr - data,
				expected_key_auth, fils->ick_len);

	if (memcmp(ap_key_auth, expected_key_auth, fils->ick_len)) {
		l_error("AP KeyAuth did not verify");
		goto assoc_failed;
	}

	handshake_state_set_pmk(fils->hs, fils->pmk, fils->pmk_len);
	handshake_state_set_pmkid(fils->hs, fils->pmkid);

	if (gtk)
		handshake_state_install_gtk(fils->hs, gtk_key_index, gtk,
						gtk_len, key_rsc, 6);

	if (igtk)
		handshake_state_install_igtk(fils->hs, igtk_key_index,
						igtk + 6, igtk_len - 6, igtk);

	handshake_state_set_ptk(fils->hs, fils->kek_and_tk, fils->kek_len + 16);
	handshake_state_install_ptk(fils->hs);

	fils->complete(0, fils->in_auth, false, fils->user_data);

	return;

assoc_failed:
	fils_failed(fils, MMPDU_STATUS_CODE_UNSPECIFIED, false);
	return;

invalid_ies:
	fils_failed(fils, MMPDU_STATUS_CODE_INVALID_ELEMENT, false);
}
