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

#include "src/util.h"
#include "src/ie.h"
#include "src/handshake.h"
#include "src/crypto.h"
#include "src/mpdu.h"
#include "src/ecc.h"
#include "src/sae.h"

#define SAE_RETRANSMIT_TIMEOUT	2
#define SAE_SYNC_MAX		3

enum sae_state {
	SAE_STATE_NOTHING = 0,
	SAE_STATE_COMMITTED = 1,
	SAE_STATE_CONFIRMED = 2,
	SAE_STATE_ACCEPTED = 3,
};

struct sae_sm {
	struct handshake_state *handshake;
	struct ecc_point pwe;
	enum sae_state state;
	uint64_t rand[NUM_ECC_DIGITS];
	uint64_t scalar[NUM_ECC_DIGITS];
	uint64_t p_scalar[NUM_ECC_DIGITS];
	struct ecc_point element;
	struct ecc_point p_element;
	uint16_t send_confirm;
	uint8_t kck[32];
	uint8_t pmk[32];
	uint8_t pmkid[16];
	uint8_t *token;
	size_t token_len;
	/* number of state resyncs that have occurred */
	uint16_t sync;
	/* number of SAE confirm messages that have been sent */
	uint16_t sc;
	/* received value of the send-confirm counter */
	uint16_t rc;
	/* remote peer */
	uint8_t peer[6];

	sae_tx_packet_func_t tx;
	sae_complete_func_t complete;
	void *user_data;
};

static uint64_t curve_p[NUM_ECC_DIGITS] = CURVE_P_32;
static uint64_t curve_n[NUM_ECC_DIGITS] = CURVE_N_32;

/* calculate random quadratic residue */
static void sae_get_qr(uint64_t *qr)
{
	l_getrandom(qr, 32);

	while (vli_legendre(qr, curve_p) != -1)
		l_getrandom(qr, 32);
}

/* calculate random quadratic non-residue */
static void sae_get_qnr(uint64_t *qnr)
{
	l_getrandom(qnr, 32);

	while (vli_legendre(qnr, curve_p) != 1)
		l_getrandom(qnr, 32);
}

/* blinding technique to determine if 'value' is quadratic residue */
static bool sae_is_quadratic_residue(uint64_t *value, uint64_t *qr,
						uint64_t *qnr)
{
	uint64_t y_sqr[NUM_ECC_DIGITS];
	uint64_t r[NUM_ECC_DIGITS];
	uint64_t num[NUM_ECC_DIGITS];

	ecc_compute_y_sqr(y_sqr, value);

	l_getrandom(r, 32);

	while (vli_cmp(r, curve_p) >= 0)
		l_getrandom(r, 32);

	vli_mod_mult_fast(num, y_sqr, r);
	vli_mod_mult_fast(num, num, r);

	if (r[0] & 1) {
		vli_mod_mult_fast(num, num, qr);

		if (vli_legendre(num, curve_p) == -1)
			return true;
	} else {
		vli_mod_mult_fast(num, num, qnr);

		if (vli_legendre(num, curve_p) == 1)
			return true;
	}

	return false;
}

static bool sae_pwd_seed(const uint8_t *addr1, const uint8_t *addr2,
				uint8_t *base, size_t base_len,
				uint8_t counter, uint8_t *out)
{
	uint8_t key[12];

	if (memcmp(addr1, addr2, 6) > 0) {
		memcpy(key, addr1, 6);
		memcpy(key + 6, addr2, 6);
	} else {
		memcpy(key, addr2, 6);
		memcpy(key + 6, addr1, 6);
	}

	return hkdf_extract_sha256(key, 12, 2, out, base, base_len,
					&counter, 1);
}

static bool sae_pwd_value(uint8_t *pwd_seed, uint64_t *pwd_value)
{
	uint64_t prime[NUM_ECC_DIGITS];

	memcpy(prime, curve_p, 32);

	ecc_be2native(prime);

	return kdf_sha256(pwd_seed, 32, "SAE Hunting and Pecking",
			strlen("SAE Hunting and Pecking"), prime, 32,
			pwd_value, 32);
}

/* IEEE 802.11-2016 - Section 12.4.2 Assumptions on SAE */
static bool sae_cn(const uint8_t *kck, uint16_t send_confirm,
			const uint64_t *scalar1, const uint64_t *element1,
			const uint64_t *scalar2, const uint64_t *element2,
			uint8_t *confirm)
{
	struct l_checksum *hmac;
	struct iovec iov[5];
	int ret;

	hmac = l_checksum_new_hmac(L_CHECKSUM_SHA256, kck, 32);
	if (!hmac)
		return false;

	iov[0].iov_base = &send_confirm;
	iov[0].iov_len = 2;
	iov[1].iov_base = (void *) scalar1;
	iov[1].iov_len = 32;
	iov[2].iov_base = (void *) element1;
	iov[2].iov_len = 64;
	iov[3].iov_base = (void *) scalar2;
	iov[3].iov_len = 32;
	iov[4].iov_base = (void *) element2;
	iov[4].iov_len = 64;

	l_checksum_updatev(hmac, iov, 5);

	ret = l_checksum_get_digest(hmac, confirm, 32);

	l_checksum_free(hmac);

	return (ret == 32);
}

static void sae_authentication_failed(struct sae_sm *sm, uint16_t reason)
{
	sm->complete(reason, sm->user_data);

	sae_sm_free(sm);
}

static void sae_reject_authentication(struct sae_sm *sm, uint16_t reason)
{
	uint8_t reject[6];
	uint8_t *ptr = reject;

	/* transaction */
	l_put_u16(1, ptr);
	ptr += 2;
	/* status success */
	l_put_u16(reason, ptr);
	ptr += 2;

	if (reason == MMPDU_REASON_CODE_UNSUPP_FINITE_CYCLIC_GROUP) {
		l_put_u16(19, ptr);
		ptr += 2;
	}

	sm->tx(sm->peer, reject, ptr - reject, sm->user_data);

	sae_authentication_failed(sm, reason);
}

/*
 * IEEE 802.11-2016 Section 12.4.4.2.2
 * Generation of the password element with ECC groups
 */
static bool sae_compute_pwe(char *password, const uint8_t *addr1,
				const uint8_t *addr2, struct ecc_point *pwe)
{
	bool found = false;
	uint8_t counter = 1;
	uint8_t k = 20;
	uint8_t pwd_seed[32];
	uint64_t pwd_value[NUM_ECC_DIGITS];
	uint8_t random[32];
	uint8_t *base = (uint8_t *) password;
	size_t base_len = strlen(password);
	uint8_t save[32] = { 0 };
	uint64_t qr[NUM_ECC_DIGITS];
	uint64_t qnr[NUM_ECC_DIGITS];

	/* create qr/qnr prior to beginning hunting-and-pecking loop */
	sae_get_qr(qr);
	sae_get_qnr(qnr);

	do {
		/* pwd-seed = H(max(addr1, addr2) || min(addr1, addr2),
		 *                base || counter)
		 * pwd-value = KDF-256(pwd-seed, "SAE Hunting and Pecking", p)
		 */
		sae_pwd_seed(addr1, addr2, base, base_len, counter, pwd_seed);

		sae_pwd_value(pwd_seed, pwd_value);

		ecc_be2native(pwd_value);

		/* if (pwd-value < p) { */
		if (vli_cmp(pwd_value, curve_p) < 0) {
			if (sae_is_quadratic_residue(pwd_value, qr, qnr)) {
				if (found == false) {
					memcpy(pwe->x, pwd_value, 32);
					memcpy(save, pwd_seed, 32);

					l_getrandom(random, 32);
					base = random;
					base_len = 32;

					found = true;
				}
			}
		}

		counter++;

	} while ((counter <= k) || (found == false));

	if (!found) {
		l_error("max PWE iterations reached!");
		return false;
	}

	if (!ecc_compute_y(pwe->y, pwe->x)) {
		/* should always return true */
		l_error("computing y failed, was x quadratic residue?");
		return false;
	}

	if ((pwe->y[0] & 1) != (save[31] & 1))
		vli_mod_sub(pwe->y, curve_p, pwe->y, curve_p);

	return true;
}

/* commit-scalar = (rand + mask) mod r */
static void sae_get_commit_scalar(uint64_t *scalar, uint64_t *mask,
					uint64_t *rand)
{
	uint64_t _1[NUM_ECC_DIGITS] = { 1ull };

	l_getrandom(rand, ECC_BYTES);

	/* ensure 1 < p_rand < r */
	while (!((vli_cmp(rand, _1) > 0) &&
			(vli_cmp(rand, curve_n) < 0)))
		l_getrandom(rand, ECC_BYTES);

	l_getrandom(mask, ECC_BYTES);

	/* ensure 1 < p_mask < r */
	while (!((vli_cmp(mask, _1) > 0) &&
			(vli_cmp(mask, curve_n) < 0)))
		l_getrandom(mask, ECC_BYTES);

	/* (rand + mask) mod r */
	vli_mod_add(scalar, rand, mask, curve_n);
}

/* commit-element = inv(mask * PWE) */
static bool sae_get_commit_element(struct ecc_point *element,
					struct ecc_point *pwe, uint64_t *mask)
{
	/* p_mask * PWE */
	ecc_point_mult(element, pwe, mask, NULL, vli_num_bits(mask));

	if (!ecc_valid_point(element))
		return false;

	/* inv(p_mask * PWE) */
	vli_sub(element->y, curve_p, element->y);

	if (!ecc_valid_point(element))
		return false;

	return true;
}

static bool sae_build_commit(struct sae_sm *sm, const uint8_t *addr1,
				const uint8_t *addr2, uint8_t *commit,
				size_t *len, bool retry)
{
	uint64_t scalar[NUM_ECC_DIGITS];
	uint64_t mask[NUM_ECC_DIGITS];
	struct ecc_point element;
	uint8_t *ptr = commit;

	if (retry)
		goto old_commit;

	if (!sm->handshake->passphrase) {
		l_error("no handshake passphrase found");
		return false;
	}

	if (!sae_compute_pwe(sm->handshake->passphrase, addr1,
			addr2, &sm->pwe)) {
		l_error("could not compute PWE");
		return false;
	}

	sae_get_commit_scalar(sm->scalar, mask, sm->rand);

	if (!sae_get_commit_element(&sm->element, &sm->pwe, mask)) {
		l_error("error calculating commit element");
		return false;
	}

	/*
	 * Several cases require retransmitting the same commit message. The
	 * anti-clogging code path requires this as well as the retransmition
	 * timeout.
	 */
old_commit:
	memcpy(scalar, sm->scalar, 32);
	memcpy(element.x, sm->element.x, 32);
	memcpy(element.y, sm->element.y, 32);

	ecc_native2be(scalar);
	ecc_native2be(element.x);
	ecc_native2be(element.y);

	/* transaction */
	l_put_le16(1, ptr);
	ptr += 2;
	/* status success */
	l_put_le16(0, ptr);
	ptr += 2;
	/* group */
	l_put_le16(19, ptr);
	ptr += 2;

	if (sm->token) {
		memcpy(ptr, sm->token, sm->token_len);
		ptr += sm->token_len;
	}

	memcpy(ptr, scalar, 32);
	ptr += 32;
	memcpy(ptr, element.x, 32);
	ptr += 32;
	memcpy(ptr, element.y, 32);
	ptr += 32;

	*len = ptr - commit;

	return true;
}

static void sae_send_confirm(struct sae_sm *sm)
{
	uint8_t confirm[32];
	uint8_t body[38];
	uint8_t *ptr = body;

	ecc_native2be(sm->scalar);
	ecc_native2be(sm->element.x);
	ecc_native2be(sm->element.y);
	ecc_native2be(sm->p_scalar);
	ecc_native2be(sm->p_element.x);
	ecc_native2be(sm->p_element.y);

	/*
	 * confirm = CN(KCK, send-confirm, commit-scalar, COMMIT-ELEMENT,
	 *			peer-commit-scalar, PEER-COMMIT-ELEMENT)
	 */
	sae_cn(sm->kck, sm->sc, sm->scalar, (uint64_t *) &sm->element,
			sm->p_scalar, (uint64_t *) &sm->p_element, confirm);

	/*
	 * in case of retransmition, we will need to reuse these values, so
	 * go back to native endianness for consistency.
	 */
	ecc_be2native(sm->scalar);
	ecc_be2native(sm->element.x);
	ecc_be2native(sm->element.y);
	ecc_be2native(sm->p_scalar);
	ecc_be2native(sm->p_element.x);
	ecc_be2native(sm->p_element.y);

	l_put_le16(2, ptr);
	ptr += 2;
	l_put_le16(0, ptr);
	ptr += 2;
	l_put_le16(sm->sc, ptr);
	ptr += 2;
	memcpy(ptr, confirm, 32);
	ptr += 32;

	sm->state = SAE_STATE_CONFIRMED;

	sm->tx(sm->peer, body, 38, sm->user_data);
}

static void sae_process_commit(struct sae_sm *sm, const uint8_t *from,
					const uint8_t *frame, size_t len)
{
	uint8_t *ptr = (uint8_t *) frame;
	uint64_t k[NUM_ECC_DIGITS];
	struct ecc_point k_point;
	uint8_t zero_key[32] = { 0 };
	uint8_t keyseed[32];
	uint8_t kck_and_pmk[2][32];
	uint64_t tmp[NUM_ECC_DIGITS];
	uint16_t group;
	uint16_t reason = MMPDU_REASON_CODE_UNSPECIFIED;

	if (sm->state != SAE_STATE_COMMITTED) {
		l_error("bad state %u", sm->state);
		goto reject;
	}

	if (len < 98) {
		l_error("bad packet length");
		goto reject;
	}

	group = l_get_le16(ptr);
	ptr += 2;

	if (group != 19) {
		l_error("unsupported group: %u", group);
		reason =  MMPDU_REASON_CODE_UNSUPP_FINITE_CYCLIC_GROUP;
		goto reject;
	}

	memcpy(sm->p_scalar, ptr, 32);
	ptr += 32;
	memcpy(sm->p_element.x, ptr, 32);
	ptr += 32;
	memcpy(sm->p_element.y, ptr, 32);

	ecc_be2native(sm->p_scalar);
	ecc_be2native(sm->p_element.x);
	ecc_be2native(sm->p_element.y);

	if (!memcmp(sm->p_scalar, sm->scalar, 32) ||
			!memcmp(sm->p_element.x, sm->element.x, 32) ||
			!memcmp(sm->p_element.y, sm->element.y, 32)) {
		/* possible reflection attack, silently discard message */
		l_warn("peer scalar or element matched own, discarding frame");

		return;
	}

	sm->sc++;

	/*
	 * K = scalar-op(rand, (element-op(scalar-op(peer-commit-scalar, PWE),
	 *			PEER-COMMIT-ELEMENT)))
	 */

	/* k_point = scalar-op(peer-commit-scalar, PWE) */
	ecc_point_mult(&k_point, &sm->pwe, sm->p_scalar, NULL,
				vli_num_bits(sm->p_scalar));

	/* k_point = element-op(k_point, PEER-COMMIT-ELEMENT) */
	ecc_point_add(&k_point, &k_point, &sm->p_element);

	/* k_point = scalar-op(rand, k_point) */
	ecc_point_mult(&k_point, &k_point, sm->rand, NULL,
				vli_num_bits(sm->rand));

	/*
	 * IEEE 802.11-2016 - Section 12.4.4.2.1 ECC group definition
	 * ECC groups make use of a mapping function, F, that maps a
	 * point (x, y) that satisfies the curve equation to its x-coordinate—
	 * i.e., if P = (x, y) then F(P) = x.
	 */
	memcpy(k, k_point.x, 32);

	ecc_native2be(k);

	/* keyseed = H(<0>32, k) */
	hmac_sha256(zero_key, 32, k, 32, keyseed, 32);

	/*
	 * kck_and_pmk = KDF-Hash-512(keyseed, "SAE KCK and PMK",
				(commit-scalar + peer-commit-scalar) mod r)
	 */
	vli_mod_add(tmp, sm->p_scalar, sm->scalar, curve_n);

	ecc_native2be(tmp);

	kdf_sha256(keyseed, 32, "SAE KCK and PMK", strlen("SAE KCK and PMK"),
			tmp, 32, kck_and_pmk, 64);

	memcpy(sm->kck, kck_and_pmk[0], 32);
	memcpy(sm->pmk, kck_and_pmk[1], 32);

	/*
	 * PMKID = L((commit-scalar + peer-commit-scalar) mod r, 0, 128)
	 */
	vli_mod_add(tmp, sm->scalar, sm->p_scalar, curve_n);
	ecc_native2be(tmp);
	/* don't set the handshakes pmkid until confirm is verified */
	memcpy(sm->pmkid, tmp, 16);

	sae_send_confirm(sm);

	return;

reject:
	sae_reject_authentication(sm, reason);
}

static bool sae_verify_confirm(struct sae_sm *sm, const uint8_t *frame)
{
	uint8_t check[32];
	uint16_t rc = l_get_le16(frame);

	ecc_native2be(sm->scalar);
	ecc_native2be(sm->element.x);
	ecc_native2be(sm->element.y);
	ecc_native2be(sm->p_scalar);
	ecc_native2be(sm->p_element.x);
	ecc_native2be(sm->p_element.y);

	sae_cn(sm->kck, rc, sm->p_scalar,
			(const uint64_t *) &sm->p_element, sm->scalar,
			(const uint64_t *) &sm->element, check);

	ecc_be2native(sm->scalar);
	ecc_be2native(sm->element.x);
	ecc_be2native(sm->element.y);
	ecc_be2native(sm->p_scalar);
	ecc_be2native(sm->p_element.x);
	ecc_be2native(sm->p_element.y);

	if (memcmp(frame + 2, check, 32)) {
		l_error("confirm did not match");
		return false;
	}

	sm->rc = rc;

	return true;
}

static void sae_process_confirm(struct sae_sm *sm, const uint8_t *from,
				const uint8_t *frame, size_t len)
{
	const uint8_t *ptr = frame;

	if (sm->state != SAE_STATE_CONFIRMED) {
		l_error("bad state %u", sm->state);
		goto reject;
	}

	if (len < 34) {
		l_error("bad length");
		goto reject;
	}

	if (!sae_verify_confirm(sm, ptr))
		goto reject;

	/* Sc shall be set to the value 2^16 - 1 */
	sm->sc = 0xffff;

	handshake_state_set_pmkid(sm->handshake, sm->pmkid);
	handshake_state_set_pmk(sm->handshake, sm->pmk, 32);

	sm->complete(0, sm->user_data);

	sm->state = SAE_STATE_ACCEPTED;

	return;

reject:
	sae_reject_authentication(sm, MMPDU_REASON_CODE_UNSPECIFIED);
}

static void sae_send_commit(struct sae_sm *sm, bool retry)
{
	struct handshake_state *hs = sm->handshake;
	/* regular commit + possible 256 byte token */
	uint8_t commit[358];
	size_t len;

	if (!sae_build_commit(sm, hs->spa, hs->aa, commit, &len, retry))
		return;

	sm->state = SAE_STATE_COMMITTED;

	sm->tx(sm->peer, commit, len, sm->user_data);
}

void sae_timeout(struct sae_sm *sm)
{
	/* regardless of state, reject if sync exceeds max */
	if (sm->sync > SAE_SYNC_MAX) {
		sae_reject_authentication(sm, MMPDU_REASON_CODE_UNSPECIFIED);
		return;
	}

	sm->sync++;

	switch (sm->state) {
	case SAE_STATE_COMMITTED:
		sae_send_commit(sm, true);
		break;
	case SAE_STATE_CONFIRMED:
		sm->sc++;
		sae_send_confirm(sm);
		break;
	default:
		/* should never happen */
		l_error("SAE timeout in bad state %u", sm->state);
		return;
	}
}

/*
 * 802.11-2016 - Section 12.4.8.6.4
 * If the Status code is ANTI_CLOGGING_TOKEN_REQUIRED, a new SAE Commit message
 * shall be constructed with the Anti-Clogging Token from the received
 * Authentication frame, and the commit-scalar and COMMIT-ELEMENT previously
 * sent. The new SAE Commit message shall be transmitted to the peer, Sync shall
 * be zeroed, and the t0 (retransmission) timer shall be set.
 */
static void sae_process_anti_clogging(struct sae_sm *sm, const uint8_t *ptr,
					size_t len)
{
	/*
	 * IEEE 802.11-2016 - Section 12.4.6 Anti-clogging tokens
	 *
	 * It is suggested that an Anti-Clogging Token not exceed 256 octets
	 */
	if (len > 256) {
		l_error("anti-clogging token size %zu too large, 256 max", len);
		return;
	}

	sm->token = l_memdup(ptr + 2, len - 2);
	sm->token_len = len - 2;
	sm->sync = 0;

	sae_send_commit(sm, true);
}

/*
 * 802.11-2016 - 12.4.8.6.3 Protocol instance behavior - Nothing state
 */
static bool sae_verify_nothing(struct sae_sm *sm, uint16_t transaction,
					uint16_t status, const uint8_t *frame,
					size_t len)
{
	/*
	 * TODO: This does not handle the transition from NOTHING -> CONFIRMED
	 * as this is only relevant to the AP or in Mesh mode which is not
	 * yet supported.
	 */
	if (transaction != SAE_STATE_COMMITTED)
		return false;

	/* frame shall be silently discarded and Del event sent */
	if (status != 0) {
		sae_authentication_failed(sm, MMPDU_REASON_CODE_UNSPECIFIED);
		return false;
	}

	/* reject with unsupported group */
	if (l_get_le16(frame) != 19) {
		sae_reject_authentication(sm,
				MMPDU_REASON_CODE_UNSUPP_FINITE_CYCLIC_GROUP);
		return false;
	}

	return true;
}

/*
 * 802.11-2016 - 12.4.8.6.4 Protocol instance behavior - Committed state
 */
static bool sae_verify_committed(struct sae_sm *sm, uint16_t transaction,
					uint16_t status, const uint8_t *frame,
					size_t len)
{
	/*
	 * Upon receipt of a Con event...
	 * Then the protocol instance checks the value of Sync. If it
	 * is greater than dot11RSNASAESync, the protocol instance shall send a
	 * Del event to the parent process and transition back to Nothing state.
	 * If Sync is not greater than dot11RSNASAESync, the protocol instance
	 * shall increment Sync, transmit the last SAE Commit message sent to
	 * the peer...
	 */
	if (transaction == SAE_STATE_CONFIRMED) {
		if (sm->sync > SAE_SYNC_MAX) {
			sae_authentication_failed(sm,
						MMPDU_REASON_CODE_UNSPECIFIED);
			return false;
		}

		sm->sync++;

		sae_send_commit(sm, true);

		return false;
	}

	switch (status) {
	case MMPDU_REASON_CODE_ANTI_CLOGGING_TOKEN_REQ:
		sae_process_anti_clogging(sm, frame, len);
		return false;
	case MMPDU_REASON_CODE_UNSUPP_FINITE_CYCLIC_GROUP:
		l_error("AP requested unsupported FCC group %d",
				l_get_le16(frame));

		goto reject_unsupp_group;
	case 0:
		if (l_get_le16(frame) != 19) {
			if (sm->sync > SAE_SYNC_MAX) {
				sae_authentication_failed(sm,
						MMPDU_REASON_CODE_UNSPECIFIED);
				return false;
			}

			sm->sync++;

			goto reject_unsupp_group;
		}

		return true;
	default:
		/*
		 * If the Status is some other nonzero value, the frame shall
		 * be silently discarded...
		 */
		return false;
	}

reject_unsupp_group:
	sae_reject_authentication(sm,
			MMPDU_REASON_CODE_UNSUPP_FINITE_CYCLIC_GROUP);
	return false;
}

/*
 * 802.11-2016 - 12.4.8.6.5 Protocol instance behavior - Confirmed state
 */
static bool sae_verify_confirmed(struct sae_sm *sm, uint16_t trans,
					uint16_t status, const uint8_t *frame,
					size_t len)
{
	if (trans == SAE_STATE_CONFIRMED)
		return true;

	/*
	 * If the Status is nonzero, the frame shall be silently discarded...
	 */
	if (status != 0)
		return false;

	/*
	 * If Sync is greater than dot11RSNASAESync, the protocol instance
	 * shall send the parent process a Del event and transitions back to
	 * Nothing state.
	 */
	if (sm->sync > SAE_SYNC_MAX) {
		sae_authentication_failed(sm, MMPDU_REASON_CODE_UNSPECIFIED);
		return false;
	}

	/* frame shall be silently discarded */
	if (l_get_le16(frame) != 19)
		return false;

	/*
	 * the protocol instance shall increment Sync, increment Sc, and
	 * transmit its Commit and Confirm (with the new Sc value) messages.
	 */
	sm->sync++;
	sm->sc++;

	sae_send_commit(sm, true);
	sae_send_confirm(sm);

	return false;
}

/*
 * 802.11-2016 - 12.4.8.6.6 Protocol instance behavior - Accepted state
 */
static bool sae_verify_accepted(struct sae_sm *sm, uint16_t trans,
					uint16_t status, const uint8_t *frame,
					size_t len)
{
	uint16_t sc;

	/* spec does not specify what to do here, so print and discard */
	if (trans != SAE_STATE_CONFIRMED) {
		l_error("received transaction %u in accepted state", trans);
		return false;
	}

	if (sm->sync > SAE_SYNC_MAX) {
		sae_authentication_failed(sm, MMPDU_REASON_CODE_UNSPECIFIED);
		return false;
	}

	sc = l_get_le16(frame);

	/*
	 * ... the value of send-confirm shall be checked. If the value is not
	 * greater than Rc or is equal to 2^16 - 1, the received frame shall be
	 * silently discarded.
	 */
	if (sc <= sm->rc || sc == 0xffff)
		return false;

	/*
	 * If the verification fails, the received frame shall be silently
	 * discarded.
	 */
	if (!sae_verify_confirm(sm, frame))
		return false;

	/*
	 * If the verification succeeds, the Rc variable shall be set to the
	 * send-confirm portion of the frame, the Sync shall be incremented and
	 * a new SAE Confirm message shall be constructed (with Sc set to
	 * 2^16 - 1) and sent to the peer.
	 */
	sm->sync++;
	sm->sc = 0xffff;

	sae_send_confirm(sm);

	/*
	 * Since the confirmed needed special processing because of accepted
	 * state we don't want the standard code path to execute.
	 */
	return false;
}

static bool sae_verify_packet(struct sae_sm *sm, uint16_t trans,
				uint16_t status, const uint8_t *frame,
				size_t len)
{
	if (trans != SAE_STATE_COMMITTED && trans != SAE_STATE_CONFIRMED)
		return false;

	switch (sm->state) {
	case SAE_STATE_NOTHING:
		return sae_verify_nothing(sm, trans, status, frame, len);
	case SAE_STATE_COMMITTED:
		return sae_verify_committed(sm, trans, status, frame, len);
	case SAE_STATE_CONFIRMED:
		return sae_verify_confirmed(sm, trans, status, frame, len);
	case SAE_STATE_ACCEPTED:
		return sae_verify_accepted(sm, trans, status, frame, len);
	}

	/* should never get here */
	return false;
}

void sae_rx_packet(struct sae_sm *sm, const uint8_t *from, const uint8_t *frame,
				size_t len)
{
	uint16_t transaction;
	uint16_t status;
	const uint8_t *ptr = frame;

	if (len < 4) {
		l_error("bad packet length");
		goto reject;
	}

	transaction = l_get_le16(ptr);
	ptr += 2;
	status = l_get_le16(ptr);
	ptr += 2;

	/* AP rejected authentication */
	if (len == 4) {
		sae_authentication_failed(sm, status);
		return;
	}

	if (!sae_verify_packet(sm, transaction, status, ptr, len - 4))
		return;

	switch (transaction) {
	case SAE_STATE_COMMITTED:
		sae_process_commit(sm, from, ptr, len - 4);
		return;
	case SAE_STATE_CONFIRMED:
		sae_process_confirm(sm, from, ptr, len - 4);
		return;
	default:
		l_error("invalid transaction sequence %u", transaction);
	}

reject:
	sae_reject_authentication(sm, MMPDU_REASON_CODE_UNSPECIFIED);
}

void sae_start(struct sae_sm *sm)
{
	if (sm->handshake->authenticator)
		memcpy(sm->peer, sm->handshake->spa, 6);
	else
		memcpy(sm->peer, sm->handshake->aa, 6);

	sae_send_commit(sm, false);
}

struct sae_sm *sae_sm_new(struct handshake_state *hs, sae_tx_packet_func_t tx,
				sae_complete_func_t complete, void *user_data)
{
	struct sae_sm *sm;

	sm = l_new(struct sae_sm, 1);

	if (!sm)
		return NULL;

	sm->tx = tx;
	sm->complete = complete;
	sm->user_data = user_data;
	sm->handshake = hs;
	sm->state = SAE_STATE_NOTHING;

	return sm;
}

void sae_sm_free(struct sae_sm *sm)
{
	l_free(sm->token);

	/* zero out whole structure, including keys */
	memset(sm, 0, sizeof(struct sae_sm));

	l_free(sm);
}
