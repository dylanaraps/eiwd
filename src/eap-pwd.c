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

#include <ell/ell.h>

#include "eap.h"
#include "util.h"
#include "ecc.h"

#define EAP_PWD_GROUP_DESC	19
#define EAP_PWD_RAND_FN		0x01
#define EAP_PWD_PRF		0x01

/* EAP header + PWD-Exch */
#define EAP_PWD_HDR_LEN		6
#define EAP_PWD_L_BIT		(1 << 7)
#define EAP_PWD_M_BIT		(1 << 6)

enum eap_pwd_prep {
	EAP_PWD_PREP_NONE =	0x00,
	EAP_PWD_PREP_MS =	0x01,
	EAP_PWD_PREP_SASL =	0x02
};

enum eap_pwd_exch {
	EAP_PWD_EXCH_RESERVED = 0,
	EAP_PWD_EXCH_ID,
	EAP_PWD_EXCH_COMMIT,
	EAP_PWD_EXCH_CONFIRM
};

enum eap_pwd_state {
	EAP_PWD_STATE_INIT = 0,
	EAP_PWD_STATE_ID,
	EAP_PWD_STATE_COMMIT,
	EAP_PWD_STATE_CONFIRM
};

struct eap_pwd_handle {
	enum eap_pwd_state state;
	enum eap_pwd_prep prep;
	char *identity;
	char *password;
	struct ecc_point pwe;
	struct ecc_point element_s;
	struct ecc_point element_p;
	uint32_t ciphersuite;
	uint64_t scalar_s[NUM_ECC_DIGITS];
	uint64_t scalar_p[NUM_ECC_DIGITS];
	uint64_t p_rand[NUM_ECC_DIGITS];
	uint8_t *rx_frag_buf;
	uint16_t rx_frag_total;
	uint16_t rx_frag_count;
	uint8_t *tx_frag_buf;
	uint8_t *tx_frag_pos;
	uint16_t tx_frag_remaining;
};

static uint64_t curve_p[NUM_ECC_DIGITS] = CURVE_P_32;

static bool H(uint8_t num_args, uint8_t *out, ...)
{
	struct l_checksum *hmac;
	struct iovec iov[num_args];
	uint8_t k[32] = { 0 };
	va_list va;
	int i;
	int ret;

	va_start(va, out);

	hmac = l_checksum_new_hmac(L_CHECKSUM_SHA256, k, 32);
	if (!hmac)
		return false;

	for (i = 0; i < num_args; i++) {
		iov[i].iov_base = va_arg(va, void *);
		iov[i].iov_len = va_arg(va, size_t);
	}

	if (!l_checksum_updatev(hmac, iov, num_args))
		return false;

	ret = l_checksum_get_digest(hmac, out, 32);
	l_checksum_free(hmac);

	return (ret == 32);
}

/* RFC 5931, Section 2.5 - Key Derivation Function */
static bool kdf(uint8_t *key, size_t key_len, const char *label,
		size_t label_len, void *out, size_t olen)
{
	struct l_checksum *hmac;
	struct iovec iov[4];
	uint16_t ibuf, i = 1;
	uint16_t L = L_CPU_TO_BE16(olen * 8);
	size_t len = 0;

	while (len < olen) {
		int iov_pos = 0;

		hmac = l_checksum_new_hmac(L_CHECKSUM_SHA256, key, key_len);
		if (!hmac)
			return false;

		/* PRF(key, K(i - 1) | i | label | L) */
		if (i > 1) {
			iov[iov_pos].iov_base = out + len - 32;
			iov[iov_pos++].iov_len = 32;
		}

		ibuf = L_CPU_TO_BE16(i);
		iov[iov_pos].iov_base = (void *) &ibuf;
		iov[iov_pos++].iov_len = 2;
		iov[iov_pos].iov_base = (void *)label;
		iov[iov_pos++].iov_len = label_len;
		iov[iov_pos].iov_base = &L;
		iov[iov_pos++].iov_len = 2;

		if (!l_checksum_updatev(hmac, iov, iov_pos))
			return false;

		l_checksum_get_digest(hmac, out + len, 32);
		l_checksum_free(hmac);

		len += 32;
		i++;
	}

	return true;
}

static void eap_pwd_free(struct eap_state *eap)
{
	struct eap_pwd_handle *pwd = eap_get_data(eap);

	l_free(pwd->identity);
	l_free(pwd->password);
	l_free(pwd->tx_frag_buf);
	l_free(pwd->rx_frag_buf);
	l_free(pwd);

	eap_set_data(eap, NULL);
}

static void eap_pwd_send_response(struct eap_state *eap,
					uint8_t *pkt, size_t len)
{
	struct eap_pwd_handle *pwd = eap_get_data(eap);
	size_t mtu = eap_get_mtu(eap);
	uint8_t frag[mtu];
	uint8_t *pos = frag;
	/* first fragment data bytes (mtu - header - Total-Length) */
	uint16_t send_bytes = mtu - EAP_PWD_HDR_LEN - 2;

	/* packet will fit within mtu */
	if (len <= mtu) {
		eap_send_response(eap, EAP_TYPE_PWD, pkt, len);
		return;
	}

	if (pwd->tx_frag_buf) {
		l_error("already processing fragment, cannot send response");
		return;
	}

	/* header */
	memcpy(pos, pkt, 5);
	pos += 5;
	/* PWD-Exch, first frag, so L and M are both set */
	*pos++ = pwd->state | EAP_PWD_L_BIT | EAP_PWD_M_BIT;
	/* Total-Length */
	l_put_be16((uint16_t)len, pos);
	pos += 2;
	/* copy packet data bytes */
	memcpy(pos, pkt + EAP_PWD_HDR_LEN, send_bytes);

	pwd->tx_frag_remaining = len - EAP_PWD_HDR_LEN - send_bytes;

	l_info("sending initial fragment, %zu bytes", mtu);

	eap_send_response(eap, EAP_TYPE_PWD, frag, mtu);

	/* alloc/copy remainder of packet to frag buf */
	pwd->tx_frag_buf = l_malloc(pwd->tx_frag_remaining);

	memcpy(pwd->tx_frag_buf, pkt + EAP_PWD_HDR_LEN + send_bytes,
			pwd->tx_frag_remaining);

	pwd->tx_frag_pos = pwd->tx_frag_buf;
}

static void eap_pwd_handle_id(struct eap_state *eap,
				const uint8_t *pkt, size_t len)
{
	struct eap_pwd_handle *pwd = eap_get_data(eap);
	uint16_t group;
	uint8_t rand_fn;
	uint8_t prf;
	uint32_t token;
	uint8_t counter = 1;
	uint8_t resp[15 + strlen(pwd->identity)];
	uint8_t *pos;
	uint8_t pwd_seed[ECC_BYTES];
	uint64_t pwd_value[NUM_ECC_DIGITS];	/* used as X value */
	uint64_t y_value[NUM_ECC_DIGITS];

	/*
	 * Group desc (2) + Random func (1) + prf (1) + token (4) + prep (1) +
	 * Identity (at least 1 byte)
	 */
	if (len < 9) {
		l_error("bad packet length");
		goto error;
	}

	if (pwd->state != EAP_PWD_STATE_INIT) {
		l_error("received ID request in invalid state");
		goto error;
	}

	pwd->state = EAP_PWD_STATE_ID;

	group = l_get_be16(pkt);
	if (group != EAP_PWD_GROUP_DESC) {
		l_error("group %d not supported", group);
		goto error;
	}

	rand_fn = pkt[2];
	if (rand_fn != EAP_PWD_RAND_FN) {
		l_error("rand_fn %d not supported", rand_fn);
		goto error;
	}

	prf = pkt[3];
	if (prf != EAP_PWD_PRF) {
		l_error("PRF function %d not supported", prf);
		goto error;
	}

	/*
	 * RFC 5931 Section 3.2.1
	 * The Group Description, Random Function, and PRF together, and in that
	 * order, comprise the Ciphersuite...
	 */
	pwd->ciphersuite = l_get_u32(pkt);
	token = l_get_u32(pkt + 4);
	pwd->prep = pkt[8];

	if (pwd->prep != EAP_PWD_PREP_NONE) {
		/*
		 * TODO: Support other PW prep types
		 */
		l_error("prep type %d not currently supported", pwd->prep);
		goto error;
	}

	while (counter < 20) {
		/* pwd-seed = H(token|peer-ID|server-ID|password|counter) */
		H(5, pwd_seed, &token, 4, pwd->identity, strlen(pwd->identity),
				pkt + 9, len - 9, pwd->password,
				strlen(pwd->password), &counter, 1);

		/*
		 * pwd-value = KDF(pwd-seed, "EAP-pwd Hunting And Pecking",
		 *                 len(p))
		 */
		kdf(pwd_seed, 32, "EAP-pwd Hunting And Pecking",
				strlen("EAP-pwd Hunting And Pecking"),
				pwd_value, 32);

		ecc_be2native(pwd_value);

		if (ecc_compute_y(y_value, pwd_value)) {
			l_info("computed y in %u tries", counter);

			/* unambiguously choose Y coordinate */
			if ((y_value[0] & 1) != (pwd_seed[31] & 1))
				vli_mod_sub(y_value, curve_p, y_value, curve_p);

			memcpy(pwd->pwe.x, pwd_value, 32);
			memcpy(pwd->pwe.y, y_value, 32);

			if (!ecc_valid_point(&pwd->pwe))
				goto invalid_point;

			break;
		}

		counter++;
	}

	pos = resp + 5; /* header */
	*pos++ = EAP_PWD_EXCH_ID;
	l_put_be16(group, pos);
	pos += 2;
	*pos++ = rand_fn;
	*pos++ = prf;
	l_put_u32(token, pos);
	pos += 4;
	*pos++ = pwd->prep;
	memcpy(pos, pwd->identity, strlen(pwd->identity));
	pos += strlen(pwd->identity);

	eap_pwd_send_response(eap, resp, pos - resp);

	return;

invalid_point:
	l_error("point not on curve");
error:
	eap_method_error(eap);
}

static void eap_pwd_handle_commit(struct eap_state *eap,
					const uint8_t *pkt, size_t len)
{
	struct eap_pwd_handle *pwd = eap_get_data(eap);
	uint8_t resp[102];
	uint8_t *pos;
	uint64_t p_mask[NUM_ECC_DIGITS];
	uint64_t one[NUM_ECC_DIGITS] = { 1 };
	uint64_t curve_n[NUM_ECC_DIGITS] = CURVE_N_32;

	if (len != 96) {
		l_error("bad packet length, expected 96, got %zu", len);
		goto error;
	}

	if (pwd->state != EAP_PWD_STATE_ID) {
		l_error("received commit request in invalid state");
		goto error;
	}

	pwd->state = EAP_PWD_STATE_COMMIT;

	/*
	 * RFC 5114 Section 2.6 - 256-bit Random ECP Group
	 * Prime p is 32 bytes in length, therefore x and y will also each be
	 * 32 bytes in length (total of 64), leaving the remainder for the
	 * scalar value (32).
	 */
	memcpy(pwd->element_s.x, pkt, ECC_BYTES);
	memcpy(pwd->element_s.y, pkt + ECC_BYTES, ECC_BYTES);
	memcpy(pwd->scalar_s, pkt + 64, ECC_BYTES);

	ecc_be2native(pwd->element_s.x);
	ecc_be2native(pwd->element_s.y);
	ecc_be2native(pwd->scalar_s);

	if (!ecc_valid_point(&pwd->element_s))
		goto invalid_point;

	/*
	 * RFC 5931 Section 2.8.4.1
	 *
	 * chose two random numbers, 1 < s_rand, s_mask < r
	 * compute Scalar_P and Element_P
	 * Scalar_P = (p_rand + p_mask) mod r
	 * Element_P = inv(p_mask * PWE)
	 */
	l_getrandom(pwd->p_rand, ECC_BYTES);

	/* ensure 1 < p_rand < r */
	while (!((vli_cmp(pwd->p_rand, one) > 0) &&
			(vli_cmp(pwd->p_rand, curve_n) < 0)))
		l_getrandom(pwd->p_rand, ECC_BYTES);

	l_getrandom(p_mask, ECC_BYTES);

	/* ensure 1 < p_mask < r */
	while (!((vli_cmp(p_mask, one) > 0) &&
			(vli_cmp(p_mask, curve_n) < 0)))
		l_getrandom(p_mask, ECC_BYTES);

	vli_mod_add(pwd->scalar_p, pwd->p_rand, p_mask, curve_n);

	/* p_mask * PWE */
	ecc_point_mult(&pwd->element_p, &pwd->pwe, p_mask, NULL,
		vli_num_bits(p_mask));

	if (!ecc_valid_point(&pwd->element_p))
		goto invalid_point;

	/* inv(p_mask * PWE) */
	vli_sub(pwd->element_p.y, curve_p, pwd->element_p.y);

	if (!ecc_valid_point(&pwd->element_p))
		goto invalid_point;

	/* change peer into to MSB first byte ordering before sending back */
	ecc_native2be(pwd->element_p.x);
	ecc_native2be(pwd->element_p.y);
	ecc_native2be(pwd->scalar_p);

	/* send element_p and scalar_p */
	pos = resp + 5; /* header */
	*pos++ = EAP_PWD_EXCH_COMMIT;
	memcpy(pos, pwd->element_p.x, ECC_BYTES);
	pos += ECC_BYTES;
	memcpy(pos, pwd->element_p.y, ECC_BYTES);
	pos += ECC_BYTES;
	memcpy(pos, pwd->scalar_p, ECC_BYTES);
	pos += ECC_BYTES;

	eap_pwd_send_response(eap, resp, pos - resp);

	return;

invalid_point:
	l_error("invalid point during commit exchange");
error:
	eap_method_error(eap);
}

static void eap_pwd_handle_confirm(struct eap_state *eap,
					const uint8_t *pkt, size_t len)
{
	struct eap_pwd_handle *pwd = eap_get_data(eap);
	struct ecc_point kp;
	uint8_t resp[38];
	uint8_t *pos;
	uint64_t confirm_s[NUM_ECC_DIGITS];
	uint8_t confirm_p[ECC_BYTES];
	uint8_t expected_confirm_s[ECC_BYTES];
	uint8_t mk[32];
	uint8_t msk_emsk[128], session_id[33];

	if (len != 32) {
		l_error("bad packet length");
		goto error;
	}

	if (pwd->state != EAP_PWD_STATE_COMMIT) {
		l_error("received confirm request in invalid state");
		goto error;
	}

	pwd->state = EAP_PWD_STATE_CONFIRM;

	memcpy(confirm_s, pkt, ECC_BYTES);

	/* compute KP = (p_rand * (Scalar_S * PWE + Element_S)) */
	ecc_point_mult(&kp, &pwd->pwe, pwd->scalar_s, NULL,
			vli_num_bits(pwd->scalar_s));

	if (!ecc_valid_point(&kp))
		goto invalid_point;

	ecc_point_add(&kp, &kp, &pwd->element_s);

	if (!ecc_valid_point(&kp))
		goto invalid_point;

	ecc_point_mult(&kp, &kp, pwd->p_rand, NULL, vli_num_bits(pwd->p_rand));

	if (!ecc_valid_point(&kp))
		goto invalid_point;

	ecc_native2be(kp.x);
	ecc_native2be(pwd->element_s.x);
	ecc_native2be(pwd->element_s.y);
	ecc_native2be(pwd->scalar_s);

	/*
	 * compute Confirm_P = H(kp | Element_P | Scalar_P |
	 *                       Element_S | Scalar_S | Ciphersuite)
	 */
	H(8, confirm_p, kp.x, ECC_BYTES, pwd->element_p.x, ECC_BYTES,
			pwd->element_p.y, ECC_BYTES, pwd->scalar_p,
			ECC_BYTES, pwd->element_s.x, ECC_BYTES,
			pwd->element_s.y, ECC_BYTES, pwd->scalar_s,
			ECC_BYTES, &pwd->ciphersuite, 4);

	H(8, expected_confirm_s, kp.x, ECC_BYTES, pwd->element_s.x,
			ECC_BYTES, pwd->element_s.y, ECC_BYTES,
			pwd->scalar_s, ECC_BYTES, pwd->element_p.x,
			ECC_BYTES, pwd->element_p.y, ECC_BYTES,
			pwd->scalar_p, ECC_BYTES, &pwd->ciphersuite, 4);

	if (memcmp(confirm_s, expected_confirm_s, ECC_BYTES)) {
		l_error("Confirm_S did not verify");
		goto error;
	}

	pos = resp + 5; /* header */
	*pos++ = EAP_PWD_EXCH_CONFIRM;
	memcpy(pos, confirm_p, ECC_BYTES);
	pos += 32;

	/* derive MK = H(kp | Confirm_P | Confirm_S ) */
	H(3, mk, kp.x, ECC_BYTES, confirm_p, ECC_BYTES,
			confirm_s, ECC_BYTES);

	eap_pwd_send_response(eap, resp, pos - resp);

	eap_method_success(eap);

	session_id[0] = 52;
	H(3, session_id + 1, &pwd->ciphersuite, 4, pwd->scalar_p, ECC_BYTES,
			pwd->scalar_s, ECC_BYTES);
	kdf(mk, 32, (const char *) session_id, 33, msk_emsk, 128);
	eap_set_key_material(eap, msk_emsk, 64, msk_emsk + 64, 64, NULL, 0);

	return;

invalid_point:
	l_error("invalid point during confirm exchange");
error:
	eap_method_error(eap);
}

static void eap_pwd_process(struct eap_state *eap,
				const uint8_t *pkt, size_t len)
{
	uint8_t pwd_exch = util_bit_field(pkt[0], 0, 6);

	if (len < 1)
		return;

	switch (pwd_exch) {
	case EAP_PWD_EXCH_ID:
		eap_pwd_handle_id(eap, pkt + 1, len - 1);
		break;
	case EAP_PWD_EXCH_COMMIT:
		eap_pwd_handle_commit(eap, pkt + 1, len - 1);
		break;
	case EAP_PWD_EXCH_CONFIRM:
		eap_pwd_handle_confirm(eap, pkt + 1, len - 1);
		break;
	}
}

static void eap_pwd_send_ack(struct eap_state *eap)
{
	struct eap_pwd_handle *pwd = eap_get_data(eap);
	uint8_t buf[6];

	buf[5] = pwd->state + 1;

	eap_send_response(eap, EAP_TYPE_PWD, buf, 6);
}

#define FRAG_BYTES(mtu, remaining) \
	((mtu - EAP_PWD_HDR_LEN) < remaining) ? (mtu - EAP_PWD_HDR_LEN) : \
			remaining

static void eap_pwd_handle_request(struct eap_state *eap,
					const uint8_t *pkt, size_t len)
{
	struct eap_pwd_handle *pwd = eap_get_data(eap);
	uint8_t len_bit = false;
	uint8_t more_bit = false;

	/* ACK from tx fragment, send next fragment */
	if (len == 1 && pwd->tx_frag_buf) {
		size_t mtu = eap_get_mtu(eap);
		uint8_t frag[mtu];
		uint8_t *pos = frag;
		uint16_t frag_bytes = FRAG_BYTES(mtu, pwd->tx_frag_remaining);

		pos += 5; /* header */
		*pos = pwd->state;

		/* more fragments coming, set M bit */
		if (frag_bytes < pwd->tx_frag_remaining)
			*pos |= EAP_PWD_M_BIT;

		pos++;

		memcpy(pos, pwd->tx_frag_pos, frag_bytes);

		pwd->tx_frag_pos += frag_bytes;
		pwd->tx_frag_remaining -= frag_bytes;

		l_info("sending fragment, %d bytes",
				frag_bytes + EAP_PWD_HDR_LEN);

		eap_send_response(eap, EAP_TYPE_PWD, frag,
				frag_bytes + EAP_PWD_HDR_LEN);

		if (!pwd->tx_frag_remaining) {
			/* done sending fragments, free */
			l_free(pwd->tx_frag_buf);
			pwd->tx_frag_buf = NULL;
			pwd->tx_frag_pos = NULL;
			pwd->tx_frag_remaining = 0;
		}

		return;
	}

	if (pwd->tx_frag_buf) {
		l_error("received packet while waiting for ACK!");
		return;
	}

	if (len < 1) {
		l_error("packet is too small");
		return;
	}

	/* set if Total-Length parameter is include (i.e. first fragment) */
	len_bit = util_is_bit_set(pkt[0], 7);
	/* set on all but the last fragment */
	more_bit = util_is_bit_set(pkt[0], 6);

	/* first rx fragment */
	if (len_bit) {
		if (len < 3) {
			l_error("malformed packet");
			return;
		}

		/* remove length of Total-Length parameter (2) */
		pwd->rx_frag_total = l_get_be16(pkt + 1) - 2;
		pwd->rx_frag_buf = l_malloc(pwd->rx_frag_total);

		/* skip copying Total-Length for easier processing later */
		pwd->rx_frag_buf[0] = pkt[0];
		memcpy(pwd->rx_frag_buf + 1, pkt + 3, len - 2);

		pwd->rx_frag_count = len - 2;

		l_info("received first fragment, %d total bytes",
				pwd->rx_frag_total);

		eap_pwd_send_ack(eap);

		return;
	}

	/* more rx fragments */
	if (pwd->rx_frag_buf) {
		/* continue building packet (not including PWD-Exch byte) */
		memcpy(pwd->rx_frag_buf + pwd->rx_frag_count, pkt + 1, len - 1);
		pwd->rx_frag_count += (len - 1);

		l_info("received another fragment, %zu bytes", len);

		/* more fragments coming */
		if (more_bit) {
			eap_pwd_send_ack(eap);
			return;
		}

		if (pwd->rx_frag_count != pwd->rx_frag_total) {
			l_error("fragment length mismatch");
			return;
		}

		/* this was the last fragment, process */
		eap_pwd_process(eap, pwd->rx_frag_buf, pwd->rx_frag_total);

		l_free(pwd->rx_frag_buf);
		pwd->rx_frag_buf = NULL;
		pwd->rx_frag_count = 0;
		pwd->rx_frag_total = 0;

		return;
	}

	/* no fragmentation, process normally */
	eap_pwd_process(eap, pkt, len);
}

static int eap_pwd_check_settings(struct l_settings *settings,
					struct l_queue *secrets,
					const char *prefix,
					struct l_queue **out_missing)
{
	const char *identity, *password = NULL;
	const struct eap_secret_info *secret;
	char setting[64];

	snprintf(setting, sizeof(setting), "%sIdentity", prefix);
	identity = l_settings_get_value(settings, "Security", setting);

	if (!identity) {
		secret = l_queue_find(secrets, eap_secret_info_match, setting);
		if (!secret) {
			eap_append_secret(out_missing,
					EAP_SECRET_REMOTE_USER_PASSWORD,
					setting, NULL);
		}

		return 0;
	}

	snprintf(setting, sizeof(setting), "%sPWD-Password", prefix);
	password = l_settings_get_value(settings, "Security", setting);

	if (!password) {
		secret = l_queue_find(secrets, eap_secret_info_match, setting);
		if (!secret) {
			eap_append_secret(out_missing,
					EAP_SECRET_REMOTE_PASSWORD,
					setting, identity);
		}
	}

	return 0;
}

static bool eap_pwd_load_settings(struct eap_state *eap,
					struct l_settings *settings,
					const char *prefix)
{
	struct eap_pwd_handle *pwd;
	char setting[64];

	pwd = l_new(struct eap_pwd_handle, 1);

	pwd->state = EAP_PWD_STATE_INIT;

	snprintf(setting, sizeof(setting), "%sIdentity", prefix);
	pwd->identity = l_strdup(l_settings_get_value(settings, "Security",
			setting));

	if (!pwd->identity) {
		l_error("EAP-Identity is missing");
		goto error;
	}

	snprintf(setting, sizeof(setting), "%sPWD-Password", prefix);
	pwd->password = l_strdup(l_settings_get_value(settings, "Security",
			setting));

	if (!pwd->password) {
		l_error("EAP-PWD password is missing");
		goto error;
	}

	eap_set_data(eap, pwd);

	return true;

error:
	l_free(pwd->identity);
	l_free(pwd->password);
	l_free(pwd);
	return false;
}

static struct eap_method eap_pwd = {
	.request_type = EAP_TYPE_PWD,
	.exports_msk = true,
	.name = "PWD",
	.free = eap_pwd_free,
	.handle_request = eap_pwd_handle_request,
	.check_settings = eap_pwd_check_settings,
	.load_settings = eap_pwd_load_settings,
};

static int eap_pwd_init(void)
{
	l_debug("");
	return eap_register_method(&eap_pwd);
}

static void eap_pwd_exit(void)
{
	l_debug("");
	eap_unregister_method(&eap_pwd);
}

EAP_METHOD_BUILTIN(eap_pwd, eap_pwd_init, eap_pwd_exit)
