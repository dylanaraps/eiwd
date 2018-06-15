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

/*
 * EAP-SIM/EAP-AKA shared values
 */
#define EAP_SIM_MK_LEN		20
#define EAP_SIM_K_ENCR_LEN	16
#define EAP_SIM_K_AUT_LEN	16
#define EAP_AKA_PRIME_K_AUT_LEN	32
#define EAP_SIM_MSK_LEN		64
#define EAP_SIM_EMSK_LEN	64
#define EAP_SIM_IV_LEN		16
#define EAP_SIM_MAC_LEN		16
#define EAP_SIM_RAND_LEN	16
#define EAP_AKA_K_RE_LEN	32
#define EAP_AKA_IK_LEN		16
#define EAP_AKA_CK_LEN		16

/*
 * Possible pad types for EAP-SIM/EAP-AKA attributes
 *
 * NONE - No padding, data passed in immediately follows type/size
 * ZERO - Zero pad where "real" length would be
 * LENGTH - A "real" data length in bytes immediately follows type/size
 * LENGTH_BITS - A "real" data length in bits follows type/size
 */
#define EAP_SIM_PAD_NONE		0
#define EAP_SIM_PAD_ZERO		1
#define EAP_SIM_PAD_LENGTH		2
#define EAP_SIM_PAD_LENGTH_BITS		3

/*
 * Round up value to nearest word
 */
#define EAP_SIM_ROUND(x) ((x + 3) & ~0x3)

struct eap_sim_tlv_iter {
	const uint8_t *pos;
	const uint8_t *end;
	uint8_t tag;
	uint16_t len;
	const uint8_t *data;
};

/*
 * RFC 4187, section 11
 */
enum eap_sim_at {
	EAP_SIM_AT_RAND			= 0x01,
	EAP_SIM_AT_AUTN			= 0x02,
	EAP_SIM_AT_RES			= 0x03,
	EAP_SIM_AT_AUTS			= 0x04,
	EAP_SIM_AT_PADDING		= 0x06,
	EAP_SIM_AT_NONCE		= 0x07,
	EAP_SIM_AT_PERMANENT_ID_REQ	= 0x0a,
	EAP_SIM_AT_MAC			= 0x0b,
	EAP_SIM_AT_NOTIFICATION		= 0x0c,
	EAP_SIM_AT_ANY_ID_REQ		= 0x0d,
	EAP_SIM_AT_IDENTITY		= 0x0e,
	EAP_SIM_AT_VERSION_LIST		= 0x0f,
	EAP_SIM_AT_SELECTED_VERSION	= 0x10,
	EAP_SIM_AT_FULLAUTH_ID_REQ	= 0x11,
	EAP_SIM_AT_COUNTER		= 0x13,
	EAP_SIM_AT_NONCE_S		= 0x15,
	EAP_SIM_AT_CLIENT_ERROR_CODE	= 0x16,
	EAP_SIM_AT_KDF_INPUT		= 0x17,
	EAP_SIM_AT_KDF			= 0x18,
	EAP_SIM_AT_IV			= 0x81,
	EAP_SIM_AT_ENCR_DATA		= 0x82,
	EAP_SIM_AT_NEXT_PSEUDONYM	= 0x84,
	EAP_SIM_AT_NEXT_REAUTH_ID	= 0x85,
	EAP_SIM_AT_CHECKCODE		= 0x86,
	EAP_SIM_AT_RESULT_IND		= 0x87,
	EAP_SIM_AT_BIDDING		= 0x88
};

/*
 * Possible client error's
 */
enum eap_sim_error {
	EAP_SIM_ERROR_PROCESS = 0,
	EAP_SIM_ERROR_VERSION_VERSION,
	EAP_SIM_ERROR_CHALLENGE,
	EAP_SIM_ERROR_RANDS
};

/*
 * Notification error codes (and success).
 */
enum eap_sim_fail {
	EAP_SIM_FAIL_AFTER_AUTH		= 0,
	EAP_SIM_FAIL_DENIED_ACCESS	= 1026,
	EAP_SIM_FAIL_NOT_SUBSCRIBED	= 1031,
	EAP_SIM_FAIL_BEFORE_AUTH	= 16384,
	EAP_SIM_SUCCESS			= 32768
};

/*
 * RFC 4186 Appendix B. FIPS 186 Pseudo-random number generator
 *
 * seed - PRF seed, e.g. the Master Key (MK)
 * slen - seed length
 * out - PRF output buffer
 * olen - length of out
 */
void eap_sim_fips_prf(const void *seed, size_t slen, uint8_t *out, size_t olen);

/*
 * 3GPP TS 35.206
 *
 * Algorithm for generating milenage parameters.
 *
 * opc - Input: OPc value
 * k - Input: K key value
 * rand - Input: Rand from server
 * sqn - Input: Sequence number
 * amf - Input: AMF value
 *
 * autn - Output: AUTN computed
 * ck - Output: CK computed
 * ik - Output: IK computed
 * res - Output: RES computed
 *
 * Internal Functions used:
 * f1 and f1* output MAC-A and MAC-S. MAC-A along with SQN/AK/AMF make AUTN
 * f2 outputs RES where RES == OUT2[8-16]
 * f3 outputs CK where CK == OUT3[0-16]
 * f4 outputs IK where IK == OUT4[0-16]
 * f5 outputs AK where AK == OUT2[0-6]
 *
 * f5* outputs AK', not used with EAP-AKA
 */
bool eap_aka_get_milenage(const uint8_t *opc, const uint8_t *k,
		const uint8_t *rand, const uint8_t *sqn, const uint8_t *amf,
		uint8_t *autn, uint8_t *ck, uint8_t *ik, uint8_t *res);

/*
 * 3GPP TS 33.402
 * Derivation of CK' and IK' from CK and IK
 *
 * FC = 0x20
 * P0 = access network identity ('network')
 * L0 = length of P0
 * P1 = SQN ^ AK = first 6 bytes of AUTN
 * L1 = length of P1 = 0x0006
 *
 * (CK' | IK') = HMAC_SHA256(FC |P0 | L0 | P1 | L1)
 */
bool eap_aka_derive_primes(const uint8_t *ck, const uint8_t *ik,
		const uint8_t *autn, const uint8_t *network, uint16_t net_len,
		uint8_t *ck_p, uint8_t *ik_p);

/*
 * RFC 5448, Section 3.4.1
 *
 * PRF'(K,S) = T1 | T2 | T3 | T4 | ...
 *
 *     where:
 *     T1 = HMAC-SHA-256 (K, S | 0x01)
 *     T2 = HMAC-SHA-256 (K, T1 | S | 0x02)
 *     T3 = HMAC-SHA-256 (K, T2 | S | 0x03)
 *     T4 = HMAC-SHA-256 (K, T3 | S | 0x04)
 *     ...
 *
 * RFC 5448, Section 3.3
 *
 * MK = PRF'(IK'|CK',"EAP-AKA'"|Identity)
 *      K_encr = MK[0..127]
 *      K_aut  = MK[128..383]
 *      K_re   = MK[384..639]
 *      MSK    = MK[640..1151]
 *      EMSK   = MK[1152..1663]
 */
bool eap_aka_prf_prime(const uint8_t *ik_p, const uint8_t *ck_p,
		const char *identity, uint8_t *k_encr, uint8_t *k_aut,
		uint8_t *k_re, uint8_t *msk, uint8_t *emsk);

/*
 * Separate PRNG data into encryption keys. k_encr and k_aut may be NULL in the
 * case of fast re-authentication.
 *
 * buf - output data from the PRNG, 160 bytes
 * k_encr - first 16 bytes of buf
 * k_aut - next 16 bytes of buf
 * msk - next 64 bytes of buf
 * emsk - next 64 bytes of buf
 */
bool eap_sim_get_encryption_keys(const uint8_t *buf, uint8_t *k_encr,
		uint8_t *k_aut, uint8_t *msk, uint8_t *emsk);

/*
 * Derive a packets MAC. This can be used to compute the packets MAC in place,
 * by setting mac to the proper zero'ed location in buf.
 *
 * buf - the SIM packet, including MAC portion zero'ed, plus extra (e.g. SRES)
 * len - the total length of buf
 * key - encryption key to use (e.g. K_encr)
 * mac - buffer for the 16 byte MAC
 */
bool eap_sim_derive_mac(enum eap_type type, const uint8_t *buf, size_t len,
		const uint8_t *key, uint8_t *mac);

/*
 * Helper to build the EAP packet header
 *
 * eap - eap_state, used to get the identifier
 * method - EAP method (SIM or AKA)
 * type - EAP-SIM subtype
 * buf - EAP packet
 * len - length of packet
 */
size_t eap_sim_build_header(struct eap_state *eap, enum eap_type method,
		uint8_t type, uint8_t *buf, uint16_t len);

/*
 * Signal that the client has detected an error
 *
 * eap - eap_state
 * type - type of EAP method (SIM or AKA)
 * code - error code to send
 */
void eap_sim_client_error(struct eap_state *eap, enum eap_type type,
		uint16_t code);

/*
 * Add an EAP-SIM attribute to a buffer.
 *
 * buf - pointer to start of EAP-SIM attribute
 * attr - type of attribute
 * ptype - Padding type AT_PAD_ZERO, AT_PAD_NONE or AT_PAD_LENGTH
 * data - EAP-SIM attribute data, if NULL zeros will be written
 * dlen - length of data pointer in bytes
 *
 * Returns the number of bytes written to buf.
 */
size_t eap_sim_add_attribute(uint8_t *buf, enum eap_sim_at attr,
		uint8_t ptype, const uint8_t *data, uint16_t dlen);

/*
 * Verify a packets MAC
 *
 * eap - eap_state pointer, used to rebuild the EAP header
 * buf - should point to the start of the EAP-SIM packet
 * len - length of EAP packet
 * extra - Any extra block of data needed to compute the MAC
 * elen - Length of 'extra'
 */
bool eap_sim_verify_mac(struct eap_state *eap, enum eap_type type,
		const uint8_t *buf, uint16_t len, uint8_t *k_aut,
		uint8_t *extra, size_t elen);

bool eap_sim_tlv_iter_init(struct eap_sim_tlv_iter *iter, const uint8_t *data,
		uint32_t len);

bool eap_sim_tlv_iter_next(struct eap_sim_tlv_iter *iter);

uint8_t eap_sim_tlv_iter_get_type(struct eap_sim_tlv_iter *iter);

uint16_t eap_sim_tlv_iter_get_length(struct eap_sim_tlv_iter *iter);

const void *eap_sim_tlv_iter_get_data(struct eap_sim_tlv_iter *iter);
