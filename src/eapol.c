/*
 *
 *  Wireless daemon for Linux
 *
 *  Copyright (C) 2013-2014  Intel Corporation. All rights reserved.
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

#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <linux/if.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <arpa/inet.h>
#include <ell/ell.h>

#include "sha1.h"
#include "crypto.h"
#include "eapol.h"
#include "ie.h"
#include "util.h"
#include "mpdu.h"

struct l_queue *state_machines;
eapol_tx_packet_func_t tx_packet = NULL;
eapol_get_nonce_func_t get_nonce = NULL;
eapol_install_tk_func_t install_tk = NULL;
eapol_install_gtk_func_t install_gtk = NULL;
eapol_deauthenticate_func_t deauthenticate = NULL;
enum eapol_protocol_version protocol_version = EAPOL_PROTOCOL_VERSION_2004;

#define VERIFY_IS_ZERO(field)					\
	do {							\
		unsigned int i;					\
		for (i = 0; i < sizeof(field); i++)		\
			if ((field)[i] != 0)			\
				return false;			\
	} while (false)						\

/*
 * MIC calculation depends on the selected hash function.  The has function
 * is given in the EAPoL Key Descriptor Version field.
 *
 * The MIC length is always 16 bytes for currently known Key Descriptor
 * Versions.
 *
 * The input struct eapol_key *frame should have a zero-d MIC field
 */
bool eapol_calculate_mic(const uint8_t *kck, const struct eapol_key *frame,
				uint8_t *mic)
{
	size_t frame_len = sizeof(struct eapol_key);

	frame_len += L_BE16_TO_CPU(frame->key_data_len);

	switch (frame->key_descriptor_version) {
	case EAPOL_KEY_DESCRIPTOR_VERSION_HMAC_MD5_ARC4:
		return hmac_md5(kck, 16, frame, frame_len, mic, 16);
	case EAPOL_KEY_DESCRIPTOR_VERSION_HMAC_SHA1_AES:
		return hmac_sha1(kck, 16, frame, frame_len, mic, 16);
	case EAPOL_KEY_DESCRIPTOR_VERSION_AES_128_CMAC_AES:
		return cmac_aes(kck, 16, frame, frame_len, mic, 16);
	default:
		return false;
	}
}

bool eapol_verify_mic(const uint8_t *kck, const struct eapol_key *frame)
{
	size_t frame_len = sizeof(struct eapol_key);
	uint8_t mic[16];
	struct iovec iov[3];
	struct l_checksum *checksum = NULL;

	iov[0].iov_base = (void *) frame;
	iov[0].iov_len = offsetof(struct eapol_key, key_mic_data);

	memset(mic, 0, sizeof(mic));
	iov[1].iov_base = mic;
	iov[1].iov_len = sizeof(mic);

	iov[2].iov_base = ((void *) frame) +
				offsetof(struct eapol_key, key_data_len);
	iov[2].iov_len = frame_len - offsetof(struct eapol_key, key_data_len) +
				L_BE16_TO_CPU(frame->key_data_len);

	switch (frame->key_descriptor_version) {
	case EAPOL_KEY_DESCRIPTOR_VERSION_HMAC_MD5_ARC4:
		checksum = l_checksum_new_hmac(L_CHECKSUM_MD5, kck, 16);
		break;
	case EAPOL_KEY_DESCRIPTOR_VERSION_HMAC_SHA1_AES:
		checksum = l_checksum_new_hmac(L_CHECKSUM_SHA1, kck, 16);
		break;
	case EAPOL_KEY_DESCRIPTOR_VERSION_AES_128_CMAC_AES:
		checksum = l_checksum_new_cmac_aes(kck, 16);
		break;
	default:
		return false;
	}

	if (checksum == NULL)
		return false;

	l_checksum_updatev(checksum, iov, 3);
	l_checksum_get_digest(checksum, mic, 16);
	l_free(checksum);

	if (!memcmp(frame->key_mic_data, mic, 16))
		return true;

	return false;
}

uint8_t *eapol_decrypt_key_data(const uint8_t *kek,
				const struct eapol_key *frame,
				size_t *decrypted_size)
{
	size_t key_data_len = L_BE16_TO_CPU(frame->key_data_len);
	const uint8_t *key_data = frame->key_data;
	size_t expected_len;
	uint8_t *buf;

	switch (frame->key_descriptor_version) {
	case EAPOL_KEY_DESCRIPTOR_VERSION_HMAC_MD5_ARC4:
		expected_len = key_data_len;
		break;
	case EAPOL_KEY_DESCRIPTOR_VERSION_HMAC_SHA1_AES:
	case EAPOL_KEY_DESCRIPTOR_VERSION_AES_128_CMAC_AES:
		expected_len = key_data_len - 8;
		break;
	default:
		return NULL;
	};

	buf = l_new(uint8_t, expected_len);

	switch (frame->key_descriptor_version) {
	case EAPOL_KEY_DESCRIPTOR_VERSION_HMAC_MD5_ARC4:
	{
		uint8_t key[32];
		bool ret;

		memcpy(key, frame->eapol_key_iv, 16);
		memcpy(key + 16, kek, 16);

		ret = arc4_skip(key, 32, 256, key_data, key_data_len, buf);
		memset(key, 0, sizeof(key));

		if (!ret)
			goto error;

		break;
	}
	case EAPOL_KEY_DESCRIPTOR_VERSION_HMAC_SHA1_AES:
	case EAPOL_KEY_DESCRIPTOR_VERSION_AES_128_CMAC_AES:
		if (key_data_len < 8 || key_data_len % 8)
			goto error;

		if (!aes_unwrap(kek, key_data, key_data_len, buf))
			goto error;

		break;
	}

	if (decrypted_size)
		*decrypted_size = expected_len;

	return buf;

error:
	l_free(buf);
	return NULL;
}

const struct eapol_key *eapol_key_validate(const uint8_t *frame, size_t len)
{
	const struct eapol_key *ek;
	uint16_t key_data_len;

	if (len < sizeof(struct eapol_key))
		return NULL;

	ek = (const struct eapol_key *) frame;

	if (ek->protocol_version != EAPOL_PROTOCOL_VERSION_2001 &&
			ek->protocol_version != EAPOL_PROTOCOL_VERSION_2004)
		return NULL;

	if (ek->packet_type != 3)
		return NULL;

	switch (ek->descriptor_type) {
	case EAPOL_DESCRIPTOR_TYPE_RC4:
	case EAPOL_DESCRIPTOR_TYPE_80211:
	case EAPOL_DESCRIPTOR_TYPE_WPA:
		break;
	default:
		return NULL;
	}

	switch (ek->key_descriptor_version) {
	case EAPOL_KEY_DESCRIPTOR_VERSION_HMAC_MD5_ARC4:
	case EAPOL_KEY_DESCRIPTOR_VERSION_HMAC_SHA1_AES:
	case EAPOL_KEY_DESCRIPTOR_VERSION_AES_128_CMAC_AES:
		break;
	default:
		return NULL;
	}

	key_data_len = L_BE16_TO_CPU(ek->key_data_len);
	if (len < sizeof(struct eapol_key) + key_data_len)
		return NULL;

	return ek;
}

#define VERIFY_PTK_COMMON(ek)	\
	if (!ek->key_type)	\
		return false;	\
	if (ek->smk_message)	\
		return false;	\
	if (ek->request)	\
		return false;	\
	if (ek->error)		\
		return false	\

bool eapol_verify_ptk_1_of_4(const struct eapol_key *ek)
{
	/* Verify according to 802.11, Section 11.6.6.2 */
	VERIFY_PTK_COMMON(ek);

	if (ek->install)
		return false;

	if (!ek->key_ack)
		return false;

	if (ek->key_mic)
		return false;

	if (ek->secure)
		return false;

	if (ek->encrypted_key_data)
		return false;

	if (ek->wpa_key_id)
		return false;

	VERIFY_IS_ZERO(ek->eapol_key_iv);
	VERIFY_IS_ZERO(ek->key_rsc);
	VERIFY_IS_ZERO(ek->reserved);
	VERIFY_IS_ZERO(ek->key_mic_data);

	return true;
}

bool eapol_verify_ptk_2_of_4(const struct eapol_key *ek)
{
	uint16_t key_len;

	/* Verify according to 802.11, Section 11.6.6.3 */
	VERIFY_PTK_COMMON(ek);

	if (ek->install)
		return false;

	if (ek->key_ack)
		return false;

	if (!ek->key_mic)
		return false;

	if (ek->secure)
		return false;

	if (ek->encrypted_key_data)
		return false;

	if (ek->wpa_key_id)
		return false;

	key_len = L_BE16_TO_CPU(ek->key_length);
	if (key_len != 0)
		return false;

	VERIFY_IS_ZERO(ek->eapol_key_iv);
	VERIFY_IS_ZERO(ek->key_rsc);
	VERIFY_IS_ZERO(ek->reserved);

	return true;
}

bool eapol_verify_ptk_3_of_4(const struct eapol_key *ek, bool is_wpa)
{
	uint16_t key_len;

	/* Verify according to 802.11, Section 11.6.6.4 */
	VERIFY_PTK_COMMON(ek);

	/*
	 * TODO: Handle cases where install might be 0:
	 * For PTK generation, 0 only if the AP does not support key mapping
	 * keys, or if the STA has the No Pairwise bit (in the RSN Capabilities
	 * field) equal to 1 and only the group key is used.
	 */
	if (!ek->install)
		return false;

	if (!ek->key_ack)
		return false;

	if (!ek->key_mic)
		return false;

	if (ek->secure != !is_wpa)
		return false;

	/* Must be encrypted when GTK is present but reserved in WPA */
	if (!ek->encrypted_key_data && !is_wpa)
		return false;

	if (ek->wpa_key_id)
		return false;

	key_len = L_BE16_TO_CPU(ek->key_length);
	if (key_len != 16 && key_len != 32)
		return false;

	VERIFY_IS_ZERO(ek->reserved);

	/* 0 (Version 2) or random (Version 1) */
	if (ek->key_descriptor_version ==
			EAPOL_KEY_DESCRIPTOR_VERSION_HMAC_SHA1_AES)
		VERIFY_IS_ZERO(ek->eapol_key_iv);

	return true;
}

bool eapol_verify_ptk_4_of_4(const struct eapol_key *ek, bool is_wpa)
{
	uint16_t key_len;

	/* Verify according to 802.11, Section 11.6.6.5 */
	VERIFY_PTK_COMMON(ek);

	if (ek->install)
		return false;

	if (ek->key_ack)
		return false;

	if (!ek->key_mic)
		return false;

	if (ek->secure != !is_wpa)
		return false;

	if (ek->encrypted_key_data)
		return false;

	if (ek->wpa_key_id)
		return false;

	key_len = L_BE16_TO_CPU(ek->key_length);
	if (key_len != 0)
		return false;

	VERIFY_IS_ZERO(ek->key_nonce);
	VERIFY_IS_ZERO(ek->eapol_key_iv);
	VERIFY_IS_ZERO(ek->key_rsc);
	VERIFY_IS_ZERO(ek->reserved);

	return true;
}

#define VERIFY_GTK_COMMON(ek)	\
	if (ek->key_type)	\
		return false;	\
	if (ek->smk_message)	\
		return false;	\
	if (ek->request)	\
		return false;	\
	if (ek->error)		\
		return false;	\
	if (ek->install)	\
		return false	\

bool eapol_verify_gtk_1_of_2(const struct eapol_key *ek, bool is_wpa)
{
	uint16_t key_len;

	VERIFY_GTK_COMMON(ek);

	if (!ek->key_ack)
		return false;

	if (!ek->key_mic)
		return false;

	if (!ek->secure)
		return false;

	/* Must be encrypted when GTK is present but reserved in WPA */
	if (!ek->encrypted_key_data && !is_wpa)
		return false;

	key_len = L_BE16_TO_CPU(ek->key_length);
	if (key_len == 0)
		return false;

	VERIFY_IS_ZERO(ek->reserved);

	/* 0 (Version 2) or random (Version 1) */
	if (ek->key_descriptor_version ==
			EAPOL_KEY_DESCRIPTOR_VERSION_HMAC_SHA1_AES)
		VERIFY_IS_ZERO(ek->eapol_key_iv);

	/*
	 * WPA_80211_v3_1, Section 2.2.4:
	 * "Key Index (bits 4 and 5): specifies the key id of the temporal
	 * key of the key derived from the message. The value of this shall be
	 * zero (0) if the value of Key Type (bit 4) is Pairwise (1). The Key
	 * Type and Key Index shall not both be 0 in the same message.
	 *
	 * Group keys shall not use key id 0. This means that key ids 1 to 3
	 * are available to be used to identify Group keys. This document
	 * recommends that implementations reserve key ids 1 and 2 for Group
	 * Keys, and that key id 3 is not used.
	 */
	if (is_wpa && !ek->wpa_key_id)
		return false;

	return true;
}

bool eapol_verify_gtk_2_of_2(const struct eapol_key *ek, bool is_wpa)
{
	uint16_t key_len;

	/* Verify according to 802.11, Section 11.6.7.3 */
	VERIFY_GTK_COMMON(ek);

	if (ek->key_ack)
		return false;

	if (!ek->key_mic)
		return false;

	if (!ek->secure)
		return false;

	if (ek->encrypted_key_data)
		return false;

	key_len = L_BE16_TO_CPU(ek->key_length);
	if (key_len != 0)
		return false;

	VERIFY_IS_ZERO(ek->key_nonce);
	VERIFY_IS_ZERO(ek->eapol_key_iv);
	VERIFY_IS_ZERO(ek->key_rsc);
	VERIFY_IS_ZERO(ek->reserved);

	return true;
}

static struct eapol_key *eapol_create_common(
				enum eapol_protocol_version protocol,
				enum eapol_key_descriptor_version version,
				bool secure,
				uint64_t key_replay_counter,
				const uint8_t snonce[],
				size_t extra_len,
				const uint8_t *extra_data,
				int key_type,
				bool is_wpa)
{
	size_t to_alloc = sizeof(struct eapol_key);
	struct eapol_key *out_frame = l_malloc(to_alloc + extra_len);

	memset(out_frame, 0, to_alloc + extra_len);

	out_frame->protocol_version = protocol;
	out_frame->packet_type = 0x3;
	out_frame->packet_len = L_CPU_TO_BE16(to_alloc + extra_len - 4);
	out_frame->descriptor_type = is_wpa ? EAPOL_DESCRIPTOR_TYPE_WPA :
		EAPOL_DESCRIPTOR_TYPE_80211;
	out_frame->key_descriptor_version = version;
	out_frame->key_type = key_type;
	out_frame->install = false;
	out_frame->key_ack = false;
	out_frame->key_mic = true;
	out_frame->secure = secure;
	out_frame->error = false;
	out_frame->request = false;
	out_frame->encrypted_key_data = false;
	out_frame->smk_message = false;
	out_frame->key_length = 0;
	out_frame->key_replay_counter = L_CPU_TO_BE64(key_replay_counter);
	memcpy(out_frame->key_nonce, snonce, sizeof(out_frame->key_nonce));
	out_frame->key_data_len = L_CPU_TO_BE16(extra_len);
	memcpy(out_frame->key_data, extra_data, extra_len);

	return out_frame;
}

struct eapol_key *eapol_create_ptk_2_of_4(
				enum eapol_protocol_version protocol,
				enum eapol_key_descriptor_version version,
				uint64_t key_replay_counter,
				const uint8_t snonce[],
				size_t extra_len,
				const uint8_t *extra_data,
				bool is_wpa)
{
	return eapol_create_common(protocol, version, false, key_replay_counter,
					snonce, extra_len, extra_data, 1,
					is_wpa);
}

struct eapol_key *eapol_create_ptk_4_of_4(
				enum eapol_protocol_version protocol,
				enum eapol_key_descriptor_version version,
				uint64_t key_replay_counter,
				bool is_wpa)
{
	uint8_t snonce[32];

	memset(snonce, 0, sizeof(snonce));
	return eapol_create_common(protocol, version,
					is_wpa ? false : true,
					key_replay_counter, snonce, 0, NULL,
					1, is_wpa);
}

struct eapol_key *eapol_create_gtk_2_of_2(
				enum eapol_protocol_version protocol,
				enum eapol_key_descriptor_version version,
				uint64_t key_replay_counter,
				bool is_wpa, uint8_t wpa_key_id)
{
	uint8_t snonce[32];
	struct eapol_key *step2;

	memset(snonce, 0, sizeof(snonce));
	step2 = eapol_create_common(protocol, version, true,
					key_replay_counter, snonce, 0, NULL,
					0, is_wpa);

	if (!step2)
		return step2;

	/*
	 * WPA_80211_v3_1, Section 2.2.4:
	 * "The Key Type and Key Index shall not both be 0 in the same message"
	 *
	 * The above means that even though sending the key index back to the
	 * AP has no practical value, we must still do so.
	 */
	if (is_wpa)
		step2->wpa_key_id = wpa_key_id;

	return step2;
}

struct eapol_sm {
	uint32_t ifindex;
	uint8_t spa[6];
	uint8_t aa[6];
	uint8_t *ap_ie;
	uint8_t *own_ie;
	uint8_t pmk[32];
	uint64_t replay_counter;
	uint8_t snonce[32];
	uint8_t anonce[32];
	uint8_t ptk[64];
	void *user_data;
	struct l_timeout *timeout;
	bool have_snonce:1;
	bool have_replay:1;
	bool ptk_complete:1;
	bool wpa_ie:1;
};

static void eapol_sm_destroy(void *value)
{
	struct eapol_sm *sm = value;

	l_free(sm->ap_ie);
	l_free(sm->own_ie);

	l_timeout_remove(sm->timeout);

	l_free(sm);
}

struct eapol_sm *eapol_sm_new()
{
	struct eapol_sm *sm;

	sm = l_new(struct eapol_sm, 1);

	return sm;
}

void eapol_sm_free(struct eapol_sm *sm)
{
	eapol_sm_destroy(sm);
}

void eapol_sm_set_supplicant_address(struct eapol_sm *sm, const uint8_t *spa)
{
	memcpy(sm->spa, spa, sizeof(sm->spa));
}

void eapol_sm_set_authenticator_address(struct eapol_sm *sm, const uint8_t *aa)
{
	memcpy(sm->aa, aa, sizeof(sm->aa));
}

void eapol_sm_set_pmk(struct eapol_sm *sm, const uint8_t *pmk)
{
	memcpy(sm->pmk, pmk, sizeof(sm->pmk));
}

static void eapol_sm_set_ap_ie(struct eapol_sm *sm, const uint8_t *ie,
				size_t len, bool is_wpa)
{
	if (ie[1] + 2u != len)
		return;

	l_free(sm->ap_ie);
	sm->ap_ie = l_memdup(ie, len);
	sm->wpa_ie = is_wpa;
}

static void eapol_sm_set_own_ie(struct eapol_sm *sm, const uint8_t *ie,
				size_t len, bool is_wpa)
{
	if (ie[1] + 2u != len)
		return;

	l_free(sm->own_ie);
	sm->own_ie = l_memdup(ie, len);
	sm->wpa_ie = is_wpa;
}

void eapol_sm_set_ap_rsn(struct eapol_sm *sm, const uint8_t *rsn_ie, size_t len)
{
	eapol_sm_set_ap_ie(sm, rsn_ie, len, false);
}

void eapol_sm_set_own_rsn(struct eapol_sm *sm, const uint8_t *rsn_ie,
				size_t len)
{
	eapol_sm_set_own_ie(sm, rsn_ie, len, false);
}

void eapol_sm_set_ap_wpa(struct eapol_sm *sm, const uint8_t *wpa_ie, size_t len)
{
	eapol_sm_set_ap_ie(sm, wpa_ie, len, true);
}

void eapol_sm_set_own_wpa(struct eapol_sm *sm, const uint8_t *wpa_ie,
				size_t len)
{
	eapol_sm_set_own_ie(sm, wpa_ie, len, true);
}

void eapol_sm_set_user_data(struct eapol_sm *sm, void *user_data)
{
	sm->user_data = user_data;
}

static bool eapol_sm_ifindex_match(void *data, void *user_data)
{
	struct eapol_sm *sm = data;
	uint32_t ifindex = L_PTR_TO_UINT(user_data);

	if (sm->ifindex != ifindex)
		return false;

	eapol_sm_free(sm);

	return true;
}

void eapol_cancel(uint32_t ifindex)
{
	l_queue_foreach_remove(state_machines, eapol_sm_ifindex_match,
					L_UINT_TO_PTR(ifindex));
}

static inline void handshake_failed(uint32_t ifindex, struct eapol_sm *sm,
					uint16_t reason_code)
{
	if (deauthenticate)
		deauthenticate(ifindex, sm->aa, sm->spa, reason_code,
				sm->user_data);

	l_queue_remove(state_machines, sm);
	eapol_sm_free(sm);
}

static void eapol_timeout(struct l_timeout *timeout, void *user_data)
{
	struct eapol_sm *sm = user_data;

	handshake_failed(sm->ifindex, sm,
				MPDU_REASON_CODE_4WAY_HANDSHAKE_TIMEOUT);
}

void eapol_start(uint32_t ifindex, struct eapol_sm *sm)
{
	sm->ifindex = ifindex;
	sm->timeout = l_timeout_create(2, eapol_timeout, sm, NULL);
	l_queue_push_head(state_machines, sm);
}

static void eapol_handle_ptk_1_of_4(uint32_t ifindex, struct eapol_sm *sm,
					const struct eapol_key *ek,
					void *user_data)
{
	struct crypto_ptk *ptk = (struct crypto_ptk *) sm->ptk;
	struct eapol_key *step2;
	uint8_t mic[16];

	if (!eapol_verify_ptk_1_of_4(ek)) {
		handshake_failed(ifindex, sm, MPDU_REASON_CODE_UNSPECIFIED);
		return;
	}

	if (!get_nonce(sm->snonce)) {
		handshake_failed(ifindex, sm, MPDU_REASON_CODE_UNSPECIFIED);
		return;
	}

	sm->have_snonce = true;
	sm->ptk_complete = false;

	memcpy(sm->anonce, ek->key_nonce, sizeof(ek->key_nonce));

	crypto_derive_pairwise_ptk(sm->pmk, sm->spa, sm->aa,
					sm->anonce, sm->snonce,
					ptk, sizeof(sm->ptk));

	step2 = eapol_create_ptk_2_of_4(protocol_version,
					ek->key_descriptor_version,
					sm->replay_counter,
					sm->snonce,
					sm->own_ie[1] + 2, sm->own_ie,
					sm->wpa_ie);

	if (!eapol_calculate_mic(ptk->kck, step2, mic)) {
		l_info("MIC calculation failed. "
			"Ensure Kernel Crypto is available.");
		l_free(step2);
		handshake_failed(ifindex, sm, MPDU_REASON_CODE_UNSPECIFIED);

		return;
	}

	memcpy(step2->key_mic_data, mic, sizeof(mic));
	tx_packet(ifindex, sm->aa, sm->spa, step2, user_data);
	l_free(step2);

	l_timeout_remove(sm->timeout);
	sm->timeout = NULL;
}

static const uint8_t *eapol_find_gtk_kde(const uint8_t *data, size_t data_len,
						size_t *out_gtk_len)
{
	static const unsigned char gtk_oui[] = { 0x00, 0x0f, 0xac, 0x01 };
	struct ie_tlv_iter iter;
	const uint8_t *gtk;
	unsigned int len;

	ie_tlv_iter_init(&iter, data, data_len);

	while (ie_tlv_iter_next(&iter)) {
		if (ie_tlv_iter_get_tag(&iter) != IE_TYPE_VENDOR_SPECIFIC)
			continue;

		len = ie_tlv_iter_get_length(&iter);
		if (len < 4)		/* Take care of padding */
			return NULL;

		/* Check OUI */
		gtk = ie_tlv_iter_get_data(&iter);
		if (memcmp(gtk, gtk_oui, 4))
			continue;

		if (out_gtk_len)
			*out_gtk_len = len - 4;

		return gtk + 4;
	}

	return NULL;
}

static const uint8_t *eapol_find_rsne(const uint8_t *data, size_t data_len)
{
	struct ie_tlv_iter iter;

	ie_tlv_iter_init(&iter, data, data_len);

	while (ie_tlv_iter_next(&iter)) {
		if (ie_tlv_iter_get_tag(&iter) != IE_TYPE_RSN)
			continue;

		return ie_tlv_iter_get_data(&iter) - 2;
	}

	return NULL;
}

static const uint8_t *eapol_find_wpa_ie(const uint8_t *data, size_t data_len)
{
	struct ie_tlv_iter iter;

	ie_tlv_iter_init(&iter, data, data_len);

	while (ie_tlv_iter_next(&iter)) {
		if (ie_tlv_iter_get_tag(&iter) != IE_TYPE_VENDOR_SPECIFIC)
			continue;

		if (is_ie_wpa_ie(ie_tlv_iter_get_data(&iter),
				ie_tlv_iter_get_length(&iter)))
			return ie_tlv_iter_get_data(&iter) - 2;
	}

	return NULL;
}

/*
 * This function performs a match of the RSN/WPA IE obtained from the scan
 * results vs the RSN/WPA IE obtained as part of the 4-way handshake.  If they
 * don't match, the EAPoL packet must be silently discarded.
 */
static bool eapol_ap_ie_matches(const uint8_t *eapol_ie,
				const uint8_t *scan_ie, bool is_wpa)
{
	struct ie_rsn_info eapol_info;
	struct ie_rsn_info scan_info;

	/*
	 * First check that the sizes match, if they do, run a bitwise
	 * comparison.
	 */
	if (eapol_ie[1] == scan_ie[1] &&
			!memcmp(eapol_ie + 2, scan_ie + 2, eapol_ie[1]))
		return true;

	/*
	 * Otherwise we have to parse the IEs and compare the individual
	 * fields
	 */
	if (!is_wpa) {
		if (ie_parse_rsne_from_data(eapol_ie, eapol_ie[1] + 2,
						&eapol_info) < 0)
			return false;

		if (ie_parse_rsne_from_data(scan_ie, scan_ie[1] + 2,
						&scan_info) < 0)
			return false;
	} else {
		if (ie_parse_wpa_from_data(eapol_ie, eapol_ie[1] + 2,
						&eapol_info) < 0)
			return false;

		if (ie_parse_wpa_from_data(scan_ie, scan_ie[1] + 2,
						&scan_info) < 0)
			return false;
	}

	if (eapol_info.group_cipher != scan_info.group_cipher)
		return false;

	if (eapol_info.pairwise_ciphers != scan_info.pairwise_ciphers)
		return false;

	if (eapol_info.akm_suites != scan_info.akm_suites)
		return false;

	if (eapol_info.preauthentication != scan_info.preauthentication)
		return false;

	if (eapol_info.no_pairwise != scan_info.no_pairwise)
		return false;

	if (eapol_info.ptksa_replay_counter != scan_info.ptksa_replay_counter)
		return false;

	if (eapol_info.gtksa_replay_counter != scan_info.gtksa_replay_counter)
		return false;

	if (eapol_info.mfpr != scan_info.mfpr)
		return false;

	if (eapol_info.mfpc != scan_info.mfpc)
		return false;

	if (eapol_info.peerkey_enabled != scan_info.peerkey_enabled)
		return false;

	if (eapol_info.spp_a_msdu_capable != scan_info.spp_a_msdu_capable)
		return false;

	if (eapol_info.spp_a_msdu_required != scan_info.spp_a_msdu_required)
		return false;

	if (eapol_info.pbac != scan_info.pbac)
		return false;

	if (eapol_info.extended_key_id != scan_info.extended_key_id)
		return false;

	/* We don't check the PMKIDs since these might actually be different */

	if (eapol_info.group_management_cipher !=
			scan_info.group_management_cipher)
		return false;

	return true;
}

static void eapol_handle_ptk_3_of_4(uint32_t ifindex,
					struct eapol_sm *sm,
					const struct eapol_key *ek,
					const uint8_t *decrypted_key_data,
					size_t decrypted_key_data_size,
					void *user_data)
{
	struct crypto_ptk *ptk = (struct crypto_ptk *) sm->ptk;
	struct eapol_key *step4;
	uint8_t mic[16];
	const uint8_t *gtk;
	size_t gtk_len;
	const uint8_t *rsne;
	uint8_t gtk_key_index;

	if (!eapol_verify_ptk_3_of_4(ek, sm->wpa_ie)) {
		handshake_failed(ifindex, sm, MPDU_REASON_CODE_UNSPECIFIED);
		return;
	}

	/*
	 * 11.6.6.4: "On reception of Message 3, the Supplicant silently
	 * discards the message if ... or if the ANonce value in Message 3
	 * differs from the ANonce value in Message 1"
	 */
	if (memcmp(sm->anonce, ek->key_nonce, sizeof(ek->key_nonce)))
		return;

	/*
	 * 11.6.6.4: "Verifies the RSNE. If it is part of a Fast BSS Transition
	 * Initial Mobility Domain Association, see 12.4.2. Otherwise, if it is
	 * not identical to that the STA received in the Beacon or Probe
	 * Response frame, the STA shall disassociate.
	 */
	if (!sm->wpa_ie)
		rsne = eapol_find_rsne(decrypted_key_data,
					decrypted_key_data_size);
	else
		rsne = eapol_find_wpa_ie(decrypted_key_data,
					decrypted_key_data_size);

	if (!rsne) {
		handshake_failed(ifindex, sm, MPDU_REASON_CODE_IE_DIFFERENT);
		return;
	}

	if (!eapol_ap_ie_matches(rsne, sm->ap_ie, sm->wpa_ie)) {
		handshake_failed(ifindex, sm, MPDU_REASON_CODE_IE_DIFFERENT);
		return;
	}

	/*
	 * TODO: Parse second RSNE
	 * 11.6.6.4: "If a second RSNE is provided in the message, the
	 * Supplicant uses the pairwise cipher suite specified in the second
	 * RSNE or deauthenticates."
	 */

	/*
	 * TODO: Handle IE_RSN_CIPHER_SUITE_NO_GROUP_TRAFFIC case
	 */
	if (!sm->wpa_ie) {
		gtk = eapol_find_gtk_kde(decrypted_key_data,
						decrypted_key_data_size,
						&gtk_len);
		if (!gtk || gtk_len < 8) {
			handshake_failed(ifindex, sm,
						MPDU_REASON_CODE_UNSPECIFIED);
			return;
		}

		/* TODO: Handle tx bit */

		gtk_key_index = util_bit_field(gtk[0], 0, 2);
		gtk += 2;
		gtk_len -= 2;
	} else
		gtk = NULL;

	step4 = eapol_create_ptk_4_of_4(protocol_version,
					ek->key_descriptor_version,
					sm->replay_counter, sm->wpa_ie);

	/*
	 * 802.11-2012, Section 11.6.6.4, step b):
	 * Verifies the Message 3 MIC. If the calculated MIC does not match
	 * the MIC that the Authenticator included in the EAPOL-Key frame,
	 * the Supplicant silently discards Message 3.
	 */
	if (!eapol_calculate_mic(ptk->kck, step4, mic))
		goto fail;

	memcpy(step4->key_mic_data, mic, sizeof(mic));
	tx_packet(ifindex, sm->aa, sm->spa, step4, user_data);

	sm->ptk_complete = true;

	if (install_tk)
		install_tk(sm->ifindex, sm->aa, ptk->tk, rsne, sm->user_data);

	if (gtk && install_gtk)
		install_gtk(sm->ifindex, gtk_key_index, gtk, gtk_len,
				ek->key_rsc, 6, rsne, sm->user_data);

fail:
	l_free(step4);
}

static void eapol_handle_gtk_1_of_2(uint32_t ifindex,
					struct eapol_sm *sm,
					const struct eapol_key *ek,
					const uint8_t *decrypted_key_data,
					size_t decrypted_key_data_size,
					void *user_data)
{
	struct crypto_ptk *ptk = (struct crypto_ptk *) sm->ptk;
	struct eapol_key *step2;
	uint8_t mic[16];
	const uint8_t *gtk;
	size_t gtk_len;
	uint8_t gtk_key_index;

	if (!eapol_verify_gtk_1_of_2(ek, sm->wpa_ie)) {
		handshake_failed(ifindex, sm, MPDU_REASON_CODE_UNSPECIFIED);
		return;
	}

	if (!sm->wpa_ie) {
		gtk = eapol_find_gtk_kde(decrypted_key_data,
						decrypted_key_data_size,
						&gtk_len);

		if (!gtk || gtk_len < 8)
			return;
	} else {
		gtk = decrypted_key_data;
		gtk_len = decrypted_key_data_size;

		if (!gtk || gtk_len < 6)
			return;
	}

	if (!sm->wpa_ie) {
		gtk_key_index = util_bit_field(gtk[0], 0, 2);
		gtk += 2;
		gtk_len -= 2;
	} else
		gtk_key_index = ek->wpa_key_id;

	step2 = eapol_create_gtk_2_of_2(protocol_version,
					ek->key_descriptor_version,
					sm->replay_counter, sm->wpa_ie,
					ek->wpa_key_id);

	/*
	 * 802.11-2012, Section 11.6.7.3, step b):
	 * Verifies that the MIC is valid, i.e., it uses the KCK that is
	 * part of the PTK to verify that there is no data integrity error.
	 */
	ptk = (struct crypto_ptk *) sm->ptk;

	if (!eapol_calculate_mic(ptk->kck, step2, mic))
		goto done;

	memcpy(step2->key_mic_data, mic, sizeof(mic));
	tx_packet(ifindex, sm->aa, sm->spa, step2, user_data);

	if (install_gtk)
		install_gtk(sm->ifindex, gtk_key_index, gtk, gtk_len,
				ek->key_rsc, 6, sm->ap_ie, sm->user_data);

done:
	l_free(step2);
}

static struct eapol_sm *eapol_find_sm(uint32_t ifindex,
						const uint8_t *spa,
						const uint8_t *aa)
{
	const struct l_queue_entry *entry;
	struct eapol_sm *sm;

	for (entry = l_queue_get_entries(state_machines); entry;
					entry = entry->next) {
		sm = entry->data;

		if (sm->ifindex != ifindex)
			continue;

		if (memcmp(sm->spa, spa, 6))
			continue;

		if (memcmp(sm->aa, aa, 6))
			continue;

		return sm;
	}

	return NULL;
}

void __eapol_rx_packet(uint32_t ifindex, const uint8_t *spa, const uint8_t *aa,
			const uint8_t *frame, size_t len, void *user_data)
{
	const struct eapol_key *ek;
	struct eapol_sm *sm;
	struct crypto_ptk *ptk;
	uint8_t *decrypted_key_data = NULL;
	size_t key_data_len = 0;
	uint64_t replay_counter;

	ek = eapol_key_validate(frame, len);
	if (!ek)
		return;

	sm = eapol_find_sm(ifindex, spa, aa);
	if (!sm)
		return;

	/* Wrong direction */
	if (!ek->key_ack)
		return;

	/* Further Descriptor Type check */
	if (!sm->wpa_ie && ek->descriptor_type != EAPOL_DESCRIPTOR_TYPE_80211)
		return;
	else if (sm->wpa_ie && ek->descriptor_type != EAPOL_DESCRIPTOR_TYPE_WPA)
		return;

	replay_counter = L_BE64_TO_CPU(ek->key_replay_counter);

	/*
	 * 11.6.6.2: "If the Key Replay Counter field value is less than or
	 * equal to the current local value, the Supplicant discards the
	 * message.
	 *
	 * 11.6.6.4: "On reception of Message 3, the Supplicant silently
	 * discards the message if the Key Replay Counter field value has
	 * already been used...
	 */
	if (sm->have_replay && sm->replay_counter >= replay_counter)
		return;

	sm->replay_counter = replay_counter;
	sm->have_replay = true;

	ptk = (struct crypto_ptk *) sm->ptk;

	if (ek->key_mic) {
		/* Haven't received step 1 yet, so no ptk */
		if (!sm->have_snonce)
			return;

		if (!eapol_verify_mic(ptk->kck, ek))
			return;
	}

	if ((ek->encrypted_key_data && !sm->wpa_ie) ||
			(ek->key_type == 0 && sm->wpa_ie)) {
		/* Haven't received step 1 yet, so no ptk */
		if (!sm->have_snonce)
			return;

		decrypted_key_data = eapol_decrypt_key_data(ptk->kek, ek,
						&key_data_len);
		if (!decrypted_key_data)
			return;
	} else
		key_data_len = L_BE16_TO_CPU(ek->key_data_len);

	if (ek->key_type == 0) {
		/* Only GTK handshake allowed after PTK handshake complete */
		if (!sm->ptk_complete)
			goto done;

		if (!decrypted_key_data)
			goto done;

		eapol_handle_gtk_1_of_2(ifindex, sm, ek,
					decrypted_key_data,
					key_data_len, user_data);
		goto done;
	}

	/* If no MIC, then assume packet 1, otherwise packet 3 */
	if (!ek->key_mic)
		eapol_handle_ptk_1_of_4(ifindex, sm, ek, user_data);
	else {
		if (sm->ptk_complete)
			goto done;

		if (!key_data_len)
			goto done;

		eapol_handle_ptk_3_of_4(ifindex, sm, ek,
					decrypted_key_data ?: ek->key_data,
					key_data_len, user_data);
	}

done:
	l_free(decrypted_key_data);
}

void __eapol_set_tx_packet_func(eapol_tx_packet_func_t func)
{
	tx_packet = func;
}

void __eapol_set_get_nonce_func(eapol_get_nonce_func_t func)
{
	get_nonce = func;
}

void __eapol_set_protocol_version(enum eapol_protocol_version version)
{
	protocol_version = version;
}

void __eapol_set_install_tk_func(eapol_install_tk_func_t func)
{
	install_tk = func;
}

void __eapol_set_install_gtk_func(eapol_install_gtk_func_t func)
{
	install_gtk = func;
}

void __eapol_set_deauthenticate_func(eapol_deauthenticate_func_t func)
{
	deauthenticate = func;
}

struct l_io *eapol_open_pae(uint32_t index)
{
	struct l_io *io;
	struct sockaddr_ll sll;
	int fd;

	fd = socket(PF_PACKET, SOCK_DGRAM | SOCK_CLOEXEC, htons(ETH_P_PAE));
	if (fd < 0) {
		l_error("Failed to create PAE socket %s (%d)",
						strerror(errno), errno);
		return NULL;
	}

	memset(&sll, 0, sizeof(sll));
	sll.sll_family = AF_PACKET;
	sll.sll_protocol = htons(ETH_P_PAE);
	sll.sll_ifindex = index;

	if (bind(fd, (struct sockaddr *) &sll, sizeof(sll)) < 0) {
		l_error("Failed to bind PAE socket %s (%d)",
						strerror(errno), errno);
		close(fd);
		return NULL;
	}

	io = l_io_new(fd);
	if (!io) {
		l_error("Failed to create IO handling for PAE socket ");
		close(fd);
		return NULL;
	}

	l_io_set_close_on_destroy(io, true);

	return io;
}

/*
 * Default implementation of the frame transmission function.
 * This function expects an fd to be passed as user_data
 */
static int eapol_write(uint32_t ifindex, const uint8_t *aa, const uint8_t *spa,
			const struct eapol_key *ek, void *user_data)
{
	int fd = L_PTR_TO_INT(user_data);
	size_t frame_size;
	struct sockaddr_ll sll;
	ssize_t r;

	memset(&sll, 0, sizeof(sll));
	sll.sll_family = AF_PACKET;
	sll.sll_ifindex = ifindex;
	sll.sll_protocol = htons(ETH_P_PAE);
	sll.sll_halen = ETH_ALEN;
	memcpy(sll.sll_addr, aa, ETH_ALEN);

	frame_size = sizeof(struct eapol_key) + L_BE16_TO_CPU(ek->key_data_len);

	r = sendto(fd, ek, frame_size, 0,
			(struct sockaddr *) &sll, sizeof(sll));
	if (r < 0) {
		l_error("EAPoL write socket: %s", strerror(errno));
		return -errno;
	}

	return 0;
}

static bool eapol_get_nonce(uint8_t nonce[])
{
	return l_getrandom(nonce, 32);
}

bool eapol_init()
{
	state_machines = l_queue_new();
	protocol_version = EAPOL_PROTOCOL_VERSION_2004;
	get_nonce = eapol_get_nonce;
	tx_packet = eapol_write;

	return true;
}

bool eapol_exit()
{
	l_queue_destroy(state_machines, eapol_sm_destroy);
	get_nonce = NULL;
	tx_packet = NULL;

	return true;
}
