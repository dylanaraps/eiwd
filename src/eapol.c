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
#include <ell/ell.h>

#include "sha1.h"
#include "md5.h"
#include "aes.h"
#include "eapol.h"

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

const struct eapol_key *eapol_verify_ptk_1_of_4(const uint8_t *frame,
							size_t len)
{
	const struct eapol_key *ek;

	ek = eapol_key_validate(frame, len);
	if (!ek)
		return NULL;

	/* Verify according to 802.11, Section 11.6.6.2 */
	if (!ek->key_type)
		return NULL;

	if (ek->smk_message)
		return NULL;

	if (ek->install)
		return NULL;

	if (!ek->key_ack)
		return NULL;

	if (ek->key_mic)
		return NULL;

	if (ek->secure)
		return NULL;

	if (ek->error)
		return NULL;

	if (ek->request)
		return NULL;

	if (ek->encrypted_key_data)
		return NULL;

	VERIFY_IS_ZERO(ek->eapol_key_iv);
	VERIFY_IS_ZERO(ek->key_rsc);
	VERIFY_IS_ZERO(ek->reserved);
	VERIFY_IS_ZERO(ek->key_mic_data);

	return ek;
}

const struct eapol_key *eapol_verify_ptk_2_of_4(const uint8_t *frame,
						size_t len)
{
	const struct eapol_key *ek;
	uint16_t key_len;

	ek = eapol_key_validate(frame, len);
	if (!ek)
		return NULL;

	/* Verify according to 802.11, Section 11.6.6.3 */
	if (!ek->key_type)
		return NULL;

	if (ek->smk_message)
		return NULL;

	if (ek->install)
		return NULL;

	if (ek->key_ack)
		return NULL;

	if (!ek->key_mic)
		return NULL;

	if (ek->secure)
		return NULL;

	if (ek->error)
		return NULL;

	if (ek->request)
		return NULL;

	if (ek->encrypted_key_data)
		return NULL;

	key_len = L_BE16_TO_CPU(ek->key_length);
	if (key_len != 0)
		return NULL;

	return ek;
}

static struct eapol_key *eapol_create_common(
				enum eapol_protocol_version protocol,
				enum eapol_key_descriptor_version version,
				bool secure,
				uint64_t key_replay_counter,
				const uint8_t snonce[],
				size_t extra_len,
				const uint8_t *extra_data)
{
	size_t to_alloc = sizeof(struct eapol_key);
	struct eapol_key *out_frame = l_malloc(to_alloc + extra_len);

	memset(out_frame, 0, to_alloc + extra_len);

	out_frame->protocol_version = protocol;
	out_frame->packet_type = 0x3;
	out_frame->packet_len = L_CPU_TO_BE16(to_alloc + extra_len - 4);
	out_frame->descriptor_type = EAPOL_DESCRIPTOR_TYPE_80211;
	out_frame->key_descriptor_version = version;
	out_frame->key_type = true;
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
				const uint8_t *extra_data)
{
	return eapol_create_common(protocol, version, false, key_replay_counter,
					snonce, extra_len, extra_data);
}

struct eapol_key *eapol_create_ptk_4_of_4(
				enum eapol_protocol_version protocol,
				enum eapol_key_descriptor_version version,
				uint64_t key_replay_counter,
				const uint8_t snonce[])
{
	return eapol_create_common(protocol, version, true, key_replay_counter,
					snonce, 0, NULL);
}
