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

#include "eapol.h"

#define VERIFY_IS_ZERO(field)					\
	do {							\
		unsigned int i;					\
		for (i = 0; i < sizeof(field); i++)		\
			if ((field)[i] != 0)			\
				return false;			\
	} while (false)						\

bool eapol_verify(const uint8_t *data, size_t len)
{
	struct eapol_key *ek;
	uint16_t key_data_len;

	if (len < sizeof(struct eapol_key))
		return false;

	ek = (struct eapol_key *) data;

	if (ek->protocol_version != EAPOL_PROTOCOL_VERSION_2001 &&
			ek->protocol_version != EAPOL_PROTOCOL_VERSION_2004)
		return false;

	if (ek->packet_type != 3)
		return false;

	switch (ek->descriptor_type) {
	case EAPOL_DESCRIPTOR_TYPE_RC4:
	case EAPOL_DESCRIPTOR_TYPE_80211:
	case EAPOL_DESCRIPTOR_TYPE_WPA:
		break;
	default:
		return false;
	}

	switch (ek->key_descriptor_version) {
	case EAPOL_KEY_DESCRIPTOR_VERSION_HMAC_MD5_ARC4:
	case EAPOL_KEY_DESCRIPTOR_VERSION_HMAC_SHA1_AES:
	case EAPOL_KEY_DESCRIPTOR_VERSION_AES_128_CMAC_AES:
		break;
	default:
		return false;
	}

	key_data_len = L_BE16_TO_CPU(ek->key_data_len);
	if (len < sizeof(struct eapol_key) + key_data_len)
		return false;

	return true;
}

bool eapol_process_ptk_1_of_4(const uint8_t *data, size_t len,
				uint8_t out_anonce[])
{
	struct eapol_key *ek;

	if (!eapol_verify(data, len))
		return false;

	ek = (struct eapol_key *) data;

	/* Verify according to 802.11, Section 11.6.6.2 */
	if (!ek->key_type)
		return false;

	if (ek->smk_message)
		return false;

	if (ek->install)
		return false;

	if (!ek->key_ack)
		return false;

	if (ek->key_mic)
		return false;

	if (ek->secure)
		return false;

	if (ek->error)
		return false;

	if (ek->request)
		return false;

	if (ek->encrypted_key_data)
		return false;

	VERIFY_IS_ZERO(ek->eapol_key_iv);
	VERIFY_IS_ZERO(ek->key_rsc);
	VERIFY_IS_ZERO(ek->reserved);
	VERIFY_IS_ZERO(ek->key_mic_data);

	memcpy(out_anonce, ek->key_nonce, sizeof(ek->key_nonce));

	return true;
}

bool eapol_process_ptk_2_of_4(const uint8_t *data, size_t len,
				uint8_t out_snonce[])
{
	struct eapol_key *ek;
	uint16_t key_len;

	if (!eapol_verify(data, len))
		return false;

	ek = (struct eapol_key *) data;

	/* Verify according to 802.11, Section 11.6.6.2 */
	if (!ek->key_type)
		return false;

	if (ek->smk_message)
		return false;

	if (ek->install)
		return false;

	if (ek->key_ack)
		return false;

	if (!ek->key_mic)
		return false;

	if (ek->secure)
		return false;

	if (ek->error)
		return false;

	if (ek->request)
		return false;

	if (ek->encrypted_key_data)
		return false;

	key_len = L_BE16_TO_CPU(ek->key_length);
	if (key_len != 0)
		return false;

	memcpy(out_snonce, ek->key_nonce, sizeof(ek->key_nonce));

	return true;
}
