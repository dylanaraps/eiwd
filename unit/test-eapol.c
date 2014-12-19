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

#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <ell/ell.h>

#include "src/eapol.h"

struct eapol_key_data {
	const unsigned char *frame;
	size_t frame_len;
	enum eapol_protocol_version protocol_version;
	uint16_t packet_len;
	enum eapol_descriptor_type descriptor_type;
	enum eapol_key_descriptor_version key_descriptor_version;
	bool key_type:1;
	bool install:1;
	bool key_ack:1;
	bool key_mic:1;
	bool secure:1;
	bool error:1;
	bool request:1;
	bool encrypted_key_data:1;
	bool smk_message:1;
	uint16_t key_length;
	uint8_t key_replay_counter[8];
	uint8_t key_nonce[32];
	uint8_t eapol_key_iv[16];
	uint8_t key_rsc[8];
	uint8_t key_mic_data[16];
	uint16_t key_data_len;
};

static const unsigned char eapol_key_data_1[] = {
	0x01, 0x03, 0x00, 0x5f, 0xfe, 0x00, 0x89, 0x00, 0x20, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x01, 0xd5, 0xe2, 0x13, 0x9b, 0x1b, 0x1c, 0x1e,
	0xcb, 0xf4, 0xc7, 0x9d, 0xb3, 0x70, 0xcd, 0x1c, 0xea, 0x07, 0xf1, 0x61,
	0x76, 0xed, 0xa6, 0x78, 0x8a, 0xc6, 0x8c, 0x2c, 0xf4, 0xd7, 0x6f, 0x2b,
	0xf7, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00,
};

static struct eapol_key_data eapol_key_test_1 = {
	.frame = eapol_key_data_1,
	.frame_len = sizeof(eapol_key_data_1),
	.protocol_version = EAPOL_PROTOCOL_VERSION_2001,
	.packet_len = 95,
	.descriptor_type = EAPOL_DESCRIPTOR_TYPE_WPA,
	.key_descriptor_version = EAPOL_KEY_DESCRIPTOR_VERSION_HMAC_MD5_ARC4,
	.key_type = true,
	.install = false,
	.key_ack = true,
	.key_mic = false,
	.secure = false,
	.error = false,
	.request = false,
	.encrypted_key_data = false,
	.smk_message = false,
	.key_length = 32,
	.key_replay_counter =
		{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 },
	.key_nonce = { 0xd5, 0xe2, 0x13, 0x9b, 0x1b, 0x1c, 0x1e, 0xcb, 0xf4,
			0xc7, 0x9d, 0xb3, 0x70, 0xcd, 0x1c, 0xea, 0x07, 0xf1,
			0x61, 0x76, 0xed, 0xa6, 0x78, 0x8a, 0xc6, 0x8c, 0x2c,
			0xf4, 0xd7, 0x6f, 0x2b, 0xf7 },
	.eapol_key_iv = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
	.key_rsc = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
	.key_mic_data = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
	.key_data_len = 0,
};

static void eapol_key_test(const void *data)
{
	const struct eapol_key_data *test = data;
	struct eapol_key *packet;

	packet = (struct eapol_key *)test->frame;

	assert(packet->protocol_version == test->protocol_version);
	assert(packet->packet_type == 0x03);
	assert(L_BE16_TO_CPU(packet->packet_len) == test->packet_len);
	assert(packet->descriptor_type == test->descriptor_type);
	assert(packet->key_descriptor_version == test->key_descriptor_version);
	assert(packet->key_type == test->key_type);
	assert(packet->install == test->install);
	assert(packet->key_ack == test->key_ack);
	assert(packet->key_mic == test->key_mic);
	assert(packet->secure == test->secure);
	assert(packet->error == test->error);
	assert(packet->request == test->request);
	assert(packet->encrypted_key_data == test->encrypted_key_data);
	assert(packet->smk_message == test->smk_message);
	assert(L_BE16_TO_CPU(packet->key_length) == test->key_length);
	assert(!memcmp(packet->key_replay_counter, test->key_replay_counter,
			sizeof(packet->key_replay_counter)));
	assert(!memcmp(packet->key_nonce, test->key_nonce,
			sizeof(packet->key_nonce)));
	assert(!memcmp(packet->eapol_key_iv, test->eapol_key_iv,
			sizeof(packet->eapol_key_iv)));
	assert(!memcmp(packet->key_mic_data, test->key_mic_data,
			sizeof(packet->key_mic_data)));
	assert(!memcmp(packet->key_rsc, test->key_rsc,
			sizeof(packet->key_rsc)));
	assert(L_BE16_TO_CPU(packet->key_data_len) == test->key_data_len);
}

int main(int argc, char *argv[])
{
	l_test_init(&argc, &argv);

	l_test_add("/EAPoL Key/Key Frame 1",
			eapol_key_test, &eapol_key_test_1);

	return l_test_run();
}
