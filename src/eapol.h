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

#include <stdint.h>
#include <stdbool.h>
#include <asm/byteorder.h>
#include <linux/types.h>

enum eapol_protocol_version {
	EAPOL_PROTOCOL_VERSION_2001	= 1,
	EAPOL_PROTOCOL_VERSION_2004	= 2,
};

/*
 * 802.1X-2010: Table 11-5—Descriptor Type value assignments
 * The WPA key type of 254 comes from somewhere else.  Seems it is a legacy
 * value that might still be used by older implementations
 */
enum eapol_descriptor_type {
	EAPOL_DESCRIPTOR_TYPE_RC4	= 1,
	EAPOL_DESCRIPTOR_TYPE_80211	= 2,
	EAPOL_DESCRIPTOR_TYPE_WPA	= 254,
};

enum eapol_key_descriptor_version {
	EAPOL_KEY_DESCRIPTOR_VERSION_AKM_DEFINED	= 0,
	EAPOL_KEY_DESCRIPTOR_VERSION_HMAC_MD5_ARC4	= 1,
	EAPOL_KEY_DESCRIPTOR_VERSION_HMAC_SHA1_AES	= 2,
	EAPOL_KEY_DESCRIPTOR_VERSION_AES_128_CMAC_AES	= 3,
};

struct eapol_sm;
struct handshake_state;
struct preauth_sm;
enum handshake_kde;
enum ie_rsn_akm_suite;

struct eapol_header {
	uint8_t protocol_version;
	uint8_t packet_type;
	__be16 packet_len;
} __attribute__ ((packed));

struct eapol_frame {
	struct eapol_header header;
	uint8_t data[0];
} __attribute__ ((packed));

struct eapol_key {
	struct eapol_header header;
	uint8_t descriptor_type;
#if defined(__LITTLE_ENDIAN_BITFIELD)
	bool key_mic:1;
	bool secure:1;
	bool error:1;
	bool request:1;
	bool encrypted_key_data:1;
	bool smk_message:1;
	uint8_t reserved2:2;
	uint8_t key_descriptor_version:3;
	bool key_type:1;
	uint8_t wpa_key_id:2; /* Bits 4-5 reserved in RSN, Key ID in WPA */
	bool install:1;
	bool key_ack:1;
#elif defined (__BIG_ENDIAN_BITFIELD)
	uint8_t reserved2:2;
	bool smk_message:1;
	bool encrypted_key_data:1;
	bool request:1;
	bool error:1;
	bool secure:1;
	bool key_mic:1;
	bool key_ack:1;
	bool install:1;
	uint8_t wpa_key_id:2; /* Bits 4-5 reserved in RSN, Key ID in WPA */
	bool key_type:1;
	uint8_t key_descriptor_version:3;
#else
#error  "Please fix <asm/byteorder.h>"
#endif

	__be16 key_length;
	__be64 key_replay_counter;
	uint8_t key_nonce[32];
	uint8_t eapol_key_iv[16];
	uint8_t key_rsc[8];
	uint8_t reserved[8];
	uint8_t key_mic_data[16];
	__be16 key_data_len;
	uint8_t key_data[0];
} __attribute__ ((packed));

typedef int (*eapol_tx_packet_func_t)(uint32_t ifindex,
					const uint8_t *dest, uint16_t proto,
					const struct eapol_frame *ef,
					bool noencrypt,
					void *user_data);
typedef void (*eapol_rekey_offload_func_t)(uint32_t ifindex,
					const uint8_t *kek,
					const uint8_t *kck,
					uint64_t replay_counter,
					void *user_data);
typedef void (*eapol_sm_event_func_t)(unsigned int event,
							const void *event_data,
							void *user_data);
typedef void (*eapol_preauth_cb_t)(const uint8_t *pmk, void *user_data);
typedef void (*eapol_preauth_destroy_func_t)(void *user_data);
typedef void (*eapol_frame_watch_func_t)(uint16_t proto, const uint8_t *from,
						const struct eapol_frame *frame,
						void *user_data);

bool eapol_calculate_mic(enum ie_rsn_akm_suite akm, const uint8_t *kck,
				const struct eapol_key *frame, uint8_t *mic);
bool eapol_verify_mic(enum ie_rsn_akm_suite akm, const uint8_t *kck,
			const struct eapol_key *frame);

uint8_t *eapol_decrypt_key_data(enum ie_rsn_akm_suite akm, const uint8_t *kek,
				const struct eapol_key *frame,
				size_t *decrypted_size);
bool eapol_encrypt_key_data(const uint8_t *kek, uint8_t *key_data,
				size_t key_data_len,
				struct eapol_key *out_frame);
void eapol_key_data_append(struct eapol_key *ek, enum handshake_kde selector,
				const uint8_t *data, size_t data_len);

const struct eapol_key *eapol_key_validate(const uint8_t *frame, size_t len);

bool eapol_verify_ptk_1_of_4(const struct eapol_key *ek);
bool eapol_verify_ptk_2_of_4(const struct eapol_key *ek);
bool eapol_verify_ptk_3_of_4(const struct eapol_key *ek, bool is_wpa);
bool eapol_verify_ptk_4_of_4(const struct eapol_key *ek, bool is_wpa);
bool eapol_verify_gtk_1_of_2(const struct eapol_key *ek, bool is_wpa);
bool eapol_verify_gtk_2_of_2(const struct eapol_key *ek, bool is_wpa);

struct eapol_key *eapol_create_ptk_2_of_4(
				enum eapol_protocol_version protocol,
				enum eapol_key_descriptor_version version,
				uint64_t key_replay_counter,
				const uint8_t snonce[],
				size_t extra_len,
				const uint8_t *extra_data,
				bool is_wpa);

struct eapol_key *eapol_create_ptk_4_of_4(
				enum eapol_protocol_version protocol,
				enum eapol_key_descriptor_version version,
				uint64_t key_replay_counter,
				bool is_wpa);

struct eapol_key *eapol_create_gtk_2_of_2(
				enum eapol_protocol_version protocol,
				enum eapol_key_descriptor_version version,
				uint64_t key_replay_counter,
				bool is_wpa, uint8_t wpa_key_id);

const uint8_t *eapol_find_rsne(const uint8_t *data, size_t data_len,
				const uint8_t **optional);

void __eapol_rx_packet(uint32_t ifindex, const uint8_t *src, uint16_t proto,
			const uint8_t *frame, size_t len, bool noencrypt);
void __eapol_tx_packet(uint32_t ifindex, const uint8_t *dst, uint16_t proto,
			const struct eapol_frame *frame, bool noencrypt);
void __eapol_set_tx_packet_func(eapol_tx_packet_func_t func);
void __eapol_set_tx_user_data(void *user_data);

void __eapol_set_rekey_offload_func(eapol_rekey_offload_func_t func);
void __eapol_update_replay_counter(uint32_t ifindex, const uint8_t *spa,
				const uint8_t *aa, uint64_t replay_counter);
void __eapol_set_config(struct l_settings *config);

struct eapol_sm *eapol_sm_new(struct handshake_state *hs);
void eapol_sm_free(struct eapol_sm *sm);

void eapol_sm_set_protocol_version(struct eapol_sm *sm,
				enum eapol_protocol_version protocol_version);

void eapol_sm_set_use_eapol_start(struct eapol_sm *sm, bool enabled);
void eapol_sm_set_require_handshake(struct eapol_sm *sm, bool enabled);
void eapol_sm_set_listen_interval(struct eapol_sm *sm, uint16_t interval);
void eapol_sm_set_user_data(struct eapol_sm *sm, void *user_data);
void eapol_sm_set_event_func(struct eapol_sm *sm, eapol_sm_event_func_t func);

void eapol_register(struct eapol_sm *sm);
void eapol_register_authenticator(struct eapol_sm *sm);
bool eapol_start(struct eapol_sm *sm);

uint32_t eapol_frame_watch_add(uint32_t ifindex,
				eapol_frame_watch_func_t handler,
				void *user_data);
bool eapol_frame_watch_remove(uint32_t id);

struct preauth_sm *eapol_preauth_start(const uint8_t *aa,
					const struct handshake_state *hs,
					eapol_preauth_cb_t cb, void *user_data,
					eapol_preauth_destroy_func_t destroy);
void eapol_preauth_cancel(uint32_t ifindex);

bool eapol_init();
bool eapol_exit();
