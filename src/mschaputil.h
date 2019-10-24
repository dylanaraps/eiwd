/*
 *
 *  Wireless daemon for Linux
 *
 *  Copyright (C) 2018-2019  Intel Corporation. All rights reserved.
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

#define NT_CHALLENGE_RESPONSE_LEN 24

bool mschap_challenge_response(const uint8_t *challenge,
						const uint8_t *password_hash,
						uint8_t *response);
bool mschap_nt_password_hash(const char *password, uint8_t *password_hash);
bool mschapv2_hash_nt_password_hash(const uint8_t password_hash[static 16],
					uint8_t password_hash_hash[static 16]);

bool mschapv2_generate_nt_response(const uint8_t password_hash[static 16],
				const uint8_t peer_challenge[static 16],
				const uint8_t server_challenge[static 16],
				const char *user,
				uint8_t response[static 24]);

bool mschapv2_generate_authenticator_response(
				const uint8_t pw_hash_hash[static 16],
				const uint8_t nt_response[static 24],
				const uint8_t peer_challenge[static 16],
				const uint8_t server_challenge[static 16],
				const char *user, char response[static 42]);
