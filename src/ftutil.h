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

#include <stdbool.h>

struct handshake_state;

bool ft_calculate_fte_mic(struct handshake_state *hs, uint8_t seq_num,
				const uint8_t *rsne, const uint8_t *fte,
				const uint8_t *ric, uint8_t *out_mic);

bool ft_parse_authentication_resp_frame(const uint8_t *data, size_t len,
				const uint8_t *addr1, const uint8_t *addr2,
				const uint8_t *addr3, uint16_t auth_seq,
				uint16_t *out_status, const uint8_t **out_ies,
				size_t *out_ies_len);
