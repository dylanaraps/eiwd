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

struct sae_sm;
struct handshake_state;

typedef int (*sae_tx_packet_func_t)(const uint8_t *dest, const uint8_t *frame,
					size_t len, void *user_data);

typedef void (*sae_complete_func_t)(uint16_t status, void *user_data);

struct sae_sm *sae_sm_new(struct handshake_state *hs, sae_tx_packet_func_t tx,
				sae_complete_func_t complete, void *user_data);
void sae_sm_free(struct sae_sm *sm);

void sae_rx_packet(struct sae_sm *sm, const uint8_t *src,
				const uint8_t *frame, size_t len);
void sae_timeout(struct sae_sm *sm);

void sae_start(struct sae_sm *sm);
