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

struct owe_sm;
struct handshake_state;

typedef void (*owe_tx_authenticate_func_t)(void *user_data);
typedef void (*owe_tx_associate_func_t)(struct iovec *ie_iov, size_t iov_len,
					void *user_data);
typedef void (*owe_complete_func_t)(uint16_t status, void *user_data);

struct owe_sm *owe_sm_new(struct handshake_state *hs,
				owe_tx_authenticate_func_t auth,
				owe_tx_associate_func_t assoc,
				owe_complete_func_t complete, void *user_data);
void owe_sm_free(struct owe_sm *owe);

void owe_start(struct owe_sm *owe);
void owe_rx_authenticate(struct owe_sm *owe);
void owe_rx_associate(struct owe_sm *owe, const uint8_t *frame, size_t len);
