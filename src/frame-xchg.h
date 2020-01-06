/*
 *
 *  Wireless daemon for Linux
 *
 *  Copyright (C) 2020  Intel Corporation. All rights reserved.
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

struct mmpdu_header;

typedef void (*frame_watch_cb_t)(const struct mmpdu_header *frame,
					const void *body, size_t body_len,
					int rssi, void *user_data);
typedef void (*frame_xchg_destroy_func_t)(void *user_data);

bool frame_watch_add(uint64_t wdev_id, uint32_t group, uint16_t frame_type,
			const uint8_t *prefix, size_t prefix_len,
			frame_watch_cb_t handler, void *user_data,
			frame_xchg_destroy_func_t destroy);
bool frame_watch_group_remove(uint64_t wdev_id, uint32_t group);
bool frame_watch_wdev_remove(uint64_t wdev_id);
