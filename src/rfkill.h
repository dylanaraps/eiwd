/*
 *
 *  Wireless daemon for Linux
 *
 *  Copyright (C) 2016  Intel Corporation. All rights reserved.
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

typedef void (*rfkill_state_cb_t)(unsigned int wiphy_id, bool soft,
					bool hard, void *user_data);

uint32_t rfkill_watch_add(rfkill_state_cb_t func, void *user_data);
bool rfkill_watch_remove(uint32_t watch_id);

bool rfkill_get_soft_state(unsigned int wiphy_id);
bool rfkill_set_soft_state(unsigned int wiphy_id, bool state);
bool rfkill_get_hard_state(unsigned int wiphy_id);

int rfkill_init(void);
void rfkill_exit(void);
