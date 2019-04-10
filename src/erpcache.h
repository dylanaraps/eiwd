/*
 *
 *  Wireless daemon for Linux
 *
 *  Copyright (C) 2019  Intel Corporation. All rights reserved.
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

void erp_add_key(const char *id, const void *session_id, size_t session_len,
			const void *emsk, size_t emsk_len,
			const char *ssid, const char *erp_domain);

void erp_remove_key(const char *id);

bool erp_find_key_by_identity(const char *id, void *session,
			size_t *session_len, void *emsk, size_t *emsk_len,
			const char **erp_domain);

bool erp_has_key_for_ssid(const char *ssid);

bool erp_has_key_for_identity(const char *id);

void erp_init(void);
void erp_exit(void);
