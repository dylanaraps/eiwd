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

/*
 * Generate a private/public key pair. All inputs are expected in little-endian.
 */
bool ecdh_generate_key_pair(void *private, size_t priv_len,
				void *public, size_t pub_len);
/*
 * Generate a shared secret from a private/public key. All inputs are expected
 * in little-endian.
 */
bool ecdh_generate_shared_secret(const void *private, const void *other_public,
					size_t pub_len, void *secret,
					size_t secret_len);
