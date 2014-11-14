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

#include <stdbool.h>
#include <string.h>
#include <errno.h>

#include <ell/ell.h>

#include "sha1.h"
#include "crypto.h"

int crypto_psk_from_passphrase(const char *passphrase,
				const unsigned char *ssid, size_t ssid_len,
				unsigned char *out_psk)
{
	size_t passphrase_len;
	size_t i;
	bool result;
	unsigned char psk[32];

	if (!passphrase)
		return -EINVAL;

	if (!ssid)
		return -EINVAL;

	/*
	 * IEEE 802.11, Annex M, Section M.4.1:
	 * "A pass-phrase is a sequence of between 8 and 63 ASCII-encoded
	 * characters. The limit of 63 comes from the desire to distinguish
	 * between a pass-phrase and a PSK displayed as 64 hexadecimal
	 * characters."
	 */
	passphrase_len = strlen(passphrase);
	if (passphrase_len < 8 || passphrase_len > 63)
		return -ERANGE;

	if (ssid_len == 0 || ssid_len > 32)
		return -ERANGE;

	/* IEEE 802.11, Annex M, Section M.4.1:
	 * "Each character in the pass-phrase must have an encoding in the
	 * range of 32 to 126 (decimal), inclusive."
	 *
	 * This corresponds to printable characters only
	 */
	for (i = 0; i < passphrase_len; i++) {
		if (l_ascii_isprint(passphrase[i]))
			continue;

		return -EINVAL;
	}

	result = pbkdf2_sha1(passphrase, passphrase_len, ssid, ssid_len,
				4096, psk, sizeof(psk));
	if (!result)
		return -ENOKEY;

	if (out_psk)
		memcpy(out_psk, psk, sizeof(psk));

	return 0;
}
