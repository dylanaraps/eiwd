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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <errno.h>
#include <ell/ell.h>

#include "eap.h"

struct eap_md5_state {
	char *secret;
};

static void eap_md5_free(struct eap_state *eap)
{
	struct eap_md5_state *md5 = eap_get_data(eap);

	eap_set_data(eap, NULL);

	l_free(md5->secret);
	l_free(md5);
}

static void eap_md5_handle_request(struct eap_state *eap,
					const uint8_t *pkt, size_t len)
{
	struct eap_md5_state *md5 = eap_get_data(eap);
	const uint8_t *value;
	struct l_checksum *hash;
	uint8_t identifier, response[5 + 1 + 16];

	if (len < 1 || len < (size_t) pkt[0] + 1 || pkt[0] < 1) {
		l_error("EAP-MD5 request too short");
		goto err;
	}

	value = pkt + 1;

	hash = l_checksum_new(L_CHECKSUM_MD5);
	if (!hash) {
		l_error("Can't create the MD5 checksum");
		goto err;
	}

	eap_save_last_id(eap, &identifier);
	l_checksum_update(hash, &identifier, 1);
	l_checksum_update(hash, md5->secret, strlen(md5->secret));
	l_checksum_update(hash, value, pkt[0]);

	response[5] = 16;
	l_checksum_get_digest(hash, response + 6, 16);
	l_checksum_free(hash);

	eap_send_response(eap, EAP_TYPE_MD5_CHALLENGE,
				response, sizeof(response));

	/* We have no choice but to call it a success */
	eap_method_success(eap);

	return;

err:
	eap_method_error(eap);
}

static bool eap_md5_load_settings(struct eap_state *eap,
					struct l_settings *settings,
					const char *prefix)
{
	struct eap_md5_state *md5;
	char setting[64];
	char *secret;

	snprintf(setting, sizeof(setting), "%sMD5-Secret", prefix);
	secret = l_strdup(l_settings_get_value(settings, "Security", setting));

	if (!secret) {
		l_error("EAP-MD5 secret is missing");
		return false;
	}

	md5 = l_new(struct eap_md5_state, 1);
	md5->secret = secret;
	eap_set_data(eap, md5);

	return true;
}

static struct eap_method eap_md5 = {
	.request_type = EAP_TYPE_MD5_CHALLENGE,
	.exports_msk = false,
	.name = "MD5",

	.free = eap_md5_free,
	.handle_request = eap_md5_handle_request,
	.load_settings = eap_md5_load_settings,
};

static int eap_md5_init(void)
{
	l_debug("");
	return eap_register_method(&eap_md5);
}

static void eap_md5_exit(void)
{
	l_debug("");
	eap_unregister_method(&eap_md5);
}

EAP_METHOD_BUILTIN(eap_md5, eap_md5_init, eap_md5_exit)
