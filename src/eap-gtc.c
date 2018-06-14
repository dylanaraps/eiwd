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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <errno.h>
#include <ell/ell.h>

#include "eap.h"

struct eap_gtc_state {
	char *secret;
};

static void eap_gtc_free(struct eap_state *eap)
{
	struct eap_gtc_state *gtc = eap_get_data(eap);

	eap_set_data(eap, NULL);

	l_free(gtc->secret);
	l_free(gtc);
}

static void eap_gtc_handle_request(struct eap_state *eap,
					const uint8_t *pkt, size_t len)
{
	struct eap_gtc_state *gtc = eap_get_data(eap);
	size_t secret_len = strlen(gtc->secret);
	uint8_t response[5 + secret_len];

	if (len < 8)
		goto error;

	if (strncmp((const char *)pkt, "Password", 8))
		goto error;

	memcpy(response + 5, gtc->secret, secret_len);

	eap_send_response(eap, EAP_TYPE_GTC, response, 5 + secret_len);

	eap_method_success(eap);

	return;

error:
	l_error("invalid GTC request");
	eap_method_error(eap);
}

static int eap_gtc_check_settings(struct l_settings *settings,
					struct l_queue *secrets,
					const char *prefix,
					struct l_queue **out_missing)
{
	char setting[64];

	snprintf(setting, sizeof(setting), "%sGTC-Secret", prefix);

	if (!l_settings_get_value(settings, "Security", setting)) {
		l_error("Property %s is missing", setting);
		return -ENOENT;
	}

	return 0;
}

static bool eap_gtc_load_settings(struct eap_state *eap,
					struct l_settings *settings,
					const char *prefix)
{
	struct eap_gtc_state *gtc;
	char setting[64];
	char *secret;

	snprintf(setting, sizeof(setting), "%sGTC-Secret", prefix);
	secret = l_settings_get_string(settings, "Security", setting);

	gtc = l_new(struct eap_gtc_state, 1);
	gtc->secret = secret;
	eap_set_data(eap, gtc);

	return true;
}

static struct eap_method eap_gtc = {
	.request_type = EAP_TYPE_GTC,
	.exports_msk = false,
	.name = "GTC",
	.free = eap_gtc_free,
	.handle_request = eap_gtc_handle_request,
	.check_settings = eap_gtc_check_settings,
	.load_settings = eap_gtc_load_settings,
};

static int eap_gtc_init(void)
{
	l_debug("");
	return eap_register_method(&eap_gtc);
}

static void eap_gtc_exit(void)
{
	l_debug("");
	eap_unregister_method(&eap_gtc);
}

EAP_METHOD_BUILTIN(eap_gtc, eap_gtc_init, eap_gtc_exit)
