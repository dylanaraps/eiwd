/*
 *
 *  Wireless daemon for Linux
 *
 *  Copyright (C) 2013-2018  Intel Corporation. All rights reserved.
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

#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <ell/ell.h>

#include "src/missing.h"
#include "src/eap.h"
#include "src/eap-private.h"
#include "src/eap-tls-common.h"

static bool eap_tls_tunnel_ready(struct eap_state *eap,
						const char *peer_identity)
{
	uint8_t msk_emsk[128];
	uint8_t iv[64];

	eap_method_success(eap);
	eap_tls_common_set_completed(eap);

	/* MSK, EMSK and IV derivation */
	eap_tls_common_tunnel_prf_get_bytes(eap, true, "client EAP encryption",
								msk_emsk, 128);
	eap_tls_common_tunnel_prf_get_bytes(eap, false, "client EAP encryption",
									iv, 64);

	/* TODO: Derive Session-ID */
	eap_set_key_material(eap, msk_emsk + 0, 64, msk_emsk + 64, 64, iv, 64,
				NULL, 0);
	explicit_bzero(msk_emsk, sizeof(msk_emsk));
	explicit_bzero(iv, sizeof(iv));

	eap_tls_common_send_empty_response(eap);

	return true;
}

static int eap_tls_settings_check(struct l_settings *settings,
						struct l_queue *secrets,
						const char *prefix,
						struct l_queue **out_missing)
{
	char tls_prefix[72];

	snprintf(tls_prefix, sizeof(tls_prefix), "%sTLS-", prefix);

	return eap_tls_common_settings_check(settings, secrets, tls_prefix,
								out_missing);
}

static const struct eap_tls_variant_ops eap_tls_ops = {
	.tunnel_ready = eap_tls_tunnel_ready,
};

static bool eap_tls_settings_load(struct eap_state *eap,
						struct l_settings *settings,
						const char *prefix)
{
	char setting_key_prefix[72];

	snprintf(setting_key_prefix, sizeof(setting_key_prefix), "%sTLS-",
									prefix);

	if (!eap_tls_common_settings_load(eap, settings, setting_key_prefix,
							&eap_tls_ops, NULL))
		return false;

	return true;
}

static struct eap_method eap_tls = {
	.request_type = EAP_TYPE_TLS,
	.exports_msk = true,
	.name = "TLS",

	.handle_request = eap_tls_common_handle_request,
	.handle_retransmit = eap_tls_common_handle_retransmit,
	.reset_state = eap_tls_common_state_reset,
	.free = eap_tls_common_state_free,

	.check_settings = eap_tls_settings_check,
	.load_settings = eap_tls_settings_load,
};

static int eap_tls_init(void)
{
	l_debug("");
	return eap_register_method(&eap_tls);
}

static void eap_tls_exit(void)
{
	l_debug("");
	eap_unregister_method(&eap_tls);
}

EAP_METHOD_BUILTIN(eap_tls, eap_tls_init, eap_tls_exit)
