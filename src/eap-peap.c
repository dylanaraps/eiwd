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

#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <ell/ell.h>

#include "eap.h"

enum peap_version {
	PEAP_VERSION_0               = 0x00,
	PEAP_VERSION_1               = 0x01,
	__PEAP_VERSION_MAX_SUPPORTED = PEAP_VERSION_1,
	PEAP_VERSION_MASK            = 0x07,
	PEAP_VERSION_NOT_NEGOTIATED  = 0x08,
};

struct eap_peap_state {
	enum peap_version version;

	char *ca_cert;
	char *client_cert;
	char *client_key;
	char *passphrase;
};

static void eap_peap_free(struct eap_state *eap)
{
	struct eap_peap_state *peap = eap_get_data(eap);

	eap_set_data(eap, NULL);

	l_free(peap->ca_cert);
	l_free(peap->client_cert);
	l_free(peap->client_key);
	l_free(peap->passphrase);

	l_free(peap);
}

static void eap_peap_handle_request(struct eap_state *eap,
					const uint8_t *pkt, size_t len)
{
	eap_method_error(eap);
}

static bool eap_peap_load_settings(struct eap_state *eap,
					struct l_settings *settings,
					const char *prefix)
{
	struct eap_peap_state *peap;
	char entry[64];

	peap = l_new(struct eap_peap_state, 1);

	peap->version = PEAP_VERSION_NOT_NEGOTIATED;

	snprintf(entry, sizeof(entry), "%sPEAP-CACert", prefix);
	peap->ca_cert = l_strdup(l_settings_get_value(settings, "Security",
									entry));

	snprintf(entry, sizeof(entry), "%sPEAP-ClientCert", prefix);
	peap->client_cert = l_strdup(l_settings_get_value(settings, "Security",
									entry));

	snprintf(entry, sizeof(entry), "%sPEAP-ClientKey", prefix);
	peap->client_key = l_strdup(l_settings_get_value(settings, "Security",
									entry));

	snprintf(entry, sizeof(entry), "%sPEAP-ClientKeyPassphrase", prefix);
	peap->passphrase = l_strdup(l_settings_get_value(settings, "Security",
									entry));

	if (!peap->client_cert && peap->client_key) {
		l_error("Client key present but no client certificate");
		goto error;
	}

	if (!peap->client_key && peap->passphrase) {
		l_error("Passphrase present but no client private key");
		goto error;
	}

	eap_set_data(eap, peap);

	return true;

error:
	l_free(peap->ca_cert);
	l_free(peap->client_cert);
	l_free(peap->client_key);
	l_free(peap->passphrase);
	l_free(peap);

	return false;
}

static struct eap_method eap_peap = {
	.request_type = EAP_TYPE_PEAP,
	.name = "PEAP",
	.exports_msk = true,

	.handle_request = eap_peap_handle_request,
	.load_settings = eap_peap_load_settings,
	.free = eap_peap_free,
};

static int eap_peap_init(void)
{
	l_debug("");
	return eap_register_method(&eap_peap);
}

static void eap_peap_exit(void)
{
	l_debug("");
	eap_unregister_method(&eap_peap);
}

EAP_METHOD_BUILTIN(eap_peap, eap_peap_init, eap_peap_exit)
