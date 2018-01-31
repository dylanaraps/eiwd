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

enum peap_flag {
	/* Reserved    = 0x00, */
	PEAP_FLAG_S    = 0x20,
};

struct eap_peap_state {
	enum peap_version version;
	struct l_tls *tunnel;

	char *ca_cert;
	char *client_cert;
	char *client_key;
	char *passphrase;
};

static void eap_peap_free(struct eap_state *eap)
{
	struct eap_peap_state *peap = eap_get_data(eap);

	if (peap->tunnel) {
		l_tls_free(peap->tunnel);
		peap->tunnel = NULL;
	}

	eap_set_data(eap, NULL);

	l_free(peap->ca_cert);
	l_free(peap->client_cert);
	l_free(peap->client_key);
	l_free(peap->passphrase);

	l_free(peap);
}

static void eap_peap_tunnel_data_send(const uint8_t *data, size_t data_len,
								void *user_data)
{
}

static void eap_peap_tunnel_data_received(const uint8_t *data, size_t data_len,
								void *user_data)
{
}

static void eap_peap_tunnel_ready(const char *peer_identity, void *user_data)
{
}

static void eap_peap_tunnel_disconnected(enum l_tls_alert_desc reason,
						bool remote, void *user_data)
{
	l_info("PEAP TLS tunnel has disconnected");
}

static bool eap_peap_tunnel_init(struct eap_state *eap)
{
	struct eap_peap_state *peap = eap_get_data(eap);

	if (peap->tunnel)
		return false;

	peap->tunnel = l_tls_new(false, eap_peap_tunnel_data_received,
					eap_peap_tunnel_data_send,
					eap_peap_tunnel_ready,
					eap_peap_tunnel_disconnected,
					eap);

	if (!peap->tunnel) {
		l_error("Failed to create a TLS instance.");
		return false;
	}

	if (!l_tls_set_auth_data(peap->tunnel, peap->client_cert,
					peap->client_key, NULL)) {
		l_error("Failed to set authentication data.");
		return false;
	}

	if (peap->ca_cert)
		l_tls_set_cacert(peap->tunnel, peap->ca_cert);

	return true;
}

static bool eap_peap_validate_version(struct eap_state *eap,
							uint8_t flags_version)
{
	struct eap_peap_state *peap = eap_get_data(eap);
	enum peap_version version_proposed = flags_version & PEAP_VERSION_MASK;

	if (peap->version == version_proposed)
		return true;

	if (!(flags_version & PEAP_FLAG_S) ||
			peap->version != PEAP_VERSION_NOT_NEGOTIATED)
		return false;

	if (version_proposed < __PEAP_VERSION_MAX_SUPPORTED)
		peap->version = version_proposed;
	else
		peap->version = __PEAP_VERSION_MAX_SUPPORTED;

	return true;
}

static void eap_peap_handle_request(struct eap_state *eap,
					const uint8_t *pkt, size_t len)
{
	uint8_t flags_version;

	if (len < 1) {
		l_error("EAP-PEAP request too short");
		goto error;
	}

	flags_version = pkt[0];

	if (!eap_peap_validate_version(eap, flags_version)) {
		l_error("EAP-PEAP version negotiation failed");
		goto error;
	}

	if (flags_version & PEAP_FLAG_S)
		if (!eap_peap_tunnel_init(eap))
			goto error;

	return;

error:
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
