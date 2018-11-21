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

#include "src/eap.h"
#include "src/eap-private.h"
#include "src/eap-tls-common.h"

struct databuf *databuf_new(size_t capacity)
{
	struct databuf *databuf;

	if (!capacity)
		return NULL;

	databuf = l_new(struct databuf, 1);
	databuf->data = l_malloc(capacity);
	databuf->capacity = capacity;

	return databuf;
}

void databuf_append(struct databuf *databuf, const uint8_t *data,
								size_t data_len)
{
	size_t new_len;

	if (!databuf)
		return;

	new_len = databuf->len + data_len;

	if (new_len > databuf->capacity) {
		databuf->capacity = new_len * 2;
		databuf->data = l_realloc(databuf->data, databuf->capacity);
	}

	memcpy(databuf->data + databuf->len, data, data_len);

	databuf->len = new_len;
}

void databuf_free(struct databuf *databuf)
{
	if (!databuf)
		return;

	l_free(databuf->data);
	l_free(databuf);
}

struct eap_tls_state {
	enum eap_tls_version version_negotiated;

	char *ca_cert;
	char *client_cert;
	char *client_key;
	char *passphrase;
};

static void __eap_tls_common_state_reset(struct eap_tls_state *eap_tls)
{
	eap_tls->version_negotiated = EAP_TLS_VERSION_NOT_NEGOTIATED;
}

void eap_tls_common_state_free(struct eap_state *eap)
{
	struct eap_tls_state *eap_tls = eap_get_data(eap);

	__eap_tls_common_state_reset(eap_tls);

	eap_set_data(eap, NULL);

	l_free(eap_tls->ca_cert);
	l_free(eap_tls->client_cert);
	l_free(eap_tls->client_key);

	if (eap_tls->passphrase) {
		memset(eap_tls->passphrase, 0, strlen(eap_tls->passphrase));
		l_free(eap_tls->passphrase);
	}

	l_free(eap_tls);
}

int eap_tls_common_settings_check(struct l_settings *settings,
					struct l_queue *secrets,
					const char *prefix,
					struct l_queue **out_missing)
{
	char setting_key[72];
	char client_cert_setting[72];
	char passphrase_setting[72];
	uint8_t *cert;
	size_t size;

	L_AUTO_FREE_VAR(char *, path);
	L_AUTO_FREE_VAR(char *, client_cert) = NULL;
	L_AUTO_FREE_VAR(char *, passphrase) = NULL;

	snprintf(setting_key, sizeof(setting_key), "%sCACert", prefix);
	path = l_settings_get_string(settings, "Security", setting_key);
	if (path) {
		cert = l_pem_load_certificate(path, &size);
		if (!cert) {
			l_error("Failed to load %s", path);
			return -EIO;
		}

		l_free(cert);
	}

	snprintf(client_cert_setting, sizeof(client_cert_setting),
							"%sClientCert", prefix);
	client_cert = l_settings_get_string(settings, "Security",
							client_cert_setting);
	if (client_cert) {
		cert = l_pem_load_certificate(client_cert, &size);
		if (!cert) {
			l_error("Failed to load %s", client_cert);
			return -EIO;
		}

		l_free(cert);
	}

	l_free(path);

	snprintf(setting_key, sizeof(setting_key), "%sClientKey", prefix);
	path = l_settings_get_string(settings, "Security", setting_key);

	if (path && !client_cert) {
		l_error("%s present but no client certificate (%s)",
					setting_key, client_cert_setting);
		return -ENOENT;
	}

	snprintf(passphrase_setting, sizeof(passphrase_setting),
					"%sClientKeyPassphrase", prefix);
	passphrase = l_settings_get_string(settings, "Security",
							passphrase_setting);

	if (!passphrase) {
		const struct eap_secret_info *secret;

		secret = l_queue_find(secrets, eap_secret_info_match,
							passphrase_setting);
		if (secret)
			passphrase = l_strdup(secret->value);
	}

	if (path) {
		struct l_key *priv_key;
		bool encrypted;

		priv_key = l_pem_load_private_key(path, passphrase, &encrypted);
		if (!priv_key) {
			if (!encrypted) {
				l_error("Error loading client private key %s",
									path);
				return -EIO;
			}

			if (passphrase) {
				l_error("Error loading encrypted client "
							"private key %s", path);
				return -EACCES;
			}

			/*
			 * We've got an encrypted key and passphrase was not
			 * saved in the network settings, need to request
			 * the passphrase.
			 */
			eap_append_secret(out_missing,
					EAP_SECRET_LOCAL_PKEY_PASSPHRASE,
					passphrase_setting, NULL, path,
					EAP_CACHE_TEMPORARY);
		} else {
			l_key_free(priv_key);

			if (passphrase && !encrypted) {
				l_error("%s present but client private "
						"key %s is not encrypted",
						passphrase_setting, path);
				return -ENOENT;
			}
		}
	} else if (passphrase) {
		l_error("%s present but no client private key path set (%s)",
					passphrase_setting, setting_key);
		return -ENOENT;
	}

	return 0;
}

bool eap_tls_common_settings_load(struct eap_state *eap,
						struct l_settings *settings,
						const char *prefix)
{
	struct eap_tls_state *eap_tls;
	char setting_key[72];

	eap_tls = l_new(struct eap_tls_state, 1);

	eap_tls->version_negotiated = EAP_TLS_VERSION_NOT_NEGOTIATED;

	snprintf(setting_key, sizeof(setting_key), "%sCACert", prefix);
	eap_tls->ca_cert = l_settings_get_string(settings, "Security",
								setting_key);

	snprintf(setting_key, sizeof(setting_key), "%sClientCert", prefix);
	eap_tls->client_cert = l_settings_get_string(settings, "Security",
								setting_key);

	snprintf(setting_key, sizeof(setting_key), "%sClientKey", prefix);
	eap_tls->client_key = l_settings_get_string(settings, "Security",
								setting_key);

	snprintf(setting_key, sizeof(setting_key), "%sClientKeyPassphrase",
									prefix);
	eap_tls->passphrase = l_settings_get_string(settings, "Security",
								setting_key);

	eap_set_data(eap, eap_tls);

	return true;
}
