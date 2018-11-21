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

#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <ell/ell.h>

#include "eap.h"
#include "eap-private.h"

struct eap_tls_state {
	char *ca_cert;
	char *client_cert;
	char *client_key;
	char *passphrase;

	struct l_tls *tls;
	uint8_t *rx_pkt_buf;
	size_t rx_pkt_received, rx_pkt_len;
	uint8_t *tx_pkt_buf;
	size_t tx_pkt_len, tx_pkt_capacity, tx_pkt_offset;
	bool completed;
};

static void __eap_tls_reset_state(struct eap_tls_state *tls)
{
	tls->completed = false;

	l_free(tls->rx_pkt_buf);
	tls->rx_pkt_buf = NULL;
	tls->rx_pkt_received = 0;
	tls->rx_pkt_len = 0;

	l_free(tls->tx_pkt_buf);
	tls->tx_pkt_buf = NULL;
	tls->tx_pkt_capacity = 0;
	tls->tx_pkt_len = 0;
	tls->tx_pkt_offset = 0;

	if (tls->tls) {
		l_tls_free(tls->tls);
		tls->tls = NULL;
	}
}

static bool eap_tls_reset_state(struct eap_state *eap)
{
	struct eap_tls_state *tls = eap_get_data(eap);

	__eap_tls_reset_state(tls);
	return true;
}

static void eap_tls_free(struct eap_state *eap)
{
	struct eap_tls_state *tls = eap_get_data(eap);

	__eap_tls_reset_state(tls);
	eap_set_data(eap, NULL);

	l_free(tls->ca_cert);
	l_free(tls->client_cert);
	l_free(tls->client_key);

	if (tls->passphrase) {
		memset(tls->passphrase, 0, strlen(tls->passphrase));
		l_free(tls->passphrase);
	}

	l_free(tls);
}

#define EAP_TLS_RESPONSE_HEADER_LEN	10

#define EAP_TLS_FLAG_L (1 << 7)
#define EAP_TLS_FLAG_M (1 << 6)
#define EAP_TLS_FLAG_S (1 << 5)
#define EAP_TLS_FLAG_LM_MASK	\
	(EAP_TLS_FLAG_L | EAP_TLS_FLAG_M)

static uint8_t *eap_tls_tx_buf_reserve(struct eap_tls_state *tls, size_t size)
{
	int offset = tls->tx_pkt_offset + tls->tx_pkt_len;
	size_t end_offset = offset + size;

	tls->tx_pkt_len += size;

	if (end_offset > tls->tx_pkt_capacity) {
		tls->tx_pkt_capacity = end_offset + 1024;
		tls->tx_pkt_buf =
			l_realloc(tls->tx_pkt_buf, tls->tx_pkt_capacity);
	}

	return tls->tx_pkt_buf + offset;
}

static void eap_tls_tx_cb(const uint8_t *data, size_t len, void *user_data)
{
	struct eap_state *eap = user_data;
	struct eap_tls_state *tls = eap_get_data(eap);

	memcpy(eap_tls_tx_buf_reserve(tls, len), data, len);
}

static void eap_tls_data_cb(const uint8_t *data, size_t len, void *user_data)
{
	/* This should never be called */
}

static void eap_tls_ready_cb(const char *peer_identity, void *user_data)
{
	struct eap_state *eap = user_data;
	struct eap_tls_state *tls = eap_get_data(eap);
	uint8_t msk_emsk[128];
	uint8_t iv[64];

	/* TODO: if we have a CA certificate require non-NULL peer_identity */

	eap_method_success(eap);
	tls->completed = true;

	eap_start_complete_timeout(eap);

	/* MSK, EMSK and IV derivation */
	l_tls_prf_get_bytes(tls->tls, true,
				"client EAP encryption", msk_emsk, 128);
	l_tls_prf_get_bytes(tls->tls, false,
				"client EAP encryption", iv, 64);

	eap_set_key_material(eap, msk_emsk + 0, 64, msk_emsk + 64, 64, iv, 64);
}

static void eap_tls_disconnect_cb(enum l_tls_alert_desc reason,
					bool remote, void *user_data)
{
	struct eap_state *eap = user_data;
	struct eap_tls_state *tls = eap_get_data(eap);

	tls->completed = true;
}

static void eap_tls_debug_cb(const char *str, void *user_data)
{
	l_info("EAP-TLS %s", str);
}

static void eap_tls_handle_request(struct eap_state *eap,
					const uint8_t *pkt, size_t len)
{
	uint8_t flags;
	uint32_t total_len;
	struct eap_tls_state *tls = eap_get_data(eap);
	size_t fragment_len;
	uint8_t *tx_buf;

	if (len < 1) {
		l_error("EAP-TLS request too short");
		goto err;
	}

	flags = pkt[0];

	pkt += 1;
	len -= 1;

	/* Check if we're expecting a fragment ACK */
	if (tls->tx_pkt_len) {
		if (flags || len) {
			l_error("EAP-TLS request is not an ACK");
			goto err;
		}

		/* Send next response fragment, prepend the 6-byte header */
		tx_buf = &tls->tx_pkt_buf[tls->tx_pkt_offset - 6];

		fragment_len = eap_get_mtu(eap) - 6;
		tx_buf[5] = EAP_TLS_FLAG_M; /* Flags */

		if (tls->tx_pkt_len <= fragment_len) {
			fragment_len = tls->tx_pkt_len;
			tx_buf[5] = 0; /* Flags */
		}

		eap_send_response(eap, EAP_TYPE_TLS_EAP,
					tx_buf, fragment_len + 6);

		tls->tx_pkt_len -= fragment_len;
		tls->tx_pkt_offset += fragment_len;

		return;
	}

	/* Complain if S bit is not correct */
	if (!(flags & EAP_TLS_FLAG_S) == !tls->tls) {
		l_error("EAP-TLS request S flag invalid");
		goto err;
	}

	/* Method can't be restarted */
	if ((flags & EAP_TLS_FLAG_S) && tls->completed) {
		l_error("EAP-TLS start after completed");
		goto err;
	}

	/* Sanity check that first fragmented request has L flag set */
	if ((flags & EAP_TLS_FLAG_LM_MASK) == EAP_TLS_FLAG_M &&
			!tls->rx_pkt_buf) {
		l_error("EAP-TLS request 1st fragment with no length");
		goto err;
	}

	if (flags & EAP_TLS_FLAG_L) {
		if (len < 7) {
			l_error("EAP-TLS request with L flag too short");
			goto err;
		}

		total_len = l_get_be32(pkt);
		pkt += 4;
		len -= 4;

		if ((flags & EAP_TLS_FLAG_M) && !tls->rx_pkt_buf) {
			if (total_len > 512 * 1024) {
				l_error("EAP-TLS Message too long");
				goto err;
			}

			tls->rx_pkt_buf = l_malloc(total_len);
			tls->rx_pkt_len = total_len;
			tls->rx_pkt_received = 0;
		}

		if ((tls->rx_pkt_buf && total_len != tls->rx_pkt_len) ||
				(!tls->rx_pkt_buf && total_len != len)) {
			l_error("EAP-TLS request length mismatch");

			l_free(tls->rx_pkt_buf);
			tls->rx_pkt_buf = NULL;

			goto err;
		}
	}

	if (tls->rx_pkt_buf) {
		if (
				((flags & EAP_TLS_FLAG_M) &&
				 tls->rx_pkt_received + len >=
				 tls->rx_pkt_len) ||
				(!(flags & EAP_TLS_FLAG_M) &&
				 tls->rx_pkt_received + len !=
				 tls->rx_pkt_len)) {
			l_error("EAP-TLS request fragment length mismatch");

			l_free(tls->rx_pkt_buf);
			tls->rx_pkt_buf = NULL;

			goto err;
		}

		memcpy(tls->rx_pkt_buf + tls->rx_pkt_received, pkt, len);
		tls->rx_pkt_received += len;
	}

	if (flags & EAP_TLS_FLAG_M) {
		uint8_t buf[6];

		/* Send an empty response as ACK */
		buf[5] = 0;
		eap_send_response(eap, EAP_TYPE_TLS_EAP, buf, 6);

		return;
	}

	if (tls->rx_pkt_buf) {
		pkt = tls->rx_pkt_buf;
		len = tls->rx_pkt_len;
	}

	eap_tls_tx_buf_reserve(tls, EAP_TLS_RESPONSE_HEADER_LEN);
	tls->tx_pkt_offset = tls->tx_pkt_len;
	tls->tx_pkt_len = 0;

	if (flags & EAP_TLS_FLAG_S) {
		tls->tls = l_tls_new(false, eap_tls_data_cb,
					eap_tls_tx_cb, eap_tls_ready_cb,
					eap_tls_disconnect_cb, eap);

		if (!tls->tls) {
			l_error("Creating a TLS instance failed");
			goto err;
		}

		if (getenv("IWD_TLS_DEBUG"))
			l_tls_set_debug(tls->tls, eap_tls_debug_cb, NULL, NULL);

		if (!l_tls_set_auth_data(tls->tls, tls->client_cert,
					tls->client_key, tls->passphrase) ||
				(tls->ca_cert &&
				 !l_tls_set_cacert(tls->tls, tls->ca_cert))) {
			l_error("Error loading EAP-TLS keys or certificates");
			goto err;
		}
	}

	/*
	 * Here we take advantage of knowing that ell will send all the
	 * records corresponding to the current handshake step from within
	 * the l_tls_handle_rx call because it doesn't use any other context
	 * such as timers - basic TLS specifies no timeouts.  Otherwise we
	 * would need to analyze the record types in eap_tls_tx_cb to decide
	 * when we're ready to send out a response.
	 */
	if (len)
		l_tls_handle_rx(tls->tls, pkt, len);

	if (tls->rx_pkt_buf) {
		l_free(tls->rx_pkt_buf);
		tls->rx_pkt_buf = NULL;
	}

	/*
	 * Note if tls->completed && !eap->method_success we can send an empty
	 * response instead of passing the TLS alert.
	 */

	if (tls->tx_pkt_len + 6 <= eap_get_mtu(eap)) {
		/*
		 * Response fits in a single response packet, prepend the
		 * 6-byte header (no length) before the data.
		 */
		tx_buf = &tls->tx_pkt_buf[tls->tx_pkt_offset - 6];

		tx_buf[5] = 0; /* Flags */

		eap_send_response(eap, EAP_TYPE_TLS_EAP,
					tx_buf, tls->tx_pkt_len + 6);

		tls->tx_pkt_len = 0;
	} else {
		/*
		 * Fragmentation needed, prepend the 10-byte header
		 * (4 EAP header + 2 response + 4 length) to build the
		 * initial fragment packet.
		 */
		tx_buf = &tls->tx_pkt_buf[tls->tx_pkt_offset - 10];

		tx_buf[5] = EAP_TLS_FLAG_L | EAP_TLS_FLAG_M; /* Flags */
		l_put_be32(tls->tx_pkt_len, &tx_buf[6]);

		fragment_len = eap_get_mtu(eap) - 10;
		eap_send_response(eap, EAP_TYPE_TLS_EAP,
					tx_buf, fragment_len + 10);

		tls->tx_pkt_len -= fragment_len;
		tls->tx_pkt_offset += fragment_len;
	}

	if (tls->completed) {
		l_tls_free(tls->tls);
		tls->tls = NULL;
	}

	return;

err:
	tls->completed = true;

	l_tls_free(tls->tls);
	tls->tls = NULL;

	eap_method_error(eap);
}

static int eap_tls_check_settings(struct l_settings *settings,
					struct l_queue *secrets,
					const char *prefix,
					struct l_queue **out_missing)
{
	char setting[64], client_cert_setting[64], passphrase_setting[64];
	L_AUTO_FREE_VAR(char *, path) = NULL;
	L_AUTO_FREE_VAR(char *, client_cert) = NULL;
	L_AUTO_FREE_VAR(char *, passphrase) = NULL;
	uint8_t *cert;
	size_t size;

	snprintf(setting, sizeof(setting), "%sTLS-CACert", prefix);
	path = l_settings_get_string(settings, "Security", setting);
	if (path) {
		cert = l_pem_load_certificate(path, &size);
		if (!cert) {
			l_error("Failed to load %s", path);
			return -EIO;
		}

		l_free(cert);
	}

	snprintf(client_cert_setting, sizeof(client_cert_setting),
			"%sTLS-ClientCert", prefix);
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

	snprintf(setting, sizeof(setting), "%sTLS-ClientKey", prefix);
	path = l_settings_get_string(settings, "Security", setting);

	if (path && !client_cert) {
		l_error("%s present but no client certificate (%s)",
			setting, client_cert_setting);
		return -ENOENT;
	}

	snprintf(passphrase_setting, sizeof(passphrase_setting),
			"%sTLS-ClientKeyPassphrase", prefix);
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
			passphrase_setting, setting);
		return -ENOENT;
	}

	return 0;
}

static bool eap_tls_load_settings(struct eap_state *eap,
					struct l_settings *settings,
					const char *prefix)
{
	struct eap_tls_state *tls;
	char setting[64];

	tls = l_new(struct eap_tls_state, 1);

	snprintf(setting, sizeof(setting), "%sTLS-CACert", prefix);
	tls->ca_cert = l_settings_get_string(settings, "Security", setting);

	snprintf(setting, sizeof(setting), "%sTLS-ClientCert", prefix);
	tls->client_cert = l_settings_get_string(settings, "Security", setting);

	snprintf(setting, sizeof(setting), "%sTLS-ClientKey", prefix);
	tls->client_key = l_settings_get_string(settings, "Security", setting);

	snprintf(setting, sizeof(setting), "%sTLS-ClientKeyPassphrase", prefix);
	tls->passphrase = l_settings_get_string(settings, "Security", setting);

	eap_set_data(eap, tls);

	return true;
}

static struct eap_method eap_tls = {
	.request_type = EAP_TYPE_TLS_EAP,
	.exports_msk = true,
	.name = "TLS",

	.free = eap_tls_free,
	.handle_request = eap_tls_handle_request,
	.check_settings = eap_tls_check_settings,
	.load_settings = eap_tls_load_settings,
	.reset_state = eap_tls_reset_state,
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
