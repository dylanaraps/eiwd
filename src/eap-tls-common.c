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

#define EAP_TLS_PDU_MAX_LEN 65536

#define EAP_TLS_HEADER_LEN  6

#define EAP_TLS_HEADER_OCTET_FLAGS 5
#define EAP_TLS_HEADER_OCTET_FRAG_LEN 6

enum eap_tls_flag {
	/* Reserved    = 0x00, */
	EAP_TLS_FLAG_S    = 0x20,
	EAP_TLS_FLAG_M    = 0x40,
	EAP_TLS_FLAG_L    = 0x80,
};

struct eap_tls_state {
	enum eap_tls_version version_negotiated;

	struct l_tls *tunnel;

	bool method_completed:1;
	bool phase2_failed:1;

	struct databuf *plain_buf;
	struct databuf *tx_pdu_buf;
	struct databuf *rx_pdu_buf;

	size_t tx_frag_offset;
	size_t tx_frag_last_len;

	bool expecting_frag_ack:1;

	char *ca_cert;
	char *client_cert;
	char *client_key;
	char *passphrase;

	const struct eap_tls_variant_ops *variant_ops;
	void *variant_data;
};

static void __eap_tls_common_state_reset(struct eap_tls_state *eap_tls)
{
	eap_tls->version_negotiated = EAP_TLS_VERSION_NOT_NEGOTIATED;
	eap_tls->method_completed = false;
	eap_tls->phase2_failed = false;
	eap_tls->expecting_frag_ack = false;

	if (eap_tls->tunnel) {
		l_tls_free(eap_tls->tunnel);
		eap_tls->tunnel = NULL;
	}

	eap_tls->tx_frag_offset = 0;
	eap_tls->tx_frag_last_len = 0;

	if (eap_tls->plain_buf) {
		databuf_free(eap_tls->plain_buf);
		eap_tls->plain_buf = NULL;
	}

	if (eap_tls->tx_pdu_buf) {
		databuf_free(eap_tls->tx_pdu_buf);
		eap_tls->tx_pdu_buf = NULL;
	}

	if (eap_tls->rx_pdu_buf) {
		databuf_free(eap_tls->rx_pdu_buf);
		eap_tls->rx_pdu_buf = NULL;
	}
}

bool eap_tls_common_state_reset(struct eap_state *eap)
{
	struct eap_tls_state *eap_tls = eap_get_data(eap);

	__eap_tls_common_state_reset(eap_tls);

	if (eap_tls->variant_ops->reset)
		eap_tls->variant_ops->reset(eap_tls->variant_data);

	return true;
}

void eap_tls_common_state_free(struct eap_state *eap)
{
	struct eap_tls_state *eap_tls = eap_get_data(eap);

	__eap_tls_common_state_reset(eap_tls);

	eap_set_data(eap, NULL);

	if (eap_tls->variant_ops->destroy)
		eap_tls->variant_ops->destroy(eap_tls->variant_data);

	l_free(eap_tls->ca_cert);
	l_free(eap_tls->client_cert);
	l_free(eap_tls->client_key);

	if (eap_tls->passphrase) {
		memset(eap_tls->passphrase, 0, strlen(eap_tls->passphrase));
		l_free(eap_tls->passphrase);
	}

	l_free(eap_tls);
}

static void eap_tls_tunnel_debug(const char *str, void *user_data)
{
	struct eap_state *eap = user_data;

	l_info("%s: %s", eap_get_method_name(eap), str);
}

static void eap_tls_tunnel_data_send(const uint8_t *data, size_t data_len,
								void *user_data)
{
	struct eap_state *eap = user_data;
	struct eap_tls_state *eap_tls = eap_get_data(eap);

	if (!eap_tls->tx_pdu_buf)
		eap_tls->tx_pdu_buf = databuf_new(data_len);

	databuf_append(eap_tls->tx_pdu_buf, data, data_len);
}

static void eap_tls_tunnel_data_received(const uint8_t *data, size_t data_len,
								void *user_data)
{
	struct eap_state *eap = user_data;
	struct eap_tls_state *eap_tls = eap_get_data(eap);

	if (!eap_tls->plain_buf)
		eap_tls->plain_buf = databuf_new(data_len);

	databuf_append(eap_tls->plain_buf, data, data_len);
}

static void eap_tls_tunnel_ready(const char *peer_identity, void *user_data)
{
	struct eap_state *eap = user_data;
	struct eap_tls_state *eap_tls = eap_get_data(eap);

	/* TODO: if we have a CA certificate require non-NULL peer_identity */

	/*
	 * Since authenticator may not send us EAP-Success/EAP-Failure
	 * in cleartext for the outer EAP method, we reinforce
	 * the completion with a timer.
	 */
	eap_start_complete_timeout(eap);

	if (!eap_tls->variant_ops->tunnel_ready)
		return;

	if (!eap_tls->variant_ops->tunnel_ready(eap, peer_identity))
		l_tls_close(eap_tls->tunnel);
}

static void eap_tls_tunnel_disconnected(enum l_tls_alert_desc reason,
						bool remote, void *user_data)
{
	struct eap_state *eap = user_data;
	struct eap_tls_state *eap_tls = eap_get_data(eap);

	l_info("%s: Tunnel has disconnected with alert: %s",
			eap_get_method_name(eap), l_tls_alert_to_str(reason));

	eap_tls->method_completed = true;
}

static bool eap_tls_validate_version(struct eap_state *eap,
							uint8_t flags_version)
{
	struct eap_tls_state *eap_tls = eap_get_data(eap);
	enum eap_tls_version version_proposed =
					flags_version & EAP_TLS_VERSION_MASK;

	if (eap_tls->version_negotiated == version_proposed)
		return true;

	if (!(flags_version & EAP_TLS_FLAG_S) ||
			eap_tls->version_negotiated !=
						EAP_TLS_VERSION_NOT_NEGOTIATED)
		return false;

	if (version_proposed < eap_tls->variant_ops->version_max_supported)
		eap_tls->version_negotiated = version_proposed;
	else
		eap_tls->version_negotiated =
				eap_tls->variant_ops->version_max_supported;

	return true;
}

static void eap_tls_send_fragment(struct eap_state *eap)
{
	struct eap_tls_state *eap_tls = eap_get_data(eap);
	size_t mtu = eap_get_mtu(eap);
	uint8_t buf[mtu];
	size_t len = eap_tls->tx_pdu_buf->len - eap_tls->tx_frag_offset;
	size_t header_len = EAP_TLS_HEADER_LEN;

	buf[EAP_TLS_HEADER_OCTET_FLAGS] = eap_tls->version_negotiated;

	if (len > mtu - EAP_TLS_HEADER_LEN) {
		len = mtu - EAP_TLS_HEADER_LEN;
		buf[EAP_TLS_HEADER_OCTET_FLAGS] |= EAP_TLS_FLAG_M;
		eap_tls->expecting_frag_ack = true;
	}

	if (!eap_tls->tx_frag_offset) {
		buf[EAP_TLS_HEADER_OCTET_FLAGS] |= EAP_TLS_FLAG_L;
		l_put_be32(eap_tls->tx_pdu_buf->len,
					&buf[EAP_TLS_HEADER_OCTET_FRAG_LEN]);
		len -= 4;
		header_len += 4;
	}

	memcpy(buf + header_len,
		eap_tls->tx_pdu_buf->data + eap_tls->tx_frag_offset, len);
	eap_send_response(eap, eap_get_method_type(eap), buf, header_len + len);

	eap_tls->tx_frag_last_len = len;
}

static void eap_tls_send_response(struct eap_state *eap,
					const uint8_t *pdu, size_t pdu_len)
{
	struct eap_tls_state *eap_tls = eap_get_data(eap);
	size_t msg_len = EAP_TLS_HEADER_LEN + pdu_len;

	if (msg_len <= eap_get_mtu(eap)) {
		uint8_t buf[msg_len];

		buf[EAP_TLS_HEADER_OCTET_FLAGS] = eap_tls->version_negotiated;
		memcpy(buf + EAP_TLS_HEADER_LEN, pdu, pdu_len);

		eap_send_response(eap, eap_get_method_type(eap), buf, msg_len);
		return;
	}

	eap_tls->tx_frag_offset = 0;
	eap_tls_send_fragment(eap);
}

void eap_tls_common_send_empty_response(struct eap_state *eap)
{
	struct eap_tls_state *eap_tls = eap_get_data(eap);
	uint8_t buf[EAP_TLS_HEADER_LEN];

	buf[EAP_TLS_HEADER_OCTET_FLAGS] = eap_tls->version_negotiated;

	eap_send_response(eap, eap_get_method_type(eap), buf,
							EAP_TLS_HEADER_LEN);
}

static int eap_tls_init_request_assembly(struct eap_state *eap,
						const uint8_t *pkt, size_t len,
						uint8_t flags)
{
	struct eap_tls_state *eap_tls = eap_get_data(eap);
	size_t tls_msg_len;

	if (eap_tls->rx_pdu_buf) {
		/*
		 * EAP-TLS: RFC 5216 Section 3.1
		 *
		 * The L bit (length included) is set to indicate the presence
		 * of the four-octet TLS Message Length field, and MUST be set
		 * for the first fragment of a fragmented TLS message or set of
		 * messages.
		 */
		l_warn("%s: Server has set the L bit in the fragment other "
			"than the first of a fragmented TLS message.",
						eap_get_method_name(eap));

		return 0;
	}

	if (len < 4)
		return -EINVAL;

	if (!(flags & EAP_TLS_FLAG_M))
		/*
		 * EAP-TLS: RFC 5216 Section 3.1
		 *
		 * The M bit (more fragments) is set on all but the last
		 * fragment.
		 *
		 * Note: Some of the EAP-TLS based server implementations break
		 * the protocol and do not set the M flag for the first packet
		 * during the fragmented transmission. To stay compatible with
		 * such devices, we have relaxed this requirement.
		 */
		l_warn("%s: Server has failed to set the M flag in the first"
				" packet of the fragmented transmission.",
						eap_get_method_name(eap));

	tls_msg_len = l_get_be32(pkt);
	len -= 4;

	if (!tls_msg_len || tls_msg_len > EAP_TLS_PDU_MAX_LEN) {
		l_warn("%s: Fragmented pkt size is outside of alowed"
				" boundaries [1, %u]", eap_get_method_name(eap),
							EAP_TLS_PDU_MAX_LEN);

		return -EINVAL;
	}

	if (tls_msg_len == len) {
		/*
		 * EAP-TLS: RFC 5216 Section 3.1
		 *
		 * The L bit (length included) is set to indicate the presence
		 * of the four-octet TLS Message Length field, and MUST be set
		 * for the first fragment of a fragmented TLS message or set of
		 * messages.
		 *
		 * EAP-TTLSv0: RFC 5281, Section 9.2.2:
		 * "Unfragmented messages MAY have the L bit set and include
		 * the length of the message (though this information is
		 * redundant)."
		 *
		 * Some of the PEAP server implementations set the L flag along
		 * with redundant TLS Message Length field for the un-fragmented
		 * packets.
		 */
		l_warn("%s: Server has set the redundant TLS Message Length "
					"field for the un-fragmented packet.",
						eap_get_method_name(eap));

		return -ENOMSG;
	}

	if (tls_msg_len < len) {
		l_warn("%s: Fragmented pkt size is smaller than the received "
					"packet.", eap_get_method_name(eap));

		return -EINVAL;
	}

	eap_tls->rx_pdu_buf = databuf_new(tls_msg_len);

	return 0;
}

static void eap_tls_send_fragmented_request_ack(struct eap_state *eap)
{
	eap_tls_common_send_empty_response(eap);
}

static bool eap_tls_handle_fragmented_response_ack(struct eap_state *eap,
								size_t len)
{
	struct eap_tls_state *eap_tls = eap_get_data(eap);

	if (len)
		return false;

	if (!eap_tls->tx_frag_last_len)
		return false;

	eap_tls->tx_frag_offset += eap_tls->tx_frag_last_len;
	eap_tls->tx_frag_last_len = 0;
	eap_tls->expecting_frag_ack = false;

	eap_tls_send_fragment(eap);

	return true;
}

static int eap_tls_handle_fragmented_request(struct eap_state *eap,
						const uint8_t *pkt,
						size_t len,
						uint8_t flags_version)
{
	struct eap_tls_state *eap_tls = eap_get_data(eap);

	if (flags_version & EAP_TLS_FLAG_L) {
		int r = eap_tls_init_request_assembly(eap, pkt, len,
								flags_version);
		if (r)
			return r;

		pkt += 4;
		len -= 4;
	}

	if (!eap_tls->rx_pdu_buf)
		return -EINVAL;

	if (eap_tls->rx_pdu_buf->capacity < eap_tls->rx_pdu_buf->len + len) {
		l_error("%s: Request fragment pkt size mismatch.",
						eap_get_method_name(eap));
		return -EINVAL;
	}

	databuf_append(eap_tls->rx_pdu_buf, pkt, len);

	if (flags_version & EAP_TLS_FLAG_M) {
		eap_tls_send_fragmented_request_ack(eap);

		return -EAGAIN;
	}

	return 0;
}

static bool eap_tls_tunnel_init(struct eap_state *eap)
{
	struct eap_tls_state *eap_tls = eap_get_data(eap);

	if (eap_tls->tunnel)
		return false;

	eap_tls->tunnel = l_tls_new(false, eap_tls_tunnel_data_received,
					eap_tls_tunnel_data_send,
					eap_tls_tunnel_ready,
					eap_tls_tunnel_disconnected,
					eap);

	if (!eap_tls->tunnel) {
		l_error("%s: Failed to create a TLS instance.",
						eap_get_method_name(eap));
		return false;
	}

	if (getenv("IWD_TLS_DEBUG"))
		l_tls_set_debug(eap_tls->tunnel, eap_tls_tunnel_debug, NULL,
									NULL);

	if (!l_tls_set_auth_data(eap_tls->tunnel, eap_tls->client_cert,
					eap_tls->client_key,
					eap_tls->passphrase)) {
		l_error("%s: Failed to set authentication data.",
						eap_get_method_name(eap));
		return false;
	}

	if (eap_tls->ca_cert)
		l_tls_set_cacert(eap_tls->tunnel, eap_tls->ca_cert);

	return true;
}

void eap_tls_common_handle_request(struct eap_state *eap,
					const uint8_t *pkt, size_t len)
{
	struct eap_tls_state *eap_tls = eap_get_data(eap);
	uint8_t flags_version;

	if (eap_tls->method_completed)
		return;

	if (len < 1) {
		l_error("%s: Request packet is too short.",
						eap_get_method_name(eap));
		goto error;
	}

	flags_version = pkt[0];

	if (!eap_tls_validate_version(eap, flags_version)) {
		l_error("%s: Version negotiation has failed.",
						eap_get_method_name(eap));
		goto error;
	}

	pkt += 1;
	len -= 1;

	if (eap_tls->expecting_frag_ack) {
		if (!eap_tls_handle_fragmented_response_ack(eap, len))
			goto error;

		return;
	}

	if (flags_version & EAP_TLS_FLAG_L || eap_tls->rx_pdu_buf) {
		int r = eap_tls_handle_fragmented_request(eap, pkt, len,
								flags_version);

		if (r == -EAGAIN)
			/* Expecting more fragments. */
			return;

		if (r == -ENOMSG) {
			/*
			 * Redundant usage of the L flag, no packet reassembly
			 * is required.
			 */
			pkt += 4;
			len -= 4;

			goto proceed;
		}

		if (r < 0)
			goto error;

		if (eap_tls->rx_pdu_buf->capacity != eap_tls->rx_pdu_buf->len) {
			l_error("%s: Request fragment packet size mismatch",
						eap_get_method_name(eap));
			goto error;
		}

		pkt = eap_tls->rx_pdu_buf->data;
		len = eap_tls->rx_pdu_buf->len;
	}

proceed:
	if (eap_tls->tx_pdu_buf) {
		/*
		* tx_pdu_buf is used for the re-transmission and needs to be
		* cleared on a new request.
		*/
		databuf_free(eap_tls->tx_pdu_buf);
		eap_tls->tx_pdu_buf = NULL;
	}

	if (flags_version & EAP_TLS_FLAG_S) {
		if (!eap_tls_tunnel_init(eap))
			goto error;
	}

	if (eap_tls->rx_pdu_buf) {
		databuf_free(eap_tls->rx_pdu_buf);
		eap_tls->rx_pdu_buf = NULL;
	}

	if (!eap_tls->tx_pdu_buf) {
		if (eap_tls->phase2_failed)
			goto error;

		return;
	}

	eap_tls_send_response(eap, eap_tls->tx_pdu_buf->data,
						eap_tls->tx_pdu_buf->len);

	if (eap_tls->phase2_failed)
		goto error;

	return;

error:
	eap_method_error(eap);
}

void eap_tls_common_handle_retransmit(struct eap_state *eap,
						const uint8_t *pkt, size_t len)
{
	struct eap_tls_state *eap_tls = eap_get_data(eap);
	uint8_t flags_version;

	if (len < 1) {
		l_error("%s: Request packet is too short.",
						eap_get_method_name(eap));
		goto error;
	}

	flags_version = pkt[0];

	if (!eap_tls_validate_version(eap, flags_version)) {
		l_error("%s: Version negotiation has failed.",
						eap_get_method_name(eap));
		goto error;
	}

	if (flags_version & EAP_TLS_FLAG_M) {
		if (!eap_tls->rx_pdu_buf)
			goto error;

		eap_tls_send_fragmented_request_ack(eap);

		return;
	}

	if (!eap_tls->tx_pdu_buf || !eap_tls->tx_pdu_buf->data ||
						!eap_tls->tx_pdu_buf->len)
		goto error;

	if (EAP_TLS_HEADER_LEN + eap_tls->tx_pdu_buf->len > eap_get_mtu(eap))
		eap_tls_send_fragment(eap);
	else
		eap_tls_send_response(eap, eap_tls->tx_pdu_buf->data,
						eap_tls->tx_pdu_buf->len);

	return;

error:
	eap_method_error(eap);
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
				struct l_settings *settings, const char *prefix,
				const struct eap_tls_variant_ops *variant_ops,
				void *variant_data)
{
	struct eap_tls_state *eap_tls;
	char setting_key[72];

	eap_tls = l_new(struct eap_tls_state, 1);

	eap_tls->version_negotiated = EAP_TLS_VERSION_NOT_NEGOTIATED;
	eap_tls->variant_ops = variant_ops;
	eap_tls->variant_data = variant_data;

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

void eap_tls_common_set_completed(struct eap_state *eap)
{
	struct eap_tls_state *eap_tls = eap_get_data(eap);

	eap_tls->method_completed = true;
}

void eap_tls_common_set_phase2_faild(struct eap_state *eap)
{
	struct eap_tls_state *eap_tls = eap_get_data(eap);

	eap_tls->phase2_failed = true;
}
