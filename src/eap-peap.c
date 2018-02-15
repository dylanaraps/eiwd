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
#include <ell/tls-private.h>

#include "eap.h"

/*
 * Protected EAP Protocol (PEAP): EAP type 25 as described in:
 *
 * PEAPv0: draft-kamath-pppext-peapv0-00
 * PEAPv1: draft-josefsson-pppext-eap-tls-eap-05
 */

#define PEAP_PDU_MAX_LEN 65536

#define PEAP_HEADER_LEN  6

#define PEAP_HEADER_OCTET_FLAGS 5
#define PEAP_HEADER_OCTET_FRAG_LEN 6

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
	PEAP_FLAG_M    = 0x40,
	PEAP_FLAG_L    = 0x80,
};

struct databuf {
	uint8_t *data;
	size_t len;
	size_t capacity;
};

struct eap_peap_state {
	enum peap_version version;
	struct l_tls *tunnel;

	struct databuf *tx_pdu_buf;
	struct databuf *plain_buf;

	uint8_t *rx_pdu_buf;
	size_t rx_pdu_buf_len;
	size_t rx_pdu_buf_offset;

	size_t tx_frag_offset;
	size_t tx_frag_last_len;

	bool expecting_frag_ack:1;

	char *ca_cert;
	char *client_cert;
	char *client_key;
	char *passphrase;
};

static struct databuf *databuf_new(size_t capacity)
{
	struct databuf *databuf;

	if (!capacity)
		return NULL;

	databuf = l_new(struct databuf, 1);
	databuf->data = l_malloc(capacity);
	databuf->capacity = capacity;

	return databuf;
}

static void databuf_append(struct databuf *databuf, const uint8_t *data,
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

static void databuf_free(struct databuf *databuf)
{
	if (!databuf)
		return;

	l_free(databuf->data);
	l_free(databuf);
}

static void eap_peap_free_rx_buffer(struct eap_state *eap)
{
	struct eap_peap_state *peap = eap_get_data(eap);

	if (!peap->rx_pdu_buf)
		return;

	l_free(peap->rx_pdu_buf);
	peap->rx_pdu_buf = NULL;
	peap->rx_pdu_buf_len = 0;
	peap->rx_pdu_buf_offset = 0;
}

static void eap_peap_free(struct eap_state *eap)
{
	struct eap_peap_state *peap = eap_get_data(eap);

	if (peap->tunnel) {
		l_tls_free(peap->tunnel);
		peap->tunnel = NULL;
	}

	if (peap->tx_pdu_buf) {
		databuf_free(peap->tx_pdu_buf);
		peap->tx_pdu_buf = NULL;
	}

	if (peap->plain_buf) {
		databuf_free(peap->plain_buf);
		peap->plain_buf = NULL;
	}

	eap_peap_free_rx_buffer(eap);

	eap_set_data(eap, NULL);

	l_free(peap->ca_cert);
	l_free(peap->client_cert);
	l_free(peap->client_key);
	l_free(peap->passphrase);

	l_free(peap);
}

static void eap_peap_send_fragment(struct eap_state *eap)
{
	struct eap_peap_state *peap = eap_get_data(eap);
	size_t mtu = eap_get_mtu(eap);
	uint8_t buf[mtu];
	size_t len = peap->tx_pdu_buf->len - peap->tx_frag_offset;
	size_t header_len = PEAP_HEADER_LEN;

	buf[PEAP_HEADER_OCTET_FLAGS] = peap->version;

	if (len > mtu - PEAP_HEADER_LEN) {
		len = mtu - PEAP_HEADER_LEN;
		buf[PEAP_HEADER_OCTET_FLAGS] |= PEAP_FLAG_M;
		peap->expecting_frag_ack = true;
	}

	if (!peap->tx_frag_offset) {
		buf[PEAP_HEADER_OCTET_FLAGS] |= PEAP_FLAG_L;
		l_put_be32(peap->tx_pdu_buf->len,
					&buf[PEAP_HEADER_OCTET_FRAG_LEN]);
		len -= 4;
		header_len += 4;
	}

	memcpy(buf + header_len, peap->tx_pdu_buf->data + peap->tx_frag_offset,
									len);
	eap_send_response(eap, EAP_TYPE_PEAP, buf, header_len + len);

	peap->tx_frag_last_len = len;
}

static void eap_peap_send_response(struct eap_state *eap,
					const uint8_t *pdu, size_t pdu_len)
{
	struct eap_peap_state *peap = eap_get_data(eap);
	size_t msg_len = PEAP_HEADER_LEN + pdu_len;

	if (msg_len <= eap_get_mtu(eap)) {
		uint8_t buf[msg_len];

		buf[PEAP_HEADER_OCTET_FLAGS] = peap->version;
		memcpy(buf + PEAP_HEADER_LEN, pdu, pdu_len);

		eap_send_response(eap, EAP_TYPE_PEAP, buf, msg_len);
		return;
	}

	peap->tx_frag_offset = 0;
	eap_peap_send_fragment(eap);
}

static void eap_peap_send_empty_response(struct eap_state *eap)
{
	struct eap_peap_state *peap = eap_get_data(eap);
	uint8_t buf[PEAP_HEADER_LEN];

	buf[PEAP_HEADER_OCTET_FLAGS] = peap->version;

	eap_send_response(eap, EAP_TYPE_PEAP, buf, PEAP_HEADER_LEN);
}

static void eap_peap_tunnel_data_send(const uint8_t *data, size_t data_len,
								void *user_data)
{
}

static void eap_peap_tunnel_data_received(const uint8_t *data, size_t data_len,
								void *user_data)
{
	struct eap_state *eap = user_data;
	struct eap_peap_state *peap = eap_get_data(eap);

	if (!peap->plain_buf)
		peap->plain_buf = databuf_new(data_len);

	databuf_append(peap->plain_buf, data, data_len);
}

static void eap_peap_tunnel_ready(const char *peer_identity, void *user_data)
{
	struct eap_state *eap = user_data;
	struct eap_peap_state *peap = eap_get_data(eap);

	uint8_t msk_emsk[128];
	uint8_t random[64];

	/*
	* PEAP V5, Section 2.1.1
	*
	* Cleartext Failure packets MUST be silently discarded once TLS tunnel
	* has been brought up.
	*/
	eap_method_success(eap);

	/* MSK, EMSK and challenge derivation */
	memcpy(random +  0, peap->tunnel->pending.client_random, 32);
	memcpy(random + 32, peap->tunnel->pending.server_random, 32);

	tls_prf_get_bytes(peap->tunnel, L_CHECKSUM_SHA256, 32,
				peap->tunnel->pending.master_secret,
				sizeof(peap->tunnel->pending.master_secret),
				"client EAP encryption", random, 64,
				msk_emsk, 128);

	eap_set_key_material(eap, msk_emsk + 0, 64, NULL, 0, NULL, 0);

	eap_peap_send_empty_response(eap);
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

static void eap_peap_handle_payload(struct eap_state *eap,
						const uint8_t *pkt,
						size_t pkt_len)
{
}

static bool eap_peap_init_request_assembly(struct eap_state *eap,
						const uint8_t *pkt, size_t len,
						uint8_t flags) {
	struct eap_peap_state *peap = eap_get_data(eap);

	if (peap->rx_pdu_buf || !(flags & PEAP_FLAG_M) || len < 4)
		return false;

	peap->rx_pdu_buf_len = l_get_be32(pkt);

	if (!peap->rx_pdu_buf_len || peap->rx_pdu_buf_len > PEAP_PDU_MAX_LEN) {
		l_warn("Fragmented pkt size is outside of alowed boundaries "
					"[1, %u]", PEAP_PDU_MAX_LEN);

		return false;
	}

	if (peap->rx_pdu_buf_len < len) {
		l_warn("Fragmented pkt size is smaller than the received "
								"packet");

		return false;
	}

	peap->rx_pdu_buf = l_malloc(peap->rx_pdu_buf_len);
	peap->rx_pdu_buf_offset = 0;

	return true;
}

static void eap_peap_send_fragmented_request_ack(struct eap_state *eap)
{
	eap_peap_send_empty_response(eap);
}

static bool eap_peap_handle_fragmented_response_ack(struct eap_state *eap,
								size_t len)
{
	struct eap_peap_state *peap = eap_get_data(eap);

	if (len)
		return false;

	if (!peap->tx_frag_last_len)
		return false;

	peap->tx_frag_offset += peap->tx_frag_last_len;
	peap->tx_frag_last_len = 0;
	peap->expecting_frag_ack = false;

	eap_peap_send_fragment(eap);

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

static int eap_peap_handle_fragmented_request(struct eap_state *eap,
						const uint8_t *pkt,
						size_t len,
						uint8_t flags_version)
{
	struct eap_peap_state *peap = eap_get_data(eap);
	size_t rx_header_offset = 0;
	size_t pdu_len;

	if (flags_version & PEAP_FLAG_L) {
		if (!eap_peap_init_request_assembly(eap, pkt, len,
								flags_version))
			return -EINVAL;

		rx_header_offset = 4;
	}

	if (!peap->rx_pdu_buf)
		return -EINVAL;

	pdu_len = len - rx_header_offset;

	if (peap->rx_pdu_buf_len < peap->rx_pdu_buf_offset + pdu_len) {
		l_error("Request fragment pkt size mismatch");
		return -EINVAL;
	}

	memcpy(peap->rx_pdu_buf + peap->rx_pdu_buf_offset,
					pkt + rx_header_offset, pdu_len);
	peap->rx_pdu_buf_offset += pdu_len;

	if (flags_version & PEAP_FLAG_M) {
		eap_peap_send_fragmented_request_ack(eap);

		return -EAGAIN;
	}

	return 0;
}

static void eap_peap_handle_request(struct eap_state *eap,
					const uint8_t *pkt, size_t len)
{
	struct eap_peap_state *peap = eap_get_data(eap);
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

	pkt += 1;
	len -= 1;

	if (peap->expecting_frag_ack) {
		if (!eap_peap_handle_fragmented_response_ack(eap, len))
			goto error;

		return;
	}

	if (flags_version & PEAP_FLAG_L || peap->rx_pdu_buf) {
		int r = eap_peap_handle_fragmented_request(eap, pkt, len,
								flags_version);

		if (r == -EAGAIN)
			return;

		if (r < 0)
			goto error;

		if (peap->rx_pdu_buf_len != peap->rx_pdu_buf_offset) {
			l_error("Request fragment pkt size mismatch");
			goto error;
		}

		pkt = peap->rx_pdu_buf;
		len = peap->rx_pdu_buf_len;
	}

	/*
	 * tx_pdu_buf is used for the retransmission and needs to be cleared on
	 * a new request
	 */
	if (peap->tx_pdu_buf) {
		databuf_free(peap->tx_pdu_buf);
		peap->tx_pdu_buf = NULL;
	}

	if (flags_version & PEAP_FLAG_S) {
		if (!eap_peap_tunnel_init(eap))
			goto error;

		/*
		 * PEAPv2 packets may include optional Outer TLVs (TLVs outside
		 * the TLS tunnel), which are only allowed in the first two
		 * messages before the version negotiation has occurred. Since
		 * PEAPv2 is not currently supported, we set len to zero to
		 * ignore them.
		 */
		len = 0;
	}

	if (!len)
		goto send_response;

	eap_peap_handle_payload(eap, pkt, len);

	eap_peap_free_rx_buffer(eap);

send_response:
	if (!peap->tx_pdu_buf)
		return;

	eap_peap_send_response(eap, peap->tx_pdu_buf->data,
							peap->tx_pdu_buf->len);

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
