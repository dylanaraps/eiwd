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
#include "eap-private.h"

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
	bool completed:1;
	bool phase2_failed:1;

	struct eap_state *phase2_eap;

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

static void eap_peap_free_rx_buffer(struct eap_peap_state *peap)
{
	if (!peap->rx_pdu_buf)
		return;

	l_free(peap->rx_pdu_buf);
	peap->rx_pdu_buf = NULL;
	peap->rx_pdu_buf_len = 0;
	peap->rx_pdu_buf_offset = 0;
}

static void __eap_peap_reset_state(struct eap_peap_state *peap)
{
	peap->version = PEAP_VERSION_NOT_NEGOTIATED;
	peap->completed = false;
	peap->phase2_failed = false;
	peap->expecting_frag_ack = false;

	if (peap->tunnel) {
		l_tls_free(peap->tunnel);
		peap->tunnel = NULL;
	}

	peap->tx_frag_offset = 0;
	peap->tx_frag_last_len = 0;

	if (peap->tx_pdu_buf) {
		databuf_free(peap->tx_pdu_buf);
		peap->tx_pdu_buf = NULL;
	}

	if (peap->plain_buf) {
		databuf_free(peap->plain_buf);
		peap->plain_buf = NULL;
	}

	eap_peap_free_rx_buffer(peap);
}

static bool eap_peap_reset_state(struct eap_state *eap)
{
	struct eap_peap_state *peap = eap_get_data(eap);

	if (!peap->phase2_eap)
		return false;

	if (!eap_reset(peap->phase2_eap))
		return false;

	__eap_peap_reset_state(peap);
	return true;
}

static void eap_peap_free(struct eap_state *eap)
{
	struct eap_peap_state *peap = eap_get_data(eap);

	__eap_peap_reset_state(peap);
	eap_set_data(eap, NULL);

	if (peap->phase2_eap) {
		eap_free(peap->phase2_eap);
		peap->phase2_eap = NULL;
	}

	l_free(peap->ca_cert);
	l_free(peap->client_cert);
	l_free(peap->client_key);

	if (peap->passphrase) {
		memset(peap->passphrase, 0, strlen(peap->passphrase));
		l_free(peap->passphrase);
	}

	l_free(peap);
}

static void eap_peap_phase2_send_response(const uint8_t *pdu, size_t pdu_len,
								void *user_data)
{
	struct eap_state *eap = user_data;
	struct eap_peap_state *peap = eap_get_data(eap);

	if (peap->version == PEAP_VERSION_0) {
		if (pdu_len < 5)
			return;

		if (pdu[4] != EAP_TYPE_EXTENSIONS) {
			pdu += 4;
			pdu_len -= 4;
		}
	}

	l_tls_write(peap->tunnel, pdu, pdu_len);
}

static void eap_peap_phase2_complete(enum eap_result result, void *user_data)
{
	struct eap_state *eap = user_data;
	struct eap_peap_state *peap = eap_get_data(eap);

	/*
	 * PEAPv1: draft-josefsson-pppext-eap-tls-eap-05, Section 2.2
	 *
	 * The receipt of a EAP-Failure or EAP-Success within the TLS protected
	 * channel results in a shutdown of the TLS channel by the peer.
	 */
	l_tls_close(peap->tunnel);

	eap_discard_success_and_failure(eap, false);
	peap->completed = true;

	if (result != EAP_RESULT_SUCCESS) {
		peap->phase2_failed = true;
		return;
	}

	eap_method_success(eap);
}

/*
 * PEAPv0: draft-kamath-pppext-peapv0-00, Section 2
 */
#define EAP_EXTENSIONS_HEADER_LEN 5
#define EAP_EXTENSIONS_AVP_HEADER_LEN 4

enum eap_extensions_avp_type {
	/* Reserved = 0x0000, */
	/* Reserved = 0x0001, */
	/* Reserved = 0x0002, */
	EAP_EXTENSIONS_AVP_TYPE_RESULT = 0x8003,
};

enum eap_extensions_result {
	EAP_EXTENSIONS_RESULT_SUCCCESS = 1,
	EAP_EXTENSIONS_RESULT_FAILURE  = 2,
};

static int eap_extensions_handle_result_avp(struct eap_state *eap,
						const uint8_t *data,
						size_t data_len,
						uint8_t *response)
{
	struct eap_peap_state *peap = eap_get_data(eap);
	uint16_t type;
	uint16_t len;
	uint16_t result;

	if (data_len < EAP_EXTENSIONS_AVP_HEADER_LEN + 2)
		return -ENOENT;

	type = l_get_be16(data);

	if (type != EAP_EXTENSIONS_AVP_TYPE_RESULT)
		return -ENOENT;

	data += 2;

	len = l_get_be16(data);

	if (len != 2)
		return -ENOENT;

	data += 2;

	result = l_get_be16(data);

	switch (result) {
	case EAP_EXTENSIONS_RESULT_SUCCCESS:
		result = eap_method_is_success(peap->phase2_eap) ?
					EAP_EXTENSIONS_RESULT_SUCCCESS :
					EAP_EXTENSIONS_RESULT_FAILURE;
		/* fall through */
	case EAP_EXTENSIONS_RESULT_FAILURE:
		break;
	default:
		return -ENOENT;
	}

	l_put_be16(EAP_EXTENSIONS_AVP_TYPE_RESULT,
					&response[EAP_EXTENSIONS_HEADER_LEN]);
	l_put_be16(2, &response[EAP_EXTENSIONS_HEADER_LEN + 2]);
	l_put_be16(result, &response[EAP_EXTENSIONS_HEADER_LEN +
						EAP_EXTENSIONS_AVP_HEADER_LEN]);

	return result;
}

static void eap_extensions_handle_request(struct eap_state *eap,
							uint8_t id,
							const uint8_t *pkt,
							size_t len)
{
	struct eap_peap_state *peap = eap_get_data(eap);
	uint8_t response[EAP_EXTENSIONS_HEADER_LEN +
					EAP_EXTENSIONS_AVP_HEADER_LEN + 2];
	int r = eap_extensions_handle_result_avp(eap, pkt, len, response);

	if (r < 0)
		return;

	response[0] = EAP_CODE_RESPONSE;
	response[1] = id;
	l_put_be16(sizeof(response), &response[2]);
	response[4] = EAP_TYPE_EXTENSIONS;

	eap_peap_phase2_send_response(response, sizeof(response), eap);

	l_tls_close(peap->tunnel);

	eap_discard_success_and_failure(eap, false);
	peap->completed = true;

	if (r != EAP_EXTENSIONS_RESULT_SUCCCESS)
		return;

	eap_method_success(eap);
}

static void eap_peap_phase2_handle_request(struct eap_state *eap,
							const uint8_t *pkt,
								size_t len)
{
	struct eap_peap_state *peap = eap_get_data(eap);
	uint8_t id;

	if (len > 4 && pkt[4] == EAP_TYPE_EXTENSIONS) {
		uint16_t pkt_len;
		uint8_t code = pkt[0];

		if (code != EAP_CODE_REQUEST)
			return;

		pkt_len = l_get_be16(pkt + 2);
		if (pkt_len != len)
			return;

		id = pkt[1];

		eap_extensions_handle_request(eap, id,
				pkt + EAP_EXTENSIONS_HEADER_LEN,
				len - EAP_EXTENSIONS_HEADER_LEN);

		return;
	}

	if (peap->version == PEAP_VERSION_0) {
		if (len < 1)
			return;

		/*
		 * The PEAPv0 phase2 packets are headerless. Our implementation
		 * of the EAP methods requires packet identifier. Therefore,
		 * PEAP packet identifier is used for the headerless
		 * phase2 packets.
		 */
		eap_save_last_id(eap, &id);

		__eap_handle_request(peap->phase2_eap, id, pkt, len);

		return;
	}

	eap_rx_packet(peap->phase2_eap, pkt, len);
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
	struct eap_state *eap = user_data;
	struct eap_peap_state *peap = eap_get_data(eap);

	if (!peap->tx_pdu_buf)
		peap->tx_pdu_buf = databuf_new(data_len);

	databuf_append(peap->tx_pdu_buf, data, data_len);
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

	/*
	* PEAPv1: draft-josefsson-pppext-eap-tls-eap-05, Section 2.1.1
	*
	* Cleartext Success/Failure packets MUST be silently discarded once TLS
	* tunnel has been brought up.
	*/
	eap_discard_success_and_failure(eap, true);

	/*
	 * PEAPv1: draft-josefsson-pppext-eap-tls-eap-05, Section 2.2
	 *
	 * Since authenticator may not send us EAP-Success/EAP-Failure
	 * in cleartext for the outer EAP method (PEAP), we reinforce
	 * the completion with a timer.
	 */
	eap_start_complete_timeout(eap);

	/* MSK, EMSK and challenge derivation */
	l_tls_prf_get_bytes(peap->tunnel, true,
				"client EAP encryption", msk_emsk, 128);

	eap_set_key_material(eap, msk_emsk + 0, 64, NULL, 0, NULL, 0);

	eap_peap_send_empty_response(eap);
}

static void eap_peap_tunnel_disconnected(enum l_tls_alert_desc reason,
						bool remote, void *user_data)
{
	l_info("PEAP TLS tunnel has disconnected with alert: %s",
		l_tls_alert_to_str(reason));
}

static void eap_peap_debug_cb(const char *str, void *user_data)
{
	l_info("PEAP TLS %s", str);
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

	if (getenv("IWD_TLS_DEBUG"))
		l_tls_set_debug(peap->tunnel, eap_peap_debug_cb, NULL, NULL);

	if (!l_tls_set_auth_data(peap->tunnel, peap->client_cert,
				peap->client_key, NULL) ||
			(peap->ca_cert &&
			 !l_tls_set_cacert(peap->tunnel, peap->ca_cert))) {
		l_error("PEAP: Failed to set authentication data.");
		return false;
	}

	return true;
}

static void eap_peap_handle_payload(struct eap_state *eap,
						const uint8_t *pkt,
						size_t pkt_len)
{
	struct eap_peap_state *peap = eap_get_data(eap);

	l_tls_handle_rx(peap->tunnel, pkt, pkt_len);

	/* Plaintext phase two eap packet is stored into peap->plain_buf */
	if (!peap->plain_buf)
		return;

	eap_peap_phase2_handle_request(eap, peap->plain_buf->data,
							peap->plain_buf->len);

	databuf_free(peap->plain_buf);
	peap->plain_buf = NULL;
}

static int eap_peap_init_request_assembly(struct eap_state *eap,
						const uint8_t *pkt, size_t len,
						uint8_t flags) {
	struct eap_peap_state *peap = eap_get_data(eap);

	if (peap->rx_pdu_buf || len < 4)
		return -EINVAL;

	/*
	 * Some of the PEAP server implementations break the protocol and do not
	 * set the M flag for the first packet during the fragmented
	 * transmission. To stay compatible with such devices, we have relaxed
	 * this requirement in iwd.
	 */
	if (!(flags & PEAP_FLAG_M))
		l_warn("PEAP: Server has failed to set the M flag in the first"
				" packet of the fragmented transmission.");

	peap->rx_pdu_buf_len = l_get_be32(pkt);
	len -= 4;

	if (!peap->rx_pdu_buf_len || peap->rx_pdu_buf_len > PEAP_PDU_MAX_LEN) {
		l_warn("PEAP: Fragmented pkt size is outside of alowed"
				" boundaries [1, %u]", PEAP_PDU_MAX_LEN);

		return -EINVAL;
	}

	if (peap->rx_pdu_buf_len == len) {
		/*
		 * PEAPv1: draft-josefsson-pppext-eap-tls-eap-05, Section 3.2:
		 * "The L bit (length included) is set to indicate the presence
		 * of the four octet TLS Message Length field, and MUST be set
		 * for the first fragment of a fragmented TLS message or set of
		 * messages."
		 *
		 * TTLSv0: RFC 5281, Section 9.2.2:
		 * "Unfragmented messages MAY have the L bit set and include
		 * the length of the message (though this information is
		 * redundant)."
		 *
		 * Some of the PEAP server implementations set the L flag along
		 * with redundant TLS Message Length field for the un-fragmented
		 * packets.
		 */
		l_warn("PEAP: Server has set the redundant TLS Message Length "
					"field for the un-fragmented packet.");

		return -ENOMSG;
	}

	if (peap->rx_pdu_buf_len < len) {
		l_warn("PEAP: Fragmented pkt size is smaller than the received "
								"packet");

		return -EINVAL;
	}

	peap->rx_pdu_buf = l_malloc(peap->rx_pdu_buf_len);
	peap->rx_pdu_buf_offset = 0;

	return 0;
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
		int r = eap_peap_init_request_assembly(eap, pkt, len,
								flags_version);
		if (r)
			return r;

		rx_header_offset = 4;
	}

	if (!peap->rx_pdu_buf)
		return -EINVAL;

	pdu_len = len - rx_header_offset;

	if (peap->rx_pdu_buf_len < peap->rx_pdu_buf_offset + pdu_len) {
		l_error("PEAP: Request fragment pkt size mismatch");
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

	if (peap->completed)
		return;

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

		if (peap->rx_pdu_buf_len != peap->rx_pdu_buf_offset) {
			l_error("PEAP: Request fragment pkt size mismatch");
			goto error;
		}

		pkt = peap->rx_pdu_buf;
		len = peap->rx_pdu_buf_len;
	}

proceed:
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

	eap_peap_free_rx_buffer(peap);

send_response:
	if (!peap->tx_pdu_buf) {
		if (peap->phase2_failed)
			goto error;

		return;
	}

	eap_peap_send_response(eap, peap->tx_pdu_buf->data,
							peap->tx_pdu_buf->len);

	if (peap->phase2_failed)
		goto error;

	return;

error:
	eap_method_error(eap);
}

static void eap_peap_handle_retransmit(struct eap_state *eap,
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
		l_error("EAP-PEAP version validation failed");
		goto error;
	}

	if (flags_version & PEAP_FLAG_M) {
		if (!peap->rx_pdu_buf)
			goto error;

		eap_peap_send_fragmented_request_ack(eap);

		return;
	}

	if (!peap->tx_pdu_buf || !peap->tx_pdu_buf->data ||
							!peap->tx_pdu_buf->len)
		goto error;

	if (PEAP_HEADER_LEN + peap->tx_pdu_buf->len > eap_get_mtu(eap))
		eap_peap_send_fragment(eap);
	else
		eap_peap_send_response(eap, peap->tx_pdu_buf->data,
							peap->tx_pdu_buf->len);

	return;

error:
	eap_method_error(eap);
}

static int eap_peap_check_settings(struct l_settings *settings,
					struct l_queue *secrets,
					const char *prefix,
					struct l_queue **out_missing)
{
	char entry[64], client_cert_entry[64], passphrase_entry[64];
	L_AUTO_FREE_VAR(char *, path) = NULL;
	L_AUTO_FREE_VAR(char *, client_cert) = NULL;
	L_AUTO_FREE_VAR(char *, passphrase) = NULL;
	uint8_t *cert;
	size_t size;

	snprintf(entry, sizeof(entry), "%sPEAP-CACert", prefix);
	path = l_settings_get_string(settings, "Security", entry);
	if (path) {
		cert = l_pem_load_certificate(path, &size);
		if (!cert) {
			l_error("Failed to load %s", path);
			return -EIO;
		}

		l_free(cert);
	}

	snprintf(client_cert_entry, sizeof(client_cert_entry),
			"%sPEAP-ClientCert", prefix);
	client_cert = l_settings_get_string(settings, "Security",
						client_cert_entry);
	if (client_cert) {
		cert = l_pem_load_certificate(client_cert, &size);
		if (!cert) {
			l_error("PEAP: Failed to load %s", client_cert);
			return -EIO;
		}

		l_free(cert);
	}

	l_free(path);

	snprintf(entry, sizeof(entry), "%sPEAP-ClientKey", prefix);
	path = l_settings_get_string(settings, "Security", entry);

	if (path && !client_cert) {
		l_error("%s present but no client certificate (%s)",
			entry, client_cert_entry);
		return -ENOENT;
	}

	snprintf(passphrase_entry, sizeof(passphrase_entry),
			"%sPEAP-ClientKeyPassphrase", prefix);
	passphrase = l_settings_get_string(settings, "Security",
						passphrase_entry);

	if (!passphrase) {
		const struct eap_secret_info *secret;

		secret = l_queue_find(secrets, eap_secret_info_match,
					passphrase_entry);
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
					passphrase_entry, NULL, path,
					EAP_CACHE_TEMPORARY);
		} else {
			l_key_free(priv_key);

			if (passphrase && !encrypted) {
				l_error("%s present but client private "
					"key %s is not encrypted",
					passphrase_entry, path);
				return -EIO;
			}
		}
	} else if (passphrase) {
		l_error("%s present but no client private key path set (%s)",
			passphrase_entry, entry);
		return -ENOENT;
	}

	snprintf(entry, sizeof(entry), "%sPEAP-Phase2-", prefix);

	return __eap_check_settings(settings, secrets, entry, false,
					out_missing);
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
	peap->ca_cert = l_settings_get_string(settings, "Security", entry);

	snprintf(entry, sizeof(entry), "%sPEAP-ClientCert", prefix);
	peap->client_cert = l_settings_get_string(settings, "Security", entry);

	snprintf(entry, sizeof(entry), "%sPEAP-ClientKey", prefix);
	peap->client_key = l_settings_get_string(settings, "Security", entry);

	snprintf(entry, sizeof(entry), "%sPEAP-ClientKeyPassphrase", prefix);
	peap->passphrase = l_settings_get_string(settings, "Security", entry);

	peap->phase2_eap = eap_new(eap_peap_phase2_send_response,
					eap_peap_phase2_complete, eap);

	if (!peap->phase2_eap) {
		l_error("Could not create the PEAP phase two EAP instance");
		goto error;
	}

	snprintf(entry, sizeof(entry), "%sPEAP-Phase2-", prefix);

	if (!eap_load_settings(peap->phase2_eap, settings, entry)) {
		eap_free(peap->phase2_eap);

		goto error;
	}

	eap_set_data(eap, peap);

	return true;

error:
	l_free(peap->ca_cert);
	l_free(peap->client_cert);
	l_free(peap->client_key);
	if (peap->passphrase)
		memset(peap->passphrase, 0, strlen(peap->passphrase));
	l_free(peap->passphrase);
	l_free(peap);

	return false;
}

static struct eap_method eap_peap = {
	.request_type = EAP_TYPE_PEAP,
	.name = "PEAP",
	.exports_msk = true,

	.handle_request = eap_peap_handle_request,
	.handle_retransmit = eap_peap_handle_retransmit,
	.check_settings = eap_peap_check_settings,
	.load_settings = eap_peap_load_settings,
	.free = eap_peap_free,
	.reset_state = eap_peap_reset_state,
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
