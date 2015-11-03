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
#include <ell/tls-private.h>

#include "eap.h"

struct eap_ttls_state {
	char *ca_cert;
	char *client_cert;
	char *client_key;
	char *passphrase;

	struct l_tls *tls;
	uint8_t *rx_pkt_buf;
	size_t rx_pkt_received, rx_pkt_len;
	uint8_t *tx_pkt_buf;
	size_t tx_pkt_len, tx_pkt_capacity, tx_pkt_offset;
	uint8_t *avp_buf;
	size_t avp_received, avp_capacity;
	bool phase1_completed;
	bool completed;
	struct eap_state *eap;
	uint8_t negotiated_version;
};

static int eap_ttls_probe(struct eap_state *eap, const char *name)
{
	struct eap_ttls_state *ttls;

	if (strcasecmp(name, "TTLS"))
		return -ENOTSUP;

	ttls = l_new(struct eap_ttls_state, 1);

	eap_set_data(eap, ttls);

	return 0;
}

static void eap_ttls_remove(struct eap_state *eap)
{
	struct eap_ttls_state *ttls = eap_get_data(eap);

	eap_set_data(eap, NULL);

	l_free(ttls->ca_cert);
	l_free(ttls->client_cert);
	l_free(ttls->client_key);
	l_free(ttls->passphrase);

	if (ttls->rx_pkt_buf) {
		l_free(ttls->rx_pkt_buf);
		ttls->rx_pkt_buf = NULL;
	}

	if (ttls->tx_pkt_buf) {
		l_free(ttls->tx_pkt_buf);
		ttls->tx_pkt_buf = NULL;
		ttls->tx_pkt_capacity = 0;
		ttls->tx_pkt_len = 0;
	}

	if (ttls->avp_buf) {
		l_free(ttls->avp_buf);
		ttls->avp_buf = NULL;
		ttls->avp_received = 0;
	}

	if (ttls->eap) {
		eap_free(ttls->eap);
		ttls->eap = NULL;
	}

	if (ttls->tls) {
		l_tls_free(ttls->tls);
		ttls->tls = NULL;
	}

	l_free(ttls);
}

#define EAP_TTLS_RESPONSE_HEADER_LEN	10

#define EAP_TTLS_FLAG_L	(1 << 7)
#define EAP_TTLS_FLAG_M	(1 << 6)
#define EAP_TTLS_FLAG_S	(1 << 5)
#define EAP_TTLS_FLAG_MASK	\
	(EAP_TTLS_FLAG_L | EAP_TTLS_FLAG_M | EAP_TTLS_FLAG_S)

static uint8_t *eap_ttls_tx_buf_reserve(struct eap_ttls_state *ttls,
					size_t size)
{
	int offset = ttls->tx_pkt_offset + ttls->tx_pkt_len;
	size_t end_offset = offset + size;

	ttls->tx_pkt_len += size;

	if (end_offset > ttls->tx_pkt_capacity) {
		ttls->tx_pkt_capacity = end_offset + 1024;
		ttls->tx_pkt_buf =
			l_realloc(ttls->tx_pkt_buf, ttls->tx_pkt_capacity);
	}

	return ttls->tx_pkt_buf + offset;
}

static void eap_ttls_tx_cb(const uint8_t *data, size_t len, void *user_data)
{
	struct eap_state *eap = user_data;
	struct eap_ttls_state *ttls = eap_get_data(eap);

	memcpy(eap_ttls_tx_buf_reserve(ttls, len), data, len);
}

struct eap_ttls_avp {
	__be32 avp_code;
	uint8_t avp_flags;
	uint8_t avp_len[3];
	uint8_t data[0];
} __attribute__ ((packed));

#define EAP_TTLS_AVP_FLAG_V	(1 << 7)
#define EAP_TTLS_AVP_FLAG_M	(1 << 6)

#define RADIUS_AVP_EAP_MESSAGE	79

static bool eap_ttls_handle_avp(struct eap_state *eap, struct eap_ttls_avp *avp)
{
	struct eap_ttls_state *ttls = eap_get_data(eap);
	uint8_t *data;
	uint64_t code;
	size_t data_len;

	data = avp->data;
	data_len = ((avp->avp_len[0] << 16) |
		(avp->avp_len[1] << 8) |
		(avp->avp_len[2] << 0)) - sizeof(struct eap_ttls_avp);

	code = l_get_be32(&avp->avp_code);

	if (avp->avp_flags & EAP_TTLS_AVP_FLAG_V) {
		if (data_len < 4)
			goto avp_err;

		code |= (uint64_t) l_get_be32(data) << 32;
		data += 4;
		data_len -= 4;
	}

	switch (code) {
	/* EAP-Message attribute, actually defined in RFC2869 5.13 */
	case RADIUS_AVP_EAP_MESSAGE:
		if (!ttls->eap)
			goto avp_err;

		/* TODO: split if necessary */
		eap_rx_packet(ttls->eap, data, data_len);

		break;

	default:
		if (avp->avp_flags & EAP_TTLS_AVP_FLAG_M)
			goto avp_err;

		break;
	}

	return true;

avp_err:
	l_tls_close(ttls->tls);

	return false;
}

static size_t avp_min_len(const uint8_t *buf, size_t len)
{
	struct eap_ttls_avp *avp;

	if (len < sizeof(struct eap_ttls_avp))
		return sizeof(struct eap_ttls_avp);

	avp = (struct eap_ttls_avp *) buf;

	return (((avp->avp_len[0] << 16) |
		(avp->avp_len[1] << 8) |
		(avp->avp_len[2] << 0)) + 3) & ~3;
}

static void eap_ttls_data_cb(const uint8_t *data, size_t len, void *user_data)
{
	struct eap_state *eap = user_data;
	struct eap_ttls_state *ttls = eap_get_data(eap);
	struct eap_ttls_avp *avp;
	size_t avp_len, chunk_len;

	/* Continue assembling the AVP that we have buffered */
	while (ttls->avp_received) {
		avp_len = avp_min_len(ttls->avp_buf, ttls->avp_received);
		chunk_len = avp_len - ttls->avp_received;

		if (chunk_len > len)
			chunk_len = len;

		if (ttls->avp_received + chunk_len > ttls->avp_capacity) {
			ttls->avp_capacity = avp_len;
			ttls->avp_buf = l_realloc(ttls->avp_buf,
							ttls->avp_capacity);
		}

		memcpy(ttls->avp_buf + ttls->avp_received, data, chunk_len);
		ttls->avp_received += chunk_len;

		if (avp_len > ttls->avp_received) /* Wait for more data */
			return;

		/* Do we have a full AVP or just the header */
		if (ttls->avp_received - chunk_len >=
				sizeof(struct eap_ttls_avp)) {
			ttls->avp_received = 0;

			avp = (struct eap_ttls_avp *) ttls->avp_buf;

			if (!eap_ttls_handle_avp(eap, avp))
				return;

			data += chunk_len;
			len -= chunk_len;
		}
	}

	/* Handle all the AVPs fully contained in the newly received data */
	while (len) {
		avp_len = avp_min_len(data, len);
		if (len < avp_len || len < sizeof(struct eap_ttls_avp))
			break;

		avp = (struct eap_ttls_avp *) data;

		if (!eap_ttls_handle_avp(eap, avp))
			return;

		data += avp_len;
		len -= avp_len;
	}

	if (!len)
		return;

	/* Store the remaining bytes */
	if (ttls->avp_capacity < len) {
		ttls->avp_capacity = avp_len;
		ttls->avp_buf = l_realloc(ttls->avp_buf, ttls->avp_capacity);
	}

	memcpy(ttls->avp_buf, data, len);
	ttls->avp_received = len;
}

static void eap_ttls_eap_tx_packet(const uint8_t *eap_data, size_t len,
					void *user_data)
{
	struct eap_state *eap = user_data;
	struct eap_ttls_state *ttls = eap_get_data(eap);
	uint8_t buf[sizeof(struct eap_ttls_avp) + len + 3];
	struct eap_ttls_avp *avp = (struct eap_ttls_avp *) buf;
	size_t avp_len = sizeof(struct eap_ttls_avp) + len;

	l_put_be32(RADIUS_AVP_EAP_MESSAGE, &avp->avp_code);

	avp->avp_flags = EAP_TTLS_AVP_FLAG_M;

	avp->avp_len[0] = avp_len >> 16;
	avp->avp_len[1] = avp_len >>  8;
	avp->avp_len[2] = avp_len >>  0;

	memcpy(avp->data, eap_data, len);

	if (avp_len & 3)
		memset(avp->data + len, 0, 4 - (avp_len & 3));

	l_tls_write(ttls->tls, buf, (avp_len + 3) & ~3);
}

static void eap_ttls_eap_complete(enum eap_result result, void *user_data)
{
	struct eap_state *eap = user_data;
	struct eap_ttls_state *ttls = eap_get_data(eap);
	uint8_t last_id;

	eap_save_last_id(ttls->eap, &last_id);

	/* Prepare for possible chained authentication */
	/* We currently have no way to configure the new instance */
	eap_free(ttls->eap);
	ttls->eap = eap_new(eap_ttls_eap_tx_packet,
				eap_ttls_eap_complete, eap);

	if (!ttls->eap) {
		ttls->completed = true;
		return;
	}

	/* Preserve the last_id as mandated by 11.3 */
	eap_restore_last_id(ttls->eap, last_id);
}

static void eap_ttls_ready_cb(const char *peer_identity, void *user_data)
{
	struct eap_state *eap = user_data;
	struct eap_ttls_state *ttls = eap_get_data(eap);
	uint8_t msk_emsk[128];
	uint8_t seed[64];
	uint8_t packet[5] = { EAP_CODE_REQUEST, 0, 0, 5, EAP_TYPE_IDENTITY };

	/* TODO: if we have a CA certificate require non-NULL peer_identity */

	ttls->phase1_completed = true;

	/*
	 * TTLSv0 seems to assume that the TLS handshake phase authenticates
	 * the server to the client enough that the inner method success or
	 * failure status doesn't matter as long as the server lets us in,
	 * although in various places it says the client may also have a
	 * specific policy.
	 */
	eap_method_success(eap);

	/* MSK, EMSK and challenge derivation */
	memcpy(seed +  0, ttls->tls->pending.client_random, 32);
	memcpy(seed + 32, ttls->tls->pending.server_random, 32);

	tls_prf_get_bytes(ttls->tls, L_CHECKSUM_SHA256, 32,
				ttls->tls->pending.master_secret,
				sizeof(ttls->tls->pending.master_secret),
				"ttls keying material", seed, 64,
				msk_emsk, 128);

	memset(seed, 0, 64);

	eap_set_key_material(eap, msk_emsk + 0, 64, msk_emsk + 64, 64,
				NULL, 0);

	/* Start the EAP negotiation */
	if (!ttls->eap) {
		ttls->eap = eap_new(eap_ttls_eap_tx_packet,
					eap_ttls_eap_complete, eap);
		if (!ttls->eap) {
			l_error("Could not create the TTLS inner EAP instance");
			goto err;
		}
	}

	/*
	 * Consume a fake Request/Identity packet so that the EAP instance
	 * starts with its Response/Identity right away.
	 */
	eap_rx_packet(ttls->eap, packet, sizeof(packet));

	return;
err:
	l_tls_close(ttls->tls);
}

static void eap_ttls_disconnect_cb(enum l_tls_alert_desc reason,
					bool remote, void *user_data)
{
	struct eap_state *eap = user_data;
	struct eap_ttls_state *ttls = eap_get_data(eap);

	ttls->completed = true;
}

static void eap_ttls_handle_request(struct eap_state *eap,
					const uint8_t *pkt, size_t len)
{
	uint8_t flags;
	uint32_t total_len;
	struct eap_ttls_state *ttls = eap_get_data(eap);
	size_t fragment_len;
	uint8_t *tx_buf;

	if (len < 1) {
		l_error("EAP-TTLS request too short");
		goto err;
	}

	flags = pkt[0];

	pkt += 1;
	len -= 1;

	if (!(flags & EAP_TTLS_FLAG_S) &&
			(flags & 7) != ttls->negotiated_version) {
		l_error("Non-zero EAP-TTLS version: %i", flags & 7);
		goto err;
	}

	/* Check if we're expecting a fragment ACK */
	if (ttls->tx_pkt_len) {
		if ((flags & EAP_TTLS_FLAG_MASK) || len) {
			l_error("EAP-TTLS request is not an ACK");
			goto err;
		}

		/* Send next response fragment, prepend the 6-byte header */
		tx_buf = &ttls->tx_pkt_buf[ttls->tx_pkt_offset - 6];

		fragment_len = eap_get_mtu(eap) - 6;
		tx_buf[5] = EAP_TTLS_FLAG_M |
			ttls->negotiated_version; /* Flags */

		if (ttls->tx_pkt_len <= fragment_len) {
			fragment_len = ttls->tx_pkt_len;
			tx_buf[5] = ttls->negotiated_version; /* Flags */
		}

		eap_send_response(eap, EAP_TYPE_TTLS,
					tx_buf, fragment_len + 6);

		ttls->tx_pkt_len -= fragment_len;
		ttls->tx_pkt_offset += fragment_len;

		return;
	}

	/* Complain if S bit is not correct */
	if (!(flags & EAP_TTLS_FLAG_S) == !ttls->tls) {
		l_error("EAP-TTLS request S flag invalid");
		goto err;
	}

	/* Method can't be restarted */
	if ((flags & EAP_TTLS_FLAG_S) && ttls->completed) {
		l_error("EAP-TTLS start after completed");
		goto err;
	}

	if (flags & EAP_TTLS_FLAG_L) {
		if (len < 7) {
			l_error("EAP-TTLS request with L flag too short");
			goto err;
		}

		total_len = l_get_be32(pkt);
		pkt += 4;
		len -= 4;

		if (ttls->rx_pkt_buf) {
			l_error("EAP-TTLS request L flag invalid");

			l_free(ttls->rx_pkt_buf);
			ttls->rx_pkt_buf = NULL;

			goto err;
		}

		if (!(flags & EAP_TTLS_FLAG_M) && total_len != len) {
			l_error("EAP-TTLS request Length value invalid");

			goto err;
		}
	}

	if (!ttls->rx_pkt_buf && (flags & EAP_TTLS_FLAG_M)) {
		if (!(flags & EAP_TTLS_FLAG_L)) {
			l_error("EAP-TTLS requst 1st fragment with no length");

			goto err;
		}

		ttls->rx_pkt_buf = l_malloc(total_len);
		ttls->rx_pkt_len = total_len;
		ttls->rx_pkt_received = 0;
	}

	if (ttls->rx_pkt_buf) {
		if (
				((flags & EAP_TTLS_FLAG_M) &&
				 ttls->rx_pkt_received + len >=
				 ttls->rx_pkt_len) ||
				(!(flags & EAP_TTLS_FLAG_M) &&
				 ttls->rx_pkt_received + len !=
				 ttls->rx_pkt_len)) {
			l_error("EAP-TTLS request fragment length mismatch");

			l_free(ttls->rx_pkt_buf);
			ttls->rx_pkt_buf = NULL;

			goto err;
		}

		memcpy(ttls->rx_pkt_buf + ttls->rx_pkt_received, pkt, len);
		ttls->rx_pkt_received += len;
	}

	if (flags & EAP_TTLS_FLAG_M) {
		uint8_t buf[6];

		/* Send an empty response as ACK */
		buf[5] = 0;
		eap_send_response(eap, EAP_TYPE_TTLS, buf, 6);

		return;
	}

	if (ttls->rx_pkt_buf) {
		pkt = ttls->rx_pkt_buf;
		len = ttls->rx_pkt_len;
	}

	eap_ttls_tx_buf_reserve(ttls, EAP_TTLS_RESPONSE_HEADER_LEN);
	ttls->tx_pkt_offset = ttls->tx_pkt_len;
	ttls->tx_pkt_len = 0;

	if (flags & EAP_TTLS_FLAG_S) {
		ttls->tls = l_tls_new(false, eap_ttls_data_cb,
					eap_ttls_tx_cb, eap_ttls_ready_cb,
					eap_ttls_disconnect_cb, eap);

		if (!ttls->tls) {
			l_error("Creating a TLS instance failed");
			goto err;
		}

		l_tls_set_auth_data(ttls->tls, ttls->client_cert,
					ttls->client_key, ttls->passphrase);

		if (ttls->ca_cert)
			l_tls_set_cacert(ttls->tls, ttls->ca_cert);

		/*
		 * RFC5281 section 9.1: "For all packets other than a
		 * Start packet, the Data field consists of the raw
		 * TLS message sequence or fragment thereof.  For a
		 * Start packet, the Data field may optionally
		 * contain an AVP sequence."
		 * We ignore the unencrypted AVP sequence if there is
		 * any.
		 */
		len = 0;
	}

	/*
	 * Here we take advantage of knowing that ell will send all the
	 * records corresponding to the current handshake step from within
	 * the l_tls_handle_rx call because it doesn't use any other context
	 * such as timers - basic TLS specifies no timeouts.  Otherwise we
	 * would need to analyze the record types in eap_ttls_tx_cb to decide
	 * when we're ready to send out a response.
	 */
	if (len)
		l_tls_handle_rx(ttls->tls, pkt, len);

	if (ttls->rx_pkt_buf) {
		l_free(ttls->rx_pkt_buf);
		ttls->rx_pkt_buf = NULL;
	}

	/*
	 * Note if ttls->completed && !eap->method_success we can send an empty
	 * response instead of passing the TLS alert.
	 */

	if (ttls->tx_pkt_len <= eap_get_mtu(eap)) {
		/*
		 * Response fits in a single response packet, prepend the
		 * 6-byte header (no length) before the data.
		 */
		tx_buf = &ttls->tx_pkt_buf[ttls->tx_pkt_offset - 6];

		tx_buf[5] = ttls->negotiated_version; /* Flags */

		eap_send_response(eap, EAP_TYPE_TTLS,
					tx_buf, ttls->tx_pkt_len + 6);

		ttls->tx_pkt_len = 0;
	} else {
		/*
		 * Fragmentation needed, prepend the 10-byte header
		 * (4 EAP header + 2 response + 4 length) to build the
		 * initial fragment packet.
		 */
		tx_buf = &ttls->tx_pkt_buf[ttls->tx_pkt_offset - 10];

		tx_buf[5] = EAP_TTLS_FLAG_L | EAP_TTLS_FLAG_M |
			ttls->negotiated_version; /* Flags */
		l_put_be32(ttls->tx_pkt_len, &tx_buf[6]);

		fragment_len = eap_get_mtu(eap) - 10;
		eap_send_response(eap, EAP_TYPE_TTLS,
					tx_buf, fragment_len + 10);

		ttls->tx_pkt_len -= fragment_len;
		ttls->tx_pkt_offset += fragment_len;
	}

	if (ttls->completed) {
		l_tls_free(ttls->tls);
		ttls->tls = NULL;

		if (ttls->eap) {
			eap_free(ttls->eap);
			ttls->eap = NULL;
		}
	}

	return;

err:
	ttls->completed = true;

	l_tls_free(ttls->tls);
	ttls->tls = NULL;

	eap_method_error(eap);
}

static bool eap_ttls_load_settings(struct eap_state *eap,
					struct l_settings *settings,
					const char *prefix)
{
	struct eap_ttls_state *ttls = eap_get_data(eap);
	char setting[64];

	snprintf(setting, sizeof(setting), "%sTTLS-CACert", prefix);
	ttls->ca_cert = l_strdup(l_settings_get_value(settings,
						"Security", setting));

	snprintf(setting, sizeof(setting), "%sTTLS-ClientCert", prefix);
	ttls->client_cert = l_strdup(l_settings_get_value(settings,
						"Security", setting));

	snprintf(setting, sizeof(setting), "%sTTLS-ClientKey", prefix);
	ttls->client_key = l_strdup(l_settings_get_value(settings,
						"Security", setting));

	snprintf(setting, sizeof(setting), "%sTTLS-ClientKeyPassphrase",
			prefix);
	ttls->passphrase = l_strdup(l_settings_get_value(settings,
						"Security", setting));

	if (!ttls->client_cert && ttls->client_key) {
		l_error("Client key present but no client certificate");
		return false;
	}

	if (!ttls->client_key && ttls->passphrase) {
		l_error("Passphrase present but no client private key");
		return false;
	}

	ttls->eap = eap_new(eap_ttls_eap_tx_packet,
				eap_ttls_eap_complete, eap);
	if (!ttls->eap) {
		l_error("Could not create the TTLS inner EAP instance");
		return false;
	}

	snprintf(setting, sizeof(setting), "%sTTLS-Phase2-", prefix);

	return eap_load_settings(ttls->eap, settings, setting);
}

static struct eap_method eap_ttls = {
	.request_type = EAP_TYPE_TTLS,
	.exports_msk = true,
	.name = "TTLS",

	.probe = eap_ttls_probe,
	.remove = eap_ttls_remove,
	.handle_request = eap_ttls_handle_request,
	.load_settings = eap_ttls_load_settings,
};

static int eap_ttls_init(void)
{
	l_debug("");
	return eap_register_method(&eap_ttls);
}

static void eap_ttls_exit(void)
{
	l_debug("");
	eap_unregister_method(&eap_ttls);
}

EAP_METHOD_BUILTIN(eap_ttls, eap_ttls_init, eap_ttls_exit)
