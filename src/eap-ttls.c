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
#include <ell/tls-private.h>

#include "eap.h"
#include "eap-private.h"
#include "eap-tls-common.h"

#define TTLS_AVP_HEADER_LEN 8
#define TTLS_AVP_LEN_MASK 0xFFFFFF

enum ttls_avp_flag {
	TTLS_AVP_FLAG_M =	0x40,
	TTLS_AVP_FLAG_V =	0x80,
	TTLS_AVP_FLAG_MASK =	0xFF,
};

enum radius_attr {
	RADIUS_ATTR_EAP_MESSAGE			= 79,
};

struct avp_builder {
	uint8_t flags;
	size_t capacity;
	uint8_t *buf;
	size_t offset;
	uint32_t current_len;
};

static void avp_builder_grow(struct avp_builder *builder)
{
	builder->buf = l_realloc(builder->buf, builder->capacity * 2);
	builder->capacity *= 2;
}

static uint8_t *avp_builder_reserve(struct avp_builder *builder, size_t len)
{
	while (builder->offset + TTLS_AVP_HEADER_LEN + builder->current_len
						+ len >= builder->capacity) {
		avp_builder_grow(builder);
	}

	return builder->buf + builder->offset + TTLS_AVP_HEADER_LEN +
							builder->current_len;
}

static void avp_builder_finalize_avp(struct avp_builder *builder)
{
	uint8_t *p = builder->buf + builder->offset;

	if (builder->current_len & 3) {
		/*
		* If an AVP is not a multiple of four octets, it must be padded
		* with zeros to the next four-octet boundary.
		*/
		uint8_t pad_len = 4 - (builder->current_len & 3);

		memset(avp_builder_reserve(builder, pad_len), 0, pad_len);
	}

	builder->current_len += TTLS_AVP_HEADER_LEN;
	builder->offset += (builder->current_len + 3) & ~3;
	builder->current_len |= builder->flags << 24;

	l_put_be32(builder->current_len, p + 4);

	builder->flags = 0;
	builder->current_len = 0;
}

static bool avp_builder_start_avp(struct avp_builder *builder,
					enum radius_attr type,
					bool mandatory, uint32_t vendor_id)
{
	uint8_t *p;

	if (!builder->current_len && builder->offset)
		return false;

	if (builder->offset + TTLS_AVP_HEADER_LEN + (vendor_id ? 4 : 0)
							>= builder->capacity)
		avp_builder_grow(builder);

	p = builder->buf + builder->offset;
	l_put_be32(type, p);

	if (mandatory)
		builder->flags |= TTLS_AVP_FLAG_M;

	if (vendor_id) {
		builder->flags |= TTLS_AVP_FLAG_V;
		l_put_be32(vendor_id, p + TTLS_AVP_HEADER_LEN);
		builder->current_len += 4;
	}

	return true;
}

static struct avp_builder *avp_builder_new(size_t capacity)
{
	struct avp_builder *builder;

	if (!capacity)
		return NULL;

	builder = l_new(struct avp_builder, 1);
	builder->buf = l_malloc(capacity);
	builder->capacity = capacity;

	return builder;
}

static uint8_t *avp_builder_free(struct avp_builder *builder, bool free_data,
							size_t *out_size)
{
	uint8_t *ret;

	if (free_data) {
		l_free(builder->buf);
		builder->buf = NULL;
	}

	ret = builder->buf;

	if (out_size)
		*out_size = builder->offset;

	l_free(builder);

	return ret;
}

static bool avp_builder_put_bytes(struct avp_builder *builder,
						const void *data, size_t len)
{
	memcpy(avp_builder_reserve(builder, len), data, len);
	builder->current_len += len;

	return true;
}

struct avp_iter {
	enum radius_attr type;
	uint8_t flags;
	uint32_t len;
	uint32_t vendor_id;
	const uint8_t *data;
	const uint8_t *buf;
	size_t buf_len;
	size_t offset;
};

static void avp_iter_init(struct avp_iter *iter, const uint8_t *buf, size_t len)
{
	iter->buf = buf;
	iter->buf_len = len;
	iter->offset = 0;
}

static bool avp_iter_next(struct avp_iter *iter)
{
	const uint8_t *start = iter->buf + iter->offset;
	const uint8_t *end = iter->buf + iter->buf_len;
	enum radius_attr type;
	uint32_t len;
	uint8_t flags;
	uint8_t pad_len;

	/* Make sure we have at least the header fields */
	if (iter->offset + TTLS_AVP_HEADER_LEN >= iter->buf_len)
		return false;

	type = l_get_be32(start);
	start += 4;

	len = l_get_be32(start);
	start += 4;

	flags = (len >> 24) & TTLS_AVP_FLAG_MASK;
	len &= TTLS_AVP_LEN_MASK;

	len -= TTLS_AVP_HEADER_LEN;

	if (start + len > end)
		return false;

	if (flags & TTLS_AVP_FLAG_V) {
		if (len < 4)
			return false;

		iter->vendor_id = l_get_be32(start);
		start += 4;
		len -= 4;
	} else {
		iter->vendor_id = 0;
	}

	iter->type = type;
	iter->flags = flags;
	iter->len = len;
	iter->data = start;

	if (len & 3)
		pad_len = 4 - (len & 3);
	else
		pad_len = 0;

	iter->offset = start + len + pad_len - iter->buf;

	return true;
}

struct phase2_method {
	void *state;
	bool (*init)(struct eap_state *eap);
	bool (*handle_avp)(struct eap_state *eap, enum radius_attr type,
				uint32_t vendor_id, const uint8_t *data,
								size_t len);
	bool (*load_settings)(struct eap_state *eap,
						struct l_settings *settings,
						const char *prefix);
	void (*destroy)(struct eap_state *eap);
	bool (*reset)(struct eap_state *eap);
};

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
	struct databuf *avp_buf;
	bool completed;
	uint8_t negotiated_version;

	struct phase2_method *phase2;
};

static void __eap_ttls_reset_state(struct eap_ttls_state *ttls)
{
	ttls->completed = false;

	l_free(ttls->rx_pkt_buf);
	ttls->rx_pkt_buf = NULL;
	ttls->rx_pkt_received = 0;
	ttls->rx_pkt_len = 0;

	l_free(ttls->tx_pkt_buf);
	ttls->tx_pkt_buf = NULL;
	ttls->tx_pkt_capacity = 0;
	ttls->tx_pkt_len = 0;
	ttls->tx_pkt_offset = 0;

	databuf_free(ttls->avp_buf);
	ttls->avp_buf = NULL;

	if (ttls->tls) {
		l_tls_free(ttls->tls);
		ttls->tls = NULL;
	}
}

static bool eap_ttls_reset_state(struct eap_state *eap)
{
	struct eap_ttls_state *ttls = eap_get_data(eap);

	if (ttls->phase2->reset)
		ttls->phase2->reset(eap);

	__eap_ttls_reset_state(ttls);

	return true;
}

static void eap_ttls_free(struct eap_state *eap)
{
	struct eap_ttls_state *ttls = eap_get_data(eap);

	__eap_ttls_reset_state(ttls);

	if (ttls->phase2->destroy)
		ttls->phase2->destroy(eap);

	eap_set_data(eap, NULL);

	l_free(ttls->ca_cert);
	l_free(ttls->client_cert);
	l_free(ttls->client_key);

	if (ttls->passphrase) {
		memset(ttls->passphrase, 0, strlen(ttls->passphrase));
		l_free(ttls->passphrase);
	}

	l_free(ttls);
}

#define EAP_TTLS_RESPONSE_HEADER_LEN	10

#define EAP_TTLS_FLAG_L	(1 << 7)
#define EAP_TTLS_FLAG_M	(1 << 6)
#define EAP_TTLS_FLAG_S	(1 << 5)
#define EAP_TTLS_FLAG_MASK	\
	(EAP_TTLS_FLAG_L | EAP_TTLS_FLAG_M | EAP_TTLS_FLAG_S)

static void eap_ttls_phase2_eap_send_response(const uint8_t *data, size_t len,
								void *user_data)
{
	struct eap_state *eap = user_data;
	struct eap_ttls_state *ttls = eap_get_data(eap);
	struct avp_builder *builder;
	uint8_t *msg_data;
	size_t msg_data_len;

	builder = avp_builder_new(TTLS_AVP_HEADER_LEN + len);

	avp_builder_start_avp(builder, RADIUS_ATTR_EAP_MESSAGE, true, 0);
	avp_builder_put_bytes(builder, data, len);
	avp_builder_finalize_avp(builder);

	msg_data = avp_builder_free(builder, false, &msg_data_len);

	l_tls_write(ttls->tls, msg_data, msg_data_len);
	l_free(msg_data);
}

static void eap_ttls_phase2_eap_complete(enum eap_result result,
								void *user_data)
{
	struct eap_state *eap = user_data;
	struct eap_ttls_state *ttls = eap_get_data(eap);

	ttls->completed = true;
}

static bool eap_ttls_phase2_eap_load_settings(struct eap_state *eap,
						struct l_settings *settings,
						const char *prefix)
{
	struct eap_ttls_state *ttls = eap_get_data(eap);

	ttls->phase2->state = eap_new(eap_ttls_phase2_eap_send_response,
						eap_ttls_phase2_eap_complete,
						eap);
	if (!ttls->phase2->state) {
		l_error("Could not create the TTLS Phase 2 EAP instance");
		return false;
	}

	if (!eap_load_settings(ttls->phase2->state, settings, prefix)) {
		eap_free(ttls->phase2->state);
		return false;
	}

	return true;
}

static bool eap_ttls_phase2_eap_init(struct eap_state *eap)
{
	struct eap_ttls_state *ttls = eap_get_data(eap);
	uint8_t packet[5] = { EAP_CODE_REQUEST, 0, 0, 5, EAP_TYPE_IDENTITY };

	if (!ttls->phase2->state)
		return false;
	/*
	 * Consume a fake Request/Identity packet so that the EAP instance
	 * starts with its Response/Identity right away.
	 */
	eap_rx_packet(ttls->phase2->state, packet, sizeof(packet));

	return true;
}

static bool eap_ttls_phase2_eap_handle_avp(struct eap_state *eap,
						enum radius_attr type,
						uint32_t vendor_id,
						const uint8_t *data,
						size_t len)
{
	struct eap_ttls_state *ttls = eap_get_data(eap);

	if (type != RADIUS_ATTR_EAP_MESSAGE)
		return false;

	eap_rx_packet(ttls->phase2->state, data, len);

	return true;
}

static void eap_ttls_phase2_eap_destroy(struct eap_state *eap)
{
	struct eap_ttls_state *ttls = eap_get_data(eap);

	if (!ttls->phase2->state)
		return;

	eap_reset(ttls->phase2->state);

	eap_free(ttls->phase2->state);
	ttls->phase2->state = NULL;
}

static bool eap_ttls_phase2_eap_reset(struct eap_state *eap)
{
	struct eap_ttls_state *ttls = eap_get_data(eap);

	if (!ttls->phase2->state)
		return false;

	return eap_reset(ttls->phase2->state);
}

static struct phase2_method phase2_eap = {
	.load_settings = eap_ttls_phase2_eap_load_settings,
	.init = eap_ttls_phase2_eap_init,
	.handle_avp = eap_ttls_phase2_eap_handle_avp,
	.destroy = eap_ttls_phase2_eap_destroy,
	.reset = eap_ttls_phase2_eap_reset,
};

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

static void eap_ttls_data_cb(const uint8_t *data, size_t data_len,
								void *user_data)
{
	struct eap_state *eap = user_data;
	struct eap_ttls_state *ttls = eap_get_data(eap);

	if (!ttls->avp_buf)
		ttls->avp_buf = databuf_new(data_len);

	databuf_append(ttls->avp_buf, data, data_len);
}

static void eap_ttls_ready_cb(const char *peer_identity, void *user_data)
{
	struct eap_state *eap = user_data;
	struct eap_ttls_state *ttls = eap_get_data(eap);
	uint8_t msk_emsk[128];
	uint8_t seed[64];

	/* TODO: if we have a CA certificate require non-NULL peer_identity */

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

	if (!ttls->phase2->state)
		goto err;

	if (ttls->phase2->init)
		ttls->phase2->init(eap);

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

static void eap_ttls_handle_payload(struct eap_state *eap,
						const uint8_t *pkt,
						size_t pkt_len)
{
	struct eap_ttls_state *ttls = eap_get_data(eap);
	struct avp_iter iter;

	l_tls_handle_rx(ttls->tls, pkt, pkt_len);

	if (!ttls->phase2->handle_avp)
		return;

	/* Plaintext phase two data is stored into ttls->avp_buf */
	if (!ttls->avp_buf)
		return;

	avp_iter_init(&iter, ttls->avp_buf->data, ttls->avp_buf->len);

	while (avp_iter_next(&iter)) {
		if (ttls->phase2->handle_avp(eap, iter.type, iter.vendor_id,
							iter.data, iter.len))
			continue;

		if (iter.flags & TTLS_AVP_FLAG_M)
			l_tls_close(ttls->tls);
	}

	databuf_free(ttls->avp_buf);
	ttls->avp_buf = NULL;
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
			l_error("EAP-TTLS request 1st fragment with no length");

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

	if (len)
		eap_ttls_handle_payload(eap, pkt, len);

	if (ttls->rx_pkt_buf) {
		l_free(ttls->rx_pkt_buf);
		ttls->rx_pkt_buf = NULL;
	}

	/*
	 * Note if ttls->completed && !eap->method_success we can send an empty
	 * response instead of passing the TLS alert.
	 */

	if (ttls->tx_pkt_len + 6 <= eap_get_mtu(eap)) {
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

		if (ttls->phase2->destroy)
			ttls->phase2->destroy(eap);
	}

	return;

err:
	ttls->completed = true;

	l_tls_free(ttls->tls);
	ttls->tls = NULL;

	eap_method_error(eap);
}

static int eap_ttls_check_settings(struct l_settings *settings,
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

	snprintf(setting, sizeof(setting), "%sTTLS-CACert", prefix);
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
			"%sTTLS-ClientCert", prefix);
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

	snprintf(setting, sizeof(setting), "%sTTLS-ClientKey", prefix);
	path = l_settings_get_string(settings, "Security", setting);

	if (path && !client_cert) {
		l_error("%s present but no client certificate (%s)",
			setting, client_cert_setting);
		return -ENOENT;
	}

	snprintf(passphrase_setting, sizeof(passphrase_setting),
			"%sTTLS-ClientKeyPassphrase", prefix);
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
		bool encrypted;
		uint8_t *priv_key;
		size_t size;

		priv_key = l_pem_load_private_key(path, passphrase,
							&encrypted, &size);
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
			memset(priv_key, 0, size);
			l_free(priv_key);

			if (passphrase && !encrypted) {
				l_error("%s present but client private "
					"key %s is not encrypted",
					passphrase_setting, path);
				return -EIO;
			}
		}
	} else if (passphrase) {
		l_error("%s present but no client private key path set (%s)",
			passphrase_setting, setting);
		return -ENOENT;
	}

	snprintf(setting, sizeof(setting), "%sTTLS-Phase2-", prefix);

	return __eap_check_settings(settings, secrets, setting, false,
					out_missing);
}

static bool eap_ttls_load_settings(struct eap_state *eap,
					struct l_settings *settings,
					const char *prefix)
{
	struct eap_ttls_state *ttls;
	char setting[64];

	ttls = l_new(struct eap_ttls_state, 1);

	snprintf(setting, sizeof(setting), "%sTTLS-CACert", prefix);
	ttls->ca_cert = l_settings_get_string(settings, "Security", setting);

	snprintf(setting, sizeof(setting), "%sTTLS-ClientCert", prefix);
	ttls->client_cert = l_settings_get_string(settings,
							"Security", setting);

	snprintf(setting, sizeof(setting), "%sTTLS-ClientKey", prefix);
	ttls->client_key = l_settings_get_string(settings, "Security", setting);

	snprintf(setting, sizeof(setting), "%sTTLS-ClientKeyPassphrase",
			prefix);
	ttls->passphrase = l_settings_get_string(settings, "Security", setting);

	ttls->phase2 = &phase2_eap;

	eap_set_data(eap, ttls);

	snprintf(setting, sizeof(setting), "%sTTLS-Phase2-", prefix);
	if (ttls->phase2->load_settings &&
			!ttls->phase2->load_settings(eap, settings, setting))
		goto err;

	return true;

err:
	eap_set_data(eap, NULL);
	l_free(ttls->ca_cert);
	l_free(ttls->client_cert);
	l_free(ttls->client_key);
	if (ttls->passphrase)
		memset(ttls->passphrase, 0, strlen(ttls->passphrase));
	l_free(ttls->passphrase);
	l_free(ttls);

	return false;
}

static struct eap_method eap_ttls = {
	.request_type = EAP_TYPE_TTLS,
	.exports_msk = true,
	.name = "TTLS",

	.free = eap_ttls_free,
	.handle_request = eap_ttls_handle_request,
	.check_settings = eap_ttls_check_settings,
	.load_settings = eap_ttls_load_settings,
	.reset_state = eap_ttls_reset_state,
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
