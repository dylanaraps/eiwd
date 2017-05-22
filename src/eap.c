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

static uint32_t default_mtu;
struct l_queue *eap_methods;

struct eap_state {
	eap_tx_packet_func_t tx_packet;
	eap_key_material_func_t set_key_material;
	eap_complete_func_t complete;
	eap_event_func_t event_func;
	void *user_data;
	size_t mtu;

	struct eap_method *method;
	char *identity;

	int last_id;
	void *method_state;
	bool method_success;
	struct l_timeout *complete_timeout;
};

struct eap_state *eap_new(eap_tx_packet_func_t tx_packet,
			eap_complete_func_t complete, void *user_data)
{
	struct eap_state *eap;

	eap = l_new(struct eap_state, 1);

	eap->last_id = -1;
	eap->mtu = default_mtu;

	eap->tx_packet = tx_packet;
	eap->complete = complete;
	eap->user_data = user_data;

	return eap;
}

/*
 * Setting a non-NULL set_key_material callback for this EAP instance will
 * disable the legacy methods that don't generate key material, such
 * as EAP-MD5.
 */
void eap_set_key_material_func(struct eap_state *eap,
				eap_key_material_func_t func)
{
	eap->set_key_material = func;
}

void eap_set_event_func(struct eap_state *eap, eap_event_func_t func)
{
	eap->event_func = func;
}

void eap_free(struct eap_state *eap)
{
	if (eap->method_state)
		eap->method->remove(eap);

	if (eap->identity)
		l_free(eap->identity);

	l_timeout_remove(eap->complete_timeout);

	l_free(eap);
}

/* Note: callers must check for a minimum value */
void eap_set_mtu(struct eap_state *eap, size_t mtu)
{
	eap->mtu = mtu;
}

size_t eap_get_mtu(struct eap_state *eap)
{
	return eap->mtu;
}

/**
 * eap_send_response:
 * @eap: EAP state
 * @type: Type of response being sent
 * @buf: Buffer to send
 * @len: Size of the buffer
 *
 * Sends out a response to a received request.  This method first fills the
 * EAP header into the buffer based on the EAP type response being sent.
 *
 * If the response type is EAP_TYPE_EXPANDED, then the Vendor-Id and
 * Vendor-Type fields are filled in based on contents of the eap_method
 * associated with @eap.
 *
 * The buffer passed in MUST be at least 12 bytes long if @type is
 * EAP_TYPE_EXPANDED and at least 5 bytes for other cases.
 **/
void eap_send_response(struct eap_state *eap, enum eap_type type,
						uint8_t *buf, size_t len)
{
	buf[0] = EAP_CODE_RESPONSE;
	buf[1] = eap->last_id;
	l_put_be16(len, &buf[2]);
	buf[4] = type;

	if (type == EAP_TYPE_EXPANDED) {
		memcpy(buf + 5, eap->method->vendor_id, 3);
		l_put_be32(eap->method->vendor_type, buf + 8);
	}

	eap->tx_packet(buf, len, eap->user_data);
}

static void eap_complete_timeout(struct l_timeout *timeout, void *user_data)
{
	struct eap_state *eap = user_data;

	eap->complete_timeout = NULL;

	eap->complete(eap->method_success ? EAP_RESULT_SUCCESS :
			EAP_RESULT_TIMEOUT, eap->user_data);
}

void eap_start_complete_timeout(struct eap_state *eap)
{
	if (eap->complete_timeout)
		l_timeout_remove(eap->complete_timeout);

	eap->complete_timeout = l_timeout_create(5, eap_complete_timeout,
							eap, NULL);
}

static void eap_send_identity_response(struct eap_state *eap, char *identity)
{
	int len = identity ? strlen(identity) : 0;
	uint8_t buf[5 + len];

	if (!identity)
		identity = "";

	memcpy(buf + 5, identity, len);

	eap_send_response(eap, EAP_TYPE_IDENTITY, buf, len + 5);
}

static void eap_handle_request(struct eap_state *eap, uint16_t id,
				const uint8_t *pkt, size_t len)
{
	enum eap_type type;
	uint8_t buf[10];
	int buf_len;
	void (*op)(struct eap_state *eap,
				const uint8_t *pkt, size_t len);

	if (len < 1)
		/* Invalid packets to be ignored */
		return;

	type = pkt[0];
	if (type >= __EAP_TYPE_MIN_METHOD && !eap->method) {
		l_warn("EAP server tried method %i while client had no method "
			"configured", type);

		goto unsupported_method;
	}

	if (id == eap->last_id)
		op = eap->method->handle_retransmit;
	else
		op = eap->method->handle_request;

	eap->last_id = id;

	if (type >= __EAP_TYPE_MIN_METHOD) {
		if (type != eap->method->request_type) {
			l_warn("EAP server tried method %i while client was "
					"configured for method %i",
					type, eap->method->request_type);

			goto unsupported_method;
		}

		if (type != EAP_TYPE_EXPANDED) {
			op(eap, pkt + 1, len - 1);
			return;
		}

		/*
		 * TODO: Handle Expanded Nak if our vendor-id / vendor-types
		 * don't match
		 */
		if (len < 8)
			return;

		op(eap, pkt + 8, len - 8);
		return;
	}

	switch (type) {
	case EAP_TYPE_IDENTITY:
		if (len >= 2)
			l_warn("EAP identity prompt: \"%.*s\"",
					(int) len - 1, buf + 1);

		eap_send_identity_response(eap, eap->identity);

		return;

	case EAP_TYPE_NOTIFICATION:
		if (len < 2)
			/* Invalid packets to be ignored */
			return;

		l_warn("EAP notification: \"%.*s\"", (int) len - 1, buf + 1);

		eap_send_response(eap, EAP_TYPE_NOTIFICATION, buf, 5);

		return;

	default:
	unsupported_method:
		/* Send a legacy NAK response */
		buf_len = 5;

		/*
		 * RFC3748, Section 5.3.1: "A peer supporting Expanded Types
		 * that receives a Request for an unacceptable authentication
		 * Type (4-253,255) MAY include the value 254 in the Nak
		 * Response (Type 3) to indicate the desire for an Expanded
		 * authentication Type."
		 */
		buf[buf_len++] = eap->method ? eap->method->request_type : 0;

		eap_send_response(eap, EAP_TYPE_NAK, buf, buf_len);
		return;
	}
}

void eap_rx_packet(struct eap_state *eap, const uint8_t *pkt, size_t len)
{
	uint8_t code, id;
	uint16_t eap_len;

	if (len < 4 || l_get_be16(&pkt[2]) < 4 || len < l_get_be16(&pkt[2]))
		/* Invalid packets to be silently discarded */
		return;

	code = pkt[0];
	id = pkt[1];
	eap_len = l_get_be16(&pkt[2]);

	switch ((enum eap_code) code) {
	case EAP_CODE_REQUEST:
		eap_handle_request(eap, id, pkt + 4, eap_len - 4);
		return;

	case EAP_CODE_FAILURE:
	case EAP_CODE_SUCCESS:
		l_timeout_remove(eap->complete_timeout);
		eap->complete_timeout = NULL;

		/* Section 4.2 */

		if (id != eap->last_id)
			return;

		if (eap_len != 4)
			/* Invalid packets to be silently discarded */
			return;

		if (code == EAP_CODE_SUCCESS && !eap->method_success)
			/* "Canned" success packets to be discarded */
			return;

		if (code == EAP_CODE_FAILURE && eap->method_success)
			/*
			 * "On the peer, after success result indications have
			 * been exchanged by both sides, a Failure packet MUST
			 * be silently discarded."
			 *
			 * "Where the peer authenticates successfully to the
			 * authenticator, but the authenticator does not send
			 * a result indication, the authenticator MAY deny
			 * access by sending a Failure packet where the peer
			 * is not currently authorized for network access."
			 * -- eap->method_success implies we've received
			 * a full result indication.
			 */
			return;

		if (eap->method_state)
			eap->method->remove(eap);

		eap->method = NULL;

		eap->complete(code == EAP_CODE_SUCCESS ? EAP_RESULT_SUCCESS :
				EAP_RESULT_FAIL, eap->user_data);
		return;

	default:
		/* Invalid packets to be silently discarded */
		return;
	}
}

bool eap_load_settings(struct eap_state *eap, struct l_settings *settings,
			const char *prefix)
{
	char setting[64];
	const char *method_name;
	const struct l_queue_entry *entry;
	struct eap_method *method;

	snprintf(setting, sizeof(setting), "%sMethod", prefix);
	method_name = l_settings_get_value(settings, "Security", setting);

	if (!method_name)
		return false;

	for (entry = l_queue_get_entries(eap_methods); entry;
					entry = entry->next) {
		method = entry->data;

		if (method->probe(eap, method_name) == 0) {
			eap->method = method;

			break;
		}
	}

	if (!eap->method)
		return false;

	/* Check if selected method is suitable for 802.1x */
	if (eap->set_key_material && !eap->method->exports_msk) {
		l_error("EAP method \"%s\" doesn't export key material",
				method_name);

		goto err;
	}

	snprintf(setting, sizeof(setting), "%sIdentity", prefix);
	eap->identity = l_strdup(l_settings_get_value(settings,
						"Security", setting));
	if (!eap->identity) {
		l_error("EAP Identity is missing");

		goto err;
	}

	if (!eap->method->load_settings)
		return true;

	if (!eap->method->load_settings(eap, settings, prefix))
		goto err;

	return true;

err:
	if (eap->method->remove)
		eap->method->remove(eap);

	eap->method = NULL;

	return false;
}

void eap_set_data(struct eap_state *eap, void *data)
{
	eap->method_state = data;
}

void *eap_get_data(struct eap_state *eap)
{
	return eap->method_state;
}

void eap_set_key_material(struct eap_state *eap,
				const uint8_t *msk_data, size_t msk_len,
				const uint8_t *emsk_data, size_t emsk_len,
				const uint8_t *iv, size_t iv_len)
{
	if (!eap->set_key_material)
		return;

	eap->set_key_material(msk_data, msk_len, emsk_data, emsk_len,
				iv, iv_len, eap->user_data);
}

void eap_method_event(struct eap_state *eap, unsigned int id, const void *data)
{
	if (!eap->event_func)
		return;

	eap->event_func(id, data, eap->user_data);
}

void eap_method_success(struct eap_state *eap)
{
	eap->method_success = true;
}

void eap_method_error(struct eap_state *eap)
{
	/*
	 * It looks like neither EAP nor EAP-TLS specify the error handling
	 * behavior.
	 */
	eap->complete(EAP_RESULT_FAIL, eap->user_data);
}

void eap_save_last_id(struct eap_state *eap, uint8_t *last_id)
{
	*last_id = eap->last_id;
}

void eap_restore_last_id(struct eap_state *eap, uint8_t last_id)
{
	eap->last_id = last_id;
}

int eap_register_method(struct eap_method *method)
{
	l_queue_push_head(eap_methods, method);
	return 0;
}

int eap_unregister_method(struct eap_method *method)
{
	bool r;

	r = l_queue_remove(eap_methods, method);
	if (r)
		return 0;

	return -ENOENT;
}

static void __eap_method_enable(struct eap_method_desc *start,
					struct eap_method_desc *stop)
{
	struct eap_method_desc *desc;

	l_debug("");

	if (start == NULL || stop == NULL)
		return;

	for (desc = start; desc < stop; desc++) {
		if (!desc->init)
			continue;

		desc->init();
	}
}

static void __eap_method_disable(struct eap_method_desc *start,
					struct eap_method_desc *stop)
{
	struct eap_method_desc *desc;

	l_debug("");

	if (start == NULL || stop == NULL)
		return;

	for (desc = start; desc < stop; desc++) {
		if (!desc->exit)
			continue;

		desc->exit();
	}
}

extern struct eap_method_desc __start___eap[];
extern struct eap_method_desc __stop___eap[];

void eap_init(uint32_t mtu)
{
	eap_methods = l_queue_new();
	__eap_method_enable(__start___eap, __stop___eap);

	/*
	 * RFC 3748, Section 3.1, [4], "Minimum MTU":
	 * EAP is capable of functioning on lower layers that
	 *        provide an EAP MTU size of 1020 octets or greater.
	 */
	if (mtu == 0)
		default_mtu = 1020;
	else
		default_mtu = mtu;
}

void eap_exit(void)
{
	__eap_method_disable(__start___eap, __stop___eap);
	l_queue_destroy(eap_methods, NULL);
}
