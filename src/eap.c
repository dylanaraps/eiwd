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

#define _GNU_SOURCE
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <ell/ell.h>

#include "eap.h"
#include "eap-private.h"

static uint32_t default_mtu;
struct l_queue *eap_methods;

static void dump_eap(const char *str, void *user_data)
{
	const char *prefix = user_data;

	l_info("%s%s\n", prefix, str);
}

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

	bool discard_success_and_failure:1;
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

bool eap_reset(struct eap_state *eap)
{
	if (eap->method_state && eap->method->reset_state) {
		if (!eap->method->reset_state(eap))
			return false;
	}

	eap->method_success = false;
	l_timeout_remove(eap->complete_timeout);
	eap->complete_timeout = NULL;

	return true;
}

void eap_free(struct eap_state *eap)
{
	if (eap->method_state && eap->method->free)
		eap->method->free(eap);

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

void __eap_handle_request(struct eap_state *eap, uint16_t id,
				const uint8_t *pkt, size_t len)
{
	enum eap_type type;
	uint8_t buf[10];
	int buf_len;
	bool retransmit;

	if (len < 1)
		/* Invalid packets to be ignored */
		return;

	type = pkt[0];
	if (type >= __EAP_TYPE_MIN_METHOD && !eap->method) {
		l_warn("EAP server tried method %i while client had no method "
			"configured", type);

		goto unsupported_method;
	}

	retransmit = id == eap->last_id ? true : false;
	eap->last_id = id;

	if (type >= __EAP_TYPE_MIN_METHOD) {
		void (*op)(struct eap_state *eap,
					const uint8_t *pkt, size_t len);

		if (type != eap->method->request_type) {
			l_warn("EAP server tried method %i while client was "
					"configured for method %i",
					type, eap->method->request_type);

			goto unsupported_method;
		}

		op = retransmit && eap->method->handle_retransmit ?
						eap->method->handle_retransmit :
						eap->method->handle_request;

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
			l_debug("Optional EAP server identity prompt: \"%.*s\"",
					(int) len - 1, pkt + 1);

		eap_send_identity_response(eap, eap->identity);

		return;

	case EAP_TYPE_NOTIFICATION:
		if (len < 2)
			/* Invalid packets to be ignored */
			return;

		l_warn("EAP notification: \"%.*s\"", (int) len - 1, pkt + 1);

		eap_send_response(eap, EAP_TYPE_NOTIFICATION, buf, 5);

		return;

	default:
	unsupported_method:
		if (!eap->method) {
			l_info("Received an unhandled EAP packet:");
			l_util_hexdump(true, pkt, len, dump_eap, "[EAP] ");
		}

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
		__eap_handle_request(eap, id, pkt + 4, eap_len - 4);
		return;

	case EAP_CODE_FAILURE:
	case EAP_CODE_SUCCESS:
		if (eap->discard_success_and_failure)
			return;

		l_timeout_remove(eap->complete_timeout);
		eap->complete_timeout = NULL;

		/* RFC3748, Section 4.2
		 *
		 * The Identifier field of the Success and Failure packets
		 * MUST match the Identifier field of the Response packet that
		 * it is sent in response to. However, many currently deployed
		 * implementations ignore this rule and increment Identity for
		 * the Success and Failure packets. In order to support
		 * interoperability with these products we validate id against
		 * eap->last_id and its incremented value.
		 */
		if (id != eap->last_id && id != eap->last_id + 1)
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

		eap->complete(code == EAP_CODE_SUCCESS ? EAP_RESULT_SUCCESS :
				EAP_RESULT_FAIL, eap->user_data);
		return;

	default:
		/* Invalid packets to be silently discarded */
		return;
	}
}

bool eap_secret_info_match(const void *a, const void *b)
{
	const struct eap_secret_info *s = a;

	return !strcmp(s->id, b);
}

void eap_append_secret(struct l_queue **out_missing, enum eap_secret_type type,
			const char *id, const char *id2, const char *parameter,
			enum eap_secret_cache_policy cache_policy)
{
	struct eap_secret_info *info;

	if (!*out_missing)
		*out_missing = l_queue_new();

	info = l_new(struct eap_secret_info, 1);
	info->id = l_strdup(id);
	info->id2 = l_strdup(id2);
	info->type = type;
	info->parameter = l_strdup(parameter);
	info->cache_policy = cache_policy;
	l_queue_push_tail(*out_missing, info);
}

void eap_secret_info_free(void *data)
{
	struct eap_secret_info *info = data;

	if (!info)
		return;

	if (info->value) {
		memset(info->value, 0, strlen(info->value));
		l_free(info->value);
	}

	if (info->parameter) {
		memset(info->parameter, 0, strlen(info->parameter));
		l_free(info->parameter);
	}

	l_free(info->id);
	l_free(info->id2);
	l_free(info);
}

static int eap_setting_exists(struct l_settings *settings,
				const char *setting,
				struct l_queue *secrets,
				struct l_queue *missing)
{
	if (l_settings_get_value(settings, "Security", setting))
		return 0;

	if (l_queue_find(secrets, eap_secret_info_match, setting))
		return 0;

	if (l_queue_find(missing, eap_secret_info_match, setting))
		return 0;

	return -ENOENT;
}

int __eap_check_settings(struct l_settings *settings, struct l_queue *secrets,
				const char *prefix, bool set_key_material,
				struct l_queue **missing)
{
	char setting[64];
	const char *method_name;
	const struct l_queue_entry *entry;
	struct eap_method *method;
	int ret = 0;

	snprintf(setting, sizeof(setting), "%sMethod", prefix);
	method_name = l_settings_get_value(settings, "Security", setting);

	if (!method_name) {
		l_error("Property %s missing", setting);
		return -ENOENT;
	}

	for (entry = l_queue_get_entries(eap_methods); entry;
					entry = entry->next) {
		method = entry->data;

		if (!strcasecmp(method_name, method->name))
			break;
	}

	if (!entry) {
		l_error("EAP method \"%s\" unsupported", method_name);
		return -ENOTSUP;
	}

	/* Check if selected method is suitable for 802.1x */
	if (set_key_material && !method->exports_msk) {
		l_error("EAP method \"%s\" doesn't export key material",
				method_name);
		return -ENOTSUP;
	}

	if (method->check_settings) {
		ret = method->check_settings(settings, secrets,
						prefix, missing);

		if (ret < 0)
			return ret;
	}

	/*
	 * Methods that provide the get_identity callback are responsible
	 * for ensuring, inside check_settings(), that they have enough data
	 * to return the identity after load_settings().
	 */
	if (!method->get_identity) {
		snprintf(setting, sizeof(setting), "%sIdentity", prefix);

		ret = eap_setting_exists(settings, setting, secrets, *missing);
		if (ret < 0) {
			l_error("Property %s is missing", setting);
			return -ENOENT;
		}
	}

	return 0;
}

int eap_check_settings(struct l_settings *settings, struct l_queue *secrets,
			const char *prefix, bool set_key_material,
			struct l_queue **out_missing)
{
	struct l_queue *missing = NULL;
	int ret = __eap_check_settings(settings, secrets, prefix,
					set_key_material, &missing);

	if (ret < 0) {
		l_queue_destroy(missing, eap_secret_info_free);
		return ret;
	}

	if (missing && l_queue_isempty(missing)) {
		l_queue_destroy(missing, NULL);
		missing = NULL;
	}

	*out_missing = missing;
	return 0;
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

		if (!strcasecmp(method_name, method->name)) {
			eap->method = method;

			break;
		}
	}

	if (!eap->method)
		return false;

	/* Check if selected method is suitable for 802.1x */
	if (eap->set_key_material && !eap->method->exports_msk)
		goto err;

	if (eap->method->load_settings)
		if (!eap->method->load_settings(eap, settings, prefix))
			goto err;

	/* get identity from settings or from EAP method */
	if (!eap->method->get_identity) {
		snprintf(setting, sizeof(setting), "%sIdentity", prefix);
		eap->identity = l_settings_get_string(settings,
							"Security", setting);
	} else {
		eap->identity = l_strdup(eap->method->get_identity(eap));
	}

	if (!eap->identity)
		goto err;

	return true;

err:
	if (eap->method_state && eap->method->free)
		eap->method->free(eap);

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

enum eap_type eap_get_method_type(struct eap_state *eap)
{
	return eap->method->request_type;
}

const char *eap_get_method_name(struct eap_state *eap)
{
	return eap->method->name;
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

bool eap_method_is_success(struct eap_state *eap)
{
	return eap->method_success;
}

void eap_method_success(struct eap_state *eap)
{
	eap->method_success = true;
}

void eap_discard_success_and_failure(struct eap_state *eap, bool discard)
{
	eap->discard_success_and_failure = discard;
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
	if (!method->handle_request)
		return -EPERM;

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
