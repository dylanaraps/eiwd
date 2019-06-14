/*
 *
 *  Wireless daemon for Linux
 *
 *  Copyright (C) 2019  Intel Corporation. All rights reserved.
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

#include <stdint.h>

#include <ell/ell.h>

#include "src/anqp.h"
#include "src/util.h"
#include "src/eap-private.h"

static const uint8_t wifi_alliance_oui[3] = { 0x50, 0x6f, 0x9a };

void anqp_iter_init(struct anqp_iter *iter, const unsigned char *anqp,
			unsigned int len)
{
	iter->anqp = anqp;
	iter->max = len;
	iter->pos = 0;
}

bool anqp_iter_next(struct anqp_iter *iter, uint16_t *id, uint16_t *len,
			const void **data)
{
	const unsigned char *anqp = iter->anqp + iter->pos;
	const unsigned char *end = iter->anqp + iter->max;

	if (iter->pos + 4 >= iter->max)
		return false;

	if (anqp + l_get_le16(anqp + 2) > end)
		return false;

	*id = l_get_le16(anqp);
	anqp += 2;

	*len = l_get_le16(anqp);
	anqp += 2;

	*data = anqp;

	iter->id = *id;
	iter->len = *len;
	iter->data = *data;

	iter->pos = anqp + *len - iter->anqp;

	return true;
}

bool anqp_hs20_parse_osu_provider_nai(const unsigned char *anqp,
					unsigned int len, const char **nai_out)
{
	uint8_t nai_len;
	static char nai[256] = { 0 };

	if (len < 1)
		return false;

	nai_len = *anqp++;
	len--;

	if (len < nai_len)
		return false;

	memcpy(nai, anqp, nai_len);

	*nai_out = nai;

	return true;
}

bool anqp_iter_is_hs20(const struct anqp_iter *iter, uint8_t *stype,
			unsigned int *len, const unsigned char **data)
{
	const unsigned char *anqp = iter->data;
	unsigned int anqp_len = iter->len;
	uint8_t type;

	if (iter->len < 6)
		return false;

	if (memcmp(anqp, wifi_alliance_oui, 3))
		return false;

	anqp += 3;
	anqp_len -= 3;

	type = *anqp++;
	anqp_len--;

	if (type != 0x11)
		return false;

	*stype = *anqp++;
	anqp_len--;

	/* reserved byte */
	anqp++;
	anqp_len--;

	*data = anqp;
	*len = anqp_len;

	return true;
}

static bool parse_eap_params(const unsigned char *anqp, unsigned int len,
				uint8_t *method, uint8_t *non_eap_inner,
				uint8_t *eap_inner, uint8_t *credential,
				uint8_t *tunneled_credential)
{
	uint8_t param_count;

	if (len < 2)
		return false;

	*method = *anqp++;
	param_count = *anqp++;

	len -= 2;

	*non_eap_inner = 0;
	*eap_inner = 0;
	*credential = 0;
	*tunneled_credential = 0;

	while (param_count--) {
		uint8_t ap_id;
		uint8_t ap_len;

		if (len < 2)
			return false;

		ap_id = *anqp++;
		ap_len = *anqp++;
		len -= 2;

		if (len < ap_len)
			return false;

		switch (ap_id) {
		case ANQP_AP_NON_INNER_AUTH_EAP:
			*non_eap_inner = *anqp;
			break;
		case ANQP_AP_INNER_AUTH_EAP:
			*eap_inner = *anqp;
			break;
		case ANQP_AP_CREDENTIAL:
			*credential = *anqp;
			break;
		case ANQP_AP_TUNNELED_EAP_CREDENTIAL:
			*tunneled_credential = *anqp;
			break;
		case ANQP_AP_EXPANDED_EAP_METHOD:
		case ANQP_AP_EXPANDED_INNER_EAP_METHOD:
		case ANQP_AP_VENDOR_SPECIFIC:
			break;
		}

		anqp += ap_len;
		len -= ap_len;
	}

	return true;
}

/*
 * Parses an EAP ANQP list.
 */
static bool parse_eap(const unsigned char *anqp, unsigned int len,
			const char *nai, bool hs20,
			struct anqp_eap_method *method_out)
{
	uint8_t eap_count;

	if (len < 1)
		return false;

	eap_count = *anqp++;
	len--;

	while (eap_count--) {
		uint8_t eap_len;
		uint8_t method;
		uint8_t non_eap_inner;
		uint8_t eap_inner;
		uint8_t credential;
		uint8_t tunneled_credential;

		if (len < 1)
			return false;

		eap_len = *anqp++;
		len--;

		if (!parse_eap_params(anqp, eap_len,
					&method, &non_eap_inner,
					&eap_inner, &credential,
					&tunneled_credential))
			return false;

		if (hs20) {
			/*
			 * TODO: Support EAP-SIM/AKA/AKA' with Hotspot
			 */
			if (method != EAP_TYPE_TTLS) {
				l_debug("EAP method %u not supported", method);
				goto next;
			}

			/* MSCHAPv2 */
			if (non_eap_inner != 4) {
				l_debug("Non-EAP inner %u not supported",
						non_eap_inner);
				goto next;
			}

			/* username/password */
			if (credential != 7) {
				l_debug("credential type %u not supported",
						credential);
				goto next;
			}
		} else {
			/* can't use methods without user/password */
			if (credential != 7 && tunneled_credential != 7)
				goto next;
		}

		method_out->method = method;
		/* nai is guarenteed to NULL terminate and be < 256 bytes */
		l_strlcpy(method_out->realm, nai, sizeof(method_out->realm));
		method_out->non_eap_inner = non_eap_inner;
		method_out->eap_inner = eap_inner;
		method_out->credential = credential;
		method_out->tunneled_credential = tunneled_credential;

		return true;

next:
		if (len < eap_len)
			return false;

		anqp += eap_len;
		len -= eap_len;
	}

	return false;
}

/*
 * Parses NAI Realm ANQP-element. The code here parses the NAI Realm until an
 * acceptable EAP method is found. Once a method is found it is returned via
 * method_out. The structure of NAI realm is such that it does not allow for a
 * convenient static structure (several nested lists). Since we can only handle
 * EAP methods with user/password credentials anyways it makes sense to just
 * return the first EAP method found that meets our criteria. In addition, this
 * is only being used for Hotspot 2.0, which mandates EAP-TLS/TTLS/SIM/AKA,
 * meaning TTLS is the only contender for this parsing.
 *
 * @param hs20	true if this parsing is for a Hotspot 2.0 network. This will
 * 		restrict what EAP method info is chosen as to comply with the
 * 		Hotspot 2.0 spec (i.e. EAP-TTLS w/ MSCHAPv2 or SIM/AKA/AKA').
 */
bool anqp_parse_nai_realm(const unsigned char *anqp, unsigned int len,
				bool hs20, struct anqp_eap_method *method_out)
{
	uint16_t count;

	if (len < 2)
		return false;

	count = l_get_le16(anqp);

	anqp += 2;
	len -= 2;

	while (count--) {
		uint16_t realm_len;
		uint8_t encoding;
		uint8_t nai_len;
		char nai_realm[256] = { 0 };

		/*
		 * The method list is a variable field, so the only way to
		 * reliably increment anqp is by realm_len at the very end since
		 * we dont know how many bytes parse_eap advanced (it does
		 * internal length checking so it should not overflow). We
		 * cant incrementally advance anqp/len, hence the hardcoded
		 * length and pointer adjustments.
		 */

		if (len < 4)
			return false;

		realm_len = l_get_le16(anqp);
		anqp += 2;
		len -= 2;

		encoding = anqp[0];

		nai_len = anqp[1];

		if (len - 2 < nai_len)
			return false;

		memcpy(nai_realm, anqp + 2, nai_len);

		/*
		 * TODO: Verify NAI encoding in accordance with RFC 4282 ?
		 *
		 * The encoding in RFC 4282 seems to only limit which characters
		 * can be used in an NAI. Since these come in from public
		 * action frames it could have been spoofed, but ultimately if
		 * its bogus the AP won't allow us to connect.
		 */
		if (!util_is_bit_set(encoding, 0))
			l_warn("Not verifying NAI encoding");
		else if (!l_utf8_validate(nai_realm, nai_len, NULL)) {
			l_warn("NAI is not UTF-8");
			return false;
		}

		if (parse_eap(anqp + 2 + nai_len, realm_len - 2 - nai_len,
				nai_realm, hs20, method_out))
			return true;

		if (len < realm_len)
			return false;

		anqp += realm_len;
		len -= realm_len;
	}

	return false;
}
