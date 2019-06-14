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

#include <stdbool.h>
#include <stddef.h>
#include <unistd.h>

/* IEEE 802.11-2016 Section 9.4.5 ANQP elements */
enum anqp_element {
	/* 0-255 reserved */
	ANQP_QUERY_LIST = 256,
	ANQP_CAPABILITY_LIST = 257,
	ANQP_VENUE_NAME = 258,
	ANQP_EMERGENCY_CALL_NUMBER = 259,
	ANQP_NETWORK_AUTH_TYPE = 260,
	ANQP_ROAMING_CONSORTIUM = 261,
	ANQP_IP_ADDRESS_TYPE_AVAILABILITY = 262,
	ANQP_NAI_REALM = 263,
	ANQP_3GPP_CELLULAR_NETWORK = 264,
	ANQP_AP_GEOSPATIAL_LOCATION = 265,
	ANQP_AP_CIVIC_LOCATION = 266,
	ANQP_AP_LOCATION_PUBLIC_ID = 267,
	ANQP_DOMAIN_NAME = 268,
	ANQP_EMERGENCY_ALERT_ID_URI = 269,
	ANQP_TDLS_CAPABILITY = 270,
	ANQP_EMERGENCY_NAI = 271,
	ANQP_NEIGHBOR_REPORT = 272,
	/* 273-276 reserved */
	ANQP_VENUE_URI = 277,
	ANQP_ADVICE_OF_CHARGE = 278,
	ANQP_LOCAL_CONTENT = 279,
	ANQP_NETWORK_AUTH_TYPE_WITH_TIMESTAMP = 280,
	/* 281-56796 reserved */
	ANQP_VENDOR_SPECIFIC = 56797,
	/* 56798-65535 reserved */
};

/* WiFi Alliance Hotspot 2.0 Spec - Section 4 Hotspot 2.0 ANQP-elements */
enum anqp_hs20_element {
	ANQP_HS20_QUERY_LIST = 1,
	ANQP_HS20_CAPABILITY_LIST = 2,
	ANQP_HS20_OPERATOR_FRIENDLY_NAME = 3,
	ANQP_HS20_WLAN_METRICS = 4,
	ANQP_HS20_CONNECTION_CAPABILITY = 5,
	ANQP_HS20_NAI_HOME_REALM_QUERY = 6,
	ANQP_HS20_OPERATING_CLASS_INDICATION = 7,
	ANQP_HS20_OSU_PROVIDERS_LIST = 8,
	/* 9 reserved */
	ANQP_HS20_ICON_REQUST = 10,
	ANQP_HS20_ICON_BINARY_FILE = 11,
	ANQP_HS20_OPERATOR_ICON_METADATA = 12,
	ANQP_HS20_OSU_PROVIDERS_NAI_LIST = 13,
	/* 14 - 255 reserved */
};

/* IEEE 802.11-2016 Table 9-275 Authentication Parameter types */
enum anqp_auth_parameter_type {
	ANQP_AP_EXPANDED_EAP_METHOD = 1,
	ANQP_AP_NON_INNER_AUTH_EAP = 2,
	ANQP_AP_INNER_AUTH_EAP = 3,
	ANQP_AP_EXPANDED_INNER_EAP_METHOD = 4,
	ANQP_AP_CREDENTIAL = 5,
	ANQP_AP_TUNNELED_EAP_CREDENTIAL = 6,
	ANQP_AP_VENDOR_SPECIFIC = 221,
};

struct anqp_iter {
	unsigned int max;
	unsigned int pos;
	const unsigned char *anqp;

	unsigned int id;
	unsigned int len;
	const unsigned char *data;
};

/*
 * TODO: Support expanded EAP types
 */
struct anqp_eap_method {
	char realm[256];
	uint8_t method;
	uint8_t non_eap_inner;
	uint8_t eap_inner;
	uint8_t credential;
	uint8_t tunneled_credential;
};

void anqp_iter_init(struct anqp_iter *iter, const unsigned char *anqp,
			unsigned int len);
bool anqp_iter_next(struct anqp_iter *iter, uint16_t *id, uint16_t *len,
			const void **data);
bool anqp_iter_is_hs20(const struct anqp_iter *iter, uint8_t *stype,
			unsigned int *len, const unsigned char **data);
bool anqp_hs20_parse_osu_provider_nai(const unsigned char *anqp,
					unsigned int len, const char **nai_out);
bool anqp_parse_nai_realm(const unsigned char *anqp, unsigned int len,
				bool hs20, struct anqp_eap_method *method);
