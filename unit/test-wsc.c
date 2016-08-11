/*
 *
 *  Wireless daemon for Linux
 *
 *  Copyright (C) 2015  Intel Corporation. All rights reserved.
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
#include <string.h>
#include <assert.h>
#include <stdlib.h>
#include <ell/ell.h>

#include "src/wscutil.h"

static const unsigned char wsc_attrs1[] = {
	0x10, 0x4a, 0x00, 0x01, 0x10, 0x10, 0x44, 0x00, 0x01, 0x02, 0x10, 0x41,
	0x00, 0x01, 0x01, 0x10, 0x12, 0x00, 0x02, 0x00, 0x04, 0x10, 0x53, 0x00,
	0x02, 0x26, 0x88, 0x10, 0x3b, 0x00, 0x01, 0x03, 0x10, 0x47, 0x00, 0x10,
	0xc4, 0x4a, 0xad, 0x8d, 0x25, 0x2f, 0x52, 0xc6, 0xf9, 0x6b, 0x38, 0x5d,
	0xcb, 0x23, 0x31, 0xae, 0x10, 0x21, 0x00, 0x15, 0x41, 0x53, 0x55, 0x53,
	0x54, 0x65, 0x4b, 0x20, 0x43, 0x6f, 0x6d, 0x70, 0x75, 0x74, 0x65, 0x72,
	0x20, 0x49, 0x6e, 0x63, 0x2e, 0x10, 0x23, 0x00, 0x1c, 0x57, 0x69, 0x2d,
	0x46, 0x69, 0x20, 0x50, 0x72, 0x6f, 0x74, 0x65, 0x63, 0x74, 0x65, 0x64,
	0x20, 0x53, 0x65, 0x74, 0x75, 0x70, 0x20, 0x52, 0x6f, 0x75, 0x74, 0x65,
	0x72, 0x10, 0x24, 0x00, 0x08, 0x52, 0x54, 0x2d, 0x41, 0x43, 0x36, 0x38,
	0x55, 0x10, 0x42, 0x00, 0x11, 0x31, 0x30, 0x3a, 0x63, 0x33, 0x3a, 0x37,
	0x62, 0x3a, 0x35, 0x34, 0x3a, 0x37, 0x34, 0x3a, 0x64, 0x30, 0x10, 0x54,
	0x00, 0x08, 0x00, 0x06, 0x00, 0x50, 0xf2, 0x04, 0x00, 0x01, 0x10, 0x11,
	0x00, 0x08, 0x52, 0x54, 0x2d, 0x41, 0x43, 0x36, 0x38, 0x55, 0x10, 0x08,
	0x00, 0x02, 0x20, 0x08, 0x10, 0x3c, 0x00, 0x01, 0x03, 0x10, 0x49, 0x00,
	0x0e, 0x00, 0x37, 0x2a, 0x00, 0x01, 0x20, 0x01, 0x06, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff,
};

static void wsc_test_iter_sanity_check(const void *data)
{
	struct wsc_attr_iter iter;
	struct wsc_wfa_ext_iter wfa_iter;

	wsc_attr_iter_init(&iter, wsc_attrs1, sizeof(wsc_attrs1));

	assert(wsc_attr_iter_next(&iter));
	assert(wsc_attr_iter_get_type(&iter) == WSC_ATTR_VERSION);
	assert(wsc_attr_iter_get_length(&iter) == 1);

	assert(wsc_attr_iter_next(&iter));
	assert(wsc_attr_iter_get_type(&iter) == WSC_ATTR_WSC_STATE);
	assert(wsc_attr_iter_get_length(&iter) == 1);

	assert(wsc_attr_iter_next(&iter));
	assert(wsc_attr_iter_get_type(&iter) == WSC_ATTR_SELECTED_REGISTRAR);
	assert(wsc_attr_iter_get_length(&iter) == 1);

	assert(wsc_attr_iter_next(&iter));
	assert(wsc_attr_iter_get_type(&iter) == WSC_ATTR_DEVICE_PASSWORD_ID);
	assert(wsc_attr_iter_get_length(&iter) == 2);

	assert(wsc_attr_iter_next(&iter));
	assert(wsc_attr_iter_get_type(&iter) ==
			WSC_ATTR_SELECTED_REGISTRAR_CONFIGURATION_METHODS);
	assert(wsc_attr_iter_get_length(&iter) == 2);

	assert(wsc_attr_iter_next(&iter));
	assert(wsc_attr_iter_get_type(&iter) == WSC_ATTR_RESPONSE_TYPE);
	assert(wsc_attr_iter_get_length(&iter) == 1);

	assert(wsc_attr_iter_next(&iter));
	assert(wsc_attr_iter_get_type(&iter) == WSC_ATTR_UUID_E);
	assert(wsc_attr_iter_get_length(&iter) == 16);

	assert(wsc_attr_iter_next(&iter));
	assert(wsc_attr_iter_get_type(&iter) == WSC_ATTR_MANUFACTURER);
	assert(wsc_attr_iter_get_length(&iter) == 21);

	assert(wsc_attr_iter_next(&iter));
	assert(wsc_attr_iter_get_type(&iter) == WSC_ATTR_MODEL_NAME);
	assert(wsc_attr_iter_get_length(&iter) == 28);

	assert(wsc_attr_iter_next(&iter));
	assert(wsc_attr_iter_get_type(&iter) == WSC_ATTR_MODEL_NUMBER);
	assert(wsc_attr_iter_get_length(&iter) == 8);

	assert(wsc_attr_iter_next(&iter));
	assert(wsc_attr_iter_get_type(&iter) == WSC_ATTR_SERIAL_NUMBER);
	assert(wsc_attr_iter_get_length(&iter) == 17);

	assert(wsc_attr_iter_next(&iter));
	assert(wsc_attr_iter_get_type(&iter) == WSC_ATTR_PRIMARY_DEVICE_TYPE);
	assert(wsc_attr_iter_get_length(&iter) == 8);

	assert(wsc_attr_iter_next(&iter));
	assert(wsc_attr_iter_get_type(&iter) == WSC_ATTR_DEVICE_NAME);
	assert(wsc_attr_iter_get_length(&iter) == 8);

	assert(wsc_attr_iter_next(&iter));
	assert(wsc_attr_iter_get_type(&iter) == WSC_ATTR_CONFIGURATION_METHODS);
	assert(wsc_attr_iter_get_length(&iter) == 2);

	assert(wsc_attr_iter_next(&iter));
	assert(wsc_attr_iter_get_type(&iter) == WSC_ATTR_RF_BANDS);
	assert(wsc_attr_iter_get_length(&iter) == 1);

	assert(wsc_attr_iter_next(&iter));
	assert(wsc_attr_iter_get_type(&iter) == WSC_ATTR_VENDOR_EXTENSION);
	assert(wsc_attr_iter_get_length(&iter) == 14);

	assert(wsc_attr_iter_recurse_wfa_ext(&iter, &wfa_iter));

	assert(wsc_wfa_ext_iter_next(&wfa_iter));
	assert(wsc_wfa_ext_iter_get_type(&wfa_iter) ==
			WSC_WFA_EXTENSION_VERSION2);
	assert(wsc_wfa_ext_iter_get_length(&wfa_iter) == 1);

	assert(wsc_wfa_ext_iter_next(&wfa_iter));
	assert(wsc_wfa_ext_iter_get_type(&wfa_iter) ==
			WSC_WFA_EXTENSION_AUTHORIZED_MACS);
	assert(wsc_wfa_ext_iter_get_length(&wfa_iter) == 6);

	assert(!wsc_attr_iter_next(&iter));
}


static const unsigned char beacon1[] = {
	0x10, 0x4a, 0x00, 0x01, 0x10, 0x10, 0x44, 0x00, 0x01, 0x02, 0x10, 0x49,
	0x00, 0x06, 0x00, 0x37, 0x2a, 0x00, 0x01, 0x20
};

struct beacon_data {
	struct wsc_beacon expected;
	const void *pdu;
	unsigned int len;
};

static const struct beacon_data beacon_data_1 = {
	.pdu = beacon1,
	.len = sizeof(beacon1),
	.expected = {
		.version2 = true,
		.config_state = WSC_CONFIG_STATE_CONFIGURED,
		.ap_setup_locked = false,
		.selected_registrar = false,
	},
};

static void wsc_test_parse_beacon(const void *data)
{
	const struct beacon_data *test = data;
	struct wsc_beacon beacon;
	const struct wsc_beacon *expected = &test->expected;
	int r;

	r = wsc_parse_beacon(test->pdu, test->len, &beacon);
	assert(r == 0);

	assert(expected->version2 == beacon.version2);
	assert(expected->config_state == beacon.config_state);
	assert(expected->ap_setup_locked == beacon.ap_setup_locked);
	assert(expected->selected_registrar == beacon.selected_registrar);
	assert(expected->device_password_id == beacon.device_password_id);
	assert(expected->selected_reg_config_methods ==
				beacon.selected_reg_config_methods);
	assert(!memcmp(expected->uuid_e, beacon.uuid_e, 16));
	assert(expected->rf_bands == beacon.rf_bands);

	assert(!memcmp(expected->authorized_macs,
				beacon.authorized_macs,
				sizeof(beacon.authorized_macs)));
	assert(expected->reg_config_methods ==
				beacon.reg_config_methods);
}

struct probe_response_data {
	struct wsc_probe_response expected;
	const void *pdu;
	unsigned int len;
};

static const struct probe_response_data probe_response_data_1 = {
	.pdu = wsc_attrs1,
	.len = sizeof(wsc_attrs1),
	.expected = {
		.version2 = true,
		.config_state = WSC_CONFIG_STATE_CONFIGURED,
		.ap_setup_locked = false,
		.selected_registrar = true,
		.device_password_id = WSC_DEVICE_PASSWORD_ID_PUSH_BUTTON,
		.selected_reg_config_methods =
				WSC_CONFIGURATION_METHOD_VIRTUAL_DISPLAY_PIN |
				WSC_CONFIGURATION_METHOD_VIRTUAL_PUSH_BUTTON |
				WSC_CONFIGURATION_METHOD_PHYSICAL_PUSH_BUTTON,
		.response_type = WSC_RESPONSE_TYPE_AP,
		.uuid_e = { 0xc4, 0x4a, 0xad, 0x8d, 0x25, 0x2f, 0x52, 0xc6,
			0xf9, 0x6b, 0x38, 0x5d, 0xcb, 0x23, 0x31, 0xae },
		.manufacturer = "ASUSTeK Computer Inc.",
		.model_name = "Wi-Fi Protected Setup Router",
		.model_number = "RT-AC68U",
		.serial_number = "10:c3:7b:54:74:d0",
		.primary_device_type = {
			.category = 6,
			.oui = { 0x00, 0x50, 0xf2 },
			.oui_type = 0x04,
			.subcategory = 1, },
		.device_name = "RT-AC68U",
		.config_methods = WSC_CONFIGURATION_METHOD_VIRTUAL_DISPLAY_PIN,
		.rf_bands = WSC_RF_BAND_2_4_GHZ | WSC_RF_BAND_5_0_GHZ,
		.authorized_macs = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, },
	},
};

static void wsc_test_parse_probe_response(const void *data)
{
	const struct probe_response_data *test = data;
	struct wsc_probe_response probe_response;
	const struct wsc_probe_response *expected = &test->expected;
	int r;

	r = wsc_parse_probe_response(test->pdu, test->len, &probe_response);
	assert(r == 0);

	assert(expected->version2 == probe_response.version2);
	assert(expected->config_state == probe_response.config_state);
	assert(expected->ap_setup_locked == probe_response.ap_setup_locked);
	assert(expected->selected_registrar ==
					probe_response.selected_registrar);
	assert(expected->device_password_id ==
					probe_response.device_password_id);
	assert(expected->selected_reg_config_methods ==
				probe_response.selected_reg_config_methods);
	assert(expected->response_type == probe_response.response_type);
	assert(!memcmp(expected->uuid_e, probe_response.uuid_e, 16));
	assert(!strcmp(expected->manufacturer, probe_response.manufacturer));
	assert(!strcmp(expected->model_name, probe_response.model_name));
	assert(!strcmp(expected->model_number, probe_response.model_number));
	assert(!strcmp(expected->serial_number, probe_response.serial_number));

	assert(expected->primary_device_type.category ==
				probe_response.primary_device_type.category);
	assert(!memcmp(expected->primary_device_type.oui,
				probe_response.primary_device_type.oui, 3));
	assert(expected->primary_device_type.oui_type ==
				probe_response.primary_device_type.oui_type);
	assert(expected->primary_device_type.subcategory ==
				probe_response.primary_device_type.subcategory);

	assert(!strcmp(expected->device_name, probe_response.device_name));
	assert(expected->config_methods == probe_response.config_methods);
	assert(expected->rf_bands == probe_response.rf_bands);

	assert(!memcmp(expected->authorized_macs,
				probe_response.authorized_macs,
				sizeof(probe_response.authorized_macs)));
	assert(expected->reg_config_methods ==
				probe_response.reg_config_methods);
}

static const unsigned char probe_request1[] = {
	0x10, 0x4a, 0x00, 0x01, 0x10, 0x10, 0x3a, 0x00, 0x01, 0x01, 0x10, 0x08,
	0x00, 0x02, 0x21, 0x48, 0x10, 0x47, 0x00, 0x10, 0x79, 0x0c, 0x1f, 0x80,
	0x4f, 0x2b, 0x52, 0xb7, 0xbe, 0x30, 0xc0, 0xe9, 0x72, 0x92, 0x08, 0x8d,
	0x10, 0x54, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x10, 0x3c, 0x00, 0x01, 0x03, 0x10, 0x02, 0x00, 0x02, 0x00, 0x00, 0x10,
	0x09, 0x00, 0x02, 0x00, 0x00, 0x10, 0x12, 0x00, 0x02, 0x00, 0x04, 0x10,
	0x21, 0x00, 0x01, 0x20, 0x10, 0x23, 0x00, 0x01, 0x20, 0x10, 0x24, 0x00,
	0x01, 0x20, 0x10, 0x11, 0x00, 0x01, 0x20, 0x10, 0x49, 0x00, 0x09, 0x00,
	0x37, 0x2a, 0x00, 0x01, 0x20, 0x03, 0x01, 0x01,
};

struct probe_request_data {
	struct wsc_probe_request expected;
	const void *pdu;
	unsigned int len;
};

static const struct probe_request_data probe_request_data_1 = {
	.pdu = probe_request1,
	.len = sizeof(probe_request1),
	.expected = {
		.version2 = true,
		.request_type = WSC_REQUEST_TYPE_ENROLLEE_OPEN_8021X,
		.config_methods =
				WSC_CONFIGURATION_METHOD_VIRTUAL_DISPLAY_PIN |
				WSC_CONFIGURATION_METHOD_NFC_INTERFACE |
				WSC_CONFIGURATION_METHOD_KEYPAD,
		.uuid_e = { 0x79, 0x0c, 0x1f, 0x80, 0x4f, 0x2b, 0x52, 0xb7,
			0xbe, 0x30, 0xc0, 0xe9, 0x72, 0x92, 0x08, 0x8d },
		.primary_device_type = {
			.category = 0,
			.oui = { 0x00, 0x00, 0x00 },
			.oui_type = 0x00,
			.subcategory = 0, },
		.rf_bands = WSC_RF_BAND_2_4_GHZ | WSC_RF_BAND_5_0_GHZ,
		.association_state = WSC_ASSOCIATION_STATE_NOT_ASSOCIATED,
		.configuration_error = WSC_CONFIGURATION_ERROR_NO_ERROR,
		.device_password_id = WSC_DEVICE_PASSWORD_ID_PUSH_BUTTON,
		.manufacturer = " ",
		.model_name = " ",
		.model_number = " ",
		.device_name = " ",
		.request_to_enroll = true,
	},
};

static void wsc_test_parse_probe_request(const void *data)
{
	const struct probe_request_data *test = data;
	struct wsc_probe_request probe_request;
	const struct wsc_probe_request *expected = &test->expected;
	int r;

	r = wsc_parse_probe_request(test->pdu, test->len, &probe_request);
	assert(r == 0);

	assert(expected->version2 == probe_request.version2);
	assert(expected->request_type == probe_request.request_type);

	assert(expected->config_methods == probe_request.config_methods);
	assert(!memcmp(expected->uuid_e, probe_request.uuid_e, 16));

	assert(expected->primary_device_type.category ==
				probe_request.primary_device_type.category);
	assert(!memcmp(expected->primary_device_type.oui,
				probe_request.primary_device_type.oui, 3));
	assert(expected->primary_device_type.oui_type ==
				probe_request.primary_device_type.oui_type);
	assert(expected->primary_device_type.subcategory ==
				probe_request.primary_device_type.subcategory);

	assert(expected->rf_bands == probe_request.rf_bands);
	assert(expected->association_state == probe_request.association_state);
	assert(expected->configuration_error ==
				probe_request.configuration_error);
	assert(expected->device_password_id ==
					probe_request.device_password_id);

	assert(!strcmp(expected->manufacturer, probe_request.manufacturer));
	assert(!strcmp(expected->model_name, probe_request.model_name));
	assert(!strcmp(expected->model_number, probe_request.model_number));
	assert(!strcmp(expected->device_name, probe_request.device_name));

	assert(expected->request_to_enroll == probe_request.request_to_enroll);

	assert(expected->requested_device_type.category ==
				probe_request.requested_device_type.category);
	assert(!memcmp(expected->requested_device_type.oui,
				probe_request.requested_device_type.oui, 3));
	assert(expected->requested_device_type.oui_type ==
				probe_request.requested_device_type.oui_type);
	assert(expected->requested_device_type.subcategory ==
			probe_request.requested_device_type.subcategory);
}

static void wsc_test_build_probe_request(const void *data)
{
	const struct probe_request_data *test = data;
	uint8_t *pr;
	size_t prlen;

	pr = wsc_build_probe_request(&test->expected, &prlen);
	assert(pr);

	assert(!memcmp(test->pdu, pr, test->len));

	l_free(pr);
}

struct uuid_from_addr_data {
	uint8_t addr[6];
	uint8_t expected_uuid[16];
};

static const struct uuid_from_addr_data uuid_from_addr_data_1 = {
	.addr = { 0xa0, 0xa8, 0xcd, 0x1c, 0x7e, 0xc9 },
	.expected_uuid = { 0x79, 0x0c, 0x1f, 0x80, 0x4f, 0x2b, 0x52, 0xb7,
			0xbe, 0x30, 0xc0, 0xe9, 0x72, 0x92, 0x08, 0x8d },
};

static void wsc_test_uuid_from_addr(const void *data)
{
	const struct uuid_from_addr_data *test = data;
	uint8_t uuid[16];

	assert(wsc_uuid_from_addr(test->addr, uuid));

	assert(!memcmp(test->expected_uuid, uuid, 16));
}

static const unsigned char eap_wsc_m1[] = {
	0x01, 0x00, 0x01, 0x78, 0x02, 0x01, 0x01, 0x78, 0xfe, 0x00, 0x37, 0x2a,
	0x00, 0x00, 0x00, 0x01, 0x04, 0x00, 0x10, 0x4a, 0x00, 0x01, 0x10, 0x10,
	0x22, 0x00, 0x01, 0x04, 0x10, 0x47, 0x00, 0x10, 0x79, 0x0c, 0x1f, 0x80,
	0x4f, 0x2b, 0x52, 0xb7, 0xbe, 0x30, 0xc0, 0xe9, 0x72, 0x92, 0x08, 0x8d,
	0x10, 0x20, 0x00, 0x06, 0xa0, 0xa8, 0xcd, 0x1c, 0x7e, 0xc9, 0x10, 0x1a,
	0x00, 0x10, 0xab, 0x84, 0x41, 0x2f, 0xe7, 0xc3, 0xc9, 0xc9, 0xd7, 0xf4,
	0xe8, 0xc1, 0x4f, 0x49, 0x2b, 0x79, 0x10, 0x32, 0x00, 0xc0, 0xb2, 0xfc,
	0xd6, 0x4f, 0xf6, 0x71, 0x5a, 0x33, 0x84, 0x60, 0x4a, 0xe8, 0x2c, 0x1e,
	0x55, 0x4a, 0xdb, 0xd5, 0x18, 0x17, 0x91, 0xa6, 0xf5, 0x70, 0xcd, 0x23,
	0xd7, 0x12, 0x6e, 0x4c, 0xaf, 0x27, 0x9a, 0x4e, 0xf5, 0x37, 0xea, 0x8f,
	0x03, 0xc9, 0x0e, 0x79, 0xc5, 0x8d, 0x37, 0xf8, 0xfb, 0x11, 0xa1, 0x39,
	0x19, 0x9b, 0x5a, 0x3a, 0x66, 0x36, 0x6d, 0xfb, 0xae, 0xed, 0xfc, 0xa5,
	0x90, 0xcb, 0xb3, 0xe1, 0xd5, 0x92, 0x2e, 0xe9, 0x99, 0xbd, 0x0b, 0x93,
	0x82, 0x57, 0xe1, 0xbd, 0x70, 0x17, 0xa7, 0x78, 0x7a, 0x0a, 0xff, 0x42,
	0x06, 0x95, 0x2c, 0x0b, 0x6c, 0x1a, 0x6b, 0x2f, 0x6b, 0xed, 0x42, 0xa5,
	0x60, 0x8a, 0xb0, 0xb5, 0x79, 0x1b, 0xa9, 0xe6, 0x15, 0x17, 0xa3, 0x6c,
	0xe9, 0x84, 0xb3, 0x77, 0x48, 0x9b, 0x7a, 0x4d, 0x04, 0xf6, 0xb8, 0x27,
	0xe5, 0x0c, 0xcb, 0x76, 0xfc, 0x3c, 0x65, 0x49, 0xd7, 0x28, 0x06, 0x8d,
	0x99, 0x18, 0x0f, 0xa7, 0x35, 0xb2, 0x9d, 0x15, 0x35, 0x51, 0xea, 0x83,
	0xb6, 0x4d, 0x14, 0xb0, 0x21, 0xa4, 0x82, 0x1f, 0xb8, 0x73, 0x2b, 0x15,
	0x1d, 0x48, 0x99, 0x9f, 0x32, 0x2c, 0xe1, 0xe1, 0xab, 0x66, 0x3f, 0xb4,
	0x40, 0x79, 0xe8, 0x96, 0xe1, 0x9d, 0x54, 0x8b, 0xb6, 0x7f, 0x1a, 0x5b,
	0x5f, 0x09, 0x9f, 0x40, 0xa7, 0x8b, 0xc8, 0xf6, 0x27, 0x80, 0x10, 0x04,
	0x00, 0x02, 0x00, 0x23, 0x10, 0x10, 0x00, 0x02, 0x00, 0x0d, 0x10, 0x0d,
	0x00, 0x01, 0x01, 0x10, 0x08, 0x00, 0x02, 0x21, 0x48, 0x10, 0x44, 0x00,
	0x01, 0x01, 0x10, 0x21, 0x00, 0x01, 0x20, 0x10, 0x23, 0x00, 0x01, 0x20,
	0x10, 0x24, 0x00, 0x01, 0x20, 0x10, 0x42, 0x00, 0x01, 0x20, 0x10, 0x54,
	0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x11,
	0x00, 0x01, 0x20, 0x10, 0x3c, 0x00, 0x01, 0x02, 0x10, 0x02, 0x00, 0x02,
	0x00, 0x00, 0x10, 0x12, 0x00, 0x02, 0x00, 0x04, 0x10, 0x09, 0x00, 0x02,
	0x00, 0x00, 0x10, 0x2d, 0x00, 0x04, 0x80, 0x00, 0x00, 0x00, 0x10, 0x49,
	0x00, 0x06, 0x00, 0x37, 0x2a, 0x00, 0x01, 0x20,
};

struct m1_data {
	struct wsc_m1 expected;
	const void *pdu;
	unsigned int len;
};

static const struct m1_data m1_data_1 = {
	.pdu = eap_wsc_m1 + 18,
	.len = sizeof(eap_wsc_m1) - 18,
	.expected = {
		.version2 = true,
		.uuid_e = { 0x79, 0x0c, 0x1f, 0x80, 0x4f, 0x2b, 0x52, 0xb7,
			0xbe, 0x30, 0xc0, 0xe9, 0x72, 0x92, 0x08, 0x8d },
		.addr = { 0xa0, 0xa8, 0xcd, 0x1c, 0x7e, 0xc9 },
		.enrollee_nonce = { 0xab, 0x84, 0x41, 0x2f, 0xe7, 0xc3, 0xc9,
					0xc9, 0xd7, 0xf4, 0xe8, 0xc1, 0x4f,
					0x49, 0x2b, 0x79 },
		.public_key = { }, /* Tested elsewhere */
		.auth_type_flags =
			WSC_AUTHENTICATION_TYPE_WPA2_PERSONAL |
			WSC_AUTHENTICATION_TYPE_WPA_PERSONAL |
			WSC_AUTHENTICATION_TYPE_OPEN,
		.encryption_type_flags = WSC_ENCRYPTION_TYPE_AES_TKIP |
						WSC_ENCRYPTION_TYPE_NONE,
		.connection_type_flags = WSC_CONNECTION_TYPE_ESS,
		.config_methods = WSC_CONFIGURATION_METHOD_VIRTUAL_DISPLAY_PIN |
				WSC_CONFIGURATION_METHOD_KEYPAD |
				WSC_CONFIGURATION_METHOD_DISPLAY |
				WSC_CONFIGURATION_METHOD_NFC_INTERFACE,
		.config_state = WSC_CONFIG_STATE_NOT_CONFIGURED,
		.manufacturer = " ",
		.model_name = " ",
		.model_number = " ",
		.serial_number = " ",
		.primary_device_type = {
			.category = 0,
			.oui = { 0x00, 0x00, 0x00 },
			.oui_type = 0x00,
			.subcategory = 0, },
		.device_name = " ",
		.rf_bands = WSC_RF_BAND_5_0_GHZ,
		.association_state = WSC_ASSOCIATION_STATE_NOT_ASSOCIATED,
		.device_password_id = WSC_DEVICE_PASSWORD_ID_PUSH_BUTTON,
		.configuration_error = WSC_CONFIGURATION_ERROR_NO_ERROR,
		.os_version = 0,
		.request_to_enroll = false,
	},
};

static void wsc_test_parse_m1(const void *data)
{
	const struct m1_data *test = data;
	struct wsc_m1 m1;
	const struct wsc_m1 *expected = &test->expected;
	int r;

	r = wsc_parse_m1(test->pdu, test->len, &m1);
	assert(r == 0);

	assert(expected->version2 == m1.version2);
	assert(!memcmp(expected->uuid_e, m1.uuid_e, 16));
	assert(!memcmp(expected->addr, m1.addr, 6));
	assert(!memcmp(expected->enrollee_nonce, m1.enrollee_nonce, 16));

	/* Skip public_key testing */

	assert(expected->auth_type_flags == m1.auth_type_flags);
	assert(expected->encryption_type_flags == m1.encryption_type_flags);
	assert(expected->connection_type_flags == m1.connection_type_flags);
	assert(expected->config_methods == m1.config_methods);
	assert(expected->config_state == m1.config_state);

	assert(!strcmp(expected->manufacturer, m1.manufacturer));
	assert(!strcmp(expected->model_name, m1.model_name));
	assert(!strcmp(expected->model_number, m1.model_number));
	assert(!strcmp(expected->serial_number, m1.serial_number));

	assert(expected->primary_device_type.category ==
				m1.primary_device_type.category);
	assert(!memcmp(expected->primary_device_type.oui,
				m1.primary_device_type.oui, 3));
	assert(expected->primary_device_type.oui_type ==
				m1.primary_device_type.oui_type);
	assert(expected->primary_device_type.subcategory ==
				m1.primary_device_type.subcategory);

	assert(!strcmp(expected->device_name, m1.device_name));
	assert(expected->rf_bands == m1.rf_bands);
	assert(expected->association_state == m1.association_state);
	assert(expected->device_password_id == m1.device_password_id);
	assert(expected->configuration_error == m1.configuration_error);
	assert(expected->os_version == m1.os_version);
	assert(expected->request_to_enroll == m1.request_to_enroll);
}

int main(int argc, char *argv[])
{
	l_test_init(&argc, &argv);

	l_test_add("/wsc/iter/sanity-check", wsc_test_iter_sanity_check, NULL);

	l_test_add("/wsc/parse/beacon 1", wsc_test_parse_beacon,
					&beacon_data_1);

	l_test_add("/wsc/parse/probe response 1", wsc_test_parse_probe_response,
					&probe_response_data_1);

	l_test_add("/wsc/parse/probe request 1", wsc_test_parse_probe_request,
					&probe_request_data_1);

	l_test_add("/wsc/build/probe request 1", wsc_test_build_probe_request,
					&probe_request_data_1);

	l_test_add("/wsc/gen_uuid/1", wsc_test_uuid_from_addr,
					&uuid_from_addr_data_1);

	l_test_add("/wsc/parse/m1 1", wsc_test_parse_m1, &m1_data_1);

	return l_test_run();
}
