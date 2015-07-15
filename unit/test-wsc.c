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

#include "src/wsc.h"

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
	unsigned short len;
	enum wsc_attr type;

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

	assert(!wsc_attr_iter_next(&iter));
}

int main(int argc, char *argv[])
{
	l_test_init(&argc, &argv);

	l_test_add("/wsc/iter/sanity-check", wsc_test_iter_sanity_check, NULL);

	return l_test_run();
}
