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
#include <ell/ell.h>

#include "src/ie.h"
#include "src/scan.h"

struct test_data {
	unsigned int len;
	unsigned char *buf;
	enum ie_bss_capability capability;
};


static unsigned char ssid_security_wpa_data_1[] = {
	0x30, 0x14, 0x01, 0x00, 0x00, 0x0f, 0xac, 0x04,
	0x01, 0x00, 0x00, 0x0f, 0xac, 0x04, 0x01, 0x00,
	0x00, 0x0f, 0xac, 0x02, 0x0c, 0x00,
};

static struct test_data ssid_security_wpa_test_1 = {
	.len = sizeof(ssid_security_wpa_data_1),
	.buf = ssid_security_wpa_data_1,
	.capability = IE_BSS_CAP_ESS,
};

static unsigned char ssid_security_wpa2_data_1[] = {
	0x30, 0x14, 0x01, 0x00, 0x00, 0x0f, 0xac, 0x04,
	0x01, 0x00, 0x00, 0x0f, 0xac, 0x04, 0x01, 0x00,
	0x00, 0x0f, 0xac, 0x02, 0x00, 0x00,
};

static struct test_data ssid_security_wpa_test_2 = {
	.len = sizeof(ssid_security_wpa2_data_1),
	.buf = ssid_security_wpa2_data_1,
	.capability = IE_BSS_CAP_ESS,
};

static unsigned char ssid_security_8021x_data_1[] = {
	0x30, 0x14, 0x01, 0x00, 0x00, 0x0f, 0xac, 0x04,
	0x01, 0x00, 0x00, 0x0f, 0xac, 0x04, 0x01, 0x00,
	0x00, 0x0f, 0xac, 0x01, 0x28, 0x00,
};

static struct test_data ssid_security_8021x_test_1 = {
	.len = sizeof(ssid_security_8021x_data_1),
	.buf = ssid_security_8021x_data_1,
	.capability = IE_BSS_CAP_ESS,
};

static struct test_data ssid_security_wep_test_1 = {
	.len = 0,
	.buf = NULL,
	.capability = IE_BSS_CAP_ESS | IE_BSS_CAP_PRIVACY,
};

static struct test_data ssid_security_open_test_1 = {
	.len = 0,
	.buf = NULL,
	.capability = IE_BSS_CAP_ESS,
};

static void ssid_security_open_test(const void *data)
{
	const struct test_data *test_data = data;

	assert(scan_get_ssid_security(test_data->capability,
		(struct ie_rsn_info *)test_data->buf) ==
						SCAN_SSID_SECURITY_NONE);
}

static void ssid_security_wep_test(const void *data)
{
	const struct test_data *test_data = data;

	assert(scan_get_ssid_security(test_data->capability,
		(struct ie_rsn_info *)test_data->buf) ==
						SCAN_SSID_SECURITY_WEP);
}

static void ssid_security_psk_test(const void *data)
{
	const struct test_data *test_data = data;
	struct ie_rsn_info info;
	int ret;

	ret = ie_parse_rsne_from_data(test_data->buf, test_data->len, &info);
	assert(ret == 0);
	assert(scan_get_ssid_security(test_data->capability,
					&info) == SCAN_SSID_SECURITY_PSK);
}

static void ssid_security_8021x_test(const void *data)
{
	const struct test_data *test_data = data;
	struct ie_rsn_info info;
	int ret;

	ret = ie_parse_rsne_from_data(test_data->buf, test_data->len, &info);
	assert(ret == 0);
	assert(scan_get_ssid_security(test_data->capability,
					&info) == SCAN_SSID_SECURITY_8021X);
}

int main(int argc, char *argv[])
{
	l_test_init(&argc, &argv);

	l_test_add("/SSID Security/Open",
			ssid_security_open_test, &ssid_security_open_test_1);
	l_test_add("/SSID Security/WPA",
			ssid_security_psk_test, &ssid_security_wpa_test_1);
	l_test_add("/SSID Security/WPA2",
			ssid_security_psk_test, &ssid_security_wpa_test_2);
	l_test_add("/SSID Security/8021x",
			ssid_security_8021x_test, &ssid_security_8021x_test_1);
	l_test_add("/SSID Security/WEP",
			ssid_security_wep_test, &ssid_security_wep_test_1);

	return l_test_run();
}
