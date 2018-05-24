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

#include "src/iwd.h"
#include "src/common.h"
#include "src/ie.h"

struct test_data {
	unsigned char *rsne;
	unsigned int rsne_len;
	enum ie_bss_capability capability;
	enum security expected;
};

static unsigned char ssid_security_wpa_data_1[] = {
	0x30, 0x14, 0x01, 0x00, 0x00, 0x0f, 0xac, 0x04,
	0x01, 0x00, 0x00, 0x0f, 0xac, 0x04, 0x01, 0x00,
	0x00, 0x0f, 0xac, 0x02, 0x0c, 0x00,
};

static struct test_data ssid_security_wpa_test_1 = {
	.rsne = ssid_security_wpa_data_1,
	.rsne_len = sizeof(ssid_security_wpa_data_1),
	.capability = IE_BSS_CAP_ESS,
	.expected = SECURITY_PSK,
};

static unsigned char ssid_security_wpa2_data_1[] = {
	0x30, 0x14, 0x01, 0x00, 0x00, 0x0f, 0xac, 0x04,
	0x01, 0x00, 0x00, 0x0f, 0xac, 0x04, 0x01, 0x00,
	0x00, 0x0f, 0xac, 0x02, 0x00, 0x00,
};

static struct test_data ssid_security_wpa_test_2 = {
	.rsne = ssid_security_wpa2_data_1,
	.rsne_len = sizeof(ssid_security_wpa2_data_1),
	.capability = IE_BSS_CAP_ESS,
	.expected = SECURITY_PSK,
};

static unsigned char ssid_security_8021x_data_1[] = {
	0x30, 0x14, 0x01, 0x00, 0x00, 0x0f, 0xac, 0x04,
	0x01, 0x00, 0x00, 0x0f, 0xac, 0x04, 0x01, 0x00,
	0x00, 0x0f, 0xac, 0x01, 0x28, 0x00,
};

static struct test_data ssid_security_8021x_test_1 = {
	.rsne = ssid_security_8021x_data_1,
	.rsne_len = sizeof(ssid_security_8021x_data_1),
	.capability = IE_BSS_CAP_ESS,
	.expected = SECURITY_8021X,
};

static struct test_data ssid_security_wep_test_1 = {
	.capability = IE_BSS_CAP_ESS | IE_BSS_CAP_PRIVACY,
	.expected = SECURITY_WEP,
};

static struct test_data ssid_security_open_test_1 = {
	.capability = IE_BSS_CAP_ESS,
	.expected = SECURITY_NONE,
};

static void ssid_security_test(const void *data)
{
	const struct test_data *test = data;
	struct ie_rsn_info info;
	const struct ie_rsn_info *infop;
	int ret;

	if (test->rsne) {
		ret = ie_parse_rsne_from_data(test->rsne,
							test->rsne_len, &info);
		assert(ret == 0);

		infop = &info;
	} else
		infop = NULL;

	assert(security_determine(test->capability, infop) == test->expected);
}

int main(int argc, char *argv[])
{
	l_test_init(&argc, &argv);

	l_test_add("/SSID Security/Open",
			ssid_security_test, &ssid_security_open_test_1);
	l_test_add("/SSID Security/WPA",
			ssid_security_test, &ssid_security_wpa_test_1);
	l_test_add("/SSID Security/WPA2",
			ssid_security_test, &ssid_security_wpa_test_2);
	l_test_add("/SSID Security/8021x",
			ssid_security_test, &ssid_security_8021x_test_1);
	l_test_add("/SSID Security/WEP",
			ssid_security_test, &ssid_security_wep_test_1);

	return l_test_run();
}
