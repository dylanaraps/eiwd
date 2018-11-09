/*
 *
 *  Wireless daemon for Linux
 *
 *  Copyright (C) 2014  Intel Corporation. All rights reserved.
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

#include "src/util.h"

struct ssid_test_data {
	size_t len;
	uint8_t ssid[32];
	const char *string;
	bool result;
};

const struct ssid_test_data ssid_samples[] = {
	{ 0, { }, "", true },
	{ 1, { }, "", true },
	{ 32, { }, "", true },
	{ 33, { }, "", true },
	{ 33, { 'a', 'b', 'c', }, "", true },
	{ 42, { }, "", true },
	{ 3, { 'f', 'o', 'o', }, "foo", true },
	{ 3, { }, "", true },
	{ 3, { 'f', 'o', 'o', }, "bar", false },
	{ 3, { 'f', 'o', 'o', 0xff, }, "foo", true },
	{ 5, { 'f', 'o', 'o', 'b', 'a', 'r' }, "fooba", true },
	{ 5, { 'f', 'o', 'o', 'b', 'a', 'r' }, "foobar", false },
	{ 5, { 'f', 'o', 'o', 'b', 'a', 'r' }, "oobar", false },
	{ 4, { 'x', 'y', 'z', 0xff }, "xyz�", true },
	{ 6, { 'x', 'y', 'z', 0xff, '1', '2' }, "xyz�12", true },
	{ 7, { 0xf0, 0xf3, '3', '4', '5', '6', '7', }, "��34567", true },
	{ 6, { 0xc3, 0x96, '3', '4', '5', '6' }, "Ö3456", true },
	{ 6, { '1', 0xc3, 0x96, '4', '5', '6' }, "1Ö456", true },
	{ 6, { '1', '2', '3', '4', 0xc3, 0x96 }, "1234Ö", true },
};

static void ssid_to_utf8(const void *data)
{
	const struct ssid_test_data *ssid = data;
	int i = 0, samples = L_ARRAY_SIZE(ssid_samples);

	while (i < samples) {
		const char *result = util_ssid_to_utf8(ssid[i].len,
						ssid[i].ssid);

		assert(!memcmp(ssid[i].string, result,
				strlen(ssid[i].string)) == ssid[i].result);

		i++;
	}

}

int main(int argc, char *argv[])
{
	l_test_init(&argc, &argv);

	l_test_add("/util/ssid_to_utf8/", ssid_to_utf8, ssid_samples);

	return l_test_run();
}
