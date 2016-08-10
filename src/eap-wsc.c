/*
 *
 *  Wireless daemon for Linux
 *
 *  Copyright (C) 2016  Intel Corporation. All rights reserved.
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
#include "wscutil.h"

#define EAP_WSC_OFFSET 12

struct eap_wsc_state {
};

static int eap_wsc_probe(struct eap_state *eap, const char *name)
{
	struct eap_wsc_state *wsc;

	if (strcasecmp(name, "WSC"))
		return -ENOTSUP;

	wsc = l_new(struct eap_wsc_state, 1);

	eap_set_data(eap, wsc);

	return 0;
}

static void eap_wsc_remove(struct eap_state *eap)
{
	struct eap_wsc_state *wsc = eap_get_data(eap);

	eap_set_data(eap, NULL);

	l_free(wsc);
}

static void eap_wsc_handle_request(struct eap_state *eap,
					const uint8_t *pkt, size_t len)
{
	uint8_t buf[256];

	/* TODO: Fill in response */
	eap_send_response(eap, EAP_TYPE_EXPANDED, buf, 256);
}

static bool eap_wsc_load_settings(struct eap_state *eap,
					struct l_settings *settings,
					const char *prefix)
{
	return true;
}

static struct eap_method eap_wsc = {
	.request_type = EAP_TYPE_EXPANDED,
	.exports_msk = true,
	.name = "WSC",
	.probe = eap_wsc_probe,
	.remove = eap_wsc_remove,
	.handle_request = eap_wsc_handle_request,
	.load_settings = eap_wsc_load_settings,
};

static int eap_wsc_init(void)
{
	l_debug("");

	return eap_register_method(&eap_wsc);
}

static void eap_wsc_exit(void)
{
	l_debug("");

	eap_unregister_method(&eap_wsc);
}

EAP_METHOD_BUILTIN(eap_wsc, eap_wsc_init, eap_wsc_exit)
