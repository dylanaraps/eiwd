/*
 *
 *  Wireless daemon for Linux
 *
 *  Copyright (C) 2017  Intel Corporation. All rights reserved.
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

#include <errno.h>
#include <linux/if_ether.h>

#include <ell/ell.h>

#include "src/iwd.h"
#include "src/device.h"
#include "src/wiphy.h"
#include "src/ie.h"
#include "src/ap.h"

struct ap_state {
	struct device *device;
	char *ssid;
	char *psk;
	ap_event_cb_t event_cb;
	int channel;
	unsigned int ciphers;
	uint32_t beacon_interval;
	struct l_uintset *rates;
};

static struct l_genl_family *nl80211 = NULL;

static struct l_queue *ap_list = NULL;

static void ap_free(void *data)
{
	struct ap_state *ap = data;

	l_free(ap->ssid);
	memset(ap->psk, 0, strlen(ap->psk));
	l_free(ap->psk);

	if (ap->rates)
		l_uintset_free(ap->rates);

	l_free(ap);
}

static void ap_stopped(struct ap_state *ap)
{
	ap->event_cb(ap->device, AP_EVENT_STOPPED);

	ap_free(ap);

	l_queue_remove(ap_list, ap);
}

static bool ap_match_device(const void *a, const void *b)
{
	const struct ap_state *ap = a;

	return ap->device == b;
}

int ap_start(struct device *device, const char *ssid, const char *psk,
		ap_event_cb_t event_cb)
{
	struct wiphy *wiphy = device_get_wiphy(device);
	struct ap_state *ap;

	if (l_queue_find(ap_list, ap_match_device, device))
		return -EEXIST;

	ap = l_new(struct ap_state, 1);
	ap->device = device;
	ap->ssid = l_strdup(ssid);
	ap->psk = l_strdup(psk);
	ap->event_cb = event_cb;
	/* TODO: Start a Get Survey to decide the channel */
	ap->channel = 6;
	/* TODO: Add all ciphers supported by wiphy */
	ap->ciphers = wiphy_select_cipher(wiphy, 0xffff);
	ap->beacon_interval = 100;
	/* TODO: Use actual supported rates */
	ap->rates = l_uintset_new(200);
	l_uintset_put(ap->rates, 2); /* 1 Mbps*/
	l_uintset_put(ap->rates, 11); /* 5.5 Mbps*/
	l_uintset_put(ap->rates, 22); /* 11 Mbps*/

	if (!ap_list)
		ap_list = l_queue_new();

	l_queue_push_tail(ap_list, ap);

	return 0;
}

int ap_stop(struct device *device)
{
	struct ap_state *ap = l_queue_find(ap_list, ap_match_device, device);

	if (!ap)
		return -ENODEV;

	/* TODO: Send NL80211_CMD_STOP_AP */
	ap_stopped(ap);

	return 0;
}

void ap_init(struct l_genl_family *in)
{
	nl80211 = in;

	/*
	 * TODO: Check wiphy supports AP mode, supported channels,
	 * check wiphy's NL80211_ATTR_TX_FRAME_TYPES.
	 */
}

void ap_exit(void)
{
	l_queue_destroy(ap_list, ap_free);
}
