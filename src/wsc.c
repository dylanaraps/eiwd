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

#include <errno.h>
#include <ell/ell.h>

#include "dbus.h"
#include "netdev.h"
#include "wiphy.h"
#include "scan.h"
#include "mpdu.h"
#include "ie.h"
#include "wscutil.h"
#include "wsc.h"

#define WALK_TIME 120

static struct l_genl_family *nl80211 = NULL;
static uint32_t netdev_watch = 0;

struct wsc_sm {
	uint8_t *wsc_ies;
	size_t wsc_ies_size;
	struct l_timeout *walk_timer;
};

struct wsc {
	struct netdev *netdev;
};

struct wsc_sm *wsc_sm_new_pushbutton(uint32_t ifindex, const uint8_t *addr,
					uint32_t bands)
{
	static const uint8_t wfa_oui[] = { 0x00, 0x50, 0xF2 };
	struct wsc_sm *sm;
	struct wsc_probe_request req;
	uint8_t *wsc_data;
	size_t wsc_data_size;

	memset(&req, 0, sizeof(req));

	req.version2 = true;
	req.request_type = WSC_REQUEST_TYPE_ENROLLEE_INFO;

	/* TODO: Grab from configuration file ? */
	req.config_methods = WSC_CONFIGURATION_METHOD_VIRTUAL_PUSH_BUTTON |
				WSC_CONFIGURATION_METHOD_KEYPAD;

	if (!wsc_uuid_from_addr(addr, req.uuid_e))
		return NULL;

	/* TODO: Grab from configuration file ? */
	req.primary_device_type.category = 255;
	memcpy(req.primary_device_type.oui, wfa_oui, 3);
	req.primary_device_type.oui_type = 0x04;
	req.primary_device_type.subcategory = 0;

	if (bands & SCAN_BAND_2_4_GHZ)
		req.rf_bands |= WSC_RF_BAND_2_4_GHZ;
	if (bands & SCAN_BAND_5_GHZ)
		req.rf_bands |= WSC_RF_BAND_5_0_GHZ;

	req.association_state = WSC_ASSOCIATION_STATE_NOT_ASSOCIATED,
	req.configuration_error = WSC_CONFIGURATION_ERROR_NO_ERROR,
	req.device_password_id = WSC_DEVICE_PASSWORD_ID_PUSH_BUTTON,
	req.request_to_enroll = true,

	wsc_data = wsc_build_probe_request(&req, &wsc_data_size);
	if (!wsc_data)
		return NULL;

	sm = l_new(struct wsc_sm, 1);
	sm->wsc_ies = ie_tlv_encapsulate_wsc_payload(wsc_data, wsc_data_size,
							&sm->wsc_ies_size);
	l_free(wsc_data);

	if (sm->wsc_ies) {
		l_free(sm);
		return NULL;
	}

	return sm;
}

void wsc_sm_free(struct wsc_sm *sm)
{
	l_free(sm);
}

static struct l_dbus_message *wsc_push_button(struct l_dbus *dbus,
						struct l_dbus_message *message,
						void *user_data)
{
	l_debug("");

	return dbus_error_not_implemented(message);
}

static struct l_dbus_message *wsc_cancel(struct l_dbus *dbus,
						struct l_dbus_message *message,
						void *user_data)
{
	l_debug("");

	return dbus_error_not_implemented(message);
}

static void setup_wsc_interface(struct l_dbus_interface *interface)
{
	l_dbus_interface_method(interface, "PushButton", 0,
				wsc_push_button, "", "");
	l_dbus_interface_method(interface, "Cancel", 0,
				wsc_cancel, "", "");
}

static void wsc_free(void *userdata)
{
	struct wsc *wsc = userdata;

	l_free(wsc);
}

static void netdev_appeared(struct netdev *netdev, void *userdata)
{
	struct l_dbus *dbus = dbus_get_bus();
	struct wsc *wsc;

	wsc = l_new(struct wsc, 1);
	wsc->netdev = netdev;

	if (!l_dbus_register_interface(dbus, iwd_device_get_path(netdev),
					IWD_WSC_INTERFACE,
					setup_wsc_interface,
					wsc, wsc_free)) {
		wsc_free(wsc);
		l_info("Unable to register %s interface", IWD_WSC_INTERFACE);
	}
}

static void netdev_disappeared(struct netdev *netdev, void *userdata)
{
	struct l_dbus *dbus = dbus_get_bus();

	if (!l_dbus_unregister_interface(dbus, iwd_device_get_path(netdev),
						IWD_WSC_INTERFACE))
		l_info("Unable to unregister %s interface", IWD_WSC_INTERFACE);
}

bool wsc_init(struct l_genl_family *in)
{
	netdev_watch = netdev_watch_add(netdev_appeared, netdev_disappeared,
						NULL, NULL);
	if (!netdev_watch)
		return false;

	nl80211 = in;
	return true;
}

bool wsc_exit()
{
	l_debug("");

	if (!nl80211)
		return false;

	netdev_watch_remove(netdev_watch);
	nl80211 = 0;

	return true;
}
