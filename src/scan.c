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

#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <sys/socket.h>
#include <linux/if.h>
#include <linux/if_ether.h>
#include <ell/ell.h>

#include "linux/nl80211.h"
#include "src/iwd.h"
#include "src/wiphy.h"
#include "src/ie.h"
#include "src/scan.h"

void scan_start(struct l_genl_family *nl80211, uint32_t ifindex,
		scan_func_t callback, void *user_data)
{
	struct l_genl_msg *msg;

	msg = l_genl_msg_new_sized(NL80211_CMD_TRIGGER_SCAN, 16);
	l_genl_msg_append_attr(msg, NL80211_ATTR_IFINDEX, 4, &ifindex);
	l_genl_family_send(nl80211, msg, callback, user_data, NULL);
	l_genl_msg_unref(msg);
}

void scan_sched_start(struct l_genl_family *nl80211, uint32_t ifindex,
			uint32_t scan_interval,
			scan_func_t callback, void *user_data)
{
	struct l_genl_msg *msg;

	scan_interval *= 1000;	/* in kernel the interval is in msecs */

	msg = l_genl_msg_new_sized(NL80211_CMD_START_SCHED_SCAN, 32);
	l_genl_msg_append_attr(msg, NL80211_ATTR_IFINDEX, 4, &ifindex);
	l_genl_msg_append_attr(msg, NL80211_ATTR_SCHED_SCAN_INTERVAL,
							4, &scan_interval);
	l_genl_msg_append_attr(msg, NL80211_ATTR_SOCKET_OWNER, 0, NULL);

	if (!l_genl_family_send(nl80211, msg, callback, user_data, NULL))
		l_error("Starting scheduled scan failed");

	l_genl_msg_unref(msg);
}

void scan_get_results(struct l_genl_family *nl80211, uint32_t ifindex,
			scan_func_t callback, scan_done_func_t scan_done,
			void *user_data)
{
	struct l_genl_msg *msg;

	msg = l_genl_msg_new_sized(NL80211_CMD_GET_SCAN, 8);
	l_genl_msg_append_attr(msg, NL80211_ATTR_IFINDEX, 4, &ifindex);
	l_genl_family_dump(nl80211, msg, callback, user_data, scan_done);
	l_genl_msg_unref(msg);
}

enum scan_ssid_security scan_get_ssid_security(
					enum ie_bss_capability bss_capability,
					const struct ie_rsn_info *info)
{
	if (bss_capability & IE_BSS_CAP_PRIVACY)
		return SCAN_SSID_SECURITY_WEP;

	if (!info)
		return SCAN_SSID_SECURITY_NONE;

	if (info->akm_suites & IE_RSN_AKM_SUITE_PSK ||
			info->akm_suites & IE_RSN_AKM_SUITE_PSK_SHA256 ||
			info->akm_suites & IE_RSN_AKM_SUITE_FT_USING_PSK)
		return SCAN_SSID_SECURITY_PSK;

	return SCAN_SSID_SECURITY_8021X;
}
