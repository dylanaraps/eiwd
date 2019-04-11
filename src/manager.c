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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <linux/if_ether.h>
#include <fnmatch.h>

#include <ell/ell.h>

#include "linux/nl80211.h"

#include "src/iwd.h"
#include "src/wiphy.h"
#include "src/util.h"
#include "src/common.h"

static struct l_genl_family *nl80211 = NULL;

static void manager_new_wiphy_event(struct l_genl_msg *msg)
{
	struct wiphy *wiphy;
	struct l_genl_attr attr;
	uint32_t id;
	const char *name;

	if (!l_genl_attr_init(&attr, msg))
		return;

	if (!wiphy_parse_id_and_name(&attr, &id, &name))
		return;

	wiphy = wiphy_find(id);
	if (wiphy) {
		wiphy_update_from_genl(wiphy, msg);
		return;
	}

	wiphy = wiphy_create(id, name);
	if (!wiphy)	/* Possibly blacklisted */
		return;

	wiphy_update_from_genl(wiphy, msg);
}

static uint32_t manager_parse_wiphy_id(struct l_genl_attr *attr)
{
	uint16_t type, len;
	const void *data;

	while (l_genl_attr_next(attr, &type, &len, &data)) {
		if (type != NL80211_ATTR_WIPHY)
			continue;

		if (len != sizeof(uint32_t))
			break;

		return *((uint32_t *) data);
	}

	return -1;
}

static void manager_del_wiphy_event(struct l_genl_msg *msg)
{
	struct wiphy *wiphy;
	struct l_genl_attr attr;
	uint32_t id;

	if (!l_genl_attr_init(&attr, msg))
		return;

	id = manager_parse_wiphy_id(&attr);

	wiphy = wiphy_find(id);
	if (wiphy)
		wiphy_destroy(wiphy);
}

static void manager_config_notify(struct l_genl_msg *msg, void *user_data)
{
	uint8_t cmd;

	cmd = l_genl_msg_get_command(msg);

	l_debug("Notification of command %u", cmd);

	switch (cmd) {
	case NL80211_CMD_NEW_WIPHY:
		manager_new_wiphy_event(msg);
		break;

	case NL80211_CMD_DEL_WIPHY:
		manager_del_wiphy_event(msg);
		break;
	}
}

static void manager_wiphy_dump_callback(struct l_genl_msg *msg, void *user_data)
{
	l_debug("");

	manager_new_wiphy_event(msg);
}

bool manager_init(struct l_genl_family *in)
{
	nl80211 = in;

	if (!l_genl_family_register(nl80211, "config", manager_config_notify,
					NULL, NULL))
		l_error("Registering for config notifications failed");

	if (!l_genl_family_dump(nl80211,
				l_genl_msg_new(NL80211_CMD_GET_WIPHY),
				manager_wiphy_dump_callback,
				NULL, NULL))
		l_error("Initial wiphy information dump failed");

	return true;
}

void manager_exit(void)
{
	nl80211 = NULL;
}
