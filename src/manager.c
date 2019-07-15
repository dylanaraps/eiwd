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
#include "src/netdev.h"
#include "src/wiphy.h"
#include "src/util.h"
#include "src/common.h"
#include "src/nl80211cmd.h"

static struct l_genl_family *nl80211 = NULL;
static char **whitelist_filter;
static char **blacklist_filter;
static bool randomize;

struct wiphy_setup_state {
	uint32_t id;
	struct wiphy *wiphy;
	struct l_timeout *setup_timeout;
	unsigned int pending_cmd_count;
	bool aborted;

	/*
	 * Data we may need if the driver does not seem to support interface
	 * manipulation and we fall back to using the driver-created default
	 * interface.
	 */
	bool use_default;
	struct l_genl_msg *default_if_msg;
};

static struct l_queue *pending_wiphys;

/* With these drivers don't even try creating our interfaces */
const char *default_if_driver_list[] = {
	/*
	 * The out-of-tree rtl88x2bu crashes the kernel hard.  Seemingly
	 * many other drivers are built from the same source code so
	 * blacklist all of them.  Unfortunately there are in-tree drivers
	 * that also match these names and may be fine.  Use
	 * use_default_interface to override.
	 */
	"rtl81*",
	"rtl87*",
	"rtl88*",
	"rtw_*",

	NULL,
};

static void wiphy_setup_state_free(void *data)
{
	struct wiphy_setup_state *state = data;

	if (state->setup_timeout)
		l_timeout_remove(state->setup_timeout);

	if (state->default_if_msg)
		l_genl_msg_unref(state->default_if_msg);

	L_WARN_ON(state->pending_cmd_count);
	l_free(state);
}

static void wiphy_setup_state_destroy(struct wiphy_setup_state *state)
{
	l_queue_remove(pending_wiphys, state);
	wiphy_setup_state_free(state);
}

static bool manager_use_default(struct wiphy_setup_state *state)
{
	l_debug("");

	if (!state->default_if_msg) {
		l_error("No default interface for wiphy %u",
			(unsigned int) state->id);
		return false;
	}

	netdev_create_from_genl(state->default_if_msg, randomize);
	return true;
}

static void manager_new_interface_cb(struct l_genl_msg *msg, void *user_data)
{
	struct wiphy_setup_state *state = user_data;

	l_debug("");

	if (state->aborted)
		return;

	if (l_genl_msg_get_error(msg) < 0) {
		l_error("NEW_INTERFACE failed: %s",
			strerror(-l_genl_msg_get_error(msg)));
		/*
		 * Nothing we can do to use this wiphy since by now we
		 * will have successfully deleted any default interface
		 * there may have been.
		 */
		return;
	}

	netdev_create_from_genl(msg, randomize &&
					!wiphy_has_feature(state->wiphy,
						NL80211_FEATURE_MAC_ON_CREATE));
}

static void manager_new_interface_done(void *user_data)
{
	struct wiphy_setup_state *state = user_data;

	state->pending_cmd_count--;
	wiphy_setup_state_destroy(state);
}

static void manager_create_interfaces(struct wiphy_setup_state *state)
{
	struct l_genl_msg *msg;
	char ifname[10];
	uint32_t iftype = NL80211_IFTYPE_STATION;
	unsigned cmd_id;

	if (state->aborted)
		return;

	if (state->use_default) {
		manager_use_default(state);
		return;
	}

	/*
	 * Current policy: we maintain one netdev per wiphy for station,
	 * AP and Ad-Hoc modes, one optional p2p-device and zero or more
	 * p2p-GOs or p2p-clients.  The P2P-related interfaces will be
	 * created on request.
	 */

	/* To be improved */
	snprintf(ifname, sizeof(ifname), "wlan%i", (int) state->id);
	l_debug("creating %s", ifname);

	msg = l_genl_msg_new(NL80211_CMD_NEW_INTERFACE);
	l_genl_msg_append_attr(msg, NL80211_ATTR_WIPHY, 4, &state->id);
	l_genl_msg_append_attr(msg, NL80211_ATTR_IFTYPE, 4, &iftype);
	l_genl_msg_append_attr(msg, NL80211_ATTR_IFNAME,
				strlen(ifname) + 1, ifname);
	l_genl_msg_append_attr(msg, NL80211_ATTR_4ADDR, 1, "\0");
	l_genl_msg_append_attr(msg, NL80211_ATTR_SOCKET_OWNER, 0, "");

	if (randomize && wiphy_has_feature(state->wiphy,
					NL80211_FEATURE_MAC_ON_CREATE)) {
		uint8_t random_addr[6];

		wiphy_generate_random_address(state->wiphy, random_addr);
		l_debug("Creating interface on phy: %s with random addr: "MAC,
						wiphy_get_name(state->wiphy),
						MAC_STR(random_addr));
		l_genl_msg_append_attr(msg, NL80211_ATTR_MAC, 6, random_addr);
	}

	cmd_id = l_genl_family_send(nl80211, msg,
					manager_new_interface_cb, state,
					manager_new_interface_done);

	if (!cmd_id) {
		l_error("Error sending NEW_INTERFACE for %s", ifname);
		return;
	}

	state->pending_cmd_count++;
}

static void manager_setup_cmd_done(void *user_data)
{
	struct wiphy_setup_state *state = user_data;

	state->pending_cmd_count--;

	if (state->pending_cmd_count)
		return;

	manager_create_interfaces(state);

	if (!state->pending_cmd_count)
		wiphy_setup_state_destroy(state);
}

static void manager_del_interface_cb(struct l_genl_msg *msg, void *user_data)
{
	struct wiphy_setup_state *state = user_data;

	l_debug("");

	if (state->aborted)
		return;

	if (l_genl_msg_get_error(msg) < 0) {
		l_error("DEL_INTERFACE failed: %s",
			strerror(-l_genl_msg_get_error(msg)));
		state->use_default = true;
	}
}

static void manager_get_interface_cb(struct l_genl_msg *msg, void *user_data)
{
	struct wiphy_setup_state *state = user_data;
	struct l_genl_attr attr;
	uint16_t type, len;
	const void *data;
	const uint32_t *ifindex = NULL, *iftype = NULL;
	const uint64_t *wdev_idx = NULL;
	const char *ifname = NULL;
	struct l_genl_msg *del_msg;
	unsigned cmd_id;
	char *pattern;
	unsigned int i;
	bool whitelisted = false, blacklisted = false;

	l_debug("");

	if (state->aborted)
		return;

	if (!l_genl_attr_init(&attr, msg))
		return;

	while (l_genl_attr_next(&attr, &type, &len, &data)) {
		switch (type) {
		case NL80211_ATTR_IFINDEX:
			if (len != sizeof(uint32_t)) {
				l_warn("Invalid interface index attribute");
				return;
			}

			ifindex = data;
			break;

		case NL80211_ATTR_WDEV:
			if (len != sizeof(uint64_t)) {
				l_warn("Invalid wdev index attribute");
				return;
			}

			wdev_idx = data;
			break;

		case NL80211_ATTR_WIPHY:
			if (len != sizeof(uint32_t) ||
					*((uint32_t *) data) != state->id) {
				l_warn("Invalid wiphy attribute");
				return;
			}

			break;

		case NL80211_ATTR_IFTYPE:
			if (len != sizeof(uint32_t)) {
				l_warn("Invalid interface type attribute");
				return;
			}

			iftype = data;
			break;

		case NL80211_ATTR_IFNAME:
			if (len < 1 || !memchr(data + 1, 0, len - 1)) {
				l_warn("Invalid interface name attribute");
				return;
			}

			ifname = data;
			break;
		}
	}

	if (!wdev_idx || !iftype)
		return;

	if (ifindex) {
		if (!ifname)
			return;

		if (whitelist_filter) {
			for (i = 0; (pattern = whitelist_filter[i]); i++) {
				if (fnmatch(pattern, ifname, 0) != 0)
					continue;

				whitelisted = true;
				break;
			}
		}

		if (blacklist_filter) {
			for (i = 0; (pattern = blacklist_filter[i]); i++) {
				if (fnmatch(pattern, ifname, 0) != 0)
					continue;

				blacklisted = true;
				break;
			}
		}
	}

	/*
	 * If this interface is usable as our default netdev in case the
	 * driver does not support interface manipulation, save the message
	 * just in case.
	 */
	if ((*iftype == NL80211_IFTYPE_ADHOC ||
				*iftype == NL80211_IFTYPE_STATION ||
				*iftype == NL80211_IFTYPE_AP) &&
			ifindex && *ifindex != 0 &&
			!state->default_if_msg &&
			(!whitelist_filter || whitelisted) &&
			!blacklisted)
		state->default_if_msg = l_genl_msg_ref(msg);

	if (state->use_default)
		return;

	del_msg = l_genl_msg_new(NL80211_CMD_DEL_INTERFACE);

	if (ifindex)
		l_genl_msg_append_attr(del_msg, NL80211_ATTR_IFINDEX, 4, ifindex);

	l_genl_msg_append_attr(del_msg, NL80211_ATTR_WDEV, 8, wdev_idx);
	l_genl_msg_append_attr(del_msg, NL80211_ATTR_WIPHY, 4, &state->id);
	cmd_id = l_genl_family_send(nl80211, del_msg,
					manager_del_interface_cb, state,
					manager_setup_cmd_done);

	if (!cmd_id) {
		l_error("Sending DEL_INTERFACE for %s failed",
			ifname ?: "unnamed interface");
		state->use_default = true;
		return;
	}

	l_debug("");
	state->pending_cmd_count++;
}

static void manager_wiphy_dump_interfaces(struct wiphy_setup_state *state)
{
	struct l_genl_msg *msg;
	unsigned cmd_id;

	if (state->setup_timeout) {
		l_timeout_remove(state->setup_timeout);
		state->setup_timeout = NULL;
	}

	/*
	 * As the first step after new wiphy is detected we will query
	 * the initial interface setup, delete the default interfaces
	 * and create interfaces for our own use with NL80211_ATTR_SOCKET_OWNER
	 * on them.  After that if new interfaces are created outside of
	 * IWD, or removed outside of IWD, we don't touch them and will
	 * try to minimally adapt to handle the removals correctly.  It's
	 * a very unlikely situation in any case but it wouldn't make
	 * sense to try to continually enforce our setup fighting against
	 * some other process, and it wouldn't make sense to try to
	 * manage and use additional interfaces beyond the one or two
	 * we need for our operations.
	 */

	msg = l_genl_msg_new(NL80211_CMD_GET_INTERFACE);
	l_genl_msg_append_attr(msg, NL80211_ATTR_WIPHY, 4, &state->id);
	cmd_id = l_genl_family_dump(nl80211, msg,
					manager_get_interface_cb, state,
					manager_setup_cmd_done);

	if (!cmd_id) {
		l_error("Querying interface information for wiphy %u failed",
			(unsigned int) state->id);
		wiphy_setup_state_destroy(state);
		return;
	}

	l_debug("");
	state->pending_cmd_count++;
}

static struct wiphy_setup_state *manager_rx_cmd_new_wiphy(
							struct l_genl_msg *msg)
{
	struct wiphy_setup_state *state = NULL;
	struct wiphy *wiphy;
	struct l_genl_attr attr;
	uint32_t id;
	const char *name;
	const char *driver, **driver_bad;
	bool use_default;
	const struct l_settings *settings = iwd_get_config();

	if (!l_genl_attr_init(&attr, msg))
		return NULL;

	if (!wiphy_parse_id_and_name(&attr, &id, &name))
		return NULL;

	/*
	 * A Wiphy split dump can generate many (6+) NEW_WIPHY messages
	 * We need to parse attributes from all of them, but only perform
	 * initialization steps once for each new wiphy detected
	 */
	wiphy = wiphy_find(id);
	if (wiphy)
		goto done;

	wiphy = wiphy_create(id, name);
	if (!wiphy)
		return NULL;

	/*
	 * We've got a new wiphy, flag it as new and wait for a
	 * NEW_INTERFACE event for this wiphy's default driver-created
	 * interface.  That event's handler will check the flag and
	 * finish setting up the interfaces for this new wiphy and then
	 * clear the flag.  In some corner cases there may be no
	 * default interface on this wiphy and no user-space created
	 * interfaces from before IWD started, so set a 1-second timeout
	 * for the event.  The timeout pointer is also used as the flag.
	 */

	state = l_new(struct wiphy_setup_state, 1);
	state->id = id;
	state->wiphy = wiphy;
	l_queue_push_tail(pending_wiphys, state);

	driver = wiphy_get_driver(wiphy);

	for (driver_bad = default_if_driver_list; *driver_bad; driver_bad++)
		if (fnmatch(*driver_bad, driver, 0) == 0)
			state->use_default = true;

	/*
	 * If whitelist/blacklist were given only try to use existing
	 * interfaces same as when the driver does not support NEW_INTERFACE
	 * or DEL_INTERFACE, otherwise the interface names will become
	 * meaningless after we've created our own interface(s).  Optimally
	 * phy name white/blacklists should be used.
	 */
	if (whitelist_filter || blacklist_filter)
		state->use_default = true;

	/* The setting overrides our attempts to ensure things work */
	if (l_settings_get_bool(settings, "General",
				"use_default_interface", &use_default))
		state->use_default = use_default;

	if (state->use_default)
		l_info("Wiphy %s will only use the default interface", name);

done:
	wiphy_update_from_genl(wiphy, msg);
	return state;
}

static void manager_wiphy_setup_timeout(struct l_timeout *timeout,
					void *user_data)
{
	struct wiphy_setup_state *state = user_data;

	manager_wiphy_dump_interfaces(state);
}

static void manager_new_wiphy_event(struct l_genl_msg *msg)
{
	struct wiphy_setup_state *state;

	if (!pending_wiphys)
		return;

	state = manager_rx_cmd_new_wiphy(msg);
	if (!state)
		return;

	wiphy_create_complete(state->wiphy);

	/* Setup a timer just in case a default interface is not created */
	state->setup_timeout = l_timeout_create(1, manager_wiphy_setup_timeout,
						state, NULL);
}

static bool manager_wiphy_state_match(const void *a, const void *b)
{
	const struct wiphy_setup_state *state = a;
	uint32_t id = L_PTR_TO_UINT(b);

	return (state->id == id);
}

static struct wiphy_setup_state *manager_find_pending(uint32_t id)
{
	return l_queue_find(pending_wiphys, manager_wiphy_state_match,
				L_UINT_TO_PTR(id));
}

static uint32_t manager_parse_ifindex(struct l_genl_attr *attr)
{
	uint16_t type, len;
	const void *data;

	while (l_genl_attr_next(attr, &type, &len, &data)) {
		if (type != NL80211_ATTR_IFINDEX)
			continue;

		if (len != sizeof(uint32_t))
			break;

		return *((uint32_t *) data);
	}

	return -1;
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
	struct wiphy_setup_state *state;
	struct wiphy *wiphy;
	struct l_genl_attr attr;
	uint32_t id;

	if (!l_genl_attr_init(&attr, msg))
		return;

	id = manager_parse_wiphy_id(&attr);

	state = manager_find_pending(id);
	if (state) {
		if (state->pending_cmd_count)
			state->aborted = true;
		else
			wiphy_setup_state_destroy(state);
	}

	wiphy = wiphy_find(id);
	if (wiphy)
		wiphy_destroy(wiphy);
}

static void manager_config_notify(struct l_genl_msg *msg, void *user_data)
{
	uint8_t cmd;
	struct wiphy_setup_state *state;
	struct l_genl_attr attr;
	struct netdev *netdev;

	cmd = l_genl_msg_get_command(msg);

	l_debug("Notification of command %s(%u)",
					nl80211cmd_to_string(cmd), cmd);

	switch (cmd) {
	case NL80211_CMD_NEW_WIPHY:
		manager_new_wiphy_event(msg);
		break;

	case NL80211_CMD_DEL_WIPHY:
		manager_del_wiphy_event(msg);
		break;

	case NL80211_CMD_NEW_INTERFACE:
		/*
		 * If we have a NEW_INTERFACE for a freshly detected wiphy
		 * assume we can now query for the default or pre-created
		 * interfaces, remove any we don't need and create our own.
		 */
		if (!l_genl_attr_init(&attr, msg))
			break;

		state = manager_find_pending(manager_parse_wiphy_id(&attr));
		if (!state || !state->setup_timeout)
			break;

		manager_wiphy_dump_interfaces(state);
		break;

	case NL80211_CMD_DEL_INTERFACE:
		if (!l_genl_attr_init(&attr, msg))
			break;

		netdev = netdev_find(manager_parse_ifindex(&attr));
		if (!netdev)
			break;

		netdev_destroy(netdev);
		break;
	}
}

static void manager_interface_dump_callback(struct l_genl_msg *msg,
						void *user_data)
{
	struct wiphy_setup_state *state;
	struct l_genl_attr attr;

	l_debug("");

	if (!l_genl_attr_init(&attr, msg))
		return;

	state = manager_find_pending(manager_parse_wiphy_id(&attr));
	if (!state || state->setup_timeout)
		return;

	manager_get_interface_cb(msg, state);
}

static bool manager_check_create_interfaces(const void *a, const void *b)
{
	struct wiphy_setup_state *state = (void *) a;

	/* phy might have been detected after the initial dump */
	if (state->setup_timeout)
		return false;

	wiphy_create_complete(state->wiphy);

	if (state->pending_cmd_count)
		return false;

	/* If we are here, then there are no interfaces for this phy */
	manager_create_interfaces(state);

	if (state->pending_cmd_count)
		return false;

	wiphy_setup_state_free(state);
	return true;
}

static void manager_interface_dump_done(void *user_data)
{
	l_queue_remove_if(pending_wiphys,
				manager_check_create_interfaces, NULL);
}

static void manager_wiphy_dump_callback(struct l_genl_msg *msg, void *user_data)
{
	l_debug("");

	manager_rx_cmd_new_wiphy(msg);
}

bool manager_init(struct l_genl_family *in,
			const char *if_whitelist, const char *if_blacklist)
{
	const struct l_settings *config = iwd_get_config();
	struct l_genl_msg *msg;
	unsigned int wiphy_dump;
	unsigned int interface_dump;
	const char *randomize_str;

	nl80211 = in;

	if (if_whitelist)
		whitelist_filter = l_strsplit(if_whitelist, ',');

	if (if_blacklist)
		blacklist_filter = l_strsplit(if_blacklist, ',');

	pending_wiphys = l_queue_new();

	if (!l_genl_family_register(nl80211, "config", manager_config_notify,
					NULL, NULL)) {
		l_error("Registering for config notifications failed");
		return false;
	}

	msg = l_genl_msg_new(NL80211_CMD_GET_WIPHY);
	wiphy_dump = l_genl_family_dump(nl80211, msg,
						manager_wiphy_dump_callback,
						NULL, NULL);
	if (!wiphy_dump) {
		l_error("Initial wiphy information dump failed");
		l_genl_msg_unref(msg);
		return false;
	}

	msg = l_genl_msg_new(NL80211_CMD_GET_INTERFACE);
	interface_dump = l_genl_family_dump(nl80211, msg,
						manager_interface_dump_callback,
						NULL,
						manager_interface_dump_done);
	if (!interface_dump) {
		l_error("Initial interface information dump failed");
		l_genl_msg_unref(msg);
		l_genl_family_cancel(nl80211, wiphy_dump);
		return false;
	}

	randomize_str =
		l_settings_get_value(config, "General", "mac_randomize");
	if (randomize_str && !strcmp(randomize_str, "once"))
		randomize = true;

	return true;
}

void manager_exit(void)
{
	l_strfreev(whitelist_filter);
	l_strfreev(blacklist_filter);

	l_queue_destroy(pending_wiphys, wiphy_setup_state_free);
	pending_wiphys = NULL;

	nl80211 = NULL;
	randomize = false;
}
