/*
 *
 *  Wireless daemon for Linux
 *
 *  Copyright (C) 2020  Intel Corporation. All rights reserved.
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

#include "linux/nl80211.h"

#include "src/iwd.h"
#include "src/module.h"
#include "src/mpdu.h"
#include "src/util.h"
#include "src/watchlist.h"
#include "src/nl80211util.h"
#include "src/netdev.h"
#include "src/frame-xchg.h"

struct watch_group {
	/*
	 * Group IDs, except 0, are per wdev for user's convenience.
	 * I.e. group 1 can be used for P2P discovery and be removed as
	 * soon as the scan is over on a given device without interfering
	 * with scans on other devices.  This means a module can name
	 * all the groups it's going to need in a static enum.
	 * Group 0 is the default group and uses the iwd_get_genl() netlink
	 * socket shared with all its other users, meaning that it can not
	 * be closed through the watch API.  It is to be used for watches
	 * that don't need to be unregistered before the virtual interface
	 * type change or destruction, which are the two events that
	 * implicitly unregister all existing watches.
	 */
	uint32_t id;
	uint64_t wdev_id;
	uint32_t unicast_watch_id;
	struct l_genl *genl;
	struct l_genl_family *nl80211;
	struct watchlist watches;
};

struct frame_watch {
	uint64_t wdev_id;
	uint16_t frame_type;
	uint8_t *prefix;
	size_t prefix_len;
	struct watch_group *group;
	struct watchlist_item super;
};

static struct l_queue *watch_groups;

struct wdev_info {
	uint64_t id;
	uint32_t iftype;
};

static struct l_queue *wdevs;

struct frame_prefix_info {
	uint16_t frame_type;
	const uint8_t *body;
	size_t body_len;
	uint64_t wdev_id;
};

static bool frame_watch_match_prefix(const void *a, const void *b)
{
	const struct watchlist_item *item = a;
	const struct frame_watch *watch =
		l_container_of(item, struct frame_watch, super);
	const struct frame_prefix_info *info = b;

	return watch->frame_type == info->frame_type &&
		watch->prefix_len <= info->body_len &&
		(watch->prefix_len == 0 ||
		 !memcmp(watch->prefix, info->body, watch->prefix_len)) &&
		info->wdev_id == watch->wdev_id;
}

static void frame_watch_unicast_notify(struct l_genl_msg *msg, void *user_data)
{
	struct watch_group *group = user_data;
	const uint64_t *wdev_id = NULL;
	const uint32_t *ifindex = NULL;
	struct l_genl_attr attr;
	uint16_t type, len, frame_len;
	const void *data;
	const struct mmpdu_header *mpdu = NULL;
	const uint8_t *body;
	struct frame_prefix_info info;
	int rssi = 0;	/* No-RSSI flag value */

	if (l_genl_msg_get_command(msg) != NL80211_CMD_FRAME)
		return;

	if (!l_genl_attr_init(&attr, msg))
		return;

	while (l_genl_attr_next(&attr, &type, &len, &data)) {
		switch (type) {
		case NL80211_ATTR_WDEV:
			if (len != 8)
				break;

			wdev_id = data;
			break;

		case NL80211_ATTR_IFINDEX:
			if (len != 4)
				break;

			ifindex = data;
			break;

		case NL80211_ATTR_FRAME:
			mpdu = mpdu_validate(data, len);
			if (!mpdu) {
				l_warn("Frame didn't validate as MMPDU");
				return;
			}

			frame_len = len;
			break;

		case NL80211_ATTR_RX_SIGNAL_DBM:
			if (len != 4)
				break;

			rssi = *(const int32_t *) data;
		}
	}

	if (!wdev_id || (group->wdev_id && group->wdev_id != *wdev_id)) {
		l_warn("Bad wdev attribute");
		return;
	}

	if (!mpdu) {
		l_warn("Missing frame data");
		return;
	}

	body = mmpdu_body(mpdu);

	if (ifindex) {
		struct netdev *netdev = netdev_find(*ifindex);

		if (netdev && memcmp(mpdu->address_1,
					netdev_get_address(netdev), 6) &&
				!util_is_broadcast_address(mpdu->address_1))
			return;
	}

	/* Only match the frame type and subtype like the kernel does */
#define FC_FTYPE_STYPE_MASK 0x00fc
	info.frame_type = l_get_le16(mpdu) & FC_FTYPE_STYPE_MASK;
	info.body = (const uint8_t *) body;
	info.body_len = (const uint8_t *) mpdu + frame_len - body;
	info.wdev_id = *wdev_id;

	WATCHLIST_NOTIFY_MATCHES(&group->watches, frame_watch_match_prefix,
					&info, frame_watch_cb_t, mpdu,
					info.body, info.body_len, rssi);
}

static void frame_watch_group_destroy(void *data)
{
	struct watch_group *group = data;

	if (group->unicast_watch_id)
		l_genl_remove_unicast_watch(group->genl,
						group->unicast_watch_id);

	if (group->genl)
		l_genl_unref(group->genl);

	if (group->nl80211)
		l_genl_family_free(group->nl80211);

	watchlist_destroy(&group->watches);
	l_free(group);
}

static void frame_watch_free(struct watchlist_item *item)
{
	struct frame_watch *watch =
		l_container_of(item, struct frame_watch, super);

	l_free(watch->prefix);
	l_free(watch);
}

static const struct watchlist_ops frame_watch_ops = {
	.item_free = frame_watch_free,
};

static struct watch_group *frame_watch_group_new(uint64_t wdev_id, uint32_t id)
{
	struct watch_group *group = l_new(struct watch_group, 1);

	group->id = id;
	group->wdev_id = wdev_id;
	watchlist_init(&group->watches, &frame_watch_ops);

	if (id == 0)
		group->genl = l_genl_ref(iwd_get_genl());
	else {
		group->genl = l_genl_new();
		if (!group->genl)
			goto err;
	}

	group->unicast_watch_id = l_genl_add_unicast_watch(group->genl,
						NL80211_GENL_NAME,
						frame_watch_unicast_notify,
						group, NULL);
	if (!group->unicast_watch_id) {
		l_error("Registering for unicast notification failed");
		goto err;
	}

	group->nl80211 = l_genl_family_new(group->genl, NL80211_GENL_NAME);
	if (!group->nl80211) {
		l_error("Failed to obtain nl80211");
		goto err;
	}

	return group;

err:
	frame_watch_group_destroy(group);
	return NULL;
}

static struct watch_group *frame_watch_group_get(uint64_t wdev_id, uint32_t id)
{
	const struct l_queue_entry *entry;

	for (entry = l_queue_get_entries(watch_groups); entry;
			entry = entry->next) {
		struct watch_group *group = entry->data;

		if (group->id == id && (id == 0 || group->wdev_id == wdev_id))
			return group;
	}

	return frame_watch_group_new(wdev_id, id);
}

static void frame_watch_register_cb(struct l_genl_msg *msg, void *user_data)
{
	if (l_genl_msg_get_error(msg) < 0)
		l_error("Could not register frame watch type %04x: %i",
			L_PTR_TO_UINT(user_data), l_genl_msg_get_error(msg));
}

bool frame_watch_add(uint64_t wdev_id, uint32_t group_id, uint16_t frame_type,
			const uint8_t *prefix, size_t prefix_len,
			frame_watch_cb_t handler, void *user_data,
			frame_xchg_destroy_func_t destroy)
{
	struct watch_group *group = frame_watch_group_get(wdev_id, group_id);
	struct frame_watch *watch;
	struct l_genl_msg *msg;
	struct frame_prefix_info info = { frame_type, prefix, prefix_len, wdev_id };
	bool registered;

	if (!group)
		return false;

	registered = l_queue_find(group->watches.items,
					frame_watch_match_prefix,
					&info);

	watch = l_new(struct frame_watch, 1);
	watch->frame_type = frame_type;
	watch->prefix = prefix_len ? l_memdup(prefix, prefix_len) : NULL;
	watch->prefix_len = prefix_len;
	watch->wdev_id = wdev_id;
	watch->group = group;
	watchlist_link(&group->watches, &watch->super, handler, user_data,
			destroy);

	if (registered)
		return true;

	msg = l_genl_msg_new_sized(NL80211_CMD_REGISTER_FRAME, 32 + prefix_len);

	l_genl_msg_append_attr(msg, NL80211_ATTR_WDEV, 8, &wdev_id);
	l_genl_msg_append_attr(msg, NL80211_ATTR_FRAME_TYPE, 2, &frame_type);
	l_genl_msg_append_attr(msg, NL80211_ATTR_FRAME_MATCH,
				prefix_len, prefix);

	l_genl_family_send(group->nl80211, msg, frame_watch_register_cb,
				L_UINT_TO_PTR(frame_type), NULL);

	return true;
}

static bool frame_watch_group_match(const void *a, const void *b)
{
	const struct watch_group *group = a;
	uint32_t id = L_PTR_TO_UINT(b);

	return group->id == id;
}

bool frame_watch_group_remove(uint64_t wdev_id, uint32_t group_id)
{
	struct watch_group *group = l_queue_remove_if(watch_groups,
						frame_watch_group_match,
						L_UINT_TO_PTR(group_id));

	if (!group)
		return false;

	frame_watch_group_destroy(group);
	return true;
}

static bool frame_watch_item_remove_wdev(void *data, void *user_data)
{
	struct frame_watch *watch =
		l_container_of(data, struct frame_watch, super);
	const uint64_t *wdev_id = user_data;

	if (watch->wdev_id != *wdev_id)
		return false;

	if (watch->super.destroy)
		watch->super.destroy(watch->super.notify_data);

	frame_watch_free(&watch->super);
	return true;
}

static bool frame_watch_group_remove_wdev(void *data, void *user_data)
{
	struct watch_group *group = data;
	const uint64_t *wdev_id = user_data;

	if (group->wdev_id == *wdev_id) {
		frame_watch_group_destroy(group);
		return true;
	}

	if (group->id != 0)
		return false;

	/*
	 * Have to be careful here because we're messing with watchlist
	 * internals.
	 */
	l_queue_foreach_remove(group->watches.items,
				frame_watch_item_remove_wdev, user_data);
	return false;
}

bool frame_watch_wdev_remove(uint64_t wdev_id)
{
	return l_queue_foreach_remove(watch_groups, frame_watch_group_remove_wdev,
					&wdev_id) > 0;
}

static bool frame_xchg_wdev_match(const void *a, const void *b)
{
	const struct wdev_info *wdev = a;
	const uint64_t *id = b;

	return wdev->id == *id;
}

static void frame_xchg_config_notify(struct l_genl_msg *msg, void *user_data)
{
	uint64_t wdev_id;
	uint32_t iftype;
	struct wdev_info *wdev;

	switch (l_genl_msg_get_command(msg)) {
	case NL80211_CMD_NEW_INTERFACE:
	case NL80211_CMD_SET_INTERFACE:
		if (nl80211_parse_attrs(msg, NL80211_ATTR_WDEV, &wdev_id,
					NL80211_ATTR_IFTYPE, &iftype,
					NL80211_ATTR_UNSPEC) < 0)
			break;

		wdev = l_queue_find(wdevs, frame_xchg_wdev_match, &wdev_id);

		if (!wdev) {
			wdev = l_new(struct wdev_info, 1);
			wdev->id = wdev_id;
			wdev->iftype = iftype;

			if (!wdevs)
				wdevs = l_queue_new();

			l_queue_push_tail(wdevs, wdev);
			break;
		}

		if (wdev->iftype != iftype) {
			wdev->iftype = iftype;
			frame_watch_wdev_remove(wdev_id);
		}

		break;

	case NL80211_CMD_DEL_INTERFACE:
		if (nl80211_parse_attrs(msg, NL80211_ATTR_WDEV, &wdev_id,
					NL80211_ATTR_UNSPEC) < 0)
			break;

		wdev = l_queue_remove_if(wdevs, frame_xchg_wdev_match, &wdev_id);
		if (!wdev)
			break;

		l_free(wdev);
		frame_watch_wdev_remove(wdev_id);
		break;
	}
}

static int frame_xchg_init(void)
{
	struct watch_group *default_group = frame_watch_group_new(0, 0);

	if (!default_group)
		return -EIO;

	if (!l_genl_family_register(default_group->nl80211, "config",
					frame_xchg_config_notify,
					NULL, NULL)) {
		l_error("Registering for config notifications failed");
		frame_watch_group_destroy(default_group);
		default_group = NULL;
		return -EIO;
	}

	watch_groups = l_queue_new();
	l_queue_push_tail(watch_groups, default_group);

	return 0;
}

static void frame_xchg_exit(void)
{
	l_queue_destroy(watch_groups, frame_watch_group_destroy);
	watch_groups = NULL;

	l_queue_destroy(wdevs, l_free);
	wdevs = NULL;
}

IWD_MODULE(frame_xchg, frame_xchg_init, frame_xchg_exit);
