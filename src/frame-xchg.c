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
#include <stdarg.h>

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

struct frame_xchg_data {
	uint64_t wdev_id;
	uint32_t freq;
	struct mmpdu_header *tx_mpdu;
	size_t tx_mpdu_len;
	bool tx_acked;
	uint64_t cookie;
	bool have_cookie;
	bool early_status;
	struct {
		struct mmpdu_header *mpdu;
		const void *body;
		size_t body_len;
		int rssi;
	} early_frame;
	struct l_timeout *timeout;
	struct l_queue *rx_watches;
	frame_xchg_cb_t cb;
	void *user_data;
	uint32_t group_id;
	unsigned int retry_cnt;
	unsigned int retry_interval;
	unsigned int resp_timeout;
	bool in_frame_cb : 1;
};

struct frame_xchg_watch_data {
	struct frame_xchg_prefix *prefix;
	frame_xchg_resp_cb_t cb;
};

static struct l_queue *frame_xchgs;
static struct l_genl_family *nl80211;

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
	struct watch_group *group;

	for (entry = l_queue_get_entries(watch_groups); entry;
			entry = entry->next) {
		group = entry->data;

		if (group->id == id && (id == 0 || group->wdev_id == wdev_id))
			return group;
	}

	group = frame_watch_group_new(wdev_id, id);
	l_queue_push_tail(watch_groups, group);
	return group;
}

static void frame_watch_register_cb(struct l_genl_msg *msg, void *user_data)
{
	if (l_genl_msg_get_error(msg) < 0)
		l_error("Could not register frame watch type %04x: %i",
			L_PTR_TO_UINT(user_data), l_genl_msg_get_error(msg));
}

struct frame_duplicate_info {
	uint64_t wdev_id;
	uint16_t frame_type;
	const uint8_t *prefix;
	size_t prefix_len;
	frame_watch_cb_t handler;
	void *user_data;
	bool duplicate : 1;
	bool registered : 1;
};

static bool frame_watch_check_duplicate(void *data, void *user_data)
{
	struct watchlist_item *super = data;
	struct frame_watch *watch =
		l_container_of(super, struct frame_watch, super);
	struct frame_duplicate_info *info = user_data;
	int common_len = info->prefix_len < watch->prefix_len ?
		info->prefix_len : watch->prefix_len;

	if (info->wdev_id != watch->wdev_id ||
			info->frame_type != watch->frame_type ||
			(common_len &&
			 memcmp(info->prefix, watch->prefix, common_len)))
		/* No match */
		return false;

	if (info->prefix_len >= watch->prefix_len)
		/*
		 * A matching shorter prefix is already registered with
		 * the kernel, no need to register the new prefix.
		 */
		info->registered = true;

	if (info->handler != watch->super.notify ||
			info->user_data != watch->super.notify_data)
		return false;

	/*
	 * If we already have a watch with the exact same callback and
	 * user_data and a matching prefix (longer or shorter), drop
	 * either the existing watch, or the new watch, so as to preserve
	 * the set of frames that trigger the callback but avoid
	 * calling back twice with the same user_data.
	 */
	if (info->prefix_len >= watch->prefix_len) {
		info->duplicate = true;
		return false;
	}

	/* Drop the existing watch as a duplicate of the new one */
	return true;
}

bool frame_watch_add(uint64_t wdev_id, uint32_t group_id, uint16_t frame_type,
			const uint8_t *prefix, size_t prefix_len,
			frame_watch_cb_t handler, void *user_data,
			frame_xchg_destroy_func_t destroy)
{
	struct watch_group *group = frame_watch_group_get(wdev_id, group_id);
	struct frame_watch *watch;
	struct l_genl_msg *msg;
	struct frame_duplicate_info info = {
		wdev_id, frame_type, prefix, prefix_len,
		handler, user_data, false, false
	};

	if (!group)
		return false;

	l_queue_foreach_remove(group->watches.items,
				frame_watch_check_duplicate, &info);

	if (info.duplicate)
		return true;

	watch = l_new(struct frame_watch, 1);
	watch->frame_type = frame_type;
	watch->prefix = prefix_len ? l_memdup(prefix, prefix_len) : NULL;
	watch->prefix_len = prefix_len;
	watch->wdev_id = wdev_id;
	watch->group = group;
	watchlist_link(&group->watches, &watch->super, handler, user_data,
			destroy);

	if (info.registered)
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

struct watch_group_match_info {
	uint64_t wdev_id;
	uint32_t id;
};

static bool frame_watch_group_match(const void *a, const void *b)
{
	const struct watch_group *group = a;
	const struct watch_group_match_info *info = b;

	return group->wdev_id == info->wdev_id && group->id == info->id;
}

bool frame_watch_group_remove(uint64_t wdev_id, uint32_t group_id)
{
	struct watch_group_match_info info = { wdev_id, group_id };
	struct watch_group *group = l_queue_remove_if(watch_groups,
						frame_watch_group_match, &info);

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

struct frame_watch_handler_check_info {
	frame_watch_cb_t handler;
	void *user_data;
};

static bool frame_watch_item_remove_by_handler(void *data, void *user_data)
{
	struct frame_watch *watch = data;
	struct frame_watch_handler_check_info *info = user_data;

	if (watch->super.notify != info->handler ||
			watch->super.notify_data != info->user_data)
		return false;

	if (watch->super.destroy)
		watch->super.destroy(watch->super.notify_data);

	frame_watch_free(&watch->super);
	return true;
}

/*
 * Note this one doesn't interact with the kernel watches, only forgets our
 * struct frame_watch instances.
 *
 * Also note empty groups are not automatically destroyed because right now
 * this is not desired in frame_xchg_reset -- the only user of this function.
 */
static bool frame_watch_remove_by_handler(uint64_t wdev_id, uint32_t group_id,
						frame_watch_cb_t handler,
						void *user_data)
{
	struct watch_group_match_info group_info =
		{ wdev_id, group_id };
	struct frame_watch_handler_check_info handler_info =
		{ handler, user_data };
	struct watch_group *group = l_queue_find(watch_groups,
						frame_watch_group_match,
						&group_info);

	if (!group)
		return false;

	return l_queue_foreach_remove(group->watches.items,
					frame_watch_item_remove_by_handler,
					&handler_info) > 0;
}

static void frame_xchg_tx_retry(struct frame_xchg_data *fx);
static void frame_xchg_resp_cb(const struct mmpdu_header *mpdu,
				const void *body, size_t body_len,
				int rssi, void *user_data);

static void frame_xchg_wait_cancel(struct frame_xchg_data *fx)
{
	struct l_genl_msg *msg;

	if (!fx->have_cookie)
		return;

	l_debug("");

	msg = l_genl_msg_new_sized(NL80211_CMD_FRAME_WAIT_CANCEL, 32);
	l_genl_msg_append_attr(msg, NL80211_ATTR_WDEV, 8, &fx->wdev_id);
	l_genl_msg_append_attr(msg, NL80211_ATTR_COOKIE, 8, &fx->cookie);
	l_genl_family_send(nl80211, msg, NULL, NULL, NULL);

	fx->have_cookie = false;
}

static void frame_xchg_reset(struct frame_xchg_data *fx)
{
	fx->in_frame_cb = false;

	frame_xchg_wait_cancel(fx);

	if (fx->timeout)
		l_timeout_remove(fx->timeout);

	l_free(fx->early_frame.mpdu);
	fx->early_frame.mpdu = NULL;
	l_queue_destroy(fx->rx_watches, l_free);
	fx->rx_watches = NULL;
	l_free(fx->tx_mpdu);
	fx->tx_mpdu = NULL;
	frame_watch_remove_by_handler(fx->wdev_id, fx->group_id,
					frame_xchg_resp_cb, fx);
}

static void frame_xchg_destroy(struct frame_xchg_data *fx, int err)
{
	if (fx->cb)
		fx->cb(err, fx->user_data);

	frame_xchg_reset(fx);
	l_free(fx);
}

static void frame_xchg_cancel(void *user_data)
{
	struct frame_xchg_data *fx = user_data;

	frame_xchg_destroy(fx, -ECANCELED);
}

static void frame_xchg_done(struct frame_xchg_data *fx, int err)
{
	l_queue_remove(frame_xchgs, fx);
	frame_xchg_destroy(fx, err);
}

static void frame_xchg_timeout_destroy(void *user_data)
{
	struct frame_xchg_data *fx = user_data;

	fx->timeout = NULL;
}

static void frame_xchg_timeout_cb(struct l_timeout *timeout,
					void *user_data)
{
	struct frame_xchg_data *fx = user_data;

	l_timeout_remove(fx->timeout);
	frame_xchg_tx_retry(fx);
}

static void frame_xchg_resp_timeout_cb(struct l_timeout *timeout,
					void *user_data)
{
	struct frame_xchg_data *fx = user_data;

	frame_xchg_done(fx, 0);
}

static void frame_xchg_tx_status(struct frame_xchg_data *fx, bool acked)
{
	if (!acked) {
		frame_xchg_wait_cancel(fx);

		if (!fx->retry_interval || fx->retry_cnt >= 15) {
			if (!fx->resp_timeout)
				fx->have_cookie = false;

			l_error("Frame tx retry limit reached");
			frame_xchg_done(fx, -ECOMM);
			return;
		}

		l_free(fx->early_frame.mpdu);
		fx->early_frame.mpdu = NULL;
		fx->timeout = l_timeout_create_ms(fx->retry_interval,
						frame_xchg_timeout_cb, fx,
						frame_xchg_timeout_destroy);
		return;
	}

	if (!fx->resp_timeout) {
		/* No listen period to cancel */
		fx->have_cookie = false;
		frame_xchg_done(fx, 0);
		return;
	}

	fx->tx_acked = true;

	/* Process frames received early for strange drivers */
	if (fx->early_frame.mpdu) {
		/* The command is now over so no need to cancel it */
		fx->have_cookie = false;

		l_debug("Processing an early frame");
		frame_xchg_resp_cb(fx->early_frame.mpdu, fx->early_frame.body,
					fx->early_frame.body_len,
					fx->early_frame.rssi, fx);

		frame_xchg_done(fx, 0);
		return;
	}

	/* Txed frame ACKed, listen for response frames */
	fx->timeout = l_timeout_create_ms(fx->resp_timeout,
						frame_xchg_resp_timeout_cb, fx,
						frame_xchg_timeout_destroy);
}

static void frame_xchg_tx_cb(struct l_genl_msg *msg, void *user_data)
{
	struct frame_xchg_data *fx = user_data;
	int error = l_genl_msg_get_error(msg);
	uint64_t cookie;
	bool early_status;

	l_debug("err %i", -error);

	if (error < 0) {
		if (error == -EBUSY) {
			fx->timeout = l_timeout_create_ms(fx->retry_interval,
						frame_xchg_timeout_cb, fx,
						frame_xchg_timeout_destroy);
			return;
		}

		l_error("Frame tx failed: %s (%i)", strerror(-error), -error);
		goto error;
	}

	if (L_WARN_ON(nl80211_parse_attrs(msg, NL80211_ATTR_COOKIE, &cookie,
						NL80211_ATTR_UNSPEC) < 0)) {
		error = -EINVAL;
		goto error;
	}

	early_status = fx->early_status && cookie == fx->cookie;
	fx->tx_acked = early_status && fx->tx_acked;
	fx->have_cookie = true;
	fx->cookie = cookie;

	if (early_status)
		frame_xchg_tx_status(fx, fx->tx_acked);

	return;
error:
	frame_xchg_done(fx, error);
}

static void frame_xchg_tx_retry(struct frame_xchg_data *fx)
{
	struct l_genl_msg *msg;
	uint32_t cmd_id;
	uint32_t duration = fx->resp_timeout;

	/*
	 * TODO: in Station, AP, P2P-Client, GO or Ad-Hoc modes if we're
	 * transmitting the frame on the BSS's operating channel we can skip
	 * NL80211_ATTR_DURATION and we should still receive the frames
	 * without potentially interfering with other operations.
	 *
	 * TODO: we may want to react to NL80211_CMD_CANCEL_REMAIN_ON_CHANNEL
	 * in the group socket's unicast handler.
	 */

	msg = l_genl_msg_new_sized(NL80211_CMD_FRAME, 128 + fx->tx_mpdu_len);
	l_genl_msg_append_attr(msg, NL80211_ATTR_WDEV, 8, &fx->wdev_id);
	l_genl_msg_append_attr(msg, NL80211_ATTR_WIPHY_FREQ, 4, &fx->freq);
	l_genl_msg_append_attr(msg, NL80211_ATTR_OFFCHANNEL_TX_OK, 0, NULL);
	l_genl_msg_append_attr(msg, NL80211_ATTR_TX_NO_CCK_RATE, 0, NULL);
	l_genl_msg_append_attr(msg, NL80211_ATTR_FRAME,
				fx->tx_mpdu_len, fx->tx_mpdu);

	if (duration)
		l_genl_msg_append_attr(msg, NL80211_ATTR_DURATION, 4,
					&duration);

	cmd_id = l_genl_family_send(nl80211, msg, frame_xchg_tx_cb, fx, NULL);
	if (!cmd_id) {
		l_error("Error sending frame");
		l_genl_msg_unref(msg);
		frame_xchg_done(fx, -EIO);
		return;
	}

	fx->tx_acked = false;
	fx->have_cookie = false;
	fx->early_status = false;
	fx->retry_cnt++;
}

static void frame_xchg_resp_cb(const struct mmpdu_header *mpdu,
				const void *body, size_t body_len,
				int rssi, void *user_data)
{
	struct frame_xchg_data *fx = user_data;
	const struct l_queue_entry *entry;
	size_t hdr_len;

	l_debug("");

	if (memcmp(mpdu->address_1, fx->tx_mpdu->address_2, 6))
		return;

	if (memcmp(mpdu->address_2, fx->tx_mpdu->address_1, 6))
		return;

	/*
	 * Is the received frame's BSSID same as the transmitted frame's
	 * BSSID, may have to be moved to the user callback if there are
	 * usages where this is false.  Some drivers (brcmfmac) can't
	 * report the BSSID so check for all-zeros too.
	 */
	if (memcmp(mpdu->address_3, fx->tx_mpdu->address_3, 6) &&
			!util_mem_is_zero(mpdu->address_3, 6))
		return;

	for (entry = l_queue_get_entries(fx->rx_watches);
			entry; entry = entry->next) {
		struct frame_xchg_watch_data *watch = entry->data;
		bool done;

		if (body_len < watch->prefix->len ||
				memcmp(body, watch->prefix->data,
					watch->prefix->len))
			continue;

		if (!fx->tx_acked)
			goto early_frame;

		fx->in_frame_cb = true;
		done = watch->cb(mpdu, body, body_len, rssi, fx->user_data);

		/*
		 * If the callback has started a new frame exchange it will
		 * have reset and taken over the state variables and we need
		 * to just exit without touching anything.
		 */
		if (!fx->in_frame_cb)
			return;

		fx->in_frame_cb = false;

		if (done) {
			fx->cb = NULL;
			frame_xchg_done(fx, 0);
			return;
		}
	}

	return;

early_frame:
	/*
	 * Work around the strange order of events seen with the brcmfmac
	 * driver where we receive the response frames before the frame
	 * Tx status, which in turn is receive before the Tx callback with
	 * the operation cookie... rather then the reverse.
	 * Save the response frame to be processed in the Tx done callback.
	 */
	if (fx->early_frame.mpdu)
		return;

	hdr_len = (const uint8_t *) body - (const uint8_t *) mpdu;
	fx->early_frame.mpdu = l_memdup(mpdu, body_len + hdr_len);
	fx->early_frame.body = (const uint8_t *) fx->early_frame.mpdu + hdr_len;
	fx->early_frame.body_len = body_len;
	fx->early_frame.rssi = rssi;
}

static bool frame_xchg_match(const void *a, const void *b)
{
	const struct frame_xchg_data *fx = a;
	const uint64_t *wdev_id = b;

	return fx->wdev_id == *wdev_id;
}

/*
 * Send an action frame described by @frame.  If @retry_interval is
 * non-zero and we receive no ACK from @peer to any of the retransmissions
 * done in the kernel (at a high rate), retry after @retry_interval
 * milliseconds from the time the kernel gave up.  If no ACK is received
 * after all the retransmissions, call @cb with a non-zero error number.
 * Otherwise, if @resp_timeout is non-zero, remain on the same channel
 * and report any response frames from the frame's destination address
 * that match provided prefixes, to the corresponding callbacks.  Do so
 * for @resp_timeout milliseconds from the ACK receival or until a frame
 * callback returns @true.  Call @cb when @resp_timeout runs out and
 * no frame callback returned @true, or immediately after the ACK if
 * @resp_timeout was 0.  @frame is an iovec array terminated by an iovec
 * struct with NULL-iov_base.
 */
void frame_xchg_startv(uint64_t wdev_id, struct iovec *frame, uint32_t freq,
			unsigned int retry_interval, unsigned int resp_timeout,
			uint32_t group_id, frame_xchg_cb_t cb, void *user_data,
			va_list resp_args)
{
	struct frame_xchg_data *fx;
	size_t frame_len;
	struct iovec *iov;
	uint8_t *ptr;
	struct mmpdu_header *mpdu;

	for (frame_len = 0, iov = frame; iov->iov_base; iov++)
		frame_len += iov->iov_len;

	if (frame_len < sizeof(*mpdu)) {
		l_error("Frame too short");
		cb(-EMSGSIZE, user_data);
		return;
	}

	fx = l_queue_find(frame_xchgs, frame_xchg_match, &wdev_id);

	if (fx) {
		/*
		 * If a frame callback calls us assume it's the end of
		 * that earlier frame exchange and the start of a new one.
		 */
		if (fx->in_frame_cb)
			frame_xchg_reset(fx);
		else {
			l_error("Frame exchange in progress");
			cb(-EBUSY, user_data);
			return;
		}
	} else {
		fx = l_new(struct frame_xchg_data, 1);

		if (!frame_xchgs)
			frame_xchgs = l_queue_new();

		l_queue_push_tail(frame_xchgs, fx);
	}

	fx->wdev_id = wdev_id;
	fx->freq = freq;
	fx->retry_interval = retry_interval;
	fx->resp_timeout = resp_timeout;
	fx->cb = cb;
	fx->user_data = user_data;
	fx->group_id = group_id;

	fx->tx_mpdu = l_malloc(frame_len);
	fx->tx_mpdu_len = frame_len;
	ptr = (uint8_t *) fx->tx_mpdu;

	for (iov = frame; iov->iov_base; ptr += iov->iov_len, iov++)
		memcpy(ptr, iov->iov_base, iov->iov_len);

	/*
	 * Subscribe to the response frames now instead of in the ACK
	 * callback to save ourselves race condition considerations.
	 */
	while (1) {
		struct frame_xchg_prefix *prefix;
		struct frame_xchg_watch_data *watch;

		prefix = va_arg(resp_args, struct frame_xchg_prefix *);
		if (!prefix)
			break;

		watch = l_new(struct frame_xchg_watch_data, 1);
		watch->prefix = prefix;
		watch->cb = va_arg(resp_args, void *);
		frame_watch_add(wdev_id, group_id, 0x00d0,
				prefix->data, prefix->len,
				frame_xchg_resp_cb, fx, NULL);

		if (!fx->rx_watches)
			fx->rx_watches = l_queue_new();

		l_queue_push_tail(fx->rx_watches, watch);
	}

	fx->retry_cnt = 0;
	frame_xchg_tx_retry(fx);
}

void frame_xchg_stop(uint64_t wdev_id)
{
	struct frame_xchg_data *fx =
		l_queue_remove_if(frame_xchgs, frame_xchg_match, &wdev_id);

	if (!fx)
		return;

	frame_xchg_reset(fx);
	l_free(fx);
}

static void frame_xchg_mlme_notify(struct l_genl_msg *msg, void *user_data)
{
	uint64_t wdev_id;
	struct frame_xchg_data *fx;
	uint64_t cookie;
	bool ack;
	uint8_t cmd = l_genl_msg_get_command(msg);

	switch (cmd) {
	case NL80211_CMD_FRAME_TX_STATUS:
		if (nl80211_parse_attrs(msg, NL80211_ATTR_WDEV, &wdev_id,
					NL80211_ATTR_COOKIE, &cookie,
					NL80211_ATTR_ACK, &ack,
					NL80211_ATTR_UNSPEC) < 0)
			return;

		l_debug("Received %s", ack ? "an ACK" : "no ACK");

		fx = l_queue_find(frame_xchgs, frame_xchg_match, &wdev_id);
		if (!fx)
			return;

		if (fx->have_cookie && cookie == fx->cookie && !fx->tx_acked)
			frame_xchg_tx_status(fx, ack);
		else if (!fx->have_cookie && !fx->tx_acked) {
			/*
			 * Save the information about the frame's ACK status
			 * to be processed in frame_xchg_tx_cb if we were
			 * called before it (happens on brcmfmac).
			 */
			fx->tx_acked = ack;
			fx->cookie = cookie;
			fx->early_status = true;
		}

		break;
	}
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

	if (!l_genl_family_register(default_group->nl80211, "mlme",
					frame_xchg_mlme_notify, NULL, NULL)) {
		l_error("Registering for MLME notification failed");
		frame_watch_group_destroy(default_group);
		default_group = NULL;
		return -EIO;
	}

	watch_groups = l_queue_new();
	l_queue_push_tail(watch_groups, default_group);
	nl80211 = default_group->nl80211;

	return 0;
}

static void frame_xchg_exit(void)
{
	l_queue_destroy(watch_groups, frame_watch_group_destroy);
	watch_groups = NULL;
	nl80211 = NULL;

	l_queue_destroy(wdevs, l_free);
	wdevs = NULL;

	l_queue_destroy(frame_xchgs, frame_xchg_cancel);
	frame_xchgs = NULL;
}

IWD_MODULE(frame_xchg, frame_xchg_init, frame_xchg_exit);
