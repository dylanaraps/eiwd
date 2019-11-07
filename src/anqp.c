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

#include <stdint.h>

#include <ell/ell.h>

#include "src/module.h"
#include "src/anqp.h"
#include "src/util.h"
#include "src/eap-private.h"
#include "src/ie.h"
#include "src/nl80211util.h"
#include "src/nl80211cmd.h"
#include "src/scan.h"
#include "src/netdev.h"
#include "src/iwd.h"
#include "src/mpdu.h"
#include "src/wiphy.h"

#include "linux/nl80211.h"

struct anqp_request {
	uint32_t ifindex;
	anqp_response_func_t anqp_cb;
	anqp_destroy_func_t anqp_destroy;
	void *anqp_data;
	uint64_t anqp_cookie;
	uint8_t anqp_token;
};

static struct l_genl_family *nl80211 = NULL;

static struct l_queue *anqp_requests;
static uint8_t anqp_token = 0;

static uint32_t netdev_watch;
static uint32_t unicast_watch;

static void anqp_destroy(void *user_data)
{
	struct anqp_request *request = user_data;

	if (request->anqp_destroy)
		request->anqp_destroy(request->anqp_data);
}

static void netdev_gas_request_cb(struct l_genl_msg *msg, void *user_data)
{
	struct anqp_request *request = user_data;

	if (l_genl_msg_get_error(msg) != 0)
		goto error;

	if (nl80211_parse_attrs(msg, NL80211_ATTR_COOKIE, &request->anqp_cookie,
					NL80211_ATTR_UNSPEC) < 0)
		goto error;

	return;

error:
	l_debug("Error sending CMD_FRAME (%d)", l_genl_msg_get_error(msg));

	if (request->anqp_cb)
		request->anqp_cb(ANQP_FAILED, NULL, 0, request->anqp_data);

	if (request->anqp_destroy)
		request->anqp_destroy(request->anqp_data);

	l_free(request);
}

static bool match_token(const void *a, const void *b)
{
	const struct anqp_request *request = a;
	const struct token_match {
		uint32_t ifindex;
		uint8_t token;

	} *match = b;

	if (request->ifindex != match->ifindex)
		return false;

	if (request->anqp_token != match->token)
		return false;

	return true;
}

static void anqp_response_frame_event(uint32_t ifindex,
					const struct mmpdu_header *hdr,
					const void *body, size_t body_len)
{
	struct anqp_request *request;
	const uint8_t *ptr = body;
	uint16_t status_code;
	uint16_t delay;
	uint16_t qrlen;
	uint8_t adv_proto_len;
	uint8_t token;
	struct token_match {
		uint32_t ifindex;
		uint8_t token;

	} match;

	if (body_len < 9)
		return;

	/* Skip past category/action since this frame was prefixed matched */
	ptr += 2;
	body_len -= 2;

	/* dialog token */
	token = *ptr++;

	match.ifindex = ifindex;
	match.token = token;

	request = l_queue_find(anqp_requests, match_token, &match);
	if (!request)
		return;

	status_code = l_get_le16(ptr);
	ptr += 2;
	body_len -= 2;

	if (status_code != 0) {
		l_error("Bad status code on GAS response %u", status_code);
		return;
	}

	delay = l_get_le16(ptr);
	ptr += 2;
	body_len -= 2;

	/*
	 * IEEE 80211-2016 Section 9.6.8.13
	 *
	 * The value 0 will be returned by the STA when a Query Response is
	 * provided in this frame
	 */
	if (delay != 0) {
		l_error("GAS comeback delay was not zero");
		return;
	}

	if (*ptr != IE_TYPE_ADVERTISEMENT_PROTOCOL) {
		l_error("GAS request not advertisement protocol");
		return;
	}

	ptr++;
	body_len--;

	adv_proto_len = *ptr++;
	body_len--;

	if (body_len < adv_proto_len)
		return;

	ptr += adv_proto_len;
	body_len -= adv_proto_len;

	if (body_len < 2)
		return;

	qrlen = l_get_le16(ptr);
	ptr += 2;

	if (body_len < qrlen)
		return;

	l_queue_remove(anqp_requests, request);

	l_debug("ANQP response received from "MAC, MAC_STR(hdr->address_2));

	if (request->anqp_cb)
		request->anqp_cb(ANQP_SUCCESS, ptr, qrlen,
					request->anqp_data);

	if (request->anqp_destroy)
		request->anqp_destroy(request->anqp_data);

	l_free(request);

	return;
}

static void netdev_gas_timeout_cb(void *user_data)
{
	struct anqp_request *request = user_data;

	l_debug("GAS request timed out");

	if (request->anqp_cb)
		request->anqp_cb(ANQP_TIMEOUT, NULL, 0,
					request->anqp_data);

	/* allows anqp_request to be re-entrant */
	if (request->anqp_destroy)
		request->anqp_destroy(request->anqp_data);

	l_queue_remove(anqp_requests, request);
	l_free(request);
}

static bool match_cookie(const void *a, const void *b)
{
	const struct anqp_request *request = a;
	const struct cookie_match {
		uint64_t cookie;
		uint32_t ifindex;
	} *match = b;

	if (match->ifindex != request->ifindex)
		return false;

	if (match->cookie != request->anqp_cookie)
		return false;

	return true;
}

static void anqp_frame_wait_cancel_event(struct l_genl_msg *msg,
						uint32_t ifindex)
{
	uint64_t cookie;
	struct anqp_request *request;
	struct cookie_match {
		uint64_t cookie;
		uint32_t ifindex;
	} match;

	l_debug("");

	if (nl80211_parse_attrs(msg, NL80211_ATTR_COOKIE, &cookie,
					NL80211_ATTR_UNSPEC) < 0)
		return;

	match.cookie = cookie;
	match.ifindex = ifindex;

	request = l_queue_find(anqp_requests, match_cookie, &match);
	if (!request)
		return;

	if (cookie != request->anqp_cookie)
		return;

	netdev_gas_timeout_cb(request);
}

uint32_t anqp_request(uint32_t ifindex, const uint8_t *addr,
				struct scan_bss *bss, const uint8_t *anqp,
				size_t len, anqp_response_func_t cb,
				void *user_data, anqp_destroy_func_t destroy)
{
	struct anqp_request *request;
	uint8_t frame[512];
	struct l_genl_msg *msg;
	struct iovec iov[2];
	uint32_t id;
	uint32_t duration = 300;
	struct netdev *netdev = netdev_find(ifindex);

	if (!netdev)
		return 0;

	/*
	 * TODO: Netdev dependencies will eventually be removed so we need
	 * another way to figure out wiphy capabilities.
	 */
	if (!wiphy_can_offchannel_tx(netdev_get_wiphy(netdev))) {
		l_error("ANQP failed, driver does not support offchannel TX");
		return 0;
	}

	frame[0] = 0x04;		/* Category: Public */
	frame[1] = 0x0a;		/* Action: GAS initial Request */
	frame[2] = anqp_token;		/* Dialog Token */
	frame[3] = IE_TYPE_ADVERTISEMENT_PROTOCOL;
	frame[4] = 2;
	frame[5] = 0x7f;
	frame[6] = IE_ADVERTISEMENT_ANQP;
	l_put_le16(len, frame + 7);

	iov[0].iov_base = frame;
	iov[0].iov_len = 9;
	iov[1].iov_base = (void *)anqp;
	iov[1].iov_len = len;

	request = l_new(struct anqp_request, 1);

	request->ifindex = ifindex;
	request->anqp_cb = cb;
	request->anqp_destroy = destroy;
	request->anqp_token = anqp_token++;
	request->anqp_data = user_data;

	msg = nl80211_build_cmd_frame(ifindex, addr, bss->addr,
					bss->frequency, iov, 2);

	l_genl_msg_append_attr(msg, NL80211_ATTR_OFFCHANNEL_TX_OK, 0, "");
	l_genl_msg_append_attr(msg, NL80211_ATTR_DURATION, 4, &duration);

	id = l_genl_family_send(nl80211, msg, netdev_gas_request_cb,
					request, NULL);

	if (!id) {
		l_debug("Failed to send ANQP request");
		l_genl_msg_unref(msg);
		l_free(request);
		return 0;
	}

	l_debug("ANQP request sent to "MAC, MAC_STR(bss->addr));

	l_queue_push_head(anqp_requests, request);

	return id;
}

static void netdev_frame_cb(struct l_genl_msg *msg, void *user_data)
{
	if (l_genl_msg_get_error(msg) < 0)
		l_error("Could not register frame watch type %04x: %i",
			L_PTR_TO_UINT(user_data), l_genl_msg_get_error(msg));
}

static void anqp_register_frame(uint32_t ifindex)
{
	struct l_genl_msg *msg;
	uint16_t frame_type = 0x00d0;
	uint8_t prefix[] = { 0x04, 0x0b };

	msg = l_genl_msg_new_sized(NL80211_CMD_REGISTER_FRAME, 34);

	l_genl_msg_append_attr(msg, NL80211_ATTR_IFINDEX, 4, &ifindex);
	l_genl_msg_append_attr(msg, NL80211_ATTR_FRAME_TYPE, 2, &frame_type);
	l_genl_msg_append_attr(msg, NL80211_ATTR_FRAME_MATCH,
					sizeof(prefix), prefix);

	l_genl_family_send(nl80211, msg, netdev_frame_cb,
			L_UINT_TO_PTR(frame_type), NULL);
}

static void anqp_netdev_watch(struct netdev *netdev,
				enum netdev_watch_event event, void *user_data)
{
	switch (event) {
	case NETDEV_WATCH_EVENT_NEW:
		anqp_register_frame(netdev_get_ifindex(netdev));
		return;
	default:
		break;
	}
}

static void anqp_unicast_notify(struct l_genl_msg *msg, void *user_data)
{
	const struct mmpdu_header *mpdu = NULL;
	const uint8_t *body;
	struct l_genl_attr attr;
	uint16_t type, len;
	uint16_t frame_len = 0;
	const void *data;
	uint8_t cmd;
	uint32_t ifindex = 0;

	if (l_queue_isempty(anqp_requests))
		return;

	cmd = l_genl_msg_get_command(msg);
	if (!cmd)
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

			ifindex = *((uint32_t *) data);

			break;
		case NL80211_ATTR_FRAME:
			if (mpdu)
				return;

			mpdu = mpdu_validate(data, len);
			if (!mpdu)
				l_error("Frame didn't validate as MMPDU");

			frame_len = len;
			break;
		}
	}

	if (!ifindex || !mpdu)
		return;

	body = mmpdu_body(mpdu);

	anqp_response_frame_event(ifindex, mpdu, body,
				(const uint8_t *) mpdu + frame_len - body);
}

static void anqp_mlme_notify(struct l_genl_msg *msg, void *user_data)
{
	struct l_genl_attr attr;
	uint16_t type, len;
	const void *data;
	uint8_t cmd;
	uint32_t ifindex = 0;

	if (l_queue_isempty(anqp_requests))
		return;

	cmd = l_genl_msg_get_command(msg);

	l_debug("MLME notification %s(%u)", nl80211cmd_to_string(cmd), cmd);

	if (!l_genl_attr_init(&attr, msg))
		return;

	while (l_genl_attr_next(&attr, &type, &len, &data)) {
		switch (type) {
		case NL80211_ATTR_IFINDEX:
			if (len != sizeof(uint32_t)) {
				l_warn("Invalid interface index attribute");
				return;
			}

			ifindex = *((uint32_t *) data);
			break;
		}
	}

	if (!ifindex) {
		l_warn("MLME notification is missing ifindex attribute");
		return;
	}

	switch (cmd) {
	case NL80211_CMD_FRAME_WAIT_CANCEL:
		anqp_frame_wait_cancel_event(msg, ifindex);
		break;
	}
}

static int anqp_init(void)
{
	struct l_genl *genl = iwd_get_genl();

	nl80211 = l_genl_family_new(genl, NL80211_GENL_NAME);

	anqp_requests = l_queue_new();

	netdev_watch =  netdev_watch_add(anqp_netdev_watch, NULL, NULL);

	unicast_watch = l_genl_add_unicast_watch(genl, NL80211_GENL_NAME,
						anqp_unicast_notify,
						NULL, NULL);

	if (!l_genl_family_register(nl80211, "mlme", anqp_mlme_notify,
								NULL, NULL))
		l_error("Registering for MLME notification failed");

	return 0;
}

static void anqp_exit(void)
{
	struct l_genl *genl = iwd_get_genl();

	l_genl_family_free(nl80211);
	nl80211 = NULL;

	l_queue_destroy(anqp_requests, anqp_destroy);

	netdev_watch_remove(netdev_watch);

	l_genl_remove_unicast_watch(genl, unicast_watch);
}

IWD_MODULE(anqp, anqp_init, anqp_exit);
IWD_MODULE_DEPENDS(anqp, netdev);
