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

#include <stdlib.h>
#include <linux/rtnetlink.h>
#include <linux/if_ether.h>
#include <unistd.h>
#include <limits.h>
#include <stdio.h>
#include <time.h>
#include <errno.h>

#include <ell/ell.h>

#include "linux/nl80211.h"

#include "src/iwd.h"
#include "src/wiphy.h"
#include "src/scan.h"
#include "src/p2putil.h"
#include "src/ie.h"
#include "src/util.h"
#include "src/dbus.h"
#include "src/netdev.h"
#include "src/mpdu.h"
#include "src/common.h"
#include "src/wsc.h"
#include "src/handshake.h"
#include "src/crypto.h"
#include "src/module.h"
#include "src/frame-xchg.h"
#include "src/nl80211util.h"
#include "src/p2p.h"

struct p2p_device {
	uint64_t wdev_id;
	uint8_t addr[6];
	struct l_genl_family *nl80211;
	struct wiphy *wiphy;
	unsigned int connections_left;
	struct p2p_capability_attr capability;
	struct p2p_device_info_attr device_info;
	uint32_t start_stop_cmd_id;
	l_dbus_property_complete_cb_t pending_complete;
	struct l_dbus_message *pending_message;

	uint8_t listen_country[3];
	uint8_t listen_oper_class;
	uint32_t listen_channel;
	unsigned int scan_interval;
	time_t next_scan_ts;
	struct l_timeout *scan_timeout;
	uint32_t scan_id;
	unsigned int chans_per_scan;
	unsigned int scan_chan_idx;
	uint64_t roc_cookie;
	unsigned int listen_duration;
	struct l_queue *discovery_users;
	struct l_queue *peer_list;

	struct p2p_peer *conn_peer;
	uint16_t conn_config_method;
	char *conn_pin;
	uint8_t conn_addr[6];
	uint16_t conn_password_id;

	bool enabled : 1;
	bool have_roc_cookie : 1;
};

struct p2p_discovery_user {
	char *client;
	struct p2p_device *dev;
	unsigned int disconnect_watch;
};

struct p2p_peer {
	struct scan_bss *bss;
	struct p2p_device *dev;
	struct wsc_dbus wsc;
	char *name;
	struct wsc_primary_device_type primary_device_type;
	const uint8_t *device_addr;
	/* Whether peer is currently a GO */
	bool group;
};

static struct l_queue *p2p_device_list;

/*
 * For now we only scan the common 2.4GHz channels, to be replaced with
 * a query of actual allowed channels per band and reg-domain.
 */
static const int channels_social[] = { 1, 6, 11 };
static const int channels_scan_2_4_other[] = { 2, 3, 4, 5, 7, 8, 9, 10 };

enum {
	FRAME_GROUP_DEFAULT = 0,
	FRAME_GROUP_LISTEN,
	FRAME_GROUP_CONNECT,
};

static bool p2p_device_match(const void *a, const void *b)
{
	const struct p2p_device *dev = a;
	const uint64_t *wdev_id = b;

	return dev->wdev_id == *wdev_id;
}

struct p2p_device *p2p_device_find(uint64_t wdev_id)
{
	return l_queue_find(p2p_device_list, p2p_device_match, &wdev_id);
}

static const char *p2p_device_get_path(const struct p2p_device *dev)
{
	return wiphy_get_path(dev->wiphy);
}

static bool p2p_discovery_user_match(const void *a, const void *b)
{
	const struct p2p_discovery_user *user = a;

	return !strcmp(user->client, b);
}

static void p2p_discovery_user_free(void *data)
{
	struct p2p_discovery_user *user = data;

	if (user->disconnect_watch)
		l_dbus_remove_watch(dbus_get_bus(), user->disconnect_watch);

	l_free(user->client);
	l_free(user);
}

static bool p2p_peer_match(const void *a, const void *b)
{
	const struct p2p_peer *peer = a;
	const uint8_t *addr = b;

	return !memcmp(peer->bss->addr, addr, 6);
}

static const char *p2p_peer_get_path(const struct p2p_peer *peer)
{
	static char path[256];

	snprintf(path, sizeof(path),
			"%s/p2p_peers/%02x_%02x_%02x_%02x_%02x_%02x",
			p2p_device_get_path(peer->dev),
			peer->bss->addr[0], peer->bss->addr[1],
			peer->bss->addr[2], peer->bss->addr[3],
			peer->bss->addr[4], peer->bss->addr[5]);
	return path;
}

static void p2p_peer_free(void *user_data)
{
	struct p2p_peer *peer = user_data;

	scan_bss_free(peer->bss);
	l_free(peer->name);
	l_free(peer);
}

static void p2p_peer_put(void *user_data)
{
	struct p2p_peer *peer = user_data;

	/* Removes both interfaces, no need to call wsc_dbus_remove_interface */
	l_dbus_unregister_object(dbus_get_bus(), p2p_peer_get_path(peer));
	p2p_peer_free(peer);
}

static void p2p_device_discovery_start(struct p2p_device *dev);
static void p2p_device_discovery_stop(struct p2p_device *dev);

/* TODO: convert to iovecs */
static uint8_t *p2p_build_scan_ies(struct p2p_device *dev, uint8_t *buf,
					size_t buf_len, size_t *out_len)
{
	struct p2p_probe_req p2p_info = {};
	struct wsc_probe_request wsc_info = {};
	L_AUTO_FREE_VAR(uint8_t *, p2p_ie) = NULL;
	size_t p2p_ie_size;
	uint8_t *wsc_data;
	size_t wsc_data_size;
	L_AUTO_FREE_VAR(uint8_t *, wsc_ie) = NULL;
	size_t wsc_ie_size;

	p2p_info.capability = dev->capability;
	memcpy(p2p_info.listen_channel.country, dev->listen_country, 3);
	p2p_info.listen_channel.oper_class = dev->listen_oper_class;
	p2p_info.listen_channel.channel_num = dev->listen_channel;

	/*
	 * Note that through an attribute we can also request Group Owners
	 * to send us info on clients within their groups and could also
	 * show those on D-Bus.  Doesn't seem useful at this time but may
	 * be desired at some point.
	 */

	p2p_ie = p2p_build_probe_req(&p2p_info, &p2p_ie_size);
	if (!p2p_ie)
		return NULL;

	wsc_info.version2 = true;
	wsc_info.request_type = WSC_REQUEST_TYPE_ENROLLEE_INFO;
	wsc_info.config_methods = dev->device_info.wsc_config_methods;

	if (!wsc_uuid_from_addr(dev->addr, wsc_info.uuid_e))
		return NULL;

	wsc_info.primary_device_type = dev->device_info.primary_device_type;
	wsc_info.rf_bands = WSC_RF_BAND_2_4_GHZ;
	wsc_info.association_state = WSC_ASSOCIATION_STATE_NOT_ASSOCIATED;
	wsc_info.configuration_error = WSC_CONFIGURATION_ERROR_NO_ERROR;
	wsc_info.device_password_id = WSC_DEVICE_PASSWORD_ID_DEFAULT;
	l_strlcpy(wsc_info.device_name, dev->device_info.device_name,
			sizeof(wsc_info.device_name));

	wsc_data = wsc_build_probe_request(&wsc_info, &wsc_data_size);
	if (!wsc_data)
		return NULL;

	wsc_ie = ie_tlv_encapsulate_wsc_payload(wsc_data, wsc_data_size,
						&wsc_ie_size);
	l_free(wsc_data);

	if (!wsc_ie)
		return NULL;

	/* WFD and other service IEs go here */

	if (buf_len < wsc_ie_size + p2p_ie_size)
		return NULL;

	memcpy(buf + 0, wsc_ie, wsc_ie_size);
	memcpy(buf + wsc_ie_size, p2p_ie, p2p_ie_size);
	*out_len = wsc_ie_size + p2p_ie_size;
	return buf;
}

static void p2p_connection_reset(struct p2p_device *dev)
{
	struct p2p_peer *peer = dev->conn_peer;

	if (!peer)
		return;

	/*
	 * conn_peer is currently not refcounted and we make sure it's always
	 * on the dev->peer_list so we can just drop our reference.  Since we
	 * may not have been scanning for a while, don't drop the peer object
	 * now just because it's not been seen in scan results recently, its
	 * age will be checked on the next scan.
	 */
	dev->conn_peer = NULL;
	dev->connections_left++;

	if (dev->conn_pin) {
		explicit_bzero(dev->conn_pin, strlen(dev->conn_pin));
		l_free(dev->conn_pin);
		dev->conn_pin = NULL;
	}

	l_dbus_property_changed(dbus_get_bus(), p2p_device_get_path(dev),
				IWD_P2P_INTERFACE, "AvailableConnections");

	frame_watch_group_remove(dev->wdev_id, FRAME_GROUP_CONNECT);
	frame_xchg_stop(dev->wdev_id);

	if (!dev->enabled || (dev->enabled && dev->start_stop_cmd_id)) {
		/*
		 * The device has been disabled in the mean time, all peers
		 * have been removed except this one.  Now it's safe to
		 * drop this peer from the scan results too.
		 */
		l_queue_destroy(dev->peer_list, p2p_peer_put);
		dev->peer_list = NULL;
	}

	if (dev->enabled && !dev->start_stop_cmd_id &&
			!l_queue_isempty(dev->discovery_users))
		p2p_device_discovery_start(dev);
}

static void p2p_connect_failed(struct p2p_device *dev)
{
	struct p2p_peer *peer = dev->conn_peer;

	if (!peer)
		return;

	if (peer->wsc.pending_connect)
		dbus_pending_reply(&peer->wsc.pending_connect,
				dbus_error_failed(peer->wsc.pending_connect));

	p2p_connection_reset(dev);
}

static void p2p_peer_frame_xchg(struct p2p_peer *peer, struct iovec *tx_body,
				const uint8_t *bssid,
				unsigned int retry_interval,
				unsigned int resp_timeout,
				unsigned int retries_on_ack, bool own_channel,
				uint32_t group_id, frame_xchg_cb_t cb, ...)
{
	struct p2p_device *dev = peer->dev;
	struct iovec *frame;
	const struct iovec *iov;
	struct mmpdu_header *header;
	uint8_t header_buf[32] __attribute__ ((aligned));
	int iov_cnt;
	uint32_t freq;
	va_list args;

	/* Header */
	memset(header_buf, 0, sizeof(header_buf));
	header = (void *) header_buf;
	header->fc.protocol_version = 0;
	header->fc.type = MPDU_TYPE_MANAGEMENT;
	header->fc.subtype = MPDU_MANAGEMENT_SUBTYPE_ACTION;
	/* Section 2.4.3 */
	memcpy(header->address_1, peer->device_addr, 6);	/* DA */
	memcpy(header->address_2, dev->addr, 6);		/* SA */
	memcpy(header->address_3, bssid, 6);			/* BSSID */

	for (iov = tx_body, iov_cnt = 0; iov->iov_base; iov++)
		iov_cnt++;

	frame = l_new(struct iovec, iov_cnt + 2);
	frame[0].iov_base = header_buf;
	frame[0].iov_len = (const uint8_t *) mmpdu_body(header) - header_buf;
	memcpy(frame + 1, tx_body, sizeof(struct iovec) * iov_cnt);

	freq = own_channel ?
		scan_channel_to_freq(dev->listen_channel, SCAN_BAND_2_4_GHZ) :
		peer->bss->frequency;

	va_start(args, cb);
	frame_xchg_startv(dev->wdev_id, frame, freq, retry_interval,
				resp_timeout, retries_on_ack, group_id,
				cb, dev, args);
	va_end(args);

	l_free(frame);
}

static const struct frame_xchg_prefix p2p_frame_go_neg_resp = {
	/* Management -> Public Action -> P2P -> GO Negotiation Response */
	.data = (uint8_t []) {
		0x04, 0x09, 0x50, 0x6f, 0x9a, 0x09,
		P2P_ACTION_GO_NEGOTIATION_RESP
	},
	.len = 7,
};

static void p2p_scan_destroy(void *user_data)
{
	struct p2p_device *dev = user_data;

	dev->scan_id = 0;
}

/*
 * It seems that sending more than about 42 channels in a frame's Channel
 * List attribute will baffle some devices enough that they will ignore
 * the frame.
 */
#define MAX_CHANNELS 40

static void p2p_add_freq_func(uint32_t freq, void *user_data)
{
	struct p2p_channel_entries *channel_entry = user_data;
	uint8_t channel;
	enum scan_band band;

	if (channel_entry->n_channels >= MAX_CHANNELS)
		return;

	channel = scan_freq_to_channel(freq, &band);

	if (band != scan_oper_class_to_band((const uint8_t *) "XX\x4",
						channel_entry->oper_class))
		return;

	channel_entry->channels[channel_entry->n_channels++] = channel;
}

static void p2p_device_fill_channel_list(struct p2p_device *dev,
					struct p2p_channel_list_attr *attr)
{
	struct p2p_channel_entries *channel_entry;
	unsigned int total_channels;

	memcpy(attr->country, dev->listen_country, 3);
	attr->channel_entries = l_queue_new();

	channel_entry = l_malloc(sizeof(struct p2p_channel_entries) +
					MAX_CHANNELS);
	channel_entry->oper_class = 81;
	channel_entry->n_channels = 0;
	scan_freq_set_foreach(wiphy_get_supported_freqs(dev->wiphy),
				p2p_add_freq_func, channel_entry);
	l_queue_push_tail(attr->channel_entries, channel_entry);
	total_channels = channel_entry->n_channels;

	if (total_channels >= MAX_CHANNELS)
		return;

	channel_entry = l_malloc(sizeof(struct p2p_channel_entries) +
					MAX_CHANNELS);
	channel_entry->oper_class = 115;
	channel_entry->n_channels = 0;
	scan_freq_set_foreach(wiphy_get_supported_freqs(dev->wiphy),
				p2p_add_freq_func, channel_entry);

	if (total_channels + channel_entry->n_channels > MAX_CHANNELS)
		channel_entry->n_channels = MAX_CHANNELS - total_channels;

	l_queue_push_tail(attr->channel_entries, channel_entry);
}

static bool p2p_go_negotiation_resp_cb(const struct mmpdu_header *mpdu,
					const void *body, size_t body_len,
					int rssi, struct p2p_device *dev)
{
	/* TODO: handle the GO Negotiation Response frame */
	return false;
}

static void p2p_go_negotiation_req_done(int error, void *user_data)
{
	struct p2p_device *dev = user_data;

	if (error)
		l_error("Sending the GO Negotiation Req failed: %s (%i)",
			strerror(-error), -error);
	else
		l_error("No GO Negotiation Response after Request ACKed");

	p2p_connect_failed(dev);
}

static void p2p_start_go_negotiation(struct p2p_device *dev)
{
	struct p2p_go_negotiation_req info = {};
	uint8_t *req_body;
	size_t req_len;
	struct iovec iov[16];
	int iov_len = 0;
	/*
	 * Devices should respond within 100ms but times of ~400ms are
	 * often seen instead.
	 *
	 * 3.1.4.2: "The P2P Device that sent the Group Owner Negotiation
	 * frame shall assume that Group Owner Negotiation failed and is
	 * complete if it does not receive the next frame in the exchange
	 * within 100 milliseconds of receiving an acknowledgement frame."
	 */
	unsigned int resp_timeout = 600;

	info.dialog_token = 1;
	info.capability = dev->capability;
	info.go_intent = 0;	/* Don't want to be the GO */
	info.go_tie_breaker = 0;
	info.config_timeout.go_config_timeout = 50;	/* 500ms */
	info.config_timeout.client_config_timeout = 50;	/* 500ms */
	memcpy(info.listen_channel.country, dev->listen_country, 3);
	info.listen_channel.oper_class = dev->listen_oper_class;
	info.listen_channel.channel_num = dev->listen_channel;
	memcpy(info.intended_interface_addr, dev->conn_addr, 6);

	/*
	 * In theory we support an empty set of operating channels for
	 * our potential group as a GO but we have to include our
	 * supported channels because the peer can only choose their
	 * own channels from our list.  Use the listen channel as the
	 * preferred operating channel because we have no preference.
	 */
	p2p_device_fill_channel_list(dev, &info.channel_list);
	memcpy(info.operating_channel.country, dev->listen_country, 3);
	info.operating_channel.oper_class = dev->listen_oper_class;
	info.operating_channel.channel_num = dev->listen_channel;
	info.device_info = dev->device_info;
	info.device_password_id = dev->conn_password_id;

	req_body = p2p_build_go_negotiation_req(&info, &req_len);
	p2p_clear_go_negotiation_req(&info);

	if (!req_body) {
		p2p_connect_failed(dev);
		return;
	}

	iov[iov_len].iov_base = req_body;
	iov[iov_len].iov_len = req_len;
	iov_len++;

	/* WFD and other service IEs go here */

	iov[iov_len].iov_base = NULL;

	p2p_peer_frame_xchg(dev->conn_peer, iov, dev->conn_peer->device_addr,
				100, resp_timeout, 256, false,
				FRAME_GROUP_CONNECT,
				p2p_go_negotiation_req_done,
				&p2p_frame_go_neg_resp,
				p2p_go_negotiation_resp_cb, NULL);
}

static void p2p_start_provision_discovery(struct p2p_device *dev)
{
	/* TODO: start Provision Discovery */
}

static bool p2p_peer_get_info(struct p2p_peer *peer,
				uint16_t *wsc_config_methods,
				struct p2p_capability_attr **capability)
{
	struct wsc_probe_request wsc_info;

	switch (peer->bss->source_frame) {
	case SCAN_BSS_PROBE_RESP:
		if (!peer->bss->p2p_probe_resp_info)
			return false;

		if (wsc_config_methods)
			*wsc_config_methods = peer->bss->p2p_probe_resp_info->
				device_info.wsc_config_methods;

		*capability = &peer->bss->p2p_probe_resp_info->capability;
		return true;
	case SCAN_BSS_PROBE_REQ:
		if (!peer->bss->p2p_probe_req_info || !peer->bss->wsc)
			return false;

		if (wsc_parse_probe_request(peer->bss->wsc, peer->bss->wsc_size,
						&wsc_info) < 0)
			return false;

		if (wsc_config_methods)
			*wsc_config_methods = wsc_info.config_methods;

		*capability = &peer->bss->p2p_probe_req_info->capability;
		return true;
	case SCAN_BSS_BEACON:
		if (!peer->bss->p2p_beacon_info || !peer->bss->wsc)
			return false;

		if (wsc_parse_probe_request(peer->bss->wsc, peer->bss->wsc_size,
						&wsc_info) < 0)
			return false;

		if (wsc_config_methods)
			*wsc_config_methods = wsc_info.config_methods;

		*capability = &peer->bss->p2p_beacon_info->capability;
		break;
	}

	return false;
}

static void p2p_peer_connect(struct p2p_peer *peer, const char *pin)
{
	struct p2p_device *dev = peer->dev;
	uint16_t wsc_config_methods;
	struct p2p_capability_attr *capability;
	struct l_dbus_message *message = peer->wsc.pending_connect;
	struct l_dbus_message *reply;

	if (dev->conn_peer) {
		reply = dbus_error_busy(message);
		goto send_error;
	}

	/*
	 * Step 1, check if the device indicates it supports our WSC method
	 * and check other flags to make sure a connection is possible.
	 */
	if (!p2p_peer_get_info(peer, &wsc_config_methods, &capability)) {
		reply = dbus_error_failed(message);
		goto send_error;
	}

	dev->conn_config_method = pin ? WSC_CONFIGURATION_METHOD_KEYPAD :
		WSC_CONFIGURATION_METHOD_PUSH_BUTTON;
	dev->conn_password_id = pin ?
		(strlen(pin) == 4 || wsc_pin_is_checksum_valid(pin) ?
		 WSC_DEVICE_PASSWORD_ID_DEFAULT :
		 WSC_DEVICE_PASSWORD_ID_USER_SPECIFIED) :
		WSC_DEVICE_PASSWORD_ID_PUSH_BUTTON;

	if (!(wsc_config_methods & dev->conn_config_method)) {
		reply = dbus_error_not_supported(message);
		goto send_error;
	}

	if (capability->device_caps & P2P_DEVICE_CAP_DEVICE_LIMIT) {
		reply = dbus_error_not_supported(message);
		goto send_error;
	}

	if (capability->group_caps & P2P_GROUP_CAP_GROUP_LIMIT) {
		reply = dbus_error_not_supported(message);
		goto send_error;
	}

	if (capability->group_caps & P2P_GROUP_CAP_GROUP_FORMATION) {
		reply = dbus_error_busy(message);
		goto send_error;
	}

	p2p_device_discovery_stop(dev);

	/* Generate the interface address for our P2P-Client connection */
	wiphy_generate_random_address(dev->wiphy, dev->conn_addr);

	dev->conn_peer = peer; /* No ref counting so just set the pointer */
	dev->conn_pin = l_strdup(pin);
	dev->connections_left--;
	l_dbus_property_changed(dbus_get_bus(), p2p_device_get_path(dev),
				IWD_P2P_INTERFACE, "AvailableConnections");

	/*
	 * Step 2, if peer is already a GO then send the Provision Discovery
	 * before doing WSC.  If it's not then do Provision Discovery
	 * optionally as seems to be required by some implementations, and
	 * start GO negotiation following that.
	 * TODO: Add a AlwaysUsePD config setting.
	 */
	if (dev->conn_peer->group)
		p2p_start_provision_discovery(dev);
	else
		p2p_start_go_negotiation(dev);

	return;

send_error:
	dbus_pending_reply(&peer->wsc.pending_connect, reply);
}

static void p2p_peer_disconnect(struct p2p_peer *peer)
{
	struct p2p_device *dev = peer->dev;
	struct l_dbus_message *message = peer->wsc.pending_cancel;
	struct l_dbus_message *reply;

	if (dev->conn_peer != peer) {
		reply = dbus_error_not_connected(message);
		goto send_reply;
	}

	if (peer->wsc.pending_connect)
		dbus_pending_reply(&peer->wsc.pending_connect,
				dbus_error_aborted(peer->wsc.pending_connect));

	p2p_connection_reset(dev);
	reply = l_dbus_message_new_method_return(message);

send_reply:
	dbus_pending_reply(&peer->wsc.pending_cancel, reply);
}

#define SCAN_INTERVAL_MAX	3
#define SCAN_INTERVAL_STEP	1
#define CHANS_PER_SCAN_INITIAL	2
#define CHANS_PER_SCAN		2

static bool p2p_device_scan_start(struct p2p_device *dev);
static void p2p_device_roc_start(struct p2p_device *dev);

static void p2p_device_roc_timeout(struct l_timeout *timeout, void *user_data)
{
	struct p2p_device *dev = user_data;

	l_timeout_remove(dev->scan_timeout);

	if (time(NULL) < dev->next_scan_ts) {
		/*
		 * dev->scan_timeout destroy function will have been called
		 * by now so it won't overwrite the new timeout set by
		 * p2p_device_roc_start.
		 */
		p2p_device_roc_start(dev);
		return;
	}

	p2p_device_scan_start(dev);
}

static void p2p_device_roc_cancel(struct p2p_device *dev)
{
	struct l_genl_msg *msg;

	if (!dev->have_roc_cookie)
		return;

	l_debug("");

	msg = l_genl_msg_new_sized(NL80211_CMD_CANCEL_REMAIN_ON_CHANNEL, 32);
	l_genl_msg_append_attr(msg, NL80211_ATTR_WDEV, 8, &dev->wdev_id);
	l_genl_msg_append_attr(msg, NL80211_ATTR_COOKIE, 8, &dev->roc_cookie);
	l_genl_family_send(dev->nl80211, msg, NULL, NULL, NULL);

	dev->have_roc_cookie = false;
}

static void p2p_scan_timeout_destroy(void *user_data)
{
	struct p2p_device *dev = user_data;

	dev->scan_timeout = NULL;

	if (dev->nl80211) {
		/*
		 * Most likely when the timer expires the ROC period
		 * has finished but send a cancel command to make sure,
		 * as well as handle situations like disabling P2P.
		 */
		p2p_device_roc_cancel(dev);
	}
}

static void p2p_device_roc_cb(struct l_genl_msg *msg, void *user_data)
{
	struct p2p_device *dev = user_data;
	uint64_t cookie;
	int error = l_genl_msg_get_error(msg);

	l_debug("ROC: %s (%i)", strerror(-error), -error);

	if (error)
		return;

	if (nl80211_parse_attrs(msg, NL80211_ATTR_COOKIE, &cookie,
				NL80211_ATTR_UNSPEC) < 0)
		return;

	dev->roc_cookie = cookie;
	dev->have_roc_cookie = true;

	/*
	 * Has the command taken so long that P2P has been since disabled
	 * or the timeout otherwise ran out?
	 */
	if (!dev->scan_timeout)
		p2p_device_roc_cancel(dev);
}

static void p2p_device_roc_start(struct p2p_device *dev)
{
	struct l_genl_msg *msg;
	uint32_t listen_freq;
	uint32_t duration;
	uint32_t cmd_id;

	l_debug("");

	/*
	 * One second granularity is fine here because some randomess
	 * is desired and the intervals don't have strictly defined
	 * limits.
	 */
	duration = (dev->next_scan_ts - time(NULL)) * 1000;

	if (duration < 200)
		duration = 200;

	/*
	 * Driver max duration seems to be 5000ms or more for all drivers
	 * except mac80211_hwsim where it is only 1000ms.
	 */
	if (duration > wiphy_get_max_roc_duration(dev->wiphy))
		duration = wiphy_get_max_roc_duration(dev->wiphy);

	/*
	 * Some drivers seem to miss fewer frames if we start new requests
	 * often.
	 */
	if (duration > 1000)
		duration = 1000;

	listen_freq = scan_channel_to_freq(dev->listen_channel,
						SCAN_BAND_2_4_GHZ);

	msg = l_genl_msg_new_sized(NL80211_CMD_REMAIN_ON_CHANNEL, 64);
	l_genl_msg_append_attr(msg, NL80211_ATTR_WDEV, 8, &dev->wdev_id);
	l_genl_msg_append_attr(msg, NL80211_ATTR_WIPHY_FREQ, 4, &listen_freq);
	l_genl_msg_append_attr(msg, NL80211_ATTR_DURATION, 4, &duration);

	cmd_id = l_genl_family_send(dev->nl80211, msg, p2p_device_roc_cb, dev,
					NULL);
	if (!cmd_id)
		l_genl_msg_unref(msg);

	/*
	 * Time out after @duration ms independent of whether we were able to
	 * start the ROC command.  If we receive the CMD_REMAIN_ON_CHANNEL
	 * event we'll update the timeout to give the ROC command enough time
	 * to finish.  On an error or if we time out before the ROC command
	 * even starts, we'll just retry after @duration ms so we don't even
	 * need to handle errors specifically.
	 */
	dev->scan_timeout = l_timeout_create_ms(duration,
						p2p_device_roc_timeout, dev,
						p2p_scan_timeout_destroy);
	dev->listen_duration = duration;
	dev->have_roc_cookie = false;

	l_debug("started a ROC command on channel %i for %i ms",
		(int) dev->listen_channel, (int) duration);
}

static const char *p2p_peer_wsc_get_path(struct wsc_dbus *wsc)
{
	return p2p_peer_get_path(l_container_of(wsc, struct p2p_peer, wsc));
}

static void p2p_peer_wsc_connect(struct wsc_dbus *wsc, const char *pin)
{
	p2p_peer_connect(l_container_of(wsc, struct p2p_peer, wsc), pin);
}

static void p2p_peer_wsc_cancel(struct wsc_dbus *wsc)
{
	p2p_peer_disconnect(l_container_of(wsc, struct p2p_peer, wsc));
}

static void p2p_peer_wsc_remove(struct wsc_dbus *wsc)
{
	/*
	 * The WSC removal is triggered in p2p_peer_put so we call
	 * p2p_peer_free directly from there too.
	 */
}

static bool p2p_device_peer_add(struct p2p_device *dev, struct p2p_peer *peer)
{
	if (!strlen(peer->name) || !l_utf8_validate(
					peer->name, strlen(peer->name), NULL)) {
		l_debug("Device name doesn't validate for bssid %s",
			util_address_to_string(peer->bss->addr));
		return false;
	}

	if (!l_dbus_object_add_interface(dbus_get_bus(),
						p2p_peer_get_path(peer),
						IWD_P2P_PEER_INTERFACE, peer)) {
		l_debug("Unable to add the %s interface to %s",
			IWD_P2P_PEER_INTERFACE, p2p_peer_get_path(peer));
		return false;
	}

	if (!l_dbus_object_add_interface(dbus_get_bus(),
						p2p_peer_get_path(peer),
						L_DBUS_INTERFACE_PROPERTIES,
						NULL)) {
		l_dbus_unregister_object(dbus_get_bus(),
						p2p_peer_get_path(peer));
		l_debug("Unable to add the %s interface to %s",
			L_DBUS_INTERFACE_PROPERTIES, p2p_peer_get_path(peer));
		return false;
	}

	peer->wsc.get_path = p2p_peer_wsc_get_path;
	peer->wsc.connect = p2p_peer_wsc_connect;
	peer->wsc.cancel = p2p_peer_wsc_cancel;
	peer->wsc.remove = p2p_peer_wsc_remove;

	if (!wsc_dbus_add_interface(&peer->wsc)) {
		l_dbus_unregister_object(dbus_get_bus(),
						p2p_peer_get_path(peer));
		return false;
	}

	l_queue_push_tail(dev->peer_list, peer);

	return true;
}

struct p2p_peer_move_data {
	struct l_queue *new_list;
	struct p2p_peer *conn_peer;
	uint64_t now;
};

static bool p2p_peer_move_recent(void *data, void *user_data)
{
	struct p2p_peer *peer = data;
	struct p2p_peer_move_data *move_data = user_data;

	if (move_data->now > peer->bss->time_stamp + 30 * L_USEC_PER_SEC &&
			peer != move_data->conn_peer)
		return false;	/* Old, keep on the list */

	/* Recently seen or currently connected, move to the new list */
	l_queue_push_tail(move_data->new_list, peer);
	return true;
}

static bool p2p_peer_update_existing(struct scan_bss *bss,
					struct l_queue *old_list,
					struct l_queue *new_list)
{
	struct p2p_peer *peer;

	peer = l_queue_remove_if(old_list, p2p_peer_match, bss->addr);
	if (!peer)
		return false;

	/*
	 * We've seen this peer already, only update the scan_bss object.
	 * Do we need to update DBus properties?
	 */
	scan_bss_free(peer->bss);
	peer->bss = bss;

	l_queue_push_tail(new_list, peer);
	return true;
}

static bool p2p_scan_notify(int err, struct l_queue *bss_list,
				void *user_data)
{
	struct p2p_device *dev = user_data;
	const struct l_queue_entry *entry;
	struct l_queue *old_peer_list = dev->peer_list;
	struct p2p_peer_move_data move_data;

	if (err) {
		l_debug("P2P scan failed: %s (%i)", strerror(-err), -err);
		goto schedule;
	}

	dev->peer_list = l_queue_new();

	for (entry = l_queue_get_entries(bss_list); entry;
			entry = entry->next) {
		struct scan_bss *bss = entry->data;
		struct p2p_peer *peer;

		if (bss->source_frame != SCAN_BSS_PROBE_RESP ||
				!bss->p2p_probe_resp_info) {
			scan_bss_free(bss);
			continue;
		}

		if (p2p_peer_update_existing(bss, old_peer_list,
						dev->peer_list))
			continue;

		peer = l_new(struct p2p_peer, 1);
		peer->dev = dev;
		peer->bss = bss;
		peer->name = l_strdup(bss->p2p_probe_resp_info->
						device_info.device_name);
		peer->primary_device_type =
			bss->p2p_probe_resp_info->device_info.primary_device_type;
		peer->group =
			!!(bss->p2p_probe_resp_info->capability.group_caps &
			   P2P_GROUP_CAP_GO);
		/*
		 * Both P2P Devices and GOs can send Probe Responses so the
		 * frame's source address may not necessarily be the Device
		 * Address, use what's in the obligatory Device Info.
		 */
		peer->device_addr =
			bss->p2p_probe_resp_info->device_info.device_addr;

		if (!p2p_device_peer_add(dev, peer))
			p2p_peer_free(peer);
	}

	/*
	 * old_peer_list now only contains peers not present in the new
	 * results.  Move any peers seen in the last 30 secs to the new
	 * dev->peer_list and unref only the remaining peers.
	 */
	move_data.new_list = dev->peer_list;
	move_data.conn_peer = dev->conn_peer;
	move_data.now = l_time_now();
	l_queue_foreach_remove(old_peer_list, p2p_peer_move_recent, &move_data);
	l_queue_destroy(old_peer_list, p2p_peer_put);
	l_queue_destroy(bss_list, NULL);

schedule:
	/*
	 * Calculate interval between now and when we want the next active
	 * scan to start.  Keep issuing Remain-on-Channel commands of
	 * maximum duration until it's time to start the new scan.
	 * The listen periods are actually like a passive scan except that
	 * instead of listening for Beacons only, we also look at Probe
	 * Requests and Probe Responses because they, too, carry P2P IEs
	 * with all the information we need about peer devices.  Beacons
	 * also do, in case of GOs, but we will already get the same
	 * information from the Probe Responses and (even if we can
	 * receive the beacons in userspace in the first place) we don't
	 * want to handle so many frames.
	 *
	 * According to 3.1.2.1.1 we shall be available in listen state
	 * during Find for at least 500ms continuously at least once in
	 * every 5s.  According to 3.1.2.1.3, the Listen State lasts for
	 * between 1 and 3 one-hundred TU Intervals.
	 *
	 * The Search State duration is implementation dependent.
	 */
	if (dev->scan_interval < SCAN_INTERVAL_MAX)
		dev->scan_interval += SCAN_INTERVAL_STEP;

	dev->next_scan_ts = time(NULL) + dev->scan_interval;

	p2p_device_roc_start(dev);
	return true;
}

static bool p2p_device_scan_start(struct p2p_device *dev)
{
	struct scan_parameters params = {};
	uint8_t buf[256];
	unsigned int i;

	wiphy_get_reg_domain_country(dev->wiphy, (char *) dev->listen_country);
	dev->listen_country[2] = 4;	/* Table E-4 */
	dev->listen_oper_class = 81;	/* 2.4 band */

	params.extra_ie = p2p_build_scan_ies(dev, buf, sizeof(buf),
						&params.extra_ie_size);
	L_WARN_ON(!params.extra_ie);
	params.flush = true;
	/* P2P Wildcard SSID because we don't need legacy networks to reply */
	params.ssid = "DIRECT-";
	/*
	 * Must send probe requests at 6Mb/s, OFDM only.  The no-CCK rates
	 * flag forces the drivers to do exactly this for 2.4GHz frames.
	 *
	 * "- P2P Devices shall not use 11b rates (1, 2, 5.5, 11 Mbps) for data
	 *   and management frames except:
	 *    * Probe Request frames sent to both P2P Devices and non-P2P
	 *      Devices.
	 * - P2P Devices shall not respond to Probe Request frames that indicate
	 *   support for 11b rates only.
	 * Note 1 - This means that the P2P Group Owner transmits Beacon frames
	 * using OFDM.
	 * Note 2 - This means that the P2P Group Owner transmits Probe Response
	 * frames using OFDM, including frames sent in response to Probe
	 * Requests received at 11b rates from non 11b-only devices.
	 * Note 3 - P2P Devices shall not include 11b rates in the list of
	 * supported rates in Probe Request frame intended only for P2P Devices.
	 * 11b rates may be included in the list of supported rates in Probe
	 * Request frames intended for both P2P Devices and non-P2P Devices."
	 */
	params.no_cck_rates = true;
	params.freqs = scan_freq_set_new();

	for (i = 0; i < L_ARRAY_SIZE(channels_social); i++) {
		int chan = channels_social[i];
		uint32_t freq = scan_channel_to_freq(chan, SCAN_BAND_2_4_GHZ);

		scan_freq_set_add(params.freqs, freq);
	}

	/*
	 * Instead of doing a single Scan Phase at the beginning of the Device
	 * Discovery and then strictly a Find Phase loop as defined in the
	 * spec, mix both to keep watching for P2P groups on the non-social
	 * channels, slowly going through a few channels at a time in each
	 * Scan State iteration.  Scan dev->chans_per_scan channels each time,
	 * use dev->scan_chan_idx to keep track of which channels we've
	 * visited recently.
	 */
	for (i = 0; i < dev->chans_per_scan; i++) {
		int idx = dev->scan_chan_idx++;
		int chan = channels_scan_2_4_other[idx];
		uint32_t freq = scan_channel_to_freq(chan, SCAN_BAND_2_4_GHZ);

		if (dev->scan_chan_idx >=
				L_ARRAY_SIZE(channels_scan_2_4_other)) {
			dev->scan_chan_idx = 0;
			/*
			 * Do fewer channels per scan after we've initially
			 * gone through the 2.4 band.
			 */
			dev->chans_per_scan = CHANS_PER_SCAN;
		}

		scan_freq_set_add(params.freqs, freq);
	}

	dev->scan_id = scan_active_full(dev->wdev_id, &params, NULL,
					p2p_scan_notify, dev, p2p_scan_destroy);
	scan_freq_set_free(params.freqs);

	return dev->scan_id != 0;
}

static void p2p_device_probe_cb(const struct mmpdu_header *mpdu,
				const void *body, size_t body_len,
				int rssi, void *user_data)
{
	struct p2p_device *dev = user_data;
	struct p2p_peer *peer;
	struct p2p_probe_req p2p_info;
	struct wsc_probe_request wsc_info;
	int r;
	uint8_t *wsc_payload;
	ssize_t wsc_len;
	struct scan_bss *bss;
	struct p2p_channel_attr *channel;
	enum scan_band band;
	uint32_t frequency;

	l_debug("");

	if (!dev->scan_timeout && !dev->scan_id)
		return;

	wsc_payload = ie_tlv_extract_wsc_payload(body, body_len, &wsc_len);
	if (!wsc_payload)	/* Not a P2P Probe Req, ignore */
		return;

	r =  wsc_parse_probe_request(wsc_payload, wsc_len, &wsc_info);
	l_free(wsc_payload);

	if (r < 0) {
		l_error("Probe Request WSC IE parse error %s (%i)",
			strerror(-r), -r);
		return;
	}

	r = p2p_parse_probe_req(body, body_len, &p2p_info);
	if (r < 0) {
		if (r == -ENOENT)	/* Not a P2P Probe Req, ignore */
			return;

		l_error("Probe Request P2P IE parse error %s (%i)",
			strerror(-r), -r);
		return;
	}

	/*
	 * We don't currently have a use case for replying to Probe Requests
	 * except when waiting for a GO Negotiation Request from our target
	 * peer.
	 */

	/*
	 * The peer's listen frequency may be different from ours.
	 * The Listen Channel attribute is optional but if neither
	 * it nor the Operating Channel are set then we have no way
	 * to contact that peer.  Ignore such peers.
	 */
	if (p2p_info.listen_channel.country[0])
		channel = &p2p_info.listen_channel;
	else if (p2p_info.operating_channel.country[0])
		channel = &p2p_info.operating_channel;
	else
		goto p2p_free;

	band = scan_oper_class_to_band((const uint8_t *) channel->country,
					channel->oper_class);
	frequency = scan_channel_to_freq(channel->channel_num, band);
	if (!frequency)
		goto p2p_free;

	bss = scan_bss_new_from_probe_req(mpdu, body, body_len, frequency,
						rssi);
	if (!bss)
		goto p2p_free;

	bss->time_stamp = l_time_now();

	if (p2p_peer_update_existing(bss, dev->peer_list, dev->peer_list))
		goto p2p_free;

	peer = l_new(struct p2p_peer, 1);
	peer->dev = dev;
	peer->bss = bss;
	peer->name = l_strdup(wsc_info.device_name);
	peer->primary_device_type = wsc_info.primary_device_type;
	peer->group = !!(p2p_info.capability.group_caps & P2P_GROUP_CAP_GO);
	/*
	 * The Device Info attribute is present conditionally so we can't get
	 * the Device Address from there.  In theory only P2P Devices send
	 * out Probe Requests, not P2P GOs, so we assume the source address
	 * is the Device Address.
	 */
	peer->device_addr = bss->addr;

	if (!p2p_device_peer_add(dev, peer))
		p2p_peer_free(peer);

	/*
	 * TODO: check SSID/BSSID are wildcard values if present and
	 * reply with a Probe Response -- not useful in our current usage
	 * scenarios but required by the spec.
	 */

p2p_free:
	p2p_clear_probe_req(&p2p_info);
}

static void p2p_device_discovery_start(struct p2p_device *dev)
{
	if (dev->scan_timeout || dev->scan_id)
		return;

	dev->scan_interval = 1;
	dev->chans_per_scan = CHANS_PER_SCAN_INITIAL;
	dev->scan_chan_idx = 0;

	/*
	 * 3.1.2.1.1: "The Listen Channel shall be chosen at the beginning of
	 * the In-band Device Discovery"
	 *
	 * (Unless we're waiting for a GO Negotiation Request from a peer on
	 * a known channel)
	 */
	dev->listen_channel = channels_social[l_getrandom_uint32() %
					L_ARRAY_SIZE(channels_social)];

	frame_watch_add(dev->wdev_id, FRAME_GROUP_LISTEN, 0x0040,
			(uint8_t *) "", 0, p2p_device_probe_cb, dev, NULL);

	p2p_device_scan_start(dev);
}

static void p2p_device_discovery_stop(struct p2p_device *dev)
{
	dev->scan_interval = 0;

	if (dev->scan_id)
		scan_cancel(dev->wdev_id, dev->scan_id);

	if (dev->scan_timeout)
		l_timeout_remove(dev->scan_timeout);

	p2p_device_roc_cancel(dev);
	frame_watch_group_remove(dev->wdev_id, FRAME_GROUP_LISTEN);
}

static void p2p_device_enable_cb(struct l_genl_msg *msg, void *user_data)
{
	struct p2p_device *dev = user_data;
	int error = l_genl_msg_get_error(msg);
	struct l_dbus_message *message = dev->pending_message;

	l_debug("START/STOP_P2P_DEVICE: %s (%i)", strerror(-error), -error);

	if (error)
		goto done;

	dev->enabled = !dev->enabled;

	if (dev->enabled && !l_queue_isempty(dev->discovery_users))
		p2p_device_discovery_start(dev);

done:
	dev->pending_complete(dbus_get_bus(), message,
				error ? dbus_error_failed(message) :
				NULL);
	dev->pending_message = NULL;
	dev->pending_complete = NULL;

	if (!error)
		l_dbus_property_changed(dbus_get_bus(),
					p2p_device_get_path(dev),
					IWD_P2P_INTERFACE, "Enabled");
}

static void p2p_device_enable_destroy(void *user_data)
{
	struct p2p_device *dev = user_data;

	dev->start_stop_cmd_id = 0;
}

static void p2p_device_start_stop(struct p2p_device *dev,
				l_dbus_property_complete_cb_t complete,
				struct l_dbus_message *message)
{
	struct l_genl_msg *cmd;

	if (dev->enabled)
		p2p_device_discovery_stop(dev);

	if (!dev->enabled)
		cmd = l_genl_msg_new_sized(NL80211_CMD_START_P2P_DEVICE, 16);
	else
		cmd = l_genl_msg_new_sized(NL80211_CMD_STOP_P2P_DEVICE, 16);

	l_genl_msg_append_attr(cmd, NL80211_ATTR_WDEV, 8, &dev->wdev_id);

	dev->start_stop_cmd_id = l_genl_family_send(dev->nl80211, cmd,
						p2p_device_enable_cb, dev,
						p2p_device_enable_destroy);
	if (!dev->start_stop_cmd_id) {
		l_genl_msg_unref(cmd);
		complete(dbus_get_bus(), message, dbus_error_failed(message));
		return;
	}

	dev->pending_message = message;
	dev->pending_complete = complete;

	if (dev->enabled) {
		/*
		 * Stopping the P2P device, drop all peers as we can't start
		 * new connections from now on.
		 */
		if (dev->conn_peer)
			p2p_connect_failed(dev);

		l_queue_destroy(dev->peer_list, p2p_peer_put);
		dev->peer_list = NULL;
	}
}

static void p2p_mlme_notify(struct l_genl_msg *msg, void *user_data)
{
	struct p2p_device *dev = user_data;
	uint64_t wdev_id;
	uint64_t cookie;

	if (nl80211_parse_attrs(msg, NL80211_ATTR_WDEV, &wdev_id,
				NL80211_ATTR_COOKIE, &cookie,
				NL80211_ATTR_UNSPEC) < 0 ||
			wdev_id != dev->wdev_id)
		return;

	switch (l_genl_msg_get_command(msg)) {
	case NL80211_CMD_REMAIN_ON_CHANNEL:
		if (!dev->have_roc_cookie || cookie != dev->roc_cookie)
			break;

		if (!dev->scan_timeout)
			break;

		/*
		 * The Listen phase is actually starting here, update the
		 * timeout so we know more or less when it ends.
		 */
		l_debug("ROC started");
		l_timeout_modify_ms(dev->scan_timeout, dev->listen_duration);
		break;
	case NL80211_CMD_CANCEL_REMAIN_ON_CHANNEL:
		/* TODO */
		break;
	}
}

#define P2P_SUPPORTED_METHODS	(			\
	WSC_CONFIGURATION_METHOD_LABEL |		\
	WSC_CONFIGURATION_METHOD_KEYPAD |		\
	WSC_CONFIGURATION_METHOD_VIRTUAL_PUSH_BUTTON |	\
	WSC_CONFIGURATION_METHOD_PHYSICAL_PUSH_BUTTON |	\
	WSC_CONFIGURATION_METHOD_P2P |			\
	WSC_CONFIGURATION_METHOD_VIRTUAL_DISPLAY_PIN |	\
	WSC_CONFIGURATION_METHOD_PHYSICAL_DISPLAY_PIN)

struct p2p_device *p2p_device_update_from_genl(struct l_genl_msg *msg,
						bool create)
{
	struct l_genl_attr attr;
	uint16_t type, len;
	const void *data;
	const uint8_t *ifaddr = NULL;
	const uint64_t *wdev_id = NULL;
	struct wiphy *wiphy = NULL;
	struct p2p_device *dev;
	char hostname[HOST_NAME_MAX + 1];
	char *str;
	unsigned int uint_val;

	if (!l_genl_attr_init(&attr, msg))
		return NULL;

	while (l_genl_attr_next(&attr, &type, &len, &data)) {
		switch (type) {
		case NL80211_ATTR_WDEV:
			if (len != sizeof(uint64_t)) {
				l_warn("Invalid wdev index attribute");
				return NULL;
			}

			wdev_id = data;
			break;

		case NL80211_ATTR_WIPHY:
			if (len != sizeof(uint32_t)) {
				l_warn("Invalid wiphy attribute");
				return NULL;
			}

			wiphy = wiphy_find(*((uint32_t *) data));
			break;

		case NL80211_ATTR_IFTYPE:
			if (len != sizeof(uint32_t)) {
				l_warn("Invalid interface type attribute");
				return NULL;
			}

			if (*((uint32_t *) data) != NL80211_IFTYPE_P2P_DEVICE)
				return NULL;

			break;

		case NL80211_ATTR_MAC:
			if (len != ETH_ALEN) {
				l_warn("Invalid interface address attribute");
				return NULL;
			}

			ifaddr = data;
			break;
		}
	}

	if (!wiphy || !wdev_id || !ifaddr) {
		l_warn("Unable to parse interface information");
		return NULL;
	}

	if (create) {
		if (p2p_device_find(*wdev_id)) {
			l_debug("Duplicate p2p device %" PRIx64, *wdev_id);
			return NULL;
		}
	} else {
		dev = p2p_device_find(*wdev_id);
		if (!dev)
			return NULL;

		memcpy(dev->addr, ifaddr, ETH_ALEN);
		return NULL;
	}

	dev = l_new(struct p2p_device, 1);
	dev->wdev_id = *wdev_id;
	memcpy(dev->addr, ifaddr, ETH_ALEN);
	dev->nl80211 = l_genl_family_new(iwd_get_genl(), NL80211_GENL_NAME);
	dev->wiphy = wiphy;
	gethostname(hostname, sizeof(hostname));
	dev->connections_left = 1;

	/* TODO: allow masking capability bits through a setting? */
	dev->capability.device_caps = P2P_DEVICE_CAP_CONCURRENT_OP;
	dev->capability.group_caps = 0;

	memcpy(dev->device_info.device_addr, dev->addr, 6);

	dev->device_info.wsc_config_methods =
		WSC_CONFIGURATION_METHOD_P2P |
		WSC_CONFIGURATION_METHOD_PUSH_BUTTON;
	dev->device_info.primary_device_type.category = 1;	/* Computer */
	memcpy(dev->device_info.primary_device_type.oui, microsoft_oui, 3);
	dev->device_info.primary_device_type.oui_type = 0x04;
	dev->device_info.primary_device_type.subcategory = 1;	/* PC */
	l_strlcpy(dev->device_info.device_name, hostname,
			sizeof(dev->device_info.device_name));

	if (l_settings_get_uint(iwd_get_config(), "P2P",
				"ConfigurationMethods", &uint_val)) {
		if (!(uint_val & P2P_SUPPORTED_METHODS))
			l_error("[P2P].ConfigurationMethods must contain "
				"at least one supported method");
		else if (uint_val & ~0xffff)
			l_error("[P2P].ConfigurationMethods should be a "
				"16-bit integer");
		else
			dev->device_info.wsc_config_methods =
				uint_val & P2P_SUPPORTED_METHODS;
	}

	str = l_settings_get_string(iwd_get_config(), "P2P", "DeviceType");

	/*
	 * Standard WSC subcategories are unique and more specific than
	 * categories so there's no point for the user to specify the
	 * category if they choose to use the string format.
	 *
	 * As an example our default value (Computer - PC) can be
	 * encoded as either of:
	 *
	 * DeviceType=pc
	 * DeviceType=0x00010050f2040001
	 */
	if (str && !wsc_device_type_from_subcategory_str(
					&dev->device_info.primary_device_type,
					str)) {
		unsigned long long u;
		char *endp;

		u = strtoull(str, &endp, 0);

		/*
		 * Accept any custom category, OUI and subcategory values but
		 * require non-zero category as a sanity check.
		 */
		if (*endp != '\0' || (u & 0xffff000000000000ll) == 0)
			l_error("[P2P].DeviceType must be a subcategory string "
				"or a 64-bit integer encoding the full Primary"
				" Device Type attribute: "
				"<Category>|<OUI>|<OUI Type>|<Subcategory>");
		else {
			dev->device_info.primary_device_type.category = u >> 48;
			dev->device_info.primary_device_type.oui[0] = u >> 40;
			dev->device_info.primary_device_type.oui[1] = u >> 32;
			dev->device_info.primary_device_type.oui[2] = u >> 24;
			dev->device_info.primary_device_type.oui_type = u >> 16;
			dev->device_info.primary_device_type.subcategory = u;
		}
	}

	l_queue_push_tail(p2p_device_list, dev);

	l_debug("Created P2P device %" PRIx64, dev->wdev_id);

	scan_wdev_add(dev->wdev_id);

	if (!l_genl_family_register(dev->nl80211, NL80211_MULTICAST_GROUP_MLME,
					p2p_mlme_notify, dev, NULL))
		l_error("Registering for MLME notifications failed");

	if (!l_dbus_object_add_interface(dbus_get_bus(),
						p2p_device_get_path(dev),
						IWD_P2P_INTERFACE, dev))
		l_info("Unable to add the %s interface to %s",
			IWD_P2P_INTERFACE, p2p_device_get_path(dev));

	return dev;
}

static void p2p_device_free(void *user_data)
{
	struct p2p_device *dev = user_data;

	if (dev->pending_message) {
		struct l_dbus_message *reply =
			dbus_error_aborted(dev->pending_message);

		dev->pending_complete(dbus_get_bus(),
					dev->pending_message, reply);
		dev->pending_message = NULL;
		dev->pending_complete = NULL;
	}

	p2p_device_discovery_stop(dev);
	p2p_connection_reset(dev);
	l_dbus_unregister_object(dbus_get_bus(), p2p_device_get_path(dev));
	l_queue_destroy(dev->peer_list, p2p_peer_put);
	l_queue_destroy(dev->discovery_users, p2p_discovery_user_free);
	l_genl_family_free(dev->nl80211); /* Cancels dev->start_stop_cmd_id */
	scan_wdev_remove(dev->wdev_id);
	l_free(dev);
}

bool p2p_device_destroy(struct p2p_device *dev)
{
	if (!l_queue_remove(p2p_device_list, dev))
		return false;

	p2p_device_free(dev);
	return true;
}

static bool p2p_device_get_enabled(struct l_dbus *dbus,
					struct l_dbus_message *message,
					struct l_dbus_message_builder *builder,
					void *user_data)
{
	struct p2p_device *dev = user_data;
	bool enabled = dev->enabled;

	l_dbus_message_builder_append_basic(builder, 'b', &enabled);

	return true;
}

static struct l_dbus_message *p2p_device_set_enabled(struct l_dbus *dbus,
					struct l_dbus_message *message,
					struct l_dbus_message_iter *new_value,
					l_dbus_property_complete_cb_t complete,
					void *user_data)
{
	struct p2p_device *dev = user_data;
	bool new_enabled;

	if (!l_dbus_message_iter_get_variant(new_value, "b", &new_enabled))
		return dbus_error_invalid_args(message);

	if (dev->start_stop_cmd_id || dev->pending_message)
		return dbus_error_busy(message);

	if (dev->enabled == new_enabled) {
		complete(dbus, message, NULL);
		return NULL;
	}

	p2p_device_start_stop(dev, complete, message);
	return NULL;
}

static bool p2p_device_get_name(struct l_dbus *dbus,
				struct l_dbus_message *message,
				struct l_dbus_message_builder *builder,
				void *user_data)
{
	struct p2p_device *dev = user_data;

	l_dbus_message_builder_append_basic(builder, 's',
						dev->device_info.device_name);
	return true;
}

static struct l_dbus_message *p2p_device_set_name(struct l_dbus *dbus,
					struct l_dbus_message *message,
					struct l_dbus_message_iter *new_value,
					l_dbus_property_complete_cb_t complete,
					void *user_data)
{
	struct p2p_device *dev = user_data;
	const char *new_name;
	bool changed = false;

	if (!l_dbus_message_iter_get_variant(new_value, "s", &new_name))
		return dbus_error_invalid_args(message);

	if (!strcmp(new_name, dev->device_info.device_name))
		goto done;

	if (strlen(new_name) > sizeof(dev->device_info.device_name) - 1)
		return dbus_error_invalid_args(message);

	changed = true;
	l_strlcpy(dev->device_info.device_name, new_name,
			sizeof(dev->device_info.device_name));

done:
	complete(dbus, message, NULL);

	if (changed)
		l_dbus_property_changed(dbus, p2p_device_get_path(dev),
					IWD_P2P_INTERFACE, "Name");

	return NULL;
}

static bool p2p_device_get_avail_conns(struct l_dbus *dbus,
					struct l_dbus_message *message,
					struct l_dbus_message_builder *builder,
					void *user_data)
{
	struct p2p_device *dev = user_data;
	uint16_t avail_conns = dev->connections_left;

	l_dbus_message_builder_append_basic(builder, 'q', &avail_conns);
	return true;
}

static struct l_dbus_message *p2p_device_get_peers(struct l_dbus *dbus,
						struct l_dbus_message *message,
						void *user_data)
{
	struct p2p_device *dev = user_data;
	struct l_dbus_message *reply;
	struct l_dbus_message_builder *builder;
	const struct l_queue_entry *entry;

	if (!l_dbus_message_get_arguments(message, ""))
		return dbus_error_invalid_args(message);

	reply = l_dbus_message_new_method_return(message);
	builder = l_dbus_message_builder_new(reply);

	l_dbus_message_builder_enter_array(builder, "(on)");

	for (entry = l_queue_get_entries(dev->peer_list); entry;
			entry = entry->next) {
		const struct p2p_peer *peer = entry->data;
		int16_t signal_strength = peer->bss->signal_strength;

		l_dbus_message_builder_enter_struct(builder, "on");
		l_dbus_message_builder_append_basic(builder, 'o',
						p2p_peer_get_path(peer));
		l_dbus_message_builder_append_basic(builder, 'n',
							&signal_strength);
		l_dbus_message_builder_leave_struct(builder);
	}

	l_dbus_message_builder_leave_array(builder);

	l_dbus_message_builder_finalize(builder);
	l_dbus_message_builder_destroy(builder);

	return reply;
}

static void p2p_device_discovery_disconnect(struct l_dbus *dbus, void *user_data)
{
	struct p2p_discovery_user *user = user_data;
	struct p2p_device *dev = user->dev;

	l_debug("P2P Device Discovery user %s disconnected", user->client);

	l_queue_remove(dev->discovery_users, user);
	p2p_discovery_user_free(user);

	if (l_queue_isempty(dev->discovery_users))
		p2p_device_discovery_stop(dev);
}

static void p2p_device_discovery_destroy(void *user_data)
{
	struct p2p_discovery_user *user = user_data;

	user->disconnect_watch = 0;
}

static struct l_dbus_message *p2p_device_request_discovery(struct l_dbus *dbus,
						struct l_dbus_message *message,
						void *user_data)
{
	struct p2p_device *dev = user_data;
	struct p2p_discovery_user *user;
	bool first_user = l_queue_isempty(dev->discovery_users);

	if (!l_dbus_message_get_arguments(message, ""))
		return dbus_error_invalid_args(message);

	if (l_queue_find(dev->discovery_users, p2p_discovery_user_match,
				l_dbus_message_get_sender(message)))
		return dbus_error_already_exists(message);

	user = l_new(struct p2p_discovery_user, 1);
	user->client = l_strdup(l_dbus_message_get_sender(message));
	user->dev = dev;
	user->disconnect_watch = l_dbus_add_disconnect_watch(dbus,
						user->client,
						p2p_device_discovery_disconnect,
						user,
						p2p_device_discovery_destroy);
	l_queue_push_tail(dev->discovery_users, user);

	if (first_user && !dev->conn_peer && dev->enabled)
		p2p_device_discovery_start(dev);

	return l_dbus_message_new_method_return(message);
}

static struct l_dbus_message *p2p_device_release_discovery(struct l_dbus *dbus,
						struct l_dbus_message *message,
						void *user_data)
{
	struct p2p_device *dev = user_data;
	struct p2p_discovery_user *user;

	if (!l_dbus_message_get_arguments(message, ""))
		return dbus_error_invalid_args(message);

	user = l_queue_remove_if(dev->discovery_users,
				p2p_discovery_user_match,
				l_dbus_message_get_sender(message));
	if (!user)
		return dbus_error_not_found(message);

	p2p_discovery_user_free(user);

	if (l_queue_isempty(dev->discovery_users))
		p2p_device_discovery_stop(dev);

	return l_dbus_message_new_method_return(message);
}

static void p2p_interface_setup(struct l_dbus_interface *interface)
{
	l_dbus_interface_property(interface, "Enabled", 0, "b",
					p2p_device_get_enabled,
					p2p_device_set_enabled);
	l_dbus_interface_property(interface, "Name", 0, "s",
					p2p_device_get_name,
					p2p_device_set_name);
	l_dbus_interface_property(interface, "AvailableConnections", 0, "q",
					p2p_device_get_avail_conns, NULL);
	l_dbus_interface_method(interface, "GetPeers", 0,
				p2p_device_get_peers, "a(on)", "", "peers");
	l_dbus_interface_method(interface, "RequestDiscovery", 0,
				p2p_device_request_discovery, "", "");
	l_dbus_interface_method(interface, "ReleaseDiscovery", 0,
				p2p_device_release_discovery, "", "");
}

static bool p2p_peer_get_name(struct l_dbus *dbus,
				struct l_dbus_message *message,
				struct l_dbus_message_builder *builder,
				void *user_data)
{
	struct p2p_peer *peer = user_data;

	l_dbus_message_builder_append_basic(builder, 's', peer->name);
	return true;
}

static bool p2p_peer_get_category(struct l_dbus *dbus,
					struct l_dbus_message *message,
					struct l_dbus_message_builder *builder,
					void *user_data)
{
	struct p2p_peer *peer = user_data;
	const char *category;

	if (!wsc_device_type_to_dbus_str(&peer->primary_device_type,
						&category, NULL) ||
			!category)
		category = "unknown-device";

	l_dbus_message_builder_append_basic(builder, 's', category);
	return true;
}

static bool p2p_peer_get_subcategory(struct l_dbus *dbus,
					struct l_dbus_message *message,
					struct l_dbus_message_builder *builder,
					void *user_data)
{
	struct p2p_peer *peer = user_data;
	const char *subcategory;

	/*
	 * Should we generate subcategory strings with the numerical
	 * values for the subcategories we don't know, such as
	 * "Vendor-specific 00:11:22:33 44" ?
	 */

	if (!wsc_device_type_to_dbus_str(&peer->primary_device_type,
						NULL, &subcategory) ||
			!subcategory)
		return false;

	l_dbus_message_builder_append_basic(builder, 's', subcategory);
	return true;
}

static bool p2p_peer_get_connected(struct l_dbus *dbus,
					struct l_dbus_message *message,
					struct l_dbus_message_builder *builder,
					void *user_data)
{
	bool connected = false;

	l_dbus_message_builder_append_basic(builder, 'b', &connected);
	return true;
}

static struct l_dbus_message *p2p_peer_dbus_disconnect(struct l_dbus *dbus,
						struct l_dbus_message *message,
						void *user_data)
{
	struct p2p_peer *peer = user_data;

	if (!l_dbus_message_get_arguments(message, ""))
		return dbus_error_invalid_args(message);

	/*
	 * Save the message for both WSC.Cancel and Peer.Disconnect the
	 * same way.
	 */
	peer->wsc.pending_cancel = l_dbus_message_ref(message);

	p2p_peer_disconnect(peer);
	return NULL;
}

static void p2p_peer_interface_setup(struct l_dbus_interface *interface)
{
	l_dbus_interface_property(interface, "Name", 0, "s",
					p2p_peer_get_name, NULL);
	l_dbus_interface_property(interface, "DeviceCategory", 0, "s",
					p2p_peer_get_category, NULL);
	l_dbus_interface_property(interface, "DeviceSubcategory", 0, "s",
					p2p_peer_get_subcategory, NULL);
	l_dbus_interface_property(interface, "Connected", 0, "b",
					p2p_peer_get_connected, NULL);
	l_dbus_interface_method(interface, "Disconnect", 0,
				p2p_peer_dbus_disconnect, "", "");
}

static int p2p_init(void)
{
	if (!l_dbus_register_interface(dbus_get_bus(),
					IWD_P2P_INTERFACE,
					p2p_interface_setup,
					NULL, false))
		l_error("Unable to register the %s interface",
			IWD_P2P_INTERFACE);

	if (!l_dbus_register_interface(dbus_get_bus(),
					IWD_P2P_PEER_INTERFACE,
					p2p_peer_interface_setup,
					NULL, false))
		l_error("Unable to register the %s interface",
			IWD_P2P_PEER_INTERFACE);

	p2p_device_list = l_queue_new();

	return 0;
}

static void p2p_exit(void)
{
	l_dbus_unregister_interface(dbus_get_bus(), IWD_P2P_INTERFACE);
	l_dbus_unregister_interface(dbus_get_bus(), IWD_P2P_PEER_INTERFACE);
	l_queue_destroy(p2p_device_list, p2p_device_free);
	p2p_device_list = NULL;
}

IWD_MODULE(p2p, p2p_init, p2p_exit)
IWD_MODULE_DEPENDS(p2p, wiphy)
IWD_MODULE_DEPENDS(p2p, scan)
