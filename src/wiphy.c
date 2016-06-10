/*
 *
 *  Wireless daemon for Linux
 *
 *  Copyright (C) 2013-2014  Intel Corporation. All rights reserved.
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
#include <linux/if_packet.h>
#include <linux/if_ether.h>

#include <ell/ell.h>

#include "linux/nl80211.h"
#include "src/iwd.h"
#include "src/ie.h"
#include "src/wiphy.h"
#include "src/dbus.h"
#include "src/scan.h"
#include "src/util.h"
#include "src/common.h"
#include "src/eapol.h"
#include "src/agent.h"
#include "src/crypto.h"
#include "src/netdev.h"
#include "src/mpdu.h"
#include "src/storage.h"
#include "src/network.h"
#include "src/device.h"

static struct l_genl_family *nl80211 = NULL;

enum device_state {
	DEVICE_STATE_DISCONNECTED = 0,	/* Disconnected, no auto-connect */
	DEVICE_STATE_AUTOCONNECT,	/* Disconnected, try auto-connect */
	DEVICE_STATE_CONNECTING,	/* Connecting */
	DEVICE_STATE_CONNECTED,
	DEVICE_STATE_DISCONNECTING,
};

struct device {
	uint32_t index;
	enum device_state state;
	struct l_queue *bss_list;
	struct l_queue *old_bss_list;
	struct l_dbus_message *scan_pending;
	struct l_hashmap *networks;
	struct scan_bss *connected_bss;
	struct network *connected_network;
	struct l_queue *autoconnect_list;
	struct l_dbus_message *connect_pending;
	struct l_dbus_message *disconnect_pending;
	struct l_io *eapol_io;

	uint32_t pairwise_new_key_cmd_id;
	uint32_t pairwise_set_key_cmd_id;
	uint32_t group_new_key_cmd_id;

	struct wiphy *wiphy;
	struct netdev *netdev;
};

struct wiphy {
	uint32_t id;
	char name[20];
	uint32_t feature_flags;
	bool support_scheduled_scan:1;
	bool support_rekey_offload:1;
	uint16_t pairwise_ciphers;
	struct scan_freq_set *supported_freqs;
};

struct autoconnect_entry {
	uint16_t rank;
	struct network *network;
	struct scan_bss *bss;
};

static struct l_queue *wiphy_list = NULL;
static struct l_queue *device_list;

static bool new_scan_results(uint32_t wiphy_id, uint32_t ifindex,
				struct l_queue *bss_list, void *userdata);

static bool eapol_read(struct l_io *io, void *user_data)
{
	struct device *device = user_data;
	struct netdev *netdev = device->netdev;
	int fd = l_io_get_fd(io);
	struct sockaddr_ll sll;
	socklen_t sll_len;
	ssize_t bytes;
	uint8_t frame[2304]; /* IEEE Std 802.11 ch. 8.2.3 */

	memset(&sll, 0, sizeof(sll));
	sll_len = sizeof(sll);

	bytes = recvfrom(fd, frame, sizeof(frame), 0,
				(struct sockaddr *) &sll, &sll_len);
	if (bytes <= 0) {
		l_error("EAPoL read socket: %s", strerror(errno));
		return false;
	}

	__eapol_rx_packet(netdev_get_ifindex(netdev),
				netdev_get_address(netdev),
				sll.sll_addr, frame, bytes);

	return true;
}

static const char *iwd_network_get_path(struct device *device,
					const uint8_t *ssid, size_t ssid_len,
					enum security security)
{
	static char path[256];
	unsigned int pos, i;

	pos = snprintf(path, sizeof(path), "%s/", device_get_path(device));

	for (i = 0; i < ssid_len && pos < sizeof(path); i++)
		pos += snprintf(path + pos, sizeof(path) - pos, "%02x",
								ssid[i]);

	snprintf(path + pos, sizeof(path) - pos, "_%s",
				security_to_str(security));

	return path;
}

static const char *device_state_to_string(enum device_state state)
{
	switch (state) {
	case DEVICE_STATE_DISCONNECTED:
		return "disconnected";
	case DEVICE_STATE_AUTOCONNECT:
		return "autoconnect";
	case DEVICE_STATE_CONNECTING:
		return "connecting";
	case DEVICE_STATE_CONNECTED:
		return "connected";
	case DEVICE_STATE_DISCONNECTING:
		return "disconnecting";
	}

	return "invalid";
}

struct network *device_get_connected_network(struct device *device)
{
	return device->connected_network;
}

bool device_is_busy(struct device *device)
{
	if (device->state != DEVICE_STATE_DISCONNECTED &&
			device->state != DEVICE_STATE_AUTOCONNECT)
		return true;

	return false;
}

struct wiphy *device_get_wiphy(struct device *device)
{
	return device->wiphy;
}

static void device_enter_state(struct device *device, enum device_state state)
{
	l_debug("Old State: %s, new state: %s",
			device_state_to_string(device->state),
			device_state_to_string(state));

	switch (state) {
	case DEVICE_STATE_AUTOCONNECT:
		scan_periodic_start(device->index, new_scan_results, device);
		break;
	case DEVICE_STATE_DISCONNECTED:
		scan_periodic_stop(device->index);
		break;
	case DEVICE_STATE_CONNECTED:
		scan_periodic_stop(device->index);
		break;
	case DEVICE_STATE_CONNECTING:
		break;
	case DEVICE_STATE_DISCONNECTING:
		break;
	}

	device->state = state;
}

static void device_disassociated(struct device *device)
{
	struct network *network = device->connected_network;
	struct l_dbus *dbus = dbus_get_bus();

	if (!network)
		return;

	network_disconnected(network);

	device->connected_bss = NULL;
	device->connected_network = NULL;

	device_enter_state(device, DEVICE_STATE_AUTOCONNECT);

	l_dbus_property_changed(dbus, device_get_path(device),
				IWD_DEVICE_INTERFACE, "ConnectedNetwork");
	l_dbus_property_changed(dbus, network_get_path(network),
				IWD_NETWORK_INTERFACE, "Connected");
}

static void device_lost_beacon(struct device *device)
{
	if (device->connect_pending)
		dbus_pending_reply(&device->connect_pending,
				dbus_error_failed(device->connect_pending));

	device_disassociated(device);
}

static void genl_connect_cb(struct l_genl_msg *msg, void *user_data)
{
	struct device *device = user_data;

	if (l_genl_msg_get_error(msg) < 0) {
		if (device->connect_pending)
			dbus_pending_reply(&device->connect_pending,
				dbus_error_failed(device->connect_pending));

		device_disassociated(device);
	}
}

enum ie_rsn_cipher_suite wiphy_select_cipher(struct wiphy *wiphy, uint16_t mask)
{
	mask &= wiphy->pairwise_ciphers;

	/* CCMP is our first choice, TKIP second */
	if (mask & IE_RSN_CIPHER_SUITE_CCMP)
		return IE_RSN_CIPHER_SUITE_CCMP;

	if (mask & IE_RSN_CIPHER_SUITE_TKIP)
		return IE_RSN_CIPHER_SUITE_TKIP;

	return 0;
}

static int mlme_authenticate_cmd(struct network *network, struct scan_bss *bss)
{
	struct device *device = network_get_device(network);
	const char *ssid = network_get_ssid(network);
	uint32_t auth_type = NL80211_AUTHTYPE_OPEN_SYSTEM;
	struct l_genl_msg *msg;

	msg = l_genl_msg_new_sized(NL80211_CMD_AUTHENTICATE, 512);
	msg_append_attr(msg, NL80211_ATTR_IFINDEX, 4, &device->index);
	msg_append_attr(msg, NL80211_ATTR_WIPHY_FREQ, 4, &bss->frequency);
	msg_append_attr(msg, NL80211_ATTR_MAC, ETH_ALEN, bss->addr);
	msg_append_attr(msg, NL80211_ATTR_SSID, strlen(ssid), ssid);
	msg_append_attr(msg, NL80211_ATTR_AUTH_TYPE, 4, &auth_type);
	l_genl_family_send(nl80211, msg, genl_connect_cb, device, NULL);

	return 0;
}

void device_connect_network(struct device *device, struct network *network,
				struct scan_bss *bss,
				struct l_dbus_message *message)
{
	struct l_dbus *dbus = dbus_get_bus();

	device->connect_pending = l_dbus_message_ref(message);

	device->connected_bss = bss;
	device->connected_network = network;

	device_enter_state(device, DEVICE_STATE_CONNECTING);

	mlme_authenticate_cmd(network, bss);

	l_dbus_property_changed(dbus, device_get_path(device),
				IWD_DEVICE_INTERFACE, "ConnectedNetwork");
	l_dbus_property_changed(dbus, network_get_path(network),
				IWD_NETWORK_INTERFACE, "Connected");
}

static void bss_free(void *data)
{
	struct scan_bss *bss = data;
	const char *addr;

	addr = util_address_to_string(bss->addr);

	l_debug("Freeing BSS %s", addr);

	scan_bss_free(bss);
}

static void network_free(void *data)
{
	struct network *network = data;

	network_remove(network, -ESHUTDOWN);
}

const char *device_get_path(struct device *device)
{
	static char path[12];

	snprintf(path, sizeof(path), "/%u", device->index);
	return path;
}

const uint8_t *device_get_address(struct device *device)
{
	return netdev_get_address(device->netdev);
}

uint32_t device_get_ifindex(struct device *device)
{
	return device->index;
}

void __iwd_device_foreach(iwd_device_foreach_func func, void *user_data)
{
	const struct l_queue_entry *device_entry;

	for (device_entry = l_queue_get_entries(device_list); device_entry;
					device_entry = device_entry->next) {
		struct device *device = device_entry->data;

		func(device, user_data);
	}
}

static void device_scan_triggered(int err, void *user_data)
{
	struct device *device = user_data;
	struct l_dbus_message *reply;

	l_debug("device_scan_triggered: %i", err);

	if (err < 0) {
		dbus_pending_reply(&device->scan_pending,
				dbus_error_failed(device->scan_pending));
		return;
	}

	l_debug("Scan triggered for %s", netdev_get_name(device->netdev));

	reply = l_dbus_message_new_method_return(device->scan_pending);
	l_dbus_message_set_arguments(reply, "");
	dbus_pending_reply(&device->scan_pending, reply);
}

static struct l_dbus_message *device_scan(struct l_dbus *dbus,
						struct l_dbus_message *message,
						void *user_data)
{
	struct device *device = user_data;

	l_debug("Scan called from DBus");

	if (device->scan_pending)
		return dbus_error_busy(message);

	device->scan_pending = l_dbus_message_ref(message);

	if (!scan_passive(device->index, device_scan_triggered,
				new_scan_results, device, NULL))
		return dbus_error_failed(message);

	return NULL;
}

static void device_disconnect_cb(struct l_genl_msg *msg, void *user_data)
{
	struct device *device = user_data;
	struct l_dbus_message *reply;

	if (l_genl_msg_get_error(msg) < 0) {
		dbus_pending_reply(&device->disconnect_pending,
				dbus_error_failed(device->disconnect_pending));
		return;
	}

	device_disassociated(device);

	reply = l_dbus_message_new_method_return(device->disconnect_pending);
	l_dbus_message_set_arguments(reply, "");
	dbus_pending_reply(&device->disconnect_pending, reply);
}

static struct l_dbus_message *device_disconnect(struct l_dbus *dbus,
						struct l_dbus_message *message,
						void *user_data)
{
	struct device *device = user_data;
	struct l_genl_msg *msg;
	uint16_t reason_code = MPDU_REASON_CODE_DEAUTH_LEAVING;
	enum security security;

	l_debug("");

	if (device->state == DEVICE_STATE_CONNECTING ||
			device->state == DEVICE_STATE_DISCONNECTING)
		return dbus_error_busy(message);

	if (!device->connected_bss)
		return dbus_error_not_connected(message);

	security = network_get_security(device->connected_network);
	if (security == SECURITY_PSK || security == SECURITY_8021X)
		eapol_cancel(device->index);

	msg = l_genl_msg_new_sized(NL80211_CMD_DEAUTHENTICATE, 512);
	msg_append_attr(msg, NL80211_ATTR_IFINDEX, 4, &device->index);
	msg_append_attr(msg, NL80211_ATTR_REASON_CODE, 2, &reason_code);
	msg_append_attr(msg, NL80211_ATTR_MAC, ETH_ALEN,
						device->connected_bss->addr);
	l_genl_family_send(nl80211, msg, device_disconnect_cb, device, NULL);

	device_enter_state(device, DEVICE_STATE_DISCONNECTING);

	device->disconnect_pending = l_dbus_message_ref(message);

	return NULL;
}

static bool device_property_get_name(struct l_dbus *dbus,
					struct l_dbus_message *message,
					struct l_dbus_message_builder *builder,
					void *user_data)
{
	struct device *device = user_data;

	l_dbus_message_builder_append_basic(builder, 's',
					netdev_get_name(device->netdev));
	return true;
}

static bool device_property_get_address(struct l_dbus *dbus,
					struct l_dbus_message *message,
					struct l_dbus_message_builder *builder,
					void *user_data)
{
	struct device *device = user_data;
	const char *str;

	str = util_address_to_string(netdev_get_address(device->netdev));
	l_dbus_message_builder_append_basic(builder, 's', str);

	return true;
}

static bool device_property_get_connected_network(struct l_dbus *dbus,
					struct l_dbus_message *message,
					struct l_dbus_message_builder *builder,
					void *user_data)
{
	struct device *device = user_data;
	if (!device->connected_network)
		return false;

	l_dbus_message_builder_append_basic(builder, 'o',
				network_get_path(device->connected_network));

	return true;
}

static void setup_device_interface(struct l_dbus_interface *interface)
{
	l_dbus_interface_method(interface, "Scan", 0,
				device_scan, "", "");
	l_dbus_interface_method(interface, "Disconnect", 0,
				device_disconnect, "", "");

	l_dbus_interface_property(interface, "Name", 0, "s",
					device_property_get_name, NULL);
	l_dbus_interface_property(interface, "Address", 0, "s",
					device_property_get_address, NULL);
	l_dbus_interface_property(interface, "ConnectedNetwork", 0, "o",
					device_property_get_connected_network,
					NULL);
}

static bool bss_match(const void *a, const void *b)
{
	const struct scan_bss *bss_a = a;
	const struct scan_bss *bss_b = b;

	return !memcmp(bss_a->addr, bss_b->addr, sizeof(bss_a->addr));
}

static bool device_match(const void *a, const void *b)
{
	const struct device *device = a;
	uint32_t index = L_PTR_TO_UINT(b);

	return (device->index == index);
}

static void device_autoconnect_next(struct device *device)
{
	struct autoconnect_entry *entry;
	int r;

	while ((entry = l_queue_pop_head(device->autoconnect_list))) {
		l_debug("Considering autoconnecting to BSS '%s' with SSID: %s,"
			" freq: %u, rank: %u, strength: %i",
			util_address_to_string(entry->bss->addr),
			network_get_ssid(entry->network),
			entry->bss->frequency, entry->rank,
			entry->bss->signal_strength);

		/* TODO: Blacklist the network from auto-connect */
		r = network_autoconnect(entry->network, entry->bss);
		l_free(entry);

		if (!r)
			return;
	}
}

static void wiphy_free(void *data)
{
	struct wiphy *wiphy = data;

	l_debug("Freeing wiphy %s", wiphy->name);

	scan_freq_set_free(wiphy->supported_freqs);
	l_free(wiphy);
}

static bool wiphy_match(const void *a, const void *b)
{
	const struct wiphy *wiphy = a;
	uint32_t id = L_PTR_TO_UINT(b);

	return (wiphy->id == id);
}

static void deauthenticate_cb(struct l_genl_msg *msg,
						void *user_data)
{
	struct device *device = user_data;

	/* If we were inside a .Connect(), it has failed */
	if (device->connect_pending)
		dbus_pending_reply(&device->connect_pending,
				dbus_error_failed(device->connect_pending));

	device_disassociated(device);
}

static void setting_keys_failed(struct device *device, uint16_t reason_code)
{
	struct l_genl_msg *msg;

	/*
	 * Something went wrong with our new_key, set_key, new_key,
	 * set_station, set_oper_state transaction
	 *
	 * Cancel all pending commands, then de-authenticate
	 */
	l_genl_family_cancel(nl80211, device->pairwise_new_key_cmd_id);
	device->pairwise_new_key_cmd_id = 0;

	l_genl_family_cancel(nl80211, device->pairwise_set_key_cmd_id);
	device->pairwise_set_key_cmd_id = 0;

	l_genl_family_cancel(nl80211, device->group_new_key_cmd_id);
	device->group_new_key_cmd_id = 0;

	eapol_cancel(device->index);

	msg = l_genl_msg_new_sized(NL80211_CMD_DEAUTHENTICATE, 512);
	msg_append_attr(msg, NL80211_ATTR_IFINDEX, 4, &device->index);
	msg_append_attr(msg, NL80211_ATTR_REASON_CODE, 2, &reason_code);
	msg_append_attr(msg, NL80211_ATTR_MAC, ETH_ALEN,
						device->connected_bss->addr);
	l_genl_family_send(nl80211, msg, deauthenticate_cb, device, NULL);
	device_enter_state(device, DEVICE_STATE_DISCONNECTING);
}

static void handshake_failed(uint32_t ifindex,
				const uint8_t *aa, const uint8_t *spa,
				uint16_t reason_code, void *user_data)
{
	struct device *device = user_data;
	struct l_genl_msg *msg;

	l_error("4-Way Handshake failed for ifindex: %d", ifindex);

	msg = l_genl_msg_new_sized(NL80211_CMD_DEAUTHENTICATE, 512);
	msg_append_attr(msg, NL80211_ATTR_IFINDEX, 4, &ifindex);
	msg_append_attr(msg, NL80211_ATTR_REASON_CODE, 2, &reason_code);
	msg_append_attr(msg, NL80211_ATTR_MAC, ETH_ALEN, aa);
	l_genl_family_send(nl80211, msg, deauthenticate_cb, device, NULL);
	device_enter_state(device, DEVICE_STATE_DISCONNECTING);
}

static void mlme_set_pairwise_key_cb(struct l_genl_msg *msg, void *data)
{
	struct device *device = data;

	device->pairwise_set_key_cmd_id = 0;

	if (l_genl_msg_get_error(msg) < 0) {
		l_error("Set Key for Pairwise Key failed for ifindex: %d",
				device->index);
		setting_keys_failed(device, MPDU_REASON_CODE_UNSPECIFIED);
		return;
	}
}

static unsigned int mlme_set_pairwise_key(struct device *device)
{
	uint8_t key_id = 0;
	struct l_genl_msg *msg;
	unsigned int id;

	msg = l_genl_msg_new_sized(NL80211_CMD_SET_KEY, 512);
	if (!msg)
		return 0;

	l_genl_msg_append_attr(msg, NL80211_ATTR_KEY_IDX, 1, &key_id);
	l_genl_msg_append_attr(msg, NL80211_ATTR_IFINDEX, 4, &device->index);

	l_genl_msg_append_attr(msg, NL80211_ATTR_KEY_DEFAULT, 0, NULL);

	l_genl_msg_enter_nested(msg, NL80211_ATTR_KEY_DEFAULT_TYPES);
	l_genl_msg_append_attr(msg, NL80211_KEY_DEFAULT_TYPE_UNICAST, 0, NULL);
	l_genl_msg_leave_nested(msg);

	id = l_genl_family_send(nl80211, msg, mlme_set_pairwise_key_cb,
					device, NULL);
	if (!id)
		l_genl_msg_unref(msg);

	return id;
}

static void mlme_new_pairwise_key_cb(struct l_genl_msg *msg, void *data)
{
	struct device *device = data;

	device->pairwise_new_key_cmd_id = 0;

	if (l_genl_msg_get_error(msg) < 0) {
		l_error("New Key for Pairwise Key failed for ifindex: %d",
				device->index);
		setting_keys_failed(device, MPDU_REASON_CODE_UNSPECIFIED);
		return;
	}
}

static unsigned int mlme_new_pairwise_key(struct device *device,
							uint32_t cipher,
							const uint8_t *aa,
							const uint8_t *tk,
							size_t tk_len)
{
	uint8_t key_id = 0;
	struct l_genl_msg *msg;
	unsigned int id;

	msg = l_genl_msg_new_sized(NL80211_CMD_NEW_KEY, 512);
	if (!msg)
		return 0;

	l_genl_msg_append_attr(msg, NL80211_ATTR_KEY_DATA, tk_len, tk);
	l_genl_msg_append_attr(msg, NL80211_ATTR_KEY_CIPHER, 4, &cipher);
	l_genl_msg_append_attr(msg, NL80211_ATTR_MAC, ETH_ALEN, aa);
	l_genl_msg_append_attr(msg, NL80211_ATTR_KEY_IDX, 1, &key_id);
	l_genl_msg_append_attr(msg, NL80211_ATTR_IFINDEX, 4, &device->index);

	id = l_genl_family_send(nl80211, msg, mlme_new_pairwise_key_cb,
					device, NULL);
	if (!id)
		l_genl_msg_unref(msg);

	return id;
}

static void wiphy_set_tk(uint32_t ifindex, const uint8_t *aa,
				const uint8_t *tk, uint32_t cipher,
				void *user_data)
{
	struct device *device = user_data;
	struct network *network = device->connected_network;
	uint8_t tk_buf[32];

	l_debug("");

	switch (cipher) {
	case CRYPTO_CIPHER_CCMP:
		memcpy(tk_buf, tk, 16);
		break;
	case CRYPTO_CIPHER_TKIP:
		/*
		 * Swap the TX and RX MIC key portions for supplicant.
		 * WPA_80211_v3_1_090922 doc's 3.3.4:
		 *   The MIC key used on the Client for transmit (TX) is in
		 *   bytes 24-31, and the MIC key used on the Client for
		 *   receive (RX) is in bytes 16-23 of the PTK.  That is,
		 *   assume that TX MIC and RX MIC referred to in Clause 8.7
		 *   are referenced to the Authenticator. Similarly, on the AP,
		 *   the MIC used for TX is in bytes 16-23, and the MIC key
		 *   used for RX is in bytes 24-31 of the PTK.
		 */
		memcpy(tk_buf, tk, 16);
		memcpy(tk_buf + 16, tk + 24, 8);
		memcpy(tk_buf + 24, tk + 16, 8);
		break;
	default:
		l_error("Unexpected cipher: %x", cipher);
		setting_keys_failed(device,
				MPDU_REASON_CODE_INVALID_PAIRWISE_CIPHER);
		return;
	}

	/* If we got here, then our PSK works.  Save if required */
	network_sync_psk(network);

	device->pairwise_new_key_cmd_id =
		mlme_new_pairwise_key(device, cipher, aa,
					tk_buf, crypto_cipher_key_len(cipher));
	device->pairwise_set_key_cmd_id = mlme_set_pairwise_key(device);
}

static void operstate_cb(bool result, void *user_data)
{
	struct device *device = user_data;

	if (!result) {
		l_error("Setting LinkMode and OperState failed for ifindex %d",
			device->index);
		setting_keys_failed(device, MPDU_REASON_CODE_UNSPECIFIED);
		return;
	}

	if (device->connect_pending) {
		struct l_dbus_message *reply;

		reply = l_dbus_message_new_method_return(
						device->connect_pending);
		l_dbus_message_set_arguments(reply, "");
		dbus_pending_reply(&device->connect_pending, reply);
	}

	network_connected(device->connected_network);
	device_enter_state(device, DEVICE_STATE_CONNECTED);
}

static void set_station_cb(struct l_genl_msg *msg, void *user_data)
{
	struct device *device = user_data;

	if (l_genl_msg_get_error(msg) < 0) {
		l_error("Set Station failed for ifindex %d", device->index);
		setting_keys_failed(device, MPDU_REASON_CODE_UNSPECIFIED);
		return;
	}

	netdev_set_linkmode_and_operstate(device->index, 1, IF_OPER_UP,
					operstate_cb, device);
}

static int set_station_cmd(struct device *device)
{
	struct scan_bss *bss = device->connected_bss;
	struct l_genl_msg *msg;
	struct nl80211_sta_flag_update flags;

	flags.mask = 1 << NL80211_STA_FLAG_AUTHORIZED;
	flags.set = flags.mask;

	msg = l_genl_msg_new_sized(NL80211_CMD_SET_STATION, 512);
	msg_append_attr(msg, NL80211_ATTR_IFINDEX, 4, &device->index);
	msg_append_attr(msg, NL80211_ATTR_MAC, ETH_ALEN, bss->addr);
	msg_append_attr(msg, NL80211_ATTR_STA_FLAGS2,
			sizeof(struct nl80211_sta_flag_update), &flags);
	l_genl_family_send(nl80211, msg, set_station_cb, device, NULL);

	return 0;
}

static void mlme_new_group_key_cb(struct l_genl_msg *msg, void *data)
{
	struct device *device = data;

	device->group_new_key_cmd_id = 0;

	if (l_genl_msg_get_error(msg) < 0) {
		l_error("New Key for Group Key failed for ifindex: %d",
				device->index);
		setting_keys_failed(device, MPDU_REASON_CODE_UNSPECIFIED);
		return;
	}

	set_station_cmd(device);
}

static unsigned int mlme_new_group_key(struct device *device,
					uint32_t cipher, uint8_t key_id,
					const uint8_t *gtk, size_t gtk_len,
					const uint8_t *rsc, size_t rsc_len)
{
	struct l_genl_msg *msg;
	unsigned int id;

	msg = l_genl_msg_new_sized(NL80211_CMD_NEW_KEY, 512);
	if (!msg)
		return 0;

	l_genl_msg_append_attr(msg, NL80211_ATTR_KEY_DATA, gtk_len, gtk);
	l_genl_msg_append_attr(msg, NL80211_ATTR_KEY_CIPHER, 4, &cipher);
	l_genl_msg_append_attr(msg, NL80211_ATTR_KEY_SEQ, rsc_len, rsc);

	l_genl_msg_enter_nested(msg, NL80211_ATTR_KEY_DEFAULT_TYPES);
	l_genl_msg_append_attr(msg, NL80211_KEY_DEFAULT_TYPE_MULTICAST,
				0, NULL);
	l_genl_msg_leave_nested(msg);

	l_genl_msg_append_attr(msg, NL80211_ATTR_KEY_IDX, 1, &key_id);
	l_genl_msg_append_attr(msg, NL80211_ATTR_IFINDEX, 4, &device->index);

	id = l_genl_family_send(nl80211, msg, mlme_new_group_key_cb,
					device, NULL);
	if (!id)
		l_genl_msg_unref(msg);

	return id;
}

static void wiphy_set_gtk(uint32_t ifindex, uint8_t key_index,
				const uint8_t *gtk, uint8_t gtk_len,
				const uint8_t *rsc, uint8_t rsc_len,
				uint32_t cipher, void *user_data)
{
	struct device *device = user_data;
	uint8_t gtk_buf[32];

	l_debug("");

	switch (cipher) {
	case CRYPTO_CIPHER_CCMP:
		memcpy(gtk_buf, gtk, 16);
		break;
	case CRYPTO_CIPHER_TKIP:
		/*
		 * Swap the TX and RX MIC key portions for supplicant.
		 * WPA_80211_v3_1_090922 doc's 3.3.4:
		 *   The MIC key used on the Client for transmit (TX) is in
		 *   bytes 24-31, and the MIC key used on the Client for
		 *   receive (RX) is in bytes 16-23 of the PTK.  That is,
		 *   assume that TX MIC and RX MIC referred to in Clause 8.7
		 *   are referenced to the Authenticator. Similarly, on the AP,
		 *   the MIC used for TX is in bytes 16-23, and the MIC key
		 *   used for RX is in bytes 24-31 of the PTK.
		 *
		 * Here apply this to the GTK instead of the PTK.
		 */
		memcpy(gtk_buf, gtk, 16);
		memcpy(gtk_buf + 16, gtk + 24, 8);
		memcpy(gtk_buf + 24, gtk + 16, 8);
		break;
	default:
		l_error("Unexpected cipher: %x", cipher);
		setting_keys_failed(device,
					MPDU_REASON_CODE_INVALID_GROUP_CIPHER);
		return;
	}

	if (crypto_cipher_key_len(cipher) != gtk_len) {
		l_error("Unexpected key length: %d", gtk_len);
		setting_keys_failed(device,
					MPDU_REASON_CODE_INVALID_GROUP_CIPHER);
		return;
	}

	device->group_new_key_cmd_id =
			mlme_new_group_key(device, cipher, key_index,
					gtk_buf, gtk_len, rsc, rsc_len);
}

static void mlme_associate_event(struct l_genl_msg *msg, struct device *device)
{
	int err;

	l_debug("");

	err = l_genl_msg_get_error(msg);
	if (err < 0) {
		l_error("association failed %s (%d)", strerror(-err), err);
		dbus_pending_reply(&device->connect_pending,
				dbus_error_failed(device->connect_pending));
		device_disassociated(device);
		return;
	}

	l_info("Association completed");

	if (network_get_security(device->connected_network) == SECURITY_NONE)
		netdev_set_linkmode_and_operstate(device->index, 1, IF_OPER_UP,
						operstate_cb, device);
}

static void genl_associate_cb(struct l_genl_msg *msg, void *user_data)
{
	struct device *device = user_data;

	if (l_genl_msg_get_error(msg) < 0 && device->connect_pending)
		dbus_pending_reply(&device->connect_pending,
				dbus_error_failed(device->connect_pending));
}

static void mlme_associate_cmd(struct device *device)
{
	struct l_genl_msg *msg;
	struct scan_bss *bss = device->connected_bss;
	struct network *network = device->connected_network;
	struct wiphy *wiphy = device->wiphy;
	const char *ssid = network_get_ssid(network);
	enum security security = network_get_security(network);

	l_debug("");

	msg = l_genl_msg_new_sized(NL80211_CMD_ASSOCIATE, 512);
	msg_append_attr(msg, NL80211_ATTR_IFINDEX, 4, &device->index);
	msg_append_attr(msg, NL80211_ATTR_WIPHY_FREQ, 4, &bss->frequency);
	msg_append_attr(msg, NL80211_ATTR_MAC, ETH_ALEN, bss->addr);
	msg_append_attr(msg, NL80211_ATTR_SSID, strlen(ssid), ssid);

	if (security == SECURITY_PSK || security == SECURITY_8021X) {
		uint16_t pairwise_ciphers, group_ciphers;
		uint32_t pairwise_cipher_attr;
		uint32_t group_cipher_attr;
		uint8_t rsne_buf[256];
		struct ie_rsn_info info;
		struct eapol_sm *sm = eapol_sm_new();

		memset(&info, 0, sizeof(info));

		if (security == SECURITY_PSK)
			info.akm_suites =
				bss->sha256 ? IE_RSN_AKM_SUITE_PSK_SHA256 :
						IE_RSN_AKM_SUITE_PSK;
		else
			info.akm_suites =
				bss->sha256 ? IE_RSN_AKM_SUITE_8021X_SHA256 :
						IE_RSN_AKM_SUITE_8021X;

		bss_get_supported_ciphers(bss, &pairwise_ciphers,
						&group_ciphers);

		info.pairwise_ciphers = wiphy_select_cipher(wiphy,
							pairwise_ciphers);
		if (info.pairwise_ciphers == IE_RSN_CIPHER_SUITE_CCMP)
			pairwise_cipher_attr = CRYPTO_CIPHER_CCMP;
		else
			pairwise_cipher_attr = CRYPTO_CIPHER_TKIP;

		info.group_cipher = wiphy_select_cipher(wiphy, group_ciphers);
		if (info.group_cipher == IE_RSN_CIPHER_SUITE_CCMP)
			group_cipher_attr = CRYPTO_CIPHER_CCMP;
		else
			group_cipher_attr = CRYPTO_CIPHER_TKIP;

		/* RSN takes priority */
		if (bss->rsne) {
			ie_build_rsne(&info, rsne_buf);
			eapol_sm_set_ap_rsn(sm, bss->rsne, bss->rsne[1] + 2);
			eapol_sm_set_own_rsn(sm, rsne_buf, rsne_buf[1] + 2);
		} else {
			ie_build_wpa(&info, rsne_buf);
			eapol_sm_set_ap_wpa(sm, bss->wpa, bss->wpa[1] + 2);
			eapol_sm_set_own_wpa(sm, rsne_buf, rsne_buf[1] + 2);
		}

		if (security == SECURITY_PSK)
			eapol_sm_set_pmk(sm, network_get_psk(network));
		else
			eapol_sm_set_8021x_config(sm,
						network_get_settings(network));

		eapol_sm_set_authenticator_address(sm, bss->addr);
		eapol_sm_set_supplicant_address(sm,
					netdev_get_address(device->netdev));
		eapol_sm_set_user_data(sm, device);
		eapol_sm_set_tx_user_data(sm,
				L_INT_TO_PTR(l_io_get_fd(device->eapol_io)));
		eapol_start(device->index, sm);

		msg_append_attr(msg, NL80211_ATTR_CIPHER_SUITES_PAIRWISE,
				4, &pairwise_cipher_attr);
		msg_append_attr(msg, NL80211_ATTR_CIPHER_SUITE_GROUP,
				4, &group_cipher_attr);

		msg_append_attr(msg, NL80211_ATTR_CONTROL_PORT, 0, NULL);
		msg_append_attr(msg, NL80211_ATTR_IE,
					rsne_buf[1] + 2, rsne_buf);
	}

	l_genl_family_send(nl80211, msg, genl_associate_cb, device, NULL);
}

static void mlme_authenticate_event(struct l_genl_msg *msg,
							struct device *device)
{
	struct l_genl_attr attr;
	uint16_t type, len;
	const void *data;
	int err;

	l_debug("");

	err = l_genl_msg_get_error(msg);
	if (err < 0) {
		l_error("authentication failed %s (%d)", strerror(-err), err);
		goto error;
	}

	if (!l_genl_attr_init(&attr, msg)) {
		l_debug("attr init failed");
		goto error;
	}

	while (l_genl_attr_next(&attr, &type, &len, &data)) {
		switch (type) {
		case NL80211_ATTR_TIMED_OUT:
			l_warn("authentication timed out");
			goto error;
		}
	}

	l_info("Authentication completed");
	mlme_associate_cmd(device);
	return;

error:
	if (device->connect_pending)
		dbus_pending_reply(&device->connect_pending,
				dbus_error_failed(device->connect_pending));

	device_disassociated(device);
}

static void mlme_deauthenticate_event(struct l_genl_msg *msg,
							struct device *device)
{
	l_debug("");
}

static void mlme_disconnect_event(struct l_genl_msg *msg,
					struct device *device)
{
	struct l_genl_attr attr;
	uint16_t type, len;
	const void *data;
	uint16_t reason_code = 0;
	bool disconnect_by_ap = false;

	l_debug("");

	if (!l_genl_attr_init(&attr, msg)) {
		l_error("attr init failed");
		return;
	}

	while (l_genl_attr_next(&attr, &type, &len, &data)) {
		switch (type) {
		case NL80211_ATTR_REASON_CODE:
			if (len != sizeof(uint16_t))
				l_warn("Invalid reason code attribute");
			else
				reason_code = *((uint16_t *) data);

			break;

		case NL80211_ATTR_DISCONNECTED_BY_AP:
			disconnect_by_ap = true;
			break;
		}
	}

	l_info("Received Deauthentication event, reason: %hu, from_ap: %s",
			reason_code, disconnect_by_ap ? "true" : "false");

	if (!disconnect_by_ap)
		return;

	if (device->connect_pending) {
		struct network *network = device->connected_network;

		dbus_pending_reply(&device->connect_pending,
				dbus_error_failed(device->connect_pending));

		network_connect_failed(network);
	}

	device_disassociated(device);
}

static void mlme_cqm_event(struct l_genl_msg *msg, struct device *device)
{
	struct l_genl_attr attr;
	struct l_genl_attr nested;
	uint16_t type, len;
	const void *data;

	l_debug("");

	if (!l_genl_attr_init(&attr, msg))
		return;

	while (l_genl_attr_next(&attr, &type, &len, &data)) {
		switch (type) {
		case NL80211_ATTR_CQM:
			if (!l_genl_attr_recurse(&attr, &nested))
				return;

			while (l_genl_attr_next(&nested, &type, &len, &data)) {
				switch (type) {
				case NL80211_ATTR_CQM_BEACON_LOSS_EVENT:
					device_lost_beacon(device);
					break;
				}
			}

			break;
		}
	}
}

static void network_reset_bss_list(const void *key, void *value,
					void *user_data)
{
	struct network *network = value;

	network_bss_list_clear(network);
}

static bool network_remove_if_lost(const void *key, void *data, void *user_data)
{
	struct network *network = data;

	if (!network_bss_list_isempty(network))
		return false;

	l_debug("No remaining BSSs for SSID: %s -- Removing network",
			network_get_ssid(network));
	network_remove(network, -ERANGE);

	return true;
}

static int autoconnect_rank_compare(const void *a, const void *b, void *user)
{
	const struct autoconnect_entry *new_ae = a;
	const struct autoconnect_entry *ae = b;

	return ae->rank - new_ae->rank;
}

static void process_bss(struct device *device, struct scan_bss *bss)
{
	struct network *network;
	enum security security;
	const char *path;
	double rankmod;
	struct autoconnect_entry *entry;

	l_debug("Found BSS '%s' with SSID: %s, freq: %u, rank: %u, "
			"strength: %i",
			util_address_to_string(bss->addr),
			util_ssid_to_utf8(bss->ssid_len, bss->ssid),
			bss->frequency, bss->rank, bss->signal_strength);

	if (!util_ssid_is_utf8(bss->ssid_len, bss->ssid)) {
		l_warn("Ignoring BSS with non-UTF8 SSID");
		return;
	}

	/*
	 * If both an RSN and a WPA elements are present currently
	 * RSN takes priority and the WPA IE is ignored.
	 */
	if (bss->rsne) {
		struct ie_rsn_info rsne;
		int res = ie_parse_rsne_from_data(bss->rsne, bss->rsne[1] + 2,
							&rsne);
		if (res < 0) {
			l_debug("Cannot parse RSN field (%d, %s)",
					res, strerror(-res));
			return;
		}

		security = scan_get_security(bss->capability, &rsne);

		if (security == SECURITY_PSK)
			bss->sha256 =
				rsne.akm_suites & IE_RSN_AKM_SUITE_PSK_SHA256;
		else if (security == SECURITY_8021X)
			bss->sha256 =
				rsne.akm_suites & IE_RSN_AKM_SUITE_8021X_SHA256;
	} else if (bss->wpa) {
		struct ie_rsn_info wpa;
		int res = ie_parse_wpa_from_data(bss->wpa, bss->wpa[1] + 2,
									&wpa);
		if (res < 0) {
			l_debug("Cannot parse WPA IE (%d, %s)",
						res, strerror(-res));
			return;
		}

		security = scan_get_security(bss->capability, &wpa);
	} else
		security = scan_get_security(bss->capability, NULL);

	path = iwd_network_get_path(device, bss->ssid, bss->ssid_len,
					security);

	network = l_hashmap_lookup(device->networks, path);
	if (!network) {
		network = network_create(device, bss->ssid, bss->ssid_len,
						security);

		if (!network_register(network, path)) {
			network_remove(network, -EINVAL);
			return;
		}

		l_hashmap_insert(device->networks,
					network_get_path(network), network);
		l_debug("Added new Network \"%s\" security %s",
			network_get_ssid(network), security_to_str(security));

		network_seen(network);
	}

	network_bss_add(network, bss);

	/* See if network is autoconnectable (is a known network) */
	if (!network_rankmod(network, &rankmod))
		return;

	entry = l_new(struct autoconnect_entry, 1);
	entry->network = network;
	entry->bss = bss;
	entry->rank = bss->rank * rankmod;
	l_queue_insert(device->autoconnect_list, entry,
				autoconnect_rank_compare, NULL);
}

static bool new_scan_results(uint32_t wiphy_id, uint32_t ifindex,
				struct l_queue *bss_list, void *userdata)
{
	struct device *device = userdata;
	const struct l_queue_entry *bss_entry;

	device->old_bss_list = device->bss_list;
	device->bss_list = bss_list;
	l_hashmap_foreach(device->networks, network_reset_bss_list, NULL);

	l_queue_destroy(device->autoconnect_list, l_free);
	device->autoconnect_list = l_queue_new();

	for (bss_entry = l_queue_get_entries(bss_list); bss_entry;
				bss_entry = bss_entry->next) {
		struct scan_bss *bss = bss_entry->data;

		process_bss(device, bss);
	}

	if (device->connected_bss) {
		struct scan_bss *bss;

		bss = l_queue_find(device->bss_list, bss_match,
						device->connected_bss);

		if (!bss) {
			l_warn("Connected BSS not in scan results!");
			l_queue_push_tail(device->bss_list,
						device->connected_bss);
			network_bss_add(device->connected_network,
						device->connected_bss);
			l_queue_remove(device->old_bss_list,
						device->connected_bss);
		} else
			device->connected_bss = bss;
	}

	l_hashmap_foreach_remove(device->networks,
					network_remove_if_lost, NULL);

	l_queue_destroy(device->old_bss_list, bss_free);
	device->old_bss_list = NULL;

	if (device->state == DEVICE_STATE_AUTOCONNECT)
		device_autoconnect_next(device);

	return true;
}

struct device *device_create(struct wiphy *wiphy, struct netdev *netdev)
{
	struct device *device;
	struct l_dbus *dbus = dbus_get_bus();
	uint32_t ifindex = netdev_get_ifindex(netdev);

	device = l_new(struct device, 1);
	device->bss_list = l_queue_new();
	device->networks = l_hashmap_new();
	l_hashmap_set_hash_function(device->networks, l_str_hash);
	l_hashmap_set_compare_function(device->networks,
				(l_hashmap_compare_func_t) strcmp);
	device->index = ifindex;
	device->wiphy = wiphy;
	device->netdev = netdev;

	l_queue_push_head(device_list, device);

	if (!l_dbus_object_add_interface(dbus, device_get_path(device),
					IWD_DEVICE_INTERFACE, device))
		l_info("Unable to register %s interface", IWD_DEVICE_INTERFACE);

	__device_watch_call_added(device);

	netdev_set_linkmode_and_operstate(device->index, 1,
						IF_OPER_DORMANT, NULL, NULL);

	scan_ifindex_add(device->index);
	device_enter_state(device, DEVICE_STATE_AUTOCONNECT);

	device->eapol_io = eapol_open_pae(device->index);
	if (device->eapol_io)
		l_io_set_read_handler(device->eapol_io, eapol_read,
								device, NULL);
	else
		l_error("Failed to open PAE socket");

	return device;
}

void device_remove(struct device *device)
{
	struct l_dbus *dbus;

	l_debug("");

	l_queue_remove(device_list, device);

	if (device->scan_pending)
		dbus_pending_reply(&device->scan_pending,
				dbus_error_aborted(device->scan_pending));

	if (device->connect_pending)
		dbus_pending_reply(&device->connect_pending,
				dbus_error_aborted(device->connect_pending));

	__device_watch_call_removed(device);

	dbus = dbus_get_bus();
	l_dbus_unregister_object(dbus, device_get_path(device));

	l_hashmap_destroy(device->networks, network_free);

	l_queue_destroy(device->bss_list, bss_free);
	l_queue_destroy(device->old_bss_list, bss_free);
	l_queue_destroy(device->autoconnect_list, l_free);
	l_io_destroy(device->eapol_io);

	scan_ifindex_remove(device->index);
	netdev_set_linkmode_and_operstate(device->index, 0, IF_OPER_DOWN,
					NULL, NULL);

	l_free(device);
}

struct wiphy *wiphy_find(int wiphy_id)
{
	return l_queue_find(wiphy_list, wiphy_match, L_UINT_TO_PTR(wiphy_id));
}

static void parse_supported_commands(struct wiphy *wiphy,
						struct l_genl_attr *attr)
{
	uint16_t type, len;
	const void *data;

	while (l_genl_attr_next(attr, &type, &len, &data)) {
		uint32_t cmd = *(uint32_t *)data;

		switch (cmd) {
		case NL80211_CMD_START_SCHED_SCAN:
			wiphy->support_scheduled_scan = true;
			break;
		case NL80211_CMD_SET_REKEY_OFFLOAD:
			wiphy->support_rekey_offload = true;
		}
	}
}

static void parse_supported_ciphers(struct wiphy *wiphy, const void *data,
						uint16_t len)
{
	bool s;

	while (len >= 4) {
		uint32_t cipher = *(uint32_t *)data;

		switch (cipher) {
		case CRYPTO_CIPHER_CCMP:
			wiphy->pairwise_ciphers |= IE_RSN_CIPHER_SUITE_CCMP;
			break;
		case CRYPTO_CIPHER_TKIP:
			wiphy->pairwise_ciphers |= IE_RSN_CIPHER_SUITE_TKIP;
			break;
		case CRYPTO_CIPHER_WEP40:
			wiphy->pairwise_ciphers |= IE_RSN_CIPHER_SUITE_WEP40;
			break;
		case CRYPTO_CIPHER_WEP104:
			wiphy->pairwise_ciphers |= IE_RSN_CIPHER_SUITE_WEP104;
			break;
		case CRYPTO_CIPHER_BIP:
			wiphy->pairwise_ciphers |= IE_RSN_CIPHER_SUITE_BIP;
			break;
		default:	/* TODO: Support other ciphers */
			break;
		}

		len -= 4;
		data += 4;
	}

	s = wiphy->pairwise_ciphers & IE_RSN_CIPHER_SUITE_CCMP;
	l_info("Wiphy supports CCMP: %s", s ? "true" : "false");

	s = wiphy->pairwise_ciphers & IE_RSN_CIPHER_SUITE_TKIP;
	l_info("Wiphy supports TKIP: %s", s ? "true" : "false");
}

static void parse_supported_frequencies(struct wiphy *wiphy,
						struct l_genl_attr *freqs)
{
	uint16_t type, len;
	const void *data;
	struct l_genl_attr attr;

	l_debug("");

	while (l_genl_attr_next(freqs, NULL, NULL, NULL)) {
		if (!l_genl_attr_recurse(freqs, &attr))
			continue;

		while (l_genl_attr_next(&attr, &type, &len, &data)) {
			uint32_t u32;

			switch (type) {
			case NL80211_FREQUENCY_ATTR_FREQ:
				u32 = *((uint32_t *) data);
				scan_freq_set_add(wiphy->supported_freqs, u32);
				break;
			}
		}
	}
}

static void parse_supported_bands(struct wiphy *wiphy,
						struct l_genl_attr *bands)
{
	uint16_t type, len;
	const void *data;
	struct l_genl_attr attr;

	l_debug("");

	while (l_genl_attr_next(bands, NULL, NULL, NULL)) {
		if (!l_genl_attr_recurse(bands, &attr))
			continue;

		while (l_genl_attr_next(&attr, &type, &len, &data)) {
			struct l_genl_attr freqs;

			switch (type) {
			case NL80211_BAND_ATTR_FREQS:
				if (!l_genl_attr_recurse(&attr, &freqs))
					continue;

				parse_supported_frequencies(wiphy, &freqs);
				break;
			}
		}
	}
}

#define FAIL_NO_WIPHY()					\
	if (!wiphy) {					\
		l_warn("No wiphy structure found");	\
		return;					\
	}						\

static void wiphy_dump_callback(struct l_genl_msg *msg, void *user_data)
{
	struct wiphy *wiphy = NULL;
	struct l_genl_attr attr, nested;
	uint16_t type, len;
	const void *data;
	uint32_t id;

	if (!l_genl_attr_init(&attr, msg))
		return;

	/*
	 * The wiphy attribute is always the first attribute in the
	 * list. If not then error out with a warning and ignore the
	 * whole message.
	 *
	 * In most cases multiple of these message will be send
	 * since the information included can not fit into a single
	 * message.
	 */
	while (l_genl_attr_next(&attr, &type, &len, &data)) {
		switch (type) {
		case NL80211_ATTR_WIPHY:
			if (wiphy) {
				l_warn("Duplicate wiphy attribute");
				return;
			}

			if (len != sizeof(uint32_t)) {
				l_warn("Invalid wiphy attribute");
				return;
			}

			id = *((uint32_t *) data);

			wiphy = l_queue_find(wiphy_list, wiphy_match,
							L_UINT_TO_PTR(id));
			if (!wiphy) {
				wiphy = l_new(struct wiphy, 1);
				wiphy->id = id;
				wiphy->supported_freqs = scan_freq_set_new();
				l_queue_push_head(wiphy_list, wiphy);
			}
			break;

		case NL80211_ATTR_WIPHY_NAME:
			FAIL_NO_WIPHY();

			if (len > sizeof(wiphy->name)) {
				l_warn("Invalid wiphy name attribute");
				return;
			}

			memcpy(wiphy->name, data, len);
			break;

		case NL80211_ATTR_FEATURE_FLAGS:
			FAIL_NO_WIPHY();

			if (len != sizeof(uint32_t)) {
				l_warn("Invalid feature flags attribute");
				return;
			}

			wiphy->feature_flags = *((uint32_t *) data);
			break;
		case NL80211_ATTR_SUPPORTED_COMMANDS:
			FAIL_NO_WIPHY();

			if (!l_genl_attr_recurse(&attr, &nested))
				return;

			parse_supported_commands(wiphy, &nested);
			break;
		case NL80211_ATTR_CIPHER_SUITES:
			FAIL_NO_WIPHY();

			parse_supported_ciphers(wiphy, data, len);
			break;
		case NL80211_ATTR_WIPHY_BANDS:
			FAIL_NO_WIPHY();

			if (!l_genl_attr_recurse(&attr, &nested))
				return;

			parse_supported_bands(wiphy, &nested);
			break;
		}
	}
}

static void wiphy_dump_done(void *user)
{
	const struct l_queue_entry *wiphy_entry;

	for (wiphy_entry = l_queue_get_entries(wiphy_list); wiphy_entry;
					wiphy_entry = wiphy_entry->next) {
		struct wiphy *wiphy = wiphy_entry->data;
		uint32_t bands;

		l_info("Wiphy: %d, Name: %s", wiphy->id, wiphy->name);
		l_info("Bands:");

		bands = scan_freq_set_get_bands(wiphy->supported_freqs);

		if (bands & SCAN_BAND_2_4_GHZ)
			l_info("\t2.4 Ghz");

		if (bands & SCAN_BAND_5_GHZ)
			l_info("\t5.0 Ghz");
	}
}

static void wiphy_config_notify(struct l_genl_msg *msg, void *user_data)
{
	struct l_genl_attr attr;
	uint16_t type, len;
	const void *data;
	uint8_t cmd;

	cmd = l_genl_msg_get_command(msg);

	l_debug("Notification of command %u", cmd);

	if (!l_genl_attr_init(&attr, msg))
		return;

	switch (cmd) {
	case NL80211_CMD_NEW_WIPHY:
	case NL80211_CMD_DEL_WIPHY:
	{
		const uint32_t *wiphy_id = NULL;
		const char *wiphy_name = NULL;

		while (l_genl_attr_next(&attr, &type, &len, &data)) {
			switch (type) {
			case NL80211_ATTR_WIPHY:
				if (len != sizeof(uint32_t)) {
					l_warn("Invalid wiphy attribute");
					return;
				}

				wiphy_id = data;
				break;

			case NL80211_ATTR_WIPHY_NAME:
				wiphy_name = data;
				break;
			}
		}

		if (!wiphy_id)
			return;

		if (cmd == NL80211_CMD_NEW_WIPHY)
			l_info("New Wiphy %s[%d] added", wiphy_name, *wiphy_id);
		else
			l_info("Wiphy %s[%d] removed", wiphy_name, *wiphy_id);

		break;
	}
	}
}

static void wiphy_mlme_notify(struct l_genl_msg *msg, void *user_data)
{
	struct wiphy *wiphy = NULL;
	struct device *device = NULL;
	struct l_genl_attr attr;
	uint16_t type, len;
	const void *data;
	uint8_t cmd;

	cmd = l_genl_msg_get_command(msg);

	l_debug("MLME notification %u", cmd);

	if (!l_genl_attr_init(&attr, msg))
		return;

	while (l_genl_attr_next(&attr, &type, &len, &data)) {
		switch (type) {
		case NL80211_ATTR_WIPHY:
			if (len != sizeof(uint32_t)) {
				l_warn("Invalid wiphy attribute");
				return;
			}

			wiphy = l_queue_find(wiphy_list, wiphy_match,
					L_UINT_TO_PTR(*((uint32_t *) data)));
			if (!wiphy) {
				l_warn("No wiphy structure found");
				return;
			}
			break;

		case NL80211_ATTR_IFINDEX:
			if (!wiphy) {
				l_warn("No wiphy structure found");
				return;
			}

			if (len != sizeof(uint32_t)) {
				l_warn("Invalid interface index attribute");
				return;
			}

			device = l_queue_find(device_list, device_match,
					L_UINT_TO_PTR(*((uint32_t *) data)));
			if (!device) {
				l_warn("No interface structure found");
				return;
			}
			break;
		}
	}

	if (!wiphy) {
		l_warn("MLME notification is missing wiphy attribute");
		return;
	}

	if (!device) {
		l_warn("MLME notification is missing interface attribute");
		return;
	}


	switch (cmd) {
	case NL80211_CMD_AUTHENTICATE:
		mlme_authenticate_event(msg, device);
		break;
	case NL80211_CMD_ASSOCIATE:
		mlme_associate_event(msg, device);
		break;
	case NL80211_CMD_DEAUTHENTICATE:
		mlme_deauthenticate_event(msg, device);
		break;
	case NL80211_CMD_DISCONNECT:
		mlme_disconnect_event(msg, device);
		break;
	case NL80211_CMD_NOTIFY_CQM:
		mlme_cqm_event(msg, device);
		break;
	}
}

static void wiphy_regulatory_notify(struct l_genl_msg *msg, void *user_data)
{
	struct l_genl_attr attr;
	uint16_t type, len;
	const void *data;
	uint8_t cmd;

	cmd = l_genl_msg_get_command(msg);

	l_debug("Regulatory notification %u", cmd);

	if (!l_genl_attr_init(&attr, msg))
		return;

	while (l_genl_attr_next(&attr, &type, &len, &data)) {
	}
}

static void regulatory_info_callback(struct l_genl_msg *msg, void *user_data)
{
	struct l_genl_attr attr;
	uint16_t type, len;
	const void *data;

	if (!l_genl_attr_init(&attr, msg))
		return;

	while (l_genl_attr_next(&attr, &type, &len, &data)) {
		switch (type) {
		case NL80211_ATTR_REG_ALPHA2:
			if (len != 3) {
				l_warn("Invalid regulatory alpha2 attribute");
				return;
			}

			l_debug("Regulatory alpha2 is %s", (char *) data);
			break;
		}
	}
}

static void protocol_features_callback(struct l_genl_msg *msg, void *user_data)
{
	struct l_genl_attr attr;
	uint16_t type, len;
	const void *data;
	uint32_t features = 0;

	if (!l_genl_attr_init(&attr, msg))
		return;

	while (l_genl_attr_next(&attr, &type, &len, &data)) {
		switch (type) {
		case NL80211_ATTR_PROTOCOL_FEATURES:
			if (len != sizeof(uint32_t)) {
				l_warn("Invalid protocol features attribute");
				return;
			}

			features = *((uint32_t *) data);
			break;
		}
	}

	if (features & NL80211_PROTOCOL_FEATURE_SPLIT_WIPHY_DUMP)
		l_debug("Found split wiphy dump support");
}

bool wiphy_init(struct l_genl_family *in)
{
	struct l_genl_msg *msg;

	/*
	 * This is an extra sanity check so that no memory is leaked
	 * in case the generic netlink handling gets confused.
	 */
	if (wiphy_list) {
		l_warn("Destroying existing list of wiphy devices");
		l_queue_destroy(wiphy_list, NULL);
	}

	if (!l_dbus_register_interface(dbus_get_bus(),
					IWD_DEVICE_INTERFACE,
					setup_device_interface,
					NULL, true))
		return false;

	nl80211 = in;

	if (!l_genl_family_register(nl80211, "config", wiphy_config_notify,
								NULL, NULL))
		l_error("Registering for config notification failed");

	if (!l_genl_family_register(nl80211, "mlme", wiphy_mlme_notify,
								NULL, NULL))
		l_error("Registering for MLME notification failed");

	if (!l_genl_family_register(nl80211, "regulatory",
					wiphy_regulatory_notify, NULL, NULL))
		l_error("Registering for regulatory notification failed");

	__eapol_set_install_tk_func(wiphy_set_tk);
	__eapol_set_install_gtk_func(wiphy_set_gtk);
	__eapol_set_deauthenticate_func(handshake_failed);

	wiphy_list = l_queue_new();
	device_list = l_queue_new();

	msg = l_genl_msg_new(NL80211_CMD_GET_PROTOCOL_FEATURES);
	if (!l_genl_family_send(nl80211, msg, protocol_features_callback,
								NULL, NULL))
		l_error("Getting protocol features failed");

	msg = l_genl_msg_new(NL80211_CMD_GET_REG);
	if (!l_genl_family_send(nl80211, msg, regulatory_info_callback,
								NULL, NULL))
		l_error("Getting regulatory info failed");

	msg = l_genl_msg_new(NL80211_CMD_GET_WIPHY);
	if (!l_genl_family_dump(nl80211, msg, wiphy_dump_callback,
						NULL, wiphy_dump_done))
		l_error("Getting all wiphy devices failed");

	return true;
}

bool wiphy_exit(void)
{
	l_queue_destroy(wiphy_list, wiphy_free);
	wiphy_list = NULL;

	l_queue_destroy(device_list, (l_queue_destroy_func_t) device_remove);
	device_list = NULL;

	nl80211 = NULL;

	l_dbus_unregister_interface(dbus_get_bus(), IWD_DEVICE_INTERFACE);

	return true;
}
