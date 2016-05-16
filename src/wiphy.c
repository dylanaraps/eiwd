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

struct netdev {
	uint32_t index;
	char name[IFNAMSIZ];
	uint32_t type;
	uint8_t addr[ETH_ALEN];
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
};

struct wiphy {
	uint32_t id;
	char name[20];
	uint32_t feature_flags;
	struct l_queue *netdev_list;
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

static bool new_scan_results(uint32_t wiphy_id, uint32_t ifindex,
				struct l_queue *bss_list, void *userdata);

static bool eapol_read(struct l_io *io, void *user_data)
{
	struct netdev *netdev = user_data;
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

	__eapol_rx_packet(netdev->index, netdev->addr, sll.sll_addr,
				frame, bytes);

	return true;
}

static const char *iwd_network_get_path(struct netdev *netdev,
					const uint8_t *ssid, size_t ssid_len,
					enum security security)
{
	static char path[256];
	unsigned int pos, i;

	pos = snprintf(path, sizeof(path), "%s/", device_get_path(netdev));

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

uint32_t netdev_get_ifindex(struct netdev *netdev)
{
	return netdev->index;
}

const uint8_t *netdev_get_address(struct netdev *netdev)
{
	return netdev->addr;
}

struct network *device_get_connected_network(struct netdev *device)
{
	return device->connected_network;
}

bool device_is_busy(struct netdev *device)
{
	if (device->state != DEVICE_STATE_DISCONNECTED &&
			device->state != DEVICE_STATE_AUTOCONNECT)
		return true;

	return false;
}

struct wiphy *device_get_wiphy(struct netdev *device)
{
	return device->wiphy;
}

static void netdev_enter_state(struct netdev *netdev, enum device_state state)
{
	l_debug("Old State: %s, new state: %s",
			device_state_to_string(netdev->state),
			device_state_to_string(state));

	switch (state) {
	case DEVICE_STATE_AUTOCONNECT:
		scan_periodic_start(netdev->index, new_scan_results, netdev);
		break;
	case DEVICE_STATE_DISCONNECTED:
		scan_periodic_stop(netdev->index);
		break;
	case DEVICE_STATE_CONNECTED:
		scan_periodic_stop(netdev->index);
		break;
	case DEVICE_STATE_CONNECTING:
		break;
	case DEVICE_STATE_DISCONNECTING:
		break;
	}

	netdev->state = state;
}

static void netdev_disassociated(struct netdev *netdev)
{
	struct network *network = netdev->connected_network;

	network_settings_close(network);

	netdev->connected_bss = NULL;
	netdev->connected_network = NULL;

	netdev_enter_state(netdev, DEVICE_STATE_AUTOCONNECT);
}

static void netdev_lost_beacon(struct netdev *netdev)
{
	if (netdev->connect_pending)
		dbus_pending_reply(&netdev->connect_pending,
				dbus_error_failed(netdev->connect_pending));

	if (netdev->connected_network)
		netdev_disassociated(netdev);
}

static void genl_connect_cb(struct l_genl_msg *msg, void *user_data)
{
	struct netdev *netdev = user_data;

	if (l_genl_msg_get_error(msg) < 0) {
		if (netdev->connect_pending)
			dbus_pending_reply(&netdev->connect_pending,
				dbus_error_failed(netdev->connect_pending));

		netdev_disassociated(netdev);
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
	struct netdev *netdev = network_get_netdev(network);
	const char *ssid = network_get_ssid(network);
	uint32_t auth_type = NL80211_AUTHTYPE_OPEN_SYSTEM;
	struct l_genl_msg *msg;

	msg = l_genl_msg_new_sized(NL80211_CMD_AUTHENTICATE, 512);
	msg_append_attr(msg, NL80211_ATTR_IFINDEX, 4, &netdev->index);
	msg_append_attr(msg, NL80211_ATTR_WIPHY_FREQ, 4, &bss->frequency);
	msg_append_attr(msg, NL80211_ATTR_MAC, ETH_ALEN, bss->addr);
	msg_append_attr(msg, NL80211_ATTR_SSID, strlen(ssid), ssid);
	msg_append_attr(msg, NL80211_ATTR_AUTH_TYPE, 4, &auth_type);
	l_genl_family_send(nl80211, msg, genl_connect_cb, netdev, NULL);

	return 0;
}

void device_connect_network(struct netdev *device, struct network *network,
				struct scan_bss *bss,
				struct l_dbus_message *message)
{
	device->connect_pending = l_dbus_message_ref(message);

	device->connected_bss = bss;
	device->connected_network = network;

	netdev_enter_state(device, DEVICE_STATE_CONNECTING);

	mlme_authenticate_cmd(network, bss);
}

static void bss_free(void *data)
{
	struct scan_bss *bss = data;

	l_debug("Freeing BSS %02X:%02X:%02X:%02X:%02X:%02X",
			bss->addr[0], bss->addr[1], bss->addr[2],
			bss->addr[3], bss->addr[4], bss->addr[5]);

	scan_bss_free(bss);
}

static void network_free(void *data)
{
	struct network *network = data;

	network_remove(network);
}

const char *device_get_path(struct netdev *netdev)
{
	static char path[12];

	snprintf(path, sizeof(path), "/%u", netdev->index);
	return path;
}

bool __iwd_device_append_properties(struct netdev *netdev,
					struct l_dbus_message_builder *builder)
{
	l_dbus_message_builder_enter_array(builder, "{sv}");

	dbus_dict_append_string(builder, "Name", netdev->name);

	if (netdev->connected_network)
		dbus_dict_append_object(builder, "ConnectedNetwork",
				network_get_path(netdev->connected_network));

	l_dbus_message_builder_leave_array(builder);

	return true;
}

void __iwd_device_foreach(iwd_device_foreach_func func, void *user_data)
{
	const struct l_queue_entry *wiphy_entry;

	for (wiphy_entry = l_queue_get_entries(wiphy_list); wiphy_entry;
					wiphy_entry = wiphy_entry->next) {
		struct wiphy *wiphy = wiphy_entry->data;
		const struct l_queue_entry *netdev_entry;

		netdev_entry = l_queue_get_entries(wiphy->netdev_list);

		while (netdev_entry) {
			struct netdev *netdev = netdev_entry->data;

			func(netdev, user_data);
			netdev_entry = netdev_entry->next;
		}
	}
}

static void device_emit_added(struct netdev *netdev)
{
	struct l_dbus *dbus = dbus_get_bus();
	struct l_dbus_message *signal;
	struct l_dbus_message_builder *builder;

	signal = l_dbus_message_new_signal(dbus, IWD_MANAGER_PATH,
						IWD_MANAGER_INTERFACE,
						"DeviceAdded");

	if (!signal)
		return;

	builder = l_dbus_message_builder_new(signal);
	if (!builder) {
		l_dbus_message_unref(signal);
		return;
	}

	l_dbus_message_builder_append_basic(builder, 'o',
						device_get_path(netdev));
	__iwd_device_append_properties(netdev, builder);

	l_dbus_message_builder_finalize(builder);
	l_dbus_message_builder_destroy(builder);
	l_dbus_send(dbus, signal);
}

static void device_emit_removed(struct netdev *netdev)
{
	struct l_dbus *dbus = dbus_get_bus();
	struct l_dbus_message *signal;

	signal = l_dbus_message_new_signal(dbus, IWD_MANAGER_PATH,
						IWD_MANAGER_INTERFACE,
						"DeviceRemoved");

	if (!signal)
		return;

	l_dbus_message_set_arguments(signal, "o", device_get_path(netdev));
	l_dbus_send(dbus, signal);
}

static void device_scan_triggered(int err, void *user_data)
{
	struct netdev *netdev = user_data;
	struct l_dbus_message *reply;

	l_debug("device_scan_triggered: %i", err);

	if (err < 0) {
		dbus_pending_reply(&netdev->scan_pending,
				dbus_error_failed(netdev->scan_pending));
		return;
	}

	l_debug("Scan triggered for netdev %s", netdev->name);

	reply = l_dbus_message_new_method_return(netdev->scan_pending);
	l_dbus_message_set_arguments(reply, "");
	dbus_pending_reply(&netdev->scan_pending, reply);
}

static struct l_dbus_message *device_scan(struct l_dbus *dbus,
						struct l_dbus_message *message,
						void *user_data)
{
	struct netdev *netdev = user_data;

	l_debug("Scan called from DBus");

	if (netdev->scan_pending)
		return dbus_error_busy(message);

	netdev->scan_pending = l_dbus_message_ref(message);

	if (!scan_passive(netdev->index, device_scan_triggered,
				new_scan_results, netdev, NULL))
		return dbus_error_failed(message);

	return NULL;
}

static void append_network_properties(const void *key, void *value,
					void *user_data)
{
	struct network *network = value;
	struct l_dbus_message_builder *builder = user_data;

	l_dbus_message_builder_enter_dict(builder, "oa{sv}");
	l_dbus_message_builder_append_basic(builder, 'o',
						network_get_path(network));
	__iwd_network_append_properties(network, builder);
	l_dbus_message_builder_leave_dict(builder);
}

static struct l_dbus_message *device_get_networks(struct l_dbus *dbus,
						struct l_dbus_message *message,
						void *user_data)
{
	struct netdev *netdev = user_data;
	struct l_dbus_message *reply;
	struct l_dbus_message_builder *builder;

	reply = l_dbus_message_new_method_return(message);
	builder = l_dbus_message_builder_new(reply);

	l_dbus_message_builder_enter_array(builder, "{oa{sv}}");
	l_hashmap_foreach(netdev->networks, append_network_properties, builder);
	l_dbus_message_builder_leave_array(builder);

	l_dbus_message_builder_finalize(builder);
	l_dbus_message_builder_destroy(builder);

	return reply;
}

static void device_disconnect_cb(struct l_genl_msg *msg, void *user_data)
{
	struct netdev *netdev = user_data;
	struct l_dbus_message *reply;

	if (l_genl_msg_get_error(msg) < 0) {
		dbus_pending_reply(&netdev->disconnect_pending,
				dbus_error_failed(netdev->disconnect_pending));
		return;
	}

	netdev_disassociated(netdev);

	reply = l_dbus_message_new_method_return(netdev->disconnect_pending);
	l_dbus_message_set_arguments(reply, "");
	dbus_pending_reply(&netdev->disconnect_pending, reply);
}

static struct l_dbus_message *device_disconnect(struct l_dbus *dbus,
						struct l_dbus_message *message,
						void *user_data)
{
	struct netdev *netdev = user_data;
	struct l_genl_msg *msg;
	uint16_t reason_code = MPDU_REASON_CODE_DEAUTH_LEAVING;
	enum security security;

	l_debug("");

	if (netdev->state == DEVICE_STATE_CONNECTING ||
			netdev->state == DEVICE_STATE_DISCONNECTING)
		return dbus_error_busy(message);

	if (!netdev->connected_bss)
		return dbus_error_not_connected(message);

	security = network_get_security(netdev->connected_network);
	if (security == SECURITY_PSK || security == SECURITY_8021X)
		eapol_cancel(netdev->index);

	msg = l_genl_msg_new_sized(NL80211_CMD_DEAUTHENTICATE, 512);
	msg_append_attr(msg, NL80211_ATTR_IFINDEX, 4, &netdev->index);
	msg_append_attr(msg, NL80211_ATTR_REASON_CODE, 2, &reason_code);
	msg_append_attr(msg, NL80211_ATTR_MAC, ETH_ALEN,
						netdev->connected_bss->addr);
	l_genl_family_send(nl80211, msg, device_disconnect_cb, netdev, NULL);

	netdev_enter_state(netdev, DEVICE_STATE_DISCONNECTING);

	netdev->disconnect_pending = l_dbus_message_ref(message);

	return NULL;
}

static bool device_property_get_name(struct l_dbus *dbus,
					struct l_dbus_message *message,
					struct l_dbus_message_builder *builder,
					void *user_data)
{
	struct netdev *netdev = user_data;

	l_dbus_message_builder_append_basic(builder, 's', netdev->name);
	return true;
}

static bool device_property_get_connected_network(struct l_dbus *dbus,
					struct l_dbus_message *message,
					struct l_dbus_message_builder *builder,
					void *user_data)
{
	struct netdev *netdev = user_data;

	if (!netdev->connected_network)
		return false;

	l_dbus_message_builder_append_basic(builder, 'o',
				network_get_path(netdev->connected_network));

	return true;
}

static void setup_device_interface(struct l_dbus_interface *interface)
{
	l_dbus_interface_method(interface, "Scan", 0,
				device_scan, "", "");
	l_dbus_interface_method(interface, "GetNetworks", 0,
				device_get_networks,
				"a{oa{sv}}", "", "networks");
	l_dbus_interface_method(interface, "Disconnect", 0,
				device_disconnect, "", "");

	l_dbus_interface_signal(interface, "NetworkAdded", 0,
				"oa{sv}", "path", "properties");
	l_dbus_interface_signal(interface, "NetworkRemoved", 0,
				"o", "path");

	l_dbus_interface_property(interface, "Name", 0, "s",
					device_property_get_name, NULL);
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

static void netdev_free(void *data)
{
	struct netdev *netdev = data;
	struct l_dbus *dbus;

	if (netdev->scan_pending)
		dbus_pending_reply(&netdev->scan_pending,
				dbus_error_aborted(netdev->scan_pending));

	if (netdev->connect_pending)
		dbus_pending_reply(&netdev->connect_pending,
				dbus_error_aborted(netdev->connect_pending));

	__device_watch_call_removed(netdev);

	dbus = dbus_get_bus();
	l_dbus_unregister_object(dbus, device_get_path(netdev));

	device_emit_removed(netdev);

	l_debug("Freeing interface %s", netdev->name);

	l_hashmap_destroy(netdev->networks, network_free);

	l_queue_destroy(netdev->bss_list, bss_free);
	l_queue_destroy(netdev->old_bss_list, bss_free);
	l_queue_destroy(netdev->autoconnect_list, l_free);
	l_io_destroy(netdev->eapol_io);

	scan_ifindex_remove(netdev->index);
	netdev_set_linkmode_and_operstate(netdev->index, 0, IF_OPER_DOWN,
					NULL, NULL);

	l_free(netdev);
}

static bool netdev_match(const void *a, const void *b)
{
	const struct netdev *netdev = a;
	uint32_t index = L_PTR_TO_UINT(b);

	return (netdev->index == index);
}

static void netdev_autoconnect_next(struct netdev *netdev)
{
	struct autoconnect_entry *entry;
	int r;

	while ((entry = l_queue_pop_head(netdev->autoconnect_list))) {
		l_debug("Considering autoconnecting to BSS '%s' with SSID: %s,"
			" freq: %u, rank: %u, strength: %i",
			scan_bss_address_to_string(entry->bss),
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
	l_queue_destroy(wiphy->netdev_list, netdev_free);
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
	struct netdev *netdev = user_data;

	/* If we were inside a .Connect(), it has failed */
	if (netdev->connect_pending)
		dbus_pending_reply(&netdev->connect_pending,
				dbus_error_failed(netdev->connect_pending));

	netdev_disassociated(netdev);
}

static void setting_keys_failed(struct netdev *netdev, uint16_t reason_code)
{
	struct l_genl_msg *msg;

	/*
	 * Something went wrong with our new_key, set_key, new_key,
	 * set_station, set_oper_state transaction
	 *
	 * Cancel all pending commands, then de-authenticate
	 */
	l_genl_family_cancel(nl80211, netdev->pairwise_new_key_cmd_id);
	netdev->pairwise_new_key_cmd_id = 0;

	l_genl_family_cancel(nl80211, netdev->pairwise_set_key_cmd_id);
	netdev->pairwise_set_key_cmd_id = 0;

	l_genl_family_cancel(nl80211, netdev->group_new_key_cmd_id);
	netdev->group_new_key_cmd_id = 0;

	eapol_cancel(netdev->index);

	msg = l_genl_msg_new_sized(NL80211_CMD_DEAUTHENTICATE, 512);
	msg_append_attr(msg, NL80211_ATTR_IFINDEX, 4, &netdev->index);
	msg_append_attr(msg, NL80211_ATTR_REASON_CODE, 2, &reason_code);
	msg_append_attr(msg, NL80211_ATTR_MAC, ETH_ALEN,
						netdev->connected_bss->addr);
	l_genl_family_send(nl80211, msg, deauthenticate_cb, netdev, NULL);
	netdev_enter_state(netdev, DEVICE_STATE_DISCONNECTING);
}

static void handshake_failed(uint32_t ifindex,
				const uint8_t *aa, const uint8_t *spa,
				uint16_t reason_code, void *user_data)
{
	struct netdev *netdev = user_data;
	struct l_genl_msg *msg;

	l_error("4-Way Handshake failed for ifindex: %d", ifindex);

	msg = l_genl_msg_new_sized(NL80211_CMD_DEAUTHENTICATE, 512);
	msg_append_attr(msg, NL80211_ATTR_IFINDEX, 4, &ifindex);
	msg_append_attr(msg, NL80211_ATTR_REASON_CODE, 2, &reason_code);
	msg_append_attr(msg, NL80211_ATTR_MAC, ETH_ALEN, aa);
	l_genl_family_send(nl80211, msg, deauthenticate_cb, netdev, NULL);
	netdev_enter_state(netdev, DEVICE_STATE_DISCONNECTING);
}

static void mlme_set_pairwise_key_cb(struct l_genl_msg *msg, void *data)
{
	struct netdev *netdev = data;

	netdev->pairwise_set_key_cmd_id = 0;

	if (l_genl_msg_get_error(msg) < 0) {
		l_error("Set Key for Pairwise Key failed for ifindex: %d",
				netdev->index);
		setting_keys_failed(netdev, MPDU_REASON_CODE_UNSPECIFIED);
		return;
	}
}

static unsigned int mlme_set_pairwise_key(struct netdev *netdev)
{
	uint8_t key_id = 0;
	struct l_genl_msg *msg;
	unsigned int id;

	msg = l_genl_msg_new_sized(NL80211_CMD_SET_KEY, 512);
	if (!msg)
		return 0;

	l_genl_msg_append_attr(msg, NL80211_ATTR_KEY_IDX, 1, &key_id);
	l_genl_msg_append_attr(msg, NL80211_ATTR_IFINDEX, 4, &netdev->index);

	l_genl_msg_append_attr(msg, NL80211_ATTR_KEY_DEFAULT, 0, NULL);

	l_genl_msg_enter_nested(msg, NL80211_ATTR_KEY_DEFAULT_TYPES);
	l_genl_msg_append_attr(msg, NL80211_KEY_DEFAULT_TYPE_UNICAST, 0, NULL);
	l_genl_msg_leave_nested(msg);

	id = l_genl_family_send(nl80211, msg, mlme_set_pairwise_key_cb,
					netdev, NULL);
	if (!id)
		l_genl_msg_unref(msg);

	return id;
}

static void mlme_new_pairwise_key_cb(struct l_genl_msg *msg, void *data)
{
	struct netdev *netdev = data;

	netdev->pairwise_new_key_cmd_id = 0;

	if (l_genl_msg_get_error(msg) < 0) {
		l_error("New Key for Pairwise Key failed for ifindex: %d",
				netdev->index);
		setting_keys_failed(netdev, MPDU_REASON_CODE_UNSPECIFIED);
		return;
	}
}

static unsigned int mlme_new_pairwise_key(struct netdev *netdev,
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
	l_genl_msg_append_attr(msg, NL80211_ATTR_IFINDEX, 4, &netdev->index);

	id = l_genl_family_send(nl80211, msg, mlme_new_pairwise_key_cb,
					netdev, NULL);
	if (!id)
		l_genl_msg_unref(msg);

	return id;
}

static void wiphy_set_tk(uint32_t ifindex, const uint8_t *aa,
				const uint8_t *tk, uint32_t cipher,
				void *user_data)
{
	struct netdev *netdev = user_data;
	struct network *network = netdev->connected_network;
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
		setting_keys_failed(netdev,
				MPDU_REASON_CODE_INVALID_PAIRWISE_CIPHER);
		return;
	}

	/* If we got here, then our PSK works.  Save if required */
	network_sync_psk(network);

	netdev->pairwise_new_key_cmd_id =
		mlme_new_pairwise_key(netdev, cipher, aa,
					tk_buf, crypto_cipher_key_len(cipher));
	netdev->pairwise_set_key_cmd_id = mlme_set_pairwise_key(netdev);
}

static void operstate_cb(bool result, void *user_data)
{
	struct netdev *netdev = user_data;

	if (!result) {
		l_error("Setting LinkMode and OperState failed for ifindex %d",
			netdev->index);
		setting_keys_failed(netdev, MPDU_REASON_CODE_UNSPECIFIED);
		return;
	}

	if (netdev->connect_pending) {
		struct l_dbus_message *reply;

		reply = l_dbus_message_new_method_return(
						netdev->connect_pending);
		l_dbus_message_set_arguments(reply, "");
		dbus_pending_reply(&netdev->connect_pending, reply);
	}

	network_connected(network_get_security(netdev->connected_network),
				network_get_ssid(netdev->connected_network));
	netdev_enter_state(netdev, DEVICE_STATE_CONNECTED);
}

static void set_station_cb(struct l_genl_msg *msg, void *user_data)
{
	struct netdev *netdev = user_data;

	if (l_genl_msg_get_error(msg) < 0) {
		l_error("Set Station failed for ifindex %d", netdev->index);
		setting_keys_failed(netdev, MPDU_REASON_CODE_UNSPECIFIED);
		return;
	}

	netdev_set_linkmode_and_operstate(netdev->index, 1, IF_OPER_UP,
					operstate_cb, netdev);
}

static int set_station_cmd(struct netdev *netdev)
{
	struct scan_bss *bss = netdev->connected_bss;
	struct l_genl_msg *msg;
	struct nl80211_sta_flag_update flags;

	flags.mask = 1 << NL80211_STA_FLAG_AUTHORIZED;
	flags.set = flags.mask;

	msg = l_genl_msg_new_sized(NL80211_CMD_SET_STATION, 512);
	msg_append_attr(msg, NL80211_ATTR_IFINDEX, 4, &netdev->index);
	msg_append_attr(msg, NL80211_ATTR_MAC, ETH_ALEN, bss->addr);
	msg_append_attr(msg, NL80211_ATTR_STA_FLAGS2,
			sizeof(struct nl80211_sta_flag_update), &flags);
	l_genl_family_send(nl80211, msg, set_station_cb, netdev, NULL);

	return 0;
}

static void mlme_new_group_key_cb(struct l_genl_msg *msg, void *data)
{
	struct netdev *netdev = data;

	netdev->group_new_key_cmd_id = 0;

	if (l_genl_msg_get_error(msg) < 0) {
		l_error("New Key for Group Key failed for ifindex: %d",
				netdev->index);
		setting_keys_failed(netdev, MPDU_REASON_CODE_UNSPECIFIED);
		return;
	}

	set_station_cmd(netdev);
}

static unsigned int mlme_new_group_key(struct netdev *netdev,
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
	l_genl_msg_append_attr(msg, NL80211_ATTR_IFINDEX, 4, &netdev->index);

	id = l_genl_family_send(nl80211, msg, mlme_new_group_key_cb,
					netdev, NULL);
	if (!id)
		l_genl_msg_unref(msg);

	return id;
}

static void wiphy_set_gtk(uint32_t ifindex, uint8_t key_index,
				const uint8_t *gtk, uint8_t gtk_len,
				const uint8_t *rsc, uint8_t rsc_len,
				uint32_t cipher, void *user_data)
{
	struct netdev *netdev = user_data;
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
		setting_keys_failed(netdev,
					MPDU_REASON_CODE_INVALID_GROUP_CIPHER);
		return;
	}

	if (crypto_cipher_key_len(cipher) != gtk_len) {
		l_error("Unexpected key length: %d", gtk_len);
		setting_keys_failed(netdev,
					MPDU_REASON_CODE_INVALID_GROUP_CIPHER);
		return;
	}

	netdev->group_new_key_cmd_id =
			mlme_new_group_key(netdev, cipher, key_index,
					gtk_buf, gtk_len, rsc, rsc_len);
}

static void mlme_associate_event(struct l_genl_msg *msg, struct netdev *netdev)
{
	int err;

	l_debug("");

	err = l_genl_msg_get_error(msg);
	if (err < 0) {
		l_error("association failed %s (%d)", strerror(-err), err);
		dbus_pending_reply(&netdev->connect_pending,
				dbus_error_failed(netdev->connect_pending));
		netdev_disassociated(netdev);
		return;
	}

	l_info("Association completed");

	if (network_get_security(netdev->connected_network) == SECURITY_NONE)
		netdev_set_linkmode_and_operstate(netdev->index, 1, IF_OPER_UP,
						operstate_cb, netdev);
}

static void genl_associate_cb(struct l_genl_msg *msg, void *user_data)
{
	struct netdev *netdev = user_data;

	if (l_genl_msg_get_error(msg) < 0 && netdev->connect_pending)
		dbus_pending_reply(&netdev->connect_pending,
				dbus_error_failed(netdev->connect_pending));
}

static void mlme_associate_cmd(struct netdev *netdev)
{
	struct l_genl_msg *msg;
	struct scan_bss *bss = netdev->connected_bss;
	struct network *network = netdev->connected_network;
	struct wiphy *wiphy = netdev->wiphy;
	const char *ssid = network_get_ssid(network);
	enum security security = network_get_security(network);

	l_debug("");

	msg = l_genl_msg_new_sized(NL80211_CMD_ASSOCIATE, 512);
	msg_append_attr(msg, NL80211_ATTR_IFINDEX, 4, &netdev->index);
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
		eapol_sm_set_supplicant_address(sm, netdev->addr);
		eapol_sm_set_user_data(sm, netdev);
		eapol_sm_set_tx_user_data(sm,
				L_INT_TO_PTR(l_io_get_fd(netdev->eapol_io)));
		eapol_start(netdev->index, sm);

		msg_append_attr(msg, NL80211_ATTR_CIPHER_SUITES_PAIRWISE,
				4, &pairwise_cipher_attr);
		msg_append_attr(msg, NL80211_ATTR_CIPHER_SUITE_GROUP,
				4, &group_cipher_attr);

		msg_append_attr(msg, NL80211_ATTR_CONTROL_PORT, 0, NULL);
		msg_append_attr(msg, NL80211_ATTR_IE,
					rsne_buf[1] + 2, rsne_buf);
	}

	l_genl_family_send(nl80211, msg, genl_associate_cb, netdev, NULL);
}

static void mlme_authenticate_event(struct l_genl_msg *msg,
							struct netdev *netdev)
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
	mlme_associate_cmd(netdev);
	return;

error:
	if (netdev->connect_pending)
		dbus_pending_reply(&netdev->connect_pending,
				dbus_error_failed(netdev->connect_pending));

	netdev_disassociated(netdev);
}

static void mlme_deauthenticate_event(struct l_genl_msg *msg,
							struct netdev *netdev)
{
	l_debug("");
}

static void mlme_disconnect_event(struct l_genl_msg *msg,
					struct netdev *netdev)
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

	if (netdev->connect_pending) {
		struct network *network = netdev->connected_network;

		dbus_pending_reply(&netdev->connect_pending,
				dbus_error_failed(netdev->connect_pending));

		network_connect_failed(network);
	}

	netdev_disassociated(netdev);
}

static void mlme_cqm_event(struct l_genl_msg *msg, struct netdev *netdev)
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
					netdev_lost_beacon(netdev);
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

	l_queue_destroy(network->bss_list, NULL);
	network->bss_list = l_queue_new();
}

static bool network_remove_if_lost(const void *key, void *data, void *user_data)
{
	struct network *network = data;

	if (!l_queue_isempty(network->bss_list))
		return false;

	l_debug("No remaining BSSs for SSID: %s -- Removing network",
			network_get_ssid(network));
	network_free(network);

	return true;
}

static int autoconnect_rank_compare(const void *a, const void *b, void *user)
{
	const struct autoconnect_entry *new_ae = a;
	const struct autoconnect_entry *ae = b;

	return ae->rank - new_ae->rank;
}

static void process_bss(struct netdev *netdev, struct scan_bss *bss)
{
	struct network *network;
	enum security security;
	const char *path;
	double rankmod;
	struct autoconnect_entry *entry;

	l_debug("Found BSS '%s' with SSID: %s, freq: %u, rank: %u, "
			"strength: %i",
			scan_bss_address_to_string(bss),
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

	path = iwd_network_get_path(netdev, bss->ssid, bss->ssid_len,
					security);

	network = l_hashmap_lookup(netdev->networks, path);
	if (!network) {
		network = network_create(netdev, bss->ssid, bss->ssid_len,
						security);

		if (!network_register(network, path)) {
			network_remove(network);
			return;
		}

		l_hashmap_insert(netdev->networks,
					network_get_path(network), network);
		l_debug("Added new Network \"%s\" security %s",
			network_get_ssid(network), security_to_str(security));

		network_seen(security, network_get_ssid(network));
	}

	l_queue_insert(network->bss_list, bss, scan_bss_rank_compare, NULL);

	rankmod = network_rankmod(security, network_get_ssid(network));
	if (rankmod == 0.0)
		return;

	entry = l_new(struct autoconnect_entry, 1);
	entry->network = network;
	entry->bss = bss;
	entry->rank = bss->rank * rankmod;
	l_queue_insert(netdev->autoconnect_list, entry,
				autoconnect_rank_compare, NULL);
}

static bool new_scan_results(uint32_t wiphy_id, uint32_t ifindex,
				struct l_queue *bss_list, void *userdata)
{
	struct netdev *netdev = userdata;
	const struct l_queue_entry *bss_entry;

	netdev->old_bss_list = netdev->bss_list;
	netdev->bss_list = bss_list;
	l_hashmap_foreach(netdev->networks, network_reset_bss_list, NULL);

	l_queue_destroy(netdev->autoconnect_list, l_free);
	netdev->autoconnect_list = l_queue_new();

	for (bss_entry = l_queue_get_entries(bss_list); bss_entry;
				bss_entry = bss_entry->next) {
		struct scan_bss *bss = bss_entry->data;

		process_bss(netdev, bss);
	}

	if (netdev->connected_bss) {
		struct scan_bss *bss;

		bss = l_queue_find(netdev->bss_list, bss_match,
						netdev->connected_bss);

		if (!bss) {
			l_warn("Connected BSS not in scan results!");
			l_queue_push_tail(netdev->bss_list,
						netdev->connected_bss);
			l_queue_push_tail(netdev->connected_network->bss_list,
						netdev->connected_bss);
			l_queue_remove(netdev->old_bss_list,
						netdev->connected_bss);
		} else
			netdev->connected_bss = bss;
	}

	l_hashmap_foreach_remove(netdev->networks,
					network_remove_if_lost, NULL);

	l_queue_destroy(netdev->old_bss_list, bss_free);
	netdev->old_bss_list = NULL;

	if (netdev->state == DEVICE_STATE_AUTOCONNECT)
		netdev_autoconnect_next(netdev);

	return true;
}

static void interface_dump_callback(struct l_genl_msg *msg, void *user_data)
{
	struct wiphy *wiphy = NULL;
	struct netdev *netdev;
	struct l_genl_attr attr;
	uint16_t type, len;
	const void *data;
	char ifname[IFNAMSIZ];
	uint8_t ifaddr[ETH_ALEN];
	uint32_t ifindex, iftype;

	if (!l_genl_attr_init(&attr, msg))
		return;

	memset(ifname, 0, sizeof(ifname));
	memset(ifaddr, 0, sizeof(ifaddr));
	iftype = NL80211_IFTYPE_UNSPECIFIED;
	ifindex = 0;

	/*
	 * The interface index and interface name attributes are normally
	 * listed before the wiphy attribute. This handling assumes that
	 * all attributes are included in the same message.
	 *
	 * If any required attribute is missing, the whole message will
	 * be ignored.
	 */
	while (l_genl_attr_next(&attr, &type, &len, &data)) {
		switch (type) {
		case NL80211_ATTR_IFINDEX:
			if (len != sizeof(uint32_t)) {
				l_warn("Invalid interface index attribute");
				return;
			}

			ifindex = *((uint32_t *) data);
			break;

		case NL80211_ATTR_IFNAME:
			if (len > sizeof(ifname)) {
				l_warn("Invalid interface name attribute");
				return;
			}

			memcpy(ifname, data, len);
			break;

		case NL80211_ATTR_WIPHY:
			if (len != sizeof(uint32_t)) {
				l_warn("Invalid wiphy attribute");
				return;
			}

			wiphy = l_queue_find(wiphy_list, wiphy_match,
					L_UINT_TO_PTR(*((uint32_t *) data)));
			break;

		case NL80211_ATTR_IFTYPE:
			if (len != sizeof(uint32_t)) {
				l_warn("Invalid interface type attribute");
				return;
			}

			iftype = *((uint32_t *) data);
			break;

		case NL80211_ATTR_MAC:
			if (len != sizeof(ifaddr)) {
				l_warn("Invalid interface address attribute");
				return;
			}

			memcpy(ifaddr, data, len);
			break;
		}
	}

	if (!wiphy) {
		l_warn("Missing wiphy attribute or wiphy not found");
		return;
	}

	if (!ifindex) {
		l_warn("Missing interface index attribute");
		return;
	}

	netdev = l_queue_find(wiphy->netdev_list, netdev_match,
						L_UINT_TO_PTR(ifindex));
	if (!netdev) {
		struct l_dbus *dbus = dbus_get_bus();

		netdev = l_new(struct netdev, 1);
		netdev->bss_list = l_queue_new();
		netdev->networks = l_hashmap_new();
		l_hashmap_set_hash_function(netdev->networks, l_str_hash);
		l_hashmap_set_compare_function(netdev->networks,
					(l_hashmap_compare_func_t) strcmp);
		memcpy(netdev->name, ifname, sizeof(netdev->name));
		memcpy(netdev->addr, ifaddr, sizeof(netdev->addr));
		netdev->index = ifindex;
		netdev->type = iftype;
		netdev->wiphy = wiphy;

		l_queue_push_head(wiphy->netdev_list, netdev);

		if (!l_dbus_object_add_interface(dbus,
						device_get_path(netdev),
						IWD_DEVICE_INTERFACE, netdev))
			l_info("Unable to register %s interface",
				IWD_DEVICE_INTERFACE);
		else {
			__device_watch_call_added(netdev);
			device_emit_added(netdev);
		}

		netdev_set_linkmode_and_operstate(netdev->index, 1,
						IF_OPER_DORMANT, NULL, NULL);

		scan_ifindex_add(netdev->index);
		netdev_enter_state(netdev, DEVICE_STATE_AUTOCONNECT);
	}

	l_debug("Found interface %s", netdev->name);

	netdev->eapol_io = eapol_open_pae(netdev->index);
	if (!netdev->eapol_io) {
		l_error("Failed to open PAE socket");
		return;
	}

	l_io_set_read_handler(netdev->eapol_io, eapol_read, netdev, NULL);
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
				wiphy->netdev_list = l_queue_new();
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

	while (l_genl_attr_next(&attr, &type, &len, &data)) {
	}
}

static void wiphy_mlme_notify(struct l_genl_msg *msg, void *user_data)
{
	struct wiphy *wiphy = NULL;
	struct netdev *netdev = NULL;
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

			netdev = l_queue_find(wiphy->netdev_list, netdev_match,
					L_UINT_TO_PTR(*((uint32_t *) data)));
			if (!netdev) {
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

	if (!netdev) {
		l_warn("MLME notification is missing interface attribute");
		return;
	}


	switch (cmd) {
	case NL80211_CMD_AUTHENTICATE:
		mlme_authenticate_event(msg, netdev);
		break;
	case NL80211_CMD_ASSOCIATE:
		mlme_associate_event(msg, netdev);
		break;
	case NL80211_CMD_DEAUTHENTICATE:
		mlme_deauthenticate_event(msg, netdev);
		break;
	case NL80211_CMD_DISCONNECT:
		mlme_disconnect_event(msg, netdev);
		break;
	case NL80211_CMD_NOTIFY_CQM:
		mlme_cqm_event(msg, netdev);
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

	msg = l_genl_msg_new(NL80211_CMD_GET_INTERFACE);
	if (!l_genl_family_dump(nl80211, msg, interface_dump_callback,
								NULL, NULL))
		l_error("Getting all interface information failed");

	return true;
}

bool wiphy_exit(void)
{
	l_queue_destroy(wiphy_list, wiphy_free);
	wiphy_list = NULL;

	nl80211 = NULL;

	l_dbus_unregister_interface(dbus_get_bus(), IWD_DEVICE_INTERFACE);

	return true;
}

static void wiphy_check_dellink(void *data, void *user_data)
{
	uint32_t index = L_PTR_TO_UINT(user_data);
	struct wiphy *wiphy = data;
	struct netdev *netdev;

	netdev = l_queue_remove_if(wiphy->netdev_list, netdev_match,
						L_UINT_TO_PTR(index));
	if (netdev) {
		l_warn("Removing leftover interface %s", netdev->name);
		netdev_free(netdev);
	}
}

void wiphy_notify_dellink(uint32_t index)
{
	if (!wiphy_list)
		return;

	l_queue_foreach(wiphy_list, wiphy_check_dellink, L_UINT_TO_PTR(index));
}
