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
#include "src/eapol.h"
#include "src/agent.h"
#include "src/crypto.h"

static struct l_genl *genl = NULL;
static struct l_genl_family *nl80211 = NULL;
static int scheduled_scan_interval = 60;	/* in secs */

struct network {
	char *object_path;
	struct netdev *netdev;
	uint8_t ssid[32];
	uint8_t ssid_len;
	unsigned char *psk;
	unsigned int agent_request;
	enum scan_ssid_security ssid_security;
	struct l_queue *bss_list;
};

struct bss {
	struct network *network;
	uint8_t addr[ETH_ALEN];
	uint32_t frequency;
	int32_t signal_strength;
	uint16_t capability;
	uint8_t *rsne;
	uint8_t *wpa;
};

struct netdev {
	uint32_t index;
	char name[IFNAMSIZ];
	uint32_t type;
	uint8_t addr[ETH_ALEN];
	struct l_queue *bss_list;
	struct l_queue *old_bss_list;
	struct l_dbus_message *scan_pending;
	struct l_hashmap *networks;
	struct bss *connected_bss;
	struct l_dbus_message *connect_pending;
	struct l_io *eapol_io;
};

struct wiphy {
	uint32_t id;
	char name[20];
	uint32_t feature_flags;
	struct l_queue *netdev_list;
	bool support_scheduled_scan;
};

static struct l_queue *wiphy_list = NULL;

/*
 * WLAN reason codes from Linux kernel ieee80211.h file.
*/
enum ieee80211_reasoncode {
	WLAN_REASON_UNSPECIFIED = 1,
	WLAN_REASON_PREV_AUTH_NOT_VALID = 2,
	WLAN_REASON_DEAUTH_LEAVING = 3,
	WLAN_REASON_DISASSOC_DUE_TO_INACTIVITY = 4,
	WLAN_REASON_DISASSOC_AP_BUSY = 5,
	WLAN_REASON_CLASS2_FRAME_FROM_NONAUTH_STA = 6,
	WLAN_REASON_CLASS3_FRAME_FROM_NONASSOC_STA = 7,
	WLAN_REASON_DISASSOC_STA_HAS_LEFT = 8,
	WLAN_REASON_STA_REQ_ASSOC_WITHOUT_AUTH = 9,
	/* 802.11h */
	WLAN_REASON_DISASSOC_BAD_POWER = 10,
	WLAN_REASON_DISASSOC_BAD_SUPP_CHAN = 11,
	/* 802.11i */
	WLAN_REASON_INVALID_IE = 13,
	WLAN_REASON_MIC_FAILURE = 14,
	WLAN_REASON_4WAY_HANDSHAKE_TIMEOUT = 15,
	WLAN_REASON_GROUP_KEY_HANDSHAKE_TIMEOUT = 16,
	WLAN_REASON_IE_DIFFERENT = 17,
	WLAN_REASON_INVALID_GROUP_CIPHER = 18,
	WLAN_REASON_INVALID_PAIRWISE_CIPHER = 19,
	WLAN_REASON_INVALID_AKMP = 20,
	WLAN_REASON_UNSUPP_RSN_VERSION = 21,
	WLAN_REASON_INVALID_RSN_IE_CAP = 22,
	WLAN_REASON_IEEE8021X_FAILED = 23,
	WLAN_REASON_CIPHER_SUITE_REJECTED = 24,
	/* TDLS (802.11z) */
	WLAN_REASON_TDLS_TEARDOWN_UNREACHABLE = 25,
	WLAN_REASON_TDLS_TEARDOWN_UNSPECIFIED = 26,
	/* 802.11e */
	WLAN_REASON_DISASSOC_UNSPECIFIED_QOS = 32,
	WLAN_REASON_DISASSOC_QAP_NO_BANDWIDTH = 33,
	WLAN_REASON_DISASSOC_LOW_ACK = 34,
	WLAN_REASON_DISASSOC_QAP_EXCEED_TXOP = 35,
	WLAN_REASON_QSTA_LEAVE_QBSS = 36,
	WLAN_REASON_QSTA_NOT_USE = 37,
	WLAN_REASON_QSTA_REQUIRE_SETUP = 38,
	WLAN_REASON_QSTA_TIMEOUT = 39,
	WLAN_REASON_QSTA_CIPHER_NOT_SUPP = 45,
	/* 802.11s */
	WLAN_REASON_MESH_PEER_CANCELED = 52,
	WLAN_REASON_MESH_MAX_PEERS = 53,
	WLAN_REASON_MESH_CONFIG = 54,
	WLAN_REASON_MESH_CLOSE = 55,
	WLAN_REASON_MESH_MAX_RETRIES = 56,
	WLAN_REASON_MESH_CONFIRM_TIMEOUT = 57,
	WLAN_REASON_MESH_INVALID_GTK = 58,
	WLAN_REASON_MESH_INCONSISTENT_PARAM = 59,
	WLAN_REASON_MESH_INVALID_SECURITY = 60,
	WLAN_REASON_MESH_PATH_ERROR = 61,
	WLAN_REASON_MESH_PATH_NOFORWARD = 62,
	WLAN_REASON_MESH_PATH_DEST_UNREACHABLE = 63,
	WLAN_REASON_MAC_EXISTS_IN_MBSS = 64,
	WLAN_REASON_MESH_CHAN_REGULATORY = 65,
	WLAN_REASON_MESH_CHAN = 66,
};

static void do_debug(const char *str, void *user_data)
{
	const char *prefix = user_data;

	l_info("%s%s", prefix, str);
}

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
				frame, bytes, L_INT_TO_PTR(fd));

	return true;
}

static const char *ssid_security_to_str(enum scan_ssid_security ssid_security)
{
	switch (ssid_security) {
	case SCAN_SSID_SECURITY_NONE:
		return "open";
	case SCAN_SSID_SECURITY_WEP:
		return "wep";
	case SCAN_SSID_SECURITY_PSK:
		return "psk";
	case SCAN_SSID_SECURITY_8021X:
		return "8021x";
	}

	return NULL;
}

static const char *iwd_network_get_path(struct netdev *netdev,
					const uint8_t *ssid, size_t ssid_len,
					enum scan_ssid_security ssid_security)
{
	static char path[256];
	unsigned int pos, i;

	pos = snprintf(path, sizeof(path), "%s/", iwd_device_get_path(netdev));

	for (i = 0; i < ssid_len && pos < sizeof(path); i++)
		pos += snprintf(path + pos, sizeof(path) - pos, "%02x",
								ssid[i]);

	snprintf(path + pos, sizeof(path) - pos, "_%s",
			ssid_security_to_str(ssid_security));

	return path;
}

static bool __iwd_network_append_properties(const struct network *network,
					struct l_dbus_message_builder *builder)
{
	l_dbus_message_builder_enter_array(builder, "{sv}");

	dbus_dict_append_bytearray(builder, "SSID", network->ssid,
						network->ssid_len);

	l_dbus_message_builder_leave_array(builder);

	return true;
}

static struct l_dbus_message *network_get_properties(struct l_dbus *dbus,
						struct l_dbus_message *message,
						void *user_data)
{
	struct network *network = user_data;
	struct l_dbus_message *reply;
	struct l_dbus_message_builder *builder;

	reply = l_dbus_message_new_method_return(message);

	builder = l_dbus_message_builder_new(reply);

	__iwd_network_append_properties(network, builder);
	l_dbus_message_builder_finalize(builder);
	l_dbus_message_builder_destroy(builder);

	return reply;
}

static void genl_connect_cb(struct l_genl_msg *msg, void *user_data)
{
	struct netdev *netdev = user_data;

	if (l_genl_msg_get_error(msg) < 0 && netdev->connect_pending)
		dbus_pending_reply(&netdev->connect_pending,
				dbus_error_failed(netdev->connect_pending));
}

static int mlme_authenticate_cmd(struct network *network)
{
	struct netdev *netdev = network->netdev;
	struct bss *bss = l_queue_peek_head(network->bss_list);
	uint32_t auth_type = NL80211_AUTHTYPE_OPEN_SYSTEM;
	struct l_genl_msg *msg;

	msg = l_genl_msg_new_sized(NL80211_CMD_AUTHENTICATE, 512);
	msg_append_attr(msg, NL80211_ATTR_IFINDEX, 4, &netdev->index);
	msg_append_attr(msg, NL80211_ATTR_WIPHY_FREQ, 4, &bss->frequency);
	msg_append_attr(msg, NL80211_ATTR_MAC, ETH_ALEN, bss->addr);
	msg_append_attr(msg, NL80211_ATTR_SSID, network->ssid_len,
			network->ssid);
	msg_append_attr(msg, NL80211_ATTR_AUTH_TYPE, 4, &auth_type);
	l_genl_family_send(nl80211, msg, genl_connect_cb, netdev, NULL);

	netdev->connected_bss = bss;

	return 0;
}

static void passphrase_callback(enum agent_result result,
				const char *passphrase, void *user_data)
{
	struct network *network = user_data;
	struct netdev *netdev = network->netdev;

	l_debug("result %d", result);

	network->agent_request = 0;

	if (result != AGENT_RESULT_OK) {
		dbus_pending_reply(&netdev->connect_pending,
				dbus_error_aborted(netdev->connect_pending));

		return;
	}

	network->psk = l_malloc(32);

	if (crypto_psk_from_passphrase(passphrase, network->ssid,
					network->ssid_len, network->psk) < 0) {
		dbus_pending_reply(&netdev->connect_pending,
				dbus_error_failed(netdev->connect_pending));

		l_free(network->psk);
		network->psk = NULL;

		return;
	}

	mlme_authenticate_cmd(network);
}

static struct l_dbus_message *network_connect(struct l_dbus *dbus,
						struct l_dbus_message *message,
						void *user_data)
{
	struct network *network = user_data;
	struct netdev *netdev = network->netdev;

	l_debug("");

	if (netdev->connect_pending)
		return dbus_error_busy(message);

	switch (network->ssid_security) {
	case SCAN_SSID_SECURITY_PSK:
		if (!network->psk) {
			network->agent_request =
				agent_request_passphrase(
						network->object_path,
						passphrase_callback,
						network);
			break;
		}

		/* fall through */
	case SCAN_SSID_SECURITY_NONE:
		mlme_authenticate_cmd(network);
		break;

	default:
		return dbus_error_not_supported(message);
	}

	netdev->connect_pending = l_dbus_message_ref(message);

	return NULL;
}

static void setup_network_interface(struct l_dbus_interface *interface)
{
	l_dbus_interface_method(interface, "GetProperties", 0,
				network_get_properties,
				"a{sv}", "", "properties");
	l_dbus_interface_method(interface, "Connect", 0,
				network_connect,
				"", "");

	l_dbus_interface_signal(interface, "PropertyChanged", 0,
				"sv", "name", "value");

	l_dbus_interface_ro_property(interface, "Name", "s");
}

static void network_emit_added(struct network *network)
{
	struct l_dbus *dbus = dbus_get_bus();
	struct l_dbus_message *signal;
	struct l_dbus_message_builder *builder;

	signal = l_dbus_message_new_signal(dbus,
					iwd_device_get_path(network->netdev),
					IWD_DEVICE_INTERFACE,
					"NetworkAdded");

	if (!signal)
		return;

	builder = l_dbus_message_builder_new(signal);
	if (!builder) {
		l_dbus_message_unref(signal);
		return;
	}

	l_dbus_message_builder_append_basic(builder, 'o',
						network->object_path);
	__iwd_network_append_properties(network, builder);

	l_dbus_message_builder_finalize(builder);
	l_dbus_message_builder_destroy(builder);
	l_dbus_send(dbus, signal);
}

static void network_emit_removed(struct network *network)
{
	struct l_dbus *dbus = dbus_get_bus();
	struct l_dbus_message *signal;

	signal = l_dbus_message_new_signal(dbus,
					iwd_device_get_path(network->netdev),
					IWD_DEVICE_INTERFACE,
					"NetworkRemoved");

	if (!signal)
		return;

	l_dbus_message_set_arguments(signal, "o", network->object_path);
	l_dbus_send(dbus, signal);
}

static void bss_free(void *data)
{
	struct bss *bss = data;

	l_debug("Freeing BSS %02X:%02X:%02X:%02X:%02X:%02X",
			bss->addr[0], bss->addr[1], bss->addr[2],
			bss->addr[3], bss->addr[4], bss->addr[5]);
	l_free(bss->rsne);
	l_free(bss->wpa);
	l_free(bss);
}

static void network_free(void *data)
{
	struct network *network = data;
	struct l_dbus *dbus;

	agent_request_cancel(network->agent_request);

	dbus = dbus_get_bus();
	l_dbus_unregister_interface(dbus, network->object_path,
					IWD_NETWORK_INTERFACE);
	network_emit_removed(network);

	l_free(network->object_path);

	l_queue_destroy(network->bss_list, NULL);
	l_free(network->psk);
	l_free(network);
}

const char *iwd_device_get_path(struct netdev *netdev)
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
						iwd_device_get_path(netdev));
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

	l_dbus_message_set_arguments(signal, "o", iwd_device_get_path(netdev));
	l_dbus_send(dbus, signal);
}

static struct l_dbus_message *device_set_property(struct l_dbus *dbus,
						struct l_dbus_message *message,
						void *user_data)
{
	const char *property;
	struct l_dbus_message_iter variant;

	if (!l_dbus_message_get_arguments(message, "sv", &property, &variant))
		return l_dbus_message_new_error(message,
						"org.test.InvalidArguments",
						"Invalid arguments");

	return l_dbus_message_new_error(message, "org.test.InvalidArguments",
					"Unknown Property %s", property);
}

static struct l_dbus_message *device_get_properties(struct l_dbus *dbus,
						struct l_dbus_message *message,
						void *user_data)
{
	struct netdev *netdev = user_data;
	struct l_dbus_message *reply;
	struct l_dbus_message_builder *builder;

	reply = l_dbus_message_new_method_return(message);

	builder = l_dbus_message_builder_new(reply);

	__iwd_device_append_properties(netdev, builder);
	l_dbus_message_builder_finalize(builder);
	l_dbus_message_builder_destroy(builder);

	return reply;
}

static void device_scan_callback(struct l_genl_msg *msg, void *user_data)
{
	struct netdev *netdev = user_data;
	struct l_dbus_message *reply;

	l_debug("Scan callback");

	if (l_genl_msg_get_error(msg) < 0) {
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

	scan_start(nl80211, netdev->index, device_scan_callback, netdev);

	return NULL;
}

static void append_network_properties(const void *key, void *value,
					void *user_data)
{
	struct network *network = value;
	struct l_dbus_message_builder *builder = user_data;

	l_dbus_message_builder_enter_dict(builder, "oa{sv}");
	l_dbus_message_builder_append_basic(builder, 'o',
						network->object_path);
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

static void genl_disconnect_cb(struct l_genl_msg *msg, void *user_data)
{
	struct netdev *netdev = user_data;

	if (l_genl_msg_get_error(msg) < 0 && netdev->connect_pending)
		dbus_pending_reply(&netdev->connect_pending,
				dbus_error_failed(netdev->connect_pending));
}

static struct l_dbus_message *device_disconnect(struct l_dbus *dbus,
						struct l_dbus_message *message,
						void *user_data)
{
	struct netdev *netdev = user_data;
	struct l_genl_msg *msg;
	uint16_t reason_code = WLAN_REASON_DEAUTH_LEAVING;

	l_debug("");

	if (netdev->connect_pending)
		return dbus_error_failed(message);

	if (!netdev->connected_bss)
		return dbus_error_failed(message);

	msg = l_genl_msg_new_sized(NL80211_CMD_DEAUTHENTICATE, 512);
	msg_append_attr(msg, NL80211_ATTR_IFINDEX, 4, &netdev->index);
	msg_append_attr(msg, NL80211_ATTR_REASON_CODE, 2, &reason_code);
	msg_append_attr(msg, NL80211_ATTR_MAC, ETH_ALEN,
						netdev->connected_bss->addr);
	l_genl_family_send(nl80211, msg, genl_disconnect_cb, netdev, NULL);

	netdev->connect_pending = l_dbus_message_ref(message);

	return NULL;
}

static void setup_device_interface(struct l_dbus_interface *interface)
{
	l_dbus_interface_method(interface, "GetProperties", 0,
				device_get_properties,
				"a{sv}", "", "properties");
	l_dbus_interface_method(interface, "SetProperty", 0,
				device_set_property,
				"", "sv", "name", "value");
	l_dbus_interface_method(interface, "Scan", 0,
				device_scan, "", "");
	l_dbus_interface_method(interface, "GetNetworks", 0,
				device_get_networks,
				"a{oa{sv}}", "", "networks");
	l_dbus_interface_method(interface, "Disconnect", 0,
				device_disconnect, "", "");

	l_dbus_interface_signal(interface, "PropertyChanged", 0,
				"sv", "name", "value");
	l_dbus_interface_signal(interface, "NetworkAdded", 0,
				"oa{sv}", "path", "properties");
	l_dbus_interface_signal(interface, "NetworkRemoved", 0,
				"o", "path");

	l_dbus_interface_ro_property(interface, "Name", "s");
}

static const char *bss_address_to_string(const struct bss *bss)
{
	static char buf[32];

	snprintf(buf, sizeof(buf), "%02X:%02X:%02X:%02X:%02X:%02X",
			bss->addr[0], bss->addr[1], bss->addr[2],
			bss->addr[3], bss->addr[4], bss->addr[5]);

	return buf;
}

static bool bss_match(const void *a, const void *b)
{
	const struct bss *bss_a = a;
	const struct bss *bss_b = b;

	if (bss_a->network != bss_b->network)
		return false;

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

	dbus = dbus_get_bus();
	l_dbus_unregister_interface(dbus, iwd_device_get_path(netdev),
					IWD_DEVICE_INTERFACE);

	device_emit_removed(netdev);

	l_debug("Freeing interface %s", netdev->name);

	l_hashmap_destroy(netdev->networks, network_free);

	l_queue_destroy(netdev->bss_list, bss_free);
	l_queue_destroy(netdev->old_bss_list, bss_free);
	l_io_destroy(netdev->eapol_io);

	l_free(netdev);
}

static bool netdev_match(const void *a, const void *b)
{
	const struct netdev *netdev = a;
	uint32_t index = L_PTR_TO_UINT(b);

	return (netdev->index == index);
}

static void wiphy_free(void *data)
{
	struct wiphy *wiphy = data;

	l_debug("Freeing wiphy %s", wiphy->name);

	l_queue_destroy(wiphy->netdev_list, netdev_free);
	l_free(wiphy);
}

static bool wiphy_match(const void *a, const void *b)
{
	const struct wiphy *wiphy = a;
	uint32_t id = L_PTR_TO_UINT(b);

	return (wiphy->id == id);
}

static void mlme_associate_event(struct l_genl_msg *msg, struct netdev *netdev)
{
	struct l_dbus_message *reply;
	int err;

	l_debug("");

	err = l_genl_msg_get_error(msg);
	if (err < 0) {
		l_error("association failed %s (%d)", strerror(-err), err);
		dbus_pending_reply(&netdev->connect_pending,
				dbus_error_failed(netdev->connect_pending));
		netdev->connected_bss = NULL;
		return;
	}

	l_info("Association completed");

	if (netdev->connected_bss &&
		netdev->connected_bss->network->ssid_security ==
						SCAN_SSID_SECURITY_NONE) {
		reply = l_dbus_message_new_method_return(
						netdev->connect_pending);
		l_dbus_message_set_arguments(reply, "");
		dbus_pending_reply(&netdev->connect_pending, reply);
	}
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
	struct bss *bss;
	struct network *network;
	struct l_dbus_message *error;

	l_debug("");

	bss = netdev->connected_bss;
	if (!bss) {
		error = dbus_error_not_available(netdev->connect_pending);
		dbus_pending_reply(&netdev->connect_pending, error);
		return;
	}

	network = bss->network;
	msg = l_genl_msg_new_sized(NL80211_CMD_ASSOCIATE, 512);
	msg_append_attr(msg, NL80211_ATTR_IFINDEX, 4, &netdev->index);
	msg_append_attr(msg, NL80211_ATTR_WIPHY_FREQ, 4, &bss->frequency);
	msg_append_attr(msg, NL80211_ATTR_MAC, ETH_ALEN, bss->addr);
	msg_append_attr(msg, NL80211_ATTR_SSID, network->ssid_len,
			network->ssid);

	if (network->ssid_security == SCAN_SSID_SECURITY_PSK) {
		uint32_t ccmp = 0x000fac04;
		uint8_t rsne_buf[256];
		struct ie_rsn_info info;
		struct eapol_sm *sm = eapol_sm_new();

		memset(&info, 0, sizeof(info));
		info.group_cipher = IE_RSN_CIPHER_SUITE_CCMP;
		info.pairwise_ciphers = IE_RSN_CIPHER_SUITE_CCMP;
		info.akm_suites = IE_RSN_AKM_SUITE_PSK;

		ie_build_rsne(&info, rsne_buf);

		eapol_sm_set_pmk(sm, network->psk);
		eapol_sm_set_authenticator_address(sm, bss->addr);
		eapol_sm_set_supplicant_address(sm, netdev->addr);
		eapol_sm_set_ap_rsn(sm, bss->rsne, bss->rsne[1] + 2);
		eapol_sm_set_own_rsn(sm, rsne_buf, rsne_buf[1] + 2);
		eapol_start(netdev->index, sm);

		msg_append_attr(msg, NL80211_ATTR_CIPHER_SUITES_PAIRWISE,
				4, &ccmp);
		msg_append_attr(msg, NL80211_ATTR_CIPHER_SUITE_GROUP,
				4, &ccmp);
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
	dbus_pending_reply(&netdev->connect_pending,
				dbus_error_failed(netdev->connect_pending));
	netdev->connected_bss = NULL;
}

static void mlme_deauthenticate_event(struct l_genl_msg *msg,
							struct netdev *netdev)
{
	struct l_genl_attr attr;
	uint16_t type, len;
	const void *data;
	struct l_dbus_message *reply;
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
			l_warn("deauthentication timed out");
			goto error;
		}
	}

	l_info("Deauthentication completed");
	netdev->connected_bss = NULL;

	if (!netdev->connect_pending)
		return;

	reply = l_dbus_message_new_method_return(netdev->connect_pending);
	l_dbus_message_set_arguments(reply, "");
	dbus_pending_reply(&netdev->connect_pending, reply);

	return;

error:
	dbus_pending_reply(&netdev->connect_pending,
				dbus_error_failed(netdev->connect_pending));
	netdev->connected_bss = NULL;
}

static bool parse_ie(struct bss *bss, const uint8_t **ssid, int *ssid_len,
						const void *data, uint16_t len)
{
	struct ie_tlv_iter iter;

	ie_tlv_iter_init(&iter, data, len);

	while (ie_tlv_iter_next(&iter)) {
		uint8_t tag = ie_tlv_iter_get_tag(&iter);

		switch (tag) {
		case IE_TYPE_SSID:
			if (iter.len > 32) {
				l_warn("Got SSID > 32");
				return false;
			}

			*ssid_len = iter.len;
			*ssid = iter.data;
			break;
		case IE_TYPE_RSN:
			if (!bss->rsne)
				bss->rsne = l_memdup(iter.data - 2,
								iter.len + 2);
			break;
		case IE_TYPE_VENDOR_SPECIFIC:
			/* Interested only in WPA IE from Vendor data */
			if (!bss->wpa && is_ie_wpa_ie(iter.data, iter.len))
				bss->wpa = l_memdup(iter.data - 2,
								iter.len + 2);
			break;
		default:
			break;
		}
	}

	return true;
}

static int add_bss(const void *a, const void *b, void *user_data)
{
	const struct bss *new_bss = a, *bss = b;

	if (new_bss->signal_strength > bss->signal_strength)
		return 1;

	return 0;
}

static void parse_bss(struct netdev *netdev, struct l_genl_attr *attr)
{
	uint16_t type, len;
	const void *data;
	struct bss *bss;
	struct bss *old_bss;
	const uint8_t *ssid = NULL;
	int ssid_len;
	struct network *network;
	enum scan_ssid_security ssid_security;
	const char *path;

	bss = l_new(struct bss, 1);

	while (l_genl_attr_next(attr, &type, &len, &data)) {
		switch (type) {
		case NL80211_BSS_BSSID:
			if (len != sizeof(bss->addr)) {
				l_warn("Invalid BSSID attribute");
				goto fail;
			}

			memcpy(bss->addr, data, len);
			break;
		case NL80211_BSS_CAPABILITY:
			if (len != sizeof(uint16_t)) {
				l_warn("Invalid capability attribute");
				goto fail;
			}

			bss->capability = *((uint16_t *) data);
			break;
		case NL80211_BSS_FREQUENCY:
			if (len != sizeof(uint32_t)) {
				l_warn("Invalid frequency attribute");
				goto fail;
			}

			bss->frequency = *((uint32_t *) data);
			break;
		case NL80211_BSS_SIGNAL_MBM:
			if (len != sizeof(int32_t)) {
				l_warn("Invalid signal strength attribute");
				goto fail;
			}

			bss->signal_strength = *((int32_t *) data);
			break;
		case NL80211_BSS_INFORMATION_ELEMENTS:
			if (!parse_ie(bss, &ssid, &ssid_len, data, len)) {
				l_warn("Could not parse BSS IEs");
				goto fail;
			}

			break;
		}
	}

	if (!ssid) {
		l_warn("Received BSS but SSID IE returned NULL -- ignoring");
		goto fail;
	}

	/*
	 * TODO: Check whether WPA element is present
	 *
	 * If we have the RSN element, try to parse it and figure out the
	 * security parameters.
	 *
	 * Length was already validated by parse_ie, so use the one from the
	 * IE directly.
	 */
	if (bss->rsne) {
		struct ie_rsn_info rsne;
		int res = ie_parse_rsne_from_data(bss->rsne, bss->rsne[1] + 2,
							&rsne);
		if (res < 0) {
			l_debug("Cannot parse RSN field (%d, %s)",
					res, strerror(-res));
			goto fail;
		}

		ssid_security = scan_get_ssid_security(bss->capability, &rsne);
	} else if (bss->wpa) {
		struct ie_rsn_info wpa;
		int res = ie_parse_wpa_from_data(bss->wpa, bss->wpa[1] + 2,
									&wpa);
		if (res < 0) {
			l_debug("Cannot parse WPA IE %s (%d, %s)",
					util_ssid_to_utf8(ssid_len, ssid),
						res, strerror(-res));
			goto fail;
		}

		ssid_security = scan_get_ssid_security(bss->capability, &wpa);
	} else
		ssid_security = scan_get_ssid_security(bss->capability, NULL);

	path = iwd_network_get_path(netdev, ssid, ssid_len, ssid_security);

	network = l_hashmap_lookup(netdev->networks, path);
	if (!network) {
		l_debug("Found new SSID \"%s\" security %s",
			util_ssid_to_utf8(ssid_len, ssid),
			ssid_security_to_str(ssid_security));

		network = l_new(struct network, 1);
		network->netdev = netdev;
		memcpy(network->ssid, ssid, ssid_len);
		network->ssid_len = ssid_len;
		network->ssid_security = ssid_security;
		network->bss_list = l_queue_new();
		network->object_path = strdup(path);
		l_hashmap_insert(netdev->networks,
					network->object_path, network);

		if (!l_dbus_register_interface(dbus_get_bus(),
					network->object_path,
					IWD_NETWORK_INTERFACE,
					setup_network_interface,
					network, NULL))
			l_info("Unable to register %s interface",
				IWD_NETWORK_INTERFACE);
		else
			network_emit_added(network);
	}

	bss->network = network;
	old_bss = l_queue_remove_if(netdev->old_bss_list, bss_match, bss);

	l_debug("Found %s BSS '%s' with SSID: %s, freq: %u, "
			"strength: %i",
			old_bss ? "existing" : "new",
			bss_address_to_string(bss),
			util_ssid_to_utf8(ssid_len, ssid),
			bss->frequency, bss->signal_strength);

	if (old_bss) {
		if (netdev->connected_bss &&
				bss_match(old_bss, netdev->connected_bss))
			netdev->connected_bss = NULL;

		bss_free(old_bss);
	}

	l_queue_insert(network->bss_list, bss, add_bss, NULL);
	l_queue_push_head(netdev->bss_list, bss);
	return;

fail:
	bss_free(bss);
}

static void network_reset_bss_list(const void *key, void *value,
					void *user_data)
{
	struct network *network = value;

	l_queue_destroy(network->bss_list, NULL);
	network->bss_list = l_queue_new();
}

static void get_scan_callback(struct l_genl_msg *msg, void *user_data)
{
	struct netdev *netdev = user_data;
	struct l_genl_attr attr, nested;
	uint16_t type, len;
	const void *data;

	l_debug("get_scan_callback");

	if (!l_genl_attr_init(&attr, msg))
		return;

	if (!netdev->old_bss_list) {
		netdev->old_bss_list = netdev->bss_list;
		netdev->bss_list = l_queue_new();
		l_hashmap_foreach(netdev->networks,
					network_reset_bss_list, NULL);
	}

	while (l_genl_attr_next(&attr, &type, &len, &data)) {
		switch (type) {
		case NL80211_ATTR_IFINDEX:
			if (len != sizeof(uint32_t)) {
				l_warn("Invalid interface index attribute");
				return;
			}

			if (netdev->index != *((uint32_t *) data)) {
				l_warn("ifindex mismatch");
				return;
			}

			break;
		case NL80211_ATTR_BSS:
			if (!netdev) {
				l_warn("No interface structure found");
				return;
			}

			if (!l_genl_attr_recurse(&attr, &nested))
				return;

			parse_bss(netdev, &nested);
			break;
		}
	}
}

static void network_remove_if_lost(void *data)
{
	struct network *network = data;

	if (!l_queue_isempty(network->bss_list))
		return;

	l_debug("No remaining BSSs for SSID: %s -- Removing network",
			util_ssid_to_utf8(network->ssid_len, network->ssid));

	if (!l_hashmap_remove(network->netdev->networks, network->object_path))
		l_warn("Panic, trying to remove network that doesn't"
			" exist in the networks hashmap");

	network_free(network);
}

static void get_scan_done(void *user)
{
	struct netdev *netdev = user;
	const struct l_queue_entry *bss_entry;
	struct l_queue *lost_networks;

	l_debug("get_scan_done for netdev: %p", netdev);

	if (l_queue_isempty(netdev->old_bss_list))
		goto done;

	lost_networks = l_queue_new();

	for (bss_entry = l_queue_get_entries(netdev->old_bss_list); bss_entry;
					bss_entry = bss_entry->next) {
		struct bss *old_bss = bss_entry->data;
		struct network *network = old_bss->network;

		l_debug("Lost BSS '%s' with SSID: %s",
			bss_address_to_string(old_bss),
			util_ssid_to_utf8(network->ssid_len, network->ssid));

		l_queue_remove(lost_networks, network);
		l_queue_push_head(lost_networks, network);
	}

	l_queue_destroy(lost_networks, network_remove_if_lost);

done:
	l_queue_destroy(netdev->old_bss_list, bss_free);
	netdev->old_bss_list = NULL;
}

static void sched_scan_callback(struct l_genl_msg *msg, void *user_data)
{
	struct l_genl_attr attr;
	uint16_t type, len;
	const void *data;

	if (!l_genl_attr_init(&attr, msg)) {
		int err = l_genl_msg_get_error(msg);
		if (err < 0 && err != -EINPROGRESS) {
			l_warn("Failed to setup scheduled scan [%d/%s]",
				-err, strerror(-err));
			goto done;
		}

		l_info("Scheduled scan started");
	} else {
		while (l_genl_attr_next(&attr, &type, &len, &data)) {
		}
	}

done:
	return;
}

static void setup_scheduled_scan(struct wiphy *wiphy, struct netdev *netdev,
				uint32_t scan_interval)
{
	if (!wiphy->support_scheduled_scan) {
		l_debug("Scheduled scan not supported for %s "
			"iface %s ifindex %u", wiphy->name, netdev->name,
			netdev->index);
		return;
	}

	scan_sched_start(nl80211, netdev->index, scan_interval,
			sched_scan_callback, netdev);
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
			if (!wiphy) {
				l_warn("No wiphy structure found");
				return;
			}
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

		l_queue_push_head(wiphy->netdev_list, netdev);

		if (!l_dbus_register_interface(dbus,
						iwd_device_get_path(netdev),
						IWD_DEVICE_INTERFACE,
						setup_device_interface,
						netdev, NULL))
			l_info("Unable to register %s interface",
				IWD_DEVICE_INTERFACE);
		else
			device_emit_added(netdev);
	}

	setup_scheduled_scan(wiphy, netdev, scheduled_scan_interval);

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
		}
	}
}

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
				l_queue_push_head(wiphy_list, wiphy);
			}
			break;

		case NL80211_ATTR_WIPHY_NAME:
			if (!wiphy) {
				l_warn("No wiphy structure found");
				return;
			}

			if (len > sizeof(wiphy->name)) {
				l_warn("Invalid wiphy name attribute");
				return;
			}

			memcpy(wiphy->name, data, len);
			break;

		case NL80211_ATTR_FEATURE_FLAGS:
			if (!wiphy) {
				l_warn("No wiphy structure found");
				return;
			}

			if (len != sizeof(uint32_t)) {
				l_warn("Invalid feature flags attribute");
				return;
			}

			wiphy->feature_flags = *((uint32_t *) data);
			break;
		case NL80211_ATTR_SUPPORTED_COMMANDS:
			if (!wiphy) {
				l_warn("No wiphy structure found");
				return;
			}

			if (!l_genl_attr_recurse(&attr, &nested))
				return;

			parse_supported_commands(wiphy, &nested);
			break;
		}
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

static void wiphy_scan_notify(struct l_genl_msg *msg, void *user_data)
{
	struct wiphy *wiphy = NULL;
	struct netdev *netdev = NULL;
	struct l_genl_attr attr;
	uint16_t type, len;
	const void *data;
	uint8_t cmd;
	uint32_t uninitialized_var(attr_ifindex);
	bool have_ifindex;
	uint32_t uninitialized_var(attr_wiphy);
	bool have_wiphy;

	cmd = l_genl_msg_get_command(msg);

	l_debug("Scan notification %u", cmd);

	if (!l_genl_attr_init(&attr, msg))
		return;

	while (l_genl_attr_next(&attr, &type, &len, &data)) {
		switch (type) {
		case NL80211_ATTR_WIPHY:
			if (len != sizeof(uint32_t)) {
				l_warn("Invalid wiphy attribute");
				return;
			}

			have_wiphy = true;
			attr_wiphy = *((uint32_t *) data);
			break;
		case NL80211_ATTR_IFINDEX:
			if (len != sizeof(uint32_t)) {
				l_warn("Invalid interface index attribute");
				return;
			}

			have_ifindex = true;
			attr_ifindex = *((uint32_t *) data);
			break;
		}
	}

	if (!have_wiphy) {
		l_warn("Scan results do not contain wiphy attribute");
		return;
	}

	if (!have_ifindex) {
		l_warn("Scan results do not contain ifindex attribute");
		return;
	}

	wiphy = l_queue_find(wiphy_list, wiphy_match,
				L_UINT_TO_PTR(attr_wiphy));
	if (!wiphy) {
		l_warn("Scan notification for unknown wiphy");
		return;
	}

	netdev = l_queue_find(wiphy->netdev_list, netdev_match,
					L_UINT_TO_PTR(attr_ifindex));
	if (!netdev) {
		l_warn("Scan notification for unknown ifindex");
		return;
	}

	if (cmd == NL80211_CMD_NEW_SCAN_RESULTS ||
				cmd == NL80211_CMD_SCHED_SCAN_RESULTS) {
		scan_get_results(nl80211, netdev->index, get_scan_callback,
				get_scan_done, netdev);
		return;
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

static void nl80211_appeared(void *user_data)
{
	struct l_genl_msg *msg;

	l_debug("Found nl80211 interface");

	/*
	 * This is an extra sanity check so that no memory is leaked
	 * in case the generic netlink handling gets confused.
	 */
	if (wiphy_list) {
		l_warn("Destroying existing list of wiphy devices");
		l_queue_destroy(wiphy_list, NULL);
	}

	if (!l_genl_family_register(nl80211, "config", wiphy_config_notify,
								NULL, NULL))
		l_error("Registering for config notification failed");

	if (!l_genl_family_register(nl80211, "scan", wiphy_scan_notify,
								NULL, NULL))
		l_error("Registering for scan notification failed");

	if (!l_genl_family_register(nl80211, "mlme", wiphy_mlme_notify,
								NULL, NULL))
		l_error("Registering for MLME notification failed");

	if (!l_genl_family_register(nl80211, "regulatory",
					wiphy_regulatory_notify, NULL, NULL))
		l_error("Registering for regulatory notification failed");

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
	if (!l_genl_family_dump(nl80211, msg, wiphy_dump_callback, NULL, NULL))
		l_error("Getting all wiphy devices failed");

	msg = l_genl_msg_new(NL80211_CMD_GET_INTERFACE);
	if (!l_genl_family_dump(nl80211, msg, interface_dump_callback,
								NULL, NULL))
		l_error("Getting all interface information failed");
}

static void nl80211_vanished(void *user_data)
{
	l_debug("Lost nl80211 interface");

	l_queue_destroy(wiphy_list, wiphy_free);
	wiphy_list = NULL;
}

bool wiphy_init(void)
{
	if (genl)
		return false;

	genl = l_genl_new_default();
	if (!genl) {
		l_error("Failed to open generic netlink socket");
		return false;
	}

	if (getenv("IWD_GENL_DEBUG"))
		l_genl_set_debug(genl, do_debug, "[GENL] ", NULL);

	l_debug("Opening nl80211 interface");

	nl80211 = l_genl_family_new(genl, NL80211_GENL_NAME);
	if (!nl80211) {
		l_error("Failed to open nl80211 interface");
		goto failed;
	}

	l_genl_family_set_watches(nl80211, nl80211_appeared, nl80211_vanished,
								NULL, NULL);

	return true;

failed:
	l_genl_unref(genl);
	genl = NULL;

	return false;
}

bool wiphy_exit(void)
{
	if (!genl)
		return false;

	l_debug("Closing nl80211 interface");

	/*
	 * The generic netlink master object keeps track of all families
	 * and closing it will take care of freeing all associated resources.
	 */
	l_genl_unref(genl);
	genl = NULL;

	/*
	 * This is an extra sanity check so that no memory is leaked
	 * in case the generic netlink handling forgets to call the
	 * vanished callback.
	 */
	if (wiphy_list) {
		l_warn("Found leftover list of wiphy devices");
		l_queue_destroy(wiphy_list, wiphy_free);
		wiphy_list = NULL;
	}

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
