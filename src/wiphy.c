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
#include <sys/socket.h>
#include <linux/if.h>
#include <linux/if_ether.h>
#include <ell/ell.h>

#include "linux/nl80211.h"
#include "src/ie.h"
#include "src/wiphy.h"
#include "src/dbus.h"

static const char *network_ssid = NULL;

static struct l_genl *genl = NULL;
static struct l_genl_family *nl80211 = NULL;

struct bss {
	uint8_t addr[ETH_ALEN];
	uint32_t frequency;
	char *ssid;
};

struct netdev {
	uint32_t index;
	char name[IFNAMSIZ];
	uint32_t type;
	uint8_t addr[ETH_ALEN];
	struct l_queue *bss_list;
	struct l_dbus_message *pending;
};

struct wiphy {
	uint32_t id;
	char name[20];
	uint32_t feature_flags;
	struct l_queue *netdev_list;
};

static struct l_queue *wiphy_list = NULL;

static void do_debug(const char *str, void *user_data)
{
	const char *prefix = user_data;

	l_info("%s%s", prefix, str);
}

const char *iwd_device_get_path(struct netdev *netdev)
{
	static char path[256];

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
	struct l_genl_attr attr;
	uint16_t type, len;
	const void *data;
	struct l_dbus_message *reply;

	if (!l_genl_attr_init(&attr, msg)) {
		dbus_pending_reply(&netdev->pending,
					dbus_error_failed(netdev->pending));
		return;
	}

	while (l_genl_attr_next(&attr, &type, &len, &data)) {
	}

	l_debug("Scan triggered for netdev %s", netdev->name);

	reply = l_dbus_message_new_method_return(netdev->pending);
	l_dbus_message_set_arguments(reply, "");
	dbus_pending_reply(&netdev->pending, reply);
}

static struct l_dbus_message *device_scan(struct l_dbus *dbus,
						struct l_dbus_message *message,
						void *user_data)
{
	struct netdev *netdev = user_data;
	struct l_genl_msg *msg;

	if (netdev->pending)
		return dbus_error_busy(message);

	netdev->pending = l_dbus_message_ref(message);

	msg = l_genl_msg_new_sized(NL80211_CMD_TRIGGER_SCAN, 16);
	l_genl_msg_append_attr(msg, NL80211_ATTR_IFINDEX, 4, &netdev->index);
	l_genl_family_send(nl80211, msg, device_scan_callback, netdev, NULL);
	l_genl_msg_unref(msg);

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

	l_dbus_interface_signal(interface, "PropertyChanged", 0,
				"sv", "name", "value");

	l_dbus_interface_ro_property(interface, "Name", "s");
}

static void bss_free(void *data)
{
	struct bss *bss = data;

	l_debug("Freeing BSS %02X:%02X:%02X:%02X:%02X:%02X [%s]",
			bss->addr[0], bss->addr[1], bss->addr[2],
			bss->addr[3], bss->addr[4], bss->addr[5], bss->ssid);

	l_free(bss->ssid);
	l_free(bss);
}

static void netdev_free(void *data)
{
	struct netdev *netdev = data;
	struct l_dbus *dbus;

	dbus = dbus_get_bus();
	l_dbus_unregister_interface(dbus, iwd_device_get_path(netdev),
					IWD_DEVICE_INTERFACE);

	device_emit_removed(netdev);

	l_debug("Freeing interface %s", netdev->name);

	l_queue_destroy(netdev->bss_list, bss_free);
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

static void mlme_authenticate(struct netdev *netdev, struct bss *bss)
{
	struct l_genl_msg *msg;
	uint32_t auth_type = NL80211_AUTHTYPE_OPEN_SYSTEM;

	if (!bss) {
		bss = l_queue_peek_head(netdev->bss_list);
		if (!bss)
			return;
	}

	msg = l_genl_msg_new_sized(NL80211_CMD_AUTHENTICATE, 512);
	l_genl_msg_append_attr(msg, NL80211_ATTR_IFINDEX, 4, &netdev->index);
	l_genl_msg_append_attr(msg, NL80211_ATTR_WIPHY_FREQ, 4,
							&bss->frequency);
	l_genl_msg_append_attr(msg, NL80211_ATTR_MAC, ETH_ALEN, bss->addr);
	l_genl_msg_append_attr(msg, NL80211_ATTR_SSID, strlen(bss->ssid),
								bss->ssid);
	l_genl_msg_append_attr(msg, NL80211_ATTR_AUTH_TYPE, 4, &auth_type);
	l_genl_family_send(nl80211, msg, NULL, NULL, NULL);
	l_genl_msg_unref(msg);
}

static void mlme_associate(struct netdev *netdev, struct bss *bss)
{
	struct l_genl_msg *msg;

	if (!bss) {
		bss = l_queue_peek_head(netdev->bss_list);
		if (!bss)
			return;
	}

	msg = l_genl_msg_new_sized(NL80211_CMD_ASSOCIATE, 512);
	l_genl_msg_append_attr(msg, NL80211_ATTR_IFINDEX, 4, &netdev->index);
	l_genl_msg_append_attr(msg, NL80211_ATTR_WIPHY_FREQ, 4,
							&bss->frequency);
	l_genl_msg_append_attr(msg, NL80211_ATTR_MAC, ETH_ALEN, bss->addr);
	l_genl_msg_append_attr(msg, NL80211_ATTR_SSID, strlen(bss->ssid),
								bss->ssid);
	l_genl_family_send(nl80211, msg, NULL, NULL, NULL);
	l_genl_msg_unref(msg);
}


static bool parse_ie(struct bss *bss, const void *data, uint16_t len)
{
	struct ie_tlv_iter iter;

	ie_tlv_iter_init(&iter, data, len);

	while (ie_tlv_iter_next(&iter)) {
		uint8_t tag = ie_tlv_iter_get_tag(&iter);

		switch (tag) {
		case 0:
			bss->ssid = l_strndup((const char *) iter.data,
								iter.len);
			break;
		default:
			break;
		}
	}

	return true;
}

static void parse_bss(struct netdev *netdev, struct l_genl_attr *attr)
{
	uint16_t type, len;
	const void *data;
	struct bss *bss;

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
		case NL80211_BSS_FREQUENCY:
			if (len != sizeof(uint32_t)) {
				l_warn("Invalid frequency attribute");
				goto fail;
			}

			bss->frequency = *((uint32_t *) data);
			break;
		case NL80211_BSS_INFORMATION_ELEMENTS:
			if (!parse_ie(bss, data, len)) {
				l_warn("Could not parse BSS IEs");
				goto fail;
			}

			break;
		}
	}

	l_debug("Frequency for %s is %u", bss->ssid, bss->frequency);
	l_queue_push_head(netdev->bss_list, bss);
	return;

fail:
	bss_free(bss);
}

static void get_scan_callback(struct l_genl_msg *msg, void *user_data)
{
	struct wiphy *wiphy = user_data;
	struct netdev *netdev = NULL;
	struct l_genl_attr attr, nested;
	uint16_t type, len;
	const void *data;

	if (!l_genl_attr_init(&attr, msg))
		return;

	while (l_genl_attr_next(&attr, &type, &len, &data)) {
		switch (type) {
		case NL80211_ATTR_IFINDEX:
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

static void get_scan(struct wiphy *wiphy)
{
	struct netdev *netdev;
	struct l_genl_msg *msg;

	if (!network_ssid)
		return;

	netdev = l_queue_peek_head(wiphy->netdev_list);
	if (!netdev)
		return;

	msg = l_genl_msg_new_sized(NL80211_CMD_GET_SCAN, 8);
	l_genl_msg_append_attr(msg, NL80211_ATTR_IFINDEX, 4, &netdev->index);
	l_genl_family_dump(nl80211, msg, get_scan_callback, wiphy, NULL);
	l_genl_msg_unref(msg);
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

	l_debug("Found interface %s", netdev->name);
}

static void wiphy_dump_callback(struct l_genl_msg *msg, void *user_data)
{
	struct wiphy *wiphy = NULL;
	struct l_genl_attr attr;
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
	struct l_genl_attr attr;
	uint16_t type, len;
	const void *data;
	uint8_t cmd;

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

			wiphy = l_queue_find(wiphy_list, wiphy_match,
					L_UINT_TO_PTR(*((uint32_t *) data)));
			if (!wiphy) {
				l_warn("No wiphy structure found");
				return;
			}
			break;
		}
	}

	if (!wiphy) {
		l_warn("Scan notification is missing wiphy attribute");
		return;
	}

	if (cmd == NL80211_CMD_NEW_SCAN_RESULTS) {
		get_scan(wiphy);
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
		l_warn("Scan notification is missing wiphy attribute");
		return;
	}

	if (!netdev) {
		l_warn("Scan notification is missing interface attribute");
		return;
	}

	if (cmd == NL80211_CMD_AUTHENTICATE) {
		mlme_associate(netdev, NULL);
		return;
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
	l_genl_msg_unref(msg);

	msg = l_genl_msg_new(NL80211_CMD_GET_REG);
	if (!l_genl_family_send(nl80211, msg, regulatory_info_callback,
								NULL, NULL))
		l_error("Getting regulatory info failed");
	l_genl_msg_unref(msg);

	msg = l_genl_msg_new(NL80211_CMD_GET_WIPHY);
	if (!l_genl_family_dump(nl80211, msg, wiphy_dump_callback, NULL, NULL))
		l_error("Getting all wiphy devices failed");
	l_genl_msg_unref(msg);

	msg = l_genl_msg_new(NL80211_CMD_GET_INTERFACE);
	if (!l_genl_family_dump(nl80211, msg, interface_dump_callback,
								NULL, NULL))
		l_error("Getting all interface information failed");
	l_genl_msg_unref(msg);
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

void wiphy_set_ssid(const char *ssid)
{
	network_ssid = ssid;
}
