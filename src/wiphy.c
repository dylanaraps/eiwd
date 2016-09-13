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
#include <linux/if_ether.h>

#include <ell/ell.h>

#include "linux/nl80211.h"

#include "src/iwd.h"
#include "src/ie.h"
#include "src/crypto.h"
#include "src/scan.h"
#include "src/netdev.h"
#include "src/dbus.h"
#include "src/rfkill.h"
#include "src/wiphy.h"
#include "src/storage.h"

static struct l_genl_family *nl80211 = NULL;
static struct l_hwdb *hwdb;

struct wiphy {
	uint32_t id;
	char name[20];
	uint32_t feature_flags;
	bool support_scheduled_scan:1;
	bool support_rekey_offload:1;
	uint16_t pairwise_ciphers;
	struct scan_freq_set *supported_freqs;
	char *model_str;
	char *vendor_str;

	bool soft_rfkill : 1;
	bool hard_rfkill : 1;
};

static struct l_queue *wiphy_list = NULL;

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
static void wiphy_free(void *data)
{
	struct wiphy *wiphy = data;

	l_debug("Freeing wiphy %s[%u]", wiphy->name, wiphy->id);

	scan_freq_set_free(wiphy->supported_freqs);
	l_free(wiphy->model_str);
	l_free(wiphy->vendor_str);
	l_free(wiphy);
}

static bool wiphy_match(const void *a, const void *b)
{
	const struct wiphy *wiphy = a;
	uint32_t id = L_PTR_TO_UINT(b);

	return (wiphy->id == id);
}

struct wiphy *wiphy_find(int wiphy_id)
{
	return l_queue_find(wiphy_list, wiphy_match, L_UINT_TO_PTR(wiphy_id));
}

const char *wiphy_get_path(struct wiphy *wiphy)
{
	static char path[15];

	snprintf(path, sizeof(path), "/phy%u", wiphy->id);
	return path;
}

uint32_t wiphy_get_supported_bands(struct wiphy *wiphy)
{
	if (!wiphy->supported_freqs)
		return 0;

	return scan_freq_set_get_bands(wiphy->supported_freqs);
}

static void wiphy_print_basic_info(struct wiphy *wiphy)
{
	uint32_t bands;
	char buf[1024];

	l_info("Wiphy: %d, Name: %s", wiphy->id, wiphy->name);

	bands = scan_freq_set_get_bands(wiphy->supported_freqs);

	if (bands) {
		int len = 0;

		len += sprintf(buf + len, "\tBands:");

		if (bands & SCAN_BAND_2_4_GHZ)
			len += sprintf(buf + len, " 2.4 GHz");

		if (bands & SCAN_BAND_5_GHZ)
			len += sprintf(buf + len, " 5 GHz");

		l_info("%s", buf);
	}

	if (wiphy->pairwise_ciphers &
			(IE_RSN_CIPHER_SUITE_CCMP | IE_RSN_CIPHER_SUITE_TKIP)) {
		int len = 0;

		len += sprintf(buf + len, "\tCiphers:");

		if (wiphy->pairwise_ciphers & IE_RSN_CIPHER_SUITE_CCMP)
			len += sprintf(buf + len, " CCMP");

		if (wiphy->pairwise_ciphers & IE_RSN_CIPHER_SUITE_TKIP)
			len += sprintf(buf + len, " TKIP");

		l_info("%s", buf);
	}
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

static void wiphy_parse_attributes(struct wiphy *wiphy,
					struct l_genl_attr *attr)
{
	struct l_genl_attr nested;
	uint16_t type, len;
	const void *data;

	while (l_genl_attr_next(attr, &type, &len, &data)) {
		switch (type) {
		case NL80211_ATTR_WIPHY:
			l_warn("Duplicate wiphy attribute");
			break;
		case NL80211_ATTR_WIPHY_NAME:
			if (len > sizeof(wiphy->name))
				l_warn("Invalid wiphy name attribute");
			else
				memcpy(wiphy->name, data, len);

			break;
		case NL80211_ATTR_FEATURE_FLAGS:
			if (len != sizeof(uint32_t))
				l_warn("Invalid feature flags attribute");
			else
				wiphy->feature_flags = *((uint32_t *) data);

			break;
		case NL80211_ATTR_SUPPORTED_COMMANDS:
			if (l_genl_attr_recurse(attr, &nested))
				parse_supported_commands(wiphy, &nested);

			break;
		case NL80211_ATTR_CIPHER_SUITES:
			parse_supported_ciphers(wiphy, data, len);
			break;
		case NL80211_ATTR_WIPHY_BANDS:
			if (l_genl_attr_recurse(attr, &nested))
				parse_supported_bands(wiphy, &nested);

			break;
		}
	}

}

static void wiphy_dump_callback(struct l_genl_msg *msg, void *user_data)
{
	struct wiphy *wiphy;
	struct l_genl_attr attr;
	uint16_t type, len;
	const void *data;
	uint32_t id;

	l_debug("");

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
	if (!l_genl_attr_next(&attr, &type, &len, &data))
		return;

	if (type != NL80211_ATTR_WIPHY)
		return;


	if (len != sizeof(uint32_t)) {
		l_warn("Invalid wiphy attribute");
		return;
	}

	id = *((uint32_t *) data);

	wiphy = l_queue_find(wiphy_list, wiphy_match, L_UINT_TO_PTR(id));
	if (!wiphy) {
		wiphy = l_new(struct wiphy, 1);
		wiphy->id = id;
		wiphy->supported_freqs = scan_freq_set_new();
		l_queue_push_head(wiphy_list, wiphy);
	}

	wiphy_parse_attributes(wiphy, &attr);
}

static void wiphy_register(struct wiphy *wiphy)
{
	struct l_dbus *dbus = dbus_get_bus();

	wiphy->soft_rfkill = rfkill_get_soft_state(wiphy->id);
	wiphy->hard_rfkill = rfkill_get_hard_state(wiphy->id);

	if (wiphy->name && hwdb) {
		char modalias[128];
		ssize_t len;
		struct l_hwdb_entry *entries = NULL, *kv;

		len = read_file(modalias, sizeof(modalias) - 1,
				"/sys/class/ieee80211/%s/device/modalias",
				wiphy->name);

		if (len > 0) {
			modalias[len] = '\0';
			entries = l_hwdb_lookup(hwdb, "%s", modalias);
		}

		for (kv = entries; kv; kv = kv->next) {
			if (!strcmp(kv->key, "ID_MODEL_FROM_DATABASE")) {
				if (wiphy->model_str)
					continue;

				wiphy->model_str = l_strdup(kv->value);
			}

			if (!strcmp(kv->key, "ID_VENDOR_FROM_DATABASE")) {
				if (wiphy->vendor_str)
					continue;

				wiphy->vendor_str = l_strdup(kv->value);
			}
		}

		l_hwdb_lookup_free(entries);
	}

	if (!l_dbus_object_add_interface(dbus, wiphy_get_path(wiphy),
					IWD_WIPHY_INTERFACE, wiphy))
		l_info("Unable to add the %s interface to %s",
				IWD_WIPHY_INTERFACE, wiphy_get_path(wiphy));
}

static void wiphy_dump_done(void *user)
{
	const struct l_queue_entry *wiphy_entry;

	for (wiphy_entry = l_queue_get_entries(wiphy_list); wiphy_entry;
					wiphy_entry = wiphy_entry->next) {
		struct wiphy *wiphy = wiphy_entry->data;

		wiphy_register(wiphy);

		wiphy_print_basic_info(wiphy);
	}
}

static void wiphy_new_wiphy_event(struct l_genl_msg *msg)
{
	struct wiphy *wiphy;
	struct l_genl_attr attr;
	uint16_t type, len;
	const void *data;
	uint32_t id;

	l_debug("");

	if (!l_genl_attr_init(&attr, msg))
		return;

	if (!l_genl_attr_next(&attr, &type, &len, &data))
		return;

	if (type != NL80211_ATTR_WIPHY)
		return;

	if (len != sizeof(uint32_t)) {
		l_warn("Invalid wiphy attribute");
		return;
	}

	id = *((uint32_t *) data);

	wiphy = l_queue_find(wiphy_list, wiphy_match, L_UINT_TO_PTR(id));
	if (wiphy) {
		l_info("Wiphy %s[%d] already being tracked",
				wiphy->name, wiphy->id);
		return;
	}

	wiphy = l_new(struct wiphy, 1);
	wiphy->id = id;
	wiphy->supported_freqs = scan_freq_set_new();
	l_queue_push_head(wiphy_list, wiphy);

	wiphy_parse_attributes(wiphy, &attr);
	wiphy_print_basic_info(wiphy);

	wiphy_register(wiphy);
}

static void wiphy_del_wiphy_event(struct l_genl_msg *msg)
{
	struct wiphy *wiphy;
	struct l_genl_attr attr;
	uint16_t type, len;
	const void *data;
	uint32_t id;

	if (!l_genl_attr_init(&attr, msg))
		return;

	if (!l_genl_attr_next(&attr, &type, &len, &data))
		return;

	if (type != NL80211_ATTR_WIPHY)
		return;

	if (len != sizeof(uint32_t)) {
		l_warn("Invalid wiphy attribute");
		return;
	}

	id = *((uint32_t *) data);

	wiphy = l_queue_remove_if(wiphy_list, wiphy_match, L_UINT_TO_PTR(id));
	if (!wiphy)
		return;

	l_dbus_unregister_object(dbus_get_bus(), wiphy_get_path(wiphy));

	wiphy_free(wiphy);
}

static void wiphy_config_notify(struct l_genl_msg *msg, void *user_data)
{
	uint8_t cmd;

	cmd = l_genl_msg_get_command(msg);

	l_debug("Notification of command %u", cmd);

	switch (cmd) {
	case NL80211_CMD_NEW_WIPHY:
		wiphy_new_wiphy_event(msg);
		break;
	case NL80211_CMD_DEL_WIPHY:
		wiphy_del_wiphy_event(msg);
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

static void wiphy_rfkill_cb(unsigned int wiphy_id, bool soft, bool hard,
				void *user_data)
{
	struct wiphy *wiphy = wiphy_find(wiphy_id);
	struct l_dbus *dbus = dbus_get_bus();
	bool old_powered, new_powered;

	if (!wiphy)
		return;

	old_powered = !wiphy->soft_rfkill && !wiphy->hard_rfkill;

	wiphy->soft_rfkill = soft;
	wiphy->hard_rfkill = hard;

	new_powered = !wiphy->soft_rfkill && !wiphy->hard_rfkill;

	if (old_powered != new_powered)
		l_dbus_property_changed(dbus, wiphy_get_path(wiphy),
					IWD_WIPHY_INTERFACE, "Powered");
}

static bool wiphy_property_get_powered(struct l_dbus *dbus,
					struct l_dbus_message *message,
					struct l_dbus_message_builder *builder,
					void *user_data)
{
	struct wiphy *wiphy = user_data;
	bool value = !wiphy->soft_rfkill && !wiphy->hard_rfkill;

	l_dbus_message_builder_append_basic(builder, 'b', &value);

	return true;
}

static struct l_dbus_message *wiphy_property_set_powered(struct l_dbus *dbus,
					struct l_dbus_message *message,
					struct l_dbus_message_iter *new_value,
					l_dbus_property_complete_cb_t complete,
					void *user_data)
{
	struct wiphy *wiphy = user_data;
	bool old_powered, new_powered;

	if (!l_dbus_message_iter_get_variant(new_value, "b", &new_powered))
		return dbus_error_invalid_args(message);

	old_powered = !wiphy->soft_rfkill && !wiphy->hard_rfkill;

	if (old_powered == new_powered)
		goto done;

	if (wiphy->hard_rfkill)
		return dbus_error_not_available(message);

	if (!rfkill_set_soft_state(wiphy->id, !new_powered))
		return dbus_error_failed(message);

done:
	complete(dbus, message, NULL);

	return NULL;
}

static bool wiphy_property_get_model(struct l_dbus *dbus,
					struct l_dbus_message *message,
					struct l_dbus_message_builder *builder,
					void *user_data)
{
	struct wiphy *wiphy = user_data;

	if (!wiphy->model_str)
		return false;

	l_dbus_message_builder_append_basic(builder, 's', wiphy->model_str);

	return true;
}

static bool wiphy_property_get_vendor(struct l_dbus *dbus,
					struct l_dbus_message *message,
					struct l_dbus_message_builder *builder,
					void *user_data)
{
	struct wiphy *wiphy = user_data;

	if (!wiphy->vendor_str)
		return false;

	l_dbus_message_builder_append_basic(builder, 's', wiphy->vendor_str);

	return true;
}

static void setup_wiphy_interface(struct l_dbus_interface *interface)
{
	l_dbus_interface_property(interface, "Powered", 0, "b",
					wiphy_property_get_powered,
					wiphy_property_set_powered);
	l_dbus_interface_property(interface, "Model", 0, "s",
					wiphy_property_get_model, NULL);
	l_dbus_interface_property(interface, "Vendor", 0, "s",
					wiphy_property_get_vendor, NULL);
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

	nl80211 = in;

	if (!l_genl_family_register(nl80211, "config", wiphy_config_notify,
								NULL, NULL))
		l_error("Registering for config notification failed");

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
	if (!l_genl_family_dump(nl80211, msg, wiphy_dump_callback,
						NULL, wiphy_dump_done))
		l_error("Getting all wiphy devices failed");

	rfkill_watch_add(wiphy_rfkill_cb, NULL);

	if (!l_dbus_register_interface(dbus_get_bus(),
					IWD_WIPHY_INTERFACE,
					setup_wiphy_interface,
					NULL, true))
		l_error("Unable to register the %s interface",
				IWD_WIPHY_INTERFACE);

	hwdb = l_hwdb_new_default();

	return true;
}

bool wiphy_exit(void)
{
	l_queue_destroy(wiphy_list, wiphy_free);
	wiphy_list = NULL;

	nl80211 = NULL;

	l_dbus_unregister_interface(dbus_get_bus(), IWD_WIPHY_INTERFACE);

	l_hwdb_unref(hwdb);

	return true;
}
