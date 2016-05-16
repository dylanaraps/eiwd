/*
 *
 *  Wireless daemon for Linux
 *
 *  Copyright (C) 2013-2015  Intel Corporation. All rights reserved.
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

#include <sys/types.h>
#include <errno.h>

#include <ell/ell.h>

#include "src/ie.h"
#include "src/crypto.h"

#include "src/iwd.h"
#include "src/common.h"
#include "src/storage.h"
#include "src/scan.h"
#include "src/dbus.h"
#include "src/agent.h"
#include "src/device.h"
#include "src/wiphy.h"
#include "src/network.h"

struct network_info {
	char ssid[33];
	uint32_t type;
	struct timespec connected_time;		/* Time last connected */
};

static struct l_queue *networks = NULL;

static int timespec_compare(const void *a, const void *b, void *user_data)
{
	const struct network_info *ni_a = a;
	const struct network_info *ni_b = b;
	const struct timespec *tsa = &ni_a->connected_time;
	const struct timespec *tsb = &ni_b->connected_time;

	if (tsa->tv_sec > tsb->tv_sec)
		return -1;

	if (tsa->tv_sec < tsb->tv_sec)
		return 1;

	if (tsa->tv_nsec > tsb->tv_nsec)
		return -1;

	if (tsa->tv_nsec < tsb->tv_nsec)
		return -1;

	return 0;
}

static bool network_info_match(const void *a, const void *b)
{
	const struct network_info *ni_a = a;
	const struct network_info *ni_b = b;

	if (ni_a->type != ni_b->type)
		return false;

	if (strcmp(ni_a->ssid, ni_b->ssid))
		return false;

	return true;
}

bool network_seen(uint32_t type, const char *ssid)
{
	struct timespec mtim;
	int err;
	struct network_info *info;

	switch(type) {
	case SECURITY_PSK:
		err = storage_network_get_mtime("psk", ssid, &mtim);
		break;
	default:
		return false;
	}

	if (err < 0)
		return false;

	info = l_new(struct network_info, 1);
	info->type = type;
	strncpy(info->ssid, ssid, 32);
	info->ssid[32] = 0;
	memcpy(&info->connected_time, &mtim, sizeof(struct timespec));

	l_queue_insert(networks, info, timespec_compare, NULL);

	return true;
}

bool network_connected(uint32_t type, const char *ssid)
{
	int err;
	struct network_info *info;
	struct network_info search;
	const char *strtype;

	search.type = type;
	strncpy(search.ssid, ssid, 32);
	search.ssid[32] = 0;

	info = l_queue_remove_if(networks, network_info_match, &search);
	if (!info)
		return false;

	strtype = security_to_str(type);
	if (!strtype)
		goto fail;

	err = storage_network_touch(strtype, ssid);
	if (err < 0)
		goto fail;

	err = storage_network_get_mtime(strtype, ssid, &info->connected_time);
	if (err < 0)
		goto fail;

	l_queue_push_head(networks, info);
	return true;

fail:
	l_free(info);
	return false;
}

/* First 64 entries calculated by 1 / pow(n, 0.3) for n >= 1 */
static const double rankmod_table[] = {
	1.0000000000, 0.8122523964, 0.7192230933, 0.6597539554,
	0.6170338627, 0.5841906811, 0.5577898253, 0.5358867313,
	0.5172818580, 0.5011872336, 0.4870596972, 0.4745102806,
	0.4632516708, 0.4530661223, 0.4437850034, 0.4352752816,
	0.4274303178, 0.4201634287, 0.4134032816, 0.4070905315,
	0.4011753236, 0.3956154062, 0.3903746872, 0.3854221125,
	0.3807307877, 0.3762772797, 0.3720410580, 0.3680040435,
	0.3641502401, 0.3604654325, 0.3569369365, 0.3535533906,
	0.3503045821, 0.3471812999, 0.3441752105, 0.3412787518,
	0.3384850430, 0.3357878061, 0.3331812996, 0.3306602598,
	0.3282198502, 0.3258556179, 0.3235634544, 0.3213395618,
	0.3191804229, 0.3170827751, 0.3150435863, 0.3130600345,
	0.3111294892, 0.3092494947, 0.3074177553, 0.3056321221,
	0.3038905808, 0.3021912409, 0.3005323264, 0.2989121662,
	0.2973291870, 0.2957819051, 0.2942689208, 0.2927889114,
	0.2913406263, 0.2899228820, 0.2885345572, 0.2871745887,
};

double network_rankmod(uint32_t type, const char *ssid)
{
	const struct l_queue_entry *entry;
	int n;
	int nmax;

	for (n = 0, entry = l_queue_get_entries(networks); entry;
						entry = entry->next, n += 1) {
		const struct network_info *info = entry->data;

		if (info->type != type)
			continue;

		if (strcmp(info->ssid, ssid))
			continue;

		nmax = L_ARRAY_SIZE(rankmod_table);

		if (n >= nmax)
			n = nmax - 1;

		return rankmod_table[n];
	}

	return 0.0;
}

struct network *network_create(struct netdev *device,
				uint8_t *ssid, uint8_t ssid_len,
				enum security security)
{
	struct network *network;

	network = l_new(struct network, 1);
	network->netdev = device;
	memcpy(network->ssid, ssid, ssid_len);
	network->security = security;

	network->bss_list = l_queue_new();

	return network;
}

const char *network_get_ssid(struct network *network)
{
	return network->ssid;
}

struct netdev *network_get_netdev(struct network *network)
{
	return network->netdev;
}

const char *network_get_path(struct network *network)
{
	return network->object_path;
}

enum security network_get_security(struct network *network)
{
	return network->security;
}

const unsigned char *network_get_psk(struct network *network)
{
	return network->psk;
}

struct l_settings *network_get_settings(struct network *network)
{
	return network->settings;
}

bool network_settings_load(struct network *network)
{
	if (network->settings)
		return true;

	switch (network->security) {
	case SECURITY_8021X:
		network->settings = storage_network_open("8021x",
							network->ssid);
		break;
	case SECURITY_PSK:
		network->settings = storage_network_open("psk", network->ssid);
		break;
	default:
		return false;
	};

	return true;
}

void network_sync_psk(struct network *network)
{
	char *hex;

	if (!network->update_psk)
		return;

	network->update_psk = false;
	hex = l_util_hexstring(network->psk, 32);
	l_settings_set_value(network->settings, "Security",
						"PreSharedKey", hex);
	l_free(hex);
	storage_network_sync("psk", network->ssid, network->settings);
}

void network_settings_close(struct network *network)
{
	if (!network->settings)
		return;

	l_settings_free(network->settings);
	network->settings = NULL;
}

int network_autoconnect(struct network *network, struct scan_bss *bss)
{
	struct wiphy *wiphy = device_get_wiphy(network->netdev);

	switch (network_get_security(network)) {
	case SECURITY_NONE:
		break;
	case SECURITY_PSK:
	{
		uint16_t pairwise_ciphers, group_ciphers;
		const char *psk;
		size_t len;

		bss_get_supported_ciphers(bss,
					&pairwise_ciphers, &group_ciphers);

		if (!wiphy_select_cipher(wiphy, pairwise_ciphers) ||
				!wiphy_select_cipher(wiphy, group_ciphers)) {
			l_debug("Cipher mis-match");
			return -ENETUNREACH;
		}

		if (network->ask_psk)
			return -ENOKEY;

		network_settings_load(network);
		psk = l_settings_get_value(network->settings, "Security",
						"PreSharedKey");

		if (!psk)
			return -ENOKEY;

		l_free(network->psk);
		network->psk = l_util_from_hexstring(psk, &len);

		if (network->psk && len != 32) {
			l_free(network->psk);
			network->psk = NULL;
			return -ENOKEY;
		}

		break;
	}
	case SECURITY_8021X:
		network_settings_load(network);
		break;
	default:
		return -ENOTSUP;
	}

	device_connect_network(network->netdev, network, bss, NULL);
	return 0;
}

void network_connect_failed(struct network *network)
{
	/*
	 * Connection failed, if PSK try asking for the passphrase
	 * once more
	 */
	if (network->security == SECURITY_PSK) {
		network->update_psk = false;
		network->ask_psk = true;
	}
}

bool network_bss_add(struct network *network, struct scan_bss *bss)
{
	return l_queue_insert(network->bss_list, bss,
					scan_bss_rank_compare, NULL);
}

static struct scan_bss *network_select_bss(struct wiphy *wiphy,
						struct network *network)
{
	struct l_queue *bss_list = network->bss_list;
	const struct l_queue_entry *bss_entry;

	/* TODO: sort the list by RSSI, potentially other criteria. */

	switch (network->security) {
	case SECURITY_NONE:
		/* Pick the first bss (strongest signal) */
		return l_queue_peek_head(bss_list);

	case SECURITY_PSK:
	case SECURITY_8021X:
		/* Pick the first bss that advertises any cipher we support. */
		for (bss_entry = l_queue_get_entries(bss_list); bss_entry;
				bss_entry = bss_entry->next) {
			struct scan_bss *bss = bss_entry->data;
			uint16_t pairwise_ciphers, group_ciphers;

			bss_get_supported_ciphers(bss, &pairwise_ciphers,
							&group_ciphers);

			if (wiphy_select_cipher(wiphy, pairwise_ciphers) &&
					wiphy_select_cipher(wiphy,
							group_ciphers))
				return bss;
		}

		return NULL;

	default:
		return NULL;
	}
}

static void passphrase_callback(enum agent_result result,
				const char *passphrase,
				struct l_dbus_message *message,
				void *user_data)
{
	struct network *network = user_data;
	struct wiphy *wiphy = device_get_wiphy(network->netdev);
	struct scan_bss *bss;

	l_debug("result %d", result);

	network->agent_request = 0;

	if (result != AGENT_RESULT_OK) {
		dbus_pending_reply(&message, dbus_error_aborted(message));
		goto err;
	}

	bss = network_select_bss(wiphy, network);

	/* Did all good BSSes go away while we waited */
	if (!bss) {
		dbus_pending_reply(&message, dbus_error_failed(message));
		goto err;
	}

	l_free(network->psk);
	network->psk = l_malloc(32);

	if (crypto_psk_from_passphrase(passphrase, (uint8_t *) network->ssid,
					strlen(network->ssid),
					network->psk) < 0) {
		l_error("PMK generation failed.  "
			"Ensure Crypto Engine is properly configured");
		dbus_pending_reply(&message, dbus_error_failed(message));

		goto err;
	}

	/*
	 * We need to store the PSK in our permanent store.  However, before
	 * we do that, make sure the PSK works.  We write to the store only
	 * when we are connected
	 */
	network->update_psk = true;

	device_connect_network(network->netdev, network, bss, message);
	return;

err:
	network_settings_close(network);

	l_free(network->psk);
	network->psk = NULL;
}

static struct l_dbus_message *network_connect_psk(struct network *network,
					struct scan_bss *bss,
					struct l_dbus_message *message)
{
	struct netdev *netdev = network->netdev;
	const char *psk;

	l_debug("");

	network_settings_load(network);

	psk = l_settings_get_value(network->settings, "Security",
					"PreSharedKey");

	if (psk) {
		size_t len;

		l_debug("psk: %s", psk);

		l_free(network->psk);
		network->psk = l_util_from_hexstring(psk, &len);

		l_debug("len: %zd", len);

		if (network->psk && len != 32) {
			l_debug("Can't parse PSK");
			l_free(network->psk);
			network->psk = NULL;
		}
	}

	l_debug("ask_psk: %s", network->ask_psk ? "true" : "false");

	if (network->ask_psk || !network->psk) {
		network->ask_psk = false;

		network->agent_request =
			agent_request_passphrase(network->object_path,
						passphrase_callback,
						message,
						network);

		if (!network->agent_request)
			return dbus_error_no_agent(message);
	} else
		device_connect_network(netdev, network, bss, message);

	return NULL;
}

static struct l_dbus_message *network_connect(struct l_dbus *dbus,
						struct l_dbus_message *message,
						void *user_data)
{
	struct network *network = user_data;
	struct netdev *netdev = network->netdev;
	struct scan_bss *bss;

	l_debug("");

	if (device_is_busy(netdev))
		return dbus_error_busy(message);

	/*
	 * Select the best BSS to use at this time.  If we have to query the
	 * agent this may not be the final choice because BSS visibility can
	 * change while we wait for the agent.
	 */
	bss = network_select_bss(device_get_wiphy(netdev), network);

	/* None of the BSSes is compatible with our stack */
	if (!bss)
		return dbus_error_not_supported(message);

	switch (network->security) {
	case SECURITY_PSK:
		return network_connect_psk(network, bss, message);
	case SECURITY_NONE:
		device_connect_network(netdev, network, bss, message);
		return NULL;
	case SECURITY_8021X:
		network_settings_load(network);
		device_connect_network(netdev, network, bss, message);
		return NULL;
	default:
		return dbus_error_not_supported(message);
	}
}

static bool network_property_get_name(struct l_dbus *dbus,
					struct l_dbus_message *message,
					struct l_dbus_message_builder *builder,
					void *user_data)
{
	struct network *network = user_data;

	l_dbus_message_builder_append_basic(builder, 's', network->ssid);
	return true;
}

static bool network_property_is_connected(struct l_dbus *dbus,
					struct l_dbus_message *message,
					struct l_dbus_message_builder *builder,
					void *user_data)
{
	struct network *network = user_data;
	bool connected;

	connected = device_get_connected_network(network->netdev) == network;
	l_dbus_message_builder_append_basic(builder, 'b', &connected);
	return true;
}

static void setup_network_interface(struct l_dbus_interface *interface)
{
	l_dbus_interface_method(interface, "Connect", 0,
				network_connect,
				"", "");

	l_dbus_interface_property(interface, "Name", 0, "s",
					network_property_get_name, NULL);

	l_dbus_interface_property(interface, "Connected", 0, "b",
					network_property_is_connected,
					NULL);
}

bool __iwd_network_append_properties(const struct network *network,
					struct l_dbus_message_builder *builder)
{
	bool connected;

	l_dbus_message_builder_enter_array(builder, "{sv}");
	dbus_dict_append_string(builder, "Name", network->ssid);

	connected = device_get_connected_network(network->netdev) == network;
	dbus_dict_append_bool(builder, "Connected", connected);
	l_dbus_message_builder_leave_array(builder);

	return true;
}

static void network_emit_added(struct network *network)
{
	struct l_dbus *dbus = dbus_get_bus();
	struct l_dbus_message *signal;
	struct l_dbus_message_builder *builder;

	signal = l_dbus_message_new_signal(dbus,
					device_get_path(network->netdev),
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
					device_get_path(network->netdev),
					IWD_DEVICE_INTERFACE,
					"NetworkRemoved");

	if (!signal)
		return;

	l_dbus_message_set_arguments(signal, "o", network->object_path);
	l_dbus_send(dbus, signal);
}

bool network_register(struct network *network, const char *path)
{
	if (!l_dbus_object_add_interface(dbus_get_bus(), path,
					IWD_NETWORK_INTERFACE, network)) {
		l_info("Unable to register %s interface",
						IWD_NETWORK_INTERFACE);
		return false;
	}

	network->object_path = strdup(path);
	network_emit_added(network);

	return true;
}

static void network_unregister(struct network *network)
{
	struct l_dbus *dbus = dbus_get_bus();

	agent_request_cancel(network->agent_request);
	network_settings_close(network);

	l_dbus_unregister_object(dbus, network->object_path);
	network_emit_removed(network);

	l_free(network->object_path);
	network->object_path = NULL;
}

void network_remove(struct network *network)
{
	if (network->object_path)
		network_unregister(network);

	l_queue_destroy(network->bss_list, NULL);
	l_free(network->psk);
	l_free(network);
}

void network_init()
{
	if (!l_dbus_register_interface(dbus_get_bus(), IWD_NETWORK_INTERFACE,
					setup_network_interface, NULL, true))
		l_error("Unable to register %s interface",
						IWD_NETWORK_INTERFACE);

	networks = l_queue_new();
}

void network_exit()
{
	l_queue_destroy(networks, l_free);
	l_dbus_unregister_interface(dbus_get_bus(), IWD_NETWORK_INTERFACE);
}
