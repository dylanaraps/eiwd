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
#include <limits.h>
#include <stdio.h>

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
#include "src/eap.h"
#include "src/network.h"

struct network {
	char *object_path;
	struct device *device;
	struct network_info *info;
	unsigned char *psk;
	unsigned int agent_request;
	struct l_queue *bss_list;
	struct l_settings *settings;
	struct l_queue *secrets;
	bool update_psk:1;  /* Whether PSK should be written to storage */
	bool ask_psk:1; /* Whether we should force-ask agent for PSK */
	int rank;
};

static struct l_queue *networks = NULL;
static size_t num_known_hidden_networks;

static bool network_settings_load(struct network *network)
{
	const char *strtype;

	if (network->settings)
		return true;

	strtype = security_to_str(network_get_security(network));
	if (!strtype)
		return false;

	network->settings = storage_network_open(strtype, network->info->ssid);

	return network->settings != NULL;
}

static void network_settings_close(struct network *network)
{
	if (!network->settings)
		return;

	l_free(network->psk);
	network->psk = NULL;

	l_settings_free(network->settings);
	network->settings = NULL;
}

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

bool network_seen(struct network *network, struct timespec *when)
{
	/*
	 * Update the last seen time.  Note this is not preserved across
	 * the network going out of range and back, or program restarts.
	 * It may be desirable for it to be preserved in some way but
	 * without too frequent filesystem writes.
	 */
	memcpy(&network->info->seen_time, when, sizeof(struct timespec));

	return true;
}

bool network_connected(struct network *network)
{
	int err;
	const char *strtype;

	l_queue_remove(networks, network->info);
	l_queue_push_head(networks, network->info);

	strtype = security_to_str(network_get_security(network));
	if (!strtype)
		return false;

	err = storage_network_touch(strtype, network->info->ssid);
	switch (err) {
	case 0:
		break;
	case -ENOENT:
		/*
		 * This is an open network seen for the first time:
		 *
		 * Write an empty settings file to keep track of the
		 * last connected time.  This will also make iwd autoconnect
		 * to this network in the future.
		 */
		network->settings = l_settings_new();

		storage_network_sync(strtype, network->info->ssid,
					network->settings);
		break;
	default:
		return false;
	}

	err = storage_network_get_mtime(strtype, network->info->ssid,
					&network->info->connected_time);
	if (err < 0)
		return false;

	network->info->is_known = true;

	return true;
}

void network_disconnected(struct network *network)
{
	network_settings_close(network);
}

static int network_find_rank_index(const struct network_info *info)
{
	const struct l_queue_entry *entry;
	int n;

	for (n = 0, entry = l_queue_get_entries(networks); entry;
						entry = entry->next) {
		struct network_info *network = entry->data;

		if (network == info)
			return n;

		if (network->is_known && network->seen_count)
			n++;
	}

	return -1;
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

bool network_rankmod(const struct network *network, double *rankmod)
{
	int n;
	int nmax;

	/*
	 * Current policy is that only networks successfully connected
	 * to at least once are autoconnectable.  Known Networks that
	 * we have never connected to are not.
	 */
	if (!network->info->connected_time.tv_sec)
		return false;

	n = network_find_rank_index(network->info);
	if (n == -1)
		return false;

	nmax = L_ARRAY_SIZE(rankmod_table);

	if (n >= nmax)
		n = nmax - 1;

	*rankmod = rankmod_table[n];

	return true;
}

static void network_info_free(void *data)
{
	struct network_info *network = data;

	if (network->is_hidden)
		num_known_hidden_networks--;

	l_free(network);
}

static struct network_info *network_info_get(const char *ssid,
						enum security security)
{
	struct network_info *network, search;

	search.type = security;
	strcpy(search.ssid, ssid);

	network = l_queue_find(networks, network_info_match, &search);

	if (!network) {
		network = l_new(struct network_info, 1);
		strcpy(network->ssid, ssid);
		network->type = security;

		l_queue_push_tail(networks, network);
	}

	network->seen_count++;

	return network;
}

static void network_info_put(struct network_info *network)
{
	if (!networks)
		return;

	if (--network->seen_count)
		return;

	if (network->is_known)
		return;

	l_queue_remove(networks, network);
	network_info_free(network);
}

struct network *network_create(struct device *device, const char *ssid,
				enum security security)
{
	struct network *network;

	network = l_new(struct network, 1);
	network->device = device;
	network->info = network_info_get(ssid, security);

	network->bss_list = l_queue_new();

	return network;
}

const char *network_get_ssid(const struct network *network)
{
	return network->info->ssid;
}

struct device *network_get_device(const struct network *network)
{
	return network->device;
}

const char *network_get_path(const struct network *network)
{
	return network->object_path;
}

enum security network_get_security(const struct network *network)
{
	return network->info->type;
}

const uint8_t *network_get_psk(const struct network *network)
{
	return network->psk;
}

struct l_queue *network_get_secrets(const struct network *network)
{
	return network->secrets;
}

bool network_set_psk(struct network *network, const uint8_t *psk)
{
	if (network->info->type != SECURITY_PSK)
		return false;

	if (!network_settings_load(network))
		return false;

	l_free(network->psk);
	network->psk = l_memdup(psk, 32);
	return true;
}

int network_get_signal_strength(const struct network *network)
{
	struct scan_bss *best_bss = l_queue_peek_head(network->bss_list);

	return best_bss->signal_strength;
}

struct l_settings *network_get_settings(const struct network *network)
{
	return network->settings;
}

static bool network_set_8021x_secrets(struct network *network)
{
	const struct l_queue_entry *entry;

	if (!network->settings)
		return false;

	for (entry = l_queue_get_entries(network->secrets); entry;
			entry = entry->next) {
		struct eap_secret_info *secret = entry->data;
		char *setting;

		switch (secret->type) {
		case EAP_SECRET_LOCAL_PKEY_PASSPHRASE:
		case EAP_SECRET_REMOTE_PASSWORD:
			if (!l_settings_set_string(network->settings,
							"Security", secret->id,
							secret->value))
				return false;
			break;

		case EAP_SECRET_REMOTE_USER_PASSWORD:
			if (!l_settings_set_string(network->settings,
							"Security", secret->id,
							secret->value))
				return false;

			if (secret->id2)
				setting = secret->id2;
			else {
				setting = alloca(strlen(secret->id) + 10);
				sprintf(setting, "%s-Password", secret->id);
			}

			if (!l_settings_set_string(network->settings,
							"Security", setting,
							secret->value + 1 +
							strlen(secret->value)))
				return false;

			break;
		}
	}

	return true;
}

static int network_load_psk(struct network *network)
{
	size_t len;
	const char *psk = l_settings_get_value(network->settings,
						"Security", "PreSharedKey");

	if (!psk)
		return -ENOKEY;

	l_free(network->psk);
	network->psk = l_util_from_hexstring(psk, &len);
	if (!network->psk)
		return -EINVAL;

	if (len != 32) {
		l_free(network->psk);
		network->psk = NULL;
		return -EINVAL;
	}

	return 0;
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
	storage_network_sync("psk", network->info->ssid, network->settings);
}

int network_autoconnect(struct network *network, struct scan_bss *bss)
{
	struct wiphy *wiphy = device_get_wiphy(network->device);
	bool is_autoconnectable;
	bool is_rsn;
	int ret;

	switch (network_get_security(network)) {
	case SECURITY_NONE:
		is_rsn = false;
		break;
	case SECURITY_PSK:
		if (network->ask_psk)
			return -ENOKEY;

		/* Fall through */
	case SECURITY_8021X:
		is_rsn = true;
		break;
	default:
		return -ENOTSUP;
	}

	if (is_rsn) {
		struct ie_rsn_info rsn;

		memset(&rsn, 0, sizeof(rsn));
		scan_bss_get_rsn_info(bss, &rsn);

		if (!wiphy_select_cipher(wiphy, rsn.pairwise_ciphers) ||
				!wiphy_select_cipher(wiphy, rsn.group_cipher)) {
			l_debug("Cipher mis-match");
			return -ENETUNREACH;
		}
	}

	if (!network_settings_load(network))
		return -ENOKEY;

	/* If no entry, default to Autoconnectable=True */
	if (!l_settings_get_bool(network->settings, "Settings",
					"Autoconnect", &is_autoconnectable))
		is_autoconnectable = true;

	ret = -EPERM;
	if (!is_autoconnectable)
		goto close_settings;

	if (network_get_security(network) == SECURITY_PSK) {
		ret = network_load_psk(network);
		if (ret < 0)
			goto close_settings;
	} else if (network_get_security(network) == SECURITY_8021X) {
		struct l_queue *missing_secrets = NULL;

		ret = eap_check_settings(network->settings, network->secrets,
					"EAP-", true, &missing_secrets);
		if (ret < 0)
			goto close_settings;

		ret = -ENOKEY;
		if (!l_queue_isempty(missing_secrets)) {
			l_queue_destroy(missing_secrets, eap_secret_info_free);
			goto close_settings;
		}

		if (!network_set_8021x_secrets(network))
			goto close_settings;
	}

	return __device_connect_network(network->device, network, bss);

close_settings:
	network_settings_close(network);
	return ret;
}

void network_connect_failed(struct network *network)
{
	/*
	 * Connection failed, if PSK try asking for the passphrase
	 * once more
	 */
	if (network_get_security(network) == SECURITY_PSK) {
		network->update_psk = false;
		network->ask_psk = true;
	}

	l_queue_destroy(network->secrets, eap_secret_info_free);
	network->secrets = NULL;
}

bool network_bss_add(struct network *network, struct scan_bss *bss)
{
	return l_queue_insert(network->bss_list, bss,
					scan_bss_rank_compare, NULL);
}

bool network_bss_list_isempty(struct network *network)
{
	return l_queue_isempty(network->bss_list);
}

void network_bss_list_clear(struct network *network)
{
	l_queue_destroy(network->bss_list, NULL);
	network->bss_list = l_queue_new();
}

struct scan_bss *network_bss_find_by_addr(struct network *network,
						const uint8_t *addr)
{
	const struct l_queue_entry *bss_entry;

	for (bss_entry = l_queue_get_entries(network->bss_list); bss_entry;
						bss_entry = bss_entry->next) {
		struct scan_bss *bss = bss_entry->data;

		if (!memcmp(bss->addr, addr, sizeof(bss->addr)))
			return bss;
	}

	return NULL;
}

/* Selects what we think is the best BSS to connect to */
struct scan_bss *network_bss_select(struct network *network)
{
	struct l_queue *bss_list = network->bss_list;
	struct wiphy *wiphy = device_get_wiphy(network->device);
	const struct l_queue_entry *bss_entry;

	switch (network_get_security(network)) {
	case SECURITY_NONE:
		/* Pick the first bss (strongest signal) */
		return l_queue_peek_head(bss_list);

	case SECURITY_PSK:
	case SECURITY_8021X:
		/*
		 * Pick the first bss that advertises ciphers compatible with
		 * the wiphy.
		 */
		for (bss_entry = l_queue_get_entries(bss_list); bss_entry;
				bss_entry = bss_entry->next) {
			struct scan_bss *bss = bss_entry->data;

			if (wiphy_can_connect(wiphy, bss))
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
	struct scan_bss *bss;

	l_debug("result %d", result);

	network->agent_request = 0;

	/*
	 * agent will release its reference to message after invoking this
	 * callback.  So if we want this message, we need to take a reference
	 * to it
	 */
	l_dbus_message_ref(message);

	if (result != AGENT_RESULT_OK) {
		dbus_pending_reply(&message, dbus_error_aborted(message));
		goto err;
	}

	bss = network_bss_select(network);

	/* Did all good BSSes go away while we waited */
	if (!bss) {
		dbus_pending_reply(&message, dbus_error_failed(message));
		goto err;
	}

	l_free(network->psk);
	network->psk = l_malloc(32);

	if (crypto_psk_from_passphrase(passphrase,
					(uint8_t *) network->info->ssid,
					strlen(network->info->ssid),
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

	device_connect_network(network->device, network, bss, message);
	l_dbus_message_unref(message);
	return;

err:
	network_settings_close(network);
}

static struct l_dbus_message *network_connect_psk(struct network *network,
					struct scan_bss *bss,
					struct l_dbus_message *message)
{
	struct device *device = network->device;

	l_debug("");

	if (network_settings_load(network))
		network_load_psk(network);
	else
		network->settings = l_settings_new();

	l_debug("ask_psk: %s", network->ask_psk ? "true" : "false");

	if (network->ask_psk || !network->psk) {
		network->ask_psk = false;

		network->agent_request =
			agent_request_passphrase(network->object_path,
						passphrase_callback,
						message, network, NULL);

		if (!network->agent_request)
			return dbus_error_no_agent(message);
	} else
		device_connect_network(device, network, bss, message);

	return NULL;
}

struct eap_secret_request {
	struct network *network;
	struct eap_secret_info *secret;
	struct l_queue *pending_secrets;
	void (*callback)(enum agent_result result,
				struct l_dbus_message *message,
				struct eap_secret_request *req);
};

static void eap_secret_request_free(void *data)
{
	struct eap_secret_request *req = data;

	eap_secret_info_free(req->secret);
	l_queue_destroy(req->pending_secrets, eap_secret_info_free);
	l_free(req);
}

static bool eap_secret_info_match_local(const void *a, const void *b)
{
	const struct eap_secret_info *info = a;

	return info->type == EAP_SECRET_LOCAL_PKEY_PASSPHRASE;
}

static void eap_password_callback(enum agent_result result, const char *value,
					struct l_dbus_message *message,
					void *user_data)
{
	struct eap_secret_request *req = user_data;

	req->network->agent_request = 0;
	req->secret->value = l_strdup(value);

	req->callback(result, message, req);
}

static void eap_user_password_callback(enum agent_result result,
					const char *user, const char *passwd,
					struct l_dbus_message *message,
					void *user_data)
{
	struct eap_secret_request *req = user_data;

	req->network->agent_request = 0;

	if (user && passwd) {
		size_t len1 = strlen(user) + 1;
		size_t len2 = strlen(passwd) + 1;

		req->secret->value = l_malloc(len1 + len2);
		memcpy(req->secret->value, user, len1);
		memcpy(req->secret->value + len1, passwd, len2);
	}

	req->callback(result, message, req);
}

static bool eap_send_agent_req(struct network *network,
				struct l_queue *pending_secrets,
				struct l_dbus_message *message,
				void *callback)
{
	struct eap_secret_request *req;
	struct eap_secret_info *info;

	/*
	 * Request the locally-verifiable data first, i.e.
	 * the private key encryption passphrases so that we don't bother
	 * asking for any other data if these passphrases turn out to
	 * be wrong.
	 */
	info = l_queue_remove_if(pending_secrets, eap_secret_info_match_local,
					NULL);

	if (!info)
		info = l_queue_pop_head(pending_secrets);

	req = l_new(struct eap_secret_request, 1);
	req->network = network;
	req->secret = info;
	req->pending_secrets = pending_secrets;
	req->callback = callback;

	switch (info->type) {
	case EAP_SECRET_LOCAL_PKEY_PASSPHRASE:
		network->agent_request = agent_request_pkey_passphrase(
						network->object_path,
						eap_password_callback,
						message, req,
						eap_secret_request_free);
		break;
	case EAP_SECRET_REMOTE_PASSWORD:
		network->agent_request = agent_request_user_password(
						network->object_path,
						info->parameter,
						eap_password_callback,
						message, req,
						eap_secret_request_free);
		break;
	case EAP_SECRET_REMOTE_USER_PASSWORD:
		network->agent_request = agent_request_user_name_password(
						network->object_path,
						eap_user_password_callback,
						message, req,
						eap_secret_request_free);
		break;
	}

	if (network->agent_request)
		return true;

	eap_secret_request_free(req);
	return false;
}

static struct l_dbus_message *network_connect_8021x(struct network *network,
						struct scan_bss *bss,
						struct l_dbus_message *message);

static void eap_secret_done(enum agent_result result,
				struct l_dbus_message *message,
				struct eap_secret_request *req)
{
	struct network *network = req->network;
	struct eap_secret_info *secret = req->secret;
	struct l_queue *pending = req->pending_secrets;
	struct scan_bss *bss;

	l_debug("result %d", result);

	/*
	 * Agent will release its reference to message after invoking this
	 * callback.  So if we want this message, we need to take a reference
	 * to it.
	 */
	l_dbus_message_ref(message);

	if (result != AGENT_RESULT_OK) {
		dbus_pending_reply(&message, dbus_error_aborted(message));
		goto err;
	}

	bss = network_bss_select(network);

	/* Did all good BSSes go away while we waited */
	if (!bss) {
		dbus_pending_reply(&message, dbus_error_failed(message));
		goto err;
	}

	if (!network->secrets)
		network->secrets = l_queue_new();

	l_queue_push_tail(network->secrets, secret);

	req->secret = NULL;

	/*
	 * If we have any other missing secrets in the queue, send the
	 * next request immediately unless we've just received a passphrase
	 * for a local private key.  In that case we will first call
	 * network_connect_8021x to have it validate the new passphrase.
	 */
	if (secret->type == EAP_SECRET_LOCAL_PKEY_PASSPHRASE ||
			l_queue_isempty(req->pending_secrets)) {
		struct l_dbus_message *reply;

		reply = network_connect_8021x(network, bss, message);
		if (reply)
			dbus_pending_reply(&message, reply);
		else
			l_dbus_message_unref(message);

		return;
	}

	req->pending_secrets = NULL;

	if (eap_send_agent_req(network, pending, message,
				eap_secret_done)) {
		l_dbus_message_unref(message);
		return;
	}

	dbus_pending_reply(&message, dbus_error_no_agent(message));
err:
	network_settings_close(network);
}

static struct l_dbus_message *network_connect_8021x(struct network *network,
						struct scan_bss *bss,
						struct l_dbus_message *message)
{
	int r;
	struct l_queue *missing_secrets = NULL;
	struct l_dbus_message *reply;

	l_debug("");

	r = eap_check_settings(network->settings, network->secrets, "EAP-",
				true, &missing_secrets);
	if (r) {
		if (r == -EUNATCH)
			reply = dbus_error_not_available(message);
		else if (r == -ENOTSUP)
			reply = dbus_error_not_supported(message);
		else if (r == -EACCES)
			reply = dbus_error_failed(message);
		else
			reply = dbus_error_not_configured(message);

		goto error;
	}

	l_debug("supplied %u secrets, %u more needed for EAP",
		l_queue_length(network->secrets),
		l_queue_length(missing_secrets));

	if (l_queue_isempty(missing_secrets)) {
		if (!network_set_8021x_secrets(network)) {
			reply = dbus_error_failed(message);

			goto error;
		}

		device_connect_network(network->device, network, bss, message);

		return NULL;
	}

	if (eap_send_agent_req(network, missing_secrets, message,
				eap_secret_done))
		return NULL;

	reply = dbus_error_no_agent(message);

error:
	network_settings_close(network);

	l_queue_destroy(network->secrets, eap_secret_info_free);
	network->secrets = NULL;

	return reply;
}

static struct l_dbus_message *network_connect(struct l_dbus *dbus,
						struct l_dbus_message *message,
						void *user_data)
{
	struct network *network = user_data;
	struct device *device = network->device;
	struct scan_bss *bss;

	l_debug("");

	if (device_is_busy(device))
		return dbus_error_busy(message);

	/*
	 * Select the best BSS to use at this time.  If we have to query the
	 * agent this may not be the final choice because BSS visibility can
	 * change while we wait for the agent.
	 */
	bss = network_bss_select(network);

	/* None of the BSSes is compatible with our stack */
	if (!bss)
		return dbus_error_not_supported(message);

	switch (network_get_security(network)) {
	case SECURITY_PSK:
		return network_connect_psk(network, bss, message);
	case SECURITY_NONE:
		device_connect_network(device, network, bss, message);
		return NULL;
	case SECURITY_8021X:
		if (!network_settings_load(network))
			return dbus_error_not_configured(message);

		return network_connect_8021x(network, bss, message);
	default:
		return dbus_error_not_supported(message);
	}
}

void network_connect_new_hidden_network(struct network *network,
						struct l_dbus_message *message)
{
	struct device *device = network->device;
	struct scan_bss *bss;
	struct l_dbus_message *error;

	l_debug("");

	network_info_set_hidden(network);

	bss = network_bss_select(network);
	if (!bss) {
		/* This should never happened for the hidden networks. */
		error = dbus_error_not_supported(message);
		goto reply_error;
	}

	switch (network_get_security(network)) {
	case SECURITY_PSK:
		error = network_connect_psk(network, bss, message);
		break;
	case SECURITY_NONE:
		device_connect_network(device, network, bss, message);
		return;
	default:
		error = dbus_error_not_supported(message);
		break;
	}

	if (error)
		goto reply_error;

	return;

reply_error:
	dbus_pending_reply(&message, error);
}

static bool network_property_get_name(struct l_dbus *dbus,
					struct l_dbus_message *message,
					struct l_dbus_message_builder *builder,
					void *user_data)
{
	struct network *network = user_data;

	l_dbus_message_builder_append_basic(builder, 's', network->info->ssid);
	return true;
}

static bool network_property_is_connected(struct l_dbus *dbus,
					struct l_dbus_message *message,
					struct l_dbus_message_builder *builder,
					void *user_data)
{
	struct network *network = user_data;
	bool connected;

	connected = device_get_connected_network(network->device) == network;
	l_dbus_message_builder_append_basic(builder, 'b', &connected);
	return true;
}

static bool network_property_get_device(struct l_dbus *dbus,
					struct l_dbus_message *message,
					struct l_dbus_message_builder *builder,
					void *user_data)
{
	struct network *network = user_data;

	l_dbus_message_builder_append_basic(builder, 'o',
					device_get_path(network->device));

	return true;
}

static bool network_property_get_type(struct l_dbus *dbus,
					struct l_dbus_message *message,
					struct l_dbus_message_builder *builder,
					void *user_data)

{
	struct network *network = user_data;
	enum security security = network_get_security(network);

	l_dbus_message_builder_append_basic(builder, 's',
						security_to_str(security));

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

	l_dbus_interface_property(interface, "Device", 0, "o",
					network_property_get_device, NULL);

	l_dbus_interface_property(interface, "Type", 0, "s",
					network_property_get_type, NULL);
}

bool network_register(struct network *network, const char *path)
{
	if (!l_dbus_object_add_interface(dbus_get_bus(), path,
					IWD_NETWORK_INTERFACE, network)) {
		l_info("Unable to register %s interface",
						IWD_NETWORK_INTERFACE);
		return false;
	}

	if (!l_dbus_object_add_interface(dbus_get_bus(), path,
					L_DBUS_INTERFACE_PROPERTIES, network))
		l_info("Unable to register %s interface",
						L_DBUS_INTERFACE_PROPERTIES);

	network->object_path = strdup(path);

	return true;
}

static void network_unregister(struct network *network, int reason)
{
	struct l_dbus *dbus = dbus_get_bus();

	agent_request_cancel(network->agent_request, reason);
	network_settings_close(network);

	l_dbus_unregister_object(dbus, network->object_path);

	l_free(network->object_path);
	network->object_path = NULL;
}

void network_remove(struct network *network, int reason)
{
	if (network->object_path)
		network_unregister(network, reason);

	l_queue_destroy(network->secrets, eap_secret_info_free);
	network->secrets = NULL;

	l_queue_destroy(network->bss_list, NULL);
	network_info_put(network->info);

	l_free(network);
}

void network_init()
{
	if (!l_dbus_register_interface(dbus_get_bus(), IWD_NETWORK_INTERFACE,
					setup_network_interface, NULL, false))
		l_error("Unable to register %s interface",
						IWD_NETWORK_INTERFACE);

	networks = l_queue_new();
}

void network_exit()
{
	l_queue_destroy(networks, network_info_free);
	networks = NULL;

	l_dbus_unregister_interface(dbus_get_bus(), IWD_NETWORK_INTERFACE);
}

int network_rank_compare(const void *a, const void *b, void *user)
{
	const struct network *new_network = a;
	const struct network *network = b;

	return network->rank - new_network->rank;
}

void network_rank_update(struct network *network)
{
	bool connected;
	int rank;

	/*
	 * Theoretically there may be difference between the BSS selection
	 * here and in network_bss_select but those should be rare cases.
	 */
	struct scan_bss *best_bss = l_queue_peek_head(network->bss_list);

	connected = device_get_connected_network(network->device) == network;

	/*
	 * The rank should separate networks into four groups that use
	 * non-overlapping ranges for:
	 *   - current connected network,
	 *   - other networks we've connected to before,
	 *   - networks with preprovisioned settings file that we haven't
	 *     used yet,
	 *   - other networks.
	 *
	 * Within the 2nd group the last connection time is the main factor,
	 * for the other two groups it's the BSS rank - mainly signal strength.
	 */
	if (connected)
		rank = INT_MAX;
	else if (network->info->connected_time.tv_sec != 0) {
		int n = network_find_rank_index(network->info);

		if (n >= (int) L_ARRAY_SIZE(rankmod_table))
			n = L_ARRAY_SIZE(rankmod_table) - 1;

		rank = rankmod_table[n] * best_bss->rank + USHRT_MAX;
	} else if (network->info->is_known)
		rank = best_bss->rank;
	else
		rank = (int) best_bss->rank - USHRT_MAX; /* Negative rank */

	network->rank = rank;
}

bool network_info_add_known(const char *ssid, enum security security)
{
	struct network_info *network;
	struct l_settings *settings;
	bool is_hidden;
	int err;

	network = l_new(struct network_info, 1);
	strcpy(network->ssid, ssid);
	network->type = security;

	err = storage_network_get_mtime(security_to_str(security), ssid,
					&network->connected_time);
	if (err < 0) {
		l_free(network);
		return false;
	}

	network->is_known = true;

	settings = storage_network_open(security_to_str(security), ssid);

	if (l_settings_get_bool(settings, "Settings", "Hidden", &is_hidden))
		network->is_hidden = is_hidden;

	if (network->is_hidden)
		num_known_hidden_networks++;

	l_settings_free(settings);

	l_queue_insert(networks, network, timespec_compare, NULL);

	return true;
}

static void network_info_check_device(struct device *device, void *user_data)
{
	struct network_info *info = user_data;
	struct network *network;

	network = device_get_connected_network(device);

	if (network && network->info == info)
		device_disconnect(device);
}

bool network_info_forget_known(const char *ssid, enum security security)
{
	struct network_info *network, search;

	search.type = security;
	strcpy(search.ssid, ssid);

	network = l_queue_remove_if(networks, network_info_match, &search);
	if (!network)
		return false;

	if (!network->seen_count) {
		network_info_free(network);

		return true;
	}

	memset(&network->connected_time, 0, sizeof(struct timespec));

	network->is_known = false;

	l_queue_push_tail(networks, network);

	__iwd_device_foreach(network_info_check_device, network);

	return true;
}

void network_info_foreach(network_info_foreach_func_t function,
				void *user_data)
{
	const struct l_queue_entry *entry;

	for (entry = l_queue_get_entries(networks); entry; entry = entry->next)
		function(entry->data, user_data);
}

const struct l_queue *network_info_get_known()
{
	return networks;
}

bool network_info_has_hidden(void)
{
	return num_known_hidden_networks ? true : false;
}

void network_info_set_hidden(struct network *network)
{
	if (network->info->is_hidden)
		return;

	network->info->is_hidden = true;
	num_known_hidden_networks += 1;
}

bool network_info_is_hidden(struct network *network)
{
	return network->info->is_hidden;
}

const struct network_info *network_info_find(const char *ssid,
						enum security security)
{
	struct network_info query;

	query.type = security;
	strcpy(query.ssid, ssid);

	return l_queue_find(networks, network_info_match, &query);
}
