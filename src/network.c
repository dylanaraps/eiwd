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
#include <stdio.h>
#include <errno.h>
#include <limits.h>
#include <alloca.h>

#include <ell/ell.h>

#include "src/ie.h"
#include "src/crypto.h"

#include "src/iwd.h"
#include "src/common.h"
#include "src/storage.h"
#include "src/scan.h"
#include "src/dbus.h"
#include "src/agent.h"
#include "src/netdev.h"
#include "src/wiphy.h"
#include "src/station.h"
#include "src/eap.h"
#include "src/knownnetworks.h"
#include "src/network.h"

struct network {
	char *object_path;
	struct station *station;
	struct network_info *info;
	unsigned char *psk;
	char *passphrase;
	unsigned int agent_request;
	struct l_queue *bss_list;
	struct l_settings *settings;
	struct l_queue *secrets;
	bool update_psk:1;  /* Whether PSK should be written to storage */
	bool ask_passphrase:1; /* Whether we should force-ask agent */
	int rank;
};

static struct l_queue *networks;

static bool network_settings_load(struct network *network)
{
	if (network->settings)
		return true;

	network->settings = storage_network_open(network_get_security(network),
							network->info->ssid);

	return network->settings != NULL;
}

static void network_settings_close(struct network *network)
{
	if (!network->settings)
		return;

	l_free(network->psk);
	network->psk = NULL;

	l_free(network->passphrase);
	network->passphrase = NULL;

	l_settings_free(network->settings);
	network->settings = NULL;
}

bool network_info_match(const void *a, const void *b)
{
	const struct network_info *ni_a = a;
	const struct network_info *ni_b = b;

	if (ni_a->type != ni_b->type)
		return false;

	if (strcmp(ni_a->ssid, ni_b->ssid))
		return false;

	return true;
}

static bool network_secret_check_cacheable(void *data, void *user_data)
{
	struct eap_secret_info *secret = data;

	if (secret->cache_policy == EAP_CACHE_NEVER) {
		eap_secret_info_free(secret);
		return true;
	}

	return false;
}

void network_connected(struct network *network)
{
	int err;

	/*
	 * This triggers an update to network->info->connected_time and
	 * other possible actions in knownnetworks.c.
	 */
	err = storage_network_touch(network_get_security(network),
					network->info->ssid);
	switch (err) {
	case 0:
		break;
	case -ENOENT:
		/*
		 * This is an open network seen for the first time:
		 *
		 * Write a settings file to keep track of the
		 * last connected time.  This will also make iwd autoconnect
		 * to this network in the future.
		 */
		if (!network->settings)
			network->settings = l_settings_new();

		storage_network_sync(network_get_security(network),
					network->info->ssid,
					network->settings);
		break;
	default:
		l_error("Error %i touching network config", err);
		break;
	}

	l_queue_foreach_remove(network->secrets,
				network_secret_check_cacheable, network);
}

void network_disconnected(struct network *network)
{
	network_settings_close(network);
}

struct network_find_rank_data {
	const struct network_info *info;
	int n;
};

static bool network_find_rank_update(const struct network_info *network,
					void *user_data)
{
	struct network_find_rank_data *data = user_data;

	if (network == data->info)
		return false;

	if (network->seen_count)
		data->n++;

	return true;
}

static int network_find_rank_index(const struct network_info *info)
{
	struct network_find_rank_data data = { info, 0 };

	if (!known_networks_foreach(network_find_rank_update, &data))
		return data.n;

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

void network_info_free(void *data)
{
	struct network_info *network = data;

	l_free(network);
}

static struct network_info *network_info_get(const char *ssid,
						enum security security)
{
	struct network_info *network;

	network = known_networks_find(ssid, security);

	if (!network) {
		struct network_info search;

		search.type = security;
		strcpy(search.ssid, ssid);

		network = l_queue_find(networks, network_info_match, &search);
	}

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
	if (--network->seen_count)
		return;

	if (!networks || network->is_known)
		return;

	l_queue_remove(networks, network);
	network_info_free(network);
}

struct network *network_create(struct station *station, const char *ssid,
				enum security security)
{
	struct network *network;

	network = l_new(struct network, 1);
	network->station = station;
	network->info = network_info_get(ssid, security);

	network->bss_list = l_queue_new();

	return network;
}

const char *network_get_ssid(const struct network *network)
{
	return network->info->ssid;
}

const char *network_get_path(const struct network *network)
{
	return network->object_path;
}

enum security network_get_security(const struct network *network)
{
	return network->info->type;
}

const uint8_t *network_get_psk(struct network *network)
{
	int r;

	if (network->psk)
		return network->psk;

	if (!network->passphrase)
		return NULL;

	network->psk = l_malloc(32);
	r = crypto_psk_from_passphrase(network->passphrase,
					(uint8_t *) network->info->ssid,
					strlen(network->info->ssid),
					network->psk);
	if (!r)
		return network->psk;

	l_free(network->psk);
	network->psk = NULL;
	l_error("PMK generation failed: %s.  "
		"Ensure Crypto Engine is properly configured",
		strerror(-r));
	return NULL;
}

const char *network_get_passphrase(const struct network *network)
{
	return network->passphrase;
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

static int network_load_psk(struct network *network, bool need_passphrase)
{
	size_t len;
	const char *psk = l_settings_get_value(network->settings,
						"Security", "PreSharedKey");
	char *passphrase = l_settings_get_string(network->settings,
						"Security", "Passphrase");

	if ((!psk || need_passphrase) && !passphrase)
		return -ENOKEY;

	l_free(network->passphrase);
	network->passphrase = passphrase;
	l_free(network->psk);
	network->psk = l_util_from_hexstring(psk, &len);
	if (network->psk && len == 32)
		return 0;

	l_free(network->passphrase);
	network->passphrase = NULL;
	l_free(network->psk);
	network->psk = NULL;
	return -EINVAL;
}

void network_sync_psk(struct network *network)
{
	struct l_settings *fs_settings;

	if (!network->update_psk)
		return;

	network->update_psk = false;

	fs_settings = storage_network_open(SECURITY_PSK, network->info->ssid);

	if (network->psk) {
		char *hex = l_util_hexstring(network->psk, 32);
		l_settings_set_value(network->settings, "Security",
						"PreSharedKey", hex);

		if (fs_settings)
			l_settings_set_value(fs_settings, "Security",
						"PreSharedKey", hex);

		l_free(hex);
	}

	if (network->passphrase) {
		l_settings_set_string(network->settings, "Security",
							"Passphrase",
							network->passphrase);

		if (fs_settings)
			l_settings_set_string(fs_settings, "Security",
							"Passphrase",
							network->passphrase);
	}

	if (fs_settings) {
		storage_network_sync(SECURITY_PSK, network->info->ssid,
					fs_settings);
		l_settings_free(fs_settings);
	} else
		storage_network_sync(SECURITY_PSK, network->info->ssid,
					network->settings);
}

static inline bool __bss_is_sae(const struct scan_bss *bss,
						const struct ie_rsn_info *rsn)
{
	if (rsn->akm_suites & IE_RSN_AKM_SUITE_SAE_SHA256)
		return true;

	return false;
}

static bool bss_is_sae(const struct scan_bss *bss)
{
	struct ie_rsn_info rsn;

	memset(&rsn, 0, sizeof(rsn));
	scan_bss_get_rsn_info(bss, &rsn);

	return __bss_is_sae(bss, &rsn);
}

int network_autoconnect(struct network *network, struct scan_bss *bss)
{
	struct station *station = network->station;
	struct wiphy *wiphy = station_get_wiphy(station);
	enum security security = network_get_security(network);
	struct ie_rsn_info rsn;
	bool is_autoconnectable;
	bool is_rsn;
	int ret;

	switch (security) {
	case SECURITY_NONE:
		is_rsn = false;
		break;
	case SECURITY_PSK:
		if (network->ask_passphrase)
			return -ENOKEY;

		/* Fall through */
	case SECURITY_8021X:
		is_rsn = true;
		break;
	default:
		return -ENOTSUP;
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

	if (!is_rsn)
		goto done;

	memset(&rsn, 0, sizeof(rsn));
	scan_bss_get_rsn_info(bss, &rsn);

	if (!wiphy_select_cipher(wiphy, rsn.pairwise_ciphers) ||
			!wiphy_select_cipher(wiphy, rsn.group_cipher)) {
		l_debug("Cipher mis-match");
		ret = -ENETUNREACH;
		goto close_settings;
	}

	if (security == SECURITY_PSK) {
		ret = network_load_psk(network, __bss_is_sae(bss, &rsn));
		if (ret < 0)
			goto close_settings;
	} else if (security == SECURITY_8021X) {
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

done:
	return __station_connect_network(station, network, bss);

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
		network->ask_passphrase = true;
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
	struct wiphy *wiphy = station_get_wiphy(network->station);
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
	struct station *station = network->station;
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
	network->psk = NULL;
	l_free(network->passphrase);
	network->passphrase = l_strdup(passphrase);

	/*
	 * We need to store the PSK in our permanent store.  However, before
	 * we do that, make sure the PSK works.  We write to the store only
	 * when we are connected
	 */
	network->update_psk = true;

	station_connect_network(station, network, bss, message);
	l_dbus_message_unref(message);
	return;

err:
	network_settings_close(network);
}

static struct l_dbus_message *network_connect_psk(struct network *network,
					struct scan_bss *bss,
					struct l_dbus_message *message)
{
	struct station *station = network->station;
	/*
	 * A legacy psk file may only contain the PreSharedKey entry. For SAE
	 * networks the raw Passphrase is required. So in this case where
	 * the psk is found but no Passphrase, we ask the agent.  The psk file
	 * will then be re-written to contain the raw passphrase.
	 */
	bool need_passphrase = bss_is_sae(bss);

	l_debug("ask_passphrase: %s",
		network->ask_passphrase ? "true" : "false");

	if  (!network_settings_load(network)) {
		network->settings = l_settings_new();
		network->ask_passphrase = true;
	} else if (!network->ask_passphrase)
		network->ask_passphrase =
			network_load_psk(network, need_passphrase) < 0;

	if (network->ask_passphrase) {
		network->ask_passphrase = false;

		network->agent_request =
			agent_request_passphrase(network->object_path,
						passphrase_callback,
						message, network, NULL);

		if (!network->agent_request)
			return dbus_error_no_agent(message);
	} else
		station_connect_network(station, network, bss, message);

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
	struct station *station = network->station;
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

		station_connect_network(station, network, bss, message);

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
	struct station *station = network->station;
	struct scan_bss *bss;

	l_debug("");

	if (station_is_busy(station))
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
		station_connect_network(station, network, bss, message);
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
	struct station *station = network->station;
	struct scan_bss *bss;
	struct l_dbus_message *error;

	l_debug("");

	/*
	 * This is not a Known Network.  If connection succeeds, either
	 * network_sync_psk or network_connected will save this network
	 * as hidden and trigger an update to the hidden networks count.
	 */
	network->info->is_hidden = true;

	bss = network_bss_select(network);
	if (!bss) {
		/* This should never happened for the hidden networks. */
		error = dbus_error_not_supported(message);
		goto reply_error;
	}

	network->settings = l_settings_new();
	l_settings_set_bool(network->settings, "Settings", "Hidden", true);

	switch (network_get_security(network)) {
	case SECURITY_PSK:
		error = network_connect_psk(network, bss, message);
		break;
	case SECURITY_NONE:
		station_connect_network(station, network, bss, message);
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
	struct station *station = network->station;
	bool connected;

	connected = station_get_connected_network(station) == network;
	l_dbus_message_builder_append_basic(builder, 'b', &connected);
	return true;
}

static bool network_property_get_device(struct l_dbus *dbus,
					struct l_dbus_message *message,
					struct l_dbus_message_builder *builder,
					void *user_data)
{
	struct network *network = user_data;
	struct station *station = network->station;
	struct netdev *netdev = station_get_netdev(station);

	l_dbus_message_builder_append_basic(builder, 'o',
						netdev_get_path(netdev));

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

static bool network_property_get_known_network(struct l_dbus *dbus,
					struct l_dbus_message *message,
					struct l_dbus_message_builder *builder,
					void *user_data)
{
	struct network *network = user_data;

	if (!network->info->is_known)
		return false;

	l_dbus_message_builder_append_basic(builder, 'o',
					known_network_get_path(network->info));

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

	l_dbus_interface_property(interface, "KnownNetwork", 0, "o",
				network_property_get_known_network, NULL);
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

	network->object_path = l_strdup(path);

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

void network_rank_update(struct network *network, bool connected)
{
	/*
	 * Theoretically there may be difference between the BSS selection
	 * here and in network_bss_select but those should be rare cases.
	 */
	struct scan_bss *best_bss = l_queue_peek_head(network->bss_list);
	int rank;

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

static void emit_known_network_changed(struct station *station, void *user_data)
{
	struct network_info *info = user_data;
	struct network *network;

	network = station_network_find(station, info->ssid, info->type);
	if (!network)
		return;

	l_dbus_property_changed(dbus_get_bus(),
				network_get_path(network),
				IWD_NETWORK_INTERFACE,
				"KnownNetwork");
}

struct network_info *network_info_add_known(const char *ssid,
						enum security security)
{
	struct network_info *network;
	struct network_info search;

	strcpy(search.ssid, ssid);
	search.type = security;

	network = l_queue_remove_if(networks, network_info_match, &search);
	if (network) {
		/* Promote network to is_known */
		network->is_known = true;
		station_foreach(emit_known_network_changed, network);
		return network;
	}

	network = l_new(struct network_info, 1);
	strcpy(network->ssid, ssid);
	network->type = security;
	network->is_known = true;

	return network;
}

static void disconnect_no_longer_known(struct station *station, void *user_data)
{
	struct network_info *info = user_data;
	struct network *network;

	network = station_get_connected_network(station);

	if (network && network->info == info)
		station_disconnect(station);
}

void network_info_forget_known(struct network_info *network)
{
	network->is_known = false;

	station_foreach(emit_known_network_changed, network);
	station_foreach(disconnect_no_longer_known, network);

	/*
	 * Network is no longer a Known Network, see if we still need to
	 * keep the network_info around.
	 */
	if (network->seen_count)
		l_queue_push_tail(networks, network);
	else
		network_info_free(network);
}
