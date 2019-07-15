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

#include <dirent.h>
#include <errno.h>

#include <ell/ell.h>

#include "src/iwd.h"
#include "src/common.h"
#include "src/network.h"
#include "src/util.h"
#include "src/hotspot.h"
#include "src/ie.h"

static struct l_dir_watch *hs20_dir_watch;
static const char *hs20_dir = DAEMON_STORAGEDIR "/hotspot";
static struct l_queue *hs20_settings;

struct hs20_config {
	char *filename;
	uint8_t hessid[6];
	char **nai_realms;
	uint8_t *rc; /* roaming consortium */
	size_t rc_len;
};

static bool match_filename(const void *a, const void *b)
{
	const struct hs20_config *config = a;
	const char *filename = b;

	if (!strcmp(config->filename, filename))
		return true;

	return false;
}

static void hs20_config_free(void *user_data)
{
	struct hs20_config *config = user_data;

	l_strv_free(config->nai_realms);
	l_free(config->filename);
	l_free(config);
}

static struct hs20_config *hs20_config_new(struct l_settings *settings,
						char *filename)
{
	struct hs20_config *config;
	char *str;
	char **nai_realms = NULL;
	const char *rc_str;

	config = l_new(struct hs20_config, 1);

	/* One of HESSID, NAI realms, or Roaming Consortium must be included */
	str = l_settings_get_string(settings, "Hotspot", "HESSID");
	if (str) {
		util_string_to_address(str, config->hessid);
		l_free(str);
	}

	nai_realms = l_settings_get_string_list(settings, "Hotspot",
						"NAIRealmNames", ',');
	if (nai_realms)
		config->nai_realms = nai_realms;

	rc_str = l_settings_get_value(settings, "Hotspot", "RoamingConsortium");
	if (rc_str)
		config->rc = l_util_from_hexstring(rc_str, &config->rc_len);

	if (util_mem_is_zero(config->hessid, 6) && !nai_realms && !config->rc) {
		l_free(config);
		return NULL;
	}

	config->filename = l_strdup(filename);

	return config;
}

static void hs20_dir_watch_cb(const char *filename,
				enum l_dir_watch_event event,
				void *user_data)
{
	struct l_settings *new;
	struct hs20_config *config;

	L_AUTO_FREE_VAR(char *, full_path) = NULL;

	/*
	 * Ignore notifications for the actual directory, we can't do
	 * anything about some of them anyway.  Only react to
	 * notifications for files in the storage directory.
	 */
	if (!filename)
		return;

	full_path = l_strdup_printf("%s/%s", hs20_dir, filename);

	switch (event) {
	case L_DIR_WATCH_EVENT_CREATED:
		new = l_settings_new();

		if (!l_settings_load_from_file(new, full_path)) {
			l_settings_free(new);
			return;
		}

		config = hs20_config_new(new, full_path);
		if (!config)
			break;

		l_queue_push_head(hs20_settings, config);

		break;
	case L_DIR_WATCH_EVENT_REMOVED:
		config = l_queue_remove_if(hs20_settings, match_filename,
						full_path);
		if (!config)
			return;

		hs20_config_free(config);
		config = NULL;

		/*
		 * TODO: Disconnect any networks using this provisioning file
		 */

		break;
	case L_DIR_WATCH_EVENT_MODIFIED:
		config = l_queue_remove_if(hs20_settings, match_filename,
						full_path);
		if (!config)
			return;

		hs20_config_free(config);

		new = l_settings_new();

		if (!l_settings_load_from_file(new, full_path)) {
			l_settings_free(new);
			return;
		}

		config = hs20_config_new(new, full_path);
		if (!config)
			break;

		l_queue_push_head(hs20_settings, config);

		break;
	case L_DIR_WATCH_EVENT_ACCESSED:
		break;
	}
}

static void hs20_dir_watch_destroy(void *user_data)
{
	hs20_dir_watch = NULL;
}

static bool match_hessid(const void *a, const void *b)
{
	const struct hs20_config *config = a;
	const uint8_t *hessid = b;

	if (!memcmp(config->hessid, hessid, 6))
		return true;

	return false;
}

static bool match_nai_realm(const void *a, const void *b)
{
	const struct hs20_config *config = a;
	char **realms = (char **)b;

	while (*realms) {
		if (l_strv_contains(config->nai_realms, *realms))
			return true;

		realms++;
	}

	return false;
}

static bool match_rc(const void *a, const void *b)
{
	const struct hs20_config *config = a;
	const uint8_t *rc_ie = b;
	const uint8_t *rc1, *rc2, *rc3;
	size_t rc1_len, rc2_len, rc3_len;

	if (ie_parse_roaming_consortium_from_data(rc_ie, rc_ie[1] + 2, NULL,
						&rc1, &rc1_len, &rc2, &rc2_len,
						&rc3, &rc3_len) < 0)
		return false;

	/* rc1 is guarenteed to be set if the above returns success */
	if (rc1_len == config->rc_len && !memcmp(rc1, config->rc, rc1_len))
		return true;

	if (rc2 && rc2_len == config->rc_len &&
				!memcmp(rc2, config->rc, rc2_len))
		return true;

	if (rc3 && rc1_len == config->rc_len &&
				!memcmp(rc3, config->rc, rc3_len))
		return true;

	return false;
}

const char *hs20_find_settings_file(struct network *network)
{
	struct hs20_config *config;
	uint8_t *hessid = network_get_hessid(network);
	char **nai_realms = network_get_nai_realms(network);
	const uint8_t *rc_ie = network_get_roaming_consortium(network);

	if (!hessid || util_mem_is_zero(hessid, 6)) {
		l_debug("Network has no HESSID, trying NAI realms");
		goto try_nai_realms;
	}

	config = l_queue_find(hs20_settings, match_hessid, hessid);
	if (config)
		return config->filename;

try_nai_realms:
	if (!nai_realms) {
		l_debug("Network has no NAI Realms, trying roaming consortium");
		goto try_roaming_consortium;
	}

	config = l_queue_find(hs20_settings, match_nai_realm, nai_realms);
	if (config)
		return config->filename;

try_roaming_consortium:
	if (!rc_ie) {
		l_debug("Network has no roaming consortium IE");
		return NULL;
	}

	config = l_queue_find(hs20_settings, match_rc, rc_ie);
	if (config)
		return config->filename;

	return NULL;
}

const uint8_t *hs20_get_roaming_consortium(struct network *network,
						size_t *len)
{
	struct hs20_config *config;
	const uint8_t *rc_ie = network_get_roaming_consortium(network);

	if (!rc_ie)
		return NULL;

	config = l_queue_find(hs20_settings, match_rc, rc_ie);
	if (config) {
		*len = config->rc_len;
		return config->rc;
	}

	return NULL;
}

static int hotspot_init(void)
{
	DIR *dir;
	struct dirent *dirent;

	dir = opendir(hs20_dir);
	if (!dir)
		return -ENOENT;

	hs20_settings = l_queue_new();

	while ((dirent = readdir(dir))) {
		struct hs20_config *config;
		struct l_settings *s;
		char *filename;

		if (dirent->d_type != DT_REG && dirent->d_type != DT_LNK)
			continue;

		filename = l_strdup_printf("%s/%s", hs20_dir, dirent->d_name);
		s = l_settings_new();

		if (!l_settings_load_from_file(s, filename))
			goto next;

		config = hs20_config_new(s, filename);

		if (config)
			l_queue_push_head(hs20_settings, config);

next:
		l_free(filename);
		l_settings_free(s);
	}

	closedir(dir);

	hs20_dir_watch = l_dir_watch_new(hs20_dir, hs20_dir_watch_cb, NULL,
						hs20_dir_watch_destroy);

	return 0;
}

static void hotspot_exit(void)
{
	l_dir_watch_destroy(hs20_dir_watch);

	l_queue_destroy(hs20_settings, hs20_config_free);
	hs20_settings = NULL;
}

IWD_MODULE(hotspot, hotspot_init, hotspot_exit)
