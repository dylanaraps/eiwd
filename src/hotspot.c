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

static struct l_dir_watch *hs20_dir_watch;
static const char *hs20_dir = DAEMON_STORAGEDIR "/.hotspot";
static struct l_queue *hs20_settings;

struct hs20_config {
	char *filename;
	uint8_t hessid[6];
	char **nai_realms;
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
	char **nai_realms;

	config = l_new(struct hs20_config, 1);

	/* HESSID is an optional field */
	str = l_settings_get_string(settings, "Hotspot", "HESSID");
	if (str) {
		util_string_to_address(str, config->hessid);
		l_free(str);
	}

	/* NAI realms are required */
	nai_realms = l_settings_get_string_list(settings, "Hotspot",
						"NAIRealmNames", ',');
	if (!nai_realms) {
		l_free(config);
		return NULL;
	}

	config->nai_realms = nai_realms;
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

const char *hs20_find_settings_file(struct network *network)
{
	struct hs20_config *config;
	uint8_t *hessid = network_get_hessid(network);
	char **nai_realms = network_get_nai_realms(network);

	if (!hessid || util_mem_is_zero(hessid, 6))
		goto try_nai_realms;

	config = l_queue_find(hs20_settings, match_hessid, hessid);
	if (config)
		return config->filename;

try_nai_realms:
	if (!nai_realms)
		return NULL;

	config = l_queue_find(hs20_settings, match_nai_realm, nai_realms);
	if (!config)
		return NULL;

	return config->filename;
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
		struct l_settings *s = l_settings_new();
		char *filename = l_strdup_printf("%s/%s", hs20_dir,
							dirent->d_name);

		if (!l_settings_load_from_file(s, filename)) {
			l_free(filename);
			l_settings_free(s);
			continue;
		}

		config = hs20_config_new(s, filename);

		l_queue_push_head(hs20_settings, config);

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
