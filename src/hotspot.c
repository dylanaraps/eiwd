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
#include <stdio.h>

#include <ell/ell.h>

#include "src/iwd.h"
#include "src/common.h"
#include "src/network.h"
#include "src/util.h"
#include "src/hotspot.h"
#include "src/ie.h"
#include "src/knownnetworks.h"
#include "src/storage.h"

static struct l_dir_watch *hs20_dir_watch;
static const char *hs20_dir = DAEMON_STORAGEDIR "/hotspot";
static struct l_queue *hs20_settings;

struct hs20_config {
	struct network_info super;
	char *filename;
	uint8_t hessid[6];
	char **nai_realms;
	uint8_t *rc; /* roaming consortium */
	size_t rc_len;
	char *object_path;
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

	l_queue_remove(hs20_settings, config);

	l_strv_free(config->nai_realms);
	l_free(config->rc);
	l_free(config->object_path);
	l_free(config->filename);
	l_free(config);
}

static int hotspot_network_touch(struct network_info *info)
{
	struct hs20_config *config = l_container_of(info, struct hs20_config,
							super);

	return l_path_touch(config->filename);
}

static struct l_settings *hotspot_network_open(struct network_info *info)
{
	struct l_settings *settings;
	struct hs20_config *config = l_container_of(info, struct hs20_config,
							super);

	settings = l_settings_new();

	if (!l_settings_load_from_file(settings, config->filename)) {
		l_settings_free(settings);
		return NULL;
	}

	return settings;
}

static void hotspot_network_sync(struct network_info *info,
					struct l_settings *settings)
{
	char *data;
	size_t length = 0;
	struct hs20_config *config = l_container_of(info, struct hs20_config,
							super);

	data = l_settings_to_data(settings, &length);
	write_file(data, length, "%s", config->filename);
	l_free(data);
}

static void hotspot_network_remove(struct network_info *info)
{
	struct hs20_config *config = l_container_of(info, struct hs20_config,
							super);

	unlink(config->filename);
}

static void hotspot_network_free(struct network_info *info)
{
	struct hs20_config *config = l_container_of(info, struct hs20_config,
							super);

	hs20_config_free(config);
}

static const char *hotspot_network_get_path(const struct network_info *info)
{
	char *digest;
	struct l_checksum *sha;
	char **realms;
	struct hs20_config *config = l_container_of(info, struct hs20_config,
							super);

	if (config->object_path)
		return config->object_path;

	sha = l_checksum_new(L_CHECKSUM_SHA256);

	if (config->nai_realms) {
		realms = config->nai_realms;

		while (*realms) {
			l_checksum_update(sha, *realms, strlen(*realms));
			realms++;
		}
	}

	if (config->rc)
		l_checksum_update(sha, config->rc, config->rc_len);

	if (!util_mem_is_zero(config->hessid, 6))
		l_checksum_update(sha, config->hessid, 6);

	digest = l_checksum_get_string(sha);
	l_checksum_free(sha);
	config->object_path = l_strdup_printf("/%.8s_hotspot", digest);
	l_free(digest);

	return config->object_path;
}

static bool hotspot_match_hessid(const struct network_info *info,
					const uint8_t *hessid)
{
	struct hs20_config *config = l_container_of(info, struct hs20_config,
							super);

	if (util_mem_is_zero(config->hessid, 6) || !hessid)
		return false;

	return !memcmp(config->hessid, hessid, 6);
}

static bool hotspot_match_roaming_consortium(const struct network_info *info,
						const uint8_t *rc_ie,
						size_t rc_len)
{
	const uint8_t *rc1, *rc2, *rc3;
	size_t rc1_len, rc2_len, rc3_len;
	struct hs20_config *config = l_container_of(info, struct hs20_config,
							super);

	if (!config->rc || !rc_ie)
		return false;

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

static bool hotspot_match_nai_realms(const struct network_info *info,
					const char **nai_realms)
{
	const char **realms = nai_realms;
	struct hs20_config *config = l_container_of(info, struct hs20_config,
							super);

	if (!config->nai_realms || !nai_realms)
		return false;

	while (*realms) {
		if (l_strv_contains(config->nai_realms, *realms))
			return true;

		realms++;
	}

	return false;
}

static struct network_info_ops hotspot_ops = {
	.open = hotspot_network_open,
	.touch = hotspot_network_touch,
	.sync = hotspot_network_sync,
	.remove = hotspot_network_remove,
	.free = hotspot_network_free,
	.get_path = hotspot_network_get_path,

	.match_hessid = hotspot_match_hessid,
	.match_roaming_consortium = hotspot_match_roaming_consortium,
	.match_nai_realms = hotspot_match_nai_realms,
};

static struct hs20_config *hs20_config_new(struct l_settings *settings,
						char *filename)
{
	struct hs20_config *config;
	char *hessid_str;
	char **nai_realms = NULL;
	const char *rc_str;
	bool autoconnect = true;

	/* One of HESSID, NAI realms, or Roaming Consortium must be included */
	hessid_str = l_settings_get_string(settings, "Hotspot", "HESSID");

	nai_realms = l_settings_get_string_list(settings, "Hotspot",
						"NAIRealmNames", ',');

	rc_str = l_settings_get_value(settings, "Hotspot", "RoamingConsortium");

	l_settings_get_bool(settings, "Settings", "Autoconnect", &autoconnect);

	if (!hessid_str && !nai_realms && !rc_str)
		return NULL;

	config = l_new(struct hs20_config, 1);

	if (hessid_str) {
		util_string_to_address(hessid_str, config->hessid);
		l_free(hessid_str);
	}

	if (nai_realms)
		config->nai_realms = nai_realms;

	if (rc_str) {
		config->rc = l_util_from_hexstring(rc_str,
							&config->rc_len);
		/*
		 * WiFi Alliance Hotspot 2.0 Spec - Section 3.1.4
		 *
		 * "The Consortium OI field is 3 or 5-octet field set to a value
		 * of a roaming consortium OI"
		 */
		if (config->rc && config->rc_len != 3 &&
						config->rc_len != 5) {
			l_warn("invalid RoamingConsortium length %zu",
					config->rc_len);
			l_free(config->rc);
			config->rc = NULL;
		}
	}

	config->super.is_autoconnectable = autoconnect;
	config->super.is_hotspot = true;
	config->super.type = SECURITY_8021X;
	config->super.ops = &hotspot_ops;
	config->super.connected_time = l_path_get_mtime(filename);

	config->filename = l_strdup(filename);

	known_networks_add(&config->super);

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

		known_networks_remove(&config->super);

		/*
		 * TODO: Disconnect any networks using this provisioning file
		 */

		break;
	case L_DIR_WATCH_EVENT_MODIFIED:
		config = l_queue_remove_if(hs20_settings, match_filename,
						full_path);
		if (!config)
			return;

		known_networks_remove(&config->super);

		new = l_settings_new();

		if (!l_settings_load_from_file(new, full_path)) {
			l_settings_free(new);
			return;
		}

		config = hs20_config_new(new, full_path);
		if (!config)
			break;

		known_networks_add(&config->super);

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

const uint8_t *hs20_get_roaming_consortium(struct network *network,
						size_t *len)
{
	const struct network_info *info = network_get_info(network);
	struct hs20_config *config;

	if (!info || !info->is_hotspot)
		return NULL;

	config = l_container_of(info, struct hs20_config, super);

	if (config->rc) {
		if (len)
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
IWD_MODULE_DEPENDS(hotspot, known_networks)
