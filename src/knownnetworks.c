/*
 *
 *  Wireless daemon for Linux
 *
 *  Copyright (C) 2016-2019  Intel Corporation. All rights reserved.
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
#include <sys/stat.h>
#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <unistd.h>

#include <ell/ell.h>

#include "src/iwd.h"
#include "src/storage.h"
#include "src/common.h"
#include "src/network.h"
#include "src/dbus.h"
#include "src/knownnetworks.h"
#include "src/scan.h"
#include "src/util.h"

static struct l_queue *known_networks;
static size_t num_known_hidden_networks;
static struct l_dir_watch *storage_dir_watch;

static void network_info_free(void *data)
{
	struct network_info *network = data;

	l_queue_destroy(network->known_frequencies, l_free);

	l_free(network);
}

static int connected_time_compare(const void *a, const void *b, void *user_data)
{
	const struct network_info *ni_a = a;
	const struct network_info *ni_b = b;

	return util_timespec_compare(&ni_a->connected_time,
					&ni_b->connected_time);
}

const char *known_network_get_path(const struct network_info *network)
{
	static char path[256];
	unsigned int pos = 0, i;

	path[pos++] = '/';

	for (i = 0; network->ssid[i] && pos < sizeof(path); i++)
		pos += snprintf(path + pos, sizeof(path) - pos, "%02x",
				network->ssid[i]);

	snprintf(path + pos, sizeof(path) - pos, "_%s",
			security_to_str(network->type));

	return path;
}

/*
 * Finds the position n of this network_info in the list of known networks
 * sorted by connected_time.  E.g. an offset of 0 means the most recently
 * used network.  Only networks with seen_count > 0 are considered.  E.g.
 * only networks that appear in scan results on at least one wifi card.
 *
 * Returns -ENOENT if the entry couldn't be found.
 */
int known_network_offset(const struct network_info *target)
{
	const struct l_queue_entry *entry;
	const struct network_info *info;
	int n = 0;

	for (entry = l_queue_get_entries(known_networks); entry;
						entry = entry->next) {
		info = entry->data;
		if (target == info)
			return n;

		if (info->seen_count)
			n += 1;
	}

	return -ENOENT;
}

static void known_network_register_dbus(struct network_info *network)
{
	const char *path = known_network_get_path(network);

	if (!l_dbus_object_add_interface(dbus_get_bus(), path,
					IWD_KNOWN_NETWORK_INTERFACE, network))
		l_info("Unable to register %s interface",
						IWD_KNOWN_NETWORK_INTERFACE);

	if (!l_dbus_object_add_interface(dbus_get_bus(), path,
					L_DBUS_INTERFACE_PROPERTIES, network))
		l_info("Unable to register %s interface",
						L_DBUS_INTERFACE_PROPERTIES);
}

static void known_network_set_autoconnect(struct network_info *network,
							bool autoconnect)
{
	if (network->is_autoconnectable == autoconnect)
		return;

	network->is_autoconnectable = autoconnect;

	l_dbus_property_changed(dbus_get_bus(), known_network_get_path(network),
				IWD_KNOWN_NETWORK_INTERFACE, "Autoconnect");
}

static void known_network_update(struct network_info *orig_network,
					const char *ssid,
					enum security security,
					struct l_settings *settings,
					struct timespec *connected_time)
{
	struct network_info *network;
	bool is_hidden = false;
	bool is_autoconnectable;

	if (orig_network)
		network = orig_network;
	else
		network = network_info_add_known(ssid, security);

	if (util_timespec_compare(&network->connected_time, connected_time) &&
			orig_network) {
		l_dbus_property_changed(dbus_get_bus(),
					known_network_get_path(network),
					IWD_KNOWN_NETWORK_INTERFACE,
					"LastConnectedTime");

		l_queue_remove(known_networks, network);
		l_queue_insert(known_networks, network, connected_time_compare,
				NULL);
	}

	memcpy(&network->connected_time, connected_time,
		sizeof(struct timespec));

	l_settings_get_bool(settings, "Settings", "Hidden", &is_hidden);

	if (network->is_hidden && orig_network)
		num_known_hidden_networks--;

	if (network->is_hidden != is_hidden && orig_network)
		l_dbus_property_changed(dbus_get_bus(),
					known_network_get_path(network),
					IWD_KNOWN_NETWORK_INTERFACE,
					"Hidden");

	network->is_hidden = is_hidden;

	if (network->is_hidden)
		num_known_hidden_networks++;

	if (!l_settings_get_bool(settings, "Settings", "Autoconnect",
							&is_autoconnectable))
		/* If no entry, default to Autoconnectable=True */
		is_autoconnectable = true;

	known_network_set_autoconnect(network, is_autoconnectable);

	if (orig_network)
		return;

	l_queue_insert(known_networks, network, connected_time_compare, NULL);

	known_network_register_dbus(network);
}

bool known_networks_foreach(known_networks_foreach_func_t function,
				void *user_data)
{
	const struct l_queue_entry *entry;

	for (entry = l_queue_get_entries(known_networks); entry;
			entry = entry->next)
		if (!function(entry->data, user_data))
			break;

	return !entry;
}

bool known_networks_has_hidden(void)
{
	return num_known_hidden_networks ? true : false;
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

struct network_info *known_networks_find(const char *ssid,
						enum security security)
{
	struct network_info query;

	query.type = security;
	strcpy(query.ssid, ssid);

	return l_queue_find(known_networks, network_info_match, &query);
}

struct scan_freq_set *known_networks_get_recent_frequencies(
						uint8_t num_networks_tosearch)
{
	/*
	 * This search function assumes that the known networks are always
	 * sorted by the last connection time with the most recent ones being on
	 * top. Therefore, we just need to get the top NUM of networks from the
	 * list.
	 */
	const struct l_queue_entry *network_entry;
	const struct l_queue_entry *freq_entry;
	struct scan_freq_set *set;

	if (!num_networks_tosearch)
		return NULL;

	set = scan_freq_set_new();

	for (network_entry = l_queue_get_entries(known_networks);
				network_entry && num_networks_tosearch;
				network_entry = network_entry->next,
						num_networks_tosearch--) {
		const struct network_info *network = network_entry->data;

		for (freq_entry = l_queue_get_entries(
						network->known_frequencies);
				freq_entry; freq_entry = freq_entry->next) {
			const struct known_frequency *known_freq =
							freq_entry->data;

			scan_freq_set_add(set, known_freq->frequency);
		}
	}

	return set;
}

static struct l_dbus_message *known_network_forget(struct l_dbus *dbus,
						struct l_dbus_message *message,
						void *user_data)
{
	struct network_info *network = user_data;
	struct l_dbus_message *reply;

	/* Other actions taken care of by the filesystem watch callback */
	storage_network_remove(network->type, network->ssid);

	reply = l_dbus_message_new_method_return(message);
	l_dbus_message_set_arguments(reply, "");

	return reply;
}

static bool known_network_property_get_name(struct l_dbus *dbus,
					struct l_dbus_message *message,
					struct l_dbus_message_builder *builder,
					void *user_data)
{
	struct network_info *network = user_data;

	l_dbus_message_builder_append_basic(builder, 's', network->ssid);

	return true;
}

static bool known_network_property_get_type(struct l_dbus *dbus,
					struct l_dbus_message *message,
					struct l_dbus_message_builder *builder,
					void *user_data)
{
	struct network_info *network = user_data;

	l_dbus_message_builder_append_basic(builder, 's',
						security_to_str(network->type));

	return true;
}

static bool known_network_property_get_hidden(struct l_dbus *dbus,
					struct l_dbus_message *message,
					struct l_dbus_message_builder *builder,
					void *user_data)
{
	struct network_info *network = user_data;
	bool is_hidden = network->is_hidden;

	l_dbus_message_builder_append_basic(builder, 'b', &is_hidden);

	return true;
}

static bool known_network_property_get_autoconnect(struct l_dbus *dbus,
					struct l_dbus_message *message,
					struct l_dbus_message_builder *builder,
					void *user_data)
{
	struct network_info *network = user_data;
	bool autoconnect = network->is_autoconnectable;

	l_dbus_message_builder_append_basic(builder, 'b', &autoconnect);

	return true;
}

static struct l_dbus_message *known_network_property_set_autoconnect(
					struct l_dbus *dbus,
					struct l_dbus_message *message,
					struct l_dbus_message_iter *new_value,
					l_dbus_property_complete_cb_t complete,
					void *user_data)
{
	struct network_info *network = user_data;
	struct l_settings *settings;
	bool autoconnect;

	if (!l_dbus_message_iter_get_variant(new_value, "b", &autoconnect))
		return dbus_error_invalid_args(message);

	if (network->is_autoconnectable == autoconnect)
		return l_dbus_message_new_method_return(message);

	settings = storage_network_open(network->type, network->ssid);
	if (!settings)
		return dbus_error_failed(message);

	l_settings_set_bool(settings, "Settings", "Autoconnect", autoconnect);

	storage_network_sync(network->type, network->ssid, settings);
	l_settings_free(settings);

	return l_dbus_message_new_method_return(message);
}

static bool known_network_property_get_last_connected(struct l_dbus *dbus,
					struct l_dbus_message *message,
					struct l_dbus_message_builder *builder,
					void *user_data)
{
	struct network_info *network = user_data;
	char datestr[64];
	struct tm tm;

	if (network->connected_time.tv_sec == 0)
		return false;

	gmtime_r(&network->connected_time.tv_sec, &tm);

	if (!strftime(datestr, sizeof(datestr), "%FT%TZ", &tm))
		return false;

	l_dbus_message_builder_append_basic(builder, 's', datestr);

	return true;
}

static void setup_known_network_interface(struct l_dbus_interface *interface)
{
	l_dbus_interface_method(interface, "Forget", 0,
				known_network_forget, "", "");

	l_dbus_interface_property(interface, "Name", 0, "s",
					known_network_property_get_name, NULL);
	l_dbus_interface_property(interface, "Type", 0, "s",
					known_network_property_get_type, NULL);
	l_dbus_interface_property(interface, "Hidden", 0, "b",
					known_network_property_get_hidden,
					NULL);
	l_dbus_interface_property(interface, "Autoconnect", 0, "b",
					known_network_property_get_autoconnect,
					known_network_property_set_autoconnect);
	l_dbus_interface_property(interface, "LastConnectedTime", 0, "s",
				known_network_property_get_last_connected,
				NULL);
}

static void known_network_removed(struct network_info *network)
{
	if (network->is_hidden)
		num_known_hidden_networks--;

	l_queue_remove(known_networks, network);
	l_dbus_unregister_object(dbus_get_bus(),
					known_network_get_path(network));

	network_info_forget_known(network);
	network_info_free(network);
}

static void known_networks_watch_cb(const char *filename,
                                                enum l_dir_watch_event event,
                                                void *user_data)
{
	const char *ssid;
	L_AUTO_FREE_VAR(char *, full_path) = NULL;
	enum security security;
	struct network_info *network_before;
	struct l_settings *settings;
	struct timespec connected_time;

	/*
	 * Ignore notifications for the actual directory, we can't do
	 * anything about some of them anyway.  Only react to
	 * notifications for files in the storage directory.
	 */
	if (!filename)
		return;

	ssid = storage_network_ssid_from_path(filename, &security);
	if (!ssid)
		return;

	network_before = known_networks_find(ssid, security);

	full_path = storage_get_network_file_path(security, ssid);

	switch (event) {
	case L_DIR_WATCH_EVENT_CREATED:
	case L_DIR_WATCH_EVENT_REMOVED:
	case L_DIR_WATCH_EVENT_MODIFIED:
		/*
		 * For now treat all the operations the same.  E.g. they may
		 * result in the removal of the network (file moved out, not
		 * readable or invalid) or the creation of a new network (file
		 * created, permissions granted, syntax fixed, etc.)
		 * so we always need to re-read the file.
		 */
		settings = storage_network_open(security, ssid);

		if (settings && storage_network_get_mtime(security, ssid,
						&connected_time) == 0)
			known_network_update(network_before, ssid, security,
						settings, &connected_time);
		else {
			if (network_before)
				known_network_removed(network_before);
		}

		l_settings_free(settings);
		break;
	case L_DIR_WATCH_EVENT_ACCESSED:
		break;
	}
}

static void known_networks_watch_destroy(void *user_data)
{
	storage_dir_watch = NULL;
}

static struct l_queue *known_frequencies_from_string(char *freq_set_str)
{
	struct l_queue *known_frequencies;
	struct known_frequency *known_freq;
	uint16_t t;

	if (!freq_set_str)
		return NULL;

	if (*freq_set_str == '\0')
		return NULL;

	known_frequencies = l_queue_new();

	while (*freq_set_str != '\0') {
		errno = 0;

		t = strtoul(freq_set_str, &freq_set_str, 10);

		if (unlikely(errno == ERANGE || !t || t > 6000))
			goto error;

		known_freq = l_new(struct known_frequency, 1);
		known_freq->frequency = t;

		l_queue_push_tail(known_frequencies, known_freq);
	}

	if (l_queue_isempty(known_frequencies))
		goto error;

	return known_frequencies;

error:
	l_queue_destroy(known_frequencies, l_free);

	return NULL;
}

static void known_frequency_to_string(void *data, void *user_data)
{
	struct known_frequency *known_freq = data;
	struct l_string *str = user_data;

	l_string_append_printf(str, " %u", known_freq->frequency);
}

static char *known_frequencies_to_string(struct l_queue *known_frequencies)
{
	struct l_string *str;

	str = l_string_new(100);

	l_queue_foreach(known_frequencies, known_frequency_to_string, str);

	return l_string_unwrap(str);
}

static void known_network_frequencies_load(void)
{
	char **network_names;
	struct l_settings *known_freqs;
	struct l_queue *known_frequencies;
	uint32_t i;

	known_freqs = storage_known_frequencies_load();
	if (!known_freqs) {
		l_debug("No known frequency file found.");
		return;
	}

	network_names = l_settings_get_groups(known_freqs);
	if (!network_names[0])
		goto done;

	for (i = 0; network_names[i]; i++) {
		struct network_info *network_info;
		enum security security;
		const char *ssid;
		char *freq_list;

		ssid = storage_network_ssid_from_path(network_names[i],
								&security);
		if (!ssid)
			continue;

		freq_list = l_settings_get_string(known_freqs, network_names[i],
									"list");
		if (!freq_list)
			continue;

		network_info = known_networks_find(ssid, security);
		if (!network_info)
			goto next;

		known_frequencies = known_frequencies_from_string(freq_list);
		if (!known_frequencies)
			goto next;

		network_info->known_frequencies = known_frequencies;
next:
		l_free(freq_list);
	}

done:
	l_strv_free(network_names);
	l_settings_free(known_freqs);
}

static bool known_network_frequencies_to_settings(
					const struct network_info *network_info,
					void *user_data)
{
	struct l_settings *known_freqs = user_data;
	char *freq_list_str;
	char *network_path;

	if (!network_info->known_frequencies)
		return true;

	freq_list_str = known_frequencies_to_string(
					network_info->known_frequencies);

	network_path = storage_get_network_file_path(network_info->type,
							network_info->ssid);

	l_settings_set_value(known_freqs, network_path, "list", freq_list_str);
	l_free(network_path);
	l_free(freq_list_str);

	return true;
}

static void known_network_frequencies_sync(void)
{
	struct l_settings *known_freqs;

	known_freqs = l_settings_new();

	known_networks_foreach(known_network_frequencies_to_settings,
								known_freqs);

	storage_known_frequencies_sync(known_freqs);

	l_settings_free(known_freqs);
}

static int known_networks_init(void)
{
	struct l_dbus *dbus = dbus_get_bus();
	DIR *dir;
	struct dirent *dirent;

	if (!l_dbus_register_interface(dbus, IWD_KNOWN_NETWORK_INTERFACE,
						setup_known_network_interface,
						NULL, false)) {
		l_info("Unable to register %s interface",
				IWD_KNOWN_NETWORK_INTERFACE);
		return -EPERM;
	}

	dir = opendir(DAEMON_STORAGEDIR);
	if (!dir) {
		l_info("Unable to open %s: %s", DAEMON_STORAGEDIR,
							strerror(errno));
		l_dbus_unregister_interface(dbus, IWD_KNOWN_NETWORK_INTERFACE);
		return -ENOENT;
	}

	known_networks = l_queue_new();

	while ((dirent = readdir(dir))) {
		const char *ssid;
		enum security security;
		struct l_settings *settings;
		struct timespec connected_time;

		if (dirent->d_type != DT_REG && dirent->d_type != DT_LNK)
			continue;

		ssid = storage_network_ssid_from_path(dirent->d_name,
							&security);
		if (!ssid)
			continue;

		settings = storage_network_open(security, ssid);

		if (settings && storage_network_get_mtime(security, ssid,
							&connected_time) == 0)
			known_network_update(NULL, ssid, security, settings,
						&connected_time);

		l_settings_free(settings);
	}

	closedir(dir);

	known_network_frequencies_load();

	storage_dir_watch = l_dir_watch_new(DAEMON_STORAGEDIR,
						known_networks_watch_cb, NULL,
						known_networks_watch_destroy);

	return 0;
}

static void known_networks_exit(void)
{
	struct l_dbus *dbus = dbus_get_bus();

	l_dir_watch_destroy(storage_dir_watch);

	known_network_frequencies_sync();

	l_queue_destroy(known_networks, network_info_free);
	known_networks = NULL;

	l_dbus_unregister_interface(dbus, IWD_KNOWN_NETWORK_INTERFACE);
}

IWD_MODULE(known_networks, known_networks_init, known_networks_exit)
