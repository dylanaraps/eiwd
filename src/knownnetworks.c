/*
 *
 *  Wireless daemon for Linux
 *
 *  Copyright (C) 2016  Intel Corporation. All rights reserved.
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
#include <dirent.h>
#include <errno.h>
#include <stdio.h>

#include <ell/ell.h>

#include "iwd.h"
#include "storage.h"
#include "common.h"
#include "network.h"
#include "dbus.h"
#include "knownnetworks.h"

static struct l_queue *known_networks;
static size_t num_known_hidden_networks;

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

static const char *iwd_known_network_get_path(
					const struct network_info *network)
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

static void known_network_register_dbus(struct network_info *network)
{
	const char *path = iwd_known_network_get_path(network);

	if (!l_dbus_object_add_interface(dbus_get_bus(), path,
					IWD_KNOWN_NETWORK_INTERFACE, network))
		l_info("Unable to register %s interface",
						IWD_KNOWN_NETWORK_INTERFACE);

	if (!l_dbus_object_add_interface(dbus_get_bus(), path,
					L_DBUS_INTERFACE_PROPERTIES, network))
		l_info("Unable to register %s interface",
						L_DBUS_INTERFACE_PROPERTIES);
}

static bool known_networks_add(const char *ssid, enum security security)
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

	settings = storage_network_open(security_to_str(security), ssid);

	if (l_settings_get_bool(settings, "Settings", "Hidden", &is_hidden))
		network->is_hidden = is_hidden;

	if (network->is_hidden)
		num_known_hidden_networks++;

	l_settings_free(settings);

	l_queue_insert(known_networks, network, timespec_compare, NULL);

	known_network_register_dbus(network);

	return true;
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

struct network_info *known_networks_find(const char *ssid,
						enum security security)
{
	struct network_info query;

	query.type = security;
	strcpy(query.ssid, ssid);

	return l_queue_find(known_networks, network_info_match, &query);
}

void known_networks_connected(struct network_info *network)
{
	bool is_new;

	is_new = !l_queue_remove(known_networks, network);
	l_queue_push_head(known_networks, network);

	if (is_new && network->is_hidden)
		num_known_hidden_networks++;

	if (is_new)
		known_network_register_dbus(network);
	else
		l_dbus_property_changed(dbus_get_bus(),
					iwd_known_network_get_path(network),
					IWD_KNOWN_NETWORK_INTERFACE,
					"LastConnectedTime");
}

static struct l_dbus_message *known_network_forget(struct l_dbus *dbus,
						struct l_dbus_message *message,
						void *user_data)
{
	struct network_info *network = user_data;
	struct l_dbus_message *reply;

	if (network->is_hidden)
		num_known_hidden_networks--;

	l_queue_remove(known_networks, network);
	l_dbus_unregister_object(dbus, iwd_known_network_get_path(network));

	/*
	 * network_info_forget_known will either re-add the network_info to
	 * its seen networks lists or call network_info_free.
	 */
	network_info_forget_known(network);

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
	l_dbus_interface_property(interface, "LastConnectedTime", 0, "s",
				known_network_property_get_last_connected,
				NULL);
}

bool known_networks_init(void)
{
	struct l_dbus *dbus = dbus_get_bus();
	DIR *dir;
	struct dirent *dirent;

	if (!l_dbus_register_interface(dbus, IWD_KNOWN_NETWORK_INTERFACE,
						setup_known_network_interface,
						NULL, false)) {
		l_info("Unable to register %s interface",
				IWD_KNOWN_NETWORK_INTERFACE);
		return false;
	}

	dir = opendir(STORAGEDIR);
	if (!dir) {
		l_info("Unable to open %s: %s", STORAGEDIR, strerror(errno));
		l_dbus_unregister_interface(dbus, IWD_KNOWN_NETWORK_INTERFACE);
		return false;
	}

	known_networks = l_queue_new();

	while ((dirent = readdir(dir))) {
		const char *ssid;
		enum security security;

		if (dirent->d_type != DT_REG && dirent->d_type != DT_LNK)
			continue;

		ssid = storage_network_ssid_from_path(dirent->d_name,
							&security);
		if (!ssid)
			continue;

		known_networks_add(ssid, security);
	}

	closedir(dir);

	return true;
}

void known_networks_exit(void)
{
	struct l_dbus *dbus = dbus_get_bus();

	l_queue_destroy(known_networks, network_info_free);
	known_networks = NULL;

	l_dbus_unregister_interface(dbus, IWD_KNOWN_NETWORK_INTERFACE);
}
