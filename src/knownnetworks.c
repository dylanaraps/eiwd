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

#include <ell/ell.h>

#include "iwd.h"
#include "storage.h"
#include "common.h"
#include "network.h"
#include "dbus.h"
#include "knownnetworks.h"

static void known_network_append_properties(
					const struct network_info *network,
					void *user_data)
{
	struct l_dbus_message_builder *builder = user_data;
	char datestr[64];
	struct tm tm;

	if (!network->is_known)
		return;

	l_dbus_message_builder_enter_array(builder, "{sv}");

	dbus_dict_append_string(builder, "Name", network->ssid);
	dbus_dict_append_string(builder, "Type",
				security_to_str(network->type));

	if (network->connected_time.tv_sec != 0) {
		gmtime_r(&network->connected_time.tv_sec, &tm);

		if (strftime(datestr, sizeof(datestr), "%FT%TZ", &tm))
			dbus_dict_append_string(builder, "LastConnectedTime",
						datestr);
	}

	if (network->seen_time.tv_sec != 0) {
		gmtime_r(&network->seen_time.tv_sec, &tm);

		if (strftime(datestr, sizeof(datestr), "%FT%TZ", &tm))
			dbus_dict_append_string(builder, "LastSeenTime",
						datestr);
	}

	l_dbus_message_builder_leave_array(builder);
}

static struct l_dbus_message *list_known_networks(struct l_dbus *dbus,
						struct l_dbus_message *message,
						void *user_data)
{
	struct l_dbus_message *reply;
	struct l_dbus_message_builder *builder;

	if (!l_dbus_message_get_arguments(message, ""))
		return dbus_error_invalid_args(message);

	reply = l_dbus_message_new_method_return(message);
	builder = l_dbus_message_builder_new(reply);

	l_dbus_message_builder_enter_array(builder, "a{sv}");

	network_info_foreach(known_network_append_properties, builder);

	l_dbus_message_builder_leave_array(builder);

	l_dbus_message_builder_finalize(builder);
	l_dbus_message_builder_destroy(builder);

	return reply;
}

static struct l_dbus_message *forget_network(struct l_dbus *dbus,
						struct l_dbus_message *message,
						void *user_data)
{
	struct l_dbus_message *reply;
	const char *ssid, *strtype;
	enum security security;

	if (!l_dbus_message_get_arguments(message, "ss", &ssid, &strtype))
		return dbus_error_invalid_args(message);

	if (strlen(ssid) > 32)
		return dbus_error_invalid_args(message);

	if (!security_from_str(strtype, &security))
		return dbus_error_invalid_args(message);

	if (!network_info_forget_known(ssid, security))
		return dbus_error_failed(message);

	storage_network_remove(strtype, ssid);

	reply = l_dbus_message_new_method_return(message);
	l_dbus_message_set_arguments(reply, "");

	return reply;
}

static void setup_known_networks_interface(struct l_dbus_interface *interface)
{
	l_dbus_interface_method(interface, "ListKnownNetworks", 0,
				list_known_networks, "aa{sv}", "", "networks");
	l_dbus_interface_method(interface, "ForgetNetwork", 0,
				forget_network, "", "ss", "name", "type");
}

bool known_networks_init(void)
{
	struct l_dbus *dbus = dbus_get_bus();
	DIR *dir;
	struct dirent *dirent;

	if (!l_dbus_register_interface(dbus, IWD_KNOWN_NETWORKS_INTERFACE,
						setup_known_networks_interface,
						NULL, false)) {
		l_info("Unable to register %s interface",
				IWD_KNOWN_NETWORKS_INTERFACE);
		return false;
	}

	if (!l_dbus_object_add_interface(dbus, IWD_KNOWN_NETWORKS_PATH,
						IWD_KNOWN_NETWORKS_INTERFACE,
						NULL)) {
		l_info("Unable to register the Known Networks object on '%s'",
				IWD_KNOWN_NETWORKS_PATH);
		l_dbus_unregister_interface(dbus, IWD_KNOWN_NETWORKS_INTERFACE);
		return false;
	}

	dir = opendir(STORAGEDIR);
	if (!dir) {
		l_info("Unable to open %s: %s", STORAGEDIR, strerror(errno));
		l_dbus_unregister_object(dbus, IWD_KNOWN_NETWORKS_PATH);
		l_dbus_unregister_interface(dbus, IWD_KNOWN_NETWORKS_INTERFACE);
		return false;
	}

	while ((dirent = readdir(dir))) {
		const char *ssid;
		enum security security;

		if (dirent->d_type != DT_REG && dirent->d_type != DT_LNK)
			continue;

		ssid = storage_network_ssid_from_path(dirent->d_name,
							&security);
		if (!ssid)
			continue;

		network_info_add_known(ssid, security);
	}

	closedir(dir);

	return true;
}

void known_networks_exit(void)
{
	struct l_dbus *dbus = dbus_get_bus();

	l_dbus_unregister_object(dbus, IWD_KNOWN_NETWORKS_PATH);
	l_dbus_unregister_interface(dbus, IWD_KNOWN_NETWORKS_INTERFACE);
}
