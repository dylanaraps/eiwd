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

#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <linux/if_ether.h>

#include <ell/ell.h>

#include "linux/nl80211.h"

#include "src/util.h"

enum {
	HWSIM_CMD_UNSPEC,
	HWSIM_CMD_REGISTER,
	HWSIM_CMD_FRAME,
	HWSIM_CMD_TX_INFO_FRAME,
	HWSIM_CMD_NEW_RADIO,
	HWSIM_CMD_DEL_RADIO,
	HWSIM_CMD_GET_RADIO,
	__HWSIM_CMD_MAX,
};
#define HWSIM_CMD_MAX (__HWSIM_CMD_MAX - 1)

enum {
	HWSIM_ATTR_UNSPEC,
	HWSIM_ATTR_ADDR_RECEIVER,
	HWSIM_ATTR_ADDR_TRANSMITTER,
	HWSIM_ATTR_FRAME,
	HWSIM_ATTR_FLAGS,
	HWSIM_ATTR_RX_RATE,
	HWSIM_ATTR_SIGNAL,
	HWSIM_ATTR_TX_INFO,
	HWSIM_ATTR_COOKIE,
	HWSIM_ATTR_CHANNELS,
	HWSIM_ATTR_RADIO_ID,
	HWSIM_ATTR_REG_HINT_ALPHA2,
	HWSIM_ATTR_REG_CUSTOM_REG,
	HWSIM_ATTR_REG_STRICT_REG,
	HWSIM_ATTR_SUPPORT_P2P_DEVICE,
	HWSIM_ATTR_USE_CHANCTX,
	HWSIM_ATTR_DESTROY_RADIO_ON_CLOSE,
	HWSIM_ATTR_RADIO_NAME,
	HWSIM_ATTR_NO_VIF,
	HWSIM_ATTR_FREQ,
	__HWSIM_ATTR_MAX,
};
#define HWSIM_ATTR_MAX (__HWSIM_ATTR_MAX - 1)

static struct l_genl *genl;
static struct l_genl_family *hwsim;
static struct l_genl_family *nl80211;

static const char *options;
static int exit_status;

static enum action {
	ACTION_NONE,
	ACTION_CREATE,
	ACTION_DESTROY,
	ACTION_LIST,
} action;

static bool keep_radios_attr;
static bool no_vif_attr;
static bool p2p_attr;
static const char *radio_name_attr;

static void do_debug(const char *str, void *user_data)
{
	const char *prefix = user_data;

	l_info("%s%s", prefix, str);
}

static void create_callback(struct l_genl_msg *msg, void *user_data)
{
	struct l_genl_attr attr;
	uint32_t radio_id = 0;

	/*
	 * Note that the radio id is returned in the error field of
	 * the returned message.
	 */
	if (!l_genl_attr_init(&attr, msg)) {
		int err = l_genl_msg_get_error(msg);

		if (err < 0) {
			l_warn("Failed to initialize create return attributes"
				" [%d/%s]", -err, strerror(-err));
			exit_status = EXIT_FAILURE;
			goto done;
		}

		radio_id = err;

		l_info("Created new radio with id %u", radio_id);
	} else {
		l_warn("Failed to get create return value");
		exit_status = EXIT_FAILURE;
		goto done;
	}

done:
	l_main_quit();
}

static void destroy_callback(struct l_genl_msg *msg, void *user_data)
{
	struct l_genl_attr attr;
	uint16_t type, len;
	const void *data;

	if (!l_genl_attr_init(&attr, msg)) {
		int err = l_genl_msg_get_error(msg);

		if (err < 0) {
			l_warn("Failed to destroy radio [%d/%s]",
				-err, strerror(-err));
			exit_status = EXIT_FAILURE;
			goto done;
		}

		l_info("Destroyed radio");
		goto done;
	}

	while (l_genl_attr_next(&attr, &type, &len, &data))
	;

done:
	l_main_quit();
}

static void list_callback_done(void *user_data)
{
	l_main_quit();
}

static void list_callback(struct l_genl_msg *msg, void *user_data)
{
	struct l_genl_attr attr;
	uint16_t type, len;
	const void *data;
	uint32_t idx = 0, channels = 0, custom_reg = 0;
	bool reg_strict = false, p2p = false, chanctx = false;
	char alpha2[2] = { };
	char *hwname = NULL;

	if (!l_genl_attr_init(&attr, msg)) {
		int err = l_genl_msg_get_error(msg);

		if (err < 0) {
			l_warn("Failed to list radio [%d/%s]",
				-err, strerror(-err));
			exit_status = EXIT_FAILURE;
			return;
		}
	}

	while (l_genl_attr_next(&attr, &type, &len, &data)) {
		switch (type) {
		case HWSIM_ATTR_RADIO_ID:
			if (len == 4)
				idx = *(int *)data;
			break;

		case HWSIM_ATTR_CHANNELS:
			if (len == 4)
				channels = *(uint32_t *)data;
			break;

		case HWSIM_ATTR_REG_HINT_ALPHA2:
			if (len == 2)
				memcpy(&alpha2, data, len);
			break;

		case HWSIM_ATTR_REG_CUSTOM_REG:
			if (len == 4)
				custom_reg = *(uint32_t *)data;
			break;

		case HWSIM_ATTR_REG_STRICT_REG:
			reg_strict = true;
			break;

		case HWSIM_ATTR_SUPPORT_P2P_DEVICE:
			p2p = true;
			break;

		case HWSIM_ATTR_USE_CHANCTX:
			chanctx = true;
			break;

		case HWSIM_ATTR_RADIO_NAME:
			hwname = l_malloc(len + 1);
			if (hwname) {
				strncpy(hwname, data, len);
				hwname[len] = '\0';
			}
			break;

		default:
			break;
		}
	}

	printf("%s radio id %d channels %d alpha2 %d %d custom reg %d "
		"reg strict %d p2p %d chanctx %d\n",
		hwname, idx, channels, alpha2[0], alpha2[1], custom_reg,
		reg_strict, p2p, chanctx);

	if (hwname)
		l_free(hwname);
}

struct radio_info_rec {
	uint32_t id;
	char alpha2[2];
	bool p2p;
	uint32_t regdom;
	int channels;
	bool ready;	/* Whether we have radio, wiphy and interface data */
	char wiphy_name[0];
};

struct wiphy_info_rec {
	uint32_t id;
	char name[0];
};

struct interface_info_rec {
	uint32_t id;
	uint32_t wiphy_id;
	uint8_t addr[ETH_ALEN];
	char name[0];
};

static struct l_queue *radio_info;
static struct l_queue *wiphy_info;
static struct l_queue *interface_info;

static void hwsim_radio_cache_cleanup(void)
{
	l_queue_destroy(radio_info, l_free);
	l_queue_destroy(wiphy_info, l_free);
	l_queue_destroy(interface_info, l_free);
	radio_info = NULL;
	wiphy_info = NULL;
	interface_info = NULL;
}

static bool radio_info_match_id(const void *a, const void *b)
{
	const struct radio_info_rec *rec = a;
	uint32_t id = L_PTR_TO_UINT(b);

	return rec->id == id;
}

static bool radio_info_match_name(const void *a, const void *b)
{
	const struct radio_info_rec *rec = a;

	return !strcmp(rec->wiphy_name, b);
}

static bool wiphy_info_match_id(const void *a, const void *b)
{
	const struct wiphy_info_rec *rec = a;
	uint32_t id = L_PTR_TO_UINT(b);

	return rec->id == id;
}

static bool wiphy_info_match_name(const void *a, const void *b)
{
	const struct wiphy_info_rec *rec = a;

	return !strcmp(rec->name, b);
}

static bool interface_info_match_id(const void *a, const void *b)
{
	const struct interface_info_rec *rec = a;
	uint32_t id = L_PTR_TO_UINT(b);

	return rec->id == id;
}

static bool interface_info_match_wiphy_id(const void *a, const void *b)
{
	const struct interface_info_rec *rec = a;
	uint32_t id = L_PTR_TO_UINT(b);

	return rec->wiphy_id == id;
}

/*
 * See if we have any radios that should become "ready", i.e. where matching
 * wiphy or interface record was missing and is now available.
 */
static void process_new_radios(void)
{
	const struct l_queue_entry *radio_entry;

	for (radio_entry = l_queue_get_entries(radio_info); radio_entry;
			radio_entry = radio_entry->next) {
		struct radio_info_rec *radio = radio_entry->data;
		const struct wiphy_info_rec *wiphy;
		const struct interface_info_rec *interface;

		if (radio->ready)
			continue;

		wiphy = l_queue_find(wiphy_info, wiphy_info_match_name,
					radio->wiphy_name);
		if (!wiphy)
			continue;

		interface = l_queue_find(interface_info,
						interface_info_match_wiphy_id,
						L_UINT_TO_PTR(wiphy->id));
		if (!interface)
			continue;

		radio->ready = true;

		/* TODO: Create DBus object */
		/* TODO: insert into address cache */
	}
}

static void process_del_radio(struct radio_info_rec *radio)
{
	if (!radio->ready)
		return;

	radio->ready = false;

	/* TODO: unregister DBus object */
	/* TODO: remove from address cache */
}

static void get_radio_callback(struct l_genl_msg *msg, void *user_data)
{
	struct l_genl_attr attr;
	uint16_t type, len;
	const void *data;
	const char *name = NULL;
	const uint32_t *id = NULL;
	size_t name_len = 0;
	struct radio_info_rec *rec;

	if (!l_genl_attr_init(&attr, msg))
		return;

	while (l_genl_attr_next(&attr, &type, &len, &data)) {
		switch (type) {
		case HWSIM_ATTR_RADIO_ID:
			if (len != 4)
				break;

			id = data;
			break;

		case HWSIM_ATTR_RADIO_NAME:
			name = data;
			name_len = len;
			break;
		}
	}

	if (!id || !name)
		return;

	l_free(l_queue_remove_if(radio_info, radio_info_match_id,
					L_UINT_TO_PTR(*id)));

	rec = l_malloc(sizeof(struct radio_info_rec) + name_len + 1);
	memset(rec, 0, sizeof(struct radio_info_rec) + name_len + 1);

	rec->id = *id;
	memcpy(rec->wiphy_name, name, name_len);

	l_genl_attr_init(&attr, msg);

	while (l_genl_attr_next(&attr, &type, &len, &data)) {
		switch (type) {
		case HWSIM_ATTR_CHANNELS:
			if (len != 4)
				break;

			rec->channels = *(uint32_t *) data;
			break;

		case HWSIM_ATTR_REG_HINT_ALPHA2:
			if (len != 2)
				break;

			memcpy(rec->alpha2, data, 2);

			break;

		case HWSIM_ATTR_SUPPORT_P2P_DEVICE:
			rec->p2p = true;
			break;

		case HWSIM_ATTR_REG_CUSTOM_REG:
			if (len != 4)
				break;

			rec->regdom = *(uint32_t *) data;
			break;
		}
	}

	if (!radio_info)
		radio_info = l_queue_new();

	l_queue_push_tail(radio_info, rec);

	process_new_radios();
}

static void get_wiphy_callback(struct l_genl_msg *msg, void *user_data)
{
	struct l_genl_attr attr;
	uint16_t type, len;
	const void *data;
	const char *name = NULL;
	uint16_t name_len = 0;
	const uint32_t *id = NULL;
	struct wiphy_info_rec *rec;

	if (!l_genl_attr_init(&attr, msg))
		return;

	while (l_genl_attr_next(&attr, &type, &len, &data)) {
		switch (type) {
		case NL80211_ATTR_WIPHY:
			id = data;
			break;
		case NL80211_ATTR_WIPHY_NAME:
			name = data;
			name_len = len;
			break;
		}
	}

	if (!name || !id)
		return;

	l_free(l_queue_remove_if(wiphy_info, wiphy_info_match_id,
					L_UINT_TO_PTR(*id)));

	rec = l_malloc(sizeof(struct wiphy_info_rec) + name_len + 1);
	memset(rec, 0, sizeof(struct wiphy_info_rec) + name_len + 1);

	memcpy(rec->name, name, name_len);
	rec->id = *id;

	if (!wiphy_info)
		wiphy_info = l_queue_new();

	l_queue_push_tail(wiphy_info, rec);

	process_new_radios();
}

static void get_interface_callback(struct l_genl_msg *msg, void *user_data)
{
	struct l_genl_attr attr;
	uint16_t type, len;
	const void *data;
	const uint8_t *addr = NULL;
	const uint32_t *wiphy_id = NULL;
	const uint32_t *ifindex = NULL;
	const char *ifname = NULL;
	size_t ifname_len = 0;
	struct interface_info_rec *rec;

	if (!l_genl_attr_init(&attr, msg))
		return;

	while (l_genl_attr_next(&attr, &type, &len, &data)) {
		switch (type) {
		case NL80211_ATTR_MAC:
			if (len != ETH_ALEN)
				break;

			addr = data;
			break;

		case NL80211_ATTR_WIPHY:
			if (len != 4)
				break;

			wiphy_id = data;
			break;

		case NL80211_ATTR_IFINDEX:
			if (len != 4)
				break;

			ifindex = data;
			break;

		case NL80211_ATTR_IFNAME:
			ifname = data;
			ifname_len = len;
			break;
		}
	}

	if (!addr || !wiphy_id || !ifindex || !ifname)
		return;

	l_free(l_queue_remove_if(interface_info, interface_info_match_id,
					L_UINT_TO_PTR(*ifindex)));

	rec = l_malloc(sizeof(struct interface_info_rec) + ifname_len + 1);
	memset(rec, 0, sizeof(struct interface_info_rec) + ifname_len + 1);

	rec->id = *ifindex;
	rec->wiphy_id = *wiphy_id;
	memcpy(rec->addr, addr, ETH_ALEN);
	memcpy(rec->name, ifname, ifname_len);
	rec->name[ifname_len] = '\0';

	if (!interface_info)
		interface_info = l_queue_new();

	l_queue_push_tail(interface_info, rec);

	process_new_radios();
}

static void del_radio_event(struct l_genl_msg *msg)
{
	struct radio_info_rec *radio;
	struct l_genl_attr attr;
	uint16_t type, len;
	const void *data;
	const uint32_t *id = NULL;

	if (!l_genl_attr_init(&attr, msg))
		return;

	while (l_genl_attr_next(&attr, &type, &len, &data)) {
		switch (type) {
		case HWSIM_ATTR_RADIO_ID:
			if (len != 4)
				break;

			id = data;

			break;
		}
	}

	if (!id)
		return;

	radio = l_queue_find(radio_info, radio_info_match_id,
				L_UINT_TO_PTR(*id));
	if (!radio)
		return;

	process_del_radio(radio);

	l_free(radio);
	l_queue_remove(radio_info, radio);
}

static void del_wiphy_event(struct l_genl_msg *msg)
{
	struct wiphy_info_rec *wiphy;
	struct radio_info_rec *radio;
	struct l_genl_attr attr;
	uint16_t type, len;
	const void *data;
	uint32_t id;

	if (!l_genl_attr_init(&attr, msg))
		return;

	if (!l_genl_attr_next(&attr, &type, &len, &data))
		return;

	if (type != NL80211_ATTR_WIPHY || len != 4)
		return;

	id = *((uint32_t *) data);

	wiphy = l_queue_find(wiphy_info, wiphy_info_match_id,
				L_UINT_TO_PTR(id));
	if (!wiphy)
		return;

	radio = l_queue_find(radio_info, radio_info_match_name, wiphy->name);

	if (radio)
		process_del_radio(radio);

	l_free(wiphy);
	l_queue_remove(wiphy_info, wiphy);
}

static void del_interface_event(struct l_genl_msg *msg)
{
	struct interface_info_rec *interface;
	struct wiphy_info_rec *wiphy;
	struct radio_info_rec *radio;
	struct l_genl_attr attr;
	uint16_t type, len;
	const void *data;
	const uint32_t *ifindex = NULL;

	if (!l_genl_attr_init(&attr, msg))
		return;

	while (l_genl_attr_next(&attr, &type, &len, &data)) {
		switch (type) {
		case NL80211_ATTR_IFINDEX:
			if (len != 4)
				break;

			ifindex = data;
			break;
		}
	}

	if (!ifindex)
		return;

	interface = l_queue_find(interface_info, interface_info_match_id,
					L_UINT_TO_PTR(*ifindex));
	if (!interface)
		return;

	wiphy = l_queue_find(wiphy_info, wiphy_info_match_id,
				L_UINT_TO_PTR(interface->wiphy_id));
	if (wiphy)
		radio = l_queue_find(radio_info, radio_info_match_name,
					wiphy->name);
	else
		radio = NULL;

	if (radio)
		process_del_radio(radio);

	l_free(interface);
	l_queue_remove(interface_info, interface);
}

static void hwsim_config(struct l_genl_msg *msg, void *user_data)
{
	struct l_genl_attr attr;
	uint16_t type, len;
	const void *data;
	uint8_t cmd;

	cmd = l_genl_msg_get_command(msg);

	l_debug("Config changed cmd %u", cmd);

	if (!l_genl_attr_init(&attr, msg))
		return;

	while (l_genl_attr_next(&attr, &type, &len, &data))
		l_debug("\tattr type %d len %d", type, len);

	switch (cmd) {
	case HWSIM_CMD_NEW_RADIO:
		get_radio_callback(msg, NULL);
		break;
	case HWSIM_CMD_DEL_RADIO:
		del_radio_event(msg);
		break;
	}
}

static void nl80211_config_notify(struct l_genl_msg *msg, void *user_data)
{
	uint8_t cmd;

	cmd = l_genl_msg_get_command(msg);

	l_debug("Notification of command %u", cmd);

	switch (cmd) {
	case NL80211_CMD_NEW_WIPHY:
		get_wiphy_callback(msg, NULL);
		break;
	case NL80211_CMD_DEL_WIPHY:
		del_wiphy_event(msg);
		break;
	case NL80211_CMD_NEW_INTERFACE:
		get_interface_callback(msg, NULL);
		break;
	case NL80211_CMD_DEL_INTERFACE:
		del_interface_event(msg);
		break;
	}
}

static void nl80211_ready(void *user_data)
{
	struct l_genl_msg *msg;

	msg = l_genl_msg_new(NL80211_CMD_GET_WIPHY);
	if (!l_genl_family_dump(nl80211, msg, get_wiphy_callback,
				NULL, NULL)) {
		l_error("Getting nl80211 wiphy information failed");
		goto error;
	}

	msg = l_genl_msg_new(NL80211_CMD_GET_INTERFACE);
	if (!l_genl_family_dump(nl80211, msg, get_interface_callback,
				NULL, NULL)) {
		l_error("Getting nl80211 interface information failed");
		goto error;
	}

	if (!l_genl_family_register(nl80211, "config", nl80211_config_notify,
					NULL, NULL)) {
		l_error("Registering for nl80211 config notification "
			"failed");
		goto error;
	}

	return;

error:
	exit_status = EXIT_FAILURE;
	l_main_quit();
}

static void hwsim_ready(void *user_data)
{
	struct l_genl_msg *msg;
	int ret;
	size_t msg_size;
	uint32_t radio_id;

	ret = l_genl_family_register(hwsim, "config", hwsim_config,
					NULL, NULL);
	if (!ret) {
		fprintf(stderr, "Failed to create hwsim config listener\n");
		exit_status = EXIT_FAILURE;
		l_main_quit();
		return;
	}

	switch (action) {
	case ACTION_LIST:
		msg = l_genl_msg_new_sized(HWSIM_CMD_GET_RADIO,
					options ? 8 : 4);

		if (options) {
			radio_id = atoi(options);

			l_genl_msg_append_attr(msg, HWSIM_ATTR_RADIO_ID,
					4, &radio_id);
			l_genl_family_send(hwsim, msg, list_callback,
						NULL, list_callback_done);
		} else {
			l_genl_family_dump(hwsim, msg, list_callback,
						NULL, list_callback_done);
		}

		break;

	case ACTION_CREATE:
		msg_size = 0;

		if (!keep_radios_attr)
			msg_size += 4;

		if (radio_name_attr)
			msg_size += strlen(radio_name_attr) + 1;

		if (no_vif_attr)
			msg_size += 4;

		if (p2p_attr)
			msg_size += 4;

		msg = l_genl_msg_new_sized(HWSIM_CMD_NEW_RADIO, msg_size);

		if (!keep_radios_attr)
			l_genl_msg_append_attr(msg,
					HWSIM_ATTR_DESTROY_RADIO_ON_CLOSE,
					0, NULL);

		if (radio_name_attr)
			l_genl_msg_append_attr(msg, HWSIM_ATTR_RADIO_NAME,
						strlen(radio_name_attr) + 1,
							radio_name_attr);

		if (no_vif_attr)
			l_genl_msg_append_attr(msg, HWSIM_ATTR_NO_VIF, 0, NULL);

		if (p2p_attr)
			l_genl_msg_append_attr(msg,
						HWSIM_ATTR_SUPPORT_P2P_DEVICE,
						0, NULL);

		l_genl_family_send(hwsim, msg, create_callback, NULL, NULL);

		break;

	case ACTION_DESTROY:
		radio_id = atoi(options);

		msg = l_genl_msg_new_sized(HWSIM_CMD_DEL_RADIO, 8);
		l_genl_msg_append_attr(msg, HWSIM_ATTR_RADIO_ID, 4, &radio_id);
		l_genl_family_send(hwsim, msg, destroy_callback, NULL, NULL);

		break;

	case ACTION_NONE:
		msg = l_genl_msg_new(HWSIM_CMD_GET_RADIO);
		if (!l_genl_family_dump(hwsim, msg, get_radio_callback,
					NULL, NULL)) {
			l_error("Getting hwsim radio information failed");
			goto error;
		}

		l_genl_family_set_watches(nl80211, nl80211_ready, NULL,
						NULL, NULL);

		break;
	}

	return;

error:
	exit_status = EXIT_FAILURE;
	l_main_quit();
}

static void hwsim_disappeared(void *user_data)
{
	l_main_quit();
}

static void signal_handler(struct l_signal *signal, uint32_t signo,
							void *user_data)
{
	switch (signo) {
	case SIGINT:
	case SIGTERM:
		l_main_quit();
		break;
	}
}

static void usage(void)
{
	printf("hwsim - Wireless simulator\n"
		"Usage:\n");
	printf("\thwsim [options]\n");
	printf("Options:\n"
		"\t-L, --list [id]        List simulated radios\n"
		"\t-C, --create           Create new simulated radio\n"
		"\t-D, --destroy <id>     Destroy existing radio\n"
		"\t-k, --keep             Do not destroy radios when "
						"program exits\n"
		"\t-n, --name <name>      Name of a radio to be created\n"
		"\t-i, --nointerface      Do not create VIF\n"
		"\t-p, --p2p              Support P2P\n"
		"\t-h, --help             Show help options\n");
}

static const struct option main_options[] = {
	{ "list",	 optional_argument,	NULL, 'L' },
	{ "create",	 no_argument,		NULL, 'C' },
	{ "destroy",	 required_argument,	NULL, 'D' },
	{ "keep",	 no_argument,		NULL, 'k' },
	{ "name",	 required_argument,	NULL, 'n' },
	{ "nointerface", no_argument,		NULL, 'i' },
	{ "p2p",	 no_argument,		NULL, 'p' },
	{ "version",	 no_argument,		NULL, 'v' },
	{ "help",	 no_argument,		NULL, 'h' },
	{ }
};

int main(int argc, char *argv[])
{
	struct l_signal *signal;
	sigset_t mask;
	int actions = 0;

	for (;;) {
		int opt;

		opt = getopt_long(argc, argv, ":L:CD:kn:ipv", main_options,
									NULL);
		if (opt < 0)
			break;

		switch (opt) {
		case ':':
			if (optopt == 'L') {
				action = ACTION_LIST;
				actions++;
			} else {
				printf("option '-%c' requires an argument\n",
					optopt);
				return EXIT_FAILURE;
			}
			break;
		case 'L':
			action = ACTION_LIST;
			options = optarg;
			actions++;
			break;
		case 'C':
			action = ACTION_CREATE;
			actions++;
			break;
		case 'D':
			action = ACTION_DESTROY;
			options = optarg;
			actions++;
			break;
		case 'k':
			keep_radios_attr = true;
			break;
		case 'n':
			radio_name_attr = optarg;
			break;
		case 'i':
			no_vif_attr = true;
			break;
		case 'p':
			p2p_attr = true;
			break;
		case 'v':
			printf("%s\n", VERSION);
			return EXIT_SUCCESS;
		case 'h':
			usage();
			return EXIT_SUCCESS;
		default:
			printf("unrecognized argument '%s'\n",
				argv[optind - 1]);
			return EXIT_FAILURE;
		}
	}

	if (argc - optind > 0) {
		fprintf(stderr, "Invalid command line parameters\n");
		return EXIT_FAILURE;
	}

	if (actions > 1) {
		fprintf(stderr, "Only one action can be specified\n");
		return EXIT_FAILURE;
	}

	if (!l_main_init())
		return EXIT_FAILURE;

	sigemptyset(&mask);
	sigaddset(&mask, SIGINT);
	sigaddset(&mask, SIGTERM);

	signal = l_signal_create(&mask, signal_handler, NULL, NULL);

	l_log_set_stderr();

	printf("Wireless simulator ver %s\n", VERSION);

	genl = l_genl_new_default();
	if (!genl) {
		fprintf(stderr, "Failed to initialize generic netlink\n");
		exit_status = EXIT_FAILURE;
		goto done;
	}

	if (getenv("HWSIM_DEBUG"))
		l_genl_set_debug(genl, do_debug, "[GENL] ", NULL);

	hwsim = l_genl_family_new(genl, "MAC80211_HWSIM");
	if (!hwsim) {
		fprintf(stderr, "Failed to create generic netlink family\n");
		l_genl_unref(genl);
		exit_status = EXIT_FAILURE;
		goto done;
	}

	nl80211 = l_genl_family_new(genl, NL80211_GENL_NAME);
	if (!nl80211) {
		fprintf(stderr, "Failed to create nl80211 genl family\n");
		l_genl_family_unref(hwsim);
		l_genl_unref(genl);
		exit_status = EXIT_FAILURE;
		goto done;
	}

	l_genl_family_set_watches(hwsim, hwsim_ready, hwsim_disappeared,
					NULL, NULL);

	exit_status = EXIT_SUCCESS;

	l_main_run();

	l_genl_family_unref(hwsim);
	l_genl_family_unref(nl80211);
	l_genl_unref(genl);

	hwsim_radio_cache_cleanup();

done:
	l_signal_remove(signal);

	l_main_exit();

	return exit_status;
}
