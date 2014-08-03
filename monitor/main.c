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
#include <linux/genetlink.h>
#include <ell/ell.h>

#include "linux/nl80211.h"
#include "monitor/nlmon.h"

static struct nlmon *nlmon = NULL;

#define NLA_OK(nla,len)         ((len) >= (int) sizeof(struct nlattr) && \
				(nla)->nla_len >= sizeof(struct nlattr) && \
				(nla)->nla_len <= (len))
#define NLA_NEXT(nla,attrlen)	((attrlen) -= NLA_ALIGN((nla)->nla_len), \
				(struct nlattr*)(((char*)(nla)) + \
				NLA_ALIGN((nla)->nla_len)))

#define NLA_LENGTH(len)		(NLA_ALIGN(sizeof(struct nlattr)) + (len))
#define NLA_DATA(nla)		((void*)(((char*)(nla)) + NLA_LENGTH(0)))
#define NLA_PAYLOAD(nla)	((int)((nla)->nla_len - NLA_LENGTH(0)))

static void genl_parse(uint16_t type, const void *data, uint32_t len)
{
	const struct genlmsghdr *genlmsg = data;
	const struct nlattr *nla;
	char name[GENL_NAMSIZ];
	uint16_t id = GENL_ID_GENERATE;

	if (nlmon)
		return;

	if (type != GENL_ID_CTRL)
		return;

	if (genlmsg->cmd != CTRL_CMD_NEWFAMILY)
		return;

	for (nla = data + GENL_HDRLEN; NLA_OK(nla, len);
						nla = NLA_NEXT(nla, len)) {
		switch (nla->nla_type & NLA_TYPE_MASK) {
		case CTRL_ATTR_FAMILY_ID:
			id = *((uint16_t *) NLA_DATA(nla));
			break;
		case CTRL_ATTR_FAMILY_NAME:
			strncpy(name, NLA_DATA(nla), GENL_NAMSIZ);
			break;
		}
	}

	if (id == GENL_ID_GENERATE)
		return;

	if (!strcmp(name, NL80211_GENL_NAME))
		nlmon = nlmon_open(id);
}

static void genl_notify(uint16_t type, const void *data,
						uint32_t len, void *user_data)
{
	genl_parse(type, data, len);
}

static void genl_callback(int error, uint16_t type, const void *data,
						uint32_t len, void *user_data)
{
	if (error < 0) {
		fprintf(stderr, "Failed to lookup nl80211 family\n");
		l_main_quit();
		return;
	}

	genl_parse(type, data, len);
}

static struct l_netlink *genl_lookup(void)
{
	struct l_netlink *genl;
	char buf[GENL_HDRLEN + NLA_HDRLEN + GENL_NAMSIZ];
	struct genlmsghdr *genlmsg;
	struct nlattr *nla;

	genl = l_netlink_new(NETLINK_GENERIC);

	l_netlink_register(genl, GENL_ID_CTRL, genl_notify, NULL, NULL);

	genlmsg = (struct genlmsghdr *) buf;
	genlmsg->cmd = CTRL_CMD_GETFAMILY;
	genlmsg->version = 0;
	genlmsg->reserved = 0;

	nla = (struct nlattr *) (buf + GENL_HDRLEN);
	nla->nla_len = NLA_HDRLEN + GENL_NAMSIZ;
	nla->nla_type = CTRL_ATTR_FAMILY_NAME;
	strncpy(buf + GENL_HDRLEN + NLA_HDRLEN,
					NL80211_GENL_NAME, GENL_NAMSIZ);

	l_netlink_send(genl, GENL_ID_CTRL, 0, buf, sizeof(buf),
						genl_callback, NULL, NULL);

	return genl;
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

int main(int argc, char *argv[])
{
	struct l_signal *signal;
	struct l_netlink *genl;
	sigset_t mask;
	int exit_status;

	sigemptyset(&mask);
	sigaddset(&mask, SIGINT);
	sigaddset(&mask, SIGTERM);

	signal = l_signal_create(&mask, signal_handler, NULL, NULL);

	genl = genl_lookup();

	l_main_run();

	l_netlink_destroy(genl);
	nlmon_close(nlmon);

	exit_status = EXIT_SUCCESS;

	l_signal_remove(signal);

	return exit_status;
}
