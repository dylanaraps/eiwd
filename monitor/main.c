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
#include <sys/socket.h>
#include <linux/genetlink.h>
#include <linux/if_arp.h>
#include <ell/ell.h>

#include "linux/nl80211.h"
#include "monitor/nlmon.h"
#include "monitor/pcap.h"
#include "monitor/display.h"

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

static void genl_parse(uint16_t type, const void *data, uint32_t len,
							const char *ifname)
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

	if (!strcmp(name, NL80211_GENL_NAME)) {
		nlmon = nlmon_open(ifname, id);
		if (!nlmon)
			l_main_quit();
	}
}

static void genl_notify(uint16_t type, const void *data,
						uint32_t len, void *user_data)
{
	const char *ifname = user_data;

	genl_parse(type, data, len, ifname);
}

static void genl_callback(int error, uint16_t type, const void *data,
						uint32_t len, void *user_data)
{
	const char *ifname = user_data;

	if (error < 0) {
		fprintf(stderr, "Failed to lookup nl80211 family\n");
		l_main_quit();
		return;
	}

	genl_parse(type, data, len, ifname);
}

static struct l_netlink *genl_lookup(const char *ifname)
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
					genl_callback, (char *) ifname, NULL);

	return genl;
}

#define MAX_SNAPLEN (1024 * 16)

static int process_pcap(struct pcap *pcap)
{
	struct nlmon *nlmon = NULL;
	struct timeval tv;
	uint8_t *buf;
	uint32_t snaplen, len, real_len;

	snaplen = pcap_get_snaplen(pcap);
	if (snaplen > MAX_SNAPLEN)
		snaplen = MAX_SNAPLEN;

	buf = malloc(snaplen);
	if (!buf) {
		fprintf(stderr, "Failed to allocate packet buffer\n");
		return EXIT_FAILURE;
	}

	nlmon = nlmon_create();

	while (pcap_read(pcap, &tv, buf, snaplen, &len, &real_len)) {
		uint16_t arphrd_type;
		uint16_t proto_type;
		uint16_t pkt_type;

		if (len < 16) {
			printf("Too short packet\n");
			continue;
		}

		if (len < real_len)
			printf("Packet truncated from %u\n", real_len);

		pkt_type = L_GET_UNALIGNED((const uint16_t *) buf);
		pkt_type = L_BE16_TO_CPU(pkt_type);

		arphrd_type = L_GET_UNALIGNED((const uint16_t *) (buf + 2));
		arphrd_type = L_BE16_TO_CPU(arphrd_type);

		proto_type = L_GET_UNALIGNED((const uint16_t *) (buf + 14));
		proto_type = L_BE16_TO_CPU(proto_type);

		switch (arphrd_type) {
		case ARPHRD_ETHER:
			switch (proto_type) {
			case ETH_P_PAE:
				nlmon_print_pae(nlmon, &tv, pkt_type, -1,
							buf + 16, len - 16);
				break;
			}
			break;
		case ARPHRD_NETLINK:
			switch (proto_type) {
			case NETLINK_ROUTE:
				nlmon_print_rtnl(nlmon, &tv,
							buf + 16, len - 16);
				break;
			case NETLINK_GENERIC:
				nlmon_print_genl(nlmon, &tv,
							buf + 16, len - 16);
				break;
			}
			break;
		default:
			printf("Unsupported ARPHRD %u\n", arphrd_type);
			break;
		}
	}

	nlmon_destroy(nlmon);

	free(buf);

	return EXIT_SUCCESS;
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
	printf("iwmon - Wireless monitor\n"
		"Usage:\n");
	printf("\tiwmon [options]\n");
	printf("Options:\n"
		"\t-r, --read <file>      Read netlink PCAP trace files\n"
		"\t-i, --interface <dev>  Use specified netlink monitor\n"
		"\t-h, --help             Show help options\n");
}

static const struct option main_options[] = {
	{ "read",      required_argument, NULL, 'r' },
	{ "interface", required_argument, NULL, 'i' },
	{ "version",   no_argument,       NULL, 'v' },
	{ "help",      no_argument,       NULL, 'h' },
	{ }
};

int main(int argc, char *argv[])
{
	const char *reader_path = NULL;
	const char *ifname = "nlmon";
	struct l_signal *signal;
	struct l_netlink *genl;
	sigset_t mask;
	int exit_status;

	for (;;) {
		int opt;

		opt = getopt_long(argc, argv, "r:i:vh", main_options, NULL);
		if (opt < 0)
			break;

		switch (opt) {
		case 'r':
			reader_path = optarg;
			break;
		case 'i':
			ifname = optarg;
			break;
		case 'v':
			printf("%s\n", VERSION);
			return EXIT_SUCCESS;
		case 'h':
			usage();
			return EXIT_SUCCESS;
		default:
			return EXIT_FAILURE;
		}
	}

	if (argc - optind > 0) {
		fprintf(stderr, "Invalid command line parameters\n");
		return EXIT_FAILURE;
	}

	sigemptyset(&mask);
	sigaddset(&mask, SIGINT);
	sigaddset(&mask, SIGTERM);

	signal = l_signal_create(&mask, signal_handler, NULL, NULL);

	printf("Wireless monitor ver %s\n", VERSION);

	if (reader_path) {
		struct pcap *pcap;

		open_pager();

		pcap = pcap_open(reader_path);
		if (!pcap) {
			exit_status = EXIT_FAILURE;
			goto done;
		}

		if (pcap_get_type(pcap) != PCAP_TYPE_LINUX_SLL) {
			fprintf(stderr, "Invalid packet format\n");
			exit_status = EXIT_FAILURE;
		} else
			exit_status = process_pcap(pcap);

		pcap_close(pcap);

		close_pager();
		goto done;
	}

	genl = genl_lookup(ifname);

	l_main_run();

	l_netlink_destroy(genl);
	nlmon_close(nlmon);

	exit_status = EXIT_SUCCESS;

done:
	l_signal_remove(signal);

	return exit_status;
}
