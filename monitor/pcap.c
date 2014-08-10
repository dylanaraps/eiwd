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
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <ell/ell.h>

#include "monitor/pcap.h"

struct pcap_hdr {
	uint32_t magic_number;	/* magic number */
	uint16_t version_major;	/* major version number */
	uint16_t version_minor;	/* minor version number */
	int32_t  thiszone;	/* GMT to local correction */
	uint32_t sigfigs;	/* accuracy of timestamps */
	uint32_t snaplen;	/* max length of captured packets, in octets */
	uint32_t network;	/* data link type */
} __attribute__ ((packed));
#define PCAP_HDR_SIZE (sizeof(struct pcap_hdr))

struct pcap_pkt {
	uint32_t ts_sec;	/* timestamp seconds */
	uint32_t ts_usec;	/* timestamp microseconds */
	uint32_t incl_len;	/* number of octets of packet saved in file */
	uint32_t orig_len;	/* actual length of packet */
} __attribute__ ((packed));
#define PCAP_PKT_SIZE (sizeof(struct pcap_pkt))

struct pcap {
	int fd;
	uint32_t type;
	uint32_t snaplen;
};

struct pcap *pcap_open(const char *path)
{
	struct pcap *pcap;
	struct pcap_hdr hdr;
	ssize_t len;

	pcap = l_new(struct pcap, 1);

	pcap->fd = open(path, O_RDONLY | O_CLOEXEC);
	if (pcap->fd < 0) {
		perror("Failed to open PCAP file");
		l_free(pcap);
		return NULL;
	}

	len = read(pcap->fd, &hdr, PCAP_HDR_SIZE);
	if (len < 0) {
		perror("Failed to read PCAP header");
		goto failed;
	}

	if (len != PCAP_HDR_SIZE) {
		fprintf(stderr, "Wrong PCAP header size\n");
		goto failed;
	}

	if (hdr.magic_number != 0xa1b2c3d4) {
		fprintf(stderr, "Wrong PCAP header magic\n");
		goto failed;
	}

	if (hdr.version_major != 2 || hdr.version_minor != 4) {
		fprintf(stderr, "Wrong PCAP version number\n");
		goto failed;
	}

	pcap->snaplen = hdr.snaplen;
	pcap->type = hdr.network;

	return pcap;

failed:
	close(pcap->fd);
	l_free(pcap);

	return NULL;
}

void pcap_close(struct pcap *pcap)
{
	if (!pcap)
		return;

	if (pcap->fd >= 0)
		close(pcap->fd);

	l_free(pcap);
}

uint32_t pcap_get_type(struct pcap *pcap)
{
	if (!pcap)
		return PCAP_TYPE_INVALID;

	return pcap->type;
}

uint32_t pcap_get_snaplen(struct pcap *pcap)
{
	if (!pcap)
		return 0;

	return pcap->snaplen;
}

bool pcap_read(struct pcap *pcap, struct timeval *tv,
				void *data, uint32_t size, uint32_t *len)
{
	struct pcap_pkt pkt;
	uint32_t toread;
	ssize_t bytes_read;

	if (!pcap)
		return false;

	bytes_read = read(pcap->fd, &pkt, PCAP_PKT_SIZE);
	if (bytes_read != PCAP_PKT_SIZE)
		return false;

	if (pkt.incl_len > size)
		toread = size;
	else
		toread = pkt.incl_len;

	bytes_read = read(pcap->fd, data, toread);
	if (bytes_read < 0)
		return false;

	if (bytes_read < pkt.incl_len)
		lseek(pcap->fd, pkt.incl_len - bytes_read, SEEK_CUR);

	if (tv) {
		tv->tv_sec = pkt.ts_sec;
		tv->tv_usec = pkt.ts_usec;
	}

	if (len)
		*len = toread;

	return true;
}
