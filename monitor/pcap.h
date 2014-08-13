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

#include <stdint.h>
#include <stdbool.h>
#include <sys/time.h>

#define PCAP_TYPE_INVALID	0
#define PCAP_TYPE_LINUX_SLL	113
#define PCAP_TYPE_NETLINK	253

struct pcap;

struct pcap *pcap_open(const char *pathname);
struct pcap *pcap_create(const char *pathname);
void pcap_close(struct pcap *pcap);

uint32_t pcap_get_type(struct pcap *pcap);
uint32_t pcap_get_snaplen(struct pcap *pcap);

bool pcap_read(struct pcap *pcap, struct timeval *tv,
		void *data, uint32_t size, uint32_t *len, uint32_t *real_len);

bool pcap_write(struct pcap *pcap, const struct timeval *tv,
					const void *phdr, uint32_t plen,
					const void *data, uint32_t size);
