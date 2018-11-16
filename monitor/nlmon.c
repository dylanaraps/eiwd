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

#define _GNU_SOURCE
#include <stdio.h>
#include <errno.h>
#include <ctype.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/ether.h>
#include <linux/if.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/netlink.h>
#include <linux/genetlink.h>
#include <linux/rtnetlink.h>
#include <linux/filter.h>
#include <ell/ell.h>

#ifndef ARPHRD_NETLINK
#define ARPHRD_NETLINK	824
#endif

#include "linux/nl80211.h"
#include "src/ie.h"
#include "src/mpdu.h"
#include "src/eapol.h"
#include "src/util.h"
#include "src/wscutil.h"
#include "monitor/pcap.h"
#include "monitor/display.h"
#include "monitor/nlmon.h"

#define COLOR_TIMESTAMP		COLOR_YELLOW

#define COLOR_REQUEST		COLOR_BLUE
#define COLOR_RESPONSE		COLOR_MAGENTA
#define COLOR_COMPLETE		COLOR_MAGENTA
#define COLOR_RESULT		COLOR_MAGENTA
#define COLOR_EVENT		COLOR_CYAN

/* BSS Capabilities */
#define BSS_CAPABILITY_ESS		(1<<0)
#define BSS_CAPABILITY_IBSS		(1<<1)
#define BSS_CAPABILITY_CF_POLLABLE	(1<<2)
#define BSS_CAPABILITY_CF_POLL_REQUEST	(1<<3)
#define BSS_CAPABILITY_PRIVACY		(1<<4)
#define BSS_CAPABILITY_SHORT_PREAMBLE	(1<<5)
#define BSS_CAPABILITY_PBCC		(1<<6)
#define BSS_CAPABILITY_CHANNEL_AGILITY	(1<<7)
#define BSS_CAPABILITY_SPECTRUM_MGMT	(1<<8)
#define BSS_CAPABILITY_QOS		(1<<9)
#define BSS_CAPABILITY_SHORT_SLOT_TIME	(1<<10)
#define BSS_CAPABILITY_APSD		(1<<11)
#define BSS_CAPABILITY_DSSS_OFDM	(1<<13)

enum msg_type {
	MSG_REQUEST,
	MSG_RESPONSE,
	MSG_COMPLETE,
	MSG_RESULT,
	MSG_EVENT,
};

struct nlmon {
	uint16_t id;
	struct l_io *io;
	struct l_io *pae_io;
	struct l_queue *req_list;
	struct pcap *pcap;
	bool nortnl;
	bool nowiphy;
	bool noscan;
};

struct nlmon_req {
	uint32_t seq;
	uint32_t pid;
	uint16_t flags;
	uint8_t cmd;
	uint8_t version;
};

typedef void (*attr_func_t) (unsigned int level, const char *label,
					const void *data, uint16_t size);
enum attr_type {
	ATTR_UNSPEC,
	ATTR_FLAG,
	ATTR_U8,
	ATTR_U16,
	ATTR_U32,
	ATTR_U64,
	ATTR_S8,
	ATTR_S32,
	ATTR_S64,
	ATTR_STRING,
	ATTR_ADDRESS,
	ATTR_BINARY,
	ATTR_NESTED,
	ATTR_ARRAY,
	ATTR_FLAG_OR_U16,
	ATTR_CUSTOM,
};

struct attr_entry {
	uint16_t attr;
	const char *str;
	enum attr_type type;
	union {
		const struct attr_entry *nested;
		enum attr_type array_type;
		attr_func_t function;
	};
};

static void print_attributes(int indent, const struct attr_entry *table,
						const void *buf, uint32_t len);

struct flag_names {
	uint16_t flag;
	const char *name;
};

struct wlan_iface {
	int index;
};

static struct l_hashmap *wlan_iface_list = NULL;

static void wlan_iface_list_free(void *data)
{
	struct wlan_iface *iface = data;

	l_free(iface);
}

static void nlmon_req_free(void *data)
{
	struct nlmon_req *req = data;

	l_free(req);
}

static time_t time_offset = ((time_t) -1);

static inline void update_time_offset(const struct timeval *tv)
{
	if (tv && time_offset == ((time_t) -1))
		time_offset = tv->tv_sec;
}

#define print_indent(indent, color1, prefix, title, color2, fmt, args...) \
do { \
	printf("%*c%s%s%s%s" fmt "%s\n", (indent), ' ', \
		use_color() ? (color1) : "", prefix, title, \
		use_color() ? (color2) : "", ## args, \
		use_color() ? COLOR_OFF : ""); \
} while (0)

#define print_text(color, fmt, args...) \
		print_indent(4, COLOR_OFF, "", "", color, fmt, ## args)

#define print_field(fmt, args...) \
		print_indent(4, COLOR_OFF, "", "", COLOR_OFF, fmt, ## args)

#define print_attr(level, fmt, args...) \
		print_indent(4 + (level) * 4, COLOR_OFF, "", "", COLOR_OFF, \
								fmt, ## args)

#define print_attr_color(level, color, fmt, args...) \
		print_indent(4 + (level) * 4, COLOR_OFF, "", "", color, \
								fmt, ## args)

#define print_space(x) printf("%*c", (x), ' ');

static void print_packet(const struct timeval *tv, char ident,
					const char *color, const char *label,
					const char *text, const char *extra)
{
	int col = num_columns();
	char line[256], ts_str[64];
	int n, ts_len = 0, ts_pos = 0, len = 0, pos = 0;

	if (tv) {
		if (use_color()) {
			n = sprintf(ts_str + ts_pos, "%s", COLOR_TIMESTAMP);
			if (n > 0)
				ts_pos += n;
		}

		n = sprintf(ts_str + ts_pos, " %lu.%06lu",
					tv->tv_sec - time_offset, tv->tv_usec);
		if (n > 0) {
			ts_pos += n;
			ts_len += n;
		}
	}

	if (use_color()) {
		n = sprintf(ts_str + ts_pos, "%s", COLOR_OFF);
		if (n > 0)
			ts_pos += n;
	}

	if (use_color()) {
		n = sprintf(line + pos, "%s", color);
		if (n > 0)
			pos += n;
	}

	n = sprintf(line + pos, "%c %s", ident, label);
	if (n > 0) {
		pos += n;
		len += n;
	}

	if (text) {
		int extra_len = extra ? strlen(extra) : 0;
		int max_len = col - len - extra_len - ts_len - 3;

		n = snprintf(line + pos, max_len + 1, ": %s", text);
		if (n > max_len) {
			line[pos + max_len - 1] = '.';
			line[pos + max_len - 2] = '.';
			if (line[pos + max_len - 3] == ' ')
				line[pos + max_len - 3] = '.';

			n = max_len;
		}

		if (n > 0) {
			pos += n;
			len += n;
		}
	}

	if (use_color()) {
		n = sprintf(line + pos, "%s", COLOR_OFF);
		if (n > 0)
			pos += n;
	}

	if (extra) {
		n = sprintf(line + pos, " %s", extra);
		if (n > 0) {
			pos += n;
			len += n;
		}
	}

	if (ts_len > 0) {
		printf("%s", line);
		if (len < col)
			print_space(col - len - ts_len - 1);
		printf("%s%s\n", use_color() ? COLOR_TIMESTAMP : "", ts_str);
	} else
		printf("%s\n", line);
}

static void print_hexdump(unsigned int level,
				const unsigned char *buf, uint16_t len)
{
	static const char hexdigits[] = "0123456789abcdef";
	char str[68];
	uint16_t i;

	if (!len)
		return;

	for (i = 0; i < len; i++) {
		str[((i % 16) * 3) + 0] = hexdigits[buf[i] >> 4];
		str[((i % 16) * 3) + 1] = hexdigits[buf[i] & 0xf];
		str[((i % 16) * 3) + 2] = ' ';
		str[(i % 16) + 49] = isprint(buf[i]) ? buf[i] : '.';

		if ((i + 1) % 16 == 0) {
			str[47] = ' ';
			str[48] = ' ';
			str[65] = '\0';
			print_attr_color(level, COLOR_WHITE, "%s", str);
			str[0] = ' ';
		}
	}

	if (i % 16 > 0) {
		uint16_t j;
		for (j = (i % 16); j < 16; j++) {
			str[(j * 3) + 0] = ' ';
			str[(j * 3) + 1] = ' ';
			str[(j * 3) + 2] = ' ';
			str[j + 49] = ' ';
		}
		str[47] = ' ';
		str[48] = ' ';
		str[65] = '\0';
		print_attr_color(level, COLOR_WHITE, "%s", str);
	}
}

static const struct {
	const uint8_t oui[3];
	const char *str;
} oui_table[] = {
	{ { 0x00, 0x03, 0x7f }, "Atheros"		},
	{ { 0x00, 0x03, 0x93 }, "Apple"			},
	{ { 0x00, 0x04, 0x0e }, "AVM"			},
	{ { 0x00, 0x0f, 0xac }, "IEEE 802.11"		},
	{ { 0x00, 0x10, 0x18 }, "Broadcom"		},
	{ { 0x00, 0x17, 0xf2 }, "Apple"			},
	{ { 0x00, 0x40, 0x96 }, "Cisco Systems"		},
	{ { 0x00, 0x50, 0xf2 }, "Microsoft"		},
	{ { 0x00, 0x90, 0x4c }, "Epigram"		},
	{ { 0x50, 0x6f, 0x9a }, "Wi-Fi Alliance"	},
	{ }
};

static void print_ie_error(unsigned int level, const char *label,
				uint16_t len, int err)
{
	print_attr(level, "Error decoding %s IE len %d: %s (%d)", label, len,
			strerror(-err), err);
}

static void print_ie_ssid(unsigned int level, const char *label,
				const void *data, uint16_t size)
{
	print_attr(level, "%s: %s", label, util_ssid_to_utf8(size, data));
}

static void print_ie_rate(unsigned int level, const char *label,
				const void *data, uint16_t size)
{
	uint8_t *rate = (uint8_t *)data;
	int pos = 0, i = 0;
	char str[128];

	if (!size) {
		print_ie_error(level, label, size, -EINVAL);
		return;
	}

	print_attr(level, "%s:", label);

	while (i < size) {
		bool mandatory = (rate[i] & 0x80);

		if (rate[i] == 0xff) {
			print_attr(level + 1, "BSS membership HT_PHY");
			i++;
			continue;
		}

		pos += snprintf(&str[pos], sizeof(str) - pos, "%.1f%s ",
				(rate[i] & 127) * 0.5, mandatory? "(B)": "");

		i++;

		if (i % 8 && i != size)
			continue;

		if (pos) {
			pos += snprintf(&str[pos], sizeof(str) - pos, "Mbit/s");
			print_attr(level + 1, "%s", str);
			pos = 0;
		}

	}
}

static void print_ie_ds(unsigned int level, const char *label,
				const void *data, uint16_t size)
{
	uint8_t *channel = (uint8_t *)data;

	if (!size) {
		print_ie_error(level, label, size, -EINVAL);
		return;
	}

	print_attr(level, "%s: channel %d", label, *channel);
}

static void print_ie_tim(unsigned int level, const char *label,
				const void *data, uint16_t size)
{
	const char *dtim = data;
	int t, len = size - 3, pos = 0;
	uint8_t bit;
	char str[128];

	if (size < 4) {
		print_ie_error(level, label, size, -EINVAL);
		return;
	}

	print_attr(level, "%s:", label);
	print_attr(level + 1, "DTIM count    %2d %s", dtim[0],
			dtim[0] ? "beacon frame(s)" :
				"this beacon frame is DTIM");
	print_attr(level + 1, "DTIM period   %2d beacon frame(s)", dtim[1]);
	print_attr(level + 1, "Group buffered %d offset %d",
			!!(dtim[2] & 0x01), dtim[2] >> 1);

	len = size - 3;

	for (t = 0; t < len ; t++) {
		if (((t + 1) % 4) == 1) {
			pos = 0;
			pos += snprintf(&str[pos], sizeof(str) - pos,
					"AID  %4d - %4d ",
					t * 8 + 1,
					t + 4 > len ? len * 8 : (t + 4) * 8);
		}

		for (bit = 0x01; bit; bit <<= 1)
			pos += snprintf(&str[pos], sizeof(str) - pos,
					"%d", !!(dtim[t + 3] & bit));

		pos += snprintf(&str[pos], sizeof(str) - pos, " ");

		if ((t + 1) % 4 == 0 || t + 1 == len)
			print_attr(level + 1, "%s", str);
	}

}

static void print_ie_country(unsigned int level, const char *label,
				const void *data, uint16_t size)
{
	uint8_t *code = (uint8_t *)data;
	int i = 3;

	if (size < 6 || size % 2) {
		print_ie_error(level, label, size, -EINVAL);
		return;
	}

	print_attr(level, "%s: %c%c%c", label, code[0], code[1], code[2]);

	while (i < size) {
		if (code[i] > 200) {
			print_attr(level + 1, "Regulatory ID %3d class %3d "
				"coverage class %3d",
				code[i], code[i + 1], code[i + 2]);

			if (code[i + 2] < 32)
				print_attr(level + 1, "%27c (air propagation "
					"time %2d µs)", ' ', 3 * code[i + 2]);
		} else {
			print_attr(level + 1, "First channel %3d number of "
				"channels %2d max tx power %2d dBm",
				code[i], code[i + 1], code[i + 2]);
		}

		i += 3;
	}
}

static void print_ie_bss_load(unsigned int level, const char *label,
				const void *data, uint16_t size)
{
	uint16_t stations, capacity;
	uint8_t utilization;
	const uint8_t *bytes = data;

	if (size != 5) {
		print_ie_error(level, label, size, -EINVAL);
		return;
	}

	stations = bytes[0] | bytes[1] << 8;
	utilization = bytes[2];
	capacity = bytes[3] | bytes[4] << 8;

	print_attr(level, "%s: %2d station(s) utilization %d/255 available "
			"capacity %d 32µs/s units",
			label, stations, utilization, capacity);
}

static void print_ie_power_constraint(unsigned int level, const char *label,
					const void *data, uint16_t size)
{
	uint8_t *dB = (uint8_t *)data;

	if (!size) {
		print_ie_error(level, label, size, -EINVAL);
		return;
	}

	print_attr(level, "%s: %2d dB", label, *dB);
}

static void print_ie_tpc(unsigned int level, const char *label,
				const void *data, uint16_t size)
{
	signed char *dB = (signed char*)data;

	if (size != 2) {
		print_ie_error(level, label, size, -EINVAL);
		return;
	}

	print_attr(level, "%s: transmit power %2d dB link margin %2d dB",
			label, dB[0], dB[1]);
}

static void print_ie_erp(unsigned int level, const char *label,
				const void *data, uint16_t size)
{
	uint8_t *flags = (uint8_t *)data;

	if (!size) {
		print_ie_error(level, label, size, -EINVAL);
		return;
	}

	print_attr(level, "%s:", label);
	print_attr(level + 1, "non-ERP present      %d", !!(*flags & 0x01));
	print_attr(level + 1, "use protection       %d", !!(*flags & 0x02));
	print_attr(level + 1, "Barker preamble mode %d", !!(*flags & 0x04));
}

struct cipher_suites {
	uint32_t cipher;
	const char *str;
};

static const struct cipher_suites rsn_cipher_selectors[] = {
	{ 0x000fac00, "Use group cipher suite"		},
	{ 0x000fac01, "WEP-40"				},
	{ 0x000fac02, "TKIP"				},
	{ 0x000fac04, "CCMP"				},
	{ 0x000fac05, "WEP-104"				},
	{ 0x000fac06, "BIP"				},
	{ 0x000fac07, "Group traffic not allowed"	},
	{ 0x00147201, "WPI-SMS4"			},
	{ },
};

static const struct cipher_suites rsn_akm_selectors[] = {
	{ 0x000fac01, "IEEE 802.1X/PMKSA; RSNA/PMKSA caching"                                     },
	{ 0x000fac02, "PSK; RSNA PSK"                                                             },
	{ 0x000fac03, "IEEE 802.1X FT; FT"                                                        },
	{ 0x000fac04, "PSK FT; FT"                                                                },
	{ 0x000fac05, "IEEE 802.1X/PMKSA caching SHA256; RSNA/RSNA caching SHA256"                },
	{ 0x000fac06, "PSK SHA256; RSNA PSK SHA256"                                               },
	{ 0x000fac07, "TDLS; TPK"                                                                 },
	{ 0x000fac08, "SAE/PMKSA caching SHA256; RSNA PMKSA caching SHA256/mesh peering exchange" },
	{ 0x000fac09, "FT SAE SHA256; FT"                                                         },
	{ 0x000fac12, "OWE"                                                                       },
	{ }
};

static const struct cipher_suites wpa_cipher_selectors[] = {
	{ 0x0050f200, "Use group cipher suite"		},
	{ 0x0050f201, "WEP-40"				},
	{ 0x0050f202, "TKIP"				},
	{ 0x0050f204, "CCMP"				},
	{ 0x0050f205, "WEP-104"				},
	{ },
};

static const struct cipher_suites wpa_akm_selectors[] = {
	{ 0x0050f201, "IEEE 802.1X/PMKSA; RSNA/PMKSA caching"	},
	{ 0x0050f202, "PSK; RSNA PSK"				},
	{ }
};

static void print_ie_cipher_suite(unsigned int level, const char *label,
				const uint32_t cipher,
				const struct cipher_suites cipher_table[])
{
	const char *str = NULL;
	unsigned int i;
	unsigned char oui[] = {
		(cipher & 0xff000000) >> 24,
		(cipher & 0x00ff0000) >> 16,
		(cipher & 0x0000ff00) >> 8,
	};
	char suite_value[32] = "";

	for (i = 0; cipher_table[i].str; i++) {
		if (cipher_table[i].cipher == cipher) {
			str = cipher_table[i].str;
			snprintf(suite_value, sizeof(suite_value), " %02x",
				cipher & 0x000000ff);
			break;
		}
	}

	if (!str) {
		for (i = 0; oui_table[i].str; i++) {
			if (!memcmp(oui_table[i].oui, oui, 3)) {
				str = oui_table[i].str;
				snprintf(suite_value, sizeof(suite_value),
					" %02x (vendor specific)",
					cipher & 0x000000ff);
				break;
			}
		}
	}

	if (!str) {
		str = "unknown";
		snprintf(suite_value, sizeof(suite_value), "%02x (unknown)",
			cipher & 0x000000ff);
	}

	if (label)
		print_attr(level, "%s: %s (%02x:%02x:%02x) suite %s",
			label, str, oui[0], oui[1], oui[2], suite_value);
	else
		print_attr(level, "%s (%02x:%02x:%02x) suite %s",
			str, oui[0], oui[1], oui[2], suite_value);
}

static void print_ie_cipher_suites(unsigned int level, const char *label,
				const void *data, uint16_t size,
				const struct cipher_suites cipher_table[])
{
	uint32_t cipher;

	print_attr(level, "%s: len %u", label, size);

	while (size >= 4) {
		cipher = l_get_be32(data);

		print_ie_cipher_suite(level + 1, NULL, cipher, cipher_table);

		data += 4;
		size -= 4;
	}
}

static const char *rsn_capabilities_bitfield[] = {
	"Preauthentication",
	"No Pairwise",
	"",
	"",
	"",
	"",
	"Management Frame Protection Required",
	"Management Frame Protection Capable",
	"Reserved",
	"Peerkey Enabled",
	"SPP A-MSDU Capable",
	"SPP A-MSDU Required",
	"PBAC",
	"Extended Key ID for Individually Addressed Frames",
	"Reserved",
	"Reserved",
	NULL
};

static void print_ie_bitfield(unsigned int level, const char *label,
			const uint8_t *bytes, const uint8_t *mask, size_t len,
			const char *bitfield_table[])
{
	unsigned int i;

	for (i = 0; i < len * 8; i++) {
		uint8_t byte = i / 8;
		uint8_t bit = i % 8;

		if (!util_is_bit_set(bytes[byte] & mask[byte], bit))
			continue;

		print_attr(level, "%s: bit %2d: %s", label, i,
			bitfield_table[i]);
	}
}

static void print_ie_rsn(unsigned int level, const char *label,
			const void *data, uint16_t size)
{
	const void *end = data + size;

	uint16_t version, count;
	uint8_t bytemask[2];
	int i;
	const char *rsn_capabilities_replay_counter[] = {
		"1 replay counter",
		"2 replay counters",
		"4 replay counters",
		"16 replay counters"
	};

	print_attr(level, "RSN:");

	if (end - data < 2) {
		print_ie_error(level, label, size, -EINVAL);
		return;
	}

	version = l_get_le16(data);
	if (version != 1) {
		print_attr(level, "Unknown RSN version %d", version);
		return;
	}

	data += 2;

	if (end - data < 4)
		goto end;

	print_ie_cipher_suites(level + 1, "Group Data Cipher Suite", data, 4,
				rsn_cipher_selectors);

	data += 4;

	if (end - data < 2)
		goto end;

	count = l_get_le16(data) * 4;
	data += 2;

	if (end - data < count)
		goto end;

	print_ie_cipher_suites(level + 1, "Pairwise Cipher Suite", data,
					count, rsn_cipher_selectors);
	data += count;

	if (end - data < 2)
		goto end;

	count = l_get_le16(data) * 4;
	data += 2;

	if (end - data < count)
		goto end;

	print_ie_cipher_suites(level + 1, "AKM Suite", data, count,
				rsn_akm_selectors);
	data += count;

	if (end - data < 2)
		goto end;

	bytemask[0] = 0x03;
	bytemask[1] = 0x00;
	print_ie_bitfield(level + 1, "RSN capabilities", data, bytemask,
			sizeof(bytemask), rsn_capabilities_bitfield);

	count = (*((uint8_t *)data) & 0x0c) >> 2;
	print_attr(level + 1, "RSN capabilities: bits  2 - 3: %s per PTKSA",
		rsn_capabilities_replay_counter[count]);

	count = (*((uint8_t *)data) & 0x30) >> 4;
	print_attr(level + 1, "RSN capabilities: bits  4 - 5: %s per GTKSA",
		rsn_capabilities_replay_counter[count]);

	bytemask[0] = 0xc0;
	bytemask[1] = 0xff;
	print_ie_bitfield(level + 1, "RSN capabilities", data, bytemask,
			sizeof(bytemask), rsn_capabilities_bitfield);

	data += 2;

	if (end - data < 2)
		goto end;

	count = l_get_le16(data) * 16;
	data += 2;

	if (end - data < count)
		goto end;

	for (i = 0; i < count; i += 16) {
		const uint8_t *bytes = data;

		print_attr(level + 1, "PMKID: %02x:%02x:%02x:%02x:"
			"%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:"
			"%02x:%02x:%02x:%02x",
			bytes[i], bytes[i + 1],
			bytes[i + 2], bytes[i + 3],
			bytes[i + 4], bytes[i + 5],
			bytes[i + 6], bytes[i + 7],
			bytes[i + 8], bytes[i + 9],
			bytes[i + 10], bytes[i + 11],
			bytes[i + 12], bytes[i + 13],
			bytes[i + 14], bytes[i + 15]);
	}

	data += count;

	if (end - data < 4)
		goto end;

	print_ie_cipher_suites(level + 1, "Group Management Cipher Suite",
			data, 4, rsn_cipher_selectors);

	data += 4;

end:
	if (end - data)
		print_ie_error(level, label, size, -EINVAL);
}

static void print_ie_wpa(unsigned int level, const char *label,
						const void *data, uint16_t size)
{
	uint8_t offset;
	uint16_t version, count;

	if (size < 2)
		return;

	offset = 0;
	version = l_get_le16(data + offset);
	offset += 2;

	if (version != 1)
		return;

	print_attr(level, "WPA:");
	print_attr(level + 1, "Version: %d(%04x)", version, version);

	if (offset + 4 > size)
		goto end;

	print_ie_cipher_suites(level + 1, "Group Data Cipher Suite",
					data + offset, 4, wpa_cipher_selectors);

	offset += 4;
	if (offset + 2 > size)
		goto end;

	count = l_get_le16(data + offset) * 4;
	offset += 2;

	if (offset + count > size)
		goto end;

	print_ie_cipher_suites(level + 1, "Pairwise Cipher Suite",
				data + offset, count, wpa_cipher_selectors);
	offset += count;
	if (offset + 2 > size)
		goto end;

	count = l_get_le16(data + offset) * 4;
	offset += 2;
	if (offset + count > size)
		goto end;

	print_ie_cipher_suites(level + 1, "AKM Suite", data + offset, count,
							wpa_akm_selectors);
	return;

end:
	print_ie_error(level, label, size, -EINVAL);
}

static void print_ie_vendor(unsigned int level, const char *label,
				const void *data, uint16_t size)
{
	static const unsigned char wfa_oui[3] = { 0x00, 0x50, 0xf2 };
	const uint8_t *oui = data;
	const char *str = NULL;
	unsigned int i;

	print_attr(level, "%s: len %u", label, size);

	if (size < 4)
		return;

	for (i = 0; oui_table[i].str; i++) {
		if (!memcmp(oui_table[i].oui, oui, 3)) {
			str = oui_table[i].str;
			break;
		}
	}

	if (!str) {
		print_attr(level + 1, "OUI: %02x:%02x:%02x type:%02x",
							oui[0], oui[1], oui[2],
							oui[3]);
		return;
	}

	print_attr(level + 1, "%s (%02x:%02x:%02x) type: %02x", str,
							oui[0], oui[1], oui[2],
							oui[3]);

	data += 4;
	size -= 4;

	if (!memcmp(oui, wfa_oui, 3)) {
		switch (oui[3]) {
		case 1:		/* WFA WPA IE */
			print_ie_wpa(level + 2, label, data, size);
			return;
		default:
			return;
		}
	}
}

static void print_ie_mcs(unsigned int level, const char *label,
				const void *data, uint16_t size)
{
	const uint8_t *bytes = data;
	int i;
	uint8_t bytemask[16];
	uint16_t data_rate;
	const char *mcs_set[128] = {
		[77] = "Reserved",
		[78] = "Reserved",
		[79] = "Reserved",

		[90] = "Reserved",
		[91] = "Reserved",
		[92] = "Reserved",
		[93] = "Reserved",
		[94] = "Reserved",
		[95] = "Reserved",
		[96] = "Tx MCS set defined",

		[97]  = "Tx Rx MCS set not equal",
		[100] = "Tx unequal modulation supported",
		[101] = "Reserved",
		[102] = "Reserved",
		[103] = "Reserved",

		[104] = "Reserved",
		[105] = "Reserved",
		[106] = "Reserved",
		[107] = "Reserved",
		[108] = "Reserved",
		[109] = "Reserved",
		[110] = "Reserved",
		[111] = "Reserved",

		[112] = "Reserved",
		[113] = "Reserved",
		[114] = "Reserved",
		[115] = "Reserved",
		[116] = "Reserved",
		[117] = "Reserved",
		[118] = "Reserved",
		[119] = "Reserved",

		[120] = "Reserved",
		[121] = "Reserved",
		[122] = "Reserved",
		[123] = "Reserved",
		[124] = "Reserved",
		[125] = "Reserved",
		[126] = "Reserved",
		[127] = "Reserved",
	};

	if (size != 16)
		return print_ie_error(level, label, size, -EINVAL);

	for (i = 0; i < 77; i++) {
		uint8_t byte = i / 8;
		uint8_t bit = i % 8;

		if (util_is_bit_set(bytes[byte], bit))
			print_attr(level, "%s: MCS %d", label, i);
	}

	memset(bytemask, 0, sizeof(bytemask));

	bytemask[9] = 0xe0;

	print_ie_bitfield(level, "MCS set", bytes, bytemask, sizeof(bytemask),
			mcs_set);

	data_rate = l_get_le16(&bytes[10]) & 0x3ff;

	if (data_rate)
		print_attr(level, "MCS set: Rx Highest data rate: %d Mbit/s",
			data_rate);

	bytemask[9]  = 0x00;
	bytemask[11] = 0xfc;
	bytemask[12] = 0x03;

	print_ie_bitfield(level, "MCS Set", bytes, bytemask, sizeof(bytemask),
			mcs_set);

	if (bytes[12] & 0x0c)
		print_attr(level,
			"MCS set: Tx max spatial streams supported: %d",
			((bytes[12] & 0x0c) >> 2) + 1);

	bytemask[11] = 0x00;
	bytemask[12] = 0xf0;
	bytemask[13] = 0xff;
	bytemask[14] = 0xff;
	bytemask[15] = 0xff;

	print_ie_bitfield(level, "MCS set", bytes, bytemask, sizeof(bytemask),
			mcs_set);
}

static void print_ie_ht_operation(unsigned int level, const char *label,
					const void *data, uint16_t size)
{
	const char *secondary_offset[] = {
		"no secondary channel",
		"above primary channel",
		"reserved",
		"below primary channel"
	};
	const char *channel_width[] = {
		"20 MHz channel width",
		"Any supported channel width"
	};
	const char *ht_protection[] = {
		"No protection",
		"Nonmember protection mode",
		"20 MHz protection mode",
		"non-HT mixed mode"
	};
	const char *ht_ops_bitfield[] = {
		"",
		"",
		"",
		"RIFS permitted",
		"Reserved",
		"Reserved",
		"Reserved",
		"Reserved",

		"",
		"",
		"Non-greenfield HT STAs present",
		"Reserved",
		"OBSS non-HT STAs present",
		"Reserved",
		"Reserved",
		"Reserved",

		"Reserved",
		"Reserved",
		"Reserved",
		"Reserved",
		"Reserved",
		"Reserved",
		"Reserved",

		"Reserved",
		"Reserved",
		"Reserved",
		"Reserved",
		"Reserved",
		"Reserved",
		"Dual beacon",
		"Dual CTS protection",

		"STBC beacon",
		"L-SIG TXOP protection full support",
		"PCO active",
		"PCO Phase",
		"Reserved",
		"Reserved",
		"Reserved",
		"Reserved",

		NULL
	};
	uint8_t *bytes = (uint8_t *) data;
	uint8_t bytemask[5];
	int i;

	if (size < 22) {
		print_ie_error(level, label, size, -EINVAL);
		return;
	}

	print_attr (level, "%s:", label);
	print_attr (level + 1, "Primary channel %d", bytes[0]);

	i = bytes[1] & 0x03;
	print_attr (level + 1,
		"Information: Secondary Channel Offset: %s",
		secondary_offset[i]);

	i = (bytes[1] & 0x04) >> 2;
	print_attr (level + 1,
		"Information: Channel width: bit  2: %s",
		channel_width[i]);

	memset(bytemask, 0, sizeof(bytemask));
	bytemask[0] = 0xf8;

	print_ie_bitfield(level + 1,
			"Information", &bytes[1], bytemask,
			sizeof(bytemask), ht_ops_bitfield);

	i = bytes[2] & 0x03;
	print_attr(level + 1,
		"Information: HT Protection: bits  8 -  9: %s",
		ht_protection[i]);

	bytemask[0] = 0x00;
	bytemask[1] = 0xfc;
	bytemask[2] = 0xff;
	bytemask[3] = 0xff;
	bytemask[4] = 0xff;
	print_ie_bitfield(level + 1, "Information", &bytes[1],
			bytemask, sizeof(bytemask), ht_ops_bitfield);

	print_ie_mcs(level + 1, "Basic MCS set", &bytes[6], 16);
}

static const char *extended_capabilities_bitfield[64] = {
	[0] = "20/40 BSS coexistence management support",
	[1] = "Reserved",
	[2] = "Extended channel switching",
	[3] = "Reserved",
	[4] = "PSMP capability",
	[5] = "Reserved",
	[6] = "S-PSMP support",
	[7] = "Event",
	[8] = "Diagnostics",
	[9] = "Multicast diagnostics",
	[10] = "Location tracking",
	[11] = "FMS",
	[12] = "Proxy ARP service",
	[13] = "Collocated interference reporting",
	[14] = "Civic location",
	[15] = "Geospatial location",
	[16] = "TFS",
	[17] = "WNM-Sleep mode",
	[18] = "TIM broadcast",
	[19] = "BSS transition",
	[20] = "QoS traffic capability",
	[21] = "AC station count",
	[22] = "Multiple BSSID",
	[23] = "Timing measurement",
	[24] = "Channel usage",
	[25] = "SSID list",
	[26] = "DMS",
	[27] = "UTC TSF offset",
	[28] = "TDLS Peer U-APSD buffer STA support",
	[29] = "TDLS Peer PSM support",
	[30] = "TDLS channel switching",
	[31] = "Interworking",
	[32] = "QoS Map",
	[33] = "EBR",
	[34] = "SSPN Interface",
	[35] = "Reserved",
	[36] = "MSGCF Capability",
	[37] = "TDLS Support",
	[38] = "TDLS Prohibited",
	[39] = "TDLS Channel Switching Prohibited",
	[40] = "Reject Unadmitted Frame",
	[41 ... 43] = "Reserved",
	[44] = "Identifier Location",
	[45] = "U-APSD Coexistence",
	[46] = "WNM- Notification",
	[47] = "Reserved",
	[48] = "UTF-8 SSID",
	[49 ... 61] = "Reserved",
	[62] = "Opmode Notification",
	[63] = "TDLS Wide Bandwidth support",
};

static void print_ie_extended_capabilities(unsigned int level,
					const char *label,
					const void *data, uint16_t size)
{
	uint8_t bytemask1[] = { 0xff, 0xff, 0xff, 0xff,
				0xff, 0x01 };
	uint8_t bytemask2[] = { 0x00, 0x00, 0x00, 0x00,
				0x00, 0xf0, 0xff, 0xff };
	uint8_t interval;
	size_t bytes;
	bool spsmp;

	print_attr(level, "%s: len %u", label, size);

	if (size == 0)
		return;

	spsmp = util_is_bit_set(*((uint8_t *) data), 6);

	bytes = size < sizeof(bytemask1) ? size : sizeof(bytemask1);

	/* Print first 40 bits */
	print_ie_bitfield(level + 1, "Capability", data, bytemask1,
				bytes, extended_capabilities_bitfield);

	if (size <= bytes)
		return;

	/* Print Service Interval Granularity */
	if (spsmp) {
		interval = util_bit_field(*((uint8_t *) data + 5), 1, 3);
		print_attr(level + 1,
			"Shortest Service Interval Granularity: %d ms",
			interval * 5 + 5);
	}

	bytes = size < sizeof(bytemask2) ? size : sizeof(bytemask2);

	/* Print remainder */
	print_ie_bitfield(level + 1, "Capability", data, bytemask2,
			bytes, extended_capabilities_bitfield);
}

static void print_ie_ht_capabilities(unsigned int level,
					const char *label,
					const void *data, uint16_t size)
{
	static const char *ht_capabilities_info_bitfield[16] = {
		[0] = "LDPC Coding Capability",
		[1] = "Supported Channel Width Set",
		[2] = "SM Power Save",
		[3] = "SM Power Save",
		[4] = "HT-Greenfield",
		[5] = "Short GI for 20Mhz",
		[6] = "Short GI for 40Mhz",
		[7] = "Tx STBC",
		[8] = "Rx STBC",
		[9] = "Rx STBC",
		[10] = "HT-Delayed Block Ack",
		[11] = "Maximum A-MSDU Length",
		[12] = "DSSS/CCK Mode in 40Mhz",
		[13] = "Reserved",
		[14] = "40 Mhz Intolerant",
		[15] = "L-SIG TXOP Protection Support",
	};
	static const char *ht_capabilities_sm_power_save[4] = {
		"Static", "Dynamic", "Reserved", "Disabled",
	};
	static const char *ht_capabilities_rx_stbc[4] = {
		"Disabled", "One spatial stream", "One and two spatial streams",
		"One, two and three spatial streams"
	};
	static const char *ht_capabilities_min_mpdu_start_spacing[8] = {
		"No restriction", "1/4 us", "1/2 us", "1 us", "2 us",
		"4 us", "8 us", "16 us",
	};
	static const char *ht_capabilities_pco_transition_time[4] = {
		"No transition", "400 us", "1.5 ms", "5 ms",
	};
	static const char *ht_capabilities_mcs_feedback[4] = {
		"No feedback", "Reserved", "Unsolicited", "Both",
	};
	uint8_t info_mask[] = { 0x03, 0xfc };
	const uint8_t *htc = data;
	uint8_t sm_power_save;
	uint8_t rx_stbc;
	uint8_t ampdu_exponent;
	bool pco;
	bool plus_htc;
	bool rd_responder;
	uint8_t bits;

	print_attr(level, "%s: len %u", label, size);

	if (size != 26)
		return;

	/* Print bits 0-1 */
	print_ie_bitfield(level + 1, "HT Capabilities Info", data, info_mask,
				1, ht_capabilities_info_bitfield);

	/* Print SM Power Save */
	sm_power_save = util_bit_field(htc[0], 2, 2);
	print_attr(level + 1, "HT Capabilities Info: bits 2-3: %s",
			ht_capabilities_sm_power_save[sm_power_save]);

	/* Print bits 4-7 */
	info_mask[0] = 0xf0;
	print_ie_bitfield(level + 1, "HT Capabilities Info", data, info_mask,
				1, ht_capabilities_info_bitfield);

	rx_stbc = util_bit_field(htc[1], 0, 2);
	print_attr(level + 1, "HT Capabilities Info: bits 8-9: %s",
			ht_capabilities_rx_stbc[rx_stbc]);

	/* Print bits 10-15 */
	info_mask[0] = 0x00;
	print_ie_bitfield(level + 1, "HT Capabilities Info", data, info_mask,
				2, ht_capabilities_info_bitfield);

	ampdu_exponent = util_bit_field(htc[2], 0, 2);
	print_attr(level + 1, "A-MPDU Parameters: "
			"Maximum A-MPDU Length Exponent: %d", ampdu_exponent);

	bits = util_bit_field(htc[2], 2, 3);
	print_attr(level + 1, "A-MPDU Parameters: "
			"Minimum MPDU Start Spacing: %s",
			ht_capabilities_min_mpdu_start_spacing[bits]);

	print_ie_mcs(level + 1, "Supported MCS", htc + 3, 16);

	pco = util_is_bit_set(htc[18], 0);
	print_attr(level + 1, "HT Extended Capabilities: PCO: %s",
			bits ? "supported" : "not supported");

	if (pco) {
		bits = util_bit_field(htc[18], 1, 2);
		print_attr(level + 1, "HT Extended Capabilities: "
				"PCO Transition Time: %s",
				ht_capabilities_pco_transition_time[bits]);
	}

	bits = util_bit_field(htc[19], 0, 2);
	print_attr(level + 1, "HT Extended Capabilities: "
			"MCS Feedback: %s", ht_capabilities_mcs_feedback[bits]);

	plus_htc = util_is_bit_set(htc[19], 2);
	print_attr(level + 1, "HT Extended Capabilities: "
			"+HTC: %s", plus_htc ? "supported" : "not supported");

	rd_responder = util_is_bit_set(htc[19], 3);
	print_attr(level + 1, "HT Extended Capabilities: "
			"RD Responder: %s",
			rd_responder ? "supported" : "not supported");

	/* TODO: Transmit Beamforming Capabilities field */
	/* TODO: ASEL Capability field */
}

static void print_ie_rm_enabled_caps(unsigned int level,
					const char *label,
					const void *data, uint16_t size)
{
	static const char *capabilities[40] = {
		[0] = "Link Measurement",
		[1] = "Neighbor Report",
		[2] = "Parallel Measurements",
		[3] = "Repeated Measurements",
		[4] = "Beacon Passive Measurement",
		[5] = "Beacon Active Measurement",
		[6] = "Beacon Table Measurement",
		[7] = "Beacon Measurement Reporting Conditions",
		[8] = "Frame Measurement",
		[9] = "Channel Load Measurement",
		[10] = "Noise Histogram Measurement",
		[11] = "Statistics Measurement",
		[12] = "LCI Measurement",
		[13] = "LCI Azimuth",
		[14] = "Transmit Stream / Category Measurement",
		[15] = "Triggered Transmit Stream / Category Measurement",
		[16] = "AP Channel Report",
		[17] = "RM MIB",
		[27] = "Measurement Pilot Transmission Information",
		[28] = "Neighbor Report TSF Offset",
		[29] = "RCPI Measurement capability enabled",
		[30] = "RSNI Measurement",
		[31] = "BSS Average Access Delay",
		[32] = "BSS Available Admission Capacity",
		[33] = "Antenna capability",
	};
	const uint8_t *bytes;
	uint8_t bytemask1[3] = { 0xff, 0xff, 0x03 };
	uint8_t bytemask2[2] = { 0xf8, 0x03 };
	uint8_t byte;

	print_attr(level, "%s: len %u", label, size);

	if (size != 5)
		return;

	bytes = data;

	print_ie_bitfield(level + 1, "Enabled", bytes,
				bytemask1, sizeof(bytemask1), capabilities);

	byte = util_bit_field(bytes[2], 2, 3);
	print_attr(level + 1, "Operating Channel Max Measurement Duration: %u",
			byte);

	byte = util_bit_field(bytes[2], 5, 3);
	print_attr(level + 1, "Non-Operating Channel Max Measurement "
			"Duration: %u", byte);

	byte = util_bit_field(bytes[3], 0, 3);
	print_attr(level + 1, "Measurement Pilot Capability: %u", byte);

	print_ie_bitfield(level + 1, "Enabled", bytes + sizeof(bytemask1),
				bytemask2, sizeof(bytemask2), capabilities);
}

static void print_ie_owe(unsigned int level,
					const char *label,
					const void *data, uint16_t size)
{
	uint16_t group;

	print_attr(level, "%s: len %u", label, size);

	group = l_get_le16(data);

	print_attr(level + 1, "ECC Group: %u", group);
	print_attr(level + 1, "Public Key:");
	print_hexdump(level + 2, data + 2, size - 2);
}

static struct attr_entry ie_entry[] = {
	{ IE_TYPE_SSID,				"SSID",
		ATTR_CUSTOM,	{ .function = print_ie_ssid } },
	{ IE_TYPE_SUPPORTED_RATES,		"Supported rates",
		ATTR_CUSTOM,	{ .function = print_ie_rate } },
	{ IE_TYPE_DSSS_PARAMETER_SET,		"DSSS parameter set",
		ATTR_CUSTOM,	{ .function = print_ie_ds } },
	{ IE_TYPE_TIM,				"TIM",
		ATTR_CUSTOM,	{ .function = print_ie_tim } },
	{ IE_TYPE_COUNTRY,			"Country",
		ATTR_CUSTOM,	{ .function = print_ie_country } },
	{ IE_TYPE_BSS_LOAD,			"BSS load",
		ATTR_CUSTOM,	{ .function = print_ie_bss_load } },
	{ IE_TYPE_POWER_CONSTRAINT,		"Power constraint",
		ATTR_CUSTOM,	{ .function = print_ie_power_constraint } },
	{ IE_TYPE_TPC_REPORT,			"TPC report",
		ATTR_CUSTOM,	{ .function = print_ie_tpc } },
	{ IE_TYPE_ERP,				"ERP Information",
		ATTR_CUSTOM,	{ .function = print_ie_erp } },
	{ IE_TYPE_RSN,				"RSN",
		ATTR_CUSTOM,	{ .function = print_ie_rsn } },
	{ IE_TYPE_EXTENDED_SUPPORTED_RATES,	"Extended supported rates",
		ATTR_CUSTOM,	{ .function = print_ie_rate } },
	{ IE_TYPE_HT_OPERATION,			"HT Operation",
		ATTR_CUSTOM,	{ .function = print_ie_ht_operation } },
	{ IE_TYPE_VENDOR_SPECIFIC,		"Vendor specific",
		ATTR_CUSTOM,	{ .function = print_ie_vendor } },
	{ IE_TYPE_EXTENDED_CAPABILITIES,	"Extended Capabilities",
		ATTR_CUSTOM,	{ .function = print_ie_extended_capabilities } },
	{ IE_TYPE_HT_CAPABILITIES,		"HT Capabilities",
		ATTR_CUSTOM,	{ .function = print_ie_ht_capabilities } },
	{ IE_TYPE_RM_ENABLED_CAPABILITIES,	"RM Enabled Capabilities",
		ATTR_CUSTOM,	{ .function = print_ie_rm_enabled_caps } },
	{ IE_TYPE_OWE_DH_PARAM,			"OWE Diffie-Hellman Parameter",
		ATTR_CUSTOM,	{ .function = print_ie_owe } },
	{ },
};

static void print_ie(unsigned int level, const char *label,
					const void *data, uint16_t size)
{
	struct ie_tlv_iter iter;
	int i;

	print_attr(level, "%s: len %u", label, size);

	ie_tlv_iter_init(&iter, data, size);

	while (ie_tlv_iter_next(&iter)) {
		uint16_t tag = ie_tlv_iter_get_tag(&iter);
		struct attr_entry *entry = NULL;

		for (i = 0; ie_entry[i].str; i++) {
			if (ie_entry[i].attr == tag) {
				entry = &ie_entry[i];
				break;
			}
		}

		if (entry && entry->function)
			entry->function(level + 1, entry->str,
					iter.data, iter.len);
		else
			print_attr(level + 1, "Tag %u: len %u", tag,
					iter.len);

		print_hexdump(level + 2, iter.data, iter.len);
	}
}

static void print_wsc_byte(unsigned int level, const char *label,
				const void *data, uint16_t size)
{
	const uint8_t *bytes = data;

	if (size != 1) {
		printf("malformed packet\n");
		return;
	}

	print_attr(level, "%s: %u", label, bytes[0]);
}

static void print_wsc_bytes(unsigned int level, const char *label,
				const void *data, uint16_t size)
{
	print_attr(level, "%s: (len: %d)", label, size);
	print_hexdump(level + 1, data, size);
}

static void print_wsc_bool(unsigned int level, const char *label,
				const void *data, uint16_t size)
{
	const uint8_t *bytes = data;

	if (size != 1) {
		printf("malformed packet\n");
		return;
	}

	print_attr(level, "%s: %s", label, bytes[0] ? "True" : "False");
}

static void print_wsc_ascii_string(unsigned int level, const char *label,
					const void *data, uint16_t size,
					uint16_t max_len)
{
	const char *p = data;
	unsigned int i;

	if (size >= max_len) {
		printf("malformed packet\n");
		return;
	}

	for (i = 0; i < size; i++) {
		if (!p[i])
			break;

		if (!l_ascii_isprint(p[i]))
			goto invalid_ascii;
	}

	print_attr(level, "%s: %.*s", label, i, p);
	return;

invalid_ascii:
	print_attr(level, "%s: (Non-Ascii, len: %d)", label, size);
	print_hexdump(level + 1, data, size);
}

static void print_wsc_utf8_string(unsigned int level, const char *label,
					const void *data, uint16_t size,
					uint16_t max_len)
{
	const char *p = data;
	unsigned int i;

	if (size >= max_len) {
		printf("malformed packet\n");
		return;
	}

	for (i = 0; i < size; i++) {
		if (!p[i])
			break;
	}

	if (!l_utf8_validate((const char *) p, i, NULL))
		goto invalid_utf8;

	print_attr(level, "%s: %.*s", label, i, p);
	return;

invalid_utf8:
	print_attr(level, "%s: (Non-utf8, len: %d)", label, size);
	print_hexdump(level + 1, data, size);
}

static void print_wsc_uuid(unsigned int level, const char *label,
				const void *data, uint16_t size)
{
	const uint8_t *bytes = data;

	if (size != 16) {
		printf("malformed packet\n");
		return;
	}

	print_attr(level, "%s: %02x%02x%02x%02x-%02x%02x-%02x%02x-"
				"%02x%02x-%02x%02x%02x%02x%02x%02x",
				label,
				bytes[0], bytes[1], bytes[2], bytes[3],
				bytes[4], bytes[5], bytes[6], bytes[7],
				bytes[8], bytes[9], bytes[10], bytes[11],
				bytes[12], bytes[13], bytes[14], bytes[15]);
}

static void print_wsc_association_state(unsigned int level, const char *label,
					const void *data, uint16_t size)
{
	uint16_t state;
	static const char *state_table[] = {
		"Not Associated",
		"Connection Success",
		"Configuration Failure",
		"Association Failure",
		"IP Failure",
	};

	if (size != 2) {
		printf("malformed packet\n");
		return;
	}

	state = l_get_be16(data);

	if (state > 4)
		print_attr(level, "%s: Reserved", label);
	else
		print_attr(level, "%s: %s", label, state_table[state]);
}

static void print_wsc_auth_type_flags(unsigned int level, const char *label,
					const void *data, uint16_t size)
{
	uint16_t v;

	if (size != 2)
		return;

	v = l_get_be16(data);
	print_attr(level, "%s:", label);

	if (v & WSC_AUTHENTICATION_TYPE_OPEN)
		print_attr(level + 1, "Open");

	if (v & WSC_AUTHENTICATION_TYPE_WPA_PERSONAL)
		print_attr(level + 1, "WPA-Personal");

	if (v & WSC_AUTHENTICATION_TYPE_SHARED)
		print_attr(level + 1, "Shared");

	if (v & WSC_AUTHENTICATION_TYPE_WPA_ENTERPRISE)
		print_attr(level + 1, "WPA-Enterprise");

	if (v & WSC_AUTHENTICATION_TYPE_WPA2_ENTERPRISE)
		print_attr(level + 1, "WPA2-Enterprise");

	if (v & WSC_AUTHENTICATION_TYPE_WPA2_PERSONAL)
		print_attr(level + 1, "WPA2-Personal");

	if (v & 0xffc0)
		print_attr(level + 1, "Unknown: %04x", v & 0xffc0);
}

static void print_wsc_authenticator(unsigned int level, const char *label,
					const void *data, uint16_t size)
{
	const uint8_t *a = data;

	if (size != 8)
		return;

	print_attr(level, "%s: %02x%02x%02x%02x%02x%02x%02x%02x",
			label, a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7]);
}

static void print_wsc_configuration_error(unsigned int level, const char *label,
						const void *data, uint16_t size)
{
	uint16_t error;
	static const char *error_table[] = {
		"No Error",
		"OOB Interface Read Error",
		"Decryption CRC Failure",
		"2.4 channel not supported",
		"5.0 channel not supported",
		"Signal too weak",
		"Network auth failure",
		"Network association failure",
		"No DHCP response",
		"Failed DHCP config",
		"IP Address conflict",
		"Couldn't connect to Registrar",
		"Multiple PBC sessions detected",
		"Rogue activity suspected",
		"Device busy",
		"Setup locked",
		"Message timeout",
		"Registration session timeout",
		"Device Password Auth Failure",
		"60 Ghz channel not supported",
		"Public Key Hash Mismatch",
	};

	if (size != 2) {
		printf("malformed packet\n");
		return;
	}

	error = l_get_be16(data);

	if (error > 20)
		print_attr(level, "%s: Reserved", label);
	else
		print_attr(level, "%s: %s", label, error_table[error]);
}

static void print_wsc_config_methods(unsigned int level, const char *label,
					const void *data, uint16_t size)
{
	uint16_t v;
	uint16_t flags;

	if (size != 2) {
		printf("malformed packet\n");
		return;
	}

	v = l_get_be16(data);
	print_attr(level, "%s:", label);

	if ((v & WSC_CONFIGURATION_METHOD_PHYSICAL_DISPLAY_PIN) ==
			WSC_CONFIGURATION_METHOD_PHYSICAL_DISPLAY_PIN)
		print_attr(level + 1, "Physical Display PIN");

	if ((v & WSC_CONFIGURATION_METHOD_VIRTUAL_DISPLAY_PIN) ==
			WSC_CONFIGURATION_METHOD_VIRTUAL_DISPLAY_PIN)
		print_attr(level + 1, "Virtual Display PIN");

	flags = WSC_CONFIGURATION_METHOD_PHYSICAL_DISPLAY_PIN |
			WSC_CONFIGURATION_METHOD_VIRTUAL_DISPLAY_PIN;
	if (v & flags)
		v &= ~flags;

	if (v & WSC_CONFIGURATION_METHOD_P2P) {
		print_attr(level + 1, "P2P");
		v &= ~WSC_CONFIGURATION_METHOD_P2P;
	}

	if ((v & WSC_CONFIGURATION_METHOD_PHYSICAL_PUSH_BUTTON) ==
			WSC_CONFIGURATION_METHOD_PHYSICAL_PUSH_BUTTON)
		print_attr(level + 1, "Physical PushButton");

	if ((v & WSC_CONFIGURATION_METHOD_VIRTUAL_PUSH_BUTTON) ==
			WSC_CONFIGURATION_METHOD_VIRTUAL_PUSH_BUTTON)
		print_attr(level + 1, "Virtual PushButton");

	flags = WSC_CONFIGURATION_METHOD_PHYSICAL_PUSH_BUTTON |
			WSC_CONFIGURATION_METHOD_VIRTUAL_PUSH_BUTTON;
	if (v & flags)
		v &= ~flags;

	if (v & WSC_CONFIGURATION_METHOD_KEYPAD) {
		print_attr(level + 1, "Keypad");
		v &= ~WSC_CONFIGURATION_METHOD_KEYPAD;
	}

	if (v & WSC_CONFIGURATION_METHOD_PUSH_BUTTON) {
		print_attr(level + 1, "PushButton");
		v &= ~WSC_CONFIGURATION_METHOD_PUSH_BUTTON;
	}

	if (v & WSC_CONFIGURATION_METHOD_NFC_INTERFACE) {
		print_attr(level + 1, "NFC Interface");
		v &= ~WSC_CONFIGURATION_METHOD_NFC_INTERFACE;
	}

	if (v & WSC_CONFIGURATION_METHOD_INTEGRATED_NFC_TOKEN) {
		print_attr(level + 1, "Integrated NFC Token");
		v &= ~WSC_CONFIGURATION_METHOD_INTEGRATED_NFC_TOKEN;
	}

	if (v & WSC_CONFIGURATION_METHOD_EXTERNAL_NFC_TOKEN) {
		print_attr(level + 1, "External NFC Token");
		v &= ~WSC_CONFIGURATION_METHOD_EXTERNAL_NFC_TOKEN;
	}

	if (v & WSC_CONFIGURATION_METHOD_DISPLAY) {
		print_attr(level + 1, "Display");
		v &= ~WSC_CONFIGURATION_METHOD_DISPLAY;
	}

	if (v & WSC_CONFIGURATION_METHOD_LABEL) {
		print_attr(level + 1, "Label");
		v &= ~WSC_CONFIGURATION_METHOD_LABEL;
	}

	if (v & WSC_CONFIGURATION_METHOD_ETHERNET) {
		print_attr(level + 1, "Ethernet");
		v &= ~WSC_CONFIGURATION_METHOD_ETHERNET;
	}

	if (v & WSC_CONFIGURATION_METHOD_USBA) {
		print_attr(level + 1, "USBA");
		v &= ~WSC_CONFIGURATION_METHOD_USBA;
	}

	if (v)
		print_attr(level + 1, "Unknown: %04x", v);
}

static void print_wsc_connection_type_flags(unsigned int level,
						const char *label,
						const void *data, uint16_t size)
{
	uint8_t v;

	if (size != 1)
		return;

	v = *((uint8_t *) data);
	print_attr(level, "%s:", label);

	if (v & WSC_CONNECTION_TYPE_ESS)
		print_attr(level + 1, "ESS");

	if (v & WSC_CONNECTION_TYPE_IBSS)
		print_attr(level + 1, "IBSS");

	if (v & 0xfffc)
		print_attr(level + 1, "Unknown: %04x", v & 0xfffc);
}

static void print_wsc_device_name(unsigned int level, const char *label,
					const void *data, uint16_t size)
{
	print_wsc_utf8_string(level, label, data, size, 32);
}

static void print_wsc_device_password_id(unsigned int level, const char *label,
						const void *data, uint16_t size)
{
	uint16_t v;
	static const char *device_password_id_table[] = {
		"Default (PIN)",
		"User-specified",
		"Machine-specified",
		"Rekey",
		"PushButton",
		"Registrar-specified",
		"Reserved (for IBSS with WPS)",
		"NFC-Connection-Handover",
		"P2Ps (Reserved for WPS P2P Services Specification",
	};

	if (size != 2) {
		printf("malformed packet\n");
		return;
	}

	v = l_get_be16(data);
	if (v <= 0x0008)
		print_attr(level, "%s: %s", label, device_password_id_table[v]);
	else if (v <= 0x000F)
		print_attr(level, "%s: Reserved (%02x)", label, v);
	else
		print_attr(level, "%s: Random via OOB (%02x)", label, v);
}

static void print_wsc_encryption_type_flags(unsigned int level,
						const char *label,
						const void *data, uint16_t size)
{
	uint16_t v;

	if (size != 2)
		return;

	v = l_get_be16(data);
	print_attr(level, "%s:", label);

	if (v & WSC_ENCRYPTION_TYPE_NONE)
		print_attr(level + 1, "None");

	if (v & WSC_ENCRYPTION_TYPE_WEP)
		print_attr(level + 1, "WEP");

	if (v & WSC_ENCRYPTION_TYPE_TKIP)
		print_attr(level + 1, "TKIP");

	if (v & WSC_ENCRYPTION_TYPE_AES)
		print_attr(level + 1, "AES");

	if (v & 0xfff0)
		print_attr(level + 1, "Unknown: %04x", v & 0xfff0);
}

static void print_wsc_mac_address(unsigned int level, const char *label,
					const void *data, uint16_t size)
{
	const char *str;

	if (size != 6)
		return;

	str = util_address_to_string(data);
	print_attr(level, "%s: %s", label, str);
}

static void print_wsc_manufacturer(unsigned int level, const char *label,
					const void *data, uint16_t size)
{
	print_wsc_ascii_string(level, label, data, size, 64);
}

static void print_wsc_message_type(unsigned int level, const char *label,
					const void *data, uint16_t size)
{
	static const char *message_type_table[] = {
		"Reserved",
		"Beacon",
		"Probe Request",
		"Probe Response",
		"M1",
		"M2",
		"M2D",
		"M3",
		"M4",
		"M5",
		"M6",
		"M7",
		"M8",
		"WSC_ACK",
		"WSC_NACK",
		"WSC_DONE"
	};
	const char *s = "Reserved";
	uint8_t t = ((uint8_t *) data)[0];

	if (size != 1) {
		printf("malformed packet\n");
		return;
	}

	if (t <= 0x0f)
		s = message_type_table[t];

	print_attr(level, "%s: %s", label, s);
}

static void print_wsc_model_name(unsigned int level, const char *label,
					const void *data, uint16_t size)
{
	print_wsc_ascii_string(level, label, data, size, 32);
}

static void print_wsc_model_number(unsigned int level, const char *label,
					const void *data, uint16_t size)
{
	print_wsc_ascii_string(level, label, data, size, 32);
}

static void print_wsc_os_version(unsigned int level, const char *label,
					const void *data, uint16_t size)
{
	uint32_t version;

	if (size != 4)
		return;

	version = l_get_be32(data);
	print_attr(level, "%s: %u", label, version & 0x7fffffff);
}

static void print_wsc_primary_device_type(unsigned int level, const char *label,
						const void *data, uint16_t size)
{
	const uint8_t *bytes = data;
	uint16_t category;
	uint16_t subcategory;
	uint8_t oui[4];
	static const char *category_table[256] = {
		[0] = "Reserved",
		[1] = "Computer",
		[2] = "Input Device",
		[3] = "Printer/Scanner/Fax/Copier",
		[4] = "Camera",
		[5] = "Storage",
		[6] = "Network Infrastructure",
		[7] = "Displays",
		[8] = "Multimedia Devices",
		[9] = "Gaming Devices",
		[10] = "Telephony",
		[11] = "Audio Devices",
		[12] = "Docking Devices",
		[13 ... 254] = "Reserved",
		[255] = "Others",
	};

	if (size != 8) {
		printf("malformed packet\n");
		return;
	}

	category = l_get_be16(bytes);
	subcategory = l_get_be16(bytes + 6);
	memcpy(oui, bytes + 2, 4);

	if (category > 255) {
		print_attr(level, "%s: %04x-%02x%02x%02x%02x-%04x",
				label, category, oui[0], oui[1], oui[2], oui[3],
				subcategory);
		return;
	}

	print_attr(level, "%s: %s", label, category_table[category]);
	print_attr(level + 1, "OUI: %02x%02x%02x%02x",
			oui[0], oui[1], oui[2], oui[3]);
	print_attr(level + 1, "SubCategory: %02x", subcategory);
}

static void print_wsc_request_type(unsigned int level, const char *label,
					const void *data, uint16_t size)
{
	const uint8_t *bytes = data;
	static const char *request_type_table[] = {
		"Enrollee Info",
		"Enrollee Open 802.1X",
		"Registrar",
		"WLAN Manager Registrar",
	};

	if (size != 1 || bytes[0] > 3) {
		printf("malformed packet\n");
		return;
	}

	print_attr(level, "%s: %s", label, request_type_table[bytes[0]]);
}

static void print_wsc_response_type(unsigned int level, const char *label,
					const void *data, uint16_t size)
{
	const uint8_t *bytes = data;
	static const char *response_type_table[] = {
		"Enrollee Info",
		"Enrollee Open 802.1X",
		"Registrar",
		"AP",
	};

	if (size != 1 || bytes[0] > 3) {
		printf("malformed packet\n");
		return;
	}

	print_attr(level, "%s: %s", label, response_type_table[bytes[0]]);
}

static void print_wsc_rf_bands(unsigned int level, const char *label,
					const void *data, uint16_t size)
{
	const uint8_t *bytes = data;
	char bands[256];
	uint16_t pos = 0;

	if (size != 1) {
		printf("malformed packet\n");
		return;
	}

	if (bytes[0] >= 0x08) {
		print_attr(level, "%s: %02x", label, bytes[0]);
		return;
	}

	if (bytes[0] & WSC_RF_BAND_2_4_GHZ)
		pos += sprintf(bands + pos, " 2.4 GHz,");

	if (bytes[0] & WSC_RF_BAND_5_0_GHZ)
		pos += sprintf(bands + pos, " 5 GHz,");

	if (bytes[0] & WSC_RF_BAND_60_GHZ)
		pos += sprintf(bands + pos, " 60 GHz,");

	bands[pos - 1] = '\0';
	print_attr(level, "%s: %s", label, bands);
}

static void print_wsc_serial_number(unsigned int level, const char *label,
					const void *data, uint16_t size)
{
	print_wsc_ascii_string(level, label, data, size, 32);
}

static void print_wsc_version(unsigned int level, const char *label,
				const void *data, uint16_t size)
{
	const uint8_t *bytes = data;

	if (size != 1) {
		printf("malformed packet\n");
		return;
	}

	print_attr(level, "%s: %x", label, bytes[0]);
}

static void print_wsc_state(unsigned int level, const char *label,
				const void *data, uint16_t size)
{
	const uint8_t *bytes = data;
	static const char *state_table[3] = {
		"Reserved",
		"Not Configured",
		"Configured"
	};

	if (size != 1 || bytes[0] == 0 || bytes[0] > 2) {
		printf("malformed packet\n");
		return;
	}

	print_attr(level, "%s: %s", label, state_table[bytes[0]]);
}

static void print_wsc_wfa_ext_version2(unsigned int level, const char *label,
					const void *data, uint16_t size)
{
	const uint8_t *bytes = data;

	if (size != 1) {
		printf("malformed packet\n");
		return;
	}

	print_attr(level, "%s: %x.%x", label, bytes[0] >> 4, bytes[0] & 0xf);
}

static struct attr_entry wsc_wfa_ext_attr_entry[] = {
	{ WSC_WFA_EXTENSION_VERSION2,			"Version2",
		ATTR_CUSTOM,	{ .function = print_wsc_wfa_ext_version2 } },
	{ WSC_WFA_EXTENSION_NETWORK_KEY_SHAREABLE,
						"Network Key Shareable",
		ATTR_CUSTOM,	{ .function = print_wsc_bool } },
	{ WSC_WFA_EXTENSION_REQUEST_TO_ENROLL,		"Request to Enroll",
		ATTR_CUSTOM,	{ .function = print_wsc_bool } },
	{ },
};

static void print_wsc_wfa_ext_attributes(unsigned int level, const char *label,
						const void *data, uint16_t size)
{
	struct wsc_wfa_ext_iter iter;
	int i;

	print_attr(level, "%s: len %u", label, size);

	wsc_wfa_ext_iter_init(&iter, data, size);

	while (wsc_wfa_ext_iter_next(&iter)) {
		uint8_t type = wsc_wfa_ext_iter_get_type(&iter);
		uint8_t len = wsc_wfa_ext_iter_get_length(&iter);
		const void *attr = wsc_wfa_ext_iter_get_data(&iter);
		struct attr_entry *entry = NULL;

		for (i = 0; wsc_wfa_ext_attr_entry[i].str; i++) {
			if (wsc_wfa_ext_attr_entry[i].attr == type) {
				entry = &wsc_wfa_ext_attr_entry[i];
				break;
			}
		}

		if (entry && entry->function)
			entry->function(level + 1, entry->str, attr, len);
		else {
			print_attr(level + 1, "Type: 0x%02x: len %u",
								type, len);
			print_hexdump(level + 2, attr, len);
		}
	}
}

static void print_wsc_vendor_extension(unsigned int level, const char *label,
						const void *data, uint16_t size){
	static const unsigned char wfa_ext[3] = { 0x00, 0x37, 0x2a };
	const uint8_t *bytes = data;

	if (size < 3) {
		printf("malformed packet\n");
		return;
	}

	if (memcmp(data, wfa_ext, sizeof(wfa_ext))) {
		print_attr(level, "%s: OUI: 0x%02x 0x%02x 0x%02x: len %u",
				label, bytes[0], bytes[1], bytes[2], size);
		print_hexdump(level + 1, data + 3, size - 3);
		return;
	}

	print_wsc_wfa_ext_attributes(level, "WFA Vendor Extension",
							data + 3, size - 3);
}

static struct attr_entry wsc_attr_entry[] = {
	{ WSC_ATTR_8021X_ENABLED,		"802.1X Enabled",
		ATTR_CUSTOM,	{ .function = print_wsc_bool } },
	{ WSC_ATTR_AP_SETUP_LOCKED,		"AP Setup Locked",
		ATTR_CUSTOM,	{ .function = print_wsc_bool } },
	{ WSC_ATTR_ASSOCIATION_STATE,		"Association State",
		ATTR_CUSTOM,	{ .function = print_wsc_association_state } },
	{ WSC_ATTR_AUTHENTICATION_TYPE_FLAGS,	"Authentication Type Flags",
		ATTR_CUSTOM,	{ .function = print_wsc_auth_type_flags } },
	{ WSC_ATTR_AUTHENTICATOR,		"Authenticator",
		ATTR_CUSTOM,	{ .function = print_wsc_authenticator } },
	{ WSC_ATTR_CONFIGURATION_ERROR,		"Configuration Error",
		ATTR_CUSTOM,	{ .function = print_wsc_configuration_error } },
	{ WSC_ATTR_CONFIGURATION_METHODS,	"Configuration Methods",
		ATTR_CUSTOM,	{ .function = print_wsc_config_methods } },
	{ WSC_ATTR_CONNECTION_TYPE_FLAGS,	"Connection Type Flags",
		ATTR_CUSTOM,	{ .function =
					print_wsc_connection_type_flags } },
	{ WSC_ATTR_DEVICE_NAME,			"Device Name",
		ATTR_CUSTOM,	{ .function = print_wsc_device_name } },
	{ WSC_ATTR_DEVICE_PASSWORD_ID,		"Device Password Id",
		ATTR_CUSTOM,	{ .function = print_wsc_device_password_id } },
	{ WSC_ATTR_E_HASH1,			"E-Hash1",
		ATTR_CUSTOM,	{ .function = print_wsc_bytes } },
	{ WSC_ATTR_E_HASH2,			"E-Hash2",
		ATTR_CUSTOM,	{ .function = print_wsc_bytes } },
	{ WSC_ATTR_ENCRYPTED_SETTINGS,		"Encrypted Settings",
		ATTR_CUSTOM,	{ .function = print_wsc_bytes } },
	{ WSC_ATTR_ENCRYPTION_TYPE_FLAGS,	"Encryption Type Flags",
		ATTR_CUSTOM,	{ .function =
					print_wsc_encryption_type_flags } },
	{ WSC_ATTR_ENROLLEE_NONCE,		"Enrollee Nonce",
		ATTR_CUSTOM,	{ .function = print_wsc_bytes } },
	{ WSC_ATTR_KEY_PROVIDED_AUTOMATICALLY,	"Key Provided Automatically",
		ATTR_CUSTOM,	{ .function = print_wsc_bool } },
	{ WSC_ATTR_MAC_ADDRESS,			"MAC Address",
		ATTR_CUSTOM,	{ .function = print_wsc_mac_address } },
	{ WSC_ATTR_MANUFACTURER,		"Manufacturer",
		ATTR_CUSTOM,	{ .function = print_wsc_manufacturer } },
	{ WSC_ATTR_MESSAGE_TYPE,		"Message Type",
		ATTR_CUSTOM,	{ .function = print_wsc_message_type } },
	{ WSC_ATTR_MODEL_NAME,			"Model Name",
		ATTR_CUSTOM,	{ .function = print_wsc_model_name } },
	{ WSC_ATTR_MODEL_NUMBER,		"Model Number",
		ATTR_CUSTOM,	{ .function = print_wsc_model_number } },
	{ WSC_ATTR_NETWORK_INDEX,		"Network Index",
		ATTR_CUSTOM,	{ .function = print_wsc_byte } },
	{ WSC_ATTR_NETWORK_KEY_INDEX,		"Network Key Index (Reserved)",
		ATTR_CUSTOM,	{ .function = print_wsc_byte } },
	{ WSC_ATTR_OS_VERSION,			"OS Version",
		ATTR_CUSTOM,	{ .function = print_wsc_os_version } },
	{ WSC_ATTR_PORTABLE_DEVICE,		"Portable Device",
		ATTR_CUSTOM,	{ .function = print_wsc_bool } },
	{ WSC_ATTR_PRIMARY_DEVICE_TYPE,		"Primary Device Type",
		ATTR_CUSTOM,	{ .function = print_wsc_primary_device_type } },
	{ WSC_ATTR_PSK_CURRENT,			"PSK Current",
		ATTR_CUSTOM,	{ .function = print_wsc_byte } },
	{ WSC_ATTR_PSK_MAX,			"PSK Max",
		ATTR_CUSTOM,	{ .function = print_wsc_byte } },
	{ WSC_ATTR_PUBLIC_KEY,			"Public Key",
		ATTR_CUSTOM,	{ .function = print_wsc_bytes } },
	{ WSC_ATTR_RADIO_ENABLED,		"Radio Enabled",
		ATTR_CUSTOM,	{ .function = print_wsc_bool } },
	{ WSC_ATTR_REBOOT,			"Reboot",
		ATTR_CUSTOM,	{ .function = print_wsc_bool } },
	{ WSC_ATTR_REGISTRAR_CURRENT,		"Registrar Current",
		ATTR_CUSTOM,	{ .function = print_wsc_byte } },
	{ WSC_ATTR_REGISTRAR_ESTABLISHED,	"Registrar Established",
		ATTR_CUSTOM,	{ .function = print_wsc_bool } },
	{ WSC_ATTR_REGISTRAR_MAX,		"Registrar Max",
		ATTR_CUSTOM,	{ .function = print_wsc_byte } },
	{ WSC_ATTR_REGISTRAR_NONCE,		"Registrar Nonce",
		ATTR_CUSTOM,	{ .function = print_wsc_bytes } },
	{ WSC_ATTR_REQUEST_TYPE,		"Request Type",
		ATTR_CUSTOM,	{ .function = print_wsc_request_type } },
	{ WSC_ATTR_RESPONSE_TYPE,		"Response Type",
		ATTR_CUSTOM,	{ .function = print_wsc_response_type } },
	{ WSC_ATTR_RF_BANDS,			"RF Bands",
		ATTR_CUSTOM,	{ .function = print_wsc_rf_bands } },
	{ WSC_ATTR_R_HASH1,			"R_Hash1",
		ATTR_CUSTOM,	{ .function = print_wsc_bytes } },
	{ WSC_ATTR_R_HASH2,			"R_Hash2",
		ATTR_CUSTOM,	{ .function = print_wsc_bytes } },
	{ WSC_ATTR_SELECTED_REGISTRAR,		"Selected Registrar",
		ATTR_CUSTOM,	{ .function = print_wsc_bool } },
	{ WSC_ATTR_SERIAL_NUMBER,		"Serial Number",
		ATTR_CUSTOM,	{ .function = print_wsc_serial_number } },
	{ WSC_ATTR_TOTAL_NETWORKS,		"Total Networks",
		ATTR_CUSTOM,	{ .function = print_wsc_byte } },
	{ WSC_ATTR_UUID_E,			"UUID-E",
		ATTR_CUSTOM,	{ .function = print_wsc_uuid } },
	{ WSC_ATTR_UUID_R,			"UUID-R",
		ATTR_CUSTOM,	{ .function = print_wsc_uuid } },
	{ WSC_ATTR_VENDOR_EXTENSION,		"Vendor Extension",
		ATTR_CUSTOM,	{ .function = print_wsc_vendor_extension } },
	{ WSC_ATTR_VERSION,			"Version",
		ATTR_CUSTOM,	{ .function = print_wsc_version } },
	{ WSC_ATTR_WSC_STATE,			"WSC State",
		ATTR_CUSTOM,	{ .function = print_wsc_state } },
	{ },
};

static void print_wsc_attributes(unsigned int level, const char *label,
					const void *data, uint16_t size)
{
	struct wsc_attr_iter iter;
	int i;

	print_attr(level, "%s: len %u", label, size);

	wsc_attr_iter_init(&iter, data, size);

	while (wsc_attr_iter_next(&iter)) {
		uint16_t type = wsc_attr_iter_get_type(&iter);
		uint16_t len = wsc_attr_iter_get_length(&iter);
		const void *attr = wsc_attr_iter_get_data(&iter);
		struct attr_entry *entry = NULL;

		for (i = 0; wsc_attr_entry[i].str; i++) {
			if (wsc_attr_entry[i].attr == type) {
				entry = &wsc_attr_entry[i];
				break;
			}
		}

		if (entry && entry->function)
			entry->function(level + 1, entry->str, attr, len);
		else {
			print_attr(level + 1, "Type: 0x%02x: len %u",
								type, len);
			print_hexdump(level + 2, attr, len);
		}
	}
}

static void print_management_ies(unsigned int level, const char *label,
					const void *data, uint16_t size)
{
	void *wsc_data;
	ssize_t wsc_len;

	print_ie(level, label, data, size);

	wsc_data = ie_tlv_extract_wsc_payload(data, size, &wsc_len);
	if (!wsc_data)
		return;

	print_wsc_attributes(level + 1, "WSC Payload", wsc_data, wsc_len);
	l_free(wsc_data);
}

static void print_address(unsigned int level, const char *label,
					const unsigned char address[6])
{
	char addr[18];

	snprintf(addr, sizeof(addr), "%02X:%02X:%02X:%02X:%02X:%02X",
					address[0], address[1], address[2],
					address[3], address[4], address[5]);

	print_attr(level, "%s %s", label, addr);
}

static void print_reason_code(unsigned int level, const char *label,
				const void *data, uint16_t size)
{
	uint16_t rc;
	/* 802.11-2012, Table 8-36 */
	static const char *reason_code_table[] = {
		[0] = "Reserved",
		[1] = "Unspecified reason",
		[2] = "Previous authentication no longer valid",
		[3] = "Leaving",
		[4] = "Disassociation due to inactivity",
		[5] = "Disassociated because AP is unable to handle all"
			" currently associated STAs",
		[6] = "Class 2 frame received from nonauthenticated STA",
		[7] = "Class 3 frame received from nonassociated STA",
		[8] = "Disassociated because sending STA is leaving",
		[9] = "STA requesting (re)association is not authenticated "
			"with responding STA",
		[10] = "Disassociated because the information in the Power "
			"Capability element is unacceptable",
		[11] = "Disassociated because the information in the Supported "
			"Channels element is unacceptable",
		[12] = "Disassociated due to BSS Transition Management",
		[13] = "Invalid element",
		[14] = "MIC failure",
		[15] = "4-Way Handshake timeout",
		[16] = "Group Key Handshake timeout",
		[17] = "Element in 4-Way Handshake different from "
			"(Re)Association Request/Probe Response/Beacon frame",
		[18] = "Invalid group cipher",
		[19] = "Invalid pairwise cipher",
		[20] = "Invalid AKMP",
		[21] = "Unsupported RSNE version",
		[22] = "Invalid RSNE capabilities",
		[23] = "IEEE 802.1X authentication failed",
		[24] = "Cipher suite rejected because of the security policy",
		[25] = "TDLS direct-link teardown due to TDLS peer STA "
			"unreachable via the TDLS direct link",
		[26] = "TDLS direct-link teardown for unspecified reason",
		[27] = "Disassociated because session terminated by SSP "
			"request",
		[28] = "Disassociated because of lack of SSP roaming agreement",
		[29] = "Requested service rejected because of SSP cipher "
			"suite or AKM requirement",
		[30] = "Requested service not authorized in this location",
		[31] = "TS deleted because QoS AP lacks sufficient bandwidth "
			"for this QoS STA due to a change in BSS service "
			"characteristics or operational mode",
		[32] = "Disassociated for unspecified, QoS-related reason",
		[33] = "Disassociated because QoS AP lacks sufficient "
			"bandwidth for this QoS STA",
		[34] = "Disassociated because excessive number of frames need "
			"to be acknowledged, but are not acknowledged due to "
			"AP transmissions and/or poor channel conditions",
		[35] = "Disassociated because STA is transmitting outside the "
			"limits of its TXOPs",
		[36] = "Requested from peer STA as the STA is leaving",
		[37] = "Requested from peer STA as it does not want to use the "
			"mechanism",
		[38] = "Requested from peer STA as the STA received frames "
			"using the mechanism for which a setup is required",
		[39] = "Requested from peer STA due to timeout",
		[40 ... 44] = "Reserved",
		[45] = "Peer STA does not support the requested cipher suite",
		[46] = "The teardown was initiated by the DLS peer | "
			"Disassociated because authorized access limit reached",
		[47] = "The teardown was initiated by the AP | "
			"Disassociated due to external service requirements",
		[48] = "Invalid FT Action frame count",
		[49] = "Invalid PMKI",
		[50] = "Invalid MDE",
		[51] = "Invalid FTE",
		[52] = "SME cancels the mesh peering instance with the reason "
			"other than reaching the maximum number of peer mesh "
			"STAs",
		[53] = "The mesh STA has reached the supported maximum number "
			"of peer mesh STAs",
		[54] = "The received information violates the Mesh "
			"Configuration policy configured in the mesh STA "
			"profile",
		[55] = "The mesh STA has received a Mesh Peering Close message "
			"requesting to close the mesh peering.",
		[56] = "The mesh STA has resent dot11MeshMaxRetries Mesh "
			"Peering Open messages, without receiving a Mesh "
			"Peering Confirm message.",
		[57] = "The confirmTimer for the mesh peering instance times "
			"out.",
		[58] = "The mesh STA fails to unwrap the GTK or the values in "
			"the wrapped contents do not match",
		[59] = "The mesh STA receives inconsistent information about "
			"the mesh parameters between Mesh Peering Management "
			"frames",
		[60] = "The mesh STA fails the authenticated mesh peering "
			"exchange because due to failure in selecting either "
			"the pairwise ciphersuite or group ciphersuite",
		[61] = "The mesh STA does not have proxy information for this "
			"external destination.",
		[62] = "The mesh STA does not have forwarding information for "
			"this destination.",
		[63] = "The mesh STA determines that the link to the next hop "
			"of an active path in its forwarding information is "
			"no longer usable.",
		[64] = "The Deauthentication frame was sent because the MAC "
			"address of the STA already exists in the mesh BSS. "
			"See 10.3.6.",
		[65] = "The mesh STA performs channel switch to meet "
			"regulatory requirements.",
		[66] = "The mesh STA performs channel switch with unspecified "
			"reason.",
	};

	if (size != 2)
		return;

	rc = *((uint16_t *) data);

	if (rc >= L_ARRAY_SIZE(reason_code_table))
		print_attr(level, "%s: Reserved", label);
	else
		print_attr(level, "%s: %s", label, reason_code_table[rc]);
}

static void print_mpdu_frame_control(unsigned int level,
						const struct mpdu_fc *fc)
{
	print_attr(level, "Frame Control: protocol: %02u type: %02u "
			"subtype: %02u to: %02u from: %02u more_frags: %02u",
			fc->protocol_version, fc->type, fc->subtype,
			fc->to_ds, fc->from_ds, fc->more_fragments);
	print_attr(level + 1, "retry: %02u power_mgmt: %02u more_data: %02u "
				"protected: %02u order: %02u",
				fc->retry, fc->power_mgmt, fc->more_data,
				fc->protected_frame, fc->order);
}

static void print_mmpdu_header(unsigned int level,
					const struct mmpdu_header *mmpdu)
{
	print_attr(level, "Duration: %u", L_LE16_TO_CPU(mmpdu->duration));

	print_address(level, "Address 1 (RA):", mmpdu->address_1);
	print_address(level, "Address 2 (TA):", mmpdu->address_2);
	print_address(level, "Address 3:", mmpdu->address_3);

	print_attr(level, "Fragment Number: %u", mmpdu->fragment_number);
	print_attr(level, "Sequence Number: %u",
					MPDU_SEQUENCE_NUMBER(*mmpdu));
}

static void print_authentication_mgmt_frame(unsigned int level,
					const struct mmpdu_header *mmpdu,
					size_t size)
{
	const char *str;
	const struct mmpdu_authentication *body;
	struct ie_tlv_iter iter;

	if (!mmpdu)
		return;

	body = mmpdu_body(mmpdu);

	print_attr(level, "Authentication:");

	print_mpdu_frame_control(level + 1, &mmpdu->fc);
	print_mmpdu_header(level + 1, mmpdu);

	switch (L_LE16_TO_CPU(body->algorithm)) {
	case MMPDU_AUTH_ALGO_OPEN_SYSTEM:
		str = "Open";
		break;
	case MMPDU_AUTH_ALGO_SHARED_KEY:
		str = "Shared key";
		break;
	case MMPDU_AUTH_ALGO_FT:
		str = "FT";
		break;
	case MMPDU_AUTH_ALGO_SAE:
		str = "SAE";
		break;
	default:
		str = "Reserved";
		break;
	}

	print_attr(level + 1, "Algorithm: %s (seq: %u, status: %u)", str,
				L_LE16_TO_CPU(body->transaction_sequence),
				L_LE16_TO_CPU(body->status));

	if (L_LE16_TO_CPU(body->algorithm) != MMPDU_AUTH_ALGO_SHARED_KEY)
		return;

	if (L_LE16_TO_CPU(body->transaction_sequence) < 2 ||
			L_LE16_TO_CPU(body->transaction_sequence) > 3)
		return;

	ie_tlv_iter_init(&iter, body->ies, (const uint8_t *) mmpdu + size -
				body->ies);
	ie_tlv_iter_next(&iter);

	print_attr(level + 1, "Challenge text: \"%s\" (%u)",
				ie_tlv_iter_get_data(&iter),
				ie_tlv_iter_get_length(&iter));
}

static void print_deauthentication_mgmt_frame(unsigned int level,
					const struct mmpdu_header *mmpdu)
{
	const struct mmpdu_deauthentication *body;

	if (!mmpdu)
		return;

	body = mmpdu_body(mmpdu);

	print_attr(level, "Deauthentication:");

	print_mpdu_frame_control(level + 1, &mmpdu->fc);
	print_mmpdu_header(level + 1, mmpdu);

	print_attr(level + 1, "Reason code: %u",
				L_LE16_TO_CPU(body->reason_code));
}

static void print_frame_type(unsigned int level, const char *label,
					const void *data, uint16_t size)
{
	uint16_t frame_type = *((uint16_t *) data);
	uint8_t type = frame_type & 0x000c;
	uint8_t subtype = (frame_type & 0x00f0) >> 4;
	const struct mmpdu_header *mpdu = NULL;
	const char *str;

	print_attr(level, "%s: 0x%04x", label, frame_type);

	switch (type) {
	case 0x00:
		str = "Management";
		mpdu = mpdu_validate(data, size);
		break;
	default:
		str = "Reserved";
		break;
	}

	print_attr(level + 1, "Type: %s (%u)", str, type);

	str = NULL;

	switch (subtype) {
	case 0x00:
		str = "Association request";
		break;
	case 0x01:
		str = "Association response";
		break;
	case 0x02:
		str = "Reassociation request";
		break;
	case 0x03:
		str = "Reassociation response";
		break;
	case 0x04:
		str = "Probe request";
		break;
	case 0x05:
		str = "Probe response";
		break;
	case 0x06:
		str = "Timing Advertisement";
		break;
	case 0x08:
		str = "Beacon";
		break;
	case 0x09:
		str = "ATIM";
		break;
	case 0x0a:
		str = "Disassociation";
		break;
	case 0x0b:
		if (mpdu)
			print_authentication_mgmt_frame(level + 1, mpdu, size);
		else
			str = "Authentication";
		break;
	case 0x0c:
		if (mpdu)
			print_deauthentication_mgmt_frame(level + 1, mpdu);
		else
			str = "Deauthentication";
		break;
	case 0x0d:
		str = "Action";
		break;
	case 0x0e:
		str = "Action No Ack";
		break;
	default:
		str = "Reserved";
		break;
	}

	if (str)
		print_attr(level + 1, "Subtype: %s (%u)", str, subtype);
}

static void print_frame(unsigned int level, const char *label,
					const void *data, uint16_t size)
{
	print_attr(level, "%s: len %u", label, size);
	print_frame_type(level + 1, "Frame Type", data, size);
	print_hexdump(level + 1, data, size);
}

static void print_cipher_suite(unsigned int level, const char *label,
					const void *data, uint16_t size)
{
	uint32_t cipher = *((uint32_t *) data);

	if (size != 4)
		return;

	print_ie_cipher_suite(level, label, cipher, rsn_cipher_selectors);
}

static void print_cipher_suites(unsigned int level, const char *label,
					const void *data, uint16_t size)
{
	print_attr(level, "%s:", label);

	while (size >= 4) {
		print_cipher_suite(level + 1, NULL, data, 4);
		data += 4;
		size -= 4;
	}
}

static void print_akm_suites(unsigned int level, const char *label,
					const void *data, uint16_t size)
{
	print_attr(level, "%s:", label);

	while (size >= 4) {
		uint32_t akm = *((uint32_t *) data);

		print_ie_cipher_suite(level + 1, NULL, akm, rsn_akm_selectors);
		data += 4;
		size -= 4;
	}
}

static const struct attr_entry iftype_table[] = {
	{ NL80211_IFTYPE_ADHOC,		"Ad-hoc",	ATTR_FLAG },
	{ NL80211_IFTYPE_STATION,	"Station",	ATTR_FLAG },
	{ NL80211_IFTYPE_AP,		"AP",		ATTR_FLAG },
	{ NL80211_IFTYPE_AP_VLAN,	"AP-VLAN",	ATTR_FLAG },
	{ NL80211_IFTYPE_WDS,		"WDS",		ATTR_FLAG },
	{ NL80211_IFTYPE_MONITOR,	"Monitor",	ATTR_FLAG },
	{ NL80211_IFTYPE_MESH_POINT,	"Mesh-point",	ATTR_FLAG },
	{ NL80211_IFTYPE_P2P_CLIENT,	"P2P-Client",	ATTR_FLAG },
	{ NL80211_IFTYPE_P2P_GO,	"P2P-GO",	ATTR_FLAG },
	{ NL80211_IFTYPE_P2P_DEVICE,	"P2P-Device",	ATTR_FLAG },
	{ }
};

static const struct attr_entry bss_param_table[] = {
	{ NL80211_STA_BSS_PARAM_CTS_PROT,	"CTS protection",  ATTR_FLAG },
	{ NL80211_STA_BSS_PARAM_SHORT_PREAMBLE,	"Short Preamble",  ATTR_FLAG },
	{ NL80211_STA_BSS_PARAM_SHORT_SLOT_TIME,"Short Slot Time", ATTR_FLAG },
	{ NL80211_STA_BSS_PARAM_DTIM_PERIOD,	"DTIM Period",     ATTR_U8   },
	{ NL80211_STA_BSS_PARAM_BEACON_INTERVAL,"Beacon Interval", ATTR_U16  },
	{ }
};

static const struct attr_entry sta_flag_table[] = {
	{ NL80211_STA_FLAG_AUTHORIZED,		"Authorized",	ATTR_FLAG },
	{ NL80211_STA_FLAG_SHORT_PREAMBLE,	"ShortPreamble",ATTR_FLAG },
	{ NL80211_STA_FLAG_WME,			"WME",		ATTR_FLAG },
	{ NL80211_STA_FLAG_MFP,			"MFP",		ATTR_FLAG },
	{ NL80211_STA_FLAG_AUTHENTICATED,	"Authenticated",ATTR_FLAG },
	{ NL80211_STA_FLAG_TDLS_PEER,		"TDLS-Peer",	ATTR_FLAG },
	{ NL80211_STA_FLAG_ASSOCIATED,		"Associated",	ATTR_FLAG },
	{ }
};

static void print_sta_flag_update(unsigned int level, const char *label,
					const void *data, uint16_t size)
{
	const struct nl80211_sta_flag_update *flags = data;
	unsigned int i;

	print_attr(level, "%s: len %u", label, size);

	print_attr(level + 1, "Mask: 0x%08x", flags->mask);
	for (i = 0; sta_flag_table[i].str; i++) {
		if (flags->mask & (1 << sta_flag_table[i].attr))
			print_attr(level + 2, "%s", sta_flag_table[i].str);
	}

	print_attr(level + 1, "Set: 0x%08x", flags->set);
	for (i = 0; sta_flag_table[i].str; i++) {
		if (flags->set & (1 << sta_flag_table[i].attr))
			print_attr(level + 2, "%s", sta_flag_table[i].str);
	}
}

static const struct attr_entry rate_info_table[] = {
	{ NL80211_RATE_INFO_BITRATE,	"Bit Rate (Legacy)",	ATTR_U16 },
	{ NL80211_RATE_INFO_MCS,	"MCS Index",		ATTR_U8 },
	{ NL80211_RATE_INFO_40_MHZ_WIDTH, "40 Mhz Width",	ATTR_FLAG },
	{ NL80211_RATE_INFO_SHORT_GI,	"Short GI",		ATTR_FLAG },
	{ NL80211_RATE_INFO_BITRATE32,	"Bit Rate",		ATTR_U32 },
	{ NL80211_RATE_INFO_VHT_MCS,	"VHT MCS Index",	ATTR_U8 },
	{ NL80211_RATE_INFO_VHT_NSS,	"# VHT Streams",	ATTR_U8 },
	{ NL80211_RATE_INFO_80_MHZ_WIDTH, "80 Mhz Width",	ATTR_FLAG },
	{ NL80211_RATE_INFO_80P80_MHZ_WIDTH, "80P80 Mhz Width", ATTR_FLAG },
	{ NL80211_RATE_INFO_160_MHZ_WIDTH, "160 Mhz Width",	ATTR_FLAG },
	{ }
};

static const struct attr_entry sta_info_table[] = {
	{ NL80211_STA_INFO_INACTIVE_TIME,
					"Inactivity time",	ATTR_U32 },
	{ NL80211_STA_INFO_RX_BYTES,	"Total RX bytes",	ATTR_U32 },
	{ NL80211_STA_INFO_TX_BYTES,	"Total TX bytes",	ATTR_U32 },
	{ NL80211_STA_INFO_RX_BYTES64,	"Total RX bytes",	ATTR_U64 },
	{ NL80211_STA_INFO_TX_BYTES64,	"Total TX bytes",	ATTR_U64 },
	{ NL80211_STA_INFO_SIGNAL,	"Signal strength",	ATTR_S8  },
	{ NL80211_STA_INFO_TX_BITRATE,	"TX bitrate",
					ATTR_NESTED, { rate_info_table } },
	{ NL80211_STA_INFO_RX_PACKETS,	"RX packets",		ATTR_U32 },
	{ NL80211_STA_INFO_TX_PACKETS,	"TX packets",		ATTR_U32 },
	{ NL80211_STA_INFO_TX_RETRIES,	"TX retries",		ATTR_U32 },
	{ NL80211_STA_INFO_TX_FAILED,	"TX failed",		ATTR_U32 },
	{ NL80211_STA_INFO_SIGNAL_AVG,	"Signal strength average",
								ATTR_S8  },
	{ NL80211_STA_INFO_LLID,	"Mesh LLID",		ATTR_U16 },
	{ NL80211_STA_INFO_PLID,	"Mesh PLID",		ATTR_U16 },
	{ NL80211_STA_INFO_PLINK_STATE, "P-Link state" },
	{ NL80211_STA_INFO_RX_BITRATE,	"RX bitrate",
					ATTR_NESTED, { rate_info_table } },
	{ NL80211_STA_INFO_BSS_PARAM,	"BSS parameters",
					ATTR_NESTED, { bss_param_table } },
	{ NL80211_STA_INFO_CONNECTED_TIME,
					"Connected time",	ATTR_U32 },
	{ NL80211_STA_INFO_STA_FLAGS,	"Station flags",
			ATTR_CUSTOM, { .function = print_sta_flag_update } },
	{ NL80211_STA_INFO_BEACON_LOSS,	"Beacon loss",		ATTR_U32 },
	{ NL80211_STA_INFO_T_OFFSET,	"Timing offset",	ATTR_S64 },
	{ NL80211_STA_INFO_LOCAL_PM,	"Local mesh PM",	ATTR_U32 },
	{ NL80211_STA_INFO_PEER_PM,	"Peer mesh PM",		ATTR_U32 },
	{ NL80211_STA_INFO_NONPEER_PM,	"Neighbor mesh PM",	ATTR_U32 },
	{ NL80211_STA_INFO_CHAIN_SIGNAL,
					"Per-chain signal strength" },
	{ NL80211_STA_INFO_CHAIN_SIGNAL_AVG,
					"Per-chain signal strength average" },
	{ }
};

static void print_bss_capability(unsigned int level, const char *label,
					const void *data, uint16_t size)
{
	uint16_t cap = *(uint16_t *) data;

	print_attr(level, "%s: %"PRIu16" (0x%04"PRIx16")", label, cap, cap);

	if (cap & BSS_CAPABILITY_ESS)
		print_attr(level + 1, "ESS");
	if (cap & BSS_CAPABILITY_IBSS)
		print_attr(level + 1, "IBSS");
	if (cap & BSS_CAPABILITY_PRIVACY)
		print_attr(level + 1, "Privacy");
	if (cap & BSS_CAPABILITY_SHORT_PREAMBLE)
		print_attr(level + 1, "ShortPreamble");
	if (cap & BSS_CAPABILITY_PBCC)
		print_attr(level + 1, "PBCC");
	if (cap & BSS_CAPABILITY_CHANNEL_AGILITY)
		print_attr(level + 1, "ChannelAgility");
	if (cap & BSS_CAPABILITY_SPECTRUM_MGMT)
		print_attr(level + 1, "SpectrumMgmt");
	if (cap & BSS_CAPABILITY_QOS)
		print_attr(level + 1, "QoS");
	if (cap & BSS_CAPABILITY_SHORT_SLOT_TIME)
		print_attr(level + 1, "ShortSlotTime");
	if (cap & BSS_CAPABILITY_APSD)
		print_attr(level + 1, "APSD");
	if (cap & BSS_CAPABILITY_DSSS_OFDM)
		print_attr(level + 1, "DSSS-OFDM");
}

static const struct attr_entry bss_table[] = {
	{ NL80211_BSS_BSSID,		"BSSID",	ATTR_ADDRESS	},
	{ NL80211_BSS_FREQUENCY,	"Frequency",	ATTR_U32	},
	{ NL80211_BSS_TSF,		"TSF",		ATTR_U64	},
	{ NL80211_BSS_BEACON_INTERVAL,	"Beacon Interval",
							ATTR_U16	},
	{ NL80211_BSS_CAPABILITY,	"Capability",  ATTR_CUSTOM,
				{ .function = print_bss_capability }	},
	{ NL80211_BSS_INFORMATION_ELEMENTS, "IEs",
		ATTR_CUSTOM, { .function = print_management_ies }	},
	{ NL80211_BSS_SIGNAL_MBM,	"Signal mBm",	ATTR_S32	},
	{ NL80211_BSS_SIGNAL_UNSPEC,	"Signal Unspec",ATTR_U8		},
	{ NL80211_BSS_STATUS,		"Status",	ATTR_U32	},
	{ NL80211_BSS_SEEN_MS_AGO,	"Seen ms ago",	ATTR_U32	},
	{ NL80211_BSS_BEACON_IES, "Beacon IEs",
		ATTR_CUSTOM, { .function = print_management_ies }	},
	{ NL80211_BSS_CHAN_WIDTH,	"Chan Width",	ATTR_U32	},
	{ NL80211_BSS_BEACON_TSF,	"Beacon TSF",	ATTR_U64	},
	{ NL80211_BSS_PRESP_DATA,	"Probe Response", ATTR_FLAG	},
	{ }
};

static const struct attr_entry frame_types_field_table[] = {
	{ NL80211_ATTR_FRAME_TYPE,
			"Frame Type", ATTR_CUSTOM,
					{ .function = print_frame_type } },
	{ }
};

static const struct attr_entry frame_types_table[] = {
	{ NL80211_IFTYPE_ADHOC, "Ad-hoc", ATTR_NESTED,
						{ frame_types_field_table } },
	{ NL80211_IFTYPE_STATION, "Station", ATTR_NESTED,
						{ frame_types_field_table } },
	{ NL80211_IFTYPE_AP, "AP", ATTR_NESTED,
						{ frame_types_field_table } },
	{ NL80211_IFTYPE_AP_VLAN, "AP-VLAN", ATTR_NESTED,
						{ frame_types_field_table } },
	{ NL80211_IFTYPE_WDS, "WDS", ATTR_NESTED,
						{ frame_types_field_table } },
	{ NL80211_IFTYPE_MONITOR, "Monitor", ATTR_NESTED,
						{ frame_types_field_table } },
	{ NL80211_IFTYPE_MESH_POINT, "Mesh-point", ATTR_NESTED,
						{ frame_types_field_table } },
	{ NL80211_IFTYPE_P2P_CLIENT, "P2P-Client", ATTR_NESTED,
						{ frame_types_field_table } },
	{ NL80211_IFTYPE_P2P_GO, "P2P-GO", ATTR_NESTED,
						{ frame_types_field_table } },
	{ NL80211_IFTYPE_P2P_DEVICE, "P2P-Device", ATTR_NESTED,
						{ frame_types_field_table } },
	{ }
};

static const struct attr_entry cqm_table[] = {
	{ NL80211_ATTR_CQM_RSSI_THOLD,	"RSSI threshold",	ATTR_U32 },
	{ NL80211_ATTR_CQM_RSSI_HYST,	"RSSI hysteresis",	ATTR_U32 },
	{ NL80211_ATTR_CQM_RSSI_THRESHOLD_EVENT,
					"RSSI threshold event",	ATTR_U32 },
	{ NL80211_ATTR_CQM_PKT_LOSS_EVENT,
					"Packet loss event",	ATTR_U32 },
	{ NL80211_ATTR_CQM_TXE_RATE,	"TX error rate",	ATTR_U32 },
	{ NL80211_ATTR_CQM_TXE_PKTS,	"TX error packets",	ATTR_U32 },
	{ NL80211_ATTR_CQM_TXE_INTVL,	"TX error interval",	ATTR_U32 },
	{ NL80211_ATTR_CQM_BEACON_LOSS_EVENT, "Beacon Loss Event", ATTR_FLAG },
	{ }
};

static const struct attr_entry key_default_type_table[] = {
	{ NL80211_KEY_DEFAULT_TYPE_UNICAST,	"Unicast",	ATTR_FLAG },
	{ NL80211_KEY_DEFAULT_TYPE_MULTICAST,	"Multicast",	ATTR_FLAG },
	{ }
};

static void print_rekey_kek(unsigned int level, const char *label,
					const void *data, uint16_t size)
{
	print_attr(level, "%s: len %u", label, size);

	if (size != NL80211_KEK_LEN)
		printf("malformed packet");

	print_hexdump(level + 1, data, size);
}

static void print_rekey_kck(unsigned int level, const char *label,
					const void *data, uint16_t size)
{
	print_attr(level, "%s: len %u", label, size);

	if (size != NL80211_KCK_LEN)
		printf("malformed packet");

	print_hexdump(level + 1, data, size);
}

static void print_rekey_replay_ctr(unsigned int level, const char *label,
						const void *data, uint16_t size)
{
	print_attr(level, "%s: len %u", label, size);

	if (size != NL80211_REPLAY_CTR_LEN)
		printf("malformed packet");

	print_hexdump(level + 1, data, size);
}

static const struct attr_entry rekey_table[] = {
	{ NL80211_REKEY_DATA_KEK, "KEK", ATTR_CUSTOM,
				{ .function = print_rekey_kek } },
	{ NL80211_REKEY_DATA_KCK, "KCK", ATTR_CUSTOM,
				{ .function = print_rekey_kck } },
	{ NL80211_REKEY_DATA_REPLAY_CTR, "Replay CTR", ATTR_CUSTOM,
				{ .function = print_rekey_replay_ctr } },
	{ }
};

#define NLA_OK(nla,len)         ((len) >= (int) sizeof(struct nlattr) && \
				(nla)->nla_len >= sizeof(struct nlattr) && \
				(nla)->nla_len <= (len))
#define NLA_NEXT(nla,attrlen)	((attrlen) -= NLA_ALIGN((nla)->nla_len), \
				(struct nlattr*)(((char*)(nla)) + \
				NLA_ALIGN((nla)->nla_len)))

#define NLA_LENGTH(len)		(NLA_ALIGN(sizeof(struct nlattr)) + (len))
#define NLA_DATA(nla)		((void*)(((char*)(nla)) + NLA_LENGTH(0)))
#define NLA_PAYLOAD(nla)	((int)((nla)->nla_len - NLA_LENGTH(0)))

static const struct {
	uint8_t cmd;
	const char *str;
} cmd_table[] = {
	{ NL80211_CMD_GET_WIPHY,		"Get Wiphy"		},
	{ NL80211_CMD_SET_WIPHY,		"Set Wiphy"		},
	{ NL80211_CMD_NEW_WIPHY,		"New Wiphy"		},
	{ NL80211_CMD_DEL_WIPHY,		"Del Wiphy"		},
	{ NL80211_CMD_GET_INTERFACE,		"Get Interface"		},
	{ NL80211_CMD_SET_INTERFACE,		"Set Interface"		},
	{ NL80211_CMD_NEW_INTERFACE,		"New Interface"		},
	{ NL80211_CMD_DEL_INTERFACE,		"Del Interface"		},
	{ NL80211_CMD_GET_KEY,			"Get Key"		},
	{ NL80211_CMD_SET_KEY,			"Set Key"		},
	{ NL80211_CMD_NEW_KEY,			"New Key"		},
	{ NL80211_CMD_DEL_KEY,			"Del Key"		},
	{ NL80211_CMD_GET_BEACON,		"Get Beacon"		},
	{ NL80211_CMD_SET_BEACON,		"Set Beacon"		},
	{ NL80211_CMD_START_AP,			"Start AP"		},
	{ NL80211_CMD_STOP_AP,			"Stop AP"		},
	{ NL80211_CMD_GET_STATION,		"Get Station"		},
	{ NL80211_CMD_SET_STATION,		"Set Station"		},
	{ NL80211_CMD_NEW_STATION,		"New Station"		},
	{ NL80211_CMD_DEL_STATION,		"Del Station"		},
	{ NL80211_CMD_GET_MPATH,		"Get Mesh Path"		},
	{ NL80211_CMD_SET_MPATH,		"Set Mesh Path"		},
	{ NL80211_CMD_NEW_MPATH,		"New Mesh Path"		},
	{ NL80211_CMD_DEL_MPATH,		"Del Mesh Path"		},
	{ NL80211_CMD_SET_BSS,			"Set BSS"		},
	{ NL80211_CMD_SET_REG,			"Set Reg"		},
	{ NL80211_CMD_REQ_SET_REG,		"Req Set Reg"		},
	{ NL80211_CMD_GET_MESH_CONFIG,		"Get Mesh Config"	},
	{ NL80211_CMD_SET_MESH_CONFIG,		"Set Mesh Config"	},
	{ NL80211_CMD_SET_MGMT_EXTRA_IE,	"Mgmt Extra IE"		},
	{ NL80211_CMD_GET_REG,			"Get Reg"		},
	{ NL80211_CMD_GET_SCAN,			"Get Scan"		},
	{ NL80211_CMD_TRIGGER_SCAN,		"Trigger Scan"		},
	{ NL80211_CMD_NEW_SCAN_RESULTS,		"New Scan Results"	},
	{ NL80211_CMD_SCAN_ABORTED,		"Scan Aborted"		},
	{ NL80211_CMD_REG_CHANGE,		"Reg Change"		},
	{ NL80211_CMD_AUTHENTICATE,		"Authenticate"		},
	{ NL80211_CMD_ASSOCIATE,		"Associate"		},
	{ NL80211_CMD_DEAUTHENTICATE,		"Deauthenticate"	},
	{ NL80211_CMD_DISASSOCIATE,		"Disassociate"		},
	{ NL80211_CMD_MICHAEL_MIC_FAILURE,	"Michael MIC Failure"	},
	{ NL80211_CMD_REG_BEACON_HINT,		"Reg Beacon Hint"	},
	{ NL80211_CMD_JOIN_IBSS,		"Join IBSS"		},
	{ NL80211_CMD_LEAVE_IBSS,		"Leave IBSS"		},
	{ NL80211_CMD_TESTMODE,			"Test Mode"		},
	{ NL80211_CMD_CONNECT,			"Connect"		},
	{ NL80211_CMD_ROAM,			"Roam"			},
	{ NL80211_CMD_DISCONNECT,		"Disconnect"		},
	{ NL80211_CMD_SET_WIPHY_NETNS,		"Set Wiphy Netns"	},
	{ NL80211_CMD_GET_SURVEY,		"Get Survey"		},
	{ NL80211_CMD_NEW_SURVEY_RESULTS,	"New Survey Results"	},
	{ NL80211_CMD_SET_PMKSA,		"Set PMKSA"		},
	{ NL80211_CMD_DEL_PMKSA,		"Del PMKSA"		},
	{ NL80211_CMD_FLUSH_PMKSA,		"Flush PMKSA"		},
	{ NL80211_CMD_REMAIN_ON_CHANNEL,	"Remain on Channel"	},
	{ NL80211_CMD_CANCEL_REMAIN_ON_CHANNEL,	"Cancel Remain on Channel"},
	{ NL80211_CMD_SET_TX_BITRATE_MASK,	"Set TX Bitrate Mask"	},
	{ NL80211_CMD_REGISTER_FRAME,		"Register Frame"	},
	{ NL80211_CMD_FRAME,			"Frame"			},
	{ NL80211_CMD_FRAME_TX_STATUS,		"Frame TX Status"	},
	{ NL80211_CMD_SET_POWER_SAVE,		"Set Power Save"	},
	{ NL80211_CMD_GET_POWER_SAVE,		"Get Power Save"	},
	{ NL80211_CMD_SET_CQM,			"Set CQM"		},
	{ NL80211_CMD_NOTIFY_CQM,		"Notify CQM"		},
	{ NL80211_CMD_SET_CHANNEL,		"Set Channel"		},
	{ NL80211_CMD_SET_WDS_PEER,		"Set WDS Peer"		},
	{ NL80211_CMD_FRAME_WAIT_CANCEL,	"Frame Wait Cancel"	},
	{ NL80211_CMD_JOIN_MESH,		"Join Mesh"		},
	{ NL80211_CMD_LEAVE_MESH,		"Leave Mesh"		},
	{ NL80211_CMD_UNPROT_DEAUTHENTICATE,	"Unprot Deauthenticate"	},
	{ NL80211_CMD_UNPROT_DISASSOCIATE,	"Unprot Disassociate"	},
	{ NL80211_CMD_NEW_PEER_CANDIDATE,	"New Peer Candidate"	},
	{ NL80211_CMD_GET_WOWLAN,		"Get WoWLAN"		},
	{ NL80211_CMD_SET_WOWLAN,		"Set WoWLAN"		},
	{ NL80211_CMD_START_SCHED_SCAN,		"Start Sched Scan"	},
	{ NL80211_CMD_STOP_SCHED_SCAN,		"Stop Sched Scan"	},
	{ NL80211_CMD_SCHED_SCAN_RESULTS,	"Sched Scan Results"	},
	{ NL80211_CMD_SCHED_SCAN_STOPPED,	"Sched Scan Stopped"	},
	{ NL80211_CMD_SET_REKEY_OFFLOAD,	"Set Rekey Offload"	},
	{ NL80211_CMD_PMKSA_CANDIDATE,		"PMKSA Candidate"	},
	{ NL80211_CMD_TDLS_OPER,		"TDLS Oper"		},
	{ NL80211_CMD_TDLS_MGMT,		"TDLS Mgmt"		},
	{ NL80211_CMD_UNEXPECTED_FRAME,		"Unexpected Frame"	},
	{ NL80211_CMD_PROBE_CLIENT,		"Probe Client"		},
	{ NL80211_CMD_REGISTER_BEACONS,		"Register Beacons"	},
	{ NL80211_CMD_UNEXPECTED_4ADDR_FRAME,	"Unexpected 4addr Frame"},
	{ NL80211_CMD_SET_NOACK_MAP,		"Set NoAck Map"		},
	{ NL80211_CMD_CH_SWITCH_NOTIFY,		"Channel Switch Notify"	},
	{ NL80211_CMD_START_P2P_DEVICE,		"Start P2P Device"	},
	{ NL80211_CMD_STOP_P2P_DEVICE,		"Stop P2P Device"	},
	{ NL80211_CMD_CONN_FAILED,		"Conn Failed"		},
	{ NL80211_CMD_SET_MCAST_RATE,		"Set Mcast Rate"	},
	{ NL80211_CMD_SET_MAC_ACL,		"Set MAC ACL"		},
	{ NL80211_CMD_RADAR_DETECT,		"Radar Detect"		},
	{ NL80211_CMD_GET_PROTOCOL_FEATURES,	"Get Protocol Features"	},
	{ NL80211_CMD_UPDATE_FT_IES,		"Update FT IEs"		},
	{ NL80211_CMD_FT_EVENT,			"FT Event"		},
	{ NL80211_CMD_CRIT_PROTOCOL_START,	"Crit Protocol Start"	},
	{ NL80211_CMD_CRIT_PROTOCOL_STOP,	"Crit Protocol Stop"	},
	{ NL80211_CMD_GET_COALESCE,		"Get Coalesce"		},
	{ NL80211_CMD_SET_COALESCE,		"Set Coalesce"		},
	{ NL80211_CMD_CHANNEL_SWITCH,		"Channel Switch"	},
	{ NL80211_CMD_VENDOR,			"Vendor"		},
	{ NL80211_CMD_SET_QOS_MAP,		"Set QoS Map"		},
	{ NL80211_CMD_ADD_TX_TS,		"Add Traffic Stream"	},
	{ NL80211_CMD_DEL_TX_TS,		"Delete Traffic Stream" },
	{ NL80211_CMD_GET_MPP,			"Get Mesh Proxy Path"	},
	{ NL80211_CMD_JOIN_OCB,			"Join OCB Network"	},
	{ NL80211_CMD_LEAVE_OCB,		"Leave OCB Network"	},
	{ NL80211_CMD_CH_SWITCH_STARTED_NOTIFY, "Channel Switch Notify"	},
	{ NL80211_CMD_TDLS_CHANNEL_SWITCH,	"TDLS Channel Switch"	},
	{ NL80211_CMD_TDLS_CANCEL_CHANNEL_SWITCH,
						"Cancel TLDS Channel Switch" },
	{ NL80211_CMD_WIPHY_REG_CHANGE,		"Wiphy Reg Change"	},
	{ }
};

static void print_supported_commands(unsigned int level, const char *label,
					const void *data, uint16_t size)
{
	const struct nlattr *nla;

	print_attr(level, "%s:", label);

	for (nla = data; NLA_OK(nla, size); nla = NLA_NEXT(nla, size)) {
		const char *cmd_str = "Reserved";
		uint32_t cmd = *((uint32_t *) NLA_DATA(nla));
		unsigned int i;

		for (i = 0; cmd_table[i].str; i++) {
			if (cmd_table[i].cmd == cmd) {
				cmd_str = cmd_table[i].str;
				break;
			}
		}

		print_attr(level + 1, "%s [%d]", cmd_str, cmd);
	}
}

static const struct attr_entry frequency_attr_table[] = {
	{ NL80211_FREQUENCY_ATTR_FREQ, "Frequency", ATTR_U32 },
	{ NL80211_FREQUENCY_ATTR_DISABLED, "Disabled", ATTR_FLAG },
	{ NL80211_FREQUENCY_ATTR_NO_IR, "No IR", ATTR_FLAG },
	{ __NL80211_FREQUENCY_ATTR_NO_IBSS, "No IBSS", ATTR_FLAG },
	{ NL80211_FREQUENCY_ATTR_RADAR, "Radar Detection", ATTR_FLAG },
	{ NL80211_FREQUENCY_ATTR_MAX_TX_POWER, "Max TX Power", ATTR_U32 },
	{ NL80211_FREQUENCY_ATTR_DFS_STATE, "DFS State", ATTR_U32 },
	{ NL80211_FREQUENCY_ATTR_DFS_TIME, "DFS Time", ATTR_U32 },
	{ NL80211_FREQUENCY_ATTR_NO_HT40_MINUS, "No HT40-", ATTR_FLAG },
	{ NL80211_FREQUENCY_ATTR_NO_HT40_PLUS, "No HT40+", ATTR_FLAG },
	{ NL80211_FREQUENCY_ATTR_NO_80MHZ, "No 80 Mhz", ATTR_FLAG },
	{ NL80211_FREQUENCY_ATTR_NO_160MHZ, "No 160 Mhz", ATTR_FLAG },
	{ NL80211_FREQUENCY_ATTR_DFS_CAC_TIME, "DFS CAC Time", ATTR_U32 },
	{ NL80211_FREQUENCY_ATTR_INDOOR_ONLY, "Indoor only", ATTR_FLAG },
	{ NL80211_FREQUENCY_ATTR_GO_CONCURRENT, "Go Concurrent", ATTR_FLAG },
	{ NL80211_FREQUENCY_ATTR_NO_20MHZ, "No 20 Mhz", ATTR_FLAG },
	{ NL80211_FREQUENCY_ATTR_NO_10MHZ, "No 10 Mhz", ATTR_FLAG },
	{ }
};

static void print_band_frequencies(unsigned int level, const char *label,
					const void *data, uint16_t size)
{
	const struct nlattr *nla;
	uint16_t nla_type;

	print_attr(level, "%s: len %u", label, size);

	for (nla = data; NLA_OK(nla, size); nla = NLA_NEXT(nla, size)) {
		nla_type = nla->nla_type & NLA_TYPE_MASK;
		print_attr(level + 1, "Frequency %u: len %u", nla_type,
							NLA_PAYLOAD(nla));

		print_attributes(level + 2, frequency_attr_table,
					NLA_DATA(nla), NLA_PAYLOAD(nla));
	}
}

static const struct attr_entry wiphy_bands_table[] = {
	{ NL80211_BAND_ATTR_FREQS, "Frequencies",
			ATTR_CUSTOM, { .function = print_band_frequencies } },
	{ NL80211_BAND_ATTR_RATES, "Rates" },
	{ NL80211_BAND_ATTR_HT_MCS_SET, "HT MCS Set" },
	{ NL80211_BAND_ATTR_HT_CAPA, "HT Capabilities" },
	{ NL80211_BAND_ATTR_HT_AMPDU_FACTOR, "AMPDU Factor" },
	{ NL80211_BAND_ATTR_HT_AMPDU_DENSITY, "AMPDU Density" },
	{ NL80211_BAND_ATTR_VHT_MCS_SET, "VHT MCS Set" },
	{ NL80211_BAND_ATTR_VHT_CAPA, "VHT Capabilities" },
	{ }
};

static void print_wiphy_bands(unsigned int level, const char *label,
					const void *data, uint16_t size)
{
	const struct nlattr *nla;
	uint16_t nla_type;

	print_attr(level, "%s: len %u", label, size);

	for (nla = data; NLA_OK(nla, size); nla = NLA_NEXT(nla, size)) {
		nla_type = nla->nla_type & NLA_TYPE_MASK;
		print_attr(level + 1, "Band %u: len %u", nla_type,
							NLA_PAYLOAD(nla));

		print_attributes(level + 2, wiphy_bands_table,
					NLA_DATA(nla), NLA_PAYLOAD(nla));
	}
}

static const struct attr_entry attr_table[] = {
	{ NL80211_ATTR_WIPHY,
			"Wiphy", ATTR_U32 },
	{ NL80211_ATTR_WIPHY_NAME,
			"Wiphy Name", ATTR_STRING },
	{ NL80211_ATTR_IFINDEX,
			"Interface Index", ATTR_U32 },
	{ NL80211_ATTR_IFNAME,
			"Interface Name", ATTR_STRING },
	{ NL80211_ATTR_IFTYPE,
			"Interface Type", ATTR_U32 },
	{ NL80211_ATTR_MAC,
			"MAC Address", ATTR_ADDRESS },
	{ NL80211_ATTR_KEY_DATA,
			"Key Data", ATTR_BINARY },
	{ NL80211_ATTR_KEY_IDX,
			"Key Index", ATTR_U8 },
	{ NL80211_ATTR_KEY_CIPHER,
			"Key Cipher", ATTR_CUSTOM,
					{ .function = print_cipher_suite } },
	{ NL80211_ATTR_KEY_SEQ,
			"Key Sequence", ATTR_BINARY },
	{ NL80211_ATTR_KEY_DEFAULT,
			"Key Default", ATTR_FLAG },
	{ NL80211_ATTR_BEACON_INTERVAL,
			"Beacon Interval", ATTR_U32 },
	{ NL80211_ATTR_DTIM_PERIOD,
			"DTIM Period", ATTR_U32 },
	{ NL80211_ATTR_BEACON_HEAD,
			"Beacon Head", ATTR_BINARY },
	{ NL80211_ATTR_BEACON_TAIL,
			"Beacon Tail", ATTR_BINARY },
	{ NL80211_ATTR_STA_AID,
			"Station AID", ATTR_U16 },
	{ NL80211_ATTR_STA_FLAGS,
			"Station Flags", ATTR_NESTED, { sta_flag_table } },
	{ NL80211_ATTR_STA_LISTEN_INTERVAL,
			"Station Listen Interval", ATTR_U16 },
	{ NL80211_ATTR_STA_SUPPORTED_RATES,
			"Station Supported Rates", ATTR_BINARY },
	{ NL80211_ATTR_STA_VLAN,
			"Station VLAN", ATTR_U32 },
	{ NL80211_ATTR_STA_INFO,
			"Station Info", ATTR_NESTED, { sta_info_table } },
	{ NL80211_ATTR_WIPHY_BANDS,
			"Wiphy Bands", ATTR_CUSTOM,
				{ .function = print_wiphy_bands } },
	{ NL80211_ATTR_MNTR_FLAGS,
			"MNTR Flags" },
	{ NL80211_ATTR_MESH_ID,
			"Mesh ID", ATTR_BINARY },
	{ NL80211_ATTR_STA_PLINK_ACTION,
			"Station P-Link Action", ATTR_U8 },
	{ NL80211_ATTR_MPATH_NEXT_HOP,
			"Mesh Path Next Hop", ATTR_U32 },
	{ NL80211_ATTR_MPATH_INFO,
			"Mesh Path Info" },
	{ NL80211_ATTR_BSS_CTS_PROT,
			"BSS CTS Protection", ATTR_U8 },
	{ NL80211_ATTR_BSS_SHORT_PREAMBLE,
			"BSS Short Preamble", ATTR_U8 },
	{ NL80211_ATTR_BSS_SHORT_SLOT_TIME,
			"BSS Short Slot Time", ATTR_U8 },
	{ NL80211_ATTR_HT_CAPABILITY, "HT Capability",
			ATTR_CUSTOM, { .function = print_ie_ht_capabilities } },
	{ NL80211_ATTR_SUPPORTED_IFTYPES,
			"Supported Interface Types", ATTR_NESTED,
							{ iftype_table } },
	{ NL80211_ATTR_REG_ALPHA2,
			"Regulatory Alpha2", ATTR_STRING },
	{ NL80211_ATTR_REG_RULES,
			"Regulatory Rules" },
	{ NL80211_ATTR_MESH_CONFIG,
			"Mesh Configuration" },
	{ NL80211_ATTR_BSS_BASIC_RATES,
			"BSS Basic Rates", ATTR_BINARY },
	{ NL80211_ATTR_WIPHY_TXQ_PARAMS,
			"Wiphy TXQ Parameters" },
	{ NL80211_ATTR_WIPHY_FREQ,
			"Wiphy Frequency", ATTR_U32 },
	{ NL80211_ATTR_WIPHY_CHANNEL_TYPE,
			"Wiphy Channel Type", ATTR_U32 },
	{ NL80211_ATTR_KEY_DEFAULT_MGMT,
			"Key Default Management", ATTR_FLAG },
	{ NL80211_ATTR_MGMT_SUBTYPE,
			"Management Subtype", ATTR_U8 },
	{ NL80211_ATTR_IE,
			"Information Elements", ATTR_CUSTOM,
					{ .function = print_management_ies } },
	{ NL80211_ATTR_MAX_NUM_SCAN_SSIDS,
			"Max Number Scan SSIDs", ATTR_U8 },
	{ NL80211_ATTR_SCAN_FREQUENCIES,
			"Scan Frequencies", ATTR_ARRAY,
						{ .array_type = ATTR_U32 } },
	{ NL80211_ATTR_SCAN_SSIDS,
			"Scan SSIDs", ATTR_ARRAY,
					{ .array_type = ATTR_BINARY } },
	{ NL80211_ATTR_GENERATION,
			"Generation", ATTR_U32 },
	{ NL80211_ATTR_BSS,
			"BSS", ATTR_NESTED, { bss_table } },
	{ NL80211_ATTR_REG_INITIATOR,
			"Regulatory Initiator" },
	{ NL80211_ATTR_REG_TYPE,
			"Regulatory Type" },
	{ NL80211_ATTR_SUPPORTED_COMMANDS,
			"Supported Commands", ATTR_CUSTOM,
				{ .function = print_supported_commands } },
	{ NL80211_ATTR_FRAME,
			"Frame", ATTR_CUSTOM, { .function = print_frame } },
	{ NL80211_ATTR_SSID,
			"SSID", ATTR_BINARY },
	{ NL80211_ATTR_AUTH_TYPE,
			"Auth Type", ATTR_U32 },
	{ NL80211_ATTR_REASON_CODE,
			"Reason Code", ATTR_CUSTOM,
				{ .function = print_reason_code } },
	{ NL80211_ATTR_KEY_TYPE,
			"Key Type", ATTR_U32 },
	{ NL80211_ATTR_MAX_SCAN_IE_LEN,
			"Max Scan IE Length", ATTR_U16 },
	{ NL80211_ATTR_CIPHER_SUITES,
			"Cipher Suites", ATTR_CUSTOM,
					{ .function = print_cipher_suites } },
	{ NL80211_ATTR_FREQ_BEFORE,
			"Frequency Before" },
	{ NL80211_ATTR_FREQ_AFTER,
			"Frequency After" },
	{ NL80211_ATTR_FREQ_FIXED,
			"Frequency Fixed", ATTR_FLAG },
	{ NL80211_ATTR_WIPHY_RETRY_SHORT,
			"Wiphy Retry Short", ATTR_U8 },
	{ NL80211_ATTR_WIPHY_RETRY_LONG,
			"Wiphy Retry Long", ATTR_U8 },
	{ NL80211_ATTR_WIPHY_FRAG_THRESHOLD,
			"Wiphy Frag Threshold", ATTR_U32 },
	{ NL80211_ATTR_WIPHY_RTS_THRESHOLD,
			"Wiphy RTS Threshold", ATTR_U32 },
	{ NL80211_ATTR_TIMED_OUT,
			"Timed Out", ATTR_FLAG },
	{ NL80211_ATTR_USE_MFP,
			"Use MFP", ATTR_U32 },
	{ NL80211_ATTR_STA_FLAGS2,
			"Station Flags 2", ATTR_CUSTOM,
				{ .function = print_sta_flag_update } },
	{ NL80211_ATTR_CONTROL_PORT,
			"Control Port", ATTR_FLAG },
	{ NL80211_ATTR_TESTDATA,
			"Test Data" },
	{ NL80211_ATTR_PRIVACY,
			"Privacy", ATTR_FLAG },
	{ NL80211_ATTR_DISCONNECTED_BY_AP,
			"Disconnect by AP", ATTR_FLAG },
	{ NL80211_ATTR_STATUS_CODE,
			"Status Code", ATTR_U16 },
	{ NL80211_ATTR_CIPHER_SUITES_PAIRWISE,
			"Cipher Suites Pairwise", ATTR_CUSTOM,
					{ .function = print_cipher_suites } },
	{ NL80211_ATTR_CIPHER_SUITE_GROUP,
			"Cipher Suite Group", ATTR_CUSTOM,
					{ .function = print_cipher_suite } },
	{ NL80211_ATTR_WPA_VERSIONS,
			"WPA Versions", ATTR_U32 },
	{ NL80211_ATTR_AKM_SUITES,
			"AKM Suites", ATTR_CUSTOM,
					{ .function = print_akm_suites } },
	{ NL80211_ATTR_REQ_IE,
			"Request IE", ATTR_CUSTOM,
					{ .function = print_management_ies } },
	{ NL80211_ATTR_RESP_IE,
			"Response IE", ATTR_CUSTOM,
					{.function = print_management_ies } },
	{ NL80211_ATTR_PREV_BSSID,
			"Previous BSSID", ATTR_ADDRESS },
	{ NL80211_ATTR_KEY,
			"Key" },
	{ NL80211_ATTR_KEYS,
			"Keys" },
	{ NL80211_ATTR_PID,
			"PID", ATTR_U32 },
	{ NL80211_ATTR_4ADDR,
			"4-Address", ATTR_U8 },
	{ NL80211_ATTR_SURVEY_INFO,
			"Survey Info" },
	{ NL80211_ATTR_PMKID,
			"PMKID", ATTR_BINARY },
	{ NL80211_ATTR_MAX_NUM_PMKIDS,
			"Max Number PMKIDs", ATTR_U8 },
	{ NL80211_ATTR_DURATION,
			"Duration", ATTR_U32 },
	{ NL80211_ATTR_COOKIE,
			"Cookie", ATTR_U64 },
	{ NL80211_ATTR_WIPHY_COVERAGE_CLASS,
			"Wiphy Coverage Class", ATTR_U8	},
	{ NL80211_ATTR_TX_RATES,
			"TX Rates" },
	{ NL80211_ATTR_FRAME_MATCH,
			"Frame Match", ATTR_BINARY },
	{ NL80211_ATTR_ACK,
			"ACK", ATTR_FLAG },
	{ NL80211_ATTR_PS_STATE,
			"PS State", ATTR_U32 },
	{ NL80211_ATTR_CQM,
			"CQM", ATTR_NESTED, { cqm_table } },
	{ NL80211_ATTR_LOCAL_STATE_CHANGE,
			"Local State Change", ATTR_FLAG },
	{ NL80211_ATTR_AP_ISOLATE,
			"AP Isolate", ATTR_U8 },
	{ NL80211_ATTR_WIPHY_TX_POWER_SETTING,
			"Wiphy TX Power Setting", ATTR_U32 },
	{ NL80211_ATTR_WIPHY_TX_POWER_LEVEL,
			"Wiphy TX Power Level", ATTR_U32 },
	{ NL80211_ATTR_TX_FRAME_TYPES,
			"TX Frame Types", ATTR_NESTED,
						{ frame_types_table } },
	{ NL80211_ATTR_RX_FRAME_TYPES,
			"RX Frame Types", ATTR_NESTED,
						{ frame_types_table } },
	{ NL80211_ATTR_FRAME_TYPE,
			"Frame Type", ATTR_CUSTOM,
					{ .function = print_frame_type } },
	{ NL80211_ATTR_CONTROL_PORT_ETHERTYPE,
			"Control Port Ethertype", ATTR_FLAG_OR_U16 },
	{ NL80211_ATTR_CONTROL_PORT_NO_ENCRYPT,
			"Control Port No Encrypt", ATTR_FLAG },
	{ NL80211_ATTR_SUPPORT_IBSS_RSN,
			"Support IBSS RSN", ATTR_FLAG },
	{ NL80211_ATTR_WIPHY_ANTENNA_TX,
			"Wiphy Antenna TX", ATTR_U32 },
	{ NL80211_ATTR_WIPHY_ANTENNA_RX,
			"Wiphy Antenna RX", ATTR_U32 },
	{ NL80211_ATTR_MCAST_RATE,
			"Multicast Rate", ATTR_U32 },
	{ NL80211_ATTR_OFFCHANNEL_TX_OK,
			"Offchannel TX OK", ATTR_FLAG },
	{ NL80211_ATTR_BSS_HT_OPMODE,
			"BSS HT Operation Mode", ATTR_U16 },
	{ NL80211_ATTR_KEY_DEFAULT_TYPES,
			"Key Default Types", ATTR_NESTED,
						{ key_default_type_table } },
	{ NL80211_ATTR_MAX_REMAIN_ON_CHANNEL_DURATION,
			"Max Remain on Channel Duration ", ATTR_U32 },
	{ NL80211_ATTR_MESH_SETUP,
			"Mesh Setup" },
	{ NL80211_ATTR_WIPHY_ANTENNA_AVAIL_TX,
			"Wiphy Antenna Avail TX" },
	{ NL80211_ATTR_WIPHY_ANTENNA_AVAIL_RX,
			"Wiphy Antenna Avail RX" },
	{ NL80211_ATTR_SUPPORT_MESH_AUTH,
			"Support Mesh Auth", ATTR_FLAG },
	{ NL80211_ATTR_STA_PLINK_STATE,
			"Station P-Link State" },
	{ NL80211_ATTR_WOWLAN_TRIGGERS,
			"WoWLAN Triggers" },
	{ NL80211_ATTR_WOWLAN_TRIGGERS_SUPPORTED,
			"WoWLAN Triggers Supported" },
	{ NL80211_ATTR_SCHED_SCAN_INTERVAL,
			"Scheduled Scan Interval", ATTR_U32 },
	{ NL80211_ATTR_INTERFACE_COMBINATIONS,
			"Interface Combinations" },
	{ NL80211_ATTR_SOFTWARE_IFTYPES,
			"Software Interface Types", ATTR_NESTED,
							{ iftype_table } },
	{ NL80211_ATTR_REKEY_DATA,
			"Rekey Data", ATTR_NESTED, { rekey_table } },
	{ NL80211_ATTR_MAX_NUM_SCHED_SCAN_SSIDS,
			"Max Num Sched Scan SSIDs", ATTR_U8 },
	{ NL80211_ATTR_MAX_SCHED_SCAN_IE_LEN,
			"Max Sched Scan IE Len", ATTR_U16 },
	{ NL80211_ATTR_SCAN_SUPP_RATES,
			"Scan Supported Rates" },
	{ NL80211_ATTR_HIDDEN_SSID,
			"Hidden SSID", ATTR_U32 },
	{ NL80211_ATTR_IE_PROBE_RESP,
			"IE Probe Response", ATTR_CUSTOM,
					{ .function = print_management_ies } },
	{ NL80211_ATTR_IE_ASSOC_RESP,
			"IE Assoc Response", ATTR_CUSTOM,
					{ .function = print_management_ies } },
	{ NL80211_ATTR_STA_WME,
			"Station WME" },
	{ NL80211_ATTR_SUPPORT_AP_UAPSD,
			"Support AP UAPSD", ATTR_FLAG },
	{ NL80211_ATTR_ROAM_SUPPORT,
			"Roaming Support", ATTR_FLAG },
	{ NL80211_ATTR_SCHED_SCAN_MATCH,
			"Scheduled Scan Match" },
	{ NL80211_ATTR_MAX_MATCH_SETS,
			"Max Match Sets", ATTR_U8 },
	{ NL80211_ATTR_PMKSA_CANDIDATE,
			"PMKSA Candidate" },
	{ NL80211_ATTR_TX_NO_CCK_RATE,
			"TX No CCK Rate", ATTR_FLAG },
	{ NL80211_ATTR_TDLS_ACTION,
			"TDLS Action", ATTR_U8 },
	{ NL80211_ATTR_TDLS_DIALOG_TOKEN,
			"TDLS Dialog Token", ATTR_U8 },
	{ NL80211_ATTR_TDLS_OPERATION,
			"TDLS Operation", ATTR_U8 },
	{ NL80211_ATTR_TDLS_SUPPORT,
			"TDLS Support", ATTR_FLAG },
	{ NL80211_ATTR_TDLS_EXTERNAL_SETUP,
			"TDLS External Setup", ATTR_FLAG },
	{ NL80211_ATTR_DEVICE_AP_SME,
			"Device AP SME" },
	{ NL80211_ATTR_DONT_WAIT_FOR_ACK,
			"Don't Wait for Ack", ATTR_FLAG },
	{ NL80211_ATTR_FEATURE_FLAGS,
			"Feature Flags" },
	{ NL80211_ATTR_PROBE_RESP_OFFLOAD,
			"Probe Response Offload" },
	{ NL80211_ATTR_PROBE_RESP,
			"Probe Response" },
	{ NL80211_ATTR_DFS_REGION,
			"DFS Region", ATTR_U8 },
	{ NL80211_ATTR_DISABLE_HT,
			"Disable HT", ATTR_FLAG },
	{ NL80211_ATTR_HT_CAPABILITY_MASK,
			"HT Capability Mask" },
	{ NL80211_ATTR_NOACK_MAP,
			"No-Ack Map", ATTR_U16 },
	{ NL80211_ATTR_INACTIVITY_TIMEOUT,
			"Inactivity Timeout", ATTR_U16 },
	{ NL80211_ATTR_RX_SIGNAL_DBM,
			"RX Signal dBm", ATTR_S32 },
	{ NL80211_ATTR_BG_SCAN_PERIOD,
			"Background Scan Period", ATTR_U16 },
	{ NL80211_ATTR_WDEV,
			"Wireless Device", ATTR_U64 },
	{ NL80211_ATTR_USER_REG_HINT_TYPE,
			"User Regulatroy Hint Type", ATTR_U32 },
	{ NL80211_ATTR_CONN_FAILED_REASON,
			"Connection Failed Reason" },
	{ NL80211_ATTR_SAE_DATA,
			"SAE Data" },
	{ NL80211_ATTR_VHT_CAPABILITY,
			"VHT Capability" },
	{ NL80211_ATTR_SCAN_FLAGS,
			"Scan Flags", ATTR_U32 },
	{ NL80211_ATTR_CHANNEL_WIDTH,
			"Channel Width", ATTR_U32 },
	{ NL80211_ATTR_CENTER_FREQ1,
			"Center Frequency 1", ATTR_U32 },
	{ NL80211_ATTR_CENTER_FREQ2,
			"Center Frequency 2", ATTR_U32 },
	{ NL80211_ATTR_P2P_CTWINDOW,
			"P2P CT Window", ATTR_U8 },
	{ NL80211_ATTR_P2P_OPPPS,
			"P2P OP PPS", ATTR_U8 },
	{ NL80211_ATTR_LOCAL_MESH_POWER_MODE,
			"Local Mesh Power Mode" },
	{ NL80211_ATTR_ACL_POLICY,
			"ACL Policy", ATTR_U32 },
	{ NL80211_ATTR_MAC_ADDRS,
			"MAC Addresses" },
	{ NL80211_ATTR_MAC_ACL_MAX,
			"MAC ACL Max" },
	{ NL80211_ATTR_RADAR_EVENT,
			"Radar Event" },
	{ NL80211_ATTR_EXT_CAPA,
			"Extended Capabilities", ATTR_CUSTOM,
			{ .function = print_ie_extended_capabilities } },
	{ NL80211_ATTR_EXT_CAPA_MASK,
			"Extended Capabilities Mask" },
	{ NL80211_ATTR_STA_CAPABILITY,
			"Station Capability", ATTR_U16 },
	{ NL80211_ATTR_STA_EXT_CAPABILITY,
			"Station Extended Capability" },
	{ NL80211_ATTR_PROTOCOL_FEATURES,
			"Protocol Features", ATTR_U32 },
	{ NL80211_ATTR_SPLIT_WIPHY_DUMP,
			"Split Wiphy Dump", ATTR_FLAG},
	{ NL80211_ATTR_DISABLE_VHT,
			"Disable VHT" },
	{ NL80211_ATTR_VHT_CAPABILITY_MASK,
			"VHT Capability Mask" },
	{ NL80211_ATTR_MDID,
			"MDID", ATTR_U16 },
	{ NL80211_ATTR_IE_RIC,
			"IE RIC", ATTR_BINARY },
	{ NL80211_ATTR_CRIT_PROT_ID,
			"Critical Protocol ID" },
	{ NL80211_ATTR_MAX_CRIT_PROT_DURATION,
			"Max Critical Protocol Duration" },
	{ NL80211_ATTR_PEER_AID,
			"Peer AID", ATTR_U16 },
	{ NL80211_ATTR_COALESCE_RULE,
			"Coalesce Rule" },
	{ NL80211_ATTR_CH_SWITCH_COUNT,
			"Channel Switch Count", ATTR_U32 },
	{ NL80211_ATTR_CH_SWITCH_BLOCK_TX,
			"Channel Switch Block TX", ATTR_FLAG },
	{ NL80211_ATTR_CSA_IES,
			"CSA IEs" },
	{ NL80211_ATTR_CSA_C_OFF_BEACON,
			"CSA C Off Beacon" },
	{ NL80211_ATTR_CSA_C_OFF_PRESP,
			"CSA C Off Response" },
	{ NL80211_ATTR_RXMGMT_FLAGS,
			"RX Management Flags", ATTR_U32 },
	{ NL80211_ATTR_STA_SUPPORTED_CHANNELS,
			"Station Supported Channels" },
	{ NL80211_ATTR_STA_SUPPORTED_OPER_CLASSES,
			"Station Supported Operation Classes" },
	{ NL80211_ATTR_HANDLE_DFS,
			"Handle DFS", ATTR_FLAG },
	{ NL80211_ATTR_SUPPORT_5_MHZ,
			"Support 5 MHz" },
	{ NL80211_ATTR_SUPPORT_10_MHZ,
			"Support 10 MHz" },
	{ NL80211_ATTR_OPMODE_NOTIF,
			"Operation Mode Notification", ATTR_U8 },
	{ NL80211_ATTR_VENDOR_ID,
			"Vendor ID", ATTR_U32 },
	{ NL80211_ATTR_VENDOR_SUBCMD,
			"Vendor Subcommand", ATTR_U32 },
	{ NL80211_ATTR_VENDOR_DATA,
			"Vendor Data", ATTR_BINARY },
	{ NL80211_ATTR_VENDOR_EVENTS,
			"Vendor Events" },
	{ NL80211_ATTR_QOS_MAP,
			"QoS Map", ATTR_BINARY },
	{ NL80211_ATTR_MAC_HINT,
			"MAC Hint", ATTR_ADDRESS },
	{ NL80211_ATTR_WIPHY_FREQ_HINT,
			"Wiphy Frequency Hint", ATTR_U32 },
	{ NL80211_ATTR_MAX_AP_ASSOC_STA,
			"Max AP Assoc Station" },
	{ NL80211_ATTR_TDLS_PEER_CAPABILITY,
			"TDLS Peer Capability", ATTR_U32 },
	{ NL80211_ATTR_IFACE_SOCKET_OWNER,
			"Interface Socket Owner", ATTR_FLAG },
	{ NL80211_ATTR_CSA_C_OFFSETS_TX,
			"CSA C Offsets TX" },
	{ NL80211_ATTR_MAX_CSA_COUNTERS,
			"Max CSA Counters" },
	{ }
};

static void print_value(int indent, const char *label, enum attr_type type,
						const void *buf, uint32_t len)
{
	uint16_t val_u16;
	uint32_t val_u32;

	switch (type) {
	case ATTR_U16:
		val_u16 = *((uint16_t *) buf);
		print_attr(indent, "%s: %u (0x%04x)", label, val_u16, val_u16);
		if (len != 2)
			printf("malformed packet\n");
		break;
	case ATTR_U32:
		val_u32 = *((uint32_t *) buf);
		print_attr(indent, "%s: %u (0x%08x)", label, val_u32, val_u32);
		if (len != 4)
			printf("malformed packet\n");
		break;
	default:
		print_attr(indent, "%s: len %u", label, len);
		print_hexdump(indent  + 1, buf, len);
		break;
	}
}

static void print_array(int indent, enum attr_type type,
						const void *buf, uint32_t len)
{
	const struct nlattr *nla;

	for (nla = buf ; NLA_OK(nla, len); nla = NLA_NEXT(nla, len)) {
		uint16_t nla_type = nla->nla_type & NLA_TYPE_MASK;
		char str[8];

		snprintf(str, sizeof(str), "%u", nla_type);
		print_value(indent, str, type,
				NLA_DATA(nla), NLA_PAYLOAD(nla));
	}
}

static void print_attributes(int indent, const struct attr_entry *table,
						const void *buf, uint32_t len)
{
	const struct nlattr *nla;
	const char *str;
	int i;

	for (nla = buf ; NLA_OK(nla, len); nla = NLA_NEXT(nla, len)) {
		uint16_t nla_type = nla->nla_type & NLA_TYPE_MASK;
		enum attr_type type;
		enum attr_type array_type;
		const struct attr_entry *nested;
		attr_func_t function;
		uint64_t val64;
		uint32_t val32;
		uint16_t val16;
		uint8_t val8;
		int8_t val_s8;
		int32_t val_s32;
		int64_t val_s64;
		uint8_t *ptr;

		str = "Reserved";
		type = ATTR_UNSPEC;
		array_type = ATTR_UNSPEC;
		nested = NULL;

		if (table) {
			for (i = 0; table[i].str; i++) {
				if (nla_type == table[i].attr) {
					str = table[i].str;
					type = table[i].type;
					nested = table[i].nested;
					array_type = table[i].array_type;
					function = table[i].function;
					break;
				}
			}
		}

		switch (type) {
		case ATTR_UNSPEC:
			print_attr(indent, "%s: len %u", str,
						NLA_PAYLOAD(nla));
			print_hexdump(indent + 1,
					NLA_DATA(nla), NLA_PAYLOAD(nla));
			break;
		case ATTR_FLAG:
			print_attr(indent, "%s: true", str);
			if (NLA_PAYLOAD(nla) != 0)
				printf("malformed packet\n");
			break;
		case ATTR_U8:
			val8 = *((uint8_t *) NLA_DATA(nla));
			print_attr(indent, "%s: %"PRIu8" (0x%02"PRIx8")",
							str, val8, val8);
			if (NLA_PAYLOAD(nla) != 1)
				printf("malformed packet\n");
			break;
		case ATTR_U16:
			val16 = *((uint16_t *) NLA_DATA(nla));
			print_attr(indent, "%s: %"PRIu16" (0x%04"PRIx16")",
							str, val16, val16);
			if (NLA_PAYLOAD(nla) != 2)
				printf("malformed packet\n");
			break;
		case ATTR_U32:
			val32 = *((uint32_t *) NLA_DATA(nla));
			print_attr(indent, "%s: %"PRIu32" (0x%08"PRIx32")",
							str, val32, val32);
			if (NLA_PAYLOAD(nla) != 4)
				printf("malformed packet\n");
			break;
		case ATTR_U64:
			val64 = *((uint64_t *) NLA_DATA(nla));
			print_attr(indent, "%s: %"PRIu64" (0x%016"PRIx64")",
							str, val64, val64);
			if (NLA_PAYLOAD(nla) != 8)
				printf("malformed packet\n");
			break;
		case ATTR_S8:
			val_s8 = *((int8_t *) NLA_DATA(nla));
			print_attr(indent, "%s: %"PRId8, str, val_s8);
			if (NLA_PAYLOAD(nla) != 1)
				printf("malformed packet\n");
			break;
		case ATTR_S32:
			val_s32 = *((int32_t *) NLA_DATA(nla));
			print_attr(indent, "%s: %"PRId32, str, val_s32);
			if (NLA_PAYLOAD(nla) != 4)
				printf("malformed packet\n");
			break;
		case ATTR_S64:
			val_s64 = *((int64_t *) NLA_DATA(nla));
			print_attr(indent, "%s: %"PRId64, str, val_s64);
			if (NLA_PAYLOAD(nla) != 4)
				printf("malformed packet\n");
			break;
		case ATTR_STRING:
			print_attr(indent, "%s: %s", str,
						(char *) NLA_DATA(nla));
			break;
		case ATTR_ADDRESS:
			ptr = NLA_DATA(nla);
			print_address(indent, str, ptr);
			if (NLA_PAYLOAD(nla) != 6)
				printf("malformed packet\n");
			break;
		case ATTR_BINARY:
			print_attr(indent, "%s: len %u", str,
						NLA_PAYLOAD(nla));
			print_hexdump(indent + 1,
					NLA_DATA(nla), NLA_PAYLOAD(nla));
			break;
		case ATTR_NESTED:
			print_attr(indent, "%s: len %u", str,
						NLA_PAYLOAD(nla));
			if (!nested)
				printf("missing table\n");
			print_attributes(indent + 1, nested,
					NLA_DATA(nla), NLA_PAYLOAD(nla));
			break;
		case ATTR_ARRAY:
			print_attr(indent, "%s: len %u", str,
						NLA_PAYLOAD(nla));
			if (array_type == ATTR_UNSPEC)
				printf("missing type\n");
			print_array(indent + 1, array_type,
					NLA_DATA(nla), NLA_PAYLOAD(nla));
			break;
		case ATTR_FLAG_OR_U16:
			if (NLA_PAYLOAD(nla) == 0)
				print_attr(indent, "%s: true", str);
			else if (NLA_PAYLOAD(nla) == 2) {
				val16 = *((uint16_t *) NLA_DATA(nla));
				print_attr(indent,
					"%s: %"PRIu16" (0x%04"PRIx16")",
					str, val16, val16);
			} else
				printf("malformed packet\n");
			break;
		case ATTR_CUSTOM:
			if (function)
				function(indent, str, NLA_DATA(nla),
							NLA_PAYLOAD(nla));
			else
				printf("missing function\n");
			break;
		}
	}
}

static void print_eapol_key(const void *data, uint32_t size)
{
	const struct eapol_key *ek = eapol_key_validate(data, size);

	if (!ek)
		return;

	print_attr(1, "Descriptor Type: %u", ek->descriptor_type);
	print_attr(1, "Key MIC: %s", ek->key_mic ? "true" : "false");
	print_attr(1, "Secure: %s", ek->secure ? "true" : "false");
	print_attr(1, "Error: %s", ek->error ? "true" : "false");
	print_attr(1, "Request: %s", ek->request ? "true" : "false");
	print_attr(1, "Encrypted Key Data: %s",
				ek->encrypted_key_data ? "true" : "false");
	print_attr(1, "SMK Message: %s", ek->smk_message ? "true" : "false");
	print_attr(1, "Key Descriptor Version: %d (%02x)",
						ek->key_descriptor_version,
						ek->key_descriptor_version);
	print_attr(1, "Key Type: %s", ek->key_type ? "true" : "false");

	if (ek->descriptor_type == EAPOL_DESCRIPTOR_TYPE_WPA)
		print_attr(1, "Key Id: %u", ek->wpa_key_id);

	print_attr(1, "Install: %s", ek->install ? "true" : "false");
	print_attr(1, "Key ACK: %s", ek->key_ack ? "true" : "false");
	print_attr(1, "Key Length: %d", L_BE16_TO_CPU(ek->key_length));
	print_attr(1, "Key Replay Counter: %" PRIu64,
					L_BE64_TO_CPU(ek->key_replay_counter));
	print_attr(1, "Key NONCE");
	print_hexdump(2, ek->key_nonce, 32);
	print_attr(1, "Key IV");
	print_hexdump(2, ek->eapol_key_iv, 16);
	print_attr(1, "Key RSC ");
	print_hexdump(2, ek->key_rsc, 8);
	print_attr(1, "Key MIC Data");
	print_hexdump(2, ek->key_mic_data, 16);

	if (ek->encrypted_key_data) {
		print_attr(1, "Key Data: len %d",
					L_BE16_TO_CPU(ek->key_data_len));
		print_hexdump(2, ek->key_data, L_BE16_TO_CPU(ek->key_data_len));
		return;
	}

	print_ie(1, "Key Data", ek->key_data, L_BE16_TO_CPU(ek->key_data_len));
}

static void netlink_str(char *str, size_t size,
				uint16_t type, uint16_t flags, uint32_t len)
{
	int pos;
	bool get_req = false, new_req = false;

	pos = sprintf(str, "(0x%02x) len %u", type, len);

	switch (type) {
	case RTM_GETLINK:
	case RTM_GETADDR:
	case RTM_GETROUTE:
		get_req = true;
		break;

	case RTM_NEWLINK:
	case RTM_NEWADDR:
	case RTM_NEWROUTE:
		new_req = true;
		break;
	}

	if (flags) {
		pos += sprintf(str + pos, " [");

		if (flags & NLM_F_REQUEST) {
			flags &= ~NLM_F_REQUEST;
			pos += sprintf(str + pos, "request%c",
							flags ? ',' : ']');
		}

		if (flags & NLM_F_MULTI) {
			flags &= ~NLM_F_MULTI;
			pos += sprintf(str + pos, "multi%c", flags ? ',' : ']');
		}

		if (flags & NLM_F_ACK) {
			flags &= ~NLM_F_ACK;
			pos += sprintf(str + pos, "ack%c", flags ? ',' : ']');
		}

		if (flags & NLM_F_ECHO) {
			flags &= ~NLM_F_ECHO;
			pos += sprintf(str + pos, "echo%c", flags ? ',' : ']');
		}

		if (get_req && (flags & NLM_F_DUMP) == NLM_F_DUMP) {
			flags &= ~NLM_F_DUMP;
			pos += sprintf(str + pos, "dump%c", flags ? ',' : ']');
		}

		if (get_req && flags & NLM_F_ROOT) {
			flags &= ~NLM_F_ROOT;
			pos += sprintf(str + pos, "root%c", flags ? ',' : ']');
		}

		if (get_req && flags & NLM_F_MATCH) {
			flags &= ~NLM_F_MATCH;
			pos += sprintf(str + pos, "match%c", flags ? ',' : ']');
		}

		if (get_req && flags & NLM_F_ATOMIC) {
			flags &= ~NLM_F_ATOMIC;
			pos += sprintf(str + pos, "atomic%c",
							flags ? ',' : ']');
		}

		if (new_req && flags & NLM_F_REPLACE) {
			flags &= ~NLM_F_REPLACE;
			pos += sprintf(str + pos, "replace%c",
							flags ? ',' : ']');
		}

		if (new_req && flags & NLM_F_EXCL) {
			flags &= ~NLM_F_EXCL;
			pos += sprintf(str + pos, "excl%c", flags ? ',' : ']');
		}

		if (new_req && flags & NLM_F_CREATE) {
			flags &= ~NLM_F_CREATE;
			pos += sprintf(str + pos, "create%c",
							flags ? ',' : ']');
		}

		if (new_req && flags & NLM_F_APPEND) {
			flags &= ~NLM_F_APPEND;
			pos += sprintf(str + pos, "append%c",
							flags ? ',' : ']');
		}

		if (flags)
			pos += sprintf(str + pos, "0x%x]", flags);
	}
}

static void print_message(struct nlmon *nlmon, const struct timeval *tv,
						enum msg_type type,
						uint16_t flags, int status,
						uint8_t cmd, uint8_t version,
						const void *data, uint32_t len)
{
	char extra_str[64];
	const char *label = "";
	const char *color = COLOR_OFF;
	const char *cmd_str;
	bool out = false;
	int i;

	if (nlmon->nowiphy && (cmd == NL80211_CMD_NEW_WIPHY))
		return;

	if (nlmon->noscan && ((cmd == NL80211_CMD_NEW_SCAN_RESULTS) ||
			(cmd == NL80211_CMD_TRIGGER_SCAN)))
		return;

	switch (type) {
	case MSG_REQUEST:
		label = "Request";
		color = COLOR_REQUEST;
		out = true;
		break;
	case MSG_RESPONSE:
		label = "Response";
		color = COLOR_RESPONSE;
		break;
	case MSG_COMPLETE:
		label = "Complete";
		color = COLOR_COMPLETE;
		break;
	case MSG_RESULT:
		label = "Result";
		color = COLOR_RESULT;
		break;
	case MSG_EVENT:
		label = "Event";
		color = COLOR_EVENT;
		break;
	}

	cmd_str = "Reserved";

	for (i = 0; cmd_table[i].str; i++) {
		if (cmd_table[i].cmd == cmd) {
			cmd_str = cmd_table[i].str;
			break;
		}
	}

	netlink_str(extra_str, sizeof(extra_str), cmd, flags, len);

	print_packet(tv, out ? '<' : '>', color, label, cmd_str, extra_str);

	switch (type) {
	case MSG_REQUEST:
	case MSG_RESULT:
	case MSG_EVENT:
		print_attributes(0, attr_table, data, len);
		break;
	case MSG_RESPONSE:
		print_field("Status: %s (%d)", strerror(status), status);
		break;
	case MSG_COMPLETE:
		if (status < 0)
			print_field("Status: %s (%d)",
					strerror(-status), -status);
		else
			print_field("Status: %d", status);
		break;
	}
}

struct nlmon_req_match {
	uint32_t seq;
	uint32_t pid;
};

static bool nlmon_req_match(const void *a, const void *b)
{
	const struct nlmon_req *req = a;
	const struct nlmon_req_match *match = b;

	return (req->seq == match->seq && req->pid == match->pid);
}

static void store_packet(struct nlmon *nlmon, const struct timeval *tv,
					uint16_t pkt_type,
					uint16_t arphrd_type,
					uint16_t proto_type,
					const void *data, uint32_t size)
{
	uint8_t sll_hdr[16], *buf = sll_hdr;

	if (!nlmon->pcap)
		return;

	memset(sll_hdr, 0, sizeof(sll_hdr));

	l_put_be16(pkt_type, buf);
	l_put_be16(arphrd_type, buf + 2);
	l_put_be16(proto_type, buf + 14);

	pcap_write(nlmon->pcap, tv, &sll_hdr, sizeof(sll_hdr), data, size);
}

static void store_netlink(struct nlmon *nlmon, const struct timeval *tv,
					uint16_t proto_type,
					const struct nlmsghdr *nlmsg)
{
	store_packet(nlmon, tv, PACKET_HOST, ARPHRD_NETLINK, proto_type,
						nlmsg, nlmsg->nlmsg_len);
}

static void store_message(struct nlmon *nlmon, const struct timeval *tv,
					const struct nlmsghdr *nlmsg)
{
	store_netlink(nlmon, tv, NETLINK_GENERIC, nlmsg);
}

static void nlmon_message(struct nlmon *nlmon, const struct timeval *tv,
					const struct tpacket_auxdata *tp,
					const struct nlmsghdr *nlmsg)
{
	struct nlmon_req *req;

	if (nlmsg->nlmsg_type < NLMSG_MIN_TYPE) {
		struct nlmon_req_match match = {
			.seq = nlmsg->nlmsg_seq,
			.pid = nlmsg->nlmsg_pid
		};

		req = l_queue_remove_if(nlmon->req_list,
						nlmon_req_match, &match);
		if (req) {
			enum msg_type type;
			struct nlmsgerr *err;
			int status;

			switch (nlmsg->nlmsg_type) {
			case NLMSG_ERROR:
				type = MSG_RESPONSE;
				err = NLMSG_DATA(nlmsg);
				status = -err->error;
				break;
			case NLMSG_DONE:
				type = MSG_COMPLETE;
				status = *((int *) NLMSG_DATA(nlmsg));
				break;
			default:
				return;
			}

			store_message(nlmon, tv, nlmsg);
			print_message(nlmon, tv, type, nlmsg->nlmsg_flags, status,
						req->cmd, req->version,
						NULL, sizeof(status));
			nlmon_req_free(req);
		}
		return;
	}

	if (nlmsg->nlmsg_type != nlmon->id) {
		if (nlmsg->nlmsg_type == GENL_ID_CTRL)
			store_message(nlmon, tv, nlmsg);
		return;
	}

	if (nlmsg->nlmsg_flags & NLM_F_REQUEST) {
		const struct genlmsghdr *genlmsg = NLMSG_DATA(nlmsg);
		uint32_t flags = nlmsg->nlmsg_flags & ~NLM_F_REQUEST;

		req = l_new(struct nlmon_req, 1);

		req->seq = nlmsg->nlmsg_seq;
		req->pid = nlmsg->nlmsg_pid;
		req->flags = nlmsg->nlmsg_flags;
		req->cmd = genlmsg->cmd;
		req->version = genlmsg->version;

		l_queue_push_tail(nlmon->req_list, req);

		store_message(nlmon, tv, nlmsg);
		print_message(nlmon, tv, MSG_REQUEST, flags, 0,
					req->cmd, req->version,
					NLMSG_DATA(nlmsg) + GENL_HDRLEN,
					NLMSG_PAYLOAD(nlmsg, GENL_HDRLEN));
	} else {
		const struct genlmsghdr *genlmsg = NLMSG_DATA(nlmsg);
		enum msg_type type = MSG_EVENT;

		struct nlmon_req_match match = {
			.seq = nlmsg->nlmsg_seq,
			.pid = nlmsg->nlmsg_pid
		};

		req = l_queue_find(nlmon->req_list, nlmon_req_match, &match);
		if (req) {
			if (!(req->flags & NLM_F_ACK)) {
				l_queue_remove(nlmon->req_list, req);
				nlmon_req_free(req);
			}
			type = MSG_RESULT;
		}

		store_message(nlmon, tv, nlmsg);
		print_message(nlmon, tv, type, nlmsg->nlmsg_flags, 0,
					genlmsg->cmd, genlmsg->version,
					NLMSG_DATA(nlmsg) + GENL_HDRLEN,
					NLMSG_PAYLOAD(nlmsg, GENL_HDRLEN));
	}
}

struct nlmon *nlmon_create(uint16_t id)
{
	struct nlmon *nlmon;

	nlmon = l_new(struct nlmon, 1);

	nlmon->id = id;
	nlmon->req_list = l_queue_new();

	return nlmon;
}

void nlmon_destroy(struct nlmon *nlmon)
{
	if (!nlmon)
		return;

	l_queue_destroy(nlmon->req_list, nlmon_req_free);

	l_free(nlmon);
}

static void genl_ctrl(struct nlmon *nlmon, const void *data, uint32_t len)
{
	const struct genlmsghdr *genlmsg = data;
	const struct nlattr *nla;
	char name[GENL_NAMSIZ];
	uint16_t id = 0;

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

	if (id == 0)
		return;

	if (!strcmp(name, NL80211_GENL_NAME))
		nlmon->id = id;
}

static void print_ifi_addr(unsigned int indent, const char *str,
						const void *buf, uint16_t size)
{
	struct ether_addr eth;

	if (size != ETH_ALEN) {
		printf("malformed packet\n");
		return;
	}

	memcpy(&eth, buf, ETH_ALEN);
	print_attr(indent, "%s: %s", str, ether_ntoa(&eth));
}

static const char *oper_state_to_ascii(const uint8_t state)
{
	switch(state) {
	case IF_OPER_UNKNOWN:
		return "unknown";
	case IF_OPER_NOTPRESENT:
		return "not present";
	case IF_OPER_DOWN:
		return "down";
	case IF_OPER_LOWERLAYERDOWN:
		return "lower layer down";
	case IF_OPER_TESTING:
		return "testing";
	case IF_OPER_DORMANT:
		return "dormant";
	case IF_OPER_UP:
		return "up";
	}

	return NULL;
}

static void print_oper_state(unsigned int indent, const char *str,
						const void *buf, uint16_t size)
{
	uint8_t oper_state;

	if (size != 1) {
		printf("malformed packet\n");
		return;
	}

	oper_state = ((uint8_t *)buf)[0];

	print_attr(indent, "%s: %s (%d)", str,
		oper_state_to_ascii(oper_state), oper_state);
}

static const char *link_mode_to_ascii(const uint8_t mode)
{
	switch(mode) {
	case 0:
		return "kernel controlled";
	case 1:
		return "userspace controlled";
	}

	return NULL;
}

static void print_link_mode(unsigned int indent, const char *str,
						const void *buf, uint16_t size)
{
	uint8_t link_mode;

	if (size != 1) {
		printf("malformed packet\n");
		return;
	}

	link_mode = ((uint8_t *)buf)[0];

	print_attr(indent, "%s: %s (%d)", str,
		link_mode_to_ascii(link_mode), link_mode);
}

static struct attr_entry info_entry[] = {
	{ IFLA_ADDRESS,		"Interface Address", ATTR_CUSTOM,
					{ .function = print_ifi_addr } },
	{ IFLA_BROADCAST,	"Broadcast Address", ATTR_CUSTOM,
					{ .function = print_ifi_addr } },
	{ IFLA_IFNAME,		"IfName",	ATTR_STRING },
	{ IFLA_MASTER,		"Master",	ATTR_U32 },
	{ IFLA_MTU,		"MTU",		ATTR_U32 },
	{ IFLA_TXQLEN,		"Txqlen",	ATTR_U32 },
	{ IFLA_OPERSTATE,	"OperState",	ATTR_CUSTOM,
					{ .function = print_oper_state } },
	{ IFLA_LINKMODE,	"LinkMode",	ATTR_CUSTOM,
					{ .function = print_link_mode } },
	{ IFLA_LINK,		"Link",		ATTR_S32 },
	{ IFLA_QDISC,		"Qdisc",	ATTR_STRING },
	{ IFLA_STATS,		"Stats",	ATTR_BINARY },
	{ IFLA_MAP,		"Map",		ATTR_BINARY },
	{ IFLA_WIRELESS,	"Wireless",	ATTR_BINARY },
	{ IFLA_COST,		"Cost",		ATTR_BINARY },
	{ IFLA_PRIORITY,	"Priority",	ATTR_BINARY },
	{ IFLA_PROTINFO,	"ProtInfo",	ATTR_BINARY },
	{ IFLA_WEIGHT,		"Weight",	ATTR_BINARY },
	{ IFLA_NET_NS_PID,	"NetNSPid",	ATTR_BINARY },
	{ IFLA_IFALIAS,		"IFAlias",	ATTR_BINARY },
	{ },
};

static void print_inet_addr(unsigned int indent, const char *str,
						const void *buf, uint16_t size)
{
	struct in_addr addr;

	if (size != sizeof(struct in_addr))
		return;

	addr = *((struct in_addr *) buf);
	print_attr(indent, "%s: %s", str, inet_ntoa(addr));
}

static struct attr_entry addr_entry[] = {
	{ IFA_ADDRESS,		"Interface Address", ATTR_CUSTOM,
					{ .function = print_inet_addr } },
	{ IFA_LOCAL,		"Local Address", ATTR_CUSTOM,
					{ .function = print_inet_addr } },
	{ IFA_BROADCAST,	"Broadcast Address", ATTR_CUSTOM,
					{ .function = print_inet_addr } },
	{ IFA_ANYCAST,		"Anycast Address", ATTR_CUSTOM,
					{ .function = print_inet_addr } },
	{ IFA_LABEL,		"Label",	ATTR_STRING },
	{ IFA_CACHEINFO,	"CacheInfo",	ATTR_BINARY },
	{ },
};

static void print_rtnl_attributes(int indent, const struct attr_entry *table,
						struct rtattr *rt_attr, int len)
{
	struct rtattr *attr;

	if (!table || !rt_attr)
		return;

	for (attr = rt_attr; RTA_OK(attr, len); attr = RTA_NEXT(attr, len)) {
		uint16_t rta_type = attr->rta_type;
		enum attr_type type = ATTR_UNSPEC;
		attr_func_t function;
		uint64_t val64;
		uint32_t val32;
		uint16_t val16;
		uint8_t val8;
		int8_t val_s8;
		int32_t val_s32;
		int64_t val_s64;
		const char *str;
		int i, payload;

		str = "Reserved";

		for (i = 0; table[i].str; i++) {
			if (rta_type == table[i].attr) {
				str = table[i].str;
				type = table[i].type;
				function = table[i].function;
				break;
			}
		}

		payload = RTA_PAYLOAD(attr);

		switch (type) {
		case ATTR_CUSTOM:
			if (function)
				function(indent, str, RTA_DATA(attr), payload);
			else
				printf("missing function\n");
			break;
		case ATTR_STRING:
			print_attr(indent, "%s: %s", str,
						(char *) RTA_DATA(attr));
			break;
		case ATTR_U8:
			val8 = *((uint8_t *) RTA_DATA(attr));
			print_attr(indent, "%s: %"PRIu8" (0x%02"PRIx8")", str,
								val8, val8);
			if (payload != 1)
				printf("malformed packet\n");
			break;
		case ATTR_U16:
			val16 = *((uint16_t *) RTA_DATA(attr));
			print_attr(indent, "%s: %"PRIu16" (0x%04"PRIx16")", str,
								val16, val16);
			if (payload != 2)
				printf("malformed packet\n");
			break;
		case ATTR_U32:
			val32 = *((uint32_t *) RTA_DATA(attr));
			print_attr(indent, "%s: %"PRIu32" (0x%08"PRIx32")", str,
								val32, val32);
			if (payload != 4)
				printf("malformed packet\n");
			break;
		case ATTR_U64:
			val64 = *((uint64_t *) RTA_DATA(attr));
			print_attr(indent, "%s: %"PRIu64" (0x%016"PRIx64")",
							str, val64, val64);
			if (payload != 8)
				printf("malformed packet\n");
			break;
		case ATTR_S8:
			val_s8 = *((int8_t *) RTA_DATA(attr));
			print_attr(indent, "%s: %"PRId8, str, val_s8);
			if (payload != 1)
				printf("malformed packet\n");
			break;
		case ATTR_S32:
			val_s32 = *((int32_t *) RTA_DATA(attr));
			print_attr(indent, "%s: %"PRId32, str, val_s32);
			if (payload != 4)
				printf("malformed packet\n");
			break;
		case ATTR_S64:
			val_s64 = *((int64_t *) RTA_DATA(attr));
			print_attr(indent, "%s: %"PRId64, str, val_s64);
			if (payload != 8)
				printf("malformed packet\n");
			break;
		case ATTR_FLAG:
			print_attr(indent, "%s: true", str);
			if (payload != 0)
				printf("malformed packet\n");
			break;
		case ATTR_FLAG_OR_U16:
			if (payload == 0)
				print_attr(indent, "%s: true", str);
			else if (payload == 2) {
				val16 = *((uint16_t *) RTA_DATA(attr));
				print_attr(indent,
						"%s: %"PRIu16" (0x%04"PRIx16")",
							str, val16, val16);
			} else
				printf("malformed packet\n");
			break;
		case ATTR_BINARY:
			print_attr(indent, "%s: len %d", str, payload);
			print_hexdump(indent + 1, RTA_DATA(attr), payload);
			break;
		case ATTR_ADDRESS:
		case ATTR_NESTED:
		case ATTR_ARRAY:
		case ATTR_UNSPEC:
			print_attr(indent, "%s: len %d", str, payload);
			break;
		}
	}
}

static struct flag_names rtnl_flags[] = {
	{ IFF_UP, "up" },
	{ IFF_BROADCAST, "broadcast" },
	{ IFF_DEBUG, "debug" },
	{ IFF_LOOPBACK, "loopback" },
	{ IFF_POINTOPOINT, "pointopoint"},
	{ IFF_NOTRAILERS, "notrailers" },
	{ IFF_RUNNING, "running" },
	{ IFF_NOARP, "noarp" },
	{ IFF_PROMISC, "promisc" },
	{ IFF_ALLMULTI, "allmulti" },
	{ IFF_MASTER, "master" },
	{ IFF_SLAVE, "slave" },
	{ IFF_MULTICAST, "multicast" },
	{ IFF_PORTSEL, "portsel" },
	{ IFF_AUTOMEDIA, "automedia" },
	{ IFF_DYNAMIC, "dynamic" },
	{ },
};

static void ififlags_str(char *str, size_t size, uint16_t flags)
{
	int pos, i;

	pos = sprintf(str, "(0x%02x)", flags);
	if (!flags)
		return;

	pos += sprintf(str + pos, " [");

	for (i = 0; rtnl_flags[i].name; i++) {
		if (flags & rtnl_flags[i].flag) {
			flags &= ~rtnl_flags[i].flag;
			pos += sprintf(str + pos, "%s%s", rtnl_flags[i].name,
							flags ? "," : "");
		}
	}

	pos += sprintf(str + pos, "]");
}

static void print_ifinfomsg(const struct ifinfomsg *info)
{
	char str[256];

	if (!info)
		return;

	print_field("IFLA Family: %u", info->ifi_family);
	print_field("IFLA Type: %u", info->ifi_type);
	print_field("IFLA Index: %d", info->ifi_index);
	print_field("IFLA ChangeMask: %u", info->ifi_change);
	ififlags_str(str, sizeof(str), info->ifi_flags);
	print_field("IFLA Flags: %s", str);
}

static void print_ifaddrmsg(const struct ifaddrmsg *addr)
{
	if (!addr)
		return;

	print_field("IFA Family: %u", addr->ifa_family);
	print_field("IFA Prefixlen: %u", addr->ifa_prefixlen);
	print_field("IFA Index: %d", addr->ifa_index);
	print_field("IFA Scope: %u", addr->ifa_scope);
	print_field("IFA Flags: %u", addr->ifa_flags);
}

static void read_uevent(const char *ifname, int index)
{
	char filename[64], line[128];
	FILE *f;

	snprintf(filename, sizeof(filename), "/sys/class/net/%s/uevent",
								ifname);
	f = fopen(filename, "re");
	if (!f) {
		printf("%s do not exist\n", filename);
		return;
	}

	while (fgets(line, sizeof(line), f)) {
		char *pos;

		pos = strchr(line, '\n');
		if (!pos)
			continue;
		pos[0] = '\0';

		if (strncmp(line, "DEVTYPE=", 8) != 0)
			continue;

		if (strcmp(line + 8, "wlan") == 0) {
			struct wlan_iface *iface;

			iface = l_new(struct wlan_iface, 1);
			iface->index = index;

			if (!l_hashmap_insert(wlan_iface_list,
					L_INT_TO_PTR(index), iface))
				l_free(iface);
		}
	}

	fclose(f);
}

static char *rtnl_get_ifname(const struct ifinfomsg *ifi, int len)
{
	struct rtattr *attr;
	char *ifname = NULL;

	if (!ifi)
		return NULL;

	for (attr = IFLA_RTA(ifi); RTA_OK(attr, len);
					attr = RTA_NEXT(attr, len))
		if (attr->rta_type == IFLA_IFNAME)
			ifname = (char *) RTA_DATA(attr);

	return ifname;
}

static void print_rtm_link(uint16_t type, const struct ifinfomsg *info, int len)
{
	struct wlan_iface *iface;
	char *ifname;

	if (!info || len <= 0)
		return;

	if (type == RTM_NEWLINK) {
		ifname = rtnl_get_ifname(info, len);
		if (!ifname)
			return;

		read_uevent(ifname, info->ifi_index);
	}

	iface = l_hashmap_lookup(wlan_iface_list,
						L_INT_TO_PTR(info->ifi_index));
	if (!iface)
		return;

	print_ifinfomsg(info);
	print_rtnl_attributes(1, info_entry, IFLA_RTA(info), len);

	if (type == RTM_DELLINK) {
		iface = l_hashmap_remove(wlan_iface_list,
						L_INT_TO_PTR(info->ifi_index));
		if (!iface)
			return;

		l_free(iface);
	}
}

static const char *nlmsg_type_to_str(uint32_t msg_type)
{
	const char *str = NULL;

	switch (msg_type) {
	case NLMSG_NOOP:
		str = "Noop";
		break;
	case NLMSG_ERROR:
		str = "Error";
		break;
	case NLMSG_DONE:
		str = "Done";
		break;
	case NLMSG_OVERRUN:
		str = "Overrun";
		break;
	case RTM_NEWLINK:
		str = "New Link";
		break;
	case RTM_DELLINK:
		str = "Delete Link";
		break;
	case RTM_GETLINK:
		str = "Get Link";
		break;
	case RTM_SETLINK:
		str = "Set Link";
		break;
	case RTM_NEWADDR:
		str = "New Address";
		break;
	case RTM_DELADDR:
		str = "Delete Address";
		break;
	case RTM_GETADDR:
		str = "Get Address";
		break;
	case RTM_NEWROUTE:
		str = "New Route";
		break;
	case RTM_DELROUTE:
		str = "Delete Route";
		break;
	case RTM_GETROUTE:
		str = "Get Route";
		break;
	default:
		str = "Reserved";
		break;
	}

	return str;
}

static void print_nlmsghdr(const struct timeval *tv,
						const struct nlmsghdr *nlmsg)
{
	char extra_str[256];
	const char *str;
	bool out;

	str = nlmsg_type_to_str(nlmsg->nlmsg_type);
	out = !!(nlmsg->nlmsg_flags & NLM_F_REQUEST);

	netlink_str(extra_str, sizeof(extra_str), nlmsg->nlmsg_type,
				nlmsg->nlmsg_flags, NLMSG_PAYLOAD(nlmsg, 0));

	print_packet(tv, out ? '<' : '>', COLOR_YELLOW, "RTNL", str, extra_str);

	print_field("Flags: %d (0x%03x)", nlmsg->nlmsg_flags,
							nlmsg->nlmsg_flags);
	print_field("Sequence number: %d (0x%08x)",
					nlmsg->nlmsg_seq, nlmsg->nlmsg_seq);
	print_field("Port ID: %d", nlmsg->nlmsg_pid);
}

static void print_nlmsg(const struct timeval *tv, const struct nlmsghdr *nlmsg)
{
	struct nlmsgerr *err;
	int status;

	print_nlmsghdr(tv, nlmsg);

	switch (nlmsg->nlmsg_type) {
	case NLMSG_ERROR:
		err = NLMSG_DATA(nlmsg);
		status = -err->error;
		if (status < 0)
			print_field("Error: %d (%s)", status, strerror(status));
		else
			print_field("ACK: %d", status);
		break;

	case NLMSG_DONE:
		status = *((int *) NLMSG_DATA(nlmsg));
		print_field("Status: %d", status);
		break;

	case NLMSG_NOOP:
	case NLMSG_OVERRUN:
		break;
	}
}

static void print_rtnl_msg(const struct timeval *tv,
						const struct nlmsghdr *nlmsg)
{
	struct ifinfomsg *info;
	struct ifaddrmsg *addr;
	struct wlan_iface *iface;
	int len;

	switch (nlmsg->nlmsg_type) {
	case RTM_NEWLINK:
	case RTM_DELLINK:
	case RTM_SETLINK:
	case RTM_GETLINK:
		info = (struct ifinfomsg *) NLMSG_DATA(nlmsg);
		len = IFLA_PAYLOAD(nlmsg);
		print_nlmsghdr(tv, nlmsg);
		print_rtm_link(nlmsg->nlmsg_type, info, len);
		break;

	case RTM_NEWADDR:
	case RTM_DELADDR:
	case RTM_GETADDR:
		addr = (struct ifaddrmsg *) NLMSG_DATA(nlmsg);
		len = IFA_PAYLOAD(nlmsg);
		if (!addr || len <= 0)
			return;

		iface = l_hashmap_lookup(wlan_iface_list,
						L_INT_TO_PTR(addr->ifa_index));
		if (!iface)
			return;

		print_nlmsghdr(tv, nlmsg);
		print_ifaddrmsg(addr);
		print_rtnl_attributes(1, addr_entry, IFA_RTA(addr), len);
		break;
	}
}

void nlmon_print_rtnl(struct nlmon *nlmon, const struct timeval *tv,
					const void *data, uint32_t size)
{
	uint32_t aligned_size = NLMSG_ALIGN(size);
	const struct nlmsghdr *nlmsg;

	update_time_offset(tv);

	for (nlmsg = data; NLMSG_OK(nlmsg, aligned_size);
				nlmsg = NLMSG_NEXT(nlmsg, aligned_size)) {
		switch (nlmsg->nlmsg_type) {
		case NLMSG_NOOP:
		case NLMSG_OVERRUN:
		case NLMSG_ERROR:
		case NLMSG_DONE:
			print_nlmsg(tv, nlmsg);
			break;

		case RTM_NEWLINK:
		case RTM_DELLINK:
		case RTM_SETLINK:
		case RTM_GETLINK:
		case RTM_NEWADDR:
		case RTM_DELADDR:
		case RTM_GETADDR:
			print_rtnl_msg(tv, nlmsg);
			break;
		}
	}
}

void nlmon_print_genl(struct nlmon *nlmon, const struct timeval *tv,
					const void *data, uint32_t size)
{
	const struct nlmsghdr *nlmsg;

	update_time_offset(tv);

	for (nlmsg = data; NLMSG_OK(nlmsg, size);
				nlmsg = NLMSG_NEXT(nlmsg, size)) {
		if (nlmsg->nlmsg_type == GENL_ID_CTRL)
			genl_ctrl(nlmon, NLMSG_DATA(nlmsg),
						NLMSG_PAYLOAD(nlmsg, 0));
		else
			nlmon_message(nlmon, tv, NULL, nlmsg);
	}
}

static bool nlmon_receive(struct l_io *io, void *user_data)
{
	struct nlmon *nlmon = user_data;
	struct nlmsghdr *nlmsg;
	struct msghdr msg;
	struct sockaddr_ll sll;
	struct iovec iov;
	struct cmsghdr *cmsg;
	struct timeval copy_tv;
	struct tpacket_auxdata copy_tp;
	const struct timeval *tv = NULL;
	const struct tpacket_auxdata *tp = NULL;
	uint16_t proto_type;
	unsigned char buf[8192];
	unsigned char control[32];
	ssize_t bytes_read;
	size_t nlmsg_len;
	int fd;

	fd = l_io_get_fd(io);
	if (fd < 0)
		return false;

	memset(&sll, 0, sizeof(sll));

	memset(&iov, 0, sizeof(iov));
	iov.iov_base = buf;
	iov.iov_len = sizeof(buf);

	memset(&msg, 0, sizeof(msg));
	msg.msg_name = &sll;
	msg.msg_namelen = sizeof(sll);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = control;
	msg.msg_controllen = sizeof(control);

	bytes_read = recvmsg(fd, &msg, 0);
	if (bytes_read < 0) {
		if (errno != EAGAIN && errno != EINTR)
			return false;

		return true;
	}

	if (sll.sll_hatype != ARPHRD_NETLINK)
		return true;

	proto_type = ntohs(sll.sll_protocol);

	for (cmsg = CMSG_FIRSTHDR(&msg); cmsg;
				cmsg = CMSG_NXTHDR(&msg, cmsg)) {
		if (cmsg->cmsg_level == SOL_SOCKET &&
					cmsg->cmsg_type == SCM_TIMESTAMP) {
			memcpy(&copy_tv, CMSG_DATA(cmsg), sizeof(copy_tv));
			tv = &copy_tv;
		}

		if (cmsg->cmsg_level == SOL_PACKET &&
					cmsg->cmsg_type != PACKET_AUXDATA) {
			memcpy(&copy_tp, CMSG_DATA(cmsg), sizeof(copy_tp));
			tp = &copy_tp;
		}
	}

	nlmsg_len = bytes_read;

	for (nlmsg = iov.iov_base; NLMSG_OK(nlmsg, nlmsg_len);
				nlmsg = NLMSG_NEXT(nlmsg, nlmsg_len)) {
		switch (proto_type) {
		case NETLINK_ROUTE:
			store_netlink(nlmon, tv, proto_type, nlmsg);

			if (!nlmon->nortnl)
				nlmon_print_rtnl(nlmon, tv, nlmsg,
							nlmsg->nlmsg_len);
			break;
		case NETLINK_GENERIC:
			nlmon_message(nlmon, tv, tp, nlmsg);
			break;
		}
	}

	return true;
}

/*
 * BPF filter to match skb->dev->type == 824 (ARPHRD_NETLINK) and
 * either match skb->protocol == 0x0000 (NETLINK_ROUTE) or match
 * skb->protocol == 0x0010 (NETLINK_GENERIC).
 */
static struct sock_filter mon_filter[] = {
	{ 0x28,  0,  0, 0xfffff01c },	/* ldh #hatype		*/
	{ 0x15,  0,  3, 0x00000338 },	/* jne #824, drop	*/
	{ 0x28,  0,  0, 0xfffff000 },	/* ldh #proto		*/
	{ 0x15,  2,  0, 0000000000 },	/* jeq #0x0000, pass	*/
	{ 0x15,  1,  0, 0x00000010 },	/* jeq #0x0010, pass	*/
	{ 0x06,  0,  0, 0000000000 },	/* drop: ret #0		*/
	{ 0x06,  0,  0, 0xffffffff },	/* pass: ret #-1	*/
};

static const struct sock_fprog mon_fprog = { .len = 7, .filter = mon_filter };

static struct l_io *open_packet(const char *name)
{
	struct l_io *io;
	struct sockaddr_ll sll;
	struct packet_mreq mr;
	struct ifreq ifr;
	int fd, opt = 1;

	fd = socket(PF_PACKET, SOCK_RAW | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
	if (fd < 0) {
		perror("Failed to create packet socket");
		return NULL;
	}

	strncpy(ifr.ifr_name, name, IFNAMSIZ);

	if (ioctl(fd, SIOCGIFINDEX, &ifr) < 0) {
		perror("Failed to get monitor index");
		close(fd);
		return NULL;
	}

	memset(&sll, 0, sizeof(sll));
	sll.sll_family = AF_PACKET;
	sll.sll_protocol = htons(ETH_P_ALL);
	sll.sll_ifindex = ifr.ifr_ifindex;

	if (bind(fd, (struct sockaddr *) &sll, sizeof(sll)) < 0) {
		perror("Failed to bind packet socket");
		close(fd);
		return NULL;
	}

	memset(&mr, 0, sizeof(mr));
	mr.mr_ifindex = ifr.ifr_ifindex;
	mr.mr_type = PACKET_MR_ALLMULTI;

	if (setsockopt(fd, SOL_PACKET, PACKET_ADD_MEMBERSHIP,
						&mr, sizeof(mr)) < 0) {
		perror("Failed to enable all multicast");
		close(fd);
		return NULL;
	}

	if (setsockopt(fd, SOL_SOCKET, SO_ATTACH_FILTER,
					&mon_fprog, sizeof(mon_fprog)) < 0) {
		perror("Failed to enable monitor filter");
		close(fd);
		return NULL;
	}

	if (setsockopt(fd, SOL_SOCKET, SO_TIMESTAMP, &opt, sizeof(opt)) < 0) {
		perror("Failed to enable monitor timestamps");
		close(fd);
		return NULL;
	}

	io = l_io_new(fd);

	l_io_set_close_on_destroy(io, true);

	return io;
}

static void print_eap_wsc(const uint8_t *eap_wsc, uint32_t size)
{
	const char *str;

	if (size < 2)
		return;

	switch (eap_wsc[0]) {
	case 0x01:
		str = "WSC-Start";
		break;
	case 0x02:
		str = "WSC-Ack";
		break;
	case 0x03:
		str = "WSC-Nack";
		break;
	case 0x04:
		str = "WSC-Msg";
		break;
	case 0x05:
		str = "WSC-Done";
		break;
	case 0x06:
		str = "WSC-Frag-Ack";
		break;
	default:
		str = "Reserved";
		break;
	}

	print_attr(1, "Op-Code: %u (%s)", eap_wsc[0], str);
	print_attr(1, "Flags: %02x", eap_wsc[1]);

	if (eap_wsc[1] == 0)
		print_wsc_attributes(2, "EAP-WSC Payload",
						eap_wsc + 2, size - 2);
}

static void print_eap(const void *data, uint32_t size)
{
	static const uint8_t wfa_smi[3] = { 0x00, 0x37, 0x2a };
	const uint8_t *eap = data;
	const char *str;

	if (size < 5)
		return;

	switch (eap[0]) {
	case 0x01:
		str = "Request";
		break;
	case 0x02:
		str = "Response";
		break;
	case 0x03:
		str = "Success";
		break;
	case 0x04:
		str = "Failure";
		break;
	default:
		str = "Reserved";
		break;
	};

	print_attr(1, "Code: %u (%s)", eap[0], str);
	print_attr(1, "Identifier: %u", eap[1]);
	print_attr(1, "Length: %u", l_get_be16(eap + 2));

	switch (eap[4]) {
	case 1:
		str = "Identity";
		break;
	case 2:
		str = "Notification";
		break;
	case 3:
		str = "Nak";
		break;
	case 4:
		str = "MD5 Challenge";
		break;
	case 13:
		str = "TLS EAP";
		break;
	case 21:
		str = "TTLS";
		break;
	case 254:
		str = "Expanded";
		break;
	default:
		str = "Reserved";
		break;
	}

	print_attr(1, "Type: %u (%s)", eap[4], str);

	if (eap[4] == 254) {
		if (size < 12)
			return;

		if (memcmp(eap + 5, wfa_smi, 3))
			return;

		if (l_get_be32(eap + 8) == 1)
			print_eap_wsc(eap + 12, size - 12);
	}
}

void nlmon_print_pae(struct nlmon *nlmon, const struct timeval *tv,
					uint8_t type, int index,
					const void *data, uint32_t size)
{
	char extra_str[16];
	const char *str;
	const struct eapol_header *eh;

	update_time_offset(tv);

	sprintf(extra_str, "len %u", size);

	print_packet(tv, (type == PACKET_HOST) ? '>' : '<',
					COLOR_YELLOW, "PAE", extra_str, "");
	if (index >= 0)
		print_attr(0, "Interface Index: %u", index);

	if (size < 4)
		return;

	print_attr(0, "EAPoL: len %u", size);
	print_hexdump(0, data, size);

	eh = data;

	switch (eh->protocol_version) {
	case 0x01:
		str = "802.1X-2001";
		break;
	case 0x02:
		str = "802.1X-2004";
		break;
	case 0x03:
		str = "802.1X-2010";
		break;
	default:
		str = "Reserved";
		break;
	}

	print_attr(1, "Protocol Version: %u (%s)", eh->protocol_version, str);

	switch (eh->packet_type) {
	case 0x00:
		str = "EAP";
		break;
	case 0x01:
		str = "Start";
		break;
	case 0x02:
		str = "Logoff";
		break;
	case 0x03:
		str = "Key";
		break;
	case 0x04:
		str = "Encapsulated-ASF-Alert";
		break;
	case 0x05:
		str = "MKA";
		break;
	case 0x06:
		str = "Announcement (Generic)";
		break;
	case 0x07:
		str = "Announcement (Specific)";
		break;
	case 0x08:
		str = "Announcement-Req";
		break;
	default:
		str = "Reserved";
		break;
	}

	print_attr(1, "Type: %u (%s)", eh->packet_type, str);
	print_attr(1, "Length: %d", L_BE16_TO_CPU(eh->packet_len));

	switch (eh->packet_type) {
	case 0x03:
		print_eapol_key(data, size);
		break;
	case 0x00:
		print_eap(data + 4, size - 4);
	}
}

static bool pae_receive(struct l_io *io, void *user_data)
{
	struct nlmon *nlmon = user_data;
	struct msghdr msg;
	struct sockaddr_ll sll;
	struct iovec iov;
	struct cmsghdr *cmsg;
	struct timeval copy_tv;
	const struct timeval *tv = NULL;
	unsigned char buf[8192];
	unsigned char control[32];
	ssize_t bytes_read;
	int fd;

	fd = l_io_get_fd(io);
	if (fd < 0)
		return false;

	memset(&sll, 0, sizeof(sll));

	memset(&iov, 0, sizeof(iov));
	iov.iov_base = buf;
	iov.iov_len = sizeof(buf);

	memset(&msg, 0, sizeof(msg));
	msg.msg_name = &sll;
	msg.msg_namelen = sizeof(sll);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = control;
	msg.msg_controllen = sizeof(control);

	bytes_read = recvmsg(fd, &msg, 0);
	if (bytes_read < 0) {
		if (errno != EAGAIN && errno != EINTR)
			return false;

		return true;
	}

	if (sll.sll_hatype != ARPHRD_ETHER)
		return true;

	for (cmsg = CMSG_FIRSTHDR(&msg); cmsg;
				cmsg = CMSG_NXTHDR(&msg, cmsg)) {
		if (cmsg->cmsg_level == SOL_SOCKET &&
					cmsg->cmsg_type == SCM_TIMESTAMP) {
			memcpy(&copy_tv, CMSG_DATA(cmsg), sizeof(copy_tv));
			tv = &copy_tv;
		}
	}

	store_packet(nlmon, tv, sll.sll_pkttype, ARPHRD_ETHER,
				ntohs(sll.sll_protocol), buf, bytes_read);

	nlmon_print_pae(nlmon, tv, sll.sll_pkttype, sll.sll_ifindex,
							buf, bytes_read);

	return true;
}

/*
 * BPF filter to match skb->dev->type == 1 (ARPHRD_ETHER) and
 * match skb->protocol == 0x888e (PAE) or 0x88c7 (preauthentication).
 */
static struct sock_filter pae_filter[] = {
	{ 0x28,  0,  0, 0xfffff01c },	/* ldh #hatype		*/
	{ 0x15,  0,  4, 0x00000001 },	/* jne #1, drop		*/
	{ 0x28,  0,  0, 0xfffff000 },	/* ldh #proto		*/
	{ 0x15,  1,  0, 0x0000888e },	/* je  #0x888e, keep	*/
	{ 0x15,  0,  1, 0x000088c7 },	/* jne #0x88c7, drop	*/
	{ 0x06,  0,  0, 0xffffffff },	/* keep: ret #-1	*/
	{ 0x06,  0,  0, 0000000000 },	/* drop: ret #0		*/
};

static const struct sock_fprog pae_fprog = { .len = 7, .filter = pae_filter };

static struct l_io *open_pae(void)
{
	struct l_io *io;
	int fd, opt = 1;

	fd = socket(PF_PACKET, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK,
							htons(ETH_P_ALL));
	if (fd < 0) {
		perror("Failed to create authentication socket");
		return NULL;
	}

	if (setsockopt(fd, SOL_SOCKET, SO_ATTACH_FILTER,
					&pae_fprog, sizeof(pae_fprog)) < 0) {
		perror("Failed to enable authentication filter");
		close(fd);
		return NULL;
	}

	if (setsockopt(fd, SOL_SOCKET, SO_TIMESTAMP, &opt, sizeof(opt)) < 0) {
		perror("Failed to enable authentication timestamps");
		close(fd);
		return NULL;
	}

	io = l_io_new(fd);

	l_io_set_close_on_destroy(io, true);

	return io;
}

struct nlmon *nlmon_open(const char *ifname, uint16_t id, const char *pathname,
				const struct nlmon_config *config)
{
	struct nlmon *nlmon;
	struct l_io *io, *pae_io;
	struct pcap *pcap;

	io = open_packet(ifname);
	if (!io)
		return NULL;

	pae_io = open_pae();
	if (!pae_io) {
		l_io_destroy(io);
		return NULL;
	}

	if (pathname) {
		pcap = pcap_create(pathname);
		if (!pcap) {
			l_io_destroy(pae_io);
			l_io_destroy(io);
			return NULL;
		}
	} else
		pcap = NULL;

	nlmon = l_new(struct nlmon, 1);

	nlmon->id = id;
	nlmon->io = io;
	nlmon->pae_io = pae_io;
	nlmon->req_list = l_queue_new();
	nlmon->pcap = pcap;
	nlmon->nortnl = config->nortnl;
	nlmon->nowiphy = config->nowiphy;
	nlmon->noscan = config->noscan;

	l_io_set_read_handler(nlmon->io, nlmon_receive, nlmon, NULL);
	l_io_set_read_handler(nlmon->pae_io, pae_receive, nlmon, NULL);

	wlan_iface_list = l_hashmap_new();

	return nlmon;
}

void nlmon_close(struct nlmon *nlmon)
{
	if (!nlmon)
		return;

	l_io_destroy(nlmon->io);
	l_io_destroy(nlmon->pae_io);
	l_queue_destroy(nlmon->req_list, nlmon_req_free);

	l_hashmap_destroy(wlan_iface_list, wlan_iface_list_free);
	wlan_iface_list = NULL;

	if (nlmon->pcap)
		pcap_close(nlmon->pcap);

	l_free(nlmon);
}
