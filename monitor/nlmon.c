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
#include <errno.h>
#include <ctype.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <linux/if.h>
#include <linux/if_arp.h>
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
#include "src/util.h"
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

static void print_ie_vendor(unsigned int level, const char *label,
				const void *data, uint16_t size)
{
	const uint8_t *oui = data;
	const char *str = NULL;
	unsigned int i;

	print_attr(level, "%s: len %u", label, size);

	if (size < 3) {
		print_hexdump(level + 1, data, size);
		return;
	}

	for (i = 0; oui_table[i].str; i++) {
		if (!memcmp(oui_table[i].oui, oui, 3)) {
			str = oui_table[i].str;
			break;
		}
	}

	if (str)
		print_attr(level + 1, "%s (%02x:%02x:%02x)", str,
						oui[0], oui[1], oui[2]);
	else
		print_attr(level + 1, "%02x:%02x:%02x",
						oui[0], oui[1], oui[2]);
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
		bool mandatory = (rate[i] & 0x8);

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

static struct attr_entry ie_entry[] = {
	{IE_TYPE_SSID,                      "SSID",
	ATTR_CUSTOM,                        { .function = print_ie_ssid } },
	{IE_TYPE_SUPPORTED_RATES,           "Supported rates",
	ATTR_CUSTOM,                        { .function = print_ie_rate } },
	{IE_TYPE_DSSS_PARAMETER_SET,        "DSSS parameter set",
	ATTR_CUSTOM,                        { .function = print_ie_ds } },
	{IE_TYPE_TIM,                       "TIM",
	ATTR_CUSTOM,                        { .function = print_ie_tim } },
	{IE_TYPE_COUNTRY,                   "Country",
	ATTR_CUSTOM,                        { .function = print_ie_country } },
	{IE_TYPE_BSS_LOAD,                  "BSS load",
	ATTR_CUSTOM,                        { .function = print_ie_bss_load } },
	{IE_TYPE_POWER_CONSTRAINT,          "Power constraint",
	ATTR_CUSTOM,                        { .function = print_ie_power_constraint } },
	{IE_TYPE_TPC_REPORT,                "TPC report",
	ATTR_CUSTOM,                        { .function = print_ie_tpc } },
	{IE_TYPE_ERP,                       "ERP Information",
	ATTR_CUSTOM,                        { .function = print_ie_erp } },
	{IE_TYPE_EXTENDED_SUPPORTED_RATES,  "Extended supported rates",
	ATTR_CUSTOM,                        { .function = print_ie_rate } },
	{IE_TYPE_VENDOR_SPECIFIC,           "Vendor specific",
	ATTR_CUSTOM,                        { .function = print_ie_vendor } },
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
		uint8_t tag = ie_tlv_iter_get_tag(&iter);
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

static void print_address(unsigned int level, const char *label,
					const unsigned char address[6])
{
	char addr[18];

	snprintf(addr, sizeof(addr), "%02X:%02X:%02X:%02X:%02X:%02X",
					address[0], address[1], address[2],
					address[3], address[4], address[5]);

	print_attr(level, "%s %s", label, addr);
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

static void print_mpdu_mgmt_header(unsigned int level, const struct mpdu *mpdu)
{
	print_attr(level, "Duration: %u",
			L_LE16_TO_CPU(mpdu->mgmt_hdr.duration));

	print_address(level, "Address 1 (RA):", mpdu->mgmt_hdr.address_1);
	print_address(level, "Address 2 (TA):", mpdu->mgmt_hdr.address_2);
	print_address(level, "Address 3:", mpdu->mgmt_hdr.address_3);

	print_attr(level, "Fragment Number: %u",
					mpdu->mgmt_hdr.fragment_number);
	print_attr(level, "Sequence Number: %u",
				MPDU_MGMT_SEQUENCE_NUMBER(mpdu->mgmt_hdr));
}

static void print_authentication_mgmt_frame(unsigned int level,
						const struct mpdu *mpdu)
{
	const char *str;

	if (!mpdu)
		return;

	print_attr(level, "Authentication:");

	print_mpdu_frame_control(level + 1, &mpdu->fc);
	print_mpdu_mgmt_header(level + 1, mpdu);

	switch (L_LE16_TO_CPU(mpdu->auth.algorithm)) {
	case MPDU_AUTH_ALGO_OPEN_SYSTEM:
		str = "Open";
		break;
	case MPDU_AUTH_ALGO_SHARED_KEY:
		str = "Shared key";
		break;
	default:
		str = "Reserved";
		break;
	}

	print_attr(level + 1, "Algorithm: %s (seq: %u, status: %u)", str,
				L_LE16_TO_CPU(mpdu->auth.transaction_sequence),
				L_LE16_TO_CPU(mpdu->auth.status));

	if (L_LE16_TO_CPU(mpdu->auth.algorithm) != MPDU_AUTH_ALGO_SHARED_KEY)
		return;

	if (L_LE16_TO_CPU(mpdu->auth.transaction_sequence) < 2 ||
			L_LE16_TO_CPU(mpdu->auth.transaction_sequence) > 3)
		return;

	print_attr(level + 1, "Challenge text: \"%s\" (%u)",
				mpdu->auth.shared_key_23.challenge_text,
				mpdu->auth.shared_key_23.challenge_text_len);
}

static void print_deauthentication_mgmt_frame(unsigned int level,
						const struct mpdu *mpdu)
{
	if (!mpdu)
		return;

	print_attr(level, "Deauthentication:");

	print_mpdu_frame_control(level + 1, &mpdu->fc);
	print_mpdu_mgmt_header(level + 1, mpdu);

	print_attr(level + 1, "Reason code: %u",
				L_LE16_TO_CPU(mpdu->deauth.reason_code));
}

static void print_frame_type(unsigned int level, const char *label,
					const void *data, uint16_t size)
{
	uint16_t frame_type = *((uint16_t *) data);
	uint8_t type = frame_type & 0x000c;
	uint8_t subtype = (frame_type & 0x00f0) >> 4;
	const struct mpdu *mpdu = NULL;
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
		str = "Authentication";
		print_authentication_mgmt_frame(level + 1, mpdu);
		break;
	case 0x0c:
		str = "Deauthentication";
		print_deauthentication_mgmt_frame(level + 1, mpdu);
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

	if (!mpdu)
		print_attr(level + 1, "Subtype: %s (%u)", str, subtype);
}

static void print_frame(unsigned int level, const char *label,
					const void *data, uint16_t size)
{
	print_attr(level, "%s: len %u", label, size);
	print_frame_type(level + 1, "Frame Type", data, size);
	print_hexdump(level + 1, data, size);
}

static const struct {
	uint32_t cipher;
	const char *str;
} cipher_table[] = {
	{ 0x000fac00, "Use group cipher suite"		},
	{ 0x000fac01, "WEP-40"				},
	{ 0x000fac02, "TKIP"				},
	{ 0x000fac04, "CCMP"				},
	{ 0x000fac05, "WEP-104"				},
	{ 0x000fac06, "BIP"				},
	{ 0x000fac07, "Group traffic not allowed"	},
	{ 0x00147201, "WPI-SMS4"			},
	{ }
};

static void print_cipher_suite(unsigned int level, const char *label,
					const void *data, uint16_t size)
{
	uint32_t cipher = *((uint32_t *) data);
	const char *str = "Reserved";
	unsigned int i;

	for (i = 0; cipher_table[i].str; i++) {
		if (cipher_table[i].cipher == cipher) {
			str = cipher_table[i].str;
			break;
		}
	}

	if (label)
		print_attr(level, "%s: %s (0x%08x)", label, str, cipher);
	else
		print_attr(level, "%s (0x%08x)", str, cipher);
}

static void print_cipher_suites(unsigned int level, const char *label,
					const void *data, uint16_t size)
{
	print_attr(level, "%s: len %u", label, size);

	while (size >= 4) {
		print_cipher_suite(level + 1, NULL, data, 4);
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

static const struct attr_entry sta_info_table[] = {
	{ NL80211_STA_INFO_INACTIVE_TIME,
					"Inactivity time",	ATTR_U32 },
	{ NL80211_STA_INFO_RX_BYTES,	"Total RX bytes",	ATTR_U32 },
	{ NL80211_STA_INFO_TX_BYTES,	"Total TX bytes",	ATTR_U32 },
	{ NL80211_STA_INFO_RX_BYTES64,	"Total RX bytes",	ATTR_U64 },
	{ NL80211_STA_INFO_TX_BYTES64,	"Total TX bytes",	ATTR_U64 },
	{ NL80211_STA_INFO_SIGNAL,	"Signal strength",	ATTR_U8  },
	{ NL80211_STA_INFO_TX_BITRATE,	"TX bitrate" },
	{ NL80211_STA_INFO_RX_PACKETS,	"RX packets",		ATTR_U32 },
	{ NL80211_STA_INFO_TX_PACKETS,	"TX packets",		ATTR_U32 },
	{ NL80211_STA_INFO_TX_RETRIES,	"TX retries",		ATTR_U32 },
	{ NL80211_STA_INFO_TX_FAILED,	"TX failed",		ATTR_U32 },
	{ NL80211_STA_INFO_SIGNAL_AVG,	"Signal strength average",
								ATTR_U8  },
	{ NL80211_STA_INFO_LLID,	"Mesh LLID",		ATTR_U16 },
	{ NL80211_STA_INFO_PLID,	"Mesh PLID",		ATTR_U16 },
	{ NL80211_STA_INFO_PLINK_STATE, "P-Link state" },
	{ NL80211_STA_INFO_RX_BITRATE,	"RX bitrate" },
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
				ATTR_CUSTOM, { .function = print_ie }	},
	{ NL80211_BSS_SIGNAL_MBM,	"Signal mBm",	ATTR_S32	},
	{ NL80211_BSS_SIGNAL_UNSPEC,	"Signal Unspec",ATTR_U8		},
	{ NL80211_BSS_STATUS,		"Status",	ATTR_U32	},
	{ NL80211_BSS_SEEN_MS_AGO,	"Seen ms ago",	ATTR_U32	},
	{ NL80211_BSS_BEACON_IES, "Beacon IEs",
				ATTR_CUSTOM, { .function = print_ie }	},
	{ NL80211_BSS_CHAN_WIDTH,	"Chan Width",	ATTR_U32	},
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
	{ }
};

static const struct attr_entry key_default_type_table[] = {
	{ NL80211_KEY_DEFAULT_TYPE_UNICAST,	"Unicast",	ATTR_FLAG },
	{ NL80211_KEY_DEFAULT_TYPE_MULTICAST,	"Multicast",	ATTR_FLAG },
	{ }
};

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
			"Wiphy Bands" },
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
	{ NL80211_ATTR_HT_CAPABILITY,
			"HT Capability" },
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
						{ .function = print_ie } },
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
			"Supported Commands", ATTR_ARRAY,
						{ .array_type = ATTR_U32 } },
	{ NL80211_ATTR_FRAME,
			"Frame", ATTR_CUSTOM, { .function = print_frame } },
	{ NL80211_ATTR_SSID,
			"SSID", ATTR_BINARY },
	{ NL80211_ATTR_AUTH_TYPE,
			"Auth Type", ATTR_U32 },
	{ NL80211_ATTR_REASON_CODE,
			"Reason Code", ATTR_U16 },
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
			"AKM Suites" },
	{ NL80211_ATTR_REQ_IE,
			"Request IE", ATTR_CUSTOM, { .function = print_ie } },
	{ NL80211_ATTR_RESP_IE,
			"Response IE", ATTR_CUSTOM, { .function = print_ie } },
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
			"Rekey Data" },
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
						{ .function = print_ie } },
	{ NL80211_ATTR_IE_ASSOC_RESP,
			"IE Assoc Response", ATTR_CUSTOM,
						{ .function = print_ie } },
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
			"Diable HT", ATTR_FLAG },
	{ NL80211_ATTR_HT_CAPABILITY_MASK,
			"HT Capability Mask" },
	{ NL80211_ATTR_NOACK_MAP,
			"No-Ack Map", ATTR_U16 },
	{ NL80211_ATTR_INACTIVITY_TIMEOUT,
			"Inactivity Timeout", ATTR_U16 },
	{ NL80211_ATTR_RX_SIGNAL_DBM,
			"RX Signal dBm", ATTR_U32 },
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
			"Extended Capabilities" },
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
			"Max Criticial Protocol Duration" },
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

#define NLA_OK(nla,len)         ((len) >= (int) sizeof(struct nlattr) && \
				(nla)->nla_len >= sizeof(struct nlattr) && \
				(nla)->nla_len <= (len))
#define NLA_NEXT(nla,attrlen)	((attrlen) -= NLA_ALIGN((nla)->nla_len), \
				(struct nlattr*)(((char*)(nla)) + \
				NLA_ALIGN((nla)->nla_len)))

#define NLA_LENGTH(len)		(NLA_ALIGN(sizeof(struct nlattr)) + (len))
#define NLA_DATA(nla)		((void*)(((char*)(nla)) + NLA_LENGTH(0)))
#define NLA_PAYLOAD(nla)	((int)((nla)->nla_len - NLA_LENGTH(0)))

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
	{ }
};

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

static void print_message(const struct timeval *tv, enum msg_type type,
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

	pkt_type = L_CPU_TO_BE16(pkt_type);
	L_PUT_UNALIGNED(pkt_type, (uint16_t *) buf);

	arphrd_type = L_CPU_TO_BE16(arphrd_type);
	L_PUT_UNALIGNED(arphrd_type, (uint16_t *) (buf + 2));

	proto_type = L_CPU_TO_BE16(proto_type);
	L_PUT_UNALIGNED(proto_type, (uint16_t *) (buf + 14));

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
			print_message(tv, type, nlmsg->nlmsg_flags, status,
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
		print_message(tv, MSG_REQUEST, flags, 0,
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
		print_message(tv, type, nlmsg->nlmsg_flags, 0,
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
	uint16_t id = GENL_ID_GENERATE;

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
		nlmon->id = id;
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
	char extra_str[32];
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
	switch (nlmsg->nlmsg_type) {
	case RTM_NEWLINK:
	case RTM_DELLINK:
	case RTM_SETLINK:
	case RTM_GETLINK:
	case RTM_NEWADDR:
	case RTM_DELADDR:
	case RTM_GETADDR:
		print_nlmsghdr(tv, nlmsg);
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

	for (nlmsg = iov.iov_base; NLMSG_OK(nlmsg, bytes_read);
				nlmsg = NLMSG_NEXT(nlmsg, bytes_read)) {
		switch (proto_type) {
		case NETLINK_ROUTE:
			store_netlink(nlmon, tv, proto_type, nlmsg);
			nlmon_print_rtnl(nlmon, tv, nlmsg, nlmsg->nlmsg_len);
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

void nlmon_print_pae(struct nlmon *nlmon, const struct timeval *tv,
					uint8_t type, int index,
					const void *data, uint32_t size)
{
	uint8_t eapol_ver, eapol_type;
	uint16_t eapol_len;
	char extra_str[16];
	const char *str;

	update_time_offset(tv);

	sprintf(extra_str, "len %u", size);

	print_packet(tv, (type == PACKET_HOST) ? '>' : '<',
					COLOR_YELLOW, "PAE", extra_str, "");
	if (index >= 0)
		print_attr(0, "Interface Index: %u", index);

	if (size < 4)
		return;

	eapol_ver = *((const uint8_t *) data);
	eapol_type = *((const uint8_t *) (data + 1));
	eapol_len = L_GET_UNALIGNED((const uint16_t *) (data + 2));
	eapol_len = L_BE16_TO_CPU(eapol_len);

	print_attr(0, "EAPoL: len %u", eapol_len);

	switch (eapol_ver) {
	case 0x01:
		str = "802.11X-2001";
		break;
	case 0x02:
		str = "802.11X-2004";
		break;
	default:
		str = "Reserved";
		break;
	}

	print_attr(1, "Version: %s (%u)", str, eapol_ver);

	switch (eapol_type) {
	case 0x00:
		str = "Packet";
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
	default:
		str = "Reserved";
		break;
	}

	print_attr(1, "Type: %s (%u)", str, eapol_type);

	print_hexdump(1, data + 4, size - 4);
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

	if (sll.sll_protocol != htons(ETH_P_PAE))
		return true;

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

	store_packet(nlmon, tv, sll.sll_pkttype, ARPHRD_ETHER, ETH_P_PAE,
							buf, bytes_read);

	nlmon_print_pae(nlmon, tv, sll.sll_pkttype, sll.sll_ifindex,
							buf, bytes_read);

	return true;
}

/*
 * BPF filter to match skb->dev->type == 1 (ARPHRD_ETHER) and
 * match skb->protocol == 0x888e (PAE).
 */
static struct sock_filter pae_filter[] = {
	{ 0x28,  0,  0, 0xfffff01c },	/* ldh #hatype		*/
	{ 0x15,  0,  3, 0x00000001 },	/* jne #1, drop		*/
	{ 0x28,  0,  0, 0xfffff000 },	/* ldh #proto		*/
	{ 0x15,  0,  1, 0x0000888e },	/* jne #0x888e, drop	*/
	{ 0x06,  0,  0, 0xffffffff },	/* ret #-1		*/
	{ 0x06,  0,  0, 0000000000 },	/* drop: ret #0		*/
};

static const struct sock_fprog pae_fprog = { .len = 6, .filter = pae_filter };

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

struct nlmon *nlmon_open(const char *ifname, uint16_t id, const char *pathname)
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

	l_io_set_read_handler(nlmon->io, nlmon_receive, nlmon, NULL);
	l_io_set_read_handler(nlmon->pae_io, pae_receive, nlmon, NULL);

	return nlmon;
}

void nlmon_close(struct nlmon *nlmon)
{
	if (!nlmon)
		return;

	l_io_destroy(nlmon->io);
	l_io_destroy(nlmon->pae_io);
	l_queue_destroy(nlmon->req_list, nlmon_req_free);

	if (nlmon->pcap)
		pcap_close(nlmon->pcap);

	l_free(nlmon);
}
