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
#include <ell/ell.h>

#include "linux/nl80211.h"
#include "src/ie.h"
#include "monitor/display.h"
#include "monitor/nlmon.h"

#define COLOR_REQUEST		COLOR_BLUE
#define COLOR_RESPONSE		COLOR_MAGENTA
#define COLOR_COMPLETE		COLOR_MAGENTA
#define COLOR_RESULT		COLOR_MAGENTA
#define COLOR_EVENT		COLOR_CYAN

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
};

struct nlmon_req {
	uint32_t seq;
	uint32_t pid;
	uint16_t flags;
	uint8_t cmd;
	uint8_t version;
};

static void nlmon_req_free(void *data)
{
	struct nlmon_req *req = data;

	l_free(req);
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

static void print_packet(const struct timeval *tv, char ident,
					const char *color, const char *label,
					const char *text, const char *extra)
{
	printf("%s%c %s: %s%s %s\n", use_color() ? color : "", ident, label,
				text, use_color() ? COLOR_OFF : "" ,extra);
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

static void print_ie_vendor(unsigned int level,
					const void *data, uint16_t size)
{
	const uint8_t *oui = data;
	const char *str = NULL;
	unsigned int i;

	print_attr(level, "Vendor specific: len %u", size);

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

	print_hexdump(level + 1, data + 3, size - 3);
}

static void print_ie(unsigned int level, const char *label,
					const void *data, uint16_t size)
{
	struct ie_tlv_iter iter;

	print_attr(level, "%s: len %u", label, size);

	ie_tlv_iter_init(&iter, data, size);

	while (ie_tlv_iter_next(&iter)) {
		uint8_t tag = ie_tlv_iter_get_tag(&iter);

		switch (tag) {
		case IE_TYPE_VENDOR_SPECIFIC:
			print_ie_vendor(level + 1, iter.data, iter.len);
			break;
		default:
			print_attr(level + 1, "Tag %u: len %u", tag, iter.len);
			print_hexdump(level + 2, iter.data, iter.len);
			break;
		}
	}
}

static void print_frame_type(unsigned int level, const char *label,
					const void *data, uint16_t size)
{
	uint16_t frame_type = *((uint16_t *) data);
	uint8_t type = frame_type & 0x000c;
	uint8_t subtype = (frame_type & 0x00f0) >> 4;
	const char *str;

	print_attr(level, "%s: 0x%04x", label, frame_type);

	switch (type) {
	case 0x00:
		str = "Management";
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
		break;
	case 0x0c:
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

	print_attr(level + 1, "Subtype: %s (%u)", str, subtype);
}

static void print_frame(unsigned int level, const char *label,
					const void *data, uint16_t size)
{
	print_attr(level, "%s: len %u", label, size);
	print_frame_type(level + 1, "Frame Type", data, 2);
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

static const struct attr_entry bss_table[] = {
	{ NL80211_BSS_BSSID,		"BSSID",	ATTR_ADDRESS	},
	{ NL80211_BSS_FREQUENCY,	"Frequency",	ATTR_U32	},
	{ NL80211_BSS_TSF,		"TSF",		ATTR_U64	},
	{ NL80211_BSS_BEACON_INTERVAL,	"Beacon Interval",
							ATTR_U16	},
	{ NL80211_BSS_CAPABILITY,	"Capability",	ATTR_U16	},
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
		char addr[18];

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
			print_attr(indent, "%s: %u (0x%02x)", str, val8, val8);
			if (NLA_PAYLOAD(nla) != 1)
				printf("malformed packet\n");
			break;
		case ATTR_U16:
			val16 = *((uint16_t *) NLA_DATA(nla));
			print_attr(indent, "%s: %u (0x%04x)", str,
							val16, val16);
			if (NLA_PAYLOAD(nla) != 2)
				printf("malformed packet\n");
			break;
		case ATTR_U32:
			val32 = *((uint32_t *) NLA_DATA(nla));
			print_attr(indent, "%s: %u (0x%08x)", str,
							val32, val32);
			if (NLA_PAYLOAD(nla) != 4)
				printf("malformed packet\n");
			break;
		case ATTR_U64:
			val64 = *((uint64_t *) NLA_DATA(nla));
			print_attr(indent, "%s: %lu (0x%016lx)", str,
							val64, val64);
			if (NLA_PAYLOAD(nla) != 8)
				printf("malformed packet\n");
			break;
		case ATTR_S32:
			val_s32 = *((int32_t *) NLA_DATA(nla));
			print_attr(indent, "%s: %d", str, val_s32);
			if (NLA_PAYLOAD(nla) != 4)
				printf("malformed packet\n");
			break;
		case ATTR_S64:
			val_s64 = *((int64_t *) NLA_DATA(nla));
			print_attr(indent, "%s: %ld", str, val_s64);
			if (NLA_PAYLOAD(nla) != 4)
				printf("malformed packet\n");
			break;
		case ATTR_STRING:
			print_attr(indent, "%s: %s", str,
						(char *) NLA_DATA(nla));
			break;
		case ATTR_ADDRESS:
			ptr = NLA_DATA(nla);
			snprintf(addr, sizeof(addr),
					"%02X:%02X:%02X:%02X:%02X:%02X",
					ptr[0], ptr[1], ptr[2],
					ptr[3], ptr[4], ptr[5]);
			print_attr(indent, "%s: %s", str, addr);
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
				print_attr(indent, "%s: %u (0x%04x)", str,
								val16, val16);
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
	int i, pos;

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

	pos = sprintf(extra_str, "(0x%02x) len %u", cmd, len);

	if (flags) {
		pos += sprintf(extra_str + pos, " [");

		if (flags & NLM_F_MULTI) {
			flags &= ~NLM_F_MULTI;
			pos += sprintf(extra_str + pos, "multi%c",
							flags ? ',' : ']');
		}

		if (flags & NLM_F_ACK) {
			flags &= ~NLM_F_ACK;
			pos += sprintf(extra_str + pos, "ack%c",
							flags ? ',' : ']');
		}

		if (flags & NLM_F_ECHO) {
			flags &= ~NLM_F_ECHO;
			pos += sprintf(extra_str + pos, "echo%c",
							flags ? ',' : ']');
		}

		if ((flags & NLM_F_DUMP) == NLM_F_DUMP) {
			flags &= ~NLM_F_DUMP;
			pos += sprintf(extra_str + pos, "dump%c",
							flags ? ',' : ']');
		}

		if (flags)
			pos += sprintf(extra_str + pos, "0x%x]", flags);
	}

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

static void store_message(struct nlmon *nlmon, const struct timeval *tv,
					const struct tpacket_auxdata *tp,
					const struct nlmsghdr *nlmsg)
{
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

			store_message(nlmon, tv, tp, nlmsg);
			print_message(tv, type, nlmsg->nlmsg_flags, status,
						req->cmd, req->version,
						NULL, sizeof(status));
			nlmon_req_free(req);
		}
		return;
	}

	if (nlmsg->nlmsg_type != nlmon->id)
		return;

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

		store_message(nlmon, tv, tp, nlmsg);
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

		store_message(nlmon, tv, tp, nlmsg);
		print_message(tv, type, nlmsg->nlmsg_flags, 0,
					genlmsg->cmd, genlmsg->version,
					NLMSG_DATA(nlmsg) + GENL_HDRLEN,
					NLMSG_PAYLOAD(nlmsg, GENL_HDRLEN));
	}
}

struct nlmon *nlmon_create(void)
{
	struct nlmon *nlmon;

	nlmon = l_new(struct nlmon, 1);

	nlmon->id = GENL_ID_GENERATE;
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

void nlmon_print_rtnl(struct nlmon *nlmon, const struct timeval *tv,
					const void *data, uint32_t size)
{
	char str[16];

	sprintf(str, "len %u", size);

	print_packet(tv, '*', COLOR_WHITE, "Route Netlink", str, "");
}

void nlmon_print_genl(struct nlmon *nlmon, const struct timeval *tv,
					const void *data, uint32_t size)
{
	const struct nlmsghdr *nlmsg;

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

	if (sll.sll_protocol != htons(NETLINK_GENERIC))
		return true;

	if (sll.sll_hatype != ARPHRD_NETLINK)
		return true;

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
		nlmon_message(nlmon, tv, tp, nlmsg);
	}

	return true;
}

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

	if (setsockopt(fd, SOL_SOCKET, SO_TIMESTAMP, &opt, sizeof(opt)) < 0) {
		perror("Failed to enable timestamps");
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

	sprintf(extra_str, "len %u", size);

	print_packet(tv, (type == PACKET_HOST) ? '>' : '<',
				COLOR_YELLOW, "PAE Packet", extra_str, "");
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

	nlmon_print_pae(nlmon, tv, sll.sll_pkttype, sll.sll_ifindex,
							buf, bytes_read);

	return true;
}

static struct l_io *open_pae(void)
{
	struct l_io *io;
	int fd, opt = 1;

	fd = socket(PF_PACKET, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK,
							htons(ETH_P_PAE));
	if (fd < 0) {
		perror("Failed to create authentication socket");
		return NULL;
	}

	if (setsockopt(fd, SOL_SOCKET, SO_TIMESTAMP, &opt, sizeof(opt)) < 0) {
		perror("Failed to enable authentication imestamps");
		close(fd);
		return NULL;
	}

	io = l_io_new(fd);

	l_io_set_close_on_destroy(io, true);

	return io;
}

struct nlmon *nlmon_open(const char *ifname, uint16_t id)
{
	struct nlmon *nlmon;
	struct l_io *io, *pae_io;

	io = open_packet(ifname);
	if (!io)
		return NULL;

	pae_io = open_pae();
	if (!pae_io) {
		l_io_destroy(io);
		return NULL;
	}

	nlmon = l_new(struct nlmon, 1);

	nlmon->id = id;
	nlmon->io = io;
	nlmon->pae_io = pae_io;
	nlmon->req_list = l_queue_new();

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

	l_free(nlmon);
}
