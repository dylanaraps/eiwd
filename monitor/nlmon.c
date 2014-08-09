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
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/netlink.h>
#include <linux/genetlink.h>
#include <ell/ell.h>

#include "linux/nl80211.h"
#include "monitor/nlmon.h"

struct nlmon {
	uint16_t id;
	struct l_io *io;
	struct l_queue *req_list;
};

struct nlmon_req {
	uint32_t seq;
	uint32_t pid;
	uint16_t flags;
};

static void nlmon_req_free(void *data)
{
	struct nlmon_req *req = data;

	l_free(req);
}

#define print_indent(indent, fmt, args...) \
	printf("%*c" fmt "\n", (indent), ' ', ## args)

#define print_text(fmt, args...) \
		print_indent(8, fmt, ## args)

static void print_hexdump(const unsigned char *buf, uint16_t len)
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
			print_text("%s", str);
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
		print_text("%s", str);
	}
}

enum attr_type {
	ATTR_UNSPEC,
	ATTR_FLAG,
	ATTR_U8,
	ATTR_U16,
	ATTR_U32,
	ATTR_U64,
	ATTR_S32,
	ATTR_STRING,
	ATTR_ADDRESS,
	ATTR_BINARY,
	ATTR_NESTED,
	ATTR_ARRAY,
	ATTR_FLAG_OR_U16,
};

struct attr_entry {
	uint16_t attr;
	const char *str;
	enum attr_type type;
	union {
		const struct attr_entry *nested;
		enum attr_type array_type;
		void (*func) (void);
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

static const struct attr_entry bss_table[] = {
	{ NL80211_BSS_BSSID,		"BSSID",	ATTR_ADDRESS	},
	{ NL80211_BSS_FREQUENCY,	"Frequency",	ATTR_U32	},
	{ NL80211_BSS_TSF,		"TSF",		ATTR_U64	},
	{ NL80211_BSS_BEACON_INTERVAL,	"Beacon Interval", ATTR_U16	},
	{ NL80211_BSS_CAPABILITY,	"Capability",	ATTR_U16	},
	{ NL80211_BSS_INFORMATION_ELEMENTS, "IEs",	ATTR_BINARY	},
	{ NL80211_BSS_SIGNAL_MBM,	"Signal mBm",	ATTR_S32	},
	{ NL80211_BSS_SIGNAL_UNSPEC,	"Signal Unspec",ATTR_U8		},
	{ NL80211_BSS_STATUS,		"Status",	ATTR_U32	},
	{ NL80211_BSS_SEEN_MS_AGO,	"Seen ms ago",	ATTR_U32	},
	{ NL80211_BSS_BEACON_IES,	"Beacon IEs",	ATTR_BINARY	},
	{ NL80211_BSS_CHAN_WIDTH,	"Chan Width",	ATTR_U32	},
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
			"Key Cipher", ATTR_U32 },
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
			"Station Info" },
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
			"Information Elements", ATTR_BINARY },
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
			"Frame", ATTR_BINARY },
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
			"Cipher Suites" },
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
			"Station Flags 2" },
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
			"Cipher Suites Pairwise" },
	{ NL80211_ATTR_CIPHER_SUITE_GROUP,
			"Cipher Suite Group", ATTR_U32 },
	{ NL80211_ATTR_WPA_VERSIONS,
			"WPA Versions", ATTR_U32 },
	{ NL80211_ATTR_AKM_SUITES,
			"AKM Suites" },
	{ NL80211_ATTR_REQ_IE,
			"Request IE" },
	{ NL80211_ATTR_RESP_IE,
			"Response IE" },
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
			"CQM" },
	{ NL80211_ATTR_LOCAL_STATE_CHANGE,
			"Local State Change", ATTR_FLAG },
	{ NL80211_ATTR_AP_ISOLATE,
			"AP Isolate", ATTR_U8 },
	{ NL80211_ATTR_WIPHY_TX_POWER_SETTING,
			"Wiphy TX Power Setting", ATTR_U32 },
	{ NL80211_ATTR_WIPHY_TX_POWER_LEVEL,
			"Wiphy TX Power Level", ATTR_U32 },
	{ NL80211_ATTR_TX_FRAME_TYPES,
			"TX Frame Types" },
	{ NL80211_ATTR_RX_FRAME_TYPES,
			"RX Frame Types" },
	{ NL80211_ATTR_FRAME_TYPE,
			"Frame Type", ATTR_U16 },
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
			"Key Default Types" },
	{ NL80211_ATTR_MAX_REMAIN_ON_CHANNEL_DURATION,
			"Remain on Channel Duration " },
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
			"IE Probe Response" },
	{ NL80211_ATTR_IE_ASSOC_RESP,
			"IE Assoc Response" },
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
		printf("%*c%s: %u (0x%04x)\n", indent, ' ',
						label, val_u16, val_u16);
		if (len != 2)
			printf("malformed packet\n");
		break;
	case ATTR_U32:
		val_u32 = *((uint32_t *) buf);
		printf("%*c%s: %u (0x%08x)\n", indent, ' ',
						label, val_u32, val_u32);
		if (len != 4)
			printf("malformed packet\n");
		break;
	default:
		printf("%*c%s: len %u\n", indent, ' ', label, len);
		print_hexdump(buf, len);
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
		uint64_t val64;
		uint32_t val32;
		uint16_t val16;
		uint8_t val8;
		int32_t val_s32;
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
					break;
				}
			}
		}

		switch (type) {
		case ATTR_UNSPEC:
			printf("%*c%s: len %u\n", indent, ' ', str,
						NLA_PAYLOAD(nla));
			print_hexdump(NLA_DATA(nla), NLA_PAYLOAD(nla));
			break;
		case ATTR_FLAG:
			printf("%*c%s: true\n", indent, ' ', str);
			if (NLA_PAYLOAD(nla) != 0)
				printf("malformed packet\n");
			break;
		case ATTR_U8:
			val8 = *((uint8_t *) NLA_DATA(nla));
			printf("%*c%s: %u (0x%02x)\n", indent, ' ', str,
								val8, val8);
			if (NLA_PAYLOAD(nla) != 1)
				printf("malformed packet\n");
			break;
		case ATTR_U16:
			val16 = *((uint16_t *) NLA_DATA(nla));
			printf("%*c%s: %u (0x%04x)\n", indent, ' ', str,
								val16, val16);
			if (NLA_PAYLOAD(nla) != 2)
				printf("malformed packet\n");
			break;
		case ATTR_U32:
			val32 = *((uint32_t *) NLA_DATA(nla));
			printf("%*c%s: %u (0x%08x)\n", indent, ' ', str,
								val32, val32);
			if (NLA_PAYLOAD(nla) != 4)
				printf("malformed packet\n");
			break;
		case ATTR_U64:
			val64 = *((uint64_t *) NLA_DATA(nla));
			printf("%*c%s: %lu (0x%016lx)\n", indent, ' ', str,
								val64, val64);
			if (NLA_PAYLOAD(nla) != 8)
				printf("malformed packet\n");
			break;
		case ATTR_S32:
			val_s32 = *((int32_t *) NLA_DATA(nla));
			printf("%*c%s: %d\n", indent, ' ', str, val_s32);
			if (NLA_PAYLOAD(nla) != 4)
				printf("malformed packet\n");
			break;
		case ATTR_STRING:
			printf("%*c%s: %s\n", indent, ' ', str,
						(char *) NLA_DATA(nla));
			break;
		case ATTR_ADDRESS:
			ptr = NLA_DATA(nla);
			snprintf(addr, sizeof(addr),
					"%02X:%02X:%02X:%02X:%02X:%02X",
					ptr[0], ptr[1], ptr[2],
					ptr[3], ptr[4], ptr[5]);
			printf("%*c%s: %s\n", indent, ' ', str, addr);
			if (NLA_PAYLOAD(nla) != 6)
				printf("malformed packet\n");
			break;
		case ATTR_BINARY:
			printf("%*c%s: len %u\n", indent, ' ', str,
						NLA_PAYLOAD(nla));
			print_hexdump(NLA_DATA(nla), NLA_PAYLOAD(nla));
			break;
		case ATTR_NESTED:
			printf("%*c%s: len %u\n", indent, ' ', str,
						NLA_PAYLOAD(nla));
			if (!nested)
				printf("missing table\n");
			print_attributes(indent + 4, nested,
					NLA_DATA(nla), NLA_PAYLOAD(nla));
			break;
		case ATTR_ARRAY:
			printf("%*c%s: len %u\n", indent, ' ', str,
						NLA_PAYLOAD(nla));
			if (array_type == ATTR_UNSPEC)
				printf("missing type\n");
			print_array(indent + 4, array_type,
					NLA_DATA(nla), NLA_PAYLOAD(nla));
			break;
		case ATTR_FLAG_OR_U16:
			if (NLA_PAYLOAD(nla) == 0)
				printf("%*c%s: true\n", indent, ' ', str);
			else if (NLA_PAYLOAD(nla) == 2) {
				val16 = *((uint16_t *) NLA_DATA(nla));
				printf("%*c%s: %u (0x%04x)\n", indent, ' ',
							str, val16, val16);
			} else
				printf("malformed packet\n");
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

static void print_message(const struct nlmsghdr *nlmsg)
{
	const struct genlmsghdr *genlmsg;
	const char *str;
	bool out;
	int i;

	if (nlmsg->nlmsg_seq && (nlmsg->nlmsg_flags & NLM_F_REQUEST))
		out = true;
	else
		out = false;

	if (nlmsg->nlmsg_type < NLMSG_MIN_TYPE) {
		switch (nlmsg->nlmsg_type) {
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
		default:
			str = "Reserved";
			break;
		}

		printf("%c %s (%u) flags 0x%04x len %u\n",
						out ? '<' : '>', str,
						nlmsg->nlmsg_type,
						nlmsg->nlmsg_flags,
						NLMSG_PAYLOAD(nlmsg, 0));
		return;
	}

	genlmsg = NLMSG_DATA(nlmsg);

	str = "Reserved";

	for (i = 0; cmd_table[i].str; i++) {
		if (genlmsg->cmd == cmd_table[i].cmd) {
			str = cmd_table[i].str;
			break;
		}
	}

	printf("%c %s (%u) flags 0x%04x len %u\n",
					out ? '<' : '>', str,
					genlmsg->cmd,
					nlmsg->nlmsg_flags,
					NLMSG_PAYLOAD(nlmsg, 0));

	print_attributes(4, attr_table, NLMSG_DATA(nlmsg) + GENL_HDRLEN,
					NLMSG_PAYLOAD(nlmsg, GENL_HDRLEN));
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

static void nlmon_message(struct nlmon *nlmon, const struct nlmsghdr *nlmsg)
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
			nlmon_req_free(req);
			print_message(nlmsg);
		}
		return;
	}

	if (nlmsg->nlmsg_type != nlmon->id)
		return;

	if (nlmsg->nlmsg_flags & NLM_F_REQUEST) {
		req = l_new(struct nlmon_req, 1);

		req->seq = nlmsg->nlmsg_seq;
		req->pid = nlmsg->nlmsg_pid;
		req->flags = nlmsg->nlmsg_flags;

		l_queue_push_tail(nlmon->req_list, req);
		print_message(nlmsg);
	} else {
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
		}

		print_message(nlmsg);
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

void nlmon_print(struct nlmon *nlmon, const void *data, uint32_t size)
{
	const struct nlmsghdr *nlmsg;

	for (nlmsg = data; NLMSG_OK(nlmsg, size);
				nlmsg = NLMSG_NEXT(nlmsg, size)) {
		if (nlmsg->nlmsg_type == GENL_ID_CTRL)
			genl_ctrl(nlmon, NLMSG_DATA(nlmsg),
						NLMSG_PAYLOAD(nlmsg, 0));
		else
			nlmon_message(nlmon, nlmsg);
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

	if (ntohs(sll.sll_protocol) != NETLINK_GENERIC)
		return true;

	for (cmsg = CMSG_FIRSTHDR(&msg); cmsg;
				cmsg = CMSG_NXTHDR(&msg, cmsg)) {
		struct tpacket_auxdata tp;

		if (cmsg->cmsg_level != SOL_PACKET)
			continue;

		if (cmsg->cmsg_type != PACKET_AUXDATA)
			continue;

		memcpy(&tp, CMSG_DATA(cmsg), sizeof(tp));
	}

	for (nlmsg = iov.iov_base; NLMSG_OK(nlmsg, bytes_read);
				nlmsg = NLMSG_NEXT(nlmsg, bytes_read)) {
		nlmon_message(nlmon, nlmsg);
	}

	return true;
}

static struct l_io *open_packet(const char *name)
{
	struct l_io *io;
	struct sockaddr_ll sll;
	struct packet_mreq mr;
	struct ifreq ifr;
	int fd;

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
						&mr, sizeof(mr) < 0)) {
		perror("Failed to enable all multicast");
		if (errno != EINVAL) {
			close(fd);
			return NULL;
		}
	}

	io = l_io_new(fd);

	l_io_set_close_on_destroy(io, true);

	return io;
}

struct nlmon *nlmon_open(const char *ifname, uint16_t id)
{
	struct nlmon *nlmon;
	struct l_io *io;

	io = open_packet(ifname);
	if (!io)
		return NULL;

	nlmon = l_new(struct nlmon, 1);

	nlmon->id = id;
	nlmon->io = io;
	nlmon->req_list = l_queue_new();

	l_io_set_read_handler(nlmon->io, nlmon_receive, nlmon, NULL);

	return nlmon;
}

void nlmon_close(struct nlmon *nlmon)
{
	if (!nlmon)
		return;

	l_io_destroy(nlmon->io);
	l_queue_destroy(nlmon->req_list, nlmon_req_free);

	l_free(nlmon);
}
