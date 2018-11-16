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

#include <errno.h>

#include <ell/ell.h>

#include "src/util.h"
#include "src/crypto.h"
#include "src/ie.h"

static const uint8_t ieee_oui[3] = { 0x00, 0x0f, 0xac };
static const uint8_t microsoft_oui[3] = { 0x00, 0x50, 0xf2 };

void ie_tlv_iter_init(struct ie_tlv_iter *iter, const unsigned char *tlv,
			unsigned int len)
{
	iter->tlv = tlv;
	iter->max = len;
	iter->pos = 0;
}

void ie_tlv_iter_recurse(struct ie_tlv_iter *iter,
				struct ie_tlv_iter *recurse)
{
	recurse->tlv = iter->data;
	recurse->max = iter->len;
	recurse->pos = 0;
}

bool ie_tlv_iter_next(struct ie_tlv_iter *iter)
{
	const unsigned char *tlv = iter->tlv + iter->pos;
	const unsigned char *end = iter->tlv + iter->max;
	unsigned int tag;
	unsigned int len;

	if (iter->pos + 1 >= iter->max)
		return false;

	tag = *tlv++;
	len = *tlv++;

	if (tag == IE_TYPE_EXTENSION) {
		if (iter->pos + 2 >= iter->max || len < 1)
			return false;

		tag = 256 + *tlv++;
		len--;
	}

	if (tlv + len > end)
		return false;

	iter->tag = tag;
	iter->len = len;
	iter->data = tlv;

	iter->pos = tlv + len - iter->tlv;

	return true;
}

/*
 * Concatenate all vendor IEs with a given OUI + type.
 *
 * Returns a newly allocated buffer with the contents of the matching ies
 * copied into it.  @out_len is set to the overall size of the contents.
 * If no matching elements were found, NULL is returned and @out_len is
 * set to -ENOENT.
 */
static void *ie_tlv_vendor_ie_concat(const unsigned char oui[],
					unsigned char type,
					const unsigned char *ies,
					unsigned int len,
					ssize_t *out_len)
{
	struct ie_tlv_iter iter;
	const unsigned char *data;
	unsigned int ie_len;
	unsigned int concat_len = 0;
	unsigned char *ret;

	ie_tlv_iter_init(&iter, ies, len);

	while (ie_tlv_iter_next(&iter)) {
		if (ie_tlv_iter_get_tag(&iter) != IE_TYPE_VENDOR_SPECIFIC)
			continue;

		ie_len = ie_tlv_iter_get_length(&iter);
		if (ie_len < 4)
			continue;

		data = ie_tlv_iter_get_data(&iter);

		if (memcmp(data, oui, 3))
			continue;

		if (data[3] != type)
			continue;

		concat_len += ie_len - 4;
	}

	if (concat_len == 0) {
		if (out_len)
			*out_len = -ENOENT;

		return NULL;
	}

	ie_tlv_iter_init(&iter, ies, len);
	ret = l_malloc(concat_len);

	concat_len = 0;

	while (ie_tlv_iter_next(&iter)) {
		if (ie_tlv_iter_get_tag(&iter) != IE_TYPE_VENDOR_SPECIFIC)
			continue;

		ie_len = ie_tlv_iter_get_length(&iter);
		if (ie_len < 4)
			continue;

		data = ie_tlv_iter_get_data(&iter);

		if (memcmp(data, oui, 3))
			continue;

		if (data[3] != type)
			continue;

		memcpy(ret + concat_len, data + 4, ie_len - 4);
		concat_len += ie_len - 4;
	}

	if (out_len)
		*out_len = concat_len;

	return ret;
}

/*
 * Wi-Fi Simple Configuration v2.0.5, Section 8.2:
 * "There may be more than one instance of the Wi-Fi Simple Configuration
 * Information Element in a single 802.11 management frame. If multiple
 * Information Elements are present, the Wi-Fi Simple Configuration data
 * consists of the concatenation of the Data components of those Information
 * Elements (the order of these elements in the original packet shall be
 * preserved when concatenating Data components)."
 */
void *ie_tlv_extract_wsc_payload(const unsigned char *ies, size_t len,
							ssize_t *out_len)
{
	return ie_tlv_vendor_ie_concat(microsoft_oui, 0x04, ies, len, out_len);
}

/*
 * Encapsulate & Fragment data into Vendor IE with a given OUI + type
 *
 * Returns a newly allocated buffer with the contents of encapsulated into
 * multiple vendor IE.  @out_len is set to the overall size of the contents.
 */
static void *ie_tlv_vendor_ie_encapsulate(const unsigned char oui[],
					uint8_t type,
					const void *data, size_t len,
					size_t *out_len)
{
	size_t overhead;
	size_t ie_len;
	size_t offset;
	uint8_t *ret;

	/*
	 * Each Vendor IE can contain up to 251 bytes of data.
	 * 255 byte maximum length - 3 for oui and 1 for type
	 */
	overhead = (len + 250) / 251 * 6;

	ret = l_malloc(len + overhead);

	if (out_len)
		*out_len = len + overhead;

	offset = 0;

	while (len) {
		ie_len = len <= 251 ? len : 251;
		ret[offset++] = IE_TYPE_VENDOR_SPECIFIC;
		ret[offset++] = ie_len + 4;
		memcpy(ret + offset, oui, 3);
		offset += 3;
		ret[offset++] = type;
		memcpy(ret + offset, data, ie_len);

		data += ie_len;
		len -= ie_len;
	}

	return ret;
}

void *ie_tlv_encapsulate_wsc_payload(const uint8_t *data, size_t len,
								size_t *out_len)
{
	return ie_tlv_vendor_ie_encapsulate(microsoft_oui, 0x04,
							data, len, out_len);
}

#define TLV_HEADER_LEN 2

static bool ie_tlv_builder_init_recurse(struct ie_tlv_builder *builder,
					unsigned char *tlv, unsigned int size)
{
	if (!builder)
		return false;

	if (!tlv) {
		memset(builder->buf, 0, MAX_BUILDER_SIZE);
		builder->tlv = builder->buf;
		builder->max = MAX_BUILDER_SIZE;
	} else {
		builder->tlv = tlv;
		builder->max = size;
	}

	builder->pos = 0;
	builder->parent = NULL;
	builder->tag = 0xffff;
	builder->len = 0;

	return true;
}

bool ie_tlv_builder_init(struct ie_tlv_builder *builder)
{
	return ie_tlv_builder_init_recurse(builder, NULL, 0);
}

static void ie_tlv_builder_write_header(struct ie_tlv_builder *builder)
{
	unsigned char *tlv = builder->tlv + builder->pos;

	if (builder->tag < 256) {
		tlv[0] = builder->tag;
		tlv[1] = builder->len;
	} else {
		tlv[0] = IE_TYPE_EXTENSION;
		tlv[1] = builder->len + 1;
		tlv[2] = builder->tag - 256;
	}
}

bool ie_tlv_builder_set_length(struct ie_tlv_builder *builder,
					unsigned int new_len)
{
	unsigned int new_pos = builder->pos + TLV_HEADER_LEN + new_len;

	if (builder->tag >= 256)
		new_pos += 1;

	if (new_pos > builder->max)
		return false;

	if (builder->parent)
		ie_tlv_builder_set_length(builder->parent, new_pos);

	builder->len = new_len;

	return true;
}

bool ie_tlv_builder_next(struct ie_tlv_builder *builder, unsigned int new_tag)
{
	if (new_tag > 0x1ff)
		return false;

	if (builder->tag != 0xffff) {
		ie_tlv_builder_write_header(builder);
		builder->pos += TLV_HEADER_LEN + builder->tlv[builder->pos + 1];
	}

	builder->tag = new_tag;

	return ie_tlv_builder_set_length(builder, 0);
}

unsigned char *ie_tlv_builder_get_data(struct ie_tlv_builder *builder)
{
	return builder->tlv + TLV_HEADER_LEN + builder->pos +
		(builder->tag >= 256 ? 1 : 0);
}

bool ie_tlv_builder_recurse(struct ie_tlv_builder *builder,
					struct ie_tlv_builder *recurse)
{
	unsigned char *end = builder->buf + builder->max;
	unsigned char *data = ie_tlv_builder_get_data(builder);

	if (!ie_tlv_builder_init_recurse(recurse, data, end - data))
		return false;

	recurse->parent = builder;

	return true;
}

void ie_tlv_builder_finalize(struct ie_tlv_builder *builder,
			unsigned int *out_len)
{
	unsigned int len = 0;

	if (builder->tag != 0xffff) {
		ie_tlv_builder_write_header(builder);

		len = builder->pos + TLV_HEADER_LEN +
			builder->tlv[builder->pos + 1];
	}

	if (out_len)
		*out_len = len;
}

/*
 * Converts RSN cipher suite into an unsigned integer suitable to be used
 * by nl80211.  The enumeration is the same as found in crypto.h
 *
 * If the suite value is invalid, this function returns 0.
 */
uint32_t ie_rsn_cipher_suite_to_cipher(enum ie_rsn_cipher_suite suite)
{
	switch (suite) {
	case IE_RSN_CIPHER_SUITE_CCMP:
		return CRYPTO_CIPHER_CCMP;
	case IE_RSN_CIPHER_SUITE_TKIP:
		return CRYPTO_CIPHER_TKIP;
	case IE_RSN_CIPHER_SUITE_WEP40:
		return CRYPTO_CIPHER_WEP40;
	case IE_RSN_CIPHER_SUITE_WEP104:
		return CRYPTO_CIPHER_WEP104;
	case IE_RSN_CIPHER_SUITE_BIP:
		return CRYPTO_CIPHER_BIP;
	default:
		return 0;
	}
}

/* 802.11, Section 8.4.2.27.2 */
static bool ie_parse_cipher_suite(const uint8_t *data,
					enum ie_rsn_cipher_suite *out)
{
	/*
	 * Compare the OUI to the ones we know.  OUI Format is found in
	 * Figure 8-187 of 802.11
	 */
	if (!memcmp(data, ieee_oui, 3)) {
		/* Suite type from Table 8-99 */
		switch (data[3]) {
		case 0:
			*out = IE_RSN_CIPHER_SUITE_USE_GROUP_CIPHER;
			return true;
		case 1:
			*out = IE_RSN_CIPHER_SUITE_WEP40;
			return true;
		case 2:
			*out = IE_RSN_CIPHER_SUITE_TKIP;
			return true;
		case 4:
			*out = IE_RSN_CIPHER_SUITE_CCMP;
			return true;
		case 5:
			*out = IE_RSN_CIPHER_SUITE_WEP104;
			return true;
		case 6:
			*out = IE_RSN_CIPHER_SUITE_BIP;
			return true;
		case 7:
			*out = IE_RSN_CIPHER_SUITE_NO_GROUP_TRAFFIC;
			return true;
		default:
			return false;
		}
	}

	return false;
}

/* 802.11, Section 8.4.2.27.2 */
static int ie_parse_akm_suite(const uint8_t *data,
					enum ie_rsn_akm_suite *out)
{
	/*
	 * Compare the OUI to the ones we know.  OUI Format is found in
	 * Figure 8-187 of 802.11
	 */
	if (!memcmp(data, ieee_oui, 3)) {
		/* Suite type from Table 8-101 */
		switch (data[3]) {
		case 0:
			return -EINVAL;
		case 1:
			*out = IE_RSN_AKM_SUITE_8021X;
			return 0;
		case 2:
			*out = IE_RSN_AKM_SUITE_PSK;
			return 0;
		case 3:
			*out = IE_RSN_AKM_SUITE_FT_OVER_8021X;
			return 0;
		case 4:
			*out = IE_RSN_AKM_SUITE_FT_USING_PSK;
			return 0;
		case 5:
			*out = IE_RSN_AKM_SUITE_8021X_SHA256;
			return 0;
		case 6:
			*out = IE_RSN_AKM_SUITE_PSK_SHA256;
			return 0;
		case 7:
			*out = IE_RSN_AKM_SUITE_TDLS;
			return 0;
		case 8:
			*out = IE_RSN_AKM_SUITE_SAE_SHA256;
			return 0;
		case 9:
			*out = IE_RSN_AKM_SUITE_FT_OVER_SAE_SHA256;
			return 0;
		case 10:
			*out = IE_RSN_AKM_SUITE_AP_PEER_KEY_SHA256;
			return 0;
		case 11:
			*out = IE_RSN_AKM_SUITE_8021X_SUITE_B_SHA256;
			return 0;
		case 12:
			*out = IE_RSN_AKM_SUITE_8021X_SUITE_B_SHA384;
			return 0;
		case 13:
			*out = IE_RSN_AKM_SUITE_FT_OVER_8021X_SHA384;
			return 0;
		case 18:
			*out = IE_RSN_AKM_SUITE_OWE;
			return 0;
		default:
			return -ENOENT;
		}
	}

	return -ENOENT;
}

static bool ie_parse_group_cipher(const uint8_t *data,
					enum ie_rsn_cipher_suite *out)
{
	enum ie_rsn_cipher_suite tmp;

	bool r = ie_parse_cipher_suite(data, &tmp);

	if (!r)
		return r;

	switch (tmp) {
	case IE_RSN_CIPHER_SUITE_CCMP:
	case IE_RSN_CIPHER_SUITE_TKIP:
	case IE_RSN_CIPHER_SUITE_WEP104:
	case IE_RSN_CIPHER_SUITE_WEP40:
	case IE_RSN_CIPHER_SUITE_NO_GROUP_TRAFFIC:
		break;
	default:
		return false;
	}

	*out = tmp;
	return true;
}

static bool ie_parse_pairwise_cipher(const uint8_t *data,
					enum ie_rsn_cipher_suite *out)
{
	enum ie_rsn_cipher_suite tmp;

	bool r = ie_parse_cipher_suite(data, &tmp);

	if (!r)
		return r;

	switch (tmp) {
	case IE_RSN_CIPHER_SUITE_CCMP:
	case IE_RSN_CIPHER_SUITE_TKIP:
	case IE_RSN_CIPHER_SUITE_WEP104:
	case IE_RSN_CIPHER_SUITE_WEP40:
	case IE_RSN_CIPHER_SUITE_USE_GROUP_CIPHER:
		break;
	default:
		return false;
	}

	*out = tmp;
	return true;
}

static bool ie_parse_group_management_cipher(const uint8_t *data,
					enum ie_rsn_cipher_suite *out)
{
	enum ie_rsn_cipher_suite tmp;

	bool r = ie_parse_cipher_suite(data, &tmp);

	if (!r)
		return r;

	switch (tmp) {
	case IE_RSN_CIPHER_SUITE_BIP:
		break;
	default:
		return false;
	}

	*out = tmp;
	return true;
}

#define RSNE_ADVANCE(data, len, step)	\
	data += step;			\
	len -= step;			\
					\
	if (len == 0)			\
		goto done		\

int ie_parse_rsne(struct ie_tlv_iter *iter, struct ie_rsn_info *out_info)
{
	const uint8_t *data = iter->data;
	size_t len = iter->len;
	uint16_t version;
	struct ie_rsn_info info;
	uint16_t count;
	uint16_t i;

	memset(&info, 0, sizeof(info));
	info.group_cipher = IE_RSN_CIPHER_SUITE_CCMP;
	info.pairwise_ciphers = IE_RSN_CIPHER_SUITE_CCMP;
	info.akm_suites = IE_RSN_AKM_SUITE_8021X;

	/* Parse Version field */
	if (len < 2)
		return -EMSGSIZE;

	version = l_get_le16(data);
	if (version != 0x01)
		return -EBADMSG;

	RSNE_ADVANCE(data, len, 2);

	/* Parse Group Cipher Suite field */
	if (len < 4)
		return -EBADMSG;

	if (!ie_parse_group_cipher(data, &info.group_cipher))
		return -ERANGE;

	RSNE_ADVANCE(data, len, 4);

	/* Parse Pairwise Cipher Suite Count field */
	if (len < 2)
		return -EBADMSG;

	count = l_get_le16(data);

	/*
	 * The spec doesn't seem to explicitly say what to do in this case,
	 * so we assume this situation is invalid.
	 */
	if (count == 0)
		return -EINVAL;

	data += 2;
	len -= 2;

	if (len < 4 * count)
		return -EBADMSG;

	/* Parse Pairwise Cipher Suite List field */
	for (i = 0, info.pairwise_ciphers = 0; i < count; i++) {
		enum ie_rsn_cipher_suite suite;

		if (!ie_parse_pairwise_cipher(data + i * 4, &suite))
			return -ERANGE;

		info.pairwise_ciphers |= suite;
	}

	RSNE_ADVANCE(data, len, count * 4);

	/* Parse AKM Suite Count field */
	if (len < 2)
		return -EBADMSG;

	count = l_get_le16(data);
	if (count == 0)
		return -EINVAL;

	data += 2;
	len -= 2;

	if (len < 4 * count)
		return -EBADMSG;

	/* Parse AKM Suite List field */
	for (i = 0, info.akm_suites = 0; i < count; i++) {
		enum ie_rsn_akm_suite suite;
		int ret;

		ret = ie_parse_akm_suite(data + i * 4, &suite);
		switch (ret) {
		case 0:
			info.akm_suites |= suite;
			break;
		case -ENOENT:
			/* Skip unknown or vendor specific AKMs */
			break;
		default:
			return -EBADMSG;
		}
	}

	RSNE_ADVANCE(data, len, count * 4);

	if (len < 2)
		return -EBADMSG;

	info.preauthentication = util_is_bit_set(data[0], 0);
	info.no_pairwise = util_is_bit_set(data[0], 1);
	info.ptksa_replay_counter = util_bit_field(data[0], 2, 2);
	info.gtksa_replay_counter = util_bit_field(data[0], 4, 2);
	info.mfpr = util_is_bit_set(data[0], 6);
	info.mfpc = util_is_bit_set(data[0], 7);
	info.peerkey_enabled = util_is_bit_set(data[1], 1);
	info.spp_a_msdu_capable = util_is_bit_set(data[1], 2);
	info.spp_a_msdu_required = util_is_bit_set(data[1], 3);
	info.pbac = util_is_bit_set(data[1], 4);
	info.extended_key_id = util_is_bit_set(data[1], 5);

	/*
	 * BIP—default group management cipher suite in an RSNA with
	 * management frame protection enabled
	 */
	if (info.mfpc)
		info.group_management_cipher = IE_RSN_CIPHER_SUITE_BIP;

	RSNE_ADVANCE(data, len, 2);

	/* Parse PMKID Count field */
	if (len < 2)
		return -EBADMSG;

	info.num_pmkids = l_get_le16(data);
	RSNE_ADVANCE(data, len, 2);

	if (info.num_pmkids > 0) {
		if (len < 16 * info.num_pmkids)
			return -EBADMSG;

		/*
		 * Parse PMKID List field.
		 *
		 * We simply assign the pointer to the PMKIDs to the structure.
		 * The PMKIDs are fixed size, 16 bytes each.
		 */
		info.pmkids = data;
		RSNE_ADVANCE(data, len, info.num_pmkids * 16);
	}

	/* Parse Group Management Cipher Suite field */
	if (len < 4)
		return -EBADMSG;

	if (!ie_parse_group_management_cipher(data,
						&info.group_management_cipher))
		return -ERANGE;

	RSNE_ADVANCE(data, len, 4);

	return -EBADMSG;

done:
	if (out_info)
		memcpy(out_info, &info, sizeof(info));

	return 0;
}

int ie_parse_rsne_from_data(const uint8_t *data, size_t len,
				struct ie_rsn_info *info)
{
	struct ie_tlv_iter iter;

	ie_tlv_iter_init(&iter, data, len);

	if (!ie_tlv_iter_next(&iter))
		return -EMSGSIZE;

	if (ie_tlv_iter_get_tag(&iter) != IE_TYPE_RSN)
		return -EPROTOTYPE;

	return ie_parse_rsne(&iter, info);
}

/*
 * 802.11, Section 8.4.2.27.2
 * 802.11i, Section 7.3.2.25.1 and WPA_80211_v3_1 Section 2.1
 */
static bool ie_build_cipher_suite(uint8_t *data, const uint8_t *oui,
					const enum ie_rsn_cipher_suite suite)
{
	switch (suite) {
	case IE_RSN_CIPHER_SUITE_USE_GROUP_CIPHER:
		memcpy(data, oui, 3);
		data[3] = 0;
		return true;
	case IE_RSN_CIPHER_SUITE_WEP40:
		memcpy(data, oui, 3);
		data[3] = 1;
		return true;
	case IE_RSN_CIPHER_SUITE_TKIP:
		memcpy(data, oui, 3);
		data[3] = 2;
		return true;
	case IE_RSN_CIPHER_SUITE_CCMP:
		memcpy(data, oui, 3);
		data[3] = 4;
		return true;
	case IE_RSN_CIPHER_SUITE_WEP104:
		memcpy(data, oui, 3);
		data[3] = 5;
		return true;
	case IE_RSN_CIPHER_SUITE_BIP:
		memcpy(data, oui, 3);
		data[3] = 6;
		return true;
	case IE_RSN_CIPHER_SUITE_NO_GROUP_TRAFFIC:
		memcpy(data, oui, 3);
		data[3] = 7;
		return true;
	}

	return false;
}

#define RETURN_AKM(data, oui, id)	\
	memcpy((data), (oui), 3);	\
	(data)[3] = (id);		\
	return true;

/* 802.11-2016, Section 9.4.2.25.3 */
static bool ie_build_rsn_akm_suite(uint8_t *data, enum ie_rsn_akm_suite suite)
{
	switch (suite) {
	case IE_RSN_AKM_SUITE_8021X:
		RETURN_AKM(data, ieee_oui, 1);
	case IE_RSN_AKM_SUITE_PSK:
		RETURN_AKM(data, ieee_oui, 2);
	case IE_RSN_AKM_SUITE_FT_OVER_8021X:
		RETURN_AKM(data, ieee_oui, 3);
	case IE_RSN_AKM_SUITE_FT_USING_PSK:
		RETURN_AKM(data, ieee_oui, 4);
	case IE_RSN_AKM_SUITE_8021X_SHA256:
		RETURN_AKM(data, ieee_oui, 5);
	case IE_RSN_AKM_SUITE_PSK_SHA256:
		RETURN_AKM(data, ieee_oui, 6);
	case IE_RSN_AKM_SUITE_TDLS:
		RETURN_AKM(data, ieee_oui, 7);
	case IE_RSN_AKM_SUITE_SAE_SHA256:
		RETURN_AKM(data, ieee_oui, 8);
	case IE_RSN_AKM_SUITE_FT_OVER_SAE_SHA256:
		RETURN_AKM(data, ieee_oui, 9);
	case IE_RSN_AKM_SUITE_AP_PEER_KEY_SHA256:
		RETURN_AKM(data, ieee_oui, 10);
	case IE_RSN_AKM_SUITE_8021X_SUITE_B_SHA256:
		RETURN_AKM(data, ieee_oui, 11);
	case IE_RSN_AKM_SUITE_8021X_SUITE_B_SHA384:
		RETURN_AKM(data, ieee_oui, 12);
	case IE_RSN_AKM_SUITE_FT_OVER_8021X_SHA384:
		RETURN_AKM(data, ieee_oui, 13);
	case IE_RSN_AKM_SUITE_OWE:
		RETURN_AKM(data, ieee_oui, 18);
	}

	return false;
}

/* 802.11i, Section 7.3.2.25.2 and WPA_80211_v3_1 Section 2.1 */
static bool ie_build_wpa_akm_suite(uint8_t *data, enum ie_rsn_akm_suite suite)
{
	switch (suite) {
	case IE_RSN_AKM_SUITE_8021X:
		RETURN_AKM(data, microsoft_oui, 1);
	case IE_RSN_AKM_SUITE_PSK:
		RETURN_AKM(data, microsoft_oui, 2);
	default:
		break;
	}

	return false;
}

/*
 * Generate an RSNE IE based on the information found in info.
 * The to array must be 256 bytes in size
 *
 * In theory it is possible to generate 257 byte IE RSNs (1 byte for IE Type,
 * 1 byte for Length and 255 bytes of data) but we don't support this
 * possibility.
 */
bool ie_build_rsne(const struct ie_rsn_info *info, uint8_t *to)
{
	/* These are the only valid pairwise suites */
	static enum ie_rsn_cipher_suite pairwise_suites[] = {
		IE_RSN_CIPHER_SUITE_CCMP,
		IE_RSN_CIPHER_SUITE_TKIP,
		IE_RSN_CIPHER_SUITE_WEP104,
		IE_RSN_CIPHER_SUITE_WEP40,
		IE_RSN_CIPHER_SUITE_USE_GROUP_CIPHER,
	};
	unsigned int pos;
	unsigned int i;
	uint8_t *countptr;
	uint16_t count;
	enum ie_rsn_akm_suite akm_suite;

	to[0] = IE_TYPE_RSN;

	/* Version field, always 1 */
	pos = 2;
	l_put_le16(1, to + pos);
	pos += 2;

	/* Group Data Cipher Suite */
	if (!ie_build_cipher_suite(to + pos, ieee_oui, info->group_cipher))
		return false;

	pos += 4;

	/* Save position for Pairwise Cipher Suite Count field */
	countptr = to + pos;
	pos += 2;

	for (i = 0, count = 0; i < L_ARRAY_SIZE(pairwise_suites); i++) {
		enum ie_rsn_cipher_suite suite = pairwise_suites[i];

		if (!(info->pairwise_ciphers & suite))
			continue;

		if (pos + 4 > 242)
			return false;

		if (!ie_build_cipher_suite(to + pos, ieee_oui, suite))
			return false;

		pos += 4;
		count += 1;
	}

	l_put_le16(count, countptr);

	/* Save position for AKM Suite Count field */
	countptr = to + pos;
	pos += 2;

	akm_suite = IE_RSN_AKM_SUITE_8021X;
	count = 0;

	for (count = 0, akm_suite = IE_RSN_AKM_SUITE_8021X;
			akm_suite <= IE_RSN_AKM_SUITE_OWE;
				akm_suite <<= 1) {
		if (!(info->akm_suites & akm_suite))
			continue;

		if (pos + 4 > 248)
			return false;

		if (!ie_build_rsn_akm_suite(to + pos, akm_suite))
			return false;

		pos += 4;
		count += 1;
	}

	l_put_le16(count, countptr);

	/* Bits 0 - 7 of RSNE Capabilities field */
	to[pos] = 0;

	if (info->preauthentication)
		to[pos] |= 0x1;

	if (info->no_pairwise)
		to[pos] |= 0x2;

	to[pos] |= info->ptksa_replay_counter << 2;
	to[pos] |= info->gtksa_replay_counter << 4;

	if (info->mfpr)
		to[pos] |= 0x40;

	if (info->mfpc)
		to[pos] |= 0x80;

	pos += 1;

	/* Bits 8 - 15 of RSNE Capabilities field */
	to[pos] = 0;

	if (info->peerkey_enabled)
		to[pos] |= 0x2;

	if (info->spp_a_msdu_capable)
		to[pos] |= 0x4;

	if (info->spp_a_msdu_required)
		to[pos] |= 0x8;

	if (info->pbac)
		to[pos] |= 0x10;

	if (info->extended_key_id)
		to[pos] |= 0x20;

	pos += 1;

	/* Short hand the generated RSNE if possible */
	if (info->num_pmkids == 0) {
		/* No Group Management Cipher Suite */
		if (to[pos - 2] == 0 && to[pos - 1] == 0) {
			pos -= 2;
			goto done;
		} else if (!info->mfpc)
			goto done;
		else if (info->group_management_cipher ==
				IE_RSN_CIPHER_SUITE_BIP)
			goto done;
	}

	/* PMKID Count */
	l_put_le16(info->num_pmkids, to + pos);
	pos += 2;

	if (pos + info->num_pmkids * 16 > 252)
		return false;

	/* PMKID List */
	memcpy(to + pos, info->pmkids, 16 * info->num_pmkids);
	pos += 16 * info->num_pmkids;

	if (!info->mfpc)
		goto done;

	if (info->group_management_cipher == IE_RSN_CIPHER_SUITE_BIP)
		goto done;

	/* Group Management Cipher Suite */
	if (!ie_build_cipher_suite(to, ieee_oui, info->group_management_cipher))
		return false;

	pos += 4;

done:
	to[1] = pos - 2;

	return true;
}

/* 802.11i-2004, Section 7.3.2.25.1 and WPA_80211_v3_1 Section 2.1 */
static bool ie_parse_wpa_cipher_suite(const uint8_t *data,
					enum ie_rsn_cipher_suite *out)
{
	/*
	 * Compare the OUI to the ones we know.  OUI Format is found in
	 * Figure 8-187 of 802.11
	 */
	if (!memcmp(data, microsoft_oui, 3)) {
		/* Suite type from 802.11i-2004, Table 20da */
		switch (data[3]) {
		case 0:
			*out = IE_RSN_CIPHER_SUITE_USE_GROUP_CIPHER;
			return true;
		case 1:
			*out = IE_RSN_CIPHER_SUITE_WEP40;
			return true;
		case 2:
			*out = IE_RSN_CIPHER_SUITE_TKIP;
			return true;
		case 4:
			*out = IE_RSN_CIPHER_SUITE_CCMP;
			return true;
		case 5:
			*out = IE_RSN_CIPHER_SUITE_WEP104;
			return true;
		default:
			return false;
		}
	}

	return false;
}

/* 802.11i-2004, Section 7.3.2.25.2 and WPA_80211_v3_1 Section 2.1 */
static bool ie_parse_wpa_akm_suite(const uint8_t *data,
					enum ie_rsn_akm_suite *out)
{
	/*
	 * Compare the OUI to the ones we know.  OUI Format is found in
	 * Figure 8-187 of 802.11
	 */
	if (!memcmp(data, microsoft_oui, 3)) {
		/* Suite type from 802.11i-2004, Table 20dc */
		switch (data[3]) {
		case 1:
			*out = IE_RSN_AKM_SUITE_8021X;
			return true;
		case 2:
			*out = IE_RSN_AKM_SUITE_PSK;
			return true;
		default:
			return false;
		}
	}

	return false;
}

static bool ie_parse_wpa_group_cipher(const uint8_t *data,
					enum ie_rsn_cipher_suite *out)
{
	enum ie_rsn_cipher_suite tmp;

	bool r = ie_parse_wpa_cipher_suite(data, &tmp);

	if (!r)
		return r;

	switch (tmp) {
	case IE_RSN_CIPHER_SUITE_CCMP:
	case IE_RSN_CIPHER_SUITE_TKIP:
	case IE_RSN_CIPHER_SUITE_WEP104:
	case IE_RSN_CIPHER_SUITE_WEP40:
		break;
	default:
		return false;
	}

	*out = tmp;
	return true;
}

static bool ie_parse_wpa_pairwise_cipher(const uint8_t *data,
					enum ie_rsn_cipher_suite *out)
{
	enum ie_rsn_cipher_suite tmp;

	bool r = ie_parse_wpa_cipher_suite(data, &tmp);

	if (!r)
		return r;

	switch (tmp) {
	case IE_RSN_CIPHER_SUITE_CCMP:
	case IE_RSN_CIPHER_SUITE_TKIP:
	case IE_RSN_CIPHER_SUITE_WEP104:
	case IE_RSN_CIPHER_SUITE_WEP40:
	/* TODO : not sure about GROUP_CIPHER */
		break;
	default:
		return false;
	}

	*out = tmp;
	return true;
}

bool is_ie_wpa_ie(const uint8_t *data, uint8_t len)
{
	if (!data || len < 6)
		return false;

	if ((!memcmp(data, microsoft_oui, 3) && data[3] == 1 &&
						l_get_le16(data + 4) == 1))
		return true;

	return false;
}

int ie_parse_wpa(struct ie_tlv_iter *iter, struct ie_rsn_info *out_info)
{
	const uint8_t *data = iter->data;
	size_t len = iter->len;
	struct ie_rsn_info info;
	uint16_t count;
	uint16_t i;

	if (!is_ie_wpa_ie(iter->data, iter->len))
		return -EINVAL;

	info.group_cipher = IE_RSN_CIPHER_SUITE_TKIP;
	info.pairwise_ciphers = IE_RSN_CIPHER_SUITE_TKIP;
	info.akm_suites = IE_RSN_AKM_SUITE_PSK;

	memset(&info, 0, sizeof(info));
	RSNE_ADVANCE(data, len, 6);

	/* Parse Group Cipher Suite field */
	if (len < 4)
		return -EBADMSG;

	if (!ie_parse_wpa_group_cipher(data, &info.group_cipher))
		return -ERANGE;

	RSNE_ADVANCE(data, len, 4);

	/* Parse Pairwise Cipher Suite Count field */
	if (len < 2)
		return -EBADMSG;

	count = l_get_le16(data);

	/*
	 * The spec doesn't seem to explicitly say what to do in this case,
	 * so we assume this situation is invalid.
	 */
	if (count == 0)
		return -EINVAL;

	data += 2;
	len -= 2;

	if (len < 4 * count)
		return -EBADMSG;

	/* Parse Pairwise Cipher Suite List field */
	for (i = 0, info.pairwise_ciphers = 0; i < count; i++) {
		enum ie_rsn_cipher_suite suite;

		if (!ie_parse_wpa_pairwise_cipher(data + i * 4, &suite))
			return -ERANGE;

		info.pairwise_ciphers |= suite;
	}

	RSNE_ADVANCE(data, len, count * 4);

	/* Parse AKM Suite Count field */
	if (len < 2)
		return -EBADMSG;

	count = l_get_le16(data);
	if (count == 0)
		return -EINVAL;

	data += 2;
	len -= 2;

	if (len < 4 * count)
		return -EBADMSG;

	/* Parse AKM Suite List field */
	for (i = 0, info.akm_suites = 0; i < count; i++) {
		enum ie_rsn_akm_suite suite;

		if (!ie_parse_wpa_akm_suite(data + i * 4, &suite))
			return -ERANGE;

		info.akm_suites |= suite;
	}

	RSNE_ADVANCE(data, len, count * 4);

	return -EBADMSG;

done:
	/*
	 * 802.11i, Section 7.3.2.25.1
	 * Use of CCMP as the group cipher suite with TKIP as the
	 * pairwise cipher suite shall not be supported.
	 */
	if (info.group_cipher & IE_RSN_CIPHER_SUITE_CCMP &&
			info.pairwise_ciphers & IE_RSN_CIPHER_SUITE_TKIP)
		return -EBADMSG;

	if (out_info)
		memcpy(out_info, &info, sizeof(info));

	return 0;
}

int ie_parse_wpa_from_data(const uint8_t *data, size_t len,
						struct ie_rsn_info *info)
{
	struct ie_tlv_iter iter;

	ie_tlv_iter_init(&iter, data, len);

	if (!ie_tlv_iter_next(&iter))
		return -EMSGSIZE;

	if (ie_tlv_iter_get_tag(&iter) != IE_TYPE_VENDOR_SPECIFIC)
		return -EPROTOTYPE;

	return ie_parse_wpa(&iter, info);
}

/*
 * Generate an WPA IE based on the information found in info.
 * The to array must be minimum of 19 bytes in size
 */
bool ie_build_wpa(const struct ie_rsn_info *info, uint8_t *to)
{
	/* These are the only valid pairwise suites */
	static enum ie_rsn_cipher_suite pairwise_suites[] = {
		IE_RSN_CIPHER_SUITE_CCMP,
		IE_RSN_CIPHER_SUITE_TKIP,
		IE_RSN_CIPHER_SUITE_WEP104,
		IE_RSN_CIPHER_SUITE_WEP40,
		/* TODO: not sure about USE_GROUP_CIPHER,*/
	};
	/* These are the only valid AKM suites */
	static enum ie_rsn_akm_suite akm_suites[] = {
		IE_RSN_AKM_SUITE_8021X,
		IE_RSN_AKM_SUITE_PSK,
	};
	unsigned int pos;
	unsigned int i;
	uint8_t *countptr;
	uint16_t count;

	/*
	 * 802.11i, Section 7.3.2.25.1
	 * Use of CCMP as the group cipher suite with TKIP as the
	 * pairwise cipher suite shall not be supported.
	 */
	if (info->group_cipher == IE_RSN_CIPHER_SUITE_CCMP &&
			info->pairwise_ciphers & IE_RSN_CIPHER_SUITE_TKIP)
		return false;

	to[0] = IE_TYPE_VENDOR_SPECIFIC;

	/* Vendor OUI and Type */
	pos = 2;
	memcpy(to + pos, microsoft_oui, 3);
	pos += 3;
	to[pos] = 1; /* OUI type 1 means WPA element */
	pos++;

	/* Version field, always 1 */
	l_put_le16(1, to + pos);
	pos += 2;

	/* Group Data Cipher Suite */
	if (!ie_build_cipher_suite(to + pos, microsoft_oui,
							info->group_cipher))
		return false;

	pos += 4;

	/* Save position for Pairwise Cipher Suite Count field */
	countptr = to + pos;
	pos += 2;

	for (i = 0, count = 0; i < L_ARRAY_SIZE(pairwise_suites); i++) {
		enum ie_rsn_cipher_suite suite = pairwise_suites[i];

		if (!(info->pairwise_ciphers & suite))
			continue;

		if (!ie_build_cipher_suite(to + pos, microsoft_oui, suite))
			return false;

		pos += 4;
		count += 1;
	}

	l_put_le16(count, countptr);

	/* Save position for AKM Suite Count field */
	countptr = to + pos;
	pos += 2;

	for (i = 0, count = 0; i < L_ARRAY_SIZE(akm_suites); i++) {
		enum ie_rsn_akm_suite suite = akm_suites[i];

		if (!(info->akm_suites & suite))
			continue;

		if (!ie_build_wpa_akm_suite(to + pos, suite))
			return false;

		pos += 4;
		count += 1;
	}

	l_put_le16(count, countptr);

	to[1] = pos - 2;

	return true;
}

int ie_parse_bss_load(struct ie_tlv_iter *iter, uint16_t *out_sta_count,
			uint8_t *out_channel_utilization,
			uint16_t *out_admission_capacity)
{
	const uint8_t *data;

	if (ie_tlv_iter_get_length(iter) != 5)
		return -EINVAL;

	data = ie_tlv_iter_get_data(iter);

	if (out_sta_count)
		*out_sta_count = data[0] | data[1] << 8;

	if (out_channel_utilization)
		*out_channel_utilization = data[2];

	if (out_admission_capacity)
		*out_admission_capacity = data[3] | data[4] << 8;

	return 0;
}

int ie_parse_bss_load_from_data(const uint8_t *data, uint8_t len,
				uint16_t *out_sta_count,
				uint8_t *out_channel_utilization,
				uint16_t *out_admission_capacity)
{
	struct ie_tlv_iter iter;

	ie_tlv_iter_init(&iter, data, len);

	if (!ie_tlv_iter_next(&iter))
		return -EMSGSIZE;

	if (ie_tlv_iter_get_tag(&iter) != IE_TYPE_BSS_LOAD)
		return -EPROTOTYPE;

	return ie_parse_bss_load(&iter, out_sta_count,
			out_channel_utilization, out_admission_capacity);
}

int ie_parse_supported_rates(struct ie_tlv_iter *iter,
				struct l_uintset **set)
{
	const uint8_t *rates;
	unsigned int len;
	unsigned int i;

	len = ie_tlv_iter_get_length(iter);

	if (ie_tlv_iter_get_tag(iter) == IE_TYPE_SUPPORTED_RATES && len == 0)
		return -EINVAL;

	rates = ie_tlv_iter_get_data(iter);

	if (!*set)
		*set = l_uintset_new(108);

	for (i = 0; i < len; i++) {
		if (rates[i] == 0xff)
			continue;

		l_uintset_put(*set, rates[i] & 0x7f);
	}

	return 0;
}

int ie_parse_supported_rates_from_data(const uint8_t *data, uint8_t len,
				struct l_uintset **set)
{
	struct ie_tlv_iter iter;
	uint8_t tag;

	ie_tlv_iter_init(&iter, data, len);

	if (!ie_tlv_iter_next(&iter))
		return -EMSGSIZE;

	tag = ie_tlv_iter_get_tag(&iter);

	if (tag != IE_TYPE_SUPPORTED_RATES &&
			tag != IE_TYPE_EXTENDED_SUPPORTED_RATES)
		return -EPROTOTYPE;

	return ie_parse_supported_rates(&iter, set);
}

int ie_parse_mobility_domain(struct ie_tlv_iter *iter, uint16_t *mdid,
				bool *ft_over_ds, bool *resource_req)
{
	const uint8_t *data;

	if (ie_tlv_iter_get_length(iter) != 3)
		return -EINVAL;

	data = ie_tlv_iter_get_data(iter);

	if (mdid)
		*mdid = l_get_le16(data);

	if (ft_over_ds)
		*ft_over_ds = (data[2] & 0x01) > 0;

	if (resource_req)
		*resource_req = (data[2] & 0x02) > 0;

	return 0;
}

int ie_parse_mobility_domain_from_data(const uint8_t *data, uint8_t len,
				uint16_t *mdid,
				bool *ft_over_ds, bool *resource_req)
{
	struct ie_tlv_iter iter;

	ie_tlv_iter_init(&iter, data, len);

	if (!ie_tlv_iter_next(&iter))
		return -EMSGSIZE;

	if (ie_tlv_iter_get_tag(&iter) != IE_TYPE_MOBILITY_DOMAIN)
		return -EPROTOTYPE;

	return ie_parse_mobility_domain(&iter, mdid, ft_over_ds, resource_req);
}

bool ie_build_mobility_domain(uint16_t mdid, bool ft_over_ds, bool resource_req,
				uint8_t *to)
{
	*to++ = IE_TYPE_MOBILITY_DOMAIN;

	*to++ = 3;

	l_put_le16(mdid, to);
	to[2] =
		(ft_over_ds ? 0x01 : 0) |
		(resource_req ? 0x02 : 0);

	return true;
}

int ie_parse_fast_bss_transition(struct ie_tlv_iter *iter,
				struct ie_ft_info *info)
{
	const uint8_t *data;
	uint8_t len, subelem_id, subelem_len;

	len = ie_tlv_iter_get_length(iter);
	if (len < 82)
		return -EINVAL;

	data = ie_tlv_iter_get_data(iter);

	memset(info, 0, sizeof(*info));

	info->mic_element_count = data[1];

	memcpy(info->mic, data + 2, 16);

	memcpy(info->anonce, data + 18, 32);

	memcpy(info->snonce, data + 50, 32);

	len -= 82;
	data += 82;

	while (len >= 2) {
		subelem_id = *data++;
		subelem_len = *data++;

		switch (subelem_id) {
		case 1:
			if (subelem_len != 6)
				return -EINVAL;

			memcpy(info->r1khid, data, 6);
			info->r1khid_present = true;

			break;

		case 2:
			if (subelem_len < 35 || subelem_len > 51)
				return -EINVAL;

			info->gtk_key_id = util_bit_field(data[0], 0, 2);
			info->gtk_len = data[2];

			/*
			 * Check Wrapped Key field length is Key Length plus
			 * padding (0 - 7 bytes) plus 8 bytes for AES key wrap.
			 */
			if (align_len(info->gtk_len, 8) + 8 != subelem_len - 11)
				return -EINVAL;

			memcpy(info->gtk_rsc, data + 3, 8);
			memcpy(info->gtk, data + 11, subelem_len - 11);

			break;
		case 3:

			if (subelem_len < 1 || subelem_len > 48)
				return -EINVAL;

			memcpy(info->r0khid, data, subelem_len);
			info->r0khid_len = subelem_len;

			break;

		case 4:
			if (subelem_len != 33)
				return -EINVAL;

			info->igtk_key_id = l_get_le16(data);
			memcpy(info->igtk_ipn, data + 2, 6);
			info->igtk_len = data[8];

			if (info->igtk_len > 16)
				return -EINVAL;

			memcpy(info->igtk, data + 9, subelem_len - 9);

			break;
		}

		data += subelem_len;
		len -= subelem_len + 2;
	}

	if (len)
		return -EINVAL;

	return 0;
}

int ie_parse_fast_bss_transition_from_data(const uint8_t *data, uint8_t len,
				struct ie_ft_info *info)
{
	struct ie_tlv_iter iter;

	ie_tlv_iter_init(&iter, data, len);

	if (!ie_tlv_iter_next(&iter))
		return -EMSGSIZE;

	if (ie_tlv_iter_get_tag(&iter) != IE_TYPE_FAST_BSS_TRANSITION)
		return -EPROTOTYPE;

	return ie_parse_fast_bss_transition(&iter, info);
}

bool ie_build_fast_bss_transition(const struct ie_ft_info *info, uint8_t *to)
{
	uint8_t *len;

	*to++ = IE_TYPE_FAST_BSS_TRANSITION;

	len = to++;
	*len = 82;

	to[0] = 0x00;
	to[1] = info->mic_element_count;

	memcpy(to + 2, info->mic, 16);

	memcpy(to + 18, info->anonce, 32);

	memcpy(to + 50, info->snonce, 32);

	to += 82;

	if (info->r1khid_present) {
		to[0] = 1;
		to[1] = 6;
		memcpy(to + 2, info->r1khid, 6);
		to += 8;
		*len += 8;
	}

	L_WARN_ON(info->gtk_len); /* Not implemented */

	if (info->r0khid_len) {
		to[0] = 3;
		to[1] = info->r0khid_len;
		memcpy(to + 2, info->r0khid, info->r0khid_len);
		to += 2 + info->r0khid_len;
		*len += 2 + info->r0khid_len;
	}

	L_WARN_ON(info->igtk_len); /* Not implemented */

	return true;
}

enum nr_subelem_id {
	NR_SUBELEM_ID_TSF_INFO			= 1,
	NR_SUBELEM_ID_CONDENSED_COUNTRY_STR	= 2,
	NR_SUBELEM_ID_BSS_TRANSITION_PREF	= 3,
	NR_SUBELEM_ID_BSS_TERMINATION_DURATION	= 4,
	NR_SUBELEM_ID_BEARING			= 5,
	NR_SUBELEM_ID_WIDE_BW_CHANNEL		= 6,
	/* Remaining defined subelements use the IE_TYPE_* ID values */
};

int ie_parse_neighbor_report(struct ie_tlv_iter *iter,
				struct ie_neighbor_report_info *info)
{
	unsigned int len = ie_tlv_iter_get_length(iter);
	const uint8_t *data = ie_tlv_iter_get_data(iter);
	struct ie_tlv_iter opt_iter;

	if (len < 13)
		return -EINVAL;

	memset(info, 0, sizeof(*info));

	memcpy(info->addr, data + 0, 6);

	info->ht = util_is_bit_set(data[8], 3);
	info->md = util_is_bit_set(data[8], 2);
	info->immediate_block_ack = util_is_bit_set(data[8], 1);
	info->delayed_block_ack = util_is_bit_set(data[8], 0);
	info->rm = util_is_bit_set(data[9], 7);
	info->apsd = util_is_bit_set(data[9], 6);
	info->qos = util_is_bit_set(data[9], 5);
	info->spectrum_mgmt = util_is_bit_set(data[9], 4);
	info->key_scope = util_is_bit_set(data[9], 3);
	info->security = util_is_bit_set(data[9], 2);
	info->reachable = util_bit_field(data[9], 0, 2);

	info->oper_class = data[10];

	info->channel_num = data[11];

	info->phy_type = data[12];

	ie_tlv_iter_init(&opt_iter, data + 13, len - 13);

	while (ie_tlv_iter_next(&opt_iter)) {
		if (ie_tlv_iter_get_tag(&opt_iter) !=
				NR_SUBELEM_ID_BSS_TRANSITION_PREF)
			continue;

		if (ie_tlv_iter_get_length(&opt_iter) != 1)
			continue;

		info->bss_transition_pref = ie_tlv_iter_get_data(&opt_iter)[0];
		info->bss_transition_pref_present = true;
	}

	return 0;
}
