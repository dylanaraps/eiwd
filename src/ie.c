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
#include "util.h"

#include "ie.h"

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

unsigned int ie_tlv_iter_get_tag(struct ie_tlv_iter *iter)
{
	return iter->tag;
}

bool ie_tlv_iter_next(struct ie_tlv_iter *iter)
{
	const unsigned char *tlv = iter->tlv + iter->pos;
	const unsigned char *end = iter->tlv + iter->max;
	unsigned int tag;
	unsigned int len;

	if (iter->pos >= iter->max)
		return false;

	tag = *tlv++;
	len = *tlv++;

	if (tlv + len > end)
		return false;

	iter->tag = tag;
	iter->len = len;
	iter->data = tlv;

	iter->pos = tlv + len - iter->tlv;

	return true;
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

	tlv[0] = builder->tag;
	tlv[1] = builder->len;
}

bool ie_tlv_builder_set_length(struct ie_tlv_builder *builder,
					unsigned int new_len)
{
	unsigned int new_pos = builder->pos + TLV_HEADER_LEN + new_len;

	if (new_pos > builder->max)
		return false;

	if (builder->parent)
		ie_tlv_builder_set_length(builder->parent, new_pos);

	builder->len = new_len;

	return true;
}

bool ie_tlv_builder_next(struct ie_tlv_builder *builder, unsigned int new_tag)
{
	if (new_tag > 0xff)
		return false;

	if (builder->tag != 0xffff) {
		ie_tlv_builder_write_header(builder);
		builder->pos += TLV_HEADER_LEN + builder->len;
	}

	if (!ie_tlv_builder_set_length(builder, 0))
		return false;

	builder->tag = new_tag;

	return true;
}

unsigned char *ie_tlv_builder_get_data(struct ie_tlv_builder *builder)
{
	return builder->tlv + TLV_HEADER_LEN + builder->pos;
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
	unsigned int len;

	ie_tlv_builder_write_header(builder);

	len = builder->pos + TLV_HEADER_LEN + builder->len;

	if (out_len)
		*out_len = len;
}

/* 802.11, Section 8.4.2.27.2 */
static bool ie_parse_cipher_suite(const uint8_t *data,
					enum ie_rsn_cipher_suite *out)
{
	static const uint8_t ieee_oui[3] = { 0x00, 0x0f, 0xac };

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
static bool ie_parse_akm_suite(const uint8_t *data,
					enum ie_rsn_akm_suite *out)
{
	static const uint8_t ieee_oui[3] = { 0x00, 0x0f, 0xac };

	/*
	 * Compare the OUI to the ones we know.  OUI Format is found in
	 * Figure 8-187 of 802.11
	 */
	if (!memcmp(data, ieee_oui, 3)) {
		/* Suite type from Table 8-101 */
		switch (data[3]) {
		case 1:
			*out = IE_RSN_AKM_SUITE_8021X;
			return true;
		case 2:
			*out = IE_RSN_AKM_SUITE_PSK;
			return true;
		case 3:
			*out = IE_RSN_AKM_SUITE_FT_OVER_8021X;
			return true;
		case 4:
			*out = IE_RSN_AKM_SUITE_FT_USING_PSK;
			return true;
		case 5:
			*out = IE_RSN_AKM_SUITE_8021X_SHA256;
			return true;
		case 6:
			*out = IE_RSN_AKM_SUITE_PSK_SHA256;
			return true;
		case 7:
			*out = IE_RSN_AKM_SUITE_TDLS;
			return true;
		case 8:
			*out = IE_RSN_AKM_SUITE_SAE_SHA256;
			return true;
		case 9:
			*out = IE_RSN_AKM_SUITE_FT_OVER_SAE_SHA256;
			return true;
		default:
			return false;
		}
	}

	return false;
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

		if (!ie_parse_akm_suite(data + i * 4, &suite))
			return -ERANGE;

		info.akm_suites |= suite;
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

	RSNE_ADVANCE(data, len, 2);

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
