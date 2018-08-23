/*
 *
 *  Wireless daemon for Linux
 *
 *  Copyright (C) 2018  Intel Corporation. All rights reserved.
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

#include <string.h>
#include <assert.h>
#include <ell/ell.h>

#include "src/util.h"
#include "src/ie.h"
#include "src/handshake.h"
#include "src/mpdu.h"
#include "src/sae.h"

struct test_handshake_state {
	struct handshake_state super;
};

struct test_data {
	/* flag for testing anti clogging */
	bool test_anti_clogging;
	/* true if a commit message was sent and verified */
	bool commit_success;
	/* true if a confirm message was sent and verified */
	bool confirm_success;
	/* true if a rejection packet was sent */
	bool tx_reject_occurred;
	/* true if the tx function was called */
	bool tx_called;
	/* copy of clogging token (if present) */
	uint8_t test_clogging_token[32];
	/* copy of last packet sent */
	uint8_t tx_packet[512];
	size_t tx_packet_len;
	/* status in complete callback */
	uint16_t status;

	struct handshake_state *handshake;
};

static uint8_t spa[] = {2, 0, 0, 0, 0, 0};
static uint8_t aa[] = {2, 0, 0, 0, 0, 1};
static char *passphrase = "secret123";

static void test_handshake_state_free(struct handshake_state *hs)
{
	struct test_handshake_state *ths =
			container_of(hs, struct test_handshake_state, super);

	l_free(ths);
}

static struct handshake_state *test_handshake_state_new(uint32_t ifindex)
{
	struct test_handshake_state *ths;

	ths = l_new(struct test_handshake_state, 1);

	ths->super.ifindex = ifindex;
	ths->super.free = test_handshake_state_free;

	return &ths->super;
}

static void test_complete_func(uint16_t status, void *user_data)
{
	struct test_data *td = user_data;

	td->status = status;
}

static int test_tx_func(const uint8_t *dest, const uint8_t *frame, size_t len,
					void *user_data)
{
	struct test_data *td = user_data;
	uint16_t trans;

	td->tx_called = true;

	memset(td->tx_packet, 0, sizeof(td->tx_packet));
	memcpy(td->tx_packet, frame, len);
	td->tx_packet_len = len;

	assert(!memcmp(dest, aa, 6));

	if (len <= 6 && l_get_le16(frame + 2) != 0) {
		td->tx_reject_occurred = true;
		return 0;
	}

	trans = l_get_le16(frame);	/* transaction */

	switch (trans) {
	case 1:
		assert(l_get_le16(frame + 2) == 0);	/* status */
		assert(l_get_le16(frame + 4) == 19);	/* group */

		if (len > 102) {
			/* clogging token */
			assert(len == 134);
			assert(!memcmp(frame + 6, td->test_clogging_token, 32));
		} else {
			assert(len == 102);
		}

		td->commit_success = true;

		return 0;
	case 2:
		assert(l_get_le16(frame + 2) == 0);
		assert(len == 38);

		td->confirm_success = true;

		return 0;
	}

	assert(false);

	return 0;
}

static struct sae_sm *test_initialize(struct test_data *td)
{
	struct sae_sm *sm;
	struct handshake_state *hs = test_handshake_state_new(1);

	td->handshake = hs;

	handshake_state_set_supplicant_address(hs, spa);
	handshake_state_set_authenticator_address(hs, aa);
	handshake_state_set_passphrase(hs, passphrase);

	memset(td->test_clogging_token, 0xde, 32);

	sm = sae_sm_new(hs, test_tx_func, test_complete_func, td);

	td->commit_success = false;
	sae_start(sm);

	assert(td->commit_success == true);

	return sm;
}

static void test_destruct(struct test_data *td)
{
	handshake_state_free(td->handshake);
	l_free(td);
}

static uint8_t aa_commit[] = {
	0x01, 0x00, 0x00, 0x00, 0x13, 0x00, 0x50, 0x5b, 0xb2, 0x1f, 0xaf, 0x7d,
	0xaf, 0x14, 0x7c, 0x7b, 0x19, 0xc9, 0x72, 0x82, 0xbc, 0x1a, 0xdb, 0xa1,
	0xbd, 0x6e, 0x5a, 0xc7, 0x58, 0x0a, 0x65, 0x1f, 0xd2, 0xde, 0xb0, 0x66,
	0xa5, 0xf9, 0x3e, 0x95, 0x4a, 0xe1, 0x83, 0xdb, 0x8a, 0xf5, 0x47, 0x8a,
	0x9d, 0x88, 0x5b, 0x58, 0xb9, 0x5b, 0xfb, 0x99, 0xff, 0xbe, 0xa0, 0xe8,
	0x70, 0x9d, 0x99, 0x2e, 0x8f, 0xa3, 0x53, 0x57, 0x3c, 0x49, 0x81, 0x0e,
	0xbc, 0x8f, 0xbc, 0xe7, 0x77, 0x8a, 0x5b, 0xf0, 0xae, 0x4a, 0xfb, 0xcd,
	0x81, 0xc0, 0x97, 0xb2, 0xf8, 0xb9, 0x12, 0xed, 0x3b, 0xd5, 0x3c, 0x5c,
	0xb2, 0x3a, 0xcc, 0x22, 0xe3, 0x9e
};

static uint8_t aa_confirm[] = {
	0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x0e, 0xf7, 0x5c, 0x1c, 0xab,
	0x7c, 0x29, 0xa1, 0x79, 0x22, 0xe4, 0x3b, 0x64, 0xb8, 0xf0, 0x70, 0x25,
	0x40, 0xcc, 0x78, 0x81, 0x27, 0x12, 0xca, 0xa9, 0xf5, 0xe5, 0x0f, 0xa7,
	0x73, 0x6d
};

static void test_confirm_timeout(const void *arg)
{
	struct test_data *td = l_new(struct test_data, 1);
	struct sae_sm *sm = test_initialize(td);
	uint8_t commit[102];
	int i;

	l_put_le16(1, commit);
	l_put_le16(0, commit + 2);
	l_put_le16(19, commit + 4);
	memset(commit + 6, 0xde, 96);

	sae_rx_packet(sm, aa, commit, sizeof(commit));

	assert(td->confirm_success);

	assert(l_get_le16(td->tx_packet + 4) == 1);

	for (i = 1; i < 5; i++) {
		sae_timeout(sm);
		assert(l_get_le16(td->tx_packet + 4) == i + 1);
	}

	sae_timeout(sm);

	assert(td->status != 0);

	test_destruct(td);
}

static void test_commit_timeout(const void *arg)
{
	struct test_data *td = l_new(struct test_data, 1);
	struct sae_sm *sm = test_initialize(td);
	uint8_t last_packet[512];
	int i;

	memcpy(last_packet, td->tx_packet, td->tx_packet_len);

	for (i = 0; i < 4; i++) {
		sae_timeout(sm);

		assert(!memcmp(last_packet, td->tx_packet, td->tx_packet_len));

		memcpy(last_packet, td->tx_packet, td->tx_packet_len);
	}

	sae_timeout(sm);

	assert(td->status != 0);

	test_destruct(td);
}

static void test_clogging(const void *arg)
{
	uint8_t frame[38];
	struct test_data *td = l_new(struct test_data, 1);
	struct sae_sm *sm = test_initialize(td);

	l_put_le16(1, frame);
	l_put_le16(MMPDU_REASON_CODE_ANTI_CLOGGING_TOKEN_REQ, frame + 2);
	l_put_le16(19, frame + 4);
	memcpy(frame + 6, td->test_clogging_token, 32);

	td->test_anti_clogging = true;
	td->commit_success = false;

	sae_rx_packet(sm, aa, frame, 38);

	assert(td->commit_success == true);

	test_destruct(td);
	sae_sm_free(sm);
}

static void test_early_confirm(const void *arg)
{
	struct test_data *td = l_new(struct test_data, 1);
	struct sae_sm *sm = test_initialize(td);

	uint8_t frame[38];
	uint8_t first_commit[102];

	/* save the initial commit */
	memcpy(first_commit, td->tx_packet, td->tx_packet_len);

	l_put_u16(2, frame);
	l_put_u16(0, frame + 2);

	memset(frame + 4, 0xfe, 32);

	td->test_anti_clogging = false;

	sae_rx_packet(sm, aa, frame, 36);

	/* verify earlier commit matched most recent */
	assert(!memcmp(td->tx_packet, first_commit, td->tx_packet_len));

	test_destruct(td);
	sae_sm_free(sm);
}

static void test_reflection(const void *arg)
{
	struct test_data *td = l_new(struct test_data, 1);
	struct sae_sm *sm = test_initialize(td);

	td->tx_called = false;
	/* send reflect same commit */
	sae_rx_packet(sm, aa, td->tx_packet, td->tx_packet_len);

	assert(td->tx_called == false);

	test_destruct(td);
	sae_sm_free(sm);
}

static void test_malformed_commit(const void *arg)
{
	struct test_data *td = l_new(struct test_data, 1);
	struct sae_sm *sm = test_initialize(td);

	/* dont send entire commit */
	sae_rx_packet(sm, aa, aa_commit, sizeof(aa_commit) - 20);

	assert(td->status != 0);

	test_destruct(td);
}

static void test_malformed_confirm(const void *arg)
{
	struct test_data *td = l_new(struct test_data, 1);
	struct sae_sm *sm = test_initialize(td);

	sae_rx_packet(sm, aa, aa_commit, sizeof(aa_commit));

	assert(td->commit_success);

	/* dont send entire confirm */
	sae_rx_packet(sm, aa, aa_confirm, sizeof(aa_confirm) - 10);

	assert(td->status != 0);

	test_destruct(td);
}

static uint8_t aa_commit_bad_group[] = {
	0x01, 0x00, 0x00, 0x00, 0x14, 0x00, 0x50, 0x5b, 0xb2, 0x1f, 0xaf, 0x7d,
	0xaf, 0x14, 0x7c, 0x7b, 0x19, 0xc9, 0x72, 0x82, 0xbc, 0x1a, 0xdb, 0xa1,
	0xbd, 0x6e, 0x5a, 0xc7, 0x58, 0x0a, 0x65, 0x1f, 0xd2, 0xde, 0xb0, 0x66,
	0xa5, 0xf9, 0x3e, 0x95, 0x4a, 0xe1, 0x83, 0xdb, 0x8a, 0xf5, 0x47, 0x8a,
	0x9d, 0x88, 0x5b, 0x58, 0xb9, 0x5b, 0xfb, 0x99, 0xff, 0xbe, 0xa0, 0xe8,
	0x70, 0x9d, 0x99, 0x2e, 0x8f, 0xa3, 0x53, 0x57, 0x3c, 0x49, 0x81, 0x0e,
	0xbc, 0x8f, 0xbc, 0xe7, 0x77, 0x8a, 0x5b, 0xf0, 0xae, 0x4a, 0xfb, 0xcd,
	0x81, 0xc0, 0x97, 0xb2, 0xf8, 0xb9, 0x12, 0xed, 0x3b, 0xd5, 0x3c, 0x5c,
	0xb2, 0x3a, 0xcc, 0x22, 0xe3, 0x9e
};

static void test_bad_group(const void *arg)
{
	struct test_data *td = l_new(struct test_data, 1);
	struct sae_sm *sm = test_initialize(td);

	sae_rx_packet(sm, aa, aa_commit_bad_group, sizeof(aa_commit_bad_group));

	assert(td->tx_reject_occurred);
	assert(td->status == MMPDU_REASON_CODE_UNSUPP_FINITE_CYCLIC_GROUP);

	test_destruct(td);
}

static int end_to_end_tx_func(const uint8_t *dest, const uint8_t *frame,
						size_t len, void *user_data)
{
	struct test_data *td = user_data;

	memcpy(td->tx_packet, frame, len);
	td->tx_packet_len = len;

	return 0;
}

static void test_bad_confirm(const void *arg)
{
	struct sae_sm *sm1;
	struct sae_sm *sm2;
	struct test_data *td1 = l_new(struct test_data, 1);
	struct test_data *td2 = l_new(struct test_data, 1);
	struct handshake_state *hs1 = test_handshake_state_new(1);
	struct handshake_state *hs2 = test_handshake_state_new(2);
	uint8_t tmp_commit[512];
	size_t tmp_commit_len;

	td1->status = 0xffff;
	td2->status = 0xffff;

	handshake_state_set_supplicant_address(hs1, spa);
	handshake_state_set_authenticator_address(hs1, aa);
	handshake_state_set_passphrase(hs1, passphrase);

	handshake_state_set_supplicant_address(hs2, aa);
	handshake_state_set_authenticator_address(hs2, spa);
	handshake_state_set_passphrase(hs2, passphrase);
	handshake_state_set_authenticator(hs2, true);

	sm1 = sae_sm_new(hs1, end_to_end_tx_func, test_complete_func, td1);
	sm2 = sae_sm_new(hs2, end_to_end_tx_func, test_complete_func, td2);

	/* both peers send out commit */
	sae_start(sm1);
	sae_start(sm2);

	/* save sm1 commit, tx_packet will get overwritten with confirm */
	memcpy(tmp_commit, td1->tx_packet, td1->tx_packet_len);
	tmp_commit_len = td1->tx_packet_len;

	/* rx commit for both peers */
	sae_rx_packet(sm1, aa, td2->tx_packet, td2->tx_packet_len);
	sae_rx_packet(sm2, spa, tmp_commit, tmp_commit_len);
	/* both peers should now have sent confirm */

	/* rx confirm for both peers */
	sae_rx_packet(sm1, aa, td2->tx_packet, td2->tx_packet_len);
	/* muck with a byte in the confirm */
	td1->tx_packet[10] = ~td1->tx_packet[10];
	sae_rx_packet(sm2, spa, td1->tx_packet, td1->tx_packet_len);

	assert(td1->status == 0);
	assert(td2->status != 0);

	handshake_state_free(hs1);
	handshake_state_free(hs2);
	sae_sm_free(sm1);
	/* sm2 gets freed by sae since it failed */
	l_free(td1);
	l_free(td2);
}

static void test_confirm_after_accept(const void *arg)
{
	struct sae_sm *sm1;
	struct sae_sm *sm2;
	struct test_data *td1 = l_new(struct test_data, 1);
	struct test_data *td2 = l_new(struct test_data, 1);
	struct handshake_state *hs1 = test_handshake_state_new(1);
	struct handshake_state *hs2 = test_handshake_state_new(2);
	uint8_t tmp_commit[512];
	size_t tmp_commit_len;

	td1->status = 0xffff;
	td2->status = 0xffff;

	handshake_state_set_supplicant_address(hs1, spa);
	handshake_state_set_authenticator_address(hs1, aa);
	handshake_state_set_passphrase(hs1, passphrase);

	handshake_state_set_supplicant_address(hs2, aa);
	handshake_state_set_authenticator_address(hs2, spa);
	handshake_state_set_passphrase(hs2, passphrase);
	handshake_state_set_authenticator(hs2, true);

	sm1 = sae_sm_new(hs1, end_to_end_tx_func, test_complete_func, td1);
	sm2 = sae_sm_new(hs2, end_to_end_tx_func, test_complete_func, td2);

	/* both peers send out commit */
	sae_start(sm1);
	sae_start(sm2);

	/* save sm1 commit, tx_packet will get overwritten with confirm */
	memcpy(tmp_commit, td1->tx_packet, td1->tx_packet_len);
	tmp_commit_len = td1->tx_packet_len;

	/* rx commit for both peers */
	sae_rx_packet(sm1, aa, td2->tx_packet, td2->tx_packet_len);
	sae_rx_packet(sm2, spa, tmp_commit, tmp_commit_len);
	/* both peers should now have sent confirm */

	/* rx confirm for one peer, sm1 should accept confirm */
	sae_rx_packet(sm1, aa, td2->tx_packet, td2->tx_packet_len);
	assert(td1->status == 0);

	/* simulate sm2 not receiving confirm and resending its confirm */
	sae_timeout(sm2);
	sae_rx_packet(sm1, aa, td2->tx_packet, td2->tx_packet_len);

	/* sc should be set to 0xffff */
	assert(l_get_u16(td1->tx_packet + 4) == 0xffff);
	/* sm1 should respond with a new confirm, and accept */
	sae_rx_packet(sm2, spa, td1->tx_packet, td1->tx_packet_len);

	assert(td1->status == 0);
	assert(td2->status == 0);

	handshake_state_free(hs1);
	handshake_state_free(hs2);
	sae_sm_free(sm1);
	sae_sm_free(sm2);
	l_free(td1);
	l_free(td2);
}

static void test_end_to_end(const void *arg)
{
	struct sae_sm *sm1;
	struct sae_sm *sm2;
	struct test_data *td1 = l_new(struct test_data, 1);
	struct test_data *td2 = l_new(struct test_data, 1);
	struct handshake_state *hs1 = test_handshake_state_new(1);
	struct handshake_state *hs2 = test_handshake_state_new(2);
	uint8_t tmp_commit[512];
	size_t tmp_commit_len;

	td1->status = 0xffff;
	td2->status = 0xffff;

	handshake_state_set_supplicant_address(hs1, spa);
	handshake_state_set_authenticator_address(hs1, aa);
	handshake_state_set_passphrase(hs1, passphrase);

	handshake_state_set_supplicant_address(hs2, aa);
	handshake_state_set_authenticator_address(hs2, spa);
	handshake_state_set_passphrase(hs2, passphrase);
	handshake_state_set_authenticator(hs2, true);

	sm1 = sae_sm_new(hs1, end_to_end_tx_func, test_complete_func, td1);
	sm2 = sae_sm_new(hs2, end_to_end_tx_func, test_complete_func, td2);

	/* both peers send out commit */
	sae_start(sm1);
	sae_start(sm2);

	/* save sm1 commit, tx_packet will get overwritten with confirm */
	memcpy(tmp_commit, td1->tx_packet, td1->tx_packet_len);
	tmp_commit_len = td1->tx_packet_len;

	/* rx commit for both peers */
	sae_rx_packet(sm1, aa, td2->tx_packet, td2->tx_packet_len);
	sae_rx_packet(sm2, spa, tmp_commit, tmp_commit_len);
	/* both peers should now have sent confirm */

	/* rx confirm for both peers */
	sae_rx_packet(sm1, aa, td2->tx_packet, td2->tx_packet_len);
	sae_rx_packet(sm2, spa, td1->tx_packet, td1->tx_packet_len);

	assert(td1->status == 0);
	assert(td2->status == 0);

	handshake_state_free(hs1);
	handshake_state_free(hs2);
	sae_sm_free(sm1);
	sae_sm_free(sm2);
	l_free(td1);
	l_free(td2);
}

int main(int argc, char *argv[])
{
	l_test_init(&argc, &argv);

	if (!l_getrandom_is_supported()) {
		l_info("l_getrandom not supported, skipping...");
		goto done;
	}

	l_test_add("SAE commit timeout", test_commit_timeout, NULL);
	l_test_add("SAE confirm timeout", test_confirm_timeout, NULL);
	l_test_add("SAE anti-clogging", test_clogging, NULL);
	l_test_add("SAE early confirm", test_early_confirm, NULL);
	l_test_add("SAE reflection", test_reflection, NULL);
	l_test_add("SAE malformed commit", test_malformed_commit, NULL);
	l_test_add("SAE malformed confirm", test_malformed_confirm, NULL);
	l_test_add("SAE bad group", test_bad_group, NULL);
	l_test_add("SAE bad confirm", test_bad_confirm, NULL);
	l_test_add("SAE confirm after accept", test_confirm_after_accept, NULL);
	l_test_add("SAE end-to-end", test_end_to_end, NULL);

done:
	return l_test_run();
}
