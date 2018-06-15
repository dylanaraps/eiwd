/*
 *
 *  Wireless daemon for Linux
 *
 *  Copyright (C) 2017  Intel Corporation. All rights reserved.
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
#include <errno.h>

#include <ell/ell.h>
#include <ell/plugin.h>

#include "src/simauth.h"

struct hardcoded_sim {
	char *identity;
	uint8_t sim_supported;
	uint8_t kc[NUM_RANDS_MAX][EAP_SIM_KC_LEN];
	uint8_t sres[NUM_RANDS_MAX][EAP_SIM_SRES_LEN];
	uint8_t aka_supported;
	uint8_t ki[EAP_AKA_KI_LEN];
	uint8_t opc[EAP_AKA_OPC_LEN];
	uint8_t amf[EAP_AKA_AMF_LEN];
	uint8_t sqn[EAP_AKA_SQN_LEN];
	struct iwd_sim_auth *auth;
};

static struct hardcoded_sim *sim;

/*
 * Helper to XOR an array
 * to - result of XOR array
 * a - array 1
 * b - array 2
 * len - size of aray
 */
#define XOR(to, a, b, len) \
	for (i = 0; i < len; i++) { \
		to[i] = a[i] ^ b[i]; \
	}

static int get_milenage(const uint8_t *opc, const uint8_t *k,
		const uint8_t *rand, const uint8_t *sqn, const uint8_t *amf,
		const uint8_t *autn_in, uint8_t *autn, uint8_t *ck, uint8_t *ik,
		uint8_t *res, uint8_t *auts)
{
	/* algorithm variables: TEMP, IN1, OUT1, OUT2, OUT5 (OUT3/4 == IK/CK) */
	uint8_t temp[16];
	uint8_t in1[16];
	uint8_t out1[16], out2[16], out5[16];
	/* other variables */
	struct l_cipher *aes;
	int i;
	uint8_t tmp1[16];
	uint8_t tmp2[16];
	uint8_t sqn_autn[6];

	aes = l_cipher_new(L_CIPHER_AES, k, 16);

	/* temp = TEMP = E[RAND ^ OPc]k */
	XOR(tmp1, rand, opc, 16);
	l_cipher_encrypt(aes, tmp1, temp, 16);

	/* IN1[0-47] = SQN[0-47] */
	memcpy(in1, sqn, 6);
	/* IN1[48-63] = AMF[0-15] */
	memcpy(in1 + 6, amf, 2);
	/* IN1[64-111] = SQN[0-47] */
	memcpy(in1 + 8, sqn, 6);
	/* IN1[112-127] = AMF[0-15] */
	memcpy(in1 + 14, amf, 2);

	/*
	 * f1 and f1* output OUT1
	 */
	/*
	 * tmp1 = rot(IN1 ^ OPc)r1
	 * r1 = 64 bits = 8 bytes
	 */
	for (i = 0; i < 16; i++)
		tmp1[(i + 8) % 16] = in1[i] ^ opc[i];

	/* tmp2 = TEMP ^ tmp1 */
	XOR(tmp2, temp, tmp1, 16);
	/* tmp2 = E[tmp2]k */
	l_cipher_encrypt(aes, tmp2, tmp1, 16);
	/* out1 = OUT1 = tmp1 ^ opc */
	XOR(out1, tmp1, opc, 16);

	/*
	 * f2 outputs OUT2 (RES | AK)
	 *
	 * r2 = 0 == no rotation
	 */
	/* tmp1 = rot(TEMP ^ OPc)r2 */
	XOR(tmp1, temp, opc, 16);
	/* tmp1 ^ c2. c2 at bit 127 == 1 */
	tmp1[15] ^= 1;
	l_cipher_encrypt(aes, tmp1, out2, 16);

	/* get RES from OUT2 */
	XOR(out2, out2, opc, 16);
	memcpy(res, out2 + 8, 8);

	/* check input autn (AUTN ^ AK = SQN)*/
	XOR(sqn_autn, autn_in, out2, 6);

	/* if SQN was not correct, generate AUTS */
	if (memcmp(sqn_autn, sqn, 6)) {
		/*
		 * f5* outputs AK' (OUT5)
		 */
		for (i = 0; i < 16; i++)
			tmp1[(i + 4) % 16] = temp[i] ^ opc[i];

		/* tmp1 ^ c5. c5 at bit 124 == 1 */
		tmp1[15] ^= 1 << 3;
		l_cipher_encrypt(aes, tmp1, out5, 16);
		/* out5 ^ opc */
		XOR(out5, out5, opc, 16);

		XOR(auts, sqn, out5, 6);

		/* run f1 with zero'd AMF to finish AUTS */
		in1[6] = 0x00;
		in1[7] = 0x00;
		in1[14] = 0x00;
		in1[15] = 0x00;

		for (i = 0; i < 16; i++)
			tmp1[(i + 8) % 16] = in1[i] ^ opc[i];

		/* tmp2 = TEMP ^ tmp1 */
		XOR(tmp2, temp, tmp1, 16);
		/* tmp2 = E[tmp2]k */
		l_cipher_encrypt(aes, tmp2, tmp1, 16);
		/* out1 = OUT1 = tmp1 ^ opc */
		XOR(out1, tmp1, opc, 16);

		memcpy(auts + 6, in1 + 8, 8);

		return -1;
	}

	/* AUTN = (SQN ^ AK) | AMF | MAC_A */
	XOR(autn, sqn, out2, 6);
	memcpy(autn + 6, amf, 2);
	memcpy(autn + 8, out1, 8);

	if (memcmp(autn, autn_in, 16))
		return -2;

	/*
	 * f3 outputs CK (OUT3)
	 *
	 * tmp1 = rot(TEMP ^ OPc)r3
	 *
	 * r3 = 32 bits = 4 bytes
	 */
	for (i = 0; i < 16; i++)
		tmp1[(i + 12) % 16] = temp[i] ^ opc[i];

	/* tmp1 ^ c3. c3 at bit 126 == 1 */
	tmp1[15] ^= 1 << 1;
	l_cipher_encrypt(aes, tmp1, ck, 16);
	/* ck ^ opc */
	XOR(ck, ck, opc, 16);

	/*
	 * f4 outputs IK (OUT4)
	 *
	 * tmp1 = rot(TEMP ^ OPc)r4
	 *
	 * r4 = 64 bits = 8 bytes
	 */
	for (i = 0; i < 16; i++)
		tmp1[(i + 8) % 16] = temp[i] ^ opc[i];

	/* tmp1 ^ c4. c4 at bit 125 == 1 */
	tmp1[15] ^= 1 << 2;
	l_cipher_encrypt(aes, tmp1, ik, 16);
	/* ik ^ opc */
	XOR(ik, ik, opc, 16);

	l_cipher_free(aes);

	return 0;
}

static int check_milenage(struct iwd_sim_auth *auth, const uint8_t *rand,
		const uint8_t *autn, sim_auth_check_milenage_cb_t cb,
		void *data)
{
	uint8_t res[8];
	uint8_t ck[16];
	uint8_t ik[16];
	uint8_t _autn[16];
	uint8_t auts[14];
	int ret;

	if (!sim->aka_supported)
		return -ENOTSUP;

	ret = get_milenage(sim->opc, sim->ki, rand, sim->sqn, sim->amf,
			autn, _autn, ck, ik, res, auts);

	/* ret == 0, success; ret == -1, sync failure; ret == -2, failure */
	if (ret == 0)
		cb(res, ck, ik, NULL, data);
	else if (ret == -1)
		cb(NULL, NULL, NULL, auts, data);
	else
		cb(NULL, NULL, NULL, NULL, data);

	return 0;

}

static int run_gsm(struct iwd_sim_auth *auth, const uint8_t *rands,
		int num_rands, sim_auth_run_gsm_cb_t cb, void *data)
{
	if (!sim->sim_supported)
		return -ENOTSUP;

	cb((const uint8_t *)sim->sres, (const uint8_t *)sim->kc, data);

	return 0;
}

static struct iwd_sim_auth_driver hardcoded_sim_driver = {
		.name = "Hardcoded SIM driver",
		.check_milenage = check_milenage,
		.run_gsm = run_gsm
};

static int sim_hardcoded_init(void)
{
	void *kc;
	void *sres;
	void *ki;
	void *opc;
	void *amf;
	void *sqn;
	const char *str;
	size_t len;
	struct l_settings *key_settings;
	const char *config_path = getenv("IWD_SIM_KEYS");

	if (!config_path) {
		l_debug("IWD_SIM_KEYS not set in env");
		return -ENOENT;
	}

	key_settings = l_settings_new();

	if (!l_settings_load_from_file(key_settings, config_path)) {
		l_error("No %s file found", config_path);
		l_settings_free(key_settings);
		return -ENOENT;
	}

	sim = l_new(struct hardcoded_sim, 1);

	if (l_settings_has_group(key_settings, "SIM")) {
		str = l_settings_get_value(key_settings, "SIM", "Kc");
		if (!str) {
			l_debug("Kc value must be present for SIM");
			goto try_aka;
		}

		kc = l_util_from_hexstring(str, &len);
		memcpy(sim->kc, kc, len);
		l_free(kc);

		str = l_settings_get_value(key_settings, "SIM", "SRES");
		if (!str) {
			l_debug("SRES value must be present for SIM");
			goto try_aka;
		}

		sres = l_util_from_hexstring(str, &len);
		memcpy(sim->sres, sres, NUM_RANDS_MAX * EAP_SIM_SRES_LEN);
		l_free(sres);

		str = l_settings_get_value(key_settings, "SIM", "Identity");
		if (!str) {
			l_debug("Identity setting must be present for SIM");
			goto try_aka;
		}

		sim->identity = l_strdup(str);

		sim->sim_supported = 1;
	}

try_aka:
	if (l_settings_has_group(key_settings, "AKA")) {
		str = l_settings_get_value(key_settings, "AKA", "KI");
		if (!str) {
			l_debug("KI value must be present for AKA");
			goto end;
		}

		ki = l_util_from_hexstring(str, &len);
		memcpy(sim->ki, ki, EAP_AKA_KI_LEN);
		l_free(ki);

		str = l_settings_get_value(key_settings, "AKA", "OPC");
		if (!str) {
			l_debug("OPC value must be preset for AKA");
			goto end;
		}

		opc = l_util_from_hexstring(str, &len);
		memcpy(sim->opc, opc, EAP_AKA_OPC_LEN);
		l_free(opc);

		str = l_settings_get_value(key_settings, "AKA", "AMF");
		if (!str) {
			l_debug("AMF value must be present for AKA");
			goto end;
		}

		amf = l_util_from_hexstring(str, &len);
		memcpy(sim->amf, amf, EAP_AKA_AMF_LEN);
		l_free(amf);

		str = l_settings_get_value(key_settings, "AKA", "SQN");
		if (!str) {
			l_debug("SQN value must be present for AKA");
			goto end;
		}

		sqn = l_util_from_hexstring(str, &len);
		memcpy(sim->sqn, sqn, EAP_AKA_SQN_LEN);
		l_free(sqn);

		str = l_settings_get_value(key_settings, "AKA", "Identity");
		if (!str) {
			l_debug("Identity setting must be present for AKA");
			goto end;
		}

		sim->identity = l_strdup(str);

		sim->aka_supported = 1;
	}
end:
	l_settings_free(key_settings);

	if (!sim->sim_supported && !sim->aka_supported) {
		l_debug("error parsing config file, values missing");

		return -EINVAL;
	}

	sim->auth = iwd_sim_auth_create(&hardcoded_sim_driver);

	iwd_sim_auth_set_nai(sim->auth, sim->identity);
	iwd_sim_auth_set_capabilities(sim->auth, sim->sim_supported,
							sim->aka_supported);

	iwd_sim_auth_register(sim->auth);

	return 0;
}

static void sim_hardcoded_exit(void)
{
	iwd_sim_auth_remove(sim->auth);

	if (sim)
		l_free(sim->identity);

	l_free(sim);
}

L_PLUGIN_DEFINE(__iwd_builtin_sim_hardcoded, sim_hardcoded,
		"Hardcoded SIM driver", "1.0", L_PLUGIN_PRIORITY_DEFAULT,
		sim_hardcoded_init, sim_hardcoded_exit)
