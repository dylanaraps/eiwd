#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <string.h>
#include <assert.h>
#include <ell/ell.h>

#include "src/ecc.h"

#define HEX2BUF(s) ((uint64_t *) l_util_from_hexstring(s, NULL))

#define CURVE_P_32_STR "FFFFFFFF000000010000000000000000"\
			"00000000FFFFFFFFFFFFFFFFFFFFFFFF"

enum ecc_test_type {
	TEST_ADD = 0,
	TEST_SUB,
	TEST_MULT,
	TEST_INV,
	TEST_EXP,
	TEST_POINT_ADD,
	TEST_SCALAR_MULT
};

struct ecc_test_data {
	enum ecc_test_type type;
	/* basic math arguments/result */
	char *a;
	char *b;
	char *mod;
	char *result;
	/* point operations */
	char *scalar;
	char *ax, *ay;
	char *bx, *by;
	char *rx, *ry;
};

/* (a + b) mod c */
struct ecc_test_data add_test = {
	.type = TEST_ADD,
	.a = "a86c9f9e8694ffebbee433936784c0edacebd4725a95fd734098444362d5e1ca",
	.b = "6184c8ce87b6ccd1de1da88ffa79b2257893994cea3fbf338ae3159de82aa093",
	.mod = CURVE_P_32_STR,
	.result = "0af1676d0d4bccbc9d02dc2262fe7213"
			"257f6ebf45d5bca7ca7b5ae04a00825e"
};

/* (a - b) mod c */
struct ecc_test_data sub_test = {
	.type = TEST_SUB,
	.a = "a86c9f9e8694ffebbee433936784c0edacebd4725a95fd734098444362d5e1ca",
	.b = "6184c8ce87b6ccd1de1da88ffa79b2257893994cea3fbf338ae3159de82aa093",
	.mod = CURVE_P_32_STR,
	.result = "47e8d6cffedd321ae0c68b036d0a0ec8"
			"34583b2670553e40b6b42ea679aa4137"
};

/* (a * b) mod c */
struct ecc_test_data mult_test = {
	.type = TEST_MULT,
	.a = "a86c9f9e8694ffebbee433936784c0edacebd4725a95fd734098444362d5e1ca",
	.b = "6184c8ce87b6ccd1de1da88ffa79b2257893994cea3fbf338ae3159de82aa093",
	.mod = CURVE_P_32_STR,
	.result = "b5aa2ffc5ea754a6f62097c1282e072c"
			"bcf1d1277f40b006d88b5dd6c7f51fa3"
};

/* (a^-1) mod c */
struct ecc_test_data inv_test = {
	.type = TEST_INV,
	.a = "a86c9f9e8694ffebbee433936784c0edacebd4725a95fd734098444362d5e1ca",
	.mod = CURVE_P_32_STR,
	.result = "c50ba653449ad70fb17ae85567983c63"
			"fd34c31f9165d5ea47105715c1aafa48"
};

/* (a^-1) mod c */
struct ecc_test_data inv_test2 = {
	.type = TEST_INV,
	.a = "184423e8cda58cfaf8c03af9da31bb9f5c2f4d7f3f0b72a9799c3ab6105c8e69",
	.mod = CURVE_P_32_STR,
	.result = "2bb4d9671dfcb7db5e34478a8a70a0c5"
			"20856c8217594ee5383c05b6c313d15f"
};

/* (a ^ b) mod c */
struct ecc_test_data exp_test = {
	.type = TEST_EXP,
	.a = "a86c9f9e8694ffebbee433936784c0edacebd4725a95fd734098444362d5e1ca",
	.b = "6184c8ce87b6ccd1de1da88ffa79b2257893994cea3fbf338ae3159de82aa093",
	.mod = CURVE_P_32_STR,
	.result = "5a4d81b5ffbf089e79958ce1f80d96b4"
			"6ffec09843a68948bfd0dfb2002e5b41"
};

struct ecc_test_data point_add_test = {
	.type = TEST_POINT_ADD,
	.ax = "df5294c307b02dd667e49dfdd6c6a24f"
		"35139bc15cbfa523be9f27a368676bd3",
	.ay = "c480972a157533f44c0f2fefb0dd184c"
		"c5744258e72d4557f3d7efe37b1e604d",
	.bx = "e0296a73bd051756ceb6410c1c8980f0"
		"41cf5dce7a59167fd36e91abd3c533c8",
	.by = "4aa0404d653adde7e6b8a71005df3351"
		"b076a3448f2379968d3ebaa85b6e269d",
	.mod = CURVE_P_32_STR,
	.rx = "01315318631812cd4f1111dc26aab387c"
		"a1f5b7ea6aeca4c14dddb40e3edc424",
	.ry = "14556f1f7ef8af98c86f4bffcad4237d0"
		"e967b251c25e986f22b94b21f39961d"
};

struct ecc_test_data point_mult_test = {
	.type = TEST_SCALAR_MULT,
	.ax = "67ac46c3e9e10ba9262c76065314c7bf6"
		"245996840bd2f28494ebf7ff1c28b76",
	.ay = "6184c8ce87b6ccd1de1da88ffa79b2257"
		"893994cea3fbf338ae3159de82aa093",
	.scalar = "8b0532ad431bd6701f34aa8eac6c829c"
		"6165867bd24e1175163c07aa40d92175",
	.mod = CURVE_P_32_STR,
	.rx = "66feed4d184383dc0f6afe4fb7ce65a93"
		"65d88804e982c54f56d9649e30dc8d4",
	.ry = "3b0f88a5c3c97fcc399d3bf5c72384ae1"
		"eb0940ee0a086324192d3d1c31a3a6d"
};

static void run_test(const void *arg)
{
	const struct ecc_test_data *data = arg;
	uint64_t *a = NULL, *b = NULL, *c = NULL, *d = NULL, *mod = NULL;
	uint64_t result[NUM_ECC_DIGITS];
	uint64_t rx[NUM_ECC_DIGITS] = { 0 }, ry[NUM_ECC_DIGITS] = { 0 };
	uint64_t *check = NULL;
	struct ecc_point point1;
	struct ecc_point point2;
	struct ecc_point point_ret;

	memset(result, 0, sizeof(result));

	switch (data->type) {
	case TEST_ADD:
		a = HEX2BUF(data->a);
		b = HEX2BUF(data->b);
		mod = HEX2BUF(data->mod);
		vli_mod_add(result, a, b, mod);
		break;
	case TEST_SUB:
		a = HEX2BUF(data->a);
		b = HEX2BUF(data->b);
		mod = HEX2BUF(data->mod);
		vli_mod_sub(result, a, b, mod);
		break;
	case TEST_MULT:
		a = HEX2BUF(data->a);
		b = HEX2BUF(data->b);
		mod = HEX2BUF(data->mod);
		vli_mod_mult_fast(result, a, b);
		break;
	case TEST_INV:
		a = HEX2BUF(data->a);
		mod = HEX2BUF(data->mod);
		vli_mod_inv(result, a, mod);
		break;
	case TEST_EXP:
		a = HEX2BUF(data->a);
		b = HEX2BUF(data->b);
		mod = HEX2BUF(data->mod);
		vli_mod_exp(result, a, b, mod);
		break;
	case TEST_POINT_ADD:
		a = HEX2BUF(data->ax);
		b = HEX2BUF(data->ay);
		c = HEX2BUF(data->bx);
		d = HEX2BUF(data->by);

		memcpy(point1.x, a, 32);
		memcpy(point1.y, b, 32);
		memcpy(point2.x, c, 32);
		memcpy(point2.y, d, 32);

		assert(ecc_valid_point(&point1) == true);
		assert(ecc_valid_point(&point2) == true);

		mod = HEX2BUF(data->mod);
		memcpy(rx, a, 32);
		memcpy(ry, b, 32);

		ecc_point_add(&point_ret, &point1, &point2);

		break;
	case TEST_SCALAR_MULT:
		a = HEX2BUF(data->ax);
		b = HEX2BUF(data->ay);
		c = HEX2BUF(data->scalar);
		mod = HEX2BUF(data->mod);

		memcpy(point1.x, a, 32);
		memcpy(point1.y, b, 32);

		assert(ecc_valid_point(&point1) == true);

		ecc_point_mult(&point_ret, &point1, c, NULL, vli_num_bits(c));

		break;
	}

	if (data->type <= TEST_EXP) {
		check = HEX2BUF(data->result);
		assert(memcmp(result, check, 32) == 0);
	} else {
		uint64_t *checkx = HEX2BUF(data->rx);
		uint64_t *checky = HEX2BUF(data->ry);

		assert(memcmp(checkx, point_ret.x, 32) == 0);
		assert(memcmp(checky, point_ret.y, 32) == 0);
		assert(ecc_valid_point(&point_ret) == true);

		l_free(checkx);
		l_free(checky);
	}

	l_free(a);
	l_free(b);
	l_free(c);
	l_free(d);
	l_free(mod);
	l_free(check);
}

int main(int argc, char *argv[])
{
	l_test_init(&argc, &argv);

	l_test_add("ECC add test", run_test, &add_test);
	l_test_add("ECC sub test", run_test, &sub_test);
	l_test_add("ECC mult test", run_test, &mult_test);
	l_test_add("ECC inv test", run_test, &inv_test);
	l_test_add("ECC inv test", run_test, &inv_test2);
	l_test_add("ECC exp test", run_test, &exp_test);
	l_test_add("ECC point add test", run_test, &point_add_test);
	l_test_add("ECC point mult test", run_test, &point_mult_test);

	return l_test_run();
}
