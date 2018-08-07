#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <string.h>
#include <assert.h>
#include <ell/ell.h>

#include "src/ecc.h"

#define HEX2BUF(s, buf) { \
	unsigned char *tmp = l_util_from_hexstring(s, NULL); \
	memcpy(buf, tmp, 32); \
	l_free(tmp); \
}

#define CURVE_P_32_STR "ffffffffffffffffffffffff00000000"\
			"000000000000000001000000ffffffff"

enum ecc_test_type {
	TEST_ADD = 0,
	TEST_SUB,
	TEST_MULT,
	TEST_INV,
	TEST_EXP,
	TEST_POINT_ADD,
	TEST_SCALAR_MULT,
	TEST_LEGENDRE,
};

struct ecc_test_data {
	enum ecc_test_type type;
	/* basic math arguments/result */
	char *a;
	char *b;
	char *qr;
	char *qnr;
	char *r;
	bool is_residue;
	char *mod;
	char *result;
	int lres;
	/* point operations */
	char *scalar;
	char *ax, *ay;
	char *bx, *by;
	char *rx, *ry;
};

/* (a + b) mod c */
struct ecc_test_data add_test = {
	.type = TEST_ADD,
	.a = "cae1d5624344984073fd955a72d4ebacedc084679333e4beebff94869e9f6ca8",
	.b = "93a02ae89d15e38a33bf3fea4c99937825b279fa8fa81dded1ccb687cec88461",
	.mod = CURVE_P_32_STR,
	.result = "5e82004ae05a7bcaa7bcd545bf6e7f25"
			"1372fe6222dc029dbccc4b0d6d67f10a"
};

/* (a - b) mod c */
struct ecc_test_data sub_test = {
	.type = TEST_SUB,
	.a = "cae1d5624344984073fd955a72d4ebacedc084679333e4beebff94869e9f6ca8",
	.b = "93a02ae89d15e38a33bf3fea4c99937825b279fa8fa81dded1ccb687cec88461",
	.mod = CURVE_P_32_STR,
	.result = "3741aa79a62eb4b6403e5570263b5834"
			"c80e0a6d038bc6e01a32ddfecfd6e847"
};

/* (a * b) mod c */
struct ecc_test_data mult_test = {
	.type = TEST_MULT,
	.a = "cae1d5624344984073fd955a72d4ebacedc084679333e4beebff94869e9f6ca8",
	.b = "93a02ae89d15e38a33bf3fea4c99937825b279fa8fa81dded1ccb687cec88461",
	.mod = CURVE_P_32_STR,
	.result = "a31ff5c7d65d8bd806b0407f27d1f1bc"
			"2c072e28c19720f6a654a75efc2faab5"

};

/* (a^-1) mod c */
struct ecc_test_data inv_test = {
	.type = TEST_INV,
	.a = "cae1d5624344984073fd955a72d4ebacedc084679333e4beebff94869e9f6ca8",
	.mod = CURVE_P_32_STR,
	.result = "48faaac115571047ead565911fc334fd"
			"633c986755e87ab10fd79a4453a60bc5"

};

/* (a^-1) mod c */
struct ecc_test_data inv_test2 = {
	.type = TEST_INV,
	.a = "698e5c10b63a9c79a9720b3f7f4d2f5c9fbb31daf93ac0f8fa8ca5cde8234418",
	.mod = CURVE_P_32_STR,
	.result = "5fd113c3b6053c38e54e5917826c8520"
			"c5a0708a8a47345edbb7fc1d67d9b42b"

};

/* (a ^ b) mod c */
struct ecc_test_data exp_test = {
	.type = TEST_EXP,
	.a = "cae1d5624344984073fd955a72d4ebacedc084679333e4beebff94869e9f6ca8",
	.b = "93a02ae89d15e38a33bf3fea4c99937825b279fa8fa81dded1ccb687cec88461",
	.mod = CURVE_P_32_STR,
	.result = "415b2e00b2dfd0bf4889a64398c0fe6f"
			"b4960df8e18c95799e08bfffb5814d5a"

};

struct ecc_test_data legendre_test1 = {
	.type = TEST_LEGENDRE,
	.a = "b59c0c366aa89ba229f857190497261d5a0a7a0a774caa72aef041ff00092447",
	.mod = "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
	.lres = -1
};

struct ecc_test_data legendre_test2 = {
	.type = TEST_LEGENDRE,
	.a = "1214f9607d348c998b3fba332d884d65945561fd007ff56d8bf603148d74d2e4",
	.mod = "ffffffff000000010000000000000000"
			"00000000ffffffffffffffffffffffff",
	.lres = 1
};

struct ecc_test_data legendre_test3 = {
	.type = TEST_LEGENDRE,
	.a = "282d751c898bfc593b1d21b6812df48e3ec811f40349b30b7294575c47b871d8",
	.mod = "ffffffff000000010000000000000000"
			"00000000ffffffffffffffffffffffff",
	.lres = 1
};

struct ecc_test_data legendre_test4 = {
	.type = TEST_LEGENDRE,
	.a = "0694ccde1db3d02faa26856678bd9358ecc0d82791405eb3892a8b4f07f1e5d6",
	.mod = "ffffffff000000010000000000000000"
			"00000000ffffffffffffffffffffffff",
	.lres = -1
};

struct ecc_test_data legendre_test5 = {
	.type = TEST_LEGENDRE,
	.a = "92247f96df65a6d04af0c57318e999fd493c42864d156f7e5bba75c964f3c6b0",
	.mod = "ffffffff000000010000000000000000"
			"00000000ffffffffffffffffffffffff",
	.lres = 1
};

struct ecc_test_data legendre_test6 = {
	.type = TEST_LEGENDRE,
	.a = "084f7eb6ed8021d095787fd401b0f19b13937dc23f7c84dfe69bb9a204bb3768",
	.mod = "ffffffff000000010000000000000000"
			"00000000ffffffffffffffffffffffff",
	.lres = -1
};

struct ecc_test_data point_add_test = {
	.type = TEST_POINT_ADD,
	.ax = "d36b6768a3279fbe23a5bf5cc19b13354"
		"fa2c6d6fd9de467d62db007c39452df",
	.ay = "4d601e7be3efd7f357452de7584274c54"
		"c18ddb0ef2f0f4cf43375152a9780c4",
	.bx = "c833c5d3ab916ed37f16597ace5dcf41f"
		"080891c0c41b6ce561705bd736a29e0",
	.by = "9d266e5ba8ba3e8d9679238f44a376b05"
		"133df0510a7b8e6e7dd3a654d40a04a",
	.rx = "24c4ede340dbdd144ccaaea67e5b1fca"
		"87b3aa26dc11114fcd12186318533101",
	.ry = "1d96391fb2942bf286e9251c257b960e"
		"7d23d4caff4b6fc898aff87e1f6f5514"

};

struct ecc_test_data point_mult_test = {
	.type = TEST_SCALAR_MULT,
	.ax = "768bc2f17fbf4e49282fbd4068994562b"
		"fc7145306762c26a90be1e9c346ac67",
	.ay = "93a02ae89d15e38a33bf3fea4c9993782"
		"5b279fa8fa81dded1ccb687cec88461",
	.scalar = "7521d940aa073c1675114ed27b866561"
		"9c826cac8eaa341f70d61b43ad32058b",
	.rx = "d4c80de349966df5542c984e80885d36"
		"a965ceb74ffe6a0fdc8343184dedfe66",
	.ry = "6d3a1ac3d1d392413286a0e00e94b01e"
		"ae8423c7f53b9d39cc7fc9c3a5880f3b"

};

static void run_test(const void *arg)
{
	const struct ecc_test_data *data = arg;
	uint64_t a[NUM_ECC_DIGITS], b[NUM_ECC_DIGITS], mod[NUM_ECC_DIGITS],
			scalar[NUM_ECC_DIGITS], result[NUM_ECC_DIGITS],
			check[NUM_ECC_DIGITS];
	struct ecc_point point1, point2, point_ret;
	int lres;

	memset(result, 0, sizeof(result));

	if (data->a) {
		HEX2BUF(data->a, a);
		ecc_be2native(a);
	}

	if (data->b) {
		HEX2BUF(data->b, b);
		ecc_be2native(b);
	}

	if (data->mod) {
		HEX2BUF(data->mod, mod);
		ecc_be2native(mod);
	}

	if (data->ax) {
		HEX2BUF(data->ax, point1.x);
		ecc_be2native(point1.x);
	}

	if (data->ay) {
		HEX2BUF(data->ay, point1.y);
		ecc_be2native(point1.y);
	}

	if (data->bx) {
		HEX2BUF(data->bx, point2.x);
		ecc_be2native(point2.x);
	}

	if (data->by) {
		HEX2BUF(data->by, point2.y);
		ecc_be2native(point2.y);
	}

	if (data->scalar) {
		HEX2BUF(data->scalar, scalar);
		ecc_be2native(scalar);
	}

	switch (data->type) {
	case TEST_ADD:
		vli_mod_add(result, a, b, mod);
		break;
	case TEST_SUB:
		vli_mod_sub(result, a, b, mod);
		break;
	case TEST_MULT:
		vli_mod_mult_fast(result, a, b);
		break;
	case TEST_INV:
		vli_mod_inv(result, a, mod);
		break;
	case TEST_EXP:
		vli_mod_exp(result, a, b, mod);
		break;
	case TEST_LEGENDRE:
		lres = vli_legendre(a, mod);
		break;
	case TEST_POINT_ADD:
		assert(ecc_valid_point(&point1) == true);
		assert(ecc_valid_point(&point2) == true);

		ecc_point_add(&point_ret, &point1, &point2);

		break;
	case TEST_SCALAR_MULT:
		assert(ecc_valid_point(&point1) == true);

		ecc_point_mult(&point_ret, &point1, scalar, NULL,
				vli_num_bits(scalar));

		break;
	}

	if (data->type <= TEST_EXP) {
		HEX2BUF(data->result, check);
		ecc_native2be(check);
		assert(memcmp(result, check, 32) == 0);
	} else if (data->type <= TEST_SCALAR_MULT) {
		uint64_t checkx[NUM_ECC_DIGITS];
		uint64_t checky[NUM_ECC_DIGITS];

		HEX2BUF(data->rx, checkx);
		ecc_native2be(checkx);
		HEX2BUF(data->ry, checky);
		ecc_native2be(checky);

		assert(memcmp(checkx, point_ret.x, 32) == 0);
		assert(memcmp(checky, point_ret.y, 32) == 0);
		assert(ecc_valid_point(&point_ret) == true);

	} else if (data->type == TEST_LEGENDRE) {
		assert(data->lres == lres);
	}
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
	l_test_add("ECC legendre", run_test, &legendre_test1);
	l_test_add("ECC legendre", run_test, &legendre_test2);
	l_test_add("ECC legendre", run_test, &legendre_test3);
	l_test_add("ECC legendre", run_test, &legendre_test4);
	l_test_add("ECC legendre", run_test, &legendre_test5);
	l_test_add("ECC legendre", run_test, &legendre_test6);

	return l_test_run();
}
