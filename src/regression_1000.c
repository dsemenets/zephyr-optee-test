#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <zephyr/ztest.h>
#include <tee_client_api.h>
#include <adbg.h>
#include "optee_test.h"

#ifndef MIN
#define MIN(a, b) ((a) < (b) ? (a) : (b))
#endif

#define STATS_UUID \
	{ 0xd96a5b40, 0xe2c7, 0xb1af, \
		{ 0x87, 0x94, 0x10, 0x02, 0xa5, 0xd5, 0xc6, 0x1b } }

#define STATS_CMD_PAGER_STATS		0

#define PAGER_PAGE_COUNT_THRESHOLD	((128 * 1024) / 4096)

extern TEEC_Context xtest_teec_ctx;

void *regression_1000_init(void)
{
	printk("Begin Test suite 1000\n");
        (void)TEEC_InitializeContext(NULL, &xtest_teec_ctx);
	return NULL;
}

void regression_1000_deinit(void *param)
{
	(void)param;
	printk("End Test suite 1000\n");
    TEEC_FinalizeContext(&xtest_teec_ctx);
}

struct xtest_crypto_session {
	struct ADBG_Case *c;
	TEEC_Session *session;
	uint32_t cmd_id_sha256;
	uint32_t cmd_id_aes256ecb_encrypt;
	uint32_t cmd_id_aes256ecb_decrypt;
};


static bool optee_pager_with_small_pool(void)
{
	TEEC_Result res = TEEC_ERROR_GENERIC;
	TEEC_UUID uuid = STATS_UUID;
	TEEC_Context ctx = { };
	TEEC_Session sess = { };
	TEEC_Operation op = { };
	uint32_t eo = 0;
	bool rc = false;

	res = TEEC_InitializeContext(NULL, &ctx);
	if (res)
		return false;

	res = TEEC_OpenSession(&ctx, &sess, &uuid, TEEC_LOGIN_PUBLIC, NULL,
			       NULL, &eo);
	if (res)
		goto out_ctx;

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_OUTPUT, TEEC_VALUE_OUTPUT,
					 TEEC_VALUE_OUTPUT, TEEC_NONE);
	res = TEEC_InvokeCommand(&sess, STATS_CMD_PAGER_STATS, &op, &eo);
	if (res)
		goto out_sess;

	if (op.params[0].value.b &&
	    op.params[0].value.b <= PAGER_PAGE_COUNT_THRESHOLD)
		rc = true;

out_sess:
	TEEC_CloseSession(&sess);
out_ctx:
	TEEC_FinalizeContext(&ctx);

	return rc;
}

static void xtest_crypto_test(struct xtest_crypto_session *cs)
{
	uint32_t ret_orig = 0;
	uint8_t crypt_out[16] = { };
	uint8_t crypt_in[16] = { 22, 17 };

	crypt_in[15] = 60;

	BeginSubCase("AES encrypt");
	{
		TEEC_Operation op = TEEC_OPERATION_INITIALIZER;

		op.params[0].tmpref.buffer = crypt_in;
		op.params[0].tmpref.size = sizeof(crypt_in);
		op.params[1].tmpref.buffer = crypt_out;
		op.params[1].tmpref.size = sizeof(crypt_out);
		op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
						 TEEC_MEMREF_TEMP_OUTPUT,
						 TEEC_NONE, TEEC_NONE);

		(void)ADBG_EXPECT_TEEC_SUCCESS(cs->c,
					       TEEC_InvokeCommand(cs->session,
						cs->
						cmd_id_aes256ecb_encrypt,
						&op,
						&ret_orig));
	}
	EndSubCase("AES encrypt");

	BeginSubCase("AES decrypt");
	{
		TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
		uint8_t out[16] = { };

		op.params[0].tmpref.buffer = crypt_out;
		op.params[0].tmpref.size = sizeof(crypt_out);
		op.params[1].tmpref.buffer = out;
		op.params[1].tmpref.size = sizeof(out);
		op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
						 TEEC_MEMREF_TEMP_OUTPUT,
						 TEEC_NONE, TEEC_NONE);

		(void)ADBG_EXPECT_TEEC_SUCCESS(cs->c,
					       TEEC_InvokeCommand(cs->session,
						cs->
						cmd_id_aes256ecb_decrypt,
						&op,
						&ret_orig));

		if (!ADBG_EXPECT(cs->c, 0,
				 memcmp(crypt_in, out, sizeof(crypt_in)))) {
			printk("crypt_in:\n");
			Do_ADBG_HexLog(crypt_in, sizeof(crypt_in), 16);
			printk("out:\n");
			Do_ADBG_HexLog(out, sizeof(out), 16);
		}
	}
	EndSubCase("AES decrypt");

	BeginSubCase("SHA-256 test, 3 bytes input");
	{
		TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
		static const uint8_t sha256_in[] = { 'a', 'b', 'c' };
		static const uint8_t sha256_out[] = {
			0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
			0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
			0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
			0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad
		};
		uint8_t out[32] = { };

		op.params[0].tmpref.buffer = (void *)sha256_in;
		op.params[0].tmpref.size = sizeof(sha256_in);
		op.params[1].tmpref.buffer = out;
		op.params[1].tmpref.size = sizeof(out);
		op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
						 TEEC_MEMREF_TEMP_OUTPUT,
						 TEEC_NONE, TEEC_NONE);

		(void)ADBG_EXPECT_TEEC_SUCCESS(cs->c,
					       TEEC_InvokeCommand(cs->session,
								  cs->
								  cmd_id_sha256,
								  &op,
								  &ret_orig));

		if (!ADBG_EXPECT(cs->c, 0, memcmp(sha256_out, out,
						  sizeof(sha256_out)))) {
			printk("sha256_out:\n");
			Do_ADBG_HexLog(sha256_out, sizeof(sha256_out), 16);
			printk("out:\n");
			Do_ADBG_HexLog(out, sizeof(out), 16);
		}
	}
	EndSubCase("SHA-256 test, 3 bytes input");

	BeginSubCase("AES-256 ECB encrypt (32B, fixed key)");
	{
		TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
		static const uint8_t in[] = {
			0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
			0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
			0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
			0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
		};
		static const uint8_t exp_out[] = {
			0x5A, 0x6E, 0x04, 0x57, 0x08, 0xFB, 0x71, 0x96,
			0xF0, 0x2E, 0x55, 0x3D, 0x02, 0xC3, 0xA6, 0x92,
			0xE9, 0xC3, 0xEF, 0x8A, 0xB2, 0x34, 0x53, 0xE6,
			0xF0, 0x74, 0x9C, 0xD6, 0x36, 0xE7, 0xA8, 0x8E
		};
		uint8_t out[sizeof(exp_out)] = { };

		op.params[0].tmpref.buffer = (void *)in;
		op.params[0].tmpref.size = sizeof(in);
		op.params[1].tmpref.buffer = out;
		op.params[1].tmpref.size = sizeof(out);
		op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
						 TEEC_MEMREF_TEMP_OUTPUT,
						 TEEC_NONE, TEEC_NONE);

		(void)ADBG_EXPECT_TEEC_SUCCESS(cs->c,
					TEEC_InvokeCommand(cs->session,
					cs->
					cmd_id_aes256ecb_encrypt,
					&op,
					&ret_orig));

		if (!ADBG_EXPECT(cs->c, 0,
				 memcmp(exp_out, out, sizeof(exp_out)))) {
			printk("exp_out:\n");
			Do_ADBG_HexLog(exp_out, sizeof(exp_out), 16);
			printk("out:\n");
			Do_ADBG_HexLog(out, sizeof(out), 16);
		}
	}
	EndSubCase("AES-256 ECB encrypt (32B, fixed key)");

	BeginSubCase("AES-256 ECB decrypt (32B, fixed key)");
	{
		TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
		static const uint8_t in[] = {
			0x5A, 0x6E, 0x04, 0x57, 0x08, 0xFB, 0x71, 0x96,
			0xF0, 0x2E, 0x55, 0x3D, 0x02, 0xC3, 0xA6, 0x92,
			0xE9, 0xC3, 0xEF, 0x8A, 0xB2, 0x34, 0x53, 0xE6,
			0xF0, 0x74, 0x9C, 0xD6, 0x36, 0xE7, 0xA8, 0x8E
		};
		static const uint8_t exp_out[] = {
			0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
			0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
			0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
			0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
		};
		uint8_t out[sizeof(exp_out)] = { };

		op.params[0].tmpref.buffer = (void *)in;
		op.params[0].tmpref.size = sizeof(in);
		op.params[1].tmpref.buffer = out;
		op.params[1].tmpref.size = sizeof(out);
		op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
						 TEEC_MEMREF_TEMP_OUTPUT,
						 TEEC_NONE, TEEC_NONE);

		(void)ADBG_EXPECT_TEEC_SUCCESS(cs->c,
				       TEEC_InvokeCommand(cs->session,
					cs->
					cmd_id_aes256ecb_decrypt,
					&op,
					&ret_orig));

		if (!ADBG_EXPECT(cs->c, 0,
				 memcmp(exp_out, out, sizeof(exp_out)))) {
			printk("exp_out:\n");
			Do_ADBG_HexLog(exp_out, sizeof(exp_out), 16);
			printk("out:\n");
			Do_ADBG_HexLog(out, sizeof(out), 16);
		}
	}
	EndSubCase("AES-256 ECB decrypt (32B, fixed key)");
}

ZTEST(regression_1000, test_1001)
{
	TEEC_Result res = TEEC_ERROR_GENERIC;
	TEEC_Session session = { };
	uint32_t ret_orig = 0;
	ADBG_STRUCT_DECLARE("Core self tests");

	/* Pseudo TA is optional: warn and nicely exit if not found */
	res = xtest_teec_open_session(&session, &pta_invoke_tests_ta_uuid, NULL,
				      &ret_orig);
	if (res == TEEC_ERROR_ITEM_NOT_FOUND) {
		printk(" - 1001 -   skip test, pseudo TA not found");
		return;
	}
	if (!ADBG_EXPECT_TEEC_SUCCESS(&c, res)) {
		ADBG_Assert(&c);
		return;
	}

	BeginSubCase("Core self tests");

	(void)ADBG_EXPECT_TEEC_SUCCESS(&c, TEEC_InvokeCommand(
		&session, PTA_INVOKE_TESTS_CMD_SELF_TESTS, NULL, &ret_orig));

	EndSubCase("Core self tests");

	BeginSubCase("Core dt_driver self tests");

	(void)ADBG_EXPECT_TEEC_SUCCESS(&c, TEEC_InvokeCommand(
		&session, PTA_INVOKE_TESTS_CMD_DT_DRIVER_TESTS, NULL,
		&ret_orig));

	EndSubCase("Core dt_driver self tests");

	TEEC_CloseSession(&session);
	ADBG_Assert(&c);
}

ZTEST(regression_1000, test_1002)
{
	TEEC_Result res = TEEC_ERROR_GENERIC;
	TEEC_Session session = { };
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t ret_orig = 0;
	uint8_t buf[16 * 1024] = { };
	uint8_t exp_sum = 0;
	size_t n = 0;
	ADBG_STRUCT_DECLARE("PTA parameters");

	/* Pseudo TA is optional: warn and nicely exit if not found */
	res = xtest_teec_open_session(&session, &pta_invoke_tests_ta_uuid, NULL,
				      &ret_orig);
	if (res == TEEC_ERROR_ITEM_NOT_FOUND) {
		printk(" - 1002 -   skip test, pseudo TA not found");
		return;
	}
	if (!ADBG_EXPECT_TEEC_SUCCESS(&c, res)) {
		ADBG_Assert(&c);
		return;
	}

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INOUT, TEEC_NONE,
					 TEEC_NONE, TEEC_NONE);
	op.params[0].tmpref.size = sizeof(buf);
	op.params[0].tmpref.buffer = buf;

	for (n = 0; n < sizeof(buf); n++)
		buf[n] = n + 1;
	for (n = 0; n < sizeof(buf); n++)
		exp_sum += buf[n];

	if (!ADBG_EXPECT_TEEC_SUCCESS(&c, TEEC_InvokeCommand(
		&session, PTA_INVOKE_TESTS_CMD_PARAMS, &op, &ret_orig)))
		goto out;

	ADBG_EXPECT_COMPARE_SIGNED(&c, exp_sum, ==, buf[0]);
out:
	TEEC_CloseSession(&session);
	ADBG_Assert(&c);
}

struct test_1003_arg {
	uint32_t test_type;
	size_t repeat;
	size_t max_before_lockers;
	size_t max_during_lockers;
	size_t before_lockers;
	size_t during_lockers;
	TEEC_Result res;
	uint32_t error_orig;
};

static void test_1003_thread(void *arg1, __attribute__ ((unused)) void *arg2,
			      __attribute__ ((unused)) void *arg3)
{
	struct test_1003_arg *a = (struct test_1003_arg *)arg1;
	TEEC_Session session = { };
	size_t rounds = 64 * 1024;
	size_t n = 0;

	a->res = xtest_teec_open_session(&session, &pta_invoke_tests_ta_uuid,
					 NULL, &a->error_orig);
	if (a->res != TEEC_SUCCESS)
		return;

	for (n = 0; n < a->repeat; n++) {
		TEEC_Operation op = TEEC_OPERATION_INITIALIZER;

		op.params[0].value.a = a->test_type;
		op.params[0].value.b = rounds;

		op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT,
						 TEEC_VALUE_OUTPUT,
						 TEEC_NONE, TEEC_NONE);
		a->res = TEEC_InvokeCommand(&session,
					    PTA_INVOKE_TESTS_CMD_MUTEX,
					    &op, &a->error_orig);
		if (a->test_type == PTA_MUTEX_TEST_WRITER &&
		    op.params[1].value.b != 1) {
			printk("n %zu %" PRIu32, n, op.params[1].value.b);
			a->res = TEEC_ERROR_BAD_STATE;
			a->error_orig = 42;
			break;
		}

		if (a->test_type == PTA_MUTEX_TEST_READER) {
			if (op.params[1].value.a > a->max_before_lockers)
				a->max_before_lockers = op.params[1].value.a;

			if (op.params[1].value.b > a->max_during_lockers)
				a->max_during_lockers = op.params[1].value.b;

			a->before_lockers += op.params[1].value.a;
			a->during_lockers += op.params[1].value.b;
		}
	}
	TEEC_CloseSession(&session);

	return;
}

#define TEST_1003_THREAD_COUNT		(3 * 2)
static struct k_thread thr[TEST_1003_THREAD_COUNT];
static struct test_1003_arg arg[TEST_1003_THREAD_COUNT] = { };
#define STACKSIZE (256 + CONFIG_TEST_EXTRA_STACK_SIZE)
static K_THREAD_STACK_ARRAY_DEFINE(thread_stack, TEST_1003_THREAD_COUNT, STACKSIZE);

ZTEST(regression_1000, test_1003)
{
	TEEC_Result res = TEEC_ERROR_GENERIC;
	TEEC_Session session = { };
	uint32_t ret_orig = 0;
	size_t repeat = 20;
	size_t max_read_concurrency = 0;
	size_t max_read_waiters = 0;
	size_t num_concurrent_read_lockers = 0;
	size_t num_concurrent_read_waiters = 0;
	size_t n = 0;
	size_t nt = TEST_1003_THREAD_COUNT;
	double mean_read_concurrency = 0;
	double mean_read_waiters = 0;
	size_t num_writers = 0;
	size_t num_readers = 0;
	ADBG_STRUCT_DECLARE("Core internal read/write mutex");

	/* Pseudo TA is optional: warn and nicely exit if not found */
	res = xtest_teec_open_session(&session, &pta_invoke_tests_ta_uuid, NULL,
				      &ret_orig);
	if (res == TEEC_ERROR_ITEM_NOT_FOUND) {
		printk(" - 1003 -   skip test, pseudo TA not found\n");
		return;
	}
	if (!ADBG_EXPECT_TEEC_SUCCESS(&c, res)) {
		ADBG_Assert(&c);
		return;
	}
	TEEC_CloseSession(&session);

	for (n = 0; n < nt; n++) {
		k_tid_t tid;
		if (n % 3) {
			arg[n].test_type = PTA_MUTEX_TEST_READER;
			num_readers++;
		} else {
			arg[n].test_type = PTA_MUTEX_TEST_WRITER;
			num_writers++;
		}
		arg[n].repeat = repeat;
		tid = k_thread_create(thr+n, thread_stack[n], STACKSIZE, test_1003_thread,
				      arg+n, NULL, NULL, K_PRIO_PREEMPT(0), K_USER, K_NO_WAIT);
		if (!ADBG_EXPECT_NOT(&c, 0, (long)tid))
			nt = n; /* break loop and start cleanup */
	}

	for (n = 0; n < nt; n++) {
		ADBG_EXPECT(&c, 0, k_thread_join(thr+n, K_FOREVER));
		if (!ADBG_EXPECT_TEEC_SUCCESS(&c, arg[n].res))
			printk("error origin %" PRIu32 "\n", arg[n].error_orig);
		if (arg[n].test_type == PTA_MUTEX_TEST_READER) {
			if (arg[n].max_during_lockers > max_read_concurrency)
				max_read_concurrency =
					arg[n].max_during_lockers;

			if (arg[n].max_before_lockers > max_read_waiters)
				max_read_waiters = arg[n].max_before_lockers;

			num_concurrent_read_lockers += arg[n].during_lockers;
			num_concurrent_read_waiters += arg[n].before_lockers;
		}
	}

	mean_read_concurrency = (double)num_concurrent_read_lockers /
				(double)(repeat * num_readers);
	mean_read_waiters = (double)num_concurrent_read_waiters /
			    (double)(repeat * num_readers);

	printk("    Number of parallel threads: %d (%zu writers and %zu readers)\n",
		    TEST_1003_THREAD_COUNT, num_writers, num_readers);
	printk("    Max read concurrency: %zu\n", max_read_concurrency);
	printk("    Max read waiters: %zu\n", max_read_waiters);
	printk("    Mean read concurrency: %g\n", mean_read_concurrency);
	printk("    Mean read waiting: %g\n", mean_read_waiters);
	ADBG_Assert(&c);
}

ZTEST(regression_1000, test_1004)
{
	TEEC_Session session = { };
	uint32_t ret_orig = 0;
	ADBG_STRUCT_DECLARE("Test User Crypt TA");

	struct xtest_crypto_session cs = { &c, &session, TA_CRYPT_CMD_SHA256,
					   TA_CRYPT_CMD_AES256ECB_ENC,
					   TA_CRYPT_CMD_AES256ECB_DEC };

	if (!ADBG_EXPECT_TEEC_SUCCESS(&c, xtest_teec_open_session(
					      &session, &crypt_user_ta_uuid,
					      NULL, &ret_orig))) {
		ADBG_Assert(&c);
		return;
	}

	/* Run the "complete crypto test suite" */
	xtest_crypto_test(&cs);

	TEEC_CloseSession(&session);
	ADBG_Assert(&c);
}

ZTEST(regression_1000, test_1005)
{
	uint32_t ret_orig = 0;
#define MAX_SESSIONS    3
	TEEC_Session sessions[MAX_SESSIONS];
	int i = 0;
	ADBG_STRUCT_DECLARE("Many sessions");

	for (i = 0; i < MAX_SESSIONS; i++) {
		if (!ADBG_EXPECT_TEEC_SUCCESS(&c,
			xtest_teec_open_session(&sessions[i],
						&concurrent_ta_uuid,
						NULL, &ret_orig)))
			break;
	}

	for (; --i >= 0; )
		TEEC_CloseSession(&sessions[i]);
	ADBG_Assert(&c);
}

ZTEST(regression_1000, test_1006)
{
	TEEC_Session session = { };
	uint32_t ret_orig = 0;
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint8_t buf[32] = { };
	ADBG_STRUCT_DECLARE("Test Basic OS features");

	if (!ADBG_EXPECT_TEEC_SUCCESS(&c,
		xtest_teec_open_session(&session, &os_test_ta_uuid, NULL,
					&ret_orig))) {
		ADBG_Assert(&c);
		return;
	}

	op.params[0].tmpref.buffer = buf;
	op.params[0].tmpref.size = sizeof(buf);
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_NONE,
					 TEEC_NONE, TEEC_NONE);

	(void)ADBG_EXPECT_TEEC_SUCCESS(&c,
		TEEC_InvokeCommand(&session, TA_OS_TEST_CMD_BASIC, &op,
				   &ret_orig));

	TEEC_CloseSession(&session);
	ADBG_Assert(&c);
}

ZTEST(regression_1000, test_1007)
{
	TEEC_Session session = { };
	uint32_t ret_orig = 0;
	ADBG_STRUCT_DECLARE("Test Panic");

	if (!ADBG_EXPECT_TEEC_SUCCESS(&c,
		xtest_teec_open_session(&session, &os_test_ta_uuid, NULL,
		                        &ret_orig))) {
		ADBG_Assert(&c);
		return;
	}

	(void)ADBG_EXPECT_TEEC_RESULT(&c,
		TEEC_ERROR_TARGET_DEAD,
		TEEC_InvokeCommand(&session, TA_OS_TEST_CMD_PANIC, NULL,
				   &ret_orig));

	(void)ADBG_EXPECT_TEEC_ERROR_ORIGIN(&c, TEEC_ORIGIN_TEE, ret_orig);

	(void)ADBG_EXPECT_TEEC_RESULT(&c,
		TEEC_ERROR_TARGET_DEAD,
		TEEC_InvokeCommand(&session, TA_OS_TEST_CMD_INIT, NULL,
				   &ret_orig));

	(void)ADBG_EXPECT_TEEC_ERROR_ORIGIN(&c, TEEC_ORIGIN_TEE, ret_orig);

	TEEC_CloseSession(&session);
	ADBG_Assert(&c);
}

ZTEST_SUITE(regression_1000, NULL, regression_1000_init, NULL, NULL, regression_1000_deinit);

