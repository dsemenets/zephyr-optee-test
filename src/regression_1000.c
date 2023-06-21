// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2023, EPAM Systems
 * Copyright (c) 2020, ARM Limited. All rights reserved.
 * Copyright (c) 2014, STMicroelectronics International N.V.
*/
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

#define UNUSED __attribute__ ((unused))

extern TEEC_Context xtest_teec_ctx;

void *regression_1000_init(void)
{
	printk("Begin Test suite regression_1000\n");
	(void)TEEC_InitializeContext(NULL, &xtest_teec_ctx);
	return NULL;
}

void regression_1000_deinit(void *param)
{
	(void)param;
	printk("End Test suite regression_1000\n");
	TEEC_FinalizeContext(&xtest_teec_ctx);
}

struct xtest_crypto_session {
	struct ADBG_Case *c;
	TEEC_Session *session;
	uint32_t cmd_id_sha256;
	uint32_t cmd_id_aes256ecb_encrypt;
	uint32_t cmd_id_aes256ecb_decrypt;
};

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

static void test_1003_thread(void *arg1, UNUSED void *arg2, UNUSED void *arg3)
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
			break;
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

ZTEST(regression_1000, test_1008)
{
	TEEC_Session session = { };
	TEEC_Session session_crypt = { };
	uint32_t ret_orig = 0;
	ADBG_STRUCT_DECLARE("TEE internal client API");

	BeginSubCase("Invoke command");
	{
		if (ADBG_EXPECT_TEEC_SUCCESS(&c,
			xtest_teec_open_session(&session, &os_test_ta_uuid,
			                        NULL, &ret_orig))) {

			(void)ADBG_EXPECT_TEEC_SUCCESS(&c,
			    TEEC_InvokeCommand(&session, TA_OS_TEST_CMD_CLIENT,
			                       NULL, &ret_orig));
			TEEC_CloseSession(&session);
		}

	}
	EndSubCase("Invoke command");

	BeginSubCase("Invoke command with timeout");
	{
		TEEC_Operation op = TEEC_OPERATION_INITIALIZER;

		op.params[0].value.a = 2000;
		op.paramTypes = TEEC_PARAM_TYPES(
			TEEC_VALUE_INPUT, TEEC_NONE, TEEC_NONE, TEEC_NONE);

		if (ADBG_EXPECT_TEEC_SUCCESS(&c, xtest_teec_open_session(&session,
					     &os_test_ta_uuid, NULL, &ret_orig))) {
			(void)ADBG_EXPECT_TEEC_SUCCESS(&c,
			  TEEC_InvokeCommand(&session,
			                     TA_OS_TEST_CMD_CLIENT_WITH_TIMEOUT,
			                     &op, &ret_orig));
			TEEC_CloseSession(&session);
		}
	}
	EndSubCase("Invoke command with timeout");

	BeginSubCase("Create session fail");
	{
		size_t n = 0;

		for (n = 0; n < 100; n++) {
			printk("n = %zu\n", n);
			(void)ADBG_EXPECT_TEEC_RESULT(&c, TEEC_ERROR_GENERIC,
				xtest_teec_open_session(&session_crypt,
					&create_fail_test_ta_uuid, NULL, &ret_orig));
			/* level > 0 may be used to detect/debug memory leaks */
			if (!level)
				break;
		}
	}
	EndSubCase("Create session fail");

	BeginSubCase("Load corrupt TA");
	printk("=============  Skipped =============\n");
//	test_1008_corrupt_ta(c);
	EndSubCase("Load corrupt TA");
	ADBG_Assert(&c);
}

static void cancellation_thread(void *arg1, UNUSED void *arg2, UNUSED void *arg3)
{
	/*
	 * Sleep 0.5 seconds before cancellation to make sure that the other
	 * thread is in RPC_WAIT.
	 */
	k_msleep(500);
	TEEC_RequestCancellation(arg1);
	return;
}

static void xtest_tee_test_1009_subcase(struct ADBG_Case *c, const char *subcase,
					uint32_t timeout, bool cancel)
{
	TEEC_Session session = { };
	uint32_t ret_orig = 0;
	static struct k_thread thr;
	k_tid_t tid;
	TEEC_Result res = TEEC_ERROR_GENERIC;

	memset(&thr, 0, sizeof(thr));

	BeginSubCase("%s", subcase);
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;

	if (ADBG_EXPECT_TEEC_SUCCESS(c,
			xtest_teec_open_session(&session, &os_test_ta_uuid, NULL, &ret_orig))) {

		(void)ADBG_EXPECT_TEEC_ERROR_ORIGIN(c, TEEC_ORIGIN_TRUSTED_APP, ret_orig);

		op.params[0].value.a = timeout;
		op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT,
				TEEC_NONE, TEEC_NONE, TEEC_NONE);
		if (cancel) {
			tid = k_thread_create(&thr, *thread_stack, STACKSIZE,
					cancellation_thread, &op, NULL, NULL,
					K_PRIO_PREEMPT(0), K_USER, K_NO_WAIT);
			if (ADBG_EXPECT_NOT(c, 0, (long)tid)) {
				res = TEEC_InvokeCommand(&session, TA_OS_TEST_CMD_WAIT,
						&op, &ret_orig);
				(void)ADBG_EXPECT_TEEC_RESULT(c, TEEC_ERROR_CANCEL, res);
			}
		} else

		res = TEEC_InvokeCommand(&session, TA_OS_TEST_CMD_WAIT, &op, &ret_orig);
		(void)ADBG_EXPECT_TEEC_SUCCESS(c, res);
		if (cancel)
			ADBG_EXPECT(c, 0, k_thread_join(&thr, K_FOREVER));

		TEEC_CloseSession(&session);
		}
	EndSubCase("%s", subcase);
}

ZTEST(regression_1000, test_1009)
{
	ADBG_STRUCT_DECLARE("TEE Wait");

	xtest_tee_test_1009_subcase(&c, "TEE Wait 0.1s", 100, false);
	xtest_tee_test_1009_subcase(&c, "TEE Wait 0.5s", 500, false);
	xtest_tee_test_1009_subcase(&c, "TEE Wait 2s cancel", 2000, true);
	xtest_tee_test_1009_subcase(&c, "TEE Wait 2s", 2000, false);
	ADBG_Assert(&c);
}

static void xtest_tee_test_invalid_mem_access(struct ADBG_Case *c, unsigned int n)
{
	TEEC_Session session = { };
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t ret_orig = 0;

	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
		xtest_teec_open_session(&session, &os_test_ta_uuid, NULL,
		                        &ret_orig)))
		return;

	op.params[0].value.a = n;
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_NONE, TEEC_NONE,
					 TEEC_NONE);

	(void)ADBG_EXPECT_TEEC_RESULT(c,
		TEEC_ERROR_TARGET_DEAD,
		TEEC_InvokeCommand(&session, TA_OS_TEST_CMD_BAD_MEM_ACCESS, &op,
				   &ret_orig));

	(void)ADBG_EXPECT_TEEC_RESULT(c,
	        TEEC_ERROR_TARGET_DEAD,
	        TEEC_InvokeCommand(&session, TA_OS_TEST_CMD_BAD_MEM_ACCESS, &op,
					&ret_orig));

	(void)ADBG_EXPECT_TEEC_ERROR_ORIGIN(c, TEEC_ORIGIN_TEE, ret_orig);

	TEEC_CloseSession(&session);
}

static void xtest_tee_test_invalid_mem_access2(struct ADBG_Case *c, unsigned int n,
							       size_t size)
{
	TEEC_Session session = { };
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t ret_orig = 0;
	TEEC_SharedMemory shm = { };

	shm.size = size;
	shm.flags = TEEC_MEM_INPUT | TEEC_MEM_OUTPUT;
	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
		TEEC_AllocateSharedMemory(&xtest_teec_ctx, &shm)))
		return;

	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
		xtest_teec_open_session(&session, &os_test_ta_uuid, NULL,
		                        &ret_orig)))
		goto rel_shm;

	op.params[0].value.a = (uint32_t)n;
	op.params[1].memref.parent = &shm;
	op.params[1].memref.size = size;
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_MEMREF_WHOLE,
					 TEEC_NONE, TEEC_NONE);

	(void)ADBG_EXPECT_TEEC_RESULT(c,
		TEEC_ERROR_TARGET_DEAD,
		TEEC_InvokeCommand(&session, TA_OS_TEST_CMD_BAD_MEM_ACCESS, &op,
				   &ret_orig));

	(void)ADBG_EXPECT_TEEC_RESULT(c,
	        TEEC_ERROR_TARGET_DEAD,
	        TEEC_InvokeCommand(&session, TA_OS_TEST_CMD_BAD_MEM_ACCESS, &op,
					&ret_orig));

	(void)ADBG_EXPECT_TEEC_ERROR_ORIGIN(c, TEEC_ORIGIN_TEE, ret_orig);

	TEEC_CloseSession(&session);
rel_shm:
	TEEC_ReleaseSharedMemory(&shm);
}

ZTEST(regression_1000, test_1010)
{
	unsigned int n = 0;
	unsigned int idx = 0;
	size_t memref_sz[] = { 1024, 65536 };
	ADBG_STRUCT_DECLARE("Invalid memory access");

	for (n = 1; n <= 7; n++) {
		BeginSubCase("Invalid memory access %u", n);
		xtest_tee_test_invalid_mem_access(&c, n);
		EndSubCase("Invalid memory access %u", n);
	}

	for (idx = 0; idx < ARRAY_SIZE(memref_sz); idx++) {
		for (n = 1; n <= 5; n++) {
			BeginSubCase("Invalid memory access %u with %zu bytes memref",
				n, memref_sz[idx]);
			xtest_tee_test_invalid_mem_access2(&c, n, memref_sz[idx]);
			EndSubCase("Invalid memory access %u with %zu bytes memref",
				n, memref_sz[idx]);
		}
	}
	ADBG_Assert(&c);
}

ZTEST(regression_1000, test_1011)
{
	TEEC_Session session = { };
	uint32_t ret_orig = 0;
	ADBG_STRUCT_DECLARE("Test TA-to-TA features with User Crypt TA");
	struct xtest_crypto_session cs = {
		&c, &session, TA_RPC_CMD_CRYPT_SHA256,
		TA_RPC_CMD_CRYPT_AES256ECB_ENC,
		TA_RPC_CMD_CRYPT_AES256ECB_DEC
	};
	struct xtest_crypto_session cs_privmem = {
		&c, &session,
		TA_RPC_CMD_CRYPT_PRIVMEM_SHA256,
		TA_RPC_CMD_CRYPT_PRIVMEM_AES256ECB_ENC,
		TA_RPC_CMD_CRYPT_PRIVMEM_AES256ECB_DEC
	};
	TEEC_UUID uuid = rpc_test_ta_uuid;

	if (!ADBG_EXPECT_TEEC_SUCCESS(&c,
		xtest_teec_open_session(&session, &uuid, NULL, &ret_orig)))
                ADBG_Assert(&c);

        BeginSubCase("TA-to-TA via non-secure shared memory");
	/*
	 * Run the "complete crypto test suite" using TA-to-TA
	 * communication
	 */
	xtest_crypto_test(&cs);
	EndSubCase("TA-to-TA via non-secure shared memory");

	BeginSubCase("TA-to-TA via TA private memory");
	/*
	 * Run the "complete crypto test suite" using TA-to-TA
	 * communication via TA private memory.
	 */
	xtest_crypto_test(&cs_privmem);
	EndSubCase("TA-to-TA via TA private memory");

	TEEC_CloseSession(&session);
	ADBG_Assert(&c);
}

/*
 * Note that this test is failing when
 * - running twice in a raw
 * - and the user TA is statically linked
 * This is because the counter is not reseted when opening the first session
 * in case the TA is statically linked
 */
ZTEST(regression_1000, test_1012)
{
	TEEC_Session session1 = { };
	TEEC_Session session2 = { };
	uint32_t ret_orig = 0;
	TEEC_UUID uuid = sims_test_ta_uuid;
	ADBG_STRUCT_DECLARE("Test Single Instance Multi Session features with SIMS TA");

	BeginSubCase("Single Instance Multi Session");
	{
		TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
		static const uint8_t in[] = {
			0x5A, 0x6E, 0x04, 0x57, 0x08, 0xFB, 0x71, 0x96,
			0xF0, 0x2E, 0x55, 0x3D, 0x02, 0xC3, 0xA6, 0x92,
			0xE9, 0xC3, 0xEF, 0x8A, 0xB2, 0x34, 0x53, 0xE6,
			0xF0, 0x74, 0x9C, 0xD6, 0x36, 0xE7, 0xA8, 0x8E
		};
		uint8_t out[32] = { };
		int i = 0;

		if (!ADBG_EXPECT_TEEC_SUCCESS(&c,
			xtest_teec_open_session(&session1, &uuid, NULL,
			                        &ret_orig)))
                        ADBG_Assert(&c);

                op.params[0].value.a = 0;
		op.params[1].tmpref.buffer = (void *)in;
		op.params[1].tmpref.size = sizeof(in);
		op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT,
						 TEEC_MEMREF_TEMP_INPUT,
						 TEEC_NONE, TEEC_NONE);

		(void)ADBG_EXPECT_TEEC_SUCCESS(&c,
			TEEC_InvokeCommand(&session1, TA_SIMS_CMD_WRITE, &op,
					   &ret_orig));

		for (i = 1; i < 3; i++) {
			if (!ADBG_EXPECT_TEEC_SUCCESS(&c,
				xtest_teec_open_session(&session2, &uuid, NULL,
				                        &ret_orig)))
				continue;

			op.params[0].value.a = 0;
			op.params[1].tmpref.buffer = out;
			op.params[1].tmpref.size = sizeof(out);
			op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT,
						TEEC_MEMREF_TEMP_OUTPUT,
						TEEC_NONE, TEEC_NONE);

			(void)ADBG_EXPECT_TEEC_SUCCESS(&c,
				TEEC_InvokeCommand(&session2, TA_SIMS_CMD_READ,
						   &op, &ret_orig));

			if (!ADBG_EXPECT_BUFFER(&c, in, sizeof(in), out,
						sizeof(out))) {
				printk("in:\n");
				Do_ADBG_HexLog(in, sizeof(in), 16);
				printk("out:\n");
				Do_ADBG_HexLog(out, sizeof(out), 16);
			}

			op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_OUTPUT,
							 TEEC_NONE, TEEC_NONE,
							 TEEC_NONE);

			(void)ADBG_EXPECT_TEEC_SUCCESS(&c,
				TEEC_InvokeCommand(&session1,
						   TA_SIMS_CMD_GET_COUNTER,
						   &op, &ret_orig));

			(void)ADBG_EXPECT(&c, 0, op.params[0].value.a);

			(void)ADBG_EXPECT_TEEC_SUCCESS(&c,
				TEEC_InvokeCommand(&session2,
						   TA_SIMS_CMD_GET_COUNTER, &op,
						   &ret_orig));

			(void)ADBG_EXPECT(&c, i, op.params[0].value.a);
			TEEC_CloseSession(&session2);
		}

		memset(out, 0, sizeof(out));
		op.params[0].value.a = 0;
		op.params[1].tmpref.buffer = out;
		op.params[1].tmpref.size = sizeof(out);
		op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT,
						 TEEC_MEMREF_TEMP_OUTPUT,
						 TEEC_NONE, TEEC_NONE);

		(void)ADBG_EXPECT_TEEC_SUCCESS(&c,
			TEEC_InvokeCommand(&session1, TA_SIMS_CMD_READ, &op,
					   &ret_orig));

		if (!ADBG_EXPECT(&c, 0, memcmp(in, out, sizeof(in)))) {
			printk("in:\n");
			Do_ADBG_HexLog(in, sizeof(in), 16);
			printk("out:\n");
			Do_ADBG_HexLog(out, sizeof(out), 16);
		}

		TEEC_CloseSession(&session1);
	}
	EndSubCase("Single Instance Multi Session");
	ADBG_Assert(&c);
}

struct test_1013_thread_arg {
	const TEEC_UUID *uuid;
	uint32_t cmd;
	uint32_t repeat;
	TEEC_SharedMemory *shm;
	uint32_t error_orig;
	TEEC_Result res;
	uint32_t max_concurrency;
	const uint8_t *in;
	size_t in_len;
	uint8_t *out;
	size_t out_len;
};

static void test_1013_thread(void *arg1, UNUSED void *arg2, UNUSED void *arg3)
{
	struct test_1013_thread_arg *a = arg1;
	TEEC_Session session = { };
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint8_t p2 = TEEC_NONE;
	uint8_t p3 = TEEC_NONE;

	a->res = xtest_teec_open_session(&session, a->uuid, NULL,
					 &a->error_orig);
	if (a->res != TEEC_SUCCESS)
		return;

	op.params[0].memref.parent = a->shm;
	op.params[0].memref.size = a->shm->size;
	op.params[0].memref.offset = 0;
	op.params[1].value.a = a->repeat;
	op.params[1].value.b = 0;
	op.params[2].tmpref.buffer = (void *)a->in;
	op.params[2].tmpref.size = a->in_len;
	op.params[3].tmpref.buffer = a->out;
	op.params[3].tmpref.size = a->out_len;

	if (a->in_len)
		p2 = TEEC_MEMREF_TEMP_INPUT;
	if (a->out_len)
		p3 = TEEC_MEMREF_TEMP_OUTPUT;

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_PARTIAL_INOUT,
					 TEEC_VALUE_INOUT, p2, p3);

	a->res = TEEC_InvokeCommand(&session, a->cmd, &op, &a->error_orig);
	a->max_concurrency = op.params[1].value.b;
	a->out_len = op.params[3].tmpref.size;
	TEEC_CloseSession(&session);
	return;
}

#define NUM_THREADS 3

static void xtest_tee_test_1013_single(struct ADBG_Case *c, double *mean_concurrency,
				       const TEEC_UUID *uuid)
{
	size_t nt = 0;
	size_t n = 0;
	size_t repeat = 1000;
	TEEC_SharedMemory shm = { };
	size_t max_concurrency = 0;
	struct test_1013_thread_arg arg[NUM_THREADS] = { };
	static const uint8_t sha256_in[] = { 'a', 'b', 'c' };
	static const uint8_t sha256_out[] = {
		0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
		0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
		0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
		0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad
	};
	uint8_t out[32] = { };
	bool skip = false;

	BeginSubCase("Busy loop repeat %zu", repeat * 10);
	*mean_concurrency = 0;

	shm.size = sizeof(struct ta_concurrent_shm);
	shm.flags = TEEC_MEM_INPUT | TEEC_MEM_OUTPUT;
	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
		TEEC_AllocateSharedMemory(&xtest_teec_ctx, &shm)))
                return;

        memset(shm.buffer, 0, shm.size);
	max_concurrency = 0;
	nt = NUM_THREADS;

	for (n = 0; n < nt; n++) {
		k_tid_t tid;
		arg[n].uuid = uuid;
		arg[n].cmd = TA_CONCURRENT_CMD_BUSY_LOOP;
		arg[n].repeat = repeat * 10;
		arg[n].shm = &shm;
		tid = k_thread_create(thr+n, thread_stack[n], STACKSIZE, test_1013_thread,
				      arg+n, NULL, NULL, K_PRIO_PREEMPT(0), K_USER, K_NO_WAIT);
		if (!ADBG_EXPECT_NOT(c, 0, (long)tid))
			break; /* break loop and start cleanup */
	}

	for (n = 0; n < nt; n++) {
		ADBG_EXPECT(c, 0, k_thread_join(thr+n, K_FOREVER));
		if (arg[n].res == TEEC_ERROR_OUT_OF_MEMORY &&
		    !memcmp(uuid, &concurrent_large_ta_uuid, sizeof(*uuid))) {
			printk("TEEC_ERROR_OUT_OF_MEMORY - ignored\n");
			skip = true;
			continue;
		}
		ADBG_EXPECT_TEEC_SUCCESS(c, arg[n].res);
		if (arg[n].max_concurrency > max_concurrency)
			max_concurrency = arg[n].max_concurrency;
	}

	/*
	 * Concurrency can be limited by several factors, for instance in a
	 * single CPU system it's dependent on the Preemption Model used by
	 * the kernel (Preemptible Kernel (Low-Latency Desktop) gives the
	 * best result there).
	 */
	if (!skip) {
		(void)ADBG_EXPECT_COMPARE_UNSIGNED(c, max_concurrency, >, 0);
		(void)ADBG_EXPECT_COMPARE_UNSIGNED(c, max_concurrency, <=,
						   NUM_THREADS);
		*mean_concurrency += max_concurrency;
	}
	EndSubCase("Busy loop repeat %zu", repeat * 10);

	BeginSubCase("SHA-256 loop repeat %zu", repeat);
	memset(shm.buffer, 0, shm.size);
	memset(arg, 0, sizeof(arg));
	max_concurrency = 0;
	nt = NUM_THREADS;

	for (n = 0; n < nt; n++) {
		k_tid_t tid;
		arg[n].uuid = uuid;
		arg[n].cmd = TA_CONCURRENT_CMD_SHA256;
		arg[n].repeat = repeat;
		arg[n].shm = &shm;
		arg[n].in = sha256_in;
		arg[n].in_len = sizeof(sha256_in);
		arg[n].out = out;
		arg[n].out_len = sizeof(out);
		tid = k_thread_create(thr+n, thread_stack[n], STACKSIZE, test_1013_thread,
				      arg+n, NULL, NULL, K_PRIO_PREEMPT(0), K_USER, K_NO_WAIT);
		if (!ADBG_EXPECT_NOT(c, 0, (long)tid))
			break; /* break loop and start cleanup */
	}

	for (n = 0; n < nt; n++) {
		ADBG_EXPECT(c, 0, k_thread_join(thr+n, K_FOREVER));
		if (arg[n].res == TEEC_ERROR_OUT_OF_MEMORY &&
		    !memcmp(uuid, &concurrent_large_ta_uuid, sizeof(*uuid))) {
			printk("TEEC_ERROR_OUT_OF_MEMORY - ignored\n");
			continue;
		}
		if (ADBG_EXPECT_TEEC_SUCCESS(c, arg[n].res))
			ADBG_EXPECT_BUFFER(c, sha256_out, sizeof(sha256_out),
					   arg[n].out, arg[n].out_len);
		if (arg[n].max_concurrency > max_concurrency)
			max_concurrency = arg[n].max_concurrency;
	}
	*mean_concurrency += max_concurrency;
	EndSubCase("SHA-256 loop repeat %zu", repeat);

	*mean_concurrency /= 2.0;
	TEEC_ReleaseSharedMemory(&shm);
}

ZTEST(regression_1000, test_1013)
{
	int i = 0;
	double mean_concurrency = 0;
	double concurrency = 0;
	int nb_loops = 24;
	ADBG_STRUCT_DECLARE("Test concurrency with concurrent TA");

	if (level == 0)
		nb_loops /= 2;

	BeginSubCase("Using small concurrency TA");
	mean_concurrency = 0;
	for (i = 0; i < nb_loops; i++) {
		xtest_tee_test_1013_single(&c, &concurrency,
					   &concurrent_ta_uuid);
		mean_concurrency += concurrency;
	}
	mean_concurrency /= nb_loops;

	printk("    Number of parallel threads: %d\n", NUM_THREADS);
	printk("    Mean concurrency: %g\n", mean_concurrency);
	EndSubCase("Using small concurrency TA");

	BeginSubCase("Using large concurrency TA");
	mean_concurrency = 0;
	for (i = 0; i < nb_loops; i++) {
		xtest_tee_test_1013_single(&c, &concurrency,
					   &concurrent_large_ta_uuid);
		mean_concurrency += concurrency;
	}
	mean_concurrency /= nb_loops;

	printk("    Number of parallel threads: %d\n", NUM_THREADS);
	printk("    Mean concurrency: %g\n", mean_concurrency);
	EndSubCase("Using large concurrency TA");
	ADBG_Assert(&c);
}

ZTEST(regression_1000, test_1016)
{
	TEEC_Session session = { };
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t ret_orig = 0;
	ADBG_STRUCT_DECLARE("Test TA to TA transfers (in/out/inout memrefs on the stack)");

	if (!ADBG_EXPECT_TEEC_SUCCESS(&c,
			xtest_teec_open_session(&session, &os_test_ta_uuid, NULL, &ret_orig))) {
		ADBG_Assert(&c);
		return;
	}

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_NONE, TEEC_NONE, TEEC_NONE,
					 TEEC_NONE);

	(void)ADBG_EXPECT_TEEC_SUCCESS(&c,
		TEEC_InvokeCommand(&session, TA_OS_TEST_CMD_TA2TA_MEMREF, &op, &ret_orig));

	TEEC_CloseSession(&session);
	ADBG_Assert(&c);
}

ZTEST(regression_1000, test_1017)
{
	TEEC_Session session = { };
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t ret_orig = 0;
	TEEC_SharedMemory shm = { };
	size_t page_size = 4096;
	ADBG_STRUCT_DECLARE("Test coalescing memrefs");

	shm.size = 8 * page_size;
	shm.flags = TEEC_MEM_INPUT | TEEC_MEM_OUTPUT;
	if (!ADBG_EXPECT_TEEC_SUCCESS(&c,
		TEEC_AllocateSharedMemory(&xtest_teec_ctx, &shm)))
                ADBG_Assert(&c);

        if (!ADBG_EXPECT_TEEC_SUCCESS(&c,
			xtest_teec_open_session(&session, &os_test_ta_uuid, NULL, &ret_orig))) {
		goto out;
	}

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_PARTIAL_INPUT,
					 TEEC_MEMREF_PARTIAL_INPUT,
					 TEEC_MEMREF_PARTIAL_OUTPUT,
					 TEEC_MEMREF_PARTIAL_OUTPUT);

	/*
	 * The first two memrefs are supposed to be combined into in
	 * region and the last two memrefs should have one region each
	 * when the parameters are mapped for the TA.
	 */
	op.params[0].memref.parent = &shm;
	op.params[0].memref.size = page_size;
	op.params[0].memref.offset = 0;

	op.params[1].memref.parent = &shm;
	op.params[1].memref.size = page_size;
	op.params[1].memref.offset = page_size;

	op.params[2].memref.parent = &shm;
	op.params[2].memref.size = page_size;
	op.params[2].memref.offset = 4 * page_size;

	op.params[3].memref.parent = &shm;
	op.params[3].memref.size = 2 * page_size;
	op.params[3].memref.offset = 6 * page_size;

	(void)ADBG_EXPECT_TEEC_SUCCESS(&c,
		TEEC_InvokeCommand(&session, TA_OS_TEST_CMD_PARAMS, &op, &ret_orig));

	TEEC_CloseSession(&session);
out:
	TEEC_ReleaseSharedMemory(&shm);
	ADBG_Assert(&c);
}

static void invoke_1byte_out_of_bounds(struct ADBG_Case *c, TEEC_Session *session,
				       TEEC_SharedMemory *shm)
{
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	TEEC_Result ret = TEEC_ERROR_GENERIC;
	uint32_t ret_orig = 0;

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_PARTIAL_INPUT,
					 TEEC_NONE, TEEC_NONE, TEEC_NONE);

	op.params[0].memref.parent = shm;
	op.params[0].memref.size = shm->size / 2;
	op.params[0].memref.offset = shm->size - (shm->size / 2) + 1;

	ret = TEEC_InvokeCommand(session, TA_OS_TEST_CMD_PARAMS,
				 &op, &ret_orig);

	ADBG_EXPECT_COMPARE_UNSIGNED(c, ret_orig, !=, TEEC_ORIGIN_TRUSTED_APP);
	if (ret != TEEC_ERROR_BAD_PARAMETERS && ret != TEEC_ERROR_GENERIC) {
		ADBG_EXPECT(c, TEEC_ERROR_BAD_PARAMETERS, ret);
		ADBG_EXPECT(c, TEEC_ERROR_GENERIC, ret);
	}
}

ZTEST(regression_1000, test_1018)
{
	TEEC_Session session = { };
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t ret_orig = 0;
	TEEC_SharedMemory shm = { };
	TEEC_Result ret = TEEC_ERROR_GENERIC;
	size_t page_size = 4096;
	/* Intentionally not 4kB aligned and odd */
	uint8_t buffer[6001] = { };
	ADBG_STRUCT_DECLARE("Test memref out of bounds");

	if (!ADBG_EXPECT_TEEC_SUCCESS(&c,
				      xtest_teec_open_session(&session,
							      &os_test_ta_uuid,
							      NULL,
							      &ret_orig))) {
		ADBG_Assert(&c);
		return;
	}

	BeginSubCase("Out of bounds > 4kB on allocated shm");

	shm.size = 8 * page_size;
	shm.flags = TEEC_MEM_INPUT | TEEC_MEM_OUTPUT;
	if (!ADBG_EXPECT_TEEC_SUCCESS(&c,
				      TEEC_AllocateSharedMemory(&xtest_teec_ctx,
								&shm)))
		goto out;

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_PARTIAL_INPUT,
					 TEEC_MEMREF_PARTIAL_INPUT,
					 TEEC_MEMREF_PARTIAL_OUTPUT,
					 TEEC_MEMREF_PARTIAL_OUTPUT);

	/*
	 * The first two memrefs are supposed to be combined into in
	 * region and the last two memrefs should have one region each
	 * when the parameters are mapped for the TA.
	 */
	op.params[0].memref.parent = &shm;
	op.params[0].memref.size = page_size;
	op.params[0].memref.offset = 0;

	op.params[1].memref.parent = &shm;
	op.params[1].memref.size = page_size;
	op.params[1].memref.offset = page_size;

	op.params[2].memref.parent = &shm;
	op.params[2].memref.size = page_size;
	op.params[2].memref.offset = 4 * page_size;

	op.params[3].memref.parent = &shm;
	op.params[3].memref.size = 3 * page_size;
	op.params[3].memref.offset = 6 * page_size;

	ret = TEEC_InvokeCommand(&session, TA_OS_TEST_CMD_PARAMS, &op,
				 &ret_orig);

	ADBG_EXPECT_COMPARE_UNSIGNED(&c, ret_orig, !=, TEEC_ORIGIN_TRUSTED_APP);
	if (ret != TEEC_ERROR_BAD_PARAMETERS && ret != TEEC_ERROR_GENERIC) {
		ADBG_EXPECT(&c, TEEC_ERROR_BAD_PARAMETERS, ret);
		ADBG_EXPECT(&c, TEEC_ERROR_GENERIC, ret);
	}

	TEEC_ReleaseSharedMemory(&shm);
	EndSubCase(NULL);

	BeginSubCase("Out of bounds by 1 byte on registered shm");

	memset(&shm, 0, sizeof(shm));
	shm.flags = TEEC_MEM_INPUT | TEEC_MEM_OUTPUT;
	shm.buffer = buffer;
	shm.size = sizeof(buffer);

	if (!ADBG_EXPECT_TEEC_SUCCESS(&c,
				      TEEC_RegisterSharedMemory(&xtest_teec_ctx,
								&shm)))
		goto out;

	invoke_1byte_out_of_bounds(&c, &session, &shm);

	TEEC_ReleaseSharedMemory(&shm);
	EndSubCase(NULL);

	BeginSubCase("Out of bounds by 1 byte ref on allocated shm");

	memset(&shm, 0, sizeof(shm));
	shm.size = sizeof(buffer);
	shm.flags = TEEC_MEM_INPUT | TEEC_MEM_OUTPUT;
	if (!ADBG_EXPECT_TEEC_SUCCESS(&c,
				      TEEC_AllocateSharedMemory(&xtest_teec_ctx,
								&shm)))
		goto out;

	invoke_1byte_out_of_bounds(&c, &session, &shm);

	TEEC_ReleaseSharedMemory(&shm);
	EndSubCase(NULL);

out:
	TEEC_CloseSession(&session);
	ADBG_Assert(&c);
}

ZTEST(regression_1000, test_1019)
{
	TEEC_Session session = { };
	uint32_t ret_orig = 0;
	ADBG_STRUCT_DECLARE("Test dynamically linked TA");

	if (!ADBG_EXPECT_TEEC_SUCCESS(&c,
			xtest_teec_open_session(&session, &os_test_ta_uuid, NULL, &ret_orig))) {
		ADBG_Assert(&c);
		return;
	}

	(void)ADBG_EXPECT_TEEC_SUCCESS(&c,
		TEEC_InvokeCommand(&session, TA_OS_TEST_CMD_CALL_LIB, NULL, &ret_orig));

	(void)ADBG_EXPECT_TEEC_RESULT(&c,
		TEEC_ERROR_TARGET_DEAD,
		TEEC_InvokeCommand(&session, TA_OS_TEST_CMD_CALL_LIB_PANIC,
				   NULL, &ret_orig));

	(void)ADBG_EXPECT_TEEC_ERROR_ORIGIN(&c, TEEC_ORIGIN_TEE, ret_orig);

	TEEC_CloseSession(&session);
	ADBG_Assert(&c);
}

ZTEST(regression_1000, test_1020)
{
	TEEC_Result res = TEEC_ERROR_GENERIC;
	TEEC_Session session = { };
	uint32_t ret_orig = 0;
	ADBG_STRUCT_DECLARE("Test lockdep algorithm");

	/* Pseudo TA is optional: warn and nicely exit if not found */
	res = xtest_teec_open_session(&session, &pta_invoke_tests_ta_uuid, NULL, &ret_orig);
	if (res == TEEC_ERROR_ITEM_NOT_FOUND) {
		printk(" - 1020 -   skip test, pseudo TA not found\n");
		ADBG_Assert(&c);
		return;
	}
	ADBG_EXPECT_TEEC_SUCCESS(&c, res);

	res = TEEC_InvokeCommand(&session, PTA_INVOKE_TESTS_CMD_LOCKDEP,
				 NULL, &ret_orig);
	if (res != TEEC_SUCCESS) {
		(void)ADBG_EXPECT_TEEC_ERROR_ORIGIN(&c, TEEC_ORIGIN_TRUSTED_APP,
						    ret_orig);
		if (res == TEEC_ERROR_NOT_SUPPORTED) {
			printk(" - 1020 -   skip test, feature not implemented\n");
			goto out;
		}
		/* Error */
		(void)ADBG_EXPECT_TEEC_SUCCESS(&c, res);
	}
out:
	TEEC_CloseSession(&session);
	ADBG_Assert(&c);
}

static TEEC_Result open_sec_session(TEEC_Session *session,
				    const TEEC_UUID *uuid)
{
	TEEC_Result res = TEEC_ERROR_GENERIC;
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t ret_orig = 0;

	op.params[0].tmpref.buffer = (void *)uuid;
	op.params[0].tmpref.size = sizeof(*uuid);
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
					 TEEC_NONE, TEEC_NONE, TEEC_NONE);

	res = TEEC_InvokeCommand(session, TA_SIMS_OPEN_TA_SESSION,
				 &op, &ret_orig);
	if (res != TEEC_SUCCESS)
		return TEEC_ERROR_GENERIC;

	return res;
}

static TEEC_Result sims_get_counter(TEEC_Session *session,
				    uint32_t *counter)
{
	TEEC_Result res = TEEC_ERROR_GENERIC;
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t ret_orig = 0;

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_OUTPUT,
					 TEEC_NONE, TEEC_NONE, TEEC_NONE);

	res = TEEC_InvokeCommand(session, TA_SIMS_CMD_GET_COUNTER,
				 &op, &ret_orig);
	if (res == TEEC_SUCCESS)
		*counter = op.params[0].value.a;

	return res;
}

static TEEC_Result trigger_panic(TEEC_Session *session,
				 const TEEC_UUID *uuid)
{
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t ret_orig = 0;

	if (!uuid) {
		op.params[0].tmpref.buffer = NULL;
		op.params[0].tmpref.size = 0;
	} else {
		op.params[0].tmpref.buffer = (void *)uuid;
		op.params[0].tmpref.size = sizeof(*uuid);
	}
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
					 TEEC_NONE, TEEC_NONE, TEEC_NONE);

	return TEEC_InvokeCommand(session, TA_SIMS_CMD_PANIC,
				  &op, &ret_orig);
}

static void test_panic_ca_to_ta(struct ADBG_Case *c, const TEEC_UUID *uuid,
				bool multi_instance)
{
	TEEC_Result exp_res = TEEC_ERROR_GENERIC;
	uint32_t counter = 0;
	uint32_t ret_orig = 0;
	uint32_t exp_counter = 0;
	TEEC_Session cs[3] = { };

	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
			xtest_teec_open_session(&cs[0], uuid, NULL,
						&ret_orig)))
		return;

	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
			xtest_teec_open_session(&cs[1], uuid, NULL,
						&ret_orig)))
		goto bail0;

	if (!ADBG_EXPECT_TEEC_SUCCESS(c, sims_get_counter(&cs[0], &counter)))
		goto bail1;

	if (!ADBG_EXPECT(c, 0, counter))
		goto bail1;

	if (!ADBG_EXPECT_TEEC_SUCCESS(c, sims_get_counter(&cs[1], &counter)))
		goto bail1;

	exp_counter = multi_instance ? 0 : 1;
	if (!ADBG_EXPECT(c, exp_counter, counter))
		goto bail1;

	if (!ADBG_EXPECT_TEEC_RESULT(c, TEEC_ERROR_TARGET_DEAD,
				     trigger_panic(&cs[1], NULL)))
		goto bail1;

	exp_res = multi_instance ? TEEC_SUCCESS : TEEC_ERROR_TARGET_DEAD;
	if (!ADBG_EXPECT_TEEC_RESULT(c, exp_res,
				     sims_get_counter(&cs[0], &counter)))
		goto bail1;

	if (!ADBG_EXPECT_TEEC_RESULT(c, TEEC_ERROR_TARGET_DEAD,
				     sims_get_counter(&cs[1], &counter)))
		goto bail1;

	/* Attempt to open a session on panicked context */
	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
			xtest_teec_open_session(&cs[1], uuid, NULL,
						&ret_orig)))
		goto bail1;

	/* Sanity check of still valid TA context */
	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
			xtest_teec_open_session(&cs[2], uuid, NULL,
						&ret_orig)))
		goto bail1;

	/* Sanity check of still valid TA context */
	if (multi_instance) {
		if (!ADBG_EXPECT_TEEC_SUCCESS(c,
				sims_get_counter(&cs[0], &counter)))
			goto bail2;

		if (!ADBG_EXPECT(c, 0, counter))
			goto bail2;
	}

	if (!ADBG_EXPECT_TEEC_SUCCESS(c, sims_get_counter(&cs[2], &counter)))
		goto bail2;

	exp_counter = multi_instance ? 0 : 1;
	if (!ADBG_EXPECT(c, exp_counter, counter))
		goto bail2;

bail2:
	TEEC_CloseSession(&cs[2]);
bail1:
	TEEC_CloseSession(&cs[1]);
bail0:
	TEEC_CloseSession(&cs[0]);
}

static void test_panic_ta_to_ta(struct ADBG_Case *c, const TEEC_UUID *uuid1,
				const TEEC_UUID *uuid2)
{
	uint32_t ret_orig = 0;
	uint32_t counter = 0;
	TEEC_Session cs[3] = { };

	/* Test pre-conditions */
	/* 2.1 - CA opens a session toward TA1 */
	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
			xtest_teec_open_session(&cs[0], uuid1, NULL,
						&ret_orig)))
		return;

	/* 2.2 - CA opens a session toward TA2 */
	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
			xtest_teec_open_session(&cs[1], uuid2, NULL,
						&ret_orig)))
		goto bail0;

	/* 2.3 - TA1 opens a session toward TA2 */
	if (!ADBG_EXPECT_TEEC_SUCCESS(c, open_sec_session(&cs[0], uuid2)))
		goto bail1;

	/* 2.4 - CA invokes TA2 which panics */
	if (!ADBG_EXPECT_TEEC_RESULT(c, TEEC_ERROR_TARGET_DEAD,
				     trigger_panic(&cs[1], NULL)))
		goto bail1;

	/* Expected results */
	/* 2.5 - Expect CA->TA1 session is still alive */
	if (!ADBG_EXPECT_TEEC_SUCCESS(c, sims_get_counter(&cs[0], &counter)))
		goto bail1;

	/* 2.6 - Expect CA->TA2 session is properly released */
	if (!ADBG_EXPECT_TEEC_RESULT(c, TEEC_ERROR_TARGET_DEAD,
				     sims_get_counter(&cs[1], &counter)))
		goto bail1;

bail1:
	TEEC_CloseSession(&cs[1]);
bail0:
	TEEC_CloseSession(&cs[0]);

	memset(cs, 0, sizeof(cs));

	/* Test pre-conditions */
	/* 2.1 - CA opens a session toward TA1 */
	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
			xtest_teec_open_session(&cs[0], uuid1, NULL,
						&ret_orig)))
		return;

	/* 2.2 - CA opens a session toward TA2 */
	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
			xtest_teec_open_session(&cs[1], uuid2, NULL,
						&ret_orig)))
		goto bail2;

	/* 2.3 - TA1 opens a session toward TA2 */
	if (!ADBG_EXPECT_TEEC_SUCCESS(c, open_sec_session(&cs[0], uuid2)))
		goto bail3;

	/* 2.4 - CA invokes TA1 which invokes TA2 which panics */
	if (!ADBG_EXPECT_TEEC_SUCCESS(c, trigger_panic(&cs[0], uuid2)))
		goto bail3;

	/* Expected results */
	/* 2.5 - Expect CA->TA1 session is still alive */
	if (!ADBG_EXPECT_TEEC_SUCCESS(c, sims_get_counter(&cs[0], &counter)))
		goto bail3;

	/* 2.6 - Expect CA->TA2 session is properly released */
	if (!ADBG_EXPECT_TEEC_RESULT(c, TEEC_ERROR_TARGET_DEAD,
				     sims_get_counter(&cs[1], &counter)))
		goto bail3;

bail3:
	TEEC_CloseSession(&cs[1]);
bail2:
	TEEC_CloseSession(&cs[0]);
}

ZTEST(regression_1000, test_1021)
{
	ADBG_STRUCT_DECLARE("Test panic context release");

	BeginSubCase("Multiple Instances Single Session");
	test_panic_ca_to_ta(&c, &miss_test_ta_uuid, true);
	EndSubCase("Multiple Instances Single Session");

	BeginSubCase("Single Instance Multi Sessions");
	test_panic_ca_to_ta(&c, &sims_test_ta_uuid, false);
	EndSubCase("Single Instance Multi Sessions");

	BeginSubCase("Single Instance Multi Sessions Keep Alive");
	test_panic_ca_to_ta(&c, &sims_keepalive_test_ta_uuid, false);
	EndSubCase("Single Instance Multi Sessions Keep Alive");

	BeginSubCase("Multi Sessions TA to TA");
	test_panic_ta_to_ta(&c, &sims_test_ta_uuid, &sims_keepalive_test_ta_uuid);
	EndSubCase("Multi Sessions TA to TA");
	ADBG_Assert(&c);
}

ZTEST(regression_1000, test_1022)
{
	TEEC_Session session = { 0 };
	uint32_t ret_orig = 0;
	ADBG_STRUCT_DECLARE("Test dlopen()/dlsym()/dlclose() API");

	if (!ADBG_EXPECT_TEEC_SUCCESS(&c,
			xtest_teec_open_session(&session, &os_test_ta_uuid, NULL, &ret_orig))) {
		ADBG_Assert(&c);
		return;
	}

	(void)ADBG_EXPECT_TEEC_SUCCESS(&c,
		TEEC_InvokeCommand(&session, TA_OS_TEST_CMD_CALL_LIB_DL, NULL, &ret_orig));

	(void)ADBG_EXPECT_TEEC_RESULT(&c,
		TEEC_ERROR_TARGET_DEAD,
		TEEC_InvokeCommand(&session, TA_OS_TEST_CMD_CALL_LIB_DL_PANIC, NULL, &ret_orig));

	(void)ADBG_EXPECT_TEEC_ERROR_ORIGIN(&c, TEEC_ORIGIN_TEE, ret_orig);

	TEEC_CloseSession(&session);
	ADBG_Assert(&c);
}

ZTEST_SUITE(regression_1000, NULL, regression_1000_init, NULL, NULL, regression_1000_deinit);
