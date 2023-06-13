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

void *regression_1000_init(void)
{
	printk("Begin Test suite 1000\n");
	return NULL;
}

void regression_1000_deinit(void *param)
{
	(void)param;
	printk("End Test suite 1000\n");
}

struct xtest_crypto_session {
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

ZTEST(regression_1000, test_1001)
{
	TEEC_Result res = TEEC_ERROR_GENERIC;
	TEEC_Session session = { };
	uint32_t ret_orig = 0;


	BeginTest(__func__);
	/* Pseudo TA is optional: warn and nicely exit if not found */
	res = xtest_teec_open_session(&session, &pta_invoke_tests_ta_uuid, NULL,
				      &ret_orig);
	if (res == TEEC_ERROR_ITEM_NOT_FOUND) {
		printk(" - 1001 -   skip test, pseudo TA not found");
		return;
	}
	if (!ADBG_EXPECT_TEEC_SUCCESS(c, res))
		return;

	BeginSubCase("Core self tests");

	(void)ADBG_EXPECT_TEEC_SUCCESS(c, TEEC_InvokeCommand(
		&session, PTA_INVOKE_TESTS_CMD_SELF_TESTS, NULL, &ret_orig));

	EndSubCase("Core self tests");

	BeginSubCase("Core dt_driver self tests");

	(void)ADBG_EXPECT_TEEC_SUCCESS(c, TEEC_InvokeCommand(
		&session, PTA_INVOKE_TESTS_CMD_DT_DRIVER_TESTS, NULL,
		&ret_orig));

	EndSubCase("Core dt_driver self tests");

	TEEC_CloseSession(&session);
	EndTest(__func__);
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

	BeginTest(__func__);
	/* Pseudo TA is optional: warn and nicely exit if not found */
	res = xtest_teec_open_session(&session, &pta_invoke_tests_ta_uuid, NULL,
				      &ret_orig);
	if (res == TEEC_ERROR_ITEM_NOT_FOUND) {
		printk(" - 1002 -   skip test, pseudo TA not found");
		return;
	}
	ADBG_EXPECT_TEEC_SUCCESS(c, res);

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INOUT, TEEC_NONE,
					 TEEC_NONE, TEEC_NONE);
	op.params[0].tmpref.size = sizeof(buf);
	op.params[0].tmpref.buffer = buf;

	for (n = 0; n < sizeof(buf); n++)
		buf[n] = n + 1;
	for (n = 0; n < sizeof(buf); n++)
		exp_sum += buf[n];

	if (!ADBG_EXPECT_TEEC_SUCCESS(c, TEEC_InvokeCommand(
		&session, PTA_INVOKE_TESTS_CMD_PARAMS, &op, &ret_orig)))
		goto out;

	ADBG_EXPECT_COMPARE_SIGNED(exp_sum, ==, buf[0]);
out:
	TEEC_CloseSession(&session);
	EndTest(__func__);
}

ZTEST_SUITE(regression_1000, NULL, regression_1000_init, NULL, NULL, regression_1000_deinit);

