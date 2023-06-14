#include <stdlib.h>
#include <stdint.h>
#include <zephyr/kernel.h>
#include <zephyr/ztest.h>
#include <tee_client_api.h>
#include "optee_test.h"

const TEEC_UUID crypt_user_ta_uuid = TA_CRYPT_UUID;
const TEEC_UUID os_test_ta_uuid = TA_OS_TEST_UUID;
const TEEC_UUID create_fail_test_ta_uuid = TA_CREATE_FAIL_TEST_UUID;
const TEEC_UUID ecc_test_ta_uuid = ECC_SELF_TEST_UUID;
const TEEC_UUID pta_invoke_tests_ta_uuid = PTA_INVOKE_TESTS_UUID;
const TEEC_UUID rpc_test_ta_uuid = TA_RPC_TEST_UUID;
const TEEC_UUID sims_test_ta_uuid = TA_SIMS_TEST_UUID;
const TEEC_UUID miss_test_ta_uuid = TA_MISS_TEST_UUID;
const TEEC_UUID sims_keepalive_test_ta_uuid = TA_SIMS_KEEP_ALIVE_TEST_UUID;
const TEEC_UUID storage_ta_uuid = TA_STORAGE_UUID;
const TEEC_UUID storage2_ta_uuid = TA_STORAGE2_UUID;
const TEEC_UUID enc_fs_key_manager_test_ta_uuid = ENC_FS_KEY_MANAGER_TEST_UUID;
const TEEC_UUID concurrent_ta_uuid = TA_CONCURRENT_UUID;
const TEEC_UUID concurrent_large_ta_uuid = TA_CONCURRENT_LARGE_UUID;
const TEEC_UUID storage_benchmark_ta_uuid = TA_STORAGE_BENCHMARK_UUID;
const TEEC_UUID socket_ta_uuid = TA_SOCKET_UUID;
const TEEC_UUID sdp_basic_ta_uuid = TA_SDP_BASIC_UUID;
const TEEC_UUID tpm_log_test_ta_uuid = TA_TPM_LOG_TEST_UUID;
const TEEC_UUID supp_plugin_test_ta_uuid = TA_SUPP_PLUGIN_UUID;
const TEEC_UUID large_ta_uuid = TA_LARGE_UUID;
const TEEC_UUID bti_test_ta_uuid = TA_BTI_UUID;
const TEEC_UUID subkey1_ta_uuid = TA_SUBKEY1_UUID;
const TEEC_UUID subkey2_ta_uuid = TA_SUBKEY2_UUID;

TEEC_Context xtest_teec_ctx;

char *xtest_tee_name = NULL;

void BeginTest(const char *msg)
{
	printk("Begin Test -- %s\n", msg);
}

void EndTest(const char *msg)
{
	printk("End Test -- %s\n", msg);
}

void BeginSubCase(const char *msg)
{
	printk("Begin subcase -- %s\n", msg);
}

void EndSubCase(const char *msg)
{
	printk("End subcase -- %s\n", msg);
}


TEEC_Result xtest_teec_ctx_init(void)
{
	return TEEC_InitializeContext(xtest_tee_name, &xtest_teec_ctx);
}

TEEC_Result xtest_teec_open_session(TEEC_Session *session,
				    const TEEC_UUID *uuid, TEEC_Operation *op,
				    uint32_t *ret_orig)
{
	return TEEC_OpenSession(&xtest_teec_ctx, session, uuid,
				TEEC_LOGIN_PUBLIC, NULL, op, ret_orig);
}

void xtest_teec_ctx_deinit(void)
{
	TEEC_FinalizeContext(&xtest_teec_ctx);
}

void xtest_mutex_init(struct k_mutex *mutex)
{
	int e = k_mutex_init(mutex);

	if (e)
		printk( "pthread_mutex_init: %s\n", strerror(e));
}

void xtest_mutex_destroy(struct k_mutex *mutex)
{
	(void)mutex;
}

void xtest_mutex_lock(struct k_mutex *mutex)
{
	int e = k_mutex_lock(mutex, K_FOREVER);

	if (e)
		printk( "pthread_mutex_lock: %s\n", strerror(e));
}

void xtest_mutex_unlock(struct k_mutex *mutex)
{
	int e = k_mutex_unlock(mutex);

	if (e)
		printk( "pthread_mutex_unlock: %si\n", strerror(e));
}
