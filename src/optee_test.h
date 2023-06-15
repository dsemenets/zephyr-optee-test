#ifndef __OPTEE_TEST_H
#define __OPTEE_TEST_H

#include <tee_client_api.h>
#include <zephyr/kernel.h>
#include <zephyr/ztest.h>

/* UUIDs */
#include <enc_fs_key_manager_test.h>
#include <pta_invoke_tests.h>
#include <ta_arm_bti.h>
#include <ta_concurrent.h>
#include <ta_concurrent_large.h>
#include <ta_create_fail_test.h>
#include <ta_crypt.h>
#include <ta_large.h>
#include <ta_miss_test.h>
#include <ta_os_test.h>
#include <ta_rpc_test.h>
#include <ta_sdp_basic.h>
#include <ta_sims_keepalive_test.h>
#include <ta_sims_test.h>
#include <ta_socket.h>
#include <ta_storage_benchmark.h>
#include <ta_storage.h>
#include <ta_subkey1.h>
#include <ta_subkey2.h>
#include <ta_supp_plugin.h>
#include <ta_tpm_log_test.h>

#define ECC_SELF_TEST_UUID \
		{ 0xf34f4f3c, 0xab30, 0x4573,  \
		{ 0x91, 0xBF, 0x3C, 0x57, 0x02, 0x4D, 0x51, 0x99 } }

#define TEEC_OPERATION_INITIALIZER	{ }

extern const TEEC_UUID crypt_user_ta_uuid;
extern const TEEC_UUID os_test_ta_uuid;
extern const TEEC_UUID create_fail_test_ta_uuid;
extern const TEEC_UUID ecc_test_ta_uuid;
extern const TEEC_UUID pta_invoke_tests_ta_uuid;
extern const TEEC_UUID rpc_test_ta_uuid;
extern const TEEC_UUID sims_test_ta_uuid;
extern const TEEC_UUID miss_test_ta_uuid;
extern const TEEC_UUID sims_keepalive_test_ta_uuid;
extern const TEEC_UUID storage_ta_uuid;
extern const TEEC_UUID storage2_ta_uuid;
extern const TEEC_UUID enc_fs_key_manager_test_ta_uuid;
extern const TEEC_UUID concurrent_ta_uuid;
extern const TEEC_UUID concurrent_large_ta_uuid;
extern const TEEC_UUID storage_benchmark_ta_uuid;
extern const TEEC_UUID socket_ta_uuid;
extern const TEEC_UUID sdp_basic_ta_uuid;
extern const TEEC_UUID tpm_log_test_ta_uuid;
extern const TEEC_UUID supp_plugin_test_ta_uuid;
extern const TEEC_UUID large_ta_uuid;
extern const TEEC_UUID bti_test_ta_uuid;
extern const TEEC_UUID subkey1_ta_uuid;
extern const TEEC_UUID subkey2_ta_uuid;

void BeginTest(const char *msg);
void EndTest(const char *msg);
void BeginSubCase(const char *msg);
void EndSubCase(const char *msg);

TEEC_Result xtest_teec_ctx_init(void);
TEEC_Result xtest_teec_open_session(TEEC_Session *session,
				    const TEEC_UUID *uuid, TEEC_Operation *op,
				    uint32_t *ret_orig);
void xtest_teec_ctx_deinit(void);
void xtest_mutex_init(struct k_mutex *mutex);
void xtest_mutex_destroy(struct k_mutex *mutex);
void xtest_mutex_lock(struct k_mutex *mutex);
void xtest_mutex_unlock(struct k_mutex *mutex);

#endif      /* __OPTEE_TEST_H */
