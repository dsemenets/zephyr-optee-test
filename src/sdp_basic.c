#include <stdio.h>                                                                                                                                                                                     
#include <stdlib.h>
#include <string.h>
#include "optee_test.h"
#include <tee_client_api.h>
#include "sdp_basic.h"

int sdp_basic_test(enum test_target_ta ta, size_t size, size_t loop,
		   const char *heap_name, int ion_heap, int rnd_offset, int verbosity)
{
	struct tee_ctx *ctx = NULL;
	unsigned char *test_buf = NULL;
	unsigned char *ref_buf = NULL;
	void *shm_ref = NULL;
	unsigned int err = 1;
	int fd = -1;
	size_t sdp_size = size;
	size_t offset = 0;
	size_t loop_cnt = 0;

	if (!loop) {
		fprintf(stderr, "Error: null loop value\n");
		return 1;
	}

	/* reduce size to enable offset tests (max offset is 255 bytes) */
	if (rnd_offset)
		size -= 255;

	test_buf = malloc(size);
	ref_buf = malloc(size);
	if (!test_buf || !ref_buf) {
		printk("failed to allocate memory\n");
		goto bail1;
	}

	fd = allocate_buffer(sdp_size, heap_name, ion_heap, verbosity);
	if (fd < 0) {
		printk("Failed to allocate SDP buffer (%zu bytes) in %s heap %d: %d\n",
				sdp_size, heap_name, ion_heap, fd);
		goto bail1;
	}

	/* register secure buffer to TEE */
	ctx = malloc(sizeof(*ctx));
	if (!ctx)
		goto bail1;
	if (create_tee_ctx(ctx, ta))
		goto bail1;
	if (tee_register_buffer(ctx, &shm_ref, fd))
		goto bail2;

	/* release registered fd: tee should still hold refcount on resource */
	close(fd);
	fd = -1;

	/* invoke trusted application with secure buffer as memref parameter */
	for (loop_cnt = loop; loop_cnt; loop_cnt--) {
		/* get an buffer of random-like values */
		if (get_random_bytes((char *)ref_buf, size))
			goto bail2;
		memcpy(test_buf, ref_buf, size);
		/* random offset [0 255] */
		offset = (unsigned int)*ref_buf;

		/* TA writes into SDP buffer */
		if (inject_sdp_data(ctx, test_buf, offset, size, shm_ref, ta))
			goto bail2;

		/* TA reads/writes into SDP buffer */
		if (transform_sdp_data(ctx, offset, size, shm_ref, ta))
			goto bail2;

		/* TA reads into SDP buffer */
		if (dump_sdp_data(ctx, test_buf, offset, size, shm_ref, ta))
			goto bail2;

		/* check dumped data are the expected ones */
		if (check_sdp_dumped(ctx, ref_buf, size, test_buf)) {
			fprintf(stderr, "check SDP data: %d errors\n", err);
			goto bail2;
		}
	}

	err = 0;
bail2:
	if (fd >= 0)
		close(fd);
	if (shm_ref)
		tee_deregister_buffer(ctx, shm_ref);
	finalize_tee_ctx(ctx);
bail1:
	free(ctx);
	free(ref_buf);
	free(test_buf);
	return err;
}
