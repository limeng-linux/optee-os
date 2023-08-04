// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023 NXP
 */

#include <config.h>
#include <drvcrypt.h>
#include <drvcrypt_hash.h>
#include <hse_core.h>
#include <hse_interface.h>
#include <hse_services.h>
#include <tee/cache.h>
#include <string.h>
#include <utee_defines.h>
#include <malloc.h>

struct hse_hash_tpl {
	char hash_name[128];
	hseHashAlgo_t algo_type;
	size_t blocksize;
};

struct hse_hash_context {
	struct crypto_hash_ctx hash_ctx;
	const struct hse_hash_tpl *algo;
	struct drvcrypt_buf cached_block;
	size_t max_cached_size;
	bool init;
	uint8_t stream_id;
	uint8_t channel;
};

static const struct hse_hash_tpl hse_hash_algs[] = {
#ifdef HSE_HASH_ALGO_MD5
	[TEE_MAIN_ALGO_MD5] = {
		.hash_name = "MD5",
		.algo_type = HSE_HASH_ALGO_MD5,
		.blocksize = 64,
	},
#endif
	[TEE_MAIN_ALGO_SHA1] = {
		.hash_name = "SHA1",
		.algo_type = HSE_HASH_ALGO_SHA_1,
		.blocksize = 64,
	},
	[TEE_MAIN_ALGO_SHA224] = {
		.hash_name = "SHA2-224",
		.algo_type = HSE_HASH_ALGO_SHA2_224,
		.blocksize = 64,
	},
	[TEE_MAIN_ALGO_SHA256] = {
		.hash_name = "SHA2-256",
		.algo_type = HSE_HASH_ALGO_SHA2_256,
		.blocksize = 64,
	},
	[TEE_MAIN_ALGO_SHA384] = {
		.hash_name = "SHA2-384",
		.algo_type = HSE_HASH_ALGO_SHA2_384,
		.blocksize = 128,
	},
	[TEE_MAIN_ALGO_SHA512] = {
		.hash_name = "SHA2-512",
		.algo_type = HSE_HASH_ALGO_SHA2_512,
		.blocksize = 128,
	},
#if CFG_HSE_PREMIUM_FW
	[TEE_MAIN_ALGO_SHA3_224] = {
		.hash_name = "SHA3-224",
		.algo_type = HSE_HASH_ALGO_SHA3_224,
		.blocksize = 144,
	},
	[TEE_MAIN_ALGO_SHA3_256] = {
		.hash_name = "SHA3-256",
		.algo_type = HSE_HASH_ALGO_SHA3_256,
		.blocksize = 136,
	},
	[TEE_MAIN_ALGO_SHA3_384] = {
		.hash_name = "SHA3-384",
		.algo_type = HSE_HASH_ALGO_SHA3_384,
		.blocksize = 104,
	},
	[TEE_MAIN_ALGO_SHA3_512] = {
		.hash_name = "SHA3-512",
		.algo_type = HSE_HASH_ALGO_SHA3_512,
		.blocksize = 72,
	}
#endif
};

static const struct hse_hash_tpl *get_algo(uint32_t algo)
{
	uint32_t alg = TEE_ALG_GET_MAIN_ALG(algo), min_alg, max_alg;

#ifdef HSE_HASH_ALGO_MD5
	min_alg = TEE_MAIN_ALGO_MD5;
#else
	min_alg  = TEE_MAIN_ALGO_SHA1;
#endif

	max_alg = IS_ENABLED(CFG_HSE_PREMIUM_FW) ?
		  TEE_MAIN_ALGO_SHA3_512 : TEE_MAIN_ALGO_SHA512;

	if (alg >= min_alg && alg <= max_alg && hse_hash_algs[alg].algo_type)
		return &hse_hash_algs[alg];

	return NULL;
}

static void hse_free_stream(struct hse_hash_context *hse_ctx)
{
	hse_stream_channel_release(hse_ctx->stream_id);
	hse_ctx->stream_id = HSE_STREAM_COUNT;
	hse_ctx->channel = 0;
}

static void hse_hash_reset(struct hse_hash_context *hse_ctx)
{
	if (!hse_ctx)
		return;

	hse_free_stream(hse_ctx);
	hse_ctx->init = false;
	if (hse_ctx->cached_block.data) {
		free(hse_ctx->cached_block.data);
		hse_ctx->cached_block.data = NULL;
	}
	hse_ctx->cached_block.length = 0;
}

static TEE_Result hse_start_stream(struct hse_hash_context *hse_ctx)
{
	TEE_Result res;

	HSE_SRV_DESC_INIT(srv_desc);

	srv_desc.srvId = HSE_SRV_ID_HASH;
	srv_desc.hseSrv.hashReq.hashAlgo = hse_ctx->algo->algo_type;
	srv_desc.hseSrv.hashReq.accessMode = HSE_ACCESS_MODE_START;
	srv_desc.hseSrv.hashReq.sgtOption = HSE_SGT_OPTION_NONE;
	srv_desc.hseSrv.hashReq.streamId = hse_ctx->stream_id;
	srv_desc.hseSrv.hashReq.inputLength = 0;

	res = hse_srv_req_sync(hse_ctx->channel, &srv_desc);
	if (res != TEE_SUCCESS)
		EMSG("Stream start operation failed with error code0x%x", res);

	hse_ctx->init = true;
	return res;
}

static TEE_Result hse_hash_init(struct crypto_hash_ctx *ctx)
{
	struct hse_hash_context *hse_ctx;
	const struct hse_hash_tpl *alg_tpl;
	TEE_Result res;

	hse_ctx = container_of(ctx, struct hse_hash_context, hash_ctx);
	alg_tpl = hse_ctx->algo;

	hse_hash_reset(hse_ctx);

	hse_ctx->max_cached_size = CFG_HSE_MAX_HASH_BLK_SIZE -
				   (CFG_HSE_MAX_HASH_BLK_SIZE %
				    alg_tpl->blocksize);
	hse_ctx->cached_block.data = calloc(hse_ctx->max_cached_size,
					    sizeof(uint8_t));
	if (!hse_ctx->cached_block.data)
		return TEE_ERROR_OUT_OF_MEMORY;

	res = hse_stream_channel_acquire(&hse_ctx->channel,
					 &hse_ctx->stream_id);
	if (res != TEE_SUCCESS)
		return res;

	return hse_start_stream(hse_ctx);
}

static TEE_Result update_operation(struct hse_hash_context *hse_ctx,
				   struct hse_buf *in_buf)
{
	TEE_Result res;

	HSE_SRV_DESC_INIT(srv_desc);

	srv_desc.srvId = HSE_SRV_ID_HASH;
	srv_desc.hseSrv.hashReq.hashAlgo = hse_ctx->algo->algo_type;
	srv_desc.hseSrv.hashReq.accessMode = HSE_ACCESS_MODE_UPDATE;

	srv_desc.hseSrv.hashReq.inputLength = hse_buf_get_size(in_buf);
	srv_desc.hseSrv.hashReq.streamId = hse_ctx->stream_id;
	srv_desc.hseSrv.hashReq.pInput = hse_buf_get_paddr(in_buf);
	srv_desc.hseSrv.hashReq.sgtOption = HSE_SGT_OPTION_NONE;

	res = hse_srv_req_sync(hse_ctx->channel, &srv_desc);
	if (res != TEE_SUCCESS)
		EMSG("Hash update operation failed with error code0x%x", res);

	return res;
}

static TEE_Result hse_hash_update(struct crypto_hash_ctx *ctx,
				  const uint8_t *data, size_t len)
{
	TEE_Result res;
	struct hse_hash_context *hse_ctx;
	struct hse_buf *in_buf = NULL;
	size_t rem, idx = 0, actual_len = 0;
	size_t max_cached_size, *cached_size;
	uint8_t *cached_block;

	hse_ctx = container_of(ctx, struct hse_hash_context, hash_ctx);
	if (!data || !len)
		return TEE_ERROR_BAD_PARAMETERS;

	max_cached_size = hse_ctx->max_cached_size;
	cached_size = &hse_ctx->cached_block.length;
	cached_block = hse_ctx->cached_block.data;

	if (ADD_OVERFLOW(len, *cached_size, &actual_len))
		return TEE_ERROR_OVERFLOW;

	if (actual_len < max_cached_size) {
		memcpy(cached_block + *cached_size, data, len);
		*cached_size += len;
		return TEE_SUCCESS;
	}

	in_buf = hse_buf_alloc(max_cached_size);
	if (!in_buf) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}

	hse_buf_put_data(in_buf, cached_block,
			 *cached_size, 0);
	hse_buf_put_data(in_buf, data, max_cached_size - *cached_size,
			 *cached_size);
	res = update_operation(hse_ctx, in_buf);

	if (res != TEE_SUCCESS)
		goto out;

	idx = max_cached_size - *cached_size;
	while (len - idx > max_cached_size) {
		hse_buf_put_data(in_buf, data + idx, max_cached_size, 0);
		res = update_operation(hse_ctx, in_buf);

		if (res != TEE_SUCCESS)
			goto out;

		if (ADD_OVERFLOW(idx, max_cached_size, &idx)) {
			res = TEE_ERROR_OVERFLOW;
			goto out;
		}
	}

	if (SUB_OVERFLOW(len, idx, &rem)) {
		res = TEE_ERROR_OVERFLOW;
		goto out;
	}
	memcpy(cached_block, data + idx, rem);
	*cached_size = rem;
	res = TEE_SUCCESS;

out:
	hse_buf_free(in_buf);
	return res;
}

static TEE_Result hse_hash_final(struct crypto_hash_ctx *ctx,
				 uint8_t *digest, size_t len)
{
	HSE_SRV_DESC_INIT(srv_desc);
	struct hse_hash_context *hse_ctx;
	TEE_Result res;
	struct hse_buf *in_buf = NULL, *len_buf = NULL, *out_buf = NULL;
	size_t cached_size;
	uint8_t *cached_block;

	hse_ctx = container_of(ctx, struct hse_hash_context, hash_ctx);
	cached_size = hse_ctx->cached_block.length;
	cached_block = hse_ctx->cached_block.data;

	if (!len || !digest)
		return TEE_ERROR_BAD_PARAMETERS;

	if (cached_size) {
		in_buf = hse_buf_init(cached_block,
				      cached_size);
		if (!in_buf) {
			res = TEE_ERROR_OUT_OF_MEMORY;
			goto out;
		}
	}

	len_buf = hse_buf_init(&len, sizeof(size_t));
	if (!len_buf) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}

	out_buf = hse_buf_alloc(len);
	if (!out_buf) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}

	srv_desc.srvId = HSE_SRV_ID_HASH;
	srv_desc.hseSrv.hashReq.accessMode = HSE_ACCESS_MODE_FINISH;
	srv_desc.hseSrv.hashReq.sgtOption = HSE_SGT_OPTION_NONE;
	srv_desc.hseSrv.hashReq.streamId = hse_ctx->stream_id;
	srv_desc.hseSrv.hashReq.hashAlgo = hse_ctx->algo->algo_type;
	srv_desc.hseSrv.hashReq.inputLength = cached_size;
	srv_desc.hseSrv.hashReq.pInput = hse_buf_get_paddr(in_buf);
	srv_desc.hseSrv.hashReq.pHashLength = hse_buf_get_paddr(len_buf);
	srv_desc.hseSrv.hashReq.pHash = hse_buf_get_paddr(out_buf);

	res = hse_srv_req_sync(hse_ctx->channel, &srv_desc);
	if (res != TEE_SUCCESS) {
		EMSG("hse_srv_req_sync failed with err 0x%x", res);
		goto out;
	}
	hse_buf_get_data(out_buf, digest, len, 0);

out:
	hse_buf_free(in_buf);
	hse_buf_free(len_buf);
	hse_buf_free(out_buf);

	return res;
}

static void hse_hash_free_ctx(struct crypto_hash_ctx *ctx)
{
	struct hse_hash_context *hse_ctx = NULL;

	hse_ctx = container_of(ctx, struct hse_hash_context, hash_ctx);

	hse_hash_reset(hse_ctx);
	free(hse_ctx);
}

static void hse_hash_copy_state(struct crypto_hash_ctx *dst_ctx,
				struct crypto_hash_ctx *src_ctx)
{
	TEE_Result res = TEE_SUCCESS;
	struct hse_hash_context *dst_hse_ctx;
	struct hse_hash_context *src_hse_ctx;

	if (!src_ctx || !dst_ctx)
		return;

	src_hse_ctx = container_of(src_ctx, struct hse_hash_context, hash_ctx);
	dst_hse_ctx = container_of(dst_ctx, struct hse_hash_context, hash_ctx);
	if (src_hse_ctx->init) {
		res = hse_stream_ctx_copy(src_hse_ctx->stream_id,
					  dst_hse_ctx->stream_id);
		if (res != TEE_SUCCESS)
			goto out;
	}
	dst_hse_ctx->cached_block.length = src_hse_ctx->cached_block.length;
	memcpy(dst_hse_ctx->cached_block.data,
	       src_hse_ctx->cached_block.data,
	       src_hse_ctx->cached_block.length);
	dst_hse_ctx->init = src_hse_ctx->init;

out:
	if (res != TEE_SUCCESS)
		EMSG("Hash copy state failed with err 0x%x", res);
}

static const struct crypto_hash_ops driver_hash = {
	.init = hse_hash_init,
	.update = hse_hash_update,
	.final = hse_hash_final,
	.free_ctx = hse_hash_free_ctx,
	.copy_state = hse_hash_copy_state,
};

static TEE_Result hse_hash_alloc_ctx(struct crypto_hash_ctx **ctx,
				     uint32_t algo)
{
	struct hse_hash_context *hse_ctx = NULL;
	const struct hse_hash_tpl *alg_tpl;
	TEE_Result res = TEE_SUCCESS;

	*ctx = NULL;
	hse_ctx = calloc(1, sizeof(*hse_ctx));
	if (!hse_ctx) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto out_err;
	}

	alg_tpl = get_algo(algo);
	if (!alg_tpl) {
		res = TEE_ERROR_NOT_IMPLEMENTED;
		goto out_err;
	}

	hse_ctx->algo = alg_tpl;
	hse_ctx->hash_ctx.ops = &driver_hash;
	hse_ctx->stream_id = HSE_STREAM_COUNT;
	*ctx = &hse_ctx->hash_ctx;
	DMSG("Allocated context for algo %s", hse_ctx->algo->hash_name);
	return TEE_SUCCESS;

out_err:
	if (hse_ctx)
		free(hse_ctx);

	EMSG("Hash initialisation failed with error 0x%x", res);
	return res;
}

TEE_Result hse_hash_register(void)
{
	return drvcrypt_register_hash(&hse_hash_alloc_ctx);
}
