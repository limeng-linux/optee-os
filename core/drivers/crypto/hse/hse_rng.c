// SPDX-License-Identifier: BSD 3-clause
/*
 * NXP HSE Driver - Hardware True Random Number Generator Support
 *
 * Copyright 2022-2023 NXP
 */

#include <crypto/crypto.h>
#include <hse_core.h>
#include <hse_interface.h>
#include <hse_mu.h>
#include <hse_services.h>
#include <kernel/boot.h>
#include <kernel/spinlock.h>
#include <kernel/interrupt.h>
#include <kernel/panic.h>
#include <rng_support.h>
#include <string.h>
#include <tee/cache.h>
#include <tee/tee_cryp_utl.h>

/* total size of driver internal cache */
#define HSE_RNG_CACHE_MAX    512u

/* minimum threshold for cache refill */
#define HSE_RNG_CACHE_MIN    (HSE_RNG_CACHE_MAX / 4)

/**
 * struct hse_rng_ctx - RNG context
 * @cache: driver internal random data cache
 * @cache_idx: current index in internal cache
 * @srv_desc: service descriptor used for cache refill
 * @req_lock: spinlock used for retrieving data from cache
 * @in_progress: indicates if an async request is in progress
 */
struct hse_rng_ctx {
	struct hse_buf *cache;
	unsigned int cache_idx;
	hseSrvDescriptor_t srv_desc;
	unsigned int req_lock; /* data request spinlock */
	bool in_progress;
};

static struct hse_rng_ctx rng_ctx;

static inline void set_rand_size(unsigned int size)
{
	rng_ctx.srv_desc.hseSrv.getRandomNumReq.randomNumLength = size;
}

/**
 * hse_rng_sync_refill - synchronously refill internal cache
 *
 * Issue a RNG service request and wait for the response
 */
static TEE_Result hse_rng_sync_refill(unsigned int size)
{
	TEE_Result err;

	set_rand_size(size);
	err = hse_srv_req_sync(HSE_CHANNEL_ANY, &rng_ctx.srv_desc);
	if (err) {
		DMSG("HSE RNG cache refill sync request failed: %x", err);
		return err;
	}

	rng_ctx.cache_idx = size;

	return TEE_SUCCESS;
}

/**
 * hse_rng_refill_done - callback function for the asynchronous cache refill
 * @err: error code returned upon receiving HSE's response
 * @ctx: unused
 */
static void hse_rng_refill_done(TEE_Result err, void *ctx __unused)
{
	uint32_t exceptions;

	if (err != TEE_SUCCESS) {
		DMSG("HSE RNG cache refill callback failed: %x", err);
		return;
	}

	exceptions = cpu_spin_lock_xsave(&rng_ctx.req_lock);

	rng_ctx.cache_idx = HSE_RNG_CACHE_MAX;
	rng_ctx.in_progress = false;

	cpu_spin_unlock_xrestore(&rng_ctx.req_lock, exceptions);
}

/**
 * hse_rng_async_refill - asynchronously refill internal cache
 *
 * Issue a RNG service request and return.
 */
static TEE_Result hse_rng_async_refill(void)
{
	TEE_Result err;

	if (rng_ctx.in_progress)
		return TEE_SUCCESS;

	rng_ctx.in_progress = true;

	set_rand_size(HSE_RNG_CACHE_MAX);
	err = hse_srv_req_async(HSE_CHANNEL_ANY, &rng_ctx.srv_desc, NULL,
				hse_rng_refill_done);
	if (err) {
		EMSG("HSE RNG cache refill async request failed: %x", err);
		return err;
	}

	return TEE_SUCCESS;
}

/**
 * hse_rng_read - generate random bytes of data into a supplied buffer
 * @buf: destination buffer
 * @blen: number of bytes
 *
 * If possible, get random data from internal cache, otherwise trigger a
 * cache refill and wait to return the new random data.
 */
static TEE_Result hse_rng_read(void *buf, size_t blen)
{
	TEE_Result ret = TEE_SUCCESS;
	struct hse_buf *cache = rng_ctx.cache;
	unsigned int *cache_idx = &rng_ctx.cache_idx;
	uint32_t exceptions;

	if (!is_hse_status_ok())
		return TEE_ERROR_ACCESS_DENIED;

	exceptions = cpu_spin_lock_xsave(&rng_ctx.req_lock);

	if (blen <= *cache_idx) {
		hse_buf_get_data(cache, buf, blen, *cache_idx - blen);
		*cache_idx -= blen;

		if (*cache_idx < HSE_RNG_CACHE_MIN)
			ret = hse_rng_async_refill();

	} else if (blen <= HSE_RNG_CACHE_MAX) {
		ret = hse_rng_async_refill();
		if (ret != TEE_SUCCESS)
			goto out;

		ret = TEE_ERROR_BUSY;

	} else {
		unsigned int remlen = blen, copylen;

		do {
			ret = hse_rng_sync_refill(HSE_RNG_CACHE_MAX);
			if (ret != TEE_SUCCESS)
				goto out;

			copylen = MIN(remlen, *cache_idx);
			hse_buf_get_data(cache, buf, copylen,
					 *cache_idx - copylen);
			*cache_idx -= copylen;

			remlen -= copylen;

		} while (remlen > 0);
	}
out:
	cpu_spin_unlock_xrestore(&rng_ctx.req_lock, exceptions);
	return ret;
}

/**
 * hse_rng_init - initialize RNG
 *
 * Initialize RNG's private data and perform a sync request to
 * fill the cache with half of its MAX value due to boot time
 * considerations.
 */
TEE_Result hse_rng_initialize(void)
{
	TEE_Result err;
	hseGetRandomNumSrv_t rand_srv;

	rng_ctx.cache = hse_buf_alloc(HSE_RNG_CACHE_MAX);
	if (!rng_ctx.cache)
		return TEE_ERROR_OUT_OF_MEMORY;

	rand_srv.rngClass = HSE_RNG_CLASS_PTG3;
	rand_srv.pRandomNum = hse_buf_get_paddr(rng_ctx.cache);

	memset(&rng_ctx.srv_desc, 0, sizeof(rng_ctx.srv_desc));
	rng_ctx.srv_desc.srvId = HSE_SRV_ID_GET_RANDOM_NUM;
	rng_ctx.srv_desc.hseSrv.getRandomNumReq = rand_srv;

	rng_ctx.cache_idx = 0;
	rng_ctx.req_lock = SPINLOCK_UNLOCK;
	rng_ctx.in_progress = false;

	/* Perform a sync refill as secure irqs are not yet enabled */
	err = hse_rng_sync_refill(HSE_RNG_CACHE_MAX / 2);
	if (err != TEE_SUCCESS)
		return err;

	return TEE_SUCCESS;
}

void plat_rng_init(void)
{
}

TEE_Result hw_get_random_bytes(void *buf, size_t blen)
{
	TEE_Result ret;

	if (!buf)
		return TEE_ERROR_BAD_PARAMETERS;

	ret = hse_rng_read(buf, blen);

	while (ret == TEE_ERROR_BUSY)
		ret = hse_rng_read(buf, blen);

	return ret;
}

#if defined(_CFG_CORE_STACK_PROTECTOR) || defined(CFG_WITH_STACK_CANARIES)
/* Generate random stack canary value on boot up */
void plat_get_random_stack_canaries(void *buf, size_t ncan, size_t size)
{
	TEE_Result ret = TEE_ERROR_GENERIC;
	size_t i = 0;

	assert(buf && ncan && size);

	/*
	 * With virtualization the RNG is not initialized in Nexus core.
	 * Need to override with platform specific implementation.
	 */
	if (IS_ENABLED(CFG_NS_VIRTUALIZATION))
		goto fixed_value;

	/*
	 * When booting a fresh image, the RNG will return
	 * TEE_ERROR_ACCESS_DENIED as HSE Firmware has not been initialized.
	 */
	ret = hse_rng_read(buf, ncan * size);
	if (ret == TEE_SUCCESS)
		goto out;
	else if (ret == TEE_ERROR_ACCESS_DENIED)
		goto fixed_value;
	else
		panic("Failed to generate random stack canary");

fixed_value:
	IMSG("WARNING: Using fixed value for stack canary");
	memset(buf, 0xab, ncan * size);
out:
	/* Leave null byte in canary to prevent string base exploit */
	for (i = 0; i < ncan; i++)
		*((uint8_t *)buf + size * i) = 0;
}
#endif /* _CFG_CORE_STACK_PROTECTOR || CFG_WITH_STACK_CANARIES */
