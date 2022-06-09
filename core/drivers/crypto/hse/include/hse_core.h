/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2022-2023 NXP
 */

#ifndef HSE_CORE_H
#define HSE_CORE_H

#include <hse_interface.h>
#include <tee_api_types.h>
#include <types_ext.h>

#define HSE_CHANNEL_ANY    0xACu /* use any channel, no request ordering */
#define HSE_CHANNEL_ADM    0u /* channel reserved for administrative services */

#define HSE_SRV_DESC_INIT(sname)  \
	hseSrvDescriptor_t ((sname)) = {0} \

/**
 * enum hse_ch_type - channel type
 * @HSE_CHANNEL_ADMIN: restricted to administrative services
 * @HSE_CHANNEL_SHARED: shared channel, available for crypto
 * @HSE_CHANNEL_STREAM: reserved for streaming mode use
 */
enum hse_ch_type {
	HSE_CH_TYPE_ADMIN = 0u,
	HSE_CH_TYPE_SHARED = 1u,
	HSE_CH_TYPE_STREAM = 2u,
};

/* Opaque data type */
struct hse_buf;

struct hse_buf *hse_buf_alloc(size_t size);
void hse_buf_free(struct hse_buf *buf);
struct hse_buf *hse_buf_init(const void *data, size_t size);

TEE_Result hse_buf_put_data(struct hse_buf *buf, const void *data, size_t size,
			    size_t offset);
TEE_Result hse_buf_get_data(struct hse_buf *buf, void *data, size_t size,
			    size_t offset);
TEE_Result hse_buf_copy(struct hse_buf *dst, struct hse_buf *src, size_t size);
uint32_t hse_buf_get_size(struct hse_buf *buf);
paddr_t hse_buf_get_paddr(struct hse_buf *buf);

TEE_Result hse_srv_req_sync(uint8_t channel, const void *srv_desc);

#endif /* HSE_CORE_H */
