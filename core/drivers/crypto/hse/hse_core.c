// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2022-2023 NXP
 */

#include <arm.h>
#include <atomic.h>
#include <hse_core.h>
#include <hse_mu.h>
#include <initcall.h>
#include <kernel/interrupt.h>
#include <kernel/spinlock.h>
#include <malloc.h>
#include <string.h>
#include <tee_api_types.h>
#include <trace.h>

/**
 * struct hse_drvdata - HSE driver private data
 * @srv_desc[n].ptr: service descriptor virtual address for channel n
 * @srv_desc[n].paddr: service descriptor physical address for channel n
 * @srv_desc[n].id: current service request ID for channel n
 * @mu: MU instance handle returned by lower abstraction layer
 * @type[n]: designated type of service channel n
 * @tx_lock: lock used for service request transmission
 * @firmware_version: firmware version
 */
struct hse_drvdata {
	struct {
		void  *ptr;
		paddr_t paddr;
		uint32_t id;
	} srv_desc[HSE_NUM_OF_CHANNELS_PER_MU];
	void *mu;
	bool channel_busy[HSE_NUM_OF_CHANNELS_PER_MU];
	enum hse_ch_type type[HSE_NUM_OF_CHANNELS_PER_MU];
	unsigned int tx_lock;
	hseAttrFwVersion_t firmware_version;
};

static struct hse_drvdata *drv;

/**
 * hse_err_decode - HSE error code translation
 * @srv_rsp: HSE service response
 *
 * Return: 0 on service request success, error code otherwise
 */
static TEE_Result hse_err_decode(uint32_t srv_rsp)
{
	switch (srv_rsp) {
	case HSE_SRV_RSP_OK:
		return TEE_SUCCESS;
	case HSE_SRV_RSP_VERIFY_FAILED:
		return TEE_ERROR_SECURITY;
	case HSE_SRV_RSP_INVALID_ADDR:
	case HSE_SRV_RSP_INVALID_PARAM:
		return TEE_ERROR_BAD_PARAMETERS;
	case HSE_SRV_RSP_NOT_SUPPORTED:
		return TEE_ERROR_NOT_SUPPORTED;
	case HSE_SRV_RSP_NOT_ALLOWED:
		return TEE_ERROR_ACCESS_DENIED;
	case HSE_SRV_RSP_NOT_ENOUGH_SPACE:
		return TEE_ERROR_OUT_OF_MEMORY;
	case HSE_SRV_RSP_CANCELED:
		return TEE_ERROR_CANCEL;
	case HSE_SRV_RSP_KEY_NOT_AVAILABLE:
	case HSE_SRV_RSP_KEY_EMPTY:
	case HSE_SRV_RSP_KEY_INVALID:
	case HSE_SRV_RSP_KEY_WRITE_PROTECTED:
	case HSE_SRV_RSP_KEY_UPDATE_ERROR:
		return TEE_ERROR_BAD_STATE;
	default:
		return TEE_ERROR_GENERIC;
	}
}

/**
 * hse_sync_srv_desc - sync service descriptor
 * @channel: service channel
 * @desc: service descriptor address
 *
 * Copy descriptor to the dedicated space and cache service ID internally.
 */
static inline void hse_sync_srv_desc(uint8_t channel,
				     const hseSrvDescriptor_t *srv_desc)
{
	if (channel >= HSE_NUM_OF_CHANNELS_PER_MU || !srv_desc)
		return;

	memset(drv->srv_desc[channel].ptr, 0, HSE_MAX_DESCR_SIZE);
	memcpy(drv->srv_desc[channel].ptr, srv_desc, sizeof(*srv_desc));
	drv->srv_desc[channel].id = srv_desc->srvId;
}

/**
 * hse_next_free_channel - find the next available shared channel
 * @type: channel type
 *
 * Return: channel index, HSE_CHANNEL_INV if none available
 */
static uint8_t hse_next_free_channel(void)
{
	uint8_t channel;

	for (channel = ARRAY_SIZE(drv->type) - 1; channel > 0; channel--)
		if (drv->type[channel] == HSE_CH_TYPE_SHARED &&
		    !drv->channel_busy[channel])
			return channel;

	return HSE_CHANNEL_INV;
}

/**
 * hse_srv_req_sync - initiate service request and wait for response
 * @channel: selects channel for the service request
 * @srv_desc: address of service descriptor
 *
 * Return: TEE_SUCCESS on succes, specific err code on error
 */
TEE_Result hse_srv_req_sync(uint8_t channel, const void *srv_desc)
{
	TEE_Result ret;
	uint32_t srv_rsp, exceptions;
	void *mu = drv->mu;

	if (!srv_desc)
		return TEE_ERROR_BAD_PARAMETERS;

	if (channel != HSE_CHANNEL_ANY &&
	    channel >= HSE_NUM_OF_CHANNELS_PER_MU)
		return TEE_ERROR_BAD_PARAMETERS;

	exceptions = cpu_spin_lock_xsave(&drv->tx_lock);

	if (channel == HSE_CHANNEL_ANY) {
		channel = hse_next_free_channel();
		if (channel == HSE_CHANNEL_INV) {
			cpu_spin_unlock_xrestore(&drv->tx_lock, exceptions);
			DMSG("No channel available\n");
			return TEE_ERROR_BUSY;
		}
	} else if (drv->channel_busy[channel]) {
		cpu_spin_unlock_xrestore(&drv->tx_lock, exceptions);
		DMSG("channel %d busy\n", channel);
		return TEE_ERROR_BUSY;
	}

	drv->channel_busy[channel] = true;

	cpu_spin_unlock_xrestore(&drv->tx_lock, exceptions);

	hse_sync_srv_desc(channel, srv_desc);

	/* HSE MU interface can only send 32 bit messages */
	if (drv->srv_desc[channel].paddr > UINT32_MAX) {
		ret = TEE_ERROR_BAD_FORMAT;
		goto out;
	}

	ret = hse_mu_msg_send(mu, channel, drv->srv_desc[channel].paddr);
	if (ret != TEE_SUCCESS)
		goto out;

	while (!hse_mu_msg_pending(mu, channel))
		;

	ret = hse_mu_msg_recv(mu, channel, &srv_rsp);
	if (ret != TEE_SUCCESS)
		goto out;

	ret = hse_err_decode(srv_rsp);

out:
	drv->channel_busy[channel] = false;
	return ret;
}

/**
 * hse_config_channels - configure channels and manage descriptor space
 *
 * HSE firmware restricts channel zero to administrative services, all the rest
 * are usable for crypto operations. Driver reserves the last HSE_STREAM_COUNT
 * channels for streaming mode use and marks the remaining as shared channels.
 */
static inline void hse_config_channels(void)
{
	unsigned int offset;
	uint8_t channel;
	vaddr_t ch_addr;

	drv->type[0] = HSE_CH_TYPE_ADMIN;
	drv->srv_desc[0].ptr = hse_mu_desc_base_ptr(drv->mu);
	drv->srv_desc[0].paddr = hse_mu_desc_base_paddr(drv->mu);
	drv->channel_busy[0] = false;

	for (channel = 1; channel < HSE_NUM_OF_CHANNELS_PER_MU; channel++) {
		if (channel >= HSE_NUM_OF_CHANNELS_PER_MU - HSE_STREAM_COUNT)
			drv->type[channel] = HSE_CH_TYPE_STREAM;
		else
			drv->type[channel] = HSE_CH_TYPE_SHARED;

		offset = channel * HSE_MAX_DESCR_SIZE;
		ch_addr = (vaddr_t)drv->srv_desc[0].ptr + offset;

		drv->srv_desc[channel].ptr = (void *)ch_addr;
		drv->srv_desc[channel].paddr = drv->srv_desc[0].paddr + offset;

		drv->channel_busy[channel] = false;
	}
}

/**
 * hse_check_fw_version - retrieve firmware version
 *
 * Issues a service request for retrieving the HSE Firmware version
 */
static TEE_Result hse_check_fw_version(void)
{
	HSE_SRV_DESC_INIT(srv_desc);
	TEE_Result err;
	struct hse_buf *buf = NULL;
	uint32_t attr_size = sizeof(hseAttrFwVersion_t);

	buf = hse_buf_alloc(attr_size);
	if (!buf) {
		DMSG("failed to allocate fw_version buffer");
		return TEE_ERROR_OUT_OF_MEMORY;
	}

	srv_desc.srvId = HSE_SRV_ID_GET_ATTR;
	srv_desc.hseSrv.getAttrReq.attrId = HSE_FW_VERSION_ATTR_ID;
	srv_desc.hseSrv.getAttrReq.attrLen = attr_size;
	srv_desc.hseSrv.getAttrReq.pAttr = hse_buf_get_paddr(buf);

	err = hse_srv_req_sync(HSE_CHANNEL_ADM, &srv_desc);
	if (err) {
		DMSG("request failed: %d", err);
		hse_buf_free(buf);
		return err;
	}

	hse_buf_get_data(buf, &drv->firmware_version, attr_size, 0);
	hse_buf_free(buf);

	return TEE_SUCCESS;
}

static TEE_Result crypto_driver_init(void)
{
	TEE_Result err;
	uint16_t status;

	drv = calloc(1, sizeof(*drv));
	if (!drv) {
		EMSG("Could not malloc drv instance");
		err = TEE_ERROR_OUT_OF_MEMORY;
		goto out_err;
	}

	drv->mu = hse_mu_init();
	if (!drv->mu) {
		EMSG("Could not get MU Instance");
		err = TEE_ERROR_BAD_STATE;
		goto out_err;
	}

	status = hse_mu_check_status(drv->mu);
	if (!(status & HSE_STATUS_INIT_OK)) {
		EMSG("Firmware not initialised");
		err = TEE_ERROR_BAD_STATE;
		goto out_err;
	}

	hse_config_channels();

	drv->tx_lock = SPINLOCK_UNLOCK;

	err = hse_check_fw_version();
	if (err != TEE_SUCCESS)
		goto out_err;

	DMSG("%s firmware, version %d.%d.%d\n",
	     drv->firmware_version.fwTypeId == 0 ? "standard" :
	     (drv->firmware_version.fwTypeId == 1 ? "premium" : "custom"),
	     drv->firmware_version.majorVersion,
	     drv->firmware_version.minorVersion,
	     drv->firmware_version.patchVersion);

	IMSG("HSE is successfully initialized");

	return TEE_SUCCESS;

out_err:
	if (drv) {
		if (drv->mu)
			hse_mu_free(drv->mu);
		free(drv);
		drv = NULL;
	}

	EMSG("HSE Crypto Driver init failed with err 0x%x", err);
	return err;
}

early_init(crypto_driver_init);
