// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2022-2023 NXP
 */

#include <assert.h>
#include <hse_core.h>
#include <hse_interface.h>
#include <hse_services.h>
#include <kernel/tee_common_otp.h>
#include <tee/cache.h>
#include <trace.h>

#define HSE_HUK_LENGTH	32
#define HSE_IV_LENGTH	16

static uint8_t stored_key[HSE_HUK_LENGTH];
static bool key_retrieved;

static TEE_Result hse_extract_step(hseKeyHandle_t key_handle)
{
	HSE_SRV_DESC_INIT(srv_desc);
	TEE_Result ret = TEE_SUCCESS;
	hseKeyDeriveSrv_t *derive_req = &srv_desc.hseSrv.keyDeriveReq;

	derive_req->kdfAlgo = HSE_KDF_ALGO_EXTRACT_STEP;
	derive_req->sch.extractStep.secretKeyHandle = HSE_ROM_KEY_AES256_KEY1;
	derive_req->sch.extractStep.targetKeyHandle = key_handle;
	derive_req->sch.extractStep.kdfPrf = HSE_KDF_PRF_HMAC;
	derive_req->sch.extractStep.prfAlgo.hmacHash = HSE_HASH_ALGO_SHA2_256;
	derive_req->sch.extractStep.salt.saltKeyHandle = HSE_INVALID_KEY_HANDLE;
	derive_req->sch.extractStep.salt.pSalt = 0;

	srv_desc.srvId = HSE_SRV_ID_KEY_DERIVE;

	ret = hse_srv_req_sync(HSE_CHANNEL_ANY, &srv_desc);
	if (ret != TEE_SUCCESS)
		EMSG("HSE Derive Key service request failed");

	return ret;
}

static TEE_Result hse_expand_step(hseKeyHandle_t key_handle)
{
	HSE_SRV_DESC_INIT(srv_desc);
	TEE_Result ret = TEE_SUCCESS;
	hseKdfCommonParams_t *kdf_common =
		&srv_desc.hseSrv.keyDeriveReq.sch.HKDF_Expand.kdfCommon;

	kdf_common->srcKeyHandle = key_handle;
	kdf_common->targetKeyHandle = key_handle;
	kdf_common->keyMatLen = HSE_HUK_LENGTH;
	kdf_common->kdfPrf = HSE_KDF_PRF_HMAC;
	kdf_common->prfAlgo.hmacHash = HSE_HASH_ALGO_SHA2_256;
	kdf_common->pInfo = 0;
	kdf_common->infoLength = 0;

	srv_desc.srvId = HSE_SRV_ID_KEY_DERIVE;
	srv_desc.hseSrv.keyDeriveReq.kdfAlgo = HSE_KDF_ALGO_HKDF_EXPAND;

	ret = hse_srv_req_sync(HSE_CHANNEL_ANY, &srv_desc);
	if (ret != TEE_SUCCESS)
		EMSG("HSE Derive Key service request failed");

	return ret;
}

static TEE_Result hse_copy_and_extract(hseKeyHandle_t src_handle,
				       hseKeyHandle_t dst_handle,
				       uint8_t *data)

{
	HSE_SRV_DESC_INIT(srv_desc);
	TEE_Result ret = TEE_SUCCESS;
	uint16_t flags, bit_len;
	struct hse_buf *keyinf = NULL, *keybuf = NULL, *keysize = NULL,
		       *iv = NULL;
	uint16_t huk_size = HSE_HUK_LENGTH;
	hseSymCipherScheme_t *sym_cipher;

	if (!data)
		return TEE_ERROR_BAD_PARAMETERS;

	flags = HSE_KF_ACCESS_EXPORTABLE | HSE_KF_USAGE_SIGN;
	bit_len = HSE_HUK_LENGTH * 8;

	srv_desc.srvId = HSE_SRV_ID_KEY_DERIVE_COPY;
	srv_desc.hseSrv.keyDeriveCopyKeyReq.keyHandle = src_handle;
	srv_desc.hseSrv.keyDeriveCopyKeyReq.startOffset = 0;
	srv_desc.hseSrv.keyDeriveCopyKeyReq.targetKeyHandle = dst_handle;
	srv_desc.hseSrv.keyDeriveCopyKeyReq.keyInfo.keyFlags = flags;
	srv_desc.hseSrv.keyDeriveCopyKeyReq.keyInfo.keyBitLen = bit_len;
	srv_desc.hseSrv.keyDeriveCopyKeyReq.keyInfo.smrFlags = 0;
	srv_desc.hseSrv.keyDeriveCopyKeyReq.keyInfo.keyType = HSE_KEY_TYPE_HMAC;

	ret = hse_srv_req_sync(HSE_CHANNEL_ANY, &srv_desc);
	if (ret != TEE_SUCCESS) {
		EMSG("HSE Derive Copy Key service request failed");
		return ret;
	}

	keyinf = hse_buf_alloc(sizeof(hseKeyInfo_t));
	if (!keyinf)
		return TEE_ERROR_OUT_OF_MEMORY;

	keybuf = hse_buf_alloc(HSE_HUK_LENGTH);
	if (!keybuf) {
		ret = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}

	keysize = hse_buf_init(&huk_size, sizeof(uint16_t));
	if (!keysize) {
		ret = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}

	iv = hse_buf_alloc(HSE_IV_LENGTH);
	if (!iv) {
		ret = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}

	memset(&srv_desc, 0, sizeof(srv_desc));

	sym_cipher = &srv_desc.hseSrv.exportKeyReq.cipher.cipherScheme
		     .symCipher;
	sym_cipher->cipherAlgo = HSE_CIPHER_ALGO_AES;
	sym_cipher->cipherBlockMode = HSE_CIPHER_BLOCK_MODE_CTR;
	sym_cipher->ivLength = HSE_IV_LENGTH;
	sym_cipher->pIV = hse_buf_get_paddr(iv);

	srv_desc.srvId = HSE_SRV_ID_EXPORT_KEY;
	srv_desc.hseSrv.exportKeyReq.targetKeyHandle = dst_handle;
	srv_desc.hseSrv.exportKeyReq.pKeyInfo = hse_buf_get_paddr(keyinf);
	srv_desc.hseSrv.exportKeyReq.pKey[2] = hse_buf_get_paddr(keybuf);
	srv_desc.hseSrv.exportKeyReq.pKeyLen[2] = hse_buf_get_paddr(keysize);
	srv_desc.hseSrv.exportKeyReq.cipher.cipherKeyHandle =
		HSE_ROM_KEY_AES256_KEY1;
	srv_desc.hseSrv.exportKeyReq.keyContainer.authKeyHandle =
		HSE_INVALID_KEY_HANDLE;

	ret = hse_srv_req_sync(HSE_CHANNEL_ANY, &srv_desc);
	if (ret != TEE_SUCCESS) {
		EMSG("HSE Export Key service request failed");
		goto out;
	}

	hse_buf_get_data(keybuf, data, HSE_HUK_LENGTH, 0);

out:
	hse_buf_free(iv);
	hse_buf_free(keysize);
	hse_buf_free(keybuf);
	hse_buf_free(keyinf);

	return ret;
}

TEE_Result hse_retrieve_huk(void)
{
	TEE_Result ret = TEE_SUCCESS;
	hseKeyHandle_t secret_handle = HSE_INVALID_KEY_HANDLE,
		hmac_handle = HSE_INVALID_KEY_HANDLE;

	assert(!key_retrieved);

	secret_handle = hse_keyslot_acquire(HSE_KEY_TYPE_SHARED_SECRET);
	if (secret_handle == HSE_INVALID_KEY_HANDLE) {
		ret = TEE_ERROR_BUSY;
		goto out;
	}

	ret = hse_extract_step(secret_handle);
	if (ret != TEE_SUCCESS) {
		EMSG("Extract Step failed");
		goto out;
	}

	ret = hse_expand_step(secret_handle);
	if (ret != TEE_SUCCESS) {
		EMSG("Expand Step failed");
		goto out;
	}

	hmac_handle = hse_keyslot_acquire(HSE_KEY_TYPE_HMAC);
	if (hmac_handle == HSE_INVALID_KEY_HANDLE)
		goto out;

	ret = hse_copy_and_extract(secret_handle, hmac_handle, stored_key);
	if (ret != TEE_SUCCESS) {
		EMSG("Copy and Export Step failed");
		goto out;
	}

	key_retrieved = true;

out:
	hse_keyslot_release(hmac_handle);
	hse_keyslot_release(secret_handle);

	if (ret != TEE_SUCCESS)
		EMSG("HW Unique Key request failed with err 0x%x", ret);
	return ret;
}

TEE_Result tee_otp_get_hw_unique_key(struct tee_hw_unique_key *hwkey)
{
	COMPILE_TIME_ASSERT(sizeof(stored_key) >= sizeof(hwkey->data));

	memcpy(&hwkey->data[0], &stored_key[0], sizeof(hwkey->data));

	return TEE_SUCCESS;
}
