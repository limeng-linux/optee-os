// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023 NXP
 * Copyright (c) 2018-2020 Jan Jancar, Vladimir Sedlacek
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 */

#include <crypto/crypto_impl.h>
#include <drvcrypt.h>
#include <drvcrypt_acipher.h>
#include <hse_core.h>
#include <hse_interface.h>
#include <hse_services.h>
#include <malloc.h>
#include <string.h>
#include <tee/cache.h>

/* Parameters for 192 bit and 224 bit Weierstrass curves
 * Source: https://github.com/J08nY/std-curves
 */
const uint8_t a_192[] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF,
0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFC};
const uint8_t b_192[] = {0x64, 0x21, 0x05, 0x19, 0xE5, 0x9C, 0x80,
0xE7, 0x0F, 0xA7, 0xE9, 0xAB, 0x72, 0x24, 0x30, 0x49, 0xFE, 0xB8,
0xDE, 0xEC, 0xC1, 0x46, 0xB9, 0xB1};
const uint8_t G_192[] = {0x18, 0x8D, 0xA8, 0x0E, 0xB0, 0x30, 0x90,
0xF6, 0x7C, 0xBF, 0x20, 0xEB, 0x43, 0xA1, 0x88, 0x00, 0xF4, 0xFF,
0x0A, 0xFD, 0x82, 0xFF, 0x10, 0x12, 0x07, 0x19, 0x2B, 0x95, 0xFF,
0xC8, 0xDA, 0x78, 0x63, 0x10, 0x11, 0xED, 0x6B, 0x24, 0xCD, 0xD5,
0x73, 0xF9, 0x77, 0xA1, 0x1E, 0x79, 0x48, 0x11};
const uint8_t p_192[] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF,
0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
const uint8_t n_192[] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x99, 0xDE, 0xF8, 0x36, 0x14, 0x6B,
0xC9, 0xB1, 0xB4, 0xD2, 0x28, 0x31};

const uint8_t a_224[] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF,
0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE};
const uint8_t b_224[] = {0xB4, 0x05, 0x0A, 0x85, 0x0C, 0x04, 0xB3,
0xAB, 0xF5, 0x41, 0x32, 0x56, 0x50, 0x44, 0xB0, 0xB7, 0xD7, 0xBF,
0xD8, 0xBA, 0x27, 0x0B, 0x39, 0x43, 0x23, 0x55, 0xFF, 0xB4};
const uint8_t G_224[] = {0xB7, 0x0E, 0x0C, 0xBD, 0x6B, 0xB4, 0xBF,
0x7F, 0x32, 0x13, 0x90, 0xB9, 0x4A, 0x03, 0xC1, 0xD3, 0x56, 0xC2,
0x11, 0x22, 0x34, 0x32, 0x80, 0xD6, 0x11, 0x5C, 0x1D, 0x21, 0xBD,
0x37, 0x63, 0x88, 0xB5, 0xF7, 0x23, 0xFB, 0x4C, 0x22, 0xDF, 0xE6,
0xCD, 0x43, 0x75, 0xA0, 0x5A, 0x07, 0x47, 0x64, 0x44, 0xD5, 0x81,
0x99, 0x85, 0x00, 0x7E, 0x34};
const uint8_t p_224[] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01};
const uint8_t n_224[] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x16, 0xA2, 0xE0, 0xB8,
0xF0, 0x3E, 0x13, 0xDD, 0x29, 0x45, 0x5C, 0x5C, 0x2A, 0x3D};

#define DUMMY_AES_KEK_SIZE	32
#define HSE_IV_LENGTH	16

static uint8_t bin_key_param[HSE_BITS_TO_BYTES(HSE_MAX_ECC_KEY_BITS_LEN)];

static const struct crypto_ecc_keypair_ops *pair_ops;
static const struct crypto_ecc_public_ops *pub_ops;

static bool is_ecc_key_supported(uint32_t type)
{
	switch (type) {
	case TEE_TYPE_ECDSA_KEYPAIR:
	case TEE_TYPE_ECDSA_PUBLIC_KEY:
#ifdef CFG_NXP_HSE_ECDH_DRV
	case TEE_TYPE_ECDH_KEYPAIR:
	case TEE_TYPE_ECDH_PUBLIC_KEY:
#endif
		return true;
	default:
		return false;
	}
}

static TEE_Result
hse_alloc_keypair(struct ecc_keypair *key, uint32_t type,
		  size_t size_bits)
{
	if (!is_ecc_key_supported(type))
		return TEE_ERROR_NOT_IMPLEMENTED;

	memset(key, 0, sizeof(*key));

	key->d = crypto_bignum_allocate(size_bits);
	if (!key->d)
		goto out;

	key->x = crypto_bignum_allocate(size_bits);
	if (!key->x)
		goto out;

	key->y = crypto_bignum_allocate(size_bits);
	if (!key->y)
		goto out;

	return TEE_SUCCESS;
out:
	crypto_bignum_free(&key->d);
	crypto_bignum_free(&key->x);
	return TEE_ERROR_OUT_OF_MEMORY;
}

static void hse_free_publickey(struct ecc_public_key *key)
{
	crypto_bignum_free(&key->x);
	crypto_bignum_free(&key->y);
}

static TEE_Result
hse_alloc_publickey(struct ecc_public_key *key, uint32_t type __unused,
		    size_t size_bits)
{
	if (!is_ecc_key_supported(type))
		return TEE_ERROR_NOT_IMPLEMENTED;

	memset(key, 0, sizeof(*key));

	key->x = crypto_bignum_allocate(size_bits);
	if (!key->x)
		goto out;

	key->y = crypto_bignum_allocate(size_bits);
	if (!key->y)
		goto out;

	return TEE_SUCCESS;
out:
	hse_free_publickey(key);
	return TEE_ERROR_OUT_OF_MEMORY;
}

static TEE_Result hse_gen_keypair(struct ecc_keypair *key, size_t size_bits)
{
	if (!pair_ops->generate)
		return TEE_ERROR_NOT_IMPLEMENTED;

	return pair_ops->generate(key, size_bits);
}

static TEE_Result get_hse_curve(uint32_t tee_curve, hseEccCurveId_t *hse_curve,
				hseKeyBits_t *bitlen)
{
	switch (tee_curve) {
	case TEE_ECC_CURVE_NIST_P192:
		*hse_curve = HSE_EC_USER_CURVE1;
		*bitlen = HSE_KEY192_BITS;
		break;
	case TEE_ECC_CURVE_NIST_P224:
		*hse_curve = HSE_EC_USER_CURVE2;
		*bitlen = HSE_KEY224_BITS;
		break;
	case TEE_ECC_CURVE_NIST_P256:
		*hse_curve = HSE_EC_SEC_SECP256R1;
		*bitlen = HSE_KEY256_BITS;
		break;
#if CFG_HSE_PREMIUM_FW
	case TEE_ECC_CURVE_NIST_P384:
		*hse_curve = HSE_EC_SEC_SECP384R1;
		*bitlen = HSE_KEY384_BITS;
		break;
	case TEE_ECC_CURVE_NIST_P521:
		*hse_curve = HSE_EC_SEC_SECP521R1;
		*bitlen = HSE_KEY521_BITS;
		break;
#endif
	default:
		return TEE_ERROR_NOT_SUPPORTED;
	}

	return TEE_SUCCESS;
}

static TEE_Result hse_set_curve(hseEccCurveId_t curve)
{
	struct hse_buf *p = NULL, *a = NULL, *b = NULL, *g = NULL, *n = NULL;
	TEE_Result res = TEE_ERROR_OUT_OF_MEMORY;
	hseKeyBits_t bitlen;

	HSE_SRV_DESC_INIT(srv_desc);

	switch (curve) {
	case HSE_EC_USER_CURVE1:
		bitlen = HSE_KEY192_BITS;
		p = hse_buf_init(p_192, sizeof(p_192));
		if (!p)
			goto out;
		a = hse_buf_init(a_192, sizeof(a_192));
		if (!a)
			goto out;
		b = hse_buf_init(b_192, sizeof(b_192));
		if (!b)
			goto out;
		g = hse_buf_init(G_192, sizeof(G_192));
		if (!g)
			goto out;
		n = hse_buf_init(n_192, sizeof(n_192));
		if (!n)
			goto out;
		break;
	case HSE_EC_USER_CURVE2:
		bitlen = HSE_KEY224_BITS;
		p = hse_buf_init(p_224, sizeof(p_224));
		if (!p)
			goto out;
		a = hse_buf_init(a_224, sizeof(a_224));
		if (!a)
			goto out;
		b = hse_buf_init(b_224, sizeof(b_224));
		if (!b)
			goto out;
		g = hse_buf_init(G_224, sizeof(G_224));
		if (!g)
			goto out;
		n = hse_buf_init(n_224, sizeof(n_224));
		if (!n)
			goto out;
		break;
	case HSE_EC_SEC_SECP256R1:
	case HSE_EC_SEC_SECP384R1:
	case HSE_EC_SEC_SECP521R1:
		return TEE_SUCCESS;
	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}

	srv_desc.srvId = HSE_SRV_ID_LOAD_ECC_CURVE;
	srv_desc.hseSrv.loadEccCurveReq.eccCurveId = curve;
	srv_desc.hseSrv.loadEccCurveReq.nBitLen = bitlen;
	srv_desc.hseSrv.loadEccCurveReq.pA = hse_buf_get_paddr(a);
	srv_desc.hseSrv.loadEccCurveReq.pB = hse_buf_get_paddr(b);
	srv_desc.hseSrv.loadEccCurveReq.pBitLen = bitlen;
	srv_desc.hseSrv.loadEccCurveReq.pG = hse_buf_get_paddr(g);
	srv_desc.hseSrv.loadEccCurveReq.pN = hse_buf_get_paddr(n);
	srv_desc.hseSrv.loadEccCurveReq.pP = hse_buf_get_paddr(p);
	res = hse_srv_req_sync(HSE_CHANNEL_ANY, &srv_desc);
	if (res)
		EMSG("Curve allocation failed with error 0x%x", res);

out:
	hse_buf_free(p);
	hse_buf_free(a);
	hse_buf_free(b);
	hse_buf_free(g);
	hse_buf_free(n);

	return res;
}

static TEE_Result
get_hse_hash_algo(uint32_t ecc_algo)
{
	switch (ecc_algo) {
	case TEE_ALG_ECDSA_SHA1:
		return HSE_HASH_ALGO_SHA_1;
	case TEE_ALG_ECDSA_SHA224:
		return HSE_HASH_ALGO_SHA2_224;
	case TEE_ALG_ECDSA_SHA256:
		return HSE_HASH_ALGO_SHA2_256;
	case TEE_ALG_ECDSA_SHA384:
		return HSE_HASH_ALGO_SHA2_384;
	case TEE_ALG_ECDSA_SHA512:

	default:
		return HSE_HASH_ALGO_NULL;
	}
}

static TEE_Result hse_import_ecckey(struct hse_buf *pub_key,
				    struct hse_buf *y, struct hse_buf *d,
				    hseKeyHandle_t *key_handle,
				    hseKeyFlags_t flags,
				    hseKeyType_t type,
				    hseEccCurveId_t curve,
				    hseKeyBits_t bitlen)
{
	TEE_Result res;
	hseKeyInfo_t key_info = {0};

	res = hse_set_curve(curve);
	if (res != TEE_SUCCESS)
		return res;

	key_info.keyFlags = flags;
	key_info.keyBitLen = bitlen;
	key_info.keyType = type;
	key_info.specific.eccCurveId = curve;
	return hse_acquire_and_import_key(key_handle, &key_info, pub_key, y, d);
}

static TEE_Result hse_import_keypair(struct ecc_keypair *key,
				     hseKeyHandle_t *key_handle,
				     hseKeyFlags_t flags,
				     size_t key_size)
{
	TEE_Result res = TEE_SUCCESS;
	size_t d_len, x_len, y_len, offs;
	hseEccCurveId_t curve = HSE_EC_CURVE_NONE;
	struct hse_buf *pub_key = NULL, *y = NULL, *d = NULL;
	hseKeyBits_t bitlen;

	if (flags != HSE_KF_USAGE_SIGN)
		return TEE_ERROR_BAD_PARAMETERS;

	x_len = crypto_bignum_num_bytes(key->x);
	y_len = crypto_bignum_num_bytes(key->y);
	d_len = crypto_bignum_num_bytes(key->d);

	if (x_len > key_size || y_len > key_size || d_len > key_size)
		return TEE_ERROR_BAD_PARAMETERS;

	res = get_hse_curve(key->curve, &curve, &bitlen);
	if (res != TEE_SUCCESS)
		return res;

	pub_key = hse_buf_alloc(2 * key_size);
	if (!pub_key) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}

	offs = key_size - x_len;
	crypto_bignum_bn2bin(key->x, bin_key_param);
	res = hse_buf_put_data(pub_key, bin_key_param, x_len, offs);
	if (res != TEE_SUCCESS)
		goto out;

	offs = key_size - y_len;
	crypto_bignum_bn2bin(key->y, bin_key_param);
	res = hse_buf_put_data(pub_key, bin_key_param, y_len, key_size + offs);
	if (res != TEE_SUCCESS)
		goto out;

	d = hse_buf_alloc(key_size);
	if (!d) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}

	offs = key_size - d_len;
	crypto_bignum_bn2bin(key->d, bin_key_param);
	res = hse_buf_put_data(d, bin_key_param, d_len, offs);
	if (res != TEE_SUCCESS)
		goto out;
	res = hse_import_ecckey(pub_key, y, d, key_handle, flags,
				HSE_KEY_TYPE_ECC_PAIR, curve, bitlen);

out:
	hse_buf_free(pub_key);
	hse_buf_free(d);
	return res;
}

static TEE_Result hse_import_pubkey(struct ecc_public_key *key,
				    hseKeyHandle_t *key_handle,
				    hseKeyFlags_t flags,
				    size_t key_size)
{
	TEE_Result res = TEE_ERROR_OUT_OF_MEMORY;
	size_t x_len, y_len, offs;
	hseEccCurveId_t curve = HSE_EC_CURVE_NONE;
	struct hse_buf *pub_key = NULL, *y = NULL, *d = NULL;
	hseKeyBits_t bitlen;

	if (flags != HSE_KF_USAGE_VERIFY && flags != HSE_KF_USAGE_EXCHANGE)
		return TEE_ERROR_BAD_PARAMETERS;
	x_len = crypto_bignum_num_bytes(key->x);
	y_len = crypto_bignum_num_bytes(key->y);
	if (x_len > key_size || y_len > key_size)
		return TEE_ERROR_BAD_PARAMETERS;

	res = get_hse_curve(key->curve, &curve, &bitlen);
	if (res != TEE_SUCCESS)
		return res;

	pub_key = hse_buf_alloc(2 * key_size);
	if (!pub_key) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}

	offs = key_size - x_len;
	crypto_bignum_bn2bin(key->x, bin_key_param);
	res = hse_buf_put_data(pub_key, bin_key_param, x_len, offs);
	if (res != TEE_SUCCESS)
		goto out;

	offs = key_size - y_len;
	crypto_bignum_bn2bin(key->y, bin_key_param);
	res = hse_buf_put_data(pub_key, bin_key_param, y_len, key_size + offs);
	if (res != TEE_SUCCESS)
		goto out;

	res = hse_import_ecckey(pub_key, y, d, key_handle, flags,
				HSE_KEY_TYPE_ECC_PUB, curve, bitlen);

out:
	hse_buf_free(pub_key);
	return res;
}

static TEE_Result
hse_ecc_sign_operation(struct drvcrypt_sign_data *sdata,
		       hseAuthDir_t direction)
{
	HSE_SRV_DESC_INIT(srv_desc);
	hseSignScheme_t *sign_scheme = &srv_desc.hseSrv.signReq.signScheme;
	TEE_Result res = TEE_SUCCESS;
	hseKeyHandle_t key_handle;
	struct hse_buf *R = NULL, *in_buf = NULL,
	*S = NULL, *R_len = NULL, *S_len = NULL;
	uint32_t x, y;

	if (!sdata || !sdata->key ||
	    !sdata->message.data || !sdata->signature.data)
		return TEE_ERROR_BAD_PARAMETERS;

	sign_scheme->signSch = HSE_SIGN_ECDSA;
	sign_scheme->sch.ecdsa.hashAlgo = get_hse_hash_algo(sdata->algo);

	res = (direction == HSE_AUTH_DIR_GENERATE) ?
	hse_import_keypair(sdata->key, &key_handle,
			   HSE_KF_USAGE_SIGN, sdata->size_sec) :
	hse_import_pubkey(sdata->key, &key_handle,
			  HSE_KF_USAGE_VERIFY, sdata->size_sec);

	/* The ECC curve is not supported. Fallback to sw implementation */
	if (res == TEE_ERROR_NOT_SUPPORTED) {
		DMSG("Falling back to sw implementation for ECC algo 0x%x",
		     sdata->algo);

		res = (direction == HSE_AUTH_DIR_GENERATE) ?
		pair_ops->sign(sdata->algo, sdata->key, sdata->message.data,
			       sdata->message.length, sdata->signature.data,
			       &sdata->signature.length) :
		pub_ops->verify(sdata->algo, sdata->key, sdata->message.data,
			       sdata->message.length, sdata->signature.data,
			       sdata->signature.length);

		goto out;

	} else if (res != TEE_SUCCESS) {
		goto out;
	}

	res = TEE_ERROR_OUT_OF_MEMORY;
	in_buf = hse_buf_init(sdata->message.data, sdata->message.length);
	if (!in_buf)
		goto out;

	if (direction == HSE_AUTH_DIR_VERIFY) {
		R = hse_buf_init(sdata->signature.data, sdata->size_sec);
		if (!R)
			goto out;
		R_len = hse_buf_init(&sdata->size_sec, sizeof(uint32_t));
		if (!R_len)
			goto out;
		S = hse_buf_init(sdata->signature.data + sdata->size_sec,
				 sdata->size_sec);
		if (!S)
			goto out;
		S_len = hse_buf_init(&sdata->size_sec, sizeof(uint32_t));
		if (!S_len)
			goto out;
	} else {
		R = hse_buf_alloc(sdata->size_sec);
		if (!R)
			goto out;
		R_len = hse_buf_init(&sdata->size_sec, sizeof(uint32_t));
		if (!R_len)
			goto out;
		S = hse_buf_alloc(sdata->size_sec);
		if (!S)
			goto out;
		S_len = hse_buf_init(&sdata->size_sec, sizeof(uint32_t));
		if (!S_len)
			goto out;
	}

	srv_desc.srvId = HSE_SRV_ID_SIGN;
	srv_desc.hseSrv.signReq.accessMode = HSE_ACCESS_MODE_ONE_PASS;
	srv_desc.hseSrv.signReq.authDir = direction;
	srv_desc.hseSrv.signReq.inputLength = hse_buf_get_size(in_buf);
	srv_desc.hseSrv.signReq.keyHandle = key_handle;
	srv_desc.hseSrv.signReq.pInput = hse_buf_get_paddr(in_buf);
	srv_desc.hseSrv.signReq.pSignatureLength[0] = hse_buf_get_paddr(R_len);
	srv_desc.hseSrv.signReq.pSignatureLength[1] = hse_buf_get_paddr(S_len);
	srv_desc.hseSrv.signReq.pSignature[0] = hse_buf_get_paddr(R);
	srv_desc.hseSrv.signReq.pSignature[1] = hse_buf_get_paddr(S);
	srv_desc.hseSrv.signReq.sgtOption = HSE_SGT_OPTION_NONE;
	srv_desc.hseSrv.signReq.bInputIsHashed = true;
	res = hse_srv_req_sync(HSE_CHANNEL_ANY, &srv_desc);
	if (res != TEE_SUCCESS) {
		if (res == TEE_ERROR_SECURITY)
			res = TEE_ERROR_SIGNATURE_INVALID;
		EMSG("HSE Digital Signature request failed with err 0x%x", res);
		goto out;
	}
	if (direction == HSE_AUTH_DIR_GENERATE) {
		hse_buf_get_data(R_len, &x, sizeof(uint32_t), 0);
		hse_buf_get_data(S_len, &y, sizeof(uint32_t), 0);
		sdata->signature.length = x + y;
		hse_buf_get_data(R, sdata->signature.data, x, 0);
		hse_buf_get_data(S, sdata->signature.data + x, y, 0);
	}

out:
	hse_release_and_erase_key(key_handle);
	hse_buf_free(in_buf);
	hse_buf_free(R_len);
	hse_buf_free(R);
	hse_buf_free(S);
	hse_buf_free(S_len);

	return res;
}

static TEE_Result hse_ecc_sign(struct drvcrypt_sign_data *sdata)
{
	return hse_ecc_sign_operation(sdata, HSE_AUTH_DIR_GENERATE);
}

static TEE_Result hse_ecc_verify(struct drvcrypt_sign_data *sdata)
{
	return hse_ecc_sign_operation(sdata, HSE_AUTH_DIR_VERIFY);
}

#ifdef CFG_NXP_HSE_ECDH_DRV
static TEE_Result hse_import_privkey(struct ecc_keypair *key,
				     hseKeyHandle_t *key_handle,
				     hseKeyFlags_t flags,
				     size_t key_size)
{
	TEE_Result res = TEE_ERROR_BAD_PARAMETERS;
	size_t d_len;
	struct hse_buf *pub_key = NULL, *y = NULL, *d = NULL;
	size_t min_keylen = HSE_BITS_TO_BYTES(HSE_MIN_ECC_KEY_BITS_LEN);
	size_t max_keylen = HSE_BITS_TO_BYTES(HSE_MAX_ECC_KEY_BITS_LEN);
	hseEccCurveId_t curve;
	hseKeyBits_t bitlen;

	d_len = crypto_bignum_num_bytes(key->d);
	if (d_len > key_size)
		return TEE_ERROR_BAD_PARAMETERS;

	if (key_size > max_keylen || key_size < min_keylen)
		return TEE_ERROR_BAD_PARAMETERS;

	res = get_hse_curve(key->curve, &curve, &bitlen);
	if (res != TEE_SUCCESS)
		return res;

	crypto_bignum_bn2bin(key->d, bin_key_param);
	d = hse_buf_init(bin_key_param, d_len);
	if (!d) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}

	res = hse_import_ecckey(pub_key, y, d, key_handle, flags,
				HSE_KEY_TYPE_ECC_PAIR, curve, bitlen);
	hse_buf_free(d);
out:
	return res;
}

static TEE_Result hse_derivecopy_and_export(hseKeyHandle_t key_handle,
					    hseKeyHandle_t dummy_kek_handle,
					    uint8_t *exported_buf,
					    size_t exported_buf_len)
{
	hseKeyHandle_t copied_key_handle = HSE_INVALID_KEY_HANDLE;
	TEE_Result ret = TEE_SUCCESS;
	hseKeyDeriveCopyKeySrv_t *copy_req = NULL;
	hseExportKeySrv_t *export_req = NULL;
	hseSymCipherScheme_t *sym_cipher = NULL;
	struct hse_buf *exported_key_inf = NULL, *exported_key_buf = NULL,
				*exported_key_size = NULL, *iv = NULL;
	HSE_SRV_DESC_INIT(srv_desc);

	if (!exported_buf || !exported_buf_len)
		return TEE_ERROR_BAD_PARAMETERS;

	/* Make a copy into a key of type other than HSE_KEY_TYPE_SHARED_SECRET.
	 * HMAC is a good choice because it does not restrict the ley length.
	 */

	copied_key_handle = hse_keyslot_acquire(HSE_KEY_TYPE_HMAC);
	if (copied_key_handle == HSE_INVALID_KEY_HANDLE) {
		EMSG("Error acquiring key slot for DeriveCopy");
		ret = TEE_ERROR_STORAGE_NOT_AVAILABLE;
		goto out;
	}
	hse_erase_key(copied_key_handle);
	srv_desc.srvId = HSE_SRV_ID_KEY_DERIVE_COPY;
	copy_req = &srv_desc.hseSrv.keyDeriveCopyKeyReq;
	copy_req->keyHandle = key_handle;
	copy_req->startOffset = 0;
	copy_req->targetKeyHandle = copied_key_handle;
	/* Must have a KF_USAGE flag, otherwise DeriveCopy will fail.
	 * We don't really care about the flags we're setting on the target key,
	 * as all we want from it is to be eventually exported.
	 */
	copy_req->keyInfo.keyFlags = HSE_KF_ACCESS_EXPORTABLE |
					HSE_KF_USAGE_SIGN | HSE_KF_USAGE_VERIFY;
	copy_req->keyInfo.keyBitLen = HSE_BYTES_TO_BITS(exported_buf_len);
	copy_req->keyInfo.keyType = HSE_KEY_TYPE_HMAC;

	ret = hse_srv_req_sync(HSE_CHANNEL_ANY, &srv_desc);
	if (ret != TEE_SUCCESS) {
		EMSG("DeriveCopy error");
		goto out;
	}
	DMSG("DeriveCopy success");

	/* Export the new key */
	ret = TEE_ERROR_OUT_OF_MEMORY;
	exported_key_inf = hse_buf_alloc(sizeof(hseKeyInfo_t));
	if (!exported_key_inf) {
		EMSG("Error allocating exported keyInfo");
		goto out;
	}

	exported_key_buf = hse_buf_alloc(exported_buf_len);
	if (!exported_key_buf) {
		EMSG("Error allocating exported buf data");
		goto out;
	}

	exported_key_size = hse_buf_init(&exported_buf_len, sizeof(uint32_t));
	if (!exported_key_size) {
		EMSG("Error allocating exported key size");
		goto out;
	}
	/* pKeyLen[2] is an INPUT/OUTPUT field to hseExportKeySrv_t;
	 * this here is the INPUT part
	 */
	iv = hse_buf_alloc(HSE_IV_LENGTH);
	if (!iv) {
		EMSG("Error allocating IV");
		goto out;
	}
	memset(&srv_desc, 0, sizeof(srv_desc));
	export_req = &srv_desc.hseSrv.exportKeyReq;
	sym_cipher = &export_req->cipher.cipherScheme.symCipher;

	srv_desc.srvId = HSE_SRV_ID_EXPORT_KEY;

	sym_cipher->cipherAlgo = HSE_CIPHER_ALGO_AES;
	sym_cipher->cipherBlockMode = HSE_CIPHER_BLOCK_MODE_CTR;
	sym_cipher->ivLength = HSE_IV_LENGTH;
	sym_cipher->pIV = hse_buf_get_paddr(iv);

	export_req->targetKeyHandle = copied_key_handle;
	export_req->pKeyInfo = hse_buf_get_paddr(exported_key_inf);
	export_req->pKey[2] = hse_buf_get_paddr(exported_key_buf);
	export_req->pKeyLen[2] = hse_buf_get_paddr(exported_key_size);
	export_req->cipher.cipherKeyHandle = dummy_kek_handle;
	export_req->keyContainer.authKeyHandle = HSE_INVALID_KEY_HANDLE;

	DMSG("Executing key export...");
	ret = hse_srv_req_sync(HSE_CHANNEL_ANY, &srv_desc);
	if (ret != TEE_SUCCESS) {
		EMSG("HSE export failed");
		goto out;
	}

	/* if successful, retrieve the exported (and encrypted!) key */
	ret = hse_buf_get_data(exported_key_buf, exported_buf,
			       exported_buf_len, 0);

	DMSG("Successfully copied exported key on %ld bytes", exported_buf_len);

out:
	hse_keyslot_release(copied_key_handle);
	hse_buf_free(exported_key_inf);
	hse_buf_free(exported_key_buf);
	hse_buf_free(exported_key_size);
	hse_buf_free(iv);
	return ret;
}

static TEE_Result import_dummy_kek(hseKeyHandle_t dummy_kek, size_t kek_size)
{
	TEE_Result ret = TEE_SUCCESS;
	hseKeyInfo_t dummy_kek_info = {0};
	struct hse_buf *dummy_kek_buf = NULL;

	if (dummy_kek == HSE_INVALID_KEY_HANDLE) {
		EMSG("Invalid key handle received");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	if (GET_CATALOG_ID(dummy_kek) != HSE_KEY_CATALOG_ID_NVM) {
		EMSG("You must provide a keyhandle from NVM Catalog");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	dummy_kek_buf = hse_buf_alloc(kek_size);
	if (!dummy_kek_buf) {
		EMSG("Buffset allocation/memset error");
		return TEE_ERROR_OUT_OF_MEMORY;
	}

	dummy_kek_info.keyFlags = HSE_KF_USAGE_ENCRYPT |
				HSE_KF_USAGE_KEY_PROVISION;
	dummy_kek_info.keyBitLen = (uint16_t)HSE_BYTES_TO_BITS(kek_size);
	dummy_kek_info.keyType = HSE_KEY_TYPE_AES;

	ret = hse_import_key(dummy_kek, &dummy_kek_info, NULL, NULL,
			     dummy_kek_buf);
	if (ret != TEE_SUCCESS)
		EMSG("Error importing dummy KEK");

	hse_buf_free(dummy_kek_buf);
	return ret;
}

static TEE_Result hse_ecc_shared_secret(struct drvcrypt_secret_data *sdata)
{
	HSE_SRV_DESC_INIT(srv_desc);
	TEE_Result res = TEE_SUCCESS;
	hseKeyHandle_t pub_key = HSE_INVALID_KEY_HANDLE,
		       priv_key = HSE_INVALID_KEY_HANDLE,
		       dest_key = HSE_INVALID_KEY_HANDLE,
		       dummy_kek = HSE_INVALID_KEY_HANDLE;

	if (!sdata->key_priv || !sdata->key_pub || !sdata->secret.data)
		return TEE_ERROR_BAD_PARAMETERS;

	res = hse_import_privkey(sdata->key_priv, &priv_key,
				 HSE_KF_USAGE_EXCHANGE, sdata->size_sec);
	if (res == TEE_ERROR_NOT_SUPPORTED) {
		DMSG("Falling back to sw implementation for ECC shared secret");

		res = pair_ops->shared_secret(sdata->key_priv, sdata->key_pub,
					      sdata->secret.data,
					      &sdata->secret.length);
		goto out;

	} else if (res != TEE_SUCCESS) {
		goto out;
	}

	res = hse_import_pubkey(sdata->key_pub, &pub_key,
				HSE_KF_USAGE_EXCHANGE, sdata->size_sec);
	if (res != TEE_SUCCESS)
		goto out;

	dest_key = hse_keyslot_acquire(HSE_KEY_TYPE_SHARED_SECRET);
	if (dest_key == HSE_INVALID_KEY_HANDLE) {
		res = TEE_ERROR_STORAGE_NO_SPACE;
		goto out;
	}
	hse_erase_key(dest_key);
	srv_desc.srvId = HSE_SRV_ID_DH_COMPUTE_SHARED_SECRET;
	srv_desc.hseSrv.dhComputeSecretReq.peerPubKeyHandle = pub_key;
	srv_desc.hseSrv.dhComputeSecretReq.privKeyHandle = priv_key;
	srv_desc.hseSrv.dhComputeSecretReq.targetKeyHandle = dest_key;

	res = hse_srv_req_sync(HSE_CHANNEL_ANY, &srv_desc);
	if (res) {
		EMSG("HSE DH shared secret req failed with err 0x%x", res);
		goto out;
	}
	dummy_kek = dest_key;
	dummy_kek = GET_KEY_HANDLE(HSE_KEY_CATALOG_ID_NVM,
				   CFG_HSE_ECC_DUMMY_KEK_GROUP_ID,
				   CFG_HSE_ECC_DUMMY_KEK_SLOT_ID);
	hse_erase_key(dummy_kek);
	res = import_dummy_kek(dummy_kek, DUMMY_AES_KEK_SIZE);
	if (res != TEE_SUCCESS)
		goto out;

	res = hse_derivecopy_and_export(dest_key, dummy_kek,
					sdata->secret.data, sdata->size_sec);
	if (res != TEE_SUCCESS) {
		EMSG("Error derive, copy & exporting");
		goto out;
	}
	sdata->secret.length = sdata->size_sec;
	DMSG("Dumping exported (encrypted) secret ...");
	DHEXDUMP(sdata->secret.data, sdata->size_sec);

out:
	hse_release_and_erase_key(pub_key);
	hse_release_and_erase_key(priv_key);
	hse_keyslot_release(dest_key);
	hse_release_and_erase_key(dummy_kek);
	return res;
}
#else
static TEE_Result
hse_ecc_shared_secret(struct drvcrypt_secret_data *sdata __unused)
{
	return TEE_SUCCESS;
}
#endif

static struct drvcrypt_ecc hse_ecc = {
	.alloc_keypair = hse_alloc_keypair,
	.alloc_publickey = hse_alloc_publickey,
	.free_publickey = hse_free_publickey,
	.gen_keypair = hse_gen_keypair,
	.sign = hse_ecc_sign,
	.verify = hse_ecc_verify,
	.shared_secret = hse_ecc_shared_secret,
};

TEE_Result hse_ecc_register(void)
{
	pair_ops = crypto_asym_get_ecc_keypair_ops(TEE_TYPE_ECDSA_KEYPAIR);
	if (!pair_ops)
		return TEE_ERROR_GENERIC;

	pub_ops = crypto_asym_get_ecc_public_ops(TEE_TYPE_ECDSA_PUBLIC_KEY);
	if (!pub_ops)
		return TEE_ERROR_GENERIC;

	return drvcrypt_register_ecc(&hse_ecc);
}
