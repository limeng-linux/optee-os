/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2022-2023 NXP
 */

#ifndef HSE_SERVICES_H
#define HSE_SERVICES_H

#include <tee_api_types.h>

/* Cipher Services */
TEE_Result hse_cipher_register(void);

/* RNG Services */
TEE_Result hse_rng_initialize(void);

#endif /* HSE_SERVICES_H */
