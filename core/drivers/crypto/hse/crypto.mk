ifeq ($(CFG_NXP_HSE), y)

# Enable the crypto driver
$(call force,CFG_CRYPTO_DRIVER,y)
CFG_CRYPTO_DRIVER_DEBUG ?= 0

ifeq ($(CFG_NXP_HSE_FWDIR),)
$(error Path to HSE Firmware Package not set. Please use the \
HSE Firmware Package corresponding to PLATFORM_FLAVOR=$(PLATFORM_FLAVOR))
endif

# Determine if the HSE Firmware Version is Premium or Standard
HSE_FWTYPE_STR=$(shell grep -r '\#define HSE_FWTYPE' $(CFG_NXP_HSE_FWDIR)/interface/config/hse_target.h \
		| sed 's/.*\(PREMIUM\|STANDARD\).*/\1/')
ifeq ($(HSE_FWTYPE_STR), PREMIUM)
$(call force,CFG_HSE_PREMIUM_FW,1)
else
$(call force,CFG_HSE_PREMIUM_FW,0)
endif

endif # CFG_NXP_HSE