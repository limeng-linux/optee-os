ifeq ($(CFG_NXP_HSE), y)

# Enable the crypto driver
$(call force,CFG_CRYPTO_DRIVER,y)
CFG_CRYPTO_DRIVER_DEBUG ?= 0

ifeq ($(CFG_NXP_HSE_FWDIR),)
$(error Path to HSE Firmware Package not set. Please use the \
HSE Firmware Package corresponding to PLATFORM_FLAVOR=$(PLATFORM_FLAVOR))
endif

# Enable BestFit algorithm for memory alignment
CFG_CORE_BGET_BESTFIT=y

# Determine if the HSE Firmware Version is Premium or Standard
HSE_FWTYPE_STR=$(shell grep -r '\#define HSE_FWTYPE' $(CFG_NXP_HSE_FWDIR)/interface/config/hse_target.h \
		| sed 's/.*\(PREMIUM\|STANDARD\).*/\1/')
ifeq ($(HSE_FWTYPE_STR), PREMIUM)
$(call force,CFG_HSE_PREMIUM_FW,1)
else
$(call force,CFG_HSE_PREMIUM_FW,0)
endif

$(call force,HSE_NVM_CATALOG,1)
$(call force,HSE_RAM_CATALOG,2)

# Define a keygroup for a certain key type (e.g AES, HMAC etc.)
# A keygroup has 3 attributes: Catalog (NVM or RAM) ID and
# Size (number of slots in the group)
# These keygroups are a reflection of the keygroups of HSE's Key Catalog which is
# currently defined in pkcs11-hse repository: examples/hse-secboot/keys-config.h
# Therefore, the current values and names must be kept in sync with pkcs11-hse's
#
# This will generate three config variables for Catalog, ID and Size in this particular order:
# CFG_NXP_HSE_*_KEYGROUP_CTLG
# CFG_NXP_HSE_*_KEYGROUP_ID
# CFG_NXP_HSE_*_KEYGROUP_SIZE
#
# Example: Define an AES keygroup in the RAM Catalog with ID 2 and 7 slots
#     $(eval $(call hse-keygroup-define, $(HSE_RAM_CATALOG) AES, 2, 7))
define hse-keygroup-define
_type := $(strip $(1))
_catalog := $(strip $(2))
_id := $(strip $(3))
_size := $(strip $(4))
CFG_NXP_HSE_$$(_type)_KEYGROUP_CTLG := $$(_catalog)
CFG_NXP_HSE_$$(_type)_KEYGROUP_ID := $$(_id)
CFG_NXP_HSE_$$(_type)_KEYGROUP_SIZE := $$(_size)
endef


endif # CFG_NXP_HSE