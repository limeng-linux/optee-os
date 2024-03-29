srcs-$(_CFG_CORE_LTC_SHA224_DESC) += sha224.c

ifneq ($(_CFG_CORE_LTC_SHA256_ACCEL),y)
srcs-$(_CFG_CORE_LTC_SHA256_DESC) += sha256.c
endif

srcs-$(_CFG_CORE_LTC_SHA384_DESC) += sha384.c

ifneq ($(_CFG_CORE_LTC_SHA512_ACCEL),y)
srcs-$(_CFG_CORE_LTC_SHA512_DESC) += sha512.c
endif

srcs-$(_CFG_CORE_LTC_SHA512_256) += sha512_256.c
