incdirs-y += include

incdirs_ext-y += $(CFG_NXP_HSE_FWDIR)/interface
incdirs_ext-y += $(CFG_NXP_HSE_FWDIR)/interface/inc_common
incdirs_ext-y += $(CFG_NXP_HSE_FWDIR)/interface/inc_services
incdirs_ext-y += $(CFG_NXP_HSE_FWDIR)/interface/config
ifeq ($(shell [ -d $(CFG_NXP_HSE_FWDIR)/interface/inc_custom ]; echo $$?), 0)
incdirs_ext-y += $(CFG_NXP_HSE_FWDIR)/interface/inc_custom
endif

srcs-y += hse_mu.c
srcs-y += hse_core.c
srcs-y += hse_util.c
