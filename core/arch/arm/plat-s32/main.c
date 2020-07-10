// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2020-2022, 2024 NXP
 */

#include <console.h>
#include <drivers/gic.h>
#include <drivers/s32_uart.h>
#include <kernel/boot.h>
#include <mm/core_mmu.h>
#include <platform_config.h>

static struct s32_uart_data console_data __nex_bss;

register_phys_mem(MEM_AREA_IO_NSEC, CONSOLE_UART_BASE,
		  CONSOLE_UART_SIZE);

register_phys_mem(MEM_AREA_IO_SEC, GICD_BASE, GIC_DIST_REG_SIZE);

void boot_primary_init_intc(void)
{
	/* Initialize GIC */
	gic_init(0, GICD_BASE);
}

void console_init(void)
{
	s32_uart_init(&console_data, CONSOLE_UART_BASE, CONSOLE_UART_SIZE);
	register_serial_console(&console_data.chip);
}
