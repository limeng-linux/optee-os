// SPDX-License-Identifier: BSD-3-Clause
/*
 * NXP HSE Driver - Messaging Unit Interface
 *
 * This file contains the interface implementation for the Messaging Unit
 * instance used by host application cores to request services from HSE.
 *
 * Copyright 2022-2023 NXP
 */

#include <bitstring.h>
#include <hse_interface.h>
#include <hse_mu.h>
#include <kernel/interrupt.h>
#include <io.h>
#include <kernel/boot.h>
#include <kernel/dt.h>
#include <libfdt.h>
#include <kernel/spinlock.h>
#include <malloc.h>
#include <mm/core_memprot.h>
#include <trace.h>

#define GIC_MAX_IRQS	1020

/**
 * struct hse_mu_regs - HSE Messaging Unit Registers
 * @ver: Version ID Register, offset 0x0
 * @par: Parameter Register, offset 0x4
 * @cr: Control Register, offset 0x8
 * @sr: Status Register, offset 0xC
 * @fcr: Flag Control Register, offset 0x100
 * @fsr: Flag Status Register, offset 0x104
 * @gier: General Interrupt Enable Register, offset 0x110
 * @gcr: General Control Register, offset 0x114
 * @gsr: General Status Register, offset 0x118
 * @tcr: Transmit Control Register, offset 0x120
 * @tsr: Transmit Status Register, offset 0x124
 * @rcr: Receive Control Register, offset 0x128
 * @rsr: Receive Status Register, offset 0x12C
 * @tr[n]: Transmit Register n, offset 0x200 + 4*n
 * @rr[n]: Receive Register n, offset 0x280 + 4*n
 */
struct hse_mu_regs {
	const uint32_t ver;
	const uint32_t par;
	uint32_t cr;
	uint32_t sr;
	uint8_t reserved0[240]; /* 0xF0 */
	uint32_t fcr;
	const uint32_t fsr;
	uint8_t reserved1[8]; /* 0x8 */
	uint32_t gier;
	uint32_t gcr;
	uint32_t gsr;
	uint8_t reserved2[4]; /* 0x4 */
	uint32_t tcr;
	const uint32_t tsr;
	uint32_t rcr;
	const uint32_t rsr;
	uint8_t reserved3[208]; /* 0xD0 */
	uint32_t tr[16];
	uint8_t reserved4[64]; /* 0x40 */
	const uint32_t rr[16];
};

/**
 * struct hse_mu_data - MU interface private data
 * @regs: MU instance register space base virtual address
 * @desc_base_ptr: descriptor space base virtual address
 * @desc_base_paddr: descriptor space base physical address
 * @irq_lock: protects the enable/disable of channel irq
 */
struct hse_mu_data {
	struct hse_mu_regs *regs;
	void *desc_base_ptr;
	paddr_t desc_base_paddr;
	unsigned int irq_lock;
};

static struct itr_handler hse_rx_handler;

static const char *hse_compatible = "nxp,s32cc-hse";

/**
 * hse_ioread32 - read from a 32-bit MU register
 * @addr: address of the register to read from
 *
 * Return: value of read register
 */
static uint32_t hse_ioread32(const uint32_t *addr)
{
	return io_read32((vaddr_t)addr);
}

/**
 * hse_iowrite32 - write value to a 32-bit MU register
 * @addr: address of the register to write to
 * @val: value to write
 *
 */
static void hse_iowrite32(const uint32_t *addr, uint32_t val)
{
	io_write32((vaddr_t)addr, val);
}

/**
 * hse_mu_check_status - check the HSE global status
 * @mu: MU instance handle
 *
 * Return: 16 MSB of MU instance FSR
 */
uint16_t hse_mu_check_status(void *mu)
{
	struct hse_mu_data *priv = mu;
	uint32_t fsrval;

	if (!mu)
		return 0;

	fsrval = hse_ioread32(&priv->regs->fsr);
	fsrval = (fsrval & HSE_STATUS_MASK) >> 16u;

	return (uint16_t)fsrval;
}

/**
 * hse_mu_check_event - check for HSE system events
 * @mu: MU instance handle
 *
 * Return: HSE system event mask
 */
TEE_Result hse_mu_check_event(void *mu, uint32_t *val)
{
	struct hse_mu_data *priv = mu;

	if (!mu)
		return TEE_ERROR_BAD_PARAMETERS;

	*val = hse_ioread32(&priv->regs->gsr);

	return TEE_SUCCESS;
}

/**
 * get_irq_regaddr - get the register address along with its mask
 * @mu: MU instance handle
 * @irq_type: interrupt type
 * @irq_mask: return location for the corresponding interrupt mask
 *
 * Return: HSE register address corresponding to the interrupt type.
 *         Also, *irq_mask will store the interrupt mask.
 *         On error, return NULL.
 */
static void *get_irq_regaddr(void *mu, enum hse_irq_type irq_type,
			     uint32_t *irq_mask)
{
	struct hse_mu_data *priv = mu;
	void *regaddr;

	switch (irq_type) {
	case HSE_INT_ACK_REQUEST:
		regaddr = &priv->regs->tcr;
		*irq_mask &= HSE_CH_MASK_ALL;
		break;
	case HSE_INT_RESPONSE:
		regaddr = &priv->regs->rcr;
		*irq_mask &= HSE_CH_MASK_ALL;
		break;
	case HSE_INT_SYS_EVENT:
		regaddr = &priv->regs->gier;
		*irq_mask &= HSE_EVT_MASK_ALL;
		break;
	default:
		return NULL;
	}

	return regaddr;
}

/**
 * hse_mu_irq_enable - enable a specific type of interrupt using a mask
 * @mu: MU instance handle
 * @irq_type: interrupt type
 * @irq_mask: interrupt mask
 */
void hse_mu_irq_enable(void *mu, enum hse_irq_type irq_type,
		       uint32_t irq_mask)
{
	struct hse_mu_data *priv = mu;
	void *regaddr;
	uint32_t exceptions;

	regaddr = get_irq_regaddr(priv, irq_type, &irq_mask);
	if (!regaddr)
		return;

	exceptions = cpu_spin_lock_xsave(&priv->irq_lock);

	hse_iowrite32(regaddr, hse_ioread32(regaddr) | irq_mask);

	cpu_spin_unlock_xrestore(&priv->irq_lock, exceptions);
}

/**
 * hse_mu_irq_disable - disable a specific type of interrupt using a mask
 * @mu: MU instance handle
 * @irq_type: interrupt type
 * @irq_mask: interrupt mask
 */
void hse_mu_irq_disable(void *mu, enum hse_irq_type irq_type,
			uint32_t irq_mask)
{
	struct hse_mu_data *priv = mu;
	void *regaddr;
	uint32_t exceptions;

	regaddr = get_irq_regaddr(priv, irq_type, &irq_mask);
	if (!regaddr)
		return;

	exceptions = cpu_spin_lock_xsave(&priv->irq_lock);

	hse_iowrite32(regaddr, hse_ioread32(regaddr) & ~irq_mask);

	cpu_spin_unlock_xrestore(&priv->irq_lock, exceptions);
}

/**
 * hse_mu_is_irq_enabled - checks if the interrupt type is enabled
 *                         for the given channel
 * @mu: MU instance handle
 * @irq_type: interrupt type
 * @channel: channel ID
 *
 * Return: true if the irq is enabled, false otherwise
 */

bool hse_mu_is_irq_enabled(void *mu, enum hse_irq_type irq_type,
			   uint8_t channel)
{
	struct hse_mu_data *priv = mu;
	void *regaddr;
	uint32_t exceptions, val, irq_mask;

	if (channel >= HSE_NUM_OF_CHANNELS_PER_MU)
		return false;

	irq_mask = BIT(channel);
	regaddr = get_irq_regaddr(priv, irq_type, &irq_mask);
	if (!regaddr)
		return false;

	exceptions = cpu_spin_lock_xsave(&priv->irq_lock);

	val = hse_ioread32(regaddr) & irq_mask;

	cpu_spin_unlock_xrestore(&priv->irq_lock, exceptions);

	return val;
}

/**
 * hse_mu_channel_available - check service channel status
 * @mu: MU instance handle
 * @channel: channel index
 *
 * The 16 LSB of MU instance FSR are used by HSE for signaling channel status
 * as busy after a service request has been sent, until the HSE reply is ready.
 *
 * Return: true for channel available, false for invalid index or channel busy
 */
static bool hse_mu_channel_available(void *mu, uint8_t channel)
{
	struct hse_mu_data *priv = mu;
	uint32_t fsrval, tsrval, rsrval;

	if (channel >= HSE_NUM_OF_CHANNELS_PER_MU)
		return false;

	fsrval = hse_ioread32(&priv->regs->fsr) & BIT(channel);
	tsrval = hse_ioread32(&priv->regs->tsr) & BIT(channel);
	rsrval = hse_ioread32(&priv->regs->rsr) & BIT(channel);

	if (fsrval || !tsrval || rsrval)
		return false;

	return true;
}

/**
 * hse_mu_pending_channels - return all pending channels
 * @mu: MU instance handle
 *
 * Return: masked rsr value, 0 if no message pending
 */
uint32_t hse_mu_pending_channels(void *mu)
{
	struct hse_mu_data *priv = mu;

	if (!mu)
		return 0;

	return hse_ioread32(&priv->regs->rsr) & HSE_CH_MASK_ALL;
}

/**
 * hse_mu_msg_pending - check if a service request response is pending
 * @mu: MU instance handle
 * @channel: channel index
 *
 * Return: true for response ready, false otherwise
 */
bool hse_mu_msg_pending(void *mu, uint8_t channel)
{
	struct hse_mu_data *priv = mu;
	uint32_t rsrval;

	if (!mu || channel >= HSE_NUM_OF_CHANNELS_PER_MU)
		return false;

	rsrval = hse_ioread32(&priv->regs->rsr) & BIT(channel);
	if (!rsrval)
		return false;

	return true;
}

/**
 * hse_mu_msg_send - send a message over MU (non-blocking)
 * @mu: MU instance handle
 * @channel: channel index
 * @msg: input message
 *
 * Return: 0 on success, TEE_ERROR_BAD_PARAMETERS for invalid channel or mu,
 *         TEE_ERROR_BUSY for selected channel busy
 */
TEE_Result hse_mu_msg_send(void *mu, uint8_t channel, uint32_t msg)
{
	struct hse_mu_data *priv = mu;

	if (!mu)
		return TEE_ERROR_BAD_PARAMETERS;

	if (channel >= HSE_NUM_OF_CHANNELS_PER_MU)
		return TEE_ERROR_BAD_PARAMETERS;

	if (!hse_mu_channel_available(mu, channel)) {
		DMSG("channel %d busy\n", channel);
		return TEE_ERROR_BUSY;
	}

	hse_iowrite32(&priv->regs->tr[channel], msg);

	return TEE_SUCCESS;
}

/**
 * hse_mu_msg_recv - read a message received over MU (non-blocking)
 * @mu: MU instance handle
 * @channel: channel index
 * @msg: output message
 *
 * Return: 0 on success, TEE_ERROR_BAD_PARAMETERS for invalid channel or mu,
 *         TEE_ERROR_NO_DATA if no pending message is available
 */
TEE_Result hse_mu_msg_recv(void *mu, uint8_t channel, uint32_t *msg)
{
	struct hse_mu_data *priv = mu;

	if (!mu || !msg)
		return TEE_ERROR_BAD_PARAMETERS;

	if (channel >= HSE_NUM_OF_CHANNELS_PER_MU)
		return TEE_ERROR_BAD_PARAMETERS;

	if (!hse_mu_msg_pending(mu, channel)) {
		DMSG("no message pending on channel %d\n", channel);
		return TEE_ERROR_NO_DATA;
	}

	*msg = hse_ioread32(&priv->regs->rr[channel]);

	return TEE_SUCCESS;
}

void *hse_mu_desc_base_ptr(void *mu)
{
	struct hse_mu_data *priv = mu;

	if (!mu)
		return NULL;

	return priv->desc_base_ptr;
}

paddr_t hse_mu_desc_base_paddr(void *mu)
{
	struct hse_mu_data *priv = mu;

	if (!mu)
		return 0;

	return priv->desc_base_paddr;
}

/**
 * hse_mu_space_map - map the physical address space to virtual addresses
 * @base: base physical address
 * @len: length of the physical space
 *
 * Return: starting virtual address on success, NULL on error
 */
static void *hse_mu_space_map(paddr_t base, size_t len)
{
	void *space = NULL;

	space = phys_to_virt_io(base, len);
	if (!space) {
		if (!core_mmu_add_mapping(MEM_AREA_IO_SEC, base, len)) {
			EMSG("Unable to map HSE_MU Space");
			return NULL;
		}

		space = phys_to_virt_io(base, len);
		if (!space) {
			EMSG("Unable to get the MU Base address");
			return NULL;
		}
	}

	return space;
}

static int fdt_read_irq_cells(const fdt32_t *prop, int nr_cells)
{
	int it_num;
	uint32_t res;

	if (!prop || nr_cells < 2)
		return DT_INFO_INVALID_INTERRUPT;

	res = fdt32_to_cpu(prop[1]);
	if (res >= GIC_MAX_IRQS)
		return DT_INFO_INVALID_INTERRUPT;

	it_num = (int)res;

	switch (fdt32_to_cpu(prop[0])) {
	case 1:
		it_num += 16;
		break;
	case 0:
		it_num += 32;
		break;
	default:
		it_num = DT_INFO_INVALID_INTERRUPT;
	}

	return it_num;
}

static int fdt_get_irq_props_by_index(const void *dtb, int node,
				      unsigned int index, int *irq_num)
{
	const fdt32_t *prop;
	int parent, len = 0;
	uint32_t ic, cell, res;

	parent = fdt_parent_offset(dtb, node);
	if (parent < 0)
		return -FDT_ERR_BADOFFSET;

	prop = fdt_getprop(dtb, parent, "#interrupt-cells", NULL);
	if (!prop) {
		IMSG("Couldn't find \"#interrupts-cells\" property in dtb\n");
		return -FDT_ERR_NOTFOUND;
	}

	ic = fdt32_to_cpu(*prop);

	if (MUL_OVERFLOW(index, ic, &cell))
		return -FDT_ERR_BADVALUE;

	prop = fdt_getprop(dtb, node, "interrupts", &len);
	if (!prop) {
		IMSG("Couldn't find \"interrupts\" property in dtb\n");
		return -FDT_ERR_NOTFOUND;
	}

	if (ADD_OVERFLOW(cell, ic, &res))
		return -FDT_ERR_BADVALUE;

	if (MUL_OVERFLOW(res, sizeof(uint32_t), &res))
		return -FDT_ERR_BADVALUE;

	/* res = (cell + ic) * sizeof(uint32_t) */
	if (res > (unsigned int)len)
		return -FDT_ERR_BADVALUE;

	if (irq_num) {
		*irq_num = fdt_read_irq_cells(&prop[cell], ic);
		if (*irq_num < 0)
			return -FDT_ERR_BADVALUE;
	}

	return 0;
}

static int find_hse_compatible_enabled(void *fdt)
{
	int offs = -1;

	while (true) {
		offs = fdt_node_offset_by_compatible(fdt, offs, hse_compatible);

		if (offs < 0)
			break;

		if (fdt_get_status(fdt, offs) == (DT_STATUS_OK_NSEC |
						   DT_STATUS_OK_SEC))
			break;
	}

	return offs;
}

static int hse_dt_get_irq(int *rx_irq)
{
	void *fdt = NULL;
	int offset;
	int rx_irq_off;
	int ret;

	fdt = get_dt();
	if (!fdt) {
		EMSG("No Device Tree found");
		return -1;
	}

	offset = find_hse_compatible_enabled(fdt);
	if (offset < 0) {
		EMSG("Could not find node with matching compatible \"%s\"",
		     hse_compatible);
		return offset;
	}
	rx_irq_off = fdt_stringlist_search(fdt, offset, "interrupt-names",
					   "hse-rx");
	if (rx_irq_off < 0)
		return rx_irq_off;

	ret = fdt_get_irq_props_by_index(fdt, offset, rx_irq_off, rx_irq);
	if (ret < 0)
		return ret;

	return 0;
}

static int hse_dt_get_regs(paddr_t *regs_base, size_t *regs_size,
			   paddr_t *desc_base, size_t *desc_size)
{
	void *fdt = NULL;
	int offset, ret;
	paddr_t base;
	size_t size;

	fdt = get_dt();
	if (!fdt) {
		EMSG("No Device Tree found");
		return -1;
	}

	offset = find_hse_compatible_enabled(fdt);
	if (offset < 0) {
		EMSG("Could not find node with matching compatible \"%s\"",
		     hse_compatible);
		return offset;
	}

	ret = fdt_get_reg_props_by_name(fdt, offset, "hse-regs", &base, &size);
	if (ret < 0)
		return ret;
	*regs_base = base;
	*regs_size = size;

	ret = fdt_get_reg_props_by_name(fdt, offset, "hse-desc", &base, &size);
	if (ret < 0)
		return ret;
	*desc_base = base;
	*desc_size = size;

	return 0;
}

/**
 * hse_mu_init - initial setup of MU interface
 *
 * Return: MU instance handle on success, NULL otherwise
 */
void *hse_mu_init(void *data, enum itr_return (*rx_itr)(struct itr_handler *h))
{
	TEE_Result res;
	struct hse_mu_data *mu = NULL;
	uint8_t channel;
	uint32_t msg;
	int err;
	int rx_irq_num;
	paddr_t regs_base, desc_base;
	size_t regs_size, desc_size;

	mu = malloc(sizeof(*mu));
	if (!mu) {
		EMSG("Could not malloc MU Instance");
		return NULL;
	}

	err = hse_dt_get_regs(&regs_base, &regs_size, &desc_base, &desc_size);
	if (err) {
		EMSG("Failed to parse \"regs\" properties from the DT");
		goto out_err;
	}
	mu->regs = hse_mu_space_map(regs_base, regs_size);
	if (!mu->regs)
		goto out_err;

	mu->desc_base_ptr = hse_mu_space_map(desc_base, desc_size);
	if (!mu->desc_base_ptr)
		goto out_err;

	mu->desc_base_paddr = desc_base;

	err = hse_dt_get_irq(&rx_irq_num);
	if (err) {
		EMSG("Failed to parse \"interrupts\" properties from the DT");
		goto out_err;
	}

	/* Register the interrupt handler for the RX interrupt */
	hse_rx_handler.it = rx_irq_num;
	hse_rx_handler.handler = rx_itr;
	hse_rx_handler.data = data;
	itr_add(&hse_rx_handler);
	itr_enable(hse_rx_handler.it);

	mu->irq_lock = SPINLOCK_UNLOCK;

	hse_mu_irq_disable(mu, HSE_INT_ACK_REQUEST, HSE_CH_MASK_ALL);
	hse_mu_irq_disable(mu, HSE_INT_RESPONSE, HSE_CH_MASK_ALL);
	hse_mu_irq_disable(mu, HSE_INT_SYS_EVENT, HSE_EVT_MASK_ALL);

	/* discard any pending messages */
	for (channel = 0; channel < HSE_NUM_OF_CHANNELS_PER_MU; channel++)
		if (hse_mu_msg_pending(mu, channel)) {
			res = hse_mu_msg_recv(mu, channel, &msg);
			if (res == TEE_SUCCESS)
				IMSG("channel %d: msg %08x dropped\n",
				     channel, msg);
		}

	return mu;

out_err:
	free(mu);
	return NULL;
}
