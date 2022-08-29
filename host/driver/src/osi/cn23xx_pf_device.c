/**********************************************************************
 * Author: Cavium, Inc.
 *
 * Contact: support@cavium.com
 *          Please include "LiquidIO" in the subject.
 *
 * Copyright (c) 2003-2016 Cavium, Inc.
 *
 * This file is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License, Version 2, as
 * published by the Free Software Foundation.
 *
 * This file is distributed in the hope that it will be useful, but
 * AS-IS and WITHOUT ANY WARRANTY; without even the implied warranty
 * of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE, TITLE, or
 * NONINFRINGEMENT.  See the GNU General Public License for more details.
 ***********************************************************************/
#include "cavium_sysdep.h"
#include "liquidio_common.h"
#include "octeon_droq.h"
#include "octeon_iq.h"
#include "response_manager.h"
#include "octeon_device.h"
#include "cn23xx_pf_device.h"
#include "octeon_main.h"
#include "octeon_mailbox.h"

#define RESET_NOTDONE 0
#define RESET_DONE 1

/* for non-Linux code, we must provide these definitions (from linux/pci.h) */
#  define PCI_BASE_ADDRESS_0 0x10
#  define PCI_BASE_ADDRESS_1 0x14
#  define PCI_BASE_ADDRESS_2 0x18
#  define PCI_BASE_ADDRESS_3 0x1c

#if !defined(__linux_upstream__) && defined(RHEL_RELEASE_CODE) && defined(RHEL_RELEASE_VERSION)
#  if (RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(6, 0)) && (RHEL_RELEASE_CODE < RHEL_RELEASE_VERSION(7, 0))
#    define OCT_RHEL_GTE60_AND_LT70
#  endif
#endif

void cn23xx_dump_pf_initialized_regs(struct octeon_device *oct)
{
	int i = 0;
	u32 regval = 0;
	struct octeon_cn23xx_pf *cn23xx = (struct octeon_cn23xx_pf *)oct->chip;

	/*In cn23xx_soft_reset*/
	lio_dev_dbg(oct, "%s[%llx] : 0x%llx\n",
		    "CN23XX_WIN_WR_MASK_REG", CVM_CAST64(CN23XX_WIN_WR_MASK_REG),
		    CVM_CAST64(octeon_read_csr64(oct, CN23XX_WIN_WR_MASK_REG)));
	lio_dev_dbg(oct, "%s[%llx] : 0x%016llx\n",
		    "CN23XX_SLI_SCRATCH1", CVM_CAST64(CN23XX_SLI_SCRATCH1),
		    CVM_CAST64(octeon_read_csr64(oct, CN23XX_SLI_SCRATCH1)));
	lio_dev_dbg(oct, "%s[%llx] : 0x%016llx\n",
		    "CN23XX_RST_SOFT_RST", CN23XX_RST_SOFT_RST,
		    lio_pci_readq(oct, CN23XX_RST_SOFT_RST));

	/*In cn23xx_set_dpi_regs*/
	lio_dev_dbg(oct, "%s[%llx] : 0x%016llx\n",
		    "CN23XX_DPI_DMA_CONTROL", CN23XX_DPI_DMA_CONTROL,
		    lio_pci_readq(oct, CN23XX_DPI_DMA_CONTROL));

	for (i = 0; i < 6; i++) {
		lio_dev_dbg(oct, "%s(%d)[%llx] : 0x%016llx\n",
			    "CN23XX_DPI_DMA_ENG_ENB", i,
			    CN23XX_DPI_DMA_ENG_ENB(i),
			    lio_pci_readq(oct, CN23XX_DPI_DMA_ENG_ENB(i)));
		lio_dev_dbg(oct, "%s(%d)[%llx] : 0x%016llx\n",
			    "CN23XX_DPI_DMA_ENG_BUF", i,
			    CN23XX_DPI_DMA_ENG_BUF(i),
			    lio_pci_readq(oct, CN23XX_DPI_DMA_ENG_BUF(i)));
	}

	lio_dev_dbg(oct, "%s[%llx] : 0x%016llx\n", "CN23XX_DPI_CTL",
		    CN23XX_DPI_CTL, lio_pci_readq(oct, CN23XX_DPI_CTL));

	/*In cn23xx_setup_pcie_mps and cn23xx_setup_pcie_mrrs */
	OCTEON_READ_PCI_CONFIG(oct, CN23XX_CONFIG_PCIE_DEVCTL, &regval);
	lio_dev_dbg(oct, "%s[%llx] : 0x%016llx\n",
		    "CN23XX_CONFIG_PCIE_DEVCTL",
		    CVM_CAST64(CN23XX_CONFIG_PCIE_DEVCTL), CVM_CAST64(regval));

	lio_dev_dbg(oct, "%s(%d)[%llx] : 0x%016llx\n",
		    "CN23XX_DPI_SLI_PRTX_CFG", oct->pcie_port,
		    CN23XX_DPI_SLI_PRTX_CFG(oct->pcie_port),
		    lio_pci_readq(oct, CN23XX_DPI_SLI_PRTX_CFG(oct->pcie_port)));

	/*In cn23xx_specific_regs_setup */
	lio_dev_dbg(oct, "%s(%d)[%llx] : 0x%016llx\n",
		    "CN23XX_SLI_S2M_PORTX_CTL", oct->pcie_port,
		    CVM_CAST64(CN23XX_SLI_S2M_PORTX_CTL(oct->pcie_port)),
		    CVM_CAST64(octeon_read_csr64(
			oct, CN23XX_SLI_S2M_PORTX_CTL(oct->pcie_port))));

	lio_dev_dbg(oct, "%s[%llx] : 0x%016llx\n",
		    "CN23XX_SLI_RING_RST", CVM_CAST64(CN23XX_SLI_PKT_IOQ_RING_RST),
		    (u64)octeon_read_csr64(oct, CN23XX_SLI_PKT_IOQ_RING_RST));

	/*In cn23xx_setup_global_mac_regs*/
	for (i = 0; i < CN23XX_MAX_MACS; i++) {
		lio_dev_dbg(oct, "%s(%d)[%llx] : 0x%016llx\n",
			    "CN23XX_SLI_PKT_MAC_RINFO64", i,
			    CVM_CAST64(CN23XX_SLI_PKT_MAC_RINFO64(i, oct->pf_num)),
			    CVM_CAST64(octeon_read_csr64
				       (oct, CN23XX_SLI_PKT_MAC_RINFO64
					(i, oct->pf_num))));
	}

	/*In cn23xx_setup_global_input_regs*/
	for (i = 0; i < CN23XX_MAX_INPUT_QUEUES; i++) {
		lio_dev_dbg(oct, "%s(%d)[%llx] : 0x%016llx\n",
			    "CN23XX_SLI_IQ_PKT_CONTROL64", i,
			    CVM_CAST64(CN23XX_SLI_IQ_PKT_CONTROL64(i)),
			    CVM_CAST64(octeon_read_csr64
				       (oct, CN23XX_SLI_IQ_PKT_CONTROL64(i))));
	}

	/*In cn23xx_setup_global_output_regs*/
	lio_dev_dbg(oct, "%s[%llx] : 0x%016llx\n",
		    "CN23XX_SLI_OQ_WMARK", CVM_CAST64(CN23XX_SLI_OQ_WMARK),
		    CVM_CAST64(octeon_read_csr64(oct, CN23XX_SLI_OQ_WMARK)));

	for (i = 0; i < CN23XX_MAX_OUTPUT_QUEUES; i++) {
		lio_dev_dbg(oct, "%s(%d)[%llx] : 0x%016llx\n",
			    "CN23XX_SLI_OQ_PKT_CONTROL", i,
			    CVM_CAST64(CN23XX_SLI_OQ_PKT_CONTROL(i)),
			    CVM_CAST64(octeon_read_csr(
				oct, CN23XX_SLI_OQ_PKT_CONTROL(i))));
		lio_dev_dbg(oct, "%s(%d)[%llx] : 0x%016llx\n",
			    "CN23XX_SLI_OQ_PKT_INT_LEVELS", i,
			    CVM_CAST64(CN23XX_SLI_OQ_PKT_INT_LEVELS(i)),
			    CVM_CAST64(octeon_read_csr64(
				oct, CN23XX_SLI_OQ_PKT_INT_LEVELS(i))));
	}

	/*In cn23xx_enable_interrupt and cn23xx_disable_interrupt*/
	lio_dev_dbg(oct, "%s[%llx] : 0x%016llx\n",
		    "cn23xx->intr_enb_reg64",
		    CVM_CAST64((size_t)(cn23xx->intr_enb_reg64)),
		    CVM_CAST64(OCTEON_READ64(cn23xx->intr_enb_reg64)));

	lio_dev_dbg(oct, "%s[%llx] : 0x%016llx\n",
		    "cn23xx->intr_sum_reg64",
		    CVM_CAST64((size_t)(cn23xx->intr_sum_reg64)),
		    CVM_CAST64(OCTEON_READ64(cn23xx->intr_sum_reg64)));

	/*In cn23xx_setup_iq_regs*/
	for (i = 0; i < CN23XX_MAX_INPUT_QUEUES; i++) {
		lio_dev_dbg(oct, "%s(%d)[%llx] : 0x%016llx\n",
			    "CN23XX_SLI_IQ_BASE_ADDR64", i,
			    CVM_CAST64(CN23XX_SLI_IQ_BASE_ADDR64(i)),
			    CVM_CAST64(octeon_read_csr64(
				oct, CN23XX_SLI_IQ_BASE_ADDR64(i))));
		lio_dev_dbg(oct, "%s(%d)[%llx] : 0x%016llx\n",
			    "CN23XX_SLI_IQ_SIZE", i,
			    CVM_CAST64(CN23XX_SLI_IQ_SIZE(i)),
			    CVM_CAST64(octeon_read_csr
				       (oct, CN23XX_SLI_IQ_SIZE(i))));
		lio_dev_dbg(oct, "%s(%d)[%llx] : 0x%016llx\n",
			    "CN23XX_SLI_IQ_DOORBELL", i,
			    CVM_CAST64(CN23XX_SLI_IQ_DOORBELL(i)),
			    CVM_CAST64(octeon_read_csr64(
				oct, CN23XX_SLI_IQ_DOORBELL(i))));
		lio_dev_dbg(oct, "%s(%d)[%llx] : 0x%016llx\n",
			    "CN23XX_SLI_IQ_INSTR_COUNT64", i,
			    CVM_CAST64(CN23XX_SLI_IQ_INSTR_COUNT64(i)),
			    CVM_CAST64(octeon_read_csr64(
				oct, CN23XX_SLI_IQ_INSTR_COUNT64(i))));
	}

	/*In cn23xx_setup_oq_regs*/
	for (i = 0; i < CN23XX_MAX_OUTPUT_QUEUES; i++) {
		lio_dev_dbg(oct, "%s(%d)[%llx] : 0x%016llx\n",
			    "CN23XX_SLI_OQ_BASE_ADDR64", i,
			    CVM_CAST64(CN23XX_SLI_OQ_BASE_ADDR64(i)),
			    CVM_CAST64(octeon_read_csr64(
				oct, CN23XX_SLI_OQ_BASE_ADDR64(i))));
		lio_dev_dbg(oct, "%s(%d)[%llx] : 0x%016llx\n",
			    "CN23XX_SLI_OQ_SIZE", i,
			    CVM_CAST64(CN23XX_SLI_OQ_SIZE(i)),
			    CVM_CAST64(octeon_read_csr
				       (oct, CN23XX_SLI_OQ_SIZE(i))));
		lio_dev_dbg(oct, "%s(%d)[%llx] : 0x%016llx\n",
			    "CN23XX_SLI_OQ_BUFF_INFO_SIZE", i,
			    CVM_CAST64(CN23XX_SLI_OQ_BUFF_INFO_SIZE(i)),
			    CVM_CAST64(octeon_read_csr(
				oct, CN23XX_SLI_OQ_BUFF_INFO_SIZE(i))));
		lio_dev_dbg(oct, "%s(%d)[%llx] : 0x%016llx\n",
			    "CN23XX_SLI_OQ_PKTS_SENT", i,
			    CVM_CAST64(CN23XX_SLI_OQ_PKTS_SENT(i)),
			    CVM_CAST64(octeon_read_csr64(
				oct, CN23XX_SLI_OQ_PKTS_SENT(i))));
		lio_dev_dbg(oct, "%s(%d)[%llx] : 0x%016llx\n",
			    "CN23XX_SLI_OQ_PKTS_CREDIT", i,
			    CVM_CAST64(CN23XX_SLI_OQ_PKTS_CREDIT(i)),
			    CVM_CAST64(octeon_read_csr64(
				oct, CN23XX_SLI_OQ_PKTS_CREDIT(i))));
	}

	lio_dev_dbg(oct, "%s[%llx] : 0x%016llx\n",
		    "CN23XX_SLI_PKT_TIME_INT",
		    CVM_CAST64(CN23XX_SLI_PKT_TIME_INT),
		    CVM_CAST64(octeon_read_csr64(oct, CN23XX_SLI_PKT_TIME_INT)));
	lio_dev_dbg(oct, "%s[%llx] : 0x%016llx\n",
		    "CN23XX_SLI_PKT_CNT_INT",
		    CVM_CAST64(CN23XX_SLI_PKT_CNT_INT),
		    CVM_CAST64(octeon_read_csr64(oct, CN23XX_SLI_PKT_CNT_INT)));
}

static int cn23xx_pf_soft_reset(struct octeon_device *oct)
{
	octeon_write_csr64(oct, CN23XX_WIN_WR_MASK_REG, 0xFF);

	lio_dev_dbg(oct, "OCTEON[%d]: BIST enabled for CN23XX soft reset\n",
		    oct->octeon_id);

	octeon_write_csr64(oct, CN23XX_SLI_SCRATCH1, 0x1234ULL);

	/* Initiate chip-wide soft reset */
	lio_pci_readq(oct, CN23XX_RST_SOFT_RST);
	lio_pci_writeq(oct, 1, CN23XX_RST_SOFT_RST);

	/* Wait for 100ms as Octeon resets. */
	cavium_mdelay(100);

	if (octeon_read_csr64(oct, CN23XX_SLI_SCRATCH1) != 0x0ULL) {
		lio_dev_err(oct, "OCTEON[%d]: Soft reset failed\n",
			    oct->octeon_id);
		return 1;
	}

	lio_dev_dbg(oct, "OCTEON[%d]: Reset completed\n",
		    oct->octeon_id);

	/* restore the  reset value*/
	octeon_write_csr64(oct, CN23XX_WIN_WR_MASK_REG, 0xFF);

	return 0;
}

static void cn23xx_enable_error_reporting(struct octeon_device *oct)
{
	u32 regval;
	u32 uncorrectable_err_mask, corrtable_err_status;

	OCTEON_READ_PCI_CONFIG(oct, CN23XX_CONFIG_PCIE_DEVCTL, &regval);
	if (regval & CN23XX_CONFIG_PCIE_DEVCTL_MASK) {
		uncorrectable_err_mask = 0;
		corrtable_err_status = 0;
		OCTEON_READ_PCI_CONFIG(oct,
				       CN23XX_CONFIG_PCIE_UNCORRECT_ERR_MASK,
				       &uncorrectable_err_mask);
		OCTEON_READ_PCI_CONFIG(oct,
				       CN23XX_CONFIG_PCIE_CORRECT_ERR_STATUS,
				       &corrtable_err_status);
		lio_dev_err(oct, "PCI-E Fatal error detected;\n"
				 "\tdev_ctl_status_reg = 0x%08x\n"
				 "\tuncorrectable_error_mask_reg = 0x%08x\n"
				 "\tcorrectable_error_status_reg = 0x%08x\n",
			    regval, uncorrectable_err_mask,
			    corrtable_err_status);
	}

	regval |= 0xf; /* Enable Link error reporting */

	lio_dev_dbg(oct, "OCTEON[%d]: Enabling PCI-E error reporting..\n",
		    oct->octeon_id);
	OCTEON_WRITE_PCI_CONFIG(oct, CN23XX_CONFIG_PCIE_DEVCTL, regval);
}

static u32 cn23xx_coprocessor_clock(struct octeon_device *oct)
{
	/* Bits 29:24 of RST_BOOT[PNR_MUL] holds the ref.clock MULTIPLIER
	 * for SLI.
	 */

	/* TBD: get the info in Hand-shake */
	return (((lio_pci_readq(oct, CN23XX_RST_BOOT) >> 24) & 0x3f) * 50);
}

u32 cn23xx_pf_get_oq_ticks(struct octeon_device *oct, u32 time_intr_in_us)
{
	/* This gives the SLI clock per microsec */
	u32 oqticks_per_us = cn23xx_coprocessor_clock(oct);

	oct->pfvf_hsword.coproc_tics_per_us = oqticks_per_us;

	/* This gives the clock cycles per millisecond */
	oqticks_per_us *= 1000;

	/* This gives the oq ticks (1024 core clock cycles) per millisecond */
	oqticks_per_us /= 1024;

	/* time_intr is in microseconds. The next 2 steps gives the oq ticks
	 *  corressponding to time_intr.
	 */
	oqticks_per_us *= time_intr_in_us;
	oqticks_per_us /= 1000;

	return oqticks_per_us;
}

static void cn23xx_setup_global_mac_regs(struct octeon_device *oct)
{
	u16 mac_no = oct->pcie_port;
	u16 pf_num = oct->pf_num;
	u64 reg_val;
	u64 temp;

	/* programming SRN and TRS for each MAC(0..3)  */

	lio_dev_dbg(oct, "%s:Using pcie port %d\n",
		    __CVM_FUNCTION__, mac_no);
	/* By default, mapping all 64 IOQs to  a single MACs */

	reg_val =
	    octeon_read_csr64(oct, CN23XX_SLI_PKT_MAC_RINFO64(mac_no, pf_num));

	if (oct->rev_id == OCTEON_CN23XX_REV_1_1) {
		/* setting SRN <6:0>  */
		reg_val = pf_num * CN23XX_MAX_RINGS_PER_PF_PASS_1_1;
	} else {
		/* setting SRN <6:0>  */
		reg_val = pf_num * CN23XX_MAX_RINGS_PER_PF;
	}

	/* setting TRS <23:16> */
	reg_val = reg_val |
		  (oct->sriov_info.trs << CN23XX_PKT_MAC_CTL_RINFO_TRS_BIT_POS);
	/* setting RPVF <39:32> */
	temp = oct->sriov_info.rings_per_vf & 0xff;
	reg_val |= (temp << CN23XX_PKT_MAC_CTL_RINFO_RPVF_BIT_POS);

	/* setting NVFS <55:48> */
	temp = oct->sriov_info.max_vfs & 0xff;
	reg_val |= (temp << CN23XX_PKT_MAC_CTL_RINFO_NVFS_BIT_POS);

	/* write these settings to MAC register */
	octeon_write_csr64(oct, CN23XX_SLI_PKT_MAC_RINFO64(mac_no, pf_num),
			   reg_val);

	lio_dev_dbg(oct, "SLI_PKT_MAC(%d)_PF(%d)_RINFO : 0x%016llx\n",
		    mac_no, pf_num, (u64)octeon_read_csr64
		    (oct, CN23XX_SLI_PKT_MAC_RINFO64(mac_no, pf_num)));
}

static int cn23xx_reset_io_queues(struct octeon_device *oct)
{
	u32 loop = BUSY_READING_REG_PF_LOOP_COUNT;
	u32 q_no, srn, ern;
	int ret_val = 0;
	u64 d64;

	srn = oct->sriov_info.pf_srn;
	ern = srn + oct->sriov_info.num_pf_rings;

	/*As per HRM reg description, s/w cant write 0 to ENB. */
	/*to make the queue off, need to set the RST bit. */

	/* Reset the Enable bit for all the 64 IQs.  */
	for (q_no = srn; q_no < ern; q_no++) {
		/* set RST bit to 1. This bit applies to both IQ and OQ */
		d64 = octeon_read_csr64(oct, CN23XX_SLI_IQ_PKT_CONTROL64(q_no));
		d64 = d64 | CN23XX_PKT_INPUT_CTL_RST;
		octeon_write_csr64(oct, CN23XX_SLI_IQ_PKT_CONTROL64(q_no), d64);
	}

	/* wait until the RST bit is clear or the RST and quiet bits are set */
	for (q_no = srn; q_no < ern; q_no++) {
		cavium_volatile_u64 reg_val = octeon_read_csr64(oct,
					CN23XX_SLI_IQ_PKT_CONTROL64(q_no));
		while ((cavium_read_once64(reg_val) & CN23XX_PKT_INPUT_CTL_RST) &&
		       !(cavium_read_once64(reg_val) & CN23XX_PKT_INPUT_CTL_QUIET) &&
		       loop) {
			cavium_write_once64(reg_val, octeon_read_csr64(
			    oct, CN23XX_SLI_IQ_PKT_CONTROL64(q_no)));
			loop--;
		}
		if (!loop) {
			lio_dev_err(oct,
				    "clearing the reset reg failed or setting the quiet reg failed for qno: %u\n",
				    q_no);
			return -1;
		}
		cavium_write_once64(reg_val, cavium_read_once64(reg_val) &
			~CN23XX_PKT_INPUT_CTL_RST);
		octeon_write_csr64(oct, CN23XX_SLI_IQ_PKT_CONTROL64(q_no),
				   cavium_read_once64(reg_val));

		cavium_write_once64(reg_val, octeon_read_csr64(
			   oct, CN23XX_SLI_IQ_PKT_CONTROL64(q_no)));
		if (cavium_read_once64(reg_val) & CN23XX_PKT_INPUT_CTL_RST) {
			lio_dev_err(oct,
				    "clearing the reset failed for qno: %u\n",
				    q_no);
			ret_val = -1;
		}
	}

	return ret_val;
}

static int cn23xx_pf_setup_global_input_regs(struct octeon_device *oct)
{
	struct octeon_cn23xx_pf *cn23xx = (struct octeon_cn23xx_pf *)oct->chip;
	struct octeon_instr_queue *iq;
	u64 intr_threshold, reg_val;
	u32 q_no, ern, srn;
	u64 pf_num;
	u64 vf_num;

	pf_num = oct->pf_num;

	srn = oct->sriov_info.pf_srn;
	ern = srn + oct->sriov_info.num_pf_rings;

	if (cn23xx_reset_io_queues(oct))
		return -1;

	/** Set the MAC_NUM and PVF_NUM in IQ_PKT_CONTROL reg
	 * for all queues.Only PF can set these bits.
	 * bits 29:30 indicate the MAC num.
	 * bits 32:47 indicate the PVF num.
	 */
	for (q_no = 0; q_no < ern; q_no++) {
		reg_val = oct->pcie_port << CN23XX_PKT_INPUT_CTL_MAC_NUM_POS;

		/* for VF assigned queues. */
		if (q_no < oct->sriov_info.pf_srn) {
			vf_num = q_no / oct->sriov_info.rings_per_vf;
			vf_num += 1; /* VF1, VF2,........ */
		} else {
			vf_num = 0;
		}

		reg_val |= vf_num << CN23XX_PKT_INPUT_CTL_VF_NUM_POS;
		reg_val |= pf_num << CN23XX_PKT_INPUT_CTL_PF_NUM_POS;

		octeon_write_csr64(oct, CN23XX_SLI_IQ_PKT_CONTROL64(q_no),
				   reg_val);
	}

	/* Select ES, RO, NS, RDSIZE,DPTR Fomat#0 for
	 * pf queues
	 */
	for (q_no = srn; q_no < ern; q_no++) {
		void cavium_iomem *inst_cnt_reg;

		iq = oct->instr_queue[q_no];
		if (iq)
			inst_cnt_reg = iq->inst_cnt_reg;
		else
			inst_cnt_reg = (u8 *)oct->mmio[0].hw_addr +
				       CN23XX_SLI_IQ_INSTR_COUNT64(q_no);

		reg_val =
		    octeon_read_csr64(oct, CN23XX_SLI_IQ_PKT_CONTROL64(q_no));

		reg_val |= CN23XX_PKT_INPUT_CTL_MASK;

		octeon_write_csr64(oct, CN23XX_SLI_IQ_PKT_CONTROL64(q_no),
				   reg_val);

		/* Set WMARK level for triggering PI_INT */
		/* intr_threshold = CN23XX_DEF_IQ_INTR_THRESHOLD & */
		intr_threshold = CFG_GET_IQ_INTR_PKT(cn23xx->conf) &
				 CN23XX_PKT_IN_DONE_WMARK_MASK;

		OCTEON_WRITE64(inst_cnt_reg,
			       (OCTEON_READ64(inst_cnt_reg) &
				~(CN23XX_PKT_IN_DONE_WMARK_MASK <<
				  CN23XX_PKT_IN_DONE_WMARK_BIT_POS)) |
			       (intr_threshold << CN23XX_PKT_IN_DONE_WMARK_BIT_POS));
	}
	return 0;
}

static void cn23xx_pf_setup_global_output_regs(struct octeon_device *oct)
{
	u32 reg_val;
	u32 q_no, ern, srn;
	u64 time_threshold;

	struct octeon_cn23xx_pf *cn23xx = (struct octeon_cn23xx_pf *)oct->chip;

	srn = oct->sriov_info.pf_srn;
	ern = srn + oct->sriov_info.num_pf_rings;

	if (CFG_GET_IS_SLI_BP_ON(cn23xx->conf)) {
		octeon_write_csr64(oct, CN23XX_SLI_OQ_WMARK, 32);
	} else {
		/** Set Output queue watermark to 0 to disable backpressure */
		octeon_write_csr64(oct, CN23XX_SLI_OQ_WMARK, 0);
	}

	for (q_no = srn; q_no < ern; q_no++) {
		reg_val = octeon_read_csr(oct, CN23XX_SLI_OQ_PKT_CONTROL(q_no));

		reg_val &= ~CN23XX_PKT_OUTPUT_CTL_IPTR;

		/* set IPTR & DPTR */
#if (OCTEON_OQ_INFOPTR_MODE)
		reg_val |= CN23XX_PKT_OUTPUT_CTL_IPTR;
#endif
		reg_val |= CN23XX_PKT_OUTPUT_CTL_DPTR;

		/* reset BMODE */
		reg_val &= ~(CN23XX_PKT_OUTPUT_CTL_BMODE);

		/* No Relaxed Ordering, No Snoop, 64-bit Byte swap
		 * for Output Queue ScatterList
		 * reset ROR_P, NSR_P
		 */
		reg_val &= ~(CN23XX_PKT_OUTPUT_CTL_ROR_P);
		reg_val &= ~(CN23XX_PKT_OUTPUT_CTL_NSR_P);

#ifdef __CAVIUM_LITTLE_ENDIAN_BITFIELD
		reg_val &= ~(CN23XX_PKT_OUTPUT_CTL_ES_P);
#else
		reg_val |= (CN23XX_PKT_OUTPUT_CTL_ES_P);
#endif
		/* No Relaxed Ordering, No Snoop, 64-bit Byte swap
		 * for Output Queue Data
		 * reset ROR, NSR
		 */
		reg_val &= ~(CN23XX_PKT_OUTPUT_CTL_ROR);
		reg_val &= ~(CN23XX_PKT_OUTPUT_CTL_NSR);
		/* set the ES bit */
		reg_val |= (CN23XX_PKT_OUTPUT_CTL_ES);

		/* write all the selected settings */
		octeon_write_csr(oct, CN23XX_SLI_OQ_PKT_CONTROL(q_no), reg_val);

		/* Enabling these interrupt in oct->fn_list.enable_interrupt()
		 * routine which called after IOQ init.
		 * Set up interrupt packet and time thresholds
		 * for all the OQs
		 */
		time_threshold = cn23xx_pf_get_oq_ticks(
		    oct, (u32)CFG_GET_OQ_INTR_TIME(cn23xx->conf));

		octeon_write_csr64(oct, CN23XX_SLI_OQ_PKT_INT_LEVELS(q_no),
				   (CFG_GET_OQ_INTR_PKT(cn23xx->conf) |
				    (time_threshold << 32)));
	}

	/** Setting the water mark level for pko back pressure **/
	OCTEON_WRITE64((u8 *)oct->mmio[0].hw_addr + CN23XX_SLI_OQ_WMARK, 0x40);

	/** Disabling setting OQs in reset when ring has no dorebells
	 * enabling this will cause of head of line blocking
	 */
	/* Do it only for pass1.1. and pass1.2 */
	if ((oct->rev_id == OCTEON_CN23XX_REV_1_0) ||
	    (oct->rev_id == OCTEON_CN23XX_REV_1_1))
		OCTEON_WRITE64((u8 *)oct->mmio[0].hw_addr + CN23XX_SLI_GBL_CONTROL,
			       OCTEON_READ64((u8 *)oct->mmio[0].hw_addr +
					     CN23XX_SLI_GBL_CONTROL) | 0x2);

	/** Enable channel-level backpressure */
	if (oct->pf_num)
		OCTEON_WRITE64((u8 *)oct->mmio[0].hw_addr + CN23XX_SLI_OUT_BP_EN2_W1S,
			       0xffffffffffffffffULL);
	else
		OCTEON_WRITE64((u8 *)oct->mmio[0].hw_addr + CN23XX_SLI_OUT_BP_EN_W1S,
			       0xffffffffffffffffULL);
}

static int cn23xx_setup_pf_device_regs(struct octeon_device *oct)
{
	cn23xx_enable_error_reporting(oct);

	/* program the MAC(0..3)_RINFO before setting up input/output regs */
	cn23xx_setup_global_mac_regs(oct);

	if (cn23xx_pf_setup_global_input_regs(oct))
		return -1;

	cn23xx_pf_setup_global_output_regs(oct);

	/* Default error timeout value should be 0x200000 to avoid host hang
	 * when reads invalid register
	 */
	octeon_write_csr64(oct, CN23XX_SLI_WINDOW_CTL,
			   CN23XX_SLI_WINDOW_CTL_DEFAULT);

	/* set SLI_PKT_IN_JABBER to handle large VXLAN packets */
	octeon_write_csr64(oct, CN23XX_SLI_PKT_IN_JABBER,
			   CN23XX_MAX_INPUT_JABBER);
	return 0;
}

static void cn23xx_setup_iq_regs(struct octeon_device *oct, u32 iq_no)
{
	struct octeon_instr_queue *iq = oct->instr_queue[iq_no];
	u64 pkt_in_done;

	iq_no += oct->sriov_info.pf_srn;

	/* Write the start of the input queue's ring and its size  */
	octeon_write_csr64(oct, CN23XX_SLI_IQ_BASE_ADDR64(iq_no),
			   iq->base_addr_dma);
	octeon_write_csr(oct, CN23XX_SLI_IQ_SIZE(iq_no), iq->max_count);

	/* Remember the doorbell & instruction count register addr
	 * for this queue
	 */
	iq->doorbell_reg =
	    (u8 *)oct->mmio[0].hw_addr + CN23XX_SLI_IQ_DOORBELL(iq_no);
	iq->inst_cnt_reg =
	    (u8 *)oct->mmio[0].hw_addr + CN23XX_SLI_IQ_INSTR_COUNT64(iq_no);
	lio_dev_dbg(oct, "InstQ[%d]:dbell reg @ 0x%p instcnt_reg @ 0x%p\n",
		    iq_no, iq->doorbell_reg, iq->inst_cnt_reg);

	/* Store the current instruction counter (used in flush_iq
	 * calculation)
	 */
	pkt_in_done = OCTEON_READ64(iq->inst_cnt_reg);

	if (oct->msix_on) {
		/* Set CINT_ENB to enable IQ interrupt   */
		OCTEON_WRITE64(iq->inst_cnt_reg,
			       (pkt_in_done | CN23XX_INTR_CINT_ENB));
	} else {
		/* Clear the count by writing back what we read, but don't
		 * enable interrupts
		 */
		OCTEON_WRITE64(iq->inst_cnt_reg, pkt_in_done);
	}

	iq->reset_instr_cnt = 0;
}

static void cn23xx_setup_oq_regs(struct octeon_device *oct, u32 oq_no)
{
	u32 reg_val;
	struct octeon_droq *droq = oct->droq[oq_no];
	struct octeon_cn23xx_pf *cn23xx = (struct octeon_cn23xx_pf *)oct->chip;
	u64 time_threshold;
	u64 cnt_threshold;

	oq_no += oct->sriov_info.pf_srn;

	octeon_write_csr64(oct, CN23XX_SLI_OQ_BASE_ADDR64(oq_no),
			   droq->desc_ring_dma);
	octeon_write_csr(oct, CN23XX_SLI_OQ_SIZE(oq_no), droq->max_count);

#if (OCTEON_OQ_INFOPTR_MODE)
	octeon_write_csr(oct, CN23XX_SLI_OQ_BUFF_INFO_SIZE(oq_no),
			 (droq->buffer_size | (OCT_RH_SIZE << 16)));
#else
	octeon_write_csr(oct, CN23XX_SLI_OQ_BUFF_INFO_SIZE(oq_no),
			 droq->buffer_size);
#endif
	/* Get the mapped address of the pkt_sent and pkts_credit regs */
	droq->pkts_sent_reg =
	    (u8 *)oct->mmio[0].hw_addr + CN23XX_SLI_OQ_PKTS_SENT(oq_no);
	droq->pkts_credit_reg =
	    (u8 *)oct->mmio[0].hw_addr + CN23XX_SLI_OQ_PKTS_CREDIT(oq_no);

	if (!oct->msix_on) {
		/* Enable this output queue to generate Packet Timer Interrupt
		 */
		reg_val =
		    octeon_read_csr(oct, CN23XX_SLI_OQ_PKT_CONTROL(oq_no));
		reg_val |= CN23XX_PKT_OUTPUT_CTL_TENB;
		octeon_write_csr(oct, CN23XX_SLI_OQ_PKT_CONTROL(oq_no),
				 reg_val);

		/* Enable this output queue to generate Packet Count Interrupt
		 */
		reg_val =
		    octeon_read_csr(oct, CN23XX_SLI_OQ_PKT_CONTROL(oq_no));
		reg_val |= CN23XX_PKT_OUTPUT_CTL_CENB;
		octeon_write_csr(oct, CN23XX_SLI_OQ_PKT_CONTROL(oq_no),
				 reg_val);
	} else {
		time_threshold = cn23xx_pf_get_oq_ticks(
		    oct, (u32)CFG_GET_OQ_INTR_TIME(cn23xx->conf));
		cnt_threshold = (u32)CFG_GET_OQ_INTR_PKT(cn23xx->conf);

		octeon_write_csr64(
		    oct, CN23XX_SLI_OQ_PKT_INT_LEVELS(oq_no),
		    ((time_threshold << 32 | cnt_threshold)));
	}
}

static void cn23xx_pf_mbox_thread(struct cavium_work *work)
{
	struct cavium_wk *wk = (struct cavium_wk *)work;
	struct octeon_mbox *mbox = (struct octeon_mbox *)wk->ctxptr;
	struct octeon_device *oct = mbox->oct_dev;
	u64 mbox_int_val, val64;
	u32 q_no, i;

	if (oct->rev_id < OCTEON_CN23XX_REV_1_1) {
		/*read and clear by writing 1*/
		mbox_int_val = OCTEON_READ64(mbox->mbox_int_reg);
		OCTEON_WRITE64(mbox->mbox_int_reg, mbox_int_val);

		for (i = 0; i < oct->sriov_info.num_vfs_alloced; i++) {
			q_no = i * oct->sriov_info.rings_per_vf;

			val64 = OCTEON_READ64(oct->mbox[q_no]->mbox_write_reg);

			if (val64 && (val64 != OCTEON_PFVFACK)) {
				if (octeon_mbox_read(oct->mbox[q_no]))
					octeon_mbox_process_message(
					    oct->mbox[q_no]);
			}
		}

#if !defined(__linux_upstream__) && defined(OCT_RHEL_GTE60_AND_LT70)
		cavium_queue_delayed_work(oct->mbox_wq, &wk->work, 10);
#else
		cavium_schedule_delayed_work(&wk->work, 10);
#endif
	} else {
		octeon_mbox_process_message(mbox);
	}
}

static int cn23xx_setup_pf_mbox(struct octeon_device *oct)
{
	struct octeon_mbox *mbox = NULL;
	u16 mac_no = oct->pcie_port;
	u16 pf_num = oct->pf_num;
	u32 q_no, i;

	if (!oct->sriov_info.max_vfs)
		return 0;

#if !defined(__linux_upstream__) && defined(OCT_RHEL_GTE60_AND_LT70)
	{
	char string[32];
	sprintf(string, "mbox-%02x:%02x.%x",
		oct->loc.bus, oct->loc.dev, oct->loc.func);
	oct->mbox_wq = cavium_create_workqueue(string);
	}
#endif

	for (i = 0; i < oct->sriov_info.max_vfs; i++) {
		q_no = i * oct->sriov_info.rings_per_vf;

		mbox = cavium_vmalloc(sizeof(*mbox));
		if (!mbox)
			goto free_mbox;

		cavium_memset(mbox, 0, sizeof(struct octeon_mbox));

		cavium_spin_lock_init(&mbox->lock);

		mbox->oct_dev = oct;

		mbox->q_no = q_no;

		mbox->state = OCTEON_MBOX_STATE_IDLE;

		/* PF mbox interrupt reg */
		mbox->mbox_int_reg = (u8 *)oct->mmio[0].hw_addr +
				     CN23XX_SLI_MAC_PF_MBOX_INT(mac_no, pf_num);

		/* PF writes into SIG0 reg */
		mbox->mbox_write_reg = (u8 *)oct->mmio[0].hw_addr +
				       CN23XX_SLI_PKT_PF_VF_MBOX_SIG(q_no, 0);

		/* PF reads from SIG1 reg */
		mbox->mbox_read_reg = (u8 *)oct->mmio[0].hw_addr +
				      CN23XX_SLI_PKT_PF_VF_MBOX_SIG(q_no, 1);

		/*Mail Box Thread creation*/
		CAVIUM_INIT_DELAYED_WORK(&mbox->mbox_poll_wk.work,
					 cn23xx_pf_mbox_thread);
		mbox->mbox_poll_wk.ctxptr = (void *)mbox;

		oct->mbox[q_no] = mbox;

		OCTEON_WRITE64(mbox->mbox_read_reg, OCTEON_PFVFSIG);
	}

	if (oct->rev_id < OCTEON_CN23XX_REV_1_1)
#if !defined(__linux_upstream__) && defined(OCT_RHEL_GTE60_AND_LT70)
		cavium_queue_delayed_work(oct->mbox_wq,
					  &oct->mbox[0]->mbox_poll_wk.work, 0);
#else
		cavium_schedule_delayed_work(&oct->mbox[0]->mbox_poll_wk.work,
					     0);
#endif

	return 0;

free_mbox:
	while (i) {
		i--;
		cavium_vfree(oct->mbox[i]);
	}

	return 1;
}

static int cn23xx_free_pf_mbox(struct octeon_device *oct)
{
	u32 q_no, i;

	if (!oct->sriov_info.max_vfs)
		return 0;

	for (i = 0; i < oct->sriov_info.max_vfs; i++) {
		q_no = i * oct->sriov_info.rings_per_vf;
		if (oct->mbox[q_no] != NULL) {
			cavium_cancel_delayed_work_sync(
		    		&oct->mbox[q_no]->mbox_poll_wk.work);
			cavium_vfree(oct->mbox[q_no]);
		}
	}

#if !defined(__linux_upstream__) && defined(OCT_RHEL_GTE60_AND_LT70)
	cavium_destroy_workqueue(oct->mbox_wq);
#endif

	return 0;
}

static int cn23xx_enable_io_queues(struct octeon_device *oct)
{
	u32 loop = BUSY_READING_REG_PF_LOOP_COUNT;
	u32 srn, ern, q_no;
	u64 reg_val;

	srn = oct->sriov_info.pf_srn;
	ern = srn + oct->num_iqs;

	for (q_no = srn; q_no < ern; q_no++) {
		/* set the corresponding IQ IS_64B bit */
		if (oct->io_qmask.iq64B & BIT_ULL(q_no - srn)) {
			reg_val = octeon_read_csr64(
			    oct, CN23XX_SLI_IQ_PKT_CONTROL64(q_no));
			reg_val = reg_val | CN23XX_PKT_INPUT_CTL_IS_64B;
			octeon_write_csr64(
			    oct, CN23XX_SLI_IQ_PKT_CONTROL64(q_no), reg_val);
		}

		/* set the corresponding IQ ENB bit */
		if (oct->io_qmask.iq & BIT_ULL(q_no - srn)) {
			/* IOQs are in reset by default in PEM2 mode,
			 * clearing reset bit
			 */
			reg_val = octeon_read_csr64(
			    oct, CN23XX_SLI_IQ_PKT_CONTROL64(q_no));

			if (reg_val & CN23XX_PKT_INPUT_CTL_RST) {
				while ((reg_val & CN23XX_PKT_INPUT_CTL_RST) &&
				       !(reg_val &
					 CN23XX_PKT_INPUT_CTL_QUIET) &&
				       loop) {
					reg_val = octeon_read_csr64(
					    oct,
					    CN23XX_SLI_IQ_PKT_CONTROL64(q_no));
					loop--;
				}
				if (!loop) {
					lio_dev_err(oct,
						    "clearing the reset reg failed or setting the quiet reg failed for qno: %u\n",
						    q_no);
					return -1;
				}
				reg_val = reg_val & ~CN23XX_PKT_INPUT_CTL_RST;
				octeon_write_csr64(
				    oct, CN23XX_SLI_IQ_PKT_CONTROL64(q_no),
				    reg_val);

				reg_val = octeon_read_csr64(
				    oct, CN23XX_SLI_IQ_PKT_CONTROL64(q_no));
				if (reg_val & CN23XX_PKT_INPUT_CTL_RST) {
					lio_dev_err(oct,
						    "clearing the reset failed for qno: %u\n",
						    q_no);
					return -1;
				}
			}
			reg_val = octeon_read_csr64(
			    oct, CN23XX_SLI_IQ_PKT_CONTROL64(q_no));
			reg_val = reg_val | CN23XX_PKT_INPUT_CTL_RING_ENB;
			octeon_write_csr64(
			    oct, CN23XX_SLI_IQ_PKT_CONTROL64(q_no), reg_val);
		}
	}
	for (q_no = srn; q_no < ern; q_no++) {
		u32 reg_val32;
		/* set the corresponding OQ ENB bit */
		if (oct->io_qmask.oq & BIT_ULL(q_no - srn)) {
			reg_val32 = octeon_read_csr(
			    oct, CN23XX_SLI_OQ_PKT_CONTROL(q_no));
			reg_val32 = reg_val32 | CN23XX_PKT_OUTPUT_CTL_RING_ENB;
			octeon_write_csr(oct, CN23XX_SLI_OQ_PKT_CONTROL(q_no),
					 reg_val32);
		}
	}
	return 0;
}

static void cn23xx_disable_io_queues(struct octeon_device *oct)
{
	int loop;
	unsigned int q_no;
	cavium_volatile_u64 d64;
	cavium_volatile_u32 d32;
	u32 srn, ern;

	srn = oct->sriov_info.pf_srn;
	ern = srn + oct->num_iqs;

	/*** Disable Input Queues. ***/
	for (q_no = srn; q_no < ern; q_no++) {
		loop = CAVIUM_TICKS_PER_SEC;

		/* start the Reset for a particular ring */
		cavium_write_once64(d64, octeon_read_csr64(
			   oct, CN23XX_SLI_IQ_PKT_CONTROL64(q_no)));
		cavium_write_once64(d64, cavium_read_once64(d64) &
					(~(CN23XX_PKT_INPUT_CTL_RING_ENB)));
		cavium_write_once64(d64, cavium_read_once64(d64) | CN23XX_PKT_INPUT_CTL_RST);
		octeon_write_csr64(oct, CN23XX_SLI_IQ_PKT_CONTROL64(q_no),
				   cavium_read_once64(d64));

		/* Wait until hardware indicates that the particular IQ
		 * is out of reset.
		 */
		cavium_write_once64(d64, octeon_read_csr64(
					oct, CN23XX_SLI_PKT_IOQ_RING_RST));
		while (!(cavium_read_once64(d64) & BIT_ULL(q_no)) &&
		       loop--) {
			cavium_write_once64(d64, octeon_read_csr64(
					oct, CN23XX_SLI_PKT_IOQ_RING_RST));
			cavium_sleep_timeout(1);
		}

		/* Reset the doorbell register for this Input Queue. */
		octeon_write_csr(oct, CN23XX_SLI_IQ_DOORBELL(q_no), 0xFFFFFFFF);
		while (((octeon_read_csr64(
			    oct, CN23XX_SLI_IQ_DOORBELL(q_no))) != 0ULL) &&
		       loop--) {
			cavium_sleep_timeout(1);
		}
	}

	/*** Disable Output Queues. ***/
	for (q_no = srn; q_no < ern; q_no++) {
		loop = CAVIUM_TICKS_PER_SEC;

		/* Wait until hardware indicates that the particular IQ
		 * is out of reset.It given that SLI_PKT_RING_RST is
		 * common for both IQs and OQs
		 */
		cavium_write_once64(d64, octeon_read_csr64(
					oct, CN23XX_SLI_PKT_IOQ_RING_RST));
		while (!(cavium_read_once64(d64) & BIT_ULL(q_no)) &&
		       loop--) {
			cavium_write_once64(d64, octeon_read_csr64(
					oct, CN23XX_SLI_PKT_IOQ_RING_RST));
			cavium_sleep_timeout(1);
			loop--;
		}

		/* Reset the doorbell register for this Output Queue. */
		octeon_write_csr(oct, CN23XX_SLI_OQ_PKTS_CREDIT(q_no),
				 0xFFFFFFFF);
		while (((octeon_read_csr64(
			    oct, CN23XX_SLI_OQ_PKTS_CREDIT(q_no))) != 0ULL) &&
		       loop--) {
			cavium_sleep_timeout(1);
		}

		/* clear the SLI_PKT(0..63)_CNTS[CNT] reg value */
		cavium_write_once(d32, octeon_read_csr(
					oct, CN23XX_SLI_OQ_PKTS_SENT(q_no)));
		octeon_write_csr(oct, CN23XX_SLI_OQ_PKTS_SENT(q_no),
				 cavium_read_once(d32));
	}
}

static u64 cn23xx_pf_msix_interrupt_handler(void *dev)
{
	struct octeon_ioq_vector *ioq_vector = (struct octeon_ioq_vector *)dev;
	struct octeon_device *oct = ioq_vector->oct_dev;
	u64 pkts_sent;
	u64 ret = 0;
	struct octeon_droq *droq = oct->droq[ioq_vector->droq_index];

	lio_dev_dbg(oct, "In %s octeon_dev @ %p\n", __CVM_FUNCTION__, oct);

	if (!droq) {
		lio_dev_err(oct, "23XX bringup FIXME: oct pfnum:%d ioq_vector->ioq_num :%d droq is NULL\n",
			    oct->pf_num, ioq_vector->ioq_num);
		return 0;
	}

	pkts_sent = OCTEON_READ64(droq->pkts_sent_reg);

	/* If our device has interrupted, then proceed. Also check
	 * for all f's if interrupt was triggered on an error
	 * and the PCI read fails.
	 */
	if (!pkts_sent || (pkts_sent == 0xFFFFFFFFFFFFFFFFULL))
		return ret;

	/* Write count reg in sli_pkt_cnts to clear these int.*/
	if ((pkts_sent & CN23XX_INTR_PO_INT) ||
	    (pkts_sent & CN23XX_INTR_PI_INT)) {
		if (pkts_sent & CN23XX_INTR_PO_INT)
			ret |= MSIX_PO_INT;
	}

	if (pkts_sent & CN23XX_INTR_PI_INT)
		/* We will clear the count when we update the read_index. */
		ret |= MSIX_PI_INT;

	/* Never need to handle msix mbox intr for pf. They arrive on the last
	 * msix
	 */
	return ret;
}

static void cn23xx_handle_pf_mbox_intr(struct octeon_device *oct)
{
	struct cavium_delayed_work *work;
	u64 mbox_int_val;
	u32 i, q_no;

	mbox_int_val = OCTEON_READ64(oct->mbox[0]->mbox_int_reg);

	for (i = 0; i < oct->sriov_info.num_vfs_alloced; i++) {
		q_no = i * oct->sriov_info.rings_per_vf;

		if (mbox_int_val & BIT_ULL(q_no)) {
			OCTEON_WRITE64(oct->mbox[0]->mbox_int_reg,
				       BIT_ULL(q_no));
			if (octeon_mbox_read(oct->mbox[q_no])) {
				work = &oct->mbox[q_no]->mbox_poll_wk.work;
#if !defined(__linux_upstream__) && defined(OCT_RHEL_GTE60_AND_LT70)
				cavium_queue_delayed_work(oct->mbox_wq, work, 0);
#else
				cavium_schedule_delayed_work(work,
							     0);
#endif
			}
		}
	}
}

static cvm_intr_return_t cn23xx_interrupt_handler(void *dev)
{
	struct octeon_device *oct = (struct octeon_device *)dev;
	struct octeon_cn23xx_pf *cn23xx = (struct octeon_cn23xx_pf *)oct->chip;
	u64 intr64;

	lio_dev_dbg(oct, "In %s octeon_dev @ %p\n", __CVM_FUNCTION__, oct);
	intr64 = OCTEON_READ64(cn23xx->intr_sum_reg64);

	oct->int_status = 0;

	if (intr64 & CN23XX_INTR_ERR)
		lio_dev_err(oct, "OCTEON[%d]: Error Intr: 0x%016llx\n",
			    oct->octeon_id, CVM_CAST64(intr64));

	/* When VFs write into MBOX_SIG2 reg,these intr is set in PF */
	if (intr64 & CN23XX_INTR_VF_MBOX)
		cn23xx_handle_pf_mbox_intr(oct);

	if (oct->msix_on != LIO_FLAG_MSIX_ENABLED) {
		if (intr64 & CN23XX_INTR_PKT_DATA)
			oct->int_status |= OCT_DEV_INTR_PKT_DATA;
	}

	if (intr64 & (CN23XX_INTR_DMA0_FORCE))
		oct->int_status |= OCT_DEV_INTR_DMA0_FORCE;
	if (intr64 & (CN23XX_INTR_DMA1_FORCE))
		oct->int_status |= OCT_DEV_INTR_DMA1_FORCE;

	/* Clear the current interrupts */
	OCTEON_WRITE64(cn23xx->intr_sum_reg64, intr64);

	return CVM_INTR_HANDLED;
}
static void cn23xx_reinit_regs(struct octeon_device *oct)
{
	u32 i;

	/* TODO: Need to wait for quiet bit to set if RST bit is set
	 * RST bit may set, if it receives an FLR or pkt error
	 */
	lio_dev_dbg(oct, "-- %s =--\n", __CVM_FUNCTION__);

	for (i = 0; i < MAX_POSSIBLE_OCTEON_INSTR_QUEUES; i++) {
		if (!(oct->io_qmask.iq & BIT_ULL(i)))
			continue;
		oct->fn_list.setup_iq_regs(oct, i);
	}

	for (i = 0; i < MAX_POSSIBLE_OCTEON_OUTPUT_QUEUES; i++) {
		if (!(oct->io_qmask.oq & BIT_ULL(i)))
			continue;
		oct->fn_list.setup_oq_regs(oct, i);
	}

	oct->fn_list.setup_device_regs(oct);

	oct->fn_list.enable_interrupt(oct, OCTEON_ALL_INTR);

	oct->fn_list.enable_io_queues(oct);

	for (i = 0; i < MAX_POSSIBLE_OCTEON_OUTPUT_QUEUES; i++) {
		if (!(oct->io_qmask.oq & BIT_ULL(i)))
			continue;
		OCTEON_WRITE32(oct->droq[i]->pkts_credit_reg,
			       oct->droq[i]->max_count);
	}
}

static void cn23xx_bar1_idx_setup(struct octeon_device *oct, u64 core_addr,
				  u32 idx, int valid)
{
	cavium_volatile_u64 bar1;
	u64 reg_adr;

	if (!valid) {
		reg_adr = lio_pci_readq(
			oct, CN23XX_PEM_BAR1_INDEX_REG(oct->pcie_port, idx));
		cavium_write_once64(bar1, reg_adr);
		lio_pci_writeq(oct, (cavium_read_once64(bar1) & 0xFFFFFFFEULL),
			       CN23XX_PEM_BAR1_INDEX_REG(oct->pcie_port, idx));
		reg_adr = lio_pci_readq(
			oct, CN23XX_PEM_BAR1_INDEX_REG(oct->pcie_port, idx));
		cavium_write_once64(bar1, reg_adr);
		return;
	}

	/*  The PEM(0..3)_BAR1_INDEX(0..15)[ADDR_IDX]<23:4> stores
	 *  bits <41:22> of the Core Addr
	 */
	lio_pci_writeq(oct, (((core_addr >> 22) << 4) | PCI_BAR1_MASK),
		       CN23XX_PEM_BAR1_INDEX_REG(oct->pcie_port, idx));

	cavium_write_once64(bar1, lio_pci_readq(
		   oct, CN23XX_PEM_BAR1_INDEX_REG(oct->pcie_port, idx)));
}

static void cn23xx_bar1_idx_write(struct octeon_device *oct, u32 idx, u32 mask)
{
	lio_pci_writeq(oct, mask,
		       CN23XX_PEM_BAR1_INDEX_REG(oct->pcie_port, idx));
}

static u32 cn23xx_bar1_idx_read(struct octeon_device *oct, u32 idx)
{
	return (u32)lio_pci_readq(
	    oct, CN23XX_PEM_BAR1_INDEX_REG(oct->pcie_port, idx));
}

/* always call with lock held */
static u32 cn23xx_update_read_index(struct octeon_instr_queue *iq)
{
	u32 new_idx;
	u32 last_done;
	u32 pkt_in_done = OCTEON_READ32(iq->inst_cnt_reg);

	last_done = pkt_in_done - iq->pkt_in_done;
	iq->pkt_in_done = pkt_in_done;

	/* Modulo of the new index with the IQ size will give us
	 * the new index.  The iq->reset_instr_cnt is always zero for
	 * cn23xx, so no extra adjustments are needed.
	 */
	new_idx = (iq->octeon_read_index +
		   (u32)(last_done & CN23XX_PKT_IN_DONE_CNT_MASK)) %
		  iq->max_count;

	return new_idx;
}

static void cn23xx_enable_pf_interrupt(struct octeon_device *oct, u8 intr_flag)
{
	struct octeon_cn23xx_pf *cn23xx = (struct octeon_cn23xx_pf *)oct->chip;
	u64 intr_val = 0;

	/*  Divide the single write to multiple writes based on the flag. */
	/* Enable Interrupt */
	if (intr_flag == OCTEON_ALL_INTR) {
		OCTEON_WRITE64(cn23xx->intr_enb_reg64, cn23xx->intr_mask64);
	} else if (intr_flag & OCTEON_OUTPUT_INTR) {
		intr_val = OCTEON_READ64(cn23xx->intr_enb_reg64);
		intr_val |= CN23XX_INTR_PKT_DATA;
		OCTEON_WRITE64(cn23xx->intr_enb_reg64, intr_val);
	} else if ((intr_flag & OCTEON_MBOX_INTR) &&
		   (oct->sriov_info.max_vfs > 0)) {
		if (oct->rev_id >= OCTEON_CN23XX_REV_1_1) {
			intr_val = OCTEON_READ64(cn23xx->intr_enb_reg64);
			intr_val |= CN23XX_INTR_VF_MBOX;
			OCTEON_WRITE64(cn23xx->intr_enb_reg64, intr_val);
		}
	}
}

static void cn23xx_disable_pf_interrupt(struct octeon_device *oct, u8 intr_flag)
{
	struct octeon_cn23xx_pf *cn23xx = (struct octeon_cn23xx_pf *)oct->chip;
	u64 intr_val = 0;

	/* Disable Interrupts */
	if (intr_flag == OCTEON_ALL_INTR) {
		OCTEON_WRITE64(cn23xx->intr_enb_reg64, 0);
	} else if (intr_flag & OCTEON_OUTPUT_INTR) {
		intr_val = OCTEON_READ64(cn23xx->intr_enb_reg64);
		intr_val &= ~CN23XX_INTR_PKT_DATA;
		OCTEON_WRITE64(cn23xx->intr_enb_reg64, intr_val);
	} else if ((intr_flag & OCTEON_MBOX_INTR) &&
		   (oct->sriov_info.max_vfs > 0)) {
		if (oct->rev_id >= OCTEON_CN23XX_REV_1_1) {
			intr_val = OCTEON_READ64(cn23xx->intr_enb_reg64);
			intr_val &= ~CN23XX_INTR_VF_MBOX;
			OCTEON_WRITE64(cn23xx->intr_enb_reg64, intr_val);
		}
	}
}

static void cn23xx_get_pcie_qlmport(struct octeon_device *oct)
{
	oct->pcie_port = (octeon_read_csr(oct, CN23XX_SLI_MAC_NUMBER)) & 0xff;

	lio_dev_dbg(oct, "OCTEON: CN23xx uses PCIE Port %d\n",
		    oct->pcie_port);
}

static int cn23xx_get_pf_num(struct octeon_device *oct)
{
	u32 fdl_bit = 0;
	u64 pkt0_in_ctl, d64;
	int pfnum, mac, trs, ret;

	ret = 0;

	/** Read Function Dependency Link reg to get the function number */
	if (OCTEON_READ_PCI_CONFIG(oct, CN23XX_PCIE_SRIOV_FDL,
				   &fdl_bit) == 0) {
		oct->pf_num = ((fdl_bit >> CN23XX_PCIE_SRIOV_FDL_BIT_POS) &
			       CN23XX_PCIE_SRIOV_FDL_MASK);
	} else {
		ret = EINVAL;

		/* Under some virtual environments, extended PCI regs are
		 * inaccessible, in which case the above read will have failed.
		 * In this case, read the PF number from the
		 * SLI_PKT0_INPUT_CONTROL reg (written by f/w)
		 */
		pkt0_in_ctl = octeon_read_csr64(oct,
						CN23XX_SLI_IQ_PKT_CONTROL64(0));
		pfnum = (pkt0_in_ctl >> CN23XX_PKT_INPUT_CTL_PF_NUM_POS) &
			CN23XX_PKT_INPUT_CTL_PF_NUM_MASK;
		mac = (octeon_read_csr(oct, CN23XX_SLI_MAC_NUMBER)) & 0xff;

		/* validate PF num by reading RINFO; f/w writes RINFO.trs == 1*/
		d64 = octeon_read_csr64(oct,
					CN23XX_SLI_PKT_MAC_RINFO64(mac, pfnum));
		trs = (int)(d64 >> CN23XX_PKT_MAC_CTL_RINFO_TRS_BIT_POS) & 0xff;
		if (trs == 1) {
			lio_dev_err(oct,
				    "OCTEON: error reading PCI cfg space pfnum, re-read %u\n",
				    pfnum);
			oct->pf_num = (u16)pfnum;
			ret = 0;
		} else {
			lio_dev_err(oct,
				    "OCTEON: error reading PCI cfg space pfnum; could not ascertain PF number\n");
		}
	}

	return ret;
}

static void cn23xx_setup_reg_address(struct octeon_device *oct)
{
	u8 cavium_iomem *bar0_pciaddr = oct->mmio[0].hw_addr;
	struct octeon_cn23xx_pf *cn23xx = (struct octeon_cn23xx_pf *)oct->chip;

	oct->reg_list.pci_win_wr_addr_hi =
	    (u32 cavium_iomem *)(bar0_pciaddr + CN23XX_WIN_WR_ADDR_HI);
	oct->reg_list.pci_win_wr_addr_lo =
	    (u32 cavium_iomem *)(bar0_pciaddr + CN23XX_WIN_WR_ADDR_LO);
	oct->reg_list.pci_win_wr_addr =
	    (u64 cavium_iomem *)(bar0_pciaddr + CN23XX_WIN_WR_ADDR64);

	oct->reg_list.pci_win_rd_addr_hi =
	    (u32 cavium_iomem *)(bar0_pciaddr + CN23XX_WIN_RD_ADDR_HI);
	oct->reg_list.pci_win_rd_addr_lo =
	    (u32 cavium_iomem *)(bar0_pciaddr + CN23XX_WIN_RD_ADDR_LO);
	oct->reg_list.pci_win_rd_addr =
	    (u64 cavium_iomem *)(bar0_pciaddr + CN23XX_WIN_RD_ADDR64);

	oct->reg_list.pci_win_wr_data_hi =
	    (u32 cavium_iomem *)(bar0_pciaddr + CN23XX_WIN_WR_DATA_HI);
	oct->reg_list.pci_win_wr_data_lo =
	    (u32 cavium_iomem *)(bar0_pciaddr + CN23XX_WIN_WR_DATA_LO);
	oct->reg_list.pci_win_wr_data =
	    (u64 cavium_iomem *)(bar0_pciaddr + CN23XX_WIN_WR_DATA64);

	oct->reg_list.pci_win_rd_data_hi =
	    (u32 cavium_iomem *)(bar0_pciaddr + CN23XX_WIN_RD_DATA_HI);
	oct->reg_list.pci_win_rd_data_lo =
	    (u32 cavium_iomem *)(bar0_pciaddr + CN23XX_WIN_RD_DATA_LO);
	oct->reg_list.pci_win_rd_data =
	    (u64 cavium_iomem *)(bar0_pciaddr + CN23XX_WIN_RD_DATA64);

	cn23xx_get_pcie_qlmport(oct);

	cn23xx->intr_mask64 = CN23XX_INTR_MASK;
	if (!oct->msix_on)
		cn23xx->intr_mask64 |= CN23XX_INTR_PKT_TIME;
	if (oct->rev_id >= OCTEON_CN23XX_REV_1_1)
		cn23xx->intr_mask64 |= CN23XX_INTR_VF_MBOX;

	cn23xx->intr_sum_reg64 =
	    bar0_pciaddr +
	    CN23XX_SLI_MAC_PF_INT_SUM64(oct->pcie_port, oct->pf_num);
	cn23xx->intr_enb_reg64 =
	    bar0_pciaddr +
	    CN23XX_SLI_MAC_PF_INT_ENB64(oct->pcie_port, oct->pf_num);
}
int cn23xx_sriov_config(struct octeon_device *oct)
{
	struct octeon_cn23xx_pf *cn23xx = (struct octeon_cn23xx_pf *)oct->chip;
	u32 num_pf_rings, total_rings, max_rings, rings_per_vf, max_vfs;
	u32 max_possible_vfs;

	cn23xx->conf =
	    (struct octeon_config *)oct_get_config_info(oct, LIO_23XX);

	switch (oct->rev_id) {
	case OCTEON_CN23XX_REV_1_0:
		max_rings = CN23XX_MAX_RINGS_PER_PF_PASS_1_0;
		max_possible_vfs = CN23XX_MAX_VFS_PER_PF_PASS_1_0;
		break;
	case OCTEON_CN23XX_REV_1_1:
		max_rings = CN23XX_MAX_RINGS_PER_PF_PASS_1_1;
		max_possible_vfs = CN23XX_MAX_VFS_PER_PF_PASS_1_1;
		break;
	default:
		max_rings = CN23XX_MAX_RINGS_PER_PF;
		max_possible_vfs = CN23XX_MAX_VFS_PER_PF;
		break;
	}

#ifdef CONFIG_PCI_IOV
	rings_per_vf = oct->sriov_info.rings_per_vf;
	if ((rings_per_vf > CN23XX_MAX_RINGS_PER_VF) ||
	    (rings_per_vf & (rings_per_vf - 1))) {
		rings_per_vf = 1;
		lio_dev_warn(oct,
			 "Invalid num_queues_per_vf:%u requested. Using default num_queues_per_vf:%u\n",
			 oct->sriov_info.rings_per_vf,
			 rings_per_vf);
	}
#else
	rings_per_vf = 0;
#endif

	if (oct->sriov_info.num_pf_rings) {
		num_pf_rings = oct->sriov_info.num_pf_rings;
		if (num_pf_rings + rings_per_vf > max_rings) {
			num_pf_rings = cavium_min_t(u32, cavium_get_present_cpu_count(),
					     (max_rings - rings_per_vf));
			lio_dev_warn(oct,
				 "num_queues_per_pf requested %u is more than available rings (%u). Reducing to %u\n",
				 oct->sriov_info.num_pf_rings,
				 max_rings - rings_per_vf,
				 num_pf_rings);
		}
	} else {
		num_pf_rings = cavium_min_t(u32, cavium_get_present_cpu_count(),
				     (max_rings - rings_per_vf));
	}

	if (rings_per_vf) {
		max_vfs = (max_rings - num_pf_rings) / rings_per_vf;
		max_vfs = cavium_min_t(u32, max_vfs, max_possible_vfs);
	} else {
		max_vfs = 0;
	}

	total_rings = num_pf_rings + (max_vfs * rings_per_vf);

	oct->sriov_info.trs = total_rings;
	oct->sriov_info.max_vfs = max_vfs;
	oct->sriov_info.rings_per_vf = rings_per_vf;
	oct->sriov_info.pf_srn = total_rings - num_pf_rings;
	oct->sriov_info.num_pf_rings = num_pf_rings;
	lio_dev_dbg(oct, "trs:%d max_vfs:%d rings_per_vf:%d pf_srn:%d num_pf_rings:%d\n",
		    oct->sriov_info.trs, oct->sriov_info.max_vfs,
		    oct->sriov_info.rings_per_vf, oct->sriov_info.pf_srn,
		    oct->sriov_info.num_pf_rings);

	oct->sriov_info.sriov_enabled = 0;

	return 0;
}

int setup_cn23xx_octeon_pf_device(struct octeon_device *oct)
{
	u32 data32;
	u64 BAR0, BAR1;

	OCTEON_READ_PCI_CONFIG(oct, PCI_BASE_ADDRESS_0, &data32);
	BAR0 = (u64)(data32 & ~0xf);
	OCTEON_READ_PCI_CONFIG(oct, PCI_BASE_ADDRESS_1, &data32);
	BAR0 |= ((u64)data32 << 32);
	OCTEON_READ_PCI_CONFIG(oct, PCI_BASE_ADDRESS_2, &data32);
	BAR1 = (u64)(data32 & ~0xf);
	OCTEON_READ_PCI_CONFIG(oct, PCI_BASE_ADDRESS_3, &data32);
	BAR1 |= ((u64)data32 << 32);

	if (!BAR0 || !BAR1) {
		if (!BAR0)
			lio_dev_err(oct, "device BAR0 unassigned\n");
		if (!BAR1)
			lio_dev_err(oct, "device BAR1 unassigned\n");
		return 1;
	}

	if (octeon_map_pci_barx(oct, 0, 0))
		return 1;

	if (octeon_map_pci_barx(oct, 1, MAX_BAR1_IOREMAP_SIZE)) {
		lio_dev_err(oct, "%s CN23XX BAR1 map failed\n",
			    __CVM_FUNCTION__);
		octeon_unmap_pci_barx(oct, 0);
		return 1;
	}

	if (cn23xx_get_pf_num(oct) != 0)
		return 1;

	if (cn23xx_sriov_config(oct)) {
		octeon_unmap_pci_barx(oct, 0);
		octeon_unmap_pci_barx(oct, 1);
		return 1;
	}

	octeon_write_csr64(oct, CN23XX_SLI_MAC_CREDIT_CNT, 0x3F802080802080ULL);

	oct->fn_list.setup_iq_regs = cn23xx_setup_iq_regs;
	oct->fn_list.setup_oq_regs = cn23xx_setup_oq_regs;
	oct->fn_list.setup_mbox = cn23xx_setup_pf_mbox;
	oct->fn_list.free_mbox = cn23xx_free_pf_mbox;

	oct->fn_list.process_interrupt_regs = cn23xx_interrupt_handler;
	oct->fn_list.msix_interrupt_handler = cn23xx_pf_msix_interrupt_handler;

	oct->fn_list.soft_reset = cn23xx_pf_soft_reset;
	oct->fn_list.setup_device_regs = cn23xx_setup_pf_device_regs;
	oct->fn_list.reinit_regs = cn23xx_reinit_regs;
	oct->fn_list.update_iq_read_idx = cn23xx_update_read_index;

	oct->fn_list.bar1_idx_setup = cn23xx_bar1_idx_setup;
	oct->fn_list.bar1_idx_write = cn23xx_bar1_idx_write;
	oct->fn_list.bar1_idx_read = cn23xx_bar1_idx_read;

	oct->fn_list.enable_interrupt = cn23xx_enable_pf_interrupt;
	oct->fn_list.disable_interrupt = cn23xx_disable_pf_interrupt;

	oct->fn_list.enable_io_queues = cn23xx_enable_io_queues;
	oct->fn_list.disable_io_queues = cn23xx_disable_io_queues;

	cn23xx_setup_reg_address(oct);

	oct->coproc_clock_rate = 1000000ULL * cn23xx_coprocessor_clock(oct);

	oct->core_mask = lio_pci_readq(oct, CN23XX_CIU3_FUSE);

	return 0;
}

int validate_cn23xx_pf_config_info(struct octeon_device *oct,
				   struct octeon_config *conf23xx)
{
	if (CFG_GET_IQ_MAX_Q(conf23xx) > CN23XX_MAX_INPUT_QUEUES) {
		lio_dev_err(oct, "%s: Num IQ (%d) exceeds Max (%d)\n",
			    __CVM_FUNCTION__, CFG_GET_IQ_MAX_Q(conf23xx),
			    CN23XX_MAX_INPUT_QUEUES);
		return 1;
	}

	if (CFG_GET_OQ_MAX_Q(conf23xx) > CN23XX_MAX_OUTPUT_QUEUES) {
		lio_dev_err(oct, "%s: Num OQ (%d) exceeds Max (%d)\n",
			    __CVM_FUNCTION__, CFG_GET_OQ_MAX_Q(conf23xx),
			    CN23XX_MAX_OUTPUT_QUEUES);
		return 1;
	}

	if (CFG_GET_IQ_INSTR_TYPE(conf23xx) != OCTEON_32BYTE_INSTR &&
	    CFG_GET_IQ_INSTR_TYPE(conf23xx) != OCTEON_64BYTE_INSTR) {
		lio_dev_err(oct, "%s: Invalid instr type for IQ\n",
			    __CVM_FUNCTION__);
		return 1;
	}

	if ((CFG_GET_OQ_INFO_PTR(conf23xx) != OCTEON_OQ_INFOPTR_MODE) ||
	    !(CFG_GET_OQ_REFILL_THRESHOLD(conf23xx))) {
		lio_dev_err(oct, "%s: Invalid parameter for OQ\n",
			     __CVM_FUNCTION__);
		return 1;
	}

	if (!(CFG_GET_OQ_INTR_TIME(conf23xx))) {
		lio_dev_err(oct, "%s: Invalid parameter for OQ\n",
			    __CVM_FUNCTION__);
		return 1;
	}

	return 0;
}

void cn23xx_dump_iq_regs(struct octeon_device *oct)
{
	u32 regval, q_no;

	lio_dev_dbg(oct, "SLI_IQ_DOORBELL_0 [0x%x]: 0x%016llx\n",
		    CN23XX_SLI_IQ_DOORBELL(0),
		    CVM_CAST64(octeon_read_csr64
			       (oct, CN23XX_SLI_IQ_DOORBELL(0))));

	lio_dev_dbg(oct, "SLI_IQ_BASEADDR_0 [0x%x]: 0x%016llx\n",
		    CN23XX_SLI_IQ_BASE_ADDR64(0),
		    CVM_CAST64(octeon_read_csr64
			       (oct, CN23XX_SLI_IQ_BASE_ADDR64(0))));

	lio_dev_dbg(oct, "SLI_IQ_FIFO_RSIZE_0 [0x%x]: 0x%016llx\n",
		    CN23XX_SLI_IQ_SIZE(0),
		    CVM_CAST64(octeon_read_csr64(oct, CN23XX_SLI_IQ_SIZE(0))));

	lio_dev_dbg(oct, "SLI_CTL_STATUS [0x%x]: 0x%016llx\n",
		    CN23XX_SLI_CTL_STATUS,
		    CVM_CAST64(octeon_read_csr64(oct, CN23XX_SLI_CTL_STATUS)));

	for (q_no = 0; q_no < CN23XX_MAX_INPUT_QUEUES; q_no++) {
		lio_dev_dbg(oct, "SLI_PKT[%d]_INPUT_CTL [0x%x]: 0x%016llx\n",
			    q_no, CN23XX_SLI_IQ_PKT_CONTROL64(q_no),
			    CVM_CAST64(octeon_read_csr64
				       (oct, CN23XX_SLI_IQ_PKT_CONTROL64(q_no))));
	}

	OCTEON_READ_PCI_CONFIG(oct, CN23XX_CONFIG_PCIE_DEVCTL, &regval);
	lio_dev_dbg(oct, "Config DevCtl [0x%x]: 0x%08x\n",
		    CN23XX_CONFIG_PCIE_DEVCTL, regval);

	lio_dev_dbg(oct, "SLI_PRT[%d]_CFG [0x%llx]: 0x%016llx\n",
		    oct->pcie_port, CN23XX_DPI_SLI_PRTX_CFG(oct->pcie_port),
		    CVM_CAST64(lio_pci_readq(
			oct, CN23XX_DPI_SLI_PRTX_CFG(oct->pcie_port))));

	lio_dev_dbg(oct, "SLI_S2M_PORT[%d]_CTL [0x%x]: 0x%016llx\n",
		    oct->pcie_port, CN23XX_SLI_S2M_PORTX_CTL(oct->pcie_port),
		    CVM_CAST64(octeon_read_csr64(
			oct, CN23XX_SLI_S2M_PORTX_CTL(oct->pcie_port))));
}

int cn23xx_fw_loaded(struct octeon_device *oct)
{
	u64 val;

	val = octeon_read_csr64(oct, CN23XX_SLI_SCRATCH2);
	return (val >> SCR2_BIT_FW_LOADED) & 1ULL;
}

void cn23xx_tell_vfs_cores_crashed(struct octeon_device *oct)
{
	int vf_idx;
	struct octeon_mbox_cmd mbox_cmd;

	if (!oct)
		return;

	mbox_cmd.msg.u64 = 0;
	mbox_cmd.msg.s.type = OCTEON_MBOX_REQUEST;
	mbox_cmd.msg.s.resp_needed = 0;
	mbox_cmd.msg.s.cmd = OCTEON_CORES_CRASHED;
	mbox_cmd.msg.s.len = 1;
	mbox_cmd.recv_len = 0;
	mbox_cmd.recv_status = 0;
	mbox_cmd.fn = NULL;
	mbox_cmd.fn_arg = 0UL;

	for (vf_idx = 0; vf_idx < MAX_POSSIBLE_VFS; vf_idx++) {
		if (oct->sriov_info.vf_drv_loaded_mask & (1ULL << vf_idx)) {
			mbox_cmd.q_no = vf_idx * oct->sriov_info.rings_per_vf;
			octeon_mbox_write(oct, &mbox_cmd);
		}
	}
}

void cn23xx_tell_vf_its_macaddr_changed(struct octeon_device *oct, int vfidx,
					u8 *mac)
{
	if (oct->sriov_info.vf_drv_loaded_mask & BIT_ULL(vfidx)) {
		struct octeon_mbox_cmd mbox_cmd;

		mbox_cmd.msg.u64 = 0;
		mbox_cmd.msg.s.type = OCTEON_MBOX_REQUEST;
		mbox_cmd.msg.s.resp_needed = 0;
		mbox_cmd.msg.s.cmd = OCTEON_PF_CHANGED_VF_MACADDR;
		mbox_cmd.msg.s.len = 1;
		mbox_cmd.recv_len = 0;
		mbox_cmd.recv_status = 0;
		mbox_cmd.fn = NULL;
		mbox_cmd.fn_arg = 0;
		cavium_memcpy(mbox_cmd.msg.s.params, mac, 6);
		mbox_cmd.q_no = vfidx * oct->sriov_info.rings_per_vf;
		octeon_mbox_write(oct, &mbox_cmd);
	}
}


void cn23xx_tell_vf_its_vlan_was_set_or_cleared(struct octeon_device *oct,
						int vfidx, bool vlan_was_set)
{
	if (oct->sriov_info.vf_drv_loaded_mask & (1ULL << vfidx)) {
		struct octeon_mbox_cmd mbox_cmd;

		mbox_cmd.msg.u64 = 0;
		mbox_cmd.msg.s.type = OCTEON_MBOX_REQUEST;
		mbox_cmd.msg.s.resp_needed = 0;
		mbox_cmd.msg.s.cmd = OCTEON_PF_SET_OR_CLEARED_VF_VLAN;
		mbox_cmd.msg.s.len = 1;
		mbox_cmd.msg.s.params[0] = vlan_was_set;
		mbox_cmd.recv_len = 0;
		mbox_cmd.recv_status = 0;
		mbox_cmd.fn = NULL;
		mbox_cmd.fn_arg = 0UL;

		mbox_cmd.q_no = vfidx * oct->sriov_info.rings_per_vf;
		octeon_mbox_write(oct, &mbox_cmd);
	}
}

static void
cn23xx_get_vf_stats_callback(struct octeon_device *oct,
			     struct octeon_mbox_cmd *cmd, void *arg)
{
	struct oct_vf_stats_ctx *ctx = arg;

	cavium_memcpy(ctx->stats, cmd->data, sizeof(struct oct_vf_stats));
	cavium_atomic_set(&ctx->status, 1);
}

int cn23xx_get_vf_stats(struct octeon_device *oct, int vfidx,
			struct oct_vf_stats *stats)
{
	uint32_t timeout = CAVIUM_TICKS_PER_SEC; // 1sec
	struct octeon_mbox_cmd mbox_cmd;
	struct oct_vf_stats_ctx ctx;
	uint32_t count = 0, ret;

	if (!(oct->sriov_info.vf_drv_loaded_mask & (1ULL << vfidx)))
		return -1;

	if (sizeof(struct oct_vf_stats) > sizeof(mbox_cmd.data))
		return -1;

	mbox_cmd.msg.u64 = 0;
	mbox_cmd.msg.s.type = OCTEON_MBOX_REQUEST;
	mbox_cmd.msg.s.resp_needed = 1;
	mbox_cmd.msg.s.cmd = OCTEON_GET_VF_STATS;
	mbox_cmd.msg.s.len = 1;
	mbox_cmd.q_no = vfidx * oct->sriov_info.rings_per_vf;
	mbox_cmd.recv_len = 0;
	mbox_cmd.recv_status = 0;
	mbox_cmd.fn = (octeon_mbox_callback_t)cn23xx_get_vf_stats_callback;
	ctx.stats = stats;
	cavium_atomic_set(&ctx.status, 0);
	mbox_cmd.fn_arg = (void *)&ctx;
	cavium_memset(mbox_cmd.data, 0, sizeof(mbox_cmd.data));
	octeon_mbox_write(oct, &mbox_cmd);

	do {
		cavium_sleep_timeout(1);
	} while ((cavium_atomic_read(&ctx.status) == 0) && (count++ < timeout));

	ret = cavium_atomic_read(&ctx.status);
	if (ret == 0) {
		octeon_mbox_cancel(oct, 0);
		lio_dev_err(oct, "Unable to get stats from VF-%d, timedout\n",
			    vfidx);
		return -1;
	}

	return 0;
}
