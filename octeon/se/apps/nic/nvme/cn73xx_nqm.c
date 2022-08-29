/*
 * Author: Cavium, Inc.
 *
 * Copyright (c) 2015 Cavium, Inc. All rights reserved.
 *
 * Contact: support@cavium.com
 *          Please include "LiquidIO" in the subject.
 *
 * This file, which is part of the LiquidIO SDK from Cavium Inc.,
 * contains proprietary and confidential information of Cavium Inc.
 * and in some cases its suppliers. 
 *
 * Any licensed reproduction, distribution, modification, or other use of
 * this file or the confidential information or patented inventions
 * embodied in this file is subject to your license agreement with Cavium
 * Inc. Unless you and Cavium Inc. have agreed otherwise in writing, the
 * applicable license terms "OCTEON SDK License Type 5" can be found under
 * the directory: $LIQUIDIO_ROOT/licenses/
 *
 * All other use and disclosure is prohibited.
 *
 * TO THE MAXIMUM EXTENT PERMITTED BY LAW, THE SOFTWARE IS PROVIDED "AS IS"
 * AND WITH ALL FAULTS AND CAVIUM INC. MAKES NO PROMISES, REPRESENTATIONS
 * OR WARRANTIES, EITHER EXPRESS, IMPLIED, STATUTORY, OR OTHERWISE, WITH
 * RESPECT TO THE SOFTWARE, INCLUDING ITS CONDITION, ITS CONFORMITY TO ANY
 * REPRESENTATION OR DESCRIPTION, OR THE EXISTENCE OF ANY LATENT OR PATENT
 * DEFECTS, AND CAVIUM SPECIFICALLY DISCLAIMS ALL IMPLIED (IF ANY)
 * WARRANTIES OF TITLE, MERCHANTABILITY, NONINFRINGEMENT, FITNESS FOR A
 * PARTICULAR PURPOSE, LACK OF VIRUSES, ACCURACY OR COMPLETENESS, QUIET
 * ENJOYMENT, QUIET POSSESSION OR CORRESPONDENCE TO DESCRIPTION. THE ENTIRE
 * RISK ARISING OUT OF USE OR PERFORMANCE OF THE SOFTWARE LIES WITH YOU.
 */

/***************************************************************************//**

\file

\brief This module contains the code for the 73xx hardware interface.

*******************************************************************************/

/*-----------------------------------------------------------------------------
 *                                 Revision History
 *                                     $Log: hil_nvme.c $
 *---------------------------------------------------------------------------*/

#include "nvme_cvm.h"
#include "nvme.h"
#include "cvmx-nqm-defs.h"
#include "cvmcs-profile.h"
#include "cn73xx_nqm.h"

/*
 * pf/vf device control structure array
 */
extern CVMX_SHARED struct nvme_dev *nqm_device_structs[NVME_NUM_PFVF];
CVMX_SHARED uint8_t nqm_tag_mode = NQM_TAG_GLBL_VF_SQID;
CVMX_SHARED uint8_t nqm_vf_mode = NQM_VF_MODE_2;
CVMX_SHARED uint16_t nqm_sq_credits = 0;
CVMX_SHARED uint16_t nqm_cplq_size = DEFAULT_CPLQ_SIZE;

CVMX_SHARED nqm_vf_mode_map_t nqm_vf_mode_map[] = {
	{NQM_VF_MODE0_VF_MAX, NQM_VF_MODE0_IOQ_MAX},
	{NQM_VF_MODE1_VF_MAX, NQM_VF_MODE1_IOQ_MAX},
	{NQM_VF_MODE2_VF_MAX, NQM_VF_MODE2_IOQ_MAX}
};

cvmx_nqm_interrupt_handler_t nqm_irq_handler[NQM_INTR_COUNT];

void
nqm_set_vf_mode(char *mode)
{
	int vf_mode = atoi(mode);

	if (vf_mode < NQM_VF_MODE_0 || vf_mode > NQM_VF_MODE_2) {
		debug_printf(1, "Invalud vf_mode %d passed\n", vf_mode);
		return;
	}

	nqm_vf_mode = vf_mode;
	debug_printf(1, "Setting vf_mode to %d", nqm_vf_mode);
}

void
nvme_set_sq_credits(char *creds)
{
	nqm_sq_credits = atoi(creds);
	if (nqm_sq_credits > MAX_SQ_DEPTH)
		nqm_sq_credits = 0;
	debug_printf(1, "Setting nqm sq credits to %d", nqm_sq_credits);
}

void
nvme_set_cplq_size(char *size)
{
	nqm_cplq_size = atoi(size);

	if (!nqm_cplq_size || nqm_cplq_size > MAX_CPLQ_SIZE)
		nqm_cplq_size = MAX_CPLQ_SIZE;

	if (nqm_cplq_size & (nqm_cplq_size -1)) {
		// Round up the 16bit value to next highest power of 2
		nqm_cplq_size--;
		nqm_cplq_size |= (nqm_cplq_size >> 1);
		nqm_cplq_size |= (nqm_cplq_size >> 2);
		nqm_cplq_size |= (nqm_cplq_size >> 4);
		nqm_cplq_size |= (nqm_cplq_size >> 8);
		nqm_cplq_size++;
	}

	debug_printf(1, "Setting nqm cplq size to %d", nqm_cplq_size);
}

/***************************************************************************//**

Initialize vf/pf local NQM registers

Initializes the per pf/vf registers.

*******************************************************************************/

int nqm_pfvf_reg_init(int pfvf)
{
	cvmx_write_csr(CVMX_NQM_VFX_CPLX_BASE_ADDR_N_SZ(0, pfvf), 0x0);

	cvmx_write_csr(CVMX_NQM_VFX_CPLX_TDB(0, pfvf), 0x0);
	cvmx_write_csr(CVMX_NQM_VFX_CQX_ENA(0, pfvf), 0x0);
	cvmx_write_csr(CVMX_NQM_VFX_SQX_SSO_SETUP(0, pfvf), 0x0);
	cvmx_write_csr(CVMX_NQM_VFX_SQX_CREDIT(0, pfvf), 0x0);
	cvmx_write_csr(CVMX_NQM_VFX_SQX_ENA(0, pfvf), 0x0);
	cvm_write_csr32(CVMX_PEXP_NQM_VFX_SQX_TDBL(0, pfvf), 0x0);
	//cvm_write_csr32(CVMX_PEXP_NQM_VFX_CQX_HDBL(0, pfvf), 0x0);
	return 0;
}

/***************************************************************************//**

Handle NQM controller configuration register write interrupt

This routine is the entry point for the interrupt from any writes to the
controller configuration register.

*******************************************************************************/
int nqm_cc_change_interrupt(int pfvf)
{
	struct nvme_dev *dev; // device info structure pointer
	int ret = 0;

	if (pfvf >= nqm_vf_mode_map[nqm_vf_mode].vf_cnt) {
		debug_printf(1, "Error: Cannot create vf %d", pfvf);
		debug_printf(1, "Max supported vfs in nqm_vf_mode %u are %u\n",
			nqm_vf_mode, nqm_vf_mode_map[nqm_vf_mode].vf_cnt);
		return STATUS_ERROR;
	}

	debug_printf(3, "cc change interrupt");
	// make sure that device exists
	ret = nvme_init_dev(pfvf);
	if (ret < 0)
		return ret;

	// Get associated dev struct
	dev = nqm_device_structs[pfvf];

	npl_controller_configuration(dev);

	return ret;
}

static void
cn73xx_nqm_handle_reset_intr(int vf_id, aq_delete_cause_t casue)
{
	struct nvme_dev *dev;

	dev = nqm_device_structs[vf_id];

	if (!dev)
		return;

	if (!cvmx_atomic_get32(&dev->vf_active))
		return;

	npl_controller_disable(dev);
	npl_delete_admin_queues(dev, casue);

	nqm_device_structs[dev->pfvf] = NULL;
	memset(dev, 0, sizeof(struct nvme_dev));
}

/**
 * NQM irq handler
 */
static void
cn73xx_nqm_irq_handler(struct cvmx_interrupt *top_irq, uint64_t *registers)
{
	unsigned int intsn, vf_id, major_block;
	cvmx_nqm_interrupt_handler_t *irq_handler =
		(cvmx_nqm_interrupt_handler_t *)top_irq;
	cvmx_nqm_vfx_int_t int_sts;
	struct nvme_dev *dev;
	struct async_event_result nvme_async_evt = { 0, };
	struct nvme_log_error error_log = { 0, };
	int i;

	intsn = irq_handler->intsn;

	major_block = (intsn >> 12);

	if (major_block == NQM_CC_INTSN) {
		vf_id = intsn & 0xFFF;
		if (vf_id >= NVME_NUM_PFVF) {
			debug_printf(1, "VF value %u is out of range", vf_id);
			return;
		}

		/* NVMe config change interrupts */
		int_sts.u64 = cvmx_read_csr(CVMX_NQM_VFX_INT(vf_id));
		
		/* Clear the interrupt status */
		cvmx_write_csr(CVMX_NQM_VFX_INT(vf_id), int_sts.u64);

		if (int_sts.s.ccw) {
			debug_printf(3, "CC change intr.");
			/* Controller configuration change */
			nqm_cc_change_interrupt(vf_id);
			/* 1. CC[EN] 0->1 transition */

			/* 2. CC[EN] 1->0 transition
			 * Delete all IO SQ & CQs of the controller
			 * Abort all outstanding admin & IO commands
			 * Do not reset AQA, ASQ and ACQ
			 * Reset all other NVMe registers (BAR1)
			 * Set NQM_VF(vf_id)_CSTS[RDY] to 0
			 */
		}

		if (int_sts.s.sq_db || int_sts.s.cq_db ||
			int_sts.s.sq_db_val || int_sts.s.cq_db_val) {

			dev = nqm_device_structs[vf_id];
			debug_printf(1, "Improper update to vf %d %s. "
				"Status %lx", vf_id,
				int_sts.s.cq_db ? "CQ": "SQ", int_sts.u64);

			if (dev && cvmx_atomic_get32(&dev->vf_active)) {
				if (int_sts.s.sq_db_val || int_sts.s.cq_db_val)
					nvme_async_evt.aei = INVALID_DB_WRITE;
				else
					nvme_async_evt.aei =  INVALID_DB_REGISTER;

				nvme_async_evt.aet =  AET_ERROR_STATUS;
				nvme_async_evt.alp = ERROR_BIT;
				npl_update_error_logpages(dev, &error_log);
				npl_async_event_update(dev, &nvme_async_evt);
			} else
				debug_printf(1, "vf %d is not active to post async logs", vf_id);
		}

		if (int_sts.s.cq_fe) {
			/* CQ fatal error due to PRP read failure. Disable CQ
			 * which has NQM_VF(vf_id)_CQ(1..16)_BASE[PRIP, BV] reset.
			 */
			debug_printf(1, "CQ fatal error due to PRP read failure");
		}

		if (int_sts.s.sq_fe) {
			/* SQ fatal error due to PRP read failure. Disable SQ
			 * which has NQM_VF(vf_id)_SQ(1..16)_BASE[PRIP, BV] reset.
			 */
			debug_printf(1, "SQ fatal error due to PRP read failure");
		}

		if (int_sts.s.acq_cfg || int_sts.s.asq_cfg) {
			/* Report controller fatal status through
			 * NQM_VF(vf_id)_CSTS[CFS]
			 */
			debug_printf(1, "Host changed the configuration of the"
				" vf %d admin %s while it is eabled", vf_id,
				int_sts.s.acq_cfg ? "CQ": "SQ");
		}

		if (int_sts.s.flr) {

			int_sts.s.flr = 0;
			/* PCIe function level reset */

			/* 1. flr to the VF
			 * Delete all Admin/IO SQ & CQs of the controller
			 * Abort all outstanding admin & IO commands
			 * Reset all NVMe registers (BAR0)
			 * Set NQM_VF(vf_id)_CSTS[RDY] to 0
			 */
			debug_printf(1, "FLR to nvme controller %d", vf_id);
			if (vf_id) {
				int idx;
				int offset;
				uint64_t stopreq;
				cn73xx_nqm_handle_reset_intr(vf_id, AQ_DEL_FLR);
				//clear stop req
				idx = (vf_id-1)/64;
				offset = (vf_id-1)%64;

				stopreq = cvmx_read_csr(
					CVMX_SPEMX_FLR_PF2_VFX_STOPREQ(idx, 0));
				if (stopreq & (0x1UL << offset))
					debug_printf(1, "stop req bit set for PF2 vf-%d",
						vf_id-1);
				//make sure to only clear this vf.
				stopreq = (0x1UL << offset);
				//wait 100ms at least
				cvmx_wait_usec(100000);
				cvmx_write_csr(
					CVMX_SPEMX_FLR_PF2_VFX_STOPREQ(idx, 0), stopreq);
			} else {
				uint64_t stopreq;
				/* 2. flr to the PF
				 * Delete all Admin/IO SQ & CQs of the all the controllers
				 * Abort all outstanding admin & IO commands of
				 * all the controllers. Reset all NQM registers
				 * Set NQM_VF(vf_id)_CSTS[RDY] to 0 of all the controllers
				 */
				for (i = 1; i < nqm_vf_mode_map[nqm_vf_mode].vf_cnt; i++) {
					cn73xx_nqm_handle_reset_intr(i, AQ_DEL_FLR);
				}

				cn73xx_nqm_handle_reset_intr(vf_id, AQ_DEL_FLR);
				stopreq = cvmx_read_csr(CVMX_SPEMX_FLR_PF_STOPREQ(0));
				if (stopreq & (0x1UL << 2)) {
					debug_printf(1, "stop req bit set for PF 2\n");
				}
				//make sure to clear only our pf
				stopreq =  (0x1UL << 2);
				//wait 100ms at least
				cvmx_wait_usec(100000);
				cvmx_write_csr(CVMX_SPEMX_FLR_PF_STOPREQ(0), stopreq);
			}
		}

	} else if (major_block == NQM_INTSN) {

		if (intsn == NQM_INTSN_PCIE_VF_ENABLE_CLR) {
			/* VFs are disabled from PF's PCIe SRIOV-extended capabilities */

			/* PF (i.e VF[0]) is untouched
			 * VF[1-1027] are resetted similar to flr to vf but all the
			 * NQM registers belongs to VFs will be resetted.
			 */
			debug_printf(1, "NQM: PCIE_VF_ENABLE_CLR interrupt");

			for (i = 1; i < nqm_vf_mode_map[nqm_vf_mode].vf_cnt; i++)
				cn73xx_nqm_handle_reset_intr(i, AQ_DEL_FLR);

			cvmx_write_csr(CVMX_NQM_INT,
				cvmx_read_csr(CVMX_NQM_INT) &
				NQM_INT_PCIE_VF_ENABLE_CLR);
		} else if (intsn == NQM_INTSN_PCIE_MAC_RESET) {
			/* PCIe MAC Reset
			 * Handling is similar to flr to the PF
			 */
			debug_printf(1, "NQM: PCIE_MAC_RESET interrupt");

			for (i = 1; i < nqm_vf_mode_map[nqm_vf_mode].vf_cnt; i++)
				cn73xx_nqm_handle_reset_intr(i, AQ_DEL_FLR);
			cn73xx_nqm_handle_reset_intr(0, AQ_DEL_FLR);

			cvmx_write_csr(CVMX_NQM_INT,
				cvmx_read_csr(CVMX_NQM_INT) &
				NQM_INT_PCIE_MAC_RESET);

		} else if (intsn == NQM_INTSN_FPA_NO_PTRS) {
			/* NQM recieved a signal for no FPA pointers available. */
			debug_printf(1, "NQM: FPA_NO_PTRS interrupt");
			cvmx_write_csr(CVMX_NQM_INT,
				cvmx_read_csr(CVMX_NQM_INT) &
				NQM_INT_FPA_NO_PTRS);
		} else {
			if (intsn >= NQM_INTSN_CS_DBE0 &&
					intsn < NQM_INTSN_CS_SBE0) {
				/* NQM CS double bit error ECC interrupts; */
				debug_printf(1, "NQM: CS DBE interrupt");

				cvmx_write_csr(CVMX_NQM_CS_ECC0_INT,
					cvmx_read_csr(CVMX_NQM_CS_ECC0_INT &
					NQM_CS_ERR_DBE_MASK));
			}

			if (intsn >= NQM_INTSN_CS_SBE0 &&
					intsn < NQM_INTSN_NCB_TX_ERR) {
				/* NQM CS single bit error ECC interrupts; */
				debug_printf(1, "NQM: CS SBE interrupt");
				cvmx_write_csr(CVMX_NQM_CS_ECC0_INT,
					cvmx_read_csr(CVMX_NQM_CS_ECC0_INT &
						NQM_CS_ERR_SBE_MASK));
			}

			if (intsn == NQM_INTSN_NCB_TX_ERR) {
				/* NCB transaction error occurred */
				debug_printf(1, "NQM: NCB_TX_ERR interrupt");

				cvmx_write_csr(CVMX_NQM_NCB_INT,
					cvmx_read_csr(CVMX_NQM_NCB_INT));
			}

			if (intsn >= NQM_INTSN_HS_DBE0 && intsn < NQM_INTSN_HS_SBE0) {
				/* NQM HS double bit error ECC interrupts; */
				debug_printf(1, "NQM: HS DBE interrupt");

				cvmx_write_csr(CVMX_NQM_HS_ECC0_INT,
					cvmx_read_csr(CVMX_NQM_HS_ECC0_INT) &
						NQM_HS_ERR_DBE_MASK);
			}

			if (intsn >= NQM_INTSN_HS_SBE0 &&
					intsn < NQM_INTSN_PCIE_MAC_RESET) {
				/* NQM HS single bit error ECC interrupts; */
				debug_printf(1, "NQM: HS DBE interrupt");

				cvmx_write_csr(CVMX_NQM_HS_ECC0_INT,
					cvmx_read_csr(CVMX_NQM_HS_ECC0_INT) &
						NQM_HS_ERR_SBE_MASK);
			}
		}
	}
}

/**
 * Enable NQM interrupts and register interrupts handlers
 */
static void
nqm_intr_config(void)
{
	cvmx_nqm_vfx_int_ena_w1s_t int_en;
	int i, vec, vf;

	for (i = 0, vec = 0; i < NQM_CS_ERR_DBE_INTR_COUNT; i++, vec++)
		nqm_intr_register(nqm_irq_handler, vec,
			NQM_INTSN_CS_DBE0_BIT(i), cn73xx_nqm_irq_handler);

	for (i = 0; i < NQM_CS_ERR_SBE_INTR_COUNT; i++, vec++)
		nqm_intr_register(nqm_irq_handler, vec,
			NQM_INTSN_CS_SBE0_BIT(i), cn73xx_nqm_irq_handler);

	
	nqm_intr_register(nqm_irq_handler, vec,
		NQM_INTSN_NCB_TX_ERR, cn73xx_nqm_irq_handler);
	vec++;

	for (i = 0; i < NQM_HS_ERR_DBE_INTR_COUNT; i++, vec++)
		nqm_intr_register(nqm_irq_handler, vec,
			NQM_INTSN_HS_DBE0_BIT(i), cn73xx_nqm_irq_handler);

	for (i = 0; i < NQM_HS_ERR_SBE_INTR_COUNT; i++, vec++)
		nqm_intr_register(nqm_irq_handler, vec,
			NQM_INTSN_HS_SBE0_BIT(i), cn73xx_nqm_irq_handler);

	nqm_intr_register(nqm_irq_handler, vec,
		NQM_INTSN_PCIE_MAC_RESET, cn73xx_nqm_irq_handler);
	vec++;

	nqm_intr_register(nqm_irq_handler, vec,
		NQM_INTSN_PCIE_VF_ENABLE_CLR, cn73xx_nqm_irq_handler);
	vec++;

	nqm_intr_register(nqm_irq_handler, vec,
		NQM_INTSN_FPA_NO_PTRS, cn73xx_nqm_irq_handler);
	vec++;

	int_en.u64		= 0;
	int_en.s.ccw		= 1;
	int_en.s.flr		= 1;
	int_en.s.sq_db		= 1;
	int_en.s.sq_db_val	= 1;
	int_en.s.cq_db		= 1;
	int_en.s.cq_db_val	= 1;
	int_en.s.acq_cfg	= 1;
	int_en.s.asq_cfg	= 1;
	int_en.s.cq_fe		= 1;
	int_en.s.sq_fe		= 1;
	int_en.s.sli_err	= 1;

	for (vf = 0; vf < nqm_vf_mode_map[nqm_vf_mode].vf_cnt; vf++, vec++) {
		cvmx_ciu3_iscx_w1c_t isc_ctl_w1c;
		unsigned int intsn = NQM_INTSN_VFX_INT(vf);

		/* Clear en & raw bits in ISC */
		isc_ctl_w1c.u64		= 0;
		isc_ctl_w1c.s.raw	= 1;
		isc_ctl_w1c.s.en	= 1;
		cvmx_write_csr(CVMX_CIU3_ISCX_W1C(intsn), isc_ctl_w1c.u64);

		/* Read it back to make sure it took effect. */
		cvmx_read_csr(CVMX_CIU3_ISCX_W1C(intsn));

		nqm_intr_register(nqm_irq_handler, vec,
			intsn, cn73xx_nqm_irq_handler);

		/* Enable NQM vf interrupts */
		cvmx_write_csr(CVMX_NQM_VFX_INT_ENA_W1S(vf), int_en.u64);
	}
}

/***************************************************************************//**

Initialize global NQM registers

Initializes the fixed (not indexed by pf/vf) registers in the NQM.

Note: all global registers are init'ed, by default with the hardware specified
reset value. This means that this routine can be used to reinitialize the NQM.
The registers appear in HRM order.

*******************************************************************************/

int nqm_global_reg_init(void)
{
	cvmx_nqm_vf_mode_t vf_mode;
	cvmx_nqm_ic_div_t ic_div;
	cvmx_nqm_glbl_tag_t glbl_tag;
	cvmx_nqm_cfg_t cfg;
	cvmx_nqm_fi_fpa_aura_t fi_fpa_aura;
	cvmx_nqm_clken_t clken;
	cvmx_nqm_hs_bist_status0_t hs_bist;
	cvmx_nqm_cs_bist_status0_t cs_bist;

	hs_bist.u64 = cvmx_read_csr(CVMX_NQM_HS_BIST_STATUS0);
	debug_printf(1, "hs bist status is %x", hs_bist.s.bist_status);
	if (hs_bist.s.bist_status) {
		debug_printf(1, "hs bist status is %x", hs_bist.s.bist_status);
		return STATUS_ERROR;
	}

	cs_bist.u64 = cvmx_read_csr(CVMX_NQM_CS_BIST_STATUS0);
	debug_printf(1, "cs bist status is %x", cs_bist.s.bist_status);
	if (cs_bist.s.bist_status) {
		debug_printf(1, "cs bist status is %x", cs_bist.s.bist_status);
		return STATUS_ERROR;
	}

	// 1028 virtual functions with 4 I/O queue pairs max
	vf_mode.u64		= 0;
	vf_mode.s.vf_mode	= nqm_vf_mode;
	cvmx_write_csr(CVMX_NQM_VF_MODE, vf_mode.u64);

	// 2.5 seconds interrupt coalescing timer
	ic_div.u64		= 0;
	ic_div.s.div		= NQM_MSIX_COALESCE_DIV;
	cvmx_write_csr(CVMX_NQM_IC_DIV, ic_div.u64);

	// glbl tag mode, tag is 0
	glbl_tag.u64		= 0;
	glbl_tag.s.tag_mode	= nqm_tag_mode;
	if (OCTEON_IS_MODEL(OCTEON_CN73XX_PASS1_0)) {
#ifdef NQM_FETCH_PCI_DMA
		glbl_tag.s.tag	= CMD_FETCH_TAG << NQM_TAG_SHIFT;
#else
		glbl_tag.s.tag	= CMD_HANDLE_TAG << NQM_TAG_SHIFT;
#endif
	} else
		glbl_tag.s.tag	= CMD_HANDLE_TAG << NQM_TAG_SHIFT;

	cvmx_write_csr(CVMX_NQM_GLBL_TAG, glbl_tag.u64);

	// NVMe version 1.1, timeout 1.27.5 seconds, CPL entry load type LDI,
	// store type STF
	cfg.u64			= 0;
	cfg.s.mjr		= 1;
	//Use upper 8 bits for mnr version as lower bits are reserved (spec 1.1b)
	cfg.s.mnr		= 0x0100;
	cfg.s.to		= 0xff;
	cfg.s.ld_type		= 0;
	cfg.s.st_type		= 0;
	cvmx_write_csr(CVMX_NQM_CFG, cfg.u64);

	// Retry timer 10us, FPA pool for NQM use is CVMX_FPA_WQE_POOL
	fi_fpa_aura.u64		= 0;
	fi_fpa_aura.s.retry_timer = NQM_FPA_WQE_RETRY_TIMEO;
	fi_fpa_aura.s.laura	= CVMX_FPA_WQE_POOL;
	cvmx_write_csr(CVMX_NQM_FI_FPA_AURA, fi_fpa_aura.u64);

	// hardware controls clock
	clken.u64		= 0;
	clken.s.clken		= 0;
	cvmx_write_csr(CVMX_NQM_CLKEN, clken.u64);

#ifdef NVME_FLASH_BOOT
	{
		int pcie_port = 2;
		cvmx_pcieepx_cfg097_t cfg97;

		// Set PCI Express SR-IOV Initial VFs/Total VFs Registers
		// PCIEEP0_CFG097[TVF, IVF] according to vf_mode.
		cfg97.cn73xx.ivf = cfg97.cn73xx.tvf =
			nqm_vf_mode_map[nqm_vf_mode].vf_cnt - 1;
		cvmx_pcie_cfgx_write(0,
			CVMX_PCIEEPX_CFG097(pcie_port) | (1ull << 31) |
			(pcie_port << 24), cfg97.u32);
	}
#endif

	nqm_intr_config();
	return 0;
}

/***************************************************************************//**

Setup NQM interrupt vectors

*******************************************************************************/

int nqm_set_intvec(void)
{
	return 0;
}

/**
 * Create admin submission queue.
 *
 * @param vf: VF, the ASQ being created belongs to
 */
int
cn73xx_nqm_create_admin_sq(struct nvme_dev *dev)
{
	cvmx_nqm_vfx_sqx_sso_setup_t sq_sso_setup;
	cvmx_nqm_vfx_sqx_credit_t sq_credits;
	cvmx_nqm_vfx_aqa_t aqa;
	uint16_t vf = dev->pfvf;
	uint16_t cred;

	debug_printf(2, "NQM: VF %d ASQ create start", vf);
	cvm_write_csr32(CVMX_PEXP_NQM_VFX_SQX_TDBL(NQM_AQ_ID, vf), 0);
	cvmx_write_csr(CVMX_NQM_VFX_SQX_HEAD(NQM_AQ_ID, vf), 0);

	/* Tag type and group for nvme_wqe */
	sq_sso_setup.u64	= 0;
	sq_sso_setup.s.tag_type	= CVMX_POW_TAG_TYPE_ORDERED;
	sq_sso_setup.s.group	= NQM_SQ_SSO_GROUP;
	cvmx_write_csr(CVMX_NQM_VFX_SQX_SSO_SETUP(NQM_AQ_ID, vf), sq_sso_setup.u64);

	aqa.u32 = cvm_read_csr32(CVMX_PEXP_NQM_VFX_AQA(vf));
	cred = nqm_sq_credits ? nqm_sq_credits : aqa.s.asqs;
	/* Outstanding admin SQ commands in flight */
	sq_credits.u64		= 0;
	sq_credits.s.cred	= cred;
	cvmx_write_csr(CVMX_NQM_VFX_SQX_CREDIT(NQM_AQ_ID, vf), sq_credits.u64);

	cn73xx_nqm_enable_sq(vf, NQM_AQ_ID);
	debug_printf(2, "NQM: VF %d ASQ create complete", vf);

	return 0;
}

/**
 * Delete admin submission queue
 *
 * @param vf: VF the ASQ being deleted belongs to.
 */
int
cn73xx_nqm_delete_admin_sq(struct nvme_dev *dev)
{
	volatile cvmx_nqm_vfx_sqx_credit_t sq_cred;
	cvmx_nqm_vfx_aqa_t aqa;
	uint16_t vf = dev->pfvf, cred;
	uint64_t ticks;

	debug_printf(2, "NQM: VF %d ASQ delete start", vf);
	aqa.u32 = cvm_read_csr32(CVMX_PEXP_NQM_VFX_AQA(vf));
	cred = nqm_sq_credits ? nqm_sq_credits : aqa.s.asqs;

	NVME_MARKTIME(ticks);
	do {
		sq_cred.u64 = cvmx_read_csr(CVMX_NQM_VFX_SQX_CREDIT(NQM_AQ_ID, vf));
	} while ((sq_cred.s.cred != (cred)) && !NVME_TIMEOUT(ticks, NVME_QUEUE_TIMEOUTVAL));

	if (sq_cred.s.cred != cred)
		debug_printf(1, "Exiting vf %d admin sq delete abruptly after timeout", vf);

	cn73xx_nqm_disable_sq(vf, NQM_AQ_ID);
	debug_printf(2, "NQM: VF %d ASQ delete complete", vf);

	return 0;
}

/**
 * Create admin completion queue
 *
 * @param dev: nvme_dev pointer of the controller (VF)
 */
int
cn73xx_nqm_create_admin_cq(struct nvme_dev *dev)
{
	cvmx_nqm_vfx_cplx_tdb_t cpl_tbd;
	cvmx_nqm_vfx_cplx_base_addr_n_sz_t cpl_base_sz;
	cvmx_nqm_vfx_acq_cc_t acq_cc;
	cvmx_nqm_vfx_cqx_tail_t cq_tail;
	uint16_t vf = dev->pfvf;

	debug_printf(2, "NQM: VF %d ACQ create start", vf);
	/* Setup CPL queue base address and queue size */
	if ((cvmx_ptr_to_phys(dev->queue->cq[NQM_AQ_ID]->cqes)) & 0x7f)
		debug_printf(1, "error amin cpl base address not 128 bit aligned");

	cpl_base_sz.u64		= 0;
	cpl_base_sz.s.base_addr	=
		(cvmx_ptr_to_phys(dev->queue->cq[NQM_AQ_ID]->cqes)) >> 7;
	cpl_base_sz.s.qsize	= nqm_cplq_size - 1;
	cvmx_write_csr(CVMX_NQM_VFX_CPLX_BASE_ADDR_N_SZ(NQM_AQ_ID, vf), cpl_base_sz.u64);

	/* Reset CPL queue tail value to zero */
	cpl_tbd.u64		= 0;
	cvmx_write_csr(CVMX_NQM_VFX_CPLX_TDB(NQM_AQ_ID, vf), cpl_tbd.u64);

	cvm_write_csr32(CVMX_PEXP_NQM_VFX_CQX_HDBL(NQM_AQ_ID, vf), 0);

	cq_tail.u64		= 0;
	cq_tail.s.pt		= 1;
	cvmx_write_csr(CVMX_NQM_VFX_CQX_TAIL(NQM_AQ_ID, vf), cq_tail.u64);

	/* Configure admin CQ */
	acq_cc.u64		= 0;
	acq_cc.s.ien		= 1;
	acq_cc.s.p		= 1;
	acq_cc.s.iv		= 0;
	cvmx_write_csr(CVMX_NQM_VFX_ACQ_CC(vf), acq_cc.u64);

	cn73xx_nqm_enable_cq(vf, NQM_AQ_ID);
	debug_printf(2, "NQM: VF %d ACQ create complete", vf);
	return 0;
}

/**
 * Delete admin completion queue
 *
 * @param dev: nvme_dev pointer of the controller (VF)
 */
int
cn73xx_nqm_delete_admin_cq(struct nvme_dev *dev)
{
	uint16_t vf;
	volatile cvmx_nqm_vfx_cplx_tdb_t cpl_tdb;
	volatile cvmx_nqm_vfx_cplx_h_t cpl_h;
	uint64_t ticks;

	vf = dev->pfvf;

	debug_printf(2, "NQM: VF %d ACQ delete start", vf);
	NVME_MARKTIME(ticks);
	do {
		cpl_tdb.u64 = cvmx_read_csr(CVMX_NQM_VFX_CPLX_TDB(NQM_AQ_ID, vf));
		cpl_h.u64 = cvmx_read_csr(CVMX_NQM_VFX_CPLX_H(NQM_AQ_ID, vf));
	} while ((cpl_tdb.s.tail != cpl_h.s.head) && !NVME_TIMEOUT(ticks, NVME_QUEUE_TIMEOUTVAL));

	if (cpl_tdb.s.tail != cpl_h.s.head)
		debug_printf(1, "Exiting vf %d admin cq delete abruptly after timeout", vf);

	cn73xx_nqm_disable_cq(vf, NQM_AQ_ID);
	debug_printf(2, "NQM: VF %d ACQ delete complete", vf);

	return 0;
}

/**
 * Create IO completion queue
 *
 * @param dev: nvme_dev pointer of the controller (VF)
 * @param cqid: IO completion queue ID
 * @param q_size: CQ size (zero based value)
 * @param prp: PRP/Physical addr of CQ on the host
 * @param pc: is CQ Physically contiguos on the host?
 * @param iv: interrupt vector of this queue (0 to 16)
 * @param ien: Interrupt enable?
 */
int
cn73xx_nqm_create_io_cq(struct nvme_dev *dev, uint8_t cqid, uint16_t q_size,
		uint64_t prp, uint8_t pc, uint16_t iv, uint8_t ien,
		struct completion_status_field *cpl_entry)
{
	cvmx_nqm_vfx_cqx_cc_t cq_cc;
	cvmx_nqm_vfx_cplx_base_addr_n_sz_t cpl_base_sz;
	cvmx_nqm_vfx_cqx_tail_t cq_tail;
	cvmx_nqm_vfx_cqx_prp_t cq_prp;
	cvmx_nqm_vfx_cqx_base_t cq_base;
	uint16_t vf;

	if (iv > 16) {
		debug_printf(1, "NQM: Improper IV %d while creating IO CQ", iv);
		cpl_entry->sct = SCT_COMMAND;
		cpl_entry->sc = INVALID_IV;
		cpl_entry->m = 0;
		cpl_entry->dnr = 1;

		return STATUS_ERROR;
	}

	vf = dev->pfvf;

	debug_printf(2, "NQM: VF %d CQ %d create start", vf, cqid);
	debug_printf(3, "cq create vf %d cqid %d size %d", vf, cqid, q_size);

	cvm_write_csr32(CVMX_PEXP_NQM_VFX_CQX_HDBL(cqid, vf), 0);

	cq_tail.u64		= 0;
	cq_tail.s.pt		= 1;
	cvmx_write_csr(CVMX_NQM_VFX_CQX_TAIL(cqid, vf), cq_tail.u64);

	if (pc) {
		cq_prp.u64		= 0;
		cvmx_write_csr(CVMX_NQM_VFX_CQX_PRP(cqid, vf), cq_prp.u64);

		/* Physically contiguous CQ. */
		cq_base.u64		= 0;
		cq_base.s.pba		= prp >> GET_HOST_PAGE_SHIFT(dev);
		cq_base.s.prip		= 0;
		cq_base.s.bv		= 0;
		cvmx_write_csr(CVMX_NQM_VFX_CQX_BASE(cqid, vf), cq_base.u64);
		debug_printf(3, "create io cqid %d NQM_VF0_CQX_BASE  %016lx",
			cqid, cvmx_read_csr(CVMX_NQM_VFX_CQX_BASE(cqid, vf)));
	} else {
		cq_base.u64		= 0;
		cvmx_write_csr(CVMX_NQM_VFX_CQX_BASE(cqid, vf), cq_base.u64);
		
		/* Not a PC Queue. prp points to the queue segments */
		cq_prp.u64		= 0;
		//set acording to mps
		cq_prp.s.prp		= prp >> GET_HOST_PAGE_SHIFT(dev);
		cvmx_write_csr(CVMX_NQM_VFX_CQX_PRP(cqid, vf), cq_prp.u64);
		debug_printf(3, "create io cqid not pc %d NQM_VF0_CQX_PRP  %016lx",
			cqid, cvmx_read_csr(CVMX_NQM_VFX_CQX_PRP(cqid, vf)));
	}

	/* Configure IO CQ attributes */
	cq_cc.u64		= 0;
	cq_cc.s.pc		= pc;
	cq_cc.s.ien		= ien;
	cq_cc.s.p		= 1;
	cq_cc.s.iv		= iv;
	cq_cc.s.qsize		= q_size;
	cvmx_write_csr(CVMX_NQM_VFX_CQX_CC(cqid, vf), cq_cc.u64);
	debug_printf(3, "create io cqid %d CVMX_NQM_VF0_CQX_CC %016lx", cqid,
		cvmx_read_csr(CVMX_NQM_VFX_CQX_CC(cqid, vf)));

	debug_printf(3, "addr of VF%d_CQ%d_CC 0x%016llx",
		vf, cqid, CVMX_NQM_VFX_CQX_CC(cqid, vf));

	cvmx_write_csr(CVMX_NQM_VFX_CPLX_TDB(cqid, vf), 0);
	cvmx_write_csr(CVMX_NQM_VFX_CPLX_H(cqid, vf), 0);

	if ((cvmx_ptr_to_phys(dev->queue->cq[cqid]->cqes)) & 0x7f)
		debug_printf(1, "error cpl base addr not 128 bit aligned cqid %d", cqid);

	/* Setup CPL base address and size */
	cpl_base_sz.u64		= 0;
	cpl_base_sz.s.base_addr	= (cvmx_ptr_to_phys(dev->queue->cq[cqid]->cqes)) >> 7;
	cpl_base_sz.s.qsize	= nqm_cplq_size - 1;
	cvmx_write_csr(CVMX_NQM_VFX_CPLX_BASE_ADDR_N_SZ(cqid, vf), cpl_base_sz.u64);
	debug_printf(3, "create io cqid  %d NQM_VF0_CPLX_BASE_ADDR_N_SZ  %016lx",
		cqid, cvmx_read_csr(CVMX_NQM_VFX_CPLX_BASE_ADDR_N_SZ(cqid, vf)));

	cn73xx_nqm_enable_cq(vf, cqid);
	debug_printf(3, "create io cqid  %d NQM_VF0_CQX_ENA  %016lx",
		cqid, cvmx_read_csr(CVMX_NQM_VFX_CQX_ENA(cqid, vf)));
	debug_printf(2, "NQM: VF %d CQ %d create complete", vf, cqid);

	return 0;
}

/**
 * Delete IO completion queue
 *
 * @param dev: nvme_dev pointer of the controller (VF)
 * @param cqid: cqid to delete 
 */
int
cn73xx_nqm_delete_io_cq(struct nvme_dev *dev, uint8_t cqid)
{
	cvmx_nqm_vfx_cplx_tdb_t cpl_tdb;
	cvmx_nqm_vfx_cplx_h_t cpl_h;
	uint16_t vf;
	uint64_t ticks;

	if (!cqid) {
		debug_printf(1, "Invalid IO CQID\n");
		return STATUS_ERROR;
	}

	vf = dev->pfvf;
	debug_printf(2, "NQM: VF %d CQ %d delete start", vf, cqid);

	NVME_MARKTIME(ticks);
	do {
		cpl_tdb.u64 = cvmx_read_csr(CVMX_NQM_VFX_CPLX_TDB(cqid, vf));
		cpl_h.u64 = cvmx_read_csr(CVMX_NQM_VFX_CPLX_H(cqid, vf));
	} while ((cpl_tdb.s.tail != cpl_h.s.head) && !NVME_TIMEOUT(ticks, NVME_QUEUE_TIMEOUTVAL));

	if (cpl_tdb.s.tail != cpl_h.s.head)
		debug_printf(1, "Exiting vf %d io cq %d delete abruptly after timeout", vf, cqid);

	cn73xx_nqm_disable_cq(vf, cqid);
	debug_printf(2, "NQM: VF %d CQ %d delete complete", vf, cqid);

	return 0;
}

/**
 * Create IO submission queue
 *
 * @param dev: nvme_dev pointer of the controller (VF)
 * @param sqid: SQ ID to create
 * @param q_size: SQ size (zero based value)
 * @param prp: PRP/Physical address of the SQ in host memory
 * @param pc: Physically contigous?
 */
int
cn73xx_nqm_create_io_sq(struct nvme_dev *dev, uint8_t sqid,
		uint16_t q_size, void *prp, uint8_t pc)
{
	cvmx_nqm_vfx_sqx_cc_t sq_cc;
	cvmx_nqm_vfx_sqx_sso_setup_t sq_sso_setup;
	cvmx_nqm_vfx_sqx_credit_t sq_credits;
	cvmx_nqm_vfx_sqx_base_t sq_base;
	cvmx_nqm_vfx_sqx_prp_t sq_prp;
	uint16_t vf = dev->pfvf;
	uint16_t cred = nqm_sq_credits ? nqm_sq_credits : q_size;

	cvm_write_csr32(CVMX_PEXP_NQM_VFX_SQX_TDBL(sqid, vf), 0);
	cvmx_write_csr(CVMX_NQM_VFX_SQX_HEAD(sqid, vf), 0);

	debug_printf(2, "NQM: VF %d SQ %d create start", vf, sqid);
	/* Outstanding IO SQ commands in flight */
	sq_credits.u64		= 0;
	sq_credits.s.cred	= cred;
	cvmx_write_csr(CVMX_NQM_VFX_SQX_CREDIT(sqid, vf), sq_credits.u64);
	debug_printf(3, "create io_sq sq %d CVMX_NQM_VFX_SQX_CREDIT 0x%016lx", sqid, 
		cvmx_read_csr(CVMX_NQM_VFX_SQX_CREDIT(sqid, vf)));

	/* Setup SQ attributes */
	sq_cc.u64		= 0;
	sq_cc.s.qsize		= q_size;
	sq_cc.s.pc		= pc;
	cvmx_write_csr(CVMX_NQM_VFX_SQX_CC(sqid, vf), sq_cc.u64);
	debug_printf(3, "create io_sq sqid %d CVMX_NQM_VFX_SQX_CC 0x%016lx", sqid,
		cvmx_read_csr(CVMX_NQM_VFX_SQX_CC(sqid, vf)));

	if (!pc) {
		sq_base.u64		= 0;
		cvmx_write_csr(CVMX_NQM_VFX_SQX_BASE(sqid, vf), sq_base.u64);

		/* Not a PC Queue. prp points to the queue segments */
		sq_prp.u64		= 0;
		sq_prp.s.prp		= (uint64_t)prp >> GET_HOST_PAGE_SHIFT(dev);
		cvmx_write_csr(CVMX_NQM_VFX_SQX_PRP(sqid, vf), sq_prp.u64);
		debug_printf(3, "create io_sq sqid %d CVMX_NQM_VFX_SQX_PRP 0x%016lx", sqid, 
		cvmx_read_csr(CVMX_NQM_VFX_SQX_PRP(sqid, vf)));
	} else {
		sq_prp.u64		= 0;
		cvmx_write_csr(CVMX_NQM_VFX_SQX_PRP(sqid, vf), sq_prp.u64);

		/* Physically contiguous SQ. */
		sq_base.u64		= 0;
		sq_base.s.pba		= (uint64_t)prp >> GET_HOST_PAGE_SHIFT(dev);
		sq_base.s.prip		= 0;
		sq_base.s.bv		= 0;
		cvmx_write_csr(CVMX_NQM_VFX_SQX_BASE(sqid, vf), sq_base.u64);
		debug_printf(3, "create io_sq sqid %d CVMX_NQM_VFX_SQX_BASE 0x%016lx", sqid,
		cvmx_read_csr(CVMX_NQM_VFX_SQX_BASE(sqid, vf)));
	}

 	/* Tag type and group for nvme_wqe of this Q */
	sq_sso_setup.u64	= 0;
	sq_sso_setup.s.tag_type	= CVMX_POW_TAG_TYPE_ORDERED;
	sq_sso_setup.s.group	= NQM_SQ_SSO_GROUP;
	cvmx_write_csr(CVMX_NQM_VFX_SQX_SSO_SETUP(sqid, vf), sq_sso_setup.u64);
	debug_printf(3, "create io_sq sqid %d CVMX_NQM_VFX_SQX_SSO_SETUP 0x%016lx", sqid,
	cvmx_read_csr(CVMX_NQM_VFX_SQX_SSO_SETUP(sqid, vf)));

	cn73xx_nqm_enable_sq(vf, sqid);
	debug_printf(3, "create io_sq sq %d CVMX_NQM_VFX_SQX_ENA 0x%016lx", sqid, 
	cvmx_read_csr(CVMX_NQM_VFX_SQX_ENA(sqid, vf)));

	debug_printf(2, "NQM: VF %d SQ %d create complete", vf, sqid);

	return 0;
}

/**
 * Delete IO submission queue
 *
 * @param dev: nvme_dev pointer of the controller (VF)
 * @param sqid: SQID to delete
 */
int
cn73xx_nqm_delete_io_sq(struct nvme_dev *dev, uint8_t sqid)
{
	cvmx_nqm_vfx_sqx_cc_t sq_cc;
	volatile cvmx_nqm_vfx_sqx_credit_t sq_cred;
	volatile cvmx_nqm_vfx_sqx_tdbl_t sq_tbdl;
	volatile cvmx_nqm_vfx_sqx_head_t sq_head;
	uint16_t vf = dev->pfvf, cred;
	uint64_t ticks;

	debug_printf(2, "NQM: VF %d SQ %d delete start", vf, sqid);
	if (!sqid) {
		debug_printf(1, "Invalid IO SQID");
		return STATUS_ERROR;
	}

	sq_cc.u64 = cvmx_read_csr(CVMX_NQM_VFX_SQX_CC(sqid, vf));

	NVME_MARKTIME(ticks);
	do {
		sq_tbdl.u32 = cvm_read_csr32(CVMX_PEXP_NQM_VFX_SQX_TDBL(sqid, vf));
		sq_head.u64 = cvmx_read_csr(CVMX_NQM_VFX_SQX_HEAD(sqid, vf));

	} while ((sq_tbdl.s.sqt !=
		(sq_head.s.head % (sq_cc.s.qsize + 1))) && !NVME_TIMEOUT(ticks, NVME_QUEUE_TIMEOUTVAL));

	if ((sq_tbdl.s.sqt != (sq_head.s.head % (sq_cc.s.qsize + 1))))
		debug_printf(1, "Exiting vfid %d iosq %d delete abruptly "
			"after qempty wait timeout", vf, sqid);

	cred = nqm_sq_credits ? nqm_sq_credits : sq_cc.s.qsize;

	NVME_MARKTIME(ticks);
	do {
		sq_cred.u64 = cvmx_read_csr(CVMX_NQM_VFX_SQX_CREDIT(sqid, vf));
	} while ((sq_cred.s.cred != cred) && !NVME_TIMEOUT(ticks, NVME_QUEUE_TIMEOUTVAL));

	if (sq_cred.s.cred != cred)
		debug_printf(1, "Exiting vfid %d iosq %d delete abruptly "
			"after credit wait timeout", vf, sqid);

	cn73xx_nqm_disable_sq(vf, sqid);
	debug_printf(2, "NQM: VF %d SQ %d delete complete", vf, sqid);

	return 0;
}


/**
 * Submit completions to CPL and hence to the host
 *
 * @param dev: NVMe device pointer
 * @param cqid: Completion queueID (Admin/IO)
 * @param compl: 16bytes completion
 */
static int
cn73xx_nqm_cpl_submit(struct nvme_dev *dev,
	uint8_t cqid, cvmx_wqe_tt *wqe, uint8_t *compl)
{
	uint16_t vf = dev->pfvf;
	void *cpl_addr;
	cvmx_nqm_vfx_cplx_tdb_t cpl_tdb;
	cvmx_nqm_vfx_cplx_h_t cpl_h;
	uint8_t sq_id = wqe->word3.qw3.sq_id;
	struct nvme_sub_queue *sq;
	cvmx_nqm_vfx_cqx_ena_t cq_en;

	sq = dev->queue->sq[sq_id];
retry:
	cq_en.u64 = cvmx_read_csr(CVMX_NQM_VFX_CQX_ENA(cqid, vf));

	if (!cq_en.s.enable || !dev->queue || !dev->queue->cq[cqid] ||
			!dev->queue->cq[cqid]->cqes) {
		debug_printf(1, "NQM: Err: CPL submit: CPL queue deleted\n");
		return 0;
	}

	cvmx_rwlock_wp_write_lock(&dev->queue->cq[cqid]->cq_lock);

	cvmx_atomic_fetch_and_bset64_nosync(&sq->cmd_id_arr[LCMDID(wqe)], (CMDID_INVALID << 32));
	
	if (cvmx_atomic_get64((int64_t *)&sq->cmd_id_arr[LCMDID(wqe)]) & 1) {
		cvmx_rwlock_wp_write_unlock(&dev->queue->cq[cqid]->cq_lock);
		npl_handle_aborted_cmd(dev, wqe);
		return 0;
	}

	cpl_tdb.u64 = cvmx_read_csr(CVMX_NQM_VFX_CPLX_TDB(cqid, vf));
	cpl_h.u64 = cvmx_read_csr(CVMX_NQM_VFX_CPLX_H(cqid, vf));

	/* TODO: Temporary work around for CPL queue full condition, synchronization */
	while (((cpl_tdb.s.tail + 1) % nqm_cplq_size) == cpl_h.s.head) {
		/* Wait for some time */
		cvmx_rwlock_wp_write_unlock(&dev->queue->cq[cqid]->cq_lock);
		cvmx_wait_usec(1000);

		goto retry;
	}

	cpl_addr = ((void *)dev->queue->cq[cqid]->cqes) +
			(cpl_tdb.s.tail * COMPLETIONQUEUE_ENTRY_SIZE);

	memcpy(cpl_addr, compl, COMPLETIONQUEUE_ENTRY_SIZE);
	
	CVMX_SYNCWS;
	cpl_tdb.s.tail = (cpl_tdb.s.tail + 1) % nqm_cplq_size; 

	cvmx_write_csr(CVMX_NQM_VFX_CPLX_TDB(cqid, vf), cpl_tdb.u64);

	cvmx_rwlock_wp_write_unlock(&dev->queue->cq[cqid]->cq_lock);

	npl_free_local_cmd_id(dev, sq_id, LCMDID(wqe));
    	cvmx_atomic_add32((int32_t *)&sq->num_entries, -1);

	if (wqe->nvme_cmd.rw.opc == nvme_cmd_read)
		cvmcs_profile_mark_timed_event(PROF_NVME_READ_PROC, wqe->reserved);
	else if (wqe->nvme_cmd.rw.opc == nvme_cmd_write)
		cvmcs_profile_mark_timed_event(PROF_NVME_WRITE_PROC, wqe->reserved);

	return 0;
}

int
cn73xx_submit_completion_entry(struct nvme_dev *dev, uint8_t cqid,
	cvmx_wqe_tt *wqe, uint32_t result, struct completion_status_field cpl_status)
{
	//struct nvme_completion cpl_queue_entry = { 0 };
	struct nvme_cn73xx_completion cpl_queue_entry = { 0 };

	cpl_queue_entry.sqid = wqe->word3.qw3.sq_id;
	cpl_queue_entry.sqhead = 0;//hw sets this
	cpl_queue_entry.cmdid = wqe->nvme_cmd.common.cmdid;
	cpl_queue_entry.result = result;

	if (cpl_status.sct == SCT_GENERIC) {
		debug_printf(3, "STATUS_GENERIC");
		STATUS_GENERIC(cpl_queue_entry.status, cpl_status.sc,
				cpl_status.m, cpl_status.dnr);
	} else if (cpl_status.sct == SCT_COMMAND) {
		debug_printf(3, "STATUS_COMMAND");
		STATUS_COMMAND(cpl_queue_entry.status, cpl_status.sc,
				cpl_status.m, cpl_status.dnr);
	} else {
		debug_printf(3, "STATUS_MEDIA");
		STATUS_MEDIA(cpl_queue_entry.status, cpl_status.sc,
				cpl_status.m, cpl_status.dnr);
	}

	return cn73xx_nqm_cpl_submit(dev, cqid, wqe, (uint8_t *)&cpl_queue_entry);
}

static inline uint64_t xxx_cvmx_read_csr(uint64_t csr_addr)
{
	return cvmx_read64_uint64(csr_addr);
}

static inline uint64_t xxx_cvmx_read_csr_node(uint64_t node, uint64_t csr_addr)
{
	uint64_t node_addr;

	node_addr = (csr_addr & ~CVMX_NODE_IO_MASK) |
				(node & CVMX_NODE_MASK) << CVMX_NODE_IO_SHIFT;
	debug_printf(3, "node %lu node_addr 0x%016lx", node, node_addr);
	
	return xxx_cvmx_read_csr(node_addr);
}


void nvme_dump_csrs(int vf)
{
	int i;

	debug_printf(1, "NQM_VF%d_CAP %lx", vf, cvmx_read_csr(CVMX_PEXP_NQM_VFX_CAP(vf)));
	debug_printf(1, "NQM_VF%d_VS %x", vf, cvm_read_csr32(CVMX_PEXP_NQM_VFX_VS(vf)));
	debug_printf(1, "NQM_VF%d_INTMS %x", vf, cvm_read_csr32(CVMX_PEXP_NQM_VFX_INTMS(vf)));
	debug_printf(1, "NQM_VF%d_INTMC %x", vf, cvm_read_csr32(CVMX_PEXP_NQM_VFX_INTMC(vf)));
	debug_printf(1, "NQM_VF%d_CC %x", vf, cvm_read_csr32(CVMX_PEXP_NQM_VFX_CC(vf)));
	debug_printf(1, "NQM_VF%d_CSTS %x", vf, cvm_read_csr32(CVMX_PEXP_NQM_VFX_CSTS(vf)));
	debug_printf(1, "NQM_VF%d_NSSR %x", vf, cvm_read_csr32(CVMX_PEXP_NQM_VFX_NSSR(vf)));
	debug_printf(1, "NQM_VF%d_AQA %x", vf, cvm_read_csr32(CVMX_PEXP_NQM_VFX_AQA(vf)));
	debug_printf(1, "NQM_VF%d_ASQ %lx", vf, cvmx_read_csr(CVMX_PEXP_NQM_VFX_ASQ(vf)));
	debug_printf(1, "NQM_VF%d_ACQ %lx", vf, cvmx_read_csr(CVMX_PEXP_NQM_VFX_ACQ(vf)));

	for (i = 0; i <= nqm_vf_mode_map[nqm_vf_mode].vf_max_ioq; i++) {
		debug_printf(1, "NQM_VF%d_SQ%d_TDBL %x",
			vf, i, cvm_read_csr32(CVMX_PEXP_NQM_VFX_SQX_TDBL(i,vf)));
		debug_printf(1, "NQM_VF%d_CQ%d_HDBL %x",
			vf, i, cvm_read_csr32(CVMX_PEXP_NQM_VFX_CQX_HDBL(i,vf)));
		debug_printf(1, "NQM_VF%d_SQ%d_ENA %lx",
			vf, i, cvmx_read_csr(CVMX_NQM_VFX_SQX_ENA(i,vf)));
		debug_printf(1, "NQM_VF%d_SQ%d_CREDIT %lx",
			vf, i, cvmx_read_csr(CVMX_NQM_VFX_SQX_CREDIT(i,vf)));
		debug_printf(1, "NQM_VF%d_SQ%d_HEAD %lx",
			vf, i, cvmx_read_csr(CVMX_NQM_VFX_SQX_HEAD(i,vf)));
		debug_printf(1, "NQM_VF%d_SQ%d_FC %lx",
			vf, i, cvmx_read_csr(CVMX_NQM_VFX_SQX_IFC(i,vf)));
	}

	for (i = 1; i <= nqm_vf_mode_map[nqm_vf_mode].vf_max_ioq; i++) {
		debug_printf(1, "NQM_VF%d_SQ%d_CC %lx",
			vf, i, cvmx_read_csr(CVMX_NQM_VFX_SQX_CC(i,vf)));
		debug_printf(1, "NQM_VF%d_SQ%d_PRP %lx",
			vf, i, cvmx_read_csr(CVMX_NQM_VFX_SQX_PRP(i,vf)));
		debug_printf(1, "NQM_VF%d_SQ%d_BASE %lx",
			vf, i, cvmx_read_csr(CVMX_NQM_VFX_SQX_BASE(i,vf)));
		debug_printf(1, "NQM_VF%d_CQ%d_ENA %lx",
			vf, i, cvmx_read_csr(CVMX_NQM_VFX_CQX_ENA(i,vf)));
	}

	debug_printf(1, "NQM_VF%d_ACQ_CC %lx", vf, cvmx_read_csr(CVMX_NQM_VFX_ACQ_CC(vf)));

	for (i = 0; i <= nqm_vf_mode_map[nqm_vf_mode].vf_max_ioq; i++) {
		debug_printf(1, "NQM_VF%d_CPL%d_TDB %lx",
			vf, i, cvmx_read_csr(CVMX_NQM_VFX_CPLX_TDB(i,vf)));
		debug_printf(1, "NQM_VF%d_SQ%d_SSO_SETUP %lx",
			vf, i, cvmx_read_csr(CVMX_NQM_VFX_SQX_SSO_SETUP(i,vf)));
		debug_printf(1, "NQM_VF%d_CPL%d_BASE_ADDR_N_SZ %lx",
			vf, i, cvmx_read_csr(CVMX_NQM_VFX_CPLX_BASE_ADDR_N_SZ(i,vf)));
		debug_printf(1, "NQM_VF%d_CPL%d_H %lx",
			vf, i, cvmx_read_csr(CVMX_NQM_VFX_CPLX_H(i,vf)));
		debug_printf(1, "NQM_VF%d_CPL%d_IFC %lx",
			vf, i, cvmx_read_csr(CVMX_NQM_VFX_CPLX_IFC(i,vf)));
		debug_printf(1, "NQM_VF%d_CQ%d_TAIL %lx",
			vf, i, cvmx_read_csr(CVMX_NQM_VFX_CQX_TAIL(i,vf)));
	}

	for (i = 1; i <= nqm_vf_mode_map[nqm_vf_mode].vf_max_ioq; i++) {
		debug_printf(1, "NQM_VF%d_CQ%d_PRP %lx",
			vf, i, cvmx_read_csr(CVMX_NQM_VFX_CQX_PRP(i,vf)));
		debug_printf(1, "NQM_VF%d_CQ%d_BASE %lx",
			vf, i, cvmx_read_csr(CVMX_NQM_VFX_CQX_BASE(i,vf)));
		debug_printf(1, "NQM_VF%d_CQ%d_CC %lx",
			vf, i, cvmx_read_csr(CVMX_NQM_VFX_CQX_CC(i,vf)));
	}

	debug_printf(1, "NQM_CS_ECC0_INT %lx", cvmx_read_csr(CVMX_NQM_CS_ECC0_INT));
	debug_printf(1, "NQM_CS_MEM_CTL0 %lx", cvmx_read_csr(CVMX_NQM_CS_MEM_CTL0));
	debug_printf(1, "NQM_CS_BIST_STATUS0 %lx", cvmx_read_csr(CVMX_NQM_CS_BIST_STATUS0));
	debug_printf(1, "NQM_VF%d_INT %lx", vf, cvmx_read_csr(CVMX_NQM_VFX_INT(vf)));
	debug_printf(1, "NQM_VF%d_INT_W1S %lx", vf, cvmx_read_csr(CVMX_NQM_VFX_INT_W1S(vf)));
	debug_printf(1, "NQM_VF%d_INT_ENA_W1C %lx",
		vf, cvmx_read_csr(CVMX_NQM_VFX_INT_ENA_W1C(vf)));
	debug_printf(1, "NQM_VF%d_INT_ENA_W1S %lx",
		vf, cvmx_read_csr(CVMX_NQM_VFX_INT_ENA_W1S(vf)));
	debug_printf(1, "NQM_VF_MODE %lx", cvmx_read_csr(CVMX_NQM_VF_MODE));
	debug_printf(1, "NQM_IC_DIV %lx", cvmx_read_csr(CVMX_NQM_IC_DIV));
	debug_printf(1, "NQM_GLBL_TAG %lx", cvmx_read_csr(CVMX_NQM_GLBL_TAG));
	debug_printf(1, "NQM_CFG %lx", cvmx_read_csr(CVMX_NQM_CFG));
	debug_printf(1, "NQM_FI_FPA_AURA %lx", cvmx_read_csr(CVMX_NQM_FI_FPA_AURA));
	debug_printf(1, "NQM_SCRATCH %lx", cvmx_read_csr(CVMX_NQM_SCRATCH));
	debug_printf(1, "NQM_CLKEN %lx", cvmx_read_csr(CVMX_NQM_CLKEN));
	debug_printf(1, "NQM_HS_ECC0_INT %lx", cvmx_read_csr(CVMX_NQM_HS_ECC0_INT));
	debug_printf(1, "NQM_HS_MEM_CTL0 %lx", cvmx_read_csr(CVMX_NQM_HS_MEM_CTL0));
	debug_printf(1, "NQM_HS_BIST_STATUS0 %lx", cvmx_read_csr(CVMX_NQM_HS_BIST_STATUS0));
	debug_printf(1, "NQM_INT %lx", cvmx_read_csr(CVMX_NQM_INT));
	debug_printf(1, "NQM_NCB_TX_ERR_WORD %lx", cvmx_read_csr(CVMX_NQM_NCB_TX_ERR_WORD));
	debug_printf(1, "NQM_NCB_TX_ERR_INFO %lx", cvmx_read_csr(CVMX_NQM_NCB_TX_ERR_INFO));
	debug_printf(1, "NQM_NCB_INT %lx", cvmx_read_csr(CVMX_NQM_NCB_INT));

	for (i = 0; i < 16; i++) {
		debug_printf(1, "NQM_VF%d_VEC%d_MSIX_ADDR %lx",
			vf, i, cvmx_read_csr(CVMX_PEXP_NQM_VFX_VECX_MSIX_ADDR(i,vf)));
		debug_printf(1, "NQM_VF%d_VEC%d_MSIX_CTL %lx",
			vf, i, cvmx_read_csr(CVMX_PEXP_NQM_VFX_VECX_MSIX_CTL(i,vf)));
	}

	debug_printf(1, "NQM_VF%d_MSIX_PBA %lx",
		vf, cvmx_read_csr(CVMX_PEXP_NQM_VFX_MSIX_PBA(vf)));
	debug_printf(1, "NQM_VF%d_IC_THR %lx", vf, cvmx_read_csr(CVMX_NQM_VFX_IC_THR(vf)));
	debug_printf(1, "NQM_VF%d_IC_TIME %lx", vf, cvmx_read_csr(CVMX_NQM_VFX_IC_TIME(vf)));
	debug_printf(1, "NQM_MSIX_DBG_CI_SM %lx", cvmx_read_csr(CVMX_NQM_MSIX_DBG_CI_SM));
	debug_printf(1, "NQM_MSIX_DBG %lx", cvmx_read_csr(CVMX_NQM_MSIX_DBG));

	for (i = 0; i < 16; i++)
		debug_printf(1, "NQM_VF%d_VEC%d_MSIX_CD %lx",
			vf, i, cvmx_read_csr(CVMX_NQM_VFX_VECX_MSIX_CD(i,vf)));

	debug_printf(1, "NQM_VF%d_MSIX_CONFIG %lx",
		vf, cvmx_read_csr(CVMX_NQM_VFX_MSIX_CONFIG(vf)));
	debug_printf(1, "NQM_MSIX_DBG_TW_SM %lx", cvmx_read_csr(CVMX_NQM_MSIX_DBG_TW_SM));

	for (i = 0; i < 16; i++)
		debug_printf(1, "NQM_VF%d_VEC%d_MSIX_INT_ST %lx", vf, i,
			cvmx_read_csr(CVMX_NQM_VFX_VECX_MSIX_INT_ST(i,vf)));
}

void
cn73xx_nqm_reset(struct nvme_dev *dev, aq_delete_cause_t cause)
{
	uint8_t qid, vec;
	uint16_t vf = dev->pfvf;

	for (qid = 0; qid < nqm_vf_mode_map[nqm_vf_mode].vf_max_ioq; qid++) {
		cvmx_write_csr(CVMX_NQM_VFX_SQX_ENA(qid, vf), 0);
		cvmx_write_csr(CVMX_NQM_VFX_CQX_ENA(qid, vf), 0);
	}

	//cvmx_write_csr(CVMX_NQM_VFX_INT_ENA_W1C(vf), 0xffffffff);

	if (cause != AQ_DEL_CC_DIS) {
		cvm_write_csr32(CVMX_PEXP_NQM_VFX_AQA(vf), 0);
		cvm_write_csr32(CVMX_PEXP_NQM_VFX_CC(vf), 0);
		cvmx_write_csr(CVMX_PEXP_NQM_VFX_ASQ(vf), 0);
		cvmx_write_csr(CVMX_PEXP_NQM_VFX_ACQ(vf), 0);

		for (vec = 0; vec < 16; vec++) {
			cvmx_write_csr(CVMX_PEXP_NQM_VFX_VECX_MSIX_ADDR(vec, vf), 0);
			cvmx_write_csr(CVMX_PEXP_NQM_VFX_VECX_MSIX_CTL(vec, vf), 0);
			cvmx_write_csr(CVMX_NQM_VFX_VECX_MSIX_CD(vec, vf), 0);
		}

		cvmx_write_csr(CVMX_PEXP_NQM_VFX_MSIX_PBA(vf), 0);
	}

	cvmx_write_csr(CVMX_NQM_VFX_ACQ_CC(vf), 0);

	for (qid = 0; qid < nqm_vf_mode_map[nqm_vf_mode].vf_max_ioq; qid++) {
		cvmx_write_csr(CVMX_NQM_VFX_CPLX_TDB(qid, vf), 0);
		cvmx_write_csr(CVMX_NQM_VFX_CPLX_H(qid, vf), 0);
		cvmx_write_csr(CVMX_NQM_VFX_CPLX_BASE_ADDR_N_SZ(qid, vf), 0);

		cvm_write_csr32(CVMX_PEXP_NQM_VFX_SQX_TDBL(qid, vf), 0);
		cvmx_write_csr(CVMX_NQM_VFX_SQX_CREDIT(qid, vf), 0);
		cvmx_write_csr(CVMX_NQM_VFX_SQX_HEAD(qid, vf), 0);
		cvmx_write_csr(CVMX_NQM_VFX_SQX_SSO_SETUP(qid, vf), 0);

		cvm_write_csr32(CVMX_PEXP_NQM_VFX_CQX_HDBL(qid, vf), 0);
		cvmx_write_csr(CVMX_NQM_VFX_CQX_TAIL(qid, vf), 0);

		if (qid) {
			cvmx_write_csr(CVMX_NQM_VFX_SQX_CC(qid, vf), 0);
			cvmx_write_csr(CVMX_NQM_VFX_SQX_PRP(qid, vf), 0);
			cvmx_write_csr(CVMX_NQM_VFX_SQX_BASE(qid, vf), 0);

			cvmx_write_csr(CVMX_NQM_VFX_CQX_PRP(qid, vf), 0);
			cvmx_write_csr(CVMX_NQM_VFX_CQX_BASE(qid, vf), 0);
			cvmx_write_csr(CVMX_NQM_VFX_CQX_CC(qid, vf), 0);
		}
	}

	cvmx_write_csr(CVMX_NQM_VFX_INT(vf), 0xffffffff);
	cvmx_write_csr(CVMX_NQM_VFX_IC_THR(vf), 0);
	cvmx_write_csr(CVMX_NQM_VFX_IC_TIME(vf), 0);
	cvm_write_csr32(CVMX_PEXP_NQM_VFX_CSTS(vf), 0);
}

int
cn73xx_get_intr_coalescing(struct nvme_dev *dev,
	uint8_t *thr, uint8_t *time)
{
	cvmx_nqm_vfx_ic_thr_t ic_thr;
	cvmx_nqm_vfx_ic_time_t ic_time;
	int pfvf = dev->pfvf;

	ic_thr.u64 = cvmx_read_csr(CVMX_NQM_VFX_IC_THR(pfvf));
	*thr	= ic_thr.s.thr;

	ic_time.u64 = cvmx_read_csr(CVMX_NQM_VFX_IC_TIME(pfvf));
	*time = ic_time.s.ctime;

	return STATUS_SUCCESS;
}

int
cn73xx_set_intr_coalescing(struct nvme_dev *dev,
	uint8_t thr, uint8_t time)
{
	cvmx_nqm_vfx_ic_thr_t ic_thr;
	cvmx_nqm_vfx_ic_time_t ic_time;
	int pfvf = dev->pfvf;

	ic_thr.u64	= 0;
	ic_thr.s.thr	= thr;
	cvmx_write_csr(CVMX_NQM_VFX_IC_THR(pfvf), ic_thr.u64);

	ic_time.u64	= 0;
	ic_time.s.ctime = time;
	cvmx_write_csr(CVMX_NQM_VFX_IC_TIME(pfvf), ic_time.u64);

	return STATUS_SUCCESS;
}

int
cn73xx_cfg_intr_vect(struct nvme_dev *dev, uint16_t iv, uint8_t cd)
{
	cvmx_nqm_vfx_vecx_msix_cd_t msix_cd;
	int pfvf = dev->pfvf;

	if (iv > 16)
		return STATUS_ERROR;

	msix_cd.u64 = 0;
	msix_cd.s.cd = cd;
	cvmx_write_csr(CVMX_NQM_VFX_VECX_MSIX_CD(iv, pfvf), msix_cd.u64);

	return STATUS_SUCCESS;
}

int
cn73xx_get_intr_vect_cfg(struct nvme_dev *dev, uint16_t iv, uint8_t *cd)
{
	cvmx_nqm_vfx_vecx_msix_cd_t msix_cd;
	int pfvf = dev->pfvf;

	if (iv > 16)
		return STATUS_ERROR;

	msix_cd.u64 = cvmx_read_csr(CVMX_NQM_VFX_VECX_MSIX_CD(iv, pfvf));
	*cd = msix_cd.s.cd;

	return STATUS_SUCCESS;
}

/***************************************************************************//**

Process nqm init

Initializes the nqm hardware interface module.

*******************************************************************************/

int nqm_init(void)
{
	int ret = 0;
	int vf;

	debug_printf(1, "nqm init:");

	// initialize config module
	ret = nvme_config_init();
	if (ret < 0)
		return ret;

	// initialize sal module
	ret = sal_init();
	if (ret < 0)
		return ret;

	/*
	 * Initialize global NQM registers
	 */
	ret = nqm_global_reg_init();
	if(ret < 0)
		return ret;

	/*
	 * set up interrupt vectors
	 */
	ret = nqm_set_intvec();
	if(ret < 0)
		return ret;

	/*
	 * Create dev[0], or the PF
	 */
	debug_printf(1, "VF mode: 1PF and %d VFs\n" ,
			nqm_vf_mode_map[nqm_vf_mode].vf_cnt - 1);

	// preinitialize all vfs
	for (vf = 0; vf < nqm_vf_mode_map[nqm_vf_mode].vf_cnt; vf++)
		nvme_init_dev(vf);

	return ret;
}

/***************************************************************************//**

Process nqm deinit

Deinitializes the nqm hardware interface module.

*******************************************************************************/

int nqm_deinit(void)
{
	return 0;
}

