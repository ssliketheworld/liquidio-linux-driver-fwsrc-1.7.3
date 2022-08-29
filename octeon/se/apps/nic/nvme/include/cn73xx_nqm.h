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
#ifndef __73XX_NQM_H__
#define __73XX_NQM_H__

#include "cvmx-interrupt.h"
#include "nvme_cvm.h"
#include "cvmx-nqm-defs.h"
#include "cn73xx_nqm_defines.h"

enum NQM_VF_MODE_E {
	NQM_PF_MODE = 0,
	NQM_VF_MODE_0 = 0,
	NQM_VF_MODE_1,
	NQM_VF_MODE_2,
	NQM_VF_MODE_RSVD,
};

#define NQM_MSIX_COALESCE_DIV 0x61a8
#define NQM_FPA_WQE_RETRY_TIMEO 0xa

#define NQM_AQ_ID			0
#define NQM_SQ_SSO_GROUP		0
#define NQM_SQ_CREDITS_RESET_VAL	0xFFF
#define NQM_CPL_LOCK_TAG		0x1111

typedef enum NQM_TAG_MODE {
	NQM_TAG_GLBL,
	NQM_TAG_GLBL_VF,
	NQM_TAG_GLBL_VF_SQID,
} NQM_TAG_MODE_E;

typedef struct nqm_vf_mode_map {
	uint16_t vf_cnt;
	uint8_t vf_max_ioq;
} nqm_vf_mode_map_t;

typedef struct cvmx_nqm_interrupt_handler {
	struct cvmx_interrupt nqm_irq;
	uint32_t intsn;
} cvmx_nqm_interrupt_handler_t;

#define NQM_INTSN			0x45
#define NQM_CC_INTSN			0x46

#define NQM_CS_ERR_NCBO_FIF_RAM		0x00000001
#define NQM_CS_ERR_NCBI_L2_OUT_RAM	0x00000002
#define NQM_CS_ERR_NCBI_PP_OUT_RAM	0x00000004
#define NQM_CS_ERR_NCB_ST_FIF_RAM	0x00000008
#define NQM_CS_ERR_NQM_CS_CQ_ST_RAM	0x00000010
#define NQM_CS_ERR_NQM_CS_CPL_ST_RAM	0x00000020
#define NQM_CS_ERR_NQM_CS_CPL_VF_RAM	0x00000030
#define NQM_CS_ERR_NQM_CS_CMD_SSO_RAM	0x00000040
#define NQM_CS_ERR_NQM_INTR_RAM		0x00000100
#define NQM_CS_ERR_NQM_CS_IV_ACQ_RAM	0x00000200
#define NQM_CS_ERR_NQM_CS_IV_IOCQ_RAM	0x00000400

#define NQM_CS_ERR_DBE_MASK		0x00000000000007ff
#define NQM_CS_ERR_SBE_MASK		0x000000007ff00000
#define NQM_CS_ERR_DBE_INTR_COUNT	11
#define NQM_CS_ERR_SBE_INTR_COUNT	11

#define NQM_HS_ERR_VF_SRAM		0x00000001
#define NQM_HS_ERR_SQ_STATE_RAM		0x00000002
#define NQM_HS_ERR_SQ_CMD_FIFO		0x00000004
#define NQM_HS_ERR_SQ_PRP_FIFO		0x00000008
#define NQM_HS_ERR_M2S_PN_FIFO		0x00000010
#define NQM_HS_ERR_S2M_C_FIFO		0x00000020
#define NQM_HS_ERR_SQ_CSB_FIFO		0x00000040
#define NQM_HS_ERR_CQ_CPL_FIFO		0x00000080
#define NQM_HS_ERR_CQ_CSB_FIFO		0x00000100
#define NQM_HS_ERR_CQ_CSB_SQHD_FIFO	0x00000200
#define NQM_HS_ERR_CQ_MSIX_FIFO		0x00000400
#define NQM_HS_ERR_VEC_SRAM		0x00000800
#define NQM_HS_ERR_VF_THRESH_SRAM	0x00001000
#define NQM_HS_ERR_VF_PBA_SRAM		0x00002000
#define NQM_HS_ERR_CQ_PRP_FIFO		0x00004000
#define NQM_HS_ERR_IV_ST_EMP_SRAM	0x00008000

#define NQM_HS_ERR_DBE_MASK		0x000000000000ffff
#define NQM_HS_ERR_SBE_MASK		0x0000000ffff00000
#define NQM_HS_ERR_DBE_INTR_COUNT	16
#define NQM_HS_ERR_SBE_INTR_COUNT	16

#define NQM_NCB_INT_MASK		0x00000001
#define NQM_NCB_INT_COUNT		1
 
#define NQM_INT_PCIE_MAC_RESET 		0x00000001
#define NQM_INT_PCIE_VF_ENABLE_CLR 	0x00000002
#define NQM_INT_FPA_NO_PTRS 		0x00000004
#define NQM_GLB_INT_MASK		0x00000007
#define NQM_GLB_INT_COUNT		3


#define NQM_INTSN_CS_DBE0		0x45000
#define NQM_INTSN_CS_DBE0_BIT(_cs_err)	(NQM_INTSN_CS_DBE0 + _cs_err)
#define NQM_INTSN_CS_SBE0		0x45014
#define NQM_INTSN_CS_SBE0_BIT(_cs_err)	(NQM_INTSN_CS_SBE0 + _cs_err)
#define NQM_INTSN_NCB_TX_ERR		0x450FF
#define NQM_INTSN_HS_DBE0		0x45100
#define NQM_INTSN_HS_DBE0_BIT(_hs_err)	(NQM_INTSN_HS_DBE0 + _hs_err)
#define NQM_INTSN_HS_SBE0		0x45114
#define NQM_INTSN_HS_SBE0_BIT(_hs_err)	(NQM_INTSN_HS_SBE0 + _hs_err)
#define NQM_INTSN_PCIE_MAC_RESET	(0x451FD)
#define NQM_INTSN_PCIE_VF_ENABLE_CLR	(0x451FE)
#define NQM_INTSN_FPA_NO_PTRS		(0x451FF)
#define NQM_INTSN_VFX_INT(_vf)		(0x46000 + _vf)

#define NQM_INT_VF_INTR_CCW		0x00000001
#define NQM_INT_FLR			0x00000002
#define NQM_INT_SQ_DB			0x00000004
#define NQM_INT_SQ_DB_VAL		0x00000008
#define NQM_INT_CQ_DB			0x00000010
#define NQM_INT_CQ_DB_VAL		0x00000020
#define NQM_INT_ACQ_CFG			0x00000040
#define NQM_INT_ASQ_CFG			0x00000080
#define NQM_INT_CQ_FE			0x00000100
#define NQM_INT_SQ_FE			0x00000200
#define NQM_INT_SLI_ERR			0x00000400

#define NQM_VF_INTR_MASK		0x000007ff
#define NQM_INTR_COUNT		(NQM_CS_ERR_DBE_INTR_COUNT + NQM_CS_ERR_SBE_INTR_COUNT + \
				NQM_HS_ERR_DBE_INTR_COUNT + NQM_HS_ERR_SBE_INTR_COUNT + \
				NQM_NCB_INT_COUNT + NQM_GLB_INT_COUNT + NQM_VF_MODE2_VF_MAX)

#define nqm_intr_register(__nqm_irq, __vec, __intsn, __handler)	\
	do {							\
		__nqm_irq[__vec].nqm_irq.handler= __handler;	\
		__nqm_irq[__vec].intsn		= __intsn;	\
		cvmx_interrupt_register(__nqm_irq[__vec].intsn,	\
			&__nqm_irq[__vec].nqm_irq);		\
		__nqm_irq[__vec].nqm_irq.unmask(&__nqm_irq[__vec].nqm_irq); \
	} while (0);

typedef union  {
	uint64_t u64;

	struct {
		uint64_t scraddr : 8;
		uint64_t len : 8;
		uint64_t did : 8;
		uint64_t reserved_38_39 : 2;
		uint64_t node:2;
		uint64_t address : 36;
	} s;
} cvmcs_pcie_iobdma_t;

#if 0
typedef union  {
	uint64_t u64;

	struct {
		uint64_t scraddr : 8;
		uint64_t len : 8;
		uint64_t did : 8;
		uint64_t node:4;
		uint64_t se:2;
		uint64_t address : 34;
	} s;
} cvmcs_pcie_iobdma_t;
#endif

int cn73xx_nqm_create_admin_sq(struct nvme_dev *dev);
int cn73xx_nqm_delete_admin_sq(struct nvme_dev *dev);
int cn73xx_nqm_create_admin_cq(struct nvme_dev *dev);
int cn73xx_nqm_delete_admin_cq(struct nvme_dev *dev);
int cn73xx_nqm_create_io_cq(struct nvme_dev *dev, uint8_t cqid, uint16_t q_size,
	uint64_t prp, uint8_t pc, uint16_t iv, uint8_t ien,
	struct completion_status_field *cpl_entry);
int cn73xx_nqm_delete_io_cq(struct nvme_dev *dev, uint8_t cqid);
int cn73xx_nqm_create_io_sq(struct nvme_dev *dev, uint8_t sqid,
		uint16_t q_size, void *prp, uint8_t pc);
int cn73xx_nqm_delete_io_sq(struct nvme_dev *dev, uint8_t sqid);
int cn73xx_submit_completion_entry(struct nvme_dev *dev, uint8_t cqid,
        cvmx_wqe_tt *wqe, uint32_t result, struct completion_status_field cpl_status);
void cn73xx_nqm_reset(struct nvme_dev *dev, aq_delete_cause_t cause);
int cn73xx_get_intr_coalescing(struct nvme_dev *dev,
	uint8_t *ic_thr, uint8_t *ic_time);
int cn73xx_set_intr_coalescing(struct nvme_dev *dev,
	uint8_t ic_thr, uint8_t ic_time);
int cn73xx_cfg_intr_vect(struct nvme_dev *dev, uint16_t iv, uint8_t cd);
int cn73xx_get_intr_vect_cfg(struct nvme_dev *dev, uint16_t iv, uint8_t *cd);
void nvme_dump_csrs(int vf);


/**
 * Disable Admin/IO SQ
 * @param vf: VF number
 * @param sqid: Submission queueID
 * @param enable: enable/disable flag
 */
static inline void
cn73xx_nqm_disable_sq(uint16_t vf, uint8_t sqid)
{
	volatile cvmx_nqm_vfx_sqx_ena_t sq_en;
	uint64_t ticks;

	/* enable/disable admin SQ */
	sq_en.u64		= 0;
	sq_en.s.enable		= 0;
	cvmx_write_csr_node(cvmx_get_node_num(),
		CVMX_NQM_VFX_SQX_ENA(sqid, vf), sq_en.u64);

	NVME_MARKTIME(ticks);
	do {
		sq_en.u64 = cvmx_read_csr_node(cvmx_get_node_num(),
			CVMX_NQM_VFX_SQX_ENA(sqid, vf));
	} while (sq_en.s.enable && !NVME_TIMEOUT(ticks, NVME_QUEUE_TIMEOUTVAL));

	if (sq_en.s.enable)
		debug_printf(1, "Exiting sq %d disable abruptly after timeout", sqid);
}

/**
 * Enable Admin/IO SQ
 * @param vf: VF number
 * @param sqid: Submission queueID
 */
static inline void
cn73xx_nqm_enable_sq(uint16_t vf, uint8_t sqid)
{
	cvmx_nqm_vfx_sqx_ena_t sq_en;

	/* enable/disable admin SQ */
	sq_en.u64		= 0;
	sq_en.s.enable		= 1;
	cvmx_write_csr_node(cvmx_get_node_num(), CVMX_NQM_VFX_SQX_ENA(sqid, vf), sq_en.u64);
}


static inline void
cn73xx_nqm_disable_cq(uint16_t vf, uint8_t cqid)
{
	volatile cvmx_nqm_vfx_cqx_ena_t cq_en;
	uint64_t ticks;

	/* Enable/Disable admin CQ */
	cq_en.u64		= 0;
	cq_en.s.enable		= 0;
	cvmx_write_csr_node(cvmx_get_node_num(), CVMX_NQM_VFX_CQX_ENA(cqid, vf), cq_en.u64);

	NVME_MARKTIME(ticks);
	do {
		cq_en.u64 = cvmx_read_csr_node(cvmx_get_node_num(),
			CVMX_NQM_VFX_CQX_ENA(cqid, vf));
	} while (cq_en.s.enable && !NVME_TIMEOUT(ticks, NVME_QUEUE_TIMEOUTVAL));

	if (cq_en.s.enable)
		debug_printf(1, "Exiting cq %d disable abruptly after timeout", cqid);
}

/**
 * Enable Admin/IO CQ
 * @param vf: VF number
 * @param cqid: Completion queueID
 */
static inline void
cn73xx_nqm_enable_cq(uint16_t vf, uint8_t cqid)
{
	cvmx_nqm_vfx_cqx_ena_t cq_en;

	/* Enable/Disable admin CQ */
	cq_en.u64		= 0;
	cq_en.s.enable		= 1;
	cvmx_write_csr_node(cvmx_get_node_num(), CVMX_NQM_VFX_CQX_ENA(cqid, vf), cq_en.u64);
}
#endif
