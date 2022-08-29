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
*
*  \file
*
*  \brief This module contains the code for the nvme processing layer.
*
*******************************************************************************/

/*---------------------------------------------------------------------------
 *                               Revision History
 *                                           $Log: npl_nvme.c $
 *  ---------------------------------------------------------------------------*/
#include "nvme_cvm.h"
#include "sal_linux_bdev.h"
#include "cvmx-helper.h"
#include "cvmx-config.h"
#include "cvmcs-nic-defs.h"
#include "cvmcs-common.h"
#include "cvmx-nqm-defs.h"
#include "cvmcs-profile.h"
#include "cn73xx_nqm.h"
#include "nvme_stats.h"

// Note that we need to remove all references to nvme_bar1 in this code [saf]
#ifdef NVME_68XX_SUPPORT
// this is only needed for emulation
extern CVMX_SHARED struct nvme_bar *nvme_bar1;
#endif

#define MIN_QUEUE_ENTRIES 2

extern CVMX_SHARED nqm_vf_mode_map_t nqm_vf_mode_map[];
extern CVMX_SHARED uint8_t nqm_vf_mode;
extern CVMX_SHARED struct nvme_queue* nvme_queue_base;
extern CVMX_SHARED  int gbl_host_page_size_pool;
extern CVMX_SHARED  int gbl_host_page_size;
extern CVMX_SHARED struct nvme_dev *nqm_device_structs[NVME_NUM_PFVF];
extern CVMX_SHARED uint16_t nqm_cplq_size;
extern CVMX_SHARED char *nvme_stats_mem;

CVMX_SHARED nvme_queue_mem_t gbl_nvme_queue_mem[NVME_NUM_PFVF] = {{0}};
CVMX_SHARED uint8_t nqm_intr_coalescing = 1;

uint8_t io_dma_queue[NVME_IO_DMAQ_MAX] = {1, 2, 3, 5, 6, 7};

static void npl_abort_async_event_req(struct nvme_dev *dev);

/***************************************************************************//**
*
*   Set controller fail status
*
*   Sets the controller fail status bit.
*
*       @param dev     Pointer to device private structure
*
*******************************************************************************/

void npl_fail_status(struct nvme_dev *dev)
{
	cvm_write_csr32(CVMX_NQM_VFX_CSTS(dev->pfvf),
	                cvm_read_csr32(CVMX_NQM_VFX_CSTS(dev->pfvf)) |  NVME_CSTS_CFS);
}

/***************************************************************************//**
*
*   npl_controller_enable()
*
*   Create admin submission and completion queues for device.
*
*       @param dev     Pointer to device private structure
*
*******************************************************************************/

int npl_controller_enable(struct nvme_dev *dev)
{
	int host_page_size;
	int ret;

	debug_printf(3, "controller enable");
	if(!(cvm_read_csr32(CVMX_PEXP_NQM_VFX_CSTS(dev->pfvf)) & NVME_CSTS_RDY) &&
	    (cvm_read_csr32(CVMX_PEXP_NQM_VFX_AQA(dev->pfvf)) != 0) )
	{
		if(cvmx_read_csr_node(cvmx_get_node_num(),
			CVMX_PEXP_NQM_VFX_ASQ(dev->pfvf)) != 0) {
			/* Create Admin submission queue */
			ret = npl_create_admin_sub_queue(dev);
			if (ret != STATUS_SUCCESS) goto fail;

		}
		if(cvmx_read_csr_node(cvmx_get_node_num(),
			CVMX_PEXP_NQM_VFX_ACQ(dev->pfvf)) != 0) {
			/* Create Admin completion queue */
			ret = npl_create_admin_cpl_queue(dev);
			if (ret != STATUS_SUCCESS) goto fail;
		}
	}

	cvmx_atomic_set32(&dev->vf_active, 1);

	memset(dev->event_info, 0, sizeof(struct async_event_info));

	if (nqm_intr_coalescing)
		cn73xx_set_intr_coalescing(dev, 255, 1);

	/**
	 * Initialize FPA pool for host page size after reading
	 * CC.MPS register.
	 *
	 * Host Page size shall be intact across controller reset.
	 * The Host Page size is allocated using boot_mem_alloc which
	 * can not be freed.
	 */
	host_page_size = 1 << GET_HOST_PAGE_SHIFT(dev);
	if (gbl_host_page_size_pool == -1) {
		if (cvmcs_app_mem_alloc("DEV_HOST_PG_SZ",
		                         DEV_HOST_PAGE_SIZE_POOL,
		                         npl_calc_fpa_pool_size(
		                                  host_page_size),
		                         DEV_HOST_PAGE_SIZE_POOL_COUNT))
                        debug_printf(1,
                                     "List_DEV_HOST_PG_SZ Allocation failed");

			gbl_host_page_size_pool = DEV_HOST_PAGE_SIZE_POOL;
			gbl_host_page_size = host_page_size;
	} else {
		if (host_page_size  != gbl_host_page_size) {
			debug_printf(1, "multiple page sizes needed by hosts. "
				"not yet handled\n");
		}
	}

	if (!dev->page_flag_set) {
		dev->host_page_size = gbl_host_page_size;
		dev->num_prp_per_host_page =
			dev->host_page_size / PRP_ENTRY_SIZE;
			dev->page_flag_set = 1;
	}

#if DISCONTIGUOUS_Q_SUPPORT
	dev->max_sq_entry_per_page =
		dev->host_page_size /
			(1 << ((cvm_read_csr32(CVMX_PEXP_NQM_VFX_CC(dev->pfvf)) >> 16) & 0x0F));
	dev->max_cq_entry_per_page = dev->host_page_size /
		(1 << (cvm_read_csr32(CVMX_PEXP_NQM_VFX_CC(dev->pfvf)) >> 20 & 0x0000000F));
	dev->max_discontiguous_sq_size = dev->num_prp_per_host_page *
	                                     dev->max_sq_entry_per_page;
	dev->max_discontiguous_cq_size = dev->num_prp_per_host_page *
	                                     dev->max_cq_entry_per_page;
#endif

	cvm_write_csr32(CVMX_PEXP_NQM_VFX_CSTS(dev->pfvf),
	                cvm_read_csr32(CVMX_PEXP_NQM_VFX_CSTS(dev->pfvf)) |  NVME_CSTS_RDY);
	cvmx_atomic_set32((int32_t *)&(dev->system_state), SYSTEM_READY);

	return STATUS_SUCCESS;

fail:
	return STATUS_ERROR;
}

/***************************************************************************//**
*
*   npl_delete_admin_queues()
*
*   Delete admin SQ and CQ
*
*       @param dev     Pointer to device private structure
*
*******************************************************************************/

void npl_delete_admin_queues(struct nvme_dev *dev, aq_delete_cause_t cause)
{
    struct nvme_list *cpl_list_entry, *tmp_entry;

    cvmx_atomic_set32(&dev->vf_active, 0);

    if (!dev->queue)
        return;

    npl_abort_async_event_req(dev);

    if (dev->queue->sq[0] != NULL) {
        if (OCTEON_IS_MODEL(OCTEON_CN73XX))
            cn73xx_nqm_delete_admin_sq(dev);
        /* Reset ASQ tail */
#ifdef NVME_68XX_SUPPORT
        if (!OCTEON_IS_MODEL(OCTEON_CN73XX)) {
            cvmx_atomic_set32((int32_t *)((uint8_t *)nvme_bar1 +
                                          NVME_DOORBELL_OFFSET), 0);
        }
#endif
    }

    if (dev->queue->cq[0] != NULL) {
        if (OCTEON_IS_MODEL(OCTEON_CN73XX))
            cn73xx_nqm_delete_admin_cq(dev);

        /* Free all the entries from list */
        list_for_each_entry_safe(cpl_list_entry, tmp_entry,
                                 &dev->queue->cq[0]->cpl_list.list, list){
            /*Freeing the memory for each entry from the completion list */
            npl_fpa_free(cpl_list_entry->data, CPL_QUEUE_UPDATE_POOL,
                         sizeof(struct nvme_completion));
            list_del(&cpl_list_entry->list);
            npl_fpa_free(cpl_list_entry, LIST_NODE_POOL,
                         sizeof(struct nvme_list));
        }

#ifdef NVME_68XX_SUPPORT
        if (!OCTEON_IS_MODEL(OCTEON_CN73XX)) {
            /*Reset ACQ head */
            cvmx_atomic_set32((int32_t *)((uint8_t *)nvme_bar1 +
                                          (NVME_DOORBELL_OFFSET + 4)), 0);
        }
#endif
        dev->queue = NULL;
    }

    if (OCTEON_IS_MODEL(OCTEON_CN73XX)) {
        cn73xx_nqm_reset(dev, cause);
    } else {
        npl_reset_nvme_bar(dev);

        cvm_write_csr32(CVMX_PEXP_NQM_VFX_CSTS(dev->pfvf),
            cvm_read_csr32(CVMX_PEXP_NQM_VFX_CSTS(dev->pfvf)) & NVME_CSTS_RDY_RESET);
    }
    cvmx_atomic_set32((int32_t *)&(dev->system_state), SYSTEM_RESET);

}

/***************************************************************************//**
*
*   npl_controller_disable()
*
*   Delete all I/O submission and completion queues.
*
*       @param dev     Pointer to device private structure
*
*******************************************************************************/

void npl_controller_disable(struct nvme_dev *dev)
{
    uint16_t i;
    struct completion_status_field cpl_entry;
    uint32_t result;

    if (!dev->queue)
        return;

    /* Delete all the I/O submission queues */
    for (i = 1; i < dev->queue->max_sub_queues; i++) {
        if (dev->queue->sq[i] != NULL)
            npl_delete_io_sq(dev, i, &cpl_entry, &result);
    }
    /* Delete all the I/O completion queues */
    for (i = 1; i < dev->queue->max_cpl_queues; i++) {
        if (dev->queue->cq[i] != NULL)
            npl_delete_io_cq(dev, i, &cpl_entry, &result);
    }
}

/***************************************************************************//**
*
*   npl_controller_configuration()
*
*   This function handles the NVMe controller configuration register write
*   requests.
*
*    @param dev     Pointer to device private structure
*
*******************************************************************************/
void npl_controller_configuration(struct nvme_dev *dev)
{
    int ret;
    int pfvf = dev->pfvf;

    uint32_t cc = cvm_read_csr32(CVMX_PEXP_NQM_VFX_CC(dev->pfvf));

    /*  EN transition from ' 0' to '1'  - controller init */
    if (!(dev->old_cc & NVME_CC_ENABLE) && (cc & NVME_CC_ENABLE)) {
        debug_printf(1, "Controller %d enable: CC %x",  dev->pfvf, cc);
        ret = npl_controller_enable(dev);
        if (ret != STATUS_SUCCESS) {
            debug_printf(1, "Controller %d enable failed", dev->pfvf);

            return;
        }
        debug_printf(1, "Controller %d enable done: CC %x",  dev->pfvf, cc);

        dev->old_cc = cc;
        cvmx_atomic_add64(&nvme_global_stats->active_vfs, 1);
        test_and_set_bit(pfvf, nvme_global_stats->vf_bitmap);
        return;
    }

#if 0
    // In all other cases, schedule a work.
    wqe = npl_fpa_alloc(dev, CVMX_FPA_WQE_POOL);
    if (wqe) {
        wqe->word1.qw1.tag =
            (NQM_INTR_HANDLE_TAG << NQM_TAG_SHIFT) | dev->pfvf;
        wqe->word1.qw1.tt = CVMX_POW_TAG_TYPE_ATOMIC;
        wqe->word3.qw3.vf = dev->pfvf;
        wqe->word1.qw1.grp = 0;
        npl_setup_wqe(wqe);

        cvmx_pow_work_submit_node((cvmx_wqe_t *)wqe, wqe->word1.qw1.tag,
                CVMX_POW_TAG_TYPE_ATOMIC, cvmx_wqe_get_xgrp((cvmx_wqe_t *)wqe),
                cvmx_get_node_num());

        return;
    }
#endif

    // WQE alloc failed. Shutdown controller in intr itself
    npl_controller_shutdown(dev);
}

void
npl_controller_shutdown(struct nvme_dev *dev)
{
    uint32_t cc;

    if (!dev) {
        return;
    }

    cc = cvm_read_csr32(CVMX_PEXP_NQM_VFX_CC(dev->pfvf));

    if ((dev->old_cc & NVME_CC_ENABLE) && !(cc & NVME_CC_ENABLE)) {
        debug_printf(1, "Controller %d disable: CC %x", dev->pfvf, cc);
        npl_controller_disable(dev);
        npl_delete_admin_queues(dev, AQ_DEL_CC_DIS);
        nqm_device_structs[dev->pfvf] = NULL;
        debug_printf(1, "Controller %d disable done", dev->pfvf);
        cvmx_atomic_add64(&nvme_global_stats->active_vfs, -1);
        test_and_clear_bit(dev->pfvf, nvme_global_stats->vf_bitmap);
        memset(dev, 0, sizeof(struct nvme_dev));

        return;
    }

    if (cc & NVME_CC_SHN_ABRUPT) {
        debug_printf(1, "Controller %d abrupt shutdown: CC %x", dev->pfvf, cc);
        npl_controller_disable(dev);
        npl_delete_admin_queues(dev, AQ_DEL_SHUTDOWN);
        cvm_write_csr32(CVMX_PEXP_NQM_VFX_CSTS(dev->pfvf),
            (cvm_read_csr32(CVMX_PEXP_NQM_VFX_CSTS(dev->pfvf)) & ~NVME_CSTS_SHST_MASK) |
            NVME_CSTS_SHST_COMPLETE);
        nqm_device_structs[dev->pfvf] = NULL;
        debug_printf(1, "Controller %d abrupt shutdown done", dev->pfvf);
        cvmx_atomic_add64(&nvme_global_stats->active_vfs, -1);
        test_and_clear_bit(dev->pfvf, nvme_global_stats->vf_bitmap);
        memset(dev, 0, sizeof(struct nvme_dev));

        return;
    }

    if (cc & NVME_CC_SHN_NORMAL) {
        debug_printf(1, "Controller %d normal shutdown: CC %x", dev->pfvf, cc);
        npl_delete_admin_queues(dev, AQ_DEL_SHUTDOWN);
        cvm_write_csr32(CVMX_PEXP_NQM_VFX_CSTS(dev->pfvf),
            (cvm_read_csr32(CVMX_PEXP_NQM_VFX_CSTS(dev->pfvf)) & ~NVME_CSTS_SHST_MASK) |
            NVME_CSTS_SHST_COMPLETE);
        nqm_device_structs[dev->pfvf] = NULL;
        debug_printf(1, "Controller %d normal shutdown done", dev->pfvf);
        cvmx_atomic_add64(&nvme_global_stats->active_vfs, -1);
        test_and_clear_bit(dev->pfvf, nvme_global_stats->vf_bitmap);
        memset(dev, 0, sizeof(struct nvme_dev));

        return;
    }
}

/*******************************************************************************
*    npl_alloc_block()
*
*   This function returns the memory pointer from the requested memory pool.
*   The memory pools should be setup before requesting memory from it.
*   The return memory pointer is always aligned cache line size.
*
*		@param dev          Pointer to device structure nvme_dev
*       @param qid			SQ-ID for which command memory is allocated
*       @param que_type		Allocate memory for specified queue type
*       @param size			Size in bytes of block to allocate
*
*******************************************************************************/
void *npl_alloc_block(struct nvme_dev * dev,
                              uint16_t          qid,
                              QUEUE_TYPE_T      que_type,
                              uint64_t          size)
{
    uint32_t support_que_depth;
    uint64_t allocate_mem_base = 0x00ULL;

    support_que_depth = le16_cpu(dev->dev_config.cap_mqes) + 1;

    switch (que_type) {
    case SUBMISSION_QUEUE:
        allocate_mem_base =
            dev->queue->base_addr_sq_cmds +
            (qid * npl_calc_fpa_pool_size(SUBQUEUE_ENTRY_SIZE *
                                          support_que_depth));
        break;

    case COMPLETION_QUEUE:
        allocate_mem_base =
            dev->queue->base_addr_cq_cmds +
            (qid * npl_calc_fpa_pool_size(COMPLETIONQUEUE_ENTRY_SIZE *
                                          nqm_cplq_size));
        break;

    case SUBMISSION_QUEUE_STRUCT:
        allocate_mem_base =
            dev->queue->base_addr_sq_struct +
            (qid * npl_calc_fpa_pool_size(sizeof(struct nvme_sub_queue)));
        break;

    case COMPLETION_QUEUE_STRUCT:
        allocate_mem_base =
            dev->queue->base_addr_cq_struct +
            (qid * npl_calc_fpa_pool_size(sizeof(struct nvme_cpl_queue)));
        break;

    default:
        debug_printf(1, "Error: Unknown Queue Type");
        break;
    }
    return (void *)allocate_mem_base;
}


/***************************************************************************//**
*
*   npl_create_admin_sub_queue()
*
*   This function would create the admin submission queue in device
*
*       @param dev     Pointer to device private structure
*
*       @return Zero on success, or negative error code on failure.
*
*******************************************************************************/
int npl_create_admin_sub_queue(struct nvme_dev *dev)
{
    struct nvme_sub_queue *sq = NULL;
    uint32_t sq_depth, align_depth = 1;
    uint32_t sq_size;
    int i;

    debug_printf(3, "create admin sub queue");
    if (!dev->queue){
        dev->queue = findalloc(nvme_queue, dev->pfvf, CVMX_CACHE_LINE_SIZE);
    }
    memset(dev->queue, 0, sizeof(struct nvme_queue));
    /* A free entry in the abort_arr means the entry with opcode field set as 0xFF, Initially we will set all the fields as 0xFF */
    memset(dev->queue->abort_arr, 0xFF,
           (sizeof(struct nvme_cmd_abort) * MAX_ABORT_CMDS));
    sq_depth = (cvm_read_csr32(CVMX_PEXP_NQM_VFX_AQA(dev->pfvf)) & 0x00000fff) + 1;
    /* check for valid AQA value */
    if (sq_depth < MIN_QUEUE_ENTRIES) {
        debug_printf(1, "Error: sq depth fail");
        goto fail;
    }

    dev->queue->max_sub_queues =
        le16_cpu(dev->dev_config.max_sub_queues) + 1 + 1;
    sq_size = (sq_depth * SUBQUEUE_ENTRY_SIZE);

    /**
     * Allocate memory for submission queue structure for all supported queues
     * at once(assume it as submission queue structure memory pool).
     * Every allocated submission queue structure is cache line size aligned.
     * Clear submission queue structure memory pool content.
     *
     * Get Admin Submission Queue[0] structure memory from the submission queue
     * structure memory pool.
     */
    if (gbl_nvme_queue_mem[dev->pfvf].subq_mem) {
        dev->queue->base_addr_sq_struct = gbl_nvme_queue_mem[dev->pfvf].subq_mem;
    } else {
        debug_printf(1, "Error: Memory is not allocated for subq_mem\n");
        return STATUS_ERROR;
    }

    memset((void *)dev->queue->base_addr_sq_struct, 0,
           npl_calc_fpa_pool_size(sizeof(struct nvme_sub_queue)) *
           dev->queue->max_sub_queues);

    sq = (struct nvme_sub_queue *)npl_alloc_block(
        dev, 0x0000, SUBMISSION_QUEUE_STRUCT, sizeof(struct nvme_sub_queue));
    if (!sq)
        goto fail;

    /**
     * Allocate memory for submission queue Commands for all supported queues
     * at once(assume it as submission queue Commands memory pool).
     * Every allocated submission queue Commands base memory is cache line
     * size aligned.
     * Clear submission queue Commands pool content.
     *
     * Get Admin Submission Queue[0] Commands memory from the submission queue
     * Commands memory pool.
     */
    if (OCTEON_IS_MODEL(OCTEON_CN73XX)) {
        dev->queue->base_addr_sq_cmds = 0;
        sq->sq_cmds = NULL;
    } else {
        if (gbl_nvme_queue_mem[dev->pfvf].subq_cmnds_mem) {
            dev->queue->base_addr_sq_cmds = gbl_nvme_queue_mem[dev->pfvf].subq_cmnds_mem;
        } else {
            debug_printf(1, "Error: Memory is not allocated for subq_cmnds_mem\n");
            return STATUS_ERROR;
        }

        sq->sq_cmds = (struct nvme_cmd *)npl_alloc_block(
            dev, 0x0000, SUBMISSION_QUEUE, sq_size);
        if (!sq->sq_cmds)
            goto fail;

        memset(sq->sq_cmds, 0, sq_size);
    }

    dev->queue->sq[0] = (struct nvme_sub_queue *)sq;
    sq->sq_head = 0;
    sq->sq_tail = 0;
    sq->cq_id = 0;
    sq->sq_depth = sq_depth;
    for (i = 0; i < MAX_SQ_DEPTH; i++)
        cvmx_atomic_set64((int64_t *)&sq->cmd_id_arr[i], (CMDID_INVALID << 32));
    for (i = 0; i < MAX_SQ_DEPTH/64; i++)
        sq->cmd_id_bitmask[i] = 0;

    while (align_depth < sq_depth) align_depth <<= 1;
    sq->sq_depth_mask = align_depth -1;
    /* Initialize the number of entries in the queue with zero */
    cvmx_atomic_set32((int32_t *)&(sq->num_entries), 0);

    if (OCTEON_IS_MODEL(OCTEON_CN73XX)) {
    	dev->queue->sq[0]->host_sub_queue_addr =
		(struct nvme_cmd *)(cvmx_read_csr_node(cvmx_get_node_num(),
			CVMX_PEXP_NQM_VFX_ASQ(dev->pfvf)));
    } else {
        dev->queue->sq[0]->host_sub_queue_addr =
            (struct nvme_cmd *)((cvmx_read_csr_node(cvmx_get_node_num(),
			CVMX_PEXP_NQM_VFX_ASQ(dev->pfvf)) << 32) |
			(cvmx_read_csr_node(cvmx_get_node_num(),
			CVMX_PEXP_NQM_VFX_ASQ(dev->pfvf)) >> 32)) ;
    }
    cvmx_atomic_add32((int32_t *)&(dev->queue->sub_queue_count), 0x01);
    if (OCTEON_IS_MODEL(OCTEON_CN73XX)) {
        if (cn73xx_nqm_create_admin_sq(dev))
            goto fail;
    }

    return STATUS_SUCCESS;

fail:
    npl_fail_status(dev); // set controller fail status

    return STATUS_ERROR;
}

/***************************************************************************//**
*
*   npl_create_admin_cpl_queue()
*
*   This function would create the Admin completion queue in device
*
*       @param dev     Pointer to device private structure
*
*       @return Zero on success, or negative error code on failure.
*
*******************************************************************************/
int npl_create_admin_cpl_queue(struct nvme_dev *dev)
{
    struct nvme_cpl_queue *cq;
    uint32_t cq_depth;
    uint32_t cq_size;

    debug_printf(3, "create admin cpl queue");
    cq_depth = ((cvm_read_csr32(CVMX_PEXP_NQM_VFX_AQA(dev->pfvf))>>16) & 0x0FFF) + 1;

    /* check for valid AQA value */
    if (cq_depth < MIN_QUEUE_ENTRIES) {
        debug_printf(1,
                     "Error: CQ depth is less than mimimum queue entry size");
        goto fail;
    }

    dev->queue->max_cpl_queues =
        le16_cpu(dev->dev_config.max_cpl_queues) + 1 + 1;
    cq_size = (cq_depth * COMPLETIONQUEUE_ENTRY_SIZE);
    /**
     * Allocate memory for completion queue structure for all supported queues
     * at once(assume it as completion queue structure memory pool).
     * Every allocated completion queue structure is cache line size aligned.
     * Clear completion queue structure memory pool content.
     *
     * Get Admin Completion Queue[0] structure memory from the completion queue
     * structure memory pool.
     */
    if (gbl_nvme_queue_mem[dev->pfvf].cq_mem) {
        dev->queue->base_addr_cq_struct = gbl_nvme_queue_mem[dev->pfvf].cq_mem;
    } else {
        debug_printf(1, "Error: Memory is not allocated for cq_mem\n");
        return STATUS_ERROR;
    }
    memset((void *)dev->queue->base_addr_cq_struct, 0,
           npl_calc_fpa_pool_size(sizeof(struct nvme_cpl_queue)) *
           dev->queue->max_cpl_queues);
    cq = (struct nvme_cpl_queue *)npl_alloc_block(
        dev, 0x0000, COMPLETION_QUEUE_STRUCT, sizeof(struct nvme_cpl_queue));
    if (!cq)
        goto fail;

    dev->queue->cq[0] = (struct nvme_cpl_queue *)cq;
    cvmx_rwlock_wp_init(&cq->cq_lock);
    cq->cq_head = 0;
    cq->cq_tail = 0;
    cq->cq_id = 0;
    cq->cq_depth = cq_depth;
    if (OCTEON_IS_MODEL(OCTEON_CN73XX)) {
        dev->queue->cq[0]->host_cpl_queue_addr =
            (struct nvme_completion *)(cvmx_read_csr_node(cvmx_get_node_num(),
                CVMX_PEXP_NQM_VFX_ACQ(dev->pfvf)));
    } else {
        dev->queue->cq[0]->host_cpl_queue_addr =
            (struct nvme_completion *)
            ((cvmx_read_csr_node(cvmx_get_node_num(), CVMX_PEXP_NQM_VFX_ACQ(dev->pfvf)) << 32) |
            (cvmx_read_csr_node(cvmx_get_node_num(), CVMX_PEXP_NQM_VFX_ACQ(dev->pfvf)) >> 32)) ;
    }
    /**
     * Allocate memory for completion queue Commands for all supported queues
     * at once(assume it as completion queue Commands memory pool).
     * Every allocated completion queue Commands base memory is cache line
     * size aligned.
     * Clear completion queue Commands pool content.
     *
     * Get Admin Completion Queue[0] Commands memory from the completion queue
     * Commands memory pool.
     */
    if (gbl_nvme_queue_mem[dev->pfvf].cq_cmnds_mem) {
        dev->queue->base_addr_cq_cmds = gbl_nvme_queue_mem[dev->pfvf].cq_cmnds_mem;
    } else {
        debug_printf(1, "Error: Memory is not allocated for cq_cmnds_mem\n");
        return STATUS_ERROR;
    }

    dev->queue->cq[0]->cqes = (struct nvme_completion *)npl_alloc_block(
        dev, 0x0000, COMPLETION_QUEUE, cq_size);
    if (!dev->queue->cq[0]->cqes)
        goto fail;

    memset(dev->queue->cq[0]->cqes, 0, COMPLETIONQUEUE_ENTRY_SIZE * nqm_cplq_size);
    cvmx_atomic_add32((int32_t *)&(dev->queue->cpl_queue_count), 0x01);
    /* Initialize list for overflow */
    INIT_LIST_HEAD(&dev->queue->cq[0]->cpl_list.list);

    if (OCTEON_IS_MODEL(OCTEON_CN73XX)) {
        if (cn73xx_nqm_create_admin_cq(dev))
            goto fail;
    }

    return STATUS_SUCCESS;

fail:
    npl_fail_status(dev); // set controller fail status

    return STATUS_ERROR;
}

/***************************************************************************//**
*
*   npl_reset_nvme_bar()
*
*  This function resets all the controller register fields except AQA, ASQ,ACQ
*  register
*
*    @param dev     Pointer to device private structure
*
*******************************************************************************/
void npl_reset_nvme_bar(struct nvme_dev *dev)
{
    /*Configure CAP register*/
    cvmx_write_csr_node(cvmx_get_node_num(), CVMX_PEXP_NQM_VFX_CAP(dev->pfvf),
                    ((le16_cpu((uint64_t)dev->dev_config.cap_mqes)) << 32) |
                    (((uint64_t)dev->dev_config.cap_cqr) << 48) |
                    (((uint64_t)dev->dev_config.cap_ams) << 49) |
                    (((uint64_t)dev->dev_config.cap_to) << 56) |
                    (((uint64_t)dev->dev_config.cap_dstrd) << 0) |
                    (((uint64_t)dev->dev_config.cap_nssrs) << 4) |
                    (((uint64_t)dev->dev_config.cap_css) << 5) |
                    (((uint64_t)dev->dev_config.cap_mpsmin) << 16) |
                    (((uint64_t)dev->dev_config.cap_mpsmax) << 20));
    /*Configure version register in bar1*/
    cvm_write_csr32(CVMX_PEXP_NQM_VFX_VS(dev->pfvf), NVME_VERSION_DEF);
    /*INTMS reset*/
    cvm_write_csr32(CVMX_PEXP_NQM_VFX_INTMS(dev->pfvf), NVME_INTMS_RESET);
    /*INTMC reset*/
    cvm_write_csr32(CVMX_PEXP_NQM_VFX_INTMC(dev->pfvf), NVME_INTMC_RESET);
    /*  CC Reset */
    cvm_write_csr32(CVMX_PEXP_NQM_VFX_CC(dev->pfvf), 0);
    /*CSTS reset*/
    SET_PEXP_REGISTER_VAL32(dev, CSTS,NVME_CSTS_SHST_RESET,2,3);
    SET_PEXP_REGISTER_VAL32(dev, CSTS,NVME_CSTS_RDY_RESET,0,0);
    /*NSSR reset*/
    cvm_write_csr32(CVMX_PEXP_NQM_VFX_NSSR(dev->pfvf), NVME_NSSR_RESET);
}

/***************************************************************************//**
*
*   npl_initialize_bar1()
*
*   This function initialize all the controller register fields except AQA,
*    ASQ, ACQ register
*
*    @param dev     Pointer to device private structure
*
*******************************************************************************/
void npl_initialize_bar1(struct nvme_dev *dev)
{
    /* Initialize the CAP register */
    cvmx_write_csr_node(cvmx_get_node_num(), CVMX_PEXP_NQM_VFX_CAP(dev->pfvf),
                    ((le16_cpu((uint64_t)dev->dev_config.cap_mqes)) << 32) |
                    (((uint64_t)dev->dev_config.cap_cqr) << 48) |
                    (((uint64_t)dev->dev_config.cap_ams) << 49) |
                    (((uint64_t)dev->dev_config.cap_to) << 56) |
                    (((uint64_t)dev->dev_config.cap_dstrd) << 0) |
                    (((uint64_t)dev->dev_config.cap_nssrs) << 4) |
                    (((uint64_t)dev->dev_config.cap_css) << 5) |
                    (((uint64_t)dev->dev_config.cap_mpsmin) << 16) |
                    (((uint64_t)dev->dev_config.cap_mpsmax) << 20));
    /*Configure version register in bar1*/
    cvm_write_csr32(CVMX_PEXP_NQM_VFX_VS(dev->pfvf), NVME_VERSION_DEF);
}

/***************************************************************************//**
*
*   npl_initialize_nvme_id_ctrl()
*
*   This function initializes nvme_id_ctrl structure fields
*
*    @param dev     Pointer to device private structure
*
*******************************************************************************/
void npl_initialize_nvme_id_ctrl(struct nvme_dev *dev)
{
    /* NVMe identify controller structure configuration */
    memcpy(dev->id_ctrl, &dev->dev_config.id_ctrl, sizeof(struct nvme_ctrl_id));
}

/***************************************************************************//**
*
*   npl_check_alignment()
*
*   Checks the prp alignment
*
*    @param dev     Pointer to device private structure
*    @param prp  prp address
*    @param cpl_entry   completion status
*    @param alignment_format  check to be performed
*
*******************************************************************************/
int npl_check_alignment(struct nvme_dev *               dev,
                        uint64_t                        prp,
                        struct completion_status_field *cpl_entry,
                        uint32_t                        alignment_format)
{
    uint64_t prp_addr_mask;

    switch (alignment_format) {
    case PAGE_ALIGNMENT:
        prp_addr_mask = ~(0x03ull);
        prp_addr_mask <<= (10 + GET_CC_MPS(dev));
        break;
    case DWORD_ALIGNMENT:
        prp_addr_mask = ~(0x03ull);
        break;
    case QWORD_ALIGNMENT:
        prp_addr_mask = ~(0x07ull);
        break;
    default:
        return STATUS_SUCCESS;
    }
    if (prp & ~(prp_addr_mask)) {
        cpl_entry->sct = SCT_GENERIC;
        cpl_entry->sc = BAD_ALLIGNMENT;
        cpl_entry->m = 0;
        cpl_entry->dnr = 0;
        return STATUS_ERROR;
    }
    return STATUS_SUCCESS;
}

/***************************************************************************//**
*
*   npl_process_io_request
*
*   This function processes the IO request
*
*       @param dev     Private data structure pointer
*       @param wqp     Work queue entry pointer
*
*       @return Zero on success, or negative error code on failure.
*
*******************************************************************************/
int
npl_process_io_request(struct nvme_dev *dev,
                       cvmx_wqe_tt *     wqp)
{
    struct nvme_cmd cmd;
    struct nvme_cmd_rw rw_cmd;
    uint8_t flbas, fs;
    uint64_t total_xfer_bytes, prp1_po, prp1_size, *first_lmp, host_page_size;
    uint32_t num_prps, entries_remaining;
    struct nvme_dma nvme_dma = { 0, };
    struct prp_list_transfer_info *prp_list_transfer_info;
    int32_t status;
    cvmx_wqe_tt *new_wqp;
    uint64_t lba_size;
    uint64_t prp2_offset;
    uint32_t num_prps_in_prp2_page;
    uint32_t result = 0;
    struct completion_status_field cpl_entry = { 0 };
    struct nvme_sub_queue *sq;
    uint32_t opcode;
    struct nvme_list *cmp_list_entry = NULL, *fused_first_node = NULL;
    cvmx_wqe_tt *fused_second_cmd_wqe;
    uint64_t namespace_id;

    sq = dev->queue->sq[wqp->word3.qw3.sq_id];

    wqp->nvme_cmd.rw.len += 1; //Now, not a zero based value

    cmd = wqp->nvme_cmd;
    rw_cmd = cmd.rw;
    namespace_id = cmd.rw.nsid;
    opcode = rw_cmd.opc;
        
    cpl_entry.sct = SCT_GENERIC;
    cpl_entry.sc = INTERNAL_ERROR;

    NVME_SET_IOSQ_STATS(sq, last_sub_ts, cvmx_get_cycle()); 

    if (OCTEON_IS_MODEL(OCTEON_CN73XX_PASS1_0)) {
        if (((cvmx_wqe_nqm_t *)wqp)->word2 != wqp->nvme_cmd.common.cmdid) {
            debug_printf(1, "Command ID mismatch after sq fetch: vf %d "
                "old cmdid 0x%lx: New cmdid 0x%x\n", dev->pfvf,
                ((cvmx_wqe_nqm_t *)wqp)->word2, wqp->nvme_cmd.common.cmdid);
        }
        ((cvmx_wqe_nqm_t *)wqp)->word2 = 0;
    }

    debug_printf(3, "io command sqid %d opcode %d", wqp->word3.qw3.sq_id, opcode);
    if (!cmd.rw.nsid || cmd.rw.nsid > le32_cpu(dev->dev_config.id_ctrl.nn) ||
        !NSPACE(dev, cmd.rw.nsid)) {

        npl_update_iosq_rwcmds_no_nsid(sq, opcode);
        debug_printf(1, "Error: Invalid name space ID");
        cpl_entry.sct = SCT_GENERIC;
        cpl_entry.sc = INVALID_NAMESPACE;
        cpl_entry.m = 0;
        cpl_entry.dnr = 0;
        result = 0;
        npl_submit_completion_entry(dev, wqp, result, cpl_entry);
        return STATUS_ERROR;
    }

    if ((le64_cpu(NSPACE(dev, namespace_id)->id_ns.ncap, ULL) == 0) ||
        (namespace_id == 0)) {

        npl_update_iosq_rwcmds_no_nsid(sq, opcode);
        debug_printf(1, "Error: Invalid name space ID");
        cpl_entry.sct = SCT_GENERIC;
        cpl_entry.sc = INVALID_FIELD_CMD;
        cpl_entry.m = 0;
        cpl_entry.dnr = 0;
        result = 0;
        npl_submit_completion_entry(dev, wqp, result, cpl_entry);
        return STATUS_ERROR;
    }
    
    npl_update_iosq_rwcmds(sq, opcode, NSPACE(dev, namespace_id)->ns_id);

    if (cvmx_atomic_get32((int32_t *)&(sq->marked_for_deletion))) {
        /* The queue is marked for deletion, so abort the command */
        npl_set_status_and_submit(dev, wqp, SCT_GENERIC, SQ_DELETION_ABORT, 0);
        return STATUS_SUCCESS;
    }

    /* If it is a compare and a fused_first_command, then keep the command in the list */
    if (opcode == nvme_cmd_compare && cmd.common.flags == fused_first_command) {
        /* Allocate memory for the list node and the command */
        cmp_list_entry = npl_fpa_alloc(dev, LIST_NODE_POOL);
        if (!cmp_list_entry) goto fail;
        
        new_wqp = npl_fpa_alloc(dev, CVMX_FPA_WQE_POOL);
        if (!new_wqp) goto fail;
        memcpy(new_wqp, wqp, sizeof(cvmx_wqe_t));
        npl_setup_wqe(new_wqp);
        
        cmp_list_entry->data = (uint64_t *)new_wqp;
        list_add_tail(&cmp_list_entry->list, &sq->cmp_cmd_list.list);
        return STATUS_SUCCESS;
    }

    /* if it is a fused_second_command, then get the corresponding fused_first_command from the list */
    if (cmd.common.flags == fused_second_command) {
        /* search for the fused_first_command with matching LBA */
        list_for_each_entry(cmp_list_entry, &sq->cmp_cmd_list.list, list){
            if (((cvmx_wqe_tt *)(cmp_list_entry->data))->nvme_cmd.rw.slba ==
                cmd.rw.slba &&
                ((cvmx_wqe_tt *)(cmp_list_entry->data))->nvme_cmd.rw.len ==
                cmd.rw.len)
                /* LBA matches, keep its address */
                fused_first_node = cmp_list_entry;
        }
        if (fused_first_node != NULL) {
            /* Found the fused_first_command */
            /* Keep the fused_second_command address in word6 of the work queue */
            fused_second_cmd_wqe = npl_fpa_alloc(dev, CVMX_FPA_WQE_POOL);
            if (!fused_second_cmd_wqe) goto fail;
            memcpy(fused_second_cmd_wqe, wqp, sizeof(cvmx_wqe_t));
            npl_setup_wqe(fused_second_cmd_wqe);

            /* Get the fused_first_command into the wqp */
            memcpy(wqp, (void *)fused_first_node->data, sizeof(cvmx_wqe_t));
            npl_setup_wqe(wqp);
            wqp->word6.u64 = (uint64_t)fused_second_cmd_wqe;
            /* Free the memory allocated for keeping the command */
            npl_fpa_free(fused_first_node->data,
                         CVMX_FPA_WQE_POOL, sizeof(cvmx_wqe_t));
            /* Remove the entry from list and free it */
            list_del(&fused_first_node->list);
            npl_fpa_free(fused_first_node, LIST_NODE_POOL,
                         sizeof(struct nvme_list));
            /* update the cmd with the fused first command - for further processing*/
            cmd = wqp->nvme_cmd;
            rw_cmd = cmd.rw;
            namespace_id = cmd.rw.nsid;
            opcode = rw_cmd.opc;
        } else {
            /* fused_first_command not found in the list, fail the command */
            cpl_entry.sct = SCT_GENERIC;
            cpl_entry.sc = MISSING_FUSED_CMD;
            cpl_entry.m = 0;
            cpl_entry.dnr = 0;
            npl_submit_completion_entry(dev, wqp, 0, cpl_entry);
            return STATUS_ERROR;
        }
    }
    host_page_size = dev->host_page_size;
    /* calculate the total bytes to be transferred */
    flbas = NSPACE(dev, rw_cmd.nsid)->id_ns.flbas;
    fs = flbas & 0x0F;
    lba_size = 1 << (NSPACE(dev, rw_cmd.nsid)->id_ns.lbaf[fs].lbads);
    total_xfer_bytes = rw_cmd.len * lba_size;

    /* PRP bad alignment check */
    if (npl_check_alignment(dev, rw_cmd.prp1, &cpl_entry, DWORD_ALIGNMENT)) {
        debug_printf(1, "PRP1 bad alignment");
        npl_submit_completion_entry(dev, wqp, result, cpl_entry);
        return STATUS_ERROR;
    }
    if (total_xfer_bytes == 0) {
        /* We will report success */
        cpl_entry.sct = SCT_GENERIC;
        cpl_entry.sc = CMD_SUCCESSFUL;
        cpl_entry.m = 0;
        cpl_entry.dnr = 1;
        result = 0;
        npl_submit_completion_entry(dev, wqp, result, cpl_entry);
        return STATUS_SUCCESS;
    }
    /* Calculate the data size in prp1 */
    prp1_po = PRP_PHY_PAGE_OFFSET(rw_cmd.prp1, dev);
    prp1_size = host_page_size - prp1_po;
    if (total_xfer_bytes <= prp1_size + host_page_size) {
        /* Check for prp2 is page aligned */
        if ((total_xfer_bytes > prp1_size) && 
            npl_check_alignment(dev, rw_cmd.prp2, &cpl_entry, PAGE_ALIGNMENT)) {
            debug_printf(1, "PRP2 bad alignment");
            npl_submit_completion_entry(dev, wqp, result, cpl_entry);
            return STATUS_ERROR;
        }
        return sal_do_data_transfer(dev, NULL, wqp);
    } else {
        /* Check for prp2 list pointer qword aligned */
        if (npl_check_alignment(dev, rw_cmd.prp2, &cpl_entry,
                                QWORD_ALIGNMENT)) {
            debug_printf(1, "PRP2 List pointer alignment");
            npl_submit_completion_entry(dev, wqp, result, cpl_entry);
            return STATUS_ERROR;
        }

        /* PRP2 is a list pointer */
        num_prps = (total_xfer_bytes - prp1_size) / host_page_size;
        /* consider the remainder */
        if ((total_xfer_bytes - prp1_size) % host_page_size)
            num_prps++;
        first_lmp = npl_fpa_alloc(dev, DEV_HOST_PAGE_SIZE_POOL);
        if (!first_lmp) goto fail;
        memset(first_lmp, 0, host_page_size);
        prp2_offset = rw_cmd.prp2 % host_page_size;

        num_prps_in_prp2_page = (host_page_size - prp2_offset) / PRP_ENTRY_SIZE;
        if ((host_page_size - prp2_offset) % PRP_ENTRY_SIZE)
            num_prps_in_prp2_page++;

        if (prp2_offset)
            first_lmp = first_lmp + prp2_offset / PRP_ENTRY_SIZE;

        prp_list_transfer_info = npl_fpa_alloc(dev, PRP_LIST_TRANSF_INFO_POOL);
        if (!prp_list_transfer_info) goto fail;

        if (num_prps > num_prps_in_prp2_page) {
            nvme_dma.nbytes = host_page_size - prp2_offset;
            /* Last entry will be a pointer to the next page */
            entries_remaining = num_prps - (num_prps_in_prp2_page - 1);
            prp_list_transfer_info->num_entry_xferd = num_prps_in_prp2_page;
        } else {
            /* Total prps will fit in one page */
            nvme_dma.nbytes = num_prps * PRP_ENTRY_SIZE;
            entries_remaining = 0;
            prp_list_transfer_info->num_entry_xferd = num_prps;
        }

        nvme_dma.src = (uint64_t)rw_cmd.prp2;
        nvme_dma.dst = (uint64_t)first_lmp;
        nvme_dma.trans_type.dma_mode = DMA_INBOUND;
        nvme_dma.trans_type.prp_mode = PRP_NULL;
        new_wqp = npl_fpa_alloc(dev, CVMX_FPA_WQE_POOL);
        if (!new_wqp) goto fail;
        memcpy(new_wqp, wqp, sizeof(cvmx_wqe_t));
        npl_setup_wqe(new_wqp);
        new_wqp->word1.qw1.tag =
            (PRP_LIST_TRANSFER_TAG << NQM_TAG_SHIFT) |
            (wqp->word3.qw3.sq_id << NQM_QID_SHIFT);
        new_wqp->word1.qw1.tt = CVMX_POW_TAG_TYPE_ORDERED;
        prp_list_transfer_info->entries_remaining = entries_remaining;
        prp_list_transfer_info->curr_lmp = (uint64_t)first_lmp;
        prp_list_transfer_info->first_lmp = (uint64_t)first_lmp;
        new_wqp->word5.u64 = (uint64_t)prp_list_transfer_info;
        status = npl_dma_submit(dev, &nvme_dma, new_wqp);
        if (status == DMA_ERROR) {
            debug_printf(1, "Error: DMA transfer failed");
            first_lmp = first_lmp - prp2_offset / 8;
            npl_fpa_free(first_lmp, DEV_HOST_PAGE_SIZE_POOL, host_page_size);
            npl_fpa_free(new_wqp, CVMX_FPA_WQE_POOL, sizeof(cvmx_wqe_t));
            npl_fpa_free(prp_list_transfer_info, PRP_LIST_TRANSF_INFO_POOL,
                         sizeof(struct prp_list_transfer_info));
            goto fail;
        }
    }
    return STATUS_SUCCESS;

fail:
    npl_submit_completion_entry(dev, wqp, result, cpl_entry);
    return STATUS_ERROR;
}

/***************************************************************************//**
*
*   npl_process_admin_request
*
*   This function extracts and processes the NVMe admin command from
*   the admin request structure
*
*       @param dev - Private data structure pointer
*       @param wqp - Work queue entry pointer
*
*       @return Zero on success, or negative error code on failure.
*
*******************************************************************************/
int
npl_process_admin_request(struct nvme_dev * dev,
                          cvmx_wqe_tt *      wqp)
{
    bool b_imm_cpl = 1;
    int16_t ret, cmd;
    struct nvme_cmd *nvme_cmd = &(wqp->nvme_cmd);
    struct completion_status_field cpl_entry = { 0 };
    uint32_t result;

    cmd = nvme_cmd->common.opc;
    debug_printf(3, "admin cmd  0x%x", cmd);

    NVME_INC_ADMINQ_STATS(wqp->word3.qw3.vf, submitted, 1); 
    NVME_SET_ADMINQ_STATS(wqp->word3.qw3.vf, last_sub_ts, cvmx_get_cycle()); 

    if (cvmx_atomic_get32((int32_t *)&(dev->queue->sq[0]->marked_for_deletion)))
    {
	debug_printf(3, "queue marked for deletion");
        /* The queue is marked for deletion, so abort the command */
        npl_set_status_and_submit(dev, wqp, SCT_GENERIC, SQ_DELETION_ABORT, 0);
        return STATUS_SUCCESS;
    }

    switch (cmd) {
    case NVME_ADMIN_CMD_CREATE_CQ:
        ret = npl_create_io_cq(dev, wqp, &cpl_entry, &result);
        if (ret > 0)
            b_imm_cpl = 0;
        break;

    case NVME_ADMIN_CMD_CREATE_SQ:
        ret = npl_create_io_sq(dev, wqp, &cpl_entry, &result);
        if (ret > 0)
            b_imm_cpl = 0;
        break;

    case NVME_ADMIN_CMD_DELETE_CQ:
        npl_delete_io_cq(dev,
		nvme_cmd->delete_queue.qid, &cpl_entry, &result);
        break;

    case NVME_ADMIN_CMD_DELETE_SQ:
        npl_delete_io_sq(dev,
		nvme_cmd->delete_queue.qid, &cpl_entry, &result);
        break;

    case NVME_ADMIN_CMD_IDENTIFY:
        ret = npl_process_identify(dev, wqp, &cpl_entry, &result);
        if (ret >= 0)
            b_imm_cpl = 0;
        break;

    case NVME_ADMIN_CMD_ABORT:
        ret = npl_abort_command(dev, wqp, &cpl_entry, &result);
        if (ret >= 0)
            b_imm_cpl = 0;
        break;

    case NVME_ADMIN_CMD_SET_FEATURES:
        npl_set_features(dev, nvme_cmd, wqp->word3.qw3.sq_id, &cpl_entry,
                         &result);
        break;

    case NVME_ADMIN_CMD_GET_FEATURES:
        npl_get_features(dev, nvme_cmd, wqp->word3.qw3.sq_id, &cpl_entry,
                         &result);
        break;

    case NVME_ADMIN_CMD_GET_LOG_PAGE:
        ret = npl_process_logpage(dev, wqp, &cpl_entry, &result);
        if (ret >= 0)
            b_imm_cpl = 0;
        break;

    case NVME_ADMIN_CMD_ASYNC_EVENT:
        ret = npl_async_event_command(dev, nvme_cmd, &cpl_entry, &result);
        if (ret >= 0)
            b_imm_cpl = 0;
        break;

    case NVME_ADMIN_CMD_STATS:
        ret = npl_process_get_stats(dev, wqp, &cpl_entry, &result);
        if (ret > 0)
            b_imm_cpl = 0;
        break;

    default:
        cpl_entry.sct = SCT_GENERIC;
        cpl_entry.sc = INVALID_OPCODE;
        cpl_entry.m = 0;
        cpl_entry.dnr = 0;
        result = 0;
        break;
    }
    if (b_imm_cpl)
        npl_submit_completion_entry(dev, wqp, result, cpl_entry);
    return STATUS_SUCCESS;
}

/***************************************************************************//**
*
*   npl_create_io_cq
*
*   This function creates an IO completion queue
*
*       @param dev          Private data structure pointer
*       @param wqp          Pointer to the work queue
*       @param cpl_entry     Completion queue entry pointer
*       @param result          Pointer to update the processing result
*
*******************************************************************************/
int
npl_create_io_cq(struct nvme_dev *                  dev,
                 cvmx_wqe_tt *                       wqp,
                 struct completion_status_field *   cpl_entry,
                 uint32_t *                         result)
{
    uint64_t cq_base_addr;
    uint16_t cqid, qsize;
    struct nvme_queue *queue = dev->queue;
    struct nvme_cmd_create_cq *create_cq_cmd = &(wqp->nvme_cmd.create_cq);
    struct nvme_cpl_queue *cpl_queue;
    volatile uint64_t bar_cap_register;
    int ret = 0;

#if DISCONTIGUOUS_Q_SUPPORT
    uint64_t *prp_list_page;
    struct nvme_dma nvme_dma = { 0, };
    uint32_t num_prps = 0;
    int status;
    cvmx_wqe_tt *new_wqp;
#endif

    bar_cap_register = cvm_read_csr32(CVMX_PEXP_NQM_VFX_CAP(dev->pfvf));
    cqid = create_cq_cmd->qid;
    debug_printf(2, "Create IOCQ: VF: %d: IOQ %d start", dev->pfvf, cqid);
    
    cpl_entry->sct = SCT_GENERIC;
    cpl_entry->sc = INTERNAL_ERROR;
    cpl_entry->m = 0;
    cpl_entry->dnr = 0;
    *result = 0;

#if !DISCONTIGUOUS_Q_SUPPORT
    if (!((create_cq_cmd->q_flags) & 0x01)) {
        /* Completion Queue is not physically contiguous */
        debug_printf(1, "Error: Completion Queue is not physically contiguous");
        cpl_entry->sct = SCT_COMMAND;
        cpl_entry->sc = INVALID_FIELD_CMD;
        cpl_entry->m = 0;
        cpl_entry->dnr = 1;
        *result = 0;
        return STATUS_ERROR;
    }
#endif
    if (cqid == 0) {
        /* Update the completion entry status fields */
        debug_printf(1, "Error: Invalid CQID");
        cpl_entry->sct = SCT_COMMAND;
        cpl_entry->sc = INVALID_QID;
        cpl_entry->m = 0;
        cpl_entry->dnr = 1;
        *result = 0;
        return STATUS_ERROR;
    }
    /*  check for prp1 page alignment */
    if (npl_check_alignment(dev, create_cq_cmd->prp1, cpl_entry,
                            PAGE_ALIGNMENT)) {
        debug_printf(1, "Error: PRP Bad alignment");
        *result = 0;
        return STATUS_ERROR;
    }

    qsize = create_cq_cmd->qsize + 1;
    /* Check whether the queue size is greater than the maximum queue entries supported */
    if ((qsize > ((bar_cap_register & 0xffff) + 1)) ||
        (qsize < MIN_QUEUE_ENTRIES)) {
        debug_printf(1, "Error: Invalid queue size: %d", qsize);
        cpl_entry->sct = SCT_COMMAND;
        cpl_entry->sc = Q_SZ_EXCEEDED;
        cpl_entry->m = 0;
        cpl_entry->dnr = 1;
        *result = 0;
        return STATUS_ERROR;
    }
    /* Compare with the number of queues in set feature command */
    if (cqid > queue->max_cpl_queues - 1) {
        /* Update the completion entry status fields */
        debug_printf(1, "Error: Invalid cqid: %d", cqid);
        cpl_entry->sct = SCT_COMMAND;
        cpl_entry->sc = INVALID_QID;
        cpl_entry->m = 0;
        cpl_entry->dnr = 1;
        *result = 0;
        return STATUS_ERROR;
    }
    /* Check whether any completion queue with same qid is already existing or not */
    if (queue->cq[cqid] != NULL) {
        /* Update the completion entry status fields */
        debug_printf(1, "Error: Queue with same qid already exists: %d", cqid);
        cpl_entry->sct = SCT_COMMAND;
        cpl_entry->sc = INVALID_QID;
        cpl_entry->m = 0;
        cpl_entry->dnr = 1;
        *result = 0;
        return STATUS_ERROR;
    }

    /**
     * Get Completion Queue Commands memory from the completion queue
     * Commands memory pool and clear its content.
     *
     * Get Completion Queue structure memory from the completion queue
     * structure memory pool and clear its content.
     */
    cq_base_addr =
        (uint64_t)npl_alloc_block(dev, cqid, COMPLETION_QUEUE, qsize);

    cpl_queue = (struct nvme_cpl_queue *)npl_alloc_block(
        dev, cqid, COMPLETION_QUEUE_STRUCT, sizeof(struct nvme_cpl_queue));
    if (!cpl_queue || !cq_base_addr) {
        debug_printf(1, "Error: CQ %d memory allocation failed:", cqid);
        cpl_entry->sct = SCT_GENERIC;
        cpl_entry->sc = INTERNAL_ERROR;
        cpl_entry->m = 0;
        cpl_entry->dnr = 1;
        *result = 0;
        return STATUS_ERROR;
    }

    memset((void *)cq_base_addr, 0, nqm_cplq_size * COMPLETIONQUEUE_ENTRY_SIZE);
    memset(cpl_queue, 0, sizeof(struct nvme_cpl_queue));
    cpl_queue->cqes = (struct nvme_completion *)cq_base_addr;
    cvmx_rwlock_wp_init(&cpl_queue->cq_lock);
    cpl_queue->cq_id = cqid;
    cpl_queue->cq_tail = 0;
    cvmx_atomic_set32((int32_t *)&(cpl_queue->cq_head), 0);
    cpl_queue->cq_depth = qsize;
    queue->cq[cqid] = cpl_queue;
    cvmx_atomic_add32((int32_t *)&(queue->cpl_queue_count), 0x01);
    INIT_LIST_HEAD(&queue->cq[cqid]->cpl_list.list);
    /* Initialize the list for keeping list of sub queues associated with a completion queue */
    if (!OCTEON_IS_MODEL(OCTEON_CN73XX)) {
    INIT_LIST_HEAD(&queue->cq[cqid]->associated_list.list);
    }

#if DISCONTIGUOUS_Q_SUPPORT
    if ((OCTEON_IS_MODEL(OCTEON_CN73XX_PASS1_0) &&
            !(create_cq_cmd->q_flags & 0x01)) ||
        (!OCTEON_IS_MODEL(OCTEON_CN73XX) &&
            !(create_cq_cmd->q_flags & 0x01))) {
        /* This is a dis-contiguous queue */
        if (qsize > dev->max_discontiguous_cq_size) {
            debug_printf(1, "Error: Queue size not supported");
            cpl_entry->sct = SCT_COMMAND;
            cpl_entry->sc = Q_SZ_EXCEEDED;
            cpl_entry->m = 0;
            cpl_entry->dnr = 1;
            *result = 0;
            return STATUS_ERROR;
        }
        /* Allocate a local page with the size of host page size */
        prp_list_page = npl_fpa_alloc(dev, DEV_HOST_PAGE_SIZE_POOL);
        if (!prp_list_page) goto fail;
        /* Transfer the host PRP list by initiating DMA from PRP1 to local page */
        nvme_dma.src = (uint64_t)create_cq_cmd->prp1;
        nvme_dma.dst = (uint64_t)prp_list_page;
        num_prps = qsize / dev->max_cq_entry_per_page;
        if (qsize % dev->max_cq_entry_per_page)
            num_prps++;
        nvme_dma.nbytes = num_prps * PRP_ENTRY_SIZE;
        nvme_dma.trans_type.dma_mode = DMA_INBOUND;
        nvme_dma.trans_type.prp_mode = PRP_NULL;
        /* Set the cpl_queue->host_cpl_queue_addr with the locally allocated memory address */
        cpl_queue->host_cpl_queue_addr =
            (struct nvme_completion *)prp_list_page;
        /* set the dis-contiguous flag for the queue */
        cpl_queue->queue_discontiguous = 1;
        /* Allocate a new work queue and submit the work */
        new_wqp = npl_fpa_alloc(dev, CVMX_FPA_WQE_POOL);
        if (!new_wqp) goto fail;
        memcpy(new_wqp, wqp, sizeof(cvmx_wqe_t));
        npl_setup_wqe(new_wqp);
        new_wqp->word3.qw3.vf = dev->pfvf; // set pf/vf
        new_wqp->word1.qw1.tag =
           (ADMIN_DATA_TRANSFER_TAG << NQM_TAG_SHIFT) |
           (wqp->word3.qw3.sq_id << NQM_QID_SHIFT);
        new_wqp->word1.qw1.tt = CVMX_POW_TAG_TYPE_ORDERED;
        status = npl_dma_submit(dev, &nvme_dma, new_wqp);
        if (status == DMA_ERROR) {
            debug_printf(1, "Error: DMA transfer failed");
            /* Free the work queue */
            npl_fpa_free(new_wqp, CVMX_FPA_WQE_POOL, sizeof(cvmx_wqe_t));
            cpl_entry->sct = SCT_GENERIC;
            cpl_entry->sc = INTERNAL_ERROR;
            cpl_entry->m = 0;
            cpl_entry->dnr = 1;
            *result = 0;
            return STATUS_ERROR;
        }
    } else
#endif
    {
        cpl_queue->host_cpl_queue_addr =
            (struct nvme_completion *)(create_cq_cmd->prp1);
    }
    CVMX_SYNCWS;
	
#if  DISCONTIGUOUS_Q_SUPPORT
    if (cpl_queue->queue_discontiguous)
        /**
         * The is a dis contiguous queue, we have to wait for the DMA to complete before completing
         * the command, so do not do an immediate completion
         */
        return STATUS_WAIT;

#endif
    if (OCTEON_IS_MODEL(OCTEON_CN73XX)) {
        ret = cn73xx_nqm_create_io_cq(dev, cpl_queue->cq_id, cpl_queue->cq_depth - 1,
            (uint64_t)cpl_queue->host_cpl_queue_addr, create_cq_cmd->q_flags & 0x01,
            create_cq_cmd->vector, ((create_cq_cmd->q_flags & 0x02)?1:0), cpl_entry);
        if (ret) {
            cvmx_atomic_add32((int32_t *)&(queue->cpl_queue_count), -0x01);
            queue->cq[cqid] = NULL;
            *result = 0;
            return STATUS_ERROR;
        }
    }

    debug_printf(2, "Create IOCQ: VF: %d: IOQ %d complete", dev->pfvf, cqid);
    /* Create the command completion with status success */
    cpl_entry->sct = SCT_GENERIC;
    cpl_entry->sc = CMD_SUCCESSFUL;
    cpl_entry->m = 0;
    cpl_entry->dnr = 0;
    *result = 0;
    return STATUS_SUCCESS;

#if DISCONTIGUOUS_Q_SUPPORT
fail:
    return STATUS_ERROR;
#endif
}

/***************************************************************************//**
*
*   npl_create_io_sq
*
*   This function creates an IO submission queue
*
*       @param dev          Private data structure pointer
*       @param wqp			Pointer to the nvme command
*       @param cpl_entry     Completion queue entry pointer
*       @param result          Pointer to update the processing result
*
*******************************************************************************/
int
npl_create_io_sq(struct nvme_dev *                  dev,
                 cvmx_wqe_tt *                       wqp,
                 struct completion_status_field *   cpl_entry,
                 uint32_t *                         result)
{
    uint64_t sq_base_addr;
    uint16_t sqid, cqid, qsize, align_depth = 1;
    struct nvme_queue *queue = dev->queue;
    struct nvme_cmd_create_sq *create_sq_cmd = &(wqp->nvme_cmd.create_sq);
    struct nvme_sub_queue *sub_queue;
    uint8_t cq_found = 0;
    struct nvme_list *associated_cpl_list_entry;
    volatile uint64_t bar_cap_register;
    int i;

#if DISCONTIGUOUS_Q_SUPPORT
    struct nvme_dma nvme_dma = { 0, };
    uint32_t num_prps = 0;
    int status;
    uint64_t *prp_list_page;
    cvmx_wqe_tt *new_wqp;
#endif

    bar_cap_register = cvm_read_csr32(CVMX_PEXP_NQM_VFX_CAP(dev->pfvf));
    sqid = create_sq_cmd->qid;
    cqid = create_sq_cmd->cqid;

    debug_printf(2, "Create IOSQ: VF: %d: IOQ %d start", dev->pfvf, sqid);
        
    cpl_entry->sct = SCT_GENERIC;
    cpl_entry->sc = INTERNAL_ERROR;
    cpl_entry->m = 0;
    cpl_entry->dnr = 0;
    *result = 0;

#if !DISCONTIGUOUS_Q_SUPPORT
    if (!((create_sq_cmd->q_flags) & 0x01)) {
        debug_printf(1, "Error: Submission Queue is not physically contiguous");
        /* Update the completion entry status fields */
        cpl_entry->sct = SCT_COMMAND;
        cpl_entry->sc = INVALID_FIELD_CMD;
        cpl_entry->m = 0;
        cpl_entry->dnr = 1;
        *result = 0;
        return STATUS_ERROR;
    }
#endif
    qsize = create_sq_cmd->qsize + 1;
    /* Check whether the queue size is greater than the maximum queue entries supported */
    if ((qsize > ((bar_cap_register & 0xffff) + 1)) ||
        (qsize < MIN_QUEUE_ENTRIES)) {
        debug_printf(1, "Error: queue size exceeded");
        /* Update the completion entry status fields */
        cpl_entry->sct = SCT_COMMAND;
        cpl_entry->sc = Q_SZ_EXCEEDED;
        cpl_entry->m = 0;
        cpl_entry->dnr = 1;
        *result = 0;
        return STATUS_ERROR;
    }
    if (sqid == 0) {
        debug_printf(1, "Error: Invalid Qid");
        /* Update the completion entry status fields */
        cpl_entry->sct = SCT_COMMAND;
        cpl_entry->sc = INVALID_QID;
        cpl_entry->m = 0;
        cpl_entry->dnr = 1;
        *result = 0;
        return STATUS_ERROR;
    }
    /* Check for prp1 page alignment */
    if (npl_check_alignment(dev, create_sq_cmd->prp1, cpl_entry,
                            PAGE_ALIGNMENT)) {
        debug_printf(1, "Error: PRP bad alignment");
        return STATUS_ERROR;
    }
    /* Check whether the queue id is out or range or not */
    if (sqid > (queue->max_sub_queues - 1)) {
        debug_printf(1, "Error: INVALID QID");
        /* Update the completion entry status fields */
        cpl_entry->sct = SCT_COMMAND;
        cpl_entry->sc = INVALID_QID;
        cpl_entry->m = 0;
        cpl_entry->dnr = 1;
        *result = 0;
        return STATUS_ERROR;
    }
    /* Check whether any submission queue with the same QID is already existing or not */
    if (queue->sq[sqid] != NULL) {
        debug_printf(1, " Error: invalid QID check");
        /* Update the completion entry status fields */
        cpl_entry->sct = SCT_COMMAND;
        cpl_entry->sc = INVALID_QID;
        cpl_entry->m = 0;
        cpl_entry->dnr = 1;
        *result = 0;
        return STATUS_ERROR;
    }
    /* Check for the creation of IOSQ with Admin QID*/
    if (cqid == 0) {
        debug_printf(1, "Error: Invalid QID");
        /* Update the completion entry status fields */
        cpl_entry->sct = SCT_COMMAND;
        cpl_entry->sc = INVALID_CQID;
        cpl_entry->m = 0;
        cpl_entry->dnr = 1;
        *result = 0;
        return STATUS_ERROR;
    }
    /* Check whether the associated completion queue is created or not */
    if (cqid <= queue->max_cpl_queues - 1)
        if (queue->cq[cqid] != NULL)
            cq_found = TRUE;
    if (!cq_found) {
        /* Associated completion queue does not exist */
        debug_printf(1, " Error: Invalid CQID");
        /* Update the completion entry status fields */
        cpl_entry->sct = SCT_COMMAND;
        cpl_entry->sc = INVALID_CQID;
        cpl_entry->m = 0;
        cpl_entry->dnr = 1;
        *result = 0;
        return STATUS_ERROR;
    }

    /**
     * Get Submission Queue structure memory from the submission queue
     * structure memory pool and clear its content.
     */
    sub_queue = (struct nvme_sub_queue *)npl_alloc_block(
        dev, sqid, SUBMISSION_QUEUE_STRUCT, sizeof(struct nvme_sub_queue));
    if (!sub_queue) {
        debug_printf(1, "Error: SQ %d memory allocation failed:", sqid);
        cpl_entry->sct = SCT_GENERIC;
        cpl_entry->sc = INTERNAL_ERROR;
        cpl_entry->m = 0;
        cpl_entry->dnr = 1;
        *result = 0;
        return STATUS_ERROR;
    }
    memset(sub_queue, 0, sizeof(struct nvme_sub_queue));

    /**
     * Get Submission Queue Commands memory from the submission queue
     * Commands memory pool and clear its content.
     */
    if (OCTEON_IS_MODEL(OCTEON_CN73XX)) {
        sq_base_addr = 0;
        sub_queue->sq_cmds = NULL;
    } else {
        sq_base_addr =
            (uint64_t)npl_alloc_block(dev, sqid, SUBMISSION_QUEUE, qsize);
        memset((void *)sq_base_addr, 0, qsize *
            (1 << ((cvm_read_csr32(CVMX_PEXP_NQM_VFX_CC(dev->pfvf)) >> 16) & 0x0F)));
        sub_queue->sq_cmds = (struct nvme_cmd *)sq_base_addr;
    }

    /**
     * maintaining list of sub queues associated with a completion queue
     *
     */
    if (!OCTEON_IS_MODEL(OCTEON_CN73XX)) {
    associated_cpl_list_entry =
        (struct nvme_list *)npl_fpa_alloc(dev, LIST_NODE_POOL);
    if (!associated_cpl_list_entry) goto fail;
    associated_cpl_list_entry->data =
        (uint16_t *)npl_fpa_alloc(dev, CPL_QUEUE_UPDATE_POOL);
    if (!associated_cpl_list_entry->data) goto fail;
    *((uint16_t *)associated_cpl_list_entry->data) = sqid;
    list_add_tail(&associated_cpl_list_entry->list,
                  &dev->queue->cq[cqid]->associated_list.list);
    }

    sub_queue->sq_id = sqid;
    sub_queue->cq_id = cqid;
    sub_queue->gsq_id = GSQID(dev->pfvf, sqid);
    sub_queue->sq_tail = 0;
    cvmx_atomic_set32((int32_t *)&(sub_queue->sq_head), 0);
    sub_queue->sq_depth = qsize;
    for (i = 0; i < MAX_SQ_DEPTH; i++)
        cvmx_atomic_set64((int64_t *)&sub_queue->cmd_id_arr[i], (CMDID_INVALID << 32));
    for (i = 0; i < MAX_SQ_DEPTH/64; i++)
        sub_queue->cmd_id_bitmask[i] = 0;

    while (align_depth < qsize) align_depth <<= 1;
    sub_queue->sq_depth_mask = align_depth -1;
    /* initialize the number of entries in the queue with zero */
    cvmx_atomic_set32((int32_t *)&(sub_queue->num_entries), 0);
    /* Set the queue deletion flag to zero */
    cvmx_atomic_set32((int32_t *)&(sub_queue->marked_for_deletion), 0);
    queue->sq[sqid] = sub_queue;
    /* Initialize the list for keeping the fused first command */
    INIT_LIST_HEAD(&sub_queue->cmp_cmd_list.list);
    cvmx_atomic_add32((int32_t *)&(queue->sub_queue_count), 0x01);
    /* Increment associated queue count for cq */
    if (!OCTEON_IS_MODEL(OCTEON_CN73XX)) {
    cvmx_atomic_add32((int32_t *)&(queue->cq[cqid]->associated_subq_count), 0x01);
    }

#if DISCONTIGUOUS_Q_SUPPORT
    if ((OCTEON_IS_MODEL(OCTEON_CN73XX_PASS1_0) &&
            !(create_sq_cmd->q_flags & 0x01)) ||
        (!OCTEON_IS_MODEL(OCTEON_CN73XX) &&
            !(create_sq_cmd->q_flags & 0x01))) {
        /* check the queue size */
        if (qsize > dev->max_discontiguous_sq_size) {
            debug_printf(1, "Error: Queue size exceeded");
            /* Update the completion entry status fields */
            cpl_entry->sct = SCT_COMMAND;
            cpl_entry->sc = Q_SZ_EXCEEDED;
            cpl_entry->m = 0;
            cpl_entry->dnr = 1;
            *result = 0;
            return STATUS_ERROR;
        }
        /* Allocate a local page with the size of host page size */
        prp_list_page = npl_fpa_alloc(dev, DEV_HOST_PAGE_SIZE_POOL);
        if (!prp_list_page) goto fail;
        /* Transfer the host PRP list by initiating DMA from PRP1 to local page */
        nvme_dma.src = (uint64_t)create_sq_cmd->prp1;
        nvme_dma.dst = (uint64_t)prp_list_page;
        num_prps = qsize / dev->max_sq_entry_per_page;
        if (qsize % dev->max_sq_entry_per_page)
            num_prps++;
        nvme_dma.nbytes = num_prps * PRP_ENTRY_SIZE;
        nvme_dma.trans_type.dma_mode = DMA_INBOUND;
        nvme_dma.trans_type.prp_mode = PRP_NULL;
        /* Set the sub_queue->host_sub_queue_addr with the locally allocated memory address */
        sub_queue->host_sub_queue_addr = (struct nvme_cmd *)prp_list_page;
        /* set the dis-contiguous flag for the queue */
        sub_queue->queue_discontiguous = 1;
        /* Allocate a new work queue and submit the work */
        new_wqp = npl_fpa_alloc(dev, CVMX_FPA_WQE_POOL);
        if (!new_wqp) goto fail;
        memcpy(new_wqp, wqp, sizeof(cvmx_wqe_t));
        npl_setup_wqe(new_wqp);
        new_wqp->word3.qw3.vf = dev->pfvf; // set pf/vf
        new_wqp->word1.qw1.tag =
            (ADMIN_DATA_TRANSFER_TAG << NQM_TAG_SHIFT) |
            (wqp->word3.qw3.sq_id << NQM_QID_SHIFT);
        new_wqp->word1.qw1.tt = CVMX_POW_TAG_TYPE_ORDERED;
        status = npl_dma_submit(dev, &nvme_dma, new_wqp);
        if (status == DMA_ERROR) {
            debug_printf(1, "Error: DMA transfer failed");
            /* Free the work queue */
            npl_fpa_free(new_wqp, CVMX_FPA_WQE_POOL, sizeof(cvmx_wqe_t));
            /* Update the completion entry status fields */
            cpl_entry->sct = SCT_GENERIC;
            cpl_entry->sc = INTERNAL_ERROR;
            cpl_entry->m = 0;
            cpl_entry->dnr = 1;
            *result = 0;
            return STATUS_ERROR;
        }
    } else
#endif
    {
        sub_queue->host_sub_queue_addr =
            (struct nvme_cmd *)(create_sq_cmd->prp1);
    }
    CVMX_SYNCWS;

    /* Create the command completion with status success */
#if  DISCONTIGUOUS_Q_SUPPORT
    if (sub_queue->queue_discontiguous)
        /**
         * The is a dis contiguous queue, we have to wait for the DMA to complete before completing
         * the command, so do not do an immediate completion
         */
        return STATUS_WAIT;

#endif
    if (OCTEON_IS_MODEL(OCTEON_CN73XX)) {
        cn73xx_nqm_create_io_sq(dev, sub_queue->sq_id, sub_queue->sq_depth -1,
            sub_queue->host_sub_queue_addr, (create_sq_cmd->q_flags & 0x01));
    }

    debug_printf(2, "Create IOSQ: VF: %d: IOQ %d complete", dev->pfvf, sqid);
    /* Update the completion entry status fields */
    cpl_entry->sct = SCT_GENERIC;
    cpl_entry->sc = CMD_SUCCESSFUL;
    cpl_entry->m = 0;
    cpl_entry->dnr = 0;
    *result = 0;
    return STATUS_SUCCESS;

fail:
    return STATUS_ERROR;
}


/***************************************************************************//**
*
*   npl_delete_io_sq
*
*   This function deletes the IO submission queue with the specified queue id
*
*       @param dev          Private data structure pointer
*       @param nvme_cmd          Pointer to the nvme command
*       @param cpl_entry     Completion queue entry pointer
*       @param result          Pointer to update the processing result
*
*******************************************************************************/
int
npl_delete_io_sq(struct nvme_dev *                  dev,
                 uint8_t                            sqid,
                 struct completion_status_field *   cpl_entry,
                 uint32_t *                         result)
{
    struct nvme_queue *queue = dev->queue;
    uint16_t cqid;
    struct nvme_list *cmp_list_entry, *tmp_entry;
    struct nvme_list *associated_cpl_list_entry;
    uint64_t t;
    int temp = 0;

    debug_printf(2, "Delete IOSQ VF: %d: IOQ %d Start", dev->pfvf, sqid);
    
    cpl_entry->sct = SCT_GENERIC;
    cpl_entry->sc = INTERNAL_ERROR;
    cpl_entry->m = 0;
    cpl_entry->dnr = 0;
    *result = 0;
    
    if (sqid == 0) {
        debug_printf(1, "Error: Invalid QID");
        /* Update the completion entry status fields */
        cpl_entry->sct = SCT_COMMAND;
        cpl_entry->sc = INVALID_QID;
        cpl_entry->m = 0;
        cpl_entry->dnr = 1;
        *result = 0;
        return -1;
    }
    if (sqid > queue->max_sub_queues - 1) {
        debug_printf(1, "Error: Invalid QID");
        /* Update the completion entry status fields */
        cpl_entry->sct = SCT_COMMAND;
        cpl_entry->sc = INVALID_QID;
        cpl_entry->m = 0;
        cpl_entry->dnr = 1;
        *result = 0;
        return -1;
    }
    /* check the queue is existing or not */
    if (queue->sq[sqid] == NULL) {
        debug_printf(1, "Error:  queue does not exist");
        /* Update the completion entry status fields */
        cpl_entry->sct = SCT_COMMAND;
        cpl_entry->sc = INVALID_QID;
        cpl_entry->m = 0;
        cpl_entry->dnr = 1;
        *result = 0;
        return -1;
    }
    /* set the marked_for_deletion flag to indicate the queue is about to delete */
    cvmx_atomic_set32((int32_t *)&(queue->sq[sqid]->marked_for_deletion), 1);

    if (OCTEON_IS_MODEL(OCTEON_CN73XX)) {
        if (cvmx_atomic_get32((int32_t *)&(queue->sq[sqid]->num_entries))) {
            debug_printf(1, "Waiting for %d outstanding commands..",
                cvmx_atomic_get32((int32_t *)&(queue->sq[sqid]->num_entries)));

            NVME_MARKTIME(t); // get elapsed marker
            while (cvmx_atomic_get32((int32_t *)&(queue->sq[sqid]->num_entries))) {
                if (NVME_TIMEOUT(t, NVME_QUEUE_TIMEOUTVAL)) {
                    debug_printf(1, "Error: Timeout while waiting for outstanding cmd completion");
                    break;
                }
            }
            debug_printf(1, "done");
        }
        cn73xx_nqm_delete_io_sq(dev, sqid);
    } else {
        /* Wait here for all the queue entries to be aborted/completed */
        if (core_count > 2) {
            NVME_MARKTIME(t); // get elapsed marker
            while (cvmx_atomic_get32((int32_t *)&(queue->sq[sqid]->num_entries))) {
                if (NVME_TIMEOUT(t, NVME_TIMEOUTVAL)) goto fail; // process timeout
            }
        }
    }

    /* If any fused_first command is remaining in the list, free it  */
    list_for_each_entry_safe(cmp_list_entry, tmp_entry,
                             &dev->queue->sq[sqid]->cmp_cmd_list.list, list){
        npl_fpa_free(cmp_list_entry->data, CVMX_FPA_WQE_POOL, sizeof(cvmx_wqe_t));
        list_del(&cmp_list_entry->list);
        npl_fpa_free(cmp_list_entry, LIST_NODE_POOL, sizeof(struct nvme_list));
        temp++;
    }
    if (temp)
        debug_printf(1, "Error: Freed %d fused cmp cmds", temp);
#if DISCONTIGUOUS_Q_SUPPORT
    /* Delete the page we allocated for keeping the PRP list */
    if (queue->sq[sqid]->queue_discontiguous) {
        if (queue->sq[sqid]->host_sub_queue_addr != NULL)
            npl_fpa_free(queue->sq[sqid]->host_sub_queue_addr,
                         DEV_HOST_PAGE_SIZE_POOL, dev->host_page_size);
    }
#endif
    /**
     * Clear the content of nvme_sub_queue structure allocated, and
     * reset array pointer pointing at that structure
     *
     * Decrement the submission queue count
     */
    memset(queue->sq[sqid], 0, sizeof(struct nvme_sub_queue));
    queue->sq[sqid] = NULL;
    cvmx_atomic_add32((int32_t *)&(queue->sub_queue_count), -0x01);

    if (!OCTEON_IS_MODEL(OCTEON_CN73XX)) {
        cqid = queue->sq[sqid]->cq_id; //to get associated cq id
    /*  Delete the associated list entry in the cq */
    list_for_each_entry_safe(associated_cpl_list_entry, tmp_entry,
                             &dev->queue->cq[cqid]->associated_list.list, list){
        /*Freeing the memory for each entry from the associated list */
        npl_fpa_free(associated_cpl_list_entry->data, CPL_QUEUE_UPDATE_POOL,
                     sizeof(struct nvme_completion));
        list_del(&associated_cpl_list_entry->list);
        npl_fpa_free(associated_cpl_list_entry, LIST_NODE_POOL,
                     sizeof(struct nvme_list));
    }
        cvmx_atomic_add32((int32_t *)
            &(queue->cq[cqid]->associated_subq_count), -0x01);
    }

    debug_printf(2, "Delete IOSQ: VF: %d: IOQ %d Complete", dev->pfvf, sqid);
    /* Create the command completion with status success */
    cpl_entry->sct = SCT_GENERIC;
    cpl_entry->sc = CMD_SUCCESSFUL;
    cpl_entry->m = 0;
    cpl_entry->dnr = 0;
    *result = 0;
    return 0;

fail:
    return -1;
}

/***************************************************************************//**
*
*   nvme_delete_io_cq
*
*   This function deletes the IO completion queue with the specified queue id
*
*       @param dev          Private data structure pointer
*       @param nvme_cmd          Pointer to the nvme command
*       @param cpl_entry     Completion queue entry pointer
*       @param result          Pointer to update the processing result
*
*******************************************************************************/
void
npl_delete_io_cq(struct nvme_dev *                  dev,
                 uint8_t                            cqid,
                 struct completion_status_field *   cpl_entry,
                 uint32_t *                         result)
{
    struct nvme_queue *queue = dev->queue;
    struct nvme_list *cpl_list_entry, *tmp_entry;

    debug_printf(2, "Delete IOCQ: VF: %d: IOQ %d start", dev->pfvf, cqid);
    if (cqid == 0) {
        debug_printf(1, "Error: Invalid QID");
        /* Update the completion entry status fields */
        cpl_entry->sct = SCT_COMMAND;
        cpl_entry->sc = INVALID_QID;
        cpl_entry->m = 0;
        cpl_entry->dnr = 1;
        *result = 0;
        return;
    }
    if (cqid > queue->max_cpl_queues - 1) {
        debug_printf(1, "Error: Invalid QID");
        /* Update the completion entry status fields */
        cpl_entry->sct = SCT_COMMAND;
        cpl_entry->sc = INVALID_QID;
        cpl_entry->m = 0;
        cpl_entry->dnr = 1;
        *result = 0;
        return;
    }
    /* Check the queue is existing or not */
    if (queue->cq[cqid] == NULL) {
        debug_printf(1, "Error: The queue not exists");
        /* Update the completion entry status fields */
        cpl_entry->sct = SCT_COMMAND;
        cpl_entry->sc = INVALID_QID;
        cpl_entry->m = 0;
        cpl_entry->dnr = 1;
        *result = 0;
        return;
    }

    if (OCTEON_IS_MODEL(OCTEON_CN73XX)) {
        cn73xx_nqm_delete_io_cq(dev, cqid);
    }

#if DISCONTIGUOUS_Q_SUPPORT
    /* Delete the page we allocated for keeping the PRP list */
    if (queue->cq[cqid]->queue_discontiguous) {
        if (queue->cq[cqid]->host_cpl_queue_addr != NULL)
            npl_fpa_free(queue->cq[cqid]->host_cpl_queue_addr,
                         DEV_HOST_PAGE_SIZE_POOL, dev->host_page_size);
    }
#endif
    if (queue->cq[cqid]->associated_subq_count) {
        debug_printf(1, "Error: sub queue associated to this cq exist");
        /* Associated Submission Queue exists */
        cpl_entry->sct = SCT_COMMAND;
        cpl_entry->sc = INVALID_QDELETION;
        cpl_entry->m = 0;
        cpl_entry->dnr = 1;
        *result = 0;
        return;
    }
    list_for_each_entry_safe(cpl_list_entry, tmp_entry,
                             &queue->cq[cqid]->cpl_list.list, list){
        /*Freeing the memory for each entry from the completion list */
        npl_fpa_free(cpl_list_entry->data, CPL_QUEUE_UPDATE_POOL,
                     sizeof(struct nvme_completion));
        list_del(&cpl_list_entry->list);
        npl_fpa_free(cpl_list_entry, LIST_NODE_POOL, sizeof(struct nvme_list));
    }
    /* Reset the CQ head */
#ifdef NVME_68XX_SUPPORT
    if (!OCTEON_IS_MODEL(OCTEON_CN73XX)) {
        cvmx_atomic_set32((int32_t *)((uint8_t *)nvme_bar1 +
                                  (0x1000 + (0x08 * cqid + 4))), 0);
    }
#endif
    /**
     * Clear the content of nvme_cpl_queue structure allocated, and
     * reset array pointer pointing at that structure
     *
     * Decrement the completion queue count
     */
    memset(queue->cq[cqid], 0, sizeof(struct nvme_cpl_queue));
    queue->cq[cqid] = NULL;
    cvmx_atomic_add32((int32_t *)&(queue->cpl_queue_count), -0x01);

    debug_printf(2, "Delete IOCQ: VF: %d: IOQ %d complete", dev->pfvf, cqid);
    /* Create the command completion with status success */
    cpl_entry->sct = SCT_GENERIC;
    cpl_entry->sc = CMD_SUCCESSFUL;
    cpl_entry->m = 0;
    cpl_entry->dnr = 0;
    *result = 0;

    return;
}

/***************************************************************************//**
*
*   npl_process_identify
*
*   This function processes the identify command
*
*       @param dev          Private data structure pointer
*       @param wqp          workm queue pointer
*       @param cpl_entry     Completion queue entry pointer
*       @param result          Pointer to update the processing result
*
*       @return     Zero on success, or negative error code on failure.
*
*******************************************************************************/
int
npl_process_identify(struct nvme_dev *                  dev,
                     cvmx_wqe_tt *                       wqp,
                     struct completion_status_field *   cpl_entry,
                     uint32_t *                         result)
{
    struct nvme_cmd cmd = wqp->nvme_cmd;
    struct nvme_cmd_identify identify = cmd.identify;
    uint32_t ctrlr_or_namespace;
    struct nvme_dma nvme_dma = { 0, };
    cvmx_wqe_tt *new_wqp;
    int32_t status;
    uint32_t *local_page = NULL, *ns_entry = NULL;
    int i = 0;

    debug_printf(3, "process identify");
    
    cpl_entry->sct = SCT_GENERIC;
    cpl_entry->sc = INTERNAL_ERROR;
    cpl_entry->m = 0;
    cpl_entry->dnr = 0;
    *result = 0;
    
    ctrlr_or_namespace = identify.cns;
    switch (ctrlr_or_namespace) {
    case IDENTIFY_NAMESPACE:
        /* Return identify Namespace data structure to the host */
        if (!cmd.identify.nsid ||
            cmd.identify.nsid > le32_cpu(dev->dev_config.id_ctrl.nn) ||
            !NSPACE(dev, cmd.identify.nsid)) {
            debug_printf(1, "Error: Invalid NSID");
            cpl_entry->sct = SCT_GENERIC;
            cpl_entry->sc = INVALID_NAMESPACE;
            cpl_entry->m = 0;
            cpl_entry->dnr = 0;
            *result = 0;
            return STATUS_ERROR;
        }
        nvme_dma.src = (uint64_t) &(NSPACE(dev, identify.nsid)->id_ns);
        nvme_dma.dst = (uint64_t)NULL;
        nvme_dma.nbytes = sizeof(struct nvme_ns_id);
        break;

    case IDENTIFY_CONTROLLER:
        /* Return identify Controller data structure to the host */
        nvme_dma.src = (uint64_t)&(dev->dev_config.id_ctrl);
        nvme_dma.dst = (uint64_t)NULL;
        nvme_dma.nbytes = sizeof(struct nvme_ctrl_id);
        break;

    case NAMESPACE_LIST:
        /* Return a list of up to 1024 active name space IDs to the host */
        local_page = npl_fpa_alloc(dev, DEV_HOST_PAGE_SIZE_POOL);
        if (!local_page)
            goto fail;
        ns_entry = local_page;
        while (i < 1024) {
            *ns_entry = NSPACE(dev, i+1) ? le32_cpu(i+1) : le32_cpu(0);
            if (!NSPACE(dev, i+1))
                break;
            i++;
            ns_entry++;
        }
        nvme_dma.src = (uint64_t)local_page;
        nvme_dma.dst = (uint64_t)NULL;
        nvme_dma.nbytes = sizeof(uint32_t) * (i + 1);
        break;

    default:
        debug_printf(1, "Unknown identify request %d\n", ctrlr_or_namespace);
        goto fail;
        break;
    }
    nvme_dma.trans_type.dma_mode = DMA_OUTBOUND;
    nvme_dma.trans_type.prp_mode = PRP_NOLIST;
    if (identify.prp1 == 0) {
        debug_printf(1, "Error: PRP1 is not valid");
        /* Update the completion entry status fields */
        cpl_entry->sct = SCT_GENERIC;
        cpl_entry->sc = INVALID_FIELD_CMD;
        cpl_entry->m = 0;
        cpl_entry->dnr = 1;
        *result = 0;
        return STATUS_ERROR;
    }
    if (nvme_dma.nbytes >
        (dev->host_page_size - PRP_PHY_PAGE_OFFSET(identify.prp1, dev))) {
        if (identify.prp2 == 0) {
            debug_printf(1, "Error: PRP2 is invalid");
            /* Update the completion entry status fields */
            cpl_entry->sct = SCT_GENERIC;
            cpl_entry->sc = INVALID_FIELD_CMD;
            cpl_entry->m = 0;
            cpl_entry->dnr = 1;
            *result = 0;
            return STATUS_ERROR;
        }
        nvme_dma.lastptr.prp2 = identify.prp2;
    }
    nvme_dma.lastptr.prp1 = identify.prp1;
    new_wqp = npl_fpa_alloc(dev, CVMX_FPA_WQE_POOL);
    if (!new_wqp) goto fail;
    memcpy(new_wqp, wqp, sizeof(cvmx_wqe_t));
    npl_setup_wqe(new_wqp);
    new_wqp->word3.qw3.vf = dev->pfvf; // set pf/vf
    new_wqp->word1.qw1.tag =
        (ADMIN_DATA_TRANSFER_TAG << NQM_TAG_SHIFT) |
        (wqp->word3.qw3.sq_id << NQM_QID_SHIFT);
    new_wqp->word1.qw1.tt = CVMX_POW_TAG_TYPE_ORDERED;
    new_wqp->word5.u64 = (uint64_t)local_page;
    status = npl_dma_submit(dev, &nvme_dma, new_wqp);
    if (status == DMA_ERROR) {
        debug_printf(1, "Error: Identify CMD Admin Data transfer has failed");
        npl_fpa_free(new_wqp, CVMX_FPA_WQE_POOL, sizeof(cvmx_wqe_t));
        /* Update the completion entry status fields */
        cpl_entry->sct = SCT_GENERIC;
        cpl_entry->sc = INTERNAL_ERROR;
        cpl_entry->m = 0;
        cpl_entry->dnr = 1;
        *result = 0;
        return STATUS_ERROR;
    }
    /* Update the completion entry status fields */
    cpl_entry->sct = SCT_GENERIC;
    cpl_entry->sc = CMD_SUCCESSFUL;
    cpl_entry->m = 0;
    cpl_entry->dnr = 0;
    *result = 0;
    return STATUS_SUCCESS;

fail:
    cpl_entry->sct = SCT_GENERIC;
    cpl_entry->sc = INTERNAL_ERROR;
    cpl_entry->m = 0;
    cpl_entry->dnr = 1;
    *result = 0;
    return STATUS_ERROR;
}

/***************************************************************************//**
*
*   npl_process_get_stats
*
*   This function processes the user defied admin command get_stats
*
*       @param dev          Private data structure pointer
*       @param wqp          workqueue pointer
*       @param cpl_entry    Completion queue entry pointer
*       @param result       Pointer to update the processing result
*
*       @return     Zero on success, or negative error code on failure.
*
*******************************************************************************/
int
npl_process_get_stats(struct nvme_dev *dev,
                     cvmx_wqe_tt *wqp,
                     struct completion_status_field *cpl_entry,
                     uint32_t *result)
{
    struct nvme_cmd_common get_stats = wqp->nvme_cmd.common;
    uint32_t subcmd;
    struct nvme_dma nvme_dma = { 0, };
    cvmx_wqe_tt *new_wqp;
    int32_t status;
    uint16_t coreid, i;
    struct nvme_stats_dma_mem *stats_mem = dev->stats_dma_mem;
    uint32_t *tlv;

    debug_printf(3, "process get stats admin command");
    
    cpl_entry->sct = SCT_GENERIC;
    cpl_entry->sc = INTERNAL_ERROR;
    cpl_entry->m = 0;
    cpl_entry->dnr = 0;
    *result = 0;
    
    subcmd = get_stats.cdw2[1] & 0xff;

    debug_printf(3, "get_stats: Subcommand ID %d\n", subcmd);
    switch (subcmd) {
    case CLEAR_STATS_NS:
    case GET_STATS_NS: {
        nvme_ns_stats_t *ns_stats_mem = &stats_mem->ns_stats;
        uint32_t backend_nsid;
	nvme_per_cpu_stats_t *per_cpu_stats;
	nvme_ns_stats_t *per_cpu_ns_stats;

        if (!get_stats.nsid ||
                get_stats.nsid > le32_cpu(dev->dev_config.id_ctrl.nn) ||
                !NSPACE(dev, get_stats.nsid)) {
            debug_printf(1, "Error: Invalid NSID");
            cpl_entry->sct = SCT_GENERIC;
            cpl_entry->sc = INVALID_NAMESPACE;
            cpl_entry->m = 0;
            cpl_entry->dnr = 0;
            *result = 0;
            return STATUS_ERROR;
        }

	backend_nsid = NSPACE(dev, get_stats.nsid)->ns_id;
	memset(ns_stats_mem, 0, sizeof(nvme_ns_stats_t));

	for (coreid = 0; coreid < NVME_MAX_CORES; coreid++) {

		tlv  = (uint32_t *)(nvme_stats_mem + 8 + TLV_SIZE_ALIGN(sizeof(nvme_global_stats_t)) +
			coreid * (8 + TLV_SIZE_ALIGN(sizeof(nvme_per_cpu_stats_t))));

		if (*tlv != OCTEON_NVME_STATS_TYPE_PCPU)
			continue;

		tlv += 2;
		per_cpu_stats = (void *)tlv;
		per_cpu_ns_stats = &per_cpu_stats->g_ns[backend_nsid];

		if (subcmd == CLEAR_STATS_NS) {
			memset(per_cpu_ns_stats, 0, sizeof(nvme_ns_stats_t));
			continue;
		}
		
		ns_stats_mem->rd_cmds  += per_cpu_ns_stats->rd_cmds;
		ns_stats_mem->wr_cmds  += per_cpu_ns_stats->wr_cmds;
		ns_stats_mem->rd_bytes += per_cpu_ns_stats->rd_bytes;
		ns_stats_mem->wr_bytes += per_cpu_ns_stats->wr_bytes;
		ns_stats_mem->errors   += per_cpu_ns_stats->errors;

		if (per_cpu_ns_stats->rd_time > ns_stats_mem->rd_time)
			ns_stats_mem->rd_time = per_cpu_ns_stats->rd_time;

		if (per_cpu_ns_stats->wr_time > ns_stats_mem->wr_time)
			ns_stats_mem->wr_time = per_cpu_ns_stats->wr_time;

		if (per_cpu_ns_stats->last_error_ts > ns_stats_mem->last_error_ts)
			ns_stats_mem->last_error_ts = per_cpu_ns_stats->last_error_ts;
	}

	if (subcmd == CLEAR_STATS_NS) {
            cpl_entry->sct = SCT_GENERIC;
            cpl_entry->sc = CMD_SUCCESSFUL;
            cpl_entry->m = 0;
            cpl_entry->dnr = 0;
            *result = 0;
            return STATUS_SUCCESS;
        }

	for (i = 0; i < sizeof(nvme_ns_stats_t) / sizeof(uint64_t); i++)
		((uint64_t *)ns_stats_mem)[i] = le64_cpu(((uint64_t *)ns_stats_mem)[i], ULL);
		
        nvme_dma.src = (uint64_t) ns_stats_mem;
        nvme_dma.dst = (uint64_t)NULL;
        nvme_dma.nbytes = sizeof(nvme_ns_stats_t);
        }
        break;

    case CLEAR_STATS_IOQ:
    case GET_STATS_IOQ: {
        nvme_io_q_stats_t *ioq_stats_mem = &stats_mem->ioq_stats;
        uint8_t qid, gsq_id, queue, max_queues;
	nvme_per_cpu_stats_t *per_cpu_stats;
	nvme_io_q_stats_t *per_cpu_ioq_stats;

	memset(ioq_stats_mem, 0, sizeof(nvme_io_q_stats_t));

        qid = (get_stats.cdw2[1] >> 8) & 0xff;
	max_queues = le16_cpu(dev->dev_config.max_sub_queues) + 1;

        if ((qid == 0) || (qid != 0xff && (qid > max_queues))) {
            debug_printf(1, "Error: Invalid QID");
            cpl_entry->sct = SCT_GENERIC;
            cpl_entry->sc = INVALID_FIELD_CMD;
            cpl_entry->m = 0;
            cpl_entry->dnr = 0;
            *result = 0;
            return STATUS_ERROR;
        }

	if (qid == 0xff) {
		queue = 1;
	} else {
		queue = qid;
		max_queues = 1;
	}

	for (; max_queues--; queue++) {
		
		if (!dev->queue->sq[queue])
			continue;

		gsq_id = dev->queue->sq[queue]->gsq_id;
		for (coreid = 0; coreid < NVME_MAX_CORES; coreid++) {

			tlv  = (uint32_t *)(nvme_stats_mem + 8 + TLV_SIZE_ALIGN(sizeof(nvme_global_stats_t)) +
				coreid * (8 + TLV_SIZE_ALIGN(sizeof(nvme_per_cpu_stats_t))));

			if (*tlv != OCTEON_NVME_STATS_TYPE_PCPU)
				continue;

			tlv += 2;
			per_cpu_stats = (void *)tlv;
			per_cpu_ioq_stats = &per_cpu_stats->g_io_sq[gsq_id];

			if (subcmd == CLEAR_STATS_IOQ) {
				memset(per_cpu_ioq_stats, 0, sizeof(nvme_io_q_stats_t));
				continue;
			}

			ioq_stats_mem->rd_cmds  += per_cpu_ioq_stats->rd_cmds;
			ioq_stats_mem->wr_cmds  += per_cpu_ioq_stats->wr_cmds;
			ioq_stats_mem->rd_bytes += per_cpu_ioq_stats->rd_bytes;
			ioq_stats_mem->wr_bytes += per_cpu_ioq_stats->wr_bytes;
			ioq_stats_mem->completions += per_cpu_ioq_stats->completions;
			ioq_stats_mem->errors   += per_cpu_ioq_stats->errors;
			ioq_stats_mem->aborted  += per_cpu_ioq_stats->aborted;


			if (per_cpu_ioq_stats->rd_time > ioq_stats_mem->rd_time)
				ioq_stats_mem->rd_time = per_cpu_ioq_stats->rd_time;

			if (per_cpu_ioq_stats->wr_time > ioq_stats_mem->wr_time)
				ioq_stats_mem->wr_time = per_cpu_ioq_stats->wr_time;

			if (per_cpu_ioq_stats->last_sub_ts > ioq_stats_mem->last_sub_ts)
				ioq_stats_mem->last_sub_ts = per_cpu_ioq_stats->last_sub_ts;

			if (per_cpu_ioq_stats->last_compl_ts > ioq_stats_mem->last_compl_ts)
				ioq_stats_mem->last_compl_ts = per_cpu_ioq_stats->last_compl_ts;

			if (per_cpu_ioq_stats->last_error_ts > ioq_stats_mem->last_error_ts)
				ioq_stats_mem->last_error_ts = per_cpu_ioq_stats->last_error_ts;
		}
	}

	if (subcmd == CLEAR_STATS_IOQ) {
            cpl_entry->sct = SCT_GENERIC;
            cpl_entry->sc = CMD_SUCCESSFUL;
            cpl_entry->m = 0;
            cpl_entry->dnr = 0;
            *result = 0;
	    return STATUS_SUCCESS;
        }

	for (i = 0; i < sizeof(nvme_io_q_stats_t) / sizeof(uint64_t); i++)
		((uint64_t *)ioq_stats_mem)[i] = le64_cpu(((uint64_t *)ioq_stats_mem)[i], ULL);

        nvme_dma.src = (uint64_t)ioq_stats_mem;
        nvme_dma.dst = (uint64_t)NULL;
        nvme_dma.nbytes = sizeof(nvme_io_q_stats_t);
        }
        break;

    case CLEAR_STATS_ADMINQ:
    case GET_STATS_ADMINQ: {
        nvme_admin_q_stats_t *adminq_stats_mem = &stats_mem->adminq_stats;
	nvme_per_cpu_stats_t *per_cpu_stats;
	nvme_admin_q_stats_t *per_cpu_adminq_stats;
        uint8_t qid;

	memset(adminq_stats_mem, 0, sizeof(nvme_admin_q_stats_t));

        qid = (get_stats.cdw2[1] >> 8) & 0xff;
        if (!qid) {
            debug_printf(1, "Error: Invalid QID");
            cpl_entry->sct = SCT_GENERIC;
            cpl_entry->sc = INVALID_FIELD_CMD;
            cpl_entry->m = 0;
            cpl_entry->dnr = 0;
            *result = 0;
            return STATUS_ERROR;
        }

	for (coreid = 0; coreid < NVME_MAX_CORES; coreid++) {

		tlv  = (uint32_t *)(nvme_stats_mem + 8 + TLV_SIZE_ALIGN(sizeof(nvme_global_stats_t)) +
			coreid * (8 + TLV_SIZE_ALIGN(sizeof(nvme_per_cpu_stats_t))));

		if (*tlv != OCTEON_NVME_STATS_TYPE_PCPU)
			continue;

		tlv += 2;
		per_cpu_stats = (void *)tlv;
		per_cpu_adminq_stats = &per_cpu_stats->g_admin_q[dev->pfvf];

		if (subcmd == CLEAR_STATS_ADMINQ) {
			memset(per_cpu_adminq_stats, 0, sizeof(nvme_admin_q_stats_t));
			continue;
		}
		adminq_stats_mem->submitted += per_cpu_adminq_stats->submitted;
		adminq_stats_mem->completed += per_cpu_adminq_stats->completed;
		adminq_stats_mem->errors   += per_cpu_adminq_stats->errors;

		if (per_cpu_adminq_stats->last_sub_ts > adminq_stats_mem->last_sub_ts)
			adminq_stats_mem->last_sub_ts = per_cpu_adminq_stats->last_sub_ts;

		if (per_cpu_adminq_stats->last_compl_ts > adminq_stats_mem->last_compl_ts)
			adminq_stats_mem->last_compl_ts = per_cpu_adminq_stats->last_compl_ts;
	}

	if (subcmd == CLEAR_STATS_ADMINQ) {
            cpl_entry->sct = SCT_GENERIC;
            cpl_entry->sc = CMD_SUCCESSFUL;
            cpl_entry->m = 0;
            cpl_entry->dnr = 0;
            *result = 0;
            return STATUS_SUCCESS;
        }

	for (i = 0; i < sizeof(nvme_admin_q_stats_t) / sizeof(uint64_t); i++)
		((uint64_t *)adminq_stats_mem)[i] = le64_cpu(((uint64_t *)adminq_stats_mem)[i], ULL);

        nvme_dma.src = (uint64_t)adminq_stats_mem;
        nvme_dma.dst = (uint64_t)NULL;
        nvme_dma.nbytes = sizeof(nvme_admin_q_stats_t);
        }
        break;

    default:
        debug_printf(1, "Invalid subcode in GET_STATS command");
        /* Update the completion entry status fields */
        cpl_entry->sct = SCT_GENERIC;
        cpl_entry->sc = INVALID_FIELD_CMD;
        cpl_entry->m = 0;
        cpl_entry->dnr = 1;
        *result = 0;
        return STATUS_ERROR;
    }

    nvme_dma.trans_type.dma_mode = DMA_OUTBOUND;
    nvme_dma.trans_type.prp_mode = PRP_NOLIST;
    if (get_stats.prp1 == 0) {
        debug_printf(1, "Error: PRP1 is not valid");
        /* Update the completion entry status fields */
        cpl_entry->sct = SCT_GENERIC;
        cpl_entry->sc = INVALID_FIELD_CMD;
        cpl_entry->m = 0;
        cpl_entry->dnr = 1;
        *result = 0;
        return STATUS_ERROR;
    }
    if (nvme_dma.nbytes >
        (dev->host_page_size - PRP_PHY_PAGE_OFFSET(get_stats.prp1, dev))) {
        if (get_stats.prp2 == 0) {
            debug_printf(1, "Error: PRP2 is invalid");
            /* Update the completion entry status fields */
            cpl_entry->sct = SCT_GENERIC;
            cpl_entry->sc = INVALID_FIELD_CMD;
            cpl_entry->m = 0;
            cpl_entry->dnr = 1;
            *result = 0;
            return STATUS_ERROR;
        }
        nvme_dma.lastptr.prp2 = get_stats.prp2;
    }
    nvme_dma.lastptr.prp1 = get_stats.prp1;
    new_wqp = npl_fpa_alloc(dev, CVMX_FPA_WQE_POOL);
    if (!new_wqp) goto fail;
    memcpy(new_wqp, wqp, sizeof(cvmx_wqe_t));
    npl_setup_wqe(new_wqp);
    new_wqp->word3.qw3.vf = dev->pfvf; // set pf/vf
    new_wqp->word1.qw1.tag =
        (ADMIN_DATA_TRANSFER_TAG << NQM_TAG_SHIFT) |
        (wqp->word3.qw3.sq_id << NQM_QID_SHIFT);
    new_wqp->word1.qw1.tt = CVMX_POW_TAG_TYPE_ORDERED;
    status = npl_dma_submit(dev, &nvme_dma, new_wqp);
    if (status == DMA_ERROR) {
        debug_printf(1, "Error: GET_STATS Admin Data transfer has failed");
        npl_fpa_free(new_wqp, CVMX_FPA_WQE_POOL, sizeof(cvmx_wqe_t));
        /* Update the completion entry status fields */
        cpl_entry->sct = SCT_GENERIC;
        cpl_entry->sc = INTERNAL_ERROR;
        cpl_entry->m = 0;
        cpl_entry->dnr = 1;
        *result = 0;
        return STATUS_ERROR;
    }
    /* Update the completion entry status fields */
    cpl_entry->sct = SCT_GENERIC;
    cpl_entry->sc = CMD_SUCCESSFUL;
    cpl_entry->m = 0;
    cpl_entry->dnr = 0;
    *result = 0;
    return STATUS_WAIT;

fail:
    return STATUS_ERROR;
}


/***************************************************************************//**
*
*   npl_set_features
*
*   This function handles NVMe set feature admin command request.
*
*       @param dev          Private data structure pointer
*       @param nvme_cmd          Pointer to the nvme command
*       @param cpl_entry     Completion queue entry pointer
*       @param result          Pointer to update the processing result
*
*       @return     Zero on success, or negative error code on failure.
*
*******************************************************************************/
int
npl_set_features(struct nvme_dev *                  dev,
                 struct nvme_cmd *              nvme_cmd,
                 uint16_t                           sq_id,
                 struct completion_status_field *   cpl_entry,
                 uint32_t *                         result)
{
    struct nvme_queue *queue = dev->queue;
    uint32_t fid = nvme_cmd->features.fid;
    uint32_t feature_cmd_dword11 = nvme_cmd->features.dword;
    int8_t ret = -1;
    uint16_t iv;
    uint8_t cd, ic_thr, ic_time;

    if (fid == 0 || ((fid >= 0x0D) && (fid <= 0x7F)) ||
        ((fid >= 0x80) && (fid <= 0xBF))) {
        debug_printf(1, "Error: Unsupported fid");
        *result = 0;
        /* Update the completion entry status fields */
        cpl_entry->sct = SCT_GENERIC;
        cpl_entry->sc = INVALID_FIELD_CMD;
        cpl_entry->m = 0;
        cpl_entry->dnr = 0;
        ret = STATUS_SUCCESS;
        return ret;
    }
    switch (fid) {
    case NVME_FEAT_NUM_QUEUES:
        cpl_entry->sct = SCT_GENERIC;
        cpl_entry->sc = CMD_SUCCESSFUL;
        cpl_entry->m = 0;
        cpl_entry->dnr = 0;
        queue->max_sub_queues = (feature_cmd_dword11 & 0x0000FFFF) + 2;

        if (le16_cpu(dev->dev_config.max_sub_queues) <
            (queue->max_sub_queues - 1))
            queue->max_sub_queues =
                le16_cpu(dev->dev_config.max_sub_queues) + 2;
        queue->max_cpl_queues = ((feature_cmd_dword11 >> 16) & 0x0000FFFF) + 2;
        if (le16_cpu(dev->dev_config.max_cpl_queues) <
            (queue->max_cpl_queues - 1))
            queue->max_cpl_queues =
                le16_cpu(dev->dev_config.max_cpl_queues) + 2;
        *result =
            (((queue->max_cpl_queues - 2) << 16) | (queue->max_sub_queues - 2));
        dev->max_entries = (queue->max_sub_queues + 63) / 64;
        ret = STATUS_SUCCESS;
        break;
    case NVME_FEAT_ASYNC_EVENT:
        dev->dev_config.smart_ctrl = feature_cmd_dword11 & 0x000000FF;
        cpl_entry->sct = SCT_GENERIC;
        cpl_entry->sc = CMD_SUCCESSFUL;
        cpl_entry->m = 0;
        cpl_entry->dnr = 0;
        ret = STATUS_SUCCESS;

        break;
    case NVME_FEAT_IRQ_COALESCE:
        ic_thr = feature_cmd_dword11 & 0xff;
        ic_time = (feature_cmd_dword11 >> 8) & 0xff;
        if (OCTEON_IS_MODEL(OCTEON_CN73XX)) {
            cn73xx_set_intr_coalescing(dev, ic_thr, ic_time);
            *result = 0;
            cpl_entry->sct = SCT_GENERIC;
            cpl_entry->sc = CMD_SUCCESSFUL;
            cpl_entry->m = 0;
            cpl_entry->dnr = 0;
            ret = STATUS_SUCCESS;
        } else {
            *result = 0;
            cpl_entry->sct = SCT_COMMAND;
            cpl_entry->sc = FEATURE_NOT_CHANGEABLE;
            cpl_entry->m = 0;
            cpl_entry->dnr = 1;
            ret = STATUS_SUCCESS;
        }
        break;
    case NVME_FEAT_IRQ_CONFIG:
        iv = feature_cmd_dword11 & 0xffff;
        cd = (feature_cmd_dword11 >> 16) & 0x1;

        *result = 0;
        if (OCTEON_IS_MODEL(OCTEON_CN73XX)) {
            ret = cn73xx_cfg_intr_vect(dev, iv, cd);
            cpl_entry->sct = SCT_GENERIC;
            cpl_entry->sc = CMD_SUCCESSFUL;
            cpl_entry->m = 0;
            cpl_entry->dnr = 0;

            if (ret != STATUS_SUCCESS) {
                cpl_entry->sc = INVALID_FIELD_CMD;
                cpl_entry->dnr = 1;
	    }
            ret = STATUS_SUCCESS;
        } else {
            *result = 0;
            cpl_entry->sct = SCT_COMMAND;
            cpl_entry->sc = FEATURE_NOT_CHANGEABLE;
            cpl_entry->m = 0;
            cpl_entry->dnr = 1;
            ret = STATUS_SUCCESS;
        }
        break;
    case NVME_FEAT_ERR_RECOVERY:    /* Not supported */
    case NVME_FEAT_TEMP_THRESH:     /* We don't report async events for temperature thresholds */
    case NVME_FEAT_ARBITRATION:     /* We support simple round robin with 1 arbitration burst */
    case NVME_FEAT_POWER_MGMT:      /* We support only one power state */
    case NVME_FEAT_VOLATILE_WC:
    case NVME_FEAT_AUTOPWR_TRANS:
    case NVME_FEAT_WRITE_ATOMIC:             /* Not supported right now */
    case NVME_FEAT_LBA_RANGE:
    default:
        *result = 0;
        /* Update the completion entry status fields */
        cpl_entry->sct = SCT_COMMAND;
        cpl_entry->sc = FEATURE_NOT_CHANGEABLE;
        cpl_entry->m = 0;
        cpl_entry->dnr = 1;
        ret = STATUS_SUCCESS;
        break;
    }
    return ret;
}

/***************************************************************************//**
*
*   npl_get_features
*
*   This function handles NVMe get feature Admin command request.
*
*       @param dev          Private data structure pointer
*       @param nvme_cmd          Pointer to the NVMe command
*       @param cpl_entry     Completion queue entry pointer
*       @param result          Pointer to update the processing result
*
*       @return     Zero on success, or negative error code on failure.
*
*******************************************************************************/
int
npl_get_features(struct nvme_dev *                  dev,
                 struct nvme_cmd *              nvme_cmd,
                 uint16_t                           sq_id,
                 struct completion_status_field *   cpl_entry,
                 uint32_t *                         result)
{
    struct nvme_queue *queue = dev->queue;
    uint8_t smart_ctrl = dev->dev_config.smart_ctrl;
    uint32_t fid = nvme_cmd->features.fid;
    int8_t ret = -1;

    if (fid == 0 || ((fid >= 0x0D) && (fid <= 0x7F)) ||
        ((fid >= 0x80) && (fid <= 0xBF))) {
        debug_printf(1, "Error: Unsupproted fid");
        *result = 0;
        /* Update the completion entry status fields */
        cpl_entry->sct = SCT_GENERIC;
        cpl_entry->sc = INVALID_FIELD_CMD;
        cpl_entry->m = 0;
        cpl_entry->dnr = 0;
        ret = STATUS_SUCCESS;
        return ret;
    }
    switch (fid) {
    case NVME_FEAT_ARBITRATION:
    {
        *result = 1;         /* We support one command at a time */
        /* Update the completion entry status fields */
        cpl_entry->sct = SCT_GENERIC;
        cpl_entry->sc = CMD_SUCCESSFUL;
        cpl_entry->m = 0;
        cpl_entry->dnr = 0;
        ret = STATUS_SUCCESS;
    }
    break;
    case NVME_FEAT_IRQ_COALESCE:
    {
        uint8_t ic_time, ic_thr;

        *result = 0;
        if (OCTEON_IS_MODEL(OCTEON_CN73XX)) {
             cn73xx_get_intr_coalescing(dev, &ic_thr, &ic_time);
            *result = (ic_thr | (ic_time << 8));
        }
        /* Update the completion entry status fields */
        cpl_entry->sct = SCT_GENERIC;
        cpl_entry->sc = CMD_SUCCESSFUL;
        cpl_entry->m = 0;
        cpl_entry->dnr = 0;
        ret = STATUS_SUCCESS;
    }
    break;
    case NVME_FEAT_IRQ_CONFIG:
    {
        uint16_t iv;
        uint8_t cd = 0;

        if (OCTEON_IS_MODEL(OCTEON_CN73XX)) {
            iv = (nvme_cmd->features.dword) & 0xffff;
            ret = cn73xx_get_intr_vect_cfg(dev, iv, &cd);
        } else {
            iv = 0xffff;
            ret = STATUS_SUCCESS;
        }

        if (ret != STATUS_SUCCESS) {
            *result = 0;
            /* Update the completion entry status fields */
            cpl_entry->sct = SCT_GENERIC;
            cpl_entry->sc = INVALID_FIELD_CMD;
            cpl_entry->m = 0;
            cpl_entry->dnr = 1;
            ret = STATUS_SUCCESS;
            break;
        }
        *result = (iv & 0xFFFF) | ((cd & 0x1) << 16);
        /* Update the completion entry status fields */
        cpl_entry->sct = SCT_GENERIC;
        cpl_entry->sc = CMD_SUCCESSFUL;
        cpl_entry->m = 0;
        cpl_entry->dnr = 0;
        ret = STATUS_SUCCESS;
    }
    break;

    case NVME_FEAT_LBA_RANGE:
        *result = 0;
        /* Update the completion entry status fields */
        cpl_entry->sct = SCT_GENERIC;
        cpl_entry->sc = INVALID_FIELD_CMD;
        cpl_entry->m = 0;
        cpl_entry->dnr = 0;
        ret = STATUS_SUCCESS;
        break;

    case NVME_FEAT_NUM_QUEUES:
    {
        *result = ((queue->max_cpl_queues - 2) << 16) |
                  (queue->max_sub_queues - 2);
        /* Update the completion entry status fields */
        cpl_entry->sct = SCT_GENERIC;
        cpl_entry->sc = CMD_SUCCESSFUL;
        cpl_entry->m = 0;
        cpl_entry->dnr = 0;
        ret = STATUS_SUCCESS;
    }
    break;

    case NVME_FEAT_ASYNC_EVENT:
        *result = smart_ctrl;
        /* Update the completion entry status fields */
        cpl_entry->sct = SCT_GENERIC;
        cpl_entry->sc = CMD_SUCCESSFUL;
        cpl_entry->m = 0;
        cpl_entry->dnr = 0;
        ret = STATUS_SUCCESS;
        break;
    case NVME_FEAT_POWER_MGMT:          /* We support only one power state */
    case NVME_FEAT_TEMP_THRESH:
    case NVME_FEAT_ERR_RECOVERY:
    case NVME_FEAT_WRITE_ATOMIC:
    case NVME_FEAT_VOLATILE_WC:
    case NVME_FEAT_AUTOPWR_TRANS:
    {
        *result = 0;
        /* Update the completion entry status fields */
        cpl_entry->sct = SCT_GENERIC;
        cpl_entry->sc = CMD_SUCCESSFUL;
        cpl_entry->m = 0;
        cpl_entry->dnr = 0;
        ret = STATUS_SUCCESS;
    }
    break;
    }
    return ret;
}


/***************************************************************************//**
*
*   npl_make_prp_list_local
*
*   This function checks whether any PRP list is to be transferred to
*   the device, if so it initiates further DMA transfers else calls
*   the data transfer function
*
*       @param dev     Private data structure pointer
*       @param wqp     Work queue entry pointer
*
*       @return     Zero on success, or negative error code on failure.
*
*******************************************************************************/
int
npl_make_prp_list_local(struct nvme_dev *   dev,
                        cvmx_wqe_tt *        wqp)
{
    struct prp_list_transfer_info *prp_list_transfer_info;
    struct nvme_cmd nvme_cmd;
    uint32_t entries_remaining;
    uint64_t *curr_lmp, *local_page, *temp_addr;
    struct nvme_dma nvme_dma = { 0, };
    cvmx_wqe_tt *new_wqp;
    int32_t status;
    uint64_t host_page_addr;
    uint64_t host_page_size = dev->host_page_size;
    uint32_t i = 0;

    uint64_t *temp_page1, *temp_page2;
    struct completion_status_field cpl_entry;
    uint32_t result = 0;
    uint64_t prp_addr_mask = ~(0x03ull);
    uint64_t prp2_offset = 0;

    cpl_entry.sct = SCT_GENERIC;
    cpl_entry.sc = INTERNAL_ERROR; //Generic error
    cpl_entry.m = 0;
    cpl_entry.dnr = 0;

    prp_list_transfer_info = (struct prp_list_transfer_info *)(wqp->word5.u64);
    nvme_cmd = wqp->nvme_cmd;
    entries_remaining = prp_list_transfer_info->entries_remaining;
    curr_lmp = (uint64_t *)prp_list_transfer_info->curr_lmp;
    /* PRP list bad alignment check */
    temp_addr = (uint64_t *)curr_lmp;
    for (i = 0; i < prp_list_transfer_info->num_entry_xferd; i++) {
        if (le64_cpu(*temp_addr, ULL) &
            ~(prp_addr_mask << (10 + GET_CC_MPS(dev)))) {
            result = 0;
            cpl_entry.sct = SCT_GENERIC;
            cpl_entry.sc = BAD_ALLIGNMENT; //MEMORY NOT ALIGNED
            cpl_entry.m = 0;
            cpl_entry.dnr = 0;

            debug_printf(1, "Bad Aligned PRP in prp-list");

            /* Starting from the first_lmp to current_lmp free  all the prp_list_transfer_info */
            if (curr_lmp == (uint64_t *)prp_list_transfer_info->first_lmp) {
                prp2_offset = nvme_cmd.rw.prp2 % host_page_size;
                curr_lmp = curr_lmp - prp2_offset / PRP_ENTRY_SIZE;
                npl_fpa_free(curr_lmp, DEV_HOST_PAGE_SIZE_POOL, host_page_size);
            } else {
                temp_page1 = (uint64_t *)prp_list_transfer_info->first_lmp;
                while (temp_page1 !=
                       (uint64_t *)prp_list_transfer_info->curr_lmp) {
                    if (temp_page1 ==
                        (uint64_t *)prp_list_transfer_info->first_lmp) {
                        prp2_offset = nvme_cmd.rw.prp2 % host_page_size;
                        prp_list_transfer_info->first_lmp =
                            prp_list_transfer_info->first_lmp - prp2_offset /
                            PRP_ENTRY_SIZE;
                    }

                    temp_page2 =
                        (uint64_t *)*(temp_page1 +
                                      (dev->num_prp_per_host_page - 1));
                    npl_fpa_free(temp_page1, DEV_HOST_PAGE_SIZE_POOL,
                                 host_page_size);
                    temp_page1 = temp_page2;
                }
                npl_fpa_free((uint64_t *)prp_list_transfer_info->curr_lmp,
                             DEV_HOST_PAGE_SIZE_POOL, host_page_size);
            }
            npl_fpa_free(prp_list_transfer_info, PRP_LIST_TRANSF_INFO_POOL,
                         sizeof(struct prp_list_transfer_info));
            npl_submit_completion_entry(dev, wqp, result, cpl_entry);
            return STATUS_ERROR;
        }
        temp_addr++;
    }

    if (!entries_remaining) {
        cvmcs_profile_mark_timed_event(PROF_NVME_PRP_LIST_TX, wqp->reserved);
        /* List is fully copied, check  whether abort is requested for this command */
        /* List copy completed, start the data transfer */
        sal_do_data_transfer(dev, (uint64_t *)prp_list_transfer_info->first_lmp,
                             wqp);
        /* Free the context */
        npl_fpa_free(prp_list_transfer_info, PRP_LIST_TRANSF_INFO_POOL,
                     sizeof(struct prp_list_transfer_info));
    } else {
        uint64_t prp_addr_mask = ~(0x03ull);
        local_page = npl_fpa_alloc(dev, DEV_HOST_PAGE_SIZE_POOL);
        if (!local_page) goto fail;
        temp_addr =
            (uint64_t *)((uint64_t)curr_lmp &
                         (prp_addr_mask << (10 + GET_CC_MPS(dev))));
        /* Go to the last entry of that page */
        temp_addr += (dev->num_prp_per_host_page - 1);
        /* Calculate the remaining prp entries */
        if (entries_remaining > dev->num_prp_per_host_page) {
            nvme_dma.nbytes = dev->host_page_size;
            /* Last entry will be a pointer to the next page */
            entries_remaining = entries_remaining -
                                (dev->num_prp_per_host_page - 1);
            prp_list_transfer_info->num_entry_xferd =
                dev->num_prp_per_host_page;
        } else {
            prp_list_transfer_info->num_entry_xferd = entries_remaining;
            nvme_dma.nbytes = entries_remaining * PRP_ENTRY_SIZE;
            entries_remaining = 0;
        }
        /* Host side address of the next list */
        host_page_addr = *temp_addr;
        host_page_addr = le64_cpu(host_page_addr, ULL);
        nvme_dma.src = host_page_addr;
        nvme_dma.dst = (uint64_t)local_page;
        nvme_dma.trans_type.dma_mode = DMA_INBOUND;
        nvme_dma.trans_type.prp_mode = PRP_NULL;
        /* Store the newly created local page address in the previous local page's last entry */
        *temp_addr = (uint64_t)local_page;
        new_wqp = npl_fpa_alloc(dev, CVMX_FPA_WQE_POOL);
        if (!new_wqp) goto fail;
        memcpy(new_wqp, wqp, sizeof(cvmx_wqe_t));
        npl_setup_wqe(new_wqp);
        new_wqp->word1.qw1.tag =
            (PRP_LIST_TRANSFER_TAG << NQM_TAG_SHIFT) |
            (wqp->word3.qw3.sq_id << NQM_QID_SHIFT);
        new_wqp->word1.qw1.tt = CVMX_POW_TAG_TYPE_ORDERED;
        /* We can reuse the structure */
        prp_list_transfer_info->entries_remaining = entries_remaining;
        prp_list_transfer_info->curr_lmp = (uint64_t)local_page;
        new_wqp->word5.u64 = (uint64_t)prp_list_transfer_info;
        /* Start dma for transferring the next list page */
        status = npl_dma_submit(dev, &nvme_dma, new_wqp);
        if (status == DMA_ERROR) {
            debug_printf(1, "Error: PRP List local DMA txfer has failed");
            /* Cleanup all the allocated pages and the  context */
            if (local_page == (uint64_t *)prp_list_transfer_info->first_lmp) {
                npl_fpa_free(local_page, DEV_HOST_PAGE_SIZE_POOL,
                             sizeof(struct prp_list_transfer_info));
            } else {
                temp_page1 = (uint64_t *)prp_list_transfer_info->first_lmp;
                while (temp_page1 !=
                       (uint64_t *)prp_list_transfer_info->curr_lmp) {
                    temp_page2 =
                        (uint64_t *)*(temp_page1 + (dev->host_page_size - 1));
                    npl_fpa_free(temp_page1, DEV_HOST_PAGE_SIZE_POOL,
                                 sizeof(struct prp_list_transfer_info));
                    temp_page1 = temp_page2;
                }
                npl_fpa_free((uint64_t *)prp_list_transfer_info->curr_lmp,
                             DEV_HOST_PAGE_SIZE_POOL,
                             sizeof(struct prp_list_transfer_info));
            }
            npl_fpa_free(new_wqp, CVMX_FPA_WQE_POOL, sizeof(cvmx_wqe_t));
            npl_fpa_free(prp_list_transfer_info, PRP_LIST_TRANSF_INFO_POOL,
                         sizeof(struct prp_list_transfer_info));
            goto fail;
        }
    }
    return STATUS_SUCCESS;

fail:
    npl_submit_completion_entry(dev, wqp, result, cpl_entry);

    return STATUS_ERROR;
}


/***************************************************************************//**
*
*   npl_process_admin_data_transfer_tag
*
*   This function processes the work queue entry having the tag
*   ADMIN_DATA_TRANSFER_TAG
*
*       @param dev     Private data structure pointer
*       @param wqp     Work queue entry pointer
*
*       @return     Zero on success, or negative error code on failure.
*
*******************************************************************************/
int
npl_process_admin_data_transfer_tag(struct nvme_dev *   dev,
                                    cvmx_wqe_tt *        wqp)
{
#if DISCONTIGUOUS_Q_SUPPORT
    uint16_t qid;
    uint32_t num_prps = 0;
    struct nvme_cmd *cmd;
    uint64_t prp_entry;
    uint32_t i = 0;
    uint16_t qsize;
#endif
    uint32_t result;
    struct completion_status_field cpl_entry = { 0 };
    /* update cpl_entry with appropriate values */
    cpl_entry.sct = SCT_GENERIC;
    cpl_entry.sc = CMD_SUCCESSFUL;
    cpl_entry.m = 0;
    cpl_entry.dnr = 0;
    result = 0;

#if DISCONTIGUOUS_Q_SUPPORT
    /** if the command is to create sq or cq, and also it is dis-contiguous in the host side,
     * swap the PRP entries in the page, that we just transferred to the device side
     */
    cmd = &wqp->nvme_cmd;
    switch (cmd->common.opc) {
    case NVME_ADMIN_CMD_CREATE_SQ:
        qid = cmd->create_sq.qid;
        qsize = cmd->create_sq.qsize + 1;
        if (dev->queue->sq[qid]->queue_discontiguous) {
            /* find the number of PRP entries transferred*/
            num_prps = qsize / dev->max_sq_entry_per_page;
            if (qsize % dev->max_sq_entry_per_page)
                num_prps++;
            for (i = 0; i < num_prps; i++) {
                prp_entry =
                    *((uint64_t *)(dev->queue->sq[qid]->host_sub_queue_addr) +
                      i);
                prp_entry = le64_cpu(prp_entry, ULL);
                *((uint64_t *)(dev->queue->sq[qid]->host_sub_queue_addr) +
                  i) = prp_entry;
            }

            if (OCTEON_IS_MODEL(OCTEON_CN73XX_PASS1_0)) {
                struct nvme_sub_queue *sub_queue;

                sub_queue = dev->queue->sq[qid];
                cn73xx_nqm_create_io_sq(dev, sub_queue->sq_id, sub_queue->sq_depth -1,
                    (void *)cmd->create_sq.prp1, (cmd->create_sq.q_flags & 0x01));
            }
        }

        break;

    case NVME_ADMIN_CMD_CREATE_CQ:
        qid = cmd->create_cq.qid;
        qsize = cmd->create_cq.qsize + 1;
        if (dev->queue->cq[qid]->queue_discontiguous) {
            /* find the number of PRP entries transferred*/
            num_prps = qsize / dev->max_cq_entry_per_page;
            if (qsize % dev->max_cq_entry_per_page)
                num_prps++;
            for (i = 0; i < num_prps; i++) {
                prp_entry =
                    *((uint64_t *)(dev->queue->cq[qid]->host_cpl_queue_addr) +
                      i);
                prp_entry = le64_cpu(prp_entry, ULL);
                *((uint64_t *)(dev->queue->cq[qid]->host_cpl_queue_addr) +
                  i) = prp_entry;
            }
            if (OCTEON_IS_MODEL(OCTEON_CN73XX_PASS1_0)) {
                struct nvme_cpl_queue *cpl_queue;
                int ret;

                cpl_queue = dev->queue->cq[qid];
                ret = cn73xx_nqm_create_io_cq(dev, cpl_queue->cq_id, cpl_queue->cq_depth - 1,
                      (uint64_t)cmd->create_cq.prp1, cmd->create_cq.q_flags & 0x01,
                      cmd->create_cq.vector, ((cmd->create_cq.q_flags & 0x02)?1:0), &cpl_entry);
                if (ret) {
                    cvmx_atomic_add32((int32_t *)&(dev->queue->cpl_queue_count), -0x01);
                    dev->queue->cq[qid] = NULL;
                    result = 0;
                }
            }
        }
        break;
    case NVME_ADMIN_CMD_IDENTIFY:
        if (wqp->word5.u64) {
            npl_fpa_free((uint64_t *)wqp->word5.u64,
                    DEV_HOST_PAGE_SIZE_POOL,
                    dev->host_page_size);
            wqp->word5.u64 = 0;
        }
        break;
    default:
        break;
    }
#endif
    npl_submit_completion_entry(dev, wqp, result, cpl_entry);
    return STATUS_SUCCESS;
}


/***************************************************************************//**
*
*   npl_process_io_data_transfer_tag
*
*   This function processes the work queue entry having the tag
*   IO_DATA_TRANSFER_TAG
*
*       @param dev     Private data structure pointer
*       @param wqp     Work queue entry pointer
*
*       @return     Zero on success, or negative error code on failure.
*
*******************************************************************************/
void npl_process_io_data_transfer_tag(struct nvme_dev * dev,
                                      cvmx_wqe_tt *      wqe_io)
{
    struct nvme_sub_queue *sq;
    uint64_t total_xfer_bytes, nsid;
    uint64_t lba_data_size;
    uint32_t opcode;
    uint32_t flbas;
    struct context_struct *io_context = (struct context_struct *)wqe_io->word5.u64;
    uint64_t actual_context_byte_count;
    uint64_t *context_byte_count;
	struct completion_status_field cpl_entry;

    sq = dev->queue->sq[wqe_io->word3.qw3.sq_id];
    if (!sq)
        goto cleanup;

    context_byte_count = &(sq->cmd_id_arr[LCMDID(wqe_io)]);
    /* Remove the LSB, to get the actual context_byte_count, LSB is used as the abort flag */
    nsid = wqe_io->nvme_cmd.rw.nsid;
    flbas = NSPACE(dev, nsid)->id_ns.flbas & 0x0f;
    lba_data_size = NSPACE(dev, nsid)->id_ns.lbaf[flbas].lbads;
    lba_data_size = 1 << lba_data_size;
    total_xfer_bytes = wqe_io->nvme_cmd.rw.len * lba_data_size;
    opcode = wqe_io->nvme_cmd.rw.opc;

    /*
     * add the remaining bytes into the respective queues of similar command id's
     */
    actual_context_byte_count = cvmx_atomic_fetch_and_add64(
        (int64_t *)context_byte_count,
        (io_context->no_bytes_transd << 1));
    actual_context_byte_count += (io_context->no_bytes_transd) << 1;
    
    if (((actual_context_byte_count & 0xFFFFFFFF) >> 1) == total_xfer_bytes) {

        if (actual_context_byte_count & 1) {
            /* Abort as there was a dma failure */
            debug_printf(1, "Error: DMA failure seen for sqid %u cmdid %u", 
                    wqe_io->word3.qw3.sq_id, wqe_io->nvme_cmd.rw.cmdid);
            cpl_entry.sct = SCT_GENERIC;
            cpl_entry.sc = INTERNAL_ERROR;
            cpl_entry.m = 0;
            cpl_entry.dnr = 0;
            cvmx_atomic_fetch_and_bclr64_nosync(&sq->cmd_id_arr[LCMDID(wqe_io)], 1);
            npl_submit_completion_entry(dev, wqe_io, 0, cpl_entry);
            npl_helper_free_context(io_context);
            return;
        }

        if (opcode == nvme_cmd_read)
            cvmcs_profile_mark_timed_event(PROF_NVME_READ_DMA, wqe_io->reserved);
        else if (opcode == nvme_cmd_write)
            cvmcs_profile_mark_timed_event(PROF_NVME_WRITE_DMA, wqe_io->reserved);

        if (opcode != nvme_cmd_compare) {

            dev->disk_dev.io_handler[nsid - 1].sal_complete_io(dev, wqe_io);

            npl_update_iosq_rwbytes(sq, opcode, NSPACE(dev, nsid)->ns_id, total_xfer_bytes);

        } else {
            cvmx_atomic_fetch_and_bclr64_nosync(context_byte_count, 0XFFFFFFFE);
            dev->disk_dev.io_handler[nsid - 1].sal_complete_io(dev, wqe_io);
        }
    } else {
cleanup:
        npl_fpa_free((void*)wqe_io->word5.u64,
            CONTEXT_STRUCT_IO_DMA_POOL,
            sizeof(struct context_struct));
    }
}

/***************************************************************************//**
*
*   npl_submit_completion_entry
*
*   This function creates and submits the an admin completion entry
*
*       @param dev          Private data structure pointer
*       @param wqp          Work queue pointer
*       @param result          Pointer to update the processing result
*       @param cpl_entry     completion_status_field structure
*
*       @return     Zero on success, or negative error code on failure.
*
*******************************************************************************/
int
npl_submit_completion_entry(struct nvme_dev *               dev,
                            cvmx_wqe_tt *                    wqp,
                            uint32_t                        result,
                            struct completion_status_field  cpl_entry)
{
    uint16_t current_cqid = dev->queue->sq[wqp->word3.qw3.sq_id]->cq_id;
    struct nvme_completion *cpl_queue_entry;
    struct cpl_queue_update *cpl_queue_update;
    struct nvme_sub_queue *sq = dev->queue->sq[wqp->word3.qw3.sq_id];
    uint32_t opcode;
    cvmx_wqe_tt *wqp_cqe;

    opcode = wqp->nvme_cmd.rw.opc;

    npl_update_cpl_stats(dev, sq, opcode, wqp, &cpl_entry);

    if (OCTEON_IS_MODEL(OCTEON_CN73XX)) {
        cvmx_wqe_set_tag((cvmx_wqe_t *)wqp, 
            ((CMD_COMPLETION_REQUEST_TAG << NQM_TAG_SHIFT) |
            (current_cqid << NQM_QID_SHIFT) | dev->pfvf));
        return cn73xx_submit_completion_entry(
            dev, current_cqid, wqp, result, cpl_entry);
    }

    cpl_queue_update = npl_fpa_alloc(dev, CPL_QUEUE_UPDATE_POOL);
    if (!cpl_queue_update) goto fail;
    memset(cpl_queue_update, 0, sizeof(struct cpl_queue_update));
    cpl_queue_entry = &(cpl_queue_update->cqes);

    wqp_cqe = npl_fpa_alloc(dev, CVMX_FPA_WQE_POOL);
    if (!wqp_cqe) goto fail;
    memset(wqp_cqe, 0, sizeof(cvmx_wqe_t));
    memcpy(wqp_cqe, wqp, sizeof(cvmx_wqe_t));
    npl_setup_wqe(wqp_cqe);
    wqp_cqe->word3.qw3.vf = dev->pfvf; // set pf/vf
    cpl_queue_entry->sqid = wqp_cqe->word3.qw3.sq_id;
    wqp_cqe->word1.qw1.tag =
        (CMD_COMPLETION_REQUEST_TAG << NQM_TAG_SHIFT) |
        (current_cqid << NQM_QID_SHIFT);
    cpl_queue_entry->sqhead = wqp_cqe->word4.qw4.sq_head;
    cpl_queue_entry->cmdid = wqp_cqe->nvme_cmd.common.cmdid;
    cpl_queue_entry->result = result;
    if (cpl_entry.sct == SCT_GENERIC) {
        debug_printf(3, "STATUS_GENERIC");
        STATUS_GENERIC(cpl_queue_entry->status, cpl_entry.sc, cpl_entry.m,
                       cpl_entry.dnr);
    } else if (cpl_entry.sct == SCT_COMMAND) {
        debug_printf(3, "STATUS_COMMAND");
        STATUS_COMMAND(cpl_queue_entry->status, cpl_entry.sc, cpl_entry.m,
                       cpl_entry.dnr);
    } else {
        debug_printf(3, "STATUS_MEDIA");
        STATUS_MEDIA(cpl_queue_entry->status, cpl_entry.sc, cpl_entry.m,
                     cpl_entry.dnr);
    }
    cpl_queue_update->cq = dev->queue->cq[current_cqid];
    wqp_cqe->word5.u64 = (uint64_t)cpl_queue_update;
    cvmx_pow_work_submit((cvmx_wqe_t *)wqp_cqe,
                ((CMD_COMPLETION_REQUEST_TAG << NQM_TAG_SHIFT) |
                (current_cqid << NQM_QID_SHIFT)),
                         CVMX_POW_TAG_TYPE_ATOMIC, NVME_WQE_QOS, NVME_WQE_GRP);
    return STATUS_SUCCESS;

fail:
    // Set controller fail status 
    // since the failure is in completion entry
    npl_fail_status(dev);

    return STATUS_ERROR;
}

/***************************************************************************//**
*
*   npl_async_event_command ()
*
*  This function used to notify host software of status, error, and health
*  information as these events occur
*
*    @param nvme_cmd          pointer to nvme command
*    @param dev          Private structure pointer
*    @param cpl_entry     Pointer to struct completion_status_field
*    @param result          result field of completion entry
*
*    @return     On success zero and negative error code on failure
*
*******************************************************************************/
int npl_async_event_command(struct nvme_dev *               dev,
                            struct nvme_cmd *           nvme_cmd,
                            struct completion_status_field *cpl_entry,
                            uint32_t *                      result)
{
    uint8_t max_aerl = dev->dev_config.id_ctrl.aerl + 1;

    if (dev->event_info->req_head ==
        (dev->event_info->req_tail + 1) % (max_aerl + 1)) {
        debug_printf(1, "Error: Max AeRl reached");
        *result = 0;
        cpl_entry->sct = SCT_COMMAND;
        cpl_entry->sc = ASYNCHRONOUS_EVENT_REQUEST_LIMIT;
        cpl_entry->m = 0;
        cpl_entry->dnr = 1;
        return STATUS_ERROR;
    } else {
        dev->event_info->async_req_arr[dev->event_info->req_tail].cid =
            nvme_cmd->async_evt_req.cmdid;
        dev->event_info->req_tail =
            (dev->event_info->req_tail + 1) % (max_aerl + 1);
    }
    npl_async_check(dev);

    /* fill completon entry for the async_event command */
    cpl_entry->sct = SCT_GENERIC;
    cpl_entry->sc = CMD_SUCCESSFUL;
    cpl_entry->m = 0;
    cpl_entry->dnr = 1;
    *result = 0;
    return STATUS_SUCCESS;
}

/***************************************************************************//**
*
*   npl_async_event_update ()
*
*    @param dev     Private structure pointer
*
*    @return     On success zero and negative error code on failure
*
*******************************************************************************/
void npl_async_event_update(struct nvme_dev *           dev,
                            struct async_event_result * event_result)
{
    int32_t ret = -1;
    uint8_t max_aerl = dev->dev_config.id_ctrl.aerl + 1;

    if (dev->id_ctrl->aerl == 0) {
        debug_printf(1,
                     "Error: Asynchronous limit is set to zero :"
                     "Can't handle async event updates from device");
        return;
    }
    
    cvmx_spinlock_lock(&dev->event_info_lock);
    
    if (event_result->aet == AET_ERROR_STATUS) {
        dev->event_info->error_queue[dev->event_info->error_tail] =
            *event_result;
        dev->event_info->error_tail =
            (dev->event_info->error_tail + 1) % (max_aerl + 1);
    } else if (event_result->aet == AET_SMART_HEALTH_STATUS) {
        dev->event_info->smart_queue[dev->event_info->smart_tail] =
            *event_result;
        dev->event_info->smart_tail =
            (dev->event_info->smart_tail + 1) % (max_aerl + 1);
    }
    
    cvmx_spinlock_unlock(&dev->event_info_lock);

    ret = npl_async_check(dev);
    if (ret < 0)
        return;
}

/*****************************************************************************
*
*   npl_abort_async_event_req() - Abort all outstanding async event req
*
*    @param dev     Private structure pointer
*
*    @return     void
*
*******************************************************************************/
static void npl_abort_async_event_req(struct nvme_dev *dev)
{
    struct completion_status_field cpl_status;
    cvmx_wqe_tt *wqe;
    uint32_t max_aerl = dev->dev_config.id_ctrl.aerl + 1;
    uint8_t cqid = 0;
    int i;

    if (dev->event_info->req_head == dev->event_info->req_tail)
        return;

    debug_printf(1, "Aborting outstanding async requests");
    wqe = npl_fpa_alloc(dev, CVMX_FPA_WQE_POOL);
    if (!wqe) goto fail;
    npl_setup_wqe(wqe);
    cvmx_wqe_set_tag((cvmx_wqe_t *)wqe,
        ((CMD_COMPLETION_REQUEST_TAG << NQM_TAG_SHIFT) |
        (cqid << NQM_QID_SHIFT) | dev->pfvf));
    wqe->word3.qw3.sq_id = 0;

    while (dev->event_info->req_head != dev->event_info->req_tail) {

        if (dev->event_info->req_head >= (max_aerl + 1) ||
            dev->event_info->req_tail >= (max_aerl + 1))
            break;

        wqe->nvme_cmd.common.cmdid =
            dev->event_info->async_req_arr[dev->event_info->req_head].cid;

        cpl_status.sct = SCT_GENERIC;
        cpl_status.sc = SQ_DELETION_ABORT;
        cpl_status.dnr = 1;
        cpl_status.m = 0;

        for (i = 0; i < MAX_SQ_DEPTH; i++) {
            if ((cvmx_atomic_get64((int64_t *)&dev->queue->sq[0]->
                cmd_id_arr[i]) >> 32) == wqe->nvme_cmd.common.cmdid) {
                LCMDID(wqe) = i;
                break;
            }
        }
        if (i != MAX_SQ_DEPTH)
            npl_submit_completion_entry(dev, wqe, 0, cpl_status);

        dev->event_info->req_head =
            (dev->event_info->req_head + 1) % (max_aerl + 1);
    }
    npl_fpa_free(wqe, CVMX_FPA_WQE_POOL, sizeof(cvmx_wqe_t));
    return;

fail:
    return;
}

/***************************************************************************//**
*
*   npl_async_check () - REVISIT
*
*    @param dev     Private structure pointer
*
*    @return     On success zero and negative error code on failure
*
*******************************************************************************/
int npl_async_check(struct nvme_dev *dev)
{
    cvmx_wqe_tt *wqp = NULL;
    uint16_t cpl_queue_id = 0;
    struct nvme_completion *cqes = NULL;
    struct cpl_queue_update *queue_update = NULL;
    uint8_t max_aerl = dev->dev_config.id_ctrl.aerl + 1;
    int i;

    cvmx_spinlock_lock(&dev->event_info_lock);
    if (dev->event_info->req_head != dev->event_info->req_tail) {
        if ((dev->event_info->error_tail != dev->event_info->error_head) &&
            !(dev->event_info->Is_error_Masked)) {
            queue_update = npl_fpa_alloc(dev, CPL_QUEUE_UPDATE_POOL);
            if (!queue_update) goto fail;
            cqes = &(queue_update->cqes);
            STATUS_GENERIC(cqes->status, 0, 0, 0);
            ASYNC_EVENT(cqes->result,
                        dev->event_info->error_queue[dev->event_info->error_head].aet,
                        dev->event_info->error_queue[dev->event_info->error_head].aei,
                        dev->event_info->error_queue[dev->event_info->error_head].alp);
            cqes->sqid = 0;
            cqes->sqhead =
                cvmx_atomic_get32((int *)&(dev->queue->sq[0]->sq_head));
            cqes->cmdid =
                dev->event_info->async_req_arr[dev->event_info->req_head].cid;
            queue_update->cq = dev->queue->cq[0];
            wqp = npl_fpa_alloc(dev, CVMX_FPA_WQE_POOL);
            if (!wqp) goto fail;
            npl_setup_wqe(wqp); // set as NVM port type
            wqp->word3.qw3.vf = dev->pfvf; // set pf/vf
            wqp->word5.u64 = (uint64_t)queue_update;

            if (OCTEON_IS_MODEL(OCTEON_CN73XX)) {
                cvmx_wqe_set_tag((cvmx_wqe_t *)wqp,
                    ((CMD_COMPLETION_REQUEST_TAG << NQM_TAG_SHIFT) |
                    (cpl_queue_id << NQM_QID_SHIFT) | dev->pfvf));
                wqp->word3.qw3.sq_id = 0;
                wqp->nvme_cmd.common.cmdid = cqes->cmdid;

                for (i = 0; i < MAX_SQ_DEPTH; i++) {
                    if ((cvmx_atomic_get64((int64_t *)&dev->queue->sq[0]->
                        cmd_id_arr[i]) >> 32) == wqp->nvme_cmd.common.cmdid) {
                        LCMDID(wqp) = i;
                        break;
                    }
                }
                if (i != MAX_SQ_DEPTH)
                    npl_submit_completion_entry(dev, wqp, cqes->result,
                        *(struct completion_status_field *)(&cqes->status));
                npl_fpa_free(wqp, CVMX_FPA_WQE_POOL, sizeof(cvmx_wqe_t));
            } else {
                cvmx_pow_work_submit((cvmx_wqe_t *)wqp,
                    ((CMD_COMPLETION_REQUEST_TAG << NQM_TAG_SHIFT) |
                    (cpl_queue_id << NQM_QID_SHIFT)),
                    CVMX_POW_TAG_TYPE_ATOMIC, NVME_WQE_QOS, NVME_WQE_GRP);
            }

            dev->event_info->Is_error_Masked = 1;
            dev->event_info->error_head = (dev->event_info->error_head + 1) % (max_aerl + 1);
            dev->event_info->req_head = (dev->event_info->req_head + 1) % (max_aerl + 1);
        } else if (dev->event_info->smart_tail != dev->event_info->smart_head &&
                   !(dev->event_info->Is_smart_Masked)) {
            queue_update = npl_fpa_alloc(dev, CPL_QUEUE_UPDATE_POOL);
            if (!queue_update) goto fail;
            cqes = &(queue_update->cqes);
            STATUS_GENERIC(cqes->status, 0, 0, 0);
            ASYNC_EVENT(cqes->result,
                        dev->event_info->smart_queue[dev->event_info->smart_head].aet,
                        dev->event_info->smart_queue[dev->event_info->smart_head].aei,
                        dev->event_info->smart_queue[dev->event_info->smart_head].alp);
            cqes->sqid = 0;
            cqes->sqhead =
                cvmx_atomic_get32((int *)&(dev->queue->sq[0]->sq_head));
            cqes->cmdid =
                dev->event_info->async_req_arr[dev->event_info->req_head].cid;
            queue_update->cq = dev->queue->cq[0];
            wqp = npl_fpa_alloc(dev, CVMX_FPA_WQE_POOL);
            if (!wqp) goto fail;
            npl_setup_wqe(wqp); // set as NVM port type
            wqp->word3.qw3.vf = dev->pfvf; // set pf/vf
            wqp->word5.u64 = (uint64_t)queue_update;

            if (OCTEON_IS_MODEL(OCTEON_CN73XX)) {
                cvmx_wqe_set_tag((cvmx_wqe_t *)wqp,
                    ((CMD_COMPLETION_REQUEST_TAG << NQM_TAG_SHIFT) |
                    (cpl_queue_id << NQM_QID_SHIFT) | dev->pfvf));
                wqp->word3.qw3.sq_id = 0;
                wqp->nvme_cmd.common.cmdid = cqes->cmdid;
                for (i = 0; i < MAX_SQ_DEPTH; i++) {
                    if ((cvmx_atomic_get64((int64_t *)&dev->queue->sq[0]->
                        cmd_id_arr[i]) >> 32) == wqp->nvme_cmd.common.cmdid) {
                        LCMDID(wqp) = i;
                        break;
                    }
                }
                if (i != MAX_SQ_DEPTH)
                    npl_submit_completion_entry(dev, wqp, cqes->result,
                        *(struct completion_status_field *)(&cqes->status));
                npl_fpa_free(wqp, CVMX_FPA_WQE_POOL, sizeof(cvmx_wqe_t));
            } else {
                cvmx_pow_work_submit((cvmx_wqe_t *)wqp,
                    ((CMD_COMPLETION_REQUEST_TAG << NQM_TAG_SHIFT) |
                    (cpl_queue_id << NQM_QID_SHIFT)),
                    CVMX_POW_TAG_TYPE_ATOMIC, NVME_WQE_QOS, NVME_WQE_GRP);
            }

            dev->event_info->Is_smart_Masked = 1;
            dev->event_info->smart_head = (dev->event_info->smart_head + 1) % (max_aerl + 1);
            dev->event_info->req_head = (dev->event_info->req_head + 1) % (max_aerl + 1);
        }
    }
    cvmx_spinlock_unlock(&dev->event_info_lock);
    return 0;

fail:
    npl_fail_status(dev); // set controller fail status
    cvmx_spinlock_unlock(&dev->event_info_lock);

    return -1;
}

/***************************************************************************//**
*
*  npl_update_error_logpages
*
*******************************************************************************/
void npl_update_error_logpages(struct nvme_dev *        dev,
                               struct nvme_log_error *  error_log)
{
    cvmx_atomic_add32((int32_t *)&(error_log->error_count), 1);
    memcpy(&dev->eptr.error_log_array[dev->eptr.top], error_log,
           sizeof(struct nvme_log_error));

    if ((dev->eptr.top == 0)) {
        dev->eptr.top = ERR_LOG_SIZE - 1;

        dev->eptr.queue_wrapped = 1;
    } else {
        dev->eptr.top--;
    }
}

/*enable and compile when SMART feature needed*/

/***************************************************************************//**
*
*  npl_update_smart_logpages
*
*******************************************************************************/
void npl_update_smart_logpages(struct nvme_dev *        dev,
                               struct nvme_log_smart*  smart_log)
{
    memcpy(&dev->sptr.smart_log_array[dev->sptr.top], smart_log,
           sizeof(struct nvme_log_smart));

    if (dev->sptr.top == 0) {
        dev->sptr.top = SMART_LOG_SIZE - 1;
        dev->eptr.queue_wrapped = 1;
    } else {
        dev->sptr.top--;
    }
}

/***************************************************************************//**
*
*  npl_process_logpage
*
*******************************************************************************/
int8_t npl_process_logpage(struct nvme_dev *                dev,
                           cvmx_wqe_tt *                     wqp,
                           struct completion_status_field * cpl_entry,
                           uint32_t *                       result)
{
    uint32_t requested_len = 0;
    uint32_t segment1 = 0;
    struct nvme_dma dma_entry = { 0, };
    struct nvme_cmd nvme_cmd = wqp->nvme_cmd;
    int32_t ret = 0;
    cvmx_wqe_tt *wqp_new;
    uint32_t count = 15000;

    cpl_entry->sct = SCT_GENERIC;
    cpl_entry->sc = INTERNAL_ERROR;
    cpl_entry->m = 0;
    cpl_entry->dnr = 0;
    *result = 0;

    if ((le32_cpu(nvme_cmd.get_log_page.nsid) >
         le32_cpu(dev->dev_config.id_ctrl.nn) &&
         (le32_cpu(nvme_cmd.get_log_page.nsid) != 0xFFFFFFFF))) {
        cpl_entry->sct = SCT_GENERIC;
        cpl_entry->sc = INVALID_FIELD_CMD;
        cpl_entry->m = 0;
        cpl_entry->dnr = 0;
        *result = 0;
        return STATUS_ERROR;
    }
    if (((nvme_cmd.get_log_page.lpi) & 0xff) == 0x01) { /* Error Information */
        /* Check the number of Dwords requested and calculate the total bytes to transfer */
        requested_len = (((nvme_cmd.get_log_page.lpi >> 16) & 0xfff) + 1) * 4;

        segment1 = (ERR_LOG_SIZE - (dev->eptr.top)) *
                   (sizeof(struct nvme_log_error));
        if ((dev->eptr.queue_wrapped) && (requested_len > segment1)) {
            dma_entry.src =
                (uint64_t)&dev->eptr.error_log_array[dev->eptr.top + 1];
            dma_entry.nbytes = segment1;
            dma_entry.lastptr.prp1 = nvme_cmd.get_log_page.prp1;
            dma_entry.lastptr.prp2 = nvme_cmd.get_log_page.prp2;
            dma_entry.trans_type.dma_mode = DMA_OUTBOUND;
            dma_entry.trans_type.prp_mode = DMA_ONLY_NONE;

            dma_entry.trans_type.prp_mode = DMA_BYTE_POINTER;
            dma_entry.byte_pointer = (char *)npl_fpa_alloc(dev, CVMX_FPA_WQE_POOL);
            if (!dma_entry.byte_pointer) goto fail;
            *((volatile char *)dma_entry.byte_pointer) = 1;
            ret = npl_dma_submit(dev, &dma_entry, wqp);
            if (ret == DMA_ERROR) {
                debug_printf(1, "Error: process_logpage() SMART DMA failed");
                return STATUS_ERROR;
            }
            while (*((volatile char *)dma_entry.byte_pointer) != 0 && count--) {
                debug_printf(3, "dma counter = %u", count);
                CVMX_SYNCWS;
            }

            if (!count)
                debug_printf(1,
                             "Error: npl_process_logpage(): dma too slow or failed");


            npl_fpa_free(dma_entry.byte_pointer, CVMX_FPA_WQE_POOL,
                         sizeof(cvmx_wqe_t));                                                                //DMA LOG

            /* Alocate a new WQ */
            wqp_new = npl_fpa_alloc(dev, CVMX_FPA_WQE_POOL);
            if (!wqp_new) goto fail;
            memcpy(wqp_new, wqp, sizeof(cvmx_wqe_t));
            npl_setup_wqe(wqp_new);
            wqp_new->word3.qw3.vf = dev->pfvf; // set pf/vf
            wqp_new->word1.qw1.tag =
                (ADMIN_DATA_TRANSFER_TAG << NQM_TAG_SHIFT) |
                (wqp->word3.qw3.sq_id << NQM_QID_SHIFT);
            wqp_new->word1.qw1.tt = CVMX_POW_TAG_TYPE_ORDERED;

            dma_entry.src = (uint64_t)&dev->eptr.error_log_array[0];
            dma_entry.nbytes = (requested_len - segment1);
            dma_entry.lastptr.prp1 = nvme_cmd.get_log_page.prp1;
            dma_entry.lastptr.prp2 = nvme_cmd.get_log_page.prp2;
            dma_entry.trans_type.dma_mode = DMA_OUTBOUND;
            dma_entry.trans_type.prp_mode = PRP_NOLIST;
            ret = npl_dma_submit(dev, &dma_entry, wqp_new);
            if (ret == DMA_ERROR) {
                debug_printf(1, "Error:  process_logpage() dma has failed");
                npl_fpa_free(wqp_new, CVMX_FPA_WQE_POOL, sizeof(cvmx_wqe_t));
                return STATUS_ERROR;
            }

            dev->event_info->Is_error_Masked = 0;

            cpl_entry->sct = SCT_GENERIC;
            cpl_entry->sc = CMD_SUCCESSFUL;
            cpl_entry->m = 0;
            cpl_entry->dnr = 1;
            *result = 0;
            return STATUS_SUCCESS;
        } else {
            dma_entry.src =
                (uint64_t)&dev->eptr.error_log_array[dev->eptr.top + 1];

            dma_entry.nbytes = requested_len;
            dma_entry.lastptr.prp1 = nvme_cmd.get_log_page.prp1;
            dma_entry.lastptr.prp2 = nvme_cmd.get_log_page.prp2;
            dma_entry.trans_type.dma_mode = DMA_OUTBOUND;
            dma_entry.trans_type.prp_mode = PRP_NOLIST;

            /* Alocate a new WQ */
            wqp_new = npl_fpa_alloc(dev, CVMX_FPA_WQE_POOL);
            if (!wqp_new) goto fail;
            memcpy(wqp_new, wqp, sizeof(cvmx_wqe_t));
            npl_setup_wqe(wqp_new);
            wqp_new->word3.qw3.vf = dev->pfvf; // set pf/vf
            wqp_new->word1.qw1.tag =
                (ADMIN_DATA_TRANSFER_TAG << NQM_TAG_SHIFT) |
                (wqp->word3.qw3.sq_id << NQM_QID_SHIFT);
            wqp_new->word1.qw1.tt = CVMX_POW_TAG_TYPE_ORDERED;

            ret = npl_dma_submit(dev, &dma_entry, wqp_new);
            if (ret == DMA_ERROR) {
                debug_printf(1, "Error:  process_logpage() dma has failed");
                npl_fpa_free(wqp_new, CVMX_FPA_WQE_POOL, sizeof(cvmx_wqe_t));

                return STATUS_ERROR;
            }
            dev->event_info->Is_error_Masked = 0;

            cpl_entry->sct = SCT_GENERIC;
            cpl_entry->sc = CMD_SUCCESSFUL;
            cpl_entry->m = 0;
            cpl_entry->dnr = 1;
            *result = 0;
            return STATUS_SUCCESS;
        }
    }
    /*SMART Health enable & compile when needed*/
    else if ((nvme_cmd.get_log_page.lpi & 0xff) == 0x2) {
        requested_len = (((nvme_cmd.get_log_page.lpi >> 16) & 0xfff) + 1) * 4;

        segment1 = (SMART_LOG_SIZE - (dev->sptr.top)) *
                   (sizeof(struct nvme_log_smart));
        if ((dev->eptr.queue_wrapped) && (requested_len > segment1)) {
            dma_entry.src =
                (uint64_t)&dev->sptr.smart_log_array[dev->sptr.top + 1];

            dma_entry.nbytes = segment1;
            dma_entry.lastptr.prp1 = nvme_cmd.get_log_page.prp1;

            dma_entry.lastptr.prp2 = nvme_cmd.get_log_page.prp2;
            dma_entry.trans_type.dma_mode = DMA_OUTBOUND;
            dma_entry.trans_type.prp_mode = DMA_ONLY_NONE;

            dma_entry.trans_type.prp_mode = DMA_BYTE_POINTER;
            dma_entry.byte_pointer = (char *)npl_fpa_alloc(dev, CVMX_FPA_WQE_POOL);
            if (!dma_entry.byte_pointer) goto fail;
            *((volatile char *)dma_entry.byte_pointer) = 1;

            ret = npl_dma_submit(dev, &dma_entry, wqp);
            if (ret == DMA_ERROR) {
                debug_printf(1, "Error: process_logpage() SMART dma failed");

                return STATUS_ERROR;
            }

            while (*((volatile char *)dma_entry.byte_pointer) != 0 && count--) {
                debug_printf(3, "dma counter = %u", count);
                CVMX_SYNCWS;
            }

            if (!count)
                debug_printf(1,
                             "Error: npl_process_logpage(): dma too slow or failed");


            npl_fpa_free(dma_entry.byte_pointer, CVMX_FPA_WQE_POOL,
                         sizeof(cvmx_wqe_t));                                                                //DMA LOG

            /* Alocate a new WQ */
            wqp_new = npl_fpa_alloc(dev, CVMX_FPA_WQE_POOL);
            if (!wqp_new) goto fail;
            memcpy(wqp_new, wqp, sizeof(cvmx_wqe_t));
            npl_setup_wqe(wqp_new);
            wqp_new->word3.qw3.vf = dev->pfvf; // set pf/vf
            wqp_new->word1.qw1.tag =
                (ADMIN_DATA_TRANSFER_TAG << NQM_TAG_SHIFT) |
                (wqp->word3.qw3.sq_id << NQM_QID_SHIFT);
            wqp_new->word1.qw1.tt = CVMX_POW_TAG_TYPE_ORDERED;

            dma_entry.src = (uint64_t)&dev->sptr.smart_log_array[0];
            dma_entry.nbytes = (requested_len - segment1);
            dma_entry.lastptr.prp1 = nvme_cmd.get_log_page.prp1;
            dma_entry.lastptr.prp2 = nvme_cmd.get_log_page.prp2;
            dma_entry.trans_type.dma_mode = DMA_OUTBOUND;
            dma_entry.trans_type.prp_mode = PRP_NOLIST;

            ret = npl_dma_submit(dev, &dma_entry, wqp_new);
            if (ret == DMA_ERROR) {
                debug_printf(1, "Error:  process_logpage() dma has failed");
                npl_fpa_free(wqp_new, CVMX_FPA_WQE_POOL, sizeof(cvmx_wqe_t));

                return STATUS_ERROR;
            }

            dev->event_info->Is_smart_Masked = 0;
            cpl_entry->sct = SCT_GENERIC;
            cpl_entry->sc = CMD_SUCCESSFUL;
            cpl_entry->m = 0;
            cpl_entry->dnr = 1;
            *result = 0;
            return STATUS_SUCCESS;
        } else {
            dma_entry.src =
                (uint64_t)&dev->sptr.smart_log_array[dev->sptr.top + 1];
            dma_entry.nbytes = requested_len;
            dma_entry.lastptr.prp1 = nvme_cmd.get_log_page.prp1;
            dma_entry.lastptr.prp2 = nvme_cmd.get_log_page.prp2;
            dma_entry.trans_type.dma_mode = DMA_OUTBOUND;
            dma_entry.trans_type.prp_mode = PRP_NOLIST;

            /* Alocate a new WQ */
            wqp_new = npl_fpa_alloc(dev, CVMX_FPA_WQE_POOL);
            if (!wqp_new) goto fail;
            memcpy(wqp_new, wqp, sizeof(cvmx_wqe_t));
            npl_setup_wqe(wqp_new);
            wqp_new->word3.qw3.vf = dev->pfvf; // set pf/vf
            wqp_new->word1.qw1.tag =
                (ADMIN_DATA_TRANSFER_TAG << NQM_TAG_SHIFT) |
                (wqp->word3.qw3.sq_id << NQM_QID_SHIFT);
            wqp_new->word1.qw1.tt = CVMX_POW_TAG_TYPE_ORDERED;

            ret = npl_dma_submit(dev, &dma_entry, wqp_new);
            if (ret == DMA_ERROR) {
                debug_printf(1, "Error:  process_logpage() dma has failed");
                npl_fpa_free(wqp_new, CVMX_FPA_WQE_POOL, sizeof(cvmx_wqe_t));
                return STATUS_ERROR;
            }
            dev->event_info->Is_smart_Masked = 0;

            cpl_entry->sct = SCT_GENERIC;
            cpl_entry->sc = CMD_SUCCESSFUL;
            cpl_entry->m = 0;
            cpl_entry->dnr = 1;
            *result = 0;
            return STATUS_SUCCESS;
        }
    } else if (((nvme_cmd.get_log_page.lpi) & 0xff) == 0x03) {
        requested_len = (((nvme_cmd.get_log_page.lpi >> 16) & 0xfff) + 1) * 4;
        
        segment1 = (FIRMWARE_LOG_SIZE - (dev->fware_ptr.top)) *
                   (sizeof(struct nvme_log_firmware));
        if ((dev->fware_ptr.queue_wrapped) && (requested_len > segment1)) {
            dma_entry.src =
                (uint64_t)&dev->fware_ptr.firmware_log_array[
                    dev->fware_ptr.top + 1];

            dma_entry.nbytes = segment1;
            dma_entry.lastptr.prp1 = nvme_cmd.get_log_page.prp1;

            dma_entry.lastptr.prp2 = nvme_cmd.get_log_page.prp2;
            dma_entry.trans_type.dma_mode = DMA_OUTBOUND;
            dma_entry.trans_type.prp_mode = DMA_ONLY_NONE;

            dma_entry.trans_type.prp_mode = DMA_BYTE_POINTER;
            dma_entry.byte_pointer = (char *)npl_fpa_alloc(dev, CVMX_FPA_WQE_POOL);
            if (!dma_entry.byte_pointer) goto fail;
            *((volatile char *)dma_entry.byte_pointer) = 1;

            ret = npl_dma_submit(dev, &dma_entry, wqp);
            if (ret == DMA_ERROR) {
                debug_printf(1, "Error: process_logpage() SMART dma failed");

                return STATUS_ERROR;
            }

            while (*((volatile char *)dma_entry.byte_pointer) != 0 && count--) {
                debug_printf(3, "dma counter = %u", count);
                CVMX_SYNCWS;
            }

            if (!count)
                debug_printf(1,
                             "npl_process_logpage(): dma too slow or failed");

            npl_fpa_free(dma_entry.byte_pointer, CVMX_FPA_WQE_POOL,
                         sizeof(cvmx_wqe_t));

            /* Alocate a new WQ */
            wqp_new = npl_fpa_alloc(dev, CVMX_FPA_WQE_POOL);
            if (!wqp_new) goto fail;
            memcpy(wqp_new, wqp, sizeof(cvmx_wqe_t));
            npl_setup_wqe(wqp_new);
            wqp_new->word3.qw3.vf = dev->pfvf; // set pf/vf
            wqp_new->word1.qw1.tag =
                (ADMIN_DATA_TRANSFER_TAG << NQM_TAG_SHIFT) |
                (wqp->word3.qw3.sq_id << NQM_QID_SHIFT);
            wqp_new->word1.qw1.tt = CVMX_POW_TAG_TYPE_ORDERED;

            dma_entry.src = (uint64_t)&dev->fware_ptr.firmware_log_array[0];
            dma_entry.nbytes = (requested_len - segment1);
            dma_entry.lastptr.prp1 = nvme_cmd.get_log_page.prp1;
            dma_entry.lastptr.prp2 = nvme_cmd.get_log_page.prp2;
            dma_entry.trans_type.dma_mode = DMA_OUTBOUND;
            dma_entry.trans_type.prp_mode = PRP_NOLIST;
            ret = npl_dma_submit(dev, &dma_entry, wqp_new);
            if (ret == DMA_ERROR) {
                debug_printf(1, "Error:  process_logpage() dma has failed");
                npl_fpa_free(wqp_new, CVMX_FPA_WQE_POOL, sizeof(cvmx_wqe_t));

                return STATUS_ERROR;
            }
            cpl_entry->sct = SCT_GENERIC;
            cpl_entry->sc = CMD_SUCCESSFUL;
            cpl_entry->m = 0;
            cpl_entry->dnr = 1;
            *result = 0;
            return STATUS_SUCCESS;
        } else {
            dma_entry.src = (uint64_t)&dev->fware_ptr.firmware_log_array[
                dev->fware_ptr.top + 1];
            dma_entry.nbytes = requested_len;
            dma_entry.lastptr.prp1 = nvme_cmd.get_log_page.prp1;
            dma_entry.lastptr.prp2 = nvme_cmd.get_log_page.prp2;
            dma_entry.trans_type.dma_mode = DMA_OUTBOUND;
            dma_entry.trans_type.prp_mode = PRP_NOLIST;

            /* Alocate a new WQ */
            wqp_new = npl_fpa_alloc(dev, CVMX_FPA_WQE_POOL);
            if (!wqp_new) goto fail;
            memcpy(wqp_new, wqp, sizeof(cvmx_wqe_t));
            npl_setup_wqe(wqp_new);
            wqp_new->word3.qw3.vf = dev->pfvf; // set pf/vf
            wqp_new->word1.qw1.tag =
                (ADMIN_DATA_TRANSFER_TAG << NQM_TAG_SHIFT) |
                (wqp->word3.qw3.sq_id << NQM_QID_SHIFT);
            wqp_new->word1.qw1.tt = CVMX_POW_TAG_TYPE_ORDERED;

            ret = npl_dma_submit(dev, &dma_entry, wqp_new);
            if (ret == DMA_ERROR) {
                debug_printf(1, "Error:  process_logpage() dma has failed");
                npl_fpa_free(wqp_new, CVMX_FPA_WQE_POOL, sizeof(cvmx_wqe_t));
                return STATUS_ERROR;
            }

            cpl_entry->sct = SCT_GENERIC;
            cpl_entry->sc = CMD_SUCCESSFUL;
            cpl_entry->m = 0;
            cpl_entry->dnr = 1;
            *result = 0;
            return STATUS_SUCCESS;
        }
    } else {
        /*Return a completion entry with status value  INVALID_LOG_PAGE  */
        *result = 0;
        cpl_entry->sct = SCT_COMMAND;
        cpl_entry->sc = INVALID_LOG_PAGE;
        cpl_entry->m = 0;
        cpl_entry->dnr = 1;
        return STATUS_ERROR;
    }
    return STATUS_SUCCESS;

fail:
    return STATUS_ERROR;
}

/***************************************************************************//**
*
*   npl_add_completion_queue_entry ()
*
*  This function used to submit the completion entries from device to
*  host
*
*    @param dev          Private structure pointer
*    @param wqe_cq     Work queue entry
*
*
*******************************************************************************/
int npl_add_completion_queue_entry(struct nvme_dev *   dev,
                                    cvmx_wqe_tt *        wqe_cq)
{
    struct nvme_dma nvme_dma_cplq = { 0, }; /* declare nvme_dma variable */
    uint8_t phase = 0;
    uint16_t cq_id = dev->queue->sq[wqe_cq->word3.qw3.sq_id]->cq_id;
    volatile struct nvme_completion *cq_entry_ptr;
    struct nvme_completion recd_cq_entry = { 0 };
    struct cpl_queue_update *cpl_update = NULL;
    uint32_t cpl_entry_count = 0;
    struct nvme_list *cpl_list_entry = NULL;
    int result;
    uint16_t prev_cq_tail, cq_tail, cq_depth;
    uint8_t i;
    cvmx_wqe_tt *new_wqp;

    uint32_t *cq_full = &(dev->queue->cq[cq_id]->cq_full);
    volatile uint32_t *cq_head;

    uint32_t pending_entries = dev->queue->cq[cq_id]->pending_entries;

    prev_cq_tail = cq_tail = dev->queue->cq[cq_id]->cq_tail;
    cq_head = &(dev->queue->cq[cq_id]->cq_head);
    cq_depth = dev->queue->cq[cq_id]->cq_depth;

    /* Chcek if we have a valid completion entry */
    if (wqe_cq->word5.u64 != 0)
        cpl_update = (struct cpl_queue_update *)wqe_cq->word5.u64;

#ifdef NVME_68XX_SUPPORT
    if (!OCTEON_IS_MODEL(OCTEON_CN73XX)) {
        cvmx_atomic_set32((int32_t *)cq_head,
                          *((volatile uint32_t *)
                            ((uint8_t *)nvme_bar1 + (0x1000 + (0x08 * cq_id + 4)))));
    }
#endif
    /*   Queue the completion entry if the completion queue under subject is
     *    full and there is a valid completion entry (not dummy call).
     */
    if (((cq_tail + 1) % cq_depth) == cvmx_atomic_get32((int32_t *)cq_head)) {
        cvmx_atomic_set32(((int32_t *)cq_full), 1);
        if (wqe_cq->word5.u64 != 0) {
            /* Add the completion entry (wqe_cq->word5.u64)->cqes to the tail of the pending queue list */
            cpl_list_entry = (struct nvme_list *)npl_fpa_alloc(dev, LIST_NODE_POOL);
            if (!cpl_list_entry) goto fail;
            memset(cpl_list_entry, 0, sizeof(struct nvme_list));
            cpl_list_entry->data = (struct nvme_completion *)npl_fpa_alloc(dev,
                CPL_QUEUE_UPDATE_POOL);
            if (!cpl_list_entry->data) goto fail;
            memset(cpl_list_entry->data, 0, sizeof(struct nvme_completion));
            memcpy(cpl_list_entry->data, &cpl_update->cqes,
                   sizeof(struct nvme_completion));
            list_add_tail(&cpl_list_entry->list,
                          &dev->queue->cq[cq_id]->cpl_list.list);
            /* Increment the pending queue entries. Will be used as a check flag for posting dummy work entries */
            pending_entries++;
            /* Decrement the entry count in the submission queue by 1 */
            if (cvmx_atomic_get32(
                    (int32_t *)&(dev->queue->sq[wqe_cq->word3.qw3.sq_id]->
                                 num_entries)) > 0)
                cvmx_atomic_add32(
                    (int32_t *)&(dev->queue->sq[wqe_cq->word3.qw3.sq_id]->
                                 num_entries), -1);
        } else {
            debug_printf(1, "ERROR: Completion Queue entry Invalid");
            return -1;
        }
    } else {
        /* If there are no pending entries already and we have a valid work entry */
        if (wqe_cq->word5.u64 != 0)
            ++pending_entries;
        while ((((cq_tail + 1) % cq_depth) !=
                cvmx_atomic_get32((int32_t *)cq_head)) && (pending_entries)) {
            /* Get the cq tail to insert a new entry */
            cq_entry_ptr = &dev->queue->cq[cq_id]->cqes[cq_tail];
            /* Check the abort array, if this command is requested for abort */
            for (i = 0; i < dev->id_ctrl->acl; i++) {
                if (dev->queue->abort_arr[i].sqid == cq_entry_ptr->sqid &&
                    dev->queue->abort_arr[i].cid == cq_entry_ptr->cmdid) {
                    /**
                     * Abort requested for this command, but we can not abort this
                     * because it is already completed, so complete the abort command
                     */
                    new_wqp = npl_fpa_alloc(dev, CVMX_FPA_WQE_POOL);
                    if (!new_wqp) goto fail;
                    npl_setup_wqe(new_wqp);
                    new_wqp->word3.qw3.vf = dev->pfvf; // set pf/vf
                    new_wqp->word3.qw3.sq_id = cq_entry_ptr->sqid;
                    memcpy((struct nvme_cmd *)&(new_wqp->nvme_cmd),
                           (struct nvme_cmd *)&(dev->queue->abort_arr[i]),
                           sizeof(struct nvme_cmd));
                    /* The command can not be aborted, so set the result value as 1 */
                    npl_set_status_and_submit(dev, new_wqp, SCT_GENERIC,
                                              CMD_SUCCESSFUL, 1);
                    /* Clear the abort flag */
                    cvmx_atomic_fetch_and_bclr64_nosync(
                        &(dev->queue->sq[cq_entry_ptr->sqid]->cmd_id_arr
                          [cq_entry_ptr->cmdid]), 1);
                    break;
                }
            }
            /* Retrieve the current phase bit from 0th bit of status */
            phase = (uint8_t)(le16_cpu(cq_entry_ptr->status) & 0x0001);
            /* Retrieve the completion queue entry to process */
            if (wqe_cq->word5.u64 != 0) {
                memcpy(&recd_cq_entry, &(cpl_update->cqes),
                       sizeof(struct nvme_completion));
                wqe_cq->word5.u64 = 0;
            } else {
                /* Get the first entry from the list */
                cpl_list_entry = list_first_entry_or_null(
                    &dev->queue->cq[cq_id]->cpl_list.list, struct nvme_list,
                    list);
                if (cpl_list_entry != NULL) {
                    memcpy((void *)&(recd_cq_entry), cpl_list_entry->data,
                           sizeof(struct nvme_completion));
                    /* Free the list entry */
                    npl_fpa_free(cpl_list_entry->data, CPL_QUEUE_UPDATE_POOL,
                                 sizeof(struct nvme_completion));
                    list_del(&cpl_list_entry->list);
                    npl_fpa_free(cpl_list_entry, LIST_NODE_POOL,
                                 sizeof(struct nvme_list));
                } else {
                    debug_printf(1, "Error:Process from cpl_list");
                }
            }
            /* Update the completion command entry */
            cq_entry_ptr->result = recd_cq_entry.result;
            cq_entry_ptr->status = recd_cq_entry.status;
            cq_entry_ptr->cmdid = recd_cq_entry.cmdid;
            cq_entry_ptr->sqid = recd_cq_entry.sqid;
            //cq_entry_ptr->sq_head   = dev->queue->sq[wqe_cq->word3.qw3.sq_id]->sq_head;
            cq_entry_ptr->sqhead =
                dev->queue->sq[recd_cq_entry.sqid]->sq_head;
            /* Decrement the entry count in the submission queue by 1 */
            if (cvmx_atomic_get32(
                    (int32_t *)&(dev->queue->sq[wqe_cq->word3.qw3.sq_id]->
                                 num_entries)) > 0)
                cvmx_atomic_add32(
                    (int32_t *)&(dev->queue->sq[cq_entry_ptr->sqid]->
                                 num_entries), -1);
            /* toggle the phase bit */
            if (phase)
                cq_entry_ptr->status &= ~(0x0001);
            else
                cq_entry_ptr->status |= 0x0001;

            cq_entry_ptr->cmdid = le16_cpu(cq_entry_ptr->cmdid);
            cq_entry_ptr->result = le32_cpu(cq_entry_ptr->result);
            cq_entry_ptr->status = le16_cpu(cq_entry_ptr->status);
            cq_entry_ptr->sqid = le16_cpu(cq_entry_ptr->sqid);
            cq_entry_ptr->sqhead = le16_cpu(cq_entry_ptr->sqhead);

            /* Increment the cq->cq_tail and check whether the tail reaches the cq->cq_depth, if so update the cq->cq_tail value to zero */
            if (++cq_tail == cq_depth) {
                ++cpl_entry_count;
                --pending_entries;
#if DISCONTIGUOUS_Q_SUPPORT
                if (dev->queue->cq[cq_id]->queue_discontiguous) {
                    /* Transfer the completion queue entries to the host side dis-contiguous queue */
                    npl_xfer_discontiguous_cq_entries(dev, prev_cq_tail,
                                                      cpl_entry_count, cq_id,
                                                      wqe_cq);
                } else
#endif
                {
                    /* Set up nvme_dma structure for transferring the completion queue entry to host */
                    nvme_dma_cplq.src =
                        (uint64_t)(dev->queue->cq[cq_id]->cqes + prev_cq_tail);
                    nvme_dma_cplq.dst =
                        (uint64_t)(dev->queue->cq[cq_id]->host_cpl_queue_addr +
                                   prev_cq_tail);
                    nvme_dma_cplq.nbytes = cpl_entry_count *
                                           sizeof(struct nvme_completion);
                    nvme_dma_cplq.trans_type.dma_mode = DMA_OUTBOUND;
                    nvme_dma_cplq.trans_type.prp_mode = PRP_NULL;
                    nvme_dma_cplq.trans_type.cpl_transfer = 1;

                    /* Call the DMA function to update host completion queue */
                    result =
                        npl_dma_submit(dev, &nvme_dma_cplq, /*NULL*/ wqe_cq);       //0503
                    if (result)
                        debug_printf(1,
                                     "Error: Add Completion Entry DMA txfer has failed");

                }
                prev_cq_tail = 0;
                cq_tail = 0;
                cpl_entry_count = 0;
                continue;
            }
            ++cpl_entry_count;
            --pending_entries;
        }/* end of while */

        /* Do a DMA if entries were copied into the main completion queue */
        if (cpl_entry_count) {
#if DISCONTIGUOUS_Q_SUPPORT
            if (dev->queue->cq[cq_id]->queue_discontiguous) {
                /* Transfer the completion queue entries to the host side dis-contiguous queue */
                npl_xfer_discontiguous_cq_entries(dev, prev_cq_tail,
                                                  cpl_entry_count, cq_id,
                                                  wqe_cq);
            } else
#endif
            {
                /* Setup nvme_dma structure for transferring the completion queue entry to host */
                nvme_dma_cplq.src =
                    (uint64_t)(dev->queue->cq[cq_id]->cqes + prev_cq_tail);
                nvme_dma_cplq.dst =
                    (uint64_t)(dev->queue->cq[cq_id]->host_cpl_queue_addr +
                               prev_cq_tail);
                nvme_dma_cplq.nbytes = cpl_entry_count *
                                       sizeof(struct nvme_completion);
                nvme_dma_cplq.trans_type.dma_mode = DMA_OUTBOUND;
                nvme_dma_cplq.trans_type.prp_mode = PRP_NULL;
                nvme_dma_cplq.trans_type.cpl_transfer = 1;
                /* Call the DMA function to update host completion queue */
                result = npl_dma_submit(dev, &nvme_dma_cplq, wqe_cq);
                if (result)
                    debug_printf(1,
                                 "Error: Add Completion Entry DMA txfer has failed");

            }
        }

        /**
         * if the pending_entries count is 0 && the queue full condition is not met && the cq_full flag is set,
         *  reset the  cq_full flag atomically.
         */
        if ((pending_entries == 0) && (*cq_full == 1) &&
            ((cq_tail + 1) % cq_depth) != cvmx_atomic_get32((int32_t *)cq_head))
            cvmx_atomic_set32(((int32_t *)cq_full), 0);

        /* Free the memory allocated for wqe_cq */
        if (wqe_cq) {
            if (cpl_update)
                npl_fpa_free(cpl_update, CPL_QUEUE_UPDATE_POOL,
                             sizeof(struct cpl_queue_update));
            wqe_cq = NULL;
        }
    }
    cvmx_atomic_set32((int32_t *)&(dev->queue->cq[cq_id]->pending_entries),
                      pending_entries);
    dev->queue->cq[cq_id]->cq_tail = cq_tail;

    return 0;

fail:
    npl_fail_status(dev); // set controller fail status

    return -1;
}


/***************************************************************************//**
*
*  npl_dma_submit():
*
*  This function will provide the abstraction from physical dma to modules.
*  It is called by modules for performing inbound or outbound dma for nvme-queue transfers, list transfers,
*  prp based transfers and completion transfers.
*
*  @param dev          pointer to a device structure of type struct nvme_dev.
*  @param dma_entry     pointer to a structure of type struct nvme_dma
*  @param wqe          pointer to work queue entry of type cvmx_wqe_t
*                      (Freed only if success)
*
*
*  @return     -1 : DMA_ERROR, 0 : DMA_SUCCESS
*              On DMA_ERROR, dma_entry will contain bytes not xfered.
*
*******************************************************************************/
int npl_dma_submit(struct nvme_dev *dev,
                   struct nvme_dma *dma_entry,
                   cvmx_wqe_tt *     wqe)
{
    /*declare an array of buffers for DMA Instruction info*/
    cvmx_dma_engine_buffer_t buffers[32];

    uint64_t first_address = 0;
    uint64_t last_address = 0;
    int ret = -1;
    int words = 0;
    uint64_t prp1_nbytes = 0;
    uint64_t pagesize = dev->host_page_size;
    uint64_t pageoffset = 0;

    cvmx_dma_engine_header_t dma_hdr = {{ 0 }, { 0 } };
    cvmx_wqe_tt *wqe_new = NULL;
    uint32_t dma_engine = DMA_ENGINE;
    cvmx_dma_engine_buffer_t *dma_buf = NULL;

#ifdef DMA_MULTI_Q
#if 0 //modified DMA scheduling to Round-Robin; kept old scheme code for reference.

#ifdef DMA_MULTI_Q_CMDID
    uint16_t cmd_id = wqe->nvme_cmd.rw.cmdid;
    dma_engine = cmd_id % DMA_MAX_HW_ENGINES;
#else
    uint16_t sq_id = wqe->word3.qw3.sq_id;
    dma_engine = sq_id % DMA_MAX_HW_ENGINES;
#endif

#else
    /* Commands are scheduled to DMA engines in round-robin method;
     * These commands include CMD_FETCH commands 
     */
    static uint32_t next_dma_engine = 0;

    if (OCTEON_IS_MODEL(OCTEON_CN73XX_PASS1_0)) {
        dma_engine = next_dma_engine % NVME_IO_DMAQ_MAX;

        // Use DMA engine-0 (queue 0) for nvme_cmd fetch and 1, 2, 3 for IO
        if ((cvmx_wqe_get_tag((cvmx_wqe_t *)wqe) >>
                NQM_TAG_SHIFT) == CMD_HANDLE_TAG)
            dma_engine = 0;
        else
            dma_engine = io_dma_queue[dma_engine];
    } else
	dma_engine = next_dma_engine % DMA_MAX_HW_ENGINES;

    next_dma_engine++;
#endif
#endif

    memset(buffers, 0, sizeof(cvmx_dma_engine_buffer_t) * 32);
    /*initialize DMA header*/
    dma_hdr.word0.u64 = 0;
    if (OCTEON_IS_MODEL(OCTEON_CN73XX)) {
        dma_hdr.word0.cn78xx.lport = NVME_PCIE_PORT;
        dma_hdr.word0.cn78xx.ii = 1;
        dma_hdr.word0.cn78xx.aura = 0;
    	dma_hdr.word1.s.deallocv  = (2 << 13) | dev->pfvf;
    	dma_hdr.word0.cn78xx.pvfe = 1;
    } else {
        dma_hdr.word0.cn38xx.lport = 1;
        dma_hdr.word0.cn38xx.ii = 1;
    }
    /*change these 2 where ever required(cpl_transfer, prp list transfer), initialize accordingly*/
    if (wqe) {
        if (OCTEON_IS_MODEL(OCTEON_CN73XX)) {
            dma_hdr.word1.s.ptr = cvmx_ptr_to_phys(wqe);
            dma_hdr.word0.cn78xx.pt = 2;
        } else {
            dma_hdr.word0.cn38xx.addr = cvmx_ptr_to_phys(wqe);
            dma_hdr.word0.cn38xx.wqp = 1;
        }
    }
    if (dma_entry->trans_type.dma_mode == DMA_INBOUND) {
        if (OCTEON_IS_MODEL(OCTEON_CN73XX))
            dma_hdr.word0.cn78xx.type = DMA_INBOUND;
        else
            dma_hdr.word0.cn38xx.type = DMA_INBOUND;
        first_address = cvmx_ptr_to_phys((void *)dma_entry->dst);
    } else {
        if (OCTEON_IS_MODEL(OCTEON_CN73XX))
            dma_hdr.word0.cn78xx.type = DMA_OUTBOUND;
        else
            dma_hdr.word0.cn38xx.type = DMA_OUTBOUND;

        first_address = cvmx_ptr_to_phys((void *)dma_entry->src);
    }
    switch (dma_entry->trans_type.prp_mode) {
    /*When 'dst' and 'src' are only defined: Queue transfer, List Transfer (no PRPs)*/
    case PRP_NULL:
        if (dma_entry->trans_type.dma_mode == DMA_INBOUND)
            last_address = dma_entry->src;
        else
            last_address = dma_entry->dst;
        if (dma_entry->trans_type.cpl_transfer == CPL_TRANSFER) {
#ifdef DMA_INTR_COALESCING

            if (!wqe->word3.qw3.sq_id) {    //sqid=0, if Admin Command, Immediately raise an interrupt.
                if (OCTEON_IS_MODEL(OCTEON_CN73XX))
                    dma_hdr.word0.cn78xx.fi = 0;           //enable forced interrupt
                else
                    dma_hdr.word0.cn38xx.fi = 1;           //enable forced interrupt
            } else {
                if (OCTEON_IS_MODEL(OCTEON_CN73XX)) {
                    dma_hdr.word0.cn78xx.csel = 1;            //Use COUNTER 1
                    dma_hdr.word0.cn78xx.ca = 1;           //use COUNTER add
                } else {
                    dma_hdr.word0.cn38xx.c = 1;            //Use COUNTER 1
                    dma_hdr.word0.cn38xx.ca = 1;           //use COUNTER add
                }
            }

#else
            if (OCTEON_IS_MODEL(OCTEON_CN73XX))
                dma_hdr.word0.cn78xx.fi = 0;                   //enable forced interrupt
            else
                dma_hdr.word0.cn38xx.fi = 1;                   //enable forced interrupt
#endif

            if (OCTEON_IS_MODEL(OCTEON_CN73XX)) {
                dma_hdr.word1.s.ptr = 0;
                dma_hdr.word0.cn78xx.pt = 0;
            } else {
                dma_hdr.word0.cn38xx.addr = 0;
                dma_hdr.word0.cn38xx.wqp = 0;
            }
        }
        if (!first_address || !last_address || !dma_entry->nbytes) {
            debug_printf(1, "DMA ERROR: PRP_NULL ....wrong parameters");

            if (!first_address)
                debug_printf(1, "First Addr= 0x%016lx", first_address);

            if (!last_address)
                debug_printf(1, "Last Addr= 0x%016lx", last_address);

            if (!dma_entry->nbytes)
                debug_printf(1, "nbytes = 0x%x", dma_entry->nbytes);
            
            return DMA_ERROR;
        }
        /*call SDK dma transfer API; Assuming memories are contiguous both sides and limited to */
        npl_update_dma_inout_stats(dma_engine, dma_entry->trans_type.dma_mode);

        CVMX_SYNCWS;
        ret = cvmx_dma_engine_transfer(dma_engine, dma_hdr, first_address,
                                       last_address, dma_entry->nbytes);
        if (ret) {
            debug_printf(1, "DMA_ERROR: ....PRP_NULL");
        } else {
            dma_entry->nbytes = 0;
        }
        break;

    /* When only PRPs are involved */
    case PRP_NOLIST:
        if (!first_address || !dma_entry->lastptr.prp1 || !dma_entry->nbytes) {
            debug_printf(1, "DMA ERROR: PRP_NOLIST ....wrong parameters");

            if (!first_address)
                debug_printf(1, "First Addr= 0x%016lx", first_address);

            if (!dma_entry->lastptr.prp1)
                debug_printf(1, "lastptr.prp1= 0x%016lx",
                             dma_entry->lastptr.prp1);

            if (!dma_entry->nbytes)
                debug_printf(1, "nbytes = 0x%x", dma_entry->nbytes);
            
            return DMA_ERROR;
        }
        /* first pointers calculation */
        if (OCTEON_IS_MODEL(OCTEON_CN73XX)) {
            dma_hdr.word0.cn78xx.nfst =
                npl_dma_create_first_pointers(
                    buffers, first_address, dma_entry);
            words += dma_hdr.word0.cn78xx.nfst;
        } else {
            dma_hdr.word0.cn38xx.nfst =
                npl_dma_create_first_pointers(
                    buffers, first_address, dma_entry);
            words += dma_hdr.word0.cn38xx.nfst;
        }
        pageoffset = PRP_PHY_PAGE_OFFSET(dma_entry->lastptr.prp1, dev);
        prp1_nbytes = pagesize - pageoffset;

        if (prp1_nbytes > dma_entry->nbytes)
            prp1_nbytes = dma_entry->nbytes;
        /* last pointers calculation */
        /* PRP1 is valid in every case */
        buffers[words + 0].u64 = 0;
        buffers[words + 0].pcie_length.len0 = prp1_nbytes;
        buffers[words + 1].u64 = PRP_PHYSICAL_ADD(dma_entry->lastptr.prp1, dev);
        if (OCTEON_IS_MODEL(OCTEON_CN73XX))
            dma_hdr.word0.cn78xx.nlst++;
        else
            dma_hdr.word0.cn38xx.nlst++;

        if ((dma_entry->lastptr.prp2 != 0) && (dma_entry->nbytes - prp1_nbytes)) {
            buffers[words + 0].pcie_length.len1 = dma_entry->nbytes -
                                                  prp1_nbytes;
            buffers[words + 2].u64 = PRP_PHYSICAL_ADD(dma_entry->lastptr.prp2,
                                                      dev);
            if (OCTEON_IS_MODEL(OCTEON_CN73XX))
                dma_hdr.word0.cn78xx.nlst++;
            else
                dma_hdr.word0.cn38xx.nlst++;
        }

        if (OCTEON_IS_MODEL(OCTEON_CN73XX)) {
            words += dma_hdr.word0.cn78xx.nlst +
                ((dma_hdr.word0.cn78xx.nlst - 1) >> 2) + 1;
        } else {
            words += dma_hdr.word0.cn38xx.nlst +
                ((dma_hdr.word0.cn38xx.nlst - 1) >> 2) + 1;
        }
        npl_update_dma_inout_stats(dma_engine, dma_entry->trans_type.dma_mode);
        
        CVMX_SYNCWS;
        ret = cvmx_dma_engine_submit(dma_engine, dma_hdr, words, buffers);
        if (ret) {
            debug_printf(1, "DMA_ERROR:  PRP_NOLIST");
        } else {
            dma_entry->nbytes = 0;
        }
        break;
    /* PRP List based transfers */
    case PRP_LIST:
        /* Do the DMA for PRP1 only */
        pageoffset = PRP_PHY_PAGE_OFFSET(dma_entry->lastptr.prp1, dev);
        prp1_nbytes = pagesize - pageoffset;

        /* Allocate a new work queue */
        wqe_new = npl_dma_alloc_wqe(dev, wqe);
        if (!wqe_new) goto fail;
        ((struct context_struct *)(wqe_new->word5.u64))->no_bytes_transd =
            prp1_nbytes;
        if (OCTEON_IS_MODEL(OCTEON_CN73XX)) {
            dma_hdr.word1.s.ptr = cvmx_ptr_to_phys(wqe_new);
            dma_hdr.word0.cn78xx.pt = 2;
        } else {
            dma_hdr.word0.cn38xx.addr = cvmx_ptr_to_phys(wqe_new);
            dma_hdr.word0.cn38xx.wqp = 1;
        }
        CVMX_SYNCWS;
        if (dma_entry->trans_type.dma_buffer_type) {
            dma_buf = (void *)cvmx_phys_to_ptr(first_address);
            ret = cvmx_dma_engine_transfer(dma_engine, dma_hdr,
                dma_buf[0].internal_cn78xx.addr,
                dma_entry->lastptr.prp1, prp1_nbytes);
        } else {
            ret = cvmx_dma_engine_transfer(dma_engine, dma_hdr,
                first_address, dma_entry->lastptr.prp1, prp1_nbytes);
        }
        npl_update_dma_inout_stats(dma_engine, dma_entry->trans_type.dma_mode);
        
        if (ret < 0) {
            debug_printf(1, "Error: npl_dma_submit");
            /* free the local fpa struct context */
            npl_fpa_free((uint64_t *)(wqe_new->word5.u64),
                         CONTEXT_STRUCT_IO_DMA_POOL,
                         sizeof(struct context_struct));
            /* free the local fpa wqe */
            npl_fpa_free(wqe_new, CVMX_FPA_WQE_POOL, sizeof(cvmx_wqe_t));
            return DMA_ERROR;
        }

        if (dma_entry->trans_type.dma_buffer_type) {
            dma_buf[0].internal_cn78xx.size = prp1_nbytes;
            /* Passed Octeon buffer is of dma buffer type */
            if ((int32_t)prp1_nbytes < FPA_DATA_BUF_POOL_SIZE) {
                dma_entry->next_free_segment = 0;
            } else {
                dma_entry->next_free_segment = 1;
            }
        } else {
            if (dma_entry->trans_type.dma_mode == DMA_INBOUND)
                dma_entry->dst += prp1_nbytes;
            else
                dma_entry->src += prp1_nbytes;
        }

        dma_entry->nbytes -= prp1_nbytes;
        dma_entry->lastptr.prp1 = 0;

        /* Now start processing PRP-list(local address) passed in dma_entry->laastptr.prp2 */
        ret = npl_dma_process_list(dev, dma_entry, wqe, &dma_hdr, buffers);
        break;

    case DMA_BYTE_POINTER:
        last_address = dma_entry->lastptr.prp1;     /* outbound:host */

        if (!first_address || !last_address || !dma_entry->nbytes) {
            debug_printf(1,
                         "DMA Error!!! DMA_BYTE_POINTER ..... wrong parameters");
            return DMA_ERROR;
        }

        //Set DMA header
        if (OCTEON_IS_MODEL(OCTEON_CN73XX)) {
            dma_hdr.word1.s.ptr = cvmx_ptr_to_phys((char *)dma_entry->byte_pointer);
            dma_hdr.word0.cn78xx.pt = 0;
        } else {
            dma_hdr.word0.cn38xx.addr = cvmx_ptr_to_phys((char *)dma_entry->byte_pointer);
            dma_hdr.word0.cn38xx.wqp = 0;
        }

        /*call SDK dma transfer API; Assuming memories are contiguous both sides and limited to */
        npl_update_dma_inout_stats(dma_engine, dma_entry->trans_type.dma_mode);
        
        CVMX_SYNCWS;
        ret = cvmx_dma_engine_transfer(dma_engine, dma_hdr, first_address,
                                       last_address, dma_entry->nbytes);
        if (ret) {
            debug_printf(1, "DMA_ERROR: ....DMA_BYTE_POINTER");
        } else {
            dma_entry->nbytes = 0;
        }

        break;

    case DMA_ONLY_NONE:

        if (dma_entry->trans_type.dma_mode == DMA_INBOUND)
            last_address = dma_entry->src;      //host
        else
            last_address = dma_entry->dst;      //outbound:host

        if (!first_address || !last_address || !dma_entry->nbytes) {
            debug_printf(1,
                         "DMA Error!!! DMA_ONLY_NONE ..... wrong parameters");
            return DMA_ERROR;
        }

        //Set DMA header, Do only DMA nothing
        if (OCTEON_IS_MODEL(OCTEON_CN73XX)) {
            dma_hdr.word1.s.ptr = 0;
            dma_hdr.word0.cn78xx.pt = 0;
        } else {
            dma_hdr.word0.cn38xx.addr = 0;
            dma_hdr.word0.cn38xx.wqp = 0;
        }

        /*call SDK dma transfer API; Assuming memories are contiguous both sides and limited to */
        npl_update_dma_inout_stats(dma_engine, dma_entry->trans_type.dma_mode);
        
        CVMX_SYNCWS;
        ret = cvmx_dma_engine_transfer(dma_engine /*DMA_ENGINE*/, dma_hdr,
                                       first_address, last_address,
                                       dma_entry->nbytes);
        if (ret) {
            debug_printf(1, "DMA_ERROR: ....DMA_ONLY_NONE");
        } else {
            dma_entry->nbytes = 0;
        }

        break;

    default:
        break;
    }
    return ret;

fail:

    // Caller should be taking care of cmd completion.
    return -1;
}


/***************************************************************************//**
*
*  npl_dma_process_list() :
*
*  This function implements a logic for processing PRPs from a given list and then call function
*  npl_dma_on_list() to initiate the transfer. This logic feeds the DMA engine with fixed
*  allowable number of DMA instructions. That is current limitation of MAX_ENTRIES
*
*  @param dev          pointer to a device structure of type struct nvme_dev.
*  @param dma_entry     pointer to a structure of type struct nvme_dma
*  @param wqe          pointer to work queue entry of type cvmx_wqe_t
*  @param dma_hdr          pointer to a dma header structure of type cvmx_dma_engine_header_t (union)
*  @param buffers          pointer to a array of buffers of type
*
*  @return     -1: DMA_ERROR, 0: DMA_SUCCESS
*
*  4KB page: 512 prps* page_size = 2097152 bytes
*  8KB page: 1024 prps * page_size = 8388608 bytes
*
*  @todo Reverify the logic
*
*******************************************************************************/
int npl_dma_process_list(struct nvme_dev *          dev,
                         struct nvme_dma *          dma_entry,
                         cvmx_wqe_tt *               wqe,
                         cvmx_dma_engine_header_t * dma_hdr,
                         cvmx_dma_engine_buffer_t * buffers)
{
    uint64_t prp_size = PRP_ENTRY_SIZE;
    int ret = -1;
    uint64_t loop_counter = 0;
    uint64_t page_size = dev->host_page_size;
    uint64_t max_entries_in_list = dev->num_prp_per_host_page;
    uint64_t max_bytes_in_list = page_size * max_entries_in_list;
    uint64_t j = 0;
    uint64_t next_list_addr = dma_entry->lastptr.prp2;
    uint64_t curr_list_addr = next_list_addr;
    uint64_t remaining_bytes = dma_entry->nbytes;
    uint64_t prp_entries_in_curr_list = 0;
    uint64_t num_full_prps = 0;
    uint64_t bytes_in_curr_list = 0;
    uint64_t bytes_to_send_for_dma = 0;
    uint64_t no_of_entries_sending_for_dma = 0;
    cvmx_wqe_tt *wqe_new = NULL;
    uint64_t local_wq_flag = 0;
    uint64_t prp2_offset;
    uint64_t num_prps_in_prp2_page;
    uint64_t max_dma_entries_adjusted = DMA_INST_MAX_ENTRIES;

    uint64_t total_prps = 0;

    /* Reduce by one if buffers passed are dma buffers
     * as first buffer can be partially filled
     */
    if (dma_entry->trans_type.dma_buffer_type)
            max_dma_entries_adjusted -= 1;

    total_prps = remaining_bytes / page_size;
    if (remaining_bytes % page_size)
        total_prps++;

    prp2_offset = curr_list_addr % page_size;
    if (prp2_offset) {
        num_prps_in_prp2_page = (page_size - prp2_offset) / PRP_ENTRY_SIZE;
        if ((page_size - prp2_offset) % PRP_ENTRY_SIZE)
            num_prps_in_prp2_page++;

        if (num_prps_in_prp2_page > total_prps)
            num_prps_in_prp2_page = total_prps;

        max_entries_in_list = num_prps_in_prp2_page;
        max_bytes_in_list = page_size * max_entries_in_list;
    }
    while (remaining_bytes && (next_list_addr != 0)) {
        if (remaining_bytes > max_bytes_in_list) {   /*need to process some more list    */
            next_list_addr =
                *((uint64_t *)curr_list_addr + (max_entries_in_list - 1));
            prp_entries_in_curr_list = max_entries_in_list - 1;
            bytes_in_curr_list = prp_entries_in_curr_list * page_size;
        } else {    /*No more list to process    */
            next_list_addr = 0;
            prp_entries_in_curr_list = remaining_bytes / page_size;
            if (remaining_bytes % page_size)
                prp_entries_in_curr_list++;
            bytes_in_curr_list = remaining_bytes;
        }
        num_full_prps = bytes_in_curr_list / page_size;
        loop_counter = num_full_prps / max_dma_entries_adjusted;

        bytes_to_send_for_dma = (max_dma_entries_adjusted * page_size);
        no_of_entries_sending_for_dma = max_dma_entries_adjusted;
        dma_entry->nbytes = bytes_to_send_for_dma;
        dma_entry->lastptr.no_of_entries = no_of_entries_sending_for_dma;
        for (j = 0; j < loop_counter; j++) {
            /* Allocate a new work queue entry */
            wqe_new = npl_dma_alloc_wqe(dev, wqe);
            if (!wqe_new) goto fail;
            ((struct context_struct *)(wqe_new->word5.u64))->no_bytes_transd =
                bytes_to_send_for_dma;
            /* post new work queue */
            if (OCTEON_IS_MODEL(OCTEON_CN73XX)) {
                dma_hdr->word1.s.ptr = cvmx_ptr_to_phys(wqe_new);
                dma_hdr->word0.cn78xx.pt = 2;
            } else {
                dma_hdr->word0.cn38xx.addr = cvmx_ptr_to_phys(wqe_new);
                dma_hdr->word0.cn38xx.wqp = 1;
            }
            local_wq_flag = 1;
            ret = npl_dma_on_list(dev, dma_entry, dma_hdr, buffers);
            if (ret < 0)
                goto cleanup;

            if (!dma_entry->trans_type.dma_buffer_type) {
                /* If local buffers are of type dma buffers
                 * then need not adjust offsets
                 */
                if (dma_entry->trans_type.dma_mode == DMA_OUTBOUND)
                    dma_entry->src += bytes_to_send_for_dma;
                else
                    dma_entry->dst += bytes_to_send_for_dma;
            }

            dma_entry->lastptr.prp2 +=
                (no_of_entries_sending_for_dma * prp_size);
            bytes_in_curr_list -= bytes_to_send_for_dma;
            remaining_bytes -= bytes_to_send_for_dma;
        }

        /* This if covers the remaining entries which is less than DMA_INST_MAX_ENTRIES */
        if (bytes_in_curr_list) {
            bytes_to_send_for_dma = bytes_in_curr_list;
            no_of_entries_sending_for_dma = bytes_to_send_for_dma / page_size;
            if (bytes_to_send_for_dma % page_size)
                no_of_entries_sending_for_dma++;

            dma_entry->nbytes = bytes_to_send_for_dma;
            dma_entry->lastptr.no_of_entries = no_of_entries_sending_for_dma;
            wqe_new = npl_dma_alloc_wqe(dev, wqe);
            if (!wqe_new) goto fail;
            ((struct context_struct *)(wqe_new->word5.u64))->no_bytes_transd =
                bytes_to_send_for_dma;
            /* post new work queue */
            if (OCTEON_IS_MODEL(OCTEON_CN73XX)) {
                dma_hdr->word1.s.ptr = cvmx_ptr_to_phys(wqe_new);
                dma_hdr->word0.cn78xx.pt = 2;
            } else {
                dma_hdr->word0.cn38xx.addr = cvmx_ptr_to_phys(wqe_new);
                dma_hdr->word0.cn38xx.wqp = 1;
            }
            local_wq_flag = 1;
            ret = npl_dma_on_list(dev, dma_entry, dma_hdr, buffers);
            if (ret < 0)
                goto cleanup;

           if (!dma_entry->trans_type.dma_buffer_type) {
                   if (dma_entry->trans_type.dma_mode == DMA_OUTBOUND)
                           dma_entry->src += bytes_to_send_for_dma;
                   else
                           dma_entry->dst += bytes_to_send_for_dma;
           }

            bytes_in_curr_list -= bytes_to_send_for_dma;
            remaining_bytes -= bytes_to_send_for_dma;
        }
        if (curr_list_addr % page_size)
            curr_list_addr -= prp2_offset;
        npl_fpa_free((uint64_t *)curr_list_addr, DEV_HOST_PAGE_SIZE_POOL,
                     page_size);
        curr_list_addr = next_list_addr;
        /* After processing the current list, update with next list address */
        dma_entry->lastptr.prp2 = next_list_addr;
        max_entries_in_list = dev->num_prp_per_host_page;
        max_bytes_in_list = page_size * max_entries_in_list;
    }
    npl_fpa_free((uint64_t *)(wqe->word5.u64), CONTEXT_STRUCT_IO_DMA_POOL,
                 sizeof(struct context_struct));
    npl_fpa_free(wqe, CVMX_FPA_WQE_POOL, sizeof(cvmx_wqe_t));
    dma_entry->nbytes = remaining_bytes;
    return ret;
cleanup:
    if (local_wq_flag) {
        /* free the local fpa struct context */
        npl_fpa_free((uint64_t *)(wqe_new->word5.u64),
                     CONTEXT_STRUCT_IO_DMA_POOL, sizeof(struct context_struct));
        /* free the local fpa wqe */
        npl_fpa_free(wqe_new, CVMX_FPA_WQE_POOL, sizeof(cvmx_wqe_t));
    }
    dma_entry->nbytes = remaining_bytes;
    return ret;

fail:
    // Caller will take care of cmd completion
    dma_entry->nbytes = remaining_bytes;
    return -1;
}

/***************************************************************************//**
*
*  npl_dma_on_list():
*
*  This function  creates dma instructions on a given list of prps. Then calls the DMA function
*  from SDK to start the transfer.
*
*  @param dev        pointer to a device structure of type struct nvme_dev.
*  @param dma_entry  pointer to a structure of type struct nvme_dma.
*  @param dma_hdr    pointer to a dma header structure of type cvmx_dma_engine_header_t.
*  @param buffers    pointer to an array of cvmx_dma_engine_buffer_t (cvmx-dma-engine.h).
*
*  @return 0: DMA_SUCCESS, -1: DMA_ERROR
*
*******************************************************************************/
int npl_dma_on_list(struct nvme_dev *           dev,
                    struct nvme_dma *           dma_entry,
                    cvmx_dma_engine_header_t *  hdr,
                    cvmx_dma_engine_buffer_t *  buffers)
{
    int ret = 0;
    int words = 0;
    uint64_t first_address = 0;
    cvmx_dma_engine_header_t dma_hdr = *hdr;
    uint32_t dma_engine = DMA_ENGINE;
    cvmx_wqe_tt *wqe;
#ifdef DMA_MULTI_Q_CMDID
    uint16_t cmd_id;
#else
    uint16_t sq_id;
#endif

#ifdef DMA_MULTI_Q
    if (OCTEON_IS_MODEL(OCTEON_CN73XX))
        wqe = cvmx_phys_to_ptr(dma_hdr.word1.s.ptr);
    else
        wqe = cvmx_phys_to_ptr(dma_hdr.word0.cn38xx.addr);
    

#ifdef DMA_MULTI_Q_CMDID
    cmd_id = wqe->nvme_cmd.rw.cmdid;
    dma_engine = cmd_id % DMA_MAX_HW_ENGINES;
#else
    sq_id = wqe->word3.qw3.sq_id;
    dma_engine = sq_id % DMA_MAX_HW_ENGINES;
#endif

#endif
    memset(buffers, 0, sizeof(cvmx_dma_engine_buffer_t) * 32);
    if (dma_entry->trans_type.dma_mode == DMA_INBOUND)
        first_address = cvmx_ptr_to_phys((void *)dma_entry->dst);
    else
        first_address = cvmx_ptr_to_phys((void *)dma_entry->src);

    if (OCTEON_IS_MODEL(OCTEON_CN73XX)) {
        /* FirstPointer Calculation */
        dma_hdr.word0.cn78xx.nfst =
            npl_dma_create_first_pointers(buffers, first_address, dma_entry);
        words += dma_hdr.word0.cn78xx.nfst;
        /* LastPointer Calculation based on prp list, */
        dma_hdr.word0.cn78xx.nlst = npl_dma_create_last_pointers(dev, buffers + words,
                                                  dma_entry);
        words += dma_hdr.word0.cn78xx.nlst + ((dma_hdr.word0.cn78xx.nlst - 1) >> 2) + 1;
    } else {
        /* FirstPointer Calculation */
        dma_hdr.word0.cn38xx.nfst =
            npl_dma_create_first_pointers(buffers, first_address, dma_entry);
        words += dma_hdr.word0.cn38xx.nfst;
        /* LastPointer Calculation based on prp list, */
        dma_hdr.word0.cn38xx.nlst = npl_dma_create_last_pointers(dev, buffers + words,
                                                  dma_entry);
        words += dma_hdr.word0.cn38xx.nlst + ((dma_hdr.word0.cn38xx.nlst - 1) >> 2) + 1;
    }
        
    npl_update_dma_inout_stats(dma_engine, dma_entry->trans_type.dma_mode);
    
    CVMX_SYNCWS;
    ret = cvmx_dma_engine_submit(dma_engine, dma_hdr, words, buffers);
    return ret;
}


/***************************************************************************//**
*
*  npl_dma_create_first_pointers():
*
*  This function will create the dma instruction for local memory i.e.this function will create DPI
*  DMA Local Pointers format entries for dma engine instruction.  It returns number of first pointers generated.
*
*  @param buffers pointer to an array of cvmx_dma_engine_buffer_t (cvmx-dma-engine.h)
*  @param address address value of local device memory
*  @param size    total bytes to transfer
*
*  @return Number of first pointers created. (local device memory pointers)
*
*******************************************************************************/
int npl_dma_create_first_pointers(cvmx_dma_engine_buffer_t *buffers,
                                  uint64_t                  address,
                                  struct nvme_dma *         dma_entry)
{
    int segments = 0, free_offset = 0;
    int chunk = 0;
    uint64_t *st_ptrs = (uint64_t *)cvmx_phys_to_ptr(address);
    int num_st_ptrs = dma_entry->trans_type.num_st_ptrs;
    int size = dma_entry->nbytes;
    bool dma_buffer_type = dma_entry->trans_type.dma_buffer_type;
    cvmx_dma_engine_buffer_t *dma_buf = NULL;

    if (dma_buffer_type) {
        free_offset = dma_entry->next_free_segment;
    }

    if (num_st_ptrs > 1) {
        for (; (segments < num_st_ptrs) && (size != 0);
          segments++, free_offset++) {
            buffers[segments].u64 = 0;
            chunk = size;
            if (chunk > FPA_DATA_BUF_POOL_SIZE)
                chunk = FPA_DATA_BUF_POOL_SIZE;

            if (dma_buffer_type) {
                dma_buf = (void *)&st_ptrs[free_offset];

                address = dma_buf->internal_cn78xx.addr +
                           dma_buf->internal_cn78xx.size;
                
                if ((chunk + dma_buf->internal_cn78xx.size) > FPA_DATA_BUF_POOL_SIZE)
                    chunk = FPA_DATA_BUF_POOL_SIZE - dma_buf->internal_cn78xx.size;

                /* Accumulate used space */
                dma_buf->internal_cn78xx.size += chunk;

            } else {
                address = st_ptrs[segments];
            }

            if (OCTEON_IS_MODEL(OCTEON_CN73XX)) {
                buffers[segments].internal_cn78xx.size = chunk;
                buffers[segments].internal_cn78xx.addr = address;
            } else {
                buffers[segments].internal.size = chunk;
                buffers[segments].internal.addr = address;
            }
            size -= chunk;
        }

        if (dma_buffer_type) {
            if (dma_buf->internal_cn78xx.size != FPA_DATA_BUF_POOL_SIZE) {
                dma_entry->next_free_segment = free_offset - 1;
            } else {
                dma_entry->next_free_segment = free_offset;
            }
        }
        return segments;
    }
    while (size > 0) {
        chunk = size;
        if (chunk > 8191)  /* limitation by DMA hardware */
            chunk = 8191;

        buffers[segments].u64 = 0;
        if (OCTEON_IS_MODEL(OCTEON_CN73XX)) {
            buffers[segments].internal_cn78xx.size = chunk;
            buffers[segments].internal_cn78xx.addr = address;
        } else {
            buffers[segments].internal.size = chunk;
            buffers[segments].internal.addr = address;
        }
        address += chunk;
        size -= chunk;
        segments++;
        if (!address)
            debug_printf(1,
                         "Error npl_dma_create_first_pointers: First Pointer is NULL");

    }
    return segments;
}


/***************************************************************************//**
*
*  npl_dma_create_last_pointers():
*
*  This function will create the DPI components as last pointers containing host
*  physical address from PRP List for DMA engine instruction.
*
*  @param dev      pointer to a device structure of type struct nvme_dev.
*  @param buffers  pointer to buffers that will have headers
*  @param address  pointer to a PRP list
*  @param size     total bytes to transfer
*
*  @return Number of last pointers created. (MAC pointers)
*
*  @todo Reverify
*
*******************************************************************************/
int npl_dma_create_last_pointers(struct nvme_dev *          dev,
                                 cvmx_dma_engine_buffer_t * buffers,
                                 struct nvme_dma *          dma_entry)
{
    /* Get the local memory list pointer */
    uint64_t *address = (uint64_t *)dma_entry->lastptr.prp2;
    uint16_t page_size = dev->host_page_size;
    uint64_t host_address;
    uint16_t remaining_bytes = dma_entry->nbytes;
    uint16_t len_bytes;
    uint16_t i = 0, j, k, nr;
    uint16_t *mac_length;

    nr = dma_entry->lastptr.no_of_entries;
    for (j = 0; j < nr; j += 4) {
        mac_length = (uint16_t *)&buffers[i];
        buffers[i++].u64 = 0;
        for (k = 0; k < (((nr - j) >= 4) ? 4 : (nr - j)); k++) {
            len_bytes = remaining_bytes >
                        page_size ? page_size : remaining_bytes;
            mac_length[k] = len_bytes;
            host_address = le64_cpu(*address, ULL);
            buffers[i++].u64 = host_address;
            remaining_bytes -= len_bytes;
            address++;
            if (!host_address)
                debug_printf(1,
                             "Error npl_dma_create_last_pointers: Last Pointer Address is NULL");

        }
    }
    return nr;
}

/***************************************************************************//**
*
*  npl_dma_alloc_wqe():
*
*  This function will allocate and initialize a new workqueue and a context structure
*
*  @param wqe  pointer to a work queue entry.
*
*  @return A pointer to a work queue entry.
*
*******************************************************************************/
cvmx_wqe_tt *npl_dma_alloc_wqe(struct nvme_dev *dev, cvmx_wqe_tt *wqe)
{
    /* Allocate context structure */
    struct context_struct *cntxt;
    cvmx_wqe_tt *wqe_new = 0;

    cntxt = npl_fpa_alloc(dev, CONTEXT_STRUCT_IO_DMA_POOL);
    if (!cntxt) goto fail;
    /* Allocate work queue */
    wqe_new = npl_fpa_alloc(dev, CVMX_FPA_WQE_POOL);
    if (!wqe_new) goto fail;

    /* Initialize Context structure dest,src,size */
    memcpy((char *)cntxt, (char *)(wqe->word5.u64),
           sizeof(struct context_struct));
    /* Initialize Work Queue Entry dest,src,size*/
    memcpy(wqe_new, wqe, sizeof(cvmx_wqe_t));
    npl_setup_wqe(wqe_new);
    /* Assign allocated context structure to wqe_new->word0 */
    wqe_new->word5.u64 = (uint64_t)cntxt;

fail:
    return wqe_new;
}


/***************************************************************************//**
*
*    npl_fpa_alloc
*
*    This function allocates the buffer size memory from the specified pool_id
*    and returns its pointer to the caller function.
*    The function loops infinitely till the memory gets allocated from the pool.
*
*         @param pool_id     pool ID from which memory to be allocated.
*
*         @return Pointer to the allocated memory from the FPA pool
*
*******************************************************************************/
void *npl_fpa_alloc(struct nvme_dev *dev, uint64_t pool_id)
{
    void *pvoid = NULL;
    int flag = 0;
    uint64_t t;


    /**
     * Get the pointer to the allocated memory size.
     * Loop until the requested memory size is allocated from the FPA pool for
     * the specified pool ID
     */
    NVME_MARKTIME(t); // get elapsed marker
    do {
        pvoid = cvmx_fpa_alloc(pool_id);
        if (!pvoid) {
            if (!flag) {
                debug_printf(1, "Pool ID: 0x%lx", pool_id);
                debug_printf(1, "..............");
                flag = 1;
            }
        }
    } while (pvoid == NULL && !NVME_TIMEOUT(t, NVME_TIMEOUTVAL));

    return pvoid;
}


/***************************************************************************//**
*
*    npl_calc_fpa_pool_size
*
*    This function calculates the size of a pool aligned to cache line size.
*    Aligning the pool size to cache line size is necessary as FPA
*    pool should always be aligned to it.
*
*         @param nvme_pool_size - Actual size of the pool element in FPA pool
*
*         @return Size of the pool element aligned to cache line size
*
*******************************************************************************/
uint32_t  npl_calc_fpa_pool_size(uint64_t nvme_pool_size)
{
    uint32_t nvme_num_cache_lines;

    nvme_num_cache_lines = nvme_pool_size / CVMX_CACHE_LINE_SIZE;
    if (nvme_pool_size % CVMX_CACHE_LINE_SIZE)
        nvme_num_cache_lines++;

    return nvme_num_cache_lines * CVMX_CACHE_LINE_SIZE;
}


/***************************************************************************//**
*
*    npl_fpa_free
*
*    This function free the buffer size memory to the specified pool by pool_id.
*
*         @param ptr          Previously allocated memory pointer from the pool.
*         @param pool_id           Pool ID to which memory is freed.
*            @param pool_size     Buffer size to be returned to the pool.
*                             Minimum cache line size bytes to be freed
*
*    @todo
*    1. Check for strict alignment for cache line size in hardware
*
*******************************************************************************/
void npl_fpa_free(void *    ptr,
                  uint64_t  pool_id,
                  uint64_t  pool_size)
{
    uint64_t nvme_num_cache_lines;

    if (!ptr)
        return;
    /**
     *  Free buffer size memory to the specified pool
     */
    nvme_num_cache_lines = npl_calc_fpa_pool_size(pool_size);
    nvme_num_cache_lines /= CVMX_CACHE_LINE_SIZE;
    cvmx_fpa_free(ptr, pool_id, nvme_num_cache_lines);
    ptr = NULL;
}

/**************************************************************************//**
*
*   npl_helper_free_context
*
*   This functions helps freeing context_struct and its associated buffers
*
*       @parm ptr           Pointer to context_struct
*       
*******************************************************************************/
void npl_helper_free_context(struct context_struct *ptr)
{
    uint32_t i;
    uint64_t *bufs;

    if (!ptr)
        return;

    /* Free data bufs */
    bufs = cvmx_phys_to_ptr((uint64_t)ptr->data_bufs);
    if (bufs) {
        for (i = 0; i < ptr->num_data_bufs ;i++)
            cvmx_fpa_free(cvmx_phys_to_ptr(bufs[i]),
                    FPA_DATA_BUF_POOL, 0);
        cvmx_fpa_free(bufs, FPA_DATA_BUF_POOL, 0);
    }

    /* Free compare bufs */
    bufs = cvmx_phys_to_ptr((uint64_t)ptr->compare_buff);

    if (bufs) {
        for (i = 0; i < ptr->num_comp_bufs; i++)
            cvmx_fpa_free(cvmx_phys_to_ptr(bufs[i]),
                    FPA_DATA_BUF_POOL, 0);
        cvmx_fpa_free(bufs, FPA_DATA_BUF_POOL, 0);
    }

    npl_fpa_free((uint64_t *)ptr,
            CONTEXT_STRUCT_IO_DMA_POOL,
            sizeof(struct context_struct));
    return;
}

/**************************************************************************//**
*
*   npl_helper_cleanup_fused_cmd
*
*   This functions helps cleaning up fused commands. 
*
*       @parm dev           Pointer to nvme_dev
*       @parm wqe_io        Pointer to wqe in which we need to check 
*                           if fused command exists and fail it.
*
*******************************************************************************/
void npl_helper_cleanup_fused_cmd(struct nvme_dev * dev, cvmx_wqe_tt *wqe_io)
{
    struct nvme_cmd cmd = wqe_io->nvme_cmd;
    struct completion_status_field cpl_entry = { 0 };
    uint32_t result = 0, opcode = 0;;

    opcode = cmd.rw.opc;
    /* Cleanup fused second cmd */
    if ((opcode == nvme_cmd_compare) &&
        (cmd.common.flags == fused_first_command)) {
        /* Check for the next command and complete that with status as 'Command Aborted due to Failed Fused Command' */
        if (wqe_io->word6.u64 != 0) {
            cpl_entry.sct = SCT_GENERIC;
            cpl_entry.sc = FAILED_FUSED_CMD;
            cpl_entry.m = 0;
            cpl_entry.dnr = 0;
            result = 0;
            npl_submit_completion_entry(dev, (cvmx_wqe_tt *)wqe_io->word6.u64, result, cpl_entry);
            /* Free the memory allocated for keeping the fused-second command */
            npl_fpa_free((void *)wqe_io->word6.u64, CVMX_FPA_WQE_POOL,
                    sizeof(cvmx_wqe_t));
            wqe_io->word6.u64 = 0;
        }
    }

    return;
}

/***************************************************************************//**
*
*    npl_debug_log
*
*    This function prints the debug messages to console. The
*
*         @param format     Pointer to constant character array and variable
*                   arguments.
*
*******************************************************************************/
void npl_debug_log(const char *format,
                   ...)
{
#if     CVMX_ENABLE_DEBUG_PRINTS
    printf(format);
#endif
}

/***************************************************************************//**
*
*  print_cmd_info_nbytes
*
*******************************************************************************/
void print_cmd_info_nbytes(uint8_t *cmd_ptr,
                           uint32_t nbytes)
{
    uint8_t index;

    for (index = 0; index < nbytes; index++) {
        if (!(index % 4))
            debug_printf(1, "\nDWORD%d :", index / 4);
        debug_printf(1, " 0x%02x", cmd_ptr[index]);
    }
    debug_printf(1, "\n");
}

/***************************************************************************//**
*
*    npl_convert_iocmds_le_to_be
*
*    This function converts the NVME commands in little endian to big endian
*    architecture. This function is called when the NVME command processing
*    machine follows big endian architecture.
*
*         @param ptr     Command structure pointer.
*         @param cmd_type     Command type(admin/IO command)
*
*    @todo
*    1. Currently ALL NVME ADMIN commands are not supported.
*
*******************************************************************************/
void npl_convert_iocmds_le_to_be(struct nvme_cmd *  cmd_ptr,
                                 CMD_TYPE_T             cmd_type)
{
    uint8_t i;

    if (!OCTEON_IS_MODEL(OCTEON_CN73XX) ||
        OCTEON_IS_MODEL(OCTEON_CN73XX_PASS1_0)) {
        for (i = 0; i < (sizeof(struct nvme_cmd) / sizeof(uint64_t)); i++)
            *((uint64_t *)cmd_ptr + i) = le64_cpu(*((uint64_t *)cmd_ptr + i), ULL);
    }

    return;

    if (cmd_type) {
        /**
         * I/O Command type
         */
        cmd_ptr->rw.eilbrt = le32_cpu(cmd_ptr->rw.eilbrt);
        cmd_ptr->rw.elbatm = le16_cpu(cmd_ptr->rw.elbatm);
        cmd_ptr->rw.elbat = le16_cpu(cmd_ptr->rw.elbat);
        cmd_ptr->rw.cmdid = le16_cpu(cmd_ptr->rw.cmdid);
        cmd_ptr->rw.ctrl = le16_cpu(cmd_ptr->rw.ctrl);
        cmd_ptr->rw.dsm = le32_cpu(cmd_ptr->rw.dsm);
        cmd_ptr->rw.len = le16_cpu(cmd_ptr->rw.len);
        cmd_ptr->rw.mptr = le64_cpu(cmd_ptr->rw.mptr, ULL);
        cmd_ptr->rw.nsid = le32_cpu(cmd_ptr->rw.nsid);
        cmd_ptr->rw.prp1 = le64_cpu(cmd_ptr->rw.prp1, ULL);
        cmd_ptr->rw.prp2 = le64_cpu(cmd_ptr->rw.prp2, ULL);
        cmd_ptr->rw.slba = le64_cpu(cmd_ptr->rw.slba, ULL);
    } else {
        /**
         * Admin Command type
         */
        switch (cmd_ptr->common.opc) {
        case NVME_ADMIN_CMD_ABORT:
            cmd_ptr->abort.cid = le16_cpu(cmd_ptr->abort.cid);
            cmd_ptr->abort.cmdid = le16_cpu(cmd_ptr->abort.cmdid);
            cmd_ptr->abort.sqid = le16_cpu(cmd_ptr->abort.sqid);
            break;

        case NVME_ADMIN_CMD_ASYNC_EVENT:
            /** All command fields are reserved. Revisit spec for this command */
            cmd_ptr->async_evt_req.cmdid =
                le16_cpu(cmd_ptr->async_evt_req.cmdid);
            break;

        case NVME_ADMIN_CMD_CREATE_CQ:
            cmd_ptr->create_cq.cmdid =
                le16_cpu(cmd_ptr->create_cq.cmdid);
            cmd_ptr->create_cq.q_flags = le16_cpu(cmd_ptr->create_cq.q_flags);
            cmd_ptr->create_cq.qid = le16_cpu(cmd_ptr->create_cq.qid);
            cmd_ptr->create_cq.vector =
                le16_cpu(cmd_ptr->create_cq.vector);
            cmd_ptr->create_cq.prp1 = le64_cpu(cmd_ptr->create_cq.prp1, ULL);
            cmd_ptr->create_cq.qsize = le16_cpu(cmd_ptr->create_cq.qsize);
            break;

        case NVME_ADMIN_CMD_CREATE_SQ:
            cmd_ptr->create_sq.cmdid =
                le16_cpu(cmd_ptr->create_sq.cmdid);
            cmd_ptr->create_sq.cqid = le16_cpu(cmd_ptr->create_sq.cqid);
            cmd_ptr->create_sq.prp1 = le64_cpu(cmd_ptr->create_sq.prp1, ULL);
            cmd_ptr->create_sq.qsize = le16_cpu(cmd_ptr->create_sq.qsize);
            cmd_ptr->create_sq.q_flags = le16_cpu(cmd_ptr->create_sq.q_flags);
            cmd_ptr->create_sq.qid = le16_cpu(cmd_ptr->create_sq.qid);
            break;

        case NVME_ADMIN_CMD_DELETE_CQ:
        case NVME_ADMIN_CMD_DELETE_SQ:
            cmd_ptr->delete_queue.cmdid =
                le16_cpu(cmd_ptr->delete_queue.cmdid);
            cmd_ptr->delete_queue.qid = le16_cpu(cmd_ptr->delete_queue.qid);
            break;

        case NVME_ADMIN_CMD_GET_LOG_PAGE:
            cmd_ptr->get_log_page.prp1 =
                le64_cpu(cmd_ptr->get_log_page.prp1, ULL);
            cmd_ptr->get_log_page.prp2 =
                le64_cpu(cmd_ptr->get_log_page.prp2, ULL);
            cmd_ptr->get_log_page.lpi = le32_cpu(cmd_ptr->get_log_page.lpi);
            break;

        case NVME_ADMIN_CMD_IDENTIFY:
            cmd_ptr->identify.cns = le32_cpu(cmd_ptr->identify.cns);
            cmd_ptr->identify.cmdid =
                le16_cpu(cmd_ptr->identify.cmdid);
            cmd_ptr->identify.nsid = le32_cpu(cmd_ptr->identify.nsid);
            cmd_ptr->identify.prp1 = le64_cpu(cmd_ptr->identify.prp1, ULL);
            cmd_ptr->identify.prp2 = le64_cpu(cmd_ptr->identify.prp2, ULL);
            break;

        case NVME_ADMIN_CMD_GET_FEATURES:
        case NVME_ADMIN_CMD_SET_FEATURES:
            cmd_ptr->features.cmdid =
                le16_cpu(cmd_ptr->features.cmdid);
            cmd_ptr->features.dword = le32_cpu(cmd_ptr->features.dword);
            cmd_ptr->features.fid = le32_cpu(cmd_ptr->features.fid);
            cmd_ptr->features.nsid = le32_cpu(cmd_ptr->features.nsid);
            cmd_ptr->features.prp1 = le64_cpu(cmd_ptr->features.prp1, ULL);
            cmd_ptr->features.prp2 = le64_cpu(cmd_ptr->features.prp2, ULL);
            break;

        default:
            debug_printf(1,
                         "ERROR : Invalid/Unsupported Admin Command Opcode detected ");
            break;
        }
    }
}

/***************************************************************************//**
*
*    npl_xfer_discontiguous_cq_entries
*
*    This function transfers the completion queue entries from the device side
*    queue to the host side dis-contiguous queue
*
*         @param dev            Pointer to device structure nvme_dev
*         @param prev_cq_tail       completion queue tail
*         @param cpl_entry_count     entries to be transferred
*         @param cq_id   completion queue id
*         @param wqp        work queue pointer
*
*
*******************************************************************************/
#if DISCONTIGUOUS_Q_SUPPORT
void npl_xfer_discontiguous_cq_entries(struct nvme_dev *dev,
                                       uint16_t         prev_cq_tail,
                                       uint32_t         cpl_entry_count,
                                       uint16_t         cq_id,
                                       cvmx_wqe_tt *     wqp)
{
    uint16_t prp_entry_offset;
    uint16_t page_offset;
    uint64_t prp_entry;
    uint64_t host_cq_entry_ptr;
    uint16_t count;
    uint16_t remaining_entries;
    uint8_t result = STATUS_ERROR;
    struct nvme_dma nvme_dma_cplq = { 0, };

    while (cpl_entry_count) {
        /* calculate the offset of the PRP entry in the list page */
        prp_entry_offset = prev_cq_tail / dev->max_cq_entry_per_page;
        /* calculate the index of the completion entry in the page */
        page_offset = prev_cq_tail % dev->max_cq_entry_per_page;
        /* Get the PRP entry */
        prp_entry =
            *((uint64_t *)(dev->queue->cq[cq_id]->host_cpl_queue_addr) +
              prp_entry_offset);
        /* Get the address of the completion queue entry */
        host_cq_entry_ptr =
            (uint64_t)((struct nvme_completion *)prp_entry + page_offset);
        /* calculate the number of entries that can be copies in one shot, considering queue wrap around*/
        remaining_entries = dev->max_cq_entry_per_page - page_offset;
        count =
            (remaining_entries >=
             cpl_entry_count) ? cpl_entry_count : remaining_entries;
        cpl_entry_count -= count;
        /* Set up nvme_dma structure for transfer completion queue entry to host */
        nvme_dma_cplq.src =
            (uint64_t)(dev->queue->cq[cq_id]->cqes + prev_cq_tail);
        nvme_dma_cplq.dst = host_cq_entry_ptr;
        nvme_dma_cplq.nbytes = count * sizeof(struct nvme_completion);
        nvme_dma_cplq.trans_type.dma_mode = DMA_OUTBOUND;
        nvme_dma_cplq.trans_type.prp_mode = PRP_NULL;
        nvme_dma_cplq.trans_type.cpl_transfer = 1;
        /* Call the DMA function to update host completion queue */
        result = npl_dma_submit(dev, &nvme_dma_cplq, wqp);
        if (result)
            debug_printf(1, "Error: DMA transfer has failed");
        prev_cq_tail += count;
    }
}

#endif

/***************************************************************************//**
*
*    npl_check_for_cmd_in_cq
*
*    checks for the command in the completion queue
*
*         @param dev            Pointer to device structure nvme_dev
*         @param cq_id   completion queue id
*         @param cmd_id    The command id
*
*   @return Zero on success, or negative error code on failure.
*
*******************************************************************************/
int npl_check_for_cmd_in_cq(struct nvme_dev *   dev,
                            uint16_t            cq_id,
                            uint16_t            cmd_id)
{
    uint16_t cq_tail;
    uint32_t *cq_head;
    uint32_t cq_depth;
    uint8_t cmd_found = 0;
    struct nvme_completion *cq_entry_ptr;

    cq_tail = dev->queue->cq[cq_id]->cq_tail;
    cq_head = (uint32_t *)&(dev->queue->cq[cq_id]->cq_head);
    cq_depth = dev->queue->cq[cq_id]->cq_depth;
    while (((cq_tail + 1) % cq_depth) !=
           (uint32_t)cvmx_atomic_get32((int32_t *)cq_head)) {
        cq_entry_ptr = &dev->queue->cq[cq_id]->cqes[cq_tail];
        /* check for the command id */
        if (cq_entry_ptr->cmdid == cmd_id)
            cmd_found = 1;
    }
    return cmd_found;
}

int npl_abort_cmd_in_sq(struct nvme_dev *   dev,
                            uint16_t            sqid,
                            uint16_t            cmd_id)
{
    uint8_t cmd_found = 0;
    struct nvme_sub_queue *sq = dev->queue->sq[sqid];
    uint16_t cqid = sq->cq_id;
    int i;

    cvmx_rwlock_wp_write_lock(&dev->queue->cq[cqid]->cq_lock);
    for (i = 0; i < MAX_SQ_DEPTH; i++) {
        if ((cvmx_atomic_get64((int64_t *)&sq->cmd_id_arr[i]) >> 32) == cmd_id) {
            cvmx_atomic_fetch_and_bset64_nosync(&sq->cmd_id_arr[i], 1);
            cmd_found = 1;
            break;
        }
    }
    cvmx_rwlock_wp_write_unlock(&dev->queue->cq[cqid]->cq_lock);

    if (cmd_found)
        debug_printf(1, "Command %d is in fly. Aborting", cmd_id);

    return cmd_found;
}
/***************************************************************************//**
*
*    npl_abort_command
*
*    The Abort command is used to abort a specific command previously submitted to the Admin
*   Submission Queue or an I/O Submission Queue.
*
*         @param dev            Pointer to device structure nvme_dev
*         @param nvme_cmd    Pointer to the NVMe command
*         @param cpl_entry    Completion queue entry pointer
*         @param result    Pointer to update the processing result
*
*   @return Zero on success, or negative error code on failure.
*
*******************************************************************************/
int
npl_abort_command(struct nvme_dev *                 dev,
                  cvmx_wqe_tt *                      wqp,
                  struct completion_status_field *  cpl_entry,
                  uint32_t *                        result)
{
    uint8_t i = 0;
    uint8_t cmd_stored = 0;
    uint8_t cmd_found = 0;
    uint16_t sq_id;
    uint16_t cmd_id;
    struct nvme_cmd_abort abort_cmd = wqp->nvme_cmd.abort;

    sq_id = abort_cmd.sqid;
    cmd_id = abort_cmd.cid; /*id of the command to be aborted */

    debug_printf(1, "Abort command: cmdid %d on VF %d SQ %d", cmd_id, dev->pfvf, sq_id);
    /* Store the command in the first free location of abort_arr[ ] */
    for (i = 0; i < dev->id_ctrl->acl; i++) {
        if (dev->queue->abort_arr[i].opc == 0xFF) {
            /* We found a free slot, keep the command here and set the flag */
            dev->queue->abort_arr[i] = abort_cmd;
            cmd_stored = 1;
            break;
        }
    }
    if (!cmd_stored) {
        /* Number of abort command is greater than maximum supported, So Complete the command with ABORT_LIMIT_EXCEEDED */
        cpl_entry->sct = SCT_COMMAND;
        cpl_entry->sc = ABORT_LIMIT_EXCEEDED;
        cpl_entry->m = 0;
        cpl_entry->dnr = 0;
        /* The command is not aborted */
        *result = 1;
        return STATUS_ERROR;
    }
    cmd_found = npl_abort_cmd_in_sq(dev, sq_id, cmd_id);
    if (!cmd_found) {
        debug_printf(1, "Command %d is not in SQ %d. Can't be aborted", cmd_id, sq_id);
        /* The command to be aborted is already completed */
        cpl_entry->sct = SCT_GENERIC;
        cpl_entry->sc = CMD_SUCCESSFUL;
        cpl_entry->m = 0;
        cpl_entry->dnr = 0;
        /* The command is not aborted */
        *result = 1;
        /* Go to the  abort array and clear the entry */
        for (i = 0; i < dev->id_ctrl->acl; i++) {
            if (dev->queue->abort_arr[i].sqid == sq_id &&
                dev->queue->abort_arr[i].cid == cmd_id) {
                /* An entry with opcode field 0xFF represents a free slot */
                dev->queue->abort_arr[i].opc = 0xFF;
                break;
            }
        }
        return STATUS_ERROR;
    }

    return STATUS_SUCCESS;
}

/***************************************************************************//**
*
*    npl_set_status_and_submit
*
*    This function sets the status code and submits the completion entry
*
*         @param dev            Pointer to device structure nvme_dev
*         @param wqp   work queue pointer.
*         @param status_code_type    The completion entry's status code  type.
*         @param status_codec    The completion entry's status code
*         @param result    The completion entry's result field
*
*   @return Zero on success, or negative error code on failure.
*
*******************************************************************************/
int
npl_set_status_and_submit(struct nvme_dev * dev,
                          cvmx_wqe_tt *      wqp,
                          uint16_t          status_code_type,
                          uint16_t          status_codec,
                          uint32_t          result)
{
    struct completion_status_field cpl_entry = { 0 };

    /* update cpl_entry with the received values */
    cpl_entry.sct = status_code_type;
    cpl_entry.sc = status_codec;
    cpl_entry.m = 0;
    cpl_entry.dnr = 0;
    npl_submit_completion_entry(dev, wqp, result, cpl_entry);
    return STATUS_SUCCESS;
}

/***************************************************************************//**
*    npl_setup_wqe()
*
*   Sets up a 73xx WQE for NVME. 73xx NVMe WQEs on 68xx use an "indicator bit" to
*   flag special handling for NVMe. On the 73xx, this is done by a port value of
*   0x200, and that is what hardware uses.
*
*       @param wqp	Pointer to WQE.
*
*******************************************************************************/
void npl_setup_wqe(cvmx_wqe_tt *wqe)
{
    if (OCTEON_IS_MODEL(OCTEON_CN68XX))
        /*
         * Set this indicator bit to flag NVME processing in 68xx series processor.
         * This is not required in 73xx. In this case, the port number should be
         * set to 0x200.
         */
        wqe->word0.u64 |= 0x40;
    else
        cvmx_wqe_set_port((cvmx_wqe_t *)wqe, 0x200); /* set NVME processing indicator */
}

struct nvme_dma fetch_sq_entry = {
	.nbytes = SUBQUEUE_ENTRY_SIZE,
	.trans_type = {.prp_mode = PRP_NULL, .dma_mode = DMA_INBOUND},
};

#define npl_patch_dma_cmd(__cmd, __src, __dst)	\
do {						\
	__cmd.src = __src;			\
	__cmd.dst = __dst;			\
} while(0);

void
npl_fetch_nvme_command(struct nvme_dev *dev, cvmx_wqe_nqm_t *nqm_wqe)
{
	uint8_t sqid = nqm_wqe->word3.sqid;
	uint16_t vfid = nqm_wqe->word3.vfnum;
	uint16_t sqhead = nqm_wqe->word4.sqhead;
	struct nvme_sub_queue *sub_queue = dev->queue->sq[sqid];
	uint64_t sq_entry, host_sub_queue_addr;
	int ret = 0;

	sqhead = sqhead & dev->queue->sq[sqid]->sq_depth_mask;

	host_sub_queue_addr = (uint64_t)dev->queue->sq[sqid]->host_sub_queue_addr;
	if (sub_queue->queue_discontiguous) {
		sq_entry = *((uint64_t *)host_sub_queue_addr +
			(sqhead / dev->max_sq_entry_per_page));
		sq_entry = sq_entry +
			((sqhead % dev->max_sq_entry_per_page) *
			SUBQUEUE_ENTRY_SIZE);
		
	} else {
		sq_entry = host_sub_queue_addr +
			(sqhead * SUBQUEUE_ENTRY_SIZE);
	}

	debug_printf(3, "fetching command from vf %d sqid %d "
		"sq_cmd_addr %016lx\n", vfid, sqid, sq_entry);

	cvmx_wqe_set_tag((cvmx_wqe_t *)nqm_wqe,
		(CMD_HANDLE_TAG << NQM_TAG_SHIFT) |
		(sqid << NQM_QID_SHIFT) | (vfid));

	npl_patch_dma_cmd(fetch_sq_entry, sq_entry, (uint64_t)((void *)nqm_wqe + 64));
	nqm_wqe->word2 = ((*((uint64_t *)nqm_wqe + 8)) >> 16) & 0xFFFF;

	CVMX_SYNCWS;

	ret = npl_dma_submit(dev, &fetch_sq_entry, (cvmx_wqe_tt *)nqm_wqe);
	if (ret)
		debug_printf(1, "%s dma failure\n", __func__);
}



int
npl_pcie_iobdma(uint64_t host_addr, int scratch_off, int len_8B)
{
	cvmcs_pcie_iobdma_t iobdma;

	iobdma.u64 = 0;
	iobdma.s.scraddr = (scratch_off >> 3);
	iobdma.s.len = len_8B;
	iobdma.s.did = 0x1B;
	iobdma.s.address = host_addr;

	cvmx_send_single(iobdma.u64);
	CVMX_SYNCIOBDMA;

	return 0;
}

void
npl_iobdma_fetch_sq_entry(struct nvme_dev *dev, cvmx_wqe_nqm_t *nqm_wqe)
{
	uint8_t sqid = nqm_wqe->word3.sqid;
	uint16_t sqhead = nqm_wqe->word4.sqhead, sq_depth;
	uint64_t sq_entry;
	uint8_t i;
	uint64_t *ptr = ((uint64_t *)nqm_wqe) + 8;

	sq_depth = dev->queue->sq[sqid]->sq_depth;
	sq_entry = (uint64_t)dev->queue->sq[sqid]->host_sub_queue_addr +
		((sqhead % sq_depth)* SUBQUEUE_ENTRY_SIZE);

#if 0
	for (i = 0; i < SUBQUEUE_ENTRY_SIZE / sizeof(uint64_t); i++)
		cvmx_scratch_write64((IOBDMA_FETCH_SQE + i * 8), 0ull);
#endif

	npl_pcie_iobdma(sq_entry, IOBDMA_FETCH_SQE,
		SUBQUEUE_ENTRY_SIZE / sizeof(uint64_t));

	for (i = 0; i < SUBQUEUE_ENTRY_SIZE / sizeof(uint64_t); i++)
		ptr[i] = cvmx_scratch_read64(IOBDMA_FETCH_SQE + i * 8);
}

uint16_t
npl_alloc_local_cmd_id(struct nvme_dev *dev, uint8_t sqid, uint16_t cmdid)
{
	int lcmdid;
	struct nvme_sub_queue *sq = dev->queue->sq[sqid];

	do {
		lcmdid = find_first_zero_bit(sq->cmd_id_bitmask, MAX_SQ_DEPTH);
		if (lcmdid >= MAX_SQ_DEPTH) {
			debug_printf(1, "Err: lcmdid pool empty");
			return 0xffff;
		}
	} while (test_and_set_bit(lcmdid, sq->cmd_id_bitmask));

	cvmx_atomic_set64((int64_t *)&sq->cmd_id_arr[lcmdid], (((uint64_t)cmdid) << 32));

	return lcmdid;
}

int
npl_free_local_cmd_id(struct nvme_dev *dev, uint8_t sqid, int lcmdid) 
{
	struct nvme_sub_queue *sq = dev->queue->sq[sqid];

	if (lcmdid > MAX_SQ_DEPTH-1) {
		debug_printf(1, "Err: lcmdid >= MAX_SQ_DEPTH");
		return -1;
        }

	if (!test_and_clear_bit(lcmdid, sq->cmd_id_bitmask)) {
		debug_printf(1, "Err: Trying to clear bit that is not set: SQID %d lcmdid %d", sqid, lcmdid);
		return -1;
	}

	cvmx_atomic_set64((int64_t *)&sq->cmd_id_arr[lcmdid], (CMDID_INVALID << 32));
	return 0;
}


void
npl_handle_aborted_cmd(struct nvme_dev *dev, cvmx_wqe_tt *work_entry)
{
	uint8_t sq_id = work_entry->word3.qw3.sq_id;
	uint16_t cmd_id = work_entry->nvme_cmd.common.cmdid;
	struct nvme_sub_queue *sq = dev->queue->sq[sq_id];
	cvmx_wqe_tt *new_wqp;
	int i;

	debug_printf(1, "Aborting cmd %d on VF %d SQ %d", cmd_id, dev->pfvf, sq_id);
	cvmx_atomic_fetch_and_bclr64_nosync(&sq->cmd_id_arr[LCMDID(work_entry)], 1);

	/* Abort requested for this command update the status and complete the command */
	npl_set_status_and_submit(dev, work_entry, SCT_GENERIC, ABORT_REQUESTED, 0);

	/* complete the abort command also */
	for (i = 0; i < dev->id_ctrl->acl; i++) {
		if (dev->queue->abort_arr[i].sqid == sq_id &&
		    dev->queue->abort_arr[i].cid == cmd_id) {
			debug_printf(1, "Completing abort cmdid %d on VF %d",
				dev->queue->abort_arr[i].cmdid, dev->pfvf);
			new_wqp = npl_fpa_alloc(dev, CVMX_FPA_WQE_POOL);
			if (!new_wqp) return;
			npl_setup_wqe(new_wqp);
			new_wqp->word3.qw3.vf = dev->pfvf; // set pf/vf
			new_wqp->word3.qw3.sq_id = 0;
			memcpy((struct nvme_cmd *)&(new_wqp->nvme_cmd),
				(struct nvme_cmd *)&(dev->queue->abort_arr[i]),
				sizeof(struct nvme_cmd));

			for (i = 0; i < MAX_SQ_DEPTH; i++) {
				if ((cvmx_atomic_get64((int64_t *)&dev->queue->sq[0]->
					cmd_id_arr[i]) >> 32) == new_wqp->nvme_cmd.common.cmdid) {
					LCMDID(new_wqp) = i;
					break;
				}
			}
			if (i != MAX_SQ_DEPTH)
				/*  update the status and c mplete the command */
				npl_set_status_and_submit(dev, new_wqp, SCT_GENERIC,
					CMD_SUCCESSFUL, 0);
			dev->queue->abort_arr[i].opc = 0xff;
			npl_fpa_free((void*)new_wqp, CVMX_FPA_WQE_POOL, sizeof(cvmx_wqe_tt));
			break;
		}
	}
	return;
}

void
nvme_set_intr_coalescing_off(void)
{
	nqm_intr_coalescing = 0;

	debug_printf(1, "NQM interrrupt coalescing disabled");
}
