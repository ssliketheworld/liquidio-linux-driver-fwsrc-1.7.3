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

\brief This module contains the code for the host interface layer.

*******************************************************************************/

/*-----------------------------------------------------------------------------
 *                                 Revision History
 *                                     $Log: hil_nvme.c $
 *---------------------------------------------------------------------------*/

#include "nvme_cvm.h"
#include "nvme.h"
#include "cvmcs-common.h"
#include "cvmx-nqm-defs.h"

extern CVMX_SHARED unsigned char *cn73xx_nqm_mempool;

/*
 * pf/vf device control structure array
 */
extern CVMX_SHARED struct nvme_dev *nqm_device_structs[1028];

/**
 * Globals
 */

/*
 * Pseudo-register set for NVME
 *
 * The bar structure is shared in common with the host and contains all of the
 * structures we share with the host, including controller registers, queues, etc.
 *
 */
CVMX_SHARED struct nvme_bar*      nvme_bar1; // live bar
/*
 * Polling ring buffer
 *
 * This is a shared area used to allow the host driver to communicate events here.
 */
CVMX_SHARED struct nvme_reg_poll* reg_poll;  /* polling ring buffer shared using BAR2 */

/* Function Prototypes */
static void hil_frame_wqe(cvmx_wqe_tt *  nvme_wqe,
                          uint16_t      sq_no,
                          uint16_t      processed_sub_queue_tail,
					uint64_t transfer_cnt);
void print_cmd_info(uint8_t * cmd_ptr);

/***************************************************************************//**
*
*    hil_allocate_bar1()
*
*      This function Allocate memory for controller BAR 1  and doorbell register
*    BAR2 for the device.
*
*    @param dev Pointer to device private structure
*
*    @return On success zero and negative error code on failure
*
*******************************************************************************/

int hil_allocate_bar1(void)
{
    int32_t i;
    uint64_t phy_address = 0;
	cvmx_pemx_bar1_indexx_t bar_index;
	uint64_t mask = 0x000000000000ffff;
	uint64_t addr;
    int32_t pcie_port = 1;

    bar_index.u64 = 0;
	
	/* BAR1 memory allocation */
    nvme_bar1 = cvmx_bootmem_alloc(BAR_SIZE, MEM_ALLIGNMENT);
    if (nvme_bar1 == NULL) {
       		 debug_printf(1, "Error:  BAR1 memory allocation failed");
        return STATUS_ERROR;
    	}
    memset(nvme_bar1, 0, BAR_SIZE);

	/* Reg poll memory allocation */
	// [saf] we allocate double the register set to make up for the removal
	// of bkp_bar.
    reg_poll = (struct nvme_reg_poll *)((uint8_t *)nvme_bar1 + NVME_REG_SIZE*2);
    phy_address = cvmx_ptr_to_phys(nvme_bar1);
	

    /* PEM configuration */
    for (i = 0; i < 16; i++) {
		addr = mask & ((phy_address + (i * 0x400000)) >> 22 );
		bar_index.u64 = (addr << 4) ;
        bar_index.u64 = bar_index.u64 | 0x0f;          /* for setting ADDR_V  & CA, 0x0f=32 bit Exchange mode */

		cvmx_write_csr( CVMX_PEMX_BAR1_INDEXX(i,pcie_port) ,bar_index.u64);

   }
    return STATUS_SUCCESS;
}

/***************************************************************************//**

hil_process_ctrlreg()

Handles the NVMe control register write requests. If the register address is
invalid, the request is ignored. In this version, we handle only write requests,
and the host can process reads to the NVMe control registers without notifying
us.

	@param dev	Pointer to device private structure
	@param access_offset offset into nvme regs

*******************************************************************************/

void hil_process_ctrlreg(struct nvme_dev *dev, uint64_t access_offset)
{
	if (access_offset > MAX_CTRL_CONFIG_REG_OFFSET)
		return;
	else {
		switch (access_offset) {

		case NVME_REG_CAP: /* R/O */
			break;

		case NVME_REG_VS: /* R/O */
			break;

		case NVME_REG_INTMS:
			//TODO
			break;

		case NVME_REG_INTMC:
			//TODO
			break;

		case NVME_REG_CC:
			// process controller CC writes
			npl_controller_configuration(dev);
			break;

		case NVME_REG_RESERVE:
			break;

		case NVME_REG_CSTS :
			break;

		case NVME_REG_AQA:
			break;

		case NVME_REG_ASQ:
			// EN bit check for admin queue creation(should be 0)
			if (le32_cpu(cvm_read_csr32(
			    CVMX_NQM_VFX_CC(dev->pfvf))) & NVME_CC_ENABLE) {
				debug_printf(1, " asq::EN bit is set"
					" no aqa write permitted\n");
				return;
			}
			break;

		case NVME_REG_ACQ:
			// EN bit check for admin queue creation(should be 0)
			if (le32_cpu(cvm_read_csr32(
			    CVMX_NQM_VFX_CC(dev->pfvf))) & NVME_CC_ENABLE) {
				debug_printf(1, "acq:: EN bit is set"
					" no aqa write permitted\n");
				return;
			}
			break;
		default:
			debug_printf(1, "Error: Invalid bar register 0x%lx", access_offset);
			break;
        	}
	}
}

/***************************************************************************//**

Both host and device will access this memory at the same time

hil_reg_poll_update() :

This function will keep on polling the 'head' and 'tail' of Polling Register.
If update is found, will check the offset limit w.r.t circular buffer array as
'head'index and then call hil_process_ctrlreg() or hil_update_subqueue(),
depending on if the access is with the NVMe register area or queue area.

In this version, we assume all register accesses are write, and ignore the read
access type. This is because the host driver can directly read the registers
and not send notifications of reads down to us.

    @param dev pointer to a device structure of type struct nvme_dev.

*******************************************************************************/

//Madhu We definitely need more comments in this file.
void hil_reg_poll_update(struct nvme_dev *dev)
{
	uint64_t offset;
	uint32_t head = 0;
	uint32_t tail = 0;
	static volatile uint32_t *reg_poll_head;
	static volatile uint32_t *reg_poll_tail;

	reg_poll_head = &reg_poll->head;
	reg_poll_tail = &reg_poll->tail;
	head = cvmx_atomic_get32((int32_t *)reg_poll_head);
	tail = cvmx_atomic_get32((int32_t *)reg_poll_tail);

	while (head != tail) {
		offset = reg_poll->cir_buf[head].access_offset;

		if (offset < NVME_DOORBELL_OFFSET) {
			hil_process_ctrlreg( dev, offset);
		} else if (SYSTEM_READY ==
			cvmx_atomic_get32((int32_t *)&(dev->system_state))) {
			hil_update_subqueue(dev, offset);
		}
		++head;
		head %= POLL_LIST_SIZE;
	}
	cvmx_atomic_set32((int32_t *)reg_poll_head, head);
}

/***************************************************************************//**

*
*   hil_rrlist_init
*
*   This function initializes struct nvme_rrlist_process within struct nvme_dev
*    struct nvme_rrlist_process is used to handle submission queues updated by
*    the host software.
*
*       @param dev Pointer to device structure nvme_dev
*
*       @return Zero on success, or negative error code on failure.
*

*******************************************************************************/

int hil_rrlist_init(struct nvme_dev * dev)
{
	uint16_t maximum_entries;
	uint16_t maximum_subq;
	/**
	 * Initialize nvme_rr_mgmt structure members to zero
	 */
	memset(&(dev->nvme_rr_mgmt), 0, sizeof(struct  nvme_rrlist_process));
	/* maximum sub queues are zero based value, one admin queue and I/O queue */
	maximum_subq = le16_cpu(dev->dev_config.max_sub_queues) + 1 + 1;
	maximum_entries = maximum_subq / 64;      /* 64 entries per rrlist entry */

	/**
	 * Increment by one to cover boundary conditions
	 * Minimum one pair of I/O queues and admin queue.
	 * Modulo of 64 queues, should increment the maximum entries by one
	 */	
	if (maximum_subq % 64)
		maximum_entries++;
	dev->max_entries = maximum_entries;

	return STATUS_SUCCESS;
}

/***************************************************************************//**

*
*    hil_update_subqueue
*
*    This function extracts the submission queue number, sets the pending bit for
*    the corresponding queue in the round robin list and increments the pending
*    submission queues
*
*         @param dev      Pointer to device structure nvme_dev
*         @param offset      Offset to the updated queue(submission/completion)
*
*         @return Zero on success, or negative error code on failure.
*
*    @todo
*
*         1. Remove warning messages on atomic operation argument 1
*

*******************************************************************************/

int hil_update_subqueue(struct nvme_dev *   dev,
                        uint32_t            offset)
{

	uint16_t qid;
	uint8_t index;
	uint32_t idx_offset;
	struct async_event_result nvme_async_evt = { 0, };
	struct nvme_log_error error_log = { 0, };
	cvmx_wqe_tt *wqe_new;
	struct nvme_sub_queue *sub_queue;
	struct nvme_cpl_queue *cpl_queue;
	uint16_t cq_no;
	struct nvme_list *associated_cpl_list_entry = NULL;
	uint64_t subqueue_db_offset;
	uint16_t associated_qid;
	/**
	 * Extract queue ID from the offset
	 *
	 */ 
	qid = ( offset - NVME_SQ_TAIL_DB_OFFSET) / 8;

	/**
	 * If Modulo of 8 operation on offset value results in non zero value, then
	 * completion queue is updated. Otherwise submission queue is updated
	 */
	if ((offset - NVME_SQ_TAIL_DB_OFFSET) % 8) {
		/**
		 * Check whether queue corresponding to completion queue ID has been
		 * created
		 */
		if (dev->queue->cq[qid] == NULL) {
			/**
			 * The queue ID corresponds to a completion queue that has not got created, generate
			 * asynchronous event and return status as failure
			 */
			nvme_async_evt.aet =  AET_ERROR_STATUS;
			nvme_async_evt.aei =  INVALID_DB_REGISTER ;
			return STATUS_ERROR;
		}
		/**
		 * Update the head of corresponding completion queue with the value in
		 * doorbell register
		 */
		cpl_queue = dev->queue->cq[qid];
		cvmx_atomic_set32((int32_t *)&(dev->queue->cq[qid]->cq_head),
		*((uint32_t *)((uint8_t *)nvme_bar1 + offset)));
		if (cvmx_atomic_get32((int32_t *)&dev->queue->cq[qid]->pending_entries)) {
			wqe_new = (cvmx_wqe_tt *)npl_fpa_alloc(dev, CVMX_FPA_WQE_POOL);
			if (!wqe_new) goto fail;
			npl_setup_wqe(wqe_new);
			wqe_new->word3.qw3.vf = dev->pfvf; // set pf/vf

			if (qid != 0) {
				associated_cpl_list_entry = list_first_entry_or_null(
					&cpl_queue->associated_list.list,
					struct nvme_list, list);
				if (associated_cpl_list_entry == NULL)
					return STATUS_ERROR;

				wqe_new->word3.qw3.sq_id =
					*((uint16_t *)associated_cpl_list_entry->data);
			} else {
				wqe_new->word3.qw3.sq_id = 0;
			}
			wqe_new->word5.u64 = 0;
			wqe_new->word1.qw1.tag =
				((CMD_COMPLETION_REQUEST_TAG << NQM_TAG_SHIFT) |
				(qid << NQM_QID_SHIFT));
			wqe_new->word1.qw1.tt = CVMX_POW_TAG_TYPE_ATOMIC;
			cvmx_pow_work_submit((cvmx_wqe_t *)wqe_new,
				((CMD_COMPLETION_REQUEST_TAG << NQM_TAG_SHIFT) |
				(qid << NQM_QID_SHIFT)),
				CVMX_POW_TAG_TYPE_ATOMIC,
				NVME_WQE_QOS, NVME_WQE_GRP);

			/**
			 * in a loop, process all associated sub queues
			 * associated with this completion queue.
			 *
			 */
			if (qid != 0) {
				list_for_each_entry(associated_cpl_list_entry,
				    &cpl_queue->associated_list.list, list) {
					if (associated_cpl_list_entry != NULL) {
						associated_qid = *((uint16_t *)
						    associated_cpl_list_entry->data);
						subqueue_db_offset =
							NVME_SQ_TAIL_DB_OFFSET +
							associated_qid * 8;
						/* Add to the rr list */
						hil_update_subqueue(dev,
							subqueue_db_offset);
					}
				}
			} else {
				associated_qid = 0;
				subqueue_db_offset =
				NVME_SQ_TAIL_DB_OFFSET + associated_qid * 8;
				/* Add to the rr list */
				hil_update_subqueue(dev, subqueue_db_offset);
			}
		} else if ((cvmx_atomic_get32((int32_t *)&cpl_queue->cq_full))) {
			cvmx_atomic_set32(((int32_t *)&cpl_queue->cq_full), 0);
			if (qid != 0) {
				list_for_each_entry(associated_cpl_list_entry,
				    &cpl_queue->associated_list.list, list){
					if (associated_cpl_list_entry != NULL) {
						associated_qid =
						    *((uint16_t *)
						    associated_cpl_list_entry->data);
						subqueue_db_offset =
						    NVME_SQ_TAIL_DB_OFFSET +
						    associated_qid * 8;
						/* Add to the rr list */
						hil_update_subqueue(dev,
							subqueue_db_offset);
					}
				}
			} else {
				associated_qid = 0;
				subqueue_db_offset = NVME_SQ_TAIL_DB_OFFSET +
				associated_qid * 8;
		                /* Add to the rr list */
				hil_update_subqueue(dev, subqueue_db_offset);
			}
		}
	} else {
		/**
		 * Check whether queue corresponding to submission
		 * queue ID has been created
		 */
		if (dev->queue->sq[qid] == NULL) {
			/**
			 * The queue ID corresponds to has not been created queue,
			 * generate asynchronous event and return status as failure
			 */
			nvme_async_evt.aet =  AET_ERROR_STATUS;
			nvme_async_evt.aei =  INVALID_DB_REGISTER ;
			nvme_async_evt.alp = ERROR_BIT;
			npl_update_error_logpages(dev, &error_log);
			npl_async_event_update(dev, &nvme_async_evt);
			return STATUS_ERROR;
		}
		sub_queue = dev->queue->sq[qid];
		cq_no = sub_queue->cq_id;
		cpl_queue = dev->queue->cq[cq_no];

		/**
		* Check for the CQ full condition
		* Check the cq_full flag is Set or not
		*/
		if (qid != 0)
			if (cvmx_atomic_get32((int32_t *)&cpl_queue->cq_full))
				return STATUS_ERROR;

		/**
		 * Submission queue has been updated, and process the submission queue
		 */
		index = qid / 64;
		idx_offset = qid % 64;
		if (!(dev->nvme_rr_mgmt.nvme_sq_list[index] &
		    (0x01 << idx_offset))) {
			/**
			 * Submission queue is scheduled for processing
			 * Hence set the corresponding pending bit in submission queue list
			 * and increment number of pending submission queues
			 */
			dev->nvme_rr_mgmt.nvme_sq_list[index] |=
				(0x01 << idx_offset);
			++(dev->nvme_rr_mgmt.nvme_sq_set_cnt);
		}
	}
		
	return 0;

fail:
	return -1;
}


/***************************************************************************//**
*
*   hil_process_cmd_transfer_tag
*
*   This function processes the work queue entry having the tag
*   CMD_TRANSFER_TAG
*
*       @param dev Private data structure pointer
*       @param wqp Work queue entry pointer
*
*       @return Zero on success, or negative error code on failure.
*
*******************************************************************************/

int 
hil_process_cmd_transfer_tag(struct nvme_dev *  dev,
                             cvmx_wqe_tt *       wqp)
{
    struct nvme_cmd *sq_cmd;
    struct nvme_cmd *sq_ba;
    struct nvme_sub_queue *queue;
    uint32_t i = 0, k = 0;
    uint32_t sq_head;
    uint8_t *sqhead_flags;
    uint16_t entry_count ;
    uint32_t qdepth;
    struct nvme_cmd_transfer *queue_info =
        (struct nvme_cmd_transfer *)&(wqp->word5.u64);
    uint32_t tag;
    
    entry_count = queue_info->entry_count;  
    queue = dev->queue->sq[queue_info->qid];
    sqhead_flags = queue->sqhead_flags;
    sq_head = queue->sq_head;
    qdepth = queue->sq_depth;
    sq_ba = dev->queue->sq[queue_info->qid]->sq_cmds;   
    k = queue_info->q_entry;
   tag = (CMD_HANDLE_TAG << NQM_TAG_SHIFT) | (queue_info->qid << NQM_QID_SHIFT);
    while (entry_count--) {
        sqhead_flags[k++] = 1;
        for (i = 0; i < qdepth; i++) {
            if (sqhead_flags[(sq_head + i) % qdepth] != 1) {
                sq_head = (sq_head + i) % qdepth;
                break;
            }
            sqhead_flags[(sq_head + i) % qdepth] = 0;
        }
    }
    entry_count = queue_info->entry_count;
    cvmx_atomic_set32((int32_t *)&queue->sq_head, sq_head);
    while (entry_count--) {
        cvmx_wqe_tt *work;
        sq_cmd = &sq_ba[queue_info->q_entry];
        work = npl_fpa_alloc(dev, CVMX_FPA_WQE_POOL);
        if (!work) goto fail;
        npl_setup_wqe(work);
        work->word3.qw3.vf = dev->pfvf; // set pf/vf
        work->word3.qw3.sq_id = queue_info->qid;
        work->word4.qw4.sq_head = sq_head;
        work->word1.qw1.tag = (CMD_HANDLE_TAG << NQM_TAG_SHIFT) |
                              (queue_info->qid << NQM_QID_SHIFT);
        work->word1.qw1.tt = CVMX_POW_TAG_TYPE_ORDERED;
        work->word1.qw1.grp = 0;
        memcpy(&(work->nvme_cmd), sq_cmd, sizeof(struct nvme_cmd));
        cvmx_pow_work_submit((cvmx_wqe_t *)work, tag,
                             CVMX_POW_TAG_TYPE_ORDERED,
                             NVME_WQE_QOS, NVME_WQE_GRP);

        queue_info->q_entry++;
    }
    return STATUS_SUCCESS;

fail:

    return STATUS_ERROR;
}

/***************************************************************************//**
*
*    hil_process_rr_list
*
*      This function process the round robin list for the pending submission
*      queues for processing. If any submission queues are pending it calls a
*      function to dma transfer of submission queue commands and posting work
*      queue entry
*
*         @param dev Pointer to device structure nvme_dev
*
*         @return Zero on success, or negative error code on failure.
*
*******************************************************************************/

int hil_process_rr_list(struct nvme_dev * dev)
{
	uint64_t nvme_bar1_offset_reg;
	uint32_t nvme_sq_tail_val;
	uint32_t current_index;
	uint8_t current_offset;
	int32_t result = STATUS_ERROR;
	int32_t count = 0;
	uint64_t * nvme_sq_list;
	uint16_t nvme_sq_set_cnt; 
	uint16_t max_entries;
	uint32_t nvme_process_queue;
	uint16_t sq_no = 0x00;
	
	max_entries =dev->max_entries;
	if (dev->nvme_rr_mgmt.nvme_sq_set_cnt > 0) {
		/* Pending submission queue for processing */
		current_index = dev->nvme_rr_mgmt.current_index;

		current_offset =  dev->nvme_rr_mgmt.current_offset;

		nvme_sq_list = dev->nvme_rr_mgmt.nvme_sq_list;
		nvme_sq_set_cnt =  dev->nvme_rr_mgmt.nvme_sq_set_cnt;

		/**
		 *  Process the pending submission queue list to identify the pending
		 * submission queue number starting from last processed submission queue
		 */

		for (; count < nvme_sq_set_cnt;
		    current_index = (current_index + 1) % max_entries) {
			for (; ((current_offset < 64) && nvme_sq_list[current_index]);
			    current_offset++) {
				if (nvme_sq_list[current_index] &
				    (0x01ULL << current_offset)) {
					nvme_process_queue =
					    ((current_index << 6) + current_offset) * 8;
					nvme_bar1_offset_reg =
						(uint64_t)((uint8_t *)nvme_bar1) +
						NVME_SQ_TAIL_DB_OFFSET +
						nvme_process_queue;
					nvme_sq_tail_val =
						*(volatile uint32_t *)nvme_bar1_offset_reg;
						sq_no = nvme_process_queue / 8;
					if (nvme_sq_tail_val <
					    dev->queue->sq[sq_no]->sq_depth) {
						/**
						 * Valid tail count for the corresponding
						 * submission queue.
						 * Initiate dma transfer to copy commands
						 * from host side to local copy of the
						 * submission queue on device side.
						 */
			                        result = hil_trig_dma_transfer(dev, sq_no,
                                                       nvme_sq_tail_val);
						nvme_sq_list[current_index] &=
							~(0x1 << current_offset);
					} else {
						debug_printf(1, "Error: Invalid tail"
							" count update has occurred");
						/**
						 * Invalid tail count for submission queue
						 * Raise an asynchronous event
						 */
						result = STATUS_ERROR;
					}					
					count++;
				}
			}
			if (count == nvme_sq_set_cnt)
				break;
			current_offset = 0;
		}
		if (current_offset == 64) {
			current_offset = 0;
			current_index = (current_index+1)  % max_entries;
		}
		dev->nvme_rr_mgmt.nvme_sq_set_cnt = 0;
		dev->nvme_rr_mgmt.current_index = current_index;
		dev->nvme_rr_mgmt.current_offset = current_offset;		
	}		
	result = 0;

	return result;
}

/***************************************************************************//**
*
*    hil_trig_dma_transfer
*
*    This function initiates the dma transfer of commands for the submission
*    queue on host side to local copy of submission queue on device side.
*    Posts a work queue entry and retruns to caller with dma transfer status
*
*         @param dev           Pointer to device structure nvme_dev
*         @param sq_no           submission queue number
*         @param sq_tail_val      submission queue tail value
*
*         @return Zero on success, or negative error code on failure.
*
*******************************************************************************/
int hil_trig_dma_transfer(struct nvme_dev * dev,
                          uint16_t          sq_no,
                          uint32_t          sq_tail_val)
{
	uint16_t transfer_cnt;
	uint8_t result = STATUS_ERROR;
	uint16_t sub_queue_cmd_size = dev->dev_config.io_sqes;
	uint32_t processed_sub_queue_tail= dev->queue->sq[sq_no]->sq_tail;
	uint16_t sub_queue_depth = dev->queue->sq[sq_no]->sq_depth;

    uint64_t host_sub_queue_base =
        (uint64_t)dev->queue->sq[sq_no]->host_sub_queue_addr;
	uint64_t dev_sub_queue_base = (uint64_t)dev->queue->sq[sq_no]->sq_cmds;
	uint64_t host_sub_queue_addr = host_sub_queue_base;
	uint64_t dev_sub_queue_addr = dev_sub_queue_base;
    DMA_LIMIT_DATA_TRN_T dma_data_trans;
				
	/**
     * Initialize DMA limited data transfer structure to zero
	 */
    memset(&dma_data_trans, 0, sizeof(dma_data_trans));

	/**
	 * Calculate the offset from the base address for actual addresses of
	 * submission queue
	 */
	host_sub_queue_addr += processed_sub_queue_tail * sub_queue_cmd_size;
	dev_sub_queue_addr += processed_sub_queue_tail * sub_queue_cmd_size;

	/**
     * Update DMA limited data transfer structure members with
     * necessary information
	 */
    dma_data_trans.packet_size = sub_queue_cmd_size;
    dma_data_trans.queue_no = sq_no;
    dma_data_trans.dma_mode = DMA_INBOUND;
    dma_data_trans.source_addr = host_sub_queue_addr;
    dma_data_trans.dest_addr = dev_sub_queue_addr;
    dma_data_trans.processed_entry = processed_sub_queue_tail;
    dma_data_trans.path = SUBMISSION_PATH;
    if (processed_sub_queue_tail < sq_tail_val) {
		/**
		 * Submission queue wrap around has not occured
		 *
         * Calculate number of commands to transfer
		 *
         * Update DMA limited data transfer structure members with
		 * necessary information
		 */		 
		transfer_cnt = ( sq_tail_val - processed_sub_queue_tail);
        dma_data_trans.transfer_cnt = transfer_cnt;
#if DISCONTIGUOUS_Q_SUPPORT
        /*  If the queue is dis-contiguous, get the sq entries from the host dis-contiguous queue */
        if (dev->queue->sq[sq_no]->queue_discontiguous) {
            result = hil_xfer_discontiguous_sq_entries(dev, transfer_cnt,
                                                       processed_sub_queue_tail,
                                                       dev_sub_queue_addr,
                                                       sq_no);
            if (STATUS_SUCCESS == result) {
			processed_sub_queue_tail =  sq_tail_val;
                /* update the entry count in the submission queue */
                cvmx_atomic_add32((int32_t *)&(dev->queue->sq[sq_no]->
                                               num_entries), transfer_cnt);
            } else {
			/**
			 * DMA transfer is unsuccessful, return the DMA transfer status to
			 * the caller
			 */
                debug_printf(1,
                             "Error: DMA transfer of dis-contiguous sq cmds to local buffer failed");
            }
        } else
        /*  The host side queue is not dis-contiguous */
#endif
        {
            /**
             * Call DMA function for data transfer
             */
            result = hil_dma_limit_data_tansfer(dev, &dma_data_trans);
            if (STATUS_SUCCESS == result) {
                /**
                 * DMA transfer is successful, update the submission queue tail
                 */
                processed_sub_queue_tail = sq_tail_val;
                /* update the entry count in the submission queue */
                cvmx_atomic_add32((int32_t *)&(dev->queue->sq[sq_no]->
                                               num_entries), transfer_cnt);
            } else {
                /**
                 * DMA transfer is unsuccessful, return the DMA transfer status to
                 * the caller
                 */
                debug_printf(1,
                             "Error: DMA txfr of sq cmds to local buffer failed");
		}
	}
    } else if (processed_sub_queue_tail == sq_tail_val) {
        /**
         * Processed submission queue and current submission queue are equal.
         * Hence we don't process the queue. But free the allocated work queue
         * entry.
         */
        result = STATUS_SUCCESS;
        return result;
    } else {
		/**
		 * Submission queue wrap around has occured
		 *
         * Update Work Queue Entry and DMA limit transfer structure members with
		 * necessary information
		 */		 
		transfer_cnt = sub_queue_depth - processed_sub_queue_tail; 
#if DISCONTIGUOUS_Q_SUPPORT
        /*  If the queue is dis-contiguous, get the sq entries from the host dis-contiguous queue */
        if (dev->queue->sq[sq_no]->queue_discontiguous) {
            result = hil_xfer_discontiguous_sq_entries(dev, transfer_cnt,
                                                       processed_sub_queue_tail,
                                                       dev_sub_queue_addr,
                                                       sq_no);
            if ((STATUS_SUCCESS == result) && sq_tail_val) {
                /* update the entry count in the submission queue */
                cvmx_atomic_add32((int32_t *)&(dev->queue->sq[sq_no]->
                                               num_entries), transfer_cnt);
                processed_sub_queue_tail = sub_queue_depth;
                transfer_cnt = sq_tail_val;
                dev_sub_queue_addr = dev_sub_queue_base;
                result = hil_xfer_discontiguous_sq_entries(dev, transfer_cnt,
                                                           processed_sub_queue_tail,
                                                           dev_sub_queue_addr,
                                                           sq_no);
                if (STATUS_SUCCESS == result) {
                    /**
                     * DMA transfer is successful, update the submission queue tail
                     */
                    processed_sub_queue_tail = sq_tail_val;
                    /* update the entry count in the submission queue */
                    cvmx_atomic_add32((int32_t *)&(dev->queue->sq[sq_no]->
                                                   num_entries), transfer_cnt);
                } else {
                    /**
                     * DMA transfer is unsuccessful, return the DMA transfer status to
                     * the caller
                     */
                    debug_printf(1,
                                 "Error: DMA transfer of dis-contiguous sq cmds to local buffer failed");
                }
            } else if (STATUS_SUCCESS == result) {
                processed_sub_queue_tail = sub_queue_depth;
            }
        } else
        /*  The host side queue is not dis-contiguous */
#endif
        {
            dma_data_trans.transfer_cnt = transfer_cnt;

            /**
             * Call DMA function for data transfer
             */
            result = hil_dma_limit_data_tansfer(dev, &dma_data_trans);

            if ((STATUS_SUCCESS == result) && sq_tail_val) {
                /* update the entry count in the submission queue */
                cvmx_atomic_add32((int32_t *)&(dev->queue->sq[sq_no]->
                                               num_entries), transfer_cnt);
			/**
			 * DMA transfer is successful, update the submission queue tail.
			 * Schedule next DMA transfer.
			 * New work queue entry is generated for remaining DMA transfer.
			 * Get memory for work queue entry from the FPA pool
			 */
			processed_sub_queue_tail = sub_queue_depth;

			/**
			 * Source and destination address of host and device submission
			 * queue is the base address of the queues
                 *
                 * Beginning of the sub-queue:
			 * sub_queue_depth - processed_sub_queue_tail = zero
			 * Variable processed_sub_queue_tail is updated after successful
			 * DMA transfer
			 */
                transfer_cnt = sq_tail_val;
                dma_data_trans.transfer_cnt = transfer_cnt;
                dma_data_trans.source_addr = host_sub_queue_base;
                dma_data_trans.dest_addr = dev_sub_queue_base;
                dma_data_trans.processed_entry = 0x00UL;

                result = hil_dma_limit_data_tansfer(dev, &dma_data_trans);
                if (STATUS_SUCCESS == result) {
				/**
				 * DMA transfer is successful, update the submission queue tail
				 */
				processed_sub_queue_tail =  sq_tail_val;
                    /* update the entry count in the submission queue */
                    cvmx_atomic_add32((int32_t *)&(dev->queue->sq[sq_no]->
                                                   num_entries), transfer_cnt);
                } else {
				/**
				 * DMA transfer is unsuccessful, return the DMA transfer status to
				 * the caller
				 *
                 * For wrap around case:
				 * what if first half of the transfer is successful next half
				 * of the transfer is unsuccessful - Currently the tail count
				 * is updated for the successful transfer.
				 */
                    debug_printf(1,
                                 "Error: DMA transfer of sq commands to local buffer failed");
			}

            } else if (STATUS_SUCCESS == result) {
			processed_sub_queue_tail = sub_queue_depth;			
            } else {
			/**
			 * DMA transfer is unsuccessful, return the DMA transfer status to
			 * the caller
			 */
                debug_printf(1,
                             "Error: DMA transfer of sq commands to local buffer failed");
		}
      }
	}
	/**
	 * If the command transferred is last element of the queue, next command
	 * processing starts from the beginning of queue
	 */
	if (sub_queue_depth == processed_sub_queue_tail)
		processed_sub_queue_tail = 0;
    dev->queue->sq[sq_no]->sq_tail = processed_sub_queue_tail;
	return result;
}

/***************************************************************************//**

*
*    hil_frame_wqe
*
*    This function updates the work queue entry and command transfer structure
*    members with necessary values. This function used internally in this file
*
*         @param nvme_wqe           Pointer to work queue entry structure nvme_wqe
*         @param sq_no               Submission queue number
*         @param processed_sub_queue_tail     submission queue tail value
*         @param transfer_cnt          Number of commands to transfer
*
*    @todo hil_frame_wqe
*

*******************************************************************************/

static void hil_frame_wqe(cvmx_wqe_tt *  nvme_wqe,
                          uint16_t      sq_no,
                          uint16_t      processed_sub_queue_tail,
					uint64_t transfer_cnt)
{
	struct nvme_cmd_transfer * nvme_cmmd_transfer;
	
	nvme_cmmd_transfer = (struct nvme_cmd_transfer *)&nvme_wqe->word5.u64 ;
    nvme_wqe->word1.qw1.tag = (CMD_TRANSFER_TAG << NQM_TAG_SHIFT) |
                              (sq_no << NQM_QID_SHIFT);
	nvme_wqe->word1.qw1.tt =  CVMX_POW_TAG_TYPE_ATOMIC;
    nvme_wqe->word1.qw1.grp = 0;
	nvme_wqe->word3.qw3.sq_id = sq_no;
	nvme_wqe->word3.qw3.vf = 0; // set as vf(0) (PF) always
	nvme_cmmd_transfer->qid = sq_no;
	nvme_cmmd_transfer->q_entry = processed_sub_queue_tail;
	nvme_cmmd_transfer->entry_count = transfer_cnt;
}

/***************************************************************************//**

*
*  print_cmd_info
*

*******************************************************************************/

void print_cmd_info(uint8_t * cmd_ptr)
{

	uint8_t index;
	
    for (index = 0; index < 64; index++) {
			if(index % 4)
            debug_printf(1, "\nDWORD%d :", index);
			debug_printf(1, " 0x%02x", cmd_ptr[index]);
	}
}

/***************************************************************************//**
*
*    hil_xfer_discontiguous_sq_entries
*
*    This function transfers the submission queue entries from the host
*    side dis-contiguous queue to the device side
*
*         @param dev            Pointer to device structure nvme_dev
*         @param transfer_cnt       Number of commands to transfer
*         @param processed_sub_queue_tail     submission queue tail value
*         @param dev_sub_queue_addr    device side queue address
*         @param sq_no               Submission queue number
*
*         @return Zero on success, or negative error code on failure.
*
*******************************************************************************/
#if DISCONTIGUOUS_Q_SUPPORT
int hil_xfer_discontiguous_sq_entries(struct nvme_dev * dev,
                                      uint16_t          transfer_cnt,
                                      uint32_t          processed_sub_queue_tail,
                                      uint64_t          dev_sub_queue_addr,
                                      uint16_t          sq_no)
{
    uint16_t prp_entry_offset;
    uint16_t page_offset;
    uint64_t prp_entry;
    uint64_t host_sq_entry_ptr;
    uint16_t count;
    uint16_t remaining_entries;
    uint16_t sub_queue_cmd_size = dev->dev_config.io_sqes;
    int32_t result = STATUS_ERROR;
    struct nvme_dma nvme_dma_trsfr;

    while (transfer_cnt) {
        cvmx_wqe_tt *nvme_wqe;
        nvme_wqe = (cvmx_wqe_tt *)npl_fpa_alloc(dev, CVMX_FPA_WQE_POOL);
        if (!nvme_wqe) goto fail;
        npl_setup_wqe(nvme_wqe);
        nvme_wqe->word3.qw3.vf = dev->pfvf; // set pf/vf
        memset(&nvme_dma_trsfr, 0, sizeof(nvme_dma_trsfr));
        /* Calculate the offset of the PRP entry in the list page */
        prp_entry_offset = processed_sub_queue_tail /
                           dev->max_sq_entry_per_page;
        /* calculate the index of the submission entry in the page */
        page_offset = processed_sub_queue_tail % dev->max_sq_entry_per_page;
        /* Get the PRP entry */
        prp_entry =
            *((uint64_t *)(dev->queue->sq[sq_no]->host_sub_queue_addr) +
              prp_entry_offset);
        /*Get the address of the submission queue entry */
        host_sq_entry_ptr =
            (uint64_t)((struct nvme_cmd *)prp_entry + page_offset);
        /* calculate the number of entries that can be copies in one shot, considering queue wrap around*/
        remaining_entries = dev->max_sq_entry_per_page - page_offset;
        count =
            (remaining_entries >=
             transfer_cnt) ? transfer_cnt : remaining_entries;
        transfer_cnt -= count;
        /* Set up nvme_dma structure for transfer the submission queue entry to host */
        nvme_dma_trsfr.src = host_sq_entry_ptr;
        nvme_dma_trsfr.dst = dev_sub_queue_addr;
        nvme_dma_trsfr.nbytes = count * sub_queue_cmd_size;
        nvme_dma_trsfr.trans_type.prp_mode = PRP_NULL;
        nvme_dma_trsfr.trans_type.dma_mode = DMA_INBOUND;
        hil_frame_wqe(nvme_wqe, sq_no, processed_sub_queue_tail, count);
        /* Call DMA function for data transfer */
        result = npl_dma_submit(dev, &nvme_dma_trsfr, nvme_wqe);
        if (result == DMA_ERROR) {
            /**
             * DMA transfer is unsuccessful, return the DMA transfer status to
             * the caller
             */
            debug_printf(1,
                         "Error: DMA transfer of sq commands to local buffer failed");
            npl_fpa_free(nvme_wqe, CVMX_FPA_WQE_POOL, sizeof(cvmx_wqe_t));
            return STATUS_ERROR;
        }
        processed_sub_queue_tail += count;
        dev_sub_queue_addr += count * sub_queue_cmd_size;
    }
    return STATUS_SUCCESS;

fail:

    return STATUS_ERROR;
}

#endif

/***************************************************************************//**
*
*       hil_dma_limit_data_tansfer
*
*       This function transfers the number of bytes requested by taking care of
*       DMA hardware limitation on bulk data transfer. The requested byte
*       transfer is  higher than DMA hardware limitation, transfers are made in
*       chunks of DMA hardware limitation size.
*
*       @param dev                  Pointer to device structure nvme_dev
*       @param dma_data_trnsfr      Pointer to DMA data transfer structure.
*
*       @return Zero on success, or negative error code on failure.
*
*******************************************************************************/
int hil_dma_limit_data_tansfer(struct nvme_dev *        dev,
                               DMA_LIMIT_DATA_TRN_T *   dma_data_trnsfr)
{
    uint32_t transfer_cnt;
    uint32_t interim_transfer_cnt;
    uint32_t data_transfer_bytes;
    uint32_t size;
    struct nvme_dma nvme_dma_trsfr;
    cvmx_wqe_tt *nvme_wqe;
    uint8_t result = STATUS_ERROR;
    uint64_t dst_addr;
    uint64_t src_addr;
    uint32_t processed_entry;
    uint16_t sq_no;

    /**
     * Initialize the variables from the dma data transfer structure
     */
    transfer_cnt = dma_data_trnsfr->transfer_cnt;
    size = dma_data_trnsfr->packet_size;
    dst_addr = dma_data_trnsfr->dest_addr;
    src_addr = dma_data_trnsfr->source_addr;
    processed_entry = dma_data_trnsfr->processed_entry;
    sq_no = dma_data_trnsfr->queue_no;

    while (transfer_cnt) {
        data_transfer_bytes = transfer_cnt * size;
        interim_transfer_cnt = transfer_cnt;

        if (data_transfer_bytes > DMA_BLOCK_TRNSFER_LIMIT) {
            data_transfer_bytes = DMA_BLOCK_TRNSFER_LIMIT;
            interim_transfer_cnt = data_transfer_bytes / size;
        }

        /**
         * Get memory for work queue entry from the FPA pool
         */
        nvme_wqe = (cvmx_wqe_tt *)npl_fpa_alloc(dev, CVMX_FPA_WQE_POOL);
        if (!nvme_wqe) goto fail;

        /**
         * Initialize the work queue entry and nvme_dma structure
         */
        memset(nvme_wqe, 0, sizeof(cvmx_wqe_t));
        npl_setup_wqe(nvme_wqe);
        nvme_wqe->word3.qw3.vf = dev->pfvf; // set pf/vf
        memset(&nvme_dma_trsfr, 0, sizeof(nvme_dma_trsfr));
        nvme_dma_trsfr.trans_type.dma_mode = dma_data_trnsfr->dma_mode;

        /**
         * Update dma structure with local address and host address of
         * corresponding submission queue for dma transfer.
         */
        nvme_dma_trsfr.dst = dst_addr;
        nvme_dma_trsfr.src = src_addr;

        /**
         * Calculate number of bytes to transfer
         *
         * Update Work Queue Entry and nvme_dma structure members with
         * necessary information
         */
        data_transfer_bytes = size * interim_transfer_cnt;
        nvme_dma_trsfr.nbytes = data_transfer_bytes;

        if (SUBMISSION_PATH == dma_data_trnsfr->path)
            hil_frame_wqe(nvme_wqe, sq_no, processed_entry,
                          interim_transfer_cnt);

        /**
         * Call DMA function for data transfer
         */
        result = npl_dma_submit(dev, &nvme_dma_trsfr, nvme_wqe);
        if (STATUS_SUCCESS == result) {
            /**
             * DMA transfer is successful, update the submission queue tail
             */
            processed_entry += interim_transfer_cnt;
        } else {
            /**
             * DMA transfer is unsuccessful, return the DMA transfer status to
             * the caller
             */
            debug_printf(1,
                         "Error: DMA transfer of sq commands to local buffer failed");
            npl_fpa_free(nvme_wqe, CVMX_FPA_WQE_POOL, sizeof(cvmx_wqe_t));
            return STATUS_ERROR;
        }

        /**
         * Decrement the transfer count by number of successful transfer counts
         *
         * Increment source and destination address by number of bytes
         * transferred.
         */
        transfer_cnt -= interim_transfer_cnt;
        dst_addr += data_transfer_bytes;
        src_addr += data_transfer_bytes;
    }
    return STATUS_SUCCESS;

fail:

    return STATUS_ERROR;
}

/***************************************************************************//**

Process hil init

Initializes the hil module.

*******************************************************************************/

int hil_init(void)
{
	struct nvme_dev *dev; // device info structure pointer
	int ret = -1;

	debug_printf(1, "hil init:");

	/* Allocate memory for NVMe controller registers and the polling
	   registers */
	ret = hil_allocate_bar1();
	if(ret < 0)
		return ret;

	// initialize config module
	ret = nvme_config_init();
	if(ret < 0)
		return ret;

	// initialize sal module
	ret = sal_init();
	if (ret < 0)
		return ret;

	/*
	 * Create and initialize PF (0)
	 */
	ret = nvme_init_dev(0);
	if(ret < 0)
		return ret;

	dev = nqm_device_structs[0];
	if (!dev) {
		debug_printf(1, "PF device fails to allocate");
		return -1;
	}

	/* Initialize the round robin list */
	ret = hil_rrlist_init(dev);
	if(ret < 0)
		return ret;

	return 0;
}

/***************************************************************************//**

Process hil deinit

Deinitializes the hil module.

*******************************************************************************/

int hil_deinit(void)
{
	return 0;
}
