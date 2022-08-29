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
 * NONINFRINGEMENT.  See the GNU General Public License for more
 * details.
 **********************************************************************/
#include "cavium_sysdep.h"
#include "liquidio_common.h"
#include "octeon_droq.h"
#include "octeon_iq.h"
#include "response_manager.h"
#include "octeon_device.h"
#include "octeon_main.h"

static void oct_poll_req_completion(struct cavium_work *work);

int octeon_setup_response_list(struct octeon_device *oct)
{
	int i, ret = 0;
	struct cavium_wq *cwq;

	for (i = 0; i < MAX_RESPONSE_LISTS; i++) {
		CAVIUM_INIT_LIST_HEAD(&oct->response_list[i].head);
		cavium_spin_lock_init(&oct->response_list[i].lock);
		cavium_atomic_set(&oct->response_list[i].pending_req_count, 0);
	}
	cavium_spin_lock_init(&oct->cmd_resp_wqlock);

	oct->dma_comp_wq.wq = cavium_alloc_workqueue("dma-comp",
						     WQ_MEM_RECLAIM, 0);
	if (!oct->dma_comp_wq.wq) {
		lio_dev_err(oct, "failed to create wq thread\n");
		return -ENOMEM;
	}

	cwq = &oct->dma_comp_wq;
	CAVIUM_INIT_DELAYED_WORK(&cwq->wk.work, oct_poll_req_completion);
	cwq->wk.ctxptr = oct;
	oct->cmd_resp_state = OCT_DRV_ONLINE;

	return ret;
}

void octeon_delete_response_list(struct octeon_device *oct)
{
	if (oct->dma_comp_wq.wq) {
		cavium_cancel_delayed_work_sync(&oct->dma_comp_wq.wk.work);
		cavium_destroy_workqueue(oct->dma_comp_wq.wq);
	}

	oct->dma_comp_wq.wq = NULL;
}

int lio_process_ordered_list(struct octeon_device *octeon_dev,
			     u32 force_quit)
{
	struct octeon_response_list *ordered_sc_list;
	struct octeon_soft_command *sc;
	int request_complete = 0;
	int resp_to_process = MAX_ORD_REQS_TO_PROCESS;
	u32 status;
	u64 status64;

	octeon_free_sc_processed_done_list(octeon_dev);

	ordered_sc_list = &octeon_dev->response_list[OCTEON_ORDERED_SC_LIST];

	do {
		cavium_spin_lock_softirqsave(&ordered_sc_list->lock);

		if (CAVIUM_LIST_EMPTY(&ordered_sc_list->head)) {
			/* ordered_sc_list is empty; there is
			 * nothing to process
			 */
			cavium_spin_unlock_softirqrestore
			    (&ordered_sc_list->lock);
			return 1;
		}

		sc = CAVIUM_LIST_FIRST_ENTRY(&ordered_sc_list->head,
				      struct octeon_soft_command, node);

		status = OCTEON_REQUEST_PENDING;

		/* check if octeon has finished DMA'ing a response
		 * to where rptr is pointing to
		 */
		status64 = *sc->status_word;

		if (status64 != COMPLETION_WORD_INIT) {
			/* This logic ensures that all 64b have been written.
			 * 1. check byte 0 for non-FF
			 * 2. if non-FF, then swap result from BE to host order
			 * 3. check byte 7 (swapped to 0) for non-FF
			 * 4. if non-FF, use the low 32-bit status code
			 * 5. if either byte 0 or byte 7 is FF, don't use status
			 */
			if ((status64 & 0xff) != 0xff) {
				octeon_swap_8B_data(&status64, 1);
				if (((status64 & 0xff) != 0xff)) {
					/* retrieve 16-bit firmware status */
					status = (u32)(status64 & 0xffffULL);
					if (status) {
						status =
						  FIRMWARE_STATUS_CODE(status);
					} else {
						/* i.e. no error */
						status = OCTEON_REQUEST_DONE;
					}
				}
			}
		} else if (unlikely(force_quit || (sc->expiry_time &&
			cavium_check_timeout(cavium_jiffies, sc->expiry_time)))) {
			struct octeon_instr_irh *irh = (struct octeon_instr_irh *)&sc->cmd.cmd3.irh;

			lio_dev_err(octeon_dev, "%s: cmd %x/%x/%llx/%llx failed, expiry_time (%ld, %ld), force_quit=%d\n",
				__CVM_FUNCTION__, 
				irh->opcode, irh->subcode, sc->cmd.cmd3.ossp[0], sc->cmd.cmd3.ossp[1], 
				(long)cavium_jiffies, (long)sc->expiry_time, force_quit);
			status = OCTEON_REQUEST_TIMEOUT;
		}

		if (status != OCTEON_REQUEST_PENDING) {
		    sc->sc_status = status;

		    if (sc->callback == NULL) {
			cavium_set_bit(ORDERED_PROCESS_DONE_BIT, &sc->done);

			CAVIUM_LIST_DEL(&sc->node);
			cavium_atomic_dec(&octeon_dev->response_list
                                          [OCTEON_ORDERED_SC_LIST].
                                          pending_req_count);

			cavium_atomic_inc(&octeon_dev->response_list
				[OCTEON_PROCESSED_DONE_LIST].
				pending_req_count);
			CAVIUM_LIST_ADD_TAIL(&sc->node, &octeon_dev->response_list
				[OCTEON_PROCESSED_DONE_LIST].head);

			if (unlikely(cavium_test_bit(CALLER_DONE_BIT, &sc->done))) {
				/* process does not wait for response from firmware */
				if (status != OCTEON_REQUEST_DONE) {
					struct octeon_instr_irh *irh;
					irh = (struct octeon_instr_irh *)&sc->cmd.cmd3.irh;
					lio_dev_dbg(octeon_dev, "%s: sc failed: opcode=%x, subcode=%x, ossp[0]=%llx, ossp[1]=%llx, status=%d\n",
						__FUNCTION__,
						irh->opcode, irh->subcode, sc->cmd.cmd3.ossp[0], sc->cmd.cmd3.ossp[1],
						status);
				}
			} else 
				cavium_complete(&sc->complete);

			cavium_spin_unlock_softirqrestore(&ordered_sc_list->lock);
		
		    } else { /* sc with callback function */
			/* we have received a response or we have timed out */
			/* remove node from linked list */
			CAVIUM_LIST_DEL(&sc->node);
			cavium_atomic_dec(&octeon_dev->response_list
					  [OCTEON_ORDERED_SC_LIST].
					  pending_req_count);

			if (status == OCTEON_REQUEST_TIMEOUT) {
				cavium_atomic_inc(&octeon_dev->response_list
					[OCTEON_ZOMBIE_SC_LIST].
					pending_req_count);
				CAVIUM_LIST_ADD_TAIL(&sc->node, &octeon_dev->response_list
					[OCTEON_ZOMBIE_SC_LIST].head);

				cavium_atomic_inc(&octeon_dev->sc_zombie_cnt);
			}
			cavium_spin_unlock_softirqrestore
			    (&ordered_sc_list->lock);

			if (sc->callback) {
				sc->callback(octeon_dev, status,
					     sc->callback_arg);
			}
		    }

		    request_complete++;

		} else {
			/* no response yet */
			request_complete = 0;
			cavium_spin_unlock_softirqrestore
			    (&ordered_sc_list->lock);
		}

		/* If we hit the Max Ordered requests to process every loop,
		 * we quit
		 * and let this function be invoked the next time the poll
		 * thread runs
		 * to process the remaining requests. This function can take up
		 * the entire CPU if there is no upper limit to the requests
		 * processed.
		 */
		if (request_complete >= resp_to_process)
			break;
	} while (request_complete);

	return 0;
}

static void oct_poll_req_completion(struct cavium_work *work)
{
	struct cavium_wk *wk = (struct cavium_wk *)work;
	struct octeon_device *oct = (struct octeon_device *)wk->ctxptr;
	struct cavium_wq *cwq = &oct->dma_comp_wq;

	lio_process_ordered_list(oct, 0);

	if (cavium_atomic_read(&oct->response_list[OCTEON_ORDERED_SC_LIST].
                    pending_req_count))
		cavium_queue_delayed_work(cwq->wq, &cwq->wk.work, 1);
}
