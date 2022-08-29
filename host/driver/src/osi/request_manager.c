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
#include "octeon_network.h"
#include "cn66xx_device.h"
#include "cn23xx_pf_device.h"
#include "cn23xx_vf_device.h"


struct iq_post_status {
	int status;
	int index;
};

static void check_db_timeout(struct cavium_work *work);
static void  __check_db_timeout(struct octeon_device *oct, u64 iq_no);

static void (*reqtype_free_fn[MAX_OCTEON_DEVICES][REQTYPE_LAST + 1]) (void *);

static inline int IQ_INSTR_MODE_64B(struct octeon_device *oct, int iq_no)
{
	struct octeon_instr_queue *iq =
	    (struct octeon_instr_queue *)oct->instr_queue[iq_no];
	return iq->iqcmd_64B;
}

#define IQ_INSTR_MODE_32B(oct, iq_no)  (!IQ_INSTR_MODE_64B(oct, iq_no))

/* Define this to return the request status comaptible to old code */
/*#define OCTEON_USE_OLD_REQ_STATUS*/

/* Return 0 on success, 1 on failure */
int octeon_init_instr_queue(struct octeon_device *oct,
			    union oct_txpciq txpciq,
			    u32 num_descs)
{
	struct octeon_instr_queue *iq;
	struct octeon_iq_config *conf = NULL;
	u32 iq_no = (u32)txpciq.s.q_no;
	u32 q_size;
	struct cavium_wq *db_wq;
	int numa_node = cavium_iq_to_node(oct, iq_no);

	if (OCTEON_CN6XXX(oct))
		conf = &(CFG_GET_IQ_CFG(CHIP_CONF(oct, cn6xxx)));
	else if (OCTEON_CN23XX_PF(oct))
		conf = &(CFG_GET_IQ_CFG(CHIP_CONF(oct, cn23xx_pf)));
	else if (OCTEON_CN23XX_VF(oct))
		conf = &(CFG_GET_IQ_CFG(CHIP_CONF(oct, cn23xx_vf)));

	if (!conf) {
		lio_dev_err(oct, "Unsupported Chip %x\n",
			    oct->chip_id);
		return 1;
	}

	q_size = (u32)conf->instr_type * num_descs;

	iq = oct->instr_queue[iq_no];

	iq->oct_dev = oct;

	iq->base_addr = lio_dma_alloc(oct, "instr_queue", iq_no, q_size,
				      (cavium_dma_addr_t *)&iq->base_addr_dma);
	if (!iq->base_addr) {
		lio_dev_err(oct, "Cannot allocate memory for instr queue %d\n",
			    iq_no);
		return 1;
	}

	iq->max_count = num_descs;

	/* Initialize a list to holds requests that have been posted to Octeon
	 * but has yet to be fetched by octeon
	 */
	iq->request_list = cavium_vmalloc_node((sizeof(*iq->request_list) * num_descs),
					       numa_node);
	if (!iq->request_list)
		iq->request_list = cavium_vmalloc(sizeof(*iq->request_list) *
						  num_descs);
	if (!iq->request_list) {
		lio_dma_free(oct, q_size, iq->base_addr, iq->base_addr_dma);
		lio_dev_err(oct, "Alloc failed for IQ[%d] nr free list\n",
			    iq_no);
		return 1;
	}

	cavium_memset(iq->request_list, 0, sizeof(*iq->request_list) * num_descs);

	lio_dev_dbg(oct, "IQ[%d]: base: %p basedma: %llx count: %d\n",
		    iq_no, iq->base_addr, iq->base_addr_dma, iq->max_count);

	iq->txpciq.u64 = txpciq.u64;
	iq->fill_threshold = (u32)conf->db_min;
	iq->fill_cnt = 0;
	iq->host_write_index = 0;
	iq->octeon_read_index = 0;
	iq->flush_index = 0;
	iq->last_db_time = 0;
	iq->do_auto_flush = 1;
	iq->db_timeout = (u32)conf->db_timeout;
	cavium_atomic_set(&iq->instr_pending, 0);
	iq->pkts_processed = 0;

	/* Initialize the spinlock for this instruction queue */
	cavium_spin_lock_init(&iq->lock);
	if (iq_no == 0) {
		iq->allow_soft_cmds = 1;
		cavium_spin_lock_init(&iq->post_lock);
	} else {
		iq->allow_soft_cmds = 0;
	}

	cavium_spin_trylock_init(&iq->iq_flush_running_lock);

	oct->io_qmask.iq |= BIT_ULL(iq_no);

	/* Set the 32B/64B mode for each input queue */
	oct->io_qmask.iq64B |= ((conf->instr_type == 64) << iq_no);
	iq->iqcmd_64B = (conf->instr_type == 64);

	oct->fn_list.setup_iq_regs(oct, iq_no);

	oct->check_db_wq[iq_no].wq = cavium_alloc_workqueue("check_iq_db",
							    WQ_MEM_RECLAIM,
							    0);
	if (!oct->check_db_wq[iq_no].wq) {
		cavium_vfree(iq->request_list);
		iq->request_list = NULL;
		lio_dma_free(oct, q_size, iq->base_addr, iq->base_addr_dma);
		lio_dev_err(oct, "check db wq create failed for iq %d\n",
			    iq_no);
		return 1;
	}

	db_wq = &oct->check_db_wq[iq_no];

	CAVIUM_INIT_DELAYED_WORK(&db_wq->wk.work, check_db_timeout);
	db_wq->wk.ctxptr = oct;
	db_wq->wk.ctxul = iq_no;
	cavium_queue_delayed_work(db_wq->wq, &db_wq->wk.work, 1);


	return 0;
}

int octeon_delete_instr_queue(struct octeon_device *oct, u32 iq_no)
{
	u64 desc_size = 0, q_size;
	struct octeon_instr_queue *iq = oct->instr_queue[iq_no];

	cavium_cancel_delayed_work_sync(&oct->check_db_wq[iq_no].wk.work);
	cavium_destroy_workqueue(oct->check_db_wq[iq_no].wq);


	if (OCTEON_CN6XXX(oct))
		desc_size =
		    CFG_GET_IQ_INSTR_TYPE(CHIP_CONF(oct, cn6xxx));
	else if (OCTEON_CN23XX_PF(oct))
		desc_size =
		    CFG_GET_IQ_INSTR_TYPE(CHIP_CONF(oct, cn23xx_pf));
	else if (OCTEON_CN23XX_VF(oct))
		desc_size =
		    CFG_GET_IQ_INSTR_TYPE(CHIP_CONF(oct, cn23xx_vf));

	cavium_vfree(iq->request_list);

	if (iq->base_addr) {
		q_size = iq->max_count * desc_size;
		lio_dma_free(oct, (u32)q_size, iq->base_addr,
			     iq->base_addr_dma);

		oct->io_qmask.iq &= ~(1ULL << iq_no);
		cavium_vfree(oct->instr_queue[iq_no]);
		oct->instr_queue[iq_no] = NULL;
		oct->num_iqs--;

		return 0;
	}
	return 1;
}

/* Return 0 on success, 1 on failure */
int octeon_setup_iq(struct octeon_device *oct,
		    int ifidx,
		    int q_index,
		    union oct_txpciq txpciq,
		    u32 num_descs,
		    void *app_ctx)
{
	u32 iq_no = (u32)txpciq.s.q_no;
	int numa_node = cavium_iq_to_node(oct, iq_no);

	if (oct->instr_queue[iq_no]) {
		lio_dev_dbg(oct, "IQ is in use. Cannot create the IQ: %d again\n",
			    iq_no);
		oct->instr_queue[iq_no]->txpciq.u64 = txpciq.u64;
		oct->instr_queue[iq_no]->app_ctx = app_ctx;
		return 0;
	}
	oct->instr_queue[iq_no] =
	    cavium_vmalloc_node(sizeof(struct octeon_instr_queue), numa_node);
	if (!oct->instr_queue[iq_no])
		oct->instr_queue[iq_no] =
		    cavium_vmalloc(sizeof(struct octeon_instr_queue));
	if (!oct->instr_queue[iq_no])
		return 1;

	cavium_memset(oct->instr_queue[iq_no], 0,
		      sizeof(struct octeon_instr_queue));

	oct->instr_queue[iq_no]->q_index = q_index;
	oct->instr_queue[iq_no]->app_ctx = app_ctx;
	oct->instr_queue[iq_no]->ifidx = ifidx;

	if (octeon_init_instr_queue(oct, txpciq, num_descs)) {
		cavium_vfree(oct->instr_queue[iq_no]);
		oct->instr_queue[iq_no] = NULL;
		return 1;
	}

	oct->num_iqs++;
	if (oct->fn_list.enable_io_queues(oct))
		return 1;

	return 0;
}

int lio_wait_for_instr_fetch(struct octeon_device *oct)
{
	int i, retry = 1000, pending, instr_cnt = 0;

	do {
		instr_cnt = 0;

		for (i = 0; i < MAX_OCTEON_INSTR_QUEUES(oct); i++) {
			if (!(oct->io_qmask.iq & BIT_ULL(i)))
				continue;
			pending =
			    cavium_atomic_read(&oct->instr_queue[i]->instr_pending);
			if (pending)
				__check_db_timeout(oct, i);
			instr_cnt += pending;
		}

		if (instr_cnt == 0)
			break;

		cavium_sleep_timeout(1);

	} while (retry-- && instr_cnt);

	return instr_cnt;
}

static inline void
ring_doorbell(struct octeon_device *oct, struct octeon_instr_queue *iq)
{
	if (cavium_atomic_read(&oct->status) == OCT_DEV_RUNNING) {
		OCTEON_WRITE32(iq->doorbell_reg, iq->fill_cnt);
		/* make sure doorbell write goes through */
		cavium_sys_flush_write();
		iq->fill_cnt = 0;
		iq->last_db_time = cavium_jiffies;
		return;
	}
}

void
octeon_ring_doorbell_locked(struct octeon_device *oct, u32 iq_no)
{
	struct octeon_instr_queue *iq;

	iq = oct->instr_queue[iq_no];
	cavium_spin_lock(&iq->post_lock);
	if (iq->fill_cnt)
		ring_doorbell(oct, iq);
	cavium_spin_unlock(&iq->post_lock);
}

static inline void __copy_cmd_into_iq(struct octeon_instr_queue *iq,
				      u8 *cmd)
{
	u8 *iqptr, cmdsize;

	cmdsize = ((iq->iqcmd_64B) ? 64 : 32);
	iqptr = iq->base_addr + (cmdsize * iq->host_write_index);

	cavium_memcpy(iqptr, cmd, cmdsize);
}

static inline struct iq_post_status
__post_command2(struct octeon_instr_queue *iq, u8 *cmd)
{
	struct iq_post_status st;

	st.status = IQ_SEND_OK;

	/* This ensures that the read index does not wrap around to the same
	 * position if queue gets full before Octeon could fetch any instr.
	 */
	if (cavium_atomic_read(&iq->instr_pending) >= (s32)(iq->max_count - 1)) {
		st.status = IQ_SEND_FAILED;
		st.index = -1;
		return st;
	}

	if (cavium_atomic_read(&iq->instr_pending) >= (s32)(iq->max_count - 2))
		st.status = IQ_SEND_STOP;

	__copy_cmd_into_iq(iq, cmd);

	/* "index" is returned, host_write_index is modified. */
	st.index = iq->host_write_index;
	iq->host_write_index = incr_index(iq->host_write_index, 1,
					  iq->max_count);
	iq->fill_cnt++;

	/* Flush the command into memory. We need to be sure the data is in
	 * memory before indicating that the instruction is pending.
	 */
	cavium_flush_write();

	cavium_atomic_inc(&iq->instr_pending);

	return st;
}

int
octeon_register_reqtype_free_fn(struct octeon_device *oct, int reqtype,
				void (*fn)(void *))
{
	if (reqtype > REQTYPE_LAST) {
		lio_dev_err(oct, "%s: Invalid reqtype: %d\n",
			    __CVM_FUNCTION__, reqtype);
		return -EINVAL;
	}

	reqtype_free_fn[oct->octeon_id][reqtype] = fn;

	return 0;
}

static inline void
__add_to_request_list(struct octeon_instr_queue *iq,
		      int idx, void *buf, int reqtype)
{
	iq->request_list[idx].buf = buf;
	iq->request_list[idx].reqtype = reqtype;
}

/* Can only run in process context */
int
lio_process_iq_request_list(struct octeon_device *oct,
			    struct octeon_instr_queue *iq, u32 napi_budget)
{
	int reqtype;
	void *buf;
	u32 old = iq->flush_index;
	u32 inst_count = 0;
	unsigned int pkts_compl = 0, bytes_compl = 0;
	struct octeon_soft_command *sc;
	struct octeon_instr_irh *irh;
	unsigned long flags = 0;
	struct cavium_wq *cwq = &oct->dma_comp_wq;

	while (old != iq->octeon_read_index) {
		reqtype = iq->request_list[old].reqtype;
		buf     = iq->request_list[old].buf;

		if (reqtype == REQTYPE_NONE)
			goto skip_this;

		octeon_update_tx_completion_counters(buf, reqtype, &pkts_compl,
						     &bytes_compl);

		switch (reqtype) {
		case REQTYPE_NORESP_NET:
		case REQTYPE_NORESP_NET_SG:
		case REQTYPE_RESP_NET_SG:
			reqtype_free_fn[oct->octeon_id][reqtype](buf);
			break;
		case REQTYPE_RESP_NET:
		case REQTYPE_SOFT_COMMAND:
			sc = buf;

			if (OCTEON_CN23XX_PF(oct) || OCTEON_CN23XX_VF(oct))
				irh = (struct octeon_instr_irh *)
					&sc->cmd.cmd3.irh;
			else
				irh = (struct octeon_instr_irh *)
					&sc->cmd.cmd2.irh;
			/* We're expecting a response from Octeon.
			 * It's up to lio_process_ordered_list() to
			 * process  sc. Add sc to the ordered soft
			 * command response list because we expect
			 * a response from Octeon.
			 */
			cavium_spin_lock_irqsave
				(&oct->response_list
				 [OCTEON_ORDERED_SC_LIST].lock,
				 flags);
			cavium_atomic_inc(&oct->response_list
				[OCTEON_ORDERED_SC_LIST].
				pending_req_count);
			CAVIUM_LIST_ADD_TAIL(&sc->node, &oct->response_list
				[OCTEON_ORDERED_SC_LIST].head);
			cavium_spin_unlock_irqrestore
				(&oct->response_list
				 [OCTEON_ORDERED_SC_LIST].lock,
				 flags);
			break;
		default:
			lio_dev_err(oct,
				    "%s Unknown reqtype: %d buf: %p at idx %d\n",
				    __CVM_FUNCTION__, reqtype, buf, old);
		}

		iq->request_list[old].buf = NULL;
		iq->request_list[old].reqtype = 0;

 skip_this:
		inst_count++;
		old = incr_index(old, 1, iq->max_count);

		if ((napi_budget) && (inst_count >= napi_budget))
			break;
	}
	if (bytes_compl)
		octeon_report_tx_completion_to_bql(iq->app_ctx, pkts_compl,
						   bytes_compl);
	iq->flush_index = old;

	if (cavium_atomic_read(&oct->response_list[OCTEON_ORDERED_SC_LIST].
		    pending_req_count))
		cavium_queue_delayed_work(cwq->wq, &cwq->wk.work, 0);

	return inst_count;
}

/* Can only be called from process context */
int
octeon_flush_iq(struct octeon_device *oct, struct octeon_instr_queue *iq,
		u32 napi_budget)
{
	u32 inst_processed = 0;
	u32 tot_inst_processed = 0;
	int tx_done = 1;

	if (!cavium_spin_trylock(&iq->iq_flush_running_lock))
		return tx_done;

	cavium_spin_lock_softirqsave(&iq->lock);

	iq->octeon_read_index = oct->fn_list.update_iq_read_idx(iq);

	do {
		/* Process any outstanding IQ packets. */
		if (iq->flush_index == iq->octeon_read_index)
			break;

		if (napi_budget)
			inst_processed =
				lio_process_iq_request_list(oct, iq,
							    napi_budget -
							    tot_inst_processed);
		else
			inst_processed =
				lio_process_iq_request_list(oct, iq, 0);

		if (inst_processed) {
			iq->pkts_processed += inst_processed;
			cavium_atomic_sub(inst_processed, &iq->instr_pending);
			iq->stats.instr_processed += inst_processed;
		}

		tot_inst_processed += inst_processed;

	} while (tot_inst_processed < napi_budget);

	if (napi_budget && (tot_inst_processed >= napi_budget))
		tx_done = 0;

	iq->last_db_time = cavium_jiffies;

	cavium_spin_unlock_softirqrestore(&iq->lock);

	cavium_spin_tryunlock(&iq->iq_flush_running_lock);

	return tx_done;
}

/* Process instruction queue after timeout.
 * This routine gets called from a workqueue or when removing the module.
 */
static void __check_db_timeout(struct octeon_device *oct, u64 iq_no)
{
	struct octeon_instr_queue *iq;
	u64 next_time;

	if (!oct)
		return;

	iq = oct->instr_queue[iq_no];
	if (!iq)
		return;

	/* return immediately, if no work pending */
	if (!cavium_atomic_read(&iq->instr_pending))
		return;
	/* If cavium_jiffies - last_db_time < db_timeout do nothing  */
	next_time = iq->last_db_time + iq->db_timeout;
	if (!cavium_check_timeout(cavium_jiffies, next_time))
		return;
	iq->last_db_time = cavium_jiffies;

	/* Flush the instruction queue */
	octeon_flush_iq(oct, iq, 0);

	lio_enable_irq(NULL, iq);
}

/* Called by the Poll thread at regular intervals to check the instruction
 * queue for commands to be posted and for commands that were fetched by Octeon.
 */
static void check_db_timeout(struct cavium_work *work)
{
	struct cavium_wk *wk = (struct cavium_wk *)work;
	struct octeon_device *oct = (struct octeon_device *)wk->ctxptr;
	u64 iq_no = wk->ctxul;
	struct cavium_wq *db_wq = &oct->check_db_wq[iq_no];
	u32 delay = 10;

	__check_db_timeout(oct, iq_no);
	cavium_queue_delayed_work(db_wq->wq, &db_wq->wk.work, delay);
}


int
octeon_send_command(struct octeon_device *oct, u32 iq_no,
		    u32 force_db, void *cmd, void *buf,
		    u32 datasize, u32 reqtype)
{
	int xmit_stopped;
	struct iq_post_status st;
	struct octeon_instr_queue *iq = oct->instr_queue[iq_no];

	/* Get the lock and prevent other tasks and tx interrupt handler from
	 * running.
	 */
	if (iq->allow_soft_cmds)
		cavium_spin_lock_softirqsave(&iq->post_lock);

	st = __post_command2(iq, cmd);

	if (st.status != IQ_SEND_FAILED) {
		xmit_stopped = octeon_report_sent_bytes_to_bql(buf, reqtype);
		__add_to_request_list(iq, st.index, buf, reqtype);
		INCR_INSTRQUEUE_PKT_COUNT(oct, iq_no, bytes_sent, datasize);
		INCR_INSTRQUEUE_PKT_COUNT(oct, iq_no, instr_posted, 1);

		if (iq->fill_cnt >= MAX_OCTEON_FILL_COUNT || force_db ||
		    xmit_stopped || st.status == IQ_SEND_STOP)
			ring_doorbell(oct, iq);
	} else {
		INCR_INSTRQUEUE_PKT_COUNT(oct, iq_no, instr_dropped, 1);
	}

	if (iq->allow_soft_cmds)
		cavium_spin_unlock_softirqrestore(&iq->post_lock);

	/* This is only done here to expedite packets being flushed
	 * for cases where there are no IQ completion interrupts.
	 */

	return st.status;
}

void
octeon_prepare_soft_command(struct octeon_device *oct,
			    struct octeon_soft_command *sc,
			    u8 opcode,
			    u8 subcode,
			    u32 irh_ossp,
			    u64 ossp0,
			    u64 ossp1)
{
	struct octeon_config *oct_cfg;
	struct octeon_instr_ih2 *ih2;
	struct octeon_instr_ih3 *ih3;
	struct octeon_instr_pki_ih3 *pki_ih3;
	struct octeon_instr_irh *irh;
	struct octeon_instr_rdp *rdp;

	BUG_ON(opcode > 15);
	BUG_ON(subcode > 127);

	oct_cfg = octeon_get_conf(oct);

	if (OCTEON_CN23XX_PF(oct) || OCTEON_CN23XX_VF(oct)) {
		ih3 = (struct octeon_instr_ih3 *)&sc->cmd.cmd3.ih3;

		ih3->pkind = oct->instr_queue[sc->iq_no]->txpciq.s.pkind;

		pki_ih3 = (struct octeon_instr_pki_ih3 *)&sc->cmd.cmd3.pki_ih3;

		pki_ih3->w           = 1;
		pki_ih3->raw         = 1;
		pki_ih3->utag        = 1;
		pki_ih3->uqpg        =
			oct->instr_queue[sc->iq_no]->txpciq.s.use_qpg;
		pki_ih3->utt         = 1;
		pki_ih3->tag     = LIO_CONTROL;
		pki_ih3->tagtype = ATOMIC_TAG;
		pki_ih3->qpg         =
			oct->instr_queue[sc->iq_no]->txpciq.s.ctrl_qpg;
		pki_ih3->pm          = 0x7;
		pki_ih3->sl          = 8;

		if (sc->datasize)
			ih3->dlengsz = sc->datasize;

		irh            = (struct octeon_instr_irh *)&sc->cmd.cmd3.irh;
		irh->opcode    = opcode;
		irh->subcode   = subcode;

		/* opcode/subcode specific parameters (ossp) */
		irh->ossp       = irh_ossp;
		sc->cmd.cmd3.ossp[0] = ossp0;
		sc->cmd.cmd3.ossp[1] = ossp1;

		if (sc->rdatasize) {
			rdp = (struct octeon_instr_rdp *)&sc->cmd.cmd3.rdp;
			rdp->pcie_port = oct->pcie_port;
			rdp->rlen      = sc->rdatasize;

			irh->rflag =  1;
			/*PKI IH3*/
			/* pki_ih3 irh+ossp[0]+ossp[1]+rdp+rptr = 48 bytes */
			ih3->fsz    = LIO_SOFTCMDRESP_IH3;
		} else {
			irh->rflag =  0;
			/*PKI IH3*/
			/* pki_h3 + irh + ossp[0] + ossp[1] = 32 bytes */
			ih3->fsz    = LIO_PCICMD_O3;
		}

	} else {
		ih2          = (struct octeon_instr_ih2 *)&sc->cmd.cmd2.ih2;
		ih2->tagtype = ATOMIC_TAG;
		ih2->tag     = LIO_CONTROL;
		ih2->raw     = 1;
		ih2->grp     = ((oct_cfg) ? CFG_GET_CTRL_Q_GRP(oct_cfg) : 1) & 0xF;

		if (sc->datasize) {
			ih2->dlengsz = sc->datasize;
			ih2->rs = 1;
		}

		irh            = (struct octeon_instr_irh *)&sc->cmd.cmd2.irh;
		irh->opcode    = opcode;
		irh->subcode   = subcode;

		/* opcode/subcode specific parameters (ossp) */
		irh->ossp       = irh_ossp;
		sc->cmd.cmd2.ossp[0] = ossp0;
		sc->cmd.cmd2.ossp[1] = ossp1;

		if (sc->rdatasize) {
			rdp = (struct octeon_instr_rdp *)&sc->cmd.cmd2.rdp;
			rdp->pcie_port = oct->pcie_port;
			rdp->rlen      = sc->rdatasize;

			irh->rflag =  1;
			/* irh+ossp[0]+ossp[1]+rdp+rptr = 40 bytes */
			ih2->fsz   = LIO_SOFTCMDRESP_IH2;
		} else {
			irh->rflag =  0;
			/* irh + ossp[0] + ossp[1] = 24 bytes */
			ih2->fsz   = LIO_PCICMD_O2;
		}
	}
}

#ifdef LINUX_IPSEC
EXPORT_SYMBOL(octeon_prepare_soft_command);
#endif

int octeon_send_soft_command(struct octeon_device *oct,
			     struct octeon_soft_command *sc)
{
	struct octeon_instr_queue *iq;
	struct octeon_instr_ih2 *ih2;
	struct octeon_instr_ih3 *ih3;
	struct octeon_instr_irh *irh;
	u32 len;

	iq = oct->instr_queue[sc->iq_no];
	if (!iq->allow_soft_cmds) {
		lio_dev_err(oct, "Soft commands are not allowed on Queue %d\n",
			    sc->iq_no);
		INCR_INSTRQUEUE_PKT_COUNT(oct, sc->iq_no, instr_dropped, 1);
		return IQ_SEND_FAILED;
	}

	if (OCTEON_CN23XX_PF(oct) || OCTEON_CN23XX_VF(oct)) {
		ih3 =  (struct octeon_instr_ih3 *)&sc->cmd.cmd3.ih3;
		if (ih3->dlengsz) {
			BUG_ON(!sc->dmadptr);
			sc->cmd.cmd3.dptr = sc->dmadptr;
		}
		irh = (struct octeon_instr_irh *)&sc->cmd.cmd3.irh;
		if (irh->rflag) {
			BUG_ON(!sc->dmarptr);
			BUG_ON(!sc->status_word);
			if (sc->status_word != NULL)
				*sc->status_word = COMPLETION_WORD_INIT;
			sc->cmd.cmd3.rptr = sc->dmarptr;
		}
		len = (u32)ih3->dlengsz;
	} else {
		ih2 = (struct octeon_instr_ih2 *)&sc->cmd.cmd2.ih2;
		if (ih2->dlengsz) {
			BUG_ON(!sc->dmadptr);
			sc->cmd.cmd2.dptr = sc->dmadptr;
		}
		irh = (struct octeon_instr_irh *)&sc->cmd.cmd2.irh;
		if (irh->rflag) {
			BUG_ON(!sc->dmarptr);
			BUG_ON(!sc->status_word);
			if (sc->status_word != NULL)
				*sc->status_word = COMPLETION_WORD_INIT;
			sc->cmd.cmd2.rptr = sc->dmarptr;
		}
		len = (u32)ih2->dlengsz;
	}

	sc->expiry_time = cavium_jiffies + cavium_msecs_to_jiffies(LIO_SC_MAX_TMO_MS);

	return (octeon_send_command(oct, sc->iq_no, 1, &sc->cmd, sc,
				    len, REQTYPE_SOFT_COMMAND));
}

#ifdef LINUX_IPSEC
EXPORT_SYMBOL(octeon_send_soft_command);
#endif

int octeon_setup_sc_buffer_pool(struct octeon_device *oct)
{
	int i;
	u64 dma_addr;
	struct octeon_soft_command *sc;

	CAVIUM_INIT_LIST_HEAD(&oct->sc_buf_pool.head);
	cavium_spin_lock_init(&oct->sc_buf_pool.lock);
	cavium_atomic_set(&oct->sc_buf_pool.alloc_buf_count, 0);

	for (i = 0; i < MAX_SOFT_COMMAND_BUFFERS; i++) {
		sc = (struct octeon_soft_command *)
			lio_dma_alloc(oct, "sc_buf", i,
				      SOFT_COMMAND_BUFFER_SIZE,
					  (cavium_dma_addr_t *)&dma_addr);
		if (!sc) {
			octeon_free_sc_buffer_pool(oct);
			return 1;
		}

		sc->dma_addr = dma_addr;
		sc->size = SOFT_COMMAND_BUFFER_SIZE;

		CAVIUM_LIST_ADD_TAIL(&sc->node, &oct->sc_buf_pool.head);
	}

	return 0;
}

int 
octeon_free_sc_processed_done_list(struct octeon_device *octeon_dev)
{
	struct octeon_soft_command *sc;
	struct cavium_list_head *tmp, *tmp2;
	int fcount=0;
	struct octeon_response_list *ordered_sc_list;
	u64 status64;

	ordered_sc_list = &octeon_dev->response_list[OCTEON_ORDERED_SC_LIST];
	fcount = 0;

	fcount = cavium_atomic_read(&octeon_dev->response_list
                                          [OCTEON_PROCESSED_DONE_LIST].
                                          pending_req_count);

	if (fcount) {
		lio_dev_dbg(octeon_dev, "%s: fcount=%d\n", __FUNCTION__, fcount);
	} else {
		return 0;
	}

	cavium_spin_lock_softirqsave(&ordered_sc_list->lock);
	CAVIUM_LIST_FOR_EACH_SAFE(tmp, tmp2, &octeon_dev->response_list[OCTEON_PROCESSED_DONE_LIST].head) {
                sc = (struct octeon_soft_command *)tmp;

		if (cavium_test_bit(ORDERED_PROCESS_DONE_BIT, &sc->done)) {
			if (cavium_test_bit(CALLER_DONE_BIT, &sc->done)) {
				/* we have received a response or we have timed out */
				/* remove node from linked list */
				CAVIUM_LIST_DEL(&sc->node);
				cavium_atomic_dec(&octeon_dev->response_list
					  [OCTEON_PROCESSED_DONE_LIST].
					  pending_req_count);
				status64 = *sc->status_word;
				if (status64 ==  COMPLETION_WORD_INIT) {
					/*FATAL timeout; move sc to zombie list */
					cavium_atomic_inc(&octeon_dev->response_list
						[OCTEON_ZOMBIE_SC_LIST].
						pending_req_count);
					CAVIUM_LIST_ADD_TAIL(&sc->node, &octeon_dev->response_list
						[OCTEON_ZOMBIE_SC_LIST].head);

					cavium_atomic_inc(&octeon_dev->sc_zombie_cnt);
				} else {
					octeon_free_soft_command(octeon_dev, sc);
				}
				
				fcount++;
			}
		}

	}
	cavium_spin_unlock_softirqrestore(&ordered_sc_list->lock);

	lio_dev_dbg(octeon_dev, "%s: fcount=%d\n", __FUNCTION__, fcount);

	return fcount;
}

int octeon_free_sc_zombie_list(struct octeon_device *oct)
{
	struct octeon_soft_command *sc;
	int sc_tmo;
	int count=0;

	if ((sc_tmo = cavium_atomic_read(&oct->response_list[OCTEON_ZOMBIE_SC_LIST].
		pending_req_count)) != 0) {
		struct octeon_response_list *sc_list, *ordered_sc_list;

		ordered_sc_list = &oct->response_list[OCTEON_ORDERED_SC_LIST];
		
		cavium_spin_lock_softirqsave(&ordered_sc_list->lock);
		sc_list = &oct->response_list[OCTEON_ZOMBIE_SC_LIST];
		while (!CAVIUM_LIST_EMPTY(&sc_list->head)) {
			sc = CAVIUM_LIST_FIRST_ENTRY(&sc_list->head,
				struct octeon_soft_command, node);
			CAVIUM_LIST_DEL(&sc->node);
			cavium_atomic_dec(&oct->response_list
				[OCTEON_ZOMBIE_SC_LIST].
				pending_req_count);
			count++;
			octeon_free_soft_command(oct, sc);
		}

		cavium_spin_unlock_softirqrestore(&ordered_sc_list->lock);

		lio_dev_err(oct, "%s: TMO sc count=%d, free sc=%d\n", __FUNCTION__, sc_tmo, count);
	}

	return 0;
}

int octeon_free_sc_buffer_pool(struct octeon_device *oct)
{
	struct cavium_list_head *tmp, *tmp2;
	struct octeon_soft_command *sc;
	int sc_tmo;
	int count=0;

	if (cavium_atomic_read(&oct->response_list[OCTEON_PROCESSED_DONE_LIST].pending_req_count)) {
		lio_dev_err(oct, 
			"%s: oct->response_list[OCTEON_PROCESSED_DONE_LIST].pending_req_count)=%d\n", 
			__FUNCTION__, 
			cavium_atomic_read(&oct->response_list[OCTEON_PROCESSED_DONE_LIST].pending_req_count));
	}
	
	if ((sc_tmo = cavium_atomic_read(&oct->response_list[OCTEON_ZOMBIE_SC_LIST].
		pending_req_count)) != 0) {

		octeon_free_sc_zombie_list(oct);
	}

	cavium_spin_lock_softirqsave(&oct->sc_buf_pool.lock);

	count = 0;
	CAVIUM_LIST_FOR_EACH_SAFE(tmp, tmp2, &oct->sc_buf_pool.head) {
		CAVIUM_LIST_DEL(tmp);

		sc = (struct octeon_soft_command *)tmp;

		lio_dma_free(oct, sc->size, sc, sc->dma_addr);
		count++;
	}

	if (count != MAX_SOFT_COMMAND_BUFFERS)
		lio_dev_err(oct, "octeon_free_sc_buffer_pool: count=%d, MAX_SOFT_COMMAND_BUFFERS=%d\n",
			count, MAX_SOFT_COMMAND_BUFFERS);
	CAVIUM_INIT_LIST_HEAD(&oct->sc_buf_pool.head);

	cavium_spin_unlock_softirqrestore(&oct->sc_buf_pool.lock);

	return 0;
}

struct octeon_soft_command *octeon_alloc_soft_command(struct octeon_device *oct,
						      u32 datasize,
						      u32 rdatasize,
						      u32 ctxsize)
{
	u64 dma_addr;
	u32 size;
	u32 offset = sizeof(struct octeon_soft_command);
	struct octeon_soft_command *sc = NULL;
	struct cavium_list_head *tmp;

	if (rdatasize == 0) {
		rdatasize = 16;
	}

	BUG_ON((offset + datasize + rdatasize + ctxsize) >
	       SOFT_COMMAND_BUFFER_SIZE);

	cavium_spin_lock_softirqsave(&oct->sc_buf_pool.lock);

	if (CAVIUM_LIST_EMPTY(&oct->sc_buf_pool.head)) {
		cavium_spin_unlock_softirqrestore(&oct->sc_buf_pool.lock);
		return NULL;
	}

	CAVIUM_LIST_FOR_EACH(tmp, &oct->sc_buf_pool.head)
		break;

	CAVIUM_LIST_DEL(tmp);

	cavium_atomic_inc(&oct->sc_buf_pool.alloc_buf_count);

	cavium_spin_unlock_softirqrestore(&oct->sc_buf_pool.lock);

	sc = (struct octeon_soft_command *)tmp;

	dma_addr = sc->dma_addr;
	size = sc->size;

	cavium_memset(sc, 0, sc->size);

	sc->dma_addr = dma_addr;
	sc->size = size;

	if (ctxsize) {
		sc->ctxptr = (u8 *)sc + offset;
		sc->ctxsize = ctxsize;
	}

	/* Start data at 128 byte boundary */
	offset = (offset + ctxsize + 127) & 0xffffff80;

	if (datasize) {
		sc->virtdptr = (u8 *)sc + offset;
		sc->dmadptr = dma_addr + offset;
		sc->datasize = datasize;
	}

	/* Start rdata at 128 byte boundary */
	offset = (offset + datasize + 127) & 0xffffff80;

	if (rdatasize) {
		BUG_ON(rdatasize < 16);
		sc->virtrptr = (u8 *)sc + offset;
		sc->dmarptr = dma_addr + offset;
		sc->rdatasize = rdatasize;
		sc->status_word = (u64 *)((u8 *)(sc->virtrptr) + rdatasize - 8);
	}

	return sc;
}

#ifdef LINUX_IPSEC
EXPORT_SYMBOL(octeon_alloc_soft_command);
#endif

void octeon_free_soft_command(struct octeon_device *oct,
			      struct octeon_soft_command *sc)
{
	cavium_spin_lock_softirqsave(&oct->sc_buf_pool.lock);

	CAVIUM_LIST_ADD_TAIL(&sc->node, &oct->sc_buf_pool.head);

	cavium_atomic_dec(&oct->sc_buf_pool.alloc_buf_count);

	cavium_spin_unlock_softirqrestore(&oct->sc_buf_pool.lock);
}

#ifdef LINUX_IPSEC
EXPORT_SYMBOL(octeon_free_soft_command);
#endif
