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
#include "cvmcs-common.h"
#include "cvmcs-nic.h"
#include <cvmx-atomic.h>
#include <cvmx-tim.h>
#include <cavium-list.h>
#include "cvmcs-nic-ether.h"
#include "cvmcs-nic-ip.h"
#include "cvmcs-nic-ipv6.h"
#include "cvmcs-nic-tcp.h"
#include "cvmcs-nic-udp.h"
#include "cvmcs-nic-tunnel.h"
#include "cvmcs-nic-rss.h"
#include "cvmcs-nic-fnv.h"
#include "cvmcs-nic-switch.h"
#include "cvm-nic-ipsec.h"

#ifdef DEBUG
#define print_error(msg, ...)   printf(msg,##__VA_ARGS__)
#define print_debug(msg, ...)   printf(msg,##__VA_ARGS__)
#else
#define print_error(msg, ...)   printf(msg,##__VA_ARGS__)
#define print_debug(msg, ...)
#endif
extern CVMX_SHARED cvm_per_core_stats_t *per_core_stats;

#ifdef FLOW_ENGINE
/**
 *  cvmcs_lro_lut_init - Flow engine look up table init
 */
int
cvmcs_lro_lut_init(cfe_dispatch_entry_t *cfe, hash_node_t  **lut, uint32_t feature)
{
	hash_node_t *hash_table;

	hash_table = hash_table_alloc(LRO_LUT_SIZE);
	if (!hash_table) {
		printf("Error :%s allocating hash_table for:%x \n", __func__, feature);
		return -1;
	}

	*lut = hash_table;
	return 0;
}

#else
/* SHARED HASH TABLE BETWEEN ALL CORES FOR LRO CONTEXT */
CVMX_SHARED struct list_head *lro_hash_table;
#endif

static int
cvmcs_nic_send_gather_list_to_host(cvmx_wqe_t * wqe, int ifidx,
		cvmx_buf_ptr_t *gather_list, int port, int queue,
		int total_size, int bp_credits, cvmx_wqe_t *wqe_list,
		int wqe_list_size)
{
	int ret;
	union octeon_rh *rh;
	cvmx_buf_ptr_t *gather_buf;
	cvmx_pko_command_word0_t    pko_command;
	cvmcs_nic_metadata_t *mdata = CVMCS_NIC_METADATA(wqe);

	gather_buf = (cvmx_buf_ptr_t *)cvmx_phys_to_ptr(gather_list->s.addr);
	rh = (union octeon_rh *)CVM_DRV_GET_PTR(gather_buf[0].s.addr);

        if (OCT_NIC_PORT_VF(ifidx) && (octnic->port[ifidx].user_set_vlanTCI & 0xFFF)) {
                /* The hypervisor had previously set the VLAN tag for this VF via the
                 * "ip link" command.  But the VF driver will not see any VLAN tags.
                 */
        } else {
                rh->r_dh.priority = CVMCS_NIC_METADATA_PRIORITY(mdata);
                rh->r_dh.vlan = CVMCS_NIC_METADATA_VLAN_ID(mdata);
        }

	if (octeon_has_feature(OCTEON_FEATURE_PKO3)) {
		cvmx_pko_send_hdr_t pko_send_hdr;
		cvmx_pko_send_work_t pko_send_work;
		cvmx_pko_buf_ptr_t pko_send_link, *lnkptr;
		cvmx_pko_buf_ptr_t pko_send_gather;
		cvmx_buf_ptr_pki_t *tmp_lptr;
		cvmx_pko_query_rtn_t pko_status;
		uint64_t *jump_buf=NULL;
		uint16_t pko_gaura=0;
		int bufcount, i;
		unsigned node, nwords, dq;
		unsigned scr_base;
		unsigned iphdrlen;

		if (wqe_list_size > 0) {
			cvmcs_nic_metadata_t *tmp_mdata = CVMCS_NIC_METADATA(wqe_list);
			tmp_lptr = (cvmx_buf_ptr_pki_t *)&wqe_list->packet_ptr;
			/* We have wqe_data[0] available. mdata starts at wqe_data[1] */
		 	*(((uint64_t *)&tmp_mdata->front) - 1) = tmp_lptr->u64;
			tmp_lptr->u64 = 0;
			tmp_lptr->addr = CVM_DRV_GET_PHYS(&tmp_mdata->front);
			tmp_lptr->size = tmp_mdata->front_size;

			cvmx_wqe_set_bufs(wqe_list, cvmx_wqe_get_bufs(wqe_list) + 1);
			cvmx_wqe_set_len(wqe_list, (cvmx_wqe_get_len(wqe_list) + tmp_mdata->front_size));

			tmp_mdata->front.irh.s.opcode = OPCODE_NIC;
			tmp_mdata->front.irh.s.subcode = OCT_NIC_LRO_COMPLETION_OP;
			tmp_mdata->front.ossp[1] = wqe_list_size;
			((cvmx_wqe_78xx_t *)wqe_list)->word2.software = 1;
		}

		scr_base = cvmx_pko3_lmtdma_scr_base();

		/* Separa global DQ# into node and local DQ */
		dq = queue;
		node = dq >> 10;
		dq &= (1 << 10)-1;

		pko_send_hdr.u64 = 0;
		pko_send_hdr.s.total = total_size;
		pko_send_hdr.s.aura = cvmx_wqe_get_aura(wqe);
		pko_send_hdr.s.l3ptr = gather_buf[0].s.size + ETH_HLEN;
		
#ifdef VSWITCH
		//Vlan offload is not supported for VFs for now. So consider vlan size.
		//Note: for PFs it is supported, so check if metadata has vlan data.
		//If not, consider vlan length
		if(CVMCS_NIC_METADATA_IS_VLAN(mdata) && !CVMCS_NIC_METADATA_VLAN_TCI(mdata))
			pko_send_hdr.s.l3ptr = gather_buf[0].s.size + VLAN_ETH_HLEN;
#endif //VSWITCH

		if (CVMCS_NIC_METADATA_IS_PTP_HEADER(mdata)) {
			pko_send_hdr.s.l3ptr += OCTNET_FRM_PTP_HEADER_SIZE;
		}

		if (CVMCS_NIC_METADATA_IS_IPV4(mdata)) {
			struct iphdr *iph4 = (struct iphdr *)((uint8_t *)cvmx_phys_to_ptr(gather_buf[1].s.addr) + pko_send_hdr.s.l3ptr - gather_buf[0].s.size);
			pko_send_hdr.s.ckl3 = 1;
			iphdrlen = iph4->ihl << 2;
		} else {
			iphdrlen = 40;
		}

		pko_send_hdr.s.l4ptr = pko_send_hdr.s.l3ptr + iphdrlen;

		if (OCTEON_IS_MODEL(OCTEON_CN78XX_PASS1_X)) {
			/* see section 2.2.10.5.1 of "OCTEON II CN78XX Known Issues" version 1.11 */
			pko_send_hdr.s.ckl4 = 0;
		} else {
			pko_send_hdr.s.ckl4 = CKL4ALG_TCP;

			if (CVMCS_NIC_METADATA_IS_TUNNEL(mdata)) {
				if (CVMCS_NIC_METADATA_IS_INNER_IPV4(mdata)) {
					pko_send_hdr.s.l3ptr = pko_send_hdr.s.l3ptr + CVMCS_NIC_METADATA_INNER_L3_OFFSET(mdata) - ETH_HLEN; 
					pko_send_hdr.s.ckl3 = 1;
				} else {
					pko_send_hdr.s.ckl3 = 0;
				}

				if (CVMCS_NIC_METADATA_IS_INNER_TCP(mdata)) {
					pko_send_hdr.s.l4ptr = pko_send_hdr.s.l3ptr + CVMCS_NIC_METADATA_INNER_L4_OFFSET(mdata) - CVMCS_NIC_METADATA_INNER_L3_OFFSET(mdata);
					pko_send_hdr.s.ckl4 = CKL4ALG_TCP;
				} else if (CVMCS_NIC_METADATA_IS_INNER_UDP(mdata)) {
					pko_send_hdr.s.l4ptr = pko_send_hdr.s.l3ptr + CVMCS_NIC_METADATA_INNER_L4_OFFSET(mdata) - CVMCS_NIC_METADATA_INNER_L3_OFFSET(mdata);
					pko_send_hdr.s.ckl4 = CKL4ALG_UDP;
				} else {
					pko_send_hdr.s.ckl4 = 0;
				}

			}

		}

		nwords = 0;
		cvmx_scratch_write64(scr_base+sizeof(uint64_t)*(nwords++), pko_send_hdr.u64);

		if (wqe_list_size > 0) {

			bufcount = gather_list->s.size;
			if (bufcount > ((wqe_list_size > 0) ? 13 : 14)) {
                        	cvmx_pko_buf_ptr_t jump_s;
                        	cvmx_fpa3_gaura_t aura;
                        	unsigned fpa_node = cvmx_get_node_num();

                        	/* Allocate jump buffer from PKO internal FPA AURA, size=4KiB */
                        	pko_gaura = __cvmx_pko3_aura_get(fpa_node);
                        	aura = __cvmx_fpa3_gaura(pko_gaura >> 10, pko_gaura & 0x3ff);

                        	jump_buf = cvmx_fpa3_alloc(aura);
                        	if (jump_buf == NULL) {
                                	print_debug("error unable to alloc jump buffer \n");
                                	//packet will be freed by caller
                                	return 1;
                        	}
                        	jump_s.u64 = 0;
                        	jump_s.s.addr = cvmx_ptr_to_phys(jump_buf);
                        	jump_s.s.i = 1;
                        	// the extra one is for aura
                        	jump_s.s.size = bufcount + ((wqe_list_size > 0) ? 1 : 0) + 1;
                        	jump_s.s.subdc3 = CVMX_PKO_SENDSUBDC_JUMP;
                        	cvmx_scratch_write64(scr_base+sizeof(uint64_t)*(nwords++), jump_s.u64);
			}

			pko_send_gather.u64 = 0;
			pko_send_gather.s.subdc3 = CVMX_PKO_SENDSUBDC_GATHER;

			for (i = 0; i < bufcount; i++) {
				pko_send_gather.s.size = gather_buf[i].s.size;
				pko_send_gather.s.addr = gather_buf[i].s.addr;
				pko_send_gather.s.i = gather_buf[i].s.i;
				if (jump_buf)
					jump_buf[i] = pko_send_gather.u64;
				else
					cvmx_scratch_write64(scr_base+sizeof(uint64_t)*(nwords++), pko_send_gather.u64);
			}

			if (wqe_list_size > 0) {
				pko_send_work.u64 = 0;
				pko_send_work.s.subdc4 = CVMX_PKO_SENDSUBDC_WORK;
				pko_send_work.s.addr = cvmx_ptr_to_phys(wqe_list);
				pko_send_work.s.grp = cvmx_wqe_get_grp(wqe_list);
				pko_send_work.s.tt = cvmx_wqe_get_tt(wqe_list);
				if (jump_buf)
					jump_buf[i++] = pko_send_work.u64;
				else
					cvmx_scratch_write64(scr_base+sizeof(uint64_t)*(nwords++), pko_send_work.u64);
			}

                	if (jump_buf) {
                        	cvmx_pko_send_aura_t aura_s;
                        	aura_s.u64=0;
                        	aura_s.s.aura = pko_gaura;
                        	aura_s.s.offset = 0;
                        	aura_s.s.alg = AURAALG_NOP;
                        	aura_s.s.subdc4 = CVMX_PKO_SENDSUBDC_AURA;
                        	jump_buf[i] = aura_s.u64;
                	}
		} else {
			pko_send_link.u64 = 0;
			pko_send_link.s.subdc3 = CVMX_PKO_SENDSUBDC_LINK;

			bufcount = gather_list->s.size;

			lnkptr = &pko_send_link;

			for (i = 0; i < bufcount; i++) {
				lnkptr->s.size = gather_buf[i].s.size;
				lnkptr->s.addr = gather_buf[i].s.addr;
				lnkptr->s.i = gather_buf[i].s.i;
				lnkptr = (cvmx_pko_buf_ptr_t *)CVM_DRV_GET_PTR(lnkptr->s.addr - 8);
				lnkptr->u64 = 0;
			}

			cvmx_scratch_write64(scr_base+sizeof(uint64_t)*(nwords++), pko_send_link.u64);
		}

		CVMX_SYNCWS;

		pko_status = cvmcs_pko3_lmtdma(node, dq, nwords, false, false);

		switch (pko_status.s.dqstatus) {
		case PKO_DQSTATUS_PASS:
			cvmx_fpa_free(cvmx_phys_to_ptr(gather_list->s.addr), CVMX_FPA_GATHER_LIST_POOL, 0);
			ret = CVMX_PKO_SUCCESS;
			break;

		case PKO_DQSTATUS_ALREADY:
			ret = CVMX_PKO_PORT_ALREADY_SETUP;
			break;

		case PKO_DQSTATUS_NOFPABUF:
		case PKO_DQSTATUS_NOPKOBUF:
			ret = CVMX_PKO_NO_MEMORY;
			break;

		case PKO_DQSTATUS_NOTCREATED:
			ret = CVMX_PKO_INVALID_QUEUE;
			break;

		case PKO_DQSTATUS_BADSTATE:
			ret = CVMX_PKO_CMD_QUEUE_INIT_ERROR;
			break;

		default:
			ret = CVMX_PKO_INVALID_PORT;
			break;
		}

	} else {

		mdata->front.irh.s.opcode = OPCODE_NIC;
		mdata->front.irh.s.subcode = OCT_NIC_LRO_COMPLETION_OP;
		mdata->front.ossp[0] = (uint64_t)wqe_list;
		mdata->front.ossp[1] = (bp_credits << 16) | wqe_list_size;
		cvmx_wqe_set_soft(wqe, 1);


		if (octeon_has_feature(OCTEON_FEATURE_PKND))
			cvmx_pko_send_packet_prepare_pkoid(port, queue, 1);
		else
			cvmx_pko_send_packet_prepare(port, queue, 1);

		pko_command.u64           = 0;
		pko_command.s.ignore_i    = 0;
		pko_command.s.dontfree    = 0;

		pko_command.s.gather      = 1;
		pko_command.s.segs        = gather_list->s.size;
		pko_command.s.total_bytes = total_size;
		pko_command.s.ipoffp1	  = OCT_RH_SIZE + 8 + ETH_HLEN + 1;

		if (CVMCS_NIC_METADATA_IS_PTP_HEADER(mdata)) {
			pko_command.s.ipoffp1	  += OCTNET_FRM_PTP_HEADER_SIZE;
		}

		//BP credits
		pko_command.s.wqp = 1;
		pko_command.s.rsp = 1;

		if (octeon_has_feature(OCTEON_FEATURE_PKND)) {
			CVMX_SYNCWS;
			ret = cvmx_pko_send_packet_finish3_pkoid(port, queue,
					pko_command, *gather_list,
					cvmx_ptr_to_phys(wqe), 1);
		} else {
			CVMX_SYNCWS;
			ret = cvmx_pko_send_packet_finish3(port, queue,
					pko_command, *gather_list,
					cvmx_ptr_to_phys(wqe), 1);
		}
	}

	return ret;
}

static inline void
add_lro_context(lro_context_t *lro_ctx, uint16_t hash)
{
#ifdef FLOW_ENGINE
	cfe_lut_insert(&lro_ctx->list, (hash & LRO_TAG_MASK), lro_ctx->ifidx, CFE_DEFAULT_OP);
#else
	cavium_list_add_tail(&lro_ctx->list, &lro_hash_table[hash]);
#endif
}

static inline lro_context_t *
alloc_lro_context(cvmx_wqe_t *wqe, lro_context_t *temp_ctx)
{
	cvmcs_nic_metadata_t *mdata = CVMCS_NIC_METADATA(wqe);
	lro_context_t *lro_ctx = NULL;
	int32_t *port_lro_used = NULL;
	int32_t *lro_ctx_cnt = NULL;

	if (CVMCS_NIC_METADATA_IS_PACKET_FROM_GMX(mdata)) {
		port_lro_used = &octnic->gmx_port_info[mdata->gmx_id].lro_pkt_cnt;
		lro_ctx_cnt = &octnic->gmx_port_info[mdata->gmx_id].lro_ctx_cnt;
		if (cvmx_atomic_get32(port_lro_used) > MAX_LRO_PACKETS_PER_GMX) {
			DBG2("ERROR: LRO context allocation failed; max LRO buffer limit reached.\n");
			return NULL;
		}
		if (cvmx_atomic_get32(lro_ctx_cnt) >= MAX_LRO_CTX_PER_GMX) {
			DBG2("ERROR: LRO context allocation failed; max LRO context limit reached.\n");
			return NULL;
		}
	}

	lro_ctx = cvmx_fpa_alloc(CVMX_FPA_LRO_CONTEXT_POOL);
	if (NULL == lro_ctx) {
		printf("ERR : LRO CONTEXT ALLOC FAILED\n");
		return NULL;
	}

	memset(lro_ctx, 0, sizeof(lro_context_t));

	*lro_ctx = *temp_ctx;

	add_lro_context(lro_ctx, (cvmx_wqe_get_tag(wqe) & LRO_TAG_MASK));

	/* limit the buffers used for LRO on each BGX port; this is not required
	 * for LRO on DPI functions (VF to VF, VF to PF, or PF to VF) as the
	 * number of buffers used for LRO on these paths are automatically
	 * limited by the DPI queue's AURA limits which are already low (256)
	 */
	if (CVMCS_NIC_METADATA_IS_PACKET_FROM_GMX(mdata))
	{
		/* for quick access in every LRO packet processing,
		 * save the reference to total buffers and context used by
		 * corresponding source BGX port
		 * these are later used to limit max buffers used for LRO
		 */
		lro_ctx->port_lro_used = port_lro_used;
		lro_ctx->lro_ctx_cnt = lro_ctx_cnt;
		cvmx_atomic_add32(lro_ctx->port_lro_used, 1);
		cvmx_atomic_add32(lro_ctx->lro_ctx_cnt, 1);
	}

	return lro_ctx;
}

static inline void
remove_lro_context(lro_context_t *lro_ctx)
{
#ifdef FLOW_ENGINE
	cfe_lut_del(&lro_ctx->list, lro_ctx->ifidx, CFE_DEFAULT_OP);
#else
	cavium_list_del(&lro_ctx->list);
#endif
}

static inline void
free_lro_context(lro_context_t *lro_ctx)
{
	remove_lro_context(lro_ctx);
	if (lro_ctx->port_lro_used && lro_ctx->packet_cnt) {
		/* reclaim the flushed LRO buffers to Rx port's used LRO buffer
		 * count, and update LRO context count
		 */
		cvmx_atomic_add32(lro_ctx->port_lro_used, -lro_ctx->packet_cnt);
		lro_ctx->port_lro_used = NULL;
		cvmx_atomic_add32(lro_ctx->lro_ctx_cnt, -1);
		lro_ctx->lro_ctx_cnt = NULL;
	}

	if (!lro_ctx->timer_pending) {
		cvmx_fpa_free(lro_ctx, CVMX_FPA_LRO_CONTEXT_POOL, 0);
	}
}

static inline int
lro_tot_len(lro_context_t *lro_ctx)
{
	uint32_t tot_len = 0;
	struct iphdr *iph4 = NULL;
	struct ipv6hdr *iph6 = NULL;
        cvmcs_nic_metadata_t *mdata = CVMCS_NIC_METADATA(lro_ctx->wqe);

	if (lro_ctx->is_v6)
		iph6 = (struct ipv6hdr *) lro_ctx->iphdr;
	else
		iph4 = (struct iphdr *) lro_ctx->iphdr;

	tot_len = OCT_RH_SIZE + 8 + ETH_HLEN;

	if (CVMCS_NIC_METADATA_IS_PTP_HEADER(mdata))
		tot_len += OCTNET_FRM_PTP_HEADER_SIZE;

	tot_len += lro_ctx->is_v6 ? (iph6->payload_len + 40): iph4->tot_len;


	if (CVMCS_NIC_METADATA_IS_TUNNEL(mdata)) {
		tot_len += ((CVMCS_NIC_METADATA_IS_INNER_VLAN(mdata)) ? VLAN_HLEN : 0);
		tot_len += CVMCS_NIC_METADATA_TUNNEL_HEADER_LENGTH(mdata);
	}

	return tot_len;
}

static inline void
lro_update_header(lro_context_t *lro_ctx)
{
	struct iphdr *iph4 = NULL, *outer_iph4 = NULL;
	struct ipv6hdr *iph6 = NULL, *outer_iph6 = NULL;
	struct tcphdr *tcp = NULL;
	uint32_t *tsptr = NULL, tcp_opt_len = 0;
        cvmcs_nic_metadata_t *mdata = CVMCS_NIC_METADATA(lro_ctx->wqe);

	if (lro_ctx->is_v6)
		iph6 = (struct ipv6hdr *) lro_ctx->iphdr;
	else
		iph4 = (struct iphdr *) lro_ctx->iphdr;

	tcp = lro_ctx->tcp;
	tcp_opt_len = (tcp->doff << 2) - sizeof(*tcp);

	/* MODIFY TOTAL LENGTH IN IP */
	if (lro_ctx->is_v6)
		iph6->payload_len = (tcp->doff << 2) + lro_ctx->tcp_data_len;
	else
		iph4->tot_len = (iph4->ihl << 2) + (tcp->doff << 2) + lro_ctx->tcp_data_len;

	if (!octeon_has_feature(OCTEON_FEATURE_PKO3)) {
		/* RECALCULATE IP CHECKSUM FOR IPV4 HDR */
		if (!lro_ctx->is_v6)
			cvmcs_nic_ip_header_checksum(iph4, &iph4->check);
	}

	/* UPDATE TCP ACK */
	tcp->ack_seq = lro_ctx->ack_seq;
	tcp->window  = lro_ctx->window;

	/* Update TCP timestamps */
	if (0 != tcp_opt_len) {
		tsptr = (uint32_t *)(tcp+1);
		*(tsptr+1) = lro_ctx->tsval;
		*(tsptr+2) = lro_ctx->tsecr;
	}

	/* UPDATE PUSH FLAG */
	if (lro_ctx->is_psh)
		tcp->psh = 1;

	/* UPDATE TUNNEL FRAME */
	if (CVMCS_NIC_METADATA_IS_TUNNEL(mdata)) {
		if (CVMCS_NIC_METADATA_IS_IPV4(mdata)) {
			outer_iph4 = (struct iphdr *)CVMCS_NIC_METADATA_L3_HEADER(mdata);
			/* ADD UPTO INNER L3 PAYLOAD */
			outer_iph4->tot_len = lro_ctx->is_v6 ? iph6->payload_len + 40 : iph4->tot_len;

			outer_iph4->tot_len += CVMCS_NIC_METADATA_INNER_L3_OFFSET(mdata) - CVMCS_NIC_METADATA_L3_OFFSET(mdata);

			//calculate outer ip checksum
			cvmcs_nic_ip_header_checksum(outer_iph4, &outer_iph4->check);

		}
		else {
			outer_iph6 = (struct ipv6hdr *)CVMCS_NIC_METADATA_L3_HEADER(mdata);
			/* ADD UPTO INNER L3 PAYLOAD */
			outer_iph6->payload_len = lro_ctx->is_v6 ? iph6->payload_len + 40 : iph4->tot_len;

			outer_iph6->payload_len += CVMCS_NIC_METADATA_INNER_L3_OFFSET(mdata) - CVMCS_NIC_METADATA_L3_OFFSET(mdata);
			outer_iph6->payload_len -= sizeof(struct ipv6hdr);
		}

		if (CVMCS_NIC_METADATA_IS_UDP(mdata)) {
			struct udphdr *udph = (struct udphdr *)CVMCS_NIC_METADATA_L4_HEADER(mdata);
			udph->len = (CVMCS_NIC_METADATA_IS_IPV6(mdata)) ? outer_iph6->payload_len :
						(outer_iph4->tot_len - (outer_iph4->ihl << 2));
			udph->check = 0;
		}
	}
}

void
cvmcs_nic_flush_lro(cvmx_wqe_t *orig_wqe, lro_context_t *lro_ctx, int del_timer)
{
	cvmx_buf_ptr_t *glist_ptr = NULL;
	int32_t  port, queue, rxq, rxq_idx, i;
	vnic_port_info_t *nicport =  NULL;
	cvmx_wqe_t *wqe = lro_ctx->wqe;
	uint32_t hash = (uint32_t)-1, *hash_ptr = NULL;
	uint32_t hashtype = 0;
	union octeon_rh *rh;
	ipsec_rx_info_t ipsec_rx_info;
        cvmcs_nic_metadata_t *mdata = CVMCS_NIC_METADATA(lro_ctx->wqe);

	print_debug("\nGOT THE CONTEXT : %p APPEND COUNT : %d\n", lro_ctx, lro_ctx->append_cnt);

	if (del_timer == 1 ) {
		if (CVMX_TIM_STATUS_BUSY == cvmx_tim_delete_entry(&lro_ctx->delete_info)) {
			/* LET THE TIMER FREE THE CONTEXT */
			lro_ctx->timer_pending = 1;
		}
		else {
			cvmcs_wqe_free(lro_ctx->timer_wqe);
		}
	}
	else {
		if ( lro_ctx->timer_pending ) {
			cvmx_pow_tag_sw_null();
			cvmx_fpa_free(lro_ctx, CVMX_FPA_LRO_CONTEXT_POOL, 0);
			return;
		}
	}

	/* DETACH LRO CONTEXT FROM HASH BUCKET */
	/* remove_lro_context(lro_ctx); */
	/* lro_tag_sw_order(wqe); */

	nicport = &octnic->port[lro_ctx->ifidx];
	glist_ptr = (cvmx_buf_ptr_t *) cvmx_phys_to_ptr(lro_ctx->gather_list.s.addr);

	if (lro_ctx->packet_cnt > 1) {
		lro_update_header(lro_ctx);
		if (CVMCS_NIC_METADATA_IS_PTP_HEADER(mdata))
			*((uint64_t *) cvmx_phys_to_ptr(glist_ptr[1].s.addr)) = lro_ctx->ptp_ts;
	}

	/* rtf TODO: append DUP Ack count to support Windows RSC packet indications.
     * This could be done using the 'r_dh.extra' field in the receive hdr. */

	/* Fill no of entries in gather list */
	lro_ctx->gather_list.s.size = lro_ctx->append_cnt;
	print_debug("lro_ctx->gather_list.s.size: %d \n", lro_ctx->gather_list.s.size);

	if (!nicport->state.rx_on) {
		print_error("[%s]ERROR: RX STATE IS OFF\n", __FUNCTION__);
		per_core_stats[cvmx_get_core_num()].link_stats[lro_ctx->ifidx].fromwire.fw_err_drop += 1;
		for (i = 1; i < lro_ctx->gather_list.s.size; i++) {
			if (OCTEON_IS_OCTEON3())
				cvmx_fpa_free(cvmx_phys_to_ptr(glist_ptr[i].s.addr),
				      cvmx_wqe_get_aura(wqe), 0);
			else
				cvmx_fpa_free(cvmx_phys_to_ptr(glist_ptr[i].s.addr),
				      CVMX_FPA_PACKET_POOL, 0);
		}
		cvmx_fpa_free(glist_ptr, CVMX_FPA_GATHER_LIST_POOL, 0);
		cvm_update_bp_port(cvmx_wqe_get_port(wqe), lro_ctx->bp_credits);
		free_lro_context(lro_ctx);
		CVMX_SYNCWS;
		cvmx_pow_tag_sw_null();
		if (!OCTEON_IS_OCTEON3())
			cvmx_wqe_free(wqe);
		return;
	}

	rh = (union octeon_rh *)CVM_DRV_GET_PTR(glist_ptr[0].s.addr);
	hash_ptr = (uint32_t *)(rh + 1);

	if (nicport->state.rss_on) {
		rxq_idx = cvmcs_nic_rss_get_queue(wqe, &hash, &hashtype, lro_ctx->ifidx);
		if (-1 == rxq_idx) {
			rxq_idx = (cvmx_wqe_get_tag(wqe) % (nicport->linfo.num_rxpciq));
#if defined(USE_CUSTOM_OQ)
			rxq_idx = 0;
#endif
		}
	}
	else if (nicport->state.fnv_on) {
		rxq_idx = cvmcs_nic_fnv_get_queue(wqe, &hash, lro_ctx->ifidx);
		if (-1 == rxq_idx) {
			rxq_idx = (cvmx_wqe_get_tag(wqe) % (nicport->linfo.num_rxpciq));
#if defined(USE_CUSTOM_OQ)
			rxq_idx = 0;
#endif
		}
	}
	else {
		hash = cvmx_wqe_get_tag(wqe);
		if (nicport->pkt_steering_enable && CVMCS_NIC_METADATA_IS_TCP(mdata))
			rxq_idx = get_queue_from_pkt_steering_table(nicport, wqe);
		else
			rxq_idx = (cvmx_wqe_get_tag(wqe) % (nicport->linfo.num_rxpciq));
#if defined(USE_CUSTOM_OQ)
		rxq_idx = 0;
#endif
	}

	rxq = OCT_NIC_OQ_NUM(nicport, rxq_idx);

	{
		*hash_ptr = hash;
		*(hash_ptr + 1) = hashtype;
		rh->r_dh.has_hash = 0x1; /* indicate hash */
		rh->r_dh.len += 1;
		glist_ptr[0].s.size += 8;
	}

	DBG("%s: hash 0x%x, rxq = %d\n", __func__, hash, rxq);

        /* Using extra to show IPSec status */
        ipsec_rx_info.u32 = 0;
        ipsec_rx_info.s.status = (CVMCS_NIC_METADATA_IS_IPSEC(mdata) & nicport->state.ipsecv2_ah_esp) ? 0 : -1;
        if (CVMCS_NIC_METADATA_IS_IPSEC_ESP(mdata)) {
                ipsec_rx_info.s.esp_pad_length = CVMCS_NIC_METADATA_IPSEC_ESP_PAD_LEN(mdata);
                ipsec_rx_info.s.esp_next_hdr = CVMCS_NIC_METADATA_IPSEC_NEXT_PROTO(mdata);
		ipsec_rx_info.s.esp_info_set = 1;
        }
        rh->r_dh.extra = ipsec_rx_info.u32 & 0x0fffffff;

	port  = cvm_pci_get_oq_pkoport(rxq);
	queue = cvm_pci_get_oq_pkoqueue(rxq);

	if (cvmx_unlikely(port == -1 || queue == -1)) {
		print_error("[%s]ERROR: PORT/QUEUE = -1\n", __FUNCTION__);
		per_core_stats[cvmx_get_core_num()].link_stats[lro_ctx->ifidx].fromwire.fw_err_drop += 1;
		for (i = 1; i < lro_ctx->gather_list.s.size; i++) {
			if (octeon_has_feature(OCTEON_FEATURE_CN78XX_WQE))
				cvmx_fpa_free(cvmx_phys_to_ptr(glist_ptr[i].s.addr),
				      cvmx_wqe_get_aura(wqe), 0);
			else
				cvmx_fpa_free(cvmx_phys_to_ptr(glist_ptr[i].s.addr),
				      CVMX_FPA_PACKET_POOL, 0);
		}
		cvmx_fpa_free(glist_ptr, CVMX_FPA_GATHER_LIST_POOL, 0);
		cvm_update_bp_port(cvmx_wqe_get_port(wqe), lro_ctx->bp_credits);
		free_lro_context(lro_ctx);
		//lro_tag_sw_order(wqe);
		CVMX_SYNCWS;
		cvmx_pow_tag_sw_null();
		if (!octeon_has_feature(OCTEON_FEATURE_CN78XX_WQE))
			cvmx_wqe_free(wqe);
		return;
	}

	{
		cvmx_buf_ptr_t gather_list;
		uint32_t tot_len = lro_tot_len(lro_ctx);
		uint32_t bp_credits = lro_ctx->bp_credits;
		cvmx_wqe_t *wqe_list = lro_ctx->wqe_list;
		int wqe_list_size = lro_ctx->wqe_list_size;
		int idx = lro_ctx->ifidx;
		gather_list.u64 = lro_ctx->gather_list.u64;

		free_lro_context(lro_ctx);
		CVMX_SYNCWS;
		lro_tag_sw_order(orig_wqe);
		//cvmx_pow_tag_sw_null();

		if (cvmcs_nic_send_gather_list_to_host(wqe, idx, &gather_list,
				port, queue, tot_len, bp_credits,
				wqe_list, wqe_list_size)) {
			print_error("[%s]ERROR: SEND TO PKO FAILED\n", __FUNCTION__);
			per_core_stats[cvmx_get_core_num()].link_stats[idx].fromwire.fw_err_drop += 1;
			for (i = 1; i < gather_list.s.size; i++) {
				if (octeon_has_feature(OCTEON_FEATURE_CN78XX_WQE))
					cvmx_fpa_free(cvmx_phys_to_ptr(glist_ptr[i].s.addr),
					      cvmx_wqe_get_aura(wqe), 0);
				else
					cvmx_fpa_free(cvmx_phys_to_ptr(glist_ptr[i].s.addr),
					      CVMX_FPA_PACKET_POOL, 0);
			}
			cvmx_fpa_free(glist_ptr, CVMX_FPA_GATHER_LIST_POOL, 0);
			cvm_update_bp_port(cvmx_wqe_get_port(wqe), bp_credits);
			if (!octeon_has_feature(OCTEON_FEATURE_CN78XX_WQE))
				cvmx_wqe_free(wqe);
			return;
		}

		per_core_stats[cvmx_get_core_num()].link_stats[idx].fromwire.fw_total_lro += 1;
		per_core_stats[cvmx_get_core_num()].perq_stats[idx].fromwire.fw_total_fwd[rxq_idx] += 1;
		per_core_stats[cvmx_get_core_num()].perq_stats[idx].fromwire.fw_total_fwd_bytes[rxq_idx] += tot_len;
	}
}


static inline int
cvmcs_nic_set_lro_timer(lro_context_t *lro_ctx)
{
	cvmx_wqe_t *timer_work;
	cvmx_raw_inst_front_t *front;
	cvmx_tim_delete_t *delete_info;
	uint64_t tim = (LRO_TIMER_TICKS_MS);

	timer_work = cvmcs_wqe_alloc();
	if(NULL == timer_work) {
		print_error("timer_work alloc failed \n");
		return -1;
	}

	lro_ctx->timer_wqe = timer_work;

	if (octeon_has_feature(OCTEON_FEATURE_CN78XX_WQE)) {
		cvmx_wqe_78xx_t *wqe_o3 = (cvmx_wqe_78xx_t *)timer_work;
		front = (cvmx_raw_inst_front_t *)wqe_o3->wqe_data;
		wqe_o3->packet_ptr.packet_outside_wqe = 0;
		wqe_o3->packet_ptr.addr = cvmx_ptr_to_phys(front);
		wqe_o3->word0.bufs = 0;
		wqe_o3->word0.aura = cvmcs_wqe_pool();
	} else {
		front = (cvmx_raw_inst_front_t *)timer_work->packet_data;
	}

	memset(front, 0, sizeof(cvmx_raw_inst_front_t));
	front->irh.s.opcode = OPCODE_NIC;
	front->irh.s.subcode = OCT_NIC_LRO_TIMER_OP;
	front->ossp[0] =  (uint64_t)lro_ctx;
	cvmx_wqe_set_soft(timer_work, 1);

	cvmx_wqe_set_qos(timer_work, 1);
	cvmx_wqe_set_tt(timer_work, CVMX_POW_TAG_TYPE_ATOMIC);
	cvmx_wqe_set_tag(timer_work, (cvmx_wqe_get_tag(lro_ctx->wqe) & LRO_TAG_MASK));
	cvmx_wqe_set_grp(timer_work, cvmx_wqe_get_grp(lro_ctx->wqe));

	delete_info = (cvmx_tim_delete_t *)&lro_ctx->delete_info;
	CVMX_SYNCWS;
	if (cvmx_tim_add_entry(timer_work, tim, delete_info) !=
	    CVMX_TIM_STATUS_SUCCESS) {
		print_error("timer add failed\n");
		cvmcs_wqe_free(timer_work);
		return -1;
	}
	return 0;
}

static inline bool
tcp_flow_match_ipv4_headers(struct iphdr *iph4, struct iphdr *temp_iph4)
{
	/* MATCH SOURCE ADDR AND DEST ADDR */
	if ( iph4->saddr != temp_iph4->saddr ||
		 iph4->daddr != temp_iph4->daddr)
		return false;

	return true;
}

static inline bool
tcp_flow_match_ipv6_headers(struct ipv6hdr *iph6, struct ipv6hdr *temp_iph6)
{
	int i;

	/* MATCH SOURCE ADDR */
	for (i=0; i<4; ++i) {
		if (iph6->saddr.s6_addr32[i] != temp_iph6->saddr.s6_addr32[i])
			return false;
	}

	/* MATCH DEST ADDR */
	for (i=0; i<4; ++i) {
		if (iph6->daddr.s6_addr32[i] != temp_iph6->daddr.s6_addr32[i])
			return false;
	}

	return true;
}

static inline bool
tcp_flow_match_tcp_headers(struct tcphdr *tcp, struct tcphdr *temp_tcp)
{
	/* CHECK TCP HEADER */
	if ((tcp->source != temp_tcp->source) || (tcp->dest != temp_tcp->dest)) {
		print_debug("TCP HDR MATCH FAILED\n");
		return false;
	}

	return true;
}

static inline bool
tcp_flow_match(cvmx_wqe_t *wqe, lro_context_t *lro_ctx, lro_context_t *temp_ctx)
{
        cvmcs_nic_metadata_t *mdata = CVMCS_NIC_METADATA(lro_ctx->wqe);
        cvmcs_nic_metadata_t *temp_mdata = CVMCS_NIC_METADATA(wqe);
	
	/* Match outer Vlans */
	if (CVMCS_NIC_METADATA_VLAN_TCI(temp_mdata) != CVMCS_NIC_METADATA_VLAN_TCI(mdata))
		return false;

	/* Check outer ip headers */
	if (CVMCS_NIC_METADATA_IS_IPV4(temp_mdata)) {
		if ((!CVMCS_NIC_METADATA_IS_IPV4(mdata)) ||
		    (tcp_flow_match_ipv4_headers(
			(struct iphdr *)CVMCS_NIC_METADATA_L3_HEADER(temp_mdata),
			(struct iphdr *)CVMCS_NIC_METADATA_L3_HEADER(mdata)) == false))
			return false;
	} else {
		if ((!CVMCS_NIC_METADATA_IS_IPV6(mdata)) ||
		    (tcp_flow_match_ipv6_headers(
			(struct ipv6hdr *)CVMCS_NIC_METADATA_L3_HEADER(temp_mdata),
			(struct ipv6hdr *)CVMCS_NIC_METADATA_L3_HEADER(mdata)) == false))
			return false;
	}

	/* Check if tunnel present */
	if (CVMCS_NIC_METADATA_IS_TUNNEL(temp_mdata) ^ CVMCS_NIC_METADATA_IS_TUNNEL(mdata))
		return false;

	/* CHECK FOR TUNNEL FRAME */
	if (CVMCS_NIC_METADATA_IS_TUNNEL(temp_mdata)) {

		if (CVMCS_NIC_METADATA_INNER_VLAN_TCI(temp_mdata) !=
		    CVMCS_NIC_METADATA_INNER_VLAN_TCI(mdata))
				return false;

		/* Check outer ip headers */
		if (CVMCS_NIC_METADATA_IS_INNER_IPV4(temp_mdata)) {
			if ((!CVMCS_NIC_METADATA_IS_INNER_IPV4(mdata)) ||
		    	    (tcp_flow_match_ipv4_headers(
				(struct iphdr *)CVMCS_NIC_METADATA_INNER_L3_HEADER(temp_mdata),
				(struct iphdr *)CVMCS_NIC_METADATA_INNER_L3_HEADER(mdata)) == false))
				return false;
		} else {
			if ((!CVMCS_NIC_METADATA_IS_INNER_IPV6(mdata)) ||
		    	    (tcp_flow_match_ipv6_headers(
				(struct ipv6hdr *)CVMCS_NIC_METADATA_INNER_L3_HEADER(temp_mdata),
				(struct ipv6hdr *)CVMCS_NIC_METADATA_INNER_L3_HEADER(mdata)) == false))
				return false;
		}

		if (lro_ctx->vni != temp_ctx->vni)
			return false;

		return tcp_flow_match_tcp_headers(
				(struct tcphdr *)CVMCS_NIC_METADATA_INNER_L4_HEADER(mdata),
				(struct tcphdr *)CVMCS_NIC_METADATA_INNER_L4_HEADER(temp_mdata));
	} else {

		return tcp_flow_match_tcp_headers(
				(struct tcphdr *)CVMCS_NIC_METADATA_L4_HEADER(mdata),
				(struct tcphdr *)CVMCS_NIC_METADATA_L4_HEADER(temp_mdata));
	}
}

#ifdef FLOW_ENGINE    
uint32_t
cvmcs_lro_flow_compare(void *ctx, hash_node_t *node)
{   
	lro_context_t *tmp, *lro_ctx = ctx;

	tmp = (lro_context_t *) hlist_entry(node, lro_context_t, list);
	if (tcp_flow_match(NULL, lro_ctx, tmp))
		return 1;

	return 0;
}
#endif


static inline lro_context_t *
find_lro_ctx(cvmx_wqe_t *wqe, lro_context_t *temp_ctx, uint32_t ifidx)
{
#ifdef FLOW_ENGINE
	struct hash_node *tmp = NULL;
#else
	struct list_head *tmp = NULL;
	lro_context_t *lro_ctx = NULL;
#endif
	uint16_t hash = cvmx_wqe_get_tag(wqe) & LRO_TAG_MASK;

#ifdef FLOW_ENGINE
	tmp = cfe_lut_search(temp_ctx, (hash & LRO_TAG_MASK), ifidx, CFE_DEFAULT_OP); 
	if (tmp)
		return ((lro_context_t *) hlist_entry(tmp, lro_context_t, list));
	else
		return NULL;
#else
	/* SEARCH FOR A CONTEXT IN HASHTABLE */
	CAVIUM_LIST_FOR_EACH(tmp, &lro_hash_table[hash]) {
		lro_ctx = (lro_context_t *) container_of(tmp, lro_context_t, list);
		if (tcp_flow_match(wqe, lro_ctx, temp_ctx))
			return lro_ctx;
	}

	return NULL;
#endif
}

static inline int
oct_nic_lro_validate_pkt(cvmx_wqe_t *wqe, bool is_v6, void *iph, struct tcphdr *tcp)
{
	struct iphdr *iph4;
	struct ipv6hdr *iph6;
	int tcp_hlen = 0;
	uint32_t *ts_ptr = NULL;
	int HCK_tcp_flags_war = 0;	/* workaround for HCK tests w/TCP flags == 0x00 */

	HCK_tcp_flags_war = octeon_has_feature(OCTEON_FEATURE_CN78XX_WQE) &&
				(((cvmx_wqe_78xx_t *)wqe)->word2.err_level == CVMX_PKI_ERRLEV_E_LF) &&
				(((cvmx_wqe_78xx_t *)wqe)->word2.err_code == CVMX_PKI_OPCODE_TCP_FLAG);

	if (!is_v6) {
		iph4 = (struct iphdr *)iph;
		/* IP4 PACKET */
		/* IP Header must
		 *    have no IP options
		 *    MF bit not set
		 *    Fragment offset not set
		 */
		if ( ((iph4->ihl << 2) != sizeof(struct iphdr)) || (iph4->frag_off & IP_MF) ||
				(iph4->frag_off & IP_OFFSET) ) {
			print_debug("IP header Check Failed \n");
			return -1;
		}

		if (0 == (iph4->tot_len - (iph4->ihl << 2 ) - (tcp->doff << 2))) {
			print_debug("Data Len Zero\n");
			return -1;
		}
	}
	else {
		iph6 = (struct ipv6hdr *)iph;
		if (0 == (iph6->payload_len - (tcp->doff << 2)))
			return -1;
	}

	/* TCP flag checks */
	/* rtf TODO: review ECE/CWR behaviour; I don't believe mere presence of
	 * these flags warrants an LRO coalesce finalize */
	if (tcp->syn || tcp->urg || tcp->rst || tcp->fin || tcp->ece ||
			tcp->cwr || (!tcp->ack && !HCK_tcp_flags_war)) {
		print_debug("TCP header Check Failed \n");
		return -1;
	}

	/* Check for timestamps */
	tcp_hlen = (tcp->doff << 2);
	tcp_hlen -= sizeof(*tcp);
	ts_ptr = (uint32_t *)(tcp + 1);
	if (tcp_hlen != 0 &&
			((tcp_hlen != TCPOLEN_TSTAMP_APPA) || (*ts_ptr != TCPOPT_TSTAMP_HDR ))) {
		print_debug("TCP Timestamp Check Failed \n");
		return -1;
	}

	/* rtf TODO: I don't think this catches GRE Inner IP bad cksum (CVMX_PKI_ERRLEV_E_LE) */
	if ((cvmx_wqe_is_l4_error(wqe) && !HCK_tcp_flags_war) || cvmx_wqe_is_ip_exception(wqe)) {
		print_debug("ERROR : OOPS L3/L4 error\n");
		return -1;
	}

	return 0;
}

static inline int
oct_nic_lro_context_init(cvmx_wqe_t *wqe, int ifidx, lro_context_t *lro_ctx)
{
        cvmcs_nic_metadata_t *mdata = CVMCS_NIC_METADATA(wqe);

	memset(lro_ctx, 0, sizeof(lro_context_t));

	lro_ctx->wqe =  wqe;

        if (CVMCS_NIC_METADATA_IS_TUNNEL(mdata)) {

		if (CVMCS_NIC_METADATA_IS_IPV4(mdata)) {
			struct iphdr *iph4 = (struct iphdr *)CVMCS_NIC_METADATA_L3_HEADER(mdata);
			if (((iph4->ihl << 2) != sizeof(struct iphdr)) ||
				(iph4->frag_off & IP_MF) ||
				(iph4->frag_off & IP_OFFSET) ) {
				print_debug("OUTER IP HEADER CHECK FAILED\n");
				return -1;
			}
		}

		if ((!CVMCS_NIC_METADATA_IS_GRE(mdata)) &&
		    (!CVMCS_NIC_METADATA_IS_UDP(mdata))) {
			print_debug("IP TUNNEL CHECK FAILED\n");
			return -1;
		}

		if (!CVMCS_NIC_METADATA_IS_INNER_TCP(mdata)) {
			print_debug("IP TUNNEL CHECK FAILED\n");
			return -1;
		}

                lro_ctx->ethhdr = CVMCS_NIC_METADATA_INNER_L2_HEADER(mdata);

                lro_ctx->is_v6 = CVMCS_NIC_METADATA_IS_INNER_IPV6(mdata);
                lro_ctx->iphdr = CVMCS_NIC_METADATA_INNER_L3_HEADER(mdata);
                lro_ctx->tcp = (struct tcphdr *)CVMCS_NIC_METADATA_INNER_L4_HEADER(mdata);

		if (CVMCS_NIC_METADATA_IS_GRE(mdata)) {
			gre_hdr_t *greh = (gre_hdr_t *)CVMCS_NIC_METADATA_L4_HEADER(mdata);
			lro_ctx->vni = ((gre_key_hdr_t *)((void *)greh + sizeof(gre_hdr_t)))->key;
		}
		else if (CVMCS_NIC_METADATA_IS_UDP(mdata)) {
			struct udphdr *udph = (struct udphdr *)CVMCS_NIC_METADATA_L4_HEADER(mdata);
			lro_ctx->vni = (*((uint32_t *)((void *)udph + sizeof(struct udphdr) + 4)) >> 8);
		}
        }
        else {
		if (!CVMCS_NIC_METADATA_IS_TCP(mdata)) {
			print_debug("IP TUNNEL CHECK FAILED\n");
			return -1;
		}

                lro_ctx->ethhdr = CVMCS_NIC_METADATA_L2_HEADER(mdata);
                lro_ctx->is_v6 = CVMCS_NIC_METADATA_IS_IPV6(mdata);
                lro_ctx->iphdr = CVMCS_NIC_METADATA_L3_HEADER(mdata);
                lro_ctx->tcp = (struct tcphdr *)CVMCS_NIC_METADATA_L4_HEADER(mdata);
        }

	return oct_nic_lro_validate_pkt(wqe, lro_ctx->is_v6,
				lro_ctx->iphdr, lro_ctx->tcp);
}

static cvmx_buf_ptr_t get_legacy_buf_ptr(cvmx_wqe_t *wqe)
{
	if (octeon_has_feature(OCTEON_FEATURE_CN78XX_WQE)) {
		cvmx_buf_ptr_t legacy_buf_ptr;
		cvmx_buf_ptr_pki_t pki_pkt_ptr;

		pki_pkt_ptr = cvmx_wqe_get_pki_pkt_ptr(wqe);
		legacy_buf_ptr.u64 = 0;
		legacy_buf_ptr.s.size = pki_pkt_ptr.size;
		legacy_buf_ptr.s.addr = pki_pkt_ptr.addr;
		legacy_buf_ptr.s.pool = cvmx_wqe_get_aura(wqe);

		return legacy_buf_ptr;
	} else {
		return wqe->packet_ptr;
	}
}

static cvmx_buf_ptr_t u64_to_legacy_buf_ptr(uint64_t u64)
{
	cvmx_buf_ptr_t legacy_buf_ptr;

	if (octeon_has_feature(OCTEON_FEATURE_CN78XX_WQE)) {
		cvmx_buf_ptr_pki_t pki_pkt_ptr;

		pki_pkt_ptr.u64 = u64;

		legacy_buf_ptr.u64 = 0;
		legacy_buf_ptr.s.size = pki_pkt_ptr.size;
		legacy_buf_ptr.s.addr = pki_pkt_ptr.addr;
		legacy_buf_ptr.s.pool = CVMX_FPA_PACKET_POOL;

	} else {
		legacy_buf_ptr.u64 = u64;
	}

	return legacy_buf_ptr;
}

int
oct_nic_lro_receive_pkt(cvmx_wqe_t *wqe, int ifidx)
{
	struct iphdr *iph4 = NULL;
	struct ipv6hdr *iph6 = NULL;
	struct tcphdr *tcp = NULL;

	cvmx_buf_ptr_t *glist_ptr, cur;
	int cur_tcp_data_len, tcp_opt_len, data_offset, tot_pkt_len;

	int  i, filled_len = 0;
	vnic_port_info_t *nicport = &octnic->port[ifidx];

	lro_context_t *lro_ctx, temp_ctx;
	uint32_t *tsptr = NULL;
	union octeon_rh *rh;
	int wqe_and_pkt_data_are_in_separate_bufs;
	unsigned maxsegcount, lro_segment_threshold;

	bool is_v6;
	uint8_t wqe_bufs = cvmx_wqe_get_bufs(wqe);
	cvmcs_nic_metadata_t *mdata = CVMCS_NIC_METADATA(wqe);

	if (CVMCS_NIC_METADATA_IS_IPSEC(mdata)) {
		print_debug("IPSEC PACKET NOT VALID FOR LRO\n");
		return FORWARD_PKT_TO_HOST;
	} else if (CVMCS_NIC_METADATA_IS_IPV4(mdata)) {
		if (!nicport->state.lro_on_ipv4)
			return FORWARD_PKT_TO_HOST;
	} else if (CVMCS_NIC_METADATA_IS_IPV6(mdata)) {
		if (!nicport->state.lro_on_ipv6)
			return FORWARD_PKT_TO_HOST;
	} else {
		print_debug("PACKET NOT VALID FOR LRO\n");
		return FORWARD_PKT_TO_HOST;
	}

	if (oct_nic_lro_context_init(wqe, ifidx, &temp_ctx)) {
		print_debug("PACKET NOT VALID FOR LRO\n");
		return FORWARD_PKT_TO_HOST;
	}

	is_v6 = temp_ctx.is_v6;
	if (!is_v6)
		iph4 = temp_ctx.iphdr;
	else
		iph6 = temp_ctx.iphdr;
	tcp = temp_ctx.tcp;

	/* REQUEST FOR TAG SWITCH */
	cvmx_pow_tag_sw_full(wqe, (cvmx_wqe_get_tag(wqe) & LRO_TAG_MASK),
				CVMX_POW_TAG_TYPE_ATOMIC, cvmx_wqe_get_grp(wqe));

	cur_tcp_data_len = is_v6 ? iph6->payload_len : (iph4->tot_len - (iph4->ihl << 2 ));
	cur_tcp_data_len -= (tcp->doff << 2);

	data_offset = CVMCS_NIC_METADATA_HEADER_LENGTH(mdata);

	if (CVMCS_NIC_METADATA_IS_PTP_HEADER(mdata))
		data_offset += OCTNET_FRM_PTP_HEADER_SIZE;

	tot_pkt_len = cvmx_wqe_get_len(wqe);

	print_debug("TOT PKT LEN : %d DATA LEN : %d HDR LEN : %d\n", tot_pkt_len, data_offset, cur_tcp_data_len);

	tcp_opt_len = (tcp->doff << 2) - sizeof(*tcp);
	if (tcp_opt_len != 0 )
		tsptr = (uint32_t *)(tcp+1);

	/* WAIT TILL TAG SWITCH COMPLETES */
	cvmx_pow_tag_sw_wait();

	lro_segment_threshold = LRO_SEGMENT_THRESHOLD;

	/* LOOK FOR MATCHING FLOW */
	lro_ctx = find_lro_ctx(wqe, &temp_ctx, ifidx);
	if (lro_ctx) {
		//Requirement for updating per port backpressure
		if (cvmx_wqe_get_port(wqe) != cvmx_wqe_get_port(lro_ctx->wqe)) {
			cvmcs_nic_flush_lro(wqe, lro_ctx, 1);
			per_core_stats[cvmx_get_core_num()].link_stats[ifidx].fromwire.fw_lro_aborts += 1;
			per_core_stats[cvmx_get_core_num()].link_stats[ifidx].fromwire.fw_lro_aborts_port += 1;
			lro_tag_sw_order(wqe);
			return FORWARD_PKT_TO_HOST;
		}
		if( (tcp->seq != lro_ctx->next_seq) ||
				(cur_tcp_data_len == 0)) {
			cvmcs_nic_flush_lro(wqe, lro_ctx, 1);
			per_core_stats[cvmx_get_core_num()].link_stats[ifidx].fromwire.fw_lro_aborts += 1;
			per_core_stats[cvmx_get_core_num()].link_stats[ifidx].fromwire.fw_lro_aborts_seq += 1;
			lro_tag_sw_order(wqe);
			return FORWARD_PKT_TO_HOST;
		}

		/* CHECK IF TIME STAMPS */
		if(tcp_opt_len != 0) {
			if(lro_ctx->tsval > *(tsptr+1) || *(tsptr+2) == 0) {
				cvmcs_nic_flush_lro(wqe, lro_ctx, 1);
				per_core_stats[cvmx_get_core_num()].link_stats[ifidx].fromwire.fw_lro_aborts += 1;
				per_core_stats[cvmx_get_core_num()].link_stats[ifidx].fromwire.fw_lro_aborts_tsval += 1;
				lro_tag_sw_order(wqe);
				return FORWARD_PKT_TO_HOST;
			}
		}

		if (!(octeon_has_feature(OCTEON_FEATURE_CN78XX_WQE)) ||
			CVMCS_NIC_METADATA_IS_DUP_WQE(mdata) || (lro_ctx->wqe_list_size > 0))
			maxsegcount = LRO_SEGMENT_GATHER_MAX;
		else
			maxsegcount = LRO_SEGMENT_LINK_MAX;

		if (((lro_ctx->append_cnt + wqe_bufs) > maxsegcount) ||
		    (lro_ctx->append_cnt + wqe_bufs) > (CVMX_FPA_GATHER_LIST_POOL_SIZE/sizeof(cvmx_buf_ptr_t))) {
			per_core_stats[cvmx_get_core_num()].link_stats[ifidx].fromwire.fw_lro_aborts++;
			cvmcs_nic_flush_lro(wqe, lro_ctx, 1);
			lro_tag_sw_order(wqe);
			return FORWARD_PKT_TO_HOST;
		}

		/* PACKET CAN BE CONSIDERED FOR AGGREGATION */
		cur = get_legacy_buf_ptr(wqe);
		glist_ptr = cvmx_phys_to_ptr(lro_ctx->gather_list.s.addr);

		/* FILL GATHER LIST */
		for (i=0; i < wqe_bufs; i++) {
			if (0 == i) {
				/* FIRST BUFFER SO SKIP THE HEADER */
				glist_ptr[lro_ctx->append_cnt].u64 = cur.u64;
				glist_ptr[lro_ctx->append_cnt].s.addr = cur.s.addr + data_offset;

				if (i == wqe_bufs-1)
					glist_ptr[lro_ctx->append_cnt].s.size = tot_pkt_len - data_offset;
				else
					glist_ptr[lro_ctx->append_cnt].s.size = cur.s.size - data_offset;

				/* UPDATE BACK */
				glist_ptr[lro_ctx->append_cnt].s.back =
					((cur.s.addr + data_offset) - (((cur.s.addr >> 7)- cur.s.back) << 7))/
					CVMX_CACHE_LINE_SIZE;
				glist_ptr[lro_ctx->append_cnt].s.i = CVMCS_NIC_METADATA_IS_DUP_WQE(mdata);
			}
			else {
				glist_ptr[lro_ctx->append_cnt].u64 = cur.u64;

				if (i == wqe_bufs-1)
					glist_ptr[lro_ctx->append_cnt].s.size = tot_pkt_len - filled_len 
						- data_offset;
				else
					glist_ptr[lro_ctx->append_cnt].s.size = cur.s.size;

				glist_ptr[lro_ctx->append_cnt].s.i = CVMCS_NIC_METADATA_IS_DUP_WQE(mdata);
			}

			filled_len += glist_ptr[lro_ctx->append_cnt].s.size;

			lro_ctx->append_cnt += 1;
			cur = u64_to_legacy_buf_ptr(*(uint64_t *)cvmx_phys_to_ptr(cur.s.addr - 8));
		}

		/* UPDATE LRO CONTEXT */
		lro_ctx->bp_credits +=  wqe_bufs;
		lro_ctx->next_seq   = tcp->seq + cur_tcp_data_len;
		lro_ctx->ack_seq    = tcp->ack_seq;
		lro_ctx->tcp_data_len += cur_tcp_data_len;
		lro_ctx->window     = tcp->window;
		if (tcp_opt_len != 0) {
			lro_ctx->tsval      = *(tsptr + 1);
			lro_ctx->tsecr      = *(tsptr + 2);
		}

		lro_ctx->packet_cnt++;
		if (CVMCS_NIC_METADATA_IS_PTP_HEADER(mdata))
			lro_ctx->ptp_ts = *(uint64_t *)PACKET_START(wqe);

		per_core_stats[cvmx_get_core_num()].link_stats[ifidx].fromwire.fw_lro_pkts += 1;
		per_core_stats[cvmx_get_core_num()].link_stats[ifidx].fromwire.fw_lro_octs += cur_tcp_data_len;

		CVMX_SYNCWS;

		if (CVMCS_NIC_METADATA_IS_DUP_WQE(mdata)) {
			wqe_and_pkt_data_are_in_separate_bufs = 0;

			if (lro_ctx->wqe_list != NULL) {
				/* Use ossp[0] to link wqes */
				mdata->front.ossp[0] = (uint64_t)lro_ctx->wqe_list;	
			}

			lro_ctx->wqe_list = wqe;
			lro_ctx->wqe_list_size++;
		} else {
			if (octeon_has_feature(OCTEON_FEATURE_CN78XX_WQE))
				wqe_and_pkt_data_are_in_separate_bufs = 0;
			else
				wqe_and_pkt_data_are_in_separate_bufs = 1;
		}

		if (lro_ctx->port_lro_used &&
		    (cvmx_atomic_fetch_and_add32(lro_ctx->port_lro_used, 1) >
		     MAX_LRO_PACKETS_PER_GMX)) {
			if (tcp->psh)
				lro_ctx->is_psh = true;
			cvmcs_nic_flush_lro(wqe, lro_ctx, 1);
			if (wqe_and_pkt_data_are_in_separate_bufs)
				cvmcs_wqe_free(wqe);
			return 0;
		}

		if (tcp->psh) {
			lro_ctx->is_psh = true;
			cvmcs_nic_flush_lro(wqe, lro_ctx, 1);
			if (wqe_and_pkt_data_are_in_separate_bufs)
				cvmcs_wqe_free(wqe);
			return 0;
		}
		if ((lro_ctx->tcp_data_len + cur_tcp_data_len) > lro_segment_threshold) {
			cvmcs_nic_flush_lro(wqe, lro_ctx, 1);
			if (wqe_and_pkt_data_are_in_separate_bufs)
				cvmcs_wqe_free(wqe);
			return 0;
		}

		/* THIS WONT BE FIRST WQE SO FREE IT ONLY WQE */
		//lro_tag_sw_order(wqe);
		cvmx_pow_tag_sw_null();
		if (wqe_and_pkt_data_are_in_separate_bufs)
			cvmcs_wqe_free(wqe);
		return 0;
	}

	/* FLUSH PUSH PACKET */
	if (tcp->psh) {
		lro_tag_sw_order(wqe);
		return FORWARD_PKT_TO_HOST;
	}

	/* CREATE A NEW CONTEXT */
	temp_ctx.ifidx = ifidx;
	lro_ctx = alloc_lro_context(wqe, &temp_ctx);
	if (NULL == lro_ctx) {
		per_core_stats[cvmx_get_core_num()].link_stats[ifidx].fromwire.fw_lro_aborts += 1;
		lro_tag_sw_order(wqe);
		return FORWARD_PKT_TO_HOST;
	}

	print_debug("NEW CONTEXT CREATED : %p\n", lro_ctx);

	/* REQUEST FOR GATHER LIST TO FPA */
	cvmx_fpa_async_alloc(CVMCS_TEST_BUF_PTR, CVMX_FPA_GATHER_LIST_POOL);

	/* FILL LRO CONTEXT */
	lro_ctx->tcp_data_len = cur_tcp_data_len;
	if (tcp_opt_len) {
		lro_ctx->tsval = *(tsptr + 1);
		lro_ctx->tsecr = *(tsptr + 2);
	}

	nicport =  &octnic->port[ifidx];

	lro_ctx->next_seq = tcp->seq + lro_ctx->tcp_data_len;
	lro_ctx->ack_seq  = tcp->ack_seq;
	lro_ctx->window = tcp->window;
	lro_ctx->wqe = wqe; /* STORE FIRST WQE */
	lro_ctx->packet_cnt = 1;
	lro_ctx->append_cnt = 0;
	lro_ctx->ifidx = ifidx;

	/* CREATE GATHER LIST */
	glist_ptr = (cvmx_buf_ptr_t *)cvmx_fpa_async_alloc_finish(
			CVMCS_TEST_BUF_PTR, CVMX_FPA_GATHER_LIST_POOL);
	if (NULL == glist_ptr ) {
		print_error("ERR: GATHER LIST ALLOC FAILED\n");
		//remove_lro_context(lro_ctx);
		free_lro_context(lro_ctx);
		per_core_stats[cvmx_get_core_num()].link_stats[ifidx].fromwire.fw_lro_aborts += 1;
		lro_tag_sw_order(wqe);
		return FORWARD_PKT_TO_HOST;
	}

	lro_ctx->gather_list.u64 = 0;
	lro_ctx->gather_list.s.addr = CVM_DRV_GET_PHYS(glist_ptr);
	lro_ctx->gather_list.s.pool = CVMX_FPA_GATHER_LIST_POOL;

	/* USE mdata->reserved filed to store resp header */
	rh = (union octeon_rh *)&mdata->rh;

	rh->u64 = 0;
	rh->r_dh.opcode = OPCODE_NIC;
	rh->r_dh.subcode = OPCODE_NIC_NW_DATA;
	if (CVMCS_NIC_METADATA_IS_TUNNEL(mdata))
		rh->r_dh.csum_verified = CNNIC_TUN_CSUM_VERIFIED;
	else
		rh->r_dh.csum_verified = CNNIC_CSUM_VERIFIED;
	rh->r_dh.encap_on = CVMCS_NIC_METADATA_IS_ENCAP_ON(mdata);
	if (OCTEON_IS_MODEL(OCTEON_CN6XXX)) {
		rh->r_dh.has_hwtstamp = 1;
		rh->r_dh.len = 1;
	}

	glist_ptr[0].u64    = 0;
	glist_ptr[0].s.addr = CVM_DRV_GET_PHYS(rh);
	glist_ptr[0].s.pool = cvmcs_wqe_pool();
	glist_ptr[0].s.size = OCT_RH_SIZE;
	//for backpressure, this wqe is returned by pko
	//and then freed after adjusting backpressure
	//credits
	glist_ptr[0].s.i = 1;


	lro_ctx->append_cnt += 1;

	cur = get_legacy_buf_ptr(wqe);

	if (!(octeon_has_feature(OCTEON_FEATURE_CN78XX_WQE)) || CVMCS_NIC_METADATA_IS_DUP_WQE(mdata))
		maxsegcount = LRO_SEGMENT_GATHER_MAX;
	else
		maxsegcount = LRO_SEGMENT_LINK_MAX;

	if (((lro_ctx->append_cnt + wqe_bufs) > maxsegcount) ||
	     (lro_ctx->append_cnt + wqe_bufs) > (CVMX_FPA_GATHER_LIST_POOL_SIZE/sizeof(cvmx_buf_ptr_t))) {
		print_error("too many segs\n");
		cvmx_fpa_free(glist_ptr, CVMX_FPA_GATHER_LIST_POOL, 0);
		per_core_stats[cvmx_get_core_num()].link_stats[ifidx].fromwire.fw_lro_aborts++;
		free_lro_context(lro_ctx);
		lro_tag_sw_order(wqe);
		return FORWARD_PKT_TO_HOST;
	}
	/* FILL THE REST OF BUFFERS IN GATHER LIST */
	for (i=0; i < wqe_bufs; ++i) {
		glist_ptr[lro_ctx->append_cnt].u64 = cur.u64;

		glist_ptr[lro_ctx->append_cnt].s.i = CVMCS_NIC_METADATA_IS_DUP_WQE(mdata);

		if (i == wqe_bufs-1) /* IF LAST BUFFER */
			glist_ptr[lro_ctx->append_cnt].s.size = tot_pkt_len - filled_len;

		filled_len += glist_ptr[lro_ctx->append_cnt].s.size;
		lro_ctx->append_cnt += 1;

		/* GET NEXT BUFFER */
		cur = u64_to_legacy_buf_ptr(*(uint64_t *)cvmx_phys_to_ptr(cur.s.addr - 8));
	}

	lro_ctx->bp_credits  += wqe_bufs;

	if (CVMCS_NIC_METADATA_IS_DUP_WQE(mdata)) {
		lro_ctx->wqe_list = wqe;
		lro_ctx->wqe_list_size = 1;
	}

	/* START PER FLOW TIMER */
	if (cvmcs_nic_set_lro_timer(lro_ctx)) {
		print_error("TIMER SETTING ERROR\n");
		/* FLUSH LRO CONTEXT */
		cvmx_fpa_free(glist_ptr, CVMX_FPA_GATHER_LIST_POOL, 0);
		per_core_stats[cvmx_get_core_num()].link_stats[ifidx].fromwire.fw_lro_aborts += 1;
		per_core_stats[cvmx_get_core_num()].link_stats[ifidx].fromwire.fw_lro_aborts_timer += 1;
		//remove_lro_context(lro_ctx);
		free_lro_context(lro_ctx);
		lro_tag_sw_order(wqe);
		return FORWARD_PKT_TO_HOST;
	}

	per_core_stats[cvmx_get_core_num()].link_stats[ifidx].fromwire.fw_lro_pkts += 1;
	per_core_stats[cvmx_get_core_num()].link_stats[ifidx].fromwire.fw_lro_octs += cur_tcp_data_len;

	//add_lro_context(lro_ctx, wqe->word1.tag & LRO_TAG_MASK);
	CVMX_SYNCWS;
	//lro_tag_sw_order(wqe);
	cvmx_pow_tag_sw_null();

	return 0;
}


int
oct_nic_lro_tso_receive_pkt(cvmx_wqe_t *wqe, int ifidx)
{
	lro_context_t *lro_ctx, temp_ctx;
	vnic_port_info_t *nicport = &octnic->port[ifidx];
	cvmcs_nic_metadata_t *mdata = CVMCS_NIC_METADATA(wqe);

	if (CVMCS_NIC_METADATA_IS_IPV4(mdata)) {
		if (!nicport->state.lro_on_ipv4)
			return FORWARD_PKT_TO_HOST;
	} else if (CVMCS_NIC_METADATA_IS_IPV6(mdata)) {
		if (!nicport->state.lro_on_ipv6)
			return FORWARD_PKT_TO_HOST;
	} else {
		print_debug("PACKET NOT VALID FOR LRO\n");
		return FORWARD_PKT_TO_HOST;
	}

	if (oct_nic_lro_context_init(wqe, ifidx, &temp_ctx)) {
		print_debug("PACKET NOT VALID FOR LRO\n");
		return FORWARD_PKT_TO_HOST;
	}

	/* REQUEST FOR TAG SWITCH */
	cvmx_pow_tag_sw_full(wqe, (cvmx_wqe_get_tag(wqe) & LRO_TAG_MASK),
				CVMX_POW_TAG_TYPE_ATOMIC, cvmx_wqe_get_grp(wqe));

	/* WAIT TILL TAG SWITCH COMPLETES */
	cvmx_pow_tag_sw_wait();

	/* LOOK FOR MATCHING FLOW */
	lro_ctx = find_lro_ctx(wqe, &temp_ctx, ifidx);
	if (lro_ctx) {
		cvmcs_nic_flush_lro(wqe, lro_ctx, 1);
	} else {
		lro_tag_sw_order(wqe);
	}

	if (CVMCS_NIC_METADATA_IS_IPV4(mdata)) {
		struct iphdr *iphdr = (struct iphdr *)
			CVMCS_NIC_METADATA_L3_HEADER(mdata);
			
		iphdr->tot_len = cvmx_wqe_get_len(wqe) -
			CVMCS_NIC_METADATA_L3_OFFSET(mdata);
	}
	else if (CVMCS_NIC_METADATA_IS_IPV6(mdata)) {
		struct ipv6hdr *iphdr = (struct ipv6hdr *)
			CVMCS_NIC_METADATA_L3_HEADER(mdata);
			
		iphdr->payload_len = cvmx_wqe_get_len(wqe) -
                        CVMCS_NIC_METADATA_L3_OFFSET(mdata) - 40;
	}

	if (CVMCS_NIC_METADATA_IS_TUNNEL(mdata)) {

		if (CVMCS_NIC_METADATA_IS_INNER_IPV4(mdata)) {
			struct iphdr *iphdr = (struct iphdr *)
				CVMCS_NIC_METADATA_INNER_L3_HEADER(mdata);
			
			iphdr->tot_len = cvmx_wqe_get_len(wqe) -
				CVMCS_NIC_METADATA_INNER_L3_OFFSET(mdata);
		}
		else if (CVMCS_NIC_METADATA_IS_INNER_IPV6(mdata)) {
			struct ipv6hdr *iphdr = (struct ipv6hdr *)
				CVMCS_NIC_METADATA_INNER_L3_HEADER(mdata);
			
			iphdr->payload_len = cvmx_wqe_get_len(wqe) -
                        	CVMCS_NIC_METADATA_INNER_L3_OFFSET(mdata) - 40;
		}

	}

	return FORWARD_PKT_TO_HOST;
}

void oct_nic_lro_init()
{

#ifndef FLOW_ENGINE
	int32_t i;

	if (!booting_for_the_first_time) {
		lro_hash_table = live_upgrade_ctx->lro_hash_table;
		return;
	}

	lro_hash_table = cvmx_bootmem_alloc_named(LRO_HASH_SIZE * sizeof (struct list_head), CVMX_CACHE_LINE_SIZE, "__lro_hash_table");
	if (!lro_hash_table) {
		printf("ERROR: failed to alloc lro_hash_table\n");
		return;
	}
	live_upgrade_ctx->lro_hash_table = lro_hash_table;

	/* INITIALIZE HASH TABLE */
	for (i = 0; i < LRO_HASH_SIZE; i++)
		CAVIUM_INIT_LIST_HEAD(&lro_hash_table[i]);
#endif

	/* SET THE TIMER FOR LRO CONTEXT FLUSHING
	 * 0.01 SECONDS 360 MAX TIMEOUT
	 */
	cvmx_tim_set_fpa_pool_config(3, 1024, 0);

	cvmx_tim_setup(NIC_TIMER_PERIOD_US, 36000 * 1000 / (NIC_TIMER_PERIOD_US));
	cvmx_tim_start();

	/* ENABLE L4 ERROR CHECK */
	if (!octeon_has_feature(OCTEON_FEATURE_PKI)) {
		cvmx_pip_gbl_ctl_t pip_gbl_ctl;

		/* SET AN IP OFFSET TO INCLUDE MAC HEADER */
		cvmx_write_csr(CVMX_PIP_IP_OFFSET, LRO_IP_OFFSET);
		pip_gbl_ctl.u64 = cvmx_read_csr(CVMX_PIP_GBL_CTL);
		pip_gbl_ctl.s.l2_mal = 1;
		pip_gbl_ctl.s.l4_len = 1;
		pip_gbl_ctl.s.l4_chk = 1;
		pip_gbl_ctl.s.l4_prt = 1;
		pip_gbl_ctl.s.l4_mal = 1;
		pip_gbl_ctl.s.ip_mal = 1;
		pip_gbl_ctl.s.ip_chk = 1;
		cvmx_write_csr(CVMX_PIP_GBL_CTL, pip_gbl_ctl.u64);
	} else {
		struct cvmx_pki_port_config port_cfg;
		int ipd_port;

		/* Make sure TCP checksum is on.  */
		for (i = 0; i < (int)octnic->ngmxports; i++) {
			ipd_port = octnic->gmx_port_info[i].ipd_port;

			cvmx_pki_get_port_config(ipd_port, &port_cfg);
			port_cfg.style_cfg.parm_cfg.csum_lf = 1;
			cvmx_pki_set_port_config(ipd_port, &port_cfg);
		}
	}
}

void oct_nic_lro_discard(int ifidx)
{
	int32_t i;
	struct list_head *tmp = NULL;
	lro_context_t *lro_ctx = NULL;

	for (i = 0; i < LRO_HASH_SIZE; i++) {
		CAVIUM_LIST_FOR_EACH(tmp, &lro_hash_table[i]) {
			lro_ctx = (lro_context_t *) container_of(tmp, lro_context_t, list);
			if (lro_ctx->ifidx == ifidx)
				cvmcs_nic_flush_lro(lro_ctx->wqe, lro_ctx, 1);
		}
	}
}
