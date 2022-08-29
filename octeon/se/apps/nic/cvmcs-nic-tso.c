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
#include  <cvmx-atomic.h>
#include "cvmcs-nic-ether.h"
#include "cvmcs-nic-ip.h"
#include "cvmcs-nic-ipv6.h"
#include "cvmcs-nic-tcp.h"
#include "cvmcs-nic-udp.h"
#include "cvmcs-nic-tunnel.h"
#include "cvmcs-nic-switch.h"
#include "cvmcs-nic-mdata.h"
#include "cvm-nic-ipsec.h"
#include "cvmcs-nic-rss.h"
#include "cvmcs-nic-fnv.h"
#include "cvmcs-nic-tso.h"
#include "cvmcs-dcb.h"

#ifdef DEBUG
#define print_error(msg, ...)   printf(msg,##__VA_ARGS__)
#define print_debug(msg, ...)   printf(msg,##__VA_ARGS__)
#else
#define print_error(msg, ...)   printf(msg,##__VA_ARGS__)
#define print_debug(msg, ...)
#endif

#define DIV_ROUND_UP(n,d) (((n) + (d) - 1) / (d))

#ifdef VSWITCH
bool is_tunnel(uint8_t proto, uint16_t udp_port);
#endif

extern CVMX_SHARED cvm_per_core_stats_t *per_core_stats;

int cvmcs_nic_process_ipsec(cvmx_wqe_t *wqe, cvmx_buf_ptr_t *temp_list ,int32_t *pkt_size,
	int16_t gso_segs,uint16_t esp_ah_offset, uint16_t esp_ah_hdrlen, int ifidx);

int cvmcs_nic_process_ipsec_o3(cvmx_wqe_t *wqe,
                            struct tso_o3_pkt_desc *temp_list, int32_t *pkt_size,
                            int16_t gso_segs, int ifidx);

int cvmcs_nic_add_ipsec_tso_info_o3(cvmx_wqe_t *wqe, tso_hdr_info_t *tso_hdr);

static void
tso_init_hdr_info(cvmx_wqe_t *wqe, int ifidx, tso_hdr_info_t *tso_hdr)
{
	tx_info_t *tso_info;
	cvmcs_nic_metadata_t *mdata = CVMCS_NIC_METADATA(wqe);

	if (CVMCS_NIC_METADATA_IS_TUNNEL(mdata)) {
		tso_hdr->ethhdr = CVMCS_NIC_METADATA_INNER_L2_HEADER(mdata);

		tso_hdr->is_vlan = CVMCS_NIC_METADATA_IS_INNER_VLAN(mdata);

		tso_hdr->is_v6 = CVMCS_NIC_METADATA_IS_INNER_IPV6(mdata);
		tso_hdr->ip_offset = CVMCS_NIC_METADATA_INNER_L3_OFFSET(mdata);
		tso_hdr->iphdr = CVMCS_NIC_METADATA_INNER_L3_HEADER(mdata);
		tso_hdr->tcp = CVMCS_NIC_METADATA_INNER_L4_HEADER(mdata);
		tso_hdr->tcp_offset = CVMCS_NIC_METADATA_INNER_L4_OFFSET(mdata);
	}
	else {
		tso_hdr->is_vlan = CVMCS_NIC_METADATA_IS_VLAN(mdata);
		tso_hdr->ethhdr = CVMCS_NIC_METADATA_L2_HEADER(mdata);
		tso_hdr->is_v6 = CVMCS_NIC_METADATA_IS_IPV6(mdata);
		tso_hdr->iphdr = CVMCS_NIC_METADATA_L3_HEADER(mdata);
		tso_hdr->ip_offset = CVMCS_NIC_METADATA_L3_OFFSET(mdata);
		tso_hdr->tcp = CVMCS_NIC_METADATA_L4_HEADER(mdata);
		tso_hdr->tcp_offset = CVMCS_NIC_METADATA_L4_OFFSET(mdata);
	}

	tso_hdr->hdr_len = CVMCS_NIC_METADATA_HEADER_LENGTH(mdata);
	tso_info = (tx_info_t *) (&mdata->front.ossp[0]);
	tso_hdr->gso_size = tso_info->s.gso_size;
	tso_hdr->gso_segs = DIV_ROUND_UP((cvmx_wqe_get_len(wqe) - tso_hdr->hdr_len), tso_hdr->gso_size);
	tso_hdr->mss = tso_info->s.gso_size + tso_hdr->hdr_len;

	return;
}

static inline void
tso_free_lists(cvmx_buf_ptr_t *gather_list, int start, int segs)
{
	cvmx_buf_ptr_t *glist_ptr = NULL;
	int from = start;

	for( ;from<segs; ++from) {
		glist_ptr = (cvmx_buf_ptr_t *)
				cvmx_phys_to_ptr(gather_list[from].s.addr);

		/* Free protocol header */
		cvmx_fpa_free(cvmx_phys_to_ptr(glist_ptr[0].s.addr),
				CVMX_FPA_PROTOCOL_HEADER_POOL, 0);

		/* Free Gather list of Segment i */
		cvmx_fpa_free(glist_ptr, CVMX_FPA_GATHER_LIST_POOL, 0);
	}
}


static inline void
tso_free_lists_o3(struct tso_o3_pkt_desc  *gather_list, int start, int segs)
{
	int from = start;

	for (;from<segs; ++from) {
		/* Free protocol header */
		cvmx_fpa_free(cvmx_phys_to_ptr(gather_list[from].g_bufs[0].buf.s.addr),
					CVMX_FPA_PROTOCOL_HEADER_POOL, 0);

	}
}

static inline int
cvmcs_nic_send_gather_list_to_pko3(struct tso_o3_pkt_desc *gather_list,
					int ifidx, int *total_size, cvmx_wqe_t *wqe,
					int gso_segs, uint8_t l3_offset, uint8_t l4_offset)
{
	int32_t i = 0;
	cvmx_buf_ptr_pki_t *tmp_lptr;
	vnic_port_info_t *nicport;
	int rxq, port, dq;
	int rxq_idx=0;
	uint32_t hash = (uint32_t)-1;
	uint32_t hashtype = 0;
	cvmcs_nic_metadata_t *mdata = CVMCS_NIC_METADATA(wqe);

	if (ifidx == -1 ) {
		/* send to gmx port */
#ifdef VSWITCH
		nicport = &octnic->port[mdata->to_ifidx];
#else
		nicport = &octnic->port[mdata->from_ifidx];
#endif
		port  = nicport->linfo.gmxport;
		dq = cvmcs_dcb_get_dq(wqe, port);
	} else {
		/* send to dpi port */
		nicport = &octnic->port[ifidx];
		if (nicport->state.rss_on) {
			rxq_idx = cvmcs_nic_rss_get_queue(wqe, &hash, &hashtype, ifidx);
                	if (-1 == rxq_idx) {
                        	rxq_idx = (cvmx_wqe_get_tag(wqe) % (nicport->linfo.num_rxpciq));
#if defined(USE_CUSTOM_OQ)
                        	rxq-idx = 0;
#endif
                	}
		} else if (nicport->state.fnv_on) {
			rxq_idx = cvmcs_nic_fnv_get_queue(wqe, &hash, ifidx);
                	if (-1 == rxq_idx) {
                        	rxq_idx = (cvmx_wqe_get_tag(wqe) % (nicport->linfo.num_rxpciq));
#if defined(USE_CUSTOM_OQ)
                        	rxq-idx = 0;
#endif
                	}
		} else {
			rxq_idx =  cvmcs_nic_get_rxq(wqe, &hash, ifidx);
#if defined(USE_CUSTOM_OQ)
                	rxq_idx = 0;
#endif
		}

                rxq = OCT_NIC_OQ_NUM(nicport, rxq_idx);

	        port = cvm_pci_get_oq_pkoport(rxq);
        	dq = cvm_pci_get_oq_pkoqueue(rxq);
	}

	if(cvmx_unlikely(port == -1 || dq == -1)) {
		int idx = (ifidx == -1) ? mdata->from_ifidx:ifidx;
		per_core_stats[cvmx_get_core_num()].link_stats[idx].fromhost.fw_err_drop += 1;
		print_error("Error port :%d queue: %d \n",port, dq);
		tso_free_lists_o3(gather_list, 0 , gso_segs);
		return -1;
	}

	tmp_lptr = (cvmx_buf_ptr_pki_t *)&wqe->packet_ptr;
	/* We have wqe_data[0] available. mdata starts at wqe_data[1] */
	*(((uint64_t *)&mdata->front) - 1) = tmp_lptr->u64;
	tmp_lptr->u64 = 0;
	tmp_lptr->addr = CVM_DRV_GET_PHYS(&mdata->front);
	tmp_lptr->size = mdata->front_size;
	cvmx_wqe_set_bufs(wqe, cvmx_wqe_get_bufs(wqe) + 1);
	cvmx_wqe_set_len(wqe, (cvmx_wqe_get_len(wqe) + mdata->front_size));
	mdata->front.irh.s.opcode = OPCODE_NIC;
	mdata->front.irh.s.subcode = OCT_NIC_TSO_COMPLETION_OP;
	((cvmx_wqe_78xx_t *)wqe)->word2.software = 1;

	for (i=0; i<gso_segs; ++i) {
		cvmx_pko_query_rtn_t pko_status;
		cvmx_pko_send_hdr_t hdr_s;
		cvmx_pko_buf_ptr_t gtr_s;
		union octeon_rh *rh;
		unsigned node, nwords;
		unsigned scr_base = cvmx_pko3_lmtdma_scr_base();
		int j;

		/* Separa global DQ# into node and local DQ */
		node = dq >> 10;
		dq &= (1 << 10)-1;

		if (ifidx != -1) {
			rh = (union octeon_rh *)cvmx_phys_to_ptr(gather_list[i].g_bufs[0].buf.s.addr);
			*(uint32_t *)(rh + 1) = hash;
			*(((uint32_t *)(rh + 1)) + 1) = hashtype;
		}

		if (!i)
			cvmx_pow_tag_sw_full(wqe, (cvmx_wqe_get_tag(wqe) ^ dq), CVMX_POW_TAG_TYPE_ATOMIC, cvmx_wqe_get_grp(wqe));

		/* Fill in header */
		hdr_s.u64 = 0;
		hdr_s.s.total = total_size[i];
		hdr_s.s.df = 0;
		hdr_s.s.ii = 0;
		hdr_s.s.aura = gather_list[i].g_bufs[0].aura;
#ifdef __LITTLE_ENDIAN_BITFIELD
		hdr_s.s.le = 1;
#endif
		if (l3_offset) {
			if (CVMCS_NIC_METADATA_IS_TUNNEL(mdata)) {
			     if (CVMCS_NIC_METADATA_IS_INNER_IPV4(mdata))
					hdr_s.s.ckl3 = 1;
			}
			else {
			     if (CVMCS_NIC_METADATA_IS_IPV4(mdata))
					hdr_s.s.ckl3 = 1;
			}
			hdr_s.s.l3ptr =  l3_offset;
		}
		if (l4_offset) {
			hdr_s.s.ckl4 = CKL4ALG_TCP;
			hdr_s.s.l4ptr = l4_offset;
		}
		/* Fill in gather */
		if (gather_list[i].nbufs > MAX_GATHER_BUFS_O3) {
			tso_free_lists_o3(gather_list, i , gso_segs);
			goto err;
		}
		nwords = 0;
		cvmx_scratch_write64(scr_base+sizeof(uint64_t)*(nwords++), hdr_s.u64);
		gtr_s.u64 = gather_list[i].g_bufs[0].buf.u64;
		gtr_s.s.subdc3 = CVMX_PKO_SENDSUBDC_GATHER;
		cvmx_scratch_write64(scr_base+sizeof(uint64_t)*(nwords++), gtr_s.u64);
		for (j = 1; j < gather_list[i].nbufs; j++) {
			if (nwords >= MAX_PKO3_CMD_WORDS) {
				tso_free_lists_o3(gather_list, i, gso_segs);
				goto err;
			}
			gtr_s.u64 = gather_list[i].g_bufs[j].buf.u64;
			gtr_s.s.subdc3 = CVMX_PKO_SENDSUBDC_GATHER;
			cvmx_scratch_write64(scr_base+sizeof(uint64_t)*(nwords++), gtr_s.u64);
		}
		if (i == gso_segs-1) {
			//add response wqe. should be the only send work and the last
			//one
			cvmx_pko_send_work_t work_s;
			if (nwords >= MAX_PKO3_CMD_WORDS) {
				tso_free_lists_o3(gather_list, i, gso_segs);
				goto err;
			}
			work_s.u64 = 0;
			work_s.s.subdc4 = CVMX_PKO_SENDSUBDC_WORK;
			work_s.s.addr = cvmx_ptr_to_phys(wqe);
			work_s.s.grp = cvmx_wqe_get_grp(wqe);
			work_s.s.tt = cvmx_wqe_get_tt(wqe);
			cvmx_scratch_write64(scr_base+sizeof(uint64_t)*(nwords++), work_s.u64);
		}
		/* Do LMTDMA */
		if (!i) {
			cvmx_pow_tag_sw_wait();
		}
		pko_status = cvmcs_pko3_lmtdma(node, dq, nwords, false,
					       ((i == gso_segs-1) ? true :
						false));

		if (cvmx_likely(pko_status.s.dqstatus != PKO_DQSTATUS_PASS)) {
			print_debug("error sending packet %d\n", i);
			tso_free_lists_o3(gather_list, i, gso_segs);
			goto err;
		}
		{
			if (ifidx != -1) {
				per_core_stats[cvmx_get_core_num()].perq_stats[ifidx].fromwire.fw_total_fwd_bytes[rxq_idx] += total_size[i];
				per_core_stats[cvmx_get_core_num()].perq_stats[ifidx].fromwire.fw_total_fwd[rxq_idx] += 1;
			}
		}
	}
	
	return 0;
err:
	{
		int idx = (ifidx == -1) ? mdata->from_ifidx:ifidx;
		cvmcs_nic_delete_first_buffer(wqe);
		print_debug("too many send descs\n");
		per_core_stats[cvmx_get_core_num()].link_stats[idx].fromhost.fw_err_pko += 1;
		return -1;
	}
}

static inline int
cvmcs_nic_send_gather_list_to_pko(cvmx_buf_ptr_t *gather_list,
					int ifidx, int *total_size, cvmx_wqe_t *wqe,
					int gso_segs, uint8_t ipoffp1)
{
	int32_t ret = 0, i = 0;
	cvmx_pko_command_word0_t pko_command;
	vnic_port_info_t *nicport;
	int rxq, port, queue;
	int rxq_idx=0;
	union octeon_rh *rh;
	uint32_t hash = (uint32_t)-1;
	uint32_t hashtype;
	cvmcs_nic_metadata_t *mdata = CVMCS_NIC_METADATA(wqe);

	if (ifidx == -1 ) {
		/* send to gmx port */
		nicport = &octnic->port[mdata->from_ifidx];
		port  = nicport->linfo.gmxport;
		queue = cvmcs_dcb_get_dq(wqe, port);
	} else {
		/* send to dpi port */
		nicport = &octnic->port[ifidx];
		if (nicport->state.rss_on) {
			rxq = cvmcs_nic_rss_get_queue(wqe, &hash, &hashtype, ifidx);
                	if (-1 == rxq) {
                        	rxq = (cvmx_wqe_get_tag(wqe) % (nicport->linfo.num_rxpciq));
#if defined(USE_CUSTOM_OQ)
                        	rxq = 0;
#endif
                	}
		} else if (nicport->state.fnv_on) {
			rxq = cvmcs_nic_fnv_get_queue(wqe, &hash, ifidx);
                	if (-1 == rxq) {
                        	rxq = (cvmx_wqe_get_tag(wqe) % (nicport->linfo.num_rxpciq));
#if defined(USE_CUSTOM_OQ)
                        	rxq = 0;
#endif
                	}
		} else {
			rxq =  cvmcs_nic_get_rxq(wqe, &hash, ifidx);
#if defined(USE_CUSTOM_OQ)
                	rxq = 0;
#endif
		}

                rxq = OCT_NIC_OQ_NUM(nicport, rxq);

	        port = cvm_pci_get_oq_pkoport(rxq);
        	queue = cvm_pci_get_oq_pkoqueue(rxq);
	}

	if(cvmx_unlikely(port == -1 || queue == -1)) {
		int idx = (ifidx == -1) ? mdata->from_ifidx:ifidx;
		per_core_stats[cvmx_get_core_num()].link_stats[idx].fromhost.fw_err_drop += 1;
		print_error("Error port :%d queue: %d \n",port,queue);
		tso_free_lists(gather_list, 0, gso_segs);
		return -1;
	}

	CVMX_SYNCWS;

	/* Prepare to send a packet to PKO. */
	cvmx_pko_send_packet_prepare(port, queue, 1);

	for (i=0; i<gso_segs; ++i) {
		/* Build a PKO pointer to this packet */
		pko_command.u64           = 0;
		pko_command.s.ignore_i    = 0;
		pko_command.s.dontfree    = 0;
		pko_command.s.gather      = 1;
		pko_command.s.segs        = gather_list[i].s.size;
		pko_command.s.total_bytes = total_size[i];

		if (ipoffp1)
			pko_command.s.ipoffp1 = ipoffp1 + 1;

		if (ifidx != -1) {
			rh = (union octeon_rh *)cvmx_phys_to_ptr(gather_list[i].s.addr);
			*(uint32_t *)(rh + 1) = hash;
			*(((uint32_t *)(rh + 1)) + 1) = hash;
		}

		DBG_PRINT(DBG_FLOW,"pko cmd: %016llx lptr: %016llx PORT: %d Q: %d\n",
	        cast64(pko_command.u64), cast64(gather_list[i].u64), port,
		cvmx_pko_get_base_queue(port));
		if(i != (gso_segs-1))
			ret = cvmx_pko_send_packet_finish(port, queue,
							  pko_command, gather_list[i], !i);
		else {
			/* Last  packet */
			pko_command.s.wqp = 1;
			pko_command.s.rsp = 1;
			/* Send a packet to PKO, with a completion WQE */
			ret = cvmx_pko_send_packet_finish3(port, queue,
							   pko_command, gather_list[i],
							   cvmx_ptr_to_phys(wqe), 0);
		}
		if (CVMX_PKO_SUCCESS == ret) {
			if (ifidx != -1) {
				per_core_stats[cvmx_get_core_num()].perq_stats[ifidx].fromwire.fw_total_fwd[rxq_idx] += 1;
				per_core_stats[cvmx_get_core_num()].perq_stats[ifidx].fromwire.fw_total_fwd_bytes[rxq_idx] += total_size[i];
			}
		} else {
			int idx = (ifidx == -1) ? mdata->from_ifidx:ifidx;
			per_core_stats[cvmx_get_core_num()].link_stats[idx].fromhost.fw_err_pko += 1;
			//free the rest of the packets
			tso_free_lists(gather_list, i, gso_segs);
			print_error("PACKET SEND FAILED : %d\n", i);
			return ret;
		}
	}

	return 0;
}

int
tso_send_to_wire(cvmx_wqe_t *wqe, cvmx_buf_ptr_t *gather_list,
		uint16_t *sizes, int nsegs, uint8_t ipoffp1)
{
	int32_t ifidx;

	ifidx = get_vnic_port_id(cvmx_wqe_get_port(wqe));

	return cvmcs_nic_send_gather_list_to_pko(gather_list, ifidx,
				 (int32_t *)sizes, wqe, nsegs, ipoffp1);
}

static void
cvmcs_nic_put_tcp_checksum_ipv4_glist(struct iphdr *ip, struct tcphdr *tcp,
				      cvmx_buf_ptr_t *glist, int buf_count)
{
	uint16_t *p, ippayloadlen, tcphdrlen;
	uint64_t checksum;
	int i, iterations, b, msb;
	uint8_t last_byte, *byte_ptr;

	ippayloadlen = ip->tot_len - (ip->ihl << 2);

	p = (uint16_t *)ip;

	/* pseudo header starts with source IP addr and dest IP addr */
	checksum  = p[6];
	checksum += p[7];
	checksum += p[8];
	checksum += p[9];

	checksum += IPPROTO_TCP;
	checksum += ippayloadlen;

	tcp->check = 0; /* clear out the checksum field */
	tcphdrlen = tcp->doff << 2;
	iterations = tcphdrlen >> 1; /* convert from units of bytes to units of 16-bit words */
	p = (uint16_t *)tcp;
	for (i = 0; i < iterations; i++)
		checksum += p[i];

	if (buf_count == 1) {
		iterations = (ippayloadlen - tcphdrlen) >> 1;
		p = p+i;
		for (i = 0; i < iterations; i++)
			checksum += p[i];

		if (ippayloadlen & 1) {
			/* ippayloadlen is odd */
			last_byte = *(uint8_t *)(p + iterations);
			checksum += last_byte << 8;
		}
	} else {
		/* Flag to indicate that we're dealing with the most significant
		 * byte of a 16-bit word */
		msb = 1;

		for (b = 1; b < buf_count; b++) {
			iterations = glist[b].s.size;
			byte_ptr = cvmx_phys_to_ptr(glist[b].s.addr);
			/* Iterate per byte instead of per 16-bit word
			 * because it's possible that a 16-bit word will
			 * straddle two adjacent buffers in the glist.
			 */
			for (i = 0; i < iterations; i++, msb=!msb)
				if (msb)
					checksum += byte_ptr[i] << 8;
				else
					checksum += byte_ptr[i];
		}
	}

	checksum = (uint16_t) checksum + (checksum >> 16);
	checksum = (uint16_t) checksum + (checksum >> 16);
	checksum = (uint16_t) (checksum ^ 0xffff);

	tcp->check = (uint16_t) checksum;
}

static void
cvmcs_nic_put_tcp_checksum_ipv6_glist(struct ipv6hdr *ip6, int exthdrs_len,
				      struct tcphdr *tcp, cvmx_buf_ptr_t *glist,
				      int buf_count)
{
	uint16_t *p;
	uint64_t checksum;
	int i, iterations, b, msb;
	uint32_t tcplen, tcphdrlen;
	uint8_t last_byte, *byte_ptr;

	p = (uint16_t *)&ip6->saddr;
	checksum = 0;
	for (i = 0; i < 16; i++)
		checksum += p[i];

	tcplen = (uint32_t)ip6->payload_len - (uint32_t)exthdrs_len;
	p = (uint16_t *)&tcplen;
	checksum += p[0];
	checksum += p[1];

	checksum += IPPROTO_TCP;

	tcp->check = 0;
	tcphdrlen = tcp->doff << 2;
	iterations = tcphdrlen >> 1; /* convert from units of bytes to units of 16-bit words */
	p = (uint16_t *)tcp;
	for (i = 0; i < iterations; i++)
		checksum += p[i];

	if (buf_count == 1) {
		iterations = (tcplen - tcphdrlen) >> 1;
		p = p+i;
		for (i = 0; i < iterations; i++)
			checksum += p[i];

		if (tcplen & 1) {
			/* tcplen is odd */
			last_byte = *(uint8_t *)(p + iterations);
			checksum += last_byte << 8;
		}
	} else {
		/* Flag to indicate that we're dealing with the most significant
		 * byte of a 16-bit word */
		msb = 1;

		for (b = 1; b < buf_count; b++) {
			iterations = glist[b].s.size;
			byte_ptr = cvmx_phys_to_ptr(glist[b].s.addr);
			/* Iterate per byte instead of per 16-bit word
			 * because it's possible that a 16-bit word will
			 * straddle two adjacent buffers in the glist.
			 */
			for (i = 0; i < iterations; i++, msb=!msb)
				if (msb)
					checksum += byte_ptr[i] << 8;
				else
					checksum += byte_ptr[i];
		}
	}

	checksum = (uint16_t) checksum + (checksum >> 16);
	checksum = (uint16_t) checksum + (checksum >> 16);
	checksum = (uint16_t) (checksum ^ 0xffff);

	tcp->check = (uint16_t) checksum;
}


static inline int
cvmcs_nic_process_tso_o3(cvmx_wqe_t *wqe, int ifidx, tso_hdr_info_t *tso_hdr)
{
	int is_ipv4opts=0;
	int ipv6exthdrs_len=0;
	uint8_t ipoffset;
	cvmx_buf_ptr_pki_t prev;
	cvmx_buf_ptr_pki_t prev_seg_buf;
	cvmcs_nic_metadata_t *mdata = CVMCS_NIC_METADATA(wqe);
	uint16_t gso_size= tso_hdr->gso_size, gso_segs=tso_hdr->gso_segs, last_gso_seg;
	uint16_t ip_id = 0, tcp_fin=0, tcp_psh=0, outer_ip_id = 0;
	uint32_t tcp_next_seq = 0;
	int32_t  i = 0, remaining = 0, ret = 0;
	int32_t lengths[512], dpi_hdr_len = 0;
	int32_t expctd_seglen = 0;
	/* don't explicitly initialize this array; each elem used is init'd
	 * by the code (this saves ~8200 cycles per pkt in s/w TSO) */
	struct tso_o3_pkt_desc temp_gather_list[512];
	uint8_t  l4_offset = 0;
	union octeon_rh dpi_rh;
	uint32_t npkt=0;
	int idx = (ifidx == -1) ? mdata->from_ifidx:ifidx;

	if (ifidx != -1) {
		/* we are sending these packets to a dpi port */
		dpi_rh.u64 = 0;
        	dpi_rh.r_dh.opcode = OPCODE_NIC;
        	dpi_rh.r_dh.subcode = OPCODE_NIC_NW_DATA;
        	if (CVMCS_NIC_METADATA_IS_TUNNEL(mdata))
                	dpi_rh.r_dh.csum_verified = CNNIC_TUN_CSUM_VERIFIED;
        	else
                	dpi_rh.r_dh.csum_verified = CNNIC_CSUM_VERIFIED;
#if 0 ///Raghu 73xx ptp disabled for now
        	dpi_rh.r_dh.has_hwtstamp = 1;
        	dpi_rh.r_dh.len = 1;
#endif
        	dpi_rh.r_dh.encap_on = CVMCS_NIC_METADATA_IS_ENCAP_ON(mdata);
                dpi_rh.r_dh.priority = mdata->front.irh.s.priority;
                dpi_rh.r_dh.vlan = mdata->front.irh.s.vlan;

		dpi_hdr_len = OCT_RH_SIZE;

                dpi_rh.r_dh.has_hash = 0x1; /* indicate RSS */
                dpi_rh.r_dh.len += 1;
		dpi_hdr_len += 8;
        }

	if ((gso_segs <= 0) || (gso_segs > 512))
		return -1;

	CVMX_SYNCWS;

	prev.u64 = prev_seg_buf.u64 = 0;

	print_debug("GSO SIZE : %d SEGS : %d TOT LEN : %d HEADER LEN : %d \n", gso_size, gso_segs, cvmx_wqe_get_len(wqe), CVMCS_NIC_METADATA_HEADER_LENGTH(mdata));
#if 0
	if (CVMCS_NIC_METADATA_IS_IPSEC_OP(mdata)) { //IPsec + TSO may have padding to be removed
		//TODO ipsec
		int pad_len = CVMCS_NIC_METADATA_IPSEC_PAD_LENGTH(mdata);
		cvmx_wqe_set_len(wqe,cvmx_wqe_get_len(wqe) - pad_len);
		//printf("\n padding = %d wqe len = %d ",pad_len,cvmx_wqe_get_len(wqe));
	}
#endif
        prev_seg_buf = cvmx_wqe_get_pki_pkt_ptr(wqe);
        prev_seg_buf.addr += CVMCS_NIC_METADATA_HEADER_LENGTH(mdata);
        prev_seg_buf.size = 0;
        remaining = cvmx_wqe_get_pki_pkt_ptr(wqe).size - CVMCS_NIC_METADATA_HEADER_LENGTH(mdata);
        prev = cvmx_wqe_get_pki_pkt_ptr(wqe);

	for(last_gso_seg = gso_segs-1, i=0; i<= last_gso_seg; i++) {
		struct tso_o3_gather_buf *glist_o3_ptr = NULL;
		cvmx_fpa3_gaura_t gaura;
		cvmx_buf_ptr_pki_t cur_buf;
		struct iphdr *ip4 = NULL;
		struct ipv6hdr *ip6 = NULL;
		struct tcphdr *tcp = NULL;
		uint8_t *proto_hdr_ptr = NULL;
		int32_t buf_cnt = 0, payload_size = 0;

		cur_buf.u64 = 0;

		glist_o3_ptr =  &temp_gather_list[i].g_bufs[0];
		if (CVMCS_NIC_METADATA_IS_IPSEC_OP(mdata))
			glist_o3_ptr += 3; // Making sure sufficient free space for 3 pointer at top

		/* Protocol header to store headers of segmented packets */
		proto_hdr_ptr = (uint8_t *) cvmx_fpa_alloc(CVMX_FPA_PROTOCOL_HEADER_POOL);
		if(NULL == proto_hdr_ptr ) {
			print_error("protocol header alloc failed\n");
			tso_free_lists_o3(temp_gather_list, 0 , i);
			per_core_stats[cvmx_get_core_num()].link_stats[idx].fromhost.fw_err_tso += 1;
			return -1;
		}
		
		if (dpi_hdr_len > 0){
			memcpy(proto_hdr_ptr, &dpi_rh, dpi_hdr_len);
		}

		npkt++;

		/* Copy protocol header from original packet */
		memcpy((uint8_t *)proto_hdr_ptr + dpi_hdr_len,
				cvmx_phys_to_ptr(wqe->packet_ptr.s.addr),
				CVMCS_NIC_METADATA_HEADER_LENGTH(mdata));

		/* Fill protocol header address in the gather list */

		glist_o3_ptr[buf_cnt].buf.u64 = 0;
		glist_o3_ptr[buf_cnt].buf.s.addr = cvmx_ptr_to_phys(proto_hdr_ptr);
		glist_o3_ptr[buf_cnt].buf.s.size = dpi_hdr_len + CVMCS_NIC_METADATA_HEADER_LENGTH(mdata);
		gaura = cvmx_fpa1_pool_to_fpa3_aura(CVMX_FPA_PROTOCOL_HEADER_POOL);
		glist_o3_ptr[buf_cnt].aura = (gaura.node << 10) | gaura.laura;
		/*
		 * Expected segment payload len
		 * 					=  gso size, for all segments except last segment
		 * 					<= gso_size, for last segment
		 */
		if (cvmx_unlikely(i == last_gso_seg))
			expctd_seglen = ((cvmx_wqe_get_len(wqe) - CVMCS_NIC_METADATA_HEADER_LENGTH(mdata)) - (gso_size*i));
		else
			expctd_seglen = gso_size;

		payload_size = 0;
		if(remaining) {
			/* If there are some bytes 'remaining' in a packet buffer from previous segment,
			 * 		Start the new segment in the same buffer
			 * Else
			 * 		Skip and Go to next packet buffer
			 */
			payload_size = (remaining > expctd_seglen)? expctd_seglen:remaining;

			buf_cnt++;
			if (buf_cnt > MAX_GATHER_BUFS_O3) {
				per_core_stats[cvmx_get_core_num()].link_stats[idx].fromhost.fw_err_tso += 1;
				tso_free_lists_o3(temp_gather_list, 0, i);
				return -1;
			}
			glist_o3_ptr[buf_cnt].buf.u64 = 0;
			glist_o3_ptr[buf_cnt].buf.s.addr = prev_seg_buf.addr + prev_seg_buf.size;
			glist_o3_ptr[buf_cnt].buf.s.size = payload_size;
			glist_o3_ptr[buf_cnt].buf.s.i = 1;
			glist_o3_ptr[buf_cnt].aura = cvmx_wqe_get_aura(wqe);
			remaining -= glist_o3_ptr[buf_cnt].buf.s.size;
		}

		while(payload_size < expctd_seglen) {
			buf_cnt++;
			cur_buf = *((cvmx_buf_ptr_pki_t *) cvmx_phys_to_ptr(prev.addr - 8));
			glist_o3_ptr[buf_cnt].buf.u64 = 0;
			glist_o3_ptr[buf_cnt].buf.s.addr = cur_buf.addr;
			glist_o3_ptr[buf_cnt].buf.s.size = (cur_buf.size > (expctd_seglen - payload_size))?
						(expctd_seglen - payload_size) : cur_buf.size;
			glist_o3_ptr[buf_cnt].buf.s.i = 1;
			glist_o3_ptr[buf_cnt].aura = cvmx_wqe_get_aura(wqe);
			payload_size += glist_o3_ptr[buf_cnt].buf.s.size;
			remaining = cur_buf.size - glist_o3_ptr[buf_cnt].buf.s.size;
			prev = cur_buf;
		}

		if (CVMCS_NIC_METADATA_IS_TUNNEL(mdata)) {
			if (!CVMCS_NIC_METADATA_IS_IPV6(mdata)) {
				ip4 = (struct iphdr *) (proto_hdr_ptr + CVMCS_NIC_METADATA_L3_OFFSET(mdata) + dpi_hdr_len);
				ip4->tot_len = payload_size + CVMCS_NIC_METADATA_HEADER_LENGTH(mdata) - CVMCS_NIC_METADATA_L3_OFFSET(mdata);
				if (i == 0)
                                	outer_ip_id = ip4->id ;

				ip4->id = outer_ip_id + i;

				/* OUTER IP HEADER CSUM */
				cvmcs_nic_ip_header_checksum(ip4, &ip4->check);

				if (CVMCS_NIC_METADATA_IS_UDP(mdata)) {
					struct udphdr *uh = (struct udphdr *) (proto_hdr_ptr + CVMCS_NIC_METADATA_L4_OFFSET(mdata) + dpi_hdr_len);
					uh->len = payload_size + CVMCS_NIC_METADATA_HEADER_LENGTH(mdata) 
						- CVMCS_NIC_METADATA_L4_OFFSET(mdata);
					uh->check = 0;
				}
			}
			else {
				ip6 = (struct ipv6hdr *) (proto_hdr_ptr + dpi_hdr_len + CVMCS_NIC_METADATA_L3_OFFSET(mdata));
				ip6->payload_len = payload_size + CVMCS_NIC_METADATA_HEADER_LENGTH(mdata) - 40 - CVMCS_NIC_METADATA_L3_OFFSET(mdata);
				if (CVMCS_NIC_METADATA_IS_UDP(mdata)) {
					struct udphdr *uh = (struct udphdr *) (proto_hdr_ptr + CVMCS_NIC_METADATA_L4_OFFSET(mdata) + dpi_hdr_len);
					uh->len = ip6->payload_len;
					uh->check = 0;
				}
			}
		}

		if (!tso_hdr->is_v6) {
			ip4 = (struct iphdr *) (proto_hdr_ptr + dpi_hdr_len + tso_hdr->ip_offset);
                        if (i == 0) {
                                if (ip4->ihl > 5)
                                        is_ipv4opts = 1;
                                ip_id = ip4->id;
                        }

                        ip4->id = ip_id + i;

			ip4->tot_len = payload_size + CVMCS_NIC_METADATA_HEADER_LENGTH(mdata) - tso_hdr->ip_offset;
			tcp = (struct tcphdr *) (proto_hdr_ptr + dpi_hdr_len + tso_hdr->tcp_offset);
		}
		else {
                        if (i == 0) {
                                ip6 = tso_hdr->iphdr;
                                tcp = tso_hdr->tcp;

                                ipv6exthdrs_len = (uint8_t *)tcp - (uint8_t*)ip6 - 40;
                        }

			ip6 = (struct ipv6hdr *) (proto_hdr_ptr + dpi_hdr_len + tso_hdr->ip_offset);
			tcp = (struct tcphdr *) (proto_hdr_ptr + dpi_hdr_len + tso_hdr->tcp_offset);
			ip6->payload_len = payload_size + CVMCS_NIC_METADATA_HEADER_LENGTH(mdata) -
tso_hdr->ip_offset - 40;
		}

                if(i == 0) {
                        tcp_next_seq = tcp->seq;
                        /* If TCP FIN or PSH is set, reset them in first segment */
                        tcp_fin = tcp->fin;
                        tcp_psh = tcp->psh;
                }

		tcp->seq = tcp_next_seq;
		tcp_next_seq = tcp->seq + payload_size;

		/* Retain FIN and PSH bits for last segment
		 * For other segments, reset
		 */
		tcp->fin = (i == last_gso_seg) ? tcp_fin:0;
		tcp->psh = (i == last_gso_seg) ? tcp_psh:0;

		prev_seg_buf.u64 = 0;
		prev_seg_buf.addr = glist_o3_ptr[buf_cnt].buf.s.addr;
		prev_seg_buf.size = glist_o3_ptr[buf_cnt].buf.s.size;

		temp_gather_list[i].nbufs = buf_cnt + 1;
		lengths[i] = payload_size + dpi_hdr_len + CVMCS_NIC_METADATA_HEADER_LENGTH(mdata);

		if (!tso_hdr->is_v6) {
			if (is_ipv4opts) {
				//TODO options can be handled by PKO3
				//cvmcs_nic_put_tcp_checksum_ipv4_glist(ip4, tcp, glist_ptr, buf_cnt+1);
			}
		} else if (ipv6exthdrs_len > 0) {
				//TODO extensions can be handled by PKO3
			//cvmcs_nic_put_tcp_checksum_ipv6_glist(ip6, ipv6exthdrs_len, tcp, glist_ptr, buf_cnt+1);
		}

	}

	if (CVMCS_NIC_METADATA_IS_IPSEC_OP(mdata))
                return cvmcs_nic_process_ipsec_o3(wqe, temp_gather_list,
                        lengths, gso_segs, ifidx);

	// PKO3 can calculate checksums when options/ext hdrs are present.
	ipoffset = tso_hdr->ip_offset + dpi_hdr_len;
	l4_offset = tso_hdr->tcp_offset + dpi_hdr_len;

	if (CVMCS_NIC_METADATA_IS_TUNNEL(mdata)) {
		per_core_stats[cvmx_get_core_num()].link_stats[mdata->from_ifidx].fromhost.fw_tx_vxlan += npkt;
	}
	per_core_stats[cvmx_get_core_num()].link_stats[idx].fromhost.fw_tso_fwd += npkt;
	per_core_stats[cvmx_get_core_num()].link_stats[idx].fromhost.fw_tso += 1;


	ret = cvmcs_nic_send_gather_list_to_pko3(temp_gather_list, ifidx, lengths, wqe,
				gso_segs, ipoffset, l4_offset);

	return ret;
}


static inline int
cvmcs_nic_process_hw_tso_o3(cvmx_wqe_t *wqe, int ifidx, tso_hdr_info_t *tso_hdr)
{
	vnic_port_info_t *nicport;
	uint8_t  l4_offset,l3_offset = 0;
	cvmx_pko_send_hdr_t hdr_s;
	cvmx_pko_query_rtn_t pko_status;
	cvmx_buf_ptr_pki_t *tmp_lptr;
	int port, dq;
	unsigned node, nwords;
	unsigned scr_base = cvmx_pko3_lmtdma_scr_base();
	uint64_t nextptr;
	cvmcs_nic_metadata_t *mdata = CVMCS_NIC_METADATA(wqe);
	int idx = (ifidx == -1) ? mdata->from_ifidx:ifidx;
	
	if (CVMCS_NIC_METADATA_IS_IPSEC_OP(mdata)) {
		cvmcs_nic_add_ipsec_tso_info_o3(wqe, tso_hdr);
		port = CVM_PHYS_78XX_LOOPBACK_IPSEC_PORT;
		dq = cvmx_pko_get_base_queue(port);
	} else {
#ifdef VSWITCH
		nicport = &octnic->port[mdata->to_ifidx];
#else	
		nicport = &octnic->port[mdata->from_ifidx];
#endif
		port = nicport->linfo.gmxport;
		dq = cvmcs_dcb_get_dq(wqe, port);
	}

	if(cvmx_unlikely(port == -1 || dq == -1)) {
		per_core_stats[cvmx_get_core_num()].link_stats[idx].fromhost.fw_err_drop += 1;
		per_core_stats[cvmx_get_core_num()].link_stats[idx].fromhost.fw_err_tso += 1;
		print_error("Error port :%d queue: %d \n",port, dq);
		//packet will be freed by caller
		return -1;
	} else {
		per_core_stats[cvmx_get_core_num()].link_stats[idx].fromhost.fw_tso += 1;
	}

	l3_offset = tso_hdr->ip_offset;
	l4_offset = tso_hdr->tcp_offset;

	//printf("hw tso port %d dq %d\n", port, dq);
	//printf("hw tso gso_segs %d gso_size %d hdr_len %d l3_offset %d l4_offset %d\n", gso_segs, gso_size, tso_hdr->hdr_len, l3_offset, l4_offset);
	//printf("hw tso wqe total len %d\n", cvmx_wqe_get_len(wqe));

	/* Separate global DQ# into node and local DQ */
	node = dq >> 10;
	dq &= (1 << 10)-1;

	cvmx_pow_tag_sw_full(wqe, (cvmx_wqe_get_tag(wqe)^dq), CVMX_POW_TAG_TYPE_ATOMIC, cvmx_wqe_get_grp(wqe));

	/* Fill in header */
	hdr_s.u64 = 0;
	hdr_s.s.total = cvmx_wqe_get_len(wqe);
	hdr_s.s.df = 0;
	hdr_s.s.ii = 0;
	//hdr_s.s.n2 = 1;	/* No L2 allocate works faster */
	hdr_s.s.aura = cvmx_wqe_get_aura(wqe);
#ifdef __LITTLE_ENDIAN_BITFIELD
	hdr_s.s.le = 1;
#endif
	if (!tso_hdr->is_v6)
		hdr_s.s.ckl3 = 1;
	hdr_s.s.l3ptr =  l3_offset;
	hdr_s.s.ckl4 = CKL4ALG_TCP;
	hdr_s.s.l4ptr = l4_offset;
	nwords = 0;
	cvmx_scratch_write64(scr_base+sizeof(uint64_t)*(nwords++), hdr_s.u64);

	{
		cvmx_pko_send_tso_t send_tso;
		send_tso.u64 = 0;
		/* rtf - 20151211; see 73xx HRM PKO_SEND_TSO_S section
		 * "...PKO_SEND_HDR_S[L3PTR] = [L2LEN] + 2" */
		send_tso.s.l2len = l3_offset-2;
		send_tso.s.subdc4 = CVMX_PKO_SENDSUBDC_TSO;
		send_tso.s.sb = tso_hdr->hdr_len;
		send_tso.s.mss = tso_hdr->mss;
		cvmx_scratch_write64(scr_base+sizeof(uint64_t)*(nwords++), send_tso.u64);
	}

	/*pko can be slow if linked mode is used 
	 * and Making a gather entry for each link
	 * involves sw cycles, 
	 * TODO find which is worse 
	 * */
//#define HW_TSO_SEND_LINK
//for some reason linked bufs with TSO is not working
//throws  PKO_PEB interrupt
#ifdef HW_TSO_SEND_LINK
	#define MAX_PKO_LINKED_BUFS 200
	if (cvmx_wqe_get_bufs(wqe) > MAX_PKO_LINKED_BUFS) {
		print_debug("error too many links \n");
		//packet will be freed by caller
		goto err;
	}
	{
		cvmx_pko_buf_ptr_t send_link;
		tmp_lptr = (cvmx_buf_ptr_pki_t *)&wqe->packet_ptr;
		send_link.u64 = 0;
		send_link.s.subdc3 = CVMX_PKO_SENDSUBDC_LINK;
		send_link.s.addr = tmp_lptr->addr;
		send_link.s.size = tmp_lptr->size;
		//printf("send_link addr 0x%016lx\n", (unsigned long)send_link.s.addr);
		//printf("send_link size %d\n", send_link.s.size);
		cvmx_scratch_write64(scr_base+sizeof(uint64_t)*(nwords++), send_link.u64);
	}
afdasas
#else
	{
		int total_size = cvmx_wqe_get_len(wqe);
		int i;
		cvmx_pko_buf_ptr_t send_gather;
		int count = cvmx_wqe_get_bufs(wqe);
		uint64_t *jump_buf=NULL;
		uint16_t pko_gaura=0;
		///TODO get size with hard coding
		const int jump_buf_size = 4*1024 / sizeof(uint64_t);
		#define MAX_PKO_GATHER_BUFS 13 //discount sendhdr and sendtso
		#define MAX_PKO_JUMP_BUFS 255
		//leave 2 one for aura one for wqe response
		if (count > MAX_PKO_JUMP_BUFS || count > (jump_buf_size-2)) {
			print_debug("error too many links \n");
			//packet will be freed by caller
			goto err;
		}
		//Need Jump buf
		if (count > MAX_PKO_GATHER_BUFS) {
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
				goto err;
			}
			jump_s.u64 = 0;
			jump_s.s.addr = cvmx_ptr_to_phys(jump_buf);
			jump_s.s.i = 1;
			// the extra one is for aura
			jump_s.s.size = count+1;
			jump_s.s.subdc3 = CVMX_PKO_SENDSUBDC_JUMP;
			cvmx_scratch_write64(scr_base+sizeof(uint64_t)*(nwords++), jump_s.u64);
		}
		tmp_lptr = (cvmx_buf_ptr_pki_t *)&wqe->packet_ptr;
		for (i = 0; i < count; i++) {
			//printf("link %d addr 0x%016lx  size %d\n",  i, (unsigned long)tmp_lptr->addr, tmp_lptr->size);
			send_gather.u64= 0;
			if ( i != count-1) {
				send_gather.s.size = tmp_lptr->size;
				total_size -= tmp_lptr->size;
			} else {
				//printf("size left in last buf %d\n", total_size);
				send_gather.s.size = total_size;
			}
			send_gather.s.subdc3 = CVMX_PKO_SENDSUBDC_GATHER;
			send_gather.s.addr = tmp_lptr->addr;
			if (jump_buf)
				jump_buf[i] = send_gather.u64;
			else
				cvmx_scratch_write64(scr_base+sizeof(uint64_t)*(nwords++), send_gather.u64);
			nextptr = *((uint64_t *)CVM_DRV_GET_PTR(tmp_lptr->addr - 8));
			tmp_lptr = (cvmx_buf_ptr_pki_t *)&nextptr;
		} 
		//last aura is for jump_buf
		if (jump_buf) {
			cvmx_pko_send_aura_t aura_s;
			aura_s.u64=0;
			aura_s.s.aura = pko_gaura;
			aura_s.s.offset = 0;
			aura_s.s.alg = AURAALG_NOP;
			aura_s.s.subdc4 = CVMX_PKO_SENDSUBDC_AURA;
			jump_buf[i] = aura_s.u64;
		}
	}
#endif
		

	CVMX_SYNCWS;
	/* Do LMTDMA */
	cvmx_pow_tag_sw_wait();
	pko_status = cvmcs_pko3_lmtdma(node, dq, nwords, false, true);

	if (cvmx_likely(pko_status.s.dqstatus != PKO_DQSTATUS_PASS)) {
		print_debug("error sending packet\n");
		//packet will be freed by caller
		goto err;
	}


	//dont free wqe , assuming dis_wq_dat=0
	{
		if (ifidx == -1) {
			per_core_stats[cvmx_get_core_num()].link_stats[idx].fromhost.fw_tso_fwd += tso_hdr->gso_segs;
		} else {
			print_error("should not come here, hw tsoed packets cannot go to dpi\n");
		}
	}

	return 0;
err:
	print_debug("too many send descs\n");
	per_core_stats[cvmx_get_core_num()].link_stats[idx].fromhost.fw_err_pko += 1;
	per_core_stats[cvmx_get_core_num()].link_stats[idx].fromhost.fw_err_tso += 1;
	return -1;
}


static inline int
cvmcs_nic_process_tso(cvmx_wqe_t *wqe, int ifidx, tso_hdr_info_t *tso_hdr)
{
	int is_ipv4opts=0;
	int ipv6exthdrs_len=0;
	uint8_t ipoffset;
	cvmx_buf_ptr_t temp_gather_list[512];
	cvmx_buf_ptr_t prev;
	cvmx_buf_ptr_t prev_seg_buf;
	uint16_t ip_id = 0, tcp_fin=0, tcp_psh=0, outer_ip_id = 0;
	uint16_t gso_size = tso_hdr->gso_size, gso_segs = tso_hdr->gso_segs;
	uint32_t tcp_next_seq = 0;
	int32_t  i = 0, remaining = 0, ret = 0;
	int32_t lengths[512], dpi_hdr_len = 0;
	int32_t expctd_seglen = 0;
	union octeon_rh dpi_rh;
	cvmcs_nic_metadata_t *mdata = CVMCS_NIC_METADATA(wqe);

	cvmx_fpa_async_alloc(CVMCS_TEST_BUF_PTR, CVMX_FPA_GATHER_LIST_POOL);

	if (ifidx != -1) {
		/* we are sending these packets to a dpi port */
		dpi_rh.u64 = 0;
        	dpi_rh.r_dh.opcode = OPCODE_NIC;
        	dpi_rh.r_dh.subcode = OPCODE_NIC_NW_DATA;
        	if (CVMCS_NIC_METADATA_IS_TUNNEL(mdata))
                	dpi_rh.r_dh.csum_verified = CNNIC_TUN_CSUM_VERIFIED;
        	else
                	dpi_rh.r_dh.csum_verified = CNNIC_CSUM_VERIFIED;
        	dpi_rh.r_dh.has_hwtstamp = 1;
        	dpi_rh.r_dh.len = 1;
        	dpi_rh.r_dh.encap_on = CVMCS_NIC_METADATA_IS_ENCAP_ON(mdata);
                dpi_rh.r_dh.priority = mdata->front.irh.s.priority;
                dpi_rh.r_dh.vlan = mdata->front.irh.s.vlan;

		dpi_hdr_len = OCT_RH_SIZE;

                dpi_rh.r_dh.has_hash = 0x1; /* indicate hash */
                dpi_rh.r_dh.len += 1;
		dpi_hdr_len += 8;
	}

	if ((gso_segs <= 0) || (gso_segs > 512))
		return -1;

	CVMX_SYNCWS;

	prev.u64 = prev_seg_buf.u64 = 0;
	mdata->front.irh.s.opcode = OPCODE_NIC;
	mdata->front.irh.s.subcode = OCT_NIC_TSO_COMPLETION_OP;

	print_debug("GSO SIZE : %d SEGS : %d TOT LEN : %d HEADER LEN : %d \n", gso_size, gso_segs, cvmx_wqe_get_len(wqe), CVMCS_NIC_METADATA_HEADER_LENGTH(mdata));

#if 0
	if (CVMCS_NIC_METADATA_IS_IPSEC_OP(mdata)) { //IPsec + TSO may have padding to be removed
		int pad_len = CVMCS_NIC_METADATA_IPSEC_PAD_LENGTH(mdata);
		cvmx_wqe_set_len(wqe,cvmx_wqe_get_len(wqe) - pad_len);
		//printf("\n padding = %d wqe len = %d ",pad_len,cvmx_wqe_get_len(wqe));
	}
#endif
	prev_seg_buf = wqe->packet_ptr;
	prev_seg_buf.s.addr += CVMCS_NIC_METADATA_HEADER_LENGTH(mdata);
	prev_seg_buf.s.size = 0;
	remaining = wqe->packet_ptr.s.size - CVMCS_NIC_METADATA_HEADER_LENGTH(mdata);
	prev = wqe->packet_ptr;

	for(i=0; i< gso_segs; i++) {
		cvmx_buf_ptr_t *glist_ptr = NULL;
		cvmx_buf_ptr_t cur_buf;
		struct iphdr *ip4 = NULL;
		struct ipv6hdr *ip6 = NULL;
		struct tcphdr *tcp = NULL;
		uint8_t *proto_hdr_ptr = NULL;
		int32_t buf_cnt = 0, payload_size = 0;

		cur_buf.u64 = 0;

		/* Gather list to stored buffer addresses of segmented packet */
		glist_ptr = (cvmx_buf_ptr_t *) cvmx_fpa_async_alloc_finish(
								CVMCS_TEST_BUF_PTR, CVMX_FPA_GATHER_LIST_POOL);
		if(NULL == glist_ptr ) {
			print_error("Gather list alloc failed\n");
			tso_free_lists(temp_gather_list, 0, i);
			return -1;
		}

		if (CVMCS_NIC_METADATA_IS_IPSEC_OP(mdata))
			glist_ptr += 5; // Making sure sufficient free space for 5 pointer at top

                /* Protocol header to store headers of segmented packets */
                proto_hdr_ptr = (uint8_t *) cvmx_fpa_alloc(CVMX_FPA_PROTOCOL_HEADER_POOL);
                if(NULL == proto_hdr_ptr ) {
                	print_error("protocol header alloc failed\n");
                        cvmx_fpa_free(glist_ptr, CVMX_FPA_GATHER_LIST_POOL, 0);
                        tso_free_lists(temp_gather_list, 0, i);
                        return -1;
                }

		if (dpi_hdr_len > 0) {
			memcpy(proto_hdr_ptr, &dpi_rh, dpi_hdr_len);
		}

                /* Copy protocol header from original packet */
                memcpy((uint8_t *)proto_hdr_ptr + dpi_hdr_len,
                        	cvmx_phys_to_ptr(wqe->packet_ptr.s.addr),
                        	CVMCS_NIC_METADATA_HEADER_LENGTH(mdata));

                /* Fill protocol header address in the gather list */
                glist_ptr[buf_cnt].u64 = 0;
                glist_ptr[buf_cnt].s.addr = cvmx_ptr_to_phys(proto_hdr_ptr);
                glist_ptr[buf_cnt].s.size = dpi_hdr_len + CVMCS_NIC_METADATA_HEADER_LENGTH(mdata);
                glist_ptr[buf_cnt].s.pool = CVMX_FPA_PROTOCOL_HEADER_POOL;

                /*
		 * Expected segment payload len
 		 *          =  gso size, for all segments except last segment
                 *          <= gso_size, for last segment
                 */
                expctd_seglen = (i == (gso_segs-1))?
                                ((cvmx_wqe_get_len(wqe) - CVMCS_NIC_METADATA_HEADER_LENGTH(mdata)) - (gso_size*i)) : gso_size;

                payload_size = 0;

                if(remaining) {
                	/* If there are some bytes 'remaining' in a packet
  			 * buffer from previous segment, Start the new segment
  			 * in the same buffer
                         * Else Skip and Go to next packet buffer
                         */
                        payload_size = (remaining > expctd_seglen)? expctd_seglen:remaining;

                        buf_cnt++;
                        glist_ptr[buf_cnt].u64 = 0;
                        glist_ptr[buf_cnt].s.addr = prev_seg_buf.s.addr + prev_seg_buf.s.size;
                        glist_ptr[buf_cnt].s.size = payload_size;
                        glist_ptr[buf_cnt].s.i = 1;

                        remaining -= glist_ptr[buf_cnt].s.size;
                }

                while(payload_size < expctd_seglen) {
                        /* Data present in more packet buffers */
                        buf_cnt++;

                        /* Fetch the next buffer and add entry in gather list */
                        cur_buf = *((cvmx_buf_ptr_t *) cvmx_phys_to_ptr(prev.s.addr - 8));

                        /* Fill the buffer address in gather list */
                        glist_ptr[buf_cnt].u64 = 0;
                        glist_ptr[buf_cnt].s.addr = cur_buf.s.addr;
                        glist_ptr[buf_cnt].s.size =
				(cur_buf.s.size > (expctd_seglen - payload_size))?
        			(expctd_seglen - payload_size) : cur_buf.s.size;
                        glist_ptr[buf_cnt].s.i = 1;

                        payload_size += glist_ptr[buf_cnt].s.size;
                        remaining = cur_buf.s.size - glist_ptr[buf_cnt].s.size;

                        prev = cur_buf;
		}

		/* UPDATE TUNNEL FRAME */
                if (CVMCS_NIC_METADATA_IS_TUNNEL(mdata)) {
                        if (!CVMCS_NIC_METADATA_IS_IPV6(mdata)) {
                		ip4 = (struct iphdr *) (proto_hdr_ptr + CVMCS_NIC_METADATA_L3_OFFSET(mdata) + dpi_hdr_len);
                                ip4->tot_len = payload_size + CVMCS_NIC_METADATA_HEADER_LENGTH(mdata) - CVMCS_NIC_METADATA_L3_OFFSET(mdata);
				if (i == 0)
					outer_ip_id = ip4->id ;

                                ip4->id = outer_ip_id + i;

                                /* OUTER IP HEADER CSUM */
                                cvmcs_nic_ip_header_checksum(ip4, &ip4->check);
                        }
                        else {
                                ip6 = (struct ipv6hdr *) (proto_hdr_ptr + CVMCS_NIC_METADATA_L3_OFFSET(mdata) + dpi_hdr_len);
                                ip6->payload_len = payload_size + CVMCS_NIC_METADATA_HEADER_LENGTH(mdata) - 40 - CVMCS_NIC_METADATA_L3_OFFSET(mdata);
                        }
               }

               if (!tso_hdr->is_v6) {
                        ip4 = (struct iphdr *) (proto_hdr_ptr + dpi_hdr_len + tso_hdr->ip_offset);
			if (i == 0) {
                                if (ip4->ihl > 5)
                                        is_ipv4opts = 1;
				ip_id = ip4->id;
			}

                        ip4->id = ip_id + i;

                        ip4->tot_len = payload_size + CVMCS_NIC_METADATA_HEADER_LENGTH(mdata) - tso_hdr->ip_offset;
                        tcp = (struct tcphdr *) (proto_hdr_ptr + dpi_hdr_len + tso_hdr->tcp_offset);
               }
               else {
			if (i == 0) {
                                ip6 = tso_hdr->iphdr;
                                tcp = tso_hdr->tcp;

                                ipv6exthdrs_len = (uint8_t *)tcp - (uint8_t*)ip6 - 40;
			}

                        ip6 = (struct ipv6hdr *) (proto_hdr_ptr + dpi_hdr_len + tso_hdr->ip_offset);
                        tcp = (struct tcphdr *) (proto_hdr_ptr + dpi_hdr_len + tso_hdr->tcp_offset);

                        ip6->payload_len = payload_size + CVMCS_NIC_METADATA_HEADER_LENGTH(mdata) - tso_hdr->ip_offset - 40;

                }

		if(i == 0) {
			tcp_next_seq = tcp->seq;
			/* If TCP FIN or PSH is set, reset them in first segment */
			tcp_fin = tcp->fin;
			tcp_psh = tcp->psh;
		}

		tcp->seq = tcp_next_seq;
		tcp_next_seq = tcp->seq + payload_size;

		/* Retain FIN and PSH bits for last segment
		 * For other segments, reset
		 */
		tcp->fin = (i == (gso_segs-1)) ? tcp_fin:0;
		tcp->psh = (i == (gso_segs-1)) ? tcp_psh:0;

		prev_seg_buf = glist_ptr[buf_cnt];
		temp_gather_list[i].u64 = 0;
		temp_gather_list[i].s.addr = cvmx_ptr_to_phys(glist_ptr);
		temp_gather_list[i].s.size = buf_cnt + 1;
		temp_gather_list[i].s.pool = CVMX_FPA_GATHER_LIST_POOL;

		lengths[i] = payload_size + CVMCS_NIC_METADATA_HEADER_LENGTH(mdata) + dpi_hdr_len;

		if (!tso_hdr->is_v6) {
			cvmcs_nic_ip_header_checksum(ip4, &ip4->check);
			if (is_ipv4opts)
				cvmcs_nic_put_tcp_checksum_ipv4_glist(ip4, tcp, glist_ptr, buf_cnt+1);
		} else if (ipv6exthdrs_len > 0) {
			cvmcs_nic_put_tcp_checksum_ipv6_glist(ip6, ipv6exthdrs_len, tcp, glist_ptr, buf_cnt+1);
		}

		if(i != gso_segs-1)
			cvmx_fpa_async_alloc(CVMCS_TEST_BUF_PTR, CVMX_FPA_GATHER_LIST_POOL);
	}

	if (CVMCS_NIC_METADATA_IS_IPSEC_OP(mdata)) {
		return cvmcs_nic_process_ipsec(wqe, temp_gather_list, lengths, gso_segs,
				CVMCS_NIC_METADATA_IPSEC_ESP_AH_OFFSET(mdata),
				CVMCS_NIC_METADATA_IPSEC_ESP_AH_HDRLEN(mdata), ifidx);
	}

	if (is_ipv4opts || ipv6exthdrs_len > 0)
		ipoffset = 0;
	else
		ipoffset = tso_hdr->ip_offset + dpi_hdr_len;

	ret = cvmcs_nic_send_gather_list_to_pko(temp_gather_list, ifidx, lengths,
					wqe, gso_segs, ipoffset);
	return ret;
}

static inline int
check_hw_tso_valid_pkt(cvmx_wqe_t *wqe, tso_hdr_info_t *tso_hdr)
{
/* [MSS] must be >= 576.
 * [MSS] must be <= 1535 whenever PKO considers the length/type field selected
 * by [L2LEN] to be a length field.
 */
#define MIN_HW_TSO_MSS_LEN 576
#define MAX_HW_TSO_MSS_LEN 1535
#define MAX_HW_TSO_SEGS 128
/* rtf - 20151215
 * Errata 73xx PKO-24989 limits PKO_JUMP to 31 segs.
 *  1 seg is reserved for Aura
 *  1 seg (first) at (2K buf - WORD0..4 - FIRST_SKIP_WORDS = 2048-40-256 = 1752)
 * 29 segs at (2K buf - 8B link = 2040)
 * Max Total = (1 * 1752) + (29 * 2040) = 60912
 */
#define PKO_BUG_24989_WQE_LEN (60912)
	struct tcphdr *tcp;
	cvmcs_nic_metadata_t *mdata = CVMCS_NIC_METADATA(wqe);

	/* rtf - 20151211
	 * The h/w TSO segment calculation is independent of what the s/w says.
	 * See HRM PKO_SEND_TSO_S description
	 */
	/* For Jumbo frames MSS length may be greater than 1535, then try to use 
	 * software based TSO segmentation */
	if ((tso_hdr->gso_segs > MAX_HW_TSO_SEGS) ||
	    (tso_hdr->mss < MIN_HW_TSO_MSS_LEN) ||
	    (tso_hdr->mss > MAX_HW_TSO_MSS_LEN) ||
	    CVMCS_NIC_METADATA_IS_DUP_WQE(mdata) ||
	    CVMCS_NIC_METADATA_IS_TUNNEL(mdata)  ||
	    ((cvmx_wqe_get_len(wqe) > PKO_BUG_24989_WQE_LEN) &&
	     OCTEON_IS_MODEL(OCTEON_CN73XX_PASS1_X))) {
		return -1;
	}

	if (CVMCS_NIC_METADATA_IS_IPV4(mdata) &&
	    CVMCS_NIC_METADATA_IS_IP_FRAG(mdata)) {
		print_debug("IP Fragment [%x]\n", iph4->frag_off);
		return -1;
	}

	if (!CVMCS_NIC_METADATA_IS_TCP(mdata)) {
		print_debug("IP Protocol[%x] is NOT Tcp\n", iph4->protocol);
		return -1;
	}

	tcp = tso_hdr->tcp;

	if(tcp->syn || tcp->urg || tcp->rst) {
		print_debug("TCP flags set syn[%x] urg[%x] rst[%x]\n",
				tcp->syn, tcp->urg, tcp->rst);
		return -1;
	}

	if(tcp->urg_ptr) {
		print_debug("TCP urg ptr[%x] is set\n", tcp->urg_ptr);
		return -1;
	}

	return 0;
}
static inline int
check_tso_valid_pkt(cvmx_wqe_t *wqe, tso_hdr_info_t *tso_hdr)
{
	bool is_v6;
	struct tcphdr *tcp;
	struct iphdr *iph4;
	cvmcs_nic_metadata_t *mdata = CVMCS_NIC_METADATA(wqe);

	if (CVMCS_NIC_METADATA_IS_TUNNEL(mdata)) {
		/* CHECK FOR VLAN PACKET */
		if (CVMCS_NIC_METADATA_IS_VLAN(mdata)) {
			if ((!CVMCS_NIC_METADATA_IS_IPV4(mdata)) &&
			    (!CVMCS_NIC_METADATA_IS_IPV6(mdata)))
				return -1;
		}

		/* CHECKS FOR OUTER IP */
		if (CVMCS_NIC_METADATA_IS_IPV4(mdata)) {
			iph4 = (struct iphdr *)CVMCS_NIC_METADATA_L3_HEADER(mdata);
			if ((iph4->frag_off & IP_MF) ||
				(iph4->frag_off & IP_OFFSET))
				return -1;
		}

		if ((!CVMCS_NIC_METADATA_IS_GRE(mdata)) &&
		    (!CVMCS_NIC_METADATA_IS_UDP(mdata)) &&
		    (!CVMCS_NIC_METADATA_IS_IPSEC_OP(mdata)))
			return -1;

		if (CVMCS_NIC_METADATA_IS_GRE(mdata) &&
		   (!CVMCS_NIC_METADATA_IS_IPSEC_OP(mdata))) {
			struct gre_hdr *gre = (struct gre_hdr *)CVMCS_NIC_METADATA_L4_HEADER(mdata);
#ifdef VSWITCH
			if (gre->C || gre->R || gre->S)
				return -1;
#else
			if (!gre->K || gre->C || gre->R || gre->S)
				return -1;
#endif //VSWITCH
		}
		else if (!CVMCS_NIC_METADATA_IS_IPSEC_OP(mdata)) {
#ifdef VSWITCH
			struct udphdr *udph = (struct udphdr *)CVMCS_NIC_METADATA_L4_HEADER(mdata);
			if (!is_tunnel(IPPROTO_UDP, udph->dest))
				return -1;
#endif //VSWITCH
		}
	}

	is_v6 = tso_hdr->is_v6;
	tcp = tso_hdr->tcp;

	if (!is_v6) {
		iph4 = (struct iphdr *)tso_hdr->iphdr;

		if (iph4->frag_off & IP_MF) {
			print_debug("IP MF is set[%x]\n", iph4->frag_off);
			return -1;
		}

		if (iph4->frag_off & IP_OFFSET) {
			print_debug("IP Frag offset is set[%x]\n", iph4->frag_off);
			return -1;
		}

		if ((!CVMCS_NIC_METADATA_IS_IPSEC_OP(mdata)) && (iph4->protocol != IPPROTO_TCP)) {
			print_debug("IP Protocol[%x] is NOT Tcp\n", iph4->protocol);
			return -1;
		}
	}

	if(tcp->syn || tcp->urg || tcp->rst) {
		print_debug("TCP flags set syn[%x] urg[%x] rst[%x]\n",
				tcp->syn, tcp->urg, tcp->rst);
		return -1;
	}

	if(tcp->urg_ptr) {
		print_debug("TCP urg ptr[%x] is set\n", tcp->urg_ptr);
		return -1;
	}

	return 0;
}

int
cvmcs_nic_handle_tso(cvmx_wqe_t *wqe, int ifidx)
{
	tso_hdr_info_t tso_hdr;
	cvmcs_nic_metadata_t *mdata = CVMCS_NIC_METADATA(wqe);

	tso_init_hdr_info(wqe, ifidx, &tso_hdr);

	if ((!(mdata->ipsec_esp_ah_hdrlen)) && CVMCS_NIC_METADATA_IS_IPSEC_OP(mdata))
		return -1;	

	if (OCTEON_IS_MODEL(OCTEON_CN73XX) && (ifidx == -1) &&
	   (!check_hw_tso_valid_pkt(wqe, &tso_hdr))) {
		return cvmcs_nic_process_hw_tso_o3(wqe, ifidx, &tso_hdr);
	}

	if (check_tso_valid_pkt(wqe, &tso_hdr)) {
		print_debug("PACKET NOT VALID FOR TSO ...\n");
		return -1;
	}

	if (octeon_has_feature(OCTEON_FEATURE_PKO3))
		return cvmcs_nic_process_tso_o3(wqe, ifidx, &tso_hdr);
	else
		return cvmcs_nic_process_tso(wqe, ifidx, &tso_hdr);
}
