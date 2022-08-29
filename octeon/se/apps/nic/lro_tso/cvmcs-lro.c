#include "cvmcs-common.h"
#include "cvmcs-nic.h"
#include "cvmcs-lro.h"
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

#ifdef DEBUG
#define print_error(msg, ...)   printf(msg,##__VA_ARGS__)
#define print_debug(msg, ...)   printf(msg,##__VA_ARGS__)
#else
#define print_error(msg, ...)   printf(msg,##__VA_ARGS__)
#define print_debug(msg, ...)
#endif

#define PACKET_START(WQE)       cvmx_phys_to_ptr(WQE->packet_ptr.s.addr)

static inline void *packet_start(cvmx_wqe_t * wqe)
{
	return (cvmx_phys_to_ptr(wqe->packet_ptr.s.addr));
}

static inline int lro_l2_hdr_len(cvmx_wqe_t * wqe, void *pkt_start)
{
	/* includes PTP timestamp */
	struct ethhdr *eth = (struct ethhdr *)
	    (pkt_start ? pkt_start : (uint8_t *) packet_start(wqe) + 8);

	if (eth->h_proto != ETH_P_8021Q)
		return ETH_HLEN;
	else {
		DBG("VLAN header\n");
		return VLAN_ETH_HLEN;
	}
}

inline uint16_t lro_get_l3_hdr_type(cvmx_wqe_t * wqe, void **l3_hdr)
{
	struct ethhdr *inner_eth;

	if (!wqe->word2.s.not_IP) {
		if (!wqe->word2.s.is_v6) {
			struct iphdr *iph = packet_start(wqe) +
			    wqe->word2.s.ip_offset;

			if (iph->protocol == IPPROTO_GRE) {
				/*
				 * On the encapsulation side, a tunnel packet
				 * should not include an inner VLAN tag unless
				 * configured otherwise.
				 */
				inner_eth = (void *)iph +
				    (iph->ihl << 2) + sizeof(gre_hdr_t) +
				    sizeof(gre_key_hdr_t);

				*l3_hdr = (void *)inner_eth +
				    lro_l2_hdr_len(wqe, (void *)inner_eth);

				return inner_eth->h_proto;
			} else if (iph->protocol == IPPROTO_UDP) {
				struct udphdr *udph =
				    (struct udphdr *)((void *)iph +
						      (iph->ihl << 2));

				if (udph->dest == VTEP_UDP_SERVER_PORT1) {
					inner_eth = (void *)udph +
					    sizeof(struct udphdr) + 8;

					*l3_hdr = (void *)inner_eth +
					    lro_l2_hdr_len(wqe,
							   (void *)inner_eth);

					return inner_eth->h_proto;
				}
			}

			*l3_hdr =
			    (void *)((uint8_t *) packet_start(wqe) +
				     wqe->word2.s.ip_offset);
			return ETH_P_IP;
		} else {
			struct ipv6hdr *ipv6h = packet_start(wqe) +
			    wqe->word2.s.ip_offset;

			if (ipv6h->nexthdr == IPPROTO_GRE) {
				inner_eth = (void *)ipv6h +
				    sizeof(struct ipv6hdr) +
				    sizeof(gre_hdr_t) + sizeof(gre_key_hdr_t);

				*l3_hdr = (void *)inner_eth +
				    lro_l2_hdr_len(wqe, (void *)inner_eth);

				return inner_eth->h_proto;

			} else if (ipv6h->nexthdr == IPPROTO_UDP) {
				struct udphdr *udph =
				    (struct udphdr *)((void *)ipv6h +
						      sizeof(struct ipv6hdr));

				if (udph->dest == VTEP_UDP_SERVER_PORT1) {
					inner_eth = (void *)udph +
					    sizeof(struct udphdr) + 8;

					*l3_hdr = (void *)inner_eth +
					    lro_l2_hdr_len(wqe,
							   (void *)inner_eth);
					return inner_eth->h_proto;
				}
			}

			*l3_hdr =
			    (void *)((uint8_t *) packet_start(wqe) +
				     wqe->word2.s.ip_offset);
			return ETH_P_IPV6;
		}
	} else {
		return 0;
	}
}

/* SHARED HASH TABLE BETWEEN ALL CORES FOR LRO CONTEXT */
CVMX_SHARED struct list_head lro_hash_table[HASH_SIZE];

static int
cvmcs_nic_send_gather_list_to_host(cvmx_wqe_t * wqe,
				   cvmx_buf_ptr_t * gather_list, int port,
				   int queue, int total_size, int vlan_hdr_len,
				   int bp_credits, int ip_offset, bool is_rss)
{
	cvmx_pko_command_word0_t pko_command;
	int ret;

	//use pkt_data to store credits
	cvmx_raw_inst_front_t *front;
	front = (cvmx_raw_inst_front_t *) wqe->packet_data;
	front->irh.s.opcode = OPCODE_NIC;
	front->irh.s.subcode = OCT_NIC_LRO_COMPLETION_OP;
	front->ossp[0] = bp_credits;
	wqe->word2.s.software = 1;

	if (octeon_has_feature(OCTEON_FEATURE_PKND))
		cvmx_pko_send_packet_prepare_pkoid(port, queue, 1);
	else
		cvmx_pko_send_packet_prepare(port, queue, 1);

	pko_command.u64 = 0;
	pko_command.s.ignore_i = 0;
	pko_command.s.dontfree = 0;

	pko_command.s.gather = 1;
	pko_command.s.segs = gather_list->s.size;
	pko_command.s.total_bytes = total_size;
	pko_command.s.ipoffp1 = ip_offset + 1;
	if (is_rss) {
		pko_command.s.total_bytes += 8;
		pko_command.s.ipoffp1 += 8;
	}
	assert(pko_command.s.total_bytes != 0);
	assert(pko_command.s.segs != 0);
	//BP credits
	pko_command.s.wqp = 1;
	pko_command.s.rsp = 1;

	if (octeon_has_feature(OCTEON_FEATURE_PKND)) {
		CVMX_SYNCWS;
		ret = cvmx_pko_send_packet_finish3_pkoid(port, queue,
							 pko_command,
							 *gather_list,
							 cvmx_ptr_to_phys(wqe),
							 1);
	} else {
		CVMX_SYNCWS;
		ret = cvmx_pko_send_packet_finish3(port, queue,
						   pko_command, *gather_list,
						   cvmx_ptr_to_phys(wqe), 1);
	}
	return ret;
}

static inline void add_lro_context(lro_context_t * lro_ctx, uint16_t hash)
{
	cavium_list_add_tail(&lro_ctx->list, &lro_hash_table[hash]);
}

static inline lro_context_t *alloc_lro_context(cvmx_wqe_t * wqe,
					       lro_context_t * temp_ctx)
{

	lro_context_t *lro_ctx = NULL;
	lro_ctx = cvmx_fpa_alloc(CVMX_FPA_LRO_CONTEXT_POOL);
	if (NULL == lro_ctx) {
		printf("ERR : LRO CONTEXT ALLOC FAILED\n");
		return NULL;
	}
	memset(lro_ctx, 0, sizeof(lro_context_t));
	*lro_ctx = *temp_ctx;
	add_lro_context(lro_ctx, (cvmx_wqe_get_tag(wqe) & LRO_TAG_MASK));

	return lro_ctx;
}

static inline void remove_lro_context(lro_context_t * lro_ctx)
{
	cavium_list_del(&lro_ctx->list);
}

static inline void free_lro_context(lro_context_t * lro_ctx)
{
	remove_lro_context(lro_ctx);
	if (!lro_ctx->timer_pending) {
		cvmx_fpa_free(lro_ctx, CVMX_FPA_LRO_CONTEXT_POOL, 0);
	}
}

static inline int lro_tot_len(lro_context_t * lro_ctx)
{
	uint32_t tot_len = 0;
	struct iphdr *iph4 = NULL;
	struct ipv6hdr *iph6 = NULL;

	if (lro_ctx->is_v6)
		iph6 = (struct ipv6hdr *)lro_ctx->iphdr;
	else
		iph4 = (struct iphdr *)lro_ctx->iphdr;

	tot_len = ETH_HLEN + (lro_ctx->is_vlan ? VLAN_HLEN : 0);
	tot_len += lro_ctx->is_v6 ? (iph6->payload_len + 40) : iph4->tot_len;

	return tot_len;
}

static inline void lro_update_header(lro_context_t * lro_ctx)
{
	struct iphdr *iph4 = NULL;
	struct ipv6hdr *iph6 = NULL;
	struct tcphdr *tcp = NULL;
	uint32_t *tsptr = NULL, tcp_opt_len = 0;

	if (lro_ctx->is_v6)
		iph6 = (struct ipv6hdr *)lro_ctx->iphdr;
	else
		iph4 = (struct iphdr *)lro_ctx->iphdr;

	tcp = lro_ctx->tcp;
	tcp_opt_len = (tcp->doff << 2) - sizeof(*tcp);

	/* MODIFY TOTAL LENGTH IN IP */
	if (lro_ctx->is_v6)
		iph6->payload_len = (tcp->doff << 2) + lro_ctx->tcp_data_len;
	else
		iph4->tot_len =
		    (iph4->ihl << 2) + (tcp->doff << 2) + lro_ctx->tcp_data_len;

	/* RECALCULATE IP CHECKSUM FOR IPV4 HDR */
	if (!lro_ctx->is_v6)
		cvmcs_nic_ip_header_checksum(iph4, &iph4->check);

	/* UPDATE TCP ACK */
	tcp->ack_seq = lro_ctx->ack_seq;
	tcp->window = lro_ctx->window;

	/* Update TCP timestamps */
	if (0 != tcp_opt_len) {
		tsptr = (uint32_t *) (tcp + 1);
		*(tsptr + 1) = lro_ctx->tsval;
		*(tsptr + 2) = lro_ctx->tsecr;
	}

	/* UPDATE PUSH FLAG */
	if (lro_ctx->is_psh)
		tcp->psh = 1;
}

static uint32_t add_ptp_ts(lro_context_t * lro_ctx)
{
	cvmx_buf_ptr_t *glist_ptr = (cvmx_buf_ptr_t *)
	    cvmx_phys_to_ptr(lro_ctx->gather_list.s.addr);
	void *ptp_buf = NULL;

	glist_ptr -= 1;
	lro_ctx->gather_list.s.back =
	    (glist_ptr - lro_ctx->glist_ptr) / CVMX_CACHE_LINE_SIZE;

	ptp_buf = cvmx_fpa_alloc(CVMX_FPA_PACKET_POOL);
	if (!ptp_buf) {
		print_error(" PTP buffer alloc failed\n");
		return 0;
	}

	*((uint64_t *) ptp_buf) = lro_ctx->ptp_ts;
	glist_ptr[0].u64 = 0;
	glist_ptr[0].s.addr = CVM_DRV_GET_PHYS(ptp_buf);
	glist_ptr[0].s.pool = CVMX_FPA_PACKET_POOL;
	glist_ptr[0].s.size = 8;

	lro_ctx->append_cnt += 1;
	lro_ctx->gather_list.s.addr = CVM_DRV_GET_PHYS(glist_ptr);

	return 8;
}

static uint32_t add_resp_hdr(lro_context_t * lro_ctx)
{
	cvmx_wqe_t *wqe = lro_ctx->wqe;
	octnic_port_info_t *nicport = &octnic->port[lro_ctx->ifidx];
	cvmx_buf_ptr_t *glist_ptr = (cvmx_buf_ptr_t *)
	    cvmx_phys_to_ptr(lro_ctx->gather_list.s.addr);
	union octeon_rh *rh;

	glist_ptr -= 1;
	lro_ctx->gather_list.s.back =
	    (glist_ptr - lro_ctx->glist_ptr) / CVMX_CACHE_LINE_SIZE;

	/* USE wqe->packet_data TO STORE RESP PTR */
	rh = (union octeon_rh *)((uint8_t *) (wqe->packet_data) +
				 CVM_RAW_FRONT_SIZE);
	rh->u64 = 0;
	rh->r_dh.opcode = OPCODE_NIC;
	rh->r_dh.subcode = OPCODE_NIC_NW_DATA;
	rh->r_dh.link = nicport->linfo.ifidx;
	rh->r_dh.csum_verified = CNNIC_CSUM_VERIFIED;
	if (lro_ctx->is_ptp) {
		rh->r_dh.has_hwtstamp = 1;
		rh->r_dh.len = 1;
	} else {
		rh->r_dh.has_hwtstamp = 0;
		rh->r_dh.len = 0;
	}

	glist_ptr[0].u64 = 0;
	glist_ptr[0].s.addr = CVM_DRV_GET_PHYS(rh);
	glist_ptr[0].s.pool = CVMX_FPA_WQE_POOL;
	glist_ptr[0].s.size = OCT_RH_SIZE;
	//for backpressure, this wqe is returned by pko
	//and then freed after adjusting backpressure
	//credits
	glist_ptr[0].s.i = 1;

	lro_ctx->append_cnt += 1;
	lro_ctx->gather_list.s.addr = CVM_DRV_GET_PHYS(glist_ptr);

	return OCT_RH_SIZE;
}

void
cvmcs_nic_flush_lro(cvmx_wqe_t * orig_wqe, lro_context_t * lro_ctx,
		    int del_timer)
{
	cvmx_buf_ptr_t *glist_ptr = NULL;
	int32_t port, queue, rxq, i;
	octnic_port_info_t *nicport = NULL;
	cvmx_wqe_t *wqe = lro_ctx->wqe;
	uint32_t vlan_hdr_len = lro_ctx->is_vlan ? VLAN_HLEN : 0;
	uint32_t *rss_hash_ptr = NULL;
	uint64_t start_of_buffer = 0;

	print_debug("\nGOT THE CONTEXT : %p APPEND COUNT : %d\n", lro_ctx,
		    lro_ctx->append_cnt);

	if (del_timer == 1) {
		if (CVMX_TIM_STATUS_BUSY ==
		    cvmx_tim_delete_entry(&lro_ctx->delete_info)) {
			/* LET THE TIMER FREE THE CONTEXT */
			lro_ctx->timer_pending = 1;
		} else {
			cvmx_fpa_free(lro_ctx->timer_wqe, CVMX_FPA_WQE_POOL, 0);
		}
	} else {
		if (lro_ctx->timer_pending) {
			cvmx_pow_tag_sw_null();
			cvmx_fpa_free(lro_ctx, CVMX_FPA_LRO_CONTEXT_POOL, 0);
			return;
		}
	}

	/* DETACH LRO CONTEXT FROM HASH BUCKET */
	/* remove_lro_context(lro_ctx); */
	/* lro_tag_sw_order(wqe); */

	nicport = &octnic->port[lro_ctx->ifidx];
	glist_ptr =
	    (cvmx_buf_ptr_t *) cvmx_phys_to_ptr(lro_ctx->gather_list.s.addr);

	if (lro_ctx->append_cnt > 1)
		lro_update_header(lro_ctx);

#if 0
	/* Fill no of entries in gather list */
	lro_ctx->gather_list.s.size = lro_ctx->append_cnt;
	print_debug("lro_ctx->gather_list.s.size: %d \n",
		    lro_ctx->gather_list.s.size);
#endif

	if (!nicport->state.rx_on) {
		print_error("[%s]ERROR: RX STATE IS OFF\n", __FUNCTION__);
		cvmx_atomic_add_u64(&nicport->stats.fromwire.fw_err_drop, 1);
		for (i = 1; i < lro_ctx->append_cnt; i++) {
			if (!glist_ptr[i].s.i) {
				start_of_buffer = ((glist_ptr[i].s.addr >> 7) -
							glist_ptr[i].s.back) << 7;
				cvmx_fpa_free(cvmx_phys_to_ptr(start_of_buffer),
						CVMX_FPA_PACKET_POOL, 0);
			}
		}
		cvmx_fpa_free(lro_ctx->glist_ptr, CVMX_FPA_GATHER_LIST_POOL, 0);
		cvm_update_bp_port(cvmx_wqe_get_port(wqe), lro_ctx->bp_credits);
		free_lro_context(lro_ctx);
		CVMX_SYNCWS;
		cvmx_pow_tag_sw_null();
		cvmx_fpa_free(wqe, CVMX_FPA_WQE_POOL, 0);
		return;
	}

	if (nicport->state.rss_on) {
		uint32_t hash = (uint32_t) - 1;
		union octeon_rh *rh =
		    (union octeon_rh *)((uint8_t *) (wqe->packet_data) +
					CVM_RAW_FRONT_SIZE);
		rss_hash_ptr = (uint32_t *) (rh + 1);

		rxq = cvmcs_nic_rss_get_queue(wqe, &hash, lro_ctx->ifidx);
		if (-1 == rxq) {
			rxq =
			    (cvmx_wqe_get_tag(wqe) &
			     (nicport->linfo.num_rxpciq - 1));
			rxq = nicport->linfo.rxpciq[rxq];
#if defined(USE_CUSTOM_OQ)
			rxq = nicport->linfo.rxpciq[0];
#endif
		}

		*rss_hash_ptr = hash;
		rh->r_dh.extra = 0x1;	/* Using exra to indicate RSS */
		rh->r_dh.len += 1;
		glist_ptr[0].s.size += 8;

		DBG("%s: rss hash 0x%x\n", __func__, hash);
	} else {
		rxq = (cvmx_wqe_get_tag(wqe) & (nicport->linfo.num_rxpciq - 1));
		rxq = nicport->linfo.rxpciq[rxq];
#if defined(USE_CUSTOM_OQ)
		rxq = nicport->linfo.rxpciq[0];
#endif
	}
	port = cvm_pci_get_oq_pkoport(rxq);
	queue = cvm_pci_get_oq_pkoqueue(rxq);

	if (cvmx_unlikely(port == -1 || queue == -1)) {
		cvmx_atomic_add_u64(&nicport->stats.fromwire.fw_err_drop, 1);
		for (i = 1; i < lro_ctx->append_cnt; i++) {
			start_of_buffer = ((glist_ptr[i].s.addr >> 7) -
						glist_ptr[i].s.back) << 7;
			cvmx_fpa_free(cvmx_phys_to_ptr(start_of_buffer),
					CVMX_FPA_PACKET_POOL, 0);
		}
		cvmx_fpa_free(lro_ctx->glist_ptr, CVMX_FPA_GATHER_LIST_POOL, 0);
		cvm_update_bp_port(cvmx_wqe_get_port(wqe), lro_ctx->bp_credits);
		free_lro_context(lro_ctx);
		//lro_tag_sw_order(wqe);
		CVMX_SYNCWS;
		cvmx_pow_tag_sw_null();
		cvmx_fpa_free(wqe, CVMX_FPA_WQE_POOL, 0);
		return;
	}

	{
		cvmx_buf_ptr_t gather_list;
		uint32_t tot_len = 0;
		uint32_t bp_credits = 0;
		uint32_t len = 0, ip_offset = 0;
		cvmx_buf_ptr_t *glist = lro_ctx->glist_ptr;
		cvmx_buf_ptr_t *glist_ptr = NULL;

		/* Default value */
		ip_offset = ETH_HLEN + vlan_hdr_len;

		/* Tunnel header callback shall take care of timestamping also */
		if (lro_ctx->tun_hdr_cb) {
			len =
			    lro_ctx->tun_hdr_cb(wqe, lro_ctx,
						lro_ctx->tun_cb_arg);
			ip_offset += len;
			tot_len += len;
		} else {
			/* Update only if incoming pkt has ptp timestamp
 			 * with the content
 			 */
			if (lro_ctx->is_ptp) {
				/* TODO : Handle error case */
				len = add_ptp_ts(lro_ctx);
				ip_offset += len;
				tot_len += len;
			}
		}

		len = add_resp_hdr(lro_ctx);
		ip_offset += len;
		tot_len += len;

		tot_len += lro_tot_len(lro_ctx);
		bp_credits = lro_ctx->bp_credits;
		/* Fill no of entries in gather list */
		lro_ctx->gather_list.s.size = lro_ctx->append_cnt;
		gather_list.u64 = lro_ctx->gather_list.u64;
		glist_ptr = (cvmx_buf_ptr_t *)
		    cvmx_phys_to_ptr(lro_ctx->gather_list.s.addr);

		free_lro_context(lro_ctx);
		CVMX_SYNCWS;
		lro_tag_sw_order(orig_wqe);
		//cvmx_pow_tag_sw_null();

		if (cvmcs_nic_send_gather_list_to_host(wqe, &gather_list,
						       port, queue, tot_len,
						       vlan_hdr_len, bp_credits,
						       ip_offset,
						       rss_hash_ptr ? true :
						       false)) {
			print_error("[%s]ERROR: SEND TO PKO FAILED\n",
				    __FUNCTION__);
			cvmx_atomic_add_u64(&nicport->stats.fromwire.fw_err_pko,
					    1);
			for (i = 1; i < gather_list.s.size; i++) {
				start_of_buffer = ((glist_ptr[i].s.addr >> 7) -
							glist_ptr[i].s.back) << 7;
				cvmx_fpa_free(cvmx_phys_to_ptr(start_of_buffer),
						CVMX_FPA_PACKET_POOL, 0);
			}
			cvmx_fpa_free(glist, CVMX_FPA_GATHER_LIST_POOL, 0);
			cvm_update_bp_port(cvmx_wqe_get_port(wqe), bp_credits);
			cvmx_fpa_free(wqe, CVMX_FPA_WQE_POOL, 0);
			return;
		}

		cvmx_atomic_add_u64(&nicport->stats.fromwire.fw_total_fwd, 1);
	}
}

static inline int cvmcs_nic_set_lro_timer(lro_context_t * lro_ctx)
{
	cvmx_wqe_t *timer_work;
	cvmx_raw_inst_front_t *front;
	cvmx_tim_delete_t *delete_info;
	uint64_t tim = (LRO_TIMER_TICKS_MS);

	timer_work = cvmx_fpa_alloc(CVMX_FPA_WQE_POOL);
	if (NULL == timer_work) {
		print_error("timer_work alloc failed \n");
		return -1;
	}

	lro_ctx->timer_wqe = timer_work;
	front = (cvmx_raw_inst_front_t *) timer_work->packet_data;
	memset(front, 0, sizeof(cvmx_raw_inst_front_t));
	front->irh.s.opcode = OPCODE_NIC;
	front->irh.s.subcode = OCT_NIC_LRO_TIMER_OP;
	front->ossp[0] = (uint64_t) lro_ctx;
	timer_work->word2.s.software = 1;

	cvmx_wqe_set_qos(timer_work, 1);
	cvmx_wqe_set_tt(timer_work, CVMX_POW_TAG_TYPE_ATOMIC);
	cvmx_wqe_set_tag(timer_work, (cvmx_wqe_get_tag(lro_ctx->wqe) &
				      LRO_TAG_MASK));
	cvmx_wqe_set_grp(timer_work, cvmx_wqe_get_grp(lro_ctx->wqe));

	delete_info = (cvmx_tim_delete_t *) & lro_ctx->delete_info;
	CVMX_SYNCWS;
	if (cvmx_tim_add_entry(timer_work, tim, delete_info) !=
	    CVMX_TIM_STATUS_SUCCESS) {
		print_error("timer add failed\n");
		cvmx_fpa_free(timer_work, CVMX_FPA_WQE_POOL, 0);
		return -1;
	}
	//print_error("timer add success\n");
	return 0;
}

static inline bool
tcp_flow_match(cvmx_wqe_t * wqe,
	       lro_context_t * lro_ctx, lro_context_t * temp_ctx)
{
	bool is_vlan, is_v6;
	void *eth, *iph;
	struct tcphdr *tcp;

	is_vlan = temp_ctx->is_vlan;
	is_v6 = temp_ctx->is_v6;
	eth = temp_ctx->ethhdr;
	iph = temp_ctx->iphdr;
	tcp = temp_ctx->tcp;

	/* CHECK VLAN TYPE */
	if (is_vlan) {
		if (!lro_ctx->is_vlan)
			return false;

		if (((struct vlan_hdr *)lro_ctx->ethhdr)->vlan_TCI !=
		    ((struct vlan_hdr *)eth)->vlan_TCI)
			return false;
	}

	/* CHECK IP HEADER */
	if (is_v6) {
		/* MATCH IPV6 HEADER FIELDS */
		if (!lro_ctx->is_v6)
			return false;

		/* MATCH SOURCE ADDR */
		int i = 0;
		for (i = 0; i < 4; ++i) {
			if (((struct ipv6hdr *)lro_ctx->iphdr)->saddr.
			    s6_addr32[i] !=
			    ((struct ipv6hdr *)iph)->saddr.s6_addr32[i]) {
				return false;
			}
		}

		/* MATCH DEST ADDR */
		for (i = 0; i < 4; ++i) {
			if (((struct ipv6hdr *)lro_ctx->iphdr)->daddr.
			    s6_addr32[i] !=
			    ((struct ipv6hdr *)iph)->daddr.s6_addr32[i]) {
				return false;
			}
		}

		/* CHECK TCP HEADER */
		if ((lro_ctx->tcp->source != tcp->source) ||
		    (lro_ctx->tcp->dest != tcp->dest)) {
			print_debug("TCP HDR MATCH FAILED\n");
			return false;
		}

		return true;
	} else {
		struct iphdr *ip4 = (struct iphdr *)lro_ctx->iphdr;

		if (lro_ctx->is_v6)
			return false;

		/* MATCH SOURCE ADDR AND DEST ADDR */
		if (ip4->saddr != ((struct iphdr *)iph)->saddr ||
		    ip4->daddr != ((struct iphdr *)iph)->daddr)
			return false;

		/* CHECK TCP HEADER */
		if ((lro_ctx->tcp->source != tcp->source) ||
		    (lro_ctx->tcp->dest != tcp->dest)) {
			print_debug("TCP HDR MATCH FAILED\n");
			return false;
		}

		return true;
	}

	return false;
}

static inline lro_context_t *find_lro_ctx(cvmx_wqe_t * wqe,
					  lro_context_t * temp_ctx)
{
	lro_context_t *lro_ctx = NULL;
	struct list_head *tmp = NULL;
	uint16_t hash = cvmx_wqe_get_tag(wqe) & LRO_TAG_MASK;

	/* SEARCH FOR A CONTEXT IN HASHTABLE */
	CAVIUM_LIST_FOR_EACH(tmp, &lro_hash_table[hash]) {
		lro_ctx =
		    (lro_context_t *) container_of(tmp, lro_context_t, list);
		if (tcp_flow_match(wqe, lro_ctx, temp_ctx))
			return lro_ctx;
	}

	return NULL;
}

static inline int
check_lro_valid_pkt(cvmx_wqe_t * wqe, bool is_v6, void *iph, struct tcphdr *tcp)
{
	struct iphdr *iph4;
	struct ipv6hdr *iph6;
	int tcp_hlen = 0;
	uint32_t *ts_ptr = NULL;

	if (!is_v6) {
		iph4 = (struct iphdr *)iph;
		/* IP4 PACKET */
		if (IPPROTO_TCP != iph4->protocol) {
			print_debug("LRO not supported for Non-TCP packets\n");
			return -1;
		}

		/* IP Header must
		 *    have no IP options
		 *    MF bit not set
		 *    Fragment offset not set
		 */
		if (((iph4->ihl << 2) != sizeof(struct iphdr))
		    || (iph4->frag_off & IP_MF)
		    || (iph4->frag_off & IP_OFFSET)) {
			print_debug("IP header Check Failed \n");
			return -1;
		}

		if (0 == (iph4->tot_len - (iph4->ihl << 2) - (tcp->doff << 2))) {
			print_debug("Data Len Zero\n");
			return -1;
		}
	} else {
		iph6 = (struct ipv6hdr *)iph;
		if (IPPROTO_TCP != iph6->nexthdr)
			return -1;

		if (0 == (iph6->payload_len - (tcp->doff << 2)))
			return -1;
	}

	/* TCP flag checks */
	if (tcp->syn || tcp->urg || tcp->rst || tcp->fin || tcp->ece ||
	    tcp->cwr || !tcp->ack) {
		print_debug("TCP header Check Failed \n");
		return -1;
	}

	/* Check for timestamps */
	tcp_hlen = (tcp->doff << 2);
	tcp_hlen -= sizeof(*tcp);
	ts_ptr = (uint32_t *) (tcp + 1);
	if (tcp_hlen != 0 &&
	    ((tcp_hlen != TCPOLEN_TSTAMP_APPA)
	     || (*ts_ptr != TCPOPT_TSTAMP_HDR))) {
		print_debug("TCP Timestamp Check Failed \n");
		return -1;
	}

	if (wqe->word2.s.L4_error && !wqe->word2.s.rcv_error
	    && !wqe->word2.s.IP_exc) {
		print_debug("ERROR : OOPS L4 error\n");
		return -1;
	}

	return 0;
}

static inline int is_lro_valid(cvmx_wqe_t * wqe, lro_context_t * lro_ctx)
{
	struct vlan_hdr *vlan = NULL;

	if (lro_ctx->iphdr == NULL)
		return -1;

	if (lro_ctx->is_vlan) {
		vlan = lro_ctx->ethhdr;
		/* IP packet validation is done above */
		if (0 == vlan->vlan_TCI)
			return -1;
	}

	return check_lro_valid_pkt(wqe,
				   lro_ctx->is_v6,
				   lro_ctx->iphdr, lro_ctx->tcp);
}

void
get_headers(cvmx_wqe_t * wqe, lro_pkt_info_t * lro_pkt_info,
	    lro_context_t * lro_ctx)
{
	struct ethhdr *eth = (struct ethhdr *)((uint8_t *) PACKET_START(wqe)
					       + lro_pkt_info->ethoff);
	int l2_proto = eth->h_proto;
	int vlan_hdr_len = 0;
	struct vlan_hdr *vlan = NULL;

	memset(lro_ctx, 0, sizeof(lro_context_t));

	if ((l2_proto != ETH_P_IP) && (l2_proto != ETH_P_IPV6) &&
	    (l2_proto != ETH_P_8021Q))
		return;

	lro_ctx->ethhdr = (void *)eth;
	if (ETH_P_8021Q == l2_proto) {
		vlan = (struct vlan_hdr *)eth;
		lro_ctx->is_vlan = true;
		vlan_hdr_len = VLAN_HLEN;
		if ((ETH_P_IP != vlan->proto) && (ETH_P_IPV6 != vlan->proto))
			return;
		l2_proto = vlan->proto;
	}

	lro_ctx->iphdr =
	    (void *)((uint8_t *) lro_ctx->ethhdr + ETH_HLEN + vlan_hdr_len);
	lro_ctx->is_v6 = (l2_proto == ETH_P_IPV6 ? 1 : 0);

	if (!lro_ctx->is_v6)
		lro_ctx->tcp =
		    (struct tcphdr *)((struct iphdr *)lro_ctx->iphdr + 1);
	else
		lro_ctx->tcp =
		    (struct tcphdr *)((struct ipv6hdr *)lro_ctx->iphdr + 1);
}

int
oct_nic_lro_receive_pkt(cvmx_wqe_t * wqe,
	lro_pkt_info_t * lro_pkt_info, int ifidx)
{
	struct iphdr *iph4 = NULL;
	struct ipv6hdr *iph6 = NULL;
	struct tcphdr *tcp = NULL;

	cvmx_buf_ptr_t *glist_ptr, *cur, first_buf;
	int cur_tcp_data_len, tcp_opt_len, proto_hdr_len, tot_pkt_len;

	int i, filled_len = 0, vlan_hdr_len = 0;

	lro_context_t *lro_ctx, temp_ctx;
	uint32_t *tsptr = NULL;

	bool is_v6, is_vlan;
	get_headers(wqe, lro_pkt_info, &temp_ctx);

	if (is_lro_valid(wqe, &temp_ctx)) {
		print_debug("PACKET NOT VALID FOR LRO\n");
		return LRO_INVALID;
	}

	is_vlan = temp_ctx.is_vlan;
	is_v6 = temp_ctx.is_v6;
	if (!is_v6)
		iph4 = temp_ctx.iphdr;
	else
		iph6 = temp_ctx.iphdr;
	tcp = temp_ctx.tcp;
	vlan_hdr_len = is_vlan ? VLAN_HLEN : 0;

	/* REQUEST FOR TAG SWITCH */
	/* FIXME : CHECK : This tag switch is based on outer headers if any, 
	 * but does that matter?
	 */
	cvmx_pow_tag_sw_full(wqe, (cvmx_wqe_get_tag(wqe) & LRO_TAG_MASK),
			     CVMX_POW_TAG_TYPE_ATOMIC, cvmx_wqe_get_grp(wqe));

	cur_tcp_data_len =
	    is_v6 ? iph6->payload_len : (iph4->tot_len - (iph4->ihl << 2));
	cur_tcp_data_len -= (tcp->doff << 2);

	proto_hdr_len = ETH_HLEN + vlan_hdr_len;
	proto_hdr_len += is_v6 ? 40 : (iph4->ihl << 2);
	proto_hdr_len += (tcp->doff << 2);

	tot_pkt_len = cvmx_wqe_get_len(wqe);

	print_debug("TOT PKT LEN : %d DATA LEN : %d HDR LEN : %d\n",
		    tot_pkt_len, cur_tcp_data_len, proto_hdr_len);

	tcp_opt_len = (tcp->doff << 2) - sizeof(*tcp);
	if (tcp_opt_len != 0)
		tsptr = (uint32_t *) (tcp + 1);

	/* WAIT TILL TAG SWITCH COMPLETES */
	cvmx_pow_tag_sw_wait();

	/* LOOK FOR MATCHING FLOW */
	lro_ctx = find_lro_ctx(wqe, &temp_ctx);
	if (lro_ctx) {
		//Requirement for updating per port backpressure
		if (cvmx_wqe_get_port(wqe) != cvmx_wqe_get_port(lro_ctx->wqe)) {
			cvmcs_nic_flush_lro(wqe, lro_ctx, 1);
			return LRO_UNHANDLED;
		}
		if ((tcp->seq != lro_ctx->next_seq) || (cur_tcp_data_len == 0)) {
			cvmcs_nic_flush_lro(wqe, lro_ctx, 1);
			return LRO_UNHANDLED;
		}

		/* CHECK IF TIME STAMPS */
		if (tcp_opt_len != 0) {
			if (lro_ctx->tsval > *(tsptr + 1) || *(tsptr + 2) == 0) {
				cvmcs_nic_flush_lro(wqe, lro_ctx, 1);
				return LRO_UNHANDLED;
			}
		}

		/* Take into account tunnel headers, timestamp and response headers */
		if (((lro_ctx->append_cnt + wqe->word2.s.bufs) > 12) ||
		    (lro_ctx->append_cnt + wqe->word2.s.bufs) >
		    ((CVMX_FPA_GATHER_LIST_POOL_SIZE / sizeof(cvmx_buf_ptr_t)) -
		     4)) {
			cvmcs_nic_flush_lro(wqe, lro_ctx, 1);
			return LRO_UNHANDLED;
		}

		/* PACKET CAN BE CONSIDERED FOR AGGREGATION */
		cur = &wqe->packet_ptr;
		glist_ptr =
		    (cvmx_buf_ptr_t *) cvmx_phys_to_ptr(lro_ctx->gather_list.s.
							addr);

		/* FILL GATHER LIST */
		for (i = 0; i < wqe->word2.s.bufs; i++) {
			if (0 == i) {
				/* FIRST BUFFER SO SKIP THE HEADER */
				glist_ptr[lro_ctx->append_cnt].u64 = cur->u64;
				glist_ptr[lro_ctx->append_cnt].s.addr =
				    cur->s.addr + lro_pkt_info->ethoff +
				    proto_hdr_len;

				if (i == (wqe->word2.s.bufs - 1))
					glist_ptr[lro_ctx->append_cnt].s.size =
					    tot_pkt_len - lro_pkt_info->ethoff -
					    proto_hdr_len;
				else
					glist_ptr[lro_ctx->append_cnt].s.size =
					    cur->s.size - lro_pkt_info->ethoff -
					    proto_hdr_len;

				/* UPDATE BACK */
				glist_ptr[lro_ctx->append_cnt].s.back =
				    ((cur->s.addr + lro_pkt_info->ethoff +
				      proto_hdr_len) - (((cur->s.addr >> 7) -
							 cur->s.back) << 7)) /
				    CVMX_CACHE_LINE_SIZE;
			} else {
				glist_ptr[lro_ctx->append_cnt].u64 = cur->u64;

				if (i == (wqe->word2.s.bufs - 1))
					glist_ptr[lro_ctx->append_cnt].s.size =
					    tot_pkt_len - filled_len;
				else
					glist_ptr[lro_ctx->append_cnt].s.size =
					    cur->s.size;
			}

			filled_len += glist_ptr[lro_ctx->append_cnt].s.size;

			lro_ctx->append_cnt += 1;
			cur =
			    ((cvmx_buf_ptr_t *)
			     cvmx_phys_to_ptr(cur->s.addr - 8));
		}

		/* UPDATE LRO CONTEXT */
		lro_ctx->bp_credits += wqe->word2.s.bufs;
		lro_ctx->next_seq = tcp->seq + cur_tcp_data_len;
		lro_ctx->ack_seq = tcp->ack_seq;
		lro_ctx->tcp_data_len += cur_tcp_data_len;
		lro_ctx->window = tcp->window;
		if (tcp_opt_len != 0) {
			lro_ctx->tsval = *(tsptr + 1);
			lro_ctx->tsecr = *(tsptr + 2);
		}
		if (lro_pkt_info->is_ptp) {
			lro_ctx->is_ptp = true;
			lro_ctx->ptp_ts =
			    *((uint64_t *) (cvmx_phys_to_ptr(wqe->packet_ptr.s.addr)));
		}

		CVMX_SYNCWS;
		if (tcp->psh) {
			lro_ctx->is_psh = true;
			cvmcs_nic_flush_lro(wqe, lro_ctx, 1);
			cvmx_fpa_free(wqe, CVMX_FPA_WQE_POOL, 0);
			return LRO_AGGREGATED;
		}
		if ((lro_ctx->tcp_data_len + cur_tcp_data_len) >
		    LRO_SEGMENT_THRESHOLD) {
			cvmcs_nic_flush_lro(wqe, lro_ctx, 1);
			cvmx_fpa_free(wqe, CVMX_FPA_WQE_POOL, 0);
			return LRO_AGGREGATED;
		}

		/* THIS WONT BE FIRST WQE SO FREE IT ONLY WQE */
		//lro_tag_sw_order(wqe);
		cvmx_pow_tag_sw_null();
		cvmx_fpa_free(wqe, CVMX_FPA_WQE_POOL, 0);
		return LRO_AGGREGATED;
	}

	/* FLUSH PUSH PACKET */
	if (tcp->psh) {
		lro_tag_sw_order(wqe);
		return LRO_UNHANDLED;
	}

	/* CREATE A NEW CONTEXT */
	lro_ctx = alloc_lro_context(wqe, &temp_ctx);
	if (NULL == lro_ctx) {
		lro_tag_sw_order(wqe);
		return LRO_UNHANDLED;
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

	lro_ctx->next_seq = tcp->seq + lro_ctx->tcp_data_len;
	lro_ctx->ack_seq = tcp->ack_seq;
	lro_ctx->window = tcp->window;
	lro_ctx->wqe = wqe;	/* STORE FIRST WQE */
	lro_ctx->append_cnt = 0;
	lro_ctx->ifidx = ifidx;
	lro_ctx->tun_hdr_cb = lro_pkt_info->tun_hdr_cb;
	lro_ctx->proto_hdr_len = proto_hdr_len;
	lro_ctx->tun_hdr_len = lro_pkt_info->tun_hdr_len;
	lro_ctx->is_ptp = lro_pkt_info->is_ptp;

	/* CREATE GATHER LIST */
	lro_ctx->glist_ptr =
	    (cvmx_buf_ptr_t *) cvmx_fpa_async_alloc_finish(CVMCS_TEST_BUF_PTR,
							   CVMX_FPA_GATHER_LIST_POOL);
	if (NULL == lro_ctx->glist_ptr) {
		print_error("ERR: GATHER LIST ALLOC FAILED\n");
		//remove_lro_context(lro_ctx);
		free_lro_context(lro_ctx);
		lro_tag_sw_order(wqe);
		return LRO_UNHANDLED;
	}

	/* Make sure enough room is there for tunnel and response headers */
	glist_ptr = lro_ctx->glist_ptr;
	glist_ptr += 4;

	lro_ctx->gather_list.u64 = 0;
	lro_ctx->gather_list.s.addr = CVM_DRV_GET_PHYS(glist_ptr);
	lro_ctx->gather_list.s.pool = CVMX_FPA_GATHER_LIST_POOL;
	lro_ctx->gather_list.s.back =
	    (glist_ptr - lro_ctx->glist_ptr) / CVMX_CACHE_LINE_SIZE;

	/* Tunnel hdr, if present is here in this buffer only
	 * So, tunnel header callback should set its own gather pointer
	 * is such a way that the PKO does not free the FPA buffer
	 */
	cur = &wqe->packet_ptr;
	first_buf.u64 = 0;
	first_buf.s.addr = cur->s.addr + lro_pkt_info->ethoff;
	first_buf.s.size = cur->s.size - lro_pkt_info->ethoff;

	if (((lro_ctx->append_cnt + wqe->word2.s.bufs) > 12) ||
	    (lro_ctx->append_cnt + wqe->word2.s.bufs) >
	    ((CVMX_FPA_GATHER_LIST_POOL_SIZE / sizeof(cvmx_buf_ptr_t)) - 4)) {
		cvmx_fpa_free(lro_ctx->glist_ptr, CVMX_FPA_GATHER_LIST_POOL, 0);
		free_lro_context(lro_ctx);
		lro_tag_sw_order(wqe);
		return LRO_UNHANDLED;
	}
	/* FILL THE REST OF BUFFERS IN GATHER LIST */
	for (i = 0; i < wqe->word2.s.bufs; ++i) {
		if (0 == i) {
			glist_ptr[lro_ctx->append_cnt].u64 = cur->u64;
			glist_ptr[lro_ctx->append_cnt].s.addr =
			    first_buf.s.addr;
			glist_ptr[lro_ctx->append_cnt].s.size =
			    first_buf.s.size;
			glist_ptr[lro_ctx->append_cnt].s.back =
			    ((first_buf.s.addr) -
			     (((cur->s.addr >> 7) -
			       cur->s.back) << 7)) / CVMX_CACHE_LINE_SIZE;
		} else
			glist_ptr[lro_ctx->append_cnt].u64 = cur->u64;

		if (i == (wqe->word2.s.bufs - 1))	/* IF LAST BUFFER */
			glist_ptr[lro_ctx->append_cnt].s.size =
			    tot_pkt_len - (lro_pkt_info->ethoff + filled_len);

		filled_len += glist_ptr[lro_ctx->append_cnt].s.size;
		lro_ctx->append_cnt += 1;

		/* GET NEXT BUFFER */
		cur = ((cvmx_buf_ptr_t *) cvmx_phys_to_ptr(cur->s.addr - 8));
	}

	lro_ctx->bp_credits += wqe->word2.s.bufs;

	/* START PER FLOW TIMER */
	if (cvmcs_nic_set_lro_timer(lro_ctx)) {
		print_error("TIMER SETTING ERROR\n");
		/* FLUSH LRO CONTEXT */
		cvmx_fpa_free(lro_ctx->glist_ptr, CVMX_FPA_GATHER_LIST_POOL, 0);
		//remove_lro_context(lro_ctx);
		free_lro_context(lro_ctx);
		lro_tag_sw_order(wqe);
		return LRO_UNHANDLED;
	}
	//add_lro_context(lro_ctx, wqe->word1.tag & LRO_TAG_MASK);
	CVMX_SYNCWS;
	//lro_tag_sw_order(wqe);
	cvmx_pow_tag_sw_null();

	return LRO_AGGREGATED;
}

void oct_nic_lro_init()
{
	int32_t i;

	/* INITIALIZE HASH TABLE */
	for (i = 0; i < HASH_SIZE; i++)
		CAVIUM_INIT_LIST_HEAD(&lro_hash_table[i]);

	/* SET AN IP OFFSET TO INCLUDE MAC HEADER */
	cvmx_write_csr(CVMX_PIP_IP_OFFSET, LRO_IP_OFFSET);

	/* SET THE TIMER FOR LRO CONTEXT FLUSHING
	 * 0.01 SECONDS 360 MAX TIMEOUT
	 */
	cvmx_tim_setup(10000, 3600);
	cvmx_tim_start();

	/* ENABLE L4 ERROR CHECK */
	{
		cvmx_pip_gbl_ctl_t pip_gbl_ctl;
		pip_gbl_ctl.u64 = cvmx_read_csr(CVMX_PIP_GBL_CTL);
		pip_gbl_ctl.s.l2_mal = 1;
		pip_gbl_ctl.s.l4_len = 1;
		pip_gbl_ctl.s.l4_chk = 1;
		pip_gbl_ctl.s.l4_prt = 1;
		pip_gbl_ctl.s.l4_mal = 1;
		pip_gbl_ctl.s.ip_mal = 1;
		pip_gbl_ctl.s.ip_chk = 1;
		cvmx_write_csr(CVMX_PIP_GBL_CTL, pip_gbl_ctl.u64);
	}
}
