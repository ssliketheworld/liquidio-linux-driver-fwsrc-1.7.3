
#include "cvmcs-common.h"
#include "cvmcs-nic.h"
#include  <cvmx-atomic.h>
#include "cvmcs-nic-ether.h"
#include "cvmcs-nic-ip.h"
#include "cvmcs-nic-ipv6.h"
#include "cvmcs-nic-tcp.h"
#include "cvmcs-nic-udp.h"
#include "cvmcs-nic-tunnel.h"
#include "cvm-nic-ipsec.h"

#include "cvmcs-tso.h"
#include "cvmcs-nic-mdata.h"

/* #define DEBUG */
#ifdef DEBUG
#define print_error(msg, ...)   printf(msg,##__VA_ARGS__)
#define print_debug(msg, ...)   printf(msg,##__VA_ARGS__)
#else
#define print_error(msg, ...)   printf(msg,##__VA_ARGS__)
#define print_debug(msg, ...)
#endif

#define DIV_ROUND_UP(n,d) (((n) + (d) - 1) / (d))
#define PACKET_START(WQE)       cvmx_phys_to_ptr(WQE->packet_ptr.s.addr)

void
tso_free_lists_o3(struct tso_pkt_desc_o3  *gather_list, int start, int segs)
{
        int from = start;

        for (;from<segs; ++from) {
                if (from != 0)
                        /* Free protocol header */
                        cvmx_fpa_free(cvmx_phys_to_ptr(gather_list[from].g_bufs[0].buf.s.addr),
                                        CVMX_FPA_PROTOCOL_HEADER_POOL, 0);

        }
}

inline void
tso_free_lists(cvmx_buf_ptr_t * gather_list, int start, int segs)
{
	cvmx_buf_ptr_t *glist_ptr = NULL;
	int from = start;

	for (; from < segs; ++from) {
		glist_ptr = (cvmx_buf_ptr_t *)
		    cvmx_phys_to_ptr(gather_list[from].s.addr);

		if (from != 0)
			/* Free protocol header */
			cvmx_fpa_free(cvmx_phys_to_ptr(glist_ptr[0].s.addr),
				      CVMX_FPA_PROTOCOL_HEADER_POOL, 0);

		/* Free Gather list of Segment i */
		cvmx_fpa_free((void *)((uint64_t)glist_ptr & 0xffffffffffffff80),
				CVMX_FPA_GATHER_LIST_POOL, 0);
	}
}

int
cvmcs_tso_send_gather_list_to_wire_pko3(struct tso_pkt_desc_o3 *gather_list,
					int ifidx, uint32_t *total_size, cvmx_wqe_t *wqe,
					int gso_segs, uint8_t l3_offset, uint8_t l4_offset,
					int lport, int flag)
{

	int32_t i = 0;
	vnic_port_info_t *nicport = &octnic->port[ifidx];
	int port, dq;
	uint32_t ckl4_algo;

	print_debug("####%s: Entry. \n", __func__);

	/* Is Loopback port? */
	port = (flag == 1) ? lport : nicport->linfo.gmxport;
	dq = cvmx_pko_get_base_queue(port);
	if(cvmx_unlikely(port == -1 || dq == -1)) {
//		cvmx_atomic_add_u64(&nicport->stats.fromhost.fw_err_drop, 1);
		print_error("Error port :%d queue: %d \n",port, dq);
		tso_free_lists_o3(gather_list, 0 , gso_segs);
		return -1;
	}

	ckl4_algo = (((cvmx_wqe_78xx_t *)wqe)->word2.lf_hdr_type == CVMX_PKI_LTYPE_E_UDP) ?
				CKL4ALG_UDP : CKL4ALG_TCP;

	print_debug("l4_hdr_type:%u ckl4_algo:%u \n", ((cvmx_wqe_78xx_t *)wqe)->word2.lf_hdr_type, ckl4_algo);
	for (i=0; i<gso_segs; ++i) {
		cvmx_pko_query_rtn_t pko_status;
		cvmx_pko_send_hdr_t hdr_s;
		cvmx_pko_buf_ptr_t gtr_s;
		unsigned node, nwords;
		unsigned scr_base = cvmx_pko3_lmtdma_scr_base();
		int cur_aura, prev_aura;
		int j;

		if (!i)
			cvmx_pow_tag_sw_full(wqe, (cvmx_wqe_get_tag(wqe) ^ dq), CVMX_POW_TAG_TYPE_ATOMIC, cvmx_wqe_get_grp(wqe));

		/* Separa global DQ# into node and local DQ */
		node = dq >> 10;
		dq &= (1 << 10)-1;

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
			hdr_s.s.ckl3 = cvmx_wqe_is_l3_ipv4(wqe);
			hdr_s.s.l3ptr =  l3_offset;
		}
		if (l4_offset) {
			//hdr_s.s.ckl4 = /* TCP */ 2; 
			hdr_s.s.ckl4 = ckl4_algo;
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
		prev_aura = hdr_s.s.aura;
		for (j = 1; j < gather_list[i].nbufs; j++) {
			cur_aura = gather_list[i].g_bufs[j].aura;
			/* worry about aura only if i bit is 0 */
			if ((!gather_list[i].g_bufs[j].buf.s.i) && 
			    (prev_aura != cur_aura)) {
				/* aura changed insert aura desc */
				cvmx_pko_send_aura_t aura_s;
				aura_s.u64 = 0;
				aura_s.s.aura = cur_aura;
				/* TODO: find out if we set NOP, does the buf count */
				/* get decremented or not */
				aura_s.s.alg = AURAALG_NOP;
				aura_s.s.subdc4 = CVMX_PKO_SENDSUBDC_AURA;
				if (nwords >= MAX_PKO3_CMD_WORDS) {
					tso_free_lists_o3(gather_list, i , gso_segs);
					goto err;
				}
				cvmx_scratch_write64(scr_base+sizeof(uint64_t)*(nwords++), aura_s.u64);
				prev_aura = cur_aura;
			}
			if (nwords >= MAX_PKO3_CMD_WORDS) {
				tso_free_lists_o3(gather_list, i, gso_segs);
				goto err;
			}
			gtr_s.u64 = gather_list[i].g_bufs[j].buf.u64;
			gtr_s.s.subdc3 = CVMX_PKO_SENDSUBDC_GATHER;
			cvmx_scratch_write64(scr_base+sizeof(uint64_t)*(nwords++), gtr_s.u64);
		}

		if ((i == gso_segs-1) && (flag != 2 /* Not post-frag flag */)) {
			/* add response wqe. should be the only send work and the last one */
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
		if (!i)
			cvmx_pow_tag_sw_wait();
		pko_status = cvmcs_pko3_lmtdma(node, dq, nwords, false);

		if (cvmx_likely(pko_status.s.dqstatus != PKO_DQSTATUS_PASS)) {
			print_debug("ERROR: sending packet %d failed.\n", i);
			tso_free_lists_o3(gather_list, i, gso_segs);
			goto err;
		}

	}
//	cvmx_atomic_add_u64(&nicport->stats.fromhost.fw_total_fwd, 1);
	return 0;
err:
	print_debug("ERROR: too many send descs\n");
//	cvmx_atomic_add_u64(&nicport->stats.fromhost.fw_err_pko, 1);
	return -1;
}

inline int
cvmcs_nic_send_gather_list_to_wire(cvmx_wqe_t * wqe, uint16_t gso_segs,
				   uint8_t ip_offset,
				   cvmx_buf_ptr_t * gather_list,
				   uint32_t * total_size, int ifidx)
{
	int32_t ret = 0, i = 0;
	cvmx_pko_command_word0_t pko_command;
	vnic_port_info_t *nicport = &octnic->port[ifidx];
	int port = nicport->linfo.gmxport;
	int queue = cvmx_pko_get_base_queue(port);

	if (cvmx_unlikely(port == -1 || queue == -1)) {
//		cvmx_atomic_add_u64(&nicport->stats.fromhost.fw_err_drop, 1);
		print_error("Error port :%d queue: %d \n", port, queue);
		tso_free_lists(gather_list, 0, gso_segs);
		return TSO_FAILED;
	}

	CVMX_SYNCWS;

	/* Prepare to send a packet to PKO. */
	cvmx_pko_send_packet_prepare(port, queue, 1);

	for (i = 0; i < gso_segs; ++i) {
		/* Build a PKO pointer to this packet */
		pko_command.u64 = 0;
		pko_command.s.ignore_i = 0;
		pko_command.s.dontfree = 0;
		pko_command.s.gather = 1;
		pko_command.s.segs = gather_list[i].s.size;
		pko_command.s.total_bytes = total_size[i];
		pko_command.s.ipoffp1 = ip_offset + 1;

		print_debug("pko cmd: %016llx lptr: %016llx PORT: %d Q: %d\n",
			    cast64(pko_command.u64), cast64(gather_list[i].u64),
			    port, cvmx_pko_get_base_queue(port));
		if (i != (gso_segs - 1))
			ret = cvmx_pko_send_packet_finish(port, queue,
							  pko_command,
							  gather_list[i], !i);
		else {
			/* Last  packet */
			pko_command.s.wqp = 1;
			pko_command.s.rsp = 1;
			/* Send a packet to PKO, with a completion WQE */
			ret = cvmx_pko_send_packet_finish3(port, queue,
							   pko_command,
							   gather_list[i],
							   cvmx_ptr_to_phys
							   (wqe), 0);
		}
		if (CVMX_PKO_SUCCESS == ret) {
//			cvmx_atomic_add_u64(&nicport->stats.fromhost.
//					    fw_total_fwd, 1);
		} else {
//			cvmx_atomic_add_u64(&nicport->stats.fromhost.fw_err_pko,
//					    1);
			//free the rest of the packets
			tso_free_lists(gather_list, i, gso_segs);
			print_error("PACKET SEND FAILED : %d\n", i);
			return ret;
		}
	}

	return TSO_SUCCESS;
}

/* O3 function to chunk the tcp payload and finally calls a callback function 
 * TODO: Tunnel headers support.
 */
static inline int
cvmcs_nic_process_tso_o3(cvmx_wqe_t *wqe, tso_info_t *tso_info,
		      tso_hdr_t *tso_hdr)
{
	int is_ipv4opts=0;
	int ipv6exthdrs_len=0;
	uint8_t ipoffset;
	cvmx_buf_ptr_pki_t prev;
	cvmx_buf_ptr_pki_t prev_seg_buf;
	cvmx_raw_inst_front_t *front = NULL;
//	union octnic_packet_params packet_params;
	uint16_t gso_size=0, gso_segs=0;
	uint16_t ip_id = 0, tcp_fin=0, tcp_psh=0;
	uint32_t tcp_next_seq = 0;
	uint32_t proto_hdr_len, tun_hdr_len, vlan_hdr_len;
	int32_t  i = 0, remaining = 0, front_size;
	uint32_t ifidx = 0, lengths[512];
	int32_t expctd_seglen = 0;
	struct tso_pkt_desc_o3 temp_gather_list[512] = { [0 ... 511] = { .g_bufs[0 ... MAX_GATHER_BUFS_O3-1]  = { {0}, 0}, .nbufs=0 } };
	uint8_t  l4_offset = 0;

	print_debug("####%s: Entry. \n", __func__);

	front = (cvmx_raw_inst_front_t *) cvmx_phys_to_ptr(cvmx_wqe_get_pki_pkt_ptr(wqe).addr);
	front_size = front->irh.s.rflag ? CVM_RAW_FRONT_SIZE : CVM_RAW_FRONT_SIZE - 16;
//	packet_params.u32 = front->irh.s.ossp;
	/* TODO: fix this call cvmcs_nic_find_idx */
	ifidx = get_vnic_port_id(cvmx_wqe_get_port(wqe));

	vlan_hdr_len = tso_hdr->is_vlan ? VLAN_HLEN : 0;
	proto_hdr_len = tso_hdr->hdr_len;
	tun_hdr_len = /* tso_hdr->tun_hdr_len */ 0;

	gso_size = tso_info->gso_size;
	gso_segs = DIV_ROUND_UP((cvmx_wqe_get_len(wqe) - front_size - proto_hdr_len - tun_hdr_len), gso_size);
	if (gso_segs > 512)
		return -1;

	CVMX_SYNCWS;

	prev.u64 = prev_seg_buf.u64 = 0;
	front->irh.s.opcode = OPCODE_NIC;
	front->irh.s.subcode = OCT_NIC_TSO_COMPLETION_OP;
	((cvmx_wqe_78xx_t *)wqe)->word2.software = 1;


	print_debug("GSO SIZE:%d SEGS:%d TOT-LEN:%d PROTO-LEN:%d \n", gso_size, gso_segs, cvmx_wqe_get_len(wqe), proto_hdr_len);

	for(i=0; i< gso_segs; i++) {
		struct tso_gather_buf_o3 *glist_o3_ptr = NULL;
		cvmx_buf_ptr_pki_t cur_buf;
		struct iphdr *ip4 = NULL;
		struct ipv6hdr *ip6 = NULL;
		struct tcphdr *tcp = NULL;
		uint8_t *proto_hdr_ptr = NULL;
		int32_t buf_cnt = 0, payload_size = 0;

		cur_buf.u64 = 0;

		glist_o3_ptr =  &temp_gather_list[i].g_bufs[0];

		/* FIXME: Hardcoded to 1 for IPSec. May need more for Tunnel headers support. */
		glist_o3_ptr += 1;

		if(i == 0) {
			/*
 			 * Expected segment payload len
			 * 					=  gso size, for all segments except last segment
 			 * 					<= gso_size, for last segment
 			 */
			expctd_seglen = (i == (gso_segs-1))?
							(cvmx_wqe_get_len(wqe) - front_size - proto_hdr_len - tun_hdr_len) : gso_size;

			/* Check whether total segment data is present in one packet buffer */
			remaining = cvmx_wqe_get_pki_pkt_ptr(wqe).size - front_size - proto_hdr_len - tun_hdr_len;

			payload_size = (remaining > expctd_seglen)? expctd_seglen:remaining;

			/* First buffer address in the segment */
			glist_o3_ptr[buf_cnt].buf.u64 = 0;
			glist_o3_ptr[buf_cnt].buf.s.addr = (cvmx_wqe_get_pki_pkt_ptr(wqe).addr + front_size);
			glist_o3_ptr[buf_cnt].buf.s.size = payload_size + proto_hdr_len + tun_hdr_len;
			glist_o3_ptr[buf_cnt].buf.s.i = 1;
			glist_o3_ptr[buf_cnt].aura = cvmx_wqe_get_aura(wqe);


			remaining -= payload_size;

			prev = cvmx_wqe_get_pki_pkt_ptr(wqe);

			while(payload_size < expctd_seglen) {
				/* Data present in more packet buffers */
				buf_cnt++;
				if (buf_cnt >  MAX_GATHER_BUFS_O3) {
					tso_free_lists_o3(temp_gather_list, 0 , i);
					return -1;
				}

				/* Fetch the next buffer and add entry in gather list */
				cur_buf = *((cvmx_buf_ptr_pki_t *) cvmx_phys_to_ptr(prev.addr - 8));

				/* Fill the buffer address in gather list */
				glist_o3_ptr[buf_cnt].buf.u64 = 0;
				glist_o3_ptr[buf_cnt].buf.s.addr = cur_buf.addr;
				glist_o3_ptr[buf_cnt].buf.s.size = (cur_buf.size > (expctd_seglen - payload_size)) ?
									(expctd_seglen - payload_size) : cur_buf.size;
				glist_o3_ptr[buf_cnt].buf.s.i = 1;
				glist_o3_ptr[buf_cnt].aura = cvmx_wqe_get_aura(wqe);/* get from wqe */

				payload_size += glist_o3_ptr[buf_cnt].buf.s.size;
				remaining = cur_buf.size - glist_o3_ptr[buf_cnt].buf.s.size;

				prev = cur_buf;
			}

			/* TODO: Add Tunnel header support. */

			if (!tso_hdr->is_v6) {
				ip4 = tso_hdr->iphdr;
				if (ip4->ihl > 5)
					is_ipv4opts = 1;

				tcp = tso_hdr->tcp;

				/* Modify total length in IP Header */
				ip4->tot_len = (proto_hdr_len - ETH_HLEN - vlan_hdr_len) + payload_size;

				/* Store IP Identification and TCP next Seq num */
				ip_id   = ip4->id;
			} else {
				ip6 = tso_hdr->iphdr;
				tcp = tso_hdr->tcp;

				ipv6exthdrs_len = (uint8_t *)tcp - (uint8_t*)ip6 - 40;

				ip6->payload_len = (proto_hdr_len - ETH_HLEN - vlan_hdr_len - 40) + payload_size;
			}

			tcp_next_seq = tcp->seq + payload_size;

			/* If TCP FIN or PSH is set, reset them in first segment */
			tcp_fin = tcp->fin;
			tcp->fin = 0;
			tcp_psh = tcp->psh;
			tcp->psh = 0;

		} else {

			/* Protocol header to store headers of segmented packets */
			cvmx_fpa3_gaura_t gaura;
			proto_hdr_ptr = (uint8_t *) cvmx_fpa_alloc(CVMX_FPA_PROTOCOL_HEADER_POOL);
			if(NULL == proto_hdr_ptr ) {
				print_error("protocol header alloc failed\n");
				tso_free_lists_o3(temp_gather_list, 0 , i);
				return -1;
			}

			/* Copy protocol header from original packet */
			memcpy(proto_hdr_ptr,
					cvmx_phys_to_ptr(wqe->packet_ptr.s.addr + front_size),
					(proto_hdr_len + tun_hdr_len));

			/* Fill protocol header address in the gather list */

			glist_o3_ptr[buf_cnt].buf.u64 = 0;
			glist_o3_ptr[buf_cnt].buf.s.addr = cvmx_ptr_to_phys(proto_hdr_ptr);
			glist_o3_ptr[buf_cnt].buf.s.size = proto_hdr_len + tun_hdr_len;
			gaura = cvmx_fpa1_pool_to_fpa3_aura(CVMX_FPA_PROTOCOL_HEADER_POOL);
			glist_o3_ptr[buf_cnt].aura = (gaura.node << 10) | gaura.laura;
			/*
 			 * Expected segment payload len
 			 * 					=  gso size, for all segments except last segment
 			 * 					<= gso_size, for last segment
 			 */
			expctd_seglen = (i == (gso_segs-1)) ?
						((cvmx_wqe_get_len(wqe) - front_size - proto_hdr_len - tun_hdr_len) - (gso_size*i)) : gso_size;

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

			/* TODO: Tunnel header support. */

			if (!tso_hdr->is_v6) {
				/* ip4 = (struct iphdr *) (proto_hdr_ptr + tso_hdr->inner_ip_offset); */
				ip4 = (struct iphdr *) (proto_hdr_ptr + ETH_HLEN + vlan_hdr_len);
				ip4->tot_len = expctd_seglen + proto_hdr_len - ETH_HLEN - vlan_hdr_len;
				ip4->id = ip_id + 1;
				ip_id = ip4->id;
				tcp = (struct tcphdr *) ((uint32_t *)ip4 + ip4->ihl);
			} else {
				/* ip6 = (struct ipv6hdr *) (proto_hdr_ptr + tso_hdr->inner_ip_offset); */
				ip6 = (struct ipv6hdr *) (proto_hdr_ptr + ETH_HLEN + vlan_hdr_len);
				tcp = (struct tcphdr *) ((uint8_t *)ip6 + 40 + ipv6exthdrs_len);
				ip6->payload_len = expctd_seglen + proto_hdr_len - ETH_HLEN - vlan_hdr_len - 40;

			}

			tcp->seq = tcp_next_seq;
			tcp_next_seq = tcp->seq + payload_size;

			/* Retain FIN and PSH bits for last segment
  			 * For other segments, reset
  			 */
			tcp->fin = (i == (gso_segs-1)) ? tcp_fin:0;
			tcp->psh = (i == (gso_segs-1)) ? tcp_psh:0;
		}

		prev_seg_buf.u64 = 0;
		prev_seg_buf.addr = glist_o3_ptr[buf_cnt].buf.s.addr;
		prev_seg_buf.size = glist_o3_ptr[buf_cnt].buf.s.size;

		temp_gather_list[i].nbufs = buf_cnt + 1;
		lengths[i] = payload_size + proto_hdr_len + tun_hdr_len;

		print_debug("seg#:%d nbufs:%d length:%d  \n", i, temp_gather_list[i].nbufs, lengths[i]);

		if (!tso_hdr->is_v6) {
			cvmcs_nic_ip_header_checksum(ip4, &ip4->check);
			if (is_ipv4opts) {
				/* TODO options can be handled by PKO3 */
				/* cvmcs_nic_put_tcp_checksum_ipv4_glist(ip4, tcp, glist_ptr, buf_cnt+1); */
			}
		} else if (ipv6exthdrs_len > 0) {
				/* TODO extensions can be handled by PKO3 */
			/* cvmcs_nic_put_tcp_checksum_ipv6_glist(ip6, ipv6exthdrs_len, tcp, glist_ptr, buf_cnt+1); */
		}
	}

	/* TODO: PKO3 can calculate checksums when options/ext hdrs are present.*/
	if (is_ipv4opts || ipv6exthdrs_len > 0) {
		ipoffset = 0;
		l4_offset = 0;
	} else {
		ipoffset = (uint8_t *)tso_hdr->iphdr - (uint8_t *)tso_hdr->ethhdr;
		l4_offset = (uint8_t *)tso_hdr->tcp - (uint8_t *)tso_hdr->ethhdr;
	}

	print_debug("ipoffset:%u l4_offset:%u \n", ipoffset, l4_offset);

	if (tso_info->cb)
		return tso_info->cb(wqe, gso_segs, ipoffset, l4_offset, (void *)temp_gather_list,
					lengths, ifidx, tso_info->cb_arg);
	else
		return cvmcs_tso_send_gather_list_to_wire_pko3(temp_gather_list, ifidx,
					lengths, wqe, gso_segs, ipoffset, l4_offset, 0, 0);
}

/* Function to chunk the tcp payload and finally calls a callback function */
static int
cvmcs_nic_process_tso(cvmx_wqe_t * wqe, tso_info_t * tso_info,
		      tso_hdr_t * tso_hdr, int ifidx)
{
	cvmx_buf_ptr_t prev;
	cvmx_buf_ptr_t prev_seg_buf;
	uint16_t ip_id = 0, tcp_fin = 0, tcp_psh = 0;
	uint32_t tcp_next_seq = 0;
	uint32_t proto_hdr_len = 0, vlan_hdr_len = 0;
	int32_t i = 0, remaining = 0;
	cvmx_buf_ptr_t temp_gather_list[1024];
	uint32_t lengths[1024];
	int32_t expctd_seglen = 0;
	uint16_t gso_segs = 0;
	uint32_t tcp_payload_len =
	    cvmx_wqe_get_len(wqe) - (tso_info->tun_hdr_len +
				     tso_hdr->hdr_len);
	uint16_t gso_size = tso_info->gso_size;
	cvmx_buf_ptr_t first_buf;
	uint8_t ip_offset = 0;

	first_buf.u64 = 0;

	cvmx_fpa_async_alloc(CVMCS_TEST_BUF_PTR, CVMX_FPA_GATHER_LIST_POOL);

	proto_hdr_len = tso_hdr->hdr_len;
	vlan_hdr_len = tso_hdr->is_vlan ? VLAN_HLEN : 0;
	ip_offset = ETH_HLEN + vlan_hdr_len + tso_info->tun_hdr_len;

	gso_segs = DIV_ROUND_UP(tcp_payload_len, gso_size);
	if (gso_segs > 1024)
		return TSO_FAILED;

	CVMX_SYNCWS;

	prev.u64 = prev_seg_buf.u64 = 0;

	print_debug("GSO SIZE : %d SEGS : %d TOT LEN : %d PROTO LEN : %d \n",
		    gso_size, gso_segs, tcp_payload_len, proto_hdr_len);

	/* printf("-%d:%d-\n", gso_segs, gso_size); */
	for (i = 0; i < gso_segs; i++) {
		cvmx_buf_ptr_t *glist_ptr = NULL;
		cvmx_buf_ptr_t cur_buf;
		struct iphdr *ip4 = NULL;
		struct ipv6hdr *ip6 = NULL;
		struct tcphdr *tcp = NULL;
		uint8_t *proto_hdr_ptr = NULL;
		uint8_t *tun_hdr_ptr = NULL;
		int32_t buf_cnt = 0, payload_size = 0;

		cur_buf.u64 = 0;

		/* Gather list to stored buffer addresses of segmented packet */
		glist_ptr =
		    (cvmx_buf_ptr_t *)
		    cvmx_fpa_async_alloc_finish(CVMCS_TEST_BUF_PTR,
						CVMX_FPA_GATHER_LIST_POOL);
		if (NULL == glist_ptr) {
			print_error("Gather list alloc failed\n");
			tso_free_lists(temp_gather_list, 0, i);
			return TSO_FAILED;
		}

		glist_ptr += 4;	// Making sure sufficient free space for 4 pointer at top

		if (i == 0) {
			// Start of the content we are interested in
			first_buf.s.size =
			    wqe->packet_ptr.s.size - tso_info->ethoff;
			first_buf.s.addr =
			    wqe->packet_ptr.s.addr + tso_info->ethoff;
			/*
			 * Expected segment payload len
			 *      =  gso size, for all segments except last segment
			 *      <= gso_size, for last segment
			 */
			expctd_seglen =
			    (i == (gso_segs - 1)) ? tcp_payload_len : gso_size;

			/* Check whether total segment data is present in one packet buffer
			 * Front should have to be adjusted earlier
			 */
			remaining = first_buf.s.size - proto_hdr_len;
			payload_size =
			    (remaining >
			     expctd_seglen) ? expctd_seglen : remaining;

			/* First buffer address in the segment */
			glist_ptr[buf_cnt].u64 = 0;
			glist_ptr[buf_cnt].s.addr = first_buf.s.addr;
			glist_ptr[buf_cnt].s.size =
			    payload_size + proto_hdr_len;
			glist_ptr[buf_cnt].s.i = 1;

			remaining -= payload_size;

			prev = wqe->packet_ptr;

			while (payload_size < expctd_seglen) {
				/* Data present in more packet buffers */
				buf_cnt++;

				/* Fetch the next buffer and add entry in gather list */
				cur_buf =
				    *((cvmx_buf_ptr_t *)
				      cvmx_phys_to_ptr(prev.s.addr - 8));

				/* Fill the buffer address in gather list */
				glist_ptr[buf_cnt].u64 = 0;
				glist_ptr[buf_cnt].s.addr = cur_buf.s.addr;
				glist_ptr[buf_cnt].s.size =
				    (cur_buf.s.size >
				     (expctd_seglen -
				      payload_size)) ? (expctd_seglen -
							payload_size) : cur_buf.
				    s.size;
				glist_ptr[buf_cnt].s.i = 1;

				payload_size += glist_ptr[buf_cnt].s.size;
				remaining =
				    cur_buf.s.size - glist_ptr[buf_cnt].s.size;

				prev = cur_buf;
			}

			if (!tso_hdr->is_v6) {
				ip4 = (struct iphdr *)tso_hdr->iphdr;
				tcp = (struct tcphdr *)tso_hdr->tcp;

				/* Modify total length in IP Header */
				ip4->tot_len =
				    (proto_hdr_len - ETH_HLEN - vlan_hdr_len) +
				    payload_size;
				/* Store IP Identification and TCP next Seq num */
				ip_id = ip4->id;
			} else {
				ip6 = (struct ipv6hdr *)tso_hdr->iphdr;
				tcp = (struct tcphdr *)tso_hdr->tcp;
				ip6->payload_len =
				    (proto_hdr_len - ETH_HLEN - vlan_hdr_len -
				     40) + payload_size;
			}

			tcp_next_seq = tcp->seq + payload_size;

			/* If TCP FIN or PSH is set, reset them in first segment */
			tcp_fin = tcp->fin;
			tcp->fin = 0;
			tcp_psh = tcp->psh;
			tcp->psh = 0;

		} else {

			/* Protocol header to store headers of segmented packets */
			proto_hdr_ptr =
			    (uint8_t *)
			    cvmx_fpa_alloc(CVMX_FPA_PROTOCOL_HEADER_POOL);
			if (NULL == proto_hdr_ptr) {
				print_error("protocol header alloc failed\n");
				cvmx_fpa_free((void *)((uint64_t)glist_ptr & 0xffffffffffffff80),
						CVMX_FPA_GATHER_LIST_POOL, 0);
				tso_free_lists(temp_gather_list, 0, i);
				return TSO_FAILED;
			}

			/* Copy protocol header from original packet */
			memcpy(proto_hdr_ptr,
			       cvmx_phys_to_ptr(first_buf.s.addr),
			       proto_hdr_len);

			/* Fill protocol header address in the gather list */
			glist_ptr[buf_cnt].u64 = 0;
			glist_ptr[buf_cnt].s.addr =
			    cvmx_ptr_to_phys(proto_hdr_ptr);
			glist_ptr[buf_cnt].s.size = proto_hdr_len;
			glist_ptr[buf_cnt].s.pool =
			    CVMX_FPA_PROTOCOL_HEADER_POOL;

			/*
			 * Expected segment payload len
			 *      =  gso size, for all segments except last segment
			 *      <= gso_size, for last segment
			 */
			expctd_seglen = (i == (gso_segs - 1)) ?
			    (tcp_payload_len - (gso_size * i)) : gso_size;

			payload_size = 0;
			if (remaining) {
				/* If there are some bytes 'remaining' in a packet buffer from previous segment,
				 *      Start the new segment in the same buffer
				 * Else
				 *      Skip and Go to next packet buffer
				 */
				payload_size =
				    (remaining >
				     expctd_seglen) ? expctd_seglen : remaining;

				buf_cnt++;
				glist_ptr[buf_cnt].u64 = 0;
				glist_ptr[buf_cnt].s.addr =
				    prev_seg_buf.s.addr + prev_seg_buf.s.size;
				glist_ptr[buf_cnt].s.size = payload_size;
				glist_ptr[buf_cnt].s.i = 1;

				remaining -= glist_ptr[buf_cnt].s.size;
			}

			while (payload_size < expctd_seglen) {
				buf_cnt++;
				cur_buf =
				    *((cvmx_buf_ptr_t *)
				      cvmx_phys_to_ptr(prev.s.addr - 8));
				glist_ptr[buf_cnt].u64 = 0;
				glist_ptr[buf_cnt].s.addr = cur_buf.s.addr;
				glist_ptr[buf_cnt].s.size =
				    (cur_buf.s.size >
				     (expctd_seglen -
				      payload_size)) ? (expctd_seglen -
							payload_size) : cur_buf.
				    s.size;
				glist_ptr[buf_cnt].s.i = 1;

				payload_size += glist_ptr[buf_cnt].s.size;
				remaining =
				    cur_buf.s.size - glist_ptr[buf_cnt].s.size;
				prev = cur_buf;
			}

			if (!tso_hdr->is_v6) {
				ip4 =
				    (struct iphdr *)(proto_hdr_ptr +
						     ETH_HLEN + vlan_hdr_len);
				ip4->tot_len =
				    expctd_seglen + proto_hdr_len - ETH_HLEN -
				    vlan_hdr_len;
				ip4->id = ip_id + 1;
				ip_id = ip4->id;
				tcp = (struct tcphdr *)(ip4 + 1);
			} else {
				ip6 =
				    (struct ipv6hdr *)(proto_hdr_ptr +
						       ETH_HLEN + vlan_hdr_len);
				tcp = (struct tcphdr *)(ip6 + 1);
				ip6->payload_len =
				    expctd_seglen + proto_hdr_len - ETH_HLEN -
				    vlan_hdr_len - 40;
			}

			tcp->seq = tcp_next_seq;
			tcp_next_seq = tcp->seq + payload_size;

			/* Retain FIN and PSH bits for last segment
			 * For other segments, reset
			 */
			tcp->fin = (i == (gso_segs - 1)) ? tcp_fin : 0;
			tcp->psh = (i == (gso_segs - 1)) ? tcp_psh : 0;
		}

		prev_seg_buf = glist_ptr[buf_cnt];
		temp_gather_list[i].u64 = 0;
		temp_gather_list[i].s.addr = cvmx_ptr_to_phys(glist_ptr);
		temp_gather_list[i].s.size = buf_cnt + 1;
		temp_gather_list[i].s.pool = CVMX_FPA_GATHER_LIST_POOL;

		lengths[i] = payload_size + proto_hdr_len;

		if (!tso_hdr->is_v6)
			cvmcs_nic_ip_header_checksum(ip4, &ip4->check);

		if (tso_info->tun_hdr_len) {
			glist_ptr -= 1;
			/*  Provision to store tunnel headers for each segmented packets */
			tun_hdr_ptr =
			    (uint8_t *)
			    cvmx_fpa_alloc(CVMX_FPA_PROTOCOL_HEADER_POOL);
			if (NULL == tun_hdr_ptr) {
				print_error("tunnel header alloc failed\n");
				cvmx_fpa_free((void *)((uint64_t)glist_ptr & 0xffffffffffffff80),
						CVMX_FPA_GATHER_LIST_POOL, 0);
				tso_free_lists(temp_gather_list, 0, i);
				return TSO_FAILED;
			}

			/* Copy protocol header from original packet */
			memcpy(tun_hdr_ptr,
			       tso_info->tun_hdr,
			       tso_info->tun_hdr_len);

			/* Fill protocol header address in the gather list */
			glist_ptr[0].u64 = 0;
			glist_ptr[0].s.addr = cvmx_ptr_to_phys(tun_hdr_ptr);
			glist_ptr[0].s.size = tso_info->tun_hdr_len;
			glist_ptr[0].s.pool = CVMX_FPA_PROTOCOL_HEADER_POOL;

			temp_gather_list[i].s.addr =
			    cvmx_ptr_to_phys(glist_ptr);
			temp_gather_list[i].s.size += 1;
			lengths[i] += tso_info->tun_hdr_len;

			/* Call the tunnel header updation callback */
			if (tso_info->tun_hdr_cb)
				tso_info->tun_hdr_cb(wqe, &glist_ptr[0],
						     lengths[i], i,
						     tso_info->cb_arg);
		}

		if (i != gso_segs - 1)
			cvmx_fpa_async_alloc(CVMCS_TEST_BUF_PTR,
					     CVMX_FPA_GATHER_LIST_POOL);
	}

	if (tso_info->cb)
		return tso_info->cb(wqe, gso_segs, ip_offset, 0,
				    temp_gather_list, lengths,
				    ifidx, tso_info->cb_arg);
	else
		return cvmcs_nic_send_gather_list_to_wire(wqe, gso_segs,
							  ip_offset, 
							  temp_gather_list,
							  lengths, ifidx);
}

static
void tso_get_headers(cvmx_wqe_t * wqe, tso_info_t * tso_info,
		     tso_hdr_t * tso_hdr)
{
	cvmcs_nic_metadata_t *mdata = CVMCS_NIC_METADATA(wqe);

	tso_hdr->is_vlan = CVMCS_NIC_METADATA_IS_VLAN(mdata);
	tso_hdr->ethhdr = CVMCS_NIC_METADATA_L2_HEADER(mdata);
	tso_hdr->is_v6 = CVMCS_NIC_METADATA_IS_IPV6(mdata);
	tso_hdr->iphdr = CVMCS_NIC_METADATA_L3_HEADER(mdata);
	tso_hdr->tcp = (struct tcphdr *)CVMCS_NIC_METADATA_L4_HEADER(mdata);
	tso_hdr->hdr_len = CVMCS_NIC_METADATA_HEADER_LENGTH(mdata);

	return;
}

static
int check_tso_valid_pkt(tso_hdr_t * tso_hdr)
{
	struct tcphdr *tcp;
	struct iphdr *iph4;
	struct ipv6hdr *iph6;

	/* CHECK FOR VLAN PACKET */
	if (tso_hdr->is_vlan) {
		struct vlan_hdr *vlan = (struct vlan_hdr *)tso_hdr->ethhdr;
		if ((ETH_P_IP != vlan->proto) && (ETH_P_IPV6 != vlan->proto))
			return -1;
		if ((ETH_P_8021Q != vlan->vlan_proto))
			return -1;
	}

	if (!tso_hdr->is_v6) {
		iph4 = (struct iphdr *)tso_hdr->iphdr;

		if (iph4->frag_off & IP_MF) {
			print_debug("IP MF is set[%x]\n", iph4->frag_off);
			return -1;
		}

		if (iph4->frag_off & IP_OFFSET) {
			print_debug("IP Frag offset is set[%x]\n",
				    iph4->frag_off);
			return -1;
		}

		if (iph4->protocol != IPPROTO_TCP) {
			print_debug("IP Protocol[%x] is NOT Tcp\n",
				    iph4->protocol);
			return -1;
		}
	} else {
		iph6 = (struct ipv6hdr *)tso_hdr->iphdr;

		if (iph6->nexthdr != IPPROTO_TCP) {
			printf("NOT VALID TSO PACKET\n");
			return -1;
		}
	}

	tcp = (struct tcphdr *)tso_hdr->tcp;
	if (tcp->syn || tcp->urg || tcp->rst) {
		print_debug("TCP flags set syn[%x] urg[%x] rst[%x]\n",
			    tcp->syn, tcp->urg, tcp->rst);
		return -1;
	}

	if (tcp->urg_ptr) {
		print_debug("TCP urg ptr[%x] is set\n", tcp->urg_ptr);
		return -1;
	}

	return 0;
}

int
cvmcs_nic_process_ipsec_hw_tso_o3(cvmx_wqe_t *wqe, tso_hdr_t *tso_hdr, tso_info_t * tso_info);

int check_hw_tso_valid_pkt(cvmx_wqe_t *wqe, tso_hdr_t *tso_hdr, tso_info_t *tso_info)
{
#define MIN_HW_TSO_LEN 	576
#define MAX_HW_TSO_SEGS 128
#define INSHDR_MDATA_SIZE 24 

	uint16_t gso_segs;

        gso_segs = DIV_ROUND_UP((cvmx_wqe_get_len(wqe) - tso_hdr->hdr_len), tso_info->gso_size);

        if (((tso_hdr->hdr_len + INSHDR_MDATA_SIZE + tso_info->gso_size) < MIN_HW_TSO_LEN) ||
		(gso_segs > MAX_HW_TSO_SEGS))
		return 0;

	return 1;
}

int cvmcs_handle_tso(cvmx_wqe_t * wqe, tso_info_t * tso_info, int ifidx)
{
	tso_hdr_t tso_hdr = { 0 };

	tso_get_headers(wqe, tso_info, &tso_hdr);
	if (check_tso_valid_pkt(&tso_hdr)) {
		print_debug("PACKET NOT VALID FOR TSO ...\n");
		return TSO_INVALID;
	}

	if (OCTEON_IS_MODEL(OCTEON_CN73XX) && check_hw_tso_valid_pkt(wqe, &tso_hdr, tso_info))
		return cvmcs_nic_process_ipsec_hw_tso_o3(wqe, &tso_hdr, tso_info);

	if (octeon_has_feature(OCTEON_FEATURE_PKO3))
                return cvmcs_nic_process_tso_o3(wqe, tso_info, &tso_hdr);
	else
		return cvmcs_nic_process_tso(wqe, tso_info, &tso_hdr, ifidx);
}

/* This has to come from the consumers of TSO lib */
int tso_process_pkt(cvmx_wqe_t * wqe, int front_size, tso_info_t *tso_info)
{
	cvmx_raw_inst_front_t *front = NULL;
//	union octnic_packet_params packet_params = { 0 };
	int ifidx = 0;
	uint64_t nextptr;

	print_debug("####%s: Entry. \n", __func__);

	if (OCTEON_IS_MODEL(OCTEON_CN78XX) || OCTEON_IS_MODEL(OCTEON_CN73XX)) {
		print_debug("78XX packet. \n");
		if (front_size)
			tso_info->ethoff += front_size;
	} else {
		if (front_size) {
			nextptr = *((uint64_t *)CVM_DRV_GET_PTR(wqe->packet_ptr.s.addr - 8));
			wqe->packet_ptr.s.addr += front_size;
			wqe->packet_ptr.s.size -= front_size;
			cvmx_wqe_set_len(wqe, (cvmx_wqe_get_len(wqe) - front_size));
			*((uint64_t *)CVM_DRV_GET_PTR(wqe->packet_ptr.s.addr - 8)) = nextptr;
		}

		front = (cvmx_raw_inst_front_t *) wqe->packet_data;
//		packet_params.u32 = front->irh.s.ossp;
		ifidx = get_vnic_port_id(cvmx_wqe_get_port(wqe));
		front->irh.s.opcode = OPCODE_NIC;
		front->irh.s.subcode = OCT_NIC_TSO_COMPLETION_OP;
	}

	return cvmcs_handle_tso(wqe, tso_info, ifidx);
}
