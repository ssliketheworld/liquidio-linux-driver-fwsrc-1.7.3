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
#include "cvmcs-nic.h"
#include "cvmcs-common.h"
#include "cvmcs-nic-tcp.h"
#include "cvmcs-nic-udp.h"
#include "cvmcs-nic-ip.h"
#include "cvmcs-nic-ipv6.h"
#include "cvmcs-nic-ether.h"
#include "cvmcs-nic-tunnel.h"
#include "cvmcs-nic-mdata.h"

void cvmcs_nic_put_l4checksum_ipv6_with_exthdr(cvmx_wqe_t *, int );
void cvmcs_nic_put_l4checksum_ipv4(cvmx_wqe_t *, int );
int cvmcs_nic_get_l4_from_ipv6_with_exthdr(uint8_t *, uint16_t **,
				uint32_t *, uint8_t *);
int cvmcs_nic_verify_l3l4checksums_of_ip_header_with_options(cvmx_wqe_t *wqe, int offset);
int cvmcs_nic_verify_l4checksum_ipv6_with_exthdr(cvmx_wqe_t *wqe, int offset);

int
cvmcs_nic_tunnel_is_loopback_port(cvmx_wqe_t *wqe)
{
	if (octeon_has_feature(OCTEON_FEATURE_CN78XX_WQE))
		return (cvmx_wqe_get_port(wqe) ==
			CVM_PHYS_78XX_LOOPBACK_PORT);

	if (octeon_has_feature(OCTEON_FEATURE_PKND))
		return (wqe->word0.pip.cn68xx.pknd ==
			CVM_PHYS_LOOPBACK_PORT);
	else
		return (cvmx_wqe_get_port(wqe) ==
			CVM_PHYS_LOOPBACK_PORT);
}

void
cvmcs_nic_tunnel_loopback_port_init(void)
{
	int port_num;
	cvmx_pip_prt_cfgx_t port_config;
	cvmx_pip_prt_tagx_t tag_config;
	cvmx_pip_gbl_ctl_t pip_gbl_ctl;

	pip_gbl_ctl.u64 = cvmx_read_csr(CVMX_PIP_GBL_CTL);
	pip_gbl_ctl.s.l4_chk = 1;
	pip_gbl_ctl.s.ip_chk = 1;
	cvmx_write_csr(CVMX_PIP_GBL_CTL, pip_gbl_ctl.u64);
	if (octeon_has_feature(OCTEON_FEATURE_PKND)) {
		int pknd;
		pknd = cvmx_helper_get_pknd(8, 0);
		port_num = pknd;
	} else
		port_num = CVM_PHYS_LOOPBACK_PORT;

	port_config.u64 = cvmx_read_csr(CVMX_PIP_PRT_CFGX(port_num));
	//port_config.s.mode = CVMX_PIP_PORT_CFG_MODE_SKIPL2;
	port_config.s.inst_hdr = 1;
	cvmx_write_csr(CVMX_PIP_PRT_CFGX(port_num), port_config.u64);

	tag_config.u64 = cvmx_read_csr(CVMX_PIP_PRT_TAGX(port_num));
	tag_config.s.tcp6_tag_type = CVMX_POW_TAG_TYPE_NULL;
	tag_config.s.tcp4_tag_type = CVMX_POW_TAG_TYPE_NULL;
	tag_config.s.ip6_tag_type = CVMX_POW_TAG_TYPE_NULL;
	tag_config.s.ip4_tag_type = CVMX_POW_TAG_TYPE_NULL;
	tag_config.s.non_tag_type = CVMX_POW_TAG_TYPE_NULL;
	/* Put all packets in group 0. */
	tag_config.s.grp = 0;
	tag_config.s.inc_prt_flag  = FALSE;
	tag_config.s.ip6_dprt_flag = TRUE;
	tag_config.s.ip4_dprt_flag = TRUE;
	tag_config.s.ip6_sprt_flag = TRUE;
	tag_config.s.ip4_sprt_flag = TRUE;
	tag_config.s.ip4_pctl_flag = FALSE;
	tag_config.s.ip6_nxth_flag = FALSE;
	tag_config.s.ip6_dst_flag  = TRUE;
	tag_config.s.ip4_dst_flag  = TRUE;
	tag_config.s.ip6_src_flag  = TRUE;
	tag_config.s.ip4_src_flag  = TRUE;

	cvmx_write_csr(CVMX_PIP_PRT_TAGX(port_num),tag_config.u64);
}

static int
cvmcs_nic_tunnel_valid_for_offload(cvmx_wqe_t *wqe, uint8_t *skip, uint8_t *is_txl4)

{
	cvmcs_nic_metadata_t *mdata = CVMCS_NIC_METADATA(wqe);

	if (!(CVMCS_NIC_METADATA_IS_IPV4(mdata) || CVMCS_NIC_METADATA_IS_IPV6(mdata)) ||
	    !CVMCS_NIC_METADATA_IS_TUNNEL(mdata) ||
	    !(CVMCS_NIC_METADATA_IS_INNER_IPV4(mdata) || CVMCS_NIC_METADATA_IS_INNER_IPV6(mdata)) ||
	     CVMCS_NIC_METADATA_IS_IP_FRAG(mdata) || 
	     CVMCS_NIC_METADATA_IS_INNER_IP_FRAG(mdata))
		return -1;

	if (CVMCS_NIC_METADATA_IS_INNER_TCP(mdata) || CVMCS_NIC_METADATA_IS_INNER_UDP(mdata)) {
		*skip = CVMCS_NIC_METADATA_TUNNEL_HEADER_LENGTH(mdata);

		/* For packets coming from the wire, if inner IP header contains
		   options or extension headers, then firmware will verify L4 checksum */
		if (0 == *is_txl4) {
			if (CVMCS_NIC_METADATA_IS_INNER_IP_OPTS_OR_EXTH(mdata)) {
				if (CVMCS_NIC_METADATA_IS_INNER_IPV4(mdata)) {
					if (cvmcs_nic_verify_l3l4checksums_of_ip_header_with_options(wqe, CVMCS_NIC_METADATA_INNER_L3_OFFSET(mdata)) == CNNIC_CSUM_VERIFIED)
						return GOOD_CHECKSUM;
					else
						return BAD_CHECKSUM;
				} else {
					if (cvmcs_nic_verify_l4checksum_ipv6_with_exthdr(wqe, CVMCS_NIC_METADATA_INNER_L3_OFFSET(mdata)) == CNNIC_CSUM_VERIFIED)
						return GOOD_CHECKSUM;
					else
						return BAD_CHECKSUM;
				}
			}
		}

		return 0;
	}
	else if (1 == *is_txl4) {
		*is_txl4 = NO_TXL4;
		return 0;
	}

	return -1;
}

void
cvmcs_nic_tunnel_ip_offset(cvmx_wqe_t *wqe, short *offload)
{
	uint8_t skip;
	uint8_t is_txl4 = 1;
	cvmcs_nic_metadata_t *mdata = CVMCS_NIC_METADATA(wqe);

	if (!cvmcs_nic_tunnel_valid_for_offload(wqe, &skip, &is_txl4)) {

		if (CVMCS_NIC_METADATA_IS_IPV4(mdata)){
			struct iphdr *outer_iph = (struct iphdr *)
				CVMCS_NIC_METADATA_L3_HEADER(mdata);

			cvmcs_nic_ip_header_checksum(outer_iph, &outer_iph->check);
		}

		if (CVMCS_NIC_METADATA_IS_INNER_IPV4(mdata)) {
			struct iphdr *inner_iph = (struct iphdr *)
				CVMCS_NIC_METADATA_INNER_L3_HEADER(mdata);

			cvmcs_nic_ip_header_checksum(inner_iph, &inner_iph->check);
		}

		if (NO_TXL4 == is_txl4)
			return;

		*offload = CVMCS_NIC_METADATA_INNER_L3_OFFSET(mdata) + 1;

		if (CVMCS_NIC_METADATA_IS_IP_OPTS_OR_EXTH(mdata)) {

			if (CVMCS_NIC_METADATA_IS_IPV4(mdata)) {
				cvmcs_nic_put_l4checksum_ipv4(wqe, *offload - 1);
				*offload = 0;
			}
			else {
				cvmcs_nic_put_l4checksum_ipv6_with_exthdr(wqe, *offload - 1);
				*offload = 0;
			}
		}
	}
}

int
cvmcs_nic_tunnel_verify_cksum(cvmx_wqe_t **wqe, pkt_proc_flags_t *flags)
{
	int ifidx;
	cvmcs_tunnel_front_t *front;
	cvmx_wqe_t *cur_wqe = *wqe;

	front = (cvmcs_tunnel_front_t *)PACKET_START(cur_wqe);

	ifidx = front->s.ifidx;

	*wqe = front->wqe;

	if (flags->s.csum_verified == CNNIC_CSUM_VERIFIED)
		flags->s.csum_verified = CNNIC_TUN_CSUM_VERIFIED;

	flags->s.csum_verified |= front->s.outer_flags;

	cvm_free_wqe_wrapper(cur_wqe);

	return ifidx;
}

int
cvmcs_nic_78xx_tunnel_calculate_cksum(cvmx_wqe_t *wqe, int ifidx, pkt_proc_flags_t *flags)
{
	int retval;
	int queue;
	uint8_t skip = 0, is_txl4 = 0;
	cvmcs_nic_metadata_t *mdata = CVMCS_NIC_METADATA(wqe);

	if (!(retval=cvmcs_nic_tunnel_valid_for_offload(wqe, &skip, &is_txl4))) {

		cvmcs_tunnel_front_t *front;
		cvmx_pko_send_hdr_t pko_send_hdr;
		cvmx_pko_buf_ptr_t pko_send_gather;
		cvmx_buf_ptr_pki_t *tmp_lptr;
		cvmx_pko_query_rtn_t pko_status;
		int bufcount, i, len;
		unsigned node, nwords, dq;
		unsigned scr_base;

		/* Time stamp */
		if (CVMCS_NIC_METADATA_IS_PTP_HEADER(mdata))
			skip += OCTNET_FRM_PTP_HEADER_SIZE;

		front = (cvmcs_tunnel_front_t *)&mdata->ih3;
		front->ih3.u64 = 0;
		front->ih3.s.w = 0; //2 byte header
		front->ih3.s.raw = 0;
		front->ih3.s.pm = CVMX_PKI_PARSE_LA_TO_LG;
		front->ih3.s.sl = sizeof(cvmcs_tunnel_front_t) + skip;
		front->s.outer_flags = flags->s.csum_verified;
		front->s.ifidx = ifidx;
		front->wqe = wqe;

		queue = cvmx_pko_get_base_queue(CVM_PHYS_78XX_LOOPBACK_PORT);
		if (queue == -1) {
			printf("Invalid queue for Loop back\n");
			return -1;
		}

		scr_base = cvmx_pko3_lmtdma_scr_base();

		/* Separa global DQ# into node and local DQ */
		dq = queue;
		node = dq >> 10;
		dq &= (1 << 10)-1;

		cvmx_pow_tag_sw_full(wqe, (cvmx_wqe_get_tag(wqe)^dq), CVMX_POW_TAG_TYPE_ATOMIC, cvmx_wqe_get_grp(wqe));
		pko_send_hdr.u64 = 0;
		/*
		 * total len = cvmx_wqe_get_len(wqe) +
		 * (instr_hdr + outer csum flags + ifidx + pad) + wqe ptr
		 */
		pko_send_hdr.s.total = cvmx_wqe_get_len(wqe) + sizeof(cvmcs_tunnel_front_t);

   		if(OCTEON_IS_MODEL(OCTEON_CN78XX_PASS1_X))
               		pko_send_hdr.s.n2 = 0; /* L2 allocate everything */
       		else
               		pko_send_hdr.s.n2 = 1; /* No L2 allocate works faster */

		pko_send_hdr.s.aura = cvmx_wqe_get_aura(wqe);

#ifdef __LITTLE_ENDIAN_BITFIELD
       		hdr_s.s.le = 1;
#endif
		nwords = 0;
		cvmx_scratch_write64(scr_base+sizeof(uint64_t)*(nwords++), pko_send_hdr.u64);

		bufcount = cvmx_wqe_get_bufs(wqe);
		len = cvmx_wqe_get_len(wqe);

		if (bufcount > 13) {
			//TODO use jump buf
			printf("too many bufs\n");
			return -1;
		}

		pko_send_gather.u64 = 0;
		pko_send_gather.s.subdc3 = CVMX_PKO_SENDSUBDC_GATHER;

		pko_send_gather.s.size = sizeof(cvmcs_tunnel_front_t);
		pko_send_gather.s.addr = CVM_DRV_GET_PHYS(front);
		pko_send_gather.s.i = 1; /* Don't free */
		cvmx_scratch_write64(scr_base+sizeof(uint64_t)*(nwords++), pko_send_gather.u64);

		tmp_lptr = (cvmx_buf_ptr_pki_t *)&wqe->packet_ptr;

		for (i = 0; i < bufcount; i++) {
			pko_send_gather.s.size = (tmp_lptr->size < len) ? tmp_lptr->size: len;
			pko_send_gather.s.addr = tmp_lptr->addr;
			pko_send_gather.s.i = 1; /* Don't free */
			cvmx_scratch_write64(scr_base+sizeof(uint64_t)*(nwords++), pko_send_gather.u64);

			len -= tmp_lptr->size;
			tmp_lptr = (cvmx_buf_ptr_pki_t *)cvmx_phys_to_ptr(tmp_lptr->addr - 8);
		}

	        cvmx_pow_tag_sw_wait();

		pko_status = cvmcs_pko3_lmtdma(node, dq, nwords, false, true);

		if (cvmx_unlikely(pko_status.s.dqstatus != PKO_DQSTATUS_PASS)) {
			return -1;
		}

		return 0;

	} else if (retval == GOOD_CHECKSUM) {
		flags->s.csum_verified = CNNIC_TUN_CSUM_VERIFIED;
	}

	return -1;
}

int
cvmcs_nic_tunnel_calculate_cksum(cvmx_wqe_t *wqe, int ifidx, pkt_proc_flags_t *flags)
{
	int retval;
	uint64_t port, queue;
	uint8_t skip = 0, is_txl4 = 0;

	cvmcs_nic_metadata_t *mdata = CVMCS_NIC_METADATA(wqe);

	if (!(retval=cvmcs_nic_tunnel_valid_for_offload(wqe, &skip, &is_txl4))) {
		cvmx_buf_ptr_t *glist_ptr = NULL;
		uint32_t buf_cnt;
		int32_t i, len;
		cvmx_buf_ptr_t lptr;
		cvmcs_tunnel_front_t *front;
		cvmx_pko_command_word0_t pko_command;

		cvmx_fpa_async_alloc(CVMCS_TEST_BUF_PTR, CVMX_FPA_GATHER_LIST_POOL);

               	/* Gather list to stored buffer addresses of segmented packet */
               	glist_ptr = (cvmx_buf_ptr_t *) cvmx_fpa_async_alloc_finish(
                                            CVMCS_TEST_BUF_PTR, CVMX_FPA_GATHER_LIST_POOL);
               	if(NULL == glist_ptr ) {
                       	printf("Gather list alloc failed\n");
                       	return -1;
               	}

		/* Time stamp */
		if (CVMCS_NIC_METADATA_IS_PTP_HEADER(mdata))
			skip += OCTNET_FRM_PTP_HEADER_SIZE;

		front = (cvmcs_tunnel_front_t *) &mdata->ih2;
		front->ih2.u64 = 0;
		front->ih2.s.r = 0;
		front->ih2.s.pm = CVMX_PIP_PORT_CFG_MODE_SKIPL2;
		front->ih2.s.sl = sizeof(cvmcs_tunnel_front_t) + skip;
		front->s.outer_flags = flags->s.csum_verified;
		front->s.ifidx = ifidx;
		front->wqe = wqe;
			
		buf_cnt = 0;

               	glist_ptr[buf_cnt].u64 = 0;
               	glist_ptr[buf_cnt].s.addr = cvmx_ptr_to_phys(front);
               	glist_ptr[buf_cnt].s.size = sizeof(cvmcs_tunnel_front_t);
               	glist_ptr[buf_cnt].s.pool = CVMX_FPA_WQE_POOL;
		glist_ptr[buf_cnt].s.i = 1; /* Don't free */

		buf_cnt++;

		len = cvmx_wqe_get_len(wqe);
		lptr = (cvmx_buf_ptr_t )wqe->packet_ptr;

		for (i = 0; i < cvmx_wqe_get_bufs(wqe); i++) {

               		glist_ptr[buf_cnt].u64 = 0;
               		glist_ptr[buf_cnt].s.addr = (lptr.s.size < len) ? lptr.s.size : len;
               		glist_ptr[buf_cnt].s.size = lptr.s.addr;
               		glist_ptr[buf_cnt].s.pool = lptr.s.pool;
               		glist_ptr[buf_cnt].s.back = lptr.s.back;
			glist_ptr[buf_cnt].s.i = 1; /* Don't Free */

			buf_cnt++;

			len -= lptr.s.size;

			lptr = *((cvmx_buf_ptr_t *)cvmx_phys_to_ptr(lptr.s.addr - 8));
		}

		if (octeon_has_feature(OCTEON_FEATURE_PKND)) {
			port = cvmx_helper_cfg_ipd2pko_port_base(cvmx_helper_get_ipd_port(8, 0));
			queue = cvmx_pko_get_base_queue_pkoid(port);
		} else {
			port = CVM_PHYS_LOOPBACK_PORT;
			queue = cvmx_pko_get_base_queue(port);
		}

		/* Prepare to send a packet to PKO. */
		if (octeon_has_feature(OCTEON_FEATURE_PKND))
			cvmx_pko_send_packet_prepare_pkoid(port, queue, 1);
		else
			cvmx_pko_send_packet_prepare(port, queue, 1);

		lptr.u64 = 0;
		lptr.s.addr = cvmx_ptr_to_phys(glist_ptr);
		lptr.s.size = buf_cnt;
		lptr.s.pool = CVMX_FPA_GATHER_LIST_POOL;

		pko_command.u64           = 0;
		pko_command.s.ignore_i    = 0;
		pko_command.s.dontfree    = 0;
		pko_command.s.gather   	  = 1;
		pko_command.s.segs        = buf_cnt;
		pko_command.s.total_bytes = cvmx_wqe_get_len(wqe) + sizeof(cvmcs_tunnel_front_t);
		pko_command.s.ipoffp1     = 0;
 
		if (octeon_has_feature(OCTEON_FEATURE_PKND))
			cvmx_pko_send_packet_finish_pkoid(port, queue, pko_command, lptr, 1);
		else
			cvmx_pko_send_packet_finish(port, queue, pko_command, lptr, 1);

		return 0;

	} else if (retval == GOOD_CHECKSUM) {
		flags->s.csum_verified = CNNIC_TUN_CSUM_VERIFIED;
	}

	return -1;
}
