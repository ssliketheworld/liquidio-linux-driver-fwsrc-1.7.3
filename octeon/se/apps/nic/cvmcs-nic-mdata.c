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
/*
#include "global-config.h"
#include "octeon-pci-console.h"
#include "cvmcs-common.h"
#include "cvmcs-nic.h"
#include  <cvmx-atomic.h>
#include  <cvmx-access.h>
#include  <cvmx-fau.h>
#include "cvm-nic-ipsec.h"
*/
#include "cvmcs-nic.h"
#include  <cvmx-atomic.h>
#include "cvmx-helper.h"
#include "cvmx-helper-board.h"
#include "cvmx-helper-bgx.h"
#include "cvmx-mdio.h"
#include "cvmx-rwlock.h"
#include "cvm-pci-loadstore.h"
#include "cvmcs-nic-tunnel.h"
#include "cvmcs-nic-rss.h"
#include "cvmcs-nic-switch.h"
#include "cvmcs-nic-mdata.h"
#include "cvmcs-nic-ipv6.h"
#include "cvmcs-nic-ether.h"
#include "cvmcs-nic-udp.h"
#include "cvmcs-nic-tcp.h"
#include "cvm-nic-ipsec.h"

static void cvmcs_nic_mdata_strip_front_data(cvmx_wqe_t *wqe)
{
        uint64_t nextptr, startptr;
        cvmx_buf_ptr_pki_t  *pki_lptr;
	cvmcs_nic_metadata_t *mdata = CVMCS_NIC_METADATA(wqe);

        if (octeon_has_feature(OCTEON_FEATURE_CN78XX_WQE)) {
                pki_lptr = (cvmx_buf_ptr_pki_t *)&wqe->packet_ptr;
                nextptr = *((uint64_t *)CVM_DRV_GET_PTR(pki_lptr->addr - 8));
                pki_lptr->addr += mdata->front_size;
                pki_lptr->size -= mdata->front_size;
                *((uint64_t *)CVM_DRV_GET_PTR(pki_lptr->addr - 8)) = nextptr;
        } else {
                nextptr = *((uint64_t *) CVM_DRV_GET_PTR(wqe->packet_ptr.s.addr - 8));
                startptr = (((wqe->packet_ptr.s.addr >> 7) - wqe->packet_ptr.s.back) << 7);
                wqe->packet_ptr.s.addr += mdata->front_size;
                wqe->packet_ptr.s.size -= mdata->front_size;
                wqe->packet_ptr.s.back = ((wqe->packet_ptr.s.addr - startptr) >> 7);
                *((uint64_t *) CVM_DRV_GET_PTR(wqe->packet_ptr.s.addr - 8)) = nextptr;
        }

        cvmx_wqe_set_len(wqe, (cvmx_wqe_get_len(wqe) - mdata->front_size));
}

static void cvmcs_nic_strip_vlan_tag(cvmx_wqe_t *wqe)
{
        int32_t i;
        uint32_t *ptr;
        struct vlan_hdr *vlh;
	uint64_t nextptr, start;
	cvmcs_nic_metadata_t *mdata = CVMCS_NIC_METADATA(wqe);

        vlh = (struct vlan_hdr *)CVMCS_NIC_METADATA_PACKET_START(mdata);

        if (vlh->vlan_proto != ETH_P_8021Q) {
		return;
	}

	mdata->outer_vlanTCI = vlh->vlan_TCI;

        i = (2 * ETH_ALEN) / 4;

	if (CVMCS_NIC_METADATA_IS_PTP_HEADER(mdata))
        	i += OCTNET_FRM_PTP_HEADER_SIZE / 4;

	if (octeon_has_feature(OCTEON_FEATURE_CN78XX_WQE)) {
		cvmx_buf_ptr_pki_t *tmp_lptr = (cvmx_buf_ptr_pki_t *)&wqe->packet_ptr;
		nextptr = *((uint64_t *)CVM_DRV_GET_PTR(tmp_lptr->addr - 8));
		ptr = (uint32_t *)CVM_DRV_GET_PTR(tmp_lptr->addr);

                while (i > 0) {
                        ptr[i] = ptr[i-1];
                        i--;
                }

                tmp_lptr->addr += 4;
                tmp_lptr->size -= 4;

		*((uint64_t *)CVM_DRV_GET_PTR(tmp_lptr->addr - 8)) = nextptr;
	} else {
		cvmx_buf_ptr_t *buf_ptr = (cvmx_buf_ptr_t *)&wqe->packet_ptr;
                nextptr = *((uint64_t *) cvmx_phys_to_ptr(buf_ptr->s.addr - 8));
                start = (((buf_ptr->s.addr >> 7) - buf_ptr->s.back) << 7);
                ptr = (uint32_t *) cvmx_phys_to_ptr(buf_ptr->s.addr);

                while (i > 0) {
                        ptr[i] = ptr[i-1];
                        i--;
                }

                buf_ptr->s.addr += 4;
                buf_ptr->s.size -= 4;
                buf_ptr->s.back = ((buf_ptr->s.addr - start) >> 7);

                *(uint64_t *) cvmx_phys_to_ptr(buf_ptr->s.addr - 8) = nextptr;
        }
	
	cvmx_wqe_set_len(wqe, (cvmx_wqe_get_len(wqe) - 4));

	mdata->packet_start = (uint8_t *)PACKET_START(wqe);

	if (CVMCS_NIC_METADATA_IS_PTP_HEADER(mdata))
		mdata->packet_start += OCTNET_FRM_PTP_HEADER_SIZE;

	return;
}

void cvmcs_nic_insert_vlan_tag(cvmx_wqe_t *wqe)
{
	uint64_t nextptr, startptr;
	uint8_t *bufptr;
	cvmcs_nic_metadata_t *mdata = CVMCS_NIC_METADATA(wqe);

	if ((!CVMCS_NIC_METADATA_IS_PACKET_FROM_DPI(mdata)) ||
	    ( CVMCS_NIC_METADATA_VLAN_TCI(mdata) == 0))
		return;

	if (octeon_has_feature(OCTEON_FEATURE_CN78XX_WQE)) {
		cvmx_buf_ptr_pki_t *tmp_lptr = (cvmx_buf_ptr_pki_t *)&wqe->packet_ptr;
		nextptr = *((uint64_t *)CVM_DRV_GET_PTR(tmp_lptr->addr - 8));

		/* Insert vlan tag */
		tmp_lptr->addr -= 4;
		tmp_lptr->size += 4;

		bufptr = (uint8_t *)CVM_DRV_GET_PTR(tmp_lptr->addr);

		((uint32_t *)bufptr)[0] = ((uint32_t *)bufptr)[1];
		((uint32_t *)bufptr)[1] = ((uint32_t *)bufptr)[2];
		((uint32_t *)bufptr)[2] = ((uint32_t *)bufptr)[3];
		((uint32_t *)bufptr)[3] = ((0x8100 << 16) | CVMCS_NIC_METADATA_VLAN_TCI(mdata));

		*((uint64_t *)CVM_DRV_GET_PTR(tmp_lptr->addr - 8)) = nextptr;

	} else {

		nextptr = *((uint64_t *) CVM_DRV_GET_PTR(wqe->packet_ptr.s.addr - 8));
		startptr = (((wqe->packet_ptr.s.addr >> 7) - wqe->packet_ptr.s.back) << 7);
		/* Insert vlan tag */
		wqe->packet_ptr.s.addr -= 4;
		wqe->packet_ptr.s.size += 4;
		wqe->packet_ptr.s.back = ((wqe->packet_ptr.s.addr - startptr) >> 7);

		bufptr = (uint8_t *)CVM_DRV_GET_PTR(wqe->packet_ptr.s.addr);

		((uint32_t *)bufptr)[0] = ((uint32_t *)bufptr)[1];
		((uint32_t *)bufptr)[1] = ((uint32_t *)bufptr)[2];
		((uint32_t *)bufptr)[2] = ((uint32_t *)bufptr)[3];
		((uint32_t *)bufptr)[3] = ((0x8100 << 16) | CVMCS_NIC_METADATA_VLAN_TCI(mdata));

		*((uint64_t *) CVM_DRV_GET_PTR(wqe->packet_ptr.s.addr - 8)) = nextptr;
	}

	cvmx_wqe_set_len(wqe, (cvmx_wqe_get_len(wqe) + 4));

	mdata->packet_start = (uint8_t *)PACKET_START(wqe);

	if (CVMCS_NIC_METADATA_IS_PTP_HEADER(mdata))
		mdata->packet_start += OCTNET_FRM_PTP_HEADER_SIZE;
}
#if defined(OVS_IPSEC) || defined(VSWITCH)
void *
#else
static void *
#endif
cvmcs_nic_mdata_get_l4hdr_from_ipv6(struct ipv6hdr *ipv6, uint8_t  *l3proto, uint8_t *is_frag)
{
        uint8_t nexthdr, *exthdr;
        int exthdrlen, done = 0;
	int count = 1024; /* to make sure we don't get stuck in a loop */

        nexthdr = ipv6->nexthdr;
        exthdr = (uint8_t *)(ipv6 + 1);

	*is_frag = 0;

	do {
		switch (nexthdr) {
        		case IPV6_EXTH_FRAG:
				*is_frag = 1;
        		case IPV6_EXTH_HOH:
        		case IPV6_EXTH_ROUTING:
        		case IPV6_EXTH_DEST_OPT:
        		case IPV6_EXTH_MOBILITY:
			case IPV6_EXTH_HIP:
			case IPV6_EXTH_SHIM:
			case IPV6_EXTH_EXP1:
			case IPV6_EXTH_EXP2:
                		nexthdr = exthdr[0];
                		exthdrlen = (exthdr[1] + 1) << 3;
                		exthdr += exthdrlen;
				break;
        		case IPV6_EXTH_ESP:
        		case IPV6_EXTH_AH:
        		case IPV6_EXTH_ICMP:
        		case IPV6_EXTH_TCP:
        		case IPV6_EXTH_UDP:
        		case IPV6_EXTH_GRE:
        		case IPV6_EXTH_NNH:
			default :
				*l3proto = nexthdr;
				done = 1;
				break;
		}
	} while ((!done) && (--count));

        return (void *)exthdr;
}

#ifndef LINUX_IPSEC
static int cvmcs_nic_mdata_parse_ipsec_headers(cvmx_wqe_t *wqe, int ifidx)
{
	uint8_t icv_len, next_proto, pad_len;
	uint16_t hdr_len;
	cvmcs_nic_metadata_t *mdata = CVMCS_NIC_METADATA(wqe);

	mdata->ipsec_esp_ah_hdrlen = 0;

	if (CVMCS_NIC_METADATA_IS_IPSEC_OP(mdata)) {

		if (CVMCS_NIC_METADATA_IS_IPSEC_AH(mdata)) {

			mdata->ipsec_next_proto = cvmcs_nic_ipsec_get_ah_next_hdr(wqe);
			mdata->ipsec_esp_ah_hdrlen = cvmcs_nic_ipsec_get_ah_hdr_len(wqe);
			if (mdata->ipsec_next_proto == CVM_IPSEC_NH_ESP)
				mdata->flags |= METADATA_FLAGS_IPSEC_ESP;	
		}

		if (CVMCS_NIC_METADATA_IS_IPSEC_ESP(mdata)) {

			cvmcs_nic_ipsec_get_esp_hdr_icv_len(wqe, mdata->from_ifidx, &hdr_len, &icv_len);
			mdata->ipsec_esp_ah_hdrlen += hdr_len;
			mdata->ipsec_esp_icv_len = icv_len;

			cvmcs_nic_ipsec_get_esp_next_hdr_pad_len(wqe, mdata->from_ifidx, &next_proto, &pad_len);
			mdata->ipsec_next_proto = next_proto;
			mdata->ipsec_esp_pad_len = pad_len;
		}

		if ((mdata->ipsec_next_proto == CVM_IPSEC_NH_IPV4) ||
		    (mdata->ipsec_next_proto == CVM_IPSEC_NH_IPV6))
			mdata->flags |= METADATA_FLAGS_IPSEC_TUNNEL;

		cvmcs_nic_mdata_parse_headers(wqe, ifidx);
		return 0;
	}

	if (CVMCS_NIC_METADATA_IS_IPSEC_AH(mdata)) {

		next_proto = cvmcs_nic_ipsec_get_ah_next_hdr(wqe);
		mdata->ipsec_esp_ah_hdrlen = cvmcs_nic_ipsec_get_ah_hdr_len(wqe);

		if ((next_proto == CVM_IPSEC_NH_IPV4) || (next_proto == CVM_IPSEC_NH_IPV6))
			mdata->flags |= METADATA_FLAGS_IPSEC_TUNNEL;

		if (next_proto != CVM_IPSEC_NH_ESP) {
			mdata->ipsec_next_proto = next_proto;
			cvmcs_nic_mdata_parse_headers(wqe, ifidx);
			return 0;
		} else {
			mdata->flags |= METADATA_FLAGS_IPSEC_ESP;	
		}
	}

	cvmcs_nic_ipsec_get_esp_hdr_icv_len(wqe, ifidx, &hdr_len, &icv_len);
	mdata->ipsec_esp_ah_hdrlen += hdr_len;
	mdata->ipsec_esp_icv_len = icv_len;

	/* For ESP, Continue processing the headers after data is decrypted */

        return 0;
}
#endif

void cvmcs_nic_mdata_ipsec_update_metadata(cvmx_wqe_t *wqe, int ifidx)
{
	uint8_t next_proto, pad_len;
	cvmcs_nic_metadata_t *mdata = CVMCS_NIC_METADATA(wqe);

	if (!CVMCS_NIC_METADATA_IS_IPSEC_ESP(mdata))
		return;

	cvmcs_nic_ipsec_get_esp_next_hdr_pad_len(wqe, mdata->from_ifidx, &next_proto, &pad_len);

	if ((next_proto == CVM_IPSEC_NH_IPV4) || (next_proto == CVM_IPSEC_NH_IPV6))
		mdata->flags |= METADATA_FLAGS_IPSEC_TUNNEL;

	mdata->ipsec_next_proto = next_proto;
	mdata->ipsec_esp_pad_len = pad_len;

	cvmcs_nic_mdata_parse_headers(wqe, ifidx);
}

void cvmcs_nic_mdata_parse_ip_headers(uint8_t *l3hdr, uint16_t *l3hdr_len,
                  uint8_t * l3_proto, uint8_t *is_frag, uint8_t *is_opts_exth)
{

	*is_frag = 0;
	*is_opts_exth = 0;

	if (((l3hdr[0]) >> 4) == 4) {
		struct iphdr *iph4 = (struct iphdr *)l3hdr;

		if ((iph4->frag_off & IP_MF) || (iph4->frag_off & IP_OFFSET))
			*is_frag = 1;

		if (iph4->ihl > 5)
			*is_opts_exth = 1;

		*l3hdr_len = (iph4->ihl << 2);

		*l3_proto = iph4->protocol;
	} else {
		void *l4hdr;

        	l4hdr = cvmcs_nic_mdata_get_l4hdr_from_ipv6((void *)l3hdr, l3_proto, is_frag);

        	*l3hdr_len = (l4hdr - (void *)l3hdr);

		if (*l3hdr_len > 40)
			*is_opts_exth = 1;
	}

}

void cvmcs_nic_mdata_parse_headers(cvmx_wqe_t *wqe, int ifidx)
{
	uint8_t l3proto, is_frag, is_opts_or_exth;
	uint16_t l2proto, l2hlen, l3hlen;
	uint16_t outer_l3offset;
	void  *outer_l3hdr, *outer_l4hdr;
	void  *inner_l2hdr = NULL, *inner_l3hdr, *inner_l4hdr;
	cvmcs_nic_metadata_t *mdata = CVMCS_NIC_METADATA(wqe);
	struct ethhdr *eth;

	eth = (struct ethhdr *)CVMCS_NIC_METADATA_PACKET_START(mdata);

	if (mdata->flags & (METADATA_FLAGS_IPSEC_AH | METADATA_FLAGS_IPSEC_ESP)) {
		if (CVMCS_NIC_METADATA_IS_IPSEC_TUNNEL(mdata)) {
			if (mdata->ipsec_next_proto == CVM_IPSEC_NH_IPV4)
				l2proto = ETH_P_IP;
			else if (mdata->ipsec_next_proto == CVM_IPSEC_NH_IPV6)
				l2proto = ETH_P_IPV6;
			else
				return;

			outer_l3offset = mdata->ipsec_esp_ah_offset +
				mdata->ipsec_esp_ah_hdrlen;
			outer_l3hdr = (void *)((uint8_t *)eth + outer_l3offset);

			cvmcs_nic_mdata_parse_ip_headers(outer_l3hdr, &l3hlen,
				&l3proto, &is_frag, &is_opts_or_exth);
		} else {
			outer_l3offset = mdata->ipsec_l3offset;
			outer_l3hdr = (void *)((uint8_t *)eth + outer_l3offset);
			l2proto = mdata->ipsec_l2proto;
			cvmcs_nic_mdata_parse_ip_headers(outer_l3hdr, &l3hlen,
				&l3proto, &is_frag, &is_opts_or_exth);
			l3proto = mdata->ipsec_next_proto;
			l3hlen = mdata->ipsec_esp_ah_offset - mdata->ipsec_l3offset + mdata->ipsec_esp_ah_hdrlen;
		}	

	} else {

		mdata->outer_l2offset = 0;

		cvmcs_dcb_get_l2_proto_hlen(wqe, &l2proto, &l2hlen);

        	outer_l3hdr = (void *)((uint8_t *)eth + l2hlen);
        	outer_l3offset = mdata->outer_l2offset + l2hlen;

		if ((l2proto != ETH_P_IP) && (l2proto != ETH_P_IPV6)) {
			/* Not IP Protocol */
			return;
		}

		cvmcs_nic_mdata_parse_ip_headers(outer_l3hdr, &l3hlen, &l3proto,
			&is_frag, &is_opts_or_exth);

#ifndef LINUX_IPSEC
        	if (l3proto == CVM_IPSEC_NH_AH) {
			mdata->flags |= METADATA_FLAGS_IPSEC_AH;
		} else if (l3proto == CVM_IPSEC_NH_ESP) {
			mdata->flags |= METADATA_FLAGS_IPSEC_ESP;
		}

		if (mdata->flags & (METADATA_FLAGS_IPSEC_AH | METADATA_FLAGS_IPSEC_ESP)) {
			mdata->ipsec_l2proto = l2proto;
			mdata->ipsec_l3offset = outer_l3offset;
			mdata->ipsec_esp_ah_offset =  outer_l3offset + l3hlen;
			if (is_frag) {
				mdata->flags |= METADATA_FLAGS_IPSEC_FRAG;
			} else {

				if (CVMCS_NIC_METADATA_IS_IPSEC_OP(mdata) || (ifidx != -1))
					cvmcs_nic_mdata_parse_ipsec_headers(wqe, ifidx);
			}
			return;
		}
#endif
	}
	
	if (l2proto == ETH_P_IP) {
		mdata->flags |= METADATA_FLAGS_IPV4;
	} else if (l2proto == ETH_P_IPV6) {
		mdata->flags |= METADATA_FLAGS_IPV6;
	}

	mdata->outer_l3offset = outer_l3offset;
	mdata->outer_l4offset = outer_l3offset + l3hlen;
        outer_l4hdr = (void *)((uint8_t *)eth + mdata->outer_l4offset);

	if (is_frag)
		mdata->flags |= METADATA_FLAGS_IP_FRAG;
	
	if (is_opts_or_exth)
		mdata->flags |= METADATA_FLAGS_IP_OPTS_OR_EXTH;

	if (l3proto == IPPROTO_UDP) {
		struct udphdr *udp = (struct udphdr *)outer_l4hdr;

		mdata->flags |= METADATA_FLAGS_UDP;

		if (((ifidx == -1 ) && 
			(mdata->flags & METADATA_FLAGS_CSUM_INNER_L4)) ||
		    ((ifidx >= 0) && VXLAN_PORT_COUNT(ifidx) &&
			((VXLAN_FIND_DEFAULT_PORT(udp->dest, ifidx)) ||
			(VXLAN_FIND_PORT_TO_DB(udp->dest, ifidx))))) {

			mdata->flags |= METADATA_FLAGS_TUNNEL | METADATA_FLAGS_ENCAP_ON;
			inner_l2hdr =
				(void *)((uint8_t *)udp + sizeof(struct udphdr) + 8);
			mdata->inner_l2offset =
				mdata->outer_l4offset + sizeof(struct udphdr) + 8;
                }

	} else if (l3proto == IPPROTO_TCP) {
		struct tcphdr *tcp = (struct tcphdr *)outer_l4hdr;

		mdata->flags |= METADATA_FLAGS_TCP;

		if (tcp->syn)
			mdata->flags |= METADATA_FLAGS_TCP_SYN;

	} else if (l3proto == IPPROTO_GRE) {

		struct gre_hdr *gre = (struct gre_hdr *)outer_l4hdr;
                int gre_hdr_size = sizeof(gre_hdr_t) +
                		gre->K * sizeof(gre_key_hdr_t) +
                               	gre->C * sizeof(gre_cksum_hdr_t) +
                               	gre->S * sizeof(gre_seq_num_hdr_t) +
                               	gre->R * sizeof(gre_routing_hdr_t);

		mdata->flags |= METADATA_FLAGS_TUNNEL | METADATA_FLAGS_GRE;

		inner_l2hdr = (void *)((uint8_t *)gre + gre_hdr_size);
		mdata->inner_l2offset = mdata->outer_l4offset + gre_hdr_size;

	}

	if (CVMCS_NIC_METADATA_IS_TUNNEL(mdata)) {

		eth = (struct ethhdr *)inner_l2hdr;

        	if (eth->h_proto == ETH_P_8021Q){
                	struct vlan_hdr *vh = (struct vlan_hdr *)eth;
			mdata->flags |= METADATA_FLAGS_INNER_VLAN;
			mdata->inner_vlanTCI = vh->vlan_TCI;
			l2proto = vh->proto;
			l2hlen = VLAN_ETH_HLEN;
		} else {
			l2proto = eth->h_proto;
			l2hlen = ETH_HLEN;
 		}

		if ((l2proto != ETH_P_IP) && (l2proto != ETH_P_IPV6)) {
			/* Not IP Protocol */
			return;
		}

        	inner_l3hdr = (void *)((uint8_t *)eth + l2hlen);
        	mdata->inner_l3offset = mdata->inner_l2offset + l2hlen;

		inner_l4hdr = NULL;

		cvmcs_nic_mdata_parse_ip_headers(inner_l3hdr, &l3hlen, &l3proto,
				&is_frag, &is_opts_or_exth);

		if (l2proto == ETH_P_IP) {
			mdata->flags |= METADATA_FLAGS_INNER_IPV4;
		} else {
			mdata->flags |= METADATA_FLAGS_INNER_IPV6;
		}

        	inner_l4hdr = (void *)((uint8_t *)inner_l3hdr + l3hlen);
		mdata->inner_l4offset = mdata->inner_l3offset + l3hlen;

		if (is_frag)
			mdata->flags |= METADATA_FLAGS_INNER_IP_FRAG;
	
		if (is_opts_or_exth)
			mdata->flags |= METADATA_FLAGS_INNER_IP_OPTS_OR_EXTH;

		if (IPPROTO_TCP == l3proto) {
			mdata->flags |= METADATA_FLAGS_INNER_TCP;

        		mdata->header_len = mdata->inner_l4offset +
				(((struct tcphdr *)inner_l4hdr)->doff << 2);
		} 
		else if (IPPROTO_UDP == l3proto) {
			mdata->flags |= METADATA_FLAGS_INNER_UDP;

        		mdata->header_len = mdata->inner_l4offset + 8;
		}
	} else {
		if (IPPROTO_TCP == l3proto) {
        		mdata->header_len = mdata->outer_l4offset +
				(((struct tcphdr *)outer_l4hdr)->doff << 2);
		} 
		else if (IPPROTO_UDP == l3proto) {
        		mdata->header_len = mdata->outer_l4offset + 8;
		}
	}

	return;
}

int cvmcs_nic_mdata_tunnel_update_metadata(cvmx_wqe_t *wqe)
{
	cvmcs_nic_metadata_t *mdata = CVMCS_NIC_METADATA(wqe);

        mdata->flags |= METADATA_FLAGS_ENCAP_ON;

        mdata->from_interface = METADATA_PORT_LOOP;
        mdata->from_ifidx = -1;

	return 0;
}

int cvmcs_nic_mdata_init_metadata(cvmx_wqe_t *wqe)
{
	uint16_t user_set_vlanTCI;
	vnic_port_info_t *src_port;
	union octnic_packet_params packet_params;
	cvmcs_nic_metadata_t *mdata = CVMCS_NIC_METADATA(wqe);

	/* 66xx/68xx packet_data already has fron data  */
	memset(&mdata->packet_start, 0, sizeof(*mdata) - CVM_RAW_FRONT_SIZE);

	mdata->from_port = cvmx_wqe_get_port(wqe);

	if ((mdata->gmx_id = get_gmx_port_id(mdata->from_port)) == -1) {
		/* Packet came from one of DPI ports */
		mdata->from_interface = METADATA_PORT_DPI;
		mdata->from_ifidx = get_vnic_port_id(mdata->from_port);
		mdata->gmx_id = octnic->port[mdata->from_ifidx].gmxport_id;
		mdata->gmx_port = octnic->port[mdata->from_ifidx].linfo.gmxport;

		if (octeon_has_feature(OCTEON_FEATURE_CN78XX_WQE))
			memcpy(&mdata->front,
				(cvmx_raw_inst_front_t *)cvmx_phys_to_ptr(cvmx_wqe_get_pki_pkt_ptr(wqe).addr),
				CVM_RAW_FRONT_SIZE);

		if (mdata->front.irh.s.rflag)
			mdata->front_size = CVM_RAW_FRONT_SIZE;
		else
			mdata->front_size = CVM_RAW_FRONT_SIZE-16;

		cvmcs_nic_mdata_strip_front_data(wqe);

		mdata->packet_start = (uint8_t *)PACKET_START(wqe);

		mdata->outer_vlanTCI = 0;
		cvmcs_nic_strip_vlan_tag(wqe); /* this will set mdata->outer_vlanTCI if vlan tag is found in Eth header*/

		if (OCT_NIC_PORT_VF(mdata->from_ifidx))
			user_set_vlanTCI = octnic->port[mdata->from_ifidx].user_set_vlanTCI;
		else
			user_set_vlanTCI = 0;

		if (user_set_vlanTCI & 0xFFF)
			mdata->outer_vlanTCI = user_set_vlanTCI;
		else {
			if (mdata->front.irh.s.vlan || mdata->front.irh.s.priority)
				mdata->outer_vlanTCI =  (mdata->front.irh.s.priority << 13) |
							mdata->front.irh.s.vlan;
		}

		src_port = &octnic->port[mdata->from_ifidx];
		packet_params.u32 = mdata->front.irh.s.ossp;

		if (packet_params.s.ipsec_ops)
			mdata->flags |= METADATA_FLAGS_IPSEC_OP;

		if (packet_params.s.ip_csum)
			mdata->flags |= METADATA_FLAGS_CSUM_L3;
		if (packet_params.s.transport_csum)
			mdata->flags |= METADATA_FLAGS_CSUM_L4;

		if ((packet_params.s.tnl_csum) &&
		    (src_port->state.tnl_tx_csum)) {
			mdata->flags |= METADATA_FLAGS_CSUM_INNER_L4;
			if (packet_params.s.ip_csum)
				mdata->flags |= METADATA_FLAGS_CSUM_INNER_L3;
		}
	} else {
		mdata->gmx_port = mdata->from_port;
		mdata->front_size = 0;
		mdata->from_interface = METADATA_PORT_GMX;
		mdata->from_ifidx = -1;
		mdata->packet_start = (uint8_t *)PACKET_START(wqe);
		if (OCTEON_IS_MODEL(OCTEON_CN6XXX)) {
			mdata->packet_start += OCTNET_FRM_PTP_HEADER_SIZE;
			mdata->flags |= METADATA_FLAGS_PTP_HEADER;
		}
		cvmcs_nic_strip_vlan_tag(wqe);
		cvmcs_dcb_strip_cntag(wqe);
	}

#if defined (OVS_IPSEC) || defined (LINUX_IPSEC)
	mdata->flags |= METADATA_FLAGS_MDATA_INIT;
#endif

#ifdef VSWITCH
	mdata->fw_crc = 0;
#endif
	return 0;
}
