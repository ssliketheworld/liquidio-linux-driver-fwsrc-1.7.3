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
#include "cvm-nic-ipsec.h"
#include "cvmcs-nic-tunnel.h"
#include "cvmcs-nic-rss.h"
#include "cvmcs-nic-fnv.h"
#include "cvmcs-nic-switch.h"
#include "cvmcs-nic-mdata.h"
#include "cvmcs-nic-ipv6.h"
#include "cvmcs-nic-ether.h"
#include "cvmcs-nic-udp.h"
#include "cvmcs-profile.h"
#include "cvmcs-dcb.h"

extern CVMX_SHARED cvm_per_core_stats_t *per_core_stats;
extern CVMX_SHARED uint64_t cpu_freq;

/* Find the list of interfaces that this wqe entry should be sent to.
 * It only returns interfaces that are active.
 *
 * @param wqe    work queue entry
 * @param mdata  Metadata extracted from WQE and  preallocated buffer
 *               that is a bitmask indicating which interfaces this
 *               wqe applies to for mcast/bcast case
 *
 * @returns interface number if only on one interface, -1 if not found,
 *          -2 if mcast, bcast (ifl will have list of interfaces)
 */
int cvmcs_nic_get_ifidx_list(cvmx_wqe_t *wqe, int from_dpi)
{
	int ifidx = -1;
	unsigned int h, j, k;
	struct ethhdr *eth;
	uint64_t dest_mac;
	mcast_ifl_t *p;
	gmx_port_info_t *info;
	int16_t is_vlan = 0, vlanId = 0;
	cvmcs_nic_metadata_t *mdata = CVMCS_NIC_METADATA(wqe);

	if (mdata->gmx_id == -1)
		return -ENOIF;

	eth = (struct ethhdr *)CVMCS_NIC_METADATA_PACKET_START(mdata);

	is_vlan = CVMCS_NIC_METADATA_VLAN_TCI(mdata) ? 1 : 0;
	vlanId = CVMCS_NIC_METADATA_VLAN_ID(mdata);

	DBG("GMX%d: find MAC %012lx is_vlan = %d vlanId = %d\n", mdata->gmx_id, cvmcs_nic_mac_to_64(eth->h_dest), is_vlan, vlanId);

	info = &octnic->gmx_port_info[mdata->gmx_id];

	/* If multiple VNIC port are on a GMX, use a hash to find
	 * the index, then linear search through the subsequent table
	 * entries if it is not a perfect match. 
	 */
	dest_mac = ((*(uint64_t *)eth)>>16) & (0x0000ffffffffffffUL);

	/* Copy all promiscuous interfaces.
	 * If mdata->ifl.active == 0, then there are no promiscuous interfaces.
	 */

	/* Broadcast */
	if (dest_mac == 0x0000ffffffffffffUL) {
		iflist_union(&mdata->dest_ifl, &info->vnic_bcast);

		if (is_vlan)
			iflist_intersection(&mdata->dest_ifl, &info->vlans[vlanId]);
		else
			iflist_intersection(&mdata->dest_ifl, &info->vnic_without_user_set_vlan);

		/* Promisc interface will receive all vlans. This may happen
		 * when interface  doesnot not belong to any vlan but is uplink
		 * for host bridge. */
		iflist_union(&mdata->dest_ifl, &info->vnic_promisc);

		DBG("GMX%d BCAST: ifl->mask[0]=0x%016lx,%016lx,%016lx,%016lx last=%d\n",
		    mdata->gmx_id, mdata->dest_ifl.mask[0],
		    (OCT_NIC_VFS_PER_PF * MAX_NUM_PFS) > 64 ? mdata->dest_ifl.mask[1] : 0UL,
		    (OCT_NIC_VFS_PER_PF * MAX_NUM_PFS) > 128 ? mdata->dest_ifl.mask[2] : 0UL,
		    (OCT_NIC_VFS_PER_PF * MAX_NUM_PFS) > 192 ? mdata->dest_ifl.mask[3] : 0UL,
		    mdata->dest_ifl.last);

		return -EMBCAST;
	}

	/* Multicast */
	if (eth->h_dest[0] & 0x01) {

		/* rtf - 12/5/2015
		 *
		 * In order to support 'ALLMULTI', we must send the packet to any
		 * interface which has (ANY of):
		 *    1. added this MAC addr to the m/c table
		 *    2. set interface flags w/'OCTNET_IFFLAG_ALLMULTI'
		 *    3. set interface flags w/'OCTNET_IFFLAG_PROMISC'
		 *
		 * Per above comment, don't check VLAN...
		 */

		/* vnic_promisc already set into 'dest_ifl', above */
		iflist_union(&mdata->dest_ifl, &info->vnic_allmulti);

		p = find_mcast_ifl(mdata->gmx_id, dest_mac);
		if (p) {
			struct ifidx_list tmp;
			memcpy(&tmp, &info->vnic_multi, sizeof (struct ifidx_list));
			iflist_intersection(&tmp, &p->ifl);
			iflist_union(&mdata->dest_ifl, &tmp);
		} else if (!info->vnic_allmulti.active && !info->vnic_promisc.active) {
			if (from_dpi)
				return -EMBCAST;
			return -ENOIF;
		}

		if (is_vlan)
			iflist_intersection(&mdata->dest_ifl, &info->vlans[vlanId]);
		else
			iflist_intersection(&mdata->dest_ifl, &info->vnic_without_user_set_vlan);

		/* Promisc interface will receive all vlans. This may happen
		 * when interface  doesnot not belong to any vlan but is uplink
		 * for host bridge. */
		iflist_union(&mdata->dest_ifl, &info->vnic_promisc);

		DBG("GMX%d MCAST: ifl->mask[0]=0x%016lx,%016lx last=%d\n",
		    mdata->gmx_id, mdata->dest_ifl.mask[0],
		    (OCT_NIC_VFS_PER_PF * MAX_NUM_PFS) > 64 ?  mdata->dest_ifl.mask[1] : 0UL,
		    mdata->dest_ifl.last);

		return -EMBCAST;
	}

	/* Unicast. */
	memcpy(&mdata->dest_ifl, &info->vnic_promisc, sizeof(mdata->dest_ifl));
	h = mac_hash(eth->h_dest) << NIC_HASH_SHIFT;

	/* Guard against run-time MAC address changes or additions */
	cvmx_rwlock_wp_read_lock(&info->mac_hash_lock);

	for(j = 0; j < MAX_OCTEON_NIC_HASH_SIZE; j++) {
		k = (h + j) & (MAX_OCTEON_NIC_HASH_SIZE - 1);
		if (info->hash[k].ifidx == -1) {
			/* No match */
			break;
		}
		if ((info->hash[k].hw_addr == dest_mac) &&
		    (octnic->port[info->hash[k].ifidx].state.active) &&
		    ((!is_vlan && iflist_on(&info->vnic_without_user_set_vlan, info->hash[k].ifidx)) || ((is_vlan) &&
		      (iflist_on(&info->vlans[vlanId], info->hash[k].ifidx))))) {
			/* MAC matches, state is active,
			 * and either there is no VLAN in the packet,
			 * or the received VLAN passes the VLAN filter.
			 *
			 * If for some reason there were multiple
			 * interfaces with the same MAC and no VLANs,
			 * the first MAC would get the packet.
			 *
			 * If there were multiple interfaces with the
			 * same MAC but on different VLANs, this logic
			 * should deliver the packet to the correct
			 * interface.
			 */
			iflist_set(&mdata->dest_ifl, info->hash[k].ifidx);
			ifidx = info->hash[k].ifidx;

			DBG("GMX%d UNICAST: ifl->mask[0]=0x%016lx,%016lx last=%d\n",
			    mdata->gmx_id, mdata->dest_ifl.mask[0],
			    (OCT_NIC_VFS_PER_PF * MAX_NUM_PFS) > 64 ?  mdata->dest_ifl.mask[1] : 0UL,
			    mdata->dest_ifl.last);

			break;
		}
	}

	cvmx_rwlock_wp_read_unlock(&info->mac_hash_lock);

#ifdef PF_PROMISC_MODE_WILL_SEE_VF_UNICAST_PACKETS
	if (!mdata->dest_ifl.active) {
		/* No promiscuous interfaces */
		if (ifidx != -1) {
			mdata->dest_ifl.last = ifidx;
			mdata->dest_ifl.active = 1;
			return ifidx;
		} else {
			return -ENOIF;
		}
	}
#else
	/* PF promisc mode won't see VF unicast packets */
	if (ifidx != -1) {
		/* hash table search hit */
		if (from_dpi && mdata->from_ifidx == ifidx) {
			/* Packet came from DPI, and it's destined to go back to
			 * its source.  Weird.  Do not forward.
			 */
			return -EBADPACKET;
		}

		mdata->dest_ifl.last = ifidx;
		mdata->dest_ifl.active = 1;
		return ifidx;
	} else {
		/* hash table search miss */
		if (from_dpi) {
			/* packet came from DPI and it's destined for the wire */
			return -ENOIF;
		}

		if (!mdata->dest_ifl.active) {
			/* there are no promiscuous interfaces */
			return -ENOIF;
		}
	}
#endif

	/* This is a unicast packet which missed the filters
	 * but it may be destined for the pf or trusted vf in promiscuous mode.
	 */

	if (info->trusted_vf.active &&
	    iflist_on(&info->vnic_promisc, info->trusted_vf.id)) {
		/* clear PF and all non trusted VFs */
		mdata->dest_ifl.mask[0] = 0ULL;
		mdata->dest_ifl.mask[1] = 0ULL;
		iflist_set(&mdata->dest_ifl, info->trusted_vf.id);
		ifidx = info->trusted_vf.id;
	} else {
		/* No trusted VFs, clear all VFs */
		mdata->dest_ifl.mask[0] &= 1ULL;
		mdata->dest_ifl.mask[1] &= 1ULL;
		ifidx = OCT_NIC_PORT_IDX(mdata->gmx_id, 0);
	}

	iflist_set_last(&mdata->dest_ifl);
	iflist_set_active(&mdata->dest_ifl);

	/* check if pf or vf is set */
	if (!mdata->dest_ifl.active)
		return -ENOIF;

	/* Some promiscuous interfaces included */

	DBG("GMX%d PROMISCUOUS: ifl->mask[0]=0x%016lx,%016lx last=%d\n",
	    mdata->gmx_id, mdata->dest_ifl.mask[0],
	    (OCT_NIC_VFS_PER_PF * MAX_NUM_PFS) > 64 ? mdata->dest_ifl.mask[1] : 0UL,
	    mdata->dest_ifl.last);

	return ifidx;
}

int cvmcs_nic_get_rxq(cvmx_wqe_t *wqe, uint32_t *hash, int ifidx)
{
	uint32_t tag;
	uint8_t from_lpport;
	cvmcs_nic_metadata_t *mdata;
	vnic_port_info_t *nicport = &octnic->port[ifidx];

	tag = cvmx_wqe_get_tag(wqe);
	from_lpport = cvmcs_nic_tunnel_is_loopback_port(wqe);
	mdata = CVMCS_NIC_METADATA(wqe);

	if (CVMCS_NIC_METADATA_IS_IP_FRAG(mdata) && 
            CVMCS_NIC_METADATA_IS_IPV4(mdata)) {
		struct iphdr *ip4;
		uint16_t *u16;
		uint32_t *u32;
		uint32_t iv=0;
		uint32_t htag;

		ip4 = (struct iphdr *)(CVMCS_NIC_METADATA_L3_HEADER(mdata));

		CVMX_MT_CRC_POLYNOMIAL (0x1edc6f41);
		CVMX_MT_CRC_IV (iv);

		/* calculate tag for ipv4 fragments */
		u32 = (uint32_t *)&ip4->saddr;
		CVMX_MT_CRC_WORD(*u32);
		u32 = (uint32_t *)&ip4->daddr;
		CVMX_MT_CRC_WORD(*u32);
		u16 = (uint16_t *)&ip4->id;
		CVMX_MT_CRC_HALF(*u16);
		CVMX_MF_CRC_IV(htag);

		if ((ip4->frag_off & IP_OFFSET) == 0) {
			uint32_t tmptag;

			/* 1st fragment, store hw tag */
			u16 = (uint16_t *)(CVMCS_NIC_METADATA_L4_HEADER(mdata));
			CVMX_MT_CRC_POLYNOMIAL (0x1edc6f41);
			CVMX_MT_CRC_IV (iv);

			u32 = (uint32_t *)&ip4->saddr;
			CVMX_MT_CRC_WORD(*u32);
			u32 = (uint32_t *)&ip4->daddr;
			CVMX_MT_CRC_WORD(*u32);
			CVMX_MT_CRC_HALF(*u16);
			CVMX_MT_CRC_HALF(*(u16+1));
			CVMX_MF_CRC_IV(tmptag);

			nicport->hashed_frg_tb[htag%HFRGTB_SIZE].hwtag = tmptag;	
			nicport->hashed_frg_tb[htag%HFRGTB_SIZE].hash3tag = htag;
			tag = tmptag;
		} else {
			if ((htag != nicport->hashed_frg_tb[htag%HFRGTB_SIZE].hash3tag)
			    && (nicport->hashed_frg_tb[htag%HFRGTB_SIZE].hwtag)) {
				DBG("ipv4 fragment hash collide %d\n", htag%HFRGTB_SIZE);
			}
			tag = nicport->hashed_frg_tb[htag%HFRGTB_SIZE].hwtag;
		}

		cvmx_wqe_set_tag(wqe, tag);
	}

	if (CVMCS_NIC_METADATA_IS_IP_OPTS_OR_EXTH(mdata) && 
	    CVMCS_NIC_METADATA_IS_IPV6(mdata)) {
		union {
                	struct ipv6hdr *iph;
                	struct ipv6_opt_hdr *opth;
			struct ipv6_frag_hdr *fh;
                	char *raw;
        	} exthdr;
		struct ipv6hdr *ip6;
		int nexthdr;
		char *end;
		uint16_t *u16;
		uint32_t *u32;
		uint64_t *u64;
		uint32_t tmptag, htag;

		ip6 = (struct ipv6hdr *)(CVMCS_NIC_METADATA_L3_HEADER(mdata));

		CVMX_MT_CRC_POLYNOMIAL (0x1edc6f41);
		CVMX_MT_CRC_IV (0);

		exthdr.iph = ip6;
		end = (char *)(CVMCS_NIC_METADATA_L4_HEADER(mdata));
		nexthdr = ip6->nexthdr;
		exthdr.iph++;
			
		u64 = (uint64_t *)&ip6->saddr;
		CVMX_MT_CRC_DWORD(*u64++);
		CVMX_MT_CRC_DWORD(*u64);
		
		u64 = (uint64_t *)&ip6->daddr;
		CVMX_MT_CRC_DWORD(*u64++);
		CVMX_MT_CRC_DWORD(*u64);
		
		/* ip id */
		while (exthdr.raw < end) {
			switch (nexthdr) {
			case CVM_IPV6_NEXTHDR_FRAGMENT:
				u32 = (uint32_t *)&(exthdr.fh->identification);
				CVMX_MT_CRC_WORD(*u32);
				CVMX_MF_CRC_IV(htag);

				/* first fragment */
				if ((exthdr.fh->frag_off & 0xfff8) == 0) {
					
					CVMX_MT_CRC_POLYNOMIAL (0x1edc6f41);
					CVMX_MT_CRC_IV (0);
					u64 = (uint64_t *)&ip6->saddr;
					CVMX_MT_CRC_DWORD(*u64++);
					CVMX_MT_CRC_DWORD(*u64);
		
					u64 = (uint64_t *)&ip6->daddr;
					CVMX_MT_CRC_DWORD(*u64++);
					CVMX_MT_CRC_DWORD(*u64);

					u16 = (uint16_t *)(CVMCS_NIC_METADATA_L4_HEADER(mdata));
					CVMX_MT_CRC_HALF(*u16);
					CVMX_MT_CRC_HALF(*(u16+1));
					CVMX_MF_CRC_IV(tmptag);

					nicport->hashed_frg_tb[htag%HFRGTB_SIZE].hwtag = tmptag;	
					nicport->hashed_frg_tb[htag%HFRGTB_SIZE].hash3tag = htag;
					tag = tmptag;
				} else {
					if ((htag != nicport->hashed_frg_tb[htag%HFRGTB_SIZE].hash3tag)
					    && (nicport->hashed_frg_tb[htag%HFRGTB_SIZE].hwtag)) {
						DBG("ipv6 fragment hash collide %d\n", htag%HFRGTB_SIZE);
					}
					tag = nicport->hashed_frg_tb[htag%HFRGTB_SIZE].hwtag;

				}

				cvmx_wqe_set_tag(wqe, tag);
				break;
			}
			nexthdr = exthdr.opth->nexthdr;
			exthdr.raw += (((exthdr.opth)->hdrlen+1) << 3);
		}
	}

#ifndef OVS_IPSEC
	if(CVMCS_NIC_METADATA_TUNNEL_HEADER_LENGTH(mdata)) {
		tag = vxlan_get_tag(wqe, CVMCS_NIC_METADATA_TUNNEL_HEADER_LENGTH(mdata), from_lpport);
		if (!tag) {
			/* When Tag is received as Zero */
			tag = cvmx_wqe_get_tag(wqe);
		}
	}
#endif

	*hash = tag;

	if (nicport->pkt_steering_enable && CVMCS_NIC_METADATA_IS_TCP(mdata))
		return get_queue_from_pkt_steering_table(nicport, wqe);

#ifdef VSWITCH
	return ((tag + CVMCS_NIC_METADATA_FW_CRC(mdata))% (nicport->linfo.num_rxpciq));
#else
	return (tag % (nicport->linfo.num_rxpciq));
#endif
}

static
void cvmcs_nic_calculate_new_tag(cvmx_wqe_t *wqe, void *L3, void *L4, uint8_t protocol)
{
	struct iphdr   *ip4=0;
	struct ipv6hdr *ip6=0;
	uint32_t *L4header=0;
	uint32_t newtag;
	uint8_t *packet_start;
	uint64_t *u64;
	uint8_t proto;

	if (L3 && L4 && protocol) {
		if (cvmx_wqe_is_l3_ipv6(wqe))
			ip6 = L3;
		else
			ip4 = L3;

		L4header = L4;
		proto = protocol;

	} else {
		packet_start = cvmx_phys_to_ptr(wqe->packet_ptr.s.addr);

		if (cvmx_wqe_is_l3_ipv6(wqe)) {
			ip6 = (struct ipv6hdr *)(packet_start + cvmx_wqe_get_l3_offset(wqe));
			L4header = (uint32_t *)(ip6 + 1);
			proto = ip6->nexthdr;
		} else {
			ip4 = (struct iphdr *)(packet_start + cvmx_wqe_get_l3_offset(wqe));
			L4header = (uint32_t *)(ip4 + 1);
			proto = ip4->protocol;
		}
	}

	CVMX_MT_CRC_POLYNOMIAL (0x1edc6f41);
	CVMX_MT_CRC_IV (0);

	if (ip4) {
		u64 = (uint64_t *)&ip4->saddr;
		CVMX_MT_CRC_DWORD(*u64);
	} else {
		u64 = (uint64_t *)&ip6->saddr;
		CVMX_MT_CRC_DWORD(*u64++);
		CVMX_MT_CRC_DWORD(*u64++);
		CVMX_MT_CRC_DWORD(*u64++);
		CVMX_MT_CRC_DWORD(*u64);
	}

	CVMX_MT_CRC_WORD(*L4header);
	CVMX_MT_CRC_BYTE(proto);

	CVMX_MF_CRC_IV(newtag);

	cvmx_wqe_set_tag(wqe, newtag);
}

static inline int cvm_wqe_is_ip_options(cvmx_wqe_t *work)
{
	if (octeon_has_feature(OCTEON_FEATURE_CN78XX_WQE)) {
		cvmx_wqe_78xx_t *wqe = (void *)work;
		if((wqe->word2.lc_hdr_type == CVMX_PKI_LTYPE_E_IP4_OPT) ||
		   (wqe->word2.lc_hdr_type == CVMX_PKI_LTYPE_E_IP6_OPT))
			return 1;
		if((wqe->word2.le_hdr_type == CVMX_PKI_LTYPE_E_IP4_OPT) ||
		   (wqe->word2.le_hdr_type == CVMX_PKI_LTYPE_E_IP6_OPT))
			return 1;
	} else {
		if (work->word2.s.L4_error &&
			(work->word2.s.err_code == 9))
				return 1;
	}
	return 0;
}

static inline int cvm_wqe_l4_error_bad_csum(cvmx_wqe_t *work)
{
	if (octeon_has_feature(OCTEON_FEATURE_CN78XX_WQE)) {
		cvmx_wqe_78xx_t *wqe = (void *)work;
		if (wqe->word2.err_code == 0x62)
			return 1;
	} else if (work->word2.s.err_code == 2) {
		return 1;
	}
	return 0;
}

void
cvmcs_nic_put_l4checksum_ipv4(cvmx_wqe_t * wqe, int offset)
{
	uint8_t *packet_start, last_byte;
	struct iphdr *iph;
	uint16_t ippayloadlen;
	uint64_t l4checksum;
	uint16_t *p, *l4header, *l4checksumfield;
	int i, iterations;

	packet_start = cvmx_phys_to_ptr(wqe->packet_ptr.s.addr);
	iph = (struct iphdr *)(packet_start + offset);

	ippayloadlen = iph->tot_len - (iph->ihl << 2);

	p = (uint16_t *)iph;

	/* IPv4 pseudo header starts with source IP addr and dest IP addr */
	l4checksum  = p[6];
	l4checksum += p[7];
	l4checksum += p[8];
	l4checksum += p[9];

	l4checksum += iph->protocol;

	l4checksum += ippayloadlen;

	l4header = p + (iph->ihl << 1);
	/* clear out the L4 checksum field */
	if (iph->protocol == IPPROTO_UDP)
		l4checksumfield = l4header + 3;
	else if (iph->protocol == IPPROTO_TCP)
		l4checksumfield = l4header + 8;
	else
		return; /* neither UDP nor TCP; get out */

	*l4checksumfield = 0;

	p = l4header;
	iterations = ippayloadlen >> 1;
	for (i = 0; i < iterations; i++) {
		l4checksum += p[i];
	}

	if (ippayloadlen & 1) {
		/* IP payload len is odd */
		last_byte = *(uint8_t *)(p + iterations);
		l4checksum += last_byte << 8;
	}

	l4checksum = (uint16_t) l4checksum + (l4checksum >> 16);
	l4checksum = (uint16_t) l4checksum + (l4checksum >> 16);
	l4checksum = (uint16_t) (l4checksum ^ 0xffff);

	*l4checksumfield = (uint16_t) l4checksum;
}

static uint16_t
cvmcs_nic_calculate_l4checksum_ipv6(uint8_t *ipv6header, uint16_t *l4header,
				    uint32_t l4len, uint8_t l4proto)
{
	uint8_t last_byte;
	uint16_t *p;
	uint64_t l4checksum;
	int i, iterations, index_to_skip;

	p = (uint16_t *)(ipv6header + 8); /* point to source IPv6 address */
	l4checksum = 0;
	for (i = 0; i < 16; i++)
		l4checksum += p[i];

	p = (uint16_t *)&l4len;
	l4checksum += p[0];
	l4checksum += p[1];

	l4checksum += l4proto;

	if (l4proto == IPPROTO_UDP)
		index_to_skip = 3;
	else if (l4proto == IPPROTO_TCP)
		index_to_skip = 8;
	else
		return 0; /* neither UDP nor TCP; get out */

	p = l4header;
	iterations = l4len >> 1;
	for (i = 0; i < iterations; i++) {
		if (i == index_to_skip)
			continue;
		l4checksum += p[i];
	}

	if (l4len & 1) {
		/* L4 len is odd */
		last_byte = *(uint8_t *)(p + iterations);
		l4checksum += last_byte << 8;
	}

	l4checksum = (uint16_t) l4checksum + (l4checksum >> 16);
	l4checksum = (uint16_t) l4checksum + (l4checksum >> 16);
	l4checksum = (uint16_t) (l4checksum ^ 0xffff);

	return (uint16_t) l4checksum;
}

int
cvmcs_nic_get_l4_from_ipv6_with_exthdr(uint8_t *ipv6header, uint16_t **l4header,
				       uint32_t *l4len, uint8_t *l4proto)
{
	int looking_for_tcp_or_udp, exthdrlen, exthdrs_total_len;
	uint16_t payloadlen;
	uint8_t *exthdr, nextheader;
	struct ipv6hdr *ip6 = NULL;

	payloadlen = *(uint16_t *)(ipv6header + 4);
	exthdr = ipv6header + 40;
	exthdrs_total_len = 0;
	looking_for_tcp_or_udp = 1;

	ip6 = (struct ipv6hdr *)ipv6header;
	switch (ip6->nexthdr) {
		case IPPROTO_UDP:
		case IPPROTO_TCP:
		/* L4 found; No Ext HDRs in this packet*/
		 looking_for_tcp_or_udp=0;
		 nextheader = ip6->nexthdr;
	}

	while (looking_for_tcp_or_udp) {
		nextheader = exthdr[0];
		exthdrlen = (exthdr[1] + 1) << 3;
		exthdrs_total_len += exthdrlen;
		if (exthdrs_total_len > (int)payloadlen)
			return -1;
		exthdr += exthdrlen;

		switch (nextheader) {
		case IPPROTO_UDP:
		case IPPROTO_TCP:
			looking_for_tcp_or_udp=0;
			break;
		case CVM_IPV6_NEXTHDR_HOP:
		case CVM_IPV6_NEXTHDR_ROUTING:
		case CVM_IPV6_NEXTHDR_FRAGMENT:
		case CVM_IPV6_NEXTHDR_ESP:
		case CVM_IPV6_NEXTHDR_AUTH:
		case CVM_IPV6_NEXTHDR_ICMP:
		case CVM_IPV6_NEXTHDR_DEST:
		case CVM_IPV6_NEXTHDR_MLD:
			break;

		default:
		   return -1;
		}
	}

	*l4header = (uint16_t *)exthdr;
	*l4len = (uint32_t)payloadlen - (uint32_t)exthdrs_total_len;
	*l4proto = nextheader;

	return 0;
}

void
cvmcs_nic_put_l4checksum_ipv6_with_exthdr(cvmx_wqe_t * wqe, int offset)
{
	uint8_t *packet_start, *ipv6, l4proto;
	uint16_t *l4header, *l4checksumfield;
	uint32_t l4len;

	packet_start = cvmx_phys_to_ptr(wqe->packet_ptr.s.addr);
	ipv6 = packet_start + offset;

	if (cvmcs_nic_get_l4_from_ipv6_with_exthdr(ipv6, &l4header, &l4len, &l4proto) == -1)
		return; /* error */

	if (l4proto == IPPROTO_UDP)
		l4checksumfield = l4header + 3;
	else /* TCP */
		l4checksumfield = l4header + 8;

	*l4checksumfield = cvmcs_nic_calculate_l4checksum_ipv6(ipv6, l4header, l4len, l4proto);
}

int
cvmcs_nic_verify_l4checksum_ipv6_with_exthdr(cvmx_wqe_t *wqe, int offset)
{
	uint8_t *packet_start, *ipv6, l4proto;
	uint16_t *l4header, *l4checksumfield, l4checksum;
	uint32_t l4len;

	packet_start = cvmx_phys_to_ptr(wqe->packet_ptr.s.addr);
	ipv6 = packet_start + offset;

	if (cvmcs_nic_get_l4_from_ipv6_with_exthdr(ipv6, &l4header, &l4len, &l4proto) == -1)
		return 0;

	if (l4proto == IPPROTO_UDP) {
		cvmcs_nic_calculate_new_tag(wqe, ipv6, l4header, IPPROTO_UDP);
		l4checksumfield = l4header + 3;
		if (*l4checksumfield == 0)
			return 0; /* no checksum to verify */
	} else {/* TCP */
		cvmcs_nic_calculate_new_tag(wqe, ipv6, l4header, IPPROTO_TCP);
		l4checksumfield = l4header + 8;
	}

	l4checksum = cvmcs_nic_calculate_l4checksum_ipv6(ipv6, l4header, l4len, l4proto);
	if (l4checksum == 0)
		return 0;

	if (l4checksum == *l4checksumfield)
		return CNNIC_CSUM_VERIFIED; /* good checksum */

	return 0; /* bad checksum */
}

int
cvmcs_nic_verify_l3l4checksums_of_ip_header_with_options(cvmx_wqe_t *wqe, int offset)
{
	uint8_t *packet_start;
	struct iphdr *iph;
	uint16_t orig_checksum, *l4header, *l4checksumfield, *p;

	packet_start = cvmx_phys_to_ptr(wqe->packet_ptr.s.addr);
	iph = (struct iphdr *)(packet_start + offset);
	orig_checksum = iph->check;

	cvmcs_nic_ip_header_checksum(iph, &iph->check);

	if (orig_checksum != iph->check){
		iph->check = orig_checksum;
		return 0; /* bad IP header checksum */
	}

	/* for IP fragment, we cannot verify L4 checksum */
	if (iph->frag_off & 0x3FFF) {
		return CNNIC_IPSUM_VERIFIED;
	}

	/* also verify L4 checksum for UDP and TCP */
	p = (uint16_t *)iph;
	l4header = p + (iph->ihl << 1);

	switch (iph->protocol) {
	case IPPROTO_UDP:
		cvmcs_nic_calculate_new_tag(wqe, iph, l4header, IPPROTO_UDP);
		l4checksumfield = l4header + 3;
		if (*l4checksumfield == 0)
			return CNNIC_IPSUM_VERIFIED;
		break;
	case IPPROTO_TCP:
		cvmcs_nic_calculate_new_tag(wqe, iph, l4header, IPPROTO_TCP);
		l4checksumfield = l4header + 8;
		break;
	default:
		/* neither UDP nor TCP; get out */
		return CNNIC_IPSUM_VERIFIED;
		break;
	}

	orig_checksum = *l4checksumfield;
	cvmcs_nic_put_l4checksum_ipv4(wqe, offset);
	if (orig_checksum != *l4checksumfield) {
		*l4checksumfield = orig_checksum;
		return CNNIC_IPSUM_VERIFIED; /* bad L4 checksum */
	}

	return CNNIC_CSUM_VERIFIED; /* good L4 checksum */
}

static inline int cvmcs_78xx_wqe_is_l3_ip_exception(cvmx_wqe_78xx_t* wqe)
{
	if (wqe->word2.err_level == CVMX_PKI_ERRLEV_E_LC)
		return 1;
	else
		return 0;
}

static inline int verify_csum(cvmx_wqe_t *work)
{
	int csum_verified = 0;

	if (octeon_has_feature(OCTEON_FEATURE_CN78XX_WQE)) {
		cvmx_wqe_78xx_t *wqe = (void *)work;

		if (cvmx_likely(!wqe->word2.err_level)) {
			/* No errors. Check whether TCP or UDP is present
			 * to indicate what checksums were verified.
			 */
			if (cvmx_likely(cvmx_wqe_is_l4_udp_or_tcp(work))) {
				csum_verified = CNNIC_CSUM_VERIFIED;
			} else if (cvmx_likely(cvmx_wqe_is_l3_ip(work))) {
				csum_verified = CNNIC_IPSUM_VERIFIED;
				/* 
				 * HCK packets can contain multiple, contiguous Destination Option Headers.
				 * These are invalid IPV6 options header combinations (per rfc2460),
				 * which we don't parse.
				 * In this case, check for L4 UDP/TCP and, if present, verify checksum.
				 *
				 * optimization: can we do this with PCAM entries?
				 * optimization: if not, can we perform cksum quicker using CVM instrs?
				 *
				 * NOTE: we verified '...is_l3_ip()' above and have ALREADY set
				 * CNNIC_IPSUM_VERIFIED.  So, we logical-or the return value from 
				 * 'cvmcs_nic_verify_l4checksum_ipv6_with_exthdr()'.
				 */
				if((wqe->word2.lc_hdr_type == CVMX_PKI_LTYPE_E_IP6_OPT) &&
					(wqe->word2.ld_hdr_type == 0) &&
					(wqe->word2.le_hdr_type == 0) &&
					(wqe->word2.lf_hdr_type == 0) &&
					(wqe->word2.lg_hdr_type == 0)) {
					csum_verified |= cvmcs_nic_verify_l4checksum_ipv6_with_exthdr(
														work, cvmx_wqe_get_l3_offset(work));
				}
			}
		} else {
			/* Error indicated. Regardless of whether it was an
			 * actual checksum error or not, we should indicate
			 * to the host to re-verify.
			 */
			if (wqe->word2.err_level > CVMX_PKI_ERRLEV_E_LC) {
				csum_verified = CNNIC_IPSUM_VERIFIED;
				if (cvmx_likely(cvmx_wqe_is_l4_udp_or_tcp(work))) {
					/* windows HCK tests send packets w/TCP flags == 0;
 					 * disregard this error */
				    if(wqe->word2.err_level != CVMX_PKI_ERRLEV_E_LF) {
						csum_verified = CNNIC_CSUM_VERIFIED;
					} else if(wqe->word2.err_code == CVMX_PKI_OPCODE_TCP_FLAG) {
						csum_verified = CNNIC_CSUM_VERIFIED;
					}
				}
			}
		}
	} else {
		if (cvmx_likely(cvmx_wqe_is_l3_ip(work)) &&
		    cvmx_likely(!cvmx_wqe_is_l3_frag(work))) {
			if(cvmx_likely(!cvmx_wqe_is_ip_exception(work))) {
				csum_verified = CNNIC_IPSUM_VERIFIED;
				if (cvmx_likely(cvmx_wqe_is_l4_udp_or_tcp(work))) {
					if (cvmx_likely(!cvmx_wqe_is_l4_error(work))) {
						csum_verified = CNNIC_CSUM_VERIFIED;
					} else {
						if (!cvmx_likely(cvm_wqe_l4_error_bad_csum(work))) {
							csum_verified = CNNIC_CSUM_VERIFIED;
						}
					}

					cvmcs_nic_calculate_new_tag(work, 0, 0, 0);
				}
			} else {
				if (cvm_wqe_is_ip_options(work)) {
					/* PIP/IPD has detected an IP-options exception */
					if (cvmx_wqe_is_l3_ipv6(work)) {
						csum_verified = cvmcs_nic_verify_l4checksum_ipv6_with_exthdr(work, cvmx_wqe_get_l3_offset(work));
					} else {
						csum_verified = cvmcs_nic_verify_l3l4checksums_of_ip_header_with_options(work, cvmx_wqe_get_l3_offset(work));
					}
				}
			}
		}
	}

	return csum_verified;
}

union octeon_rh *cvmcs_nic_insert_dpi_headers(cvmx_wqe_t *wqe, int ifidx, pkt_proc_flags_t *flags)
{
	int i;
	union octeon_rh *rh;
	cvmx_buf_ptr_pki_t  *pki_lptr;
	cvmx_buf_ptr_t	*lptr;
	cvmcs_nic_metadata_t *mdata = CVMCS_NIC_METADATA(wqe);

	/* We use the space in meta data reserved for the response
	 * header information. 
	 */
	if (octeon_has_feature(OCTEON_FEATURE_CN78XX_WQE)) {
                cvmx_pko_buf_ptr_t *pki_link = (cvmx_pko_buf_ptr_t *)&mdata->next_buf_ptr;
        	pki_lptr = (cvmx_buf_ptr_pki_t *)&wqe->packet_ptr;
                pki_link->s.addr = pki_lptr->addr;
                pki_link->s.size = pki_lptr->size;
                if (!flags->s.dontfree) {
                        /* set don't free so that this buffer will not be freed.
                         * set invert on all other buffers in link so that they will be
                         * freed by pko
                         */
                        flags->s.dontfree = 1;
                        for (i = 0; i < cvmx_wqe_get_bufs(wqe); i++) {
                                pki_link->s.i = 1;
                                pki_link = (cvmx_pko_buf_ptr_t *)CVM_DRV_GET_PTR(pki_link->s.addr - 8);
                        }
                }
        	pki_lptr->u64 = 0;
		pki_lptr->addr   = CVM_DRV_GET_PHYS(&mdata->rh);
		pki_lptr->size   = OCT_RH_SIZE + 8;



#ifdef LINUX_IPSEC
		if (mdata->ipsec_mark) {
			/*RH append size for ipsec xfrm mark */
			pki_lptr->size += 8;
		}
#endif

                cvmx_wqe_set_bufs(wqe, cvmx_wqe_get_bufs(wqe) + 1);
        	cvmx_wqe_set_len(wqe, (cvmx_wqe_get_len(wqe) + pki_lptr->size));
		rh = (union octeon_rh *) cvmx_phys_to_ptr(pki_lptr->addr);
	} else {
                lptr         = &wqe->packet_ptr;
		mdata->next_buf_ptr = lptr->u64;
                lptr->u64    = 0;
                lptr->s.addr = CVM_DRV_GET_PHYS(&mdata->rh);
		lptr->s.back = (lptr->s.addr - CVM_DRV_GET_PHYS(wqe))/CVMX_CACHE_LINE_SIZE;
                lptr->s.size = OCT_RH_SIZE + 8;
                lptr->s.pool = CVMX_FPA_WQE_POOL;
                cvmx_wqe_set_bufs(wqe, cvmx_wqe_get_bufs(wqe) + 1);
        	cvmx_wqe_set_len(wqe, (cvmx_wqe_get_len(wqe) + lptr->s.size));
		rh = (union octeon_rh *) cvmx_phys_to_ptr(lptr->s.addr);
	}

	return rh;
}

void cvmcs_nic_delete_first_buffer(cvmx_wqe_t *wqe)
{
        cvmx_buf_ptr_pki_t *lptr;
        cvmx_pko_buf_ptr_t link;

        lptr = (cvmx_buf_ptr_pki_t *)&wqe->packet_ptr;
        link.u64 = *((uint64_t *)CVM_DRV_GET_PTR(lptr->addr - 8));
        lptr->addr = link.s.addr;
        lptr->size = link.s.size;
        cvmx_wqe_set_bufs(wqe, cvmx_wqe_get_bufs(wqe) - 1);
        cvmx_wqe_set_len(wqe, (cvmx_wqe_get_len(wqe) - link.s.size));
}

static inline int cvmcs_nic_process_dpi_wqe_ifidx(cvmx_wqe_t *wqe,
					      int ifidx,
					      pkt_proc_flags_t flags)
{
	tx_info_t *txinfo;
	ipsec_rx_info_t ipsec_rx_info;
	short offset = 0, timestamp_this_packet;
	vnic_port_info_t *dest_port;
	union octeon_rh *rh;
	int port, queue, rxq_idx, rxq, tot_len = cvmx_wqe_get_len(wqe);
	int16_t ipsec_ret = -1;
	uint32_t hash = (uint32_t)-1; /* All ones !*/
	uint32_t hashtype = 0;
	union octnic_packet_params packet_params;
	cvmcs_nic_metadata_t *mdata = CVMCS_NIC_METADATA(wqe);
	int fromq_idx;
	uint32_t *rh_meta;

	dest_port = &octnic->port[ifidx];

	packet_params.u32 = mdata->front.irh.s.ossp;
	timestamp_this_packet = packet_params.s.tsflag;

	fromq_idx = (mdata->from_port-0x100) - octnic->port[mdata->from_ifidx].iq_base;
	per_core_stats[cvmx_get_core_num()].link_stats[mdata->from_ifidx].fromhost.fw_total_sent += 1;
	per_core_stats[cvmx_get_core_num()].perq_stats[mdata->from_ifidx].fromhost.fw_total_fwd[fromq_idx] += 1;
	per_core_stats[cvmx_get_core_num()].perq_stats[mdata->from_ifidx].fromhost.fw_total_fwd_bytes[fromq_idx] += tot_len;

	/*Check for TSO packet*/
	txinfo = (tx_info_t *)(&mdata->front.ossp[0]);
	if ((!timestamp_this_packet) &&
	    (!(dest_port->state.lro_on_ipv4 || dest_port->state.lro_on_ipv6)) &&
	    (txinfo->s.gso_segs)) {
		/*
	 	 * if TSO is successful, packet bufs and wqe will be freed
	 	 * later in the TSO completion callback
	 	 */
		if (cvmcs_nic_handle_tso(wqe, ifidx))
		{
			per_core_stats[cvmx_get_core_num()].link_stats[mdata->from_ifidx].fromhost.fw_err_drop += 1;
			cvmcs_cond_free_wqe(wqe);
			return -1;
		}
		return 0;
	}

#if 0
	/* TODO: ip sec switching need to be supported. this is old code not functional */
	if (CVMCS_NIC_METADATA_IS_IPSEC_OP(mdata)) {
		if (CVMCS_NIC_METADATA_IS_IPSEC(mdata) && nicport->state.ipsecv2_ah_esp) {
			if (cvm_ipsec_offload(wqe, front_size, ifidx, OUTBOUND_PROCESSING))
				cvm_free_wqe_wrapper(wqe);
		}
		return -1;
	}
#endif

	if (CVMCS_NIC_METADATA_IS_IPV4(mdata) || CVMCS_NIC_METADATA_IS_IPV6(mdata)) {
		/* The actual header checksums are done later when we send to PKO. */
		flags.s.csum_verified = CNNIC_IPSUM_VERIFIED;

		if (CVMCS_NIC_METADATA_IS_TCP(mdata) || CVMCS_NIC_METADATA_IS_UDP(mdata))
			flags.s.csum_verified = CNNIC_CSUM_VERIFIED;
	}

	if (dest_port->state.tnl_rx_csum) {
		if (CVMCS_NIC_METADATA_IS_TUNNEL(mdata)) {
			flags.s.csum_verified |= CNNIC_TUN_CSUM_VERIFIED;
		}
	}

#if 0
	/* TODO: ip sec switching need to be supported. this is old code not functional */
	if ((!OCTEON_IS_MODEL(OCTEON_CN78XX) && !OCTEON_IS_MODEL(OCTEON_CN73XX))
	    && CVMCS_NIC_METADATA_IS_IPSEC(mdata) && nicport->state.ipsecv2_ah_esp) {
		ipsec_ret = cvm_ipsec_offload(wqe, 0, ifidx, INBOUND_PROCESSING);
		if (!ipsec_ret)
			cvmcs_nic_mdata_ipsec_update_metadata(wqe, ifidx);
		//cvmcs_cond_free_wqe(wqe, flags);
		//return;
	}
#endif

	if (ipsec_ret <= 0) {
		if (txinfo->s.gso_segs) {
			oct_nic_lro_tso_receive_pkt(wqe, ifidx);
		} else {
	    		if (!oct_nic_lro_receive_pkt(wqe, ifidx))
				return 0;
		}
	}

	per_core_stats[cvmx_get_core_num()].link_stats[ifidx].fromwire.fw_total_rcvd += 1;

	if (dest_port->state.rss_on) {   /* RSS ENABLED */
		rxq_idx = cvmcs_nic_rss_get_queue(wqe, &hash, &hashtype, ifidx);
		if (-1 == rxq_idx) {
			rxq_idx =  (cvmx_wqe_get_tag(wqe) % (dest_port->linfo.num_rxpciq));
#if defined(USE_CUSTOM_OQ)
			rxq_idx = 0;
#endif
		}

		DBG("%s: rss hash 0x%x\n", __func__, hash);
	} else if (dest_port->state.fnv_on) {   /* FNV ENABLED */
		rxq_idx = cvmcs_nic_fnv_get_queue(wqe, &hash, ifidx);
		if (-1 == rxq_idx) {
			rxq_idx =  (cvmx_wqe_get_tag(wqe) % (dest_port->linfo.num_rxpciq));
#if defined(USE_CUSTOM_OQ)
			rxq_idx = 0;
#endif
		}

		DBG("%s: fnv hash 0x%x\n", __func__, hash);
	} else {
		//rxq_idx =
		//   nicport->linfo.rxpciq[0] +
		//  (cvmx_wqe_get_tag(wqe) & (nicport->linfo.num_rxpciq - 1));
		/* Receive Queue Selection Mechanism is called when
		 * tunnel header length is non-zero
		 */
		uint32_t tag = cvmx_wqe_get_tag(wqe);
		uint8_t from_lpport = cvmcs_nic_tunnel_is_loopback_port(wqe);

		if(CVMCS_NIC_METADATA_TUNNEL_HEADER_LENGTH(mdata)) {
			/* from_lpport will be
			 *    0 - packet not received from loopback
			 *    1 - packet received from loopback
			 */
			tag = vxlan_get_tag(wqe,
					CVMCS_NIC_METADATA_TUNNEL_HEADER_LENGTH(mdata),
					from_lpport);
			if (!tag) {
				/* When Tag is received as Zero */
				tag = cvmx_wqe_get_tag(wqe);
			}
		}

		hash = tag;
		if (dest_port->pkt_steering_enable && CVMCS_NIC_METADATA_IS_TCP(mdata))
			rxq_idx = get_queue_from_pkt_steering_table(dest_port, wqe);
		else
			rxq_idx =  (tag % (dest_port->linfo.num_rxpciq));
#if defined(USE_CUSTOM_OQ)
		rxq_idx = 0;
#endif
	}

	rxq = OCT_NIC_OQ_NUM(dest_port, rxq_idx);

	rh = cvmcs_nic_insert_dpi_headers(wqe, ifidx, &flags);

	offset += OCT_RH_SIZE;
	tot_len += OCT_RH_SIZE;


	rh->u64 = 0;
	rh->r_dh.opcode = OPCODE_NIC;
	rh->r_dh.subcode = OPCODE_NIC_NW_DATA;
	rh->r_dh.csum_verified = flags.s.csum_verified;	/* checksum notification to Host */
	rh->r_dh.encap_on = CVMCS_NIC_METADATA_IS_ENCAP_ON(mdata);
	if (OCTEON_IS_MODEL(OCTEON_CN6XXX)) {
		rh->r_dh.has_hwtstamp = 1;
		rh->r_dh.len = 1;
	}

	rh_meta = (uint32_t *)(rh + 1);
	{
		*rh_meta = hash;
		rh_meta++;
		*rh_meta = hashtype;
		rh_meta++;
		rh->r_dh.has_hash = 0x1; /* indicate hash */
		rh->r_dh.len += 1;
		offset += 8;
		tot_len += 8;
	}


        if (OCT_NIC_PORT_VF(ifidx) && (octnic->port[ifidx].user_set_vlanTCI & 0xFFF)) {
                /* The hypervisor had previously set the VLAN tag for this VF via the
                 * "ip link" command.  But the VF driver will not see any VLAN tags.
                 */
        } else {
                rh->r_dh.priority = CVMCS_NIC_METADATA_PRIORITY(mdata);
                rh->r_dh.vlan = CVMCS_NIC_METADATA_VLAN_ID(mdata);
        }

	/* Using extra to show IPSec status */
	ipsec_rx_info.u32 = 0;
	ipsec_rx_info.s.status = ipsec_ret & 0xff;
	if ((!ipsec_ret) && CVMCS_NIC_METADATA_IS_IPSEC_ESP(mdata)) {
		ipsec_rx_info.s.esp_pad_length = CVMCS_NIC_METADATA_IPSEC_ESP_PAD_LEN(mdata);
		ipsec_rx_info.s.esp_next_hdr = CVMCS_NIC_METADATA_IPSEC_NEXT_PROTO(mdata);
		ipsec_rx_info.s.esp_info_set = 1;
	}
	rh->r_dh.extra = ipsec_rx_info.u32 & 0x0fffffff;

	DBG("wqe @ %p wqe bufs: %d len: %d pkt_ptr @ %lx ts=%016llx rts=%016llx\n", wqe,
	    cvmx_wqe_get_bufs(wqe), cvmx_wqe_get_len(wqe),
	    (unsigned long)wqe->packet_ptr.s.addr,
	    *((long long unsigned int *)CVM_DRV_GET_PTR(wqe->packet_ptr.s.addr)+1),
	    (long long unsigned int)cvmx_read_csr(CVMX_MIO_PTP_CLOCK_HI));

	DBG_DUMP_PACKET(wqe);

	port = cvm_pci_get_oq_pkoport(rxq);
	queue = cvm_pci_get_oq_pkoqueue(rxq);

	if (cvmx_unlikely(port == -1 || queue == -1)) {
		per_core_stats[cvmx_get_core_num()].link_stats[ifidx].fromwire.fw_err_drop += 1;
		cvmcs_nic_delete_first_buffer(wqe);
		cvmcs_cond_free_wqe(wqe);
		return -ENOIF;
	}

	flags.s.offset = offset;
	flags.s.timestamp_packet = timestamp_this_packet;
	flags.s.rsp = timestamp_this_packet;
	flags.s.subcode = OPCODE_NIC_TIMESTAMP;

	DBG("to host: rxq: %d port: %d queue: %d\n", rxq, port, queue);
	if (octeon_has_feature(OCTEON_FEATURE_PKO3)) {
		if(!cvmcs_nic_send_to_pko3(wqe, 1, port, queue, flags, dest_port)) {
			per_core_stats[cvmx_get_core_num()].perq_stats[ifidx].fromwire.fw_total_fwd[rxq_idx] += 1;
			per_core_stats[cvmx_get_core_num()].perq_stats[ifidx].fromwire.fw_total_fwd_bytes[rxq_idx] += tot_len;
			if (cvmx_wqe_is_l2_mcast(wqe))
				per_core_stats[cvmx_get_core_num()].link_stats[ifidx].fromwire.fw_total_mcast += 1;
			else if (cvmx_wqe_is_l2_bcast(wqe))
				per_core_stats[cvmx_get_core_num()].link_stats[ifidx].fromwire.fw_total_bcast += 1;
			return 0;
		}
	}
	else {
		if (!cvmcs_nic_send_to_pko(wqe, 1, port, queue, flags, dest_port)) {
			per_core_stats[cvmx_get_core_num()].perq_stats[ifidx].fromwire.fw_total_fwd[rxq_idx] += 1;
			per_core_stats[cvmx_get_core_num()].perq_stats[ifidx].fromwire.fw_total_fwd_bytes[rxq_idx] += tot_len;
			if (cvmx_wqe_is_l2_mcast(wqe))
				per_core_stats[cvmx_get_core_num()].link_stats[ifidx].fromwire.fw_total_mcast += 1;
			else if (cvmx_wqe_is_l2_bcast(wqe))
				per_core_stats[cvmx_get_core_num()].link_stats[ifidx].fromwire.fw_total_bcast += 1;
			return 0;
		}
	}

	per_core_stats[cvmx_get_core_num()].link_stats[ifidx].fromwire.fw_err_pko += 1;
	cvmcs_nic_delete_first_buffer(wqe);
	cvmcs_cond_free_wqe(wqe);

	return -ENOTFWD;
}

int
cvmcs_nic_forward_packet_to_host(cvmx_wqe_t * wqe, int ifidx, pkt_proc_flags_t flags)
{
	union octeon_rh *rh;
	int port, queue, rxq, rxq_idx, tot_len;
	int16_t ipsec_ret = -1;
	vnic_port_info_t * nicport =  &octnic->port[ifidx];
	uint32_t hash = (uint32_t)-1; /* All ones !*/
	uint32_t hashtype, *rh_meta;
	uint8_t encap_on = 0;
	ipsec_rx_info_t ipsec_rx_info;
	cvmcs_nic_metadata_t *mdata = CVMCS_NIC_METADATA(wqe);

	per_core_stats[cvmx_get_core_num()].link_stats[ifidx].fromwire.fw_total_rcvd += 1;

	if (!nicport->state.rx_on) {
		per_core_stats[cvmx_get_core_num()].link_stats[ifidx].fromwire.fw_err_drop += 1;
		cvmcs_cond_free_wqe(wqe);
		return -ENOTFWD;
	}

	cvmcs_profile_mark_event(PROF_RX_FILTER);

	if (CVMCS_NIC_METADATA_IS_IPSEC(mdata) && nicport->state.ipsecv2_ah_esp) {
		ipsec_ret = cvm_ipsec_offload(wqe, 0, ifidx, INBOUND_PROCESSING);
		if (!ipsec_ret)
			cvmcs_nic_mdata_ipsec_update_metadata(wqe, ifidx);
		//cvmcs_cond_free_wqe(wqe, flags);
		//return;
	}

	if (nicport->state.tnl_rx_csum) {
		if (octeon_has_feature(OCTEON_FEATURE_CN78XX_WQE)) {
			cvmx_wqe_78xx_t *wqe78 = (cvmx_wqe_78xx_t *) wqe;
			if ((wqe78->word2.ld_hdr_type == CVMX_PKI_LTYPE_E_NVGRE) ||
		    	    ((wqe78->word2.ld_hdr_type == CVMX_PKI_LTYPE_E_UDP_VXLAN) &&
			     ((wqe78->word2.lf_hdr_type == CVMX_PKI_LTYPE_E_TCP) ||
			      (wqe78->word2.lf_hdr_type == CVMX_PKI_LTYPE_E_UDP)))) {
			    /* windows HCT tests send packets w/TCP flags == 0; disregard this error */
			    	if (cvmx_likely (!wqe78->word2.err_level) ||
				    ((wqe78->word2.err_level == CVMX_PKI_ERRLEV_E_LF) &&
				     (wqe78->word2.err_code == CVMX_PKI_OPCODE_TCP_FLAG))) {
					flags.s.csum_verified = CNNIC_TUN_CSUM_VERIFIED;
			    	} else {
					per_core_stats[cvmx_get_core_num()].link_stats[ifidx].fromwire.fw_rx_vxlan_err += 1;
			    	}
			} else {
				if (!CVMCS_NIC_METADATA_IS_PACKET_FROM_LOOP_BACK(mdata)) {
					if (!cvmcs_nic_78xx_tunnel_calculate_cksum(wqe, ifidx, &flags)) {
						return 0;
					}
				} else {
					/* This is a pkt from loopback, check for tunnel csum error;
					 * see 'cvmcs_nic_tunnel_verify_cksum()'.
					*/
					if (CVMCS_NIC_METADATA_IS_ENCAP_ON(mdata) &&
					    !(flags.s.csum_verified & CNNIC_TUN_CSUM_VERIFIED)) {
						per_core_stats[cvmx_get_core_num()].link_stats[ifidx].fromwire.fw_rx_vxlan_err += 1;
					}
				}
			}
		} else {
			if (!CVMCS_NIC_METADATA_IS_PACKET_FROM_LOOP_BACK(mdata)) {
				if (!cvmcs_nic_tunnel_calculate_cksum(wqe, ifidx, &flags)) {
					return 0;
				}
			}
		}

		encap_on = CVMCS_NIC_METADATA_IS_ENCAP_ON(mdata);
		if (CVMCS_NIC_METADATA_IS_TUNNEL(mdata))
			per_core_stats[cvmx_get_core_num()].link_stats[ifidx].fromwire.fw_rx_vxlan += 1;
	}

	cvmcs_profile_mark_event(PROF_RX_CSUM);

	if ((ipsec_ret <= 0) && !oct_nic_lro_receive_pkt(wqe, ifidx)) {
		return 0;
	}

	if (nicport->state.rss_on) {   /* RSS ENABLED */
		rxq_idx = cvmcs_nic_rss_get_queue(wqe, &hash, &hashtype, ifidx);
		if (-1 == rxq_idx) {
			rxq_idx =  (cvmx_wqe_get_tag(wqe) % (nicport->linfo.num_rxpciq));
#if defined(USE_CUSTOM_OQ)
			rxq_idx = 0;
#endif
		}

		DBG("%s: rss hash 0x%x rxq = %d\n", __func__, hash, rxq_idx);
	} else if (nicport->state.fnv_on) {   /* FNV ENABLED */
		rxq_idx = cvmcs_nic_fnv_get_queue(wqe, &hash, ifidx);
		if (-1 == rxq_idx) {
			rxq_idx =  (cvmx_wqe_get_tag(wqe) % (nicport->linfo.num_rxpciq));
#if defined(USE_CUSTOM_OQ)
			rxq_idx = 0;
#endif
		}

		DBG("%s: fnv hash 0x%x rxq = %d\n", __func__, hash, rxq_idx);
	} else {
		rxq_idx = cvmcs_nic_get_rxq(wqe, &hash, ifidx);
#if defined(USE_CUSTOM_OQ)
		rxq_idx = 0;
#endif
	}

	rxq = OCT_NIC_OQ_NUM(nicport, rxq_idx);

	rh = cvmcs_nic_insert_dpi_headers(wqe, ifidx, &flags);

	rh->u64 = 0;
	rh->r_dh.opcode = OPCODE_NIC;
	rh->r_dh.subcode = OPCODE_NIC_NW_DATA;
	rh->r_dh.csum_verified = flags.s.csum_verified;	/* checksum notification to Host */
	rh->r_dh.encap_on = encap_on;
	if (OCTEON_IS_MODEL(OCTEON_CN6XXX)) {
		rh->r_dh.has_hwtstamp = 1;
		rh->r_dh.len = 1;
	}
#ifdef OVS_IPSEC
	rh->r_dh.has_hwtstamp = 0;
	rh->r_dh.len = 0;
#endif

	rh_meta = (uint32_t *)(rh + 1);
	{
		*rh_meta = hash;
		rh_meta++;
		*rh_meta = hashtype;
		rh_meta++;
		rh->r_dh.has_hash = 0x1;
		rh->r_dh.len += 1;
	}


#ifdef LINUX_IPSEC
	if (mdata->ipsec_mark) {
		rh->r_dh.has_ipsec_xfrm_mark = 1;
		rh->r_dh.len += 1;
		*rh_meta  = mdata->ipsec_mark;
		rh_meta++;
		*rh_meta  = 0;
		DBG("rhlen=%d, mdata->ipsec_mark=%llu\n", rh->r_dh.len,(unsigned long long) mdata->ipsec_mark);
	}
#endif

	if (OCT_NIC_PORT_VF(ifidx) && (octnic->port[ifidx].user_set_vlanTCI & 0xFFF)) {
		/* The hypervisor had previously set the VLAN tag for this VF via the
		 * "ip link" command.  But the VF driver will not see any VLAN tags.
		 */
	} else {
		rh->r_dh.priority = CVMCS_NIC_METADATA_PRIORITY(mdata);
		rh->r_dh.vlan = CVMCS_NIC_METADATA_VLAN_ID(mdata);
	}

        /* Using extra to show IPSec status */
        ipsec_rx_info.u32 = 0;
        ipsec_rx_info.s.status = ipsec_ret & 0xff;
        if ((!ipsec_ret) && CVMCS_NIC_METADATA_IS_IPSEC_ESP(mdata)) {
                ipsec_rx_info.s.esp_pad_length = CVMCS_NIC_METADATA_IPSEC_ESP_PAD_LEN(mdata);
                ipsec_rx_info.s.esp_next_hdr = CVMCS_NIC_METADATA_IPSEC_NEXT_PROTO(mdata);
		ipsec_rx_info.s.esp_info_set = 1;
        }
        rh->r_dh.extra = ipsec_rx_info.u32 & 0x0fffffff;

	DBG("wqe @ %p wqe bufs: %d len: %d pkt_ptr @ %lx ts=%016llx rts=%016llx\n", wqe,
	    cvmx_wqe_get_bufs(wqe), cvmx_wqe_get_len(wqe),
	    (unsigned long)wqe->packet_ptr.s.addr,
	    *((long long unsigned int *)CVM_DRV_GET_PTR(wqe->packet_ptr.s.addr)+1),
	    (long long unsigned int)cvmx_read_csr(CVMX_MIO_PTP_CLOCK_HI));

	DBG_DUMP_PACKET(wqe);

	port = cvm_pci_get_oq_pkoport(rxq);
	queue = cvm_pci_get_oq_pkoqueue(rxq);

	if (cvmx_unlikely(port == -1 || queue == -1)) {
		per_core_stats[cvmx_get_core_num()].link_stats[ifidx].fromwire.fw_err_drop += 1;
		cvmcs_nic_delete_first_buffer(wqe);
		cvmcs_cond_free_wqe(wqe);
		return -ENOIF;
	}

	tot_len = cvmx_wqe_get_len(wqe);

	cvmcs_profile_mark_event(PROF_RX_RH_DONE);

	DBG("to host: rxq: %d port: %d queue: %d\n", rxq, port, queue);
	if (octeon_has_feature(OCTEON_FEATURE_PKO3)) {
		if(!cvmcs_nic_send_to_pko3(wqe, 1, port, queue, flags, nicport)) {
			per_core_stats[cvmx_get_core_num()].perq_stats[ifidx].fromwire.fw_total_fwd[rxq_idx] += 1;
			per_core_stats[cvmx_get_core_num()].perq_stats[ifidx].fromwire.fw_total_fwd_bytes[rxq_idx] += tot_len;
			if (cvmx_wqe_is_l2_mcast(wqe))
				per_core_stats[cvmx_get_core_num()].link_stats[ifidx].fromwire.fw_total_mcast += 1;
			else if (cvmx_wqe_is_l2_bcast(wqe))
				per_core_stats[cvmx_get_core_num()].link_stats[ifidx].fromwire.fw_total_bcast += 1;
			return 0;
		}
	}
	else {
		if (!cvmcs_nic_send_to_pko(wqe, 1, port, queue, flags, nicport)) {
			per_core_stats[cvmx_get_core_num()].perq_stats[ifidx].fromwire.fw_total_fwd[rxq_idx] += 1;
			per_core_stats[cvmx_get_core_num()].perq_stats[ifidx].fromwire.fw_total_fwd_bytes[rxq_idx] += tot_len;
			if (cvmx_wqe_is_l2_mcast(wqe))
				per_core_stats[cvmx_get_core_num()].link_stats[ifidx].fromwire.fw_total_mcast += 1;
			else if (cvmx_wqe_is_l2_bcast(wqe))
				per_core_stats[cvmx_get_core_num()].link_stats[ifidx].fromwire.fw_total_bcast += 1;
			return 0;
		}
	}
	per_core_stats[cvmx_get_core_num()].link_stats[ifidx].fromwire.fw_err_pko += 1;
	cvmcs_nic_delete_first_buffer(wqe);
	cvmcs_cond_free_wqe(wqe);

	return -ENOTFWD;
}

static inline int cvmcs_nic_process_gmx_wqe_ifidx(cvmx_wqe_t *wqe,
					      int ifidx,
					      pkt_proc_flags_t flags)
{
	int err_code = cvmx_wqe_get_rcv_err(wqe);

	if (cvmx_unlikely(err_code)) {
		if (cvmcs_nic_opcode_to_stats(ifidx, err_code)) {
			DBG("L2/L1 error from port %d. Error code=%x\n",
			    cvmx_wqe_get_port(wqe), err_code);
			cvmcs_cond_free_wqe(wqe);

			return -EBADPACKET;
		}
	}

	if (cvmcs_nic_validate_rx_frame_len(wqe, ifidx)) {
		cvmcs_cond_free_wqe(wqe);
		return -ENOIF;
	}

	/* May be an L3/L4 errored packet, but process anyway */
#ifdef ENABLE_NIC_PEER_TO_PEER
	return cvmcs_nic_forward_pkt_to_ep(wqe, ifidx);
#else
	cvmcs_profile_mark_event(PROF_RX_ERROR_CHECK);

	return cvmcs_nic_forward_packet_to_host(wqe, ifidx, flags);
#endif
}

static inline int cvmcs_nic_process_wqe_ifidx(cvmx_wqe_t *wqe,
					      int ifidx,
					      pkt_proc_flags_t flags)
{
	cvmcs_nic_metadata_t *mdata = CVMCS_NIC_METADATA(wqe);

	if (octnic->port[ifidx].state.active) {
		if (cvmx_unlikely(octnic->port[ifidx].state.rx_on == 0) || (OCT_NIC_PORT_VF(ifidx) && octnic->port[ifidx].user_set_linkstate == IFLA_VF_LINK_STATE_DISABLE)) {
			/* Broadcast/multicast packet received on VNIC port that
			 * is not up yet
			 */
			per_core_stats[cvmx_get_core_num()].link_stats[ifidx].fromhost.fw_err_drop += 1;
			cvmcs_cond_free_wqe(wqe);
			return -ENOIF;
		}

		DBG("%s ifidx=%d flags[df=%d,rsp=%d,subone1=%d,reg1=%x,size1=%d,subcode=%d]\n",
			__func__, ifidx, flags.s.dontfree, flags.s.rsp,
			flags.s.subone1, flags.s.reg1, flags.s.size1,
			flags.s.subcode);

		//TODO can be optimized
		cvmcs_nic_mdata_parse_headers(wqe, ifidx);

		if (octnic->port[mdata->from_ifidx].pkt_steering_enable &&
		    CVMCS_NIC_METADATA_IS_TCP_SYN(mdata))
			set_queue_in_pkt_steering_table(wqe);

		if (CVMCS_NIC_METADATA_IS_PACKET_FROM_DPI(mdata))
		    	return cvmcs_nic_process_dpi_wqe_ifidx(wqe, ifidx, flags);
		else
		   	return cvmcs_nic_process_gmx_wqe_ifidx(wqe, ifidx, flags);

	} else {
		DBG("Interface %d not yet active\n", ifidx);
		cvmcs_cond_free_wqe(wqe);
		return -ENOIF;
	}

	return 0;
}


int
cvmcs_nic_forward_packet_to_wire(cvmx_wqe_t * wqe, pkt_proc_flags_t flags)
{
	short timestamp_this_packet;
	vnic_port_info_t *nicport;
	int port, queue, fromq_idx;
	tx_info_t *txinfo;
	union octnic_packet_params packet_params;
	int ipsec_op;
	int pf_ifidx;
	octnic_if_state_t *pf_if_state;
	cvmcs_nic_metadata_t *mdata = CVMCS_NIC_METADATA(wqe);
	int len = cvmx_wqe_get_len(wqe);

	pf_ifidx = OCT_NIC_PORT_IDX(OCT_NIC_PORT_PF(mdata->from_ifidx), 0);
	pf_if_state = &octnic->port[pf_ifidx].state;
	if (pf_if_state->rx_on == 0) {
		cvmcs_cond_free_wqe(wqe);
		return -ENOTFWD;
	}

	if (OCT_NIC_PORT_VF(mdata->from_ifidx)) {
		/* This packet came from a VF; don't forward it to the wire if the VF's parent PF's link is down. */
		union oct_link_status *pf_ls;
		pf_ls = &octnic->port[pf_ifidx].linfo.link;
		if (pf_ls->s.link_up == 0) {
			cvmcs_cond_free_wqe(wqe);
			return -ENOTFWD;
		}
	}

	cvmcs_nic_insert_vlan_tag(wqe);
#ifndef LINUX_IPSEC
	cvmcs_dcb_process_qcn(wqe);
	cvmcs_nic_mdata_parse_headers(wqe, -1);
#endif

	packet_params.u32 = mdata->front.irh.s.ossp;
	timestamp_this_packet = packet_params.s.tsflag;
	ipsec_op = packet_params.s.ipsec_ops;

	nicport = &octnic->port[mdata->from_ifidx];
	fromq_idx = (mdata->from_port - 0x100)-nicport->iq_base;
	per_core_stats[cvmx_get_core_num()].link_stats[mdata->from_ifidx].fromhost.fw_total_sent += 1;
	per_core_stats[cvmx_get_core_num()].perq_stats[mdata->from_ifidx].fromhost.fw_total_fwd[fromq_idx] += 1;
	per_core_stats[cvmx_get_core_num()].perq_stats[mdata->from_ifidx].fromhost.fw_total_fwd_bytes[fromq_idx] += len;

	if (cvmx_unlikely(nicport->linfo.link.s.link_up == 0)) {
		per_core_stats[cvmx_get_core_num()].link_stats[mdata->from_ifidx].fromhost.fw_err_link += 1;
		cvmcs_cond_free_wqe(wqe);
		return -ENOTFWD;
	}

	if (octnic->port[mdata->from_ifidx].pkt_steering_enable &&
	    CVMCS_NIC_METADATA_IS_TCP_SYN(mdata))
			set_queue_in_pkt_steering_table(wqe);

	/*Check for TSO packet*/
	txinfo = (tx_info_t *)(&mdata->front.ossp[0]);
	if ((!timestamp_this_packet) && (txinfo->s.gso_segs)) {
		/*
	 	 * if TSO is successful, packet bufs and wqe will be freed
	 	 * later in the TSO completion callback
	 	 */
		if (cvmcs_nic_handle_tso(wqe, -1))
		{
			per_core_stats[cvmx_get_core_num()].link_stats[mdata->from_ifidx].fromhost.fw_err_drop += 1;
			cvmcs_cond_free_wqe(wqe);
			return -ENOTFWD;
		}
		return 0;
	}

	if (ipsec_op) {
		if (CVMCS_NIC_METADATA_IS_IPSEC(mdata) && nicport->state.ipsecv2_ah_esp) {
			if (cvm_ipsec_offload(wqe, mdata->front_size, mdata->from_ifidx, OUTBOUND_PROCESSING)){
				cvmcs_cond_free_wqe(wqe);
				return -ENOTFWD;
			}
			return 0;
		}
	}

	port = nicport->linfo.gmxport;
	queue = cvmcs_dcb_get_dq(wqe, port);

	if (cvmx_unlikely(port == -1 || queue == -1)) {
		per_core_stats[cvmx_get_core_num()].link_stats[mdata->from_ifidx].fromhost.fw_err_drop += 1;
		cvmcs_cond_free_wqe(wqe);
		return -ENOTFWD;
	}

#ifdef RLIMIT
	int pko_port = cvmx_helper_cfg_ipd2pko_port_base(port);	/* RateLimit feature */
#endif

	cvmcs_profile_mark_event(PROF_TX_HEADERS);

	flags.s.offset = 0;
	flags.s.timestamp_packet = timestamp_this_packet;
	flags.s.rsp = timestamp_this_packet;
	flags.s.subcode = OPCODE_NIC_TIMESTAMP;

	cvmcs_profile_mark_event(PROF_TX_BEFORE_PKO);

	DBG("to wire: port: %d queue: %d\n", port, queue);
	/* 0x100 is the starting offset for dpi ports */
	if (octeon_has_feature(OCTEON_FEATURE_PKO3)) {
		if(!cvmcs_nic_send_to_pko3(wqe, 0, port, queue, flags, nicport)) {
			if (cvmx_wqe_is_l2_mcast(wqe))
				per_core_stats[cvmx_get_core_num()].link_stats[mdata->from_ifidx].fromhost.fw_total_mcast_sent += 1;
			else if (cvmx_wqe_is_l2_bcast(wqe))
				per_core_stats[cvmx_get_core_num()].link_stats[mdata->from_ifidx].fromhost.fw_total_bcast_sent += 1;
#ifdef RLIMIT
			cvmx_fau_atomic_add64(pko_rate_limit[pko_port].fau, 1);	/* RateLimit feature */
#endif
			return 0;
		}
	} else {
		if (!cvmcs_nic_send_to_pko(wqe, 0, port, queue, flags, nicport)) {
			if (!CVMCS_NIC_METADATA_IS_DUP_WQE(mdata))
				cvmx_wqe_free(wqe);
			if (cvmx_wqe_is_l2_mcast(wqe))
				per_core_stats[cvmx_get_core_num()].link_stats[mdata->from_ifidx].fromhost.fw_total_mcast_sent += 1;
			else if (cvmx_wqe_is_l2_bcast(wqe))
				per_core_stats[cvmx_get_core_num()].link_stats[mdata->from_ifidx].fromhost.fw_total_bcast_sent += 1;
#ifdef RLIMIT
			cvmx_fau_atomic_add64(pko_rate_limit[pko_port].fau, 1);	/* RateLimit feature */
#endif
			return 0;
		}
	}

	//cvmx_atomic_add_u64(&nicport->stats.fromwire.fw_err_pko, 1);
	per_core_stats[cvmx_get_core_num()].link_stats[mdata->from_ifidx].fromhost.fw_err_pko += 1;
	cvmcs_cond_free_wqe(wqe);
	return -ENOTFWD;
}

cvmx_wqe_t *cvmcs_nic_dup_wqe(cvmx_wqe_t *wqe)
{
	cvmx_wqe_t *new_wqe = 0;
	cvmcs_nic_metadata_t *mdata;

	new_wqe = (cvmx_wqe_t *)cvmcs_wqe_alloc();
	if (cvmx_unlikely(!new_wqe)) {
		DBG("[ DRV ] failed to allocate new wqe.\n");
		return 0;
	}

	/* Copy the wqe */
	memcpy(new_wqe, wqe, CVMCS_NIC_METADATA_WQE_SIZE);

	mdata = CVMCS_NIC_METADATA(new_wqe);

	mdata->flags |= METADATA_FLAGS_DUP_WQE;

	if (octeon_has_feature(OCTEON_FEATURE_CN78XX_WQE)) {
		cvmx_buf_ptr_pki_t *lptr_pki =
			(cvmx_buf_ptr_pki_t *)&wqe->packet_ptr;
		lptr_pki->packet_outside_wqe = 1;
		((cvmx_wqe_78xx_t *)new_wqe)->word0.aura = cvmcs_wqe_pool();
	}

	return new_wqe;
}

static void cvmcs_nic_dup_first_buffer(cvmx_wqe_t *wqe, void *buf)
{
	int i, count, offset, size;
	uint64_t *sbuf, *dbuf;
        uint64_t nextptr, startptr;
        cvmx_buf_ptr_pki_t  *pki_lptr;
        cvmcs_nic_metadata_t *mdata = CVMCS_NIC_METADATA(wqe);

        if (octeon_has_feature(OCTEON_FEATURE_CN78XX_WQE)) {
                pki_lptr = (cvmx_buf_ptr_pki_t *)&wqe->packet_ptr;
                nextptr = *((uint64_t *)CVM_DRV_GET_PTR(pki_lptr->addr - 8));
		offset = pki_lptr->addr & (CVMX_FPA_PACKET_POOL_SIZE - 1);
		size = pki_lptr->size;
		sbuf = (uint64_t *)CVM_DRV_GET_PTR(pki_lptr->addr);
		dbuf = (uint64_t *)((uint8_t *)buf + offset);
                *(dbuf - 1) = nextptr;
                pki_lptr->addr = CVM_DRV_GET_PHYS(dbuf);
        } else {
                nextptr = *((uint64_t *) CVM_DRV_GET_PTR(wqe->packet_ptr.s.addr - 8));
                startptr = (((wqe->packet_ptr.s.addr >> 7) - wqe->packet_ptr.s.back) << 7);
		offset = wqe->packet_ptr.s.addr - startptr;
		size = wqe->packet_ptr.s.size;
		sbuf = (uint64_t *) CVM_DRV_GET_PTR(wqe->packet_ptr.s.addr);
		dbuf = (uint64_t *)((uint8_t *)buf + offset);
                *(dbuf - 1) = nextptr;
                wqe->packet_ptr.s.addr = CVM_DRV_GET_PHYS(dbuf);
        }
	

	if (size > cvmx_wqe_get_len(wqe))
		size = cvmx_wqe_get_len(wqe);

	count = size / 8;

	for (i = 0; i < count; i++) {
		dbuf[i] = sbuf[i];
	}	

	i = count * 8;

	while (i < size) {
		((uint8_t *)dbuf)[i] = ((uint8_t *)sbuf)[i];
		i++;
	}

	mdata->packet_start = (uint8_t *)PACKET_START(wqe);

        if (CVMCS_NIC_METADATA_IS_PTP_HEADER(mdata))
                mdata->packet_start += OCTNET_FRM_PTP_HEADER_SIZE;

	return;
}

/** Frees list of WQEs and associated buffers.
 * Word1 is a next pointer. Associated buffers are
 * freed from the last in the list. Word0 has the original
 * word0 data. Word2 of the last wqe has the original port.
 *
 * @param wqe head of the WQE list.
 */
static inline void cvmcs_free_wqe_list(cvmx_wqe_t *head)
{
	cvmx_wqe_t *next;
	
	do {
		next = CVMCS_NIC_METADATA(head)->next_wqe;

		if (next) {
			/* Free the head */
			cvmcs_wqe_free(head);

			head = next;
		}
	} while (next);

	cvm_free_wqe_wrapper(head);
}

CVMX_SHARED mbcast_sched_list_t *mbcast_list;

int cvmcs_nic_handle_mbcast_completion(void *arg)
{
	mbcast_sched_list_t *mblist = (mbcast_sched_list_t *)arg;
	struct list_head *curr, *next;

	cvmx_spinlock_lock(&mblist->lock);

	CAVIUM_LIST_FOR_EACH_SAFE(curr, next, &mblist->list) {

		mbcast_sched_node_t *sched = (mbcast_sched_node_t *) curr;
		cvmx_wqe_t *head = sched->head;
		unsigned char cnt =  cvmx_atomic_get64(&sched->subone);

		DBG("%s: cnt = %x head=%016llx\n", __func__,
				cnt, (unsigned long long)head);

		if (cnt == 0) {
			CAVIUM_LIST_DEL(&sched->list);
			mbcast_list->count--;
			cvmcs_free_wqe_list(head);
			DBG("Freed sched node%llu since done\n", (unsigned long long)sched);
			cvmx_fpa_free(sched, CVMX_FPA_PACKET_POOL, 0);
		}

	}

	cvmx_spinlock_unlock(&mblist->lock);

	/* Invoke scheduler again */
	return 0;
}

int cvmcs_nic_start_mbcast_list_task()
{
	return cvmcs_common_add_task( (cpu_freq * 1 ) / 10 ,
		cvmcs_nic_handle_mbcast_completion, (void *)mbcast_list);
}

int cvmcs_nic_init_mbcast_list(void)
{
	if (booting_for_the_first_time) {
		mbcast_list = cvmx_bootmem_alloc_named(sizeof (mbcast_sched_list_t), CVMX_CACHE_LINE_SIZE, "__mbcast_list");

		if (!mbcast_list)
			return -1;

		live_upgrade_ctx->mbcast_list = mbcast_list;

		cavium_init_list_head(&mbcast_list->list);
		mbcast_list->count = 0;
		cvmx_spinlock_init(&mbcast_list->lock);

	} else {
		mbcast_list = live_upgrade_ctx->mbcast_list;
	}

	return 0;
}

/* Forward the packet to all interfaces specified. It assumes
 * at least one bit is set in the ifl.
 * @param wqe   work queue entry
 * @param mdata metadata with list of interfaces
 *
 * @returns 0 if successful, else a failure code if it did not forward
 * any packets
 */
int cvmcs_nic_process_wqe_mbcast(cvmx_wqe_t *wqe, pkt_proc_flags_t flags)
{
	int i;
	cvmx_wqe_t *new_wqe = NULL;
	cvmx_wqe_t *prev_wqe;
	int sent_cnt = 0;
	mbcast_sched_node_t *sched;
	cvmcs_nic_metadata_t *mdata = CVMCS_NIC_METADATA(wqe);

	DBG("%s:%d wqe=%016llx\n", __func__, __LINE__, (unsigned long long)wqe);

	if (OCTEON_IS_MODEL(OCTEON_CN66XX) || OCTEON_IS_MODEL(OCTEON_CN68XX)) {
		if (CVMCS_NIC_METADATA_IS_PACKET_FROM_DPI(mdata)) {
			if (cvmcs_nic_forward_packet_to_wire(wqe, flags)) {
				/*In this case the WQE is Already Freed
 				 * so no need to free again
 				 */
				//cvm_free_wqe_wrapper(wqe);
				return -ENOIF;
			}
		} else {
			for (i = 0; i <= mdata->dest_ifl.last; i++) {
				if (iflist_on(&mdata->dest_ifl, i) &&
				    octnic->port[i].state.active &&
				    octnic->port[i].state.rx_on) {
					if (cvmcs_nic_process_wqe_ifidx(wqe, i, flags)) {
						cvm_free_wqe_wrapper(wqe);
						return -ENOIF;
					}
				}
			}
		}

		return 0;
	}

	/* Allocate an FAU for dealing with completion of all the responses. */
	sched = cvmx_fpa_alloc(CVMX_FPA_PACKET_POOL);
	if (!sched) {
		DBG("%s: Out of FPA Packet pool\n", __func__);
		cvm_free_wqe_wrapper(wqe);
		return -ENOMEM;
	}

	memset(sched, 0, sizeof(mbcast_sched_node_t));
	mdata->wqe_ref_count = &sched->subone;

	/* The PKO is told to subtract one from the new FAU register
	 * after it is sent.
	 * They also will not free any associated buffers since we
	 * are re-using them.
	 */
	flags.s.subone1 = 1;
	flags.s.dontfree = 1;

	mdata->next_wqe = NULL;

	/* The original WQE is at the tail of the list and will be freed when
         * the list is freed.
	 */
	prev_wqe = wqe;

	for (i = 0; i <= mdata->dest_ifl.last; i++) {
		if (iflist_on(&mdata->dest_ifl, i) && (i != mdata->from_ifidx) && octnic->port[i].state.active && octnic->port[i].state.rx_on) {
			new_wqe = cvmcs_nic_dup_wqe(wqe);

			if (new_wqe) {
				cvmx_atomic_add64(&sched->subone, 1);
				CVMCS_NIC_METADATA(new_wqe)->wqe_ref_count =  mdata->wqe_ref_count;
				if (cvmcs_nic_process_wqe_ifidx(new_wqe, i, flags)) {
                                	/* Did not send for some reason.
                                	 * Subtract from the fau, and free the new wqe
                                	*/
                                	cvmx_atomic_add64(&sched->subone, -1);
                                	cvmcs_wqe_free(new_wqe);
				} else {
				
					/* Sent properly. Put the new WQE on the head of
					 * the list. The port really only needs to be in
					 * the original wqe, but only after
					 * it has been sent to the PKO.
					 */
					sent_cnt++;
					CVMCS_NIC_METADATA(new_wqe)->next_wqe = prev_wqe;
					DBG("Sent! send_cnt=%d ifidx=%d prev=%016llx head=%016llx\n",
						sent_cnt, i,
						(unsigned long long)prev_wqe,
						(unsigned long long)new_wqe);
					prev_wqe = new_wqe;
				}
			}
		}
	}

	if (CVMCS_NIC_METADATA_IS_PACKET_FROM_DPI(mdata)) {

		new_wqe = cvmcs_nic_dup_wqe(wqe);

		if (new_wqe) {

			CVMCS_NIC_METADATA(new_wqe)->wqe_ref_count =  mdata->wqe_ref_count;
			cvmx_atomic_add64(&sched->subone, 1);

			if ((sent_cnt > 0) && CVMCS_NIC_METADATA_VLAN_TCI(mdata)) {
				/* vlan tag is going to be inserted into first buffer
				 * which will affect the packets sent to dpi ports above
                                 * duplicate first buffer. We can use the buffer allocated 
     				 * for sched for this purpose
				 */
				cvmcs_nic_dup_first_buffer(new_wqe, sched);
			}

			if (cvmcs_nic_forward_packet_to_wire(new_wqe, flags)) {
                                /* Did not send for some reason.
                                 * Subtract from the fau, and free the new wqe
                                 */
                                cvmx_atomic_add64(&sched->subone, -1);
                                cvmcs_wqe_free(new_wqe);
			} else {

				/* Sent properly. Put the new WQE on the head of
				 * the list. The port really only needs to be in
				 * the original wqe, but only after
				 * it has been sent to the PKO.
				 */
				sent_cnt++;
				CVMCS_NIC_METADATA(new_wqe)->next_wqe = prev_wqe;
				DBG("Sent! send_cnt=%d ifidx=%d prev=%016llx head=%016llx\n",
					sent_cnt, -1,
					(unsigned long long)prev_wqe,
					(unsigned long long)new_wqe);
				prev_wqe = new_wqe;
			}
		}
	}

	if (sent_cnt) {
		/* Schedule work to clean up the buffers after they are all
		 * sent. prev_wqe is the head of the list of WQEs we sent.
		 */
		sched->head = prev_wqe;

		cvmx_spinlock_lock(&mbcast_list->lock);
		cavium_list_add_head(&sched->list, &mbcast_list->list);
		mbcast_list->count++;
		cvmx_spinlock_unlock(&mbcast_list->lock);

	} else {
		/* If we didn't actually send any, we must free the FAU and
		 * original WQE and buffers.
		 */
		cvmx_fpa_free(sched, CVMX_FPA_PACKET_POOL, 0);
		cvm_free_wqe_wrapper(wqe);
		return -ENOIF;
	}

	return 0;
}


int cvmcs_nic_switch_packets_from_gmx(cvmx_wqe_t *wqe)
{
	int ret = 0;
	int ifidx;
	pkt_proc_flags_t flags = {.u=0,};

#if defined (OVS_IPSEC) || defined (LINUX_IPSEC)
        cvmcs_nic_metadata_t *mdata = CVMCS_NIC_METADATA(wqe);
#endif

	flags.s.csum_verified = verify_csum(wqe);

	if (cvmcs_nic_tunnel_is_loopback_port(wqe)) {
		ifidx = cvmcs_nic_tunnel_verify_cksum(&wqe, &flags);
		cvmcs_nic_mdata_tunnel_update_metadata(wqe);
	} else if (cvmcs_nic_is_ipsec_loopback_port(wqe)) {
		return process_ipsec_loopback_pkt(wqe);
	} else {
#if defined (OVS_IPSEC) || defined (LINUX_IPSEC)
       if (!CVMCS_NIC_METADATA_IS_MDATA_INIT(mdata))
            cvmcs_nic_mdata_init_metadata(wqe);
#else
		cvmcs_nic_mdata_init_metadata(wqe);
#endif
		if (!cvmcs_dcb_gmx_wqe_handler(wqe))
			return 0;
#ifdef FLOW_ENGINE
		return (cvmcs_cfe_handle_uplink_traffic(wqe));
#else
		ifidx = cvmcs_nic_get_ifidx_list(wqe, 0);
#endif	
	}


	cvmcs_profile_mark_event(PROF_RX_GET_IFIDX);

	DBG("PktWQE @ %p ipprt: %d ifidx: %d bufs: %d len: %d\n",
	    wqe, cvmx_wqe_get_port(wqe), ifidx, cvmx_wqe_get_bufs(wqe),
	    cvmx_wqe_get_len(wqe));

	if (cvmx_likely(ifidx >= 0)) {
		/* unicast case */
		ret = cvmcs_nic_process_wqe_ifidx(wqe, ifidx, flags);
	} else if (ifidx == -ENOIF) {
		/* No stats to peg since there is no interface */
		DBG("No NIC idx for WQE@%p from ipprt: %d bufs: %d len: %d\n",
		     wqe, cvmx_wqe_get_port(wqe), cvmx_wqe_get_bufs(wqe),
		     cvmx_wqe_get_len(wqe));
		DBG_print_wqe(wqe);

		cvm_free_wqe_wrapper(wqe);
		return -ENOIF;
	} else if (ifidx == -EMBCAST) {
		/* mcast/bcast case */
		ret = cvmcs_nic_process_wqe_mbcast(wqe, flags);
	}

	cvmcs_profile_mark_event(PROF_RX_DONE);

	return ret;
}

int cvmcs_nic_switch_packets_from_dpi(cvmx_wqe_t *wqe)
{
	int ifidx;
	pkt_proc_flags_t flags = {.u=0,};
	cvmcs_nic_metadata_t *mdata = CVMCS_NIC_METADATA(wqe);
	int from_ifidx;

/* Implementation Note: for 'LINUX_IPSEC', metadata initialization occurred in
 * 'ipsec_process_host_packet()' (see cvmcs_nic_component_host_packet()). */
#ifndef LINUX_IPSEC
	cvmcs_nic_mdata_init_metadata(wqe);
#endif

	/* per bug 20952, check for DPI PKI errors on 78xx */
	if (octeon_has_feature(OCTEON_FEATURE_CN78XX_WQE)) {
		cvmx_wqe_78xx_t *wqe78xx = (cvmx_wqe_78xx_t *)wqe;
		if (cvmx_unlikely((wqe78xx->word2.err_level == CVMX_PKI_ERRLEV_E_RE) &&
					(wqe78xx->word2.err_code != 0))) {
			/* drop ANY PKI/DPI error packets */
			printf("DPI PKI error from port %d. Error code=%x, mdata->from_ifidx %u\n",
			    cvmx_wqe_get_port(wqe), wqe78xx->word2.err_code, mdata->from_ifidx);
			cvmcs_cond_free_wqe(wqe);

			if (mdata->from_ifidx >= 0) {
				per_core_stats[core_id].link_stats[mdata->from_ifidx].fromhost.fw_err_pki += 1;
			}

			return -EBADPACKET;
		}
	}

	from_ifidx = mdata->from_ifidx;

	if (octnic->port[from_ifidx].linfo.macaddr_spoofchk) {
		/* check source mac address */
		int retval=0;

		cvmcs_nic_metadata_t *mdata = CVMCS_NIC_METADATA(wqe);
		struct ethhdr *eth = (struct ethhdr *)CVMCS_NIC_METADATA_PACKET_START(mdata);
		retval =  memcmp(&eth->h_source, ((u8 *)&octnic->port[from_ifidx].user_set_macaddr + 2), ETH_ALEN);

		if (retval != 0) {
			/* u64 smac=0;
			   memcpy(&smac, &eth->h_source, ETH_ALEN);
			   printf("spoof src mac detected: cvmcs_nic_switch_packets_from_dpi: from_ifidx=%d, smac=%lx, mymac=%lx\n",
				from_ifidx, smac, octnic->port[from_ifidx].user_set_macaddr);
			 */

			cvmcs_cond_free_wqe(wqe);
			per_core_stats[cvmx_get_core_num()].link_stats[mdata->from_ifidx].fromhost.fw_err_drop += 1;
			per_core_stats[cvmx_get_core_num()].vf_stats[mdata->from_ifidx].spoofmac_cnt += 1;

			return -EBADPACKET;
		}
	}

	ifidx = cvmcs_nic_get_ifidx_list(wqe, 1);

	if (ifidx == -ENOIF) {
		/* Packet is not for any one of internal ports.
		 * Send it to gmx port.
		 */
		return cvmcs_nic_forward_packet_to_wire(wqe, flags);
	}

	if (ifidx == -EMBCAST) {
		/* Packet is multicast or boradcast packet
		 * Send it to internal and external ports.
		 */
		return cvmcs_nic_process_wqe_mbcast(wqe, flags);
	}

	if (ifidx == -EBADPACKET) {
		cvmcs_cond_free_wqe(wqe);
		return -EBADPACKET;
	}

	return cvmcs_nic_process_wqe_ifidx(wqe, ifidx, flags);
}
