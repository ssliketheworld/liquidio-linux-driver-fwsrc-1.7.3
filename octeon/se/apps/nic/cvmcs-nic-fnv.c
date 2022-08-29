/*
 * Author: Cavium, Inc.
 *
 * Copyright (c) 2017 Cavium, Inc. All rights reserved.
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
#include  <cvmx-tim.h>
#include "cvmcs-nic-ipv6.h"
#include "cvmcs-nic-ip.h"
#include "cvmcs-nic-fnv.h"
#include "cvmcs-nic-mdata.h"

static inline void
cvmcs_nic_fnv_hash(uint8_t *buf, uint32_t len, uint32_t *hash)
{
	while (len--) {
		(*hash) ^= (uint32_t)(*buf++);
#if 0
		(*hash) *= FNV_PRIME;
#else
		(*hash) += ((*hash) << 24) + ((*hash) << 8) +
			((*hash) << 7) + ((*hash) << 4) + ((*hash) << 1);
#endif
	}
}

int
cvmcs_nic_fnv_get_queue(cvmx_wqe_t *wqe, uint32_t *hash, int ifidx)
{
	struct iphdr *iph = NULL;
	struct ipv6hdr *ip6h = NULL;
	cvmcs_nic_metadata_t *mdata = CVMCS_NIC_METADATA(wqe);

	*hash = FNV_OFFSET_BASIS;

	cvmcs_nic_fnv_hash((uint8_t *)CVMCS_NIC_METADATA_L2_HEADER(mdata),
		ETH_ALEN * 2, hash);

	if (CVMCS_NIC_METADATA_IS_VLAN(mdata)) {
		cvmcs_nic_fnv_hash((uint8_t *)&CVMCS_NIC_METADATA_VLAN_TCI(mdata),
			2, hash);
	}

	if (CVMCS_NIC_METADATA_IS_IPV4(mdata)) {
		iph = (struct iphdr *)CVMCS_NIC_METADATA_L3_HEADER(mdata);
		cvmcs_nic_fnv_hash((uint8_t *)&iph->saddr, sizeof(iph->saddr), hash);
		cvmcs_nic_fnv_hash((uint8_t *)&iph->daddr, sizeof(iph->daddr), hash);
	} else {
		if (CVMCS_NIC_METADATA_IS_IPV6(mdata)) {
			ip6h = (struct ipv6hdr *)CVMCS_NIC_METADATA_L3_HEADER(mdata);
			cvmcs_nic_fnv_hash((uint8_t *)&ip6h->saddr,
				sizeof(ip6h->saddr), hash);
			cvmcs_nic_fnv_hash((uint8_t *)&ip6h->daddr,
				sizeof(ip6h->daddr), hash);
		} else {
			return ((*hash) % (octnic->port[ifidx].linfo.num_rxpciq)); 
		}
	}

	if (!CVMCS_NIC_METADATA_IS_IP_FRAG(mdata) &&
	    (CVMCS_NIC_METADATA_IS_TCP(mdata) || CVMCS_NIC_METADATA_IS_UDP(mdata) ||
	     CVMCS_NIC_METADATA_IS_SCTP(mdata))) {
		cvmcs_nic_fnv_hash((uint8_t *)CVMCS_NIC_METADATA_L4_HEADER(mdata),
			4, hash);
	}


	if (CVMCS_NIC_METADATA_IS_TUNNEL(mdata)) {
		cvmcs_nic_fnv_hash((uint8_t *)CVMCS_NIC_METADATA_INNER_L2_HEADER(mdata),
			ETH_ALEN * 2, hash);

		if (CVMCS_NIC_METADATA_IS_INNER_VLAN(mdata))
			cvmcs_nic_fnv_hash((uint8_t *)
				&CVMCS_NIC_METADATA_INNER_VLAN_TCI(mdata), 2, hash);

		if (CVMCS_NIC_METADATA_IS_INNER_IPV4(mdata)) {
			iph = (struct iphdr *)CVMCS_NIC_METADATA_INNER_L3_HEADER(mdata);
			cvmcs_nic_fnv_hash((uint8_t *)&iph->saddr,
				sizeof(iph->saddr), hash);
			cvmcs_nic_fnv_hash((uint8_t *)&iph->daddr,
				sizeof(iph->daddr), hash);
		} else {
			if (CVMCS_NIC_METADATA_IS_INNER_IPV6(mdata)) {
				ip6h = (struct ipv6hdr *)
					CVMCS_NIC_METADATA_INNER_L3_HEADER(mdata);
				cvmcs_nic_fnv_hash((uint8_t *)&ip6h->saddr,
					sizeof(ip6h->saddr), hash);
				cvmcs_nic_fnv_hash((uint8_t *)&ip6h->daddr,
					sizeof(ip6h->daddr), hash);
			} else {
				return ((*hash) % (octnic->port[ifidx].linfo.num_rxpciq)); 
			}
		}

		if (!CVMCS_NIC_METADATA_IS_INNER_IP_FRAG(mdata) &&
		    (CVMCS_NIC_METADATA_IS_INNER_TCP(mdata) ||
		     CVMCS_NIC_METADATA_IS_INNER_UDP(mdata) ||
		     CVMCS_NIC_METADATA_IS_INNER_SCTP(mdata))) {
			cvmcs_nic_fnv_hash((uint8_t *)
				CVMCS_NIC_METADATA_INNER_L4_HEADER(mdata), 4, hash);
		}
	}

	return ((*hash) % (octnic->port[ifidx].linfo.num_rxpciq)); 
}
