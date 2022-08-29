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
#ifndef _CVMCS_IPV6_H_
#define _CVMCS_IPV6_H_

/*
 * fragmentation header
 */
struct ipv6_frag_hdr {
	uint8_t                 nexthdr;
	uint8_t                 reserved;
	uint16_t                frag_off;
	uint32_t                identification;
};

struct ipv6_opt_hdr {
        uint8_t            nexthdr;
        uint8_t            hdrlen;
        /* 
	 * TLV encoded option data follows.
	 */
} __attribute__ ((packed));     /* required for some archs */

struct in6_addr {
	union {
		uint8_t         u6_addr8[16];
		uint16_t        u6_addr16[8];
		uint32_t        u6_addr32[4];
		uint64_t        u6_addr64[2];
	} in6_u;
#define s6_addr                 in6_u.u6_addr8
#define s6_addr16               in6_u.u6_addr16
#define s6_addr32               in6_u.u6_addr32
#define s6_addr64               in6_u.u6_addr64
};

struct ipv6hdr {
#if defined(__LITTLE_ENDIAN_BITFIELD)
	uint8_t                 priority:4,
	version:4;
#else
	uint8_t                 version:4,
				priority:4;
#endif
	uint8_t                 flow_lbl[3];

	uint16_t                payload_len;
	uint8_t                 nexthdr;
	uint8_t                 hop_limit;

	struct  in6_addr        saddr;
	struct  in6_addr        daddr;
};

/* IPv6 Extentsion header macros */


/*
 *      IPv6 TLV options.
 */

#define IPV6_TLV_PAD1           0
#define IPV6_TLV_PADN           1
#define IPV6_TLV_ROUTERALERT    5
#define IPV6_TLV_JUMBO          194
#define IPV6_TLV_HAO            201     /* home address option */


#define CVM_IPV6_NEXTHDR_HOP             0       /* Hop-by-hop option header. */
#define CVM_IPV6_NEXTHDR_TCP             6       /* TCP segment. */
#define CVM_IPV6_NEXTHDR_UDP             17      /* UDP message. */
#define CVM_IPV6_NEXTHDR_IPV6            41      /* IPv6 in IPv6 */
#define CVM_IPV6_NEXTHDR_ROUTING         43      /* Routing header. */
#define CVM_IPV6_NEXTHDR_FRAGMENT        44      /* Fragmentation/reassembly header. */
#define CVM_IPV6_NEXTHDR_GRE             47      /* GRE header. */
#define CVM_IPV6_NEXTHDR_ESP             50      /* Encapsulating security payload. */
#define CVM_IPV6_NEXTHDR_AUTH            51      /* Authentication header. */
#define CVM_IPV6_NEXTHDR_ICMP            58      /* ICMP for IPv6. */
#define CVM_IPV6_NEXTHDR_NONE            59      /* No next header */
#define CVM_IPV6_NEXTHDR_DEST            60      /* Destination options header. */
#define CVM_IPV6_NEXTHDR_MOBILITY        135     /* Mobility header. */
#define CVM_IPV6_NEXTHDR_MLD             143     /* MLDv2 */

#define CVM_IPV6_NEXTHDR_MAX             255

#endif  //_CVMCS_IPV6_H_
