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
#ifndef _CVMCS_IP_H_
#define _CVMCS_IP_H_

/* IP flags. */
#define IP_CE       0x8000	/* Flag: "Congestion"       */
#define IP_DF       0x4000	/* Flag: "Don't Fragment"   */
#define IP_MF       0x2000	/* Flag: "More Fragments"   */
#define IP_OFFSET   0x1FFF	/* "Fragment Offset" part   */

/* Standard well-defined IP protocols.  */
enum {
	IPPROTO_IP = 0,		/* Dummy protocol for TCP       */
	IPPROTO_ICMP = 1,	/* Internet Control Message Protocol    */
	IPPROTO_IGMP = 2,	/* Internet Group Management Protocol   */
	IPPROTO_IPIP = 4,	/* IPIP tunnels (older KA9Q tunnels use 94) */
	IPPROTO_TCP = 6,	/* Transmission Control Protocol    */
	IPPROTO_EGP = 8,	/* Exterior Gateway Protocol        */
	IPPROTO_PUP = 12,	/* PUP protocol             */
	IPPROTO_UDP = 17,	/* User Datagram Protocol       */
	IPPROTO_IDP = 22,	/* XNS IDP protocol         */
	IPPROTO_DCCP = 33,	/* Datagram Congestion Control Protocol */
	IPPROTO_RSVP = 46,	/* RSVP protocol            */
	IPPROTO_GRE = 47,	/* Cisco GRE tunnels (rfc 1701,1702)    */

	IPPROTO_IPV6 = 41,	/* IPv6-in-IPv4 tunnelling      */

	IPPROTO_ESP = 50,	/* Encapsulation Security Payload protocol */
	IPPROTO_AH = 51,	/* Authentication Header protocol       */
	IPPROTO_ICMPV6 = 58,	/* Internet Control Message Protocol V6   */
	IPPROTO_BEETPH = 94,	/* IP option pseudo header for BEET */
	IPPROTO_PIM = 103,	/* Protocol Independent Multicast   */

	IPPROTO_COMP = 108,	/* Compression Header protocol */
	IPPROTO_SCTP = 132,	/* Stream Control Transport Protocol    */
	IPPROTO_UDPLITE = 136,	/* UDP-Lite (RFC 3828)          */

	IPPROTO_RAW = 255,	/* Raw IP packets           */
	IPPROTO_MAX
};

/* IPv6 extension header types */
enum {
	IPV6_EXTH_HOH = 0,	/* Hop-by-Hop Options */
	IPV6_EXTH_TCP = 6,	/* TCP */
	IPV6_EXTH_UDP = 17,	/* UDP */
	IPV6_EXTH_ROUTING = 43,	/* Routing Header */
	IPV6_EXTH_FRAG = 44,	/* Fragment header */
	IPV6_EXTH_GRE = 47,	/* GRE */
	IPV6_EXTH_ESP = 50,	/* Encapsulation security payload Header */
	IPV6_EXTH_AH = 51,	/* Authentication Header */
	IPV6_EXTH_ICMP = 58,	/* ICMPv6 */
	IPV6_EXTH_NNH = 59,	/* No Next header */
	IPV6_EXTH_DEST_OPT = 60,/* Destination Options */
	IPV6_EXTH_MOBILITY = 135,/* Mobility Header */
	IPV6_EXTH_HIP = 139,	/* Host Identity Protocol */
	IPV6_EXTH_SHIM = 140,	/* Shim6 protocol */
	IPV6_EXTH_EXP1 = 253,	/* Experimental and Testing */
	IPV6_EXTH_EXP2 = 254	/* Experimental and Testing */
};

struct iphdr {
#if defined(__LITTLE_ENDIAN_BITFIELD)
	uint8_t ihl:4, version:4;
#else
	uint8_t version:4, ihl:4;
#endif
	uint8_t tos;
	uint16_t tot_len;
	uint16_t id;
	uint16_t frag_off;
	uint8_t ttl;
	uint8_t protocol;
	uint16_t check;
	uint32_t saddr;
	uint32_t daddr;
	/*The options start here. */
};

#endif	/* _CVMCS_IP_H */
