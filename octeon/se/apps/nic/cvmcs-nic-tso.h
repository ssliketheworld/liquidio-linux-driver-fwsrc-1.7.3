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

#ifndef __CVMCS_NIC_TSO_H__
#define __CVMCS_NIC_TSO_H__

typedef struct tso_hdr_info {
	bool is_vlan;
	bool is_v6;
	void *ethhdr;
	void *iphdr;
	void *tcp;
	uint8_t ip_offset;
	uint8_t tcp_offset;
	uint16_t hdr_len;
	uint16_t gso_size;
	uint16_t gso_segs;
	uint16_t mss;
} tso_hdr_info_t;

//worst case assuming you have to insert aura hdr before every gather ptr
#define MAX_GATHER_BUFS_O3 7
#define MAX_PKO3_CMD_WORDS 15 //without send jmp
/* describes a single buffer along with this aura pki bufs dont carry aura info */
struct tso_o3_gather_buf {
	cvmx_pko_buf_ptr_t buf;
	int aura;
};

/* struct to store all the gather bufs of a packet */
struct tso_o3_pkt_desc {
	//max descs is 14 without jmp, discount for one aura per ptr
	//ext hdrs etc
	//array of gather buffers
	struct tso_o3_gather_buf g_bufs[MAX_GATHER_BUFS_O3];
	//number of buffers
	int nbufs;
};

#endif /*__CVMCS_NIC_TSO_H__*/
