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
#ifndef CVMCS_NIC_TUNNEL_H
#define CVMCS_NIC_TUNNEL_H

#define NO_TXL4 0x2
#define CVM_PHYS_LOOPBACK_PORT 36
#define VTEP_UDP_SERVER_PORT1 4789
#define GENEVE_DST_PORT 6081
#define CVM_PHYS_78XX_LOOPBACK_PORT 0x000

#define GENEVE_VER 0
#define GOOD_CHECKSUM 1
#define BAD_CHECKSUM  2

typedef struct gre_cksum_hdr {
	uint16_t	cksum;
	uint16_t	offset;
} gre_cksum_hdr_t;

typedef struct gre_key_hdr {
	uint32_t	key;
} gre_key_hdr_t;

typedef struct gre_seq_num_hdr {
	uint32_t	seq_num;
} gre_seq_num_hdr_t;

typedef struct gre_routing_hdr {
	uint32_t	route;
} gre_routing_hdr_t;

typedef struct gre_hdr {
	uint8_t		C:1,
			R:1,
			K:1,
			S:1,
			s:1,
			rec_ctl:3;

	uint8_t		flags:5,
			ver:3;
	uint16_t	proto_type;
} gre_hdr_t;

/* VXLAN protocol header */
struct vxlanhdr {
	uint32_t vx_flags;
	uint32_t vx_vni;
};

typedef struct cvmcs_tunnel_front {
	union {
		cvm_pci_pki_ih3_t 	ih3;
		cvm_pci_inst_hdr2_t 	ih2;
		struct {
			uint16_t	ih;
			uint16_t	outer_flags;
			uint16_t	ifidx;
			uint16_t	reserved;
		} s;
	};
	cvmx_wqe_t	*wqe;
} cvmcs_tunnel_front_t;


struct genevehdr {
	uint8_t ver:2;
	uint8_t opt_len:6;
	uint8_t oam:1;
	uint8_t critical:1;
	uint8_t rsvd1:6;
	uint16_t proto_type;
	uint8_t vni[3];
	uint8_t rsvd2;
	uint8_t options[];
};

int cvmcs_nic_tunnel_is_loopback_port(cvmx_wqe_t *wqe);
void cvmcs_nic_tunnel_loopback_port_init(void);
void cvmcs_nic_tunnel_ip_offset(cvmx_wqe_t *wqe, short *offload);
int cvmcs_nic_tunnel_verify_cksum(cvmx_wqe_t **wqe, pkt_proc_flags_t *flags);
int cvmcs_nic_tunnel_calculate_cksum(cvmx_wqe_t *wqe, int ifidx, pkt_proc_flags_t *flags);
int cvmcs_nic_78xx_tunnel_calculate_cksum(cvmx_wqe_t *wqe, int ifidx, pkt_proc_flags_t *flags);

#endif
