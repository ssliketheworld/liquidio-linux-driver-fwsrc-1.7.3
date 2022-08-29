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

#ifndef __CVMCS_NIC_MDATA_H__
#define __CVMCS_NIC_MDATA_H__

/* Metadata flags */
#define METADATA_FLAGS_IPSEC_OP			0x00000001
#define METADATA_FLAGS_IPSEC_AH			0x00000002
#define METADATA_FLAGS_IPSEC_ESP		0x00000004
#define METADATA_FLAGS_IPSEC_TUNNEL		0x00000008
#define METADATA_FLAGS_IPSEC_FRAG		0x00000010
#define METADATA_FLAGS_TUNNEL			0x00000020
#define METADATA_FLAGS_ENCAP_ON			0x00000040
#define METADATA_FLAGS_VLAN			0x00000080
#define METADATA_FLAGS_IPV4			0x00000100
#define METADATA_FLAGS_IPV6			0x00000200
#define METADATA_FLAGS_GRE			0x00000400
#define METADATA_FLAGS_TCP			0x00000800
#define METADATA_FLAGS_UDP			0x00001000
#define METADATA_FLAGS_SCTP			0x00002000
#define METADATA_FLAGS_IP_FRAG			0x00004000
#define METADATA_FLAGS_IP_OPTS_OR_EXTH		0x00008000
#define METADATA_FLAGS_INNER_VLAN		0x00010000
#define METADATA_FLAGS_INNER_IPV4		0x00020000
#define METADATA_FLAGS_INNER_IPV6		0x00040000
#define METADATA_FLAGS_INNER_TCP		0x00080000
#define METADATA_FLAGS_INNER_UDP		0x00100000
#define METADATA_FLAGS_INNER_SCTP		0x00200000
#define METADATA_FLAGS_INNER_IP_FRAG		0x00400000
#define METADATA_FLAGS_INNER_IP_OPTS_OR_EXTH	0x00800000
#define METADATA_FLAGS_CSUM_L3			0x01000000
#define METADATA_FLAGS_CSUM_L4			0x02000000
#define METADATA_FLAGS_CSUM_INNER_L3		0x04000000
#define METADATA_FLAGS_CSUM_INNER_L4		0x08000000
#define METADATA_FLAGS_TCP_SYN			0x10000000
#if defined (OVS_IPSEC) || defined (LINUX_IPSEC)
#define METADATA_FLAGS_MDATA_INIT		0x20000000
#endif
#define METADATA_FLAGS_PTP_HEADER		0x40000000
#define METADATA_FLAGS_DUP_WQE			0x80000000

/* port types */
#define METADATA_PORT_NONE	0
#define METADATA_PORT_GMX	1
#define METADATA_PORT_DPI	2
#define METADATA_PORT_LOOP	3

typedef struct cvmcs_nic_metadata {
	/* front should be the first filed. Please don't move */
	cvmx_raw_inst_front_t		front;
	uint8_t				*packet_start;
	int16_t				from_port;
	int16_t				gmx_port; 
	int8_t				front_size;
	int8_t				from_interface;
	int8_t				gmx_id;
	int8_t                          reserved1;
	struct ifidx_list		dest_ifl;
	int16_t                         from_ifidx;
	uint16_t			header_len;
	uint32_t			flags;
	uint16_t			outer_l2offset;
	uint16_t			outer_l3offset;
	uint16_t			outer_l4offset;
	uint16_t			outer_vlanTCI;
	uint16_t			inner_l2offset;
	uint16_t			inner_l3offset;
	uint16_t			inner_l4offset;
	uint16_t			inner_vlanTCI;
	uint16_t			ipsec_l2proto;
	uint16_t			ipsec_l3offset;
        uint16_t 			ipsec_esp_ah_offset;
        uint16_t 			ipsec_esp_ah_hdrlen;
	uint8_t				ipsec_esp_pad_len;
	uint8_t				ipsec_next_proto;
	uint8_t				ipsec_esp_icv_len;
	uint8_t				reserved3;
#ifdef VSWITCH
	int16_t                         to_ifidx;
	uint16_t			fw_crc;
#else
	uint16_t			reserved4[2];
#endif
/* Note: In ipsec git, reserved4 is used for ipsec_mark. 
 * Due to conflict , using reserved5 here. 
 * Need to address it and make it common 
 */
#ifdef LINUX_IPSEC
	uint32_t			ipsec_mark;
	uint32_t			reserved5;
#else
	uint64_t			reserved5;
#endif
	int64_t				*wqe_ref_count;
	cvmx_wqe_t			*next_wqe;
	/* Please do not change the following fields */
	uint64_t			next_buf_ptr;
	union {
		union octeon_rh		rh;
		cvm_pci_inst_hdr2_t	ih2;
		cvm_pci_pki_ih3_t	ih3;
	};
	uint64_t			rss_hash;
} cvmcs_nic_metadata_t;

#define CVMCS_NIC_METADATA_SIZE sizeof(cvmcs_nic_metadata_t)

static inline cvmcs_nic_metadata_t *CVMCS_NIC_METADATA(cvmx_wqe_t *wqe)
{
	if (octeon_has_feature(OCTEON_FEATURE_CN78XX_WQE)) {
		/*  We dont start metadata in wqe_data[0]. We can use wqe_data[0]
                 *  to link buffers, if front_data need to be included back in cases
                 *  like tso_completion
		 */
		return 	((cvmcs_nic_metadata_t *)&((cvmx_wqe_78xx_t *)wqe)->wqe_data[1]);
	} else {
		return 	((cvmcs_nic_metadata_t *)wqe->packet_data);
	}
}

#define CVMCS_NIC_METADATA_WQE_SIZE			\
	(uint32_t)(uint64_t)((int8_t *)CVMCS_NIC_METADATA(0) + CVMCS_NIC_METADATA_SIZE)

#define CVMCS_NIC_METADATA_IS_PACKET_FROM_GMX(mdata) \
	(mdata->from_interface == METADATA_PORT_GMX)

#define CVMCS_NIC_METADATA_IS_PACKET_FROM_DPI(mdata) \
	(mdata->from_interface == METADATA_PORT_DPI)

#define CVMCS_NIC_METADATA_IS_PACKET_FROM_LOOP_BACK(mdata) \
	(mdata->from_interface == METADATA_PORT_LOOP)

#define	CVMCS_NIC_METADATA_PACKET_START(mdata)		(mdata->packet_start)

#define	CVMCS_NIC_METADATA_HEADER_LENGTH(mdata)		(mdata->header_len)

#define	CVMCS_NIC_METADATA_L2_OFFSET(mdata)		(mdata->outer_l2offset)

#define	CVMCS_NIC_METADATA_L2_HEADER(mdata)		\
	(mdata->packet_start + mdata->outer_l2offset)

#define	CVMCS_NIC_METADATA_L3_OFFSET(mdata)		(mdata->outer_l3offset)

#define	CVMCS_NIC_METADATA_L3_HEADER(mdata)		\
	(mdata->packet_start + mdata->outer_l3offset)

#define	CVMCS_NIC_METADATA_L4_OFFSET(mdata)		(mdata->outer_l4offset)

#define	CVMCS_NIC_METADATA_L4_HEADER(mdata)		\
	(mdata->packet_start + mdata->outer_l4offset)

#define	CVMCS_NIC_METADATA_VLAN_TCI(mdata)		(mdata->outer_vlanTCI)

#define	CVMCS_NIC_METADATA_VLAN_ID(mdata)		(mdata->outer_vlanTCI & 0xfff)

#define	CVMCS_NIC_METADATA_PRIORITY(mdata)		(mdata->outer_vlanTCI >> 13)

#define	CVMCS_NIC_METADATA_INNER_L2_OFFSET(mdata)	(mdata->inner_l2offset)

#define	CVMCS_NIC_METADATA_INNER_L2_HEADER(mdata)	\
	(mdata->packet_start + mdata->inner_l2offset)

#define	CVMCS_NIC_METADATA_INNER_L3_OFFSET(mdata)	(mdata->inner_l3offset)

#define	CVMCS_NIC_METADATA_INNER_L3_HEADER(mdata)	\
	(mdata->packet_start + mdata->inner_l3offset)

#define	CVMCS_NIC_METADATA_INNER_L4_OFFSET(mdata)	(mdata->inner_l4offset)

#define	CVMCS_NIC_METADATA_INNER_L4_HEADER(mdata)	\
	(mdata->packet_start + mdata->inner_l4offset)

#define	CVMCS_NIC_METADATA_INNER_VLAN_TCI(mdata)	(mdata->inner_vlanTCI)

#define	CVMCS_NIC_METADATA_INNER_VLAN_ID(mdata)		(mdata->inner_vlanTCI & 0xfff)

#define	CVMCS_NIC_METADATA_INNER_PRIORITY(mdata)	(mdata->inner_vlanTCI >> 13)

#define	CVMCS_NIC_METADATA_TUNNEL_HEADER_LENGTH(mdata)	(mdata->inner_l2offset)

#define	CVMCS_NIC_METADATA_IPSEC_L2PROTO(mdata)	(mdata->ipsec_l2proto)

#define	CVMCS_NIC_METADATA_IPSEC_L3OFFSET(mdata)	(mdata->ipsec_l3offset)

#define	CVMCS_NIC_METADATA_IPSEC_L3_HEADER(mdata)		\
	(mdata->packet_start + mdata->ipsec_l3offset)

#define	CVMCS_NIC_METADATA_IPSEC_ESP_AH_OFFSET(mdata)	(mdata->ipsec_esp_ah_offset)

#define	CVMCS_NIC_METADATA_IPSEC_ESP_AH_HEADER(mdata)		\
	(mdata->packet_start + mdata->ipsec_esp_ah_offset)

#define	CVMCS_NIC_METADATA_IPSEC_ESP_AH_HDRLEN(mdata)	(mdata->ipsec_esp_ah_hdrlen)

#define CVMCS_NIC_METADATA_IPSEC_ESP_PAD_LEN(mdata)	(mdata->ipsec_esp_pad_len)

#define	CVMCS_NIC_METADATA_IPSEC_NEXT_PROTO(mdata)	(mdata->ipsec_next_proto)

#define	CVMCS_NIC_METADATA_IPSEC_ESP_ICV_LEN(mdata)	(mdata->ipsec_esp_icv_len)

#define CVMCS_NIC_METADATA_IPSEC_TCP_TRNS_OFFSET(mdata) \
	(mdata->ipsec_esp_ah_offset + mdata->ipsec_esp_ah_hdrlen)

#define CVMCS_NIC_METADATA_IS_IPSEC_OP(mdata) \
	((mdata->flags & METADATA_FLAGS_IPSEC_OP) == METADATA_FLAGS_IPSEC_OP)

#define CVMCS_NIC_METADATA_IS_IPSEC_AH(mdata) \
	((mdata->flags & METADATA_FLAGS_IPSEC_AH) == METADATA_FLAGS_IPSEC_AH)

#define CVMCS_NIC_METADATA_IS_IPSEC_ESP(mdata) \
	((mdata->flags & METADATA_FLAGS_IPSEC_ESP) == METADATA_FLAGS_IPSEC_ESP)

#define CVMCS_NIC_METADATA_IS_IPSEC(mdata) \
	(CVMCS_NIC_METADATA_IS_IPSEC_AH(mdata) || CVMCS_NIC_METADATA_IS_IPSEC_ESP(mdata))

#define CVMCS_NIC_METADATA_IS_IPSEC_TUNNEL(mdata) \
	((mdata->flags & METADATA_FLAGS_IPSEC_TUNNEL) == METADATA_FLAGS_IPSEC_TUNNEL)

#define CVMCS_NIC_METADATA_IS_TUNNEL(mdata) \
	((mdata->flags & METADATA_FLAGS_TUNNEL) == METADATA_FLAGS_TUNNEL)

#define CVMCS_NIC_METADATA_IS_IPSEC_FRAG(mdata) \
	((mdata->flags & METADATA_FLAGS_IPSEC_FRAG) == METADATA_FLAGS_IPSEC_FRAG)

#define CVMCS_NIC_METADATA_IS_ENCAP_ON(mdata) \
	((mdata->flags & METADATA_FLAGS_ENCAP_ON) == METADATA_FLAGS_ENCAP_ON)

#define CVMCS_NIC_METADATA_IS_VLAN(mdata) \
	((mdata->flags & METADATA_FLAGS_VLAN) == METADATA_FLAGS_VLAN)

#define CVMCS_NIC_METADATA_IS_IPV4(mdata) \
	((mdata->flags & METADATA_FLAGS_IPV4) == METADATA_FLAGS_IPV4)

#define CVMCS_NIC_METADATA_IS_IPV6(mdata) \
	((mdata->flags & METADATA_FLAGS_IPV6) == METADATA_FLAGS_IPV6)

#define CVMCS_NIC_METADATA_IS_GRE(mdata) \
	((mdata->flags & METADATA_FLAGS_GRE) == METADATA_FLAGS_GRE)

#define CVMCS_NIC_METADATA_IS_TCP(mdata) \
	((mdata->flags & METADATA_FLAGS_TCP) == METADATA_FLAGS_TCP)

#define CVMCS_NIC_METADATA_IS_TCP_SYN(mdata) \
	(mdata->flags & METADATA_FLAGS_TCP_SYN)

#define CVMCS_NIC_METADATA_IS_UDP(mdata) \
	((mdata->flags & METADATA_FLAGS_UDP) == METADATA_FLAGS_UDP)

#define CVMCS_NIC_METADATA_IS_SCTP(mdata) \
	((mdata->flags & METADATA_FLAGS_SCTP) == METADATA_FLAGS_SCTP)

#define CVMCS_NIC_METADATA_IS_INNER_VLAN(mdata) \
	((mdata->flags & METADATA_FLAGS_INNER_VLAN) == METADATA_FLAGS_INNER_VLAN)

#define CVMCS_NIC_METADATA_IS_IP_FRAG(mdata) \
	((mdata->flags & METADATA_FLAGS_IP_FRAG) == METADATA_FLAGS_IP_FRAG)

#define CVMCS_NIC_METADATA_IS_IP_OPTS_OR_EXTH(mdata) \
	((mdata->flags & METADATA_FLAGS_IP_OPTS_OR_EXTH) == METADATA_FLAGS_IP_OPTS_OR_EXTH)

#define CVMCS_NIC_METADATA_IS_INNER_IPV4(mdata) \
	((mdata->flags & METADATA_FLAGS_INNER_IPV4) == METADATA_FLAGS_INNER_IPV4)


#define CVMCS_NIC_METADATA_IS_INNER_IPV6(mdata) \
	((mdata->flags & METADATA_FLAGS_INNER_IPV6) == METADATA_FLAGS_INNER_IPV6)

#define CVMCS_NIC_METADATA_IS_INNER_TCP(mdata) \
	((mdata->flags & METADATA_FLAGS_INNER_TCP) == METADATA_FLAGS_INNER_TCP)

#define CVMCS_NIC_METADATA_IS_INNER_UDP(mdata) \
	((mdata->flags & METADATA_FLAGS_INNER_UDP) == METADATA_FLAGS_INNER_UDP)

#define CVMCS_NIC_METADATA_IS_INNER_SCTP(mdata) \
	((mdata->flags & METADATA_FLAGS_INNER_SCTP) == METADATA_FLAGS_INNER_SCTP)

#define CVMCS_NIC_METADATA_IS_INNER_IP_FRAG(mdata) \
	((mdata->flags & METADATA_FLAGS_INNER_IP_FRAG) == METADATA_FLAGS_INNER_IP_FRAG)

#define CVMCS_NIC_METADATA_IS_INNER_IP_OPTS_OR_EXTH(mdata) \
	((mdata->flags & METADATA_FLAGS_INNER_IP_OPTS_OR_EXTH) == METADATA_FLAGS_INNER_IP_OPTS_OR_EXTH)

#if defined  (OVS_IPSEC) || defined (LINUX_IPSEC)
#define CVMCS_NIC_METADATA_IS_MDATA_INIT(mdata) \
	((mdata->flags & METADATA_FLAGS_MDATA_INIT) == METADATA_FLAGS_MDATA_INIT)
#endif

#define CVMCS_NIC_METADATA_CSUM_L3(mdata) \
	((mdata->flags & METADATA_FLAGS_CSUM_L3) == METADATA_FLAGS_CSUM_L3)

#define CVMCS_NIC_METADATA_CSUM_L4(mdata) \
	((mdata->flags & METADATA_FLAGS_CSUM_L4) == METADATA_FLAGS_CSUM_L4)

#define CVMCS_NIC_METADATA_CSUM_INNER_L3(mdata) \
	((mdata->flags & METADATA_FLAGS_CSUM_INNER_L3) == METADATA_FLAGS_CSUM_INNER_L3)

#define CVMCS_NIC_METADATA_CSUM_INNER_L4(mdata) \
	((mdata->flags & METADATA_FLAGS_CSUM_INNER_L4) == METADATA_FLAGS_CSUM_INNER_L4)

#define CVMCS_NIC_METADATA_IS_PTP_HEADER(mdata) \
	((mdata->flags & METADATA_FLAGS_PTP_HEADER) == METADATA_FLAGS_PTP_HEADER)

#define CVMCS_NIC_METADATA_IS_DUP_WQE(mdata) \
	((mdata->flags & METADATA_FLAGS_DUP_WQE) == METADATA_FLAGS_DUP_WQE)

#ifdef VSWITCH
#define CVMCS_NIC_METADATA_FW_CRC(mdata)	(mdata->fw_crc)
#endif

int cvmcs_nic_mdata_init_metadata(cvmx_wqe_t *wqe);
int cvmcs_nic_mdata_tunnel_update_metadata(cvmx_wqe_t *wqe);
void cvmcs_nic_mdata_ipsec_update_metadata(cvmx_wqe_t *wqe, int ifidx);
void cvmcs_nic_mdata_parse_headers(cvmx_wqe_t *wqe, int ifidx);
void cvmcs_nic_insert_vlan_tag(cvmx_wqe_t *wqe);

#endif /*__CVMCS_NIC_MDATA_H__*/
