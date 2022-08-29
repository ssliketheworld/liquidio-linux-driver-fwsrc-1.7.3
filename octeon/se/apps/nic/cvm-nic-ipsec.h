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
#ifndef __CVM_NIC_IPSEC_H__
#define __CVM_NIC_IPSEC_H__

#include "cvmcs-common.h"
#include "cvmcs-nic.h"
#include "cvm-core-cap.h"

// IPSec internal opcodes
#define OUTBOUND_PROCESSING  0x10
#define INBOUND_PROCESSING   0x11

#define IPSEC_EXTRA_INPUT  20 //IPSEC 20 byte of extra input more than front

#define CVM_PHYS_LOOPBACK_IPSEC_PORT 39
#define CVM_PHYS_78XX_LOOPBACK_IPSEC_PORT 2 

/**
 * Next header type 
 */
#define   CVM_IPSEC_NH_IPV4       4         /**< IPv4 header */
#define   CVM_IPSEC_NH_TCP        6         /**< TCP header */
#define   CVM_IPSEC_NH_UDP        17        /**< UDP header */
#define   CVM_IPSEC_NH_IPV6       41        /**< IPv6 header */
#define   CVM_IPSEC_NH_ESP        50        /**< ESP header */
#define   CVM_IPSEC_NH_AH         51        /**< AH header */
#define   CVM_IPSEC_NH_IPCOMP     108       /**< Ipcomp header */
#define   CVM_IPSEC_NH_HOP        0         /**< Hop-by-hop option header */
#define   CVM_IPSEC_NH_ROUTING    43        /**< Routing header */
#define   CVM_IPSEC_NH_FRAGMENT   44        /**< Fragmentation/reassembly header */
#define   CVM_IPSEC_NH_NONE       59        /**< No next header */
#define   CVM_IPSEC_NH_DEST       60        /**< Destination options header */

typedef void * cvm_ipsec_sa_handle_t;           /**< SA handle */

/**
 * IPSec Tx Info
 **/
typedef union {
	uint32_t u32;
	struct {
#if __BYTE_ORDER == __BIG_ENDIAN
		uint32_t esp_hdr_offset:8;
		uint32_t ah_hdr_offset:8;
		uint32_t esp_pad_length:8;
		uint32_t esp_next_hdr:8;
#else
		uint32_t esp_next_hdr:8;
		uint32_t esp_pad_length:8;
		uint32_t ah_hdr_offset:8;
		uint32_t esp_hdr_offset:8;
#endif
	} s;
} ipsec_tx_info_t;

/**
 * IPSec Rx Info
 **/
typedef union {
	int32_t        u32;
	struct {
#if __BYTE_ORDER == __BIG_ENDIAN
		int32_t reserved:7;
		int32_t	esp_info_set:1;
		int32_t esp_next_hdr:8;
		int32_t esp_pad_length:8;
		int32_t status:8;
#else
		int32_t status:8;
		int32_t esp_pad_length:8;
		int32_t esp_next_hdr:8;
		int32_t	esp_info_set:1;
		int32_t reserved:7;
#endif
       } s;
} ipsec_rx_info_t;

/**
* IP packet info structure
*/
typedef struct {
   cvmx_pip_wqe_word2_t word2;                                /**< word 2 of the work queue entry */
} cvm_ipsec_packet_info;


/**
* Extra arguments for outbound IPsec processing
*/
typedef union {
   uint64_t u64;
   struct {
#if __BYTE_ORDER == __BIG_ENDIAN
      uint64_t dontfree                 : 1;                /**< dont free the buffers in case of frc_alloc is set */
      uint64_t no_nh                    : 1;                /**< Reserved */
      uint64_t gather                   : 1;                /**< Input packet is in gather mode */
      uint64_t copy_dscp                : 1;                /**< copy the dscp to the IP header */
      uint64_t flow                     :20;                /**< Flow label value (for IPv6) */
      uint64_t tos_tc                   : 8;                /**< TOS/Traffic class value to be copied to the IP header */
      uint64_t tfc_size                 :16;                /**< the amount of tfc padding to insert (tunnel mode only) */
      uint64_t sa_read_only             : 1;                /**< read only sa */
      uint64_t packet_iv                : 1;                /**< Reserved */
      uint64_t gre_bit                  : 1;                /**< Reserved */
      uint64_t single_sa                : 1;                /**< Reserved */
      uint64_t trailer_pre_formatted    : 1;                /**< if set don't add padding bytes */
      uint64_t copy_df                  : 1;                /**< copy the df bit */
      uint64_t df                       : 1;                /**< df bit to be copied */
      uint64_t frc_alloc                : 1;                /**< if set, allocate new buffers for the result; otherwise process in-place */
      uint64_t max_pre_exp              : 8;                /**< number of bytes available for header expansion. max_pre_exp+8 bytes must exist 
                                                                 in the first buffer to avoid allocating new buffer space for the packet */
#else
      uint64_t max_pre_exp              : 8;   
      uint64_t frc_alloc                : 1;   
      uint64_t df                       : 1;
      uint64_t copy_df                  : 1;
      uint64_t trailer_pre_formatted    : 1;
      uint64_t single_sa                : 1; 
      uint64_t gre_bit                  : 1;
      uint64_t packet_iv                : 1;
      uint64_t sa_read_only             : 1;
      uint64_t tfc_size                 :16;
      uint64_t tos_tc                   : 8;
      uint64_t flow                     :20;
      uint64_t copy_dscp                : 1;
      uint64_t gather                   : 1;
      uint64_t no_nh                    : 1;
      uint64_t dontfree                 : 1;
#endif
   } s;
} cvm_ipsec_outbound_args_t;

#pragma pack(1)
typedef struct {
	union {
		cvm_pci_pki_ih3_t ih3;
		struct {
			uint16_t ih;
			uint16_t ifidx;
			uint32_t tcp_seq_no;
		} s;
	};
	uint8_t  esp_ah_hdrlen;
	uint8_t	 iph_offset;
	uint8_t  iph_len;
	uint8_t	 iph_proto;
	uint16_t gso_size;
	uint16_t reserved;
        uint64_t ossp;
	uint64_t tnl_hdl;
        uint64_t trns_hdl;
} ipsec_tso_info;

#define IPSEC_TSO_INFO_SIZE	((sizeof(ipsec_tso_info) + 7) & ~0x7)
#pragma pack()

/**
 * Determine if the WQE on a ipsec loopback port
 * 
 * @param wqe Work Queue Entry
 */
static inline int cvmcs_nic_is_ipsec_loopback_port(cvmx_wqe_t *wqe)
{

	if (OCTEON_IS_MODEL(OCTEON_CN78XX) || OCTEON_IS_MODEL(OCTEON_CN23XX))
                return (cvmx_wqe_get_port(wqe) ==
                                CVM_PHYS_78XX_LOOPBACK_IPSEC_PORT);

        if (octeon_has_feature(OCTEON_FEATURE_PKND))
                return (wqe->word0.pip.cn68xx.pknd ==
                                CVM_PHYS_LOOPBACK_IPSEC_PORT);
        else
                return (cvmx_wqe_get_port(wqe) ==
                                CVM_PHYS_LOOPBACK_IPSEC_PORT);
}

/**
 * Initialize the IPsec loopback port
 */
void cvmcs_nic_ipsec_loopback_port_init(void);

/**
 * Offloads IPsec crypt/decrypt
 *
 * @param wqe          Work queue entry
 * @param front_size   amount of data preceding data
 * @param ifidx        interface index
 * @param opcode       operation that triggered ipsec offload.
 *
 * @returns 0 if successful. Non-zero in failure cases.
 */
int cvm_ipsec_offload(cvmx_wqe_t * wqe, int front_size, int ifidx, int opcode);

/**
 * Process an ipsec packet after receiving on loopback port
 *
 * @param wqe   Work queue entry
 *
 * @returns 0 on success. Non-zero otherwise
 */
int process_ipsec_loopback_pkt(cvmx_wqe_t *wqe);

/**
 * Processes outgoing IPsec packets for TSO.
 *
 * @param wqe           work queue entry
 * @param temp_list     list of segments
 * @param pkt_size      list of packet sizes
 * @param gso_segs      number of segments
 * @param esp_ah_offset offset to ESP AH
 * @param esp_ah_hdrlen length of ESP AH header
 * @param ifidx         interface index
 *
 * @returns 0 on success, non-zero on failure
 */
#if 0
int cvmcs_nic_process_ipsec(cvmx_wqe_t *wqe,
			    cvmx_buf_ptr_t *temp_list, int32_t *pkt_size,
			    int16_t gso_segs, uint16_t esp_ah_offset,
			    uint16_t esp_ah_hdrlen, int ifidx);
#endif

/**
 * Get the header length from Payload Length field AH header
 *
 * @param wqe		wqe
 *
 * @returns header length from Payload Length field AH header
 */
inline int cvmcs_nic_ipsec_get_ah_hdr_len(cvmx_wqe_t *wqe);

/**
 * Get the next_header field of AH header
 *
 * @param wqe		wqe
 *
 * @returns next_header field of AH header in bytes
 */
inline int cvmcs_nic_ipsec_get_ah_next_hdr(cvmx_wqe_t *wqe);

/**
 * Get the header length and icv_length from the ESP header
 *
 * @param wqe		wqe
 * @param ifidx		ifidx
 * @param hdr_len	Buffer to return header length
 * @param icv_len	Buffer to return icv length
 *
 * @returns header length from ESP header
 */
int cvmcs_nic_ipsec_get_esp_hdr_icv_len(cvmx_wqe_t *wqe, int ifidx, uint16_t *hdr_len, uint8_t *icv_len);

/**
 * Get the next_header from the ESP header
 *
 * @param wqe		wqe
 * param ifidx		ifidx
 * @param next_hdr	Buffer to return next_header
 * @param pad_len	Buffer to return pad length
 *
 * @returns next_header from ESP header
 */
int cvmcs_nic_ipsec_get_esp_next_hdr_pad_len(cvmx_wqe_t *wqe, int ifidx, uint8_t *next_hdr, uint8_t *pad_len);

#ifdef CVM_IPSEC_STATS

int is_ah_esp_hdr(cvmx_wqe_t *wqe, int front_size);

struct ipsec_pkt_stats {
	uint64_t rx_processed;
	uint64_t rx_failed;
	uint64_t rx_bypassed;
	uint64_t tx_processed;
	uint64_t tx_failed;
	uint64_t tx_bypassed;
	uint64_t frame_count;
	uint64_t v6_count;
	uint64_t proto_mismatch;
	uint64_t spi_outofrange;
	uint64_t sa_notfound;
	uint64_t udp_pkt;
};

extern CVMX_SHARED struct ipsec_pkt_stats ipsec_stats;

#define cvm_ipsec_stats_inc(x) cvmx_atomic_add_u64(&ipsec_stats.x, 1)

static inline void cvmcs_nic_print_ipsec_stats()
{

	printf("Framecount %llu\n", cast64(ipsec_stats.frame_count));
	printf("rx_ipsec_processed %llu\n", cast64(ipsec_stats.rx_processed));
	printf("rx_ipsec_failed %llu\n", cast64(ipsec_stats.rx_failed));
	printf("rx_ipsec_bypassed %llu\n", cast64(ipsec_stats.rx_bypassed));
	printf("rx_ipsec_TOTAL: %llu\n", cast64(ipsec_stats.rx_processed + ipsec_stats.rx_bypassed));
	printf("sa_notfound %llu, totalbpassed %llu\n", cast64(ipsec_stats.sa_notfound), cast64(ipsec_stats.proto_mismatch + ipsec_stats.spi_outofrange + ipsec_stats.sa_notfound));
	printf("proto_mismatch %llu, spi_outofrange %llu\n", cast64(ipsec_stats.proto_mismatch), cast64(ipsec_stats.spi_outofrange));
	printf("udp_pkts %llu, v6_pkts %llu\n", cast64(ipsec_stats.v6_count),cast64(ipsec_stats.udp_pkt));
	printf("tx_ipsec_processed %llu\n", cast64(ipsec_stats.tx_processed));
	printf("tx_ipsec_failed %llu\n", cast64(ipsec_stats.tx_failed));
	printf("tx_ipsec_bypassed %llu\n", cast64(ipsec_stats.tx_bypassed));
	printf("tx_ipsec_TOTAL %llu\n", cast64(ipsec_stats.tx_processed + ipsec_stats.tx_bypassed));

	ipsec_stats.frame_count++;
}

#else
#define cvm_ipsec_stats_inc(x)
#endif //CVM_IPSEC_STATS

#define CVM_IPSEC_NH_AH_FLAG    1
#define CVM_IPSEC_NH_ESP_FLAG   2



#ifdef DELAY_DELETE_SA
/**
 *  Delete SA 
 *
 *  @param oct_sa_data	SA to be deleted
 *
 *  @returns void
 *
 */
void cvm_ipsec_delete_sa_completion(uint8_t *oct_sa_data);
#endif //DELAY_DELETE_SA

#endif  // __CVM_NIC_IPSEC_H__
