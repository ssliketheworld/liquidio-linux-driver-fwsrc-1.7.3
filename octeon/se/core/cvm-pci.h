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



/*! \file cvm-pci.h
    \brief Core Driver: PCI instruction format and core mem mapping.
*/


#ifndef __CVM_PCI_H__
#define __CVM_PCI_H__

#include "cvmx.h"
//#include "octeon_config.h"
#include "liquidio_common.h"


/* The 4 PCI ports are from 32 to 35  */
#define    FIRST_PCI_PORT                   32
#define    LAST_PCI_PORT                    35

#define    DRV_REQUEST_DONE                 0




/** Core: The (Packet) Instruction Header appears in the format shown below for 
  * Octeon. Refer to the Octeon HW Manual to read more about the 
  * conversion from PCI instruction header to Packet Instruction Header.
  */
typedef union {
    uint64_t   u64;
    struct {
#if __BYTE_ORDER == __LITTLE_ENDIAN
       uint64_t   tag:32;        /**< 31-00 Tag for the Packet. */
       cvmx_pow_tag_type_t tt:2; /**< 33-32 Tagtype */
       uint64_t   rs:1;          /**< 34    Is the PCI packet a RAW-SHORT? */
       uint64_t   grp:4;         /**< 38-35 The group that gets this Packet */
       uint64_t   qos: 3;        /**< 41-39 The QOS set for this Packet. */
       uint64_t   rsvd3:6;       /**< 47-42 Reserved */
       uint64_t   sl:7;          /**< 54-48 Skip Length */
       uint64_t   rsvd2:1;       /**< 55    Reserved. */
       uint64_t   pm:2;          /**< 57-56 The parse mode to use for the packet. */
       uint64_t   rsvd1:5;       /**< 62-58 Reserved */
       uint64_t   r:1;           /**< 63    Is the PCI packet in RAW-mode? */
#else
       uint64_t   r:1;           /**< 63    Is the PCI packet in RAW-mode? */
       uint64_t   rsvd1:5;       /**< 62-58 Reserved */
       uint64_t   pm:2;          /**< 57-56 The parse mode to use for the packet. */
       uint64_t   rsvd2:1;       /**< 55    Reserved. */
       uint64_t   sl:7;          /**< 54-48 Skip Length */
       uint64_t   rsvd3:6;       /**< 47-42 Reserved */
       uint64_t   qos: 3;        /**< 41-39 The QOS set for this Packet. */
       uint64_t   grp:4;         /**< 38-35 The group that gets this Packet */
       uint64_t   rs:1;          /**< 34    Is the PCI packet a RAW-SHORT? */
       cvmx_pow_tag_type_t tt:2; /**< 33-32 Tagtype */
       uint64_t   tag:32;        /**< 31-00 Tag for the Packet. */
#endif
    } s;
} cvm_pci_inst_hdr2_t;


typedef union  {
	uint64_t u64;
	struct {
#if __BYTE_ORDER == __BIG_ENDIAN
		/** Wider bit */
		uint64_t     w:1;

		/** Raw mode indicator 1 = RAW */
		uint64_t     raw:1;

		/** Use Tag */
		uint64_t     utag:1;

		/** Use QPG */
		uint64_t     uqpg:1;

		/** Reserved2 */
		uint64_t     reserved2:1;

		/** Parse Mode */
		uint64_t     pm:3;

		/** Skip Length */
		uint64_t     sl:8;

		/** Use Tag Type */
		 uint64_t     utt:1;

		 /** Tag type */
		 uint64_t     tagtype:2;

		 /** Reserved1 */
		 uint64_t     reserved1:2;

		 /** QPG Value */
		 uint64_t     qpg:11;

		 /** Tag Value */
		 uint64_t     tag:32;
#else
		 uint64_t     tag:32;
		 /** Tag Value */

		 uint64_t     qpg:11;
		 /** QPG Value */

		 uint64_t     reserved1:2;
		 /** Reserved1 */

		 uint64_t     tagtype:2;
		 /** Tag type */

		 uint64_t     utt:1;
		/** Use Tag Type */

		uint64_t     sl:8;
		/** Skip Length */

		uint64_t     pm:3;
		/** Parse Mode */

		uint64_t     reserved2:1;
		/** Reserved2 */

		uint64_t     uqpg:1;
		/** Use QPG */

		uint64_t     utag:1;
		/** Use Tag */

		uint64_t     raw:1;
		/** Raw mode indicator 1 = RAW */

		uint64_t     w:1;
		/** Wider bit */
#endif
	}s;

} cvm_pci_pki_ih3_t;



/** Core: Format of the input request header in an instruction. */
typedef union  {

    uint64_t  u64;
    struct octeon_instr_irh s;

} cvmx_pci_inst_irh_t;




/** Core: Format of the return data parameters in an instruction. */
typedef union {

    uint64_t  u64;
    struct octeon_instr_rdp s;

} cvmx_pci_inst_rdp_t;

typedef union {
	uint64_t  u64;
	cvm_pci_inst_hdr2_t   ih2;
	cvm_pci_pki_ih3_t     pki_ih3;
} cvm_pci_inst_hdr_t;

/** Core: Format of the front data for a raw instruction in the first 24 bytes
 *  of the wqe->packet_data or packet ptr when a core gets work from a PCI input
 *  port.
 */
typedef struct  {

  /** The instruction header. */
   cvm_pci_inst_hdr_t   ih;

  /** The input request header. */
   cvmx_pci_inst_irh_t   irh;

  /** opcode/subcode specific parameters */
   uint64_t ossp[2];

  /** return data parameters */
   cvmx_pci_inst_rdp_t   rdp;

  /** The host physical address where a response (if any) is expected. */
   uint64_t              rptr;

} cvmx_raw_inst_front_t;


#define CVM_RAW_FRONT_SIZE   (sizeof(cvmx_raw_inst_front_t))





/** Core: The core driver routines can handle local pointers of the these
  * types. 
  */
typedef enum {
   CVM_DIRECT_DATA = 0, /**< Local Pointer points directly to data */
   CVM_GATHER_DATA = 1, /**< Local Pointer points to a gather list of local pointers */
   CVM_LINKED_DATA = 2, /**< Local pointer points to data which has links to more buffers */
   CVM_NULL_DATA   = 3  /**< If no data is sent and a flag is required, use this. */
} cvm_ptr_type_t;

/** Tx timestamp response format */
typedef struct __timestamp_resp_t {
	uint64_t resp_hdr;
	uint64_t timestamp;
	uint64_t status;
} cvmx_timestamp_resp_t;

/** Get the size of data in the first packet buffer in a WQE from PCI.
  * @param bufptr - the packet pointer from wqe (wqe->packet_ptr).
  * @param raw    - flag to indicate if the PCI packet is in RAW mode.
  * @return Returns the size of data in this packet buffer.
  */
static inline int
cvm_get_first_buf_size(cvmx_buf_ptr_t   bufptr, int raw)
{
	int  len=0;
	if (!octeon_has_feature(OCTEON_FEATURE_PKI)) {
		len = ( ( (cvmx_read_csr(CVMX_IPD_PACKET_MBUFF_SIZE) & 0xfff)
			- ((cvmx_read_csr(CVMX_IPD_1ST_MBUFF_SKIP) & 0x3f) + 1) ) * 8)
			- (bufptr.s.addr & 0x7);
	if(raw)
		len -= CVM_RAW_FRONT_SIZE;
	}
	return len;
}


/** Call this routine to get the size of data for packet buffers following
  * the first buffer in a WQE from PCI.
  * @return Returns the size of data in this packet buffer.
  */
static inline int
cvm_get_next_buf_size(void)
{
	int len = 0;

	if (!octeon_has_feature(OCTEON_FEATURE_PKI)) {
		len = (((cvmx_read_csr(CVMX_IPD_PACKET_MBUFF_SIZE) & 0xfff)
			- ((cvmx_read_csr(CVMX_IPD_NOT_1ST_MBUFF_SKIP) & 0x3f) + 1)) * 8);
	}
	return len;
}



/** Call this routine with virtual address of packet buffer to get the
  * address of the next packet buffer in the WQE chain.
  * @param pktptr - virtual address of packet buffer
  * @return Returns the virtual address of next packet buffer.
  */
static inline void *
cvm_get_next_pkt_ptr(void  *pktptr)
{
	cvmx_buf_ptr_t  *ptr = (cvmx_buf_ptr_t *)((uint8_t *)pktptr - 8); 
	return (void *)cvmx_phys_to_ptr(ptr->s.addr);
}




#endif  /* __CVM_PCI_H__ */

/* $Id$ */
