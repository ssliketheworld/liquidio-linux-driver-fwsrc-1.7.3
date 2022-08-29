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

/*! \file cvm-pci-dma.h
    \brief  Core Driver: Structures and routines for PCI DMA queue
            management.
 */

#ifndef __CVM_PCI_DMA_H__
#define __CVM_PCI_DMA_H__

#include  "cvm-driver-defs.h"
#include  "cvm-oct-dev.h"


/* Enable this flag to turn on tracking of PCI DMA transactions.
   See cvm-pci-dma.c for a description of the tracking mechanism.
*/
//#define CVM_PCI_TRACK_DMA
#define CVM_PCI_DMA_TRACKER_PORT   0x2f
#define CVM_PCI_DMA_TRACKER_TAG    0x12345678


#define MAX_PCI_DMA_LOCAL_BUF_SIZE    ((1 << 13) - 8)


#define CVM_FPA_DMA_CHUNK_POOL        CVMX_FPA_PACKET_POOL
#define CVM_DMA_CHUNK_SIZE    \
       (cvmx_fpa_get_block_size(CVM_FPA_DMA_CHUNK_POOL))


#define OCTEON_MAX_DMA_LOCAL_POINTERS          14
#define OCTEON_MAX_DMA_REMOTE_POINTERS         13
#define OCTEON_MAX_DMA_POINTERS                27

typedef enum {

	CVMX_DMA_QUEUE0 = 0,
	CVMX_DMA_QUEUE1 = 1,
	CVMX_DMA_QUEUE2 = 2,
	CVMX_DMA_QUEUE3 = 3,
	CVMX_DMA_QUEUE4 = 4,

}CVMX_DMA_QUEUE_TYPE;

#define  CVM_PCI_DMA_START_ADDR_REG(q_no)  \
	((q_no)?CVMX_NPI_LOWP_IBUFF_SADDR:CVMX_NPI_HIGHP_IBUFF_SADDR)

#define  CVM_PCI_DMA_DOORBELL_REG(q_no)  \
	((q_no)?CVMX_NPI_LOWP_DBELL:CVMX_NPI_HIGHP_DBELL)


#define	CVMX_HIGHP_DMA_QUEUE    CVMX_DMA_QUEUE0
#define	CVMX_LOWP_DMA_QUEUE     CVMX_DMA_QUEUE1 






/* Core: Flags in cvm_pci_dma_cmd_t can take one or more of the 
         values defined here. The flags are used in PCI send and receive API's.

  -------
|  Bit 7  | - Reserved
  -------
|  Bit 6  | - If set, DMA Command uses WQE for completion; 
  -------
|  Bit 5  | - If set, DMA Command FreeLocal bit is set.
  -------
|  Bit 4  | - If set, DMA Command IgnoreI bit is set.
  -------
|  Bit 3  | - If set, DMA Command Force Interrupt bit is set
  -------
|  Bit 2  | - If set, DMA Command Counter Add bit is set
  -------
| Bit 0-1 | - Direction.
  ------- 
*/


typedef enum {
	PCI_DMA_OUTBOUND  =  0,     /* Default DMA direction is outbound */
	PCI_DMA_INBOUND   =  1,
	PCI_DMA_EXTERNAL  =  2,
	PCI_DMA_INTERNAL  =  3,
	PCI_DMA_CNTRADD   =  4,
	PCI_DMA_FORCEINT  =  8,
	PCI_DMA_IGNOREI   =  16,
	PCI_DMA_FREELOCAL =  32, 
	PCI_DMA_PUTWQE    =  64,
} oct_pci_dma_flags_t;


/* There is no bit set in the DMA command for using a memory location for
   completion. This flag is defined here just to complete the set of flags.
*/
#define PCI_DMA_PUTWORD    0


/* By default, none of the above flags are set. The driver would still set the
   force interrupt bit for a instruction response.
*/
#define PCI_DMA_FLAGS_DEFAULT  0



/* Normal local buffer pointer and DMA local buffer pointer differ in the
 * bits below. 
 * Bit53 should not be set, Bits 39-36 should not be set. */
#define  CVM_PCI_DMA_LOCAL_PTR_MASK     0xFFDFFF0FFFFFFFFFULL

/* For OCT-III models, PKI buffer pointer and DMA local buffer pointer
 * differ in the bits below. 
 * Bits 63-61, 47-42.
 * resetting those bits to 0, using the mask. 
 */
#define  CVM_PCI_DMA_LOCAL_PTR_MASK_O3  0x1FFF03FFFFFFFFFFULL




typedef enum {

	DMA_BLOCKING     = 1,
	DMA_NON_BLOCKING = 2

} DMA_ACTION;




/** Core: Hardware defined 64-bit PCI DMA command structure. Most of the bits
	are shared across all Octeon processors. Some bits were reserved in
	CN38XX/CN58XX processors but have meaning in CN56XX. */
typedef union {

	uint64_t       u64;

	struct {
#if __BYTE_ORDER == __LITTLE_ENDIAN
		uint64_t   ptr  :40;
		uint64_t   nl   : 4;
		uint64_t   nr   : 4;
		uint64_t   fl   : 1;
		uint64_t   ii   : 1;
		uint64_t   fi   : 1;
		uint64_t   ca   : 1;
		uint64_t   c    : 1;
		uint64_t   wqp  : 1;
		uint64_t   dir  : 2;  /**< This field is 1 bit wide in CN38xx/58xx */
		uint64_t   lport: 2;  /**< This field doesn't exist in CN38xx/58xx */
		uint64_t   fport: 2;  /**< This field doesn't exist in CN38xx/58xx */
		uint64_t   rsvd : 4;  
#else
		uint64_t   rsvd : 4;
		uint64_t   fport: 2;  /**< This field doesn't exist in CN38xx/58xx */
		uint64_t   lport: 2;  /**< This field doesn't exist in CN38xx/58xx */
		uint64_t   dir  : 2;  /**< This field is 1 bit wide in CN38xx/58xx */
		uint64_t   wqp  : 1;
		uint64_t   c    : 1;
		uint64_t   ca   : 1;
		uint64_t   fi   : 1;
		uint64_t   ii   : 1;
		uint64_t   fl   : 1;
		uint64_t   nr   : 4;
		uint64_t   nl   : 4;
		uint64_t   ptr  :40;
#endif
	} cn38xx;

	struct {
#if __BYTE_ORDER == __LITTLE_ENDIAN
        uint64_t   aura : 12;
        uint64_t   rsvd_12_15 : 4;
        uint64_t   tt : 2;
        uint64_t   grp : 10;
        uint64_t   rsvd_28_30 : 3;
	uint64_t   pvfe : 1;
        uint64_t   nl : 4;
        uint64_t   rsvd_36_37 : 2;
        uint64_t   nr : 4;
        uint64_t   rsvd_42 : 1;
        uint64_t   dealloce : 1;
        uint64_t   pt : 2;
        uint64_t   rsvd_46 : 1;
        uint64_t   fl : 1;
        uint64_t   ii : 1;
        uint64_t   fi : 1;
        uint64_t   ca : 1;
        uint64_t   csel : 1;
        uint64_t   type : 2;
        uint64_t   rsvd_54_55 : 2; 
        uint64_t   fport: 2; 
        uint64_t   rsvd_58_59 : 2;
        uint64_t   lport: 2;  
        uint64_t   rsvd_62_63 : 2;

#else
		uint64_t   rsvd_62_63 : 2;
		uint64_t   lport: 2; 
		uint64_t   rsvd_58_59 : 2;
		uint64_t   fport: 2;
		uint64_t   rsvd_54_55 : 2; 
		uint64_t   type : 2;
		uint64_t   csel : 1;
		uint64_t   ca : 1;
		uint64_t   fi : 1;
	    uint64_t   ii : 1;
	    uint64_t   fl : 1;
	    uint64_t   rsvd_46 : 1;
		uint64_t   pt : 2;
		uint64_t   dealloce : 1;
		uint64_t   rsvd_42 : 1;
		uint64_t   nr : 4;
		uint64_t   rsvd_36_37 : 2;
		uint64_t   nl : 4;
		uint64_t   pvfe : 1;
	 	uint64_t   rsvd_28_30 : 3;
		uint64_t   grp : 10;
		uint64_t   tt : 2;
		uint64_t   rsvd_12_15 : 4;
		uint64_t   aura : 12;
#endif
	}cn78xx;
}cvmx_oct_pci_dma_inst_hdr_word0_t;
		
typedef union {

	uint64_t       u64;

	struct {
#if __BYTE_ORDER == __LITTLE_ENDIAN
		uint64_t   ptr : 42;
		uint64_t   rsvd_42_47 : 6;
		uint64_t   deallocv   : 16;
#else
		uint64_t   deallocv : 16;
		uint64_t   rsvd_42_47 : 6;
		uint64_t   ptr   : 42;
#endif
	}s;
}cvmx_oct_pci_dma_inst_hdr_word1_t;


typedef struct cvmx_oct_pci_dma_inst_hdr {
	cvmx_oct_pci_dma_inst_hdr_word0_t	word0;
	cvmx_oct_pci_dma_inst_hdr_word1_t	word1;
} cvmx_oct_pci_dma_inst_hdr_t;






/** Core: Hardware defined 64-bit PCI DMA local buffer format. */
typedef union {
   uint64_t                   u64;
   void                    *ptr;
   uint64_t               *u64ptr;
   struct {
#if __BYTE_ORDER == __LITTLE_ENDIAN
      uint64_t                addr  :36;
      uint64_t            reserved  : 4;
      uint64_t                size  :13;
      uint64_t                   l  : 1;
      uint64_t                   a  : 1;
      uint64_t                   f  : 1;
      uint64_t                pool  : 3;
      uint64_t                back  : 4;
      uint64_t                   i  : 1;
#else
      uint64_t                   i  : 1;
      uint64_t                back  : 4;
      uint64_t                pool  : 3;
      uint64_t                   f  : 1;
      uint64_t                   a  : 1;
      uint64_t                   l  : 1;
      uint64_t                size  :13;
      uint64_t            reserved  : 4;
      uint64_t                addr  :36;
#endif
   } cn38xx;
   struct {
#if __BYTE_ORDER == __LITTLE_ENDIAN
      uint64_t                addr  :42;
      uint64_t           rsvd_42_46 : 5;
      uint64_t                   l  : 1;
      uint64_t                size  : 13;
      uint64_t                	ac  : 1;
      uint64_t                	 f  : 1;
      uint64_t                   i  : 1;
#else
      uint64_t                   i  : 1;
      uint64_t                	 f  : 1;
      uint64_t                	 ac : 1;
      uint64_t                size  : 13;
      uint64_t                   l  : 1;
      uint64_t            rsvd_42_46: 5;
      uint64_t                addr  :42;
#endif
   } cn78xx;

} cvmx_oct_pci_dma_local_ptr_t;







/** Core: Information about PCI DMA operation.
  * This structure tells the core driver about the type of DMA 
  * operation to be submitted to Octeon PCI DMA engines. The
  * Octeon PCI DMA command is built from the field defined here.
  * This structure is passed to the PCI send/receive api's. It is
  * not used in the instruction response API's.
  */
typedef union {

	uint64_t   u64;

	struct {
		/** Number of remote pointers in the operation. */
		uint64_t   nr:4;

		/** Number of local pointers in the operation. */
		uint64_t   nl:4;

		/** Determines DMA queue to use for this operation.
		    There are 2 DMA queues forCN38XX, 5 for CN56XX and 8 for CN63XX. */
		uint64_t   q_no:3;

		/** CN56XX/63XX Only. Determines First PCI-Express Port for DMA. */
		uint64_t   pciefport:1;

		/** CN56XX/63XX Only. Determines Last PCI-Express Port for DMA. */
		/** Using 2-bits for accommodating 4 PCIe Port Ids....         */
		uint64_t   pcielport:2;

		/** Reserved */
		uint64_t   rsvd:2;

		/** Flags describe the direction of DMA and post-DMA
		    operations as defined in the enum oct_pci_dma_flags_t */
		oct_pci_dma_flags_t   flags:8;

		/** Physical address of WQE buffer or location in Octeon memory
		    for post-DMA operation. */
		uint64_t   ptr:40;
	} s;

} cvm_pci_dma_cmd_t;


#define  INIT_PCI_DMA_CMD(pcmd)         (pcmd->u64 = 0)


/* Get the direction bits from the flags field of the CVM PCI DMA Command. */
#define  CVM_PCI_DMA_DIR(dmacmdptr)     (dmacmdptr->s.flags & 0x3)



/** Core: Scatter response information 
  * This structure is passed by application when calling a scatter response
  * API.
  */ 
typedef struct {

	/** The receive header for the instruction. Ignored for
	    cvm_dma_send_scatter_response_direct()  since ORH is part of 
	    response data for direct API. */
	union octeon_rh      orh;

	/** The status to be returned to host. Ignored for 
	    cvm_dma_send_scatter_response_direct() since status is part of 
	    response data for direct API. */
	uint64_t             status;

	/** Number of entries in the scatter list. */
	uint32_t             remote_segs;

	/** PCIe port to use to read scatter list and send response. */
	uint8_t              pcie_port;

	/** Reserved. */ 
	uint8_t             reserved[3];

	/** The scatter list that contains the host output buffer addresses. */
	struct octeon_sg_entry   *sg_entry;

} cvm_pci_scatter_resp_t;


 



/** Core: Format for size of remote data buffer in a PCI DMA component.
  * Refer to section 10.5.3 in Octeon Hardware Manual. */
typedef union {

   uint64_t  u64;

   struct {
      uint16_t  len[4];
   } l;

} cvm_dma_remote_len_t; 





/**  Core:  Address of the host machine are presented to PCI DMA routines in
  *  this format. The driver translates this to the PCI component format.
  */
typedef union {

   uint64_t  u64;

   struct {
      uint64_t     addr:48;
      uint64_t     size:16;
   }s;

}  cvm_dma_remote_ptr_t;





#ifdef CVM_PCI_TRACK_DMA

/* Application should call this routine for all WQE's received from port 0x2f.
   The DMA tracker had modified the DMA command to generate these WQE. They
   should be sent to the DMA tracker routine for proper processing.
*/
void  cvm_pci_dma_remove_from_tracker_list(cvmx_wqe_t  *wqe);


/* Applications can call this routine to print the list of DMA commands that
   have not been processed by the DMA engine.
*/
void cvm_pci_dma_dump_tracker_list(void);


#endif



/*------------------------- Inline Routines -------------------------------*/

#if 0
/*------------------------- Accessor Functions for DMA Instruction Header -------------------------------*/
static inline void
cvm_dma_inst_hdr_set_aura(cvmx_oct_pci_dma_inst_hdr_t *hdr, uint64_t aura) {

	if (OCTEON_IS_MODEL(OCTEON_CN78XX))
		hdr->word0.cn78xx.aura = aura;
}

static inline uint64_t
cvm_dma_inst_hdr_get_nl(cvmx_oct_pci_dma_inst_hdr_t *hdr) {

	if (OCTEON_IS_MODEL(OCTEON_CN78XX))
		return hdr->word0.cn78xx.nl;
	else
		return hdr->word0.cn38xx.nl;
}

static inline void
cvm_dma_inst_hdr_set_nl(cvmx_oct_pci_dma_inst_hdr_t *hdr, uint64_t nl) {

	if (OCTEON_IS_MODEL(OCTEON_CN78XX))
		hdr->word0.cn78xx.nl = nl;
	else
		hdr->word0.cn38xx.nl = nl;
}

static inline uint64_t
cvm_dma_inst_hdr_get_nr(cvmx_oct_pci_dma_inst_hdr_t *hdr) {

	if (OCTEON_IS_MODEL(OCTEON_CN78XX))
		return hdr->word0.cn78xx.nr;
	else
		return hdr->word0.cn38xx.nr;
}

static inline void
cvm_dma_inst_hdr_set_nr(cvmx_oct_pci_dma_inst_hdr_t *hdr, uint64_t nr) {

	if (OCTEON_IS_MODEL(OCTEON_CN78XX))
		hdr->word0.cn78xx.nr = nr;
	else
		hdr->word0.cn38xx.nr = nr;
}


static inline void
cvm_dma_inst_hdr_set_wqp(cvmx_oct_pci_dma_inst_hdr_t *hdr, uint64_t wqp) {

	if (OCTEON_IS_MODEL(OCTEON_CN78XX))
		hdr->word0.cn78xx.pt = wqp;
	else
		hdr->word0.cn38xx.wqp = wqp;
}

static inline uint64_t
cvm_dma_inst_hdr_get_csel(cvmx_oct_pci_dma_inst_hdr_t *hdr) {

	if (OCTEON_IS_MODEL(OCTEON_CN78XX))
		return hdr->word0.cn78xx.csel;
	else
		return hdr->word0.cn38xx.c;
}

static inline void
cvm_dma_inst_hdr_set_csel(cvmx_oct_pci_dma_inst_hdr_t *hdr, uint64_t csel) {

	if (OCTEON_IS_MODEL(OCTEON_CN78XX))
		hdr->word0.cn78xx.csel = csel;
	else
		hdr->word0.cn38xx.c = csel;

}

static inline void
cvm_dma_inst_hdr_set_fport(cvmx_oct_pci_dma_inst_hdr_t *hdr, uint64_t fport) {

	if (OCTEON_IS_MODEL(OCTEON_CN78XX))
		hdr->word0.cn78xx.fport = fport;
	else
		hdr->word0.cn38xx.fport = fport;
}

static inline void
cvm_dma_inst_hdr_set_lport(cvmx_oct_pci_dma_inst_hdr_t *hdr, uint64_t lport) {

	if (OCTEON_IS_MODEL(OCTEON_CN78XX))
		hdr->word0.cn78xx.lport = lport;
	else
		hdr->word0.cn38xx.lport = lport;
}

static inline uint64_t
cvm_dma_inst_hdr_get_dir(cvmx_oct_pci_dma_inst_hdr_t *hdr) {

	if (OCTEON_IS_MODEL(OCTEON_CN78XX))
		return hdr->word0.cn78xx.type;
	else
		return hdr->word0.cn38xx.dir;
}

static inline void
cvm_dma_inst_hdr_set_dir(cvmx_oct_pci_dma_inst_hdr_t *hdr, uint64_t type) {

	if (OCTEON_IS_MODEL(OCTEON_CN78XX))
		hdr->word0.cn78xx.type = type;
	else
		hdr->word0.cn38xx.dir = type;
}

static inline uint64_t
cvm_dma_inst_hdr_get_ptr(cvmx_oct_pci_dma_inst_hdr_t *hdr) {

	if (OCTEON_IS_MODEL(OCTEON_CN78XX))
		return hdr->word1.s.ptr;
	else
		return hdr->word0.cn38xx.ptr;
}

static inline void
cvm_dma_inst_hdr_set_ptr(cvmx_oct_pci_dma_inst_hdr_t *hdr, uint64_t ptr) {

	if (OCTEON_IS_MODEL(OCTEON_CN78XX))
		hdr->word1.s.ptr = ptr;
	else
		hdr->word0.cn38xx.ptr = ptr;
}


static inline void
cvm_dma_inst_hdr_set_ca(cvmx_oct_pci_dma_inst_hdr_t *hdr, uint64_t ca) {

	if (OCTEON_IS_MODEL(OCTEON_CN78XX))
		hdr->word0.cn78xx.ca = ca;
	else
		hdr->word0.cn38xx.ca = ca;
}

static inline void
cvm_dma_inst_hdr_set_fi(cvmx_oct_pci_dma_inst_hdr_t *hdr, uint64_t fi) {

	if (OCTEON_IS_MODEL(OCTEON_CN78XX))
		hdr->word0.cn78xx.fi = fi;
	else
		hdr->word0.cn38xx.fi = fi;
}

static inline void
cvm_dma_inst_hdr_set_fl(cvmx_oct_pci_dma_inst_hdr_t *hdr, uint64_t fl) {

	if (OCTEON_IS_MODEL(OCTEON_CN78XX))
		hdr->word0.cn78xx.fl = fl;
	else
		hdr->word0.cn38xx.fl = fl;
}

static inline void
cvm_dma_inst_hdr_set_ii(cvmx_oct_pci_dma_inst_hdr_t *hdr, uint64_t ii) {

	if (OCTEON_IS_MODEL(OCTEON_CN78XX))
		hdr->word0.cn78xx.ii = ii;
	else
		hdr->word0.cn38xx.ii = ii;
}


/*------------------------- Accessor Functions for DMA Local ptr -------------------------------*/

static inline uint64_t
cvm_dma_local_ptr_get_addr(cvmx_oct_pci_dma_local_ptr_t *lptr) {

	if (OCTEON_IS_MODEL(OCTEON_CN78XX))
		return lptr->cn78xx.addr;
	else
		return lptr->cn38xx.addr;
}

static inline void
cvm_dma_local_ptr_set_addr(cvmx_oct_pci_dma_local_ptr_t *lptr, uint64_t addr) {

	if (OCTEON_IS_MODEL(OCTEON_CN78XX))
		lptr->cn78xx.addr = addr;
	else
		lptr->cn38xx.addr = addr;
}

static inline uint64_t
cvm_dma_local_ptr_get_size(cvmx_oct_pci_dma_local_ptr_t *lptr) {

	if (OCTEON_IS_MODEL(OCTEON_CN78XX))
		return lptr->cn78xx.size;
	else
		return lptr->cn38xx.size;
}

static inline void
cvm_dma_local_ptr_set_size(cvmx_oct_pci_dma_local_ptr_t *lptr, uint64_t size) {

	if (OCTEON_IS_MODEL(OCTEON_CN78XX))
		lptr->cn78xx.size = size;
	else
		lptr->cn38xx.size = size;
}

static inline uint64_t
cvm_dma_local_ptr_get_back(cvmx_oct_pci_dma_local_ptr_t *lptr) {

	if (!OCTEON_IS_MODEL(OCTEON_CN78XX))
		return lptr->cn38xx.back;

	return 0;
}

static inline void
cvm_dma_local_ptr_set_back(cvmx_oct_pci_dma_local_ptr_t *lptr, uint64_t back) {

	if (!OCTEON_IS_MODEL(OCTEON_CN78XX))
		lptr->cn38xx.back = back;
}

static inline uint64_t
cvm_dma_local_ptr_get_pool(cvmx_oct_pci_dma_local_ptr_t *lptr) {

	if (!OCTEON_IS_MODEL(OCTEON_CN78XX))
		return lptr->cn38xx.pool;
	return 0;
}

static inline void
cvm_dma_local_ptr_set_pool(cvmx_oct_pci_dma_local_ptr_t *lptr, uint64_t pool) {

	if (!OCTEON_IS_MODEL(OCTEON_CN78XX))
		lptr->cn38xx.pool = pool;
}

static inline uint64_t
cvm_dma_local_ptr_get_invert(cvmx_oct_pci_dma_local_ptr_t *lptr) {

	if (OCTEON_IS_MODEL(OCTEON_CN78XX))
		return lptr->cn78xx.i;
	else
		return lptr->cn38xx.i;
}

static inline void 
cvm_dma_local_ptr_set_invert(cvmx_oct_pci_dma_local_ptr_t *lptr, uint64_t invert) {

	if (OCTEON_IS_MODEL(OCTEON_CN78XX))
		lptr->cn78xx.i = invert;
	else
		lptr->cn38xx.i = invert;
}

static inline uint64_t 
cvm_dma_local_ptr_get_endian(cvmx_oct_pci_dma_local_ptr_t *lptr) {

	if (OCTEON_IS_MODEL(OCTEON_CN78XX))
		return lptr->cn78xx.l;
	else
		return lptr->cn38xx.l;
}

static inline void 
cvm_dma_local_ptr_set_endian(cvmx_oct_pci_dma_local_ptr_t *lptr, uint64_t endian) {

	if (OCTEON_IS_MODEL(OCTEON_CN78XX))
		lptr->cn78xx.l = endian;
	else
		lptr->cn38xx.l = endian;
}
#endif
/** Core: Routine to fill the PCI DMA instruction local pointers. This 
  * routines translates LINKED, DIRECT and GATHER mode pointers to a list of
  * local pointers as required by the PCI DMA engine. Applications that
  * require calling a direct PCI DMA API like cvm_pci_dma_raw() should call
  * this function to prepare the local pointer list.
  *
  * @param local_ptr: Local pointer list to be passed to DMA instruction
  * @param lptr     : Local pointer list (linked/gather) available with app.
  * @param segs     : Number of local pointers.
  * @param ptr_type : CVM_DIRECT_DATA, CVM_LINKED_DATA or CVM_GATHER_DATA.
  * @return Sum of buffer sizes for the addresses copied into local_ptr.
  */
static inline int
cvm_dma_fill_local_ptrs(cvmx_oct_pci_dma_local_ptr_t    *local_ptr,
                        cvmx_buf_ptr_t                   lptr,
                        uint32_t                         segs,
                        cvm_ptr_type_t                   ptr_type)
{
	uint32_t         total_bytes=0, i;
	cvmx_buf_ptr_t   *list;

	switch(ptr_type) {
		case CVM_DIRECT_DATA:
			if(segs == 1) {
				if(lptr.s.size > MAX_PCI_DMA_LOCAL_BUF_SIZE)
					return -1;

				local_ptr->u64 = (lptr.u64 & CVM_PCI_DMA_LOCAL_PTR_MASK);
				total_bytes = lptr.s.size;
			}
			break;
		case CVM_LINKED_DATA:
			if(lptr.s.size > MAX_PCI_DMA_LOCAL_BUF_SIZE)
				return -1;

			local_ptr->u64 = (lptr.u64 & CVM_PCI_DMA_LOCAL_PTR_MASK);

			total_bytes    = local_ptr->cn38xx.size;
			local_ptr++;
			list = (cvmx_buf_ptr_t *)CVM_DRV_GET_PTR(lptr.s.addr - 8);
			for(i = 1; i < segs; i++, local_ptr++) {
				if(list->s.size > MAX_PCI_DMA_LOCAL_BUF_SIZE)
					return -1;

				local_ptr->u64 = (list->u64 & CVM_PCI_DMA_LOCAL_PTR_MASK);

				total_bytes    += local_ptr->cn38xx.size;
				list = (cvmx_buf_ptr_t *)CVM_DRV_GET_PTR(list->s.addr - 8);
			}
			break;
		case CVM_GATHER_DATA:
			list = (cvmx_buf_ptr_t *)CVM_DRV_GET_PTR(lptr.s.addr);
			DBG_PRINT(DBG_FLOW, "cvm_pci_dma: gptr @ 0x%p\n", list);
			DBG_PRINT(DBG_FLOW, "gather list contents\n");
			for(i = 0; i < segs; i++, local_ptr++) {
				if(list[i].s.size > MAX_PCI_DMA_LOCAL_BUF_SIZE)
					return -1;

				local_ptr->u64 = (list[i].u64 & CVM_PCI_DMA_LOCAL_PTR_MASK);

				total_bytes    += local_ptr->cn38xx.size;
				DBG_PRINT(DBG_FLOW, "gather list[%d]: 0x%llx\n", i, cast64(list[i].u64));
			}
			break;
		case CVM_NULL_DATA:  /* Nothing to do here/. */
			break;
	}
	CVMX_SYNCWS;
	return total_bytes;
}


/** Routine for OCT-III models. 
  * Core: Routine to fill the PCI DMA instruction local pointers.
  * This routines translates LINKED, DIRECT and GATHER mode pointers to a list of
  * local pointers as required by the PCI DMA engine. Applications that
  * require calling a direct PCI DMA API like cvm_pci_dma_raw() should call
  * this function to prepare the local pointer list.
  *
  * @param local_ptr: Local pointer list to be passed to DMA instruction
  * @param lptr     : Local pointer list (linked/gather) available with app.
  * @param segs     : Number of local pointers.
  * @param ptr_type : CVM_DIRECT_DATA, CVM_LINKED_DATA or CVM_GATHER_DATA.
  * @return Sum of buffer sizes for the addresses copied into local_ptr.
  */
static inline int
cvm_dma_fill_local_ptrs_o3(cvmx_oct_pci_dma_local_ptr_t    *local_ptr,
                        cvmx_buf_ptr_pki_t                 lptr,
                        uint32_t                           segs,
                        cvm_ptr_type_t                     ptr_type)
{
	uint32_t              total_bytes=0, i;
	cvmx_buf_ptr_pki_t   *list;

	switch(ptr_type) {
		case CVM_DIRECT_DATA:
			if(segs == 1) {
				if(lptr.size > MAX_PCI_DMA_LOCAL_BUF_SIZE)
					return -1;

				local_ptr->u64 = (lptr.u64 & CVM_PCI_DMA_LOCAL_PTR_MASK_O3);
				local_ptr->cn78xx.i = 1;
                total_bytes = lptr.size;
            }
			break;
		case CVM_LINKED_DATA:
			if(lptr.size > MAX_PCI_DMA_LOCAL_BUF_SIZE)
				return -1;

			local_ptr->u64 = (lptr.u64 & CVM_PCI_DMA_LOCAL_PTR_MASK_O3);
			local_ptr->cn78xx.i = 1;

			total_bytes    = local_ptr->cn78xx.size;
			local_ptr++;
			list = (cvmx_buf_ptr_pki_t *)CVM_DRV_GET_PTR(lptr.addr - 8);

			for(i = 1; i < segs; i++, local_ptr++) {
				if(list->size > MAX_PCI_DMA_LOCAL_BUF_SIZE)
					return -1;

				local_ptr->u64 = (list->u64 & CVM_PCI_DMA_LOCAL_PTR_MASK_O3);
				local_ptr->cn78xx.i = 1;

				total_bytes    += local_ptr->cn78xx.size;
				list = (cvmx_buf_ptr_pki_t *)CVM_DRV_GET_PTR(list->addr - 8);
			}
			break;
		case CVM_GATHER_DATA:
			list = (cvmx_buf_ptr_pki_t *)CVM_DRV_GET_PTR(lptr.addr);
			DBG_PRINT(DBG_FLOW, "cvm_pci_dma: gptr @ 0x%p\n", list);
			DBG_PRINT(DBG_FLOW, "gather list contents\n");
			for(i = 0; i < segs; i++, local_ptr++) {
				if(list[i].size > MAX_PCI_DMA_LOCAL_BUF_SIZE)
					return -1;

				local_ptr->u64 = (list[i].u64 & CVM_PCI_DMA_LOCAL_PTR_MASK_O3);
				local_ptr->cn78xx.i = 1;

				total_bytes    += local_ptr->cn78xx.size;
				DBG_PRINT(DBG_FLOW, "gather list[%d]: 0x%llx\n", i, cast64(list[i].u64));
			}
			break;
		case CVM_NULL_DATA:  /* Nothing to do here/. */
			break;
	}
	CVMX_SYNCWS;
	return total_bytes;
}




/*-------------------------- FUNCTION PROTOTYPES ---------------------------*/

/** Core: Initialize a PCI DMA instruction chunk. This routine allocates the
 *  first chunk for each DMA instruction queue and writes the chunk addr,
 *  maximum writeable space in chunk to CSR. It also allocates extra chunk for
 *  fast chaining.
 *  @return Success: 0; Failure: 1.
 */
int  cvm_dma_queue_init(cvm_oct_dev_t  *oct);







/**  Core: This routines creates a PCI DMA instruction based on information in
 *   the DMA header and local and remote pointers and buffer sizes passed to it.
 *   Applications have more control over the DMA operation when using this API.
 *   This function can be called for INBOUND & OUTBOUND operations only for all
 *   variants of Octeon.
 *
 *   @param  dma_hdr  -  the DMA instruction header.
 *   @param  lptr     -  list of local  data pointers.
 *   @param  rptr     -  list of remote (host/peer) addresses.
 *   @return Success: 0; Failure: -ENOMEM, -EINVAL.
 */
int
cvm_pci_dma_raw(cvmx_oct_pci_dma_inst_hdr_t      *dma_hdr,
                cvmx_oct_pci_dma_local_ptr_t     *lptr,
                cvm_dma_remote_ptr_t             *rptr);



/**  Core: This routines creates a PCI DMA instruction based on information in
 *   the DMA header and local and remote pointers and buffer sizes passed to it.
 *   Applications have more control over the DMA operation when using this API.
 *   This function can be called for INBOUND & OUTBOUND operations.
 *   For CN56XX & CN63xx, an application can also achieve INTERNAL-ONLY or
 *   EXTERNAL-ONLY operations using this API.
 *   Based on the DMA type specified, the firstptrs and lastptrs will be
 *   interpreted differently. In all cases, the pointers from the firstptrs
 *   list will be copied into the DMA instruction chunk, followed by the 
 *   pointers in the lastptrs list.
 *
 *   @param  q_no      -  The PCI DMA queue to use for this DMA operation.
 *                        The DMA instruction header does not have a field for
 *                        the queue to be used. So this is passed separately for
 *                        CN56XX & CN63XX.
 *   @param  dma_hdr   -  the DMA instruction header.
 *   @param  firstptrs -  first set of pointers.
 *   @param  lastptrs  -  second set of pointers.
 *   @return Success: 0; Failure: -ENOMEM, -EINVAL.
 */
int
cvm_pcie_dma_raw(int                              q_no,
                 cvmx_oct_pci_dma_inst_hdr_t     *dma_hdr,
                 void                            *firstptrs,
                 void                            *lastptrs);



/** Core: Write data to host or PCI-Express memory using Octeon PCI DMA engine.
  * @param cmd  - describes the DMA operation. See cvm_pci_dma_cmd_t for
  *               description of fields. 
  * @param lptr - list of addresses in Octeon local memory (max 15).
  * @param rptr - list of addresses in host/PCI-E memory (max 15).
  * @return Success: 0; Failure: -ENOMEM, -EINVAL. 
  */
int
cvm_pci_dma_send_data(cvm_pci_dma_cmd_t     *cmd,
                      cvmx_buf_ptr_t        *lptr, 
                      cvm_dma_remote_ptr_t  *rptr);



/** Core: Read data from host or PCI-Express memory using Octeon PCI DMA engine.
  * @param cmd  - describes the DMA operation. See cvm_pci_dma_cmd_t for
  *               description of fields. 
  * @param lptr - list of addresses in Octeon local memory (max 15).
  * @param rptr - list of addresses in host/PCI-E memory (max 15).
  * @return Success: 0; Failure: -ENOMEM, -EINVAL. 
  */
int
cvm_pci_dma_recv_data(cvm_pci_dma_cmd_t     *cmd,
                      cvmx_buf_ptr_t        *lptr, 
                      cvm_dma_remote_ptr_t  *rptr);




/** Core: Routine for OCT-III models.
  * Write data to host or PCI-Express memory using Octeon PCI DMA engine.
  * @param cmd  - describes the DMA operation. See cvm_pci_dma_cmd_t for
  *               description of fields. 
  * @param lptr - list of addresses in Octeon local memory (max 15).
  * @param rptr - list of addresses in host/PCI-E memory (max 15).
  * @param pool - pool to free the buffers.
  * @return Success: 0; Failure: -ENOMEM, -EINVAL. 
  */
int
cvm_pci_dma_send_data_o3(cvm_pci_dma_cmd_t      *cmd,
                      cvmx_buf_ptr_pki_t        *lptr, 
                      cvm_dma_remote_ptr_t      *rptr,
                      cvmx_wqe_t  *wqe,
		      int	ibit);

/** Core: Routine for OCT-III models.
  * Read data from host or PCI-Express memory using Octeon PCI DMA engine.
  * @param cmd  - describes the DMA operation. See cvm_pci_dma_cmd_t for
  *               description of fields. 
  * @param lptr - list of addresses in Octeon local memory (max 15).
  * @param rptr - list of addresses in host/PCI-E memory (max 15).
  * @return Success: 0; Failure: -ENOMEM, -EINVAL. 
  */
int
cvm_pci_dma_recv_data_o3(cvm_pci_dma_cmd_t     *cmd,
                      cvmx_buf_ptr_pki_t       *lptr, 
                      cvm_dma_remote_ptr_t  *rptr);

/**  Core: Routine for OCT-III models.
 *   This routines creates a PCI DMA instruction based on information in
 *   the DMA header and local and remote pointers and buffer sizes passed to it.
 *   Applications have more control over the DMA operation when using this API.
 *   This function can be called for INBOUND & OUTBOUND operations.
 *   For CN56XX & CN63xx, an application can also achieve INTERNAL-ONLY or
 *   EXTERNAL-ONLY operations using this API.
 *   Based on the DMA type specified, the firstptrs and lastptrs will be
 *   interpreted differently. In all cases, the pointers from the firstptrs
 *   list will be copied into the DMA instruction chunk, followed by the 
 *   pointers in the lastptrs list.
 *
 *   @param  q_no      -  The PCI DMA queue to use for this DMA operation.
 *                        The DMA instruction header does not have a field for
 *                        the queue to be used. So this is passed separately for
 *                        CN56XX & CN63XX.
 *   @param  dma_hdr   -  the DMA instruction header.
 *   @param  firstptrs -  first set of pointers.
 *   @param  lastptrs  -  second set of pointers.
 *   @return Success: 0; Failure: -ENOMEM, -EINVAL.
 */
int
cvm_pcie_dma_raw_o3(int                              q_no,
                 cvmx_oct_pci_dma_inst_hdr_t     *dma_hdr,
                 void                            *firstptrs,
                 void                            *lastptrs);


/** Core: Function to get a completion pointer from core driver pool.
 *        The application would use the comp_byte in the structure as a 
 *        completion word for PCI DMA.
 * @return Success: Pointer to completion byte; Failure: NULL.
 */
cvm_dma_comp_ptr_t *    cvm_get_dma_comp_ptr(void);


/** Core: Function to free completion pointer to core driver pool.
 */
void    cvm_release_dma_comp_ptr(cvm_dma_comp_ptr_t *ptr);




/** Core: Wrapper around the cvm_pci_dma_raw() function.
 *        cvm_pci_dma_send_direct() existed in older releases and may be
 *        removed in the future.
 */
static inline int
cvm_pci_dma_send_direct(cvmx_oct_pci_dma_inst_hdr_t      *dma_hdr,
                        cvmx_oct_pci_dma_local_ptr_t     *lptr,
                        cvm_dma_remote_ptr_t             *rptr)
{
	return cvm_pci_dma_raw(dma_hdr, lptr, rptr);
}



void    cn56xx_setup_dma_intr_threshold(int q_no);

/* Parse and print the contents of the 64-bit PCI DMA header. */
void cvm_pci_dma_print_header(cvmx_oct_pci_dma_inst_hdr_t  *dmahdr);

uint16_t cvm_pcie_pvf_num(cvmx_wqe_t  *wqe);

void
cvm_drv_debug_print_dmaq(int q_no);


#endif  /*  __CVM_PCI_DMA_H__ */

/* $Id$ */
