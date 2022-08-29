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



/*! \file cvm-oct-dev.h
    \brief  Core Driver: Octeon device structure for core driver 
 */


#ifndef __CVM_OCT_DEV_H__
#define __CVM_OCT_DEV_H__

#include "liquidio_common.h"

/* CN63XX & CN68XX supports upto 8 queues.
   CN56XX supports upto 5 dma queues. We'll save space for the max.
   possible. */
#define   MAX_DMA_QS            8

/* Max number of cores in a 56xx */
#define   CN56XX_MAX_CORES           12



#define   CVM_DRV_INIT    1
#define   CVM_DRV_READY   2
#define   CVM_DRV_RESET   3

#define   CVM_DRV_PKO_STOP  0
#define   CVM_DRV_PKO_READY 1

#define MAX_OPCODES                   64 /* 7-bits */

//#define   DMA_CHUNK_LOCK_USE_TAG


#define   CVM_PCI_DMA_CHUNK_TAG(i)    (0x11001100 + i)


/** Core: The PCI DMA uses instruction chunks to read the DMA instructions
 *  posted by the driver. The chunks are a chained list of fixed-size
 *  buffers. This structure is used solely by the PCI core driver.
 */
typedef struct {

#ifdef  DMA_CHUNK_LOCK_USE_TAG
  uint32_t            tag;
  uint32_t            resvd_lock;
#else
  /** Lock to control access to this structure. */
  cvmx_spinlock_t     lock;
#endif

  /** Address of the current instruction chunk. */
  uint64_t            *buf;

  /** Size of chunk in the PCI DMA instruction chunked list. */
  uint32_t             chunk_size;

  /** The current offset into the current chunk where the next DMA
      instruction word is written by host. */
  uint32_t             current_word;

  /** Total words that can be written in the chunk's free space.  */
  uint32_t             total_free_words;

  /** Maximum words that can be written in this chunk. max_words = 
      (chunk_size / word_size(8 bytes)) - 1 (for next pointer). */
  uint32_t             max_words;

  uint64_t             doorbell_reg;

  /** An extra buffer allocated so that chunks can be quickly chained. */
  uint64_t             extra_buf;

  /** The pool from which the chunks are allocated by driver.
      The Hardware frees them to the same pool. */
  uint32_t             pool;

}  cvm_oct_dma_chunk_t;



/** Core: Software defined PCI DMA Completion byte pool buffer format. */ 
typedef struct {
	uint8_t   comp_byte;
	uint8_t   in_use;
} cvm_dma_comp_ptr_t;

/*
   Core driver allocates an array of type cvm_dma_comp_ptr_t as a free pool of
   completion pointer bytes. Application can call a function to get the next
   available comp_ptr_t. It can use the comp_byte as a completion byte to be
   passed to the DMA hardware. The in_use field is used by the core driver to
   keep track of the entries in the free pool.
*/

#define CVM_DMA_COMP_PTR_SIZE   (sizeof(cvm_dma_comp_ptr_t))

#define CVM_DMA_COMP_PTR_COUNT  1024
#define CVM_DMA_COMP_POOL_SIZE  (CVM_DMA_COMP_PTR_COUNT * CVM_DMA_COMP_PTR_SIZE)


/** Core: Structure to manage software defined Completion byte buffer pool. */
typedef  struct {

	/** Lock for the completion words free pool. */
	cvmx_spinlock_t         lock;

	/** The completion byte pool. */
	cvm_dma_comp_ptr_t     *list;

	/** The next entry in the completion byte free pool. */
	uint32_t                idx;

} cvm_oct_comp_ptr_pool_t;



/** Core: Octeon PKO port and queue numbers corressponding to Octeon PCI output
   queues. */
struct __cvm_pci_pko_qmap {

	uint8_t    active;
	uint8_t    rsvd[3];
	uint16_t   port;
	uint16_t   queue;
};


/** Core: Structure that maintains information for the Octeon device in the
	      core driver. */
typedef struct {

	/** Current core driver state */
	uint8_t                      state;

	/** Current software global PKO state */
	uint8_t                      pko_state;

	/** Clock ticks per microsecond. */
	uint16_t                     clocks_per_us;


	/** This octeon device's id. Given to Octeon by the host driver. */
	uint8_t                      dev_id;

	/** The interface number for the PCI ports */
	uint8_t                      npi_if;

	uint8_t                      reserved[3];


	/** Max DMA engines in this Octeon device. */
	uint8_t                      max_dma_qs;

	/** Max local pointers supported by this Octeon device DMA engine. */
	uint8_t                      max_lptrs;

	/** Max remote pointers supported by this Octeon device DMA engine. */
	uint8_t                      max_rptrs;

	/** Sum of local and remote pointers */
	uint8_t                      max_dma_ptrs;


	/** base DQ of Octeon PCI Output Queues */
	uint8_t                      pcipko_base_dq;

	struct __cvm_pci_pko_qmap   *pcipkomap;

	/** Address of the next chunk for each DMA engine. */
	cvm_oct_dma_chunk_t         *chunk[MAX_DMA_QS];

	/** Address of the completion byte software pool. */
	cvm_oct_comp_ptr_pool_t     *comp_ptr;

	/** Lookup table for opcodes. */
	int                         (*optable[MAX_OPCODES])(cvmx_wqe_t *);



	/** BAR0 PCI mapped address for this Octeon device. Provided by the host
	    driver. */
	uint64_t                     bar0_addr;

	/** BAR1 PCI mapped address for this Octeon device. Provided by the host
	    driver. */
	uint64_t                     bar1_addr;



	/** Application code (identifies type of app running on Octeon). */
	int                          app_code;

	/** spinlock that prevents concurrent access to SLI_PP_PKT_CSR_CONTROL
	    register */
	cvmx_spinlock_t              pp_pkt_csr_ctrl_lock;

	/** lookup table that maps DPI ring number (drn) to physical/virtual
	    function number (pvfn) */
	uint16_t                     lut_drn_to_pvfn[128];

#define	MAX_NUM_PFS	2
	uint16_t                     pf_started[MAX_NUM_PFS];

	uint64_t                     pci_mem_subdid_base;

	cvmx_spinlock_t              mem_access_lock;
} cvm_oct_dev_t;



#define  cvm_oct_dev_get_chunk_ptr(oct, chunk_no)	\
	(chunk_no < oct->max_dma_qs)?(oct->chunk[chunk_no]):NULL)



int octdev_get_device_id(void);
int octdev_max_dma_localptrs(void);
int octdev_max_dma_remoteptrs(void);
int octdev_max_dma_sumptrs(void);
int octdev_get_state(void);
int octdev_get_pko_state(void);
#ifdef CN56XX_PEER_TO_PEER
int octdev_get_max_peers(void);
#endif


#endif

/* $Id$ */



