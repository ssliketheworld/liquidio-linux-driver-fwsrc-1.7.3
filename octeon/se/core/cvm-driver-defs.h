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



/*! \file cvm-driver-defs.h
    \brief Core Driver: Debug macros and wqe manipulation.
           Include this file in all applications.
*/


#ifndef __CVM_DRIVER_DEFS_H__
#define __CVM_DRIVER_DEFS_H__

#include "cvmx-config.h"
#include "executive-config.h"
#include "cvmx.h"
#include "cvmx-fpa.h"
#include "cvmx-npi.h"
#include "cvmx-pko.h"
#include "cvmx-pip.h"
#include "cvmx-ipd.h"
#include "cvmx-malloc.h"
#include "cvmx-scratch.h"
#include "cvmx-bootmem.h"
#include "cvmx-spinlock.h"
#include "cvmx-version.h"
#include "cvmx-helper.h"
#include "cvmx-helper-util.h"
#include "cvmx-fau.h"

#ifndef __CAVIUM_LITTLE_ENDIAN
#define __CAVIUM_LITTLE_ENDIAN 1234
#endif

#ifndef __CAVIUM_BIG_ENDIAN
#define __CAVIUM_BIG_ENDIAN     4321
#endif

#ifdef __BYTE_ORDER
   #if __BYTE_ORDER == __LITTLE_ENDIAN
   #define __CAVIUM_BYTE_ORDER __CAVIUM_LITTLE_ENDIAN
   #define __CAVIUM_LITTLE_ENDIAN_BITFIELD 
   #else
   #define __CAVIUM_BYTE_ORDER __CAVIUM_BIG_ENDIAN
   #define __CAVIUM_BIG_ENDIAN_BITFIELD 
   #endif
#else
#error __BYTE_ORDER undefined
#endif

typedef uint8_t  u8;
typedef int8_t   s8;
typedef uint16_t u16;
typedef int16_t  s16;
typedef uint32_t u32;
typedef int32_t  s32;
typedef uint64_t u64;
typedef int64_t  s64;

#include "cvm-drv-debug.h"

/* OCTEON - III Supports Max of 48 cores */
#define MAX_DRV_CORES			48

/* In order to use PCIe port #1, set this macro to 1 */
#define OCTEON_PCIE_PORT        0 //1

/* Driver header files inserted below. */

/** Debug levels for driver prints. */
#define DBG_ALL       7
#define DBG_STRUCT    6
#define DBG_NORM      4
#define DBG_FLOW      3
#define DBG_WARN      2
#define DBG_ERROR     1
#define DBG_CRIT      0

#define DBG_TEMP      0

#define PTR_SIZE   (sizeof(void*))



#define   cast64(val)    ((unsigned long long)val)

#define  castptr(type, val)    ((type)((unsigned long)val))



/** Print debug messages.
 *
 *  @param lvl    - debug level at which to print this message.
 *  @param format - format to use to print the message.
 *  @param args   - variable length arg list to create the message.
 */
#ifdef OCTEON_DEBUG_LEVEL
#define DBG_PRINT(lvl, format, args...) \
{ \
    if (lvl <= OCTEON_DEBUG_LEVEL) \
    { \
        printf("[ DRV ]"); \
        printf(format, ##args); \
    } \
}
#else
#define DBG_PRINT(lvl, format, args...)  do{ }while(0)
#endif

#if OCTEON_DEBUG_LEVEL == 7
#define DBG_DUMP_PACKET(wqe) do { \
		unsigned char *p; \
		int i, len=cvmx_wqe_get_len(wqe); \
		p= (unsigned char *)CVM_DRV_GET_PTR(wqe->packet_ptr.s.addr); \
		for (i=0; i < len; i++, p++) { \
			printf("%02x ", *p); \
			if (!((i+1) % 16)) printf("\n"); \
		} \
		printf("\n"); \
	} while (0)
#else
#define DBG_DUMP_PACKET(wqe) 
#endif



#define drv_err(format, args...)    printf(format, ##args)

//#define dbg_printf(format, ...)    printf( format, ## __VA_ARGS__)

#define dbg_printf(format, ...)    do { } while(0)


#ifndef ROUNDUP4
#define ROUNDUP4(val) (((val) + 3)&0xfffffffc)
#endif

#ifndef ROUNDUP8
#define ROUNDUP8(val) (((val) + 7)&0xfffffff8)
#endif

#ifndef ROUNDUP16
#define ROUNDUP16(val) (((val) + 15)&0xfffffff0)
#endif

#ifndef ROUNDUP32
#define ROUNDUP32(val) (((val) + 31)&0xffffffe0)
#endif

#ifndef ROUNDUP64
#define ROUNDUP64(val) (((val) + 63)&0xffffffc0)
#endif


/**
 getstructptr - get the address of structure given the address of a member
  Params:
        ptr: the pointer to the member.
       type: the type of the struct this ptr is a member.
     member: the name of the member within the struct.
*/
#define getstructptr(ptr, type, member)                   \
	 (type *)( (char *)ptr - offsetof(type,member) )



#define   CVM_DRV_GET_PHYS(ptr)         (cast64(cvmx_ptr_to_phys(ptr)))
#define   CVM_DRV_GET_PTR(phys_addr)    cvmx_phys_to_ptr((phys_addr))



/* liquidio_common should be included after the endianness has been set. */
#include "octeon_config.h"
#include "liquidio_common.h"
#include "cvm-pci.h"
#include "cvm-pci-pko.h"
#include "cvm-pci-dma.h"
#include "cvm-drv-reqresp.h"


#ifdef  CVM_SPINLOCK_DEBUG

static inline void
cvm_drv_spinlock_trylockloop(cvmx_spinlock_t  *lockp)
{
   volatile uint32_t lock_loops=0;
   while(cvmx_spinlock_locked(lockp) && (lock_loops++ < 1000));
   if(lock_loops == 1000)
      printf("[ DRV ] Spinlock @ %p failed at %s: %d \n",lockp, __FILE__, __LINE__);
   cvmx_spinlock_lock(lockp);
}

#define  cvm_drv_spinlock_lock(lockp)                 cvm_drv_spinlock_trylockloop(lockp);

#else

#define  cvm_drv_spinlock_lock(lockp)                 cvmx_spinlock_lock(lockp);

#endif


#define cvm_drv_fpa_alloc_sync(pool)                 \
		cvmx_fpa_alloc((pool))

#define cvm_drv_fpa_free(ptr, pool, cache_lines)     \
		cvmx_fpa_free((ptr), (pool), (cache_lines))

static inline void
cvm_drv_free_pkt_buffer(cvmx_buf_ptr_t  pkt)
{
	void  *buf;

	buf = (void *)CVM_DRV_GET_PTR((((uint64_t)pkt.s.addr >> 7) - pkt.s.back) << 7);
	DBG_PRINT(DBG_FLOW,"Freeing pkt buf @ %p (pkt: 0x%016lx)\n", buf, pkt.u64);
	cvm_drv_fpa_free(buf, pkt.s.pool, 0);
}





/** Core: Call this routine to free the packet buffers in a work queue entry (WQE).
  * The packet pointer is made NULL and buf count is 0 in the WQE when this routine
  * returns.
  * @param wqe - the wqe whose buffers are to be freed.
  */
static inline void
cvm_free_wqe_packet_bufs(cvmx_wqe_t  *wqe)
{
	cvmx_helper_free_packet_data(wqe);

	CVMX_SYNCWS;
}





/** Core: Free a work queue entry (WQE) and its buffers received from the
 *  hardware. 
 *  @param  wqe - work queue entry buffer to be freed.
 *  Frees a work queue entry and its packet data buffer.
 */
static inline void
cvm_free_host_instr(cvmx_wqe_t    *wqe)
{
#ifdef OVS_IPSEC
   uint8_t is_packet_outside;
#endif

   if(wqe == NULL) {
      printf("[ DRV ]: cvm_free_host_instr: NULL WQE\n");
      return;
   }

   DBG_PRINT(DBG_FLOW,"--free_host_instr, wqe @ %p, pkt @ %llx-\n",
             wqe, cast64(wqe->packet_ptr.s.addr));

#ifdef OVS_IPSEC
   is_packet_outside = cvmx_wqe_get_pki_pkt_ptr(wqe).packet_outside_wqe;
#endif
   cvm_free_wqe_packet_bufs(wqe);

   /* For 78xx above routine frees the WQE also.
    *
    * Clarification: the above routine frees all the packet buffers.
    * SINCE we've configured the chip to place the WQE in the first
    * packet buffer, we do not need to free the WQE separately. 
    */

   /* SDK API to free the wqe for OCTEON-II models */
   if (!octeon_has_feature(OCTEON_FEATURE_CN78XX_WQE)) {
   	DBG_PRINT(DBG_FLOW,"Freeing wqe @ 0x%p \n",wqe);
   	cvmx_wqe_free(wqe);
   }

#ifdef OVS_IPSEC
   if(cvmx_unlikely(is_packet_outside))
	cvmx_wqe_free(wqe);
#endif
}


#define  cvm_free_wqe_and_pkt_bufs(wqe) cvm_free_host_instr((wqe))


typedef union {
    uint64_t   u64;
    struct {
#if __BYTE_ORDER == __LITTLE_ENDIAN
       uint64_t   tag:32;        /**< 31-00 Tag for the Packet. */
       cvmx_pow_tag_type_t tt:2; /**< 33-32 Tagtype */
       uint64_t   rs:1;          /**< 34    Is the PCI packet a RAW-SHORT? */
       uint64_t   grp:4;         /**< 38-35 The group that gets this Packet */
       uint64_t   qos: 3;        /**< 41-39 The QOS set for this Packet. */
       uint64_t   fsz:6;
       uint64_t   dlengsz:14;
       uint64_t   gather:1;
       uint64_t   r:1;           /**< 63    Is the PCI packet in RAW-mode? */
#else
       uint64_t   r:1;           /**< 63    Is the PCI packet in RAW-mode? */
       uint64_t   gather:1;
       uint64_t   dlengsz:14;
       uint64_t   fsz:6;
       uint64_t   qos: 3;        /**< 41-39 The QOS set for this Packet. */
       uint64_t   grp:4;         /**< 38-35 The group that gets this Packet */
       uint64_t   rs:1;          /**< 34    Is the PCI packet a RAW-SHORT? */
       cvmx_pow_tag_type_t tt:2; /**< 33-32 Tagtype */
       uint64_t   tag:32;        /**< 31-00 Tag for the Packet. */
#endif
    } s;
} cvm_pci_host_inst_hdr_t;



/* PCI Command in the Instruction Queue */
struct octeon_instr_32B {

  uint64_t                   dptr;
  cvm_pci_host_inst_hdr_t    ih;
  uint64_t                   rptr;
  cvmx_pci_inst_irh_t        irh;

};




#endif

/* $Id$ */
