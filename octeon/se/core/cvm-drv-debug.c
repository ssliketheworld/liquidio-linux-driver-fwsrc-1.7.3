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

#include "cvm-driver-defs.h"
#include "cvm-drv-debug.h"


#define  MAX_DEBUG_FN    16

/* Array of pointers to debug functions. */
void (*cvm_drv_dbg_fn_list[MAX_DEBUG_FN])(void *);
/* Array of void * arguments to pass to the above functions. */
void *cvm_drv_dbg_fn_arg_list[MAX_DEBUG_FN];
/* Number of functions currently registered. */
int cvm_drv_dbg_fn_count=0;


#ifdef CVM_DRV_SANITY_CHECKS
#define MAX_DBG_PTR_CNT  128 
CVMX_SHARED  uint64_t  dbg_lptrs[MAX_DBG_PTR_CNT];
CVMX_SHARED  uint64_t  dbg_lptr_cnt=0;
CVMX_SHARED  uint64_t  dbg_lptr_rollover=0;
CVMX_SHARED  uint64_t  dbg_rptrs[MAX_DBG_PTR_CNT];
CVMX_SHARED  uint64_t  dbg_rptr_cnt=0;
CVMX_SHARED  uint64_t  dbg_rptr_rollover=0;

void 
cvm_drv_reset_dbg_ptr_cnt(void)
{
  dbg_lptr_cnt = 0;
  dbg_rptr_cnt = 0;
}

void
cvm_drv_add_dbg_lptr(uint64_t  ptr)
{
   dbg_lptrs[dbg_lptr_cnt++] =  ptr;
   if(dbg_lptr_cnt == MAX_DBG_PTR_CNT) {
      dbg_lptr_rollover=1;
      dbg_lptr_cnt = 0; 
   }
}



void
cvm_drv_add_dbg_rptr(uint64_t  ptr)
{
   dbg_rptrs[dbg_rptr_cnt++] =  ptr;
   if(dbg_rptr_cnt == MAX_DBG_PTR_CNT) {
      dbg_rptr_rollover=1;
      dbg_rptr_cnt = 0; 
   }
}


void
cvm_drv_print_dbg_lptr(void)
{
   int i,cnt;
   printf("\n--- Debug local pointers ---\n");
   cnt = (dbg_lptr_rollover)?MAX_DBG_PTR_CNT:dbg_lptr_cnt;
   if(dbg_lptr_rollover) 
     printf("Rollover occured. idx at %lu now\n", dbg_lptr_cnt);
   for(i = 0; i < cnt; i++) {
      printf("dbg_lptrs[%d]: 0x%016lx\n", i, dbg_lptrs[i]);
   }
}


void
cvm_drv_print_dbg_rptr(void)
{
   int i, cnt;
   printf("\n--- Debug remote pointers ---\n");
   cnt = (dbg_rptr_rollover)?MAX_DBG_PTR_CNT:dbg_rptr_cnt;
   if(dbg_rptr_rollover) 
     printf("Rollover occured. idx at %lu now\n", dbg_rptr_cnt);
   for(i = 0; i < cnt; i++) {
      printf("dbg_rptrs[%d]: 0x%016lx\n", i, dbg_rptrs[i]);
   }
}


void
cvm_drv_print_dbg_ptrs(void)
{
   cvm_drv_print_dbg_lptr();
   cvm_drv_print_dbg_rptr();
}
#endif



void
cvm_drv_print_data(void *udata, uint32_t size)
{
  uint32_t   i, j;
  uint8_t   *data = (uint8_t *)udata;

  printf("---   Printing %d bytes at %p\n", size, udata);
  j = 0;
  for(i = 0; i < size; i++) {
    printf(" %02x", data[i]);
    if((i & 0x7) == 0x7) {
      printf(" << %d - %d\n", j, i);
      j = i+1;
    }
  }
  printf("\n");
}
                                                                                                
void
cvm_drv_print_wqe(cvmx_wqe_t  *wqe)
{
	int len = cvmx_wqe_get_len(wqe);

    printf("\n------ PRINT WQE @ %p------\n", wqe);
    printf("swp: unused: 0x%x tag: 0x%x, tt: 0x%x iprt: 0x%x \n",
       cvmx_wqe_get_unused8(wqe), (uint32_t)wqe->word1.tag, (uint32_t)wqe->word1.tag_type, cvmx_wqe_get_port(wqe));
    printf("wqe->pkt_ptr: 0x%016llx (addr: 0x%llx size: %d)\n",
	       cast64(wqe->packet_ptr.u64), cast64(wqe->packet_ptr.s.addr), wqe->packet_ptr.s.size);
    printf("segs: %d len: %d\n", wqe->word2.s.bufs, len);
    printf("WQE Header - 4 64-bit Words\n");
    cvm_drv_print_data(wqe, 32);
    printf("WQE Data Payload - first 64 bytes\n");
    cvm_drv_print_data(((uint8_t *)wqe + 32), 64);
    if(wqe->packet_ptr.s.addr) {
       if(len > 128) len = 128;
       printf("WQE Packet Ptr - first %d bytes\n", len);
       cvm_drv_print_data(CVM_DRV_GET_PTR(wqe->packet_ptr.s.addr), len);
    }
    printf("\n------ PRINT WQE @ %p DONE------\n", wqe);
}



char *
cvm_drv_get_tag_type(int tt)
{
	switch(tt) {
		case CVMX_POW_TAG_TYPE_ORDERED: return "Ordered";
		case CVMX_POW_TAG_TYPE_ATOMIC:  return "Atomic";
		case CVMX_POW_TAG_TYPE_NULL:    return "Null";
		case CVMX_POW_TAG_TYPE_NULL_NULL: return "Null-Null";
		default: return "Invalid";
	}
	return "";
}

void
cvm_drv_print_pci_instr(cvmx_raw_inst_front_t     *front)
{
#if 0
	printf("\n--- Printing PCI Instruction\n");

	printf("IH: 0x%016llx\n    ", cast64(front->ih.u64));
	if(front->ih.s.r) printf("RAW ");
	if(front->ih.s.rs) printf("SHORT ");
	printf("PM: %d ", front->ih.s.pm);
	printf("SL: %d ", front->ih.s.sl);
	printf("GRP: %d ", front->ih.s.grp);
	printf("QOS: %d ", front->ih.s.qos);
	printf("TAG: 0x%08x (%s)\n", front->ih.s.tag,
	       cvm_drv_get_tag_type(front->ih.s.tt));

	printf("IRH: 0x%016llx\n    ", cast64(front->irh.u64));
	printf("Opcode: 0x%04x ", front->irh.s.opcode);
	printf("Param: 0x%02x ", front->irh.s.param);
	printf("Flag: %d ", front->irh.s.flag);
	printf("RLen: %d ", front->irh.s.rlenssz);

	printf("RPTR: 0x%016llx\n", cast64(front->rptr));
	printf("\n");
#endif
}

  


int
cvm_drv_register_debug_fn(void (*fn)(void *), void *arg)
{
   if(cvm_drv_dbg_fn_count == MAX_DEBUG_FN) {
       printf("[ DRV ]: Reached maximum allowed debug functions\n");
       return 1;
   }
   cvm_drv_dbg_fn_list[cvm_drv_dbg_fn_count]       = fn;
   cvm_drv_dbg_fn_arg_list[cvm_drv_dbg_fn_count++] = arg;
   return 0;
}



void
cvm_drv_debug_fn(void)
{
   int i;

   for(i = 0; i < cvm_drv_dbg_fn_count; i++) {
       (*cvm_drv_dbg_fn_list[i])(cvm_drv_dbg_fn_arg_list[i]);
   }
}










static inline void
__print_dbgselect_data(uint32_t dbgsel)
{
	volatile uint64_t   dbg;

	cvmx_write_csr(CVMX_PEXP_SLI_DBG_SELECT, dbgsel);
	CVMX_SYNCWS;
	dbg = cvmx_read_csr(CVMX_PEXP_SLI_DBG_SELECT);
	CVMX_SYNCWS;
	dbg = cvmx_read_csr(CVMX_PEXP_SLI_DBG_DATA);
	printf("DbgSelect: %x  DbgValue: 0x%08x\n", dbgsel, (uint32_t)(dbg & 0xffff));
}





static inline void
__print_dbgselect_in_range(uint32_t   start,
                           uint32_t   end,
                           int        offset)
{
	uint32_t  dbgsel = start;
	while(dbgsel <= end) {
		__print_dbgselect_data(dbgsel);
		dbgsel += offset;
	}
}



void
dump_dbgselect(void)
{
	__print_dbgselect_in_range(0x1f000000, 0x1f000032, 1);

	__print_dbgselect_in_range(0xdf000000, 0xdf000005, 1);

	__print_dbgselect_in_range(0xdf200000, 0xdf20001d, 1);

	__print_dbgselect_in_range(0xdf201000, 0xdf201001, 1);

	__print_dbgselect_in_range(0xdf203000, 0xdf2030f8, 8);

	__print_dbgselect_in_range(0xdf203001, 0xdf2030f9, 8);

	__print_dbgselect_in_range(0xdf203002, 0xdf2030fa, 8);

	__print_dbgselect_in_range(0xdf203003, 0xdf2030fb, 8);

	__print_dbgselect_in_range(0xdf203004, 0xdf2030fc, 8);

	__print_dbgselect_in_range(0xdf203005, 0xdf2030fd, 8);

	__print_dbgselect_in_range(0xdf203100, 0xdf2031f8, 8);

	__print_dbgselect_in_range(0xdf203101, 0xdf2031f9, 8);

	__print_dbgselect_in_range(0xdf203103, 0xdf2031fb, 8);

	__print_dbgselect_in_range(0xdf203104, 0xdf2031fc, 8);

	__print_dbgselect_in_range(0xdf203105, 0xdf2031fd, 8);

	__print_dbgselect_in_range(0xdf20300a, 0xdf2030fa, 0x10);

	__print_dbgselect_in_range(0xdf300000, 0xdf300090, 0x10);

	__print_dbgselect_in_range(0xdf300001, 0xdf300031, 0x10);

	__print_dbgselect_in_range(0xdf300002, 0xdf300032, 0x10);

	__print_dbgselect_in_range(0xdf400000, 0xdf400000, 1);

	__print_dbgselect_in_range(0xdf500000, 0xdf500000, 1);

	__print_dbgselect_in_range(0xdf600001, 0xdf600006, 1);

	__print_dbgselect_in_range(0xdf700001, 0xdf700002, 1);

	__print_dbgselect_in_range(0xdf800001, 0xdf800007, 1);

	__print_dbgselect_in_range(0xdf800010, 0xdf800010, 1);

	__print_dbgselect_in_range(0xdf900000, 0xdf900000, 1);

}

/* $Id$ */

