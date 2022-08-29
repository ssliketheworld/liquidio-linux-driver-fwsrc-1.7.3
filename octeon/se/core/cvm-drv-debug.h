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




/*!  \file cvm-drv-debug.h
     \brief Core driver:  debug and sanity check routines.
*/

#ifndef __CVM_DRV_DEBUG_H__
#define __CVM_DRV_DEBUG_H__

#include "cvmx.h"
#include "cvmx-fpa.h"
#include "cvmx-wqe.h"
#include "cvm-pci.h"


void    cvm_drv_print_data(void *udata, uint32_t size);
void    cvm_drv_print_wqe(cvmx_wqe_t  *wqe);
void    cvm_drv_print_pci_instr(cvmx_raw_inst_front_t *front);

void    dump_dbgselect(void);

#ifdef OCTEON_DEBUG_LEVEL
#define DBG_print_data(data, size) cvm_drv_print_data(data, size)
#define DBG_print_wqe(wqe) cvm_drv_print_wqe(wqe)
#else
#define DBG_print_data(data, size)
#define DBG_print_wqe(wqe)
#endif

#define cvm_drv_init_debug_fn_list()   CAVIUM_INIT_LIST_HEAD(&cvm_drv_fn_list)

int cvm_drv_register_debug_fn(void (*fn)(void *), void *arg);

#ifdef CVM_DRV_SANITY_CHECKS
void  cvm_drv_add_dbg_lptr(uint64_t ptr);
void  cvm_drv_add_dbg_rptr(uint64_t ptr);
void  cvm_drv_print_dbg_lptr(void);
void  cvm_drv_print_dbg_rptr(void);
void  cvm_drv_print_dbg_ptrs(void);
void  cvm_drv_reset_dbg_ptr_cnt(void);
#else
#define cvm_drv_add_dbg_lptr(ptr)      do { }while(0);
#define cvm_drv_add_dbg_rptr(ptr)      do { }while(0);
#define cvm_drv_print_dbg_lptr()       do { }while(0);
#define cvm_drv_print_dbg_rptr()       do { }while(0);
#define cvm_drv_print_dbg_ptrs()       do { }while(0);
#define cvm_drv_reset_dbg_ptr_cnt()    do { }while(0);
#endif



void cvm_drv_debug_fn(void);

#endif

/* $Id$ */

