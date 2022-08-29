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



/*! \file cvm-drv.h
    \brief  Core Driver: Initialization and instruction processing. 
 */


#ifndef __CVM_DRV_H__
#define __CVM_DRV_H__

#include "cvm-driver-defs.h"

#define RED_LOW_WMARK       (512)
#define RED_HIGH_WMARK      (3 * 1024)

/* OPCODES used with OPCODE_CORE. Work backwards from max value */
#define CORE_MEM_MAP_OP             0x3f
#define HOT_RESET_OP                0x3e
#define DEVICE_STOP_OP              0x3d
#define DEVICE_START_OP             0x3c
#define PCIE_MAP_OP                 0x3b

/* These opcodes are used in test packets sent to the core application
   in base module. */
#define CVMCS_REQRESP_OP            0x3a
#define CVMCS_DMA_OP                0x2f
#define CVMCS_REQRESP_COMP_OP       0x2e

/* For CN56XX Peer to Peer test packet */
#define EP_TO_EP_OP                 0x2d

/* These two subcodes are used by the base application to send test packets
 * on Output queues. */
#define DROQ_PKT_OP1                0x2c
#define DROQ_PKT_OP2                0x2b

/* Values in param field for DEVICE_START/STOP_OP */
#define  DEVICE_IPD                 0x1
#define  DEVICE_PKO                 0x2


/** Core: The application should call this routine when its doing its per-core
  * local initialization. This routine sets up the scratchpad registers
  * used by the driver.
  */
void
cvm_drv_local_init(void);




/** Core: The application should call this routine when it's doing global
  * initialization from only one of the cores its running on. This routines
  * sets up the PCI ports.
  *
  */
int
cvm_drv_init(void);


int cvm_drv_start_pf(int pf_num, int num_gmx_ports, int max_nic_ports);
int cvm_drv_start_pfs(int num_gmx_ports, int max_nic_ports);

void cvm_drv_restart_pf(int pf_num);

/** Core: This routine sends a notification to the host driver is ready to
  * accept instructions. The application should call this from only one of
  * its cores.
  * 
  */
int
cvm_drv_start(int ngmxports, int max_nic_ports);


/** Core: Common routine to parse all driver instructions. This routine looks
  * up the opcode to find a handler that's registered for this opcode.
  * If no handler is found, the wqe is freed. If a handler was found,
  * the handler is called with the WQE. The handler is expected to free
  * the WQE after its processing.
  *
  * @param  wqe - the work queue entry that contains the instruction.
  * @return  0 if a handler is found for the opcode; else 1.
  */
int
cvm_drv_process_instr(cvmx_wqe_t   *wqe);





/** Core: Register a handler for an opcode. When the driver sees the
 * opcode/subcode, it will call the function registered for the opcode/subcode.
 *  @param opcode - register this opcode.
 *  @param subcode - register this subcode.
 *  @param handler - register this function. Call it with the WQE pointer
 *                   when a raw instruction with the opcode above is received.
 *  @return 0 if the handler was registered successfully, else 1.
 */
int
cvm_drv_register_op_handler(uint16_t opcode, uint16_t subcode, int (*handler)(cvmx_wqe_t *));




/** Core: Sets the application type. The application type registered by this call
 *  is passed to the host when the core driver sends the start notification
 *  in cvm_drv_start().  Application types are defined in liquidio_common.h
 *  @param app_mode: application type.
 */
void
cvm_drv_setup_app_mode(int app_mode);




void
cvm_56xx_pass2_update_pcie_req_num(void);

/* Implementation note:
 * whomever links to this module (i.e. the APP) can override this global.
 * This function ptr is used by 'cvm_drv_start_pf()' to determine when
 * the host has written the RINFO register.
 * If not present, the default behavior is to assume that the host has
 * written the RINFO register if the 'trs' field is !0.
 */
extern CVMX_SHARED int (*rinfo_set_by_host_fn)(int pf_num, uint64_t rinfo_raw);

/* Implementation note:
 * whomever links to this module (i.e. the APP) can override this global.
 * This function ptr, if non-null, will be invoked by 'cvm_drv_restart_pf()'.
 * This allows the application to be notified when the PF driver has been
 * stopped/reset.
 */
extern CVMX_SHARED void (*drv_restart_app_cb)(int pf_num);

#endif

/* $Id$ */
