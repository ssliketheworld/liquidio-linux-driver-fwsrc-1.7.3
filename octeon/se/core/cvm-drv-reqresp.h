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



/*! \file cvm-drv-reqresp.h
    \brief Core Driver: PCI instruction response routines.
*/

#ifndef  __CVM_DRV_REQRESP_H__
#define  __CVM_DRV_REQRESP_H__


/** Core: This routine is called to post a response to a PCI instruction when 
 *  the response will be sent to multiple host buffers. In other words, for
 *  scatter mode responses, use this API. The response header (ORH),
 *  status of instruction processing, the scatter list containing the host
 *  buffer addresses are passed to this function in a cvm_pci_scatter_resp_t
 *  structure. The response data and pointer to the raw instruction for which
 *  the response is being sent are passed as params. The function can be
 *  called in blocking/non-blocking mode. For non-blocking mode, it takes
 *  a pointer to a work queue entry which is scheduled in the POW when the
 *  DMA completes.
 *
 *  @param  action - specify DMA_BLOCKING/DMA_NON_BLOCKING
 *  @param  wqe    - For non-blocking mode, a pointer to a work queue entry
 *                   is passed here.
 *  @param  resp   - pointer to a cvm_pci_scatter_resp_t structure which
 *                   contains the scatter list, status & response header
 *  @param  lptr   - the local pointer to  response data.
 *  @param  local_segs   - number of local data segments in response data.
 *  @param  ptr_type - type of pointer for "lptr" (DIRECT/LINKED/GATHER)
 *
 *  @return Success: 0; Failure: -ENOMEM, -EINVAL. 
 */
int
cvm_drv_send_scatter_response(DMA_ACTION              action,
                              cvmx_wqe_t             *wqe,
                              cvm_pci_scatter_resp_t *resp,
                              cvmx_buf_ptr_t          lptr,
                              uint32_t                local_segs,
                              cvm_ptr_type_t          ptr_type);







/** Core: This routine is called to post a response to a PCI instruction when 
 *  the response will be sent to multiple host buffers. In other words, for
 *  scatter mode responses, use this API. The response header (ORH) and
 *  status of instruction processing are assumed to be part of the response
 *  data passed to this function. The scatter list containing the host
 *  buffer addresses are passed to this function in a cvm_pci_scatter_resp_t
 *  structure. The response data and pointer to the raw instruction for which
 *  the response is being sent are passed as params. The function can be
 *  called in blocking/non-blocking mode. For non-blocking mode, it takes
 *  a pointer to a work queue entry which is scheduled in the POW when the
 *  DMA completes.
 *
 *  @param  action - specify DMA_BLOCKING/DMA_NON_BLOCKING
 *  @param  wqe    - For non-blocking mode, a pointer to a work queue entry
 *                   is passed here.
 *  @param  resp   - pointer to a cvm_pci_scatter_resp_t structure which
 *                   contains the scatter list. The status & orh fields are
 *                   ignored her.
 *  @param  lptr   - the local pointer to  response data which includes the
 *                   response header (first 8 bytes) and status (last 8 bytes).
 *  @param  local_segs   - number of local data segments in response data.
 *  @param  ptr_type - type of pointer for "lptr" (DIRECT/LINKED/GATHER)
 *
 *  @return Success: 0; Failure: -ENOMEM, -EINVAL. 
 */
int
cvm_drv_send_scatter_response_direct(DMA_ACTION              action,
                                     cvmx_wqe_t             *wqe,
                                     cvm_pci_scatter_resp_t *resp,
                                     cvmx_buf_ptr_t          lptr,
                                     uint32_t                local_segs,
                                     cvm_ptr_type_t          ptr_type);





/** Core: Read a scatter list from the host memory.
 *
 *  @param  action - specify DMA_BLOCKING/DMA_NON_BLOCKING
 *  @param  host_hw_addr - Host memory address of scatter list
 *  @param  front - pointer to the PCI instruction.
 *  @param  sptr - address of local buffer to read in  the scatter list.
 *  @param  wqe    - For non-blocking mode, a pointer to a work queue entry
 *                   is passed here.
 *  @return Success:0 Failure: non-zero error value
 */
int
cvm_drv_read_scatter_list(DMA_ACTION              action,
                          uint64_t                host_hw_addr,
                          cvmx_raw_inst_front_t  *front,
                          struct octeon_sg_entry *sptr,
                          cvmx_wqe_t             *wqe);




/** Core: This routine is called to post a response to a PCI instruction when 
 *  the response will be sent to a single host buffer. The response data and
 *  pointer to the raw instruction for which the response is being sent are
 *  passed as params. The response header & status of instruction processing 
 *  are assumed to be part of the response data.
 *  The function can be called in blocking/non-blocking mode. For non-blocking
 *  mode, it takes a pointer to a work queue entry which is scheduled in the
 *  POW when the DMA completes.
 *
 *  @param  action - specify DMA_BLOCKING/DMA_NON_BLOCKING
 *  @param  front  - the RAW instruction from where the return address and
 *                   IRH are read.
 *  @param  lptr   - the local pointer to  response data.
 *  @param  segs   - number of local data segments in response data.
 *  @param  ptr_type - type of pointer for "lptr" (DIRECT/LINKED/GATHER)
 *  @param  wqe    - For non-blocking mode, a pointer to a work queue entry
 *                   is passed here.
 *
 *  @return Success: 0; Failure: -ENOMEM, -EINVAL. 
 */
int
cvm_drv_pci_instr_response_direct(DMA_ACTION               action,
                                  cvmx_raw_inst_front_t   *front,
                                  cvmx_buf_ptr_t           lptr,
                                  uint32_t                 segs,
                                  cvm_ptr_type_t           ptr_type,
                                  cvmx_wqe_t              *wqe);


/** Core: This routine is called to post a response to a PCI instruction when 
 *  the response will be sent to a single host buffer. The response header,
 *  status of instruction processing, the response data and pointer to the raw
 *  instruction for which the response is being sent are passed as params.
 *  The function can be called in blocking/non-blocking mode. For non-blocking
 *  mode, it takes a pointer to a work queue entry which is scheduled in the
 *  POW when the DMA completes.
 *
 *  @param  action - specify DMA_BLOCKING/DMA_NON_BLOCKING
 *  @param  front  - the RAW instruction from where the return address and
 *                   IRH are read.
 *  @param  orh    - The response header.
 *  @param  status - status of instruction processing.
 *  @param  lptr   - the local pointer to  response data.
 *  @param  segs   - number of local data segments in response data.
 *  @param  ptr_type - type of pointer for "lptr" (DIRECT/LINKED/GATHER)
 *  @param  wqe    - For non-blocking mode, a pointer to a work queue entry
 *                   is passed here.
 *
 *  @return Success: 0; Failure: -ENOMEM, -EINVAL. 
 */

int
cvm_drv_pci_instr_response(DMA_ACTION              action,
                           cvmx_raw_inst_front_t  *front,
                           union octeon_rh        *orh,
                           uint64_t                status,
                           cvmx_buf_ptr_t          lptr,
                           uint32_t                segs,
                           cvm_ptr_type_t          ptr_type,
                           cvmx_wqe_t             *wqe);



/** Core: cvm_dma_send_scatter_response_direct() existed in older releases and
 *        may be removed from future releases. The new function
 *        cvm_drv_send_scatter_response_direct() uses the uniform naming
 *        convention used for all core driver API. 
 */
static inline int
cvm_dma_send_scatter_response_direct(DMA_ACTION              action,
                                     cvmx_wqe_t             *wqe,
                                     cvm_pci_scatter_resp_t *resp,
                                     cvmx_buf_ptr_t          lptr,
                                     uint32_t                local_segs,
                                     cvm_ptr_type_t          ptr_type)
{
	return cvm_drv_send_scatter_response_direct(action, wqe, resp, lptr, local_segs, ptr_type);
}


/** Core: cvm_dma_send_scatter_response() existed in older releases and
 *        may be removed from future releases. The new function
 *        cvm_drv_send_scatter_response() uses the uniform naming
 *        convention used for all core driver API. 
 */
static inline int
cvm_dma_send_scatter_response(DMA_ACTION              action,
                              cvmx_wqe_t             *wqe, 
                              cvm_pci_scatter_resp_t *resp,
                              cvmx_buf_ptr_t          lptr,
                              uint32_t                local_segs,
                              cvm_ptr_type_t          ptr_type)
{
	return cvm_drv_send_scatter_response(action, wqe, resp, lptr, local_segs, ptr_type);
}

/* -----------------------------   APIs for OCTEON-III Models -------------------------*/

/** Core: This routine is called in OCTEON-III models to post a response to 
 *  a PCI instruction when the response will be sent to multiple host buffers. 
 *  In other words, for scatter mode responses, use this API. The response 
 *  header (ORH), status of instruction processing, the scatter list containing 
 *  the host buffer addresses are passed to this function in a cvm_pci_scatter_resp_t
 *  structure. The response data and pointer to the raw instruction for which
 *  the response is being sent are passed as params. The function can be
 *  called in blocking/non-blocking mode. For non-blocking mode, it takes
 *  a pointer to a work queue entry which is scheduled in the POW when the
 *  DMA completes.
 *
 *  @param  action - specify DMA_BLOCKING/DMA_NON_BLOCKING
 *  @param  wqe    - For non-blocking mode, a pointer to a work queue entry
 *                   is passed here.
 *  @param  resp   - pointer to a cvm_pci_scatter_resp_t structure which
 *                   contains the scatter list, status & response header
 *  @param  lptr   - the local pointer to  response data.
 *  @param  local_segs   - number of local data segments in response data.
 *  @param  ptr_type - type of pointer for "lptr" (DIRECT/LINKED/GATHER)
 *  @param  pool   - Pool number used to create the local data segments.
 *
 *  @return Success: 0; Failure: -ENOMEM, -EINVAL. 
 */
int
cvm_drv_send_scatter_response_o3(DMA_ACTION              action,
                              cvmx_wqe_t             *wqe,
                              cvm_pci_scatter_resp_t *resp,
                              cvmx_buf_ptr_pki_t      lptr,
                              uint32_t                local_segs,
                              cvm_ptr_type_t          ptr_type,
                              int                     pool); 

/** Core: This routine is called in OCTEON-III models to post a response to 
 *  a PCI instruction when the response will be sent to multiple host buffers. 
 *  In other words, for scatter mode responses, use this API. 
 *  The response header (ORH) and status of instruction processing are assumed 
 *  to be part of the response data passed to this function. The scatter list 
 *  containing the host buffer addresses are passed to this function in a 
 *  cvm_pci_scatter_resp_t structure. The response data and pointer to the 
 *  raw instruction for which the response is being sent are passed as params. 
 *  The function can be called in blocking/non-blocking mode. For non-blocking mode, 
 *  it takes a pointer to a work queue entry which is scheduled in the POW when the
 *  DMA completes.
 *
 *  @param  action - specify DMA_BLOCKING/DMA_NON_BLOCKING
 *  @param  wqe    - For non-blocking mode, a pointer to a work queue entry
 *                   is passed here.
 *  @param  resp   - pointer to a cvm_pci_scatter_resp_t structure which
 *                   contains the scatter list. The status & orh fields are
 *                   ignored her.
 *  @param  lptr   - the local pointer to  response data which includes the
 *                   response header (first 8 bytes) and status (last 8 bytes).
 *  @param  local_segs   - number of local data segments in response data.
 *  @param  ptr_type - type of pointer for "lptr" (DIRECT/LINKED/GATHER)
 *  @param  pool   - Pool number used to create the local data segments.
 *
 *  @return Success: 0; Failure: -ENOMEM, -EINVAL. 
 */
int
cvm_drv_send_scatter_response_direct_o3(DMA_ACTION              action,
                                     cvmx_wqe_t             *wqe,
                                     cvm_pci_scatter_resp_t *resp,
                                     cvmx_buf_ptr_pki_t      lptr,
                                     uint32_t                local_segs,
                                     cvm_ptr_type_t          ptr_type,
                                     int                     pool);

/** Core: This routine is called in OCTEON-III models to post a response to a 
 *  PCI instruction when the response will be sent to a single host buffer. 
 *  The response data and pointer to the raw instruction for which the response 
 *  is being sent are passed as params. The response header & status of 
 *  instruction processing are assumed to be part of the response data.
 *  The function can be called in blocking/non-blocking mode. For non-blocking
 *  mode, it takes a pointer to a work queue entry which is scheduled in the
 *  POW when the DMA completes.
 *
 *  @param  action - specify DMA_BLOCKING/DMA_NON_BLOCKING
 *  @param  front  - the RAW instruction from where the return address and
 *                   IRH are read.
 *  @param  lptr   - the local pointer to  response data.
 *  @param  segs   - number of local data segments in response data.
 *  @param  ptr_type - type of pointer for "lptr" (DIRECT/LINKED/GATHER)
 *  @param  wqe    - For non-blocking mode, a pointer to a work queue entry
 *                   is passed here.
 *  @param  pool   - Pool number used to create the local data segments.
 *
 *  @return Success: 0; Failure: -ENOMEM, -EINVAL. 
 */
int
cvm_drv_pci_instr_response_direct_o3(DMA_ACTION               action,
                                  cvmx_raw_inst_front_t   *front,
                                  cvmx_buf_ptr_pki_t       lptr,
                                  uint32_t                 segs,
                                  cvm_ptr_type_t           ptr_type,
                                  cvmx_wqe_t              *wqe,
                                  int                      pool);

/** Core: This routine is called in OCTEON-III models to post a response to a 
 * PCI instruction when the response will be sent to a single host buffer.
 *  The response header, status of instruction processing, the response data 
 *  and pointer to the raw instruction for which the response is being sent 
 *  are passed as params. The function can be called in blocking/non-blocking 
 *  mode. For non-blocking mode, it takes a pointer to a work queue entry which 
 *  is scheduled in the POW when the DMA completes.
 *
 *  @param  action - specify DMA_BLOCKING/DMA_NON_BLOCKING
 *  @param  front  - the RAW instruction from where the return address and
 *                   IRH are read.
 *  @param  orh    - The response header.
 *  @param  status - status of instruction processing.
 *  @param  lptr   - the local pointer to  response data.
 *  @param  segs   - number of local data segments in response data.
 *  @param  ptr_type - type of pointer for "lptr" (DIRECT/LINKED/GATHER)
 *  @param  wqe    - For non-blocking mode, a pointer to a work queue entry
 *                   is passed here.
 *  @param  pool   - Pool number used to create the local data segments.                  
 *
 *  @return Success: 0; Failure: -ENOMEM, -EINVAL. 
 */

int
cvm_drv_pci_instr_response_o3(DMA_ACTION              action,
                           cvmx_raw_inst_front_t  *front,
                           union octeon_rh        *orh,
                           uint64_t                status,
                           cvmx_buf_ptr_pki_t      lptr,
                           uint32_t                segs,
                           cvm_ptr_type_t          ptr_type,
                           cvmx_wqe_t             *wqe,
                           int                     pool);

/** Core: cvm_dma_send_scatter_response_direct() existed in older releases and
 *        may be removed from future releases. The new function
 *        cvm_drv_send_scatter_response_direct() uses the uniform naming
 *        convention used for all core driver API. 
 */
static inline int
cvm_dma_send_scatter_response_direct_o3(DMA_ACTION              action,
                                     cvmx_wqe_t             *wqe,
                                     cvm_pci_scatter_resp_t *resp,
                                     cvmx_buf_ptr_pki_t      lptr,
                                     uint32_t                local_segs,
                                     cvm_ptr_type_t          ptr_type,
									 int                     pool)
{
	return cvm_drv_send_scatter_response_direct_o3(action, wqe, resp, lptr, local_segs, ptr_type, pool);
}


/** Core: cvm_dma_send_scatter_response() existed in older releases and
 *        may be removed from future releases. The new function
 *        cvm_drv_send_scatter_response() uses the uniform naming
 *        convention used for all core driver API. 
 */
static inline int
cvm_dma_send_scatter_response_o3(DMA_ACTION              action,
                              cvmx_wqe_t             *wqe, 
                              cvm_pci_scatter_resp_t *resp,
                              cvmx_buf_ptr_pki_t      lptr,
                              uint32_t                local_segs,
                              cvm_ptr_type_t          ptr_type,
	                          int                     pool)
{
	return cvm_drv_send_scatter_response_o3(action, wqe, resp, lptr, local_segs, ptr_type, pool);
}




#endif


/* $Id$ */

