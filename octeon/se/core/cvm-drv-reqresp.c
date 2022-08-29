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
#include "cvm-drv.h"
#include "liquidio_common.h"
#include <errno.h>


extern  CVMX_SHARED  cvm_oct_dev_t    *oct;






static inline int
cvm_drv_wait_for_resp_completion(cvm_dma_comp_ptr_t  *comp)
{
	uint64_t   wait_cycles = 0, start_cycle = cvmx_get_cycle();

	while(comp->comp_byte) {
		CVMX_SYNCWS;
		cvmx_wait(10);
		wait_cycles++;
		if(!(wait_cycles & 0xffffff)) {
			printf("%s: Waiting too long for completion (%lu cycles so far)\n",
			      __FUNCTION__, (cvmx_get_cycle() - start_cycle));
		}
	}

	return 0;
}






static inline int
cvm_drv_prepare_response_dma_header(DMA_ACTION                     action,
                                    cvmx_wqe_t                    *wqe,
                                    cvmx_oct_pci_dma_inst_hdr_t   *dma_hdr)
{
	/* Initialize the dma header. The FL and II bits remain set to 0.
	   ptr is NULL; DIR is outbound C is 0, CA is 0; */
	dma_hdr->word0.u64 = 0;
	dma_hdr->word1.u64 = 0;

	/* Use DMA channel 0 and force an interrupt. Speeds up request completion
	   on host. */
	dma_hdr->word0.cn38xx.c = 0;
	dma_hdr->word0.cn38xx.fi = 1; 

	if(action == DMA_NON_BLOCKING) {
		if(wqe == NULL) {
			printf("NULL WQE found for NON-BLOCKING instr response\n");
			return -EINVAL;
		}
		dma_hdr->word0.cn38xx.wqp =1; 
		dma_hdr->word0.cn38xx.ptr = CVM_DRV_GET_PHYS(wqe);
	} else {
		cvm_dma_comp_ptr_t  *comp = cvm_get_dma_comp_ptr();
		if(comp == NULL) {
			printf("[ DRV ] comptr alloc failed for BLOCKING response\n");
			return -ENOMEM;
		}
		comp->comp_byte = 0xff;
		dma_hdr->word0.cn38xx.ptr = CVM_DRV_GET_PHYS(&comp->comp_byte);
	}
	return 0;
}










static inline int
cvm_drv_post_response(DMA_ACTION                      action,
                      cvmx_oct_pci_dma_inst_hdr_t    *dma_hdr,
                      cvmx_oct_pci_dma_local_ptr_t   *lptr,
                      cvm_dma_remote_ptr_t           *rptr)
{
	int  retval;

	CVMX_SYNCW;


	if (OCTEON_IS_OCTEON3())
		retval = cvm_pcie_dma_raw_o3(0, dma_hdr,(void *) lptr,(void *) rptr);
	else if(OCTEON_IS_MODEL(OCTEON_CN56XX) || OCTEON_IS_MODEL(OCTEON_CN63XX) ||
	   OCTEON_IS_MODEL(OCTEON_CN66XX) || OCTEON_IS_MODEL(OCTEON_CN68XX) ||
	   OCTEON_IS_MODEL(OCTEON_CN61XX) || OCTEON_IS_MODEL(OCTEON_CN70XX))
		retval = cvm_pcie_dma_raw(0, dma_hdr, lptr, rptr);
	else
		retval = cvm_pci_dma_raw(dma_hdr, lptr, rptr);

	if(action == DMA_BLOCKING) {
		cvm_dma_comp_ptr_t *comp;
		if (OCTEON_IS_OCTEON3())
			comp  = (cvm_dma_comp_ptr_t *)CVM_DRV_GET_PTR(dma_hdr->word1.s.ptr);
		else
			comp  = (cvm_dma_comp_ptr_t *)CVM_DRV_GET_PTR(dma_hdr->word0.cn38xx.ptr);
	
		if(retval == 0)
			retval = cvm_drv_wait_for_resp_completion(comp);

		cvm_release_dma_comp_ptr(comp);
	}

	return retval;
}







static inline  uint32_t
cvm_dma_fill_scatter_ptrs(cvm_dma_remote_ptr_t   *remote_ptr,
                          struct octeon_sg_entry *sg_entry,
                          uint32_t                remote_segs)
{
	uint32_t   i, j, k, remote_bytes=0;

	for(i = 0, k = 0; i < remote_segs; k++) {
		for(j = 0; ((j < 4) && (i < remote_segs)); j++, i++)  {
			remote_ptr[i].s.size = sg_entry[k].u.size[3-j];
			remote_ptr[i].s.addr = sg_entry[k].ptr[j];
			DBG_PRINT(DBG_FLOW,"remote_ptr[%d] addr: 0x%llx size: %d\n", i,
			       cast64(remote_ptr[i].s.addr), remote_ptr[i].s.size);
			remote_bytes += remote_ptr[i].s.size;
		}
	}
	return remote_bytes;
}




/*
 * API Function.
 * Send response to host scatter buffers. The response header, data and
 * completion code are available in the data buffers in "lptr".
 */

int
cvm_drv_send_scatter_response_direct(DMA_ACTION              action,
                                     cvmx_wqe_t             *wqe,
                                     cvm_pci_scatter_resp_t *resp,
                                     cvmx_buf_ptr_t          lptr,
                                     uint32_t                local_segs,
                                     cvm_ptr_type_t          ptr_type)
{
	uint32_t                       local_bytes=0, remote_bytes=0;
	cvmx_oct_pci_dma_local_ptr_t   local_ptr[16];
	cvm_dma_remote_ptr_t           remote_ptr[16];
	cvmx_oct_pci_dma_inst_hdr_t    dma_hdr;


	DBG_PRINT(DBG_FLOW,"----cvm_dma_send_scatter_response_direct----\n");

	if( (local_segs > oct->max_lptrs)
	     || (resp->remote_segs > oct->max_rptrs)) {
		printf("[ DRV ] Scatter direct response ptrs (local: %d) (remote: %d) exceeds max allowed\n", local_segs, resp->remote_segs);
		return -EINVAL;
	}


	/* Copy all the local data pointers. */
	local_bytes = cvm_dma_fill_local_ptrs(local_ptr,lptr,local_segs, ptr_type);
	if((int)local_bytes == -1) {
		printf("[ DRV ] Scatter Direct: Local buffer found with size > %d\n",
		        MAX_PCI_DMA_LOCAL_BUF_SIZE);
		return -EINVAL;
	}


	/* Copy all the remote data pointers. */
	remote_bytes = cvm_dma_fill_scatter_ptrs(remote_ptr, resp->sg_entry,
	                                         resp->remote_segs);

	if(local_bytes != remote_bytes) {
		printf("[ DRV ] Scatter Direct Response: Local (%d) & remote (%d) sizes do not match\n", local_bytes, remote_bytes);
		return -EINVAL;
	}

	if(cvm_drv_prepare_response_dma_header(action, wqe, &dma_hdr))
		return  -ENOMEM;

    dma_hdr.word0.cn38xx.nl = local_segs;
    dma_hdr.word0.cn38xx.nr = resp->remote_segs;
    dma_hdr.word0.cn38xx.lport = resp->pcie_port;

	return cvm_drv_post_response(action, &dma_hdr, local_ptr, remote_ptr);
}





/*
 * API Function.
 * Send response to host scatter buffers. The response header and completion
 * code are available from the "resp" parameter. Response data is present in
 * "lptr".
*/

int
cvm_drv_send_scatter_response(DMA_ACTION              action,
                              cvmx_wqe_t             *wqe, 
                              cvm_pci_scatter_resp_t *resp,
                              cvmx_buf_ptr_t          lptr,
                              uint32_t                local_segs,
                              cvm_ptr_type_t          ptr_type)
{
	uint32_t                        remote_bytes = 0, local_bytes = 0, idx=0;
	uint64_t                       *resp_buf = NULL;
	cvmx_oct_pci_dma_local_ptr_t    local_ptr[16];
	cvm_dma_remote_ptr_t            remote_ptr[16];
	cvmx_oct_pci_dma_inst_hdr_t     dma_hdr;
	int                             retval = -EINVAL;


	DBG_PRINT(DBG_FLOW,"----cvm_dma_send_scatter_response----\n");

	if((resp->status & 0xff) == 0xff) {
		printf("[ DRV ] Scatter Response: Byte 0 of status cannot be 0xff\n");
		return -EINVAL;
	}

	/* 1 Local Pointer reserved for resp_hdr, 1 for status. */
	if(local_segs > (uint32_t)(oct->max_lptrs-2)) {
		printf("[ DRV ] Scatter Response supports max %d local ptrs (found %d)\n", (oct->max_lptrs-2), local_segs);
		return -EINVAL;
	}

	if(resp->remote_segs > oct->max_rptrs) {
		printf("[ DRV ] Scatter Response supports max %d remote segs (found %d)\n", oct->max_rptrs, resp->remote_segs);
		return -EINVAL;
	}


	resp_buf = (uint64_t *)cvm_drv_fpa_alloc_sync(lptr.s.pool);
	if(resp_buf == NULL)  {
		printf("[ DRV ] Buffer alloc failed to send scatter response\n");
		return -ENOMEM;
	}
	resp_buf[0] = resp->orh.u64;
	resp_buf[1] = resp->status;

	/* Prepare the local pointer list now. */
	idx = 0;

	/* The response header comes first. */
	local_ptr[idx].u64 = 0;
    local_ptr[idx].cn38xx.addr = CVM_DRV_GET_PHYS(resp_buf);
    local_ptr[idx].cn38xx.size = OCT_RH_SIZE;
    local_ptr[idx].cn38xx.pool = lptr.s.pool;
	idx++;

	/* Followed by all the local data pointers. */
	local_bytes = cvm_dma_fill_local_ptrs(&local_ptr[idx], lptr, local_segs, ptr_type);
	if((int)local_bytes == -1) {
		printf("[ DRV ] Scatter Response: Local buffer found with size > %d\n",
		        MAX_PCI_DMA_LOCAL_BUF_SIZE);
		goto scatter_response_fail;
	}

	idx += local_segs;

	/* Total local bytes = data + resp_hdr + status word */
	local_bytes += OCT_RH_SIZE + 8;
	CVMX_SYNCWS;


	/* And finally the status word. The I bit is set for resp_buf here. */
	local_ptr[idx].u64 = 0;

    local_ptr[idx].cn38xx.addr = CVM_DRV_GET_PHYS(&(resp_buf[1]));
    local_ptr[idx].cn38xx.size = 8;
    local_ptr[idx].cn38xx.pool = lptr.s.pool;
    local_ptr[idx].cn38xx.i = 1;
	idx++;


	remote_bytes = cvm_dma_fill_scatter_ptrs(remote_ptr, resp->sg_entry, resp->remote_segs);

	/* The response hdr and status are added separately in this routine. */
	if(local_bytes != remote_bytes) {
		printf("[ DRV ] Scatter Response: Local (%d) & remote (%d) sizes do not match\n", local_bytes, remote_bytes);
		goto scatter_response_fail;
	}

	retval = cvm_drv_prepare_response_dma_header(action, wqe, &dma_hdr);
	if(retval)
		goto scatter_response_fail;

    dma_hdr.word0.cn38xx.nl = idx;
    dma_hdr.word0.cn38xx.nr = resp->remote_segs;
    dma_hdr.word0.cn38xx.lport = resp->pcie_port;

	retval = cvm_drv_post_response(action, &dma_hdr, local_ptr, remote_ptr);

scatter_response_fail:
	if(retval)
		cvm_drv_fpa_free(resp_buf, lptr.s.pool, 0);

	return retval;
}










/*
 * API Function.
 * Send response to a single host buffer. The response header, response data and
 * completion code are in the local buffers in "lptr" passed to this function. 
 */

int
cvm_drv_pci_instr_response_direct(DMA_ACTION               action,
                                  cvmx_raw_inst_front_t   *front,
                                  cvmx_buf_ptr_t           lptr,
                                  uint32_t                 segs,
                                  cvm_ptr_type_t           ptr_type,
                                  cvmx_wqe_t              *wqe)
{
	uint32_t                       total_bytes = 0;
	cvmx_oct_pci_dma_local_ptr_t   local_ptr[16];
	cvm_dma_remote_ptr_t           remote_ptr;
	cvmx_oct_pci_dma_inst_hdr_t    dma_hdr;
	int                            retval = -EINVAL;

	DBG_PRINT(DBG_FLOW,"----cvm_dma_send_instr_response_direct----\n");

	if(segs > (uint32_t)(oct->max_lptrs)) {
		printf("[ DRV ] Direct Instr Response support max %d segs, found %d\n",
		       oct->max_lptrs, segs);
		return -EINVAL;
	}



	/* Copy all the local data pointers. */
	total_bytes = cvm_dma_fill_local_ptrs(local_ptr, lptr, segs, ptr_type);
	if((int)total_bytes == -1) {
		printf("[ DRV ] Direct Instr Response Local buffer size > %d\n",
		       MAX_PCI_DMA_LOCAL_BUF_SIZE);
	}


	if(total_bytes != front->rdp.s.rlen) {
		printf("[ DRV ] Direct Instr Response bytes (%u) != IRH len (%u)\n",
		        total_bytes, front->rdp.s.rlen);
		return -EINVAL;
	}

	/* The remote pointers are calculated from the rptr */
	/* Scatter mode is not supported right now. */
	remote_ptr.s.addr = front->rptr;
	remote_ptr.s.size = total_bytes;

	retval = cvm_drv_prepare_response_dma_header(action, wqe, &dma_hdr);
	if(retval)
		return retval;

	dma_hdr.word0.cn38xx.nl = segs; 
	dma_hdr.word0.cn78xx.nr = 1; 
	dma_hdr.word0.cn78xx.lport = front->rdp.s.pcie_port; 

	return cvm_drv_post_response(action, &dma_hdr, local_ptr, &remote_ptr);
}





/*
 * API Function.
 * Send response to a single host buffer. The response header is passed in
 * "orh", response data in the local buffers in "lptr", and completion code is
 * in "status" parameter passed to this function. 
 */
int
cvm_drv_pci_instr_response(DMA_ACTION              action,
                           cvmx_raw_inst_front_t  *front,
                           union octeon_rh        *orh,
                           uint64_t                status,
                           cvmx_buf_ptr_t          lptr,
                           uint32_t                segs,
                           cvm_ptr_type_t          ptr_type,
                           cvmx_wqe_t             *wqe)
{
	uint32_t                       data_bytes = 0, total_bytes = 0, idx=0;
	uint64_t                      *resp_buf = NULL;
	cvmx_oct_pci_dma_local_ptr_t   local_ptr[16];
	cvm_dma_remote_ptr_t           remote_ptr;
	cvmx_oct_pci_dma_inst_hdr_t    dma_hdr;
	int                            retval = -EINVAL;

	DBG_PRINT(DBG_FLOW,"----cvm_dma_send_instr_response----\n");

	if((status & 0xff) == 0xff) {
		printf("[ DRV ] Byte 0 of status cannot be 0xff\n");
		return  -EINVAL;
	}


	/* 1 reserved for resp_hdr. 1 for status */
	if(segs > (uint32_t) (oct->max_lptrs - 2)) {
		printf("[ DRV ] Instr Response does not support %d segs\n", segs);
		return  -EINVAL;
	}

	resp_buf = (uint64_t *)cvm_drv_fpa_alloc_sync(lptr.s.pool);
	if(resp_buf == NULL)  {
		printf("[ DRV ] resp_buf alloc failed\n");
		return -ENOMEM;
	}
	resp_buf[0] = orh->u64;
	resp_buf[1] = status;

	/* Prepare the local pointer list now. */
	idx = 0;

	/* The response header comes first. */
	local_ptr[idx].u64 = 0;
	local_ptr[idx].cn38xx.addr = CVM_DRV_GET_PHYS(resp_buf);
	local_ptr[idx].cn38xx.size = OCT_RH_SIZE;
	local_ptr[idx].cn38xx.pool = lptr.s.pool;
	idx++;

	/* Followed by all the local data pointers. */
	data_bytes = cvm_dma_fill_local_ptrs(&local_ptr[idx], lptr, segs, ptr_type);
	if((int)data_bytes == -1) {
		printf("[ DRV ] Instr Response: Local buffer found with size > %d\n",
		        MAX_PCI_DMA_LOCAL_BUF_SIZE);
		goto response_fail;
	}

	idx += segs;

	/* Total bytes = data + resp_hdr + status word */
	total_bytes = data_bytes + OCT_RH_SIZE + 8;
	CVMX_SYNCWS;

	/* The response hdr and status are added separately in this routine. */
	if(total_bytes != front->rdp.s.rlen) {
		printf("[ DRV ] CVM_PCI_DMA: (1) total response bytes (%d) don't match length in IRH (IRH: 0x%016llx)\n", total_bytes, cast64(front->irh.u64));
		goto response_fail;
	}

	/* And finally the status word. The I bit is set for resp_buf here. */
	local_ptr[idx].u64 = 0;
	local_ptr[idx].cn38xx.addr = CVM_DRV_GET_PHYS(&(resp_buf[1]));
	local_ptr[idx].cn38xx.size = 8;
	local_ptr[idx].cn38xx.pool = lptr.s.pool;
	local_ptr[idx].cn38xx.i = 1;
	idx++;


	/* The remote pointers are calculated from the rptr */
	/* Scatter mode is not supported right now. */
	remote_ptr.s.addr = front->rptr;
	remote_ptr.s.size = total_bytes;

	retval = cvm_drv_prepare_response_dma_header(action, wqe, &dma_hdr);
	if(retval)
		goto response_fail;

	dma_hdr.word0.cn38xx.nl = idx;
	dma_hdr.word0.cn38xx.nr = 1;
	dma_hdr.word0.cn38xx.lport = front->rdp.s.pcie_port;


	retval = cvm_drv_post_response(action, &dma_hdr, local_ptr, &remote_ptr);
response_fail:
	if(retval)
		cvm_drv_fpa_free(resp_buf, lptr.s.pool, 0);
	return retval;
}


static inline int
cvm_drv_prepare_response_dma_header_o3(DMA_ACTION                     action,
                                    cvmx_wqe_t                    *wqe,
                                    cvmx_oct_pci_dma_inst_hdr_t   *dma_hdr)
{
	/* Initialize the dma header. The FL and II bits remain set to 0.
	   ptr is NULL; DIR is outbound C is 0, CA is 0; */
	dma_hdr->word0.u64 = 0;
	dma_hdr->word1.u64 = 0;

	/* Use DMA channel 0 and force an interrupt. Speeds up request completion
	   on host. */
	dma_hdr->word0.cn78xx.csel = 0;
	dma_hdr->word0.cn78xx.fi = 1; 

	if(action == DMA_NON_BLOCKING) {
		if(wqe == NULL) {
			printf("NULL WQE found for NON-BLOCKING instr response\n");
			return -EINVAL;
		}
		dma_hdr->word0.cn78xx.pt =2; 
		dma_hdr->word1.s.ptr = CVM_DRV_GET_PHYS(wqe);
	} else {

		cvm_dma_comp_ptr_t  *comp = cvm_get_dma_comp_ptr();
		if(comp == NULL) {
			printf("[ DRV ] comptr alloc failed for BLOCKING response\n");
			return -ENOMEM;
		}
		comp->comp_byte = 0xff;
		dma_hdr->word1.s.ptr = CVM_DRV_GET_PHYS(&comp->comp_byte);
	}
	return 0;
}


/*
 * API Function for OCT-III models.
 * Send response to host scatter buffers. The response header, data and
 * completion code are available in the data buffers in "lptr".
 */

int
cvm_drv_send_scatter_response_direct_o3(DMA_ACTION              action,
                                     cvmx_wqe_t             *wqe,
                                     cvm_pci_scatter_resp_t *resp,
                                     cvmx_buf_ptr_pki_t      lptr,
                                     uint32_t                local_segs,
                                     cvm_ptr_type_t          ptr_type,
	                                 int                     pool)
{
	uint32_t                       local_bytes=0, remote_bytes=0;
	cvmx_oct_pci_dma_local_ptr_t   local_ptr[16];
	cvm_dma_remote_ptr_t           remote_ptr[16];
	cvmx_oct_pci_dma_inst_hdr_t    dma_hdr;


	DBG_PRINT(DBG_FLOW,"----cvm_dma_send_scatter_response_direct----\n");

	if( (local_segs > oct->max_lptrs)
	     || (resp->remote_segs > oct->max_rptrs)) {
		printf("[ DRV ] Scatter direct response ptrs (local: %d) (remote: %d) exceeds max allowed\n", local_segs, resp->remote_segs);
		return -EINVAL;
	}


	/* Copy all the local data pointers. */
	local_bytes = cvm_dma_fill_local_ptrs_o3(local_ptr,lptr,local_segs, ptr_type);
	if((int)local_bytes == -1) {
		printf("[ DRV ] Scatter Direct: Local buffer found with size > %d\n",
		        MAX_PCI_DMA_LOCAL_BUF_SIZE);
		return -EINVAL;
	}


	/* Copy all the remote data pointers. */
	remote_bytes = cvm_dma_fill_scatter_ptrs(remote_ptr, resp->sg_entry,
	                                         resp->remote_segs);

	if(local_bytes != remote_bytes) {
		printf("[ DRV ] Scatter Direct Response: Local (%d) & remote (%d) sizes do not match\n", local_bytes, remote_bytes);
		return -EINVAL;
	}

	if(cvm_drv_prepare_response_dma_header_o3(action, wqe, &dma_hdr))
		return  -ENOMEM;

    dma_hdr.word0.cn78xx.nl = local_segs;
    dma_hdr.word0.cn78xx.nr = resp->remote_segs;
    dma_hdr.word0.cn78xx.lport = resp->pcie_port;
    dma_hdr.word0.cn78xx.aura = pool;

	return cvm_drv_post_response(action, &dma_hdr, local_ptr, remote_ptr);
}


/*
 * API Function for OCT-III models.
 * Send response to host scatter buffers. The response header and completion
 * code are available from the "resp" parameter. Response data is present in
 * "lptr".
*/

int
cvm_drv_send_scatter_response_o3(DMA_ACTION              action,
                              cvmx_wqe_t             *wqe, 
                              cvm_pci_scatter_resp_t *resp,
                              cvmx_buf_ptr_pki_t      lptr,
                              uint32_t                local_segs,
                              cvm_ptr_type_t          ptr_type,
                              int                     pool)
{
	uint32_t                        remote_bytes = 0, local_bytes = 0, idx=0;
	uint64_t                       *resp_buf = NULL;
	cvmx_oct_pci_dma_local_ptr_t    local_ptr[16];
	cvm_dma_remote_ptr_t            remote_ptr[16];
	cvmx_oct_pci_dma_inst_hdr_t     dma_hdr;
	int                             retval = -EINVAL;


	DBG_PRINT(DBG_FLOW,"----cvm_dma_send_scatter_response----\n");

	if((resp->status & 0xff) == 0xff) {
		printf("[ DRV ] Scatter Response: Byte 0 of status cannot be 0xff\n");
		return -EINVAL;
	}

	/* 1 Local Pointer reserved for resp_hdr, 1 for status. */
	if(local_segs > (uint32_t) (oct->max_lptrs-2)) {
		printf("[ DRV ] Scatter Response supports max %d local ptrs (found %d)\n", (oct->max_lptrs-2), local_segs);
		return -EINVAL;
	}

	if(resp->remote_segs > oct->max_rptrs) {
		printf("[ DRV ] Scatter Response supports max %d remote segs (found %d)\n", oct->max_rptrs, resp->remote_segs);
		return -EINVAL;
	}


	resp_buf = (uint64_t *)cvm_drv_fpa_alloc_sync(pool);
	if(resp_buf == NULL)  {
		printf("[ DRV ] Buffer alloc failed to send scatter response\n");
		return -ENOMEM;
	}
	resp_buf[0] = resp->orh.u64;
	resp_buf[1] = resp->status;

	/* Prepare the local pointer list now. */
	idx = 0;

	/* The response header comes first. */
	local_ptr[idx].u64 = 0;
    local_ptr[idx].cn78xx.addr = CVM_DRV_GET_PHYS(resp_buf);
    local_ptr[idx].cn78xx.size = OCT_RH_SIZE;
	idx++;

	/* Followed by all the local data pointers. */
	local_bytes = cvm_dma_fill_local_ptrs_o3(&local_ptr[idx], lptr, local_segs, ptr_type);
	if((int)local_bytes == -1) {
		printf("[ DRV ] Scatter Response: Local buffer found with size > %d\n",
		        MAX_PCI_DMA_LOCAL_BUF_SIZE);
		goto scatter_response_fail;
	}

	idx += local_segs;

	/* Total local bytes = data + resp_hdr + status word */
	local_bytes += OCT_RH_SIZE + 8;
	CVMX_SYNCWS;


	/* And finally the status word. The I bit is set for resp_buf here. */
	local_ptr[idx].u64 = 0;

    local_ptr[idx].cn78xx.addr = CVM_DRV_GET_PHYS(&(resp_buf[1]));
    local_ptr[idx].cn78xx.size = 8;
    local_ptr[idx].cn78xx.i = 1;
	idx++;


	remote_bytes = cvm_dma_fill_scatter_ptrs(remote_ptr, resp->sg_entry, resp->remote_segs);

	/* The response hdr and status are added separately in this routine. */
	if(local_bytes != remote_bytes) {
		printf("[ DRV ] Scatter Response: Local (%d) & remote (%d) sizes do not match\n", local_bytes, remote_bytes);
		goto scatter_response_fail;
	}

	retval = cvm_drv_prepare_response_dma_header_o3(action, wqe, &dma_hdr);
	if(retval)
		goto scatter_response_fail;

    dma_hdr.word0.cn78xx.nl = idx;
    dma_hdr.word0.cn78xx.nr = resp->remote_segs;
    dma_hdr.word0.cn78xx.lport = resp->pcie_port;
    dma_hdr.word0.cn78xx.aura = pool;

	retval = cvm_drv_post_response(action, &dma_hdr, local_ptr, remote_ptr);

scatter_response_fail:
	if(retval)
		cvm_drv_fpa_free(resp_buf, pool, 0);

	return retval;
}

/*
 * API Function for OCT-III models.
 * Send response to a single host buffer. The response header, response data and
 * completion code are in the local buffers in "lptr" passed to this function. 
 */

int
cvm_drv_pci_instr_response_direct_03(DMA_ACTION               action,
                                  cvmx_raw_inst_front_t   *front,
                                  cvmx_buf_ptr_pki_t       lptr,
                                  uint32_t                 segs,
                                  cvm_ptr_type_t           ptr_type,
                                  cvmx_wqe_t              *wqe,
								  int                     pool)
{
	uint32_t                       total_bytes = 0;
	cvmx_oct_pci_dma_local_ptr_t   local_ptr[16];
	cvm_dma_remote_ptr_t           remote_ptr;
	cvmx_oct_pci_dma_inst_hdr_t    dma_hdr;
	int                            retval = -EINVAL;

	DBG_PRINT(DBG_FLOW,"----cvm_dma_send_instr_response_direct----\n");

	if(segs > oct->max_lptrs) {
		printf("[ DRV ] Direct Instr Response support max %d segs, found %d\n",
		       oct->max_lptrs, segs);
		return -EINVAL;
	}



	/* Copy all the local data pointers. */
	total_bytes = cvm_dma_fill_local_ptrs_o3(local_ptr, lptr, segs, ptr_type);
	if((int)total_bytes == -1) {
		printf("[ DRV ] Direct Instr Response Local buffer size > %d\n",
		       MAX_PCI_DMA_LOCAL_BUF_SIZE);
	}


	if(total_bytes != front->rdp.s.rlen) {
		printf("[ DRV ] Direct Instr Response bytes (%u) != IRH len (%u)\n",
		        total_bytes, front->rdp.s.rlen);
		return -EINVAL;
	}

	/* The remote pointers are calculated from the rptr */
	/* Scatter mode is not supported right now. */
	remote_ptr.s.addr = front->rptr;
	remote_ptr.s.size = total_bytes;

	retval = cvm_drv_prepare_response_dma_header_o3(action, wqe, &dma_hdr);
	if(retval)
		return retval;
	dma_hdr.word0.cn78xx.nl = segs; 
	dma_hdr.word0.cn78xx.nl = 1; 
	dma_hdr.word0.cn78xx.lport = front->rdp.s.pcie_port; 
	dma_hdr.word0.cn78xx.aura = pool; 

	return cvm_drv_post_response(action, &dma_hdr, local_ptr, &remote_ptr);
}

/*
 * API Function for OCT-III models.
 * Send response to a single host buffer. The response header is passed in
 * "orh", response data in the local buffers in "lptr", and completion code is
 * in "status" parameter passed to this function. 
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
						   int                     pool)
{
	uint32_t                       data_bytes = 0, total_bytes = 0, idx=0;
	uint64_t                      *resp_buf = NULL;
	cvmx_oct_pci_dma_local_ptr_t   local_ptr[16];
	cvm_dma_remote_ptr_t           remote_ptr;
	cvmx_oct_pci_dma_inst_hdr_t    dma_hdr;
	int                            retval = -EINVAL;

	DBG_PRINT(DBG_FLOW,"----cvm_dma_send_instr_response----\n");

	if((status & 0xff) == 0xff) {
		printf("[ DRV ] Byte 0 of status cannot be 0xff\n");
		return  -EINVAL;
	}


	/* 1 reserved for resp_hdr. 1 for status */
	if(segs > (uint32_t) (oct->max_lptrs - 2)) {
		printf("[ DRV ] Instr Response does not support %d segs\n", segs);
		return  -EINVAL;
	}

	resp_buf = (uint64_t *)cvm_drv_fpa_alloc_sync(pool);
	if(resp_buf == NULL)  {
		printf("[ DRV ] resp_buf alloc failed\n");
		return -ENOMEM;
	}
	resp_buf[0] = orh->u64;
	resp_buf[1] = status;

	/* Prepare the local pointer list now. */
	idx = 0;

	/* The response header comes first. */
	local_ptr[idx].u64 = 0;
	local_ptr[idx].cn78xx.addr = CVM_DRV_GET_PHYS(resp_buf);
	local_ptr[idx].cn78xx.size = OCT_RH_SIZE;
	idx++;

	/* Followed by all the local data pointers. */
	data_bytes = cvm_dma_fill_local_ptrs_o3(&local_ptr[idx], lptr, segs, ptr_type);
	if((int)data_bytes == -1) {
		printf("[ DRV ] Instr Response: Local buffer found with size > %d\n",
		        MAX_PCI_DMA_LOCAL_BUF_SIZE);
		goto response_fail;
	}

	idx += segs;

	/* Total bytes = data + resp_hdr + status word */
	total_bytes = data_bytes + OCT_RH_SIZE + 8;
	CVMX_SYNCWS;

	/* The response hdr and status are added separately in this routine. */
	if(total_bytes != front->rdp.s.rlen) {
		printf("[ DRV ] CVM_PCI_DMA: (1) total response bytes (%d) don't match length in IRH (IRH: 0x%016llx)\n", total_bytes, cast64(front->irh.u64));
		goto response_fail;
	}

	/* And finally the status word. The I bit is set for resp_buf here. */
	local_ptr[idx].u64 = 0;
	local_ptr[idx].cn78xx.addr = CVM_DRV_GET_PHYS(&(resp_buf[1]));
	local_ptr[idx].cn78xx.size = 8;
	local_ptr[idx].cn78xx.i = 1;
	idx++;


	/* The remote pointers are calculated from the rptr */
	/* Scatter mode is not supported right now. */
	remote_ptr.s.addr = front->rptr;
	remote_ptr.s.size = total_bytes;

	retval = cvm_drv_prepare_response_dma_header_o3(action, wqe, &dma_hdr);
	if(retval)
		goto response_fail;

	dma_hdr.word0.cn78xx.nl = idx;
	dma_hdr.word0.cn78xx.nr = 1;
	dma_hdr.word0.cn78xx.lport = front->rdp.s.pcie_port;
	dma_hdr.word0.cn78xx.aura = pool; 


	retval = cvm_drv_post_response(action, &dma_hdr, local_ptr, &remote_ptr);
response_fail:
	if(retval)
		cvm_drv_fpa_free(resp_buf, pool, 0);
	return retval;
}





/*
 * API Function.
 * Call this function to read a scatter list from the host. This function
 * should be called when an instruction from host requires the response to 
 * be copied into scatter buffers. 
 */
int
cvm_drv_read_scatter_list(DMA_ACTION              action,
                          uint64_t                host_hw_addr,
                          cvmx_raw_inst_front_t  *front,
                          struct octeon_sg_entry *sptr,
                          cvmx_wqe_t             *wqe)
{
	cvm_dma_comp_ptr_t    *comp=NULL;
	cvm_pci_dma_cmd_t      pci_cmd;
	cvmx_buf_ptr_t         lptr;
	cvm_dma_remote_ptr_t   rptr;
	uint32_t               sg_cnt, sg_size;
	int                    retval;

	if((action == DMA_NON_BLOCKING) && (wqe == NULL)) {
		printf("[ DRV ] WQE cannot be NULL for non-blocking scatter read\n");
		return -EINVAL;
	}

	sg_cnt  = front->rdp.s.rlen;
	sg_size = (ROUNDUP4(sg_cnt) >> 2) * OCT_SG_ENTRY_SIZE;

	pci_cmd.u64  = 0;
	pci_cmd.s.nr = 1;
	pci_cmd.s.nl = 1;

	pci_cmd.s.pcielport = front->rdp.s.pcie_port;

	if(action == DMA_NON_BLOCKING) {
		pci_cmd.s.flags = PCI_DMA_INBOUND | PCI_DMA_PUTWQE;
		pci_cmd.s.ptr   = CVM_DRV_GET_PHYS(wqe);
	} else {
		comp = cvm_get_dma_comp_ptr();
		if(comp == NULL) {
			printf("[ DRV ] comptr alloc failed for scatter read\n");
			return -ENOMEM;
		}
		comp->comp_byte = 0xff;
		pci_cmd.s.flags = PCI_DMA_INBOUND | PCI_DMA_PUTWORD;
		pci_cmd.s.ptr   = CVM_DRV_GET_PHYS(&comp->comp_byte);
	}

	/* Read into sptr. Pass the physical address here. */
	lptr.u64    = 0;
	if (octeon_has_feature(OCTEON_FEATURE_PKI)) {
		cvmx_buf_ptr_pki_t *lptr_o3 = (cvmx_buf_ptr_pki_t *)&lptr;
		lptr_o3->addr = CVM_DRV_GET_PHYS(sptr);
		lptr_o3->size = sg_size;

	} else {
		lptr.s.addr = CVM_DRV_GET_PHYS(sptr);
		lptr.s.size = sg_size;
	}

	rptr.s.addr = host_hw_addr;
	rptr.s.size = sg_size;
	CVMX_SYNCWS;

	if (octeon_has_feature(OCTEON_FEATURE_PKI))
	    retval = cvm_pci_dma_recv_data_o3(&pci_cmd,(cvmx_buf_ptr_pki_t *) &lptr, &rptr);
	else
    	retval = cvm_pci_dma_recv_data(&pci_cmd, &lptr, &rptr);
	
	if(action == DMA_BLOCKING) {
		/* return error val right away if cvm_pci_dma_recv_data() failed. */
		if(retval)  return retval;
		while(comp->comp_byte) {
			CVMX_SYNCWS;
			cvmx_wait(10);
		}
		cvm_release_dma_comp_ptr(comp);
		return 0;
	}
	return retval;
}

/* $Id$ */
