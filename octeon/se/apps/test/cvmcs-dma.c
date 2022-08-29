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

#include "cvmcs-test.h"
#include "cvmcs-common.h"

#ifdef CVMCS_DMA_DEMO

#include "octeon-dma-test.h"

#define DMA_WAIT_INTERVAL  100000


/* Enable any one of the following. The routines below will use buffers
 * from FPA Pool when DMA_USE_FPA_POOL is enabled. If DMA_USE_MALLOC, the
 * local buffers will be allocated using malloc.
 * Do not use DMA_USE_MALLOC, when compiling for linux_n32.
 */
#define DMA_USE_FPA_POOL
//#define DMA_USE_MALLOC


/* Enable any one of the following. If DMA_USE_COMPLETION_WORD is enabled, 
 * the application passes a memory location to the PCI DMA command for
 * DMA completion indication. If DMA_USE_COMPLETION_WQE is enabled, the
 * application sends a WQE in the PCI DMA command. The DMA hardware 
 * will schedule this WQE on DMA completion.
 */
#define DMA_USE_COMPLETION_WORD
//#define DMA_USE_COMPLETION_WQE


#if  defined(DMA_USE_FPA_POOL) && defined(DMA_USE_MALLOC)
#error "DMA_USE_FPA_POOL and DMA_USE_MALLOC both defined"
#endif

#if  defined(DMA_USE_COMPLETION_WORD) && defined(DMA_USE_COMPLETION_WQE)
#error  "DMA_USE_COMPLETION_WORD and DMA_USE_COMPLETION_WQE both defined"
#endif



/* Structure that holds information about local buffers. This structure
 * is copied into the WQE when DMA completion uses WQE. 
 */
struct dma_comp_store {

		uint16_t         test_type;
		uint16_t         buf_count;
		uint32_t         rem_size;
		uint64_t         malloc_buf;
		cvmx_buf_ptr_t   lstore[CN3XXX_MAX_DMA_LOCAL_POINTERS];
};






/* Routine to verify data received from remote host in a PCI DMA RECEIVE
 * operation. The local buffers are freed in this routine for both SEND
 * and RECEIVE DMA operations.
 */
void
cvmcs_dma_completion_check(struct dma_comp_store  *comp)
{
	int      i, j, k;
	uint8_t  *cbuf; 

	DBG("\n\ntest_type: %d  rem_size: %d  buf_count: %d\n",
	      comp->test_type, comp->rem_size, comp->buf_count);
	DBG("malloc_buf: %lx\n", comp->malloc_buf);
	DBG("lptrs:\n");
	for(i = 0; i < comp->buf_count; i++) {
		DBG("lptr[%d]: %lx\n", i, comp->lstore[i].u64);
	}

	if(comp->test_type == DMA_DEMO_OCTEON_SEND) 
		goto free_on_completion;

#if defined(DMA_USE_MALLOC)
	cbuf = castptr(uint8_t *, comp->malloc_buf);
	k=0;
	for(i = 0; i < comp->rem_size; i++) {
		if(cbuf[i] != pattern[(k++ & 0xff)]) {
			printf("Data mismatch in local buffer\n");
			printf("First 64 bytes in local buffer\n");
			cvm_drv_print_data(cbuf, 64);
			goto free_on_completion;
		}
	}
#else
	{
		k=0;
		for(i = 0; i < comp->buf_count; i++) {
			cbuf = CVM_DRV_GET_PTR(comp->lstore[i].s.addr);
			for(j = 0; j < comp->lstore[i].s.size; j++) {
				if(cbuf[j] != pattern[(k++ & 0xff)]) {
					printf("Data mismatch in local buffer %d\n", i);
					printf("First 64 bytes in local buffer\n");
					cvm_drv_print_data(cbuf, 64);
					goto free_on_completion;
				}
			}
		}
	}
#endif
	printf("DMA RECV Data Match (%d bytes): Success\n", comp->rem_size);

free_on_completion:
#if defined(DMA_USE_MALLOC)
	cvmx_free(castptr(void *, comp->malloc_buf));
#else
	for(i = 0; i < comp->buf_count; i++) {
		if(comp->lstore[i].s.addr) {
			cbuf = CVM_DRV_GET_PTR(comp->lstore[i].s.addr);
			cvm_common_free_fpa_buffer(cbuf, CVM_FPA_TEST_POOL, 0);
		}
	}
#endif
}








void
cvmcs_print_dma_demo_instr(struct oct_dma_test_info  *dma_info)
{
	int i;
	printf("\n\n--DMA DEMO Request No: %llu (bufs: %llu) Type: %s \n",
	        cast64(dma_info->request_no),
	        cast64(dma_info->bufcount),
	       (dma_info->test_type == DMA_DEMO_OCTEON_SEND)?"Send":"Receive");

	printf("Remote Buffer List:\n");
	for(i = 0; i < dma_info->bufcount; i++)  {
		printf("Addr: 0x%016lx, size: %lu\n", dma_info->buf_addr[i],
		        dma_info->buf_size[i]);
	}
}









/* Routine to process the DMA_DEMO_OP instruction received from remote host.
 * The instruction contains a list of pointers to remote host buffers and their
 * sizes. This routine attempts to send data in a pattern defined in 
 * components/driver/common/octeon-dma-test.h for PCI SEND operation. The
 * remote host will verify the pattern. For a PCI RECEIVE operation, it issues
 * a PCI receive command and verifies the pattern locally.
 */

int
cvmcs_process_dma_demo(cvmx_wqe_t  *wqe)
{
	cvmx_raw_inst_front_t  *front;
	cvm_pci_dma_cmd_t       pci_cmd;
	cvmx_buf_ptr_t          lptr[OCTEON_MAX_DMA_LOCAL_POINTERS];
	cvm_dma_remote_ptr_t    rptr[OCTEON_MAX_DMA_REMOTE_POINTERS];
	struct oct_dma_test_info  *dma_info;
	struct dma_comp_store   comp, *cptr;
	uint32_t                localsize, rem_size, i, j, lptr_cnt=0;

#if defined(DMA_USE_COMPLETION_WORD)
	cvm_dma_comp_ptr_t     *comp_ptr = NULL;
	uint8_t                *word_to_check= NULL;
#endif

#if defined(DMA_USE_MALLOC)
	/* If the local buffers are allocated using malloc(), each local buffer
	 * is limited only by the PCI DMA hardware limit for a DMA local buffer.
	 */
	uint8_t                *malloc_buf= NULL;
	uint32_t                max_lbuf_size = MAX_PCI_DMA_LOCAL_BUF_SIZE ;
#else
	/* If the local buffers are allocated from FPA Pool, each local buffer
	 * is limited by the size of the FPA buffer. Note that the buffer size
	 */
	uint32_t                max_lbuf_size = CVM_FPA_TEST_POOL_SIZE-1;
#endif


	/* Get the PCI instruction bytes */
 	front = (cvmx_raw_inst_front_t *)(CVM_DRV_GET_PTR(wqe->packet_ptr.s.addr));


	/* Instructions from the host arrive with param = 0. If its 0x20, then this
     * is a WQE that was scheduled by the PCI DMA hardware on DMA completion.
     */
	if(front->irh.s.param == 0x20) {
		printf("Received WQE for DMA Completion\n");
		cptr = (struct dma_comp_store *)((uint8_t *)front+CVM_RAW_FRONT_SIZE);
		cvmcs_dma_completion_check(cptr);
		cvm_free_host_instr(wqe);
		return 0;
	}


	/* We reach here only for host PCI instruction processing.*/
	/* The DMA operation information follows the PCI instruction in the
     * received data. 
     */
	dma_info = (struct oct_dma_test_info*)((uint8_t *)front+CVM_RAW_FRONT_SIZE);
	cvmcs_print_dma_demo_instr(dma_info);

	/* Get the total bytes to transfer */
	rem_size = 0;
	for(i = 0; i < dma_info->bufcount; i++)
		rem_size += dma_info->buf_size[i];


	for(i = 0; i < OCTEON_MAX_DMA_LOCAL_POINTERS; i++) 
		lptr[i].u64 = 0;


	/* Ensure that the transaction can fit in one PCI DMA command. You could
	 * issue multiple PCI DMA Commands, but this demo application limits to
	 * issuing one PCI DMA command per transaction.
	 */
	localsize = 0; lptr_cnt = 0;
	while(localsize < rem_size) {
		lptr_cnt++; 
		localsize += max_lbuf_size;
	}

	
	if(lptr_cnt > OCTEON_MAX_DMA_LOCAL_POINTERS) {
		printf("Discard. Need %d local pointers for this DMA demo transfer\n",
		       lptr_cnt);
		goto dma_return_data_end;
	}


#if defined(DMA_USE_COMPLETION_WORD)
	/* If the DMA Completion uses a memory location, get a word from the
	 * core PCI driver. 
	 */
	comp_ptr = cvm_get_dma_comp_ptr();
	if(comp_ptr == NULL) {
		printf("Discard. No comp_ptr allocated\n");
		goto dma_return_data_end;
	}
	word_to_check = &comp_ptr->comp_byte;
	*word_to_check = 0xff;
#endif



#if defined(DMA_USE_MALLOC)

	malloc_buf = cvmx_malloc(cvm_common_arenas, rem_size);
	if(malloc_buf == NULL) {
		printf("Discard. Local buf alloc failed\n");
		goto dma_return_data_end;
 	}

#else

	for(i = 0; i < lptr_cnt; i++) {
		void *lbuf;
		lbuf=cvm_common_alloc_fpa_buffer(CVMCS_TEST_BUF_PTR, CVM_FPA_TEST_POOL);
		if(lbuf == NULL) {
			printf("Discard. Local buf alloc failed\n");
			goto dma_return_data_end;
		}
		if(OCTEON_IS_MODEL(OCTEON_CN78XX))
			*((cvmx_buf_ptr_pki_t *)&lptr[i])->addr = CVM_DRV_GET_PHYS(lbuf);
		else
			lptr[i].s.addr = CVM_DRV_GET_PHYS(lbuf);
	}

#endif


	/* Prepare the local pointers for DMA. */
	localsize = 0;
	if(OCTEON_IS_MODEL(OCTEON_CN78XX)) {
		cvm_but_ptr_pki_t *lptr_o3 = lptr; 
		for( i = 0, j = 0; i < lptr_cnt; i++)  {
			int k;
			uint8_t  *lbuf;

#if defined(DMA_USE_MALLOC)
			lbuf = malloc_buf + localsize;
			lptr_o3[i]->addr = CVM_DRV_GET_PHYS(lbuf);
#else
			lbuf = CVM_DRV_GET_PTR(lptr_o3[i]->addr);
#endif

			if((localsize + max_lbuf_size) < rem_size)
				lptr_o3[i]->size = max_lbuf_size;
			else
				lptr_o3[i]->size = (rem_size - localsize);

			localsize += lptr_o3[i]->size;

			if(dma_info->test_type == DMA_DEMO_OCTEON_SEND) {
				for(k = 0; k < lptr_o3[i]->size; k++)
					lbuf[k] = pattern[j++ & 0xff];
			}
		}
	}
	else {
		for( i = 0, j = 0; i < lptr_cnt; i++)  {
			int k;
			uint8_t  *lbuf;

#if defined(DMA_USE_MALLOC)
			lbuf = malloc_buf + localsize;
			lptr[i].s.addr = CVM_DRV_GET_PHYS(lbuf);
#else
			lbuf = CVM_DRV_GET_PTR(lptr[i].s.addr);
#endif

			if((localsize + max_lbuf_size) < rem_size)
				lptr[i].s.size = max_lbuf_size;
			else
				lptr[i].s.size = (rem_size - localsize);

			localsize += lptr[i].s.size;

			if(dma_info->test_type == DMA_DEMO_OCTEON_SEND) {
				for(k = 0; k < lptr[i].s.size; k++)
					lbuf[k] = pattern[j++ & 0xff];
			}
		}
	}
	pci_cmd.u64 = 0;
	pci_cmd.s.nl = lptr_cnt;
	pci_cmd.s.q_no = 0;

	/* Prepare the remote pointers for DMA. The demo limits the number of
	 * remote pointers to fit in one PCI DMA Command.
	 */
	{
	uint32_t   rsize;
	j = 0;
	for(i = 0; i < dma_info->bufcount; i++) {
		rsize = 0;
		while(rsize < dma_info->buf_size[i]) {

			rptr[j].s.addr = dma_info->buf_addr[i] + rsize;
			if((rsize + MAX_PCI_DMA_LOCAL_BUF_SIZE) < dma_info->buf_size[i])
				rptr[j].s.size = MAX_PCI_DMA_LOCAL_BUF_SIZE;
			else
				rptr[j].s.size = (dma_info->buf_size[i] - rsize);
			rsize += rptr[j].s.size;
			j++;
			if(j == OCTEON_MAX_DMA_REMOTE_POINTERS) {
				printf("DMA Test reached max remote pointers. Aborting!\n");
				goto dma_return_data_end;
			}
		}
	}
	pci_cmd.s.nr = j;
	}


	/* Depending on the type of completion used, the corresponding pointer
	 * is passed in the PCI Command. For WQE, the received WQE is reused.
	 */
#if defined(DMA_USE_COMPLETION_WORD)
	pci_cmd.s.flags |= PCI_DMA_PUTWORD;
	pci_cmd.s.ptr = cvmx_ptr_to_phys(word_to_check);
#else
	pci_cmd.s.flags |= PCI_DMA_PUTWQE;
	front->irh.s.param = 0x20;
	pci_cmd.s.ptr = cvmx_ptr_to_phys(wqe);
#endif	



	/* Save a copy of the local pointers for processing on DMA completion. */
	comp.test_type = dma_info->test_type;
	comp.rem_size  = rem_size;
#if defined(DMA_USE_MALLOC)
	comp.malloc_buf = (unsigned long)malloc_buf;
#else
	comp.buf_count = pci_cmd.s.nl;
	for(i = 0; i < pci_cmd.s.nl; i++) {
		comp.lstore[i].u64 = lptr[i].u64;
	}
#endif



#if defined(DMA_USE_COMPLETION_WQE)
	/* Copy the local buffer information into the WQE that will be scheduled
	 * on DMA completion.
	 */
	cptr = (struct dma_comp_store *)((uint8_t *)front+CVM_RAW_FRONT_SIZE);
	memcpy(cptr, &comp, sizeof(struct dma_comp_store));
#endif



	/* Perform the required PCI DMA operation. */
	if(comp.test_type == DMA_DEMO_OCTEON_SEND) {
		printf("Send PCI DMA pci_cmd: 0x%016lx lptr_cnt: %d\n",
		       pci_cmd.u64, lptr_cnt);
		cvm_pci_dma_send_data(&pci_cmd, lptr, rptr);
	} else {
		printf("Recv PCI DMA pci_cmd: 0x%016lx lptr_cnt: %d\n",
		       pci_cmd.u64, lptr_cnt);
		cvm_pci_dma_recv_data(&pci_cmd, lptr, rptr);
	}


	/* If the DMA completion issues a WQE, no more processing needs to be
	 * done here. If DMA completion is indicated by polling a memory 
	 * location, we do that here.
	 */
#if defined(DMA_USE_COMPLETION_WORD)
	i = 0;
	while((*word_to_check == 0xff) && (++i < DMA_WAIT_INTERVAL)) {
		cvmx_wait(10);
		CVMX_SYNCWS;
	}

	if(i == DMA_WAIT_INTERVAL) {
		printf("DMA FAILED interval: %d  Completion Word value: %x\n", i,
		       *word_to_check);
	} else {
		printf("DMA Completed!! interval: %d Completion word: %x\n", i,
		       *word_to_check);
	}

	/* Call to verify the data received for a PCI RECEIVE operation. This
	 * routine also frees the local buffers.
	 */
	cvmcs_dma_completion_check(&comp);
#else
	return 0;
#endif



/* We come here only if the DMA completion used a memory location. Free the
 * memory location here and free the WQE that held the DMA_DEMO insruction.
 */
dma_return_data_end:
#if defined(DMA_USE_COMPLETION_WORD)
	if(comp_ptr)
		cvm_release_dma_comp_ptr(comp_ptr);

	cvm_free_host_instr(wqe);
#endif
	return 0;
}


#endif



/* $Id$ */
