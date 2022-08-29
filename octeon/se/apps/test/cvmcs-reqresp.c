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

#include <stdio.h>
#include "cvmx.h"
#include "cvmx-config.h"
#include "cvm-driver-defs.h"
#include "cvm-drv.h"
#include "cvm-pci-dma.h"
#include "cvm-drv-reqresp.h"
#include "cvm-drv-debug.h"
#include "liquidui_common.h"
#include "cvmcs-test.h"

#include "cvmcs-common.h"

CVMX_SHARED uint64_t cvmcs_pkt_count[MAX_DRV_CORES] =
		{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
		 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
		 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};


extern               uint32_t      core_id;
extern CVMX_SHARED   uint64_t      cpu_freq;




/** Print the PCI input queue base address and size */
void
cvmcs_print_input_q()
{
	int i;
	int node = cvmx_get_node_num();
	printf("Input queues\n");
	for(i = 0; i < 4; i++) {
		printf("Q[%d]: Base Addr: 0x%llx  Size: 0x%llx\n", i,
		       CAST64(cvmx_read_csr_node(node, CVMX_NPI_BASE_ADDR_INPUT0 + (i * 0x10))),
		       CAST64(cvmx_read_csr_node(node, CVMX_NPI_SIZE_INPUT0 + (i * 0x10))));
	}
}






void
cvmcs_print_reg_contents()
{
	cvmcs_print_input_q();
}



static inline int
__get_localbufsize(uint32_t         resplen,
                   uint32_t         curlen,
                   cvmx_buf_ptr_t  *ptr,
                   int              idx,
                   cvmx_wqe_t		*wqe)
{
/* If currsize + byes in this buffer exceeds resplen, then bytes in this buffer
   satisfies resplen; in which case return resplen - curr size;

	bytes in this buffer is pkt pool size - offset.
	Subtract 24 for first buffer.
*/
	int offset; 
	uint32_t thisbufsize;

	if(OCTEON_IS_MODEL(OCTEON_CN78XX)) {
		cvmx_pki_stylex_buf_t     style_buf_reg;

		style_buf_reg.u64 = cvmx_read_csr_node(cvmx_get_node_num(), CVMX_PKI_STYLEX_BUF(cvmx_wqe_get_style(wqe)));
		if (idx ==0 )
			offset = style_buf_reg.s.first_skip * 8 + wqe->word0.pki.apad + 8;  
		else
			offset = style_buf_reg.s.later_skip * 8 + wqe->word0.pki.apad + 8;

	} else {
		offset = (ptr->s.addr - (((ptr->s.addr >> 7) - ptr->s.back) << 7));
	}

	thisbufsize = (CVMX_FPA_PACKET_POOL_SIZE - offset - ((idx == 0)?24:0));

	return ((curlen + thisbufsize) > resplen)?(resplen - curlen):thisbufsize;
}







int
cvmcs_process_direct_instruction(cvmx_wqe_t             *wqe,
                                 cvmx_raw_inst_front_t  *front)
{
	cvmx_oct_pci_dma_inst_hdr_t     dmacmd;
	cvm_dma_remote_ptr_t            rptr;
	cvmx_oct_pci_dma_local_ptr_t    lptr[15];
	cvmx_buf_ptr_t                 *dptr;
	uint64_t                       *respptr;
	uint32_t                        respsize, currsize=0, lastrptrsize=0;
	int                             i = 0, bufidx = 0;
	uint8_t							*pkt_ptr;


	/* The response contains the entire data payload in the received request
	   PLUS 16 bytes for the ORH and status words. Since the wqe payload
	   contains the front data as well, we take that out of the total. */
	respsize = cvmx_wqe_get_len(wqe) - sizeof(cvmx_raw_inst_front_t) + 16;

	//printf("%s: wqe @ %p, len: %d pkt_ptr: 0x%016lx respsize: %d\n", __FUNCTION__, wqe, wqe->len, wqe->packet_ptr.u64, respsize);


	/* These fields are fixed. The rest we generate on the way. */
	dmacmd.word0.u64      = 0;
	dmacmd.word1.u64 = 0;

	dmacmd.word0.cn38xx.nr = 1;
	dmacmd.word0.cn38xx.lport = front->irh.s.pcie_port;

#ifdef CVMCS_DMA_IC
	dmacmd.word0.cn38xx.c = 0;
#else
	dmacmd.word0.cn38xx.c = core_id & 1;
#endif


	/* We use the space in the wqe->packet data for ORH and status words. We
	   set them to 0. If the host app checks the ORH, set the first 8 bytes
	   accordingly. */
	pkt_ptr = (uint8_t *) wqe->packet_data;
	
	respptr = (uint64_t *) (pkt_ptr + sizeof(cvmx_raw_inst_front_t));
	respptr[0] = respptr[1] = 0;


	/* The first 8 bytes to be transmitted are the ORH. */
	lptr[i].u64    = 0;
	lptr[i].cn38xx.addr = cvmx_ptr_to_phys(respptr);
	lptr[i].cn38xx.size = 8;
	currsize += 8;
	i++;

	/* Then starts the data payload. The first local pointer for data needs to
	   be handled differently since the WQE packet ptr data include the front
	   data. */

	lptr[i].u64    = 0ULL;
	dptr = (cvmx_buf_ptr_t *)cvmx_phys_to_ptr(wqe->packet_ptr.s.addr + sizeof(cvmx_raw_inst_front_t) );
	lptr[i].cn38xx.addr = cvmx_ptr_to_phys(dptr);

	/* response length includes 16 bytes which are not present in the input
	   bytes, so don't include them. Also current size includes the 8 bytes of
	   ORH which is not present in the input bytes, so don't include them.
	*/
	lptr[i].cn38xx.size =  __get_localbufsize(respsize - 16,
	                            currsize-8, &wqe->packet_ptr, bufidx,wqe);

	lptr[i].cn38xx.pool = CVMX_FPA_PACKET_POOL;
	lptr[i].cn38xx.i = 1;
	lptr[i].cn38xx.l = 0;


	currsize += lptr[i].cn38xx.size;
	i++; bufidx++; 

	/* Get the next buffer pointer. */
	dptr = (cvmx_buf_ptr_t *)cvmx_phys_to_ptr(wqe->packet_ptr.s.addr - 8);


	/* If there are more buffers, start adding them to this DMA command. */
	while(bufidx < cvmx_wqe_get_bufs(wqe)) {

		lptr[i].u64    = dptr->u64;
		lptr[i].cn38xx.size =  __get_localbufsize(respsize - 16,
		                            currsize-8, dptr, bufidx,wqe);
		lptr[i].cn38xx.pool = CVMX_FPA_PACKET_POOL;
		lptr[i].cn38xx.i = 1;
		lptr[i].cn38xx.l = 0;

		currsize += lptr[i].cn38xx.size;
		i++; bufidx++;

		/* If we have collected max local pointers, then issue a DMA command.
		   The rest will be sent in additional DMA commands later on. */
		if(i == octdev_max_dma_localptrs()) {
			dmacmd.word0.cn38xx.nl =i;
			/* The location to copy in host memory needs to be adjusted to
			   account for the bytes we already sent. */
			rptr.s.addr = front->rptr + lastrptrsize;
			rptr.s.size = currsize - lastrptrsize;
			CVMX_SYNCWS;
			if(cvm_pci_dma_raw(&dmacmd, lptr, &rptr)) {
				printf("%s: Failed to send DMA command: word0: 0x%016lx, word1: 0x%016lx\n",
				       __FUNCTION__, dmacmd.word0.u64, dmacmd.word1.u64);
				return 1;
			}
			i = 0; lastrptrsize = currsize;
		}

		/* Get the next buffer pointer */
		dptr = (cvmx_buf_ptr_t *)cvmx_phys_to_ptr(dptr->s.addr - 8);
	}


	/* If there isn't enough space to accomodate the last local pointer (for
	   status word, send the DMA command now for accumulated local buffers. */
	if((i+1) > octdev_max_dma_localptrs()) {
		dmacmd.word0.cn38xx.nl = i;
		rptr.s.addr = front->rptr + lastrptrsize;
		rptr.s.size = currsize - lastrptrsize;
		CVMX_SYNCWS;
		if(cvm_pci_dma_raw(&dmacmd, lptr, &rptr)) {
			printf("%s: Failed to send DMA command: word0: 0x%016lx, word1: 0x%016lx\n",
			       __FUNCTION__, dmacmd.word0.u64, dmacmd.word1.u64);
			return 1;
		}
		i = 0; lastrptrsize = currsize;
	}


	/* Finally, the status bytes should be included in the response. */
	lptr[i].u64    = 0;
	lptr[i].cn38xx.addr = cvmx_ptr_to_phys(respptr + 1);
	lptr[i].cn38xx.size = 8;
	lptr[i].cn38xx.pool =  cvmcs_wqe_pool();
	lptr[i].cn38xx.i = 1;

	currsize += 8;

	i++;
	
	dmacmd.word0.cn38xx.nl = i;
#ifdef CVMCS_DMA_IC
	dmacmd.word0.cn38xx.ca = 1;
#endif
	rptr.s.addr = front->rptr + lastrptrsize;
	rptr.s.size = currsize - lastrptrsize;
	CVMX_SYNCWS;

	return cvm_pci_dma_raw(&dmacmd, lptr, &rptr);
}







static inline void
__get_scatter_pointer(struct octeon_sg_entry  *sg,
                      cvm_dma_remote_ptr_t    *rptr,
                      int                      idx)
{
	rptr->s.addr = sg[idx >> 2].ptr[idx & 0x3];
	rptr->s.size = sg[idx >> 2].u.size[(3 - (idx&0x3))];
}




static inline int
__get_total_scatter_size(struct octeon_sg_entry  *sg, int cnt)
{
	int i, j, k, rlen = 0;

	for(i = 0, k = 0; i < cnt; k++) {
		for(j = 0; ((j < 4) && (i < cnt)); j++, i++)  {
			rlen += sg[k].u.size[3-j];
		}
	}

	return rlen;
}








//#define dbg_printf(format, ...)    printf( format, ## __VA_ARGS__)

#define dbg_printf(format, ...)    do { } while(0)

int resp_pcie_port = 0;


static int
__send_dma_command(cvm_dma_remote_ptr_t    *rptr,
           cvmx_oct_pci_dma_local_ptr_t    *lptr,
           int                             *ridx,
           int                             *lidx,
           cvm_dma_remote_ptr_t            *nextrptr)
{
	cvmx_oct_pci_dma_inst_hdr_t     dmacmd;

	dmacmd.word0.u64   = 0;
	dmacmd.word1.u64   = 0;

    dmacmd.word0.cn38xx.c = core_id & 1;
    dmacmd.word0.cn38xx.nr = *ridx;
    dmacmd.word0.cn38xx.nl = *lidx;
    dmacmd.word0.cn38xx.lport = resp_pcie_port;
	
	CVMX_SYNCWS;

	if(cvmx_unlikely(cvm_pci_dma_raw(&dmacmd, lptr, rptr))) {
		printf("%s: Failed to send DMA command: word0: 0x%016lx, word1: 0x%016lx\n",
		       __FUNCTION__, dmacmd.word0.u64, dmacmd.word1.u64);
		return 1;
	}

	*lidx = 0; *ridx = 0;

	/* If the last rptr was split, the remainder would be in nextrptr.
	   Use it now. */
	if(nextrptr->u64) {
		dbg_printf("nextrptr exists (0x%016lx), copied to idx %d\n",
		        nextrptr->u64, *ridx);
		rptr[*ridx].u64 = nextrptr->u64;
		nextrptr->u64 = 0;
		(*ridx)++;
	}

	return 0;
}






static inline int
__add_rptr(cvm_dma_remote_ptr_t            *rptr,
           cvmx_oct_pci_dma_local_ptr_t    *lptr,
           cvm_dma_remote_ptr_t            *nextrptr,
           struct octeon_sg_entry          *sg,
           int                             *sgidx,
           int                             *ridx,
           int                             *lidx,
           uint32_t                        *currlsize,
           uint32_t                        *currrsize)
{

	dbg_printf("currlsize: %d currrsize: %d lidx: %d ridx: %d sgidx: %d\n",
	           *currlsize, *currrsize, *lidx, *ridx, *sgidx);

send_remaining:
	if(*currrsize < *currlsize)  {
		while( (*currrsize < *currlsize)
		         && (*ridx < (octdev_max_dma_remoteptrs() - 1)) )  {

			__get_scatter_pointer(sg, &rptr[*ridx], *sgidx);
			dbg_printf("Adding rptr (0x%016lx) at idx %d from sg at idx %d\n",
			           rptr[*ridx].u64, *ridx, *sgidx);
			*currrsize += rptr[*ridx].s.size;
			(*sgidx)++;
			(*ridx)++;
		}
	}

	if( cvmx_likely((*ridx < (octdev_max_dma_remoteptrs() - 1))
	                 && (*lidx < octdev_max_dma_localptrs()) )) {
		return 0;
	}

	if(*currrsize > *currlsize) {
		/* We have collected enough rptr's to send the local buf contents,
		   but size of the last rptr added exceeds the local data size.
		   Adjust the last rptr and save the space left out from the rptr
		   to be used for next DMA. */
		dbg_printf("Adjust rptr[%d]: 0x%016lx to", *ridx-1,
		           rptr[(*ridx - 1)].u64);
		rptr[(*ridx - 1)].s.size -= (*currrsize - *currlsize);
		nextrptr->s.size = (*currrsize - *currlsize);
		nextrptr->s.addr = rptr[(*ridx - 1)].s.addr + rptr[(*ridx - 1)].s.size;
		dbg_printf(" 0x%016lx nextrptr: 0x%016lx\n", rptr[(*ridx - 1)].u64,
		           nextrptr->u64);
	}


	/* We cannot add any more remote pointers. Either we have exactly enough
	   space in the rptr buf (rsize == lsize), or we have reached the max
	   rptrs. If we have maxed out in pointer count and we still don't have
	   ehough rptr buf space, adjust the local buf ptrs. */
	if(*currrsize < *currlsize) {

		cvmx_oct_pci_dma_local_ptr_t    savedlptrs[15];
		cvmx_oct_pci_dma_inst_hdr_t     dmacmd;
		int savedidx=0;
		uint64_t	addr = 0, size = 0;
		
		/* Got back in the local buffer list till the sum of local buffers
		   matches or just exceed by one local pointer's worth. */
		while( (*currlsize - lptr[(*lidx - 1)].cn38xx.size ) >= *currrsize) {
			(*lidx)--;
			*currlsize -= lptr[*lidx].cn38xx.size;
			savedlptrs[savedidx].u64 = lptr[*lidx].u64;
			savedidx++;
		}

		/* At this point, either currrsize = currlsize
		   or currrsize < currlsize */ 
		if(*currrsize < *currlsize) {
			dbg_printf("Adjust lptr[%d]: 0x%016lx to", *lidx-1,
			          lptr[(*lidx - 1)].u64);

			size = lptr[(*lidx - 1)].cn38xx.size;
			lptr[(*lidx - 1)].cn38xx.size = size - (*currlsize - *currrsize);
			lptr[(*lidx - 1)].cn38xx.i = 0;
			savedlptrs[savedidx].u64 = 0;
			savedlptrs[savedidx].cn38xx.size = (*currlsize - *currrsize);

			addr = lptr[(*lidx - 1)].cn38xx.addr; 
			size = lptr[(*lidx - 1)].cn38xx.size;
			savedlptrs[savedidx].cn38xx.addr = addr + size;
		
			savedlptrs[savedidx].cn38xx.pool = lptr[(*lidx - 1)].cn38xx.pool;

			addr = 	((savedlptrs[savedidx].cn38xx.addr - 
					 (lptr[(*lidx - 1)].cn38xx.addr & ~(CVMX_FPA_PACKET_POOL_SIZE - 1))) >> 7);
			savedlptrs[savedidx].cn38xx.back = lptr[(*lidx - 1)].cn38xx.back  + addr ; 

			savedlptrs[savedidx].cn38xx.i = 1;
			savedidx++;
			dbg_printf(" 0x%016lx nextlptr: 0x%016lx\n", lptr[(*lidx - 1)].u64,
			           savedlptrs[savedidx].u64);
		}

		/* We've made all the adjustments we need. Send the DMA Cpmmand now. */
		dmacmd.word0.u64   = 0;
		dmacmd.word1.u64   = 0;

		dmacmd.word0.cn38xx.c = core_id & 1;
		dmacmd.word0.cn38xx.nr = *ridx;
		dmacmd.word0.cn38xx.nl = *lidx;
		dmacmd.word0.cn38xx.lport = resp_pcie_port;

		CVMX_SYNCWS;

		if(cvmx_unlikely(cvm_pci_dma_raw(&dmacmd, lptr, rptr))) {
			printf("%s: Failed to send DMA command: word0: 0x%016lx, word1: 0x%016lx\n",
			       __FUNCTION__, dmacmd.word0.u64, dmacmd.word1.u64);
			return 1;
		}

		/* Now that the DMA command was sent successfully, lets get all the
		   local pointers we rolled back. */
		*lidx = 0; *ridx = 0; *currlsize = 0; *currrsize = 0;
		while(*lidx < savedidx) {
			lptr[*lidx].u64 = savedlptrs[*lidx].u64;
			*currlsize += lptr[*lidx].cn38xx.size;
			(*lidx)++;
		}

		/* Get rptr's for the remaining local buffers. */
		goto send_remaining;
	}

	/* currlsize = currsize. Send DMA now. */
	return __send_dma_command(rptr, lptr, ridx, lidx, nextrptr);
}










int
cvmcs_process_scatter_instruction(cvmx_wqe_t  *wqe)
{
	cvmx_raw_inst_front_t  *front;
	struct octeon_sg_entry         *sg;
	int                             lidx=0, ridx=0, bufidx = 0, sgidx = 0;
	cvm_dma_remote_ptr_t            rptr[15], nextrptr;
	cvmx_oct_pci_dma_local_ptr_t    lptr[15];
	cvmx_buf_ptr_t                 *dptr;
	uint64_t                       *respptr;
	uint32_t                        respsize, currlsize=0, currrsize = 0;
	uint8_t							*pkt_ptr;



	front = (cvmx_raw_inst_front_t *)wqe->packet_data;
	sg = (struct octeon_sg_entry *)front->rptr;
	resp_pcie_port = front->irh.s.pcie_port;


	dbg_printf("WQE @%p pkt_ptr @0x%016lx len: %d inbufs: %d sgcnt: %d\n", 
	       wqe, wqe->packet_ptr.u64, cvmx_wqe_get_len(wqe), cvmx_wqe_get_bufs(wqe), front->irh.s.rlenssz);
//	cvm_drv_print_data(sg, (((front->irh.s.rlenssz + 3)/4) * 40) );


	respsize = __get_total_scatter_size(sg, front->irh.s.rlenssz);

	nextrptr.u64 = 0;

	/* We use the space in the wqe->packet data for ORH and status words. We
	   set them to 0. If the host app checks the ORH, set the first 8 bytes
	   accordingly. */
	pkt_ptr = (uint8_t  *)wqe->packet_data;

	respptr = (uint64_t *) (pkt_ptr + sizeof(cvmx_raw_inst_front_t));
	respptr[0] = respptr[1] = 0;


	/* The first 8 bytes to be transmitted are the ORH. */
	lptr[lidx].u64    = 0;
    lptr[lidx].cn38xx.addr = cvmx_ptr_to_phys(respptr);
    lptr[lidx].cn38xx.size = 8;

	currlsize += 8;
	lidx++;

	if(__add_rptr(rptr, lptr, &nextrptr, sg, &sgidx, &ridx, &lidx, &currlsize, &currrsize)) {
		printf("WQE @%p pkt_ptr @0x%016lx len: %d inbufs: %d sgcnt: %d\n", 
	       wqe, wqe->packet_ptr.u64, cvmx_wqe_get_len(wqe),
		   cvmx_wqe_get_bufs(wqe), front->irh.s.rlenssz);
		return 1;
	}

	dbg_printf("---1---\n");

	/* Then starts the data payload. The first local pointer for data needs to
	   be handled differently since the WQE packet ptr data include the front
	   data. */
	
	lptr[lidx].u64    = 0ULL;
	dptr = (cvmx_buf_ptr_t *)cvmx_phys_to_ptr(wqe->packet_ptr.s.addr + sizeof(cvmx_raw_inst_front_t) );

    lptr[lidx].cn38xx.addr = cvmx_ptr_to_phys(dptr);


	/* response length includes 16 bytes which are not present in the input
	   bytes, so don't include them. Also current size includes the 8 bytes of
	   ORH which is not present in the input bytes, so don't include them.
	*/
    lptr[lidx].cn38xx.size = __get_localbufsize(respsize - 16,
	                         	 currlsize-8, &wqe->packet_ptr, bufidx,wqe);
    lptr[lidx].cn38xx.pool = CVMX_FPA_PACKET_POOL;
    lptr[lidx].cn38xx.i = 1;
    lptr[lidx].cn38xx.l = 0;


	currlsize += lptr[lidx].cn38xx.size;
	lidx++; bufidx++; 

	if(__add_rptr(rptr, lptr, &nextrptr, sg, &sgidx, &ridx, &lidx, &currlsize, &currrsize)) {
		printf("WQE @%p pkt_ptr @0x%016lx len: %d inbufs: %d sgcnt: %d\n", 
	       wqe, wqe->packet_ptr.u64, cvmx_wqe_get_len(wqe), cvmx_wqe_get_bufs(wqe), front->irh.s.rlenssz);
		return 1;
	}

	dbg_printf("---2---\n");

	/* Get the next buffer pointer. */
	dptr = (cvmx_buf_ptr_t *)cvmx_phys_to_ptr(wqe->packet_ptr.s.addr - 8);
	dbg_printf(">> Next pkt ptr @ 0x%016lx\n", dptr->u64);

	/* If there are more buffers, start adding them to this DMA command. */
	while(bufidx < cvmx_wqe_get_bufs(wqe)) {

		lptr[lidx].u64    = dptr->u64;
	    lptr[lidx].cn38xx.size = __get_localbufsize(respsize - 16,
	                         	 currlsize-8, dptr, bufidx,wqe);
    	lptr[lidx].cn38xx.pool = CVMX_FPA_PACKET_POOL;
	    lptr[lidx].cn38xx.i = 1;
    	lptr[lidx].cn38xx.l = 0;

		currlsize += lptr[lidx].cn38xx.size;
		lidx++; bufidx++;

		if(__add_rptr(rptr, lptr, &nextrptr, sg, &sgidx, &ridx, &lidx, &currlsize, &currrsize)) {
			printf("WQE @%p pkt_ptr @0x%016lx len: %d inbufs: %d sgcnt: %d\n", 
			       wqe, wqe->packet_ptr.u64, cvmx_wqe_get_len(wqe),
			       cvmx_wqe_get_bufs(wqe), front->irh.s.rlenssz);
			return 1;
		}

		dbg_printf("---3---\n");

		dptr = (cvmx_buf_ptr_t *)cvmx_phys_to_ptr(dptr->s.addr - 8);

		dbg_printf(">> Next pkt ptr @ 0x%016lx\n", dptr->u64);
	}


	/* If there isn't enough space to accomodate the last local pointer (for
	   status word, send the DMA command now for accumulated local buffers. */
	if( lidx == octdev_max_dma_localptrs()) {
		if(__send_dma_command(rptr, lptr, &ridx, &lidx, &nextrptr)) {
			printf("WQE @%p pkt_ptr @0x%016lx len: %d inbufs: %d sgcnt: %d\n", 
		       wqe, wqe->packet_ptr.u64, cvmx_wqe_get_len(wqe), cvmx_wqe_get_bufs(wqe), front->irh.s.rlenssz);
			return 1;
		}
	}

	dbg_printf("---4---\n");

	/* Finally, the status bytes should be included in the response. */
	lptr[lidx].u64    = 0;
    lptr[lidx].cn38xx.addr = cvmx_ptr_to_phys(respptr + 1); 
    lptr[lidx].cn38xx.size = 8;
	lptr[lidx].cn38xx.pool = cvmcs_wqe_pool();
    lptr[lidx].cn38xx.i = 1;

	currlsize += 8;
	lidx++;

	if(__add_rptr(rptr, lptr, &nextrptr, sg, &sgidx, &ridx, &lidx, &currlsize, &currrsize)) {
		printf("WQE @%p pkt_ptr @0x%016lx len: %d inbufs: %d sgcnt: %d\n", 
		       wqe, wqe->packet_ptr.u64, cvmx_wqe_get_len(wqe),
		       cvmx_wqe_get_bufs(wqe), front->irh.s.rlenssz);
		return 1;
	}

	dbg_printf("---5---\n");

	if(lidx || ridx) {
		__add_rptr(rptr, lptr, &nextrptr, sg, &sgidx, &ridx, &lidx, &currlsize, &currrsize);
		if(__send_dma_command(rptr, lptr, &ridx, &lidx, &nextrptr)) {
			printf("WQE @%p pkt_ptr @0x%016lx len: %d inbufs: %d sgcnt: %d\n", 
		       wqe, wqe->packet_ptr.u64, cvmx_wqe_get_len(wqe), cvmx_wqe_get_bufs(wqe), front->irh.s.rlenssz);
			return 1;
		}
	}
	dbg_printf("---6---\n");

	/* Time to free the sg entry buffer. */
	cvm_common_free_fpa_buffer(sg, CVM_FPA_TEST_POOL, 0);

	dbg_printf("--End of %s\n", __FUNCTION__);
	return 0;
}

/*-------------------------- Routines for OCT-III models -----------------------------*/

static int
__send_dma_command_o3(cvm_dma_remote_ptr_t    *rptr,
           cvmx_oct_pci_dma_local_ptr_t    *lptr,
           int                             *ridx,
           int                             *lidx,
           cvm_dma_remote_ptr_t            *nextrptr, 
		   int								pool)
{
	cvmx_oct_pci_dma_inst_hdr_t     dmacmd;

	dmacmd.word0.u64   = 0;
	dmacmd.word1.u64   = 0;

    dmacmd.word0.cn78xx.csel = core_id & 1;
    dmacmd.word0.cn78xx.nl = *lidx;
    dmacmd.word0.cn78xx.nr = *ridx;
    dmacmd.word0.cn78xx.lport = resp_pcie_port;
	// TBD
    dmacmd.word0.cn78xx.aura = pool; 
	
	CVMX_SYNCWS;

	if(cvmx_unlikely(cvm_pcie_dma_raw_o3(core_id%4, &dmacmd,lptr,rptr))) {
		printf("%s: Failed to send DMA command: word0: 0x%016lx, word1: 0x%016lx\n",
		       __FUNCTION__, dmacmd.word0.u64, dmacmd.word1.u64);
		return 1;
	}

	*lidx = 0; *ridx = 0;

	/* If the last rptr was split, the remainder would be in nextrptr.
	   Use it now. */
	if(nextrptr->u64) {
		dbg_printf("nextrptr exists (0x%016lx), copied to idx %d\n",
		        nextrptr->u64, *ridx);
		rptr[*ridx].u64 = nextrptr->u64;
		nextrptr->u64 = 0;
		(*ridx)++;
	}

	return 0;
}



static inline int
__add_rptr_o3(cvm_dma_remote_ptr_t            *rptr,
           cvmx_oct_pci_dma_local_ptr_t    *lptr,
           cvm_dma_remote_ptr_t            *nextrptr,
           octeon_sg_entry_t               *sg,
           int                             *sgidx,
           int                             *ridx,
           int                             *lidx,
           uint32_t                        *currlsize,
           uint32_t                        *currrsize,
		   int 								pool)
{

	dbg_printf("currlsize: %d currrsize: %d lidx: %d ridx: %d sgidx: %d\n",
	           *currlsize, *currrsize, *lidx, *ridx, *sgidx);

send_remaining:
	if(*currrsize < *currlsize)  {
		while( (*currrsize < *currlsize)
		         && (*ridx < (octdev_max_dma_remoteptrs() - 1)) )  {

			__get_scatter_pointer(sg, &rptr[*ridx], *sgidx);
			dbg_printf("Adding rptr (0x%016lx) at idx %d from sg at idx %d\n",
			           rptr[*ridx].u64, *ridx, *sgidx);
			*currrsize += rptr[*ridx].s.size;
			(*sgidx)++;
			(*ridx)++;
		}
	}

	if( cvmx_likely((*ridx < (octdev_max_dma_remoteptrs() - 1))
	                 && (*lidx < octdev_max_dma_localptrs()) )) {
		return 0;
	}

	if(*currrsize > *currlsize) {
		/* We have collected enough rptr's to send the local buf contents,
		   but size of the last rptr added exceeds the local data size.
		   Adjust the last rptr and save the space left out from the rptr
		   to be used for next DMA. */
		dbg_printf("Adjust rptr[%d]: 0x%016lx to", *ridx-1,
		           rptr[(*ridx - 1)].u64);
		rptr[(*ridx - 1)].s.size -= (*currrsize - *currlsize);
		nextrptr->s.size = (*currrsize - *currlsize);
		nextrptr->s.addr = rptr[(*ridx - 1)].s.addr + rptr[(*ridx - 1)].s.size;
		dbg_printf(" 0x%016lx nextrptr: 0x%016lx\n", rptr[(*ridx - 1)].u64,
		           nextrptr->u64);
	}


	/* We cannot add any more remote pointers. Either we have exactly enough
	   space in the rptr buf (rsize == lsize), or we have reached the max
	   rptrs. If we have maxed out in pointer count and we still don't have
	   ehough rptr buf space, adjust the local buf ptrs. */
	if(*currrsize < *currlsize) {

		cvmx_oct_pci_dma_local_ptr_t    savedlptrs[15];
		cvmx_oct_pci_dma_inst_hdr_t     dmacmd;
		int savedidx=0;
		uint64_t	addr = 0, size = 0;
		
		/* Got back in the local buffer list till the sum of local buffers
		   matches or just exceed by one local pointer's worth. */
		while( (*currlsize - lptr[(*lidx - 1)].cn78xx.size ) >= *currrsize) {
			(*lidx)--;
			*currlsize -= lptr[*lidx].cn78xx.size;
			savedlptrs[savedidx].u64 = lptr[*lidx].u64;
			savedidx++;
		}

		/* At this point, either currrsize = currlsize
		   or currrsize < currlsize */ 
		if(*currrsize < *currlsize) {
			dbg_printf("Adjust lptr[%d]: 0x%016lx to", *lidx-1,
			          lptr[(*lidx - 1)].u64);

			size = lptr[(*lidx - 1)].cn78xx.size;
			lptr[(*lidx - 1)].cn78xx.size = size - (*currlsize - *currrsize);
			lptr[(*lidx - 1)].cn78xx.i=  0;
			savedlptrs[savedidx].u64 = 0;
			savedlptrs[savedidx].cn78xx.size = (*currlsize - *currrsize);

			addr = lptr[(*lidx - 1)].cn78xx.addr; 
			size = lptr[(*lidx - 1)].cn78xx.size;
			savedlptrs[savedidx].cn78xx.addr = addr + size;
		

			addr = 	((savedlptrs[savedidx].cn78xx.addr - 
					 (lptr[(*lidx - 1)].cn78xx.addr & ~(CVMX_FPA_PACKET_POOL_SIZE - 1))) >> 7);
			savedlptrs[savedidx].cn78xx.i = 1;
			savedidx++;
			dbg_printf(" 0x%016lx nextlptr: 0x%016lx\n", lptr[(*lidx - 1)].u64,
			           savedlptrs[savedidx].u64);
		}

		/* We've made all the adjustments we need. Send the DMA Cpmmand now. */
		dmacmd.word0.u64   = 0;
		dmacmd.word1.u64   = 0;

		dmacmd.word0.cn78xx.csel = core_id & 1;
		dmacmd.word0.cn78xx.nl = *lidx;
		dmacmd.word0.cn78xx.nr = *ridx;
		dmacmd.word0.cn78xx.lport = resp_pcie_port;
		dmacmd.word0.cn78xx.aura = pool;

		CVMX_SYNCWS;

		if(cvmx_unlikely(cvm_pcie_dma_raw_o3(core_id%4, &dmacmd, lptr, rptr))) {
			printf("%s: Failed to send DMA command: word0: 0x%016lx, word1: 0x%016lx\n",
			       __FUNCTION__, dmacmd.word0.u64, dmacmd.word1.u64);
			return 1;
		}

		/* Now that the DMA command was sent successfully, lets get all the
		   local pointers we rolled back. */
		*lidx = 0; *ridx = 0; *currlsize = 0; *currrsize = 0;
		while(*lidx < savedidx) {
			lptr[*lidx].u64 = savedlptrs[*lidx].u64;
			*currlsize += lptr[*lidx].cn78xx.size;
			(*lidx)++;
		}

		/* Get rptr's for the remaining local buffers. */
		goto send_remaining;
	}

	/* currlsize = currsize. Send DMA now. */
	return __send_dma_command_o3(rptr, lptr, ridx, lidx, nextrptr, pool);
}



int
cvmcs_process_direct_instruction_o3(cvmx_wqe_t             *wqe,
                                 cvmx_raw_inst_front_t  *front)
{
	cvmx_oct_pci_dma_inst_hdr_t     dmacmd;
	cvm_dma_remote_ptr_t            rptr;
	cvmx_oct_pci_dma_local_ptr_t    lptr[15];
	cvmx_buf_ptr_pki_t              *dptr;
	uint64_t                       *respptr;
	uint32_t                        respsize, currsize=0, lastrptrsize=0;
	int                             i = 0, bufidx = 0;
	uint8_t							*pkt_ptr;


	/* The response contains the entire data payload in the received request
	   PLUS 16 bytes for the ORH and status words. Since the wqe payload
	   contains the front data as well, we take that out of the total. */
	respsize = cvmx_wqe_get_len(wqe) - sizeof(cvmx_raw_inst_front_t) + 16;

	//printf("%s: wqe @ %p, len: %d pkt_ptr: 0x%016lx respsize: %d\n", __FUNCTION__, wqe, wqe->len, wqe->packet_ptr.u64, respsize);


	/* These fields are fixed. The rest we generate on the way. */
	dmacmd.word0.u64      = 0;
	dmacmd.word1.u64 = 0;

	dmacmd.word0.cn78xx.nr = 1;
	dmacmd.word0.cn78xx.lport = front->irh.s.pcie_port;
	dmacmd.word0.cn78xx.aura = cvmx_wqe_get_aura(wqe);
#ifdef CVMCS_DMA_IC
	dmacmd.word0.cn78xx.csel = 0;
#else
	dmacmd.word0.cn78xx.csel = core_id & 1;
#endif


	/* We use the space in the wqe->packet data for ORH and status words. We
	   set them to 0. If the host app checks the ORH, set the first 8 bytes
	   accordingly. */
	pkt_ptr = (uint8_t *) (wqe->packet_data + 8);
	
	respptr = (uint64_t *) (pkt_ptr + sizeof(cvmx_raw_inst_front_t));
	respptr[0] = respptr[1] = 0;


	/* The first 8 bytes to be transmitted are the ORH. */
	lptr[i].u64    = 0;
	lptr[i].cn78xx.addr = cvmx_ptr_to_phys(respptr);
	lptr[i].cn78xx.size = 8;
	currsize += 8;
	i++;

	/* Then starts the data payload. The first local pointer for data needs to
	   be handled differently since the WQE packet ptr data include the front
	   data. */

	lptr[i].u64    = 0ULL;
	dptr = (cvmx_buf_ptr_pki_t *)cvmx_phys_to_ptr(cvmx_wqe_get_pki_pkt_ptr(wqe).addr + sizeof(cvmx_raw_inst_front_t) );
	lptr[i].cn78xx.addr = cvmx_ptr_to_phys(dptr);

	/* response length includes 16 bytes which are not present in the input
	   bytes, so don't include them. Also current size includes the 8 bytes of
	   ORH which is not present in the input bytes, so don't include them.
	*/
	lptr[i].cn78xx.size = __get_localbufsize(respsize - 16,
	                            currsize-8, &wqe->packet_ptr, bufidx,wqe);

	lptr[i].cn78xx.i = 1;
	lptr[i].cn78xx.l = 0;


	currsize += lptr[i].cn78xx.size;
	i++; bufidx++; 

	/* Get the next buffer pointer. */
	dptr = (cvmx_buf_ptr_pki_t *)cvmx_phys_to_ptr(cvmx_wqe_get_pki_pkt_ptr(wqe).addr - 8);


	/* If there are more buffers, start adding them to this DMA command. */
	while(bufidx < cvmx_wqe_get_bufs(wqe)) {

		lptr[i].u64    = dptr->u64;
		lptr[i].cn78xx.size = __get_localbufsize(respsize - 16,
		                            currsize-8,(cvmx_buf_ptr_t *)dptr, bufidx,wqe);
		lptr[i].cn78xx.i = 1;
		lptr[i].cn78xx.l = 0;

		currsize += lptr[i].cn78xx.size;
		i++; bufidx++;

		/* If we have collected max local pointers, then issue a DMA command.
		   The rest will be sent in additional DMA commands later on. */
		if(i == octdev_max_dma_localptrs()) {
			dmacmd.word0.cn78xx.nl = i;
			/* The location to copy in host memory needs to be adjusted to
			   account for the bytes we already sent. */
			rptr.s.addr = front->rptr + lastrptrsize;
			rptr.s.size = currsize - lastrptrsize;
			CVMX_SYNCWS;
			if(cvm_pcie_dma_raw_o3(core_id%4,&dmacmd, lptr, &rptr)) {
				printf("%s: Failed to send DMA command: word0: 0x%016lx, word1: 0x%016lx\n",
				       __FUNCTION__, dmacmd.word0.u64, dmacmd.word1.u64);
				return 1;
			}
			i = 0; lastrptrsize = currsize;
		}

		/* Get the next buffer pointer */
		dptr = (cvmx_buf_ptr_pki_t *)cvmx_phys_to_ptr( ((cvmx_buf_ptr_pki_t *)dptr)->addr - 8);
	}


	/* If there isn't enough space to accomodate the last local pointer (for
	   status word, send the DMA command now for accumulated local buffers. */
	if((i+1) > octdev_max_dma_localptrs()) {
		dmacmd.word0.cn78xx.nl = i;
		rptr.s.addr = front->rptr + lastrptrsize;
		rptr.s.size = currsize - lastrptrsize;
		CVMX_SYNCWS;
		if(cvm_pcie_dma_raw_o3(core_id%4, &dmacmd, lptr, &rptr)) {
			printf("%s: Failed to send DMA command: word0: 0x%016lx, word1: 0x%016lx\n",
			       __FUNCTION__, dmacmd.word0.u64, dmacmd.word1.u64);
			return 1;
		}
		i = 0; lastrptrsize = currsize;
	}


	/* Finally, the status bytes should be included in the response. */
	lptr[i].u64    = 0;
	lptr[i].cn78xx.addr = cvmx_ptr_to_phys(respptr + 1);
	lptr[i].cn78xx.size = 8;
	lptr[i].cn78xx.i = 1;

	currsize += 8;

	i++;

	dmacmd.word0.cn78xx.nl = i;
#ifdef CVMCS_DMA_IC
	dmacmd.word0.cn78xx.ca = 1;
#endif
	rptr.s.addr = front->rptr + lastrptrsize;
	rptr.s.size = currsize - lastrptrsize;
	CVMX_SYNCWS;

	return cvm_pcie_dma_raw_o3(core_id%4, &dmacmd, lptr, &rptr);
}


int
cvmcs_process_scatter_instruction_o3(cvmx_wqe_t  *wqe)
{
	cvmx_raw_inst_front_t  *front;
	octeon_sg_entry_t      *sg;
	int                             lidx=0, ridx=0, bufidx = 0, sgidx = 0;
	cvm_dma_remote_ptr_t            rptr[15], nextrptr;
	cvmx_oct_pci_dma_local_ptr_t    lptr[15];
	cvmx_buf_ptr_pki_t              *dptr;
	uint64_t                       *respptr;
	uint32_t                        respsize, currlsize=0, currrsize = 0;
	uint8_t							*pkt_ptr;
	int								pool = cvmx_wqe_get_aura(wqe);

	front =  (cvmx_raw_inst_front_t *) cvmx_phys_to_ptr(cvmx_wqe_get_pki_pkt_ptr(wqe).addr);

	sg = (octeon_sg_entry_t *)front->rptr;
	resp_pcie_port = front->irh.s.pcie_port;


	dbg_printf("WQE @%p pkt_ptr @0x%016lx len: %d inbufs: %d sgcnt: %d\n", 
	       wqe, wqe->packet_ptr.u64, cvmx_wqe_get_len(wqe), cvmx_wqe_get_bufs(wqe), front->irh.s.rlenssz);
//	cvm_drv_print_data(sg, (((front->irh.s.rlenssz + 3)/4) * 40) );


	respsize = __get_total_scatter_size(sg, front->irh.s.rlenssz);

	nextrptr.u64 = 0;

	/* We use the space in the wqe->packet data for ORH and status words. We
	   set them to 0. If the host app checks the ORH, set the first 8 bytes
	   accordingly. */
	pkt_ptr = (uint8_t  *) (wqe->packet_data + 8);

	respptr = (uint64_t *) (pkt_ptr + sizeof(cvmx_raw_inst_front_t));
	respptr[0] = respptr[1] = 0;


	/* The first 8 bytes to be transmitted are the ORH. */
	lptr[lidx].u64    = 0;
	lptr[lidx].cn78xx.addr = cvmx_ptr_to_phys(respptr);
	lptr[lidx].cn78xx.size = 8;
	currlsize += 8;
	lidx++;

	if(__add_rptr_o3(rptr, lptr, &nextrptr, sg, &sgidx, &ridx, &lidx, &currlsize, &currrsize, pool)) {
		printf("WQE @%p pkt_ptr @0x%016lx len: %d inbufs: %d sgcnt: %d\n", 
	       wqe, wqe->packet_ptr.u64, cvmx_wqe_get_len(wqe),
		   cvmx_wqe_get_bufs(wqe), front->irh.s.rlenssz);
		return 1;
	}

	dbg_printf("---1---\n");

	/* Then starts the data payload. The first local pointer for data needs to
	   be handled differently since the WQE packet ptr data include the front
	   data. */
	
	lptr[lidx].u64    = 0ULL;
	dptr = (cvmx_buf_ptr_pki_t *)cvmx_phys_to_ptr(cvmx_wqe_get_pki_pkt_ptr(wqe).addr + sizeof(cvmx_raw_inst_front_t) );

	lptr[lidx].cn78xx.addr = cvmx_ptr_to_phys(dptr);





	/* response length includes 16 bytes which are not present in the input
	   bytes, so don't include them. Also current size includes the 8 bytes of
	   ORH which is not present in the input bytes, so don't include them.
	*/
	lptr[lidx].cn78xx.size = __get_localbufsize(respsize - 16,
	                         	 currlsize-8, &wqe->packet_ptr, bufidx,wqe);
	lptr[lidx].cn78xx.i = 1; 
	lptr[lidx].cn78xx.l = 0;


	currlsize += lptr[lidx].cn78xx.size; 
	lidx++; bufidx++; 

	if(__add_rptr_o3(rptr, lptr, &nextrptr, sg, &sgidx, &ridx, &lidx, &currlsize, &currrsize, pool)) {
		printf("WQE @%p pkt_ptr @0x%016lx len: %d inbufs: %d sgcnt: %d\n", 
	       wqe, wqe->packet_ptr.u64, cvmx_wqe_get_len(wqe), cvmx_wqe_get_bufs(wqe), front->irh.s.rlenssz);
		return 1;
	}

	dbg_printf("---2---\n");

	/* Get the next buffer pointer. */
	dptr = (cvmx_buf_ptr_pki_t *)cvmx_phys_to_ptr(cvmx_wqe_get_pki_pkt_ptr(wqe).addr - 8);
	dbg_printf(">> Next pkt ptr @ 0x%016lx\n", dptr->u64);

	/* If there are more buffers, start adding them to this DMA command. */
	while(bufidx < cvmx_wqe_get_bufs(wqe)) {

		lptr[lidx].u64    = dptr->u64;
		lptr[lidx].cn78xx.size = __get_localbufsize(respsize - 16,
		                         	 currlsize-8, (cvmx_buf_ptr_t *)dptr, bufidx,wqe);
		lptr[lidx].cn78xx.i = 1; 
		lptr[lidx].cn78xx.l = 0;

		currlsize += lptr[lidx].cn78xx.size; 
		lidx++; bufidx++;

		if(__add_rptr_o3(rptr, lptr, &nextrptr, sg, &sgidx, &ridx, &lidx, &currlsize, &currrsize, pool)) {
			printf("WQE @%p pkt_ptr @0x%016lx len: %d inbufs: %d sgcnt: %d\n", 
			       wqe, wqe->packet_ptr.u64, cvmx_wqe_get_len(wqe),
			       cvmx_wqe_get_bufs(wqe), front->irh.s.rlenssz);
			return 1;
		}

		dbg_printf("---3---\n");

		/* Get the next buffer pointer */
		dptr = (cvmx_buf_ptr_pki_t *)cvmx_phys_to_ptr(((cvmx_buf_ptr_pki_t *)dptr)->addr - 8);

		dbg_printf(">> Next pkt ptr @ 0x%016lx\n", dptr->u64);
	}


	/* If there isn't enough space to accomodate the last local pointer (for
	   status word, send the DMA command now for accumulated local buffers. */
	if( lidx == octdev_max_dma_localptrs()) {
		if(__send_dma_command_o3(rptr, lptr, &ridx, &lidx, &nextrptr, pool)) {
			printf("WQE @%p pkt_ptr @0x%016lx len: %d inbufs: %d sgcnt: %d\n", 
		       wqe, wqe->packet_ptr.u64, cvmx_wqe_get_len(wqe), cvmx_wqe_get_bufs(wqe), front->irh.s.rlenssz);
			return 1;
		}
	}

	dbg_printf("---4---\n");

	/* Finally, the status bytes should be included in the response. */
	lptr[lidx].u64    = 0;
	lptr[lidx].cn78xx.addr = cvmx_ptr_to_phys(respptr + 1); 
	lptr[lidx].cn78xx.size = 8; 
	lptr[lidx].cn78xx.i = 1; 

	currlsize += 8;
	lidx++;

	if(__add_rptr_o3(rptr, lptr, &nextrptr, sg, &sgidx, &ridx, &lidx, &currlsize, &currrsize, pool)) {
		printf("WQE @%p pkt_ptr @0x%016lx len: %d inbufs: %d sgcnt: %d\n", 
		       wqe, wqe->packet_ptr.u64, cvmx_wqe_get_len(wqe),
		       cvmx_wqe_get_bufs(wqe), front->irh.s.rlenssz);
		return 1;
	}

	dbg_printf("---5---\n");

	if(lidx || ridx) {
		__add_rptr_o3(rptr, lptr, &nextrptr, sg, &sgidx, &ridx, &lidx, &currlsize, &currrsize, pool);
		if(__send_dma_command_o3(rptr, lptr, &ridx, &lidx, &nextrptr, pool)) {
			printf("WQE @%p pkt_ptr @0x%016lx len: %d inbufs: %d sgcnt: %d\n", 
		       wqe, wqe->packet_ptr.u64, cvmx_wqe_get_len(wqe), cvmx_wqe_get_bufs(wqe), front->irh.s.rlenssz);
			return 1;
		}
	}
	dbg_printf("---6---\n");

	/* Time to free the sg entry buffer. */
	cvm_common_free_fpa_buffer(sg, CVM_FPA_TEST_POOL, 0);

	dbg_printf("--End of %s\n", __FUNCTION__);
	return 0;
}





int
cvmcs_process_instruction(cvmx_wqe_t   *wqe)
{
	cvmx_raw_inst_front_t  *front;
	
	if(OCTEON_IS_MODEL(OCTEON_CN78XX))
		front =  (cvmx_raw_inst_front_t *) cvmx_phys_to_ptr(cvmx_wqe_get_pki_pkt_ptr(wqe).addr);
	else
		front = (cvmx_raw_inst_front_t *)wqe->packet_data;

	/* Noresponse packets have rptr = 0. These packets are valid, but require
	   no more processing. Free the WQE and return success. */
	if(front->rptr == 0) {
		cvm_free_host_instr(wqe);
		return 0;
	}


	if(cvmx_likely(front->irh.s.scatter == 0)) {
		/* For a request with direct response, the return address is known. The
		   response can be sent right away. */
		if(OCTEON_IS_MODEL(OCTEON_CN78XX))
			return cvmcs_process_direct_instruction_o3(wqe, front);
		else
			return cvmcs_process_direct_instruction(wqe, front);
	} else {
		/* For a scatter response, the scatter addresses needs to be read
		   first. Schedule a DMA command to read the scatter pointers with
		   the wqe we received to be enqueued into POW on completion. */
		void     *sptr = cvm_common_alloc_fpa_buffer(CVMCS_TEST_BUF_PTR, CVM_FPA_TEST_POOL);
		uint64_t  host_addr;
		if(cvmx_unlikely(sptr == NULL)) {
			printf("Failed to allocated scatter list buffer\n");
			cvm_free_host_instr(wqe);
			return 0;
		}
		front->irh.s.opcode = CORE_DRV_TEST_SCATTER_OP;
		host_addr      = (uint64_t)front->rptr;
		front->rptr    = (unsigned long)sptr;
		CVMX_SYNCWS;
		cvm_drv_read_scatter_list(DMA_NON_BLOCKING, host_addr,
		                          front, sptr, wqe);
	}

	return 0;
}










/* $Id$ */
