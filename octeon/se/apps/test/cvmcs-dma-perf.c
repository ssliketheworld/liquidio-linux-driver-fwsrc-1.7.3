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

#ifdef DMA_PERF_TEST 

#define   MAX_PENDING            64
#define   TEST_TIME              10
#define   DMA_REMOTE_ADDR        0x50000000

#define   PCI_DMA_BIDIRECTIONAL  2
#define   USE_WQE    1
#define   USE_CWORD  2



/*---- Tunables -----*/
#define   DMA_ENGINE             (core_id % 5) //0


//#define   DIRECTION        PCI_DMA_INBOUND
//#define   DIRECTION        PCI_DMA_OUTBOUND
#define   DIRECTION        PCI_DMA_BIDIRECTIONAL


#define   DMA_COMPLETION     USE_WQE
//#define   DMA_COMPLETION     USE_CWORD


/* ---- */

extern              uint32_t  core_id;
extern CVMX_SHARED  uint64_t  cpu_freq;


#define DMA_SIZE_CNT     10
CVMX_SHARED int dma_test_size[DMA_SIZE_CNT] = {64, 128, 256, 512, 1024, 1500, 2048, 4096, 8192, 16384};
int         dma_test_idx;

CVMX_SHARED int dma_perf_run_ok = 1;

 
CVMX_SHARED uint64_t   inpkts[MAX_CORES], indata[MAX_CORES];
CVMX_SHARED uint64_t   outpkts[MAX_CORES], outdata[MAX_CORES];
CVMX_SHARED uint64_t   in_cycles[MAX_CORES], out_cycles[MAX_CORES];
CVMX_SHARED cvmx_spinlock_t   dm_test_lock[MAX_CORES];
CVMX_SHARED int dma_size,  dma_test_ok = 1;
uint64_t    last_test_change_cycle;



struct dma_test {
	cvmx_buf_ptr_t               lptr[8]; /* 0 - 63 */
	cvm_dma_remote_ptr_t         rptr;    /* 64 - 71 */
	cvmx_oct_pci_dma_inst_hdr_t  cmd;     /* 72 - 79 */
	cvmx_wqe_t                  *wqe;     /* 80 - 87 */
	uint64_t                     stamp;   /* 88 - 95 */
};

struct dma_test *tp[MAX_PENDING];




struct dma_test *
cvmcs_generate_pci_dma_command(int size, int cnt)
{
	cvmx_wqe_t      *wqe;
	struct dma_test *t;

	/* Allocate a wqe even when completion uses word ptr. We'll use this
	   space for our dma command info. */
	wqe = cvmcs_wqe_alloc();
	if(wqe == NULL)
		return NULL;
	memset(wqe, 0 , sizeof(cvmx_wqe_t));

	if (OCTEON_IS_MODEL(OCTEON_CN78XX))
		t = (struct dma_test *)(wqe->packet_data + 8);
	else
		t = (struct dma_test *)wqe->packet_data;

	t->wqe          = wqe;

	t->cmd.u64      = 0;
	t->cmd.s.nr     = 1;
	t->cmd.s.nl     = 1;
	t->cmd.s.fport  = 0;
	t->cmd.s.lport  = 0;
#if DIRECTION == PCI_DMA_BIDIRECTIONAL
	t->cmd.s.dir    = (core_id & 1); //(cnt & 1);
#else
	t->cmd.s.dir    = DIRECTION;
#endif


	/* These fields in the WQE are used in both completion modes. */
	cvmx_wqe_set_len(wqe, size);
	cvmx_wqe_set_bufs(wqe, 1);
	cvmx_wqe_set_grp(wqe, core_id);
	cvmx_wqe_set_port(wqe, 20);
	cvmx_wqe_set_soft(wqe, 1);
	cvmx_wqe_set_tag(wqe, (1 << core_id));
	cvmx_wqe_get_tt(wqe, CVMX_POW_TAG_TYPE_ORDERED);

#if  DMA_COMPLETION == USE_WQE
	t->cmd.s.ptr          = cvmx_ptr_to_phys(wqe);
	t->cmd.s.wqp          = 1;
#endif


#if  DMA_COMPLETION == USE_CWORD
	t->cmd.s.ptr          = cvmx_ptr_to_phys(&wqe->packet_ptr);
	*((uint8_t *)(&wqe->packet_ptr)) = 1;
#endif



	/* Allocate a single buffer. The first test size needs to be less than
	   CVM_FPA_TEST_POOL */
	t->lptr[0].u64    = 0;
	t->lptr[0].s.addr = cvmx_ptr_to_phys(cvmx_fpa_alloc(CVM_FPA_TEST_POOL));
	if(t->lptr[0].s.addr == 0) {
		cvmcs_wqe_free(wqe);
		return NULL;
	}

	t->lptr[0].s.size = size;

	t->rptr.s.addr = DMA_REMOTE_ADDR + (cnt * size);// + 1;
	t->rptr.s.size = size;

	CVMX_SYNCWS;
	//printf("wqe @ %p t @ %p dir: %s\n", wqe, t, t->cmd.s.dir?"INBOUND":"OUTBOUND");
	return t;
}





void
cvmcs_dma_perf_free_wqe_bufs(cvmx_wqe_t  *wqe)
{
	int i;
	struct dma_test *t; 

	if (OCTEON_IS_MODEL(OCTEON_CN78XX))
		t = (struct dma_test *)(wqe->packet_data + 8);
	else
		t = (struct dma_test *)wqe->packet_data;

	for(i = 0; i < cvmx_wqe_get_buf(wqe); i++)
		cvmx_fpa_free(cvmx_phys_to_ptr(t->lptr[i].s.addr), CVM_FPA_TEST_POOL, 0);
}




struct dma_test *
cvmcs_regenerate_pci_dma_command(cvmx_wqe_t  *wqe, int tot_size)
{
	struct dma_test *t;
	int              i, alloc_size;

	if (OCTEON_IS_MODEL(OCTEON_CN78XX))
		t = (struct dma_test *)(wqe->packet_data + 8);
	else
		t = (struct dma_test *)wqe->packet_data;

	cvmcs_dma_perf_free_wqe_bufs(wqe);

	alloc_size = 0; i = 0;
	do {
		t->lptr[i].s.addr = cvmx_ptr_to_phys(cvmx_fpa_alloc(CVM_FPA_TEST_POOL));
		if(t->lptr[i].s.addr == 0)
			goto regen_failed;
		if((alloc_size + CVM_FPA_TEST_POOL_SIZE) < tot_size)
			t->lptr[i].s.size = CVM_FPA_TEST_POOL_SIZE;
		else
			t->lptr[i].s.size = (tot_size - alloc_size);
		alloc_size += t->lptr[i].s.size;
		i++;
	} while(alloc_size < tot_size);

	t->rptr.s.addr = DMA_REMOTE_ADDR + (cvmx_wqe_get_tag(wqe) * tot_size); // + 1;
	t->rptr.s.size = tot_size;
	t->cmd.s.nl       = i;

	cvmx_wqe_set_len(wqe, tot_size);
	cvmx_wqe_set_bufs(wqe, i);

	CVMX_SYNCWS;

	
//	printf("Regenerate wqe @ %p t @ %p new size: %d\n", wqe, t, tot_size);
	return t;

regen_failed:
	while(i)
		cvmx_fpa_free(cvmx_phys_to_ptr(t->lptr[i].s.addr), CVM_FPA_TEST_POOL, 0);
		
	cvmcs_wqe_free(wqe);
	return NULL;
}







/* This function is executed on each core. Each core has its own set of
   DMA commands. */
int
cvmcs_dma_perf_send_first_cmds(void)
{
	int i, in=0, out=0;

	/* Initialize the per-core stats lock and stats fields. */
	cvmx_spinlock_init(&dm_test_lock[core_id]);

	inpkts[core_id]    = indata[core_id]     = 0;
	outpkts[core_id]   = outdata[core_id]    = 0;
	in_cycles[core_id] = out_cycles[core_id] = 0;
	CVMX_SYNCWS;

	/* Note the cycle count and first dma size to use. */
	last_test_change_cycle = cvmx_get_cycle();
	dma_size = dma_test_size[0];


	/* Create the PCI DMA command and allocate WQE. Store the values in
	   the test structure. */
	for(i = 0 ; i < MAX_PENDING; i++) {
		tp[i] = cvmcs_generate_pci_dma_command(dma_size, i);
		if(tp[i] == NULL) {
			printf("%s: Test Packet Alloc failed\n", __FUNCTION__);
			return 1;
		}

		(tp[i]->cmd.s.dir)?in++:out++;
	}
		
	printf("%d Inbound & %d Outbound commands\n", in, out);


	/* Issue all DMA commands for this core. */
	for(i = 0 ; i < MAX_PENDING; i++) {
		struct dma_test *t;
	    if (OCTEON_IS_MODEL(OCTEON_CN78XX))
    	    t = (struct dma_test *)(tp[i]->wqe->packet_data + 8);
	    else
    	    t = (struct dma_test *)tp[i]->wqe->packet_data;

		t->stamp = cvmx_get_cycle();
		CVMX_SYNCWS;
		if(cvm_pcie_dma_raw(DMA_ENGINE, &tp[i]->cmd, tp[i]->lptr, &tp[i]->rptr)) {
			printf("%s: DMA command[%d] failed\n", __FUNCTION__, i);
			return 1;
		}
	}


	return 0;
}






int
cvmcs_dma_perf_process_wqe(cvmx_wqe_t  *wqe)
{
	struct dma_test *t; 

    if (OCTEON_IS_MODEL(OCTEON_CN78XX))
        t = (struct dma_test *)(wqe->packet_data + 8);
    else
        t = (struct dma_test *)wqe->packet_data;

	if(cvmx_unlikely(cvmx_wqe_get_port(wqe) != 20))
		return 1;

	cvmx_spinlock_lock(&dm_test_lock[core_id]);

	if(t->cmd.s.dir == PCI_DMA_OUTBOUND) {
		outpkts[core_id]++; outdata[core_id] += cvmx_wqe_get_len(wqe);
		out_cycles[core_id] += (cvmx_get_cycle() - t->stamp);
	}

	if(t->cmd.s.dir == PCI_DMA_INBOUND) {
		inpkts[core_id]++; indata[core_id] += cvmx_wqe_get_len(wqe);
		in_cycles[core_id] += (cvmx_get_cycle() - t->stamp);
	}

	cvmx_spinlock_unlock(&dm_test_lock[core_id]);


	if(cvmx_unlikely(!dma_test_ok)) {
		cvmcs_dma_perf_free_wqe_bufs(wqe);
		cvmcs_wqe_free(wqe);
		return 0;
	}

	if(cvmx_unlikely( cvmx_wqe_get_len(wqe) != dma_size)) {
		if(cvmcs_regenerate_pci_dma_command(wqe, dma_size) == NULL) {
			printf("Regenerate Failed for size %d\n", dma_size);
			cvmcs_dma_perf_free_wqe_bufs(wqe);
			cvmcs_wqe_free(wqe);
			return 0;
		}
	}

	t->stamp = cvmx_get_cycle();
	CVMX_SYNCWS;

	cvm_pcie_dma_raw(DMA_ENGINE, &t->cmd, t->lptr, &t->rptr);

	return 0;
}




int
cvmcs_dma_perf_loop(void)
{
	cvmx_wqe_t    *wqe = NULL;
	int            status = 0;

#if  DMA_COMPLETION == USE_CWORD
	uint8_t      *cword;
	int           idx=0, count=0;
#endif

	if(cvmcs_dma_perf_send_first_cmds())
		return 1;

	do {

#if  DMA_COMPLETION == USE_WQE
		wqe = cvmcs_app_get_work_sync(0);
		if (wqe == NULL)
			continue;

#endif

#if  DMA_COMPLETION == USE_CWORD

		cword = (uint8_t *)cvmx_phys_to_ptr(tp[idx]->cmd.s.ptr);
		CVMX_SYNCWS;
		if((*cword)) {
			INCR_INDEX_BY1(idx, MAX_PENDING);
			continue;
		}

		wqe = tp[idx]->wqe;
		*cword = 1;
	
#endif

		status = cvmcs_dma_perf_process_wqe(wqe);

	} while( (status == 0) && (dma_perf_run_ok));

	return 0;
}




void
cvmcs_print_dma_perf_stats(void)
{
	volatile uint64_t  tot_in_pkts = 0, tot_in_data = 0;
	volatile uint64_t  tot_out_pkts = 0, tot_out_data = 0;
	volatile uint64_t  tot_in_cycles=0, tot_out_cycles = 0;
	int  i;

	for(i = 0; i < MAX_CORES; i++) {
		cvmx_spinlock_lock(&dm_test_lock[i]);
		tot_in_pkts  += inpkts[i];
		tot_out_pkts += outpkts[i];
		tot_in_data  += indata[i];
		tot_out_data += outdata[i];
		tot_in_cycles   += in_cycles[i]; 
		tot_out_cycles  += out_cycles[i]; 
		inpkts[i] = outpkts[i] = 0;
		indata[i] = outdata[i] = 0;
		in_cycles[i] = out_cycles[i] = 0;
		cvmx_spinlock_unlock(&dm_test_lock[i]);
	}

	printf("DMA Counts : ");
	for(i = 0; i < 5; i++) {
		unsigned long cnt = cvmx_read_csr_node(cvmx_get_node_num(), CVMX_PEXP_NPEI_DMAX_COUNTS(i));
		
		printf(" [ %d: %lu/%lu ] ", i, (cnt >> 32), (cnt & 0xffffffff));
	}
	printf("\n");


	if(tot_in_pkts) {
		printf("Size: %5d inpkts: %8lu indata:  %10lu bps cycles: %6lu\n", dma_size, tot_in_pkts, tot_in_data * 8, tot_in_cycles/tot_in_pkts);
	}

	if(tot_out_pkts) {
		printf("Size: %5d outpkts: %7lu outdata: %10lu bps cycles: %6lu\n", dma_size, tot_out_pkts, tot_out_data * 8, tot_out_cycles/tot_out_pkts);
	}

	if( (cvmx_get_cycle() - last_test_change_cycle) >= ( cpu_freq * TEST_TIME)){
		dma_test_idx = (dma_test_idx + 1) % DMA_SIZE_CNT;
		dma_size = dma_test_size[dma_test_idx];
		last_test_change_cycle = cvmx_get_cycle();
	}

}




#endif

