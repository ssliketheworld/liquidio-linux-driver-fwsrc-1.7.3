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

#if  defined(CVMCS_TEST_PKO) || defined(MAX_PACKET_RATE_TEST)

#if  defined(CVMCS_TEST_PKO) && defined(MAX_PACKET_RATE_TEST)
#error "Enable either CVMCS_TEST_PKO  or  MAX_PACKET_RATE_TEST, not both"
#endif

#ifdef  MAX_PACKET_RATE_TEST
void  cvmcs_max_pkt_pko_test(void);
#endif

extern CVMX_SHARED    uint64_t         cpu_freq;
extern               uint32_t      core_id;


/* The cycle count when the PKO test was run last on this core. */
uint64_t  last_pko_run=0;


uint32_t  test_pkt_sent=0;

/* Used in sequential and random data size calculation. */
uint32_t  last_data_size = CVM_MIN_DATA;


#if  defined(PROGRAM_THRU_SCRATCH)
CVMX_SHARED static uint32_t  pkts_per_sec       = 0; // Tunable
#else
CVMX_SHARED static uint32_t  pkts_per_sec       = PKO_TEST_PKT_RATE; // Tunable
#endif

/* Extending the Masks support to 64 bit */
CVMX_SHARED static uint64_t  pko_test_core_mask = 0xFFFFFFFFFFFFFFFF;
CVMX_SHARED uint64_t  pko_test_oq_mask   = 0xFFFFFFFFFFFFFFFF;


CVMX_SHARED static uint64_t  pkt_time_delay     = 1;

/* PKO Test for sending Few Packtes */
//#define PKO_SEND_ONLY_FEWPKTS		3000

/* Decision on when to send a PKO packet from each core. */
static inline int
cvmcs_ok_to_send_pko_pkt(void)
{
	if(!(pko_test_core_mask & (1 << cvmx_get_core_num())))
		return 0;

	if(!pkts_per_sec || !pko_test_oq_mask)
		return 0;

	if(octdev_get_pko_state() != CVM_DRV_PKO_READY)
		return 0;

#ifdef PKO_SEND_ONLY_FEWPKTS
	if(test_pkt_sent >= PKO_SEND_ONLY_FEWPKTS)
		return 0;

#endif

	if(cvmx_get_cycle() > (last_pko_run + pkt_time_delay)) {
		last_pko_run = cvmx_get_cycle();
		return 1;
	}

	return 0;
}






/* Get the packet size to use for the next PKO packet. */
static inline int
cvmcs_get_pko_pkt_size(void)
{
	uint32_t  data_size;

#if  (CVMCS_TEST_PKO == PKO_TEST_RANDOM_DATA)
	data_size = CVM_MIN_DATA + (cvmx_get_cycle() % (CVM_MAX_DATA - CVM_MIN_DATA + 1));
#elif (CVMCS_TEST_PKO == PKO_TEST_SEQUENTIAL_DATA)
	data_size = last_data_size++;
	if(last_data_size > CVM_MAX_DATA)
		last_data_size = CVM_MIN_DATA;
#elif (CVMCS_TEST_PKO == PKO_TEST_FIXED_DATA)
	data_size = CVM_MAX_DATA;
#endif

	return data_size;
}





#if  defined(PROGRAM_THRU_SCRATCH)
static int
cvmcs_test_pko_update_test_params(void *arg)
{
	uint64_t   scratch;
	uint32_t   op,value;

    if(OCTEON_IS_MODEL(OCTEON_CN56XX))
        scratch = cvmx_read_csr(CVMX_PEXP_NPEI_SCRATCH_1);
    else
        scratch = cvmx_read_csr(CVMX_PEXP_SLI_SCRATCH_1);

	op = scratch >> 32;
	value = scratch & 0xffffffff;

	switch(op) {
		case 1: /* pkts/sec */
			if(value != pkts_per_sec) {
				printf("PKO_TEST: Changing pkts/sec to %u\n", value);
				pkts_per_sec = value;
				pkt_time_delay = (pkts_per_sec)?cpu_freq/pkts_per_sec:0;
			}
			break;
		case 2: /* Queue mask */
			if(value != pko_test_oq_mask) {
				printf("PKO_TEST: Changing Queue Mask to 0x%08x\n", value);
				pko_test_oq_mask = value;
			}
			break;
		case 3: /* Core mask */
			if(value != pko_test_core_mask) {
				printf("PKO_TEST: Changing Core Mask to 0x%08x\n", value);
				pko_test_core_mask = value;
			}
			break;
		case 4:
			printf("PKO Test: %u pkts/sec coremask: 0x%08x queuemask: 0x%08x\n",
			      pkts_per_sec, pko_test_core_mask, pko_test_oq_mask);
			break;
		default:
			break;
	}

    if(OCTEON_IS_MODEL(OCTEON_CN56XX))
        cvmx_write_csr(CVMX_PEXP_NPEI_SCRATCH_1, value);
    else
		cvmx_write_csr_node(cvmx_get_node_num(), CVMX_PEXP_NPEI_SCRATCH_1, value);
	CVMX_SYNCWS;

	return 0;
}
#endif







void
cvmcs_test_pko_global_init(void)
{
	if(pkts_per_sec)
		pkt_time_delay = cpu_freq/pkts_per_sec;

	//pko_test_core_mask = (cvmx_sysinfo_get())->core_mask; //TBD

	if(OCTEON_IS_MODEL(OCTEON_CN56XX) || OCTEON_IS_MODEL(OCTEON_CN63XX) ||
	   OCTEON_IS_MODEL(OCTEON_CN66XX) || OCTEON_IS_MODEL(OCTEON_CN61XX) ||
	   OCTEON_IS_MODEL(OCTEON_CN68XX) || OCTEON_IS_MODEL(OCTEON_CN70XX)) {

		#if  defined(PROGRAM_THRU_SCRATCH)
		cvmcs_common_add_task(cpu_freq, cvmcs_test_pko_update_test_params, NULL);
		#endif
	}
}




static inline void
cvmcs_test_pko_sign_data(cvmx_buf_ptr_t  *gptr, int bufcount, int adjust)
{
#ifdef CVMCS_SIGN_DATA
	if(bufcount == 1) {
		cvmcs_sign_data(cvmx_phys_to_ptr(gptr->s.addr + adjust),
		                            gptr->s.size - adjust, 0);
	} else {
		int i, sign_byte = 0;

		for(i = 0; i < bufcount; i++) {
			sign_byte = cvmcs_sign_data(cvmx_phys_to_ptr(gptr[i].s.addr + adjust),
			                            gptr[i].s.size - adjust, sign_byte);
			adjust = 0;
		}
	}
#endif
}




/** This routine sends a packet to a PCI output queue. The size is passed
  * as an argument by the caller. The routine allocated multiple buffers,
  * if required, and calls a PCI core driver routine to send it on the
  * PCI output port specified.
  */
int
cvmcs_test_pko(uint32_t  oq_no, uint32_t size)
{
	struct octeon_rh   *rh;
	uint8_t            *firstbuf;
	cvmx_buf_ptr_t      lptr;
	cvm_ptr_type_t      ptr_type = CVM_DIRECT_DATA;
	uint32_t            i, bufcount = 0, data_bytes = 0;


	/* Include space for the response header. */
	size += sizeof(struct octeon_rh);

	/* Get the number of buffers required. */ 
	for(i = 0; i < size; i += CVM_FPA_TEST_POOL_SIZE) {
		bufcount++;
	}

	/* Atleast one buffer is always required. It will hold the response header
	   and data directly when bufcount = 1. For gather, it will hold the gather
	   list first followed by response header and data. */
	firstbuf = cvmx_fpa_alloc(CVM_FPA_TEST_POOL);

	if(!firstbuf) {
		//printf("%s: First buf alloc failed\n",__FUNCTION__);
		return 1;
	}

	lptr.u64    = 0;
	lptr.s.addr = cvmx_ptr_to_phys(firstbuf);
	lptr.s.pool = CVM_FPA_TEST_POOL;
	lptr.s.i    = 1;


	if(bufcount == 1) {

		lptr.s.size = size;
		data_bytes  = size;

		cvmcs_test_pko_sign_data(&lptr, bufcount, sizeof(struct octeon_rh));

		rh    = (struct octeon_rh *)firstbuf;

	} else {
		cvmx_buf_ptr_t     *gptr;
		uint32_t            glistsize = 0, headroom = 0;

		ptr_type  = CVM_GATHER_DATA;

		glistsize = (bufcount * sizeof(cvmx_buf_ptr_t));

		/* If the bufcount calculated above does not have space for
		   the gather list, add another buffer to the count.*/
		if((bufcount * CVM_FPA_TEST_POOL_SIZE) < (size + glistsize))
			bufcount++;

		/* Recalculate glistsize */
		glistsize = (bufcount * sizeof(cvmx_buf_ptr_t));
		headroom  = glistsize + sizeof(struct octeon_rh);

		/* The start of the buffer holds the gather list. */
		gptr = (cvmx_buf_ptr_t *)firstbuf;

		gptr[0].u64    = 0;
		gptr[0].s.addr = CVM_DRV_GET_PHYS(firstbuf) + glistsize;
		gptr[0].s.pool = CVM_FPA_TEST_POOL;
		gptr[0].s.back = glistsize/CVMX_CACHE_LINE_SIZE;
		gptr[0].s.size = CVM_FPA_TEST_POOL_SIZE - glistsize;

		data_bytes += gptr[0].s.size;

		/* Allocate the additional buffers. */
		for(i = 1; i < bufcount; i++) {
			uint8_t     *buf;
			uint32_t   thisbuf_size=0;

			/* Allocate from the TEST FPA pool. */
			//buf = cvm_common_alloc_fpa_buffer(CVMCS_TEST_BUF_PTR, CVM_FPA_TEST_POOL);
			/* changing the API type to sync for fixing the pko multibuffer issue */
			buf = cvm_common_alloc_fpa_buffer_sync(CVM_FPA_TEST_POOL);
			if(!buf) {
				/* printf("# cvmcs: Buffer[%d/%d] allocation failed in %s\n",
				       i, bufcount, __FUNCTION__); */
				while(--i) {
					unsigned long ptr = ((gptr[i].s.addr >> 7) - gptr[i].s.back) << 7;
					cvm_common_free_fpa_buffer(cvmx_phys_to_ptr(ptr),
			                           gptr[i].s.pool, 0);


				}

				return 1;
			}

			thisbuf_size = CVM_FPA_TEST_POOL_SIZE;
	 
			if((data_bytes + thisbuf_size) > size)
				thisbuf_size = size - data_bytes;

			data_bytes += thisbuf_size;

			/* Create a gather list of buffers. */
			gptr[i].u64    = 0;
			gptr[i].s.addr = CVM_DRV_GET_PHYS(buf);
			gptr[i].s.pool = CVM_FPA_TEST_POOL;
			gptr[i].s.size = thisbuf_size;
			gptr[i].s.i    = 1;
		}


		/*for(i = 0; i < bufcount; i++) {
			printf("gptr[%d]: addr: %lx size: %d pool: %d back: %d free: %d\n", i,
			    (uint64_t)gptr[i].s.addr, gptr[i].s.size, gptr[i].s.pool,
			    gptr[i].s.back, gptr[i].s.i);
		}*/

		cvmcs_test_pko_sign_data(gptr, bufcount, headroom);

		lptr.s.size = bufcount;

		/* Response header follows the gather list but precedes the data. */
		rh = (struct octeon_rh *)(firstbuf + glistsize);
	}


	/* Create a response header. If a dispatch function is registered
	   with the host PCI driver for this opcode, it will be processed,
	   else this packet will be dropped in the host driver. */
	rh->u64 = 0;
	rh->r.opcode    = OPCODE_CORE;
	/* Packets can one of two opcodes which are generated randomly. */
	if(cvmx_get_cycle() & 0x1)
		rh->r.subcode    = DROQ_PKT_OP2;
	else
		rh->r.subcode    = DROQ_PKT_OP1;
	rh->r_dh.extra = oq_no;
	rh->r_dh.link = oq_no;


	CVMX_SYNCWS;

	/* Send a single buffer to PKO */
	if (cvm_send_pci_pko_direct(lptr, ptr_type, bufcount, data_bytes, oq_no)) {
		cvmx_buf_ptr_t  *gptr;
		i    = bufcount;
		gptr = (i == 1)?&lptr:cvmx_phys_to_ptr(lptr.s.addr);
		while(--i) {
			unsigned long ptr = ((gptr[i].s.addr >> 7) - gptr[i].s.back) << 7;
			cvm_common_free_fpa_buffer(cvmx_phys_to_ptr(ptr), gptr[i].s.pool,0);
		}
	}

	test_pkt_sent++;
	return 0;
}






#ifdef  MAX_PACKET_RATE_TEST
void
cvmcs_do_pko_test()
{
	cvmcs_max_pkt_pko_test();
}
#else
void
cvmcs_do_pko_test()
{
	if(cvmcs_ok_to_send_pko_pkt()) {
		int  i;
		for(i = 0; i < OCTEON_MAX_BASE_IOQ; i++) {
			if(pko_test_oq_mask & (1ULL << i))
				cvmcs_test_pko(i, cvmcs_get_pko_pkt_size());
		}
	}
#ifdef PKO_SEND_ONLY_FEWPKTS 
	else
		return;
#endif

}
#endif



static inline int
cvm_pko_get_db(int port_num)
{
	cvmx_pko_reg_read_idx_t pko_reg_read_idx;

	pko_reg_read_idx.u64 = 0;
	pko_reg_read_idx.s.index = port_num;
	cvmx_write_csr_node(cvmx_get_node_num(), CVMX_PKO_REG_READ_IDX, pko_reg_read_idx.u64);
	return cvmx_read_csr_node(cvmx_get_node_num(), CVMX_PKO_MEM_DEBUG9);
}



#ifdef  MAX_PACKET_RATE_TEST

//#define MAX_PKT_REUSE_BUF

#ifdef MAX_PKT_REUSE_BUF
static void *reuse_buf = NULL;
#endif

#define MAX_PKT_TEST_SIZES  8
#define TEST_TIME_PER_SIZE  20

CVMX_SHARED int pkt_size[MAX_PKT_TEST_SIZES] = { 64, 128, 256, 360, 512, 1024, 2048, 4096};
CVMX_SHARED int size_idx=0;
int max_pkt_loop_cnt=0;

void
cvmcs_max_pkt_pko_test(void)
{
    uint8_t              *buf;
    uint32_t              size, oq_no;
    //struct octeon_rh      *rh;
    cvmx_buf_ptr_t        lptr;
    static unsigned long  last_db_check=0;
    extern CVMX_SHARED uint64_t   cpu_freq;

    if(octdev_get_pko_state() != CVM_DRV_PKO_READY)
        return;

    oq_no = 0; //core_id;

    if(cvmx_get_core_num() == 0) {
       if(cvmx_get_cycle() > (last_db_check + cpu_freq))  {
          last_db_check = cvmx_get_cycle();
          if(max_pkt_loop_cnt++ >= TEST_TIME_PER_SIZE)  {
              max_pkt_loop_cnt = 0;
              size_idx++;
              if(size_idx == MAX_PKT_TEST_SIZES)
                 size_idx = 0;
              printf("Starting Max Packet rate PKO test for size: %d bytes\n",
                      pkt_size[size_idx]);
          }
       }

    }


    size = pkt_size[size_idx];

#ifdef MAX_PKT_REUSE_BUF
	if(cvmx_likely(reuse_buf)) {
		buf = reuse_buf;
	} else {
		buf = cvmx_fpa_alloc(CVM_FPA_TEST_POOL);
		if(buf == NULL)
			return;
		reuse_buf = buf;
	}
#else
	buf = cvmx_fpa_alloc(CVM_FPA_TEST_POOL);
    if(buf == NULL)
        return;
#endif


    lptr.u64    = 0;
    lptr.s.addr = CVM_DRV_GET_PHYS(buf);
    lptr.s.size = size + 8;
    lptr.s.pool = CVM_FPA_TEST_POOL;
#if !defined(MAX_PKT_REUSE_BUF)
    lptr.s.i    = 1;
#endif

    /* Send a single buffer to PKO */
    cvm_send_pci_pko_direct(lptr, CVM_DIRECT_DATA, 1, size, oq_no);
}
#endif


#endif



/* $Id$ */
