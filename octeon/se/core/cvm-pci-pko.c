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
#include "liquidio_common.h"
#include <errno.h>
#include "cvmx-version.h"


CVMX_SHARED cvmx_spinlock_t  cvm_drv_pko_lock; 
extern  CVMX_SHARED  cvm_oct_dev_t    *oct;
extern  CVMX_SHARED  uint8_t max_droq;


#define CVM_PCI_PKO_MAP_ENTRIES     64

int
__get_active_pci_oq_count(void)
{
	int i, qcnt = 0;

	if(OCTEON_IS_MODEL(OCTEON_CN78XX) || OCTEON_IS_MODEL(OCTEON_CN73XX))
	{
		int node = cvmx_get_node_num();
		for(i = 0; i < 64; i++)
		{
			if( cvmx_read_csr_node(node, CVMX_PEXP_SLI_PKTX_SLIST_BADDR(i)) && 
		    	cvmx_read_csr_node(node, CVMX_PEXP_SLI_PKTX_SLIST_FIFO_RSIZE(i)) ) 
				qcnt++;
		}	
	}
	else if(OCTEON_IS_MODEL(OCTEON_CN68XX)) 
	{
		for(i = 0; i < 32; i++)
		{
			if( cvmx_read_csr(CVMX_PEXP_SLI_PKTX_SLIST_BADDR(i)) && 
		    	cvmx_read_csr(CVMX_PEXP_SLI_PKTX_SLIST_FIFO_RSIZE(i)) ) 
				qcnt++;
		}	
	}


	return qcnt;
}

#ifndef OCTEON_CN73XX_PASS1_3
#define OCTEON_CN73XX_PASS1_3	0x000d9703
#endif

int
setup_pci_pko_ports()
{
	int i, activeqcnt;
	uint32_t size = sizeof(struct __cvm_pci_pko_qmap) * CVM_PCI_PKO_MAP_ENTRIES;

	if (OCTEON_IS_MODEL(OCTEON_CN73XX)) {
		max_droq = MAX_DROQS_CN73XX;
		activeqcnt = max_droq;

		printf("[ DRV ] Active CN73xx PCI Queues: %d\n", activeqcnt);
	} else if(OCTEON_IS_MODEL(OCTEON_CN78XX)) {

		max_droq = MAX_DROQS_CN78XX;
		if(max_droq)
			activeqcnt = max_droq;
		else
			activeqcnt = __get_active_pci_oq_count();

		printf("[ DRV ] Active CN78xx PCI Queues: %d (derived from checking queue registers)\n", activeqcnt);
	} else if(OCTEON_IS_MODEL(OCTEON_CN68XX)) {
		cvmx_sli_tx_pipe_t  slitxpipe;
		slitxpipe.u64 = cvmx_read_csr(CVMX_PEXP_SLI_TX_PIPE);

		max_droq = MAX_DROQS_CN68XX;
		if(max_droq)
			activeqcnt = max_droq;
		else
			activeqcnt = __get_active_pci_oq_count();

		slitxpipe.s.nump = activeqcnt;
		cvmx_write_csr(CVMX_PEXP_SLI_TX_PIPE, slitxpipe.u64);
		printf("[ DRV ] Active PCI Queues: %d (derived from checking queue registers)\n", activeqcnt);
	} else {
		max_droq = MAX_DROQS_CN66XX;
		if(max_droq)
			activeqcnt = max_droq;
		else
			activeqcnt = CVMX_PKO_QUEUES_PER_PORT_PCI * 4;
	}


	oct->pcipkomap = NULL;

#ifdef HYBRID
	oct->pcipkomap = cvmx_fpa_alloc(cvmx_fpa_get_packet_pool());
#else
	for(i = 0; i < CVMX_FPA_NUM_POOLS; i++) {
		if(cvmx_fpa_get_block_size(i) >= size) {
			oct->pcipkomap = cvmx_fpa_alloc(i);
			if(oct->pcipkomap) break;
		}
	}
#endif  //HYBRID

	if(oct->pcipkomap == NULL)
		return 1;

	memset(oct->pcipkomap, 0, size);


	printf("[ DRV ] PCIPKOMAP (port, queue):");
	for(i = 0; i < activeqcnt; i++) {
		if ((i % 4) == 0)
			printf("\n%3d: ", i);
		oct->pcipkomap[i].active = 1;
		if (octeon_has_feature(OCTEON_FEATURE_PKO3)) {
 			oct->pcipkomap[i].port   = cvmx_pko_get_base_pko_port(oct->npi_if, i);
 			oct->pcipkomap[i].queue  = cvmx_pko_get_base_queue_pkoid(cvmx_pko_get_base_pko_port(oct->npi_if, i));
		#if 0
			/* mapping mutiples of 8 pko-queue numbers of all the pko-ports */
			baseq = cvmx_pko_get_base_queue_pkoid(cvmx_pko_get_base_pko_port(oct->npi_if, i));
			oct->pcipkomap[i].queue  = baseq + (8-(baseq & 0x7));
		#endif
		} else if(OCTEON_IS_MODEL(OCTEON_CN68XX)) {
			oct->pcipkomap[i].port   = cvmx_pko_get_base_pko_port(oct->npi_if, i);
			oct->pcipkomap[i].queue  = cvmx_pko_get_base_queue_pkoid(cvmx_pko_get_base_pko_port(oct->npi_if, i));
		} else {
			oct->pcipkomap[i].port   = FIRST_PCI_PORT + i%4;
			oct->pcipkomap[i].queue  =
		       cvmx_pko_get_base_queue(oct->pcipkomap[i].port) +  (i/4);
		}
		printf("(%3d, %3d) ", oct->pcipkomap[i].port,
			oct->pcipkomap[i].queue);
	}
	oct->pcipko_base_dq = oct->pcipkomap[0].queue;
	printf("\n");


	/* enable channel level backpressure for pass1.2 */
	if (OCTEON_IS_MODEL(OCTEON_CN73XX_PASS1_2) ||
	    OCTEON_IS_MODEL(OCTEON_CN73XX_PASS1_3)) {
		//cvmx_pko_l1_sqx_link_t link;
		cvmx_pko_channel_level_t level;
		cvmx_pko_dqx_topology_t dqtop;
		cvmx_pko_l3_sqx_topology_t l3top;
		//cvmx_pko_l2_sqx_topology_t l2top;
		cvmx_pko_l3_l2_sqx_channel_t l3_l2_channel;
		unsigned dq, l3_l2_sq;
//		int node = cvmx_get_node_num();
		//int l1q = -1;

#define DQ_LIMIT 768

		//Configure per channel backpressure
		for (i = 0; i < activeqcnt; i++) {
			dq = oct->pcipkomap[i].queue;
			dq &= (1 << 10)-1;
			dqtop.u64 = cvmx_read_csr(CVMX_PKO_DQX_TOPOLOGY(dq));
			l3top.u64 = cvmx_read_csr(CVMX_PKO_L3_SQX_TOPOLOGY(dqtop.s.parent));
			/*if (l1q == -1) {
				l2top.u64 = cvmx_read_csr(CVMX_PKO_L2_SQX_TOPOLOGY(l3top.s.parent));
				l1q = l2top.s.parent;
			}*/
			level.u64 = cvmx_read_csr(CVMX_PKO_CHANNEL_LEVEL);
			//cc_level=1 backpressure at L3 else backpressure at l2
			if (level.s.cc_level) 
				l3_l2_sq = dqtop.s.parent;
			 else 
				l3_l2_sq = l3top.s.parent;
			l3_l2_channel.u64 = cvmx_read_csr(CVMX_PKO_L3_L2_SQX_CHANNEL(l3_l2_sq));
			l3_l2_channel.s.cc_enable = 1;
			//allow mtu+1 bytes
			l3_l2_channel.s.cc_word_cnt = 32;
			//allow one outstanding packet
			l3_l2_channel.s.cc_packet_cnt = 8;
			cvmx_write_csr(CVMX_PKO_L3_L2_SQX_CHANNEL(l3_l2_sq), l3_l2_channel.u64);
//			cvmx_pko3_dq_set_limit(node, dq, DQ_LIMIT);
		}
		/*Configure Link backpressure
		link.u64 = cvmx_read_csr(CVMX_PKO_L1_SQX_LINK(l1q));
		allow mtu+1 bytes
		link.s.cc_word_cnt = 1;
		allow 128 outstanding packets
		link.s.cc_packet_cnt = 127;
		link.s.cc_enable = 1;
		cvmx_write_csr(CVMX_PKO_L1_SQX_LINK(l1q), link.u64);
		*/
	}
	/* The rest of the entries are already marked inactive by memset */
	CVMX_SYNCWS;

	return 0;
}



int
cvm_pci_get_oq_pkoport(int oq)
{
	if(cvmx_unlikely(oq >= 128))
		return -1;

	if(cvmx_unlikely(oct->pcipkomap[oq].active == 0))
		return -1;

	return oct->pcipkomap[oq].port;
}



int
cvm_pci_get_oq_pkoqueue(int oq)
{
	if(cvmx_unlikely(oq >= 128))
		return -1;

	if(cvmx_unlikely(oct->pcipkomap[oq].active == 0))
		return -1;

	return oct->pcipkomap[oq].queue;
}



static inline int 
__cvm_post_pko3_command(cvmx_buf_ptr_t      lptr,
                       uint32_t            pko_ptr_type,
                       uint32_t            segs,
                       uint32_t            total_bytes,
                       uint32_t            port,
                       uint32_t            q_no,
                       uint32_t            flags,
                       uint64_t            flag_data)
{
	uint8_t *data_ptr;
	cvmx_pko3_pdesc_t desc;
    cvmx_pko_send_hdr_t * hdr_s;

	cvmx_pko3_pdesc_init(&desc);
	hdr_s = desc.hdr_s;

	hdr_s->u64 = 0;
    hdr_s->s.df = 0; // H/W will free the buffers by default
    hdr_s->s.ii = 0;

	if(pko_ptr_type == PKO_GATHER_DATA) {
        /* Process legacy gather list */
        uint32_t i;
        cvmx_buf_ptr_t *pPtr;
        cvmx_buf_ptr_t blk;

        pPtr = cvmx_phys_to_ptr(lptr.s.addr);
        blk = pPtr[0];
        data_ptr = cvmx_phys_to_ptr(blk.s.addr);

        for(i = 0; i < segs; i ++) {
            /* Insert PKO_SEND_GATHER_S for the current buffer */
			cvmx_pko3_pdesc_buf_append(&desc, (void *)cvmx_phys_to_ptr(blk.s.addr), blk.s.size,blk.s.pool);
            /* get next bufptr */
            blk = pPtr[i+1];
        }
    } 
	else {
        /* Process legacy linked buffer list */
        cvmx_buf_ptr_t blk;
        void * vptr;

        data_ptr = cvmx_phys_to_ptr(lptr.s.addr);
        blk = lptr;
        do {
			cvmx_pko3_pdesc_buf_append(&desc, (void *)cvmx_phys_to_ptr(blk.s.addr), blk.s.size,blk.s.pool);
            /* Get the next buffer pointer */
            vptr = cvmx_phys_to_ptr(blk.s.addr);
            memcpy(&blk, vptr - sizeof(blk), sizeof(blk));

            segs --;
        } while(segs > 0);
	}

    /* non-zero IP header offset requires L3/L4 checksum calculation */
	if(flags & CVM_USE_HW_CKSUM_OFFLOAD) {
        uint8_t ipoff, ip0, l4_proto = 0;

        /* Get IP header offset */
        ipoff =  (flag_data & 0xff) -1;

        /* Configure IP checksum generation */
        hdr_s->s.l3ptr = ipoff;
        hdr_s->s.ckl3 = 1;
        ip0 = data_ptr[ipoff];

        /* Decode L3 header for L4 type and offset */
        if ((ip0 >> 4) == 4) {
            hdr_s->s.l4ptr = hdr_s->s.l3ptr +
                ((ip0 & 0xf) << 2);
            l4_proto = data_ptr[ipoff + 9];
        }
        if ((ip0 >> 4) == 6) {
            hdr_s->s.l4ptr = hdr_s->s.l3ptr + 40;
            l4_proto = data_ptr[ipoff + 6];
        }
        /* Set L4 checksum algo based on L4 protocol */
        if (l4_proto == 6)
            hdr_s->s.ckl4 = /* TCP */ 2;
        else if (l4_proto == 17)
            hdr_s->s.ckl4 = /* UDP */ 1;
        else if (l4_proto == 132)
            hdr_s->s.ckl4 = /* SCTP */ 3;
        else
            hdr_s->s.ckl4 = /* Uknown */ 0;
    }	

	cvmcs_pko3_pdesc_transmit(&desc, q_no, NULL);

	return 0;
}




static inline int
__cvm_post_pko_command(cvmx_buf_ptr_t      lptr,
                       uint32_t            pko_ptr_type,
                       uint32_t            segs,
                       uint32_t            total_bytes,
                       uint32_t            port,
                       uint32_t            q_no,
                       uint32_t            flags,
                       uint64_t            flag_data)
{
	cvmx_pko_command_word0_t    pko_command;


	CVMX_SYNCWS;
	if(cvmx_unlikely(total_bytes > 65528 || segs > 63)) {
		printf("[ DRV ] Unsupported configuration: total_bytes: %d segs: %d\n", total_bytes, segs);
		printf("[ DRV ] total_bytes cannot be > 65528; segs cannot be > 63\n");
		return 1;
	}

	/* Prepare to send a packet to PKO. */
	if (octeon_has_feature(OCTEON_FEATURE_PKND))
		cvmx_pko_send_packet_prepare_pkoid(port, q_no, 1);
	else
		cvmx_pko_send_packet_prepare(port, q_no, 1);


	/* Build a PKO pointer to this packet */
	pko_command.u64           = 0;
	/* Setting II = 0 and DF = 1 will free all buffers whose I bit is set. */
	pko_command.s.ignore_i    = 0;
	pko_command.s.dontfree    = 1;
	pko_command.s.segs        = segs;
	pko_command.s.total_bytes = total_bytes;
	/* For linked mode data and direct mode data this field is zero. */
	pko_command.s.gather      = (pko_ptr_type == PKO_GATHER_DATA);
	if(flags & CVM_USE_HW_CKSUM_OFFLOAD)
		pko_command.s.ipoffp1 = flag_data & 0xff;

	DBG_PRINT(DBG_FLOW,"\n>>>>>pko cmd: %016llx totalbytes: %d lptr: %016llx PORT: %d Q: %d\n",
	          cast64(pko_command.u64), total_bytes, cast64(lptr.u64), port, q_no);

	if (octeon_has_feature(OCTEON_FEATURE_PKND))
		cvmx_pko_send_packet_finish_pkoid(port, q_no, pko_command,lptr, 1);
	else
		cvmx_pko_send_packet_finish(port, q_no, pko_command,lptr, 1);

	return 0;
}





int
cvm_pko_send_direct(cvmx_buf_ptr_t   lptr,
                    cvm_ptr_type_t   ptr_type,
                    uint32_t         segs,
                    uint32_t         total_bytes,
                    uint32_t         port)
{
	int q_no = cvmx_pko_get_base_queue(port);

	if(cvmx_unlikely(oct->pko_state != CVM_DRV_PKO_READY)) {
		printf("[ DRV ] Core driver PKO is in state (0x%x); PKO Send abort!\n",
		     oct->pko_state);
		return 1;
	}

	if (octeon_has_feature(OCTEON_FEATURE_PKO3))
		return   __cvm_post_pko3_command(lptr, (uint32_t)ptr_type, segs, total_bytes, port, q_no, 0, 0);
	else
		return   __cvm_post_pko_command(lptr, (uint32_t)ptr_type, segs, total_bytes, port, q_no, 0, 0);
}





int
cvm_send_pci_pko_direct(cvmx_buf_ptr_t   lptr,
                        cvm_ptr_type_t   ptr_type,
                        uint32_t         segs,
                        uint32_t         total_bytes,
                        uint32_t         oq_no)
{
//	printf("%s lptr: 0x%016lx ptrtype: %d segs: %d total_bytes: %d oq_no: %d\n", __FUNCTION__, lptr.u64, ptr_type, segs, total_bytes, oq_no);

	if(cvmx_unlikely(oct->pko_state != CVM_DRV_PKO_READY)) {
		printf("[ DRV ] Core driver PKO is in state (0x%x); PKO Send abort!\n",
		     oct->pko_state);
		return 1;
	}

	if(cvmx_unlikely(!oct->pcipkomap[oq_no].active)) {
		printf("[ DRV ] %s: OQ# %d is not active\n", __FUNCTION__, oq_no);
		return 1;
	}

	if (octeon_has_feature(OCTEON_FEATURE_PKO3))
		return  __cvm_post_pko3_command(lptr, (uint32_t)ptr_type, segs, total_bytes,
		             oct->pcipkomap[oq_no].port, oct->pcipkomap[oq_no].queue, 0, 0);
	else
		return  __cvm_post_pko_command(lptr, (uint32_t)ptr_type, segs, total_bytes,
		             oct->pcipkomap[oq_no].port, oct->pcipkomap[oq_no].queue, 0, 0);
}




int
cvm_pko_send_direct_flags(cvmx_buf_ptr_t   lptr,
                          cvm_ptr_type_t   ptr_type,
                          uint32_t         segs,
                          uint32_t         total_bytes,
                          uint32_t         port,
                          uint32_t         flags,
                          uint64_t         flag_data)
{
	int q_no = cvmx_pko_get_base_queue(port);

	if(oct->pko_state != CVM_DRV_PKO_READY) {
		printf("[ DRV ] Core driver PKO is in state (0x%x); PKO Send abort!\n",
		       oct->pko_state);
		return 1;
	}

	return   __cvm_post_pko_command(lptr, (uint32_t)ptr_type, segs, total_bytes, port, q_no, flags, flag_data);
}





#define GATHER_LIST_OFFSET    4

/**
  *  Call this routine to send a data packet to the Octeon output 
  *  queues. For a linked mode or direct mode data, this routine
  *  adds another buffer to the start of the linked list into which the
  *  response header is copied. For a gather mode data sent by user,
  *  this routine creates a new gather list and makes the user
  *  response header the first element of the gather list. Needless
  *  to say, if performance is important, you should make space
  *  to add 8 bytes of response header before your data and call
  *  cvm_post_pko_command() directly. 
  *
  *  @param union octeon_rh  - the receive header that identifies the
  *                            user data.
  *  @param total_bytes      - amount of user data (excludes response
  *                            header)
  *  @param segs  - number of user buffers (in linked and gather mode)
  *  @param port  - PKO port on which to send data ( 32 <= port <= 35)
  *  @param dptr  - pointer to the user data.
  *  @param flags - type of data pointed by dptr( linked/gather/direct)
  *
  *  @return  Success: returns 0, else 1.
  */
int
cvm_pko_send_data(union octeon_rh  *user_rh,
                  cvmx_buf_ptr_t    dptr,
                  cvm_ptr_type_t    ptr_type,
                  uint32_t          total_bytes,
                  uint32_t          segs,
                  uint32_t          port)
{
    cvmx_buf_ptr_t    lptr;
    union octeon_rh  *rh;
    uint16_t          gcount=0;
    cvmx_buf_ptr_t   *glist,*send_buf;

	if(oct->pko_state != CVM_DRV_PKO_READY) {
		printf("[ DRV ] Core driver PKO is in state (0x%x); PKO Send abort!\n",
		       oct->pko_state);
		return 1;
	}

    send_buf = CVM_PCI_PKO_ALLOC_BUFFER();
    if(!send_buf) {
       printf("[ DRV ] CVM_PKO: Allocation failed in sending PKO data\n");
       return 1;
    }

    rh = (union octeon_rh *)&send_buf[1];
    memcpy(rh, user_rh, OCT_RH_SIZE);


    if(ptr_type != CVM_GATHER_DATA)  {
          DBG_PRINT(DBG_FLOW, "Direct or linked mode data\n");

          /*  The response header adds 8 bytes to pko send data size. */
          total_bytes += 8; 
          segs ++;

          /* Creating a linked mode data packet for user data that is in
             DIRECT or LINKED mode. */
          /* The start of the buffer points to the data sent by user. */
          send_buf->u64    = dptr.u64;

          lptr.u64    = 0;
          lptr.s.size = 8;
          lptr.s.addr = CVM_DRV_GET_PHYS(&send_buf[1]);
          lptr.s.pool = CVM_PCI_PKO_FPA_POOL;
          lptr.s.i    = 1;  /* PKO SHOULD FREE THIS BUFFER */
          DBG_PRINT(DBG_FLOW,"lptr: %016llx segs: %d total_bytes: %d\n", cast64(lptr.u64), segs, total_bytes);
          CVMX_SYNCWS;
          cvm_pko_send_direct(lptr, PKO_LINKED_DATA, segs, total_bytes, port);

    } else {
          uint16_t           i;
          cvmx_buf_ptr_t    *ptr = (cvmx_buf_ptr_t *)CVM_DRV_GET_PTR(dptr.s.addr);

          glist = (send_buf + GATHER_LIST_OFFSET);

          /* Prepare the gather list */
          /* First element points to the response header contents (8Bytes)*/
          glist[gcount].u64    = 0;
          glist[gcount].s.addr = CVM_DRV_GET_PHYS(rh);
          glist[gcount].s.size = 8;
          total_bytes   += 8;
          gcount++;

          DBG_PRINT(DBG_FLOW,"cvm_pko_send: Data as a gather list @ %p\n", ptr);
          /* If dptr points to a gather list of user data, the size field
             holds the number of elements in the gather list  */
          for(i = 0; i < dptr.s.size; i++, ptr++) {
              DBG_PRINT(DBG_NORM,"copying Val: 0x%016llx from 0x%p into 0x%p\n",
                       cast64(ptr->u64), ptr, &glist[gcount]);
              glist[gcount++].u64 = ptr->u64;
          }
          DBG_PRINT(DBG_NORM,"glist @ %p, gcount: %d, total_bytes: %d\n",
                    glist, gcount, total_bytes);

          lptr.u64    = 0;
          lptr.s.size = gcount;
          lptr.s.addr = CVM_DRV_GET_PHYS(glist);
          lptr.s.pool = CVM_PCI_PKO_FPA_POOL;
          lptr.s.i    = 1;  /* PKO SHOULD FREE THIS BUFFER */
          CVMX_SYNCWS;
          cvm_pko_send_direct(lptr, PKO_GATHER_DATA, gcount, total_bytes, port);
    }
    return 0;
}




/* $Id$ */
