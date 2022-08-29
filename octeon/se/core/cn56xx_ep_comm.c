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



#include "cn56xx_ep_comm.h"
#include "cvm-drv-debug.h"
#include "cvm-pci-loadstore.h"

#include "cn56xx_regs.h"

#define DBG(format, args...)     do{ }while(0)
//#define  DBG printf

/* This should be number of ((number of target devices) - 1)  */
#define  MAX_PEERS          3

#define  FIRST_PEER_IQ      4

#define  PEER_CMDQ_SIZE     1024



#define PEER_NONE  0
#define PEER_OK    1

CVMX_SHARED  uint8_t   ep_count=0, send_p2p_ok = 0;

CVMX_SHARED  uint64_t  ep_pkts_sent[CN56XX_MAX_CORES], ep_pkts_recvd[CN56XX_MAX_CORES];

extern CVMX_SHARED  cvm_oct_dev_t   *oct;


#define EP_BUF_SIZE  256
#define EP_BUF_COUNT 1




CVMX_SHARED static struct remote_iq {

	cvmx_spinlock_t       lock;

	uint64_t              piq_id:8;
	uint64_t              swap_mode:8;
	uint64_t              reserved:48;

	struct octeon_instr_32B   *my_cmdq;
	cn56xx_ep_buflist_t  *buflist;
	uint64_t              my_iqsize;
	uint64_t              my_wr_idx;
	uint64_t              my_rd_idx;
	uint64_t              my_reqs_pending;
	uint64_t              my_state;
	uint64_t              my_iq_base_addr;

	uint64_t              rem_base_addr_reg;
	uint64_t              rem_iqsize_reg;
	uint64_t              rem_wr_idx_reg;
	uint64_t              rem_rd_idx_reg;

	uint64_t              rem_bar0_base_addr;
	uint64_t              rem_bar1_base_addr;

	uint64_t              pkts_sent;

} *peeriq[MAX_PEERS];



/* There will be MAX_PEERS+1 devices in the system */
CVMX_SHARED struct  {
	struct remote_iq   *piq;
} remoctdev[MAX_PEERS + 1];






int
cn56xx_process_pci_map(cvmx_wqe_t  *wqe);





/* Allocate memory for the command queue in Octeon memory and
   struct remote_iq that manages the command queue. */
int
cn56xx_alloc_peeriq_memory(void)
{
	int i;

	for(i = 0; i < MAX_PEERS; i++) {
		uint32_t  size;

		peeriq[i] = cvmx_bootmem_alloc(sizeof(struct remote_iq), CVMX_CACHE_LINE_SIZE);
		if(peeriq[i] == NULL)
			return 1;

		memset(peeriq[i], 0, sizeof(struct remote_iq));
		printf("CN56XX PASS1: PeerIQ[%d] allocated @ %p\n", i, peeriq[i]);


		size = sizeof(struct octeon_instr_32B) * PEER_CMDQ_SIZE;
		peeriq[i]->my_cmdq = cvmx_bootmem_alloc(size, CVMX_CACHE_LINE_SIZE);
		if(peeriq[i]->my_cmdq == NULL)
			return 1;

		memset(peeriq[i]->my_cmdq, 0, size);
		printf("CN56XX PASS1: PeerIQ[%d] CmdQ allocated @ %p\n",
		       i, peeriq[i]->my_cmdq);


		size = sizeof(cn56xx_ep_buflist_t) * PEER_CMDQ_SIZE;
		peeriq[i]->buflist = cvmx_bootmem_alloc(size, CVMX_CACHE_LINE_SIZE);
		if(peeriq[i]->buflist == NULL)
			return 1;

		memset(peeriq[i]->buflist, 0, size);
		printf("CN56XX PASS1: PeerIQ[%d] Buflist allocated @ %p\n",
		       i, peeriq[i]->buflist);


		peeriq[i]->my_iqsize = PEER_CMDQ_SIZE;
		cvmx_spinlock_init(&peeriq[i]->lock);
	}


	for(i = 0; i < CN56XX_MAX_CORES; i++)
		ep_pkts_sent[i] = ep_pkts_recvd[i] = 0;


	/* Initialize the remote octeon device structures to NULL */
	memset(remoctdev, 0, (sizeof(void *) * MAX_PEERS));

	return 0;
}






/* Opcode handler for the PCI Map instruction sent by host */
void
cn56xx_setup_peeriq_op_handler(void)
{
    cvm_drv_register_op_handler(OPCODE_CORE, PCIE_MAP_OP,  cn56xx_process_pci_map);
}





static void
cn56xx_setup_peeriq(struct remote_iq   *piq,
                    cn56xx_pci_map_t   *map)
{

	printf("%s  piq @ %p map @ %p oct_id: %d\n",
		 __FUNCTION__, piq, map, oct->dev_id);


	piq->rem_bar0_base_addr = map->bar0_pci_addr;
	piq->rem_bar1_base_addr = map->bar1_pci_addr;

	piq->rem_base_addr_reg = (unsigned long)map->bar0_pci_addr
	            + CN56XX_NPEI_IQ_BASE_ADDR64(FIRST_PEER_IQ + oct->dev_id);
	printf("Remote Base Addr: 0x%016lx\n", piq->rem_base_addr_reg);

	piq->rem_iqsize_reg    = (unsigned long)map->bar0_pci_addr
	            + CN56XX_NPEI_IQ_SIZE(FIRST_PEER_IQ + oct->dev_id);
	printf("Remote IQ Size: 0x%016lx\n", piq->rem_iqsize_reg);

	piq->rem_wr_idx_reg    = (unsigned long)map->bar0_pci_addr
	            + CN56XX_NPEI_IQ_DOORBELL(FIRST_PEER_IQ + oct->dev_id);
	printf("Remote Wr Idx: 0x%016lx\n", piq->rem_wr_idx_reg);

	piq->rem_rd_idx_reg    = (unsigned long)map->bar0_pci_addr
	            + CN56XX_NPEI_IQ_INSTR_COUNT(FIRST_PEER_IQ + oct->dev_id);
	printf("Remote Rd Idx: 0x%016lx\n", piq->rem_rd_idx_reg);

}



int
cn56xx_setup_remote_iq_regs(struct remote_iq *piq)
{
	uint64_t  val64;

	printf("Writing 0x%lx into remote reg @ %lx\n",
		piq->my_iq_base_addr, piq->rem_base_addr_reg);

	cvm_pci_mem_writell(piq->rem_base_addr_reg,
	                    ENDIAN_SWAP_8_BYTE(piq->my_iq_base_addr));
	cvm_pci_mem_writell(piq->rem_iqsize_reg,
	                    ENDIAN_SWAP_8_BYTE(piq->my_iqsize));


	cvm_pci_mem_writell(piq->rem_bar0_base_addr
		+ CN56XX_NPEI_IQ_BP64(FIRST_PEER_IQ + oct->dev_id),
			0xFFFFFFFFULL);

	cvm_pci_mem_writell(piq->rem_bar0_base_addr
		+ CN56XX_NPEI_IQ_PKT_INSTR_HDR64(FIRST_PEER_IQ + oct->dev_id),
			0);

	val64 = cvm_pci_mem_readll(piq->rem_bar0_base_addr + CN56XX_NPEI_PKT_INSTR_ENB);
	printf("INSTR ENB read as 0x%016lx\n", val64);
	val64 = ENDIAN_SWAP_8_BYTE(val64);
	val64 |= (1 << (FIRST_PEER_IQ + oct->dev_id));
	val64 = ENDIAN_SWAP_8_BYTE(val64);
	printf("Writing INSTR ENB as 0x%016lx\n", val64);
	cvm_pci_mem_writell(piq->rem_bar0_base_addr + CN56XX_NPEI_PKT_INSTR_ENB,
		val64);

	send_p2p_ok = 1;
	return 0;
}







/* Received a PCI map from the host with the base address info for each 56xx
   target device in the system. */
int
cn56xx_process_pci_map(cvmx_wqe_t  *wqe)
{
	cn56xx_map_data_t  *data;
	cn56xx_pci_map_t   *map;
	int                 idx;



	printf("--- Received PCI MAP Instruction\n");
	if( ! OCTEON_IS_MODEL(OCTEON_CN56XX)) {
		printf(" !! Error !! EP-to-EP is not supported on this Octeon model\n");
		cvm_free_host_instr(wqe);
		return 1;
	}

	data = (cn56xx_map_data_t *)CVM_DRV_GET_PTR(wqe->packet_ptr.s.addr + CVM_RAW_FRONT_SIZE);
	map = &data->map;

	cvm_drv_print_data(data, (cvmx_wqe_get_len(wqe) - CVM_RAW_FRONT_SIZE));

	if(data->hdr.my_device_id > MAX_PEERS) {
		printf(" !! ERROR !! Invalid Octeon ID (%u) received\n",
		       data->hdr.my_device_id);
		cvm_free_host_instr(wqe);
		return 1;
	}

	oct->dev_id    = data->hdr.my_device_id;
	oct->bar0_addr = map[oct->dev_id].bar0_pci_addr;
	oct->bar1_addr = map[oct->dev_id].bar1_pci_addr;
	printf("My bar0_pci_addr: %lx bar1_pci_addr: %lx\n",
		oct->bar0_addr, oct->bar1_addr);


	if(data->hdr.dev_count > 1) {

		struct remote_iq *piq;

		printf("There are %d octeon devices in the system\n",
		       data->hdr.dev_count);

		for(idx = 0; idx < data->hdr.dev_count; idx++) {

			if(idx == data->hdr.my_device_id)
				continue;

			printf("\n\nInitializing Peer[%d] to communicate with Octeon[%d]\n",
			       oct->max_peers, idx);

			piq = peeriq[oct->max_peers];
			piq->piq_id = oct->max_peers;
			remoctdev[idx].piq = piq;

			cn56xx_setup_peeriq(piq, &map[idx]);

			piq->swap_mode        = data->hdr.swap_mode;
			if(piq->swap_mode)
				printf("PIQ[%d] Commands set to be swapped\n", oct->max_peers);
			piq->my_iq_base_addr  = CVM_DRV_GET_PHYS(piq->my_cmdq) +
			                        oct->bar1_addr;


			printf("IQ_BASE: %lx\n", piq->my_iq_base_addr);
			printf("Remote Registers base_addr_reg: %lx iqsize: %lx\n",
				piq->rem_base_addr_reg, piq->rem_iqsize_reg);

			printf("Setting up remote registers for PIQ[%d]\n",oct->max_peers); 
			cn56xx_setup_remote_iq_regs(piq);
			piq->my_state = PEER_OK;

			oct->max_peers++;
			CVMX_SYNCW;
		}

	} else {

		printf("There are no peers to this device\n");

	}

	cvm_free_host_instr(wqe);

	return 0;
}







void
cn56xx_ep_free_bufs(int bufcount, cn56xx_ep_buflist_t   *buflist)
{
	int    i;

	DBG("%s called to check & free %d bufs\n",__FUNCTION__, bufcount);

	for(i = 0; i < bufcount; i++) {
		if(buflist->buf[i].s.i) {
			DBG("Freeing buffer @ %p into pool %d\n",
			        CVM_DRV_GET_PTR(buflist->buf[i].s.addr),
			        buflist->buf[i].s.pool);
			cvm_drv_free_pkt_buffer(buflist->buf[i]);
		}
		buflist->buf[i].u64 = 0;
	}

	if(bufcount > 1) {
		DBG("Freeing gatherlist @ %p into pool %d\n",
		        CVM_DRV_GET_PTR(buflist->gptr.s.addr),buflist->gptr.s.pool);
		cvmx_fpa_free(CVM_DRV_GET_PTR(buflist->gptr.s.addr),
			               buflist->gptr.s.pool, 0);
	}
	CVMX_SYNCW;
}








void
cn56xx_ep_update_peeriq(int  piq_id)
{
	uint64_t                        old_rd_idx;
	struct remote_iq               *piq = peeriq[piq_id];

	if(piq->my_wr_idx == piq->my_rd_idx)
		return;

	old_rd_idx = piq->my_rd_idx;

	piq->my_rd_idx = ENDIAN_SWAP_8_BYTE(cvm_pci_mem_readll(piq->rem_rd_idx_reg))%piq->my_iqsize;

	if(old_rd_idx != piq->my_rd_idx) {
		struct octeon_instr_32B   *cmd;
	
		DBG("\n>>old_rd_idx: %lu new_rd_idx: %lu\n", old_rd_idx, piq->my_rd_idx);
		while(old_rd_idx != piq->my_rd_idx) {
			DBG("%s: PeerIQ completed fetching of index %lu\n", __FUNCTION__, old_rd_idx);
			cmd = &(piq->my_cmdq[old_rd_idx]);
			cn56xx_ep_free_bufs( (cmd->ih.s.gather)?(cmd->ih.s.dlengsz):1, 
			                     &piq->buflist[old_rd_idx]);
			INCR_INDEX_BY1(old_rd_idx, piq->my_iqsize);
			piq->my_reqs_pending--;
			piq->pkts_sent++;
		}
	}

}








cvmx_buf_ptr_t 
cn56xx_create_ep_gather_list(cn56xx_ep_packet_t  *pkt)
{
	struct __sg {
		uint16_t   len[4];
		uint64_t   ptr[4];
	} *sg;
	int                i;
	cvmx_buf_ptr_t     g;

	g.u64    = 0;

	sg = cvmx_fpa_alloc(CVMX_FPA_SMALL_BUFFER_POOL);
	if(sg == NULL)
		return g;

	DBG("%s: gather list allocated at %p\n", __FUNCTION__, sg);

	memset(sg, 0, sizeof(struct __sg));
	for(i = 0; i < pkt->bufcount; i++) {
		sg->len[i] = pkt->buf[i].s.size;
		sg->ptr[i] = oct->bar1_addr + pkt->buf[i].s.addr;
	}

	g.s.addr = CVM_DRV_GET_PHYS(sg);
	g.s.pool = CVMX_FPA_SMALL_BUFFER_POOL;
	g.s.size = sizeof(struct __sg);
	g.s.i    = 0;

	return g;
}








void
cn56xx_ep_copy_pkt_bufs_to_cmdq(cn56xx_ep_buflist_t  *buflist,
                                cn56xx_ep_packet_t   *pkt)
{
	int i;

	for(i = 0; i < pkt->bufcount; i++)
		buflist->buf[i].u64 = pkt->buf[i].u64;

	if(pkt->bufcount > 1)
		buflist->gptr = cn56xx_create_ep_gather_list(pkt);
}
















int
cn56xx_send_ep_packet(cn56xx_ep_packet_t  *pkt)
{
	struct octeon_instr_32B   iqcmd;
	struct remote_iq    *piq;


	if(pkt->piq_id >= oct->max_peers) {
		printf("Packet for non-existent PeerIQ (id: %d)\n", pkt->piq_id);
		return 1;
	}

	piq = peeriq[pkt->piq_id];


	if(piq->my_state != PEER_OK) {
		printf("PeerIQ[%d] state is not PEER_OK\n", piq->piq_id);
		return 1;
	}


	if(pkt->bufcount == 0 || pkt->bufcount > MAX_EP_PKT_BUFS) {
		printf("%s Invalid pkt buf count (%d)\n", __FUNCTION__, pkt->bufcount);
		return 1;
	}

	memset(&iqcmd, 0, sizeof(struct octeon_instr_32B));

	iqcmd.ih.s.tt      = pkt->tagtype;
	iqcmd.ih.s.tag     = pkt->tag;
	iqcmd.ih.s.grp     = pkt->grp;
	iqcmd.ih.s.qos     = pkt->qos;
	iqcmd.ih.s.r       = 1;
	iqcmd.ih.s.fsz     = 16;

	iqcmd.irh.s.opcode = pkt->opcode;
	iqcmd.irh.s.param  = pkt->param;
	/////////  THIS IS FOR TEST ONLY ////////////////
	iqcmd.irh.s.rlenssz = EP_BUF_SIZE;



	cvmx_spinlock_lock(&piq->lock);


	if(piq->my_reqs_pending >= (piq->my_iqsize - 1)) {
		cn56xx_ep_update_peeriq(pkt->piq_id);
		cvmx_spinlock_unlock(&piq->lock);
		printf("%s No space in Peer[%d] Input Queue (pending: %lu)\n",
		        __FUNCTION__, piq->piq_id, piq->my_reqs_pending);
		return 1;
	}

	if(piq->my_reqs_pending >= (piq->my_iqsize/2)) {
		/* Update Read index every time */
		cn56xx_ep_update_peeriq(pkt->piq_id);
	}

	cn56xx_ep_copy_pkt_bufs_to_cmdq(&piq->buflist[piq->my_wr_idx], pkt);

	if(cvmx_likely(pkt->bufcount == 1)) {
		iqcmd.ih.s.dlengsz = pkt->buf[0].s.size;
		iqcmd.dptr         = pkt->buf[0].s.addr + oct->bar1_addr;
	} else {
		iqcmd.ih.s.gather   = 1;
		iqcmd.ih.s.dlengsz  = pkt->bufcount;
		if(piq->buflist[piq->my_wr_idx].gptr.s.addr == 0) {
			cvmx_spinlock_unlock(&piq->lock);
			printf("%s Gather list alloc failed in peer iq\n", __FUNCTION__);
			return 1;
		}
		iqcmd.dptr = oct->bar1_addr + piq->buflist[piq->my_wr_idx].gptr.s.addr;
	}


	if(piq->swap_mode)
	{
		uint64_t   *cmd = (uint64_t *)&iqcmd;
		int i;
		for(i = 0; i < 4; i++)
			CVMX_ES64(cmd[i], cmd[i]);
	}


	memcpy(&piq->my_cmdq[piq->my_wr_idx], &iqcmd, sizeof(struct octeon_instr_32B));

	INCR_INDEX_BY1(piq->my_wr_idx, piq->my_iqsize);

	DBG("PeerIQ my_wr_idx updated to %lu\n", piq->my_wr_idx);

	CVMX_SYNCW;

	cvm_pci_mem_writell(piq->rem_wr_idx_reg, ENDIAN_SWAP_8_BYTE(1ULL));

	piq->my_reqs_pending++;

	cvmx_spinlock_unlock(&piq->lock);

	return 0;
}






int
cn56xx_send_ep_pkt_to_octeon(int oct_id, cn56xx_ep_packet_t  *pkt)
{
	if(remoctdev[oct_id].piq) {
		pkt->piq_id = remoctdev[oct_id].piq->piq_id;
		return cn56xx_send_ep_packet(pkt);
	}

	return 1;
}






static int
cn56xx_create_ep_test_pkt(cn56xx_ep_packet_t   *pkt)
{
	uint8_t   *data;
	int        i, size=EP_BUF_SIZE, bufcount = EP_BUF_COUNT;


	memset(pkt, 0, sizeof(cn56xx_ep_packet_t));

	pkt->bufcount = bufcount;

	for(i = 0; i < bufcount; i++) {

		size = EP_BUF_SIZE;
		data = (uint8_t *)cvmx_fpa_alloc(CVMX_FPA_PACKET_POOL);


		if(data == NULL) {
			printf("%s Packet data alloc failed\n", __FUNCTION__);
			return 1;
		}

		////////////  PTR ADJUSTMENT ////////////
		//data += cvmx_get_cycle() & 0x7;

		DBG("pkt.data allocated @ %p\n", data);
		pkt->buf[i].s.addr = CVM_DRV_GET_PHYS(data);
		pkt->buf[i].s.size = size;
		pkt->buf[i].s.pool = CVMX_FPA_PACKET_POOL;
		pkt->buf[i].s.i    = 1;

		while(size--)
			data[size] = size;
	}

	pkt->tag     = 0x11001100;
	pkt->tagtype = CVMX_POW_TAG_TYPE_ORDERED;
	pkt->param   = ep_count++;
	pkt->opcode  = EP_TO_EP_OP;

	return 0;
}




int
cn56xx_send_ep_test_pkt_to_peer(int peer_id)
{
	cn56xx_ep_packet_t   pkt;

	if(send_p2p_ok == 0)
		return 1;

	if(cn56xx_create_ep_test_pkt(&pkt))
		return 1;

	pkt.piq_id  = peer_id;
	DBG("Sending peer pkt to PIQ[%d] with opcode: %x param: %x\n",
		pkt.piq_id, pkt.opcode, pkt.param);

	if(cn56xx_send_ep_packet(&pkt)) {
		int i;
		for(i = 0; i < pkt.bufcount; i++)
			cvm_drv_free_pkt_buffer(pkt.buf[i]);
		printf("EP Test Packet Send failed, Wait a while...\n");
		cvmx_wait(500000000);
		send_p2p_ok = 0;
		return 1;
	} else {
		ep_pkts_sent[cvmx_get_core_num()]++;
	}

	return 0;
}






int
cn56xx_send_ep_test_pkt_to_octeon(int oct_id)
{
	cn56xx_ep_packet_t   pkt;

	if(send_p2p_ok == 0)
		return 1;

	if(remoctdev[oct_id].piq == NULL)
		return 1;

	if(cn56xx_create_ep_test_pkt(&pkt))
		return 1;

	DBG("Sending peer pkt to octeon[%d] with opcode: %x param: %x\n",
		oct_id, pkt.opcode, pkt.param);

	if(cn56xx_send_ep_pkt_to_octeon(oct_id, &pkt)) {
		int i;
		for(i = 0; i < pkt.bufcount; i++)
			cvm_drv_free_pkt_buffer(pkt.buf[i]);
		printf("EP Test Packet Send failed, Wait a while...\n");
		cvmx_wait(500000000);
		send_p2p_ok = 0;
		return 1;
	} else {
		ep_pkts_sent[cvmx_get_core_num()]++;
	}

	return 0;
}





void
cn56xx_process_ep_test_packet(cvmx_wqe_t   *wqe)
{
#if DBG
	cvmx_raw_inst_front_t  *front = (cvmx_raw_inst_front_t *)wqe->packet_data;

	printf("%s Received test pkt (pkt len: %d bufs: %d)\n",
	       __FUNCTION__, cvmx_wqe_get_len(wqe), cvmx_wqe_get_bufs(wqe));
	printf("EP Test Pkt: Param: %x\n", front->irh.s.param);

	cvm_drv_print_data(CVM_DRV_GET_PTR(wqe->packet_ptr.s.addr), cvmx_wqe_get_len(wqe));
#endif
	cvm_free_host_instr(wqe);
	ep_pkts_recvd[cvmx_get_core_num()]++;
}



void
cn56xx_print_peer_iq_stats(int piq_id)
{
	struct remote_iq  *piq;

	if(piq_id > oct->max_peers)
		return;

	piq = peeriq[piq_id];
	printf("PeerIQ reqs_pending: %lu wr_idx: %lu rd_idx: %lu pkts_sent: %lu\n",
	     piq->my_reqs_pending, piq->my_wr_idx, piq->my_rd_idx, piq->pkts_sent);
}



void
cn56xx_print_ep_pkt_count(void)
{
	uint64_t   i, pkts_sent=0, pkts_recvd=0;

 	for(i = 0; i < CN56XX_MAX_CORES; i++) {
		pkts_recvd += ep_pkts_recvd[i];
		pkts_sent  += ep_pkts_sent[i];
	}

	printf("Total EP Test pkts: Sent: %lu Received: %lu\n", pkts_sent, pkts_recvd);
}



/* $Id$  */
