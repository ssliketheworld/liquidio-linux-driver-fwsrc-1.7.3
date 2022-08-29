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

/*! \file  cn56xx_ep_comm.h
    \brief Core Driver: Structures & simple executive API for
	                    endpoint-to-endpoint communication.
*/


#ifndef  __CN56XX_EP_COMM_H__
#define  __CN56XX_EP_COMM_H__



#include "cvmx.h"
#include "cvm-drv.h"
#include "cvm-driver-defs.h"
#include "liquidio_common.h"

#define  MAX_EP_PKT_BUFS  4


/** Core: Structure used by driver for buffer management in end-point 
	      communication. */
typedef  struct {

	/** List of buffers */
	cvmx_buf_ptr_t  buf[MAX_EP_PKT_BUFS];

	/** Internal gather pointer used by driver. */
	cvmx_buf_ptr_t  gptr;

} cn56xx_ep_buflist_t;




/** Core: Structure passed by application to send data to another endpoint. */
typedef struct {

	/** Tag in IH to use in input queue command. */
	uint32_t  tag;

	/** Tagtype in IH to use in input queue command. */
	uint8_t   tagtype;

	/** Param value in IRH to use in input queue command. */
	uint8_t   param;

	/** Opcode value in IRH to use in input queue command. */
	uint16_t  opcode;

	/** Group value in IH to use in input queue command. */
	uint8_t   grp:4;

	/** QOS in IH to use in input queue command. */
	uint8_t   qos:3;

	uint8_t   free:1;

	/** Number of input buffers */
	uint8_t   bufcount;

	/** The Peer Input queue to use to send data. */
	uint8_t   piq_id;

	uint8_t   reserved;

	/** List of input buffers */
	cvmx_buf_ptr_t  buf[MAX_EP_PKT_BUFS];

} cn56xx_ep_packet_t;






int   cn56xx_alloc_peeriq_memory(void);

void  cn56xx_setup_peeriq_op_handler(void);

void  cn56xx_ep_update_peeriq(int piq_id);



int
cn56xx_send_ep_packet(cn56xx_ep_packet_t  *pkt);

int
cn56xx_send_ep_packet_to_octeon(int oct_id, cn56xx_ep_packet_t  *pkt);



int  cn56xx_send_ep_test_pkt_to_peer(int peer_id);
int  cn56xx_send_ep_test_pkt_to_octeon(int oct_id);


void  cn56xx_process_ep_test_packet(cvmx_wqe_t   *wqe);

void  cn56xx_print_peer_iq_stats(int piq_id);
void  cn56xx_print_ep_pkt_count();


#endif


/* $Id$  */

