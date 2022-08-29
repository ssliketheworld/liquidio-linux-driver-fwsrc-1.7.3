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



int
cvmcs_test_process_wqe(cvmx_wqe_t  *wqe)
{
	cvmx_raw_inst_front_t  *front;

	if(OCTEON_IS_MODEL(OCTEON_CN78XX))
		front =  (cvmx_raw_inst_front_t *) cvmx_phys_to_ptr(cvmx_wqe_get_pki_pkt_ptr(wqe).addr);
	else
		front  = (cvmx_raw_inst_front_t *)wqe->packet_data;

	switch(front->irh.s.subcode) {

		case CVMCS_REQRESP_OP:
			//printf("Received Test Request\n");
			cvmcs_process_instruction(wqe);
			break;

		case CVMCS_REQRESP_COMP_OP:
			cvm_free_host_instr(wqe);
			break;

		case CORE_DRV_TEST_SCATTER_OP:
			if(OCTEON_IS_MODEL(OCTEON_CN78XX))
				cvmcs_process_scatter_instruction_o3(wqe);
			else
				cvmcs_process_scatter_instruction(wqe);
			break;

#ifdef CVMCS_DMA_DEMO
		case CVMCS_DMA_OP:
			cvmcs_process_dma_demo(wqe);
			break;
#endif

#ifdef CN56XX_PEER_TO_PEER
		case EP_TO_EP_OP:
			cn56xx_process_ep_test_packet(wqe);
			break;
#endif
		/* Fd close() indication message to SE application.
 		 * Just ignoring this message 
 		 */ 	
		case FD_CLOSE_INDICATION:
			cvm_free_host_instr(wqe);
			/*printf("Close FD Opcode %x (pid: %d) not supported (wqe->len: %d)\n",
			       front->irh.s.opcode, front->irh.s.rid, cvmx_wqe_get_len(wqe)); */
			break;
		default:
			printf("Opcode %x (param: %x) not supported (wqe->len: %d)\n",
			       front->irh.s.opcode, front->irh.s.param, cvmx_wqe_get_len(wqe));
			cvm_drv_print_wqe(wqe);
			return 1;
	}
	return 0;
}





uint8_t
cvmcs_sign_data(uint8_t  *buf, uint32_t  size, uint8_t  start)
{
	while(size--)
		*(buf++) = start++;

	return start;
}



void
cvmcs_test_print_options()
{
#if defined(CVMCS_DMA_DEMO)
	printf(" [ DMA DEMO ] ");
#endif
#ifdef CVMCS_TEST_PKO
	printf(" [ TEST PKO ] ");
#endif
	printf("\n");
}





void
cvmcs_test_global_init(void)
{
#if  defined(CVMCS_TEST_PKO) || defined(MAX_PACKET_RATE_TEST)
	cvmcs_test_pko_global_init();
#endif
}

