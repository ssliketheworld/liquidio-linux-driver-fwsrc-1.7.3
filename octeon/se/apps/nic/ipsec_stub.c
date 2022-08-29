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

/**
 * \file
 * \brief This module contains the stubbed versions of all IPsec functions.
 */

#include "cvmcs-nic.h"
#include "cvm-nic-ipsec.h"
#include "cvmcs-nic-tso.h"

void cvmcs_nic_ipsec_loopback_port_init(void)
{
}

int cvm_ipsec_offload(cvmx_wqe_t * wqe, int front_size, int ifidx, int opcode)
{
	return -1;
}

int process_ipsec_loopback_pkt(cvmx_wqe_t *wqe)
{
	return -1;
}

int cvmcs_nic_process_ipsec(cvmx_wqe_t *wqe,
			    cvmx_buf_ptr_t *temp_list, int32_t *pkt_size,
			    int16_t gso_segs, uint16_t esp_ah_offset,
			    uint16_t esp_ah_hdrlen, int ifidx)
{
	return -1;
}

int cvmcs_nic_process_ipsec_o3(cvmx_wqe_t *wqe,
                            struct tso_o3_pkt_desc *temp_list, int32_t *pkt_size,
                            int16_t gso_segs, int ifidx) 
{
	return -1;

}

int cvmcs_nic_add_ipsec_tso_info_o3(cvmx_wqe_t *wqe, tso_hdr_info_t *tso_hdr)
{
	return -1;

}

inline int cvmcs_nic_ipsec_get_ah_hdr_len(cvmx_wqe_t *wqe)
{
	return 0;
}

inline int cvmcs_nic_ipsec_get_ah_next_hdr(cvmx_wqe_t *wqe)
{
	return 0;
}

int cvmcs_nic_ipsec_get_esp_hdr_icv_len(cvmx_wqe_t *wqe, int ifidx, uint16_t *hdr_len, uint8_t *icv_len)
{
	return 0;
}

int cvmcs_nic_ipsec_get_esp_next_hdr_pad_len(cvmx_wqe_t *wqe, int ifidx, uint8_t *next_hdr, uint8_t *pad_len)
{
	return 0;
}

int cvm_app_ipsec_setup_memory()
{
	return 0;
}

int cvm_app_ipsec_cap_init()
{
	return 0;
}

#ifdef DELAY_DELETE_SA
void  cvm_ipsec_delete_sa_completion(uint8_t *oct_sa_data)
{
}
#endif //DELAY_DELETE_SA
