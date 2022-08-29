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

#ifndef __CVMCS_DCB_H__
#define __CVMCS_DCB_H__

#define	OCTNIC_DCB_FIELDS	

int cvmcs_dcb_get_xfi_interface();
void cvmcs_dcb_queue_config_pfc_en(int interface);
int cvmcs_dcb_dpi_wqe_handler(cvmx_wqe_t *wqe);
int cvmcs_dcb_gmx_wqe_handler(cvmx_wqe_t *wqe);
int cvmcs_dcb_get_dq(cvmx_wqe_t *wqe, int port);
void cvmcs_dcb_schedule_qcn_byte_counter(cvmx_wqe_t *wqe,int port,int prio);
void cvmcs_dcb_process_qcn(cvmx_wqe_t *wqe);
void cvmcs_dcb_get_l2_proto_hlen(cvmx_wqe_t *wqe, uint16_t *l2proto, uint16_t *l2hlen);
void cvmcs_dcb_insert_cntag(cvmx_wqe_t *wqe);
void cvmcs_dcb_strip_cntag(cvmx_wqe_t *wqe);
int  cvmcs_dcbx_enable(int ifidx);
void  cvmcs_dcbx_disable(int ifidx);

#endif /* __CVMCS_DCB_H__ */
