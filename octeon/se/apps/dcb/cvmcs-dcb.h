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

#include "cvmx-config.h"
#include "cvmx.h"
#include "cvmx-version.h"
#include "cvmx-error.h"
#include "cvmx-pki-defs.h"
#include "cvmx-pki.h"
#include "cvmx-fpa.h"
#include "cvmx-helper-pki.h"
#include "cvmx-pki-resources.h"
#include "cvmx-pow.h"
#include "cvmx-fpa.h"
#include "cvmx-pko3.h"
#include "cvmx-helper.h"
#include "cvmx-interrupt.h"
#include "cvmx-helper-pko3.h"
#include "cvmx-helper-bgx.h"
#include "cvmx-pko3-resources.h"
#include "cvm-pci-loadstore.h"
#include "liquidio_common_dcb.h"
#include "cvmcs-qcn.h"
#include "cvmcs-dcbx-ieee.h"
#include "cvmcs-dcbx-cee.h"
#include "cvmcs-dcbx.h"

/****PKI Control frames TAG's****/
#define QCN_FRAME_RECEIVED			0x0FFFED4D
#define DCBX_LLDP_FRAME_RECEIVED		0x0FFF8AF1

typedef struct {
	int			ifidx;
        bool                    dcb_enabled;
        bool                	dcbx_offload;
	bool			dcbx_ieee;
	bool			dcbx_cee;	
	dcbx_def_config_t	dcbx_def_cfg;
        dcbx_config_t           dcbx_cfg;
        octeon_qcn_t            qcn;
	uint8_t			l1_queue;
        uint8_t                 l2_base;
        uint8_t                 l3_base;
        bool                    allocated;
}octeon_dcb_t;

#define OCTNIC_DCB_FIELDS	\
        octeon_dcb_t dcb[MAX_OCTEON_GMX_PORTS];

/******** Functions*********/
int cvmcs_dcb_pki_configure(int mode, int port_num);

/*********PFC Functions*********/
void cvmcs_dcb_disable_pfc(int port_num);

/*********PKO Functions*********/
int cvmcs_dcb_get_xfi_interface();
void cvmcs_dcb_queue_config_pfc_en(int interface);
int cvmcs_dcb_init_pko(int port);
int cvmcs_dcb_ets_disable(int port_num);
uint8_t cvmcs_dcb_pfc_config (uint8_t , uint8_t , uint8_t );
uint8_t cvmcs_dcb_ets_config(uint8_t , uint8_t *, uint8_t *, uint8_t *);

/********* QCN_DCBX function ********/
int cvmcs_dcb_dpi_wqe_handler(cvmx_wqe_t *wqe);
int cvmcs_dcb_gmx_wqe_handler(cvmx_wqe_t *wqe);

/********* QCN function ********/
void cvmcs_dcb_schedule_qcn_byte_counter(cvmx_wqe_t *wqe,int port,int prio);
void cvmcs_dcb_process_qcn(cvmx_wqe_t *wqe);
void cvmcs_dcb_get_l2_proto_hlen(cvmx_wqe_t *wqe, uint16_t *l2proto, uint16_t *l2hlen);
void cvmcs_dcb_insert_cntag(cvmx_wqe_t *wqe);
void cvmcs_dcb_strip_cntag(cvmx_wqe_t *wqe);
void cvmcs_dcb_qcn_reconfig(cn_tlv_t *cn_tlv, int port_no);

/*************Helper functions*******/
int cvmcs_dcb_get_dq(cvmx_wqe_t *wqe, int port);

#endif /* __CVMCS_DCB_H__ */
