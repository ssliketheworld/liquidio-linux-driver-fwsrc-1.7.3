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
#include "cvmcs-nic.h"
#include "cvmcs-nic-tunnel.h"
#include "cvmcs-nic-switch.h"
#include "cvmcs-dcb.h"

/*
 * 
 * 
 * 
 */
int cvmcs_dcb_get_xfi_interface()
{
	return 0;
}

/*
 *  
 * 
 *
 * 
 */
void cvmcs_dcb_queue_config_pfc_en(int interface)
{
	return;
}

int cvmcs_dcb_dpi_wqe_handler(cvmx_wqe_t *wqe)
{
	return 0;
}

int cvmcs_dcb_gmx_wqe_handler(cvmx_wqe_t *wqe)
{
	return -ENOIF;
}

int cvmcs_dcb_get_dq(cvmx_wqe_t *wqe, int port)
{
	if (octeon_has_feature(OCTEON_FEATURE_CN78XX_WQE))
		return cvmx_pko_get_base_queue_pkoid(port);
	else if (octeon_has_feature(OCTEON_FEATURE_PKND))
		/*CN68XX : get pko_port from ipd_port and pass
		  it */
		return cvmx_pko_get_base_queue_pkoid(cvmx_helper_cfg_ipd2pko_port_base(port));
	else
		return cvmx_pko_get_base_queue(port);
}

void cvmcs_dcb_schedule_qcn_byte_counter(cvmx_wqe_t *wqe,int port,int prio)
{
	return;
}

void cvmcs_dcb_process_qcn(cvmx_wqe_t *wqe)
{
	return;
}

void cvmcs_dcb_get_l2_proto_hlen(cvmx_wqe_t *wqe, uint16_t *l2proto, uint16_t *l2hlen)
{
	struct ethhdr *eth;
	cvmcs_nic_metadata_t *mdata = CVMCS_NIC_METADATA(wqe);

	eth = (struct ethhdr *)CVMCS_NIC_METADATA_PACKET_START(mdata);

	if (eth->h_proto == ETH_P_8021Q){
                struct vlan_hdr *vh = (struct vlan_hdr *)eth;
                mdata->flags |= METADATA_FLAGS_VLAN;
                *l2proto = vh->proto;
                *l2hlen = VLAN_ETH_HLEN;
        } else {
                *l2proto = eth->h_proto;
                *l2hlen = ETH_HLEN;
        }
	
	return;
}

void cvmcs_dcb_insert_cntag(cvmx_wqe_t *wqe)
{
	return;
}

void cvmcs_dcb_strip_cntag(cvmx_wqe_t *wqe)
{
	return;
}

int  cvmcs_dcbx_enable(int port_num)
{
	return 1;
}

void  cvmcs_dcbx_disable(int port_num);
{
	return;
}
