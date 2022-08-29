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

#include "cvmcs-common.h"
#include "cvmcs-nic.h"

/*Prototype Functions */
extern CVMX_SHARED octnic_dev_t	*octnic;
extern CVMX_SHARED cvm_oct_dev_t *oct;

/**  DCBx Asymmetric state machine
 *
 * @param port_num	physical port number
 *
 */
void  cvmcs_dcbx_ieee_asymmetric_st_machine(uint8_t port_num)
{
	struct dcbx_ieee_config *dcbx_ieee =
		 &octnic->dcb[port_num].dcbx_cfg.dcbx_ieee;
	ieee_ets_cfg_t *local_param = &dcbx_ieee->local_port.ets_config;
	ieee_ets_recmd_cfg_t *remote_param = &dcbx_ieee->remote_port.ets_recmnd;
	struct as_port_config *oper_param = &dcbx_ieee->oper_port.ets_config;

	if ((!local_param->willing) ||
	    (!(dcbx_ieee->ets_flag & REMOTE_PARAM_CHANGE))) {
		dcbx_ieee->ets_flag |= OPER_PARAM_CHANGE;
		oper_param->max_tcs = local_param->max_tcs;
		oper_param->cbs = 0;
		memcpy(oper_param->prio_assign_table,
		       local_param->prio_assign_table,
		       IEEE_8021QAZ_MAX_TCS);
		memcpy(oper_param->tc_bw_table,
		       local_param->tc_bw_table,
		       IEEE_8021QAZ_MAX_TCS);
		memcpy(oper_param->tsa_assign_table,
		       local_param->tsa_assign_table,
		       IEEE_8021QAZ_MAX_TCS);

	} else if (local_param->willing &&
	    	   (dcbx_ieee->ets_flag & REMOTE_PARAM_CHANGE)) {
		dcbx_ieee->ets_flag |= OPER_PARAM_CHANGE;
		oper_param->max_tcs = octnic->dcb[port_num].
			dcbx_def_cfg.dcbx_ieee.ets_config.num_traffic_classes;
		oper_param->cbs = 0;
		memcpy(oper_param->prio_assign_table,
		       remote_param->prio_assign_table,
		       IEEE_8021QAZ_MAX_TCS);
		memcpy(oper_param->tc_bw_table,
		       remote_param->tc_bw_table,
		       IEEE_8021QAZ_MAX_TCS);
		memcpy(oper_param->tsa_assign_table,
		       remote_param->tsa_assign_table,
		       IEEE_8021QAZ_MAX_TCS);
	}

	return;
}

/**  DCBx symmetric state machine
 *
 * @param port_num	physical port number
 *
 */
void  cvmcs_dcbx_ieee_symmetric_st_machine(uint8_t port_num)
{
	struct dcbx_ieee_config *dcbx_ieee =
		 &octnic->dcb[port_num].dcbx_cfg.dcbx_ieee;
	ieee_pfc_cfg_t *local_param = &dcbx_ieee->local_port.pfc_config;
	ieee_pfc_cfg_t *remote_param = &dcbx_ieee->remote_port.pfc_config;
	struct sy_port_config *oper_param = &dcbx_ieee->oper_port.pfc_config;
	uint64_t local_mac = dcbx_ieee->local_port.port_addr;
	uint64_t remote_mac = dcbx_ieee->remote_port.port_addr;

	if ((!local_param->willing) ||
	    (!(dcbx_ieee->pfc_flag & REMOTE_PARAM_CHANGE)) ||
	   (local_param->willing && remote_param->willing && (local_mac < remote_mac))) {
		dcbx_ieee->pfc_flag |= OPER_PARAM_CHANGE ;
		oper_param->mbc = local_param->mbc;
		oper_param->pfc_cap = local_param->pfc_cap;
		oper_param->pfc_enable = local_param->pfc_enable;
	}
	else if (local_param->willing &&
	        (dcbx_ieee->pfc_flag & REMOTE_PARAM_CHANGE) &&
		(!remote_param->willing || (remote_param->willing && (local_mac > remote_mac)))) {
		dcbx_ieee->pfc_flag |= OPER_PARAM_CHANGE ;
		oper_param->mbc = remote_param->mbc;
		oper_param->pfc_cap = remote_param->pfc_cap;
		oper_param->pfc_enable = remote_param->pfc_enable;
	}
}

/**  Construct  IEEE DCBx LLDP frame
 *
 * @param port_num	physical port number
 * @param *port		pointer to lldp_sm_attr_t
 *
  * @return Returns 0 on success, 1 on error.
 */
uint8_t cvmcs_dcbx_ieee_mib_constr_info_lldpdu(uint8_t port_num,
						lldp_sm_attr_t *port )
{
	struct dcbx_ieee_config *dcbx_ieee =
		 &octnic->dcb[port_num].dcbx_cfg.dcbx_ieee;
	uint16_t  size=0, frame_size = 0 ;
	void *tlv_offset=NULL;
	struct default_tlvs 	*d_tlv;
	struct as_port_config 	*ets_operparam;
	struct sy_port_config 	*pfc_operparam;
	ieee_app_prio_cfg_t 	*app_localparam;
	struct ets_config_tlv 	*ets;
	struct pfc_config_tlv 	*pfc;
	struct app_priority_tlv *app;

	cvmx_spinlock_lock(&octnic->dcb[port_num].dcbx_cfg.lock);

	ets_operparam = &dcbx_ieee->oper_port.ets_config;
	pfc_operparam = &dcbx_ieee->oper_port.pfc_config;
	app_localparam = &dcbx_ieee->local_port.app_config;

	/* total size of LLDP frame */
	size = ETHER_HDR_LENGTH;
	size += CHASSIS_ID_TLV_LENGTH + TLV_HDDR_LENGTH;
	size += PORT_ID_TLV_LENGTH + TLV_HDDR_LENGTH;
	size += TTL_TLV_LENGTH + TLV_HDDR_LENGTH;
	size += END_OF_LLDP_SIZE;
	size += ETS_CONFIG_TLV_LENGTH + TLV_HDDR_LENGTH;
	size += PFC_CONFIG_TLV_LENGTH + TLV_HDDR_LENGTH;
	size += APP_CONFIG_TLV_LENGTH(app_localparam->num_prio) + TLV_HDDR_LENGTH;

	if (size < MIN_ETH_SIZE )
		frame_size = MIN_ETH_SIZE;
	else
		frame_size = size;

        if (port->tx.frameout == NULL) {
                port->tx.frameout = cvmx_fpa_alloc(CVMX_FPA_PACKET_POOL);
                if(port->tx.frameout == NULL)
                {
			cvmx_spinlock_unlock(&octnic->dcb[port_num].dcbx_cfg.lock);
                        printf(" Error5: failed to allocate memory to LLDP frame\n");
                        return 1;
                }
        }

	tlv_offset = (uint8_t *)port->tx.frameout;

	memset(tlv_offset, 0, size);

	port->tx.sizeout = frame_size;

	/* Add Ether header */
	memcpy(tlv_offset,
	       &octnic->dcb[port_num].dcbx_cfg.eth_hddr,
	       ETHER_HDR_LENGTH);

	tlv_offset += ETHER_HDR_LENGTH;

 	/*write mandatoryTLV's */
	d_tlv = &octnic->dcb[port_num].dcbx_cfg.default_tlv;

	memcpy (tlv_offset, &d_tlv->chassis_id, CHASSIS_ID_TLV_LENGTH +
							TLV_HDDR_LENGTH);
	tlv_offset += CHASSIS_ID_TLV_LENGTH +  TLV_HDDR_LENGTH;

	memcpy (tlv_offset, &d_tlv->port_id, PORT_ID_TLV_LENGTH +
							TLV_HDDR_LENGTH);
	tlv_offset += PORT_ID_TLV_LENGTH + TLV_HDDR_LENGTH;

	d_tlv->ttl.ttl = port->tx.tx_ttl;
	memcpy (tlv_offset, &d_tlv->ttl, TTL_TLV_LENGTH + TLV_HDDR_LENGTH);
  	tlv_offset += TTL_TLV_LENGTH + TLV_HDDR_LENGTH;

	/* Write ORGANIZATIONALLY SPECIFIC TLV */
	ets = (struct ets_config_tlv *)tlv_offset;
	/*initializing & write ETS config tlv */
	ets->type 	= ORGANIZATIONALLY_SPECIFIC_TLV_TYPE;
	ets->length 	= ETS_CONFIG_TLV_LENGTH;
	ets->oui[0] 	= OUI_0;
	ets->oui[1] 	= OUI_1;
	ets->oui[2] 	= OUI_2;
	ets->subtype	= ETS_CONFIGURATION;
	ets->willing 	= dcbx_ieee->local_port.ets_config.willing;
	ets->cbs 	= ets_operparam->cbs;

	if (ets_operparam->max_tcs == IEEE_8021QAZ_MAX_TCS)
		ets->max_tcs = 0;	//max_tc is 3 bit field so '0' means TC's
	else
		ets->max_tcs = ets_operparam->max_tcs;

	/* pack  & write  prio assign table */
	cvmcs_dcbx_ieee_pack_store_prio_assign_tbl(
					ets_operparam->prio_assign_table,
					ets->prio_assign_table);

	/* write bandwidth table & tsa asign table */
	memcpy(ets->tc_bw_table, ets_operparam->tc_bw_table, IEEE_8021QAZ_MAX_TCS);
	memcpy(ets->tsa_assign_table, ets_operparam->tsa_assign_table, IEEE_8021QAZ_MAX_TCS);
	memcpy(tlv_offset, ets, ETS_CONFIG_TLV_LENGTH + TLV_HDDR_LENGTH);
	tlv_offset +=  ETS_CONFIG_TLV_LENGTH + TLV_HDDR_LENGTH;

	/*initializing & write PFC config tlv */
	pfc = (struct pfc_config_tlv *)tlv_offset;
	pfc->type 		= ORGANIZATIONALLY_SPECIFIC_TLV_TYPE;
	pfc->length 		= PFC_CONFIG_TLV_LENGTH;
	pfc->oui[0] 		= OUI_0;
	pfc->oui[1] 		= OUI_1;
	pfc->oui[2] 		= OUI_2;
	pfc->subtype 		= PFC_CONFIGURATION;
	pfc->willing 		= dcbx_ieee->local_port.pfc_config.willing;
	pfc->mbc 		= pfc_operparam->mbc;
	pfc->pfc_cap 		= pfc_operparam->pfc_cap;
	pfc->pfc_enable 	= pfc_operparam->pfc_enable;
	memcpy(tlv_offset, pfc, PFC_CONFIG_TLV_LENGTH + TLV_HDDR_LENGTH);
	tlv_offset 		+= PFC_CONFIG_TLV_LENGTH + TLV_HDDR_LENGTH;

	/*initializing & write APP config tlv */
	app = (struct app_priority_tlv *)tlv_offset;
	app->type 		= ORGANIZATIONALLY_SPECIFIC_TLV_TYPE;
	app->length 		= APP_CONFIG_TLV_LENGTH(app_localparam->num_prio);
	app->oui[0] 		= OUI_0;
	app->oui[1] 		= OUI_1;
	app->oui[2] 		= OUI_2;
	app->subtype 		= APPLICATION_PRIORITY;
	memcpy(app->priority_table,
	       app_localparam->priority_table,
	       app_localparam->num_prio * sizeof(struct packed_app_prio_table));
	memcpy(tlv_offset, app, app->length + TLV_HDDR_LENGTH);
	tlv_offset 		+= app->length + TLV_HDDR_LENGTH;

	cvmx_spinlock_unlock(&octnic->dcb[port_num].dcbx_cfg.lock);

	/* Write End_of_lldp_tlv */
	memcpy(tlv_offset, (void *)&d_tlv->endof_lldp, END_OF_LLDP_SIZE);
	return 0;
}

/**  Indicated the RX  LLDP state machine about new frame received
 *
 * @param port_num	physical port number	
 * @param *wqe			work queue entry
 *
 * @return Returns 0 on success, 1 on error.
 */
uint8_t  cvmcs_dcbx_ieee_rx_frame (uint8_t port_num, cvmx_wqe_t  *wqe)
{
	lldp_sm_attr_t *port = &octnic->dcb[port_num].dcbx_cfg.port;

	/* TODO : Handle multiple peer LLDP ports case */

	//lock: providing sync for 2 instance of received_lldp for 'temp_framein' resource

	cvmx_spinlock_lock(&octnic->dcb[port_num].dcbx_cfg.lock);
	if (port->rx.temp_framein != NULL ) {
		cvm_free_wqe_wrapper(port->rx.temp_framein);
		port->rx.temp_framein = NULL;
	}
	port->rx.temp_framein = wqe;
	//unlock
	cvmx_spinlock_unlock(&octnic->dcb[port_num].dcbx_cfg.lock);

	if ((port->rx.framein == NULL) && (port->rx.temp_framein)) {
		//lock to update framein with temp_framein.
		cvmx_spinlock_lock(&octnic->dcb[port_num].dcbx_cfg.lock);
		port->rx.framein = port->rx.temp_framein;
		port->rx.temp_framein = NULL;
		cvmx_atomic_set32(&port->rx.rcv_frame, TRUE);
		//unlock
		cvmx_spinlock_unlock(&octnic->dcb[port_num].dcbx_cfg.lock);
	}

	return 0;
}


/**  Received shutdown LLDP
 *
 * @param port_num	physical port number
 */
void cvmcs_dcbx_ieee_rx_shutdown(uint8_t port_num)
{
	struct dcbx_ieee_config *dcbx_ieee;
	struct as_port_config  	*ets_config;
	struct sy_port_config  	*pfc_config;

	dcbx_ieee = &octnic->dcb[port_num].dcbx_cfg.dcbx_ieee;

	cvmx_spinlock_lock(&octnic->dcb[port_num].dcbx_cfg.lock);

	dcbx_ieee->ets_flag = 0;

	/*Run asymmetric(ETS) state machine */
	cvmcs_dcbx_ieee_asymmetric_st_machine(port_num);
	dcbx_ieee->ets_flag |= REMOTE_PARAM_SHUTDOWN;

	/* Configure ETS queues */
	ets_config = &(dcbx_ieee->oper_port.ets_config);
	if (cvmcs_dcb_ets_config(port_num,
				ets_config->prio_assign_table,
				ets_config->tc_bw_table,
				ets_config->tsa_assign_table))
	{
		printf("Error3:In dcbx_set_default_configure \n");
		cvmx_spinlock_unlock(&octnic->dcb[port_num].dcbx_cfg.lock);
		return;
	}

	dcbx_ieee->pfc_flag = 0;

	/*Run symmetric(PFC) state machine */
	cvmcs_dcbx_ieee_symmetric_st_machine(port_num);
	dcbx_ieee->pfc_flag |= REMOTE_PARAM_SHUTDOWN;

	/* Configure Priority queues for PFC*/
	pfc_config = &(dcbx_ieee->oper_port.pfc_config);
	if (cvmcs_dcb_pfc_config(port_num,
		pfc_config->pfc_enable,
		pfc_config->pfc_cap))
	{
		printf("Error4: In  dcbx_set_default_configure \n");
        	cvmcs_dcb_ets_disable(port_num);
		cvmx_spinlock_unlock(&octnic->dcb[port_num].dcbx_cfg.lock);
		return;
	}

	dcbx_ieee->app_flag |= REMOTE_PARAM_SHUTDOWN;

	cvmx_atomic_set32((int32_t *)&octnic->dcb[port_num].dcbx_cfg.port.tx.local_change, (int32_t)1);

	cvmcs_dcbx_param_indication(port_num);

	cvmx_spinlock_unlock(&octnic->dcb[port_num].dcbx_cfg.lock);

	return  ;
}

void cvmcs_dcbx_ieee_something_changed_remote(uint8_t port_num, lldp_sm_attr_t *port)
{
	struct as_port_config  	*ets_config;
	struct sy_port_config   *pfc_config;
	uint8_t local_change = False;

	cvmx_spinlock_lock(&octnic->dcb[port_num].dcbx_cfg.lock);

	octnic->dcb[port_num].dcbx_cfg.dcbx_ieee.ets_flag = 0;

	/* Run asymmetric state machine */
	cvmcs_dcbx_ieee_asymmetric_st_machine(port_num);

	if (octnic->dcb[port_num].dcbx_cfg.dcbx_ieee.ets_flag & OPER_PARAM_CHANGE)
	{
		ets_config = &octnic->dcb[port_num].dcbx_cfg.dcbx_ieee.
					oper_port.ets_config;
		if (cvmcs_dcb_ets_config(port_num,
					ets_config->prio_assign_table,
					ets_config->tc_bw_table,
					ets_config->tsa_assign_table))
			printf("Error: In  cvmcs_dcbx_ieee_asymmetric_st_machine \n");

		local_change = True;
	}
	
	octnic->dcb[port_num].dcbx_cfg.dcbx_ieee.pfc_flag = 0;

	cvmcs_dcbx_ieee_symmetric_st_machine(port_num);

	if (octnic->dcb[port_num].dcbx_cfg.dcbx_ieee.pfc_flag & OPER_PARAM_CHANGE) {
		pfc_config = &octnic->dcb[port_num].dcbx_cfg.dcbx_ieee.
					oper_port.pfc_config;
		if (cvmcs_dcb_pfc_config(port_num,
				pfc_config->pfc_enable,
				pfc_config->pfc_cap))
			printf("Error: Error: In %s \n", __func__);

		local_change = True;
	}

	if (local_change)
		cvmx_atomic_set32((int32_t *)&port->tx.local_change, (int32_t)local_change);

	cvmcs_dcbx_param_indication(port_num);

	cvmx_spinlock_unlock(&octnic->dcb[port_num].dcbx_cfg.lock);
}

/** Deletes the last received cfg of remote peer
 *
 * @param port_num physical port number
 * @param port		lldp_sm_attr_t variable address
 *
 */
uint8_t cvmcs_dcbx_ieee_mib_delete_objects(uint8_t port_num,
					 lldp_sm_attr_t *port)
{
	dcbx_config_t 		*dcbx ;
	struct lldp_port 	*remote_port;

	dcbx 		= &octnic->dcb[port_num].dcbx_cfg;
	remote_port 	= &dcbx->dcbx_ieee.remote_port;

	memset(remote_port, 0, sizeof(struct lldp_port));

	return 0;
}

/** Fetch current dcbx configuration and fill 'struct octeon_dcbx_config'
 *
 * @param port_num		physical port number
 * @param current_dcbx_info	struct oct_nic_dcbx_info object address 
 *
 */
void cvmcs_dcbx_ieee_current_param(uint8_t port_num,
		struct oct_nic_dcbx_info *current_dcbx_info)
{
	struct dcbx_ieee_config	*ieee_dcbx_cfg;
	ieee_ets_recmd_cfg_t	*rcvd_ets_rcmnd;
	ieee_pfc_cfg_t	 	*rcvd_pfc;
	ieee_app_prio_cfg_t 	*rcvd_app;
	struct as_port_config	*ets_operparam;
	struct sy_port_config	*pfc_operparam;
	struct oct_nic_dcbx_config *remote_dcbx_cfg = &current_dcbx_info->remote;
	struct oct_nic_dcbx_config *oper_dcbx_cfg = &current_dcbx_info->operational;
	uint8_t i=0;

	ieee_dcbx_cfg 	= &octnic->dcb[port_num].dcbx_cfg.dcbx_ieee;
	rcvd_ets_rcmnd 	= &ieee_dcbx_cfg->remote_port.ets_recmnd;
	rcvd_pfc	= &ieee_dcbx_cfg->remote_port.pfc_config;
	ets_operparam 	= &ieee_dcbx_cfg->oper_port.ets_config;
	pfc_operparam 	= &ieee_dcbx_cfg->oper_port.pfc_config;
	rcvd_app 	= &ieee_dcbx_cfg->remote_port.app_config;

	current_dcbx_info->dcbx_version = DCBX_IEEE;

	if (ieee_dcbx_cfg->pfc_flag & REMOTE_PARAM_CHANGE)
	{		
		current_dcbx_info->flags |= DCB_FLAG_REMOTE_PFC;
		remote_dcbx_cfg->pfc_config.pfc_capability	= rcvd_pfc->pfc_cap;
		remote_dcbx_cfg->pfc_config.pfc_enable 		= rcvd_pfc->pfc_enable;
		remote_dcbx_cfg->pfc_config.mbc 		= rcvd_pfc->mbc;
		if (rcvd_pfc->willing)
			remote_dcbx_cfg->pfc_config.pfc_flags |= DCBX_FLAG_WILLING;
	}

	if (ieee_dcbx_cfg->pfc_flag & OPER_PARAM_CHANGE)
	{
		current_dcbx_info->flags |= DCB_FLAG_OPER_PFC;
		oper_dcbx_cfg->pfc_config.pfc_capability = pfc_operparam->pfc_cap;
		oper_dcbx_cfg->pfc_config.pfc_enable = pfc_operparam->pfc_enable;
		oper_dcbx_cfg->pfc_config.mbc = pfc_operparam->mbc;
		if (ieee_dcbx_cfg->local_port.pfc_config.willing)
			oper_dcbx_cfg->pfc_config.pfc_flags |= DCBX_FLAG_WILLING;
	}

	if (ieee_dcbx_cfg->ets_flag & REMOTE_PARAM_CHANGE)
	{
		current_dcbx_info->flags |= DCB_FLAG_REMOTE_ETS;
		remote_dcbx_cfg->ets_config.num_traffic_classes = octnic->dcb[port_num].dcbx_def_cfg.dcbx_ieee.ets_config.num_traffic_classes;
		memcpy(&remote_dcbx_cfg->ets_config.ieee.tc_bandwidth_assignment_table,
			&rcvd_ets_rcmnd->tc_bw_table, IEEE_8021QAZ_MAX_TCS);
		memcpy(&remote_dcbx_cfg->ets_config.ieee.priority_assignment_table,
			&rcvd_ets_rcmnd->prio_assign_table, IEEE_8021QAZ_MAX_TCS);
		memcpy(&remote_dcbx_cfg->ets_config.ieee.tsa_assignment_table,
			&rcvd_ets_rcmnd->tsa_assign_table, IEEE_8021QAZ_MAX_TCS);
	}

	if (ieee_dcbx_cfg->ets_flag & OPER_PARAM_CHANGE) 
	{
		current_dcbx_info->flags |= DCB_FLAG_OPER_ETS;
		if (ieee_dcbx_cfg->local_port.ets_config.willing)
			oper_dcbx_cfg->ets_config.ets_flags |= DCBX_FLAG_WILLING;
		oper_dcbx_cfg->ets_config.num_traffic_classes = ets_operparam->max_tcs;
		oper_dcbx_cfg->ets_config.ieee.cbs = ets_operparam->cbs;
		memcpy(&oper_dcbx_cfg->ets_config.ieee.tc_bandwidth_assignment_table,
				&ets_operparam->tc_bw_table,
				IEEE_8021QAZ_MAX_TCS);
		memcpy(&oper_dcbx_cfg->ets_config.ieee.priority_assignment_table,
				&ets_operparam->prio_assign_table,
				IEEE_8021QAZ_MAX_TCS);
		memcpy(&oper_dcbx_cfg->ets_config.ieee.tsa_assignment_table,
				&ets_operparam->tsa_assign_table,
				IEEE_8021QAZ_MAX_TCS);
	}

	if (ieee_dcbx_cfg->app_flag & REMOTE_PARAM_CHANGE) {
		current_dcbx_info->flags |= DCB_FLAG_REMOTE_APP;
		remote_dcbx_cfg->app_config.num_app_prio = rcvd_app->num_prio;
		for(i=0; i<remote_dcbx_cfg->app_config.num_app_prio; i++)
		{
			remote_dcbx_cfg->app_config.app_prio[i].selector = 
				rcvd_app->priority_table[i].sel; 
			remote_dcbx_cfg->app_config.app_prio[i].priority = 
				rcvd_app->priority_table[i].priority;
			remote_dcbx_cfg->app_config.app_prio[i].protocol_id 
				= rcvd_app->priority_table[i].protocol_id;
		}
	}

	if ((ieee_dcbx_cfg->ets_flag & REMOTE_PARAM_SHUTDOWN) ||
	    (ieee_dcbx_cfg->pfc_flag & REMOTE_PARAM_SHUTDOWN) ||
	    (ieee_dcbx_cfg->app_flag & REMOTE_PARAM_SHUTDOWN)) {
		current_dcbx_info->flags |= DCB_FLAG_REMOTE_SHUTDOWN;
	}

	ieee_dcbx_cfg->ets_flag = 0;
	ieee_dcbx_cfg->pfc_flag = 0;
	ieee_dcbx_cfg->app_flag = 0;
}

/** Validates the received LLDP frame & check for duplicate frame
 *
 * @param port_num	physical port number
 * @param rcv_wqe	work queue entry 	
 *
 * @return Returns 0 on success, 1 on error.
 */
uint8_t cvmcs_dcbx_ieee_validate_duplicate_detection_frame(uint8_t port_num, cvmx_wqe_t *rcv_wqe)
{
	int ets_config_tlv_count = 0, ets_recmnd_tlv_count = 0,
	    pfc_tlv_count = 0, ttl_tlv_count = 0, congestion_tlv_count = 0, i, 
	    total_bw = 0, dup = 1;
	uint8_t *frame	= (uint8_t *)cvmx_phys_to_ptr(rcv_wqe->packet_ptr.s.addr);
	uint8_t *tlv_offset 	=  frame;
	ieee_ets_cfg_t 		ets_cfg;
	ieee_ets_recmd_cfg_t	ets_recmnd;
	ieee_pfc_cfg_t		pfc_cfg;
	ieee_app_prio_cfg_t  	app_config;
	uint8_t *read;
	uint16_t  tlv_length 	= 0,  tlv_type ;
	uint8_t subtype;
	struct ttl_tlv		*rcv_ttl	= NULL;
	struct ets_config_tlv 	*rcv_ets 	= NULL;
	struct ets_recmnd_tlv 	*rcv_ets_rcmnd 	= NULL;
	struct pfc_config_tlv 	*rcv_pfc 	= NULL;
	tlv_hdr_t 		*tlv_hdr 	= NULL;
	struct app_priority_tlv	*rcv_app	= NULL;

	lldp_sm_attr_t *port = &octnic->dcb[port_num].dcbx_cfg.port;
	
	tlv_offset += 14;
	while(1)
	{
		read = tlv_offset;
		tlv_type = 0;
		tlv_length = 0;

		/* read type & length */
		tlv_hdr 	= (tlv_hdr_t *)tlv_offset;
		tlv_type 	= tlv_hdr->type;
		tlv_length 	= tlv_hdr->length;

		if (tlv_type == 0)
		{
			//End of LLDP.
			if ((ttl_tlv_count > 1) || (ets_config_tlv_count > 1) ||
				(ets_recmnd_tlv_count > 1) ||(congestion_tlv_count > 1) ||
				(pfc_tlv_count > 1)) {
				printf("Frame validation failed:tlv count \n");
				return 1;
			}
			break;	// break the while loop
		}

		/* validate mandatory tlvs */
		if (tlv_type == TTL_TLV_TYPE) {
			if (tlv_length == TTL_TLV_LENGTH) {
				ttl_tlv_count++;
			}
			rcv_ttl = (struct ttl_tlv *) tlv_offset;
			tlv_offset += (tlv_length + TLV_HDDR_LENGTH);
		}else if (tlv_type == ORGANIZATIONALLY_SPECIFIC_TLV_TYPE) {
			read += TLV_HEADER_LENGTH;
			read += OUI_LENGTH;
			subtype = (uint8_t)*read;
			read += SUB_TYPE_LENGTH;
			switch(subtype)
			{
				case ETS_CONFIGURATION:
					ets_config_tlv_count++;
					rcv_ets = (struct ets_config_tlv *)tlv_offset;
					break;

				case ETS_RECOMMENDATION:
					ets_recmnd_tlv_count++;
					rcv_ets_rcmnd = (struct ets_recmnd_tlv *)tlv_offset;
					if (rcv_ets_rcmnd->length != ETS_RECMND_TLV_LENGTH) {
						printf("Validation Ignored frame:ets rcmnd len\n");
						return 1;
					}

					total_bw = 0;
					for(i = 0; i < IEEE_8021QAZ_MAX_TCS ; i++) {
						total_bw += rcv_ets_rcmnd->tc_bw_table[i];
					}
					if (total_bw != 100) {
						printf("Validation ingnored frame:Total bw =%d \n", total_bw);
						return 1;
					}
					break;

				case PFC_CONFIGURATION:
					pfc_tlv_count++;
					rcv_pfc = (struct pfc_config_tlv *)tlv_offset;
					break;

				case APPLICATION_PRIORITY:
					/* app priority not supported */
					rcv_app = (struct app_priority_tlv *)tlv_offset;
					break;

				case CONGESTION_TLV_SUBTYPE:
					congestion_tlv_count++;
					break;
			}

			tlv_offset += tlv_length + TLV_HEADER_LENGTH;
		}
		else {
			/* Not an ORG TLV, skip this tlv */
			tlv_offset += tlv_length + TLV_HEADER_LENGTH;
		}
	}// end of while loop

	/* Update rxttl value*/
	cvmcs_dcbx_read_ttl_tlv(rcv_ttl, port );
	if (congestion_tlv_count == 1)
		return 0;

	if (octnic->dcb[port_num].dcbx_cfg.remote_enabled) {
		/* Duplicate detection of received frame */
		memset(&ets_cfg, 0, sizeof(ieee_ets_cfg_t));
		memset(&ets_recmnd, 0, sizeof(ieee_ets_recmd_cfg_t));
		memset(&pfc_cfg, 0, sizeof(ieee_pfc_cfg_t));
		memset(&app_config, 0, sizeof(ieee_app_prio_cfg_t));
		if (rcv_ets) {
			ets_cfg.willing = rcv_ets->willing;
			ets_cfg.cbs = rcv_ets->cbs;
			if (rcv_ets->max_tcs == 0)
				ets_cfg.max_tcs = 8;
			else
				ets_cfg.max_tcs = rcv_ets->max_tcs;
			/* unpack & store prio assign table */
			cvmcs_dcbx_ieee_unpack_prio_assign_tbl(
					rcv_ets->prio_assign_table,
					ets_cfg.prio_assign_table);
			
			memcpy(ets_cfg.tc_bw_table, rcv_ets->tc_bw_table, 
					sizeof(rcv_ets->tc_bw_table));
			memcpy(ets_cfg.tsa_assign_table, rcv_ets->tsa_assign_table,
					sizeof(rcv_ets->tsa_assign_table));
			if (!memcmp(&ets_cfg,
				&octnic->dcb[port_num].dcbx_cfg.dcbx_ieee.remote_port.ets_config,
				sizeof(ets_cfg))) {
				//duplicate
			} else {
				//Not duplicate
				dup = 0;
			}
			
		}

		if (rcv_ets_rcmnd != NULL) {
			/* unpack & store prio assign table */
			cvmcs_dcbx_ieee_unpack_prio_assign_tbl(
					rcv_ets_rcmnd->prio_assign_table,
					ets_recmnd.prio_assign_table);

			memcpy(ets_recmnd.tc_bw_table, rcv_ets_rcmnd->tc_bw_table,
					sizeof(rcv_ets_rcmnd->tc_bw_table));
			memcpy(ets_recmnd.tsa_assign_table, rcv_ets_rcmnd->tsa_assign_table,
					sizeof(rcv_ets_rcmnd->tsa_assign_table));
			if (!memcmp(&ets_recmnd,
				&octnic->dcb[port_num].dcbx_cfg.dcbx_ieee.remote_port.ets_recmnd,
				sizeof(ets_recmnd))) {
				//duplicate
			}else
			{
				// Non duplicate
				dup = 0;
			}
		}
		if (rcv_pfc != NULL) {
			pfc_cfg.willing = rcv_pfc->willing;
			pfc_cfg.mbc = rcv_pfc->mbc;
			pfc_cfg.pfc_cap = rcv_pfc->pfc_cap;
			pfc_cfg.pfc_enable = rcv_pfc->pfc_enable;
			if (!memcmp(&pfc_cfg,
				&octnic->dcb[port_num].dcbx_cfg.dcbx_ieee.remote_port.pfc_config,
				sizeof(pfc_cfg))) {
				//duplicate
			}else
			{
				// Non duplicate
				dup = 0;
			}
		}
		if (rcv_app) {

			app_config.num_prio = (((rcv_app->length)-5)/3);
			memcpy(app_config.priority_table,
			       rcv_app->priority_table,
			       app_config.num_prio * 3);

			if (app_config.num_prio != octnic->dcb[port_num].dcbx_cfg.
					dcbx_ieee.remote_port.app_config.num_prio){
				//not duplicate
				dup = 0;
			}
			else {
				if (!memcmp(&app_config.priority_table,
					octnic->dcb[port_num].dcbx_cfg.dcbx_ieee.
						remote_port.app_config.priority_table,
					(app_config.num_prio *3))) {
				 	//duplicate
				}else {
					//Not duplicate
					dup = 0;
				}
			}
				
		}
		return dup;
	}
	else
		octnic->dcb[port_num].dcbx_cfg.remote_enabled = TRUE;
	return 0;
}

/** Process the received frame
 *
 * @param port_num	 physical port number
 * @param port		 lldp_sm_attr_t variable
 *
 */
uint8_t  cvmcs_dcbx_ieee_rx_process_frame(uint8_t port_num, lldp_sm_attr_t * port)
{
	cvmx_wqe_t *rcv_wqe 	= port->rx.framein;
  	uint8_t *frame 		= (uint8_t *)cvmx_phys_to_ptr(rcv_wqe->packet_ptr.s.addr);
  	uint8_t *tlv_offset 	=  frame;
	uint8_t *read;
	uint8_t local_change 	= 0;
	tlv_hdr_t *tlv_hdr 	= NULL;
  	uint16_t  tlv_length 	= 0, tlv_type;
	uint8_t subtype;
	struct ets_config_tlv 	*rcv_ets 	= NULL;
	struct ets_recmnd_tlv 	*rcv_ets_rcmnd 	= NULL;
	struct pfc_config_tlv 	*rcv_pfc 	= NULL;
	struct app_priority_tlv	*rcv_app	= NULL;
	uint16_t 		 ttl;
	struct lldp_port 	*remote_port;
	struct dcbx_ieee_config *ieee_dcbx_cfg;

	ieee_dcbx_cfg   = &octnic->dcb[port_num].dcbx_cfg.dcbx_ieee;

	remote_port = &ieee_dcbx_cfg->remote_port;

	if (cvmcs_dcbx_ieee_validate_duplicate_detection_frame(port_num, rcv_wqe)) {
		DBG("Validation & duplicate detection is ignored recvd LLDP frame \n");
		return 1;
	}

	cvmx_spinlock_lock(&octnic->dcb[port_num].dcbx_cfg.lock);

	memset(remote_port, 0, sizeof(struct lldp_port));

	memcpy(((uint8_t *)(&remote_port->port_addr) + 2),
  	       ((struct ethernet_header *)frame)->source_addr, 6);

	tlv_offset += 14;

	while(1) {
		read = tlv_offset;
		tlv_type = 0;
		tlv_length =0;

		/* read type & length */
		tlv_hdr 	= (tlv_hdr_t *)tlv_offset;
		tlv_type 	= tlv_hdr->type;
		tlv_length 	= tlv_hdr->length;
		if (tlv_type == 0) {
			/* End of LLDP.*/
			break;	// break the while loop
		}

		/* Read mandatory tlvs */
		if ((tlv_type == CHASSIS_ID_TLV_TYPE)||
			(tlv_type == PORT_ID_TLV_TYPE) ||
			(tlv_type == TTL_TLV_TYPE)) {
			switch(tlv_type) {
				case CHASSIS_ID_TLV_TYPE:
					/* skip chassis id tlv */
					tlv_offset += (tlv_length +
							TLV_HDDR_LENGTH);
					break;

				case PORT_ID_TLV_TYPE:
					/* skip port id tlv */
					tlv_offset += (tlv_length +
							TLV_HDDR_LENGTH);
					break;

				case TTL_TLV_TYPE:
					if (tlv_length == TTL_TLV_LENGTH) {
						memcpy(&ttl, tlv_offset+
								TLV_HEADER_LENGTH ,
								TTL_TLV_LENGTH );
						tlv_offset += cvmcs_dcbx_read_ttl_tlv(
								tlv_offset, port );
					}
					if (port->timer.rx_ttl == 0) {
						cvmx_spinlock_unlock(&octnic->dcb[port_num].dcbx_cfg.lock);
						return 0;
					}
					break;
			}//End of switch
		}else if (tlv_type == ORGANIZATIONALLY_SPECIFIC_TLV_TYPE)
		{
			read += TLV_HEADER_LENGTH;
			read += OUI_LENGTH;
			subtype = (uint8_t)*read;
			read += SUB_TYPE_LENGTH;
			switch(subtype)
			{
				case ETS_CONFIGURATION:
					rcv_ets = (struct ets_config_tlv *)tlv_offset;
					break;

				case ETS_RECOMMENDATION:
					rcv_ets_rcmnd = (struct ets_recmnd_tlv *)tlv_offset;
					break;

				case PFC_CONFIGURATION:
					rcv_pfc = (struct pfc_config_tlv *)tlv_offset;
					break;

				case APPLICATION_PRIORITY:
					/* app priority not supported only 
 					 * for indication to host*/
					rcv_app = (struct app_priority_tlv *)tlv_offset;
					remote_port->app_config.num_prio = 
						((rcv_app->length - 5) / SIZE_OF_TABLE);
					memcpy(remote_port->app_config.priority_table,
					       rcv_app->priority_table,
					       remote_port->app_config.num_prio * SIZE_OF_TABLE);

					if (remote_port->app_config.num_prio)
						ieee_dcbx_cfg->app_flag |= REMOTE_PARAM_CHANGE;
					break;

				case CONGESTION_TLV_SUBTYPE:
					cvmcs_dcb_qcn_reconfig((cn_tlv_t *)tlv_offset, port_num );
					break;

			}
			tlv_offset += tlv_length + TLV_HEADER_LENGTH;
		}
		else {
			/* Not an ORG TLV, skip this tlv */
			tlv_offset += tlv_length + TLV_HEADER_LENGTH;
		}
	}// end of while loop

	if (rcv_ets != NULL)
	{
		remote_port->ets_flag 		= 1;
		remote_port->ets_config.willing	= rcv_ets->willing;
		remote_port->ets_config.cbs 	= rcv_ets->cbs;
		if (rcv_ets->max_tcs == 0)
			remote_port->ets_config.max_tcs = 8;
		else
			remote_port->ets_config.max_tcs = rcv_ets->max_tcs;
		/* unpack & store prio assign table */
		cvmcs_dcbx_ieee_unpack_prio_assign_tbl(rcv_ets->prio_assign_table,
					remote_port->ets_config.prio_assign_table);
		memcpy(remote_port->ets_config.tc_bw_table , rcv_ets->tc_bw_table,
							IEEE_8021QAZ_MAX_TCS);
		memcpy(remote_port->ets_config.tsa_assign_table,
					rcv_ets->tsa_assign_table,
					IEEE_8021QAZ_MAX_TCS);
	}

	if (rcv_ets_rcmnd != NULL)
	{
		remote_port->ets_flag |= 2;
		/* unpack & store prio assign table */
		cvmcs_dcbx_ieee_unpack_prio_assign_tbl(
				rcv_ets_rcmnd->prio_assign_table,
				remote_port->ets_recmnd.prio_assign_table);

		memcpy(remote_port->ets_recmnd.tc_bw_table,
					rcv_ets_rcmnd->tc_bw_table,
					IEEE_8021QAZ_MAX_TCS);
		memcpy(remote_port->ets_recmnd.tsa_assign_table,
					rcv_ets_rcmnd->tsa_assign_table,
					IEEE_8021QAZ_MAX_TCS);

		ieee_dcbx_cfg->ets_flag = REMOTE_PARAM_CHANGE;

		/* Run asymmetric state machine */
		cvmcs_dcbx_ieee_asymmetric_st_machine(port_num);

		if (ieee_dcbx_cfg->ets_flag & OPER_PARAM_CHANGE)
		{
			struct as_port_config *ets_config =
				 &ieee_dcbx_cfg->oper_port.ets_config;
			if (cvmcs_dcb_ets_config(port_num,
						ets_config->prio_assign_table,
						ets_config->tc_bw_table,
						ets_config->tsa_assign_table))
				printf("Error: In  cvmcs_dcbx_ieee_asymmetric_st_machine \n");
		}

		local_change = True;
	}

	if (rcv_pfc!= NULL)
	{
		remote_port->pfc_flag 			= 1;
		remote_port->pfc_config.willing 	= rcv_pfc->willing;
		remote_port->pfc_config.mbc 		= rcv_pfc->mbc;
		remote_port->pfc_config.pfc_cap 	= rcv_pfc->pfc_cap;
		remote_port->pfc_config.pfc_enable 	= rcv_pfc->pfc_enable;

		ieee_dcbx_cfg->pfc_flag = REMOTE_PARAM_CHANGE;

		cvmcs_dcbx_ieee_symmetric_st_machine(port_num);

		if (ieee_dcbx_cfg->pfc_flag & OPER_PARAM_CHANGE) {
			struct sy_port_config *pfc_config =
				 &ieee_dcbx_cfg->oper_port.pfc_config;
			if (cvmcs_dcb_pfc_config(port_num,
					pfc_config->pfc_enable,
					pfc_config->pfc_cap))
				printf("Error: Error: In %s \n", __func__);
		}

		local_change = True;
	}
	
	if (local_change)
		cvmx_atomic_set32((int32_t *)&port->tx.local_change, (int32_t)local_change);

	port->rx.rx_changes = true;
	cvmcs_dcbx_param_indication(port_num);

	cvmx_spinlock_unlock(&octnic->dcb[port_num].dcbx_cfg.lock);
	
	return 0;
}

/** Unpack the priority assignment table
 *
 * @param packed_prio_assign_table	packed table
 * @param unpacked_prio_assign_table	unpacked table
 *
 */
void cvmcs_dcbx_ieee_unpack_prio_assign_tbl(uint8_t *packed_prio_assign_table,
					 uint8_t *unpacked_prio_assign_tbl)
{
	uint8_t i, temp, prio_tc;

	memset(unpacked_prio_assign_tbl, 0, 8);
	for (i = 0; i < 8; i++) {
		//temp value selected depending upon whether to
		//read MSB or LSB
	        temp = (i % 2) ? 0x0f:0xf0;
		//read the prio_assign_table value (MSB or LSB)
	        prio_tc = *packed_prio_assign_table & temp;
		//if read MSB shift the value
	        if (temp == 0xf0)
        		prio_tc >>= 4;
		//point to next prio_assign_table if read MSB
        	packed_prio_assign_table += (i % 2);
		unpacked_prio_assign_tbl[i] = prio_tc;
	}
}

/** pack the priority assignment table
 *
 * @param unpacked_prio_assign_table	unpacked table
 * @param packed_prio_assign_table	packed table
 *
 */
void cvmcs_dcbx_ieee_pack_store_prio_assign_tbl(uint8_t *unpacked_prio_assign_table,
						 uint8_t *packed_prio_assign_tbl)
{
	uint8_t i,temp,octet=0;

	for(i =0; i<IEEE_8021QAZ_MAX_TCS; i++) {
		//temp value selected based on whether to write to MSB or LSB
		temp = (i %2) ? 0:4;
		packed_prio_assign_tbl[octet] |= unpacked_prio_assign_table[i]<<temp;
		octet += (i %2)? 1:0 ;
	}

}

void cvmcs_dcbx_ieee_show_cfg_details(struct oct_nic_dcbx_config *dcbx_config)
{
	int i;

	printf("num_traffic_classes = %x\n", dcbx_config->ets_config.num_traffic_classes);
	printf("ets_flags = %x \n", dcbx_config->ets_config.ets_flags);
	printf("pfc_flags = %x \n", dcbx_config->pfc_config.pfc_flags);

	printf("priority_assignment_table = ");
	for(i = 0; i < IEEE_8021QAZ_MAX_TCS; i++)
		printf("%d \t", dcbx_config->ets_config.ieee.priority_assignment_table[i]);
	printf("\n");

	printf("tc_bw_assignment_table 	 = ");
	for(i = 0; i < IEEE_8021QAZ_MAX_TCS; i++)
		printf("%d \t", dcbx_config->ets_config.ieee.tc_bandwidth_assignment_table[i]);
	printf("\n");

	printf("tsa_assignment_table      = ");
	for(i=0; i<IEEE_8021QAZ_MAX_TCS; i++)
		printf("%d \t", dcbx_config->ets_config.ieee.tsa_assignment_table[i]);
	printf("\n");

	printf("PfcEnable = %x \n", dcbx_config->pfc_config.pfc_enable);

	printf("App priority tables = %d\n", dcbx_config->app_config.num_app_prio);
	for(i=0;i<dcbx_config->app_config.num_app_prio; i++)
	{
		printf("Table[%d] selector = %d,priority = %d, protocol_id = %x\n",i,
					dcbx_config->app_config.app_prio[i].selector, 
					dcbx_config->app_config.app_prio[i].priority,
					dcbx_config->app_config.app_prio[i].protocol_id);	
	}
}

/**  Config DCBX_IEEE 
 *
 * @param port_num	physical port number
 */
void cvmcs_dcbx_ieee_config(uint8_t port_num)
{
	struct dcbx_ieee_config *dcbx_ieee =
		&octnic->dcb[port_num].dcbx_cfg.dcbx_ieee;
	struct as_port_config  	*ets_config = &dcbx_ieee->oper_port.ets_config;
	struct sy_port_config  	*pfc_config = &dcbx_ieee->oper_port.pfc_config;

	dcbx_ieee->ets_flag = 0;

	/*Run asymmetric(ETS) state machine */
	cvmcs_dcbx_ieee_asymmetric_st_machine(port_num);

	/* Configure ETS queues */
	if (cvmcs_dcb_ets_config(port_num,
				ets_config->prio_assign_table,
				ets_config->tc_bw_table,
				ets_config->tsa_assign_table))
	{
		printf("Error3:In dcbx_set_default_configure \n");
		return;
	}

	dcbx_ieee->pfc_flag = 0;

	/*Run symmetric(PFC) state machine */
	cvmcs_dcbx_ieee_symmetric_st_machine(port_num);

	/* Configure Priority queues for PFC*/
	if (cvmcs_dcb_pfc_config(port_num,
				pfc_config->pfc_enable,
				pfc_config->pfc_cap))
	{
		printf("Error4: In  dcbx_set_default_configure \n");
        	cvmcs_dcb_ets_disable(port_num);
		return;
	}

	return  ;
}

/**  Set default parameters
 *
 * @param port_num	physical port number
 *
  * @return Returns 0 on success, 1 on error.
 */
uint8_t cvmcs_dcbx_ieee_set_default_params(uint8_t port_num)
{
        struct dcbx_ieee_config *dcbx_ieee =
        	&octnic->dcb[port_num].dcbx_cfg.dcbx_ieee;
	struct oct_nic_dcbx_config *def_config =
		&octnic->dcb[port_num].dcbx_def_cfg.dcbx_ieee;
	struct lldp_port *local_port = &dcbx_ieee->local_port;

	local_port->port_addr =
		octnic->gmx_port_info[port_num].hw_base_addr;

	local_port->ets_flag = 1;

	local_port->ets_config.willing =
		!!(def_config->ets_config.ets_flags & DCBX_FLAG_WILLING);

	// Not supporting CBS
	local_port->ets_config.cbs = 0;

	local_port->ets_config.max_tcs =
		def_config->ets_config.num_traffic_classes;

	/* Initializing the priority assignment table */
	memcpy(local_port->ets_config.prio_assign_table,
	       def_config->ets_config.ieee.priority_assignment_table,
	       sizeof(def_config->ets_config.ieee.priority_assignment_table));
	memcpy(local_port->ets_config.tc_bw_table,
	       def_config->ets_config.ieee.tc_bandwidth_assignment_table,
	       sizeof(def_config->ets_config.ieee.tc_bandwidth_assignment_table));
	memcpy(local_port->ets_config.tsa_assign_table,
	       def_config->ets_config.ieee.tsa_assignment_table,
	       sizeof(def_config->ets_config.ieee.tsa_assignment_table));

	local_port->pfc_flag = 1;

	local_port->pfc_config.willing =
		!!(def_config->pfc_config.pfc_flags & DCBX_FLAG_WILLING);

	local_port->pfc_config.mbc = 0;
	local_port->pfc_config.pfc_cap =
		def_config->pfc_config.pfc_capability;
	local_port->pfc_config.pfc_enable =
		def_config->pfc_config.pfc_enable;

	return 0;
}

/** Handles the set calls from host
 *
 * @param port_num      physical port number
 * @param dcbx_cmd      Command received from the host
 *
 */
int cvmcs_dcbx_ieee_set_params(int port_num, struct oct_nic_dcbx_cmd *dcbx_cmd)
{
	int i, local_change = False;
	dcbx_config_t *dcbx;
	lldp_sm_attr_t *port;

	dcbx = &octnic->dcb[port_num].dcbx_cfg;

	port = &dcbx->port;

	if (dcbx->remote_dcbx_ver) {
		if (dcbx->remote_dcbx_ver != dcbx_cmd->dcbx_version) {
			printf("DCBX Version Mistmatch\n");
			return 1;
		}
	} else {
		if (!octnic->dcb[port_num].dcbx_ieee) {
			printf("DCBX Version Not Offloaded\n");
			return 1;
		}

		dcbx->oper_dcbx_ver = DCBX_IEEE;
	}

	cvmx_spinlock_lock(&octnic->dcb[port_num].dcbx_cfg.lock);

	if (dcbx_cmd->cmd & DCBX_CMD_SET_ETS ) {

		/* Initialize the local_admin_param(state machine variable) */
		ieee_ets_cfg_t *ets_config = &dcbx->dcbx_ieee.local_port.ets_config;

		ets_config->willing =
			!!(dcbx_cmd->config.ets_config.ets_flags & DCBX_FLAG_WILLING);
		ets_config->cbs = dcbx_cmd->config.ets_config.ieee.cbs;
		ets_config->max_tcs = 
			dcbx_cmd->config.ets_config.num_traffic_classes;
		memcpy(ets_config->prio_assign_table, 
		       dcbx_cmd->config.ets_config.ieee.priority_assignment_table,
		       IEEE_8021QAZ_MAX_TCS);
		memcpy(ets_config->tc_bw_table, 
		       dcbx_cmd->config.ets_config.ieee.tc_bandwidth_assignment_table,
		       IEEE_8021QAZ_MAX_TCS);
		memcpy(ets_config->tsa_assign_table, 
		       dcbx_cmd->config.ets_config.ieee.tsa_assignment_table,
		       IEEE_8021QAZ_MAX_TCS);

		local_change = True;
	}

	if (dcbx_cmd->cmd & DCBX_CMD_SET_PFC) {
		/* set up the symmetric state machine & configure pfc  */
		ieee_pfc_cfg_t *pfc_config = &dcbx->dcbx_ieee.local_port.pfc_config;

		pfc_config->willing =
			!!(dcbx_cmd->config.pfc_config.pfc_flags & DCBX_FLAG_WILLING);
		pfc_config->mbc = dcbx_cmd->config.pfc_config.mbc;
		pfc_config->pfc_cap = dcbx_cmd->config.pfc_config.pfc_capability;
		pfc_config->pfc_enable = dcbx_cmd->config.pfc_config.pfc_enable;

		local_change = True;
	}

	if (dcbx_cmd->cmd & DCBX_CMD_SET_APP) {
		/* set up app priorities */
		ieee_app_prio_cfg_t *app_config = &dcbx->dcbx_ieee.local_port.app_config;
		app_config->num_prio =
			dcbx_cmd->config.app_config.num_app_prio;

		for (i = 0; i < app_config->num_prio; i++) {
			app_config->priority_table[i].priority =
				dcbx_cmd->config.app_config.app_prio[i].priority;
			app_config->priority_table[i].reserved = 0;
			app_config->priority_table[i].sel =
				dcbx_cmd->config.app_config.app_prio[i].selector;
			app_config->priority_table[i].protocol_id =
				dcbx_cmd->config.app_config.app_prio[i].protocol_id;
		}	
	}

	if (local_change) {
		cvmcs_dcbx_ieee_config(port_num);
		cvmx_atomic_set32((int32_t *)&port->tx.local_change,
				(int32_t)local_change);
		cvmcs_dcbx_param_indication(port_num);
	}

	cvmx_spinlock_unlock(&octnic->dcb[port_num].dcbx_cfg.lock);

	return 0;
}

/** Get Local Admin Parameters
 *
 * @param port_num      physical port number
 * @param dcbx_config   DCBX config
 *
 */
void cvmcs_dcbx_ieee_get_params(int port_num, struct oct_nic_dcbx_config *dcbx_config)
{
	int i;
	struct lldp_port *local_port =
		&octnic->dcb[port_num].dcbx_cfg.dcbx_ieee.local_port;

	if (local_port->pfc_config.willing)
		dcbx_config->pfc_config.pfc_flags = DCBX_FLAG_WILLING;
	else
		dcbx_config->pfc_config.pfc_flags = 0;

	dcbx_config->pfc_config.pfc_capability = local_port->pfc_config.pfc_cap;
	dcbx_config->pfc_config.pfc_enable = local_port->pfc_config.pfc_enable;
	dcbx_config->pfc_config.mbc = local_port->pfc_config.mbc;
		
	if (local_port->ets_config.willing)
		dcbx_config->ets_config.ets_flags = DCBX_FLAG_WILLING;
	else
		dcbx_config->ets_config.ets_flags = 0;

	dcbx_config->ets_config.num_traffic_classes = local_port->ets_config.max_tcs;
	dcbx_config->ets_config.ieee.cbs = local_port->ets_config.cbs;

	memcpy(dcbx_config->ets_config.ieee.priority_assignment_table,
	       local_port->ets_config.prio_assign_table,
	       IEEE_8021QAZ_MAX_TCS);

	memcpy(dcbx_config->ets_config.ieee.tc_bandwidth_assignment_table,
	       local_port->ets_config.tc_bw_table,
	       IEEE_8021QAZ_MAX_TCS);

	memcpy(dcbx_config->ets_config.ieee.tsa_assignment_table,
	       local_port->ets_config.tsa_assign_table,
	       IEEE_8021QAZ_MAX_TCS);

	dcbx_config->app_config.num_app_prio = local_port->app_config.num_prio;

	for (i = 0; i < local_port->app_config.num_prio; i++) {
		dcbx_config->app_config.app_prio[i].priority =
			local_port->app_config.priority_table[i].priority;
		dcbx_config->app_config.app_prio[i].selector =
			local_port->app_config.priority_table[i].sel;
		dcbx_config->app_config.app_prio[i].protocol_id =
			local_port->app_config.priority_table[i].protocol_id;
	}	
}
