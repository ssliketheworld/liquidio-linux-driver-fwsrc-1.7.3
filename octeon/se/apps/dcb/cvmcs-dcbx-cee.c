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

extern CVMX_SHARED octnic_dev_t *octnic;
extern CVMX_SHARED cvm_oct_dev_t *oct;

void cvmcs_dcbx_cee_update_local_port(uint8_t port_num)
{
	struct control_sm_variables *control =
		&octnic->dcb[port_num].dcbx_cfg.dcbx_cee.control_sm_var;
	struct feat_sm_var *pg_var =
		&octnic->dcb[port_num].dcbx_cfg.dcbx_cee.feature_sm_var.pg;
	struct feat_sm_var *pfc_var =
		&octnic->dcb[port_num].dcbx_cfg.dcbx_cee.feature_sm_var.pfc;
	struct feat_sm_var *app_var =
		&octnic->dcb[port_num].dcbx_cfg.dcbx_cee.feature_sm_var.app;
  	struct cee_lldp_port *local_port =
		&octnic->dcb[port_num].dcbx_cfg.dcbx_cee.local_port;

  	/*Initialize org tlv */
  	local_port->header.type = ORGANIZATIONALLY_SPECIFIC_TLV_TYPE;
  	local_port->header.length =
		ORG_HDDR_LENGTH(app_var->desired_cfg.app.app_tbl_entries);
 	local_port->header.oui[0] = INTEL_OUI_0;
  	local_port->header.oui[1] = INTEL_OUI_1;
  	local_port->header.oui[2] = INTEL_OUI_2;
  	local_port->header.subtype = DCBX_CEE_SUBTYPE;

  	/*Initialize protocol_control_sub_tlv */
  	local_port->control.type = PRO_CON_SUB_TLV_TYPE;
  	local_port->control.length = PRO_CON_SUB_TLV_LENGTH - 2;
  	local_port->control.oper_version = control->oper_version;
  	local_port->control.max_version = control->max_version;
  	local_port->control.seqno = control->seqno;
  	local_port->control.ackno = control->ackno;

  	/*Initialize the pg feature_tlv_header */
  	local_port->pg.header.type = PG_SUB_TLV_TYPE;
  	local_port->pg.header.length =
		FEAT_SUB_TLV_HDDR_LENGTH - 2 + FEAT_PG_CFG_SIZE;
  	local_port->pg.header.oper_version = pg_var->oper_version;
  	local_port->pg.header.max_version = pg_var->max_version;

  	/*Initialize using Host Configuration recvd */
  	local_port->pg.header.en = pg_var->enabled;
  	local_port->pg.header.w = pg_var->willing;
  	local_port->pg.header.er = pg_var->error;
  	local_port->pg.header.subtype = 0;

  	/*Initialize feature_pg_cfg */
  	memcpy(&local_port->pg.pg_cfg,
	       &pg_var->oper_cfg.pg,
	       sizeof(struct feature_pg_cfg));

  	/*Initialize pfc_sub_tlv header fields */
  	local_port->pfc.header.type = PFC_SUB_TLV_TYPE;
  	local_port->pfc.header.length =
		FEAT_SUB_TLV_HDDR_LENGTH - 2 + FEAT_PFC_CFG_SIZE;
  	local_port->pfc.header.oper_version = pfc_var->oper_version;
  	local_port->pfc.header.max_version = pfc_var->max_version;
  	local_port->pfc.header.en = pfc_var->enabled;
  	local_port->pfc.header.w = pfc_var->willing;
  	local_port->pfc.header.er = pfc_var->error;
  	local_port->pfc.header.subtype = 0;

  	/*Initialize feature_pfc_cfg */
  	memcpy(&local_port->pfc.pfc_cfg,
	       &pg_var->oper_cfg.pfc,
	       sizeof(struct feature_pfc_cfg));

  	/*Initialize app_sub_tlv header fields */
  	local_port->app.header.type = APP_PROTOCOL_SUB_TLV_TYPE;
  	local_port->app.header.length =
		FEAT_SUB_TLV_HDDR_LENGTH - 2 +
		FEAT_APP_CFG_SIZE(app_var->desired_cfg.app.app_tbl_entries);
  	local_port->app.header.oper_version = app_var->oper_version;
  	local_port->app.header.max_version = app_var->max_version;
  	local_port->app.header.en = app_var->enabled;
  	local_port->app.header.w = app_var->willing;
  	local_port->app.header.er = app_var->error;
  	local_port->app.header.subtype = 0;

  	/*Initialize feature_app_cfg */
  	memcpy(local_port->app.app_cfg,
	       pg_var->desired_cfg.app.app_tbl,
	       sizeof(struct feature_app_cfg) * 84);

	local_port->app_tbl_entries = app_var->desired_cfg.app.app_tbl_entries;

  	return;
}

void cvmcs_dcbx_cee_convert(struct feature_pg_cfg *pg, uint8_t *prio_tc, uint8_t *tc_tsa)
{
	uint8_t i, j, temp, pgid;
	uint8_t *packed_prio_assign_table = (uint8_t *) pg;

	memset(prio_tc, 0, 8);
	memset(tc_tsa, 0, 8);
	for (i = 0; i < 8; i++) {
		//temp value selected depending upon whether to
		//read MSB or LSB
		temp = (i % 2) ? 0x0f:0xf0;
		//read the prio_assign_table value (MSB or LSB)
	        pgid = *packed_prio_assign_table & temp;
		//if read MSB shift the value
	        if (temp == 0xf0)
        		pgid >>= 4;
		//point to next prio_assign_table if read MSB
        	packed_prio_assign_table += (i % 2);
		prio_tc[i] = pgid;
	}

        for (i = 0; i < 8; i++) {
                for (j = 0; j < 8; j++) {
                        if (prio_tc[j] == i)
                                break;
                } 

                if (j == 8)
                        temp = i;
        }

        for (i = 0; i < 8; i++) {
                if (prio_tc[i] == 15)
                        prio_tc[i] = temp;
                if (i == temp)
                        tc_tsa[i] = OCTEON_TSA_STRICT_PRIORITY;
                else
                        tc_tsa[i] = OCTEON_TSA_ETS;
        }

}

void cvmcs_dcbx_cee_set_feat_cfg(uint8_t port_num,
				struct feat_sm_var *feature,
				bool peer_config)
{
	uint8_t prio_tc[8];
	uint8_t tsa_assign_table[8]={0};

	switch (feature->type) {
		case CEE_PG_TYPE:
			if (peer_config) {
				memcpy(&feature->oper_cfg.pg,
				       &feature->peer_cfg.pg,
				       sizeof (struct feature_pg_cfg));
			} else {
				memcpy(&feature->oper_cfg.pg,
				       &feature->desired_cfg.pg,
				       sizeof (struct feature_pg_cfg));
			}

			feature->enabled = True;

			cvmcs_dcbx_cee_convert(&feature->oper_cfg.pg,
					prio_tc, tsa_assign_table);

			cvmcs_dcb_ets_config(port_num,
					     prio_tc,
					     feature->oper_cfg.pg.pg_percentage,
					     tsa_assign_table);

			feature->flags |= OPER_PARAM_CHANGE;
			break;

		case CEE_PFC_TYPE:
			if (peer_config) {
				memcpy(&feature->oper_cfg.pfc,
				       &feature->peer_cfg.pfc,
				       sizeof (struct feature_pfc_cfg));
			} else {
				memcpy(&feature->oper_cfg.pfc,
				       &feature->desired_cfg.pfc,
				       sizeof (struct feature_pfc_cfg));
			}

			feature->enabled = True;

			cvmcs_dcb_pfc_config (port_num,
					      feature->oper_cfg.pfc.pfc_enable,
					      feature->oper_cfg.pfc.
					      num_tcpfc_supported);

			feature->flags |= OPER_PARAM_CHANGE;
			break;
	}
}

int cvmcs_dcbx_cee_compatible(struct feat_sm_var *feature)
{
	switch (feature->type){
		case CEE_PG_TYPE:
	        case CEE_APP_TYPE:
			return 1;

	        case CEE_PFC_TYPE:
			return (feature->enabled == feature->rx_feature_enabled); 

		default:
			printf ("Error: In dcbx_cee_Compatible function \n");
			return 0;
	}
}

uint8_t cvmcs_dcbx_cee_feat_sm_next(uint8_t port_num, struct feat_sm_var *feature)
{
	struct control_sm_variables *control =
		&octnic->dcb[port_num].dcbx_cfg.dcbx_cee.control_sm_var;
	
	switch (feature->state) {
		case LINKUP:
			feature->state = SET_LOCAL_PARAMETERS;
			break;

		case SET_LOCAL_PARAMETERS:
		case FEATURE_NO_ADVERTISE:
		case PEER_NOT_ADVERTISE_DCBX:
		case PEER_NOT_ADVERTISE_FEATURE:
		case UPDATE_OPER_VERSION:
		case PEER_UPDATE_OPER_VERSION:
		case ERROR_CHANGE:
			feature->state = FWAIT;
			break;

		case CFG_NOT_COMPATIBLE:
		case USE_LOCAL_CFG:
		case USE_PEER_CFG:
		case FEATURE_DISABLED:
			feature->state = (feature->syncd ? FWAIT : ERROR_CHANGE);
			break;

		case GET_PEER_CFG:
		   	if (!(feature->enabled && feature->rx_feature_enabled)) {
				feature->state = FEATURE_DISABLED;
				break;
			}

		   	if (feature->willing && !feature->peer_willing) {
				feature->state = USE_PEER_CFG;
				break;
			}

		   	if (!feature->willing && feature->peer_willing) {
				feature->state = USE_LOCAL_CFG;
				break;
			}

		      	if (cvmcs_dcbx_cee_compatible(feature)) {
				feature->state = USE_LOCAL_CFG;
				break;
			}

			feature->state = CFG_NOT_COMPATIBLE;
			break;

		case FWAIT:
		  	if (feature->local_parameter_change && feature->syncd) {
				feature->state = SET_LOCAL_PARAMETERS;
				break;
			}

		  	if (!feature->advertise) {
				feature->state = FEATURE_NO_ADVERTISE;
				break;
			}
			
			if (!control->dcbx_feature_update)
				break;

		  	if (control->no_dcbxtlv_received) {
				feature->state = PEER_NOT_ADVERTISE_DCBX;
				break;
			}

		  	if (!feature->rx_feature_present) {
				feature->state = PEER_NOT_ADVERTISE_FEATURE;
				break;
			}

			if (!(feature->syncd ||
			     (control->rcvdackno == feature->feature_seqno)))
				break;

			if (feature->oper_version !=
                            (min(feature->rx_feature_max_version, feature->max_version))) {
				feature->state = UPDATE_OPER_VERSION;
				break;
			}

			if (feature->oper_version == feature->rx_feature_oper_version) {
				feature->state = GET_PEER_CFG;
				break;
			}

			feature->state = PEER_UPDATE_OPER_VERSION;
			break;

		default:
			printf("Error: dcbx_cee_feat_sm_next is broken. state = %d\n",
				feature->state);
			break;
	}

	return feature->state;
}

void cvmcs_dcbx_cee_feat_sm_run(uint8_t port_num, struct feat_sm_var *feature)
{
	struct control_sm_variables *control =
		&octnic->dcb[port_num].dcbx_cfg.dcbx_cee.control_sm_var;

	while (cvmcs_dcbx_cee_feat_sm_next(port_num, feature) != FWAIT) {
		switch (feature->state) {
			case LINKUP:
  				feature->oper_version = DCBX_CEE;
  				feature->max_version = DCBX_CEE;
  				feature->advertise = TRUE;
				break;

			case SET_LOCAL_PARAMETERS:
				feature->syncd = !feature->local_param_advertise;
				feature->enabled = feature->local_param_enabled;
				feature->advertise = feature->local_param_advertise;
				feature->willing = feature->local_param_willing;
				feature->desired_cfg = feature->local_param_cfg;
		      		feature->feature_seqno = control->seqno + 1;
		      		feature->local_parameter_change = FALSE;
				if (octnic->dcb[port_num].dcbx_cfg.remote_dcbx_ver == DCBX_UNKNOWN)
					cvmcs_dcbx_cee_set_feat_cfg(port_num, feature, FALSE);
				break;

			case FEATURE_NO_ADVERTISE:
				cvmcs_dcbx_cee_set_feat_cfg(port_num, feature, FALSE);

		      		feature->error = FALSE;
		     		break;

			case PEER_NOT_ADVERTISE_DCBX:
				cvmcs_dcbx_cee_set_feat_cfg(port_num, feature, FALSE);

		      		feature->syncd = FALSE;
		      		feature->feature_seqno = control->seqno + 1;
		      		feature->error = TRUE;
				feature->flags |= REMOTE_PARAM_SHUTDOWN;
		     		break;

		  	case PEER_NOT_ADVERTISE_FEATURE:
				cvmcs_dcbx_cee_set_feat_cfg(port_num, feature, FALSE);

		      		feature->syncd = TRUE;
		      		feature->error = TRUE;
		    		break;

		  	case UPDATE_OPER_VERSION:
		  		feature->oper_version = 
					min(feature->rx_feature_max_version,
					feature->max_version);
		      		feature->syncd = FALSE;
		      		feature->feature_seqno = control->seqno + 1;
		    		break;

		  	case PEER_UPDATE_OPER_VERSION:
		      		feature->syncd = TRUE;
		    		break;

		  	case CFG_NOT_COMPATIBLE:
				cvmcs_dcbx_cee_set_feat_cfg(port_num, feature, FALSE);

		     		feature->syncd = feature->error;
		      		feature->error = TRUE;
		    		break;

		  	case USE_LOCAL_CFG:
				cvmcs_dcbx_cee_set_feat_cfg(port_num, feature, FALSE);

		      		feature->syncd = !feature->error;
		      		feature->error = FALSE;
		    		break;

		  	case USE_PEER_CFG:
				cvmcs_dcbx_cee_set_feat_cfg(port_num, feature, TRUE);

		      		feature->syncd = !feature->error;
		      		feature->error = FALSE;
		    		break;

		  	case FEATURE_DISABLED:
				cvmcs_dcbx_cee_set_feat_cfg(port_num, feature, FALSE);

		      		feature->syncd = !feature->error;
		      		feature->error = FALSE;
		    		break;

		  	case ERROR_CHANGE:
		      		feature->feature_seqno = control->seqno + 1;
		    		break;

		  	case GET_PEER_CFG:
		      		feature->peer_cfg = feature->rx_feature_cfg;
		      		feature->peer_willing = feature->rx_feature_willing;
				feature->flags |= REMOTE_PARAM_CHANGE;
		    		break;

	      		default:
				printf("Error: dcbx_cee_feat_sm_run is broken. state = %d\n",
					feature->state);
				break;
		  }
	}
}

uint8_t cvmcs_dcbx_cee_cntrl_sm_next(uint8_t port_num)
{
	struct control_sm_variables *control =
		&octnic->dcb[port_num].dcbx_cfg.dcbx_cee.control_sm_var;

	struct feature_sm_variables *features =
		&octnic->dcb[port_num].dcbx_cfg.dcbx_cee.feature_sm_var;
		
	switch (control->state) {
		case LINKUP:
	      	case PEER_NOT_ADVERTISE_DCBXC:
	      	case ACK_PEER:
			if ((control->seqno == control->rcvdackno) &&
		    	    !(features->pfc.syncd && features->pg.syncd &&
			      features->app.syncd)) {
				control->state = UPDATE_DCBX_TLV;
				break;
		 	}	

			control->state = DWAIT;
			break;

	      	case UPDATE_DCBX_TLV:
	      	case UPDATE_OPER_VERSIONC:
			control->state = DWAIT;
			break;

	      	case DWAIT:
			if ((control->seqno == control->rcvdackno) &&
		    	    !(features->pfc.syncd && features->pg.syncd &&
			      features->app.syncd)) {
				control->state = UPDATE_DCBX_TLV;
				break;
		 	}	

			if (!control->something_changed_remote)
				break;

			if (control->no_dcbxtlv_received) {
				control->state = PEER_NOT_ADVERTISE_DCBXC;
				break;
		 	}

			if (control->oper_version !=
			    (min(control->rx_max_version, control->max_version))) {
				control->state = UPDATE_OPER_VERSIONC;
				break;
		  	}

			if (control->oper_version == control->rx_oper_version){
				control->state = PROCESS_PEER_TLV;
				break;
		  	}

			return False;

	      	case PROCESS_PEER_TLV:
	
			if (control->ackno != control->rxseqno) {
				control->state = ACK_PEER;
				break;
			}

			if ((control->seqno == control->rcvdackno) &&
		    	    !(features->pfc.syncd && features->pg.syncd &&
			      features->app.syncd)) {
				control->state = UPDATE_DCBX_TLV;
				break;
		 	}	

			control->state = DWAIT;
			break;

	      	default:
			printf("Error: dcbx_cee_cntrl_sm_next is broken. state = %d\n",
				control->state);
			break;
	}

	return control->state;
}

void cvmcs_dcbx_cee_cntrl_sm_run(uint8_t port_num)
{
	struct control_sm_variables *control =
		&octnic->dcb[port_num].dcbx_cfg.dcbx_cee.control_sm_var;

    	struct feature_sm_variables *features =
		&octnic->dcb[port_num].dcbx_cfg.dcbx_cee.feature_sm_var;

	while (cvmcs_dcbx_cee_cntrl_sm_next(port_num) != DWAIT) {

		switch (control->state) {
			case LINKUP:
  				control->seqno = 0;
  				control->ackno = 0;
				control->rcvdseqno = 0;
				control->rcvdackno = 0;
				control->oper_version = DCBX_CEE;
				control->max_version = DCBX_CEE;
		      		control->dcbx_feature_update = TRUE;
		    		break;

  			case UPDATE_DCBX_TLV:
				control->seqno++;
		     		control->something_changed_local = TRUE;
		    		break;

			case PEER_NOT_ADVERTISE_DCBXC:
				control->seqno = 0;
		     		control->ackno = 0;
		     		control->rcvdackno = 0;
		     		control->oper_version = control->max_version;
		     		control->dcbx_feature_update = TRUE;
		    		break;

		  	case UPDATE_OPER_VERSIONC:
		 	 	control->oper_version = min(control->rx_max_version,
					control->max_version);
		      		control->something_changed_local = TRUE;
		    		break;

		  	case PROCESS_PEER_TLV:
		  		control->rcvdackno = control->rxackno;
		      		control->dcbx_feature_update = TRUE;
		    		break;

		  	case ACK_PEER:
		  		control->ackno = control->rxseqno;	
		      		control->something_changed_local = TRUE;
		    		break;

		  	default:
		  		printf("Error: dcbx_cee_cntrl_sm_run is broken. state = %d\n",
					control->state);
		    		break;

		}

		if (control->dcbx_feature_update) {
			cvmcs_dcbx_cee_feat_sm_run(port_num, &features->pg);
			cvmcs_dcbx_cee_feat_sm_run(port_num, &features->pfc);
			cvmcs_dcbx_cee_feat_sm_run(port_num, &features->app);
			/* update current configuration */
			cvmcs_dcbx_param_indication(port_num);
			control->dcbx_feature_update = FALSE;
		}
	}

	if (control->something_changed_local) {
		cvmcs_dcbx_cee_update_local_port(port_num);
		control->something_changed_local = FALSE;
		control->no_dcbxtlv_received = FALSE;
		octnic->dcb[port_num].dcbx_cfg.port.tx.local_change =TRUE;
	}

	control->something_changed_remote = FALSE;
}

uint8_t cvmcs_dcbx_cee_config (uint8_t port_num)
{
	struct dcbx_cee_config *dcbx_cee = &octnic->dcb[port_num].dcbx_cfg.dcbx_cee;
	struct feature_sm_variables *fea_sm_var = &dcbx_cee->feature_sm_var;
	struct control_sm_variables *con_sm_var = &dcbx_cee->control_sm_var;

	dcbx_cee->control_sm_var.something_changed_remote = FALSE;
  
  	octnic->dcb[port_num].dcbx_cfg.port.tx.local_change = FALSE;

	/*Initialize the control state machine variables */
  	con_sm_var->state 			= LINKUP;
	con_sm_var->no_dcbxtlv_received 	= TRUE;
	con_sm_var->something_changed_remote	= FALSE;

	/*Initialize the feature state machine variable */
	fea_sm_var->pg.type 			= CEE_PG_TYPE;
  	fea_sm_var->pg.state 			= LINKUP;

	fea_sm_var->pfc.type 			= CEE_PFC_TYPE;
  	fea_sm_var->pfc.state 			= LINKUP;

	fea_sm_var->app.type 			= CEE_APP_TYPE;
  	fea_sm_var->app.state 			= LINKUP;

  	/* run the state machine */
  	cvmcs_dcbx_cee_cntrl_sm_run (port_num);

  	return 0;
}

uint8_t cvmcs_dcbx_cee_mib_constr_info_lldpdu (uint8_t port_num,
					   lldp_sm_attr_t * port)
{
	uint16_t size = 0, frame_size = 0;
  	void *TLV_offset = NULL;

	dcbx_config_t *dcbx = &octnic->dcb[port_num].dcbx_cfg;
  	struct cee_lldp_port *data =
    		&dcbx->dcbx_cee.local_port;
  	struct default_tlvs *d_tlv = &dcbx->default_tlv;
	
	cvmx_spinlock_lock(&octnic->dcb[port_num].dcbx_cfg.lock);

  	/* finding total size of LLDP frame */
  	size = ETHER_HDR_LENGTH;
  	size += CHASSIS_ID_TLV_LENGTH + TLV_HDDR_LENGTH;
  	size += PORT_ID_TLV_LENGTH + TLV_HDDR_LENGTH;
  	size += TTL_TLV_LENGTH + TLV_HDDR_LENGTH;
  	size += END_OF_LLDP_SIZE;
  	size += ORG_HEADER_SIZE;
  	size += PRO_CON_SUB_TLV_LENGTH;
  	size += FEAT_SUB_TLV_HDDR_LENGTH;
  	size += FEAT_PG_CFG_SIZE;
  	size += FEAT_SUB_TLV_HDDR_LENGTH;
  	size += FEAT_PFC_CFG_SIZE;
  	size += FEAT_SUB_TLV_HDDR_LENGTH;
  	size += FEAT_APP_CFG_SIZE(data->app_tbl_entries);

  	if (size < MIN_ETH_SIZE)
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

  	TLV_offset = (uint8_t *)port->tx.frameout;
  	memset (TLV_offset, 0, size);

  	port->tx.sizeout = frame_size;

      	memcpy (TLV_offset, &octnic->dcb[port_num].dcbx_cfg.eth_hddr,
	      	ETHER_HDR_LENGTH);

      	TLV_offset += ETHER_HDR_LENGTH;

  	memcpy (TLV_offset, &d_tlv->chassis_id,
		CHASSIS_ID_TLV_LENGTH + TLV_HDDR_LENGTH);
	
	TLV_offset += (CHASSIS_ID_TLV_LENGTH + TLV_HDDR_LENGTH);

  	memcpy (TLV_offset, &d_tlv->port_id, PORT_ID_TLV_LENGTH + TLV_HDDR_LENGTH);

  	TLV_offset += (PORT_ID_TLV_LENGTH + TLV_HDDR_LENGTH);

  	d_tlv->ttl.ttl = port->tx.tx_ttl;
  	memcpy (TLV_offset, &d_tlv->ttl, TTL_TLV_LENGTH + TLV_HDDR_LENGTH);
  	TLV_offset += (TTL_TLV_LENGTH + TLV_HDDR_LENGTH);

  	//org_header
  	memcpy (TLV_offset, &data->header, ORG_HEADER_SIZE);

  	TLV_offset += ORG_HEADER_SIZE;

  	memcpy (TLV_offset, &data->control, PRO_CON_SUB_TLV_LENGTH);
  	TLV_offset += PRO_CON_SUB_TLV_LENGTH;

  	//pg_sub_tlv
  	memcpy (TLV_offset, &data->pg.header, FEAT_SUB_TLV_HDDR_LENGTH);
  	TLV_offset += FEAT_SUB_TLV_HDDR_LENGTH;

  	memcpy (TLV_offset, &data->pg.pg_cfg, FEAT_PG_CFG_SIZE);
  	TLV_offset += FEAT_PG_CFG_SIZE;

  	//pfc_sub_tlv
  	memcpy (TLV_offset, &data->pfc.header, FEAT_SUB_TLV_HDDR_LENGTH);
  	TLV_offset += FEAT_SUB_TLV_HDDR_LENGTH;

 	memcpy (TLV_offset, &data->pfc.pfc_cfg, FEAT_PFC_CFG_SIZE);
  	TLV_offset += FEAT_PFC_CFG_SIZE;

  	//app_sub_tlv
  	memcpy (TLV_offset, &data->app.header, FEAT_SUB_TLV_HDDR_LENGTH);
  	TLV_offset += FEAT_SUB_TLV_HDDR_LENGTH;

 	memcpy (TLV_offset, &data->app.app_cfg,
		FEAT_APP_CFG_SIZE(data->app_tbl_entries));
  	TLV_offset += FEAT_APP_CFG_SIZE(data->app_tbl_entries);

	cvmx_spinlock_unlock(&octnic->dcb[port_num].dcbx_cfg.lock);

  	//end of tlv
  	memcpy (TLV_offset, &d_tlv->endof_lldp, END_OF_LLDP_SIZE);
  	TLV_offset += END_OF_LLDP_SIZE;

  	return 0;
}

void cvmcs_dcbx_cee_something_changed_remote(uint8_t port_num, lldp_sm_attr_t *port)
{
	struct control_sm_variables *control =
		&octnic->dcb[port_num].dcbx_cfg.dcbx_cee.control_sm_var;

	cvmx_spinlock_lock(&octnic->dcb[port_num].dcbx_cfg.lock);

	control->something_changed_remote = TRUE;

  	/* run the state machine */
  	cvmcs_dcbx_cee_cntrl_sm_run (port_num);

	cvmx_spinlock_unlock(&octnic->dcb[port_num].dcbx_cfg.lock);
}

uint8_t  cvmcs_dcbx_cee_rx_frame(uint8_t port_num, cvmx_wqe_t  *wqe)
{
        lldp_sm_attr_t *port = &octnic->dcb[port_num].dcbx_cfg.port;

       // lock: providing sync for 2 instance of received_lldp for 'temp_framein' resource
        cvmx_spinlock_lock(&octnic->dcb[port_num].dcbx_cfg.lock);
        if(port->rx.temp_framein != NULL ) {
                cvm_free_wqe_wrapper(port->rx.temp_framein);
                port->rx.temp_framein = NULL;
        }
        port->rx.temp_framein = wqe;
       // unlock
        cvmx_spinlock_unlock(&octnic->dcb[port_num].dcbx_cfg.lock);

        if((port->rx.framein == NULL) && (port->rx.temp_framein)) {
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

void cvmcs_dcbx_cee_rx_shutdown(uint8_t port_num)
{
	struct control_sm_variables *control =
		&octnic->dcb[port_num].dcbx_cfg.dcbx_cee.control_sm_var;

	cvmx_spinlock_lock(&octnic->dcb[port_num].dcbx_cfg.lock);

	control->something_changed_remote = TRUE;
	control->no_dcbxtlv_received = TRUE;

        /* run the state machine */
        cvmcs_dcbx_cee_cntrl_sm_run (port_num);

	cvmx_spinlock_unlock(&octnic->dcb[port_num].dcbx_cfg.lock);

	return;
}

void cvmcs_dcbx_cee_rx_process_frame (uint8_t port_num, lldp_sm_attr_t * port)
{
	cvmx_wqe_t *rcv_wqe = port->rx.framein;
	uint8_t *frame = (uint8_t *) cvmx_phys_to_ptr (rcv_wqe->packet_ptr.s.addr);
  	uint8_t *tlv_offset = frame;	 
  	struct dcbx_cee_config *dcbx_cee =
    		&octnic->dcb[port_num].dcbx_cfg.dcbx_cee;
  	struct cee_lldp_port *remote_port = &dcbx_cee->remote_port;
  	uint16_t tlv_length = 0,tlv_type;
  	struct feature_sm_variables *feature = &dcbx_cee->feature_sm_var;
  	struct control_sm_variables *control = &dcbx_cee->control_sm_var;
  	struct org_header *rcvd_org_hddr;
  	uint8_t read_org_length = 0;
  	struct protocol_control_sub_tlv *rcvd_cntrl_sub_tlv = NULL;
  	struct pg_sub_tlv *rcvd_pg_sub_tlv = NULL;
  	struct pfc_sub_tlv *rcvd_pfc_sub_tlv = NULL;
  	struct app_sub_tlv *rcvd_app_sub_tlv = NULL;
  	struct tlv_hdr *tlv_hdr;
  	struct ttl_tlv *ttl;
  	
	cvmx_spinlock_lock(&octnic->dcb[port_num].dcbx_cfg.lock);

	/* skipping eth header */
  	tlv_offset += 14;
  	
	while (1) {
      	
		tlv_type = 0, tlv_length = 0;
      		/* read type & length */
      		tlv_hdr = (tlv_hdr_t *) tlv_offset;
      		tlv_type = tlv_hdr->type;
      		tlv_length = tlv_hdr->length;
     
	 	if (tlv_type == 0) {
	  		//End of LLDP.
	  		break;	// break the while loop
		}

      		if ((tlv_type == CHASSIS_ID_TLV_TYPE) ||
	  		(tlv_type == PORT_ID_TLV_TYPE) || (tlv_type == TTL_TLV_TYPE)) {
	  	
			switch (tlv_type) {
	 		
				case CHASSIS_ID_TLV_TYPE:
	      				/* skip chassis id tlv */
	      				tlv_offset += (tlv_length + TLV_HDDR_LENGTH);
	      				break;

	    			case PORT_ID_TLV_TYPE:
	      				/* skip port id tlv */
	      				tlv_offset += (tlv_length + TLV_HDDR_LENGTH);
	      				break;

	    			case TTL_TLV_TYPE:
	      				if (tlv_length == TTL_TLV_LENGTH) {
		  				memcpy (&ttl, tlv_offset +
			  			TLV_HEADER_LENGTH, TTL_TLV_LENGTH);
		  				tlv_offset +=
		    					cvmcs_dcbx_read_ttl_tlv (tlv_offset, port);
					}
	      				if (port->timer.rx_ttl == 0) {
		  				printf ("In %s : shutdown frame \n", __func__);
		  				dcbx_cee->feature_sm_var.pg.rx_feature_present = False;
		  				dcbx_cee->feature_sm_var.pfc.rx_feature_present = False;
						cvmx_spinlock_unlock(&octnic->dcb[port_num].dcbx_cfg.lock);
		  				return;
					}
	      			break;
	    		}	//End of switch
		}
		else if (tlv_type == ORGANIZATIONALLY_SPECIFIC_TLV_TYPE) {
			/* Reading org header */
			rcvd_org_hddr = (struct org_header *) tlv_offset;

			if(!((rcvd_org_hddr->oui[0] == 0x00) &&
			     (rcvd_org_hddr->oui[1] == 0x1b) &&
                             (rcvd_org_hddr->oui[2] == 0x21))) {
				//printf("SKipping unwanted org tlv \n");	
				tlv_offset += (tlv_length + TLV_HEADER_LENGTH);
				continue;
			}

			memset (remote_port, 0, sizeof (struct cee_lldp_port));

			remote_port->header.type = rcvd_org_hddr->type;
			remote_port->header.length = rcvd_org_hddr->length;
			memcpy(remote_port->header.oui, rcvd_org_hddr->oui, OUI_LENGTH);
	        	remote_port->header.subtype = rcvd_org_hddr->subtype;
			tlv_offset += sizeof (struct org_header);
			read_org_length += 4;//sizeof (struct org_header);
			/* Reading org sub tlvs */
		
			while (read_org_length != remote_port->header.length) {
			
		    		tlv_type = 0, tlv_length = 0;
		    		/* read type & length */
		    		tlv_hdr = (tlv_hdr_t *) tlv_offset;
		    		tlv_type = tlv_hdr->type;
		    		tlv_length = tlv_hdr->length;

		    		switch (tlv_type){
			
					case PRO_CON_SUB_TLV_TYPE:
						rcvd_cntrl_sub_tlv =
			  				(struct protocol_control_sub_tlv *) tlv_offset;
						if((control->rcvdseqno == rcvd_cntrl_sub_tlv->seqno) &&
						   (control->rcvdackno == rcvd_cntrl_sub_tlv->ackno)) {
                               				goto end; 
                        			}

						control->rcvdseqno = rcvd_cntrl_sub_tlv->seqno;
						break;

		      			case PG_SUB_TLV_TYPE:
						rcvd_pg_sub_tlv = (struct pg_sub_tlv *) tlv_offset;
						break;

		      			case PFC_SUB_TLV_TYPE:
						rcvd_pfc_sub_tlv = (struct pfc_sub_tlv *) tlv_offset;
						break;
		      
		       			case APP_PROTOCOL_SUB_TLV_TYPE:
						rcvd_app_sub_tlv = (struct app_sub_tlv *) tlv_offset;
						break;
		      
					default:
						printf ("switch Defaultbad frame TLV_TYPE = %d\n",tlv_type);
		    		}		//end of switch 

				tlv_offset += tlv_length + TLV_HEADER_LENGTH;
				read_org_length += tlv_length + TLV_HEADER_LENGTH;

			}		//end of org while loop
		}	// elseif	
		else {
			tlv_offset += (tlv_length + TLV_HEADER_LENGTH);
		}	
        }	//endof main while loop
	    
	// Update state machine variables
	
	if (rcvd_pg_sub_tlv) {
		memcpy (&remote_port->pg.header,
			&rcvd_pg_sub_tlv->header, FEAT_TLV_HDR_SIZE);
		remote_port->pg.pg_cfg.pgid_0 = rcvd_pg_sub_tlv->pg_cfg.pgid_0;
		remote_port->pg.pg_cfg.pgid_1 = rcvd_pg_sub_tlv->pg_cfg.pgid_1;
		remote_port->pg.pg_cfg.pgid_2 = rcvd_pg_sub_tlv->pg_cfg.pgid_2;
		remote_port->pg.pg_cfg.pgid_3 = rcvd_pg_sub_tlv->pg_cfg.pgid_3;
		remote_port->pg.pg_cfg.pgid_4 = rcvd_pg_sub_tlv->pg_cfg.pgid_4;
		remote_port->pg.pg_cfg.pgid_5 = rcvd_pg_sub_tlv->pg_cfg.pgid_5;
		remote_port->pg.pg_cfg.pgid_6 = rcvd_pg_sub_tlv->pg_cfg.pgid_6;
		remote_port->pg.pg_cfg.pgid_7 = rcvd_pg_sub_tlv->pg_cfg.pgid_7;

		memcpy (&remote_port->pg.pg_cfg.pg_percentage,
			rcvd_pg_sub_tlv->pg_cfg.pg_percentage, 8);
		remote_port->pg.pg_cfg.num_tcs_supported =
			rcvd_pg_sub_tlv->pg_cfg.num_tcs_supported;

		/*set feature state machine - pg */
		feature->pg.rx_feature_enabled = remote_port->pg.header.en;
		feature->pg.rx_feature_present = TRUE;
		feature->pg.rx_feature_oper_version =
	      		remote_port->pg.header.oper_version;
		feature->pg.rx_feature_max_version =
	      		remote_port->pg.header.max_version;
		feature->pg.rx_feature_willing = remote_port->pg.header.w;
		feature->pg.rx_error = remote_port->pg.header.er;
		memcpy (&feature->pg.rx_feature_cfg.pg,
		    	&remote_port->pg.pg_cfg, FEAT_PG_CFG_SIZE);
	} else {
		feature->pg.rx_feature_present = FALSE;
		feature->pg.rx_feature_enabled = 0;
		feature->pg.rx_feature_oper_version = 0;
		feature->pg.rx_feature_max_version = 0;
		feature->pg.rx_feature_willing = 0;
		feature->pg.rx_error = 0;
		memset (&feature->pg.rx_feature_cfg.pg,
		    	0, FEAT_PG_CFG_SIZE);
	}

	if (rcvd_pfc_sub_tlv) {
		memcpy (&remote_port->pfc.header,
			&rcvd_pfc_sub_tlv->header, FEAT_TLV_HDR_SIZE);
		remote_port->pfc.pfc_cfg.pfc_enable =
			rcvd_pfc_sub_tlv->pfc_cfg.pfc_enable;

		remote_port->pfc.pfc_cfg.num_tcpfc_supported =
			rcvd_pfc_sub_tlv->pfc_cfg.num_tcpfc_supported;

		/*set feature state machine - pfc */
		feature->pfc.rx_feature_enabled = remote_port->pfc.header.en;
		feature->pfc.rx_feature_present = TRUE;
		feature->pfc.rx_feature_oper_version =
		      	remote_port->pfc.header.oper_version;
		feature->pfc.rx_feature_max_version =
	      		remote_port->pfc.header.max_version;
		feature->pfc.rx_feature_willing = remote_port->pfc.header.w;
		feature->pfc.rx_error = remote_port->pfc.header.er;
		memcpy (&feature->pfc.rx_feature_cfg.pfc,
		    	&remote_port->pfc.pfc_cfg, FEAT_PFC_CFG_SIZE);
	} else {
		feature->pfc.rx_feature_present = FALSE;
		feature->pfc.rx_feature_enabled = 0;
		feature->pfc.rx_feature_oper_version = 0;
		feature->pfc.rx_feature_max_version = 0;
		feature->pfc.rx_feature_willing = 0;
		feature->pfc.rx_error = 0;
		memset (&feature->pfc.rx_feature_cfg.pfc,
		    	0, FEAT_PFC_CFG_SIZE);
	}

	if (rcvd_app_sub_tlv) {
		memcpy (&remote_port->app.header,
			&rcvd_pfc_sub_tlv->header, FEAT_TLV_HDR_SIZE);

		memcpy (remote_port->app.app_cfg,
			rcvd_app_sub_tlv->app_cfg,
			(rcvd_pfc_sub_tlv->header.length + TLV_HEADER_LENGTH - FEAT_TLV_HDR_SIZE));	

		/*set feature state machine - app */
		feature->app.rx_feature_enabled = remote_port->app.header.en;
		feature->app.rx_feature_present = TRUE;
		feature->app.rx_feature_oper_version =
		      	remote_port->app.header.oper_version;
		feature->app.rx_feature_max_version =
	      		remote_port->app.header.max_version;
		feature->app.rx_feature_willing = remote_port->app.header.w;
		feature->app.rx_error = remote_port->app.header.er;
		feature->app.rx_feature_cfg.app.app_tbl_entries =
			(rcvd_pfc_sub_tlv->header.length + TLV_HEADER_LENGTH - FEAT_TLV_HDR_SIZE) / CEE_APP_PRIO_TABLE_SIZE;
		memcpy (&feature->app.rx_feature_cfg.app.app_tbl,
		    	&remote_port->app.app_cfg,
			FEAT_APP_CFG_SIZE(rcvd_pfc_sub_tlv->header.length));
	} else {
		feature->app.rx_feature_present = FALSE;
		feature->app.rx_feature_enabled = 0;
		feature->app.rx_feature_oper_version = 0;
		feature->app.rx_feature_max_version = 0;
		feature->app.rx_feature_willing = 0;
		feature->app.rx_error = 0;
		feature->app.rx_feature_cfg.app.app_tbl_entries = 0;
		memset (&feature->app.rx_feature_cfg.app.app_tbl,
		    	0, FEAT_APP_CFG_SIZE(84));
	}

	if (rcvd_cntrl_sub_tlv) {
		remote_port->control.type = rcvd_cntrl_sub_tlv->type;
		remote_port->control.type = rcvd_cntrl_sub_tlv->type;
		remote_port->control.length = rcvd_cntrl_sub_tlv->length;
		remote_port->control.oper_version = rcvd_cntrl_sub_tlv->oper_version;
		remote_port->control.max_version = rcvd_cntrl_sub_tlv->max_version;
		remote_port->control.seqno = rcvd_cntrl_sub_tlv->seqno;
		remote_port->control.ackno = rcvd_cntrl_sub_tlv->ackno;

		control->rxseqno = remote_port->control.seqno;
		control->rxackno = remote_port->control.ackno;
		control->rx_oper_version = remote_port->control.oper_version;
		control->rx_max_version = remote_port->control.max_version;

		control->something_changed_remote = TRUE;
		control->no_dcbxtlv_received = FALSE;

	 	/* run the state machine */
	 	cvmcs_dcbx_cee_cntrl_sm_run (port_num);	
	}

end:
	cvmx_spinlock_unlock(&octnic->dcb[port_num].dcbx_cfg.lock);
	return;
}

uint8_t cvmcs_dcbx_cee_current_param(uint8_t port_num,
				  struct oct_nic_dcbx_info *current_dcbx_info)
{
	struct feature_sm_variables *feature =
		&octnic->dcb[port_num].dcbx_cfg.dcbx_cee.feature_sm_var;
	struct feature_pg_cfg *current_pg;
	struct feature_pfc_cfg *current_pfc;
	struct feature_app_cfg *current_app;
	struct oct_nic_dcbx_config *oper_dcbx_cfg = &current_dcbx_info->operational;
	struct oct_nic_dcbx_config *remote_dcbx_cfg = &current_dcbx_info->remote;

	current_dcbx_info->dcbx_version = DCBX_CEE;

	if (feature->pfc.flags & OPER_PARAM_CHANGE) {
		current_pfc = &feature->pfc.oper_cfg.pfc;

		current_dcbx_info->flags |= DCB_FLAG_OPER_PFC;

		if (feature->pfc.enabled)
			oper_dcbx_cfg->pfc_config.pfc_flags |= DCBX_FLAG_ENABLED;
		if (feature->pfc.willing)
			oper_dcbx_cfg->pfc_config.pfc_flags |= DCBX_FLAG_WILLING;
		if (feature->pfc.error)
			oper_dcbx_cfg->pfc_config.pfc_flags |= DCBX_FLAG_ERROR;

		oper_dcbx_cfg->pfc_config.pfc_enable =
			current_pfc->pfc_enable;
		oper_dcbx_cfg->pfc_config.pfc_capability =
	 	     	current_pfc->num_tcpfc_supported;
	}

	if (feature->pfc.flags & REMOTE_PARAM_CHANGE) {
		current_pfc = &feature->pfc.peer_cfg.pfc;

		current_dcbx_info->flags |= DCB_FLAG_REMOTE_PFC;

		if (feature->pfc.rx_feature_enabled)
			remote_dcbx_cfg->pfc_config.pfc_flags |= DCBX_FLAG_ENABLED;
		if (feature->pfc.rx_feature_willing)
			remote_dcbx_cfg->pfc_config.pfc_flags |= DCBX_FLAG_WILLING;
		if (feature->pfc.rx_error)
			remote_dcbx_cfg->pfc_config.pfc_flags |= DCBX_FLAG_ERROR;

		remote_dcbx_cfg->pfc_config.pfc_enable =
			 current_pfc->pfc_enable;
		remote_dcbx_cfg->pfc_config.pfc_capability =
	 	     	current_pfc->num_tcpfc_supported;
	}

	if (feature->pg.flags & OPER_PARAM_CHANGE) {
		current_pg = &feature->pg.oper_cfg.pg;

		current_dcbx_info->flags |= DCB_FLAG_OPER_ETS;

		if (feature->pg.enabled)
			oper_dcbx_cfg->ets_config.ets_flags |= DCBX_FLAG_ENABLED;
		if (feature->pg.willing)
			oper_dcbx_cfg->ets_config.ets_flags |= DCBX_FLAG_WILLING;
		if (feature->pg.error)
			oper_dcbx_cfg->ets_config.ets_flags |= DCBX_FLAG_ERROR;

		oper_dcbx_cfg->ets_config.num_traffic_classes =
		      	current_pg->num_tcs_supported;
		memcpy(oper_dcbx_cfg->ets_config.cee.pg_bw,
			current_pg->pg_percentage, 8);

		oper_dcbx_cfg->ets_config.cee.pgid[0] = current_pg->pgid_0;
		oper_dcbx_cfg->ets_config.cee.pgid[1] = current_pg->pgid_1;
		oper_dcbx_cfg->ets_config.cee.pgid[2] = current_pg->pgid_2;
		oper_dcbx_cfg->ets_config.cee.pgid[3] = current_pg->pgid_3;
		oper_dcbx_cfg->ets_config.cee.pgid[4] = current_pg->pgid_4;
		oper_dcbx_cfg->ets_config.cee.pgid[5] = current_pg->pgid_5;
		oper_dcbx_cfg->ets_config.cee.pgid[6] = current_pg->pgid_6;
		oper_dcbx_cfg->ets_config.cee.pgid[7] = current_pg->pgid_7;
	}

	if (feature->pg.flags & REMOTE_PARAM_CHANGE) {
		current_pg = &feature->pg.peer_cfg.pg;

		current_dcbx_info->flags |= DCB_FLAG_REMOTE_ETS;

		if (feature->pg.rx_feature_enabled)
			remote_dcbx_cfg->ets_config.ets_flags |= DCBX_FLAG_ENABLED;
		if (feature->pg.rx_feature_willing)
			remote_dcbx_cfg->ets_config.ets_flags |= DCBX_FLAG_WILLING;
		if (feature->pg.rx_error)
			remote_dcbx_cfg->ets_config.ets_flags |= DCBX_FLAG_ERROR;

		remote_dcbx_cfg->ets_config.num_traffic_classes =
		      	current_pg->num_tcs_supported;
		memcpy(remote_dcbx_cfg->ets_config.cee.pg_bw,
			current_pg->pg_percentage, 8);

		remote_dcbx_cfg->ets_config.cee.pgid[0] = current_pg->pgid_0;
		remote_dcbx_cfg->ets_config.cee.pgid[1] = current_pg->pgid_1;
		remote_dcbx_cfg->ets_config.cee.pgid[2] = current_pg->pgid_2;
		remote_dcbx_cfg->ets_config.cee.pgid[3] = current_pg->pgid_3;
		remote_dcbx_cfg->ets_config.cee.pgid[4] = current_pg->pgid_4;
		remote_dcbx_cfg->ets_config.cee.pgid[5] = current_pg->pgid_5;
		remote_dcbx_cfg->ets_config.cee.pgid[6] = current_pg->pgid_6;
		remote_dcbx_cfg->ets_config.cee.pgid[7] = current_pg->pgid_7;
	}

	if (feature->app.flags & REMOTE_PARAM_CHANGE) {
		int i;
		current_app = feature->app.peer_cfg.app.app_tbl;

		current_dcbx_info->flags |= DCB_FLAG_REMOTE_APP;

		if (feature->app.rx_feature_enabled)
			remote_dcbx_cfg->app_config.app_flags |= DCBX_FLAG_ENABLED;
		if (feature->app.rx_feature_willing)
			remote_dcbx_cfg->app_config.app_flags |= DCBX_FLAG_WILLING;
		if (feature->app.rx_error)
			remote_dcbx_cfg->app_config.app_flags |= DCBX_FLAG_ERROR;

		remote_dcbx_cfg->app_config.num_app_prio =
			feature->app.peer_cfg.app.app_tbl_entries;

		for (i = 0; i < feature->app.peer_cfg.app.app_tbl_entries; i++) {
			remote_dcbx_cfg->app_config.app_prio[i].protocol_id =
				current_app[i].protocol;
			remote_dcbx_cfg->app_config.app_prio[i].selector =
				current_app[i].sel;
			remote_dcbx_cfg->app_config.app_prio[i].priority =
				current_app[i].priority;
		}
	}

	if ((feature->pg.flags & REMOTE_PARAM_SHUTDOWN) &&
	    (feature->pfc.flags & REMOTE_PARAM_SHUTDOWN) &&
	    (feature->app.flags & REMOTE_PARAM_SHUTDOWN)) {
		current_dcbx_info->flags |= DCB_FLAG_REMOTE_SHUTDOWN;
	}

	feature->pg.flags = 0;
	feature->pfc.flags = 0;
	feature->app.flags = 0;

	return 0;
}

uint8_t cvmcs_dcbx_cee_set_default_params(uint8_t port_num)
{
	int i;
	struct oct_nic_dcbx_config *def_config =
		&octnic->dcb[port_num].dcbx_def_cfg.dcbx_cee;
	struct feature_sm_variables *fea_sm_var =
		 &octnic->dcb[port_num].dcbx_cfg.dcbx_cee.feature_sm_var;
	
	/*Initialize the feature state machine variable */
  	fea_sm_var->pg.local_param_enabled = 
		!!(def_config->ets_config.ets_flags & DCBX_FLAG_ENABLED);

  	fea_sm_var->pg.local_param_willing =
		!!(def_config->ets_config.ets_flags & DCBX_FLAG_WILLING);

  	fea_sm_var->pg.local_param_advertise = TRUE;

  	fea_sm_var->pg.local_param_cfg.pg.num_tcs_supported =
    		def_config->ets_config.num_traffic_classes;

  	memcpy (fea_sm_var->pg.local_param_cfg.pg.pg_percentage,
		def_config->ets_config.cee.pg_bw, 8);

	fea_sm_var->pg.local_param_cfg.pg.pgid_0 =
		def_config->ets_config.cee.pgid[0];
	fea_sm_var->pg.local_param_cfg.pg.pgid_1 =
		def_config->ets_config.cee.pgid[1];
	fea_sm_var->pg.local_param_cfg.pg.pgid_2 =
		def_config->ets_config.cee.pgid[2];
	fea_sm_var->pg.local_param_cfg.pg.pgid_3 =
		def_config->ets_config.cee.pgid[3];
	fea_sm_var->pg.local_param_cfg.pg.pgid_4 =
		def_config->ets_config.cee.pgid[4];
	fea_sm_var->pg.local_param_cfg.pg.pgid_5 =
		def_config->ets_config.cee.pgid[5];
	fea_sm_var->pg.local_param_cfg.pg.pgid_6 =
		def_config->ets_config.cee.pgid[6];
	fea_sm_var->pg.local_param_cfg.pg.pgid_7 =
		def_config->ets_config.cee.pgid[7];

  	fea_sm_var->pfc.local_param_enabled =
		!!(def_config->pfc_config.pfc_flags & DCBX_FLAG_ENABLED);

  	fea_sm_var->pfc.local_param_willing =
		!!(def_config->pfc_config.pfc_flags & DCBX_FLAG_WILLING);

  	fea_sm_var->pfc.local_param_advertise = TRUE;

  	fea_sm_var->pfc.local_param_cfg.pfc.num_tcpfc_supported =
    		def_config->pfc_config.pfc_capability;
  	fea_sm_var->pfc.local_param_cfg.pfc.pfc_enable =
    		def_config->pfc_config.pfc_enable;

  	fea_sm_var->app.local_param_enabled =
		!!(def_config->app_config.app_flags & DCBX_FLAG_ENABLED);

  	fea_sm_var->app.local_param_willing =
		!!(def_config->app_config.app_flags & DCBX_FLAG_WILLING);

  	fea_sm_var->app.local_param_advertise = TRUE;

	for (i = 0; i < def_config->app_config.num_app_prio; i++) {
		fea_sm_var->app.local_param_cfg.app.app_tbl[i].protocol =
			def_config->app_config.app_prio[i].protocol_id;
		fea_sm_var->app.local_param_cfg.app.app_tbl[i].oui_h = INTEL_OUI_0;
		fea_sm_var->app.local_param_cfg.app.app_tbl[i].sel =
			def_config->app_config.app_prio[i].selector;
		fea_sm_var->app.local_param_cfg.app.app_tbl[i].oui_l =
			(INTEL_OUI_1 << 8) | INTEL_OUI_2;
		fea_sm_var->app.local_param_cfg.app.app_tbl[i].priority =
			def_config->app_config.app_prio[i].priority;
	}

	fea_sm_var->app.local_param_cfg.app.app_tbl_entries =
			def_config->app_config.num_app_prio;

  	return 0;
}

/** Handles the set calls from host
 *
 * @param port_num      physical port number
 * @param dcbx_cmd      Command received from the host
 *
 */
int cvmcs_dcbx_cee_set_params(int port_num, struct oct_nic_dcbx_cmd *dcbx_cmd)
{
	dcbx_config_t *dcbx = &octnic->dcb[port_num].dcbx_cfg;
	struct feature_sm_variables *fea_sm_var = &dcbx->dcbx_cee.feature_sm_var;

	if (dcbx->remote_dcbx_ver) {
		if (dcbx->remote_dcbx_ver != dcbx_cmd->dcbx_version) {
			printf("DCBX Version Mistmatch\n");
			return 1;
		}
	} else {
		if (!octnic->dcb[port_num].dcbx_cee) {
			printf("DCBX Version Not Offloaded\n");
			return 1;
		}
		
		dcbx->oper_dcbx_ver = DCBX_CEE;
	}

	cvmx_spinlock_lock(&octnic->dcb[port_num].dcbx_cfg.lock);

	if( dcbx_cmd->cmd & DCBX_CMD_SET_ETS ) {
		fea_sm_var->pg.local_param_enabled =
			!!(dcbx_cmd->config.ets_config.ets_flags & DCBX_FLAG_ENABLED);
		fea_sm_var->pg.local_param_willing =
			!!(dcbx_cmd->config.ets_config.ets_flags & DCBX_FLAG_WILLING);
		fea_sm_var->pg.local_param_advertise = TRUE;
		/* Copy pg_bw,pgid,num_traffic_classes of host config info local_param_cfg */
		memcpy (fea_sm_var->pg.local_param_cfg.pg.pg_percentage,
			dcbx_cmd->config.ets_config.cee.pg_bw, 8);

		fea_sm_var->pg.local_param_cfg.pg.pgid_0 =
			dcbx_cmd->config.ets_config.cee.pgid[0];
		fea_sm_var->pg.local_param_cfg.pg.pgid_1 =
			dcbx_cmd->config.ets_config.cee.pgid[1];
		fea_sm_var->pg.local_param_cfg.pg.pgid_2 =
			dcbx_cmd->config.ets_config.cee.pgid[2];
		fea_sm_var->pg.local_param_cfg.pg.pgid_3 =
			dcbx_cmd->config.ets_config.cee.pgid[3];
		fea_sm_var->pg.local_param_cfg.pg.pgid_4 =
			dcbx_cmd->config.ets_config.cee.pgid[4];
		fea_sm_var->pg.local_param_cfg.pg.pgid_5 =
			dcbx_cmd->config.ets_config.cee.pgid[5];
		fea_sm_var->pg.local_param_cfg.pg.pgid_6 =
			dcbx_cmd->config.ets_config.cee.pgid[6];
		fea_sm_var->pg.local_param_cfg.pg.pgid_7 =
			dcbx_cmd->config.ets_config.cee.pgid[7];

		fea_sm_var->pg.local_param_cfg.pg.num_tcs_supported = 
			dcbx_cmd->config.ets_config.num_traffic_classes;

		/*Setup state for feature state machine */
		fea_sm_var->pg.local_parameter_change = TRUE;
	}

	if(dcbx_cmd->cmd & DCBX_CMD_SET_PFC) {
		/*Initialize feature stmc pfc cfg from host info */
		fea_sm_var->pfc.local_param_enabled =
			!!(dcbx_cmd->config.pfc_config.pfc_flags & DCBX_FLAG_ENABLED);
		fea_sm_var->pfc.local_param_willing =
			!!(dcbx_cmd->config.pfc_config.pfc_flags & DCBX_FLAG_WILLING);
		fea_sm_var->pfc.local_param_advertise = TRUE;

		fea_sm_var->pfc.local_param_cfg.pfc.num_tcpfc_supported =
			dcbx_cmd->config.pfc_config.pfc_capability;
		fea_sm_var->pfc.local_param_cfg.pfc.pfc_enable =
			dcbx_cmd->config.pfc_config.pfc_enable;

		/*Setup state for feature state machine */
		fea_sm_var->pfc.local_parameter_change = TRUE;
	}

	if(dcbx_cmd->cmd & DCBX_CMD_SET_APP) {
		int i;

		/*Initialize feature stmc app cfg from host info */
		fea_sm_var->app.local_param_enabled =
			!!(dcbx_cmd->config.app_config.app_flags & DCBX_FLAG_ENABLED);
		fea_sm_var->app.local_param_willing =
			!!(dcbx_cmd->config.app_config.app_flags & DCBX_FLAG_WILLING);
		fea_sm_var->app.local_param_advertise = TRUE;

		for (i = 0; i < dcbx_cmd->config.app_config.num_app_prio; i++) {
			fea_sm_var->app.local_param_cfg.app.app_tbl[i].protocol =
				dcbx_cmd->config.app_config.app_prio[i].protocol_id;
			fea_sm_var->app.local_param_cfg.app.app_tbl[i].oui_h = INTEL_OUI_0;
			fea_sm_var->app.local_param_cfg.app.app_tbl[i].sel =
				dcbx_cmd->config.app_config.app_prio[i].selector;
			fea_sm_var->app.local_param_cfg.app.app_tbl[i].oui_l =
				(INTEL_OUI_1 << 8) | INTEL_OUI_2;
			fea_sm_var->app.local_param_cfg.app.app_tbl[i].priority =
				dcbx_cmd->config.app_config.app_prio[i].priority;
		}

		fea_sm_var->app.local_param_cfg.app.app_tbl_entries =
			dcbx_cmd->config.app_config.num_app_prio;

		/*Setup state for feature state machine */
		fea_sm_var->app.local_parameter_change = TRUE;
	}

	if (dcbx->remote_dcbx_ver == DCBX_UNKNOWN){
		cvmcs_dcbx_cee_config(port_num);
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
void cvmcs_dcbx_cee_get_params(int port_num, struct oct_nic_dcbx_config *dcbx_config)
{
	int i;
	struct dcbx_cee_config *dcbx_cee = 
		&octnic->dcb[port_num].dcbx_cfg.dcbx_cee;
	struct feature_sm_variables *fea_sm_var = &dcbx_cee->feature_sm_var;

	dcbx_config->pfc_config.pfc_flags = 0;

	if (fea_sm_var->pfc.local_param_enabled)
		dcbx_config->pfc_config.pfc_flags |= DCBX_FLAG_ENABLED;

	if (fea_sm_var->pfc.local_param_willing)
		dcbx_config->pfc_config.pfc_flags |= DCBX_FLAG_WILLING;

	dcbx_config->pfc_config.pfc_capability =
  		fea_sm_var->pfc.local_param_cfg.pfc.num_tcpfc_supported;

	dcbx_config->pfc_config.pfc_enable =
  		fea_sm_var->pfc.local_param_cfg.pfc.pfc_enable;


	dcbx_config->ets_config.ets_flags = 0;

  	if (fea_sm_var->pg.local_param_enabled)
		dcbx_config->ets_config.ets_flags |= DCBX_FLAG_ENABLED;

  	if (fea_sm_var->pg.local_param_willing)
		dcbx_config->ets_config.ets_flags |= DCBX_FLAG_WILLING;

	dcbx_config->ets_config.num_traffic_classes =
  		fea_sm_var->pg.local_param_cfg.pg.num_tcs_supported;

  	memcpy (dcbx_config->ets_config.cee.pg_bw,
		fea_sm_var->pg.local_param_cfg.pg.pg_percentage,
		8);

	dcbx_config->ets_config.cee.pgid[0] = 
		fea_sm_var->pg.local_param_cfg.pg.pgid_0;

	dcbx_config->ets_config.cee.pgid[1] = 
		fea_sm_var->pg.local_param_cfg.pg.pgid_1;

	dcbx_config->ets_config.cee.pgid[2] = 
		fea_sm_var->pg.local_param_cfg.pg.pgid_2;

	dcbx_config->ets_config.cee.pgid[3] = 
		fea_sm_var->pg.local_param_cfg.pg.pgid_3;

	dcbx_config->ets_config.cee.pgid[4] = 
		fea_sm_var->pg.local_param_cfg.pg.pgid_4;

	dcbx_config->ets_config.cee.pgid[5] = 
		fea_sm_var->pg.local_param_cfg.pg.pgid_5;

	dcbx_config->ets_config.cee.pgid[6] = 
		fea_sm_var->pg.local_param_cfg.pg.pgid_6;

	dcbx_config->ets_config.cee.pgid[7] = 
		fea_sm_var->pg.local_param_cfg.pg.pgid_7;

	if (fea_sm_var->app.local_param_enabled)
		dcbx_config->app_config.app_flags |= DCBX_FLAG_ENABLED;

	if (fea_sm_var->app.local_param_willing)
		dcbx_config->app_config.app_flags |= DCBX_FLAG_WILLING;

	dcbx_config->app_config.num_app_prio =
		fea_sm_var->app.local_param_cfg.app.app_tbl_entries;

	for (i = 0; i < dcbx_config->app_config.num_app_prio; i++) {
		dcbx_config->app_config.app_prio[i].protocol_id =
			fea_sm_var->app.local_param_cfg.app.app_tbl[i].protocol;
		dcbx_config->app_config.app_prio[i].selector =
			fea_sm_var->app.local_param_cfg.app.app_tbl[i].sel;
		dcbx_config->app_config.app_prio[i].priority =
			fea_sm_var->app.local_param_cfg.app.app_tbl[i].priority;
	}
}
