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

/**  Initialize constant fields DCBx structure
 *
 * @param port_num  physical port number
 */
int cvmcs_dcbx_enable(int ifidx)
{
	int 			port_num = octnic->port[ifidx].gmxport_id;
	struct default_tlvs	*d_tlv;
	dcbx_config_t		*dcbx = &octnic->dcb[port_num].dcbx_cfg;
	cvmx_wqe_t              *timer_wqe = NULL;
	cvmx_raw_inst_front_t   *front;

	if (OCT_NIC_IS_VF(ifidx) ||
	    !octnic->dcb[port_num].dcb_enabled ||
	    !octnic->dcb[port_num].dcbx_offload ||
	    (cvmx_atomic_get32((int32_t *)&dcbx->port.admin_status) != disabled))
		return 0;

	/* Add Destination MAC Address*/
	dcbx->eth_hddr.dest_addr[0] = MULTICAST_ADDR_0;
	dcbx->eth_hddr.dest_addr[1] = MULTICAST_ADDR_1;
	dcbx->eth_hddr.dest_addr[2] = MULTICAST_ADDR_2;
	dcbx->eth_hddr.dest_addr[3] = MULTICAST_ADDR_3;
	dcbx->eth_hddr.dest_addr[4] = MULTICAST_ADDR_4;
	dcbx->eth_hddr.dest_addr[5] = MULTICAST_ADDR_5;

	/*Add source MAC address*/
	memcpy(dcbx->eth_hddr.source_addr,
	       (((uint8_t *)&octnic->gmx_port_info[port_num].hw_base_addr) + 2), 6);

	/* Add Ethertype*/
	dcbx->eth_hddr.ether_type = 0x88cc;

	d_tlv = &dcbx->default_tlv;
	d_tlv->chassis_id.type		= CHASSIS_ID_TLV_TYPE;
	d_tlv->chassis_id.length	= CHASSIS_ID_TLV_LENGTH;
	d_tlv->chassis_id.sub_type	= CHASSIS_ID_SUB_TYPE;
	memcpy(d_tlv->chassis_id.chassis_id, dcbx->eth_hddr.source_addr, 6);

	d_tlv->port_id.type 		= PORT_ID_TLV_TYPE;
	d_tlv->port_id.length		= PORT_ID_TLV_LENGTH;
	d_tlv->port_id.sub_type		= PORT_ID_SUB_TYPE;
	memcpy(d_tlv->port_id.port_id, dcbx->eth_hddr.source_addr, 6);

	/* initializing ttl tlv */
	d_tlv->ttl.type 		= TTL_TLV_TYPE;
	d_tlv->ttl.length 		= TTL_TLV_LENGTH ;
	d_tlv->ttl.ttl			= (DEFAULT_TX_INTERVAL * DEFAULT_TX_HOLD) + 1;

	/* initialize the end of lldp */
	d_tlv->endof_lldp.type 		= END_OF_LLDP_TLV_TYPE;
	d_tlv->endof_lldp.length	= END_OF_LLDP_LENGTH;

	/* initialize QCN tlv */
	d_tlv->cn_tlv.type 		= CONGESTION_TLV_TYPE;
	d_tlv->cn_tlv.length 		= CONGESTION_TLV_LENGTH;
	d_tlv->cn_tlv.oui[0] 		= CONGESTION_TLV_OUI0;
	d_tlv->cn_tlv.oui[1] 		= CONGESTION_TLV_OUI1;
	d_tlv->cn_tlv.oui[2] 		= CONGESTION_TLV_OUI2;
	d_tlv->cn_tlv.sub_type 		= CONGESTION_TLV_SUBTYPE;
	d_tlv->cn_tlv.per_prio_cnpv_indicator	= CONGESTION_TLV_CNPV;
	d_tlv->cn_tlv.per_prio_ready_indicator 	= CONGESTION_TLV_READY;

	octnic->dcb[port_num].dcbx_cfg.timer_flag 	= True;

	/* Intialize the LLDP SM variables for initialization LLDP SM*/
	cvmx_atomic_set32((int32_t *)&dcbx->port.tx.local_change, (int32_t) True);
	cvmx_atomic_set32((int32_t *)&dcbx->port.port_enabled, (int32_t)True);
	cvmx_atomic_set32((int32_t *)&dcbx->port.admin_status, (int32_t)enabled_rx_tx);

	/*Create WQE for running the LLDP state machines */
	timer_wqe =  (cvmx_wqe_t *)cvmcs_wqe_alloc();
	if(timer_wqe == NULL)
	{
		printf(" Error5: failed to allocate memory to timer wqe \n");
		return 1;
	}

	front = (cvmx_raw_inst_front_t *)cvmx_fpa_alloc(CVMX_FPA_PACKET_POOL);
	if(front == NULL) {
		printf("Failed to allocate memory to Front \n");
		cvmcs_wqe_free(timer_wqe);
		return 1;
	}

	memset(front, 0, sizeof(cvmx_raw_inst_front_t));

	front->irh.s.opcode     = OPCODE_NIC;
	front->irh.s.subcode    = OPCODE_NIC_DCBX_TIMER;
	front->irh.s.ossp       = port_num;

	cvmx_wqe_set_port(timer_wqe, octnic->port[octnic->dcb[port_num].ifidx].iq_base);
	cvmx_wqe_set_soft(timer_wqe, 1);
	cvmx_wqe_set_tt(timer_wqe, CVMX_POW_TAG_TYPE_ATOMIC);

	/*Setting the initial state of Tx timer,Tx, Rx state machines */
	dcbx->port.tx.state     = TX_BEGIN;
	dcbx->port.rx.state     = RX_BEGIN;
	dcbx->port.timer.state  = TX_TIMER_BEGIN;

	timer_wqe->packet_ptr.s.addr = CVM_DRV_GET_PHYS(front);

	/* submit wqe to SSO */
	cvmx_pow_work_submit(timer_wqe, cvmx_wqe_get_tag(timer_wqe),
		cvmx_wqe_get_tt(timer_wqe), cvmx_wqe_get_qos(timer_wqe),
		cvmx_wqe_get_grp(timer_wqe));

	return 0;
}

/**  Disable DCBx
 *
 * @param port_num  physical port number
 */
void cvmcs_dcbx_disable(int ifidx)
{
	int port_num = octnic->port[ifidx].gmxport_id;
	dcbx_config_t *dcbx = &octnic->dcb[port_num].dcbx_cfg;

	if (OCT_NIC_IS_VF(ifidx) ||
	    !octnic->dcb[port_num].dcb_enabled ||
	    (cvmx_atomic_get32((int32_t *)&dcbx->port.admin_status) == disabled))
		return;

	cvmx_atomic_set32((int32_t *)&dcbx->port.admin_status, (int32_t)disabled);

	cvmx_spinlock_lock(&octnic->dcb[port_num].dcbx_cfg.lock);

	if (octnic->dcb[port_num].dcbx_cfg.oper_dcbx_ver == DCBX_IEEE) {
		cvmcs_dcbx_ieee_config(port_num);
	}
	else {
		cvmcs_dcbx_cee_config(port_num);
	}

	cvmx_spinlock_unlock(&octnic->dcb[port_num].dcbx_cfg.lock);

	return ;
}

/**  Send DCBx LLDP frame to remote peer
 *
 * @param port_num	physical port number
 * @param *lldp_port		pointer to lldp_sm_attr_t
 *
  * @return Returns 0 on success, 1 on error.
 */
uint8_t cvmcs_dcbx_tx_frame(uint8_t port_num, lldp_sm_attr_t *lldp_port)
{
	int port, queue;
	cvmx_pko_send_hdr_t hdr_s;
	cvmx_pko_query_rtn_t pko_status;
	unsigned node, dq, nwords;
	unsigned scr_base = cvmx_pko3_lmtdma_scr_base();
	cvmx_pko_buf_ptr_t send;

	port = octnic->gmx_port_info[port_num].ipd_port;

        if (octeon_has_feature(OCTEON_FEATURE_PKND))
                queue = cvmx_pko_get_base_queue_pkoid(port);
        else
                queue = cvmx_pko_get_base_queue(port);

	dq = queue;

	node = dq >> 10;
	dq &= (1 << 10)-1;

	/* Fill in header */
	hdr_s.u64 = 0;
	hdr_s.s.total = lldp_port->tx.sizeout;
	hdr_s.s.df = 0;
	hdr_s.s.ii = 0;
        if(OCTEON_IS_MODEL(OCTEON_CN78XX_PASS1_X))
                hdr_s.s.n2 = 0; /* L2 allocate everything */
        else
                hdr_s.s.n2 = 1; /* No L2 allocate works faster */
        hdr_s.s.aura = 
#ifdef __LITTLE_ENDIAN_BITFIELD
        hdr_s.s.le = 1;
#endif

	nwords = 0;
        cvmx_scratch_write64(scr_base+sizeof(uint64_t)*(nwords++), hdr_s.u64);

        send.u64 = 0;
        send.s.addr = cvmx_ptr_to_phys(lldp_port->tx.frameout);
        send.s.size = lldp_port->tx.sizeout;
        send.s.subdc3 = CVMX_PKO_SENDSUBDC_GATHER;
        cvmx_scratch_write64(scr_base+sizeof(uint64_t)*(nwords++), send.u64);

	lldp_port->tx.frameout = NULL;
	lldp_port->tx.sizeout = 0;

        CVMX_SYNCWS;

        /* Do LMTDMA */
	pko_status = cvmcs_pko3_lmtdma(node, dq, nwords, true, false);

        if (cvmx_unlikely(pko_status.s.dqstatus != PKO_DQSTATUS_PASS)) {
                return 1;
        }

	return 0;
}

/**  Finds the remote peer DCBx version
 *
 * @param *wqe		work queue entry
 *
 * @return Returns 0 on success, 1 on error.
 */
uint8_t  cvmcs_dcbx_auto_negotiation (cvmx_wqe_t  *wqe )
{
	tlv_hdr_t *tlv_hdr;
	uint8_t  port_num;
  	uint8_t	 dcbx_frame	= 0;
	void     *frame 	= (void *)cvmx_phys_to_ptr(wqe->packet_ptr.s.addr);
	/* Skip ethernet header */
  	uint8_t * tlv_offset 	= frame + ETHER_HDR_LENGTH;
  	uint32_t oui 		= 0;
	uint8_t subtype 	= 0;
	uint16_t  tlv_type 	= 0, tlv_length = 0;
	uint16_t *ttl;

	port_num = get_gmx_port_id(cvmx_wqe_get_port(wqe));

	if (!octnic->dcb[port_num].dcbx_offload)
		return 1;

  	while(1) {
		tlv_type = 0 , tlv_length  = 0;
		tlv_hdr = (tlv_hdr_t *)tlv_offset;
		tlv_type = tlv_hdr->type;
		tlv_length = tlv_hdr->length;
		if(tlv_type == END_OF_LLDP_TLV_TYPE) {
			/* Frame reading completed */
			break;
		}
		if(tlv_type == TTL_TLV_TYPE) {
			tlv_offset += TLV_HEADER_LENGTH;
			ttl = (uint16_t*)tlv_offset;
			if(*ttl == 0) {
				/* Peer LLDP is shutting down */
				break;
			}
			tlv_offset += tlv_length;
			continue;
		}/*End of if(tlv_type == TTL_TLV_TYPE) */
		if(tlv_type != ORGANIZATIONALLY_SPECIFIC_TLV_TYPE) {
			tlv_offset += tlv_length +  TLV_HEADER_LENGTH;
			continue;
		}
		tlv_offset += TLV_HEADER_LENGTH;
		memcpy(&oui, tlv_offset , OUI_LENGTH);
		oui = oui>>8;
		tlv_offset += OUI_LENGTH;
		switch(oui) {
			case IEEE_OUI: /*Read subtype */
				if (!octnic->dcb[port_num].dcbx_ieee)
					break;
				memcpy(&subtype, tlv_offset, 1);
				if (octnic->dcb[port_num].dcbx_cfg.oper_dcbx_ver != DCBX_IEEE) {
					octnic->dcb[port_num].dcbx_cfg.oper_dcbx_ver = DCBX_IEEE;
					cvmx_spinlock_lock(&octnic->dcb[port_num].dcbx_cfg.lock);
					cvmcs_dcbx_ieee_config(port_num);
					cvmx_spinlock_unlock(&octnic->dcb[port_num].dcbx_cfg.lock);
				}
				octnic->dcb[port_num].dcbx_cfg.remote_dcbx_ver = DCBX_IEEE;
				switch(subtype) {
					case ETS_CONFIGURATION:
					case ETS_RECOMMENDATION:
					case PFC_CONFIGURATION :
					case APPLICATION_PRIORITY:
					case CONGESTION_TLV_SUBTYPE:
						dcbx_frame = 1;

						cvmcs_dcbx_ieee_rx_frame(port_num, wqe);
						return 0;
					default:
						tlv_offset += (tlv_length - OUI_LENGTH);
				}
				break;

			case INTEL_OUI: /* Read the subtype */
				memcpy( &subtype, tlv_offset,1);
				switch(subtype)
				{
					case DCBX_CEE_SUBTYPE :
						if (!octnic->dcb[port_num].dcbx_cee)
							break;
						if (octnic->dcb[port_num].dcbx_cfg.oper_dcbx_ver != DCBX_CEE) {
							octnic->dcb[port_num].dcbx_cfg.oper_dcbx_ver = DCBX_CEE;
							cvmx_spinlock_lock(&octnic->dcb[port_num].dcbx_cfg.lock);
							cvmcs_dcbx_cee_config(port_num);
							cvmx_spinlock_unlock(&octnic->dcb[port_num].dcbx_cfg.lock);
						}
						octnic->dcb[port_num].dcbx_cfg.remote_dcbx_ver = DCBX_CEE;
						dcbx_frame = 1;

						cvmcs_dcbx_cee_rx_frame(port_num, wqe);
						break;

					case DCBX_CIN_SUBTYPE :
						//Unsupported DCBx version drop packet
						break;

					default :
						printf("Error1: In %s \n ",__func__);
				}
				break;
			default :
				tlv_offset += (tlv_length - OUI_LENGTH);
		} //End of switch(oui)
	}	// End of while loop

	if ((!dcbx_frame) &&
	    (octnic->dcb[port_num].dcbx_cfg.remote_dcbx_ver != DCBX_UNKNOWN)) {
		/* received lldp frame is not for DCBx */
		switch(octnic->dcb[port_num].dcbx_cfg.remote_dcbx_ver) {
			case DCBX_IEEE:
				cvmcs_dcbx_ieee_rx_shutdown(port_num);
				break;
			case DCBX_CEE:
				cvmcs_dcbx_cee_rx_shutdown(port_num);
				break;
			default:
				break;
		}

		octnic->dcb[port_num].dcbx_cfg.remote_dcbx_ver = DCBX_UNKNOWN;
		return 1;
	}

	return (!dcbx_frame);
}

/** Receive state machine(LLDP)
 *
 * @param port_num	physical port number	
 * @param *port		lldp_sm_attr_t variable address
 *
 */
void cvmcs_dcbx_rx_statemachine_run(uint8_t port_num, lldp_sm_attr_t *port)
{
	cvmcs_dcbx_rx_global_statemachine_run(port);
	do
	{
		switch(port->rx.state)
		{
			case LLDP_WAIT_PORT_OPERATIONAL:
				/* Do Nothing */
				break;

			case DELETE_AGED_INFO:
				cvmcs_dcbx_rx_delete_aged_info(port_num, port);
				break;

			case RX_LLDP_INITIALIZE:
				cvmcs_dcbx_rx_initialize_lldp(port_num, port);
				break;

			case RX_WAIT_FOR_FRAME:
				cvmcs_dcbx_rx_wait_for_frame(port_num, port);
				break;

			case RX_FRAME:
				cvmcs_dcbx_rx_frame( port_num, port);
				break;

			case DELETE_INFO:
				cvmcs_dcbx_rx_delete_info( port_num, port);
				break;

			case UPDATE_INFO:
				cvmcs_dcbx_rx_update_info(port);
				break;

			default:
				printf("ERROR: The RX State Machine is broken!\n");
		}
	} while (cvmcs_dcbx_rx_global_statemachine_run(port) == True);
}

/** Take cares of state transition of receive  state machine
 *
 * @param *port		lldp_sm_attr_t variable address
 *
 */
bool cvmcs_dcbx_rx_global_statemachine_run( lldp_sm_attr_t  *port)
{
	if ((port->rx.state == RX_BEGIN)||((port->rx.rx_info_age == False) &&
		((uint8_t)cvmx_atomic_get32((int32_t *)&port->port_enabled) == False))) {
		port->rx.state = LLDP_WAIT_PORT_OPERATIONAL;
		return True;
	}

	switch(port->rx.state) {
		case LLDP_WAIT_PORT_OPERATIONAL:
			if (port->rx.rx_info_age == True) {
				port->rx.state = DELETE_AGED_INFO;
				return True;
			}
			else if ((uint8_t)cvmx_atomic_get32(
				(int32_t *)&port->port_enabled) == True) {
				port->rx.state = RX_LLDP_INITIALIZE;
				return True;
			}
			return False;

		case DELETE_AGED_INFO:
			port->rx.state = LLDP_WAIT_PORT_OPERATIONAL;
			return True;

		case RX_LLDP_INITIALIZE:
			if(((uint8_t)cvmx_atomic_get32((int32_t *)&port->admin_status )
				== enabled_rx_tx) ||
				((uint8_t)cvmx_atomic_get32((int32_t *)&port->admin_status)
								== enabled_rx_only)) {
				port->rx.state = RX_WAIT_FOR_FRAME;
				return True;
			}
			return False;

		case RX_WAIT_FOR_FRAME:
			if (((uint8_t)cvmx_atomic_get32((int32_t *)&port->admin_status) 
									== disabled) ||
			((uint8_t)cvmx_atomic_get32((int32_t *)&port->admin_status) 
								== enabled_tx_only))
			{
				port->rx.state = RX_LLDP_INITIALIZE;
				return True;
			}
			if (port->rx.rx_info_age == True) {
				port->rx.state = DELETE_INFO;
				return True;
			} else if (cvmx_atomic_get32((int32_t *)&port->rx.rcv_frame)== True) {
				port->rx.state = RX_FRAME;
				return True;
			}
			return False;

		case DELETE_INFO:
			port->rx.state = RX_WAIT_FOR_FRAME;
			return True;

		case RX_FRAME:
			if (port->timer.rx_ttl == 0) {
				port->rx.state = DELETE_INFO;
				return True;
			} else if ((port->timer.rx_ttl != 0) && (port->rx.rx_changes == True)) {
				port->rx.state = UPDATE_INFO;
				return True;
			}
			port->rx.state = RX_WAIT_FOR_FRAME;
			return True;

		case UPDATE_INFO:
			port->rx.state = RX_WAIT_FOR_FRAME;
			return True;

		default:
			printf("ERROR: The RX State Machine is broken!\n");
			return False;
	}
}

void cvmcs_dcbx_rx_delete_aged_info(uint8_t port_num,
						lldp_sm_attr_t *port)
{
	cvmcs_dcbx_ieee_mib_delete_objects(port_num, port);
	port->rx.rx_info_age = False;
	port->rx.remote_change = True;
	return;
}

/** Initializes the  defaults values receive state machine variables
 *
 * @param port_num physical port number
 * @param port		lldp_sm_attr_t variable address
 *
 * @return Returns 0 on success, 1 on error.
 */
uint8_t cvmcs_dcbx_rx_initialize_lldp(uint8_t port_num, lldp_sm_attr_t *port)
{
	port->rx.too_many_neighbors 	= TOO_MANY_NEIGHBORS;
    	port->rx.rx_info_age	     	= RX_INFO_AGE;
	port->rx.rx_changes	     	= False;

     	cvmcs_dcbx_ieee_mib_delete_objects(port_num, port) ;

	if(port->rx.framein != NULL ) {
		cvm_free_wqe_wrapper(port->rx.framein);
		port->rx.framein =NULL;
	}

	cvmx_atomic_set32((int32_t *)&port->rx.rcv_frame, (int32_t) RCV_FRAME);
	return 0;
}

/** RX_WAIT_FOR_FRAME state of receive state machine
 *
 * @param port_num physical port number
 * @param port		lldp_sm_attr_t variable address
 *
 */
void cvmcs_dcbx_rx_wait_for_frame(uint8_t port_num, lldp_sm_attr_t*port)
{
	port->rx.rx_info_age 	= False;
	return;
}

/** RX_FRAME state of receive state machine
 *
 * @param port_num physical port number
 * @param port		lldp_sm_attr_t variable address
 *
 */
void cvmcs_dcbx_rx_frame(uint8_t port_num, lldp_sm_attr_t *port)
{
	dcbx_config_t *dcbx 	= &octnic->dcb[port_num].dcbx_cfg;

	port->rx.remote_change 	= False;
	port->rx.rx_changes 	= False;

	switch(dcbx->oper_dcbx_ver) {
		case DCBX_CEE :
			cvmcs_dcbx_cee_rx_process_frame(port_num, port);
			break;

		case DCBX_IEEE:
			cvmcs_dcbx_ieee_rx_process_frame(port_num, port);
			break;

		default:
			printf("Error in '  cvmcs_dcb_dcbx_rx_frame state ");
	}

	if(port->rx.framein != NULL ) {
		cvm_free_wqe_wrapper(port->rx.framein);
		port->rx.framein =NULL;
	}

	cvmx_atomic_set32(&port->rx.rcv_frame, FALSE);
	return;
}

/** RX_DELETE_INFO state of receive state machine
 *
 * @param port_num physical port number
 * @param port		lldp_sm_attr_t variable address
 *
 */
void  cvmcs_dcbx_rx_delete_info(uint8_t port_num, lldp_sm_attr_t *port)
{
	dcbx_config_t *dcbx 	= &octnic->dcb[port_num].dcbx_cfg;

	cvmcs_dcbx_ieee_mib_delete_objects(port_num, port);

	if (port->rx.framein) {
		cvm_free_wqe_wrapper(port->rx.framein);
		port->rx.framein = NULL;
	}

	port->rx.sizein = 0;
	port->rx.remote_change = True;

	switch(dcbx->oper_dcbx_ver) {
		case DCBX_CEE :
			cvmcs_dcbx_cee_something_changed_remote(port_num, port);
			break;

		case DCBX_IEEE:
			cvmcs_dcbx_ieee_something_changed_remote(port_num, port);
			break;

		default:
			printf("Error in '  cvmcs_dcb_dcbx_rx_frame state ");
	}

	return;
}

/** RX_UPDATE_INFO state of receive state machine
 *
 * @param port_num physical port number
 * @param port		lldp_sm_attr_t variable address
 *
 */
void cvmcs_dcbx_rx_update_info(lldp_sm_attr_t *port)
{
	port->rx.remote_change = True;
	return;
}

/** Transmit state machine
 *
 * @param port_num 	physical port number
  *
 */
void cvmcs_dcbx_tx_statemachine_run(uint8_t port_num)
{
	lldp_sm_attr_t *port =  &octnic->dcb[port_num].dcbx_cfg.port;

	cvmcs_dcbx_set_tx_state(port);

	do
	{
		switch(port->tx.state)
		{
			case TX_LLDP_INITIALIZE:
				cvmcs_dcbx_tx_initialize_lldp(port_num, port);
				break;

			case TX_IDLE:
				cvmcs_dcbx_tx_idle(port);
				break;

			case TX_SHUTDOWN_FRAME:
				cvmcs_dcbx_tx_shutdown_frame(port_num, port);
				break;

			case TX_INFO_FRAME:
				cvmcs_dcbx_tx_info_frame(port_num, port);
				break;

			default:
				printf("ERROR The TX State Machine is broken!\n");
		}
	} while (cvmcs_dcbx_set_tx_state(port) == True);

	return;
}

/** Performs  state transition of transmit state mahine
 *
 * @param port		lldp_sm_attr_t variable
 *
 */
bool cvmcs_dcbx_set_tx_state(lldp_sm_attr_t *port)
{
	if ((port->tx.state == TX_BEGIN) ||
		((uint8_t)cvmx_atomic_get32((int32_t *)&port->port_enabled) == False))
	{
		port->tx.state = TX_LLDP_INITIALIZE;
		return True;
	}

	switch (port->tx.state)
	{
		case TX_LLDP_INITIALIZE:
			if ( ((uint8_t)cvmx_atomic_get32(
				(int32_t *)&port->admin_status) == enabled_rx_tx) ||
				((uint8_t)cvmx_atomic_get32(
				(int32_t *)&port->admin_status) == enabled_tx_only)) {
				port->tx.state = TX_IDLE;
				return True;
			}
			return False;

		case TX_IDLE:
			if (((uint8_t)cvmx_atomic_get32(
				(int32_t *)&port->admin_status) == disabled) ||
				((uint8_t)cvmx_atomic_get32(
				(int32_t *)&port->admin_status) == enabled_rx_only)) {
				port->tx.state = TX_SHUTDOWN_FRAME;
				return True;
			}

			if ((port->tx.tx_now) && ((port->timer.tx_credit > 0)))
			{
				port->tx.state = TX_INFO_FRAME;
				return True;
			}
			return False;

		case TX_SHUTDOWN_FRAME:
			if (port->timer.tx_shutdown_while == 0)
			{
				port->tx.state = TX_LLDP_INITIALIZE;
				return True;
			}
			return False;

		case TX_INFO_FRAME:
			port->tx.state = TX_IDLE;
			return True;

		default:
			printf("ERROR: The TX State Machine is broken!\n");
			return False;
	}
}

/** Initializes the default values to transmit state machine variables
 *
 * @param port_num	physical port number	
 * @param port		lldp_sm_attr_t variable address
 *
 */
void cvmcs_dcbx_tx_initialize_lldp(uint8_t port_num, lldp_sm_attr_t *port)
{
	port->timer.reinit_delay	= REINIT_DELAY;
	port->timer.msg_tx_hold     	= DEFAULT_TX_HOLD;
	port->timer.msg_tx_interval 	= DEFAULT_TX_INTERVAL;
	port->timer.msg_fast_tx     	= FAST_TX_INTERVAL;
	port->tx.tx_ttl 		= 0;
	return;
}

/** TX_IDLE state of transmit state machine
 *
 * @param port	lldp_sm_attr_t variable address
 *
 */
void cvmcs_dcbx_tx_idle( lldp_sm_attr_t *port)
{
	port->tx.tx_ttl = min(65535, (port->timer.msg_tx_interval  *
					port->timer.msg_tx_hold) + 1);
	return;
}

/** TX_SHUTDOWN_FRAME state of transmit state machine
 *
 * @param port		lldp_sm_attr_t variable 
 *
 */
void cvmcs_dcbx_tx_shutdown_frame(uint8_t port_num, lldp_sm_attr_t *port)
{
	if (port->timer.tx_shutdown_while == 0) {
		if ( !cvmcs_dcbx_mib_constr_shutdown_lldpdu(port_num, port)) {
			 cvmcs_dcbx_tx_frame(port_num, port);
		}
		else
			printf("Error : In  cvmcs_dcb_dcbx_tx_shutdown_frame \n");
	}

	/*For stopping LLDp state machine for DCB_DISABLE */
	octnic->dcb[port_num].dcbx_cfg.timer_flag = False;
	return;
}

/** Construct shutdown lldp frame
 *
 * @param port_num	physical port number
 * @param port		lldp_sm_attr_t variable 
 *
 */
uint8_t cvmcs_dcbx_mib_constr_shutdown_lldpdu(uint8_t port_num, lldp_sm_attr_t *port)
{
  	void *tlv_offset;
	dcbx_config_t  *dcbx = &octnic->dcb[port_num].dcbx_cfg;
	struct ttl_tlv ttl;

        if (port->tx.frameout == NULL) {
                port->tx.frameout = cvmx_fpa_alloc(CVMX_FPA_PACKET_POOL);
                if(port->tx.frameout == NULL)
                {
                        printf(" Error5: failed to allocate memory to LLDP frame\n");
                        return 1;
                }
        }

	port->tx.sizeout = SIZEOF_SHUTDOWN_LLDP + ETHER_HDR_LENGTH;

	tlv_offset = (uint64_t *)port->tx.frameout ;

	memset(tlv_offset, 0, SIZEOF_SHUTDOWN_LLDP + ETHER_HDR_LENGTH);

  	/* write  ether_hddr to frame */
	memcpy(tlv_offset, &dcbx->eth_hddr, ETHER_HDR_LENGTH);
	tlv_offset += ETHER_HDR_LENGTH;

  	/* write chassis id TLV  */
	memcpy (tlv_offset, &dcbx->default_tlv.chassis_id, CHASSIS_ID_TLV_LENGTH +
								TLV_HDDR_LENGTH);
	tlv_offset += (CHASSIS_ID_TLV_LENGTH +  TLV_HDDR_LENGTH);

  	/* write port id TLV */
	memcpy (tlv_offset, &dcbx->default_tlv.port_id, PORT_ID_TLV_LENGTH +
								TLV_HDDR_LENGTH);
	tlv_offset += PORT_ID_TLV_LENGTH +  TLV_HDDR_LENGTH;

  	/*write ttl TLV */
	memcpy(&ttl, &dcbx->default_tlv.ttl, TTL_TLV_LENGTH + TLV_HDDR_LENGTH );
	ttl.ttl = 0;
	memcpy(tlv_offset, &ttl, TTL_TLV_LENGTH + TLV_HDDR_LENGTH );
	tlv_offset += TTL_TLV_LENGTH + TLV_HDDR_LENGTH;

	/*write end of lldp tlv */
	memcpy(tlv_offset,&dcbx->default_tlv.endof_lldp, 2);

	return 0;
}

/** TX_INFO_FRAME state of transmit state machine
 *
* @param port_num	physical port number
 * @param port		lldp_sm_attr_t variable 
 *
 */
void cvmcs_dcbx_tx_info_frame(uint8_t port_num, lldp_sm_attr_t *port)
{
	dcbx_config_t *dcbx = &octnic->dcb[port_num].dcbx_cfg;

	/* Create Frame */
	switch(dcbx->oper_dcbx_ver) {
		case DCBX_IEEE:
			if(cvmcs_dcbx_ieee_mib_constr_info_lldpdu(port_num, 
									port)) {
				printf("Error1:In %s \n Failed to Create frame \
					for port %d \n", __func__,port_num);
				port->tx.tx_now = False;
				return;
			}
			break;

		case DCBX_CEE:
			cvmcs_dcbx_cee_mib_constr_info_lldpdu(port_num, port);
			break;

	}

	/* Sendind frame to remote peer */
	cvmcs_dcbx_tx_frame(port_num, port);

	if (port->timer.tx_credit > 0)
		port->timer.tx_credit--;

	port->tx.tx_now = False;
	return;
}

/** Update current DCBx cfg info to host
 *
 * @param port_num		physical port number
 *
 */
void cvmcs_dcbx_param_indication(uint8_t port_num)
{
	uint8_t              	*buf, oq;
	union octeon_rh      	*rh;
	cvmx_buf_ptr_t       	lptr;
	struct oct_nic_dcbx_info *current_dcbx_info;
	int     		datalen = 0;

	buf = (uint8_t *)cvmx_fpa_alloc(CVMX_FPA_PACKET_POOL);
	if(buf == NULL)	{
       		printf("Error : in dcbx_capability_update: \n");
	       oct->pko_state = CVM_DRV_PKO_STOP;
	       CVMX_SYNCWS;
		return ;
	}

	rh = (union octeon_rh *)buf;
    	current_dcbx_info = (struct oct_nic_dcbx_info *)(buf + sizeof(*rh));
	memset(current_dcbx_info, 0, sizeof(struct oct_nic_dcbx_info));
	datalen = sizeof(struct oct_nic_dcbx_info);

	rh->u64         = 0;
	rh->r.opcode 	= OPCODE_NIC;
	rh->r.subcode 	= OPCODE_NIC_DCB_INFO;
	rh->r.ossp 	= port_num;

	if (octnic->dcb[port_num].dcbx_cfg.oper_dcbx_ver == DCBX_IEEE)
		cvmcs_dcbx_ieee_current_param(port_num, current_dcbx_info);
	else
		cvmcs_dcbx_cee_current_param (port_num, current_dcbx_info);

	if (current_dcbx_info->flags == 0) {
		cvmx_fpa_free(buf, CVMX_FPA_PACKET_POOL, 0);
		return;
	}

	lptr.u64    = 0;
	lptr.s.size = sizeof(union octeon_rh) + datalen;
	lptr.s.addr = CVM_DRV_GET_PHYS(buf);
	lptr.s.pool = CVMX_FPA_PACKET_POOL;
	lptr.s.i    = 1;

	CVMX_SYNCWS;

	oq = OCT_NIC_OQ_NUM(&octnic->port[octnic->dcb[port_num].ifidx], 0);

	if (cvm_send_pci_pko_direct(lptr, CVM_DIRECT_DATA, 1, lptr.s.size, oq))
		printf("Failed to send dcbx cfg \n");
}

/** Update the transmit timer state machine variables
 *
 * @param port	lldp_sm_attr_t variable
 *
 */
void cvmcs_dcbx_update_tx_timers(lldp_sm_attr_t *port)
{
	if (port->timer.tx_ttr)
		port->timer.tx_ttr--;
	port->timer.tx_tick = True;
	if(port->timer.tx_shutdown_while>0)
		port->timer.tx_shutdown_while--;
	return;
}

/** Update the receive timer state machine variables
 *
 * @param port	 lldp_sm_attr_t variable
 *
 */
void cvmcs_dcbx_update_rx_timers(lldp_sm_attr_t *port)
{
	if (cvmx_atomic_get32((int32_t *)&port->timer.rx_ttl)) {
		 cvmx_atomic_add32((int32_t *)&port->timer.rx_ttl, (int32_t ) -1);
		if (cvmx_atomic_get32((int32_t *)&port->timer.rx_ttl) == 0) {
			port->rx.rx_info_age = True;
		}
	}
}

/** It runs the all LLDP state machine per 1'sec
 *
 * @param wqe	timer work queue  entry
 *
 */
void cvmcs_dcbx_timer(cvmx_wqe_t *wqe)
{
	cvmx_raw_inst_front_t *front;
	int  port_num = 0;
	lldp_sm_attr_t * port;
	dcbx_config_t *dcbx = &octnic->dcb[port_num].dcbx_cfg;

	front = (cvmx_raw_inst_front_t *) cvmx_phys_to_ptr(cvmx_wqe_get_pki_pkt_ptr(wqe).addr);
	port_num = front->irh.s.ossp ;

	if(octnic->dcb[port_num].dcbx_cfg.timer_flag == False) {
		printf(" LLDP state machines stopped  for port %d \n", port_num);
		cvmx_fpa_free(front,CVMX_FPA_PACKET_POOL,0);
		cvmcs_wqe_free(wqe);
		if (dcbx->port.tx.frameout)
			cvmx_fpa_free(dcbx->port.tx.frameout,CVMX_FPA_PACKET_POOL,0);
		memset(&dcbx->timer_delete_info, 0, sizeof(cvmx_tim_delete_t));
		memset(&dcbx->port, 0, sizeof(lldp_sm_attr_t));
		dcbx->remote_dcbx_ver = DCBX_UNKNOWN;
		dcbx->dcbx_ieee.ets_flag = 0;
		dcbx->dcbx_ieee.pfc_flag = 0;
		dcbx->dcbx_ieee.app_flag = 0;
        	memset(&dcbx->dcbx_ieee.remote_port, 0, sizeof(struct lldp_port));
        	memset(&dcbx->dcbx_cee.remote_port, 0, sizeof(struct cee_lldp_port));
        	memset(&dcbx->dcbx_cee.local_port, 0, sizeof(struct cee_lldp_port));
        	memset(&dcbx->dcbx_cee.control_sm_var, 0, sizeof(struct control_sm_variables));

        	memset(&dcbx->dcbx_cee.feature_sm_var.pg.peer_cfg, 0,
		       sizeof(feat_sm_attr_t));
        	memset(&dcbx->dcbx_cee.feature_sm_var.pfc.peer_cfg, 0,
		       sizeof(feat_sm_attr_t));
        	memset(&dcbx->dcbx_cee.feature_sm_var.app.peer_cfg, 0,
		       sizeof(feat_sm_attr_t));

		memset(&dcbx->default_tlv, 0, sizeof(struct default_tlvs));
		dcbx->remote_enabled = 0;
		return;
	}

	port  = &octnic->dcb[port_num].dcbx_cfg.port;
	cvmcs_dcbx_update_tx_timers( port);
	cvmcs_dcbx_run_tx_timers_sm(port);
	cvmcs_dcbx_tx_statemachine_run(port_num);
	cvmcs_dcbx_update_rx_timers( port);
	cvmcs_dcbx_rx_statemachine_run(port_num, port);

	CVMX_SYNCWS;
	/* Reschedule same wqe to execute after 1's */
	if(cvmx_tim_add_entry(wqe, 1000, NULL) !=
					CVMX_TIM_STATUS_SUCCESS) {
		printf("timer failled\n");
	}
}

/** Transmit timer state machine
 *
 * @param port	lldp_sm_attr_t variable
 *
 */
void cvmcs_dcbx_run_tx_timers_sm(lldp_sm_attr_t  *port)
{
  	cvmcs_dcbx_set_tx_timers_state(port);
	do {
		switch (port->timer.state) {
			case TX_TIMER_INITIALIZE:
				 cvmcs_dcbx_tx_initialize_timers(port) ;
				break;

			case TX_TIMER_IDLE:
				/* Do nothing */
				break;

			case TX_TIMER_EXPIRES:
				if(port->tx.tx_fast)
					port->tx.tx_fast--;
				break;

			case TX_TICK:
				port->timer.tx_tick = False;
				if (port->timer.tx_credit < port->timer.tx_max_credit)
					port->timer.tx_credit++;
				break;

			case SIGNAL_TX:
				port->tx.tx_now = True;
				cvmx_atomic_set32((int32_t *)&port->tx.local_change,
								 (int32_t) False);
				if(port->tx.tx_fast > 0)
					port->timer.tx_ttr = port->timer.msg_fast_tx;
				else
					port->timer.tx_ttr = port->timer.msg_tx_interval;
				break;

			case TX_FAST_START:
				port->rx.new_neighbor = False;
				if (port->tx.tx_fast == 0)
					port->tx.tx_fast = port->timer.tx_fast_init;
				break;
		}
	} while ( cvmcs_dcbx_set_tx_timers_state(port) == True);
  	return;
}

/** Sets the state of transmit timer state machine
 *
 * @param port	lldp_sm_attr_t variable
 *
 */
bool cvmcs_dcbx_set_tx_timers_state(lldp_sm_attr_t  *port)
{
	if((port->timer.state == TX_TIMER_BEGIN)||
	(((uint8_t)cvmx_atomic_get32((int32_t *)&port->port_enabled)== False) ||
	 (((uint8_t)cvmx_atomic_get32((int32_t *)&port->admin_status) == disabled) ||
	 ((uint8_t)cvmx_atomic_get32((int32_t *)&port->admin_status) == enabled_rx_only)))) {
		cvmcs_dcbx_tx_timer_change_state(port, TX_TIMER_INITIALIZE);
		return False;
	}
  	switch(port->timer.state)
	{
		case TX_TIMER_INITIALIZE:
			if (((uint8_t)cvmx_atomic_get32((int32_t *)&port->admin_status) == enabled_rx_tx)||
			((uint8_t)cvmx_atomic_get32((int32_t *)&port->admin_status) == enabled_tx_only)) {
				cvmcs_dcbx_tx_timer_change_state(port, TX_TIMER_IDLE);
				return True;
			}
				return False;

		case TX_TIMER_IDLE:
			 if(cvmx_atomic_get32((int32_t*)&port->tx.local_change)) {
				cvmcs_dcbx_tx_timer_change_state(port, SIGNAL_TX);
				return True;
			 }
			if(port->timer.tx_ttr == 0) {
				cvmcs_dcbx_tx_timer_change_state(port, TX_TIMER_EXPIRES);
				return True;
			}
			if(port->rx.new_neighbor) {
				cvmcs_dcbx_tx_timer_change_state(port, TX_FAST_START);
				return True;
			}
			if(port->timer.tx_tick) {
				cvmcs_dcbx_tx_timer_change_state(port, TX_TICK);
				return True;
			}
			return False;

		case TX_TIMER_EXPIRES:
				cvmcs_dcbx_tx_timer_change_state(port, SIGNAL_TX);
				return True;

		case SIGNAL_TX:
		case TX_TICK:
				cvmcs_dcbx_tx_timer_change_state(port, TX_TIMER_IDLE);
				return True;

		case TX_FAST_START:
				cvmcs_dcbx_tx_timer_change_state(port, TX_TIMER_EXPIRES);
				return True;

		default:
				printf("Error : %s \n ", __func__);
				return false;
	}
}

/** Performs the state transition of transmit timer state machine
 *
 * @param port		lldp_sm_attr_t variable
 * @param newstate 	newstate
 *
 */
void cvmcs_dcbx_tx_timer_change_state(lldp_sm_attr_t  *port, uint8_t newstate)
{
	port->timer.state = newstate;
	return;
}

/** Initializes the transmit timer state machine variables default values 
 *
 * @param port		lldp_sm_attr_t variable
 *
 */
void cvmcs_dcbx_tx_initialize_timers(lldp_sm_attr_t  *port)
{
	port->tx.tx_now = false;
	port->timer.tx_ttr = 0;

	port->tx.tx_fast = 0;
	port->timer.tx_shutdown_while = 0;
	/* after initialisation send frame in fast intial mode */
	port->timer.tx_max_credit	= TX_CREDIT_MAX;
	port->timer.tx_credit		= TX_CREDIT_MAX;
	port->timer.tx_fast_init 	= TX_FAST_INIT;
	port->timer.reinit_delay	= REINIT_DELAY;
	port->timer.msg_tx_hold		= DEFAULT_TX_HOLD;
	port->timer.msg_tx_interval	= DEFAULT_TX_INTERVAL;
	port->timer.msg_fast_tx		= FAST_TX_INTERVAL;
	return;
}

/** Read TTL tlv
 *
 * @param tlv_offser	tlv address
 * @param port 		lldp_sm_attr_t object
 *
 */
int cvmcs_dcbx_read_ttl_tlv (void  *tlv_offset, lldp_sm_attr_t *port)
{
	tlv_hdr_t *tlv_hdr;
	uint16_t ttl;
	tlv_hdr = (tlv_hdr_t *)tlv_offset;
	if(!((tlv_hdr->type == TTL_TLV_TYPE) || (tlv_hdr->length == TTL_TLV_LENGTH)))
		return 1;
	memcpy(&ttl, (tlv_offset+TLV_HEADER_LENGTH) ,TTL_TLV_LENGTH );
	cvmx_atomic_set32((int32_t *)&port->timer.rx_ttl, (int32_t) ttl);
	return (tlv_hdr->length +  TLV_HEADER_LENGTH);

}

/** Handles the set calls from host
 *
 * @param port_num      physical port number
 * @param dcbx_cmd      Command received from the host
 *
 */
int cvmcs_dcbx_set_params(int port_num, struct oct_nic_dcbx_cmd *dcbx_cmd)
{
	int res = 1;

	if (!octnic->dcb[port_num].dcb_enabled)
		return 1;

	if (dcbx_cmd->cmd & DCBX_CMD_SET_ALL) {
		if (dcbx_cmd->dcbx_version & DCBX_IEEE)
			res = cvmcs_dcbx_ieee_set_params(port_num, dcbx_cmd);
		else
			res = cvmcs_dcbx_cee_set_params(port_num, dcbx_cmd);
	}

	return res;
}
