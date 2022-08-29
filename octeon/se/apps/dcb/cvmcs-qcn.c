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
#include "cvmcs-nic-mdata.h"

extern CVMX_SHARED octnic_dev_t *octnic;

int cvmcs_dcb_qcn_init(int port_num)
{
	uint16_t i = 0;
	octeon_qcn_t *qcn = &octnic->dcb[port_num].qcn;
	if(!qcn->qcn_port_enable){
		qcn->qcn_port_enable = TRUE;
		for(i = 0; i < NUM_PRIO_PER_PORT; i++){
			/* initialize rp_state_machine_t for all supported priorities*/
			qcn->rp_per_prio[i].qcn_sm.rp_enabled = FALSE;
			qcn->rp_per_prio[i].qcn_sm.rp_bytecount = RPG_BYTE_RESET;
			qcn->rp_per_prio[i].qcn_sm.counter_submitted = FALSE;
			qcn->rp_per_prio[i].qcn_sm.target_rate = RPG_MAX_RATE;
			qcn->rp_per_prio[i].qcn_sm.current_rate = 0;
			qcn->rp_per_prio[i].qcn_sm.rp_byte_wqe = NULL;
			qcn->rp_per_prio[i].qcn_sm.rp_timer_wqe = NULL;
			cvmx_spinlock_init(&(qcn->rp_per_prio[i].qcn_sm.lock));
		}
	}
	return 0;
}

void cvmcs_dcb_qcn_disable(int port_num)
{
	unsigned short int i = 0;
	qcn_data_pkt_t *qcn_data_pkt = NULL;
	octeon_qcn_t  *qcn = &octnic->dcb[port_num].qcn;
	qcn_per_port_t *rp_per_prio = NULL; 
	if(qcn->qcn_port_enable){
		for(i = 0; i < NUM_PRIO_PER_PORT; i++){
			rp_per_prio = &qcn->rp_per_prio[i];
			rp_per_prio->qcn_sm.rp_enabled = FALSE;
			if(rp_per_prio->qcn_sm.rp_timer_wqe){
				qcn_data_pkt =(qcn_data_pkt_t *)CVM_DRV_GET_PTR
					(cvmx_wqe_get_pki_pkt_ptr
					(rp_per_prio->qcn_sm.rp_timer_wqe).addr);
				cvmx_fpa_free(qcn_data_pkt,CVMX_FPA_PACKET_POOL,0);
				cvmcs_wqe_free(rp_per_prio->qcn_sm.rp_timer_wqe);
			}
			if(rp_per_prio->qcn_sm.rp_byte_wqe){
				qcn_data_pkt =(qcn_data_pkt_t *)CVM_DRV_GET_PTR
					(cvmx_wqe_get_pki_pkt_ptr
					 (rp_per_prio->qcn_sm.rp_byte_wqe).addr);
				cvmx_fpa_free(qcn_data_pkt,CVMX_FPA_PACKET_POOL,0);
				cvmcs_wqe_free(rp_per_prio->qcn_sm.rp_byte_wqe);
			}

		}
		qcn->qcn_port_enable = FALSE;
		qcn->qcn_prio_enable = 0;
	}
	return;
}


void cvmcs_dcb_qcn_reconfig(cn_tlv_t *cn_tlv, int port_no)
{
	octeon_qcn_t	*qcn = &octnic->dcb[port_no].qcn;
	qcn->qcn_prio_enable = cn_tlv->per_prio_ready_indicator;
	return;
}

int cvmcs_dcb_qcn_main(cvmx_wqe_t *wqe)
{
	unsigned short int	priority = 0,port_num= 0, queue = 0;
	rp_state_machine_t  	*qcn_sm = NULL;
	cnm_frame_t 		*pkt_frame = NULL;
	octeon_qcn_t 		*qcn = NULL;
	cnm_pdu_t    		*cnm_pdu = NULL;
	uint8_t			i;
	uint16_t		vers,rsvd,fb,msdu_len;
	uint64_t		cpid = 0;
	port_num = cvmx_wqe_get_port(wqe);
	queue = cvmx_pko_get_base_queue(port_num);
	port_num = get_gmx_port_id((int)port_num);
	qcn = &octnic->dcb[port_num].qcn;
	if(qcn->qcn_port_enable){
		pkt_frame = (cnm_frame_t *)CVM_DRV_GET_PTR
			(cvmx_wqe_get_pki_pkt_ptr(wqe).addr);
		if(CNM_FRAME_TYPE == pkt_frame->cnm_tag){
			cnm_pdu = &(pkt_frame->cnm_pdu);
			vers = (cnm_pdu->vrf & VERSION_MASK_VALUE) >> 12;
			rsvd = (cnm_pdu->vrf & RSVD_MASK_VALUE) >> 6;
			fb = (cnm_pdu->vrf & FEEDBACK_MASK_VALUE);
			for(i=0; i<4; i++)
				cpid = (cpid << 16) | cnm_pdu->cpid[i];

			if(!vers && !rsvd){
				if(fb && cpid){
					priority = cnm_pdu->encap_priority;
					if(qcn->qcn_prio_enable & (1 << priority)){
						msdu_len = cnm_pdu->msdu_len;
						if(CNM_ENCAP_MIN_LEN <= msdu_len){
							qcn_sm = &(qcn->rp_per_prio[priority]
									.qcn_sm);
							qcn_sm->priority = priority;
							qcn_sm->queue = queue + priority;
							qcn_sm->rpfb = fb;
							cvmcs_dcb_qcn_init_rp(qcn_sm);
							return 1;
						}
					}
				}
			}
		}
	}
	printf("ERROR %s : Invalid CNM-frame\n", __func__);
	return -1;
}

void cvmcs_dcb_qcn_init_rp(rp_state_machine_t *qcn_sm)
{
	qcn_data_pkt_t		*byte_data_pkt = NULL,*timer_data_pkt = NULL;
	cvmx_raw_inst_front_t 	*byte_front = NULL,*timer_front = NULL;
	cvmx_wqe_t		*rp_byte_wqe = NULL, *rp_timer_wqe = NULL;

	/*Initialialize the state machine of the corresponding reaction point
	  verify lock requirement for sync */
	if(!qcn_sm->rp_enabled) {
		if(!qcn_sm->rp_byte_wqe){
			rp_byte_wqe = cvmcs_wqe_alloc();
			if(!rp_byte_wqe){
				printf("ERROR %s : rp_byte_wqe allocation failed\n", __func__);
				return;
			}

			byte_data_pkt = (qcn_data_pkt_t *)cvmx_fpa_alloc
				(CVMX_FPA_PACKET_POOL);
			if(!byte_data_pkt){
				printf("ERROR %s : byte_data_pkt allocation failed\n",__func__);
				cvmcs_wqe_free(rp_byte_wqe);
				qcn_sm->rp_byte_wqe = NULL;
				return;
			}
			byte_front = &byte_data_pkt->front;
			memset(byte_front,0,sizeof(cvmx_raw_inst_front_t));
			byte_front->irh.s.opcode = OPCODE_NIC;
			byte_front->irh.s.subcode = OPCODE_NIC_QCN_BYTE_COUNTER;
			cvmx_wqe_set_soft(rp_byte_wqe, 1);
			byte_data_pkt->qcn_sm = qcn_sm;
			rp_byte_wqe->packet_ptr.s.addr = CVM_DRV_GET_PHYS(byte_data_pkt);
			qcn_sm->rp_byte_wqe = rp_byte_wqe;
		}
		cvmx_atomic_set32(&qcn_sm->rp_bytecount,RPG_BYTE_RESET);
		cvmx_atomic_set32((int32_t *)&qcn_sm->counter_submitted,FALSE);
		cvmx_atomic_set32(&qcn_sm->txn_byte_cnt,0);

		if(!qcn_sm->rp_timer_wqe){
			rp_timer_wqe =  cvmcs_wqe_alloc();
			if(!rp_timer_wqe){
				cvmx_fpa_free(byte_front,CVMX_FPA_PACKET_POOL,0);
				byte_front = NULL;
				printf("ERROR %s : rp_timer_wqe allocation failed\n", __func__);
				cvmcs_wqe_free(rp_byte_wqe);
				qcn_sm->rp_byte_wqe = NULL;
				return;
			}
			timer_data_pkt = (qcn_data_pkt_t *)cvmx_fpa_alloc
				(CVMX_FPA_PACKET_POOL);
			if(!timer_data_pkt){
				printf("ERROR %s : timer_data_pkt allocation failed\n", __func__);
				cvmcs_wqe_free(rp_timer_wqe);
				qcn_sm->rp_timer_wqe = NULL;
				cvmx_fpa_free(byte_front,CVMX_FPA_PACKET_POOL,0);
				byte_front = NULL;
				cvmcs_wqe_free(rp_byte_wqe);
				qcn_sm->rp_byte_wqe = NULL;
				return;
			}
			timer_front = &timer_data_pkt->front;
			memset(timer_front,0,sizeof(cvmx_raw_inst_front_t));
			timer_front->irh.s.opcode = OPCODE_NIC;
			timer_front->irh.s.subcode = OPCODE_NIC_QCN_TIMER_COUNTER;
			cvmx_wqe_set_soft(rp_timer_wqe, 1);
			timer_data_pkt->qcn_sm = qcn_sm;
			rp_timer_wqe->packet_ptr.s.addr = CVM_DRV_GET_PHYS(timer_data_pkt);
			qcn_sm->rp_timer_wqe = rp_timer_wqe;
		}	

		CVMX_SYNCWS;
		qcn_sm->rp_enabled = TRUE;
		cvmcs_dcb_qcn_rp_process_cnm(qcn_sm);
		cvmcs_dcb_qcn_rp_timer(qcn_sm);
	}
	else {
		cvmx_atomic_set32(&qcn_sm->rp_bytecount,RPG_BYTE_RESET);
		cvmx_atomic_set32(&qcn_sm->txn_byte_cnt,0);
		cvmx_atomic_set32(&qcn_sm->rp_bytestage,0);
		cvmx_atomic_set32(&qcn_sm->rp_timestage,0);
		cvmcs_dcb_qcn_rp_process_cnm(qcn_sm);
	}

	return;
}

/* Decrement the rate based on decrement factor on reception of CNM frame*/
void cvmcs_dcb_qcn_rp_process_cnm(rp_state_machine_t *qcn_sm)
{
	int dec_factor = 0;
	int node = cvmx_get_node_num();
	cvmx_pko_dqx_shape_state_t dq_shape_stat;

	dec_factor = (1 - ((1/RPG_GD) * qcn_sm->rpfb));
	if(dec_factor < (1/RPG_MIN_DEC_FAC))
		dec_factor = (1/RPG_MIN_DEC_FAC);

	cvmx_spinlock_lock(&qcn_sm->lock);

	dq_shape_stat.u64 = cvmx_read_csr_node
		(node, CVMX_PKO_DQX_SHAPE_STATE(qcn_sm->priority));
	qcn_sm->target_rate = qcn_sm->target_rate / 2;
	qcn_sm->current_rate = dq_shape_stat.s.cir_accum * dec_factor;

	if(qcn_sm->current_rate < (qcn_sm->target_rate / 2))
		qcn_sm->current_rate = qcn_sm->target_rate / 2;

	cvmx_pko3_dq_red(node, qcn_sm->queue, CVMX_PKO3_SHAPE_RED_STALL, ADJUST);
	cvmx_pko3_dq_pir_set(node, qcn_sm->queue, qcn_sm->current_rate, 0);
	cvmx_spinlock_unlock(&qcn_sm->lock);

	return;
}

void cvmcs_dcb_qcn_rp_counter(cvmx_wqe_t *rp_counter_wqe)
{
	qcn_data_pkt_t  *data_pkt = NULL;
	rp_state_machine_t *qcn_sm = NULL;
	cvmx_raw_inst_front_t *front = NULL;
	uint8_t subcode = 0;

	data_pkt = (qcn_data_pkt_t *)CVM_DRV_GET_PTR
		(rp_counter_wqe->packet_ptr.s.addr);
	front = &data_pkt->front;
	qcn_sm = data_pkt->qcn_sm;
	subcode = front->irh.s.subcode;

	if(qcn_sm->rp_enabled){
		switch(subcode)
		{
			case OPCODE_NIC_QCN_BYTE_COUNTER:
				{
					if(RPG_THRESHOLD > qcn_sm->rp_bytestage)
						cvmcs_dcb_qcn_rp_fast_byte(qcn_sm);
					else if(RPG_THRESHOLD < qcn_sm->rp_bytestage)
						cvmcs_dcb_qcn_rp_hyper_byte(qcn_sm);
					else
						cvmcs_dcb_qcn_rp_active_byte(qcn_sm);
					cvmcs_dcb_qcn_rp_self_increase(qcn_sm);
					cvmx_atomic_set32(&qcn_sm->txn_byte_cnt,0);
					cvmx_atomic_set32((int32_t *)&qcn_sm->counter_submitted,
							FALSE);
				}
				break;

			case OPCODE_NIC_QCN_TIMER_COUNTER:
				{
					cvmcs_dcb_qcn_rp_self_increase(qcn_sm);
					/* To Avoid timer add after maximum rate reached */
					if(qcn_sm->rp_enabled)
						cvmcs_dcb_qcn_rp_timer(qcn_sm);
				}
				break;
		}
	}
	return;
}


void cvmcs_dcb_qcn_rp_fast_byte(rp_state_machine_t *qcn_sm)
{
	qcn_sm->rp_bytecount = RPG_BYTE_RESET;
	cvmx_atomic_add32(&qcn_sm->rp_bytestage,1);
}


void cvmcs_dcb_qcn_rp_active_byte(rp_state_machine_t *qcn_sm)
{
	/*random number between (0.08 -1.15)refered as 1 */
	if(qcn_sm->rp_bytestage < RPG_THRESHOLD)
		qcn_sm->rp_bytecount = RPG_BYTE_RESET* 1;
	else
		qcn_sm->rp_bytecount = (RPG_BYTE_RESET * 1)/2;
	cvmx_atomic_add32(&qcn_sm->rp_bytestage,1);
}

void cvmcs_dcb_qcn_rp_hyper_byte(rp_state_machine_t *qcn_sm)
{
	qcn_sm->rp_bytecount = RPG_BYTE_RESET / 2;
	cvmx_atomic_add32(&qcn_sm->rp_bytestage,1);
}

void cvmcs_dcb_qcn_rp_timer(rp_state_machine_t *qcn_sm)
{
	/*Incremented prior to schedule,
	  to sync incremented value in self increase.*/
	cvmx_atomic_add32(&qcn_sm->rp_timestage,1);
	if(RPG_THRESHOLD > qcn_sm->rp_timestage)
		cvmcs_dcb_qcn_rp_fast_time(qcn_sm);
	else if(RPG_THRESHOLD < qcn_sm->rp_timestage)
		cvmcs_dcb_qcn_rp_hyper_time(qcn_sm);
	else
		cvmcs_dcb_qcn_rp_active_time(qcn_sm);
}

void cvmcs_dcb_qcn_rp_fast_time(rp_state_machine_t *qcn_sm)
{
	cvmx_tim_delete_t	*delete_info = NULL;
	uint64_t 		tim = RPG_TIME_RESET;
	CVMX_SYNCWS;
	if(CVMX_TIM_STATUS_SUCCESS != cvmx_tim_add_entry(qcn_sm->rp_timer_wqe,
				tim, delete_info)){
		printf("ERROR %s : QCN RP FAST TIME add failed\n", __func__);
		cvmcs_wqe_free(qcn_sm->rp_timer_wqe);
		qcn_sm->rp_timer_wqe = NULL;
	}
	return;
}

void cvmcs_dcb_qcn_rp_active_time(rp_state_machine_t *qcn_sm)
{
	cvmx_tim_delete_t	*delete_info = NULL;
	uint64_t 		tim = 0;

	if(qcn_sm->rp_timestage < RPG_THRESHOLD)
		tim = 1 *RPG_TIME_RESET;
	else
		tim = (1 * RPG_TIME_RESET)/2;

	CVMX_SYNCWS;

	if(CVMX_TIM_STATUS_SUCCESS != cvmx_tim_add_entry(qcn_sm->rp_timer_wqe,
				tim, delete_info)){
		printf("ERROR %s : QCN RP ACTIVE TIME add failed\n", __func__);
		cvmcs_wqe_free(qcn_sm->rp_timer_wqe);
		qcn_sm->rp_timer_wqe = NULL;
	}
	return;
}

void cvmcs_dcb_qcn_rp_hyper_time(rp_state_machine_t *qcn_sm)
{
	cvmx_tim_delete_t	*delete_info = NULL;
	uint64_t 		tim = RPG_TIME_RESET/2;

	CVMX_SYNCWS;

	if(CVMX_TIM_STATUS_SUCCESS != cvmx_tim_add_entry(qcn_sm->rp_timer_wqe,
				tim, delete_info)){
		printf("ERROR %s : QCN RP HYPER ACTIVE TIME add failed\n", __func__);
		cvmcs_wqe_free(qcn_sm->rp_timer_wqe);
		qcn_sm->rp_timer_wqe = NULL;
	}
	return;
}

void cvmcs_dcb_qcn_rp_self_increase(rp_state_machine_t *qcn_sm)
{
	unsigned int rate_increase = 0, count = 0;

	cvmx_spinlock_lock(&qcn_sm->lock);
	if(qcn_sm->rp_bytestage > qcn_sm->rp_timestage)
		count = qcn_sm->rp_timestage;
	else
		count =  qcn_sm->rp_bytestage;

	if((RPG_THRESHOLD > qcn_sm->rp_bytestage) &&
			(RPG_THRESHOLD > qcn_sm->rp_timestage))
		rate_increase = 0;
	else if((RPG_THRESHOLD <= qcn_sm->rp_bytestage) &&
			(RPG_THRESHOLD <= qcn_sm->rp_timestage))
		rate_increase = RPG_HAI_RATE * (count - RPG_THRESHOLD);
	else
		rate_increase = RPG_AI_RATE;

	cvmcs_dcb_qcn_adjust_rate(qcn_sm, rate_increase);
	cvmx_spinlock_unlock(&qcn_sm->lock);
	return;
}

void  cvmcs_dcb_qcn_adjust_rate(rp_state_machine_t *qcn_sm,  int rate_increase)
{
	int node;

	if(((1 == qcn_sm->rp_bytestage)||(1 == qcn_sm->rp_timestage)) &&
			(qcn_sm->target_rate > (10 * qcn_sm->current_rate)))
		qcn_sm->target_rate = qcn_sm->target_rate/8;
	else
		qcn_sm->target_rate = qcn_sm->target_rate + rate_increase;

	qcn_sm->current_rate  = (qcn_sm->current_rate +
			qcn_sm->target_rate)/2;

	if(RPG_MAX_RATE < qcn_sm->current_rate)
		qcn_sm->current_rate = RPG_MAX_RATE;

	node = cvmx_get_node_num();
	cvmx_pko3_dq_red(node, qcn_sm->queue, CVMX_PKO3_SHAPE_RED_STALL, ADJUST);
	cvmx_pko3_dq_pir_set(node, qcn_sm->queue, qcn_sm->current_rate, 0);

	if(RPG_MAX_RATE == qcn_sm->current_rate){
		qcn_sm->rp_enabled = FALSE;
		cvmx_atomic_set32(&qcn_sm->txn_byte_cnt,0);
		cvmx_atomic_set32(&qcn_sm->rp_bytestage,0);
		cvmx_atomic_set32(&qcn_sm->rp_timestage,0);
	}
	return;
}

void cvmcs_dcb_schedule_qcn_byte_counter(cvmx_wqe_t *wqe, int port, int prio)
{
	rp_state_machine_t *qcn_sm = NULL;
	qcn_sm = &(octnic->dcb[port].qcn.rp_per_prio[prio].qcn_sm);
	if(qcn_sm->rp_enabled){
		if(FALSE == cvmx_atomic_get32((int32_t *)
					&qcn_sm->counter_submitted)){
			cvmx_atomic_add32(&qcn_sm->txn_byte_cnt,
					cvmx_wqe_get_len(wqe));

			if(qcn_sm->rp_bytecount <= qcn_sm->txn_byte_cnt)
				if(cvmx_atomic_compare_and_store32((uint32_t *)
							&qcn_sm->counter_submitted,FALSE,TRUE)){
					/* Avoid race condition */
					cvmx_pow_work_submit(qcn_sm->rp_byte_wqe,
							cvmx_wqe_get_tag(qcn_sm->rp_byte_wqe),
							cvmx_wqe_get_tt(qcn_sm->rp_byte_wqe),
							cvmx_wqe_get_qos(qcn_sm->rp_byte_wqe),
							cvmx_wqe_get_grp(qcn_sm->rp_byte_wqe));
				}
		}
	}
	return;
}


void cvmcs_dcb_process_qcn(cvmx_wqe_t *wqe)
{
	octeon_qcn_t *qcn;
	uint8_t  priority;
	cvmcs_nic_metadata_t *mdata = CVMCS_NIC_METADATA(wqe);
	
        priority =  CVMCS_NIC_METADATA_PRIORITY(mdata);
        qcn = &octnic->dcb[mdata->gmx_id].qcn;

        if(qcn->qcn_prio_enable & (1 << priority)){
        	cvmcs_dcb_insert_cntag(wqe);
        	cvmcs_dcb_schedule_qcn_byte_counter(wqe, mdata->gmx_id, priority);
        }

	return;
}

void cvmcs_dcb_get_l2_proto_hlen(cvmx_wqe_t *wqe, uint16_t *l2proto, uint16_t *l2hlen)
{
	octeon_qcn_t *qcn;
	uint8_t  priority;
	struct ethhdr *eth;
	cvmcs_nic_metadata_t *mdata = CVMCS_NIC_METADATA(wqe);

	priority =  CVMCS_NIC_METADATA_PRIORITY(mdata);
	qcn = &octnic->dcb[mdata->gmx_id].qcn;

	eth = (struct ethhdr *)CVMCS_NIC_METADATA_PACKET_START(mdata);

        if (eth->h_proto == ETH_P_8021Q){
               if(qcn->qcn_prio_enable & (1 << priority)){
                        struct cn_hdr *ch = (struct cn_hdr *)eth;
                        mdata->flags |= METADATA_FLAGS_VLAN;
                        *l2proto = ch->proto;
                        *l2hlen = CNTAG_ETH_HLEN;
                }
                else {
                	struct vlan_hdr *vh = (struct vlan_hdr *)eth;
                        mdata->flags |= METADATA_FLAGS_VLAN;
                        *l2proto = vh->proto;
                        *l2hlen = VLAN_ETH_HLEN;
                }
        } else {
                *l2proto = eth->h_proto;
                *l2hlen = ETH_HLEN;
        }

	return;
}


void cvmcs_dcb_insert_cntag(cvmx_wqe_t *wqe)
{
	uint64_t nextptr, startptr;
	uint8_t *bufptr, priority;
	uint16_t queue;
	cvmcs_nic_metadata_t *mdata = CVMCS_NIC_METADATA(wqe);
	vnic_port_info_t *nicport;
	nicport = &octnic->port[mdata->from_ifidx];
	priority = mdata->front.irh.s.priority;
	queue = cvmx_pko_get_base_queue(nicport->linfo.gmxport);
	queue += priority;

	if ((!CVMCS_NIC_METADATA_IS_PACKET_FROM_DPI(mdata)) ||
			( CVMCS_NIC_METADATA_VLAN_TCI(mdata) == 0))
		return;

	if (octeon_has_feature(OCTEON_FEATURE_CN78XX_WQE)) {
		cvmx_buf_ptr_pki_t *tmp_lptr = (cvmx_buf_ptr_pki_t *)&wqe->packet_ptr;
		nextptr = *((uint64_t *)CVM_DRV_GET_PTR(tmp_lptr->addr - 8));

		/* Insert cn-tag */
		tmp_lptr->addr -= 4;
		tmp_lptr->size += 4;

		bufptr = (uint8_t *)CVM_DRV_GET_PTR(tmp_lptr->addr);

		((uint32_t *)bufptr)[0] = ((uint32_t *)bufptr)[1];
		((uint32_t *)bufptr)[1] = ((uint32_t *)bufptr)[2];
		((uint32_t *)bufptr)[2] = ((uint32_t *)bufptr)[3];
		((uint32_t *)bufptr)[3] = ((uint32_t *)bufptr)[4];
		((uint32_t *)bufptr)[4] = ((CN_TAG_TYPE << 16) | queue);

		*((uint64_t *)CVM_DRV_GET_PTR(tmp_lptr->addr - 8)) = nextptr;

	} else {

		nextptr = *((uint64_t *) CVM_DRV_GET_PTR(wqe->packet_ptr.s.addr - 8));
		startptr = (((wqe->packet_ptr.s.addr >> 7) - wqe->packet_ptr.s.back) << 7);
		/* Insert cn-tag */
		wqe->packet_ptr.s.addr -= 4;
		wqe->packet_ptr.s.size += 4;
		wqe->packet_ptr.s.back = ((wqe->packet_ptr.s.addr - startptr) >> 7);

		bufptr = (uint8_t *)CVM_DRV_GET_PTR(wqe->packet_ptr.s.addr);

		((uint32_t *)bufptr)[0] = ((uint32_t *)bufptr)[1];
		((uint32_t *)bufptr)[1] = ((uint32_t *)bufptr)[2];
		((uint32_t *)bufptr)[2] = ((uint32_t *)bufptr)[3];
		((uint32_t *)bufptr)[3] = ((uint32_t *)bufptr)[4];
		((uint32_t *)bufptr)[4] = ((CN_TAG_TYPE << 16) | queue);

		*((uint64_t *) CVM_DRV_GET_PTR(wqe->packet_ptr.s.addr - 8)) = nextptr;
	}

	cvmx_wqe_set_len(wqe, (cvmx_wqe_get_len(wqe) + 4));

	mdata->packet_start = (uint8_t *)PACKET_START(wqe);

	if (CVMCS_NIC_METADATA_IS_PTP_HEADER(mdata))
		mdata->packet_start += OCTNET_FRM_PTP_HEADER_SIZE;
}

void cvmcs_dcb_strip_cntag(cvmx_wqe_t *wqe)
{
	int32_t i;
	uint32_t *ptr;
	struct cntag_hdr *cn_hdr;
	uint64_t nextptr, start;
	cvmcs_nic_metadata_t *mdata = CVMCS_NIC_METADATA(wqe);
	cn_hdr = (struct cntag_hdr *)CVMCS_NIC_METADATA_PACKET_START(mdata);

	if (cn_hdr->cntag_proto != CN_TAG_TYPE) 
		return;

	i = (2 * ETH_ALEN) / 4;
	if (CVMCS_NIC_METADATA_IS_PTP_HEADER(mdata))
		i += OCTNET_FRM_PTP_HEADER_SIZE / 4;

	if (octeon_has_feature(OCTEON_FEATURE_CN78XX_WQE)) {
		cvmx_buf_ptr_pki_t *tmp_lptr = (cvmx_buf_ptr_pki_t *)&wqe->packet_ptr;
		nextptr = *((uint64_t *)CVM_DRV_GET_PTR(tmp_lptr->addr - 8));
		ptr = (uint32_t *)CVM_DRV_GET_PTR(tmp_lptr->addr);
		while (i > 0) {
			ptr[i] = ptr[i-1];
			i--;
		}
		tmp_lptr->addr += 4;
		tmp_lptr->size -= 4;

		*((uint64_t *)CVM_DRV_GET_PTR(tmp_lptr->addr - 8)) = nextptr;
	} else {
		cvmx_buf_ptr_t *buf_ptr = (cvmx_buf_ptr_t *)&wqe->packet_ptr;
		nextptr = *((uint64_t *) cvmx_phys_to_ptr(buf_ptr->s.addr - 8));
		start = (((buf_ptr->s.addr >> 7) - buf_ptr->s.back) << 7);
		ptr = (uint32_t *) cvmx_phys_to_ptr(buf_ptr->s.addr);

		while (i > 0) {
			ptr[i] = ptr[i-1];
			i--;
		}
		buf_ptr->s.addr += 4;
		buf_ptr->s.size -= 4;
		buf_ptr->s.back = ((buf_ptr->s.addr - start) >> 7);

		*(uint64_t *) cvmx_phys_to_ptr(buf_ptr->s.addr - 8) = nextptr;
	}

	cvmx_wqe_set_len(wqe, (cvmx_wqe_get_len(wqe) - 4));
	mdata->packet_start = (uint8_t *)PACKET_START(wqe);

	if (CVMCS_NIC_METADATA_IS_PTP_HEADER(mdata))
		mdata->packet_start += OCTNET_FRM_PTP_HEADER_SIZE;

	return;
}

