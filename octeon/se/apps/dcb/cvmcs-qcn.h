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

/*header files*/
#include <stdio.h>
#include "cvmx.h"
#include "cvmx-coremask.h"
#include "cvmx-bootmem.h"
#include "cvmx-helper.h"
#include "cvmx-pko3.h"
#include "cvmx-pko.h"
#include "cvmx-version.h"
#include "cvmx-error.h"
#include "cvmx-pki-defs.h"
#include "cvmx-pki.h"
#include "cvmx-helper-pki.h"
#include "cvmx-pki-resources.h"
#include "cvmx-pow.h"
#include "cvmx-helper-util.h"
#include "cvmx-sysinfo.h"
#include "cvmx-helper-fpa.h"
#include "cvmx-wqe.h"
#include "cvmx-tim.h"
#include "cvmx-access-native.h"
#include "cvmx-pko-defs.h"
#include <inttypes.h>
#include "cvmx-atomic.h"
#include "cvmx-config.h"

/*Macros*/
#define 	FALSE 			0
#define 	RPG_MAX_RATE 		10000000
#define 	RPG_BYTE_RESET 		150000						  
#define 	RPG_MIN_DEC_FAC		2
#define 	RPG_GD			128
#define 	RPG_TIME_RESET		15				   		
#define		RPG_THRESHOLD		5
#define 	RPG_AI_RATE		5000		/*5 Mbps*/
#define 	RPG_HAI_RATE		50000		/*50 Mbps*/
#define   	NUM_PRIO_PER_PORT	8
#define 	CNM_ENCAP_MIN_LEN	24
#define 	CN_TAG_TYPE     	0x22E9
#define		CNM_FRAME_TYPE		0x22E7
#define 	ADJUST 			4
#define		VERSION_MASK_VALUE	0xF000
#define		RSVD_MASK_VALUE		0x0FC0
#define		FEEDBACK_MASK_VALUE	0x003F
#define 	CNTAG_ETH_HLEN		22

/*structures*/

struct cntag_hdr {
	uint8_t		dest[6];
	uint8_t		source[6];
	uint16_t	cntag_proto;
	uint16_t	cntag_queue;
	uint16_t	proto;
};

struct cn_hdr {
	uint8_t 	dest[6];
	uint8_t		source[6];
	uint16_t	vlan_proto;
	uint16_t	vlan_TCI;
	uint16_t	cn_proto;
	uint16_t	cn_queue;
	uint16_t	proto;
};

typedef struct{
	uint16_t	tpid;
	uint16_t	tci;
}vlan_t;

typedef struct {
	uint16_t	ethertype;
	uint16_t	flow_id;
}cn_tag_t;

struct s_encap_msdu_t{
	uint16_t	dest_mac[3];
	uint16_t	src_mac[3];
	vlan_t		vlan_tag;
	uint16_t	cnm_tag;
	uint16_t	ether_type;
	uint16_t	rsvd;
}__attribute__ ((packed));
typedef struct s_encap_msdu_t encap_msdu_t;

struct s_cnm_pdu_t{
	uint16_t	vrf;
	uint16_t	cpid[4];
	uint16_t	qod[2];
	uint16_t	encap_priority;
	uint16_t	encap_dest_mac[3];
	uint16_t	msdu_len;
	encap_msdu_t	encap_msdu;
}__attribute__ ((packed));
typedef struct s_cnm_pdu_t cnm_pdu_t;

struct s_cnm_frame_t{
	uint16_t	dest_mac[3];
	uint16_t	src_mac[3];
	vlan_t		vlan_tag;
	uint16_t	cnm_tag;
	cnm_pdu_t	cnm_pdu;
}__attribute__ ((packed));
typedef struct s_cnm_frame_t cnm_frame_t;

typedef struct{
	unsigned int	priority;
	unsigned int	queue;
	bool		rp_enabled;
	int32_t		rp_bytecount;
	int32_t		rp_bytestage;
	int32_t		rp_timestage;
	uint64_t 	target_rate;
	uint64_t	current_rate;
	bool		counter_submitted;
	int32_t		txn_byte_cnt;
	cvmx_wqe_t	*rp_timer_wqe;
	cvmx_wqe_t	*rp_byte_wqe;
	cvmx_spinlock_t lock;
	int		rpfb;
}rp_state_machine_t;

typedef struct{
	cvmx_raw_inst_front_t	front;
	rp_state_machine_t	*qcn_sm;
}qcn_data_pkt_t;

typedef struct{
	rp_state_machine_t	qcn_sm;
}qcn_per_port_t;

typedef struct{
	bool 		qcn_port_enable;
	uint8_t 	qcn_prio_enable;
	qcn_per_port_t	rp_per_prio[NUM_PRIO_PER_PORT];
}octeon_qcn_t;

/*Prototype*/
int cvmcs_dcb_qcn_init(int port_num);
void cvmcs_dcb_qcn_disable(int port_num);
int cvmcs_dcb_qcn_main(cvmx_wqe_t *wqe);
void cvmcs_dcb_qcn_init_rp(rp_state_machine_t *qcn_sm);
void cvmcs_dcb_qcn_rp_process_cnm(rp_state_machine_t	*qcn_sm);
void cvmcs_dcb_qcn_rp_counter(cvmx_wqe_t *rp_counter_wqe);
void cvmcs_dcb_qcn_rp_fast_byte(rp_state_machine_t *qcn_sm);
void cvmcs_dcb_qcn_rp_active_byte(rp_state_machine_t *qcn_sm);
void cvmcs_dcb_qcn_rp_hyper_byte(rp_state_machine_t *qcn_sm);
void cvmcs_dcb_qcn_rp_timer(rp_state_machine_t *qcn_sm);
void cvmcs_dcb_qcn_rp_fast_time(rp_state_machine_t *qcn_sm);
void cvmcs_dcb_qcn_rp_active_time(rp_state_machine_t *qcn_sm);
void cvmcs_dcb_qcn_rp_hyper_time(rp_state_machine_t *qcn_sm);
void cvmcs_dcb_qcn_rp_self_increase(rp_state_machine_t *qcn_sm);
void cvmcs_dcb_qcn_adjust_rate(rp_state_machine_t *qcn_sm, int rate_increase);
void cvmcs_dcb_schedule_qcn_byte_counter(cvmx_wqe_t *wqe,int port,int prio);
void cvmcs_dcb_insert_cntag(cvmx_wqe_t *wqe);
void cvmcs_dcb_strip_cntag(cvmx_wqe_t *wqe);

