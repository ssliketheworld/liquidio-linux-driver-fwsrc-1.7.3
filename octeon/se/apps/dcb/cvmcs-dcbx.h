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
#ifndef __CVMCS_DCBX_H__
#define __CVMCS_DCBX_H__

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
#include "cvmx-wqe.h"
#include "cvmx-tim.h"
#include "cvmx-atomic.h"
#include <stdarg.h>

/*Macro Definitions */

/* 802.1 subtype */
#define ETS_CONFIGURATION			0x09
#define ETS_RECOMMENDATION			0x0A
#define PFC_CONFIGURATION			0x0B
#define APPLICATION_PRIORITY			0x0C

#define INFO_STRING				tlv_offset + TLV_HEADER_LENGTH
#define OUI_LENGTH				3
#define SUB_TYPE_LENGTH				1
#define SUB_TYPE				tlv_offset + TLV_HEADER_LENGTH + OUI_LENGTH

//States from the receive state machine diagram
#define RX_BEGIN				10
#define LLDP_WAIT_PORT_OPERATIONAL 		4
#define DELETE_AGED_INFO           		5
#define RX_LLDP_INITIALIZE         		6
#define RX_WAIT_FOR_FRAME          		7
#define RX_FRAME                   		8
#define DELETE_INFO                		9
#define UPDATE_INFO                		1

/*  txInitializeTimers default values */
#define DEFAULT_TX_HOLD  			4
#define DEFAULT_TX_INTERVAL 			30
#define FAST_TX_INTERVAL  			1
#define TX_FAST_INIT 				4
#define TX_CREDIT_MAX           		5

/* size of tlvs */
#define MAX_TLV_LEN             		512
#define CHASSIS_ID_TLV_LENGTH 			7
#define PORT_ID_TLV_LENGTH 			7
#define TTL_TLV_LENGTH				2
#define TLV_HDDR_LENGTH				2
#define END_OF_LLDP_LENGTH			0
#define SIZE_OF_TABLE 				3
#define ETHER_HDR_LENGTH			14
#define MIN_ETH_SIZE				64
#define END_OF_LLDP_SIZE			2
#define SIZEOF_SHUTDOWN_LLDP			CHASSIS_ID_TLV_LENGTH + \
						TLV_HDDR_LENGTH + \
						PORT_ID_TLV_LENGTH + \
						TLV_HDDR_LENGTH + \
						TTL_TLV_LENGTH + \
						TLV_HDDR_LENGTH + \
						END_OF_LLDP_SIZE

/* struct lldp_tx_port variables default values */
#define	REINIT_DELAY			2

/* struct lldp_rx_port variables default values */

#define	RCV_FRAME 			0
#define	TOO_MANY_NEIGHBORS		0
#define	RX_INFO_AGE			0

/* QCN macros */
#define CONGESTION_TLV_TYPE     127
#define CONGESTION_TLV_LENGTH   6
#define CONGESTION_TLV_OUI0     0x00
#define CONGESTION_TLV_OUI1     0x80
#define CONGESTION_TLV_OUI2     0xC2
#define CONGESTION_TLV_SUBTYPE  8
#define CONGESTION_TLV_CNPV     0xFF
#define CONGESTION_TLV_READY    0x00

#define min(a,b)        a<b? a:b

/*Macro Definitions */
/* TLV types */
#define CHASSIS_ID_TLV_TYPE			1
#define PORT_ID_TLV_TYPE			2
#define TTL_TLV_TYPE				3
#define PORT_DESC_TLV_TYPE			4
#define SYSTEM_NAME_TLV_TYPE			5
#define SYSTEM_DESC_TLV_TYPE			6
#define SYSTEM_CAP_TLV_TYPE			7
#define MANAGEMENT_ADDR_TLV_TYPE		8
#define ORGANIZATIONALLY_SPECIFIC_TLV_TYPE	127
#define END_OF_LLDP_TLV_TYPE			0

#define CHASSIS_ID_SUB_TYPE			4
#define PORT_ID_SUB_TYPE			3

/* used in the frame creation*/
#define TLV_HEADER_LENGTH 			2
#define TLV_TYPE_MASK				0x7F			/* seven 1's */
#define TLV_LENGTH_MASK				0x1FF			/* nine 1's */

#define OUI_0			0x00
#define OUI_1			0x80
#define OUI_2			0xC2

#define INTEL_OUI_0		0x00
#define INTEL_OUI_1		0x1B
#define INTEL_OUI_2		0x21

#define ETHER_TYPE_0		0x88
#define ETHER_TYPE_1		0xCC

/* multi cast address for frame creation */
#define	MULTICAST_ADDR_0	0x01
#define	MULTICAST_ADDR_1	0x80
#define	MULTICAST_ADDR_2	0xc2
#define	MULTICAST_ADDR_3	0x00
#define	MULTICAST_ADDR_4	0x00
#define	MULTICAST_ADDR_5	0x0e

/* these are used in auto negotiation */
#define IEEE_OUI		0x0080C2
#define INTEL_OUI		0x001B21
#define DCBX_CEE_SUBTYPE	2
#define DCBX_CIN_SUBTYPE	1

/* Default cfg */
#define BW_PERCENT       	100
#define MAX_BANDWIDTH_GROUPS   	8
#define MAX_TCS			8
#define STRICT_PRIORITY		0
#define DEFAULT_APP_TABLES	3
#define FCoE_ETHERTYPE		0x8906
#define RoCE_ETHERTYPE		0x8915
#define ISCSI_PORT_NUM		860
#define ETHERTYPE_SELECTOR	1
#define TCP_SELECTOR		2

#define OPER_PARAM_CHANGE		1
#define REMOTE_PARAM_CHANGE		2
#define REMOTE_PARAM_SHUTDOWN		4

enum {ieee_oui = 1, intel_oui};
enum bool_val	{False, True};
enum condistion{greater_than, lesser_than};
enum remote_willing { rwNull , rwTrue , rwFalse =0 };
enum dcbx_flag	{Received_cfg=2, Local_cfg=1};

enum dcbx_cap_version       {
        DCBX_CAP_CIN,
        DCBX_CAP_CEE=0x04,
        DCBX_CAP_IEEE=0x08
        };


#pragma pack(1)
typedef struct tlv_hdr
{
	uint16_t 	type:7;
	uint16_t	 length:9;
}tlv_hdr_t;

struct chassis_id_tlv {
	uint16_t 	type:7;
	uint16_t	length:9;
	/* TLV information string */
	uint8_t		sub_type;
	uint8_t		chassis_id[6];
};

struct port_id_tlv {
	uint16_t 	type:7;
	uint16_t	length:9;
	/* TLV information string */
	uint8_t		sub_type;
	uint8_t		port_id[6];
};

struct ttl_tlv {
	uint16_t 	type:7;
	uint16_t	length:9;
	/* TLV information string */
	uint16_t	ttl;
};

struct endof_lldp_tlv  {
	uint16_t 	type:7;
	uint16_t	length:9;
};

#pragma pack(0)
struct port_time	{
/* Tx */
	uint16_t state;
	uint16_t reinit_delay;
	uint16_t msg_tx_hold;
	uint16_t msg_tx_interval;
	uint16_t msg_fast_tx;
	uint16_t tx_fast_init;
	uint16_t tx_ttr;
	uint16_t tx_shutdown_while;
	uint16_t tx_credit;
	uint16_t tx_max_credit;
	bool 	 tx_tick;
/* Rx */
	uint16_t too_many_nghbrs_timer;
	uint32_t rx_ttl;
	uint16_t lastrx_ttl;  	/* cache last received */
};

struct lldp_tx_port {
    uint64_t 	*frameout; 	 /*The tx frame buffer */
    uint16_t	sizeout;	 /* The size of our tx frame */
    uint8_t 	state;    	 /* The tx state for this interface */
    uint32_t 	local_change; 	 /* indicates change in local config */
    uint16_t	tx_ttl;		 /* TTL value */
    bool 	tx_now;
    uint16_t	tx_fast;
  };
struct lldp_rx_port {
    cvmx_wqe_t 	*framein;
    cvmx_wqe_t 	*temp_framein;
    uint16_t 	sizein;
    uint8_t 	state;
    int32_t 	rcv_frame;
    uint8_t 	rx_info_age;
    uint8_t 	rx_changes;
    uint8_t  	remote_change;
    uint8_t 	too_many_neighbors;
    uint8_t 	dcbx_st;
    bool	new_neighbor;
};
typedef struct lldp_sm_attr
{
	struct lldp_rx_port 	rx;
	struct lldp_tx_port 	tx;
	// Madhu Should be timer
	struct port_time	timer;
	uint32_t 		port_enabled;
	uint8_t 		admin_status;
}lldp_sm_attr_t;

struct default_tlvs {
	struct chassis_id_tlv	chassis_id;
	struct port_id_tlv	port_id;
	struct ttl_tlv		ttl;
	struct endof_lldp_tlv 	endof_lldp;
	cn_tlv_t 		cn_tlv;			//qcn tlv
};

/* This DCBX main structure  can holds  all DCBX Versions cfg  */
typedef struct dcbx_config {
	bool				timer_flag;
	cvmx_tim_delete_t	 	timer_delete_info;
	lldp_sm_attr_t			port;
	uint8_t				remote_dcbx_ver;
	uint8_t				oper_dcbx_ver;
	struct dcbx_ieee_config         dcbx_ieee;
	struct dcbx_cee_config          dcbx_cee;
	struct ethernet_header 		eth_hddr;
	struct default_tlvs		default_tlv;
	uint8_t				remote_enabled;
	cvmx_spinlock_t 		lock;
}dcbx_config_t;

typedef struct dcbx_def_config {
	struct oct_nic_dcbx_config      dcbx_ieee;
	struct oct_nic_dcbx_config      dcbx_cee;
} dcbx_def_config_t;

/* Enums */
/* port admin status */
enum portAdminStatus {
    disabled,			/* to disable the LLDP */
    enabled_tx_only,		/* LLDP configured to only Tx */
    enabled_rx_only,		/* LLDP configured to only Rx */
    enabled_rx_tx		/* LLDP configured to both Tx & Rx */
};

/* Tx Timer States */
enum {
	TX_TIMER_BEGIN,
	TX_TIMER_INITIALIZE,
	TX_TIMER_IDLE,
	TX_TIMER_EXPIRES,
	TX_TICK,
	SIGNAL_TX,
	TX_FAST_START
};

/* Tx States */
enum {
	TX_BEGIN,
	TX_LLDP_INITIALIZE,
	TX_IDLE,
	TX_SHUTDOWN_FRAME,
	TX_INFO_FRAME
};

int  cvmcs_dcbx_enable(int ifidx);
void  cvmcs_dcbx_disable(int ifidx);
uint8_t cvmcs_dcbx_tx_frame(uint8_t port_num, lldp_sm_attr_t *port);

uint8_t cvmcs_dcbx_auto_negotiation (cvmx_wqe_t  *wqe );
void cvmcs_dcbx_rx_statemachine_run(uint8_t port_num, lldp_sm_attr_t *port);
bool cvmcs_dcbx_rx_global_statemachine_run( lldp_sm_attr_t  *port);
void cvmcs_dcbx_rx_delete_aged_info(uint8_t port_num, lldp_sm_attr_t *port);
uint8_t  cvmcs_dcbx_rx_initialize_lldp(uint8_t port_num, lldp_sm_attr_t  *port);
void cvmcs_dcbx_rx_wait_for_frame(uint8_t port_num, lldp_sm_attr_t*port);
void cvmcs_dcbx_rx_frame(uint8_t port_num, lldp_sm_attr_t *port);
void cvmcs_dcbx_rx_delete_info(uint8_t port_num, lldp_sm_attr_t *port);
void cvmcs_dcbx_rx_update_info(lldp_sm_attr_t *port);
void cvmcs_dcbx_tx_statemachine_run(uint8_t port_num);
bool cvmcs_dcbx_set_tx_state(lldp_sm_attr_t *port);
void cvmcs_dcbx_tx_initialize_lldp(uint8_t port_num, lldp_sm_attr_t *port);
void cvmcs_dcbx_tx_idle( lldp_sm_attr_t *port);
void cvmcs_dcbx_tx_shutdown_frame(uint8_t port_num, lldp_sm_attr_t *port);
uint8_t  cvmcs_dcbx_mib_constr_shutdown_lldpdu(uint8_t port_num, lldp_sm_attr_t *port);
void cvmcs_dcbx_tx_info_frame(uint8_t port_num, lldp_sm_attr_t *port);
void cvmcs_dcbx_param_indication(uint8_t port_num);
void  cvmcs_dcbx_update_tx_timers(lldp_sm_attr_t *port);
void cvmcs_dcbx_update_rx_timers(lldp_sm_attr_t *port);

int  cvmcs_dcbx_read_ttl_tlv(void  *tlv_offset, lldp_sm_attr_t *port);
void cvmcs_dcbx_timer(cvmx_wqe_t *wqe);
void cvmcs_dcbx_run_tx_timers_sm(lldp_sm_attr_t  *port);
bool cvmcs_dcbx_set_tx_timers_state(lldp_sm_attr_t  *port);
void cvmcs_dcbx_tx_timer_change_state(lldp_sm_attr_t  *port, uint8_t newstate);
void cvmcs_dcbx_tx_initialize_timers(lldp_sm_attr_t  *port);

int cvmcs_dcbx_set_params(int port_num, struct oct_nic_dcbx_cmd *dcbx_cmd);

#endif /*__CVMCS_DCBX_H__*/
