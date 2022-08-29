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
#ifndef __CVMCS_DCBX_CEE_H__
#define __CVMCS_DCBX_CEE_H__

typedef struct lldp_sm_attr lldp_sm_attr_t;

#define PRO_CON_SUB_TLV_TYPE		1
#define PG_SUB_TLV_TYPE			2
#define PFC_SUB_TLV_TYPE		3
#define APP_PROTOCOL_SUB_TLV_TYPE	4

#pragma pack(1)
struct org_header 	{
	uint16_t 	type:7; 
	uint16_t	length:9; 
	uint8_t		oui[3];
	uint8_t		subtype;
};

struct protocol_control_sub_tlv		{
	uint16_t 	type:7; 
	uint16_t	length:9; 
	uint8_t		oper_version;
	uint8_t		max_version;
	uint32_t	seqno;
	uint32_t	ackno;
};
struct feature_pg_cfg		{
	uint8_t		pgid_0:4;		/* PGID of priority 0 */ 
	uint8_t		pgid_1:4;		/* PGID of priority 1 */ 
	uint8_t		pgid_2:4;		/* PGID of priority 2 */ 
	uint8_t		pgid_3:4;		/* PGID of priority 3 */ 
	uint8_t		pgid_4:4;		/* PGID of priority 4 */ 
	uint8_t		pgid_5:4;		/* PGID of priority 5 */ 
	uint8_t		pgid_6:4;		/* PGID of priority 6 */ 
	uint8_t		pgid_7:4;		/* PGID of priority 7 */ 
	uint8_t 	pg_percentage[8];	
	uint8_t		num_tcs_supported;
};

struct feature_pfc_cfg	{	
	uint8_t		pfc_enable;		/* bitmap of priorities indiactes PFC status */
	uint8_t		num_tcpfc_supported;
};

struct feature_app_cfg {
	uint16_t	protocol;
	uint8_t		oui_h:6;
	uint8_t		sel:2;
	uint16_t	oui_l;
	uint8_t		priority;
};

typedef struct feature_tlv_header {
        uint16_t 	type:7;
        uint16_t	length:9;
        uint8_t		oper_version;
        uint8_t		max_version;
        uint8_t		en:1;
        uint8_t		w:1;
        uint8_t		er:1;
        uint8_t		reserv:5;
        uint8_t		subtype;
}feature_tlv_header_t;

struct pg_sub_tlv 	{
	struct feature_tlv_header 	header;
	struct feature_pg_cfg		pg_cfg;
};

struct pfc_sub_tlv	{
	struct feature_tlv_header	header;
	struct feature_pfc_cfg		pfc_cfg;
};

struct app_sub_tlv	{
	struct feature_tlv_header	header;
	struct feature_app_cfg		app_cfg[84];
};

struct cee_lldp_port {		
	struct org_header 		header;
	struct protocol_control_sub_tlv control;
	struct pg_sub_tlv 		pg;
	struct pfc_sub_tlv		pfc;
	struct app_sub_tlv		app;
	uint8_t 			app_tbl_entries;
};
#pragma pack(0)

/* Control state machine variables */	
struct control_sm_variables	{
	uint8_t		state;
	uint32_t	seqno;
	uint32_t	ackno;	
	uint8_t		oper_version;		/* Current dcbx version */
	uint8_t		max_version;
	bool 		no_dcbxtlv_received;	/* No dcbx tlvs received */
	bool		dcbx_feature_update;	/* Indicates a change in DCBX Feature */
	bool		something_changed_local;
	bool		something_changed_remote;
	uint8_t 	rx_oper_version ;
	uint8_t 	rx_max_version;
	uint32_t 	rxackno;
	uint32_t 	rxseqno;
	uint32_t	rcvdseqno;
	uint8_t		rcvdackno;		/* ackno from the most recent peer */
};

typedef union feat_sm_attr	{
	struct feature_pg_cfg	pg;
	struct feature_pfc_cfg	pfc;
	struct {
		uint8_t	app_tbl_entries;
		struct feature_app_cfg	app_tbl[84];
	} app;
}feat_sm_attr_t;

struct feat_sm_var	{
	uint8_t		type;			/* 2 - PG, 3 - PFC, 4 - APP*/
	uint8_t		state;
	bool		willing;
	uint8_t		oper_version;
	uint8_t		max_version;
	bool 		error;
	bool		enabled;
	bool		advertise;
	uint32_t	feature_seqno;
	bool 		syncd;		
	uint32_t	flags;
	feat_sm_attr_t 	oper_cfg;		/* Current operational cfg */		
	feat_sm_attr_t 	peer_cfg;		/* Cfg received from peer */
	feat_sm_attr_t 	desired_cfg;		/* Locally configured cfg */
	bool		peer_willing;		/* Willing state of the peer */
	feat_sm_attr_t 	local_param_cfg;
	bool		local_param_willing;
	bool		local_param_advertise;
	bool		local_param_enabled;
	bool		local_parameter_change;	/* state variable has been modified */
	bool 		rx_feature_present;
	bool 		rx_feature_enabled;
	uint8_t 	rx_feature_oper_version;
	uint8_t 	rx_feature_max_version;
	feat_sm_attr_t 	rx_feature_cfg;
	bool 		rx_feature_willing;
	bool 		rx_error;
};

/* Feature state machine variables */
struct feature_sm_variables	{
	struct feat_sm_var	pg;	
	struct feat_sm_var	pfc;
	struct feat_sm_var	app;
};

struct dcbx_cee_config	{
	struct cee_lldp_port 		local_port ; //(/*cee_lldp_du*/)
	struct cee_lldp_port		remote_port;
	struct control_sm_variables	control_sm_var;
	struct feature_sm_variables	feature_sm_var;
};

/*CEE Macros and Enums*/

//Macro defination
#define PROTOCOL_CONTROL_SUB_TLV_LENGTH 10

/* Macros used in creating LLDP frame */
#define PRO_CON_SUB_TLV_LENGTH		12
#define FEAT_SUB_TLV_HDDR_LENGTH	6
#define FEAT_PG_CFG_SIZE		13
#define FEAT_PFC_CFG_SIZE		2   
#define CEE_APP_PRIO_TABLE_SIZE		6
#define FEAT_APP_CFG_SIZE(n)		(n * CEE_APP_PRIO_TABLE_SIZE)   
#define ORG_HEADER_SIZE			6
#define SUB_TYPE_SIZE			1
#define FEAT_TLV_HDR_SIZE		6
#define ORG_HDDR_LENGTH(n)         	(ORG_HEADER_SIZE-2)+PRO_CON_SUB_TLV_LENGTH+\
                                	FEAT_SUB_TLV_HDDR_LENGTH+FEAT_PG_CFG_SIZE+\
                                	FEAT_SUB_TLV_HDDR_LENGTH+FEAT_PFC_CFG_SIZE+\
                                	FEAT_SUB_TLV_HDDR_LENGTH+FEAT_APP_CFG_SIZE(n)

enum  feature_type	{
	CEE_CONTROL_TYPE =1,
	CEE_PG_TYPE,
	CEE_PFC_TYPE,
	CEE_APP_TYPE
};

enum control_sm_states{
	LINKUP,
	DWAIT,
	UPDATE_DCBX_TLV,
	PEER_NOT_ADVERTISE_DCBXC,
	UPDATE_OPER_VERSIONC,
	PROCESS_PEER_TLV,
	ACK_PEER,
};

enum feature_sm_states {
	SET_LOCAL_PARAMETERS=10,
	FEATURE_NO_ADVERTISE,
	PEER_NOT_ADVERTISE_DCBX,
	PEER_NOT_ADVERTISE_FEATURE,
	UPDATE_OPER_VERSION,
	PEER_UPDATE_OPER_VERSION,
	CFG_NOT_COMPATIBLE,
	USE_LOCAL_CFG,
	USE_PEER_CFG,
	FEATURE_DISABLED,
	ERROR_CHANGE,
	FWAIT,
	GET_PEER_CFG,
};
	
	
uint8_t cvmcs_dcbx_cee_mib_constr_info_lldpdu(uint8_t port_num, 
						lldp_sm_attr_t *port);
uint8_t cvmcs_dcbx_cee_rx_frame(uint8_t port_num, cvmx_wqe_t  *wqe);
void cvmcs_dcbx_cee_rx_shutdown(uint8_t port_num);
void cvmcs_dcbx_cee_something_changed_remote(uint8_t port_num, lldp_sm_attr_t *port);
void cvmcs_dcbx_cee_rx_process_frame(uint8_t port_num, lldp_sm_attr_t * port);
uint8_t cvmcs_dcbx_cee_current_param(uint8_t port_num, 
				     struct oct_nic_dcbx_info * current_dcbx_info);
uint8_t cvmcs_dcbx_cee_config(uint8_t port_num);
uint8_t cvmcs_dcbx_cee_set_default_params(uint8_t port_num);
int cvmcs_dcbx_cee_set_params(int port_num, struct oct_nic_dcbx_cmd *dcbx_cmd);
void cvmcs_dcbx_cee_get_params(int port_num, struct oct_nic_dcbx_config *dcbx_config);

#endif /*__CVMCS_DCBX_CEE_H__*/
