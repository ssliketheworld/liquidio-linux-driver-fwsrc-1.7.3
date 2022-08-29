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
#ifndef __CVMCS_DCBX_IEEE_H__
#define __CVMCS_DCBX_IEEE_H__

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
#define IEEE_8021QAZ_MAX_TCS            8
#define IEEE_PRIO_ASSIGN_SIZE           4

#define ETS_CONFIG_TLV_LENGTH		25
#define ETS_RECMND_TLV_LENGTH		25
#define PFC_CONFIG_TLV_LENGTH		6
#define APP_CONFIG_TLV_LENGTH(n)	(5 + (n * 3))

#define	DCBNL_IEEE_GET_ETS		100
#define	DCBNL_IEEE_SET_ETS		101
#define	DCBNL_IEEE_GET_PFC		102
#define	DCBNL_IEEE_SET_PFC		103
#define	DCBNL_IEEE_GET_APP		104
#define	DCBNL_IEEE_SET_APP		105
#define	DCBNL_IEEE_DEL_APP		106
#define	DCBNL_IEEE_PEER_GET_ETS		107
#define	DCBNL_IEEE_PEER_GET_PFC		108
#define	DCBNL_IEEE_GET_DCBX		109
#define	DCBNL_IEEE_SET_DCBX		110

/*Data structures */
typedef struct lldp_sm_attr lldp_sm_attr_t;

#pragma 	pack(1)
/* ETS configuration TLV */
struct ets_config_tlv {
	uint16_t 	type:7;
	uint16_t	length:9;
	/* TLV information string */
	uint8_t		oui[3];			/* 802.1 OUI i.e 00-80-C2 */
	uint8_t		subtype;		/* IEEE 802.1 subtype i.e 09 */
	uint8_t		willing:1;
	uint8_t		cbs:1;
	uint8_t		reserved:3;
	uint8_t		max_tcs:3;
	uint8_t		prio_assign_table[4];	/* Priority Assignment Table */
	uint8_t		tc_bw_table[8];		/* TC Bandwidth Table */
	uint8_t		tsa_assign_table[8];	/* TSA Assignment Table */
};

/* ETS recommendation TLV */
struct ets_recmnd_tlv {
	uint16_t 	type:7;
	uint16_t	length:9;
	/* TLV information string */
	uint8_t		oui[3];			/* 802.1 OUI i.e 00-80-C2 */
	uint8_t		subtype;		/* IEEE 802.1 subtype i.e 10 */
	uint8_t		reserved;
	 /* Priority Assignment Table */
	uint8_t		prio_assign_table[IEEE_PRIO_ASSIGN_SIZE];
	/* TC Bandwidth Table */
	uint8_t		tc_bw_table[IEEE_8021QAZ_MAX_TCS];
	/* TSA Assignment Table */
	uint8_t		tsa_assign_table[IEEE_8021QAZ_MAX_TCS];
};

/* PFC configuration TLV */
struct pfc_config_tlv {
	uint16_t 	type:7;
	uint16_t	length:9;
	/* TLV information string */
	uint8_t		oui[3];			/* 802.1 OUI i.e 00-80-C2 */
	uint8_t		subtype;		/* IEEE 802.1 subtype i.e 11*/
	uint8_t		willing:1;
	uint8_t		mbc:1;
 	uint8_t		reserved:2;
	uint8_t		pfc_cap:4;		/* Number of traffic classes supports PFC*/
	uint8_t		pfc_enable;		/* PFC Enable bit vector */
};

/* Application Priority TLV */
struct packed_app_prio_table
{
	uint8_t		priority:3;
	uint8_t		reserved:2;
	uint8_t		sel:3;
	uint16_t	protocol_id;
};

struct app_priority_tlv {
	uint16_t 	type:7;
	uint16_t	length:9;
	/* TLV information string */
	uint8_t		oui[3];			/* 802.1 oui i.e 00-80-C2 */
	uint8_t		subtype;		/* IEEE 802.1 subtype  */
	uint8_t		reserved;
	struct packed_app_prio_table    priority_table[];
};

/* Ethernet header  */
struct ethernet_header {
	uint8_t		 dest_addr[6];		/* Destination address */
	uint8_t		 source_addr[6];	/* source MAC address */
	uint16_t	 ether_type;		/* Ethertype i.e 88cc*/
};

/* QCN tlv */
typedef struct {
	uint16_t	type:7;
	uint16_t	length:9;
	/* TLV information string */
	uint8_t		oui[3];
	uint8_t		sub_type;
	uint8_t		per_prio_cnpv_indicator;
	uint8_t		per_prio_ready_indicator;

}cn_tlv_t;
#pragma 	pack(0)

typedef struct ieee_ets_cfg {
	uint8_t		willing;
	uint8_t		cbs;
	uint8_t		max_tcs;
	uint8_t		prio_assign_table[8];		/* Priority Assignment Table */
	uint8_t		tc_bw_table[8];			/* TC Bandwidth Table */
	uint8_t		tsa_assign_table[8];		/* TSA Assignment Table */
}ieee_ets_cfg_t;

typedef struct ieee_ets_recmd_cfg {
	uint8_t		prio_assign_table[8];		/* Priority Assignment Table */
	uint8_t		tc_bw_table[8];			/* TC Bandwidth Table */
	uint8_t		tsa_assign_table[8];		/* TSA Assignment Table */
}ieee_ets_recmd_cfg_t;

typedef struct ieee_pfc_cfg {
	uint8_t		willing;
	uint8_t		mbc;
	uint8_t		pfc_cap;			/* Number of traffic classes supports PFC*/
	uint8_t		pfc_enable;			/* PFC Enable bit vector */
}ieee_pfc_cfg_t;

typedef struct ieee_app_prio_cfg {
	uint8_t	num_prio;
	struct packed_app_prio_table priority_table[169]; //MAX_APP_TBL_ENTRIES
} ieee_app_prio_cfg_t;

struct lldp_port {
	uint64_t		port_addr;
	uint8_t			ets_flag;
	uint8_t			pfc_flag;
	ieee_ets_cfg_t 	 	ets_config;
	ieee_ets_recmd_cfg_t	ets_recmnd;
	ieee_pfc_cfg_t	 	pfc_config;
	ieee_app_prio_cfg_t	app_config;
};

struct as_port_config {
	uint8_t		local_willing;
	uint8_t		cbs;
	uint8_t		max_tcs;
	uint8_t		prio_assign_table[IEEE_8021QAZ_MAX_TCS];
	uint8_t		tc_bw_table[IEEE_8021QAZ_MAX_TCS];
	uint8_t		tsa_assign_table[IEEE_8021QAZ_MAX_TCS];
};

/* Symmetric state port configuration */
struct sy_port_config {
	uint8_t		mbc;
	uint8_t		pfc_cap;
	uint8_t		pfc_enable;
};

struct oper_port {
	struct sy_port_config   pfc_config ;
	struct as_port_config 	ets_config;
};

/*IEEE DCBX  Variables */
struct dcbx_ieee_config	{
	//to identify current app cfg is admin_cfg or receive_cfg
	uint8_t				ets_flag;
	uint8_t				pfc_flag;
	uint8_t				app_flag;
	struct lldp_port		local_port;
	struct lldp_port		remote_port;
	struct oper_port		oper_port;
};

void cvmcs_dcbx_ieee_asymmetric_st_machine(uint8_t port_num);
void cvmcs_dcbx_ieee_symmetric_st_machine(uint8_t port_num);
void cvmcs_dcbx_ieee_something_changed_remote(uint8_t port_num, lldp_sm_attr_t *port);
uint8_t cvmcs_dcbx_ieee_mib_constr_info_lldpdu(uint8_t port_num,lldp_sm_attr_t *port);

uint8_t cvmcs_dcbx_ieee_rx_frame (uint8_t  port_num, cvmx_wqe_t  *wqe);
void cvmcs_dcbx_ieee_rx_shutdown(uint8_t port_num);
uint8_t cvmcs_dcbx_ieee_mib_delete_objects(uint8_t port_num, lldp_sm_attr_t *port);
void cvmcs_dcbx_ieee_current_param(uint8_t port_num, struct oct_nic_dcbx_info *current_dcbx_info);
uint8_t cvmcs_dcbx_ieee_rx_process_frame(uint8_t port_num, lldp_sm_attr_t * port);

void cvmcs_dcbx_ieee_unpack_prio_assign_tbl(uint8_t *packed_prio_assign_table,
					uint8_t *unpacked_prio_assign_tbl);
void cvmcs_dcbx_ieee_pack_store_prio_assign_tbl(uint8_t *unpacked_prio_assign_table,
						 uint8_t *packed_prio_assign_tbl);

void cvmcs_dcbx_ieee_show_cfg_details(struct oct_nic_dcbx_config *dcbx_config);
void cvmcs_dcbx_ieee_config(uint8_t port_num);
uint8_t cvmcs_dcbx_ieee_set_default_params(uint8_t port_num);
int cvmcs_dcbx_ieee_set_params(int port_num, struct oct_nic_dcbx_cmd *dcbx_cmd);
void cvmcs_dcbx_ieee_get_params(int port_num, struct oct_nic_dcbx_config *dcbx_config);

#endif /*__CVMCS_DCBX_IEEE_H__*/
