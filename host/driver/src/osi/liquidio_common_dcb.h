/**********************************************************************
* Author: Cavium, Inc.
*
* Contact: support@cavium.com
*          Please include "LiquidIO" in the subject.
*
* Copyright (c) 2003-2016 Cavium, Inc.
*
* This file is free software; you can redistribute it and/or modify
* it under the terms of the GNU General Public License, Version 2, as
* published by the Free Software Foundation.
*
* This file is distributed in the hope that it will be useful, but
* AS-IS and WITHOUT ANY WARRANTY; without even the implied warranty
* of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE, TITLE, or
* NONINFRINGEMENT.  See the GNU General Public License for more
* details.
*
* This file may also be available under a different license from Cavium.
* Contact Cavium, Inc. for more information
**********************************************************************/

/*!  \file  liquidio_common_dcb.h
 *   \brief Common: Structures and macros used in PCI-NIC package by core and
 *   host driver.
 */

#ifndef __LIQUIDIO_COMMON_DCB_H__
#define __LIQUIDIO_COMMON_DCB_H__

#include "liquidio_common.h"

#define OCTEON_MAX_TRAFFIC_CLASSES                8
#define OCTEON_MAX_PRIO_GROUP                     8
#define OCTEON_MAX_PRIORITIES                     8
#define OCTEON_MAX_APPLICATION_PRIORITIES       169

#define OCTEON_DCB_CAP_DCBX_HOST               0x01
#define OCTEON_DCB_CAP_DCBX_LLD_MANAGED        0x02
#define OCTEON_DCB_CAP_DCBX_VER_CEE            0x04
#define OCTEON_DCB_CAP_DCBX_VER_IEEE           0x08
#define OCTEON_DCB_CAP_DCBX_STATIC             0x10

#define OCTEON_CAP_FLAG_DCB			0x1
#define OCTEON_CAP_FLAG_QCN			0x2

#define OCTEON_FLAG_DCB_ENABLE			0x1
#define OCTEON_FLAG_QCN_ENABLE			0x2

#define DCB_CFG_CMD_DCB_CONFIG			0x1
#define DCB_CFG_CMD_DCB_RECONFIG		0x2
#define DCB_CFG_CMD_DCB_ENABLE			0x3
#define DCB_CFG_CMD_DCB_DISABLE			0x4
#define DCB_CFG_CMD_DCB_SET_PARAMS		0x5

#define QCN_FRAME_HANDLE             		0x0FFF0C83
#define DCBX_LLDP_FRAME_HANDLE       		0x0FFF8AF1

#define DCBX_CMD_SET_PFC			0x1
#define DCBX_CMD_SET_ETS			0x2
#define DCBX_CMD_SET_APP			0x4
#define DCBX_CMD_SET_ALL			0x7

#define DCB_FLAG_OPER_PFC			0x01
#define DCB_FLAG_OPER_ETS			0x02
#define DCB_FLAG_OPER_APP			0x04
#define DCB_FLAG_OPER_SHUTDOWN			0x08
#define DCB_FLAG_OPER_ALL			0x07
#define DCB_FLAG_REMOTE_PFC			0x10
#define DCB_FLAG_REMOTE_ETS			0x20
#define DCB_FLAG_REMOTE_APP			0x40
#define DCB_FLAG_REMOTE_SHUTDOWN		0x80
#define DCB_FLAG_REMOTE_ALL			0x70

#define DCBX_FLAG_ENABLED			0x80		
#define DCBX_FLAG_WILLING			0x40		
#define DCBX_FLAG_ERROR				0x20		

enum dcbx_version {
	DCBX_UNKNOWN	= 0,
	DCBX_CEE 	= 1,
	DCBX_IEEE	= 2,
	DCBX_CIN	= 4
};

/* This structure contains the IEEE 802.1Qaz APP managed object. This
 * object is also used for the CEE std as well. There is no difference
 * between the objects.
 *
 * @selector: protocol identifier type
 * @protocol: protocol of type indicated
 * @priority: 3-bit unsigned integer indicating priority
 *
 * ----
 *  Selector field values
 *      0       Reserved
 *      1       Ethertype
 *      2       Well known port number over TCP or SCTP
 *      3       Well known port number over UDP or DCCP
 *      4       Well known port number over TCP, SCTP, UDP, or DCCP
 *      5-7     Reserved
 */
struct app_prio_table {
	u8 selector;
	u8 priority;
	u16 protocol_id;
};

struct dcbx_app_prio_config {
	u8 app_flags;
	u8 num_app_prio;
	struct app_prio_table app_prio[OCTEON_MAX_APPLICATION_PRIORITIES];
};

/* This structure contains the IEEE 802.1Qaz PFC managed object
 *
 * @pfc_flags: Enabled, willing and error bits in PFC
 * @pfc_capability: Indicates the number of traffic classes on the local device
 *                that may simultaneously have PFC enabled.
 * @pfc_enable: bitmap indicating pfc enabled traffic classes
 * @mbc: enable macsec bypass capability
 */
struct dcbx_pfc_config {
	u8 pfc_flags;
	u8 pfc_capability;
	u8 pfc_enable;
	u8 mbc;
};

/* This structure contains the IEEE 802.1Qaz ETS managed object
 * @ets_flags: Enabled, willing and error bits in ETS
 * @NumTrafficClasses: indicates supported capacity of ets feature
 * @cbs: credit based shaper ets algorithm supported
 * @TcBandwidthAssignmentTable: tc tx bandwidth indexed by traffic class
 * @TsaAssignmentTable: TSA Assignment table, indexed by traffic class
 * @PriorityAssignmentTable: priority assignment table mapping 8021Qp to traffic
 * class.
 * @pgid:priority to PG mapping indexed by priority (Priority Group[0..7])
 * @pg_bw: bandwidth percentage for each priority group
 * @prio_type:priority type is link or group .
 *
 * ----
 *	PG ID 15 is reserved for Strict priority
 *      TSA Assignment 8 bit identifiers
 *              0               strict priority
 *              1               credit-based shaper
 *              2               enhanced transmission selection
 *              3-254   reserved
 *              255             vendor specific
 */
enum octeon_dcb_tsa_assignment {
	OCTEON_TSA_STRICT_PRIORITY = 0,
	OCTEON_TSA_CREDIT_BASED_SHAPER = 1,
	OCTEON_TSA_ETS = 2,
	OCTE_TSA_VENDOR = 255,
};
	
struct dcbx_ets_config {
	u8 ets_flags;
	u8 num_traffic_classes;
	union {
		struct {
			u8 cbs;
			u8 priority_assignment_table[OCTEON_MAX_TRAFFIC_CLASSES];
			u8 tc_bandwidth_assignment_table[OCTEON_MAX_TRAFFIC_CLASSES];
			u8 tsa_assignment_table[OCTEON_MAX_TRAFFIC_CLASSES];
		} ieee;
		struct {
			u8 pgid[OCTEON_MAX_TRAFFIC_CLASSES];
			u8 pg_bw[OCTEON_MAX_PRIO_GROUP];
		} cee;
	};
};

/* This structure used for dcb configuration.
 * @pfc_config:pfc config structure.
 * @ets_config:ets_config structure.
 */
struct oct_nic_dcbx_config {
	struct dcbx_pfc_config pfc_config;
	struct dcbx_ets_config ets_config;
	struct dcbx_app_prio_config app_config;
};

/* This structure used by the host to send local DCBX parameters
 * @cmd: set PFC/ETS/SET APP
 * @dcbx_version: DCBX Version
 * @local: local dcbx parameters.
 */
struct oct_nic_dcbx_cmd {
	u8 cmd;
	u8 dcbx_version;
	struct oct_nic_dcbx_config config;
};

/* This structure used by firmware to update host the remote and operational
 * parameters
 * @flags: Flags 
 * @dcbx_version: DCBX Version
 * @remote: Remote parameters
 * @operational: Operational parametrs
 */
struct oct_nic_dcbx_info {
	u8 flags;
	u8 dcbx_version;
	struct oct_nic_dcbx_config remote;
	struct oct_nic_dcbx_config operational;
};

/* This structure used for dcb capabilities supported by the device
 *
 * @dcbx_version: IEEE,CEE,CIN version supported by the device
 * @MaxNumTrafficClasses:  maximum number of traffic classes
 * @MaxNumEtsCapableTrafficClasses:max no.of Ets capable traffic classes
 * @MaxNumPfcEnabledTrafficClasses:max no.of pfc enabled traffic classes
 *
 */
struct oct_nic_dcb_cap {
	u8 dcbx_cap;
	u8 maxnum_traffic_classes;
	u8 maxnum_etscapable_traffic_classes;
	u8 maxnum_pfcenabled_traffic_classes;
};

/* This structure is used to return the capabilities and current
 * parameters of DCB in the firmware.
 *
 * @dcb_cap : NIC DCB capabilities
 * @dcbx_version : Current Local DCBX Version
 * @ieee_config : Current Local DCBX IEEE configuration
 * @cee_config : Current Local DCBX CEE configuration
 */
struct oct_nic_dcb_cfg_info
{
	struct oct_nic_dcb_cap		dcb_cap;
	u8 				dcbx_version;
	struct oct_nic_dcbx_config	ieee_config;
	struct oct_nic_dcbx_config	cee_config;
};

/* This structure is used to configure the DCB features
 *
 * @qcn_enable : Enable QCN feature
 * @dcbx_offload : DCBX porotocol offload
 * @dcbx_ieee : Offload DCBX_IEEE protocol
 * @dcbx_cee : Offload DCBX_CEE protocol
 */
union oct_nic_dcb_cfg
{
	u64	u64;
	struct {
#ifdef __CAVIUM_BIG_ENDIAN_BITFIELD
		u64	cfg_command:4;
		u64	qcn_enable:1;
		u64	dcbx_offload:1;
		u64	dcbx_ieee:1;
		u64	dcbx_cee:1;
		u64	reserved:56;
#else
		u64	reserved:56;
		u64	dcbx_cee:1;
		u64	dcbx_ieee:1;
		u64	dcbx_offload:1;
		u64	qcn_enable:1;
		u64	cfg_command:4;
#endif
	} s;
};

#endif
