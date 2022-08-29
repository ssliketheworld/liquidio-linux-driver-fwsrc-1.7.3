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

/*! \file octeon_dcb_main.h
 *  \brief Host Driver: This file defines the DCB related macros and structures
 */
#ifndef _OCTEON_DCB_H_
#define	_OCTEON_DCB_H_

#define  MAX_PRIORITY		8
#define  TRUE			1
#define  FALSE			0

#define NUM_TRAFFIC_CLASS	4
//#define DCB_SLEEP_TIMEOUT	500

#define MAX_NUM_TC		8

/* Polling interval for determining when NIC application is alive */
#define LIQUIDIO_STARTER_POLL_INTERVAL_MS 100

enum {
	OCTEON_DCB_ENABLE = (1 << 1),
	OCTEON_QCN_ENABLE = (1 << 2),
};

struct liquidio_dcb_context {
        int octeon_id;
        cavium_wait_channel wc;
        int cond;
        u64 status;
};

struct liquidio_dcb_resp {
        u64 rh;
        u64 status;
};

struct liquidio_dcb_cfg_resp { 
        u64 rh; 
        struct oct_nic_dcb_cfg_info cfg_info;
        u64 status; 
};


/* proto type  for nic module  */

void show_dcb_config(struct oct_nic_dcbx_config *dcbx_config, int dcbx_version);

typedef void (*liquidio_dcb_cfg_callback)(struct lio *lio,
					  struct liquidio_dcb_cfg_resp *resp);
int liquidio_dcb_cfg(struct lio *lio, union oct_nic_dcb_cfg *cfg,
		     liquidio_dcb_cfg_callback resp_fn);
void liquidio_dcb_cfg_init(struct lio *lio, struct liquidio_dcb_cfg_resp *resp);
int liquidio_dcb_init(struct octeon_device *octeon_dev,int ifidx);
int liquidio_dcb_select_q(struct net_device *dev, struct sk_buff *skb);

#endif
