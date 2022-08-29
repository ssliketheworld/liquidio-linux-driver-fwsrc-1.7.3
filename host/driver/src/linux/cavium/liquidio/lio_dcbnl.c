/**********************************************************************
* Author: Cavium, Inc.
*
* Contact: support@cavium.com
*          Please include "LiquidIO" in the subject.
*
* Copyright (c) 2003-2014 Cavium, Inc.
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
#include <linux/types.h>
#include <linux/list.h>
#include <linux/workqueue.h>
#include <linux/interrupt.h>
#include "cavium_sysdep.h"
#include "octeon_config.h"
#include "liquidio_common.h"
#include "octeon_droq.h"
#include "octeon_iq.h"
#include "response_manager.h"
#include "octeon_device.h"
#include "octeon_nic.h"
#include "octeon_main.h"
#include "octeon_network.h"
#include "cn66xx_regs.h"
#include "cn66xx_device.h"
#include "cn68xx_regs.h"
#include "cn68xx_device.h"
#include "liquidio_image.h"
#include <linux/dcbnl.h>
#include "lio_dcb_main.h"

static int liquidio_dcb_set_params(struct lio *lio)
{
	union oct_nic_dcb_cfg cfg;

	cfg.u64 = 0;

	cfg.s.cfg_command = DCB_CFG_CMD_DCB_SET_PARAMS;

	return liquidio_dcb_cfg(lio, &cfg, NULL);
}

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 0, 0))

/**
 * liquidio_dcbnl_ieee_getets - retrieve local IEEE ETS configuration
 * @netdev: the corresponding netdev
 * @ets: structure to hold the ETS information
 * Returns local IEEE ETS configuration
 **/
static int liquidio_dcbnl_ieee_getets(struct net_device *dev,
				      struct ieee_ets *ets)
{
	struct lio *lio = GET_LIO(dev);
	struct dcbx_ets_config ets_config =
		lio->oct_dcb.dcbx_info.operational.ets_config;

	if (!atomic_read(&lio->oct_dcb.dcb_state)) {
		cavium_pr_info("DCB is not enabled\n");
		return 1;
	}

	if (lio->oct_dcb.dcbx_info.dcbx_version != DCBX_IEEE) {
		cavium_pr_info("DCBX Version Mismatch\n");
		return 1;
	}

	ets->willing = (ets_config.ets_flags & DCBX_FLAG_WILLING) ? 1 : 0;

	ets->ets_cap = ets_config.num_traffic_classes;

	ets->cbs = ets_config.ieee.cbs;

	memcpy(ets->tc_tx_bw,
	       ets_config.ieee.tc_bandwidth_assignment_table,
	       sizeof(ets->tc_tx_bw));

	memcpy(ets->tc_tsa,
	       ets_config.ieee.tsa_assignment_table,
	       sizeof(ets->tc_tsa));

	memcpy(ets->prio_tc,
	       ets_config.ieee.priority_assignment_table,
	       sizeof(ets->prio_tc));

	return 0;
}

/**
 * liquidio_dcbnl_ieee_setets - Set the ETS information to octeon
 * @netdev: the corresponding netdev
 * @ets: structure to hold the ETS information
 *
 * Set the ETS configuration information to octeon
 **/
static int liquidio_dcbnl_ieee_setets(struct net_device *dev,
				      struct ieee_ets *ets)
{
	struct lio *lio = GET_LIO(dev);
	struct dcbx_ets_config *ets_config =
		&lio->oct_dcb.dcbx_ieee_cmd.config.ets_config;

	lio->oct_dcb.dcbx_ieee_cmd.cmd = DCBX_CMD_SET_ETS;

	ets_config->num_traffic_classes = ets->ets_cap;

	if (ets->willing)
		ets_config->ets_flags |=  DCBX_FLAG_WILLING;

	memcpy(ets_config->ieee.tc_bandwidth_assignment_table,
	       ets->tc_tx_bw,
	       sizeof(ets_config->ieee.tc_bandwidth_assignment_table));

	memcpy(ets_config->ieee.tsa_assignment_table,
	       ets->tc_tsa,
	       sizeof(ets_config->ieee.tsa_assignment_table));

	memcpy(ets_config->ieee.priority_assignment_table,
	       ets->prio_tc,
	       sizeof(ets_config->ieee.priority_assignment_table));

	if (liquidio_dcb_set_params(lio)) {
		cavium_pr_info(" send dcb command failed\n");
		return 1;
	}

	lio->oct_dcb.dcbx_ieee_cmd.cmd = 0;

	return 0;
}

/**
 * liquidio_dcbnl_ieee_getpfc - retrieve local IEEE PFC configuration
 * @netdev: the corresponding netdev
 * @pfc: structure to hold the PFC information
 *
 * Returns local IEEE PFC configuration
 **/
static int liquidio_dcbnl_ieee_getpfc(struct net_device *dev,
				      struct ieee_pfc *pfc)
{
	struct lio *lio = GET_LIO(dev);
	struct dcbx_pfc_config pfc_cfg = 
		lio->oct_dcb.dcbx_info.operational.pfc_config;

	pfc->pfc_cap = pfc_cfg.pfc_capability;
	pfc->pfc_en = pfc_cfg.pfc_enable;
	pfc->mbc = pfc_cfg.mbc;
	return 0;
}

static int liquidio_dcbnl_ieee_setpfc(struct net_device *dev,
				      struct ieee_pfc *pfc)
{
	struct lio *lio = GET_LIO(dev);
	struct dcbx_pfc_config *pfc_config =
		&lio->oct_dcb.dcbx_ieee_cmd.config.pfc_config;

	lio->oct_dcb.dcbx_ieee_cmd.cmd = DCBX_CMD_SET_PFC;

	pfc_config->pfc_capability = pfc->pfc_cap;
	pfc_config->pfc_enable = pfc->pfc_en;
	pfc_config->mbc = pfc->mbc;

	if (liquidio_dcb_set_params(lio)) {
		cavium_pr_info(" send dcb command failed\n");
		return 1;
	}

	lio->oct_dcb.dcbx_ieee_cmd.cmd = 0;

	return 0;
}

static int liquidio_dcbnl_ieee_getapp(struct net_device *dev,
				      struct dcb_app *app)
{
	int i;
	struct lio *lio = GET_LIO(dev);
	struct dcbx_app_prio_config app_config =
		lio->oct_dcb.dcbx_info.operational.app_config;

	if (!atomic_read(&lio->oct_dcb.dcb_state)) {
		cavium_pr_info("DCB is not enabled\n");
		return 1;
	}

	if (lio->oct_dcb.dcbx_info.dcbx_version != DCBX_IEEE) {
		cavium_pr_info("DCBX Version Mismatch\n");
		return 1;
	}

	for (i = 0; i < app_config.num_app_prio; i++) {
		if ((app_config.app_prio[i].selector == app->selector) &&
		    (app_config.app_prio[i].protocol_id == app->protocol)) {
			app->priority = app_config.app_prio[i].priority;
			return 0;
		}
	}

	return 1;
}

static int liquidio_dcbnl_ieee_setapp(struct net_device *dev,
				      struct dcb_app *app)
{
	int i;
	struct lio *lio = GET_LIO(dev);
	struct dcbx_app_prio_config *app_config =
		&lio->oct_dcb.dcbx_ieee_cmd.config.app_config;

	if (!atomic_read(&lio->oct_dcb.dcb_state)) {
		cavium_pr_info("DCB is not enabled\n");
		return 1;
	}

	if (lio->oct_dcb.dcbx_info.dcbx_version != DCBX_IEEE) {
		cavium_pr_info("DCBX Version Mismatch\n");
		return 1;
	}

	for (i = 0; i < app_config->num_app_prio; i++) {
		if ((app_config->app_prio[i].selector == app->selector) &&
		    (app_config->app_prio[i].protocol_id == app->protocol)) {
			app_config->app_prio[i].priority = app->priority;
			lio->oct_dcb.dcbx_ieee_cmd.cmd |= DCBX_CMD_SET_APP;

			if (liquidio_dcb_set_params(lio)) {
				cavium_pr_info(" send dcb command failed\n");
				return 1;
			}

			lio->oct_dcb.dcbx_ieee_cmd.cmd = 0;
			return 0;
		}
	}

	if (app_config->num_app_prio >= OCTEON_MAX_APPLICATION_PRIORITIES) {
		cavium_pr_info("Max Applications reached\n");
		return 1;
	}

	i = app_config->num_app_prio++;

	app_config->app_prio[i].selector = app->selector;
	app_config->app_prio[i].priority = app->priority;
	app_config->app_prio[i].protocol_id = app->protocol;

	lio->oct_dcb.dcbx_ieee_cmd.cmd |= DCBX_CMD_SET_APP;

	if (liquidio_dcb_set_params(lio)) {
		cavium_pr_info(" send dcb command failed\n");
		return 1;
	}

	lio->oct_dcb.dcbx_ieee_cmd.cmd = 0;

	return 0;

}

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 1, 0))
static int liquidio_dcbnl_ieee_delapp(struct net_device *dev,
				      struct dcb_app *app)
{
	int i, j;
	struct lio *lio = GET_LIO(dev);
	struct dcbx_app_prio_config *app_config =
		&lio->oct_dcb.dcbx_ieee_cmd.config.app_config;

	if (!atomic_read(&lio->oct_dcb.dcb_state)) {
		cavium_pr_info("DCB is not enabled\n");
		return 1;
	}

	if (lio->oct_dcb.dcbx_info.dcbx_version != DCBX_IEEE) {
		cavium_pr_info("DCBX Version Mismatch\n");
		return 1;
	}

	for (i = 0; i < app_config->num_app_prio; i++) {
		if ((app_config->app_prio[i].selector == app->selector) &&
		    (app_config->app_prio[i].protocol_id == app->protocol)) {
			for (j = i + 1;
			     j < app_config->num_app_prio;
			     j++) {
				app_config->app_prio[j - 1] =
					app_config->app_prio[j];
			}

			app_config->num_app_prio--;

			lio->oct_dcb.dcbx_ieee_cmd.cmd |= DCBX_CMD_SET_APP;

			if (liquidio_dcb_set_params(lio)) {
				cavium_pr_info(" send dcb command failed\n");
				return 1;
			}

			lio->oct_dcb.dcbx_ieee_cmd.cmd = 0;
			return 0;
		}
	}

	return 1;
}
#endif

static int liquidio_dcbnl_ieee_peer_getets(struct net_device *dev,
					   struct ieee_ets *ets)
{
	struct lio *lio = GET_LIO(dev);
	struct dcbx_ets_config ets_config =
		lio->oct_dcb.dcbx_info.remote.ets_config;

	if (!atomic_read(&lio->oct_dcb.dcb_state)) {
		cavium_pr_info("DCB is not enabled\n");
		return 1;
	}

	if (lio->oct_dcb.dcbx_info.dcbx_version != DCBX_IEEE) {
		cavium_pr_info("DCBX Version Mismatch\n");
		return 1;
	}

	ets->willing = (ets_config.ets_flags & DCBX_FLAG_WILLING) ? 1 : 0;

	ets->ets_cap = ets_config.num_traffic_classes;

	ets->cbs = ets_config.ieee.cbs;

	memcpy(ets->tc_tx_bw,
	       ets_config.ieee.tc_bandwidth_assignment_table,
	       sizeof(ets->tc_tx_bw));

	memcpy(ets->tc_tsa,
	       ets_config.ieee.tsa_assignment_table,
	       sizeof(ets->tc_tsa));

	memcpy(ets->prio_tc,
	       ets_config.ieee.priority_assignment_table,
	       sizeof(ets->prio_tc));

	return 0;

}

static int liquidio_dcbnl_ieee_peer_getpfc(struct net_device *dev,
					   struct ieee_pfc *pfc)
{
	struct lio *lio = GET_LIO(dev);
	struct dcbx_pfc_config pfc_cfg = 
		lio->oct_dcb.dcbx_info.remote.pfc_config;

	pfc->pfc_cap = pfc_cfg.pfc_capability;
	pfc->pfc_en = pfc_cfg.pfc_enable;
	pfc->mbc = pfc_cfg.mbc;
	return 0;
}

#endif

static u8 liquidio_dcbnl_get_state(struct net_device *netdev)
{
	struct lio *lio = GET_LIO(netdev);

	return (!!atomic_read(&lio->oct_dcb.dcb_state));
}

static u8 liquidio_dcbnl_set_state(struct net_device *netdev, u8 state)
{
	int retval;
	union oct_nic_dcb_cfg cfg;
	struct lio *lio = GET_LIO(netdev);

	cfg.u64 = 0;

	if (state) {
		if (atomic_read(&lio->oct_dcb.dcb_state))
			return 0;

		atomic_set(&lio->oct_dcb.dcb_state, 1);

		cfg.s.cfg_command = DCB_CFG_CMD_DCB_ENABLE;

		retval = liquidio_dcb_cfg(lio, &cfg, liquidio_dcb_cfg_init);
		if (retval) {
			atomic_set(&lio->oct_dcb.dcb_state, 0);
			netdev_reset_tc(netdev);
			return 1;
		}
	}
	else {
		if (!atomic_read(&lio->oct_dcb.dcb_state))
			return 0;

		atomic_set(&lio->oct_dcb.dcb_state, 0);

		cfg.s.cfg_command = DCB_CFG_CMD_DCB_DISABLE;

		retval = liquidio_dcb_cfg(lio, &cfg, liquidio_dcb_cfg_init);
		if (retval) {
			atomic_set(&lio->oct_dcb.dcb_state, 1);
			return 1;
		}
		else {
			netdev_reset_tc(netdev);
		}
	}

	return 0;
}

static void liquidio_dcbnl_getpermhwaddr(struct net_device *dev, u8 *perm_addr)
{
	cavium_memset(perm_addr, 0xff, dev->addr_len);
	cavium_memcpy(perm_addr, dev->dev_addr, dev->addr_len);
}

static void liquidio_dcbnl_set_ets_config(struct net_device *netdev, int tc,
				   u8 prio_type UNUSED, u8 pgid,
				   u8 bw_pct, u8 up_map)
{
	int i;
	struct lio *lio = GET_LIO(netdev);
	struct dcbx_ets_config *ets_config;
	ets_config = &lio->oct_dcb.dcbx_cee_cmd.config.ets_config;
	
	if (!atomic_read(&lio->oct_dcb.dcb_state)) {
		cavium_pr_info("DCB is not enabled\n");
		return;
	}

	if (lio->oct_dcb.dcbx_info.dcbx_version != DCBX_CEE) {
		cavium_pr_info("DCBX Version Mismatch\n");
		return;
	}

	if ((tc < 0) || (tc >= OCTEON_MAX_TRAFFIC_CLASSES)) {
		cavium_pr_info("unsupported traffic classes\n");
		return;
	}

	if ((pgid < 0) || ((pgid >= OCTEON_MAX_TRAFFIC_CLASSES) &&
	    (pgid != 15))) {
		cavium_pr_info("Invalid pgid\n");
		return;
	}

	for (i = 0; i < OCTEON_MAX_PRIORITIES; i++) {
		if (up_map & (1 << i))
			ets_config->cee.pgid[i] = pgid;
	}

	if (pgid != 15)
		ets_config->cee.pg_bw[pgid] = bw_pct;

	lio->oct_dcb.dcbx_cee_cmd.cmd |= DCBX_CMD_SET_ETS;
}

void liquidio_dcbnl_get_ets_config(struct net_device *netdev, int tc,
				   u8 *prio_type, u8 *pgid,
				   u8 *bw_per, u8 *up_tc_map)
{
	int i, pg15_map = 0;
	struct lio *lio = GET_LIO(netdev);
	struct dcbx_ets_config *ets_config =
		&lio->oct_dcb.dcbx_info.operational.ets_config;

	if (!atomic_read(&lio->oct_dcb.dcb_state)) {
		cavium_pr_info("DCB is not enabled\n");
		return;
	}

	if (lio->oct_dcb.dcbx_info.dcbx_version != DCBX_CEE) {
		cavium_pr_info("DCBX Version Mismatch\n");
		return;
	}

	if (tc < 0 || (tc >= OCTEON_MAX_TRAFFIC_CLASSES)) {
		cavium_pr_info("\n unsupported traffic classes\n");
		return;
	}


	*prio_type = 0;
	*up_tc_map = 0;
	*pgid = 0;
	*bw_per = 0;	

	for (i = 0; i < OCTEON_MAX_PRIORITIES; i++) {
		if (ets_config->cee.pgid[i] == tc)
			*up_tc_map |= (1 << i);
		else if (ets_config->cee.pgid[i] == 15)
			pg15_map |= (1 << i);
	}

	if (*up_tc_map) {
		*pgid = tc;
		*bw_per = ets_config->cee.pg_bw[tc];
	} else if (pg15_map && (tc == ets_config->num_traffic_classes + 1)) {
		*pgid = 15;
		*up_tc_map = pg15_map;
		*bw_per = 0;
	}
}

void liquidio_dcbnl_set_ets_bw(struct net_device *netdev, int pgid, u8 bw_per)
{
	struct lio *lio = GET_LIO(netdev);
	struct oct_nic_dcbx_cmd *dcbx_cmd = &lio->oct_dcb.dcbx_cee_cmd;

	if (!atomic_read(&lio->oct_dcb.dcb_state)) {
		cavium_pr_info("DCB is not enabled\n");
		return;
	}

	if (lio->oct_dcb.dcbx_info.dcbx_version != DCBX_CEE) {
		cavium_pr_info("DCBX Version Mismatch\n");
		return;
	}

	if ((pgid < 0) || (pgid >= OCTEON_MAX_TRAFFIC_CLASSES)) {
		cavium_pr_info("Invalid pgid\n");
		return;
	}

	dcbx_cmd->config.ets_config.cee.pg_bw[pgid] = bw_per;
	dcbx_cmd->cmd |= DCBX_CMD_SET_ETS;
}

void liquidio_dcbnl_get_ets_bw(struct net_device  *netdev, int pgid,u8 *bw_pct)

{
	struct lio *lio = GET_LIO(netdev);
	struct dcbx_ets_config *ets_config =
		&lio->oct_dcb.dcbx_info.operational.ets_config;

	if (!atomic_read(&lio->oct_dcb.dcb_state)) {
		cavium_pr_info("DCB is not enabled\n");
		return;
	}

	if (lio->oct_dcb.dcbx_info.dcbx_version != DCBX_CEE) {
		cavium_pr_info("DCBX Version Mismatch\n");
		return;
	}

	if ((pgid < 0) || (pgid >= OCTEON_MAX_TRAFFIC_CLASSES)) {
		cavium_pr_info("Invalid pgid\n");
		return;
	}

	*bw_pct = ets_config->cee.pg_bw[pgid];
}

/* Enable/disable Priority Pause Frames for the specified
*  Traffic Class   Priority
*/
void liquidio_dcbnl_set_pfc_config(struct net_device *netdev,
				   int prio, u8 setting)
{
	struct lio *lio = GET_LIO(netdev);
	struct oct_nic_dcbx_cmd *dcbx_cmd = &lio->oct_dcb.dcbx_cee_cmd;

	if (!atomic_read(&lio->oct_dcb.dcb_state)) {
		cavium_pr_info("DCB is not enabled\n");
		return;
	}

	if (lio->oct_dcb.dcbx_info.dcbx_version != DCBX_CEE) {
		cavium_pr_info("DCBX Version Mismatch\n");
		return;
	}

	if ((prio < 0) || (prio >= OCTEON_MAX_PRIORITIES)) {
		cavium_pr_info("Invalid priority\n");
		return;
	}

	if (setting) {
		dcbx_cmd->config.pfc_config.pfc_enable |= (1 << prio);
		dcbx_cmd->config.pfc_config.pfc_flags |= DCBX_FLAG_ENABLED;
	}
	else
		dcbx_cmd->config.pfc_config.pfc_enable &= ~(1 << prio);
	
	dcbx_cmd->cmd |= DCBX_CMD_SET_PFC;
}

void liquidio_dcbnl_get_pfc_config(struct net_device *netdev, int prio,
				   u8 *setting)
{
	struct lio *lio = GET_LIO(netdev);
	struct dcbx_pfc_config *pfc_config =
		&lio->oct_dcb.dcbx_info.operational.pfc_config;

	if (!atomic_read(&lio->oct_dcb.dcb_state)) {
		cavium_pr_info("DCB is not enabled\n");
		return;
	}

	if (lio->oct_dcb.dcbx_info.dcbx_version != DCBX_CEE) {
		cavium_pr_info("DCBX Version Mismatch\n");
		return;
	}

	if ((prio < 0) || (prio >= OCTEON_MAX_PRIORITIES)) {
		cavium_pr_info("Invalid priority\n");
		return;
	}

	*setting = (pfc_config->pfc_enable >> prio) & 0x1;
}

u8 liquidio_dcbnl_setall(struct net_device *dev)
{
	struct lio *lio = GET_LIO(dev);

	if (!atomic_read(&lio->oct_dcb.dcb_state)) {
		cavium_pr_info("DCB is not enabled\n");
		return 1;
	}

	if (lio->oct_dcb.dcbx_info.dcbx_version != DCBX_CEE) {
		cavium_pr_info("Remote DCBX Version does not match\n");
		return 1;
	}

	if (!lio->oct_dcb.dcbx_cee_cmd.cmd) {
		cavium_pr_info("Nothing to Apply\n");
		return 1;
	}

	if (liquidio_dcb_set_params(lio)) {
		cavium_pr_info("Set Config Failed\n");
		return 1;
	}

	lio->oct_dcb.dcbx_cee_cmd.cmd = 0;

	return 0;
}

u8 liquidio_dcbnl_getcap(struct net_device *netdev, int capid, u8 *cap)
{
	u8 ret = 0;
	struct lio *lio = GET_LIO(netdev);
	struct oct_nic_dcb_cap *dcb_cap = &lio->oct_dcb.dcb_cap;

	switch (capid) {
	case DCB_CAP_ATTR_PG:
	case DCB_CAP_ATTR_PFC:
	case DCB_CAP_ATTR_UP2TC:
		*cap = true;
		break;
	case DCB_CAP_ATTR_PG_TCS:
		*cap = dcb_cap->maxnum_etscapable_traffic_classes;
		break;
	case DCB_CAP_ATTR_PFC_TCS:
		*cap = dcb_cap->maxnum_pfcenabled_traffic_classes;
		break;
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 0, 0))
	case DCB_CAP_ATTR_DCBX:
		*cap = dcb_cap->dcbx_cap;
		break;
#endif
	case DCB_CAP_ATTR_GSP:
		*cap = false;
		break;
	case DCB_CAP_ATTR_BCN:
		*cap = false;
		break;
	default:
		ret = 1;
		*cap = false;
		break;
	}

	return ret;
}

/* Return the number of Traffic Classes for
 * the indicated Traffic Class ID
 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 1, 4)
int liquidio_dcbnl_getnumtcs(struct net_device *netdev, int tcid, u8 *num)
#else
u8 liquidio_dcbnl_getnumtcs(struct net_device *netdev, int tcid, u8 *num)
#endif /* LINUX_VERSION_CODE >= KERNEL_VERSION(3,1,4) */
{
	struct lio *lio = GET_LIO(netdev);
	struct oct_nic_dcbx_config *dcbx_config =
		&lio->oct_dcb.dcbx_info.operational;
	int rval = 0;

	if (!atomic_read(&lio->oct_dcb.dcb_state)) {
		cavium_pr_info("DCB is not enabled\n");
		return 0;
	}

	if (lio->oct_dcb.dcbx_info.dcbx_version != DCBX_CEE) {
		cavium_pr_info("DCBX Version Mismatch\n");
		return 0;
	}

	switch (tcid) {
	case DCB_NUMTCS_ATTR_PG:
		*num = dcbx_config->ets_config.num_traffic_classes;
		break;
	case DCB_NUMTCS_ATTR_PFC:
		*num = dcbx_config->pfc_config.pfc_capability;
		break;
	default:
		cavium_pr_info("In valid TC-ID\n");
		rval = 0;
		break;
	}

	return rval;
}

/* Set the number of Traffic Classes supported for
 * the indicated Traffic Class ID.
 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 1, 4)
int liquidio_dcbnl_setnumtcs(struct net_device *netdev, int tcid, u8 num)
#else
u8 liquidio_dcbnl_setnumtcs(struct net_device *netdev, int tcid, u8 num)
#endif /* LINUX_VERSION_CODE >= KERNEL_VERSION(3,1,4) */
{
	int rval = 0;
	struct lio *lio = GET_LIO(netdev);
	struct oct_nic_dcbx_config *dcbx_config =
		&lio->oct_dcb.dcbx_cee_cmd.config;

	if (!atomic_read(&lio->oct_dcb.dcb_state)) {
		cavium_pr_info("DCB is not enabled\n");
		return 1;
	}

	if (lio->oct_dcb.dcbx_info.dcbx_version != DCBX_CEE) {
		cavium_pr_info("DCBX Version Mismatch\n");
		return 1;
	}

	switch (tcid) {
	case DCB_NUMTCS_ATTR_PG:
		dcbx_config->ets_config.num_traffic_classes = num;
		lio->oct_dcb.dcbx_cee_cmd.cmd |= DCBX_CMD_SET_ETS;
		break;
	case DCB_NUMTCS_ATTR_PFC:
		dcbx_config->pfc_config.pfc_capability = num;
		lio->oct_dcb.dcbx_cee_cmd.cmd |= DCBX_CMD_SET_PFC;
		break;
	default:
		cavium_pr_info("Invalid TC-ID\n");
		rval = 1;
		break;
	}

	return rval;
}

u8 liquidio_dcbnl_getpfcstate(struct net_device *dev)
{
	struct lio *lio = GET_LIO(dev);
	struct dcbx_pfc_config *pfc_config =
		&lio->oct_dcb.dcbx_info.operational.pfc_config;

	if (!atomic_read(&lio->oct_dcb.dcb_state)) {
		cavium_pr_info("DCB is not enabled\n");
		return 0;
	}

	if (lio->oct_dcb.dcbx_info.dcbx_version != DCBX_CEE) {
		cavium_pr_info("DCBX Version Mismatch\n");
		return 0;
	}

	return ((pfc_config->pfc_flags & DCBX_FLAG_ENABLED) ? 1 : 0);
}

void liquidio_dcbnl_setpfcstate(struct net_device *dev, u8 state)
{
	struct lio *lio = GET_LIO(dev);
	struct dcbx_pfc_config *pfc_config =
		&lio->oct_dcb.dcbx_cee_cmd.config.pfc_config;

	if (!atomic_read(&lio->oct_dcb.dcb_state)) {
		cavium_pr_info("DCB is not enabled\n");
		return;
	}

	if (lio->oct_dcb.dcbx_info.dcbx_version != DCBX_CEE) {
		cavium_pr_info("DCBX Version Mismatch\n");
		return;
	}

	pfc_config->pfc_flags |= DCBX_FLAG_ENABLED;
	lio->oct_dcb.dcbx_cee_cmd.cmd = DCBX_CMD_SET_PFC;
}

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 17, 0))
int liquidio_dcbnl_setapp(struct net_device *dev, u8 selector,
			 u16 protocol_id, u8 priority)
#else
u8 liquidio_dcbnl_setapp(struct net_device *dev, u8 selector,
			 u16 protocol_id, u8 priority)
#endif
{
	int i, j;
	struct lio *lio = GET_LIO(dev);
	struct dcbx_app_prio_config *app_config =
		&lio->oct_dcb.dcbx_cee_cmd.config.app_config;

	if (!atomic_read(&lio->oct_dcb.dcb_state)) {
		cavium_pr_info("DCB is not enabled\n");
		return 1;
	}

	if (lio->oct_dcb.dcbx_info.dcbx_version != DCBX_CEE) {
		cavium_pr_info("DCBX Version Mismatch\n");
		return 1;
	}

	for (i = 0; i < app_config->num_app_prio; i++) {
		if ((app_config->app_prio[i].selector == selector) &&
		    (app_config->app_prio[i].protocol_id == protocol_id)) {
			if (priority)
				app_config->app_prio[i].priority = priority;
			else {
				for (j = i + 1;
				     j < app_config->num_app_prio;
				     j++) {
					app_config->app_prio[j - 1] =
						app_config->app_prio[j];
				}

				app_config->num_app_prio--;
			}
			lio->oct_dcb.dcbx_cee_cmd.cmd |= DCBX_CMD_SET_APP;
			return 0;
		}
	}

	if (app_config->num_app_prio >= OCTEON_MAX_APPLICATION_PRIORITIES) {
		cavium_pr_info("Max Applications reached\n");
		return 1;
	}

	i = app_config->num_app_prio++;

	app_config->app_prio[i].selector = selector;
	app_config->app_prio[i].priority = priority;
	app_config->app_prio[i].protocol_id = protocol_id;

	lio->oct_dcb.dcbx_cee_cmd.cmd |= DCBX_CMD_SET_APP;

	return 0;
}

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 17, 0))
int liquidio_dcbnl_getapp(struct net_device *dev, u8 selector, u16 protocol_id)
#else
u8 liquidio_dcbnl_getapp(struct net_device *dev, u8 selector, u16 protocol_id)
#endif
{
	int i;
	struct lio *lio = GET_LIO(dev);
	struct dcbx_app_prio_config *app_config =
		&lio->oct_dcb.dcbx_info.operational.app_config;

	if (!atomic_read(&lio->oct_dcb.dcb_state)) {
		cavium_pr_info("DCB is not enabled\n");
		return 1;
	}

	if (lio->oct_dcb.dcbx_info.dcbx_version != DCBX_CEE) {
		cavium_pr_info("DCBX Version Mismatch\n");
		return 1;
	}

	for (i = 0; i < app_config->num_app_prio; i++) {
		if ((app_config->app_prio[i].selector == selector) &&
		    (app_config->app_prio[i].protocol_id == protocol_id))
			return app_config->app_prio[i].priority;
	}

	return 0;
}

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 0, 0))

u8 liquidio_dcbnl_getfeatcfg(struct net_device *dev, int fid, u8 *flag)
{
	u8 ret = 0;
	struct lio *lio = GET_LIO(dev);
	struct dcbx_pfc_config *pfc_config =
		&lio->oct_dcb.dcbx_info.operational.pfc_config;
	struct dcbx_ets_config *ets_config =
		&lio->oct_dcb.dcbx_info.operational.ets_config;
	struct dcbx_app_prio_config *app_config =
		&lio->oct_dcb.dcbx_info.operational.app_config;

	if (!atomic_read(&lio->oct_dcb.dcb_state)) {
		cavium_pr_info("DCB is not enabled\n");
		return 1;
	}

	if (lio->oct_dcb.dcbx_info.dcbx_version != DCBX_CEE) {
		cavium_pr_info("DCBX Version Mismatch\n");
		return 1;
	}
	
	*flag = 0;
	switch (fid) {
	case DCB_FEATCFG_ATTR_PG:
		if (ets_config->ets_flags & DCBX_FLAG_ENABLED)
			*flag |= DCB_FEATCFG_ENABLE;

		if (ets_config->ets_flags & DCBX_FLAG_WILLING)
			*flag |= DCB_FEATCFG_WILLING;

		if (ets_config->ets_flags & DCBX_FLAG_ERROR)
			*flag |= DCB_FEATCFG_ERROR;
		break;

	case DCB_FEATCFG_ATTR_PFC:
		if (pfc_config->pfc_flags & DCBX_FLAG_ENABLED)
			*flag |= DCB_FEATCFG_ENABLE;

		if (pfc_config->pfc_flags & DCBX_FLAG_WILLING)
			*flag |= DCB_FEATCFG_WILLING;

		if (pfc_config->pfc_flags & DCBX_FLAG_ERROR)
			*flag |= DCB_FEATCFG_ERROR;
		break;

	case DCB_FEATCFG_ATTR_APP:
		if (app_config->app_flags & DCBX_FLAG_ENABLED)
			*flag |= DCB_FEATCFG_ENABLE;

		if (app_config->app_flags & DCBX_FLAG_WILLING)
			*flag |= DCB_FEATCFG_WILLING;

		if (app_config->app_flags & DCBX_FLAG_ERROR)
			*flag |= DCB_FEATCFG_ERROR;
		break;
	default:
		ret = 1;
		netdev_err(dev, "Invalid Feature ID %d\n", fid);
		break;
	}
	return ret;
}

u8 liquidio_dcbnl_setfeatcfg(struct net_device *dev, int featid, u8 flags)
{
	u8 rval = 0;
	struct lio *lio = GET_LIO(dev);
	struct dcbx_pfc_config *pfc_config =
		&lio->oct_dcb.dcbx_cee_cmd.config.pfc_config;
	struct dcbx_ets_config *ets_config =
		&lio->oct_dcb.dcbx_cee_cmd.config.ets_config;
	struct dcbx_app_prio_config *app_config =
		&lio->oct_dcb.dcbx_cee_cmd.config.app_config;

	if (!atomic_read(&lio->oct_dcb.dcb_state)) {
		cavium_pr_info("DCB is not enabled\n");
		return 1;
	}

	if (lio->oct_dcb.dcbx_info.dcbx_version != DCBX_CEE) {
		cavium_pr_info("DCBX Version Mismatch\n");
		return 1;
	}
	
	switch (featid) {
	case DCB_FEATCFG_ATTR_PG:
		if (flags & DCB_FEATCFG_ENABLE)
			ets_config->ets_flags |= DCBX_FLAG_ENABLED;

		if (flags & DCB_FEATCFG_WILLING)
			ets_config->ets_flags |= DCBX_FLAG_WILLING;

		lio->oct_dcb.dcbx_cee_cmd.cmd |= DCBX_CMD_SET_ETS;
		break;

	case DCB_FEATCFG_ATTR_PFC:
		if (flags & DCB_FEATCFG_ENABLE)
			pfc_config->pfc_flags |= DCBX_FLAG_ENABLED;

		if (flags & DCB_FEATCFG_WILLING)
			pfc_config->pfc_flags |= DCBX_FLAG_WILLING;

		lio->oct_dcb.dcbx_cee_cmd.cmd |= DCBX_CMD_SET_PFC;
		break;

	case DCB_FEATCFG_ATTR_APP:
		if (flags & DCB_FEATCFG_ENABLE)
			app_config->app_flags |= DCBX_FLAG_ENABLED;

		if (flags & DCB_FEATCFG_WILLING)
			app_config->app_flags |= DCBX_FLAG_WILLING;

		lio->oct_dcb.dcbx_cee_cmd.cmd |= DCBX_CMD_SET_APP;
		break;

	default:
		cavium_pr_info("Invalid feature-ID\n");
		rval = 1;
		break;
	}

	return rval;
}

/**
 * liquidio_dcbnl_ieee_getdcbx - retrieve current DCBx capability
 * @netdev: the corresponding netdev
 *
 * Returns DCBx version
 **/
u8 liquidio_dcbnl_getdcbx(struct net_device *dev)
{
	struct lio *lio = GET_LIO(dev);
	struct oct_nic_dcb_cap *dcb_cap = &lio->oct_dcb.dcb_cap;

	return dcb_cap->dcbx_cap;
}

u8 liquidio_dcbnl_setdcbx(struct net_device *dev, u8 mode)
{
	struct lio *lio = GET_LIO(dev);
	union oct_nic_dcb_cfg dcb_cfg;
	struct oct_nic_dcb_cap *dcb_cap = &lio->oct_dcb.dcb_cap;

	if (!mode || (mode == dcb_cap->dcbx_cap))
		return 0;

	dcb_cfg.u64 = 0;

	dcb_cfg.s.cfg_command = DCB_CFG_CMD_DCB_RECONFIG;

	if (mode & DCB_CAP_DCBX_LLD_MANAGED)
		dcb_cfg.s.dcbx_offload = 1;

	if (mode & DCB_CAP_DCBX_VER_IEEE)
		dcb_cfg.s.dcbx_ieee = 1;

	if (mode & DCB_CAP_DCBX_VER_CEE)
		dcb_cfg.s.dcbx_cee = 1;
	
	return liquidio_dcb_cfg(lio, &dcb_cfg, liquidio_dcb_cfg_init);
}

static int liquidio_dcbnl_peer_getappinfo(struct net_device *dev,
					  struct dcb_peer_app_info *app_info,
					  u16 *count) 
{
	struct lio *lio = GET_LIO(dev);
	struct dcbx_app_prio_config *app_config =
		&lio->oct_dcb.dcbx_info.remote.app_config;

	if (!atomic_read(&lio->oct_dcb.dcb_state)) {
		cavium_pr_info("DCB is not enabled\n");
		return 1;
	}

	app_info->willing = (app_config->app_flags & DCBX_FLAG_WILLING) ? 1 : 0;
	app_info->error = (app_config->app_flags & DCBX_FLAG_ERROR) ? 1 : 0;
	*count = app_config->num_app_prio;
	
	return 0;
}

static int liquidio_dcbnl_peer_getapptable(struct net_device *dev,
					   struct dcb_app *app_table)
{
	int i;
	struct lio *lio = GET_LIO(dev);
	struct dcbx_app_prio_config *app_config =
		&lio->oct_dcb.dcbx_info.remote.app_config;

	if (!atomic_read(&lio->oct_dcb.dcb_state)) {
		cavium_pr_info("DCB is not enabled\n");
		return 1;
	}

	for (i = 0; i < app_config->num_app_prio; i++) {
		app_table[i].selector = app_config->app_prio[i].selector;
		app_table[i].priority = app_config->app_prio[i].priority;
		app_table[i].protocol = app_config->app_prio[i].protocol_id;
	}

	return 0;
}

static int liquidio_dcbnl_cee_peer_getpg(struct net_device *dev,
					 struct cee_pg *pg)
{
	struct lio *lio = GET_LIO(dev);
	struct dcbx_ets_config *ets_config =
		&lio->oct_dcb.dcbx_info.remote.ets_config;

	if (!atomic_read(&lio->oct_dcb.dcb_state)) {
		cavium_pr_info("DCB is not enabled\n");
		return 1;
	}

	if (lio->oct_dcb.dcbx_info.dcbx_version != DCBX_CEE) {
		cavium_pr_info("DCBX Version Mismatch\n");
		return 1;
	}
	
	pg->willing = (ets_config->ets_flags & DCBX_FLAG_WILLING) ? 1 : 0;
	pg->error = (ets_config->ets_flags & DCBX_FLAG_ERROR) ? 1 : 0;
	pg->pg_en = (ets_config->ets_flags & DCBX_FLAG_ENABLED) ? 1 : 0;
	pg->tcs_supported = ets_config->num_traffic_classes;
	memcpy(pg->pg_bw, ets_config->cee.pg_bw,
	       min(CEE_DCBX_MAX_PGS, OCTEON_MAX_PRIO_GROUP));
	memcpy(pg->prio_pg, ets_config->cee.pgid,
	       min(CEE_DCBX_MAX_PGS, OCTEON_MAX_TRAFFIC_CLASSES));

	return 0;
}

static int liquidio_dcbnl_cee_peer_getpfc(struct net_device *dev,
			 		  struct cee_pfc *pfc)
{
	struct lio *lio = GET_LIO(dev);
	struct dcbx_pfc_config *pfc_config =
		&lio->oct_dcb.dcbx_info.remote.pfc_config;

	if (!atomic_read(&lio->oct_dcb.dcb_state)) {
		cavium_pr_info("DCB is not enabled\n");
		return 1;
	}

	if (lio->oct_dcb.dcbx_info.dcbx_version != DCBX_CEE) {
		cavium_pr_info("DCBX Version Mismatch\n");
		return 1;
	}

	pfc->willing = (pfc_config->pfc_flags & DCBX_FLAG_WILLING) ? 1 : 0;	
	pfc->error = (pfc_config->pfc_flags & DCBX_FLAG_ERROR) ? 1 : 0;
	pfc->pfc_en = pfc_config->pfc_enable;
	pfc->tcs_supported = pfc_config->pfc_capability;
	
	return 0;
}

#endif

const struct dcbnl_rtnl_ops octeon_dcbnl_ops = {
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 0, 0))
	/* IEEE 802.1Qaz std */
	.ieee_getets = liquidio_dcbnl_ieee_getets,
	.ieee_setets = liquidio_dcbnl_ieee_setets,
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 5, 0))
	.ieee_getmaxrate = NULL,
	.ieee_setmaxrate = NULL,
#endif
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4, 1, 0))
	.ieee_getqcn = NULL,
	.ieee_setqcn = NULL,
	.ieee_getqcnstats = NULL,
#endif
	.ieee_getpfc = liquidio_dcbnl_ieee_getpfc,
	.ieee_setpfc = liquidio_dcbnl_ieee_setpfc,
	.ieee_getapp = liquidio_dcbnl_ieee_getapp,
	.ieee_setapp = liquidio_dcbnl_ieee_setapp,
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 1, 0))
	.ieee_delapp = liquidio_dcbnl_ieee_delapp,
#endif
	.ieee_peer_getets = liquidio_dcbnl_ieee_peer_getets,
	.ieee_peer_getpfc = liquidio_dcbnl_ieee_peer_getpfc,
#endif
	/* CEE std	*/
	.getstate = liquidio_dcbnl_get_state,
	.setstate = liquidio_dcbnl_set_state,
	.getpermhwaddr = liquidio_dcbnl_getpermhwaddr,
	.setpgtccfgtx = liquidio_dcbnl_set_ets_config,
	.setpgbwgcfgtx = liquidio_dcbnl_set_ets_bw,
	.getpgtccfgtx = liquidio_dcbnl_get_ets_config,
	.getpgbwgcfgtx = liquidio_dcbnl_get_ets_bw,
	.setpfccfg = liquidio_dcbnl_set_pfc_config,
	.getpfccfg = liquidio_dcbnl_get_pfc_config,
	.setall = liquidio_dcbnl_setall,
	.getcap = liquidio_dcbnl_getcap,
	.getnumtcs = liquidio_dcbnl_getnumtcs,
	.setnumtcs = liquidio_dcbnl_setnumtcs,
	.getpfcstate = liquidio_dcbnl_getpfcstate,
	.setpfcstate = liquidio_dcbnl_setpfcstate,
	.getbcncfg = NULL,
	.setbcncfg = NULL,
	.getbcnrp = NULL,
	.setbcnrp = NULL,
	.setapp = liquidio_dcbnl_setapp,
	.getapp = liquidio_dcbnl_getapp,
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 0, 0))
	.getfeatcfg = liquidio_dcbnl_getfeatcfg,
	.setfeatcfg = liquidio_dcbnl_setfeatcfg,

	/* DCBX configuration */
	.getdcbx = liquidio_dcbnl_getdcbx,
	.setdcbx = liquidio_dcbnl_setdcbx,

	/* peer apps */
	.peer_getappinfo = liquidio_dcbnl_peer_getappinfo,
	.peer_getapptable = liquidio_dcbnl_peer_getapptable,

	/* CEE peer */
	.cee_peer_getpg = liquidio_dcbnl_cee_peer_getpg,
	.cee_peer_getpfc = liquidio_dcbnl_cee_peer_getpfc
#endif
};

