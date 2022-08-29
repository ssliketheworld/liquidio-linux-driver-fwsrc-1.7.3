/**********************************************************************
* Author: Cavium, Inc.
*
* Contact: support@cavium.com
*          Please include "LiquidIO" in the subject.
*
* Copyright (c) 2003-2015 Cavium, Inc.
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
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
#include <linux/types.h>
#include <linux/list.h>
#include <linux/workqueue.h>
#include <linux/interrupt.h>
#include <linux/if_vlan.h>
#include "cavium_sysdep.h"
#include "octeon_config.h"
#include "liquidio_common_dcb.h"
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
#include "cn23xx_pf_device.h"
#include "lio_dcb_main.h"

static int count = 2;

static u32 dcbx_offload[] = { 0, 0 };
module_param_array(dcbx_offload, uint, &count, 0644);
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 0, 0))
MODULE_PARM_DESC(dcbx_offload, "two comma separated unsigned integers that specify the dcbx state (0 - Host Based, 1 - offload DCBX-CEE, 2 - offload DCBX-IEEE, 3 - offload both DCBX-CEE and DCBX-IEEE) on PF0 (left of the comma) and PF1 (right of the comma)");
#else
MODULE_PARM_DESC(dcbx_offload, "two comma separated unsigned integers that specify the dcbx state (0 - Host Based, 1 - offload DCBX-CEE) on PF0 (left of the comma) and PF1 (right of the comma)");
#endif

static u32 dcb_enable[] = { 0, 0 };
module_param_array(dcb_enable, uint, &count, 0644);
MODULE_PARM_DESC(dcb_enable, "two comma separated unsigned integers that specify the dcb state (0 - disable, 1 - enable) on PF0 (left of the comma) and PF1 (right of the comma)");

static u32 qcn_enable[] = { 0, 0 };
module_param_array(qcn_enable, uint, &count, 0644);
MODULE_PARM_DESC(qcn_enable, "two comma separated unsigned integers that specify qcn state (0 - disable, 1 - enable) on PF0 (left of the comma) and PF1 (right of the comma)");

extern struct dcbnl_rtnl_ops octeon_dcbnl_ops;

/*brief shows dcb configuration while debug flag enabled*/

void show_dcb_config(struct oct_nic_dcbx_config *dcbx_config, int dcbx_version)
{
	int i;
	struct dcbx_pfc_config pfc_config = dcbx_config->pfc_config;
	struct dcbx_ets_config ets_config = dcbx_config->ets_config;
	struct dcbx_app_prio_config app_config = dcbx_config->app_config;

	cavium_pr_info("pfc_flags=%s %s %s\n",
			(pfc_config.pfc_flags & DCBX_FLAG_ENABLED) ?
			"Enabled" : "",
			(pfc_config.pfc_flags & DCBX_FLAG_WILLING) ?
			"Willing" : "",
			(pfc_config.pfc_flags & DCBX_FLAG_ERROR) ?
			"Error" : "");
	cavium_pr_info("PfcCapability = %d PfcEnable=%x\n",
		       pfc_config.pfc_capability, pfc_config.pfc_enable);

	cavium_pr_info("ets_flags=%s %s %s\n",
			(ets_config.ets_flags & DCBX_FLAG_ENABLED) ?
			"Enabled" : "",
			(ets_config.ets_flags & DCBX_FLAG_WILLING) ?
			"Willing" : "",
			(ets_config.ets_flags & DCBX_FLAG_ERROR) ?
			"Error" : "");
	cavium_pr_info("NumTrafficClasses=%d\n",
		       ets_config.num_traffic_classes);
	if (dcbx_version == DCBX_IEEE) {
		cavium_pr_info("prio_tc_table = %d %d %d %d %d %d %d %d\n",
			       ets_config.ieee.priority_assignment_table[0],
			       ets_config.ieee.priority_assignment_table[1],
			       ets_config.ieee.priority_assignment_table[2],
			       ets_config.ieee.priority_assignment_table[3],
			       ets_config.ieee.priority_assignment_table[4],
			       ets_config.ieee.priority_assignment_table[5],
			       ets_config.ieee.priority_assignment_table[6],
			       ets_config.ieee.priority_assignment_table[7]);

		cavium_pr_info("tc_bw_table = %d %d %d %d %d %d %d %d\n",
			       ets_config.ieee.tc_bandwidth_assignment_table[0],
			       ets_config.ieee.tc_bandwidth_assignment_table[1],
			       ets_config.ieee.tc_bandwidth_assignment_table[2],
			       ets_config.ieee.tc_bandwidth_assignment_table[3],
			       ets_config.ieee.tc_bandwidth_assignment_table[4],
			       ets_config.ieee.tc_bandwidth_assignment_table[5],
			       ets_config.ieee.tc_bandwidth_assignment_table[6],
			       ets_config.ieee.tc_bandwidth_assignment_table[7]);

		cavium_pr_info("tsa_table = %d %d %d %d %d %d %d %d\n",
			       ets_config.ieee.tsa_assignment_table[0],
			       ets_config.ieee.tsa_assignment_table[1],
			       ets_config.ieee.tsa_assignment_table[2],
			       ets_config.ieee.tsa_assignment_table[3],
			       ets_config.ieee.tsa_assignment_table[4],
			       ets_config.ieee.tsa_assignment_table[5],
			       ets_config.ieee.tsa_assignment_table[6],
			       ets_config.ieee.tsa_assignment_table[7]);
	}
	else {
		cavium_pr_info("pgid_table = %d %d %d %d %d %d %d %d\n",
				ets_config.cee.pgid[0],
				ets_config.cee.pgid[1],
				ets_config.cee.pgid[2],
				ets_config.cee.pgid[3],
				ets_config.cee.pgid[4],
				ets_config.cee.pgid[5],
				ets_config.cee.pgid[6],
				ets_config.cee.pgid[7]);

		cavium_pr_info("bw_table = %d %d %d %d %d %d %d %d\n",
				ets_config.cee.pg_bw[0],
				ets_config.cee.pg_bw[1],
				ets_config.cee.pg_bw[2],
				ets_config.cee.pg_bw[3],
				ets_config.cee.pg_bw[4],
				ets_config.cee.pg_bw[5],
				ets_config.cee.pg_bw[6],
				ets_config.cee.pg_bw[7]);
	}

	cavium_pr_info("app_flags=%s %s %s\n",
			(app_config.app_flags & DCBX_FLAG_ENABLED) ?
			"Enabled" : "",
			(app_config.app_flags & DCBX_FLAG_WILLING) ?
			"Willing" : "",
			(app_config.app_flags & DCBX_FLAG_ERROR) ?
			"Error" : "");

	cavium_pr_info("App table=");

	for (i = 0; i < app_config.num_app_prio; i++)
		cavium_pr_info("%3d. Selector= %d id = %d prio = %x\n", i,
			       app_config.app_prio[i].selector,
			       app_config.app_prio[i].protocol_id,
			       app_config.app_prio[i].priority);
}

static void liquidio_set_ets_config(struct lio *lio)
{
	u8 *prio_to_tc;
	int prio, tc, qno = 0, tc_pg15 = 0;
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 0, 0))
	struct net_device *netdev = lio->netdev;
#endif
	struct dcbx_ets_config *ets_config =
		&lio->oct_dcb.dcbx_info.operational.ets_config;

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 0, 0))
	netdev_reset_tc(netdev);
	netdev_set_num_tc(netdev, ets_config->num_traffic_classes);
#else
	memset(lio->oct_dcb.prio_to_tc, 0, MAX_PRIORITY);
	memset(lio->oct_dcb.tc_to_txq, 0, MAX_NUM_TC);
	lio->oct_dcb.num_tc = ets_config->num_traffic_classes;
#endif

	if (lio->linfo.num_txpciq >= 8) {
		for (prio = 0; prio < MAX_PRIORITY; prio++) {
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 0, 0))
			netdev_set_prio_tc_map(netdev, prio, prio);
			netdev_set_tc_queue(netdev, prio, 1, prio);
#else
			lio->oct_dcb.prio_to_tc[prio] = prio;
			lio->oct_dcb.tc_to_txq[prio] = prio;
#endif
		}

		return;
	}

	if (lio->oct_dcb.dcbx_info.dcbx_version == DCBX_IEEE)
		prio_to_tc = ets_config->ieee.priority_assignment_table;
	else
		prio_to_tc = ets_config->cee.pgid;

	for (tc = 0; tc < MAX_NUM_TC; tc++) {
		for (prio = 0; prio < MAX_PRIORITY; prio++) {
			if (prio_to_tc[prio] == tc) {
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 0, 0))
				netdev_set_tc_queue(netdev, tc, 1, qno);
#else
				lio->oct_dcb.tc_to_txq[tc] = qno;
#endif
				qno++;
				break;
			}
		}

		if (prio == MAX_PRIORITY)
			tc_pg15 = tc;

		/* The following should never happen */
		if (qno >= lio->linfo.num_txpciq)
			qno = 0;
	}

	for (prio = 0; prio < MAX_PRIORITY; prio++) {
		tc = prio_to_tc[prio];
		if ((lio->oct_dcb.dcbx_info.dcbx_version == DCBX_CEE) &&
		    (tc == 15)) {
			tc = tc_pg15;
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 0, 0))
			netdev_set_tc_queue(netdev, tc, 1, qno);
#else
			lio->oct_dcb.tc_to_txq[tc] = qno;
#endif
		}
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 0, 0))
		netdev_set_prio_tc_map(netdev, prio, tc);
#else
		lio->oct_dcb.prio_to_tc[prio] = tc;
#endif
	}

	return;
}

/*brief:Notify the  DCBX information to network subsystem based on dcbx version
 */
static void liquidio_dcbcap_notify(struct cavium_work *work)
{
	struct cavium_wk *wk = (struct cavium_wk *)work;
	struct lio *lio = (struct lio *)wk->ctxptr;
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 0, 0))
	struct net_device *netdev = lio->netdev;
	struct oct_nic_dcb_cap *dcb_cap = &lio->oct_dcb.dcb_cap;
#endif

	if (!(lio->oct_dcb.dcbx_info.flags &
	    (DCB_FLAG_OPER_PFC | DCB_FLAG_OPER_ETS)))
		return;

	if (lio->oct_dcb.dcbx_info.flags & DCB_FLAG_OPER_ETS) {
		liquidio_set_ets_config(lio);
	}

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 0, 0))
	if (dcb_cap->dcbx_cap &  OCTEON_DCB_CAP_DCBX_LLD_MANAGED) {
		if (lio->oct_dcb.dcbx_info.dcbx_version == DCBX_IEEE) {		
			dcbnl_ieee_notify(netdev, RTM_GETDCB, 
					DCB_CMD_IEEE_GET, 0, lio->ifidx);	
		}
		else if (lio->oct_dcb.dcbx_info.dcbx_version == DCBX_CEE) {
			dcbnl_cee_notify(netdev, RTM_GETDCB, 
					DCB_CMD_CEE_GET, 0, lio->ifidx);	
		}
	}
#endif
}

/* brief: Called when ever dcb configuration information changed from octeon*/
static int liquidio_dcb_info_callback(struct octeon_recv_info *recv_info,
					  void *buf)
{
	int retval = 0;
	struct lio *lio = (struct lio *)buf;
	struct octeon_recv_pkt *recv_pkt = recv_info->recv_pkt;
	struct oct_nic_dcbx_info *dcbx_info = &lio->oct_dcb.dcbx_info;
	struct oct_nic_dcbx_info *new_dcbx_info;

#if (OCTEON_OQ_INFOPTR_MODE)
	if (recv_pkt->buffer_size[0] != sizeof(struct oct_nic_dcbx_info)){
#else
	if (recv_pkt->buffer_size[0] != (sizeof(struct oct_nic_dcbx_info) + 
	    OCT_DROQ_INFO_SIZE)){
#endif
		cavium_pr_err("invalid dcb config info \n");
		retval = -1;
		goto free_buf;
	}

#if (OCTEON_OQ_INFOPTR_MODE)
	new_dcbx_info = (struct oct_nic_dcbx_info *)
		get_rbd(recv_pkt->buffer_ptr[0]);
#else
	new_dcbx_info = (struct oct_nic_dcbx_info *)
		(get_rbd(recv_pkt->buffer_ptr[0]) + OCT_DROQ_INFO_SIZE);
#endif

	if (!atomic_read(&lio->oct_dcb.dcb_state))
		goto free_buf;

	lio->oct_dcb.dcbx_version = dcbx_info->dcbx_version;

	dcbx_info->flags = new_dcbx_info->flags;
	dcbx_info->dcbx_version = new_dcbx_info->dcbx_version;

	if (new_dcbx_info->flags & DCB_FLAG_OPER_PFC) {
		memcpy(&dcbx_info->operational.pfc_config,
		       &new_dcbx_info->operational.pfc_config,
		       sizeof(struct dcbx_pfc_config));
	}

	if (new_dcbx_info->flags & DCB_FLAG_OPER_ETS) {
		memcpy(&dcbx_info->operational.ets_config,
		       &new_dcbx_info->operational.ets_config,
		       sizeof(struct dcbx_ets_config));
	}

	if (new_dcbx_info->flags & DCB_FLAG_OPER_APP) {
		memcpy(&dcbx_info->operational.app_config,
		       &new_dcbx_info->operational.app_config,
		       sizeof(struct dcbx_app_prio_config));
	}

	if (new_dcbx_info->flags & DCB_FLAG_REMOTE_PFC) {
		memcpy(&dcbx_info->remote.pfc_config,
		       &new_dcbx_info->remote.pfc_config,
		       sizeof(struct dcbx_pfc_config));
	}

	if (new_dcbx_info->flags & DCB_FLAG_REMOTE_ETS) {
		memcpy(&dcbx_info->remote.ets_config,
		       &new_dcbx_info->remote.ets_config,
		       sizeof(struct dcbx_ets_config));
	}

	if (new_dcbx_info->flags & DCB_FLAG_REMOTE_APP) {
		memcpy(&dcbx_info->remote.app_config,
		       &new_dcbx_info->remote.app_config,
		       sizeof(struct dcbx_app_prio_config));
	}

	if (new_dcbx_info->flags & DCB_FLAG_REMOTE_SHUTDOWN) {
		memset(&dcbx_info->remote, 0,
		       sizeof(struct oct_nic_dcbx_config));
	}


	cavium_queue_delayed_work(lio->oct_dcb.dcb_info_wq.wq,
			   &lio->oct_dcb.dcb_info_wq.wk.work, 0);	
free_buf:
	cavium_kfree(recv_pkt->buffer_ptr[0]);
	cavium_kfree(recv_info);
	return retval;
}

int liquidio_dcb_cfg(struct lio *lio, union oct_nic_dcb_cfg *cfg,
		     liquidio_dcb_cfg_callback resp_fn)
{
	struct octeon_device *oct_dev = lio->oct_dev;
	struct octeon_soft_command *sc;
	u32 resp_size;
	int ret = 0;
	u32 datasize;

	if (cfg->s.cfg_command == DCB_CFG_CMD_DCB_SET_PARAMS) {
		datasize = sizeof(struct oct_nic_dcbx_cmd);
		resp_size = sizeof(struct liquidio_dcb_resp);
	}
	else {
		datasize = 0;
		resp_size = sizeof(struct liquidio_dcb_cfg_resp);
	}

	sc = (struct octeon_soft_command *)
		octeon_alloc_soft_command(oct_dev, datasize,
					  resp_size, 0);
	if (sc == NULL) {
		lio_dev_err(oct_dev, "Softcommand allocation failed status\n");
		return 1;
	}

	if (cfg->s.cfg_command == DCB_CFG_CMD_DCB_SET_PARAMS) {
		if (lio->oct_dcb.dcbx_info.dcbx_version == DCBX_IEEE)
			memcpy((u8 *)sc->virtdptr,
			       &lio->oct_dcb.dcbx_ieee_cmd,
			       sizeof(struct oct_nic_dcbx_cmd));
		else
			memcpy((u8 *)sc->virtdptr,
			       &lio->oct_dcb.dcbx_cee_cmd,
			       sizeof(struct oct_nic_dcbx_cmd));
	}

	
	sc->iq_no = lio->linfo.txpciq[0].s.q_no;

	octeon_prepare_soft_command(oct_dev, sc, OPCODE_NIC,
				    OPCODE_NIC_DCB_CFG, 0, cfg->u64, 0);

	init_completion(&sc->complete);
	sc->sc_status = OCTEON_REQUEST_PENDING;

	ret = octeon_send_soft_command(oct_dev, sc);
	if (ret == IQ_SEND_FAILED) {
		lio_dev_err(oct_dev,
			    "send dcb cfg failed status: %x\n",
			    ret);
		octeon_free_soft_command(oct_dev, sc);
		return(-EIO);
	}

	/* Sleep on a wait queue till the cond flag indicates that the
	 * response arrived or timed-out.
	 */
	if ((ret = cavium_sleep_cond_timeout(oct_dev, sc, 0)))
		return(ret);

	ret = sc->sc_status;
	if (sc->sc_status != OCTEON_REQUEST_DONE) {
                lio_dev_err(oct_dev,
			    "dcb cfg command failed status: %x\n",
			    ret);
		mdelay(5000);
		goto send_dcb_cfg_fail;
	}

	if (cfg->s.cfg_command != DCB_CFG_CMD_DCB_SET_PARAMS) {
		struct liquidio_dcb_cfg_resp *resp =
			(struct liquidio_dcb_cfg_resp *)sc->virtrptr;

		if (resp_fn)
			resp_fn(lio, resp);
	}

send_dcb_cfg_fail:
	cavium_set_bit(CALLER_DONE_BIT, &sc->done);

	return ret;
}

void liquidio_dcb_cfg_init(struct lio *lio, struct liquidio_dcb_cfg_resp *resp)
{
	memcpy(&lio->oct_dcb.dcb_cap,
	       &resp->cfg_info.dcb_cap,
	       sizeof(struct oct_nic_dcb_cap));

	lio->oct_dcb.dcbx_version = resp->cfg_info.dcbx_version;

	memcpy(&lio->oct_dcb.dcbx_ieee_cmd.config,
	       &resp->cfg_info.ieee_config,
	       sizeof(struct oct_nic_dcbx_config));
	lio->oct_dcb.dcbx_ieee_cmd.cmd = 0;
	lio->oct_dcb.dcbx_ieee_cmd.dcbx_version = DCBX_IEEE;

	memcpy(&lio->oct_dcb.dcbx_cee_cmd.config,
	       &resp->cfg_info.cee_config,
	       sizeof(struct oct_nic_dcbx_config));
	lio->oct_dcb.dcbx_cee_cmd.cmd = 0;
	lio->oct_dcb.dcbx_cee_cmd.dcbx_version = DCBX_CEE;

	return;
}

/*brief: Initialize the DCB functionality per port basis*/
int liquidio_dcb_init(struct octeon_device *oct_dev,int ifidx)
{
	struct net_device *netdev = oct_dev->props[ifidx].netdev;
	struct lio  *lio = GET_LIO(netdev);
	union oct_nic_dcb_cfg dcb_cfg;
	struct cavium_wq *db_wq;
	int retval;

	if (!dcb_enable[oct_dev->pci_dev->devfn] ||
	    (oct_dev->pci_dev->device != OCTEON_CN23XX_PF_VID)) {
		if (qcn_enable[oct_dev->pci_dev->devfn])
			cavium_pr_info("dcb is not enabled. qcn_enable is ignored.\n");
		return 0;
	}

	dcb_cfg.u64 = 0;

	dcb_cfg.s.cfg_command = DCB_CFG_CMD_DCB_CONFIG;

	dcb_cfg.s.qcn_enable = qcn_enable[oct_dev->pci_dev->devfn];

	switch (dcbx_offload[oct_dev->pci_dev->devfn]) {
		case 0:
			dcb_cfg.s.dcbx_offload = 0;
			dcb_cfg.s.dcbx_cee = 1;
			dcb_cfg.s.dcbx_ieee = 1;
			break;
		case 1:
			dcb_cfg.s.dcbx_offload = 1;
			dcb_cfg.s.dcbx_cee = 1;
			break;
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 0, 0))
		case 2:
			dcb_cfg.s.dcbx_offload = 1;
			dcb_cfg.s.dcbx_ieee = 1;
			break;
		case 3:
			dcb_cfg.s.dcbx_offload = 1;
			dcb_cfg.s.dcbx_cee = 1;
			dcb_cfg.s.dcbx_ieee = 1;
			break;
#endif
		default:
			lio_dev_err(oct_dev, "Invalid value for dcbx_offload\n");
			return 1;
	}

	retval = liquidio_dcb_cfg(lio, &dcb_cfg, liquidio_dcb_cfg_init);
	if (retval) {
		return retval;
        }

	atomic_set(&lio->oct_dcb.dcb_state, 1);
	atomic_set(&lio->oct_dcb.qcn_state,
		   qcn_enable[oct_dev->pci_dev->devfn]);

	lio->oct_dcb.dcb_info_wq.wq =
		cavium_alloc_workqueue("dcb_info_wq", WQ_MEM_RECLAIM, 0);
	if (!lio->oct_dcb.dcb_info_wq.wq) {
		lio_dev_err(oct_dev, "DCB Work Queue allocation Failed\n");
		return -ENOMEM;
	}

	db_wq = &lio->oct_dcb.dcb_info_wq;

	CAVIUM_INIT_DELAYED_WORK(&db_wq->wk.work, liquidio_dcbcap_notify);
	db_wq->wk.ctxptr = lio;
	db_wq->wk.ctxul = 0;

	octeon_register_dispatch_fn(oct_dev, OPCODE_NIC,
				    OPCODE_NIC_DCB_INFO,
				    liquidio_dcb_info_callback, lio);

	/* Assign dcbnl operations  */
	netdev->dcbnl_ops = &octeon_dcbnl_ops;

	lio->oct_dcb.dcbx_info.flags = DCB_FLAG_OPER_ALL;
	lio->oct_dcb.dcbx_info.dcbx_version = lio->oct_dcb.dcbx_version;

	if (lio->oct_dcb.dcbx_version == DCBX_IEEE) {
		memcpy(&lio->oct_dcb.dcbx_info.operational,
		       &lio->oct_dcb.dcbx_ieee_cmd.config,
		       sizeof(struct oct_nic_dcbx_config));

	} else if (lio->oct_dcb.dcbx_version == DCBX_CEE) {
		memcpy(&lio->oct_dcb.dcbx_info.operational,
		       &lio->oct_dcb.dcbx_cee_cmd.config,
		       sizeof(struct oct_nic_dcbx_config));
	}

	/*notify  dcb capabilities to network subsystem*/
	liquidio_dcbcap_notify((struct cavium_work *)&db_wq->wk);

	return 0;
}

int liquidio_dcb_select_q(struct net_device *netdev, struct sk_buff *skb)
{
	u32 qindex = 0;
	struct lio *lio;

	lio = GET_LIO(netdev);

	if (atomic_read(&lio->oct_dcb.dcb_state)) {
		if (skb->vlan_tci & VLAN_TAG_PRESENT) {
			qindex = ((skb->vlan_tci & VLAN_PRIO_MASK) >>
				VLAN_PRIO_SHIFT);
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 0, 0))
			qindex = netdev_get_prio_tc_map(netdev, qindex);	
			qindex = netdev->tc_to_txq[qindex].offset;
#else
			qindex = lio->oct_dcb.prio_to_tc[qindex];
			qindex = lio->oct_dcb.tc_to_txq[qindex];
#endif
		}

		return qindex;
	}

	return -1;
}
