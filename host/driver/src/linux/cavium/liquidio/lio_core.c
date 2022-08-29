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
 * NONINFRINGEMENT.  See the GNU General Public License for more details.
 ***********************************************************************/
#include <linux/pci.h>
#include <linux/if_vlan.h>
#include "cavium_sysdep.h"
#include "liquidio_common.h"
#include "octeon_droq.h"
#include "octeon_iq.h"
#include "response_manager.h"
#include "octeon_device.h"
#include "octeon_nic.h"
#include "octeon_main.h"
#include "octeon_network.h"

/* OOM task polling interval */
#define LIO_OOM_POLL_INTERVAL_MS 250

#define OCTNIC_MAX_SG  MAX_SKB_FRAGS

/**
 * \brief Delete gather lists
 * @param lio per-network private data
 */
void lio_delete_glists(struct octeon_device *oct, struct lio *lio)
{
	struct octnic_gather *g;
	int i;

	kfree(lio->glist_lock);
	lio->glist_lock = NULL;

	if (!lio->glist)
		return;

	for (i = 0; i < oct->num_iqs; i++) {
		do {
			g = (struct octnic_gather *)
				lio_list_delete_head(&lio->glist[i]);
			kfree(g);
		} while (g);

		if (lio->glists_virt_base && lio->glists_virt_base[i] &&
		    lio->glists_dma_base && lio->glists_dma_base[i]) {
			lio_dma_free(oct,
				     lio->glist_entry_size * lio->tx_qsize,
				     lio->glists_virt_base[i],
				     lio->glists_dma_base[i]);
		}
	}

	kfree(lio->glists_virt_base);
	lio->glists_virt_base = NULL;

	kfree(lio->glists_dma_base);
	lio->glists_dma_base = NULL;

	kfree(lio->glist);
	lio->glist = NULL;
}

/**
 * \brief Setup gather lists
 * @param lio per-network private data
 */
int lio_setup_glists(struct octeon_device *oct, struct lio *lio, int num_iqs)
{
	struct octnic_gather *g;
	int i, j;

	lio->glist_lock = kcalloc(num_iqs, sizeof(*lio->glist_lock),
				  __CAVIUM_MEM_GENERAL);
	if (!lio->glist_lock)
		return 1;

	lio->glist = kcalloc(num_iqs, sizeof(*lio->glist),
			     __CAVIUM_MEM_GENERAL);
	if (!lio->glist) {
		kfree((void *)lio->glist_lock);
		lio->glist_lock = NULL;
		return 1;
	}

	lio->glist_entry_size =
		ROUNDUP8((ROUNDUP4(OCTNIC_MAX_SG) >> 2) * OCT_SG_ENTRY_SIZE);
	/* allocate memory to store virtual and dma base address of
	 * per glist consistent memory
	 */
	lio->glists_virt_base = kcalloc(num_iqs, sizeof(void *),
					__CAVIUM_MEM_GENERAL);
	lio->glists_dma_base = kcalloc(num_iqs, sizeof(cavium_dma_addr_t),
				       __CAVIUM_MEM_GENERAL);
	if (!lio->glists_virt_base || !lio->glists_dma_base) {
		lio_delete_glists(oct, lio);
		return 1;
	}

	for (i = 0; i < num_iqs; i++) {
		int numa_node = cavium_dev_to_node(&oct->pci_dev->dev);

		cavium_spin_lock_init(&lio->glist_lock[i]);

		CAVIUM_INIT_LIST_HEAD(&lio->glist[i]);

		lio->glists_virt_base[i] =
			lio_dma_alloc(oct, "glist", i,
				      lio->glist_entry_size * lio->tx_qsize,
				      (cavium_dma_addr_t *)
				      &lio->glists_dma_base[i]);
		if (!lio->glists_virt_base[i]) {
			lio_delete_glists(oct, lio);
			return 1;
		}

		for (j = 0; j < lio->tx_qsize; j++) {
			g = kzalloc_node(sizeof(*g), __CAVIUM_MEM_GENERAL,
					 numa_node);
			if (!g)
				g = kzalloc(sizeof(*g), __CAVIUM_MEM_GENERAL);
			if (!g)
				break;

			g->sg = (struct octeon_sg_entry *)
				((u64)lio->glists_virt_base[i] +
				 (j * lio->glist_entry_size));
			g->sg_dma_ptr = (u64)lio->glists_dma_base[i] +
				(j * lio->glist_entry_size);
			CAVIUM_LIST_ADD_TAIL(&g->list, &lio->glist[i]);
		}

		if (j != lio->tx_qsize) {
			lio_delete_glists(oct, lio);
			return 1;
		}
	}

	return 0;
}

int liquidio_set_feature(struct net_device *netdev, int cmd, u16 param1)
{
	struct lio *lio = GET_LIO(netdev);
	struct octeon_device *oct = lio->oct_dev;
	struct octnic_ctrl_pkt nctrl;
	int ret = 0;

	memset(&nctrl, 0, sizeof(struct octnic_ctrl_pkt));

	nctrl.ncmd.u64 = 0;
	nctrl.ncmd.s.cmd = cmd;
	nctrl.ncmd.s.param1 = param1;
	nctrl.iq_no = lio->linfo.txpciq[0].s.q_no;
	nctrl.netpndev = (u64)netdev;
	nctrl.cb_fn = liquidio_link_ctrl_cmd_completion;

	ret = octnet_send_nic_ctrl_pkt(lio->oct_dev, &nctrl);
	if (ret < 0) {
		lio_dev_err(oct, "Feature change failed in core (ret: 0x%x)\n",
			    ret);
	}
	return ret;
}

void octeon_report_tx_completion_to_bql(void *txq, unsigned int pkts_compl,
					unsigned int bytes_compl)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 3, 0)
	struct netdev_queue *netdev_queue = txq;

	netdev_tx_completed_queue(netdev_queue, pkts_compl, bytes_compl);
#endif
}

void octeon_update_tx_completion_counters(void *buf, int reqtype,
					  unsigned int *pkts_compl,
					  unsigned int *bytes_compl)
{
	struct octnet_buf_free_info *finfo;
	struct sk_buff *skb = NULL;
	struct octeon_soft_command *sc;

	switch (reqtype) {
	case REQTYPE_NORESP_NET:
	case REQTYPE_NORESP_NET_SG:
		finfo = buf;
		skb = finfo->skb;
		break;

	case REQTYPE_RESP_NET_SG:
	case REQTYPE_RESP_NET:
		sc = buf;
		skb = sc->callback_arg;
		break;

	default:
		return;
	}

	(*pkts_compl)++;
	*bytes_compl += skb->len;
}

int octeon_report_sent_bytes_to_bql(void *buf, int reqtype)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 3, 0)
	struct octnet_buf_free_info *finfo;
	struct sk_buff *skb;
	struct octeon_soft_command *sc;
	struct netdev_queue *txq;

	switch (reqtype) {
	case REQTYPE_NORESP_NET:
	case REQTYPE_NORESP_NET_SG:
		finfo = buf;
		skb = finfo->skb;
		break;

	case REQTYPE_RESP_NET_SG:
	case REQTYPE_RESP_NET:
		sc = buf;
		skb = sc->callback_arg;
		break;

	default:
		return 0;
	}

	txq = netdev_get_tx_queue(skb->dev, skb_get_queue_mapping(skb));
	netdev_tx_sent_queue(txq, skb->len);

	return netif_xmit_stopped(txq);
#else
	return 0;
#endif
}

void liquidio_link_ctrl_cmd_completion(void *nctrl_ptr)
{
	struct octnic_ctrl_pkt *nctrl = (struct octnic_ctrl_pkt *)nctrl_ptr;
	struct net_device *netdev = (struct net_device *)nctrl->netpndev;
	struct lio *lio;
	struct octeon_device *oct;
	u8 *mac;

	if (netdev->reg_state != NETREG_REGISTERED)
		return;

	lio = GET_LIO(netdev);

	if (!lio->oct_dev)
		return;
	oct = lio->oct_dev;

	switch (nctrl->ncmd.s.cmd) {
	case OCTNET_CMD_CHANGE_DEVFLAGS:
	case OCTNET_CMD_SET_MULTI_LIST:
	case OCTNET_CMD_SET_UC_LIST:
		break;

	case OCTNET_CMD_CHANGE_MACADDR:
		if (nctrl->sc_status)
			break;

		mac = ((u8 *)&nctrl->udd[0]) + 2;
		if (nctrl->ncmd.s.param1) {
			/* vfidx is 0 based, but vf_num (param1) is 1 based */
			int vfidx = nctrl->ncmd.s.param1 - 1;
			bool mac_is_admin_assigned = nctrl->ncmd.s.param2;

			if (mac_is_admin_assigned)
				lio_info(lio, probe,
					 "MAC Address %pM is configured for VF %d\n",
					 mac, vfidx);
		} else {
			lio_info(lio, probe, " MACAddr changed to %pM\n",
				 mac);
		}
		break;

	case OCTNET_CMD_GPIO_ACCESS:
		lio_info(lio, probe, "LED Flashing visual identification\n");

		break;

	case OCTNET_CMD_ID_ACTIVE:
		lio_info(lio, probe, "LED Flashing visual identification\n");

		break;

	case OCTNET_CMD_LRO_ENABLE:
		lio_dev_info(oct, "%s LRO Enabled\n", netdev->name);
		break;

	case OCTNET_CMD_LRO_DISABLE:
		lio_dev_info(oct, "%s LRO Disabled\n",
			     netdev->name);
		break;

	case OCTNET_CMD_VERBOSE_ENABLE:
		lio_dev_info(oct, "%s Firmware debug enabled\n",
			     netdev->name);
		break;

	case OCTNET_CMD_VERBOSE_DISABLE:
		lio_dev_info(oct, "%s Firmware debug disabled\n",
			     netdev->name);
		break;

	case OCTNET_CMD_VLAN_FILTER_CTL:
		if (nctrl->ncmd.s.param1)
			lio_dev_info(oct, "%s VLAN filter enabled\n",
				     netdev->name);
		else
			lio_dev_info(oct, "%s VLAN filter disabled\n",
				     netdev->name);
		break;

	case OCTNET_CMD_ADD_VLAN_FILTER:
		lio_dev_info(oct, "%s VLAN filter %d added\n",
			     netdev->name, nctrl->ncmd.s.param1);
		break;

	case OCTNET_CMD_DEL_VLAN_FILTER:
		lio_dev_info(oct, "%s VLAN filter %d removed\n",
			     netdev->name, nctrl->ncmd.s.param1);
		break;

	case OCTNET_CMD_SET_SETTINGS:
		lio_dev_info(oct, "%s settings changed\n",
			     netdev->name);

		break;

#if  (LINUX_VERSION_CODE >= KERNEL_VERSION(3,12,0)) || (RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(7, 0))
	/* Case to handle "OCTNET_CMD_TNL_RX_CSUM_CTL"
	 * Command passed by NIC driver
	 */
	case OCTNET_CMD_TNL_RX_CSUM_CTL:
		if (nctrl->ncmd.s.param1 == OCTNET_CMD_RXCSUM_ENABLE) {
			lio_info(lio, probe,
				 "RX Checksum Offload Enabled\n");
		} else if (nctrl->ncmd.s.param1 ==
			   OCTNET_CMD_RXCSUM_DISABLE) {
			lio_info(lio, probe,
				 "RX Checksum Offload Disabled\n");
		}
		break;

		/* Case to handle "OCTNET_CMD_TNL_TX_CSUM_CTL"
		 * Command passed by NIC driver
		 */
	case OCTNET_CMD_TNL_TX_CSUM_CTL:
		if (nctrl->ncmd.s.param1 == OCTNET_CMD_TXCSUM_ENABLE) {
			lio_info(lio, probe,
				 "TX Checksum Offload Enabled\n");
		} else if (nctrl->ncmd.s.param1 ==
			   OCTNET_CMD_TXCSUM_DISABLE) {
			lio_info(lio, probe,
				 "TX Checksum Offload Disabled\n");
		}
		break;

		/* Case to handle "OCTNET_CMD_VXLAN_PORT_CONFIG"
		 * Command passed by NIC driver
		 */
	case OCTNET_CMD_VXLAN_PORT_CONFIG:
		if (nctrl->ncmd.s.more == OCTNET_CMD_VXLAN_PORT_ADD) {
			lio_info(lio, probe,
				 "VxLAN Destination UDP PORT:%d ADDED\n",
				 nctrl->ncmd.s.param1);
		} else if (nctrl->ncmd.s.more ==
			   OCTNET_CMD_VXLAN_PORT_DEL) {
			lio_info(lio, probe,
				 "VxLAN Destination UDP PORT:%d DELETED\n",
				 nctrl->ncmd.s.param1);
		}
		break;
#endif

	case OCTNET_CMD_SET_FLOW_CTL:
		lio_info(lio, probe, "Set RX/TX flow control parameters\n");
		break;

	case OCTNET_CMD_PKT_STEERING_CTL:
		if (nctrl->ncmd.s.param1 == OCTNET_CMD_PKT_STEERING_ENABLE) {
			lio_info(lio, probe, "%s Packet Steering Enabled\n",
				 netdev->name);
			lio_set_priv_flag(lio->oct_dev,
					  OCT_PRIV_FLAG_PKT_STEERING,
					  true);
		} else if (nctrl->ncmd.s.param1 ==
			   OCTNET_CMD_PKT_STEERING_DISABLE) {
			lio_info(lio, probe, "%s Packet Steering Disabled\n",
				 netdev->name);
			lio_set_priv_flag(lio->oct_dev,
					  OCT_PRIV_FLAG_PKT_STEERING,
					  false);
		}
		break;

	case OCTNET_CMD_QUEUE_COUNT_CTL:
		lio_info(lio, probe, "Queue count updated to %d\n",
			 nctrl->ncmd.s.param1);
		break;

	default:
		lio_dev_err(oct, "%s Unknown cmd %d\n", __CVM_FUNCTION__,
			    nctrl->ncmd.s.cmd);
	}
}

void octeon_pf_changed_vf_macaddr(struct octeon_device *oct, u8 *mac)
{
	bool macaddr_changed = false;
	struct net_device *netdev;
	struct lio *lio;

	rtnl_lock();

	netdev = oct->props[0].netdev;
	lio = GET_LIO(netdev);

	lio->linfo.macaddr_is_admin_asgnd = true;

	if (!ether_addr_equal(netdev->dev_addr, mac)) {
		macaddr_changed = true;
#if  LINUX_VERSION_CODE < KERNEL_VERSION(3, 14, 0)
		memcpy(netdev->dev_addr, mac, ETH_ALEN);
		memcpy(((u8 *)&lio->linfo.hw_addr) + 2, mac, ETH_ALEN);
#else
		ether_addr_copy(netdev->dev_addr, mac);
		ether_addr_copy(((u8 *)&lio->linfo.hw_addr) + 2, mac);
#endif
		call_netdevice_notifiers(NETDEV_CHANGEADDR, netdev);
	}

	rtnl_unlock();

	if (macaddr_changed)
		lio_dev_info(oct,
			     "PF changed VF's MAC address to %pM\n", mac);

	/* no need to notify the firmware of the macaddr change because
	 * the PF did that already
	 */
}

void octeon_pf_set_or_cleared_vf_vlan(struct octeon_device *oct, bool v_was_set)
{
	struct net_device *netdev;
	struct lio *lio;

	netdev = oct->props[0].netdev;
	lio = GET_LIO(netdev);

	lio->linfo.vlan_is_admin_assigned = v_was_set;
}

void octeon_schedule_rxq_oom_work(struct octeon_device *oct,
				  struct octeon_droq *droq)
{
	struct net_device *netdev = oct->props[0].netdev;
	struct lio *lio = GET_LIO(netdev);
	struct cavium_wq *wq = &lio->rxq_status_wq[droq->q_no];

	queue_delayed_work(wq->wq, &wq->wk.work,
			   msecs_to_jiffies(LIO_OOM_POLL_INTERVAL_MS));
}

static void octnet_poll_check_rxq_oom_status(struct cavium_work *work)
{
	struct cavium_wk *wk = (struct cavium_wk *)work;
	struct lio *lio = (struct lio *)wk->ctxptr;
	struct octeon_device *oct = lio->oct_dev;
	int q_no = wk->ctxul;
	struct octeon_droq *droq = oct->droq[q_no];

	if (!ifstate_check(lio, LIO_IFSTATE_RUNNING) || !droq)
		return;

	if (octeon_retry_droq_refill(droq))
		octeon_schedule_rxq_oom_work(oct, droq);
}

int setup_rx_oom_poll_fn(struct net_device *netdev)
{
	struct lio *lio = GET_LIO(netdev);
	struct octeon_device *oct = lio->oct_dev;
	struct cavium_wq *wq;
	int q, q_no;

	for (q = 0; q < oct->num_oqs; q++) {
		q_no = lio->linfo.rxpciq[q].s.q_no;
		wq = &lio->rxq_status_wq[q_no];
		wq->wq = cavium_alloc_workqueue("rxq-oom-status",
						WQ_MEM_RECLAIM, 0);
		if (!wq->wq) {
			lio_dev_err(oct, "unable to create cavium rxq oom status wq\n");
			return -ENOMEM;
		}

		CAVIUM_INIT_DELAYED_WORK(&wq->wk.work,
					 octnet_poll_check_rxq_oom_status);
		wq->wk.ctxptr = lio;
		wq->wk.ctxul = q_no;
	}

	return 0;
}

void cleanup_rx_oom_poll_fn(struct net_device *netdev)
{
	struct lio *lio = GET_LIO(netdev);
	struct octeon_device *oct = lio->oct_dev;
	struct cavium_wq *wq;
	int q_no;

	for (q_no = 0; q_no < oct->num_oqs; q_no++) {
		wq = &lio->rxq_status_wq[q_no];
		if (wq->wq) {
			cavium_cancel_delayed_work_sync(&wq->wk.work);
			cavium_flush_workqueue(wq->wq);
			cavium_destroy_workqueue(wq->wq);
			wq->wq = NULL;
		}
	}
}

/* Runs in interrupt context. */
static void lio_update_txq_status(struct octeon_device *oct, int iq_num)
{
	struct octeon_instr_queue *iq = oct->instr_queue[iq_num];
	struct net_device *netdev;
	struct lio *lio;

	netdev = oct->props[iq->ifidx].netdev;

	/* This is needed because the first IQ does not have
	 * a netdev associated with it.
	 */
	if (!netdev)
		return;

	lio = GET_LIO(netdev);
	if (__netif_subqueue_stopped(netdev, iq->q_index) &&
	    lio->linfo.link.s.link_up &&
	    (!octnet_iq_is_full(oct, iq_num))) {
		netif_wake_subqueue(netdev, iq->q_index);
		INCR_INSTRQUEUE_PKT_COUNT(lio->oct_dev, iq_num, tx_restart, 1);
	}
}

/**
 * \brief Setup output queue
 * @param oct octeon device
 * @param q_no which queue
 * @param num_descs how many descriptors
 * @param desc_size size of each descriptor
 * @param app_ctx application context
 */
static int octeon_setup_droq(struct octeon_device *oct, int q_no, int num_descs,
			     int desc_size, void *app_ctx)
{
	int ret_val;

	lio_dev_dbg(oct, "Creating Droq: %d\n", q_no);
	/* droq creation and local register settings. */
	ret_val = octeon_create_droq(oct, q_no, num_descs, desc_size, app_ctx);
	if (ret_val < 0)
		return ret_val;

	if (ret_val == 1) {
		lio_dev_dbg(oct, "Using default droq %d\n", q_no);
		return 0;
	}

	/* Enable the droq queues */
	octeon_set_droq_pkt_op(oct, q_no, 1);

	/* Send Credit for Octeon Output queues. Credits are always
	 * sent after the output queue is enabled.
	 */
	writel(oct->droq[q_no]->max_count, oct->droq[q_no]->pkts_credit_reg);

	return ret_val;
}


/** Routine to push packets arriving on Octeon interface upto network layer.
 * @param oct_id   - octeon device id.
 * @param skbuff   - skbuff struct to be passed to network layer.
 * @param len      - size of total data received.
 * @param rh       - Control header associated with the packet
 * @param param    - additional control data with the packet
 * @param arg      - farg registered in droq_ops
 */
static void
liquidio_push_packet(u32 octeon_id UNUSED,
		     void *skbuff,
		     u32 len,
		     union octeon_rh *rh,
		     void *param,
		     void *arg)
{
	struct net_device *netdev = (struct net_device *)arg;
	struct octeon_droq *droq =
	    container_of(param, struct octeon_droq, napi);
	struct sk_buff *skb = (struct sk_buff *)skbuff;
	struct skb_shared_hwtstamps *shhwtstamps;
	struct napi_struct *napi = param;
	u16 vtag = 0;
	u32 r_dh_off;
	u64 ns;

	if (netdev) {
		struct lio *lio = GET_LIO(netdev);
		struct octeon_device *oct = lio->oct_dev;

		/* Do not proceed if the interface is not in RUNNING state. */
		if (!ifstate_check(lio, LIO_IFSTATE_RUNNING)) {
			recv_buffer_free(skb);
			droq->stats.rx_dropped++;
			return;
		}

		skb->dev = netdev;

		skb_record_rx_queue(skb, droq->q_no);
#ifndef CAVIUM_BYTE_ALLOC_RXBUFS
		if (likely(len > MIN_SKB_SIZE)) {
			struct octeon_skb_page_info *pg_info;
			unsigned char *va;

			pg_info = ((struct octeon_skb_page_info *)(skb->cb));
			if (pg_info->page) {
				/* For Paged allocation use the frags */
				va = page_address(pg_info->page) +
					pg_info->page_offset;
				memcpy(skb->data, va, MIN_SKB_SIZE);
				skb_put(skb, MIN_SKB_SIZE);
#if (RHEL_RELEASE_CODE > RHEL_RELEASE_VERSION(6, 2)) || (LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 32))
				skb_add_rx_frag(skb, skb_shinfo(skb)->nr_frags,
						pg_info->page,
						pg_info->page_offset +
						MIN_SKB_SIZE,
						len - MIN_SKB_SIZE,
						LIO_RXBUFFER_SZ);
#else
				skb_add_rx_frag(skb, skb_shinfo(skb)->nr_frags,
						pg_info->page,
						pg_info->page_offset +
						MIN_SKB_SIZE,
						len - MIN_SKB_SIZE);

#endif
			}
		} else {
			struct octeon_skb_page_info *pg_info =
				((struct octeon_skb_page_info *)(skb->cb));
			skb_copy_to_linear_data(skb, page_address(pg_info->page)
						+ pg_info->page_offset, len);
			skb_put(skb, len);
			put_page(pg_info->page);
		}
#endif

		r_dh_off = (rh->r_dh.len - 1) * BYTES_PER_DHLEN_UNIT;

#ifdef LINUX_IPSEC
		/*IPsec XFRM Mark data */
		if (rh->r_dh.has_ipsec_xfrm_mark) {
			__be32 *ipsec_mark_be = NULL;
			ipsec_mark_be = (__be32 *)(skb->data + r_dh_off);
			skb->mark     = be32_to_cpu(*ipsec_mark_be);
			r_dh_off     -= BYTES_PER_DHLEN_UNIT;
			lio_dev_dbg(oct, "Rx xfrm skb mark=%d\n", skb->mark); 
		}
#endif
		if (oct->ptp_enable) {
			if (rh->r_dh.has_hwtstamp) {
				/* timestamp is included from the hardware at
				 * the beginning of the packet.
				 */
				if (ifstate_check
					(lio,
					 LIO_IFSTATE_RX_TIMESTAMP_ENABLED)) {
					/* Nanoseconds are in the first 64-bits
					 * of the packet.
					 */
					memcpy(&ns, (skb->data + r_dh_off),
					       sizeof(ns));
					r_dh_off -= BYTES_PER_DHLEN_UNIT;
					shhwtstamps = skb_hwtstamps(skb);
					shhwtstamps->hwtstamp =
						ns_to_ktime(ns +
							    lio->ptp_adjust);
				}
			}
		}


		if (rh->r_dh.has_hash) {
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 0, 0))
			__be32 *hash_be = (__be32 *)(skb->data + r_dh_off);
			u32 hash = be32_to_cpu(*hash_be);

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 14, 0)) || (RHEL_RELEASE_CODE >= 1794)
			skb_set_hash(skb, hash, PKT_HASH_TYPE_L4);
#else
			skb->rxhash = hash;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 2, 0)
			skb->l4_rxhash = 1;
#endif
#endif
#endif
			r_dh_off -= BYTES_PER_DHLEN_UNIT;
		}

		skb_pull(skb, rh->r_dh.len * BYTES_PER_DHLEN_UNIT);
		skb->protocol = eth_type_trans(skb, skb->dev);

		if ((netdev->features & NETIF_F_RXCSUM) &&
		    (((rh->r_dh.encap_on) &&
		      (rh->r_dh.csum_verified & CNNIC_TUN_CSUM_VERIFIED)) ||
		     (!(rh->r_dh.encap_on) &&
		      (rh->r_dh.csum_verified & CNNIC_CSUM_VERIFIED))))
			/* checksum has already been verified */
			skb->ip_summed = CHECKSUM_UNNECESSARY;
		else
			skb->ip_summed = CHECKSUM_NONE;

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3,12,0)) || (RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(7, 0))
		/* Setting Encapsulation field on basis of status received
		 * from the firmware
		 */
		if (rh->r_dh.encap_on) {
			skb->encapsulation = 1;
#if  ((LINUX_VERSION_CODE >= KERNEL_VERSION(3,18,0)) || (RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(7, 2)))
			skb->csum_level = 1;
#endif
			droq->stats.rx_vxlan++;
		}
#endif

		/* inbound VLAN tag */
#if  LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
		if ((netdev->features & NETIF_F_HW_VLAN_CTAG_RX) &&
#else
		if ((netdev->features & NETIF_F_HW_VLAN_RX) &&
#endif
		    rh->r_dh.vlan) {
			u16 priority = rh->r_dh.priority;
			u16 vid = rh->r_dh.vlan;

			vtag = (priority << VLAN_PRIO_SHIFT) | vid;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
			__vlan_hwaccel_put_tag(skb, htons(ETH_P_8021Q), vtag);
#else
			__vlan_hwaccel_put_tag(skb, vtag);
#endif
		}

#if (RHEL_RELEASE_CODE >= 1541) && (RHEL_RELEASE_CODE < 1792)
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 1, 0)
		if (lio->vlgrp && rh->r_dh.vlan)
			vlan_gro_receive(napi, lio->vlgrp, vtag, skb);
		else
			napi_gro_receive_gr(napi, skb);
#else /* if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 1, 0) */
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 14, 0)
		if (skb->encapsulation)
			netif_receive_skb(skb);
		else
			napi_gro_receive_gr(napi, skb);
#else /* LINUX_VERSION_CODE >= KERNEL_VERSION(3, 14, 0) */
		napi_gro_receive_gr(napi, skb);
#endif /* LINUX_VERSION_CODE < KERNEL_VERSION(3, 14, 0) */
#endif /* LINUX_VERSION_CODE < KERNEL_VERSION(3, 1, 0) */
#else /* !((RHEL_RELEASE_CODE >= 1541) && (RHEL_RELEASE_CODE < 1792)) */
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 1, 0)
		if (lio->vlgrp && rh->r_dh.vlan)
			vlan_gro_receive(napi, lio->vlgrp, vtag, skb);
		else
			napi_gro_receive(napi, skb);
#else
		napi_gro_receive(napi, skb);
#endif /* LINUX_VERSION_CODE < KERNEL_VERSION(3, 1, 0) */
#endif /* (RHEL_RELEASE_CODE >= 1541) && (RHEL_RELEASE_CODE < 1792) */

		droq->stats.rx_bytes_received += len - rh->r_dh.len * BYTES_PER_DHLEN_UNIT;
		droq->stats.rx_pkts_received++;
	} else {
		recv_buffer_free(skb);
	}
}

/**
 * \brief wrapper for calling napi_schedule
 * @param param parameters to pass to napi_schedule
 *
 * Used when scheduling on different CPUs
 */
static void napi_schedule_wrapper(void *param)
{
	struct napi_struct *napi = param;

	napi_schedule(napi);
}

/**
 * \brief callback when receive interrupt occurs and we are in NAPI mode
 * @param arg pointer to octeon output queue
 */
static void liquidio_napi_drv_callback(void *arg)
{
	struct octeon_device *oct;
	struct octeon_droq *droq = arg;
	int this_cpu = smp_processor_id();

	oct = droq->oct_dev;

	if (OCTEON_CN23XX_PF(oct) || OCTEON_CN23XX_VF(oct) ||
	    droq->cpu_id == this_cpu) {
#if ((LINUX_VERSION_CODE >= KERNEL_VERSION(3, 19, 0)) || (RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(7, 2)))
		napi_schedule_irqoff(&droq->napi);
#else
		napi_schedule(&droq->napi);
#endif
	} else {
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 15, 0)
		smp_call_function_single(droq->cpu_id,
					 napi_schedule_wrapper, &droq->napi, 0);
#else
		cavium_call_single_data_t *csd = &droq->csd;

		csd->func = napi_schedule_wrapper;
		csd->info = &droq->napi;
		csd->flags = 0;

		smp_call_function_single_async(droq->cpu_id, csd);
#endif
	}
}

/**
 * \brief Entry point for NAPI polling
 * @param napi NAPI structure
 * @param budget maximum number of items to process
 */
static int liquidio_napi_poll(struct napi_struct *napi, int budget)
{
	struct octeon_instr_queue *iq;
	struct octeon_device *oct;
	struct octeon_droq *droq;
	int tx_done = 0, iq_no;
	int work_done;

	droq = container_of(napi, struct octeon_droq, napi);
	oct = droq->oct_dev;
	iq_no = droq->q_no;

	/* Handle Droq descriptors */
	work_done = octeon_droq_process_poll_pkts(oct, droq, budget);

	/* Flush the instruction queue */
	iq = oct->instr_queue[iq_no];
	if (iq) {
		/* TODO: move this check to inside octeon_flush_iq,
		 * once check_db_timeout is removed
		 */
		if (cavium_atomic_read(&iq->instr_pending))
			/* Process iq buffers with in the budget limits */
			tx_done = octeon_flush_iq(oct, iq, budget);
		else
			tx_done = 1;
		/* Update iq read-index rather than waiting for next interrupt.
		 * Return back if tx_done is false.
		 */
		/* sub-queue status update */
		lio_update_txq_status(oct, iq_no);
	} else {
		lio_dev_err(oct, "%s:  iq (%d) num invalid\n",
			    __CVM_FUNCTION__, iq_no);
	}

#define MAX_REG_CNT  2000000U
	/* force enable interrupt if reg cnts are high to avoid wraparound */
	if ((work_done < budget && tx_done) ||
	    (iq && iq->pkt_in_done >= MAX_REG_CNT) ||
	    (droq->pkt_count >= MAX_REG_CNT)) {
		tx_done = 1;
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 19, 0)
		napi_complete(napi);
#else
		napi_complete_done(napi, work_done);
#endif

		octeon_enable_irq(droq->oct_dev, droq->q_no);
		return 0;
	}

	return (!tx_done) ? (budget) : (work_done);
}

/**
 * \brief Setup input and output queues
 * @param octeon_dev octeon device
 * @param ifidx Interface index
 *
 * Note: Queues are with respect to the octeon device. Thus
 * an input queue is for egress packets, and output queues
 * are for ingress packets.
 */
int liquidio_setup_io_queues(struct octeon_device *octeon_dev, int ifidx,
			     u32 num_iqs, u32 num_oqs)
{
	struct octeon_droq_ops droq_ops;
	struct net_device *netdev;
	struct octeon_droq *droq;
	struct napi_struct *napi;
	int cpu_id_modulus;
	int num_tx_descs;
	struct lio *lio;
	int retval = 0;
	int q, q_no;
	int cpu_id;

	netdev = octeon_dev->props[ifidx].netdev;

	lio = GET_LIO(netdev);

	memset(&droq_ops, 0, sizeof(struct octeon_droq_ops));

	droq_ops.fptr = liquidio_push_packet;
	droq_ops.farg = netdev;

	droq_ops.poll_mode = 1;
	droq_ops.napi_fn = liquidio_napi_drv_callback;
	cpu_id = 0;
	cpu_id_modulus = num_present_cpus();

	/* set up DROQs. */
	for (q = 0; q < num_oqs; q++) {
		q_no = lio->linfo.rxpciq[q].s.q_no;
		lio_dev_dbg(octeon_dev,
			    "%s index:%d linfo.rxpciq.s.q_no:%d\n",
			    __func__, q, q_no);
		retval = octeon_setup_droq(
		    octeon_dev, q_no,
		    CFG_GET_NUM_RX_DESCS_NIC_IF(octeon_get_conf(octeon_dev),
						lio->ifidx),
		    CFG_GET_NUM_RX_BUF_SIZE_NIC_IF(octeon_get_conf(octeon_dev),
						   lio->ifidx),
		    NULL);
		if (retval) {
			lio_dev_err(octeon_dev,
				    "%s : Runtime DROQ(RxQ) creation failed.\n",
				    __func__);
			return 1;
		}

		droq = octeon_dev->droq[q_no];
		napi = &droq->napi;
		lio_dev_dbg(octeon_dev, "netif_napi_add netdev:%llx oct:%llx\n",
			    (u64)netdev, (u64)octeon_dev);
		netif_napi_add(netdev, napi, liquidio_napi_poll, 64);

		/* designate a CPU for this droq */
		droq->cpu_id = cpu_id;
		cpu_id++;
		if (cpu_id >= cpu_id_modulus)
			cpu_id = 0;

		octeon_register_droq_ops(octeon_dev, q_no, &droq_ops);
	}

	if (OCTEON_CN23XX_PF(octeon_dev) || OCTEON_CN23XX_VF(octeon_dev)) {
		/* 23XX PF/VF can send/recv control messages (via the first
		 * PF/VF-owned droq) from the firmware even if the ethX
		 * interface is down, so that's why poll_mode must be off
		 * for the first droq.
		 */
		octeon_dev->droq[0]->ops.poll_mode = 0;
	}

	/* set up IQs. */
	for (q = 0; q < num_iqs; q++) {
		num_tx_descs = CFG_GET_NUM_TX_DESCS_NIC_IF(
		    octeon_get_conf(octeon_dev), lio->ifidx);
		retval = octeon_setup_iq(octeon_dev, ifidx, q,
					 lio->linfo.txpciq[q], num_tx_descs,
					 netdev_get_tx_queue(netdev, q));
		if (retval) {
			lio_dev_err(octeon_dev,
				    " %s : Runtime IQ(TxQ) creation failed.\n",
				    __func__);
			return 1;
		}

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 9, 0))
		/* XPS */
		if (!OCTEON_CN23XX_VF(octeon_dev) && octeon_dev->msix_on &&
		    octeon_dev->ioq_vector) {
			struct octeon_ioq_vector    *ioq_vector;

			ioq_vector = &octeon_dev->ioq_vector[q];
			netif_set_xps_queue(netdev,
					    &ioq_vector->affinity_mask,
					    ioq_vector->iq_index);
		}
#endif
	}
	if (OCTEON_CN23XX_PF(octeon_dev)) {
		octeon_dev->instr_queue[lio->txq]->octlinux_qpg =
			lio->linfo.octlinux_qpg;
		octeon_dev->instr_queue[lio->txq]->octlinux_uqpg =
	                lio->linfo.octlinux_uqpg;
	}


	return 0;
}

static
int liquidio_schedule_msix_droq_pkt_handler(struct octeon_droq *droq, u64 ret)
{
	struct octeon_device *oct = droq->oct_dev;
	struct octeon_device_priv *oct_priv =
	    (struct octeon_device_priv *)oct->priv;

	if (droq->ops.poll_mode) {
		droq->ops.napi_fn(droq);
	} else {
		if (ret & MSIX_PO_INT) {
			if (OCTEON_CN23XX_VF(oct))
				lio_dev_err(oct,
					    "should not come here should not get rx when poll mode = 0 for vf\n");
			tasklet_schedule(&oct_priv->droq_tasklet);
			return 1;
		}
		/* this will be flushed periodically by check iq db */
		if (ret & MSIX_PI_INT)
			return 0;
	}

	return 0;
}

cvm_intr_return_t
liquidio_msix_intr_handler(int irq UNUSED, void *dev)
{
	struct octeon_ioq_vector *ioq_vector = (struct octeon_ioq_vector *)dev;
	struct octeon_device *oct = ioq_vector->oct_dev;
	struct octeon_droq *droq = oct->droq[ioq_vector->droq_index];
	u64 ret;

	ret = oct->fn_list.msix_interrupt_handler(ioq_vector);

	if (ret & MSIX_PO_INT || ret & MSIX_PI_INT)
		liquidio_schedule_msix_droq_pkt_handler(droq, ret);

	return CVM_INTR_HANDLED;
}

/**
 * \brief Droq packet processor sceduler
 * @param oct octeon device
 */
static void liquidio_schedule_droq_pkt_handlers(struct octeon_device *oct)
{
	struct octeon_device_priv *oct_priv =
		(struct octeon_device_priv *)oct->priv;
	struct octeon_droq *droq;
	u64 oq_no;

	if (oct->int_status & OCT_DEV_INTR_PKT_DATA) {
		for (oq_no = 0; oq_no < MAX_OCTEON_OUTPUT_QUEUES(oct);
		     oq_no++) {
			if (!(oct->droq_intr & BIT_ULL(oq_no)))
				continue;

			droq = oct->droq[oq_no];

			if (droq->ops.poll_mode) {
				droq->ops.napi_fn(droq);
				oct_priv->napi_mask |= (1 << oq_no);
			} else {
				tasklet_schedule(&oct_priv->droq_tasklet);
			}
		}
	}
}

/**
 * \brief Interrupt handler for octeon
 * @param irq unused
 * @param dev octeon device
 */
static
cvm_intr_return_t liquidio_legacy_intr_handler(int irq UNUSED,
					 void *dev)
{
	struct octeon_device *oct = (struct octeon_device *)dev;
	cvm_intr_return_t ret;

	/* Disable our interrupts for the duration of ISR */
	oct->fn_list.disable_interrupt(oct, OCTEON_ALL_INTR);

	ret = oct->fn_list.process_interrupt_regs(oct);

	if (ret == CVM_INTR_HANDLED)
		liquidio_schedule_droq_pkt_handlers(oct);

	/* Re-enable our interrupts  */
	if (!(cavium_atomic_read(&oct->status) == OCT_DEV_IN_RESET))
		oct->fn_list.enable_interrupt(oct, OCTEON_ALL_INTR);

	return ret;
}

/**
 * \brief Setup interrupt for octeon device
 * @param oct octeon device
 *
 *  Enable interrupt in Octeon device as given in the PCI interrupt mask.
 */
int octeon_setup_interrupt(struct octeon_device *oct, u32 num_ioqs)
{
	struct msix_entry *msix_entries;
	char *queue_irq_names = NULL;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 14, 0)
	int num_alloc_ioq_vectors;
#endif
	int i, num_interrupts = 0;
	char *aux_irq_name = NULL;
	int num_ioq_vectors;
	int irqret, err;

/* 64 ring pairs max */
#define MAX_IOQ_INTERRUPTS_PER_PF (64 * 2)
/* 8 ring pairs max */
#define MAX_IOQ_INTERRUPTS_PER_VF (8 * 2)

#define INTRNAMSIZ (32)
#define IRQ_NAME_OFF(i) ((i) * INTRNAMSIZ)

	if (oct->msix_on) {
		oct->num_msix_irqs = num_ioqs;
		if (OCTEON_CN23XX_PF(oct)) {
			num_interrupts = MAX_IOQ_INTERRUPTS_PER_PF + 1;

			/* one non ioq interrupt for handling
			 * sli_mac_pf_int_sum
			 */
			oct->num_msix_irqs += 1;
		} else if (OCTEON_CN23XX_VF(oct)) {
			num_interrupts = MAX_IOQ_INTERRUPTS_PER_VF;
		}

		/* allocate storage for the names assigned to each irq */
		oct->irq_name_storage =
			kcalloc(num_interrupts, INTRNAMSIZ, GFP_KERNEL);
		if (!oct->irq_name_storage) {
			lio_dev_err(oct, "Irq name storage alloc failed...\n");
			return -ENOMEM;
		}

		queue_irq_names = oct->irq_name_storage;

		if (OCTEON_CN23XX_PF(oct))
			aux_irq_name = &queue_irq_names
				[IRQ_NAME_OFF(MAX_IOQ_INTERRUPTS_PER_PF)];

		oct->msix_entries = kcalloc(oct->num_msix_irqs,
					    sizeof(struct msix_entry),
					    GFP_KERNEL);
		if (!oct->msix_entries) {
			lio_dev_err(oct, "Memory Alloc failed...\n");
			kfree(oct->irq_name_storage);
			oct->irq_name_storage = NULL;
			return -ENOMEM;
		}

		msix_entries = (struct msix_entry *)oct->msix_entries;

		/*Assumption is that pf msix vectors start from pf srn to pf to
		 * trs and not from 0. if not change this code
		 */
		if (OCTEON_CN23XX_PF(oct)) {
			for (i = 0; i < oct->num_msix_irqs - 1; i++)
				msix_entries[i].entry =
					oct->sriov_info.pf_srn + i;

			msix_entries[oct->num_msix_irqs - 1].entry =
				oct->sriov_info.trs;
		} else if (OCTEON_CN23XX_VF(oct)) {
			for (i = 0; i < oct->num_msix_irqs; i++)
				msix_entries[i].entry = i;
		}
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 14, 0)
		num_alloc_ioq_vectors = pci_enable_msix_range(
						oct->pci_dev, msix_entries,
						oct->num_msix_irqs,
						oct->num_msix_irqs);
		if (num_alloc_ioq_vectors < 0) {
			lio_dev_err(oct, "unable to Allocate MSI-X interrupts\n");
			kfree(oct->msix_entries);
			oct->msix_entries = NULL;
			kfree(oct->irq_name_storage);
			oct->irq_name_storage = NULL;
			return num_alloc_ioq_vectors;
		}
#else
		if (pci_enable_msix(oct->pci_dev, msix_entries,
				    oct->num_msix_irqs))
		{
			lio_dev_err(oct, "unable to Allocate MSI-X interrupts\n");
			kfree(oct->msix_entries);
			oct->msix_entries = NULL;
			kfree(oct->irq_name_storage);
			oct->irq_name_storage = NULL;
			return 1;
		}
#endif

		lio_dev_dbg(oct, "OCTEON: Enough MSI-X interrupts are allocated...\n");

		num_ioq_vectors = oct->num_msix_irqs;
		/** For PF, there is one non-ioq interrupt handler */
		if (OCTEON_CN23XX_PF(oct)) {
			num_ioq_vectors -= 1;

			snprintf(aux_irq_name, INTRNAMSIZ,
				 "LiquidIO%u-pf%u-aux", oct->octeon_id,
				 oct->pf_num);
			irqret = request_irq(
					msix_entries[num_ioq_vectors].vector,
					liquidio_legacy_intr_handler, 0,
					aux_irq_name, oct);
			if (irqret) {
				lio_dev_err(oct,
					    "Request_irq failed for MSIX interrupt Error: %d\n",
					    irqret);
				pci_disable_msix(oct->pci_dev);
				kfree(oct->msix_entries);
				kfree(oct->irq_name_storage);
				oct->irq_name_storage = NULL;
				oct->msix_entries = NULL;
				return irqret;
			}
		}
		for (i = 0 ; i < num_ioq_vectors ; i++) {
			if (OCTEON_CN23XX_PF(oct))
				snprintf(&queue_irq_names[IRQ_NAME_OFF(i)],
					 INTRNAMSIZ, "LiquidIO%u-pf%u-rxtx-%u",
					 oct->octeon_id, oct->pf_num, i);

			if (OCTEON_CN23XX_VF(oct))
				snprintf(&queue_irq_names[IRQ_NAME_OFF(i)],
					 INTRNAMSIZ, "LiquidIO%u-vf%u-rxtx-%u",
					 oct->octeon_id, oct->vf_num, i);

			irqret = request_irq(msix_entries[i].vector,
					     liquidio_msix_intr_handler, 0,
					     &queue_irq_names[IRQ_NAME_OFF(i)],
					     &oct->ioq_vector[i]);

			if (irqret) {
				lio_dev_err(oct,
					    "Request_irq failed for MSIX interrupt Error: %d\n",
					    irqret);
				/** Freeing the non-ioq irq vector here . */
				free_irq(msix_entries[num_ioq_vectors].vector,
					 oct);

				while (i) {
					i--;
					/** clearing affinity mask. */
					irq_set_affinity_hint(
						      msix_entries[i].vector,
						      NULL);
					free_irq(msix_entries[i].vector,
						 &oct->ioq_vector[i]);
				}
				pci_disable_msix(oct->pci_dev);
				kfree(oct->msix_entries);
				kfree(oct->irq_name_storage);
				oct->irq_name_storage = NULL;
				oct->msix_entries = NULL;
				return irqret;
			}
			oct->ioq_vector[i].vector = msix_entries[i].vector;
			/* assign the cpu mask for this msix interrupt vector */
			irq_set_affinity_hint(msix_entries[i].vector,
					      &oct->ioq_vector[i].affinity_mask
					      );
		}
		lio_dev_dbg(oct, "OCTEON[%d]: MSI-X enabled\n",
			    oct->octeon_id);
	} else {
		err = pci_enable_msi(oct->pci_dev);
		if (err)
			lio_dev_warn(oct, "Reverting to legacy interrupts. Error: %d\n",
				     err);
		else
			oct->flags |= LIO_FLAG_MSI_ENABLED;

		/* allocate storage for the names assigned to the irq */
		oct->irq_name_storage = kcalloc(1, INTRNAMSIZ, GFP_KERNEL);
		if (!oct->irq_name_storage)
			return -ENOMEM;

		queue_irq_names = oct->irq_name_storage;

		if (OCTEON_CN23XX_PF(oct))
			snprintf(&queue_irq_names[IRQ_NAME_OFF(0)], INTRNAMSIZ,
				 "LiquidIO%u-pf%u-rxtx-%u",
				 oct->octeon_id, oct->pf_num, 0);

		if (OCTEON_CN23XX_VF(oct))
			snprintf(&queue_irq_names[IRQ_NAME_OFF(0)], INTRNAMSIZ,
				 "LiquidIO%u-vf%u-rxtx-%u",
				 oct->octeon_id, oct->vf_num, 0);

		irqret = request_irq(oct->pci_dev->irq,
				     liquidio_legacy_intr_handler,
				     IRQF_SHARED,
				     &queue_irq_names[IRQ_NAME_OFF(0)], oct);
		if (irqret) {
			if (oct->flags & LIO_FLAG_MSI_ENABLED)
				pci_disable_msi(oct->pci_dev);
			lio_dev_err(oct, "Request IRQ failed with code: %d\n",
				    irqret);
			kfree(oct->irq_name_storage);
			oct->irq_name_storage = NULL;
			return irqret;
		}
	}
	return 0;
}

static void
octnet_nic_stats_callback(struct octeon_device *oct_dev,
			  u32 status, void *ptr)
{
	struct octeon_soft_command *sc = (struct octeon_soft_command *)ptr;
	struct oct_nic_stats_resp *resp =
	    (struct oct_nic_stats_resp *)sc->virtrptr;
	struct nic_rx_stats *rsp_rstats = &resp->stats.fromwire;
	struct nic_tx_stats *rsp_tstats = &resp->stats.fromhost;

	struct nic_rx_stats *rstats = &oct_dev->link_stats.fromwire;
	struct nic_tx_stats *tstats = &oct_dev->link_stats.fromhost;

	if ((status != OCTEON_REQUEST_TIMEOUT) && !resp->status) {
		octeon_swap_8B_data((u64 *)&resp->stats,
				    (sizeof(struct oct_link_stats)) >> 3);

		/* RX link-level stats */
		rstats->total_rcvd = rsp_rstats->total_rcvd;
		rstats->bytes_rcvd = rsp_rstats->bytes_rcvd;
		rstats->total_bcst = rsp_rstats->total_bcst;
		rstats->total_mcst = rsp_rstats->total_mcst;
		rstats->runts      = rsp_rstats->runts;
		rstats->ctl_rcvd   = rsp_rstats->ctl_rcvd;
		/* Accounts for over/under-run of buffers */
		rstats->fifo_err  = rsp_rstats->fifo_err;
		rstats->dmac_drop = rsp_rstats->dmac_drop;
		rstats->fcs_err   = rsp_rstats->fcs_err;
		rstats->jabber_err = rsp_rstats->jabber_err;
		rstats->l2_err    = rsp_rstats->l2_err;
		rstats->frame_err = rsp_rstats->frame_err;
		rstats->red_drops = rsp_rstats->red_drops;

		/* RX firmware stats */
		rstats->fw_total_rcvd = rsp_rstats->fw_total_rcvd;
		rstats->fw_total_fwd = rsp_rstats->fw_total_fwd;
		rstats->fw_total_mcast = rsp_rstats->fw_total_mcast;
		rstats->fw_total_bcast = rsp_rstats->fw_total_bcast;
		rstats->fw_err_pko = rsp_rstats->fw_err_pko;
		rstats->fw_err_link = rsp_rstats->fw_err_link;
		rstats->fw_err_drop = rsp_rstats->fw_err_drop;
		rstats->fw_rx_vxlan = rsp_rstats->fw_rx_vxlan;
		rstats->fw_rx_vxlan_err = rsp_rstats->fw_rx_vxlan_err;
#ifdef LINUX_IPSEC
		rstats->fw_ipsec_in = rsp_rstats->fw_ipsec_in;
#endif
		/* Number of packets that are LROed      */
		rstats->fw_lro_pkts = rsp_rstats->fw_lro_pkts;
		/* Number of octets that are LROed       */
		rstats->fw_lro_octs = rsp_rstats->fw_lro_octs;
		/* Number of LRO packets formed          */
		rstats->fw_total_lro = rsp_rstats->fw_total_lro;
		/* Number of times lRO of packet aborted */
		rstats->fw_lro_aborts = rsp_rstats->fw_lro_aborts;
		rstats->fw_lro_aborts_port = rsp_rstats->fw_lro_aborts_port;
		rstats->fw_lro_aborts_seq = rsp_rstats->fw_lro_aborts_seq;
		rstats->fw_lro_aborts_tsval = rsp_rstats->fw_lro_aborts_tsval;
		rstats->fw_lro_aborts_timer = rsp_rstats->fw_lro_aborts_timer;
		/* intrmod: packet forward rate */
		rstats->fwd_rate = rsp_rstats->fwd_rate;

		/* TX link-level stats */
		tstats->total_pkts_sent = rsp_tstats->total_pkts_sent;
		tstats->total_bytes_sent = rsp_tstats->total_bytes_sent;
		tstats->mcast_pkts_sent = rsp_tstats->mcast_pkts_sent;
		tstats->bcast_pkts_sent = rsp_tstats->bcast_pkts_sent;
		tstats->ctl_sent = rsp_tstats->ctl_sent;
		/* Packets sent after one collision*/
		tstats->one_collision_sent = rsp_tstats->one_collision_sent;
		/* Packets sent after multiple collision*/
		tstats->multi_collision_sent = rsp_tstats->multi_collision_sent;
		/* Packets not sent due to max collisions */
		tstats->max_collision_fail = rsp_tstats->max_collision_fail;
		/* Packets not sent due to max deferrals */
		tstats->max_deferral_fail = rsp_tstats->max_deferral_fail;
		/* Accounts for over/under-run of buffers */
		tstats->fifo_err = rsp_tstats->fifo_err;
		tstats->runts = rsp_tstats->runts;
		/* Total number of collisions detected */
		tstats->total_collisions = rsp_tstats->total_collisions;

		/* firmware stats */
		tstats->fw_total_sent = rsp_tstats->fw_total_sent;
		tstats->fw_total_fwd = rsp_tstats->fw_total_fwd;
		tstats->fw_total_mcast_sent = rsp_tstats->fw_total_mcast_sent;
		tstats->fw_total_bcast_sent = rsp_tstats->fw_total_bcast_sent;
		tstats->fw_err_pko = rsp_tstats->fw_err_pko;
		tstats->fw_err_pki = rsp_tstats->fw_err_pki;
		tstats->fw_err_link = rsp_tstats->fw_err_link;
		tstats->fw_err_drop = rsp_tstats->fw_err_drop;
		tstats->fw_tso = rsp_tstats->fw_tso;
		tstats->fw_tso_fwd = rsp_tstats->fw_tso_fwd;
		tstats->fw_err_tso = rsp_tstats->fw_err_tso;
		tstats->fw_tx_vxlan = rsp_tstats->fw_tx_vxlan;
#ifdef LINUX_IPSEC
		tstats->fw_ipsec_out = rsp_tstats->fw_ipsec_out;
#endif
		resp->status = 1;
	} else {
		lio_dev_err(oct_dev, "sc OPCODE_NIC_PORT_STATS command failed\n");
		resp->status = -1;
	}
}

void lio_fetch_vf_stats(struct lio *lio)
{
	struct octeon_device *oct_dev = lio->oct_dev;
	struct octeon_soft_command *sc;
	struct oct_nic_vf_stats_resp *resp;

	int retval;

	/* Alloc soft command */
	sc = (struct octeon_soft_command *)
		octeon_alloc_soft_command(oct_dev,
					  0,
					  sizeof(struct oct_nic_vf_stats_resp),
					  0);

	if (!sc) {
		lio_dev_err(oct_dev, "Soft command allocation failed\n");
		retval = -ENOMEM;
		goto lio_fetch_vf_stats_exit;
	}

	resp = (struct oct_nic_vf_stats_resp *)sc->virtrptr;
	memset(resp, 0, sizeof(struct oct_nic_vf_stats_resp));

	init_completion(&sc->complete);
	sc->sc_status = OCTEON_REQUEST_PENDING;

	sc->iq_no = lio->linfo.txpciq[0].s.q_no;

	octeon_prepare_soft_command(oct_dev, sc, OPCODE_NIC,
				    OPCODE_NIC_VF_PORT_STATS, 0, 0, 0);

	retval = octeon_send_soft_command(oct_dev, sc);
	if (retval == IQ_SEND_FAILED) {
		octeon_free_soft_command(oct_dev, sc);
		goto lio_fetch_vf_stats_exit;
	}

	retval = cavium_sleep_cond_timeout(oct_dev, sc, (2 * LIO_SC_MAX_TMO_MS));
	if (retval)  {
		lio_dev_err(oct_dev, "sc OPCODE_NIC_VF_PORT_STATS command failed\n");
		goto lio_fetch_vf_stats_exit;
	}

	if ((sc->sc_status != OCTEON_REQUEST_TIMEOUT) && !resp->status) {
                octeon_swap_8B_data((u64 *)&resp->spoofmac_cnt, (sizeof(u64)) >> 3);

		if (resp->spoofmac_cnt != 0) {
			 lio_dev_warn(oct_dev, "%llu Spoofed packets detected\n", resp->spoofmac_cnt);
		}
	}
	cavium_set_bit(CALLER_DONE_BIT, &sc->done);

lio_fetch_vf_stats_exit:

	return;

}

void lio_fetch_stats(struct work_struct *work)
{
	struct cavium_wk *wk = (struct cavium_wk *)work;
	struct lio *lio = wk->ctxptr;
	struct octeon_device *oct_dev = lio->oct_dev;

	struct octeon_soft_command *sc;
	struct oct_nic_stats_resp *resp;

	unsigned long time_in_jiffies;
	int retval;

	if (OCTEON_CN23XX_PF(oct_dev)) {
		/* report spoofchk every 2 seconds */
		if (!(oct_dev->vfstats_poll % LIO_VFSTATS_POLL) &&
		    (oct_dev->fw_info.app_cap_flags & LIQUIDIO_SPOOFCHK_CAP) &&
        			oct_dev->sriov_info.num_vfs_alloced) {
			lio_fetch_vf_stats(lio);
		}

		oct_dev->vfstats_poll++;
	}

	/* Alloc soft command */
	sc = (struct octeon_soft_command *)
		octeon_alloc_soft_command(oct_dev,
					  0,
					  sizeof(struct oct_nic_stats_resp),
					  0);

	if (!sc) {
		lio_dev_err(oct_dev, "Soft command allocation failed\n");
		goto lio_fetch_stats_exit;
	}

	resp = (struct oct_nic_stats_resp *)sc->virtrptr;
	memset(resp, 0, sizeof(struct oct_nic_stats_resp));

	init_completion(&sc->complete);
	sc->sc_status = OCTEON_REQUEST_PENDING;

	sc->iq_no = lio->linfo.txpciq[0].s.q_no;

	octeon_prepare_soft_command(oct_dev, sc, OPCODE_NIC,
				    OPCODE_NIC_PORT_STATS, 0, 0, 0);

	retval = octeon_send_soft_command(oct_dev, sc);
	if (retval == IQ_SEND_FAILED) {
		octeon_free_soft_command(oct_dev, sc);
		goto lio_fetch_stats_exit;
	}

	retval = cavium_sleep_cond_timeout(oct_dev, sc, (2 * LIO_SC_MAX_TMO_MS));
	if (retval)  {
		lio_dev_err(oct_dev, "sc OPCODE_NIC_PORT_STATS command failed\n");
		goto lio_fetch_stats_exit;
	}

	octnet_nic_stats_callback(oct_dev, sc->sc_status, sc);
	cavium_set_bit(CALLER_DONE_BIT, &sc->done);

lio_fetch_stats_exit:
	time_in_jiffies = msecs_to_jiffies(LIQUIDIO_NDEV_STATS_POLL_TIME_MS);
	if (ifstate_check(lio, LIO_IFSTATE_RUNNING))
		schedule_delayed_work(&lio->stats_wk.work, time_in_jiffies);

	return;
}

/**
 * \brief Net device change_mtu
 * @param netdev network device
 */
int liquidio_change_mtu(struct net_device *netdev, int new_mtu)
{
	struct lio *lio = GET_LIO(netdev);
	struct octeon_device *oct = lio->oct_dev;
	struct octeon_soft_command *sc;
	union octnet_cmd *ncmd;
	int retval = 0;

#if (LINUX_VERSION_CODE < KERNEL_VERSION(4, 10, 0))
	/* Limit the MTU to make sure the ethernet packets are between 68 bytes
	 * and 16000 bytes
	 */
	if ((new_mtu < LIO_MIN_MTU_SIZE) ||
	    (new_mtu > lio->linfo.link.s.mtu)) {
		lio_dev_err(oct, "Invalid MTU: %d; Valid range is %d to %d\n",
			    new_mtu, LIO_MIN_MTU_SIZE, lio->linfo.link.s.mtu);
		return -EINVAL;
	}
#endif

	sc = (struct octeon_soft_command *)
		octeon_alloc_soft_command(oct, OCTNET_CMD_SIZE, 16, 0);

	ncmd = (union octnet_cmd *)sc->virtdptr;

	init_completion(&sc->complete);
	sc->sc_status = OCTEON_REQUEST_PENDING;

	ncmd->u64 = 0;
	ncmd->s.cmd = OCTNET_CMD_CHANGE_MTU;
	ncmd->s.param1 = new_mtu;

	octeon_swap_8B_data((u64 *)ncmd, (OCTNET_CMD_SIZE >> 3));

	sc->iq_no = lio->linfo.txpciq[0].s.q_no;

	octeon_prepare_soft_command(oct, sc, OPCODE_NIC,
				    OPCODE_NIC_CMD, 0, 0, 0);

	retval = octeon_send_soft_command(oct, sc);
	if (retval == IQ_SEND_FAILED) {
		lio_info(lio, rx_err, "Failed to change MTU\n");
		octeon_free_soft_command(oct, sc);
		return -EINVAL;
	}
	/* Sleep on a wait queue till the cond flag indicates that the
	 * response arrived or timed-out.
	 */
	if ((retval = cavium_sleep_cond_timeout(oct, sc, 0)))
		return retval;

	/* command is successful, change the MTU. */
	lio_info(lio, probe, "MTU changed from %d to %d\n",
		 netdev->mtu, new_mtu);
	netdev->mtu = new_mtu;
	lio->mtu = new_mtu;

	cavium_set_bit(CALLER_DONE_BIT, &sc->done);

	return 0;
}

void lio_wait_for_clean_oq(struct octeon_device *oct)
{
	int retry = 100, pending_pkts = 0;
	int idx;

	do {
		pending_pkts = 0;

		for (idx = 0; idx < MAX_OCTEON_OUTPUT_QUEUES(oct); idx++) {
			if (!(oct->io_qmask.oq & BIT_ULL(idx)))
				continue;
			pending_pkts += cavium_atomic_read(
					&oct->droq[idx]->pkts_pending);
		}

		if (pending_pkts > 0)
			cavium_sleep_timeout(1);

	} while (retry-- && pending_pkts);
}

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 12, 0)) || (RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(7, 0))

int liquidio_get_phys_port_id(struct net_device *netdev,
			      struct netdev_phys_item_id *ppid)
{
	struct lio *lio = GET_LIO(netdev);
	u8 addr[ETH_ALEN];

	cavium_u64_to_ether_addr(cavium_be64_to_cpu(lio->linfo.hw_addr), addr);
	ppid->id_len = ETH_ALEN;
	cavium_memcpy(ppid->id, addr, ppid->id_len);

	return 0;
}
#endif

