/**********************************************************************
 * Author: Cavium, Inc.
 *
 * Contact: support@cavium.com
 *          Please include "LiquidIO" in the subject.
 *
 * Copyright (c) 2003-2017 Cavium, Inc.
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
#include <linux/version.h>
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4, 8, 0))
#include <linux/module.h>
#include <linux/crc32.h>
#include <linux/dma-mapping.h>
#include <linux/pci.h>
#include <linux/pci_ids.h>
#include <linux/ip.h>
#include <net/ip.h>
#include <linux/ipv6.h>
#include <linux/net_tstamp.h>
#include <linux/if_vlan.h>
#include <linux/firmware.h>
#include <linux/ethtool.h>
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
#include <net/switchdev.h>
#include "lio_vf_rep.h"
#include <net/devlink.h>

static int lio_vf_rep_open(struct net_device *ndev);
static int lio_vf_rep_stop(struct net_device *ndev);
static int lio_vf_rep_pkt_xmit(struct sk_buff *skb, struct net_device *ndev);
static void lio_vf_rep_tx_timeout(struct net_device *netdev);
static int lio_vf_rep_phys_port_name(struct net_device *dev,
				     char *buf, size_t len);
#if (LINUX_VERSION_CODE < KERNEL_VERSION(4, 11, 0))
struct rtnl_link_stats64 *
#else
static void
#endif
lio_vf_rep_get_stats64(struct net_device *dev, struct rtnl_link_stats64 *);
static int lio_vf_rep_change_mtu(struct net_device *ndev, int new_mtu);

static const char lio_vf_rep_stats_strings[][ETH_GSTRING_LEN] = {
	"rx_packets",
	"tx_packets",
	"rx_bytes",
	"tx_bytes",
	"rx_dropped",
	"tx_dropped",
};

static void
lio_vf_rep_get_drvinfo(struct net_device *ndev,
		       struct ethtool_drvinfo *drvinfo)
{
	struct lio_vf_rep_desc *vf_rep = netdev_priv(ndev);
	struct octeon_device *oct;

	oct = vf_rep->oct;

	memset(drvinfo, 0, sizeof(struct ethtool_drvinfo));
	strcpy(drvinfo->driver, "liquidio");
	strcpy(drvinfo->version, LIQUIDIO_VERSION);
	strncpy(drvinfo->fw_version, oct->fw_info.liquidio_firmware_version,
		ETHTOOL_FWVERS_LEN);
}

static void
lio_vf_rep_get_ethtool_stats(struct net_device *ndev,
			     struct ethtool_stats *stats,
			     u64 *data)
{
	struct rtnl_link_stats64 *stats_ptr, net_stats;
	int i = 0;

	stats_ptr = dev_get_stats(ndev, &net_stats);

	data[i++] = stats_ptr->rx_packets;
	data[i++] = stats_ptr->tx_packets;
	data[i++] = stats_ptr->rx_bytes;
	data[i++] = stats_ptr->tx_bytes;
	data[i++] = stats_ptr->rx_dropped;
	data[i++] = stats_ptr->tx_dropped;
}

static int
lio_vf_rep_get_sset_count(struct net_device *ndev, int sset)
{
	switch (sset) {
	case ETH_SS_STATS:
		return ARRAY_SIZE(lio_vf_rep_stats_strings);

	default:
		return -EOPNOTSUPP;
	}
}

static void
lio_vf_rep_get_strings(struct net_device *ndev, u32 stringset, u8 *data)
{
	struct lio_vf_rep_desc *vf_rep = netdev_priv(ndev);
	struct octeon_device *oct = vf_rep->oct;
	int i, num_stats;

	switch (stringset) {
	case ETH_SS_STATS:
		num_stats = ARRAY_SIZE(lio_vf_rep_stats_strings);
		for (i = 0; i < num_stats; i++) {
			sprintf(data, "%s", lio_vf_rep_stats_strings[i]);
			data += ETH_GSTRING_LEN;
		}
		break;

	default:
		lio_dev_err(oct, "Unknown Stringset !!\n");
		break;
	}
}

static const struct ethtool_ops lio_vf_rep_ethtool_ops = {
	.get_drvinfo	= lio_vf_rep_get_drvinfo,
	.get_link	= ethtool_op_get_link,
	.get_strings	= lio_vf_rep_get_strings,
	.get_sset_count	= lio_vf_rep_get_sset_count,
	.get_ethtool_stats = lio_vf_rep_get_ethtool_stats,
};

static const struct net_device_ops lio_vf_rep_ndev_ops = {
	.ndo_open = lio_vf_rep_open,
	.ndo_stop = lio_vf_rep_stop,
	.ndo_start_xmit = lio_vf_rep_pkt_xmit,
	.ndo_tx_timeout = lio_vf_rep_tx_timeout,
	.ndo_get_phys_port_name = lio_vf_rep_phys_port_name,
	.ndo_get_stats64 = lio_vf_rep_get_stats64,
	.ndo_change_mtu = lio_vf_rep_change_mtu,
};

static int
lio_vf_rep_send_soft_command(struct octeon_device *oct,
			     void *req, int req_size,
			     void *resp, int resp_size)
{
	int tot_resp_size = sizeof(struct lio_vf_rep_resp) + resp_size;
	struct octeon_soft_command *sc = NULL;
	struct lio_vf_rep_resp *rep_resp;
	void *sc_req;
	int err;
	int retval;

	sc = (struct octeon_soft_command *)
		octeon_alloc_soft_command(oct, req_size,
					  tot_resp_size, 0);
	if (!sc)
		return -ENOMEM;

	init_completion(&sc->complete);
	sc->sc_status = OCTEON_REQUEST_PENDING;

	sc_req = (struct lio_vf_rep_req *)sc->virtdptr;
	memcpy(sc_req, req, req_size);

	rep_resp = (struct lio_vf_rep_resp *)sc->virtrptr;
	memset(rep_resp, 0, tot_resp_size);
	WRITE_ONCE(rep_resp->status, 1);

	sc->iq_no = 0;
	octeon_prepare_soft_command(oct, sc, OPCODE_NIC,
				    OPCODE_NIC_VF_REP_CMD, 0, 0, 0);

	err = octeon_send_soft_command(oct, sc);
	if (err == IQ_SEND_FAILED)
		goto free_buff;

	if ((retval = cavium_sleep_cond_timeout(oct, sc, LIO_VF_REP_REQ_TMO_MS))) {
		return(retval);
	}

	err = READ_ONCE(rep_resp->status) ? -EBUSY : 0;
	if (err)
		lio_dev_err(oct, "VF rep send config failed\n");
	else if (resp)
		memcpy(resp, (rep_resp + 1), resp_size);

	cavium_set_bit(CALLER_DONE_BIT, &sc->done);
	return err;

free_buff:
	octeon_free_soft_command(oct, sc);

	return err;
}

static int
lio_vf_rep_open(struct net_device *ndev)
{
	struct lio_vf_rep_desc *vf_rep = netdev_priv(ndev);
	struct lio_vf_rep_req rep_cfg;
	struct octeon_device *oct;
	int ret;

	oct = vf_rep->oct;

	memset(&rep_cfg, 0, sizeof(rep_cfg));
	rep_cfg.req_type = LIO_VF_REP_REQ_STATE;
	rep_cfg.ifidx = vf_rep->ifidx;
	rep_cfg.rep_state.state = LIO_VF_REP_STATE_UP;

	ret = lio_vf_rep_send_soft_command(oct, &rep_cfg,
					   sizeof(rep_cfg), NULL, 0);

	if (ret) {
		lio_dev_err(oct, "VF_REP open failed with err %d\n", ret);
		return -EIO;
	}

	atomic_set(&vf_rep->ifstate, (atomic_read(&vf_rep->ifstate) |
				      LIO_IFSTATE_RUNNING));

	netif_carrier_on(ndev);
	netif_start_queue(ndev);

	return 0;
}

static int
lio_vf_rep_stop(struct net_device *ndev)
{
	struct lio_vf_rep_desc *vf_rep = netdev_priv(ndev);
	struct lio_vf_rep_req rep_cfg;
	struct octeon_device *oct;
	int ret;

	oct = vf_rep->oct;

	memset(&rep_cfg, 0, sizeof(rep_cfg));
	rep_cfg.req_type = LIO_VF_REP_REQ_STATE;
	rep_cfg.ifidx = vf_rep->ifidx;
	rep_cfg.rep_state.state = LIO_VF_REP_STATE_DOWN;

	ret = lio_vf_rep_send_soft_command(oct, &rep_cfg,
					   sizeof(rep_cfg), NULL, 0);

	if (ret) {
		lio_dev_err(oct, "VF_REP dev stop failed with err %d\n", ret);
		return -EIO;
	}

	atomic_set(&vf_rep->ifstate, (atomic_read(&vf_rep->ifstate) &
				      ~LIO_IFSTATE_RUNNING));

	netif_tx_disable(ndev);
	netif_carrier_off(ndev);

	return 0;
}

static void
lio_vf_rep_tx_timeout(struct net_device *ndev)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 7, 0) || (RHEL_RELEASE_CODE > RHEL_RELEASE_VERSION(7, 4))
	netif_trans_update(ndev);
#else
	//ndev->trans_start = jiffies;
	netdev_get_tx_queue(ndev,0)->trans_start = jiffies;
#endif

	netif_wake_queue(ndev);
}

#if (LINUX_VERSION_CODE < KERNEL_VERSION(4, 11, 0))
struct rtnl_link_stats64 *
#else
static void
#endif
lio_vf_rep_get_stats64(struct net_device *dev,
		       struct rtnl_link_stats64 *stats64)
{
	struct lio_vf_rep_desc *vf_rep = netdev_priv(dev);

	/* Swap tx and rx stats as VF rep is a switch port */
	stats64->tx_packets = vf_rep->stats.rx_packets;
	stats64->tx_bytes   = vf_rep->stats.rx_bytes;
	stats64->tx_dropped = vf_rep->stats.rx_dropped;

	stats64->rx_packets = vf_rep->stats.tx_packets;
	stats64->rx_bytes   = vf_rep->stats.tx_bytes;
	stats64->rx_dropped = vf_rep->stats.tx_dropped;

#if (LINUX_VERSION_CODE < KERNEL_VERSION(4, 11, 0))
	return stats64;
#endif
}

static int
lio_vf_rep_change_mtu(struct net_device *ndev, int new_mtu)
{
	struct lio_vf_rep_desc *vf_rep = netdev_priv(ndev);
	struct lio_vf_rep_req rep_cfg;
	struct octeon_device *oct;
	int ret;

	oct = vf_rep->oct;

#if (LINUX_VERSION_CODE < KERNEL_VERSION(4, 10, 0))
	if ((new_mtu < LIO_MIN_MTU_SIZE) ||
	    (new_mtu > LIO_MAX_MTU_SIZE)) {
		lio_dev_err(oct, "Invalid MTU: %d\n", new_mtu);
		lio_dev_err(oct, "Valid range %d and %d\n",
			    LIO_MIN_MTU_SIZE, LIO_MAX_MTU_SIZE);
		return -EINVAL;
	}
#endif

	memset(&rep_cfg, 0, sizeof(rep_cfg));
	rep_cfg.req_type = LIO_VF_REP_REQ_MTU;
	rep_cfg.ifidx = vf_rep->ifidx;
	rep_cfg.rep_mtu.mtu = cavium_cpu_to_be32(new_mtu);

	ret = lio_vf_rep_send_soft_command(oct, &rep_cfg,
					   sizeof(rep_cfg), NULL, 0);
	if (ret) {
		lio_dev_err(oct, "Change MTU failed with err %d\n", ret);
		return -EIO;
	}

	ndev->mtu = new_mtu;

	return 0;
}

static int
lio_vf_rep_phys_port_name(struct net_device *dev,
			  char *buf, size_t len)
{
	struct lio_vf_rep_desc *vf_rep = netdev_priv(dev);
	struct octeon_device *oct = vf_rep->oct;
	int ret;

	ret = snprintf(buf, len, "pf%dvf%d", oct->pf_num,
		       vf_rep->ifidx - oct->pf_num * 64 - 1);
	if (ret >= len)
		return -EOPNOTSUPP;

	return 0;
}

static struct net_device *
lio_vf_rep_get_ndev(struct octeon_device *oct, int ifidx)
{
	int vf_id, max_vfs = CN23XX_MAX_VFS_PER_PF + 1;
	int vfid_mask = max_vfs - 1;

	if (ifidx <= oct->pf_num * max_vfs ||
	    ifidx >= oct->pf_num * max_vfs + max_vfs)
		return NULL;

	/* ifidx 1-63 for PF0 VFs
	 * ifidx 65-127 for PF1 VFs
	 */
	vf_id = (ifidx & vfid_mask) - 1;

	return oct->vf_rep_list.ndev[vf_id];
}

static void
lio_vf_rep_copy_packet(struct octeon_device *oct,
		       struct sk_buff *skb,
		       int len)
{
	if (likely(len > MIN_SKB_SIZE)) {
		struct octeon_skb_page_info *pg_info;
		unsigned char *va;

		pg_info = ((struct octeon_skb_page_info *)(skb->cb));
		if (pg_info->page) {
			va = page_address(pg_info->page) +
				pg_info->page_offset;
			memcpy(skb->data, va, MIN_SKB_SIZE);
			skb_put(skb, MIN_SKB_SIZE);
		}

		skb_add_rx_frag(skb, skb_shinfo(skb)->nr_frags,
				pg_info->page,
				pg_info->page_offset + MIN_SKB_SIZE,
				len - MIN_SKB_SIZE,
				LIO_RXBUFFER_SZ);
	} else {
		struct octeon_skb_page_info *pg_info =
			((struct octeon_skb_page_info *)(skb->cb));

		skb_copy_to_linear_data(skb, page_address(pg_info->page) +
					pg_info->page_offset, len);
		skb_put(skb, len);
		put_page(pg_info->page);
	}
}

static int
lio_vf_rep_pkt_recv(struct octeon_recv_info *recv_info, void *buf)
{
	struct octeon_recv_pkt *recv_pkt = recv_info->recv_pkt;
	struct lio_vf_rep_desc *vf_rep;
	struct net_device *vf_ndev;
	struct octeon_device *oct;
	union octeon_rh *rh;
	struct sk_buff *skb;
	int i, ifidx;

	oct = lio_get_device(recv_pkt->octeon_id);
	if (!oct)
		goto free_buffers;

	skb = recv_pkt->buffer_ptr[0];
	rh = &recv_pkt->rh;
	ifidx = rh->r.ossp;

	vf_ndev = lio_vf_rep_get_ndev(oct, ifidx);
	if (!vf_ndev)
		goto free_buffers;

	vf_rep = netdev_priv(vf_ndev);
	if (!(atomic_read(&vf_rep->ifstate) & LIO_IFSTATE_RUNNING) ||
	    recv_pkt->buffer_count > 1)
		goto free_buffers;

	skb->dev = vf_ndev;

	/* Multiple buffers are not used for vf_rep packets.
	 * So just buffer_size[0] is valid.
	 */
	lio_vf_rep_copy_packet(oct, skb, recv_pkt->buffer_size[0]);

	skb_pull(skb, rh->r_dh.len * BYTES_PER_DHLEN_UNIT);
	skb->protocol = eth_type_trans(skb, skb->dev);
	skb->ip_summed = CHECKSUM_NONE;

	netif_rx(skb);

	octeon_free_recv_info(recv_info);

	return 0;

free_buffers:
	for (i = 0; i < recv_pkt->buffer_count; i++)
		recv_buffer_free(recv_pkt->buffer_ptr[i]);

	octeon_free_recv_info(recv_info);

	return 0;
}

static void
lio_vf_rep_packet_sent_callback(struct octeon_device *oct,
				u32 status, void *buf)
{
	struct octeon_soft_command *sc = (struct octeon_soft_command *)buf;
	struct sk_buff *skb = sc->ctxptr;
	struct net_device *ndev = skb->dev;

	dma_unmap_single(&oct->pci_dev->dev, sc->dmadptr,
			 sc->datasize, DMA_TO_DEVICE);
	dev_kfree_skb_any(skb);
	octeon_free_soft_command(oct, sc);

	if (octnet_iq_is_full(oct, sc->iq_no))
		return;

	if (netif_queue_stopped(ndev))
		netif_wake_queue(ndev);
}

static int
lio_vf_rep_pkt_xmit(struct sk_buff *skb, struct net_device *ndev)
{
	struct lio_vf_rep_desc *vf_rep = netdev_priv(ndev);
	struct net_device *parent_ndev = vf_rep->parent_ndev;
	struct octeon_device *oct = vf_rep->oct;
	struct octeon_instr_pki_ih3 *pki_ih3;
	struct octeon_soft_command *sc;
	struct lio *parent_lio;
	int status;

	parent_lio = GET_LIO(parent_ndev);

	if (!(atomic_read(&vf_rep->ifstate) & LIO_IFSTATE_RUNNING) ||
#if (LINUX_VERSION_CODE < KERNEL_VERSION(4, 10, 0))
	    (skb->len <= 0) || (skb->len > CN23XX_MAX_INPUT_JABBER)) {
#else
	    (skb->len <= 0)) {
#endif
		goto xmit_failed;
	}

	if (octnet_iq_is_full(vf_rep->oct, parent_lio->txq)) {
		lio_dev_err(oct, "VF rep: Device IQ full\n");
		netif_stop_queue(ndev);
		return NETDEV_TX_BUSY;
	}

	sc = (struct octeon_soft_command *)
		octeon_alloc_soft_command(oct, 0, 16, 0);
	if (!sc) {
		lio_dev_err(oct, "VF rep: Soft command alloc failed\n");
		goto xmit_failed;
	}

	/* Multiple buffers are not used for vf_rep packets. */
	if (skb_shinfo(skb)->nr_frags != 0) {
		lio_dev_err(oct, "VF rep: nr_frags != 0. Dropping packet\n");
		octeon_free_soft_command(oct, sc);
		goto xmit_failed;
	}

	sc->dmadptr = dma_map_single(&oct->pci_dev->dev,
				     skb->data, skb->len, DMA_TO_DEVICE);
	if (dma_mapping_error(&oct->pci_dev->dev, sc->dmadptr)) {
		lio_dev_err(oct, "VF rep: DMA mapping failed\n");
		octeon_free_soft_command(oct, sc);
		goto xmit_failed;
	}

	sc->virtdptr = skb->data;
	sc->datasize = skb->len;
	sc->ctxptr = skb;
	sc->iq_no = parent_lio->txq;

	octeon_prepare_soft_command(oct, sc, OPCODE_NIC, OPCODE_NIC_VF_REP_PKT,
				    vf_rep->ifidx, 0, 0);
	pki_ih3 = (struct octeon_instr_pki_ih3 *)&sc->cmd.cmd3.pki_ih3;
	pki_ih3->tagtype = ORDERED_TAG;

	sc->callback = lio_vf_rep_packet_sent_callback;
	sc->callback_arg = sc;

	status = octeon_send_soft_command(oct, sc);
	if (status == IQ_SEND_FAILED) {
		dma_unmap_single(&oct->pci_dev->dev, sc->dmadptr,
				 sc->datasize, DMA_TO_DEVICE);
		octeon_free_soft_command(oct, sc);
		goto xmit_failed;
	}

	if (status == IQ_SEND_STOP)
		netif_stop_queue(ndev);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 7, 0) || (RHEL_RELEASE_CODE > RHEL_RELEASE_VERSION(7, 4))
	netif_trans_update(ndev);
#else
	netdev_get_tx_queue(ndev,0)->trans_start = jiffies;
#endif

	return NETDEV_TX_OK;

xmit_failed:
	dev_kfree_skb_any(skb);

	return NETDEV_TX_OK;
}

static int
lio_vf_rep_attr_get(struct net_device *dev, struct switchdev_attr *attr)
{
	struct lio_vf_rep_desc *vf_rep = netdev_priv(dev);
	struct net_device *parent_ndev = vf_rep->parent_ndev;
	struct lio *lio = GET_LIO(parent_ndev);

	switch (attr->id) {
	case SWITCHDEV_ATTR_ID_PORT_PARENT_ID:
		attr->u.ppid.id_len = ETH_ALEN;
		ether_addr_copy(attr->u.ppid.id,
				(void *)&lio->linfo.hw_addr + 2);
		break;

	default:
		return -EOPNOTSUPP;
	}

	return 0;
}

static const struct switchdev_ops lio_vf_rep_switchdev_ops = {
	.switchdev_port_attr_get        = lio_vf_rep_attr_get,
};

static void
lio_vf_rep_fetch_stats(struct work_struct *work)
{
	struct cavium_wk *wk = (struct cavium_wk *)work;
	struct lio_vf_rep_desc *vf_rep = wk->ctxptr;
	struct lio_vf_rep_stats stats;
	struct lio_vf_rep_req rep_cfg;
	struct octeon_device *oct;
	int ret;

	oct = vf_rep->oct;

	memset(&rep_cfg, 0, sizeof(rep_cfg));
	rep_cfg.req_type = LIO_VF_REP_REQ_STATS;
	rep_cfg.ifidx = vf_rep->ifidx;

	ret = lio_vf_rep_send_soft_command(oct, &rep_cfg, sizeof(rep_cfg),
					   &stats, sizeof(stats));

	if (!ret) {
		octeon_swap_8B_data((u64 *)&stats, (sizeof(stats) >> 3));
		memcpy(&vf_rep->stats, &stats, sizeof(stats));
	}

	schedule_delayed_work(&vf_rep->stats_wk.work,
			      msecs_to_jiffies(LIO_VF_REP_STATS_POLL_TIME_MS));
}

int
lio_vf_rep_create(struct octeon_device *oct)
{
	struct lio_vf_rep_desc *vf_rep;
	struct net_device *ndev;
	int i, num_vfs;

	if (oct->eswitch_mode != DEVLINK_ESWITCH_MODE_SWITCHDEV)
		return 0;

	if (!oct->sriov_info.sriov_enabled)
		return 0;

	num_vfs = oct->sriov_info.num_vfs_alloced;

	oct->vf_rep_list.num_vfs = 0;
	for (i = 0; i < num_vfs; i++) {
		ndev = alloc_etherdev(sizeof(struct lio_vf_rep_desc));

		if (!ndev) {
			lio_dev_err(oct, "VF rep device %d creation failed\n",
				    i);
			goto cleanup;
		}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 10, 0)
		ndev->min_mtu = LIO_MIN_MTU_SIZE;
		ndev->max_mtu = LIO_MAX_MTU_SIZE;
#endif
		ndev->netdev_ops = &lio_vf_rep_ndev_ops;

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4, 13, 0))
		SWITCHDEV_SET_OPS(ndev, &lio_vf_rep_switchdev_ops);
#elif defined (CONFIG_NET_SWITCHDEV)
		ndev->switchdev_ops = &lio_vf_rep_switchdev_ops;
#endif
		ndev->ethtool_ops = &lio_vf_rep_ethtool_ops;

		vf_rep = netdev_priv(ndev);
		memset(vf_rep, 0, sizeof(*vf_rep));

		vf_rep->ndev = ndev;
		vf_rep->oct = oct;
		vf_rep->parent_ndev = oct->props[0].netdev;
		vf_rep->ifidx = (oct->pf_num * 64) + i + 1;

		eth_hw_addr_random(ndev);

		if (register_netdev(ndev)) {
			lio_dev_err(oct, "VF rep nerdev registration failed\n");

			free_netdev(ndev);
			goto cleanup;
		}

		netif_carrier_off(ndev);

		CAVIUM_INIT_DELAYED_WORK(&vf_rep->stats_wk.work,
					 lio_vf_rep_fetch_stats);
		vf_rep->stats_wk.ctxptr = (void *)vf_rep;
		schedule_delayed_work(&vf_rep->stats_wk.work,
				      msecs_to_jiffies
				      (LIO_VF_REP_STATS_POLL_TIME_MS));
		oct->vf_rep_list.num_vfs++;
		oct->vf_rep_list.ndev[i] = ndev;
	}

	if (octeon_register_dispatch_fn(oct, OPCODE_NIC,
					OPCODE_NIC_VF_REP_PKT,
					lio_vf_rep_pkt_recv, oct)) {
		lio_dev_err(oct, "VF rep Dispatch func registration failed\n");

		goto cleanup;
	}

	return 0;

cleanup:
	for (i = 0; i < oct->vf_rep_list.num_vfs; i++) {
		ndev = oct->vf_rep_list.ndev[i];
		oct->vf_rep_list.ndev[i] = NULL;
		if (ndev) {
			vf_rep = netdev_priv(ndev);
			cavium_cancel_delayed_work_sync
				(&vf_rep->stats_wk.work);
			unregister_netdev(ndev);
			free_netdev(ndev);
		}
	}

	oct->vf_rep_list.num_vfs = 0;

	return -1;
}

void
lio_vf_rep_destroy(struct octeon_device *oct)
{
	struct lio_vf_rep_desc *vf_rep;
	struct net_device *ndev;
	int i;

	if (oct->eswitch_mode != DEVLINK_ESWITCH_MODE_SWITCHDEV)
		return;

	if (!oct->sriov_info.sriov_enabled)
		return;

	octeon_unregister_dispatch_fn(oct, OPCODE_NIC, OPCODE_NIC_VF_REP_PKT);

	for (i = 0; i < oct->vf_rep_list.num_vfs; i++) {
		ndev = oct->vf_rep_list.ndev[i];
		oct->vf_rep_list.ndev[i] = NULL;
		if (ndev) {
			vf_rep = netdev_priv(ndev);
			cavium_cancel_delayed_work_sync
				(&vf_rep->stats_wk.work);
			netif_tx_disable(ndev);
			netif_carrier_off(ndev);

			unregister_netdev(ndev);
			free_netdev(ndev);
		}
	}

	oct->vf_rep_list.num_vfs = 0;
}

static int
lio_vf_rep_netdev_event(struct notifier_block *nb,
			unsigned long event, void *ptr)
{
	struct net_device *ndev = netdev_notifier_info_to_dev(ptr);
	struct lio_vf_rep_desc *vf_rep;
	struct lio_vf_rep_req rep_cfg;
	struct octeon_device *oct;
	int ret;

	switch (event) {
	case NETDEV_REGISTER:
	case NETDEV_CHANGENAME:
		break;

	default:
		return NOTIFY_DONE;
	}

	if (ndev->netdev_ops != &lio_vf_rep_ndev_ops)
		return NOTIFY_DONE;

	vf_rep = netdev_priv(ndev);
	oct = vf_rep->oct;

	if (strlen(ndev->name) > LIO_IF_NAME_SIZE) {
		dev_err(&oct->pci_dev->dev,
			"Device name change sync failed as the size is > %d\n",
			LIO_IF_NAME_SIZE);
		return NOTIFY_DONE;
	}

	memset(&rep_cfg, 0, sizeof(rep_cfg));
	rep_cfg.req_type = LIO_VF_REP_REQ_DEVNAME;
	rep_cfg.ifidx = vf_rep->ifidx;
	strncpy(rep_cfg.rep_name.name, ndev->name, LIO_IF_NAME_SIZE);

	ret = lio_vf_rep_send_soft_command(oct, &rep_cfg,
					   sizeof(rep_cfg), NULL, 0);
	if (ret)
		dev_err(&oct->pci_dev->dev,
			"vf_rep netdev name change failed with err %d\n", ret);

	return NOTIFY_DONE;
}

static struct notifier_block lio_vf_rep_netdev_notifier = {
	.notifier_call = lio_vf_rep_netdev_event,
};

int
lio_vf_rep_modinit(void)
{
	if (register_netdevice_notifier(&lio_vf_rep_netdev_notifier)) {
		pr_err("netdev notifier registration failed\n");
		return -EFAULT;
	}

	return 0;
}

void
lio_vf_rep_modexit(void)
{
	if (unregister_netdevice_notifier(&lio_vf_rep_netdev_notifier))
		pr_err("netdev notifier unregister failed\n");
}
#endif
