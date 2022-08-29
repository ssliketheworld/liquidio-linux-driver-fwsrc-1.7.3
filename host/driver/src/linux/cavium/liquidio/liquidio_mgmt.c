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
#include <linux/version.h>
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

/* VSW specific opcodes. these should match with those in cvmcs-vsw-msg.h */
#define OPCODE_VSW_HOST_COMM_PKT_DATA   0x10

static struct net_device *netdev;
struct lio_mgmt {
	atomic_t ifstate;
	struct tasklet_struct rx_tasklet;
	struct list_head rx_pkts_list;
	struct net_device *parent_netdev;
	struct octeon_device *oct_dev;
	struct net_device *netdev;
	u64 dev_capability;
	u64 enc_dev_capability;
	struct oct_link_info linfo;
	u32 intf_open;
};

struct lio_mgmt_rx_pkt {
	struct list_head list;
	struct sk_buff *skb;
};

#define LIO_MGMT_SIZE (sizeof(struct lio_mgmt))
#define GET_LIO_MGMT(netdev)  ((struct lio_mgmt *)netdev_priv(netdev))

/* Bit mask values for lio->ifstate */
#define   LIO_IFSTATE_DROQ_OPS             0x01
#define   LIO_IFSTATE_REGISTERED           0x02
#define   LIO_IFSTATE_RUNNING              0x04

/**
 * \brief Stop Tx queues
 * @param netdev network device
 */
static inline void txqs_stop(struct net_device *netdev)
{
	if (netif_is_multiqueue(netdev)) {
		int i;

		for (i = 0; i < netdev->real_num_tx_queues; i++)
			netif_stop_subqueue(netdev, i);
	} else {
		netif_stop_queue(netdev);
	}
}

/**
 * \brief Start Tx queues
 * @param netdev network device
 */
static inline void txqs_start(struct net_device *netdev)
{
	if (netif_is_multiqueue(netdev)) {
		int i;

		for (i = 0; i < netdev->real_num_tx_queues; i++)
			netif_start_subqueue(netdev, i);
	} else {
		netif_start_queue(netdev);
	}
}

/**
 * \brief Stop Tx queue
 * @param netdev network device
 */
static void stop_txq(struct net_device *netdev)
{
	txqs_stop(netdev);
}

/**
 * \brief Start Tx queue
 * @param netdev network device
 */
static void start_txq(struct net_device *netdev)
{
	txqs_start(netdev);
}

static int lio_mgmt_open(struct net_device *netdev)
{
	struct lio_mgmt *lio_mgmt = GET_LIO_MGMT(netdev);

	ifstate_set((struct lio *)lio_mgmt, LIO_IFSTATE_RUNNING);
	netif_carrier_on(netdev);

	start_txq(netdev);

	/* Ready for link status updates */
	lio_mgmt->intf_open = 1;

	return 0;
}

/**
 * \brief Net device stop for LiquidIO
 * @param netdev network device
 */
static int lio_mgmt_stop(struct net_device *netdev)
{
	struct lio_mgmt *lio_mgmt = GET_LIO_MGMT(netdev);

	ifstate_reset((struct lio *)lio_mgmt, LIO_IFSTATE_RUNNING);

	netif_tx_disable(netdev);

	/* Inform that netif carrier is down */
	netif_carrier_off(netdev);
	lio_mgmt->intf_open = 0;

	return 0;
}

static void packet_sent_callback(struct octeon_device *oct,
				 u32 status, void *buf)
{
	struct octeon_soft_command *sc = (struct octeon_soft_command *)buf;
	struct sk_buff *skb = sc->ctxptr;

	dma_unmap_single(&oct->pci_dev->dev, sc->dmadptr,
			 sc->datasize, DMA_TO_DEVICE);
	dev_kfree_skb_any(skb);
	kfree(sc);
}

/** \brief Transmit networks packets to the Octeon interface
 * @param skbuff   skbuff struct to be passed to network layer.
 * @param netdev    pointer to network device
 * @returns whether the packet was transmitted to the device okay or not
 *             (NETDEV_TX_OK or NETDEV_TX_BUSY)
 */
static int lio_mgmt_xmit(struct sk_buff *skb, struct net_device *netdev)
{
	struct lio_mgmt *lio_mgmt;
	struct lio *parent_lio;
	struct octeon_soft_command *sc;
	int status;
	struct octeon_instr_pki_ih3 *pki_ih3;

	lio_mgmt = GET_LIO_MGMT(netdev);
	parent_lio = GET_LIO(lio_mgmt->parent_netdev);

	/* Check for all conditions in which the current packet cannot be
	 * transmitted.
	 */
	if (!(atomic_read(&lio_mgmt->ifstate) & LIO_IFSTATE_RUNNING) ||
	    (skb->len <= 0)) {
		goto lio_xmit_failed;
	}

	if (octnet_iq_is_full(lio_mgmt->oct_dev, parent_lio->txq)) {
		/* defer sending if queue is full */
		return NETDEV_TX_BUSY;
	}

	sc = kzalloc(sizeof(*sc), GFP_ATOMIC);
	if (!sc)
		goto lio_xmit_failed;

	if (skb_shinfo(skb)->nr_frags == 0) {
		sc->dmadptr = dma_map_single(&lio_mgmt->oct_dev->pci_dev->dev,
					     skb->data,
					     skb->len, DMA_TO_DEVICE);
		if (dma_mapping_error
		    (&lio_mgmt->oct_dev->pci_dev->dev, sc->dmadptr)) {
			return NETDEV_TX_BUSY;
		}
		sc->virtdptr = skb->data;
		sc->datasize = skb->len;
		sc->ctxptr = skb;	/* to be freed in sent callback */
		sc->dmarptr = 0;
		sc->rdatasize = 0;
		sc->iq_no = parent_lio->txq;	/* default input queue */
		octeon_prepare_soft_command(lio_mgmt->oct_dev, sc, OPCODE_OVS,
					    OPCODE_VSW_HOST_COMM_PKT_DATA, 0, 0,
					    0);

		/*prepare softcommand uses ATOMIC TAG, change it to ORDERED */
		pki_ih3 = (struct octeon_instr_pki_ih3 *)&sc->cmd.cmd3.pki_ih3;
		pki_ih3->tag = LIO_DATA((lio_mgmt->oct_dev->instr_queue
					[sc->iq_no]->txpciq.s.port));
		pki_ih3->tagtype = ORDERED_TAG;

		if (lio_mgmt->oct_dev->instr_queue[sc->iq_no]->octlinux_uqpg) {
			pki_ih3->uqpg = lio_mgmt->oct_dev->
				instr_queue[sc->iq_no]->octlinux_uqpg;
			pki_ih3->qpg = lio_mgmt->oct_dev->
				instr_queue[sc->iq_no]->octlinux_qpg;
		}

		sc->callback = packet_sent_callback;
		sc->callback_arg = sc;
		status = octeon_send_soft_command(lio_mgmt->oct_dev, sc);
		if (status == IQ_SEND_FAILED) {
			dma_unmap_single(&lio_mgmt->oct_dev->pci_dev->dev,
					 sc->dmadptr, sc->datasize,
					 DMA_TO_DEVICE);
			kfree(sc);
			goto lio_xmit_failed;
		}

		if (status == IQ_SEND_STOP)
			stop_txq(netdev);
	} else {
		kfree(sc);
		goto lio_xmit_failed;
	}

	netdev->stats.tx_packets++;
	netdev->stats.tx_bytes += skb->len;

	return NETDEV_TX_OK;

lio_xmit_failed:
	netdev->stats.tx_dropped++;
	dev_kfree_skb_any(skb);
	return NETDEV_TX_OK;
}

static void rx_tasklet(unsigned long data)
{
	struct net_device *netdev = (struct net_device *)(data);
	struct lio_mgmt *lio_mgmt = GET_LIO_MGMT(netdev);
	struct lio_mgmt_rx_pkt *rxpkt, *tmp;

	list_for_each_entry_safe(rxpkt, tmp, &lio_mgmt->rx_pkts_list, list) {
		netif_rx(rxpkt->skb);
		list_del(&rxpkt->list);
		kfree(rxpkt);
	}
}

static int lio_mgmt_rx(struct octeon_recv_info *recv_info, void *buf)
{
	struct octeon_recv_pkt *recv_pkt = recv_info->recv_pkt;
	struct sk_buff *skb;
	struct lio_mgmt *lio_mgmt = GET_LIO_MGMT(netdev);
	unsigned int pkt_size = 0;
	unsigned char *pkt_ptr;
	struct lio_mgmt_rx_pkt *rxpkt;
	int i;

	/* Do not proceed if the interface is not in RUNNING state. */
	if (!ifstate_check((struct lio *)lio_mgmt, LIO_IFSTATE_RUNNING)) {
		for (i = 0; i < recv_pkt->buffer_count; i++)
			recv_buffer_free(recv_pkt->buffer_ptr[i]);

		octeon_free_recv_info(recv_info);
		return 0;
	}

#if (OCTEON_OQ_INFOPTR_MODE)
	pkt_size = recv_pkt->buffer_size[0];
	pkt_ptr = get_rbd(recv_pkt->buffer_ptr[0]);
#else
	pkt_size = recv_pkt->buffer_size[0] - OCT_DROQ_INFO_SIZE;
	pkt_ptr = get_rbd(recv_pkt->buffer_ptr[0]) + OCT_DROQ_INFO_SIZE; 
#endif

	skb = netdev_alloc_skb_ip_align(netdev, pkt_size);
	if (likely(skb))
		skb_copy_to_linear_data(skb, pkt_ptr, pkt_size);

	skb_put(skb, pkt_size);
	netdev->stats.rx_packets++;
	netdev->stats.rx_bytes += skb->len;

	skb->dev = netdev;
	skb->protocol = eth_type_trans(skb, skb->dev);
	/* checksum has already been verified */
	skb->ip_summed = CHECKSUM_UNNECESSARY;

	rxpkt = kmalloc(sizeof(*rxpkt), GFP_ATOMIC);
	if (rxpkt) {
		INIT_LIST_HEAD(&rxpkt->list);
		rxpkt->skb = skb;
		list_add_tail(&rxpkt->list, &lio_mgmt->rx_pkts_list);
	}

	tasklet_schedule(&lio_mgmt->rx_tasklet);

	for (i = 0; i < recv_pkt->buffer_count; i++)
		recv_buffer_free(recv_pkt->buffer_ptr[i]);

	octeon_free_recv_info(recv_info);
	return 0;
}

const struct net_device_ops liocomdevops = {
	.ndo_open = lio_mgmt_open,
	.ndo_stop = lio_mgmt_stop,
	.ndo_start_xmit = lio_mgmt_xmit,
};

static int __lio_mgmt_init(struct octeon_device *octdev)
{
	struct lio_mgmt *lio_mgmt = NULL;
	struct lio *parent_lio;

	/* Register netdev only for pf 0 */
	if (octdev->pf_num == 0) {
		netdev = alloc_etherdev(LIO_MGMT_SIZE);
		if (!netdev) {
			dev_err(&octdev->pci_dev->dev, "Mgmt: Device allocation failed\n");
			goto nic_dev_fail;
		}

		/* SET_NETDEV_DEV(netdev, &octdev->pci_dev->dev); */
		netdev->netdev_ops = &liocomdevops;

		lio_mgmt = GET_LIO_MGMT(netdev);
		memset(lio_mgmt, 0, LIO_MGMT_SIZE);
		lio_mgmt->oct_dev = octdev;

		/*use ifidx zero of pf */
		lio_mgmt->parent_netdev = octdev->props[0].netdev;
		parent_lio = GET_LIO(lio_mgmt->parent_netdev);

		lio_mgmt->dev_capability = NETIF_F_HIGHDMA
		    | NETIF_F_IP_CSUM | NETIF_F_IPV6_CSUM | NETIF_F_RXCSUM;
		lio_mgmt->enc_dev_capability = NETIF_F_IP_CSUM
		    | NETIF_F_IPV6_CSUM | NETIF_F_HW_CSUM | NETIF_F_RXCSUM;

		netdev->vlan_features = lio_mgmt->dev_capability;
		netdev->features = lio_mgmt->dev_capability;
#if  LINUX_VERSION_CODE >= KERNEL_VERSION(3, 0, 0)
		netdev->hw_features = lio_mgmt->dev_capability;
#endif

		lio_mgmt->linfo = parent_lio->linfo;

		eth_hw_addr_random(netdev);
	}
	if (octdev->pf_num == 0) {
		char name[IFNAMSIZ];
		int dev_id, fn;

		tasklet_init(&lio_mgmt->rx_tasklet, rx_tasklet, (u64)netdev);
		INIT_LIST_HEAD(&lio_mgmt->rx_pkts_list);

		dev_id = (octdev->pci_dev->devfn & 0xff) >> 3;
		fn = octdev->pci_dev->devfn & 0x7;

		if (fn) {
			snprintf(name, IFNAMSIZ, "lio-p%ds%df%d-mgmt",
				 octdev->pci_dev->bus->number, dev_id, fn);
		} else {
			snprintf(name, IFNAMSIZ, "lio-p%ds%d-mgmt",
				 octdev->pci_dev->bus->number, dev_id);
		}

		strncpy(netdev->name, name, sizeof(netdev->name) - 1);

		/* Register the network device with the OS */
		if (register_netdev(netdev)) {
			dev_err(&octdev->pci_dev->dev, "Mgmt: Device registration failed\n");
			goto nic_dev_fail;
		}

		netif_carrier_on(netdev);
		ifstate_set((struct lio *)lio_mgmt, LIO_IFSTATE_REGISTERED);
		/*  Register RX dispatch function */
		if (octeon_register_dispatch_fn(octdev, OPCODE_OVS,
						OPCODE_VSW_HOST_COMM_PKT_DATA,
						lio_mgmt_rx, octdev)) {
			goto nic_dev_fail;
		}
	}

	return 0;

nic_dev_fail:
	if (netdev) {
		struct lio_mgmt *lio_mgmt = GET_LIO_MGMT(netdev);

		if (atomic_read(&lio_mgmt->ifstate) &
		    LIO_IFSTATE_REGISTERED)
			unregister_netdev(netdev);

		free_netdev(netdev);
		netdev = NULL;
	}

	netdev = NULL;
	return -ENOMEM;
}

static void __lio_mgmt_exit(void)
{
	pr_info("LiquidIO Communication module is now unloaded\n");

	if (netdev) {
		struct lio_mgmt *lio_mgmt = GET_LIO_MGMT(netdev);

		if (atomic_read(&lio_mgmt->ifstate) & LIO_IFSTATE_RUNNING)
			txqs_stop(netdev);

		if (atomic_read(&lio_mgmt->ifstate) &
		    LIO_IFSTATE_REGISTERED)
			unregister_netdev(netdev);

		free_netdev(netdev);
		netdev = NULL;
	}
}


int lio_mgmt_init(struct octeon_device *octdev)
{
	return __lio_mgmt_init(octdev);
}

void lio_mgmt_exit(void)
{
	__lio_mgmt_exit();
}

