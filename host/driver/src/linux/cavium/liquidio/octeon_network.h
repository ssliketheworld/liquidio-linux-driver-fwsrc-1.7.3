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
 **********************************************************************/
/*!  \file  octeon_network.h
 *   \brief Host NIC Driver: Structure and Macro definitions used by NIC Module.
 */

#ifndef __OCTEON_NETWORK_H__
#define __OCTEON_NETWORK_H__
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 0, 0)) ||  (RHEL_RELEASE_CODE >= 1541)
#include <linux/ptp_clock_kernel.h>
#endif

#ifdef CONFIG_DCB
#include "liquidio_common_dcb.h"
#include "lio_dcb_main.h"
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 10, 0)
#include <linux/if_ether.h>

#define LIO_MIN_MTU_SIZE ETH_MIN_MTU
#else
#define LIO_MIN_MTU_SIZE 68
#endif
#define LIO_MAX_MTU_SIZE (OCTNET_MAX_FRM_SIZE - OCTNET_FRM_HEADER_SIZE)

/* Bit mask values for lio->ifstate */
#define   LIO_IFSTATE_DROQ_OPS             0x01
#define   LIO_IFSTATE_REGISTERED           0x02
#define   LIO_IFSTATE_RUNNING              0x04
#define   LIO_IFSTATE_RX_TIMESTAMP_ENABLED 0x08
#define   LIO_IFSTATE_RESETTING	   0x10

struct liquidio_if_cfg_context {
	int octeon_id;
	cavium_wait_channel wc;
	int cond;
};

struct liquidio_if_cfg_resp {
	u64 rh;
	struct liquidio_if_cfg_info cfg_info;
	u64 status;
};

#define LIO_IFCFG_WAIT_TIME	3000 /* In milli seconds */
#define LIQUIDIO_NDEV_STATS_POLL_TIME_MS 200

/** Structure of a node in list of gather components maintained by
 * NIC driver for each network device.
 */
struct octnic_gather {
	/** List manipulation. Next and prev pointers. */
	struct list_head list;

	/** Size of the gather component at sg in bytes. */
	int sg_size;

	/** Number of bytes that sg was adjusted to make it 8B-aligned. */
	int adjust;

	/** Gather component that can accommodate max sized fragment list
	 *  received from the IP layer.
	 */
	struct octeon_sg_entry *sg;

	u64 sg_dma_ptr;
};

struct oct_nic_stats_resp {
	u64     rh;
	struct oct_link_stats stats;
	u64     status;
};

struct oct_nic_vf_stats_resp {
	u64     rh;
	u64	spoofmac_cnt;
	u64     status;
};

struct oct_nic_stats_ctrl {
	struct completion complete;
	struct net_device *netdev;
};

/* IPv6 extension header types */
enum {
	IPV6_EXTH_HOH = 0,      /* Hop-by-Hop Options */
	IPV6_EXTH_TCP = 6,      /* TCP */
	IPV6_EXTH_UDP = 17,     /* UDP */
	IPV6_EXTH_ROUTING = 43, /* Routing Header */
	IPV6_EXTH_FRAG = 44,    /* Fragment header */
	IPV6_EXTH_ESP = 50,     /* Encapsulation security payload Header */
	IPV6_EXTH_AH = 51,      /* Authentication Header */
	IPV6_EXTH_ICMP = 58,    /* ICMPv6 */
	IPV6_EXTH_NNH = 59,     /* No Next header */
	IPV6_EXTH_DEST_OPT = 60,/* Destination Options */
	IPV6_EXTH_MOBILITY = 135/* Mobility Header */
};

struct lio_skb_info {
	u8 is_ipv4;
	u8 is_opt;
	u8 is_ipv6;
	u8 is_exthdr;
	u8 is_frag;
	u8 is_tcp;
	u8 is_udp;
	u16 l2_off;
	u16 l3_off;
	u16 l4_off;
};

#ifdef CONFIG_DCB
/* octeon_dcb data structure
 * @dcb_cap:dcb capability structure.
 * @dcbx_version: DCBX Version
 * @dcbx_ieee_cmd: Local configuration for IEEE_DCBX
 * @dcbx_cee_cmd: Local configuration for CEE_DCBX
 * @dcbx_info: dcb configuration per port basis sent by fw.
 * @dcb_state:dcb on/off firmware support flag .
 * @qcn_state:qcn on/off firmware support flag .
 * @num_tc: Number of tcs
 * @prio_to_tc: Priority to traffic class map
 * @tc_to_txq: Traffic class to Tx queue map
 * @dcb_reconfig_wq : Work queue to post reconfig notifications ti stack
 */
struct octeon_dcb {
	struct oct_nic_dcb_cap		dcb_cap;
	u8				dcbx_version;
	struct oct_nic_dcbx_cmd		dcbx_ieee_cmd;
	struct oct_nic_dcbx_cmd		dcbx_cee_cmd;
	struct oct_nic_dcbx_info	dcbx_info;
	atomic_t			dcb_state;
	atomic_t			qcn_state;
#if (LINUX_VERSION_CODE < KERNEL_VERSION(3, 0, 0))
	u8				num_tc;
	u8				prio_to_tc[MAX_PRIORITY];
	u8				tc_to_txq[MAX_NUM_TC];
#endif
	struct 	cavium_wq 		dcb_info_wq;
};
#endif

/** LiquidIO per-interface network private data */
struct lio {
	/** State of the interface. Rx/Tx happens only in the RUNNING state.  */
	atomic_t ifstate;

	/** Octeon Interface index number. This device will be represented as
	 *  oct<ifidx> in the system.
	 */
	int ifidx;

	/** Octeon Input queue to use to transmit for this network interface. */
	int txq;

	/** Octeon Output queue from which pkts arrive
	 * for this network interface.
	 */
	int rxq;

	/** Guards each glist */
	cavium_spinlock_t *glist_lock;

	/** Array of gather component linked lists */
	struct list_head *glist;
	void **glists_virt_base;
	cavium_dma_addr_t *glists_dma_base;
	u32 glist_entry_size;

	/** Pointer to the NIC properties for the Octeon device this network
	 *  interface is associated with.
	 */
	struct octdev_props *octprops;

	/** Pointer to the octeon device structure. */
	struct octeon_device *oct_dev;

	struct net_device *netdev;

	/** Link information sent by the core application for this interface. */
	struct oct_link_info linfo;

	/** counter of link changes */
	u64 link_changes;

	/** Size of Tx queue for this octeon device. */
	u32 tx_qsize;

	/** Size of Rx queue for this octeon device. */
	u32 rx_qsize;

	/** Size of MTU this octeon device. */
	u32 mtu;

	/** msg level flag per interface. */
	u32 msg_enable;

	/** Copy of Interface capabilities: TSO, TSO6, LRO, Chescksums . */
	u64 dev_capability;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
	/* Copy of transmit encapsulation capabilities:
	 * TSO, TSO6, Checksums for this device for Kernel
	 * 3.10.0 onwards
	 */
	u64 enc_dev_capability;
#endif

	/** Copy of beacaon reg in phy */
	u32 phy_beacon_val;

	/** Copy of ctrl reg in phy */
	u32 led_ctrl_val;

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 0, 0)) ||  (RHEL_RELEASE_CODE >= 1541)
	/* PTP clock information */
	struct ptp_clock_info ptp_info;
	struct ptp_clock *ptp_clock;
#endif
	s64 ptp_adjust;

	/* for atomic access to Octeon PTP reg and data struct */
	cavium_spinlock_t ptp_lock;

	/* Interface info */
	u32	intf_open;

	/* work queue for  txq status */
	struct cavium_wq	txq_status_wq;

	/* work queue for  rxq oom status */
	struct cavium_wq rxq_status_wq[MAX_POSSIBLE_OCTEON_OUTPUT_QUEUES];

	/* work queue for  link status */
	struct cavium_wq	link_status_wq;

	/* work queue to regularly send local time to octeon firmware */
	struct cavium_wq	sync_octeon_time_wq;

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 1, 0)

	struct vlan_group *vlgrp;
#endif
	int netdev_uc_count;
#ifdef CONFIG_DCB
	/* octeon_dcb structure */
	struct octeon_dcb  oct_dcb;
#endif
	struct cavium_wk stats_wk;
};

#define LIO_SIZE         (sizeof(struct lio))
#define GET_LIO(netdev)  ((struct lio *)netdev_priv(netdev))

#define LIO_MAX_CORES 16

/**
 * \brief Enable or disable feature
 * @param netdev    pointer to network device
 * @param cmd       Command that just requires acknowledgment
 * @param param1    Parameter to command
 */
int liquidio_set_feature(struct net_device *netdev, int cmd, u16 param1);

int setup_rx_oom_poll_fn(struct net_device *netdev);

void cleanup_rx_oom_poll_fn(struct net_device *netdev);

int liquidio_setup_io_queues(struct octeon_device *octeon_dev, int ifidx,
			     u32 num_iqs, u32 num_oqs);

cvm_intr_return_t liquidio_msix_intr_handler(
				int irq UNUSED, void *dev);

int octeon_setup_interrupt(struct octeon_device *oct, u32 num_ioqs);

void lio_fetch_stats(struct work_struct *work);

void lio_if_cfg_callback(struct octeon_device *oct,
			 u32 status UNUSED, void *buf);

void lio_delete_glists(struct octeon_device *oct, struct lio *lio);

int lio_setup_glists(struct octeon_device *oct, struct lio *lio, int num_qs);
/**
 * \brief Link control command completion callback
 * @param nctrl_ptr pointer to control packet structure
 *
 * This routine is called by the callback function when a ctrl pkt sent to
 * core app completes. The nctrl_ptr contains a copy of the command type
 * and data sent to the core app. This routine is only called if the ctrl
 * pkt was sent successfully to the core app.
 */
void liquidio_link_ctrl_cmd_completion(void *nctrl_ptr);

/**
 * \brief Register ethtool operations
 * @param netdev    pointer to network device
 */
void liquidio_set_ethtool_ops(struct net_device *netdev);

/**
 * \brief Net device change_mtu
 * @param netdev network device
 */
int liquidio_change_mtu(struct net_device *netdev, int new_mtu);
#define LIO_CHANGE_MTU_SUCCESS 1
#define LIO_CHANGE_MTU_FAIL    2

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 12, 0)) || (RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(7, 0))
#if (LINUX_VERSION_CODE < KERNEL_VERSION(3, 19, 0))
#define netdev_phys_item_id netdev_phys_port_id
#endif
int liquidio_get_phys_port_id(struct net_device *netdev,
			      struct netdev_phys_item_id *ppid);
#endif

#define SKB_ADJ_MASK  0x3F
#define SKB_ADJ       (SKB_ADJ_MASK + 1)

#ifndef CAVIUM_BYTE_ALLOC_RXBUFS
#define MIN_SKB_SIZE       256 /* 8 bytes and more - 8 bytes for PTP */
#define LIO_RXBUFFER_SZ    2048

static inline void
*recv_buffer_alloc(struct octeon_device *oct,
		   struct octeon_skb_page_info *pg_info)
{
	struct page *page;
	struct sk_buff *skb;
	struct octeon_skb_page_info *skb_pg_info;

	page = alloc_page(GFP_ATOMIC);
	if (unlikely(!page))
		return NULL;

	skb = dev_alloc_skb(MIN_SKB_SIZE + SKB_ADJ);
	if (unlikely(!skb)) {
		__free_page(page);
		pg_info->page = NULL;
		return NULL;
	}

	if ((unsigned long)skb->data & SKB_ADJ_MASK) {
		u32 r = SKB_ADJ - ((unsigned long)skb->data & SKB_ADJ_MASK);

		skb_reserve(skb, r);
	}

	skb_pg_info = ((struct octeon_skb_page_info *)(skb->cb));
	/* Get DMA info */
	pg_info->dma = dma_map_page(&oct->pci_dev->dev, page, 0,
				    PAGE_SIZE, DMA_FROM_DEVICE);

	/* Mapping failed!! */
	if (dma_mapping_error(&oct->pci_dev->dev, pg_info->dma)) {
		__free_page(page);
		dev_kfree_skb_any((struct sk_buff *)skb);
		pg_info->page = NULL;
		return NULL;
	}

	pg_info->page = page;
	pg_info->page_offset = 0;
	skb_pg_info->page = page;
	skb_pg_info->page_offset = 0;
	skb_pg_info->dma = pg_info->dma;

	return (void *)skb;
}

static inline void
*recv_buffer_fast_alloc(u32 size)
{
	struct sk_buff *skb;
	struct octeon_skb_page_info *skb_pg_info;

	skb = dev_alloc_skb(size + SKB_ADJ);
	if (unlikely(!skb))
		return NULL;

	if ((unsigned long)skb->data & SKB_ADJ_MASK) {
		u32 r = SKB_ADJ - ((unsigned long)skb->data & SKB_ADJ_MASK);

		skb_reserve(skb, r);
	}

	skb_pg_info = ((struct octeon_skb_page_info *)(skb->cb));
	skb_pg_info->page = NULL;
	skb_pg_info->page_offset = 0;
	skb_pg_info->dma = 0;

	return skb;
}

static inline int
recv_buffer_recycle(struct octeon_device *oct, void *buf)
{
	struct octeon_skb_page_info *pg_info = buf;

	if (!pg_info->page) {
		lio_dev_err(oct, "%s: pg_info->page NULL\n",
			    __CVM_FUNCTION__);
		return -ENOMEM;
	}

	if (unlikely(page_count(pg_info->page) != 1) ||
	    unlikely(page_to_nid(pg_info->page)	!= numa_node_id())) {
		dma_unmap_page(&oct->pci_dev->dev,
			       pg_info->dma, (PAGE_SIZE << 0),
			       DMA_FROM_DEVICE);
		pg_info->dma = 0;
		pg_info->page = NULL;
		pg_info->page_offset = 0;
		return -ENOMEM;
	}

	/* Flip to other half of the buffer */
	if (pg_info->page_offset == 0)
		pg_info->page_offset = LIO_RXBUFFER_SZ;
	else
		pg_info->page_offset = 0;
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4, 5, 0))
	page_ref_inc(pg_info->page);
#else
	atomic_inc(&pg_info->page->_count);
#endif

	return 0;
}

static inline void
*recv_buffer_reuse(struct octeon_device *oct, void *buf)
{
	struct octeon_skb_page_info *pg_info = buf, *skb_pg_info;
	struct sk_buff *skb;

	skb = dev_alloc_skb(MIN_SKB_SIZE + SKB_ADJ);
	if (unlikely(!skb)) {
		dma_unmap_page(&oct->pci_dev->dev,
			       pg_info->dma, (PAGE_SIZE << 0),
			       DMA_FROM_DEVICE);
		return NULL;
	}

	if ((unsigned long)skb->data & SKB_ADJ_MASK) {
		u32 r = SKB_ADJ - ((unsigned long)skb->data & SKB_ADJ_MASK);

		skb_reserve(skb, r);
	}

	skb_pg_info = ((struct octeon_skb_page_info *)(skb->cb));
	skb_pg_info->page = pg_info->page;
	skb_pg_info->page_offset = pg_info->page_offset;
	skb_pg_info->dma = pg_info->dma;

	return skb;
}

static inline void
recv_buffer_destroy(void *buffer, struct octeon_skb_page_info *pg_info)
{
	struct sk_buff *skb = (struct sk_buff *)buffer;

	put_page(pg_info->page);
	pg_info->dma = 0;
	pg_info->page = NULL;
	pg_info->page_offset = 0;

	if (skb)
		dev_kfree_skb_any(skb);
}

static inline void recv_buffer_free(void *buffer)
{
	struct sk_buff *skb = (struct sk_buff *)buffer;
	struct octeon_skb_page_info *pg_info;

	if (!skb)
		return;

	pg_info = ((struct octeon_skb_page_info *)(skb->cb));

	if (pg_info->page) {
		put_page(pg_info->page);
		pg_info->dma = 0;
		pg_info->page = NULL;
		pg_info->page_offset = 0;
	}

	dev_kfree_skb_any((struct sk_buff *)buffer);
}

static inline void
recv_buffer_fast_free(void *buffer)
{
	dev_kfree_skb_any((struct sk_buff *)buffer);
}

static inline void tx_buffer_free(void *buffer)
{
	dev_kfree_skb_any((struct sk_buff *)buffer);
}

#else

static inline void
*__recv_buffer_alloc(u32 size)
{
	struct sk_buff *skb = dev_alloc_skb(size + SKB_ADJ);

	if (skb && ((unsigned long)skb->data & SKB_ADJ_MASK)) {
		u32 r = SKB_ADJ - ((unsigned long)skb->data & SKB_ADJ_MASK);

		skb_reserve(skb, r);
	}

	return (void *)skb;
}

static inline void
*recv_buffer_alloc(struct octeon_device *oct UNUSED,
		   u32 q_no UNUSED, u32 size)
{
	return __recv_buffer_alloc(size);
}

static inline void recv_buffer_free(void *buffer)
{
	dev_kfree_skb_any((struct sk_buff *)buffer);
}

#endif
#define lio_dma_alloc(oct, name, q_no, size, dma_addr) \
	dma_alloc_coherent(&(oct)->pci_dev->dev, size, dma_addr, GFP_KERNEL)
#define lio_dma_free(oct, size, virt_addr, dma_addr) \
	dma_free_coherent(&(oct)->pci_dev->dev, size, virt_addr, dma_addr)

#if (OCTEON_OQ_INFOPTR_MODE)
static inline void *
lio_alloc_info_buffer(struct octeon_device *oct,
		      struct octeon_droq *droq)
{
	void *virt_ptr = NULL;

	virt_ptr = lio_dma_alloc(oct, "info_list", droq->q_no,
				 (droq->max_count * OCT_DROQ_INFO_SIZE),
				 (cavium_dma_addr_t *)&droq->info_list_dma);
	if (virt_ptr) {
		droq->info_alloc_size = droq->max_count * OCT_DROQ_INFO_SIZE;
		droq->info_base_addr = (size_t)virt_ptr;
	}
	return virt_ptr;
}

static inline void lio_free_info_buffer(struct octeon_device *oct,
					struct octeon_droq *droq)
{
	lio_dma_free(oct, droq->info_alloc_size, droq->info_base_addr,
		     droq->info_list_dma);
}
#endif

#ifndef CAVIUM_BYTE_ALLOC_RXBUFS
static inline
void *get_rbd(struct sk_buff *skb)
{
	struct octeon_skb_page_info *pg_info;
	unsigned char *va;

	pg_info = ((struct octeon_skb_page_info *)(skb->cb));
	va = page_address(pg_info->page) + pg_info->page_offset;

	return va;
}
#else
#define   get_rbd(ptr)      (((struct sk_buff *)(ptr))->data)
#endif

#if (OCTEON_OQ_INFOPTR_MODE)
static inline u64
lio_map_ring_info(struct octeon_droq *droq, u32 i)
{
	return (u64)droq->info_list_dma + (i * sizeof(struct octeon_droq_info));
}

static inline void
lio_unmap_ring_info(struct cavium_pci_device *pci_dev,
		    u64 info_ptr, u32 size)
{
}
#endif

static inline u64
#ifndef CAVIUM_BYTE_ALLOC_RXBUFS
lio_map_ring(void *buf)
#else
lio_map_ring(struct cavium_pci_device *pci_dev,
	     void *buf, u32 size)
#endif
{
	dma_addr_t dma_addr;

#ifndef CAVIUM_BYTE_ALLOC_RXBUFS
	struct sk_buff *skb = (struct sk_buff *)buf;
	struct octeon_skb_page_info *pg_info;

	pg_info = ((struct octeon_skb_page_info *)(skb->cb));
	if (!pg_info->page) {
		cavium_pr_err("%s: pg_info->page NULL\n", __CVM_FUNCTION__);
		BUG();
	}

	/* Get DMA info */
	dma_addr = pg_info->dma;
	if (!pg_info->dma) {
		cavium_pr_err("%s: ERROR it should be already available\n",
			      __CVM_FUNCTION__);
		BUG();
	}
	dma_addr += pg_info->page_offset;
#else
	dma_addr = dma_map_single(&pci_dev->dev, get_rbd(buf), size,
				  DMA_FROM_DEVICE);
	BUG_ON(dma_mapping_error(&pci_dev->dev, dma_addr));
#endif

	return (u64)dma_addr;
}

static inline void
#ifndef CAVIUM_BYTE_ALLOC_RXBUFS
lio_unmap_ring(struct cavium_pci_device *pci_dev,
	       u64 buf_ptr)
#else
lio_unmap_ring(struct cavium_pci_device *pci_dev,
	       u64 buf_ptr, u32 size, void *host_buf UNUSED)
#endif

{
#ifndef CAVIUM_BYTE_ALLOC_RXBUFS
	dma_unmap_page(&pci_dev->dev,
		       buf_ptr, (PAGE_SIZE << 0),
		       DMA_FROM_DEVICE);
#else
	dma_unmap_single(&pci_dev->dev,
			 buf_ptr, size,
			 DMA_FROM_DEVICE);
#endif
}

#ifndef CAVIUM_BYTE_ALLOC_RXBUFS
static inline void *octeon_fast_packet_alloc(u32 size)
#else
static inline void *octeon_fast_packet_alloc(struct octeon_device *oct UNUSED,
					     struct octeon_droq *droq UNUSED,
					     u32 q_no UNUSED, u32 size)
#endif
{
#ifndef CAVIUM_BYTE_ALLOC_RXBUFS
	return recv_buffer_fast_alloc(size);
#else
	return __recv_buffer_alloc(size);
#endif
}

static inline void octeon_fast_packet_next(struct octeon_droq *droq,
					   struct cavium_netbuf *nicbuf,
					   int copy_len,
					   int idx)
{
	cavium_memcpy(recv_buf_put(nicbuf, copy_len),
		      get_rbd(droq->recv_buf_list[idx].buffer), copy_len);
}

/**
 * \brief Stop Tx queues
 * @param netdev network device
 */
static inline void stop_txqs(struct net_device *netdev)
{
	int i;

	for (i = 0; i < netdev->real_num_tx_queues; i++)
		netif_stop_subqueue(netdev, i);
}

/**
 * \brief Wake Tx queues
 * @param netdev network device
 */
static inline void wake_txqs(struct net_device *netdev)
{
	struct lio *lio = GET_LIO(netdev);
	int i, qno;

	for (i = 0; i < netdev->real_num_tx_queues; i++) {
		qno = lio->linfo.txpciq[i % lio->oct_dev->num_iqs].s.q_no;
		if (__netif_subqueue_stopped(netdev, i)) {
			INCR_INSTRQUEUE_PKT_COUNT(lio->oct_dev, qno,
						  tx_restart, 1);
			netif_wake_subqueue(netdev, i);
		}
	}
}

/**
 * \brief Start Tx queues
 * @param netdev network device
 */
static inline void start_txqs(struct net_device *netdev)
{
	struct lio *lio = GET_LIO(netdev);
	int i;

	if (lio->linfo.link.s.link_up) {
		for (i = 0; i < netdev->real_num_tx_queues; i++)
			netif_start_subqueue(netdev, i);
		return;
	}
}

static inline int skb_iq(struct octeon_device *oct, struct sk_buff *skb)
{
	return skb->queue_mapping % oct->num_iqs;
}

/**
 * \brief check interface state
 * @param lio per-network private data
 * @param state_flag flag state to check
 */
static inline int ifstate_check(struct lio *lio, int state_flag)
{
	return cavium_atomic_read(&lio->ifstate) & state_flag;
}

/**
 * \brief set interface state
 * @param lio per-network private data
 * @param state_flag flag state to set
 */
static inline void ifstate_set(struct lio *lio, int state_flag)
{
	cavium_atomic_set(&lio->ifstate, (cavium_atomic_read(&lio->ifstate) |
					  state_flag));
}

/**
 * \brief clear interface state
 * @param lio per-network private data
 * @param state_flag flag state to clear
 */
static inline void ifstate_reset(struct lio *lio, int state_flag)
{
	cavium_atomic_set(&lio->ifstate, (cavium_atomic_read(&lio->ifstate) &
					  ~(state_flag)));
}

/**
 * \brief wait for all pending requests to complete
 * @param oct Pointer to Octeon device
 *
 * Called during shutdown sequence
 */
static inline int wait_for_pending_requests(struct octeon_device *oct)
{
	int i, pcount = 0;

	for (i = 0; i < MAX_IO_PENDING_PKT_COUNT; i++) {
		pcount = cavium_atomic_read(
		    &oct->response_list[OCTEON_ORDERED_SC_LIST]
			 .pending_req_count);
		if (pcount)
			cavium_sleep_timeout(CAVIUM_TICKS_PER_SEC / 10);
		else
			break;
	}

	if (pcount)
		return 1;

	return 0;
}

/**
 * Remove the node at the head of the list. The list would be empty at
 * the end of this call if there are no more nodes in the list.
 */
static inline struct list_head *lio_list_delete_head(struct list_head *root)
{
	struct list_head *node;

	if (root->prev == root && root->next == root)
		node = NULL;
	else
		node = root->next;

	if (node)
		CAVIUM_LIST_DEL(node);

	return node;
}
#endif
