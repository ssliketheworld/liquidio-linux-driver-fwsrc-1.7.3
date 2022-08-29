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
/*! \file octeon_main.h
 *  \brief Host Driver: This file is included by all host driver source files
 *  to include common definitions.
 */

#ifndef _OCTEON_MAIN_H_
#define  _OCTEON_MAIN_H_

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0)
#include <linux/sched/signal.h>
#endif

#if BITS_PER_LONG == 32
#define CVM_CAST64(v) ((long long)(v))
#elif BITS_PER_LONG == 64
#define CVM_CAST64(v) ((long long)(long)(v))
#else
#error "Unknown system architecture"
#endif

#define DRV_NAME "LiquidIO"

struct octeon_device_priv {
	/** Tasklet structures for this device. */
	struct tasklet_struct droq_tasklet;
	unsigned long napi_mask;
};

/** This structure is used by NIC driver to store information required
 * to free the sk_buff when the packet has been fetched by Octeon.
 * Bytes offset below assume worst-case of a 64-bit system.
 */
struct octnet_buf_free_info {
	/** Bytes 1-8.  Pointer to network device private structure. */
	struct lio *lio;

	/** Bytes 9-16.  Pointer to sk_buff. */
	struct sk_buff *skb;

	/** Bytes 17-24.  Pointer to gather list. */
	struct octnic_gather *g;

	/** Bytes 25-32. Physical address of skb->data or gather list. */
	u64 dptr;

	/** Bytes 33-47. Piggybacked soft command, if any */
	struct octeon_soft_command *sc;
};

/* BQL-related functions */
int octeon_report_sent_bytes_to_bql(void *buf, int reqtype);
void octeon_update_tx_completion_counters(void *buf, int reqtype,
					  unsigned int *pkts_compl,
					  unsigned int *bytes_compl);
void octeon_report_tx_completion_to_bql(void *txq, unsigned int pkts_compl,
					unsigned int bytes_compl);
void octeon_pf_changed_vf_macaddr(struct octeon_device *oct, u8 *mac);

void octeon_pf_set_or_cleared_vf_vlan(struct octeon_device *oct,
				      bool v_was_set);

void octeon_schedule_rxq_oom_work(struct octeon_device *oct,
				  struct octeon_droq *droq);

/** Swap 8B blocks */
static inline void octeon_swap_8B_data(u64 *data, u32 blocks)
{
	while (blocks) {
		cavium_cpu_to_be64s(data);
		blocks--;
		data++;
	}
}

/**
 * \brief unmaps a PCI BAR
 * @param oct Pointer to Octeon device
 * @param baridx bar index
 */
static inline void octeon_unmap_pci_barx(struct octeon_device *oct, int baridx)
{
	lio_dev_dbg(oct, "Freeing PCI mapped regions for Bar%d\n",
		    baridx);

	if (oct->mmio[baridx].done)
		iounmap(oct->mmio[baridx].hw_addr);

	if (oct->mmio[baridx].start)
		pci_release_region(oct->pci_dev, baridx * 2);
}

/**
 * \brief maps a PCI BAR
 * @param oct Pointer to Octeon device
 * @param baridx bar index
 * @param max_map_len maximum length of mapped memory
 */
static inline int octeon_map_pci_barx(struct octeon_device *oct,
				      int baridx, int max_map_len)
{
	u32 mapped_len = 0;

	if (pci_request_region(oct->pci_dev, baridx * 2, DRV_NAME)) {
		lio_dev_err(oct, "pci_request_region failed for bar %d\n",
			    baridx);
		return 1;
	}

	oct->mmio[baridx].start = pci_resource_start(oct->pci_dev, baridx * 2);
	oct->mmio[baridx].len = pci_resource_len(oct->pci_dev, baridx * 2);

	mapped_len = oct->mmio[baridx].len;
	if (!mapped_len)
		goto err_release_region;

	if (max_map_len && (mapped_len > max_map_len))
		mapped_len = max_map_len;

	oct->mmio[baridx].hw_addr =
		ioremap(oct->mmio[baridx].start, mapped_len);
	oct->mmio[baridx].mapped_len = mapped_len;

	lio_dev_dbg(oct, "BAR%d start: 0x%llx mapped %u of %u bytes\n",
		    baridx, oct->mmio[baridx].start, mapped_len,
		    oct->mmio[baridx].len);

	if (!oct->mmio[baridx].hw_addr) {
		lio_dev_err(oct, "error ioremap for bar %d\n",
			    baridx);
		goto err_release_region;
	}
	oct->mmio[baridx].done = 1;

	return 0;

err_release_region:
	pci_release_region(oct->pci_dev, baridx * 2);
	return 1;
}

static inline void *
cnnic_numa_alloc_aligned_dma(u32 size,
			     u32 *alloc_size,
			     size_t *orig_ptr,
			     int numa_node)
{
	int retries = 0;
	void *ptr = NULL;

#define OCTEON_MAX_ALLOC_RETRIES     1
	do {
		struct page *page = NULL;

		page = alloc_pages_node(numa_node,
					GFP_KERNEL,
					get_order(size));
		if (!page)
			page = alloc_pages(GFP_KERNEL,
					   get_order(size));
		ptr = (void *)page_address(page);
		if ((unsigned long)ptr & 0x07) {
			__free_pages(page, get_order(size));
			ptr = NULL;
			/* Increment the size required if the first
			 * attempt failed.
			 */
			if (!retries)
				size += 7;
		}
		retries++;
	} while ((retries <= OCTEON_MAX_ALLOC_RETRIES) && !ptr);

	*alloc_size = size;
	*orig_ptr = (unsigned long)ptr;
	if ((unsigned long)ptr & 0x07)
		ptr = (void *)(((unsigned long)ptr + 7) & ~(7UL));
	return ptr;
}

#define cnnic_free_aligned_dma(pci_dev, ptr, size, orig_ptr, dma_addr) \
		free_pages(orig_ptr, get_order(size))

static inline int
cavium_iq_to_node(struct octeon_device *oct, int iq_no UNUSED)
{
	return cavium_dev_to_node(&oct->pci_dev->dev);
}

static inline int
cavium_droq_to_node(struct octeon_device *oct,
		    int droq_no UNUSED)
{
	return cavium_dev_to_node(&oct->pci_dev->dev);
}

static inline int
cavium_sleep_cond(cavium_wait_channel *wait_queue, int *condition)
{
	int errno = 0;
	cavium_wait_entry we;

	cavium_init_wait_entry(&we, current);
	cavium_add_to_waitq(wait_queue, &we);
	while (!(cavium_read_once(*condition))) {
		set_current_state(TASK_INTERRUPTIBLE);
		if (signal_pending(current)) {
			errno = -EINTR;
			goto out;
		}
		schedule();
	}

	if (*condition == OCTEON_REQUEST_TIMEOUT) {
		*condition = 0;
		errno = -EINTR;
		//errno = -ETIMEDOUT;
	} else {
		*condition = 1;
	}
out:
	set_current_state(TASK_RUNNING);
	cavium_remove_from_waitq(wait_queue, &we);
	return errno;
}

/* Gives up the CPU for a timeout period.
 * Check that the condition is not true before we go to sleep for a
 * timeout period.
 */
static inline void
cavium_sleep_timeout_cond(cavium_wait_channel *wait_queue,
		   int *condition,
		   int timeout)
{
	cavium_wait_entry we;

	cavium_init_wait_entry(&we, current);
	cavium_add_to_waitq(wait_queue, &we);
	set_current_state(TASK_INTERRUPTIBLE);
	if (!(*condition))
		schedule_timeout(timeout);
	set_current_state(TASK_RUNNING);
	cavium_remove_from_waitq(wait_queue, &we);
}

/*
 * input parameter:
 * condition: contain status set by a callback function 
 *     which is the status passed by lio_process_ordered_list.
 * timeout: milli sec which an application wants to wait for the response of the request.
 *          0: the request will wait until its response gets back from the firmware within 
 *             LIO_SC_MAX_TMO_MS milli sec. It the response does not return within 
 *             LIO_SC_MAX_TMO_MS milli sec, lio_process_ordered_list() will move the request
 *	       to zombie response list.
 *
 * return value: 
 * 0: got the response from firmware for the sc request.
 * errno -EINTR: user abort the command. 
 * errno -ETIME: user spefified timeout value has been expired.
 * errno -EBUSY: the response of the request does not return in resonable time (LIO_SC_MAX_TMO_MS).
 *       the sc wll be move to zombie response list by lio_process_ordered_list()
 *
 * A request with non-zero return value, the sc will be marked with CALLER_DONE_BIT.
 * When getting a request with zero return value, the requestor should mark sc with 
 * CALLER_DONE_BIT after examing the response of sc. 
 * lio_process_ordered_list() will free the soft command on behalf of the soft command requestor.
 * This is to fix the possible race condition of both timeout process and 
 * lio_process_ordered_list()/callback function to free a sc strucutre.
 */
static inline int
cavium_sleep_cond_timeout(struct octeon_device *oct_dev, struct octeon_soft_command *sc, unsigned long timeout)
{
	int errno = 0;
	long timeout_jiff;
	
	if (timeout) {
		timeout_jiff = cavium_msecs_to_jiffies(timeout);
	} else
		timeout_jiff = MAX_SCHEDULE_TIMEOUT;

	if ((timeout_jiff = wait_for_completion_interruptible_timeout(&sc->complete, timeout_jiff)) == 0) 
	{
		lio_dev_err(oct_dev, "%s: sc is timeout\n", __FUNCTION__);
		cavium_set_bit(CALLER_DONE_BIT, &sc->done);
                errno = -ETIME;
        } else if (timeout_jiff == -ERESTARTSYS) {
		lio_dev_err(oct_dev, "%s: sc is interrupted\n", __FUNCTION__);
		cavium_set_bit(CALLER_DONE_BIT, &sc->done);
		errno = -EINTR;
	} else  if (sc->sc_status == OCTEON_REQUEST_TIMEOUT) {
		lio_dev_err(oct_dev, "%s: sc has fatal timeout\n", __FUNCTION__);
		cavium_set_bit(CALLER_DONE_BIT, &sc->done);
		errno = -EBUSY;
	}

	return errno;
}

#ifndef ROUNDUP4
#define ROUNDUP4(val) (((val) + 3) & 0xfffffffc)
#endif

#ifndef ROUNDUP8
#define ROUNDUP8(val) (((val) + 7) & 0xfffffff8)
#endif

#ifndef ROUNDUP16
#define ROUNDUP16(val) (((val) + 15) & 0xfffffff0)
#endif

#ifndef ROUNDUP128
#define ROUNDUP128(val) (((val) + 127) & 0xffffff80)
#endif

#if  LINUX_VERSION_CODE < KERNEL_VERSION(3, 13, 0)
#define BIT_ULL(nr)                (1ULL << (nr))
#endif

/* Initializes the LiquidIO management interface module
 *  * @param octdev - octeon device pointer
 *   * @returns 0 if init is success, -1 otherwise
 *    */
int lio_mgmt_init(struct octeon_device *octdev);

/* De-initializes the LiquidIO management interface module */
void lio_mgmt_exit(void);

#endif /* _OCTEON_MAIN_H_ */
