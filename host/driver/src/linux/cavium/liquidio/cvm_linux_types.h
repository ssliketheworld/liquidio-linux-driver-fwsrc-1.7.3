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
#ifndef  __CVM_LINUX_TYPES_H__
#define  __CVM_LINUX_TYPES_H__

#include "cavium-list.h"


#define   __CVM_FILE__                   __FILE__

#ifndef PCI_VENDOR_ID_CAVIUM
#define PCI_VENDOR_ID_CAVIUM               0x177D
#endif

/* For non RedHat Kernel */
#ifndef RHEL_RELEASE_CODE
#define RHEL_RELEASE_CODE 0
#define RHEL_RELEASE_VERSION(A,B) 1
#endif

#define   __CVM_FUNCTION__               __FUNCTION__
#define   __CVM_LINE__                   __LINE__
#define   __CAVIUM_MEM_ATOMIC            GFP_ATOMIC
#define   __CAVIUM_MEM_GENERAL           GFP_KERNEL
#define   CAVIUM_PAGE_SIZE               PAGE_SIZE

#define	  cavium_min_t			 min_t
#define   cavium_max_t			 max_t

#define   cavium_flush_write()           wmb()
#define   cavium_sys_flush_write()       mmiowb()
#define   cavium_get_cpu_count()         num_online_cpus()
#define	  cavium_get_present_cpu_count() num_present_cpus()

#define   cavium_cpu_to_node(cpu)        cpu_to_node(cpu)
#define   cavium_dev_to_node(dev)        dev_to_node(dev)
#define   cavium_set_dev_node(dev, node) set_dev_node(dev, node)

#define   cavium_jiffies                 jiffies
#define   CAVIUM_TICKS_PER_SEC           HZ
#define   cavium_msecs_to_jiffies(msec)  msecs_to_jiffies(msec)

#define   cavium_mdelay(tmsecs)          mdelay(tmsecs)
#define   cavium_udelay(tusecs)          udelay(tusecs)

#define   cavium_kmalloc(size, flags)    kmalloc((size),(flags))
#define   cavium_kfree(pbuf)	         kfree((pbuf))
#define   cavium_kmemdup(data, size, flags)    kmemdup((data), (size),(flags))

#define   cavium_vmalloc(size)           vmalloc((size))
#define   cavium_vmalloc_node(size, node)    vmalloc_node((size), (node))
#define   cavium_vzalloc(size)           vzalloc((size))
#define   cavium_vzalloc_node(size, node)    vzalloc_node((size), (node))
#define   cavium_vfree(ptr)              vfree((ptr))

#define   cavium_kmem_cache              kmem_cache
#define   cavium_socket                  socket
#define   cavium_mutex                   mutex

#define   cavium_mutex_init(_lock)       mutex_init(_lock)
#define   cavium_mutex_lock(_lock)       mutex_lock(_lock)
#define   cavium_mutex_unlock(_lock)     mutex_unlock(_lock)

#define   cavium_memcpy(dest, src, size) memcpy((dest), (src), (size))
#define   cavium_memset(buf, val, size)  memset((buf), (val), (size))
#define   cavium_memcmp(buf1,buf2,size)  memcmp((buf1), (buf2), (size))

#define	  cavium_strncpy(dest, src, size) strncpy((dest), (src), size)
#define   cavium_strlen(str)              strlen(str)
#define   cavium_strncmp(dest, src, size) strncmp(dest, src, size)
#define   cavium_strncat(dest, src, size) strncat(dest, src, size)
#define   cavium_strnlen(str, maxlen)     strnlen(str, maxlen)

#define   cavium_atomic_t                atomic_t
#define   cavium_atomic_set(ptr, val)    atomic_set((ptr), (val))
#define   cavium_atomic_read(ptr)        atomic_read((ptr))
#define   cavium_atomic_inc(ptr)         atomic_inc((ptr))
#define   cavium_atomic_add(val, ptr)    atomic_add((val), (ptr))
#define   cavium_atomic_dec(ptr)         atomic_dec((ptr))
#define   cavium_atomic_sub(val, ptr)    atomic_sub((val), (ptr))
#define   cavium_atomic_cmpxchg(v, old, new) atomic_cmpxchg((v), (old), (new))

#define   cavium_set_bit(bit, ptr)	 set_bit((bit),(ptr))
#define   cavium_test_bit(bit, ptr)	 test_bit((bit),(ptr))

#define   cavium_complete(ptr)		 complete((ptr))

#define   cavium_test_and_set_bit(nr, ptr) test_and_set_bit(nr, (ptr))
#define   cavium_test_and_clear_bit(nr, ptr) test_and_clear_bit(nr, (ptr))

#define   cavium_kthread_create          kthread_create
#define   cavium_wake_up_process         wake_up_process
#define   cavium_kthread_stop            kthread_stop
#define   cavium_kthread_bind            kthread_bind
#define   cavium_kthread_should_stop     kthread_should_stop
#define   cavium_lower_pow		 rounddown_pow_of_two

#define   OCTEON_READ32(addr)            readl(addr)
#define   OCTEON_WRITE32(addr, val)      writel((val),(addr))
#define   OCTEON_READ16(addr)            readw(addr)
#define   OCTEON_WRITE16(addr, val)      writew((val),(addr))
#define   OCTEON_READ8(addr)             readb(addr)
#define   OCTEON_WRITE8(addr, val)       writeb((val),(addr))
#ifdef    readq
#define   OCTEON_READ64(addr)            readq(addr)
#else
static inline u64
OCTEON_READ64(void *addr)
{
	u64 val64;
	val64 = readl(addr + 4);
	val64 = (val64 << 32) | readl(addr);
	return val64;
}
#endif
#ifdef    writeq
#define   OCTEON_WRITE64(addr, val)      writeq((val),(addr))
#else
static inline void
OCTEON_WRITE64(void *addr, u64 val)
{
	writel((u32)(val & 0xffffffff), addr);
	writel((val >> 32), ((u8 *)addr + 4));
}
#endif

#define   cavium_dma_addr_t              dma_addr_t

#define   CAVIUM_DMA_FROM_DEVICE         DMA_FROM_DEVICE
#define   CAVIUM_DMA_TO_DEVICE           DMA_TO_DEVICE

#define   cavium_dma_sync_single_for_cpu dma_sync_single_for_cpu
#define   cavium_dev_ptr(pci_dev)        &(pci_dev->dev)

#define   recv_buf_put(skb, len)         skb_put((skb), (len))
#define   recv_buf_reserve(skb, len)     skb_reserve((ptr), len)
#define   recv_buffer_push(skb, len)     skb_push((skb), (len))
#define   recv_buffer_pull(skb, len)     skb_pull((skb), (len))

#define   cavium_spinlock_t                         spinlock_t
#define   cavium_spintrylock_t                      spinlock_t
#define   cavium_spin_lock_init(lock)               spin_lock_init((lock))
#define   cavium_spin_lock(lock)                    spin_lock((lock))
#define   cavium_spin_unlock(lock)                  spin_unlock((lock))
#define   cavium_spin_lock_softirqsave(lock)        spin_lock_bh(lock)
#define   cavium_spin_trylock_init(lock)            spin_lock_init((lock))
#define   cavium_spin_trylock_softirqsave(lock)     spin_trylock_bh(lock)
#define   cavium_spin_trylock(lock)                 spin_trylock(lock)
#define   cavium_spin_tryunlock(lock)               spin_unlock((lock))
#define   cavium_spin_unlock_softirqrestore(lock)   spin_unlock_bh(lock)
#define   cavium_spin_lock_irqsave(lock, flags)     spin_lock_irqsave(lock, flags)
#define   cavium_spin_unlock_irqrestore(lock,flags) spin_unlock_irqrestore(lock, flags)
#define   cavium_interrupt_spin_lock(lock)          spin_lock((lock))
#define   cavium_interrupt_spin_unlock(lock)        spin_unlock((lock))
#define   cavium_interrupt_spin_lock_irqsave(lock, flags)     spin_lock_irqsave(lock, flags)
#define   cavium_interrupt_spin_unlock_irqrestore(lock,flags) spin_unlock_irqrestore(lock, flags)

#define   cavium_wait_channel        		    wait_queue_head_t
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4, 13, 0))
#define   cavium_wait_entry          		    wait_queue_entry_t
#else
#define   cavium_wait_entry          		    wait_queue_t
#endif
#define   cavium_init_wait_channel(wc_ptr)          init_waitqueue_head(wc_ptr)
#define   cavium_init_wait_entry(we_ptr, task)      init_waitqueue_entry(we_ptr, task)
#define   cavium_add_to_waitq(wq_ptr, we_ptr)       add_wait_queue(wq_ptr, we_ptr)
#define   cavium_remove_from_waitq(wq_ptr, we_ptr)  remove_wait_queue(wq_ptr, we_ptr)

#define   cavium_check_timeout(kerntime, chk_time)  time_after((kerntime), (unsigned long)(chk_time))

#define cavium_work  				    work_struct
#define cavium_delayed_work 			    delayed_work
#define cavium_workqueue 			    workqueue_struct
#define cavium_create_workqueue(name)		    create_workqueue(name)
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 36))
#define cavium_alloc_workqueue(name, flags, max_active) alloc_workqueue(name, flags, max_active)
#else
#define cavium_alloc_workqueue(name, flags, max_active) create_workqueue(name)
#endif
#define cavium_destroy_workqueue(workqueue)         destroy_workqueue(workqueue)
#define cavium_flush_workqueue(workqueue)           flush_workqueue(workqueue)
#define cavium_queue_delayed_work(wq, work,delay)   queue_delayed_work(wq, work, msecs_to_jiffies(delay))
#define cavium_schedule_delayed_work(work,delay)    schedule_delayed_work(work,  msecs_to_jiffies(delay))
#define cavium_mod_delayed_work(wq, work,delay)     mod_delayed_work(wq, work, msecs_to_jiffies(delay))
#define cavium_cancel_delayed_work(work)	    cancel_delayed_work(work)
#define cavium_cancel_delayed_work_sync(work)	    cancel_delayed_work_sync(work)
#define CAVIUM_INIT_DELAYED_WORK(work, func)	    INIT_DELAYED_WORK(work, func)
#define cavium_cpumask_set_cpu(x, y)		    cpumask_set_cpu(x, y)
#define cavium_enable_irq(oct, x)		    enable_irq(x)
#define cavium_disable_irq(oct, x)		    disable_irq(x)
#define cavium_disable_irq_nosync(oct, x)	    disable_irq_nosync(x)

#define cavium_tasklet_init(tasklet, func, priv)    tasklet_init(tasklet, func, priv)
#define cavium_tasklet_schedule(tasklet)	    tasklet_schedule(tasklet)

#define   cavium_cpu_to_be64s                       cpu_to_be64s
#define   cavium_cpu_to_be64                        cpu_to_be64
#define   cavium_cpu_to_be32                        cpu_to_be32
#define   cavium_cpu_to_be16                        cpu_to_be16
#define   cavium_be64_to_cpu                        be64_to_cpu
#define   cavium_be32_to_cpu                        be32_to_cpu
#define   cavium_be16_to_cpu                        be16_to_cpu
#define   cavium_crc32                              crc32

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 19, 0))
#define   cavium_write_once(x, val)                 WRITE_ONCE(x, val)
#define   cavium_read_once(x)                       READ_ONCE(x)
#define   cavium_write_once64(x, val)                 WRITE_ONCE(x, val)
#define   cavium_read_once64(x)                       READ_ONCE(x)
#else
#define   cavium_write_once(x, val)                 ACCESS_ONCE(x) = val
#define   cavium_read_once(x)                       ACCESS_ONCE(x)
#define   cavium_write_once64(x, val)                 ACCESS_ONCE(x) = val
#define   cavium_read_once64(x)                       ACCESS_ONCE(x)
#endif
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 0, 0)) ||  (RHEL_RELEASE_CODE >= 1541)
#define   cavium_strtol                             kstrtol
#else
static inline s32 cavium_strtol(const s8 *s, u32 base, size_t *res)
{
	char *endp;
	*res = simple_strtol(s, &endp, base);

	return 0;
}
#endif

#define OCTEON_READ_PCI_CONFIG(dev, offset, pvalue)      \
          pci_read_config_dword((dev)->pci_dev, (offset),(pvalue))

#define OCTEON_WRITE_PCI_CONFIG(dev, offset, value)      \
          pci_write_config_dword((dev)->pci_dev, (offset),(value))

#define    cvm_intr_return_t             irqreturn_t
#define    CVM_INTR_HANDLED              IRQ_HANDLED
#define    CVM_INTR_NONE                 IRQ_NONE

/* To avoid using volatile in linux kernel
 * linux uses ACCESS_ONCE for multi threaded contexts
 * which is a volatile cast
 * linux uses accessors readlbw/writelbw for accessing 
 * memory mapped IO registers which are again volatile
 * type casts.
 * Note: other oses may or may not have the capability
 */
#define cavium_volatile_t
#define cavium_volatile_u32	u32
#define cavium_volatile_u64	u64

#define cavium_netbuf sk_buff
#define cavium_pci_device pci_dev
#define cavium_pci_reset_function pci_reset_function
#define cavium_net_device net_device
#define cavium_napi_struct napi_struct
#define cavium_devlink devlink

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 14, 0)
#define cavium_call_single_data_t struct call_single_data
#else
#define cavium_call_single_data_t call_single_data_t
#endif

#define cavium_cpumask	struct cpumask


#define cavium_list_head	list_head

#define cavium_iomem		__iomem

#define cavium_init_completion(x)	init_completion(x)
#define cavium_completion completion

#define cavium_snprintf(buf, n, format, ...)         \
        snprintf(buf, n, format, ## __VA_ARGS__)

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3,17,0)) || (RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(7, 2))
#define cavium_timespec timespec64
#define cavium_getnstimeofday(ts) getnstimeofday64(ts);
#else
#define cavium_timespec timespec
#define cavium_getnstimeofday(ts) getnstimeofday(ts);
#endif

#define cavium_pr_err(format, ...)         \
	pr_err(format, ## __VA_ARGS__)
#define cavium_pr_info(format, ...)         \
	pr_info(format, ## __VA_ARGS__)
#define lio_dev_info(oct, format, ...)         \
	dev_info(&oct->pci_dev->dev, format, ## __VA_ARGS__)
#define lio_dev_warn(oct, format, ...)         \
	dev_warn(&oct->pci_dev->dev, format, ## __VA_ARGS__)
#define lio_dev_err(oct, format, ...)         \
	dev_err(&oct->pci_dev->dev, format, ## __VA_ARGS__)
#define lio_dev_dbg(oct, format, ...)         \
	dev_dbg(&oct->pci_dev->dev, format, ## __VA_ARGS__)

#define lio_dev_notice(oct, format, ...)         \
	dev_notice(&oct->pci_dev->dev, format, ## __VA_ARGS__)

#if  LINUX_VERSION_CODE < KERNEL_VERSION(3, 0, 0)
#define lio_info(lio, lvl, _fmt, _args...) \
	do {    \
		if (unlikely(netif_msg_##lvl(lio))) \
			pr_info("%s: " _fmt, lio->netdev->name, ##_args); \
	} while (0)
#else
#define lio_info(lio, lvl, _fmt, _args...) \
	netif_info(lio, lvl, lio->netdev, _fmt,  ##_args)
#endif
#define lio_print_hex_dump_bytes(buf, len) \
	print_hex_dump_bytes("", DUMP_PREFIX_ADDRESS, buf, len)

#define CVM_MIN(d1, d2)		min(d1, d2)
#define CVM_MIN_T(type, d1, d2)	min_t(type, d1, d2)

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0)
#define cavium_u64_to_ether_addr	u64_to_ether_addr
#else
/**
 * u64_to_ether_addr - Convert a u64 to an Ethernet address.
 * @u: u64 to convert to an Ethernet MAC address
 * @addr: Pointer to a six-byte array to contain the Ethernet address
 */
static inline void cavium_u64_to_ether_addr(u64 u, u8 *addr)
{
        int i;

        for (i = ETH_ALEN - 1; i >= 0; i--) {
                addr[i] = u & 0xff;
                u = u >> 8;
        }
}
#endif

#endif
