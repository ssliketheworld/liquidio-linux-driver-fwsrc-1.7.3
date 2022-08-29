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

/*! \file linux_sysdep.h
    \brief Host Driver: This file has linux-specific definitions for macros and
                        inline routines used in the Octeon driver.
 */

#ifndef _LINUX_SYSDEP_H
#define _LINUX_SYSDEP_H

#define UNUSED  __attribute__((unused))

#define __NO_VERSION__
#include <linux/version.h>

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/random.h>
#include <asm/byteorder.h>
#include <linux/interrupt.h>
#include <linux/skbuff.h>
#include <asm/uaccess.h>
#include <asm/types.h>
#include <linux/dma-mapping.h>
#include <linux/pci.h>
#include <linux/aer.h>
#include <linux/delay.h>
#include <linux/netdevice.h>
#include <linux/vmalloc.h>
#include <linux/ipv6.h>
#include <asm/div64.h>
#include <linux/crc32.h>
#include <linux/kthread.h>

#include "cvm_linux_types.h"

#ifdef __LITTLE_ENDIAN

#define __CAVIUM_BYTE_ORDER __CAVIUM_LITTLE_ENDIAN
#ifndef __CAVIUM_LITTLE_ENDIAN_BITFIELD
#define __CAVIUM_LITTLE_ENDIAN_BITFIELD
#endif

#else

#define __CAVIUM_BYTE_ORDER __CAVIUM_BIG_ENDIAN
#ifndef __CAVIUM_BIG_ENDIAN_BITFIELD
#define __CAVIUM_BIG_ENDIAN_BITFIELD
#endif

#endif

/* Gives up the CPU for a timeout period.  */
#define   cavium_sleep_timeout(timeout)     \
do {  \
        set_current_state(TASK_INTERRUPTIBLE);  \
        schedule_timeout(timeout);              \
        set_current_state(TASK_RUNNING);        \
} while (0)

#endif				/* _LINUX_SYSDEP_H */
