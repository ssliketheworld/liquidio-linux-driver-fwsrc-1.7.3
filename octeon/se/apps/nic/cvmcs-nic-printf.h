/*
 * Author: Cavium, Inc.
 *
 * Copyright (c) 2015 Cavium, Inc. All rights reserved.
 *
 * Contact: support@cavium.com
 *          Please include "LiquidIO" in the subject.
 *
 * This file, which is part of the LiquidIO SDK from Cavium Inc.,
 * contains proprietary and confidential information of Cavium Inc.
 * and in some cases its suppliers. 
 *
 * Any licensed reproduction, distribution, modification, or other use of
 * this file or the confidential information or patented inventions
 * embodied in this file is subject to your license agreement with Cavium
 * Inc. Unless you and Cavium Inc. have agreed otherwise in writing, the
 * applicable license terms "OCTEON SDK License Type 5" can be found under
 * the directory: $LIQUIDIO_ROOT/licenses/
 *
 * All other use and disclosure is prohibited.
 *
 * TO THE MAXIMUM EXTENT PERMITTED BY LAW, THE SOFTWARE IS PROVIDED "AS IS"
 * AND WITH ALL FAULTS AND CAVIUM INC. MAKES NO PROMISES, REPRESENTATIONS
 * OR WARRANTIES, EITHER EXPRESS, IMPLIED, STATUTORY, OR OTHERWISE, WITH
 * RESPECT TO THE SOFTWARE, INCLUDING ITS CONDITION, ITS CONFORMITY TO ANY
 * REPRESENTATION OR DESCRIPTION, OR THE EXISTENCE OF ANY LATENT OR PATENT
 * DEFECTS, AND CAVIUM SPECIFICALLY DISCLAIMS ALL IMPLIED (IF ANY)
 * WARRANTIES OF TITLE, MERCHANTABILITY, NONINFRINGEMENT, FITNESS FOR A
 * PARTICULAR PURPOSE, LACK OF VIRUSES, ACCURACY OR COMPLETENESS, QUIET
 * ENJOYMENT, QUIET POSSESSION OR CORRESPONDENCE TO DESCRIPTION. THE ENTIRE
 * RISK ARISING OUT OF USE OR PERFORMANCE OF THE SOFTWARE LIES WITH YOU.
 */

#ifndef __CVMCS_NIC_PRINTF_H__
#define __CVMCS_NIC_PRINTF_H__
#include "cvmx-interrupt.h"

#define MAX_PB_SIZE (32*1024)

/* Structure that defines a single printf buffer. There will be one of these on each core.
 * The core generating printf output will write to the buffer and adjust the write index,
 * while the core that actually outputs it to the PCI or serial port will adjust the
 * read_index
 *
 * Note: when read_index == write_index, the buffer is empty.  The actual usable size
 *       of each console is console_buf_size -1;
 */
typedef struct {
	uint32_t rd_idx;
        uint32_t wr_idx;
	char buffer[MAX_PB_SIZE];
} octeon_printf_buffer_t;

void cvmcs_init_printf_buffers();
void cvmcs_flush_printf_buffers();

void cvmcs_printf(const char *format, ...) __attribute__ ((format(printf, 1, 2)));

#endif // __CVMCS_NIC_PRINTF_H__

