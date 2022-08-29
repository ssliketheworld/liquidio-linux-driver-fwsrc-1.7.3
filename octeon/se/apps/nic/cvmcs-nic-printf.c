/*
 * Author: Cavium, Inc.
 *
 * Copyright (c) 2016 Cavium, Inc. All rights reserved.
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
#include "cvmcs-nic.h"

#ifdef printf
#undef printf
#endif

extern CVMX_SHARED void (*printf_hook)(const char *fmt, ...);

extern CVMX_SHARED uint32_t num_cores;

static CVMX_SHARED octeon_printf_buffer_t octeon_printf_buffer[MAX_CORES];

void cvmcs_init_printf_buffers()
{
	uint32_t i;

	for (i = 0; i < num_cores; i++) {
		octeon_printf_buffer[i].rd_idx = 0;
		octeon_printf_buffer[i].wr_idx = 0;
	}

	printf_hook = cvmcs_printf;
}

static int printf_buffer_free_bytes(octeon_printf_buffer_t *pb)
{
	if ((pb->rd_idx >= MAX_PB_SIZE) ||
	    (pb->wr_idx >= MAX_PB_SIZE)) 
		return -1;

	return (((MAX_PB_SIZE - 1) - (pb->wr_idx - pb->rd_idx)) % MAX_PB_SIZE);
}

static int printf_buffer_avail_bytes(octeon_printf_buffer_t *pb)
{
	if ((pb->rd_idx >= MAX_PB_SIZE) ||
	    (pb->wr_idx >= MAX_PB_SIZE)) 
		return -1;

	return ((MAX_PB_SIZE - 1) - printf_buffer_free_bytes(pb));
}

void cvmcs_flush_printf_buffer(octeon_printf_buffer_t *pb)
{
	int bytes_available;
	char *buf_ptr;
	int read_size;

	buf_ptr = &pb->buffer[0];
	bytes_available = printf_buffer_avail_bytes(pb);

	if (bytes_available > 0) {
		read_size = bytes_available;

		/* limit overselves to what we can input in a contiguous block */
		if (pb->rd_idx + read_size > MAX_PB_SIZE)
			read_size = MAX_PB_SIZE - pb->rd_idx;

		printf("%.*s", read_size, buf_ptr + pb->rd_idx);

		pb->rd_idx = (pb->rd_idx + read_size) % MAX_PB_SIZE;
	}
}

/* should only be called by a single core to avoid lock contention within printf() */
void cvmcs_flush_printf_buffers()
{
	uint32_t i;

	for (i = 0; i < num_cores; i++) {
		cvmcs_flush_printf_buffer(&octeon_printf_buffer[i]);

		if (OCTEON_IS_MODEL(OCTEON_CN73XX))
			cvmx_write_csr(CVMX_CIU_PP_POKEX(core_id), 1);
	}
}

#ifndef MIN 
#define	MIN(a,b) (((a)<(b))?(a):(b))
#endif
void cvmcs_printf(const char *format, ...)
{
	octeon_printf_buffer_t *pb;
	char buffer[MAX_PB_SIZE];
	char *ptr = buffer;
	int count, free_bytes;
	va_list args;

	va_start(args, format);
	count = vsnprintf(buffer, sizeof(buffer), format, args);
	va_end(args);

	pb = &octeon_printf_buffer[core_id];

	free_bytes = printf_buffer_free_bytes(pb);

	while ((free_bytes > 0) && (count > 0)) {
		int write_size = MIN(free_bytes, count);

		if (pb->wr_idx + write_size >= MAX_PB_SIZE)
			write_size = MAX_PB_SIZE - pb->wr_idx;

		memcpy(&pb->buffer[pb->wr_idx], ptr, write_size);

		/* Make sure data is visible before changing write index */
		CVMX_SYNCW;
		pb->wr_idx = (pb->wr_idx + write_size) % MAX_PB_SIZE;

		count -= write_size;
		ptr += write_size;

		free_bytes = printf_buffer_free_bytes(pb);
	}
}
