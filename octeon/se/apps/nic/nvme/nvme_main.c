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

/***************************************************************************//**
*
*  \file
*
*  \brief This module contains the code for processing the nvme commands.
*
*******************************************************************************/

/*---------------------------------------------------------------------------
 *                               Revision History
 *   $Log: main.c $
 *  ---------------------------------------------------------------------------*/

#include "nvme_cvm.h"
#include "nvme.h"
#include "cn73xx_nqm.h"
#include "nvme_stats.h"
#include "cvmcs-profile.h"
#include "sal_linux_bdev.h"

#define OCTEON_NVME_STATS_SZ \
	 	 (4 + 4 + TLV_SIZE_ALIGN(sizeof(nvme_global_stats_t)) \
		  	+ NVME_MAX_CORES * (4 + 4 + TLV_SIZE_ALIGN(sizeof(nvme_per_cpu_stats_t))) + 8)

nvme_per_cpu_stats_t *nvme_per_cpu_stats; // Per cpu variable
CVMX_SHARED nvme_global_stats_t *nvme_global_stats; 
		

/*
 * Device control structure catalog
 */
CVMX_SHARED struct nvme_dev *nqm_device_structs[1028];
extern CVMX_SHARED uint8_t nqm_tag_mode;

CVMX_SHARED  int gbl_host_page_size_pool = -1;
CVMX_SHARED  int gbl_host_page_size = -1;
CVMX_SHARED  char *nvme_stats_mem;
CVMX_SHARED  int32_t  nvme_pcpu_stats_idx = 0;


/***************************************************************************//**

Test NVME module active

Returns true. In the stubbed version of this module, it returns false.

*******************************************************************************/

int nvme_active(void)
{
	if (OCTEON_IS_MODEL(OCTEON_CN73XX)) {
		return 1;
	} else {
#ifdef NVME_68XX_SUPPORT
		if (OCTEON_IS_MODEL(OCTEON_CN68XX))
			return 1;
#endif
	}
	return 0;
}

void cvm_dump_nvme_wqe(cvmx_wqe_nqm_t *nqm_wqe)
{
	uint64_t *ptr;
	int i;

	debug_printf(3, "word0: %016lx", nqm_wqe->word0.u64);	
	debug_printf(3, "word1: %016lx", nqm_wqe->word1.u64);	
	debug_printf(3, "word2: %016lx", nqm_wqe->word2);	
	debug_printf(3, "word3: %016lx", nqm_wqe->word3.u64);	
	debug_printf(3, "word4: %016lx", nqm_wqe->word4.u64);	
	ptr = (uint64_t *)nqm_wqe->packet_data;
	for (i = 0; i < 11; i++) {
		debug_printf(3, "word %d: 0x%016lx", 5+i, ptr[i]);
		if (i == 2)
			debug_printf(3, "command");
	}
}

/***************************************************************************//**

Process NVMe work queue entry

Executes each command in the WQE against the attached storage.

Note that the NVMe idea of what a WQE is differs from the NIC, and so is passed
as a void pointer for now. This is because the 68xx WQE has a different format
from the 73xx WQE, and there is no NVMe block on the 68xx.

*******************************************************************************/

void nvme_process_wqe(cvmx_wqe_t* wqe)
{
	cvmx_wqe_tt* wqp = (cvmx_wqe_tt*) wqe;
	struct nvme_dev *dev; // device info structure pointer
	uint32_t tag;
	int free = 1;
	uint16_t opcode;

	// avoid the preamble: we want this status line to be compact
        if (DEBUG_LEVEL >= 3)
            printf("Tag: %08x TT: %01x GRP: %03x\n", cvmx_wqe_get_tag(wqe),
                      cvmx_wqe_get_tt(wqe), cvmx_wqe_get_grp(wqe));
	dev = nqm_device_structs[wqp->word3.qw3.vf]; // pick up the indicated dev struct

	tag = (cvmx_wqe_get_tag(wqe) >> NQM_TAG_SHIFT) & TAG_PHASE_MASK;
	opcode = (cvmx_wqe_get_tag(wqe) >> NQM_QID_SHIFT) & 0x1f;

	NVME_INC_GEN_STATS(n_wqe, 1);
	NVME_SET_GEN_STATS(last_wqe_ts, cvmx_get_cycle());

	switch (tag) {
#ifdef NVME_68XX_SUPPORT
		case CMD_TRANSFER_TAG:
			// This tag is used only in emulation
			debug_printf(3, "CMD_TRANSFER_TAG");
			hil_process_cmd_transfer_tag(dev, wqp);
			break;
#endif

		// workaround for nvme command not being fetched on 73xx.
		// Only the initial 64bit are feched and rest all are ignored.
		// Initiate a seperate DMA to fetch the nvme command.
		case CMD_FETCH_TAG:
			debug_printf(3, "FETCH_TAG");
			/* Profiling uses this point as the start */
			wqp->reserved = cvmcs_profile_start();
			//cvm_dump_nvme_wqe((cvmx_wqe_nqm_t *)wqp);
			npl_fetch_nvme_command(dev, (cvmx_wqe_nqm_t *)wqe);
			free = 0;
			break;

		case CMD_HANDLE_TAG:
			if (OCTEON_IS_MODEL(OCTEON_CN73XX_PASS1_0)) {
#ifndef NQM_FETCH_PCI_DMA
				/* Profiling uses this point as the start */
				wqp->reserved = cvmcs_profile_start();

				npl_iobdma_fetch_sq_entry(dev, (cvmx_wqe_nqm_t *)wqe);
#endif
				cvmcs_profile_mark_timed_event(
					PROF_NVME_CMD_FETCH, wqp->reserved);
			} else {
				/* Profiling uses this point as the start */
				wqp->reserved = cvmcs_profile_start();
			}
#ifndef ENABLE_PROFILING
			wqp->reserved = cvmx_get_cycle();
#endif

			debug_printf(3, "CMD_HANDLE_TAG");

			npl_convert_iocmds_le_to_be(&(wqp->nvme_cmd),
				wqp->word3.qw3.sq_id ? IO_CMD: ADMIN_CMD);
			LCMDID(wqe) = npl_alloc_local_cmd_id(dev,
				wqp->word3.qw3.sq_id, wqp->nvme_cmd.common.cmdid);
			if (LCMDID(wqe) >= MAX_SQ_DEPTH) {
				debug_printf(1, "Could not allocate local commandID");
				break;
			}

			cvmx_atomic_add32((int32_t *)&dev->queue->
				sq[wqp->word3.qw3.sq_id]->num_entries, 1);

			if (wqp->word3.qw3.sq_id)
				npl_process_io_request(dev, wqp);
			else
				npl_process_admin_request(dev, wqp);
			break;
		case ADMIN_DATA_TRANSFER_TAG:
			debug_printf(3, "ADMIN_DATA_TRANSFER_TAG");
			npl_process_admin_data_transfer_tag(dev, wqp);
			break;
		case IO_DATA_TRANSFER_TAG:
			debug_printf(3, "IO_DATA_TRANSFER_TAG");
			npl_process_io_data_transfer_tag(dev, wqp);
			break;
		case CMD_COMPLETION_REQUEST_TAG:
			debug_printf(3, "CMD_COMPLETION_REQUEST_TAG");
			npl_add_completion_queue_entry(dev, wqp);
			break;
		case PRP_LIST_TRANSFER_TAG:
			debug_printf(3, "PRP_LIST_TRANSFER_TAG");
			npl_make_prp_list_local(dev, wqp);
			break;
		case MSG_FROM_OCTLINUX_TAG:
			sal_linux_bdev_process_message(wqp, opcode);
			break;
		case NQM_INTR_HANDLE_TAG:
			npl_controller_shutdown(dev);
			break;
		default:
			debug_printf(1, "Error : Unknown Tag %x", tag);
	}
	if (free)
		npl_fpa_free(wqp, CVMX_FPA_WQE_POOL, sizeof(cvmx_wqe_t));
}

/***************************************************************************//**

Process nvm init and poll

Inits the NVMe core functions, then enters the NVMe polling loop.

This last function disappears when the 73xx is used, and we will just return to
the caller.

*******************************************************************************/

void nvme_process(void)
{
#ifdef NVME_68XX_SUPPORT
	struct nvme_dev *dev; // device info structure pointer

	debug_printf(1, "Entering NVMe host polling loop");
	// pick up device structure from vf(0) (PF)
	dev = nqm_device_structs[0];
	while(1)
	{
		hil_reg_poll_update(dev);
		hil_process_rr_list(dev);
	}
#endif
}

extern int is_boot_core(uint32_t core_id);
void nvme_local_init(void)
{
	uint64_t grp_mask = ~((1ULL << LINUX_POW_DATA_GROUP) | 
					(1ULL << LINUX_POW_CTRL_GROUP));
	uint8_t core = cvmx_get_core_num(), i;
	uint32_t *tlv;
	int32_t j = 0;

	cvmx_write_csr(CVMX_SSO_PPX_SX_GRPMSKX(core, 0, 0), grp_mask);
	cvmx_write_csr(CVMX_SSO_PPX_SX_GRPMSKX(core, 1, 0), grp_mask);

	if (booting_for_the_first_time && is_boot_core(core)) {
		// Group settings for octlinux
		grp_mask = ~grp_mask;
		for (i = 0; i < core; i++) {
			cvmx_write_csr(
				CVMX_SSO_PPX_SX_GRPMSKX(i, 0, 0), grp_mask);
			cvmx_write_csr(
				CVMX_SSO_PPX_SX_GRPMSKX(i, 1, 0), grp_mask);
		}
	}

	j = cvmx_atomic_fetch_and_add32(&nvme_pcpu_stats_idx, 1);
	tlv = (void *) (nvme_stats_mem + 
			TLV_SIZE_ALIGN(sizeof(nvme_global_stats_t)) + 8 + 
			j * (TLV_SIZE_ALIGN(sizeof(nvme_per_cpu_stats_t)) + 8));

	*tlv = OCTEON_NVME_STATS_TYPE_PCPU;
 	tlv++;
	*tlv = sizeof(nvme_per_cpu_stats_t);
	tlv++;

	nvme_per_cpu_stats = (void *)tlv;

	memset(nvme_per_cpu_stats, 0x0, sizeof(*nvme_per_cpu_stats));
	debug_printf(3, "Core %d (%d) stats at %p", core, j, nvme_per_cpu_stats);
	nvme_per_cpu_stats->coreid = core;
	test_and_set_bit(core, &nvme_global_stats->active_coremask);
	CVMX_SYNCWS;
}

/***************************************************************************//**

Process nvm init

Inits the NVMe core functions. This needs to run on an excluded core (single
threaded, only one core running).

*******************************************************************************/
	
void nvme_init(void)
{
	//uint32_t pcie_port = 1;
	int ret = -1;
	int i;
	uint32_t *tlv;
	uint32_t tlv_size =  OCTEON_NVME_STATS_SZ;

	debug_printf(1, "NVMe driver init:");

	if (!booting_for_the_first_time) {
		nvme_stats_mem = live_upgrade_ctx->nvme_stats_mem;
		nvme_global_stats = live_upgrade_ctx->nvme_global_stats;
		return;
	}

	/*
	 * Clear dev pointer array, and place the pf dev struct here
	 */
	for (i = 0; i < 1028; i++) nqm_device_structs[i] = 0;

	/* Initialize the system parameters and allocate any global
	   pools etc */

	/* Initialize FPA_DATA_BUF_POOL with minimal buffers if there is no oct-linux */
	if (is_boot_core(core_id) && !core_id) {
		debug_printf(1, "NVMe setting up minimal data buf pool");
		cvmcs_app_mem_alloc("NVMe Data bufs", FPA_DATA_BUF_POOL,
				FPA_DATA_BUF_POOL_SIZE, 8*1024);
	}
	

	/* Initialize a PCIe port for use in target (EP) mode */
#if 0
	ret = cvmx_pcie_ep_initialize(pcie_port);
	if(ret)
	{
		debug_printf(1, "Error: \"cvmx_pcie_ep_initialize\" has failed \n");
		return;
	}
#endif

	if (OCTEON_IS_MODEL(OCTEON_CN73XX)) {
		/* initialize hardware NQM module */
		ret = nqm_init();
	} else {
		/* Initialize hil module */
#ifdef NVME_68XX_SUPPORT
		ret = hil_init();
#endif
	}
	if(ret < 0)
            return;

	if (!OCTEON_IS_MODEL(OCTEON_CN73XX)) {
		/* enable DMA interrupts */
		cvmx_write_csr(
			CVMX_PEXP_SLI_INT_ENB_PORTX(1), CN68XX_INTR_MASK);
	}

	if (OCTEON_IS_MODEL(OCTEON_CN73XX_PASS1_0))
	    cvmcs_profile_create(PROF_NVME_CMD_FETCH, "NVMe command fetch");

	cvmcs_profile_create(PROF_NVME_READ_PROC, "Read processing");
	cvmcs_profile_create(PROF_NVME_WRITE_PROC, "Write processing");
	cvmcs_profile_create(PROF_NVME_READ_DMA, "Read DMA (Outbound)");
	cvmcs_profile_create(PROF_NVME_WRITE_DMA, "Write DMA (Inbound)");
	cvmcs_profile_create(PROF_NVME_PRP_LIST_TX, "PRP list transfer");

	tlv = cvmx_bootmem_alloc_named(tlv_size, CVMX_CACHE_LINE_SIZE, OCTEON_NVME_STATS_BLOCK_NAME);
	memset(tlv, -1, tlv_size);
	CVMX_SYNCWS;

	if (tlv) {
		nvme_stats_mem = (void *)tlv;
		live_upgrade_ctx->nvme_stats_mem = nvme_stats_mem;
		debug_printf(3, "Allocated %s block at %p", OCTEON_NVME_STATS_BLOCK_NAME, nvme_stats_mem);
		
		*tlv = OCTEON_NVME_STATS_TYPE_GLOBAL;
 		tlv++;

		*tlv = sizeof(nvme_global_stats_t);
		tlv++;

		nvme_global_stats = (nvme_global_stats_t *)tlv;
		live_upgrade_ctx->nvme_global_stats = nvme_global_stats;
		memset(nvme_global_stats, 0x0, sizeof(*nvme_global_stats));

		nvme_global_stats->core_clock = cvmx_clock_get_rate(CVMX_CLOCK_CORE); 
		nvme_global_stats->max_ioq_per_vf = nqm_vf_mode_map[nqm_vf_mode].vf_max_ioq;
		nvme_global_stats->max_vf_possible = nqm_vf_mode_map[nqm_vf_mode].vf_cnt;
	} else {
		debug_printf(1, "Failed to named alloc %s block of size %u", OCTEON_NVME_STATS_BLOCK_NAME, 
				tlv_size);
	}

	debug_printf(1, "Init complete");

}

void nvme_deinit(void)
{
	if (OCTEON_IS_MODEL(OCTEON_CN73XX)) {
		/* deinitialize hardware NQM module */
		nqm_deinit();
	} else {
#ifdef NVME_68XX_SUPPORT
		/* deinitialize hil module */
		hil_deinit();
#endif
	}
}
