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

#ifndef __CVMCS_APP_COMMON_H__
#define __CVMCS_APP_COMMON_H__

#include <stdio.h>
#include <string.h>
#ifdef __linux__
#include <signal.h>
#endif

#include "cvmx.h"
#include "cvmx-config.h"
#include "cvmx-fpa.h"
#include "cvmx-ipd.h"
#include "cvmx-pko.h"
#include "cvmx-pow.h"
#include "cvmx-sysinfo.h"
#include "cvmx-coremask.h"
#include "cvmx-malloc.h"
#include "cvmx-bootmem.h"
#include "cvmx-helper.h"
#include "cvmx-pko3-resources.h"
#ifdef CONFIG_EBT3000
#include "cvmx-ebt3000.h"
#endif
#include "cvmx-app-hotplug.h"
#include "cvmx-tim.h"
#include "cvmx-helper-cfg.h"

#include "cvm-driver-defs.h"
#include "cvm-drv.h"
#include "cvm-drv-debug.h"
#include "liquidio_common.h"


/* If OCTEON_DEBUG_LEVEL is defined all
   application debug messages are enabled. */
#ifdef OCTEON_DEBUG_LEVEL
#define DBG                      printf
#else
#define DBG(format, args...)     do{ }while(0)
#endif

typedef struct {
	void *oct;
	void *octnic;
	void *nvme_stats_mem;
	void *nvme_global_stats;
	void *fwdbuf;
	void *fwdump;
	void *rss_state;
	void *per_core_stats;
	void *lro_hash_table;
	void *oq_status;
	void *dq_flush_in_progress;
	void *mbcast_list;

	void *cvmx_fpa3_pool_info0;
	void *cvmx_fpa3_aura_info0;

	struct cvmx_cfg_port_param cvmx_cfg_port[CVMX_MAX_NODES][CVMX_HELPER_MAX_IFACE][CVMX_HELPER_CFG_MAX_PORT_PER_IFACE];
} cvmcs_live_upgrade_ctx_t;

extern CVMX_SHARED cvmcs_live_upgrade_ctx_t *live_upgrade_ctx;

extern CVMX_SHARED bool booting_for_the_first_time;

extern CVMX_SHARED int nic_verbose;
#define DBG2(format, ...)	\
{     if(nic_verbose)   do { printf(format, ## __VA_ARGS__ );} while (0); }

static inline int
cvmcs_app_mem_alloc(char *str, int pool, int buf_size, int pool_count)
{
	void *memory;

	memory =
	    cvmx_bootmem_alloc((buf_size * pool_count), buf_size);
	if (memory == NULL) {
		printf("Out of memory initializing %s.\n", str);
		return 1;
	}

	DBG("Allocating memory from %p to %p for Pool %d\n",
	       memory, (memory + (buf_size * pool_count)), pool);

#ifdef CN56XX_PEER_TO_PEER
	if ((pool <= 1)
	    && ((unsigned long)(memory + (buf_size * pool_count)) >
		(64 * 1024 * 1024))) {
		printf("Pool %d exceeds 64M. Peer-to-Peer will not work\n",
		       pool);
		return 1;
	}
#endif

	cvmx_fpa_setup_pool(pool, str, memory, buf_size, pool_count);

	return 0;
}

/* Print the count of available buffers in each FPA pool. */
static inline void print_pool_count_stats()
{
	int i;

	DBG2("FPA Pools: \n");
	for (i = 0; i < 8; i++) {
		uint64_t  cnt = 0;
		if (octeon_has_feature(OCTEON_FEATURE_FPA3)) {
			uint64_t aura_cnt;
			uint64_t pool = cvmx_read_csr_node(cvmx_get_node_num(), CVMX_FPA_AURAX_POOL(i));
			cnt = cast64(cvmx_read_csr_node(cvmx_get_node_num(),CVMX_FPA_POOLX_AVAILABLE(pool)));
			aura_cnt = cvmx_read_csr_node(cvmx_get_node_num(), CVMX_FPA_AURAX_CNT(i));	
			DBG2("aura %2d pool %2lu aura_cnt %2lu pool_cnt %8lu\n", i, pool, aura_cnt,  cnt);
		}
		else {
			cnt = cast64(cvmx_read_csr(CVMX_FPA_QUEX_AVAILABLE(i)));

			if (cnt)
				DBG2("%d: %lu  ", i, cnt);
		}
	}
}

static inline cvmx_wqe_t *cvmcs_app_get_work_sync(int wait)
{
	return cvmx_pow_work_request_sync(wait);
}

int cvm_app_nic_cap_init(void);
int cvmcs_common_add_task(uint64_t interval, int (*fn) (void *), void *fn_arg);
int cvmcs_common_remove_task(int (*fn) (void *), void *fn_arg);
void cvmcs_common_schedule_tasks(void);

/** Global initialization. Performed by the boot core only. */
int cvmcs_app_init_global();

/** Local initialization. Performed by all cores. */
int cvmcs_app_init_local();

/** Application shutdown. Disable and shutdown PKO and FPA pools. */
int cvmcs_app_shutdown();

/** Common duty cycle operations. */
void cvmcs_app_duty_cycle_actions(uint64_t cycles);

/** Config L2C performance counters */
void cvmcs_config_l2c_perf();

/** Dump and clear L2C performance counters */
void cvmcs_print_l2c_stats(uint64_t cycles);

/** Check and print application mode (32/64 bit) */
void cvmcs_app_check_mode();

/** Common application bringup routine. */
struct cvmx_app_hotplug_callbacks;
int cvmcs_app_bringup(int nvme_active, struct cvmx_app_hotplug_callbacks *hpcb);

/** Barrier call based on coremask in cvmcs-common. */
void cvmcs_app_barrier();

/** Returns 1 if the core id is for the control core, 0 otherwise. */
int is_control_core(uint32_t core_id);

/** Returns 1 if the core id is for the boot core, 0 otherwise. */
int is_boot_core(uint32_t core_id);
/** Returns 1 if the core id is for the nvme core, 0 otherwise. */
int is_nvme_core(uint32_t core_id);

/** Returns 1 if the core id is for the display core, 0 otherwise. */
int is_display_core(uint32_t core_id);

/** Returns 1 if the core id is for the link status core, 0 otherwise. */
int is_link_status_core(uint32_t core_id);

/* Get the Base MAC address for Octeon device. */
uint8_t *cvmcs_app_get_macaddr_base();

#endif

/* $Id$ */
