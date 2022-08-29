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

#include "cvmcs-common.h"
#include "cvmx-l2c.h"

CVMX_SHARED uint64_t cpu_freq = 0;
CVMX_SHARED uint32_t num_cores = 0;
CVMX_SHARED uint32_t boot_core = 0;
CVMX_SHARED uint32_t nvme_core = 0;
CVMX_SHARED uint32_t display_core = 0;
CVMX_SHARED uint32_t control_core = 0;
CVMX_SHARED uint32_t link_status_core = 0;
CVMX_SHARED uint32_t core_count = 0;
CVMX_SHARED    uint32_t  core_active[MAX_DRV_CORES] =
	 			{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
				 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
				 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
CVMX_SHARED int nic_verbose = 0;	/* CLI feature: enable nic console */

#ifdef VSWITCH
CVMX_SHARED uint64_t cvm_per_core_cpu_stats[MAX_DRV_CORES] =
	 			{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
				 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
				 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};

#endif

uint32_t core_id = 0;

CVMX_SHARED uint8_t max_droq = 0;
/* secs_from_boot, increaments for every sec */
CVMX_SHARED uint64_t secs_from_boot = 0;

CVMX_SHARED cvmcs_live_upgrade_ctx_t *live_upgrade_ctx;
CVMX_SHARED bool booting_for_the_first_time = true;
static CVMX_SHARED bool registered_for_hotplug = false;

volatile bool cvmcs_unplug_requested;
volatile bool cvmcs_shutdown_requested;

#define  MAX_CVMCS_TASKS   8

struct __cvmcs_tasks {
	uint64_t time_to_call;
	uint64_t interval;
	int (*fn) (void *);
	void *fn_arg;
};
CVMX_SHARED cvmx_spinlock_t cvmcs_task_lock;

CVMX_SHARED struct __cvmcs_tasks cvm_tasks[MAX_CVMCS_TASKS];

int cvmcs_common_add_task(uint64_t interval, int (*fn) (void *), void *fn_arg)
{
	int i;

	cvmx_spinlock_lock(&cvmcs_task_lock);
	for (i = 0; i < MAX_CVMCS_TASKS; i++) {
		if (cvm_tasks[i].fn == NULL) {
			cvm_tasks[i].fn = fn;
			cvm_tasks[i].fn_arg = fn_arg;
			cvm_tasks[i].interval = interval;
			cvm_tasks[i].time_to_call = cvmx_get_cycle() + interval;
			break;
		}
	}
	cvmx_spinlock_unlock(&cvmcs_task_lock);

	return (i == MAX_CVMCS_TASKS);
}

int cvmcs_common_remove_task(int (*fn) (void *), void *fn_arg)
{
	int i;

	cvmx_spinlock_lock(&cvmcs_task_lock);
	for (i = 0; i < MAX_CVMCS_TASKS; i++) {
		if ((cvm_tasks[i].fn == fn) && (cvm_tasks[i].fn_arg == fn_arg)) {
			cvm_tasks[i].fn = NULL;
			cvm_tasks[i].fn_arg = NULL;
			cvm_tasks[i].interval = 0;
			cvm_tasks[i].time_to_call = 0;
			break;
		}
	}
	cvmx_spinlock_unlock(&cvmcs_task_lock);

	return (i == MAX_CVMCS_TASKS);
}

void cvmcs_common_schedule_tasks(void)
{
	uint64_t cycle = cvmx_get_cycle();
	int i;

	cvmx_spinlock_lock(&cvmcs_task_lock);
	for (i = 0; i < MAX_CVMCS_TASKS; i++) {
		if (cvm_tasks[i].fn && (cycle >= cvm_tasks[i].time_to_call)) {
			cvmx_spinlock_unlock(&cvmcs_task_lock);
			if (cvm_tasks[i].fn(cvm_tasks[i].fn_arg))
				cvmcs_common_remove_task(cvm_tasks[i].fn,
							 cvm_tasks[i].fn_arg);
			cvmx_spinlock_lock(&cvmcs_task_lock);
			cvm_tasks[i].time_to_call =
			    cvmx_get_cycle() + cvm_tasks[i].interval;
		}
	}
	cvmx_spinlock_unlock(&cvmcs_task_lock);
}

void cvmcs_get_nvme_core(uint32_t * nvme_core)
{
	uint32_t i;
	for (i = boot_core+1; i < num_cores; i++)
		if (core_active[i])
			break;
	*nvme_core = i;
	return;
}

/* The display core is the highest multiple of 8 minus one.
 * E.g., 7, 15, 23, etc. If that is not available, use the
 * last active core
 */
void cvmcs_get_display_core(uint32_t * display_core)
{
	uint32_t i;
	int last_active_core = -1;

	//for (i = (num_cores - 1); i >= 0; i--) {
	for (i = (boot_core + num_cores - 1); i >= boot_core; i--) {
		if (core_active[i]) {
			if (last_active_core == -1 )
				last_active_core = i;
			if ((i & 0x7) == 7) {
				*display_core = i;
				break;
			}
		}
	}

	if (*display_core == 0)
		*display_core = last_active_core;

	return;
}

/* The link status core is the highest-numbered core, unless that is already
 * assigned to be the display core.  In that case, the link status core is
 * the second highest-numbered core.
 */
void cvmcs_get_link_status_core(uint32_t *link_status_core)
{
	struct cvmx_sysinfo *si;
	int core;

	si = cvmx_sysinfo_get();

	core = cvmx_coremask_get_last_core(&si->core_mask);

	if (core > 0 && (uint32_t)core == display_core) {
		for (core--; core >= 0; core--) {
			if (core_active[core])
				break;
		}
	}

	*link_status_core = (uint32_t)core;
}

extern void cvmx_helper_cfg_show_cfg(void);

/** Global initialization. Performed by the boot core only. */
int cvmcs_app_init_global()
{
	memset(cvm_tasks, 0, sizeof(struct __cvmcs_tasks) * MAX_CVMCS_TASKS);
	cvmx_spinlock_init(&cvmcs_task_lock);

	if(cvm_app_nic_cap_init())
		return 1;

	/* Initialize PCI driver */
	if (cvm_drv_init())
		return 1;

	return 0;
}

/** Local initialization. Performed by all cores. */
int cvmcs_app_init_local()
{
	/* Allocate a command buffer for PKO */
	cvmx_pko_initialize_local();

	/* Scratch pad initialization for core PCI driver */
	cvm_drv_local_init();

	/* Make sure we are not in NULL_NULL POW state
	   (if we are, we can't output a packet) */
	cvmx_pow_work_request_null_rd();

	CVMX_SYNCW;
	return 0;
}

/** Application shutdown. Disable and shutdown PKO and FPA pools. */
int cvmcs_app_shutdown()
{
	int result = 0;
	int status;
	int pool;
	cvmx_fpa_ctl_status_t fpa_status;
	cvmx_pko_enable_t pko_enable;

	printf("# cvmcs: cvmcs_shutdown() called...\n");
	cvmx_pko_shutdown();

	for (pool = 0; pool < CVMX_FPA_NUM_POOLS; pool++) {
		if (cvmx_fpa_get_block_size(pool) > 0) {
			status = cvmx_fpa_shutdown_pool(pool);
			/* Special check to allow PIP to lose packets due to hardware prefetch */
			if ((pool == CVMX_FPA_PACKET_POOL) && (status > 0)
			    && (status < CVMX_PIP_NUM_INPUT_PORTS))
				status = 0;
			result |= status;
		}
	}

	fpa_status.u64 = 0;
	cvmx_write_csr(CVMX_FPA_CTL_STATUS, fpa_status.u64);
	if (octeon_has_feature(OCTEON_FEATURE_PKO3)) {
	    pko_enable.u64 = 0;
	    cvmx_write_csr_node(cvmx_get_node_num(), CVMX_PKO_ENABLE, pko_enable.u64);
	} else {
		fpa_status.u64 = 0;
		cvmx_write_csr(CVMX_FPA_CTL_STATUS, fpa_status.u64);
		cvmx_pko_disable();
	}

	printf("# cvmcs: cvmcs_shutdown() completed.\n");
	return result;
}

void cvmcs_app_duty_cycle_actions(uint64_t cycles)
{
	static cvmx_pko_port_status_t last_stat[4] = {{0,}};
	cvmx_pko_port_status_t stat;
	int i, first_port = 32, num_ports = 4;
	uint64_t sso_cnt = 0;

	if (OCTEON_IS_OCTEON3()) {
		first_port = 0x100;
		num_ports = 128;  /* 0x100 - 0x17F */
	}
	if (OCTEON_IS_MODEL(OCTEON_CN68XX)) {
		first_port = 0x100;
		num_ports = 32;
	}
	for (i = first_port; i < (first_port + num_ports); i++) {
		cvmx_pko_get_port_status(i, 0, &stat);
		if (stat.packets || stat.doorbell)
			DBG2("PKO%d: %10u pps (%10u)  db: %8llu\n", i,
			     (unsigned)((stat.packets-last_stat[i-first_port].packets)/(cycles/cpu_freq)),
			     stat.packets, cast64(stat.doorbell));
		memcpy(&last_stat[i-first_port], &stat, sizeof(stat));
	}
	for (i = 0; i < 64; i++) {
		sso_cnt += cvmx_read_csr(CVMX_SSO_GRPX_AQ_CNT(i));
	}
	DBG2("Total SSO packet count %lu\n", sso_cnt);


	print_pool_count_stats();
}

#define L2C_0 0
#define L2C_1 1
#define L2C_2 2
#define L2C_3 3

/* Configure and clear L2 cache performance registers */
void cvmcs_config_l2c_perf()
{
	union cvmx_l2c_tadx_prf l2c_tadx_prf;
	int tad;

	l2c_tadx_prf.u64 = cvmx_read_csr(CVMX_L2C_TADX_PRF(0)); 
	l2c_tadx_prf.s.cnt0sel = CVMX_L2C_TAD_EVENT_TAG_HIT;
	l2c_tadx_prf.s.cnt1sel = CVMX_L2C_TAD_EVENT_TAG_MISS;
	l2c_tadx_prf.s.cnt2sel = CVMX_L2C_TAD_EVENT_TAG_VICTIM;
	l2c_tadx_prf.s.cnt3sel = CVMX_L2C_TAD_EVENT_TAG_NOALLOC;

	for (tad = 0; tad < CVMX_L2C_TADS; tad++) {
		cvmx_write_csr(CVMX_L2C_TADX_PRF(tad), l2c_tadx_prf.u64);
		cvmx_write_csr(CVMX_L2C_TADX_PFCX(L2C_0, tad), 0);
		cvmx_write_csr(CVMX_L2C_TADX_PFCX(L2C_1, tad), 0);
		cvmx_write_csr(CVMX_L2C_TADX_PFCX(L2C_2, tad), 0);
		cvmx_write_csr(CVMX_L2C_TADX_PFCX(L2C_3, tad), 0);
	}

}

void cvmcs_print_l2c_stats(uint64_t cycles)
{
	uint64_t hit, miss, noalloc, victim, total;
	int tad = 0;

	hit     = cvmx_l2c_read_perf(L2C_0);
	miss    = cvmx_l2c_read_perf(L2C_1);
	victim  = cvmx_l2c_read_perf(L2C_2);
	noalloc = cvmx_l2c_read_perf(L2C_3);
	total = hit + miss;

	DBG2("L2C: Hits/sec: %llu  Hit:%3u.%02u%%  Victim:%3u.%02u%% ",
	     (unsigned long long)hit/(cycles/cpu_freq),
	     total ? (unsigned)((hit * 100) / total) : 0,
	     total ? (unsigned)(((hit * 10000) / total) % 100) : 0,
	     miss ? (unsigned)((victim * 100) / miss) : 0,
	     miss ? (unsigned)(((victim * 10000) / miss) % 100) : 0);

	if (noalloc) {
		DBG2("NoAlloc: %3u.%02u%%\n",
	     total ? (unsigned)((noalloc * 100) / total) : 0,
	     total ? (unsigned)(((noalloc * 10000) / total) % 100) : 0);
	}
	DBG2("\n");

	for (tad = 0; tad < CVMX_L2C_TADS; tad++) {
		cvmx_write_csr(CVMX_L2C_TADX_PFCX(L2C_0, tad), 0);
		cvmx_write_csr(CVMX_L2C_TADX_PFCX(L2C_1, tad), 0);
		cvmx_write_csr(CVMX_L2C_TADX_PFCX(L2C_2, tad), 0);
		cvmx_write_csr(CVMX_L2C_TADX_PFCX(L2C_3, tad), 0);
	}
}

void cvmcs_print_core_info()
{
	int ptrsize = sizeof(void *);
	char mode[8];

	strcpy(mode,
	       (ptrsize == 4) ? "32-bit" : (ptrsize ==
					    8) ? "64-bit" : "unknown");
	printf("Cores: %llu MHz (boot: %d, disp: %d, ctrl: %d, ls: %d),"
	       " %s app\n", cast64(cpu_freq)/1000000, boot_core, display_core,
	       control_core, link_status_core, mode);
}

/** MAIN */
int cvmcs_app_bringup(int nvme_active, struct cvmx_app_hotplug_callbacks *hpcb)
{
	//int  i;

	/* Call the simple exec application init routine. This will do the
	   required initialization for linux and plain simple exec apps. */
	cvmx_user_app_init();
	core_id = cvmx_get_core_num();
	core_active[core_id] = 1;

	cvmcs_app_barrier();

	if (cvmx_is_init_core()) {
		const cvmx_bootmem_named_block_desc_t *desc;

		if ((hpcb != NULL) &&
		    cvmx_bootmem_find_named_block(CVMX_APP_HOTPLUG_INFO_REGION_NAME)) {
			if (cvmx_app_hotplug_register_cb(hpcb, 0, 1)) {
				registered_for_hotplug = false;
			} else {
				registered_for_hotplug = true;
			}
		} else {
			registered_for_hotplug = false;
		}

		desc = cvmx_bootmem_find_named_block("__live_upgrade_ctx");
		if (desc) {
			booting_for_the_first_time = false;
			live_upgrade_ctx = cvmx_phys_to_ptr(desc->base_addr);
		} else {
			booting_for_the_first_time = true;
			live_upgrade_ctx = cvmx_bootmem_alloc_named(sizeof (cvmcs_live_upgrade_ctx_t), CVMX_CACHE_LINE_SIZE, "__live_upgrade_ctx");
		}

		boot_core = core_id;

		/* Save the frequency of the cpu for later use */
		cpu_freq = cvmx_sysinfo_get()->cpu_clock_hz;

		num_cores = cvmx_octeon_num_cores();
		if (!booting_for_the_first_time)
			printf("%u cores are running the new app\n", cvmx_coremask_get_core_count(&(cvmx_sysinfo_get()->core_mask)));

		cvmcs_get_display_core(&display_core);

		/* Use the same core as the boot core for control */
		control_core = boot_core;

		cvmcs_get_link_status_core(&link_status_core);

		// Allocate core for NVME polling task. This goes away with 73xx.
		if (nvme_active)
			cvmcs_get_nvme_core(&nvme_core);

		cvmcs_print_core_info();
	}

	cvmx_create_tim_named_block_once();

	cvmcs_app_barrier();

	if (registered_for_hotplug)
		cvmx_app_hotplug_activate();

	return 0;
}

void cvmcs_app_barrier()
{
	if (!is_core_being_hot_plugged())
		cvmx_coremask_barrier_sync(&(cvmx_sysinfo_get()->core_mask));
}

int is_control_core(uint32_t core_id)
{
	return (core_id == control_core);
}

int is_boot_core(uint32_t core_id)
{
	return (core_id == boot_core);
}

int is_nvme_core(uint32_t core_id)
{
	return (core_id == nvme_core);
}

int is_display_core(uint32_t core_id)
{
	return (core_id == display_core);
}

int is_link_status_core(uint32_t core_id)
{
	return (core_id == link_status_core);
}

uint8_t *cvmcs_app_get_macaddr_base()
{
	return cvmx_sysinfo_get()->mac_addr_base;
}

/* $Id$ */
