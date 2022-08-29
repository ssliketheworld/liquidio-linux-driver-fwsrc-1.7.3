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
/* cvm-app.c -  */

#include "global-config.h"
#include "octeon-pci-console.h"
#include "cvmcs-common.h"
#include  <cvmx-atomic.h>
#include  <cvm-core-cap.h>

int
cvm_app_ipsec_setup_memory(void);
int
 cvm_app_ipsec_cap_init(void);

int cvm_app_nic_cap_init(void)
{
	memset(&nic_cap,0,sizeof(ndis_offload));// Initialize nic_cap struct

	if (cvm_app_ipsec_cap_init())
		return 1;
	return 0;
}

int cvm_app_setup_memory(void)
{
	if (cvm_app_ipsec_setup_memory())
		return 1;
	return 0;
}

int cvm_app_process_instr(cvmx_wqe_t * work)
{
	return 1;
}

int cvm_app_setup_mode(void)
{
	return 0;
}

int cvm_app_core_local_init(void)
{
	unsigned core_id;
	core_id = cvmx_get_core_num();
	if (OCTEON_IS_MODEL(OCTEON_CN73XX)) {
		/* enable this core_id's watchdog timer, then kick it */
		cvmx_ciu_wdogx_t wdog;
		wdog.u64 = 0;
		wdog.s.mode = 1;
		wdog.s.len  = 65535;
		cvmx_write_csr(CVMX_CIU_WDOGX(core_id), wdog.u64);
		cvmx_write_csr(CVMX_CIU_PP_POKEX(core_id), 1);
	}
	return 0;
}

int cvm_app_idle_task(void)
{
	return 0;
}
int cvm_app_idle_task_start(int core)
{
	return 0;
}
int cvm_app_idle_task_end(int core)
{
	return 0;
}
