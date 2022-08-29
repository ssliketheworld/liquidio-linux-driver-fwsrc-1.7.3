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

#ifndef   __CVMCS_NIC_DEFS_H__
#define   __CVMCS_NIC_DEFS_H__

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

#include "cvmx.h"
#include "cvmx-wqe.h"

/* Enable this define to let the application print information at regular
   intervals */
#define CVMCS_DUTY_CYCLE

/* Interval in seconds after which the duty cycle prints information. */
#define DISPLAY_INTERVAL         30

#define LINK_CHECK_INTERVAL_MS    1

/* Maximum number of cores the application supports. */
/* OCTEON-III supports max of 48 cores. */
#define MAX_CORES                48 //32

#define CVMCS_FIRST_CORE         cvmx_coremask_get_first_core(&(cvmx_sysinfo_get()->core_mask))
#define CVMCS_LAST_CORE          cvmx_coremask_get_last_core(&(cvmx_sysinfo_get()->core_mask))


//TODO review
#define  CFG_CTRL_Q_GRP       1

/* number of times to monitor OQ's BGX AURA for queue stuck condition per sec */
#define BGX_OQ_TASK_SCHED_HZ 10 /* similar to Linux HZ; run 10 times in a sec */

/* Maximum number of Output queues */
#define MAX_OCTEON_OQ 128
/* time duration to monitor before declaring a DQ is stuck (not processed) */
#define PKO_DQ_STUCK_THRESH_INTVL 300 /* in msec */

/* if the WM_CNT of a DQ crosses this threshold, start monitoring for possible
 * OQ stuck condition and execute DQ-flush if the queue is found stuck
 **/
#define DQ_FLUSH_THRESHOLD_73XX 16

/* Use nqm_scratch for firmware-octlinux sync */
#define NQM_BIT_FW_IN_SYNC 63

#endif

/* $Id$ */
