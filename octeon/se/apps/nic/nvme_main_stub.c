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

\file

\brief This module contains the code for processing the nvme commands. This is
the stub module, used when the NVMe function is not present.

*******************************************************************************/

/*---------------------------------------------------------------------------
                                Revision History
    $Log: main.c $
---------------------------------------------------------------------------*/

#include "cvmcs-nic.h"
#include "nvme.h"

/***************************************************************************//**

Test NVME module active

Returns true. In the stubbed version of this module, it returns false.

*******************************************************************************/

int nvme_active(void)
{
	return 0;
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
}

/***************************************************************************//**

Process nvm init and poll

Inits the NVMe core functions, then enters the NVMe polling loop.

This last function disappears when the 73xx is used, and we will just return to
the caller.

*******************************************************************************/

void nvme_process(void)
{
}

/***************************************************************************//**

Process nvm init

Inits the NVMe core functions. This needs to run on an excluded core (single
threaded, only one core running).

*******************************************************************************/

void nvme_init(void)
{
}

void nvme_local_init(void)
{
}

void nvme_deinit(void)
{
}

void nqm_set_vf_mode(char *mode)
{
}

void nvme_set_sata_only_map(void)
{
}

void nvme_set_intr_coalescing_off(void)
{
}

void nvme_set_sq_credits(char *credits)
{
}
void nvme_set_cplq_size(char *size)
{
}
