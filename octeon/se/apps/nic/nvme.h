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
 * \file
 *
 * \brief    This file contains definitions for the external interface of NVMe
 *           as an OCTEON application module.
 *
 * This file is separate from the other header files because it features only
 * the external interface definitions for the NVMe module, that is, what
 * objects within the NVMe module are needed to initialize it, operate it, and
 * tear it down within the OCTEON/SE environment.
*******************************************************************************/

#ifndef __NVME_EXT_H__
#define __NVME_EXT_H__

int nvme_active(void);
void nvme_process_wqe(cvmx_wqe_t* wqe);
void nvme_process(void);
void nvme_init(void);
void nvme_local_init(void);
void nvme_deinit(void);
void nqm_set_vf_mode(char *args);
void nvme_set_sata_only_map(void);
void nvme_set_intr_coalescing_off(void);
void nvme_set_sq_credits(char *args);
void nvme_set_cplq_size(char *size);

#endif
