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

#ifndef __APP_CONFIG_H__
#define __APP_CONFIG_H__

/***************************************************************************//**

*
*  \file
*
*  \brief No idea what this module does.
*

*******************************************************************************/

/************************* FPA allocation *********************************/
/**
 *  Pool sizes in bytes, must be multiple of a cache line
 *  Any of the following structures change, buffer size need to be calculated
 *  and changed accordingly
 *  1. Work Queue Entry 			(struct cvmx_wqe_tt)
 *  2. PRP List Transfer Info		(struct prp_list_transfer_info)
 *  3. Completion Queue Update		(struct cpl_queue_update)
 *  4. Device Host Page size		(dev->host_page_size)
 *  5. List Node					(struct list_node)
 *  6. Context structure for I/O DMA (struct context_struct)
 *
 *  Note :
 *  Pool size for all FPA pools determined at run time.
 *
 */

/* Pools in use */

/**< PRP List Transfer info pool ID */
#define PRP_LIST_TRANSF_INFO_POOL           (CVMX_FPA_WQE_POOL)
//#define PRP_LIST_TRANSF_INFO_POOL_BUFFER_SIZE		(10240)

/**< Completion Queue Update pool ID */
#define CPL_QUEUE_UPDATE_POOL               (CVMX_FPA_WQE_POOL)
//#define CPL_QUEUE_UPDATE_POOL_BUFFER_SIZE			(102400)

/**< Device Host Page size pool ID */
// until host is ready
#define DEV_HOST_PAGE_SIZE_POOL				(CVMX_FPA_NVME_HOST_PAGE_POOL)
#define DEV_HOST_PAGE_SIZE_POOL_COUNT			(16*8*256)

/**< List Node pool ID */
#define LIST_NODE_POOL                      (CVMX_FPA_WQE_POOL)
//#define LIST_NODE_POOL_BUFFER_SIZE			(2048)

/**< Context structure for I/O DMA */
#define CONTEXT_STRUCT_IO_DMA_POOL          (CVMX_FPA_WQE_POOL)
//#define CONTEXT_STRUCT_IO_DMA_POOL_BUFFER_SIZE		(102400)

#endif /* __APP_CONFIG_H__ */
