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


/*! \file cvm-drv-resources.h
    \brief Core Driver: Provides scratchpad requirements for Core PCI driver.
*/                                                                                        

#ifndef __CVM_DRV_RESOURCES_CONFIG__
#define __CVM_DRV_RESOURCES_CONFIG__
                                                                                                                                                             
/* Content below this point is only used by the cvmx-config tool, and is
** not used by any C files as CAVIUM_COMPONENT_REQUIREMENT is never
defined.
*/
#ifdef CAVIUM_COMPONENT_REQUIREMENT
	/* global resource requirement */
	cvmxconfig
	{
		scratch CVM_DRV_SCR_WQE_BUF_PTR
			size = 8
			iobdma = true
			permanent = true
			description = "Scratch pad location for WQE buffer pointer";

		scratch CVM_DRV_SCR_PACKET_BUF_PTR
			size = 8
			iobdma = true
			permanent = true
			description = "Scratch pad location for Packet pool buffer pointer";

	}
#endif

#endif

/* $Id$ */

