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


/*! 
 * @file executive-config.h.template
 *
 * This file is a template for the executive-config.h file that each
 * application that uses the simple exec must provide.  Each application
 * should have an executive-config.h file in a directory named 'config'.
 * If the application uses other components, config files for those
 * components should be placed in the config directory as well.  The 
 * macros defined in this file control the configuration and functionality
 * provided by the simple executive.  Available macros are commented out
 * and documented in this file.
 */

/*
 * File version info: $Id$
 * $Name$
 */
#ifndef __EXECUTIVE_CONFIG_H__
#define __EXECUTIVE_CONFIG_H__

/* Define to enable the use of simple executive DFA functions */
//#define CVMX_ENABLE_DFA_FUNCTIONS

/* Define to enable the use of simple executive packet output functions.
** For packet I/O setup enable the helper functions below. 
*/ 
#define CVMX_ENABLE_PKO_FUNCTIONS

/* Define to enable the use of simple executive timer bucket functions. 
** Refer to cvmx-tim.[ch] for more information
*/
//#define CVMX_ENABLE_TIMER_FUNCTIONS

/* Define to enable the use of simple executive helper functions. These
** include many harware setup functions.  See cvmx-helper.[ch] for
** details.
*/
#define CVMX_ENABLE_HELPER_FUNCTIONS

/* CVMX_HELPER_FIRST_MBUFF_SKIP is the number of bytes to reserve before
** the beginning of the packet. If necessary, override the default  
** here.  See the IPD section of the hardware manual for MBUFF SKIP 
** details.*/
#define CVMX_HELPER_FIRST_MBUFF_SKIP 248

/* CVMX_HELPER_NOT_FIRST_MBUFF_SKIP is the number of bytes to reserve in each
** chained packet element. If necessary, override the default here */
#define CVMX_HELPER_NOT_FIRST_MBUFF_SKIP 0

/* CVMX_HELPER_ENABLE_BACK_PRESSURE controls whether back pressure is enabled
** for all input ports. If necessary, override the default here */
#define CVMX_HELPER_ENABLE_BACK_PRESSURE 0

/* CVMX_HELPER_ENABLE_IPD controls if the IPD is enabled in the helper
**  function. Once it is enabled the hardware starts accepting packets. You
**  might want to skip the IPD enable if configuration changes are need
**  from the default helper setup. If necessary, override the default here */
#define CVMX_HELPER_ENABLE_IPD 0

/* CVMX_HELPER_INPUT_TAG_TYPE selects the type of tag that the IPD assigns
** to incoming packets. */
#define CVMX_HELPER_INPUT_TAG_TYPE CVMX_POW_TAG_TYPE_ORDERED

#define CVMX_HELPER_NPI_MAX_PKNDS 2

/* Define it for the applications which requires a 5-tuple "flow tag".
 * Ex: 1) FLOW_BASED_DISTRIBUTION feature requires the flow tag to
 * distribute the packets across all the output queues (OQs).
 * Ex: 2)
 */
#define FLOW_TAG



/* The following select which fields are used by the PIP to generate
** the tag on INPUT
** 0: don't include
** 1: include */
#if defined(FLOW_TAG)

#define CVMX_HELPER_INPUT_TAG_IPV6_SRC_IP	1
#define CVMX_HELPER_INPUT_TAG_IPV6_DST_IP   	1
#define CVMX_HELPER_INPUT_TAG_IPV6_SRC_PORT 	1
#define CVMX_HELPER_INPUT_TAG_IPV6_DST_PORT 	1
#define CVMX_HELPER_INPUT_TAG_IPV6_NEXT_HEADER 	1
#define CVMX_HELPER_INPUT_TAG_IPV4_SRC_IP	1
#define CVMX_HELPER_INPUT_TAG_IPV4_DST_IP   	1
#define CVMX_HELPER_INPUT_TAG_IPV4_SRC_PORT 	1
#define CVMX_HELPER_INPUT_TAG_IPV4_DST_PORT 	1
#define CVMX_HELPER_INPUT_TAG_IPV4_PROTOCOL	1
#define CVMX_HELPER_INPUT_TAG_INPUT_PORT	0

#else

#define CVMX_HELPER_INPUT_TAG_IPV6_SRC_IP	0
#define CVMX_HELPER_INPUT_TAG_IPV6_DST_IP   	0
#define CVMX_HELPER_INPUT_TAG_IPV6_SRC_PORT 	0
#define CVMX_HELPER_INPUT_TAG_IPV6_DST_PORT 	0
#define CVMX_HELPER_INPUT_TAG_IPV6_NEXT_HEADER 	0
#define CVMX_HELPER_INPUT_TAG_IPV4_SRC_IP	0
#define CVMX_HELPER_INPUT_TAG_IPV4_DST_IP   	0
#define CVMX_HELPER_INPUT_TAG_IPV4_SRC_PORT 	0
#define CVMX_HELPER_INPUT_TAG_IPV4_DST_PORT 	0
#define CVMX_HELPER_INPUT_TAG_IPV4_PROTOCOL	0
#define CVMX_HELPER_INPUT_TAG_INPUT_PORT	1

#endif /* FLOW_TAG */

/* Select skip mode for input ports */
#define CVMX_HELPER_INPUT_PORT_SKIP_MODE	CVMX_PIP_PORT_CFG_MODE_SKIPL2

/* Define the number of queues per output port */
#define CVMX_HELPER_PKO_QUEUES_PER_PORT_INTERFACE0	1
#define CVMX_HELPER_PKO_QUEUES_PER_PORT_INTERFACE1	1

#define CVMX_PKO_QUEUES_PER_PORT_PCI	((!OCTEON_IS_MODEL(OCTEON_CN66XX))?1:8)


/* 1 = Force backpressure to be disabled.  This overrides all other
** backpressure configuration;
** 0 = enable backpressure */
#define CVMX_HELPER_DISABLE_RGMII_BACKPRESSURE 0

/* Select the number of low latency memory ports (interfaces) that
** will be configured.  Valid values are 1 and 2.
*/
#define CVMX_LLM_CONFIG_NUM_PORTS 1

#if defined(CVMX_ENABLE_HELPER_FUNCTIONS) && !defined(CVMX_ENABLE_PKO_FUNCTIONS)
#define CVMX_ENABLE_PKO_FUNCTIONS
#endif

/* SE nic application resource descriptions provided in cvcs-nic-resources.config */
#include "cvmcs-nic-resources.config"

/* CVM PCI Driver resources in cvm-drv-resources.h */
#include "cvm-drv-resources.h"

#endif

/* $Id$ */
