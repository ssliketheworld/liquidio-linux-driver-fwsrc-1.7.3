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
*  \brief Defines the namespaces and associated data for NVMe.
*
* !!!!!!!!!!!! DO NOT EDIT THIS FILE. IT IS AUTOMATICALLY GENERATED !!!!!!!!!!!!
* 
*******************************************************************************/

#include "nvme_cvm.h"

/*
 * Controller Associativity table (CAT)
 *
 * Gives possible namespace associations for each of 1028 controllers
 * (pf and vf). Zero namespaces mark empty entries. For each controller
 * slot, give a list of the logical namespace numbers that are to be
 * linked to that controller.
 *
 * Terminate this table with zero.
 */
uint32_t ns_cat[NVME_NUM_PFVF][MAX_NUMBER_NS_CTLR] = {
	{ 0, }, // controller 0
};
/*
 * Namespace ram sharing table
 *
 * Each namespace can be set to share its ram block with another namespace.
 * This is an array of namespace numbers, one per "live" namespace control
 * structures. If the namespace is 0, the ram block is not shared, but created
 * from scratch. If a logical namespace number appears, then the RAM block for
 * the namespace will be obtained from that namespace.
 */
uint32_t ns_share[MAX_NUMBER_NS] = {
	0, // namespace 0
};

/*
 * Namespace mapping policy
 */
CVMX_SHARED uint8_t ns_map_policy = MAP_ONE_TO_ONE;

/*
 * Namespace descriptor table
 */
struct ns_ctrl sal_namespace_tbl[] = {
	// namespace 1
	{
		65536, // disk size in sectors
		512, // sector size
		1, // namespace logical id
		0, // name space  type
		{0}, // namespace base pointer (to be filled in later)
		{
			le64_cpu(0x0000000000010000, ull),  // nsze: name space size
			le64_cpu(0x0000000000010000, ull),  // ncap: name space capacity
			le64_cpu(0x0000000000000000, ull),  // nuse: name space utilization
			0x00, // nsfeat
			0x00, // nlbaf
			0x00, // flbas
			0x00, // mc
			0x00, // dpc
			0x00, // dps
			0x00, // nmic
			0x00, // rescap
			0x00, // fpi
			0x00, // rsvd33
			le16_cpu(0x0000),                   // nawun:
			le16_cpu(0x0000),                   // nawupf:
			le16_cpu(0x0000),                   // nacwu:
			{ 0, },                             // rsvd40[80]
			{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, // eui64[8]
			{
				{ le16_cpu(0x0000), 0x09, 0x00}, // lba format 0
				{ le16_cpu(0x0000), 0x00, 0x00}, // lba format 1
				{ le16_cpu(0x0000), 0x00, 0x00}, // lba format 2
				{ le16_cpu(0x0000), 0x00, 0x00}, // lba format 3
				{ le16_cpu(0x0000), 0x00, 0x00}, // lba format 4
				{ le16_cpu(0x0000), 0x00, 0x00}, // lba format 5
				{ le16_cpu(0x0000), 0x00, 0x00}, // lba format 6
				{ le16_cpu(0x0000), 0x00, 0x00}, // lba format 7
				{ le16_cpu(0x0000), 0x00, 0x00}, // lba format 8
				{ le16_cpu(0x0000), 0x00, 0x00}, // lba format 9
				{ le16_cpu(0x0000), 0x00, 0x00}, // lba format 10
				{ le16_cpu(0x0000), 0x00, 0x00}, // lba format 11
				{ le16_cpu(0x0000), 0x00, 0x00}, // lba format 12
				{ le16_cpu(0x0000), 0x00, 0x00}, // lba format 13
				{ le16_cpu(0x0000), 0x00, 0x00}, // lba format 14
				{ le16_cpu(0x0000), 0x00, 0x00}, // lba format 15
			}, // lbaf[16]
			{ 0, },  // rsvd192[192]
			{
			00, 
			} // vs[3712]
		}
	},
	// namespace 2
	{
		65536, // disk size in sectors
		512, // sector size
		2, // namespace logical id
		0, // name space  type
		{0}, // namespace base pointer (to be filled in later)
		{
			le64_cpu(0x0000000000010000, ull),  // nsze: name space size
			le64_cpu(0x0000000000010000, ull),  // ncap: name space capacity
			le64_cpu(0x0000000000000000, ull),  // nuse: name space utilization
			0x00, // nsfeat
			0x00, // nlbaf
			0x00, // flbas
			0x00, // mc
			0x00, // dpc
			0x00, // dps
			0x00, // nmic
			0x00, // rescap
			0x00, // fpi
			0x00, // rsvd33
			le16_cpu(0x0000),                   // nawun:
			le16_cpu(0x0000),                   // nawupf:
			le16_cpu(0x0000),                   // nacwu:
			{ 0, },                             // rsvd40[80]
			{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, // eui64[8]
			{
				{ le16_cpu(0x0000), 0x09, 0x00}, // lba format 0
				{ le16_cpu(0x0000), 0x00, 0x00}, // lba format 1
				{ le16_cpu(0x0000), 0x00, 0x00}, // lba format 2
				{ le16_cpu(0x0000), 0x00, 0x00}, // lba format 3
				{ le16_cpu(0x0000), 0x00, 0x00}, // lba format 4
				{ le16_cpu(0x0000), 0x00, 0x00}, // lba format 5
				{ le16_cpu(0x0000), 0x00, 0x00}, // lba format 6
				{ le16_cpu(0x0000), 0x00, 0x00}, // lba format 7
				{ le16_cpu(0x0000), 0x00, 0x00}, // lba format 8
				{ le16_cpu(0x0000), 0x00, 0x00}, // lba format 9
				{ le16_cpu(0x0000), 0x00, 0x00}, // lba format 10
				{ le16_cpu(0x0000), 0x00, 0x00}, // lba format 11
				{ le16_cpu(0x0000), 0x00, 0x00}, // lba format 12
				{ le16_cpu(0x0000), 0x00, 0x00}, // lba format 13
				{ le16_cpu(0x0000), 0x00, 0x00}, // lba format 14
				{ le16_cpu(0x0000), 0x00, 0x00}, // lba format 15
			}, // lbaf[16]
			{ 0, },  // rsvd192[192]
			{
			00, 
			} // vs[3712]
		}
	},
	// end of table */
	{
		0,
		0,
		0,
		0,
		{0},
		{
			0,
		}
	}
};