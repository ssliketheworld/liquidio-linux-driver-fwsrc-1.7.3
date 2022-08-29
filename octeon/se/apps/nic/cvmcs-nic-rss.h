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
#ifndef __CVMCS_NIC_RSS_H__
#define __CVMCS_NIC_RSS_H__

/* NOTE: these MUST match Windows NDIS definitions */
#define RSS_PARAM_DISABLE_RSS           0x10
#define RSS_PARAM_HASH_KEY_UNCHANGED    0x08
#define RSS_PARAM_ITABLE_UNCHANGED      0x04
#define RSS_PARAM_HASH_INFO_UNCHANGED   0x02
#define RSS_PARAM_BASE_CPU_UNCHANGED    0x01

#define RSS_HASH_IPV4                   0x100
#define RSS_HASH_TCP_IPV4               0x200
#define RSS_HASH_IPV6                   0x400
#define RSS_HASH_TCP_IPV6               0x1000

#define RSS_HASH_IPV6_EX                0x800
#define RSS_HASH_TCP_IPV6_EX            0x2000

#define OCTNET_CMD_SET_RSS          	0xD
#define OCTNIC_RSS_MAX_TABLE_SZ     	128
#define OCTNIC_RSS_MAX_KEY_SZ       	40


typedef struct oct_rss_set {
	struct param {
#if __CAVIUM_BYTE_ORDER  ==  __CAVIUM_LITTLE_ENDIAN
		uint64_t flags                  : 16;
		uint64_t hashinfo               : 32;
		uint64_t itablesize             : 16;

		uint64_t hashkeysize    : 16;
		uint64_t reserved               : 48;
#else
		uint64_t itablesize             : 16;
		uint64_t hashinfo               : 32;
		uint64_t flags                  : 16;

		uint64_t reserved               : 48;
		uint64_t hashkeysize    : 16;
#endif
	} param;

	uint8_t Itable[OCTNIC_RSS_MAX_TABLE_SZ];
	uint8_t Key[OCTNIC_RSS_MAX_KEY_SZ];

} oct_rss_params_t;

#define CAVIUM_RSS_PARAM_SIZE 16

typedef struct oct_rss_ctx {
	uint16_t cnnic_rss_hash_key_size;
	uint8_t  cnnic_rss_hash_key[OCTNIC_RSS_MAX_KEY_SZ];
	uint8_t  cnnic_rss_itable[OCTNIC_RSS_MAX_TABLE_SZ];
	uint8_t  cnnic_rss_itable_size;
	uint8_t  cnnic_rss_itable_bits;
	uint32_t cnnic_hashinfo;
	uint32_t cnnic_rss_hash[OCTNIC_RSS_MAX_KEY_SZ * 2][16];
	uint32_t cnnic_rss_hash_mask;
} oct_rss_state_t;

int cvmcs_alloc_or_find_rss_state_array(void);
int cvmcs_nic_set_rss_params(cvmx_wqe_t *wqe, int front_size);
int cvmcs_nic_rss_get_queue(cvmx_wqe_t *wqe, uint32_t *hash, uint32_t *hashtype, int ifidx);
void cvmcs_print_rss_config();

#endif /* __CVMCS_NIC_RSS_H__ */
