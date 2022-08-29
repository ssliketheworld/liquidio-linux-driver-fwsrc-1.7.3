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

#ifndef __CVMCS_NIC_SWITCH_H__
#define __CVMCS_NIC_SWITCH_H__

#include "cvmcs-nic-mdata.h"

typedef struct mbcast_sched_node {
	struct list_head list;
        int64_t subone;
        cvmx_wqe_t *head;
} mbcast_sched_node_t;

typedef struct mbcast_sched_list{
	struct list_head list;
        int count;
        cvmx_spinlock_t lock;
} mbcast_sched_list_t;

void cvmcs_nic_put_l4checksum_ipv4(cvmx_wqe_t * wqe, int offset);
void cvmcs_nic_put_l4checksum_ipv6_with_exthdr(cvmx_wqe_t * wqe, int offset);
union octeon_rh *cvmcs_nic_insert_dpi_headers(cvmx_wqe_t *wqe, int ifidx, pkt_proc_flags_t *flags);
void cvmcs_nic_delete_first_buffer(cvmx_wqe_t *wqe);
int cvmcs_nic_get_rxq(cvmx_wqe_t *wqe, uint32_t *hash, int ifidx);
int cvmcs_nic_switch_packets_from_gmx(cvmx_wqe_t *wqe);
int cvmcs_nic_switch_packets_from_dpi(cvmx_wqe_t *wqe);
int cvmcs_nic_start_mbcast_list_task();
int cvmcs_nic_init_mbcast_list(void);

static inline uint32_t cvmcs_nic_pkt_steer_tag(cvmx_wqe_t *wqe)
{
#ifdef VSWITCH
	cvmcs_nic_metadata_t *mdata = CVMCS_NIC_METADATA(wqe);
	return ((CVMCS_NIC_METADATA_FW_CRC(mdata) + cvmx_wqe_get_tag(wqe)) & 0xffff);
#else
	return (cvmx_wqe_get_tag(wqe) & 0xffff);
#endif
}
static inline void set_queue_in_pkt_steering_table(cvmx_wqe_t *wqe)
{
	uint8_t q_no;
	cvmcs_nic_metadata_t *mdata = CVMCS_NIC_METADATA(wqe);
	vnic_port_info_t *nicport = &octnic->port[mdata->from_ifidx];
	uint32_t tag = cvmcs_nic_pkt_steer_tag(wqe);
	uint32_t index = PKT_STEERING_TABLE_INDEX(tag);
	pkt_steering_entry_t entry;

	q_no = (mdata->from_port & 0xff) - nicport->iq_base;
	
	entry.word1.u64 = 0;
	entry.word1.s.q_no = q_no;
	entry.word1.s.tag = tag;

	if (nicport->pkt_steering_table[index].word1.u64 != entry.word1.u64) {
		uint64_t last_updated = nicport->pkt_steering_table[index].last_updated;
		uint64_t now = cvmx_get_cycle();
		uint64_t cycles = CYCLE_DIFF(now, last_updated);

		if (nicport->pkt_steering_update_intrvl < cycles) {
			nicport->pkt_steering_table[index].word1.u64 = entry.word1.u64;
			nicport->pkt_steering_table[index].last_updated = now;
		}
	}
}

static inline uint8_t get_queue_from_pkt_steering_table(vnic_port_info_t *nicport, cvmx_wqe_t *wqe)
{
	uint32_t tag = cvmcs_nic_pkt_steer_tag(wqe);
	uint32_t index = PKT_STEERING_TABLE_INDEX(tag);
	uint8_t q_no;

	if (nicport->pkt_steering_table[index].word1.s.tag == tag) {
		q_no = nicport->pkt_steering_table[index].word1.s.q_no;
		q_no = q_no% nicport->linfo.num_rxpciq;
		nicport->pkt_steering_table[index].last_updated = cvmx_get_cycle();
	} else {
		q_no = tag % nicport->linfo.num_rxpciq;
	}

	return q_no;
}

#endif /*__CVMCS_NIC_SWITCH_H__*/
