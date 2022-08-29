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

#ifndef __CVMCS_NIC_H__
#define __CVMCS_NIC_H__

#include <stdio.h>
#include <string.h>

#include "cvmx-config.h"
#include "cvm-common-lib.h"
#include "cvmx.h"
#include "cvmx-sysinfo.h"
#include "cvmx-rwlock.h"

#include "cvmcs-common.h"
#include "cvm-driver-defs.h"
#include "cvm-drv.h"
#include "cvm-drv-debug.h"

#include "cvmcs-nic-defs.h"
#include "cvmcs-nic-ip.h"
#include "cvmcs-nic-ipv6.h"
#include "cavium-list.h"
#include "cvmcs-nic-ether.h"
#include <cvmx-tim.h>
#include "liquidio_common.h"
#include "cvmcs-dcb.h"
#include "cvmcs-nic-printf.h"

#define printf cvmcs_printf

#define ENOIF       1
#define EMBCAST     2
#define ENOTFWD     3
#define EBADPACKET  4
#define ENOMEM      12

#define DPI_BP
#define GMX_BP

/* how much buildup of packets do we want before the packets start getting dropped */
#define DPI_BP_THRESHOLD_66XX        1024
/* how frequently do we want to update BP counters (this is fau count not time) */
#define DPI_BP_HANDLE_INTERVAL_66XX   128

#define DPI_BP_THRESHOLD_68XX	      512
#define DPI_BP_HANDLE_INTERVAL_68XX   64

#define GMX_BP_THRESHOLD_66XX	      1024
#define GMX_BP_HANDLE_INTERVAL_66XX   128

#define GMX_BP_THRESHOLD_68XX	      512
#define GMX_BP_HANDLE_INTERVAL_68XX   64

#define DPI_BP_THRESHOLD_78XX          256
#define GMX_BP_THRESHOLD_78XX          1024
#define MAX_LRO_CTX_PER_GMX            100
#define MAX_LRO_PACKETS_PER_GMX        ((GMX_BP_THRESHOLD_78XX >> 2) * 3)

#define OCT_NIC_TSO_COMPLETION_OP	127
#define OCT_NIC_LRO_TIMER_OP		126
#define OCT_NIC_LRO_COMPLETION_OP	125

#define OCT_NIC_FLR_BH_OP		124

enum flr_bh_event {
	FLR_BH_START,
	FLR_BH_CONTINUE_INACTIVE,
	FLR_BH_CONTINUE_ACTIVE,
	FLR_BH_FINALIZE,
	FLR_BH_COMPLETED
};

/* QPG group */
#define OCTEON_DATA_GRP         0
#define OCTEON_CTRL_GRP_VF      1
#define OCTEON_CTRL_GRP_PF      2

/* This define is the POW group this program uses for packet
 * interception. Packets from routed to this POW group
 * instead of going to Linux core
 */
#define SE_POW_GROUP     (octeon_has_feature(OCTEON_FEATURE_CN78XX_WQE) ? 24 : 0) 

/* This group is for octlinux cores
 *  *  */
#define LINUX_POW_DATA_GROUP  (octeon_has_feature(OCTEON_FEATURE_CN78XX_WQE) ?  63 : 14)
#define LINUX_POW_CTRL_GROUP  62

/* SSO group Priority(0-7) 0 is highest priority, 7 is the lowest */

#define OCTEON_CTRL_GRP_PF_PRI  0
#define OCTEON_CTRL_GRP_VF_PRI  1
#define OCTEON_DATA_GRP_PRI     2

#define DELAY_DELETE_SA
#ifdef DELAY_DELETE_SA
#define OCT_NIC_DELETE_SA_TIMER_OP	123

/* 2ms period */
#define DELETE_SA_TIMER_TICKS_MS        (2 * 1000 / (NIC_TIMER_PERIOD_US))
#endif // DELAY_DELETE_SA

/* 10ms period */
#define MBCAST_TIMER_TICKS_MS           (10 * 1000 / (NIC_TIMER_PERIOD_US))

#define NIC_TIMER_PERIOD_US             1000

#define LED_ID_FLASH_INTERVAL_HZ        2

/* Look at octeon_rh.r_nic_info.ifidx as well if you change this: */
#define MAX_OCTEON_NIC_PORTS		256
#define OCT_NIC_PORT_IDX(pf,vf)		((pf << 6) | vf)
#define OCT_NIC_PORT_PF(idx)		(idx >> 6)
#define OCT_NIC_PORT_VF(idx)		(idx & 0x3F)
#define OCT_NIC_VFS_PER_PF		64
#define OCT_NIC_IS_PF(idx)              (OCT_NIC_PORT_VF(idx) == 0)
#define OCT_NIC_IS_VF(idx)              (OCT_NIC_PORT_VF(idx) != 0)

#define OCT_NIC_IQ_NUM(nicport,idx)	((nicport)->linfo.txpciq[idx].s.q_no + (nicport)->iq_base)
#define OCT_NIC_OQ_NUM(nicport,idx)	((nicport)->linfo.rxpciq[idx].s.q_no + (nicport)->oq_base)

#define MAX_OCTEON_GMX_PORTS		8
#define MAX_OCTEON_GMX_CHANNELS		8

#define MAX_MCAST_ENTRIES  (MAX_OCTEON_MULTICAST_ADDR*MAX_OCTEON_NIC_PORTS)
#define MCAST_LUT_SIZE     32
#define MCAST_LUT_MASK     (MCAST_LUT_SIZE-1)

#define PKT_STEERING_BITS_COUNT			10
#define PKT_STEERING_TABLE_SIZE			(1 << PKT_STEERING_BITS_COUNT)
#define PKT_STEERING_MASK			(PKT_STEERING_TABLE_SIZE - 1)
#define PKT_STEERING_TABLE_INDEX(_tag)		((_tag >> (16 - PKT_STEERING_BITS_COUNT)) & PKT_STEERING_MASK)
#define PKT_STEERING_UPDATE_INTRVL		1000	/* in milli seconds */

typedef struct pkt_steering_entry {
	union word1_w {
		uint64_t u64;
		struct pkt_steering_entry_s {
			uint64_t q_no		: 8;
			uint64_t tag		: 16;
			uint64_t reserved	: 40;
		} s;
	} word1;
	uint64_t last_updated;

} pkt_steering_entry_t;

#define cvmx_atomic_add_u64(ptr, val)   cvmx_atomic_add64((int64_t *)ptr, val)
#define cvmx_atomic_add_u32(ptr, val)   cvmx_atomic_add32((int32_t *)ptr, val)
#define cvmx_atomic_set_u32(ptr, val)   cvmx_atomic_set32((int32_t *)ptr, val)

#define IANA_DEFAULT_VXLAN_PORT         4789
#define LINUX_DEFAULT_VXLAN_PORT        8472

#define LINUX_DEFAULT_VXLAN_BIT         0x01
#define IANA_DEFAULT_VXLAN_BIT          0x02

/* VxLAN DB Macro*/
#define MIN_VXLAN_PORT 1                /* Minimum VxLAN port to be used */
#define MAX_VXLAN_PORT 65535            /* Maximum VxLAN port to be used */
#define MAX_VXLAN_PORT_DATA_SIZE 64     /* Data Size of array element */
/* Maximum size of VxLAN port array */
#define MAX_VXLAN_PORT_MASK_SIZE (MAX_VXLAN_PORT - MIN_VXLAN_PORT + 2) / MAX_VXLAN_PORT_DATA_SIZE

/* MACRO to identify the relative port index using the MAX VxLAN port information */
#define VXLAN_GET_RELATIVE_PORT(vxlan_port) (vxlan_port - MIN_VXLAN_PORT)
/* MACRO to identify the array index for the VxLAN port DB table */
#define VXLAN_GET_PORT_DB_INDEX(vxlan_port) (VXLAN_GET_RELATIVE_PORT(vxlan_port) / MAX_VXLAN_PORT_DATA_SIZE)
/* MACRO to identify the bit for the selected port inside the VxLAN port DB table index */
#define VXLAN_GET_PORT_DB_BITMASK(vxlan_port) (VXLAN_GET_RELATIVE_PORT(vxlan_port) % MAX_VXLAN_PORT_DATA_SIZE)
/* MACRO to add a port into the VxLAN DB table */
#define VXLAN_ADD_PORT_TO_DB(vxlan_port,ifidx) (octnic->port[ifidx].vxlan_port_db[VXLAN_GET_PORT_DB_INDEX(vxlan_port)] |= (1 << VXLAN_GET_PORT_DB_BITMASK(vxlan_port)))
/* MACRO to delete a port from the VxLAN DB table */
#define VXLAN_DEL_PORT_TO_DB(vxlan_port,ifidx) (octnic->port[ifidx].vxlan_port_db[VXLAN_GET_PORT_DB_INDEX(vxlan_port)] &= ~(1 << VXLAN_GET_PORT_DB_BITMASK(vxlan_port)))
/* MACRO to search an index of port from the VxLAN DB table */
#define VXLAN_FIND_PORT_TO_DB(vxlan_port,ifidx) (octnic->port[ifidx].vxlan_port_db[VXLAN_GET_PORT_DB_INDEX(vxlan_port)] & (1 << VXLAN_GET_PORT_DB_BITMASK(vxlan_port)))

#define VXLAN_FIND_DEFAULT_PORT(vxlan_port,ifidx) \
	(((LINUX_DEFAULT_VXLAN_PORT == vxlan_port) && (octnic->port[ifidx].vxlan_default_ports & LINUX_DEFAULT_VXLAN_BIT)) || \
	((IANA_DEFAULT_VXLAN_PORT == vxlan_port) && (octnic->port[ifidx].vxlan_default_ports & IANA_DEFAULT_VXLAN_BIT)))

#define VXLAN_PORT_COUNT(ifidx)	(octnic->port[ifidx].vxlan_port_count)

#define MAX_GMX_PORTS 8

typedef struct {
	int num_gmx_ports;
	int max_nic_ports;
	int ipd_ports[MAX_GMX_PORTS];
} gmx_conf_t;

extern CVMX_SHARED const gmx_conf_t def_66xx_conf;
extern CVMX_SHARED const gmx_conf_t def_68xx_conf;
extern CVMX_SHARED const gmx_conf_t sword_fish_2port_68xx_conf;
extern CVMX_SHARED const gmx_conf_t sword_fish_4port_68xx_conf;
extern CVMX_SHARED const gmx_conf_t def_73xx_conf;
extern CVMX_SHARED const gmx_conf_t def_78xx_conf;
extern CVMX_SHARED const gmx_conf_t def_nic225e_conf;

//Pkt processing flags
typedef union {
	uint64_t u;
	struct {
		uint64_t csum_verified:4;
		uint64_t offset:9; /* Offset for any headers preceding packet data */
		uint64_t timestamp_packet:1;
		uint64_t subone1:1;
		uint64_t reg1:11;
		cvmx_fau_op_size_t size1:2;
		uint64_t dontfree:1; /* cannot be used with backpressure */
		uint64_t rsp:1;
		uint64_t subcode:7;
		uint64_t reserved:27;
	} s;
} pkt_proc_flags_t;

typedef union {
	uint64_t u;
	struct {
		cvmx_fau_reg_32_t fau;
		uint64_t bpid:8;
		uint64_t enabled:1;
	} s;
} oct_bp_t;

#define MAX_PCI_PORTS_66XX 4
#define MAX_PCI_PORTS_68XX 32
#define MAX_PCI_PORTS_78XX 64
#define MAX_PCI_QUEUES_66XX 32
#define MAX_DROQS_66XX 32
#define MAX_PCI_QUEUES_68XX 32
#define MAX_DROQS_68XX 32
#define MAX_PCI_QUEUES_78XX 64
#define MAX_DROQS_78XX 64
typedef union {
	struct {
		oct_bp_t dpi_bp_fau_map[MAX_PCI_PORTS_66XX];
	} cn66xx;
	struct {
		oct_bp_t dpi_bp_fau_map[MAX_PCI_PORTS_68XX];
	} cn68xx;
} oct_dpi_bp_t;

typedef union {
	struct {
		oct_bp_t gmx_bp_fau_map[MAX_OCTEON_GMX_PORTS];
	} cn66xx;
	struct {
		oct_bp_t gmx_bp_fau_map[MAX_OCTEON_GMX_PORTS];
	} cn68xx;
} oct_gmx_bp_t;

typedef union {
	uint64_t u64;
	struct {
#if __CAVIUM_BYTE_ORDER == __CAVIUM_LITTLE_ENDIAN
		uint32_t reserved;
		uint16_t gso_segs;
		uint16_t gso_size;
#else
		uint16_t gso_size;
		uint16_t gso_segs;
		uint32_t reserved;
#endif
	} s;
} tx_info_t;

/*
 *  * LRO statistics
 *   */
typedef struct oct_nic_lro_stats {
	unsigned long aggregated;
	unsigned long flushed;
	unsigned long no_desc;
} oct_nic_lro_stats_t;

/* OC: LRO DATA STRUCTURE */
/* 10ms period */
#define LRO_TIMER_TICKS_MS              (10 * 1000 / (NIC_TIMER_PERIOD_US))
#define LRO_IP_OFFSET           	3
#define LRO_SEGMENT_GATHER_MAX   	29
#define LRO_SEGMENT_LINK_MAX   		127
#define LRO_SEGMENT_THRESHOLD   	65000
#define FORWARD_PKT_TO_HOST     	2
#ifdef FLOW_ENGINE
/*64 LRO flow buckets*/
#define LRO_LUT_SIZE 64
#define LRO_TAG_MASK  (LRO_LUT_SIZE -1) 
#else
#define LRO_TAG_MASK            0xffff
#endif
#define LRO_HASH_SIZE           (LRO_TAG_MASK + 1)

#define MAX_LRO_SUPPORT         100
//6 bits pko command word1.segs field
#define CVM_MAX_PKO_GATHER_SEG_SIZE 64

#define container_of(ptr, type, member) ({                  \
		const typeof( ((type *)0)->member ) *__mptr = (ptr);    \
		(type *)( (char *)__mptr - offsetof(type,member) );})

struct nic_perq_stats {
	u64 fw_total_fwd[MAX_IOQS_PER_NICIF];
	u64 fw_total_fwd_bytes[MAX_IOQS_PER_NICIF];
};

struct oct_perq_stats {
	struct nic_perq_stats fromwire;
	struct nic_perq_stats fromhost;
};

struct oct_pervf_stats {
       u64 spoofmac_cnt;
};

typedef struct cvm_per_core_stats_s {
	uint64_t wqe_count;
	struct oct_link_stats link_stats[MAX_OCTEON_NIC_PORTS];
	struct oct_perq_stats perq_stats[MAX_OCTEON_NIC_PORTS];
	struct oct_pervf_stats vf_stats[MAX_OCTEON_NIC_PORTS];
} CVMX_CACHE_LINE_ALIGNED cvm_per_core_stats_t;

typedef struct lro_context {
	bool is_vlan;
	bool is_v6;
	void *ethhdr;
	void *iphdr;
	struct tcphdr *tcp;

	uint64_t ptp_ts;

	uint32_t vni;

	bool is_psh;
	uint32_t tcp_data_len;
	uint32_t tsval;
	uint32_t tsecr;
	uint32_t next_seq;
	uint32_t ack_seq;
	uint16_t window;
	uint16_t append_cnt;
	uint16_t packet_cnt;
	int32_t  ifidx;
	/* Pointer to total number of buffers used for LRO on Rx port;
	 *
	 * Used only for BGX ports; set to NULL when the LRO context is
	 * created for packets received on DPI ports.
	 */
	int32_t *port_lro_used;
	/* Pointer to the total number of active LRO contexts on the Rx port;
	 *
	 * Used only for BGX ports; set to NULL when the LRO context is
	 * created for packets received on DPI ports.
	 */
	int32_t *lro_ctx_cnt;

	cvmx_buf_ptr_t gather_list;

	cvmx_wqe_t *wqe;
	cvmx_wqe_t *timer_wqe;
	bool timer_pending;
	cvmx_tim_delete_t delete_info;

#ifdef FLOW_ENGINE
	hash_node_t list;
#else
	struct list_head list;
#endif

	/* [saf] I added this field from tip code oct_nic_lro_desc structure */

	/* backpressure accumulated credits
	 * that need to be returned
	 */
	uint32_t bp_credits;

	/* List of duplicate WQE whose ref_cnt has to be decremented */
	cvmx_wqe_t *wqe_list;
	int wqe_list_size;

}lro_context_t;

static inline void lro_tag_sw_atomic(cvmx_wqe_t *wqe)
{
	cvmx_pow_tag_sw_full(wqe, (cvmx_wqe_get_tag(wqe) & LRO_TAG_MASK),
						CVMX_POW_TAG_TYPE_ATOMIC, cvmx_wqe_get_grp(wqe));
	cvmx_pow_tag_sw_wait();
}

static inline void lro_tag_sw_order(cvmx_wqe_t *wqe)
{
	cvmx_pow_tag_sw_full(wqe, (cvmx_wqe_get_tag(wqe) & LRO_TAG_MASK),
						CVMX_POW_TAG_TYPE_ORDERED, cvmx_wqe_get_grp(wqe));
}

static inline uint32_t cvmcs_ip_packet_start(cvmx_wqe_t *wqe)
{
	uint32_t pkt_start = 0;

	/* TODO : ADD CHECK FOR RAW PACKET OFFSET ALSO */
	if (!wqe->word2.s.not_IP) { /* Likely an ipv4 packet */
		pkt_start = (wqe->word2.s.is_v6 ^ 1) * 4;
		pkt_start += (LRO_IP_OFFSET * 8) - wqe->word2.s.ip_offset;
	}
	return (pkt_start);
}
/* :OC */

typedef struct oct_nic_lro {
	int ifidx;
	int ndesc;
	int max_desc;		/* Max number of LRO descriptors  */
	int max_aggr;		/* Max number of LRO packets to be aggregated */
	int max_segs;		/*Max number of WQE segments in a session */
} oct_nic_lro_t;

typedef struct {

	uint64_t present:1;
	uint64_t active:1;
	uint64_t rx_on:1;
	uint64_t lro_on_ipv4:1;
	uint64_t lro_on_ipv6:1;
	uint64_t tnl_tx_csum:1;
	uint64_t tnl_rx_csum:1;
	uint64_t ipsecv2_ah_esp:2;
	uint64_t rss_on:1;
	uint64_t fnv_on:1;
	uint64_t rsvd:37;
	uint64_t ifflags:16;

} octnic_if_state_t;

struct intrmod_info {
	struct oct_intrmod_cfg cfg;
	uint64_t last_rxfwd_pkts[MAX_IOQS_PER_NICIF];
	uint64_t last_rxfwd_bytes[MAX_IOQS_PER_NICIF];
	uint64_t last_txfwd_pkts[MAX_IOQS_PER_NICIF];
	uint64_t last_txfwd_bytes[MAX_IOQS_PER_NICIF];
	uint64_t last_check;
	uint64_t check_intrvl;
	uint32_t rxcnt_steps;
	uint32_t rxtmr_steps;
	uint32_t txcnt_steps;
	
};


/* cut and paste from linux-4.4/include/uapi/linux/if_link.h */
enum {
	IFLA_VF_LINK_STATE_AUTO,	/* link state of the uplink */
	IFLA_VF_LINK_STATE_ENABLE,	/* link always up */
	IFLA_VF_LINK_STATE_DISABLE,	/* link always down */
	__IFLA_VF_LINK_STATE_MAX,
};

typedef struct {
	int ifidx;
	octnic_if_state_t state;
	/* current MTU set for the port by the port admin.
	 * this includes packet from IP layer and up and
	 * does not include L2 headers
	 */
	int mtu;
	int max_mtu;  /* max limit for the port MTU 'mtu' */
	/* effective_mtu = min(mtu, max_mtu)
	 * firmware will use this to check for oversized L2 fames received 
	 * for the port; this need to be maintained in case a port admin does
	 * not adjust its MTU after firmware updated the port of new max MTU
	 */
	int effective_mtu;
	int is_mtu_master;
	struct oct_link_info linfo;
	struct intrmod_info intmod_info;
	oct_nic_lro_t lro_mgr;
	uint64_t iq_base;
	uint64_t iq_mask;
	uint64_t oq_base;
	uint64_t oq_mask;
	int	pf_srn; /*valid if port is pf */
	int gmxport_id;
	int hash_idx;
	int gmx_offset;
	int nmcast_addr;
	uint64_t ucast_table[MAX_OCTEON_UNICAST_ADDR];
	cvmx_spinlock_t ucast_table_lock;
	int ucast_count;
	uint64_t user_set_macaddr;
	uint64_t user_set_vlanTCI;
	int      user_set_linkstate;
	/* The VxLAN port DB is an array with each bit
	 * indicating the port number that is to be decoded as VxLAN ports.
	 * The array is having a size of [65536 . 1024/64] = 1024
	 */
	uint64_t vxlan_port_db[MAX_VXLAN_PORT_MASK_SIZE];
	uint8_t vxlan_default_ports; /* This is used for faster processing of default VxLAN ports */
	uint32_t vxlan_port_count;
	int pkt_steering_enable;
	pkt_steering_entry_t *pkt_steering_table;
	uint64_t pkt_steering_update_intrvl;
	cvmx_spinlock_t if_reset_lock;

#define HFRGTB_SIZE 4096
	struct {
		uint32_t hwtag;
		uint32_t hash3tag;
	} hashed_frg_tb[HFRGTB_SIZE];

	uint16_t speed_get:8;
	uint16_t rsfec_get:2;
	uint16_t rsfec_set:2;

}CVMX_CACHE_LINE_ALIGNED vnic_port_info_t;

typedef union {
	struct {
		int free_pci_ports_iqs;
		int free_pci_ports_oqs;
	} cn66xx;
	struct {
		int num_free_iqs;
		int num_free_oqs;
		uint64_t free_iq_mask;
		uint64_t free_oq_mask;
	} cn68xx;
	struct {
		int num_free_iqs;
		int num_free_oqs;
		uint64_t free_iq_mask;
		uint64_t free_oq_mask;
	} cn78xx;
} octnic_free_q_info_t;

/* This is twice as big so that we have room if the user changes
 * the MAC address. Otherwise it is easy to end up with near
 * O(MAX_OCTEON_NIC_PORTS) search time if they change a MAC address.
 */
#define NIC_HASH_SHIFT 1
#define MAX_OCTEON_NIC_HASH_SIZE (MAX_OCTEON_NIC_PORTS << 1)

typedef struct {
	uint64_t hw_addr;
	int      ifidx;
} vnic_hash_t;

static inline void set_bit(int bit, uint64_t *addr)
{
	//addr += (bit/64ULL);
	addr += bit>>6;
	//*addr |= (1ULL << (bit % 64ULL));
	*addr |= (1ULL << (bit & 63));
}

static inline void clear_bit(int bit, uint64_t *addr)
{
	//addr += (bit/64ULL);
	addr += bit>>6;
	//*addr &= ~(1ULL << (bit % 64ULL));
	*addr &= ~(1ULL << (bit &  63));
}

static inline int test_bit(int bit, uint64_t *addr)
{
	//addr += (bit/64ULL);
	addr += bit>>6;
	//return (*addr >> (bit % 64ULL)) & 1ULL;
	return (*addr >> (bit & 63)) & 1ULL;
}

/* Mask listing which interfaces are affected
 * 0-63 in first word
 * 64-127 in second word, and so on
 */
#define IFL_SIZE (ROUNDUP64(OCT_NIC_VFS_PER_PF * MAX_NUM_PFS)/64)
struct ifidx_list {
	uint64_t mask[IFL_SIZE];
	uint16_t last;    // last index set
	bool     active;  // whether any bits have been set
};

#define iflist_on(ifl, bit)      test_bit(bit, (ifl)->mask)
#define iflist_set(ifl, bit)     set_bit(bit, (ifl)->mask)
#define iflist_clear(ifl, bit)   clear_bit(bit, (ifl)->mask)
void iflist_set_active(struct ifidx_list *ifl);
void iflist_set_last(struct ifidx_list *ifl);
void iflist_union(struct ifidx_list *a, struct ifidx_list *b);
void iflist_intersection(struct ifidx_list *a, struct ifidx_list *b);

typedef struct {
	uint64_t          mcast_addr;
	struct ifidx_list ifl;
	hash_node_t       list;
} mcast_ifl_t;

enum {
	LINK_UNKNOWN,
	LINK_DOWN,
	LINK_UP,
	LINK_TRYING,
};

#define CVMCS_DMAC_FILTERS_MAX 64

typedef struct cvmcs_pcam_dmac_cfg {
	uint64_t macaddr;
} cvmcs_pcam_dmac_cfg_t;

typedef struct cvmcs_pcam_dmac_hi {
	uint16_t macaddr_hi;
	int pcam_entry_hi[CVMX_PKI_CLUSTER_ALL];
	int32_t ref_cnt;
} cvmcs_pcam_dmac_hi_t;

typedef struct cvmcs_pcam_dmac_lo {
	uint32_t macaddr_lo;
	int pcam_entry_lo[CVMX_PKI_CLUSTER_ALL];
	int32_t ref_cnt;
} cvmcs_pcam_dmac_lo_t;

typedef struct cvmcs_pcam_dmac_entry {
	cvmcs_pcam_dmac_lo_t entry_lo;
	cvmcs_pcam_dmac_hi_t entry_hi;
} cvmcs_pcam_dmac_entry_t;

typedef struct cvmcs_pcam_dmac_filters {
	cvmcs_pcam_dmac_cfg_t cfg[CVMCS_DMAC_FILTERS_MAX];
	cvmcs_pcam_dmac_entry_t entry[CVMCS_DMAC_FILTERS_MAX];
	cvmx_spinlock_t lock;
	int default_sso_grp;
	int mcast_entry_hi[CVMX_PKI_CLUSTER_ALL];
	int filters_count;
	int dmac_qpg;
	int dmac_style1;
	int dmac_style2;
	int32_t grp_refcnt;
} cvmcs_pcam_dmac_filters_t;

typedef struct {
	int         ipd_port;
	union       oct_link_status link;
	int         mtu;
	int         max_mtu;
	uint64_t    ifflags;
	uint64_t    cam_flags;
	uint64_t    hw_base_addr;
	uint64_t    hw_addr;
	int         ifidx;
	int         nports;
	int         chan0_bpid;
	/* total number of buffers used for LRO on Rx GMX port;
	 * this is used to limit the max buffers used for LRO on each GMX port.
	 */
	int32_t     lro_pkt_cnt;
	/* Total number of active LRO contexts on Rx GMX port
	 * this is used to limit the max active LRO contexts on each GMX port.
	 */
	int32_t     lro_ctx_cnt;
	cvmx_spinlock_t link_lock;
	int link_state;
	int sfp_mod_present;
	int rx_los_present;
	int tx_fault_present;
	cvmx_rwlock_wp_lock_t mac_hash_lock;
	vnic_hash_t hash[MAX_OCTEON_NIC_HASH_SIZE];
	hash_node_t *vnic_mcast_lut; /* multicast cache */
	hash_node_t vnic_mcast_free;
	struct ifidx_list vnic_bcast;
	struct ifidx_list vnic_promisc;
	struct ifidx_list vnic_multi;
	struct ifidx_list vnic_allmulti;
	struct ifidx_list vnic_without_user_set_vlan;
	struct ifidx_list vlans[MAX_VLANS];
	cvmcs_pcam_dmac_filters_t filters;
	struct lio_trusted_vf trusted_vf;
}CVMX_CACHE_LINE_ALIGNED gmx_port_info_t;

#define MAX_BPIDS 64		//on 68xx and 66xx


#ifdef FLOW_ENGINE

/* For Central Flow Engine framework */
#define CFE_COMP_CONSUMED 1
#define CFE_COMP_DROPPED 2

#define CFE_DEFAULT_OP 1
#define CFE_IPSEC_OP   2
#define CFE_BASE_OP (0x1)
#define CFE_OP_EN(OP) (CFE_BASE_OP <<(OP -1))

#define CFE_MAX_COMPONENTS 5

//TODO For working on actual SRIOV nic need to change Dispatch table size.
//#define MAX_CFE_DISPATCH_TBL 128
#define CFE_DISPATCH_TBL_SZ MAX_OCTEON_NIC_PORTS

#define hlist_entry(ptr, type, member) CVMX_CONTAINTER_OF(ptr,type,member)
typedef unsigned int hash_key_type_t;

/**
 * CFE disaptch table entry
 */

typedef struct cfe_dispatch_entry {
		/* Dynamic config changes for features like: ipsec, default fwd*/
		uint32_t cmpnts_enabled;

		/* Count of components enabled for this vport */
		uint32_t cmpnts_max;

		/* State: Could be active, down, resetting, init */
		uint32_t vport_state;

		/* Actual configuration of port, queue related info */
		vnic_port_info_t *vport;

		/* Hash look up table for flow policy */
		//TODO: Maintain separate Table for each component
		//cfe_bkt_t       *cfe_flow_lookup_tbl;
		hash_node_t  **cmpnt_lut[CFE_MAX_COMPONENTS];
} cfe_dispatch_entry_t;

/**
 * Components structure
 */
typedef struct cvmcs_component {
	char name[32];
	int opcode;
	int (*global_init)(void);
	int (*lut_init)(cfe_dispatch_entry_t *, hash_node_t **, uint32_t);
	uint32_t (*flow_compare) (void *, hash_node_t *);
	int (*from_host_msg_cb)(cvmx_wqe_t *wqe, cfe_dispatch_entry_t *cfe,      int opcode, int subcode);
	int (*vnic_traffic)(cvmx_wqe_t *wqe, cfe_dispatch_entry_t   *cfe, vnic_port_info_t *vport);
	int (*uplink_traffic)(cvmx_wqe_t *wqe, cfe_dispatch_entry_t *cfe, vnic_port_info_t *vport);
} cvmcs_component_t;



int cvmcs_vnic_traffic(cvmx_wqe_t *wqe, cfe_dispatch_entry_t *cfe, vnic_port_info_t *vport);
int cvmcs_uplink_traffic(cvmx_wqe_t *wqe, cfe_dispatch_entry_t   *cfe, vnic_port_info_t *vport);
uint32_t cvmcs_lro_flow_compare(void *ctx, hash_node_t *node);
int cfe_lut_insert(hash_node_t *node, hash_key_type_t key, int vport, int comp);
int cfe_lut_del(hash_node_t *node, int vport, int comp);
hash_node_t * cfe_lut_search(void *temp_ctx, hash_key_type_t key, int vport, int comp); 
hash_node_t * hash_table_alloc(uint32_t size, char *name);
hash_node_t * hash_table_free(char *name);
int cvmcs_lro_lut_init(cfe_dispatch_entry_t *cfe, hash_node_t  **lut, uint32_t feature);



#endif

typedef struct {
	uint32_t speed_get;
	uint32_t rsfec_get;
} vnic_port_uparam_t;

typedef struct {
	vnic_port_info_t port[MAX_OCTEON_NIC_PORTS];
	//reverse map sparse dpi port from hardware to logical port ids
	int vnic_ids[MAX_OCTEON_NIC_PORTS];
#ifdef FLOW_ENGINE
	cfe_dispatch_entry_t cfe_dispatch_tbl[CFE_DISPATCH_TBL_SZ];
	cvmcs_component_t *cfe_components[CFE_MAX_COMPONENTS];
	uint32_t cfe_num_cmpnts;
#endif
	gmx_port_info_t gmx_port_info[MAX_OCTEON_GMX_PORTS];
	//reverse map sparse gmx port from hardware to logical gmx ids
	int gmx_ids[MAX_OCTEON_GMX_PORTS];
	uint64_t board_type:16;
	uint64_t nports:16;
	uint64_t numpciqs:8;
	uint64_t dq_flush_enabled:1;
	uint64_t no_uboot_api:1;
	uint64_t rsvd:22;
	uint64_t macaddrbase;
	uint32_t ngmxports;

	uint32_t max_nic_ports;
	uint32_t null_link_l1_q;

	oct_gmx_bp_t gmx_bp;
	oct_dpi_bp_t dpi_bp;
	octnic_free_q_info_t free_q_info;

	uint32_t pci_cfgspace_reg0;
	uint32_t pci_cfgspace_reg2;

	cvmx_fau_reg_64_t idle_time_fau[MAX_CORES];

	OCTNIC_DCB_FIELDS

	uint32_t speed_change;
	vnic_port_uparam_t uparam[MAX_OCTEON_NIC_PORTS];

}CVMX_CACHE_LINE_ALIGNED octnic_dev_t;


/**
 * data structure to hold monitoring state of DROQ's
 */
typedef struct {
  uint64_t last_active_cycles; //timestamp of last active state
  uint64_t last_dq_pkts; //pko_sent of last PKO sent frames
  uint64_t pko_q:9; //DQ associated with the OQ
  uint64_t reserved:55;
} oq_mon_status_t;

extern CVMX_SHARED octnic_dev_t *octnic;

struct pko_rsp_buffer {
	cvmx_raw_inst_front_t inst;
	union {
		uint64_t ts;
		uint64_t fau;
	} data;
};

#define PACKET_START(WQE)       cvmx_phys_to_ptr(WQE->packet_ptr.s.addr)

#define LIO_INTRMOD_MAXPKT_RATETHR      196608  /* intrmod: max. packet rate threshold */
#define LIO_INTRMOD_MINPKT_RATETHR      9216    /* intrmod: min. packet rate threshold */

#define LIO_INTRMOD_RXMAXCNT_TRIGGER    64     /* intrmod: max. packets to trigger interrupt */
#define LIO_INTRMOD_RXMINCNT_TRIGGER    0       /* intrmod: min. packets to trigger interrupt */
/* 2^22-2 is the highest value (22 bits) */
#define LIO_INTRMOD_RXMAXTMR_TRIGGER    4194302  /* intrmod: max. time to trigger interrupt */
#define LIO_INTRMOD_RXMINTMR_TRIGGER    1       /* 66xx:intrmod: min. time to trigger interrupt (value of 1 is optimum for TCP_RR) */

#define LIO_INTRMOD_TXMAXCNT_TRIGGER    64     /* intrmod: max. packets to trigger interrupt */
#define LIO_INTRMOD_TXMINCNT_TRIGGER    0       /* intrmod: min. packets to trigger interrupt */

#define LIO_INTRMOD_CHECK_INTERVAL  1   /* intrmod: poll interval in seconds */

#define INTRMOD_INTRVL_LEVELS	8	/* intrmod: 8 levels of interrupt moderation */
#define INTRMOD_INTRVL_SHIFT	3	/* intrmod: 8 levels of interrupt moderation */

#define INTRMOD_RXCNT_STEPS	(LIO_INTRMOD_RXMAXCNT_TRIGGER >> INTRMOD_INTRVL_SHIFT)
#define INTRMOD_RXTMR_STEPS	(LIO_INTRMOD_RXMAXTMR_TRIGGER >> INTRMOD_INTRVL_SHIFT)

#define INTRMOD_DIV          1000

#define CYCLE_DIFF(a,b)	((a) >= (b)) ? ((a) - (b)) : ((~0ULL - (b)) + (a))

static inline int cvmcs_get_npi_interface()
{
       int i;
       const int num_interfaces = cvmx_helper_get_number_of_interfaces();

       for (i = 0; i  < num_interfaces; i++) {
               if (cvmx_helper_interface_get_mode(
                               cvmx_helper_node_interface_to_xiface(
                               cvmx_get_node_num(), i)) ==
                       CVMX_HELPER_INTERFACE_MODE_NPI)
                       break;
       }

       return ((i == num_interfaces) ? -1 : i);
}

static inline int cvmcs_get_loop_interface()
{
       int i;
       const int num_interfaces = cvmx_helper_get_number_of_interfaces();

       for (i = 0; i  < num_interfaces; i++) {
               if (cvmx_helper_interface_get_mode(
                               cvmx_helper_node_interface_to_xiface(
                               cvmx_get_node_num(), i)) ==
                       CVMX_HELPER_INTERFACE_MODE_LOOP)
                       break;
       }

       return ((i == num_interfaces) ? -1 : i);
}


#define   INTERFACE(port) (cvmx_helper_get_interface_num(port))
/* Ports 0-15 are interface 0, 16-31 are interface 1 */
#define   INDEX(port)     (cvmx_helper_get_interface_index_num(port))

static inline uint64_t cvmcs_nic_mac_to_64(uint8_t *mac)
{
	uint64_t macaddr = 0;
	int i;
	for (i = 0; i < 6; i++)
		macaddr = (macaddr << 8) | (uint64_t)(mac[i]);
	return macaddr;
}

#define mac_to_ptr(mac)  (((uint8_t *)mac) + 2)

/**
 * Calculate IPv4 header checksum.
 * No alignment requirements.
 *
 * @param  ip      pointer to the beginning of IP header
 * @param cksum:  pointer to calcukated checksum
 *
 */
static inline uint16_t
cvmcs_nic_ip_header_checksum(struct iphdr *ip, uint16_t * cksum)
{
	uint64_t sum, t0, t1, t2;
	uint64_t offset = 20;
	uint64_t len;

	/* Accumulate the first 20 bytes (skip checksum field) */
	CVMX_LOADUNA_INT64(t1, ip, 12);
	CVMX_LOADUNA_INT64(t0, ip, 4);
	CVMX_DEXT(t2, t1, 0, 32);
	t2 += t1 >> 32;
	CVMX_DEXT(t1, t0, 16, 16);	/* Exclude checksum (ie, 16 LSBs) */
	CVMX_LOADUNA_INT32(sum, ip, 0);
	t1 += t0 >> 32;
	sum += t2;
	len = ip->ihl;
	sum += t1;

	/* Check if options present
	 * (can be optimized -> assume "not taken")
	 */
	if (len > 5)
		goto slow_cksum_calc;

return_from_slow_cksum_calc:
	*cksum = sum;
	CVMX_DEXT(t0, sum, 0, 16);
	sum = t0 + (sum >> 16);
	CVMX_DEXT(t0, sum, 0, 16);
	sum = t0 + (sum >> 16);
	CVMX_DEXT(t0, sum, 0, 16);
	sum = t0 + (sum >> 16);

	/* Invert checksum */
	sum = sum ^ 0xffff;

	/* Update checksum in the header */
	CVMX_STOREUNA_INT16(sum, &ip->check, 0);

	/* Done -- return checksum */
	return ((uint16_t) sum);

	/* Slow back-end routine for IPv4 options */
slow_cksum_calc:
	len -= 5;
	do {
		CVMX_LOADUNA_INT32(t0, (uint8_t *) ip + offset, 0);
		len--;
		/* Get rid of sign extension */
		CVMX_DEXT(t0, t0, 0, 32);
		offset += 4;
		sum += t0;
	} while (len > 0);

	goto return_from_slow_cksum_calc;
}

/**
 * Initialize the mac index table
 *
 * @param  info     pointer to gmx port info
 */
void cvmcs_init_mac_hash_idx_table(gmx_port_info_t *info);

/**
 * Add a MAC to the GMX filter and hash table
 *
 * @param  ifidx      VNIC interface
 * @param  gmxport_id GMX port
 * @param  gmx_offset GMX filter offset
 * @param  mac        MAC address
 */
int cvmcs_nic_add_mac(int ifidx, int gmxport_id, int gmx_offset, uint64_t mac);

/**
 * Delete a MAC from the GMX filter and hash table
 *
 * @param  ifidx      VNIC interface
 */
void cvmcs_nic_del_mac(int ifidx);

/**
 * Enable or disable a GMX filter
 *
 * @param  ifidx      VNIC interface
 * @param  rx_on      1 = enable, 0 = disable
 */
void cvmcs_nic_change_mac_state(int ifidx, int rx_on);

static inline int is_dpi_port(int port)
{
	if (OCTEON_IS_MODEL(OCTEON_CN68XX)) {
		if (port >= 0x100 && port <= 0x11f)
			return 1;
	} else if (OCTEON_IS_MODEL(OCTEON_CN66XX)) {
		if (port >= 32 && port <= 35)
			return 1;
	}
	return 0;
}
static inline int get_gmx_port_id(int port)
{
	int ret = -1;

	//TODO remove if checks for speed up
	if (OCTEON_IS_MODEL(OCTEON_CN78XX)) {
		if (port == 0xA00 || port == 0xC00)
			return octnic->gmx_ids[((port>>8)&0xf)-8];
	} else if (OCTEON_IS_MODEL(OCTEON_CN73XX)) {
		if (port == 0xA00 || port == 0xA10)
			return octnic->gmx_ids[((port>>4)&0xf)];
		else if (port == 0x800)
			return octnic->gmx_ids[0];
		else if (port == 0x900)
			return octnic->gmx_ids[1];
	} else if (OCTEON_IS_MODEL(OCTEON_CN68XX)) {
		if ((port == 0x840 || port == 0x940 ||
		     port == 0xB40 || port == 0xC40))
			return octnic->gmx_ids[((port>>8)&0xf)-8];
	} else if (OCTEON_IS_MODEL(OCTEON_CN66XX)) {
		if ((port == 0) ||(port == 16))
			return octnic->gmx_ids[(port>>4)];
	}
	return ret;
}

#define get_vnic_port_id(port) \
	octnic->vnic_ids[port & (MAX_OCTEON_NIC_PORTS - 1)]

/**
 * Find if wqe entry is a NVMe entry. Returns true if so.
 *
 * The NVMe wqes are specified for the 73xx and beyond chips. In this version
 * for the 68xx chip, we use an illegal bit in the header to indicate that
 * the wqe comes from NVMe processing.
 */
static inline int is_nvme_wqe(cvmx_wqe_t *wqe)
{
	if (OCTEON_IS_MODEL(OCTEON_CN68XX)) {
		if (wqe->word0.pip.cn68xx.unused2 & 1) // use illegal bit to indicate
			return 1;
	} else { // 73xx and on
		if (cvmx_wqe_get_port(wqe) == 0x200)
			return 1;
	}
	return 0;
}

#define cvmcs_wqe_pool()	(octeon_has_feature(OCTEON_FEATURE_FPA3) ? \
				CVMX_FPA_PACKET_POOL : CVMX_FPA_WQE_POOL)
#define cvmcs_wqe_alloc()	cvmx_fpa_alloc(cvmcs_wqe_pool())

#ifdef VSWITCH
#define cvmcs_wqe_free(wqe)     (octeon_has_feature(OCTEON_FEATURE_CN78XX_WQE)? \
                cvmx_fpa3_free(wqe, __cvmx_fpa3_gaura(cvmx_wqe_get_aura(wqe) >> 10, cvmx_wqe_get_aura(wqe) & 0x3ff), 0) : cvmx_fpa_free(wqe, cvmcs_wqe_pool(), 0))
#else
#define cvmcs_wqe_free(wqe)	cvmx_fpa_free(wqe, cvmcs_wqe_pool(), 0)
#endif

int cvmcs_nic_uboot_ctl(cvmx_wqe_t  *wqe);

int cvmcs_nic_send_link_info(cvmx_wqe_t * wqe);

int cvmcs_nic_send_mdio_info(cvmx_wqe_t  *wqe);

int cvmcs_nic_send_vf_port_stats(cvmx_wqe_t * wqe);

int cvmcs_nic_send_port_stats(cvmx_wqe_t * wqe);

int cvmcs_nic_sfp_mod_info(cvmx_wqe_t * wqe);

int cvmcs_nic_phy_init(int gmxport_id);
void cvmcs_nic_set_link_status_led(int ifidx);
void cvmcs_nic_check_link_status(void);
uint64_t cvmcs_nic_update_link_status(union oct_link_status oldlink, int gmxport_id, int port);

int cvmcs_nic_send_timestamp(cvmx_wqe_t * wqe);

int cvmcs_intrmod_params(cvmx_wqe_t * wqe);

void cvmcs_intrmod_cfg(cvmx_wqe_t * wqe);

int cvmcs_nic_change_gmx_ifflags(int port, enum octnet_ifflags flags);

int cvmcs_nic_change_settings(union oct_link_status *host, int port);

void cvm_update_bp(cvmx_wqe_t *wqe);
void cvm_update_bp_port(int port, int num_bufs);

/* Get the Backpressure FAU if enabled on the port
 * @param wqe       work queue entry
 * @param nicport   nic port being used.
 * @param[out] fau  updated FAU value for this port. Undefined if not enabled
 *
 * @returns    0 if not enabled, 1 if enabled
 */
static inline int cvm_get_bp_fau(cvmx_wqe_t *wqe,
				 vnic_port_info_t *nicport,
				 int *fau)
{
	int enabled = 0;
#ifdef GMX_BP
	if (get_gmx_port_id(cvmx_wqe_get_port(wqe)) != -1) {
		//from wire
		if (OCTEON_IS_MODEL(OCTEON_CN68XX)) {
			int gmxport_id = nicport->gmxport_id;
			enabled = octnic->gmx_bp.cn68xx.gmx_bp_fau_map[gmxport_id].s.enabled;
			*fau = octnic->gmx_bp.cn68xx.gmx_bp_fau_map[gmxport_id].s.fau;
			//printf("gmx bp enabled %d fau %d\n", enabled, *fau);
			if (wqe->word0.pip.cn68xx.bpid != octnic->gmx_bp.cn68xx.gmx_bp_fau_map[gmxport_id].s.bpid)
				      printf("mismatch wqe bpid %d port bpid %d\n", wqe->word0.pip.cn68xx.bpid,
					      octnic->gmx_bp.cn68xx.gmx_bp_fau_map[gmxport_id].s.bpid);
		} else if (OCTEON_IS_MODEL(OCTEON_CN66XX)) {
			int gmxport_id = nicport->gmxport_id;
			enabled = octnic->gmx_bp.cn66xx.gmx_bp_fau_map[gmxport_id].s.enabled;
			*fau = octnic->gmx_bp.cn66xx.gmx_bp_fau_map[gmxport_id].s.fau;
			//printf("gmx bp enabled %d fau %d\n", enabled, *fau);
		}
	}
#endif				/* GMX */

#ifdef DPI_BP
	if (is_dpi_port(cvmx_wqe_get_port(wqe))) {
		if (OCTEON_IS_MODEL(OCTEON_CN68XX)) {
			int iq_num = cvmx_wqe_get_port(wqe) - (0x1U << 8);
			enabled = octnic->dpi_bp.cn68xx.dpi_bp_fau_map[iq_num].s.enabled;
			if (wqe->word0.pip.cn68xx.bpid != octnic->dpi_bp.cn68xx.dpi_bp_fau_map[iq_num].s.bpid)
			      printf("mismatch iq num %d  wqe bpid %d iq_num bpid %d\n",(cvmx_wqe_get_port(wqe)-256),wqe->word0.pip.cn68xx.bpid,
				      octnic->dpi_bp.cn68xx.dpi_bp_fau_map[iq_num].s.bpid);
			*fau = octnic->dpi_bp.cn68xx.dpi_bp_fau_map[iq_num].s.fau;
			//printf("dpi bp enabled %d *fau %d\n", enabled, *fau);
		} else if (OCTEON_IS_MODEL(OCTEON_CN66XX)) {
			int pci_port_idx = cvmx_wqe_get_port(wqe) - 32;
			enabled = octnic->dpi_bp.cn66xx.dpi_bp_fau_map[pci_port_idx].s.enabled;
			*fau = octnic->dpi_bp.cn66xx.dpi_bp_fau_map[pci_port_idx].s.fau;
		}
	}
#endif				/* DPI */

	return enabled;
}

int cvmcs_nic_init_bp();

int cvmcs_nic_if_cfg(cvmx_wqe_t *wqe);

int cvmcs_nic_if_reset_start(int ifidx);
int cvmcs_nic_if_reset_complete(int ifidx);
int cvmcs_nic_if_reset_finalize(int ifidx);

void cvmcs_nic_init_flow_ctl();

int cvmcs_nic_find_iq_num(cvmx_wqe_t * wqe);

void cvmcs_nic_process_cmd(cvmx_wqe_t * wqe);

void cvm_free_wqe_wrapper(cvmx_wqe_t * wqe);

void cvmcs_cond_free_wqe(cvmx_wqe_t *wqe);

int cvmcs_nic_init_macaddr_info(void);
int cvmcs_nic_init_board_info(void);
int cvmcs_nic_setup_interfaces(void);
int cvmcs_nic_init_packet_io(void);

void cvmcs_nic_read_stats_reg(int port, struct oct_link_stats *st);
int cvmcs_nic_opcode_to_stats(int ifidx, int err_code);
int cvmcs_nic_handle_tso(cvmx_wqe_t *wqe, int ifidx);
void oct_nic_lro_init();
void oct_nic_lro_discard(int ifidx);
int oct_nic_lro_receive_pkt(cvmx_wqe_t * wqe, int ifidx);
int oct_nic_lro_tso_receive_pkt(cvmx_wqe_t *wqe, int ifidx);
void oct_nic_lro_timeout(cvmx_wqe_t * wqe);
void cvmcs_nic_flush_lro(cvmx_wqe_t *wqe, lro_context_t *, int );
int cvmcs_nic_send_to_pko(cvmx_wqe_t * wqe, int dir,
	int port, int queue, pkt_proc_flags_t flags,
	vnic_port_info_t * nicport);
void add_port_to_nic(int port, uint32_t gmxport_id);
void del_port_from_nic(int ifidx);
uint32_t vxlan_get_tag(cvmx_wqe_t * wqe, uint16_t tunnel_hdr_len, uint8_t from_lpport);
int cvmcs_nic_send_to_pko3(cvmx_wqe_t  *wqe,  int dir, int port, int queue, pkt_proc_flags_t flags, vnic_port_info_t *nicport);


void cvmcs_nic_enable_vlan_filter(int ifidx);
void cvmcs_nic_disable_vlan_filter(int ifidx);
int cvmcs_nic_add_vlan(int ifidx, uint16_t vid);
int cvmcs_nic_del_vlan(int ifidx, uint16_t vid);
inline int mac_hash(uint8_t *mac);
void add_to_mcast_cache(int gmxport_id, uint64_t macaddr, int ifidx);
void clear_mcast_cache(int gmxport_id, int ifidx);
inline mcast_ifl_t *find_mcast_ifl(int gmxport_id, uint64_t mac);

void cvmcs_bgx_link_up(gmx_port_info_t *info);
void cvmcs_bgx_link_down(gmx_port_info_t *info);
void cvmcs_nic_alloc_flush_queue(void);

extern uint32_t core_id;

void cn73xx_flr_intr_handler_bh(cvmx_wqe_t * wqe);

#ifdef CONFIG_NIC_CONSOLE	/* NIC console enabled */
void nic_cmdl_init(void);
void nic_cmdl_readline(void);
#endif

#ifdef VSWITCH
#ifdef printf
#undef printf
#endif
int vswitch_printf(const char *format, ...);
#define printf(format, ...) vswitch_printf(format, ##__VA_ARGS__)
int cvmcs_nic_get_pf_min_mtu(void);

#endif //VSWITCH

int cvmcs_nic_start_dq_monitoring_task();
int cvmcs_nic_start_timestamp_task();
int cvmcs_nic_pki_pcam_init(int grp);
void cvmcs_nic_pki_pcam_exit(void);

int cvmcs_nic_dmac_filter_add(int ipd_port, uint64_t mac_addr);
int cvmcs_nic_dmac_filter_del(int ipd_port, uint64_t mac_addr);

int cvmcs_nic_validate_rx_frame_len(cvmx_wqe_t *wqe, int ifidx);

/* Functions to read FW dump in eeprom */
void cvmcs_nic_get_dump(cvmx_wqe_t *wqe);
void cvmcs_nic_set_dump_flag(cvmx_wqe_t *wqe);
void cvmcs_nic_get_dump_flag(cvmx_wqe_t *wqe);
#endif

/* $Id$ */
