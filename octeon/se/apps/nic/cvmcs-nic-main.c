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

#include "global-config.h"
#include "octeon-pci-console.h"
#include "cvmcs-common.h"
#include "cvmcs-nic.h"
#include  <cvmx-atomic.h>
#include  <cvmx-access.h>
#include  <cvmx-fau.h>
#include "cvmcs-nic-tunnel.h"
#include "cvmcs-nic-rss.h"
#include "cvmcs-nic-ipv6.h"
#include "cvmcs-nic-ether.h"
#include "cvmcs-nic-mdata.h"
#include "cvmcs-nic-switch.h"
#include "cvmcs-nic-printf.h"
#include "cvmcs-nic-fwdump.h"
#include "cvmcs-nic-flash.h"
#include "cvm-nic-ipsec.h"
#include "cvmcs-profile.h"
#include "nvme.h"
#include <errno.h>
#include "cvmcs-nic-fwdump.h"
#include "cvmcs-nic-component.h"
#include "cvmcs-nic-hybrid.h"
#include "cvmcs-dcb.h"
#include "generated/cvmcs-nic-version.h"

#define BLOCK_NAME "FW_CONFIG"
#define BLOCK_SIZE 2048

//octeon_config_t oct_cfg;

/* Exclusive Control Queue for NIC */
extern CVMX_SHARED uint8_t max_droq;
uint64_t link_query_interval = LINK_CHECK_INTERVAL_MS;
CVMX_SHARED int gmx_conf_id = 0;

extern volatile bool cvmcs_unplug_requested;
extern volatile bool cvmcs_shutdown_requested;

#ifdef RLIMIT
#define MAX_INTERNAL_PORTS (128)	/* RateLimit feature: PKO Internal ports */

/* Number of outstanding packets in PKO queue after which SW starts to drop */
#define CVM_RATE_LIMIT_DROP_THRESHOLD (512)	/* RateLimit feature: drop threshold */
#endif


#ifdef RLIMIT
CVMX_SHARED int gDropThreshold = CVM_RATE_LIMIT_DROP_THRESHOLD;
#endif

#ifdef RLIMIT
typedef struct _pko_rate_limit {	/* RateLimit feature: PKO rate limit state instance */
	cvmx_fau_reg_64_t fau;
	uint64_t pkts_dropped;
	int is_rate_limit_on;
} PKO_RATE_LIMIT_T2;

CVMX_SHARED PKO_RATE_LIMIT_T2 pko_rate_limit[MAX_INTERNAL_PORTS];	/* RateLimit feature: per port PKO rate limit state instance */
#endif

/* Enable this flag if you want to test peer-to-peer communication.
   Packets received on the GMX ports will be forwarded to the peer to be sent
   out from the same GMX port (e.g. pkt arriving from port 16 on a 56xx will
   be forwarded to the peer which will send it out on its port 16).
*/
//#define  ENABLE_NIC_PEER_TO_PEER

#ifdef ENABLE_NIC_PEER_TO_PEER
#include "cn56xx_ep_comm.h"
#endif

CVMX_SHARED cvm_per_core_stats_t *per_core_stats;

CVMX_SHARED octnic_dev_t *octnic __attribute__((__aligned__(CVMX_CACHE_LINE_SIZE)));

CVMX_SHARED int nic_console_enabled = 0;	/* CLI feature: enable nic console */
CVMX_SHARED int nic_duty_cycle = 0;	/* CLI feature: enable ouputs every duty cycle */

extern CVMX_SHARED uint64_t cpu_freq;
extern CVMX_SHARED uint32_t num_cores;
extern CVMX_SHARED uint32_t core_active[];
extern CVMX_SHARED cvm_oct_dev_t *oct;

#ifdef VSWITCH
extern CVMX_SHARED uint64_t cvm_per_core_cpu_stats[];
#endif

#ifdef CVM_IPSEC_STATS

CVMX_SHARED struct ipsec_pkt_stats ipsec_stats;

#endif //CVM_IPSEC_STATS


#ifdef __linux__
void (*prev_sig_handler) (int);
#endif

/* CLI feature interrupt moderation definitions */
CVMX_SHARED uint64_t intrmod_maxpkt_ratethr;	/* intrmod:maxpktrate threshold */
CVMX_SHARED uint64_t intrmod_minpkt_ratethr;	/* intrmod:minpktrate threshold */
CVMX_SHARED uint64_t intrmod_maxcnt_trigger;	/* intrmod:maxpktcnt threshold */
CVMX_SHARED uint64_t intrmod_mincnt_trigger;	/* intrmod:minpktcnt threshold */
CVMX_SHARED uint64_t intrmod_maxtmr_trigger;	/* intrmod:maxtimer threshold */
CVMX_SHARED uint64_t intrmod_mintmr_trigger;	/* intrmod:mintimer threshold */

CVMX_SHARED uint64_t intrmod_rxcnt_steps;	/* intrmod:per level count step */
CVMX_SHARED uint64_t intrmod_rxtmr_steps;	/* intrmod:per level timer step */

CVMX_SHARED uint64_t intrmod_check_intrvl;	/* intrmod: poll interval */

CVMX_SHARED int intmod_enable;			/* intrmod: eneble interrupt moderation */

uint64_t last_intmod_check;
uint64_t last_fwdpkts[MAX_OCTEON_NIC_PORTS]= {0};

static void cvmcs_nic_unplug_cb_fn(void *data);
static void cvmcs_nic_shutdown_cb_fn(void *data);
static void cvmcs_nic_cores_added_cb_fn(cvmx_coremask_t *coremask, void *data);
static void cvmcs_nic_cores_removed_cb_fn(cvmx_coremask_t * coremask, void *data);

extern int cvm_app_setup_memory(void);
extern int cvm_app_process_instr(cvmx_wqe_t * wqe);
extern int cvm_app_setup_mode(void);
extern int cvm_app_idle_task(void);
extern int cvm_app_core_local_init(void);
int cvmcs_nic_get_l4_from_ipv6_with_exthdr(uint8_t *ipv6header, uint16_t **l4header,
					   uint32_t *l4len, uint8_t *l4proto);
int cvm_handle_pending_error_intr(uint64_t cur_cycle);

void cvmcs_print_compile_options()
{
	printf("Application compiled with: ");
#ifdef  CVMCS_DUTY_CYCLE
	printf("[ DUTY CYCLE ] ");
#endif
#ifdef ENABLE_NIC_PEER_TO_PEER
	printf("[ PEER TO PEER ] ");
#endif
	printf("\n");
}

static inline void cvmcs_nic_print_stats(uint64_t cycles)
{
	unsigned int i,j;
	struct oct_link_stats st_str;
	struct oct_link_stats *st=&st_str;
	static struct oct_link_stats last_st[MAX_OCTEON_NIC_PORTS] = {{{0,}, {0,}},};

	for (i = 0; i < octnic->max_nic_ports; i++) {
		uint64_t err_drop = 0;
		memset(st, 0 , sizeof(*st));
		if (!octnic->port[i].state.active)
			continue;
		DBG2("ifidx %2d: ", i);
		for (j = 0; j < MAX_CORES; j++) {
			st->fromwire.fw_total_rcvd += per_core_stats[j].link_stats[i].fromwire.fw_total_rcvd;
			st->fromwire.fw_err_pko += per_core_stats[j].link_stats[i].fromwire.fw_err_pko;
			st->fromwire.fw_err_link += per_core_stats[j].link_stats[i].fromwire.fw_err_link;
			st->fromhost.fw_total_sent += per_core_stats[j].link_stats[i].fromhost.fw_total_sent;
			st->fromhost.fw_err_pko += per_core_stats[j].link_stats[i].fromhost.fw_err_pko;
			st->fromhost.fw_err_pki += per_core_stats[j].link_stats[i].fromhost.fw_err_pki;
			st->fromhost.fw_err_link += per_core_stats[j].link_stats[i].fromhost.fw_err_link;
			st->fromwire.fw_lro_pkts += per_core_stats[j].link_stats[i].fromwire.fw_lro_pkts;
			st->fromwire.fw_lro_octs += per_core_stats[j].link_stats[i].fromwire.fw_lro_octs;
			st->fromwire.fw_total_lro += per_core_stats[j].link_stats[i].fromwire.fw_total_lro;
			st->fromwire.fw_lro_aborts += per_core_stats[j].link_stats[i].fromwire.fw_lro_aborts;
			st->fromwire.fw_lro_aborts_port += per_core_stats[j].link_stats[i].fromwire.fw_lro_aborts_port;
			st->fromwire.fw_lro_aborts_seq += per_core_stats[j].link_stats[i].fromwire.fw_lro_aborts_seq;
			st->fromwire.fw_lro_aborts_tsval += per_core_stats[j].link_stats[i].fromwire.fw_lro_aborts_tsval;
			st->fromwire.fw_lro_aborts_timer += per_core_stats[j].link_stats[i].fromwire.fw_lro_aborts_timer;
		}

		cvmcs_nic_read_stats_reg(octnic->port[i].linfo.gmxport, st);
		err_drop = st->fromwire.total_rcvd - st->fromwire.fw_total_rcvd;
		err_drop += st->fromwire.dmac_drop;
		err_drop += st->fromwire.fw_err_drop;

		DBG2("Rx: %9llu pps (%9llu) ",
			cast64(st->fromwire.fw_total_rcvd - last_st[i].fromwire.fw_total_rcvd) /
			       (cycles/cpu_freq),
			cast64(st->fromwire.fw_total_rcvd));
		if (st->fromwire.ctl_rcvd)
			DBG2("(%llu CTL) ", cast64(st->fromwire.ctl_rcvd));
		if (st->fromwire.fw_err_pko)
			DBG2("(%llu PKO Err) ",
			     cast64(st->fromwire.fw_err_pko));
		if (st->fromwire.fw_err_link)
			DBG2("(%llu Link Err) ",
			     cast64(st->fromwire.fw_err_link));
		if (st->fromwire.fw_err_drop)
			DBG2("(%llu Drops) ", cast64(err_drop));
		if (st->fromwire.fifo_err)
			DBG2("(%llu OVERRUNS) ", cast64(st->fromwire.fifo_err));
		if (st->fromwire.dmac_drop)
			DBG2("(%llu DMAC Drops) ",
			     cast64(st->fromwire.dmac_drop));
		if (st->fromwire.fcs_err)
			DBG2("(%llu FCS/CRC Err) ",
			     cast64(st->fromwire.fcs_err));
		if (st->fromwire.jabber_err)
			DBG2("(%llu Jabber Err) ",
			     cast64(st->fromwire.jabber_err));
		if (st->fromwire.frame_err)
			DBG2("(%llu Frame Err) ",
			     cast64(st->fromwire.frame_err));
		if (st->fromwire.l2_err)
			DBG2("(%llu L2 Err) ", cast64(st->fromwire.l2_err));

		if (st->fromwire.fw_lro_pkts)
			DBG2("(%llu fw_lro_pkts) ", cast64(st->fromwire.fw_lro_pkts));
		if (st->fromwire.fw_lro_octs)
			DBG2("(%llu fw_lro_octs) ", cast64(st->fromwire.fw_lro_octs));
		if (st->fromwire.fw_total_lro)
			DBG2("(%llu fw_total_lro) ", cast64(st->fromwire.fw_total_lro));
		if (st->fromwire.fw_lro_aborts)
			DBG2("(%llu fw_lro_aborts) ", cast64(st->fromwire.fw_lro_aborts));
		if (st->fromwire.fw_lro_aborts_port)
			DBG2("(%llu fw_lro_aborts_port) ", cast64(st->fromwire.fw_lro_aborts_port));
		if (st->fromwire.fw_lro_aborts_seq)
			DBG2("(%llu fw_lro_aborts_seq) ", cast64(st->fromwire.fw_lro_aborts_seq));
		if (st->fromwire.fw_lro_aborts_tsval)
			DBG2("(%llu fw_lro_aborts_tsval) ", cast64(st->fromwire.fw_lro_aborts_tsval));
		if (st->fromwire.fw_lro_aborts_timer)
			DBG2("(%llu fw_lro_aborts_timer) ", cast64(st->fromwire.fw_lro_aborts_timer));



		DBG2("\n  Tx: %9llu pps (%9llu) ",
			cast64(st->fromhost.fw_total_sent - last_st[i].fromhost.fw_total_sent) /
			       (cycles/cpu_freq),
			cast64(st->fromhost.fw_total_sent));
		if (st->fromhost.runts)
			DBG2("(%llu SHORT) ", cast64(st->fromhost.runts));
		if (st->fromhost.ctl_sent)
			DBG2("(%llu CTL) ", cast64(st->fromhost.ctl_sent));
		if (st->fromhost.fw_err_pko)
			DBG2("(%llu PKO Err) ",
			     cast64(st->fromhost.fw_err_pko));
		if (st->fromhost.fw_err_pki)
			DBG2("(%llu PKI Err) ",
			     cast64(st->fromhost.fw_err_pki));
		if (st->fromhost.fw_err_link)
			DBG2("(%llu Link Err) ",
			     cast64(st->fromhost.fw_err_link));
		if (st->fromhost.fw_err_drop)
			DBG2("(%llu Drops) ", cast64(st->fromhost.fw_err_drop));
		if (st->fromhost.fifo_err)
			DBG2("(%llu UNDERRUNS) ",
			     cast64(st->fromhost.fifo_err));
		if (st->fromhost.total_collisions)
			DBG2("(%llu COL) ", cast64(st->fromhost.total_collisions));
		DBG2("\n");

		memcpy(&last_st[i], st, sizeof(*st));
	}
}

/** Print CPU statistics
 * @cycles the total number of cycles since the last update
 */
void cvmcs_nic_print_cpu_stats(uint64_t cycles)
{
	unsigned i;
	uint64_t result;

	DBG2("CPU idle: ");
	for (i=0; i < num_cores; i++) {
		if (core_active[i]) {
			result = (cvmx_fau_fetch_and_add64(octnic->idle_time_fau[i], 0)*10000)/cycles;
		
			DBG2("%d:%3u.%02u%% ", i,
				(unsigned)(result / 100),
				(unsigned)(result % 100))

#ifdef VSWITCH
			cvm_per_core_cpu_stats[i] = result;	
#endif
			cvmx_fau_atomic_write64(octnic->idle_time_fau[i], 0);
		}
	}
	DBG2("\n");

}



static int cvmcs_nic_create_profiles()
{
	cvmcs_profile_create(PROF_RX_GET_IFIDX, "Rx get_ifidx_list");
	cvmcs_profile_create(PROF_RX_ERROR_CHECK, "Rx Error checks");
	cvmcs_profile_create(PROF_RX_FILTER, "Rx Filtered");
	cvmcs_profile_create(PROF_RX_CSUM, "Rx csum");
	cvmcs_profile_create(PROF_RX_VLAN_STRIP, "Rx vlan_strip");
	cvmcs_profile_create(PROF_RX_RH_DONE, "Rx RH done. Before send_to_pko3");
	cvmcs_profile_create(PROF_TX_HEADERS, "Tx header checks");
	cvmcs_profile_create(PROF_TX_BEFORE_PKO, "Tx before send_to_pko3");
	cvmcs_profile_create(PROF_TX_CSUM, "Tx csum");
	cvmcs_profile_create(PROF_TXRX_GOT_DESC, "Tx/Rx Got PKO Descriptor");
	cvmcs_profile_create(PROF_TXRX_PDESC_XMIT, "Tx/Rx calling pdesc_transmit");
	cvmcs_profile_create(PROF_TX_DONE, "Tx DONE");
	cvmcs_profile_create(PROF_RX_DONE, "Rx DONE");

	return 0;
}



/** Setup the FPA pools. The Octeon hardware, simple executive and
  * PCI core driver use  WQE and Packet pool. OQ pool is used to
  * allocate command buffers for Output queue by simple exec.
  * Test pool is used by this application.
  */
int cvmcs_nic_setup_memory()
{
	cvmx_fpa_enable();

	if (octeon_has_feature(OCTEON_FEATURE_FPA3)) {
		printf("FPA pools: PKT: %d ", CVMX_FPA_PACKET_POOL);
	} else {
		printf("FPA pools: PKT: %d, WQE: %d, OP: %d ",
			CVMX_FPA_PACKET_POOL, CVMX_FPA_WQE_POOL,
			CVMX_FPA_OUTPUT_BUFFER_POOL);
	}

	printf("\n");

	if (cvmcs_app_mem_alloc("Packet Buffers", CVMX_FPA_PACKET_POOL,
		CVMX_FPA_PACKET_POOL_SIZE, FPA_PACKET_POOL_COUNT))
		return 1;

	if (octeon_has_feature(OCTEON_FEATURE_FPA3)) {
		/* NVME needs 32 times of buffers */
		if (cvmcs_app_mem_alloc("Small Buffers",
			CVMX_FPA_SMALL_BUFFER_POOL,
			CVMX_FPA_SMALL_BUFFER_POOL_SIZE,
#ifdef VSWITCH
            FPA_SMALL_BUFFER_POOL_COUNT))
#else
			32 * FPA_SMALL_BUFFER_POOL_COUNT))
#endif
			return 1;
		if (cvmcs_app_mem_alloc("Timer pool buffers",
			CVMX_FPA_OUTPUT_BUFFER_POOL,
			CVMX_FPA_OUTPUT_BUFFER_POOL_SIZE,
			FPA_OQ_POOL_COUNT))
		return 1;
	} else {
		if (cvmcs_app_mem_alloc("WQ Entries", CVMX_FPA_WQE_POOL,
			CVMX_FPA_WQE_POOL_SIZE, FPA_WQE_POOL_COUNT))
			return 1;
		if (cvmcs_app_mem_alloc("PKO Cmd Buffers",
			CVMX_FPA_OUTPUT_BUFFER_POOL,
			CVMX_FPA_OUTPUT_BUFFER_POOL_SIZE,
			FPA_OQ_POOL_COUNT))
		return 1;
	}

	/* OC: FOLLOWING MEMORY POOLS ARE CREATED FOR TSO & LRO FEATURES
	 *      1. GATHER LIST POOL
	 *      2. LRO CONTEXT POOL
	 */
	if( cvmcs_app_mem_alloc("Gather List Entries", CVMX_FPA_GATHER_LIST_POOL,
				CVMX_FPA_GATHER_LIST_POOL_SIZE, FPA_GATHER_LIST_POOL_COUNT)) {
				return 1;
	}

#if 0

	if( cvmcs_app_mem_alloc("Protocol Header Entries", CVMX_FPA_PROTOCOL_HEADER_POOL,
				CVMX_FPA_POOL_2_SIZE, FPA_PROTOCOL_HEADER_POOL_COUNT)) {
				return 1;
	}
#endif

	if (cvmcs_app_mem_alloc("LRO Buffers", CVMX_FPA_LRO_CONTEXT_POOL,
			CVMX_FPA_LRO_CONTEXT_POOL_SIZE, FPA_LRO_CONTEXT_POOL_COUNT))
		return 1;
	/* :OC */

	if (cvm_app_setup_memory())
		return 1;

	if (OCTEON_IS_MODEL(OCTEON_CN68XX)
	    && (cvmx_helper_initialize_sso(FPA_WQE_POOL_COUNT)))
		return -1;

	/* For OCT-III mdoels, defining SSO_POOL_COUNT as half of PKT_POOL_COUNT.*/
	if ((octeon_has_feature(OCTEON_FEATURE_FPA3)) &&
	    (cvmx_helper_initialize_sso(FPA_PACKET_POOL_COUNT/2)))
		return -1;

	return 0;
}

/* Only allow the Control Queue Group to go to the boot core. */
static int cvmcs_nic_init_control_group()
{
	int core, num_cores;

	num_cores = cvmx_octeon_num_cores();

	//groups broken on 78xx pass1.1
	if (!OCTEON_IS_MODEL(OCTEON_CN78XX) &&
	    !OCTEON_IS_MODEL(OCTEON_CN73XX)) {
		for (core=0; core < num_cores; core++) {
			if (!is_control_core(core)) {
				cvmx_write_csr(CVMX_POW_PP_GRP_MSKX(core),
					       cvmx_read_csr(CVMX_POW_PP_GRP_MSKX(core)) &
					       ~(1 << CFG_CTRL_Q_GRP));
			}
		}
	}

	CVMX_SYNCW;

	return 0;
}

static int cvm_nic_idle_time_init()
{
	unsigned int i;
	int fau;

	for (i=0; i < num_cores; i++) {
		if (core_active[i]) {
			fau = cvmx_fau64_alloc(CVMX_FAU_REG_ANY);
			if (fau == -1) {
				printf("Fau allocation failed\n");
				return -1;
			}
			octnic->idle_time_fau[i] = (cvmx_fau_reg_64_t)fau;
			cvmx_fau_atomic_write64(octnic->idle_time_fau[i], 0);
		}
	}

	return 0;
}



extern int __get_active_pci_oq_count(void);
#ifdef RLIMIT
int cvm_rate_limit(int ipd_port, uint64_t bits_s, int burst);	/* RateLimit feature: ratelimit API  */
#endif

#define NB_4MB_ALLIGNED		0x400000
#define NB_ALLOC_MAX_TRIES	0xA


int cvmcs_nic_init_global()
{
#ifdef RLIMIT
	int i;
#endif

	if (cvmcs_nic_setup_memory())
		return 1;

        /* Get the board type and determine the number of ports, the first usable
           port etc. */
        if (cvmcs_nic_init_board_info()) {
                printf("%s Board Init failed\n", __FUNCTION__);
                return 1;
        }

        if (cvmcs_nic_init_macaddr_info()) {
                printf("%s warning, MacAddrInfo init failed\n", __FUNCTION__);
        }

	if (cvmcs_nic_init_packet_io())
		return 1;

	if (cvmcs_app_init_global())
		return 1;

	if (cvmcs_nic_init_control_group())
		return 1;

	if(cvm_nic_idle_time_init())
		return 1;

	cvmcs_profile_initialize();
	if(cvmcs_nic_create_profiles())
		return 1;

	/* overwriting the SLI_TX_PIPE Register with active queue count of 4 */
#if 0 //already done in pci_pko_map
	if (OCTEON_IS_MODEL(OCTEON_CN68XX)) {
		uint32_t activeqcnt;
		cvmx_sli_tx_pipe_t slitxpipe;

		slitxpipe.u64 = cvmx_read_csr(CVMX_PEXP_SLI_TX_PIPE);
		activeqcnt = max_droq;
		slitxpipe.s.nump = activeqcnt;
		cvmx_write_csr(CVMX_PEXP_SLI_TX_PIPE, slitxpipe.u64);
		printf
		    ("[ NIC APP ] Active PCI Queues: %d (derived from checking queue registers)\n",
		     activeqcnt);
	}

#endif

#define FAU_BASE (32)
#define FAU_INCR (8)

#ifdef RLIMIT
	/* RateLimit feature: per internal port initialization */
	//TODO change to use fau allocation
	for (i = 0; i < MAX_INTERNAL_PORTS; i++) {
		pko_rate_limit[i].fau =
		    ((cvmx_fau_reg_64_t)
		     (CVMX_FAU_REG_AVAIL_BASE + FAU_BASE + (i * 8) + 1024));
		cvmx_fau_atomic_write64(pko_rate_limit[i].fau, 0);
		pko_rate_limit[i].is_rate_limit_on = 0;
	}
#endif

	if (octeon_has_feature(OCTEON_FEATURE_PKO3)) {
		cvmx_pko_enable_t pko_enable;

		pko_enable.u64 = 0;
		pko_enable.s.enable = 1;
		cvmx_write_csr_node(cvmx_get_node_num(), CVMX_PKO_ENABLE, pko_enable.u64);
	}

	if (cvmcs_nic_setup_interfaces())
		return 1;

	oct_nic_lro_init();

	return 0;
}

/** Local initialization. Performed by all cores. */
int cvmcs_nic_init_local()
{
	if (cvmcs_app_init_local())
		return 1;

	cvmcs_profile_init_local();
	
	cvmcs_nic_component_local_init();

	CVMX_SYNCW;
	return 0;
}

#ifdef ENABLE_NIC_PEER_TO_PEER
int cvmcs_nic_forward_pkt_to_ep(cvmx_wqe_t * wqe, int ifidx)
{
	cn56xx_ep_packet_t pkt;
	int retval, len = cvmx_wqe_get_len(wqe);

	cvmx_atomic_add_u64(&octnic->port[ifidx].stats.fromwire.fw_total_rcvd,
			    1);

	memset(&pkt, 0, sizeof(cn56xx_ep_packet_t));

	pkt.bufcount = 1;

	pkt.buf[0].s.addr = wqe->packet_ptr.s.addr;
	pkt.buf[0].s.size = len;
	pkt.buf[0].s.pool = CVMX_FPA_PACKET_POOL;
	pkt.buf[0].s.i = 1;

	pkt.tag = 0x11001100;
	pkt.tagtype = CVMX_POW_TAG_TYPE_ORDERED;
	pkt.param = cvmx_wqe_get_port(wqe);
	pkt.opcode = EP_TO_EP_OP;

	DBG("Sending test packet with opcode: %x param: %x\n", pkt.opcode,
	    pkt.param);

	retval = cn56xx_send_ep_packet(&pkt);

	/* If packet was sent successfully, the packet buffers would be freed by the
	   core driver EP communication code. Else we need to free it here. */
	if (retval == 0) {
		wqe->word2.s.bufs = 0;
		wqe->packet_ptr.u64 = 0;
		cvmx_atomic_add_u64(&octnic->port[ifidx].stats.fromwire.
				    fw_total_fwd, 1);
		cvmx_atomic_add_u64(&octnic->port[ifidx].stats.fromwire.
				    fw_total_fwd_bytes, len);
	} else {
		cvmx_atomic_add_u64(&octnic->port[ifidx].stats.fromwire.
				    fw_err_drop, 1);
	}

	cvm_free_wqe_wrapper(wqe);

	return retval;
}
#endif

void cvmcs_nic_dump_ptrs(cvmx_buf_ptr_t * ptr, int numbufs)
{
	int i, total = 0;
	cvmx_buf_ptr_t *next;

	for (i = 0; i < numbufs; i++) {
		next = (cvmx_buf_ptr_t *) CVM_DRV_GET_PTR(ptr->s.addr - 8);
		printf("ptr[%d]: 0x%016llx  size: %d pool %d\n", i,
		       CAST64(ptr->s.addr), ptr->s.size, ptr->s.pool);
		total += ptr->s.size;
		ptr = next;
	}

	printf("Total Bytes: %d\n", total);
}

/**
 * Create a packet descriptor from WQE
 *
 * Populate a packet descriptor with a packet data and meta-data
 * located in the Work Queue Entry.
 * After this function, it is safe to call 'cvmx-wqe-free()'
 * to release the WQE buffer if separate from data buffers.
 * This function discards any data or meta-data that may have
 * been present in the packet descriptor previously, and does not
 * require the call to 'cvmx_pko3_pdesc_init()'.
 *
 * @param pdesc Packet Desciptor.
 * @param wqe Work Queue Entry as returned from `cvmx_get_work()'
 * @param free_bufs Automatically free data buffers when transmission complete.
 *
 * This function is the quickes way to prepare a received packet
 * represented by a WQE for transmission via any output queue to
 * an output port.
 * If the packet data is to be transmitted unmodified, call
 * 'cvmcs_nic_pko_pdesc_transmit()' immediately after this function
 * returns.
 */
#if 0
static int cvmcs_nic_pko3_pdesc_from_wqe(cvmx_pko3_pdesc_t *pdesc, cvmx_wqe_78xx_t *wqe,
					 bool free_bufs)
{
	unsigned node;
	cvmx_pko_send_hdr_t *hdr_s;
	cvmx_pko_send_aura_t *ext_s;
	cvmx_pko_buf_ptr_t *buf_s;
	cvmx_buf_ptr_pki_t pki_bptr;
        cvmx_pki_stylex_buf_t style_buf_reg;

	/* Verify the WQE is legit */
	if (cvmx_unlikely(wqe->word2.software || wqe->pki_wqe_translated)) {
		cvmx_printf("%s: ERROR: invalid WQE\n", __func__);
		return -1;
	}

	/* descriptor provided by caller, reset state */
	pdesc->jump_buf = NULL;
	pdesc->hdr_offsets = 0;
	pdesc->send_work_s = 0;
	pdesc->mem_s_ix = 0;
	pdesc->ckl4_alg = 0;
	pdesc->jb_aura = -1;

	/* 1st word is SEND_HDR_S header */
	hdr_s = pdesc->hdr_s = (void *) &pdesc->word[0];
	/* 2nd word is the SEND_EXT_S header */
	ext_s = (void *) &pdesc->word[1];

	hdr_s->u64 = 0;
	ext_s->u64 = 0;
	pdesc->num_words = 2;
	ext_s->s.subdc4 = CVMX_PKO_SENDSUBDC_EXT;

	hdr_s->s.format = 0;	/* Only 0 works for Pass1 */
	hdr_s->s.ds = 0;	/* don't send, never used */

        if(OCTEON_IS_MODEL(OCTEON_CN78XX_PASS1_X))
		hdr_s->s.n2 = 0;	/* L2 allocate everything */
	else
		hdr_s->s.n2 = 1;	/* No L2 allocate works faster */

	/* Default buffer freeing setting, may be overriden by "i" */
	hdr_s->s.df = !free_bufs;

	/* Inherit GAURA */
	pdesc->last_aura =
	hdr_s->s.aura = wqe->word0.aura;

	/* Get the NODE on which this packet was received */
	node = pdesc->last_aura >> 10;

	/* Import total packet length */
	hdr_s->s.total = wqe->word1.len ;

	/* Read the PKI_STYLEX_BUF register for this packet style */
        style_buf_reg.u64 = cvmx_read_csr_node(node,
		CVMX_PKI_STYLEX_BUF(wqe->word0.style));

	/* mirror PKI endianness state: */
	hdr_s->s.le = style_buf_reg.s.pkt_lend;
#if CVMX_ENABLE_PARAMETER_CHECKING
	if (hdr_s->s.le != __native_le)
		cvmx_printf("%s: WARNING: "
			"packet endianness mismatch\n",__func__);
#endif

#if 0 // WQE fields not used (yet?)
		wqe->word0.pki.pknd
		wqe->word0.pki.channel

		wqe->word1.cn78xx.tag
		wqe->word1.cn78xx.tag_type
		wqe->word1.cn78xx.grp
#endif

	/* Carry-over layer protocol detection from PKI */
	pdesc->pki_word2 = wqe->word2;

	/* check if WQE WORD4 is present */
	if (style_buf_reg.s.wqe_hsz != 0 || style_buf_reg.s.first_skip > 4) {
		pdesc->pki_word4_present = 1;
		/* Carry-over protocol header offsets */
		pdesc->pki_word4 = wqe->word4;
	}
	else {
		pdesc->pki_word4_present = 0;
		pdesc->pki_word4.u64 = 0;
	}

	/* Checksum recalculation is not needed, until headers get modified */
	/* NOTE: Simulator does not support CKL3/CKL4, so this is not tested */
	hdr_s->s.ckl4 = CKL4ALG_NONE;
	hdr_s->s.ckl3 = 0;

	/* Convert WQE buffer ptr to LINK_S or GATHER_S bufptr in descriptor */
	pki_bptr = wqe->packet_ptr;
	buf_s = (void *) &pdesc->word[pdesc->num_words++];
	buf_s->u64 = 0;
	buf_s->s.addr = pki_bptr.addr;
	buf_s->s.size = pki_bptr.size;

	/* use LINK_S if more than one buf present, calculate headroom */
	if (cvmx_unlikely(wqe->word0.bufs > 1)) {
		pdesc->headroom =  (style_buf_reg.s.first_skip) << 3;
		buf_s->s.subdc3 = CVMX_PKO_SENDSUBDC_LINK;
	} else {
		pdesc->headroom =  (1 + style_buf_reg.s.first_skip) << 3;
		buf_s->s.subdc3 = CVMX_PKO_SENDSUBDC_GATHER;
	}
	pdesc->headroom += wqe->word0.apad;

	return 0;
}

/**
 * Add arbitrary subcommand to a packet desciptor.
 *
 * This function will also allocate a jump buffer when
 * the primary LTDMA buffer is exhausted.
 * The jump buffer is allocated from the internal PKO3 aura
 * on the node where this function is running.
 */
static int cvmcs_nic_pko3_pdesc_subdc_add(cvmx_pko3_pdesc_t *pdesc,
					  uint64_t subdc)
{
	cvmx_pko_send_hdr_t *hdr_s;
	cvmx_pko_send_aura_t *ext_s;
	cvmx_pko_buf_ptr_t *jump_s;
	const unsigned jump_buf_size = 4*1024 / sizeof(uint64_t);
	unsigned i;

	/* Simple handling while fitting the command buffer */
	if (cvmx_likely(pdesc->num_words <= 15 && pdesc->jump_buf == NULL)) {
		pdesc->word[ pdesc->num_words ] = subdc;
		pdesc->num_words ++;
		return pdesc->num_words;
	}

        /* SEND_JUMP_S missing on Pass1 */
        if(OCTEON_IS_MODEL(OCTEON_CN78XX_PASS1_X)) {
                cvmx_printf("%s: ERROR: too many segments\n",__func__);
                return -E2BIG;
        }

	hdr_s = (void *) &pdesc->word[0];
	ext_s = (void *) &pdesc->word[1];

	/* Allocate jump buffer */
	if (cvmx_unlikely(pdesc->jump_buf == NULL)) {
		uint16_t pko_gaura;
		cvmx_fpa3_gaura_t aura;
		unsigned fpa_node = cvmx_get_node_num();

		/* Allocate jump buffer from PKO internal FPA AURA, size=4KiB */
		pko_gaura = __cvmx_pko3_aura_get(fpa_node);
		aura = __cvmx_fpa3_gaura(pko_gaura >> 10, pko_gaura & 0x3ff);

		pdesc->jump_buf = cvmx_fpa3_alloc(aura);
                if(pdesc->jump_buf == NULL)
                        return -EINVAL;

		/* Save the JB aura for later */
		pdesc->jb_aura = pko_gaura;

		/* Move most of the command to the jump buffer */
		memcpy(pdesc->jump_buf, &pdesc->word[2],
			(pdesc->num_words-2)*sizeof(uint64_t));
		jump_s = (void *) &pdesc->word[2];
		jump_s->u64 = 0;
		jump_s->s.addr = cvmx_ptr_to_phys(pdesc->jump_buf);
		jump_s->s.i = !hdr_s->s.df;	/* F= ~DF */
		jump_s->s.size = pdesc->num_words - 2;
		jump_s->s.subdc3 = CVMX_PKO_SENDSUBDC_JUMP;

		/* Now the LMTDMA buffer has only HDR_S, EXT_S, JUMP_S */
		pdesc->num_words = 3;
	}

	/* Add the new subcommand to the jump buffer */
	jump_s = (void *) &pdesc->word[2];
	i = jump_s->s.size;

	/* Avoid overrunning jump buffer */
	if (i >= (jump_buf_size-2)) {
                cvmx_printf("%s: ERROR: too many segments\n",__func__);
		return -E2BIG;
	}

	pdesc->jump_buf[i] = subdc;
	jump_s->s.size++;

	(void) ext_s;

	return(i + pdesc->num_words);
}

/**
 * Send a packet in a desciptor to an output port via an output queue.
 *
 * A call to this function must follow all other functions that
 * create a packet descriptor from WQE, or after initializing an
 * empty descriptor and filling it with one or more data fragments.
 * After this function is called, the content of the packet descriptor
 * can no longer be used, and are undefined.
 *
 * @param pdesc Packet Desciptor.
 * @param dq Descriptor Queue associated with the desired output port
 * @param tag Flow Tag pointer for packet ordering or NULL
 * @return Returns 0 on success, -1 on error.
 *
 */
static int cvmcs_nic_pko3_pdesc_transmit(cvmx_pko3_pdesc_t *pdesc, uint16_t dq,
					 uint32_t *tag)
{
        cvmx_pko_query_rtn_t pko_status;
	cvmx_pko_send_aura_t aura_s;
	uint8_t port_node;
	int rc;

	/* Add last AURA_S for jump_buf, if present */
	if (cvmx_unlikely(pdesc->jump_buf != NULL) &&
	    (pdesc->last_aura != pdesc->jb_aura)) {
		/* The last AURA_S subdc refers to the jump_buf itself */
		aura_s.s.aura = pdesc->jb_aura;
		aura_s.s.offset = 0;
		aura_s.s.alg = AURAALG_NOP;
		aura_s.s.subdc4 = CVMX_PKO_SENDSUBDC_AURA;
		pdesc->last_aura = pdesc->jb_aura;

		rc = cvmcs_nic_pko3_pdesc_subdc_add(pdesc, aura_s.u64);
		if (rc < 0)
			return -1;
	}

	/* SEND_WORK_S must be the very last subdc */
	if (cvmx_unlikely(pdesc->send_work_s != 0ULL)) {
		rc = cvmcs_nic_pko3_pdesc_subdc_add(pdesc, pdesc->send_work_s);
		if (rc < 0)
			return -1;
		pdesc->send_work_s = 0ULL;
	}

        /* Derive destination node from dq */
	port_node = dq >> 10;
	dq &= (1<<10)-1;

	/* To preserve packet order, go atomic with DQ-specific tag */
	if (tag != NULL)
		cvmx_pow_tag_sw_nocheck(*tag ^ dq, CVMX_POW_TAG_TYPE_ATOMIC);

        /* Send the PKO3 command into the Descriptor Queue */
        pko_status = __cvmx_pko3_do_dma(port_node, dq,
                pdesc->word, pdesc->num_words, CVMX_PKO_DQ_SEND);

        /* Map PKO3 result codes to legacy return values */
        if (pko_status.s.dqstatus == PKO_DQSTATUS_PASS)
                return 0;

#if 0
        cvmx_printf("%s: ERROR: failed to enqueue: %s\n",
                                __FUNCTION__,
                                pko_dqstatus_error(pko_status.s.dqstatus));
#endif

	return -1;
}
#endif

/* Direction: 0 - to wire, 1 - to host */
int
cvmcs_nic_send_to_pko3(cvmx_wqe_t  *wqe,  int dir, int port, int queue, pkt_proc_flags_t flags, vnic_port_info_t *nicport)
{
	cvmx_pko_send_hdr_t hdr_s;
	cvmx_pko_query_rtn_t pko_status;
	cvmx_buf_ptr_pki_t *tmp_lptr;
	unsigned node, nwords;
	unsigned scr_base = cvmx_pko3_lmtdma_scr_base();
	cvmx_pko_buf_ptr_t send;
	cvmcs_nic_metadata_t *mdata = CVMCS_NIC_METADATA(wqe);
	unsigned dq = queue;
	int offset = flags.s.offset;

	node = dq >> 10;
	dq &= (1 << 10)-1;

	cvmx_pow_tag_sw_full(wqe, (cvmx_wqe_get_tag(wqe)^dq), CVMX_POW_TAG_TYPE_ATOMIC, cvmx_wqe_get_grp(wqe));

	/* Fill in header */
	hdr_s.u64 = 0;
	hdr_s.s.total = cvmx_wqe_get_len(wqe);
	hdr_s.s.df = flags.s.dontfree;
	hdr_s.s.ii = 0;
        if(OCTEON_IS_MODEL(OCTEON_CN78XX_PASS1_X))
		hdr_s.s.n2 = 0;	/* L2 allocate everything */
	else
		hdr_s.s.n2 = 1;	/* No L2 allocate works faster */
	hdr_s.s.aura = cvmx_wqe_get_aura(wqe);
#ifdef __LITTLE_ENDIAN_BITFIELD
	hdr_s.s.le = 1;
#endif

	/* Calculate the TCP/UDP checksum in hardware. L3PTR must
	 * point to the header just adjacent to this header.
	 * TODO: SCTP
	 */
	if (CVMCS_NIC_METADATA_IS_TUNNEL(mdata) &&
	    !CVMCS_NIC_METADATA_IS_IP_FRAG(mdata)) {
		per_core_stats[cvmx_get_core_num()].link_stats[mdata->from_ifidx].fromhost.fw_tx_vxlan += 1;

		if (cvmx_unlikely(CVMCS_NIC_METADATA_CSUM_L4(mdata))) {
			if (CVMCS_NIC_METADATA_CSUM_INNER_L4(mdata)) {
				if (CVMCS_NIC_METADATA_IS_INNER_IPV4(mdata)) {
					cvmcs_nic_put_l4checksum_ipv4(wqe,
						CVMCS_NIC_METADATA_INNER_L3_OFFSET(mdata));
				} else {
					cvmcs_nic_put_l4checksum_ipv6_with_exthdr(wqe,
						CVMCS_NIC_METADATA_INNER_L3_OFFSET(mdata));
				}
			}

			if (CVMCS_NIC_METADATA_CSUM_INNER_L3(mdata) &&
			    (CVMCS_NIC_METADATA_IS_INNER_IPV4(mdata))) {
				struct iphdr *inner_iph = (struct iphdr *)
					CVMCS_NIC_METADATA_INNER_L3_HEADER(mdata);
				cvmcs_nic_ip_header_checksum(inner_iph,
						     &inner_iph->check);
			}

			hdr_s.s.l3ptr = CVMCS_NIC_METADATA_L3_OFFSET(mdata) +
				offset;

			hdr_s.s.l4ptr = CVMCS_NIC_METADATA_L4_OFFSET(mdata) +
				offset;
			if (CVMCS_NIC_METADATA_IS_UDP(mdata))
				hdr_s.s.ckl4 = CKL4ALG_UDP;
			if (CVMCS_NIC_METADATA_IS_TCP(mdata))
				hdr_s.s.ckl4 = CKL4ALG_TCP;

			if (CVMCS_NIC_METADATA_CSUM_L3(mdata) &&
			    CVMCS_NIC_METADATA_IS_IPV4(mdata)) {
				hdr_s.s.ckl3 = 1;
			}
		} else {
			if (CVMCS_NIC_METADATA_CSUM_L3(mdata) &&
			    CVMCS_NIC_METADATA_IS_IPV4(mdata)) {
				/* Checksum outer in software */
				struct iphdr *outer_iph = (struct iphdr *)
					CVMCS_NIC_METADATA_L3_HEADER(mdata);
				cvmcs_nic_ip_header_checksum(outer_iph, &outer_iph->check);
			}

			hdr_s.s.l3ptr = CVMCS_NIC_METADATA_INNER_L3_OFFSET(mdata) +
				offset;

			if (CVMCS_NIC_METADATA_CSUM_INNER_L3(mdata) &&
			    (CVMCS_NIC_METADATA_IS_INNER_IPV4(mdata)))
				hdr_s.s.ckl3 = 1;

			if (CVMCS_NIC_METADATA_CSUM_INNER_L4(mdata)) {
				hdr_s.s.l4ptr = CVMCS_NIC_METADATA_INNER_L4_OFFSET(mdata) +
					offset;
				if (CVMCS_NIC_METADATA_IS_INNER_TCP(mdata))
					hdr_s.s.ckl4 = CKL4ALG_TCP;
				else if (CVMCS_NIC_METADATA_IS_INNER_UDP(mdata))
					hdr_s.s.ckl4 = CKL4ALG_UDP;
			}
		}
	} else {
		/* Not a tunnel */
		hdr_s.s.l3ptr = CVMCS_NIC_METADATA_L3_OFFSET(mdata) +
				offset;

		if (CVMCS_NIC_METADATA_CSUM_L3(mdata) &&
		    (CVMCS_NIC_METADATA_IS_IPV4(mdata)))
			hdr_s.s.ckl3 = 1;

		if (CVMCS_NIC_METADATA_CSUM_L4(mdata)) {
			hdr_s.s.l4ptr = CVMCS_NIC_METADATA_L4_OFFSET(mdata) +
					offset;
			if (CVMCS_NIC_METADATA_IS_TCP(mdata))
				hdr_s.s.ckl4 = CKL4ALG_TCP;
			else if (CVMCS_NIC_METADATA_IS_UDP(mdata))
				hdr_s.s.ckl4 = CKL4ALG_UDP;
		}
	}

	cvmcs_profile_mark_event(PROF_TX_CSUM);

	nwords = 0;
	cvmx_scratch_write64(scr_base+sizeof(uint64_t)*(nwords++), hdr_s.u64);

	tmp_lptr = (cvmx_buf_ptr_pki_t *)&wqe->packet_ptr;
	send.u64 = 0;
	send.s.addr = tmp_lptr->addr;
	send.s.size = tmp_lptr->size;
	if (cvmx_wqe_get_bufs(wqe) > 1)
		send.s.subdc3 = CVMX_PKO_SENDSUBDC_LINK;
	else
		send.s.subdc3 = CVMX_PKO_SENDSUBDC_GATHER;
	cvmx_scratch_write64(scr_base+sizeof(uint64_t)*(nwords++), send.u64);


	if (cvmx_unlikely(flags.s.subone1)) {
		cvmx_pko_send_mem_t mem_s = {.s={
		.subdc4 = CVMX_PKO_SENDSUBDC_MEM,
		.dsz = MEMDSZ_B64, .alg = MEMALG_SUB,
		.offset = 1,
		.wmem = 1
		}};
		mem_s.s.addr = cvmx_ptr_to_phys((uint64_t *)mdata->wqe_ref_count);
		cvmx_scratch_write64(scr_base+sizeof(uint64_t)*(nwords++), mem_s.u64);
	} 
	
	CVMX_SYNCWS;
	/* Do LMTDMA */
	pko_status = cvmcs_pko3_lmtdma(node, dq, nwords, true, true);

	if (cvmx_unlikely(pko_status.s.dqstatus != PKO_DQSTATUS_PASS)) {
		return -1;
	}
	return 0;
}
#if 0
/* Direction: 0 - to wire, 1 - to host */
int
cvmcs_nic_send_to_pko3(cvmx_wqe_t  *wqe,  int dir, int port, int queue, pkt_proc_flags_t flags, vnic_port_info_t *nicport)
{
	cvmx_pko3_pdesc_t	desc;
	cvmx_pko_send_hdr_t *hdr_s;
	cvmx_wqe_78xx_t *wqe_78 = (void *)wqe;
	int ret = -1;
	uint32_t tag = cvmx_wqe_get_tag(wqe); /* consider accounting for queue here */

	/* cvmcs_nic_pko3_pdesc_from_wqe() is very expensive.
	 * +1 stars if you can make it faster, or remove the redundancy in NIC
	 * structures which extract fields from PKI.
	 */
	if (cvmcs_nic_pko3_pdesc_from_wqe(&desc, (void *) wqe, false)) {
		printf("%d:%s",__LINE__,__FUNCTION__);
		return ret;
	}

	if(cvmx_unlikely(flags.s.subone1)) {
		cvmx_pko3_pdesc_notify_decrement(&desc,
			(uint64_t *)CVMCS_NIC_METADATA(wqe)->wqe_ref_count);
	}

	hdr_s = desc.hdr_s;
	hdr_s->s.ii = 0;
	if (flags.s.dontfree) hdr_s->s.df = 1;
	else hdr_s->s.df = 0;

	cvmcs_profile_mark_event(PROF_TXRX_GOT_DESC);

	if (flags.s.csum_offload) {

		uint8_t ip0, l4_proto = 0, doff, ipoff = flags.s.csum_offload - 1;
		uint8_t *data_ptr;
		cvmx_buf_ptr_pki_t *pki_lptr = &wqe_78->packet_ptr;

		doff = ipoff;

		while (doff > pki_lptr->size) {
			doff -= pki_lptr->size;
			pki_lptr = (cvmx_buf_ptr_pki_t *)cvmx_phys_to_ptr(pki_lptr->addr - 8);
		}

		data_ptr = cvmx_phys_to_ptr(pki_lptr->addr);

		hdr_s->s.ckl3 = 1;
		hdr_s->s.l3ptr = ipoff;
		ip0 = data_ptr[doff];

		/* Decode L3 header for L4 type and offset */
		if ((ip0 >> 4) == 4) {
		    hdr_s->s.l4ptr = hdr_s->s.l3ptr +
			((ip0 & 0xf) << 2);
		    l4_proto = data_ptr[doff + 9];
		}
		if ((ip0 >> 4) == 6) {
		    hdr_s->s.ckl3 = 0; // no checksum for ipv6
		    hdr_s->s.l4ptr = hdr_s->s.l3ptr + 40;
		    l4_proto = data_ptr[doff + 6];
		}
		/* Set L4 checksum algo based on L4 protocol */
		if (l4_proto == 6)
		    hdr_s->s.ckl4 = /* TCP */ 2;
		else if (l4_proto == 17)
		    hdr_s->s.ckl4 = /* UDP */ 1;
		else if (l4_proto == 132)
		    hdr_s->s.ckl4 = /* SCTP */ 3;
		else
		    hdr_s->s.ckl4 = /* Uknown */ 0;
	}

	cvmcs_profile_mark_event(PROF_TXRX_PDESC_XMIT);

	/* Tag switch to atomic occurs in cvmcs_nic_pko3_pdesc_transmit. This
	 * reduces the overhead of this function, and should help with
	 * scalability.
	 */
	ret = cvmcs_nic_pko3_pdesc_transmit(&desc, queue, &tag);

	return ret;
}
#endif

/** Send a packet to the PKO
 *
 * @param wqe       work queue entry
 * @param to_host   1 is to host, 0 to wire
 * @param port      octeon port
 * @param queue     queue to use
 * @param flags     metadata for constructing the PKO command
 * @param nicport   NIC port information
 *
 * @returns return code from PKO
 */
int
cvmcs_nic_send_to_pko(cvmx_wqe_t *wqe,
		      int to_host,
		      int port,
		      int queue,
		      pkt_proc_flags_t flags,
		      vnic_port_info_t *nicport)
{
	cvmx_pko_command_word0_t pko_command;
	cvmx_wqe_t *work = NULL;
	uint64_t word2;
	int ret = -1;
	cvmcs_nic_metadata_t *mdata = CVMCS_NIC_METADATA(wqe);
	int offset = flags.s.offset;

	CVMX_SYNCWS;

	/* Prepare to send a packet to PKO. */
	if (to_host && octeon_has_feature(OCTEON_FEATURE_PKND))
		cvmx_pko_send_packet_prepare_pkoid(port, queue, 1);
	else
		cvmx_pko_send_packet_prepare(port, queue, 1);

	/* Build a PKO pointer to this packet */
	pko_command.u64 = 0;

	/* Setting II = 0 and DF = 0 will free all buffers whose I bit is not set.
	   Since I bit is not set by default in pkt buffer ptrs, this setting allows
	   packets to be forwarded to host/wire without having to touch each pkt
	   ptr to set the I bit. */
	pko_command.s.ignore_i = 0;

	/* FAU 1 settings and don't free flags are not compatible with
	 * backpressure.
	 */
	pko_command.s.dontfree = flags.s.dontfree;
	pko_command.s.subone1 = flags.s.subone1;
	pko_command.s.reg1 = flags.s.reg1;
	pko_command.s.size1 = flags.s.size1;

	pko_command.s.segs = wqe->word2.s.bufs;
	assert(cvmx_wqe_get_len(wqe) != 0);
	pko_command.s.total_bytes = cvmx_wqe_get_len(wqe);

/*******************************************************************
    INTERFACE   QLM   PORT NUMBER
   ------------------------------------------------------------------
     XAUI        0     0x840
     XAUI        0     0x940
     XAUI        3     0xB40
     XAUI        4     0xC40
*******************************************************************/

#ifdef RLIMIT
	/* RateLimit feature: prepare PKO command */
	if (!to_host) {
		int pko_port = cvmx_helper_cfg_ipd2pko_port_base(port);

		pko_command.s.size0 = CVMX_FAU_OP_SIZE_64;
		pko_command.s.subone0 = 1;
		pko_command.s.reg0 = pko_rate_limit[pko_port].fau;
	}
#endif

	/* If PKO is being told not to free, then we will update BP
	 * counters when we free it later, by whatever means.
	 */
	if (cvmx_likely(!pko_command.s.dontfree)) {
		if ((wqe->word2.s.bufs == 1) ||
		    (to_host && (wqe->word2.s.bufs == 2))) {
			int fau = 0;
			if (cvm_get_bp_fau(wqe, nicport, &fau)) {
				pko_command.s.size1 = CVMX_FAU_OP_SIZE_32;
				pko_command.s.subone1 = 1;
				pko_command.s.reg1 = fau;
			}
		} else {
			/* linked buffers pko can only decrement one or number
			 * of bytes but not number of buffers, so
			 * it is probably jumbo packet
			 * TODO: use wqe response to be fired when pko
			 * is done sending then give back credits
			 * NOTE lro and tso do not come here, so this is only
			 * jumbo udp or jumbo tcp without lro/tso
			 * updating credits here itself till then
			 */
			cvm_update_bp_port(cvmx_wqe_get_port(wqe),
					   (to_host) ? (wqe->word2.s.bufs-1)
					             : (wqe->word2.s.bufs));
		}
	}

	/* Calculate the IP and TCP/UDP checksums.
	 *
	 * TCP/UDP checksum is only possible in hardware if the IP header
	 * immediately preceeds the L4 (i.e., no options or extension
	 * headers.), and it is not a fragment. 
	 */
	if (CVMCS_NIC_METADATA_IS_TUNNEL(mdata) &&
	    !CVMCS_NIC_METADATA_IS_IP_FRAG(mdata)) {
		/* Checksum outer in software */
		if (CVMCS_NIC_METADATA_CSUM_L3(mdata) &&
		    CVMCS_NIC_METADATA_IS_IPV4(mdata)) {
			struct iphdr *outer_iph = (struct iphdr *)
				CVMCS_NIC_METADATA_L3_HEADER(mdata);
			cvmcs_nic_ip_header_checksum(outer_iph, &outer_iph->check);
		}

		if (cvmx_unlikely(CVMCS_NIC_METADATA_CSUM_L4(mdata))) {
			if (CVMCS_NIC_METADATA_IS_IPV4(mdata)) {
				cvmcs_nic_put_l4checksum_ipv4(wqe,
					CVMCS_NIC_METADATA_L3_OFFSET(mdata));
			} else {
				cvmcs_nic_put_l4checksum_ipv6_with_exthdr(wqe,
					CVMCS_NIC_METADATA_L3_OFFSET(mdata));
			}
		}

		/* Checksum inner IP in software */
		if (CVMCS_NIC_METADATA_CSUM_INNER_L3(mdata) &&
		    CVMCS_NIC_METADATA_IS_INNER_IPV4(mdata)) {
			struct iphdr *inner_iph = (struct iphdr *)
				CVMCS_NIC_METADATA_INNER_L3_HEADER(mdata);
			cvmcs_nic_ip_header_checksum(inner_iph, &inner_iph->check);
		}

		/* Checksum inner TCP/UDP in hardware if no opts/exts/frag */
		if (CVMCS_NIC_METADATA_CSUM_INNER_L4(mdata) &&
		    (CVMCS_NIC_METADATA_IS_INNER_TCP(mdata) ||
		     CVMCS_NIC_METADATA_IS_INNER_UDP(mdata))) {
			if (!CVMCS_NIC_METADATA_IS_INNER_IP_OPTS_OR_EXTH(mdata) &&
			    !CVMCS_NIC_METADATA_IS_INNER_IP_FRAG(mdata)) {
				pko_command.s.ipoffp1 = CVMCS_NIC_METADATA_INNER_L3_OFFSET(mdata) +
					offset + 1;
			} else {
				if (CVMCS_NIC_METADATA_IS_INNER_IPV4(mdata) &&
				    !CVMCS_NIC_METADATA_IS_INNER_IP_FRAG(mdata)) {
					cvmcs_nic_put_l4checksum_ipv4(wqe,
						CVMCS_NIC_METADATA_INNER_L3_OFFSET(mdata)
						+ offset);
				} else if (CVMCS_NIC_METADATA_IS_INNER_IPV6(mdata)) {
					cvmcs_nic_put_l4checksum_ipv6_with_exthdr(wqe,
						CVMCS_NIC_METADATA_INNER_L3_OFFSET(mdata) + offset);
				}
			}
		}
	} else {
		/* Not a tunnel */

		/* Checksum outer IP in software */
		if (CVMCS_NIC_METADATA_CSUM_L3(mdata) &&
		    (CVMCS_NIC_METADATA_IS_IPV4(mdata))) {
			struct iphdr *inner_iph = (struct iphdr *)
				CVMCS_NIC_METADATA_INNER_L3_HEADER(mdata);
			cvmcs_nic_ip_header_checksum(inner_iph, &inner_iph->check);
		}

		if (CVMCS_NIC_METADATA_CSUM_L4(mdata) &&
		    (CVMCS_NIC_METADATA_IS_TCP(mdata) ||
		     CVMCS_NIC_METADATA_IS_UDP(mdata))) {
			if (!CVMCS_NIC_METADATA_IS_IP_OPTS_OR_EXTH(mdata) &&
			    !CVMCS_NIC_METADATA_IS_IP_FRAG(mdata)) {
				pko_command.s.ipoffp1 = CVMCS_NIC_METADATA_L3_OFFSET(mdata) +
					offset + 1;
			} else {
				if (CVMCS_NIC_METADATA_IS_IPV4(mdata) &&
				    !CVMCS_NIC_METADATA_IS_IP_FRAG(mdata)) {
					cvmcs_nic_put_l4checksum_ipv4(wqe,
						CVMCS_NIC_METADATA_L3_OFFSET(mdata)
						+ offset);
				} else if (CVMCS_NIC_METADATA_IS_IPV6(mdata)) {
					cvmcs_nic_put_l4checksum_ipv6_with_exthdr(wqe,
						CVMCS_NIC_METADATA_L3_OFFSET(mdata) + offset);
				}
			}
		}
	}

	cvmcs_profile_mark_event(PROF_TX_CSUM);

	if (cvmx_unlikely(flags.s.rsp)) {
		cvmx_raw_inst_front_t *front;
		struct pko_rsp_buffer *rb;

		DBG("%s: got rsp request\n", __FUNCTION__);

		work = cvmcs_wqe_alloc();
		if (cvmx_unlikely(!work)) {
			printf("[ DRV ] failed to allocate rsp wqe.\n");
			return 0;
		}

		pko_command.s.rsp = 1;   /* Word2 exists */
		pko_command.s.wqp = 1;   /* Word2[Ptr] is a WQE entry */

		work->word0.u64 = 0;

		work->word1.u64 = 0;
		work->word1.tag_type = CVMX_POW_TAG_TYPE_NULL;
		work->word1.tag = 0;
		work->word2.u64 = 0;
		work->word2.s.software = 1;

		/* Put an instruction in the new WQE.
		 * The PKO will place the timestamp in the word after the IRH,
		 * since we set PKO_REG_TIMESTAMP to 7.
		 * We put the rptr in the wqe so we can respond back to the
		 * host.
		 */
		//not called if 78xx
		rb = (struct pko_rsp_buffer *)&work->packet_data;
		front = (cvmx_raw_inst_front_t *)wqe->packet_data;

		DBG("%s: rb=%p, front=%p rptr=%016llu rsize=%d\n", __FUNCTION__,
		    rb, front, (unsigned long long)front->rptr,
		    front->rdp.s.rlen);

		rb->inst.ih.u64 = 0;
		rb->inst.rptr = front->rptr;
		rb->inst.rdp = front->rdp;
		rb->inst.irh.u64 = front->irh.u64;
		rb->inst.irh.s.opcode = OPCODE_NIC;
		rb->inst.irh.s.subcode = flags.s.subcode;
		if (cvmx_unlikely(flags.s.timestamp_packet)) {
			rb->data.ts = 0;
		} else {
			rb->data.fau = flags.s.reg1;
		}
	}

	DBG("pko cmd: %016llx lptr: %016llx PORT: %d Q: %d sub1=%d fau1=%d\n",
		  cast64(pko_command.u64), cast64(wqe->packet_ptr.u64), port,
		  queue, pko_command.s.subone1, pko_command.s.reg1);

	/* Send a packet to PKO. */
	//TODO check return value of pko_send
	if (to_host && octeon_has_feature(OCTEON_FEATURE_PKND))
		if (cvmx_unlikely(flags.s.rsp)) {
			/* We must tell the PKO to provide a response using the
			 * WQE in WORD2.
			 */
			word2 = CVM_DRV_GET_PHYS(work);
			if (cvmx_unlikely(flags.s.timestamp_packet)) {
				/* We must tell the PKO to provide a timestamp after
				 * sending the packet. See WORD2[PTP].
				 * The PKO returns the timestamp to a wqe we provide.
				 * Once that wqe is processed, a response is sent to the
				 * host.
				 */
				word2 |= 1ull << 40; /* Bit 40 controls timestamps */
			}
			ret = cvmx_pko_send_packet_finish3_pkoid(port, queue, pko_command,
							  wqe->packet_ptr,
							  word2, 1);
		} else {
			ret = cvmx_pko_send_packet_finish_pkoid(port, queue, pko_command,
							  wqe->packet_ptr, 1);
		}
	else
		if (cvmx_unlikely(flags.s.rsp)) {
			word2 = CVM_DRV_GET_PHYS(work);
			if (cvmx_unlikely(flags.s.timestamp_packet)) {
				word2 |= 1ull << 40; /* Bit 40 controls timestamps */
			}
			ret = cvmx_pko_send_packet_finish3(port, queue, pko_command,
					    wqe->packet_ptr, word2, 1);
		} else {
			ret = cvmx_pko_send_packet_finish(port, queue, pko_command,
					    wqe->packet_ptr, 1);
		}

	return ret;
}

static uint16_t crc16(uint16_t iv, uint64_t p) __attribute__ ((unused));
static uint16_t crc16(uint16_t iv, uint64_t p)
{
	uint32_t *ptr = (uint32_t *) &p;
	uint32_t res;

	CVMX_MT_CRC_POLYNOMIAL ((0x1021)<<16);
	CVMX_MT_CRC_IV (iv << 16);
	CVMX_MT_CRC_WORD (ptr[0]);
	CVMX_MT_CRC_WORD (ptr[1]);
	CVMX_MF_CRC_IV (res);
	iv = res >> 16;

	return iv;
}

static uint32_t crc32c(uint32_t iv, void *ptr, int len)
{
    uint32_t crc32;

    CVMX_MT_CRC_POLYNOMIAL(0x1edc6f41);
    CVMX_MT_CRC_IV(iv);

    while (len >= 64)
    {
        uint64_t *p = ptr;
        CVMX_MT_CRC_DWORD(p[0]);
        CVMX_MT_CRC_DWORD(p[1]);
        CVMX_MT_CRC_DWORD(p[2]);
        CVMX_MT_CRC_DWORD(p[3]);
        CVMX_MT_CRC_DWORD(p[4]);
        CVMX_MT_CRC_DWORD(p[5]);
        CVMX_MT_CRC_DWORD(p[6]);
        CVMX_MT_CRC_DWORD(p[7]);
        ptr += 64;
        len -= 64;
    }
    while (len>=8)
    {
        CVMX_MT_CRC_DWORD(*(uint64_t*)ptr);
        ptr += 8;
        len -= 8;
    }
    if (len>=4)
    {
        CVMX_MT_CRC_WORD(*(uint32_t*)ptr);
        ptr += 4;
        len -= 4;
    }
    if (len>=2)
    {
        CVMX_MT_CRC_HALF(*(uint16_t*)ptr);
        ptr += 2;
        len -= 2;
    }
    if (len)
        CVMX_MT_CRC_BYTE(*(uint8_t*)ptr);

    CVMX_MF_CRC_IV(crc32);

    return crc32;
}

static uint32_t
sw_ipv4_hash(cvmx_wqe_t * wqe, uint32_t IPsrc, uint32_t IPdest,
	     uint16_t sport, uint16_t dport, uint16_t proto,
	     uint16_t vlan_id, uint8_t * src_mac, uint8_t * dest_mac,
	     uint32_t vx_vni, uint8_t from_lpport)
{
	uint32_t src_dest_crc = 0xffffffff;
	uint32_t prot_crc = 0xffffffff;
	uint32_t src_mac_crc = 0xffffffff;
	uint32_t dest_mac_crc = 0xffffffff;
	uint32_t sdport_crc = 0xffffffff;
	uint32_t vni_crc = 0xffffffff;
	uint64_t vlan_proto_ports = ((uint64_t) vlan_id << 16) | proto;
	uint64_t ip_src_dst = ((uint64_t) IPdest << 32) | IPsrc;
	uint64_t sdport = 0, smac = 0, dmac = 0, vni = 0;
	uint32_t result = 0;
	uint32_t tag;

	sdport = ((uint64_t)((uint64_t) sport << 16 | dport)) << 32;
	if (src_mac)
		smac = ((uint64_t)(*src_mac)) << 16;
	if (dest_mac)
		dmac = ((uint64_t)(*dest_mac)) << 16;
	vni = ((uint64_t) vx_vni) << 40;

	/* Hash to be calculated with fields src mac & dest mac & vxlan vni for loopback packets */
	if (from_lpport) {
		tag = cvmx_wqe_get_tag(wqe);
		result = tag ^ result;
		goto out;
	}

	/* CRC for source and destination IP */
	src_dest_crc = crc32c(src_dest_crc, (void *)&ip_src_dst, sizeof(uint64_t));

	/* CRC on VLAN/PROTO */
	prot_crc = crc32c(prot_crc, (void *)&vlan_proto_ports, sizeof(uint64_t));

	/* CRC on SPORT/DPORT */
	if (sport)
		sdport_crc = crc32c(sdport_crc, (void *)&sdport, sizeof(uint64_t));

out:

	if (src_mac)
		src_mac_crc = crc32c(src_mac_crc, (void *)&smac, sizeof(uint64_t));

	if (dest_mac)
		dest_mac_crc =
			crc32c(dest_mac_crc, (void *)&dmac, sizeof(uint64_t));

	if (vx_vni)
		vni_crc = crc32c(vni_crc, (void *)&vni, sizeof(uint64_t));

	if (!from_lpport)
		result =
			(src_dest_crc ^ prot_crc ^ sdport_crc ^ src_mac_crc ^
			dest_mac_crc ^ vni_crc);
	else
		result = (src_mac_crc ^ dest_mac_crc ^ vni_crc ^ result);

	return result;
}

static uint32_t
sw_ipv6_hash(cvmx_wqe_t * wqe, uint64_t * sptr, uint64_t * dptr,
	uint16_t sport, uint16_t dport, uint16_t proto,
	uint16_t vlan_id, uint8_t * src_mac, uint8_t * dest_mac,
	uint32_t vx_vni, uint8_t from_lpport)
{

	uint32_t src_crc = 0xffffffff;
	uint32_t dst_crc = 0xffffffff;
	uint32_t prot_crc = 0xffffffff;
	uint32_t sdport_crc = 0xffffffff;
	uint32_t src_mac_crc = 0xffffffff;
	uint32_t dest_mac_crc = 0xffffffff;
	uint32_t vni_crc = 0xffffffff;
	uint64_t vlan_proto_ports = ((uint64_t) vlan_id << 16) | proto;
	uint64_t sdport = 0, smac = 0, dmac = 0, vni = 0;
	uint32_t result = 0;
	uint32_t tag;

	sdport = ((uint64_t)((uint64_t) sport << 16 | dport)) << 32;
	if (src_mac)
		smac = ((uint64_t)(*src_mac)) << 16;
	if (dest_mac)
		dmac = ((uint64_t)(*dest_mac)) << 16;
	vni = ((uint64_t) vx_vni) << 40;

	/* Hash to be calculated with fields src mac & dest mac & vxlan vni for loopback packets */
	if (from_lpport) {
		tag = cvmx_wqe_get_tag(wqe);
		result = tag ^ result;
		goto out;
	}

	/* CRC for source IP */
	if (sptr) {
		src_crc = crc32c(src_crc, (void *)sptr, sizeof(uint64_t));
		sptr++;
		src_crc = crc32c(src_crc, (void *)sptr, sizeof(uint64_t));
	}

	/* CRC for destination IP */
	if (dptr) {
		dst_crc = crc32c(dst_crc, (void *)dptr, sizeof(uint64_t));
		dptr++;
		dst_crc = crc32c(dst_crc, (void *)dptr, sizeof(uint64_t));
	}
	/* CRC on VLAN/PROTO */
	prot_crc = crc32c(prot_crc, (void *)&vlan_proto_ports, sizeof(uint64_t));

	/* CRC on SPORT/DPORT */
	if (sport)
		sdport_crc = crc32c(sdport_crc, (void *)&sdport, sizeof(uint64_t));
out:

	if (src_mac)
		src_mac_crc = crc32c(src_mac_crc, (void *)&smac, sizeof(uint64_t));

	if (dest_mac)
		dest_mac_crc =
			crc32c(dest_mac_crc, (void *)&dmac, sizeof(uint64_t));

	if (vx_vni)
		vni_crc = crc32c(vni_crc, (void *)&vni, sizeof(uint64_t));

	if (!from_lpport)
		result =
			(src_crc ^ dst_crc ^ prot_crc ^ sdport_crc ^ src_mac_crc ^
			dest_mac_crc ^ vni_crc);
	else
		result = (src_mac_crc ^ dest_mac_crc ^ vni_crc ^ result);

	return result;
}

uint32_t
vxlan_get_tag(cvmx_wqe_t * wqe, uint16_t tunnel_hdr_len, uint8_t from_lpport)
{
	uint16_t vlan_id = 0;
	struct ethhdr *inner_eth;
	struct iphdr *inner_iph;
	struct ipv6hdr *inner_ipv6h;
	uint8_t is_inner_ipv4;
	uint32_t *s_ptr, *d_ptr;
	struct vxlanhdr *vxlanh;
	uint32_t vx_vni;
	uint16_t sport;
	uint16_t dport;

	inner_eth =
		(struct ethhdr *)((uint8_t *)
		cvmx_phys_to_ptr(wqe->packet_ptr.s.addr) +
		tunnel_hdr_len);

	if (inner_eth->h_proto == ETH_P_8021Q) {
		struct vlan_hdr *vlanh = (struct vlan_hdr *)inner_eth;
		vlan_id = (vlanh->vlan_TCI & 0x0FFF);
	}

	inner_iph =
		(struct iphdr *)((uint8_t *) inner_eth +
				((inner_eth)->h_proto !=
				ETH_P_8021Q ? ETH_HLEN : VLAN_ETH_HLEN));
	inner_ipv6h = (struct ipv6hdr *)inner_iph;
	is_inner_ipv4 = (inner_iph->version == 4) ? 1 : 0;

	vxlanh =
	    (struct vxlanhdr *)((uint8_t *) inner_eth -
	                        sizeof(struct vxlanhdr));
	vx_vni = (vxlanh->vx_vni >> 8);

	sport = 0;
	dport = 0;
	if (is_inner_ipv4) {
		/* IPv4 Packet */
		if (!(inner_iph->frag_off & IP_MF
		      || inner_iph->frag_off & IP_OFFSET)) {
			if ((inner_iph->protocol == IPPROTO_TCP)
			     || (inner_iph->protocol == IPPROTO_UDP)) {
				uint16_t *l4_hdr =
					(uint16_t *) ((uint8_t *) inner_iph +
							(inner_iph->ihl << 2));
				sport = *l4_hdr;
				dport = *(l4_hdr + 1);
			}
		}
		return sw_ipv4_hash(wqe, inner_iph->saddr, inner_iph->daddr,
				    sport, dport, inner_iph->protocol, vlan_id,
				    inner_eth->h_source, inner_eth->h_dest,
				    vx_vni, from_lpport);
	} else {
		/* IPv6 Packet */
		uint8_t l4proto = 0;
		uint16_t *l4header = NULL;
		uint32_t l4len;
		s_ptr = inner_ipv6h->saddr.s6_addr32;
		d_ptr = inner_ipv6h->daddr.s6_addr32;

		cvmcs_nic_get_l4_from_ipv6_with_exthdr((uint8_t *)inner_ipv6h,
					&l4header, &l4len, &l4proto);
		if ((l4proto == IPPROTO_TCP) || (l4proto == IPPROTO_UDP)) {
			sport = *l4header;
			dport = *(l4header + 1);
		}
		return sw_ipv6_hash(wqe, (uint64_t *) s_ptr, (uint64_t *) d_ptr,
				    sport, dport, l4proto, vlan_id,
				    inner_eth->h_source, inner_eth->h_dest,
				    vx_vni, from_lpport);
	}

	return 0;
}

#ifdef FLOW_ENGINE


/**
 *	cfe_lut_insert - Flow engine look up table insert
 *	node:      Hash node to insert
 *	key:       Hash Key value
 *  vport:     Dispatch table index
 *  comp:      Component
 **/
int
cfe_lut_insert(hash_node_t *node, hash_key_type_t key, int vport, int comp)
{
	hash_node_t *lut;
	cfe_dispatch_entry_t *flow_dispatch;

	if (!node) {
		printf(":%s Error node:NULL key:%x vport:%d comp:%x \n", __func__, key, vport, comp);
		return -1;
	}

	DBG2(":%s node:%lx key:%x vport:%d comp:%x \n", __func__,(uint64_t)node, key, vport, comp);
	flow_dispatch = &octnic->cfe_dispatch_tbl[vport];
	lut = (hash_node_t  *)flow_dispatch->cmpnt_lut[comp-1];

	hash_node_insert_tail(node, &lut[key]);

	return 0;
}

/**
 *	cfe_lut_del - Flow engine look up table del
 *	node:      Hash node to del
 *  vport:     Dispatch table index
 *  comp:      Component
 **/
int
cfe_lut_del(hash_node_t *node, int vport, int comp)
{

	if (!node) {
		printf(":%s Error node:NULL vport:%d comp:%x \n", __func__, vport, comp);
		return -1;
	}
	DBG2(":%s node:%lx vport:%d comp:%x \n", __func__, (uint64_t)node, vport, comp);
	hash_node_del(node);

	return 0;
}

/**
 *	cfe_lut_search - Flow engine look up table search op
 *	temp_ctx:  context for search pattern
 *  vport:     Dispatch table index
 *  comp:      Component
 **/
hash_node_t *
cfe_lut_search(void *temp_ctx, hash_key_type_t key, int vport, int comp)
{
	hash_node_t *lut, *node, *head;
	cfe_dispatch_entry_t *flow_dispatch;
	cvmcs_component_t *component;

	if (!temp_ctx) {
		printf(":%s Error temp_ctx:NULL vport:%d comp:%x \n", __func__, vport, comp);
		return NULL;
	}

	DBG2(":%s  key:%x vport:%d comp:%x \n", __func__, key, vport, comp);
	component = octnic->cfe_components[comp -1];
	flow_dispatch = &octnic->cfe_dispatch_tbl[vport];
	lut = (hash_node_t  *)flow_dispatch->cmpnt_lut[comp-1];
	head = &lut[key];

	hash_for_each_node(node, head) {
		if (component->flow_compare(temp_ctx, node)) {
			DBG2(":%s return node:%lx key:%x vport:%d comp:%x \n", __func__,(uint64_t)node, key, vport, comp);
			return node;
		}
	}

	DBG2(":%s return:NULL key:%x vport:%d comp:%x \n", __func__, key, vport, comp);

	return NULL;
}


/**
 *	cvmcs_cfe_register_component - Template for component registration
 **/
int
cvmcs_cfe_register_component(cvmcs_component_t *comp)
{
	uint32_t idx;

	if (octnic->cfe_num_cmpnts == CFE_MAX_COMPONENTS) {
		printf("Error:%s cfe_num_cmpnts:%d exceeded CFE_MAX_COMPONENTS\n", __func__, octnic->cfe_num_cmpnts);
		return 1;
	}	
	idx = octnic->cfe_num_cmpnts;
	DBG2("func:%s comp:%s op:%X \n", __func__, comp->name, comp->opcode);
	octnic->cfe_components[idx] = comp;
	octnic->cfe_num_cmpnts++;

	return 0;
}

/**
 *	cvmcs_cfe_init_components - Template for configuring all components
 *								which can be assigned to CFE dispatch table.
 **/
int
cvmcs_cfe_init_components()
{
	cvmcs_component_t *cfe_default_op;

	/* Register for other components  : TODO */

	/* Register for Default forwarding operation */
	cfe_default_op = cvmx_bootmem_alloc(sizeof(cvmcs_component_t), CVMX_CACHE_LINE_SIZE);
	if (cfe_default_op == NULL) {
		printf("%s Allocation failed for cfe_default_op\n", __FUNCTION__);
		return 1;
	}
	memset(cfe_default_op, 0, sizeof(cvmcs_component_t));
	strcpy(cfe_default_op->name, "Default Forwarding");
	cfe_default_op->opcode = CFE_DEFAULT_OP;
	cfe_default_op->global_init = NULL;
	cfe_default_op->lut_init = cvmcs_lro_lut_init;
	cfe_default_op->flow_compare = cvmcs_lro_flow_compare;
	cfe_default_op->from_host_msg_cb = NULL;
	cfe_default_op->vnic_traffic = cvmcs_vnic_traffic;
	cfe_default_op->uplink_traffic = cvmcs_uplink_traffic;

	if (cvmcs_cfe_register_component(cfe_default_op)) {
		printf("%s comp registration failed \n", __FUNCTION__);
		return 1;
	}

	return 0;
}

/**
 *	cvmcs_vnic_traffic - Default  function for forwarding traffic.
 *	cfe: dispatch entry for corresponding port.
 *	vport: port info 
 **/
int
cvmcs_vnic_traffic(cvmx_wqe_t *wqe, cfe_dispatch_entry_t *cfe, vnic_port_info_t *vport)
{
	pkt_proc_flags_t flags = {.u=0,};
	int ret=0; 

	ret = cvmcs_nic_process_wqe_ifidx(wqe, vport->linfo.ifidx, flags);
	if (ret) {
		printf("Error :%s handling host traffic ifidx:%d \n", __func__, vport->linfo.ifidx);
		return CFE_COMP_DROPPED;
	}

	return CFE_COMP_CONSUMED;
}

/**
 *	cvmcs_uplink_traffic - Default  function for forwarding traffic.
 *	cfe: dispatch entry for corresponding port.
 *	vport: port info 
 **/
int
cvmcs_uplink_traffic(cvmx_wqe_t *wqe, cfe_dispatch_entry_t   *cfe, vnic_port_info_t *vport)
{
	pkt_proc_flags_t flags;

	flags.u = 0;

	cvmcs_nic_forward_packet_to_wire(wqe, flags);
	return CFE_COMP_CONSUMED;
}

/**
 * Function for generating index into dispatch table.  Works in the to-wire direction.
 *
 * @param wqe work entry
 * @returns interface index
 */
uint32_t
cvmcs_cfe_vport_lookup(cvmx_wqe_t *wqe)
{
	cvmx_raw_inst_front_t *front;
	union octnic_packet_params packet_params;

	front = (cvmx_raw_inst_front_t *)wqe->packet_data;
	packet_params.u32 = front->irh.s.ossp;
	return (packet_params.s.ifidx);
}

/**
 *	cvmcs_cfe_handle_vport_traffic
 *	- Flow engine default routine to handle traffic from host 
 */
int
cvmcs_cfe_handle_vport_traffic(cvmx_wqe_t *wqe)
{
	cfe_dispatch_entry_t *flow_dispatch;
	cvmcs_component_t *oct_components;
	uint32_t i, cmpnt, ret, ifidx;

	ifidx   = cvmcs_cfe_vport_lookup(wqe);
	if (ifidx >= CFE_DISPATCH_TBL_SZ) {
			printf("func:%s Error sending traffic from invalid vport:%d \n",__func__, ifidx);
			cvm_free_wqe_wrapper(wqe);
			return -1;

	}
	flow_dispatch = &octnic->cfe_dispatch_tbl[ifidx];

	/*
	 * Traverse all components configured for this vport
	 */
	for (i = 0, cmpnt=1; i < octnic->cfe_num_cmpnts; i++,cmpnt <<=1) {
		oct_components = octnic->cfe_components[i];
		if (flow_dispatch->cmpnts_enabled & cmpnt) {
			ret = oct_components->uplink_traffic(wqe, flow_dispatch, &octnic->port[ifidx]);
			if (cvmx_likely(ret == CFE_COMP_CONSUMED))
				break;
		}
	}

	if (ret != CFE_COMP_CONSUMED) {
		printf("func:%s Error sending vnic traffic from vport:%d \n",__func__, ifidx);
		cvm_free_wqe_wrapper(wqe);
		return -1;
	}

	return 0;
}

/**
 *	cvmcs_cfe_handle_uplink_traffic - Flow engine default routine to 
 *										Handle traffic from wire 
 */
int
cvmcs_cfe_handle_uplink_traffic(cvmx_wqe_t *wqe)
{
	cfe_dispatch_entry_t *flow_dispatch;
	cvmcs_component_t *oct_components;
	struct ifidx_list iflist;
	struct ifidx_list *ifl = &iflist;
	uint32_t i, cmpnt, ret = 0, ifidx;

	ifidx = cvmcs_nic_get_ifidx_list(wqe, ifl);
	if (ifidx >= CFE_DISPATCH_TBL_SZ) {
			printf("func:%s Error sending uplink traffic from invalid vport:%x \n",__func__, ifidx);
			cvm_free_wqe_wrapper(wqe);
			return -1;
	}

	/* TODO: Handle multicast and broadcast, by traversing ifidx_list */
	flow_dispatch = &octnic->cfe_dispatch_tbl[ifidx];

	/* TODO handle rcv_error failures and peg fw_err_drop stat. */


	/*
	 * Traverse all components configured for this vport
	 */
	for (i = 0, cmpnt=1; i < octnic->cfe_num_cmpnts; i++,cmpnt <<=1) {
		oct_components = octnic->cfe_components[i];
		if (flow_dispatch->cmpnts_enabled & cmpnt) {
			ret = oct_components->vnic_traffic(wqe, flow_dispatch, &octnic->port[ifidx]);
			if ((ret == CFE_COMP_CONSUMED) ||
			 	(ret == CFE_COMP_DROPPED))
				break;
		}
	}

	if ((ret != CFE_COMP_CONSUMED) &&
					(ret != CFE_COMP_DROPPED)) {
			printf("func:%s Error sending uplink traffic from vport:%d \n",__func__, ifidx);
			cvm_free_wqe_wrapper(wqe);
			return -1;
	}

	return 0;
}
#endif

/** Updates the last field in the iflist with the most significant bit that is
 * set.
 *
 * @param ifl  ifidx_list with zero or more mask bits set.
 */
void iflist_set_last(struct ifidx_list *ifl)
{
	unsigned int i;
	int msb = 0;

	ifl->last = 0;
	for (i=0; i< IFL_SIZE; i++) {
		if (!ifl->mask[i])
			continue;
		msb = (63 - __builtin_clzll(ifl->mask[i]));
		ifl->last = (64 * i) + msb;
	}
}

/** Updates the active field in the iflist with whether any bits are set
 *
 * @param ifl  ifidx_list with zero or more mask bits set.
 */
void iflist_set_active(struct ifidx_list *ifl)
{
       unsigned int i;

       ifl->active = 0;
       for (i = 0; i < IFL_SIZE; i++) {
	       if (ifl->mask[i]) {
		       ifl->active = 1;
		       return;
	       }
       }
}

/** Sets the first ifl to the union of both.
 *
 * @param a  ifidx_list with zero or more mask bits set. This will also contain
 * the result of the union
 * @param b  ifidx_list with zero or more mask bits set.
 */
void iflist_union(struct ifidx_list *a, struct ifidx_list *b)
{
       unsigned int i;

       for (i = 0; i < IFL_SIZE; i++)
               a->mask[i] |= b->mask[i];

       iflist_set_last(a);
       iflist_set_active(a);
}

void iflist_intersection(struct ifidx_list *a, struct ifidx_list *b)
{
       unsigned int i;

       for (i = 0; i < IFL_SIZE; i++)
               a->mask[i] &= b->mask[i];

       iflist_set_last(a);
       iflist_set_active(a);
}

#ifdef DELAY_DELETE_SA
static void cvmcs_nic_complete_delete_sa(cvmx_wqe_t *timer_wqe, cvmx_raw_inst_front_t *front)
{

	uint8_t *oct_sa_data = (uint8_t *) front->ossp[0];

	cvm_ipsec_delete_sa_completion(oct_sa_data);
}
#endif // DELAY_DELETE_SA

static void cvmcs_set_trusted_vf(cvmx_wqe_t *wqe)
{
	cvmx_raw_inst_front_t *front;
	gmx_port_info_t *info;
	int ifidx, vf_ifidx;
	uint32_t gmxport;
	uint64_t retaddr;

	if (octeon_has_feature(OCTEON_FEATURE_CN78XX_WQE))
		front = (cvmx_raw_inst_front_t *) cvmx_phys_to_ptr(cvmx_wqe_get_pki_pkt_ptr(wqe).addr);
	else
		front = (cvmx_raw_inst_front_t *)wqe->packet_data;

	ifidx = get_vnic_port_id(cvmx_wqe_get_port(wqe));
	gmxport = ifidx / OCT_NIC_VFS_PER_PF;
	info = &octnic->gmx_port_info[gmxport];

	if (OCT_NIC_IS_PF(ifidx)) {
		vf_ifidx = front->ossp[0] + ifidx;

		if (front->ossp[1] && !info->trusted_vf.active) {
			info->trusted_vf.active = true;
			info->trusted_vf.id = vf_ifidx;
			cvmcs_printf("VF with ifidx %u is trusted\n",
				     vf_ifidx);
		}

		if (!front->ossp[1] && info->trusted_vf.id == vf_ifidx) {
			info->trusted_vf.active = false;
			cvmcs_printf("VF with ifidx %u is not trusted\n",
				     vf_ifidx);
		}
	}

	if (front->irh.s.rflag && front->rptr) {
		retaddr = front->rptr + 8;

		if (OCTEON_IS_MODEL(OCTEON_CN73XX))
			cvm_pci_pvf_mem_writell(retaddr, 0, cvm_pcie_pvf_num(wqe));
		else
			cvm_pci_mem_writell(retaddr, 0);
	}

	cvmcs_wqe_free(wqe);
}

/** All work received by the application is forwarded to this routine.
  * All RAW packets with opcode=0x1234 and param=0x10 are test instructions
  * and handle by the application. All other RAW packets with opcode in
  * the range 0x1000-0x1FFF is given to the core driver. All other packets
  * are dropped.
  */
static inline int cvmcs_nic_process_wqe(cvmx_wqe_t * wqe)
{
	cvmx_raw_inst_front_t *front;
	uint8_t opcode, subcode;
	int port;
	int came_from_a_dpi_ring=0;


	/* Profiling uses this point as the start */
	cvmcs_profile_start();


	/* PKI#20776 Errata Workaround for CN78xx pass1.x */
	if (OCTEON_IS_MODEL(OCTEON_CN78XX_PASS1_X))
		cvmx_wqe_pki_errata_20776(wqe);

	if (octeon_has_feature(OCTEON_FEATURE_CN78XX_WQE))
		front = (cvmx_raw_inst_front_t *) cvmx_phys_to_ptr(cvmx_wqe_get_pki_pkt_ptr(wqe).addr);
	else
		front = (cvmx_raw_inst_front_t *)wqe->packet_data;

	//cvmx_helper_dump_packet(wqe);

	port = cvmx_wqe_get_port(wqe);
	if (OCTEON_IS_MODEL(OCTEON_CN78XX)) {
		if (port >= 0x100 && port <= 0x13f)
			came_from_a_dpi_ring = 1;
	} else if (OCTEON_IS_MODEL(OCTEON_CN73XX)) {
		if (port >= 0x100 && port <= 0x17f)
			came_from_a_dpi_ring = 1;
	}

	if (((octeon_has_feature(OCTEON_FEATURE_CN78XX_WQE)) 
	     && ((((cvmx_wqe_78xx_t *)wqe)->word2.software) ||
	    came_from_a_dpi_ring)) ||
	    (!OCTEON_IS_OCTEON3() && (wqe->word2.s.software))) {

		DBG("(%d)RawWQE @ %p ipprt: %d bufs: %d len: %d opcode: %x/%x ossp: %x\n",
			core_id, wqe, cvmx_wqe_get_port(wqe), cvmx_wqe_get_bufs(wqe), cvmx_wqe_get_len(wqe), front->irh.s.opcode, front->irh.s.subcode, front->irh.s.ossp);
		opcode = front->irh.s.opcode;
		subcode = front->irh.s.subcode;

		switch (opcode) {

		case OPCODE_NIC:
			switch (subcode) {
			case OPCODE_NIC_NW_DATA:
#if defined(LINUX_IPSEC) || defined(HYBRID)
				if (cvmcs_nic_component_host_packet(wqe))
					cvmcs_nic_switch_packets_from_dpi(wqe);
#else
#ifdef FLOW_ENGINE
				cvmcs_cfe_handle_vport_traffic(wqe);
#else
				cvmcs_nic_switch_packets_from_dpi(wqe);
#endif

#endif //HYBRID
				break;

			case OPCODE_NIC_CMD:
				cvmcs_nic_process_cmd(wqe);
				break;
			case OPCODE_NIC_IF_CFG:
				cvmcs_nic_if_cfg(wqe);
				break;

			case OPCODE_NIC_QCOUNT_UPDATE:
				{
					union oct_nic_if_cfg  if_cfg;
					int ifidx;

					if_cfg.u64 = front->ossp[0];
					ifidx = OCT_NIC_PORT_IDX(if_cfg.s.gmx_port_id, 0);

					octnic->port[ifidx].state.active = 0;
					cvm_drv_start_pf(if_cfg.s.gmx_port_id,
							 octnic->ngmxports,
							 octnic->max_nic_ports);
					cvmcs_nic_if_cfg(wqe);
				}
				break;

			case OPCODE_NIC_INFO:
				cvmcs_nic_send_link_info(wqe);
				break;

			case OPCODE_NIC_MDIO45:
				cvmcs_nic_send_mdio_info(wqe);
				break;

			case OPCODE_NIC_PORT_STATS:
				cvmcs_nic_send_port_stats(wqe);
				break;

			/*NIC Internal opcodes*/
			case OPCODE_NIC_TIMESTAMP:
				cvmcs_nic_send_timestamp(wqe);
				break;

			case OCT_NIC_TSO_COMPLETION_OP:
				{
					cvmcs_nic_metadata_t *mdata = CVMCS_NIC_METADATA(wqe);
					/* Original WQE and associated packet buffers */
					if (octeon_has_feature(OCTEON_FEATURE_CN78XX_WQE)) {
						/* we have added front_data in a separate buffer
					 	* in metadata. Remove it before calling free
					 	* to avoid double free of buffer containg wqe.
					 	*/
						cvmcs_nic_delete_first_buffer(wqe);
					}

					if (CVMCS_NIC_METADATA_IS_DUP_WQE(mdata)) {
						cvmx_atomic_add64(mdata->wqe_ref_count, -1);
					}
					else {
						cvm_free_wqe_wrapper(wqe);
					}
				}
				break;

			case OCT_NIC_LRO_TIMER_OP:
				{
					lro_context_t *lro_ctx = (lro_context_t *)front->ossp[0];
					cvmcs_nic_flush_lro(wqe, lro_ctx, 0);
					cvmcs_wqe_free(wqe);
				}
				break;

			case OCT_NIC_LRO_COMPLETION_OP:
				{
					int bp_credits;
					cvmcs_nic_metadata_t *mdata = CVMCS_NIC_METADATA(wqe);
					cvmx_wqe_t *wqe_list = wqe;
					uint32_t wqe_list_size = mdata->front.ossp[1] & 0xFFFF;

					int is_dup = CVMCS_NIC_METADATA_IS_DUP_WQE(mdata);

					if (octeon_has_feature(OCTEON_FEATURE_CN78XX_WQE)) {
						/* we have added front_data in a separate buffer
						 * in metadata. Remove it before calling free
						 * to avoid double free of bufferi containg wqe.
						 */
						cvmcs_nic_delete_first_buffer(wqe);
					} else {
						bp_credits = front->ossp[1] >> 16;
						cvm_update_bp_port(cvmx_wqe_get_port(wqe),
						   		bp_credits);
					}


					while(wqe_list_size-- > 0) {
						mdata = CVMCS_NIC_METADATA(wqe_list);
						wqe_list = (cvmx_wqe_t *)mdata->front.ossp[0];
						cvmx_atomic_add64(mdata->wqe_ref_count, -1);
					}

					if (!is_dup) {
						cvmx_wqe_free(wqe);
					}
				}
				break;
			case OPCODE_NIC_INTRMOD_CFG:
				cvmcs_intrmod_cfg(wqe);
				break;
			case OPCODE_NIC_INTRMOD_PARAMS:
				cvmcs_intrmod_params(wqe);
				break;
			#ifdef DELAY_DELETE_SA
			case OCT_NIC_DELETE_SA_TIMER_OP:
				{
					cvmcs_nic_complete_delete_sa(wqe, front);
					cvmcs_wqe_free(wqe);
				}
				break;
			#endif //DELAY_DELETE_SA

			case OCT_NIC_FLR_BH_OP:
				cn73xx_flr_intr_handler_bh(wqe);
				break;

			case OPCODE_NIC_DCB_CFG:
			case OPCODE_NIC_DCBX_TIMER:
			case OPCODE_NIC_QCN_BYTE_COUNTER:
			case OPCODE_NIC_QCN_TIMER_COUNTER:
				cvmcs_dcb_dpi_wqe_handler(wqe);
				break;
			case OPCODE_NIC_SET_TRUSTED_VF:
				cvmcs_set_trusted_vf(wqe);
				break;

			case OPCODE_NIC_SYNC_OCTEON_TIME:
				cvmcs_hybrid_sync_octeon_time(wqe);
				break;

			case OPCODE_NIC_VF_REP_PKT:
				cvmcs_hybrid_vf_rep_pkt(wqe);
				break;

			case OPCODE_NIC_VF_REP_CMD:
				cvmcs_hybrid_vf_rep_cmd(wqe);
				break;

			case OPCODE_NIC_UBOOT_CTL:
				cvmcs_nic_uboot_ctl(wqe);
				break;

			case OPCODE_NIC_GET_DUMP:
				cvmcs_nic_get_dump(wqe);
				break;

			case OPCODE_NIC_SET_DUMP:
				cvmcs_nic_set_dump_flag(wqe);
				break;

			case OPCODE_NIC_GET_DUMP_FLAG:
				cvmcs_nic_get_dump_flag(wqe);
				break;

			case OPCODE_NIC_SFP_MOD_INFO:
				cvmcs_nic_sfp_mod_info(wqe);
				break;

			case OPCODE_NIC_VF_PORT_STATS:
				cvmcs_nic_send_vf_port_stats(wqe);
				break;

			default:
				cvm_drv_process_instr(wqe);
				break;
			}
			break;

		default:
			/*try components*/
			if (cvmcs_nic_component_host_message(wqe,
						opcode, subcode))
				cvm_drv_process_instr(wqe);

		}		/* switch */

		cvmcs_profile_mark_event(PROF_TX_DONE);

	} else {
#if defined(LINUX_IPSEC) || defined(HYBRID)
		if (!cvmcs_nic_component_wire_packet(&wqe))
			return -ENOIF;
#endif
		return cvmcs_nic_switch_packets_from_gmx(wqe);
	}

	return -ENOIF;
}


/* BP feature: check and handle BP */
/* Assumption for DPI is that all queues belonging to same port will use the same bpid
 * that reduces the number of bpids that need to be handled
 */
static inline void cvm_handle_bp(void)
{
#if (defined(DPI_BP) || defined(GMX_BP))
	unsigned int i;
	int cnt;
	uint64_t creditback;

#define is_bp_core(x)	is_boot_core(x)	/* backpressure core for single-core credit returns:66xx */
	if (is_bp_core(core_id)) {	/* single-core credit update */
#ifdef DPI_BP
		if (OCTEON_IS_MODEL(OCTEON_CN68XX)) {
			/* 68xx: return credits for each BPID first */
			uint64_t bpid_handled_mask = 0;
			for (i = 0; i < MAX_PCI_PORTS_68XX; i++) {
				if ((octnic->dpi_bp.cn68xx.dpi_bp_fau_map[i].s.enabled) &&
				    (!(1ULL << octnic->dpi_bp.cn68xx.dpi_bp_fau_map[i].s.bpid &  bpid_handled_mask))) {
					bpid_handled_mask |= (1ULL << octnic->dpi_bp.cn68xx.dpi_bp_fau_map[i].s.bpid);
					cnt = cvmx_fau_fetch_and_add32(octnic->dpi_bp.cn68xx.dpi_bp_fau_map[i].s.fau, 0);
					if ((-cnt) >= DPI_BP_HANDLE_INTERVAL_68XX) {
						//printf("dpi bp iq_num %d bpid %d fau cnt %d\n", i,
						 //     octnic->dpi_bp.cn68xx.dpi_bp_fau_map[i].s.bpid,
						  //    cnt);
						//printf("bp counter before:bpid %d cntr %lu\n",octnic->dpi_bp.cn68xx.dpi_bp_fau_map[i].s.bpid,
						 //             cvmx_read_csr(
						  //            CVMX_IPD_BPID_BP_COUNTERX(octnic->dpi_bp.cn68xx.dpi_bp_fau_map[i].s.bpid)));
						creditback =((octnic->dpi_bp.cn68xx.dpi_bp_fau_map[i].s.bpid << 25) |
							     (cnt & 0x1ffffffU));
						cvmx_write_csr(CVMX_IPD_SUB_PORT_BP_PAGE_CNT, creditback);
						cvmx_fau_fetch_and_add32(octnic->dpi_bp.cn68xx.dpi_bp_fau_map[i].s.fau, -cnt);
						//printf("bp counter after:bpid  %d cntr %lu\n",octnic->dpi_bp.cn68xx.dpi_bp_fau_map[i].s.bpid,
						 //             cvmx_read_csr(
						  //            CVMX_IPD_BPID_BP_COUNTERX(octnic->dpi_bp.cn68xx.dpi_bp_fau_map[i].s.bpid)));
					}
				}
			}
		} else if (OCTEON_IS_MODEL(OCTEON_CN66XX)) {
			for (i = 0; i < MAX_PCI_PORTS_66XX; i++) {
				if (octnic->dpi_bp.cn66xx.dpi_bp_fau_map[i].s.enabled) {
					union cvmx_ipd_sub_port_bp_page_cnt page_cnt;
					/*Number of buffers were freed by PKO */
					cnt = cvmx_fau_fetch_and_add32(octnic->dpi_bp.cn66xx.dpi_bp_fau_map[i].s.fau,
							     0);
					if ((-cnt) >= DPI_BP_HANDLE_INTERVAL_66XX) {
						/*Reset the register*/
						//printf("dpi bp port %d   fau cnt %d\n", (i+32), cnt);
						//printf("bp counter before: port %d cntr %lu\n", (i+32),
						 //             cvmx_read_csr(CVMX_IPD_PORT_BP_COUNTERS_PAIRX(i+32)));
						page_cnt.u64 = 0;
						page_cnt.s.port = i + 32;
						/*2's complement of the number to be subtracted, 25 bits only */
						page_cnt.s.page_cnt = (0x1ffffffU & cnt);
						cvmx_write_csr(CVMX_IPD_SUB_PORT_BP_PAGE_CNT, page_cnt.u64);
						cvmx_fau_fetch_and_add32(octnic->dpi_bp.cn66xx.dpi_bp_fau_map[i].s.fau, -cnt);
						//printf("bp counter after:port %d cntr %lu\n", (i+32),
						 //             cvmx_read_csr(CVMX_IPD_PORT_BP_COUNTERS_PAIRX(i+32)));
					}
				}
			}
		}
#endif				/* DPI */

#ifdef	GMX_BP
		if (OCTEON_IS_MODEL(OCTEON_CN68XX)) {
			for (i = 0; i < octnic->ngmxports; i++) {
				if (octnic->gmx_bp.cn68xx.gmx_bp_fau_map[i].s.enabled) {
					cnt =
					    cvmx_fau_fetch_and_add32(octnic->
								     gmx_bp.cn68xx.gmx_bp_fau_map
								     [i].s.fau,
								     0);
					if ((-cnt) >= GMX_BP_HANDLE_INTERVAL_68XX) {
						//printf("gmx bp port %d bpid %d fau cnt %d\n", i,
						//	  octnic->gmx_bp.cn68xx.gmx_bp_fau_map[i].s.bpid, cnt);
						//printf("bp counter before:bpid  %d cntr %lu\n",octnic->gmx_bp.cn68xx.gmx_bp_fau_map[i].s.bpid,
						 //      cvmx_read_csr(CVMX_IPD_BPID_BP_COUNTERX(octnic->gmx_bp.cn68xx.gmx_bp_fau_map[i].s.bpid)));

						cnt =
						    cvmx_fau_fetch_and_add32(octnic->gmx_bp.cn68xx.gmx_bp_fau_map[i].s.fau, 0);
						creditback = ((octnic->gmx_bp.cn68xx.gmx_bp_fau_map[i].s.bpid << 25) |
							      (cnt & 0x1ffffffU));
						cvmx_write_csr(CVMX_IPD_SUB_PORT_BP_PAGE_CNT, creditback);
						cvmx_fau_fetch_and_add32(octnic->gmx_bp.cn68xx.gmx_bp_fau_map[i].s.fau, -cnt);
						//printf("bp counter after:bpid  %d cntr  %lu\n",octnic->gmx_bp.cn68xx.gmx_bp_fau_map[i].s.bpid,
						 //           cvmx_read_csr(
						  //          CVMX_IPD_BPID_BP_COUNTERX(octnic->gmx_bp.cn68xx.gmx_bp_fau_map[i].s.bpid)));
					}
				}
			}
		} else if (OCTEON_IS_MODEL(OCTEON_CN66XX)) {	/* 66xx: handle backpressure credits */
			for (i = 0; i < octnic->ngmxports; i++) {
				if (octnic->gmx_bp.cn66xx.gmx_bp_fau_map[i].s.enabled) {
					union cvmx_ipd_sub_port_bp_page_cnt page_cnt;

					cnt = cvmx_fau_fetch_and_add32(octnic->gmx_bp.cn66xx.gmx_bp_fau_map[i].s.fau, 0);
					if ((-cnt) >= GMX_BP_HANDLE_INTERVAL_66XX) {
						//printf("gmx bp port %d  fau cnt %d\n", octnic->gmx_port_info[i].ipd_port, cnt);
						//printf("bp counter before:port  %d cntr %lu\n", octnic->gmx_port_info[i].ipd_port,
						 //          cvmx_read_csr(CVMX_IPD_PORT_BP_COUNTERS_PAIRX(octnic->gmx_port_info[i].ipd_port)));
						/*Reset the register*/
						page_cnt.u64 = 0;
						page_cnt.s.port = octnic->gmx_port_info[i].ipd_port;
						/*2's complement of the number to be subtracted, 25 bits only */
						page_cnt.s.page_cnt = (0x1ffffffU & cnt);
						cvmx_write_csr(CVMX_IPD_SUB_PORT_BP_PAGE_CNT, page_cnt.u64);
						cvmx_fau_fetch_and_add32(octnic->gmx_bp.cn66xx.gmx_bp_fau_map[i].s.fau, -cnt);
						//printf("bp counter after:port  %d cntr %lu\n", octnic->gmx_port_info[i].ipd_port,
						 //             cvmx_read_csr(CVMX_IPD_PORT_BP_COUNTERS_PAIRX(octnic->gmx_port_info[i].ipd_port)));
					}
				}
			}

		}
#endif				/* GMX */
	}
#endif				/* DPI OR GMX */
}


#define max(X, Y)                               \
        ({ typeof(X) __x = (X);                \
        typeof(Y) __y = (Y);                    \
        (__x > __y) ? __x : __y; })



void cvm_moderate_intlvl()
{				/* intrmod: moderate interrupt levels */
	int port;
	vnic_port_info_t *nicport;
	uint64_t pktrate, byterate=0, pktsize=0;
	uint64_t rx_csrcnt[MAX_IOQS_PER_NICIF] = { 0 };
	uint64_t rx_csrtmr[MAX_IOQS_PER_NICIF] = { 0 };
	uint64_t tx_csrcnt[MAX_IOQS_PER_NICIF] = { 0 };
	/* we dont have csr tmr for tx, but imagine that we do so as to adjust rx tmr properly */
	uint64_t tx_csrtmr[MAX_IOQS_PER_NICIF] = { 0 };
	uint64_t imodpps = 0ULL;
	uint64_t imodticks;
	uint64_t intlvl_start_cycle;
	uint64_t intmod_cycles;
	uint64_t total_last_fwd=0, fromwire_total_fwd=0, fromhost_total_fwd=0;
	uint64_t total_last_fwd_bytes=0, fromhost_total_fwd_bytes=0, fromwire_total_fwd_bytes=0;
	int i,j;

	if (OCTEON_IS_MODEL(OCTEON_CN6XXX)) {
		if (!intmod_enable)
			return;
		intlvl_start_cycle = cvmx_get_cycle();
		intmod_cycles = CYCLE_DIFF(intlvl_start_cycle, last_intmod_check);
		if (intmod_cycles < intrmod_check_intrvl)
			return;
		imodticks = intmod_cycles;

		for (port = 0; port < MAX_OCTEON_NIC_PORTS; port++) {
			nicport = &octnic->port[port];
			if (nicport->state.active) {
				total_last_fwd = last_fwdpkts[port];
				for (i = 0; i < MAX_CORES; i++) {
					for (j =0; j < MAX_IOQS_PER_NICIF; j++)
						fromwire_total_fwd +=  per_core_stats[i].perq_stats[port].fromwire.fw_total_fwd[j];
				}
				pktrate = total_last_fwd ? CYCLE_DIFF(fromwire_total_fwd, total_last_fwd) : (uint64_t)fromwire_total_fwd;
				imodpps += pktrate;
				last_fwdpkts[port] = fromwire_total_fwd;
			}
		}
		if (imodticks)
			imodpps /= (imodticks + cpu_freq - 1) / cpu_freq;
		if (imodpps >= intrmod_maxpkt_ratethr) {
			rx_csrcnt[0] = intrmod_maxcnt_trigger;
			rx_csrtmr[0] = intrmod_maxtmr_trigger;
		} else if (imodpps > intrmod_minpkt_ratethr) {
			uint64_t level =
				(intrmod_maxpkt_ratethr + INTRMOD_INTRVL_LEVELS -
				 1) / INTRMOD_INTRVL_LEVELS;
			if (imodpps > level)
				rx_csrcnt[0] = rx_csrtmr[0] = 0ULL;
			while (imodpps > level) {
				imodpps -= level;
				rx_csrcnt[0] += intrmod_rxcnt_steps;
				rx_csrtmr[0] += intrmod_rxtmr_steps;
			}
		}
		cvmx_write_csr_node(cvmx_get_node_num(), CVMX_PEXP_SLI_PKT_INT_LEVELS, (rx_csrtmr[0] << 32) | rx_csrcnt[0]);
		last_intmod_check = intlvl_start_cycle;
	} else if (OCTEON_IS_MODEL(OCTEON_CN73XX)) {
		int pf_id,vf_id;
		int mac_id = 0;
		int base_queue, max_queues, i;
		uint64_t csrtmr, csrcnt;

		for (port = 0; port < MAX_OCTEON_NIC_PORTS; port++) {
			nicport = &octnic->port[port];
			pf_id = OCT_NIC_PORT_PF(nicport->ifidx);
			vf_id = OCT_NIC_PORT_VF(nicport->ifidx);
			if (OCTEON_IS_MODEL(OCTEON_CN73XX_PASS1_0) && pf_id == 1) {
				//Due to a hw bug pf1 cannot have interrupt moderation turned on
				nicport->intmod_info.cfg.rx_enable = 0;
				nicport->intmod_info.cfg.tx_enable = 0;
				continue;
			}

#define RXMAX_BYTE_RATE  100000ULL
#define RXMIN_BYTE_RATE  10000ULL
#define RXMIN_SIZE 2000

#ifdef VSWITCH
			if (nicport->state.active && cvmcs_hybrid_get_link_status(nicport->ifidx)) { 
#else
			if (nicport->state.active && nicport->state.rx_on) {
#endif
				intlvl_start_cycle = cvmx_get_cycle();
				intmod_cycles = CYCLE_DIFF(intlvl_start_cycle, nicport->intmod_info.last_check);
				imodticks = intmod_cycles;
				if (intmod_cycles > (nicport->intmod_info.cfg.check_intrvl)) {
					if (nicport->intmod_info.cfg.rx_enable) {
						for (j = 0; j < nicport->linfo.num_rxpciq; j++) {
							fromwire_total_fwd = 0;
							fromwire_total_fwd_bytes = 0;
							total_last_fwd = nicport->intmod_info.last_rxfwd_pkts[j];
							for (i = 0; i <  MAX_CORES; i++) {
								fromwire_total_fwd +=  per_core_stats[i].perq_stats[port].fromwire.fw_total_fwd[j];
							}
							total_last_fwd_bytes = nicport->intmod_info.last_rxfwd_bytes[j];
							for (i = 0; i <  MAX_CORES; i++) {
								fromwire_total_fwd_bytes +=  per_core_stats[i].perq_stats[port].fromwire.fw_total_fwd_bytes[j];
							}
							byterate = total_last_fwd_bytes ? CYCLE_DIFF(fromwire_total_fwd_bytes, total_last_fwd_bytes) : (uint64_t)fromwire_total_fwd_bytes;
							nicport->intmod_info.last_rxfwd_bytes[j] = fromwire_total_fwd_bytes;

							pktrate = total_last_fwd ? CYCLE_DIFF(fromwire_total_fwd, total_last_fwd) : (uint64_t)fromwire_total_fwd;
							nicport->intmod_info.last_rxfwd_pkts[j] = fromwire_total_fwd;

							if (imodticks) {
								byterate = (byterate * nicport->intmod_info.cfg.check_intrvl)/imodticks;
								pktrate  = (pktrate  * nicport->intmod_info.cfg.check_intrvl)/imodticks;
							}

							if (byterate && pktrate)
								pktsize = byterate/pktrate;
							else
								pktsize = 0;

//							DBG2("ifidx %d queue:%d  rx_pktrate %lu rx_pktsize %lu\n", port, j, pktrate*1000, pktsize);

							rx_csrcnt[j] = nicport->intmod_info.cfg.rx_mincnt_trigger;
							rx_csrtmr[j] = nicport->intmod_info.cfg.rx_mintmr_trigger;
							if (pktsize < RXMIN_SIZE) {
								if (byterate >= RXMAX_BYTE_RATE) {
									rx_csrcnt[j] = nicport->intmod_info.cfg.rx_maxcnt_trigger;
									rx_csrtmr[j] = nicport->intmod_info.cfg.rx_maxtmr_trigger;
								} else if (byterate > RXMIN_BYTE_RATE) {
									uint64_t level =
									    ((RXMAX_BYTE_RATE-RXMIN_BYTE_RATE) + INTRMOD_INTRVL_LEVELS -
									     1) / INTRMOD_INTRVL_LEVELS;

									while (byterate > level) {
										byterate -= level;
										rx_csrcnt[j] += nicport->intmod_info.rxcnt_steps;
										/* exponential */
										rx_csrtmr[j] <<= nicport->intmod_info.rxtmr_steps;
									}
								}
							} else {
								/* Needs review */
								if (pktsize < 4000) {
									rx_csrcnt[j] = 8;
									rx_csrtmr[j] = 8;
								} else if (pktsize >= 4000 && pktsize < 8000) {
									rx_csrcnt[j] = 6;
									rx_csrtmr[j] = 6;
								} else if (pktsize >= 8000 && pktsize < 12000) {
									rx_csrcnt[j] = 4;
									rx_csrtmr[j] = 4;
								} else if (pktsize >= 12000 && pktsize < 20000) {
									rx_csrcnt[j] = 2;
									rx_csrtmr[j] = 2;
								} else if (pktsize >= 20000) {
									rx_csrcnt[j] = 1;
									rx_csrtmr[j] = 1;
								}
							}
						}

					}
					/* we spent sometime on the rx queues, adjust imodticks  */
					imodticks += CYCLE_DIFF(cvmx_get_cycle(), intlvl_start_cycle);
					if (nicport->intmod_info.cfg.tx_enable) {
						for (j = 0; j < nicport->linfo.num_txpciq; j++) {
							fromhost_total_fwd = 0;
							fromhost_total_fwd_bytes = 0;
							total_last_fwd = nicport->intmod_info.last_txfwd_pkts[j];
							for (i = 0; i <  MAX_CORES; i++) {
								fromhost_total_fwd +=  per_core_stats[i].perq_stats[port].fromhost.fw_total_fwd[j];
							}

							pktrate = total_last_fwd ? CYCLE_DIFF(fromhost_total_fwd, total_last_fwd) : (uint64_t)fromhost_total_fwd;
							nicport->intmod_info.last_txfwd_pkts[j] = fromhost_total_fwd;

							total_last_fwd_bytes = nicport->intmod_info.last_txfwd_bytes[j];
							for (i = 0; i <  MAX_CORES; i++) {
								fromhost_total_fwd_bytes +=  per_core_stats[i].perq_stats[port].fromhost.fw_total_fwd_bytes[j];
							}

							byterate = total_last_fwd_bytes ? CYCLE_DIFF(fromhost_total_fwd_bytes, total_last_fwd_bytes) : (uint64_t)fromhost_total_fwd_bytes;
							nicport->intmod_info.last_txfwd_bytes[j] = fromhost_total_fwd_bytes;


							if (imodticks) {
								byterate = (byterate * nicport->intmod_info.cfg.check_intrvl)/imodticks;
								pktrate  = (pktrate  * nicport->intmod_info.cfg.check_intrvl)/imodticks;
							}

							if (byterate && pktrate)
								pktsize = byterate/pktrate;
							else
								pktsize = 0;
//							DBG2("ifidx %d queue:%d  tx_pktrate %lu/sec tx_pktsize %lu\n", port, j, pktrate*1000, pktsize);
#define TXMAX_BYTE_RATE (100000ULL)
#define TXMIN_BYTE_RATE (10000ULL)
#define TXMIN_SIZE 2000
							tx_csrcnt[j] = nicport->intmod_info.cfg.tx_mincnt_trigger;
							tx_csrtmr[j] = nicport->intmod_info.cfg.rx_mintmr_trigger;
							if (pktsize < TXMIN_SIZE) {
								if (byterate >= TXMAX_BYTE_RATE) {
									tx_csrcnt[j] = nicport->intmod_info.cfg.tx_maxcnt_trigger;
									tx_csrtmr[j] = nicport->intmod_info.cfg.rx_maxtmr_trigger;
								} else if (byterate > TXMIN_BYTE_RATE) {
									uint64_t level =
									    ((TXMAX_BYTE_RATE-TXMIN_BYTE_RATE) + INTRMOD_INTRVL_LEVELS -
									     1) / INTRMOD_INTRVL_LEVELS;

									while (byterate  > level) {
										byterate -= level;
										tx_csrcnt[j] += nicport->intmod_info.txcnt_steps;
										/* exponential */
										tx_csrtmr[j] <<= nicport->intmod_info.rxtmr_steps;
									}
								}
							} else {
								/* Needs review */
								if (pktsize < 4000) {
									tx_csrcnt[j] = 8;
									tx_csrtmr[j] = 8;
								} else if (pktsize >= 4000 && pktsize < 8000) {
									tx_csrcnt[j] = 6;
									tx_csrtmr[j] = 6;
								} else if (pktsize >= 8000 && pktsize < 12000) {
									tx_csrcnt[j] = 4;
									tx_csrtmr[j] = 4;
								} else if (pktsize >= 12000 && pktsize < 20000) {
									tx_csrcnt[j] = 2;
									tx_csrtmr[j] = 2;
								} else if (pktsize >= 20000) {
									tx_csrcnt[j] = 1;
									tx_csrtmr[j] = 1;
								}
							}
						}
					}

					/* Assumption is that num_rxpciq == num_txpciq for 23XX */
					if (nicport->intmod_info.cfg.tx_enable ||
					    nicport->intmod_info.cfg.rx_enable) {
						if (!vf_id)
							base_queue = (nicport->oq_base - nicport->pf_srn);
						else
							base_queue = 0;
						max_queues = nicport->linfo.num_rxpciq;// == num_txpciq
						cvmx_spinlock_lock(&oct->pp_pkt_csr_ctrl_lock);
						cvmx_write_csr(CVMX_SLI_PP_PKT_CSR_CONTROL, (uint64_t)((mac_id << 16) | (pf_id << 13) | (vf_id)));
						cvmx_read_csr(CVMX_SLI_PP_PKT_CSR_CONTROL);
						for (i = base_queue,j=0; i < (base_queue + max_queues); i++,j++) {
							if (!nicport->intmod_info.cfg.tx_enable) {
								csrcnt = rx_csrcnt[j];
								csrtmr = rx_csrtmr[j];
							} else if (!nicport->intmod_info.cfg.rx_enable) {
								csrcnt = tx_csrcnt[j];
								csrtmr = tx_csrtmr[j];
							} else {
								csrcnt = max(tx_csrcnt[j], rx_csrcnt[j]);
								csrtmr = max(tx_csrtmr[j], rx_csrtmr[j]);
							}
							{
								union cvmx_sli_pkt_in_donex_cnts donecnts;
								uint64_t resend = 0;

                                                                 donecnts.u64 = cvmx_read_csr(CVMX_PEXP_SLI_PKT_IN_DONEX_CNTS(i));
                                                                 if ((donecnts.s.wmark > csrcnt) && (donecnts.s.cnt > csrcnt))
									 resend = 1;
//								DBG2("ifidx %d queue %d  csrcnt:%lu, csrtmr:%lu\n", port, j, csrcnt, csrtmr);
								cvmx_write_csr(CVMX_PEXP_SLI_PKTX_INT_LEVELS(i), (((uint64_t)csrtmr << 32) | csrcnt));
								cvmx_write_csr(CVMX_PEXP_SLI_PKT_IN_DONEX_CNTS(i), ((resend << 60) | (1ULL << 48) |  ((csrcnt & 0xffffUL)<<32)));
							}
						}
						cvmx_spinlock_unlock(&oct->pp_pkt_csr_ctrl_lock);
					}
					nicport->intmod_info.last_check =  intlvl_start_cycle;
				}
			}
		}
	} else if (OCTEON_IS_MODEL(OCTEON_CN78XX)) {
		;//TODO
	}
	CVMX_SYNCW;
}

/** This loop is run by all cores running the application.
  * If any work is available it is processed. If there is no work
  * and
  * If CVMCS_DUTY_CYCLE is enabled, it prints useful statistics
  * at intervals determined by DISPLAY_INTERVAL.
  * If CVMCS_TEST_PKO is enabled, then packets are sent to PKO
  * port 32 at intervals determined by "cvmcs_run_freq".
  * If CVMCS_FIXED_SIZE_TEST is enabled, packets of fixed size
  * are sent. Else packet size can be of range 1-CVM_MAX_DATA
  * where CVM_MAX_DATA cannot be > 65520 bytes.
  */

int cvmcs_nic_data_loop()
{
	cvmx_wqe_t *wqe;
	uint64_t last_link_check = 0;
	uint64_t cur_cycle, last_disp_check, last_cycle;
	int i=0;
	int unplug_or_shutdown_requested_count=0;

	/* cur_cycle is now local to this function. */
	last_disp_check = last_cycle = cur_cycle = cvmx_get_cycle();


	last_intmod_check = cur_cycle;	/* intrmod: intr. moderate cycle */
	intrmod_check_intrvl *= cpu_freq;

#ifdef CONFIG_NIC_CONSOLE	/* NIC console enabled */
#ifdef VSWITCH
    if (is_display_core(core_id))
#else
    if (nic_console_enabled && is_display_core(core_id))	//TBD:DBG_CLI
#endif				/* CONFIG_NIC_CONSOLE */
        nic_cmdl_init();
#endif


	if (is_display_core(core_id)) {	/* intrmod: override and set default intrmod parameters */

		if (OCTEON_IS_MODEL(OCTEON_CN6XXX))
			cvmx_write_csr(CVMX_PEXP_SLI_PKT_INT_LEVELS,
				       (((uint64_t) LIO_INTRMOD_RXMAXTMR_TRIGGER) <<
					32) | LIO_INTRMOD_RXMAXCNT_TRIGGER);
		cvmcs_config_l2c_perf();

		cvmcs_nic_start_mbcast_list_task();

		if (octeon_has_feature(OCTEON_FEATURE_PKO3))
			cvmcs_nic_start_dq_monitoring_task();

		cvmcs_nic_start_timestamp_task();
	}

	cvmcs_app_barrier();

	DBG("Data loop started on core[%d]\n", core_id);

	cvm_app_core_local_init();
	do {
		if (cvmcs_unplug_requested || cvmcs_shutdown_requested) {
			unplug_or_shutdown_requested_count++;
			if (unplug_or_shutdown_requested_count == 2)
				cvmx_app_hotplug_core_shutdown();
		}

		/* kick the watchdog */
		if (OCTEON_IS_MODEL(OCTEON_CN73XX))
			cvmx_write_csr(CVMX_CIU_PP_POKEX(core_id), 1);

#ifdef CONFIG_NIC_CONSOLE	/* NIC console enabled */
		if (nic_console_enabled && is_display_core(core_id)) {	//TBD:DBG_CLI
			nic_cmdl_readline();
		}
#endif				/* CONFIG_NIC_CONSOLE */

		if (!OCTEON_IS_MODEL(OCTEON_CN73XX))
			cvm_handle_bp();	/* update backpressure credits */

		if(is_display_core(core_id))
			cvmcs_common_schedule_tasks();

		if (is_control_core(core_id))
			cvm_drv_start_pfs(octnic->ngmxports, octnic->max_nic_ports);

		last_cycle = cvmx_get_cycle();

		wqe = cvmcs_app_get_work_sync(0);
		if (wqe) {
			CVMX_PREFETCH0((void *) cvmx_phys_to_ptr(cvmx_wqe_get_pki_pkt_ptr(wqe).addr));
			per_core_stats[core_id].wqe_count++;
			// divert NVMe WQEs to that module
			if (is_nvme_wqe(wqe))
				nvme_process_wqe(wqe);
			else
				cvmcs_nic_process_wqe(wqe);

			/* Don't starve "idle" tasks */
			if (i++ % 1000)
				continue;
		}

		cur_cycle = cvmx_get_cycle();

		cvm_app_idle_task();

		/* There is no definition of model PASS2_0 in SDK 1.8.0; check for
		   model CN56XX_PASS2 returns true for CN56XX Pass2.0 parts only.
		   In SDK 1.8.1, check for model CN56XX_PASS2 returns true
		   for all CN56XX Pass 2.X parts, so use model CN56XX_PASS2_0 instead.
		 */

#if (OCTEON_SDK_VERSION_NUM < 108010000ULL)
		if (OCTEON_IS_MODEL(OCTEON_CN56XX_PASS2))
#else
		if (OCTEON_IS_MODEL(OCTEON_CN56XX_PASS2_0))
#endif
			cvm_56xx_pass2_update_pcie_req_num();

		if (is_link_status_core(core_id)) {
			if ((cur_cycle - last_link_check)
			    >= (cpu_freq * link_query_interval) / 1000ULL) {

				cvmcs_nic_check_link_status();
				last_link_check = cur_cycle;
				
				/* clear the pending error interrupts */
				cvm_handle_pending_error_intr(cur_cycle);
			}

		}
		if (is_display_core(core_id)) {
			uint64_t disp_cycles =
			    CYCLE_DIFF(cur_cycle, last_disp_check);

			/* intrmod: moderate interrupt levels */
			cvm_moderate_intlvl();

			cvmcs_flush_printf_buffers();
#ifdef  CVMCS_DUTY_CYCLE
			if ((cur_cycle - last_disp_check)
			    >= (cpu_freq * DISPLAY_INTERVAL)) {
				#ifdef CVM_IPSEC_STATS
				//TODO Move to per core
				cvmcs_nic_print_ipsec_stats();
				#endif //CVM_IPSEC_STATS

				if (!nic_console_enabled || nic_duty_cycle) {
					cvmcs_nic_print_stats(disp_cycles);
					cvmcs_app_duty_cycle_actions(disp_cycles);
					cvmcs_print_l2c_stats(disp_cycles);
					cvmcs_nic_print_cpu_stats(disp_cycles);
					cvmcs_profile_print_stats();
				}
				last_disp_check = cur_cycle;
				/* TODO */
				/* cvmcs_print_rss_config(); */

			}
#endif
		}

		/* Idle time is the sum of all the time from when
		 * we wait for work but don't get any, through
		 * this point.
		 */
		cvmx_fau_fetch_and_add64(octnic->idle_time_fau[core_id],
					 cvmx_get_cycle()-last_cycle);

	} while (1);

	printf("# cvmcs: Core %d Exited from data loop\n", core_id);
}

#ifdef __linux__
void signal_handler(int x)
{
	printf("# cvmcs: Received signal %d, quitting now!!\n", x);
	signal(SIGINT, prev_sig_handler);
	cvmcs_app_shutdown();
	exit(0);
}
#endif

static void modify_ipd_settings(void)
{
	cvmx_ipd_ctl_status_t ipd_reg;
	ipd_reg.u64 = cvmx_read_csr(CVMX_IPD_CTL_STATUS);
	ipd_reg.s.len_m8 = 1;
	cvmx_write_csr(CVMX_IPD_CTL_STATUS, ipd_reg.u64);
}

static void nic_process_cmdline(int argc, char *argv[])
{				/* CLI feature: console enable */
	int i = 0;

	if (argc == 3)
		return;

	for (i = 3; i < argc; i++) {
		if (!strncmp(argv[i], "console", 7))
			nic_console_enabled = 1;
		if (!strncmp(argv[i], "verbose", 7))
			nic_verbose = 1;
		if (!strncmp(argv[i], "nqm_vf_mode=", 12))
			nqm_set_vf_mode(&argv[i][12]);
		if (!strncmp(argv[i], "sata_only_map", 13))
			nvme_set_sata_only_map();
		if (!strncmp(argv[i], "nqm_sq_credits=", 15))
			nvme_set_sq_credits(&argv[i][15]);
		if (!strncmp(argv[i], "intr_coalesce_off", 17))
			nvme_set_intr_coalescing_off();
		if (!strncmp(argv[i], "nqm_cplq_size=", 14))
			nvme_set_cplq_size(&argv[i][14]);
	}
	return;
}

static inline void
cavium_parse_cvs_string(const char *cvs_name, char *ver_string, int len)
{
	static char version[sizeof(LIQUIDIO_VERSION) + 100],
	    cvs_name_str[sizeof(LIQUIDIO_VERSION) + 100];
	char *ptr;

	/* The compiler starts complaining if cvs_name is used directly about
	   array subscript exceeding boundary (since it doesnt know size of
	   cvs_name??) , so copy locally. */
	strcpy(cvs_name_str, cvs_name);

	/* Character 7 is a space when there isn't a tag. Use this as a key to
	   return the build date */
	if (strlen(cvs_name_str) < 7 || cvs_name_str[7] == ' ') {
		snprintf(version, sizeof(version), "Development Build %s",
			 __DATE__);
		version[sizeof(version) - 1] = 0;
		strcpy(ver_string, version);
	} else {
		/* Make a static copy of the CVS Name string so we can modify it */
		strncpy(version, cvs_name_str, sizeof(version));
		version[sizeof(version) - 1] = 0;

		/* Make sure there is an ending space in case someone didn't pass us
		   a CVS Name string */
		version[sizeof(version) - 2] = ' ';

		/* Convert all underscores into spaces or dots */
		while ((ptr = strchr(version, '_')) != NULL) {
			if ((ptr == version) ||	/* Assume an underscore at beginning should be a space */
			    (ptr[-1] < '0') || (ptr[-1] > '9') ||	/* If the character before it isn't a digit */
			    (ptr[1] < '0') || (ptr[1] > '9'))	/* If the character after it isn't a digit */
				*ptr = ' ';
			else
				*ptr = '.';
		}

		/* Skip over the dollar Name: at the front */
		strcpy(ver_string, version);
	}

}

void pki_tag_generation_workaround()
{
	int i;
    for(i=0;i<octnic->nports; i++)
    {   
        int interface, index, pknd;
        uint32_t ipd_port = octnic->port[i].linfo.gmxport, cluster = 0;
        struct cvmx_xport xp; 
        cvmx_pki_icgx_cfg_t pki_cl_grp;
        cvmx_pki_clx_pkindx_style_t pkind_cfg_style;
        cvmx_pki_clx_stylex_cfg2_t style_cfg2_reg;
    
        interface = cvmx_helper_get_interface_num(ipd_port);
        index = cvmx_helper_get_interface_index_num(ipd_port);
        xp = cvmx_helper_ipd_port_to_xport(ipd_port);

		/* Extract pknd, cluster, style information */
        pknd = cvmx_helper_get_pknd(interface, index);
        pki_cl_grp.u64 = cvmx_read_csr_node(xp.node, CVMX_PKI_ICGX_CFG(0));

        while(cluster < CVMX_PKI_NUM_CLUSTER) {
            if(pki_cl_grp.s.clusters & (0x01L << cluster))
                break;
            cluster++;
        }
        pkind_cfg_style.u64 = cvmx_read_csr_node(xp.node, CVMX_PKI_CLX_PKINDX_STYLE(pknd, cluster));

		/* Configure the PKI to include the src and dest port in tag calculation */
        style_cfg2_reg.u64 = cvmx_read_csr_node(xp.node, CVMX_PKI_CLX_STYLEX_CFG2(pkind_cfg_style.s.style, cluster));
        style_cfg2_reg.s.tag_src_lf = 1;
        style_cfg2_reg.s.tag_dst_lf = 1;
        cvmx_write_csr_node(xp.node,CVMX_PKI_CLX_STYLEX_CFG2(pkind_cfg_style.s.style, cluster),style_cfg2_reg.u64);
    }
}


static void cvmcs_nic_bring_all_links_down()
{
	int i;

	for (i = 0; i < (int)octnic->ngmxports; i++) {
		octnic->gmx_port_info[i].cam_flags = 0;
		octnic->gmx_port_info[i].link_state = LINK_UNKNOWN;
		cvmcs_bgx_link_down(&octnic->gmx_port_info[i]);
	}
}
static void notify_host_application_loaded()
{
	uint64_t scratch2;

	if (!OCTEON_IS_MODEL(OCTEON_CN73XX))
		return;

	scratch2 = cvmx_read_csr(CVMX_PEXP_SLI_SCRATCH_2);
	scratch2 |= (1ULL << SCR2_BIT_FW_LOADED);
	cvmx_write_csr(CVMX_PEXP_SLI_SCRATCH_2, scratch2);
}

static void notify_host_application_reloaded()
{
	uint64_t scratch2;

	if (!OCTEON_IS_MODEL(OCTEON_CN73XX))
		return;

	scratch2 = cvmx_read_csr(CVMX_PEXP_SLI_SCRATCH_2);
	scratch2 |= (1ULL << SCR2_BIT_FW_RELOADED);
	cvmx_write_csr(CVMX_PEXP_SLI_SCRATCH_2, scratch2);
}

/** MAIN */
int main(int argc, char *argv[])
{
	const char *nic_cvs_tag = LIQUIDIO_VERSION;
	char nic_version[sizeof(LIQUIDIO_VERSION) + 100];
	cvmx_app_hotplug_callbacks_t hpcb;

	/* Initialize hotplug callback structure */
	memset(&hpcb, 0, sizeof hpcb);
	hpcb.cores_added_callback = cvmcs_nic_cores_added_cb_fn;
	hpcb.unplug_core_callback = cvmcs_nic_unplug_cb_fn;
	hpcb.shutdown_callback =  cvmcs_nic_shutdown_cb_fn;
	hpcb.cores_removed_callback = cvmcs_nic_cores_removed_cb_fn;

	// execute app core bringup with flag to indicate if a core is to be
	// reserved for NVMe emulation polling. This is dependent on the NVMe
	// module being installed, and emulation mode running.
	if (cvmcs_app_bringup(nvme_active(), &hpcb) &&
	    !OCTEON_IS_MODEL(OCTEON_CN73XX))
		return 1;

	/* CLI feature interrupt moderation initializations */
	intrmod_maxpkt_ratethr = LIO_INTRMOD_MAXPKT_RATETHR;
	intrmod_minpkt_ratethr = LIO_INTRMOD_MINPKT_RATETHR;
	intrmod_maxcnt_trigger = LIO_INTRMOD_RXMAXCNT_TRIGGER;
	intrmod_mincnt_trigger = LIO_INTRMOD_RXMINCNT_TRIGGER;
	intrmod_maxtmr_trigger = LIO_INTRMOD_RXMAXTMR_TRIGGER;
	intrmod_mintmr_trigger = LIO_INTRMOD_RXMINTMR_TRIGGER;

	intrmod_rxcnt_steps = INTRMOD_RXCNT_STEPS;
	intrmod_rxtmr_steps = INTRMOD_RXTMR_STEPS;

	intrmod_check_intrvl = LIO_INTRMOD_CHECK_INTERVAL;

	intmod_enable = 1;

	if (is_boot_core(core_id)) {

		cvmcs_init_printf_buffers();

		if (cvmcs_alloc_or_find_rss_state_array()) {
			printf("ERROR: cvmcs_alloc_or_find_rss_state_array failed\n");
			return 1;
		}

		if (cvmcs_nic_fwdump_enable(num_cores)) {
			printf("ERROR: Firmware dump initialization failed\n");
			return 1;
		}

		if (cvmcs_nic_init_mbcast_list()) {
			printf("ERROR: mbcast_list initialization failed\n");
			return 1;
		}

		if (booting_for_the_first_time) {
			extern void cvmx_save_fpa3_pool_and_aura_info(void **pool_info, void **aura_info);

			per_core_stats = cvmx_bootmem_alloc_named(MAX_CORES * sizeof (cvm_per_core_stats_t), CVMX_CACHE_LINE_SIZE, "__per_core_stats");
			if (per_core_stats) {
				memset(per_core_stats, 0, MAX_CORES * sizeof (cvm_per_core_stats_t));
				live_upgrade_ctx->per_core_stats = per_core_stats;
			} else {
				printf("ERROR: failed to alloc per_core_stats array\n");
				return 1;
			}

			//cvmcs_nic_hostfw_handshake();
			//cvmcs_nic_update_pko_queue_static_config();

			printf("version: %s %s  build time: %s\n", LIQUIDIO_VERSION, BUILD_VERSION, BUILD_TIME );

			nic_process_cmdline(argc, argv);	//TBD:DBG:CLI

			printf("SDK %s (%s)\n", SDKVER, nic_version);
			cavium_parse_cvs_string(nic_cvs_tag, nic_version,
					sizeof(nic_version));
			cvmcs_print_compile_options();
			DBG("# cvmcs-nic: Starting global init on core %d\n",
			       core_id);

			if (cvmcs_nic_hybrid_init(core_id))
				return 1;

			if (cvmcs_nic_init_global())
				return 1;
			live_upgrade_ctx->oct = oct;
			cvmx_save_fpa3_pool_and_aura_info(&live_upgrade_ctx->cvmx_fpa3_pool_info0, &live_upgrade_ctx->cvmx_fpa3_aura_info0);
			memcpy(live_upgrade_ctx->cvmx_cfg_port, cvmx_cfg_port, sizeof cvmx_cfg_port);
			DBG("# cvmcs-nic: Global initialization completed\n\n");

#ifdef FLOW_ENGINE
			if (cvmcs_cfe_init_components()) {
				printf("# cvmcs-nic: components registration failed \n\n");
				return 1;
			}
#endif
			if (cvmcs_nic_init_bp())
				return 1;
			cvmcs_nic_init_flow_ctl();

			// Initialize NVMe block
			nvme_init();

		} else {
			extern void cvmx_restore_fpa3_pool_and_aura_info(void *pool_info, void *aura_info);
			oct = live_upgrade_ctx->oct;
			cvmx_restore_fpa3_pool_and_aura_info(live_upgrade_ctx->cvmx_fpa3_pool_info0, live_upgrade_ctx->cvmx_fpa3_aura_info0);
			cvmx_helper_get_pknd(3, 0); //to set port_cfg_data_initialized (a static shared global boolean in cvmx-helper-cfg.c)
			memcpy(cvmx_cfg_port, live_upgrade_ctx->cvmx_cfg_port, sizeof cvmx_cfg_port);

			octnic = live_upgrade_ctx->octnic;
			per_core_stats = live_upgrade_ctx->per_core_stats;

			__cvmx_cmd_queue_init_state_ptr(0);

			cvmcs_profile_initialize();
			cvmcs_nic_create_profiles();

			nvme_init();

			oct_nic_lro_init();
		}

		/* Components should take care of live upgrade initialization themselves */
		if (cvmcs_nic_component_global_init()) {
			printf("Global initialization of components is failed\n");
			return 1;
		}
	}

	cvmcs_app_barrier();

	/* Initialization local to each core */
	cvmcs_nic_init_local();
	nvme_local_init();

	if (is_boot_core(core_id)) {

		if (booting_for_the_first_time) {

			cvmx_helper_setup_red(RED_HIGH_WMARK, RED_LOW_WMARK);

			cvm_drv_setup_app_mode(CVM_DRV_NIC_APP);
			cvm_app_setup_mode();

			if (octeon_has_feature(OCTEON_FEATURE_PKI)) {

				cvmx_pki_enable(cvmx_get_node_num());
			} else {
				/* Modify default IPD settings */
				modify_ipd_settings();
			}
			cvmx_helper_ipd_and_packet_input_enable();

			cvmcs_nic_bring_all_links_down();

			cvm_drv_start(octnic->ngmxports, octnic->max_nic_ports);

			print_pool_count_stats();
			if (octeon_has_feature(OCTEON_FEATURE_PKI)) {
				/* Workaround to disable CVMX_DPI_INT_REG[21] */
				cvmx_error_intsn_disable_v3(cvmx_get_node_num(), 0xdf015);
				cvmx_write_csr(CVMX_SPEMX_TLP_CREDITS(0), 0x400840ff20ffULL);
				pki_tag_generation_workaround();
			}

			if (!OCTEON_IS_MODEL(OCTEON_CN78XX) &&
		    	    !OCTEON_IS_MODEL(OCTEON_CN73XX)) {
				cvmcs_nic_tunnel_loopback_port_init();
				//cvmcs_nic_ipsec_loopback_port_init();
			}
			if (!OCTEON_IS_MODEL(OCTEON_CN78XX) &&
		    	    !OCTEON_IS_MODEL(OCTEON_CN23XX) &&
			    !OCTEON_IS_MODEL(OCTEON_CN73XX)) {
				cvmcs_nic_ipsec_loopback_port_init();
			}
			if (cvmcs_nic_pki_pcam_init(LINUX_POW_DATA_GROUP))
				printf("PCAM init failed\n");
		} else {
			if (OCTEON_IS_MODEL(OCTEON_CN73XX)) {
				extern void cn73xx_intr_config(void);
				cn73xx_intr_config();
			}
			print_pool_count_stats();
		}

		if (cvmcs_nic_flash_fwdump_enable())
			printf("INFO: Firmware flash dump is not enabled\n");

		notify_host_application_loaded();
	}

	cvmcs_app_barrier();

	if (!booting_for_the_first_time) {
/* Group mask not needed for OVS since OVS already set it */
#ifndef VSWITCH
		uint64_t grp_mask[4] = { ~0ULL, ~0ULL, ~0ULL, ~0ULL };

		if (octeon_has_feature(OCTEON_FEATURE_CN78XX_WQE))
			cvmx_pow_set_xgrp_mask(cvmx_get_core_num(), 0x3, grp_mask);
		else
			cvmx_pow_set_group_mask(cvmx_get_core_num(), grp_mask[0]);
#endif
		if (is_boot_core(core_id)) {
			notify_host_application_reloaded();
		}
	}

	// check NVMe needs a polling core for emulation, that the NVMe module
	// is active, and that we are the chosen polling core
	if (is_nvme_core(core_id) && nvme_active() && !OCTEON_IS_MODEL(OCTEON_CN73XX))
		/* run nvme host polling */
		nvme_process();
	else
		/* Start the data processing loop on each remaining core. */
		cvmcs_nic_data_loop();

	cvmcs_app_barrier();

	if (is_boot_core(core_id)) {
		// Process NVMe shutdown
		nvme_deinit();
		cvmcs_app_shutdown();
	}

	return 0;
}

/*
 * This callback is invoked for all cores that are being unplugged
 * from a running application.
 */
void cvmcs_nic_unplug_cb_fn(void *data)
{
	uint64_t grp_mask[4] = { 0, 0, 0, 0 };
	int core = cvmx_get_core_num();

	if (octeon_has_feature(OCTEON_FEATURE_CN78XX_WQE)) {
		cvmx_pow_set_xgrp_mask(core, 0x3, grp_mask);
	} else {
		cvmx_pow_set_group_mask(core, grp_mask[0]);
	}

	/* kick this core's watchdog, then turn it off */
	cvmx_write_csr(CVMX_CIU_PP_POKEX(core), 1);
	cvmx_write_csr(CVMX_CIU_WDOGX(core), 0);

	printf("core %d unplug from old app requested\n", core);

	cvmcs_unplug_requested = 1;
}

/*
 * This callback notifies all cores when they are being shutdown
 */
void cvmcs_nic_shutdown_cb_fn(void *data)
{
	uint64_t grp_mask[4] = { 0, 0, 0, 0 };
	int core = cvmx_get_core_num();

	if (octeon_has_feature(OCTEON_FEATURE_CN78XX_WQE)) {
		cvmx_pow_set_xgrp_mask(core, 0x3, grp_mask);
	} else {
		cvmx_pow_set_group_mask(core, grp_mask[0]);
	}

	/* kick this core's watchdog, then turn it off */
	cvmx_write_csr(CVMX_CIU_PP_POKEX(core), 1);
	cvmx_write_csr(CVMX_CIU_WDOGX(core), 0);

	printf("core %d shutdown old app requested\n", core);

	cvmcs_shutdown_requested = 1;
}

void cvmcs_nic_cores_added_cb_fn(cvmx_coremask_t *coremask, void *data)
{
	if (cvmx_is_init_core())
		printf("%u cores are now running the new app\n", cvmx_coremask_get_core_count(&(cvmx_sysinfo_get()->core_mask)));
}

void cvmcs_nic_cores_removed_cb_fn(cvmx_coremask_t * coremask, void *data)
{
}

#ifdef RLIMIT
void cvm_rate_limit_drop_threshold(int threshold)
{				/* RateLimit feature: set drop threshold */
	if (threshold)
		gDropThreshold = threshold;
	else
		gDropThreshold = CVM_RATE_LIMIT_DROP_THRESHOLD;
}

/**
 *  ipd_port : Physical port
 *  bits_s   : Rate limit in bits/sec
 *  burst    : Maximum bits to burst before the rate limit kicks in
 */
int cvm_rate_limit(int ipd_port, uint64_t bits_s, int burst)
{				/* RateLimit feature: set port rate */
	/* For XAUI QLM 3, ipd_port is 2880 */
	int interface = -1, index = -1, pko_internal_port = -1, ret = -1;

	interface = cvmx_helper_get_interface_num(ipd_port);
	index = cvmx_helper_get_interface_index_num(ipd_port);

	pko_internal_port = cvmx_helper_get_pko_port(interface, index);

	ret = cvmx_pko_rate_limit_bits(pko_internal_port, bits_s, burst);

	if (!ret)
		pko_rate_limit[pko_internal_port].is_rate_limit_on = 1;
	return (ret);
}
#endif

/* $Id$ */
