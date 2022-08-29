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
#include "cvmcs-common.h"
#include "cvmcs-nic.h"
#include "cvmx-helper.h"
#include "cvmx-helper-board.h"
#include "cvmx-rwlock.h"
#include "cvm-pci-loadstore.h"
#include "cvmcs-nic-hybrid.h"

#define MAC_MEMINFO_ALIGNMENT  (8)
#define MAC_MEMINFO_ALIGNMASK  (MAC_MEMINFO_ALIGNMENT - 1)

/* must match OSI code */
#define OCTEON_MAC_MEMINFO_BLOCK_NAME   "__mac_meminfo"
struct mac_sharedmem_info {
	/* count of mac addresses */
	uint16_t count;
	/* starting mac address */
	uint8_t  base_mac_addr[6];
};

extern CVMX_SHARED uint32_t cvm_first_buf_size_after_skip;
extern CVMX_SHARED uint32_t cvm_subs_buf_size_after_skip;

extern CVMX_SHARED    uint64_t  cpu_freq;

extern CVMX_SHARED octnic_dev_t *octnic;

extern struct octeon_config oct_cfg;

/* see 'cvm-drv.h' */
CVMX_SHARED int (*rinfo_set_by_host_fn)(int, uint64_t) = NULL;

/* see 'cvm-drv.h' */
CVMX_SHARED void (*drv_restart_app_cb)(int) = NULL;

static void cvmcs_nic_init_pkt_skip_sizes(void)
{
	if (!octeon_has_feature(OCTEON_FEATURE_PKI)) {
		cvm_first_buf_size_after_skip =
		    (((cvmx_read_csr(CVMX_IPD_PACKET_MBUFF_SIZE) & 0xfff) -
		      ((cvmx_read_csr(CVMX_IPD_1ST_MBUFF_SKIP) & 0x3f) + 1)) * 8);
		cvm_subs_buf_size_after_skip =
		    ((cvmx_read_csr(CVMX_IPD_PACKET_MBUFF_SIZE) & 0xfff) -
		     ((cvmx_read_csr(CVMX_IPD_NOT_1ST_MBUFF_SKIP) & 0x3f) + 1)) * 8;

		DBG2("First MBUF size: %u\nSubsequent MBUF size: %u\n",
	     cvm_first_buf_size_after_skip, cvm_subs_buf_size_after_skip);
	}
}

/**
 * Calculates a default mac address based on gmx port and offset
 *
 * @param  gmx_id   gmx port
 * @param  ifidx    VNIC
 *
 * @returns index to free entry, or -1 if full
 */
static inline uint64_t cvmcs_nic_macaddr(int gmx_id, int ifidx)
{
	int offset = OCT_NIC_PORT_VF(ifidx);

	if (offset) {
		/* non-zero offset means this is for a VF */
		if (octnic->port[ifidx].user_set_macaddr)
			return octnic->port[ifidx].user_set_macaddr;
	}

	return octnic->gmx_port_info[gmx_id].hw_base_addr + offset;
}

/**
 * Initialize a mcast freelist.
 * @param head head of the list
 * @param count number of items.
 *
 * @returns 0 on success, non-zero on fail
 */
static inline int init_mcast_freelist(hash_node_t *head, int count, char *name)
{
	mcast_ifl_t *p;
	int i;

	p = (mcast_ifl_t *)cvmx_bootmem_alloc_named(sizeof(*p) * count,
					      CVMX_CACHE_LINE_SIZE, name);
	if (!p)
		return -1;

	memset(p, 0, sizeof(*p) * count);

	INIT_HLIST_NODE(head);

	for(i = 0; i < count; p++, i++) {
		hash_node_insert_tail(&p->list, head);
	}

	return 0;
}

/* Free mcast free list */
static inline void free_mcast_freelist(char *name)
{
	cvmx_bootmem_free_named(name);
}

static inline int init_pkt_steering_table(vnic_port_info_t *nicport)
{
	pkt_steering_entry_t *p;

	if (nicport->pkt_steering_table)
		return 0;

	p = (pkt_steering_entry_t *)cvmx_bootmem_alloc(sizeof(pkt_steering_entry_t) * PKT_STEERING_TABLE_SIZE,
					      CVMX_CACHE_LINE_SIZE);
	if (!p)
		return -1;

	memset(p, 0, sizeof(pkt_steering_entry_t) * PKT_STEERING_TABLE_SIZE);
	nicport->pkt_steering_table = p;

	return 0;
}

/* NIC includes all ports from firstport to lastport (inclusive) */
void add_port_to_nic(int ifidx, uint32_t gmxport_id)
{
	unsigned int i, j;
	int gmx_offset;
	gmx_port_info_t *info;
	uint64_t new_mac;
	char name[256] = {0};
	int iq_aura;

	i = ifidx;
	if (octnic->port[i].state.present) {
		printf("cannot add, port exists\n");
		return;
	}

	info = &octnic->gmx_port_info[gmxport_id];

	/* Determine the MAC based on the VNIC port number */
	new_mac = cvmcs_nic_macaddr(gmxport_id, ifidx);

	if (OCTEON_IS_MODEL(OCTEON_CN73XX)) {
		/* Temporary. Need to change to ifidx itself */
		gmx_offset = ((OCT_NIC_PORT_PF(ifidx) << 4) |
			      OCT_NIC_PORT_VF(ifidx));
	}
	else
		gmx_offset = info->nports;

	printf("GMX%d: Adding VNIC %d to IPD %d MAC %012lx gmx_offset %d\n",
	       gmxport_id, i, info->ipd_port, new_mac, gmx_offset);

	octnic->port[i].ifidx = i;
	octnic->port[i].state.present = 1;
	octnic->port[i].state.active = 0;
	octnic->port[i].state.rx_on = 0;
	octnic->port[i].linfo.gmxport = info->ipd_port;
	octnic->port[i].linfo.num_txpciq = 0;
	octnic->port[i].linfo.num_rxpciq = 0;
	octnic->port[i].gmxport_id = gmxport_id;

	if (OCT_NIC_IS_PF(i)) {
		octnic->port[i].mtu = info->mtu;
		octnic->port[i].max_mtu = info->max_mtu;
		octnic->port[i].effective_mtu = octnic->port[i].mtu;
		octnic->port[i].linfo.link.u64 = info->link.u64;
		octnic->port[i].linfo.link.s.mtu = octnic->port[i].mtu;
		/* by default, NIC PF controls the max and link MTU;
		 * it will be overridden by components, if required.
		 */
		octnic->port[i].is_mtu_master = 1;
	}
	else {
		int pf_idx = OCT_NIC_PORT_IDX(OCT_NIC_PORT_PF(i), 0);
		int min_mtu;

		min_mtu = octnic->port[pf_idx].mtu < OCTNET_DEFAULT_MTU ?
			octnic->port[pf_idx].mtu : OCTNET_DEFAULT_MTU;
		/* VF can't send frames bigger than PF's MTU */
		octnic->port[i].mtu = min_mtu;
		octnic->port[i].max_mtu = octnic->port[pf_idx].mtu;
		octnic->port[i].effective_mtu = octnic->port[i].mtu;

		octnic->port[i].linfo.link.u64 =
			octnic->port[pf_idx].linfo.link.u64;
		octnic->port[i].linfo.link.s.mtu = octnic->port[i].mtu;
		octnic->port[i].is_mtu_master = 0;
	}

	octnic->port[i].linfo.link.s.link_up = 0; /* down to start */

	for (j = 0; j < MAX_IOQS_PER_NICIF; j++) {
		iq_aura = octnic->port[i].linfo.txpciq[j].s.aura_num;
		octnic->port[i].linfo.txpciq[j].u64 = 0;
		octnic->port[i].linfo.txpciq[j].s.q_no = INVALID_IOQ_NO;
		octnic->port[i].linfo.txpciq[j].s.aura_num = iq_aura;

		octnic->port[i].linfo.rxpciq[j].u64 = 0;
		octnic->port[i].linfo.rxpciq[j].s.q_no = INVALID_IOQ_NO;
	}

	if (cvmcs_nic_add_mac(ifidx, gmxport_id, gmx_offset, new_mac)) {
		printf("GMX%d: ifidx=%d Failed to add MAC %012lx!\n",
		       gmxport_id, ifidx, new_mac);
	}

	if (info->nports == 0) {
		
		sprintf(name, "mcast_hash_%d", gmxport_id);

		info->vnic_mcast_lut = hash_table_alloc(MCAST_LUT_SIZE, name);
		if (!info->vnic_mcast_lut) {
			printf("%s: Error allocating vnic_mcast_lut\n", __func__);
			return;
		}

		memset(name, 0, sizeof(name));

		sprintf(name, "mcast_freelist_%d", gmxport_id);

		if (init_mcast_freelist(&info->vnic_mcast_free, MAX_MCAST_ENTRIES, name)) {
			printf("%s: Error allocating vnic_mcast_free\n", __func__);
			return;
		}

	}

	cvmcs_nic_enable_vlan_filter(ifidx);

	if (OCT_NIC_IS_PF(ifidx)) {
		cvmcs_nic_set_link_status_led(ifidx);
	}

	if (OCTEON_IS_MODEL(OCTEON_CN73XX) || OCTEON_IS_MODEL(OCTEON_CN78XX)) {
		memset(octnic->port[i].pkt_steering_table, 0,
			sizeof(pkt_steering_entry_t) * PKT_STEERING_TABLE_SIZE);
		octnic->port[i].pkt_steering_update_intrvl = 
				(PKT_STEERING_UPDATE_INTRVL * cpu_freq)/1000;
	}

	octnic->nports++;
	info->nports++;

}

void del_port_from_nic(int ifidx)
{
	int i;
	char name[256] = {0};
	int gmxport_id;
	gmx_port_info_t *info;
	uint64_t user_set_macaddr;
	uint16_t user_set_vlanTCI;
	int      user_set_linkstate;
	bool     macaddr_is_admin_assigned;
	bool     macaddr_spoofchk;
	int tx_aura[MAX_IOQS_PER_NICIF];
	pkt_steering_entry_t *pkt_steering_table;

	if (!octnic->port[ifidx].state.present) {
		printf("cannot del, port does not exist\n");
		return;
	}

        gmxport_id = octnic->port[ifidx].gmxport_id;
	
	info = &octnic->gmx_port_info[gmxport_id];

	oct_nic_lro_discard(ifidx);

	for(i=0; i < MAX_VLANS; i++) {
		cvmcs_nic_del_vlan(ifidx, i);
	}

	cvmcs_nic_del_mac(ifidx);

	clear_mcast_cache(gmxport_id, ifidx);

	/* TODO : Reset other modules including ipsec etc., */

	octnic->nports--;
	info->nports--;

	if (info->nports == 0) {
		sprintf(name, "mcast_freelist_%d", gmxport_id);
		free_mcast_freelist(name);

		memset(name, 0, sizeof(name));

		sprintf(name, "mcast_hash_%d", gmxport_id);
		hash_table_free(name);

		info->vnic_mcast_lut = NULL;
	} else if (info->nports == 1) {
		if (OCTEON_IS_MODEL(OCTEON_CN73XX)) {
			/* one remaining port implies that it's the PF's port */
			if (OCT_NIC_PORT_PF(ifidx))
				info->ifidx = OCT_NIC_PORT_IDX(1, 0);
			else
				info->ifidx = OCT_NIC_PORT_IDX(0, 0);
		}
	}

	/* clear out vnic_port_info_t struct except the user_set fields */
	user_set_macaddr = octnic->port[ifidx].user_set_macaddr;
	user_set_vlanTCI = octnic->port[ifidx].user_set_vlanTCI;
	user_set_linkstate = octnic->port[ifidx].user_set_linkstate;
	macaddr_is_admin_assigned =
		octnic->port[ifidx].linfo.macaddr_is_admin_asgnd;
	macaddr_spoofchk =
		octnic->port[ifidx].linfo.macaddr_spoofchk;
	pkt_steering_table = octnic->port[ifidx].pkt_steering_table;

	/* save and restore AURA for Input queues;
	 * we do not want to dynamically allocate AURA numbers for 
	 * every VF reset; we just want to reuse.
	 */
	memset(tx_aura, 0, sizeof(tx_aura));
	for (i = 0; i < MAX_IOQS_PER_NICIF; i++) {
		tx_aura[i] = octnic->port[ifidx].linfo.txpciq[i].s.aura_num;
	}

	memset(&octnic->port[ifidx], 0, sizeof(octnic->port[ifidx]));
	octnic->port[ifidx].user_set_macaddr = user_set_macaddr;
	octnic->port[ifidx].user_set_vlanTCI = user_set_vlanTCI;
	octnic->port[ifidx].user_set_linkstate = user_set_linkstate;
	octnic->port[ifidx].linfo.macaddr_is_admin_asgnd = macaddr_is_admin_assigned;
	octnic->port[ifidx].linfo.macaddr_spoofchk = macaddr_spoofchk;
	octnic->port[ifidx].pkt_steering_table = pkt_steering_table;

	if (user_set_vlanTCI & 0xFFF)
		octnic->port[ifidx].linfo.vlan_is_admin_assigned = 1;

	for (i = 0; i < MAX_IOQS_PER_NICIF; i++) {
		octnic->port[ifidx].linfo.txpciq[i].s.aura_num = tx_aura[i];
	}

	return;
}

/* calculate the [aligned] size required to populate mac_sharedmem_info */
static uint64_t calc_mac_meminfo_size(cvmx_sysinfo_t *appsysinfo)
{
	struct mac_sharedmem_info *macinfo;
	uint64_t size;

	if (!appsysinfo)
		return 0;

	size = sizeof(*macinfo);

	/* align allocation size */
	size = ((size + MAC_MEMINFO_ALIGNMASK) & ~MAC_MEMINFO_ALIGNMASK);

	return size;
}

/* Helper to initialize shared memory block (mac_meminfo) from (appinfo) */
static void mac_meminfo_init(void *ptr)
{
	struct mac_sharedmem_info *macinfo;
	cvmx_sysinfo_t *appinfo = cvmx_sysinfo_get();

	if (!ptr)
		return;

	memset(ptr, 0, (size_t)calc_mac_meminfo_size(appinfo));
	macinfo = (struct mac_sharedmem_info *)ptr;

	/* save the count of mac addresses */
	macinfo->count = appinfo->mac_addr_count;

	/* save the first (base) mac */
	memcpy(macinfo->base_mac_addr, appinfo->mac_addr_base,
	       sizeof(macinfo->base_mac_addr));
}

/*
 * This creates a shared memory area which contains the MAC address information.
 * This is used by the UEFI driver which needs access to this information prior
 * to initializing the NIC.
 *
 * returns 0 if OK, else non-zero
 */
int cvmcs_nic_init_macaddr_info(void)
{
	const cvmx_bootmem_named_block_desc_t *blk_desc;
	struct cvmx_boot_vector_element *ptr;
	uint64_t size;
	cvmx_sysinfo_t *appinfo = cvmx_sysinfo_get();

	size = calc_mac_meminfo_size(appinfo);

	blk_desc = cvmx_bootmem_find_named_block(OCTEON_MAC_MEMINFO_BLOCK_NAME);
	if (blk_desc) {
		ptr = cvmx_phys_to_ptr(blk_desc->base_addr);
		mac_meminfo_init(ptr);
	} else {
		ptr = cvmx_bootmem_alloc_named_range_once(size, 0, 0,
						  MAC_MEMINFO_ALIGNMENT,
						  OCTEON_MAC_MEMINFO_BLOCK_NAME,
						  mac_meminfo_init);
	}

	return !ptr;
}

/*
 * This is a callback assigned to the core 'rinfo_set_by_host_fn' global.
 * Its purpose is to evaluate the RINFO value (passed-in by the core) to
 * determine if the host has initialized it.
 * This allows the core to determine when the host driver has loaded.
 *
 * on entry,
 *    pf_num : PF number
 *    d64    : value of the RINFO register
 *
 * returns,
 *    0      : RINFO has NOT been initialized by the host
 *   !0      : RINFO HAS been initialized by host
 */
static int cn73xx_rinfo_set_by_host(int pf_num, uint64_t d64) {
	cvmx_sli_pkt_macx_pfx_rinfo_t rinfo;

	rinfo.u64 = d64;

	/* Confirm that RINFO is DIFFERENT from the value set by
	 * 'cn73xx_init_pf_num_in_pkt0_ctrl()'; this means that the
	 * host has indeed written this register.
	 */
	return ((rinfo.u64 != 0) &&
		((rinfo.s.trs > 1) ||
		 (rinfo.s.srn != (pf_num + (MAX_DROQS_CN73XX - 2)))));
}

/*
 * This is used to set the PF number into SLI_PKT0_INPUT_CONTROL
 * so that the host can determine its PF number from a ring register.
 *
 * This is used by the host in case it cannot read the PF number
 * from the PCI extended configuration space (in virtual environments).
 *
 * This is assigned as a callback invoked by the core (see cvm-drv.h)
 */
static void cn73xx_init_pf_num_in_pkt0_ctrl(int pf_num) 
{
	cvmx_sli_pkt_macx_pfx_rinfo_t rinfo;
	cvmx_sli_pp_pkt_csr_control_t pktcsr;
	u64 d64;
	int ring, is_configured;

	pktcsr.u64 = 0;
	pktcsr.s.mac = 0;
	pktcsr.s.pvf = (pf_num << 13);

	/* 
	 * 1. write of CVMX_SLI_PP_PKT_CSR_CONTROL is required for pass 1.0 h/w bug.
	 * 2. This routine can be called early in the initialization before
	 * the 'oct' device has been allocated; ensure we don't use a NULL ptr.
	 */
	if (oct != NULL)
		cvmx_spinlock_lock(&oct->pp_pkt_csr_ctrl_lock);

	cvmx_write_csr(CVMX_SLI_PP_PKT_CSR_CONTROL, pktcsr.u64);

	rinfo.u64 = cvmx_read_csr(CVMX_PEXP_SLI_PKT_MACX_PFX_RINFO(pf_num, 0));

	is_configured = (rinfo.s.trs != 0);

	/* If RINFO has already been configured, leave things alone. */
	if (!is_configured ) {

		/* Configure RINFO such that <ring0> is owned by PF; then, set the
		 * pf_num into the PVF_NUM field of SLI_PKT0_INPUT_CONTROL.
		 * This enables host driver to retrieve PF_NUM from <ring0>.
		 * NOTE: for PF0, <ring0> = <max_ring_number - 2>
		 *       for PF1, <ring0> = <max_ring_number - 1>
		 */
		rinfo.u64 = 0;
		rinfo.s.nvfs = 0;
		rinfo.s.rpvf = 0;
		rinfo.s.trs = 1;
		rinfo.s.srn = pf_num + (MAX_DROQS_CN73XX - 2);

		cvmx_write_csr(CVMX_PEXP_SLI_PKT_MACX_PFX_RINFO(pf_num, 0), rinfo.u64);
	}

	if (oct != NULL)
		cvmx_spinlock_unlock(&oct->pp_pkt_csr_ctrl_lock);

	/* If RINFO has already been configured, leave things alone. */
	if (is_configured)
		return;

	ring = rinfo.s.nvfs * rinfo.s.rpvf;

#define PKTX_INPUT_CTRL_PVF_NUM_PF_POS 45
#define PKTX_INPUT_CTRL_MAC_NUM_POS    29

	d64 = ((u64)pf_num << PKTX_INPUT_CTRL_PVF_NUM_PF_POS) |
	      (0ULL /* i.e. mac0 */ << PKTX_INPUT_CTRL_MAC_NUM_POS);

	/* 
	 * This routine can be called early in the initialization before
	 * the 'oct' device has been allocated; ensure we don't use a NULL ptr.
	 */
	if (oct != NULL)
		cvmx_spinlock_lock(&oct->pp_pkt_csr_ctrl_lock);

	cvmx_write_csr(CVMX_SLI_PP_PKT_CSR_CONTROL, pktcsr.u64);

	cvmx_write_csr(CVMX_PEXP_SLI_PKTX_INPUT_CONTROL(ring), d64);

	if (oct != NULL)
		cvmx_spinlock_unlock(&oct->pp_pkt_csr_ctrl_lock);
}

int cvmcs_nic_init_board_info()
{
	const gmx_conf_t *gmx_conf;
	int i;
	int ipd_port;
	cvmx_sysinfo_t *appinfo;

	if (!booting_for_the_first_time)
		return 0;

	octnic = cvmx_bootmem_alloc_named(sizeof(octnic_dev_t), CVMX_CACHE_LINE_SIZE, "__octnic");
	if (octnic == NULL) {
		printf("%s Allocation failed for octnic\n", __FUNCTION__);
		return 1;
	}
	memset(octnic, 0, sizeof(octnic_dev_t));
	live_upgrade_ctx->octnic = octnic;

	if (OCTEON_IS_MODEL(OCTEON_CN73XX) || OCTEON_IS_MODEL(OCTEON_CN78XX)) {
		for (i = 0; i < MAX_OCTEON_NIC_PORTS; i++) {
			if (init_pkt_steering_table(&octnic->port[i])) {
				printf("%s: Error allocating pkt_steering_table\n", __func__);
				return 1;
			}
		}
	}

	if (OCTEON_IS_MODEL(OCTEON_CN66XX)) {
		octnic->free_q_info.cn66xx.free_pci_ports_iqs = MAX_PCI_PORTS_66XX;
		octnic->free_q_info.cn66xx.free_pci_ports_oqs = MAX_PCI_PORTS_66XX;
	}
	if (OCTEON_IS_MODEL(OCTEON_CN68XX)) {
		octnic->free_q_info.cn68xx.num_free_iqs =  MAX_PCI_QUEUES_68XX;
		octnic->free_q_info.cn68xx.num_free_oqs =  MAX_DROQS_68XX;
		octnic->free_q_info.cn68xx.free_iq_mask = (1UL << MAX_PCI_QUEUES_68XX)-1;
		octnic->free_q_info.cn68xx.free_oq_mask = (1UL << MAX_DROQS_68XX)-1;
	}
	if (OCTEON_IS_OCTEON3()) {
		octnic->free_q_info.cn78xx.num_free_iqs = MAX_PCI_QUEUES_78XX;
		octnic->free_q_info.cn78xx.num_free_oqs = MAX_DROQS_78XX;
		octnic->free_q_info.cn78xx.free_iq_mask = -1UL;
		octnic->free_q_info.cn78xx.free_oq_mask = -1UL;
	}

	for (i = 0; i < MAX_OCTEON_GMX_PORTS; i++) {
		gmx_port_info_t *gmx_port_info;
		gmx_port_info = &octnic->gmx_port_info[i];
		/* initially, all vnics do not have user set vlan */
		memset(&gmx_port_info->vnic_without_user_set_vlan, 0xff, sizeof(gmx_port_info->vnic_without_user_set_vlan));
		iflist_set_last(&gmx_port_info->vnic_without_user_set_vlan);
		iflist_set_active(&gmx_port_info->vnic_without_user_set_vlan);
                /* VLAN 0 Should be always allowed */
                memset(&gmx_port_info->vlans[0], 0xff, sizeof(gmx_port_info->vlans[0]));
                iflist_set_last(&gmx_port_info->vlans[0]);
                iflist_set_active(&gmx_port_info->vlans[0]);
	}

#ifdef USE_MULTIPLE_OQ
	octnic->numpciqs = 4;	// Multiple Queues are required for NAPI support in host.
#else
	octnic->numpciqs = 1;
#endif

	appinfo = cvmx_sysinfo_get();
	if (appinfo) {
		char boardstring[32];
		switch (appinfo->board_type) {

		case CVMX_BOARD_TYPE_NIC10E_66:
			strcpy(boardstring, "NIC10E_66");
			gmx_conf = &def_66xx_conf;
			break;

		case CVMX_BOARD_TYPE_SNIC10E:
			strcpy(boardstring, "SNIC10E");
			gmx_conf = &def_66xx_conf;
			break;

		case CVMX_BOARD_TYPE_NIC68_4:
			strcpy(boardstring, "NIC68_4");
			gmx_conf = &def_68xx_conf;
			break;

		case CVMX_BOARD_TYPE_SWORDFISH:
			if (cvmx_read_csr(CVMX_MIO_QLMX_CFG(4)) & 0x7) {
				strcpy(boardstring, "Swordfish - 4 port");
				gmx_conf = &sword_fish_4port_68xx_conf;
			} else {
				strcpy(boardstring, "Swordfish - 2 port");
				gmx_conf = &sword_fish_2port_68xx_conf;
			}
			break;
		case CVMX_BOARD_TYPE_NIC23:
		case CVMX_BOARD_TYPE_COPPERHEAD:
		case CVMX_BOARD_TYPE_NIC73:
			/* only support 1 configuration for now 2 xaui 
			 * QLM4 and QLM6 */
			if (appinfo->board_type == CVMX_BOARD_TYPE_NIC73)
				strcpy(boardstring, "NIC73");
			else if (appinfo->board_type ==
				 CVMX_BOARD_TYPE_COPPERHEAD)
				strcpy(boardstring, "NIC COPPERHEAD");
			else
				strcpy(boardstring, "NIC23");

			gmx_conf = &def_73xx_conf;

			/* save PCI cfg space register 0;
			 * this is restored after a PF FLR
			 */
			{
				union cvmx_spemx_cfg_rd cfg_rd;
				cfg_rd.u64 = 0;
				cfg_rd.s.addr = (0 /* ie. pf_num */ << 24) | 0 /* ie. reg 0 */;
				cvmx_write_csr_node(cvmx_get_node_num(),
									CVMX_SPEMX_CFG_RD(0), cfg_rd.u64);
				cfg_rd.u64 = cvmx_read_csr_node(cvmx_get_node_num(),
									CVMX_SPEMX_CFG_RD(0));
				octnic->pci_cfgspace_reg0 = cfg_rd.s.data;
			}

			/* set globals used by core */
			rinfo_set_by_host_fn = cn73xx_rinfo_set_by_host;
			drv_restart_app_cb = cn73xx_init_pf_num_in_pkt0_ctrl;

			/* initialize our PF's */
			cn73xx_init_pf_num_in_pkt0_ctrl(0);
			cn73xx_init_pf_num_in_pkt0_ctrl(1);

			break;

		case CVMX_BOARD_TYPE_NIC225E:
			strcpy(boardstring, "NIC225E");
			gmx_conf = &def_nic225e_conf;

			/* save PCI cfg space register 0 AND register 2;
			 * these are restored after a PF FLR
			 */
			{
				union cvmx_spemx_cfg_rd cfg_rd;
				cfg_rd.u64 = 0;
				cfg_rd.s.addr = (0 /* ie. pf_num */ << 24) | 0 /* ie. reg 0 */;
				cvmx_write_csr_node(cvmx_get_node_num(),
									CVMX_SPEMX_CFG_RD(0), cfg_rd.u64);
				cfg_rd.u64 = cvmx_read_csr_node(cvmx_get_node_num(),
									CVMX_SPEMX_CFG_RD(0));
				octnic->pci_cfgspace_reg0 = cfg_rd.s.data;

				cfg_rd.u64 = 0;
				cfg_rd.s.addr = (0 /* ie. pf_num */ << 24) | 8 /* ie. reg 8 */;
				cvmx_write_csr_node(cvmx_get_node_num(),
									CVMX_SPEMX_CFG_RD(0), cfg_rd.u64);
				cfg_rd.u64 = cvmx_read_csr_node(cvmx_get_node_num(),
									CVMX_SPEMX_CFG_RD(0));
				octnic->pci_cfgspace_reg2 = cfg_rd.s.data;
			}

			/* set globals used by core */
			rinfo_set_by_host_fn = cn73xx_rinfo_set_by_host;
			drv_restart_app_cb = cn73xx_init_pf_num_in_pkt0_ctrl;

			/* initialize our PF's */
			cn73xx_init_pf_num_in_pkt0_ctrl(0);
			cn73xx_init_pf_num_in_pkt0_ctrl(1);

			break;

		case CVMX_BOARD_TYPE_EBB7800:
			/* only support 1 configuration for now 2 xaui 
			 * QLM4 and QLM6 */
			strcpy(boardstring, "78xx");
			gmx_conf = &def_78xx_conf;
			break;
		default:
			sprintf(boardstring, "Unknown (board_type: %d)",
				appinfo->board_type);
			printf("boardtype: %s \n", boardstring);
			return -1;
		}

		/* Map sparse distribution of GMX port numbers to
		 * logical gmx port ids that are sequential from zero.
		 */
		for (i = 0; i < MAX_OCTEON_GMX_PORTS; i++)
			octnic->gmx_ids[i] = -1;
		for (i = 0; i < gmx_conf->num_gmx_ports; i++) {
			ipd_port = gmx_conf->ipd_ports[i];
			octnic->gmx_port_info[i].ipd_port = ipd_port;
			octnic->gmx_port_info[i].link_state = LINK_UNKNOWN;
			if (OCTEON_IS_MODEL(OCTEON_CN68XX)) {
				octnic->gmx_ids[((ipd_port >> 8)&0xf)-8] = i;
			} else  if (OCTEON_IS_MODEL(OCTEON_CN66XX)) {
				octnic->gmx_ids[(ipd_port >> 4)] = i;
			} else if (OCTEON_IS_MODEL(OCTEON_CN78XX)) {
				octnic->gmx_ids[((ipd_port >> 8)&0xf)-8] = i;
			} else if (OCTEON_IS_MODEL(OCTEON_CN73XX)) {
				octnic->gmx_ids[i] = i;
			}
		}
		octnic->ngmxports = gmx_conf->num_gmx_ports;
		octnic->max_nic_ports = gmx_conf->max_nic_ports;
		printf("Board type: %s\n", boardstring);
	}

	return 0;
}

void cvmcs_nic_set_pip_err_reporting()
{
	cvmx_pip_prt_cfgx_t pip_prt;
	int i, port;
	int pknd;

	if (!OCTEON_IS_MODEL(OCTEON_CN70XX))
		return;

	i = 0;
	port = 0;

	while (octnic->port[i].state.present) {
		port = octnic->gmx_port_info[i].ipd_port;

		if (octeon_has_feature(OCTEON_FEATURE_PKND)) {
			pknd =
			    cvmx_helper_get_pknd(INTERFACE(port), INDEX(port));
			pip_prt.u64 = cvmx_read_csr(CVMX_PIP_PRT_CFGX(pknd));

			/* Report frames > max length defined in pip_frm_len_chkX[MAXLEN] */
			pip_prt.cn70xx.lenerr_en = 1;
			/* Report frames < max length defined in pip_frm_len_chkX[MINLEN] */
			pip_prt.cn70xx.minerr_en = 1;
			cvmx_write_csr(CVMX_PIP_PRT_CFGX(pknd), pip_prt.u64);
		}
		i++;
	}
	return;
}

static void cvmcs_nic_init_mtu(void)
{
	int port;
	unsigned int i;
	cvmx_helper_interface_mode_t mode;
	int phy_type;
	cvmx_sysinfo_t *appinfo;

		cvmx_pip_frm_len_chkx_t frm_len_chk;
		cvmx_pip_prt_cfgx_t pip_prt;
		int lastport, pknd;

		port = octnic->gmx_port_info[0].ipd_port;

		frm_len_chk.u64 = 0;
		frm_len_chk.s.minlen = OCTNET_MIN_FRM_SIZE;
		frm_len_chk.s.maxlen = OCTNET_MAX_FRM_SIZE;

		if (OCTEON_IS_MODEL(OCTEON_CN6XXX)) {
			frm_len_chk.s.minlen += OCTNET_FRM_PTP_HEADER_SIZE;
			frm_len_chk.s.maxlen += OCTNET_FRM_PTP_HEADER_SIZE;
		}

		if (octeon_has_feature(OCTEON_FEATURE_PKI)) {
			cvmx_pki_set_max_frm_len(port, -1);
		} else if (OCTEON_IS_MODEL(OCTEON_CN68XX))  {
			pknd =
			    cvmx_helper_get_pknd(INTERFACE(port), INDEX(port));
			pip_prt.u64 = cvmx_read_csr(CVMX_PIP_PRT_CFGX(pknd));
			cvmx_write_csr(CVMX_PIP_FRM_LEN_CHKX
				       (pip_prt.cn68xx.len_chk_sel),
				       frm_len_chk.u64);
		} else {
			cvmx_write_csr(CVMX_PIP_FRM_LEN_CHKX(INTERFACE(port)),
				       frm_len_chk.u64);
		}
		lastport = port;
		i = 1;
		while (i < octnic->ngmxports) {
			port = octnic->gmx_port_info[i].ipd_port;

			if (octeon_has_feature(OCTEON_FEATURE_PKI)) {
				cvmx_pki_set_max_frm_len(port, -1);
			} else if (OCTEON_IS_MODEL(OCTEON_CN68XX))  {
				pknd =
				    cvmx_helper_get_pknd(INTERFACE(port),
							 INDEX(port));
				pip_prt.u64 =
				    cvmx_read_csr(CVMX_PIP_PRT_CFGX(pknd));
				cvmx_write_csr(CVMX_PIP_FRM_LEN_CHKX
					       (pip_prt.cn68xx.len_chk_sel),
					       frm_len_chk.u64);
			} else {
				if (INTERFACE(port) != INTERFACE(lastport)) {
					cvmx_write_csr(CVMX_PIP_FRM_LEN_CHKX
						       (INTERFACE(port)),
						       frm_len_chk.u64);
				}
			}
			lastport = port;
			i++;
		}

	i = 0;
	while (i < octnic->ngmxports) {
		port = octnic->gmx_port_info[i].ipd_port;
		mode = cvmx_helper_interface_get_mode(INTERFACE(port));
		/* Bydefault autoneg is ON. Marking this flag for all the
		 * i/f's, so that the same will be communicated to the Host.
		 */
		octnic->gmx_port_info[i].link.s.autoneg = 1;
		/* Storing the interface mode in link info structure so the 
		 * same would be communicated to the Host.
		 */
		octnic->gmx_port_info[i].link.s.if_mode = mode;

		octnic->gmx_port_info[i].mtu = (OCTNET_DEFAULT_FRM_SIZE - OCTNET_FRM_HEADER_SIZE);
		octnic->gmx_port_info[i].max_mtu = (OCTNET_MAX_FRM_SIZE - OCTNET_FRM_HEADER_SIZE);

		if (octeon_has_feature(OCTEON_FEATURE_BGX))
			cvmx_write_csr_node(cvmx_get_node_num(),
					    CVMX_BGXX_SMUX_RX_JABBER(INDEX(port), INTERFACE(port)),
					    ((OCTNET_DEFAULT_FRM_SIZE + 7) & ~7));
		else
			cvmx_write_csr(CVMX_GMXX_RXX_JABBER(INDEX(port), INTERFACE(port)),
				       ((OCTNET_DEFAULT_FRM_SIZE + OCTNET_FRM_PTP_HEADER_SIZE + 7) & ~7));

		appinfo = cvmx_sysinfo_get();
		switch (appinfo->board_type) {
		case CVMX_BOARD_TYPE_COPPERHEAD:
			phy_type = LIO_PHY_PORT_TP;
			break;

		case CVMX_BOARD_TYPE_NIC23:
		case CVMX_BOARD_TYPE_NIC73:
		case CVMX_BOARD_TYPE_NIC225E:
			phy_type = LIO_PHY_PORT_FIBRE;
			break;

		default:
			phy_type = LIO_PHY_PORT_UNKNOWN;
			break;
		}
		octnic->gmx_port_info[i].link.s.phy_type = phy_type;
		i++;
	}

}

static void cvmcs_nic_init_ptp(void)
{
	int port, index, interface;
	unsigned int i;

	if (!OCTEON_IS_MODEL(OCTEON_CN6XXX)) {
		printf("Tx hardware timestamping is not supported on this"
			" Octeon model.\n");
		return;
	}

	if (octnic->ngmxports == 0) {
		printf("%s: No active ports found\n", __FUNCTION__);
		return;
	}

	i = 0;
	port = 0;

	while (i < octnic->ngmxports) {
		cvmx_pip_prt_cfgx_t pip_prt;
		int pknd;

		port = octnic->gmx_port_info[i].ipd_port;
		index = INDEX(port);
		interface = INTERFACE(port);

		/* Note: assume we're not using AGL interface */
		if (octeon_has_feature(OCTEON_FEATURE_BGX)) {
			cvmx_bgxx_smux_rx_frm_ctl_t       ctl;
			ctl.u64 = cvmx_read_csr_node(cvmx_get_node_num(), CVMX_BGXX_SMUX_RX_FRM_CTL(INDEX(port), INTERFACE(port)));
			ctl.s.ptp_mode = 1;
			cvmx_write_csr_node(cvmx_get_node_num(), CVMX_BGXX_SMUX_RX_FRM_CTL(INDEX(port), INTERFACE(port)), ctl.u64);
		} else if (OCTEON_IS_MODEL(OCTEON_CN6XXX)) {
			cvmx_gmxx_rxx_frm_ctl_t       ctl;

			ctl.u64 = cvmx_read_csr(CVMX_GMXX_RXX_FRM_CTL(index, interface));
			ctl.s.ptp_mode = 1;
			cvmx_write_csr(CVMX_GMXX_RXX_FRM_CTL(index, interface), ctl.u64 );
		}

		//outbound ptp not supported in 78xx pass1.1
		if (octeon_has_feature(OCTEON_FEATURE_PKI)) {
			cvmx_pki_clx_pkindx_skip_t skip;
			int interface, index, pknd;
			uint32_t ipd_port = octnic->gmx_port_info[i].ipd_port, cluster = 0;
			struct cvmx_xport xp;
			cvmx_pki_pkindx_icgsel_t pkind_clsel;
			cvmx_pki_icgx_cfg_t pki_cl_grp;

			interface = cvmx_helper_get_interface_num(ipd_port);
			index = cvmx_helper_get_interface_index_num(ipd_port);
			xp = cvmx_helper_ipd_port_to_xport(ipd_port);

			/* Extract pknd, cluster, style information */
			pknd = cvmx_helper_get_pknd(interface, index);
			pkind_clsel.u64 = cvmx_read_csr_node(xp.node, CVMX_PKI_PKINDX_ICGSEL(pknd));
			pki_cl_grp.u64 = cvmx_read_csr_node(xp.node, CVMX_PKI_ICGX_CFG(pkind_clsel.s.icg));

			/* CVMX_PKI_ICGX_CFG does not use offset passed to it. To avoid the compiler
			   warning which is treated as error the following assignment is needed */
			pkind_clsel.u64 = pkind_clsel.u64;

			while(cluster < CVMX_PKI_NUM_CLUSTER) {
				if(pki_cl_grp.s.clusters & (0x01L << cluster))
					break;
				cluster++;
			}
			printf("node %d ipd port %d  interface %d index %d pkind %d cluster %d\n", xp.node, ipd_port,
			       interface, index, pknd, cluster);
			printf("writing skip values\n");
			skip.u64 = cvmx_read_csr_node(xp.node, CVMX_PKI_CLX_PKINDX_SKIP(pknd, cluster));
			skip.s.fcs_skip = 8;
			skip.s.inst_skip = 8;
			cvmx_write_csr_node(xp.node, CVMX_PKI_CLX_PKINDX_SKIP(pknd, cluster), skip.u64);
		} else if (octeon_has_feature(OCTEON_FEATURE_PKND)) {
			pknd = cvmx_helper_get_pknd(INTERFACE(port), INDEX(port));
			pip_prt.u64 = cvmx_read_csr(CVMX_PIP_PRT_CFGX(pknd));
			pip_prt.s.skip = OCTNET_FRM_PTP_HEADER_SIZE;
			if (OCTEON_IS_MODEL(OCTEON_CN68XX)) {
				//need to disable crc check for 68XX with PTP
				//http://mcbuggin.caveonetworks.com/bug/16516/chip=O68@3.0
				pip_prt.s.crc_en = 0;
			}
			cvmx_write_csr(CVMX_PIP_PRT_CFGX(pknd), pip_prt.u64);
		} else if (OCTEON_IS_MODEL(OCTEON_CN66XX)) {
			pip_prt.u64 = cvmx_read_csr(CVMX_PIP_PRT_CFGX(port));
			pip_prt.s.skip = OCTNET_FRM_PTP_HEADER_SIZE;
			cvmx_write_csr(CVMX_PIP_PRT_CFGX(port),
			       pip_prt.u64);
		}

		/* Note: If PIP_TAG_INC is used, then this should be
		 * adjusted based on the PTP_MODE.
		 */

		i++;
	}

	/* For Tx timestamping we will write the timestamp in the word after the
	 * raw instruction header in the packet_data of the WQE
	 * PKO_REG_TIMESTAMP[WQE_WORD]
	 * Not applicable to 78xx
	 */
	if (OCTEON_IS_MODEL(OCTEON_CN6XXX)) {
		cvmx_write_csr(CVMX_PKO_REG_TIMESTAMP, (CVM_RAW_FRONT_SIZE +
				offsetof(cvmx_wqe_t, packet_data))/sizeof(uint64_t));
	} else {
		printf("Tx hardware timestamping is not supported on this"
			" Octeon model.\n");
	}

}

static int cvmcs_nic_change_gmx_smac(uint64_t mac, int gmx_port_id)
{
	int port = octnic->gmx_port_info[gmx_port_id].ipd_port;
	int interface = INTERFACE(port);
	int index = INDEX(port);
	cvmx_gmxx_prtx_cfg_t gmx_cfg;

	if (octeon_has_feature(OCTEON_FEATURE_BGX)) {
		int node;

		node = cvmx_get_node_num();
		interface = interface & 0xff;

		cvmcs_bgx_link_down(&octnic->gmx_port_info[gmx_port_id]);

		cvmx_write_csr_node(node, CVMX_BGXX_SMUX_SMAC(index, interface), mac);

	} else {
		gmx_cfg.u64 = cvmx_read_csr(CVMX_GMXX_PRTX_CFG(index, interface));
		cvmx_write_csr(CVMX_GMXX_PRTX_CFG(index, interface), gmx_cfg.u64 & ~1ull);
		cvmx_write_csr(CVMX_GMXX_SMACX(index, interface), mac);

		cvmx_write_csr(CVMX_GMXX_PRTX_CFG(index, interface), gmx_cfg.u64);
	}

	return 0;
}

static void cvmcs_nic_init_macaddr(void)
{
	unsigned int i;
	uint8_t *oct_mac_addr_base;

	oct_mac_addr_base = cvmcs_app_get_macaddr_base();

	octnic->macaddrbase = 0;
	for (i = 0; i < 6; i++, octnic->macaddrbase <<= 8)
		octnic->macaddrbase |= oct_mac_addr_base[i];

	octnic->macaddrbase >>= 8;

	i = 0;
	while (i < octnic->ngmxports) {
		uint64_t hw_addr;
		gmx_port_info_t *info = &octnic->gmx_port_info[i];

		cvmx_rwlock_wp_init(&info->mac_hash_lock);

		cvmx_spinlock_init(&info->link_lock);

		cvmcs_init_mac_hash_idx_table(info);

		hw_addr = ((octnic->macaddrbase & 0x0000ffffffffffffULL) + i);
		DBG2("GMX%d MAC %012lX\n", i, hw_addr);
		info->hw_base_addr = hw_addr;

		cvmcs_nic_change_gmx_smac(hw_addr, i);

		info->ifflags = OCTNET_IFFLAG_MULTICAST;

		if (octeon_has_feature(OCTEON_FEATURE_BGX)) {
			/* BGX is always in promiscuous mode because the DMAC
			 * filter has only a few entries; it cannot accomodate
			 * all the MAC addresses of the NIC73.
			 */
			cvmcs_nic_change_gmx_ifflags(i, OCTNET_IFFLAG_PROMISC);
		} else
			cvmcs_nic_change_gmx_ifflags(i, info->ifflags);
		i++;
	}
}

static void cvmcs_nic_init_pip_tag_config(void)
{
	int i, limit, port, pknd;
	cvmx_pip_prt_tagx_t tag_config;
	cvmx_pip_port_cfg_t port_cfg;
	cvmx_pip_tag_incx_t tag_inc;

	if (octeon_has_feature(OCTEON_FEATURE_PKI))
		return;

	limit = (int)octnic->ngmxports;

	tag_inc.u64 = cvmx_read_csr(CVMX_PIP_TAG_INCX(1));
	tag_inc.s.en = 0xFF; /* dest MAC addr and first 2 bytes of source MAC addr */
	cvmx_write_csr(CVMX_PIP_TAG_INCX(1), tag_inc.u64);

	tag_inc.u64 = cvmx_read_csr(CVMX_PIP_TAG_INCX(2));
	tag_inc.s.en = 0xF0; /* last 4 bytes of source MAC addr */
	cvmx_write_csr(CVMX_PIP_TAG_INCX(2), tag_inc.u64);

	if (octeon_has_feature(OCTEON_FEATURE_PKND)) {
		for (i = 0; i < limit; i++) {
			port = octnic->gmx_port_info[i].ipd_port;
			pknd = cvmx_helper_get_pknd(INTERFACE(port), INDEX(port));

			tag_config.u64 = cvmx_read_csr(CVMX_PIP_PRT_TAGX(pknd));
			tag_config.s.tag_mode = 1; /* mask tag algorithm */
			tag_config.s.inc_prt_flag = 1;
			cvmx_write_csr(CVMX_PIP_PRT_TAGX(pknd), tag_config.u64);

			/* use registers 0-15 of PIP_TAG_INCn when calculating the tag */
			port_cfg.u64 = cvmx_read_csr(CVMX_PIP_PRT_CFGX(pknd));
			port_cfg.s.tag_inc = 0;
			cvmx_write_csr(CVMX_PIP_PRT_CFGX(pknd), port_cfg.u64);
		}

	} else {
		for (i = 0; i < limit; i++) {
			port = octnic->gmx_port_info[i].ipd_port;

			tag_config.u64 = cvmx_read_csr(CVMX_PIP_PRT_TAGX(port));
			tag_config.s.tag_mode = 1; /* mask tag algorithm */
			tag_config.s.inc_prt_flag = 1;
			cvmx_write_csr(CVMX_PIP_PRT_TAGX(port), tag_config.u64);

			/* use registers 0-15 of PIP_TAG_INCn when calculating the tag */
			port_cfg.u64 = cvmx_read_csr(CVMX_PIP_PRT_CFGX(port));
			port_cfg.s.tag_inc = 0;
			cvmx_write_csr(CVMX_PIP_PRT_CFGX(port), port_cfg.u64);
		}
	}
}

int cvmcs_nic_setup_interfaces(void)
{

	/* Initialize the MTU value for all ports to their defaults. */
	cvmcs_nic_init_mtu();

	/* Initialize PTP timestamping */
	cvmcs_nic_init_ptp();

	/* Setup the MAC address for each port. */
	cvmcs_nic_init_macaddr();

	/* Get the skip sizes for first and subsequent wqe pkt buffers. */
	cvmcs_nic_init_pkt_skip_sizes();

	/* setup pip config registers to report receive errors */
	cvmcs_nic_set_pip_err_reporting();

	cvmcs_nic_init_pip_tag_config();

	CVMX_SYNCW;

	return 0;
}

int cvmcs_nic_init_loop_packet_io(void)
{
        int node, i;
	int ipd_port;
	uint32_t cluster = 0;
	cvmx_pki_icgx_cfg_t pki_cl_grp;
	struct cvmx_pki_port_config port_cfg;
	int xiface;

        node = cvmx_get_node_num();

	xiface = cvmcs_get_loop_interface();
	if (xiface == -1)
		return -1;

	ipd_port = cvmx_helper_get_ipd_port(xiface, 0);
	printf("loop interface port number %d\n", ipd_port);
	cvmx_pki_get_port_config(ipd_port, &port_cfg);
	port_cfg.style_cfg.parm_cfg.cache_mode = CVMX_PKI_OPC_MODE_STF;
	port_cfg.style_cfg.parm_cfg.lenerr_en = 1;
	port_cfg.style_cfg.parm_cfg.len_lc = 1;
	port_cfg.style_cfg.parm_cfg.len_lf = 1;
	port_cfg.style_cfg.parm_cfg.csum_lb = 1;
	port_cfg.style_cfg.parm_cfg.csum_lc = 1;
	port_cfg.style_cfg.parm_cfg.csum_ld = 1;
	port_cfg.style_cfg.parm_cfg.csum_le = 1;
	port_cfg.style_cfg.parm_cfg.csum_lf = 1;
	cvmx_pki_set_port_config(ipd_port, &port_cfg);

	pki_cl_grp.u64 = cvmx_read_csr_node(node, CVMX_PKI_ICGX_CFG(0));

	for (i = 0; i < cvmx_helper_ports_on_interface(xiface); i++) {
		cvmx_pki_clx_pkindx_cfg_t   pkind_cfg_reg;
		int pkind = cvmx_helper_get_pknd(xiface, i);

		if (pkind == CVMX_INVALID_PKND)
			continue;

		for (cluster = 0; cluster < CVMX_PKI_NUM_CLUSTER; cluster++) {
			if (!(pki_cl_grp.s.clusters & (0x01L << cluster)))
				continue;

			pkind_cfg_reg.u64 = cvmx_read_csr_node(node, CVMX_PKI_CLX_PKINDX_CFG(pkind, cluster));
			pkind_cfg_reg.s.inst_hdr = 1; /* include the PKI_INST_HDR */
			cvmx_write_csr_node(node, CVMX_PKI_CLX_PKINDX_CFG(pkind, cluster), pkind_cfg_reg.u64);
		}
	}

	return 0;
}

int cvmcs_nic_init_gmx_packet_io(void)
{
        int node, qpg, i, j;
	int ipd_port;
        char name[1024];
        cvmx_xport_t xport;
        cvmx_fpa3_pool_t pool;
        int bpid[MAX_OCTEON_GMX_CHANNELS] = {-1};
        cvmx_fpa3_gaura_t aura[MAX_OCTEON_GMX_CHANNELS] = {{0, 0, 0, 0, 0}};
	struct cvmx_pki_port_config port_cfg;
        struct cvmx_pki_qpg_config qpg_config;
	cvmx_pki_clx_stylex_alg_t style_alg_reg;
	int interface, index, pknd;
	uint32_t cluster = 0;
	cvmx_pki_icgx_cfg_t pki_cl_grp;
	cvmx_pki_clx_pkindx_style_t pkind_cfg_style;
	/* FIXME: cvmcs_pko3_dq_parameters() is not available to nic app.
	 * so had to copy the API and do a test run to get DQ-limit and hardcode
	 **/
#define DQ_LIMIT (1570)

        node = cvmx_get_node_num();

	/* Setup aura, bpid, qpg, style for each of gmx ports */
	for (i = 0; i < (int)octnic->ngmxports; i++) {

		ipd_port = octnic->gmx_port_info[i].ipd_port;
                xport = cvmx_helper_ipd_port_to_xport(ipd_port);

		/* Set the link down. If the host brings up an interface
                   on the link, we can bring it up */

		octnic->gmx_port_info[i].cam_flags = 0;

		cvmcs_nic_phy_init(i);

		cvmcs_bgx_link_down(&octnic->gmx_port_info[i]);

		pool = cvmx_fpa3_aura_to_pool(cvmx_fpa1_pool_to_fpa3_aura(CVMX_FPA_PACKET_POOL));

		qpg = cvmx_pki_qpg_entry_alloc(node, CVMX_PKI_FIND_AVAL_ENTRY, MAX_OCTEON_GMX_CHANNELS);
		if (qpg < 0) {
			printf("ERROR: %s qpg entry alloc failed\n", __func__);
			return -1;
		}

		for (j = 0; j < MAX_OCTEON_GMX_CHANNELS; j++) {
			bpid[j] = cvmx_pki_bpid_alloc(node, CVMX_PKI_FIND_AVAL_ENTRY);
			if (bpid[j] < 0) {
				printf("ERROR: %s BP ID allocation failed\n", __func__);
				break;
			}

			sprintf(name,"port%d_chan%d_aura", ipd_port, j);

			aura[j] = cvmx_fpa3_set_aura_for_pool(pool, CVMX_PKI_FIND_AVAL_ENTRY, name,
				CVMX_FPA_PACKET_POOL_SIZE, FPA_PACKET_POOL_COUNT);

			if (!__cvmx_fpa3_aura_valid(aura[j])) {
				printf("ERROR: %s AURA %d alloc failed\n", __func__, aura[j].laura);
				break;
			}
		}

		if (j < MAX_OCTEON_GMX_CHANNELS) {
			for (j = 0; j < MAX_OCTEON_GMX_CHANNELS; j++) {
				if (bpid[j] >= 0)
					cvmx_pki_bpid_free(node, bpid[j]);
				if (__cvmx_fpa3_aura_valid(aura[j]))
					cvmx_fpa3_release_aura(aura[j]);
			}

			cvmx_pki_qpg_entry_free(node, CVMX_PKI_FIND_AVAL_ENTRY, MAX_OCTEON_GMX_CHANNELS);
		}

        	CVMX_SYNCW;

		for (j = 0; j < MAX_OCTEON_GMX_CHANNELS; j++) {

			cvmx_pki_write_aura_bpid(node, aura[j].laura, bpid[j]);
                	cvmx_pki_write_channel_bpid(node, xport.port + j, bpid[j]);
			printf("setting bpid-%d on xport.port-%d chan-%d aura-%d\n",
				bpid[j], xport.port, j, aura[j].laura);

			/* set PASS threshold between BP and DROP thresholds.
			 * this give the source some time to respond to PAUSE
			 * frames sent due to BP, before start dropping packets
			 * randomly.
			 **/
			cvmx_helper_setup_aura_qos(node, aura[j].laura, 1, 1,
				(int)(GMX_BP_THRESHOLD_78XX+DQ_LIMIT)/2,
				DQ_LIMIT, 1, GMX_BP_THRESHOLD_78XX);

			qpg_config.qpg_base = qpg + j;
			qpg_config.port_add = j;
			qpg_config.aura_num = aura[j].laura;
			qpg_config.grp_ok = j;
			qpg_config.grp_bad = j;
			qpg_config.grptag_ok = 0;
			qpg_config.grptag_bad = 0;
        
        		cvmx_pki_write_qpg_entry(node, qpg_config.qpg_base, &qpg_config);
		}

		cvmx_pki_get_port_config(ipd_port, &port_cfg);
		port_cfg.style_cfg.parm_cfg.qpg_base = qpg;
		port_cfg.style_cfg.parm_cfg.qpg_qos = CVMX_PKI_QPG_QOS_NONE;
		port_cfg.style_cfg.parm_cfg.qpg_port_msb = 0;
		port_cfg.style_cfg.parm_cfg.qpg_port_sh = 0;
		port_cfg.style_cfg.parm_cfg.qpg_dis_padd = 0;
		port_cfg.style_cfg.parm_cfg.dis_wq_dat = 0;
		port_cfg.style_cfg.parm_cfg.cache_mode = CVMX_PKI_OPC_MODE_STF;
		port_cfg.style_cfg.parm_cfg.lenerr_en = 1;
		port_cfg.style_cfg.parm_cfg.len_lc = 1;
		port_cfg.style_cfg.parm_cfg.len_lf = 1;
		port_cfg.style_cfg.parm_cfg.csum_lb = 1;
		port_cfg.style_cfg.parm_cfg.csum_lc = 1;
		port_cfg.style_cfg.parm_cfg.csum_ld = 1;
		port_cfg.style_cfg.parm_cfg.csum_le = 1;
		port_cfg.style_cfg.parm_cfg.csum_lf = 1;
		
		/* Added inner src.ip and dest.ip for tag calculation for tunnel
		 * packets */
		port_cfg.style_cfg.tag_cfg.tag_fields.layer_e_src = 1;
		port_cfg.style_cfg.tag_cfg.tag_fields.layer_e_dst = 1;

		cvmx_pki_set_port_config(ipd_port, &port_cfg);

        	interface = cvmx_helper_get_interface_num(ipd_port);
        	index = cvmx_helper_get_interface_index_num(ipd_port);

		/* Extract pknd, cluster, style information */
		pknd = cvmx_helper_get_pknd(interface, index);
		pki_cl_grp.u64 = cvmx_read_csr_node(xport.node, CVMX_PKI_ICGX_CFG(0));

		while(cluster < CVMX_PKI_NUM_CLUSTER) {
			if(pki_cl_grp.s.clusters & (0x01L << cluster))
				break;
			cluster++;
		}
		pkind_cfg_style.u64 = cvmx_read_csr_node(xport.node, CVMX_PKI_CLX_PKINDX_STYLE(pknd, cluster));

		style_alg_reg.u64 = cvmx_read_csr(CVMX_PKI_CLX_STYLEX_ALG(pkind_cfg_style.s.style, cluster));
		style_alg_reg.s.tag_vni = 1;
		style_alg_reg.s.tag_vlan = 1;
		style_alg_reg.s.tag_prt = 1;
		cvmx_write_csr(CVMX_PKI_CLX_STYLEX_ALG(pkind_cfg_style.s.style, cluster), style_alg_reg.u64);
	}

	return 0;
}

void cvmcs_nic_init_sso_grp_pri(void)
{
	unsigned node = cvmx_get_node_num();
	cvmx_sso_grpx_pri_t grp_pri;

	/* Set the Priority For 73XX only */
	if  (!OCTEON_IS_MODEL(OCTEON_CN73XX))
		return;

	/* Set priority for PF Control Packet GRP */
	grp_pri.u64 = cvmx_read_csr_node(node,
					 CVMX_SSO_GRPX_PRI(OCTEON_CTRL_GRP_PF));
	grp_pri.s.pri = OCTEON_CTRL_GRP_PF_PRI;
	cvmx_write_csr_node(node, CVMX_SSO_GRPX_PRI(OCTEON_CTRL_GRP_PF),
			    grp_pri.u64);

	/* Set priority for VF Control Packet GRP */
	grp_pri.u64 = cvmx_read_csr_node(node,
					 CVMX_SSO_GRPX_PRI(OCTEON_CTRL_GRP_VF));
	grp_pri.s.pri = OCTEON_CTRL_GRP_VF_PRI;
	cvmx_write_csr_node(node, CVMX_SSO_GRPX_PRI(OCTEON_CTRL_GRP_VF),
			    grp_pri.u64);

	/* Set priority for Data Packet GRP */
	grp_pri.u64 = cvmx_read_csr_node(node,
					 CVMX_SSO_GRPX_PRI(OCTEON_DATA_GRP));
	grp_pri.s.pri = OCTEON_DATA_GRP_PRI;
	cvmx_write_csr_node(node, CVMX_SSO_GRPX_PRI(OCTEON_DATA_GRP),
			    grp_pri.u64);

#ifdef VSWITCH
	/* Any control request/response between Octlinux and SE has higher
	 * priority
	 */

	grp_pri.u64 = cvmx_read_csr_node(node,
					 CVMX_SSO_GRPX_PRI(LINUX_POW_DATA_GROUP));
	grp_pri.s.pri = OCTEON_DATA_GRP_PRI;
	cvmx_write_csr_node(node, CVMX_SSO_GRPX_PRI(LINUX_POW_DATA_GROUP),
			    grp_pri.u64);

	grp_pri.u64 = cvmx_read_csr_node(node,
					 CVMX_SSO_GRPX_PRI(LINUX_POW_CTRL_GROUP));
	grp_pri.s.pri = OCTEON_CTRL_GRP_PF_PRI;
	cvmx_write_csr_node(node, CVMX_SSO_GRPX_PRI(LINUX_POW_CTRL_GROUP),
			    grp_pri.u64);

	grp_pri.u64 = cvmx_read_csr_node(node,
					 CVMX_SSO_GRPX_PRI(SE_POW_GROUP));
	grp_pri.s.pri = OCTEON_CTRL_GRP_PF_PRI;
	cvmx_write_csr_node(node, CVMX_SSO_GRPX_PRI(SE_POW_GROUP),
			    grp_pri.u64);
#endif
}

int cvmcs_nic_init_packet_io(void)
{
        /* Used for DCB support on XFI interface */
        cvmcs_dcb_queue_config_pfc_en(cvmcs_dcb_get_xfi_interface());

	if (cvmx_helper_initialize_packet_io_global() == -1) {
		printf("# cvmcs: Failed to initialize input ports\n");
		return 1;
	}

        CVMX_SYNCW;

	/* Enable IPD only after sending the START indication packet to host. */
	if (octeon_has_feature(OCTEON_FEATURE_PKI))
                cvmx_pki_disable(cvmx_get_node_num());
        else
                cvmx_ipd_disable();

        /* Disable PKO while we configure PCI driver. */
	if (octeon_has_feature(OCTEON_FEATURE_PKI)) {
                int node;
        	cvmx_pko_enable_t pko_enable;
		cvmx_pki_gbl_pen_t gbl_pen_reg;
		struct cvmx_pki_style_config style_cfg;

                pko_enable.u64 = 0;

                cvmx_write_csr_node(cvmx_get_node_num(), CVMX_PKO_ENABLE, pko_enable.u64);

                node = cvmx_get_node_num();

		gbl_pen_reg.u64 = cvmx_read_csr_node(node, CVMX_PKI_GBL_PEN);
		gbl_pen_reg.s.virt_pen = 1;
		cvmx_write_csr_node(node, CVMX_PKI_GBL_PEN, gbl_pen_reg.u64);

		cvmx_helper_pki_get_dflt_style(node, &style_cfg);
		//style_cfg.parm_cfg.cache_mode = CVMX_PKI_OPC_MODE_STF;
		style_cfg.parm_cfg.csum_lb = true;  /* VLAN */
		style_cfg.parm_cfg.csum_lc = true;  /* Outer IPv4/IPv6 */
		style_cfg.parm_cfg.csum_ld = true;  /* VXLAN*/
		style_cfg.parm_cfg.csum_le = true;  /* Inner IPv4/IPv6 */
		style_cfg.parm_cfg.csum_lf = true;  /* TCP/UDP/SCTP/GRE */
		
		cvmx_helper_pki_set_dflt_style(node, &style_cfg);

		if (cvmcs_nic_init_loop_packet_io())
			return 1;

		if (cvmcs_nic_init_gmx_packet_io())
			return 1;

		/*Set SSO Group Priority */
		cvmcs_nic_init_sso_grp_pri();

        } else {
                cvmx_pko_disable();
        }

	return 0;
}
