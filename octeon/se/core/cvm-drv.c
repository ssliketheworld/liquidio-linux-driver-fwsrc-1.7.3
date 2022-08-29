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



#include "cvm-drv.h"
#include "liquidio_common.h"
#include "cvmx-sysinfo.h"
#include "cvm-pci-loadstore.h"
#include "cvm-core-cap.h"

#pragma weak rinfo_set_by_host_fn
CVMX_SHARED int (*rinfo_set_by_host_fn)(int, uint64_t) = NULL;

#pragma weak drv_restart_app_cb
CVMX_SHARED void (*drv_restart_app_cb)(int) = NULL;

CVMX_SHARED  cvm_oct_dev_t   *oct;
int          cvm_drv_core_id;

static bool get_uboot_params = 0;


extern void cn73xx_intr_config( void);
extern void cn73xx_local_intr_config( void);

extern int read_uboot_parameter(void );

#ifdef  CN56XX_PEER_TO_PEER
int
cn56xx_alloc_peeriq_memory(void);

extern void
cn56xx_setup_peeriq_op_handler(void);
#endif


void
cvm_drv_wait(int time_in_us)
{
	cvmx_wait(oct->clocks_per_us * time_in_us);
}





void
cvm_drv_local_init()
{
	cvm_drv_core_id = cvmx_get_core_num();
	if(OCTEON_IS_MODEL(OCTEON_CN73XX))
		cn73xx_local_intr_config();
}


void
setup_pci_input_ports(void)
{
	int port;
	cvmx_pip_port_tag_cfg_t  tag_config;
	cvmx_pip_port_cfg_t      port_config;

	for (port = FIRST_PCI_PORT; port <= LAST_PCI_PORT ; port++)   {

		port_config.u64 = 0;

		/* Have each port go to a different POW queue */
		port_config.s.qos  = port - 32;
		port_config.s.mode = CVMX_PIP_PORT_CFG_MODE_NONE;

		/* setup the ports again for ATOMIC tag */
		tag_config.u64            = 0;
		tag_config.s.inc_prt_flag = 1;
		tag_config.s.non_tag_type = CVMX_POW_TAG_TYPE_ATOMIC;
		tag_config.s.grp          = 0;

		/* Set up the PCI Input port configuration */
		cvmx_pip_config_port(port, port_config, tag_config);
	}

}


void
setup_pci_input_ports_pki(void)
{
	if (octeon_has_feature(OCTEON_FEATURE_PKI)) {

		int node, pkind, cluster, style;
		int i;
		cvmx_pki_clx_pkindx_style_t pkind_cfg_style;
		cvmx_pki_clx_stylex_alg_t style_alg_reg;
		int channels_per_pkind = (OCTEON_IS_MODEL(OCTEON_CN73XX))?64:32;
		unsigned  cluster_mask=0;
		int num_clusters;

		/* get the local node  number */
		node = cvmx_get_node_num();

		/* 2. Assign the clusters to the cluster group -0 */
		if(OCTEON_IS_MODEL(OCTEON_CN78XX))
		    cluster_mask = 0xf;

		if(OCTEON_IS_MODEL(OCTEON_CN73XX))
		    cluster_mask = 0x3;

		num_clusters = __builtin_popcount(cluster_mask);

		/* Get PKIND for DPI */
		//TODO do this for both clusters
		//we get 2 pkinds and 2 styles for DPI from SDK
		for ( i = 0; i < 2; i++) {
			pkind = cvmx_helper_get_pknd(cvmx_helper_get_interface_num(0x100), i*channels_per_pkind);
			for (cluster = 0; cluster < num_clusters; cluster++) {
				/* Get STYLE for the PKIND */
				pkind_cfg_style.u64 = cvmx_read_csr_node(node, CVMX_PKI_CLX_PKINDX_STYLE(pkind, cluster));
				style = pkind_cfg_style.s.style;
				
				style_alg_reg.u64 = cvmx_read_csr(CVMX_PKI_CLX_STYLEX_ALG(style, cluster));
				style_alg_reg.s.tag_vni = 1;
				style_alg_reg.s.tag_vlan = 1;
				style_alg_reg.s.tag_prt = 1;
				cvmx_write_csr(CVMX_PKI_CLX_STYLEX_ALG(style, cluster), style_alg_reg.u64);
			}
		}
	}
}



extern void __cn68xx_qlm_gen2_fix(void);



int
cvm_drv_init()
{

	DBG_PRINT(DBG_FLOW, "[ DRV ] Driver Initialization\n");
	if(OCTEON_IS_MODEL(OCTEON_CN56XX_PASS1)) {
		printf("[ DRV ] CN56XX Pass1 is not supported\n");
		return -1;
	}

	DBG_PRINT(DBG_FLOW, "[ DRV ] Allocating memory for octeon device\n");
	oct = cvmx_bootmem_alloc_named(sizeof (cvm_oct_dev_t), CVMX_CACHE_LINE_SIZE, "__oct");
	if(oct == NULL) {
		printf("[ DRV ] octeon device alloc failed\n");
		return -1;
	}

	memset(oct, 0, sizeof(cvm_oct_dev_t));

	oct->clocks_per_us = (cvmx_sysinfo_get()->cpu_clock_hz/ (1000 * 1000));

	if(OCTEON_IS_MODEL(OCTEON_CN78XX) || OCTEON_IS_MODEL(OCTEON_CN73XX)) {
		oct->max_dma_qs = 8;
		oct->npi_if     = cvmx_helper_get_interface_num(0x100);
	}

	if(OCTEON_IS_MODEL(OCTEON_CN68XX)) {
		oct->max_dma_qs = 8;
		oct->npi_if     = cvmx_helper_get_interface_num(0x100);
	}

	if (OCTEON_IS_MODEL(OCTEON_CN66XX))
		oct->max_dma_qs = 8;

	/* Make sure we are not in NULL_NULL POW state
	   (if we are, we cant output a packet) */
	cvmx_pow_work_request_null_rd();

	if(!(OCTEON_IS_MODEL(OCTEON_CN68XX) || OCTEON_IS_MODEL(OCTEON_CN78XX) ||
	     OCTEON_IS_MODEL(OCTEON_CN73XX)))
		setup_pci_input_ports();
	if (OCTEON_IS_MODEL(OCTEON_CN73XX) || OCTEON_IS_MODEL(OCTEON_CN78XX))
		setup_pci_input_ports_pki();

	if( OCTEON_IS_MODEL(OCTEON_CN68XX_PASS1_0) || 
	    OCTEON_IS_MODEL(OCTEON_CN68XX_PASS1_1) /*||
	    OCTEON_IS_MODEL(OCTEON_CN68XX_PASS1_2)*/ )
		__cn68xx_qlm_gen2_fix();


	if(setup_pci_pko_ports())
		return -1;
	DBG_PRINT(DBG_FLOW, "[ DRV ] PKO Done\n");

	/* To indicate a RAW mode packet in WQE word2 */
	if (octeon_has_feature(OCTEON_FEATURE_PKI)) {

		int node, pkind, cluster, style;
		int i;
		uint64_t word2;
		cvmx_pki_pkindx_icgsel_t    pkind_clsel;
		cvmx_pki_clx_pkindx_style_t pkind_cfg_style;
		cvmx_pki_clx_pkindx_cfg_t   pkind_cfg_reg;
		cvmx_pki_stylex_buf_t       style_buf_reg;
		cvmx_pki_icgx_cfg_t         icgx_cfg_reg;
		int channels_per_pkind = (OCTEON_IS_MODEL(OCTEON_CN73XX))?64:32;
		unsigned  cluster_mask=0;
		int num_clusters;

		/* get the local node  number */
		node = cvmx_get_node_num();

		/* 2. Assign the clusters to the cluster group -0 */
		if(OCTEON_IS_MODEL(OCTEON_CN78XX))
		    cluster_mask = 0xf;

		if(OCTEON_IS_MODEL(OCTEON_CN73XX))
		    cluster_mask = 0x3;

		num_clusters = __builtin_popcount(cluster_mask);

		icgx_cfg_reg.u64 = cvmx_read_csr_node(node, CVMX_PKI_ICGX_CFG(0));
		icgx_cfg_reg.s.clusters = cluster_mask;
		cvmx_write_csr_node(node, CVMX_PKI_ICGX_CFG(0), icgx_cfg_reg.u64);

		/* Get PKIND for DPI */
		//TODO do this for both clusters
		//we get 2 pkinds and 2 styles for DPI from SDK
		for ( i = 0; i < 2; i++) {
			pkind = cvmx_helper_get_pknd(cvmx_helper_get_interface_num(0x100), i*channels_per_pkind);
        		pkind_clsel.u64 = cvmx_read_csr_node(node, CVMX_PKI_PKINDX_ICGSEL(pkind));
        		pkind_clsel.s.icg = 0;
        		cvmx_write_csr_node(node, CVMX_PKI_PKINDX_ICGSEL(pkind), pkind_clsel.u64);
			for (cluster = 0; cluster < num_clusters; cluster++) {
				/* Get STYLE for the PKIND */
				pkind_cfg_style.u64 = cvmx_read_csr_node(node, CVMX_PKI_CLX_PKINDX_STYLE(pkind, cluster));
				style = pkind_cfg_style.s.style;

				/* Set the INST_HDR bit in PKI_CL[clsuter]_PKIND[pkind]_CFG */
				pkind_cfg_reg.u64 = cvmx_read_csr_node(node, CVMX_PKI_CLX_PKINDX_CFG(pkind, cluster));
				pkind_cfg_reg.s.inst_hdr = 1; /* include the PKI_INST_HDR */	
				cvmx_write_csr_node(node, CVMX_PKI_CLX_PKINDX_CFG(pkind, cluster), pkind_cfg_reg.u64);
				DBG_PRINT(DBG_NORM, "PKI_CL[%d]_PKIND[%d]_CFG[inst_hdr]: 0x%016lx\n", cluster, pkind, 
				cvmx_read_csr_node(node, CVMX_PKI_CLX_PKINDX_CFG(pkind, cluster)) );
			}
		}
		
		/* Set SW bit in the CVMX_PKI_STYLE[style]_WQ2 Register */
		word2 = cvmx_read_csr_node(node, CVMX_PKI_STYLEX_WQ2(style) );
		//word2 = word2 | 0x8000000000000000; /* set the SW bit for the packets coming from host */	
		/* write Word-2 of WQE to the STYLEn register with s/w bit set to 1 */
		cvmx_write_csr_node(node, CVMX_PKI_STYLEX_WQ2(style), word2);	
		word2 = cvmx_read_csr_node(node, CVMX_PKI_STYLEX_WQ2(style));
		DBG_PRINT(DBG_NORM, "PKI_STYLE[%d]_WQ2[sw]: 0x%016lx\n", style, word2);

		style_buf_reg.u64 = cvmx_read_csr_node(node, CVMX_PKI_STYLEX_BUF(style) );	

		/* Enable this if sharing the first buffer for WQE and Packet data */
#if 0
		/* Set the FIRST_SKIP = 0x5 in CVMX_PKI_STYLE[style]_BUF - The space for WQE first 5 words */
		/* Space of Five 8B words for WQE words */
		style_buf_reg.s.first_skip = 0x5; 
		/* Use separate buffers for WQE and Packet Data */
		style_buf_reg.s.dis_wq_dat = 0x1; 
#endif
		cvmx_write_csr_node(node, CVMX_PKI_STYLEX_BUF(style), style_buf_reg.u64);
		DBG_PRINT(DBG_NORM, "PKI_STYLE[%d]_BUF[first_skip]: 0x%016lx  \n\n", style,
			cvmx_read_csr_node(node, CVMX_PKI_STYLEX_BUF(style)) );
	}
	else
		cvmx_write_csr(CVMX_PIP_RAW_WORD, cvmx_read_csr(CVMX_PIP_RAW_WORD)|0x8000);
	
	DBG_PRINT(DBG_FLOW, "[ DRV ] Setting up DMA Engines\n");
	if(cvm_dma_queue_init(oct)) {
		printf("[ DRV ] DMA Queue initialization failed\n");
		return -1;
	}

	oct->state = CVM_DRV_INIT;

	cvm_setup_pci_load_store();


	CVMX_SYNCW;
	return 0;
}

int
cvm_drv_change_state(cvmx_wqe_t  *wqe)
{
	cvmx_raw_inst_front_t  *f;
	uint32_t                op, status=0;
	uint8_t                 action;
	if (octeon_has_feature(OCTEON_FEATURE_CN78XX_WQE))
		f = (cvmx_raw_inst_front_t *) cvmx_phys_to_ptr(cvmx_wqe_get_pki_pkt_ptr(wqe).addr);
	else
		f = (cvmx_raw_inst_front_t *)wqe->packet_data;

	op = f->irh.s.opcode;


	if(op == DEVICE_STOP_OP) {
		printf(" \n\n [ DRV ] Received Driver STOP Command from Host--\n");

#ifdef CVM_PCI_TRACK_DMA
		cvm_pci_dma_dump_tracker_list();
#endif

		action = (f->irh.s.ossp & 0xf);

		if((action & DEVICE_PKO) && (oct->pko_state == CVM_DRV_PKO_READY)) {
			oct->pko_state = CVM_DRV_PKO_STOP;
			printf("[ DRV ] Packets to PCI Host will be discarded\n");
		}

		if(action & DEVICE_IPD) {
			cvmx_ipd_disable();
			printf("[ DRV ] IPD is now disabled\n");
		}

	}

	if(op == HOT_RESET_OP) {
		oct->state     = CVM_DRV_RESET;
		oct->pko_state = CVM_DRV_PKO_STOP;
		printf(" \n\n [ DRV ] Received Device Reset from Host--\n");
		printf("[ DRV ] Packets to PCI Host will be discarded\n");
	}

	if(op == DEVICE_START_OP) {
		printf(" \n\n [ DRV ] Received Driver START Command from Host--\n");

		action = (f->irh.s.ossp & 0xf);

		if(action & DEVICE_PKO) {
			if(oct->pko_state == CVM_DRV_PKO_STOP) {
				printf("[ DRV ] Packets to PCI Host will be forwarded\n");
				oct->pko_state = CVM_DRV_PKO_READY;
			} else {
				status = 0x11000011;
			}
		}

		if(action & DEVICE_IPD) {
                	cvmx_ipd_enable();
			printf("[ DRV ] IPD is now enabled\n");
		}
	}

	/* On success, write 0 to host response address */
	if(f->rptr)
		cvm_pci_mem_writel(f->rptr, status);

	cvm_free_host_instr(wqe);
	CVMX_SYNCWS;
	return 0;
}

void
init_lut_drn_to_pvfn(cvmx_sli_pkt_macx_pfx_rinfo_t rinfo, int pfnum)
{
	int i, first_pf_ring, last_pf_ring, vf, first_ring_of_vfx;

	first_pf_ring = rinfo.s.srn + rinfo.s.nvfs * rinfo.s.rpvf;
	last_pf_ring  = rinfo.s.srn + rinfo.s.trs - 1;

	for (i = first_pf_ring; i <= last_pf_ring; i++) {
		oct->lut_drn_to_pvfn[i] = pfnum << 13;
		/* 13 is the correct bit position of the PF field in the
		   DPI_DMA_FUNC_SEL_S structure (even though the 73xx HRM says
		   something else). */
	}

	for (vf = rinfo.s.nvfs; vf > 0; vf--) {
		first_ring_of_vfx = (vf-1) * rinfo.s.rpvf + rinfo.s.srn;
		for (i = 0; i < rinfo.s.rpvf; i++) {
			oct->lut_drn_to_pvfn[first_ring_of_vfx + i] = (pfnum << 13) | (vf & 0x1FFF);
		}
	}
}

int cvm_drv_start_pf(int pf_num, int num_gmx_ports, int max_nic_ports)
{
#define CTRL_QUEUE_NUM              0
    uint32_t control_droq_no=CTRL_QUEUE_NUM;
    cvmx_sli_pkt_macx_pfx_rinfo_t rinfo;
    cvmx_sli_pp_pkt_csr_control_t pktcsr;
    cvmx_sli_pktx_output_control_t droq_ctl;
    uint8_t              *buf;
    struct octeon_core_setup *core;
    union octeon_rh      *rh;
    cvmx_buf_ptr_t        lptr;
    cvmx_sysinfo_t *sysinfo;
    pndis_offload   feature_info;
    int                   datalen = 0;

    if (OCTEON_IS_MODEL(OCTEON_CN73XX)) {
        if (OCTEON_IS_MODEL(OCTEON_CN73XX_PASS1_0) && pf_num==1) {
            rinfo.u64 = cvmx_read_csr(CVMX_PEXP_SLI_PKT_MACX_PFX_RINFO(pf_num,0));
            if ((rinfo.u64 == 0xFFFFFFFFFFFFFFFFULL) || (!rinfo.s.trs))
                return -1;

            init_lut_drn_to_pvfn(rinfo, pf_num);
            control_droq_no = rinfo.s.srn + rinfo.s.nvfs * rinfo.s.rpvf;

            /* Because of erratum DPI-25866, we can't access PF1's SLI_PKT
             * registers.  So we can't tell if PF1's control DROQ is enabled or
             * not.  If PF0 has not started yet, then we'll assume that PF1's
             * control DROQ is not yet enabled, and we won't start PF1 yet.
             * But if PF0 has started, then we'll assume that PF1's control DROQ
             * is enabled, and we'll start PF1.
             */
            if (!oct->pf_started[0])
                return -1;

        } else {
            int rinfo_is_set_by_host;

            pktcsr.s.mac = 0;
            pktcsr.s.pvf = (pf_num << 13);

            /* write of CVMX_SLI_PP_PKT_CSR_CONTROL is required for pass 1.0 h/w bug */
            cvmx_spinlock_lock(&oct->pp_pkt_csr_ctrl_lock);

            cvmx_write_csr(CVMX_SLI_PP_PKT_CSR_CONTROL, pktcsr.u64);

            rinfo.u64 = cvmx_read_csr(CVMX_PEXP_SLI_PKT_MACX_PFX_RINFO(pf_num,0));

            cvmx_spinlock_unlock(&oct->pp_pkt_csr_ctrl_lock);

            /* If a function ptr is present, invoke it to let the APP determine 
             * if RINFO has been set (by host).
             * Otherwise, the default behavior is to assume that the host has
             * written the RINFO register if the 'trs' field is !0.
             */
            if (rinfo_set_by_host_fn != NULL)
                rinfo_is_set_by_host = rinfo_set_by_host_fn(pf_num, rinfo.u64);
            else
                rinfo_is_set_by_host = (rinfo.s.trs != 0);

            /* Wait for host to set RINFO */
            if ((rinfo.u64 == 0xFFFFFFFFFFFFFFFFULL) || !rinfo_is_set_by_host)
                return -1;

            init_lut_drn_to_pvfn(rinfo, pf_num);
            control_droq_no = rinfo.s.srn + rinfo.s.nvfs * rinfo.s.rpvf;

            cvmx_spinlock_lock(&oct->pp_pkt_csr_ctrl_lock);

            cvmx_write_csr(CVMX_SLI_PP_PKT_CSR_CONTROL, pktcsr.u64);

            droq_ctl.u64 = cvmx_read_csr(CVMX_PEXP_SLI_PKTX_OUTPUT_CONTROL(rinfo.s.nvfs * rinfo.s.rpvf));

            cvmx_spinlock_unlock(&oct->pp_pkt_csr_ctrl_lock);

            if (!droq_ctl.s.enb)
                return -1;
        }
    } else {
	if (pf_num != 0)
		return 0;
    }

    buf = (uint8_t *) cvm_drv_fpa_alloc_sync(CVMX_FPA_PACKET_POOL);
    if(buf == NULL) {
       printf("\n\n[ DRV ] CRITICAL ERROR!!!\n");
       printf("[ DRV ] Failed to send core driver indicator!!!!\n\n");
       oct->state = CVM_DRV_INIT;
       oct->pko_state = CVM_DRV_PKO_STOP;
       CVMX_SYNCWS;
       return 1;
    }

    rh = (union octeon_rh *)buf;
    core = (struct octeon_core_setup *)(buf + sizeof(union octeon_rh));
    datalen = sizeof(struct octeon_core_setup);

    rh->u64         = 0;
    rh->r_core_drv_init.opcode    = OPCODE_NIC;
    rh->r_core_drv_init.subcode   = OPCODE_NIC_CORE_DRV_ACTIVE;
    rh->r_core_drv_init.app_mode  = oct->app_code;
#ifdef VSWITCH
    if (pf_num == 0)
    	rh->r_core_drv_init.app_cap_flags =  LIQUIDIO_MGMT_INTF_CAP;
    rh->r_core_drv_init.app_cap_flags |= LIQUIDIO_SWITCHDEV_CAP;
#endif
    rh->r_core_drv_init.app_cap_flags |= LIQUIDIO_SPOOFCHK_CAP;
    rh->r_core_drv_init.num_gmx_ports  = num_gmx_ports;
    rh->r_core_drv_init.max_nic_ports = max_nic_ports;
    rh->r_core_drv_init.pkind =  cvmx_helper_get_pknd(cvmx_helper_get_interface_num(0x100), (pf_num == 0) ? 0 : 64);

    core->corefreq = oct->clocks_per_us * 1000 * 1000;

    sysinfo = cvmx_sysinfo_get();
    core->board_rev_major = sysinfo->board_rev_major;
    core->board_rev_minor = sysinfo->board_rev_minor;
    strcpy(core->board_serial_number,
		    sysinfo->board_serial_number);
    strcpy(core->boardname,
		    cvmx_board_type_to_string(sysinfo->board_type));
    feature_info = (pndis_offload)(((void *)core) + datalen);
    add_nic_features(feature_info);
    datalen += sizeof(ndis_offload);

    lptr.u64    = 0;
    lptr.s.size = sizeof(union octeon_rh) + datalen;
    lptr.s.addr = CVM_DRV_GET_PHYS(buf);
    lptr.s.pool = CVMX_FPA_PACKET_POOL;
    lptr.s.i    = 1;
    CVMX_SYNCWS;

    DBG_PRINT(DBG_FLOW, "[ DRV ] Core app is active. Sending indication to host (OQ: %u)\n", control_droq_no);
    /* Send the indication packet on the first output queue. */
    return cvm_send_pci_pko_direct(lptr, CVM_DIRECT_DATA, 1, lptr.s.size, control_droq_no);
}

int cvm_drv_start_pfs(int num_gmx_ports, int max_nic_ports)
{
    int i, retval = -1;

    if (get_uboot_params == 0) {
    	read_uboot_parameter();
	get_uboot_params = 1;
    }

    for (i = 0; i < MAX_NUM_PFS; i++) {

	if (oct->pf_started[i] == 0) {

    		if (!cvm_drv_start_pf(i, num_gmx_ports, max_nic_ports)) {
			oct->pf_started[i] = 1;
			retval = 0;
		}

	}

    }

    return retval;
}

void cvm_drv_restart_pf(int pf_num)
{
	oct->pf_started[pf_num] = 0;

	if (drv_restart_app_cb != NULL)
		(*drv_restart_app_cb)(pf_num);
}

int
cvm_drv_start(int num_gmx_ports, int max_nic_ports)
{
    int	i, retval = 0;

    /* Change to state READY temporarily to allow PKO to sent indication
       to host. Check return value to adjust state before exit. */
    oct->pko_state = CVM_DRV_PKO_READY;
    CVMX_SYNCW;

    for (i = 0; i < MAX_NUM_PFS; i++)
        oct->pf_started[i] = 0;

#if 0
    /* Register the HOT RESET handler */
    DBG_PRINT(DBG_FLOW, "[Registering HotReset Handler (Opcode: 0x%x)\n", HOT_RESET_OP);
    cvm_drv_register_op_handler(OPCODE_CORE, HOT_RESET_OP,  cvm_drv_change_state); 

    DBG_PRINT(DBG_FLOW, "[Registering Output Queue Command Handler (Opcode: 0x%x)\n",
           DEVICE_STOP_OP);
    cvm_drv_register_op_handler(OPCODE_CORE, DEVICE_STOP_OP,  cvm_drv_change_state);

    DBG_PRINT(DBG_FLOW, "[Registering Output Queue Command Handler (Opcode: 0x%x)\n",
           DEVICE_START_OP);
    cvm_drv_register_op_handler(OPCODE_CORE, DEVICE_START_OP,  cvm_drv_change_state);
#endif

#ifdef  CN56XX_PEER_TO_PEER
    cn56xx_setup_peeriq_op_handler();
#endif

    /* With SDK 1.8.1, check for PASS2 include 56xx 2.x devices.
       Keep Check for Pass2.1 here to be compatible with 1.8.0 */
    if( (OCTEON_IS_MODEL(OCTEON_CN56XX_PASS2)
        || OCTEON_IS_MODEL(OCTEON_CN56XX_PASS2_1)) ) {
        uint64_t  val64 = cvmx_read_csr(CVMX_IOB_INT_ENB);
        printf("Disabling NP_DAT NP_SOP & NP_EOP for 56xx Pass2\n");
        val64 &= ~(0x13ULL);
        cvmx_write_csr(CVMX_IOB_INT_ENB, val64);  
    }

    /* If pko send was not successful, reset the state to INIT */
    if(retval) {
        oct->pko_state = CVM_DRV_PKO_STOP;
    } else {
        oct->state = CVM_DRV_READY;
        DBG_PRINT(DBG_FLOW, " [ DRV ] Octeon device is in READY state\n");
    }

#if 1 //Enable interrupt handling.
    if(OCTEON_IS_MODEL(OCTEON_CN73XX))
	    cn73xx_intr_config();
#endif


    CVMX_SYNCW;

    return retval;
}





int
cvm_drv_process_instr(cvmx_wqe_t   *wqe)
{
	cvmx_raw_inst_front_t  *front;
	uint16_t   opcode;
	uint16_t   subcode;
	uint16_t   op_tail;

	if (octeon_has_feature(OCTEON_FEATURE_CN78XX_WQE))
		front = (cvmx_raw_inst_front_t *) cvmx_phys_to_ptr(cvmx_wqe_get_pki_pkt_ptr(wqe).addr);
	else
		front = (cvmx_raw_inst_front_t *)wqe->packet_data;

	opcode  = front->irh.s.opcode;
	subcode = front->irh.s.subcode;

	DBG_PRINT(DBG_FLOW,"\n-----cvm_drv_process_instr-----\n");

	op_tail = OPCODE_SUBCODE(opcode, subcode);
	if((op_tail <= MAX_OPCODES)) {
		if(oct->optable[op_tail]) {
			oct->optable[op_tail](wqe);
			return 0;
		}
	} 
	printf("[ DRV ] Unsupported Opcode: %x in instruction\n", op_tail);
	cvm_free_host_instr(wqe);
	return 1;
}




int
cvm_drv_register_op_handler(uint16_t opcode, uint16_t subcode, int (*handler)(cvmx_wqe_t *))
{
	uint16_t   op = OPCODE_SUBCODE(opcode, subcode);
	uint16_t   op_head = ((op & 0xff00) >> 8);
	uint16_t   op_tail = (op & 0xff);

	if((op_head != 0x10 && op_head != 0x11) || (op_tail > MAX_OPCODES)) {
		printf("[ DRV ] OPCODE %x is not the supported range. Registration failed\n", op);
		return 1;
	}

	printf("[ DRV ] Registered handler @ %p for opcode: %x \n", handler, op);
	oct->optable[op_tail] = handler;
	return 0;
}





void
cvm_drv_setup_app_mode(int app_mode)
{
	oct->app_code |= app_mode;
}



void
cvm_56xx_pass2_update_pcie_req_num(void)
{
	uint64_t   mval = 8 + (cvmx_get_cycle() & 0x7);
	uint64_t   req_num = 0ULL;
	

	req_num = ( (1ULL << 63) |
				(mval << 48) |
				(mval << 32) |
				(mval << 24) |
				(mval << 16) |
				(mval << 8) |
				(0x10) );

	cvmx_write_csr(CVMX_ADD_IO_SEG(0x00011F00000085B0), req_num);
}







int
octdev_get_device_id(void)
{
	return oct->dev_id;
}


int
octdev_max_dma_localptrs(void)
{
	return oct->max_lptrs;
}


int
octdev_max_dma_remoteptrs(void)
{
	return oct->max_rptrs;
}

int
octdev_max_dma_sumptrs(void)
{
	return oct->max_dma_ptrs;
}

int
octdev_get_state(void)
{
	return oct->state;
}

int
octdev_get_pko_state(void)
{
	return oct->pko_state;
}

#ifdef CN56XX_PEER_TO_PEER
int
octdev_get_max_peers(void)
{
	return oct->max_peers;
}
#endif



/* Do not use this function within any application. This is kept here for
   test purposes only.
*/
void octdev_force_state_to_ready(void)
{
	oct->state = CVM_DRV_READY;
}

/* $Id$ */
