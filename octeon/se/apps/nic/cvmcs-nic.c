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

#include <stdio.h>
#include <string.h>
#include <math.h>

#include "cvmcs-nic.h"
#include  <cvmx-atomic.h>
#include "cvmx-helper.h"
#include "cvmx-helper-board.h"
#include "cvmx-helper-bgx.h"
#include "cvmx-helper-sfp.h"
#include "cvmx-helper-fdt.h"
#include <asm/arch/seapi_public.h>
#include "cvmx-mdio.h"
#include "cvmx-gpio.h"
#include "cvmx-rwlock.h"
#include "cvmcs-nic.h"
#include "cvm-pci-loadstore.h"
#include "cvm-nic-ipsec.h"
#include "cvmcs-nic-rss.h"
#include "cvmcs-nic-mdata.h"
#include "cvmcs-nic-flash.h"
#include "cvmcs-dcb.h"
#include "cvmcs-nic-component.h"

#include "cvmcs-nic-hybrid.h"


/* Indicates what features are advertised by the interface. */
#define ADVERTISED_10baseT_Half     (1 << 0)
#define ADVERTISED_10baseT_Full     (1 << 1)
#define ADVERTISED_100baseT_Half    (1 << 2)
#define ADVERTISED_100baseT_Full    (1 << 3)
#define ADVERTISED_1000baseT_Half   (1 << 4)
#define ADVERTISED_1000baseT_Full   (1 << 5)
#define ADVERTISED_Autoneg          (1 << 6)
#define ADVERTISED_10000baseT_Full  (1 << 12)
#define ADVERTISED_Pause            (1 << 13)
#define ADVERTISED_Asym_Pause       (1 << 14)

#define LIQUIDIO_FW_PACKAGE    ""

#define LIQUIDIO_FW_VERSION  LIQUIDIO_FW_PACKAGE LIQUIDIO_VERSION

#define SFP_TX_ENABLE(sfp)  cvmx_fdt_gpio_set((sfp)->tx_disable, 0)
#define SFP_TX_DISABLE(sfp) cvmx_fdt_gpio_set((sfp)->tx_disable, 1)

extern uint32_t core_id;
extern CVMX_SHARED uint16_t fw_dmac_filter;
extern CVMX_SHARED int nic_verbose;
extern CVMX_SHARED uint32_t num_cores;
extern CVMX_SHARED uint64_t cpu_freq;
extern CVMX_SHARED uint64_t secs_from_boot;

extern CVMX_SHARED int intmod_enable;
extern CVMX_SHARED uint64_t intrmod_maxpkt_ratethr;
extern CVMX_SHARED uint64_t intrmod_minpkt_ratethr;
extern CVMX_SHARED uint64_t intrmod_maxcnt_trigger;
extern CVMX_SHARED uint64_t intrmod_mincnt_trigger;
extern CVMX_SHARED uint64_t intrmod_maxtmr_trigger;
extern CVMX_SHARED uint64_t intrmod_mintmr_trigger;
extern CVMX_SHARED uint64_t intrmod_check_intrvl;
extern CVMX_SHARED cvm_per_core_stats_t *per_core_stats;

CVMX_SHARED uint32_t cvm_first_buf_size_after_skip;
CVMX_SHARED uint32_t cvm_subs_buf_size_after_skip;
CVMX_SHARED oq_mon_status_t *oq_status;
CVMX_SHARED uint8_t *dq_flush_in_progress;
extern CVMX_SHARED uint16_t setup_ctl_bufs;
extern __uint32_t __log2(__uint32_t);
extern int cvmcs_uboot_request_get(int ifidx, char *envariable, uint32_t *val);
extern int cvmcs_uboot_request_set(int ifidx, char *envariable, char *sval, uint32_t *val);
extern int cvmx_sfp_avsp5410_mod_abs_changed(struct cvmx_fdt_sfp_info *sfp_info, int val, void *data);
extern int uboot_seapi_init_handle(struct cvmx_seapi_handle *handle);

CVMX_SHARED const gmx_conf_t def_66xx_conf = {
	.num_gmx_ports = 2,
	.max_nic_ports = MAX_OCTEON_NIC_PORTS,
	.ipd_ports[0] = 0,
	.ipd_ports[1] = 16,
};

CVMX_SHARED const gmx_conf_t def_68xx_conf = {
	.num_gmx_ports = 4,
	.max_nic_ports = MAX_OCTEON_NIC_PORTS,
	.ipd_ports[0] = 0xB40,
	.ipd_ports[1] = 0xC40,
	.ipd_ports[2] = 0x840,
	.ipd_ports[3] = 0x940,
};

CVMX_SHARED const gmx_conf_t sword_fish_2port_68xx_conf = {
	.num_gmx_ports = 2,
	.max_nic_ports = MAX_OCTEON_NIC_PORTS,
	.ipd_ports[0] = 0x940,
	.ipd_ports[1] = 0x840,
};

CVMX_SHARED const gmx_conf_t sword_fish_4port_68xx_conf = {
	.num_gmx_ports = 4,
	.max_nic_ports = MAX_OCTEON_NIC_PORTS,
	.ipd_ports[0] = 0xC40,
	.ipd_ports[1] = 0xB40,
	.ipd_ports[2] = 0x940,
	.ipd_ports[3] = 0x840,
};

//LIO driver will only support 2 XAUI interfaces
//connected to QLM4 and QLM6 on 78xx EVB
CVMX_SHARED const gmx_conf_t def_78xx_conf = {
	.num_gmx_ports = 2,
	.max_nic_ports = MAX_OCTEON_NIC_PORTS,
	//TODO
	.ipd_ports[0] = 0xA00,
	.ipd_ports[1] = 0xC00,
};

CVMX_SHARED const gmx_conf_t def_73xx_conf = {
	.num_gmx_ports = 2,
	.max_nic_ports = MAX_OCTEON_NIC_PORTS,
	//TODO
	.ipd_ports[0] = 0xA00,
	.ipd_ports[1] = 0xA10,
};

CVMX_SHARED const gmx_conf_t def_nic225e_conf = {
	.num_gmx_ports = 2,
	.max_nic_ports = MAX_OCTEON_NIC_PORTS,
	//TODO
	.ipd_ports[0] = 0x800,
	.ipd_ports[1] = 0x900,
};

void cvmcs_nic_pf_send_link_status(int ifidx);
void cvmcs_nic_vf_send_link_status(int ifidx);
static void cvmcs_nic_sgmii_link_autoneg_on(union oct_link_status *host, int port);
static void cvmcs_nic_sgmii_link_autoneg_off(union oct_link_status *host,
					     int port);
static int cvmcs_nic_init_dpi_bp(int port);
static void cvmcs_nic_set_flow_ctl(int port, int rx_pause, int tx_pause);
static void cvmcs_clear_bgx_ber(gmx_port_info_t *info);

int cvmcs_nic_uboot_ctl_delay(int ifidx);

/* Toggle PHY operation
 * status is 0 - PHY is OFF(powered-down)
 * status is 1 - PHY is ON(normal operation)
 */
static void cvmcs_nic_link_set_phy_power(int phy_addr, int status)
{
	cvmx_mdio_phy_reg_control_t reg_control;
	reg_control.u16 =
	    cvmx_mdio_read(phy_addr >> 8, phy_addr & 0xff,
			   CVMX_MDIO_PHY_REG_CONTROL);
	reg_control.s.power_down = ~status;
	cvmx_mdio_write(phy_addr >> 8, phy_addr & 0xff,
			CVMX_MDIO_PHY_REG_CONTROL, reg_control.u16);
}

void cvmcs_nic_link_set_phy_mru(int phy_addr, int mtu, int idx)
{
	uint16_t val;
	/* read PHY id 1 */
	val = cvmx_mdio_read(phy_addr >> 8, phy_addr & 0xff, 2);

	if (val != 0x141) {
		/* Not a MVL phy */
		return;
	}
	/* From Marvell 88E1680 Datasheet:
	 * Table 171/172(pg 16, reg 0/1): LinkCrypt and PTP Read/WriteAddress - 16bits
	 * Table 173/174(pg 16, reg 2/3): LinkCrypt and PTP DataLo/Hi - 16+16 = 32bits
	 * Table 190 and 191 EDL and PTP address for Wire and Sys MAC:
	 * 0x40/0x50, 0x840/0x850, 0x1040/0x1050, 0x1840/0x1850
	 */

	/* set to page 16 by writing to register 22 */
	cvmx_mdio_write(phy_addr >> 8, phy_addr & 0xff, 22, 16);
	/* write the address of Wire MAC */
	cvmx_mdio_write(phy_addr >> 8, phy_addr & 0xff, 1, (idx << 11) | 0x40);
	/* set MRU */
	cvmx_mdio_write(phy_addr >> 8, phy_addr & 0xff, 2, (mtu << 2) | 1);
	cvmx_mdio_write(phy_addr >> 8, phy_addr & 0xff, 3, 0);

	/* write the address of System MAC */
	cvmx_mdio_write(phy_addr >> 8, phy_addr & 0xff, 1, (idx << 11) | 0x50);
	/* set MRU at 10000 */
	cvmx_mdio_write(phy_addr >> 8, phy_addr & 0xff, 2, (mtu << 2) | 1);
	cvmx_mdio_write(phy_addr >> 8, phy_addr & 0xff, 3, 0);
	/* set back to page 0 */
	cvmx_mdio_write(phy_addr >> 8, phy_addr & 0xff, 22, 0);
}

/** Function to return link status when autonegotiation is on and is in mac mode
 **/
cvmx_helper_link_info_t cvmcs_get_link_status_autoneg_on(int ipd_port)
{
	union cvmx_pcsx_mrx_control_reg pcsx_mrx_control_reg;
	union cvmx_pcsx_anx_results_reg pcsx_anx_results_reg;

	int interface = INTERFACE(ipd_port);
	int index = INDEX(ipd_port);
	int speed = 1000;

	cvmx_helper_link_info_t result;
	result.u64 = 0;

	pcsx_mrx_control_reg.u64 =
	    cvmx_read_csr(CVMX_PCSX_MRX_CONTROL_REG(index, interface));
	if (pcsx_mrx_control_reg.s.loopbck1) {
		/* Force 1Gbps full duplex link for internal loopback */
		result.s.link_up = 1;
		result.s.full_duplex = 1;
		result.s.speed = speed;
		return result;
	}

	/* Read the autoneg results */
	pcsx_anx_results_reg.u64 =
	    cvmx_read_csr(CVMX_PCSX_ANX_RESULTS_REG(index, interface));

	if (pcsx_anx_results_reg.s.an_cpt) {
		/* Auto negotiation is complete. Set status accordingly.else speed=0,duplex=0 returned */
		result.s.full_duplex = pcsx_anx_results_reg.s.dup;
		result.s.link_up = pcsx_anx_results_reg.s.link_ok;

		switch (pcsx_anx_results_reg.s.spd) {
		case 0:
			result.s.speed = speed / 100;
			break;
		case 1:
			result.s.speed = speed / 10;
			break;
		case 2:
			result.s.speed = speed;
			break;
		default:
			result.s.speed = 0;
			result.s.link_up = 0;
			break;
		}
	}

	return result;
}

/* Taken from cvmx_helper_board_link_set_phy */
int cvmcs_board_link_set_phy(int phy_addr,
			     cvmx_helper_board_set_phy_link_flags_types_t
			     link_flags, cvmx_helper_link_info_t link_info)
{

	/* Set the flow control settings based on link_flags */
	if ((link_flags & set_phy_link_flags_flow_control_mask) !=
	    set_phy_link_flags_flow_control_dont_touch) {
		cvmx_mdio_phy_reg_autoneg_adver_t reg_autoneg_adver;
		reg_autoneg_adver.u16 =
		    cvmx_mdio_read(phy_addr >> 8, phy_addr & 0xff,
				   CVMX_MDIO_PHY_REG_AUTONEG_ADVER);
		reg_autoneg_adver.s.asymmetric_pause =
		    (link_flags & set_phy_link_flags_flow_control_mask) ==
		    set_phy_link_flags_flow_control_enable;
		reg_autoneg_adver.s.pause =
		    (link_flags & set_phy_link_flags_flow_control_mask) ==
		    set_phy_link_flags_flow_control_enable;
		cvmx_mdio_write(phy_addr >> 8, phy_addr & 0xff,
				CVMX_MDIO_PHY_REG_AUTONEG_ADVER,
				reg_autoneg_adver.u16);
	}

	/* If speed isn't set and autoneg is on advertise all supported modes */
	if ((link_flags & set_phy_link_flags_autoneg)
	    && (link_info.s.speed == 0)) {
		cvmx_mdio_phy_reg_control_t reg_control;
		cvmx_mdio_phy_reg_status_t reg_status;
		cvmx_mdio_phy_reg_autoneg_adver_t reg_autoneg_adver;
		cvmx_mdio_phy_reg_extended_status_t reg_extended_status;
		cvmx_mdio_phy_reg_control_1000_t reg_control_1000;

		reg_status.u16 =
		    cvmx_mdio_read(phy_addr >> 8, phy_addr & 0xff,
				   CVMX_MDIO_PHY_REG_STATUS);
		reg_autoneg_adver.u16 =
		    cvmx_mdio_read(phy_addr >> 8, phy_addr & 0xff,
				   CVMX_MDIO_PHY_REG_AUTONEG_ADVER);
		reg_autoneg_adver.s.advert_100base_t4 =
		    reg_status.s.capable_100base_t4;
		reg_autoneg_adver.s.advert_10base_tx_full =
		    reg_status.s.capable_10_full;
		reg_autoneg_adver.s.advert_10base_tx_half =
		    reg_status.s.capable_10_half;
		reg_autoneg_adver.s.advert_100base_tx_full =
		    reg_status.s.capable_100base_x_full;
		reg_autoneg_adver.s.advert_100base_tx_half =
		    reg_status.s.capable_100base_x_half;
		cvmx_mdio_write(phy_addr >> 8, phy_addr & 0xff,
				CVMX_MDIO_PHY_REG_AUTONEG_ADVER,
				reg_autoneg_adver.u16);
		if (reg_status.s.capable_extended_status) {
			reg_extended_status.u16 =
			    cvmx_mdio_read(phy_addr >> 8, phy_addr & 0xff,
					   CVMX_MDIO_PHY_REG_EXTENDED_STATUS);
			reg_control_1000.u16 =
			    cvmx_mdio_read(phy_addr >> 8, phy_addr & 0xff,
					   CVMX_MDIO_PHY_REG_CONTROL_1000);
			reg_control_1000.s.advert_1000base_t_full =
			    reg_extended_status.s.capable_1000base_t_full;
			reg_control_1000.s.advert_1000base_t_half =
			    reg_extended_status.s.capable_1000base_t_half;
			cvmx_mdio_write(phy_addr >> 8, phy_addr & 0xff,
					CVMX_MDIO_PHY_REG_CONTROL_1000,
					reg_control_1000.u16);
		}
		reg_control.u16 =
		    cvmx_mdio_read(phy_addr >> 8, phy_addr & 0xff,
				   CVMX_MDIO_PHY_REG_CONTROL);
		reg_control.s.autoneg_enable = 1;
		reg_control.s.restart_autoneg = 1;
		cvmx_mdio_write(phy_addr >> 8, phy_addr & 0xff,
				CVMX_MDIO_PHY_REG_CONTROL, reg_control.u16);
	} else if ((link_flags & set_phy_link_flags_autoneg)) {
		cvmx_mdio_phy_reg_control_t reg_control;
		cvmx_mdio_phy_reg_status_t reg_status;
		cvmx_mdio_phy_reg_autoneg_adver_t reg_autoneg_adver;
		cvmx_mdio_phy_reg_control_1000_t reg_control_1000;

		reg_status.u16 =
		    cvmx_mdio_read(phy_addr >> 8, phy_addr & 0xff,
				   CVMX_MDIO_PHY_REG_STATUS);
		reg_autoneg_adver.u16 =
		    cvmx_mdio_read(phy_addr >> 8, phy_addr & 0xff,
				   CVMX_MDIO_PHY_REG_AUTONEG_ADVER);
		reg_autoneg_adver.s.advert_100base_t4 = 0;
		reg_autoneg_adver.s.advert_10base_tx_full = 0;
		reg_autoneg_adver.s.advert_10base_tx_half = 0;
		reg_autoneg_adver.s.advert_100base_tx_full = 0;
		reg_autoneg_adver.s.advert_100base_tx_half = 0;
		if (reg_status.s.capable_extended_status) {
			reg_control_1000.u16 =
			    cvmx_mdio_read(phy_addr >> 8, phy_addr & 0xff,
					   CVMX_MDIO_PHY_REG_CONTROL_1000);
			reg_control_1000.s.advert_1000base_t_full = 0;
			reg_control_1000.s.advert_1000base_t_half = 0;
		}
		if (link_info.s.speed & ADVERTISED_10baseT_Half) {
			DBG2("Speed: 10base_tx_half ");
			reg_autoneg_adver.s.advert_10base_tx_half = 1;
		}

		if (link_info.s.speed & ADVERTISED_10baseT_Full) {
			DBG2("Speed: 10base_tx_full ");
			reg_autoneg_adver.s.advert_10base_tx_full = 1;
		}

		if (link_info.s.speed & ADVERTISED_100baseT_Half) {
			DBG2("Speed: 100base_tx_half ");
			reg_autoneg_adver.s.advert_100base_tx_half = 1;
		}

		if (link_info.s.speed & ADVERTISED_100baseT_Full) {
			DBG2("Speed: 100base_tx_full ");
			reg_autoneg_adver.s.advert_100base_tx_full = 1;
		}

		if (link_info.s.speed & ADVERTISED_1000baseT_Half) {
			DBG2("Speed: 1000base_tx_half ");
			reg_control_1000.s.advert_1000base_t_half = 1;
		}

		if (link_info.s.speed & ADVERTISED_1000baseT_Full) {
			DBG2("Speed: 1000base_tx_full ");
			reg_control_1000.s.advert_1000base_t_full = 1;
		}
		DBG2("\n");

		cvmx_mdio_write(phy_addr >> 8, phy_addr & 0xff,
				CVMX_MDIO_PHY_REG_AUTONEG_ADVER,
				reg_autoneg_adver.u16);
		if (reg_status.s.capable_extended_status)
			cvmx_mdio_write(phy_addr >> 8, phy_addr & 0xff,
					CVMX_MDIO_PHY_REG_CONTROL_1000,
					reg_control_1000.u16);
		reg_control.u16 =
		    cvmx_mdio_read(phy_addr >> 8, phy_addr & 0xff,
				   CVMX_MDIO_PHY_REG_CONTROL);
		reg_control.s.autoneg_enable = 1;
		reg_control.s.restart_autoneg = 1;
		cvmx_mdio_write(phy_addr >> 8, phy_addr & 0xff,
				CVMX_MDIO_PHY_REG_CONTROL, reg_control.u16);
	} else {
		cvmx_mdio_phy_reg_control_t reg_control;
		reg_control.u16 =
		    cvmx_mdio_read(phy_addr >> 8, phy_addr & 0xff,
				   CVMX_MDIO_PHY_REG_CONTROL);
		reg_control.s.autoneg_enable = 0;
		reg_control.s.restart_autoneg = 1;
		reg_control.s.duplex = link_info.s.full_duplex;
		if (link_info.s.speed == 1000) {
			reg_control.s.speed_msb = 1;
			reg_control.s.speed_lsb = 0;
		} else if (link_info.s.speed == 100) {
			reg_control.s.speed_msb = 0;
			reg_control.s.speed_lsb = 1;
		} else if (link_info.s.speed == 10) {
			reg_control.s.speed_msb = 0;
			reg_control.s.speed_lsb = 0;
		}
		cvmx_mdio_write(phy_addr >> 8, phy_addr & 0xff,
				CVMX_MDIO_PHY_REG_CONTROL, reg_control.u16);
	}
	return 0;
}

int cvmcs_nic_change_phy_settings(union oct_link_status *host, int ipd_port)
{
	cvmx_phy_info_t phy_info;
	cvmx_helper_link_info_t link;
	cvmx_helper_board_set_phy_link_flags_types_t link_flags = 0;

	link.u64 = 0;
	link.s.speed = host->s.speed;
	link.s.full_duplex = host->s.duplex;

	if (cvmx_helper_board_get_phy_info(&phy_info, ipd_port) < 0) {
		printf("Couldnt get info about PHY\n");
		return -1;
	}

	if (phy_info.phy_addr < 0) {
		printf("%s: PHY address invalid for port %d\n", __func__,
		       ipd_port);
		return -1;
	}

#ifdef PHYTYPE_PRINT

	switch (phy_info.phy_type) {
	case VITESSE_GENERIC_PHY:
		DBG2("VITESSE PHY\n");
		break;

	case CORTINA_PHY:
		DBG2("CORTINA PHY\n");
		break;

	case BROADCOM_GENERIC_PHY:
		DBG2("BROADCOM PHY\n");
		break;

	case MARVELL_GENERIC_PHY:
		DBG2("MARVELL PHY\n");
		break;

	case GENERIC_8023_C22_PHY:
		DBG2("GENERIC_802.3_c22 PHY\n");
		break;

	default:
		DBG2("Unknown PHY\n");

	}
#endif

	cvmcs_nic_link_set_phy_power(phy_info.phy_addr, host->s.link_up);

	if (host->s.autoneg)
		link_flags |= set_phy_link_flags_autoneg;

	/* Never pass pause frames to the host */
	if (host->s.pause)
		link_flags |= set_phy_link_flags_flow_control_enable;
	else
		link_flags |= set_phy_link_flags_flow_control_disable;

	if (OCTEON_IS_OCTEON3())
		cvmx_helper_board_link_set_phy(phy_info.phy_addr, link_flags, link);
	else
		cvmcs_board_link_set_phy(phy_info.phy_addr, link_flags, link);

	return 0;
}

int cvmcs_nic_sfp_mod_info(cvmx_wqe_t * wqe)
{
	cvm_pci_dma_cmd_t cmd;
	cvmx_buf_ptr_t lptr;
	cvmx_buf_ptr_pki_t *bls; /* pki buffer link structure for Octeon III */
	cvm_dma_remote_ptr_t rptr;
	cvmx_raw_inst_front_t *f;
	uint64_t *buf;
	int ifidx = 0;
    	struct cvmx_fdt_sfp_info *sfp_info;
    	int ipd_port, index, iface;

	cmd.u64 = 0;
	lptr.u64 = 0;
	bls = (cvmx_buf_ptr_pki_t *)&lptr;

	if (octeon_has_feature(OCTEON_FEATURE_CN78XX_WQE))
		f = (cvmx_raw_inst_front_t *) cvmx_phys_to_ptr(cvmx_wqe_get_pki_pkt_ptr(wqe).addr);
	else
		f = (cvmx_raw_inst_front_t *)wqe->packet_data;


	ifidx = get_vnic_port_id(cvmx_wqe_get_port(wqe));
	cmd.s.pcielport = f->rdp.s.pcie_port;
	rptr.s.addr = f->rptr;
	rptr.s.size = f->rdp.s.rlen;

	if (cvmx_unlikely(rptr.s.size > CVMX_FPA_PACKET_POOL_SIZE)) {
		printf("[ DRV ] Cannot use packet pool buf for sending link info\n");
		return 1;
	}

	/* Re-use the packet pool buffer to send the link info to host. */
	buf = (uint64_t *) cvmx_phys_to_ptr(wqe->packet_ptr.s.addr);

	/* Reset all bytes so that unused fields don't have any value. */
	memset(buf, 0, rptr.s.size);

	ipd_port = octnic->port[ifidx].linfo.gmxport;
	index = cvmx_helper_get_interface_index_num(ipd_port);
	iface = cvmx_helper_get_interface_num(ipd_port);

	sfp_info = cvmx_helper_cfg_get_sfp_info(iface, index);

	if (!sfp_info || cvmx_sfp_read_i2c_eeprom(sfp_info, (uint8_t *)&buf[1])) {
		if (OCTEON_IS_MODEL(OCTEON_CN73XX))
			cvm_pci_pvf_mem_writell(rptr.s.addr + 8, 1, cvm_pcie_pvf_num(wqe));
		else
			cvm_pci_mem_writell(rptr.s.addr + 8, 1);

		return -1;
	}

	if (octeon_has_feature(OCTEON_FEATURE_CN78XX_WQE)) {
		bls->size = rptr.s.size;
		bls->addr = CVM_DRV_GET_PHYS(buf);
		bls->packet_outside_wqe = 0;
	} else {
		lptr.s.size = rptr.s.size;
		lptr.s.addr = CVM_DRV_GET_PHYS(buf);
		lptr.s.i    = 1;
		lptr.s.pool = CVMX_FPA_PACKET_POOL;
		lptr.s.back = wqe->packet_ptr.s.back;
		cvm_update_bp(wqe);
		cvmx_wqe_free(wqe);
	}

	cmd.s.nl = cmd.s.nr = 1;

	if (OCTEON_IS_OCTEON3())
		return cvm_pci_dma_send_data_o3(&cmd, bls, &rptr, wqe, 1);
	else
		return cvm_pci_dma_send_data(&cmd, &lptr, &rptr);
}

/**
 * Function called whenever mod_abs/mod_prs has changed for Avago AVSP5410
 *
 * @param       sfp     pointer to SFP data structure
 * @param       val     1 if absent, 0 if present, otherwise not set
 * @param       data    user-defined data
 *
 * @return      0 for success, -1 on error
*/
int cvmcs_nic_sfp_avsp5410_mod_abs_changed(struct cvmx_fdt_sfp_info *sfp,
					  int val, void *data)
{
	bool reinit_required = TRUE;
	int iterations = 0;
	int dfe_timeout_los_retries = 0;
	int dfe_sig_chk_retries = 0;
	uint i;
    	int err, index, iface;
	uint64_t flags;
	cvmx_ciu_wdogx_t wdog;
	gmx_port_info_t *gmx_info = (gmx_port_info_t *)data;
	struct cvmx_avsp5410 *avsp5410;
	struct cvmx_seapi_handle handle;
	const struct cvmx_sfp_mod_info *mod_info = cvmx_phy_get_sfp_mod_info(sfp);

        if (uboot_seapi_init_handle(&handle))
		return -1;

	index = cvmx_helper_get_interface_index_num(gmx_info->ipd_port);
	iface = cvmx_helper_get_interface_num(gmx_info->ipd_port);

	avsp5410 = cvmx_helper_cfg_get_avsp5410_info(iface, index);

	for (i = 0; i < num_cores; i++) {
		cvmx_write_csr(CVMX_CIU_PP_POKEX(i), 1);
		cvmx_write_csr(CVMX_CIU_WDOGX(i), 0);
	}

	if (val) {
		/* SEAPI call to turn off tx of mod side serdes because
		   SFP module is absent. */
		flags = CVMX_SW_SELFHEAL_MOD_ABSENT;
		err = handle.syscall(handle.sig_paddr, CVMX_SEAPI_SW_HEAL, 0,
			      CVMX_BOARD_TYPE_NIC225E, iface,
			      cvmx_helper_interface_get_mode(
                               cvmx_helper_node_interface_to_xiface(
                               cvmx_get_node_num(), iface)), flags,
			       cvmx_ptr_to_phys2(&avsp5410->prev_temp));
		goto the_end;
	}

	/* SEAPI call to uboot_garnet_mod_config() */
	flags = CVMX_SW_SELFHEAL_MOD_CONFIG;
	if (mod_info->active_cable)
		flags |= CVMX_SW_SELFHEAL_ACTIVE_CABLE;
	err = handle.syscall(handle.sig_paddr, CVMX_SEAPI_SW_HEAL, 0,
			      CVMX_BOARD_TYPE_NIC225E, iface,
			      cvmx_helper_interface_get_mode(
                               cvmx_helper_node_interface_to_xiface(
                               cvmx_get_node_num(), iface)), flags,
			       cvmx_ptr_to_phys2(&avsp5410->prev_temp));
	if (err)
		goto the_end;

	/* This while loop is similar to the while loop in
	   uboot_garnet_mod_tuning(). */
	while (1) {
		iterations++;

		/* This for loop doesn't exist in uboot_garnet_mod_tuning().
		   It's here in SE to prevent starvation of non-self-healing
		   SEAPI calls. */
		for (i = 0; i < 2; i++) {
			int pf_ifidx;
			pf_ifidx = OCT_NIC_PORT_IDX(i, 0);
			if (octnic->port[pf_ifidx].state.present)
				cvmcs_nic_uboot_ctl_delay(pf_ifidx);
		}

		if (iterations > 2) {
			/* SEAPI call to avsp_5410_init_ok() */
			flags = CVMX_SW_SELFHEAL_INIT_OK;
			err = handle.syscall(handle.sig_paddr, CVMX_SEAPI_SW_HEAL, 0,
			      CVMX_BOARD_TYPE_NIC225E, iface,
			      cvmx_helper_interface_get_mode(
                               cvmx_helper_node_interface_to_xiface(
                               cvmx_get_node_num(), iface)), flags,
			       cvmx_ptr_to_phys2(&avsp5410->prev_temp));

			if (!err) {
				err = -1;
				break;
			}
		}

		/* SEAPI call to sw_self_healing_ei_debounce() */
		flags = CVMX_SW_SELFHEAL_EI_DEBOUNCE;
		err = handle.syscall(handle.sig_paddr, CVMX_SEAPI_SW_HEAL, 0,
			      CVMX_BOARD_TYPE_NIC225E, iface,
			      cvmx_helper_interface_get_mode(
                               cvmx_helper_node_interface_to_xiface(
                               cvmx_get_node_num(), iface)), flags,
			       cvmx_ptr_to_phys2(&avsp5410->prev_temp));
		if (!err) {
			err = -1;
			break;
		}

		/* SEAPI call to sw_self_healing_force_heal_mod() */
		flags = CVMX_SW_SELFHEAL_FORCE_HEAL_MOD;
		err = handle.syscall(handle.sig_paddr, CVMX_SEAPI_SW_HEAL, 0,
			      CVMX_BOARD_TYPE_NIC225E, iface,
			      cvmx_helper_interface_get_mode(
                               cvmx_helper_node_interface_to_xiface(
                               cvmx_get_node_num(), iface)), flags,
			       cvmx_ptr_to_phys2(&avsp5410->prev_temp));
		switch (err) {
		case 0:
			reinit_required = FALSE;
			break;

		case 1:
			if (dfe_timeout_los_retries++ < 20)
				continue;
			break;

		case 2:
			if (dfe_timeout_los_retries++ < 20)
				continue;
			break;

		case 3:
			if (dfe_sig_chk_retries++ < 3)
				continue;
			break;

		default:
			break;
		}

		if (reinit_required) {
			/* SEAPI call to uboot_garnet_reinit() */
			flags = CVMX_SW_SELFHEAL_REINIT;
			handle.syscall(handle.sig_paddr, CVMX_SEAPI_SW_HEAL, 0,
			      CVMX_BOARD_TYPE_NIC225E, iface,
			      cvmx_helper_interface_get_mode(
                               cvmx_helper_node_interface_to_xiface(
                               cvmx_get_node_num(), iface)), flags,
			       cvmx_ptr_to_phys2(&avsp5410->prev_temp));
		}

		break;
	}

the_end:
	avsp5410->prev_temp_mins = ((cvmx_get_cycle() / cpu_freq) / 60);

	wdog.u64 = 0;
	wdog.s.mode = 1;
	wdog.s.len  = 65535;

	for (i = 0; i < num_cores; i++) {
		cvmx_write_csr(CVMX_CIU_WDOGX(i), wdog.u64);
		cvmx_write_csr(CVMX_CIU_PP_POKEX(i), 1);
	}

	if (err)
		DBG2("%s: SW Selfhealing failed\n", __func__);

	return err;
}

/* copied from U-Boot nic225e_board.c */
static int nic225e_mod_tuning_required(int ipd_port)
{
	cvmx_helper_link_info_t link;
	cvmx_bgxx_spux_status1_t spu_status1;
	cvmx_bgxx_smux_tx_ctl_t smu_tx_ctl;
	cvmx_bgxx_smux_rx_ctl_t smu_rx_ctl;
	int index, iface;

	index = cvmx_helper_get_interface_index_num(ipd_port);
	iface = cvmx_helper_get_interface_num(ipd_port);

	link = cvmx_helper_link_get(ipd_port);

	if (link.s.link_up)
		return 0;

	if (!link.s.init_success)
		return 1;

	spu_status1.u64 = cvmx_read_csr(CVMX_BGXX_SPUX_STATUS1(index, iface));
	smu_tx_ctl.u64 = cvmx_read_csr(CVMX_BGXX_SMUX_TX_CTL(index, iface));
	smu_rx_ctl.u64 = cvmx_read_csr(CVMX_BGXX_SMUX_RX_CTL(index, iface));

	if ((spu_status1.s.rcv_lnk == 0) ||
	    (smu_rx_ctl.s.status == 1) ||
	    (smu_tx_ctl.s.ls == 1))
		return 1;

	return 0;
}

int cvmcs_nic_phy_check(int gmxport_id)
{
    int ipd_port, index, iface, val, err = 0;
    struct cvmx_fdt_sfp_info *sfp_info;
    const struct cvmx_sfp_mod_info *mod_info;
    gmx_port_info_t *gmx_info = &octnic->gmx_port_info[gmxport_id];

	ipd_port = gmx_info->ipd_port;
	index = cvmx_helper_get_interface_index_num(ipd_port);
	iface = cvmx_helper_get_interface_num(ipd_port);

	DBG2("%s: port = 0x%x\n", __func__, ipd_port);

	if (!cvmx_helper_cfg_get_avsp5410_info(iface, index)) {
		/* this is not a nic225e card, so get out */
		return 0;
	}

	DBG2("%s: Phy avsp5410 for 0x%x:%d\n", __func__, iface, index);

	sfp_info = cvmx_helper_cfg_get_sfp_info(iface, index);
	if (!sfp_info) {
		DBG2("%s: No SFP associated with 0x%x:%d\n",
		     __func__, iface, index);
		return -1;
	}	

	val = cvmx_sfp_check_mod_abs(sfp_info, NULL);
	if (val < 0) {
		DBG2("%s: SFP check mod failed for 0x%x:%d\n",
		     __func__, iface, index);
		return -1;
	}

	if (!gmx_info->sfp_mod_present && val) {
		return -1;
	}

	if (val) {
		DBG2("%s: SFP module not present for 0x%x:%d\n",
		     __func__, iface, index);
		err = cvmcs_nic_sfp_avsp5410_mod_abs_changed(sfp_info, 1, gmx_info);
		gmx_info->sfp_mod_present = 0;
		return (val | err);
	}

	if (gmx_info->sfp_mod_present) {

		DBG2("%s: SFP module already present for 0x%x:%d\n",
		     __func__, iface, index);

	} else {
		cvmx_wait_usec(100000);

		val = cvmx_sfp_check_mod_abs(sfp_info, NULL);
		if (val < 0) {
			DBG2("%s: SFP check mod failed for 0x%x:%d\n",
			     __func__, iface, index);
			return -1;
		}

		if (val) {
			return -1;
		}
	}

	DBG2("%s: SFP module detected for 0x%x:%d\n",
		     __func__, iface, index);
		
	gmx_info->sfp_mod_present = 1;

	SFP_TX_ENABLE(sfp_info);

	mod_info = cvmx_phy_get_sfp_mod_info(sfp_info);

	if (mod_info->los_implemented) {
		int rx_los = cvmx_sfp_check_rx_los(sfp_info, NULL);
		if (mod_info->los_inverted)
			rx_los = !rx_los;
		if (rx_los) {
			DBG2("%s: rx_los set for 0x%x:%d\n",
		     		__func__, iface, index);
			gmx_info->rx_los_present = rx_los;
			return -1;
		} else {
			if (gmx_info->rx_los_present) {
				cvmx_wait_usec(100000);
				rx_los = cvmx_sfp_check_rx_los(sfp_info, NULL);
				if (mod_info->los_inverted)
					rx_los = !rx_los;
				if (rx_los) {
					return -1;
				}
			}
		}
	}
		
	if (mod_info->tx_fault_implemented) {
		int tx_fault = cvmx_sfp_check_tx_fault(sfp_info, NULL);
		if (tx_fault) {
			DBG2("%s: tx_fault set for 0x%x:%d\n",
		     		__func__, iface, index);
			gmx_info->tx_fault_present = tx_fault;
			return -1;
		} else {
			if (gmx_info->tx_fault_present) {
				cvmx_wait_usec(100000);
				tx_fault = cvmx_sfp_check_tx_fault(sfp_info, NULL);
				if (tx_fault) {
					return -1;
				}
			}
		}
	}

	err = cvmcs_nic_sfp_avsp5410_mod_abs_changed(sfp_info, 0, gmx_info);

	if (!err) {
		uint64_t octeon_debounce;

		/* 150ms debounce for confirming Octeon link up */
		octeon_debounce = cvmx_clock_get_count(CVMX_CLOCK_CORE) + 150000 *
			cvmx_clock_get_rate(CVMX_CLOCK_CORE) / 1000000;

		while (cvmx_clock_get_count(CVMX_CLOCK_CORE) < octeon_debounce) {
			if (!nic225e_mod_tuning_required(ipd_port))
				return 0; /* link is up and stable */

			cvmx_wait_usec(1000);
		}

		/* link is not stable */
		return -1;
	}

	return err;
}

int cvmcs_nic_phy_temp_check(int ifidx)
{
    uint i;
    int index, iface, err, ipd_port;
    cvmx_ciu_wdogx_t wdog;
    gmx_port_info_t *gmx_info;
    uint64_t flags, cur_mins;
    struct cvmx_fdt_sfp_info *sfp_info;
    struct cvmx_avsp5410 *avsp5410;
    struct cvmx_seapi_handle handle;

	i = octnic->port[ifidx].gmxport_id;
	gmx_info = (gmx_port_info_t *)&octnic->gmx_port_info[i];
	ipd_port = gmx_info->ipd_port;
	index = cvmx_helper_get_interface_index_num(ipd_port);
	iface = cvmx_helper_get_interface_num(ipd_port);

	avsp5410 = cvmx_helper_cfg_get_avsp5410_info(iface, index);
	if (!avsp5410)
		return 0;

	cur_mins = ((cvmx_get_cycle() / cpu_freq) / 60);

	if ((cur_mins - avsp5410->prev_temp_mins) < 5) 
		return 0;

	sfp_info = cvmx_helper_cfg_get_sfp_info(iface, index);
	if (!sfp_info) {
		DBG2("%s: No SFP associated with 0x%x:%d\n",
		     __func__, iface, index);
		return -1;
	}

        if (uboot_seapi_init_handle(&handle))
		return -1;

	index = cvmx_helper_get_interface_index_num(gmx_info->ipd_port);
	iface = cvmx_helper_get_interface_num(gmx_info->ipd_port);

	flags = CVMX_SW_SELFHEAL_TEMP_CHECK;

	/* Disable watchdog as it may take more than the quantum */
	for (i = 0; i < num_cores; i++) {
		cvmx_write_csr(CVMX_CIU_PP_POKEX(i), 1);
		cvmx_write_csr(CVMX_CIU_WDOGX(i), 0);
	}

	err = handle.syscall(handle.sig_paddr, CVMX_SEAPI_SW_HEAL, 0,
			      CVMX_BOARD_TYPE_NIC225E, iface,
			      cvmx_helper_interface_get_mode(
                               cvmx_helper_node_interface_to_xiface(
                               cvmx_get_node_num(), iface)), flags,
			       cvmx_ptr_to_phys2(&avsp5410->prev_temp));

	avsp5410->prev_temp_mins = ((cvmx_get_cycle() / cpu_freq) / 60);

	wdog.u64 = 0;
	wdog.s.mode = 1;
	wdog.s.len  = 65535;

	for (i = 0; i < num_cores; i++) {
		cvmx_write_csr(CVMX_CIU_WDOGX(i), wdog.u64);
		cvmx_write_csr(CVMX_CIU_PP_POKEX(i), 1);
	}

	if (err)
		DBG2("%s: SW Selfhealing failed\n", __func__);

	return 0;
}

int cvmcs_nic_phy_init(int gmxport_id)
{
    uint i;
    int index, iface, err, ipd_port;
    cvmx_ciu_wdogx_t wdog;
    gmx_port_info_t *gmx_info;
    uint64_t flags;
    struct cvmx_fdt_sfp_info *sfp_info;
    struct cvmx_avsp5410 *avsp5410;
    struct cvmx_seapi_handle handle;

	gmx_info = (gmx_port_info_t *)&octnic->gmx_port_info[gmxport_id];
	ipd_port = gmx_info->ipd_port;
	index = cvmx_helper_get_interface_index_num(ipd_port);
	iface = cvmx_helper_get_interface_num(ipd_port);

	avsp5410 = cvmx_helper_cfg_get_avsp5410_info(iface, index);
	if (!avsp5410)
		return 0;

	sfp_info = cvmx_helper_cfg_get_sfp_info(iface, index);
	if (!sfp_info) {
		DBG2("%s: No SFP associated with 0x%x:%d\n",
		     __func__, iface, index);
		return -1;
	}	

        if (uboot_seapi_init_handle(&handle))
		return -1;

	index = cvmx_helper_get_interface_index_num(gmx_info->ipd_port);
	iface = cvmx_helper_get_interface_num(gmx_info->ipd_port);

	flags = CVMX_SW_SELFHEAL_INIT | CVMX_SW_SELFHEAL_HOST_TUNE;

	/* Disable watchdog as it may take more than the quantum */
	for (i = 0; i < num_cores; i++) {
		cvmx_write_csr(CVMX_CIU_PP_POKEX(i), 1);
		cvmx_write_csr(CVMX_CIU_WDOGX(i), 0);
	}

	err = handle.syscall(handle.sig_paddr, CVMX_SEAPI_SW_HEAL, 0,
			      CVMX_BOARD_TYPE_NIC225E, iface,
			      cvmx_helper_interface_get_mode(
                               cvmx_helper_node_interface_to_xiface(
                               cvmx_get_node_num(), iface)), flags,
			       cvmx_ptr_to_phys2(&avsp5410->prev_temp));

	avsp5410->prev_temp_mins = ((cvmx_get_cycle() / cpu_freq) / 60);

	wdog.u64 = 0;
	wdog.s.mode = 1;
	wdog.s.len  = 65535;

	for (i = 0; i < num_cores; i++) {
		cvmx_write_csr(CVMX_CIU_WDOGX(i), wdog.u64);
		cvmx_write_csr(CVMX_CIU_PP_POKEX(i), 1);
	}

	if (err)
		DBG2("%s: SW Selfhealing failed\n", __func__);

    	return 0;
}

static void cvmcs_nic_print_link_status(union oct_link_status *st, int ifidx, int port)
{
	printf("ifidx %d Port %d: %d Mbps %s duplex %s\n", ifidx, port,
	       st->s.speed, (st->s.duplex) ? "Full" : "Half",
	       (st->s.link_up) ? "UP" : "DOWN");
}

/* Send link status info if the interface is running
 */
void cvmcs_nic_cond_send_unsolicited_link_info(union oct_link_status *st, int ifidx)
{
    uint8_t               *buf;
    union octeon_rh       *rh;
    union oct_link_status *ls;
    cvmx_buf_ptr_t         lptr;
    uint8_t oq;

    /* Don't send the updated link status when the state Rx state is
     * down because it already knows the state. The messages would just
     * accumulate on the host because the host won't be polling the output
     * queues.
     */
    if (!octnic->port[ifidx].state.rx_on) {
	DBG2("ifidx:%d Not sending NIC_INFO because interface is not up\n",
	     ifidx);
	return;
    }

    buf = (uint8_t *) cvm_drv_fpa_alloc_sync(CVMX_FPA_PACKET_POOL);
    if(buf == NULL) {
       printf("ifidx:%d Failed to alloc link_info!!!\n", ifidx);
       return;
    }

    oq = OCT_NIC_OQ_NUM(&octnic->port[ifidx], 0);

    rh = (union octeon_rh *)buf;
    ls = (union oct_link_status *)(buf + sizeof(*rh));

    rh->u64 = 0;
    rh->r_nic_info.opcode    = OPCODE_NIC;
    rh->r_nic_info.subcode   = OPCODE_NIC_INFO;
    rh->r_nic_info.gmxport   = octnic->port[ifidx].linfo.gmxport;


    memcpy(ls, st, sizeof(*st));

    lptr.u64    = 0;
    lptr.s.size = sizeof(union octeon_rh) + sizeof(*ls);
    lptr.s.addr = CVM_DRV_GET_PHYS(buf);
    lptr.s.pool = CVMX_FPA_PACKET_POOL;
    lptr.s.i    = 1;
    DBG2("ifidx:%d Sending NIC_INFO (OQ: %d link: %s st: %lx)\n",
	 ifidx, oq, ls->s.link_up ? "UP" : "DOWN",
	 (unsigned long)lptr.u64);
    CVMX_SYNCWS;

    /* Send the indication packet on the first output queue. 
     * For 73XX, we will want to send this to the control queue for the
     * particular interface.
     */
    if (cvm_send_pci_pko_direct(lptr, CVM_DIRECT_DATA, 1, lptr.s.size, oq))
	    printf("Failed to send NIC_INFO\n");
}

/** Get a free mcast ifl from the free list
 * @param head head of the free list
 * @returns pointer to an entry, else NULL
 */
static inline mcast_ifl_t *get_mcast_ifl(hash_node_t *head)
{
	mcast_ifl_t *p;
	if (!hash_list_empty(head)) {
		p = (mcast_ifl_t *)hlist_entry(head->next, mcast_ifl_t, list);
		hash_node_del(head->next);
		return p;
	}

	return NULL;
}

/** Free an mcast ifl and put it back on the free list
 * @param head head of the free list
 * @param p node to free
 */
static inline void free_mcast_ifl(hash_node_t *head, mcast_ifl_t *p)
{
	hash_node_insert_head(&p->list, head);
}

/** find a multicast ifl for a given MAC on a GMX port
 * @param gmxport_id   GMX port
 * @param mac          mcast MAC to find
 *
 * @returns mcast_ifl pointer if found, NULL otherwise
 */
inline mcast_ifl_t *find_mcast_ifl(int gmxport_id, uint64_t mac)
{
	mcast_ifl_t *entry = NULL;
	hash_node_t *head, *node;
	gmx_port_info_t *info = &octnic->gmx_port_info[gmxport_id];
	uint8_t *macptr = mac_to_ptr(&mac);

	if(info->vnic_mcast_lut == NULL) {
		return NULL;
	}

	head = &info->vnic_mcast_lut[mac_hash(macptr) & MCAST_LUT_MASK];

	hash_for_each_node(node, head) {
		entry = (mcast_ifl_t*)hlist_entry(node, mcast_ifl_t, list);
		if (entry->mcast_addr == mac) {
			return entry;
		}
	}

	return NULL;
}

void cvmcs_nic_enable_vlan_filter(int ifidx)
{
	int gmxport_id = octnic->port[ifidx].gmxport_id;
	gmx_port_info_t *info = &octnic->gmx_port_info[gmxport_id];

	if  (OCTEON_IS_MODEL(OCTEON_CN73XX)) {
		/* nothing to do here; VLAN filtering is always enabled anyway */
	} else {
		memset(&info->vlans, 0, sizeof(info->vlans));
		/* VLAN 0 Should be always allowed */
		memset(&info->vlans[0], 0xff, sizeof(info->vlans[0]));
		iflist_set_last(&info->vlans[0]);
		iflist_set_active(&info->vlans[0]);
	}
}

void cvmcs_nic_disable_vlan_filter(int ifidx)
{
	int i;
	int gmxport_id = octnic->port[ifidx].gmxport_id;
	gmx_port_info_t *info = &octnic->gmx_port_info[gmxport_id];

	memset(&info->vlans, 0xff, sizeof(info->vlans));
	for(i=0; i < MAX_VLANS; i++) {
		iflist_set_last(&info->vlans[i]);
		iflist_set_active(&info->vlans[i]);
	}
}

int cvmcs_nic_add_vlan(int ifidx, uint16_t vid)
{
	int gmxport_id = octnic->port[ifidx].gmxport_id;
	gmx_port_info_t *info = &octnic->gmx_port_info[gmxport_id];

	if (OCT_NIC_IS_VF(ifidx)) {
		if (octnic->port[ifidx].user_set_vlanTCI & 0xFFF)
			iflist_clear(&info->vnic_without_user_set_vlan, ifidx);
	}

	iflist_set(&info->vlans[vid], ifidx);
	iflist_set_last(&info->vlans[vid]);
	iflist_set_active(&info->vlans[vid]);

	return 0;
}

int cvmcs_nic_del_vlan(int ifidx, uint16_t vid)
{
	int gmxport_id = octnic->port[ifidx].gmxport_id;
	gmx_port_info_t *info = &octnic->gmx_port_info[gmxport_id];

	if (OCT_NIC_IS_VF(ifidx)) {
		if (!(octnic->port[ifidx].user_set_vlanTCI & 0xFFF))
			iflist_set(&info->vnic_without_user_set_vlan, ifidx);
	}

	iflist_clear(&info->vlans[vid], ifidx);
	iflist_set_last(&info->vlans[vid]);
	iflist_set_active(&info->vlans[vid]);

	return 0;
}

#if 0
int cvmcs_nic_find_idx_wqe(cvmx_wqe_t *wqe)
{
	if (cvmx_likely(!cvmx_wqe_get_rcv_err(wqe)))
		return cvmcs_nic_find_idx(cvmx_wqe_get_port(wqe),
				   ((uint8_t *)cvmx_phys_to_ptr(wqe->packet_ptr.s.addr) + 8),//timestamp
				   -1);

	return -1;
}
#endif

/** Core: Free a work queue entry (WQE) and its buffers received from the
 *  hardware.
 *  @param  wqe - work queue entry buffer to be freed.
 *  Frees a work queue entry and its packet data buffer.
 */
void cvm_free_wqe_wrapper(cvmx_wqe_t * wqe)
{
	if (!octeon_has_feature(OCTEON_FEATURE_PKO3))
		cvm_update_bp(wqe);
	cvm_free_host_instr(wqe);
}

void cvmcs_cond_free_wqe(cvmx_wqe_t *wqe)
{
        cvmcs_nic_metadata_t *mdata = CVMCS_NIC_METADATA(wqe);

        if (!CVMCS_NIC_METADATA_IS_DUP_WQE(mdata))
                cvm_free_wqe_wrapper(wqe);
}

/* Return an updated link status with any changes based on link state */
uint64_t cvmcs_nic_update_link_status(union oct_link_status oldlink, int
				      gmxport_id, int port)
{
	cvmx_helper_link_info_t link;
	union oct_link_status st;
	gmx_port_info_t *info = &octnic->gmx_port_info[gmxport_id];

	st.u64 = oldlink.u64;
	if (!cvmx_spinlock_trylock(&info->link_lock)) {
		link = cvmx_helper_link_autoconf(port);
		st.s.duplex = link.s.full_duplex;
		st.s.link_up = link.s.link_up;
		if (link.s.link_up && (info->link_state != LINK_UP)) {
			info->link_state = LINK_UP;
			cvmcs_clear_bgx_ber(info);
		}
		st.s.speed = link.s.speed;
		cvmx_spinlock_unlock(&info->link_lock);
	}
	return st.u64;
}

#define CVMX_READ_GMX_ADR(N)            (cvmx_read_csr(CVMX_GMXX_RXX_ADR_CAM##N(index, interface)))
#define CVMX_WRITE_GMX_ADR(N, val)      (cvmx_write_csr(CVMX_GMXX_RXX_ADR_CAM##N(index, interface), val))

void cvmcs_nic_change_ifflags_for_ifidx(int gmxport_id,
					int ifidx,
					enum octnet_ifflags flags)
{
	gmx_port_info_t *info = &octnic->gmx_port_info[gmxport_id];

	octnic->port[ifidx].state.ifflags = flags;

	if (flags & OCTNET_IFFLAG_PROMISC)
		iflist_set(&info->vnic_promisc, ifidx);
	else
		iflist_clear(&info->vnic_promisc, ifidx);
	iflist_set_last(&info->vnic_promisc);
	iflist_set_active(&info->vnic_promisc);

        if (flags & OCTNET_IFFLAG_BROADCAST)
                iflist_set(&info->vnic_bcast, ifidx);
        else
                iflist_clear(&info->vnic_bcast, ifidx);
        iflist_set_last(&info->vnic_bcast);
        iflist_set_active(&info->vnic_bcast);

	if (flags & OCTNET_IFFLAG_ALLMULTI)
		iflist_set(&info->vnic_allmulti, ifidx);
	else
		iflist_clear(&info->vnic_allmulti, ifidx);
	iflist_set_last(&info->vnic_allmulti);
	iflist_set_active(&info->vnic_allmulti);

	if (flags & OCTNET_IFFLAG_MULTICAST)
		iflist_set(&info->vnic_multi, ifidx);
	else
		iflist_clear(&info->vnic_multi, ifidx);
	iflist_set_last(&info->vnic_multi);
	iflist_set_active(&info->vnic_multi);

	/* If ANY interface is promiscuous or multicast, then make sure gmx
	 * is configured that way as well.
	 */
	if(info->vnic_promisc.active)
		flags |= OCTNET_IFFLAG_PROMISC;
	if((info->vnic_multi.active) || (info->vnic_allmulti.active))
		flags |= OCTNET_IFFLAG_ALLMULTI;

	if (octeon_has_feature(OCTEON_FEATURE_BGX)) {
		/* BGX is always in promiscuous mode because the DMAC
		 * filter has only a few entries; it cannot accomodate
		 * all the MAC addresses of the NIC73.
		 */
		cvmcs_nic_change_gmx_ifflags(gmxport_id, OCTNET_IFFLAG_PROMISC);
	} else
		cvmcs_nic_change_gmx_ifflags(gmxport_id, flags);
}

int cvmcs_nic_change_gmx_ifflags(int gmxport_id, enum octnet_ifflags flags)
{
	int port = octnic->gmx_port_info[gmxport_id].ipd_port;
	int interface = INTERFACE(port);
	int index = INDEX(port);
	uint64_t cam_flags = 0;

	if (octeon_has_feature(OCTEON_FEATURE_BGX)) {
		int i;
		int cam_reg_start, cam_reg_end;
		int node = cvmx_get_node_num();
		cvmx_bgxx_cmrx_rx_adr_ctl_t control;
		cvmx_bgxx_cmr_rx_adrx_cam_t adrx_cam;

		/* For 78xx, cvmx_helper_get_interface_num() returns xiface. 
		*  Hack to get the interface from xiface.
		*/
		interface = interface &  0xff;

		control.u64    = 0;
		control.s.bcst_accept = 1;     /* Allow broadcast MAC addresses */

		/* accept multicast packets. This is required to support IPv6. */
		if (flags & OCTNET_IFFLAG_MULTICAST ||
				(flags & OCTNET_IFFLAG_ALLMULTI))
			control.s.mcst_mode = 1;

		if (flags & OCTNET_IFFLAG_PROMISC) {
			control.s.mcst_mode = 1;  /* Allow all multicast packets when in promiscuous mode */
			control.s.cam_accept = 0; /* Reject matches if promisc. Since CAM is shut off, should accept everything */
		} else
			control.s.cam_accept = 1; /* Filter packets based on the CAM */


		cvmx_write_csr_node(node, CVMX_BGXX_CMRX_RX_ADR_CTL(index, interface), control.u64);

		cam_reg_start = 0;
		cam_reg_end = 32;
		if (flags && (flags & OCTNET_IFFLAG_PROMISC)) {
			for (i = cam_reg_start; i < cam_reg_end; i++){
				adrx_cam.u64  = cvmx_read_csr_node(node, CVMX_BGXX_CMR_RX_ADRX_CAM(i, interface));
				if (adrx_cam.s.id == index) {
					/* this cam entry's id matches port index; disable it */
					adrx_cam.s.en = 0;
					cvmx_write_csr_node(node, CVMX_BGXX_CMR_RX_ADRX_CAM(i, interface),adrx_cam.u64);
				}
			}
		} else {
			for (i = cam_reg_start; i < cam_reg_end; i++) {
				adrx_cam.u64  = cvmx_read_csr_node(node, CVMX_BGXX_CMR_RX_ADRX_CAM(i, interface));
				if (adrx_cam.s.adr) {
					if (adrx_cam.s.id == index) {
						/* this cam entry's id matches port index; enable it */
						adrx_cam.s.en = 1;
						cvmx_write_csr_node(node, CVMX_BGXX_CMR_RX_ADRX_CAM(i, interface),adrx_cam.u64);
					}
				}
			}
		}
	} else {
		cvmx_gmxx_prtx_cfg_t gmx_cfg;
		cvmx_gmxx_rxx_adr_ctl_t control;

		control.u64 = 0;
		control.s.bcst = 1;	/* Allow broadcast MAC addresses */

		if ((flags & OCTNET_IFFLAG_MULTICAST) ||
		    (flags & OCTNET_IFFLAG_ALLMULTI))
			/* accept multicast packets. This is required to support IPv6. */
			control.s.mcst = 2;

		if (flags & OCTNET_IFFLAG_PROMISC)
			control.s.cam_mode = 0;	/* Reject matches if promisc. Since CAM is shut off, should accept everything */
		else
			control.s.cam_mode = 1;	/* Filter packets based on the CAM */
		gmx_cfg.u64 = cvmx_read_csr(CVMX_GMXX_PRTX_CFG(index, interface));
		cvmx_write_csr(CVMX_GMXX_PRTX_CFG(index, interface), gmx_cfg.u64 & ~1ull);

		cvmx_write_csr(CVMX_GMXX_RXX_ADR_CTL(index, interface), control.u64);

		if (control.s.cam_mode)
			cam_flags = octnic->gmx_port_info[gmxport_id].cam_flags;

		cvmx_write_csr(CVMX_GMXX_RXX_ADR_CAM_ALL_EN(index, interface), cam_flags);
		cvmx_write_csr(CVMX_GMXX_PRTX_CFG(index, interface), gmx_cfg.u64);
	}
	return 0;
}

void cvmcs_init_mac_hash_idx_table(gmx_port_info_t *info)
{
	int j;

	for(j = 0; j < MAX_OCTEON_NIC_HASH_SIZE; j++) {
		info->hash[j].ifidx = -1;
		info->hash[j].hw_addr = 0;
	}
}

/**
 * Calculate a CRC-32 hash based on an input MAC address.
 * We may want to expand this to use VLAN as well.
 *
 * @param  mac      pointer to the beginning of mac 
 *
 */
inline int mac_hash(uint8_t *mac)
{
	int h;

	CVMX_MT_CRC_POLYNOMIAL (0x1edc6f41);
	CVMX_MT_CRC_IV (0);
	CVMX_MT_CRC_WORD (*(uint32_t *)(mac));
	CVMX_MT_CRC_BYTE(mac[4]);
	CVMX_MT_CRC_BYTE(mac[5]);
	CVMX_MF_CRC_IV (h);

	return h;
}

/**
 * Find a free index for a new mac
 *
 * @param  info     pointer to gmx port info
 * @param  mac      pointer to the beginning of mac 
 *
 * @returns index to free entry, or -1 if full
 */
static inline int cvmcs_find_free_mac_hash_idx(gmx_port_info_t *info,
					       uint64_t mac, int ifidx)
{
	int h, j, k;
	uint8_t *macptr = mac_to_ptr(&mac);

	h = mac_hash(macptr) << NIC_HASH_SHIFT;

	for(j = 0; j < MAX_OCTEON_NIC_HASH_SIZE; j++) {
		k = (h + j) & (MAX_OCTEON_NIC_HASH_SIZE - 1);
		if ((info->hash[k].ifidx == -1) ||
		    ((info->hash[k].hw_addr == mac) && (info->hash[k].ifidx == ifidx))) {
			return k;
		}
	}

	printf("%s: not found\n", __func__);

	return -1;
}

/**
 * Dump the mac address hashtable
 *
 * @param  gmxport_id   GMX port
 */
static inline void cvmcs_dump_mac_hashtable(int gmxport_id)
{
	int i;
	gmx_port_info_t *info = &octnic->gmx_port_info[gmxport_id];

	for(i = 0; i < MAX_OCTEON_NIC_HASH_SIZE; i++) {
		if (info->hash[i].ifidx != -1) {
			printf("GMX%d: [%d] %012lx ifidx=%d\n",
			       gmxport_id, i, info->hash[i].hw_addr,
			       info->hash[i].ifidx);
		}
	}
}

/**
 * Adds a mac index
 *
 * @param  info       pointer to gmx port info
 * @param  hash_idx   where to put it
 * @param  ifidx      interface index
 * @param  mac        mac address to add
 *
 * @returns 0 if successful, -1 if not.
 */
static inline int cvmcs_add_mac_hash_idx(gmx_port_info_t *info,
					 int hash_idx,
					 int ifidx,
					 uint64_t mac)
{
	if (info->hash[hash_idx].hw_addr != 0) {
		printf("Tried to add mac %012lx to entry %d which already had mac %012lx, overriding\n",
		       mac, hash_idx, info->hash[hash_idx].hw_addr);
	}

	info->hash[hash_idx].ifidx = ifidx;
	info->hash[hash_idx].hw_addr = mac;

	// Do this here just to keep ifidx as the newest VNIC.
	info->ifidx = ifidx;

	return 0;
}





/* Add a MAC address to the hash and CAM tables, but do not enable it.
 *
 * @param  ifidx         interface
 * @param  gmxport_id    GMX port
 * @param  gmx_offset    GMX offset
 * @param  mac           new MAC address
 */
int cvmcs_nic_add_mac(int ifidx, int gmxport_id, int gmx_offset, uint64_t mac)
{
	gmx_port_info_t *info = &octnic->gmx_port_info[gmxport_id];
	int port = info->ipd_port;
	int interface = INTERFACE(port);
	int index = INDEX(port);
	int hash_idx;
	uint64_t cam_flags = 0;
	int addr_id;

	//TODO use promisc mode if > 32

	if (gmx_offset > MAX_OCTEON_NIC_PORTS) {
		printf("error setting more than %d mac address not supported\n",
		       MAX_OCTEON_NIC_PORTS);
		return -1;
	}

	cvmx_rwlock_wp_write_lock(&info->mac_hash_lock);

	hash_idx = cvmcs_find_free_mac_hash_idx(info, mac, ifidx);
	if (hash_idx == -1) {
		printf("GMX%d: No space in MAC hashtable for port %d MAC %012lx\n",
		       gmxport_id, info->nports, mac);
		cvmx_rwlock_wp_write_unlock(&info->mac_hash_lock);
		return -1;
	}

	if (octeon_has_feature(OCTEON_FEATURE_BGX)) {
		cvmx_bgxx_cmr_rx_adrx_cam_t adrx_cam;

		/* For 78xx, cvmx_helper_get_interface_num() returns xiface. 
		*  Hack to get the interface from xiface.
		*/
		interface = interface &  0xff;

		adrx_cam.u64 = 0;
		adrx_cam.s.adr = mac;   /* assigns lower 48 bits */
		adrx_cam.s.en = 0;
		adrx_cam.s.id = index;
		cvmx_write_csr_node(cvmx_get_node_num(), CVMX_BGXX_CMR_RX_ADRX_CAM(gmx_offset,interface), adrx_cam.u64);
	} else {
		//override index to be able to reach gmxx_rx1/2/3 on xaui
		cvmx_gmxx_rxx_adr_ctl_t control;

		index = gmx_offset >> 3;
		addr_id = (gmx_offset & 0x7)*8;

		CVMX_WRITE_GMX_ADR(0, (CVMX_READ_GMX_ADR(0) & ~(0xFFull << addr_id)));
		CVMX_WRITE_GMX_ADR(1, (CVMX_READ_GMX_ADR(1) & ~(0xFFull << addr_id)));
		CVMX_WRITE_GMX_ADR(2, (CVMX_READ_GMX_ADR(2) & ~(0xFFull << addr_id)));
		CVMX_WRITE_GMX_ADR(3, (CVMX_READ_GMX_ADR(3) & ~(0xFFull << addr_id)));
		CVMX_WRITE_GMX_ADR(4, (CVMX_READ_GMX_ADR(4) & ~(0xFFull << addr_id)));
		CVMX_WRITE_GMX_ADR(5, (CVMX_READ_GMX_ADR(5) & ~(0xFFull << addr_id)));

		CVMX_WRITE_GMX_ADR(0, (CVMX_READ_GMX_ADR(0) | (((mac >> 40) & 0xff) << addr_id)));
		CVMX_WRITE_GMX_ADR(1, (CVMX_READ_GMX_ADR(1) | (((mac >> 32) & 0xff) << addr_id)));
		CVMX_WRITE_GMX_ADR(2, (CVMX_READ_GMX_ADR(2) | (((mac >> 24) & 0xff) << addr_id)));
		CVMX_WRITE_GMX_ADR(3, (CVMX_READ_GMX_ADR(3) | (((mac >> 16) & 0xff) << addr_id)));
		CVMX_WRITE_GMX_ADR(4, (CVMX_READ_GMX_ADR(4) | (((mac >>  8) & 0xff) << addr_id)));
		CVMX_WRITE_GMX_ADR(5, (CVMX_READ_GMX_ADR(5) | (((mac >>  0) & 0xff) << addr_id)));

		// clear the MAC entry for now. It will be enabled later.
		info->cam_flags &= ~(1UL << gmx_offset);

		control.u64 = cvmx_read_csr(CVMX_GMXX_RXX_ADR_CTL(index, interface));
		if (control.s.cam_mode)
			cam_flags = info->cam_flags;
		cvmx_write_csr(CVMX_GMXX_RXX_ADR_CAM_ALL_EN(index, interface), cam_flags);
	}

	cvmcs_add_mac_hash_idx(info, hash_idx, ifidx, mac);

	octnic->port[ifidx].state.ifflags = OCTNET_IFFLAG_MULTICAST;
	octnic->port[ifidx].gmx_offset = gmx_offset;
	octnic->port[ifidx].hash_idx = hash_idx;
	octnic->port[ifidx].linfo.hw_addr = mac;

	cvmx_rwlock_wp_write_unlock(&info->mac_hash_lock);

	return 0;
}

/* whoever calls this function is responsible for locking/unlocking the appropriate mac hash table */
static void add_mac_to_hash_table(int ifidx, uint64_t mac, vnic_hash_t *bucketarray)
{
	unsigned int h, j, k;

	h = mac_hash(mac_to_ptr(&mac)) << NIC_HASH_SHIFT;

	for(j = 0; j < MAX_OCTEON_NIC_HASH_SIZE; j++) {
		k = (h + j) & (MAX_OCTEON_NIC_HASH_SIZE - 1);
		if (bucketarray[k].ifidx == -1) {
			bucketarray[k].ifidx = ifidx;
			bucketarray[k].hw_addr = mac;
			break;
		} else {
			if ((bucketarray[k].hw_addr == mac) && (bucketarray[k].ifidx == ifidx))
				break;
		}
	}
}

int cvmcs_remove_mac_from_hash_table(gmx_port_info_t *info,
				     uint64_t mac, int ifidx)
{
	unsigned int h, j, k;
	int mac_was_deleted=0;
	int retval=0;
	int ifidx_to_readd;
	uint64_t mac_to_readd;

	h = mac_hash(mac_to_ptr(&mac)) << NIC_HASH_SHIFT;

	cvmx_rwlock_wp_write_lock(&info->mac_hash_lock);

	for(j = 0; j < MAX_OCTEON_NIC_HASH_SIZE; j++) {
		k = (h + j) & (MAX_OCTEON_NIC_HASH_SIZE - 1);
		if (info->hash[k].ifidx == -1) {
			retval = -1;
			break; /* nothing to delete; it's not in the hash table */
		}
		if (info->hash[k].hw_addr == mac) {
			if (info->hash[k].ifidx == ifidx) {
				info->hash[k].ifidx = -1;
				info->hash[k].hw_addr = 0;
				mac_was_deleted = 1;
			} else
				retval = -2; /* ifidx mismatch */
			break;
		}
	}

	if (mac_was_deleted) {
		/* deal with the cluster (if any) to the right of the mac that was just deleted */
		k = (k + 1) & (MAX_OCTEON_NIC_HASH_SIZE - 1);
		while (info->hash[k].ifidx != -1) {
			ifidx_to_readd = info->hash[k].ifidx;
			mac_to_readd   = info->hash[k].hw_addr;

			info->hash[k].ifidx = -1;
			info->hash[k].hw_addr = 0;

			add_mac_to_hash_table(ifidx_to_readd, mac_to_readd, info->hash);

			k = (k + 1) & (MAX_OCTEON_NIC_HASH_SIZE - 1);
		}
	}

	cvmx_rwlock_wp_write_unlock(&info->mac_hash_lock);

	return retval;
}

/* Enable or disable the interface in the CAM */
void cvmcs_nic_del_mac(int ifidx)
{
	int gmxport_id = octnic->port[ifidx].gmxport_id;
	int gmx_offset = octnic->port[ifidx].gmx_offset;
	int hash_idx   = octnic->port[ifidx].hash_idx;
	gmx_port_info_t *info = &octnic->gmx_port_info[gmxport_id];
	int port = info->ipd_port;
	int interface = INTERFACE(port);
	int index = INDEX(port);
	uint64_t cam_flags = 0;
	int addr_id;
	cvmx_gmxx_rxx_adr_ctl_t control;

	if (octeon_has_feature(OCTEON_FEATURE_BGX)) {
		cvmx_bgxx_cmr_rx_adrx_cam_t adrx_cam;

		/* For 78xx, cvmx_helper_get_interface_num() returns xiface. 
		*  Hack to get the interface from xiface.
		*/
		interface = interface &  0xff;

		adrx_cam.u64 = 0;
		adrx_cam.s.adr = 0;
		adrx_cam.s.en = 0;
		adrx_cam.s.id = index;
		cvmx_write_csr_node(cvmx_get_node_num(), CVMX_BGXX_CMR_RX_ADRX_CAM(gmx_offset,interface), adrx_cam.u64);

	} else {
		//override index to be able to reach gmxx_rx1/2/3 on xaui
		index = gmx_offset >> 3;
		addr_id = (gmx_offset & 0x7)*8;

		DBG2("Deleting MAC for interface %d at index %d gmx_offset %d hash_idx %d\n",
		     interface, index, gmx_offset, hash_idx);

		CVMX_WRITE_GMX_ADR(0, (CVMX_READ_GMX_ADR(0) & ~(0xFFull << addr_id)));
		CVMX_WRITE_GMX_ADR(1, (CVMX_READ_GMX_ADR(1) & ~(0xFFull << addr_id)));
		CVMX_WRITE_GMX_ADR(2, (CVMX_READ_GMX_ADR(2) & ~(0xFFull << addr_id)));
		CVMX_WRITE_GMX_ADR(3, (CVMX_READ_GMX_ADR(3) & ~(0xFFull << addr_id)));
		CVMX_WRITE_GMX_ADR(4, (CVMX_READ_GMX_ADR(4) & ~(0xFFull << addr_id)));
		CVMX_WRITE_GMX_ADR(5, (CVMX_READ_GMX_ADR(5) & ~(0xFFull << addr_id)));

		// clear the MAC entry for now. It will be enabled later.
		info->cam_flags &= ~(1UL << gmx_offset);

		control.u64 = cvmx_read_csr(CVMX_GMXX_RXX_ADR_CTL(index, interface));
		if (control.s.cam_mode)
			cam_flags = info->cam_flags;
		cvmx_write_csr(CVMX_GMXX_RXX_ADR_CAM_ALL_EN(index, interface), cam_flags);
	}

	if (cvmcs_remove_mac_from_hash_table(info, octnic->port[ifidx].linfo.hw_addr, ifidx)) {
		printf("GMX%d: [%d] Mismatch trying to remove MAC %012lx\n",
		       ifidx, hash_idx,
		       octnic->port[ifidx].linfo.hw_addr);
		/* fall through */
	}
}

/* Enable or disable the interface in the CAM */
void cvmcs_nic_change_mac_state(int ifidx, int rx_on)
{
	vnic_port_info_t *nicport = &octnic->port[ifidx];
	int gmxport_id = nicport->gmxport_id;
	int gmx_offset = nicport->gmx_offset;
	gmx_port_info_t *info = &octnic->gmx_port_info[gmxport_id];
	int port = info->ipd_port;
	int interface = INTERFACE(port);
	int index = INDEX(port);

	DBG2("%s MAC filter for VNIC %d GMX%d interface %d at index %d gmx_offset %d\n",
	     rx_on ? "Enabling" : "Disabling", ifidx, gmxport_id, interface,
	     index, gmx_offset);

	if (nicport->state.rx_on == rx_on)
		return;

	if (OCT_NIC_IS_VF(ifidx)) {
		octnic->port[ifidx].state.rx_on = rx_on;
		CVMX_SYNCWS; /* Make sure other cores know we can or cannot Rx. */
		return;
	}

	/* PFs only at this point */

	if (octeon_has_feature(OCTEON_FEATURE_BGX)) {
		static CVMX_SHARED cvmx_spinlock_t mutex[2]; /* each PF gets a mutex */
		int pf_num;

		interface = interface &  0xff;

		pf_num = OCT_NIC_PORT_PF(ifidx);

		cvmx_spinlock_lock(&mutex[pf_num]);

		octnic->port[ifidx].state.rx_on = rx_on;
		CVMX_SYNCWS; /* Make sure other cores know we can or cannot Rx. */

		if (rx_on)
			cvmcs_bgx_link_up(info);
		else
			cvmcs_bgx_link_down(info);

		cvmx_spinlock_unlock(&mutex[pf_num]);

	} else {
		uint64_t cam_flags;
		cvmx_gmxx_rxx_adr_ctl_t control;

		octnic->port[ifidx].state.rx_on = rx_on;
		CVMX_SYNCWS; /* Make sure other cores know we can or cannot Rx. */

		if (rx_on)
			info->cam_flags |= (1UL << gmx_offset);
		else
			info->cam_flags &= ~(1UL << gmx_offset);

		cam_flags = 0;

		//override index to be able to reach gmxx_rx1/2/3 on xaui
		index = gmx_offset >> 3;
		control.u64 = cvmx_read_csr(CVMX_GMXX_RXX_ADR_CTL(index, interface));
		if (control.s.cam_mode)
			cam_flags = info->cam_flags;
		cvmx_write_csr(CVMX_GMXX_RXX_ADR_CAM_ALL_EN(index, interface), cam_flags);
	}

	if (cvmx_sysinfo_get()->board_type == CVMX_BOARD_TYPE_NIC225E && !rx_on) {
		struct cvmx_fdt_sfp_info *sfp_info;

		sfp_info = cvmx_helper_cfg_get_sfp_info(interface, index);
		SFP_TX_DISABLE(sfp_info);
	}
}

static inline int cvmcs_nic_clear_stats(uint32_t ifidx, int port)
{
	struct oct_link_stats *st;
	int interface = INTERFACE(port);
	int index = INDEX(port);
	int i;
	vnic_port_info_t *nicport = &octnic->port[ifidx];
	int gmxport_id = nicport->gmxport_id;
	gmx_port_info_t *info = &octnic->gmx_port_info[gmxport_id];


	for (i = 0; i < MAX_CORES; i++) {
		st = &per_core_stats[i].link_stats[ifidx];
		memset(st, 0, sizeof(*st));
	}

	if (octeon_has_feature(OCTEON_FEATURE_BGX)) {

		/* Disable and enable GMX to clear the RX and TX stats registers */
		/* Disable GMX */
		cvmcs_bgx_link_down(info);

		/* Enable it Again */
		cvmcs_bgx_link_up(info);
	} else {
		/* RX */
		cvmx_write_csr(CVMX_GMXX_RXX_STATS_CTL(index, interface), 1);
		cvmx_write_csr(CVMX_GMXX_TXX_STATS_CTL(index, interface), 1);
		cvmx_read_csr(CVMX_GMXX_RXX_STATS_PKTS(index, interface));
		cvmx_read_csr(CVMX_GMXX_RXX_STATS_OCTS(index, interface));
		cvmx_read_csr(CVMX_GMXX_RXX_STATS_PKTS_CTL(index, interface));
		cvmx_read_csr(CVMX_GMXX_RXX_STATS_PKTS_DRP(index, interface));
		cvmx_read_csr(CVMX_GMXX_RXX_STATS_PKTS_DMAC(index, interface));

		/* TX */
		cvmx_read_csr(CVMX_GMXX_TXX_STAT2(index, interface));
		cvmx_read_csr(CVMX_GMXX_TXX_STAT9(index, interface));
		cvmx_read_csr(CVMX_GMXX_TXX_STAT4(index, interface));
		cvmx_read_csr(CVMX_GMXX_TXX_STAT0(index, interface));
		cvmx_write_csr(CVMX_GMXX_RXX_STATS_CTL(index, interface), 0);
		cvmx_write_csr(CVMX_GMXX_TXX_STATS_CTL(index, interface), 0);

	}
	return 0;
}

void cvmcs_nic_change_vnic_max_mtu(int ifidx, int new_mtu)
{
	if (!octnic->port[ifidx].state.present)
		return;

	if (cvmx_atomic_get32(&octnic->port[ifidx].max_mtu) == new_mtu)
		return;

	cvmx_atomic_set32(&octnic->port[ifidx].max_mtu, new_mtu);
	/* also, update effective_mtu, to be used in case the PF/VF port admin
	 * does not adjust its MTU in response to firmware notification
	 */
	if (new_mtu < octnic->port[ifidx].mtu)
		cvmx_atomic_set32(&octnic->port[ifidx].effective_mtu, new_mtu);
	octnic->port[ifidx].linfo.link.s.mtu = new_mtu;
	CVMX_SYNCW;
	cvmcs_printf("Max MTU for Host interface %d is set to %d\n",
		     ifidx, new_mtu);
}

int cvmcs_nic_change_vnic_mtu(int ifidx, int new_mtu)
{
	if (cvmx_atomic_get32(&octnic->port[ifidx].mtu) == new_mtu)
		return 0;

	if (new_mtu > octnic->port[ifidx].max_mtu) {
		cvmcs_printf("Error: Interface-%d MTU cannot be set higher than"
			     " %d\n", ifidx, octnic->port[ifidx].max_mtu);
		return -1;
	}
	cvmx_atomic_set32(&octnic->port[ifidx].mtu, new_mtu);
	cvmx_atomic_set32(&octnic->port[ifidx].effective_mtu, new_mtu);
	CVMX_SYNCW;
	cvmcs_printf("MTU for Host interface %d is set to %d; "
		     "effective_mtu = %d\n", ifidx, new_mtu,
		     octnic->port[ifidx].effective_mtu);
	return 0;
}

int cvmcs_nic_change_link_mtu(int ifidx, int gmxport, int new_mtu)
{
	int max_frm_size;
	int interface = INTERFACE(gmxport);
	int index = INDEX(gmxport);
	cvmx_phy_info_t phy_info;

	if (!OCT_NIC_IS_PF(ifidx)) {
		cvmcs_printf("Error: interface %d not allowed to change "
			     "Link MTU. Only controller interface can change"
			     " link MTU\n", ifidx);
		return -1;
	}

	/* Limit the MTU to make sure the ethernet packets are between 64 bytes
	   and 65535 bytes */
	if ((new_mtu < OCTNET_MIN_FRM_SIZE - OCTNET_FRM_HEADER_SIZE)
	    || (new_mtu > OCTNET_MAX_FRM_SIZE - OCTNET_FRM_HEADER_SIZE)) {
		printf("MTU must be between %d and %d.\n",
		       OCTNET_MIN_FRM_SIZE - OCTNET_FRM_HEADER_SIZE,
		       OCTNET_MAX_FRM_SIZE - OCTNET_FRM_HEADER_SIZE);
		return -1;
	}

	max_frm_size = new_mtu + OCTNET_FRM_HEADER_SIZE;

	if (OCTEON_IS_MODEL(OCTEON_CN6XXX))
		max_frm_size += OCTNET_FRM_PTP_HEADER_SIZE;

	/* Set the hardware to truncate packets larger than the MTU. The
	   jabber register must be set to a multiple of 8 bytes, so round up */
	if (octeon_has_feature(OCTEON_FEATURE_BGX)) {

		int node = cvmx_get_node_num();

		/* For 78xx, cvmx_helper_get_interface_num() returns xiface. 
		*  Hack to get the interface from xiface.
		*/
		interface = interface &  0xff;
		cvmx_write_csr_node(node, CVMX_BGXX_SMUX_RX_JABBER(index, interface), (max_frm_size + 7) & ~7u);
		cvmcs_printf("Jabber setting for GMX port-%d changed as per"
			     " new link MTU %d\n", gmxport, new_mtu);

		if (OCTEON_IS_MODEL(OCTEON_CN73XX))
			return 0;
	} else {
		cvmx_write_csr(CVMX_GMXX_RXX_JABBER(index, interface), (max_frm_size + 7) & ~7u);
	}

	if (cvmx_helper_board_get_phy_info(&phy_info, gmxport) < 0) {
		printf("Couldnt get info about PHY\n");
		return -1;
	}

	if (phy_info.phy_addr < 0) {
		printf("%s: PHY address invalid for port %d\n", __func__, gmxport);
		return -1;
	}

	cvmcs_nic_link_set_phy_mru(phy_info.phy_addr, max_frm_size, index);
	DBG2("interface %d port %d: MTU changed to %d \n", interface, gmxport,
	     new_mtu);

	return 0;
}

/* Return non-zero if packet should be dropped */
int cvmcs_nic_opcode_to_stats(int ifidx, int err_code)
{
	int core_id = cvmx_get_core_num();
	int drop = 0;

	if (octeon_has_feature(OCTEON_FEATURE_CN78XX_WQE)) {
		switch (err_code) {
		case CVMX_PKI_OPCODE_RE_JABBER:
			per_core_stats[core_id].link_stats[ifidx].fromwire.jabber_err += 1;
			break;
		case CVMX_PKI_OPCODE_RE_FCS:
		case CVMX_PKI_OPCODE_RE_FCS_RCV:
		case 0x20: /* L2_FRAGMENT */
		case 0x21: /* L2_OVERRUN */
		case 0x22: /* L2_PFCS */
			per_core_stats[core_id].link_stats[ifidx].fromwire.fcs_err += 1;
			break;
		case CVMX_PKI_OPCODE_RE_PARTIAL:
		case CVMX_PKI_OPCODE_RE_SKIP:
		case 0x23: /* L2_PUNY */
		case 0x26: /* L2_UNDERSIZE */
			per_core_stats[core_id].link_stats[ifidx].fromwire.runts += 1;
			break;
		case CVMX_PKI_OPCODE_RE_TERMINATE:
		case CVMX_PKI_OPCODE_RE_RX_CTL:
		case 0xF: /* RE_DMAPKT */
		case 0x13: /* RE_PKIPAR */
		case 0x14: /* RE_PKIPCAM */
		case 0x15: /* RE_MEMOUT */
		case 0x16: /* RE_BUFS_OFLOW */
		case 0x24: /* L2_MAL */
		case 0x25: /* L2_OVERSIZE */
		case 0x27: /* L2_LENMISM */
			per_core_stats[core_id].link_stats[ifidx].fromwire.l2_err += 1;
			break;
		default: /* IP_CHK, L4_CHK, etc */
			per_core_stats[core_id].link_stats[ifidx].fromwire.frame_err += 1;
			/* do not drop */
			break;
		}

		/* Drop if L2 or lower */
		drop = (err_code < 0x30);

	} else {
		switch (err_code) {
		case 2:
		case 4:
			per_core_stats[core_id].link_stats[ifidx].fromwire.jabber_err += 1;
			break;
		case 3:
		case 5:
		case 6:
		case 7:
		case 16:
			per_core_stats[core_id].link_stats[ifidx].fromwire.fcs_err += 1;
			break;
		case 8:
			per_core_stats[core_id].link_stats[ifidx].fromwire.runts += 1;
			break;
		case 18:
			per_core_stats[core_id].link_stats[ifidx].fromwire.l2_err += 1;
			break;
		default:
			per_core_stats[core_id].link_stats[ifidx].fromwire.frame_err += 1;
			break;
		}

		drop = 1; /* all rcv errors are dropped for 66xx/68xx */
	}

	if (drop)
		per_core_stats[cvmx_get_core_num()].link_stats[ifidx].fromwire.fw_err_drop += 1;

	return drop;
}

void cvmcs_nic_get_stats(struct oct_link_stats *st, int ifidx)
{
	unsigned int i,j,k;

	//	uint64_t err_drop = 0;
	i = ifidx;
	for (j = 0; j < MAX_CORES; j++) {
		st->fromwire.fw_total_rcvd += per_core_stats[j].link_stats[i].fromwire.fw_total_rcvd;
		st->fromwire.fw_err_pko += per_core_stats[j].link_stats[i].fromwire.fw_err_pko;
		st->fromwire.fw_err_link += per_core_stats[j].link_stats[i].fromwire.fw_err_link;

		st->fromhost.fw_total_sent += per_core_stats[j].link_stats[i].fromhost.fw_total_sent;
		for (k = 0; k < MAX_IOQS_PER_NICIF; k++)
			per_core_stats[j].link_stats[i].fromhost.fw_total_fwd += per_core_stats[j].perq_stats[i].fromhost.fw_total_fwd[k];
		st->fromhost.fw_total_fwd += per_core_stats[j].link_stats[i].fromhost.fw_total_fwd;

		st->fromhost.fw_err_pko += per_core_stats[j].link_stats[i].fromhost.fw_err_pko;
		st->fromhost.fw_err_pki += per_core_stats[j].link_stats[i].fromhost.fw_err_pki;
		st->fromhost.fw_err_link += per_core_stats[j].link_stats[i].fromhost.fw_err_link;
		st->fromhost.fw_tso += per_core_stats[j].link_stats[i].fromhost.fw_tso;
		st->fromhost.fw_tso_fwd += per_core_stats[j].link_stats[i].fromhost.fw_tso_fwd;
		st->fromhost.fw_err_tso += per_core_stats[j].link_stats[i].fromhost.fw_err_tso;
		st->fromhost.fw_tx_vxlan += per_core_stats[j].link_stats[i].fromhost.fw_tx_vxlan;
#ifdef LINUX_IPSEC
		st->fromhost.fw_ipsec_out += per_core_stats[j].link_stats[i].fromhost.fw_ipsec_out;
#endif
		st->fromhost.fw_total_mcast_sent +=
			per_core_stats[j].link_stats[i].fromhost.fw_total_mcast_sent;
		st->fromhost.fw_total_bcast_sent +=
			per_core_stats[j].link_stats[i].fromhost.fw_total_bcast_sent;
		st->fromhost.fw_err_drop +=
			per_core_stats[j].link_stats[i].fromhost.fw_err_drop;

		st->fromwire.fw_total_mcast  +=
			per_core_stats[j].link_stats[i].fromwire.fw_total_mcast;
		st->fromwire.fw_total_bcast  +=
			per_core_stats[j].link_stats[i].fromwire.fw_total_bcast;
		st->fromwire.fw_lro_pkts += per_core_stats[j].link_stats[i].fromwire.fw_lro_pkts;
		st->fromwire.fw_lro_octs += per_core_stats[j].link_stats[i].fromwire.fw_lro_octs;
		st->fromwire.fw_total_lro += per_core_stats[j].link_stats[i].fromwire.fw_total_lro;
		st->fromwire.fw_lro_aborts += per_core_stats[j].link_stats[i].fromwire.fw_lro_aborts;
		st->fromwire.fw_lro_aborts_port += per_core_stats[j].link_stats[i].fromwire.fw_lro_aborts_port;
		st->fromwire.fw_lro_aborts_seq += per_core_stats[j].link_stats[i].fromwire.fw_lro_aborts_seq;
		st->fromwire.fw_lro_aborts_tsval += per_core_stats[j].link_stats[i].fromwire.fw_lro_aborts_tsval;
		st->fromwire.fw_lro_aborts_timer += per_core_stats[j].link_stats[i].fromwire.fw_lro_aborts_timer;
		st->fromwire.fw_rx_vxlan += per_core_stats[j].link_stats[i].fromwire.fw_rx_vxlan;
		st->fromwire.fw_rx_vxlan_err += per_core_stats[j].link_stats[i].fromwire.fw_rx_vxlan_err;
		st->fromwire.l2_err += per_core_stats[j].link_stats[i].fromwire.l2_err;
#ifdef LINUX_IPSEC
		st->fromwire.fw_ipsec_in += per_core_stats[j].link_stats[i].fromwire.fw_ipsec_in;
#endif
		st->fromwire.runts += per_core_stats[j].link_stats[i].fromwire.runts;
		st->fromwire.jabber_err += per_core_stats[j].link_stats[i].fromwire.jabber_err;
		st->fromwire.fcs_err += per_core_stats[j].link_stats[i].fromwire.fcs_err;
		st->fromwire.frame_err += per_core_stats[j].link_stats[i].fromwire.frame_err;
		st->fromwire.fw_err_drop += per_core_stats[j].link_stats[i].fromwire.fw_err_drop;

#if 0
		err_drop = st->fromwire.total_rcvd - st->fromwire.fw_total_rcvd;
		err_drop += st->fromwire.dmac_drop;
		err_drop += st->fromwire.fw_err_drop;
#endif

	}
}

void cvmcs_nic_read_stats_reg(int port, struct oct_link_stats *st)
{
	int interface = INTERFACE(port);
	int index = INDEX(port);

	if (octeon_has_feature(OCTEON_FEATURE_BGX)) {
		int node = cvmx_get_node_num();
		/* For 78xx, cvmx_helper_get_interface_num() returns xiface. 
		 *  Hack to get the interface from xiface.
		 */
		interface = interface &  0xff;
		st->fromwire.total_rcvd  = (cvmx_read_csr_node(node, CVMX_BGXX_CMRX_RX_STAT0(index, interface)) & 0x0000FFFFFFFFFFFFull);
		st->fromwire.bytes_rcvd  = (cvmx_read_csr_node(node, CVMX_BGXX_CMRX_RX_STAT1(index, interface)) & 0x0000FFFFFFFFFFFFull);
		st->fromwire.ctl_rcvd    = (cvmx_read_csr_node(node, CVMX_BGXX_CMRX_RX_STAT2(index, interface)) & 0x0000FFFFFFFFFFFFull);
		st->fromwire.fifo_err    = (cvmx_read_csr_node(node, CVMX_BGXX_CMRX_RX_STAT6(index, interface)) & 0x0000FFFFFFFFFFFFull);
		st->fromwire.dmac_drop   = (cvmx_read_csr_node(node, CVMX_BGXX_CMRX_RX_STAT4(index, interface)) & 0x0000FFFFFFFFFFFFull);
		st->fromwire.total_bcst  += cvmx_read_csr_node(node, CVMX_PKI_STATX_STAT5(cvmx_helper_get_pknd(INTERFACE(port), INDEX(port))));
		st->fromwire.total_mcst  += cvmx_read_csr_node(node, CVMX_PKI_STATX_STAT6(cvmx_helper_get_pknd(INTERFACE(port), INDEX(port))));
		st->fromwire.red_drops  += cvmx_read_csr_node(node, CVMX_PKI_STATX_STAT3(cvmx_helper_get_pknd(INTERFACE(port), INDEX(port))));


		/* TX */
		st->fromhost.total_pkts_sent  = (cvmx_read_csr_node(node, CVMX_BGXX_CMRX_TX_STAT5(index, interface))  & 0x0000FFFFFFFFFFFFull);
		st->fromhost.total_bytes_sent  = (cvmx_read_csr_node(node, CVMX_BGXX_CMRX_TX_STAT4(index, interface))  & 0x0000FFFFFFFFFFFFull);
		st->fromhost.fifo_err    = (cvmx_read_csr_node(node, CVMX_BGXX_CMRX_TX_STAT16(index, interface)) & 0x0000FFFFFFFFFFFFull);
		st->fromhost.ctl_sent    = (cvmx_read_csr_node(node, CVMX_BGXX_CMRX_TX_STAT17(index, interface)) & 0x0000FFFFFFFFFFFFull);
		st->fromhost.runts       = (cvmx_read_csr_node(node, CVMX_BGXX_CMRX_TX_STAT6(index, interface))  & 0x0000FFFFFFFFFFFFull);
		st->fromhost.total_collisions   = (cvmx_read_csr_node(node, CVMX_BGXX_CMRX_TX_STAT0(index, interface)) & 0x0000FFFFFFFFFFFFull);
		st->fromhost.one_collision_sent   = (cvmx_read_csr_node(node, CVMX_BGXX_CMRX_TX_STAT3(index, interface)) & 0x0000FFFFFFFFFFFFull);
		st->fromhost.multi_collision_sent   = (cvmx_read_csr_node(node, CVMX_BGXX_CMRX_TX_STAT2(index, interface)) & 0x0000FFFFFFFFFFFFull);
		st->fromhost.max_collision_fail   = (cvmx_read_csr_node(node, CVMX_BGXX_CMRX_TX_STAT0(index, interface)) & 0x0000FFFFFFFFFFFFull);
		st->fromhost.max_deferral_fail   = (cvmx_read_csr_node(node, CVMX_BGXX_CMRX_TX_STAT1(index, interface)) & 0x0000FFFFFFFFFFFFull);
		st->fromhost.mcast_pkts_sent = (cvmx_read_csr_node(node, CVMX_BGXX_CMRX_TX_STAT15(index, interface))  & 0x0000FFFFFFFFFFFFull);
		st->fromhost.bcast_pkts_sent = (cvmx_read_csr_node(node, CVMX_BGXX_CMRX_TX_STAT14(index, interface))  & 0x0000FFFFFFFFFFFFull);
	} else {
		/* RX */
		st->fromwire.total_rcvd =
		    cvmx_read_csr(CVMX_GMXX_RXX_STATS_PKTS(index, interface));
		st->fromwire.bytes_rcvd =
		    cvmx_read_csr(CVMX_GMXX_RXX_STATS_OCTS(index, interface));
		st->fromwire.ctl_rcvd =
		    cvmx_read_csr(CVMX_GMXX_RXX_STATS_PKTS_CTL(index, interface));
		st->fromwire.fifo_err =
		    cvmx_read_csr(CVMX_GMXX_RXX_STATS_PKTS_DRP(index, interface));
		st->fromwire.dmac_drop =
		    cvmx_read_csr(CVMX_GMXX_RXX_STATS_PKTS_DMAC(index, interface));
		st->fromwire.total_bcst =
		    cvmx_read_csr(CVMX_PIP_STAT3_PRTX(port)) >> 32;
		st->fromwire.total_mcst =
		    cvmx_read_csr(CVMX_PIP_STAT3_PRTX(port)) &
		    0x00000000FFFFFFFFLU;

		/* TX */
		st->fromhost.total_pkts_sent =
		    cvmx_read_csr(CVMX_GMXX_TXX_STAT3(index, interface));
		st->fromhost.total_bytes_sent =
		    cvmx_read_csr(CVMX_GMXX_TXX_STAT2(index, interface));
		st->fromhost.mcast_pkts_sent =
		    cvmx_read_csr(CVMX_GMXX_TXX_STAT8(index, interface)) >> 32;
		st->fromhost.bcast_pkts_sent =
		    cvmx_read_csr(CVMX_GMXX_TXX_STAT8(index, interface)) &
		    0x00000000FFFFFFFFLU;
		st->fromhost.fifo_err =
		    cvmx_read_csr(CVMX_GMXX_TXX_STAT9(index, interface)) >> 32;
		st->fromhost.ctl_sent =
		    cvmx_read_csr(CVMX_GMXX_TXX_STAT9(index, interface)) &
		    0x00000000FFFFFFFFLU;
		st->fromhost.one_collision_sent =
		    cvmx_read_csr(CVMX_GMXX_TXX_STAT1(index, interface)) >> 32;
		st->fromhost.multi_collision_sent =
		    cvmx_read_csr(CVMX_GMXX_TXX_STAT1(index, interface)) &
		    0x00000000FFFFFFFFLU;
		st->fromhost.max_deferral_fail =
		    cvmx_read_csr(CVMX_GMXX_TXX_STAT0(index, interface)) >> 32;
		st->fromhost.max_collision_fail =
		    cvmx_read_csr(CVMX_GMXX_TXX_STAT0(index, interface)) &
		    0x00000000FFFFFFFFLU;
		st->fromhost.runts =
		    cvmx_read_csr(CVMX_GMXX_TXX_STAT4(index, interface)) &
		    0x00000000FFFFFFFFLU;
		st->fromhost.total_collisions =
		    cvmx_read_csr(CVMX_GMXX_TXX_STAT0(index, interface)) &
		    0x00000000FFFFFFFFLU;
	}
	return;
}

int cvmcs_nic_prepare_link_info_pkt(int ifidx, uint64_t * buf)
{
	int i, j, size = 0;
	struct oct_link_info *linfo;

	if (octnic->nports == 0)
		return 0;

	/* 64-bit link info field tells host driver the number of links
	   that the core has information for. */

	linfo = (struct oct_link_info *) & buf[0];

	i = ifidx;
	if (octnic->port[i].state.present) {

		cvmx_atomic_set64((int64_t *) & linfo->link.u64,
				  octnic->port[i].linfo.link.u64);

		if (!octnic->port[i].state.rx_on)
			linfo->link.s.link_up = 0;

		linfo->gmxport = octnic->port[i].linfo.gmxport;
		linfo->hw_addr = octnic->port[i].linfo.hw_addr;
		linfo->num_rxpciq = octnic->port[i].linfo.num_rxpciq;
		linfo->num_txpciq = octnic->port[i].linfo.num_txpciq;
		linfo->macaddr_is_admin_asgnd =
			octnic->port[i].linfo.macaddr_is_admin_asgnd;
		linfo->macaddr_spoofchk =
			octnic->port[i].linfo.macaddr_spoofchk;
		linfo->vlan_is_admin_assigned = octnic->port[i].linfo.vlan_is_admin_assigned;

		for (j = 0; j < MAX_IOQS_PER_NICIF; j++) {
			linfo->txpciq[j].u64 = octnic->port[i].linfo.txpciq[j].u64;
			linfo->rxpciq[j].u64= octnic->port[i].linfo.rxpciq[j].u64;
		}

		linfo->octlinux_uqpg = octnic->port[i].linfo.octlinux_uqpg;
		linfo->octlinux_qpg = octnic->port[i].linfo.octlinux_qpg;

		DBG("linfo @ %p ifidx: %d gmxport: %d rxq from: %2d to %2d  txq from: %2d to %2d hw_addr: %lx\n", linfo, i, linfo->gmxport, (int)OCT_NIC_OQ_NUM(&octnic->port[i], 0), (int)OCT_NIC_OQ_NUM(&octnic->port[i], 0) + linfo->num_rxpciq - 1, (int)OCT_NIC_IQ_NUM(&octnic->port[i], 0), (int)OCT_NIC_IQ_NUM(&octnic->port[i], 0) + linfo->num_txpciq - 1, linfo->hw_addr);
	}

	size = (OCT_LINK_INFO_SIZE) + 8;

	CVMX_SYNCWS;
	return size;
}

int cvmcs_nic_send_vf_port_stats(cvmx_wqe_t * wqe)
{
	cvm_pci_dma_cmd_t cmd;
	cvmx_buf_ptr_t lptr;
	cvmx_buf_ptr_pki_t *bls; /* pki buffer link structure for Octeon III */
	cvm_dma_remote_ptr_t rptr;
	cvmx_raw_inst_front_t *f;
	uint64_t *buf;
	int ifidx = 0;
	struct oct_pervf_stats vfstats[OCT_NIC_VFS_PER_PF];

	cmd.u64 = 0;
	lptr.u64 = 0;
	bls = (cvmx_buf_ptr_pki_t *)&lptr;

	if (octeon_has_feature(OCTEON_FEATURE_CN78XX_WQE))
		f = (cvmx_raw_inst_front_t *) cvmx_phys_to_ptr(cvmx_wqe_get_pki_pkt_ptr(wqe).addr);
	else
		f = (cvmx_raw_inst_front_t *)wqe->packet_data;


	ifidx = get_vnic_port_id(cvmx_wqe_get_port(wqe));
	cmd.s.pcielport = f->rdp.s.pcie_port;
	rptr.s.addr = f->rptr;
	rptr.s.size = f->rdp.s.rlen;

	if (OCT_NIC_IS_VF(ifidx)) {
		printf("%s: not pf: %d\n",__func__, ifidx);
		return 1;
	}

	if (cvmx_unlikely(rptr.s.size > CVMX_FPA_PACKET_POOL_SIZE)) {
		printf("[ DRV ] Cannot use packet pool buf for sending link info\n");
		return 1;
	}

	/* Re-use the packet pool buffer to send the link info to host. */
	buf = (uint64_t *) cvmx_phys_to_ptr(wqe->packet_ptr.s.addr);

	/* Reset all bytes so that unused fields don't have any value. */

	memset(buf, 0, rptr.s.size);
	memset(&vfstats[0], 0, sizeof(vfstats));

	if (octnic->nports && octnic->port[ifidx].state.present) {
		unsigned int i,j, vfifidx;
		u64 total_spoofmac=0, diff_spoofmac=0;

		for (i = 1; i < OCT_NIC_VFS_PER_PF; i++) { 
			vfifidx = OCT_NIC_PORT_IDX( OCT_NIC_PORT_PF(ifidx), i );
			for (j = 0; j < MAX_CORES; j++) {
				vfstats[i].spoofmac_cnt += per_core_stats[j].vf_stats[vfifidx].spoofmac_cnt;
				total_spoofmac += per_core_stats[j].vf_stats[vfifidx].spoofmac_cnt;
			}
		}

		if (per_core_stats[0].vf_stats[ifidx].spoofmac_cnt != total_spoofmac) {
			diff_spoofmac = total_spoofmac - per_core_stats[0].vf_stats[ifidx].spoofmac_cnt;
			/* keep spoofmac_cnt of a PF */
			per_core_stats[0].vf_stats[ifidx].spoofmac_cnt = total_spoofmac;
		}
		

		memcpy(&buf[1], &diff_spoofmac, sizeof(u64));
	}

	if (octeon_has_feature(OCTEON_FEATURE_CN78XX_WQE)) {
		bls->size = rptr.s.size;
		bls->addr = CVM_DRV_GET_PHYS(buf);
		bls->packet_outside_wqe = 0;
	} else {
		lptr.s.size = rptr.s.size;
		lptr.s.addr = CVM_DRV_GET_PHYS(buf);
		lptr.s.i    = 1;
		lptr.s.pool = CVMX_FPA_PACKET_POOL;
		lptr.s.back = wqe->packet_ptr.s.back;
		cvm_update_bp(wqe);
		cvmx_wqe_free(wqe);
	}

	cmd.s.nl = cmd.s.nr = 1;

	if (OCTEON_IS_OCTEON3())
		return cvm_pci_dma_send_data_o3(&cmd, bls, &rptr, wqe, 1);
	else
		return cvm_pci_dma_send_data(&cmd, &lptr, &rptr);
}

int cvmcs_nic_send_port_stats(cvmx_wqe_t * wqe)
{
	cvm_pci_dma_cmd_t cmd;
	cvmx_buf_ptr_t lptr;
	cvmx_buf_ptr_pki_t *bls; /* pki buffer link structure for Octeon III */
	cvm_dma_remote_ptr_t rptr;
	cvmx_raw_inst_front_t *f;
	uint64_t *buf;
	int ifidx = 0;
	struct oct_link_stats st_str;

	cmd.u64 = 0;
	lptr.u64 = 0;
	bls = (cvmx_buf_ptr_pki_t *)&lptr;

	if (octeon_has_feature(OCTEON_FEATURE_CN78XX_WQE))
		f = (cvmx_raw_inst_front_t *) cvmx_phys_to_ptr(cvmx_wqe_get_pki_pkt_ptr(wqe).addr);
	else
		f = (cvmx_raw_inst_front_t *)wqe->packet_data;


	ifidx = get_vnic_port_id(cvmx_wqe_get_port(wqe));
	cmd.s.pcielport = f->rdp.s.pcie_port;
	rptr.s.addr = f->rptr;
	rptr.s.size = f->rdp.s.rlen;

	if (cvmx_unlikely(rptr.s.size > CVMX_FPA_PACKET_POOL_SIZE)) {
		printf("[ DRV ] Cannot use packet pool buf for sending link info\n");
		return 1;
	}

	/* Re-use the packet pool buffer to send the link info to host. */
	buf = (uint64_t *) cvmx_phys_to_ptr(wqe->packet_ptr.s.addr);

	/* Reset all bytes so that unused fields don't have any value. */
	memset(buf, 0, rptr.s.size);
	memset((void *)&st_str, 0, sizeof(struct oct_link_stats));

	if (octnic->nports && octnic->port[ifidx].state.present) {
		/* Update stats if port exists */
		cvmcs_nic_get_stats(&st_str, ifidx);
		cvmcs_nic_read_stats_reg(octnic->port[ifidx].linfo.gmxport,
					 &st_str);
		memcpy(&buf[1], &st_str, OCT_LINK_STATS_SIZE);
	}

	if (octeon_has_feature(OCTEON_FEATURE_CN78XX_WQE)) {
		bls->size = rptr.s.size;
		bls->addr = CVM_DRV_GET_PHYS(buf);
		bls->packet_outside_wqe = 0;
	} else {
		lptr.s.size = rptr.s.size;
		lptr.s.addr = CVM_DRV_GET_PHYS(buf);
		lptr.s.i    = 1;
		lptr.s.pool = CVMX_FPA_PACKET_POOL;
		lptr.s.back = wqe->packet_ptr.s.back;
		cvm_update_bp(wqe);
		cvmx_wqe_free(wqe);
	}

	cmd.s.nl = cmd.s.nr = 1;

	if (OCTEON_IS_OCTEON3())
		return cvm_pci_dma_send_data_o3(&cmd, bls, &rptr, wqe, 1);
	else
		return cvm_pci_dma_send_data(&cmd, &lptr, &rptr);
}

int cvmcs_nic_send_link_info(cvmx_wqe_t * wqe)
{
	cvm_pci_dma_cmd_t cmd;
	cvmx_buf_ptr_t lptr;
	cvm_dma_remote_ptr_t rptr;
	cvmx_raw_inst_front_t *f;
	uint64_t *buf;
	int ifidx;

	cmd.u64 = 0;
	lptr.u64 = 0;

	if (octeon_has_feature(OCTEON_FEATURE_CN78XX_WQE))
		f =  (cvmx_raw_inst_front_t *) cvmx_phys_to_ptr(cvmx_wqe_get_pki_pkt_ptr(wqe).addr);
	else
		f = (cvmx_raw_inst_front_t *)wqe->packet_data;

	ifidx = get_vnic_port_id(cvmx_wqe_get_port(wqe));

	cmd.s.pcielport = f->rdp.s.pcie_port;
	rptr.s.addr = f->rptr;
	rptr.s.size = f->rdp.s.rlen;

	if (cvmx_unlikely(rptr.s.size > CVMX_FPA_PACKET_POOL_SIZE)) {
		printf
		    ("[ DRV ] Cannot use packet pool buf for sending link info\n");
		return 1;
	}

	lptr.s.size = rptr.s.size;

	/* Re-use the packet pool buffer to send the link info to host. */
	buf = (uint64_t *) cvmx_phys_to_ptr(wqe->packet_ptr.s.addr);

	/* Reset all bytes so that unused fields don't have any value. */
	memset(buf, 0, rptr.s.size);

	if (octeon_has_feature(OCTEON_FEATURE_CN78XX_WQE)) {
		((cvmx_buf_ptr_pki_t *)&lptr)->addr = CVM_DRV_GET_PHYS(buf);
		((cvmx_buf_ptr_pki_t *)&lptr)->size = rptr.s.size;
	} else {
		lptr.s.addr = CVM_DRV_GET_PHYS(buf);
		lptr.s.size = rptr.s.size;

	}
	/* First 8 bytes is response header. No information in it.
	   The link data starts from byte offset 8. */
	if (cvmcs_nic_prepare_link_info_pkt(ifidx, &buf[1]) == 0) {
		printf("[ DRV ] prepare link info pkt failed\n");
		return 1;
	}

	if (OCTEON_IS_OCTEON3()) {
		cmd.s.nl = cmd.s.nr = 1;
		return cvm_pci_dma_send_data_o3(&cmd, (cvmx_buf_ptr_pki_t *)&lptr, &rptr, wqe, 1);
	} else {
		lptr.s.i    = 1;
		lptr.s.pool = CVMX_FPA_PACKET_POOL;
		lptr.s.back = wqe->packet_ptr.s.back;
		cmd.s.nl = cmd.s.nr = 1;
		cvm_update_bp(wqe);
		cvmx_wqe_free(wqe);
		return cvm_pci_dma_send_data(&cmd, &lptr, &rptr);
	}
}


/**
 *  * GPIO Set pin
 *   *
 *    * @param node     Node to set pins on
 *     * @param set_mask Bit mask to indicate which bits to
 drive to '1'.
 *      */
static inline void cvmcs_gpio_set(uint8_t node, uint64_t
		set_mask)
{
	cvmx_gpio_tx_set_t gpio_tx_set;
	gpio_tx_set.u64 = 0;
	gpio_tx_set.s.set = set_mask;
	cvmx_write_csr_node(node, CVMX_GPIO_TX_SET,
			gpio_tx_set.u64);
}

/**
 * GPIO Clear pin
 *  *
 *   * @param node       Node to clear pin on
 *    * @param clear_mask Bit mask to indicate which
 bits to drive to '0'.
 *     */
static inline void cvmcs_gpio_clear(uint8_t node,
		uint64_t clear_mask)
{
	cvmx_gpio_tx_clr_t gpio_tx_clr;
	gpio_tx_clr.u64 = 0;
	gpio_tx_clr.s.clr = clear_mask;
	cvmx_write_csr_node(node, CVMX_GPIO_TX_CLR,
			gpio_tx_clr.u64);
}

void
cvmcs_gpio_cfg(uint8_t node, unsigned gpio, int mode)
{
	cvmx_gpio_bit_cfgx_t gpio_bit;
	gpio_bit.u64 = cvmx_read_csr_node(node,
			CVMX_GPIO_BIT_CFGX(gpio));
	gpio_bit.s.tx_oe = !!mode;
	cvmx_write_csr_node(node, CVMX_GPIO_BIT_CFGX(gpio),
			gpio_bit.u64);
}

int
cvmcs_gpio_access(unsigned gpio, int val)
{

	if (val == VITESSE_PHY_GPIO_DRIVEON) {
		cvmcs_gpio_cfg(0, gpio, 1);
		cvmcs_gpio_set(0, 1ull << gpio);

	} else if (val == VITESSE_PHY_GPIO_HIGH) {
		cvmcs_gpio_set(0, 1ull << gpio);

	} else if (val == VITESSE_PHY_GPIO_LOW) {
		cvmcs_gpio_clear(0, 1ull << gpio);

	} else if (val == VITESSE_PHY_GPIO_DRIVEOFF) {
		cvmcs_gpio_clear(0, 1ull << gpio);
		cvmcs_gpio_cfg(0, gpio, 0);
	}

	return 0;
}

void cvmcs_nic_set_link_status_led(int ifidx)
{
	int gmxport = octnic->port[ifidx].linfo.gmxport;
	int xiface = INTERFACE(gmxport);
	int index  = INDEX(gmxport);
	struct cvmx_phy_gpio_leds *leds;

	leds = cvmx_helper_get_port_phy_leds(xiface, index);

	if (leds == NULL)
		return;

	cvmx_gpio_cfg_sel(leds->link_status_gpio >> 8,
			  leds->link_status_gpio, 0);
	if (octnic->port[ifidx].state.rx_on &&
	    octnic->port[ifidx].linfo.link.s.link_up)
		cvmx_gpio_set_node(leds->link_status_gpio >> 8,
			   1 << (leds->link_status_gpio & 0xff));
	else
		cvmx_gpio_clear_node(leds->link_status_gpio >> 8,
			     1 << (leds->link_status_gpio & 0xff));
}

/* Flash LEDs for the interface (or turn them off.
 * ifidx   interface index. should be a PF interface only
 * gmxport gmxport
 * val     0 = stop flashing, 1 flash LEDs
 */
int
cvmcs_id_active(int ifidx, int gmxport, int val)
{
	int xiface = INTERFACE(gmxport) & 0xff; 
	int index  = INDEX(gmxport), port_id = get_gmx_port_id(gmxport);
	struct cvmx_phy_gpio_leds *leds = cvmx_helper_get_port_phy_leds(xiface,
									index);

	if (octnic->gmx_port_info[port_id].link.s.phy_type == LIO_PHY_PORT_TP) {
		if (val)
			cvmx_gpio_set_node(0, LIO23XX_COPPERHEAD_LED_GPIO);
		else
			cvmx_gpio_clear_node(0, LIO23XX_COPPERHEAD_LED_GPIO);
		return 0;
	}

	if (!leds) {
		printf("ifidx:%d Couldnt get info about phyleds\n", ifidx);
		return -1;
	}

	if (val) {
		octnic->gmx_port_info[gmxport].link.s.flashing = 1;
		CVMX_SYNCWS;

		/* Reconfigure the frequency and begin flashing */
		cvmx_gpio_set_freq(leds->rx_activity_gpio >> 8,
				   leds->rx_gpio_timer,
				   LED_ID_FLASH_INTERVAL_HZ);

		cvmx_gpio_cfg_sel(leds->rx_activity_gpio >> 8,
				  leds->rx_activity_gpio,
				  0x10 + leds->rx_gpio_timer);
		cvmx_gpio_set_node(leds->rx_activity_gpio >> 8,
				   1 << (leds->rx_activity_gpio & 0xff));

		cvmx_gpio_cfg_sel(leds->link_status_gpio >> 8,
				  leds->link_status_gpio,
				  0x10 + leds->rx_gpio_timer);
		cvmx_gpio_set_node(leds->link_status_gpio >> 8,
				   1 << (leds->link_status_gpio & 0xff));
	} else {
		/* Turn off LEDs and restore regular activity frequency */
		cvmx_gpio_set_freq(leds->rx_activity_gpio >> 8,
				   leds->rx_gpio_timer,
				   leds->rx_activity_hz);

		cvmx_gpio_cfg_sel(leds->rx_activity_gpio >> 8,
				  leds->rx_activity_gpio, 0);
		cvmx_gpio_clear_node(leds->rx_activity_gpio >> 8,
				     1 << (leds->rx_activity_gpio & 0xff));
		cvmx_gpio_cfg_sel(leds->link_status_gpio >> 8,
				  leds->link_status_gpio, 0);
		cvmx_gpio_clear_node(leds->link_status_gpio >> 8,
				     1 << (leds->link_status_gpio & 0xff));

		octnic->gmx_port_info[gmxport].link.s.flashing = 0;
		CVMX_SYNCWS;

		/* restore the link status LED */
		cvmcs_nic_set_link_status_led(ifidx);
	}

	return 0;
}

int
cvmcs_nic_prepare_mdio_resp(int ifidx, struct oct_mdio_cmd *mdio_cmd, uint64_t *buf)
{

	int port;
	cvmx_phy_info_t phy_info;
	struct oct_mdio_cmd *mdio_resp = (struct oct_mdio_cmd *)buf;

	port = octnic->port[ifidx].linfo.gmxport;

	if(cvmx_helper_board_get_phy_info(&phy_info, port) < 0)
	{
		printf("Port:%d Couldnt get info about PHY\n", port);
		return -1;
	}

	if(phy_info.phy_addr < 0)
	{
		printf("PHY address invalid for port %d\n", port);
		return -1;
	}


	if (mdio_cmd->op) {
		cvmx_mdio_45_write(phy_info.phy_addr >> 8,
				phy_info.phy_addr & 0xff, 0,
				mdio_cmd->mdio_addr,
				mdio_cmd->value1);
	} else {
		mdio_resp->value1 = cvmx_mdio_45_read(
				phy_info.phy_addr >> 8,
				phy_info.phy_addr & 0xff,
				0, mdio_cmd->mdio_addr);
	}

	return 0;
}

int
cvmcs_nic_send_mdio_info(cvmx_wqe_t  *wqe)
{
	cvm_pci_dma_cmd_t      cmd;
	cvmx_buf_ptr_t         lptr;
	cvm_dma_remote_ptr_t   rptr;
	cvmx_raw_inst_front_t *f;
	struct oct_mdio_cmd   *mdio_cmd;
	uint64_t *buf;
	int pool_id = -1;
	int ifidx;

	cmd.u64  = 0;
	lptr.u64 = 0;

	if (octeon_has_feature(OCTEON_FEATURE_CN78XX_WQE))
		f = (cvmx_raw_inst_front_t *) cvmx_phys_to_ptr(cvmx_wqe_get_pki_pkt_ptr(wqe).addr);
	else
		f = (cvmx_raw_inst_front_t *)wqe->packet_data;

	ifidx = get_vnic_port_id(cvmx_wqe_get_port(wqe));

	mdio_cmd = (struct oct_mdio_cmd  *) ((uint8_t *)f + CVM_RAW_FRONT_SIZE);
	cmd.s.pcielport = f->rdp.s.pcie_port;
	rptr.s.addr = f->rptr;
	rptr.s.size = f->rdp.s.rlen;

	pool_id = CVMX_FPA_PACKET_POOL;

	buf = cvmx_fpa_alloc(pool_id);
	if (cvmx_unlikely(!buf)) {
		printf("[ DRV ] failed to allocate mdio_info return buffer.\n");
		cvmcs_wqe_free(wqe);
		return -1;
	}

	/* Reset all bytes so that unused fields don't have any value. */
	memset(buf, 0, rptr.s.size);

	/* First 8 bytes is response header. Data starts from byte offset 8. */
	if(cvmcs_nic_prepare_mdio_resp(ifidx, mdio_cmd, &buf[1])) {
		printf("[ DRV ] prepare mdio info pkt failed\n");
		return -1;
	}
	if (octeon_has_feature(OCTEON_FEATURE_CN78XX_WQE)) {
		((cvmx_buf_ptr_pki_t *)&lptr)->addr = CVM_DRV_GET_PHYS(buf);
		((cvmx_buf_ptr_pki_t *)&lptr)->size = rptr.s.size;
	} else {
		lptr.s.size = rptr.s.size;
		lptr.s.addr = CVM_DRV_GET_PHYS(buf);
	}

	if (OCTEON_IS_OCTEON3()) {
		cmd.s.nl = cmd.s.nr = 1;
		cvmcs_wqe_free(wqe);
		return cvm_pci_dma_send_data_o3(&cmd, (cvmx_buf_ptr_pki_t *)&lptr, &rptr, wqe, 1);
	} else {
		lptr.s.i    = 1;
		lptr.s.pool = pool_id;
		cmd.s.nl = cmd.s.nr = 1;
		cvm_update_bp(wqe);
		cvmcs_wqe_free(wqe);
		CVMX_SYNCWS;
		return cvm_pci_dma_send_data(&cmd, &lptr, &rptr);
	}
}

void cvmcs_intrmod_cfg(cvmx_wqe_t * wqe)
{
	struct oct_intrmod_cfg *intrmod_cfg;
	cvmx_raw_inst_front_t *f;
	uint64_t retaddr, ret = 0;
	int front_size;

	if (octeon_has_feature(OCTEON_FEATURE_CN78XX_WQE))
		f = (cvmx_raw_inst_front_t *) cvmx_phys_to_ptr(cvmx_wqe_get_pki_pkt_ptr(wqe).addr);
	else
		f = (cvmx_raw_inst_front_t *)wqe->packet_data;

	if (f->irh.s.rflag)
		front_size = CVM_RAW_FRONT_SIZE;
	else
		front_size = CVM_RAW_FRONT_SIZE-16; /* rptr and rdp are not there so don't count them */

	intrmod_cfg = (struct oct_intrmod_cfg *)((uint8_t *)f + front_size);

	if (!intrmod_cfg->check_intrvl)
		intrmod_cfg->check_intrvl = LIO_INTRMOD_CHECK_INTERVAL;

	if (!intrmod_cfg->maxpkt_ratethr)
		intrmod_cfg->maxpkt_ratethr = LIO_INTRMOD_MAXPKT_RATETHR;

	if (!intrmod_cfg->minpkt_ratethr)
		intrmod_cfg->minpkt_ratethr = LIO_INTRMOD_MINPKT_RATETHR;

	if (!intrmod_cfg->rx_maxcnt_trigger)
		intrmod_cfg->rx_maxcnt_trigger = LIO_INTRMOD_RXMAXCNT_TRIGGER;

	if (!intrmod_cfg->rx_maxtmr_trigger)
		intrmod_cfg->rx_maxtmr_trigger = LIO_INTRMOD_RXMAXTMR_TRIGGER;

	if (!intrmod_cfg->rx_mintmr_trigger)
		intrmod_cfg->rx_mintmr_trigger = LIO_INTRMOD_RXMINTMR_TRIGGER;

	if (!intrmod_cfg->rx_mincnt_trigger)
		intrmod_cfg->rx_mincnt_trigger = LIO_INTRMOD_RXMINCNT_TRIGGER;

	if (!intrmod_cfg->tx_maxcnt_trigger)
		intrmod_cfg->tx_maxcnt_trigger = LIO_INTRMOD_TXMAXCNT_TRIGGER;

	if (!intrmod_cfg->tx_mincnt_trigger)
		intrmod_cfg->tx_mincnt_trigger = LIO_INTRMOD_TXMINCNT_TRIGGER;

	if (OCTEON_IS_MODEL(OCTEON_CN73XX)) {
		int pf_id,vf_id, base_queue, max_rings;
		int i, ifidx;
		int mac_id = 0;
		vnic_port_info_t *nicport;
		ifidx = get_vnic_port_id(cvmx_wqe_get_port(wqe));
		if (ifidx == -1) {
			ret = OCTNET_CMD_FAIL;
			goto cfg_failure;
		}
		nicport =  &octnic->port[ifidx];
		pf_id = OCT_NIC_PORT_PF(ifidx);
		vf_id = OCT_NIC_PORT_VF(ifidx);

		if (OCTEON_IS_MODEL(OCTEON_CN73XX_PASS1_0) && pf_id == 1) {
			//Due to a hw bug pf1 cannot have interrupt moderation turned on
			nicport->intmod_info.cfg.rx_enable = 0;
			nicport->intmod_info.cfg.tx_enable = 0;
			ret = OCTNET_CMD_FAIL;
			goto cfg_failure;
		}
		memcpy(&nicport->intmod_info.cfg, intrmod_cfg, sizeof(struct oct_intrmod_cfg));
		/* Adjust interval with cpu freq */
		nicport->intmod_info.cfg.check_intrvl *= (cpu_freq/INTRMOD_DIV);

		nicport->intmod_info.rxcnt_steps = ((nicport->intmod_info.cfg.rx_maxcnt_trigger-nicport->intmod_info.cfg.rx_mincnt_trigger) >> INTRMOD_INTRVL_SHIFT);
		/* this is  exponential */
		nicport->intmod_info.rxtmr_steps = ((uint32_t)((__log2(nicport->intmod_info.cfg.rx_maxtmr_trigger)-__log2(nicport->intmod_info.cfg.rx_mintmr_trigger)) + INTRMOD_INTRVL_LEVELS - 1) >> INTRMOD_INTRVL_SHIFT);
		nicport->intmod_info.txcnt_steps = ((nicport->intmod_info.cfg.tx_maxcnt_trigger-nicport->intmod_info.cfg.tx_mincnt_trigger) >> INTRMOD_INTRVL_SHIFT);

		if (nicport->intmod_info.cfg.rx_enable) {
			base_queue = nicport->oq_base;
			max_rings = nicport->linfo.num_rxpciq;
			cvmx_spinlock_lock(&oct->pp_pkt_csr_ctrl_lock);
			cvmx_write_csr(CVMX_SLI_PP_PKT_CSR_CONTROL, (uint64_t)((mac_id << 16) | (pf_id << 13) | (vf_id)));
			for (i = base_queue; i < (base_queue + max_rings); i++)
					cvmx_write_csr(CVMX_PEXP_SLI_PKTX_INT_LEVELS(i), (((uint64_t)
								nicport->intmod_info.cfg.rx_maxtmr_trigger) << 32) |
								nicport->intmod_info.cfg.rx_maxcnt_trigger);
			cvmx_spinlock_unlock(&oct->pp_pkt_csr_ctrl_lock);
		}
		if (nicport->intmod_info.cfg.tx_enable) {
			base_queue = nicport->iq_base;
			max_rings = nicport->linfo.num_txpciq;
			cvmx_spinlock_lock(&oct->pp_pkt_csr_ctrl_lock);
			cvmx_write_csr(CVMX_SLI_PP_PKT_CSR_CONTROL, (uint64_t)((mac_id << 16) | (pf_id << 13) | (vf_id)));
			for (i = base_queue; i < (base_queue + max_rings); i++)
					cvmx_write_csr(CVMX_PEXP_SLI_PKT_IN_DONEX_CNTS(i), (((uint64_t)
						       ((nicport->intmod_info.cfg.tx_maxcnt_trigger & 0xffffUL) << 32) | (1UL << 48))));
			cvmx_spinlock_unlock(&oct->pp_pkt_csr_ctrl_lock);
		}
	} else {
		if (intrmod_cfg->rx_enable) {
			intrmod_check_intrvl   = (intrmod_cfg->check_intrvl * cpu_freq);
			intrmod_maxpkt_ratethr = intrmod_cfg->maxpkt_ratethr;
			intrmod_minpkt_ratethr = intrmod_cfg->minpkt_ratethr;
			intrmod_maxcnt_trigger = intrmod_cfg->rx_maxcnt_trigger;
			intrmod_maxtmr_trigger = intrmod_cfg->rx_maxtmr_trigger;
			intrmod_mincnt_trigger = intrmod_cfg->rx_mincnt_trigger;
			intrmod_mintmr_trigger = intrmod_cfg->rx_mintmr_trigger;
			intmod_enable = 1;
			/* Initiate the values back to INTRMOD specific
			 * values */
			if (OCTEON_IS_MODEL(OCTEON_CN6XXX))
				cvmx_write_csr(CVMX_PEXP_SLI_PKT_INT_LEVELS, (((uint64_t)
								intrmod_maxtmr_trigger) << 32) |
						                intrmod_maxcnt_trigger);
		} else {
			intmod_enable = 0;
		}
	}

cfg_failure:

	if (f->irh.s.rflag && f->rptr) {
		retaddr = f->rptr + 8;
		if (OCTEON_IS_MODEL(OCTEON_CN73XX))
			cvm_pci_pvf_mem_writell(retaddr, ret, cvm_pcie_pvf_num(wqe));
		else
			cvm_pci_mem_writell(retaddr, ret);
	}

	cvm_free_wqe_wrapper(wqe);
	return;
}

int cvmcs_intrmod_params(cvmx_wqe_t * wqe)
{
	cvm_pci_dma_cmd_t cmd;
	cvmx_buf_ptr_t lptr;
	cvmx_buf_ptr_pki_t *bls; /* pki buffer link structure for Octeon III */
	cvm_dma_remote_ptr_t rptr;
	cvmx_raw_inst_front_t *f;
	uint64_t *buf;
	int ifidx = 0;
	struct oct_intrmod_cfg *intrmod_cfg;

        cmd.u64 = 0;
        lptr.u64 = 0;
        bls = (cvmx_buf_ptr_pki_t *)&lptr;

	if (octeon_has_feature(OCTEON_FEATURE_CN78XX_WQE))
		f = (cvmx_raw_inst_front_t *) cvmx_phys_to_ptr(cvmx_wqe_get_pki_pkt_ptr(wqe).addr);
	else
		f = (cvmx_raw_inst_front_t *)wqe->packet_data;

        ifidx = get_vnic_port_id(cvmx_wqe_get_port(wqe));
        cmd.s.pcielport = f->rdp.s.pcie_port;
        rptr.s.addr = f->rptr;
        rptr.s.size = f->rdp.s.rlen;

        if (cvmx_unlikely(rptr.s.size > CVMX_FPA_PACKET_POOL_SIZE)) {
                printf("[ DRV ] Cannot use packet pool buf for sending link info\n");
                return 1;
        }

        /* Re-use the packet pool buffer to send the link info to host. */
        buf = (uint64_t *) cvmx_phys_to_ptr(wqe->packet_ptr.s.addr);

        /* Reset all bytes so that unused fields don't have any value. */
        memset(buf, 0, rptr.s.size);
	intrmod_cfg = (struct oct_intrmod_cfg *)&buf[1];

	memcpy(intrmod_cfg, &octnic->port[ifidx].intmod_info.cfg, sizeof(struct oct_intrmod_cfg));

	intrmod_cfg->check_intrvl /= (cpu_freq/INTRMOD_DIV);

        if (octeon_has_feature(OCTEON_FEATURE_CN78XX_WQE)) {
                bls->size = rptr.s.size;
                bls->addr = CVM_DRV_GET_PHYS(buf);
                bls->packet_outside_wqe = 0;
        } else {
                lptr.s.size = rptr.s.size;
                lptr.s.addr = CVM_DRV_GET_PHYS(buf);
                lptr.s.i    = 1;
                lptr.s.pool = CVMX_FPA_PACKET_POOL;
                lptr.s.back = wqe->packet_ptr.s.back;
                cvm_update_bp(wqe);
                cvmx_wqe_free(wqe);
        }

        cmd.s.nl = cmd.s.nr = 1;

        if (OCTEON_IS_OCTEON3())
                return cvm_pci_dma_send_data_o3(&cmd, bls, &rptr, wqe, 1);
        else
                return cvm_pci_dma_send_data(&cmd, &lptr, &rptr);
}

int
cvmcs_nic_send_timestamp(cvmx_wqe_t *wqe)
{
	cvm_pci_dma_cmd_t      cmd;
	cvmx_buf_ptr_t         lptr;
	cvm_dma_remote_ptr_t   rptr;
	struct pko_rsp_buffer *tsb;
	uint64_t *buf;
	cvmx_timestamp_resp_t *resp;
	int pool_id = -1;

	cmd.u64  = 0;
	lptr.u64 = 0;

	pool_id = CVMX_FPA_PACKET_POOL;

	buf = cvmx_fpa_alloc(pool_id);
	if (cvmx_unlikely(!buf)) {
		printf("[ DRV ] failed to allocate timestamp return buffer.\n");
		return 1;
	}

	//TODO 78XX
	tsb = (struct pko_rsp_buffer *)wqe->packet_data;

	cmd.s.pcielport = tsb->inst.rdp.s.pcie_port;

	DBG2("Got Timestamp %016llu rptr.s.addr=%016llu size=%d\n",
			(long long unsigned int)tsb->data.ts,
			(long long unsigned int)tsb->inst.rptr,
			tsb->inst.rdp.s.rlen);

	/* Copy the timestamp from the WQE to the newly allocated buffer */
	resp = (cvmx_timestamp_resp_t *)buf;
	resp->timestamp = tsb->data.ts;
	resp->status = 0; /* done */

	rptr.s.addr = tsb->inst.rptr;
	rptr.s.size = tsb->inst.rdp.s.rlen;

	lptr.s.size = rptr.s.size;
	lptr.s.addr = CVM_DRV_GET_PHYS(buf);
	lptr.s.i    = 1;
	lptr.s.pool = CVMX_FPA_PACKET_POOL;

	cmd.s.nl = cmd.s.nr = 1;

	cvmcs_wqe_free(wqe);

	return cvm_pci_dma_send_data(&cmd, &lptr, &rptr);
}

/* Send the link status to the host, regardless of if it has changed because
 * rx_on has changed or a we have had a link status change.
 * All associated VFs must also get the status change
 */
void cvmcs_nic_pf_send_link_status(int ifidx)
{
	int i, gmxport, gmxport_id;
	union oct_link_status oldlink, pflink;
	union oct_link_status *linkptr;
	gmxport_id = octnic->port[ifidx].gmxport_id;

	if (!octnic->port[ifidx].state.present)
		return;

	linkptr = &octnic->port[ifidx].linfo.link;
	gmxport = octnic->port[ifidx].linfo.gmxport;

	oldlink.u64 = cvmx_atomic_get64((int64_t *)linkptr);
	oldlink.s.mtu = cvmx_atomic_get32(&octnic->port[ifidx].max_mtu);

	if (cvmcs_hybrid_get_link_status(ifidx) &&
	    (octnic->port[ifidx].state.rx_on)) {
		pflink.u64 = cvmcs_nic_update_link_status(oldlink,
							  gmxport_id, gmxport);
	} else {
		pflink.u64 = oldlink.u64;
		pflink.s.link_up = 0;
	}

	cvmx_atomic_set64((int64_t *)linkptr, pflink.u64);
	CVMX_SYNCW;

	cvmcs_nic_print_link_status(linkptr, ifidx, gmxport);

	/* Notify the PF driver */
	cvmcs_nic_cond_send_unsolicited_link_info(linkptr, ifidx);

	if (OCTEON_IS_MODEL(OCTEON_CN73XX)) {
#ifdef VSWITCH
		for (i = 0; i < (int)octnic->ngmxports; i++) {
			int j = 0;
			int idx = OCT_NIC_PORT_IDX(i, 0);
			for (j = idx + 1; j < idx + OCT_NIC_VFS_PER_PF; j++) {
				cvmcs_nic_vf_send_link_status(j);
			}
		}
#else
		/* Notify the all associated VFs. */
		for (i = ifidx + 1; i < ifidx + OCT_NIC_VFS_PER_PF; i++)
			cvmcs_nic_vf_send_link_status(i);
#endif	
	}

	if (!pflink.s.link_up)
		cvmcs_nic_set_link_status_led(ifidx);
}

void cvmcs_nic_vf_send_link_status(int ifidx)
{
	union oct_link_status pflink;
	union oct_link_status *vf;
	union oct_link_status *pf;
	int user_set_linkstate;

	if (!octnic->port[ifidx].state.present)
		return;

	vf = &octnic->port[ifidx].linfo.link;
	pf = &octnic->port[OCT_NIC_PORT_IDX(OCT_NIC_PORT_PF(ifidx), 0)].linfo.link;

	pflink.u64 = cvmx_atomic_get64((int64_t *)pf);

#ifdef VSWITCH
	user_set_linkstate = IFLA_VF_LINK_STATE_ENABLE;
#else
	user_set_linkstate = octnic->port[ifidx].user_set_linkstate;
#endif
	pflink.s.mtu = cvmx_atomic_get32(&octnic->port[ifidx].max_mtu);

	if (user_set_linkstate == IFLA_VF_LINK_STATE_ENABLE) {
		/* tell VF that the link is UP; ignore the true link state */
		pflink.s.link_up = 1;
	} else if (user_set_linkstate == IFLA_VF_LINK_STATE_DISABLE) {
		/* tell VF that the link is DOWN; ignore the true link state */
		pflink.s.link_up = 0;
	}

	cvmx_atomic_set64((int64_t *)vf, pflink.u64);
	CVMX_SYNCW;

	cvmcs_nic_cond_send_unsolicited_link_info(vf, ifidx);
}

/* Send the link status to the host, if any is online and changed.
 * This is to check actual link connectivity changes.
 */
void cvmcs_nic_check_link_status(void)
{
	uint32_t ifidx, i;

	/* Check all PF interfaces */
	for (i = 0; i < octnic->ngmxports; i++) {

		int gmxport,gmxport_id;
		union oct_link_status oldlink, newlink;
		union oct_link_status *linkptr;

		ifidx = OCT_NIC_PORT_IDX(i, 0);

		cvmcs_nic_phy_temp_check(ifidx);

#ifdef VSWITCH
		if ((!octnic->port[ifidx].state.present) ||
				(!(cvmcs_hybrid_get_link_status(ifidx) && octnic->port[ifidx].state.rx_on)))
			continue;
#else

		if (octnic->port[ifidx].state.present)
			cvmcs_nic_uboot_ctl_delay(ifidx);

		if ((!octnic->port[ifidx].state.present) ||
		    (!octnic->port[ifidx].state.rx_on))
			continue;
#endif
		gmxport = octnic->port[ifidx].linfo.gmxport;
		gmxport_id = octnic->port[ifidx].gmxport_id;
		linkptr = &octnic->port[ifidx].linfo.link;

		oldlink.u64 = cvmx_atomic_get64((int64_t *)linkptr);
		newlink.u64 = cvmcs_nic_update_link_status(oldlink, gmxport_id, gmxport);

		if (cvmx_sysinfo_get()->board_type == CVMX_BOARD_TYPE_NIC225E) {
			static struct {
				bool happened_prev;
				u64  prev_cycle;
			} errblks[2], bercnt[2];

			if (!newlink.s.link_up) {
				errblks[i].happened_prev = false;
				bercnt[i].happened_prev = false;

				if (!cvmcs_nic_phy_check(gmxport_id))
					newlink.u64 = cvmcs_nic_update_link_status(oldlink, gmxport_id, gmxport);
			} else {
				/* Link is up, but we need to monitor ERR_BLKS and BER_CNT.
				   If there are too many errors, then redo mod tuning on the Avago gearbox. */

				u64 cur_cycle, diff_cycle;
				bool retune_happened = false;
				cvmx_bgxx_spux_br_status2_t spu_br_status2;
				int index, iface;
				gmx_port_info_t *gmx_info = &octnic->gmx_port_info[gmxport_id];
				int ipd_port = gmx_info->ipd_port;
				int err_blks, ber_cnt;

				index = cvmx_helper_get_interface_index_num(ipd_port);
				iface = cvmx_helper_get_interface_num(ipd_port);

				cur_cycle = cvmx_get_cycle();
				spu_br_status2.u64 = cvmx_read_csr(CVMX_BGXX_SPUX_BR_STATUS2(index, iface));
				err_blks = spu_br_status2.s.err_blks;
				ber_cnt  = spu_br_status2.s.ber_cnt;

				if (err_blks > 5 || ber_cnt > 5) {
					printf("ifidx=%d err_blks=%d ber_cnt=%d, retune\n", ifidx, err_blks, ber_cnt);
					cvmcs_nic_phy_check(gmxport_id);
					newlink.u64 = cvmcs_nic_update_link_status(oldlink, gmxport_id, gmxport);
					retune_happened = true;
				}

				if (!retune_happened && err_blks > 0 && err_blks <= 5) {
					if (errblks[i].happened_prev) {
						diff_cycle = CYCLE_DIFF(cur_cycle, errblks[i].prev_cycle);
#define CYCLES_IN_10_SEC (10 * cpu_freq)
						if (diff_cycle < CYCLES_IN_10_SEC) {
							printf("ifidx=%d too many err_blks, retune\n", ifidx);
							cvmcs_nic_phy_check(gmxport_id);
							newlink.u64 = cvmcs_nic_update_link_status(oldlink, gmxport_id, gmxport);
							retune_happened = true;
						} else {
							errblks[i].prev_cycle = cur_cycle;
						}
					} else {
						errblks[i].happened_prev = true;
						errblks[i].prev_cycle = cur_cycle;
					}
				}

				if (!retune_happened && ber_cnt > 0 && ber_cnt <= 5) {
					if (bercnt[i].happened_prev) {
						diff_cycle = CYCLE_DIFF(cur_cycle, bercnt[i].prev_cycle);
						if (diff_cycle < CYCLES_IN_10_SEC) {
							printf("ifidx=%d ber_cnt too high, retune\n", ifidx);
							cvmcs_nic_phy_check(gmxport_id);
							newlink.u64 = cvmcs_nic_update_link_status(oldlink, gmxport_id, gmxport);
							retune_happened = true;
						} else {
							bercnt[i].prev_cycle = cur_cycle;
						}
					} else {
						bercnt[i].happened_prev = true;
						bercnt[i].prev_cycle = cur_cycle;
					}
				}

				if (retune_happened) {
					/* After a retune, disregard previous error occurrences. */
					errblks[i].happened_prev = false;
					bercnt[i].happened_prev = false;
				}
			}
		}

		/* We don't store newlink, as that is done in send link status */

		if (oldlink.u64 != newlink.u64)
			cvmcs_nic_pf_send_link_status(ifidx);

		if (OCTEON_IS_OCTEON3()) {
			if (!octnic->gmx_port_info[gmxport_id].link.s.flashing)
				cvmx_update_rx_activity_led(
					(INTERFACE(gmxport) & 0xff),
				    	INDEX(gmxport), 1);
		}
	}
}

/** Function to change settings of SGMII interface(auto negotiation speed and
 * duplex)
 **/
static int cvmcs_nic_sgmii_link_set(union oct_link_status *host, int port)
{
	union cvmx_pcsx_miscx_ctl_reg pcsx_miscx_ctl_reg;
	union cvmx_pcsx_mrx_control_reg pcsx_mrx_control_reg;
	int interface = INTERFACE(port);
	int index = INDEX(port);

	/* Turning on/off autonegotiation based on information sent by host
	 * by making changes to the bits pcsx_mrx_control_reg[an_en]
	 * and pcsx_miscx_ctl_reg[an_ovrd], making an_en = 0 and an_ovrd = 1
	 * will disable auto negotiation and making an_en = 1 and an_ovrd = 0
	 * will enable the auto negotiation
	 * */
	pcsx_mrx_control_reg.u64 =
	    cvmx_read_csr(CVMX_PCSX_MRX_CONTROL_REG(index, interface));
	pcsx_mrx_control_reg.s.an_en = host->s.autoneg;
	cvmx_write_csr(CVMX_PCSX_MRX_CONTROL_REG(index, interface),
		       pcsx_mrx_control_reg.u64);

	pcsx_miscx_ctl_reg.u64 =
	    cvmx_read_csr(CVMX_PCSX_MISCX_CTL_REG(index, interface));
	pcsx_miscx_ctl_reg.s.an_ovrd = ~host->s.autoneg;
	cvmx_write_csr(CVMX_PCSX_MISCX_CTL_REG(index, interface),
		       pcsx_miscx_ctl_reg.u64);

	/* Autoneg is ON */
	if (host->s.autoneg)
		cvmcs_nic_sgmii_link_autoneg_on(host, port);
	else
		cvmcs_nic_sgmii_link_autoneg_off(host, port);

	return 0;
}

/** Function to change settings of interface like auto negotiation
 * speed and duplex
 **/
int cvmcs_nic_change_settings(union oct_link_status * host, int port)
{
	int interface = INTERFACE(port);
	int index = INDEX(port);
	int gmx_id;

	if (!cvmx_helper_is_port_valid(interface, index))
		return 0;

	DBG2("%s : autoneg = %s\t phy = %s pause = %s\t interface is %d\t index is %d\n", __FUNCTION__, host->s.autoneg ? "ON" : "OFF", host->s.link_up ? "ON" : "OFF", host->s.pause ? "ON" : "OFF", interface, index);

	cvmcs_nic_sgmii_link_set(host, port);

	/* Program the EXTERNAL PHY with the received link settings */
	cvmcs_nic_change_phy_settings(host, port);

	/* update the octnic link autonegotiation status based on details
	 * sent by the host
	 */
	gmx_id = get_gmx_port_id(port);
	if (gmx_id != -1) {
		octnic->gmx_port_info[gmx_id].link.s.autoneg = host->s.autoneg;
		if (!host->s.autoneg) {
			octnic->gmx_port_info[gmx_id].link.s.speed = host->s.speed;
			octnic->gmx_port_info[gmx_id].link.s.duplex = host->s.duplex;
			octnic->gmx_port_info[gmx_id].link.s.link_up =
				host->s.link_up;
		}
	}
	return 0;
}


/** Function to complete Auto negotiation process of an
 * interface
 **/
static void cvmcs_nic_sgmii_link_autoneg_on(union oct_link_status * host, int port)
{
	int interface = INTERFACE(port);
	int index = INDEX(port);
	cvmx_helper_link_info_t link;

	union cvmx_pcsx_miscx_ctl_reg pcsx_miscx_ctl_reg;
	union cvmx_pcsx_linkx_timer_count_reg pcsx_linkx_timer_count_reg;
	union cvmx_gmxx_prtx_cfg gmxx_prtx_cfg;
	union cvmx_pcsx_mrx_control_reg pcsx_mrx_control_reg;

	const uint64_t clock_mhz =
	    cvmx_clock_get_rate(CVMX_CLOCK_SCLK) / 1000000;

	pcsx_miscx_ctl_reg.u64 =
	    cvmx_read_csr(CVMX_PCSX_MISCX_CTL_REG(index, interface));
	/* Disable gmexno , making mode = 0 ie..sgmii,mac_phy = 0 ie.. MAC mode */
	pcsx_miscx_ctl_reg.s.gmxeno = 1;
	pcsx_miscx_ctl_reg.s.mode = 0;
	pcsx_miscx_ctl_reg.s.mac_phy = 0;
	cvmx_write_csr(CVMX_PCSX_MISCX_CTL_REG(index, interface),
		       pcsx_miscx_ctl_reg.u64);

	/* Disable GMX */
	gmxx_prtx_cfg.u64 = cvmx_read_csr(CVMX_GMXX_PRTX_CFG(index, interface));
	gmxx_prtx_cfg.s.en = 0;
	cvmx_write_csr(CVMX_GMXX_PRTX_CFG(index, interface), gmxx_prtx_cfg.u64);

	pcsx_linkx_timer_count_reg.u64 =
	    cvmx_read_csr(CVMX_PCSX_LINKX_TIMER_COUNT_REG(index, interface));

	if (pcsx_miscx_ctl_reg.s.mode)	/* 1000BASE-X */
		pcsx_linkx_timer_count_reg.s.count =
		    (10000ull * clock_mhz) >> 10;
	else			/* SGMII */
		pcsx_linkx_timer_count_reg.s.count =
		    (1600ull * clock_mhz) >> 10;

	cvmx_write_csr(CVMX_PCSX_LINKX_TIMER_COUNT_REG(0, 1),
		       pcsx_linkx_timer_count_reg.u64);

	/* writing advertisement register based on mode bit and mac_phy bit */
	/* 1000BASE-X Mode */
	switch (pcsx_miscx_ctl_reg.s.mode) {
	case 1:
		{
			union cvmx_pcsx_anx_adv_reg pcsx_anx_adv_reg;
			DBG2("Writing advertisement register in 1000 base-x mode\n");
			/* 1000BASE-X */
			pcsx_anx_adv_reg.u64 =
			    cvmx_read_csr(CVMX_PCSX_ANX_ADV_REG(index, interface));
			pcsx_anx_adv_reg.s.rem_flt = 0;
			pcsx_anx_adv_reg.s.pause = 3;
			pcsx_anx_adv_reg.s.hfd = 1;
			pcsx_anx_adv_reg.s.fd = 1;
			cvmx_write_csr(CVMX_PCSX_ANX_ADV_REG(index, interface),
				       pcsx_anx_adv_reg.u64);
			break;
		}

	case 0:		/* SGMII Mode */
		{
			union cvmx_pcsx_sgmx_an_adv_reg pcsx_sgmx_an_adv_reg;
			if (pcsx_miscx_ctl_reg.s.mac_phy) {	/* SGMII PHY mode */
				DBG2("Writing advertisement register in SGMII-PHY mode\n");
				pcsx_sgmx_an_adv_reg.u64 =
				    cvmx_read_csr(CVMX_PCSX_SGMX_AN_ADV_REG
						  (index, interface));

				switch (host->s.duplex) {
				case 0:
					pcsx_sgmx_an_adv_reg.s.dup = 0;
					DBG2("Writing Half Duplex in advertisement register\n");
					break;

				case 1:
					pcsx_sgmx_an_adv_reg.s.dup = 1;
					DBG2("Writing Full Duplex in advertisement register\n");
					break;
				default:
					printf
					    ("Error: Unknown Value For Duplex Mode While Writing Advertisement Register\n");
				}

				switch (host->s.speed) {
				case 10:
					pcsx_sgmx_an_adv_reg.s.speed = 0;
					DBG2("Writing Speed 10Mbps in advertisement register\n");
					break;

				case 100:
					pcsx_sgmx_an_adv_reg.s.speed = 1;
					DBG2("Writing Speed 100Mbps in advertisement register\n");
					break;

				case 1000:
					pcsx_sgmx_an_adv_reg.s.speed = 2;
					DBG2("Writing Speed 1000Mbps in advertisement register\n");
					break;

				default:
					printf
					    ("Error: Unknown Value For Speed While Writing Advertisement Register\n");
				}
				cvmx_write_csr(CVMX_PCSX_SGMX_AN_ADV_REG
					       (index, interface),
					       pcsx_sgmx_an_adv_reg.u64);

			} else {	/* MAC Mode */

				/* MAC Mode - Nothing to do since transmitting advertisement is send by external PHY */
				DBG2("Advertisement Register Is Sent to External PHY Chip \n");
			}
		}

		break;

	default:
		printf("Error: Unknown PCS Mode \n");
	}

	/* Take PCS through a reset sequence. pcsx_mrx_CONTROL_REG[PWR_DN] should be
	 * cleared to zero and make pcsx_mrx_control_reg[reset] = 1
	 *
	 **/
	pcsx_mrx_control_reg.u64 =
	    cvmx_read_csr(CVMX_PCSX_MRX_CONTROL_REG(index, interface));
	pcsx_mrx_control_reg.s.pwr_dn = 0;
	pcsx_mrx_control_reg.s.reset = 1;

	cvmx_write_csr(CVMX_PCSX_MRX_CONTROL_REG(0, 1),
		       pcsx_mrx_control_reg.u64);
	if (CVMX_WAIT_FOR_FIELD64
	    (CVMX_PCSX_MRX_CONTROL_REG(index, interface),
	     cvmx_pcsx_mrx_control_reg_t, reset, ==, 0, 50000)) {
		cvmx_dprintf
		    ("SGMII%d: Timeout waiting for port %d to finish reset\n",
		     interface, index);
	}

	/*   Write PCSX_MRX_CONTROL_REG[RST_AN] = 1 to ensure a fresh sgmii negotiation starts. */
	pcsx_mrx_control_reg.s.rst_an = 1;
	cvmx_write_csr(CVMX_PCSX_MRX_CONTROL_REG(index, interface),
		       pcsx_mrx_control_reg.u64);
	CVMX_WAIT_FOR_FIELD64(CVMX_PCSX_MRX_STATUS_REG(index, interface),
			      union cvmx_pcsx_mrx_status_reg, an_cpt, ==, 1,
			      10000);

	/* this gets the status of the link based on autonegotiation results register pcsx_anx_results_reg */
	link = cvmcs_get_link_status_autoneg_on(port);

	/* setting up gmx according to the above link structure */
	gmxx_prtx_cfg.s.duplex = link.s.full_duplex;
	switch (link.s.speed) {
	case 10:
		gmxx_prtx_cfg.s.speed = 0;
		gmxx_prtx_cfg.s.speed_msb = 1;
		gmxx_prtx_cfg.s.slottime = 0;
		pcsx_miscx_ctl_reg.s.samp_pt = 0x32;
		cvmx_write_csr(CVMX_GMXX_TXX_SLOT(index, interface), 64);
		cvmx_write_csr(CVMX_GMXX_TXX_BURST(index, interface), 0);
		break;
	case 100:
		gmxx_prtx_cfg.s.speed = 0;
		gmxx_prtx_cfg.s.speed_msb = 0;
		gmxx_prtx_cfg.s.slottime = 0;
		pcsx_miscx_ctl_reg.s.samp_pt = 0x5;
		cvmx_write_csr(CVMX_GMXX_TXX_SLOT(index, interface), 64);
		cvmx_write_csr(CVMX_GMXX_TXX_BURST(index, interface), 0);
		break;
	case 1000:
		gmxx_prtx_cfg.s.speed = 1;
		gmxx_prtx_cfg.s.speed_msb = 0;
		gmxx_prtx_cfg.s.slottime = 1;
		pcsx_miscx_ctl_reg.s.samp_pt = 1;
		cvmx_write_csr(CVMX_GMXX_TXX_SLOT(index, interface), 512);
		if (gmxx_prtx_cfg.s.duplex)
			/* Full Duplex */
			cvmx_write_csr(CVMX_GMXX_TXX_BURST(index, interface),
				       0);
		else
			/* Half Duplex */
			cvmx_write_csr(CVMX_GMXX_TXX_BURST(index, interface),
				       8192);

		break;
	default:
		printf
		    ("Error Setting Unknown Speed for GMX in Autoneg ON Condition\n");
		break;
	}

	/* Write the new misc control for PCS */
	cvmx_write_csr(CVMX_PCSX_MISCX_CTL_REG(index, interface),
		       pcsx_miscx_ctl_reg.u64);

	/* Write the new GMX settings with the port still disabled */
	cvmx_write_csr(CVMX_GMXX_PRTX_CFG(index, interface), gmxx_prtx_cfg.u64);

	/* Read GMX CFG again to make sure the config completed */
	gmxx_prtx_cfg.u64 = cvmx_read_csr(CVMX_GMXX_PRTX_CFG(index, interface));

	/* Restore the enabled state */
	gmxx_prtx_cfg.s.en = 1;
	cvmx_write_csr(CVMX_GMXX_PRTX_CFG(index, interface), gmxx_prtx_cfg.u64);

	pcsx_miscx_ctl_reg.u64 =
	    cvmx_read_csr(CVMX_PCSX_MISCX_CTL_REG(index, interface));
	pcsx_miscx_ctl_reg.s.gmxeno = 0;
	cvmx_write_csr(CVMX_PCSX_MISCX_CTL_REG(index, interface),
		       pcsx_miscx_ctl_reg.u64);
}


/** Function to change settings of interface like speed and duplex
 * when  auto negotiation is off and also update interface link info
 * structure
 * */
static void cvmcs_nic_sgmii_link_autoneg_off(union oct_link_status *host, int port)
{
	int interface = INTERFACE(port);
	int index = INDEX(port);
	cvmx_helper_link_info_t link;
	union cvmx_pcsx_mrx_control_reg pcsx_mrx_control_reg;

	/* set speed setting and duplex setting in pcsx_mrx_control_reg and fill
	 * link structure used to configure GMX according to speed and duplex
	 * parameters passed by user
	 **/
	pcsx_mrx_control_reg.u64 =
	    cvmx_read_csr(CVMX_PCSX_MRX_CONTROL_REG(index, interface));
	link.s.speed = host->s.speed;
	switch ((host->s.speed)) {
	case 10:
		/*speed is 10 ,pcsx_mrx_control_reg[spdmsb]= 0 and ,pcsx_mrx_control_reg[spdlsb]= 0 */
		/*speed is 10 ,pcsx_mrx_control_reg[spdmsb]=0 and ,pcsx_mrx_control_reg[spdlsb]=0 */
		pcsx_mrx_control_reg.s.spdlsb = 0;
		pcsx_mrx_control_reg.s.spdmsb = 0;
		break;

	case 100:
		/*speed is 100 ,pcsx_mrx_control_reg[spdmsb]=0 and ,pcsx_mrx_control_reg[spdlsb]=1 */
		pcsx_mrx_control_reg.s.spdlsb = 1;
		pcsx_mrx_control_reg.s.spdmsb = 0;
		break;

	case 1000:
		/*speed is 1000 ,pcsx_mrx_control_reg[spdmsb]=1 and ,pcsx_mrx_control_reg[spdlsb]=0 */
		pcsx_mrx_control_reg.s.spdlsb = 0;
		pcsx_mrx_control_reg.s.spdmsb = 1;
		break;

	default:
		printf
		    ("Error: Unknown Speed Setting Received From Host For Autoneg OFF Condition \n");
	}

	if (host->s.duplex > 1)
		printf
		    ("Error: Unknown Duplex Setting Received From Host For Autoneg OFF Condition\n");
	link.s.full_duplex = host->s.duplex;
	pcsx_mrx_control_reg.s.dup = link.s.full_duplex;
	cvmx_write_csr(CVMX_PCSX_MRX_CONTROL_REG(index, interface),
		       pcsx_mrx_control_reg.u64);

	/* SDK executive API to set GMX. This can be used only for autoneg off condition */
	__cvmx_helper_sgmii_link_set(port, link);
}

int cvmcs_do_mdio_read_write(int ifidx, int mdio_op, int location, int value)
{
	cvmx_phy_info_t phy_info;
	uint64_t val = -1;
	int port = 0;
	static int page_no[8] = { 0 };
	uint16_t phy_id;

	port = octnic->port[ifidx].linfo.gmxport;

	if (cvmx_helper_board_get_phy_info(&phy_info, port) < 0) {
		printf("Couldnt get info about PHY\n");
		return -1;
	}

	if (phy_info.phy_addr < 0) {
		printf("%s: PHY address invalid for port %d\n", __func__, port);
		return -1;
	}
	/* read PHY id 1 */
	phy_id =
	    cvmx_mdio_read(phy_info.phy_addr >> 8, phy_info.phy_addr & 0xff, 2);

	if (phy_id != 0x141) {
		/* Not a MVL phy */
		return -1;
	}

	if (mdio_op) {
		if (location == 22)	/* write to page reg */
			page_no[ifidx] = value;
		DBG2("Writing %x @ %x for phy_addr %x on page %d\n", value,
		     location, phy_info.phy_addr, page_no[ifidx]);
		cvmx_mdio_write(phy_info.phy_addr >> 8,
				phy_info.phy_addr & 0xff, 22, page_no[ifidx]);
		cvmx_mdio_write(phy_info.phy_addr >> 8,
				phy_info.phy_addr & 0xff, location, value);
		cvmx_mdio_write(phy_info.phy_addr >> 8,
				phy_info.phy_addr & 0xff, 22, 0);
	} else {
		cvmx_mdio_write(phy_info.phy_addr >> 8,
				phy_info.phy_addr & 0xff, 22, page_no[ifidx]);
		val =
		    cvmx_mdio_read(phy_info.phy_addr >> 8,
				   phy_info.phy_addr & 0xff, location);
		cvmx_write_csr(CVMX_PEXP_SLI_SCRATCH_2, val);
		DBG2("Read val 0x%lx at page 0x%x_0x%x for phy addr 0x%x\n",
		     val, page_no[ifidx], location, phy_info.phy_addr);
		cvmx_mdio_write(phy_info.phy_addr >> 8,
				phy_info.phy_addr & 0xff, 22, 0);
	}

	return 0;
}

#ifdef FLOW_ENGINE
int 
cvmcs_register_flow_engine_ops(int ifidx, int feature)
{
	cfe_dispatch_entry_t *flow_dispatch;
	cvmcs_component_t *comp;
	int ret =0;

	flow_dispatch = &octnic->cfe_dispatch_tbl[ifidx];
	flow_dispatch->vport = &octnic->port[ifidx];
	flow_dispatch->cmpnts_enabled |= CFE_OP_EN(feature) ;
	comp = octnic->cfe_components[feature -1];

	if (comp->lut_init) {
		ret = comp->lut_init(flow_dispatch, (hash_node_t **)&flow_dispatch->cmpnt_lut[feature-1], feature);
		if (ret) {
			printf("Failure in lut_init:: %s: vport:%d cmpnts_idx:%d features:%X \n",
			       __func__, ifidx,
			       octnic->cfe_dispatch_tbl[ifidx].cmpnts_max,
			       feature);
			return -1;
		}
	}

	printf("%s: vport:%d cmpnts_idx:%d features:%X \n", __func__,
	       ifidx, octnic->cfe_dispatch_tbl[ifidx].cmpnts_max, feature);
	octnic->cfe_dispatch_tbl[ifidx].cmpnts_max++;
	return 0;
}
#endif

int cvmcs_nic_cfg_ioqueues_cn66xx(int ifidx, int num_iqueues, int num_oqueues, unsigned int base_queue)
{
	int j,pci_port;
	int queue;
	int num_ports_used;

	//all queues belonging to one pci port (32 ..35)
	//should belong to one ifidx(thats a restriction for now)
	if (base_queue == BASE_QUEUE_NOT_REQUESTED) {
		if (num_iqueues >  (octnic->free_q_info.cn66xx.free_pci_ports_iqs*8)) {
			printf("too many iqs  numqs %d numfree %d\n",
				  num_iqueues, (octnic->free_q_info.cn66xx.free_pci_ports_iqs*8));
			return 1;
		}
		if (num_oqueues > (octnic->free_q_info.cn66xx.free_pci_ports_oqs*8)) {
			printf("too many oqs or numqs %d numfree %d\n",
				  num_oqueues, (octnic->free_q_info.cn66xx.free_pci_ports_oqs*8));
			return 1;
		}

		pci_port = 4-octnic->free_q_info.cn66xx.free_pci_ports_iqs;
		queue = 0;
		num_ports_used=1;
		printf("PCI port %d:\n", pci_port);
		for (j = 0; j < num_iqueues; j++) {
			if (queue == 8) {
				queue = 0;
				pci_port++;
				num_ports_used++;
			}
			octnic->port[ifidx].linfo.txpciq[j].s.q_no = pci_port+(queue*4);
			octnic->port[ifidx].linfo.txpciq[j].s.port = ifidx;
			octnic->port[ifidx].iq_mask |= (1UL << (pci_port+(queue*4)));
			printf("  %d: IQ%02d mask 0x%016lx\n", queue, (pci_port+(queue*4)), octnic->port[ifidx].iq_mask);
			octnic->port[ifidx].linfo.num_txpciq++;
			octnic->vnic_ids[32 + pci_port] = ifidx;
			queue++;
		}
		octnic->free_q_info.cn66xx.free_pci_ports_iqs -=  num_ports_used;
		pci_port = 4-octnic->free_q_info.cn66xx.free_pci_ports_oqs;
		queue = 0;
		num_ports_used=1;
		for (j = 0; j <  num_oqueues; j++) {
			if (queue == 8) {
				queue = 0;
				pci_port++;
				num_ports_used++;
			}
			octnic->port[ifidx].linfo.rxpciq[j].s.q_no = pci_port+(queue*4);
			octnic->port[ifidx].oq_mask |= (1UL << (pci_port+(queue*4)));
			octnic->port[ifidx].linfo.num_rxpciq++;
			queue++;
		}
		octnic->free_q_info.cn66xx.free_pci_ports_oqs -=  num_ports_used;
	} else {
		if (num_iqueues >  MAX_PCI_QUEUES_66XX) {
			printf("too many iqs numqs %d numfree %d\n",
				  num_iqueues, (octnic->free_q_info.cn66xx.free_pci_ports_iqs*8));
			return 1;
		}
		if(num_oqueues > (MAX_DROQS_66XX)) {
			printf("too many oqs numqs %d numfree %d\n",
				  num_oqueues, (octnic->free_q_info.cn66xx.free_pci_ports_oqs*8));
			return 1;
		}
		for (j = 0; j < num_iqueues; j++) {
			queue = (base_queue+j) & (MAX_PCI_QUEUES_66XX-1);
			octnic->port[ifidx].linfo.txpciq[j].s.q_no = queue;
			octnic->port[ifidx].linfo.txpciq[j].s.port = ifidx;
			octnic->port[ifidx].iq_mask |= (1UL << queue);
			printf("  %d: IQ%02d mask 0x%016lx\n", j, queue, octnic->port[ifidx].iq_mask);
			octnic->port[ifidx].linfo.num_txpciq++;
			octnic->vnic_ids[32 + (queue & 0x3)] = ifidx;
		}
		for (j = 0; j <  num_oqueues; j++) {
			queue = (base_queue+j) & (MAX_DROQS_66XX-1);
			octnic->port[ifidx].linfo.rxpciq[j].s.q_no = queue;
			octnic->port[ifidx].oq_mask |= (1UL << queue);
			octnic->port[ifidx].linfo.num_rxpciq++;
			queue++;
		}
	}

	octnic->port[ifidx].iq_base = 0;
	octnic->port[ifidx].oq_base = 0;

	octnic->port[ifidx].state.active = 1;
	CVMX_SYNCWS;
	return 0;
}

int cvmcs_nic_cfg_ioqueues_cn68xx(int ifidx, int num_iqueues, int num_oqueues, unsigned int base_queue)
{
	int j;
	int queue;

	if (base_queue  == BASE_QUEUE_NOT_REQUESTED) {
		//68xx has individual pci ipd ports for each input queue and output queue	
		//so any queue can go to any ifidx.
		if (num_iqueues >  (octnic->free_q_info.cn68xx.num_free_iqs)) {
			printf("too many iqs\n");
			return 1;
		}
		if (num_oqueues >  (octnic->free_q_info.cn68xx.num_free_oqs)) {
			printf("too many oqs\n");
			return 1;
		}
		for (j = 0; j <  num_iqueues; j++) {
			queue = (ffs(octnic->free_q_info.cn68xx.free_iq_mask)-1); //1 based
			octnic->free_q_info.cn68xx.free_iq_mask &= (~(1UL << queue));
			octnic->free_q_info.cn68xx.num_free_iqs--;
			octnic->port[ifidx].linfo.txpciq[j].s.q_no = queue;
			octnic->port[ifidx].linfo.txpciq[j].s.port = ifidx;
			octnic->port[ifidx].iq_mask |= (1UL << queue);
			octnic->port[ifidx].linfo.num_txpciq++;
			octnic->vnic_ids[queue] = ifidx;
		}
		for (j = 0; j <  num_oqueues; j++) {
			queue = (ffs(octnic->free_q_info.cn68xx.free_oq_mask)-1);//1 based
			octnic->free_q_info.cn68xx.free_oq_mask &= (~(1UL << queue));
			octnic->free_q_info.cn68xx.num_free_oqs--;
			octnic->port[ifidx].linfo.rxpciq[j].s.q_no = queue;
			octnic->port[ifidx].oq_mask |= (1UL << queue);
			octnic->port[ifidx].linfo.num_rxpciq++;
		}
	} else {
		if (num_iqueues >  MAX_PCI_QUEUES_68XX) {
			printf("too many iqs\n");
			return 1;
		}
		if (num_oqueues >  MAX_DROQS_68XX) {
			printf("too many oqs\n");
			return 1;
		}
		for (j = 0; j <  num_iqueues; j++) {
			queue = (base_queue + j) & (MAX_PCI_QUEUES_68XX-1);
			octnic->port[ifidx].linfo.txpciq[j].s.q_no = queue;
			octnic->port[ifidx].linfo.txpciq[j].s.port = ifidx;
			octnic->port[ifidx].iq_mask |= (1UL << queue);
			octnic->port[ifidx].linfo.num_txpciq++;
			octnic->vnic_ids[queue] = ifidx;
		}
		for (j = 0; j <  num_oqueues; j++) {
			queue = (base_queue + j) & (MAX_DROQS_68XX-1);
			octnic->port[ifidx].linfo.rxpciq[j].s.q_no = queue;
			octnic->port[ifidx].oq_mask |= (1UL << queue);
			octnic->port[ifidx].linfo.num_rxpciq++;
		}
	}

	octnic->port[ifidx].iq_base = 0;
	octnic->port[ifidx].oq_base = 0;

	octnic->port[ifidx].state.active = 1;
	CVMX_SYNCWS;
	return 0;
}

int cvmcs_nic_cfg_ioqueues_cn78xx(int ifidx, int num_iqueues, int num_oqueues, unsigned int base_queue)
{
	int j;
	int interface, queue;
	int bpid, qpg;
	int node, ipd_port;
	char name[1024];
	cvmx_xport_t xport;
	cvmx_fpa3_pool_t pool;
	cvmx_fpa3_gaura_t aura;
	struct cvmx_pki_qpg_config qpg_config;
	cvmx_fpa_poolx_available_t avail_reg;

	node = cvmx_get_node_num();

	interface = cvmcs_get_npi_interface();

	if (base_queue  == BASE_QUEUE_NOT_REQUESTED) {
		printf("firmware controlled allocation\n");
		//78xx has individual pci ipd ports for each input queue and output queue	
		//so any queue can go to any ifidx.
		if (num_iqueues >  (octnic->free_q_info.cn78xx.num_free_iqs)) {
			printf("too many iqs\n");
			return 1;
		}
		if (num_oqueues >  (octnic->free_q_info.cn78xx.num_free_oqs)) {
			printf("too many oqs\n");
			return 1;
		}
	} else {
		printf("host controlled allocation\n");
		if (num_iqueues >  MAX_PCI_QUEUES_78XX) {
			printf("too many iqs\n");
			return 1;
		}
		if (num_oqueues >  MAX_DROQS_78XX) {
			printf("too many oqs\n");
			return 1;
		}
	}

	/* if DCB is not enabled, we allocate one aura per port */

	bpid = cvmx_pki_bpid_alloc(node, CVMX_PKI_FIND_AVAL_ENTRY);

	if (bpid < 0) {
		printf("ERROR: %s BP ID allocation failed\n", __func__);
		return -1;
	}

	pool = cvmx_fpa3_aura_to_pool(
		cvmx_fpa1_pool_to_fpa3_aura(CVMX_FPA_PACKET_POOL));

	sprintf(name,"port%d_aura", ifidx);

	/* Avoid a warning message from SDK; don't request an 
	 * AURA buffer count that is above POOL buffer count
	 * (use the 'available' count instead of 'FPA_PACKET_POOL_COUNT').
	 * See bug 21146.
	 */
	avail_reg.u64 = cvmx_read_csr_node(pool.node,
		CVMX_FPA_POOLX_AVAILABLE(pool.lpool)); 
	aura = cvmx_fpa3_set_aura_for_pool(pool, -1, name,
		CVMX_FPA_PACKET_POOL_SIZE, avail_reg.cn78xx.count);

	if (!__cvmx_fpa3_aura_valid(aura)) {
		cvmx_pki_bpid_free(node, bpid);
		printf("ERROR: %s AURA %d alloc failed\n", __func__, aura.laura);
		return -1;
	}

	cvmx_pki_write_aura_bpid(node, aura.laura, bpid);

	cvmx_helper_setup_aura_qos(node, aura.laura, 0, 0, 256, 512,
		1, DPI_BP_THRESHOLD_78XX);

	qpg_config.qpg_base = -1;
	qpg_config.port_add = 0;
	qpg_config.aura_num = aura.laura;
	qpg_config.grp_ok = 0;
	qpg_config.grp_bad = 0;
	qpg_config.grptag_ok = 0;
	qpg_config.grptag_bad = 0;

	qpg = cvmx_helper_pki_set_qpg_entry(node, &qpg_config);

	if (qpg < 0) {
		cvmx_fpa3_release_aura(aura);
		cvmx_pki_bpid_free(node, bpid);
		printf("ERROR: %s qpg entry alloc failed\n", __func__);
		return -1;
	}

	if (base_queue  == BASE_QUEUE_NOT_REQUESTED) {
		for (j = 0; j <  num_iqueues; j++) {
			queue = (ffs(octnic->free_q_info.cn78xx.free_iq_mask)-1); //1 based
			octnic->free_q_info.cn78xx.free_iq_mask &= (~(1UL << queue));
			octnic->free_q_info.cn78xx.num_free_iqs--;
			octnic->port[ifidx].linfo.txpciq[j].s.q_no = queue;
			octnic->port[ifidx].iq_mask |= (1UL << queue);
			octnic->port[ifidx].linfo.num_txpciq++;

			ipd_port = cvmx_helper_get_ipd_port(interface, queue);
			xport = cvmx_helper_ipd_port_to_xport(ipd_port);
			cvmx_pki_write_channel_bpid(node, xport.port, bpid);

			octnic->port[ifidx].linfo.txpciq[j].s.port = ifidx;
			octnic->port[ifidx].linfo.txpciq[j].s.pkind =
				cvmx_helper_get_pknd(interface, queue);
			octnic->port[ifidx].linfo.txpciq[j].s.use_qpg = 1;
			octnic->port[ifidx].linfo.txpciq[j].s.qpg = qpg;

			octnic->vnic_ids[queue] = ifidx;
		}
		for (j = 0; j <  num_oqueues; j++) {
			queue = (ffs(octnic->free_q_info.cn78xx.free_oq_mask)-1);//1 based
			octnic->free_q_info.cn78xx.free_oq_mask &= (~(1UL << queue));
			octnic->free_q_info.cn78xx.num_free_oqs--;
			octnic->port[ifidx].linfo.rxpciq[j].s.q_no = queue;
			octnic->port[ifidx].oq_mask |= (1UL << queue);
			octnic->port[ifidx].linfo.num_rxpciq++;
		}
	} else {
		for (j = 0; j <  num_iqueues; j++) {
			queue = (base_queue + j) & (MAX_PCI_QUEUES_78XX-1);
			octnic->port[ifidx].linfo.txpciq[j].s.q_no = queue;
			octnic->port[ifidx].iq_mask |= (1UL << queue);
			octnic->port[ifidx].linfo.num_txpciq++;

			ipd_port = cvmx_helper_get_ipd_port(interface, queue);
			xport = cvmx_helper_ipd_port_to_xport(ipd_port);
			cvmx_pki_write_channel_bpid(node, xport.port, bpid);

			octnic->port[ifidx].linfo.txpciq[j].s.port = ifidx;
			octnic->port[ifidx].linfo.txpciq[j].s.pkind =
				cvmx_helper_get_pknd(interface, queue);
			octnic->port[ifidx].linfo.txpciq[j].s.use_qpg = 1;
			octnic->port[ifidx].linfo.txpciq[j].s.qpg = qpg;

			octnic->vnic_ids[queue] = ifidx;
		}
		for (j = 0; j <  num_oqueues; j++) {
			queue = (base_queue + j) & (MAX_DROQS_78XX-1);
			octnic->port[ifidx].linfo.rxpciq[j].s.q_no = queue;
			octnic->port[ifidx].oq_mask |= (1UL << queue);
			octnic->port[ifidx].linfo.num_rxpciq++;
		}
	}

	octnic->port[ifidx].iq_base = 0;
	octnic->port[ifidx].oq_base = 0;

	octnic->port[ifidx].state.active = 1;
	CVMX_SYNCWS;
	return 0;
}

static void cvmcs_cleanup_queue_info(int ifidx, int base_queue)
{
	int j;
	int node, ipd_port;
	int interface, queue;
	int bpid, qpg, ctrl_qpg, aura_num;
	uint64_t aura_cnt;
	cvmx_xport_t xport;
	cvmx_fpa3_gaura_t aura;
	cvmx_pki_aurax_cfg_t pki_aura_cfg;
	struct cvmx_pki_qpg_config qpg_config;

	node = cvmx_get_node_num();
	for (j = 0; j <  octnic->port[ifidx].linfo.num_rxpciq; j++) {
		octnic->port[ifidx].linfo.rxpciq[j].s.q_no = 0;
	}

	interface = cvmcs_get_npi_interface();
	octnic->port[ifidx].oq_mask = 0;
	octnic->port[ifidx].linfo.num_rxpciq = 0;

	if (octnic->port[ifidx].linfo.octlinux_uqpg) {
		qpg = octnic->port[ifidx].linfo.octlinux_qpg;

		qpg_config.qpg_base = qpg;
		qpg_config.port_add = 0;
		qpg_config.aura_num = 0;
		qpg_config.grp_ok = 0;
		qpg_config.grp_bad = 0;
		qpg_config.grptag_ok = 0;
		qpg_config.grptag_bad = 0;

		cvmx_pki_write_qpg_entry(node, qpg, &qpg_config);
		cvmx_pki_qpg_entry_free(node, qpg, 1);
	}


	for (j = 0; j <  octnic->port[ifidx].linfo.num_txpciq; j++) {
		aura_num = octnic->port[ifidx].linfo.txpciq[j].s.aura_num;
		aura_cnt = cvmx_read_csr_node(node,
					      CVMX_FPA_AURAX_CNT(aura_num));
		if(aura_cnt - 32) {
			printf("WARNING: there are still %lu buffers left in "
			       "AURA-%d of ifidx-%d, txpciq-%d at the time of "
			       "queue cleanup\n",
			       aura_cnt - 32, aura_num, ifidx, j);
		}
		queue = base_queue + j;

		ipd_port = cvmx_helper_get_ipd_port(interface, queue);
		xport = cvmx_helper_ipd_port_to_xport(ipd_port);
		cvmx_pki_write_channel_bpid(node, xport.port, 0);

		qpg = octnic->port[ifidx].linfo.txpciq[j].s.qpg;

		cvmx_pki_read_qpg_entry(node, qpg, &qpg_config);

		aura = __cvmx_fpa3_gaura(node, qpg_config.aura_num);

		qpg_config.qpg_base = qpg;
		qpg_config.port_add = 0;
		qpg_config.aura_num = 0;
		qpg_config.grp_ok = 0;
		qpg_config.grp_bad = 0;
		qpg_config.grptag_ok = 0;
		qpg_config.grptag_bad = 0;

		cvmx_pki_write_qpg_entry(node, qpg, &qpg_config);

		cvmx_pki_qpg_entry_free(node, qpg, 1);

		ctrl_qpg = octnic->port[ifidx].linfo.txpciq[j].s.ctrl_qpg;

		cvmx_pki_read_qpg_entry(node, ctrl_qpg, &qpg_config);

		qpg_config.qpg_base = ctrl_qpg;

		cvmx_pki_write_qpg_entry(node, ctrl_qpg, &qpg_config);

		cvmx_pki_qpg_entry_free(node, ctrl_qpg, 1);

		cvmx_helper_setup_aura_qos(node, aura.laura, 0, 0, 256, 512, 0, 0);

		pki_aura_cfg.u64 = cvmx_read_csr_node(node, CVMX_PKI_AURAX_CFG(aura.laura));
		bpid = pki_aura_cfg.s.bpid;
		pki_aura_cfg.s.bpid = 0;
		cvmx_write_csr_node(node, CVMX_PKI_AURAX_CFG(aura.laura), pki_aura_cfg.u64);

		cvmx_pki_bpid_free(node, bpid);

		/* this call is commented out to make AURA allocation static
		 * TODO: add if any conditional shutdown required
		 **/
//		cvmx_fpa3_shutdown_aura(aura);

		octnic->port[ifidx].linfo.txpciq[j].s.q_no = 0;

		octnic->port[ifidx].linfo.txpciq[j].s.port = 0;
		octnic->port[ifidx].linfo.txpciq[j].s.pkind = 0;
		octnic->port[ifidx].linfo.txpciq[j].s.use_qpg = 0;
		octnic->port[ifidx].linfo.txpciq[j].s.qpg = 0;
		octnic->port[ifidx].linfo.txpciq[j].s.ctrl_qpg = 0;

		octnic->vnic_ids[queue] = 0;
	}

	octnic->port[ifidx].iq_mask = 0;
	octnic->port[ifidx].linfo.num_txpciq = 0;
}


int cvmcs_nic_cfg_ioqueues_cn73xx(int ifidx, int num_iqueues, int num_oqueues, unsigned int base_queue)
{
	int j, max_rings;
	int pf_id, vf_id;
	int interface, queue;
	int bpid, qpg, ctrl_qpg;
	int node, ipd_port;
	char name[1024];
	cvmx_xport_t xport;
	cvmx_fpa3_pool_t pool;
	cvmx_fpa3_gaura_t aura;
	struct cvmx_pki_qpg_config qpg_config;
	union cvmx_sli_pkt_macx_pfx_rinfo rinfo;
	int pf_srn = -1;
	uint64_t reg;
	int gmxport_id = octnic->port[ifidx].gmxport_id;
	int gmx_ipd_port = octnic->gmx_port_info[gmxport_id].ipd_port;
	cvmx_pki_chanx_cfg_t chan_cfg;
	cvmx_fpa_poolx_available_t avail_reg;

	node = cvmx_get_node_num();

	interface = cvmcs_get_npi_interface();

	pf_id = OCT_NIC_PORT_PF(ifidx);
	vf_id = OCT_NIC_PORT_VF(ifidx);

	if (OCTEON_IS_MODEL(OCTEON_CN73XX_PASS1_0)) {
try_again:
		rinfo.u64 = cvmx_read_csr(CVMX_PEXP_SLI_PKT_MACX_PFX_RINFO(pf_id, 0));
		if (rinfo.u64==0xffffffffffffffffULL) {
			/* fix for bugs 17151 and 17413 */
			goto try_again;
		}
		/* Fix for BP 'corruption' bug (19473, comment #8). Enable BP on ALL of PF's rings. */
		reg = !pf_id ? CVMX_PEXP_SLI_PKT_OUT_BP_EN_W1S : CVMX_PEXP_SLI_PKT_OUT_BP_EN2_W1S;
		cvmx_write_csr(reg, 0xFFFFFFFFFFFFFFFFULL);
	} else {
		cvmx_sli_pp_pkt_csr_control_t pktcsr;
		pktcsr.s.mac = 0;
		pktcsr.s.pvf = (pf_id << 13);
		cvmx_spinlock_lock(&oct->pp_pkt_csr_ctrl_lock);
		cvmx_write_csr(CVMX_SLI_PP_PKT_CSR_CONTROL, pktcsr.u64);
		rinfo.u64 = cvmx_read_csr(CVMX_PEXP_SLI_PKT_MACX_PFX_RINFO(pf_id, 0));
		/* Fix for BP 'corruption' bug (19473, comment #8). Enable BP on ALL of PF's rings. */
		reg = !pf_id ? CVMX_PEXP_SLI_PKT_OUT_BP_EN_W1S : CVMX_PEXP_SLI_PKT_OUT_BP_EN2_W1S;
		cvmx_write_csr(reg, 0xFFFFFFFFFFFFFFFFULL);
		cvmx_spinlock_unlock(&oct->pp_pkt_csr_ctrl_lock);
	}

	if (vf_id > rinfo.s.nvfs) {
		printf("PF = %d VF = %d is not provisioned\n", pf_id, vf_id);
		return 1;
	}

	if (vf_id == 0){
		base_queue = rinfo.s.srn + rinfo.s.rpvf * rinfo.s.nvfs;
		max_rings = rinfo.s.trs - rinfo.s.rpvf * rinfo.s.nvfs;
		pf_srn = rinfo.s.srn;
	} else {
		base_queue = rinfo.s.srn + (rinfo.s.rpvf * (vf_id - 1));
		max_rings = rinfo.s.rpvf;
	}

	if (num_iqueues > max_rings) {
		num_iqueues = max_rings;
	}

	if (num_oqueues > max_rings) {
		num_oqueues = max_rings;
	}

	if ((num_iqueues <=0) || (num_oqueues <= 0)) {
		return -1;
	}

	for (j = 0; j <  num_iqueues; j++) {
		bpid = cvmx_pki_bpid_alloc(node, CVMX_PKI_FIND_AVAL_ENTRY);

		if (bpid < 0) {
			printf("ERROR: %s BP ID allocation failed\n", __func__);
			goto cleanup_err;
		}

		pool = cvmx_fpa3_aura_to_pool(
			cvmx_fpa1_pool_to_fpa3_aura(CVMX_FPA_PACKET_POOL));

		sprintf(name,"port%d_aura", ifidx);

		if (octnic->port[ifidx].linfo.txpciq[j].s.aura_num) {
			aura = __cvmx_fpa3_gaura(node,
				octnic->port[ifidx].linfo.txpciq[j].s.aura_num);
		} else {
			/* Avoid a warning message from SDK; don't request an 
			 * AURA buffer count that is above POOL buffer count
			 * (use the 'available' count instead of 'FPA_PACKET_POOL_COUNT')
			 * See bug 21146.
			 */
			avail_reg.u64 = cvmx_read_csr_node(pool.node,
				CVMX_FPA_POOLX_AVAILABLE(pool.lpool)); 
			aura = cvmx_fpa3_set_aura_for_pool(pool, -1, name,
						CVMX_FPA_PACKET_POOL_SIZE,
						avail_reg.cn78xx.count);
		}

		if (!__cvmx_fpa3_aura_valid(aura)) {
			cvmx_pki_bpid_free(node, bpid);
			printf("ERROR: %s AURA %d alloc failed\n", __func__, aura.laura);
			goto cleanup_err;
		}

		cvmx_pki_write_aura_bpid(node, aura.laura, bpid);

		cvmx_helper_setup_aura_qos(node, aura.laura, 0, 0, 0, DPI_BP_THRESHOLD_78XX, 1, DPI_BP_THRESHOLD_78XX);

		qpg_config.qpg_base = -1;
		qpg_config.port_add = 0;
		qpg_config.aura_num = aura.laura;
		qpg_config.grp_ok = OCTEON_DATA_GRP;
		qpg_config.grp_bad = 0;
		qpg_config.grptag_ok = 0;
		qpg_config.grptag_bad = 0;

		qpg = cvmx_helper_pki_set_qpg_entry(node, &qpg_config);

		if (qpg < 0) {
			cvmx_fpa3_release_aura(aura);
			cvmx_pki_bpid_free(node, bpid);
			printf("ERROR: %s qpg entry alloc failed\n", __func__);
			goto cleanup_err;
		}

		/*Allocate another qpg for Control Packets */
		qpg_config.qpg_base = -1;

		if (OCT_NIC_IS_PF(ifidx))
			qpg_config.grp_ok = OCTEON_CTRL_GRP_PF;
		else
			qpg_config.grp_ok = OCTEON_CTRL_GRP_VF;

		ctrl_qpg = cvmx_helper_pki_set_qpg_entry(node, &qpg_config);

		if (ctrl_qpg < 0) {
			cvmx_fpa3_release_aura(aura);
			cvmx_pki_bpid_free(node, bpid);
			printf("ERROR: %s ctrl_qpg entry alloc failed\n", __func__);
			goto cleanup_err;
		}

		octnic->port[ifidx].linfo.txpciq[j].s.aura_num = aura.laura;

		DBG("ifidx = %d queue = %d allocated input aura = %d "
		       "bpid = %d qpg = %d ctrl_qpg = %d\n", ifidx, j,
		       aura.laura, bpid, qpg, ctrl_qpg);

		queue = base_queue + j;
		octnic->port[ifidx].linfo.txpciq[j].s.q_no = j;
		octnic->port[ifidx].iq_mask |= (1UL << j);
		octnic->port[ifidx].linfo.num_txpciq++;

		ipd_port = cvmx_helper_get_ipd_port(interface, queue);
		xport = cvmx_helper_ipd_port_to_xport(ipd_port);
		cvmx_pki_write_channel_bpid(node, xport.port, bpid);

		octnic->port[ifidx].linfo.txpciq[j].s.port = ifidx;
		octnic->port[ifidx].linfo.txpciq[j].s.pkind =
			cvmx_helper_get_pknd(interface, queue);
		octnic->port[ifidx].linfo.txpciq[j].s.use_qpg = 1;
		octnic->port[ifidx].linfo.txpciq[j].s.qpg = qpg;
		octnic->port[ifidx].linfo.txpciq[j].s.ctrl_qpg = ctrl_qpg;

		octnic->vnic_ids[queue] = ifidx;
	}

#ifdef VSWITCH
	qpg_config.qpg_base = -1;
	qpg_config.port_add = 0;
	qpg_config.aura_num = octnic->port[ifidx].linfo.txpciq[0].s.aura_num;
	qpg_config.grp_ok = LINUX_POW_DATA_GROUP;
	qpg_config.grp_bad = 0;
	qpg_config.grptag_ok = 0;
	qpg_config.grptag_bad = 0;

	qpg = cvmx_helper_pki_set_qpg_entry(node, &qpg_config);
	if (qpg < 0) {
		printf("ERROR: %s qpg entry alloc failed\n", __func__);
		goto cleanup_err;
	}

	octnic->port[ifidx].linfo.octlinux_qpg = qpg;
	octnic->port[ifidx].linfo.octlinux_uqpg = 1;
#endif


	xport = cvmx_helper_ipd_port_to_xport(gmx_ipd_port);
	chan_cfg.u64 = cvmx_read_csr_node(node, CVMX_PKI_CHANX_CFG(xport.port));
	printf("BPID of BGX port-%d is %u\n", gmx_ipd_port, chan_cfg.s.bpid);
	octnic->gmx_port_info[gmxport_id].chan0_bpid = chan_cfg.s.bpid;

	for (j = 0; j <  num_oqueues; j++) {
		octnic->port[ifidx].linfo.rxpciq[j].s.q_no = j;
		octnic->port[ifidx].oq_mask |= (1UL << j);
		octnic->port[ifidx].linfo.num_rxpciq++;
	}

	octnic->port[ifidx].iq_base = base_queue;
	octnic->port[ifidx].oq_base = base_queue;
	if (vf_id == 0)
		octnic->port[ifidx].pf_srn = pf_srn;
	else
		octnic->port[ifidx].pf_srn = -1;

	octnic->port[ifidx].intmod_info.cfg.check_intrvl   = (LIO_INTRMOD_CHECK_INTERVAL*cpu_freq)/INTRMOD_DIV;
	octnic->port[ifidx].intmod_info.cfg.maxpkt_ratethr = LIO_INTRMOD_MAXPKT_RATETHR;	/* intrmod:maxpktrate threshold */
	octnic->port[ifidx].intmod_info.cfg.minpkt_ratethr = LIO_INTRMOD_MINPKT_RATETHR;	/* intrmod:minpktrate threshold */

	octnic->port[ifidx].intmod_info.cfg.rx_maxcnt_trigger = LIO_INTRMOD_RXMAXCNT_TRIGGER;	/* intrmod:maxpktcnt threshold */
	octnic->port[ifidx].intmod_info.cfg.rx_mincnt_trigger = LIO_INTRMOD_RXMINCNT_TRIGGER;	/* intrmod:minpktcnt threshold */
	octnic->port[ifidx].intmod_info.cfg.rx_maxtmr_trigger = LIO_INTRMOD_RXMAXTMR_TRIGGER;	/* intrmod:maxtimer threshold */
	octnic->port[ifidx].intmod_info.cfg.rx_mintmr_trigger = LIO_INTRMOD_RXMINTMR_TRIGGER;	/* intrmod:mintimer threshold */

	octnic->port[ifidx].intmod_info.cfg.tx_maxcnt_trigger = LIO_INTRMOD_TXMAXCNT_TRIGGER;	/* intrmod:maxpktcnt threshold */
	octnic->port[ifidx].intmod_info.cfg.tx_mincnt_trigger = LIO_INTRMOD_TXMINCNT_TRIGGER;	/* intrmod:minpktcnt threshold */

	for (j = 0; j < MAX_IOQS_PER_NICIF; j++) {
		octnic->port[ifidx].intmod_info.last_rxfwd_pkts[j] = 0;
		octnic->port[ifidx].intmod_info.last_rxfwd_bytes[j] = 0;
		octnic->port[ifidx].intmod_info.last_txfwd_pkts[j] = 0;
		octnic->port[ifidx].intmod_info.last_txfwd_bytes[j] = 0;
	}
	octnic->port[ifidx].intmod_info.last_check = 0;
	octnic->port[ifidx].intmod_info.rxcnt_steps = ((LIO_INTRMOD_RXMAXCNT_TRIGGER - LIO_INTRMOD_RXMINCNT_TRIGGER) >> INTRMOD_INTRVL_SHIFT);
	/* this is  exponential */
	octnic->port[ifidx].intmod_info.rxtmr_steps = ((uint32_t)((__log2(LIO_INTRMOD_RXMAXTMR_TRIGGER)-__log2(LIO_INTRMOD_RXMINTMR_TRIGGER)) + INTRMOD_INTRVL_LEVELS - 1 ) >> INTRMOD_INTRVL_SHIFT);
	octnic->port[ifidx].intmod_info.txcnt_steps = ((LIO_INTRMOD_TXMAXCNT_TRIGGER - LIO_INTRMOD_TXMINCNT_TRIGGER) >> INTRMOD_INTRVL_SHIFT);

	octnic->port[ifidx].intmod_info.cfg.rx_enable         = 1; //on by default
	octnic->port[ifidx].intmod_info.cfg.tx_enable         = 1; //on by default

	octnic->port[ifidx].state.active = 1;
	CVMX_SYNCWS;
	return 0;
cleanup_err:
	cvmcs_cleanup_queue_info(ifidx, base_queue);
	return -1;
}

static int cvmcs_nic_reset_ioqueues_cn73xx(int ifidx)
{
	int j;
	int pf_id, vf_id, mac_id;
	int base_queue, max_queues;
	union cvmx_sli_pkt_macx_pfx_rinfo rinfo;
	uint64_t csr_val;

	pf_id = OCT_NIC_PORT_PF(ifidx);
	vf_id = OCT_NIC_PORT_VF(ifidx);
	/* mac fixed at 0 (per all other accesses to SLI_PP_PKT_CSR_CONTROL) */
	mac_id = 0;

	if (OCTEON_IS_MODEL(OCTEON_CN73XX_PASS1_0)) {
try_again:
		rinfo.u64 = cvmx_read_csr(CVMX_PEXP_SLI_PKT_MACX_PFX_RINFO(pf_id, 0));
		if (rinfo.u64==0xffffffffffffffffULL) {
			/* fix for bugs 17151 and 17413 */
			goto try_again;
		}
	} else {
	/* CSR lock begin --- */
		cvmx_spinlock_lock(&oct->pp_pkt_csr_ctrl_lock);

		/* obtain SLI_PKT_MACX_PFX_RINFO reg using PF (VF==0) */
		cvmx_write_csr(CVMX_SLI_PP_PKT_CSR_CONTROL,
				(uint64_t)((mac_id << 16) | (pf_id << 13) | 0));
		rinfo.u64 = cvmx_read_csr(CVMX_PEXP_SLI_PKT_MACX_PFX_RINFO(pf_id, 0));

		/*
		 * This is part of fix for zero-length packet (and others) which
		 * occurred when VF/VM was destroyed while traffic was ongoing.
		 * See also 'cvmcs_nic_if_reset_start/complete().'
		 *
		 * Per hardware team, HRM v0.985E is incorrect;
		 * only these regs are reset by FLR:
		 *   SLI_MSIX_TABLE_ADDR/DATA
		 *   SLI_PBA0/PBA1
		 *
		 * All others need to be reset per "ring initialization sequence",
		 * which we do here.  See HRM sections (HRM v0.985E):
		 *     16.1.4.2/3.1
		 *     16.1.4.2/3.2
		 *     16.1.4.2/3.5
		 *     16.1.4.2/3.6
		 *     16.1.4.2/3.9
		 *     16.1.4.2/3.10
		 *
		 */

		cvmx_write_csr(CVMX_SLI_PP_PKT_CSR_CONTROL,
				(uint64_t)((mac_id << 16) | (pf_id << 13) | (vf_id)));

		if (vf_id == 0) {
			/* for PF, don't add-in 'srn'; we need an index of 0..63 */
			base_queue = (rinfo.s.rpvf * rinfo.s.nvfs);
			max_queues = rinfo.s.trs - (rinfo.s.rpvf * rinfo.s.nvfs);
		} else {
			/* for VF, ring CSRs are 0...(rinfo.s.rpvf-1) */
			base_queue = 0;
			max_queues = rinfo.s.rpvf;
		}

		for (j = base_queue; j < (base_queue + max_queues); j++) {
			/* HRM 16.1.4.2/3.1 */
			cvmx_write_csr(CVMX_PEXP_SLI_PKTX_INSTR_BAOFF_DBELL(j), 0xffffffffULL);

			/* HRM 16.1.4.2/3.2 */
			/* read CNT */
			csr_val = cvmx_read_csr(CVMX_PEXP_SLI_PKT_IN_DONEX_CNTS(j)) & 0xffffffffULL;
			/* set max WMARK */
			csr_val |= 0xffff00000000ULL;
			cvmx_write_csr(CVMX_PEXP_SLI_PKT_IN_DONEX_CNTS(j), csr_val);

			/* HRM 16.1.4.2/3.5 */
			cvmx_write_csr(CVMX_PEXP_SLI_PKTX_SLIST_BAOFF_DBELL(j), 0xffffffffULL);

			/* HRM 16.1.4.2/3.6 */
			cvmx_write_csr(CVMX_PEXP_SLI_PKTX_CNTS(j),
					cvmx_read_csr(CVMX_PEXP_SLI_PKTX_CNTS(j)) & 0xffffffffULL);

			/* HRM 16.1.4.2/3.9 */
			cvmx_write_csr(CVMX_PEXP_SLI_PKTX_INT_LEVELS(j), 0x3fffffffffffffULL);

			/* HRM 16.1.4.2/3.10 */
			if (vf_id != 0) {
				/* for VF, write MBOX_INT */
				cvmx_write_csr(CVMX_PEXP_SLI_PKTX_MBOX_INT(j), (1ULL << 61));
			} else {
				/* for PF, write [all] VF_INT */
				cvmx_write_csr(CVMX_PEXP_SLI_MACX_PFX_MBOX_INT(pf_id, mac_id), 0xffffffffffffffffULL);
			}
		}

		cvmx_spinlock_unlock(&oct->pp_pkt_csr_ctrl_lock);
	/* CSR lock end --- */
	}

	if (vf_id > rinfo.s.nvfs) {
		printf("PF = %d VF = %d is not provisioned\n", pf_id, vf_id);
		return 1;
	}
	
	if (vf_id == 0){
		base_queue = rinfo.s.srn + rinfo.s.rpvf * rinfo.s.nvfs;
	} else {
		base_queue = rinfo.s.srn + (rinfo.s.rpvf * (vf_id - 1));
	}

	octnic->port[ifidx].state.active = 0;

	octnic->port[ifidx].iq_base = 0;
	octnic->port[ifidx].oq_base = 0;
	octnic->port[ifidx].pf_srn = -1;

	octnic->port[ifidx].intmod_info.cfg.rx_enable = 0;
	octnic->port[ifidx].intmod_info.cfg.tx_enable = 0;

	cvmcs_cleanup_queue_info(ifidx, base_queue);

	CVMX_SYNCWS;
	return 0;
}

int cvmcs_nic_cfg_ioqueues(int ifidx, int num_iqueues, int num_oqueues, unsigned int base_queue)
{
	if (OCTEON_IS_MODEL(OCTEON_CN66XX)) {
		return cvmcs_nic_cfg_ioqueues_cn66xx(ifidx, num_iqueues, num_oqueues, base_queue);
	} else if  (OCTEON_IS_MODEL(OCTEON_CN68XX)) {
		return cvmcs_nic_cfg_ioqueues_cn68xx(ifidx, num_iqueues, num_oqueues, base_queue);
	} else if  (OCTEON_IS_MODEL(OCTEON_CN78XX)) {
		return cvmcs_nic_cfg_ioqueues_cn78xx(ifidx, num_iqueues, num_oqueues, base_queue);
	} else if  (OCTEON_IS_MODEL(OCTEON_CN73XX)) {
		return cvmcs_nic_cfg_ioqueues_cn73xx(ifidx, num_iqueues, num_oqueues, base_queue);
	} else {
		printf("unsupported board\n");
		return 1;
	}
}

static int cvmcs_nic_reset_ioqueues(int ifidx)
{
	if (OCTEON_IS_MODEL(OCTEON_CN66XX)) {
		return 0;
	} else if  (OCTEON_IS_MODEL(OCTEON_CN68XX)) {
		return 0;
	} else if  (OCTEON_IS_MODEL(OCTEON_CN78XX)) {
		return 0;
		/*return cvmcs_nic_reset_ioqueues_cn78xx(ifidx);*/
	} else if  (OCTEON_IS_MODEL(OCTEON_CN73XX)) {
		return cvmcs_nic_reset_ioqueues_cn73xx(ifidx);
	} else {
		printf("unsupported board\n");
		return 1;
	}
}

static void cvmcs_send_vf_drv_notice_to_pf(int ifidx, int notice, uint64_t param)
{
	unsigned vf_num, pf_num;
	uint8_t *buf;
	union octeon_rh *rh;
	cvmx_buf_ptr_t lptr;
	uint32_t pf_control_droq_no;
	int pf_ifidx;
	uint64_t *data;

	vf_num = OCT_NIC_PORT_VF(ifidx);

	if (vf_num == 0)
		return;

	pf_num   = OCT_NIC_PORT_PF(ifidx);
	pf_ifidx = OCT_NIC_PORT_IDX(pf_num, 0);

	pf_control_droq_no = OCT_NIC_OQ_NUM(&octnic->port[pf_ifidx], 0);

	buf = (uint8_t *) cvm_drv_fpa_alloc_sync(CVMX_FPA_PACKET_POOL);
	if (buf == NULL) {
		printf("\n\n[ DRV ] Failed to send OPCODE_NIC_VF_DRV_NOTICE!!!\n");
		return;
	}

	rh            = (union octeon_rh *)buf;
	rh->u64       = 0;
	rh->r.opcode  = OPCODE_NIC;
	rh->r.subcode = OPCODE_NIC_VF_DRV_NOTICE;
	rh->r.ossp    = notice;

	data    = (uint64_t *)(buf + sizeof(*rh));
	data[0] = vf_num;
	data[1] = param;

	lptr.u64    = 0;
	lptr.s.size = sizeof (union octeon_rh) + 2 * sizeof (uint64_t);
	lptr.s.addr = CVM_DRV_GET_PHYS(buf);
	lptr.s.pool = CVMX_FPA_PACKET_POOL;
	lptr.s.i    = 1;

	CVMX_SYNCWS;

	cvm_send_pci_pko_direct(lptr, CVM_DIRECT_DATA, 1, lptr.s.size, pf_control_droq_no);
}

int cvmcs_nic_if_cfg(cvmx_wqe_t *wqe)
{
	cvm_pci_dma_cmd_t cmd;
	cvmx_buf_ptr_t lptr;
	cvm_dma_remote_ptr_t rptr;
	cvmx_raw_inst_front_t *f;
	int front_size;
	uint64_t *buf;
	unsigned int pf_id, vf_id=0, ifidx;
	uint64_t num_iqueues, num_oqueues;
	struct liquidio_if_cfg_info *cinfo;
	union oct_nic_if_cfg  if_cfg;
	unsigned int base_queue;
	unsigned int gmx_port_id;
	uint16_t pvf_num;
	struct lio_version *vdatap;

	cmd.u64 = 0;
	lptr.u64 = 0;

	if (octeon_has_feature(OCTEON_FEATURE_CN78XX_WQE))
		f = (cvmx_raw_inst_front_t *) cvmx_phys_to_ptr(cvmx_wqe_get_pki_pkt_ptr(wqe).addr);
	else
		f = (cvmx_raw_inst_front_t *)wqe->packet_data;

	if (f->irh.s.rflag)
		front_size = CVM_RAW_FRONT_SIZE;
	else
		front_size = CVM_RAW_FRONT_SIZE-16; /* rptr and rdp are not there so don't count them */

	/* Liquidio PF/VF driver version */
	vdatap = (struct lio_version *)((uint8_t *)f + front_size);
	if (vdatap->major != LIQUIDIO_BASE_MAJOR_VERSION) {
		DBG("Driver version: %d %d %d\n", vdatap->major, vdatap->minor, vdatap->micro);
	}

	if_cfg.u64 = f->ossp[0];
	num_iqueues = if_cfg.s.num_iqueues;
	num_oqueues = if_cfg.s.num_oqueues;
	base_queue = if_cfg.s.base_queue;
	gmx_port_id = if_cfg.s.gmx_port_id;

	if (OCTEON_IS_MODEL(OCTEON_CN73XX)) {
		pvf_num = cvm_pcie_pvf_num(wqe);
		vf_id = pvf_num & 0x1FFF;
		pf_id = pvf_num >> 13;
		if (vf_id)
			gmx_port_id = pf_id;
	} else {
		vf_id = 0;
		pf_id = gmx_port_id;
	}

	ifidx = OCT_NIC_PORT_IDX(pf_id, vf_id);

	printf("nic_if_cfg: GMX%u: Host requested %lu IQs and %lu OQs ",
		gmx_port_id, num_iqueues, num_oqueues);

	if (base_queue == BASE_QUEUE_NOT_REQUESTED)
		printf("(base_queue auto-select)\n");
	else
		printf("(Host requested base queue %d).\n", base_queue);

	cmd.s.pcielport = f->rdp.s.pcie_port;
	rptr.s.addr = f->rptr;
	rptr.s.size = f->rdp.s.rlen;
	if (ifidx > (octnic->max_nic_ports-1))
		return  1;
	if (gmx_port_id > (octnic->ngmxports -1))
		return 1;
	if (octnic->port[ifidx].state.active) {
		printf("ifidx=0x%x already configured\n", ifidx);
		return 1;
	}
	add_port_to_nic(ifidx, gmx_port_id);

	cvmcs_cleanup_queue_info(ifidx, base_queue);
	if (cvmcs_nic_cfg_ioqueues(ifidx, num_iqueues, num_oqueues, base_queue)) {
		printf("error ifidx confg\n");
		return 1;
	}

	//add vfs to components
	cvmcs_hybrid_add_vfs(ifidx, gmx_port_id, f->ossp[1]);

	if (cvmcs_nic_init_dpi_bp(ifidx)) {
		printf("error configuring dpi Backpressure\n");
		return 1;
	}

	if (OCT_NIC_IS_PF(ifidx)) {
		octnic->port[ifidx].speed_get = octnic->uparam[ifidx].speed_get;
		octnic->port[ifidx].rsfec_get = octnic->uparam[ifidx].rsfec_get;
	}
		
        cvmcs_nic_change_mac_state(ifidx, 0);

#ifdef FLOW_ENGINE
	if (cvmcs_register_flow_engine_ops(ifidx, CFE_DEFAULT_OP)) {
		printf("error registering flow engine\n");
		return 1;
	}
#endif

	if (cvmx_unlikely(rptr.s.size > CVMX_FPA_PACKET_POOL_SIZE)) {
		printf
		    ("[ DRV ] Cannot use packet pool buf for sending link info\n");
		return 1;
	}

	/* Re-use the packet pool buffer to send the link info to host. */
	buf = (uint64_t *) cvmx_phys_to_ptr(wqe->packet_ptr.s.addr);

	/* Reset all bytes so that unused fields don't have any value. */
	DBG2("rptr. size %d\n", rptr.s.size);
	memset(buf, 0, rptr.s.size);

	if (octeon_has_feature(OCTEON_FEATURE_PKI)) {
		((cvmx_buf_ptr_pki_t *)&lptr)->addr = CVM_DRV_GET_PHYS(buf);
		((cvmx_buf_ptr_pki_t *)&lptr)->size = rptr.s.size;
	} else {
		lptr.s.addr = CVM_DRV_GET_PHYS(buf);
		lptr.s.size = rptr.s.size;
	}

	/* First 8 bytes is response header. No information in it.
	   The link data starts from byte offset 8. */

	cinfo = (struct liquidio_if_cfg_info *)&buf[1];
	cinfo->linfo.link.u64 = 0;

	printf("Sending cfg resp ifidx %d iqmask 0x%016lx oqmask 0x%016lx\n",
			ifidx, octnic->port[ifidx].iq_mask, octnic->port[ifidx].oq_mask);
	cinfo->iqmask =  octnic->port[ifidx].iq_mask;
	cinfo->oqmask =  octnic->port[ifidx].oq_mask;
	memcpy(cinfo->liquidio_firmware_version, LIQUIDIO_FW_VERSION, sizeof(LIQUIDIO_FW_VERSION)); 

	if (cvmcs_nic_prepare_link_info_pkt(ifidx, (uint64_t *)&cinfo->linfo) == 0) {
		printf("[ DRV ] prepare link info pkt failed\n");
		return 1;
	}

	if (OCTEON_IS_OCTEON3()) {
		if (vf_id) {
			uint16_t vid = octnic->port[ifidx].user_set_vlanTCI & 0xFFF;
			if (vid)
				cvmcs_nic_add_vlan(ifidx, vid);

			cvmcs_send_vf_drv_notice_to_pf(ifidx, VF_DRV_LOADED, 0);
		}

		cmd.s.nl = cmd.s.nr = 1;
		return cvm_pci_dma_send_data_o3(&cmd, (cvmx_buf_ptr_pki_t *)&lptr, &rptr, wqe, 1);
	} else {
		lptr.s.i    = 1;
		lptr.s.pool = CVMX_FPA_PACKET_POOL;
		lptr.s.back = wqe->packet_ptr.s.back;
		cmd.s.nl = cmd.s.nr = 1;
		cvm_update_bp(wqe);
		cvmx_wqe_free(wqe);
		CVMX_SYNCWS;
		return cvm_pci_dma_send_data(&cmd, &lptr, &rptr);
	}
}

/*
 * Used to reset an interface upon receipt of an FLR.
 * NOTE: this is stage 1 of a two-stage process;
 *       see also 'cvmcs_nic_if_reset_complete()'
 *       see also 'cn73xx_flr_intr_handler_bh()' for description of FLR process.
 * on entry,
 *    ifidx:      interface id
 * returns,
 *    0:  OK
 *    !0: interface did not exist
 */
int cvmcs_nic_if_reset_start(int ifidx)
{
	cvmx_spinlock_t *if_reset_lock = &octnic->port[ifidx].if_reset_lock;

	cvmx_spinlock_lock(if_reset_lock);

	if (!octnic->port[ifidx].state.present) {
		cvmx_spinlock_unlock(if_reset_lock);
		printf("ifidx %d : Port does not exist\n", ifidx);
		return 1;
	}

	/* Part of fix for zero-length packet (and others) which occurred
	 * when VF/VM was destroyed while traffic was incoming.
	 * See also 'cvmcs_nic_reset_ioqueues_cn73xx().'
	 *
	 * Wait, with state 'rx_on' disabled;
	 * this allows in-flight packets to be discarded.
	 *
	 * Note, wait will be performed by caller.
	 */

	if (octnic->port[ifidx].state.rx_on) {
                cvmcs_nic_change_mac_state(ifidx, 0);
	}

	cvmx_spinlock_unlock(if_reset_lock);

	return 0;
}

/*
 * Used to reset an interface upon receipt of an FLR.
 * NOTE: this is stage 2 of a multi-stage process;
 *       see also 'cvmcs_nic_if_reset_start()'
 *       see also 'cvmcs_nic_if_reset_finalize()'
 *       see also 'cn73xx_flr_intr_handler_bh()' for description of FLR process.
 * on entry,
 *    ifidx:      interface id
 *
 * returns 0
 */
int cvmcs_nic_if_reset_complete(int ifidx)
{
	int uc_count;
	cvmx_spinlock_t *if_reset_lock = &octnic->port[ifidx].if_reset_lock;

	cvmx_spinlock_lock(if_reset_lock);

	cvmcs_nic_reset_ioqueues(ifidx);

	del_port_from_nic(ifidx);

	cvmx_spinlock_lock(&octnic->port[ifidx].ucast_table_lock);
	uc_count = octnic->port[ifidx].ucast_count;
	if (uc_count) {
		uint64_t *macaddr;
		gmx_port_info_t *info;
		int gmxport_id, i;

		gmxport_id = octnic->port[ifidx].gmxport_id;
		info = &octnic->gmx_port_info[gmxport_id];
		macaddr = octnic->port[ifidx].ucast_table;
		for (i = 0; i < uc_count; i++)
			cvmcs_remove_mac_from_hash_table(info, macaddr[i], ifidx);

		octnic->port[ifidx].ucast_count = 0;
	}
	cvmx_spinlock_unlock(&octnic->port[ifidx].ucast_table_lock);

	if (OCT_NIC_PORT_VF(ifidx))
		cvmcs_send_vf_drv_notice_to_pf(ifidx, VF_DRV_REMOVED, 0);

	cvmx_spinlock_unlock(if_reset_lock);

	return 0;
}

/*
 * Used to restore interface configuration upon finalization of an FLR.
 * NOTE: this is stage 3 of a multi-stage process;
 *       see also 'cvmcs_nic_if_reset_start()'
 *       see also 'cvmcs_nic_if_reset_complete()'
 *       see also 'cn73xx_flr_intr_handler_bh()' for description of FLR process.
 * on entry,
 *    ifidx:      interface id
 *
 * returns 0
 */
int cvmcs_nic_if_reset_finalize(int ifidx)
{
	cvmx_spinlock_t *if_reset_lock = &octnic->port[ifidx].if_reset_lock;

	cvmx_spinlock_lock(if_reset_lock);

	/* for PF, rewrite pci config space reg 0 */
	if (octnic->pci_cfgspace_reg0 && !OCT_NIC_PORT_VF(ifidx)) {
		union cvmx_spemx_cfg_wr cfg_wr;
		cfg_wr.u64 = 0;
		cfg_wr.s.addr =
			(OCT_NIC_PORT_PF((unsigned)ifidx) << 24) | 0 /* ie. reg 0 */;
		cfg_wr.s.data = octnic->pci_cfgspace_reg0;
		cvmx_write_csr_node(cvmx_get_node_num(),
							CVMX_SPEMX_CFG_WR(0), cfg_wr.u64);
	}

	/* for PF, some boards also need a rewrite of pci config space reg 2 */
	if (octnic->pci_cfgspace_reg2 && !OCT_NIC_PORT_VF(ifidx)) {
		union cvmx_spemx_cfg_wr cfg_wr;
		cfg_wr.u64 = 0;
		cfg_wr.s.addr =
			(OCT_NIC_PORT_PF((unsigned)ifidx) << 24) | 8 /* ie. reg 8 */;
		cfg_wr.s.data = octnic->pci_cfgspace_reg2;
		cvmx_write_csr_node(cvmx_get_node_num(),
							CVMX_SPEMX_CFG_WR(0), cfg_wr.u64);
	}

	cvmx_spinlock_unlock(if_reset_lock);

	return 0;
}

void clear_mcast_cache(int gmxport_id, int ifidx)
{
	mcast_ifl_t *entry;
	int i = 0;
	hash_node_t *head, *node, *prev;
	gmx_port_info_t *info = &octnic->gmx_port_info[gmxport_id];

	/* Iterate through entire hash table and clear this ifidx
	 * from every entry. If the entry is empty free it.
	 */
	head = info->vnic_mcast_lut;
	for (i = 0; i < MCAST_LUT_SIZE; i++, head++) {
		hash_for_each_node(node, head) {
			entry = (mcast_ifl_t*)hlist_entry(node, mcast_ifl_t, list);
			iflist_clear(&entry->ifl, ifidx);
			iflist_set_last(&entry->ifl);
			iflist_set_active(&entry->ifl);
			if((entry->ifl.last == 0) &&
			   (!iflist_on(&entry->ifl, 0))) {
				/* Free this entry. Tricky since we're iterating
				 * on the list.
				 */
				prev = node->prev;
				hash_node_del(node);
				free_mcast_ifl(&info->vnic_mcast_free, entry);
				node = prev;
			}
		}
	}

	DBG("VNIC%d cleared MCAST cache\n", ifidx);
}

/* Add to mcast cache */
void add_to_mcast_cache(int gmxport_id,
				      uint64_t macaddr,
				      int ifidx)
{
	mcast_ifl_t *p;
	gmx_port_info_t *info = &octnic->gmx_port_info[gmxport_id];

	p = find_mcast_ifl(gmxport_id, macaddr);
	if (!p) {
		p = get_mcast_ifl(&info->vnic_mcast_free);
		if (!p) {
			printf("Out of mcast entries\n");
			return;
		}

		p->mcast_addr = macaddr;

		hash_node_insert_tail(&p->list,
			&info->vnic_mcast_lut[mac_hash(mac_to_ptr(&macaddr)) &
			MCAST_LUT_MASK]);
	}

	iflist_set(&p->ifl, ifidx);
	iflist_set_last(&p->ifl);
	iflist_set_active(&p->ifl);

	DBG("VNIC%d added MCAST MAC %012lx ifl=%016lx,%016lx last=%d\n",
	    ifidx, macaddr, p->ifl.mask[0],
	    MAX_OCTEON_NIC_PORTS > 64 ?  p->ifl.mask[1] : 0UL,
	    p->ifl.last);
}

void cvmcs_nic_get_dump_flag(cvmx_wqe_t *wqe)
{
	cvm_pci_dma_cmd_t cmd;
	cvmx_buf_ptr_t lptr;
	cvmx_buf_ptr_pki_t *bls; /* pki buffer link structure for Octeon III */
	cvm_dma_remote_ptr_t rptr;
	cvmx_raw_inst_front_t *f;
	struct flash_rw_resp *resp;
	struct flash_dump_params params;
	int front_size, ret;

	cmd.u64 = 0;
	lptr.u64 = 0;
	bls = (cvmx_buf_ptr_pki_t *)&lptr;

	if (octeon_has_feature(OCTEON_FEATURE_CN78XX_WQE))
		f = (cvmx_raw_inst_front_t *)
			cvmx_phys_to_ptr(cvmx_wqe_get_pki_pkt_ptr(wqe).addr);
	else
		f = (cvmx_raw_inst_front_t *)wqe->packet_data;

	if (f->irh.s.rflag)
		front_size = CVM_RAW_FRONT_SIZE;
	else
		front_size = CVM_RAW_FRONT_SIZE-16;

	cmd.s.pcielport = f->rdp.s.pcie_port;
	rptr.s.addr = f->rptr;
	rptr.s.size = f->rdp.s.rlen;
	resp = (struct flash_rw_resp *) ((uint8_t *)f + front_size);
	memset(resp, 0, sizeof(struct flash_rw_resp));
	if (cvmcs_nic_get_flash_dump_params(&params)) {
		resp->op_status = -1;
	} else {
		resp->op_status = 0;
		resp->dump_len  = params.fw_dump_flash_size;
		resp->dump_flag = params.fw_dump_flag;
	}

	if (octeon_has_feature(OCTEON_FEATURE_CN78XX_WQE)) {
		bls->size = rptr.s.size;
		bls->addr = CVM_DRV_GET_PHYS(resp);
		bls->packet_outside_wqe = 0;
	} else {
		lptr.s.size = rptr.s.size;
		lptr.s.addr = CVM_DRV_GET_PHYS(resp);
		lptr.s.i    = 1;
		lptr.s.pool = CVMX_FPA_PACKET_POOL;
		lptr.s.back = wqe->packet_ptr.s.back;
		cvm_update_bp(wqe);
		cvmx_wqe_free(wqe);
	}
	cmd.s.nl = cmd.s.nr = 1;

	if (OCTEON_IS_OCTEON3())
		ret = cvm_pci_dma_send_data_o3(&cmd, bls, &rptr, wqe, 1);
	else
		ret = cvm_pci_dma_send_data(&cmd, &lptr, &rptr);

	if (ret)
		cvm_free_wqe_wrapper(wqe);
}

void cvmcs_nic_set_dump_flag(cvmx_wqe_t *wqe)
{
	cvm_pci_dma_cmd_t cmd;
	cvmx_buf_ptr_t lptr;
	cvmx_buf_ptr_pki_t *bls; /* pki buffer link structure for Octeon III */
	cvm_dma_remote_ptr_t rptr;
	cvmx_raw_inst_front_t *f;
	int front_size, flag, ret;
	struct flash_rw_req *req;
	struct flash_rw_resp *resp;
	struct flash_dump_params params;

	cmd.u64 = 0;
	lptr.u64 = 0;
	bls = (cvmx_buf_ptr_pki_t *)&lptr;

	if (octeon_has_feature(OCTEON_FEATURE_CN78XX_WQE))
		f = (cvmx_raw_inst_front_t *)
			cvmx_phys_to_ptr(cvmx_wqe_get_pki_pkt_ptr(wqe).addr);
	else
		f = (cvmx_raw_inst_front_t *)wqe->packet_data;

	if (f->irh.s.rflag)
		front_size = CVM_RAW_FRONT_SIZE;
	else
		front_size = CVM_RAW_FRONT_SIZE-16;

	cmd.s.pcielport = f->rdp.s.pcie_port;
	rptr.s.addr = f->rptr;
	rptr.s.size = f->rdp.s.rlen;

	/* Re-use the packet pool buffer to send the link info to host. */
	req = (struct flash_rw_req *) ((uint8_t *)f + front_size);
	resp = (struct flash_rw_resp *) ((uint8_t *)f + front_size);

	flag = req->flag;
	if ((flag == LIO_CRASH_DUMP) || (flag == LIO_NO_CRASH_DUMP)) {
		params.fw_dump_flag = flag;
		ret = cvmcs_nic_set_flash_dump_params(&params);
		resp->op_status = ret;
	} else {
		resp->op_status = -1;
	}

	if (octeon_has_feature(OCTEON_FEATURE_CN78XX_WQE)) {
		bls->size = rptr.s.size;
		bls->addr = CVM_DRV_GET_PHYS(resp);
		bls->packet_outside_wqe = 0;
	} else {
		lptr.s.size = rptr.s.size;
		lptr.s.addr = CVM_DRV_GET_PHYS(resp);
		lptr.s.i    = 1;
		lptr.s.pool = CVMX_FPA_PACKET_POOL;
		lptr.s.back = wqe->packet_ptr.s.back;
		cvm_update_bp(wqe);
		cvmx_wqe_free(wqe);
	}

	cmd.s.nl = cmd.s.nr = 1;

	if (OCTEON_IS_OCTEON3())
		ret = cvm_pci_dma_send_data_o3(&cmd, bls, &rptr, wqe, 1);
	else
		ret = cvm_pci_dma_send_data(&cmd, &lptr, &rptr);

	if (ret)
		cvm_free_wqe_wrapper(wqe);
}

void cvmcs_nic_get_dump(cvmx_wqe_t *wqe)
{
	cvm_pci_dma_cmd_t cmd;
	cvmx_buf_ptr_t lptr;
	cvmx_buf_ptr_pki_t *bls; /* pki buffer link structure for Octeon III */
	cvm_dma_remote_ptr_t rptr;
	cvmx_raw_inst_front_t *f;
	int front_size, offset, len, space_in_wqe, ret;
	struct flash_rw_req *req;
	struct flash_rw_resp *resp;

	cmd.u64 = 0;
	lptr.u64 = 0;
	bls = (cvmx_buf_ptr_pki_t *)&lptr;

	if (octeon_has_feature(OCTEON_FEATURE_CN78XX_WQE))
		f = (cvmx_raw_inst_front_t *)
			cvmx_phys_to_ptr(cvmx_wqe_get_pki_pkt_ptr(wqe).addr);
	else
		f = (cvmx_raw_inst_front_t *) wqe->packet_data;

	if (f->irh.s.rflag)
		front_size = CVM_RAW_FRONT_SIZE;
	else
		front_size = CVM_RAW_FRONT_SIZE-16;

	cmd.s.pcielport = f->rdp.s.pcie_port;
	rptr.s.addr = f->rptr;
	rptr.s.size = f->rdp.s.rlen;

	/* Re-use the packet pool buffer to send the link info to host. */
	req = (struct flash_rw_req *) ((uint8_t *)f + front_size);
	offset = req->off;
	len = req->len;
	resp = (struct flash_rw_resp *) ((uint8_t *)f + front_size);

	/* size available for us in wqe to send data out */
	space_in_wqe = CVMX_FPA_PACKET_POOL_SIZE -
		((uint8_t *)f - (uint8_t *)wqe);
	space_in_wqe -= (sizeof(struct flash_rw_resp) + front_size);
	if (space_in_wqe < len) {
		printf("Can not use packet buf for sending flash data\n");
		return;
	}
	memset(resp, 0, rptr.s.size);
	cvmcs_nic_flash_get((resp + 1), offset, len);
	resp->op_status = 0; /* Done */
	if (octeon_has_feature(OCTEON_FEATURE_CN78XX_WQE)) {
		bls->size = rptr.s.size;
		bls->addr = CVM_DRV_GET_PHYS(resp);
		bls->packet_outside_wqe = 0;
	} else {
		lptr.s.size = rptr.s.size;
		lptr.s.addr = CVM_DRV_GET_PHYS(resp);
		lptr.s.i    = 1;
		lptr.s.pool = CVMX_FPA_PACKET_POOL;
		lptr.s.back = wqe->packet_ptr.s.back;
		cvm_update_bp(wqe);
		cvmx_wqe_free(wqe);
	}

	cmd.s.nl = cmd.s.nr = 1;

	if (OCTEON_IS_OCTEON3())
		ret = cvm_pci_dma_send_data_o3(&cmd, bls, &rptr, wqe, 1);
	else
		ret = cvm_pci_dma_send_data(&cmd, &lptr, &rptr);

	if (ret)
		cvm_free_wqe_wrapper(wqe);
}

void cvmcs_nic_process_cmd(cvmx_wqe_t * wqe)
{
	cvmx_raw_inst_front_t *f;
	union octnet_cmd *ncmd;
	int gmxport, ifidx, gmxport_id;
	uint64_t retaddr = 0, ret = OCTNET_CMD_FAIL;
	int front_size;
	int came_from_a_vf;

	if (octeon_has_feature(OCTEON_FEATURE_CN78XX_WQE))
		f =  (cvmx_raw_inst_front_t *) cvmx_phys_to_ptr(cvmx_wqe_get_pki_pkt_ptr(wqe).addr);
	else
		f = (cvmx_raw_inst_front_t *)wqe->packet_data;

	if (f->irh.s.rflag)
		front_size = CVM_RAW_FRONT_SIZE;
	else
		front_size = CVM_RAW_FRONT_SIZE-16; /* rptr and rdp are not there so don't count them */

	ncmd = (union octnet_cmd *)((uint8_t *)f + front_size);

	DBG("NW Command packet received (0x%016lx)\n", ncmd->u64);

	ifidx = get_vnic_port_id(cvmx_wqe_get_port(wqe));

	if (ifidx >= MAX_OCTEON_NIC_PORTS || ifidx == -1) {
		printf("%s: Invalid ifidx (%d) received in command\n",
		       __FUNCTION__, ifidx);
		return;
	}

	if ((octnic->port[ifidx].state.present == 0)
	    || (octnic->port[ifidx].state.active == 0)) {
		printf("%s: GMX Port at ifidx (%d) appears inactive\n",
		       __FUNCTION__, ifidx);
		return;
	}

	gmxport = octnic->port[ifidx].linfo.gmxport;

	came_from_a_vf = OCT_NIC_PORT_VF(ifidx);

	switch (ncmd->s.cmdgroup)  {
	case 0 : {
	switch (ncmd->s.cmd) {

	case OCTNET_CMD_RX_CTL:
		DBG2("Command for RX Control: (ifidx %d Command: %s)\n",
		     ifidx, (ncmd->s.param1 ? "Start" : "Stop"));

		if (ncmd->s.param1)
			cvmcs_dcbx_enable(ifidx);
		else
			cvmcs_dcbx_disable(ifidx);

#ifdef VSWITCH /* Not allowing host to change MAC state for PF in OVS */

		octnic->port[ifidx].state.rx_on = ncmd->s.param1;
		CVMX_SYNCWS;

		/* Send the host PF state to octlinux for mgmt traffic decisions */
		if (OCT_NIC_IS_PF(ifidx))
			cvmcs_vsw_send_pf_state_to_octlinux(ifidx, ncmd->s.param1);

#else
		/* Change MAC filter */
		cvmcs_nic_change_mac_state(ifidx, ncmd->s.param1);
#endif //VSWITCH

		if (OCT_NIC_IS_PF(ifidx)) {
			cvmcs_nic_pf_send_link_status(ifidx);
		} else {
			cvmcs_nic_vf_send_link_status(ifidx);
		}

		ret = 0;
		break;

	case OCTNET_CMD_CHANGE_MTU:

		DBG2("Command to change MTU (ifidx %d gmxport: %d new_mtu %d)\n",
		     ifidx, gmxport, ncmd->s.param1);

		ret = 0;
		/* Only a PF that is MTU master can change link MTU */
		if (!came_from_a_vf && octnic->port[ifidx].is_mtu_master)
			ret = cvmcs_nic_change_link_mtu(ifidx, gmxport,
							ncmd->s.param1);
		if (!ret) {
#ifndef VSWITCH
			int i;
#endif
			ret = cvmcs_nic_change_vnic_mtu(ifidx, ncmd->s.param1);
			if (ret || came_from_a_vf)
				break;
#ifdef VSWITCH
			ret = cvmcs_vsw_change_mtu_from_host(ifidx, gmxport,
							     ncmd->s.param1);
#else
			/* when PF MTU changes, update max MTU of all its VFs */
			for (i = ifidx + 1; i < ifidx + OCT_NIC_VFS_PER_PF; i++) {
				cvmcs_nic_change_vnic_max_mtu(i,
							      ncmd->s.param1);
				cvmcs_nic_vf_send_link_status(i);
			}
#endif
		}
		/* do not pass -1 (all 1's; 64-bit) as error code; this will be 
		 * consideed as timeout by the host driver
		 */
		if (ret == -1ULL)
			ret = 1;
		break;

	case OCTNET_CMD_CHANGE_MACADDR:
		{
			uint64_t *macaddr;
			int gmxport_id, gmx_offset;
			uint16_t original_ifflags;

			macaddr = (uint64_t *)((uint8_t *)ncmd + sizeof(*ncmd));

			if (OCTEON_IS_MODEL(OCTEON_CN73XX)) {
				if (ncmd->s.param1) {
					/* a non-zero param1 means that the hypervisor wants to set the macaddr of a VF */
					int vf_num, vf_ifidx;

					if (came_from_a_vf)
						break; /* this came from a malicious VF, get out */

					vf_num = ncmd->s.param1;
					vf_ifidx = OCT_NIC_PORT_IDX( OCT_NIC_PORT_PF(ifidx), vf_num );

					/* make ifidx refer to the VF instead of the PF */
					ifidx = vf_ifidx;

					octnic->port[ifidx].linfo.macaddr_is_admin_asgnd = ncmd->s.param2;

					if (octnic->port[ifidx].user_set_macaddr == *macaddr) {
						/* macaddrs match; get out */
						ret=0;
						break;
					}

					octnic->port[ifidx].user_set_macaddr = *macaddr;

					if (!octnic->port[ifidx].state.present) {
						/* VF is not yet present; nothing more to do */
						ret=0;
						break;
					}
				} else if (came_from_a_vf && (octnic->port[ifidx].linfo.macaddr_is_admin_asgnd ||
					   	octnic->port[ifidx].linfo.macaddr_spoofchk)) {
					printf("VF %d is not allowed to change its mac addressx; spoofchk=%x, admin_assigned=%x\n", 
						ifidx, 
						octnic->port[ifidx].linfo.macaddr_spoofchk, 
						octnic->port[ifidx].linfo.macaddr_is_admin_asgnd);
					ret = OCTEON_REQUEST_NO_PERMISSION;
					break;
				}
			}

			gmxport_id = octnic->port[ifidx].gmxport_id;
			gmx_offset = octnic->port[ifidx].gmx_offset;
			original_ifflags = octnic->port[ifidx].state.ifflags;

			DBG2("Command to change MAC Addr (ifidx %d port %d MAC 0x%lx [%d])\n",
			     ifidx, gmxport, *macaddr, gmx_offset);

			cvmcs_nic_del_mac(ifidx);

			/* Note: gmx_offset will not be changed when we add
			 * the new MAC.
			 */
			if (cvmcs_nic_add_mac(ifidx, gmxport_id, gmx_offset,
					      *macaddr)) {
				printf("GMX%d: ifidx=%d Failed to add MAC %012lx\n",
				       gmxport_id, ifidx, *macaddr);
			} else {
				printf("GMX%d: ifidx=%d MAC changed to %012lx\n",
				       gmxport_id, ifidx, *macaddr);

				if (came_from_a_vf) {
					octnic->port[ifidx].user_set_macaddr = *macaddr;
					cvmcs_send_vf_drv_notice_to_pf(ifidx, VF_DRV_MACADDR_CHANGED, *macaddr);
				}
				ret=0;
			}

			octnic->port[ifidx].state.ifflags = original_ifflags;

#ifdef VSWITCH 
			/* Not allowing host to change MAC state for OVS */
#else
			if (octnic->port[ifidx].state.rx_on)
				cvmcs_nic_change_mac_state(ifidx, 1);
#endif

			break;
		}

	case OCTNET_CMD_SET_MULTI_LIST:
		{
			enum octnet_ifflags flags;
                        uint64_t *macaddr;
                        int i, n;

			if (!octeon_has_feature(OCTEON_FEATURE_CN78XX_WQE))
				if (wqe->word2.s.bufs > 0) {
					f = (cvmx_raw_inst_front_t *)cvmx_phys_to_ptr(wqe->packet_ptr.s.addr);
					ncmd = (union octnet_cmd *)(((uint8_t *) f) + front_size);
				}

			flags = (enum octnet_ifflags)ncmd->s.param1;

			n = ncmd->s.param2;

			DBG2("Command to set multicast MAC Addr list and Flags (ifidx %d port %d Flags 0x%lx-->0x%lx size %d)\n",
			     ifidx, gmxport, (long)octnic->port[ifidx].state.ifflags, (long)((unsigned)flags), n);

			if (n > MAX_OCTEON_MULTICAST_ADDR) {
				printf("ERROR: MAC Addr list size exceeded max size %d\n",
				       MAX_OCTEON_MULTICAST_ADDR);
				break;
			}

			if (n < 0) {
				printf("ERROR: MAC Addr list size negative (%d)\n", n);
				break;
			}

			gmxport_id = octnic->port[ifidx].gmxport_id;
			if (octnic->port[ifidx].state.ifflags != flags) {
				cvmcs_nic_change_ifflags_for_ifidx(gmxport_id, ifidx, flags);
			}
                        macaddr = (uint64_t *)((uint8_t *)ncmd + sizeof(*ncmd));

			clear_mcast_cache(gmxport_id, ifidx);

			for (i = 0; i < n; i++) {
				add_to_mcast_cache(gmxport_id, macaddr[i], ifidx);

				DBG("mcast mac[%d][%d]=%016lx\n",
				    ifidx, i, macaddr[i]);
			}

			octnic->port[ifidx].nmcast_addr = n;

			ret = 0;
			break;
		}

	case OCTNET_CMD_SET_UC_LIST:
		{
			int i, uc_count;
			uint64_t *macaddr;
			gmx_port_info_t *info;

			if (OCT_NIC_IS_PF(ifidx)) {
				/* The command is from PF driver. It could be setting
				 * the mac list for a VF
				 */
				ifidx = OCT_NIC_PORT_IDX(OCT_NIC_PORT_PF(ifidx), ncmd->s.param1);
			}

			gmxport_id = octnic->port[ifidx].gmxport_id;
			info = &octnic->gmx_port_info[gmxport_id];

			cvmx_spinlock_lock(&octnic->port[ifidx].ucast_table_lock);

			uc_count = octnic->port[ifidx].ucast_count;
			macaddr = octnic->port[ifidx].ucast_table;
			for (i = 0; i < uc_count; i++)
				cvmcs_remove_mac_from_hash_table(info, macaddr[i], ifidx);

			uc_count = ncmd->s.more;
			macaddr = (uint64_t *)((uint8_t *)ncmd + sizeof(*ncmd));
			for (i = 0; i < uc_count; i++) {
				cvmx_rwlock_wp_write_lock(&info->mac_hash_lock);
				add_mac_to_hash_table(ifidx, macaddr[i], info->hash);
				cvmx_rwlock_wp_write_unlock(&info->mac_hash_lock);
				octnic->port[ifidx].ucast_table[i] = macaddr[i];
			}

			octnic->port[ifidx].ucast_count = uc_count;
			if (uc_count)
				cvmcs_nic_change_gmx_ifflags(gmxport_id, OCTNET_IFFLAG_PROMISC);

			cvmx_spinlock_unlock(&octnic->port[ifidx].ucast_table_lock);
			ret = 0;
		}
		break;


	case OCTNET_CMD_CHANGE_DEVFLAGS:
		{
			enum octnet_ifflags flags;

			flags = (enum octnet_ifflags)ncmd->s.param1;
			DBG2("Command to change Flags (ifidx %d port %d Flags 0x%lx-->0x%lx)\n",
					ifidx, gmxport,
					(long)octnic->port[ifidx].state.ifflags, (long)((unsigned)flags));
			ret = 0;
			//TODO fix this. mcast and promisc to be changed  only
			//using a control interface or something
			if (octnic->port[ifidx].state.ifflags != flags) {
				gmxport_id = octnic->port[ifidx].gmxport_id;
				cvmcs_nic_change_ifflags_for_ifidx(gmxport_id, ifidx, flags);
			}

			break;
		}

	case OCTNET_CMD_CLEAR_STATS:
		{
			DBG2("Command to clear NIC stats(ifidx %d port %d)\n",
			     ifidx, gmxport);
			ret = cvmcs_nic_clear_stats(ifidx, gmxport);
			break;
		}
	case OCTNET_CMD_SET_SETTINGS:
		{

			union oct_link_status host;

			DBG2("Command to change nic Settings\n");
			/*getting the parameters like autoneg,speed,duplex from host */
			host.u64 = 0;
			host.s.autoneg = ncmd->s.more & 0x1;
			host.s.speed = ncmd->s.param1;
			/* Speed contains bitmask for speed & duplex when autoneg is on */
			if (!host.s.autoneg)
				host.s.duplex = ncmd->s.param2;
			host.s.link_up = (ncmd->s.more >> 1) & 0x1;
			host.s.pause = (ncmd->s.more >> 2) & 0x1;

			gmxport_id = octnic->port[ifidx].gmxport_id;
			if (octnic->gmx_port_info[gmxport_id].nports  == 1)
				ret = cvmcs_nic_change_settings(&host, gmxport);
			octnic->port[ifidx].linfo.link.s.autoneg = host.s.autoneg;
			if (!host.s.autoneg) {
				octnic->port[ifidx].linfo.link.s.speed = host.s.speed;
				octnic->port[ifidx].linfo.link.s.duplex = host.s.duplex;
				octnic->port[ifidx].linfo.link.s.link_up = host.s.link_up;
			}
			/* Print the updated status. */
			cvmcs_nic_print_link_status(&octnic->port[ifidx].linfo.link,
					    ifidx, gmxport);
			ret = 0;
			break;
		}
	case OCTNET_CMD_SET_FLOW_CTL:
		{
			cvmcs_nic_set_flow_ctl(gmxport, ncmd->s.param1, ncmd->s.param2);
			ret = 0;
			break;
		}

	case OCTNET_CMD_GPIO_ACCESS:
		{
			if (OCTEON_IS_MODEL(OCTEON_CN66XX))
				ret = cvmcs_gpio_access(ncmd->s.param1, ncmd->s.param2);
			else
				ret = 0;
			break;

		}

	case OCTNET_CMD_ID_ACTIVE:
		{
			if (OCTEON_IS_MODEL(OCTEON_CN73XX) &&
			    OCT_NIC_IS_PF(ifidx))
				ret = cvmcs_id_active(ifidx, gmxport, ncmd->s.param1);
			else
				ret = 0;
			break;

		}

	case OCTNET_CMD_MDIO_READ_WRITE:
		{
			int mdio_op = ncmd->s.more;
			int location = ncmd->s.param2;
			int value = ncmd->s.param1;

			ret =
			    cvmcs_do_mdio_read_write(ifidx, mdio_op, location,
						     value);
			if (ret)
				/* F/W processed the command
				 * but resulted in fail
				 */
				ret = OCTNET_CMD_FAIL;
			break;
		}
	case OCTNET_CMD_LRO_ENABLE:
		{
			DBG("Command to enable LRO %d PARAM : %0X\n", ifidx, ncmd->s.param1);
		    if (OCTNIC_LROIPV4 & ncmd->s.param1) {
				octnic->port[ifidx].state.lro_on_ipv4 = 1;
			}
		    if (OCTNIC_LROIPV6 & ncmd->s.param1) {
				octnic->port[ifidx].state.lro_on_ipv6 = 1;
			}

			if (OCTEON_IS_MODEL(OCTEON_CN78XX_PASS1_X)) {
				/* 78xx pass 1.x parts have an issue with L4
				   checksum calculation for large packets (see
				   section 2.2.10.5 of "OCTEON III CN78XX Known
				   Issues" version 1.11), so don't turn on LRO
				   for 1.x parts. */
				octnic->port[ifidx].state.lro_on_ipv4 = 0;
				octnic->port[ifidx].state.lro_on_ipv6 = 0;
			}
			ret = 0;
			break;
		}
	case OCTNET_CMD_LRO_DISABLE:
		{
			DBG("Command to Disable LRO %d PARAM : %0X\n", ifidx, ncmd->s.param1);
			if (OCTNIC_LROIPV4 & ncmd->s.param1) {
				octnic->port[ifidx].state.lro_on_ipv4 = 0;
			}
			if (OCTNIC_LROIPV6 & ncmd->s.param1) {
				octnic->port[ifidx].state.lro_on_ipv6 = 0;
			}
			ret = 0;
			break;
		}
	case OCTNET_CMD_VERBOSE_ENABLE:
		{
			if (!OCTEON_IS_MODEL(OCTEON_CN73XX) ||
			    OCT_NIC_IS_PF(ifidx)) {
				nic_verbose = 1; /* TODO make this ifidx specific */
				DBG("Command to enable verbose output %d\n", ifidx);
				ret = 0;
			}
			break;
		}
	case OCTNET_CMD_VERBOSE_DISABLE:
		{
			if (!OCTEON_IS_MODEL(OCTEON_CN73XX) ||
			    OCT_NIC_IS_PF(ifidx)) {
				DBG("Command to disable verbose output %d\n", ifidx);
				nic_verbose = 0;
				ret = 0;
			}
			break;
		}
	case OCTNET_CMD_VLAN_FILTER_CTL:
		{
			DBG("Command to %s VLAN filtering %d\n",
				(ncmd->s.param1) ? "enable": "disable",  ifidx);
			if (ncmd->s.param1)
				cvmcs_nic_enable_vlan_filter(ifidx);
			else
				cvmcs_nic_disable_vlan_filter(ifidx);
			ret = 0;
			break;
		}
	case OCTNET_CMD_SET_RSS:
		{
			DBG("Command to Set RSS (ifidx %d)\n", ifidx);
			ret = cvmcs_nic_set_rss_params(wqe, front_size);
			break;
		}
	case OCTNET_CMD_SET_FNV:
		{
			DBG("Command to %s FNV (ifidx %d)\n",
				(ncmd->s.param1) ? "enable": "disable",  ifidx);

			octnic->port[ifidx].state.fnv_on = !!(ncmd->s.param1);
			ret = 0;
			break;
		}
	case OCTNET_CMD_WRITE_SA:
		{
			DBG("Command to write SA \n");
			ret = cvm_ipsec_offload(wqe, front_size + sizeof(*ncmd), ifidx, OCTNET_CMD_WRITE_SA);
			break;
		}
	case OCTNET_CMD_UPDATE_SA:
		{
			DBG("Command to update SA \n");
			ret = cvm_ipsec_offload(wqe, front_size + sizeof(*ncmd), ifidx, OCTNET_CMD_UPDATE_SA);
			break;
		}
	case OCTNET_CMD_DELETE_SA:
		{
			DBG("Command to DELETE SA \n");
			ret = cvm_ipsec_offload(wqe, front_size + sizeof(*ncmd), ifidx, OCTNET_CMD_DELETE_SA);
			break;

		}
	case OCTNET_CMD_TNL_RX_CSUM_CTL:
		{
			DBG("Command to Set TNL rx checksum verify (ifidx %d)\n", ifidx);
			octnic->port[ifidx].state.tnl_rx_csum = (ncmd->s.param1 == OCTNET_CMD_RXCSUM_ENABLE);
			ret = 0;
			break;
		}

	case OCTNET_CMD_TNL_TX_CSUM_CTL:
		{
			DBG("Command to Set TNL tx checksum (ifidx %d)\n", ifidx);
			octnic->port[ifidx].state.tnl_tx_csum = (ncmd->s.param1 == OCTNET_CMD_TXCSUM_ENABLE);
			ret = 0;
			break;
		}
	case OCTNET_CMD_IPSECV2_AH_ESP_CTL:
		{
			DBG("Command to Set IPSECV2 AH ESP  (ifidx %d)\n", ifidx);
			octnic->port[ifidx].state.ipsecv2_ah_esp = ncmd->s.param1;
			ret = 0;
			break;
		}
	/* Handling firmware commands to add/del VxLAN port into Vxlan_DB  */
	case OCTNET_CMD_VXLAN_PORT_CONFIG:
		{
			uint32_t vxlan_port = ncmd->s.param1;

			if(ncmd->s.more == OCTNET_CMD_VXLAN_PORT_ADD) {
				printf("Command to ADD VxLAN Port %d ifidx %d\n", vxlan_port, ifidx);

				/* Validate VxLAN port range */
				if ((vxlan_port >= MIN_VXLAN_PORT) && (vxlan_port <= MAX_VXLAN_PORT)) {
					if (LINUX_DEFAULT_VXLAN_PORT == vxlan_port) {
						if (!(octnic->port[ifidx].vxlan_default_ports & LINUX_DEFAULT_VXLAN_BIT)) {
							octnic->port[ifidx].vxlan_default_ports |= LINUX_DEFAULT_VXLAN_BIT;
							octnic->port[ifidx].vxlan_port_count++;
						}
					}
					else if (IANA_DEFAULT_VXLAN_PORT == vxlan_port) {
						if (!(octnic->port[ifidx].vxlan_default_ports & IANA_DEFAULT_VXLAN_BIT)) {
							octnic->port[ifidx].vxlan_default_ports |= IANA_DEFAULT_VXLAN_BIT;
							octnic->port[ifidx].vxlan_port_count++;
						}
					}
					else {
						VXLAN_ADD_PORT_TO_DB(vxlan_port, ifidx);
						octnic->port[ifidx].vxlan_port_count++;
					}

					printf("VxLAN Port is added in DB octnic->port[%d].vxlan_default_ports %d\n", ifidx, octnic->port[ifidx].vxlan_default_ports);
				} else
					printf("Adding VxLAN Port in DB operation is failed %d\n", ifidx);
			} else if(ncmd->s.more == OCTNET_CMD_VXLAN_PORT_DEL) {
				printf("Command to DELETE VxLAN Port %d ifidx %d\n", vxlan_port, ifidx);

				/* Validate VxLAN port range */
				if ((vxlan_port >= MIN_VXLAN_PORT) && (vxlan_port <= MAX_VXLAN_PORT)){
					if (IANA_DEFAULT_VXLAN_PORT == vxlan_port) {
						if (octnic->port[ifidx].vxlan_default_ports & LINUX_DEFAULT_VXLAN_BIT) {
							octnic->port[ifidx].vxlan_default_ports &= ~LINUX_DEFAULT_VXLAN_BIT;
							octnic->port[ifidx].vxlan_port_count--;
						}
					}
					else if (LINUX_DEFAULT_VXLAN_PORT == vxlan_port) {
						if (octnic->port[ifidx].vxlan_default_ports & IANA_DEFAULT_VXLAN_BIT) {
							octnic->port[ifidx].vxlan_default_ports &= ~IANA_DEFAULT_VXLAN_BIT;
							octnic->port[ifidx].vxlan_port_count--;
						}
					}
					else {
						VXLAN_DEL_PORT_TO_DB(vxlan_port, ifidx);
						octnic->port[ifidx].vxlan_port_count--;
					}

					printf("VxLAN Port is deleted from DB octnic->port[%d].vxlan_default_ports %d\n", ifidx, octnic->port[ifidx].vxlan_default_ports);
				} else
					printf("Deleting VxLAN Port %x from DB operation is failed %d\n", vxlan_port, ifidx);
			}
			ret = 0;
			break;
		}

	case OCTNET_CMD_ADD_VLAN_FILTER:
		{
			if (ncmd->s.param2) {
				/* non-zero param2 means that the hypervisor wants to set vlan tag of VF */
				uint16_t vlanTCI, vlanid;
				int vf_num, vf_ifidx;

				if (came_from_a_vf)
					break; /* this came from a malicious VF; get out */

				vf_num = ncmd->s.param2;
				vf_ifidx = OCT_NIC_PORT_IDX( OCT_NIC_PORT_PF(ifidx), vf_num );

				vlanTCI = ncmd->s.param1;

				/* make ifidx refer to the VF instead of the PF */
				ifidx = vf_ifidx;

				octnic->port[ifidx].linfo.vlan_is_admin_assigned = 1;

				if (octnic->port[ifidx].user_set_vlanTCI == vlanTCI)
					break;

				if (!octnic->port[ifidx].state.present) {
					octnic->port[ifidx].user_set_vlanTCI = vlanTCI;
					break;
				}

				for (vlanid = 0; vlanid < MAX_VLANS; vlanid++)
					cvmcs_nic_del_vlan(ifidx, vlanid);

				octnic->port[ifidx].user_set_vlanTCI = vlanTCI;
				ncmd->s.param1 = vlanTCI & 0xFFF;
			} else {
				if (came_from_a_vf && octnic->port[ifidx].linfo.vlan_is_admin_assigned)
					break;
			}

			DBG("Command to Add VLAN filter (ifidx %d, vid %d)\n", ifidx,
			    ncmd->s.param1);
			cvmcs_nic_add_vlan(ifidx, ncmd->s.param1);
			ret = 0;
			break;
		}
	case OCTNET_CMD_DEL_VLAN_FILTER:
		{
			if (ncmd->s.param2) {
				/* non-zero param2 means that the hypervisor wants to turn off vlan tagging for VF */
				int vf_num, vf_ifidx;

				if (came_from_a_vf)
					break; /* this came from a malicious VF; get out */

				vf_num = ncmd->s.param2;
				vf_ifidx = OCT_NIC_PORT_IDX( OCT_NIC_PORT_PF(ifidx), vf_num );

				/* make ifidx refer to the VF instead of the PF */
				ifidx = vf_ifidx;

				octnic->port[ifidx].linfo.vlan_is_admin_assigned = 0;

				if (octnic->port[ifidx].user_set_vlanTCI == 0)
					break;

				ncmd->s.param1 = octnic->port[ifidx].user_set_vlanTCI & 0xFFF;
				octnic->port[ifidx].user_set_vlanTCI = 0;
			} else {
				if (came_from_a_vf && octnic->port[ifidx].linfo.vlan_is_admin_assigned)
					break;
			}

			DBG("Command to Delete VLAN filter (ifidx %d, vid %d)\n", ifidx,
			    ncmd->s.param1);
			cvmcs_nic_del_vlan(ifidx, ncmd->s.param1);
			ret = 0;
			break;
		}

	case OCTNET_CMD_SET_VF_LINKSTATE:
		{
			int vf_num, vf_ifidx;
#ifdef VSWITCH
			vf_num = ncmd->s.param1;
			vf_ifidx = OCT_NIC_PORT_IDX( OCT_NIC_PORT_PF(ifidx), vf_num );
#else
			int user_set_linkstate_new, user_set_linkstate_current;
			union oct_link_status *vf_ls;

			if (came_from_a_vf)
				break;

			vf_num = ncmd->s.param1;
			user_set_linkstate_new = ncmd->s.param2;

			vf_ifidx = OCT_NIC_PORT_IDX( OCT_NIC_PORT_PF(ifidx), vf_num );

			user_set_linkstate_current = octnic->port[vf_ifidx].user_set_linkstate;
			if (user_set_linkstate_current == user_set_linkstate_new) {
				ret = 0; /* no error */
				break;
			}
			octnic->port[vf_ifidx].user_set_linkstate = user_set_linkstate_new;
			CVMX_SYNCW;

			if (!octnic->port[vf_ifidx].state.present)
				break;

			vf_ls = &octnic->port[vf_ifidx].linfo.link;

			if (user_set_linkstate_new == IFLA_VF_LINK_STATE_DISABLE) {
				if (vf_ls->s.link_up == 0) {
					ret = 0; /* no error */
					break;
				}
			} else if (user_set_linkstate_new == IFLA_VF_LINK_STATE_ENABLE) {
				if (vf_ls->s.link_up == 1) {
					ret = 0; /* no error */
					break;
				}
			}

#endif
			cvmcs_nic_vf_send_link_status(vf_ifidx);
			ret = 0;
		}
		break;

	case OCTNET_CMD_PKT_STEERING_CTL:
		if (ncmd->s.param1 == OCTNET_CMD_PKT_STEERING_ENABLE) {
			DBG("Pkt steering enabled (ifidx %d)\n", ifidx);
			octnic->port[ifidx].pkt_steering_enable = 1;
		} else if (ncmd->s.param1 == OCTNET_CMD_PKT_STEERING_DISABLE) {
			DBG("Pkt steering disabled (ifidx %d)\n", ifidx);
			octnic->port[ifidx].pkt_steering_enable = 0;
		}
		ret = 0;
		break;

	case OCTNET_CMD_QUEUE_COUNT_CTL:
		DBG("Queues Count update (ifidx %d)\n", ifidx);
		octnic->port[ifidx].linfo.num_txpciq = ncmd->s.param1;
		octnic->port[ifidx].linfo.num_rxpciq = ncmd->s.param2;
		ret = 0;
		break;

	default:
		printf("Unknown NIC Command 0x%08x  \n", ncmd->s.cmd );
		break;

	}
	break;
	} /* command group 0 */

	case OCTNET_CMD_GROUP1: {
		switch(ncmd->s.cmd) {
		case OCTNET_CMD_SET_VF_SPOOFCHK: {
			if (OCT_NIC_IS_PF(ifidx)) {
				int vf_ifidx, vf_num;

				vf_num = ncmd->s.param1;
				vf_ifidx = OCT_NIC_PORT_IDX( OCT_NIC_PORT_PF(ifidx), vf_num );
				if (ncmd->s.param2) {
					octnic->port[vf_ifidx].linfo.macaddr_spoofchk = 1;
				} else {
					octnic->port[vf_ifidx].linfo.macaddr_spoofchk = 0;
				}
			}
			ret = 0;
			break;
		}

		default:
			printf("Unknown NIC Command group 1 Command 0x%08x  \n", ncmd->s.cmd );
			break;
		}

		break;
	}
	
	default:
		printf("Unknown NIC Command group 0x%08x  \n", ncmd->s.cmdgroup );
		break;
	}

	/* Bug #12699: The new IRH uses a bit to signify if a response data
	 * block is specified, vs. The previous convention of just a null pointer.
	 * This was causing backwards compatability issues.
	 */
	if (f->irh.s.rflag && f->rptr) {
		retaddr = f->rptr + 8;
		if (OCTEON_IS_MODEL(OCTEON_CN73XX))
			cvm_pci_pvf_mem_writell(retaddr, ret, cvm_pcie_pvf_num(wqe));
		else
			cvm_pci_mem_writell(retaddr, ret);
	}

	cvm_free_wqe_wrapper(wqe);
}

#ifdef DPI_BP
static void cvm_update_dpi_bp(int port, int num_bufs)
{
	int iq_num;

	if (OCTEON_IS_MODEL(OCTEON_CN68XX)) {
		iq_num = port - (1U << 8);	// 8 -11 bits of ipd port = 0x1 for dpi
		//printf("dpi bp update bpid, %d  port, %d iq_num %d\n", octnic->dpi_bp.cn68xx.dpi_bp_fau_map[iq_num].s.bpid, port, iq_num);
		if (octnic->dpi_bp.cn68xx.dpi_bp_fau_map[iq_num].s.enabled) {
			cvmx_fau_fetch_and_add32(octnic->dpi_bp.cn68xx.
						 dpi_bp_fau_map[iq_num].s.fau,
						 -(num_bufs));
		}
	} else if (OCTEON_IS_MODEL(OCTEON_CN66XX)) {
		if (octnic->dpi_bp.cn66xx.dpi_bp_fau_map[port-32].s.enabled) {
			cvmx_fau_fetch_and_add32(octnic->dpi_bp.cn66xx.
						 dpi_bp_fau_map[port-32].s.fau,
						 -(num_bufs));
		}
	}
}
#endif

#ifdef GMX_BP
static void cvm_update_gmx_bp(int port, int num_bufs)
{
	int gmxport_id;
	//printf("gmx bp update bpid, %d gmxport_id,  %d\n", octnic->gmx_bp.cn68xx.gmx_bp_fau_map[gmxport_id].s.bpid, gmxport_id);
	if (OCTEON_IS_MODEL(OCTEON_CN68XX)) {
		gmxport_id = get_gmx_port_id(port);
		if (octnic->gmx_bp.cn68xx.gmx_bp_fau_map[gmxport_id].s.enabled)
			cvmx_fau_fetch_and_add32(octnic->gmx_bp.cn68xx.gmx_bp_fau_map[gmxport_id].
					 s.fau, -(num_bufs));
	} else if (OCTEON_IS_MODEL(OCTEON_CN66XX)) {
		gmxport_id = get_gmx_port_id(port);
		if (octnic->gmx_bp.cn66xx.gmx_bp_fau_map[gmxport_id].s.enabled)
			cvmx_fau_fetch_and_add32(octnic->gmx_bp.cn66xx.gmx_bp_fau_map[gmxport_id].
					 s.fau, -(num_bufs));
	}
}
#endif

void cvm_update_bp_port(int port, int num_bufs)
{
#if (defined(GMX_BP) || defined(DPI_BP))
	if (is_dpi_port(port)) {
		cvm_update_dpi_bp(port, num_bufs);
	} else {
		cvm_update_gmx_bp(port, num_bufs);
	}
#endif
}

void cvm_update_bp(cvmx_wqe_t *wqe)
{
#if 0
#ifdef DPI_BP
	if (is_dpi_port(cvmx_wqe_get_port(wqe))) {
		int iq_num = cvmx_wqe_get_port(wqe) - (1U << 8);	// 8 -11 bits of ipd port = 0x1 for dpi
		if (OCTEON_IS_MODEL(OCTEON_CN68XX)) {
			if (wqe->word0.pip.cn68xx.bpid != octnic->dpi_bp.cn68xx.dpi_bp_fau_map[iq_num].s.bpid) {
				printf ("error wqe bpid and bpid from iq num do not match wqe bpid %d iq num bpid %d\n",
					wqe->word0.pip.cn68xx.bpid,
					octnic->dpi_bp.cn68xx.dpi_bp_fau_map[iq_num].s.bpid);
			}
		}
	}
#endif
#ifdef GMX_BP
	{
		int gmxport_id = get_gmx_port_id(cvmx_wqe_get_port(wqe));
		if (gmxport_id != -1) {
			if (OCTEON_IS_MODEL(OCTEON_CN68XX)) {
				if (wqe->word0.pip.cn68xx.bpid != octnic->gmx_bp.cn68xx.gmx_bp_fau_map[gmxport_id].s.bpid) {
					printf ("error wqe bpid and bpid from iq num do not match wqe bpid %d iq num bpid %d\n",
						wqe->word0.pip.cn68xx.bpid,
						octnic->gmx_bp.cn68xx.gmx_bp_fau_map[gmxport_id].s.bpid);
				}
			}
		}
	}
#endif
#endif
	cvm_update_bp_port(cvmx_wqe_get_port(wqe), cvmx_wqe_get_bufs(wqe));
}

static int cvmcs_nic_init_dpi_bp_ctrl_iq()
{
#ifdef DPI_BP
	int iq_num = CONTROL_IQ;
	int fau;


	if (OCTEON_IS_MODEL(OCTEON_CN68XX)) {
		cvmx_ipd_bpidx_mbuf_th_t mbuf_th;
		cvmx_ipd_sub_port_bp_page_cnt_t sub_port_page;
		cvmx_ipd_bpid_bp_counterx_t bp_cnt;
		int i;
		int npi_interface = -1;
		int pkind = 0;
		int bpid = 0;
		const int num_interfaces = cvmx_helper_get_number_of_interfaces();

		for (i = 0; i  < num_interfaces; i++) {
			if (cvmx_helper_interface_get_mode(i) == CVMX_HELPER_INTERFACE_MODE_NPI) {
				npi_interface = i;
				break;
			}
		}
		if (npi_interface == -1) {
			printf("npu interface identification failed\n");
			return -1;
		}
		pkind = cvmx_helper_get_pknd(npi_interface, iq_num);
		bpid = cvmx_helper_get_bpid(npi_interface, iq_num);
		//clear  counter
		bp_cnt.u64 =
		    cvmx_read_csr(CVMX_IPD_BPID_BP_COUNTERX(bpid));
		if (bp_cnt.s.cnt_val) {
			sub_port_page.u64 = 0;
			sub_port_page.s.port = bpid;
			sub_port_page.s.page_cnt = -bp_cnt.s.cnt_val;
			cvmx_write_csr(CVMX_IPD_SUB_PORT_BP_PAGE_CNT,
				       sub_port_page.u64);
		}
		octnic->dpi_bp.cn68xx.dpi_bp_fau_map[iq_num].s.bpid = bpid;
		//setup threshold and enable
		mbuf_th.u64 = 0;
		mbuf_th.s.bp_enb = 1;
		mbuf_th.s.page_cnt = DPI_BP_THRESHOLD_68XX >> 8;	//in 256 pages
		cvmx_write_csr(CVMX_IPD_BPIDX_MBUF_TH(bpid),
			       mbuf_th.u64);
		//setup fau to track
		fau = (cvmx_fau_reg_32_t) cvmx_fau32_alloc(CVMX_FAU_REG_ANY);
		if (fau == -1) {
			printf("Fau allocation failed\n");
			return -1;
		}
		cvmx_fau_atomic_write32(fau, 0);
		octnic->dpi_bp.cn68xx.dpi_bp_fau_map[iq_num].s.fau = fau;
		octnic->dpi_bp.cn68xx.dpi_bp_fau_map[iq_num].s.enabled = 1;
		printf
		    ("iq num %d pkind %d, bpid %d fau %d\n",
		    iq_num, pkind, bpid, fau);
	} else if (OCTEON_IS_MODEL(OCTEON_CN66XX)) {
		//66xx
		union cvmx_ipd_portx_bp_page_cnt page_cnt;
		union cvmx_ipd_sub_port_bp_page_cnt sub_page_cnt;
		int ctrl_port = (CONTROL_IQ & 0x3);
		int ctrl_pci_port = 32 + ctrl_port;
		cvmx_ipd_port_bp_counters_pairx_t bp_cnt;

		page_cnt.u64 = 0;
		page_cnt.s.page_cnt = DPI_BP_THRESHOLD_66XX >> 8;
		page_cnt.s.bp_enb = 1;
		bp_cnt.u64 = cvmx_read_csr(CVMX_IPD_PORT_BP_COUNTERS_PAIRX(ctrl_pci_port));
		if (bp_cnt.s.cnt_val) {
			printf("error bp count non zero  %d:%d\n", ctrl_port,  bp_cnt.s.cnt_val);
			printf("Setting to 0\n");
			sub_page_cnt.u64 = 0;
			sub_page_cnt.s.port = ctrl_pci_port;
			sub_page_cnt.s.page_cnt = -bp_cnt.s.cnt_val;
			cvmx_write_csr(CVMX_IPD_SUB_PORT_BP_PAGE_CNT,
						     sub_page_cnt.u64);
		}
		cvmx_write_csr(CVMX_IPD_PORTX_BP_PAGE_CNT(ctrl_pci_port), page_cnt.u64);
		fau = (cvmx_fau_reg_32_t) cvmx_fau32_alloc(CVMX_FAU_REG_ANY);
	        if (fau == -1) {
	                printf("Fau allocation failed\n");
			return -1;
		}
		cvmx_fau_atomic_write32(fau, 0);
		octnic->dpi_bp.cn66xx.dpi_bp_fau_map[ctrl_port].s.fau = fau;
		octnic->dpi_bp.cn66xx.dpi_bp_fau_map[ctrl_port].s.enabled = 1;
		printf("BP: PCI port %d index %d fau %d\n",ctrl_pci_port, ctrl_port, fau);
	}

#endif
	return 0;
}

//initiailzes backpressure for DPI IQs
//so that we can throttle the host
//from sending too much over the IQs
//and grabbing fpa buffers
static int cvmcs_nic_init_dpi_bp(int port)
{
#ifdef DPI_BP
	int iq_num = 0;
	int j;
	int fau;

	if (OCTEON_IS_MODEL(OCTEON_CN68XX)) {
		cvmx_ipd_bpidx_mbuf_th_t mbuf_th;
		cvmx_ipd_sub_port_bp_page_cnt_t sub_port_page;
		cvmx_ipd_bpid_bp_counterx_t bp_cnt;
		cvmx_sli_portx_pkind_t pkind;
		cvmx_pip_prt_cfgbx_t cfgb;
		int bpid = 0;
		int bpkind = 0;

		for (j = 0; j < octnic->port[port].linfo.num_txpciq; j++) {
			iq_num = OCT_NIC_IQ_NUM(&octnic->port[port], j);
			if (j == 0) {
				pkind.u64 = cvmx_read_csr(CVMX_PEXP_SLI_PORTX_PKIND(iq_num));
				bpkind = pkind.s.bpkind;
				cfgb.u64 = cvmx_read_csr(CVMX_PIP_PRT_CFGBX(pkind.s.pkind));
				bpid = cfgb.s.bpid;
				if (octnic->dpi_bp.cn68xx.dpi_bp_fau_map[iq_num].s.enabled) {
					fau = octnic->dpi_bp.cn68xx.dpi_bp_fau_map[iq_num].s.fau;
					printf("port %d iq num %d pkind %d,bpkind %d bpid %d fau %d\n",
					     port, iq_num, pkind.s.pkind, pkind.s.bpkind,
					     cfgb.s.bpid, fau);
					continue;
				}
				//clear  counter
				bp_cnt.u64 =
				    cvmx_read_csr(CVMX_IPD_BPID_BP_COUNTERX(bpid));
				if (bp_cnt.s.cnt_val) {
					sub_port_page.u64 = 0;
					sub_port_page.s.port = bpid;
					sub_port_page.s.page_cnt = -bp_cnt.s.cnt_val;
					cvmx_write_csr(CVMX_IPD_SUB_PORT_BP_PAGE_CNT,
						       sub_port_page.u64);
				}
				octnic->dpi_bp.cn68xx.dpi_bp_fau_map[iq_num].s.bpid = bpid;
				//setup threshold and enable
				mbuf_th.u64 = 0;
				mbuf_th.s.bp_enb = 1;
				mbuf_th.s.page_cnt = DPI_BP_THRESHOLD_68XX >> 8;	//in 256 pages
				cvmx_write_csr(CVMX_IPD_BPIDX_MBUF_TH(bpid),
					       mbuf_th.u64);
				//setup fau to track
				fau = (cvmx_fau_reg_32_t) cvmx_fau32_alloc(CVMX_FAU_REG_ANY);
				if (fau == -1) {
					printf("Fau allocation failed\n");
					return -1;
				}
				cvmx_fau_atomic_write32(fau, 0);
				octnic->dpi_bp.cn68xx.dpi_bp_fau_map[iq_num].s.fau = fau;
				octnic->dpi_bp.cn68xx.dpi_bp_fau_map[iq_num].s.enabled = 1;
			} else {
				//Assign the same bpid to every other iq on the port
				//this reduces the number of bpids that need to maintained
				pkind.u64 = cvmx_read_csr(CVMX_PEXP_SLI_PORTX_PKIND(iq_num));
				cfgb.u64 =cvmx_read_csr(CVMX_PIP_PRT_CFGBX(pkind.s.pkind));
				if (octnic->dpi_bp.cn68xx.dpi_bp_fau_map[iq_num].s.enabled) {
					fau = octnic->dpi_bp.cn68xx.dpi_bp_fau_map[iq_num].s.fau;
					printf
					    ("port %d iq num %d pkind %d,bpkind %d bpid %d fau %d\n",
					     port, iq_num, pkind.s.pkind, pkind.s.bpkind,
					     cfgb.s.bpid, fau);
					continue;
				}

				pkind.s.bpkind = bpkind;
				cvmx_write_csr(CVMX_PEXP_SLI_PORTX_PKIND
					       (iq_num), pkind.u64);
				cfgb.s.bpid = bpid;
				cvmx_write_csr(CVMX_PIP_PRT_CFGBX
					       (pkind.s.pkind),
					       cfgb.u64);
				octnic->dpi_bp.cn68xx.dpi_bp_fau_map[iq_num].s.bpid = bpid;
				octnic->dpi_bp.cn68xx.dpi_bp_fau_map[iq_num].s.fau = fau;
				octnic->dpi_bp.cn68xx.dpi_bp_fau_map[iq_num].s.enabled = 1;
			}
			printf
			    ("port %d iq num %d pkind %d,bpkind %d bpid %d fau %d\n",
			     port, iq_num, pkind.s.pkind, pkind.s.bpkind,
			     cfgb.s.bpid, fau);
		}
	} else if (OCTEON_IS_MODEL(OCTEON_CN66XX)) {
		//66xx
		union cvmx_ipd_portx_bp_page_cnt page_cnt;
		union cvmx_ipd_sub_port_bp_page_cnt sub_page_cnt;
		int pci_port;
		int pci_ports_used_mask  = 0x0;
		cvmx_ipd_port_bp_counters_pairx_t bp_cnt;

		for (j = 0; j < octnic->port[port].linfo.num_txpciq; j++) {
			iq_num = OCT_NIC_IQ_NUM(&octnic->port[port], j);
			pci_ports_used_mask  |= (1U << (iq_num &  0x3));
		}
		for (j = 0; j < MAX_PCI_PORTS_66XX; j++) {
			if (pci_ports_used_mask & (1U <<  j)) {
				pci_port = 32+j;
				if (octnic->dpi_bp.cn66xx.dpi_bp_fau_map[j].s.enabled) {
					fau = octnic->dpi_bp.cn66xx.dpi_bp_fau_map[j].s.fau;
					DBG2("BP: dpi bp already configured for pci port %d\n", pci_port);
					DBG2("BP: PCI port %d index %d fau %d\n",pci_port, j, fau);
					continue;
				}
				page_cnt.u64 = 0;
				page_cnt.s.page_cnt = DPI_BP_THRESHOLD_66XX >> 8;
				page_cnt.s.bp_enb = 1;
				bp_cnt.u64 = cvmx_read_csr(CVMX_IPD_PORT_BP_COUNTERS_PAIRX(pci_port));
				if (bp_cnt.s.cnt_val) {
					printf("error bp count non zero  %d:%d\n", pci_port,  bp_cnt.s.cnt_val);
					printf("Setting to 0\n");
					sub_page_cnt.u64 = 0;
					sub_page_cnt.s.port = pci_port;
					sub_page_cnt.s.page_cnt = -bp_cnt.s.cnt_val;
					cvmx_write_csr(CVMX_IPD_SUB_PORT_BP_PAGE_CNT,
						       sub_page_cnt.u64);
				}
				cvmx_write_csr(CVMX_IPD_PORTX_BP_PAGE_CNT(pci_port), page_cnt.u64);
				fau = (cvmx_fau_reg_32_t) cvmx_fau32_alloc(CVMX_FAU_REG_ANY);
				if (fau == -1) {
					printf("Fau allocation failed\n");
					return -1;
				}
				cvmx_fau_atomic_write32(fau, 0);
				octnic->dpi_bp.cn66xx.dpi_bp_fau_map[j].s.fau = fau;
				octnic->dpi_bp.cn66xx.dpi_bp_fau_map[j].s.enabled = 1;
				printf("BP: PCI port %d index %d fau %d\n",pci_port, j, fau);
			}
		}
	}
#endif
	return 0;
}

/* configure transmission of flow ctl */
static int cvmcs_nic_init_gmx_bp()
{
#ifdef GMX_BP
	int fau;
	int gmxport;
	uint32_t i;

	if (OCTEON_IS_MODEL(OCTEON_CN68XX)) {
		for (i = 0; i < octnic->ngmxports; i++) {
			cvmx_ipd_bpidx_mbuf_th_t mbuf_th;
			cvmx_pip_prt_cfgbx_t cfgb;
			cvmx_ipd_sub_port_bp_page_cnt_t sub_port_page;
			cvmx_ipd_bpid_bp_counterx_t bp_cnt;
			int pknd;
			int bpid;

			gmxport = octnic->gmx_port_info[i].ipd_port;
			pknd =
			    cvmx_helper_get_pknd(INTERFACE(gmxport), INDEX(gmxport));
			cfgb.u64 = cvmx_read_csr(CVMX_PIP_PRT_CFGBX(pknd));
			bpid = cfgb.s.bpid;
			//PKND, BPID, GMX_BPID_MAP are taken care of by SDK
			//clear counters
			bp_cnt.u64 =
			    cvmx_read_csr(CVMX_IPD_BPID_BP_COUNTERX(bpid));
			if (bp_cnt.s.cnt_val) {
				sub_port_page.u64 = 0;
				sub_port_page.s.port = bpid;
				sub_port_page.s.page_cnt = -bp_cnt.s.cnt_val;
				cvmx_write_csr(CVMX_IPD_SUB_PORT_BP_PAGE_CNT,
					       sub_port_page.u64);
			}
			mbuf_th.u64 = 0;
			mbuf_th.s.bp_enb = 1;
			mbuf_th.s.page_cnt = GMX_BP_THRESHOLD_68XX >> 8;	//in 256 pages
			cvmx_write_csr(CVMX_IPD_BPIDX_MBUF_TH(bpid),
				       mbuf_th.u64);
			octnic->gmx_bp.cn68xx.gmx_bp_fau_map[i].s.bpid = bpid;
			//setup faus to keep track
			fau = cvmx_fau32_alloc(CVMX_FAU_REG_ANY);
			if (fau == -1) {
				printf("fau alloc failed\n");
				return -1;
			}
			cvmx_fau_atomic_write32(fau, 0);
			octnic->gmx_bp.cn68xx.gmx_bp_fau_map[i].s.fau = fau;
			octnic->gmx_bp.cn68xx.gmx_bp_fau_map[i].s.enabled = 1;
			printf("GMX%d: IPD %d pkind %d, bpid %d fau %d\n",
			       i, gmxport, pknd, bpid, fau);
		}
	} else if (OCTEON_IS_MODEL(OCTEON_CN66XX)) {
		for (i = 0; i < octnic->ngmxports; i++) {
			union cvmx_ipd_portx_bp_page_cnt page_cnt;
			cvmx_ipd_port_bp_counters_pairx_t bp_cnt;
			union cvmx_ipd_sub_port_bp_page_cnt sub_page_cnt;
			int gmxport;

			page_cnt.u64 = 0;
			page_cnt.s.page_cnt = GMX_BP_THRESHOLD_66XX >> 8;       //in 256 pages
			page_cnt.s.bp_enb = 1;
			gmxport = octnic->gmx_port_info[i].ipd_port;
			cvmx_write_csr(CVMX_IPD_PORTX_BP_PAGE_CNT(gmxport), page_cnt.u64);
			bp_cnt.u64 = cvmx_read_csr(CVMX_IPD_PORT_BP_COUNTERS_PAIRX(gmxport));
			if (bp_cnt.s.cnt_val) {
				printf("error bp count non zero  %d:%d\n", gmxport,  bp_cnt.s.cnt_val);
				printf("Setting to 0\n");
				sub_page_cnt.u64 = 0;
				sub_page_cnt.s.port = gmxport;
				sub_page_cnt.s.page_cnt = -bp_cnt.s.cnt_val;
				cvmx_write_csr(CVMX_IPD_SUB_PORT_BP_PAGE_CNT,
							     sub_page_cnt.u64);
			}
			cvmx_write_csr(CVMX_IPD_PORTX_BP_PAGE_CNT(gmxport), page_cnt.u64);
			fau = (cvmx_fau_reg_32_t) cvmx_fau32_alloc(CVMX_FAU_REG_ANY);
			if (fau == -1) {
				printf("Fau allocation failed\n");
				return -1;
			}
			cvmx_fau_atomic_write32(fau, 0);
			octnic->gmx_bp.cn66xx.gmx_bp_fau_map[i].s.fau = fau;
			octnic->gmx_bp.cn66xx.gmx_bp_fau_map[i].s.enabled = 1;
			printf("GMX%d: IPD %d fau %d\n", i, gmxport, fau);
		}
	}
#endif
	return 0;
}

//global bp setup
int cvmcs_nic_init_bp()
{
	if (cvmcs_nic_init_dpi_bp_ctrl_iq())
		return -1;
	if (cvmcs_nic_init_gmx_bp())
		return -1;
#if (defined(DPI_BP) || defined(GMX_BP))
	if (OCTEON_IS_MODEL(OCTEON_CN68XX) ||
	    OCTEON_IS_MODEL(OCTEON_CN66XX)) {
		cvmx_ipd_ctl_status_t ctl;

		ctl.u64 = cvmx_read_csr(CVMX_IPD_CTL_STATUS);
		if (ctl.s.pbp_en)
			return 0;
		ctl.s.pbp_en = 1;
		// count number of buffers
		ctl.s.naddbuf = 0;
		ctl.s.addpkt = 0;
		cvmx_write_csr(CVMX_IPD_CTL_STATUS, ctl.u64);
	}
#endif
	return 0;
}

//configure how nic reacts to received flow ctl
static void cvmcs_nic_init_rx_flow_ctl()
{
	int port;
	uint32_t i;
	for (i=0; i < octnic->ngmxports; i++) {
		if (OCTEON_IS_MODEL(OCTEON_CN66XX) ||
		    OCTEON_IS_MODEL(OCTEON_CN68XX)) {
			cvmx_gmxx_rxx_frm_ctl_t ctl;

			port = octnic->gmx_port_info[i].ipd_port;

			ctl.u64 =
			    cvmx_read_csr(CVMX_GMXX_RXX_FRM_CTL
					  (INDEX(port), INTERFACE(port)));
			if (ctl.s.ctl_bck  && ctl.s.ctl_drp)
				return;
			//hw handles everything
			ctl.s.ctl_bck = 1;
			ctl.s.ctl_drp = 1;
			cvmx_write_csr(CVMX_GMXX_RXX_FRM_CTL
				       (INDEX(port), INTERFACE(port)), ctl.u64);
		} else {
			if (OCTEON_IS_MODEL(OCTEON_CN78XX) ||
			    OCTEON_IS_MODEL(OCTEON_CN73XX)) {
				int interface, index;
				cvmx_bgxx_smux_tx_ctl_t smu_tx_ctl;
				cvmx_bgxx_smux_rx_frm_ctl_t frm_ctl;
				cvmx_bgxx_cmrx_rx_adr_ctl_t adr_ctl;
				cvmx_bgxx_smux_cbfc_ctl_t cbfc_ctl;

				port = octnic->gmx_port_info[i].ipd_port;

 				interface = cvmx_helper_get_interface_num(port) & 0xff;
				index = cvmx_helper_get_interface_index_num(port);

        			cbfc_ctl.u64 = cvmx_read_csr(CVMX_BGXX_SMUX_CBFC_CTL(index, interface));
        			cbfc_ctl.s.rx_en  = 0;
        			cbfc_ctl.s.tx_en  = 0;
        			cbfc_ctl.s.bck_en = 0;
        			cbfc_ctl.s.drp_en = 0;
        			cvmx_write_csr(CVMX_BGXX_SMUX_CBFC_CTL(index,interface), cbfc_ctl.u64);

				smu_tx_ctl.u64 = cvmx_read_csr_node(cvmx_get_node_num(),
					CVMX_BGXX_SMUX_TX_CTL(index, interface));

				smu_tx_ctl.s.l2p_bp_conv = 1;

				cvmx_write_csr_node(cvmx_get_node_num(),
					CVMX_BGXX_SMUX_TX_CTL(index, interface), smu_tx_ctl.u64);

        			frm_ctl.u64 = cvmx_read_csr_node(cvmx_get_node_num(),
					CVMX_BGXX_SMUX_RX_FRM_CTL(index, interface));
        			frm_ctl.s.ctl_bck = 1;
        			frm_ctl.s.ctl_drp = 1;
        			cvmx_write_csr_node(cvmx_get_node_num(),
					CVMX_BGXX_SMUX_RX_FRM_CTL(index, interface), frm_ctl.u64);

                        	if (OCTEON_IS_MODEL(OCTEON_CN78XX_PASS1_X)) {
        				adr_ctl.u64 = cvmx_read_csr_node(cvmx_get_node_num(),
						CVMX_BGXX_CMRX_RX_ADR_CTL(index, interface));
        				adr_ctl.s.cam_accept = 0;
        				adr_ctl.s.mcst_mode = 1;
        				adr_ctl.s.bcst_accept = 1;
        				cvmx_write_csr_node(cvmx_get_node_num(),
						CVMX_BGXX_CMRX_RX_ADR_CTL(index, interface), adr_ctl.u64);
				}
			}
		}
	}
}

//configure how nic transmits flow control
static void cvmcs_nic_init_tx_flow_ctl(void)
{
	//specify pause time and send frequency.
	//GMX_TXX_PAUSE_PKT_TIME and GMXX_PAUSE_PKT_INTERVAL
	//configure  GMX_TXX_PAUSE_ZERO
	//not modifying defaults for now
}

void cvmcs_nic_init_flow_ctl()
{
	cvmcs_nic_init_tx_flow_ctl();
	cvmcs_nic_init_rx_flow_ctl();
}


//configure how nic reacts to received flow ctl
static void cvmcs_bgxx_set_rx_flow_ctl(int port, int on)
{
	if (OCTEON_IS_MODEL(OCTEON_CN78XX) ||
	    OCTEON_IS_MODEL(OCTEON_CN73XX)) {
		int interface, index;
		cvmx_bgxx_smux_rx_frm_ctl_t frm_ctl;

		interface = cvmx_helper_get_interface_num(port) & 0xff;
		index = cvmx_helper_get_interface_index_num(port);

		frm_ctl.u64 = cvmx_read_csr_node(cvmx_get_node_num(),
			CVMX_BGXX_SMUX_RX_FRM_CTL(index, interface));
		if (on) {
			frm_ctl.s.ctl_bck = 1;
			frm_ctl.s.ctl_drp = 1;
		} else {
			frm_ctl.s.ctl_bck = 0;
			frm_ctl.s.ctl_drp = 1;
		}
		cvmx_write_csr_node(cvmx_get_node_num(),
			CVMX_BGXX_SMUX_RX_FRM_CTL(index, interface), frm_ctl.u64);
	}
}

/* disable:
 *      1 => disable backpressure
 *      0 => enable backpressure
 */
int cvmx_nic_bgx_set_backpressure_override(int port, int disable)
{
	cvmx_bgxx_cmr_rx_ovr_bp_t rx_ovr_bp;
	int node = cvmx_get_node_num();
	unsigned index = INDEX(port);
	unsigned lmac_mask;

	rx_ovr_bp.u64 = cvmx_read_csr_node(node, CVMX_BGXX_CMR_RX_OVR_BP(INTERFACE(port)));
	lmac_mask = rx_ovr_bp.s.en;
	switch (index) {
		case 0:
			index=0x1;
			break;
		case 1:
			index=0x2;
			break;
		case 2:
			index=0x4;
			break;
		case 3:
			index=0x8;
			break;
	}

	if (disable)
		lmac_mask = lmac_mask | index;
	else
		lmac_mask = lmac_mask & (~index);

	rx_ovr_bp.s.en = lmac_mask;
	rx_ovr_bp.s.ign_fifo_bp = lmac_mask;

	cvmx_write_csr_node(node, CVMX_BGXX_CMR_RX_OVR_BP(INTERFACE(port)), rx_ovr_bp.u64);

	rx_ovr_bp.u64 = cvmx_read_csr_node(node, CVMX_BGXX_CMR_RX_OVR_BP(INTERFACE(port)));
	
	return 0;
}

//configure how nic transmits flow control
static void cvmcs_bgxx_set_tx_flow_ctl(int ipd_port, int on)
{
	if (OCTEON_IS_MODEL(OCTEON_CN78XX) ||
	    OCTEON_IS_MODEL(OCTEON_CN73XX)) {
		int interface, index;
		cvmx_bgxx_smux_tx_ctl_t smu_tx_ctl;

		interface = cvmx_helper_get_interface_num(ipd_port) & 0xff;
		index = cvmx_helper_get_interface_index_num(ipd_port);

		smu_tx_ctl.u64 = cvmx_read_csr_node(cvmx_get_node_num()     ,
			CVMX_BGXX_SMUX_TX_CTL(index, interface));

		if (on)
			smu_tx_ctl.s.l2p_bp_conv = 1;
		else
			smu_tx_ctl.s.l2p_bp_conv = 0;

		cvmx_write_csr_node(cvmx_get_node_num(),
			CVMX_BGXX_SMUX_TX_CTL(index, interface), smu_tx_ctl.u64);

		if (on)
			cvmx_nic_bgx_set_backpressure_override(ipd_port, 0);
		else
			cvmx_nic_bgx_set_backpressure_override(ipd_port, 1);
	}
}

//ethtool hook to turn on or off sending 802.3 pause frames
void cvmcs_nic_set_tx_flow_ctl(int port, int on)
{
	cvmx_gmxx_tx_ovr_bp_t gmxx_tx_ovr_bp;

	if (OCTEON_IS_MODEL(OCTEON_CN78XX) ||
	    OCTEON_IS_MODEL(OCTEON_CN73XX)) {
		cvmcs_bgxx_set_tx_flow_ctl(port, on);
		return;
	}

	gmxx_tx_ovr_bp.u64 =
	    cvmx_read_csr(CVMX_GMXX_TX_OVR_BP(INTERFACE(port)));
	gmxx_tx_ovr_bp.s.en = (!on) & (0x1 << INDEX(port));
	gmxx_tx_ovr_bp.s.ign_full = (!on) & (0x1 << INDEX(port));
	cvmx_write_csr(CVMX_GMXX_TX_OVR_BP(INTERFACE(port)),
		       gmxx_tx_ovr_bp.u64);
}

//ethtool hook to turn on or off honoring recieved pause frames
void cvmcs_nic_set_rx_flow_ctl(int port, int on)
{
	cvmx_gmxx_rxx_frm_ctl_t ctl;

	if (OCTEON_IS_MODEL(OCTEON_CN78XX) ||
	    OCTEON_IS_MODEL(OCTEON_CN73XX)) {
		cvmcs_bgxx_set_rx_flow_ctl(port, on);
		return;
	}

	ctl.u64 =
	    cvmx_read_csr(CVMX_GMXX_RXX_FRM_CTL(INDEX(port), INTERFACE(port)));
	if (on) {
		//hw handles everything
		ctl.s.ctl_bck = 1;
		ctl.s.ctl_drp = 1;
	} else {
		//ignore recieved flow ctl
		ctl.s.ctl_bck = 0;
		ctl.s.ctl_drp = 1;
	}
	cvmx_write_csr(CVMX_GMXX_RXX_FRM_CTL(INDEX(port), INTERFACE(port)),
		       ctl.u64);
}

static void cvmcs_nic_set_flow_ctl(int port, int rx_pause, int tx_pause)
{
	cvmcs_nic_set_tx_flow_ctl(port, tx_pause);
	cvmcs_nic_set_rx_flow_ctl(port, rx_pause);
}

/* copied from SDK as this function is not exported */
static int cvmcs_pko3_res_owner(int ipd_port)
{
	int res_owner;
	const int res_owner_pfix = 0x19d0 << 14;

	ipd_port &= 0x3fff;     /* 12-bit for local CHAN_E value + node */

	res_owner = res_owner_pfix | ipd_port;

	return res_owner;
}

/* setup to flush a stuck DQ and release FPA buffers from the DQ
 *
 * Reserve an L1 SQ dedicated connected to the NULL link. Let’s say that
 * L1 SQ 0 drain to the NULL link, and are set up with RR_PRIO=0.
 * when a DQ is observed to be stuck at runtime, this reserved L1-SQ will be 
 * made parent of stuck DQ's L2-SQ to free up all FPA buffers from the stuck DQ
 **/
int cvmcs_nic_setup_flush_dq(void)
{
	int node;
	int l1_q_num;
	enum cvmx_pko3_level_e level;
	int ipd_port;
	int res, res_owner;
	int null_link_mac = 15; //HRM says link 14 is NULL FIFO, but SDK uses 15

	node = cvmx_get_node_num();

	/* Build an identifiable owner identifier by MAC# for easy release */
	ipd_port = cvmx_helper_node_to_ipd_port(node, CVMX_PKO3_IPD_PORT_NULL);
	res_owner = cvmcs_pko3_res_owner(ipd_port);
	if (res_owner < 0) {
		cvmcs_printf ("%s: ERROR Invalid interface\n", __FUNCTION__);
		return -1;
	}

	/* Start configuration at L1/PQ */
	level = CVMX_PKO_PORT_QUEUES;
	l1_q_num = cvmx_pko_alloc_queues(node, level, res_owner, -1, 1);
	if (l1_q_num < 0) {
		cvmcs_printf ("%s: ERROR reserving L1 SQ\n", __func__);
		return -1;
	}

	res = cvmx_pko3_pq_config(node, null_link_mac, l1_q_num);
	if (res < 0) {
		cvmcs_printf("ERROR: %s:PQ/L1 queue configuration\n", __func__);
		return -1;
	}

	octnic->null_link_l1_q = l1_q_num;
	cvmcs_printf("%s: allocated L1-SQ%d and connected to NULL link,"
		     " to use for DQ flush\n", __func__, l1_q_num);
	octnic->dq_flush_enabled = 1;

	return 0;
}

int cvmcs_nic_find_l2q_from_dq(int node, int dq)
{
	cvmx_pko_dqx_topology_t dqtop;
	cvmx_pko_l3_sqx_topology_t l3top;

	dqtop.u64 = cvmx_read_csr_node(node, CVMX_PKO_DQX_TOPOLOGY(dq));
	l3top.u64 = 
	     cvmx_read_csr_node(node, CVMX_PKO_L3_SQX_TOPOLOGY(dqtop.s.parent));
	return l3top.s.parent;
}

int cvmcs_nic_find_l3q_from_dq(int node, int dq)
{
	cvmx_pko_dqx_topology_t dqtop;

	dqtop.u64 = cvmx_read_csr_node(node, CVMX_PKO_DQX_TOPOLOGY(dq));
	return dqtop.s.parent;
}

/* copied from SDK as this function is not exported */
static int cvmx_pko3_chan_2_xchan(uint16_t ipd_port)
{
	uint16_t xchan;
	uint8_t off;
	static const uint8_t *xchan_base = NULL;
	static const uint8_t xchan_base_cn78xx[16] = {
		/* IPD 0x000 */ 0x3c0 >> 4,	/* LBK */
		/* IPD 0x100 */ 0x380 >> 4,	/* DPI */
		/* IPD 0x200 */ 0xfff >> 4,	/* not used */
		/* IPD 0x300 */ 0xfff >> 4,	/* not used */
		/* IPD 0x400 */ 0x000 >> 4,	/* ILK0 */
		/* IPD 0x500 */ 0x100 >> 4,	/* ILK1 */
		/* IPD 0x600 */ 0xfff >> 4,	/* not used */
		/* IPD 0x700 */ 0xfff >> 4,	/* not used */
		/* IPD 0x800 */ 0x200 >> 4,	/* BGX0 */
		/* IPD 0x900 */ 0x240 >> 4,	/* BGX1 */
		/* IPD 0xa00 */ 0x280 >> 4,	/* BGX2 */
		/* IPD 0xb00 */ 0x2c0 >> 4,	/* BGX3 */
		/* IPD 0xc00 */ 0x300 >> 4,	/* BGX4 */
		/* IPD 0xd00 */ 0x340 >> 4,	/* BGX5 */
		/* IPD 0xe00 */ 0xfff >> 4,	/* not used */
		/* IPD 0xf00 */ 0xfff >> 4	/* not used */
	};
	static const uint8_t xchan_base_cn73xx[16] = {
		/* IPD 0x000 */ 0x0c0 >> 4,	/* LBK */
		/* IPD 0x100 */ 0x100 >> 4,	/* DPI */
		/* IPD 0x200 */ 0xfff >> 4,	/* not used */
		/* IPD 0x300 */ 0xfff >> 4,	/* not used */
		/* IPD 0x400 */ 0xfff >> 4,	/* not used */
		/* IPD 0x500 */ 0xfff >> 4,	/* not used */
		/* IPD 0x600 */ 0xfff >> 4,	/* not used */
		/* IPD 0x700 */ 0xfff >> 4,	/* not used */
		/* IPD 0x800 */ 0x000 >> 4,	/* BGX0 */
		/* IPD 0x900 */ 0x040 >> 4,	/* BGX1 */
		/* IPD 0xa00 */ 0x080 >> 4,	/* BGX2 */
		/* IPD 0xb00 */ 0xfff >> 4,	/* not used */
		/* IPD 0xc00 */ 0xfff >> 4,	/* not used */
		/* IPD 0xd00 */ 0xfff >> 4,	/* not used */
		/* IPD 0xe00 */ 0xfff >> 4,	/* not used */
		/* IPD 0xf00 */ 0xfff >> 4	/* not used */
	};
	static const uint8_t xchan_base_cn75xx[16] = {
		/* IPD 0x000 */ 0x040 >> 4,	/* LBK */
		/* IPD 0x100 */ 0x080 >> 4,	/* DPI */
		/* IPD 0x200 */ 0xeee >> 4,	/* SRIO0  noop */
		/* IPD 0x300 */ 0xfff >> 4,	/* not used */
		/* IPD 0x400 */ 0xfff >> 4,	/* not used */
		/* IPD 0x500 */ 0xfff >> 4,	/* not used */
		/* IPD 0x600 */ 0xfff >> 4,	/* not used */
		/* IPD 0x700 */ 0xfff >> 4,	/* not used */
		/* IPD 0x800 */ 0x000 >> 4,	/* BGX0 */
		/* IPD 0x900 */ 0xfff >> 4,	/* not used */
		/* IPD 0xa00 */ 0xfff >> 4,	/* not used */
		/* IPD 0xb00 */ 0xfff >> 4,	/* not used */
		/* IPD 0xc00 */ 0xfff >> 4,	/* not used */
		/* IPD 0xd00 */ 0xfff >> 4,	/* not used */
		/* IPD 0xe00 */ 0xfff >> 4,	/* not used */
		/* IPD 0xf00 */ 0xfff >> 4	/* not used */
	};

        if (OCTEON_IS_MODEL(OCTEON_CN73XX))
		xchan_base = xchan_base_cn73xx;
        if (OCTEON_IS_MODEL(OCTEON_CNF75XX))
		xchan_base = xchan_base_cn75xx;
        if (OCTEON_IS_MODEL(OCTEON_CN78XX))
		xchan_base = xchan_base_cn78xx;

	if (xchan_base == NULL)
		return -1;

	xchan = ipd_port >> 8;

	/* ILKx, DPI has 8 bits logical channels, others just 6 */
	if (((xchan & 0xfe) == 0x04) || xchan == 0x01)
		off = ipd_port & 0xff;
	else
		off = ipd_port & 0x3f;

	xchan = xchan_base[ xchan & 0xF ];

	if(xchan == 0xff)
		return -1;	/* Invalid IPD_PORT */
	else if (xchan == 0xee)
		return -2;	/* LUT not used */
	else
		return (xchan << 4) | off;
}

void cvmcs_nic_flush_dq(vnic_port_info_t *vnic_port, int dq)
{
	int l2_q, node;
	int xchan;
	cvmx_pko_lutx_t lutx;
	cvmx_pko_l2_sqx_sw_xoff_t l2_xoff;
	cvmx_pko_l3_l2_sqx_channel_t sq_chan;
	cvmx_pko_l2_sqx_topology_t l2top, l2top_saved;
	cvmx_pko_l2_sqx_schedule_t l2_sched, l2_sched_saved;
	cvmx_pko_dqx_wm_cnt_t wm_cnt;
	int dq_stat_idx = dq - oct->pcipko_base_dq;

	node = cvmx_get_node_num();
	/* Step-1: Reserve one L2 and L1 SQ dedicated connected to NULL link.
	 * done as part of firmware initialization: cvmcs_nic_setup_flush_dq()
	 **/
	
	/* Step-2: Stop adding descriptors to the child DQs */
	dq_flush_in_progress[dq_stat_idx] = 1;
	CVMX_SYNCWS;

	/* Step-3: Check that PKO_L3_L2_SQ(L32)_CHANNEL[HW_XOFF] is set.
	 * skip all the following steps if this HW_XOFF is clear
	 **/
	l2_q = cvmcs_nic_find_l2q_from_dq(node, dq);
	sq_chan.u64 = 
		cvmx_read_csr_node(node, CVMX_PKO_L3_L2_SQX_CHANNEL(l2_q));
	if(!sq_chan.s.hw_xoff) {
		printf("%s: SQX_CHANNEL[hw_xoff] for L2-SQ-%d is clear; "
		       "Nothing to do\n", __func__, l2_q);
		dq_flush_in_progress[dq_stat_idx] = 0;
		CVMX_SYNCWS;
		return;
	}

	/* Step-4: Set PKO_L3_SQ(L32)_SW_XOFF or PKO_L2_SQ(L32)_SW_XOFF[SW_XOFF]
	 * depending on PKO_CHANNEL_LEVEL[CC_LEVEL], to guarantee that no 
	 * further packets flow through the channel
	 **/
	/* CC_LEVEL is 0. So, Level-2 is the channel level */
	l2_xoff.u64 = cvmx_read_csr_node(node, CVMX_PKO_L2_SQX_SW_XOFF(l2_q));
        l2_xoff.s.xoff = 1;
        cvmx_write_csr_node(node, CVMX_PKO_L2_SQX_SW_XOFF(l2_q), l2_xoff.u64);

	/* Step-5: Clear PKO_L3_SQ(L32)_TOPOLOGY[PARENT] or
	 * PKO_L2_SQ(L32)_TOPOLOGY[PARENT] (depending on
	 * PKO_CHANNEL_LEVEL[CC_LEVEL]) to zero (to point to the SQs leading to
	 * the NULL link) without changing any other value in the CSR.
	 **/
        l2top.u64 = cvmx_read_csr_node(node, CVMX_PKO_L2_SQX_TOPOLOGY(l2_q));
	l2top_saved = l2top;
        l2top.s.parent = octnic->null_link_l1_q;
        cvmx_write_csr_node(node, CVMX_PKO_L2_SQX_TOPOLOGY(l2_q), l2top.u64);

	/* Step-6: Clear PKO_L3_SQ(L32)_SCHEDULE[PRIO] or
	 * PKO_L3_SQ(L32)_SCHEDULE[PRIO] (depends on
	 * PKO_CHANNEL_LEVEL[CC_LEVEL]) to zero (to use round-robin in the SQs
	 * leading to the NULL link) without changing any other value in the CSR
	 **/
        l2_sched.u64 = cvmx_read_csr_node(node, CVMX_PKO_L2_SQX_SCHEDULE(l2_q));
	l2_sched_saved.u64 = l2_sched.u64;
        l2_sched.s.prio = 0;
        cvmx_write_csr_node(node, CVMX_PKO_L2_SQX_SCHEDULE(l2_q), l2_sched.u64);

	/* Step-7: Clear the relevant PKO_LUT(0..383)[VALID] */
	xchan =  cvmx_pko3_chan_2_xchan(sq_chan.s.cc_channel);
	lutx.u64 = cvmx_read_csr_node(node, CVMX_PKO_LUTX(xchan));
	lutx.s.valid = 0;
	cvmx_write_csr_node(node, CVMX_PKO_LUTX(xchan), lutx.u64);

	/* Step-8: Clear PKO_L3_SQ(L32)_SW_XOFF[SW_XOFF] or
	 * PKO_L2_SQ(L32)_SW_XOFF[SW_XOFF] (depends on
	 * PKO_CHANNEL_LEVEL[CC_LEVEL]) to zero
	 **/
	/* moved Step-8 to past Step-9; otherwise, the DQ never got flushed */

	/* Step-9: Clear PKO_L3_L2_SQ(L32)_CHANNEL[HW_XOFF,CC_ENABLE] to zero.
	 * This should allow packets to flow through the channel despite the
	 * channel backpressure.
	 **/
	sq_chan.s.hw_xoff = 0;
	sq_chan.s.cc_enable = 0;
	cvmx_write_csr_node(node, CVMX_PKO_L3_L2_SQX_CHANNEL(l2_q), sq_chan.u64);

	/* relocated Step-8 */
        l2_xoff.s.xoff = 0;
        cvmx_write_csr_node(node, CVMX_PKO_L2_SQX_SW_XOFF(l2_q), l2_xoff.u64);

	/* Step-10: For each DQ affected by the channel backpressure
	 * (i.e. in the tree), wait for PKO_DQ(0..255)_WM_CNT[COUNT] to be 0x0
	 **/
	do {
		cvmx_wait_usec(10);
		wm_cnt.u64 = cvmx_read_csr_node(node, CVMX_PKO_DQX_WM_CNT(dq));
	} while(wm_cnt.s.count);
	//cvmcs_printf("flush of DQ-%d complete\n", dq);

	/* DQ flush complete; now restore the configuration on flushed DQ */
	/* reverse Step-10: nothing to do */
	/* reverse Step-9: Enable channel credits */
	sq_chan.s.hw_xoff = 1;
	sq_chan.s.cc_enable = 1;
	cvmx_write_csr_node(node, CVMX_PKO_L3_L2_SQX_CHANNEL(l2_q), sq_chan.u64);
	/* reverse Step-8: nothing to do */
	/* reverse Step-7: set relevant PKO_LUT(0..383)[VALID] */
	lutx.s.valid = 1;
	cvmx_write_csr_node(node, CVMX_PKO_LUTX(xchan), lutx.u64);
	/* reverse Step-6: restore scheduling on flushed DQ to original */
        cvmx_write_csr_node(node, CVMX_PKO_L2_SQX_SCHEDULE(l2_q),
			    l2_sched_saved.u64);
	/* reverse Step-5: restore the parent in flushed DQ to original */
        cvmx_write_csr_node(node,
			    CVMX_PKO_L2_SQX_TOPOLOGY(l2_q), l2top_saved.u64);
	/* reverse Step-4: nothing to do */
	/* reverse Step-3: nothing to do */
	/* reverse Step-2: nothing to do */
	/* reverse Step-1: do not release L2/L1-SQ; reuse when needed */
	cvmx_wait_usec(2);
	dq_flush_in_progress[dq_stat_idx] = 0;
	CVMX_SYNCWS;
}

//TODO: provide a private ethtool flag to disable/enable this feature ???
int cvmcs_nic_monitor_dq(void *arg)
{
	int ifidx, q_idx, oq, pko_q;
	u64 cur_cycle, diff_cycle, queue_stuck_cycles_thresh;
	vnic_port_info_t *vnic_port;
	int node;
	u64 dq_pkts, wm_cnt;

	node = cvmx_get_node_num();

	queue_stuck_cycles_thresh =
			cpu_freq * PKO_DQ_STUCK_THRESH_INTVL / 1000ULL;

	for (ifidx = 0; ifidx < MAX_OCTEON_NIC_PORTS; ifidx++) {
		vnic_port = &octnic->port[ifidx];
		/* monitor only active vnic's */
		if (! vnic_port->state.active) {
			continue;
		}

		for (q_idx = 0; q_idx < vnic_port->linfo.num_rxpciq; q_idx++) {
			oq = OCT_NIC_OQ_NUM(vnic_port, q_idx);
			pko_q = oq_status[oq].pko_q;

			wm_cnt = cvmx_read_csr_node(node, 
						    CVMX_PKO_DQX_WM_CNT(pko_q));
			if ((wm_cnt & 0xFFFFFFFFFFFFULL) <
			    DQ_FLUSH_THRESHOLD_73XX) {
				oq_status[oq].last_dq_pkts = 0;
				continue;
			}

			/* this code is executed only when there are PKO drops
			 * are seen on this DQ;
			 * check if DQ is moving; if not moving for a period of 
			 * queue_stuck_cycles_thresh cycles, assume queue is
			 * stuck and flush it; if the queue is moving, then 
			 * reset the queue monitoring state to healthy
			 */
			dq_pkts = cvmx_read_csr_node(node, 
					   CVMX_PKO_DQX_PACKETS(pko_q));
			cur_cycle = cvmx_get_cycle();
			if (!oq_status[oq].last_dq_pkts) {
				/* start monitoring DQ activity now */
				oq_status[oq].last_dq_pkts = dq_pkts;
				oq_status[oq].last_active_cycles = cur_cycle;
				/* will check for queue stuck condition in 
				 * next invocation
				 **/
				continue;
			}
			if (dq_pkts != oq_status[oq].last_dq_pkts) {
				/* DQ is moving; reset the monitoring state
				 * and continue.
				 **/
				oq_status[oq].last_dq_pkts = 0;
				continue;
			}
			diff_cycle = CYCLE_DIFF(cur_cycle,
					oq_status[oq].last_active_cycles);
			if (diff_cycle > queue_stuck_cycles_thresh) {
				cvmcs_nic_flush_dq(vnic_port, pko_q);
				oq_status[oq].last_dq_pkts = 0;
			}
			continue;
		}
	}
	return 0;
}

int cvmcs_nic_start_dq_monitoring_task()
{
	if (booting_for_the_first_time) {
		int oq;
		uint64_t size;

		size = MAX_OCTEON_OQ * sizeof (oq_mon_status_t);
		oq_status = cvmx_bootmem_alloc_named(size, CVMX_CACHE_LINE_SIZE, "__oq_status");
		live_upgrade_ctx->oq_status = oq_status;
		memset(oq_status, 0, size);

		for (oq = 0; oq < MAX_DROQS_CN73XX; oq++) {
			oq_status[oq].pko_q = cvm_pci_get_oq_pkoqueue(oq);
		}

		size = MAX_DROQS_CN73XX * sizeof (uint8_t);
		dq_flush_in_progress = cvmx_bootmem_alloc_named(size, CVMX_CACHE_LINE_SIZE, "__dq_flush_in_progress");
		live_upgrade_ctx->dq_flush_in_progress = dq_flush_in_progress;
		memset(dq_flush_in_progress, 0, size);

		/* setup DQ flush: reserve a SQ pair and connect it to null-link */
		if (cvmcs_nic_setup_flush_dq()) {
			cvmcs_printf("Failed to setup SQ pair to flush a stuck DQ\n");
			return -1;
		}
	} else {
		oq_status = live_upgrade_ctx->oq_status;
		dq_flush_in_progress = live_upgrade_ctx->dq_flush_in_progress;
	}

	return cvmcs_common_add_task((cpu_freq * 1)/BGX_OQ_TASK_SCHED_HZ,
				     cvmcs_nic_monitor_dq, NULL);
}

int cvmcs_nic_update_timestamp(void *arg)
{
	secs_from_boot++;
	return 0;	
}

int cvmcs_nic_start_timestamp_task()
{

	return cvmcs_common_add_task((cpu_freq * 1),
					cvmcs_nic_update_timestamp, NULL);
}

/* clear latched ber and bercnt at first link up */
static void cvmcs_clear_bgx_ber(gmx_port_info_t *info)
{
	int port = info->ipd_port;
	int xiface = INTERFACE(port);
	int index = INDEX(port);
	struct cvmx_xiface xi;
	cvmx_bgxx_spux_br_status2_t status2;

	xi = cvmx_helper_xiface_to_node_interface(xiface);
	status2.u64 = cvmx_read_csr(CVMX_BGXX_SPUX_BR_STATUS2(index, xi.interface));
	/* clear latched_ber. ber_cnt and err_blks is cleared on read */
	//if (status2.s.ber_cnt || status2.s.latched_ber || status2.s.err_blks)
	cvmcs_printf("clear at linkup latched_ber=%d ber_cnt=%d err_blks=%d for ipd_port %d\n", status2.s.latched_ber,
			     status2.s.ber_cnt, status2.s.err_blks, port);
	if (status2.s.latched_ber)
		cvmx_write_csr(CVMX_BGXX_SPUX_BR_STATUS2(index,xi.interface),
								  (1ULL << 14));
}

void cvmcs_bgx_link_up(gmx_port_info_t *info)
{
	int port = info->ipd_port;
	int xiface = INTERFACE(port);
	int index = INDEX(port);
	int xipd_port = cvmx_helper_get_ipd_port(xiface, index);

	if  (info->link_state == LINK_UP ||
	     info->link_state == LINK_TRYING)
		return;

	cvmx_spinlock_lock(&info->link_lock);
	__cvmx_helper_bgx_port_init(xipd_port, 0);
	info->link_state = LINK_TRYING;
	cvmx_spinlock_unlock(&info->link_lock);
}

void cvmcs_bgx_link_down(gmx_port_info_t *info)
{
	int port = info->ipd_port;
	int xiface = INTERFACE(port);
	int index = INDEX(port);
	cvmx_bgxx_cmrx_config_t config;
	cvmx_bgxx_smux_rx_jabber_t jabber;
	cvmx_bgxx_cmrx_rx_fifo_len_t fifo_len;
	cvmx_bgxx_cmrx_tx_fifo_len_t tx_fifo_len;
	cvmx_bgxx_spux_control1_t control1;
	int node = cvmx_get_node_num();
	int us,count;
	int interface;
	cvmx_pko_dqx_wm_cnt_t wm_cnt;
	int base_pko_dq, i;
	int gmx_dq_count = 1;

	if (info->link_state == LINK_DOWN)
		return;

	interface = xiface &  0xff;
	cvmx_spinlock_lock(&info->link_lock);

	/* wait for the source traffic to stop: wait for all other cores to see
	 * link going down and stop enqueuing to PKO DQ of BGX going down
	 * - this is done by waiting for corresponding PKO-DQ to get flushed
	 */
	if (octeon_has_feature(OCTEON_FEATURE_PKND))
		base_pko_dq = cvmx_pko_get_base_queue_pkoid(port);
	else
		base_pko_dq = cvmx_pko_get_base_queue(port);
	count = 0;
	while (++count < 1000) {
		cvmx_wait_usec(100);
		if (octnic->dcb[index].dcb_enabled)
			gmx_dq_count = 8;

		for (i = 0; i < gmx_dq_count; i++) {
			wm_cnt.u64 = cvmx_read_csr_node(node, 
				CVMX_PKO_DQX_WM_CNT(base_pko_dq + i));
			if (wm_cnt.s.count)
				break;
		}

		if (i == gmx_dq_count)
			break; /* all PKO-DQ's leading to BGX are clear */
	}
	if (count == 1000) {
		cvmcs_printf("Error: PKO-DQ's of BGX-%d were not flushed "
			     "even after 100msec, proceeding with link down "
			     "anyway\n", index);
	}

	/* Step 1 */
	config.u64  = cvmx_read_csr_node(node, CVMX_BGXX_CMRX_CONFIG(index, interface));
	config.s.data_pkt_rx_en =  0;
	cvmx_write_csr_node(node, CVMX_BGXX_CMRX_CONFIG(index, interface),
			    config.u64);

	/* Step 2 */
	jabber.u64 = cvmx_read_csr_node(node, CVMX_BGXX_SMUX_RX_JABBER(index,
								    interface));
	us = (((jabber.s.cnt*8)/10) + 500)/1000;
	cvmx_wait_usec(us);

	/* Step 3 */
	count = 0;
	do {
		cvmx_wait_usec(5);
		fifo_len.u64  = cvmx_read_csr_node(node, CVMX_BGXX_CMRX_RX_FIFO_LEN(index, interface));
		if (++count > 10000)
			break;
	} while (fifo_len.s.fifo_len != 0);
	if (count > 10000)
		cvmcs_printf("Error CVMX_BGX%d_CMR%d_RX_FIFO_LEN  not zero, proceeding with link down anyway\n", interface, index);

	/* 
	 * Steps 4 to 6 may be safely skipped 
	 * but step 4 seems to be needed for Bug 21048
	 */
	count = 0;
	do {
		cvmx_wait_usec(5);
		tx_fifo_len.u64 = cvmx_read_csr_node(node, CVMX_BGXX_CMRX_TX_FIFO_LEN(index, interface));
		if (++count > 10000)
			break;
	} while (tx_fifo_len.s.fifo_len != 0);
	if (count > 10000)
		cvmcs_printf("Error CVMX_BGX%d_CMR%d_TX_FIFO_LEN  not zero, proceeding with link down anyway\n", interface, index);

	/* Step 7 */
	control1.u64 = cvmx_read_csr_node(node, CVMX_BGXX_SPUX_CONTROL1(index,
								    interface));
	control1.s.lo_pwr = 1;
	cvmx_write_csr_node(node, CVMX_BGXX_SPUX_CONTROL1(index, interface),
			    control1.u64);

	/* Step 8 */
	config.u64  = cvmx_read_csr_node(node, CVMX_BGXX_CMRX_CONFIG(index, interface));
	config.s.enable =  0;
	cvmx_write_csr_node(node, CVMX_BGXX_CMRX_CONFIG(index, interface),
			    config.u64);
	info->link_state = LINK_DOWN;

	cvmx_spinlock_unlock(&info->link_lock);
}

static int
cvmcs_nic_pki_pcam_free_dmac_hi(cvmcs_pcam_dmac_filters_t *filters,
				cvmcs_pcam_dmac_cfg_t *cfg)
{
	int node = cvmx_get_node_num(), cl = 0;
	int bank = 0, index = 0;
	int mac_mask = 0xffff, i;
	uint16_t macaddr_hi = (cfg->macaddr >> 32) & mac_mask;
	cvmcs_pcam_dmac_hi_t *entry_hi;

	if (!macaddr_hi) {
		cvmcs_printf("ERROR: %s macaddr_hi is 0\n", __func__);
		return -1;
	}

	for (i = 0; i < CVMCS_DMAC_FILTERS_MAX; i++) {
		entry_hi = &filters->entry[i].entry_hi;
		if (entry_hi->macaddr_hi == macaddr_hi)
			break;
	}

	if (i == CVMCS_DMAC_FILTERS_MAX) {
		cvmcs_printf("ERROR: %s couldn't find macaddr_hi\n",
			     __func__);
		return -1;
	}

	if (cvmx_atomic_get32(&entry_hi->ref_cnt) <= 0) {
		cvmcs_printf("ERROR: %s entry_hi ref_cnt can't be <= 0\n",
			     __func__);
		return -1;
	}

	cvmx_atomic_add32(&entry_hi->ref_cnt, -1);
	if (cvmx_atomic_get32(&entry_hi->ref_cnt))
		return 0;

	for (cl = 0; cl < (int)CVMX_PKI_NUM_CLUSTER; cl++) {
		/* Disable and free the PCAM entry in bank-0. */
		index = entry_hi->pcam_entry_hi[cl];
		if (index < 0)
			continue;

		cvmx_write_csr_node
			(node, CVMX_PKI_CLX_PCAMX_TERMX(cl, bank, index), 0);
		cvmx_write_csr_node
			(node, CVMX_PKI_CLX_PCAMX_MATCHX(cl, bank, index), 0);

		cvmx_pki_pcam_entry_free(node, index, bank, cl);
		entry_hi->pcam_entry_hi[cl] = -1;
	}

	entry_hi->macaddr_hi = 0;

	return 0;
}

/* Routine to allocate pcam entry from Bank-0 and
 * add upper 16 bits of mac address to it.\
 */
static int
cvmcs_nic_pki_pcam_add_dmac_hi(cvmcs_pcam_dmac_filters_t *filters,
			       cvmcs_pcam_dmac_cfg_t *cfg,
			       int prev_style, int style_add)
{

	int node = cvmx_get_node_num(), cl = 0;
	int bank = 0, mac_mask = 0xffff, i;
	cvmx_pki_clx_pcamx_termx_t pcam_term;
	cvmx_pki_clx_pcamx_matchx_t pcam_match;
	cvmx_pki_clx_pcamx_actionx_t pcam_action;
	cvmcs_pcam_dmac_hi_t *entry_hi;
	uint16_t macaddr_hi = (cfg->macaddr >> 32) & mac_mask;
	int index[CVMX_PKI_CLUSTER_ALL];

	if (!macaddr_hi) {
		cvmcs_printf("ERROR: %s macaddr_hi is 0\n", __func__);
		return -1;
	}

	for (i = 0; i < CVMCS_DMAC_FILTERS_MAX; i++) {
		entry_hi = &filters->entry[i].entry_hi;
		if (entry_hi->macaddr_hi == macaddr_hi)
			break;
	}

	if (i < CVMCS_DMAC_FILTERS_MAX) {
		if (cvmx_atomic_get32(&entry_hi->ref_cnt) <= 0) {
			cvmcs_printf("ERROR: %s: entry ref cnt <= 0\n",
				     __func__);
			return -1;
		}

		cvmx_atomic_add32(&entry_hi->ref_cnt, 1);
		return 0;
	}

	for (i = 0; i < CVMCS_DMAC_FILTERS_MAX; i++) {
		entry_hi = &filters->entry[i].entry_hi;

		if (!entry_hi->macaddr_hi)
			break;
	}

	if (i == CVMCS_DMAC_FILTERS_MAX) {
		cvmcs_printf("ERROR: %s reached max limit for"
			     " macaddr_hi entries\n", __func__);
		return -1;
	}

	for (cl = 0; cl < (int)CVMX_PKI_NUM_CLUSTER; cl++) {
		index[cl] = cvmx_pki_pcam_entry_alloc(node,
						      CVMX_PKI_FIND_AVAL_ENTRY,
						      bank, 1 << cl);
		if (index[cl] < 0) {
			cvmcs_printf("ERROR: %s pcam entry allocation"
				     " failed.\n", __func__);
			for (i = cl - 1; i >= 0; i--)
				cvmx_pki_pcam_entry_free(node, index[i],
							 bank, 1 << i);

			return -1;
		}
	}

	for (cl = 0; cl < (int)CVMX_PKI_NUM_CLUSTER; cl++) {

		entry_hi->pcam_entry_hi[cl] = index[cl];

		/* Disable the PCAM */
		pcam_term.u64 = cvmx_read_csr_node
			(node, CVMX_PKI_CLX_PCAMX_TERMX(cl, bank, index[cl]));
		pcam_term.s.valid = 0;
		cvmx_write_csr_node
			(node, CVMX_PKI_CLX_PCAMX_TERMX(cl, bank, index[cl]),
			 pcam_term.u64);

		/* Match the higher 16 bits of mac address. */
		pcam_match.u64 = cvmx_read_csr_node
			(node, CVMX_PKI_CLX_PCAMX_MATCHX(cl, bank, index[cl]));
		pcam_match.s.data1 = (macaddr_hi) & mac_mask;
		pcam_match.s.data0 = (~macaddr_hi) & mac_mask;
		cvmx_write_csr_node
			(node, CVMX_PKI_CLX_PCAMX_MATCHX(cl, bank, index[cl]),
			 pcam_match.u64);

		/* No action here. action will be taken when the lower
		 * 32-bit address matches. */
		pcam_action.u64 = cvmx_read_csr_node
			(node, CVMX_PKI_CLX_PCAMX_ACTIONX(cl, bank, index[cl]));
		pcam_action.s.pmc = 0;
		pcam_action.s.style_add = style_add;
		pcam_action.s.pf = 0;
		pcam_action.s.setty = 0;
		pcam_action.s.advance = 0;
		cvmx_write_csr_node
			(node, CVMX_PKI_CLX_PCAMX_ACTIONX(cl, bank, index[cl]),
			 pcam_action.u64);

		/* Set the term to match and enable the pcam entry */
		pcam_term.u64 = cvmx_read_csr_node
			(node, CVMX_PKI_CLX_PCAMX_TERMX(cl, bank, index[cl]));
		pcam_term.s.term1 = CVMX_PKI_PCAM_TERM_DMACH;
		pcam_term.s.term0 = ~CVMX_PKI_PCAM_TERM_DMACH;
		pcam_term.s.style1 = prev_style;
		pcam_term.s.style0 = ~prev_style;
		pcam_term.s.valid = 1;
		cvmx_write_csr_node
			(node, CVMX_PKI_CLX_PCAMX_TERMX(cl, bank, index[cl]),
			 pcam_term.u64);
	}

	entry_hi->macaddr_hi = macaddr_hi;
	cvmx_atomic_add32(&entry_hi->ref_cnt, 1);

	return 0;
}

static int
cvmcs_nic_pki_pcam_free_dmac_lo(cvmcs_pcam_dmac_filters_t *filters,
				cvmcs_pcam_dmac_cfg_t *cfg)
{
	int node = cvmx_get_node_num(), cl = 0;
	int bank = 1, index = 0;
	int mac_mask = 0xffffffff, i;
	uint32_t macaddr_lo = cfg->macaddr & mac_mask;
	cvmcs_pcam_dmac_lo_t *entry_lo;

	if (!macaddr_lo) {
		cvmcs_printf("ERROR: %s macaddr_lo is 0\n", __func__);
		return -1;
	}

	for (i = 0; i < CVMCS_DMAC_FILTERS_MAX; i++) {
		entry_lo = &filters->entry[i].entry_lo;
		if (entry_lo->macaddr_lo == macaddr_lo)
			break;
	}

	if (i == CVMCS_DMAC_FILTERS_MAX) {
		cvmcs_printf("ERROR: %s couldn't find macaddr_lo\n", __func__);
		return -1;
	}

	if (cvmx_atomic_get32(&entry_lo->ref_cnt) <= 0) {
		cvmcs_printf("ERROR: %s entry_lo ref_cnt can't be <= 0\n",
			     __func__);
		return -1;
	}

	cvmx_atomic_add32(&entry_lo->ref_cnt, -1);
	if (cvmx_atomic_get32(&entry_lo->ref_cnt))
		return 0;

	for (cl = 0; cl < (int)CVMX_PKI_NUM_CLUSTER; cl++) {
		/* Disable and free the PCAM entry in bank-1. */
		index = entry_lo->pcam_entry_lo[cl];

		cvmx_write_csr_node
			(node, CVMX_PKI_CLX_PCAMX_TERMX(cl, bank, index), 0);

		cvmx_pki_pcam_entry_free(node, index, bank, 1 << cl);
		cvmx_write_csr_node
			(node, CVMX_PKI_CLX_PCAMX_MATCHX(cl, bank, index), 0);

		 entry_lo->pcam_entry_lo[cl] = -1;
	}

	entry_lo->macaddr_lo = 0;

	return 0;
}

/* Routine to allocate pcam entry from Bank-1 and
 * add lower 32 bits of mac address to it.
 */
static int
cvmcs_nic_pki_pcam_add_dmac_lo(cvmcs_pcam_dmac_filters_t *filters,
			       cvmcs_pcam_dmac_cfg_t *cfg,
			       int prev_style, int style_add)
{
	int node = cvmx_get_node_num(), cl = 0;
	int bank = 1, mac_mask = 0xffffffff, i;
	cvmx_pki_clx_pcamx_termx_t pcam_term;
	cvmx_pki_clx_pcamx_matchx_t pcam_match;
	cvmx_pki_clx_pcamx_actionx_t pcam_action;
	uint32_t macaddr_lo = cfg->macaddr & mac_mask;
	int index[CVMX_PKI_CLUSTER_ALL];
	cvmcs_pcam_dmac_lo_t *entry_lo;

	if (!macaddr_lo) {
		cvmcs_printf("ERROR: %s macaddr_lo is 0\n", __func__);
		return -1;
	}

	for (i = 0; i < CVMCS_DMAC_FILTERS_MAX; i++) {
		entry_lo = &filters->entry[i].entry_lo;
		if (entry_lo->macaddr_lo == macaddr_lo)
			break;
	}

	if (i < CVMCS_DMAC_FILTERS_MAX) {
		if (cvmx_atomic_get32(&entry_lo->ref_cnt) <= 0) {
			cvmcs_printf("ERROR: %s entry ref cnt <= 0\n",
				     __func__);
			return -1;
		}

		cvmx_atomic_add32(&entry_lo->ref_cnt, 1);
		return 0;
	}

	for (i = 0; i < CVMCS_DMAC_FILTERS_MAX; i++) {
		entry_lo = &filters->entry[i].entry_lo;

		if (!entry_lo->macaddr_lo)
			break;
	}

	if (i == CVMCS_DMAC_FILTERS_MAX) {
		cvmcs_printf("ERROR: %s reached max limit for"
			     " macaddr_lo entries\n", __func__);
		return -1;
	}

	for (cl = 0; cl < (int)CVMX_PKI_NUM_CLUSTER; cl++) {
		index[cl] = cvmx_pki_pcam_entry_alloc(node,
						      CVMX_PKI_FIND_AVAL_ENTRY,
						      bank, 1 << cl);
		if (index[cl] < 0) {
			cvmcs_printf("ERROR: %s pcam entry allocation"
				     " failed.\n", __func__);
			for (i = cl - 1; i >= 0; i--)
				cvmx_pki_pcam_entry_free(node, index[i],
							 bank, 1 << i);

			return -1;
		}
	}

	for (cl = 0; cl < (int)CVMX_PKI_NUM_CLUSTER; cl++) {
		/* Allocate, configure and add an entry in Bank-1 of PCAM */

		entry_lo->pcam_entry_lo[cl] = index[cl];

		/* Disable the PCAM */
		pcam_term.u64 = cvmx_read_csr_node
			(node, CVMX_PKI_CLX_PCAMX_TERMX(cl, bank, index[cl]));
		pcam_term.s.valid = 0;
		cvmx_write_csr_node
			(node, CVMX_PKI_CLX_PCAMX_TERMX(cl, bank, index[cl]),
			 pcam_term.u64);

		/* Match the lower 32-bits of mac address */
		pcam_match.u64 = cvmx_read_csr_node
			(node, CVMX_PKI_CLX_PCAMX_MATCHX(cl, bank, index[cl]));
		pcam_match.s.data1 = (macaddr_lo) & mac_mask;
		pcam_match.s.data0 = ~(macaddr_lo & mac_mask);
		cvmx_write_csr_node
			(node, CVMX_PKI_CLX_PCAMX_MATCHX(cl, bank, index[cl]),
			 pcam_match.u64);

		/* Action to take if there is a match */
		pcam_action.u64 = cvmx_read_csr_node
			(node, CVMX_PKI_CLX_PCAMX_ACTIONX(cl, bank, index[cl]));
		pcam_action.s.pmc = 0;
		pcam_action.s.style_add = style_add;
		pcam_action.s.pf = 0;
		pcam_action.s.setty = 0;
		pcam_action.s.advance = 0;
		cvmx_write_csr_node
			(node, CVMX_PKI_CLX_PCAMX_ACTIONX(cl, bank, index[cl]),
			 pcam_action.u64);

		/* Set the term to match and enable the pcam entry */
		pcam_term.u64 = cvmx_read_csr_node
			(node, CVMX_PKI_CLX_PCAMX_TERMX(cl, bank, index[cl]));
		pcam_term.s.term1 = CVMX_PKI_PCAM_TERM_DMACL;
		pcam_term.s.term0 = ~CVMX_PKI_PCAM_TERM_DMACL;
		pcam_term.s.style1 = prev_style;
		pcam_term.s.style0 = ~prev_style;
		pcam_term.s.valid = 1;
		cvmx_write_csr_node
			(node, CVMX_PKI_CLX_PCAMX_TERMX(cl, bank, index[cl]),
			 pcam_term.u64);
	}

	entry_lo->macaddr_lo = macaddr_lo;
	cvmx_atomic_add32(&entry_lo->ref_cnt, 1);

	return 0;
}

static int
cvmcs_nic_pki_pcam_del_mac(int gmx_port, uint64_t macaddr)
{
	int i;
	cvmcs_pcam_dmac_filters_t *filters;
	cvmcs_pcam_dmac_cfg_t *cfg;

	filters = &octnic->gmx_port_info[gmx_port].filters;

	for (i = 0; i < CVMCS_DMAC_FILTERS_MAX; i++) {
		if (filters->cfg[i].macaddr == macaddr) {
			break;
		}
	}

	if (i == CVMCS_DMAC_FILTERS_MAX)
		return -1;

	cfg = &filters->cfg[i];

	if (cvmx_atomic_get32(&filters->grp_refcnt) <= 0)
		return -1;

	cvmcs_nic_pki_pcam_free_dmac_lo(filters, cfg);
	cvmcs_nic_pki_pcam_free_dmac_hi(filters, cfg);

	cfg->macaddr = 0;
	cvmx_atomic_add32(&filters->grp_refcnt, -1);

	return 0;
}

static int
cvmcs_nic_pki_pcam_add_mac(int gmx_port, uint64_t macaddr)
{
	struct cvmx_pki_port_config port_cfg;
	cvmcs_pcam_dmac_filters_t *filters;
	cvmcs_pcam_dmac_cfg_t *cfg;
	int i, ipd_port, style1, style2, bgx_style;

	ipd_port = octnic->gmx_port_info[gmx_port].ipd_port;
	filters = &octnic->gmx_port_info[gmx_port].filters;

	if (!macaddr)
		return -1;

	if (filters->dmac_style1 < 0 ||
	    filters->dmac_style2 < 0) {
		cvmcs_printf("ERROR: %s: filter module init is not done\n",
			     __func__);
		return -1;
	}

	for (i = 0; i < CVMCS_DMAC_FILTERS_MAX; i++) {
		if (filters->cfg[i].macaddr == macaddr) {
			cvmcs_printf("ERROR: %s Can't add duplicate "
				     "mac addrs in pcam\n", __func__);
			return -1;
		}
	}

	for (i = 0; i < CVMCS_DMAC_FILTERS_MAX; i++) {
		if (!filters->cfg[i].macaddr)
			break;
	}

	if (i == CVMCS_DMAC_FILTERS_MAX) {
		cvmcs_printf("ERROR: %s max limit for pcam dmac add reached\n",
			     __func__);
		return -1;
	}

	cfg = &filters->cfg[i];

	cvmx_pki_get_port_config(ipd_port, &port_cfg);
	bgx_style = port_cfg.pkind_cfg.initial_style;

	style1 = filters->dmac_style1;
	style2 = filters->dmac_style2;

	cvmcs_printf("macaddr: %lx GMX %d: QPG %d: bgx style %d styles %d:%d\n",
	       macaddr, gmx_port, filters->dmac_qpg,
	       bgx_style, style1, style2);


	cfg->macaddr = macaddr;
	if (cvmcs_nic_pki_pcam_add_dmac_hi(filters, cfg, bgx_style,
					   style1 - bgx_style)) {
		cvmcs_printf("ERROR: %s can't add dmac hi\n", __func__);
		return -1;
	}

	if (cvmcs_nic_pki_pcam_add_dmac_lo(filters, cfg, style1,
					   style2 - style1)) {
		cvmcs_nic_pki_pcam_free_dmac_hi(filters, cfg);
		cfg->macaddr = 0;
		cvmcs_printf("ERROR: %s can't add dmac lo\n", __func__);
		return -1;
	}

	cvmx_atomic_add32(&filters->grp_refcnt, 1);

	return 0;
}

#ifdef MGMT_PCAM_FILTER_BCAST_MCAST
static void
cvmcs_nic_pki_pcam_del_bcast_mac(int gmx_port)
{
	uint64_t mac = (1ULL << (ETH_ALEN * 8)) -1;

	cvmcs_nic_pki_pcam_del_mac(gmx_port, mac);
}

static int
cvmcs_nic_pki_pcam_add_bcast_mac(int gmx_port)
{
	uint64_t mac = (1ULL << (ETH_ALEN * 8)) -1;

	return cvmcs_nic_pki_pcam_add_mac(gmx_port, mac);
}

static void
cvmcs_nic_pki_pcam_del_mcast_mac(int gmx_port)
{
	cvmcs_pcam_dmac_filters_t *filters;
	int node = cvmx_get_node_num(), cl = 0;
	int bank = 0, index = 0;

	filters = &octnic->gmx_port_info[gmx_port].filters;
	for (cl = 0; cl < (int)CVMX_PKI_NUM_CLUSTER; cl++) {
		/* Disable and free the PCAM entry in bank-0. */
		index = filters->mcast_entry_hi[cl];
		if (index < 0)
			continue;

		cvmx_write_csr_node
			(node, CVMX_PKI_CLX_PCAMX_TERMX(cl, bank, index), 0);
		cvmx_write_csr_node
			(node, CVMX_PKI_CLX_PCAMX_MATCHX(cl, bank, index), 0);

		cvmx_pki_pcam_entry_free(node, index, bank, cl);
		filters->mcast_entry_hi[cl] = -1;
	}
}

static int
cvmcs_nic_pki_pcam_add_mcast_mac(int gmx_port)
{
	int node = cvmx_get_node_num(), cl = 0, i;
	int bank = 0, mac_mask = 0xff00, mcast_hi = 0x0100;
	struct cvmx_pki_port_config port_cfg;
	cvmx_pki_clx_pcamx_termx_t pcam_term;
	cvmx_pki_clx_pcamx_matchx_t pcam_match;
	cvmx_pki_clx_pcamx_actionx_t pcam_action;
	cvmcs_pcam_dmac_filters_t *filters;
	int index[CVMX_PKI_CLUSTER_ALL], bgx_style, ipd_port;

	filters = &octnic->gmx_port_info[gmx_port].filters;
	ipd_port = octnic->gmx_port_info[gmx_port].ipd_port;
	if (filters->dmac_style2 < 0) {
		cvmcs_printf("ERROR: mcast style is not allocated\n");
		return -1;
	}

	cvmx_pki_get_port_config(ipd_port, &port_cfg);
	bgx_style = port_cfg.pkind_cfg.initial_style;

	for (cl = 0; cl < (int)CVMX_PKI_NUM_CLUSTER; cl++) {
		index[cl] = cvmx_pki_pcam_entry_alloc(node,
						      CVMX_PKI_FIND_AVAL_ENTRY,
						      bank, 1 << cl);
		if (index[cl] < 0) {
			cvmcs_printf("ERROR: %s pcam entry allocation"
				     " failed.\n", __func__);
			for (i = cl - 1; i >= 0; i--)
				cvmx_pki_pcam_entry_free(node, index[i],
							 bank, 1 << i);
			return -1;
		}
	}

	for (cl = 0; cl < (int)CVMX_PKI_NUM_CLUSTER; cl++) {

		filters->mcast_entry_hi[cl] = index[cl];

		/* Disable the PCAM */
		pcam_term.u64 = cvmx_read_csr_node
			(node, CVMX_PKI_CLX_PCAMX_TERMX(cl, bank, index[cl]));
		pcam_term.s.valid = 0;
		cvmx_write_csr_node
			(node, CVMX_PKI_CLX_PCAMX_TERMX(cl, bank, index[cl]),
			 pcam_term.u64);

		/* Match the higher 16 bits of mac address. */
		pcam_match.u64 = cvmx_read_csr_node
			(node, CVMX_PKI_CLX_PCAMX_MATCHX(cl, bank, index[cl]));
		pcam_match.s.data1 = (mcast_hi) & mac_mask;
		pcam_match.s.data0 = (~mcast_hi) & mac_mask;
		cvmx_write_csr_node
			(node, CVMX_PKI_CLX_PCAMX_MATCHX(cl, bank, index[cl]),
			 pcam_match.u64);

		/* No action here. action will be taken when the lower
		 * 32-bit address matches. */
		pcam_action.u64 = cvmx_read_csr_node
			(node, CVMX_PKI_CLX_PCAMX_ACTIONX(cl, bank, index[cl]));
		pcam_action.s.pmc = CVMX_PKI_PARSE_SKIP_TO_LB;
		pcam_action.s.style_add = (filters->dmac_style2 - bgx_style);
		pcam_action.s.pf = 0;
		pcam_action.s.setty = 0;
		pcam_action.s.advance = 0;
		cvmx_write_csr_node
			(node, CVMX_PKI_CLX_PCAMX_ACTIONX(cl, bank, index[cl]),
			 pcam_action.u64);

		/* Set the term to match and enable the pcam entry */
		pcam_term.u64 = cvmx_read_csr_node
			(node, CVMX_PKI_CLX_PCAMX_TERMX(cl, bank, index[cl]));
		pcam_term.s.term1 = CVMX_PKI_PCAM_TERM_DMACH;
		pcam_term.s.term0 = ~CVMX_PKI_PCAM_TERM_DMACH;
		pcam_term.s.style1 = bgx_style;
		pcam_term.s.style0 = ~bgx_style;
		pcam_term.s.valid = 1;
		cvmx_write_csr_node
			(node, CVMX_PKI_CLX_PCAMX_TERMX(cl, bank, index[cl]),
			 pcam_term.u64);
	}

	cvmcs_printf("mcast mac addr added: style %d\n",
		     filters->dmac_style2);

	return 0;
}
#endif

int
cvmcs_nic_pki_pcam_init(int grp)
{
	cvmcs_pcam_dmac_filters_t *filters;
	struct cvmx_pki_port_config port_cfg;
	struct cvmx_pki_qpg_config qpg_cfg;
	struct cvmx_pki_style_config style_cfg;
	struct cvmx_pki_qpg_config qpg_config;
	int ipd_port, i, node = cvmx_get_node_num(), cl;
	int cluster_mask = ((1 << CVMX_PKI_NUM_CLUSTER) - 1);
	int bgx_style, style1, style2, bgx_qpg, qpg;

	if (grp >= (int)CVMX_PKI_NUM_SSO_GROUP) {
		cvmcs_printf("Group can't be >= %u\n",
			     CVMX_PKI_NUM_SSO_GROUP);
		return -1;
	}

	/*
	 * For now, implementation supports selection of same grp for
	 * each dmac match as the implemtn has single style1 allocation.
	 * Selecting different style/qpg/grp for diff macs, requires style1
	 * and style2 alloc for each unique mac_hi and mac_lo.
	 */
	for (i = 0; i < (int)octnic->ngmxports; i++) {
		ipd_port = octnic->gmx_port_info[i].ipd_port;
		filters = &octnic->gmx_port_info[i].filters;

		memset(filters, 0, sizeof(cvmcs_pcam_dmac_filters_t));
		cvmx_spinlock_init(&filters->lock);

		filters->dmac_style1 = -1;
		filters->dmac_style2 = -1;
		for (cl = 0; cl < (int)CVMX_PKI_NUM_CLUSTER; cl++)
			filters->mcast_entry_hi[cl] = -1;
		filters->default_sso_grp = grp;

		cvmx_pki_get_port_config(ipd_port, &port_cfg);
		/*
		 * Style1 is the interim style selected on mac_hi matched.
		 * style2 is the final style on mac_lo match
		 * pkt transition: bgx_recv->mac_hi_match->mac_lo_match
		 * style transition: bgx_style->style1->style2.
		 */
		style1 = cvmx_pki_style_alloc(node, -1);
		style2 = cvmx_pki_style_alloc(node, -1);
		if (style1 < 0 || style2 < 0) {
		       cvmcs_printf("ERROR: %s style allocation failed\n",
				    __func__);
		       goto free;
		}

		if (style1 < port_cfg.pkind_cfg.initial_style ||
		    style2 < port_cfg.pkind_cfg.initial_style) {
			cvmcs_printf("ERROR: %s: allocated style < bgx_style\n",
				     __func__);
			if (style1 >= 0)
				cvmx_pki_style_free(node, style1);
			if (style2 >= 0)
				cvmx_pki_style_free(node, style2);
			goto free;
		}

		bgx_style = port_cfg.pkind_cfg.initial_style;
		bgx_qpg = port_cfg.style_cfg.parm_cfg.qpg_base;

		cvmx_pki_read_qpg_entry(node, bgx_qpg, &qpg_cfg);

		qpg_config.qpg_base = -1;
		qpg_config.port_add = 0;
		qpg_config.aura_num = qpg_cfg.aura_num;
		qpg_config.grp_ok = grp;
		qpg_config.grp_bad = 0;
		qpg_config.grptag_ok = 0;
		qpg_config.grptag_bad = 0;

		qpg = cvmx_helper_pki_set_qpg_entry(node, &qpg_config);
		if (qpg < 0) {
			cvmx_pki_style_free(node, style1);
			cvmx_pki_style_free(node, style2);

			cvmcs_printf("ERROR: %s qpg entry alloc failed\n",
			       __func__);
			goto free;
		}

		cvmx_pki_read_style_config(node, bgx_style,
					   cluster_mask, &style_cfg);
		cvmx_pki_write_style_config(node, style1,
					    cluster_mask, &style_cfg);
		style_cfg.parm_cfg.qpg_base = qpg;
		cvmx_pki_write_style_config(node, style2,
					    cluster_mask, &style_cfg);

		filters->dmac_style1 = style1;
		filters->dmac_style2 = style2;

		filters->dmac_qpg = qpg;
		cvmx_atomic_add32(&filters->grp_refcnt, 1);

		cvmcs_printf("bgx:%d bgx_style %d bgx_qpg %d"
			     " style1:%d style2:%d grp %d QPG:%d\n",
			     i, bgx_style, bgx_qpg, style1, style2, grp, qpg);
	}

	return 0;
free:
	cvmcs_nic_pki_pcam_exit();

	return -1;
}

void
cvmcs_nic_pki_pcam_exit(void)
{
	cvmcs_pcam_dmac_filters_t *filters;
	int i, j, node = cvmx_get_node_num();
	cvmcs_pcam_dmac_cfg_t *cfg;

	for (i = 0; i < (int)octnic->ngmxports; i++) {
		filters = &octnic->gmx_port_info[i].filters;

		if (filters->dmac_style1 < 0 || filters->dmac_style2 < 0) {
			cvmcs_printf("ERROR: %s filter module init is"
				     " not done\n", __func__);
			continue;
		}

		cvmx_pki_style_free(node, filters->dmac_style1);
		cvmx_pki_style_free(node, filters->dmac_style2);
		filters->dmac_style1 = -1;
		filters->dmac_style2 = -1;

		if (cvmx_atomic_get32(&filters->grp_refcnt))
			cvmx_pki_qpg_entry_free(node, filters->dmac_qpg, 1);

		for (j = 0; j < CVMCS_DMAC_FILTERS_MAX; j++) {
			cfg = &filters->cfg[j];

			if (!cfg->macaddr)
				continue;

			cvmcs_nic_pki_pcam_free_dmac_lo(filters, cfg);
			cvmcs_nic_pki_pcam_free_dmac_hi(filters, cfg);
		}
	}
}

int
cvmcs_nic_dmac_filter_add(int ipd_port, uint64_t dmac)
{
	cvmcs_pcam_dmac_filters_t *filters;
	int i, j, ret;

	/*
	 * If ipd_port is -1, filter dmac on all ipd_ports
	 */
	if (ipd_port == -1) {
		for (i = 0; i < (int)octnic->ngmxports; i++) {
			ret = cvmcs_nic_dmac_filter_add
				(octnic->gmx_port_info[i].ipd_port, dmac);
			if (ret) {
				for (j = i -1; j >= 0; j++)
					cvmcs_nic_dmac_filter_del
						(octnic->gmx_port_info[j].
						 ipd_port, dmac);

				return -1;
			}
		}

		return 0;
	}

	for (i = 0; i < (int)octnic->ngmxports; i++) {
		if (ipd_port == octnic->gmx_port_info[i].ipd_port)
			break;
	}

	if (i == (int)octnic->ngmxports)
		return -1;

	filters = &octnic->gmx_port_info[i].filters;
	cvmx_spinlock_lock(&filters->lock);
	ret = cvmcs_nic_pki_pcam_add_mac(i, dmac);
	if (ret) {
		cvmx_spinlock_unlock(&filters->lock);
		return -1;
	}

#ifdef MGMT_PCAM_FILTER_BCAST_MCAST
	if (!filters->filters_count) {
		if (cvmcs_nic_pki_pcam_add_mcast_mac(i)) {
			cvmcs_nic_pki_pcam_del_mac(i, dmac);
			cvmx_spinlock_unlock(&filters->lock);

			return -1;
		}

		if (cvmcs_nic_pki_pcam_add_bcast_mac(i)) {
			cvmcs_nic_pki_pcam_del_mcast_mac(i);
			cvmcs_nic_pki_pcam_del_mac(i, dmac);
			cvmx_spinlock_unlock(&filters->lock);

			return -1;
		}
	}
#endif

	filters->filters_count++;
	cvmx_spinlock_unlock(&filters->lock);

	return ret;
}

int
cvmcs_nic_dmac_filter_del(int ipd_port, uint64_t dmac)
{
	cvmcs_pcam_dmac_filters_t *filters;
	int i, ret;

	/*
	 * If ipd_port is -1, delete dmac filter on all ipd_ports
	 */
	if (ipd_port == -1) {
		for (i = 0; i < (int)octnic->ngmxports; i++)
			cvmcs_nic_dmac_filter_del
				(octnic->gmx_port_info[i].ipd_port, dmac);

		return 0;
	}

	for (i = 0; i < (int)octnic->ngmxports; i++) {
		if (ipd_port == octnic->gmx_port_info[i].ipd_port)
			break;
	}

	if (i == (int)octnic->ngmxports)
		return -1;

	filters = &octnic->gmx_port_info[i].filters;

	cvmx_spinlock_lock(&filters->lock);
	ret = cvmcs_nic_pki_pcam_del_mac(i, dmac);
	if (!ret) {
		filters->filters_count--;
#ifdef MGMT_PCAM_FILTER_BCAST_MCAST
		if (!filters->filters_count) {
			cvmcs_nic_pki_pcam_del_mcast_mac(i);
			cvmcs_nic_pki_pcam_del_bcast_mac(i);
		}
#endif
	}

	cvmx_spinlock_unlock(&filters->lock);

	return 0;
}

int cvmcs_nic_validate_rx_frame_len(cvmx_wqe_t *wqe, int ifidx)
{
	cvmcs_nic_metadata_t *mdata = CVMCS_NIC_METADATA(wqe);
	int ret = COMP_CONSUMED;
	int pkt_len;
	int mtu;

	mtu = octnic->port[ifidx].effective_mtu;
	pkt_len = cvmx_wqe_get_len(wqe) - CVMCS_NIC_METADATA_L3_OFFSET(mdata);

	if (cvmx_unlikely(pkt_len > mtu)) {
		per_core_stats[cvmx_get_core_num()].link_stats[ifidx].fromwire.l2_err += 1;
		ret = COMP_DROP;
	}
	return ret;
}

int
cvmcs_nic_uboot_ctl_delay(int ifidx)
{
	int ret=0;
	uint32_t val=0xffff;

	if (octnic->no_uboot_api)
		return 0;

	if (octnic->port[ifidx].rsfec_set == 2) {
		/* turn RS_FEC off */
		if (OCT_NIC_PORT_PF(ifidx) == 0) {
			ret = cvmcs_uboot_request_set(ifidx, "enable_fec0", "0", &val);
		}
		if (OCT_NIC_PORT_PF(ifidx) == 1) {
			ret = cvmcs_uboot_request_set(ifidx, "enable_fec1", "0", &val);
		}
		if (ret) printf("Failed to set environment variable.\n");
		else  {
			octnic->port[ifidx].rsfec_get = val;
		}
		octnic->port[ifidx].rsfec_set = 0;
	}

	if (octnic->port[ifidx].rsfec_set == 1) {
		/* turn RS_FEC on */
		if (OCT_NIC_PORT_PF(ifidx) == 0) {
			ret = cvmcs_uboot_request_set(ifidx, "enable_fec0", "1", &val);
		}

		if (OCT_NIC_PORT_PF(ifidx) == 1) {
			ret = cvmcs_uboot_request_set(ifidx, "enable_fec1", "1", &val);
		}

		if (ret) printf("Failed to set environment variable.\n");
		else {
			octnic->port[ifidx].rsfec_get = val;
		}
		octnic->port[ifidx].rsfec_set = 0;
	}
			
	if (octnic->speed_change == 10) {
		int pifidx;

		ret = cvmcs_uboot_request_set(ifidx, "octeth0_speed", "10", &val);
		ret = cvmcs_uboot_request_set(ifidx, "octeth1_speed", "10", &val);
		if (ret) val = 0xffff;

		if (OCT_NIC_PORT_PF(ifidx) == 0)
			pifidx = 1<<6;
		else pifidx = 0;

		octnic->port[ifidx].speed_get = val;
		octnic->port[pifidx].speed_get = val;
		octnic->speed_change = 0;
	}
	if (octnic->speed_change == 25) {
		int pifidx;
		ret = cvmcs_uboot_request_set(ifidx, "octeth0_speed", "25", &val);
		ret = cvmcs_uboot_request_set(ifidx, "octeth1_speed", "25", &val);
		if (ret) val = 0xffff;

		if (OCT_NIC_PORT_PF(ifidx) == 0)
			pifidx = 1 <<6;
		else pifidx = 0;

		octnic->port[ifidx].speed_get = val;
		octnic->port[pifidx].speed_get = val;
		octnic->speed_change = 0;
	}

	return 0;
}

int
cvmcs_nic_uboot_ctl(cvmx_wqe_t  *wqe)
{
	cvm_pci_dma_cmd_t      cmd;
	cvmx_buf_ptr_t         lptr;
	cvm_dma_remote_ptr_t   rptr;
	cvmx_raw_inst_front_t *f;
	uint64_t *buf;
	int pool_id = -1;
	int ifidx;
	union octnet_cmd *ncmd;
	int front_size;
	uint64_t cmd_ret;
	uint32_t val=0;
	struct oct_nic_seapi_resp *resp = NULL;

	cmd.u64  = 0;
	lptr.u64 = 0;

	if (octeon_has_feature(OCTEON_FEATURE_CN78XX_WQE))
		f = (cvmx_raw_inst_front_t *) cvmx_phys_to_ptr(cvmx_wqe_get_pki_pkt_ptr(wqe).addr);
	else
		f = (cvmx_raw_inst_front_t *)wqe->packet_data;

	ifidx = get_vnic_port_id(cvmx_wqe_get_port(wqe));

        if (f->irh.s.rflag)
                front_size = CVM_RAW_FRONT_SIZE;
        else
                front_size = CVM_RAW_FRONT_SIZE-16; /* rptr and rdp are not there so don't count them */

        ncmd = (union octnet_cmd *)((uint8_t *)f + front_size);

        DBG("NW Command packet received (0x%016lx)\n", ncmd->u64);

	cmd.s.pcielport = f->rdp.s.pcie_port;
	rptr.s.addr = f->rptr;
	rptr.s.size = f->rdp.s.rlen;

	/* Re-use the packet pool buffer to send the link info to host. */
	buf = (uint64_t *) cvmx_phys_to_ptr(wqe->packet_ptr.s.addr);

	pool_id = CVMX_FPA_PACKET_POOL;

	/* Reset all bytes so that unused fields don't have any value. */
	memset(buf, 0, rptr.s.size);
	resp = (struct oct_nic_seapi_resp *)buf;

	cmd_ret = 0;

	if (octnic->no_uboot_api) {
		val = 0xffff;
		goto uboot_ctl_out;
	}

	switch(ncmd->s.cmd) {
	case SEAPI_CMD_FEC_SET: {
		if (octnic->port[ifidx].rsfec_get && 
			    (ncmd->s.param1 == SEAPI_CMD_FEC_SET_DISABLE) ) {
			octnic->port[ifidx].rsfec_set = 2; /*1==set; 2==reset*/
			val = 0;
		}

		if ((octnic->port[ifidx].rsfec_get == 0) &&
			    (ncmd->s.param1 == SEAPI_CMD_FEC_SET_RS ) ) {
			octnic->port[ifidx].rsfec_set = 1;
			val = 1;
		}

		break;
	}
				
	case SEAPI_CMD_FEC_GET: {
		val = octnic->port[ifidx].rsfec_get;
		break;
	}

	case SEAPI_CMD_SPEED_GET:  {
		val = octnic->port[ifidx].speed_get;
		break;
	}

	case SEAPI_CMD_SPEED_SET: {
		if (OCT_NIC_IS_VF(ifidx)) {
			val = 0xffff;
			goto uboot_ctl_out;
		}
			
		val = octnic->speed_change = ncmd->s.param1;

		break;
	}

	default:
		printf("%s: unknown cmd->s.cmd=%x\n", __FUNCTION__, ncmd->s.cmd);
		break;
	}

uboot_ctl_out:
	resp->speed = val; /* set response val; speed/fec are in a union */
	resp->status = cmd_ret;

	if (octeon_has_feature(OCTEON_FEATURE_CN78XX_WQE)) {
		((cvmx_buf_ptr_pki_t *)&lptr)->addr = CVM_DRV_GET_PHYS(resp);
		((cvmx_buf_ptr_pki_t *)&lptr)->size = rptr.s.size;
		((cvmx_buf_ptr_pki_t *)&lptr)->packet_outside_wqe = 0;
	} else {
		lptr.s.size = rptr.s.size;
		lptr.s.addr = CVM_DRV_GET_PHYS(resp);
	}

	if (OCTEON_IS_OCTEON3()) {
		cmd.s.nl = cmd.s.nr = 1;
		return cvm_pci_dma_send_data_o3(&cmd, (cvmx_buf_ptr_pki_t *)&lptr, &rptr, wqe, 1);
	} else {
		lptr.s.i    = 1;
		lptr.s.pool = pool_id;
		cmd.s.nl = cmd.s.nr = 1;
		lptr.s.back = wqe->packet_ptr.s.back;
		cvm_update_bp(wqe);
		cvmcs_wqe_free(wqe);
		CVMX_SYNCWS;
		return cvm_pci_dma_send_data(&cmd, &lptr, &rptr);
	}
}


int
read_uboot_parameter()
{

	int ifidx = OCT_NIC_PORT_IDX(0,0);
	int reqret = 0;
	uint32_t val=0;

	val = 0xffff;
	if ((reqret = cvmcs_uboot_request_get(ifidx, "octeth0_speed", &val)) == 0) {
		octnic->uparam[ifidx].speed_get = val;
	} else {
		octnic->no_uboot_api = 1;
		octnic->uparam[ifidx].speed_get = 0xffff;
	}

	val = 0;
	if ((reqret=cvmcs_uboot_request_get(ifidx, "enable_fec0", &val)) == 0) {
		octnic->uparam[ifidx].rsfec_get = val;
	} else {
		octnic->uparam[ifidx].rsfec_get = 0;
	}


        ifidx = OCT_NIC_PORT_IDX(1,0);
	reqret = 0;
	val=0;
	if ((reqret = cvmcs_uboot_request_get(ifidx, "octeth1_speed", &val)) == 0) {
		octnic->uparam[ifidx].speed_get = val;
	} else {
		octnic->no_uboot_api = 1;
		octnic->uparam[ifidx].speed_get = 0xffff;
	}

	if ((reqret=cvmcs_uboot_request_get(ifidx, "enable_fec1", &val)) == 0) {
		octnic->uparam[ifidx].rsfec_get = val;
	} else {
		octnic->uparam[ifidx].rsfec_get = 0;
	}

	return 0;

}
/* $Id$ */
