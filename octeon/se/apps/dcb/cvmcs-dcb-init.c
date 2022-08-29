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

#include "cvmcs-dcb.h"
#include "cvmcs-nic.h"
#include "cvmcs-nic-switch.h"
#include "cvmcs-nic-tunnel.h"
#include "cvmcs-common.h"

extern CVMX_SHARED cvmx_user_static_pko_queue_config_t
	__cvmx_pko_queue_static_config;

/*
 * Returns the interface number for XFI
 * 
 * @return Interface number
 */
int cvmcs_dcb_get_xfi_interface()
{
	int i;
	const int num_interfaces = cvmx_helper_get_number_of_interfaces();

	for (i = 0; i  < num_interfaces; i++) {
		if (cvmx_helper_interface_get_mode(
			cvmx_helper_node_interface_to_xiface(
				cvmx_get_node_num(), i)) ==
				CVMX_HELPER_INTERFACE_MODE_XFI)
			break;
	}

	return ((i == num_interfaces) ? -1 : i);
}

/*
 * Enable the flag <pfc_enable> to create eight queues 
 * in each PKO queue levels.
 *
 * @param interface.
 */
void cvmcs_dcb_queue_config_pfc_en(int interface)
{
	__cvmx_pko_queue_static_config.pknd.
	pko_cfg_iface[interface].pfc_enable = true;
}

/*
 * Initialize the PKI, PKO and DCBx for DCB support in a particular port
 *
 * @param port_num - The physical port number
 * 
 * @return      - Zero on success, Negative on failure.		  
 */
int cvmcs_dcb_enable(int port_num)
{
	int status =0;
	int ipd_port, node;
	cvmx_bgxx_cmrx_config_t config;
	struct cvmx_pki_port_config port_cfg;

	node = cvmx_get_node_num();
	ipd_port = octnic->gmx_port_info[port_num].ipd_port;

	config.u64  = cvmx_read_csr_node(node,
		CVMX_BGXX_CMRX_CONFIG(INDEX(ipd_port), INTERFACE(ipd_port) & 0xff));
	config.s.enable = 0;
	cvmx_write_csr_node(node,
		CVMX_BGXX_CMRX_CONFIG(INDEX(ipd_port), INTERFACE(ipd_port) & 0xff),
		config.u64);

	cvmx_pki_get_port_config(ipd_port, &port_cfg);
	port_cfg.style_cfg.parm_cfg.qpg_qos = CVMX_PKI_QPG_QOS_VLAN;
	cvmx_pki_set_port_config(ipd_port, &port_cfg);

	config.u64  = cvmx_read_csr_node(node,
		CVMX_BGXX_CMRX_CONFIG(INDEX(ipd_port), INTERFACE(ipd_port) & 0xff));
	config.s.enable = 1;
	cvmx_write_csr_node(node,
		CVMX_BGXX_CMRX_CONFIG(INDEX(ipd_port), INTERFACE(ipd_port) & 0xff),
		config.u64);

	status=cvmcs_dcb_init_pko(port_num);
	if (!status) {
		octnic->dcb[port_num].dcb_enabled = true;

		if (octnic->dcb[port_num].dcbx_cfg.oper_dcbx_ver == DCBX_IEEE) {
			cvmcs_dcbx_ieee_config(port_num);
		}
		else {
			cvmcs_dcbx_cee_config(port_num);
		}
	}			

	return status;		
}

/*
 * Disable DCBx, ETS, PFC and revert PKI to its original configuration, 
 * in a particular port.
 *
 * @param port_num - The physical port number
 * 
 * @return      - Zero on success, Negative on failure.  
 */
int cvmcs_dcb_disable(int port_num)
{
	int status;
	int ipd_port, node;
	cvmx_bgxx_cmrx_config_t config;
	struct cvmx_pki_port_config port_cfg;

	node = cvmx_get_node_num();
	ipd_port = octnic->gmx_port_info[port_num].ipd_port;

	config.u64  = cvmx_read_csr_node(node,
		CVMX_BGXX_CMRX_CONFIG(INDEX(ipd_port), INTERFACE(ipd_port) & 0xff));
	config.s.enable = 0;
	cvmx_write_csr_node(node,
		CVMX_BGXX_CMRX_CONFIG(INDEX(ipd_port), INTERFACE(ipd_port) & 0xff),
		config.u64);

	cvmx_pki_get_port_config(ipd_port, &port_cfg);
	port_cfg.style_cfg.parm_cfg.qpg_qos = CVMX_PKI_QPG_QOS_NONE;
	cvmx_pki_set_port_config(ipd_port, &port_cfg);

	config.u64  = cvmx_read_csr_node(node,
		CVMX_BGXX_CMRX_CONFIG(INDEX(ipd_port), INTERFACE(ipd_port) & 0xff));
	config.s.enable = 1;
	cvmx_write_csr_node(node,
		CVMX_BGXX_CMRX_CONFIG(INDEX(ipd_port), INTERFACE(ipd_port) & 0xff),
		config.u64);

	cvmcs_dcb_disable_pfc(port_num);

	status = cvmcs_dcb_ets_disable(port_num);
	if(status < 0)
		return -1;

	octnic->dcb[port_num].dcb_enabled = false;
			
	return 0;
}

static void cvmcs_init_dcb_default_cfg(int ifidx)
{
	int i, j, k, l;
	int port_num = octnic->port[ifidx].gmxport_id;
	struct oct_nic_dcbx_config *def_config_ieee =
		&octnic->dcb[port_num].dcbx_def_cfg.dcbx_ieee;
	struct oct_nic_dcbx_config *def_config_cee =
		&octnic->dcb[port_num].dcbx_def_cfg.dcbx_cee;

	j = octnic->port[ifidx].linfo.num_txpciq;

	if (j > IEEE_8021QAZ_MAX_TCS)
		j = IEEE_8021QAZ_MAX_TCS;

	memset(def_config_ieee, 0, sizeof(struct oct_nic_dcbx_config));

        def_config_ieee->pfc_config.pfc_flags = DCBX_FLAG_ENABLED | DCBX_FLAG_WILLING;
	def_config_ieee->pfc_config.pfc_capability       = j;
        def_config_ieee->pfc_config.pfc_enable           = 0xFF;
        def_config_ieee->pfc_config.mbc                  = 0;

        def_config_ieee->ets_config.ets_flags = DCBX_FLAG_ENABLED | DCBX_FLAG_WILLING;
        def_config_ieee->ets_config.num_traffic_classes  = j;
        def_config_ieee->ets_config.ieee.cbs             = 0x0;

	for (i = 0; i < IEEE_8021QAZ_MAX_TCS; i++) {
        	def_config_ieee->ets_config.ieee.priority_assignment_table[i] =
			i % def_config_ieee->ets_config.num_traffic_classes;
        	def_config_ieee->ets_config.ieee.tsa_assignment_table[i] = OCTEON_TSA_ETS;
	}

	l = 100 / def_config_ieee->ets_config.num_traffic_classes;
	k = 100 - l;

	for (i = 0; i < def_config_ieee->ets_config.num_traffic_classes; i++) {
        	def_config_ieee->ets_config.ieee.tc_bandwidth_assignment_table[i]  =
			 l + ((k == 0) ? 0 : 1); 
		k--;
	}

	cvmcs_dcbx_ieee_set_default_params(port_num);

	memset(def_config_cee, 0, sizeof(struct oct_nic_dcbx_config));

        def_config_cee->pfc_config.pfc_flags = DCBX_FLAG_ENABLED | DCBX_FLAG_WILLING;
	def_config_cee->pfc_config.pfc_capability       = j;
        def_config_cee->pfc_config.pfc_enable           = 0xFF;
        def_config_cee->pfc_config.mbc                  = 0;

        def_config_cee->ets_config.ets_flags = DCBX_FLAG_ENABLED | DCBX_FLAG_WILLING;
        def_config_cee->ets_config.num_traffic_classes  = j;

	for (i = 0; i < IEEE_8021QAZ_MAX_TCS; i++) {
        	def_config_cee->ets_config.cee.pgid[i] =
			i % def_config_ieee->ets_config.num_traffic_classes;
	}

	l = 100 / def_config_cee->ets_config.num_traffic_classes;
	k = 100 - l;

	for (i = 0; i < def_config_cee->ets_config.num_traffic_classes; i++) {
        	def_config_cee->ets_config.cee.pg_bw[i] = l + ((k == 0) ? 0 : 1); 
		k--;
	}

	cvmcs_dcbx_cee_set_default_params(port_num);
}

/**  Send current configuration to host
 *
 * @param wqe  work queue entry
 */
static void cvmcs_dcb_send_cfg_resp(cvmx_wqe_t  *wqe)
{
        struct oct_nic_dcb_cfg_info *cfg_info;
        cvmx_buf_ptr_t lptr;
	cvm_pci_dma_cmd_t cmd;
        cvm_dma_remote_ptr_t rptr;
        cvmx_raw_inst_front_t *f;
        uint64_t *buf;
        int port_num, ifidx, num_tc;

        ifidx = get_vnic_port_id(cvmx_wqe_get_port(wqe));

	if (octnic->port[ifidx].state.present == 0)
		return;

        if (octeon_has_feature(OCTEON_FEATURE_CN78XX_WQE))
                f = (cvmx_raw_inst_front_t *) cvmx_phys_to_ptr(cvmx_wqe_get_pki_pkt_ptr(wqe).addr);
        else
                f = (cvmx_raw_inst_front_t *)wqe->packet_data;

        port_num = octnic->port[ifidx].gmxport_id;

        cmd.u64 = 0;
        cmd.s.pcielport = f->rdp.s.pcie_port;

        lptr.u64 = 0;

        rptr.s.addr = f->rptr;
        rptr.s.size = f->rdp.s.rlen;

        if (cvmx_unlikely(rptr.s.size > CVMX_FPA_PACKET_POOL_SIZE)) {
                printf("[ DRV ] Cannot use packet pool buf for sending link info\n");
                return;
        }

        /* Re-use the packet pool buffer to send the link info to host. */
        buf = (uint64_t *) cvmx_phys_to_ptr(wqe->packet_ptr.s.addr);

        /* Reset all bytes so that unused fields don't have any value. */
        DBG2("rptr. size %d\n", rptr.s.size);
        memset(buf, 0, rptr.s.size);

	cfg_info = (struct oct_nic_dcb_cfg_info *)&buf[1];

        cfg_info->dcb_cap.dcbx_cap = OCTEON_DCB_CAP_DCBX_HOST |
				     OCTEON_DCB_CAP_DCBX_LLD_MANAGED |
				     OCTEON_DCB_CAP_DCBX_VER_CEE |
				     OCTEON_DCB_CAP_DCBX_VER_IEEE;

	num_tc = octnic->port[ifidx].linfo.num_txpciq;

	if (num_tc > IEEE_8021QAZ_MAX_TCS)
		num_tc = IEEE_8021QAZ_MAX_TCS;

	cfg_info->dcb_cap.maxnum_traffic_classes = num_tc;
	cfg_info->dcb_cap.maxnum_etscapable_traffic_classes = num_tc;
	cfg_info->dcb_cap.maxnum_pfcenabled_traffic_classes = num_tc;

	cfg_info->dcbx_version = octnic->dcb[port_num].dcbx_cfg.oper_dcbx_ver;

	cvmcs_dcbx_ieee_get_params(port_num, &cfg_info->ieee_config);

	cvmcs_dcbx_cee_get_params(port_num, &cfg_info->cee_config);

        if (octeon_has_feature(OCTEON_FEATURE_PKI)) {
                ((cvmx_buf_ptr_pki_t *)&lptr)->addr = wqe->packet_ptr.s.addr;
                ((cvmx_buf_ptr_pki_t *)&lptr)->size = rptr.s.size;
        } else {
                lptr.s.addr = wqe->packet_ptr.s.addr;
                lptr.s.size = rptr.s.size;
        }

        cmd.s.nl = cmd.s.nr = 1;
        cvm_pci_dma_send_data_o3(&cmd, (cvmx_buf_ptr_pki_t *)&lptr, &rptr, wqe, 1);
}

/**  Update the DCBx capabilities and current configuration to host
 *
 * @param wqe  work queue entry
 */
void cvmcs_dcb_cfg(cvmx_wqe_t  *wqe)
{
	union oct_nic_dcb_cfg dcb_cfg;
	struct oct_nic_dcbx_cmd *dcbx_cmd;
        cvmx_raw_inst_front_t *f;
	uint64_t retaddr = 0, front_size;
        int port_num, ifidx, ret = 0;

        ifidx = get_vnic_port_id(cvmx_wqe_get_port(wqe));

	if (octnic->port[ifidx].state.present == 0)
		return;

        if (octeon_has_feature(OCTEON_FEATURE_CN78XX_WQE))
                f = (cvmx_raw_inst_front_t *) cvmx_phys_to_ptr(cvmx_wqe_get_pki_pkt_ptr(wqe).addr);
        else
                f = (cvmx_raw_inst_front_t *)wqe->packet_data;

	if (f->irh.s.rflag) {
		front_size = CVM_RAW_FRONT_SIZE;
	}
	else {
		front_size = CVM_RAW_FRONT_SIZE - 16;
	}

        port_num = octnic->port[ifidx].gmxport_id;

        dcb_cfg.u64 = (uint64_t)f->ossp[0];

	switch (dcb_cfg.s.cfg_command) {
		case DCB_CFG_CMD_DCB_CONFIG:
			if (!dcb_cfg.s.dcbx_ieee && !dcb_cfg.s.dcbx_cee) {
				ret = 1;
				break;
			}

        		/*For PKI configuration */
        		octnic->dcb[port_num].dcbx_offload = dcb_cfg.s.dcbx_offload;
        		octnic->dcb[port_num].dcbx_ieee = dcb_cfg.s.dcbx_ieee;
        		octnic->dcb[port_num].dcbx_cee = dcb_cfg.s.dcbx_cee;

        		octnic->dcb[port_num].ifidx = ifidx;

			cvmx_spinlock_init(&(octnic->dcb[port_num].dcbx_cfg.lock));

			cvmcs_init_dcb_default_cfg(ifidx);

			octnic->dcb[port_num].dcbx_cfg.remote_dcbx_ver = DCBX_UNKNOWN;

			/* Default DCBX_IEEE version*/
			if (octnic->dcb[port_num].dcbx_ieee)
				octnic->dcb[port_num].dcbx_cfg.oper_dcbx_ver = DCBX_IEEE;
			else
				octnic->dcb[port_num].dcbx_cfg.oper_dcbx_ver = DCBX_CEE;

			ret = cvmcs_dcb_enable(port_num);
			if (!ret) {
				octnic->dcb[port_num].dcbx_cfg.dcbx_ieee.pfc_flag = 0;
				octnic->dcb[port_num].dcbx_cfg.dcbx_ieee.ets_flag = 0;
				if (dcb_cfg.s.qcn_enable) {
					ret = cvmcs_dcb_qcn_init(port_num);
					if (ret) {
						cvmcs_dcb_disable(port_num);
						break;
					}
				}

				cvmcs_dcb_send_cfg_resp(wqe);
				return;
			}

			break;

		case DCB_CFG_CMD_DCB_RECONFIG:
			if (!dcb_cfg.s.dcbx_ieee && !dcb_cfg.s.dcbx_cee) {
				ret = 1;
				break;
			}

        		/*For PKI configuration */
        		octnic->dcb[port_num].dcbx_offload = dcb_cfg.s.dcbx_offload;
        		octnic->dcb[port_num].dcbx_ieee = dcb_cfg.s.dcbx_ieee;
        		octnic->dcb[port_num].dcbx_cee = dcb_cfg.s.dcbx_cee;

			if (octnic->dcb[port_num].dcbx_ieee) {
				if (octnic->dcb[port_num].dcbx_cfg.oper_dcbx_ver != DCBX_IEEE) {
					octnic->dcb[port_num].dcbx_cfg.oper_dcbx_ver = DCBX_IEEE;			
					cvmx_spinlock_lock(&octnic->dcb[port_num].dcbx_cfg.lock);
					cvmcs_dcbx_ieee_config(port_num);
					cvmx_spinlock_unlock(&octnic->dcb[port_num].dcbx_cfg.lock);
					cvmx_atomic_set32((int32_t *)
						&octnic->dcb[port_num].dcbx_cfg.port.tx.local_change, True);
					cvmcs_dcbx_param_indication(port_num);
				}
			} else {
				if (octnic->dcb[port_num].dcbx_cfg.oper_dcbx_ver != DCBX_CEE) {			
					octnic->dcb[port_num].dcbx_cfg.oper_dcbx_ver = DCBX_CEE;			
					cvmx_spinlock_lock(&octnic->dcb[port_num].dcbx_cfg.lock);
					cvmcs_dcbx_cee_config(port_num);
					cvmx_spinlock_unlock(&octnic->dcb[port_num].dcbx_cfg.lock);
					cvmx_atomic_set32((int32_t *)
						&octnic->dcb[port_num].dcbx_cfg.port.tx.local_change, True);
					cvmcs_dcbx_param_indication(port_num);
				}
			}

			if (dcb_cfg.s.dcbx_offload) {
				if (octnic->port[ifidx].state.rx_on)
					cvmcs_dcbx_enable(ifidx);
			} else {
				cvmcs_dcbx_disable(ifidx);
			}

			cvmcs_dcb_send_cfg_resp(wqe);
			return;

		case DCB_CFG_CMD_DCB_ENABLE:
			ret = cvmcs_dcb_enable(port_num);
			if (ret)
				break;

			if (octnic->port[ifidx].state.rx_on) {
				ret = cvmcs_dcbx_enable(ifidx);
				if (ret)
					break;
			}

			cvmcs_dcbx_param_indication(port_num);
			cvmcs_dcb_send_cfg_resp(wqe);
			return;

		case DCB_CFG_CMD_DCB_DISABLE:
			cvmcs_dcbx_disable(ifidx);
			ret = cvmcs_dcb_disable(port_num);
                	break;

		case DCB_CFG_CMD_DCB_SET_PARAMS:
			dcbx_cmd = (struct oct_nic_dcbx_cmd *)
				((uint8_t *)f + front_size);
			ret = cvmcs_dcbx_set_params(port_num, dcbx_cmd);
			break;

		default:
			ret = 1;
                	break;
	}

	if (f->irh.s.rflag && f->rptr) {
		retaddr = f->rptr + f->rdp.s.rlen - 8;
               	if (OCTEON_IS_MODEL(OCTEON_CN73XX))
                       	cvm_pci_pvf_mem_writell(retaddr, ret, cvm_pcie_pvf_num(wqe));
		else
			cvm_pci_mem_writell(retaddr, ret);
	}

	cvm_free_wqe_wrapper(wqe);
}

/*
 * Handles the DCBx or QCN specific work queue entries.
 *
 * @param wqe  - Work queue entry.
 * 
 * @return      - Zero on success, Negative on failure.  
 */
int cvmcs_dcb_dpi_wqe_handler(cvmx_wqe_t *wqe)
{
	cvmx_raw_inst_front_t *front;

	if (octeon_has_feature(OCTEON_FEATURE_CN78XX_WQE))
        	front = (cvmx_raw_inst_front_t *)CVM_DRV_GET_PTR(cvmx_wqe_get_pki_pkt_ptr(wqe).addr);
        else
                front = (cvmx_raw_inst_front_t *)wqe->packet_data;

	switch(front->irh.s.subcode){

                case OPCODE_NIC_DCB_CFG:
                        cvmcs_dcb_cfg(wqe);
                        break;

                case OPCODE_NIC_DCBX_TIMER:
                        cvmcs_dcbx_timer(wqe);
                        break;

                case OPCODE_NIC_QCN_BYTE_COUNTER:
                case OPCODE_NIC_QCN_TIMER_COUNTER:
                        cvmcs_dcb_qcn_rp_counter(wqe);
                        break;
		default:
                        return -ENOIF;

	}
	return 0;
}

/*
 * Handles the DCBx or QCN specific work queue entries.
 *
 * @param wqe  - Work queue entry.
 * 
 * @return      - Zero on success, Negative on failure.  
 */
int cvmcs_dcb_gmx_wqe_handler(cvmx_wqe_t *wqe)
{	
	cvmcs_nic_metadata_t *mdata = CVMCS_NIC_METADATA(wqe);
	struct ethhdr *eth = (struct ethhdr *)CVMCS_NIC_METADATA_L2_HEADER(mdata);

	if(eth->h_proto == ETH_P_QCN){
		cvmcs_dcb_qcn_main(wqe);
		cvm_free_wqe_wrapper(wqe);
		return 0;
	}else
		if(eth->h_proto == ETH_P_LLDP){
			if(cvmcs_dcbx_auto_negotiation(wqe))
				return 1;
			return 0;			
		}else
			return -ENOIF;
}

int cvmcs_dcb_get_dq(cvmx_wqe_t *wqe, int port)
{
	int priority = 0;
	vnic_port_info_t *nicport;
	cvmcs_nic_metadata_t *mdata = CVMCS_NIC_METADATA(wqe);

	if (octnic->dcb[mdata->gmx_id].dcb_enabled) {
		nicport = &octnic->port[mdata->from_ifidx];
		priority = (mdata->from_port & 0xff) - nicport->iq_base;
	}

	if (octeon_has_feature(OCTEON_FEATURE_PKND))
		return (cvmx_pko_get_base_queue_pkoid(port) + priority);
	else
		return (cvmx_pko_get_base_queue(port) + priority);
}

/*
 * Disables PFC in a particular port.
 *
 * @param interface - Interface number 
 * @param port_num  - Physical port number 
 */
void cvmcs_dcb_disable_pfc(int port_num)
{
	int interface, index;
	int ipd_port = octnic->gmx_port_info[port_num].ipd_port;
        cvmx_bgxx_smux_cbfc_ctl_t pfc_config;

	interface = cvmx_helper_get_interface_num(ipd_port) & 0xff;
	index = cvmx_helper_get_interface_index_num(ipd_port);

        pfc_config.u64 = cvmx_read_csr(CVMX_BGXX_SMUX_CBFC_CTL(index, interface));
        pfc_config.s.rx_en  = 1;
        pfc_config.s.tx_en  = 0;
        pfc_config.s.bck_en = 0;
        pfc_config.s.drp_en = 1;
        cvmx_write_csr(CVMX_BGXX_SMUX_CBFC_CTL(index,interface), pfc_config.u64);
}

/*
 * Enable PFC for the priority queues based on configuration data
 *
 * @param port The port number
 * @param pfc_enable Each set bit indicate PFC is
 *        enabled for the corresponding priority,
 * @param pfc_cap The number of priority queus/traffic classes
 *        that can support PFC simultaneosly.
 *
 * @return Zero on success.
 **/
uint8_t cvmcs_dcb_pfc_config(uint8_t port_num, uint8_t pfc_enable, uint8_t pfc_cap)
{
        uint8_t interface, index;
        uint16_t ipd_port;
        cvmx_bgxx_smux_cbfc_ctl_t pfc;
        cvmx_bgxx_smux_hg2_control_t hg2;
        cvmx_bgxx_smux_tx_ctl_t hg;
        cvmx_bgxx_smux_rx_udd_skp_t udd;
        cvmx_bgxx_smux_tx_append_t app;

        ipd_port = octnic->gmx_port_info[port_num].ipd_port;
        interface = cvmx_helper_get_interface_num(ipd_port) & 0xff;
	index = cvmx_helper_get_interface_index_num(ipd_port);
	
        hg2.u64  = cvmx_read_csr(CVMX_BGXX_SMUX_HG2_CONTROL(index,interface));
        hg.u64   = cvmx_read_csr(CVMX_BGXX_SMUX_TX_CTL(index,interface));
        app.u64  = cvmx_read_csr(CVMX_BGXX_SMUX_TX_APPEND(index,interface));
        udd.u64  = cvmx_read_csr(CVMX_BGXX_SMUX_RX_UDD_SKP(index,interface));
        pfc.u64  = cvmx_read_csr(CVMX_BGXX_SMUX_CBFC_CTL(index,interface));

        hg2.s.hg2tx_en  = 0;
        hg2.s.hg2rx_en  = 0;
        hg.s.hg_en      = 0;
        app.s.preamble  = 1;
	udd.s.fcssel    = 1;
        udd.s.len       = 0;
        pfc.s.phys_en   = 0x0;
        //pfc.s.logl_en   = 0xFF;
	pfc.s.logl_en   = pfc_enable;
	if(!pfc_enable)
	{
		pfc.s.bck_en    = 0;
		pfc.s.rx_en     = 1;
		pfc.s.tx_en     = 0;
	}
	else
	{
		pfc.s.bck_en    = 1;
		pfc.s.rx_en     = 1;
		pfc.s.tx_en     = 1;
	}

	pfc.s.drp_en    = 1;

        cvmx_write_csr(CVMX_BGXX_SMUX_HG2_CONTROL(index,interface),hg2.u64);
        cvmx_write_csr(CVMX_BGXX_SMUX_TX_CTL(index,interface),hg.u64);
        cvmx_write_csr(CVMX_BGXX_SMUX_TX_APPEND(index,interface),app.u64);
        cvmx_write_csr(CVMX_BGXX_SMUX_RX_UDD_SKP(index,interface),udd.u64);
        cvmx_write_csr(CVMX_BGXX_SMUX_CBFC_CTL(index,interface),pfc.u64);

        return 0;
}        

/*
 * Wait for all descriptor queues(DQ) to drain.
 * 
 * @param node is to specify the node to which the DQs are associated.
 * @param ipd_port The IPD port value.
 *
 * @return Returns zero on success.
 */
int cvmcs_dcb_pko_drain_dq(unsigned node, uint16_t ipd_port)
{
	int dq_base, dq_count, i, res;
	uint64_t cycles;
	const unsigned timeout = 10;	/* milliseconds */

	dq_base = cvmx_pko3_get_queue_base(ipd_port);
	dq_count = cvmx_pko3_get_queue_num(ipd_port);

	/* Get rid of node-number in DQ */
	dq_base &= (1 << 10)-1;
	
	/* Wait for all queues to drain */
	for(i = 0; i < dq_count; i++) {
		/* Prepare timeout */
		cycles = cvmx_get_cycle();
		cycles += cvmx_clock_get_rate(CVMX_CLOCK_CORE)/1000 * timeout;

		/* Wait for queue to drain */
		do {
			res = cvmx_pko3_dq_query(node, dq_base + i);
			if (cycles < cvmx_get_cycle())
				break;
		} while(res > 0);
	}
	
	return 0;
}

/*
 * Get L2 and L3 base queues for the port.
 *
 * @param node node number.
 * @param port the port number.
 *
 * @return Returns zero on success.
 */
int cvmcs_dcb_get_base_queues(unsigned node, int port)
{
	uint16_t ipd_port;
	int interface, xiface, index;
	int l1_queue, l2_queue;
	cvmx_pko_l1_sqx_topology_t pko_l1_sqx_topology;
	cvmx_pko_l2_sqx_topology_t pko_l2_sqx_topology;	

	ipd_port = octnic->gmx_port_info[port].ipd_port;
	interface = cvmx_helper_get_interface_num(ipd_port);
	xiface = cvmx_helper_node_interface_to_xiface(node, interface);
	index = cvmx_helper_get_interface_index_num(port);
	
	/* Get L1 base queue */
	l1_queue = cvmx_pko3_get_port_queue(xiface, index);
	if (l1_queue < 0) {
		printf("ERROR: %s: Invalid L1 PQ\n", __func__);
		return -1;
	}
	octnic->dcb[port].l1_queue = l1_queue;

	/* Get L2 base queue */
	pko_l1_sqx_topology.u64 = cvmx_read_csr_node(node,
			CVMX_PKO_L1_SQX_TOPOLOGY(l1_queue));
	octnic->dcb[port].l2_base = pko_l1_sqx_topology.s.prio_anchor;

	l2_queue = octnic->dcb[port].l2_base;

	/* Get L3 base queue */
	pko_l2_sqx_topology.u64 = cvmx_read_csr_node(node,
			CVMX_PKO_L2_SQX_TOPOLOGY(l2_queue));
	octnic->dcb[port].l3_base = pko_l2_sqx_topology.s.prio_anchor;

	return 0;
}

/*
 * Map channel to L3 level.
 * Get L2 and L3 base queues for the port.
 *
 * @param port the port number.
 *
 * @return Returns zero on success.
 */
int cvmcs_dcb_init_pko(int port)
{
	int res, i, l3_base, l1_queue;
	uint16_t ipd_port, chan;
	unsigned node = cvmx_get_node_num();

	res = cvmcs_dcb_get_base_queues(node, port);
	if(res < 0) 
		return -1;

	if(!(octnic->dcb[0].dcb_enabled == true) || (octnic->dcb[1].dcb_enabled == true)) {

		/* configure channel level */
		res = cvmx_pko3_channel_credit_level(node, CVMX_PKO_L3_QUEUES);
		if(res < 0) {
			cvmx_pko3_channel_credit_level(node, CVMX_PKO_L2_QUEUES);
			printf("ERROR: %s: "
					"Channel mapping failed\n", __func__);
			return -1;
		}

		ipd_port = octnic->gmx_port_info[port].ipd_port;
		l1_queue = octnic->dcb[port].l1_queue;
		l3_base = octnic->dcb[port].l3_base;

		for (i = 0; i < 8; i++) {
			chan = ipd_port | cvmx_helper_prio2qos(i);
			cvmx_pko3_map_channel(node, l1_queue, l3_base + i, chan);
		}
	}

	return 0;
}

/*
 * This function configures level 2 queues scheduling and topology parameters
 * in hardware.
 *
 * @param node is to specify the node to which this configuration is applied.
 * @param queue is the level2 queue number to be configured.
 * @param parent_queue is the parent queue at next level for this l2 queue.
 * @param prio is this queue's priority in parent's scheduler.
 * @param rr_quantum is this queue's round robin quantum value.
 * @param child_base is the first child queue number.
 * @param child_rr_prio is the round robin childs priority.
 */
void cvmcs_dcb_pko_configure_l2_queue(int node, int queue, int parent_queue,
		int prio, int rr_quantum, int child_base, int child_rr_prio)
{
	cvmx_pko_l2_sqx_schedule_t pko_sq_sched;
	cvmx_pko_l2_sqx_topology_t pko_child_topology;
	cvmx_pko_l1_sqx_topology_t pko_parent_topology;

	/* parent topology configuration */
	pko_parent_topology.u64 = cvmx_read_csr_node(node,
			CVMX_PKO_L1_SQX_TOPOLOGY(parent_queue));
	pko_parent_topology.s.prio_anchor = child_base;
	pko_parent_topology.s.rr_prio = child_rr_prio;
	cvmx_write_csr_node(node,
			CVMX_PKO_L1_SQX_TOPOLOGY(parent_queue),
			pko_parent_topology.u64);

	/* scheduler configuration for this sq in the parent queue */
	pko_sq_sched.u64 = 0;
	pko_sq_sched.s.prio = prio;
	pko_sq_sched.s.rr_quantum = rr_quantum;
	cvmx_write_csr_node(node, CVMX_PKO_L2_SQX_SCHEDULE(queue),
			pko_sq_sched.u64);

	/* child topology configuration */
	pko_child_topology.u64 = cvmx_read_csr_node(node,
			CVMX_PKO_L2_SQX_TOPOLOGY(queue));
	pko_child_topology.s.parent = parent_queue;
	cvmx_write_csr_node(node, CVMX_PKO_L2_SQX_TOPOLOGY(queue),
			pko_child_topology.u64);
}

/*
 * This function configures level 3 queues scheduling and topology parameters
 * in hardware.
 *
 * @param node is to specify the node to which this configuration is applied.
 * @param queue is the level3 queue number to be configured.
 * @param parent_queue is the parent queue at next level for this l3 queue.
 * @param prio is this queue's priority in parent's scheduler.
 * @param rr_quantum is this queue's round robin quantum value.
 * @param child_base is the first child queue number in the static prioriy childs.
 * @param child_rr_prio is the round robin childs priority.
 */
void cvmcs_dcb_pko_configure_l3_queue(int node, int queue, int parent_queue,
		int prio, int rr_quantum, int child_base, int child_rr_prio)
{
	cvmx_pko_l3_sqx_schedule_t pko_sq_sched;
	cvmx_pko_l3_sqx_topology_t pko_child_topology;
	cvmx_pko_l2_sqx_topology_t pko_parent_topology;

	/* parent topology configuration */
	pko_parent_topology.u64 = cvmx_read_csr_node(node,
			CVMX_PKO_L2_SQX_TOPOLOGY(parent_queue));
	pko_parent_topology.s.prio_anchor = child_base;
	pko_parent_topology.s.rr_prio = child_rr_prio;
	cvmx_write_csr_node(node,
			CVMX_PKO_L2_SQX_TOPOLOGY(parent_queue),
			pko_parent_topology.u64);

	/* scheduler configuration for this sq in the parent queue */
	pko_sq_sched.u64 = 0;
	pko_sq_sched.s.prio = prio;
	pko_sq_sched.s.rr_quantum = rr_quantum;
	cvmx_write_csr_node(node, CVMX_PKO_L3_SQX_SCHEDULE(queue), pko_sq_sched.u64);

	/* child topology configuration */
	pko_child_topology.u64 = cvmx_read_csr_node(node,
					 CVMX_PKO_L3_SQX_TOPOLOGY(queue)); 
	pko_child_topology.s.parent = parent_queue;
	cvmx_write_csr_node(node, CVMX_PKO_L3_SQX_TOPOLOGY(queue),
				pko_child_topology.u64);
}

/*
 * Function used by DCBX to configure ETS based on default/received
 * configuration entries.
 *
 * @param port_num The port number.
 * @param prio_assign_table The priority to traffic class table.
 * @param tc_bw_table The traffic class to bandwidth table.
 * @param tsa_table The transmission selection algorithm to traffic class table.
 *
 * @return Returns zero on success.
 */
uint8_t cvmcs_dcb_ets_config(uint8_t port_num, uint8_t *prio_assign_table,
		uint8_t *tc_bw_table, uint8_t *tsa_table)
{
	uint16_t ipd_port;
	int l2_base, l2_queue, l1_queue;
	int l3_base, l3_queue;
	int prio, tc, qos, mtu, static_prio, count;
	unsigned node = cvmx_get_node_num();
	cvmx_pko_enable_t pko_enable;

	ipd_port = octnic->gmx_port_info[port_num].ipd_port;
	l1_queue = octnic->dcb[port_num].l1_queue;
	l2_base = octnic->dcb[port_num].l2_base;
	l3_base = octnic->dcb[port_num].l3_base;
	mtu = octnic->port[octnic->dcb[port_num].ifidx].mtu;

	/* Disable PKI and wait for all DQs to drain */
	cvmx_pki_disable(node);
	cvmcs_dcb_pko_drain_dq(node, ipd_port);

	pko_enable.u64 = 0;
	cvmx_write_csr_node(cvmx_get_node_num(), CVMX_PKO_ENABLE, pko_enable.u64);

	DBG("prio_assign_table = %d  %d  %d  %d  %d  %d  %d  %d\n",
		prio_assign_table[0], prio_assign_table[1], prio_assign_table[2], prio_assign_table[3],
		prio_assign_table[4], prio_assign_table[5], prio_assign_table[6], prio_assign_table[7]);

	DBG("tc_bw_table = %d  %d  %d  %d  %d  %d  %d  %d\n",
		tc_bw_table[0], tc_bw_table[1], tc_bw_table[2], tc_bw_table[3],
		tc_bw_table[4], tc_bw_table[5], tc_bw_table[6], tc_bw_table[7]);

	DBG("tsa_table = %d  %d  %d  %d  %d  %d  %d  %d\n",
		tsa_table[0], tsa_table[1], tsa_table[2], tsa_table[3],
		tsa_table[4], tsa_table[5], tsa_table[6], tsa_table[7]);

	l2_queue = l2_base;
	static_prio = 0;

	/* Map Strict priorities first one(l3) to one(l2) and to l1 */

        for(tc = 0; tc < 8; tc++) {

		if (tsa_table[tc] == OCTEON_TSA_ETS)
			continue;

		count = 0;

		for(prio = 0; prio < 8; prio++) {

			qos = cvmx_helper_prio2qos(prio);

			if(prio_assign_table[qos] == tc) {

				l3_queue = l3_base + prio;
				l2_queue = l2_base + prio;

				cvmcs_dcb_pko_configure_l3_queue(node, l3_queue,
					l2_queue, prio, 0, l3_base, 0xF);

				cvmcs_dcb_pko_configure_l2_queue(node, l2_queue,
					l1_queue, prio, 0, l2_base, 0xF);

				count++;
			}

		}

		if (count)
			static_prio++;

	}

	/* Map ETS tcs */

	for(tc = 0; tc < 8; tc++) {

		if (tsa_table[tc] != OCTEON_TSA_ETS)
			continue;

		l2_queue = -1;

		for(prio = 0; prio < 8; prio++) {

			qos = cvmx_helper_prio2qos(prio);

			if(prio_assign_table[qos] == tc) {

				l3_queue = l3_base + prio;
				if (l2_queue == -1) {
					l2_queue = l2_base + prio;
				} else {
					cvmx_pko_l2_sqx_topology_t topology;
					cvmx_pko_l2_sqx_schedule_t sched;

					/* Unused L2 Queue */
					sched.u64 = 0;
					sched.s.rr_quantum = 0;
					cvmx_write_csr_node(node,
						CVMX_PKO_L2_SQX_SCHEDULE(l2_base + prio),
						sched.u64);

					topology.u64 = 0;
					cvmx_write_csr_node(node,
						CVMX_PKO_L2_SQX_TOPOLOGY(l2_base + prio),
						topology.u64);
				}

				cvmcs_dcb_pko_configure_l3_queue(node, l3_queue,
					l2_queue, prio, 0, l3_base, 0xF);
			}
		}

		if (l2_queue != -1) {

			cvmcs_dcb_pko_configure_l2_queue(
				node, l2_queue, l1_queue, 8,
				mtu * tc_bw_table[tc],
				((static_prio > 0) ? l2_base : 0), 8);

		}

	}

	pko_enable.s.enable = 1;
	cvmx_write_csr_node(cvmx_get_node_num(), CVMX_PKO_ENABLE, pko_enable.u64);

	/* Enable PKI after queue configuration is completed */
	cvmx_pki_enable(node);
	return 0;
}

/*
 * When DCB is disabled for a port, change PKO to default queue configuration.
 * Eight DQs with different priorities will be created. 
 *
 * @param port_num The port number.
 *
 * @return Returns zero on success.
 */
int cvmcs_dcb_ets_disable(int port_num)
{
	uint16_t ipd_port;
	int i, l3_queue, l2_queue, l1_queue;
	unsigned node = cvmx_get_node_num();

	ipd_port = octnic->gmx_port_info[port_num].ipd_port;

	/* Disable PKI and wait for all DQs to drain */
	cvmx_pki_disable(node);	
	cvmcs_dcb_pko_drain_dq(node, ipd_port);

	l1_queue = octnic->dcb[port_num].l1_queue;

	l2_queue = octnic->dcb[port_num].l2_base;

	l3_queue = octnic->dcb[port_num].l3_base;

	for(i = 0; i < 8; i++) {

		cvmcs_dcb_pko_configure_l3_queue(node, l3_queue + i,
				l2_queue + i, i, 0, l3_queue, 0xF);

		cvmcs_dcb_pko_configure_l2_queue(node, l2_queue + i,
				l1_queue, i, 0, l2_queue, 0xF);
	}

	/* Enable PKI after queue configuration is completed */
	cvmx_pki_enable(node);

	return 0;
}

