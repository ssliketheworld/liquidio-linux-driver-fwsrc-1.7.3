
#include "cvmcs-nic.h"
#ifndef HYBRID
//Stub for base nic
int cvmcs_hybrid_add_vfs(uint16_t ifidx, u32 gmx_port_id, u64 bus_devfn)
{
	return 0;
}

int cvmcs_nic_hybrid_init(int core)
{
	u64 data;
/* This must match OVS module arch/mips/octeon/cavium-setup.c AND
 * both Legacy & UEFI PXE preboot drivers.
 */
#define OCTEON_HOST_TIME_REQ 0xdead55aa

	/* Implementation note: the preboot drivers wait for the [OVS] firmware
	 * to send a 'request_for_host_time' via the SCRATCH1 register.
	 * This allows the host time to be syncronized to OctLinux' time.
	 *
	 * To prevent the preboot driver from waiting unnecessarily for this
	 * request, we simulate it ourselves.
	 * This write to the SCRATCH1 register serves as the
	 * 'request_for_host_time' and allows the preboot driver to continue
	 * its boot process (without any additional wait).
	 *
	 * Without this, there will be an additional 10-14s delay when booting
	 * a board which has been programmed with the preboot drivers
	 * and the regular NIC firmware (i.e. non-OVS).
	 */

	data = (u64)OCTEON_HOST_TIME_REQ << 32;
	cvmx_write_csr(CVMX_PEXP_SLI_SCRATCH_1, data);

	return 0;
}

/* Stub for base NIC: this is implemented to avoid using VSWITCH macro in
 * NIC code, to know link status.
 * When the firmware is complied for OVS, original definition of this API
 * will take effect
 */
uint8_t cvmcs_hybrid_get_link_status(int ifidx)
{
	return 1;
}

void cvmcs_hybrid_sync_octeon_time(cvmx_wqe_t *wqe)
{
	cvm_free_wqe_wrapper(wqe);
}

void
cvmcs_hybrid_vf_rep_pkt(cvmx_wqe_t *wqe)
{
	cvm_free_wqe_wrapper(wqe);
}

void
cvmcs_hybrid_vf_rep_cmd(cvmx_wqe_t *wqe)
{
	cvm_free_wqe_wrapper(wqe);
}
#else
#include "cvmx-fpa.h"
#include "cvmcs-nic-hybrid.h"
#include "cvmcs-common.h"
#include <cvmx-helper-ipd.h>
#include "cvmx-helper-ipd.h" 
#include "cvmx-app-config.h" 
#include "cvmx-helper-pko3.h" 

int cvmcs_nic_hybrid_init(int core)
{
	uint64_t nqm_scratch, linux_user_loaded;

	/*Only for 78xx */
	if (!OCTEON_IS_MODEL(OCTEON_CN78XX) && !OCTEON_IS_MODEL(OCTEON_CN73XX))
		return 1;

	 if (octeon_has_feature(OCTEON_FEATURE_PKI)) {
                cvmx_pki_buf_ctl_t buf_ctl;
                cvmx_safe_printf("PKI: Waiting for HW initialization from control load set... \n");
                do {
                        buf_ctl.u64 = cvmx_read_csr(CVMX_PKI_BUF_CTL);
                } while (!buf_ctl.cn78xx.pki_en);
        } else {
                cvmx_ipd_ctl_status_t ipd_reg;
                cvmx_safe_printf("IPD: Waiting for HW initialization from control load set... \n");
                do {
                        ipd_reg.u64 = cvmx_read_csr(CVMX_IPD_CTL_STATUS);
                } while (!ipd_reg.s.ipd_en);
        }

	/* Starting 1.7.0, we wait for Linux Userspace to init */
	/* Using NQM for firmware octlinux sync up */
	while (!linux_user_loaded) {
		nqm_scratch = cvmx_read_csr(CVMX_NQM_SCRATCH);
		linux_user_loaded = ((nqm_scratch >> NQM_BIT_FW_IN_SYNC) & 1);
	}

	printf("Octlinux initialization done. Pool info:\n");

	return 0;
}

int cvmcs_nic_hybrid_sso_init(void)
{
	if (OCTEON_IS_MODEL(OCTEON_CN68XX)
	    && (cvmx_helper_initialize_sso(FPA_WQE_POOL_COUNT)))
		return -1;

	return cvmx_helper_initialize_sso(FPA_PACKET_POOL_COUNT / 2);
}

static int cvmcs_ovs_global_pko3_init(int node)
{
	int result = 0;
	int num_interfaces = cvmx_helper_get_number_of_interfaces();
	int interface = 0;

	__cvmx_helper_init_port_valid();


	for (interface = 0;
	     interface < cvmx_helper_get_number_of_interfaces();
	     interface++)
		cvmx_helper_interface_probe(interface);


	if (octeon_has_feature(OCTEON_FEATURE_CN78XX_WQE)) {
		__cvmx_helper_init_port_config_data(node);
		result = cvmx_helper_pko3_init_global(node);
	} else {
		result = cvmx_helper_pko_init();
	}

	for (interface = 0; interface < num_interfaces; interface++) {
		/* Skip invalid/disabled interfaces */
		if (cvmx_helper_ports_on_interface(interface) <= 0)
			continue;
		printf("Interface %d has %d ports (%s)\n",
		       interface,
		       cvmx_helper_ports_on_interface(interface),
		       cvmx_helper_interface_mode_to_string
		       (cvmx_helper_interface_get_mode(interface)));

		result |= __cvmx_helper_ipd_setup_interface(interface);
		result |=
		    cvmx_helper_pko3_init_interface
		    (cvmx_helper_node_interface_to_xiface
		     (node, interface));
	}

	if (octeon_has_feature(OCTEON_FEATURE_PKI))
		result |= __cvmx_helper_pki_global_setup(node);
	else
		result |= __cvmx_helper_ipd_global_setup();


	return result;
}


int cvmcs_nic_hybrid_init_packet_io_global(void)
{
	unsigned int node = cvmx_get_node_num();

	/*Only for 78xx */
	if (!OCTEON_IS_MODEL(OCTEON_CN78XX) && !OCTEON_IS_MODEL(OCTEON_CN73XX)) {
		int interface;

		/*Sync config from octlinux, including 3 fpa pools */
		__cvmx_helper_init_port_valid();

		for (interface = 0;
		     interface < cvmx_helper_get_number_of_interfaces();
		     interface++)
			cvmx_helper_interface_probe(interface);


		__cvmx_import_app_config_from_named_block(CVMX_APP_CONFIG);
		__cvmx_helper_init_port_config_data_local();

	} else {

		cvmcs_ovs_global_pko3_init(node);
	}

	return 0;
}

int cvmcs_nic_hybrid_setup_memory(void)
{
	/*Only for 78xx */
	if (!OCTEON_IS_MODEL(OCTEON_CN78XX) && !OCTEON_IS_MODEL(OCTEON_CN73XX))
		return 1;

	cvmx_fpa_enable();

	printf("%s: NIC hybrid init ..\n", __func__);

	if (OCTEON_IS_MODEL(OCTEON_CN78XX) ||
	    OCTEON_IS_MODEL(OCTEON_CN73XX)) {
		if (cvmcs_app_mem_alloc("Small Buffers",
					CVMX_FPA_SMALL_BUFFER_POOL,
					CVMX_FPA_SMALL_BUFFER_POOL_SIZE,
					FPA_SMALL_BUFFER_POOL_COUNT))
			return 1;
	}

	/* FOLLOWING MEMORY POOLS ARE CREATED FOR TSO & LRO FEATURES
	 *      1. GATHER LIST POOL
	 *      2. LRO CONTEXT POOL
	 */
	if (cvmcs_app_mem_alloc
	    ("Gather List Entries", CVMX_FPA_GATHER_LIST_POOL,
	     CVMX_FPA_GATHER_LIST_POOL_SIZE, FPA_GATHER_LIST_POOL_COUNT)) {
		return 1;
	}


	if (cvmcs_app_mem_alloc("LRO Buffers", CVMX_FPA_LRO_CONTEXT_POOL,
				CVMX_FPA_LRO_CONTEXT_POOL_SIZE,
				FPA_LRO_CONTEXT_POOL_COUNT))
		return 1;

	return (cvmcs_nic_hybrid_sso_init());
}

int cvmcs_nic_hybrid_setup_core_group(void)
{
	if (OCTEON_IS_MODEL(OCTEON_CN78XX))
		return 0;

	return 0;
}

int cvmcs_nic_hybrid_port_group_setup(void)
{
	if (OCTEON_IS_MODEL(OCTEON_CN78XX)) {

	}
	return 0;
}
int cvmcs_hybrid_add_vfs(uint16_t ifidx, u32 gmx_port_id, u64 bus_devfn)
{
#ifdef VSWITCH
	return cvmcs_vsw_add_vfs(ifidx,gmx_port_id,bus_devfn);
#endif
}

uint8_t cvmcs_hybrid_get_link_status(int ifidx) 
{
#ifdef VSWITCH
	return cvmcs_vsw_get_link_status(ifidx);
#else
	return 1;
#endif
}

void cvmcs_hybrid_sync_octeon_time(cvmx_wqe_t *wqe)
{
#ifdef VSWITCH
	cvmx_raw_inst_front_t *f;
	struct lio_time *tm;
	int front_size;
	int ifidx;

	ifidx = get_vnic_port_id(cvmx_wqe_get_port(wqe));

	if (octeon_has_feature(OCTEON_FEATURE_CN78XX_WQE))
		f = (cvmx_raw_inst_front_t *)
			cvmx_phys_to_ptr(cvmx_wqe_get_pki_pkt_ptr(wqe).addr);
	else
		f = (cvmx_raw_inst_front_t *)wqe->packet_data;

	if (f->irh.s.rflag)
		front_size = CVM_RAW_FRONT_SIZE;
	else
		front_size = CVM_RAW_FRONT_SIZE - 16;

	tm = (struct lio_time *)((uint8_t *)f + front_size);

	if (cvmcs_vsw_update_time_to_octlinux(ifidx, tm))
		cvmcs_printf("Failed to sync time to octlinux\n");
#endif
	cvm_free_wqe_wrapper(wqe);
}

void
cvmcs_hybrid_vf_rep_pkt(cvmx_wqe_t *wqe)
{
	cvm_free_wqe_wrapper(wqe);
}

void
cvmcs_hybrid_vf_rep_cmd(cvmx_wqe_t *wqe)
{
	cvmcs_vsw_process_vf_rep_cmd(wqe);
}
#endif //HYBRID
