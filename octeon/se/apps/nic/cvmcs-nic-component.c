#include "cvmcs-nic-component.h"
#if defined(HYBRID) || defined(LINUX_IPSEC)
CVMX_SHARED cvmcs_component_t *lio_components[CVMCS_MAX_COMPONENTS] = {
#ifdef VSWITCH
	[OPCODE_OVS] = &lio_vsw_comp, 
#endif
#ifdef LINUX_IPSEC
       [OPCODE_IPSEC] = &ipsec_comp,
#endif
};

int cvmcs_nic_component_host_packet(cvmx_wqe_t * wqe)
{
	int i, ret=-1;

	/*
	 * Give a chance to other lio_components. 
	 * Skip CORE and NIC lio_components.
	 */
	for (i = CVMCS_MAX_COMPONENTS-1; i >= 0; i--) {
		if (lio_components[i] && lio_components[i]->from_host_packet_cb) {
			ret = lio_components[i]->from_host_packet_cb(wqe);

			if (cvmx_likely(ret == COMP_CONSUMED))
				return 0;

			if (ret == COMP_DROP) {
				cvm_free_wqe_wrapper(wqe);
				return 0;
			}

			/* 
			 * Handle this case, need to call
			 * another component
			 */
			if (ret != COMP_NOT_HANDLED) {
				cvm_free_wqe_wrapper(wqe);
				return 0;
			}

		}
	}

	return 1;
}

int cvmcs_nic_component_host_message(cvmx_wqe_t * wqe, int opcode,
				     int subcode)
{
	if ((opcode < CVMCS_MAX_COMPONENTS)  && lio_components[opcode]) {
		lio_components[opcode]->from_host_msg_cb(wqe, subcode);
		return 0;
	}
	return 1;

}

int cvmcs_nic_component_wire_packet(cvmx_wqe_t ** wqe_ref)
{
	int i, ret=-1;
	int ifidx = -1;
	cvmx_wqe_t *wqe = *wqe_ref;
	/* 
	 * Try other component Skip CORE and NIC lio_components.
	 */
	for (i = 0; i < CVMCS_MAX_COMPONENTS; i++) {
		if (lio_components[i] && lio_components[i]->from_wire_packet_cb) {
			ret = lio_components[i]->from_wire_packet_cb(&wqe, &ifidx);
#ifdef OVS_IPSEC
			*wqe_ref = wqe;
			if (ret == COMP_REVERSE) {
			    ret = lio_components[OPCODE_OVS]->from_host_packet_cb(wqe);
			}
			else if (ret == COMP_REVERSE_LOOPBACK) {
                ret = cvmcs_nic_component_host_packet(wqe);
			}
#endif
			if (cvmx_likely(ret == COMP_CONSUMED))
				return 0;

			if (ret == COMP_DROP) {
				cvm_free_wqe_wrapper(wqe);
				return 0;
			}
			/*
			 * Handle this case, need to call
			 * another component
			 */
			if (ret != COMP_NOT_HANDLED) {
				cvm_free_wqe_wrapper(wqe);
				return 0;
			}
		}
	}

	return 1;
}

int cvmcs_nic_component_cmd_init(void)
{
	int i;

	/*Initialize any component specific commands */
	for (i = 0; i < CVMCS_MAX_COMPONENTS; i++)
		if (lio_components[i] && lio_components[i]->cmd_init)
			lio_components[i]->cmd_init();
	return 0;

}

int cvmcs_nic_component_local_init(void)
{
	int i;
	/* Initialize component specific things, skip CORE and NIC */
	for (i = 0; i < CVMCS_MAX_COMPONENTS; i++) {
		if (lio_components[i])
			if (lio_components[i]->per_core_init())
				return 1;
	}
	return 0;

}

int cvmcs_nic_component_global_init(void)
{
	int i;
	/* Initialize component specific things, skip CORE and NIC */
	for (i = 0; i < CVMCS_MAX_COMPONENTS; i++) {
		if (lio_components[i])
			if (lio_components[i]->global_init())
				return 1;
	}
	return 0;

}
#else
//Stub for base nic
int cvmcs_nic_component_local_init(void)
{
	return 0;
}

int cvmcs_nic_component_host_message(cvmx_wqe_t * wqe, int opcode,
				     int subcode)
{
	return 1;
}

int cvmcs_nic_component_global_init(void)
{
	return 0;
}
int cvmcs_nic_component_cmd_init(void)
{
	return 0;
}
#endif
