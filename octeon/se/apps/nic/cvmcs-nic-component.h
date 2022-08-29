#ifndef __CVMCS_NIC_COMPONENT_H__
#define __CVMCS_NIC_COMPONENT_H__

#include "cvmcs-nic.h"
#if defined(HYBRID) || defined(LINUX_IPSEC)

#define TSO_SUCCESS              0  
#define TSO_INVALID             -1
#define TSO_FAILED              -2 
#define LRO_AGGREGATED           0
#define LRO_INVALID             -1

#define CVMCS_MAX_COMPONENTS 	 5

#ifdef  OVS_IPSEC
#define COMP_REVERSE	  	    -3
#define COMP_REVERSE_LOOPBACK	-4
#endif

typedef struct cvmcs_component {
	char *name;
	int opcode;
	int (*global_init) (void);
	int (*per_core_init) (void);
	int (*cmd_init) (void);
	int (*from_host_msg_cb) (cvmx_wqe_t * wqe, int subcode);
	int (*from_host_packet_cb) (cvmx_wqe_t * wqe);
	int (*from_wire_packet_cb) (cvmx_wqe_t ** wqe, int * ifidx);
} cvmcs_component_t;

CVMX_SHARED extern cvmcs_component_t lio_vsw_comp;
CVMX_SHARED extern cvmcs_component_t ipsec_comp;
int cvmcs_nic_component_cmd_init(void);
int cvmcs_nic_component_wire_packet(cvmx_wqe_t ** wqe);
int cvmcs_nic_component_host_packet(cvmx_wqe_t * wqe);

#endif //HYBRID

#define COMP_CONSUMED		0  //Same as CORE component
#define COMP_NOT_HANDLED	-1
#define COMP_DROP		-2

int cvmcs_nic_component_host_message(cvmx_wqe_t * wqe,
	       int opcode, int subcode);
int cvmcs_nic_component_global_init(void);
int cvmcs_nic_component_local_init(void);
int cvmcs_nic_component_cmd_init(void);
#endif
