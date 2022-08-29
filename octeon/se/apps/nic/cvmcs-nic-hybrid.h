#ifndef __NIC_HYBRID__
#define __NIC_HYBRID__


#define MAX_VFS_PER_PF 64

#define ISPF(ifidx)         ((ifidx == 0) || (ifidx == 64))
#define GMX_PF_INDEX(id)    (id * MAX_VFS_PER_PF)

CVMX_SHARED extern int hybrid_mode;

int cvmcs_nic_hybrid_init(int core);
int cvmcs_nic_hybrid_sso_init(void);
int cvmcs_nic_hybrid_init_packet_io_global(void);
int cvmcs_nic_hybrid_setup_memory(void);
int cvmcs_nic_hybrid_setup_core_group(void);
int cvmcs_nic_hybrid_port_group_setup(void);

int cvmcs_hybrid_add_vfs(uint16_t ifidx, u32 gmx_port_id, u64 bus_devfn);
int cvmcs_vsw_add_vfs(uint16_t ifidx, u32 gmx_port_id, u64 bus_devfn);

uint8_t cvmcs_hybrid_get_link_status(int ifidx);
void cvmcs_hybrid_sync_octeon_time(cvmx_wqe_t *wqe);
uint8_t cvmcs_vsw_get_link_status(int ifidx);
int cvmcs_vsw_change_mtu_from_host(int ifidx, int gmxport, int new_mtu);
int cvmcs_vsw_send_pf_state_to_octlinux(int ifidx, uint16_t state);
int cvmcs_vsw_update_time_to_octlinux(int ifidx, struct lio_time *tm);
void cvmcs_vsw_process_vf_rep_cmd(cvmx_wqe_t *wqe);
void cvmcs_hybrid_vf_rep_pkt(cvmx_wqe_t *wqe);
void cvmcs_hybrid_vf_rep_cmd(cvmx_wqe_t *wqe);

#endif
