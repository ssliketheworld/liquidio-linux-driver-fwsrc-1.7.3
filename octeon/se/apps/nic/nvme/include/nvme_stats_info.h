/*---------------------------------------------------------------------------
 * 
 * nvme_stats_info.h 
 *
 *---------------------------------------------------------------------------
 */

#ifndef __NVME_STATS_INFO_H__
#define __NVME_STATS_INFO_H__
#include "nvme_cvm_defines.h"
#include "cn73xx_nqm_defines.h"

#define OCTEON_NVME_STATS_BLOCK_NAME "__octeon_nvme_stats" 
#define OCTEON_NVME_STATS_TYPE_NONE 0xffffffff
#define OCTEON_NVME_STATS_TYPE_GLOBAL 0x41
#define OCTEON_NVME_STATS_TYPE_PCPU 0x42

#define MAX(a, b) \
            (a > b ? a : b)

/* G_IOSQ_INDEX (1 - MAX)*/
#define NVME_G_IO_SQ_MAX MAX(NQM_VF_MODE0_IOQ_MAX * NQM_VF_MODE0_VF_MAX, \
                             MAX(NQM_VF_MODE1_IOQ_MAX * NQM_VF_MODE1_VF_MAX, \
                             NQM_VF_MODE2_IOQ_MAX * NQM_VF_MODE2_VF_MAX)) + 1

/* G_ADMIN_Q_INDEX (0 - MAX-1) */
#define NVME_G_ADMIN_Q_MAX MAX(NQM_VF_MODE2_VF_MAX, \
                               MAX(NQM_VF_MODE1_VF_MAX, NQM_VF_MODE0_VF_MAX))

#define NVME_VF_MAX MAX(NQM_VF_MODE2_VF_MAX, \
                        MAX(NQM_VF_MODE1_VF_MAX, NQM_VF_MODE0_VF_MAX))

/* NVME_NS_MAX (1 - MAX) */
#define NVME_NS_MAX (MAX_NUMBER_NS + 1)

/* NVME_DMA_ENGINE_MAX (0 - MAX-1) */
#define NVME_DMA_ENGINE_MAX DMA_MAX_HW_ENGINES

#define TLV_SIZE_ALIGN(len) \
            ((len + sizeof(uint64_t) - 1) & (uint64_t) ~(sizeof(uint64_t) - 1))
            
/* Statistics structures */

typedef struct nvme_io_q_stats_s {
    uint64_t rd_cmds; //read commands processed
    uint64_t wr_cmds; //write commands processed
    uint64_t rd_bytes;
    uint64_t wr_bytes;
    uint64_t rd_time;
    uint64_t wr_time;
    uint64_t completions;
    uint64_t last_sub_ts;        //timestamp of last command read from submission queue
    uint64_t last_compl_ts;   //timestamp of last completion written to completion queue
    uint64_t aborted;
    uint64_t errors; //does not include aborted commands
    uint64_t last_error_ts;   //Timestamp of last error observed for a command from this I/O queue
}__attribute__((packed)) nvme_io_q_stats_t;


typedef struct nvme_admin_q_stats_s {
    uint64_t submitted;
    uint64_t completed;
    uint64_t last_sub_ts;        //timestamp of last command read from submission queue
    uint64_t last_compl_ts;   //timestamp of last completion written to completion queue
    uint64_t errors;
}__attribute__((packed)) nvme_admin_q_stats_t;


typedef struct nvme_ns_stats_s {
    uint64_t rd_cmds; //read commands processed
    uint64_t wr_cmds; //write commands processed
    uint64_t rd_bytes;
    uint64_t wr_bytes;
    uint64_t rd_time;
    uint64_t wr_time;
    uint64_t errors;
    uint64_t last_error_ts;   //Timestamp of last error observed for a command from this I/O queue
}__attribute__((packed)) nvme_ns_stats_t;


typedef struct nvme_dma_stats_s {
    uint64_t inb_cmds;      //DMA_INBOUND commands issued
    uint64_t outb_cmds;     //DMA_OUTBOUND commands issued
    uint64_t inb_time;      //DMA_INBOUND command time duration
    uint64_t outb_time;      //DMA_OUTBOUND command time duration
    uint64_t last_dma_ts;
    uint64_t errors;
}__attribute__((packed)) nvme_dma_stats_t;


typedef struct nvme_per_cpu_stats_s {
    nvme_io_q_stats_t       g_io_sq[NVME_G_IO_SQ_MAX];
    nvme_admin_q_stats_t    g_admin_q[NVME_G_ADMIN_Q_MAX];
    nvme_ns_stats_t         g_ns[NVME_NS_MAX];
    nvme_dma_stats_t        dma[NVME_DMA_ENGINE_MAX];
    uint64_t                n_wqe; //number of WQE entries processed by this core
    uint64_t                last_wqe_ts; //timestamp of last WQE entry processed by this core
    uint32_t                unused;
    uint32_t                coreid;
}__attribute__((packed)) nvme_per_cpu_stats_t;


typedef struct nvme_global_stats_s {
    uint64_t vf_bitmap[(NVME_VF_MAX - 1)/64 + 1]; //bitmap of 1027 VFs; 1-VF is active, 0-VF is not active 
    int64_t active_vfs;
    uint64_t active_coremask;
    uint64_t core_clock;
    uint64_t last_error_ts;
    int64_t last_error_status;
    uint32_t n_queues;
    uint32_t max_ioq_per_vf;
    uint32_t max_vf_possible;
    uint32_t vf_state[NVME_VF_MAX]; //<To-Do: yet to conclude possible values of VF state>
    uint32_t vf_to_ns_map[NVME_VF_MAX]; //namespace id of each VF
}__attribute__((packed)) nvme_global_stats_t;

typedef struct nvme_stats_dma_mem {
    nvme_io_q_stats_t    ioq_stats;
    nvme_admin_q_stats_t adminq_stats;
    nvme_ns_stats_t      ns_stats;
} nvme_stats_dma_mem_t;



#endif /* __NVME_STATS_INFO_H__ */
