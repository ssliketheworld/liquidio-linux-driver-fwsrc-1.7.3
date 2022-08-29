/*---------------------------------------------------------------------------
 * 
 * nvme_stats.h 
 *
 *---------------------------------------------------------------------------
 */

#ifndef __NVME_STATS_H__
#define __NVME_STATS_H__
#include "nvme_stats_info.h"

#define NVME_MAX_CORES 16 //TODO
#define GSQID(vfid, sqid) \
               (sqid + \
                    vfid * nqm_vf_mode_map[nqm_vf_mode].vf_max_ioq)

extern nvme_per_cpu_stats_t *nvme_per_cpu_stats;
extern CVMX_SHARED nvme_global_stats_t *nvme_global_stats;
extern CVMX_SHARED uint8_t nqm_vf_mode;
extern CVMX_SHARED nqm_vf_mode_map_t nqm_vf_mode_map[];

#define NVME_INC_IOSQ_STATS(__sq, __member, __val) \
                    nvme_per_cpu_stats->g_io_sq[__sq->gsq_id].__member += __val
                    
#define NVME_SET_IOSQ_STATS(__sq, __member, __val) \
                    nvme_per_cpu_stats->g_io_sq[__sq->gsq_id].__member = __val

#define NVME_INC_ADMINQ_STATS(__gaqid, __member, __val) \
                    nvme_per_cpu_stats->g_admin_q[__gaqid].__member += __val

#define NVME_SET_ADMINQ_STATS(__gaqid, __member, __val) \
                    nvme_per_cpu_stats->g_admin_q[__gaqid].__member = __val

#define NVME_INC_NS_STATS(__nsid, __member, __val) \
                    nvme_per_cpu_stats->g_ns[__nsid].__member += __val

#define NVME_SET_NS_STATS(__nsid, __member, __val) \
                    nvme_per_cpu_stats->g_ns[__nsid].__member = __val

#define NVME_INC_DMA_STATS(__id, __member, __val) \
                    nvme_per_cpu_stats->dma[__id].__member += __val

#define NVME_SET_DMA_STATS(__id, __member, __val) \
                    nvme_per_cpu_stats->dma[__id].__member = __val

#define NVME_INC_GEN_STATS(__member, __val) \
                    nvme_per_cpu_stats->__member += __val

#define NVME_SET_GEN_STATS(__member, __val) \
                    nvme_per_cpu_stats->__member = __val

/**************************************************************************//**
*
*   npl_update_dma_inout_stats
*
*   This functions updates # of DMA IN/OUT command stats
*
*       @parm dma_engine    DMA engine id
*       @parm mode          Mode of the DMA command (DMA_INBOUND/DMA_OUTBOUND).
*
*******************************************************************************/
static inline void
npl_update_dma_inout_stats(uint32_t dma_engine,
                           int mode)
{
    if (mode == DMA_INBOUND)
        NVME_INC_DMA_STATS(dma_engine, inb_cmds, 1);
    else
        NVME_INC_DMA_STATS(dma_engine, outb_cmds, 1);
    NVME_SET_DMA_STATS(dma_engine, last_dma_ts, cvmx_get_cycle());
}

/**************************************************************************//**
*
*   npl_update_iosq_rwbytes
*
*   This functions updates count of bytes processed for RW commands.
*
*       @parm sq           NVME submission queue pointer
*       @parm opcode       Command opcode
*       @parm nsid         Global Name space id
*       @parm val          count in bytes
*
*******************************************************************************/
static inline void 
npl_update_iosq_rwbytes(struct nvme_sub_queue *sq, 
                        uint32_t opcode, 
                        uint64_t nsid, 
                        uint64_t val) {
    if (opcode == nvme_cmd_read) {
        NVME_INC_IOSQ_STATS(sq, rd_bytes, val);
        NVME_INC_NS_STATS(nsid, rd_bytes, val);
    } else if (opcode == nvme_cmd_write) {
        NVME_INC_IOSQ_STATS(sq, wr_bytes, val);
        NVME_INC_NS_STATS(nsid, wr_bytes, val);
    }
}

/**************************************************************************//**
*
*   npl_update_iosq_rwcmds
*
*   This functions updates RW commands count for iosq and name space.
*
*       @parm sq           NVME submission queue pointer
*       @parm opcode       Command opcode
*       @parm nsid         Global Name space id
*                        
*
*******************************************************************************/
static inline void
npl_update_iosq_rwcmds(struct nvme_sub_queue *sq,
                       uint32_t opcode,
                       uint64_t nsid) 
{
    if (opcode == nvme_cmd_read) {
        NVME_INC_IOSQ_STATS(sq, rd_cmds, 1);
        NVME_INC_NS_STATS(nsid, rd_cmds, 1);
    } else if (opcode == nvme_cmd_write) {
        NVME_INC_IOSQ_STATS(sq, wr_cmds, 1);
        NVME_INC_NS_STATS(nsid, wr_cmds, 1);
    }
}

static inline void
npl_update_iosq_rwcmds_no_nsid(struct nvme_sub_queue *sq,
                               uint32_t opcode)
{
    if (opcode == nvme_cmd_read) {
        NVME_INC_IOSQ_STATS(sq, rd_cmds, 1);
    } else if (opcode == nvme_cmd_write) {
        NVME_INC_IOSQ_STATS(sq, wr_cmds, 1);
    }
}

/**************************************************************************//**
*
*   npl_update_iosq_rwtime
*
*   This functions updates the time taken for RW commands for an iosq & namespace
*
*       @parm sq           NVME submission queue pointer
*       @parm opcode       Command opcode
*       @parm nsid         Global Name space id
*       @parm val          cycles
*
*
*******************************************************************************/
static inline void
npl_update_iosq_rwtime(struct nvme_sub_queue *sq,
                       uint32_t opcode,
                       uint64_t nsid,
                       int64_t val) 
{
    if (val <= 0)
        return;
    if (opcode == nvme_cmd_read) {
        NVME_SET_IOSQ_STATS(sq, rd_time, val);
        NVME_SET_NS_STATS(nsid, rd_time, val);
    } else if (opcode == nvme_cmd_write) {
        NVME_SET_IOSQ_STATS(sq, wr_time, val);
        NVME_SET_NS_STATS(nsid, wr_time, val);
    }
}

/**************************************************************************//**
*
*   npl_update_cpl_stats
*
*   This functions updates nvme command completion stats
*
*       @parm dev          nvme_dev pointer
*       @parm sq           NVME submission queue pointer
*       @parm opcode       Command opcode
*       @parm wqp          Pointer to the nvme work
*       @parm cpl_entry    Pointer to the completion status of a completion entry
*
*******************************************************************************/
static inline void
npl_update_cpl_stats(struct nvme_dev *dev,
                     struct nvme_sub_queue *sq,
                     uint32_t opcode,
                     cvmx_wqe_tt *wqp,
                     struct completion_status_field *cpl_entry)
{

    if (!sq->sq_id) {
        if ((cpl_entry->sct == SCT_GENERIC) &&
                (cpl_entry->sc == CMD_SUCCESSFUL))
            NVME_INC_ADMINQ_STATS(wqp->word3.qw3.vf, completed, 1);
        else
            NVME_INC_ADMINQ_STATS(wqp->word3.qw3.vf, errors, 1);
        NVME_SET_ADMINQ_STATS(wqp->word3.qw3.vf, last_compl_ts, cvmx_get_cycle());
        return;
    }

    NVME_SET_IOSQ_STATS(sq, last_compl_ts, cvmx_get_cycle());
    
    if ((opcode == nvme_cmd_read) ||
            (opcode == nvme_cmd_write)) {
        if (cpl_entry->sct == SCT_GENERIC) {
            if (cpl_entry->sc == CMD_SUCCESSFUL)
                NVME_INC_IOSQ_STATS(sq, completions, 1);
            else if(cpl_entry->sc == ABORT_REQUESTED) {
                NVME_INC_IOSQ_STATS(sq, aborted, 1);
                if ((wqp->nvme_cmd.rw.nsid > MAX_NUMBER_NS_CTLR) || 
                        !NSPACE(dev, wqp->nvme_cmd.rw.nsid)) 
                    return;
            } else  {
                NVME_INC_IOSQ_STATS(sq, errors, 1);
                NVME_SET_IOSQ_STATS(sq, last_error_ts, cvmx_get_cycle());
                if ((wqp->nvme_cmd.rw.nsid > MAX_NUMBER_NS_CTLR) || 
                        !NSPACE(dev, wqp->nvme_cmd.rw.nsid)) 
                    return;
                NVME_INC_NS_STATS(NSPACE(dev, wqp->nvme_cmd.rw.nsid)->ns_id, errors, 1);
                NVME_SET_NS_STATS(NSPACE(dev, wqp->nvme_cmd.rw.nsid)->ns_id, last_error_ts, cvmx_get_cycle());
            }
        }
        else {
            NVME_INC_IOSQ_STATS(sq, errors, 1);
            NVME_SET_IOSQ_STATS(sq, last_error_ts, cvmx_get_cycle());
            if ((wqp->nvme_cmd.rw.nsid > MAX_NUMBER_NS_CTLR) || 
                    !NSPACE(dev, wqp->nvme_cmd.rw.nsid)) 
                return;
        }
        /* Update read/write time consumption */
        npl_update_iosq_rwtime(sq, 
                               opcode, NSPACE(dev, wqp->nvme_cmd.rw.nsid)->ns_id, 
                               cvmx_get_cycle() - wqp->reserved);
    }
}

#endif /* __NVME_STATS_H__ */
