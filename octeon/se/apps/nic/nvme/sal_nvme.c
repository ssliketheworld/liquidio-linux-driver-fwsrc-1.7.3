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

/***************************************************************************//**
*
*  \file
*
*  \brief This module implements the lower level drive, in this case a ramdisk.
*
*******************************************************************************/

#include "nvme_cvm.h"
#include "sal_linux_bdev.h"

/*
 * Namespace control structures base
 */
extern CVMX_SHARED struct ns_ctrl *ns_ctrl_base;
extern CVMX_SHARED cvm_bdev_list_t glb_bdev_list;

extern uint32_t ns_cat[NVME_NUM_PFVF][MAX_NUMBER_NS_CTLR];
extern uint32_t ns_share[MAX_NUMBER_NS];
extern struct ns_ctrl sal_namespace_tbl[];

/*
 * Global namespaces
 *
 * This table has entries for each namespace used in the drive.
 */
CVMX_SHARED struct ns_ctrl * sal_namespaces[MAX_NUMBER_NS];

/*
 * Namespace mapping policy
 */
extern CVMX_SHARED uint8_t ns_map_policy;
extern CVMX_SHARED int ns_sata_only_map;

/***************************************************************************//**
*
*   Local: sal_do_data_transfer()
*       This function is called from the NVMe processing layer upon
*       receiving a PRP_LIST_TRANSFER_TAG or CMD_TRANSFER_TAG
*       (without PRP lists) I/O requests are routed to specific disk
*       drive handlers depending on namespace ids.
*
*       @param dev      device specific private structure
*    @param wqp     work entry pointer
*
*       @return     Zero on success, or negative error code on failure.
*
*******************************************************************************/
int sal_do_data_transfer(struct nvme_dev *  dev,
                         uint64_t *         prp_list,
                         cvmx_wqe_tt *       wqp)
{
    uint64_t namespace_id;
    uint32_t status;
    cvmx_wqe_tt *new_wqp;
    struct completion_status_field cpl_entry = { 0 };

    new_wqp = npl_fpa_alloc(dev, CVMX_FPA_WQE_POOL);
    if (!new_wqp) goto alloc_fail;
    memset(new_wqp, 0, sizeof(cvmx_wqe_t));
    memcpy(new_wqp, wqp, sizeof(cvmx_wqe_t));
    namespace_id = new_wqp->nvme_cmd.rw.nsid;
    npl_setup_wqe(new_wqp);
    new_wqp->word3.qw3.vf = dev->pfvf; // set pf/vf
    new_wqp->word1.qw1.tag = (IO_DATA_TRANSFER_TAG << NQM_TAG_SHIFT) |
            (new_wqp->word3.qw3.sq_id << NQM_QID_SHIFT);
    new_wqp->word1.qw1.tt = CVMX_POW_TAG_TYPE_ORDERED;
    new_wqp->word1.qw1.grp = 0;
    status = dev->disk_dev.io_handler[namespace_id -1].
                 sal_do_io(dev, prp_list, new_wqp);

    if (status == STATUS_SUCCESS)
        return STATUS_SUCCESS;

    return STATUS_ERROR;
alloc_fail:
    cpl_entry.sct = SCT_GENERIC;
    cpl_entry.sc = INTERNAL_ERROR;
    cpl_entry.m = 0;
    cpl_entry.dnr = 0;
    npl_submit_completion_entry(dev, wqp, 0, cpl_entry);

    return STATUS_ERROR;
}

/***************************************************************************//**
*
*   Local: sal_do_ramdisk_io()
*       This function is called from the sal_do_data_transfer.
*       I/O requests are routed to specific disk drive  depending on
*       namespace ids.
*
*       @param dev             – device specific private structure
*       @param prp_list        - prp list
*       @param work_entry      – Local memory pointer to the work entry
*
*       @return     Zero on success, or negative error code on failure.
*
*******************************************************************************/
int sal_do_ramdisk_io(struct nvme_dev * dev,
                      uint64_t *        prp_list,
                      cvmx_wqe_tt *      work_entry)
{
    uint32_t opcode, result = 0;
    int32_t status;
    uint64_t total_xfer_bytes, no_lbas, lba_data_size;
    uint8_t *lba_address;
    struct nvme_dma dma_entry;
    struct context_struct *io_cmd_context = NULL;
    struct nvme_cmd cmd = work_entry->nvme_cmd;
    uint8_t flbas;
    struct completion_status_field cpl_entry = { 0 };
    uint64_t *compare_bufs;
    cvmx_dma_engine_buffer_t *dma_data_bufs = NULL;
    bool completion_on_err = true;
    uint64_t remaining_bytes, xfered_bytes;
    struct nvme_sub_queue *sq;

    cpl_entry.sct = SCT_GENERIC;
    cpl_entry.sc = INTERNAL_ERROR;
    
    // check ns id is valid
    if (!cmd.rw.nsid || cmd.rw.nsid > le32_cpu(dev->dev_config.id_ctrl.nn) ||
        !NSPACE(dev, cmd.rw.nsid)) {
        cpl_entry.sct = SCT_COMMAND;
        cpl_entry.sc = INVALID_NAMESPACE;
        cpl_entry.dnr = 1;
        
        goto cleanup;
    }

    flbas = NSPACE(dev, cmd.rw.nsid)->id_ns.flbas;
    sq = dev->queue->sq[work_entry->word3.qw3.sq_id];
    io_cmd_context = npl_fpa_alloc(dev, CONTEXT_STRUCT_IO_DMA_POOL);
    
    if (!io_cmd_context) {
        debug_printf(1, "Error: FPA alloc failed");
        goto cleanup;
    }
    memset(io_cmd_context, 0, sizeof(struct context_struct));
    work_entry->word5.u64 = (uint64_t)io_cmd_context;
    opcode = cmd.rw.opc;
    no_lbas = cmd.rw.len;
    lba_data_size = NSPACE(dev, cmd.rw.nsid)->id_ns.lbaf[flbas].lbads;
    lba_data_size = 1 << lba_data_size;
    total_xfer_bytes = no_lbas * lba_data_size;
    
    if (cmd.rw.slba + no_lbas > NSPACE(dev, cmd.rw.nsid)->disk_size) {
        debug_printf(1, "Error: LBA out of range");
        cpl_entry.sct = SCT_GENERIC;
        cpl_entry.sc = LBA_OUT_OF_RANGE;
        goto cleanup;
    }
    lba_address = NSPACE(dev, cmd.rw.nsid)->start_addr +
                  (cmd.rw.slba * NSPACE(dev, cmd.rw.nsid)->sector_size);
    memset(&dma_entry, 0, sizeof(struct nvme_dma));
    dma_entry.nbytes = total_xfer_bytes;
    dma_entry.lastptr.prp1 = cmd.rw.prp1;
    io_cmd_context->no_bytes_transd = total_xfer_bytes;
    if (prp_list == NULL) {
        dma_entry.trans_type.prp_mode = PRP_NOLIST;
        dma_entry.lastptr.prp2 = cmd.rw.prp2;
    } else {
        dma_entry.trans_type.prp_mode = PRP_LIST;
        dma_entry.lastptr.prp2 = (uint64_t)prp_list;
    }

    switch (opcode) {
    case nvme_cmd_read:
        dma_entry.src = (uint64_t)lba_address;
        dma_entry.dst = (uint64_t)NULL;
        dma_entry.trans_type.dma_mode = DMA_OUTBOUND;
        dma_entry.trans_type.cpl_transfer = 0;
        status = npl_dma_submit(dev, &dma_entry, work_entry);
        if (status == DMA_ERROR) {
            remaining_bytes = dma_entry.nbytes;
            debug_printf(1, "Error: I/O Read Cmd Data transfer has failed, %lu bytes left", remaining_bytes);
            cvmx_atomic_fetch_and_bset64_nosync(&sq->cmd_id_arr[LCMDID(work_entry)], 1);
            xfered_bytes = cvmx_atomic_fetch_and_add64((int64_t *)&(sq->cmd_id_arr[LCMDID(work_entry)]), 
                    (remaining_bytes << 1)); 
            xfered_bytes = (xfered_bytes & 0xFFFFFFFF) >> 1;
            xfered_bytes += remaining_bytes;
            if (xfered_bytes < total_xfer_bytes) {
                /* Let the completion be posted once in flight dma's are done */
                completion_on_err = false;
                npl_fpa_free((uint64_t *)work_entry->word5.u64,
                        CONTEXT_STRUCT_IO_DMA_POOL,
                        sizeof(struct context_struct));
                io_cmd_context = NULL;
            } else {
                cvmx_atomic_fetch_and_bclr64_nosync(&sq->cmd_id_arr[LCMDID(work_entry)], 1);
            }
            cpl_entry.sct = SCT_GENERIC;
            cpl_entry.sc = INTERNAL_ERROR;
            goto cleanup;
        }
        break;

    case nvme_cmd_write:
        dma_entry.src = (uint64_t)NULL;
        dma_entry.dst = (uint64_t)lba_address;
        dma_entry.trans_type.dma_mode = DMA_INBOUND;
        dma_entry.trans_type.cpl_transfer = 0;
        status = npl_dma_submit(dev, &dma_entry, work_entry);
        if (status == DMA_ERROR) {
            remaining_bytes = dma_entry.nbytes;
            debug_printf(1, "Error: I/O Write Cmd Data transfer has failed, %lu bytes left", 
                    remaining_bytes);
            
            cvmx_atomic_fetch_and_bset64_nosync(&sq->cmd_id_arr[LCMDID(work_entry)], 1);
            xfered_bytes = cvmx_atomic_fetch_and_add64((int64_t *)&(sq->cmd_id_arr[LCMDID(work_entry)]), 
                    (remaining_bytes << 1)); 
            xfered_bytes = (xfered_bytes & 0xFFFFFFFF) >> 1;
            xfered_bytes += remaining_bytes;
            if (xfered_bytes < total_xfer_bytes) {
                /* Let the completion be posted once in flight dma's are done */
                completion_on_err = false;
                npl_fpa_free((uint64_t *)work_entry->word5.u64,
                        CONTEXT_STRUCT_IO_DMA_POOL,
                        sizeof(struct context_struct));
                io_cmd_context = NULL;
            } else {
                cvmx_atomic_fetch_and_bclr64_nosync(&sq->cmd_id_arr[LCMDID(work_entry)], 1);
            }
            cpl_entry.sct = SCT_GENERIC;
            cpl_entry.sc = INTERNAL_ERROR;
            goto cleanup;
        }
        break;

    case nvme_cmd_flush:
        cpl_entry.sct = SCT_GENERIC;
        cpl_entry.sc = CMD_SUCCESSFUL;
        cpl_entry.m = 0;
        cpl_entry.dnr = 0;
        result = 0;
        npl_submit_completion_entry(dev, work_entry, result, cpl_entry);
        break;

    case nvme_cmd_compare:
        {
            uint32_t num_st_ptrs, i;

            num_st_ptrs = total_xfer_bytes / FPA_DATA_BUF_POOL_SIZE;
            if (total_xfer_bytes % FPA_DATA_BUF_POOL_SIZE)
                num_st_ptrs++;

            compare_bufs = cvmx_fpa_alloc(FPA_DATA_BUF_POOL);

            if (!compare_bufs) {
                debug_printf(1, "Error: io_cmd_context->compare_bufs"
                        " Mem alloc failed\n");
                goto cleanup;
            }

            debug_printf(3, "Total compare bytes %lu, prp_list %p,"
                    " mode %d", total_xfer_bytes, prp_list,
                    dma_entry.trans_type.prp_mode);

            io_cmd_context->compare_buff = (uint64_t *)
                cvmx_ptr_to_phys(compare_bufs);

            for (i = 0; i < num_st_ptrs; i++) {
                compare_bufs[i] = cvmx_ptr_to_phys(
                        cvmx_fpa_alloc(FPA_DATA_BUF_POOL));
                if (!compare_bufs[i]) {
                    debug_printf(1, "DMA Local buffers alloc failed\n");
                    io_cmd_context->num_comp_bufs = i;
                    goto cleanup;
                }
            }

            io_cmd_context->num_comp_bufs = num_st_ptrs;

            if (num_st_ptrs > 1) {
                dma_data_bufs = cvmx_fpa_alloc(FPA_DATA_BUF_POOL);

                if (!dma_data_bufs) {
                    debug_printf(1, "Error: dma_data_bufs"
                            " Mem alloc failed\n");
                    goto cleanup;
                }
                for (i = 0; i < num_st_ptrs; i++) {
                    dma_data_bufs[i].u64 = 0;
                    dma_data_bufs[i].internal_cn78xx.addr =
                        compare_bufs[i];
                }
            }

            // Fill the virt addrs as it is used inSE
            work_entry->word5.u64 = (uint64_t)io_cmd_context;
            memset(&dma_entry, 0, sizeof(struct nvme_dma));
            dma_entry.nbytes = total_xfer_bytes;
            dma_entry.lastptr.prp1 = cmd.rw.prp1;
            io_cmd_context->no_bytes_transd = total_xfer_bytes;

            if (prp_list == NULL) {
                dma_entry.trans_type.prp_mode = PRP_NOLIST;
                dma_entry.lastptr.prp2 = cmd.rw.prp2;
            } else {
                dma_entry.trans_type.prp_mode = PRP_LIST;
                dma_entry.lastptr.prp2 = (uint64_t)prp_list;
            }

            work_entry->word1.qw1.tag =
                (IO_DATA_TRANSFER_TAG << NQM_TAG_SHIFT) |
                (work_entry->word3.qw3.sq_id << NQM_QID_SHIFT) |
                dev->pfvf;
            work_entry->word1.qw1.tt = CVMX_POW_TAG_TYPE_ORDERED;
            work_entry->word3.qw3.vf = dev->pfvf;

            if (num_st_ptrs == 1) {
                lba_address = cvmx_phys_to_ptr(
                        (uint64_t)compare_bufs[0]);
                num_st_ptrs = 0;
            } else
                lba_address = (uint8_t *)compare_bufs;

            if (num_st_ptrs) {
                /* Send DMA data bufs */
                lba_address = (uint8_t *)dma_data_bufs;
                dma_entry.trans_type.dma_buffer_type = 1;
                dma_entry.next_free_segment = 0;
            }
            debug_printf(3, "Compare data xfer bytes %lu, prp_list %p,"
                    " mode %d", total_xfer_bytes, prp_list,
                    dma_entry.trans_type.prp_mode);

            dma_entry.src = (uint64_t)NULL;
            dma_entry.dst = (uint64_t)lba_address;
            dma_entry.trans_type.num_st_ptrs = num_st_ptrs;
            dma_entry.trans_type.dma_mode = DMA_INBOUND;
            dma_entry.trans_type.cpl_transfer = 0;
            status = npl_dma_submit(dev, &dma_entry, work_entry);
            if (dma_data_bufs)
                cvmx_fpa_free(dma_data_bufs, FPA_DATA_BUF_POOL, 0);
            dma_data_bufs = NULL;

            if (status == DMA_ERROR) {
                remaining_bytes = dma_entry.nbytes;
                debug_printf(1, "Error: I/O Compare Data"
                        "transfer has failed, %lu bytes left", remaining_bytes);
                cvmx_atomic_fetch_and_bset64_nosync(&sq->cmd_id_arr[LCMDID(work_entry)], 1);
                xfered_bytes = cvmx_atomic_fetch_and_add64((int64_t *)&(sq->cmd_id_arr[LCMDID(work_entry)]), 
                                                            (remaining_bytes << 1)); 
                xfered_bytes = (xfered_bytes & 0xFFFFFFFF) >> 1;
                xfered_bytes += remaining_bytes;
                if (xfered_bytes < total_xfer_bytes) {
                    /* Let the completion be posted once in flight dma's are done */
                    completion_on_err = false;
                    npl_fpa_free((uint64_t *)work_entry->word5.u64,
                            CONTEXT_STRUCT_IO_DMA_POOL,
                            sizeof(struct context_struct));
                    io_cmd_context = NULL;
                } else {
                    cvmx_atomic_fetch_and_bclr64_nosync(&sq->cmd_id_arr[LCMDID(work_entry)], 1);
                }
                cpl_entry.sct = SCT_GENERIC;
                cpl_entry.sc = INTERNAL_ERROR;
                goto cleanup;
            }
            break;
        }
    default:
        debug_printf(1, "Error: Unknown Command. Not Supported");
        cpl_entry.sct = SCT_GENERIC;
        cpl_entry.sc = INVALID_OPCODE;
        goto cleanup;
    }
    
    return STATUS_SUCCESS;

cleanup:
    if (dma_data_bufs)
        cvmx_fpa_free(dma_data_bufs, FPA_DATA_BUF_POOL, 0);

    npl_helper_free_context(io_cmd_context);

    if (completion_on_err)
        npl_submit_completion_entry(dev, work_entry, result, cpl_entry);

    npl_helper_cleanup_fused_cmd(dev, work_entry);

    /*
     * Since this is called by sal_do_data_transfer(), 
     * we need to consume the wqe  in error cases as well
     **/
    npl_fpa_free(work_entry, CVMX_FPA_WQE_POOL,
            sizeof(cvmx_wqe_t));
    return STATUS_ERROR;
}

/***************************************************************************//**
*
*    sal_complete_ramdisk_io
*
*    This function will process the compare and fused command
*
*         @param dev  Pointer to the device structure
*         @param wqe_io   Work queue pointer
*
*
*******************************************************************************/
int sal_complete_ramdisk_io(struct nvme_dev *  dev,
                             cvmx_wqe_tt *       wqe_io)
{
    uint64_t total_xfer_bytes, *src1, *src2;
    uint8_t opcode, flbas, mismatch = 0, *lba_address;
    uint8_t fused_flag = 0;
    uint32_t result = 0, nsid;
    uint16_t no_lbas;
    struct nvme_sub_queue *sq;
    struct completion_status_field cpl_entry = { 0 };
    struct context_struct *io_cmd_context =
        (struct context_struct *)wqe_io->word5.u64;
    struct nvme_cmd *nvme_cmd = &(wqe_io->nvme_cmd);
    struct nvme_cmd fused_first_cmd;
    cvmx_wqe_tt *fused_second_cmd_wqe;
    uint64_t lba_data_size;
    uint64_t *data_bufs;
    uint32_t num_st_ptrs;
    uint64_t *compare_bufs;
    uint64_t i, j, remaning_bytes;

    cpl_entry.sct = SCT_GENERIC;
    cpl_entry.sc = INTERNAL_ERROR;
    
    nsid = nvme_cmd->rw.nsid;
    // check ns id is valid
    if (!nsid || nsid > le32_cpu(dev->dev_config.id_ctrl.nn) ||
        !NSPACE(dev, nsid)) {
        cpl_entry.sct = SCT_COMMAND;
        cpl_entry.sc = INVALID_NAMESPACE;
        cpl_entry.dnr = 1;

        goto cleanup;
    }
    no_lbas = nvme_cmd->rw.len;
    flbas = NSPACE(dev, nsid)->id_ns.flbas & 0x0f;
    lba_address =
        (uint8_t *)(NSPACE(dev, nsid)->start_addr +
                    (nvme_cmd->rw.slba * NSPACE(dev, nsid)->sector_size));
    lba_data_size = 1 << NSPACE(dev, nsid)->id_ns.lbaf[flbas].lbads;
    sq = dev->queue->sq[wqe_io->word3.qw3.sq_id];
    opcode = nvme_cmd->rw.opc;
    if (opcode == nvme_cmd_compare) {

        total_xfer_bytes = no_lbas * lba_data_size;
        num_st_ptrs = total_xfer_bytes / FPA_DATA_BUF_POOL_SIZE;
        if (total_xfer_bytes % FPA_DATA_BUF_POOL_SIZE)
            num_st_ptrs++;

        /* Allocate a buffer to read data from the specified LBA */
        data_bufs = cvmx_fpa_alloc(FPA_DATA_BUF_POOL);
        if (!data_bufs) {
            debug_printf(1, "Error: io_cmd_context->data_bufs"
                    " Mem alloc failed\n");
            goto cleanup;
        }

        io_cmd_context->data_bufs = (uint64_t *)
            cvmx_ptr_to_phys(data_bufs);

        for (i = 0; i < num_st_ptrs; i++) {
            data_bufs[i] = cvmx_ptr_to_phys(
                    cvmx_fpa_alloc(FPA_DATA_BUF_POOL));
            if (!data_bufs[i]) {
                debug_printf(1, "DMA Local buffers alloc failed\n");
                io_cmd_context->num_data_bufs = i;
                goto cleanup;
            }
        }
    
        io_cmd_context->num_data_bufs = num_st_ptrs;

        /* Get data from the specified LBA */
        remaning_bytes = total_xfer_bytes;

        for (i = 0; i < num_st_ptrs; i++) {
            j = FPA_DATA_BUF_POOL_SIZE;
            if (j > remaning_bytes)
                j = remaning_bytes;

            memcpy(cvmx_phys_to_ptr(data_bufs[i]), (lba_address + i*FPA_DATA_BUF_POOL_SIZE), j); 
            remaning_bytes -= j;
        }

        /* comparing the data */
        remaning_bytes = total_xfer_bytes;

        compare_bufs = cvmx_phys_to_ptr((uint64_t)io_cmd_context->compare_buff);

        for (i = 0; i < num_st_ptrs; i++) {
            src1 = (uint64_t *)cvmx_phys_to_ptr(compare_bufs[i]);
            src2 = (uint64_t *)cvmx_phys_to_ptr(data_bufs[i]);

            j = FPA_DATA_BUF_POOL_SIZE;
            while (remaning_bytes && j) {

                if (*src1 != *src2) {
                    mismatch = 1;
                    break;
                }
                src1++;
                src2++;

                j -= 8;
                remaning_bytes -= 8;
            }
            if (mismatch)
                break;
        }
        
        wqe_io->word5.u64 = 0;
        npl_helper_free_context(io_cmd_context);
        io_cmd_context = NULL;

        if (mismatch) {
            /* Compare failed */
            cpl_entry.sct = SCT_MEDIA;
            cpl_entry.sc = COMPARE_FAILURE;
            goto cleanup;

        } else {
            /* The comparison is successful */
            fused_first_cmd = wqe_io->nvme_cmd;
            fused_flag = fused_first_cmd.common.flags;
            cvmx_atomic_set64(((int64_t *)&(sq->cmd_id_arr[LCMDID(wqe_io)])), 0);
            /* complete the compare command */
            cpl_entry.sct = SCT_GENERIC;
            cpl_entry.sc = CMD_SUCCESSFUL;
            npl_submit_completion_entry(dev, wqe_io, result, cpl_entry);

            /* Check for the fused operation flag */
            if (fused_flag == fused_first_command) {
                /* Get the fused_second_command to the nvme_cmd field of the WQE */
                fused_second_cmd_wqe = (cvmx_wqe_tt *)wqe_io->word6.u64;
                memcpy((void *)wqe_io, fused_second_cmd_wqe, sizeof(cvmx_wqe_t));
                npl_fpa_free(fused_second_cmd_wqe, CVMX_FPA_WQE_POOL, sizeof(cvmx_wqe_t));
                wqe_io->word6.u64 = 0;
                wqe_io->nvme_cmd.common.flags = 0;

                /* Check the LBA ranges of the fused commands */
                if (fused_first_cmd.rw.slba != wqe_io->nvme_cmd.rw.slba ||
                    fused_first_cmd.rw.len != wqe_io->nvme_cmd.rw.len) {
                    /* Different LBA ranges, fail the commands with status 'Invalid Field in Command' */
                    cpl_entry.sct = SCT_GENERIC;
                    cpl_entry.sc = INVALID_FIELD_CMD;
                    goto cleanup;
                } else {
                    /* process the fused second command */
                    npl_process_io_request(dev, wqe_io);
                }
            }
        }
    } else {
        /* update cpl_entry with appropriate values */
        cpl_entry.sct = SCT_GENERIC;
        cpl_entry.sc = CMD_SUCCESSFUL;
        cpl_entry.m = 0;
        cpl_entry.dnr = 0;
        result = 0;
        npl_submit_completion_entry(dev, wqe_io, result, cpl_entry);
    }

    npl_helper_free_context(io_cmd_context);
    
    /* Here caller will take care of freeing wqe */
    return 0;

cleanup:
    npl_helper_free_context(io_cmd_context);

    npl_submit_completion_entry(dev, wqe_io, result, cpl_entry);

    /* Cleanup fused second cmd */
    npl_helper_cleanup_fused_cmd(dev, wqe_io);

    /* Here caller will take care of freeing wqe */
    return -1;
}

/***************************************************************************//**
*
*    sal_storage_initialize
*
*    This function initializes a dev struct to connect to its assigned
*    namespaces.
*
*         @param dev            Pointer to device structure nvme_dev
*
*         @return Zero on success, or negative error code on failure.
*
*******************************************************************************/
int sal_storage_initialize(struct nvme_dev *dev)
{
    uint32_t i;
    uint32_t ns;
    int nsc;

    // clear namespace table in controller
    for (i = 0; i < MAX_NUMBER_NS_CTLR; i++) dev->disk_dev.ns_dir[i] = 0;
    nsc = 0; // clear namespace count

    if (ns_map_policy == MAP_ONE_TO_ALL) {
        for (i = 0; i < MAX_NUMBER_NS; i++) {
            if (sal_namespaces[i]) {
                dev->disk_dev.ns_dir[i] = sal_namespaces[i];
                // place I/O vectors
                if (dev->disk_dev.ns_dir[i]->ns_type == NS_RAMDISK) {
                    dev->disk_dev.io_handler[i].sal_do_io = sal_do_ramdisk_io;
                    dev->disk_dev.io_handler[i].sal_complete_io = sal_complete_ramdisk_io;
                } else {
                    dev->disk_dev.io_handler[i].sal_do_io = sal_do_oct_linux_bdev_io;
                    dev->disk_dev.io_handler[i].sal_complete_io = sal_complete_oct_linux_bdev_io;
                }
                nsc++;
                if (nsc >= MAX_NUMBER_NS_CTLR)
                    break;
            }
            if (ns_sata_only_map && i > (uint32_t) (glb_bdev_list.num_bdevs-1))
                break;
        }
    } else if (ns_map_policy == MAP_ONE_TO_ONE) {
        if (sal_namespaces[dev->pfvf]) {
            dev->disk_dev.ns_dir[0] = sal_namespaces[dev->pfvf];
            // place I/O vectors
            if (dev->disk_dev.ns_dir[0]->ns_type == NS_RAMDISK) {
                dev->disk_dev.io_handler[0].sal_do_io = sal_do_ramdisk_io;
                dev->disk_dev.io_handler[0].sal_complete_io = sal_complete_ramdisk_io;
            } else {
                dev->disk_dev.io_handler[0].sal_do_io = sal_do_oct_linux_bdev_io;
                dev->disk_dev.io_handler[0].sal_complete_io = sal_complete_oct_linux_bdev_io;
            }
            nsc++;
        }
    } else {
        // assign namespaces from cat table
        for (i = 0; i < MAX_NUMBER_NS_CTLR; i++) {
            ns = ns_cat[dev->pfvf][i]; // get namespace candidate
            if (ns) { // this namespace is active
                dev->disk_dev.ns_dir[i] = sal_namespaces[ns-1];
                // place I/O vectors
                if (dev->disk_dev.ns_dir[i]->ns_type == NS_RAMDISK) {
                    dev->disk_dev.io_handler[i].sal_do_io = sal_do_ramdisk_io;
                    dev->disk_dev.io_handler[i].sal_complete_io = sal_complete_ramdisk_io;
                } else {
                    dev->disk_dev.io_handler[i].sal_do_io = sal_do_oct_linux_bdev_io;
                    dev->disk_dev.io_handler[i].sal_complete_io = sal_complete_oct_linux_bdev_io;
                }
                nsc++; // count namespaces
            }
        }
    }

    // place namespace count in LE format
    dev->dev_config.id_ctrl.nn = le32_cpu(nsc);

    return STATUS_SUCCESS;
}


/***************************************************************************//**
*
*    ns_init
*
*    Associates a namespace with its storage method. In this case, it is a
*    ramdisk.
*
*         @return Zero on success, or negative error code on failure.
*
*******************************************************************************/

int sal_init_store(struct ns_ctrl* ns)

{
	if (ns_share[ns->ns_id] && sal_namespaces[ns_share[ns->ns_id]] &&
	    sal_namespaces[ns_share[ns->ns_id]]->sector_size*
	    sal_namespaces[ns_share[ns->ns_id]]->disk_size <=
	        ns->sector_size*ns->disk_size) {
		// assign this namespace as an alias
		ns->start_addr = sal_namespaces[ns_share[ns->ns_id]]->start_addr;
	} else {
		// allocate the ramdisk(s)
		ns->start_addr = cvmx_bootmem_alloc(ns->sector_size*
                                            ns->disk_size,
                                            CVMX_CACHE_LINE_SIZE);
		if (ns->start_addr == NULL) {
			debug_printf(1,
				"Error: ramdisk memory allocation failed, allocation: %ld",
				ns->sector_size*
			ns->disk_size);
			return -1;

		}
		// clear it out to zeros
		memset(ns->start_addr, 0, ns->sector_size*ns->disk_size);
	}

	return 0;

}

/***************************************************************************//**
*
*    sal_init
*
*    sal module initialize. Allocates space for the entries in the namespace
*    table. The namespace descriptors are kept both as a constant table and as
*    a ram based table, and the constant table is copied to the ram table. The
*    idea is that the NS entries will be edited or created from scratch at
*    some point. If that is not needed, then the constant definitions can be
*    used, and the ram based descriptions discarded.
*
*         @return Zero on success, or negative error code on failure.
*
*******************************************************************************/

int sal_init(void)
{
	int i;
	int ret;

	// clear spare entries in table
	for (i = 0; i < MAX_NUMBER_NS; i++) sal_namespaces[i] = 0;

	if (ns_sata_only_map) {
		debug_printf(1, "Presenting Linux block disks alone as NVMe name spaces");
		return 0;
	}

	// load table from constant table and allocate ramdisk
	for (i = 0; i < MAX_NUMBER_NS; i++) {
		// if we reach the end of the table, terminate
		if (!sal_namespace_tbl[i].sector_size) break;

		sal_namespace_tbl[i].disk_size =
			le64_cpu(sal_namespace_tbl[i].id_ns.nsze, ull);
		// get namespace control structure
		sal_namespaces[i] = findalloc(ns_ctrl, i, CVMX_CACHE_LINE_SIZE);
		if (!sal_namespaces[i]) {
			debug_printf(1, "Cannot allocate namespace structure");

			return -1;
		}
		sal_namespaces[i]->ns_id = i+1; // set logical namespace id
		// copy config data into place
		memcpy(sal_namespaces[i], &(sal_namespace_tbl[i]), sizeof(struct ns_ctrl));

		// assocate storage
		ret = sal_init_store(sal_namespaces[i]);
		if (ret < 0) return ret;
	}

	return 0;
}
