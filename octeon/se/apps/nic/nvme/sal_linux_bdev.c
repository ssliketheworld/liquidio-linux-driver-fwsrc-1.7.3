#include "nvme_cvm.h"
#include "sal_linux_bdev.h"

extern CVMX_SHARED struct nvme_dev *nqm_device_structs[NVME_NUM_PFVF];
extern CVMX_SHARED struct ns_ctrl *ns_ctrl_base;
extern uint32_t ns_cat[NVME_NUM_PFVF][MAX_NUMBER_NS_CTLR];
extern uint32_t ns_share[MAX_NUMBER_NS];
extern struct ns_ctrl sal_namespace_tbl[];
extern CVMX_SHARED struct ns_ctrl * sal_namespaces[MAX_NUMBER_NS];

#define TO_LINUX_GROUP 63
int
sal_send_work_to_octlinux(cvmx_wqe_tt* wqe)
{
	npl_setup_wqe(wqe);

	cvmx_wqe_set_xgrp((cvmx_wqe_t *)wqe, TO_LINUX_GROUP);

	cvmx_pow_work_submit_node((cvmx_wqe_t *)wqe, wqe->word1.qw1.tag,
		CVMX_POW_TAG_TYPE_ORDERED,
		cvmx_wqe_get_xgrp((cvmx_wqe_t *)wqe),
		cvmx_get_node_num());

	return 0;
}

int sal_complete_oct_linux_bdev_io(
	struct nvme_dev *dev, cvmx_wqe_tt *wqe)
{
	uint32_t opcode, tag;
	struct nvme_cmd_rw rw_cmd;
	cvmx_wqe_tt *new_wqe;
	struct context_struct *io_cmd_context = NULL;
	struct completion_status_field cpl_entry={0};
	uint32_t result, num_st_ptrs, i;
	struct nvme_sub_queue *sq;

	cpl_entry.sct = SCT_GENERIC;
	cpl_entry.sc = INTERNAL_ERROR;
	cpl_entry.m = 0;
	cpl_entry.dnr = 0;
	result = 0;
	
	rw_cmd = wqe->nvme_cmd.rw;
	opcode = rw_cmd.opc;
	
	io_cmd_context = (struct context_struct *)wqe->word5.u64;
	sq = dev->queue->sq[wqe->word3.qw3.sq_id];

	switch (opcode) {
	case nvme_cmd_read:
	{
		npl_helper_free_context(io_cmd_context);
		io_cmd_context = NULL;

		cpl_entry.sct = SCT_GENERIC;
		cpl_entry.sc = CMD_SUCCESSFUL;
		cpl_entry.m = 0;
		cpl_entry.dnr = 0;
		result = 0;
		npl_submit_completion_entry(
			dev, wqe, result, cpl_entry);
		break;
	}

	case nvme_cmd_write:
	{
		new_wqe = npl_fpa_alloc(dev, CVMX_FPA_WQE_POOL);
		if (!new_wqe) {
			printf("%s: wqe allocation failed\n", __func__);
			goto cleanup;
		}

		memset(new_wqe, 0, sizeof(cvmx_wqe_t));
		memcpy(new_wqe, wqe, sizeof(cvmx_wqe_t));
		npl_setup_wqe(new_wqe);
		// Fill phys addr as wqe is going to linux
		new_wqe->word5.u64 = cvmx_ptr_to_phys((void *)
			new_wqe->word5.u64);

		tag = (MSG_TO_OCTLINUX_TAG << NQM_TAG_SHIFT) |
			(CVM_BDEV_LINUX_WR_CMND << NQM_QID_SHIFT);

		cvmx_wqe_set_tag((cvmx_wqe_t *)new_wqe, tag);
		sal_send_work_to_octlinux(new_wqe);
		break;
	}
	case nvme_cmd_compare:
	{
		uint64_t *src1, *src2;
		uint32_t no_lbas, j;
		uint64_t lba_data_size, flbas, compare_bytes;
		struct nvme_cmd fused_first_cmd;
		uint8_t mismatch = 0, fused_flag = 0;
		uint64_t *data_bufs = NULL, *compare_bufs = NULL;
		cvmx_wqe_tt *fused_second_cmd_wqe;


		num_st_ptrs = io_cmd_context->num_comp_bufs;
		opcode = rw_cmd.opc;
		no_lbas = rw_cmd.len;
		flbas = NSPACE(dev, rw_cmd.nsid)->id_ns.flbas;
		lba_data_size = NSPACE(dev, rw_cmd.nsid)->id_ns.lbaf[flbas].lbads;
		lba_data_size = 1 << lba_data_size;
		compare_bytes = no_lbas * lba_data_size;

		data_bufs = cvmx_phys_to_ptr((uint64_t)io_cmd_context->data_bufs);
		compare_bufs = cvmx_phys_to_ptr((uint64_t)io_cmd_context->compare_buff);
		
		for (i = 0; i < num_st_ptrs; i++) {
			src1 = (uint64_t *)cvmx_phys_to_ptr(compare_bufs[i]);
			src2 = (uint64_t *)cvmx_phys_to_ptr(data_bufs[i]);

			j = FPA_DATA_BUF_POOL_SIZE;
			while (compare_bytes && j) {

				if (*src1 != *src2) {
					mismatch = 1;
					break;
				}
				src1++;
				src2++;

				j -= 8;
				compare_bytes -= 8;
			}
			if (mismatch)
				break;
		}
		
		wqe->word5.u64 = 0;
		npl_helper_free_context(io_cmd_context);
		io_cmd_context = NULL;
        
		if (mismatch) {
			/* Compare failed */
			cpl_entry.sct = SCT_MEDIA;
			cpl_entry.sc = COMPARE_FAILURE;
			goto cleanup;
		} else {
			/* The comparison is successful */
			fused_first_cmd = wqe->nvme_cmd;
			fused_flag = fused_first_cmd.common.flags;
			cvmx_atomic_set64(((int64_t *)&(sq->cmd_id_arr[LCMDID(wqe)])), 0);
			/* complete the compare command */
			cpl_entry.sct = SCT_GENERIC;
			cpl_entry.sc = CMD_SUCCESSFUL;
			cpl_entry.m = 0;
			cpl_entry.dnr = 0;
			result = 0;
			npl_submit_completion_entry(dev, wqe, result, cpl_entry);
			/* Check for the fused operation flag */
			if (fused_flag == fused_first_command) {
				/* Get the fused_second_command to the nvme_cmd field of the WQE */
				fused_second_cmd_wqe = (cvmx_wqe_tt *)wqe->word6.u64;
				memcpy((void *)wqe, fused_second_cmd_wqe, sizeof(cvmx_wqe_t));
				npl_fpa_free(fused_second_cmd_wqe, CVMX_FPA_WQE_POOL, sizeof(cvmx_wqe_t));
				wqe->word6.u64 = 0;
				wqe->nvme_cmd.common.flags = 0;

				/* Check the LBA ranges of the fused commands */
				if (fused_first_cmd.rw.slba != wqe->nvme_cmd.rw.slba ||
						fused_first_cmd.rw.len != wqe->nvme_cmd.rw.len) {
					/* Different LBA ranges, fail the commands with status 'Invalid Field in Command' */
					cpl_entry.sct = SCT_GENERIC;
					cpl_entry.sc = INVALID_FIELD_CMD;
					goto cleanup;
				} else {
					/* process the fused second command */
					npl_process_io_request(dev, wqe);
				}
			}
		}

		break;
	}
	default:
		printf("%s: Error !!! Default switch case\n", __func__);
		goto cleanup;
	}

	/* Caller takes care of wqe freeing */
	return 0;
cleanup:
	npl_helper_free_context(io_cmd_context);
	
	npl_submit_completion_entry(
		dev, wqe, result, cpl_entry);
	
	/* Cleanup fused second cmd */
	npl_helper_cleanup_fused_cmd(dev, wqe);

	/* Caller takes care of wqe freeing */
	return STATUS_ERROR;
}



/* Handle I/O requests from NVMe SE for octeon linux block devices
 * Based on sal_do_ramdisk_io.
 */
int sal_do_oct_linux_bdev_io(
	struct nvme_dev *dev, uint64_t * prp_list, cvmx_wqe_tt *wqe)
{
	struct context_struct *io_cmd_context = NULL;
	cvm_bdev_info_t *bdev_info;
	uint32_t opcode, no_lbas, result = 0, tag;
	struct nvme_cmd_rw rw_cmd;
	uint64_t lba_data_size, flbas, total_xfer_bytes;
	struct completion_status_field cpl_entry={0};
	uint8_t *lba_address = NULL;
	uint32_t num_st_ptrs, i;
	uint64_t *data_bufs = NULL;
	cvmx_dma_engine_buffer_t *dma_data_bufs = NULL;
	struct nvme_dma dma_entry;
	int status = 0;
	bool completion_on_err = true;
	uint64_t remaining_bytes, xfered_bytes;
	struct nvme_sub_queue *sq;

	rw_cmd = wqe->nvme_cmd.rw;
	opcode = rw_cmd.opc;


	cpl_entry.sct = SCT_GENERIC;
	cpl_entry.sc = INTERNAL_ERROR;
	
	io_cmd_context = npl_fpa_alloc(dev, CONTEXT_STRUCT_IO_DMA_POOL);
	if (!io_cmd_context) {
		debug_printf(1, "FPA alloc failed");
		goto cleanup;
	}
	memset(io_cmd_context, 0, sizeof(struct context_struct));

	opcode = rw_cmd.opc;
	no_lbas = rw_cmd.len;
	flbas = NSPACE(dev, rw_cmd.nsid)->id_ns.flbas;
	lba_data_size = NSPACE(dev, rw_cmd.nsid)->id_ns.lbaf[flbas].lbads;
	lba_data_size = 1 << lba_data_size;
	total_xfer_bytes = no_lbas * lba_data_size;
	sq = dev->queue->sq[wqe->word3.qw3.sq_id];

	if (rw_cmd.slba + no_lbas > NSPACE(dev, rw_cmd.nsid)->disk_size) {
		debug_printf(1, "Error: LBA out of range");
		cpl_entry.sct = SCT_GENERIC;
		cpl_entry.sc = LBA_OUT_OF_RANGE;
		goto cleanup;
	}

	bdev_info = (cvm_bdev_info_t *)NSPACE(dev, rw_cmd.nsid)->bdev_info;
	if (bdev_info == NULL) {
		debug_printf(1, "Error: BDEV info is NULL");
		goto cleanup;
	}

	io_cmd_context->prp_list = prp_list;
	io_cmd_context->bdev_info = *bdev_info;
	
	if (opcode == nvme_cmd_flush)
		goto next;
	
	num_st_ptrs = total_xfer_bytes / FPA_DATA_BUF_POOL_SIZE;
	if (total_xfer_bytes % FPA_DATA_BUF_POOL_SIZE)
		num_st_ptrs++;

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

next:
	
	switch (opcode) {
	case nvme_cmd_read:
		// Fill the phy addrs as it is going to linux
		wqe->word5.u64 = cvmx_ptr_to_phys(io_cmd_context);
		
		tag = (MSG_TO_OCTLINUX_TAG << NQM_TAG_SHIFT) |
			(CVM_BDEV_LINUX_RD_CMND << NQM_QID_SHIFT);

		cvmx_wqe_set_tag((cvmx_wqe_t *)wqe, tag);
		sal_send_work_to_octlinux(wqe);

		break;
	case nvme_cmd_write:
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
					data_bufs[i];
			}
		}
		// Fill the virt addrs as it is used inSE
		wqe->word5.u64 = (uint64_t)io_cmd_context;
		memset(&dma_entry, 0, sizeof(struct nvme_dma));
		dma_entry.nbytes = total_xfer_bytes;
		dma_entry.lastptr.prp1 = rw_cmd.prp1;
		io_cmd_context->no_bytes_transd = total_xfer_bytes;
		if (prp_list == NULL) {
			dma_entry.trans_type.prp_mode = PRP_NOLIST;
			dma_entry.lastptr.prp2 = rw_cmd.prp2;
		} else {
			dma_entry.trans_type.prp_mode = PRP_LIST;
			dma_entry.lastptr.prp2 = (uint64_t)prp_list;
		}

		if (num_st_ptrs == 1) {
			lba_address = cvmx_phys_to_ptr(
				(uint64_t)data_bufs[0]);
			num_st_ptrs = 0;
		} else
			lba_address = (uint8_t *)data_bufs;

		if (num_st_ptrs) {
			/* Send DMA data bufs */
			lba_address = (uint8_t *)dma_data_bufs;
			dma_entry.trans_type.dma_buffer_type = 1;
			dma_entry.next_free_segment = 0;
		}
		debug_printf(3, "Total xfer bytes %lu, prp_list %p,"
			" mode %d", total_xfer_bytes, prp_list,
			dma_entry.trans_type.prp_mode);


		dma_entry.src = (uint64_t)NULL;
		dma_entry.dst = (uint64_t)lba_address;
		dma_entry.trans_type.num_st_ptrs = num_st_ptrs;
		dma_entry.trans_type.dma_mode = DMA_INBOUND;
		dma_entry.trans_type.cpl_transfer = 0;
		status = npl_dma_submit(dev, &dma_entry, wqe);
		if (dma_data_bufs)
			cvmx_fpa_free(dma_data_bufs, FPA_DATA_BUF_POOL, 0);
		dma_data_bufs = NULL;

		if (status == DMA_ERROR) {
			remaining_bytes = dma_entry.nbytes;
			debug_printf(1, "Error: I/O Write Cmd Data"
				"transfer has failed, %lu bytes left", remaining_bytes);
			cvmx_atomic_fetch_and_bset64_nosync(&sq->cmd_id_arr[LCMDID(wqe)], 1);
			xfered_bytes = cvmx_atomic_fetch_and_add64((int64_t *)&(sq->cmd_id_arr[LCMDID(wqe)]), 
					(remaining_bytes << 1)); 
			xfered_bytes = (xfered_bytes & 0xFFFFFFFF) >> 1;
			xfered_bytes += remaining_bytes;
			if (xfered_bytes < total_xfer_bytes) {
				/* Let the completion be posted once in flight dma's are done */
				completion_on_err = false;
				npl_fpa_free((uint64_t *)wqe->word5.u64,
						CONTEXT_STRUCT_IO_DMA_POOL,
						sizeof(struct context_struct));
				io_cmd_context = NULL;
			} else {
				cvmx_atomic_fetch_and_bclr64_nosync(&sq->cmd_id_arr[LCMDID(wqe)], 1);
			}
			cpl_entry.sct = SCT_GENERIC;
			cpl_entry.sc = INTERNAL_ERROR;
			goto cleanup;
		}

		break;
	case nvme_cmd_flush:
		// Fill the phy addrs as it is going to linux
		wqe->word5.u64 = cvmx_ptr_to_phys(io_cmd_context);
		
		tag = (MSG_TO_OCTLINUX_TAG << NQM_TAG_SHIFT) |
			(CVM_BDEV_LINUX_WR_CMND << NQM_QID_SHIFT);

		cvmx_wqe_set_tag((cvmx_wqe_t *)wqe, tag);
		sal_send_work_to_octlinux(wqe);

		break;
	case nvme_cmd_compare:
		{
			uint64_t *compare_bufs = NULL;
			// Pre allocate compare buf or return failure */

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

			// Fill the phy addrs as it is going to linux to fetch disk data
			wqe->word5.u64 = cvmx_ptr_to_phys(io_cmd_context);

			tag = (MSG_TO_OCTLINUX_TAG << NQM_TAG_SHIFT) |
				(CVM_BDEV_LINUX_RD_CMND << NQM_QID_SHIFT);

			cvmx_wqe_set_tag((cvmx_wqe_t *)wqe, tag);
			sal_send_work_to_octlinux(wqe);

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
		npl_submit_completion_entry(dev,
			wqe, result, cpl_entry);
	
	/* Cleanup fused second cmd */
	npl_helper_cleanup_fused_cmd(dev, wqe);

	/*	
	 *	Since this is called by sal_do_data_transfer(), 
	 *	we need to consume the wqe  in error cases as well
	 */
	npl_fpa_free(wqe, CVMX_FPA_WQE_POOL,
			sizeof(cvmx_wqe_t));

	return STATUS_ERROR;
}/* sal_do_oct_linux_bdev_io */

static int
sal_rdwr_bio_done_resp_handler(cvmx_wqe_tt *wqe)
{
	struct context_struct *io_cmd_context = NULL;
	struct nvme_cmd cmd = wqe->nvme_cmd;
	uint64_t *prp_list = NULL;
	uint64_t *data_bufs = NULL;
	uint32_t result = 0;
	uint8_t *lba_address = NULL;
	uint32_t opcode;
	uint64_t no_lbas, lba_data_size, flbas, total_xfer_bytes;
	struct nvme_dma dma_entry;
	struct completion_status_field cpl_entry={0};
	struct nvme_dev *dev = NULL;
	uint32_t num_st_ptrs = 0, i;
	int status;
	cvmx_wqe_tt *new_wqe = NULL;
	cvmx_dma_engine_buffer_t *dma_data_bufs = NULL;
	bool completion_on_err = true;
	uint64_t remaining_bytes, xfered_bytes;
	struct nvme_sub_queue *sq;

	dev = nqm_device_structs[wqe->word3.qw3.vf];

	wqe->word5.u64 = (uint64_t)
		cvmx_phys_to_ptr((uint64_t)wqe->word5.u64);

	opcode = cmd.rw.opc;
	no_lbas = cmd.rw.len;
	flbas = NSPACE(dev, cmd.rw.nsid)->id_ns.flbas;
	lba_data_size = NSPACE(dev, cmd.rw.nsid)->id_ns.lbaf[flbas].lbads;
	lba_data_size = 1 << lba_data_size;
	total_xfer_bytes = no_lbas * lba_data_size;
	sq = dev->queue->sq[wqe->word3.qw3.sq_id];

	cpl_entry.sct = SCT_GENERIC;
	cpl_entry.sc = INTERNAL_ERROR;

	io_cmd_context = (struct context_struct *)wqe->word5.u64;
	if (cmd.rw.slba + no_lbas > NSPACE(dev, cmd.rw.nsid)->disk_size) {
		debug_printf(1, "Error: LBA out of range");
		cpl_entry.sct = SCT_GENERIC;
		cpl_entry.sc = LBA_OUT_OF_RANGE;
		goto cleanup;
	}

	if (!io_cmd_context) {
		debug_printf(1, "Error: io_cmd_context missing");
		goto cleanup;
	}

	/* Check if error reported by octlinux */
	if (io_cmd_context->nvme_completion_sc != CMD_SUCCESSFUL) {
		debug_printf(1, "Error: IO error, lba %lu code 0x%x", 
				cmd.rw.slba, io_cmd_context->nvme_completion_sc);
		cpl_entry.sct = SCT_GENERIC;
		cpl_entry.sc = io_cmd_context->nvme_completion_sc;
		goto cleanup;
	}
	
	prp_list = io_cmd_context->prp_list;

	data_bufs = cvmx_phys_to_ptr((uint64_t)io_cmd_context->data_bufs);
	num_st_ptrs = io_cmd_context->num_data_bufs;
		
	switch (opcode) {
	case nvme_cmd_read:
	{
		if (!data_bufs) {
			debug_printf(1, "Error: io_cmd_context->data_bufs"
				" is NULL\n");
			goto cleanup;
		}

		if (num_st_ptrs > 1) {
			dma_data_bufs = cvmx_fpa_alloc(FPA_DATA_BUF_POOL);
			if (!dma_data_bufs) {
				printf("Error: dma_data_bufs alloc failed\n");
				goto cleanup;
			}
			for (i = 0; i < num_st_ptrs; i++) {
				dma_data_bufs[i].u64 = 0;
				dma_data_bufs[i].internal_cn78xx.addr =
					data_bufs[i];
			}
		}
		/* 
		 * Allocate new wqe as this function is not called 
		 * from sal_do_transfer() unlike others 
		 */
		new_wqe = npl_fpa_alloc(dev, CVMX_FPA_WQE_POOL);
		if (!new_wqe) {
			printf("%s: wqe allocation failed\n", __func__);
			goto cleanup;
		}

		memset(new_wqe, 0, sizeof(cvmx_wqe_t));
		memcpy(new_wqe, wqe, sizeof(cvmx_wqe_t));
		npl_setup_wqe(new_wqe);

		new_wqe->word1.qw1.tag =
			(IO_DATA_TRANSFER_TAG << NQM_TAG_SHIFT) |
			(new_wqe->word3.qw3.sq_id << NQM_QID_SHIFT) |
			dev->pfvf;
		new_wqe->word1.qw1.tt = CVMX_POW_TAG_TYPE_ORDERED;
		new_wqe->word3.qw3.vf = dev->pfvf;

		if (num_st_ptrs == 1) {
			lba_address = (uint8_t *)cvmx_phys_to_ptr(
				data_bufs[0]); //TODO
			num_st_ptrs = 0;
		} else
			lba_address = (uint8_t *)data_bufs;

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

		if (num_st_ptrs) {
			lba_address = (uint8_t *)dma_data_bufs;
			dma_entry.trans_type.dma_buffer_type = 1;
			dma_entry.next_free_segment = 0;
		}

		dma_entry.src = (uint64_t)lba_address;
		dma_entry.dst = (uint64_t)NULL;
		dma_entry.trans_type.num_st_ptrs = num_st_ptrs;
		dma_entry.trans_type.dma_mode = DMA_OUTBOUND;
		dma_entry.trans_type.cpl_transfer = 0;
		status = npl_dma_submit(dev, &dma_entry, new_wqe);
		if (dma_data_bufs)
			cvmx_fpa_free(dma_data_bufs, FPA_DATA_BUF_POOL, 0);
		dma_data_bufs = NULL;
	
		if (status == DMA_ERROR) {
			remaining_bytes = dma_entry.nbytes;
			debug_printf(1, "Error: I/O Read Cmd Data"
					"transfer has failed, %lu bytes left", remaining_bytes);
			cvmx_atomic_fetch_and_bset64_nosync(&sq->cmd_id_arr[LCMDID(wqe)], 1);
			xfered_bytes = cvmx_atomic_fetch_and_add64((int64_t *)&(sq->cmd_id_arr[LCMDID(wqe)]), 
					(remaining_bytes << 1)); 
			xfered_bytes = (xfered_bytes & 0xFFFFFFFF) >> 1;
			xfered_bytes += remaining_bytes;
			if (xfered_bytes < total_xfer_bytes) {
				/* Let the completion be posted once in flight dma's are done */
				completion_on_err = false;
				npl_fpa_free((uint64_t *)wqe->word5.u64,
						CONTEXT_STRUCT_IO_DMA_POOL,
						sizeof(struct context_struct));
				io_cmd_context = NULL;
			} else {
				cvmx_atomic_fetch_and_bclr64_nosync(&sq->cmd_id_arr[LCMDID(wqe)], 1);
			}
			cpl_entry.sct = SCT_GENERIC;
			cpl_entry.sc = INTERNAL_ERROR;
			npl_fpa_free(new_wqe, CVMX_FPA_WQE_POOL,
					sizeof(cvmx_wqe_t));
			goto cleanup;
		}
		break;
	}

	case nvme_cmd_write:
	{
			
		npl_helper_free_context(io_cmd_context);

		cpl_entry.sct = SCT_GENERIC;
		cpl_entry.sc = CMD_SUCCESSFUL;
		cpl_entry.m = 0;
		cpl_entry.dnr = 0;
		result = 0;
		npl_submit_completion_entry(
			dev, wqe, result, cpl_entry);
		break;
	}
	case nvme_cmd_flush:
	{
		cpl_entry.sct = SCT_GENERIC;
		cpl_entry.sc = CMD_SUCCESSFUL;
		cpl_entry.m = 0;
		cpl_entry.dnr = 0;
		result = 0;
		npl_submit_completion_entry(dev, wqe, result, cpl_entry);
		
		if (io_cmd_context)
			cvmx_fpa_free(io_cmd_context, CVMX_FPA_WQE_POOL , 0);
		break;
	}
	case nvme_cmd_compare:
	{
		uint64_t *compare_bufs = cvmx_phys_to_ptr((uint64_t)io_cmd_context->compare_buff);
		/* Now transfer user data and do a comparision in sal_complete_io(). */
		num_st_ptrs = io_cmd_context->num_comp_bufs;

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
		wqe->word5.u64 = (uint64_t)io_cmd_context;
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
		/* 
		 * Allocate new wqe as this function is not called 
		 * from sal_do_transfer() unlike others 
		 */
		new_wqe = npl_fpa_alloc(dev, CVMX_FPA_WQE_POOL);
		if (!new_wqe) {
			printf("%s: wqe allocation failed\n", __func__);
			goto cleanup;
		}

		memset(new_wqe, 0, sizeof(cvmx_wqe_t));
		memcpy(new_wqe, wqe, sizeof(cvmx_wqe_t));
		npl_setup_wqe(new_wqe);

		new_wqe->word1.qw1.tag =
			(IO_DATA_TRANSFER_TAG << NQM_TAG_SHIFT) |
			(new_wqe->word3.qw3.sq_id << NQM_QID_SHIFT) |
			dev->pfvf;
		new_wqe->word1.qw1.tt = CVMX_POW_TAG_TYPE_ORDERED;
		new_wqe->word3.qw3.vf = dev->pfvf;
		
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
		status = npl_dma_submit(dev, &dma_entry, new_wqe);
		if (dma_data_bufs)
			cvmx_fpa_free(dma_data_bufs, FPA_DATA_BUF_POOL, 0);
		dma_data_bufs = NULL;

		if (status == DMA_ERROR) {
			remaining_bytes = dma_entry.nbytes;
			debug_printf(1, "Error: I/O Compare Data"
					"transfer has failed, %lu bytes left", remaining_bytes);
			cvmx_atomic_fetch_and_bset64_nosync(&sq->cmd_id_arr[LCMDID(wqe)], 1);
			xfered_bytes = cvmx_atomic_fetch_and_add64((int64_t *)&(sq->cmd_id_arr[LCMDID(wqe)]), 
					(remaining_bytes << 1)); 
			xfered_bytes = (xfered_bytes & 0xFFFFFFFF) >> 1;
			xfered_bytes += remaining_bytes;
			if (xfered_bytes < total_xfer_bytes) {
				/* Let the completion be posted once in flight dma's are done */
				completion_on_err = false;
				npl_fpa_free((uint64_t *)wqe->word5.u64,
						CONTEXT_STRUCT_IO_DMA_POOL,
						sizeof(struct context_struct));
				io_cmd_context = NULL;
			} else {
				cvmx_atomic_fetch_and_bclr64_nosync(&sq->cmd_id_arr[LCMDID(wqe)], 1);
			}
			npl_fpa_free(new_wqe, CVMX_FPA_WQE_POOL,
					sizeof(cvmx_wqe_t));
			goto cleanup;
		}

	}
	}
	return 0;

cleanup:
	if (dma_data_bufs)
	    cvmx_fpa_free(dma_data_bufs, FPA_DATA_BUF_POOL, 0);

	npl_helper_free_context(io_cmd_context);

	if (prp_list) {
		debug_printf(1, "Error: PRP List not freed");
	}

	if (completion_on_err)
		npl_submit_completion_entry(dev,
			wqe, result, cpl_entry);
    
	/* Cleanup fused second cmd */
	npl_helper_cleanup_fused_cmd(dev, wqe);
	
	/* Here caller will take care of freeing wqe */

	return STATUS_ERROR;

}

CVMX_SHARED cvm_bdev_list_t glb_bdev_list;
struct ns_ctrl ns_idt_template = {
	0, // disk size in sectors
	0, // sector size
	0, // namespace logical id
	1, // ns_type is block dev
	{0}, // namespace base pointer (to be filled in later)
	{
		le64_cpu(0x0000000000000000, ull),  // nsze: name space size
		le64_cpu(0x0000000000000000, ull),  // ncap: name space capacity
		le64_cpu(0x0000000000000000, ull),  // nuse: name space utilization
		0x00, // nsfeat
		0x00, // nlbaf
		0x00, // flbas
		0x00, // mc
		0x00, // dpc
		0x00, // dps
		0x00, // nmic
		0x00, // rescap
		0x00, // fpi
		0x00, // rsvd33
		le16_cpu(0x0000),                   // nawun:
		le16_cpu(0x0000),                   // nawupf:
		le16_cpu(0x0000),                   // nacwu:
		{ 0, },                             // rsvd40[80]
		{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, // eui64[8]
		{
			{ le16_cpu(0x0000), 0x09, 0x00}, // lba format 0
			{ le16_cpu(0x0000), 0x00, 0x00}, // lba format 1
			{ le16_cpu(0x0000), 0x00, 0x00}, // lba format 2
			{ le16_cpu(0x0000), 0x00, 0x00}, // lba format 3
			{ le16_cpu(0x0000), 0x00, 0x00}, // lba format 4
			{ le16_cpu(0x0000), 0x00, 0x00}, // lba format 5
			{ le16_cpu(0x0000), 0x00, 0x00}, // lba format 6
			{ le16_cpu(0x0000), 0x00, 0x00}, // lba format 7
			{ le16_cpu(0x0000), 0x00, 0x00}, // lba format 8
			{ le16_cpu(0x0000), 0x00, 0x00}, // lba format 9
			{ le16_cpu(0x0000), 0x00, 0x00}, // lba format 10
			{ le16_cpu(0x0000), 0x00, 0x00}, // lba format 11
			{ le16_cpu(0x0000), 0x00, 0x00}, // lba format 12
			{ le16_cpu(0x0000), 0x00, 0x00}, // lba format 13
			{ le16_cpu(0x0000), 0x00, 0x00}, // lba format 14
			{ le16_cpu(0x0000), 0x00, 0x00}, // lba format 15
		}, // lbaf[16]
		{ 0, },  // rsvd192[192]
		{
		00,
		} // vs[3712]
	}
};

void
sal_bdev_init()
{
	uint16_t i, nsid_start, ns_max;

	for (nsid_start = 0; nsid_start < MAX_NUMBER_NS; nsid_start++) {
		if (!sal_namespaces[nsid_start])
			break;
	}

	ns_max = ((nsid_start + glb_bdev_list.num_bdevs) >
		MAX_NUMBER_NS) ? (nsid_start + glb_bdev_list.num_bdevs) :
		MAX_NUMBER_NS;

	for (i = nsid_start; i < ns_max; i++) {
		if (!glb_bdev_list.bdev[i - nsid_start].sector_size) break;

		sal_namespaces[i] = 
			findalloc(ns_ctrl, i, CVMX_CACHE_LINE_SIZE);
		if (!sal_namespaces[i]) {
			debug_printf(1, "Can't alloc namespace structure");
			break;
		}

		memcpy(sal_namespaces[i],
			&(ns_idt_template), sizeof(struct ns_ctrl));
		sal_namespaces[i]->disk_size =
			glb_bdev_list.bdev[i - nsid_start].bdev_size;
		sal_namespaces[i]->sector_size =
			glb_bdev_list.bdev[i - nsid_start].sector_size;
		sal_namespaces[i]->ns_id = i+1;
		sal_namespaces[i]->id_ns.nsze =
			le64_cpu(sal_namespaces[i]->disk_size, ull);
		sal_namespaces[i]->id_ns.ncap =
			sal_namespaces[i]->id_ns.nsze;

		sal_namespaces[i]->bdev_info =
			(uint8_t *)&glb_bdev_list.bdev[i - nsid_start];
		printf("SATA Device %u init: size %lu\n",
			i, sal_namespaces[i]->disk_size);
	}
}

static int
sal_deregister_bdev_handler(cvmx_wqe_tt *wqe)
{
	//TODO
	memset(&glb_bdev_list, 0, sizeof(cvm_bdev_list_t));
	return 0;
}

static int
sal_register_bdev_handler(cvmx_wqe_tt *wqe)
{
	cvm_bdev_list_t *bdevs;
	uint32_t num_bdevs;
	uint32_t i;

	bdevs = cvmx_phys_to_ptr(*((uint64_t *)&wqe->nvme_cmd));
	num_bdevs = bdevs->num_bdevs;

	glb_bdev_list.num_bdevs = num_bdevs;
	for (i = 0; i < num_bdevs; i++) {
		memcpy(&glb_bdev_list.bdev[i],
			&bdevs->bdev[i], sizeof(cvm_bdev_info_t));
    
		printf("%s: bdev_size %d, sector_size %d\n",
			__func__, glb_bdev_list.bdev[i].bdev_size,
			glb_bdev_list.bdev[i].sector_size);
	}

	cvmx_fpa_free((void *)cvmx_ptr_to_phys(bdevs), FPA_DATA_BUF_POOL, 0);

	sal_bdev_init();
	return 0;
}

/* Process non-data traffic(control/config messages) initiated from
 * octeon linux bio module. Also handle RD/WR bio_done/bi_end_io
 * responses from oct-linux bio mdoule.
 */
int sal_linux_bdev_process_message(cvmx_wqe_tt * wqe, int subcode)
{
	switch (subcode) {
	case OPCODE_SAL_REGISTER_BDEVS:
		/* Received list of available bdevs from linux bio module,
		 * initialize SE side list of linux bio block device list.
		 */
        	sal_register_bdev_handler(wqe);
        break;
	case OPCODE_SAL_DEREGISTER_BDEVS:
		sal_deregister_bdev_handler(wqe);
		break;

	case OPCODE_SAL_RDWR_BIO_DONE_RESP:
		sal_rdwr_bio_done_resp_handler(wqe);
		break;

	default:
		printf("%s: Invalid opcode\n", __func__);
        	break;
	}

	CVMX_SYNCW;

	return 0;
}
