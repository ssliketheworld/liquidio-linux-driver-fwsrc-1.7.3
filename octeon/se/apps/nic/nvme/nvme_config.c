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

\file

\brief This module contains nvme configuration information.

*******************************************************************************/

/*-----------------------------------------------------------------------------
 *                                 Revision History
 *                                     $Log: nvme_config.c $
 *---------------------------------------------------------------------------*/

#include "nvme_cvm.h"
#include "nvme.h"
#include "cvmx-nqm-defs.h"
#include "cn73xx_nqm.h"
#include "nvme_stats.h"

extern CVMX_SHARED struct nvme_dev *nqm_device_structs[1028];
extern CVMX_SHARED nqm_vf_mode_map_t nqm_vf_mode_map[];
CVMX_SHARED int ns_sata_only_map = 0;
extern CVMX_SHARED uint8_t nqm_vf_mode;
extern CVMX_SHARED nqm_vf_mode_map_t nqm_vf_mode_map[];
extern CVMX_SHARED nvme_queue_mem_t gbl_nvme_queue_mem[];
extern CVMX_SHARED uint16_t nqm_cplq_size;

static struct nvme_dev_config predef_dev_config[MAX_DEV_CONFIG]={
	// CONFIG #0
	// [saf] Config #0 is not complete, do not use.
	{
		0,
	},
	// CONFIG #1
	{
        /* Configuration values for CAP register */
        le16_cpu((MAX_SQ_DEPTH -1)), /* cap_mqes:16 - 4096 entries maximum */
#if !DISCONTIGUOUS_Q_SUPPORT
        1ull,                   /*  cap_cqr:1 - contiguous, 0 - not contiguous */
#else
        0ull,                   /* cap_cqr:1 - contiguous, 0 - not contiguous */
#endif
        0ull,                   /* cap_ams:2 - Bare round robin mechanism used */
        0x0,                    /* rsvd1:5 */
        0xFFull,                /* cap_to:8 - Set to Maximum wait time */
        0x0ul,                  /* cap_dstrd:0 - (2 ^ (2 + DSTRD)) */
        0x0ul,                  /* cap_nssrs:1 - supported, 0 - not supported */
        0x01ul,                 /* cap_css:8  PREV-0x01 */
        0x0,                    /* rsvd2 */
        0x0ul,                  /* cap_mpsmin:4 */
        0x0ul,                  /* cap_mpsmax:4 */
        0x0,                    /* rsvd3 */
        /* queue attributes */
        16,                     /* io_cqes */
        64,                     /* io_sqes */
        le16_cpu(0x000f),       /* max_sub_queues */
        le16_cpu(0x000f),       /* max_cpl_queues */
        le16_cpu(0x0040),       /* max_queue_entries */
        /* identify structures */
        /* id_ctrl */
		{
            le16_cpu(0x0091),                                           /* vid */
            le16_cpu(0x177d),                                           /* ssvid */
            { 0x4F, 0x43, 0x54, 0x4E, 0x56, 0x4D, 0x45, 0x30, 0x30, 0x30, 0x30,
              0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30 },   /* sn[20] OCTNVME0000000000000 */
            { 0x4F, 0x43, 0x54, 0x45, 0x4F, 0x4E, 0x20, 0x4E, 0x56, 0x4D, 0x45,
              0x20, 0x30, 0x2E, 0x30, 0x2E, 0x31 },                     /* mn[40] OCTEON NVME 0.0.1 */
            { 0x30, 0x30, 0x2E, 0x30, 0x30, 0x2E, 0x30, 0x31 },         /* fr[8] 00.00.01 */
            0x01,                                                       /* rab round robin arbitration (fine tune) */
            { 0x4F, 0x43, 0x54 },                                       /* ieee[3] some unique value */
            0x00,                                                       /* mic single ctrlr, single pci etc */
            0x09,                                                       /* mdts - Maximum data transfer- 2 MB (2^9 4K pages)*/
            le16_cpu(0x9130),                                           /*cntlid O0 */
            le32_cpu(0x00000000),                                       /* ver */
            { 0 },                                                      /* rsvd78[172] */
            le16_cpu(0x0000),                                           /* oacs  no support for optional Admin commands */
            0x04,                                                       /* acl  - It is recommended that implementations support a minimum of four
                                                                         * Abort commands outstanding simultaneously */
            0x04,                                                       /* aerl - It is recommended that implementations support a minimum of four
                                                                         * Asynch Event Rqst Limit commands outstanding simultaneously. */
            0x00,                                                       /* frmw */
            0x00,                                                       /* lpa - does not support the SMART / Health information log page on a per
                                                                         * name space basis. */
            0x03,                                                       /* elpe - Number of Error Information log entries equals 64 */
            0x01,                                                       /* npss - Supports only one power state */
            0x00,                                                       /* avscc */
            0x00,                                                       /* apsta */
            le16_cpu(0x0000),                                           /* wctemp */
            le16_cpu(0x0000),                                           /* cctemp */
            { 0 },                                                      /* rsvd264[242] */
            0x66,                                                       /* sqes - maximum and minimum Submission Queue entry size when using the NVM
                                                                         * Command Set (2^6 = 64) */
            0x44,                                                       /* cqes - required and maximum Completion Queue entry size when using the NVM
                                                                         * Command Set (2^4 = 16) */
            { 0x00, 0x00 },                                             /* rsvd514[2] */
            le32_cpu(0x00000002),                                       /* MULTI_NS */ /* nn - valid name spaces present for the controller */
            le16_cpu(0x0001),                                           /* oncs - controller supports the Compare command */
            le16_cpu(0x0001),                                           /* fuses - controller supports the Compare and Write fused */
            0x00,                                                       /* fna */
            0x00,                                                       /* vwc - volatile write cache */
            le16_cpu(0x0008),                                           /* awun - Atomic Write Unit Normal - 8 * 512 = 1 page size (fine tune) */
            le16_cpu(0x0008),                                           /* awupf - 8 * 512 = 1 page size (finetune) */
            0x00,                                                       /* nvscc */
            0x00,                                                       /* rsvd531 */
            le16_cpu(0x0008),                                           /* acwu */
            { 0x00, 0x00 },                                             /* rsvd534[2] */
            le32_cpu(0x00000000),                                       /* sgls */
            { 0 },                                                      // 1508 //rsvd540[1518]
			{
				/* max_power rsvd2 flags  entry_lat   exit_lat    read_tput read_lat  write_tput write_lat  idle_power  idle_scale rsvd19 */
                { le16_cpu(0x0000), 0x00, 0x00, le32_cpu(0x00000000), le32_cpu(
                      0x00000000), 0x00, 0x00, 0x00, 0x00, le16_cpu(0x0000),
                  0x00, 0x00,
				/* active_power   active_work_scale   rsvd23[9]*/
                  le16_cpu(0x0000), 0x00,
                  { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } }
            },                          /* psd[32] */
            { 0 }                       /*  vs[1024] */
        },
        le32_cpu(MAX_NUMBER_NS - 1),    /* max_number_ns */
        0,
    } /* end of Config 1 */
};	

/*
 * Fixed structure allocations
 * These establish the base addresses of all fixed structures.
 */
CVMX_SHARED struct nvme_dev*         nvme_dev_base;
CVMX_SHARED struct nvme_ctrl_id*     nvme_ctrl_id_base;
CVMX_SHARED struct async_event_info* async_event_info_base;
CVMX_SHARED struct nvme_queue*       nvme_queue_base;
CVMX_SHARED struct ns_ctrl*          ns_ctrl_base;
CVMX_SHARED struct nvme_stats_dma_mem *nvme_stats_dma_mem_base;

/***************************************************************************//**

     nqm_config_initialize()

	@param dev Pointer to device private structure

	@return On success zero and negative error code on failure


*******************************************************************************/

int 
nqm_config_initialize(struct nvme_dev *dev,
                      uint32_t config_no)
{
    	int ret = -1;
	cvmx_nqm_vf_mode_t vf_mode;

//	int8_t flbas;

	memcpy(&(dev->dev_config), &(predef_dev_config[config_no]), sizeof(struct nvme_dev_config));

	if (OCTEON_IS_MODEL(OCTEON_CN73XX)) {
		vf_mode.u64 = cvmx_read_csr_node(
			cvmx_get_node_num(), CVMX_NQM_VF_MODE);
		dev->dev_config.max_sub_queues = 
			le16_cpu(nqm_vf_mode_map[vf_mode.s.vf_mode].vf_max_ioq - 1);
		dev->dev_config.max_cpl_queues =
			le16_cpu(nqm_vf_mode_map[vf_mode.s.vf_mode].vf_max_ioq - 1);
       }
	
//flbas =  dev->dev_config.id_ns[0].flbas;
	ret = sal_storage_initialize (dev);
	if(ret < 0)
        	return STATUS_ERROR;

	return STATUS_SUCCESS;
}

/***************************************************************************//**

     hil_initialize_ctrlreg()

    It initializes nvme_bar structure with respective informations along with
	required structure memory allocation.

	@param dev Pointer to device private structure

	@return On success zero and negative error code on failure

*******************************************************************************/

int nqm_initialize_ctrlreg(struct nvme_dev *dev)

{
 //Madhu : Error handling - Clean up previously allocated memory whenever there is a failure.
    npl_initialize_bar1(dev);
// Madhu1001 : same comment : taken care
    dev->id_ctrl = findalloc(nvme_ctrl_id, dev->pfvf, CVMX_CACHE_LINE_SIZE);
    if (!dev->id_ctrl)
    {
		return STATUS_ERROR;
    }
    memset(dev->id_ctrl , 0, sizeof(struct nvme_ctrl_id));

    npl_initialize_nvme_id_ctrl(dev);

    return STATUS_SUCCESS;

}

/***************************************************************************//**

Process nqm device init

Initializes the nqm device structure.

*******************************************************************************/

int nqm_dev_init(struct nvme_dev *dev)
{
	int ret = -1;

	debug_printf(3, "nqm dev init:");

	dev->eptr.top = ERR_LOG_SIZE - 1;
	dev->sptr.top = SMART_LOG_SIZE - 1;
	dev->fware_ptr.top = FIRMWARE_LOG_SIZE - 1;
	dev->eptr.queue_wrapped = 0;
	dev->sptr.queue_wrapped = 0;
	dev->fware_ptr.queue_wrapped = 0;

	dev->event_info = findalloc(async_event_info, dev->pfvf, CVMX_CACHE_LINE_SIZE);
	if (!dev->event_info) {
		debug_printf(1, "Error:async_event::Memory Allocation Failure");
		return -1;
	}

	dev->stats_dma_mem = findalloc(nvme_stats_dma_mem, dev->pfvf, CVMX_CACHE_LINE_SIZE);
	if (!dev->stats_dma_mem) {
		debug_printf(1, "Error:nvme_stats_dma_mem: Memory Allocation Failure");
		return -1;
	}

	cvmx_spinlock_init(&dev->event_info_lock);

	/* Initialize the nvme device and the storage device */
	ret = nqm_config_initialize(dev, 1);
	if(ret < 0)
		return ret;

	/* Reset and initialize all the NVMe control registers */
	ret = nqm_initialize_ctrlreg(dev);
	if(ret < 0)
		return ret;

	return 0;
}

/***************************************************************************//**

Initializes device instance

Accepts a pfvf logical number. Initializes that device.

*******************************************************************************/

int nvme_init_dev(int pfvf)

{
	struct nvme_dev *dev; // device info structure pointer
	int ret = 0;

	if (!nqm_device_structs[pfvf]) // no existing device control structure
	{
		/* find memory for the device private structure */
		dev = findalloc(nvme_dev, pfvf, CVMX_CACHE_LINE_SIZE);
		dev->pfvf = pfvf; // set pfvf
		// initialize that
		ret = nqm_dev_init(dev);
		if (ret < 0)
			return ret;
		nqm_device_structs[pfvf] = dev; // place device
	}

	sal_storage_initialize(nqm_device_structs[pfvf]);

	return 0;
}

/***************************************************************************//**

Process config init


Initializes the config module.

*******************************************************************************/

int nvme_config_init(void)
{
	int ret = 0, i;
	unsigned char* mempool;
	unsigned int alloc_len;
	uint16_t num_vfs;
	uint16_t num_queues;

	debug_printf(3, "config init:");

	num_vfs = nqm_vf_mode_map[nqm_vf_mode].vf_cnt;
	num_queues = nqm_vf_mode_map[nqm_vf_mode].vf_max_ioq + 1;

	alloc_len = (align(sizeof(struct nvme_dev), CVMX_CACHE_LINE_SIZE)+
			align(sizeof(struct nvme_ctrl_id), CVMX_CACHE_LINE_SIZE)+
			align(sizeof(struct async_event_info), CVMX_CACHE_LINE_SIZE)+
			align(sizeof(struct nvme_queue), CVMX_CACHE_LINE_SIZE) +
			align(sizeof(struct nvme_stats_dma_mem), CVMX_CACHE_LINE_SIZE)) *
			num_vfs;

	alloc_len +=  align(sizeof(struct ns_ctrl), CVMX_CACHE_LINE_SIZE) * MAX_NUMBER_NS;

	// laydown dev structs as first allocation
	mempool = (unsigned char *)
		cvmx_bootmem_alloc(alloc_len, CVMX_CACHE_LINE_SIZE);
	if (!mempool) {
		debug_printf(1, "NVME dev mem alloc failed");
		return STATUS_ERROR;
	}

	// set allocation base pointers
	nvme_dev_base         = (struct nvme_dev*) mempool;
	nvme_ctrl_id_base     = (struct nvme_ctrl_id*) ((unsigned char *) nvme_dev_base+
		align(sizeof(struct nvme_dev), CVMX_CACHE_LINE_SIZE) * num_vfs);
	async_event_info_base = (struct async_event_info*) ((unsigned char *) nvme_ctrl_id_base+
		align(sizeof(struct nvme_ctrl_id), CVMX_CACHE_LINE_SIZE) * num_vfs);
	nvme_queue_base       = (struct nvme_queue*) ((unsigned char *) async_event_info_base+
		align(sizeof(struct async_event_info), CVMX_CACHE_LINE_SIZE) * num_vfs);
	ns_ctrl_base          = (struct ns_ctrl*) ((unsigned char *) nvme_queue_base+
		align(sizeof(struct nvme_queue), CVMX_CACHE_LINE_SIZE) * num_vfs);
	nvme_stats_dma_mem_base = (struct nvme_stats_dma_mem *)
		((unsigned char *) ns_ctrl_base +
		align(sizeof(struct ns_ctrl), CVMX_CACHE_LINE_SIZE) * num_vfs);

	for (i = 0; i < num_vfs; i++) {
		gbl_nvme_queue_mem[i].subq_mem =
			(uint64_t)cvmx_bootmem_alloc(npl_calc_fpa_pool_size(
			sizeof(struct nvme_sub_queue)) * num_queues,
			CVMX_CACHE_LINE_SIZE);
		if (!gbl_nvme_queue_mem[i].subq_mem) {
			debug_printf(1, "SQ struct mem alloc failed");
			return STATUS_ERROR;
		}

		if (!OCTEON_IS_MODEL(OCTEON_CN73XX)) {
			gbl_nvme_queue_mem[i].subq_cmnds_mem =
				(uint64_t)cvmx_bootmem_alloc(npl_calc_fpa_pool_size(
				SUBQUEUE_ENTRY_SIZE * MAX_SQ_DEPTH) * num_queues, 
				CVMX_CACHE_LINE_SIZE);
			if (!gbl_nvme_queue_mem[i].subq_cmnds_mem) {
			debug_printf(1, "SQ cmds mem alloc failed");
			return STATUS_ERROR;
			}
		} else
			gbl_nvme_queue_mem[i].subq_cmnds_mem = 0;

		gbl_nvme_queue_mem[i].cq_mem =
			(uint64_t)cvmx_bootmem_alloc(npl_calc_fpa_pool_size(
			sizeof(struct nvme_cpl_queue)) * num_queues,
			CVMX_CACHE_LINE_SIZE);
		if (!gbl_nvme_queue_mem[i].cq_mem) {
			debug_printf(1, "CQ struct mem alloc failed");
			return STATUS_ERROR;
		}
		gbl_nvme_queue_mem[i].cq_cmnds_mem =
			(uint64_t)cvmx_bootmem_alloc(npl_calc_fpa_pool_size(
			COMPLETIONQUEUE_ENTRY_SIZE * nqm_cplq_size) * num_queues,
			CVMX_CACHE_LINE_SIZE);

		if (!gbl_nvme_queue_mem[i].cq_cmnds_mem) {
			debug_printf(1, "CQ cmds mem alloc failed");
			return STATUS_ERROR;
		}
	}

	debug_printf(3, "nvme_dev_base:         %p\n", nvme_dev_base);
	debug_printf(3, "nvme_id_ctrl_base:     %p\n", nvme_ctrl_id_base);
	debug_printf(3, "async_event_info_base: %p\n", async_event_info_base);
	debug_printf(3, "nvme_queue_base:       %p\n", nvme_queue_base);
	debug_printf(3, "ns_ctrl_base:          %p\n", ns_ctrl_base);
	debug_printf(3, "total allocation:      %u\n", alloc_len);

	return ret;
}

void nvme_set_sata_only_map(void)
{
	ns_sata_only_map = 1;
	
	debug_printf(1, "NS Mapping mode set to SATA only");
}
