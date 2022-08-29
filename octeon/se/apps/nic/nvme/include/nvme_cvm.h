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
* \file
*
* \brief    This file contains the declarations and definitions for
*           processing the nvme commands
*******************************************************************************/

/*-----------------------------------------------------------------------------
 *                                 Revision History
 *                                  $Log: nvme_cvm.h $
 *---------------------------------------------------------------------------*/

#ifndef __NVME_CVM_H__
#define __NVME_CVM_H__

/* Header inclusion */
#include "cvmx-config.h"  /* This should be the first inclusion file */
#include "cvmx.h"
#include "cvmx-fpa.h"
#include "cvmx-atomic.h"
#include "cvmx-pow.h"
#include "cvmx-bootmem.h"
#include "cvmx-sysinfo.h"
#include "cvmx-pcie.h"
#include "cvmx-dma-engine.h"
#include "app-config.h"
#include "nvme_list.h"
#include "cvmx-mbox.h"
#include "cvmx-helper.h"
#include "cvmx-cmd-queue.h"
#include "cvmx-spinlock.h"
#include "cvmx-clock.h"
#include "cvmx-rwlock.h"
#include "nvme_bitops.h"
#include "nvme_cvm_defines.h"

#define NVME_MAJOR_VERSION 0
#define NVME_MINOR_VERSION 0
#define NVME_MICRO_VERSION 6

#define NVME_VERSION "0.0.6"

/**
 * Short debug print system for driver FW.
 *
 * Form: debug_printf(1, "do this: %d\n:", value);
 *
 * Prints if the DEBUG definition is at the same or greater level as the
 * indicated level, with 0 being print always.
 *
 * Loosely, the levels are:
 *
 * 	0 - All debug off (driver release format).
 * 	1 - Print light diagnostics not in data path.
 * 	2 - Heavy diagnostics, but not in data path.
 * 	3 - Light Data path diagnostics.
 * 	4 - Heavy data path diagnostics, for example printing all routine entries.
 * 	5 or more - up to you to define.
 *
 * The output is:
 *
 * 	file: function: line: message \n
 *
 * Don't put \n's in the message. Partial lines make no sense when preceeded by a
 * file:function:line header.
 *
 * For all other formats, use a if (DEBUG_LEVEL >= n) ...;
 */

#define DEBUG_LEVEL                         1
#define debug_printf(level, fmt, ...)                   \
    if (DEBUG_LEVEL >= level) do {                      \
            printf("%s(): %i: " fmt "\n",                     \
                   __func__, __LINE__, ## __VA_ARGS__); \
        } while (0)

/* This macro provided to enable copy to/from volatile */
#define MEMCPY(d, s, l)                                           \
    { size_t i = l; volatile uint8_t *ps = (volatile uint8_t *)s; \
      volatile uint8_t *pd = (volatile uint8_t *)d; while (i--) *pd++ = *ps++; }

extern CVMX_SHARED uint64_t core_count;

/*	Macro definitions */

/*
 * Define the processor type. This will be defined in the new SDK, but we need
 * it now (even though it is false).
 */
//#define OCTEON_CN73XX 0 // this will be defined by the new SDK

/*
 * Number of physical/virtual functions
 */
#define NVME_NUM_PFVF 1028
#define NVME_PCIE_PORT 0

/*
 * Timeout for waits on hardware resources, in seconds.
 *
 * Note if you want subsecond, you have to change the timing calls.
 */
#define NVME_TIMEOUTVAL 1
/*
 * Queue timeout for 73XX in seconds.
 * Derived from MAX CSTS[RDY] timeout & Max # of IOQ
 */
#define NVME_QUEUE_TIMEOUTVAL 4

/*
 * Mark time
 */
#define NVME_MARKTIME(t) (t = cvmx_clock_get_count(CVMX_CLOCK_CORE))
/*
 * Find if timeout elapsed. t = mark time
 */
#define NVME_TIMEOUT(t, val) (cvmx_clock_get_count(CVMX_CLOCK_CORE)-t >= \
	                 cvmx_clock_get_rate(CVMX_CLOCK_CORE)*val)

/* NVMe Admin Commands */
#define NVME_ADMIN_CMD_DELETE_SQ                0X00
#define NVME_ADMIN_CMD_CREATE_SQ                0X01
#define NVME_ADMIN_CMD_GET_LOG_PAGE             0X02
#define NVME_ADMIN_CMD_DELETE_CQ                0X04
#define NVME_ADMIN_CMD_CREATE_CQ                0X05
#define NVME_ADMIN_CMD_IDENTIFY                 0X06
#define NVME_ADMIN_CMD_ABORT                    0X08
#define NVME_ADMIN_CMD_SET_FEATURES             0x09
#define NVME_ADMIN_CMD_GET_FEATURES             0x0A
#define NVME_ADMIN_CMD_ASYNC_EVENT              0X0C

#define NVME_ADMIN_CMD_STATS                    0XCA

/* Work entry TAGs LSb 4 bits defined here. MSb 16-bits will be used to store Queue ID and 12-bits for the port number */
#define CMD_TRANSFER_TAG                    0x01
#define CMD_COMPLETION_REQUEST_TAG          0x02
#define ADMIN_DATA_TRANSFER_TAG             0x03
#define IO_DATA_TRANSFER_TAG                0x04
#define PRP_LIST_TRANSFER_TAG               0x05
#define CMD_HANDLE_TAG                      0x06
#define CMD_FETCH_TAG                       0x07
#define MSG_FROM_OCTLINUX_TAG               0x08
#define MSG_TO_OCTLINUX_TAG                 0x09
#define NQM_INTR_HANDLE_TAG                 0x0A

/* Memory block names */
#define DEV_MEM                             "devmem"
#define BAR_MEM                             "barmem"
#define CTRL_MEM                            "ctrlmem"
#define COMPARE_BLOCK                       "comparedata"
#define ADMIN_SUB_QUEUE                     "adminsqueue"
#define ADMIN_CPL_QUEUE                     "admincqueue"
#define ADMIN_SQ_CMDS                       "admin_cmd"
#define QUEUE                               "queue"
#define QUEUE_INFO                          "queue_info"
#define ASYNC_INFO                          "async_info"

/* Status values */
#define STATUS_SUCCESS                      0
#define STATUS_ERROR                        -1
#define DMA_SUCCESS                         0
#define DMA_ERROR                           -1
#define STATUS_WAIT                         1

/* Work queue related */
#define TAG_PHASE_MASK                      0x0000FFFF
#define TAG_QUEUE_MASK                      0xFFFF0000
#define TAG_PORT_MASK                       0x0000FFF0
#define NVME_WQE_QOS                        0x00ull
#define NVME_WQE_GRP                        0

#define NQM_TAG_SHIFT                       16
#define NQM_QID_SHIFT                       11
#define NQM_VFID_SHIFT                      0

/* DMA relevant definitions */
#define DMA_ENGINE                          0           /* DMA Engine number */
#define DMA_INST_MAX_ENTRIES                13          //8  /* DMA Instruction entries */
#define DMA_BLOCK_TRNSFER_LIMIT             8 * 1024    /* DMA BLOCK SIZE TRANSFER limit by hardware */
#define NVME_IO_DMAQ_MAX                    6

#define DMA_PCIE_PORT                       1
#define CPL_TRANSFER                        1           /* For completion transfer */
#define DMA_MULTI_Q
#define DMA_MULTI_Q_CMDID                               /*Comment to use SQID based*/
#define DMA_INTR_COALESCING

/* DMA modes */
#define DMA_OUTBOUND                        0   /* I/O data read / NVMe completion queue transfer */
#define DMA_INBOUND                         1   /* I/O data write / PRP list / NVMe sub queue transfer */

/* PRP modes */
#define PRP_NULL                            0   /* involves no PRP transfer. Used for queue transfers */
#define PRP_NOLIST                          1   /* involves PRP transfer but no List */
#define PRP_LIST                            2   /* involves transfer of PRP entries from a list */
#define DMA_BYTE_POINTER                    3
#define DMA_ONLY_NONE                       4

/* PRP alignment related macros */
#define PAGE_ALIGNMENT                      1
#define DWORD_ALIGNMENT                     2
#define QWORD_ALIGNMENT                     3

#define FIRST_PTR_MAX_SIZE                  8191 /* Size field of the first pointer in a DMA instruction */

#define     CN68XX_SLI_INT_SUM64            0x0330
#define     CN68XX_SLI_INT_ENB64_PORT1      0x0350
#define     CN68XX_SLI_INT_ENB64_PORT1_REG  (0x00011F0000010350ULL)
#define     CN68XX_INTR_DMA0_FORCE          (1ULL << 32)
#define     CN68XX_INTR_DMA1_FORCE          (1ULL << 33)
#define     CN68XX_INTR_MASK  \
    (CN68XX_INTR_DMA0_FORCE | \
     CN68XX_INTR_DMA1_FORCE)

/* Mailbox */
#define MBOX_SIZE                           32
#define MBOX_CORE                           1

#define CHECKBITS(val, start_bit, end_bit) \
    ((                                     \
         (val) &                           \
         ((1 << ((end_bit) + 1)) -         \
          (1 << (start_bit)))              \
         )                                 \
     >> start_bit)

#define CLEAR_BITS(val, start_bit, end_bit) \
    (                                       \
        (val) &                             \
        ~((1ull << ((end_bit) + 1)) -       \
          (1ull << (start_bit)))            \
    )

#define SET_BITS(val, change, start_bit, end_bit) \
    ((CLEAR_BITS(val, start_bit, end_bit)) | ((change) << start_bit))

#define GET_CC_MPS(__dev) CHECKBITS(cvm_read_csr32(CVMX_PEXP_NQM_VFX_CC(__dev->pfvf)),7,10)
#define GET_HOST_PAGE_SHIFT(__dev) (12 + GET_CC_MPS(__dev))

   //SET REG VALUE

#define SET_REGISTER_VAL(dev,reg,val,start_bit,end_bits) \
	(cvm_write_csr(CVMX_NQM_VFX_##reg(dev->pfvf), \
		SET_BITS(cvm_read_csr(CVMX_NQM_VFX_##reg(dev->pfvf)), \
		(val), (start_bit), (end_bits))))

#define SET_REGISTER_VAL32(dev,reg,val,start_bit,end_bits) \
	(cvm_write_csr32(CVMX_NQM_VFX_##reg(dev->pfvf), \
		SET_BITS(cvm_read_csr32(CVMX_NQM_VFX_##reg(dev->pfvf)), \
		(val), (start_bit), (end_bits))))

#define SET_PEXP_REGISTER_VAL(dev,reg,val,start_bit,end_bits) \
	(cvm_write_csr(CVMX_PEXP_NQM_VFX_##reg(dev->pfvf), \
		SET_BITS(cvm_read_csr(CVMX_PEXP_NQM_VFX_##reg(dev->pfvf)), \
		(val), (start_bit), (end_bits))))

#define SET_PEXP_REGISTER_VAL32(dev,reg,val,start_bit,end_bits) \
	(cvm_write_csr32(CVMX_PEXP_NQM_VFX_##reg(dev->pfvf), \
		SET_BITS(cvm_read_csr32(CVMX_PEXP_NQM_VFX_##reg(dev->pfvf)), \
		(val), (start_bit), (end_bits))))

/* PRP Related */
#define PRP_ENTRY_SIZE                      sizeof(uint64_t *)
#define BAD_ALLIGNMENT                      0x13
#define LIST_TRANSFER                       1       /* Transfer of PRP list to local memory from host */
#define PRP_PHY_PAGE_ADDR(prp, dev) \
    (prp & ~((uint64_t)(dev->host_page_size - 1)))  /*Page Base Address*/
#define PRP_PHY_PAGE_OFFSET(prp, dev) \
    (prp & ((uint64_t)(dev->host_page_size - 1)))   /*Offset*/
#define PRP_PHYSICAL_ADD(prp, dev) (prp)            /*DMA Host address*/

/* Control Reg Reset */
#define NVME_INTMS_RESET                    0x00
#define NVME_INTMC_RESET                    0x00
#define NVME_CC_IOSQES_RESET                0x0000
#define NVME_CC_IOCQES_RESET                0x0000
#define NVME_CC_SHN                         0x00
#define NVME_CC_AMS_RESET                   0x000
#define NVME_CC_MPS_RESET                   0x0000
#define NVME_CC_EN_RESET                    0x00
#define NVME_CSTS_SHST_RESET                0x00
#define NVME_CSTS_RDY_RESET                 0x00
#define NVME_NSSR_RESET                     0x00
#define NVME_CC_CSS_RESET                   0x0000

/* Controller Capabilities (cap) */
#define NVME_CAP_MQES_DEF                   0x1000   /* Maximum 2048 entries per queue */
#define NVME_CAP_MPSMIN_DEF                 0x0     /* Minimum 4KB host page size */
#define NVME_CAP_MPSMAX_DEF                 0x1     /* Maximum 8KB host page size */
#define NVME_CAP_NSSRS_DEF                  1
#define NVME_CAP_TIMEOUT_DEF                0x02
#define NVME_CAP_CSS_DEF                    0x01
#define NVME_CAP_CQR_DEF                    1

/* Version default values (vs) */
#define NVME_VERSION_DEF                    0x10100 /* VS Value for 1.1 Compliant Controllers */

/* Register default values */

//Controller Capabilities (cap)
#define NVME_CAP_MQES(cap)      ((cap) & 0xffff)        /* Max queue entries supported */
#define NVME_CAP_MPSMIN(cap)    (((cap) >> 48) & 0xf)   /* Memory Page Size Max */
#define NVME_CAP_MPSMAX(cap)    (((cap) >> 52) & 0xf)   /* Memory Page Size Max */
#define NVME_CAP_NSSRS(cap)     (((cap) >> 36) & 0x1)   /* NVM Subsystem Reset */
#define NVME_CAP_TIMEOUT(cap)   (((cap) >> 24) & 0xff)  /* Timeout */
#define NVME_REG_BASE_ADDRESS               0x0000
#define NVME_OFFSET                         0x20001

/* Controller Configuration (cc) */
#define NVME_SUBSYSTEM_RESET                0x4E564D65
#define NVME_DOORBELL_OFFSET                0x1000
#define NVME_REG_CAP                        0x0000
#define NVME_REG_VS                         0x0008
#define NVME_REG_INTMS                      0x000C
#define NVME_REG_INTMC                      0x0010
#define NVME_REG_CC                         0x0014
#define NVME_REG_RESERVE                    0x0018
#define NVME_REG_CSTS                       0x001C
#define NVME_REG_NSSR                       0x0020
#define NVME_REG_AQA                        0x0024
#define NVME_REG_ASQ                        0x0028
#define NVME_REG_ACQ                        0x0030

/* Purpose: NVMe control register value bit offsets */
enum {
    NVME_CC_ENABLE                      = (1 << 0),
    NVME_CC_CSS_NVM                     = 0 << 4,
    NVME_CC_MPS_SHIFT               = 7,
    NVME_CC_ARB_RR                      = 0 << 11,
    NVME_CC_ARB_WRRU                    = 1 << 11,
    NVME_CC_ARB_VS                      = 7 << 11,
    NVME_CC_SHN_NONE                    = 0 << 14,
    NVME_CC_SHN_NORMAL                  = 1 << 14,
    NVME_CC_SHN_ABRUPT                  = 2 << 14,
    NVME_CC_SHN_MASK                    = 3 << 14,
    NVME_CC_IOSQES                      = 6 << 16,
    NVME_CC_IOCQES                      = 4 << 20,
    NVME_CSTS_RDY                       = 1 << 0,
    NVME_CSTS_CFS                       = 1 << 1,
    NVME_CSTS_SHST_NORMAL           = 0 << 2,
    NVME_CSTS_SHST_OCCURRING        = 1 << 2,
    NVME_CSTS_SHST_COMPLETE         = 2 << 2,
    NVME_CSTS_SHST_MASK                 = 3 << 2,
};

/* NVMe feature identifiers */
enum {
    NVME_FEAT_ARBITRATION   = 0x01,
    NVME_FEAT_POWER_MGMT    = 0x02,
    NVME_FEAT_LBA_RANGE             = 0x03,
    NVME_FEAT_TEMP_THRESH   = 0x04,
    NVME_FEAT_ERR_RECOVERY  = 0x05,
    NVME_FEAT_VOLATILE_WC   = 0x06,
    NVME_FEAT_NUM_QUEUES    = 0x07,
    NVME_FEAT_IRQ_COALESCE  = 0x08,
    NVME_FEAT_IRQ_CONFIG    = 0x09,
    NVME_FEAT_WRITE_ATOMIC  = 0x0a,
    NVME_FEAT_ASYNC_EVENT   = 0x0b,
    NVME_FEAT_AUTOPWR_TRANS = 0x0c,
};

/* Asynchronous related */
#define AET_ERROR_STATUS                    0x00
#define AET_SMART_HEALTH_STATUS             0x01
#define MAX_AERL                            0x08
#define   ERROR_BIT                         0x01
#define   SMART_BIT                         0x02

/* Other definitions */
#define NVME_SQ_TAIL_DB_OFFSET              0x1000
#define ASYNCHRONOUS_EVENT_REQUEST_LIMIT    0x05
#define NVME_CMD_POOL                       CPL_QUEUE_UPDATE_POOL
#define MAX_SUPPORTED_LBAF                  16
#define IDENTIFY_DS_SIZE                    4096          /* Identify structure size */
#define POLL_LIST_SIZE                      (4 * 1024)
#define MAX_CTRL_CONFIG_REG_OFFSET          0x30
#define BAR_SIZE                            (1ull << 26)    /* 64MB */
#define MEM_ALLIGNMENT                      (1ull << 26)    /* 64MB */
#define ULL                                 unsigned long long

// MAX_SQUEUES and MAX_CQUEUES are for nvme emulation
#define NVME_MAX_SUB_QS                     16
#define NVME_MAX_CPL_QS                     16

#define NVME_REG_SIZE \
    ((MAX_SQUEUES * 4) + (MAX_CQUEUES * 4) + NVME_SQ_TAIL_DB_OFFSET)
#define GEN_SECTOR_SIZE                     512
#define MAX_DEV_CONFIG                      0x02
#define MAX_ABORT_CMDS                      256
#define CMDID_INVALID                       0xffffffffull

/* NVMe queue related */
#define SUBQUEUE_ENTRY_SIZE                 64  /* Submission queue entry size */
#define COMPLETIONQUEUE_ENTRY_SIZE          16  /* Completion queue entry size */
#define MAX_SQUEUES                         1024
#define MAX_CQUEUES                         1024
#define MAX_SQ_DEPTH                        4096
#define MAX_CPLQ_SIZE                       4096
#define DEFAULT_CPLQ_SIZE                   128

/* Host side dis-contiguous queue support */
#define DISCONTIGUOUS_Q_SUPPORT             1

/* NVMe status code types */
#define SCT_GENERIC                         0
#define SCT_COMMAND                         1
#define SCT_MEDIA                           2

/* NVMe generic status codes */
#define CMD_SUCCESSFUL                      0x00
#define INVALID_FIELD_CMD                   0x02
#define DATA_TRANSFER_ERR                   0x04
#define INTERNAL_ERROR                      0x06
#define INVALID_OPCODE                      0x01
#define INVALID_NAMESPACE                   0x0B
#define LBA_OUT_OF_RANGE                    0x80
#define ABORT_REQUESTED                     0x07
#define SQ_DELETION_ABORT                   0x08

/* NVMe Command specific status codes */
#define Q_SZ_EXCEEDED                       2       /* Maximum queue size exceeded */
#define INVALID_QID                         1       /* The qid is invalid */
#define INVALID_CQID                        0       /* Completion queue id invalid */
#define  INVALID_QDELETION                  0x0C    /* Associated I/O Sub queue is in use */
#define FEATURE_NOT_CHANGEABLE              0x0E
#define INVALID_IV                          0x08
#define INVALID_LOG_PAGE                    0x09
#define COMPARE_FAILURE                     0x85
#define FAILED_FUSED_CMD                    0x09
#define MISSING_FUSED_CMD                   0x0A
#define ABORT_LIMIT_EXCEEDED                0x03


//Asynchronous event information error codes
#define INVALID_DB_REGISTER                 0x00
#define INVALID_DB_WRITE                    0x01
#define PERSISTENT_INTERNAL_DEVICE_ERROR    0x03
#define TRANSIENT_INTERNAL_DEVICE_ERROR     0x04

/* Completion Queue Entry: Status Field */
#define STATUS_GENERIC(status, SC, M, \
                       DNR) (status |= (SC << 1) | (M << 14) | (DNR << 15))
#define STATUS_COMMAND(status, SC, M,                                        \
                       DNR) (status |= (SC << 1) | (M << 14) | (DNR << 15) | \
                                       (1 << 9))
#define STATUS_MEDIA(status, SC, M,                                          \
                     DNR)   (status |= (SC << 1) | (M << 14) | (DNR << 15) | \
                                       (0x2 << 9))
#define ASYNC_EVENT(dword0, AET, AEI, \
                    ALP)    (dword0 = (AET) | (AEI << 8) | (ALP << 16))

#define ERR_LOG_SIZE                        3
#define SMART_LOG_SIZE                      10
#define FIRMWARE_LOG_SIZE                   10

/* Identify command specific */
#define IDENTIFY_NAMESPACE                  0
#define IDENTIFY_CONTROLLER                 1
#define NAMESPACE_LIST                      2

/* Get stats command specific */
#define GET_STATS_NS                        0
#define GET_STATS_IOQ                       1
#define GET_STATS_ADMINQ                    2
#define CLEAR_STATS_NS                      3
#define CLEAR_STATS_IOQ                     4
#define CLEAR_STATS_ADMINQ                  5

/* Endian conversion macros */
#define le16_cpu(x)          \
    ((((x) & 0xff00) >> 8) | \
     (((x) & 0x00ff) << 8))

#define le32_cpu(x)               \
    ((((x) & 0xff000000) >> 24) | \
     (((x) & 0x00ff0000) >> 8) |  \
     (((x) & 0x0000ff00) << 8) |  \
     (((x) & 0x000000ff) << 24))

#define le64_cpu(x, sfx)                         \
    ((((x) & 0xff00000000000000 ## sfx) >> 56) | \
     (((x) & 0x00ff000000000000 ## sfx) >> 40) | \
     (((x) & 0x0000ff0000000000 ## sfx) >> 24) | \
     (((x) & 0x000000ff00000000 ## sfx) >> 8) |  \
     (((x) & 0x00000000ff000000 ## sfx) << 8) |  \
     (((x) & 0x0000000000ff0000 ## sfx) << 24) | \
     (((x) & 0x000000000000ff00 ## sfx) << 40) | \
     (((x) & 0x00000000000000ff ## sfx) << 56))

// define macros for read and write csrs with 32 bit data, 64 bit address
#define cvm_read_csr32(s) cvmx_read64_uint32((s)^4)
#define cvm_write_csr32(s, d) cvmx_write64_uint32(((s)^4), d)

/* Data structures */

/* Purpose:Used for passing NVMe register read/writeinfo to the polling code */
struct nvme_reg_update {
    volatile uint32_t   access_type;        /* 0  Read; 1 - Write */
    volatile uint32_t   access_offset;      /* register offsets as defined in NVMe spec section 3.1 */
};

/* Purpose: Used for polling NVMe controller and doorbell registers */
struct nvme_reg_poll {
    volatile uint32_t               tail __attribute__ ((aligned(32)));     /* tail of the polling ring buffer where updates are written to */
    volatile uint32_t               head  __attribute__ ((aligned(32)));    /* head of the polling ring buffer where from updates are to be read */
    volatile struct nvme_reg_update cir_buf[POLL_LIST_SIZE];                /* polling ring buffer */
};

/* Purpose: Used for maintaining round robin scheduling information */
struct  nvme_rrlist_process {
    uint16_t    nvme_sq_set_cnt;
    uint32_t    current_index;
    uint8_t     current_offset;
    uint64_t    nvme_sq_list[MAX_SQUEUES / 64];
};

/* Purpose: Asynchronous event response structure */
struct async_event_result {
    uint16_t    aet     : 3;
    uint16_t    rsvd1   : 5;
    uint16_t    aei     : 8;
    uint16_t    alp     : 8;
    uint16_t    rsvd2   : 8;
};

/* Purpose: Asynchronous event request queueing structure */
struct req_arr {
    uint16_t    cid;
    uint16_t    in_use;
};

/* Purpose: Asynchronous event information */
struct async_event_info {
    struct req_arr              async_req_arr[MAX_AERL];
    uint32_t                    req_tail;
    uint32_t                    req_head;
    struct async_event_result   error_queue [MAX_AERL];
    struct async_event_result   smart_queue [MAX_AERL];
    uint32_t                    resp_tail;
    uint32_t                    error_head;
    uint32_t                    error_tail;
    uint32_t                    smart_head;
    uint32_t                    smart_tail;
    uint8_t                     Is_error_Masked;
    uint8_t                     Is_smart_Masked;
    uint8_t                     event_type;
};

/* Purpose: Used for conveying the queue no, start entry index and the no. of entries as part of a command transfer */
struct nvme_cmd_transfer {
    uint16_t    qid;                    /* submission queue ID */
    uint16_t    q_entry;                /* start of updated entry */
    uint16_t    entry_count;            /* no. of updated entries */
    uint16_t    rsvd;                   /* reserved */
};

/* Purpose: List node structure */
struct nvme_list {
    void *              data;
    struct list_head    list;
};

/* Purpose: Used for maintaining information about an NVMe submission queue */
struct nvme_sub_queue {
    struct          nvme_cmd *  sq_cmds;                                /* base address of the submission queue */
    struct          nvme_cmd *  host_sub_queue_addr;                    /* base address of the corresponding host queue */
    uint32_t                        sq_head __attribute__ ((aligned(32))); /* head of sub queue; pending for processing */
    uint32_t                        sq_tail __attribute__ ((aligned(32))); /* tail of sub queue; last read entry from host */
    uint16_t                        sq_depth;                              /* no. of submission entries in the queue */
    uint16_t                        sq_depth_mask;
    uint16_t                        sq_id;                                 /* queue ID (0 to max supported queues) */
    uint16_t                        cq_id;                                 /* corresponding completion queue ID */
    uint64_t                        cmd_id_bitmask[MAX_SQ_DEPTH/64];
    uint64_t                        cmd_id_arr[MAX_SQ_DEPTH] __attribute__ ((aligned(64)));
                                                                           /* queue context used by storage layer */
    uint32_t                        marked_for_deletion __attribute__ ((aligned(32)));
                                                                           /* flag to check the queue is marked for deletion or not */
    uint32_t                        num_entries __attribute__ ((aligned(32)));  /* to keep track of the number of entries in the queue */
#ifdef NVME_68XX_SUPPORT
    uint8_t                         sqhead_flags[MAX_SQ_DEPTH];
#endif
    struct nvme_list                cmp_cmd_list;                          /* List to keep the compare command */
#if DISCONTIGUOUS_Q_SUPPORT
    uint8_t                         queue_discontiguous;                        /* The host side queue is dis-contiguous or not */
#endif
    uint32_t                        gsq_id;
};

/* Purpose: NVMe command completion entry format. */
struct nvme_completion {
    uint32_t    result;         /* Used by admin commands to return data */
    uint32_t    rsvd;           /* reserved */
    uint16_t    sqhead;        /* how much of this queue may be reclaimed */
    uint16_t    sqid;          /* submission queue that generated this entry */
    uint16_t    cmdid;     /* of the command which completed */
    uint16_t    status;         /* did the command fail, and if so, why */
};

struct nvme_cn73xx_completion {
    uint32_t    rsvd;           /* reserved */
    uint32_t    result;         /* Used by admin commands to return data */
    uint16_t    status;         /* did the command fail, and if so, why */
    uint16_t    cmdid;     /* of the command which completed */
    uint16_t    sqid;          /* submission queue that generated this entry */
    uint16_t    sqhead;        /* how much of this queue may be reclaimed */
};
/* Purpose: NVMe command completion status field format. */
struct completion_status_field {
    uint16_t    dnr     : 1;    /* do not retry bit */
    uint16_t    m       : 1;    /* more bit */
    uint16_t    rsvd    : 2;    /* reserved */
    uint16_t    sct     : 3;    /* status code type */
    uint16_t    sc      : 8;    /* status code */
    uint16_t    p       : 1;    /* phase bit */
};

/* Purpose: Used for maintaining information about NVMe completion queue */
struct nvme_cpl_queue {
    struct nvme_completion *cqes;                                   /* base address of the completion queue */
    struct nvme_completion *host_cpl_queue_addr;                    /* base address of the corresponding host queue */
    cvmx_rwlock_wp_lock_t   cq_lock;
    uint16_t                cq_id;                                  /* queue ID (0 to max supported queues) */
    uint16_t                cq_tail;                                /* tail of completion queue; last written entry to host */
    volatile uint32_t       cq_head __attribute__ ((aligned(32)));  /* head of completion queue; last read entry by host */
    uint16_t                cq_depth;                               /* no. of completion entries in the queue */
    uint32_t                pending_entries;
    uint16_t                associated_subq_count;
    struct nvme_list        cpl_list;
    uint32_t                cq_full;            /* flag to check CQ full condition */
    struct nvme_list        associated_list;    /* list of sub queues associated with a completion queue */
    uint32_t                associated_sq_count;
#if DISCONTIGUOUS_Q_SUPPORT
    uint8_t                 queue_discontiguous; /* The host side queue is dis contiguous or not */
#endif
};

/* Purpose: Used to create completion queue entry for a command completion */
struct cpl_queue_update {
    struct nvme_cpl_queue * cq;         /* pointer to the corresponding completion queue */
    struct nvme_completion  cqes;       /* should be a member and not a pointer - to the completion entry structure */
};

/* Purpose: Used to specify the DMA mode, transfer purpose and direction */
struct trans_type {
    uint16_t    dma_mode        : 1;    /* outbound/inbound */
    uint16_t    dma_buffer_type : 1;    /* 0 - default, 1 -dma-buffers */
    uint16_t    prp_mode        : 6;    /* PRP mode; 0 � NO PRP, 1 � PRP NO LIST, 2 � PRP LIST */
    uint16_t    cpl_transfer    : 1;    /* set if completion queue DMA request */
    uint16_t    rsvd            : 7     /* reserved */;
    uint32_t    num_st_ptrs;            /* Count of local pointers used */
};

/* Purpose: Used for passing the last pointer information for DMA */
struct lastptr {
    uint64_t    prp1;                   /* PRP1 address from the command */
    uint64_t    prp2;                   /* PRP2 or PRP list address */
    uint32_t    no_of_entries;          /* no. of entries to transfer as part of one instruction */
};

/* Purpose: Used to indicates DMA transfer information  */
struct nvme_dma {
    uint64_t            src;            /* Source address */
    uint64_t            dst;            /* Destination address */
    uint32_t            nbytes;         /* no. of bytes to transfer */
    struct trans_type   trans_type;     /* DMA transfer type */
    struct lastptr      lastptr;        /* PRP pointers/list based on the trans_type.prp_mode bits */
    uint32_t next_free_segment; /* Valid only if trans_type.dma_buffer_type = 1 */
    char *              byte_pointer;
};

/* Purpose:Used to provide queue and entry information */
struct nvme_queue_info {
    uint16_t    qid;            /* Queue ID */
    uint16_t    q_entry;        /* Entry index in the queue */
};

/* Purpose: Used to track PRP list transfers from host to device */
struct prp_list_transfer_info {
    struct nvme_cmd *   cmd;                /* command under process */
    struct nvme_queue_info  queue_info;         /* queue information of the command */
    uint32_t                entries_remaining;  /* number of prp entries to be transferred */
    uint64_t                first_lmp;          /* pointer to the first local page with PRP list */
    uint64_t                curr_lmp;           /* pointer to the first local page with PRP list */
    uint32_t                num_entry_xferd;    /* number of PRP lists transferred */
};

/* Purpose: NVMe common Admin command specific structure. */
struct nvme_cmd_common {
#ifdef __BIG_ENDIAN_BITFIELD
    uint32_t    nsid;
    uint16_t    cmdid;
    uint8_t     flags;
    uint8_t     opc;
    uint32_t    cdw1[2];
    uint64_t    mptr;
    uint64_t    prp1;
    uint64_t    prp2;
    uint32_t    cdw2[6];
#else
    uint8_t     opc;
    uint8_t     flags;
    uint16_t    cmdid;
    uint32_t    nsid;
    uint32_t    cdw1[2];
    uint64_t    mptr;
    uint64_t    prp1;
    uint64_t    prp2;
    uint32_t    cdw2[6];
#endif
};

/*Purpose: NVMe Admin identify command specific structure. */
struct nvme_cmd_identify {
#ifdef __BIG_ENDIAN_BITFIELD
    uint32_t    nsid;
    uint16_t    cmdid;
    uint8_t     flags;
    uint8_t     opc;
    uint64_t    rsvd1[2];
    uint64_t    prp1;
    uint64_t    prp2;
    uint32_t    rsvd2;
    uint32_t    cns;
    uint32_t    rsvd3[4];
#else
    uint8_t     opc;
    uint8_t     flags;
    uint16_t    cmdid;
    uint32_t    nsid;
    uint64_t    rsvd1[2];
    uint64_t    prp1;
    uint64_t    prp2;
    uint32_t    cns;
    uint32_t    rsvd2[5];
#endif
};

/*Purpose: NVMe Admin get log page command specific structure. */
struct nvme_cmd_get_log_page {
#ifdef __BIG_ENDIAN_BITFIELD
    uint32_t    nsid;
    uint16_t    cmdid;
    uint8_t     flags;
    uint8_t     opc;
    uint64_t    rsvd1[2];
    uint64_t    prp1;
    uint64_t    prp2;
    uint32_t    rsvd2;
    uint32_t    lpi;
    uint32_t    rsvd3[4];
#else
    uint8_t     opc;
    uint8_t     flags;
    uint16_t    cmdid;
    uint32_t    nsid;
    uint64_t    rsvd1[2];
    uint64_t    prp1;
    uint64_t    prp2;
    uint32_t    lpi;
    uint32_t    rsvd2[5];
#endif
};

/*Purpose: NVMe Admin Asynchronous Event Request command specific structure. */
struct nvme_cmd_async_event_request {
#ifdef __BIG_ENDIAN_BITFIELD
    uint32_t    nsid;
    uint16_t    cmdid;
    uint8_t     flags;
    uint8_t     opc;
    uint64_t    rsvd1[7];
#else
    uint8_t     opc;
    uint8_t     flags;
    uint16_t    cmdid;
    uint32_t    nsid;
    uint64_t    rsvd1[7];
#endif
};

/* Purpose: NVMe Admin features specific structure. */
struct nvme_cmd_features {
#ifdef __BIG_ENDIAN_BITFIELD
    uint32_t    nsid;
    uint16_t    cmdid;
    uint8_t     flags;
    uint8_t     opc;
    uint64_t    rsvd1[2];
    uint64_t    prp1;
    uint64_t    prp2;
    uint32_t    dword;
    uint32_t    fid;
    uint32_t    rsvd2[4];
#else
    uint8_t     opc;
    uint8_t     flags;
    uint16_t    cmdid;
    uint32_t    nsid;
    uint64_t    rsvd1[2];
    uint64_t    prp1;
    uint64_t    prp2;
    uint32_t    fid;
    uint32_t    dword;
    uint32_t    rsvd2[4];
#endif
};

/* Purpose: NVMe Admin CREATE_COMPLETION_QUEUE command specific structure. */
struct nvme_cmd_create_cq {
#ifdef __BIG_ENDIAN_BITFIELD
    uint32_t    rsvd;
    uint16_t    cmdid;
    uint8_t     flags;
    uint8_t     opc;
    uint32_t    rsvd1[4];
    uint64_t    prp1;
    uint64_t    rsvd2;
    uint16_t    vector;
    uint16_t    q_flags;
    uint16_t    qsize;
    uint16_t    qid;
    uint32_t    rsvd3[4];
#else
    uint8_t     opc;
    uint8_t     flags;
    uint16_t    cmdid;
    uint32_t    rsvd1[5];
    uint64_t    prp1;
    uint64_t    rsvd2;
    uint16_t    qid;
    uint16_t    qsize;
    uint16_t    q_flags;
    uint16_t    vector;
    uint32_t    rsvd3[4];
#endif
};

/* Purpose: NVMe Admin CREATE_SUBMISSION_QUEUE command specific structure. */
struct nvme_cmd_create_sq {
#ifdef __BIG_ENDIAN_BITFIELD
    uint32_t    rsvd;
    uint16_t    cmdid;
    uint8_t     flags;
    uint8_t     opc;
    uint32_t    rsvd1[4];
    uint64_t    prp1;
    uint64_t    rsvd2;
    uint16_t    cqid;
    uint16_t    q_flags;
    uint16_t    qsize;
    uint16_t    qid;
    uint32_t    rsvd3[4];
#else
    uint8_t     opc;
    uint8_t     flags;
    uint16_t    cmdid;
    uint32_t    rsvd1[5];
    uint64_t    prp1;
    uint64_t    rsvd2;
    uint16_t    qid;
    uint16_t    qsize;
    uint16_t    q_flags;
    uint16_t    cqid;
    uint32_t    rsvd3[4];
#endif
};

/* Purpose: NVMe Admin DELETE_QUEUE command specific structure. */
struct nvme_cmd_delete_queue {
#ifdef __BIG_ENDIAN_BITFIELD
    uint32_t    rsvd;
    uint16_t    cmdid;
    uint8_t     flags;
    uint8_t     opc;
    uint32_t    rsvd1[9];
    uint16_t    rsvd10;
    uint16_t    qid;
    uint32_t    rsvd3[4];
#else
    uint8_t     opc;
    uint8_t     flags;
    uint16_t    cmdid;
    uint32_t    rsvd1[9];
    uint16_t    qid;
    uint16_t    rsvd10;
    uint32_t    rsvd2[5];
#endif
};

/* Purpose: NVMe Admin COMMAND_ABORT command specific structure. */
struct nvme_cmd_abort {
#ifdef __BIG_ENDIAN_BITFIELD
    uint32_t    rsvd;
    uint16_t    cmdid;
    uint8_t     flags;
    uint8_t     opc;
    uint32_t    rsvd1[9];
    uint16_t    cid;
    uint16_t    sqid;
    uint32_t    rsvd2[4];
#else
    uint8_t     opc;
    uint8_t     flags;
    uint16_t    cmdid;
    uint32_t    rsvd1[9];
    uint16_t    sqid;
    uint16_t    cid;
    uint32_t    rsvd2[5];
#endif
};

/* Purpose: NVMe IO command specific structure. */
struct nvme_cmd_rw {
#ifdef __BIG_ENDIAN_BITFIELD
    uint32_t    nsid;
    uint16_t    cmdid;
    uint8_t     flags;
    uint8_t     opc;
    uint64_t    rsvd1;
    uint64_t    mptr;
    uint64_t    prp1;
    uint64_t    prp2;
    uint64_t    slba;
    uint32_t    dsm;
    uint16_t    ctrl;
    uint16_t    len;
    uint16_t    elbat;
    uint16_t    elbatm;
    uint32_t    eilbrt;
#else
    uint8_t     opc;
    uint8_t     flags;
    uint16_t    cmdid;
    uint32_t    nsid;
    uint64_t    rsvd1;
    uint64_t    mptr;
    uint64_t    prp1;
    uint64_t    prp2;
    uint64_t    slba;
    uint16_t    len;
    uint16_t    ctrl;
    uint32_t    dsm;
    uint32_t    eilbrt;
    uint16_t    elbatm;
    uint16_t    elbat;
#endif
};

/* Purpose: 64 bytes NVMe command structure defined as union. */
struct nvme_cmd {
    union {
        struct nvme_cmd_common      common;
        struct nvme_cmd_rw          rw;
        struct nvme_cmd_identify            identify;
        struct nvme_cmd_features            features;
        struct nvme_cmd_create_cq           create_cq;
        struct nvme_cmd_create_sq           create_sq;
        struct nvme_cmd_delete_queue        delete_queue;
        struct nvme_cmd_abort               abort;
        struct nvme_cmd_get_log_page        get_log_page;
        struct nvme_cmd_async_event_request async_evt_req;
    };
};

/* Purpose: Used for Maintaing information about all NVMe queues */
struct nvme_queue {
    struct nvme_dev *dev;                /* back pointer to the nvme_dev structure */
    struct nvme_sub_queue *sq[NVME_MAX_SUB_QS + 1]; /* array of pointers to submission *
                                                   * queue structures */
    struct nvme_cpl_queue *cq[NVME_MAX_CPL_QS + 1]; /* array of pointers to completion
                                                   * queue structures */
    uint32_t cpl_queue_count;    /* last created completion queue id. */
    uint32_t sub_queue_count;    /* last created submission queue id */
    uint16_t max_cpl_queues;     /* maximum supported completion queues */
    uint16_t max_sub_queues;     /* maximum supported submission queues */
    uint64_t base_addr_sq_cmds;  /* Base address of submission queue commands */
    uint64_t base_addr_cq_cmds;  /* Base address of completion queue commands */
    uint64_t base_addr_sq_struct;/* Base address of submission queue structure */
    uint64_t base_addr_cq_struct;/* Base address of completion queue structure */
    struct nvme_cmd_abort abort_arr[MAX_ABORT_CMDS];
};

//Purpose: Work entry formats for NVMe feature
/*QWORD 0*/
typedef union {
    uint64_t u64;

#ifdef __BIG_ENDIAN_BITFIELD
    struct {
        uint64_t    rsvd2   : 20;
        uint64_t    port    : 12;
        uint64_t    lcmdid  : 32;
    } qw0;
#else
    struct {
        uint64_t    lcmdid  : 32;
        uint64_t    port    : 12;
        uint64_t    rsvd2   : 20;
    } qw0;
#endif
} cvmx_wqe_qword0_t;

/*QWORD 1*/
typedef union {
    uint64_t u64;

#ifdef __BIG_ENDIAN_BITFIELD
    struct {
        uint64_t    rsvd1   : 20;
        uint64_t    grp     : 10;
        uint64_t    tt      : 2;
        uint64_t    tag     : 32;
    } qw1;
#else
    struct {
        uint64_t    tag     : 32;
        uint64_t    tt      : 2;
        uint64_t    grp     : 10;
        uint64_t    rsvd1   : 20;
    } qw1;
#endif
} cvmx_wqe_qword1_t;

/*QWORD 2*/
typedef union {
    uint64_t u64;
    /**
     *  Analyze the bit pattern image file supplied by the customer and
     *       declare structure members accordingly.
     */

#ifdef __BIG_ENDIAN_BITFIELD
    struct {
        uint64_t    rsvd1       : 22;
        uint64_t    fuse_ptr    : 42;
    } qw2;
#else

    struct {
        uint64_t    fuse_ptr    : 42;
        uint64_t    rsvd1       : 22;
    } qw2;
#endif
} cvmx_wqe_qword2_t;

/*QWORD 3*/
typedef union {
    uint64_t u64;

#ifdef __BIG_ENDIAN_BITFIELD
    struct {
        uint64_t    rsvd3   : 8;
        uint64_t    hw_err  : 8;
        uint64_t    rsvd2   : 24;
        uint64_t    sq_id   : 8;
        uint64_t    rsvd1   : 4;
        uint64_t    vf      : 12;
    } qw3;
#else

    struct {
        uint64_t    vf      : 12;
        uint64_t    rsvd1   : 4;
        uint64_t    sq_id   : 8;
        uint64_t    rsvd2   : 24;
        uint64_t    hw_err  : 8;
        uint64_t    rsvd3   : 8;
    } qw3;
#endif
} cvmx_wqe_qword3_t;

/*QWORD 4*/
typedef union {
    uint64_t u64;
    /**
     *  Add pre-compile time selection of qw4 based on
     *       68XX_HRM or 73XX_HRM. WQE structure member sizes for 68XX and 73XX
     *       are different for QW4.
     */
#ifdef NVME_68XX_SUPPORT
#ifdef __BIG_ENDIAN_BITFIELD
    struct {
        uint64_t    rsvd4       : 4;
        uint64_t    sq_ptr      : 12;
        uint64_t    rsvd3       : 5;
        uint64_t    sq_credit   : 11;
        uint64_t    rsvd2       : 5;
        uint64_t    sq_tail     : 11;
        uint64_t    rsvd1       : 5;
        uint64_t    sq_head     : 11;
    } qw4;
#else
    struct {
        uint64_t    sq_head     : 11;
        uint64_t    rsvd1       : 5;
        uint64_t    sq_tail     : 11;
        uint64_t    rsvd2       : 5;
        uint64_t    sq_credit   : 11;
        uint64_t    rsvd3       : 5;
        uint64_t    sq_ptr      : 12;
        uint64_t    rsvd4       : 4;
    } qw4;
#endif          /* __BIG_ENDIAN_BITFIELD */

#elif defined(OCTEON_CN7XXX)
#ifdef __BIG_ENDIAN_BITFIELD
    struct {
        uint64_t    rsvd3       : 21;
        uint64_t    sq_credit   : 11;
        uint64_t    rsvd2       : 5;
        uint64_t    sq_tail     : 11;
        uint64_t    rsvd1       : 3;
        uint64_t    sq_head     : 13;
    } qw4;
#else
    struct {
        uint64_t    sq_head     : 13;
        uint64_t    rsvd1       : 3;
        uint64_t    sq_tail     : 11;
        uint64_t    rsvd2       : 5;
        uint64_t    sq_credit   : 11;
        uint64_t    rsvd3       : 21;
    } qw4;
#endif          /* __BIG_ENDIAN_BITFIELD */
#endif          /* OCTEON_CN7XXX         */
} cvmx_wqe_qword4_t;

typedef struct {
    uint64_t u64;
} cvmx_wqe_qword5_t;

typedef struct {
    uint64_t u64;
} cvmx_wqe_qword6_t;

typedef struct {
    cvmx_wqe_qword0_t   word0;      /*qword 0*/
    cvmx_wqe_qword1_t   word1;      /*qword 1*/
    cvmx_wqe_qword2_t   word2;      /*qword 2*/
    cvmx_wqe_qword3_t   word3;      /*qword 3*/
    cvmx_wqe_qword4_t   word4;      /*qword 4*/
    cvmx_wqe_qword5_t   word5;      /*qword 5*/
    cvmx_wqe_qword6_t   word6;      /*qword 6*/
    uint64_t            reserved;   /*qword 7: reserved*/
    struct nvme_cmd     nvme_cmd;   /*qword 8-15 : 8 * 8 bytes = 64 bytes*/
} CVMX_CACHE_LINE_ALIGNED cvmx_wqe_tt;

/* Purpose: NVMe  I/O command opcodes. */
enum nvme_opc {
    nvme_cmd_flush  = 0x00,
    nvme_cmd_write  = 0x01,
    nvme_cmd_read   = 0x02,
    nvme_cmd_compare= 0x05,
};

enum nvme_fused {
    normal_operation = 0x0,
    fused_first_command = 0x01,
    fused_second_command = 0x02,
};

/* Purpose: Used for indicating error log informations to report host. */
struct nvme_log_error {
    uint64_t    error_count __attribute__ ((aligned(32))); /* index of the error log */
    uint16_t    qid;                /* Sub queue associated with the error */
    uint16_t    cid;                /* command id associated */
    uint16_t    status_field;       /* status of completion */
    uint16_t    pe_loc;        /* exact byte & bit of the command which has a problem */
    uint64_t    lba;                /* associated LBA, if applicable */
    uint32_t    ns;                 /* associated name space, if applicable */
    uint8_t     vendor_spec;        /* vendor specific information */
};

struct nvme_log_smart {
    uint8_t     critical_warn;
    uint8_t     comp_temp[2];
    uint8_t     available_spare;
    uint8_t     spare_threshold;
    uint8_t     percent_used;
    uint8_t     rsvd1[26];
    uint8_t     data_units_read[16];
    uint8_t     data_units_written[16];
    uint8_t     host_read_cmds[16];
    uint8_t     host_write_cmds[16];
    uint8_t     ctrl_busy_time[16];
    uint8_t     power_cycles[16];
    uint8_t     power_on_hours[16];
    uint8_t     unsafe_shutdowns[16];
    uint8_t     media_di_errors[16];
    uint8_t     num_ele[16];
    uint32_t    warning_comp_temp_time;
    uint32_t    critical_comp_temp_time;
    uint16_t    temp_sensor[8];
    uint8_t     rsvd2[296];
};

struct nvme_log_firmware {
    uint8_t afi;
    uint8_t rsvd1[7];
    uint8_t frs1;
    uint8_t frs2;
    uint8_t frs3;
    uint8_t frs4;
    uint8_t frs5;
    uint8_t frs6;
    uint8_t frs7;
    uint8_t rsvd2[447];
};

/* Purpose: Used to save the context for each DMA transfer initiated for I/O. */
/* The pointer to this structure will be assigned to word5.uint64_t of the WQE IO_DATA_TRANSFER_TAG. */
/* TODO: Avoid multiple copies of the structure */

#include "sal_linux_bdev.h"

struct context_struct {
    uint64_t *  compare_buff;                   /* comparison buffer, phys for sal_linux */
    uint32_t    no_bytes_transd;                /* no of bytes transferred */
    uint32_t    num_data_bufs;
    uint64_t    *data_bufs;                     /* stored as phys */
    struct cvm_bdev_info bdev_info;
    uint64_t *prp_list;
    uint32_t    num_comp_bufs;
    uint16_t unused1;
    uint16_t nvme_completion_sc;                /* status code */
};

struct nvme_bar {
    uint64_t            cap;                        /* Controller Capabilities */
    uint32_t            vs;                         /* Version */
    volatile uint32_t   intms;                      /* Interrupt Mask Set */
    volatile uint32_t   intmc;                      /* Interrupt Mask Clear */
    volatile uint32_t   cc;                         /* Controller Configuration */
    uint32_t            rsvd1;                      /* Reserved */
    volatile uint32_t   csts;                       /* Controller Status */
    volatile uint32_t   nssr;                       /* Reserved */
    volatile uint32_t   aqa;                        /* Admin Queue Attributes */
    volatile uint64_t   asq;                        /* Admin SQ Base Address */
    volatile uint64_t   acq;                        /* Admin CQ Base Address */
};

/* Purpose: Power state data structure, defining the characteristics of a given power state */
struct nvme_ctrl_id_power_state {
    uint16_t    mp;                         /* centiwatts */
    uint8_t     rsvd1;
    uint8_t     flags;
    uint32_t    enlat;                          /* microseconds */
    uint32_t    exlat;                           /* microseconds */
    uint8_t     rrt;
    uint8_t     rrl;
    uint8_t     rwt;
    uint8_t     rwl;
    uint16_t    idlp;
    uint8_t     ips;
    uint8_t     rsvd2;
    uint16_t    actp;
    uint8_t     apw;
    uint8_t     rsvd3[9];
};

/* Purpose: NVMe command set specific LBA format */
struct nvme_ns_id_lbaf {
    uint16_t    ms;
    uint8_t     lbads;
    uint8_t     rp;
};

/* Purpose:NVMe command set specific identify controller structure. */
struct nvme_ctrl_id {
    uint16_t                    vid;
    uint16_t                    ssvid;
    char                        sn[20];
    char                        mn[40];
    char                        fr[8];
    uint8_t                     rab;
    uint8_t                     ieee[3];
    uint8_t                     cmic;
    uint8_t                     mdts;
    uint16_t                    cntlid;
    uint32_t                    ver;
    uint8_t                     rsvd1[172];
    uint16_t                    oacs;
    uint8_t                     acl;
    uint8_t                     aerl;
    uint8_t                     frmw;
    uint8_t                     lpa;
    uint8_t                     elpe;
    uint8_t                     npss;
    uint8_t                     avscc;
    uint8_t                     apsta;
    uint16_t                    wctemp;
    uint16_t                    cctemp;
    uint8_t                     rsvd2[242];
    uint8_t                     sqes;
    uint8_t                     cqes;
    uint8_t                     rsvd3[2];
    uint32_t                    nn;
    uint16_t                    oncs;
    uint16_t                    fuses;
    uint8_t                     fna;
    uint8_t                     vwc;
    uint16_t                    awun;
    uint16_t                    awupf;
    uint8_t                     nvscc;
    uint8_t                     rsvd4;
    uint16_t                    acwu;
    uint8_t                     rsvd5[2];
    uint32_t                    sgls;
    uint8_t                     rsvd6[1508];
    struct nvme_ctrl_id_power_state psd[32];
    uint8_t                     vs[1024];
};

/* Purpose:NVMe command set specific identifynamespace structure. */
struct nvme_ns_id {
    uint64_t            nsze __attribute__ ((aligned(128)));
    uint64_t            ncap;
    uint64_t            nuse;
    uint8_t             nsfeat;
    uint8_t             nlbaf;
    uint8_t             flbas;
    uint8_t             mc;
    uint8_t             dpc;
    uint8_t             dps;
    uint8_t             nmic;
    uint8_t             rescap;
    uint8_t             fpi;
    uint8_t             rsvd1;
    uint16_t            nawun;
    uint16_t            nawupf;
    uint16_t            nacwu;
    uint8_t             rsvd2[80];
    uint8_t             eui64[8];
    struct nvme_ns_id_lbaf lbaf[16];
    uint8_t             rsvd3[192];
    uint8_t             vs[3712];
};

struct nvme_dev_config {
    /* Configuration values for CAP register */
    uint64_t            cap_mqes    : 16;
    uint64_t            cap_cqr     : 1;
    uint64_t            cap_ams     : 2;
    uint64_t            cap_rsvd1   : 5;
    uint64_t            cap_to      : 8;
    uint64_t            cap_dstrd   : 4;
    uint64_t            cap_nssrs   : 1;
    uint64_t            cap_css     : 8;
    uint64_t            cap_rsvd2   : 3;
    uint64_t            cap_mpsmin  : 4;
    uint64_t            cap_mpsmax  : 4;
    uint64_t            cap_rsvd3   : 8;

    /* queue capabilities */
    /* queue attributes */
    uint8_t             io_cqes;                /* Completion queue entry size */
    uint8_t             io_sqes;                /* Submission queue entry size */
    uint16_t            max_sub_queues;
    uint16_t            max_cpl_queues;         /* max no. of completion queues; FEATURE */
    uint16_t            max_queue_entries;      /* max no. of entries in a queue CAP.MQES */

    /* identify structures */
    struct nvme_ctrl_id id_ctrl __attribute__ ((aligned(128)));
    uint32_t            max_number_ns;
    uint8_t             smart_ctrl;                     /* asynch smart log control FID=0x0B */
};

struct error_array {
    struct nvme_log_error   error_log_array [ERR_LOG_SIZE];
    uint32_t                top;
    bool                    queue_wrapped;
};

struct smart_array {
    struct nvme_log_smart   smart_log_array [SMART_LOG_SIZE];
    uint32_t                top;
    bool                    queue_wrapped;
};

struct firmware_array {
    struct nvme_log_firmware    firmware_log_array [FIRMWARE_LOG_SIZE];
    int                         top;
    bool                        queue_wrapped;
};

/*
 * Namespace control structure
 */

struct ns_ctrl {
    uint64_t    disk_size;   /* total disk size in sectors (each of size sector_size) */
    uint16_t    sector_size; /* size of an individual sector */
    uint32_t    ns_id;       /* name space ID */
    uint8_t	ns_type;
    union { // different storage implementations
        uint8_t *start_addr;  /* base address of ramdisk for namespace */
        uint8_t *bdev_info;
    };
    struct nvme_ns_id id_ns; /* live (ram) copy of nvme namespace descriptor */
};

typedef enum ns_type {
    NS_RAMDISK = 0,
    NS_BLKDISK
} ns_type_t;

struct sal_io_handlers {
    int         (*sal_do_io)(struct nvme_dev *, uint64_t *, cvmx_wqe_tt *);
    int         (*sal_complete_io)(struct nvme_dev *, cvmx_wqe_tt *);
};
struct sal_dev {
    struct ns_ctrl * ns_dir[MAX_NUMBER_NS_CTLR];  /* namespace directory per controller */
    struct sal_io_handlers io_handler[MAX_NUMBER_NS_CTLR];
    uint8_t     smart_info[512];
};

/* Purpose: Indicate whether the device is in ready or reset state */
typedef enum {
    SYSTEM_RESET = 0,
    SYSTEM_READY
}SYSTEM_STATE_T;

/* Purpose: Device specific private structure */
struct nvme_dev {
    int                         pfvf;                   // PF/VF logical number
    uint32_t                    old_cc;                 // previous copy of cc register to detect change
    struct nvme_ctrl_id *       id_ctrl;                /* NVMe controller identify */
    uint16_t                    host_page_size;         /* Host page size based on CC.MPS */
    uint16_t                    num_prp_per_host_page;  /* number of PRP entries in a host page */
    struct nvme_queue *         queue;                  /* NVMe queues common structure */
    struct async_event_info *   event_info;
    cvmx_spinlock_t             event_info_lock;
    struct nvme_stats_dma_mem   *stats_dma_mem;
    struct sal_dev              disk_dev;
    struct nvme_dev_config      dev_config;
#ifdef NVME_68XX_SUPPORT
    struct  nvme_rrlist_process nvme_rr_mgmt;
#endif
    struct error_array          eptr;
    struct smart_array          sptr;
    struct firmware_array       fware_ptr;
    uint16_t                    max_entries;
#if DISCONTIGUOUS_Q_SUPPORT
    uint64_t                    max_sq_entry_per_page;
    uint64_t                    max_cq_entry_per_page;
    uint64_t                    max_discontiguous_sq_size;
    uint64_t                    max_discontiguous_cq_size;
#endif
    uint32_t                    mbox_core; /* core number which handles the mailbox interrupt */
    int                         page_flag_set;
    uint32_t                    system_state __attribute__ ((aligned(32)));
    int32_t                     vf_active __attribute__ ((aligned(32)));
};

/*  Mail box shared data structure */
struct nvme_mbox_data {
    struct nvme_dev *   dev;   /*  nvme_dev structure */
    volatile uint32_t   head __attribute__ ((aligned(32)));
    volatile uint32_t   tail __attribute__ ((aligned(32)));
    volatile uint64_t   reg_offset[MBOX_SIZE]; /* Array to keep the register offset */
};

/* Purpose: Admin/IO Command type */
typedef enum {
    ADMIN_CMD = 0,
    IO_CMD
}CMD_TYPE_T;

/* Purpose: Code flow path indicator for DMA limit transfer */
typedef enum {
    SUBMISSION_PATH = 0,
    COMPLETION_PATH
}CODEPATH_TYPE_T;

/* Purpose: Structure to transfer bulk data using DMA, where in data size is not fixed over the DMA transfer invocations */

typedef struct dma_limit_trnsfer {
    uint32_t        transfer_cnt;       /* No. of packets to transfer */
    uint32_t        packet_size;        /* Packet size in bytes */
    uint64_t        source_addr;        /* Source Address of transfer */
    uint64_t        dest_addr;          /* Destination Address of transfer */
    uint16_t        queue_no;           /* Queue Number or commad ID */
    uint16_t        processed_entry;    /* Last processed entry */
    uint16_t        dma_mode;           /* DMA transfer mode */
    CODEPATH_TYPE_T path;               /* Invoke from Submission/Completion path*/
} DMA_LIMIT_DATA_TRN_T;

/* Purpose: Memory Pool indicator for memory allocation */
typedef enum {
    SUBMISSION_QUEUE = 0,
    COMPLETION_QUEUE,
    SUBMISSION_QUEUE_STRUCT,
    COMPLETION_QUEUE_STRUCT
} QUEUE_TYPE_T;

typedef enum {
    AQ_DEL_CC_DIS = 1,
    AQ_DEL_SHUTDOWN,
    AQ_DEL_FLR
} aq_delete_cause_t;

typedef struct nvme_queue_mem {
    uint64_t subq_cmnds_mem;
    uint64_t subq_mem;
    uint64_t cq_cmnds_mem;
    uint64_t cq_mem;
} nvme_queue_mem_t;

typedef enum { 
    MAP_ONE_TO_ALL = 1,
    MAP_ONE_TO_ONE,
    MAP_PER_TABLE,
} ns_map_policy_t;

/* some accessor macros */
#define NSPACE(__dev, __nsid) (__dev->disk_dev.ns_dir[(__nsid)-1])
#define LCMDID(__wqe) (((cvmx_wqe_tt *)__wqe)->word0.qw0.lcmdid)

/*Function prototypes */

/* Host Interface Layer functions */
int hil_process_rr_list(struct nvme_dev *);
int hil_update_subqueue(struct nvme_dev *, uint32_t);
int hil_rrlist_init(struct nvme_dev *);
void hil_reg_poll_update(struct nvme_dev *);
int hil_initialize_ctrlreg(struct nvme_dev *);
int hil_config_initialize(struct nvme_dev *, uint32_t);
int hil_trig_dma_transfer(struct nvme_dev *, uint16_t, uint32_t);
int hil_xfer_discontiguous_sq_entries(struct nvme_dev * dev,
                                      uint16_t          transfer_cnt,
                                      uint32_t          processed_sub_queue_tail,
                                      uint64_t          dev_sub_queue_addr,
                                      uint16_t          sq_no);
int hil_process_cmd_transfer_tag(struct nvme_dev *  dev,
                                 cvmx_wqe_tt *       wqp);

void hil_mbox_interrupt_handler(struct cvmx_mbox *, uint64_t registers[32]);
int hil_initialize_mailbox(struct nvme_dev *dev);
int hil_init(void);
int hil_deinit(void);

// NQM (hardware interface) layer functions
int nqm_process_cmd_transfer_tag(struct nvme_dev *dev, cvmx_wqe_tt *wqp);
int nqm_init(void);
int nqm_deinit(void);


/* NVMe Processing Layer functions */
void npl_process_ctrlreg(struct nvme_dev *  dev,
                         uint64_t           access_offset);
void npl_controller_configuration(struct nvme_dev *);
void npl_controller_shutdown(struct nvme_dev *);
int npl_create_admin_sub_queue(struct nvme_dev *dev);
int npl_create_admin_cpl_queue(struct nvme_dev *dev);
void npl_reset_nvme_bar(struct nvme_dev *);
void npl_initialize_bar1(struct nvme_dev *);
void npl_initialize_nvme_id_ctrl(struct nvme_dev *);
void npl_bkp_bar1_update(struct nvme_dev *);
int npl_check_alignment(struct nvme_dev *               dev,
                        uint64_t                        prp,
                        struct completion_status_field *cpl_entry,
                        uint32_t                        alignment_format);
int npl_process_cmd_transfer_tag(struct nvme_dev *,
                                 cvmx_wqe_tt *);
int npl_process_io_request(struct nvme_dev *,
                           cvmx_wqe_tt *);
int npl_process_admin_request(struct nvme_dev *,
                              cvmx_wqe_tt *);
int npl_create_io_cq(struct nvme_dev *,
                     cvmx_wqe_tt *wqp,
                     struct completion_status_field *,
                     uint32_t *);
int npl_create_io_sq(struct nvme_dev *,
                     cvmx_wqe_tt *wqp,
                     struct completion_status_field *,
                     uint32_t *);
int npl_delete_io_sq(struct nvme_dev *,
                      uint8_t qid,
                      struct completion_status_field *,
                      uint32_t *);
void npl_delete_io_cq(struct nvme_dev *,
                      uint8_t qid,
                      struct completion_status_field *,
                      uint32_t *);
int npl_process_identify(struct nvme_dev *,
                         cvmx_wqe_tt *,
                         struct completion_status_field *,
                         uint32_t *);
int npl_process_get_stats(struct nvme_dev *,
                     cvmx_wqe_tt *,
                     struct completion_status_field *,
                     uint32_t *);
int npl_abort_command(struct nvme_dev *,
                      cvmx_wqe_tt *,
                      struct completion_status_field *,
                      uint32_t *);
int npl_set_features(struct nvme_dev *                  dev,
                     struct nvme_cmd *              nvme_cmd,
                     uint16_t                           sq_id,
                     struct completion_status_field *   cpl_entry,
                     uint32_t *                         result);
int npl_get_features(struct nvme_dev *                  dev,
                     struct nvme_cmd *              nvme_cmd,
                     uint16_t                           sq_id,
                     struct completion_status_field *   cpl_entry,
                     uint32_t *                         result);
int npl_make_prp_list_local(struct nvme_dev *,
                            cvmx_wqe_tt *);
int npl_process_admin_data_transfer_tag(struct nvme_dev *,
                                        cvmx_wqe_tt *);
void npl_process_io_data_transfer_tag(struct nvme_dev *,
                                      cvmx_wqe_tt *);
int npl_submit_completion_entry(struct nvme_dev *,
                                cvmx_wqe_tt *,
                                uint32_t,
                                struct completion_status_field);
int npl_async_event_command(struct nvme_dev *,
                            struct nvme_cmd *,
                            struct completion_status_field *,
                            uint32_t *);
void npl_async_event_update(struct nvme_dev *,
                            struct async_event_result *);
int npl_async_check(struct nvme_dev *);
void npl_update_error_logpages(struct nvme_dev *,
                               struct nvme_log_error *);
int8_t npl_process_logpage(struct nvme_dev *                dev,
                           cvmx_wqe_tt *                     wqp,
                           struct completion_status_field * cpl_entry,
                           uint32_t *                       result);
int npl_add_completion_queue_entry(struct nvme_dev *,
                                    cvmx_wqe_tt *);
int npl_dma_submit(struct nvme_dev *,
                   struct nvme_dma *,
                   cvmx_wqe_tt *);
int npl_dma_process_list(struct nvme_dev *,
                         struct nvme_dma *,
                         cvmx_wqe_tt *,
                         cvmx_dma_engine_header_t *,
                         cvmx_dma_engine_buffer_t *);
int npl_dma_on_list(struct nvme_dev *,
                    struct nvme_dma *,
                    cvmx_dma_engine_header_t *,
                    cvmx_dma_engine_buffer_t *);
int npl_dma_create_first_pointers(cvmx_dma_engine_buffer_t *, uint64_t, struct nvme_dma *);
int npl_dma_create_last_pointers(struct nvme_dev *,
                                 cvmx_dma_engine_buffer_t *,
                                 struct nvme_dma *);
void *npl_fpa_alloc(struct nvme_dev *dev, uint64_t);
void npl_fpa_free(void *    ptr,
                  uint64_t  pool_id,
                  uint64_t  pool_size);
uint32_t  npl_calc_fpa_pool_size(uint64_t nvme_pool_size);
cvmx_wqe_tt *npl_dma_alloc_wqe(struct nvme_dev *dev, cvmx_wqe_tt *);
void npl_initialize_fpa_pools(struct nvme_dev *dev);
void npl_debug_log(const char *format,
                   ...);
void npl_xfer_discontiguous_cq_entries(struct nvme_dev *,
                                       uint16_t,
                                       uint32_t,
                                       uint16_t,
                                       cvmx_wqe_tt *);
void npl_convert_iocmds_le_to_be(struct nvme_cmd *  cmd_ptr,
                                 CMD_TYPE_T             cmd_type);

int npl_check_for_cmd_in_cq(struct nvme_dev *   dev,
                            uint16_t            cq_id,
                            uint16_t            cmd_id);
int
npl_set_status_and_submit(struct nvme_dev * dev,
                          cvmx_wqe_tt *      wqp,
                          uint16_t          status_code_type,
                          uint16_t          status_codec,
                          uint32_t          result);

void npl_helper_free_context(struct context_struct *);
void npl_helper_cleanup_fused_cmd(struct nvme_dev * dev, cvmx_wqe_tt *wqe_io);

void npl_setup_wqe(cvmx_wqe_tt *wqe);
void npl_fetch_nvme_command(struct nvme_dev *, cvmx_wqe_nqm_t *);
void npl_iobdma_fetch_sq_entry(struct nvme_dev *, cvmx_wqe_nqm_t *);

int npl_dma_init_global();

void npl_controller_disable(struct nvme_dev *dev);
void npl_delete_admin_queues(struct nvme_dev *dev, aq_delete_cause_t cause);

uint16_t npl_alloc_local_cmd_id(struct nvme_dev *dev, uint8_t sqid, uint16_t cmdid);
int npl_free_local_cmd_id(struct nvme_dev *dev, uint8_t sqid, int cmdid);
void npl_handle_aborted_cmd(struct nvme_dev *dev, cvmx_wqe_tt *work_entry);


int cn68xx_initialize_dma_engine(void);
void cn68xx_setup_pci_load_store(int pcie_port);
void setup_cn68xx_pci_regs(int pcie_port);
void setup_pci_regs(void);

/* Storage Abstraction Layer */
int sal_storage_initialize(struct nvme_dev *);
int sal_do_data_transfer(struct nvme_dev *,
                         uint64_t *,
                         cvmx_wqe_tt *);
int sal_do_ramdisk_io(struct nvme_dev *,
                      uint64_t *,
                      cvmx_wqe_tt *);
void sal_ramdisk_io_completion(cvmx_wqe_tt *);
int sal_init(void);

void print_cmd_info_nbytes(uint8_t *cmd_ptr,
                           uint32_t nbytes);
int hil_dma_limit_data_tansfer(struct nvme_dev *        dev,
                               DMA_LIMIT_DATA_TRN_T *   dma_data_trnsfr);

int nqm_config_initialize(struct nvme_dev *dev, uint32_t config_no);
int nqm_dev_init(struct nvme_dev *dev);
int nvme_config_init(void);
int nvme_init_dev(int pfvf);

#define align(size, align) ((size % align) ? (size + (align - (size % align))) : (size))

#define findalloc(stype, pfvf, alignv) \
	((struct stype *) ((unsigned char *)stype##_base+(pfvf)*align(sizeof(struct stype), alignv)));

#endif /* __NVME_CVM_H__ */
