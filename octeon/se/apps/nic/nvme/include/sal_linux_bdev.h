#ifndef __SAL_LINUX_BIO_H
#define __SAL_LINUX_BIO_H

#define FPA_DATA_BUF_POOL 1
#define FPA_DATA_BUF_POOL_SIZE OCTEON_LINUX_PAGE_SIZE

//Msgs from oct linux bio module to SE-SAL
#define OPCODE_SAL_REGISTER_BDEVS   1
#define OPCODE_SAL_DEREGISTER_BDEVS   2
#define OPCODE_SAL_RDWR_BIO_DONE_RESP 3

//All the ramdisks/SSD/HDD/partitions
#define MAX_BDEVS              255

/* wqe unused8 for BDEV rd/wr cmnds*/
#define CVM_BDEV_LINUX_RD_CMND 0xBDE1
#define CVM_BDEV_LINUX_WR_CMND 0xBDE2

#define OCTEON_LINUX_PAGE_SIZE  4096 //TODO: Get it from oct-linux
#define OCTEON_LINUX_PAGE_SHIFT 12

#define SENSE_DATA_SIZE 32
typedef struct bdev_rdwr_bio_done_resp {
 uint32_t bdev_idx;
 uint32_t free_sg_entry; //Table entry where hosts nvme_cmnd is parked on SAL side
 uint32_t bio_status;//response code from oct-linux-bio
 uint32_t sense_data_len;
 uint8_t sense_data[SENSE_DATA_SIZE];
} bdev_rdwr_bio_done_resp_t;

typedef struct cvm_bdev_info {
    uint16_t    sector_size;
    uint8_t     bdev_id;
    uint8_t     resv;
    uint32_t    bdev_size; 
    uint64_t    bdev_unique_id;
} cvm_bdev_info_t;

typedef struct cvm_bdev_list {
    uint8_t	num_bdevs;
    cvm_bdev_info_t bdev[MAX_BDEVS];
} cvm_bdev_list_t;
 
#define STATUS_LINUX_BIO_SUBMIT_SUCCESS 0
#define STATUS_LINUX_BIO_SUBMIT_ERR    -1
#define STATUS_RD_REQ_SENT_TO_OCT_LINUX 1
#define STATUS_WR_REQ_SENT_TO_OCT_LINUX 2

int sal_linux_bdev_process_message(cvmx_wqe_tt * wqe, int subcode);
int sal_do_oct_linux_bdev_io(struct nvme_dev *, uint64_t *, cvmx_wqe_tt *);
int sal_complete_oct_linux_bdev_io(struct nvme_dev *dev, cvmx_wqe_tt *);

#endif
