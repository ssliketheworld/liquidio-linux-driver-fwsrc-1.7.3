#ifndef __CVMCS_NIC_FLASH__
#define __CVMCS_NIC_FLASH__

struct flash_dump_params {
	uint32_t fw_dump_flash_base;
	uint32_t fw_dump_flash_size;
	uint32_t fw_dump_flag;
};

void cvmcs_spi_flash_probe(void);
int cvmcs_nic_flash_put_dump(char *ptr, int len);
int cvmcs_nic_flash_put_log(char *ptr, int len);
int cvmcs_nic_flash_get(void *buf, int offset, int len);
int cvmcs_nic_flash_put(void *buf, int offset, int len);

/* Function to initialize the flash parameters to place the F/W dump */
int cvmcs_nic_setup_flash_dump(int ctx_size);
/* Functions to get/set the F/W dump parameters */
int cvmcs_nic_get_flash_dump_params(struct flash_dump_params *params);
int cvmcs_nic_set_flash_dump_params(struct flash_dump_params *params);

void cvmcs_nic_flash_put_fwdump(int core, char *clog, int clog_sz,
		char *fwdbuf);

#define LIO_NO_CRASH_DUMP 0
#define LIO_CRASH_DUMP 1
#endif
