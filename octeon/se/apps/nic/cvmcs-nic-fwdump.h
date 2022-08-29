#ifndef _CVMCS_FWDUMP_H_
#define _CVMCS_FWDUMP_H_

#define FWDUMP_CRASHED    0x1
#define FWDUMP_LOG_VALID  0x2
#define FWDUMP_FAILED     0x4

#define FWDUMP_BUF_SIZE    (1*1024)
#define FWDUMP_CRASH_SIZE  (10*1024)
#define FWDUMP_CRASH_OTHER_SIZE  (10*1024)
#define OCT_NIC_FWDUMP_BLOCK_NAME       "__nic_fwdump_block"

struct cvmcs_nic_fwdump_info {
	uint64_t status;
	uint32_t ncores;
	uint32_t bloff;
	uint32_t logsize;
	uint32_t fw_ver_str_off;
	uint32_t fw_ver_str_len;
	uint32_t resv;
};

struct crashinfo {
	uint32_t crashed;
	uint32_t crashsize;
	uint64_t cycles;
	uint32_t reginfoff;
	uint32_t reginfosize;
	uint32_t btoff;
	uint32_t btsize;
	uint32_t tlboff;
	uint32_t tlbsize;
	uint64_t other_ptr;
	uint64_t other_size;
};

struct crash {
	char crash_buf[FWDUMP_CRASH_SIZE];
	char crash_other_buf[FWDUMP_CRASH_OTHER_SIZE];
	int  crash_used;
	int  crash_other_used;
	int  crash_buf_done;
	int  crash_dumped;
};

int cvmcs_nic_fwdump_enable(int cores);
int cvmcs_nic_flash_fwdump_enable(void);
int fwdump_safe_buf_print(char *ptr, int len);
int fwdump_safe_buf_printf(const char *fmt, ...);
int fwdump_boot_log(const char *fmt, ...);
int fwdump_crash_info(const char *fmt, ...);
#endif
