#include <time.h>
#include <sys/time.h>
#include "cvmcs-common.h"
#include "cvmcs-nic-defs.h"
#include "cvmcs-nic-fwdump.h"
#include "cvmcs-nic-flash.h"
#include "cvmx-core.h"
#include "cvmx-interrupt.h"
#include "cvmcs-nic.h"

struct fwdump_ctx {
	int   inited;
	int   log_used;
	int   log_size;
	int   logbuf_done;
	struct crash core[MAX_CORES];
	cvmx_spinlock_t bootlock;
};

CVMX_SHARED static char *fwdbuf = NULL;
CVMX_SHARED static char *fwdump_log_ptr = NULL;

CVMX_SHARED static struct fwdump_ctx *fwdump;

extern int backtrace(void *, int);
#define TRACE_SIZE 20
CVMX_SHARED void *trace[TRACE_SIZE];

#define HI32(data64)    ((uint32_t)(data64 >> 32))
#define LO32(data64)    ((uint32_t)(data64 & 0xFFFFFFFF))

static const char reg_names[][32] =
    { "r0", "at", "v0", "v1", "a0", "a1", "a2", "a3",
	"t0", "t1", "t2", "t3", "t4", "t5", "t6", "t7",
	"s0", "s1", "s2", "s3", "s4", "s5", "s6", "s7",
	"t8", "t9", "k0", "k1", "gp", "sp", "s8", "ra"
};

/* Textual descriptions of cause codes */
static const char cause_names[][128] = {
        /*  0 */ "Interrupt",
        /*  1 */ "TLB modification",
        /*  2 */ "tlb load/fetch",
        /*  3 */ "tlb store",
        /*  4 */ "address exc, load/fetch",
        /*  5 */ "address exc, store",
        /*  6 */ "bus error, instruction fetch",
        /*  7 */ "bus error, load/store",
        /*  8 */ "syscall",
        /*  9 */ "breakpoint",
        /* 10 */ "reserved instruction",
        /* 11 */ "cop unusable",
        /* 12 */ "arithmetic overflow",
        /* 13 */ "trap",
        /* 14 */ "",
        /* 15 */ "floating point exc",
        /* 16 */ "",
        /* 17 */ "",
        /* 18 */ "cop2 exception",
        /* 19 */ "",
        /* 20 */ "",
        /* 21 */ "",
        /* 22 */ "mdmx unusable",
        /* 23 */ "watch",
        /* 24 */ "machine check",
        /* 25 */ "",
        /* 26 */ "",
        /* 27 */ "",
        /* 28 */ "",
        /* 29 */ "",
        /* 30 */ "cache error",
        /* 31 */ ""
};

int fwdump_safe_buf_print(char *ptr, int len)
{

	int core = cvmx_get_core_num();
	int remaining = (FWDUMP_CRASH_SIZE - sizeof(struct crashinfo))
	    - fwdump->core[core].crash_used - 1;
	char *buf;
	struct crashinfo *cinfo;

	if (len > remaining)
		return 0;
	buf =
	    fwdump->core[core].crash_buf + sizeof(struct crashinfo) +
	    fwdump->core[core].crash_used;

	cinfo = (struct crashinfo *)(fwdump->core[core].crash_buf);

	/*This is first msg in crash. initialize struct indicating the crash. */
	if (fwdump->core[core].crash_buf_done == 0) {
		cinfo->crashed = 1;
		cinfo->crashsize = 0;
		cinfo->cycles = cvmx_get_cycle();
	}

	memcpy(buf, ptr, len);
	fwdump->core[core].crash_used += len;
	cinfo->crashsize = fwdump->core[core].crash_used;
	CVMX_SYNCWS;

	return 0;

}

int fwdump_safe_buf_printf(const char *fmt, ...)
{
	va_list list;
	int len = 0;
	char str[2048];

	if (!fwdump->inited)
		return 0;

	va_start(list, fmt);
	len = vsnprintf(str, 2047, fmt, list);
	va_end(list);

	return fwdump_safe_buf_print(str, len);
}

static inline int get_nbits(uint32_t coremask)
{
	int i = 0;
	while (coremask) {
		i++;
		coremask &= (coremask - 1);
	}
	return i;
}

static size_t TLB_SIZE(uint64_t pmask)
{
	uint64_t newmask = (pmask | 0x1fff) >> 1;
	int nbits = get_nbits(newmask) - 10;
	return 1 << nbits;
}

#define TLB_PAGESIZE(x)  (TLB_SIZE((x)))

inline void print_reg64(const char *name, uint64_t reg)
{
	fwdump_safe_buf_printf("%.16s: 0x%08x%08x\n", name, HI32(reg),
			       LO32(reg));
}

void fwdump_crash_notify(void)
{
	struct cvmcs_nic_fwdump_info *fwdinfo;

	fwdinfo = (struct cvmcs_nic_fwdump_info *)fwdbuf;

	fwdinfo->status |= FWDUMP_CRASHED;
	CVMX_SYNCW;
}

static void dump_csr_registers(int core)
{

}

static void dump_tlb_mappings(int core)
{
	int tlb_entries;
	uint64_t lo0, lo1, pgmask;
	uint32_t hi;
	uint32_t c0, c1;
	int width = 13;
	int size, i;

	tlb_entries = cvmx_core_get_tlb_entries();

	for (i = 0; i < tlb_entries; i++) {
		CVMX_MT_COP0(i, COP0_INDEX);
		asm volatile ("tlbr");
		CVMX_MF_ENTRY_HIGH(hi);
		CVMX_MF_ENTRY_LO_0(lo0);
		CVMX_MF_ENTRY_LO_1(lo1);
		CVMX_MF_PAGEMASK(pgmask);

		c0 = (lo0 >> 3) & 7;
		c1 = (lo1 >> 3) & 7;

		size = TLB_PAGESIZE(pgmask) * 1024;
		if ((lo0 & TLB_VALID) || (lo1 & TLB_VALID)) {
			fwdump_safe_buf_printf("va=%0*lx size=%d asid=%02x\n",
					       width, size, (hi & ~0x1fffUL),
					       hi & 0xff);
			fwdump_safe_buf_printf
			    ("        [pa=%0*lx c=%d d=%d v=%d g=%d] ", width,
			     (lo0 >> 6 << 12), c0, (lo0 & 4) ? 1 : 0,
			     (lo0 & 2) ? 1 : 0, (lo0 & 1) ? 1 : 0);
			fwdump_safe_buf_printf
			    ("[pa=%0*lx c=%d d=%d v=%d g=%d]\n", width,
			     (lo1 >> 6 << 12), c1, (lo1 & 4) ? 1 : 0,
			     (lo1 & 2) ? 1 : 0, (lo1 & 1) ? 1 : 0);
		}
	}
}

static void __cvmcs_nic_fwdump(int core, uint64_t *registers, bool watchdog_timeout)
{
	uint64_t r1, r2;
	int i, j;
	const char *str;
	struct crashinfo *cinfo;

	cinfo = (struct crashinfo *)(fwdump->core[core].crash_buf);

	if (watchdog_timeout)
		fwdump_safe_buf_printf("\n****CORE %d WATCHDOG TIMER EXPIRED**** \n", core);

	fwdump_safe_buf_printf("\n****REGISTER DUMP OF CORE %d**** \n", core);
	cvmcs_printf("\n****REGISTER DUMP OF CORE %d**** \n\n", core);

	/*offset into to crashbuf where register info starts */
	cinfo->reginfoff = fwdump->core[core].crash_used;
	for (i = 0; i < 16; i++) {
		r1 = registers[i];
		r2 = registers[i + 16];
		fwdump_safe_buf_printf
		    ("%3s ($%02d): 0x%08x%08x        %3s ($%02d): 0x%08x%08x\n",
		     reg_names[i], i, HI32(r1), LO32(r1), reg_names[i + 16],
		     i + 16, HI32(r2), LO32(r2));
		cvmcs_printf
		    ("%3s ($%02d): 0x%08x%08x        %3s ($%02d): 0x%08x%08x\n",
		     reg_names[i], i, HI32(r1), LO32(r1), reg_names[i + 16],
		     i + 16, HI32(r2), LO32(r2));
	}

	fwdump_safe_buf_printf("\n");
	cvmcs_printf("\n");
	CVMX_MF_COP0(r1, COP0_CAUSE);
	print_reg64("COP0_CAUSE", r1);
	str = cause_names[(r1 >> 2) & 0x1f];
	cvmcs_printf("COP0_CAUSE\t0x%016lx %s\n", r1, str && *str ? str : "Reserved exception cause");
	CVMX_MF_COP0(r2, COP0_STATUS);
	print_reg64("COP0_STATUS", r2);
	cvmcs_printf("COP0_STATUS\t0x%016lx\n", r2);
	CVMX_MF_COP0(r1, COP0_BADVADDR);
	print_reg64("COP0_BADVADDR", r1);
	cvmcs_printf("COP0_BADVADDR\t0x%016lx\n", r1);
	CVMX_MF_COP0(r2, COP0_EPC);
	print_reg64("COP0_EPC", r2);
	cvmcs_printf("COP0_EPC\t0x%016lx\n", r2);

	/*Registers info ends here */
	cinfo->reginfosize = fwdump->core[core].crash_used - cinfo->reginfoff;

	fwdump_safe_buf_printf("\n***CALL TRACE OF CORE %d***\n\n", core);
	cvmcs_printf("\n***CALL TRACE OF CORE %d***\n\n", core);

	/*Back trace starts here */
	cinfo->btoff = fwdump->core[core].crash_used;
	j = backtrace((void *)trace, 20);
	for (i = 0; i < j - 1; i++) {
		fwdump_safe_buf_printf("    #%2d  %p \n", i, trace[i]);
		cvmcs_printf("    #%2d  %p \n", i, trace[i]);
	}

	/*back trace ends here */
	cinfo->btsize = fwdump->core[core].crash_used - cinfo->btoff;
	cvmcs_printf("******************************************************************\n");

	/*TLB Mapping goes here */
	cinfo->tlboff = fwdump->core[core].crash_used;
	dump_tlb_mappings(core);
	cinfo->tlbsize = fwdump->core[core].crash_used - cinfo->tlboff;

	dump_csr_registers(core);

	cinfo = (struct crashinfo *)(fwdump->core[1].crash_buf);
	fwdump->core[core].crash_dumped = 1;
	fwdump_crash_notify();
	cvmcs_nic_flash_put_fwdump(core, (char *)&(fwdump->core[core]),
			sizeof(struct crash), fwdbuf);
}

static CVMX_SHARED cvmx_spinlock_t sli_scratch_2_lock;

static void cvmcs_nic_fwdump_exception_handler(uint64_t *registers)
{
	int core;

	core = cvmx_get_core_num();

	if (fwdump->core[core].crash_dumped)
		return;

	if (OCTEON_IS_MODEL(OCTEON_CN73XX)) {
		uint64_t scratch2;

		/* kick this core's watchdog, then turn it off */
		cvmx_write_csr(CVMX_CIU_PP_POKEX(core), 1);
		cvmx_write_csr(CVMX_CIU_WDOGX(core), 0);

		/* tell host about firmware crash via SLI_SCRATCH_2 register */
		cvmx_spinlock_lock(&sli_scratch_2_lock);
		scratch2 = cvmx_read_csr(CVMX_PEXP_SLI_SCRATCH_2);
		scratch2 |= 1ULL << core;
		cvmx_write_csr(CVMX_PEXP_SLI_SCRATCH_2, scratch2);
		cvmx_spinlock_unlock(&sli_scratch_2_lock);
	}

	cvmcs_printf("\n\nCore %d: Unhandled Exception. See oct-fwdump for details.\n", core);
	cvmcs_printf("******************************************************************\n");

	__cvmcs_nic_fwdump(core, registers, false);

	while (1);
}

void cvmcs_nic_fwdump_after_watchdog_timeout(uint64_t *registers)
{
	int core;
	uint64_t scratch2;

	core = cvmx_get_core_num();

	if (fwdump->core[core].crash_dumped)
		return;

	/* tell host about watchdog timeout via SLI_SCRATCH_2 register */
	cvmx_spinlock_lock(&sli_scratch_2_lock);
	scratch2 = cvmx_read_csr(CVMX_PEXP_SLI_SCRATCH_2);
	scratch2 |= 1ULL << core;
	cvmx_write_csr(CVMX_PEXP_SLI_SCRATCH_2, scratch2);
	cvmx_spinlock_unlock(&sli_scratch_2_lock);

	cvmcs_printf("\n\nCore %d: watchdog timer expired. See oct-fwdump for details.\n", core);
	cvmcs_printf("******************************************************************\n");

	__cvmcs_nic_fwdump(core, registers, true);
}

static int fwdump_connect_to_named_blocks(void)
{
	struct cvmcs_nic_fwdump_info *fwdinfo;

	fwdbuf = live_upgrade_ctx->fwdbuf;
	fwdinfo = (struct cvmcs_nic_fwdump_info *)fwdbuf;
	fwdump_log_ptr = fwdbuf + fwdinfo->bloff;

	fwdump = live_upgrade_ctx->fwdump;

	cvmx_interrupt_set_exception(cvmcs_nic_fwdump_exception_handler);
	CVMX_SYNCW;

	return 0;
}

int cvmcs_nic_fwdump_enable(int cores)
{
	struct cvmcs_nic_fwdump_info *fwdinfo;
	int i;
	uint64_t *crashp;
	struct crashinfo *cinfo;

	if (!cvmx_is_init_core())
		return -1;

	if (!booting_for_the_first_time)
		return fwdump_connect_to_named_blocks();

	fwdbuf =
	    cvmx_bootmem_alloc_named(FWDUMP_BUF_SIZE, 128,
				     OCT_NIC_FWDUMP_BLOCK_NAME);
	if (!fwdbuf)
		return -1;

	live_upgrade_ctx->fwdbuf = fwdbuf;

	fwdinfo = (struct cvmcs_nic_fwdump_info *)fwdbuf;
	memset(fwdinfo, 0, sizeof(*fwdinfo));

	fwdinfo->bloff = sizeof(*fwdinfo);

	fwdump = cvmx_bootmem_alloc_named(sizeof (struct fwdump_ctx), 128, "__nic_fwdump_ctx");
	if (!fwdump)
		return -1;

	live_upgrade_ctx->fwdump = fwdump;

	memset(fwdump, 0, sizeof(struct fwdump_ctx));

	crashp = (uint64_t *) (fwdbuf + sizeof(*fwdinfo));
	for (i = 0; i < MAX_CORES; i++) {
		if (!cvmx_coremask_is_core_set(&(cvmx_sysinfo_get()->core_mask), i))
			continue;
		cinfo = (struct crashinfo *)fwdump->core[i].crash_buf;

		cinfo->other_ptr = CVM_DRV_GET_PHYS(fwdump->core[i].crash_other_buf);

		/*Physical Address used by host to get the crash data */
		crashp[i] = CVM_DRV_GET_PHYS(fwdump->core[i].crash_buf);
		fwdinfo->bloff += sizeof(uint64_t);
	}
	fwdinfo->ncores = cores;
	fwdinfo->logsize = 0;

	/*Point to boot log */
	printf("BOOT LOG OFFSER %d\n", fwdinfo->bloff);

	fwdump_log_ptr = fwdbuf + fwdinfo->bloff;
	fwdump->log_size = FWDUMP_BUF_SIZE - fwdinfo->bloff;

	fwdump_log_ptr[fwdump->log_size - 1] = '\n';

	fwdump->log_used = 1;	//Prevent writing to last char
	fwdump->inited = 1;

	/*
	 * Initialize teh lock used to protect bootlog from
	 * multiple cores
	 */
	cvmx_spinlock_init(&fwdump->bootlock);

	/*Register the exception handler */
	cvmx_interrupt_set_exception(cvmcs_nic_fwdump_exception_handler);

	CVMX_SYNCW;
	return 0;
}

//Assumptions
//1. There is enough space in the current bank of the flash.
//2. spi structure in the flash is octeon_spi type
int cvmcs_nic_flash_fwdump_enable(void)
{
	int ret;

	if (!cvmx_is_init_core())
		return -1;

	ret = cvmcs_nic_setup_flash_dump(sizeof(struct fwdump_ctx));
	if (ret)
		return -1;

	CVMX_SYNCW;
	return 0;
}

static int fwdump_crash_info_other(char *ptr, int len)
{

	int core = cvmx_get_core_num();
	int remaining =
	    (FWDUMP_CRASH_OTHER_SIZE - fwdump->core[core].crash_other_used - 1);
	char *buf;
	struct crashinfo *cinfo;

	if (len > remaining)
		return 0;

	cinfo = (struct crashinfo *)(fwdump->core[core].crash_buf);

	buf = fwdump->core[core].crash_other_buf + fwdump->core[core].crash_other_used;

	memcpy(buf, ptr, len);
	fwdump->core[core].crash_other_used += len;
	cinfo->other_size = fwdump->core[core].crash_other_used;
	CVMX_SYNCWS;

	return 0;
}

int fwdump_crash_info(const char *fmt, ...)
{
	va_list list;
	int len = 0;
	char str[2048];

	if (!fwdump->inited)
		return 0;

	va_start(list, fmt);
	len = vsnprintf(str, 2047, fmt, list);
	va_end(list);

	return fwdump_crash_info_other(str, len);
}

static int boot_log_print(const char *str, int len)
{
	int log_buf_remaining;
	int print_len = 0;
	struct cvmcs_nic_fwdump_info *fwdinfo =
	    (struct cvmcs_nic_fwdump_info *)fwdbuf;

	cvmx_spinlock_lock(&fwdump->bootlock);
	if (fwdump->logbuf_done) {
		cvmx_spinlock_unlock(&fwdump->bootlock);
		return 0;
	}

	log_buf_remaining = fwdump->log_size - fwdump->log_used - 1;

	if (len > log_buf_remaining) {
		print_len = log_buf_remaining;
		fwdump->logbuf_done = 1;
	} else
		print_len = len;

	memcpy((fwdump_log_ptr + fwdump->log_used - 1), str, print_len);
	fwdump->log_used += print_len;

	
	fwdinfo->logsize = fwdump->log_used;
	cvmx_spinlock_unlock(&fwdump->bootlock);

	CVMX_SYNCWS;
	return print_len;
}

int fwdump_boot_log(const char *fmt, ...)
{
	va_list list;
	int len = 0;
	char str[2048];

	if (!fwdump->inited)
		return 0;

	va_start(list, fmt);
	len = vsnprintf(str, 2047, fmt, list);
	va_end(list);

	return boot_log_print(str, len);
}
