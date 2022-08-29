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
#include "global-config.h"
#include "octeon-pci-console.h"
#include "cvmcs-common.h"
#include "cvmcs-nic.h"
#include  <cvmx-atomic.h>
#include "cvmcs-nic-component.h"

extern CVMX_SHARED int nic_console_enabled;
extern CVMX_SHARED int nic_duty_cycle;
extern CVMX_SHARED uint64_t cpu_freq;
extern CVMX_SHARED int intmod_enable;
extern CVMX_SHARED uint64_t intrmod_maxpkt_ratethr;
extern CVMX_SHARED uint64_t intrmod_minpkt_ratethr;
extern CVMX_SHARED uint64_t intrmod_maxcnt_trigger;
extern CVMX_SHARED uint64_t intrmod_mincnt_trigger;
extern CVMX_SHARED uint64_t intrmod_maxtmr_trigger;
extern CVMX_SHARED uint64_t intrmod_mintmr_trigger;
CVMX_SHARED uint64_t intrmod_intrvl_levels;
extern CVMX_SHARED uint64_t intrmod_rxcnt_steps;
extern CVMX_SHARED uint64_t intrmod_rxtmr_steps;
extern CVMX_SHARED uint64_t intrmod_check_intrvl;

#if (!CONFIG_PCI_CONSOLE)

#ifdef printf
#undef printf
#endif

int cmdl_uart_printf(int uart_index, const char *format, ...)
	__attribute__ ((format(printf, 2, 3)));

/*
 * If we want to use serial console we need to redefine printf & putchar
 * so they write to UART memory directly for output.
 *
 * If this is not done undesirable prefix shows up at the beginning of
 * each line.
 */
#define printf(format, ...) cmdl_uart_printf(0, format, ##__VA_ARGS__)

#undef putchar
#define putchar(c) printf("%c", c)

#define fflush(a)

#endif				/* !CONFIG_PCI_CONSOLE */

#ifdef CONFIG_NIC_CONSOLE	/* CLI feature enabled */

#ifdef OVS_IPSEC
#define CMDL_MAX_VERBS	10
#else
#define CMDL_MAX_VERBS	8
#endif
/*
 * Data for tracking registered command line verbs
 */
typedef struct {
	char *verb;
	void (*proc) (int, char *[]);
} cmd_cb_func_t;

CVMX_SHARED cmd_cb_func_t cmdl_registered_verbs[CMDL_MAX_VERBS];

/*
 * Reading data from PCI console...
 */
#define CMDLINE_MAX_INPUT   256

#if CONFIG_PCI_CONSOLE
static uint64_t pci_console_desc_addr = 0;
#endif				/* CONFIG_PCI_CONSOLE */

char cmdl_pci_buf[CMDLINE_MAX_INPUT];
int cmdl_pci_idx = 0;

static void nic_cmdl_showprompt()
{
	printf("NIC-Console>");
	fflush(NULL);
}

/*
 * Register function callback associated with particular verb
 */
void nic_cmdl_register(char *verb, void (*f) (int, char *[]))
{
	int found = -1;
	int i;

	for (i = 0; i < CMDL_MAX_VERBS; i++) {
		if (cmdl_registered_verbs[i].verb == NULL) {
			found = i;
			break;
		}
	}
	if (found == -1)
		return;

	cmdl_registered_verbs[found].verb = verb;
	cmdl_registered_verbs[found].proc = f;
}

#define CMDL_MAX_ARGS	16
void nic_cmdl_main(char *inp)
{
	char buf[CMDLINE_MAX_INPUT];	// local buffer copy
	char *argv[CMDL_MAX_ARGS] = { NULL, };
	char *s;
	int argc = 0;
	int len;
	int i;

	if ((len = strlen(inp)) == 0) {
		return;
	}

	/* Local copy needed here as we may call it with static string */
	strcpy(buf, inp);
	inp = &buf[0];
	s = inp;

	while (s - inp < len && argc < CMDL_MAX_ARGS) {

		while (*s && *s == ' ')
			s++;

		if (!*s)
			break;

		argv[argc++] = s;

		while (*s && *s != ' ')
			s++;

		*s++ = 0;
	}

    if(argc == 0)
        return;

	for (i = 0; i < CMDL_MAX_VERBS; i++) {
		if (cmdl_registered_verbs[i].verb &&
		    !strcmp(argv[0], cmdl_registered_verbs[i].verb)) {
			cmdl_registered_verbs[i].proc(argc, argv);
			return;
		}
	}
	printf("%s: Command unknown\n", argv[0]);
}

#if (!CONFIG_PCI_CONSOLE)

/**
 * Get a single byte from serial port.
 *
 * @param uart_index Uart to read from (0 or 1)
 * @return The byte read
 */
static uint8_t cmdl_uart_read_byte(int uart_index)
{
	/*
	 * Read and return the data. Zero will be returned if
	 * there is no data.
	 */
	cvmx_uart_lsr_t lsrval;

	lsrval.u64 = cvmx_read_csr(CVMX_MIO_UARTX_LSR(uart_index));

	if (lsrval.s.dr) {
		return (cvmx_read_csr(CVMX_MIO_UARTX_RBR(uart_index)));
	} else {
		return (0);
	}
}

/**
 * Put a single byte to uart port.
 *
 * @param uart_index Uart to write to (0 or 1)
 * @param ch         Byte to write
 */
static void cmdl_uart_write_byte(int uart_index, uint8_t ch)
{
	cvmx_uart_lsr_t lsrval;

	/* Spin until there is room */
	do {
		lsrval.u64 = cvmx_read_csr(CVMX_MIO_UARTX_LSR(uart_index));
		if ((lsrval.s.thre == 0))
			cvmx_wait(10000);	/* Just to reduce the load on the system */
	}
	while (lsrval.s.thre == 0);

	/* Write the byte */
	cvmx_write_csr(CVMX_MIO_UARTX_THR(uart_index), ch);
}

/**
 * Version of printf for direct uart output. This bypasses the
 * normal per core banner processing.
 *
 * @param uart_index Uart to write to
 * @param format     printf format string
 * @return Number of characters written
 */
int cmdl_uart_printf(int uart_index, const char *format, ...)
{
	char buffer[1024];
	va_list args;
	int result, i;
	char *ptr;

	va_start(args, format);
	result = vsnprintf(buffer, sizeof(buffer), format, args);
	va_end(args);
	i = result;
	ptr = buffer;
	while (i > 0) {
		if (*ptr == '\n')
			cmdl_uart_write_byte(uart_index, '\r');
		cmdl_uart_write_byte(uart_index, *ptr);
		ptr++;
		i--;
	}
	return result;
}

#endif				/* !CONFIG_PCI_CONSOLE */

void nic_cmdl_readline(void)
{
	char read_buffer[CMDLINE_MAX_INPUT];
	int nchar;
	int i;
	static int first_time = 1;

	if (first_time) {
		first_time = 0;
		putchar('\n');
		nic_cmdl_showprompt();
		printf("        + + + WELCOME TO NIC CONSOLE! + + +\n");
		nic_cmdl_showprompt();
		putchar('\n');
		nic_cmdl_showprompt();
		printf
		    ("  Arrow keys are not supported, use <Back-Space> for editing!\n");
		nic_cmdl_showprompt();
		printf("  Type 'help' for list of available commands\n");
		nic_cmdl_showprompt();
		//printf("  Type 'exit' to shut down CLI and save some CPU cycles\n");
		//nic_cmdl_showprompt();
		putchar('\n');
		nic_cmdl_showprompt();
	}
#if CONFIG_PCI_CONSOLE
	nchar = octeon_pci_console_read(pci_console_desc_addr,
					0, read_buffer, CMDLINE_MAX_INPUT,
					OCT_PCI_CON_FLAG_NONBLOCK);

#else				/* Serial console */
	{
	uint8_t c;

	nchar = 0;

	while ((c = cmdl_uart_read_byte(0))) {
		read_buffer[nchar++] = c;
	}
	}
#endif				/* CONFIG_PCI_CONSOLE */

	for (i = 0; i < nchar; i++) {

		if (read_buffer[i] == 127 || read_buffer[i] == 8) {
			putchar(0x8);
			putchar(0x20);
			putchar(0x8);
			fflush(NULL);
			cmdl_pci_idx--;
			continue;
		}

		putchar(read_buffer[i]);
		fflush(NULL);

		if (read_buffer[i] == 0xd) {
			printf("\n");

			cmdl_pci_buf[cmdl_pci_idx++] = 0;

			nic_cmdl_main(cmdl_pci_buf);

			nic_cmdl_showprompt();

			cmdl_pci_idx = 0;

			continue;
		}
		cmdl_pci_buf[cmdl_pci_idx++] = read_buffer[i];
	}
}

static void nic_cmdl_help(int argc, char *argv[])
{
	int i;

	printf("\nCurrently supported commands:\n\n");

	for (i = 0; i < CMDL_MAX_VERBS; i++) {
		if (cmdl_registered_verbs[i].verb) {
			printf("    %s\n", cmdl_registered_verbs[i].verb);
		}
	}
	printf("\n");
}

/**
 * cmdl_show_sysinfo
 *
 * This function displays information about HW/SW system resources and
 * implements "sysinfo" CLI command
 *
 * @argv    UNIX-like arguments
 * @argc    number of entries
 */
static void nic_cmdl_show_sysinfo(int argc, char *argv[])
{
	uint64_t pow_total = 0;
	uint64_t fw_total_fwdrate = 0ULL;	/* intrmod: total packet fwd. rate activating intr moderation */
	static uint64_t maxqos[8] =
	    { 0ULL, 0ULL, 0ULL, 0ULL, 0ULL, 0ULL, 0ULL, 0ULL };
	static uint64_t zpool[8] =
	    { ~0ULL, ~0ULL, ~0ULL, ~0ULL, ~0ULL, ~0ULL, ~0ULL, ~0ULL };
	uint64_t mxqos, minpool;
	uint64_t pow_qoslvl[8];
#ifdef RLIMIT
	int64_t fau;
#endif
	int qos = 0;
	int i;

	pow_total = cvmx_read_csr(CVMX_SSO_IQ_COM_CNT);
	for (qos = 0; qos < 8; qos++) {
		pow_qoslvl[qos] = cvmx_read_csr(CVMX_SSO_IQ_CNTX(qos));
	}

	printf("\nTotal entries in POW = %llu\n", CAST64(pow_total));
	for (qos = 0; qos < 8; qos++) {
		mxqos = CAST64(pow_qoslvl[qos]);
		if (mxqos > maxqos[qos])	/* check for max. qos value */
			maxqos[qos] = mxqos;	/* record max. qos */
		printf("  QOS[%d] = %llu MAX=0x%llx\n", qos,
		       (long long unsigned int)mxqos,
		       (long long unsigned int)maxqos[qos]);
	}

	printf("\nFPA POOLS\n");
	for (i = 0; i < 8; i++) {
		minpool = CAST64(cvmx_read_csr(CVMX_FPA_QUEX_AVAILABLE(i)));
		if (minpool < zpool[i])
			zpool[i] = minpool;
		printf("   POOL: %d, free pages: 0x%llx MINPOOL:0x%llx\n", i,
		       (long long unsigned int)minpool,
		       (long long unsigned int)zpool[i]);
	}

#ifdef RLIMIT
	printf("\nFAU_COUNTS:\n");
	for (i = 0; i < MAX_INTERNAL_PORTS; i++) {
		fau = cvmx_fau_fetch_and_add64(pko_rate_limit[i].fau, 0);
		if (fau || pko_rate_limit[i].pkts_dropped || pko_rate_limit[i].is_rate_limit_on) {	//TBD:DBG:CLI
			printf("INP(%d): fau:%lld PktDrops:%lld ratelimit:%d\n",
			       i, (long long)fau,
			       (long long)pko_rate_limit[i].pkts_dropped,
			       pko_rate_limit[i].is_rate_limit_on);
		}
	}
#endif

	if (OCTEON_IS_MODEL(OCTEON_CN56XX)) {	/* 56xx: interrupt moderation */

		printf
		    ("\nNPEI_PKT_INT_LEVELS: 0x%llx interrupt moderation:%s\n",
		     (long long unsigned int)
		     cvmx_read_csr(CVMX_PEXP_NPEI_PKT_INT_LEVELS),
		     (intmod_enable) ? "enabled" : "disabled");
	} else {
		printf("\nSLI_PKT_INT_LEVELS: 0x%llx interrupt moderation:%s\n",
		       (long long unsigned int)
		       cvmx_read_csr(CVMX_PEXP_SLI_PKT_INT_LEVELS),
		       (intmod_enable) ? "enabled" : "disabled");
	}

	printf
	    ("intrmod_interval:%lld maxpkt_rate:%lld minpkt_rate:%lld maxcnt_trigger:%lld maxtmr_trigger:%lld maxlevels:%lld\n",
	     (long long)(intrmod_check_intrvl / cpu_freq),
	     (long long)intrmod_maxpkt_ratethr,
	     (long long)intrmod_minpkt_ratethr,
	     (long long)intrmod_maxcnt_trigger,
	     (long long)intrmod_maxtmr_trigger,
	     (long long)intrmod_intrvl_levels);

#if !defined(LINUX_IPSEC) && !defined(HYBRID)
	for (i = 0; i < MAX_OCTEON_NIC_PORTS; i++) {
		if (octnic->port[i].state.active) {
			printf
			    ("port:%d active:%d fromwire:fw_total_fwd:%llu fwd_rate:%llu\n",
			     i, octnic->port[i].state.active,
			     (long long unsigned int)octnic->port[i].stats.
			     fromwire.fw_total_fwd,
			     (long long unsigned int)octnic->port[i].stats.
			     fromwire.fwd_rate);
			fw_total_fwdrate +=
			    octnic->port[i].stats.fromwire.fwd_rate;
		}
	}
#endif //HYBRID 
	printf("fw_total_fwdrate:%llu\n",
	       (long long unsigned int)fw_total_fwdrate);
}

#ifdef RLIMIT
static void nic_cmdl_rlimit(int argc, char *argv[])
{				/* RateLimit feature: command-line to set ratelimit */
	int err, ipd_port, port = -1, on = 0;
	uint64_t rate = 10000ULL, burst = 10000ULL;

	if (argc != 3 && argc != 5) {
		printf("%s: Invalid Syntax\n", *argv);
		goto usage;
	}
	if (strncmp(argv[1], "oct", 3)) {
		printf("%s: Port Syntax Error\n", *argv);
		goto usage;
	}
	if ((sscanf(&argv[1][3], "%d", &port) != 1) || (port < 0 || port > 3)) {
		printf("%s: Portnumber Error\n", *argv);
		goto usage;
	}
	if (strcmp(argv[2], "on") && strcmp(argv[2], "off")) {
		printf("%s: Ratelimit action Error\n", *argv);
		goto usage;
	} else if (!strcmp(argv[2], "on"))
		on = 1;

	ipd_port = octnic->gmx_port_info[port].ipd_port;
	if (ipd_port < 0) {
		printf("%s: port:%d mapping error: port may not be up\n", *argv,
		       ipd_port);
		goto usage;
	}
	if (argc > 3) {
		if ((sscanf(argv[3], "%lld", (long long *)&rate) != 1) ||
		    (rate == 0ULL || rate > 10000ULL)) {
			printf("%s: Rate:%lld out of range\n", *argv,
			       (long long)rate);
			goto usage;
		}
		if ((sscanf(argv[4], "%lld", (long long *)&burst) != 1) ||
		    (burst == 0ULL || burst > 10000ULL)) {
			printf("%s: Burst:%lld out of range\n", *argv,
			       (long long)burst);
			goto usage;
		}
	}
	err = cvm_rate_limit(ipd_port, rate * 1000000ULL, burst * 1000000ULL);
	if (err) {
		printf("%s: %s error:%d setting rate-limit\n", *argv, argv[1],
		       err);
		on = 0;
	}
	pko_rate_limit[port].is_rate_limit_on = on;
	if (on) {
		printf("%s: %s set to rate:%lld MBps burst:%lld MB\n",
		       *argv, argv[1], (long long)rate, (long long)burst);
	} else {
		printf("%s: %s ratelimit off\n", *argv, argv[1]);
	}
	return;
 usage:
	printf("%s octX on|off [<rate in MBps> <burst in MB>]\n", *argv);
	printf("Examples:\n");
	printf
	    ("%s oct2 on 1000 1000 - rate-limit oct2 to 1GB after 1000MB burst\n",
	     *argv);
	printf("%s oct2 off - rate-limit turned off on oct2\n", *argv);
}
#endif

static void nic_cmdl_mintr(int argc, char *argv[])
{				/* intrmod: command-line set interrupt moderation params */
	int maxlevels;
	uint64_t maxpktrate, minpktrate, maxcsrcnt, maxcsrtmr, maxinterval;

	if (argc != 2 && argc != 8) {
		printf("%s: Invalid Syntax\n", *argv);
		goto usage;
	}
	if (strcmp(argv[1], "on") && strcmp(argv[1], "off")) {
		printf("%s: action Error\n", *argv);
		goto usage;
	} else {
		intmod_enable = strcmp(argv[1], "on") ? 0 : 1;
	}

	if (argc > 2) {
		if ((sscanf(argv[2], "%lld", (long long *)&maxinterval) != 1) ||
		    (maxinterval <= 0LL)) {
			printf("%s: interval:%lld out of range\n", *argv,
			       (long long)maxinterval);
			goto usage;
		}
		if ((sscanf(argv[3], "%lld", (long long *)&maxpktrate) != 1) ||
		    (maxpktrate == 0ULL)) {
			printf("%s: maxrate:%lld invalid\n", *argv,
			       (long long)maxpktrate);
			goto usage;
		}
		minpktrate = 0ULL;
		if (sscanf(argv[4], "%lld", (long long *)&minpktrate) != 1) {
			printf("%s: minpktrate:%lld invalid\n", *argv,
			       (long long)maxpktrate);
			goto usage;
		}
		if ((sscanf(argv[5], "%lld", (long long *)&maxcsrcnt) != 1) ||
		    (maxcsrcnt == 0ULL)) {
			printf("%s: maxcnt:%lld invalid\n", *argv,
			       (long long)maxcsrcnt);
			goto usage;
		}
		if ((sscanf(argv[6], "%lld", (long long *)&maxcsrtmr) != 1) ||
		    (maxcsrtmr == 0ULL)) {
			printf("%s: maxtmr:%lld invalid\n", *argv,
			       (long long)maxcsrtmr);
			goto usage;
		}
		if ((sscanf(argv[7], "%d", &maxlevels) != 1) ||
		    (maxlevels == 0ULL || (maxlevels & (maxlevels - 1)))) {
			printf("%s: maxlevels:%d invalid\n", *argv, maxlevels);
			goto usage;
		}
		intrmod_check_intrvl = maxinterval * cpu_freq;
		intrmod_maxpkt_ratethr = maxpktrate;
		intrmod_minpkt_ratethr = minpktrate;
		intrmod_maxcnt_trigger = maxcsrcnt;
		intrmod_maxtmr_trigger = maxcsrtmr;
		intrmod_intrvl_levels = maxlevels;
		intrmod_rxcnt_steps = (maxcsrcnt + maxlevels - 1) / maxlevels;
		intrmod_rxtmr_steps = (maxcsrtmr + maxlevels - 1) / maxlevels;
	}
	if (intmod_enable) {
		printf
		    ("%s %s interval:%lld maxrate:%lld minrate:%lld maxcnt:%lld maxtmr:%lld maxlevels:%d\n",
		     *argv, argv[1], (long long)maxinterval,
		     (long long)maxpktrate, (long long)minpktrate,
		     (long long)maxcsrcnt, (long long)maxcsrtmr, maxlevels);
	} else {
		printf("%s %s\n", *argv, argv[1]);
	}
	return;
 usage:
	printf
	    ("%s on|off [<interval(secs)><maxrate(pps)><minpktrate(pps)><maxcnt><maxtmr><maxlevels>]\n",
	     *argv);
	printf("Examples:\n");
	printf
	    ("%s on 1 200000 10000 320 128 4 - moderate interrupts every 1 sec. with specified parameters:\n",
	     *argv);
	printf
	    ("	- maxpktrate 200k pps minpktrate 10k pps intrpktcount 320 intrtimer 128 levels 4\n");
	printf("%s off - interrupt moderation turned off\n", *argv);
}

static void nic_cmdl_stats(int argc, char *argv[])
{				/* toggle display statistics: command-line for toggle */
	if (argc > 2) {
		printf("%s: Invalid Syntax\n", *argv);
		goto usage;
	}

	if (argc == 2) {
		if (strcmp(argv[1], "on") && strcmp(argv[1], "off")) {
			printf("%s: Invalid Syntax\n", *argv);
			goto usage;
		} else
			nic_duty_cycle = strcmp(argv[1], "on") ? 0 : 1;
	} else
		nic_duty_cycle = (~nic_duty_cycle) & 1;

	printf("periodic %s turned %s\n", *argv,
	       (nic_duty_cycle) ? "on" : "off");
	return;
 usage:
	printf("%s [on|off]\n", *argv);
}

void nic_cmdl_init(void)
{
	int i;
#if CONFIG_PCI_CONSOLE
	/* Initialize PCI command line block */
	const cvmx_bootmem_named_block_desc_t *block_desc =
	    cvmx_bootmem_find_named_block(OCTEON_PCI_CONSOLE_BLOCK_NAME);
	pci_console_desc_addr = block_desc->base_addr;
#endif				/* CONFIG_PCI_CONSOLE */

	/* Initialize registered verbs */
	for (i = 0; i < CMDL_MAX_VERBS; i++) {
		cmdl_registered_verbs[i].verb = NULL;
		cmdl_registered_verbs[i].proc = NULL;
	}

	nic_cmdl_register("help", nic_cmdl_help);
	nic_cmdl_register("sysinfo", nic_cmdl_show_sysinfo);
	// nic_cmdl_register("csr", nic_cmdl_csr);
#ifdef RLIMIT
	nic_cmdl_register("rlimit", nic_cmdl_rlimit);
#endif
	nic_cmdl_register("mintr", nic_cmdl_mintr);
	nic_cmdl_register("stats", nic_cmdl_stats);

	//register component specific commands
	cvmcs_nic_component_cmd_init();

	// nic_cmdl_showprompt();
}

#endif				/* CONFIG_NIC_CONSOLE */

