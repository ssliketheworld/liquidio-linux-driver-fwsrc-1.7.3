#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/ip.h>
#include <net/if.h>
#include <linux/ethtool.h>
#include <linux/sockios.h>
#include <errno.h>
#include "octeon-remote.h"
#include "cvmcs-nic-fwdump.h"
#include "cvmx-swap.h"

#define swap_8b_data(x)	cvmx_be64_to_cpu(x)
#define swap_4b_data(x)	cvmx_be32_to_cpu(x)

FILE *symfp;
FILE *logfp;
FILE *infp;

/* Print symbol associated with address */
int print_syms(unsigned int symaddr, FILE *fp)
{
	char buf[512] = { 0 };
	unsigned int addr = 0, nextaddr;

	char symbol[100], nxtsymbol[100], type;

	rewind(fp);
	while (fgets(buf, 512, fp)) {
		sscanf(buf, "%x %c %s", &addr, &type, symbol);
		if (!addr)
			continue;

		if (symaddr >= addr) {
			/*
			 * find next symbol
			 */
			int foff = ftell(fp);

			if (fgets(buf, 512, fp)) {
				sscanf(buf, "%x %c %s", &nextaddr, &type,
				       nxtsymbol);
				if (symaddr <= nextaddr) {
					/*
					 * We found the range, print the symbol
					 */
					if (logfp) {
						fprintf(logfp, "\n0x%x %s+0x%x",
							symaddr, symbol,
							symaddr - addr);

					} else {
						printf("\n0x%x %s+0x%x",
						       symaddr, symbol,
						       symaddr - addr);
					}
					break;
				}
			}
			fseek(fp, foff, SEEK_SET);
		}
	}
	return 0;
}

/* Print back trace based on crash data and symbol file */
int print_bt(struct cvmcs_nic_fwdump_info *fwdinfo,
	     struct crashinfo *cinfo, char *crashdata)
{
	int i, j, ret;
	char *buf;

	if (!cinfo->crashed)
		return 0;

	buf = crashdata + cinfo->btoff;

	if (symfp) { //symbol file
		char *tbuf = buf;
		int k = 0;
		int l = 0;
		char hash;
		int num;
		uint64_t symaddr;

		while (1) {
			while ((l < cinfo->btsize)
			       && (tbuf[l] == ' '))
				l++;
			if (l >= cinfo->btsize)
				break;

			/*replace '\n' with '\0' */
			while ((k < cinfo->btsize)
			       && (tbuf[k] != '\n'))
				k++;
			if (k >= cinfo->btsize)
				break;
			tbuf[k] = '\0';
			sscanf(&tbuf[l], "%c %d %lx", &hash, &num, &symaddr);
			print_syms(symaddr, symfp);
			k++;
			while ((k < cinfo->btsize)
			       && ((tbuf[k] == '\n')
				   || (tbuf[k] == '\0')))
				k++;
			if (k >= cinfo->btsize)
				break;
			l = k;
		}
	} else {
		if (logfp) {
			fwrite(buf, cinfo->btsize, 1, logfp);
		} else {
			for (j = 0; j < cinfo->btsize; j++)
				printf("%c", buf[j]);
		}
	}

	if (logfp)
		fprintf(logfp, "\n");
	else
		printf("\n");

	return 0;
}

/* Print crash log to stdout */
int print_crash_log(struct cvmcs_nic_fwdump_info *fwdinfo)
{
	uint32_t rem;
	struct crashinfo cinfo;
	uint32_t crashlogoff = 0;
	int len = 0;
	uint32_t phys = 0;
	int i, k, ncores;
	char *tbuf;

	phys = FWDUMP_BUF_SIZE;
	ncores = swap_4b_data(fwdinfo->ncores);

	if ((ncores < 0) || (ncores > 16)) {
		printf("No core crashed\n");
		return 0;
	}

	for (i = 0; i < ncores; i++) {
		crashlogoff = phys;
		fseek(infp, crashlogoff, SEEK_SET);

		fread(&cinfo, sizeof(struct crashinfo), 1, infp);
		cinfo.crashed = swap_4b_data(cinfo.crashed);
		cinfo.crashsize = swap_4b_data(cinfo.crashsize);
		cinfo.reginfoff = swap_4b_data(cinfo.reginfoff);
		cinfo.reginfosize = swap_4b_data(cinfo.reginfosize);
		cinfo.btoff = swap_4b_data(cinfo.btoff);
		cinfo.btsize = swap_4b_data(cinfo.btsize);
		cinfo.tlboff = swap_4b_data(cinfo.tlboff);
		cinfo.tlbsize = swap_4b_data(cinfo.tlbsize);

		if (cinfo.crashed) {
			if (cinfo.crashsize > FWDUMP_CRASH_SIZE) {
				//printf("crash size corrupt %d\n",
				//		cinfo.crashsize);
				goto next_core;
			}

			tbuf = malloc(cinfo.crashsize);
			if (!tbuf)
				return -1;

			fread(tbuf, cinfo.crashsize, 1, infp);

			if (logfp) {
				fwrite(tbuf, cinfo.crashsize, 1, logfp);
			} else {
				for (k = 0; k < cinfo.crashsize; k++)
					printf("%c", tbuf[k]);
				printf("\n");
			}
			print_bt(fwdinfo, &cinfo, tbuf);
			free(tbuf);
		}
next_core:
		phys += sizeof(struct crash);
	}

	return 0;
}

static void usage(char *command)
{
	printf("Usage: %s -d <dump-file> [-s <symbolfile>] [-l logfile] [-h]\n",
			command);
	printf("Where:\n");
	printf("-d <dump-file>: File got from \"ethtool -w\"\n");
	printf("-s <symbolfile>: Symbol file of firmware\n");
	printf("-l <logfile>: Log file where crash dump will be written to\n");
	printf("-h Prints this help\n");
	printf("\n");
}

int main(int argc, char *argv[])
{
	uint64_t status = 0;
	uint32_t offset, len;
	struct cvmcs_nic_fwdump_info *fwdinfo;
	char *logfile = NULL;
	char *symfile = NULL;
	char *infile = NULL;
	char *intf = NULL;
	int opt;
	int reset = 0;

	while ((opt = getopt(argc, argv, "hrs:l:d:")) != -1) {
		switch (opt) {
		case 'h':
			usage(argv[0]);
			return 0;
		case 'r':
			reset = 1;
			break;
		case 's':	//Symbol file
			symfile = optarg;
			break;
		case 'l':	//log crash dump output to a file
			logfile = optarg;
			break;
		case 'd':
			infile = optarg;
			break;
		default:
			usage(argv[0]);
			exit(EXIT_FAILURE);
		}
	}

	if (infile) {
		infp = fopen(infile, "r");
		if (!infp) {
			printf("Unable to open dump file: %s\n",
			       strerror(errno));
			exit(EXIT_FAILURE);
		}
	} else {
		fprintf(stderr, "%s: interface is mandatory.\n", argv[1]);
		return 1;
	}

	fwdinfo = malloc(sizeof(struct cvmcs_nic_fwdump_info));
	if (!fwdinfo)
		exit(EXIT_FAILURE);

	/*open symbol file */
	if (symfile) {
		symfp = fopen(symfile, "r");
		if (!symfp) {
			printf("Unable to open symbol file: %s\n",
			       strerror(errno));
			free(fwdinfo);
			exit(EXIT_FAILURE);
		}
	}

	if (logfile) {
		logfp = fopen(logfile, "w");
		if (!logfp) {
			printf("Unable to open log file: %s\n",
			       strerror(errno));
			if (symfp)
				fclose(symfp);
			free(fwdinfo);
			exit(EXIT_FAILURE);
		}
	}

	fread(fwdinfo, sizeof(struct cvmcs_nic_fwdump_info), 1, infp);
	status = swap_8b_data(fwdinfo->status);
	if (!(status & FWDUMP_CRASHED)) {
		printf("No crash detected.\n");
		return 0;
	}

	if (logfp)
		fprintf(logfp, "Number of cores %d\n",
				cvmx_be32_to_cpu(fwdinfo->ncores));
	else
		printf("Number of cores %d\n",
				cvmx_be32_to_cpu(fwdinfo->ncores));

	print_crash_log(fwdinfo);

	return 0;
}
