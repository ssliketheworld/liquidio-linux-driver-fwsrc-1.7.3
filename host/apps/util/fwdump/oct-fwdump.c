#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <getopt.h>
#include <fcntl.h>
#include <signal.h>
#include <errno.h>
#include "octeon-remote.h"
#include "cvmcs-nic-fwdump.h"
#include "cvmx-swap.h"

#define OCTEON_FWDUMP_REMOTE_PROTO "PCI"
#define WAIT_TIMEOUT	5

FILE *symfp;
FILE *logfp;

#define swap_8b_data(x)	cvmx_be64_to_cpu(x)
#define swap_4b_data(x)	cvmx_be32_to_cpu(x)

/* Print symbol associated with address */
int print_syms(unsigned int symaddr, FILE * fp)
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

	if (symfp) {		//symbol file
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
			for (j = 0; j < cinfo->btsize; j++) {
				printf("%c", buf[j]);
			}
		}
	}
	if (logfp)
		fprintf(logfp, "\n");
	else
		printf("\n");

	return 0;
}

/* Print crash log to stdout */
int print_crash_log(struct cvmcs_nic_fwdump_info *fwdinfo,
		    uint64_t fwdump_blkaddr)
{
	uint32_t rem;
	struct crashinfo cinfo;
	uint64_t crashlogptr = 0;
	int len = 0;
	uint64_t phys = 0;
	uint32_t i, j, k;
	char *tbuf;

	phys = fwdump_blkaddr + sizeof(*fwdinfo);

	for (i = 0; i < swap_4b_data(fwdinfo->ncores); i++) {
		j = 0;
		octeon_remote_read_mem((uint8_t *) & crashlogptr, phys,
				       sizeof(uint64_t));
		crashlogptr = swap_8b_data(crashlogptr);

		octeon_remote_read_mem((uint8_t *) & cinfo, crashlogptr,
				       sizeof(cinfo));
		cinfo.crashed = swap_4b_data(cinfo.crashed);
		cinfo.crashsize = swap_4b_data(cinfo.crashsize);
		cinfo.reginfoff = swap_4b_data(cinfo.reginfoff);
		cinfo.reginfosize = swap_4b_data(cinfo.reginfosize);
		cinfo.btoff = swap_4b_data(cinfo.btoff);
		cinfo.btsize = swap_4b_data(cinfo.btsize);
		cinfo.tlboff = swap_4b_data(cinfo.tlboff);
		cinfo.tlbsize = swap_4b_data(cinfo.tlbsize);

		if (cinfo.crashed) {
			rem = cinfo.crashsize;
			tbuf = malloc(rem);
			if (!tbuf) {
				return -1;
			}
			crashlogptr = crashlogptr + sizeof(cinfo);
			/*Read crash info into a temp buffer */
			j = 0;
			while (rem) {
				if (rem <= 1024)
					len = rem;
				else
					len = 1024;

				octeon_remote_read_mem((uint8_t *) tbuf + j,
						       crashlogptr, len);
				crashlogptr += len;
				rem -= len;
				j += len;
			}

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
		phys += sizeof(uint64_t);
	}

	return 0;
}

/* Read a crash dump into a preallocated buf. */
int read_crash_dump_to_buf(struct cvmcs_nic_fwdump_info *fwdinfo,
			   uint64_t fwdump_blkaddr, char *buf, int size)
{
	uint32_t rem;
	struct crashinfo cinfo;
	uint64_t crashlogptr = 0;
	int len = 0;
	uint64_t phys = 0;
	uint32_t i, j, k;
	char *tbuf;
	int count = 0, copy = 0;

	phys = fwdump_blkaddr + sizeof(*fwdinfo);

	for (i = 0; i < swap_4b_data(fwdinfo->ncores); i++) {
		j = 0;
		octeon_remote_read_mem((uint8_t *) & crashlogptr, phys,
				       sizeof(uint64_t));
		crashlogptr = swap_8b_data(crashlogptr);

		octeon_remote_read_mem((uint8_t *) & cinfo, crashlogptr,
				       sizeof(cinfo));
		cinfo.crashed = swap_4b_data(cinfo.crashed);
		cinfo.crashsize = swap_4b_data(cinfo.crashsize);
		cinfo.reginfoff = swap_4b_data(cinfo.reginfoff);
		cinfo.reginfosize = swap_4b_data(cinfo.reginfosize);
		cinfo.btoff = swap_4b_data(cinfo.btoff);
		cinfo.btsize = swap_4b_data(cinfo.btsize);
		cinfo.tlboff = swap_4b_data(cinfo.tlboff);
		cinfo.tlbsize = swap_4b_data(cinfo.tlbsize);
		cinfo.other_ptr = swap_8b_data(cinfo.other_ptr);
		cinfo.other_size = swap_8b_data(cinfo.other_size);

		if (cinfo.crashed) {
			rem = cinfo.crashsize;
			tbuf = malloc(rem);
			if (!tbuf) {
				printf
				    ("memory allocation failed for temp buf\n");
				return -1;
			}

			crashlogptr = crashlogptr + sizeof(cinfo);
			//      printf("Reading from %lx, size %ld\n", crashlogptr, sizeof(cinfo));
			/*Read crash info into a temp buffer */
			j = 0;
			while (rem) {
				if (rem <= 1024)
					len = rem;
				else
					len = 1024;

				octeon_remote_read_mem((uint8_t *) tbuf + j,
						       crashlogptr, len);
				crashlogptr += len;
				rem -= len;
				j += len;
			}

			if (j > (size - count))
				copy = size - count;
			else
				copy = j;

			memcpy(buf + count, tbuf, copy);
			count += copy;

			free(tbuf);

			/*Read crash other info section */
			if (cinfo.other_size) {
				tbuf = malloc(cinfo.other_size);
				if (tbuf == NULL) {
					return 0;
				}
				octeon_remote_read_mem((uint8_t *) tbuf,
						       cinfo.other_ptr,
						       cinfo.other_size);
				if (cinfo.other_size > (size - count))
					copy = size - count;
				else
					copy = cinfo.other_size;

				memcpy(buf + count, tbuf, copy);
				count += copy;
				free(tbuf);
			}

		}
		phys += sizeof(uint64_t);
	}

	return count;
}

static void usage(char *command)
{
	printf("Usage: %s [-s <symbolfile>] [-l logfile] [-p]\n", command);
	printf("Where:\n");
	printf("-s <symbolfile>: Symbol file of firmware\n");
	printf("-l <logfile>: Log file where crash dump will be written to\n");
	printf("-p poll mode. Continuously polls for crashes.\n");
	printf("\n");
}

/* Read a coredump from a LiquidIO board into a preallocated buf
 * of a given size. symfile is unused and should be NULL.
 *
 * Returns 0 if no core present, < 0 on error, or the count
 * of bytes read.
 */
int cvmcs_fwdump_read_coredump(char *buf, int size, char *symfile)
{
	int ret = 0;
	uint64_t fwdsize = 0;
	struct cvmcs_nic_fwdump_info *fwdinfo;
	uint64_t fwdump_blkaddr = 0;
	uint64_t status = 0;
	int opt;
	int count = 0;

	if (octeon_remote_open(OCTEON_FWDUMP_REMOTE_PROTO, 0)) {
		printf
		    ("Cannot communicate with octeon nic device on interface %s\n",
		     OCTEON_FWDUMP_REMOTE_PROTO);
		return -EIO;
	}

	if (!octeon_remote_mem_access_ok()) {
		printf("ERROR: Unable to read access firmware\n");
		octeon_remote_close();
		return -EIO;
	}

	if (!octeon_remote_named_block_find
	    (OCT_NIC_FWDUMP_BLOCK_NAME, &fwdump_blkaddr, &fwdsize)) {
		printf
		    ("ERROR: FWDUMP buffers not found in firmware, exiting...\n");
		octeon_remote_close();
		return -EINVAL;
	}

	fwdinfo = malloc(sizeof(*fwdinfo));
	if (!fwdinfo) {
		octeon_remote_close();
		return -ENOMEM;
	}

	/*open symbol file */
	if (symfile) {
		symfp = fopen(symfile, "r");
		if (!symfp) {
			printf("Unable to open symbol file: %s\n",
			       strerror(errno));
			free(fwdinfo);
			octeon_remote_close();
			return -ENOENT;
		}
	}

	/*Read first 64 bits of block to check if fw dumped */
	status = octeon_remote_read_mem64(fwdump_blkaddr + offsetof(struct
								    cvmcs_nic_fwdump_info,
								    status));
	if (!(status & FWDUMP_CRASHED)) {
		free(fwdinfo);
		octeon_remote_close();
		return 0;
	}

	/*read fwdump header */
	octeon_remote_read_mem(fwdinfo, fwdump_blkaddr,
			       sizeof(struct cvmcs_nic_fwdump_info));

	count += snprintf(buf + count, size - count, "Number of cores %d\n",
			  cvmx_be32_to_cpu(fwdinfo->ncores));

	count +=
	    read_crash_dump_to_buf(fwdinfo, fwdump_blkaddr, buf, size - count);

	free(fwdinfo);

	octeon_remote_close();

	return count;
}

/* Read the boot log from a LiquidIO board into a preallocated buf
 * of a given size. 
 *
 * Returns 0 if no core present, < 0 on error, or the count
 * of bytes read.
 */
int cvmcs_fwdump_read_boot_log(char *buf, int size)
{
	int ret = 0;
	uint64_t fwdsize = 0;
	struct cvmcs_nic_fwdump_info *fwdinfo;
	uint64_t fwdump_blkaddr = 0;
	uint64_t status = 0;
	int opt;
	int count = 0;

	if (octeon_remote_open(OCTEON_FWDUMP_REMOTE_PROTO, 0)) {
		printf
		    ("Cannot communicate with octeon nic device on interface %s\n",
		     OCTEON_FWDUMP_REMOTE_PROTO);
		return -EIO;
	}

	if (!octeon_remote_mem_access_ok()) {
		printf("ERROR: Unable to read access firmware\n");
		octeon_remote_close();
		return -EIO;
	}

	if (!octeon_remote_named_block_find
	    (OCT_NIC_FWDUMP_BLOCK_NAME, &fwdump_blkaddr, &fwdsize)) {
		printf
		    ("ERROR: FWDUMP buffers not found in firmware, exiting...\n");
		octeon_remote_close();
		return -EINVAL;
	}

	fwdinfo = malloc(sizeof(*fwdinfo));
	if (!fwdinfo) {
		octeon_remote_close();
		return -ENOMEM;
	}


	/*read fwdump header */
	octeon_remote_read_mem(fwdinfo, fwdump_blkaddr,
			       sizeof(struct cvmcs_nic_fwdump_info));


	if (swap_4b_data(fwdinfo->logsize) > size)
		count = size;
	else
		count = swap_4b_data(fwdinfo->logsize);


	octeon_remote_read_mem(buf, fwdump_blkaddr + swap_4b_data(fwdinfo->bloff), count);

	free(fwdinfo);

	octeon_remote_close();

	return count;
}

int main(int argc, char *argv[])
{
	int ret = 0;
	uint64_t size = 0;
	struct cvmcs_nic_fwdump_info *fwdinfo;
	uint64_t fwdump_blkaddr = 0;
	uint64_t status = 0;
	int opt;
	char *symfile = NULL;
	char *logfile = NULL;
	int poll = 0;

	while ((opt = getopt(argc, argv, "hps:l:")) != -1) {
		switch (opt) {
		case 'h':
			usage(argv[0]);
			return 0;
		case 'p':
			poll = 1;
			break;
		case 's':	//Symbol file
			symfile = optarg;
			break;
		case 'l':	//log crash dump output to a file
			logfile = optarg;
			break;
		default:
			usage(argv[0]);
			exit(EXIT_FAILURE);
		}
	}
	if (octeon_remote_open(OCTEON_FWDUMP_REMOTE_PROTO, 0)) {
		printf
		    ("Cannot communicate with octeon nic device on interface %s. Check permissions.\n",
		     OCTEON_FWDUMP_REMOTE_PROTO);
		return -1;
	}

	if (!octeon_remote_mem_access_ok()) {
		printf("ERROR: Unable to read access firmware\n");
		octeon_remote_close();
		exit(EXIT_FAILURE);
	}

	if (!octeon_remote_named_block_find
	    (OCT_NIC_FWDUMP_BLOCK_NAME, &fwdump_blkaddr, &size)) {
		printf
		    ("ERROR: FWDUMP buffers not found in firmware, exiting...\n");
		octeon_remote_close();
		exit(EXIT_FAILURE);
	}

	fwdinfo = malloc(sizeof(*fwdinfo));
	if (!fwdinfo) {
		octeon_remote_close();
		exit(EXIT_FAILURE);
	}

	/*open symbol file */
	if (symfile) {
		symfp = fopen(symfile, "r");
		if (!symfp) {
			printf("Unable to open symbol file: %s\n",
			       strerror(errno));
			free(fwdinfo);
			octeon_remote_close();
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
			octeon_remote_close();
			exit(EXIT_FAILURE);
		}
	}
	while (1) {
		/*Read first 64 bits of block to check if fw dumped */
		status = octeon_remote_read_mem64(fwdump_blkaddr + offsetof(struct
									    cvmcs_nic_fwdump_info,
									    status));
		if (!(status & FWDUMP_CRASHED)) {
			if (poll) {
				sleep(WAIT_TIMEOUT);
				continue;	//Not crashed
			} else {
				printf("No crash detected.\n");
				exit(0);
			}
		}

		/*read fwdump header */
		octeon_remote_read_mem(fwdinfo, fwdump_blkaddr,
				       sizeof(struct cvmcs_nic_fwdump_info));

		if (logfp)
			fprintf(logfp, "Number of cores %d\n",
				cvmx_be32_to_cpu(fwdinfo->ncores));
		else
			printf("Number of cores %d\n",
			       cvmx_be32_to_cpu(fwdinfo->ncores));

		print_crash_log(fwdinfo, fwdump_blkaddr);
		break;
	}

	free(fwdinfo);

	octeon_remote_close();

	return ret;
}
