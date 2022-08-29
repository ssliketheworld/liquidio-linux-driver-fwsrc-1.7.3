/*---------------------------------------------------------------------------
 * 
 * oct-nvmestats.c 
 *
 *---------------------------------------------------------------------------
 */
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <getopt.h>
#include <fcntl.h>
#include <signal.h>
#include <errno.h>
#include <stddef.h>
#include <time.h>

#include "nvme_stats_info.h"
#include "cvmx-clock.h"
#include "cvmx-version.h"
#include "octeon-remote.h"
#include <octeon_mem_map.h>
#include "cvmx-bootmem.h"
#include <endian.h>

#define OCTEON_NVME_STATS_REMOTE_PROTO "PCI"
nvme_global_stats_t global_stats;
nvme_per_cpu_stats_t pcpu_stats[17];
nvme_per_cpu_stats_t *pcpu_stats_p[17];
uint64_t pcpu_stats_addr[17];
nvme_per_cpu_stats_t old_data;
struct timespec old_data_ts;
nvme_per_cpu_stats_t data;
nvme_io_q_stats_t old_acc_iosq_stats[NVME_VF_MAX];
nvme_io_q_stats_t acc_iosq_stats[NVME_VF_MAX];
struct timespec data_ts;
static uint64_t  have_global_stats;
static int max_cpu_idx;
static uint8_t print_dma;
static int dmaid = -1;
static uint8_t print_ns;
static int nsid = -1;
static uint8_t print_iosq;
static int sqid = -1;
static uint8_t print_aq;
static int vfid = -1;
static int coreid = -1;
static int poll_sec;
static uint8_t print_detail;
static uint8_t print_inactive;
static uint64_t remote_cpu_freq;

#define debug(...)

#define GSQID_TO_VFID(__g_io_sqid) \
          ((__g_io_sqid - 1)/global_stats.max_ioq_per_vf)
            
#define ACCUMULATE_DATA(dest, source, member) \
            dest.member += be64toh(source.member)
#define UPDATE_TIMESTAMP(dest, source, member) \
            dest.member = dest.member > be64toh(source.member) ? \
                                dest.member : be64toh(source.member)

#define TIMEDIFF_MSEC(__old, __new) \
        ((uint64_t)(__new.tv_sec * 1000) + __new.tv_nsec/1000000 - \
         (uint64_t)(__old.tv_sec * 1000) - __old.tv_nsec/1000000)

#define CYCLE_COUNT_TO_USEC(__count) \
            ((uint64_t) __count / (remote_cpu_freq / 1000000))




static void
conv_global_stats_betoh(nvme_global_stats_t *statsp)
{
    int i;

    for (i = 0; i < sizeof(statsp->vf_bitmap)/sizeof(uint64_t) ; i++)
        statsp->vf_bitmap[i] = be64toh(statsp->vf_bitmap[i]);

    statsp->active_vfs = be64toh(statsp->active_vfs);
    statsp->active_coremask = be64toh(statsp->active_coremask);
    statsp->core_clock = be64toh(statsp->core_clock);
    statsp->last_error_ts = be64toh(statsp->last_error_ts);
    statsp->last_error_status = be64toh(statsp->last_error_status);
    statsp->n_queues = be32toh(statsp->n_queues);
    statsp->max_ioq_per_vf = be32toh(statsp->max_ioq_per_vf);
    statsp->max_vf_possible = be32toh(statsp->max_vf_possible);

    for (i = 0; i < sizeof(statsp->vf_state)/sizeof(uint32_t); i++)
        statsp->vf_state[i] = be32toh(statsp->vf_state[i]);
    for (i = 0; i < sizeof(statsp->vf_to_ns_map)/sizeof(uint32_t); i++)
        statsp->vf_to_ns_map[i] = be32toh(statsp->vf_to_ns_map[i]);

}

static void
conv_pcpu_stats_betoh(nvme_per_cpu_stats_t *statsp)
{
    statsp->n_wqe = be64toh(statsp->n_wqe);
    statsp->last_wqe_ts = be64toh(statsp->last_wqe_ts);
    statsp->coreid = be32toh(statsp->coreid);
}

static void
print_global_stats(void)
{
    if (!have_global_stats)
        return;
    printf("Number of VF's active\t\t:\t %ld(%u)\n", global_stats.active_vfs, global_stats.max_vf_possible);
    printf("Coremask of active cores\t:\t 0x%.4lX\n", global_stats.active_coremask);
    printf("Core Clock\t\t\t:\t %4.4lu MHz\n", remote_cpu_freq/1000000);
    if (global_stats.last_error_ts) {
        printf("Last error time stamp\t\t:\t %lu\n", global_stats.last_error_ts);
        printf("Last error status\t\t:\t %lu\n", global_stats.last_error_status);
    }
}

/*
 * Fetches remote mem in multiples of 1KB
 */
static void
fetch_octeon_remote_mem(char *dest, uint64_t addr, int len) 
{ 
    int i = 0, j = 0;

    do {
        if ((len - i) > 1024) {
            j = 1024;
        } else {
            j = len - i;
        }

        octeon_remote_read_mem(dest + i, addr + i, j);

        i += j;
    } while (i < len);

}

static int
is_vf_active(int id)
{
    uint64_t map;

    if (!have_global_stats)
        return 0;
    
    if (print_inactive)
        return 1;

    map = global_stats.vf_bitmap[id/64];


    if (map && (map & ((uint64_t)1 << (id%64)))) {
        return 1;
    }

    return 0;
}

/*
 * Retrieve IOSQ stats from Octeon and update them
 * locally
 */

static void
update_iosq_data(int core)
{
    int i, max;
    int j;

    if (!pcpu_stats_p[core])
        return;

    if (sqid > 0 && vfid >= 0) {
        i = sqid + vfid*global_stats.max_ioq_per_vf;
        max = i;
    } else {
        if (vfid >= 0) {
            i = 1 + vfid*global_stats.max_ioq_per_vf;
            max = i + global_stats.max_ioq_per_vf;
        } else {
            i = 1;
            max = NVME_G_IO_SQ_MAX;
        }
    }
    do {
        j = GSQID_TO_VFID(i);

        if (!is_vf_active(j)) {
            i++;
            continue;
        }
        fetch_octeon_remote_mem((char *)&(pcpu_stats_p[core]->g_io_sq[i]), 
                                pcpu_stats_addr[core] + offsetof(struct nvme_per_cpu_stats_s, g_io_sq[i]), 
                                sizeof(pcpu_stats_p[core]->g_io_sq[i]));

        ACCUMULATE_DATA(data.g_io_sq[i], pcpu_stats_p[core]->g_io_sq[i], rd_cmds); 
        ACCUMULATE_DATA(data.g_io_sq[i], pcpu_stats_p[core]->g_io_sq[i], wr_cmds); 
        ACCUMULATE_DATA(data.g_io_sq[i], pcpu_stats_p[core]->g_io_sq[i], rd_bytes); 
        ACCUMULATE_DATA(data.g_io_sq[i], pcpu_stats_p[core]->g_io_sq[i], wr_bytes); 
        ACCUMULATE_DATA(data.g_io_sq[i], pcpu_stats_p[core]->g_io_sq[i], rd_time); 
        ACCUMULATE_DATA(data.g_io_sq[i], pcpu_stats_p[core]->g_io_sq[i], wr_time); 
        ACCUMULATE_DATA(data.g_io_sq[i], pcpu_stats_p[core]->g_io_sq[i], aborted); 
        ACCUMULATE_DATA(data.g_io_sq[i], pcpu_stats_p[core]->g_io_sq[i], errors); 
        ACCUMULATE_DATA(data.g_io_sq[i], pcpu_stats_p[core]->g_io_sq[i], completions); 
        UPDATE_TIMESTAMP(data.g_io_sq[i], pcpu_stats_p[core]->g_io_sq[i], last_sub_ts); 
        UPDATE_TIMESTAMP(data.g_io_sq[i], pcpu_stats_p[core]->g_io_sq[i], last_compl_ts); 

        i++;
    } while (i < max);
}

/*
 * Retrieve Admin Queue stats from Octeon and update
 * them locally
 */
static void
update_aq_data(int core)
{
    int i, max;

    if (!pcpu_stats_p[core])
        return;

    if (vfid >= 0) {
        i = vfid;
        max = vfid;
    } else {
        i = 0;
        max = global_stats.max_vf_possible;
    }
    do {
        if (!is_vf_active(i)) {
            i++;
            continue;
        }
        
        fetch_octeon_remote_mem((char *)&(pcpu_stats_p[core]->g_admin_q[i]), 
                                pcpu_stats_addr[core] + offsetof(struct nvme_per_cpu_stats_s, g_admin_q[i]), 
                                sizeof(pcpu_stats_p[core]->g_admin_q[i]));

        ACCUMULATE_DATA(data.g_admin_q[i], pcpu_stats_p[core]->g_admin_q[i], submitted); 
        ACCUMULATE_DATA(data.g_admin_q[i], pcpu_stats_p[core]->g_admin_q[i], completed); 
        ACCUMULATE_DATA(data.g_admin_q[i], pcpu_stats_p[core]->g_admin_q[i], errors); 
        UPDATE_TIMESTAMP(data.g_admin_q[i], pcpu_stats_p[core]->g_admin_q[i], last_sub_ts); 
        UPDATE_TIMESTAMP(data.g_admin_q[i], pcpu_stats_p[core]->g_admin_q[i], last_compl_ts); 

        i++;
    } while (i < max);
}

/*
 * Retrieve Name Space statistics from Octeon and update them locally
 */
static void
update_ns_data(int core)
{
    int i, max;

    if (!pcpu_stats_p[core])
        return;

    if (nsid > 0) {
        i = nsid;
        max = nsid;
    } else {
        i = 1;
        max = NVME_NS_MAX;
    }
    do {
        
        fetch_octeon_remote_mem((char *)&(pcpu_stats_p[core]->g_ns[i]), 
                                pcpu_stats_addr[core] + offsetof(struct nvme_per_cpu_stats_s, g_ns[i]), 
                                sizeof(pcpu_stats_p[core]->g_ns[i]));

        ACCUMULATE_DATA(data.g_ns[i], pcpu_stats_p[core]->g_ns[i], rd_cmds); 
        ACCUMULATE_DATA(data.g_ns[i], pcpu_stats_p[core]->g_ns[i], wr_cmds); 
        ACCUMULATE_DATA(data.g_ns[i], pcpu_stats_p[core]->g_ns[i], rd_bytes); 
        ACCUMULATE_DATA(data.g_ns[i], pcpu_stats_p[core]->g_ns[i], wr_bytes); 
        ACCUMULATE_DATA(data.g_ns[i], pcpu_stats_p[core]->g_ns[i], rd_time); 
        ACCUMULATE_DATA(data.g_ns[i], pcpu_stats_p[core]->g_ns[i], wr_time); 
        UPDATE_TIMESTAMP(data.g_ns[i], pcpu_stats_p[core]->g_ns[i], last_error_ts); 
        ACCUMULATE_DATA(data.g_ns[i], pcpu_stats_p[core]->g_ns[i], errors); 

        i++;
    } while (i < max);
}

/*
 * Retrieve DMA stats from Octeon and accumulate them
 */
static void
update_dma_data(int core)
{
    int i, max;

    if (!pcpu_stats_p[core])
        return;

    if (dmaid >= 0) {
        i = dmaid;
        max = dmaid;
    } else {
        i = 0;
        max = NVME_DMA_ENGINE_MAX;
    }
    do {
            
        fetch_octeon_remote_mem((char *)&(pcpu_stats_p[core]->dma[i]), 
                                pcpu_stats_addr[core] + offsetof(struct nvme_per_cpu_stats_s, dma[i]), 
                                sizeof(pcpu_stats_p[core]->dma[i]));

        ACCUMULATE_DATA(data.dma[i], pcpu_stats_p[core]->dma[i], inb_cmds); 
        ACCUMULATE_DATA(data.dma[i], pcpu_stats_p[core]->dma[i], outb_cmds); 
        ACCUMULATE_DATA(data.dma[i], pcpu_stats_p[core]->dma[i], inb_time); 
        ACCUMULATE_DATA(data.dma[i], pcpu_stats_p[core]->dma[i], outb_time); 
        UPDATE_TIMESTAMP(data.dma[i], pcpu_stats_p[core]->dma[i], last_dma_ts); 
        ACCUMULATE_DATA(data.dma[i], pcpu_stats_p[core]->dma[i], errors); 

        i++;
    } while (i < max);
}
/*
 * Update global data
 */
static int
update_global_data(void)
{
    fetch_octeon_remote_mem((char *)&global_stats, have_global_stats, sizeof(global_stats)); 
    conv_global_stats_betoh(&global_stats);
    return 0;
}

/*
 * Accumulate per cpu data
 */
static int
update_pcpu_data(void)
{
    int i, max;
    
    memcpy(&old_data, &data, sizeof(data));
    memcpy(&old_acc_iosq_stats, &acc_iosq_stats, sizeof(acc_iosq_stats));
    old_data_ts = data_ts;

    memset(&data, 0, sizeof(data));
    memset(&acc_iosq_stats, 0, sizeof(acc_iosq_stats));

    octeon_remote_lock();
    if (coreid >= 0) {
        i = coreid;
        max = coreid;
    } else {
        i = 0;
        max = 16;
    }

    if (clock_gettime(CLOCK_MONOTONIC, &data_ts)) {
        perror("clock_gettime()\n");
        goto fail;
    }

    do {

        if (!((1 << i) & global_stats.active_coremask)) {
            i++;
            continue;
        }
        if (pcpu_stats_p[i]) {

            if (pcpu_stats_p[i]->coreid != i) {
                printf("ERROR: Remote read failed for addr 0x%lx core %d !!! %d\n", pcpu_stats_addr[i], i, pcpu_stats_p[i]->coreid);
                goto fail;
            }

            if (print_dma) {
                update_dma_data(i);
            }

            if (print_ns) {
                update_ns_data(i);
            }

            if (print_iosq) {
                update_iosq_data(i);
            }

            if (print_aq) {
                update_aq_data(i);
            }

            pcpu_stats_p[i]->n_wqe =  octeon_remote_read_mem64(pcpu_stats_addr[i] + 
                                                                offsetof(struct nvme_per_cpu_stats_s, n_wqe));
            pcpu_stats_p[i]->n_wqe = htobe64(pcpu_stats_p[i]->n_wqe);

            pcpu_stats_p[i]->last_wqe_ts =  octeon_remote_read_mem64(pcpu_stats_addr[i] + 
                                                                offsetof(struct nvme_per_cpu_stats_s, last_wqe_ts));
            pcpu_stats_p[i]->last_wqe_ts = htobe64(pcpu_stats_p[i]->last_wqe_ts);

            ACCUMULATE_DATA(data, (*pcpu_stats_p[i]), n_wqe);
            UPDATE_TIMESTAMP(data, (*pcpu_stats_p[i]), last_wqe_ts);
        }
        i++;
    } while (i < max);

    octeon_remote_unlock();
    return 0;
fail:
    octeon_remote_unlock();
    return -1;
}


/*
 * Print per cpu data
 */
static void
print_pcpu_data(void)
{
    int i, max, j = 0;

    printf("Number of WQE processed\t\t:\t %lu\n", data.n_wqe);
    printf("WQE last processed\t\t:\t %lu(usec)\n", CYCLE_COUNT_TO_USEC((data.last_wqe_ts)));
    
    if (coreid > -1)
        printf("Printing stats of core %d\n", coreid);

    if (print_iosq) {
        uint64_t rd_rate = 0, wr_rate = 0;
    
        printf(" IOSQ stats\n");
        if ((sqid > 0) && (vfid >= 0)) {
            /* Case of request to print only one SQ stats */
            i = sqid + vfid*global_stats.max_ioq_per_vf;
            max = i;
        } else if (vfid >= 0) {
            /* Case of request to print only all SQ stats of one VF */
            i = 1 + vfid*global_stats.max_ioq_per_vf;
            max = i + global_stats.max_ioq_per_vf;
        } else {
            /* Case of request to print all SQ stats of all VFs */
            i = 1;
            max = NVME_G_IO_SQ_MAX;
        }

        do {

            j = GSQID_TO_VFID(i);

            if (!is_vf_active(j)) {
                i++;
                continue;
            }

            if (print_detail) {
                if (old_data_ts.tv_sec != 0) {
                    rd_rate = (double)(data.g_io_sq[i].rd_bytes - old_data.g_io_sq[i].rd_bytes) /
                        (TIMEDIFF_MSEC(old_data_ts, data_ts));
                    wr_rate = (double)(data.g_io_sq[i].wr_bytes - old_data.g_io_sq[i].wr_bytes) /
                        (TIMEDIFF_MSEC(old_data_ts, data_ts));

                }
                printf("   IOSQ %4.4d:%2.2d (vfid:sqid) rd_cmds=%lu wr_cmds=%lu "
                        "rd_io=%luMB wr_io=%luMB rd_rate=%luKBps wr_rate=%luKBps\n",
                        GSQID_TO_VFID(i), 
                        i - global_stats.max_ioq_per_vf * GSQID_TO_VFID(i),
                        data.g_io_sq[i].rd_cmds,
                        data.g_io_sq[i].wr_cmds,
                        data.g_io_sq[i].rd_bytes/(1024*1024),
                        data.g_io_sq[i].wr_bytes/(1024*1024),
                        rd_rate,
                        wr_rate);
            }

            /* Accumulate all stats in seperate location for a vf */
            acc_iosq_stats[j].rd_cmds += data.g_io_sq[i].rd_cmds;
            acc_iosq_stats[j].wr_cmds += data.g_io_sq[i].wr_cmds;
            acc_iosq_stats[j].rd_bytes += data.g_io_sq[i].rd_bytes;
            acc_iosq_stats[j].wr_bytes += data.g_io_sq[i].wr_bytes;

            if ((GSQID_TO_VFID(i+1) == (j + 1)) && (sqid == -1)) {

                if (old_data_ts.tv_sec != 0) {
                    rd_rate = (uint64_t)(acc_iosq_stats[j].rd_bytes - old_acc_iosq_stats[j].rd_bytes) /
                        (TIMEDIFF_MSEC(old_data_ts, data_ts));
                    wr_rate = (uint64_t)(acc_iosq_stats[j].wr_bytes - old_acc_iosq_stats[j].wr_bytes) /
                        (TIMEDIFF_MSEC(old_data_ts, data_ts));

                }
                /* Print accumulated stats of a VF */
                printf("   IOSQ %4.4d:XX (vfid:sqid) rd_cmds=%lu wr_cmds=%lu "
                        "rd_io=%luMB wr_io=%luMB rd_rate=%luKBps wr_rate=%luKBps\n",
                        GSQID_TO_VFID(i), 
                        acc_iosq_stats[j].rd_cmds,
                        acc_iosq_stats[j].wr_cmds,
                        acc_iosq_stats[j].rd_bytes/(1024*1024),
                        acc_iosq_stats[j].wr_bytes/(1024*1024),
                        rd_rate,
                        wr_rate);
            }

            i++;
        } while (i < max);

    }

    /* Print DMA stats */
    if (print_dma) {
        printf(" DMA engine stats\n");
        if (dmaid >= 0) {
            i = dmaid;
            max = dmaid;
        } else {
            i = 0;
            max = NVME_DMA_ENGINE_MAX;
        }

        do {
            printf("   DMA %2.2d (eid) inb_cmds=%lu outb_cmds=%lu "
                    "inb_time=%lu(usec) outb_time=%lu(usec) last_dma_ts=%lu(usec)\n",
                    i,
                    data.dma[i].inb_cmds,
                    data.dma[i].outb_cmds,
                    CYCLE_COUNT_TO_USEC(data.dma[i].inb_time),
                    CYCLE_COUNT_TO_USEC(data.dma[i].outb_time),
                    CYCLE_COUNT_TO_USEC(data.dma[i].last_dma_ts));
            i++;
        } while (i < max);
    }

    /* Print Name space stats */
    if (print_ns) {
        uint64_t rd_rate = 0, wr_rate = 0;

        printf(" Name space stats\n");
        if (nsid > 0) {
            i = nsid;
            max = nsid;
        } else {
            i = 1;
            max = NVME_NS_MAX;
        }

        do {
            if (old_data_ts.tv_sec != 0) {
                rd_rate = (uint64_t)(data.g_ns[i].rd_bytes - old_data.g_ns[i].rd_bytes) /
                    (TIMEDIFF_MSEC(old_data_ts, data_ts));
                wr_rate = (uint64_t)(data.g_ns[i].wr_bytes - old_data.g_ns[i].wr_bytes) /
                    (TIMEDIFF_MSEC(old_data_ts, data_ts));

            }
        
            printf("   NS %4.4d (nsid) rd_cmds=%lu wr_cmds=%lu "
                    "rd_io=%luMB wr_io=%luMB rd_rate=%luKBps wr_rate=%luKBps\n",
                    i,
                    data.g_ns[i].rd_cmds,
                    data.g_ns[i].wr_cmds,
                    data.g_ns[i].rd_bytes/(1024*1024),
                    data.g_ns[i].wr_bytes/(1024*1024),
                    rd_rate,
                    wr_rate);
            i++;
        } while (i < max);
    }

    /* Print Admin queue stat */
    if (print_aq) {
        printf(" Admin queue stats\n");
        if (vfid >= 0) {
            i = vfid;
            max = vfid;
        } else {
            i = 0;
            max = global_stats.max_vf_possible;
        }

        do {
            if (!is_vf_active(i)) {
                i++;
                continue;
            }
            printf("   AQ %2.2d (vfid) submitted=%lu completed=%lu "
                    "last_sub_ts=%lu(usec) last_compl_ts=%lu(usec) errors=%lu\n",
                    i,
                    data.g_admin_q[i].submitted,
                    data.g_admin_q[i].completed,
                    CYCLE_COUNT_TO_USEC(data.g_admin_q[i].last_sub_ts),
                    CYCLE_COUNT_TO_USEC(data.g_admin_q[i].last_compl_ts),
                    data.g_admin_q[i].errors);

            i++;
        } while(i < max);
    }
}

static void usage(char *command)
{
	printf("Usage: %s [options]\n", command);
	printf("Where:\n");
	printf("-D[eid]: Print DMA stats of all engines or 'eid' engine\n");
	printf("-N[nsid]: Print NS stats for all or of 'nsid'\n");
	printf("-I[sqid]: Print IOQ stats for all or of 'sqid, 'vfid' sqid (1 - N)'\n");
	printf("-A : Print AQ stats for all or of a 'vfid'\n");
	printf("-V vfid: Print stats for VF identified by 'vfid''\n");
	printf("-a : Same as '-DNI'\n");
	printf("-C[coreid]: Print stats of specific coreid (Default is cumulative of all cores)\n");
	printf("-p[n] Continuously polls for data and prints every n seconds (min 5).\n");
	printf("-i Print inactive VF stats as well\n");
	printf("-v : Verbose output.\n");
	printf("\n");
}

int main(int argc, char *argv[])
{
    uint64_t addr, size;
    int ret;
    uint32_t type, len;
    char opt;
    int i;

    while ((opt = getopt(argc, argv, "D::N::ivaI::V:AC:p:")) != -1) {
        switch (opt) {
            case 'D':
                print_dma = 1;
                if (optarg) {
                    errno = 0;
                    dmaid = strtoul(optarg, NULL, 0);
                    if (errno)
                        dmaid = -1;
                }
                break;
            case 'a':
                print_dma = 1;
                print_ns = 1;
                print_aq = 1;
                print_iosq = 1;
                break;
            case 'p':
                if (optarg) {
                    errno = 0;
                    poll_sec = strtoul(optarg, NULL, 0);
                    if (errno)
                        poll_sec = 0;
                    if (poll_sec > 0 && poll_sec < 5)
                        poll_sec = 5;
                }
                break;
            case 'C':
                if (optarg) {
                    errno = 0;
                    coreid = strtoul(optarg, NULL, 0);
                    if (errno)
                        coreid = -1;
                }
                break;
            case 'N':
                print_ns = 1;
                if (optarg) {
                    errno = 0;
                    nsid = strtoul(optarg, NULL, 0);
                    if (errno || !nsid)
                        nsid = -1;
                }
                break;
            case 'A':
                print_aq = 1;
                break;
            case 'V':
                if (optarg) {
                    errno = 0;
                    vfid = strtoul(optarg, NULL, 0);
                    if (errno)
                        vfid = -1;
                }
                break;
            case 'I':
                print_iosq = 1;
                if (optarg) {
                    errno = 0;
                    sqid = strtoul(optarg, NULL, 0);
                    if (errno || (sqid == 0))
                        sqid = -1;
                }
                break;
            case 'v':
                print_detail = 1;
                break;
            case 'i':
                print_inactive = 1;
                break;
            default:
                usage(argv[0]);
                exit(EXIT_FAILURE);
        }
    }

    if (octeon_remote_open(OCTEON_NVME_STATS_REMOTE_PROTO, 0))
        return -1;

    if (!octeon_remote_mem_access_ok())
    {
        printf("ERROR: DRAM not setup, board needs to be booted\n");
        return -1;
    } 

    if (!octeon_remote_named_block_find(OCTEON_NVME_STATS_BLOCK_NAME, &addr, &size))
    {
        printf("ERROR: NVME stats buffer not found\n");
        exit(-1);
    }

    debug("DEBUG: Found %s at 0x%lx, size %lu\n", OCTEON_NVME_STATS_BLOCK_NAME, addr, size);

    type = octeon_remote_read_mem32(addr);
    addr += sizeof(uint32_t);


    while (type != OCTEON_NVME_STATS_TYPE_NONE) {
        len = octeon_remote_read_mem32(addr);
        addr += sizeof(uint32_t);
        debug("DEBUG: Found info of addr 0x%lx type %x, length %u bytes\n", addr, type, len);

        switch (type) {
            case OCTEON_NVME_STATS_TYPE_GLOBAL:
                fetch_octeon_remote_mem((char *)&global_stats, addr, len); 
                have_global_stats = addr;
                conv_global_stats_betoh(&global_stats);
                break;
            case OCTEON_NVME_STATS_TYPE_PCPU:
                memset(&pcpu_stats[max_cpu_idx], 0xbb, len);
                fetch_octeon_remote_mem((char *)(&pcpu_stats[max_cpu_idx]), addr, sizeof(pcpu_stats[0]));
                ret = pcpu_stats[max_cpu_idx].coreid;
                conv_pcpu_stats_betoh(&pcpu_stats[max_cpu_idx]);
                i = pcpu_stats[max_cpu_idx].coreid;
                if (pcpu_stats_addr[i]) {
                    printf("ERROR: Remote read failed for addr 0x%lx\n", addr);
                    goto fail;
                }
                pcpu_stats_addr[i] = addr;
                pcpu_stats_p[i] = &pcpu_stats[max_cpu_idx];
                max_cpu_idx++;
                break;
            default:
                printf("ERROR: Unexpected type 0x%x of len %u\n", type, len);
                goto fail;
        }
        addr = addr + TLV_SIZE_ALIGN(len);
        type = octeon_remote_read_mem32(addr);
        addr += sizeof(uint32_t);
    }

    remote_cpu_freq = global_stats.core_clock;

    if ((coreid > -1) && !(global_stats.active_coremask & (1 << coreid))) {
        printf("Core %d not active\n", coreid);
        goto fail;
    }

    if ((vfid > -1) && !(is_vf_active(vfid))) {
        printf("VF %d not active\n", vfid);
        goto fail;
    }

    do {
        if (update_global_data())
            goto fail;

        if (update_pcpu_data())
            goto fail;

        /* Print global stats */
        print_global_stats();

        /* Print Per-CPU data periodically */
        print_pcpu_data();
        sleep(poll_sec);
        printf("\n\n");
    } while (poll_sec);

    octeon_remote_close();
    return 0;
fail:
    octeon_remote_close();
    return -1;
}
