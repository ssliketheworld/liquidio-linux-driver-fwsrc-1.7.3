#include <stdio.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>

#include <linux/nvme.h>
#include "nvme_stats_info.h"

#define NVME_ADMIN_CMD_STATS     0XCA

#define GET_STATS_NS             0
#define GET_STATS_IOQ            1
#define GET_STATS_ADMINQ         2
#define CLEAR_STATS_NS           3
#define CLEAR_STATS_IOQ          4
#define CLEAR_STATS_ADMINQ       5

int main(int argc, char *argv[])
{
	int qid, nsid = 1;
	int fd, ret, stats_clear = 0;
	struct nvme_admin_cmd get_stats;
	nvme_ns_stats_t *ns_stats_buf;
	nvme_io_q_stats_t *ioq_stats_buf;
	uint64_t total_rd_cmds = 0, total_wr_cmds = 0,
		total_rd_bytes = 0, total_wr_bytes = 0;

	if (argc > 1) {
		if (!strcmp(argv[1], "clear")) {
			printf("%s: stats clear\n", argv[0]);
			stats_clear = 1;
		}
		
	}

	fd = open("/dev/nvme0", O_RDWR);

	if (fd < 0) {
		printf("/dev/nvme0 open failed\n");
		return -1;
	}

	if (stats_clear) {
		// Clear stats:
		memset(&get_stats, 0, sizeof(struct nvme_admin_cmd));
		get_stats.opcode = NVME_ADMIN_CMD_STATS;
		get_stats.cdw10 = CLEAR_STATS_NS;
		get_stats.nsid = nsid;
		ret = ioctl(fd, NVME_IOCTL_ADMIN_CMD, &get_stats);
		if (ret) {
			printf("%s:%d: IOCTL error\n", __func__, __LINE__);
			free(ns_stats_buf);
			close(fd);
			return -1;
		}
	
		memset(&get_stats, 0, sizeof(struct nvme_admin_cmd));
		get_stats.opcode = NVME_ADMIN_CMD_STATS;
		get_stats.cdw10 = (0xff << 8) | CLEAR_STATS_IOQ;
		ret = ioctl(fd, NVME_IOCTL_ADMIN_CMD, &get_stats);
		if (ret) {
			printf("%s:%d: IOCTL error\n", __func__, __LINE__);
			free(ns_stats_buf);
			close(fd);
			return -1;
		}

		close(fd);

		return 0;
	}

	ns_stats_buf = malloc(sizeof(nvme_ns_stats_t));

	memset(&get_stats, 0, sizeof(struct nvme_admin_cmd));
	get_stats.opcode = NVME_ADMIN_CMD_STATS;
	get_stats.cdw10 = GET_STATS_NS;
	get_stats.nsid = nsid;
	get_stats.addr = (uint64_t)ns_stats_buf;
	get_stats.data_len = sizeof(nvme_ns_stats_t);

	ret = ioctl(fd, NVME_IOCTL_ADMIN_CMD, &get_stats);
	if (ret) {
		printf("%s:%d: IOCTL error\n", __func__, __LINE__);
		free(ns_stats_buf);
		close(fd);
		return -1;
	}

	printf("=================\n");
	printf("NS stats: NSID %d\n", nsid);
	printf("=================\n");
	printf("rd_cmds \t\t%lf K\n", (double)ns_stats_buf->rd_cmds/1024);
	printf("wr_cmds \t\t%lf K\n", (double)ns_stats_buf->wr_cmds/1024);
	printf("rd_bytes \t\t%lf MB\n", (double)ns_stats_buf->rd_bytes / (1024*1024));
	printf("wr_bytes \t\t%lf MB\n", (double)ns_stats_buf->wr_bytes / (1024*1024));
	printf("rd_time \t\t%lu\n", ns_stats_buf->rd_time);
	printf("wr_time \t\t%lu\n", ns_stats_buf->wr_time);
	printf("errors \t\t\t%lu\n", ns_stats_buf->errors);
	printf("last_error_ts \t\t%lu\n", ns_stats_buf->last_error_ts);

	free(ns_stats_buf);

	ioq_stats_buf = malloc(sizeof(nvme_io_q_stats_t));

	printf("\n===========\n");
	printf("IOQ stats :\n", qid);
	printf("===========");
	for (qid = 1; qid <= 8; qid++) {
		memset(&get_stats, 0, sizeof(struct nvme_admin_cmd));
		get_stats.opcode = NVME_ADMIN_CMD_STATS;
		get_stats.cdw10 = (qid << 8) | GET_STATS_IOQ;
		get_stats.addr = (uint64_t)ioq_stats_buf;
		get_stats.data_len = sizeof(nvme_io_q_stats_t);

		ret = ioctl(fd, NVME_IOCTL_ADMIN_CMD, &get_stats);
		if (ret) {
			printf("%s:%d: IOCTL error\n", __func__, __LINE__);
			free(ioq_stats_buf);
			close(fd);
			return -1;
		}

#if 0
		printf("\nIOQ %d:\n", qid);
		printf("=======\n");
		printf("rd_cmds \t\t%lf K\n", (double)ioq_stats_buf->rd_cmds/1024);
		printf("wr_cmds \t\t%lf K\n", (double)ioq_stats_buf->wr_cmds/1024);
		printf("rd_bytes \t\t%lf MB\n", (double)ioq_stats_buf->rd_bytes / (1024*1024));
		printf("wr_bytes \t\t%lf MB\n", (double)ioq_stats_buf->wr_bytes / (1024*1024));
		printf("rd_time \t\t%lu\n", ioq_stats_buf->rd_time);
		printf("wr_time \t\t%lu\n", ioq_stats_buf->wr_time);
		printf("completions \t\t%lu\n", ioq_stats_buf->completions);
		printf("last_sub_ts \t\t%lu\n", ioq_stats_buf->last_sub_ts);
		printf("last_compl_ts \t\t%lu\n", ioq_stats_buf->last_compl_ts);
		printf("aborted \t\t%lu\n", ioq_stats_buf->aborted);
		printf("errors \t\t\t%lu\n", ioq_stats_buf->errors);
		printf("last_error_ts \t\t%lu\n", ioq_stats_buf->last_error_ts);
#endif

		total_rd_cmds  += ioq_stats_buf->rd_cmds;
		total_wr_cmds  += ioq_stats_buf->wr_cmds;
		total_rd_bytes += ioq_stats_buf->rd_bytes;
		total_wr_bytes += ioq_stats_buf->wr_bytes;
	}

	printf("Cumulative IOQ stats:\n");
	printf("=====================\n");
	printf("Read cmds \t\t%lf K\n", (double)total_rd_cmds / 1024);
	printf("write cmds \t\t%lf K\n", (double)total_wr_cmds / 1024);
	printf("Read bytes \t\t%lf MB\n", (double)total_rd_bytes / (1024*1024));
	printf("Write bytes \t\t%lf MB\n", (double)total_wr_bytes / (1024*1024));


	memset(&get_stats, 0, sizeof(struct nvme_admin_cmd));
	get_stats.opcode = NVME_ADMIN_CMD_STATS;
	get_stats.cdw10 = (0xff << 8) | GET_STATS_IOQ;
	get_stats.addr = (uint64_t)ioq_stats_buf;
	get_stats.data_len = sizeof(nvme_io_q_stats_t);

	ret = ioctl(fd, NVME_IOCTL_ADMIN_CMD, &get_stats);
	if (ret) {
		printf("%s:%d: IOCTL error\n", __func__, __LINE__);
		free(ioq_stats_buf);
		close(fd);
		return -1;
	}

	printf("IOQ stats for all queues:\n");
	printf("=========================\n");
	printf("rd_cmds \t\t%lf K\n", (double)ioq_stats_buf->rd_cmds/1024);
	printf("wr_cmds \t\t%lf K\n", (double)ioq_stats_buf->wr_cmds/1024);
	printf("rd_bytes \t\t%lf MB\n", (double)ioq_stats_buf->rd_bytes / (1024*1024));
	printf("wr_bytes \t\t%lf MB\n", (double)ioq_stats_buf->wr_bytes / (1024*1024));
	printf("rd_time \t\t%lu\n", ioq_stats_buf->rd_time);
	printf("wr_time \t\t%lu\n", ioq_stats_buf->wr_time);
	printf("completions \t\t%lu\n", ioq_stats_buf->completions);
	printf("last_sub_ts \t\t%lu\n", ioq_stats_buf->last_sub_ts);
	printf("last_compl_ts \t\t%lu\n", ioq_stats_buf->last_compl_ts);
	printf("aborted \t\t%lu\n", ioq_stats_buf->aborted);
	printf("errors \t\t\t%lu\n", ioq_stats_buf->errors);
	printf("last_error_ts \t\t%lu\n", ioq_stats_buf->last_error_ts);

	free(ioq_stats_buf);

	close(fd);
}
