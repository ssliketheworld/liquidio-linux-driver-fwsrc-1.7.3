#include <stdio.h>  
#include <stdlib.h>  
#include <errno.h>  
#include <unistd.h>  
// #include <poll.h>  
#include <string.h>  
// #include <fcntl.h>  
// #include <sys/stat.h>  
#include <sys/socket.h>  
// #include <sys/types.h>  
#include <signal.h>  
#include <linux/genetlink.h>  

#include "demo_genetlink.h"

/*
 * Generic macros for dealing with netlink sockets. Might be duplicated
 * elsewhere. It is recommended that commercial grade applications use
 * libnl or libnetlink and use the interfaces provided by the library
 */
#define GENLMSG_DATA(glh)	((void *)(NLMSG_DATA(glh) + GENL_HDRLEN))
// #define GENLMSG_PAYLOAD(glh)	(NLMSG_PAYLOAD(glh, 0) - GENL_HDRLEN)
#define NLA_DATA(na)		((void *)((char*)(na) + NLA_HDRLEN))
// #define NLA_PAYLOAD(len)	(len - NLA_HDRLEN)

#define MAX_MSG_SIZE	1024
#define DEBUG			1

#define PRINTF(fmt, arg...) {			\
	    if (DEBUG) {				\
		printf(fmt, ##arg);		\
	    }					\
	}

struct msgtemplate {
	struct nlmsghdr n;
	struct genlmsghdr g;
	char buf[MAX_MSG_SIZE];
};

/*
 * Create a raw netlink socket and bind
 */
static int demo_create_nl_socket(int protocol, int index)
{
	int fd;
	struct sockaddr_nl local;

	/* 创建socket */
	fd = socket(AF_NETLINK, SOCK_RAW, protocol);
	if (fd < 0)
		return -1;

	memset(&local, 0, sizeof(local));
	local.nl_family = AF_NETLINK;
	local.nl_pid = index;

	/* 使用本进程的pid进行绑定 */
	if (bind(fd, (struct sockaddr *) &local, sizeof(local)) < 0)
		goto error;

	return fd;
	
error:
	close(fd);
	return -1;
}

static int demo_send_cmd(int sd, __u16 nlmsg_type,
						__u32 nlmsg_pid,
						__u8 genl_cmd, __u16 nla_type,
						void *nla_data, int nla_len)
{
	struct nlattr *na;
	struct sockaddr_nl nladdr;
	int r, buflen;
	char *buf;

	struct msgtemplate msg;
	// printf("%s, %d\n", __func__, nlmsg_pid);

	/* 填充msg (本函数发送的msg只填充一个attr) */
	msg.n.nlmsg_len = NLMSG_LENGTH(GENL_HDRLEN);
	msg.n.nlmsg_type = nlmsg_type;
	msg.n.nlmsg_flags = NLM_F_REQUEST;
	msg.n.nlmsg_seq = nlmsg_pid*2;
	// msg.n.nlmsg_pid = nlmsg_pid + getpid();
	msg.n.nlmsg_pid = getpid();
	msg.g.cmd = genl_cmd;
	msg.g.version = 1;
	na = (struct nlattr *) GENLMSG_DATA(&msg);
	na->nla_type = nla_type;
	na->nla_len = nla_len + 1 + NLA_HDRLEN;
	memcpy(NLA_DATA(na), nla_data, nla_len);
	msg.n.nlmsg_len += NLMSG_ALIGN(na->nla_len);

	buf = (char *)&msg;
	buflen = msg.n.nlmsg_len;
	memset(&nladdr, 0, sizeof(nladdr));
	nladdr.nl_family = AF_NETLINK;

	/* 循环发送直到发送完成 */
	while ((r = sendto(sd, buf, buflen, 0, (struct sockaddr *)&nladdr, sizeof(nladdr))) < buflen) {
		if (r > 0) {
			buf += r;
			buflen -= r;
		} else if (errno != EAGAIN)
			return -1;
	}

	return 0;
}

/*
 * Probe the controller in genetlink to find the family id
 * for the DEMO_GEN_CTRL family
 */
static int demo_get_family_id(int sd, int index)
{
	struct msgtemplate ans;
	
	char name[100];
	int id = 0, ret;
	struct nlattr *na;
	int rep_len;

	/* 根据gen family name查询family id */
	sprintf(name, "%s%d", CAVIUM_GENL_NAME, index);
	printf("name: %s\n", name);
	ret = demo_send_cmd(sd, GENL_ID_CTRL, index, CTRL_CMD_GETFAMILY, CTRL_ATTR_FAMILY_NAME, (void *)name, strlen(name) + 1);
	if (ret < 0)
		return 0;

	/* 接收内核消息 */
	rep_len = recv(sd, &ans, sizeof(ans), 0);
	if (ans.n.nlmsg_type == NLMSG_ERROR || (rep_len < 0) || !NLMSG_OK((&ans.n), rep_len))
		return 0;

	/* 解析family id */
	na = (struct nlattr *) GENLMSG_DATA(&ans);
	na = (struct nlattr *) ((char *) na + NLA_ALIGN(na->nla_len));
	if (na->nla_type == CTRL_ATTR_FAMILY_ID) {
		id = *(__u16 *) NLA_DATA(na);
	}

	return id;
}

static int gnl_fd[4] = {-1, -1, -1, -1};
static int gnl_family[4] = {-1, -1, -1, -1};

int main(int argc, char* argv[]) 
{
	// int nl_fd;
	int nl_family_id;
	int index;
	int ret;

	char *stringm = "pegion one ";
	// printf("%d\n", getpid());
	char string[32];

	while(1) {
		for (index = 0; index < 4; index++) {
			/* 初始化socket */
			if (gnl_fd[index] == -1) {
				gnl_fd[index] = demo_create_nl_socket(NETLINK_GENERIC, index);
				if (gnl_fd[index] < 0) {
					fprintf(stderr, "failed to create netlink socket\n");
					return 0;		
				}
			}
			printf("nl_fd: %d, %d\n", index, gnl_fd[index]);

			/* 获取family id */
			if (gnl_family[index] == -1) {
				gnl_family[index] = demo_get_family_id(gnl_fd[index], index);
				if (!gnl_family[index]) {
					fprintf(stderr, "Error getting family id, errno %d\n", errno);
					// goto out;
				}
				printf("=======\n");
			}
			// PRINTF("index: %d, family id %d\n", index, gnl_family[index]);

			sprintf(string, "%s%d", stringm, index);
			/* 发送字符串消息 */
			ret = demo_send_cmd(gnl_fd[index], gnl_family[index], index, CAVIUM_CMD_ECHO, CAVIUM_CMD_ATTR_MESG, string, strlen(string) + 1);
			if (ret < 0) {
				fprintf(stderr, "failed to send echo cmd\n");
				// goto out;
			}
			// close(nl_fd);
			sleep(1);
		}
	}

	return 0;
}
