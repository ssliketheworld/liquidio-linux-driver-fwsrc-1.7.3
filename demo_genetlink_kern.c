#include <linux/module.h>  
#include <linux/kernel.h>  
#include <linux/init.h>  
#include <net/genetlink.h> 

#include "demo_genetlink.h"

static struct genl_family gnl_family[4] = {
	{
		.id			= GENL_ID_GENERATE,
		.name		= "CAVIUM_GENL0",
		.version	= 1,
		.maxattr	= CAVIUM_CMD_ATTR_MAX,
	},
	{
		.id			= GENL_ID_GENERATE,
		.name		= "CAVIUM_GENL1",
		.version	= 1,
		.maxattr	= CAVIUM_CMD_ATTR_MAX,
	},
	{
		.id			= GENL_ID_GENERATE,
		.name		= "CAVIUM_GENL2",
		.version	= 1,
		.maxattr	= CAVIUM_CMD_ATTR_MAX,
	},
	{
		.id			= GENL_ID_GENERATE,
		.name		= "CAVIUM_GENL3",
		.version	= 1,
		.maxattr	= CAVIUM_CMD_ATTR_MAX,
	},
};

static const struct nla_policy demo_cmd_policy[CAVIUM_CMD_ATTR_MAX+1] = {
	[CAVIUM_CMD_ATTR_MESG]	= { .type = NLA_STRING },
};

static int cmd_attr_echo_message(struct genl_info *info)
{
	struct nlattr *na; 
	char *msg;  
	int ret;

	/* 读取用户下发的消息 */
	na = info->attrs[CAVIUM_CMD_ATTR_MESG];
	if (!na)
		return -EINVAL;

	msg = (char *)nla_data(na);
	pr_info("seq:%d, generic netlink receive echo msg: %s\n", info->snd_seq, msg);  

	return ret;	
}

int demo_echo_cmd(struct sk_buff *skb, struct genl_info *info)
{
	if (info->attrs[CAVIUM_CMD_ATTR_MESG])
		return cmd_attr_echo_message(info);
	else
		return -EINVAL;
}

static const struct genl_ops demo_ops[] = {
	{
		.cmd		= CAVIUM_CMD_ECHO,
		.doit		= demo_echo_cmd,
		.policy		= demo_cmd_policy,
		.flags		= GENL_ADMIN_PERM,
	},
};

static int __init demo_genetlink_init(void)
{
	int ret, i;

	for (i = 0; i < 4; i++) {
		ret = genl_register_family_with_ops(&gnl_family[i], demo_ops);
		if (ret != 0) {
			pr_info("failed to init generic netlink example module\n");
			return ret;
		}
	}

	pr_info("generic netlink module init success\n");

	return 0;
}

static void __exit demo_genetlink_exit(void)
{
	int ret, i;
	printk("generic netlink deinit.\n");

	for (i = 0; i < 4; i++) {
		ret = genl_unregister_family(&gnl_family[i]);
		if(ret != 0) {
			printk("faled to unregister family:%i\n", ret);
		}
	}
}

module_init(demo_genetlink_init);
module_exit(demo_genetlink_exit);
MODULE_LICENSE("GPL");
