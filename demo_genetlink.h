#ifndef _DEMO_GENETLINK_KERN_H
#define _DEMO_GENETLINK_KERN_H

#define	CAVIUM_GENL_NAME		"CAVIUM_GENL"
// #define	CAVIUM_GENL_VERSION		0x1

/*
 * Commands sent from userspace
 * Not versioned. New commands should only be inserted at the enum's end
 * prior to __DEMO_CMD_MAX
 */

enum {
	CAVIUM_CMD_UNSPEC = 0,	/* Reserved */
	CAVIUM_CMD_ECHO,			/* user->kernel request/get-response */
	__CAVIUM_CMD_MAX,
};
#define CAVIUM_CMD_MAX (__CAVIUM_CMD_MAX - 1)

enum {
	CAVIUM_CMD_ATTR_UNSPEC = 0,
	CAVIUM_CMD_ATTR_MESG,		/* demo message  */
	__CAVIUM_CMD_ATTR_MAX,
};
#define CAVIUM_CMD_ATTR_MAX (__CAVIUM_CMD_ATTR_MAX - 1)

#endif /* _DEMO_GENETLINK_KERN_H */
