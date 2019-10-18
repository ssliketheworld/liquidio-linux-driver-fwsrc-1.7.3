# gen_nl_demo

1、make后得到demo_genetlink_kern.ko，加载进内核

2、gcc demo_genetlink_user.c -o demo_genetlink_user

3、用一个终端打印dmesg查看内核日志，dmesg -w

4、执行demo_genetlink_user即可通过generic netlink和内核空间进行通信
