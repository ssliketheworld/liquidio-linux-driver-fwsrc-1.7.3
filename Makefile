obj-m:=demo_genetlink_kern.o
mymodule-objs:=module
KERNEL_DIR:=/lib/modules/$(shell uname -r)/build/
MAKE:=make

default:
	$(MAKE) -C $(KERNEL_DIR) SUBDIRS=$(PWD) modules

clean:
	$(MAKE) -C $(KERNEL_DIR) SUBDIRS=$(PWD) clean
