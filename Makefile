obj-m:=demo_genetlink_kern.o
mymodule-objs:=module
KERNEL_DIR:=/lib/modules/3.10.0-514.el7.x86_64/build/
MAKE:=make

default:
	$(MAKE) -C $(KERNEL_DIR) SUBDIRS=$(PWD) modules

clean:
	$(MAKE) -C $(KERNEL_DIR) SUBDIRS=$(PWD) clean
