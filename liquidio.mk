#
# Common defines and targets for LiquidIO targets
#

-include .config.mk

.NOTPARALLEL: 

.PHONY: host_drv host_drivers host_links host_install host_vf_install \
	host_uninstall nic_app nic_app_clean host_utilities host_clean \
	host_utilities_clean

DRIVER_ROOT = $(CURDIR)
DRIVER_BIN = $(DRIVER_ROOT)/bin
OCTEON_BIN = $(DRIVER_ROOT)/bin/octeon
USR_BIN = /usr/local/bin
DEPMOD = $(shell which depmod || which /sbin/depmod || echo "echo You should now run depmod")
RM = rm -f
FIRMWARE_PATH = /lib/firmware/liquidio
OS_VERSION = $(shell uname -r)
MODULES_PATH = /lib/modules/$(OS_VERSION)/kernel/drivers/net/ethernet/cavium/liquidio
UPSTREAM_FILE = liquidio_upstream_src.tar
export LINUX_SRC = $(LIQUIDIO_ROOT)/host/driver/src/linux
export LINUX_HOST_DRIVER_SRC = $(LINUX_SRC)/cavium/liquidio
export OSI_HOST_DRIVER_SRC = $(LIQUIDIO_ROOT)/host/driver/src/osi
export LINUX_HOST_DRIVER_SRC_UPSTREAM = $(LIQUIDIO_ROOT)/host/driver/src/linux_upstream/
export OCTEON_SE_SRC = $(LIQUIDIO_ROOT)/octeon/se
export NIC_SRC = $(OCTEON_SE_SRC)/apps/nic
export HOST_UTIL_SRC = $(LIQUIDIO_ROOT)/host/apps/util
export MKNICIMAGE = $(HOST_UTIL_SRC)/mknicimage/mknicimage
LINKCMD = ln -sf
MODNAME = liquidio

ifndef_any_of = $(filter undefined,$(foreach v,$(1),$(origin $(v))))
ifneq ($(call ifndef_any_of,LIQUIDIO_ROOT NIC_PKG),)
  $(error Environment not defined. Please run './configure' first)
endif

host_drv: host_drivers host_links

$(DRIVER_BIN):
	mkdir $(DRIVER_BIN)

host_drivers:
	@cd $(LINUX_HOST_DRIVER_SRC); $(MAKE) all

host_links: $(DRIVER_BIN)/$(MODNAME).ko $(DRIVER_BIN)/$(MODNAME)_vf.ko

$(DRIVER_BIN)/$(MODNAME).ko: $(DRIVER_BIN)
	@cd $(DRIVER_BIN); $(LINKCMD) $(LINUX_HOST_DRIVER_SRC)/$(MODNAME).ko .;  cd ..

$(LINUX_HOST_DRIVER_SRC)/$(MODNAME)_vf.ko:
	cd $(LINUX_HOST_DRIVER_SRC) && $(MAKE) $(MODNAME)_vf.ko

$(DRIVER_BIN)/$(MODNAME)_vf.ko: $(DRIVER_BIN) $(LINUX_HOST_DRIVER_SRC)/$(MODNAME)_vf.ko
	@cd $(DRIVER_BIN); $(LINKCMD) $(LINUX_HOST_DRIVER_SRC)/$(MODNAME)_vf.ko .; cd ..

host_install:
	mkdir -p $(FIRMWARE_PATH)
	mkdir -p $(MODULES_PATH)
	cp $(OCTEON_BIN)/lio_*.bin $(FIRMWARE_PATH)
	cp $(DRIVER_BIN)/$(MODNAME).ko $(MODULES_PATH)
	cp $(HOST_UTIL_SRC)/cavm_*.sh $(USR_BIN)
	$(DEPMOD) -a

host_vf_install: $(DRIVER_BIN)/$(MODNAME)_vf.ko
	mkdir -p $(MODULES_PATH)
	cp $(DRIVER_BIN)/$(MODNAME)_vf.ko $(MODULES_PATH)
	cp $(HOST_UTIL_SRC)/cavm_*.sh $(USR_BIN)
	$(DEPMOD) -a

host_uninstall: 
	$(RM) $(FIRMWARE_PATH)/lio_*.bin
	$(RM) $(MODULES_PATH)/liquidio*.ko*
	$(RM) $(USR_BIN)/cavm_*.sh
	$(RM) /etc/modprobe.d/lio_*.conf
	$(RM) /etc/modprobe.d/liquidio_*.conf
	$(DEPMOD) -a

ifeq ($(NIC_PKG),SRC) 

ifndef OCTEON_ROOT
$(error OCTEON_ROOT must be defined to build firmware. Please run './configure')
endif

export PATH:=$(OCTEON_ROOT)/tools/bin:$(OCTEON_ROOT)/tools-le/bin:$(OCTEON_ROOT)/host/bin:$(PATH)

$(shell cd $(OCTEON_ROOT);source $(OCTEON_ROOT)/env-setup OCTEON_CN23XX_PASS1_2;cd $(LIQUIDIO_ROOT))

ifndef OCTEON_CPPFLAGS_GLOBAL_ADD
$(error OCTEON_CPPFLAGS_GLOBAL_ADD must be defined to build firmware. Please run './configure')
endif

# common target for building SE NIC apps
nic_app:
	@echo "*** Making $(OCTEON_MODEL) firmware ***"
	$(eval OCTEON_CPPFLAGS_GLOBAL_ADD := $(subst -DUSE_RUNTIME_MODEL_CHECKS=1,,$(OCTEON_CPPFLAGS_GLOBAL_ADD)))
	@cd $(NIC_SRC); $(MAKE) OCTEON_SINGLE_DIR=$(NIC_SRC)/$(OCTEON_MODEL) NVME_ACTIVE=1

host_utilities: 
	@cd $(HOST_UTIL_SRC); $(MAKE) all 

nic_app_clean: 
	@cd $(NIC_SRC); $(MAKE) clean OCTEON_SINGLE_DIR=$(NIC_SRC)/$(OCTEON_MODEL)

host_utilities_clean: 
	@cd $(HOST_UTIL_SRC); $(MAKE) clean

endif

host_clean: host_utilities_clean 
	@cd $(LINUX_HOST_DRIVER_SRC); $(MAKE) clean
