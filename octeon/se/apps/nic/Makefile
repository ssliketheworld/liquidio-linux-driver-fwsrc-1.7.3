#
# PCI NIC Octeon simple exec application Makefile
#

# The driver files are kept in this location.
#DRIVER_ROOT = $(LIQUIDIO_ROOT)/modules/driver

# The application specific files are located here.
APP_ROOT = $(PWD)

# The application binary is copied here after compilation.
ifdef LIQUIDIO_ROOT
BINDIR = $(LIQUIDIO_ROOT)/bin
OCTEON_SE_SRC ?= $(LIQUIDIO_ROOT)/octeon/se
COMMON_INC ?= $(LIQUIDIO_ROOT)//host/driver/src/osi
IPSEC_INC ?= $(LIQUIDIO_ROOT)/octeon/se/apps/nic/ipsec/include
DCB_INC ?= $(LIQUIDIO_ROOT)/octeon/se/apps/dcb
COMMON_HOST_INC ?= $(LIQUIDIO_ROOT)/host/driver/src/linux/cavium/liquidio
COMMON_HOST_OSI_INC ?= $(LIQUIDIO_ROOT)/host/driver/src/osi
endif

BOOTLOADER_INC ?= $(OCTEON_ROOT)/bootloader/u-boot/arch/mips/include

LINKCMD = ln -sf

#  application specification
TARGET        =  cvmcs-nic-$(OCTEON_MODEL)

ifndef LIQUIDIO_ROOT
$(error LIQUIDIO_ROOT undefined. Please 'source liquidio-env-setup.sh' first)
endif

ifndef OCTEON_ROOT
$(error OCTEON_ROOT must be defined to build firmware. Please 'source env-setup <MODEL>' in OCTEON-SDK)
endif

all : links linkdcb
	@$(MAKE) --no-print-directory cvmcs_default

#  default target
default: $(TARGET) 
	@mkdir -p $(BINDIR)/octeon
	@cp $^ $(BINDIR)/octeon/$^.strip
	mipsisa64-octeon-elf-strip $(BINDIR)/octeon/$^.strip

links:
	@$(LINKCMD) ../../test/cvmcs-test-config.h config/cvmcs-base-test-config.h
	@$(LINKCMD) ../../../core/cvm-drv-resources.h config/cvm-drv-resources.h

#  standard common Makefile fragment
include $(OCTEON_ROOT)/common.mk

#  global debug setting for compile
#DEBUG_FLAGS = -DOCTEON_DEBUG_LEVEL=6 -g
#DEBUG_FLAGS = -DFLOW_ENGINE
DEBUG_FLAGS = -g

COMPILE += -DOCTEON_CORE_DRIVER  -O2 $(DEBUG_FLAGS)

#Storing OCTEON SDK Version
OCTSDKVER :="\"$(shell oct-version | sed -n "s/.* version \(.*\)/\1/p")\""

COMPILE += -DSDKVER=$(OCTSDKVER)

COMPILE += -Wall -Wno-unused-parameter -O2 -fno-strict-aliasing $(DEBUG_FLAGS) $(CORE_MASKS) $(CC_FLAGS) $(INCLUDE_DIRS) $(DRIVER_DEFINES)

COMPILE += $(OCTDRVFLAGS)

ifdef VIRTIO_RXZCP
COMPILE += -DCAVIUM_ONLY_VIRTIO_RX_ZEROCOPY_SUPPORT
endif

ifdef BPF_OFFLOAD
COMPILE += -DCAVIUM_ONLY_BPF_OFFLOAD_SUPPORT
endif

#  include required application common
dir := $(OCTEON_SE_SRC)/apps/common
include $(dir)/driver.mk
include $(dir)/cvmcs-common.mk

#  include required Core driver Makefile fragments
dir := $(OCTEON_SE_SRC)/core
include $(dir)/core-drv.mk

ifeq ($(LIO_VSWITCH_PKG),SRC)
#include component makefiles*/
dir := $(OCTEON_SE_SRC)/apps/nic
include $(dir)/cvmcs-comp.mk
endif

#  include required simple executive Makefile fragments
dir := $(OCTEON_ROOT)/executive
include $(dir)/cvmx.mk

#include required IPsec Makefile fragments
ifeq ($(LIO_IPSEC_PKG),SRC)
dir := $(LIQUIDIO_ROOT)/octeon/se/apps/nic/ipsec
include $(dir)/nic-ipsec.mk
else
dir := $(LIQUIDIO_ROOT)/octeon/se/apps/nic
include $(dir)/nic-ipsec-stub.mk
endif

#include required DCB Makefile fragments
ifeq ($(LIO_DCB_PKG),SRC)
dir := $(LIQUIDIO_ROOT)/octeon/se/apps/dcb
include $(dir)/nic-dcb.mk
linkdcb:

else
dir := $(LIQUIDIO_ROOT)/octeon/se/apps/nic
include $(dir)/nic-dcb-stub.mk
linkdcb:
	@$(LINKCMD) dcb.h cvmcs-dcb.h
endif

#include required NVMe Makefile fragments
ifdef NVME_ACTIVE
dir := $(LIQUIDIO_ROOT)/octeon/se/apps/nic/nvme
NVME_INC ?= $(LIQUIDIO_ROOT)/octeon/se/apps/nic/nvme/include
include $(dir)/nic-nvme.mk
else
dir := $(LIQUIDIO_ROOT)/octeon/se/apps/nic
include $(dir)/nic-nvme-stub.mk
endif

#Action for making cvmcs-nic
OBJS =  $(OBJ_DIR)/cvmcs-nic-main.o   \
		$(OBJ_DIR)/cvmcs-nic-init.o   \
		$(OBJ_DIR)/cvmcs-nic-printf.o   \
		$(OBJ_DIR)/cvmcs-nic-console.o   \
		$(OBJ_DIR)/cvmcs-nic.o	\
		$(OBJ_DIR)/cvmcs-intr.o	\
		$(OBJ_DIR)/cvmcs-nic-tso.o \
		$(OBJ_DIR)/cvmcs-nic-lro.o \
		$(OBJ_DIR)/cvmcs-nic-tunnel.o \
		$(OBJ_DIR)/cvmcs-nic-switch.o \
		$(OBJ_DIR)/cvmcs-nic-mdata.o \
		$(OBJ_DIR)/cvmcs-nic-fwdump.o \
		$(OBJ_DIR)/cvmcs-profile.o \
		$(OBJ_DIR)/cvmcs-nic-hybrid.o \
		$(OBJ_DIR)/cvmcs-nic-component.o \
		$(OBJ_DIR)/cvmcs-nic-rss.o \
		$(OBJ_DIR)/cvmcs-nic-fnv.o \
		$(OBJ_DIR)/cvmcs-nic-flash.o \
		$(OBJ_DIR)/cvmcs-uboot-seapi.o

ifdef BPF_OFFLOAD
		OBJS += $(OBJ_DIR)/cvmcs-nic-bpf.o
endif

# FIXME needs -O2?
CFLAGS_LOCAL = -I../../core/ -I$(OCTEON_SE_SRC)/apps/common -I$(DCB_INC)\
		-I$(COMMON_INC) -I$(COMMON_HOST_INC) -I$(IPSEC_INC) -I$(NVME_INC) -DIGNORE_DRIVER_TYPES -I$(COMMON_HOST_OSI_INC) -I$(BOOTLOADER_INC) -W -Wall -Werror -Wno-unused-parameter

ifdef BPF_OFFLOAD
CFLAGS_LOCAL += -Wno-override-init
endif

ifeq ($(LINUX_IPSEC),1)
#include component makefiles
dir := $(OCTEON_SE_SRC)/apps/nic
include $(dir)/cvmcs-comp.mk
endif

include $(OCTEON_ROOT)/application.mk

cvmcs_default: $(CVMX_CONFIG)
	@$(MAKE) default

#  clean target
clean:
	rm -f config/cvmcs-base-test-config.h config/cvm-drv-resources.h cvmcs-dcb.h
	rm -rf $(TARGET) $(CVMX_CONFIG) $(OBJ_DIR) *.o *.d *~ $(TARGET).strip $(BINDIR)/octeon/$(TARGET).strip;
	rm -rf $(OCTEON_SINGLE_DIR)


# $Id$
