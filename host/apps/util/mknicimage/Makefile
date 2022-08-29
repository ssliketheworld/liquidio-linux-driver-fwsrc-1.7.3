DRIVER_BIN ?= $(LIQUIDIO_ROOT)/bin
LINUX_HOST_DRIVER_SRC ?= $(LIQUIDIO_ROOT)/host/driver/src/linux/cavium
OSI_HOST_DRIVER_SRC ?= $(LIQUIDIO_ROOT)/host/driver/src/osi
HOST_UTIL_SRC = $(LIQUIDIO_ROOT)/host/apps/util
LINKCMD = ln -sf
TARGETS = mknicimage $(DRIVER_BIN)/mknicimage

.PHONY: all mknic check_lio 

all: mknic

check_lio:
ifndef LIQUIDIO_ROOT
	@echo "####################################################"
	@echo "              LIQUIDIO_ROOT not defined"     
	@echo " Run the liquidio-env-setup.sh script in the installation directory"
	@echo "####################################################"
	@exit 2
endif

mknic : check_lio $(TARGETS)

#
# Compilation flags
#
CFLAGS = -Wall -Werror -I$(LINUX_HOST_DRIVER_SRC) -I$(OSI_HOST_DRIVER_SRC) $(BUILD_SPECIFIC_CFLAGS) -O2 

ifeq ($(VSWITCH),1)
CFLAGS += -DVSWITCH -DCAVIUM_ONLY_CONFIG_LIQUIDIO_VSWITCH
endif

ifeq ($(LINUX_IPSEC),1)
CFLAGS += -DLINUX_IPSEC
endif

ifeq ($(OVS_IPSEC),1)
CFLAGS += -DOVS_IPSEC -DVSWITCH
endif

mknicimage: mknicimage.c crc32.c $(OSI_HOST_DRIVER_SRC)/liquidio_image.h $(OSI_HOST_DRIVER_SRC)/liquidio_common.h
	$(CC) $(CFLAGS) -g mknicimage.c crc32.c -o $@ $(LDFLAGS)

$(DRIVER_BIN)/mknicimage: mknicimage
	@cd $(DRIVER_BIN) > /dev/null; cp $(HOST_UTIL_SRC)/mknicimage/mknicimage .; cd $(CURDIR) > /dev/null

clean:
	rm -f *.o $(TARGETS)
	cd $(DRIVER_BIN); rm -f $(TARGETS)
	
# $Id$
