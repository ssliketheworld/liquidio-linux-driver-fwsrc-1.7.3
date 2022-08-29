DRIVER_BIN ?= $(LIQUIDIO_ROOT)/bin
HOST_UTIL_SRC = $(LIQUIDIO_ROOT)/host/apps/util
LINKCMD = ln -sf

DIR = $(PWD)

REMOTE_LIBDIR := $(OCTEON_ROOT)/host/remote-lib/
LIBS := $(REMOTE_LIBDIR)/libocteon-remote.a
LIBS_CXX := ${LIBS}

CROSS=
CC=$(CROSS)gcc
CXX=$(CROSS)g++
STRIP=$(CROSS)strip
INCLUDES=-I$(NIC_SRC) -I$(OCTEON_ROOT)/executive -I$(REMOTE_LIBDIR)

BINS = \
	$(DIR)/oct-fwdump $(DRIVER_BIN)/oct-fwdump $(DIR)/oct-fwdump-flash $(DRIVER_BIN)/oct-fwdump-flash

.PHONY: all fwdump check_octroot check_lio

all: fwdump

check_lio:
ifndef LIQUIDIO_ROOT
	@echo "####################################################"
	@echo "              LIQUIDIO_ROOT not defined"     
	@echo " Run the liquidio-env-setup.sh script in the installation directory"
	@echo "####################################################"
	@exit 2
endif

check_octroot:
ifndef OCTEON_ROOT
	@echo "####################################################"
	@echo "              OCTEON_ROOT not defined"     
	@echo " Run the env-setup.sh script in the OCTEON SDK root directory"
	@echo "####################################################"
	@exit 2
endif

$(LIBS): 
	cd $(OCTEON_ROOT)/host/remote-lib; make

fwdump: check_lio check_octroot $(BINS)

$(DIR)/oct-fwdump: $(LIBS) oct-fwdump.c 
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ $^ $(LIBS) $(LIBS_FLAGS)

$(DRIVER_BIN)/oct-fwdump: $(DIR)/oct-fwdump
	@cd $(DRIVER_BIN) > /dev/null; cp $(HOST_UTIL_SRC)/fwdump/oct-fwdump .; cd $(CURDIR) > /dev/null
	
$(DIR)/oct-fwdump-flash: $(LIBS) oct-fwdump-flash.c
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ $^ $(LIBS) $(LIBS_FLAGS)

$(DRIVER_BIN)/oct-fwdump-flash: $(DIR)/oct-fwdump-flash
	@cd $(DRIVER_BIN) > /dev/null; cp $(HOST_UTIL_SRC)/fwdump/oct-fwdump-flash .; cd $(CURDIR) > /dev/null

.PHONY: clean
clean:
	rm -f $(BINS)
