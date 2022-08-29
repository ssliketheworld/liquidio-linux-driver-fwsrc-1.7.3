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
INCLUDES=-I$(NIC_SRC) -I$(NIC_SRC)/nvme/include/ -I$(OCTEON_ROOT)/executive -I$(REMOTE_LIBDIR) -I$(NIC_SRC)/config/

BINS = \
	$(DIR)/oct-nvmestats $(DRIVER_BIN)/oct-nvmestats

.PHONY: all nvme check_octroot check_lio

all: nvme 


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

nvme: check_lio check_octroot $(BINS)

$(DIR)/oct-nvmestats: $(LIBS) oct-nvmestats.c $(OCTEON_ROOT)/executive/cvmx-clock.c 
	@echo "###########################"$(INCLUDES)
	$(CC) $(CFLAGS) $(INCLUDES) -g -o $@ $^ $(LIBS) $(LIBS_FLAGS) -DUSE_RUNTIME_MODEL_CHECKS=1 -DCVMX_BUILD_FOR_LINUX_HOST=1 -lrt

$(DRIVER_BIN)/oct-nvmestats: $(DIR)/oct-nvmestats
	@cd $(DRIVER_BIN) > /dev/null; $(LINKCMD) $(HOST_UTIL_SRC)/nvmeinfo/oct-nvmestats .; cd $(CURDIR) > /dev/null


.PHONY: clean
clean:
	rm -f $(BINS)
