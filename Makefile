#
# Top-level Makefile for LiquidIO core PF and VF driver and firmware packages
##

THISMAKE := $(MAKE) -f $(lastword $(MAKEFILE_LIST))


VERSION_FILE = $(DRIVER_ROOT)/octeon/se/apps/nic/generated/cvmcs-nic-version.h
timestamp=` date +"%Y-%m-%d %H:%M:%S" `

.NOTPARALLEL: 

.PHONY: all clean nic tools firmware_images

all: host nic tools

include liquidio.mk

host: host_drv

install: all host_install

vf_install: host_vf_install

uninstall: host_uninstall

ifeq ($(LIO_RXZCP_PKG),SRC) 
include rxzcp.mk
endif

ifeq ($(NIC_PKG),SRC) 

tools: $(VERSION_FILE)

.PHONY: $(VERSION_FILE)
$(VERSION_FILE):
		if [ -e $(dir $(VERSION_FILE)) ]; then rm -fr $(VERSION_FILE); \
		else mkdir -p $(dir $(VERSION_FILE)); \
		fi
		echo "#define BUILD_TIME \"$(timestamp)\"" >> $(VERSION_FILE)
		( echo "#define BUILD_VERSION \"$(shell $(DRIVER_ROOT)/setlocalversion $(DRIVER_ROOT))\"" >> $(VERSION_FILE)); 

firmware_images: $(VERSION_FILE)
	$(MKNICIMAGE) -v --bootcmd "bootoct 0x21000000 coremask=0xff" -i $(OCTEON_BIN)/cvmcs-nic-OCTEON_CN66XX.strip -l 0x21000000 $(OCTEON_BIN)/lio_210sv_nic.bin
	$(MKNICIMAGE) -v --bootcmd "bootoct 0x21000000 coremask=0xffffff" -i $(OCTEON_BIN)/cvmcs-nic-OCTEON_CN68XX.strip -l 0x21000000 $(OCTEON_BIN)/lio_210nv_nic.bin
	$(MKNICIMAGE) -v --bootcmd "bootoct 0x21000000 coremask=0xffffffff" -i $(OCTEON_BIN)/cvmcs-nic-OCTEON_CN68XX.strip -l 0x21000000 $(OCTEON_BIN)/lio_410nv_nic.bin
	$(MKNICIMAGE) -v --bootcmd 'bootoct 0x21000000 numcores=$$(numcores)' -i $(OCTEON_BIN)/cvmcs-nic-OCTEON_CN23XX_PASS1_2.strip -l 0x21000000 $(OCTEON_BIN)/lio_23xx_nic.bin
	$(MKNICIMAGE) -v --bootcmd "bootoct 0x21000000 coremask=0xffff" -i $(OCTEON_BIN)/cvmcs-nic-OCTEON_CN23XX_PASS1_2.strip -l 0x21000000 $(OCTEON_BIN)/lio_78xx_nic.bin

nic: $(VERSION_FILE)
	@mkdir -p $(OCTEON_BIN)
	@$(MAKE) host_utilities
	@$(MAKE) nic_app OCTEON_MODEL=OCTEON_CN66XX
	@$(MAKE) nic_app OCTEON_MODEL=OCTEON_CN23XX_PASS1_2
	@$(MAKE) nic_app OCTEON_MODEL=OCTEON_CN68XX
#	@$(MAKE) nic_app OCTEON_MODEL=OCTEON_CN78XX # identical to 23XX
	@$(MAKE) firmware_images
endif

clean:
	@$(MAKE) host_clean
	rm -f $(DRIVER_BIN)/*.ko
ifeq ($(NIC_PKG),SRC) 
	rm -rf $(OCTEON_BIN)
	@$(MAKE) nic_app_clean OCTEON_MODEL=OCTEON_CN66XX
	@$(MAKE) nic_app_clean OCTEON_MODEL=OCTEON_CN68XX
	@$(MAKE) nic_app_clean OCTEON_MODEL=OCTEON_CN23XX_PASS1_2
	@$(MAKE) nic_app_clean OCTEON_MODEL=OCTEON_CN78XX
endif
