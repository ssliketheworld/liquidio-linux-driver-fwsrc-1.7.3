
#
# This file provides system-wide defaults to compile the driver sources.
#
# IMPORTANT: Do not leave spaces at the end of directory paths.
#



# Enable this flag if the driver and applications will run on an Octeon
# in PCI Host mode.
#HOST_IS_OCTEON=1

ifeq ($(HOST_IS_OCTEON), 1)
DEFAULT_CROSS_COMPILE = $(shell \
        if grep -q ^CONFIG_CPU_LITTLE_ENDIAN $(OCTEON_ROOT)/linux/kernel/linux/.config && \
        which mips64el-octeon-linux-gnu-gcc > /dev/null 2>&1 ; then \
                echo -n mips64el-octeon-linux-gnu-; \
        else \
                echo -n mips64-octeon-linux-gnu-; fi)


CROSS_COMPILE ?= $(strip $(DEFAULT_CROSS_COMPILE))

export CROSS_COMPILE
ARCH = mips
export ARCH



# The compiler needs to be changed only for the host sources.
# No changes are made if the core application includes this file.
ifneq ($(findstring OCTEON_CORE_DRIVER,$(COMPILE)), OCTEON_CORE_DRIVER)
kernel_source := $(OCTEON_ROOT)/linux/kernel/linux
CC=mips64-octeon-linux-gnu-gcc
AR=mips64-octeon-linux-gnu-ar
endif
else
kernel_source := /lib/modules/$(shell uname -r)/build
ENABLE_CURSES=1
endif



# The driver sources are assumed to be in this directory.
# Modify it if you installed the sources in a different directory.
#DRIVER_ROOT := $(OCTEON_ROOT)/components/driver

BINDIR := $(LIQUIDIO_ROOT)/bin


# This feature is intended for PCI-NIC package.
# Enable this for having the feature 
# Flow based distribution of packets to multiple output queues.

#Enable the DMA Interrupt Coalescing
#OCTDRVFLAGS += -DCVMCS_DMA_IC

#Enable DDOQ Threads
#OCTDRVFLAGS  += -DUSE_DDOQ_THREADS

#Enable this flag to turn on peer to peer communication for CN56XX
#OCTDRVFLAGS  += -DCN56XX_PEER_TO_PEER

#Enable to turn on backpressure
#OCTDRVFLAGS  += -DBP

#Enable to turn on rate limiting
#OCTDRVFLAGS  += -DRLIMIT

#Enable to turn on interrupt moderation
#OCTDRVFLAGS  += -DINTRMOD

# $Id$ 
