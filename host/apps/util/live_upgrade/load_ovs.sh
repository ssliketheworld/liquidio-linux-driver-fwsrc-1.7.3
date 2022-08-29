#!/bin/bash

# put this file in /etc/liquidio/

CUR_DIR=`pwd`
HOST_BIN_DIR=$CUR_DIR/host/bin
FW_BIN_DIR=$CUR_DIR/bin/octeon

if mkdir /var/lock/liquidio_lock; then
    # Able to acquire mutex
    :
else
    # Could not acquire mutex
    exit 1
fi

FW_FP=$FW_BIN_DIR/cvmcs-nic-OCTEON_CN23XX_PASS1_2.strip
if [ ! -e "$FW_FP" ]; then
	echo $FW_FP NOT exist
	rmdir /var/lock/liquidio_lock
        exit 1
fi

FW_SP=$FW_BIN_DIR/vmlinux.64
if [ ! -e "$FW_SP" ]; then
	echo $FW_SP NOT exist
	rmdir /var/lock/liquidio_lock
        exit 1
fi


$HOST_BIN_DIR/oct-pci-reset
# Load SP first
$HOST_BIN_DIR/oct-pci-load 0x21000000 $FW_SP
## $HOST_BIN_DIR/oct-pci-bootcmd 'bootoctlinux 0x21000000 coremask=0x7 mem=1392M console=pci1'
$HOST_BIN_DIR/oct-pci-bootcmd 'bootoctlinux 0x21000000 coremask=0x7 mem=1392M'
# Load FP
## $HOST_BIN_DIR/oct-pci-app-ctl boot -mask=0xff8 -console=pci $FW_FP
$HOST_BIN_DIR/oct-pci-app-ctl boot -mask=0xff8 $FW_FP

# Set firmware load bit in scratch2 register
scratch2=`$HOST_BIN_DIR/oct-pci-csr SLI_SCRATCH_2 | grep DATA | awk '{ print $5 }'`
let "scratch2 = (1 << 63) | $scratch2"
scratch2=`printf "0x%x" $scratch2`
$HOST_BIN_DIR/oct-pci-csr SLI_SCRATCH_2 $scratch2

modprobe -i liquidio fw_type=ovs console_bitmask=1 $*

rmdir /var/lock/liquidio_lock

exit 0
