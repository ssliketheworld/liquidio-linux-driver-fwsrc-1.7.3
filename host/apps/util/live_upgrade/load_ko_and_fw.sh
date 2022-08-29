#!/bin/bash

# put this file in /etc/liquidio/

if mkdir /var/lock/liquidio_lock; then
    # Able to acquire mutex
    :
else
    # Could not acquire mutex
    exit 1
fi

FIRMWARE=/etc/liquidio/cvmcs-nic-OCTEON_CN23XX_PASS1_2.strip

NIC_COUNT=`grep -P '^..00\s+177d9702' /proc/bus/pci/devices | wc | awk '{print $1}'`

LAST=`echo "2 * $NIC_COUNT - 2" | bc`

for i in `seq 0 2 $LAST`
do
    export OCTEON_REMOTE_PROTOCOL=PCI:$i
    oct-remote-reset
    COREMASK=`oct-remote-app-ctl info | grep Coremask | awk '{ print $4}' | sed -e s/^Coremask=//`
    oct-remote-app-ctl boot -m=$COREMASK $FIRMWARE
    oct-remote-csr SLI_SCRATCH_2 0x8000000000000000
done

modprobe -i liquidio $*

rmdir /var/lock/liquidio_lock

exit 0
