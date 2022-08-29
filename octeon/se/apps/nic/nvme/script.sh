#!/bin/bash

# echo "Hello World"

oct-pci-boot
oct-pci-load 0x20000000 nvme_cvmx
oct-pci-bootcmd 'bootoct 0x20000000 coremask=0x3 endbootargs 1'
exit 0

