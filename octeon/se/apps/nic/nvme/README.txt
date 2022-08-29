                                    CN73xx NVMe software
                                       Version 0.0.6

NVM Express or Non-volatile memory express, defines a standard high-performance
interface to solid-state drives (SSDs) over PCI Express(PCIe).

CN73XX implements NVMe standard interface and acts as a storage device to
host system. It doesn't implements backend SSD but provides different 
mechanisms by which you can connect to your storage disks. The current 
software implementation presents RAM disks and SATA disks connected to CN73XX
SATA ports as NVMe backend name spaces. The firmware is highly flexible and
can be extended to work with different types of network-based backend
storage solutions such as iSCSI, FCP etc.

CN73XX presents NVMe PCIe function capable of SRIOV to the host system that are
claimed and initialized by the default linux/windows nvme drivers
(upstream/inbox/stock drivers). By default, the OCTEON firmware creates 32 name
spaces of size 32MB each from octeon DRAM and presents 1 namespace per controller
for first 32 controllers i.e for 1PF and 31VFs. The default behavior can be changed
by following the instructions mentioned below. Name space Mapping is limited to 1PF
and 31VFs as there are only 32 NS of 32MB each are created due to memory constraints
on the octeon RAM. Overall 32*32MB from the octeon RAM is used to emulate RAM disks.

SATA disk connected to CN73XX are presented as NVMe name spaces to host by booting
octeon linux on some cores and nvme firmware on other cores of 73xx as mentioned
below. In this mode the default mapping behavior is, 32 name spaces from octeon
DRAM are created and mapped as mentioned above and the newly discovered SATA disks
are enumerated a namespace 33 and 34 and so on. Each name space is presented to
VF32, VF33 and so on. If the default configuration is changed to have N RAM disks,
the discovered SATA disks are enumarated as namespace N, namespace N+1 and so on.

Firmware has a runtime mode to presents SATA disks connected CN73XX alone to the
host and doesnt emulate RAM disks. The default mapping behavior in this mode is, each
SATA disk is presented to one VF started from VF0 (i.e PF).

This package includes either the LiquidIO nvme Firmware binary
[liquidio-nvme-fwbin] or the firmware source [liquidio-nvme-fwsrc].

If your source-tree does not include the octeon/ directory you have the
Liquidio-nvme-fwbin, and do not have firmware sources. Instead,
you will find the firmware binaries in bin/octeon/.



---------------------------------------
Section 1: NVME SOURCE INSTALLATION
---------------------------------------
Please ensure that the following pre-requisites are met prior to installation:
OS versions,
- RHEL/CentOS 7.0 (Verified)
- Ubuntu 14.04.2 LTS (Verified)

The OCTEON firmware provided in this package is expected to work with all 
other versions of Windows/RHEL/CentOS/Ubuntu nvme stock drivers but not 
verified.

To install the software unzip the archive.

# unzip liquidio-nvme-fwbin-x.x.x.zip
-or-
# unzip liquidio-nvme-fwsrc-x.x.x.zip

The following RPM must be installed to build the firmware.
- OCTEON SDK version 3.1.2
- OCTEON LINUX version 3.1.2 (Needed in NVME+SATA mode alone)

--------------------------------------------------------------------
Section 2: NVME FIRMWARE COMPILATION TO USE EMULATED RAM DISKS ALONE
--------------------------------------------------------------------

NVMe firmware sources are present only in the LiquidIO NVMe source package.

NVMe Firmware Compilation: (with liquidio-nvme-fwsrc)

# cd $OCTEON_ROOT; source env-setup OCTEON_CN73XX
# cd <LIQUIDIO_SRC>/ . liquidio-env-setup.sh
# make nvme_nic_app -f Makefile.nvme

---------------------------------------------------------------------
Section 3: NVME FIRMWARE INSTALLATION TO USE EMULATED RAM DISKS ALONE
---------------------------------------------------------------------

The section will step you through the process of installation the LiquidIO 
NVMe firmware on the LiquidIO adapter.

# cd $OCTEON_ROOT; source env-setup OCTEON_CN73XX
# oct-pci-boot --board=NIC73
# oct-pci-load 0 $LIQUIDIO_ROOT/bin/octeon/cvmcs-nic-OCTEON_CN73XX.strip
# oct-pci-bootcmd 'bootoct 0 coremask=0xfff nqm_vf_mode=0'

nqm_vf_mode in boot command:
This controls the vf mode for Octeon NVMe queue management and affectively controls
number of NVMe VFs and IO queue count per VF that can be used.
It takes following values.
0: 1 PF and up to 256 VFs each with an admin queue pair and up to 16 IO queue pairs 
1: 1 PF and up to 513 VFs each with an admin queue pair and up to 8 IO queue pairs
2: 1 PF and up to 1027 VFs each with an admin queue pair and up to 4 IO queue pairs

NVF in PCIe SRIOV config space always reports 1027 as max vfs supported but the actual
number of usable VFs is configured with nqm_vf_mode.
It is harmless to have NVF in SRIOV configspace larger than VFs allowed as long as no
host software touches a VF outside the range allowed in a specific vf_mode.

------------------------------------------------------------
Section 4: NVME FIRMWARE COMPILATION TO USE SATA DISKS ALONE
------------------------------------------------------------
This section steps you through the process of presenting SATA disks connected to CN73XX
SATA interfaces to the host system as NVMe name spaces.

NVMe firmware sources are present only in the LiquidIO NVMe source package.

NVMe Firmware Compilation: (with liquidio-nvme-fwsrc)

# cd $OCTEON_ROOT; source env-setup OCTEON_CN73XX
# cd <LIQUIDIO_SRC>/ . liquidio-env-setup.sh
# make nvme -f Makefile.nvme

-------------------------------------------------------------
Section 5: NVME FIRMWARE INSTALLATION TO USE SATA DISKS ALONE
-------------------------------------------------------------

# cd $OCTEON_ROOT; source env-setup OCTEON_CN73XX
# oct-pci-boot --board=NIC73
# oct-pci-load 0 $LIQUIDIO_ROOT/bin/octeon/cvmcs-nic-OCTEON_CN73XX.strip
# oct-pci-bootcmd 'bootoct 0 coremask=0xfc0 nqm_vf_mode=0 sata_only_map'
# oct-pci-load 0 $LIQUIDIO_ROOT/bin/octeon/vmlinux.64
# oct-pci-bootcmd 'bootoctlinux 0 coremask=0x3f mem=1024M console=pci1'
# oct-pci-console 0

From other terminal
# oct-pci-console 1

From octeon linux shell (i.e from oct-pci-console 1)
# insmod /lib/modules/3.10.85-rt80-Cavium-Octeon/drivers/net/ethernet/octeon/cvmcs-nvme-sata.ko \
bdev_names="/dev/sda,/dev/sdb,/dev/sdc"

/dev/sda and /dev/sdb are the block devices to export/present to the host as NVMe name spaces.

sata_only_map:
Allows presenting SATA disks alone as NVMe name spaces. With this setting, firmware doesn't
emulate disks from RAM, and only the SATA disks are presented to host.

One should configure 2 PCI consoles to NVME+SATA. Console0 shows SE logs and Cosnole1 gets us
the Octeon linux console. For now, both consoles should be kept open always for the
functionality of NVME+SATA.

Enabling PCI consoles from U-boot shell:
# cd $OCTEON_ROOT; source env-setup OCTEON_CN73XX
# oct-pci-boot --board=NIC73
# oct-pci-bootcmd "setenv pci_console_active 1"
# oct-pci-bootcmd "setenv pci_console_count 2"
# oct-pci-bootcmd "setenv stdin pci,bootcmd"
# oct-pci-bootcmd "setenv stdout pci"
# oct-pci-bootcmd "setenv stderr pci"
# oct-pci-bootcmd "saveenv"

----------------------------------------
Section 6: NVME FIRMWARE BOOT PARAMETERS
----------------------------------------
nqm_vf_mode:
This controls the vf mode for Octeon NVMe queue management and affectively controls
number of NVMe VFs and IO queue count per VF that can be used as mentioned above.
Default value is 0.
Possible input range: 0, 1, 2.
ex: bootoct 0 coremask=0xfff nqm_vf_mode=2

nqm_sq_credits:
It restricts number of outstanding IOs in firmware per IOQ.
Default behavior is, IO queue sized commands are outstanding.
Possible input range: 1 to 4K
ex: bootoct 0 coremask=0xfff nqm_vf_mode=0 nqm_sq_credits=8

sata_only_map:
Allows presenting SATA disks alone as NVMe name spaces as mentioned above.
Default behavior is, SE RAM Disk and SATA disks are presented.
ex: bootoct 0 coremask=0xfff sata_only_map

intr_coalesce_off:
Disable interrupt coalescing. For measuring latency numbers, interrupt
coalescing should be disabled.
By default, coalescing is enabled and threshold value is 255 and coalescing
time is 100microsec.
ex: bootoct 0 coremask=0xfff nqm_sq_credits=1 intr_coalesce_off

------------------------
Section 7: NVME  DRIVER
------------------------

The stock nvme driver doesn't have support for SRIOV. So, the default stock 
driver initializes single controller i.e the NVMe PF device. The NVMe drivers 
included with this package has support for enabling SRIOV and can enable up to 
1027 NVMe VFs in the LiquidIO adapter. 

This package includes NVMe PF drivers for following OS versions,
- Centos 7.0 at $LIQUIDIO_ROOT/host/driver/src/linux/NVMe/nvme-centos7.0/
- Ubuntu 14.04.2 LTS at $LIQUIDIO_ROOT/host/driver/src/linux/NVMe/nvme-ubuntu-14.04.2LTS/


The NVMe PF driver takes following parameter:
1. num_vfs: Number of VFs to create on NVMe physical function. Default is 0.

2. nvme_vf_claim: Controls host behavior in claiming vfs (PF is always claimed 
                         by host). Values are:
        0: The VFs are presented to guests. (Default)
        1: All the VFs are claimed and initialized by host driver.



NOTE: See important note on black listing in-kernel drivers towards the end of 
         this document.


To load nvme driver on centos 7.0 host:
# cd $LIQUIDIO_ROOT/host/driver/src/linux/NVMe/nvme-centos7.0/
# make
# insmod nvme.ko num_vfs=1027 nvme_vf_claim=0

If no arguments are passed to the driver, the driver enables the NVMe PF device
and no VFs are created.

Once the driver is loaded, the host should see one 32MB name spaces and name spaces
should be visible under lsblk.

# lsblk -l
NAME                              MAJ:MIN RM   SIZE RO TYPE MOUNTPOINT
sda                                 8:0    0 465.8G  0 disk
└─sda1                              8:1    0 142.3G  0 part
  ├─centos-swap 253:0               0   7.9G  0 lvm  [SWAP]
  ├─centos-root 253:1               0    50G  0 lvm  /
  └─centos-home 253:2               0  84.4G  0 lvm  /home
nvme0n1                           259:0    0    32M  0 disk


VF Driver
---------
Stock NVMe drivers in kernel versions < 3.19 expects INTx support on NVMe 
controllers during driver initialization. But PCI VF devices doesn't support 
INTx and always works in MSIx mode. This is true for the VFs in CN73xx as 
well. So, the stock driver on the guest with kernel version < 3.19 would fail 
during controller initialization. This issue should not be seen with kernel 
versions >= 3.19.

Details on presenting VF to the VM is not covered here. Please refer to the 
documentation for your hypervisor.

To test with a guest running kernel versions < 3.19, a patch has been provided
with this package. The patch file nvme_driver_le_kernel_3.18.patch should be 
applied to the guest nvme driver. The patch applies to CentOS 7.0 NVMe stock 
driver i.e 3.10 kernel driver but can be easily ported to other kernel versions 
as well.

Patch location: $LIQUIDIO_ROOT/host/driver/src/linux/NVMe/nvme_driver_le_kernel_3.18.patch

Steps to apply patch:
# cd <path to nvme driver src on the guest>
# patch -p1 < nvme_driver_le_kernel_3.18.patch
# make

Load NVMe driver on the guest in the usual way.
# modprobe nvme
-or-
# insmod <path to nvme driver src on the guest>/nvme.ko




----------------------------------------
Section 8: Name space configuration tool
----------------------------------------


By default, nvme firmware and controller creates 32 namespaces from Octeon RAM
and presents one name space to each nvme controller for first 32 controllers.
Name space configuration and mapping information is maintained in namespaces.c.
The new namespaces.c with different NS and mapping information can be generated
using nsgen tool.

Recompilation and reload of firmware is required for the new configuration to 
take effect. Please refer to ns_generate.docx for detailed steps to configure 
namespaces and map them to controllers.

nsgen tool compilation and usage
--------------------------------
# cd $LIQUIDIO_ROOT/octeon/se/apps/nic/nvme/
# ./make_nsgen 
	- This generates the nsgen tool.

# ./nsgen namespaces namespaces.c





----------------
Section 9: Notes
----------------

Black listing stock nvme driver
-----------------------------

This release doesn't have support for booting nvme firmware from flash. The 
in-kernel NVMe driver can hang during host system boot as the 73XX doesn't 
respond for controller initialization.

To circumvent this issue, host system should be booted without loading the in-
kernel driver. This can be done by black listing the driver during the system 
boot. The stock in-kernel driver can be found in initramfs and/or in the root 
filesystem.

If nvme.ko is __NOT__ part of the initramfs/initrd, following are the steps to
block the nvme loading from rootfs.
# echo "blacklist nvme" >> /etc/modprobe.d/blacklist.conf

If the nvme.ko is part of intramfs/initrd, initrd should be built again with the
updated black listed config as follows.

On centOS/RHEL 7.x:
# echo "blacklist nvme" >> /etc/modprobe.d/blacklist.conf
# dracut /boot/initramfs-3.10.0-229.7.2.el7.x86_64.img --force
-or-
# mkinitrd /boot/initramfs-3.10.0-229.7.2.el7.x86_64.img 3.10.0-229.7.2.el7.x86_64

On Ubuntu 14.04.2:
# echo "blacklist nvme" >> /etc/modprobe.d/blacklist.conf
# mkinitramfs -o /boot/initrd.img-3.16.0.30-generic

Or
Provide modprobe.blacklist=nvme as a linux boot param in grub

