
LiquidIO: Source/Binary package for host driver and firmware
============================================================

=============================================================================


---------------------------------
CONTENTS
---------------------------------

* Contents
* Building and Installation
* Using the Driver
* Known Issues and Troubleshooting
* Updating Your Preboot Firmware
* Support

This package includes either the LiquidIO host driver and firmware
binary [liquidio-linux-driver-fwbin], or the host driver and firmware source
[liquidio-linux-driver-fwsrc].

If the package source-tree does not include the "octeon" directory you have the
binary package, and do not have firmware source. Instead, you will find the
firmware binaries in the bin/octeon directory.

Please refer to Release_Notes for details on this specific release.


=============================================================================


---------------------------------
BUILDING AND INSTALLATION
---------------------------------

Please ensure that the following pre-requisites are met prior to installation:
     o Host operating system:
       - CentOS 6.5, 7.4, RHEL-7.5 Or
       - Ubuntu 16.04.4 LTS (kernel: 4.13.0-38.43 or 4.4.0-108.131)
	 * 4.4.x kernel requires qemu package updated to version 2.0.0+dfsg-2ubuntu1.28
	 * 4.13.0-36 has a memory leak per Ubuntu bug 1748408, so it is not
	   recommended to use with Ubuntu 16.04.4 LTS.
       - XenServer release 7.1.1 (xenenterprise). 
     o Guest operating system:
       - CentOS 6.5, 7.4, RHEL-7.5, or
       - Ubuntu 16.04.4 LTS

Install this zip archive in a separate directory from any previous installation.
Please note that a previous version of the driver may already be included by
your distribution or kernel. If so, that may need to be uninstalled and/or 
any currently running version of the module should be removed.

# unzip liquidio-linux-driver-fwbin-x.y.z.zip
-or-
# unzip liquidio-linux-driver-fwsrc-x.y.z.zip

[liquidio-linux-driver-fwsrc only]
If you have the LiquidIO NIC driver package with firmware sources, you will
also need the following RPMs and patches to build the firmware.
     o OCTEON-SDK-3.1.2-568
     o OCTEON-SDK-3.1.2 patch 13

Also please apply the patch "lio_octeon_sdk_3.1.2p13.patch" to the SDK like this:

     cd /path/to/OCTEON-SDK
     patch -p 1 -i $LIQUIDIO_ROOT/patch/lio_octeon_sdk_3.1.2p13.patch
     pushd .
     cd $OCTEON_ROOT/target/include
     ln -s ../../executive/cvmx-helper-sfp.h cvmx-helper-sfp.h
     ln -s ../../executive/libfdt/cvmx-helper-fdt.h cvmx-helper-fdt.h
     popd

After applying this patch oct-version should read p13-L4

After applying the patch, please update your adapters to the updated uboot,
by following the instructions in the LiquidIO Preboot Driver Release package.


Directory Hierarchy
-------------------
The directory hierarchy is as follows:

$LIQUIDIO_ROOT                                Top-level, including Makefile for
                                              building all host and SE targets.

    README                                    *** This file. ***
    Release_Notes
    bin/                                      Contains links to all binaries
                                              from build (drivers, SE apps,
                                              kernel+rootfs) as well as build
                                              tools

    host/                                     Contains all host-based utilities,
                                              drivers, source code, apps, and
                                              tests.
        driver/
            doc/

            src/
                linux/cavium/liquidio/        Contains all Cavium Linux source
                                              minus osi components.

                osi/                          O/S independent files

        apps/                                 Contains all user apps and utils

            util/                             Firmware image builder, mfg diags,
                                              license control, etc.

    licenses/                                 Licenses that cover Cavium driver
                                              sources.

[liquidio-linux-driver-fwsrc only]
    octeon/                                   Contains all octeon-based utils,
                                              drivers, source code, apps, and
                                              tests.

        se/                                   Contains all Simple Exec software
            doc/

            core/                             PCI, messaging

            apps/                             
                common/                       Common functions for SE apps

                nic/                          Core NIC functionality
                test/

Building liquidio-linux-driver-fwbin
------------------------------------
The following commands should be run within the installation directory.

# ./configure

$LIQUIDIO_ROOT will now point to the directory with the LiquidIO source code.

If you had an earlier installation, it is recommended to clean up old installed
modules and binaries by doing the following:

# sudo make uninstall

To build the host and VF drivers just run from $LIQUIDIO_ROOT:

# make

After the build all target files will be in $LIQUIDIO_ROOT/bin.

To install the PF driver, firmware, scripts, and run depmod (requires root/sudo
access). This will also build the host and VF drivers if necessary.

# sudo make install

To install the VF driver, and run depmod (requires root/sudo access):

# sudo make vf_install

Any drivers will be installed in:
    /lib/modules/<KERNEL VERSION>/kernel/drivers/net/ethernet/cavium/liquidio/
The firmware files will be installed in /lib/firmware/liquidio.
Any associated scripts will be installed in /usr/local/bin.


Building liquidio-linux-driver-fwsrc
------------------------------------
Along with the requirements for any Octeon SDK installation,
particularly the OCTEON_ROOT setting, the following
commands should be run within the $LIQUIDIO_ROOT directory.

# export OCTEON_ROOT=/path/to/OCTEON-SDK 
# pushd $OCTEON_ROOT 
# source ./env-setup OCTEON_CN23XX
# popd
# ./configure /path/to/OCTEON-SDK

$LIQUIDIO_ROOT will now point to the directory with the LiquidIO source code.

To build the host and VF drivers, host utilities, and LiquidIO firmware, just
run from $LIQUIDIO_ROOT:
 
# make

After the build, all target files will be in $LIQUIDIO_ROOT/bin.

To build the host and VF drivers, host utilities, and firmware, then install the
firmware and driver files, and run depmod perform the following command. This
requires write permission in the build directory for root user to build the
firmware portion.

# sudo make install

If the root user does not have permission to write in the build directory,
use the following instead, but it requires the target files be already built
with the 'make' command:

# sudo make host_install

To install the VF driver, and run depmod (requires root/sudo access):

# make vf_install

Any drivers will be installed in:
    /lib/modules/<KERNEL VERSION>/kernel/drivers/net/ethernet/cavium/liquidio/
The firmware files will be installed in /lib/firmware/liquidio.
Any associated scripts will be installed in /usr/local/bin.


============================================================


---------------------------------
USING THE DRIVER
---------------------------------

The liquidio.ko host driver is supported on the following adapters:
* LiquidIO II CN2350 210SV
* LiquidIO II CN2360 210SV
* LiquidIO II CN2350 210SVPT (early access)
* LiquidIO II CN2360 210SVPT
* LiquidIO II CN2350 225SV
* LiquidIO II CN2360 225SV

The adapters must:
* be programmed with the Octeon SDK 3.1.2 patch 13-L4 preboot firmware,
* boot from flash (not PCI)

In general, adapters are pre-programmed with the correct preboot firmware
and bootcmd settings, so just confirm your boot switch settings (if any)
against the adapter's hardware user guide.


Installing the Module
---------------------
The liquidio driver is dependent on the ptp module in the host kernel for
precision timestamping. If not installed already on your system issue the
following command:
# modprobe ptp

To install the driver, simply do the following:

# cd $LIQUIDIO_ROOT/bin
# insmod liquidio.ko

Once installed, the network interfaces p1p1 and p1p2 will appear (as
appropriate for the PCIe slot the adapter is plugged), and can
be configured using 'ifconfig' and 'ethtool'.  

If the firmware fails to load when installing the driver, use the
LiquidIO Preboot Driver release package to recover the adapter.
See "Updating Your Preboot Firmware" below. 

If VF functionality is required and it is an SR-IOV capable adapter,
use the sysfs sriov_numvfs parameter to enable VFs. For details, see
https://www.kernel.org/doc/Documentation/PCI/pci-iov-howto.txt.
The sriov_numvfs parameter indicates the number of VFs for a given PF.
Since there are two PFs, you must specify the number of VFs for each PF
device separately.

CN23x0-based adapters support a maximum of 63 VFs per PF and a total of
64 I/O queues per PF.

By default the number of queues allocated to a PF is optimized to
first allocate the maximum number of queues to the PF based on the number
of CPUs available to the host. This can also be adjusted manually using
the num_queues_per_pf module parameter.  Since there are two PFs, you must
specify two comma-separated values: to the left of the comma is the value for
PF0; to the right of the comma is the value for PF1.

For a VF, the number of queues allocated is by default 1. This can 
be adjusted manually using the num_queues_per_vf module parameter, which
is also comma-delimited so each PF can have an independent number of queues
per VF. The num_queues_per_vf must always be a power of two.

The total number of VFs available for a given PF is derived from the
aforementioned module parameters, num_queues_per_pf and num_queues_per_vf.
The maximum number of VFs on a PF (max_vfs) is equal to the following,
rounded down:
          (64 - num_queues_per_pf)
max_vfs = ------------------------
             num_queues_per_vf

The total number of VFs that are actually instantiated are then driven by
writing to the sysfs sriov_numvfs parameter. This cannot exceed the derived
max_vfs value.

Here's an example with the default configuration on a 6 CPU system:

# insmod liquidio.ko

Using the defaults, num_queues_per_pf would be 6, and num_queues_per_vf
would be 1. As a result max_vfs would be (64 - 6) / 1 = 48 on each PF.
Each VF would have 1 queue.

As another example, to specify 8 queues per PF and 2 queues per VF. For this
configuration max_vfs would be (64 - 8) / 2 = 28 per PF.

# insmod liquidio.ko num_queues_per_pf=8,8 num_queues_per_vf=2,2

To unload the driver:
# rmmod liquidio.ko

All associated VF driver instances must be unloaded before the PF driver may
be unloaded.

VF Driver
---------
The liquidio_vf.ko driver is used for 23XX virtual functions on LiquidIO II
CN23x0 adapters. To install the driver:

# cd $LIQUIDIO_ROOT/bin
# insmod liquidio_vf.ko

By default, the number of queues will be optimized to be the minimum of the
number allocated by the PF and the number of VM VCPUs. To override the number
of queues limited by the number of VCPUs, the num_queues parameter can be used.
The num_queues parameter is always limited by the num_queues_per_vf in the PF
driver (default 1).

For example, if there are 2 VCPUs but 8 queues allocated by the PF, the number
of VF queues would be optimized to two. To override this to use 8 instead, do
the following:

# insmod liquidio_vf.ko num_queues=8

Once installed, the network interfaces p1p1_1, p1p1_2, etc will appear,
and can be configured using 'ifconfig' and 'ethtool'. NOTE: In order
for a VF interface to come up, the associated PF interface was be up
and running as well.

To unload the driver:
# rmmod liquidio_vf.ko

A note on IOMMU: In order to use the VF driver on a VM, IOMMU must be
enabled in the BIOS of the system and it must be passed on the Linux kernel
command line. For Intel, use intel_iommu=on, and for AMD amd_iommu=on. 

Jumbo Frames
------------
LiquidIO adapters support jumbo frames, by adjusting the MTU beyond the
default 1500 byte MTU. If jumbo frames are required on a VF, the corresponding
PF MTU must also be adjusted. The VF's MTU cannot exceed the PF's MTU.

Ethtool
-------
Supported ethtool options include for the liquidio and liquidio_vf driver include:
-i: driver capabilities
-k/-K: feature configuration
-g/-G: ring parameters (Rx/Tx descriptor count lies in the range 128 to 2048)
-l/-L: Channel configuration (combined only)
-c/-C: Receive and transmit coalesce options (adaptive-rx, rx-frames, tx-frames)
-S: statistics
-s: debug msglvl and speed (25GbE Intelligent adapter only)
-d: dump registers
-T: timestamping capabilities (currently software only)

In addition to the above, the liquidio (not liquidio_vf) driver also supports:
-e: EEPROM access
-a/-A: Pause frame status
-p: Card identification

Changing interface speed (25GbE Intelligent adapter only)
------------------------
The LiquidIO 25GbE Intelligent adapter supports both 10Gbps and 25Gbps speeds. 
This is a global setting and changing it on one interface will change it on both
interfaces of the adapter. A user may use ethtool to set the interface speed 
and the speed setting will take effect after the driver has been reloaded.

Changing speed to 10Gbps also disables any FEC setting.

Usage:
# ethtool -s devname speed 10000|25000

Linux kernel 4.7.0 below (such as CentOS 7.4), a user may check the speed setting
by examining the output of "dmesg" after issuing "ethtool devname". 
The speed setting will be listed under "Advertising".

Usage:
# ethtool devname; dmesg

example of output for 25G setting:
[166715.293333] ethtool p3p1: 
Supported: 
	ETHTOOL_LINK_MODE_25000baseCR_Full
	ETHTOOL_LINK_MODE_25000baseSR_Full
	ETHTOOL_LINK_MODE_25000baseKR_Full
	ETHTOOL_LINK_MODE_10000baseKR_Full
[166715.343831] Advertising: 
	ETHTOOL_LINK_MODE_25000baseCR_Full
	ETHTOOL_LINK_MODE_25000baseSR_Full
	ETHTOOL_LINK_MODE_25000baseKR_Full

Changing RS-FEC setting
-----------------------
The LiquidIO 25GbE Intelligent adapter supports either RS-FEC or no FEC when the 
NIC is loaded with 25G speed mode. By default the setting is RS-FEC off. 
To show/change it use 'ethtool --show-fec <devname>' / 
'ethtool --set-fec <devname> off/rs' if ethtool and the Linux kernel supports it, 
or use the following private flag to set/unset it or show it.

Usage:
 ethtool --set-priv-flags devname RS_FEC on|off
 ethtool --show-priv-flags devname

Rx Packet Steering
------------------
The Rx packet steering feature causes the adapter to automatically select 
the same Rx queue as the Tx queue on which the packets of a given flow were
transmitted. This ensures that both the Tx and Rx packets of a flow are
processed on the same core. This generally saves CPU cycles and cache flushes 
compared to when packets from Tx and Rx of a flow are processed on 
different cores.

Usage:
 ethtool --set-priv-flags devname pkt_steering on|off

Channel Reconfiguration (ethtool -L)
------------------------------------
The combined queue count for a PF/VF interface is initialised to the module
parameters num_queues_per_pf/num_queues_per_vf.

This value can be dynamically changed for both PF and VF using the -L option.
The combined count for the PF lies between 1 and the number of queues
passed at load time if it is SRIOV enabled and lies between 1 and the
maximum possible queues that interface can support if it is SRIOV disabled.

For a VF, the combined count varies from 1 to the number of queues at load
time.

Statistics (ethtool -S)
-----------------------

Usage:
# ethtool -S devname

Output:
NIC statistics:
     rx_packets: Driver received packets
     tx_packets: Driver transmitted packets
     rx_bytes: Driver received octets
     tx_bytes: Driver transmitted octets
     rx_errors: Count of all packets
		1. Fragment error
		2. Overrun error
		3. FCS error
		4. Jabber error
		5. DMA packet error
		6. PKI parity error
		7. PKI PCAM access error
		8. PKI ran out of FPA buffers while receiving
		9. Packet exceeded the maximum of 255 FPA buffers
		10. L2 header malformed
		11. Oversize error
		12. Length mismatch error
		13. IPv4 header checksum error
		14. L4 checksum error
     tx_errors: 
     rx_dropped: Count of all packets
		 1. Dropped by driver
		 2. Due to RX FIFO full
		 3. Dropped by the DMAC filter
		 4. Inbound packets dropped by RED, buffer exhaustion
		 5. fw_err_pko
		 6. fw_err_link
		 7. fw_err_drop
     tx_dropped: Count of all packets
		 1. Dropped by driver
		 2. due to excessive collisions
		 3. due to max deferrals 
		 4. fw_err_pko
		 5. fw_err_link
		 6. fw_err_drop
		 7. fw_err_pki
Firmware Tx Statistics:
     tx_total_sent: Total packet firmware sent 
     tx_total_fwd: Total packet firmware forwarded
     tx_err_pko: 
     tx_err_pki: 
     tx_err_link: 
     tx_err_drop: 
     tx_tso: Number of TSO requests
     tx_tso_packets: Number of packets segmented in TSO
     tx_tso_err: 
     tx_vxlan:
MAC Tx Statistics: 
     mac_tx_total_pkts: Total frames sent on the interface 
     mac_tx_total_bytes: Total octets sent on the interface
     mac_tx_mcast_pkts: Packets sent to the multicast DMAC
     mac_tx_bcast_pkts: Packets sent to a broadcast DMAC
     mac_tx_ctl_packets: Control/PAUSE packets sent
     mac_tx_total_collisions: Packets dropped due to excessive collisions 
     mac_tx_one_collision: Packets sent that experienced a single collision
			   before successful transmission
     mac_tx_multi_collison: Packets sent that experienced multiple collisions
			    before successful transmission 
     mac_tx_max_collision_fail: Packets dropped due to excessive collisions
     mac_tx_max_deferal_fail: Packets not sent due to max deferal 
     mac_tx_fifo_err: Packets sent that experienced a transmit underflow and
		      were truncated 
     mac_tx_runts: Packets sent with an octet count lessthan 64
RX Firmware statistics:
     rx_total_rcvd: 
     rx_total_fwd: 
     rx_jabber_err: Jabber error
     rx_l2_err: Sum of
		1. DMA packet error
		2. PKI parity error
		3. PKI PCAM access error
		4. PKI ran out of FPA buffers while receiving
		5. Packet exceeded the maximum of 255 FPA buffers
		6. L2 header malformed
		7. Oversize error
		8. Length mismatch error
     rx_frame_err:  Sum of IPv4 header and L4 checksum error
     rx_err_pko: 
     rx_err_link: 
     rx_err_drop: 
     rx_vxlan: 
     rx_vxlan_err: 
     rx_lro_pkts: Number of packets that are LROed
     rx_lro_bytes: Number of octets that are LROed
     rx_total_lro: Number of LRO packets formed
     rx_lro_aborts: Number of times LRO of packet aborted
     rx_lro_aborts_port: 
     rx_lro_aborts_seq: 
     rx_lro_aborts_tsval: 
     rx_lro_aborts_timer: Timer setting error 
     rx_fwd_rate: 
MAC Rx Statistics: 
     mac_rx_total_rcvd: Received packets 
     mac_rx_bytes: Octets of received packets
     mac_rx_total_bcst: Number of non-dropped L2 broadcast packets
     mac_rx_total_mcst: Number of non-dropped L2 multicast packets
     mac_rx_runts: Sum of PUNY and undersize errors
     mac_rx_ctl_packets: Received PAUSE packets
     mac_rx_fifo_err: Packets dropped due to RX FIFO full 
     mac_rx_dma_drop: Packets dropped due to RX FIFO full
     mac_rx_fcs_err: Sum of Fragment, overrun and FCS errors
     link_state_changes:
TxQ{0..n-1} Statistics:
     tx-{0..n-1}-packets: Bytes sent through this queue
     tx-{0..n-1}-bytes: Total count of bytes sento to network
     tx-{0..n-1}-dropped: Numof pkts dropped dueto xmitpath errors
     tx-{0..n-1}-iq_busy: Numof times this iq was found to be full
     tx-{0..n-1}-sgentry_sent: Gather entries sent through this queue
     tx-{0..n-1}-fw_instr_posted: Instructions posted to this queue
     tx-{0..n-1}-fw_instr_processed: Instructions processed in this queue
     tx-{0..n-1}-fw_instr_dropped: Instructions that could not be processed
     tx-{0..n-1}-fw_bytes_sent: Bytes sent through this queue
     tx-{0..n-1}-tso: Count of TSO
     tx-{0..n-1}-vxlan: 
     tx-{0..n-1}-txq_restart: Number of times this queue restarted 
RxQ{0..n-1} Statistics:
     rx-{0..n-1}-packets: Number of packets sent to stack from this queue
     rx-{0..n-1}-bytes:  Number of Bytes sent to stack from this queue
     rx-{0..n-1}-dropped: Sum of rx-{0..n-1}-dropped_nomem,
			  rx-{0..n-1}-dropped_toomany,
			  and rx-{0..n-1}-fw_dropped
     rx-{0..n-1}-dropped_nomem: Packets dropped due to no memory available
     rx-{0..n-1}-dropped_toomany: Packets dropped due to large number of pkts to
				  process
     rx-{0..n-1}-fw_dropped: Num of Packets dropped due to receive path failures
     rx-{0..n-1}-fw_pkts_received: Number of packets received in this queue 
     rx-{0..n-1}-fw_bytes_received: Bytes received by this queue
     rx-{0..n-1}-fw_dropped_nodispatch: Packets dropped due to no dispatch function
     rx-{0..n-1}-vxlan: 
     rx-{0..n-1}-buffer_alloc_failure: Num of buffer allocation failures
 
Macvtap
-------
Up to 31 macvtaps can be associated to each VF; no such limit for PFs.

When using macvtap, it may be helpful to adjust some ethtool settings for
better performance. For example to improve Rx TCP throughput:
# ethtool -K <interface> lro on
Also, for some tests adjusting interrupt rates can prove helpful:
# ethtool -C <interface> rx-usecs-high 128

MAC anti-spoofing feature
-------------------------
When a malicious VF driver attempts to transmit a packet with a MAC address
on an interface that has its MAC address administratively provisioned by the
host, or if MAC anti-spoofing is turned on, the packet will be silently dropped.
MAC anti-spoofing is turned on with the 'ip link set <pf> vf <vf#> spoofchk on'
command.

NOTE: After turning on MAC anti-spoofing, the VF user will not be able to change
hardware's VF mac address even though the VF driver (or ifconfig) may report it
as changed. The host configuration will correctly show the MAC address actually
used (via ip link show...). It will correctly reject MAC address changes if the
host has administratively configured the MAC address.


============================================================


---------------------------------
KNOWN ISSUES AND TROUBLESHOOTING
---------------------------------

Common issues and limitations:
------------------------------
* For CN23x0 210SVN adapters, during the boot process the default NVMe
  driver may cause a system hang when trying interrogate the NVMe PF.
  If NVMe functionality is not required, try blacklisting the NVMe driver.
  Otherwise consult Cavium support for details on enabling NVMe.

* Direct Attach VF latency is poor on a CentOS 7.x host unless qemu is patched
  or updated to account for unaligned page accesses. This also fixes an issue
  with PCI accesses from a VM running on an Ubuntu 14.04.5 host (4.4 kernels).
  Use qemu version 2.1.3 or later, or apply the patch available here:
  http://git.qemu.org/?p=qemu.git;a=commitdiff;h=f2a64032a14c642d0ddc9a7a846fc3d737deede5 

* VM Packet processing performance can vary depending on CPU and memory
  configuration as well as hypervisor scheduling.

* Enabling SRIOV capability via the sriov_numvfs parameter on a non-SRIOV capable
  system may cause a system hang depending on system BIOS.

* Disabling SRIOV while VFs are attached to a VM can cause a hypervisor lockup.

* On CN2350/CN2360-225 adapters, the link may not come up if there is a mismatch
  in FEC settings. By default adapters have RS-FEC disabled.
  There is also no support for Autonegotiation or Fire code FEC.

* Power management is not supported.

* Receive traffic may not be distributed evenly amongst host cpu cores. Use
  the script bin/cavm_set_irq_affinity.sh to spread the load.

*  With a built-in liquidio kernel module, the driver load may fail with a 
   "Request firmware failed" message. By default, the driver attempts to
   load the appropriate firmware image from a host filesystem, normally
   /lib/firmware. If that filesystem is not available at driver loading
   time, then it will fail in this manner.  To fix this error use an initramfs
   filesystem to hold the firmware images, using the steps below:
   1) Copy the firmware images to a directory say "../initramfs/firmware/liquidio"
   2) Update the kernel .config file with these flags
      CONFIG_LIQUIDIO=y
      CONFIG_INITRAMFS_SOURCE="../initramfs/"
      CONFIG_INITRAMFS_ROOT_UID=0
      CONFIG_INITRAMFS_ROOT_GID=0
   3) Build and install kernel
   4) Pass firmware_class.path="/firmware/" as a kernel parameter.

Updating Your Preboot Firmware
------------------------------
If it is necessary to update your Preboot firmware, please
follow the instructions in the Preboot Driver Release package,
liquidio-preboot-fwbin-x.x.x, delivered separately.

Customers with firmware source may find it helpful to update the
preboot firmware with their modifications. To do this, simply build
the firmware as normal, rebuild the preboot upgrade image with the 
new firmware, then apply it to the adapter. Instructions for this can
be also found in the aforementioned Preboot Driver Release package.


============================================================


---------------------------------
SUPPORT
---------------------------------

For general information, go to the Cavium website:
http://support.cavium.com/
