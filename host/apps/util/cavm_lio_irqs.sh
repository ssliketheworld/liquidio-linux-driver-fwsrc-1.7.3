#!/bin/bash
#
# This script displays the IRQs used by a particular LiquidIO network device.

# Usage:
#    [sh] lio_irqs.sh <iface>
# Where:
#    <iface> - name of network interface
#
if [ $# -lt 1 ]; then
	echo "Please specify a LiquidIO network interface name."
	exit 1
else
	iface=$1
	shift
fi

ifconfig ${iface} > /dev/null 2>&1
if [ $? -ne 0 ]; then
	echo "Unable to locate interface '${iface}'"
	exit 1
fi

# iterate through each msi irq reported by netdevice
for f in /sys/class/net/${iface}/device/msi_irqs/*; do
	# obtain the IRQ number
	irq=`echo ${f}|awk -F / '{print $NF}'`
	# locate the IRQ number in '/proc/interrupts'
	ln=`grep  -w "${irq}:" /proc/interrupts|grep LiquidIO`
	if [ "${ln}" == "" ]; then
		echo "${iface}: unknown IRQ #${irq}"
	else
		# retrieve the name assigned to IRQ (last field)
		name=`echo ${ln} | awk '{print $NF}'`
		# retrieve Octeon name from IRQ name (first field)
		octeonname=`echo ${name} | awk -F - '{print $1}'`
		# retrieve Queue # from IRQ name (last field)
		queue=`echo ${name} | awk -F - '{print $NF}'`
		# retrieve Queue type from IRQ name (2nd-to-last field)
		type=`echo ${name} | awk -F - '{print $(NF-1)}'`
		# display results
		# - this tests for a non-numeric queue value; 
		# - if non-numeric, print it as a string (and ignore type)
		if [ -z ${queue//[0-9]} ]; then
			printf "%s: %s queue %02u ('%s') uses IRQ %u\n" \
				${iface} ${octeonname} ${queue} ${type} ${irq}
		else
			printf "%s: %s queue ('%s') uses IRQ %u\n" \
				${iface} ${octeonname} ${queue} ${irq}
		fi
	fi
done
