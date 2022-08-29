#!/bin/bash

# NUMA-aware IRQ affinity script

# Get the PCIe domain, bus, device, function of the LiquidIO NIC
pci_dbdf=`lspci -D | grep -m 1 -i cavium | sed "s/ .*\$//"`
if [ -z $pci_dbdf ]
then
    echo "No LiquidIO NIC detected"
    exit 1
fi

# Get the IRQs that belong to the LiquidIO NIC
array_of_irqs=(`grep LiquidIO /proc/interrupts | sed "s/: .*//g" | sed "s/^ *//g"`)
if [ ${#array_of_irqs[@]} -eq 0 ]
then
    echo "No IRQs found\n"
    exit 2
fi

# Check if irqbalance is running
IRQBALANCE_ON=`ps ax | grep -v grep | grep -q irqbalance; echo $?`
if [ "$IRQBALANCE_ON" == "0" ]
then
    echo " WARNING: irqbalance is running and will"
    echo "          likely override this script's affinitization."
    echo "          Please stop the irqbalance service and/or execute"
    echo "          'killall irqbalance'"
    exit 3
fi

# Get the bitmask that indicates which CPUs are NUMA local to the PCIe slot
# occupied by the LiquidIO NIC
local_cpus_mask=`cat /sys/bus/pci/devices/$pci_dbdf/local_cpus`

# "local_cpus_mask" probably has many bits set.  We need to break it up into
# its constituent parts.  Each part is a bitmask that has only one bit set.
# All those parts are contained in "array_of_cpu_masks".
array_of_32bitwords=(`echo $local_cpus_mask | sed "s/,/\n/g"`)
suffix=""
n=0
let "last_index = ${#array_of_32bitwords[@]} - 1"
for i in `seq $last_index -1 0`
do
    let "word = 16#${array_of_32bitwords[$i]}"
    for j in `seq 0 31`
    do
        let "bit = ($word >> $j) & 1"
        if [ $bit -eq 1 ]
        then
            let "mask = 1 << $j"
            mask_string=`printf "%x%s" $mask $suffix`
            array_of_cpu_masks[$n]=$mask_string
            let "n++"
        fi
    done
    suffix="${suffix},00000000"
done


cpu_masks_count=${#array_of_cpu_masks[@]}
i=0
for irq in ${array_of_irqs[@]}
do
    cmd=`printf "echo %s > /proc/irq/%s/smp_affinity" ${array_of_cpu_masks[$i]} $irq`
    echo $cmd
    eval $cmd

    let "i++"
    if [ $i -eq $cpu_masks_count ]
    then
        # wrap around to 0 to prevent going out of bounds in array_of_cpu_masks
        i=0
    fi
done
