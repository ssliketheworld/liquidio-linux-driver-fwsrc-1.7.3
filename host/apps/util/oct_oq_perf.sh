#!/bin/bash
iface=$1
if [ -z "$1" ]; then
	echo Enter interface as first argument
	exit
fi
tmpfile=/tmp/oct_oq_perf_$$${iface}

trap ctrl_c INT

function ctrl_c() {
	rm -f ${tmpfile}
	exit
}

while true
do
	let last_total=0
	ethtool -S ${iface} > ${tmpfile}
	for (( i=0; i<12; i++  ))
	do
		last=`cat ${tmpfile} | grep rx-${i}-dropped: | awk '{ print $2 }'`
		if [ -n "$last" ]; then
		   last_total=$(($last_total+$last))
		fi
	done
	sleep 1.99
	let now_total=0
	ethtool -S ${iface} > ${tmpfile}
	for (( i=0; i<12; i++  ))
	do
		now=`cat ${tmpfile} | grep rx-${i}-dropped: | awk '{ print $2 }'`
		if [ -n "$now" ]; then
		   now_total=$(($now_total+$now))
		fi
	done
	let rate=(now_total-last_total)/2
	echo ${iface} rate is $rate pps
	rm ${tmpfile}
done


