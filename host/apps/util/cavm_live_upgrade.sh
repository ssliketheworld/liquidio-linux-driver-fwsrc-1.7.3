#!/bin/bash

export OCTEON_REMOTE_PROTOCOL=PCI:0

if [ -z "$1" ]; then
    echo Please specify firmware image to load.
    exit 1
else
    img=$1
    shift
fi

if [ -f "${img}" ]; then
    file_info=`file -b ${img}  | grep -o "ELF.*MIPS64"`
    if [ -z "$file_info" ]; then
        echo ${img} is not a valid firmware image.
        exit 2
    fi
else
    echo ${img} is not a valid firmware image.
    exit 3
fi

txt=`oct-remote-app-ctl info`
rc=$?
string=`echo ${txt} | grep "\-\-\- [01]"`

if [ -z "$string" ] || [ ${rc} -lt 0 ]; then
    exit 4
fi

img_count=`echo ${txt} | grep "\-\-\- [01] \| [01] " | wc -l`

if [ $img_count -ne 1 ] || [ ${rc} -lt 0 ]; then
    exit 5
fi

old_index=`echo ${txt} | grep "\-\-\- [01]" | sed "s/.*\-\-\- \([0,1]\) .*/\1/g"`

if [ $old_index -eq 0 ]; then
    new_index=1
else
    new_index=0
fi

cmd="oct-remote-app-ctl del -numcores=8 -index=$old_index 2>&1"
txt=`eval ${cmd}`
rc=$?
echo ${txt} | grep SUCCESS > /dev/null
if [ $? -eq 0 ]; then
    coremask=`echo ${txt} | sed "s/.*UCCESS: App index [0-9]* now runs on cores 0x\([0-9,a-f]*\).*/\1/g"`
else
    coremask=
fi

if [ ${rc} -ne 0 ] || [ -z "${coremask}" ]; then
    echo "Error: 8"
    echo "cmd: \"${cmd}\""
    echo "txt: \"${txt}\", coremask: \"${coremask}\", rc: ${rc}"
    exit 8
fi

cmd="oct-remote-app-ctl boot -numcores=8 ${img} lio-live-upg"
txt=`eval ${cmd}`
rc=$?

if [ ${rc} -ne 0 ]; then
    echo "Error: 9"
    echo "cmd: \"${cmd}\""
    echo "txt: \"${txt}\", rc: ${rc}"
    exit 9
fi

# Calculate corecount by getting the Hamming weight of coremask.
# Use a here document to embed a bc script.
# hamming() function came from http://phodd.net/gnu-bc/code/logic.bc
corecount=$(bc -q <<EOF
define hamming(x,y) {
  auto os,a,b,t;
  os=scale;scale=0;x/=1;y/=1
  if(bitwidth){
    if(x<0||y<0)b=2^bitwidth
    if(x<0)x=(b+b+x)%b #x=unsign(x)
    if(y<0)y=(b+b+y)%b #y=unsign(y)
  } else {
    if(x<0&&y<0){x=-1-x;y=-1-y}
    if(x<0||y<0){
      print "hamming: infinite distance from mismatched signs\n";
      b=os;b*=D*D+A*A;b/=9*9 # approximate nearest power of 2 to A^os
      scale=os;return 2^b-1
    }
  }
  t=0;while(x||y){if((a=x%4)!=(b=y%4))t+=1+(a+b==3);x/=4;y/=4}
  scale=os;return t
}
ibase=16
hamming($coremask,0)
EOF
)
# end of embedded bc script

for i in `seq 1 20`
do
    echo -e -n "\rWaiting for f/w reload: ${i}... "
    sleep 1
    txt=`oct-remote-csr SLI_SCRATCH_2`
    scratch2=`echo ${txt} | grep "DATA" | sed "s/.*DATA = \([0-9]*\)\(.*\)/\1/g"`
    if [ -z ${scratch2} ]; then
        echo "Error reading SLI_SCRATCH_2"
        echo "txt: \"${txt}\""
        exit 10
    fi
    let "fw_is_reloaded = ($scratch2 >> 62) & 1"
    if [ $fw_is_reloaded -eq 1 ]; then
	echo "f/w reloaded."
        let "scratch2 = $scratch2 & 0xBFFFFFFFFFFFFFFF"
        scratch2=`echo "obase=16; $scratch2" | bc | sed -e s/^-/0x/g`
        txt=`oct-remote-csr SLI_SCRATCH_2 $scratch2`
        txt=`oct-remote-app-ctl shut -index=$old_index`
        rc=$?
        if [ ${rc} -ne 0 ]; then
            echo "Error: oct-remote-app-ctl shut, rc ${rc}"
            echo "txt: \"${txt}\""
            exit 11
        fi
        txt=`oct-remote-app-ctl add -numcores=$corecount -index=$new_index`
        if [ ${rc} -ne 0 ]; then
            echo "Error: oct-remote-app-ctl add, rc ${rc}"
            echo "txt: \"${txt}\""
            exit 12
        fi
        printf "Done.\n\n"
        exit 0
    fi
done

exit 6
