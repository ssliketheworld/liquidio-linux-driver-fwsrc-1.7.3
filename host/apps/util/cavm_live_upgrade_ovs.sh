#!/bin/bash

CUR_DIR=`pwd`
HOST_BIN_DIR=$CUR_DIR/host/bin

if [ -z "$1" ]; then
    echo Please specify firmware image to load.
	echo "Usage:  ./cavm_live_upgrade_ovs.sh <firmware image>" 
    exit 1
fi

if [ -f "$1" ]; then
    file_info=`file -b $1  | grep -o "ELF.*MIPS64"`
    if [ -z "$file_info" ]; then
        echo \"$1\"is not a valid firmware image.
	    echo "Usage:  ./cavm_live_upgrade_ovs.sh <firmware image>" 
        exit 2
    fi
else
    echo \"$1\" is not a valid firmware image.
	echo "Usage:  ./cavm_live_upgrade_ovs.sh <firmware image>" 
    exit 3
fi

string=`$HOST_BIN_DIR/oct-pci-app-ctl info | grep "    [01]"`

if [ -z "$string" ]; then
    exit 4
fi

img_count=`$HOST_BIN_DIR/oct-pci-app-ctl info | grep "    [01]" | wc -l`

if [ $img_count -ne 1 ]; then
    exit 5
fi

old_index=`$HOST_BIN_DIR/oct-pci-app-ctl info | grep "    [01]" | awk '{ print $1}'`

if [ $old_index -eq 0 ]; then
    new_index=1
else
    new_index=0
fi

coremask=`$HOST_BIN_DIR/oct-pci-app-ctl del -numcores=8 -index=$old_index 2>&1 | grep ^SUCCESS | awk '{ print $9 }' | sed -e s/0x// | tr [:lower:] [:upper:]`
$HOST_BIN_DIR/oct-pci-app-ctl boot -numcores=8 $1


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
    sleep 1
    scratch2=`$HOST_BIN_DIR/oct-pci-csr SLI_SCRATCH_2 | grep DATA | awk '{ print $5 }'`
    let "fw_is_reloaded = ($scratch2 >> 62) & 1"
    if [ $fw_is_reloaded -eq 1 ]; then
        let "scratch2 = $scratch2 & 0xBFFFFFFFFFFFFFFF"
	scratch2=`printf "0x%x" $scratch2`
        $HOST_BIN_DIR/oct-pci-csr SLI_SCRATCH_2 $scratch2
        $HOST_BIN_DIR/oct-pci-app-ctl shut -index=$old_index
        $HOST_BIN_DIR/oct-pci-app-ctl add  -numcores=$corecount -index=$new_index
        exit 0
    fi
done

exit 6
