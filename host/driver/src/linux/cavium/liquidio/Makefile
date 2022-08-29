#
# Makefile for Liquid IO Server Adapters
#

CDIR = ../../../osi/

export BPF_DIR := $(shell if [ x"${BPF_OFFLOAD}" != x ]; then echo ../../ebpf_mips64/; fi)

PF_DEPENDENCIES := $(shell find . $(CDIR) $(BPF_DIR) -name '*.[ch]' -print | sed 's/^\.\///' | sed -e 's/^.*\.mod.c$$//' -e 's/lio_vf_main.c//')
VF_DEPENDENCIES := $(shell find . $(CDIR) -name '*.[ch]' -print | sed 's/^\.\///' | sed -e 's/^.*\.mod.c$$//' -e 's/lio_main.c//')

.NOTPARALLEL:

.PHONY:	all clean partial_clean

all:	liquidio.ko liquidio_vf.ko

clean:	partial_clean
	rm -rf *.ko

partial_clean:
	rm -rf .*.cmd *.mod.* *.o .tmp_versions
	rm -f modules.order Module*.symvers *.ko.unsigned
	rm -f $(CDIR).*.cmd $(CDIR)*.o
	if [ x"${BPF_OFFLOAD}" != x ]; then \
		rm -f $(BPF_DIR).*.cmd $(BPF_DIR)*.o; \
	fi
	rm -f Kbuild

liquidio.ko: $(PF_DEPENDENCIES)
	$(MAKE) partial_clean
	ln -s Kbuild.pf Kbuild
	$(MAKE) -C /lib/modules/`uname -r`/build V=1 M=`pwd` modules
	mv -f Module.symvers Module.liquidio.symvers

liquidio_vf.ko: $(VF_DEPENDENCIES)
	$(MAKE) partial_clean
	ln -s Kbuild.vf Kbuild
	$(MAKE) -C /lib/modules/`uname -r`/build M=`pwd` modules
	mv -f Module.symvers Module.liquidio_vf.symvers
