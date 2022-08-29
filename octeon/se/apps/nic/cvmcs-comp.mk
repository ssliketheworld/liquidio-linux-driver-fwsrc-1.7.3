ifdef HYBRID
COMPILE += -DHYBRID
ifdef VSWITCH
COMPILE += -DVSWITCH
COMPILE += -DOCTLINUX_CONTROLS_PF_MTU
# set PKI_TAG_SECRET_VALUE below to override
# the default behavior of setting CVMX_PKI_TAG_SECRET
# to some random value at init.
COMPILE += -DPKI_TAG_SECRET_VALUE=0x161756F9C6A94F22
dir := $(OCTEON_SE_SRC)/apps/vswitch
include $(dir)/cvmcs-vsw.mk
COMPILE += -I./
endif #VSWITCH
ifdef OVS_WIREMGMT_IF_EN
COMPILE += -DLIO_OVS_WIRE_MGMT_IF -DMGMT_PCAM_FILTER_BCAST_MCAST
endif
endif #HYBRID

ifdef LINUX_IPSEC

LRO_TSO_INC ?= $(OCTEON_SE_SRC)/nic/lro_tso
dir := $(OCTEON_SE_SRC)/apps/nic/lro_tso
include $(dir)/cvmcs-lro-tso.mk

COMPILE += -DLINUX_IPSEC -DCVM_IPSEC_SUPPORT  -DCVMX_NULL_POINTER_PROTECT

dir := $(OCTEON_SE_SRC)/apps/messaging
include $(dir)/lio-common.mk

dir := $(OCTEON_SE_SRC)/apps/flowcache
include $(dir)/flowcache.mk

IPSEC_ROOT = $(OCTEON_SE_SRC)/apps/ipsec
dir := $(IPSEC_ROOT)
include $(dir)/ipsec.mk

# Alert: Below assignments should not impact the original Makefile.
CFLAGS_LOCAL += -I$(LRO_TSO_INC)

endif #LINUX_IPSEC

ifdef OVS_IPSEC
COMPILE += -DOVS_IPSEC
endif #OVS_IPSEC

DCB_ROOT = $(OCTEON_SE_SRC)/apps/dcb
COMPILE += -I$(DCB_ROOT)
