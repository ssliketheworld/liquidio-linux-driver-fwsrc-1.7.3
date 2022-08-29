#
#    NVMe Makefile fragment
#
ifdef LIQUIDIO_ROOT
BINDIR = $(LIQUIDIO_ROOT)/bin
OCTEON_SE_SRC ?= $(LIQUIDIO_ROOT)/octeon/se
DCB_INC ?= $(LIQUIDIO_ROOT)/octeon/se/apps/dcb
COMMON_INC ?= $(LIQUIDIO_ROOT)/host/driver/src/osi
COMMON_HOST_INC ?= $(LIQUIDIO_ROOT)/host/driver/src/linux/cavium/liquidio
endif

d               :=  $(dir)

#  file specification

LIBRARY := $(OBJ_DIR)/libnvme.a 

OBJS_$(d) =	$(OBJ_DIR)/nvme_main_stub.o

$(OBJS_$(d)):  CFLAGS_LOCAL := -I$(d) -I$(d)/../../include  -I$(DCB_INC)\
		-I../../core/ -I$(PWD) -I$(OCTEON_SE_SRC)/apps/common  -I$(PWD)/nvme/include \
                -I$(COMMON_INC) -I$(COMMON_HOST_INC) -W -Wall -Werror -Wno-unused-parameter -DIGNORE_DRIVER_TYPES
#  Makefile rules

DEPS_$(d)   :=  $(OBJS_$(d):.o=.d)

LIBS_LIST   :=  $(LIBS_LIST) $(LIBRARY)


-include $(DEPS_$(d))

$(LIBRARY): $(OBJS_$(d))
	$(AR) -r $@ $^

$(OBJ_DIR)/%.o:	$(d)/%.c
	$(COMPILE)

$(OBJ_DIR)/%.o:	$(d)/%.S
	$(COMPILE)
