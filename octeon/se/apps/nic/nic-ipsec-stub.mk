#
#    IPsec Makefile fragment
#
ifdef LIQUIDIO_ROOT
BINDIR = $(LIQUIDIO_ROOT)/bin
OCTEON_SE_SRC ?= $(LIQUIDIO_ROOT)/octeon/se
COMMON_INC ?= $(LIQUIDIO_ROOT)/host/driver/src/osi
COMMON_HOST_INC ?= $(LIQUIDIO_ROOT)/host/driver/src/linux/cavium/liquidio
endif

d               :=  $(dir)

#  file specification

LIBRARY := $(OBJ_DIR)/libipsec.a 

OBJS_$(d) =	$(OBJ_DIR)/ipsec_stub.o

DEPS_$(d)   :=  $(OBJS_$(d):.o=.d)

LIBS_LIST   :=  $(LIBS_LIST) $(LIBRARY)


-include $(DEPS_$(d))

$(LIBRARY): $(OBJS_$(d))
	$(AR) -r $@ $^

$(OBJ_DIR)/%.o:	$(d)/%.c
	$(COMPILE)

$(OBJ_DIR)/%.o:	$(d)/%.S
	$(COMPILE)
