#
#  Vswitch Makefile fragment
#
#  copied from cvmx.mk

#ifdef OCTEON_TARGET
# ifeq (${OCTEON_TARGET},linux_o32)
#  ${error Only targets cvmx_64,cvmx_32,linux_64,linux_n32 are supported}
# endif
#endif

sp              :=  $(sp).x
dirstack_$(sp)  :=  $(d)
d               :=  $(dir)

#  component specification

LIBRARY := $(OBJ_DIR)/liblrotso.a

TSO_OBJS := $(OBJ_DIR)/cvmcs-tso.o 
#		$(OBJ_DIR)/cvmcs-lro.o

OBJS_$(d)  :=  $(TSO_OBJS)

TSO_CFLAGS_LOCAL := -I$(d)
TSO_CFLAGS_LOCAL += -O2 
TSO_CFLAGS_LOCAL += -g 

# kbuild compatibility
ifdef OCTEON_TARGET
TSO_CFLAGS_LOCAL += -W 
TSO_CFLAGS_LOCAL += -Wall 
endif


TSO_CFLAGS_LOCAL += -Wno-unused-parameter 

TSO_CFLAGS_LOCAL += -DVNIC -I../../core/ -I./ -I$(OCTEON_SE_SRC)/apps/common \
                -I$(COMMON_INC) -I$(COMMON_HOST_INC) -I$(IPSEC_INC) -DIGNORE_DRIVER_TYPES -I$(COMMON_HOST_OSI_INC) -W -Wall  -Wno-unused-parameter
TSO_CFLAGS_GLOBAL += -DOCTEON_MODEL=$(OCTEON_MODEL)

TSO_CFLAGS_LOCAL += $(TSO_CFLAGS_GLOBAL)

#Added to avoid compilation error
TSO_CFLAGS_LOCAL += -I $(LIQUIDIO_ROOT)/octeon/se/apps/dcb

$(OBJS_$(d)):  CFLAGS_LOCAL := $(TSO_CFLAGS_LOCAL) 


#  standard component Makefile rules

DEPS_$(d)   :=  $(OBJS_$(d):.o=.d)

LIBS_LIST   :=  $(LIBS_LIST) $(LIBRARY)

-include $(DEPS_$(d))

$(LIBRARY): $(OBJS_$(d))
	$(AR) -cr $@ $^ 

$(OBJ_DIR)/%.o:	$(d)/%.c
	$(COMPILE)

$(OBJ_DIR)/%.o:	$(d)/%.S
	$(COMPILE)


#  standard component Makefile footer

d   :=  $(dirstack_$(sp))
sp  :=  $(basename $(sp))
