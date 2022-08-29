


#
#  Makefile fragment
#

#  standard component Makefile header
sp              :=  $(sp).x
dirstack_$(sp)  :=  $(d)
d               :=  $(dir)

ifdef LIQUIDIO_ROOT
COMMON_INC ?= $(LIQUIDIO_ROOT)/include
endif

#  component specification

LIBRARY := $(OBJ_DIR)/libcvmcstest.a

OBJS_$(d) :=	$(OBJ_DIR)/cvmcs-test.o $(OBJ_DIR)/cvmcs-reqresp.o \
		$(OBJ_DIR)/cvmcs-pko-test.o $(OBJ_DIR)/cvmcs-dma.o


$(OBJS_$(d)):  CFLAGS_LOCAL := -I$(d) -I../../core/ -I$(d)/../common -I$(COMMON_INC) -O2 -g -Werror

#  standard component Makefile rules

DEPS_$(d)   :=  $(OBJS_$(d):.o=.d)

LIBS_LIST   :=  $(LIBS_LIST) $(LIBRARY)


-include $(DEPS_$(d))

$(LIBRARY): $(OBJS_$(d))
	$(AR) -r $@ $^

$(OBJ_DIR)/%.o:	$(d)/%.c
	$(COMPILE)

$(OBJ_DIR)/%.o:	$(d)/%.S
	$(COMPILE)

#  standard component Makefile footer

d   :=  $(dirstack_$(sp))
sp  :=  $(basename $(sp))


# $Id:$ 
