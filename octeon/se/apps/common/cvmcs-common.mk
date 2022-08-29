


#
#  Makefile fragment
#

#  standard component Makefile header
sp              :=  $(sp).x
dirstack_$(sp)  :=  $(d)
d               :=  $(dir)

#  component specification

LIBRARY := $(OBJ_DIR)/libcvmcscommon.a

OBJS_$(d)  :=  $(OBJ_DIR)/cvmcs-common.o
OBJS_$(d)  +=  $(OBJ_DIR)/cvm-app.o

$(OBJS_$(d)): CFLAGS_LOCAL := -I$(d) -I$(d)/../../core/ -I$(LIQUIDIO_ROOT)/octeon/include -I$(LIQUIDIO_ROOT)/host/driver/src/linux/cavium/liquidio -I$(LIQUIDIO_ROOT)/host/driver/src/osi -O2 -g -Werror

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
