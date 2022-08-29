
#
#  Core Driver  Makefile fragment
#

#  standard component Makefile header
sp              :=  $(sp).x
dirstack_$(sp)  :=  $(d)
d               :=  $(dir)

#  component specification

LIBRARY := $(OBJ_DIR)/libcvm-pci-drv.a 

OBJS_$(d)  := 	$(OBJ_DIR)/cvm-pci-pko.o	\
		$(OBJ_DIR)/cvm-drv.o 		 \
		$(OBJ_DIR)/cvm-drv-debug.o	 \
		$(OBJ_DIR)/cvm-drv-reqresp.o \
		$(OBJ_DIR)/cvm-pci-loadstore.o \
		$(OBJ_DIR)/cvm-cn63xx.o \
		$(OBJ_DIR)/cvm-cn68xx.o \
		$(OBJ_DIR)/cvm-cn78xx.o \
		$(OBJ_DIR)/cvm-core-cap.o \
		$(OBJ_DIR)/cvm-pci-dma.o


ifeq ($(findstring CN56XX_PEER_TO_PEER,$(OCTDRVFLAGS)), CN56XX_PEER_TO_PEER)
OBJS_$(d) +=  $(OBJ_DIR)/cn56xx_ep_comm.o 
endif




$(OBJS_$(d)):  CFLAGS_LOCAL := -I$(d) -I$(d)/../../include -I$(d)/../../../host/driver/src/linux/cavium/liquidio -I$(d)/../../../host/driver/src/osi -DIGNORE_DRIVER_TYPES -DUSE_SDK_DMA_API -O2 -g -Werror

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


# $Id$
