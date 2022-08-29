#
#    NVMe Makefile fragment
#
NO_68XX_SUPPORT := 1

ifdef LIQUIDIO_ROOT
BINDIR = $(LIQUIDIO_ROOT)/bin
OCTEON_SE_SRC ?= $(LIQUIDIO_ROOT)/octeon/se
COMMON_INC ?= $(LIQUIDIO_ROOT)/host/driver/src/osi
COMMON_HOST_INC ?= $(LIQUIDIO_ROOT)/host/driver/src/linux/cavium/liquidio
endif

d               :=  $(dir)

#  file specification

LIBRARY := $(OBJ_DIR)/libnvme.a 

ifdef NO_68XX_SUPPORT
OBJS_$(d) =	$(OBJ_DIR)/npl_nvme.o \
		$(OBJ_DIR)/nvme_main.o\
		$(OBJ_DIR)/sal_nvme.o \
		$(OBJ_DIR)/nvme_config.o \
		$(OBJ_DIR)/cn73xx_nqm.o \
		$(OBJ_DIR)/namespaces.o \
		$(OBJ_DIR)/sal_linux_bdev.o
		
$(OBJS_$(d)):  CFLAGS_LOCAL := -I$(d) -I$(d)/../../include  \
		-I../../core/ -I$(PWD) -I$(OCTEON_SE_SRC)/apps/common  -I$(PWD)/nvme/include \
		-I$(COMMON_INC) -I$(COMMON_HOST_INC) -I$(DCB_INC) -W -Wall -Werror -Wno-unused-parameter \
		-DIGNORE_DRIVER_TYPES -DNQM_FETCH_PCI_DMA -g
		#-DNVME_FLASH_BOOT

else
OBJS_$(d) =	$(OBJ_DIR)/npl_nvme.o \
		$(OBJ_DIR)/hil_nvme.o \
		$(OBJ_DIR)/nvme_main.o\
		$(OBJ_DIR)/sal_nvme.o \
		$(OBJ_DIR)/nvme_config.o \
		$(OBJ_DIR)/cn73xx_nqm.o \
		$(OBJ_DIR)/namespaces.o \
		$(OBJ_DIR)/sal_linux_bdev.o

$(OBJS_$(d)):  CFLAGS_LOCAL := -I$(d) -I$(d)/../../include  \
		-I../../core/ -I$(PWD) -I$(OCTEON_SE_SRC)/apps/common  -I$(PWD)/nvme/include \
                -I$(COMMON_INC) -I$(COMMON_HOST_INC) -I$(DCB_INC) -W -Wall -Werror -Wno-unused-parameter -DIGNORE_DRIVER_TYPES \
		-DNQM_FETCH_PCI_DMA -DNVME_68XX_SUPPORT -g
		#-DNVME_FLASH_BOOT
endif

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
