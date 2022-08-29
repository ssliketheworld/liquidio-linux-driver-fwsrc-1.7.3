


#
# Makefile for creating symbolic links to Octeon BASE core driver header files
#

check_octeon_sdk:
ifndef OCTEON_ROOT
	@echo "####################################################"
	@echo "              OCTEON_ROOT not defined"
	@echo " Run the env-setup script in SDK root directory"
	@echo " octeon-models.txt list the Octeon Models supported"
	@echo "####################################################"
	@exit 2
endif

#PHONY: links


#links:
#	@for i in *.h; do ln -sf $(LIQUIDIO_ROOT)/modules/driver/src/firmware/core/"$${i}" $(OCTEON_ROOT)/target/include; done

clean: check_octeon_sdk 
	@for i in *.h; do rm -f $(OCTEON_ROOT)/target/include/"$${i}"; done





# $Id$ 
