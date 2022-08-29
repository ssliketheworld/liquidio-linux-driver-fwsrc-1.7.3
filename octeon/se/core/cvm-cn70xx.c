/*
 * Author: Cavium, Inc.
 *
 * Copyright (c) 2015 Cavium, Inc. All rights reserved.
 *
 * Contact: support@cavium.com
 *          Please include "LiquidIO" in the subject.
 *
 * This file, which is part of the LiquidIO SDK from Cavium Inc.,
 * contains proprietary and confidential information of Cavium Inc.
 * and in some cases its suppliers. 
 *
 * Any licensed reproduction, distribution, modification, or other use of
 * this file or the confidential information or patented inventions
 * embodied in this file is subject to your license agreement with Cavium
 * Inc. Unless you and Cavium Inc. have agreed otherwise in writing, the
 * applicable license terms "OCTEON SDK License Type 5" can be found under
 * the directory: $LIQUIDIO_ROOT/licenses/
 *
 * All other use and disclosure is prohibited.
 *
 * TO THE MAXIMUM EXTENT PERMITTED BY LAW, THE SOFTWARE IS PROVIDED "AS IS"
 * AND WITH ALL FAULTS AND CAVIUM INC. MAKES NO PROMISES, REPRESENTATIONS
 * OR WARRANTIES, EITHER EXPRESS, IMPLIED, STATUTORY, OR OTHERWISE, WITH
 * RESPECT TO THE SOFTWARE, INCLUDING ITS CONDITION, ITS CONFORMITY TO ANY
 * REPRESENTATION OR DESCRIPTION, OR THE EXISTENCE OF ANY LATENT OR PATENT
 * DEFECTS, AND CAVIUM SPECIFICALLY DISCLAIMS ALL IMPLIED (IF ANY)
 * WARRANTIES OF TITLE, MERCHANTABILITY, NONINFRINGEMENT, FITNESS FOR A
 * PARTICULAR PURPOSE, LACK OF VIRUSES, ACCURACY OR COMPLETENESS, QUIET
 * ENJOYMENT, QUIET POSSESSION OR CORRESPONDENCE TO DESCRIPTION. THE ENTIRE
 * RISK ARISING OUT OF USE OR PERFORMANCE OF THE SOFTWARE LIES WITH YOU.
 */
#include "cvmx.h"
#include "cvmx-helper.h"
#include "cvmx-pip.h"


static inline void
__print_regs_in_range(unsigned long long  start,
                      unsigned long long  end,
                      int                 offset,
                      char               *str)
{
	uint64_t  reg = start;

	while(reg <= end) {
		printf("%s[0x%016lx]:  0x%016lx\n", str, reg,
			 cvmx_read_csr(CVMX_ADD_IO_SEG(reg)));
		reg += offset;
	}
}







void
dump_cn70xx_pem_regs(int pcieport)
{
	unsigned long long  base = 0x00011800C0000000ULL;

	printf("\n ---- Dumping CN70xx PEM registers for PCIe port %d\n", pcieport);

	if(pcieport > 1) {
		printf("Invalid pcie port %d passed to %s\n", pcieport, __FUNCTION__);
		return;
	}

	base += (pcieport * 1000000ULL);

	__print_regs_in_range(base, base + 0x18, 0x8, "PEM");

	__print_regs_in_range(base + 0x20, base + 0x20, 0x8, "PEM");

	__print_regs_in_range(base + 0x38, base + 0x130, 0x8, "PEM");

	__print_regs_in_range(base + 0x408, base + 0x420, 0x8, "PEM");
}



void
cvm_dump_cn70xx_regs(void)
{
	dump_cn70xx_pem_regs(0);
}





