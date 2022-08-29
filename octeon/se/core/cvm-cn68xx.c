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
#include "cvmx-helper-jtag.h"


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




static inline void
__print_config_regs_in_range(uint32_t   start,
                             uint32_t   end,
                             int        offset,
                             int        pcieport)
{
	cvmx_pemx_cfg_rd_t pemx_cfg_rd;
	uint32_t           reg = start;

	while (reg <= end) {
		pemx_cfg_rd.u64 = 0;
		pemx_cfg_rd.s.addr = reg;
		cvmx_write_csr(CVMX_PEMX_CFG_RD(pcieport), pemx_cfg_rd.u64);
		pemx_cfg_rd.u64 = cvmx_read_csr(CVMX_PEMX_CFG_RD(pcieport));
		printf("Port%d Config[0x%x]: 0x%08x\n",pcieport, reg,
			  pemx_cfg_rd.s.data);
		reg += offset;
	}
}



static inline void
__print_dbgselect_data(uint32_t dbgsel)
{
	volatile uint64_t   dbg;

	cvmx_write_csr(CVMX_PEXP_SLI_DBG_SELECT, dbgsel);
	CVMX_SYNCWS;
	dbg = cvmx_read_csr(CVMX_PEXP_SLI_DBG_SELECT);
	CVMX_SYNCWS;
	dbg = cvmx_read_csr(CVMX_PEXP_SLI_DBG_DATA);
	printf("DbgSelect: %x  DbgValue: 0x%08x\n", dbgsel, (uint32_t)(dbg & 0xffff));
}





static inline void
__print_dbgselect_in_range(uint32_t   start,
                           uint32_t   end,
                           int        offset)
{
	uint32_t  dbgsel = start;
	while(dbgsel <= end) {
		__print_dbgselect_data(dbgsel);
		dbgsel += offset;
	}
}




void
dump_sli_debug_data(void)
{

	uint64_t  csr64;

	csr64 = cvmx_read_csr(CVMX_ILK_TXX_CFG0(0));
	csr64 &= ~(0xFF);
	cvmx_write_csr(CVMX_ILK_TXX_CFG0(0), csr64);

	csr64 = cvmx_read_csr(CVMX_ILK_TXX_CFG0(1));
	csr64 &= ~(0xFF);
	cvmx_write_csr(CVMX_ILK_TXX_CFG0(1), csr64);

	csr64 = cvmx_read_csr(CVMX_ILK_RXX_CFG0(0));
	csr64 &= ~(0xFF);
	cvmx_write_csr(CVMX_ILK_RXX_CFG0(0), csr64);

	csr64 = cvmx_read_csr(CVMX_ILK_RXX_CFG0(1));
	csr64 &= ~(0xFF);
	cvmx_write_csr(CVMX_ILK_RXX_CFG0(1), csr64);

	csr64 = cvmx_read_csr(CVMX_ILK_GBL_CFG);
	csr64 &= ~(2);
	cvmx_write_csr(CVMX_ILK_GBL_CFG, csr64);

	cvmx_wait(1000);


	printf("\n ---- Dumping data for CN68xx SLI DebugSelect\n");

	__print_dbgselect_in_range(0xdf000000, 0xdf000005, 1);

	__print_dbgselect_in_range(0xdf100000, 0xdf10001d, 1);

	__print_dbgselect_in_range(0x4f000000, 0x4f000053, 1);

	__print_dbgselect_in_range(0xA0000011, 0xA0000013, 1);

	__print_dbgselect_in_range(0x5000004b, 0x5000004b, 1);

	__print_dbgselect_in_range(0xdf800001, 0xdf800007, 1);

	__print_dbgselect_in_range(0xdf800010, 0xdf800010, 1);

}








void
dump_cn68xx_pem_regs(int pcieport)
{
	unsigned long long  base = 0x00011800C0000000ULL;

	printf("\n ---- Dumping CN68xx PEM registers for PCIe port %d\n", pcieport);

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
dump_cn68xx_fpa_regs(void)
{
	unsigned long long  base = 0x0001180028000000ULL;

	printf("\n ---- Dumping CN68xx FPA registers \n");

	__print_regs_in_range(base, base + 0xD8, 0x8, "FPA");

	__print_regs_in_range(base + 0xE8, base + 0x180, 0x8, "FPA");

	__print_regs_in_range(base + 0x240, base + 0x298, 0x8, "FPA");

	__print_regs_in_range(base + 0x358, base + 0x398, 0x8, "FPA");

	__print_regs_in_range(base + 0x458, base + 0x468, 0x8, "FPA");

}





void
dump_cn68xx_pip_regs(void)
{
	unsigned long long  base = 0x00011800A0000000ULL;

	printf("\n ---- Dumping CN68xx PIP registers \n");

	__print_regs_in_range(base, base + 0x40, 0x8, "PIP");

	__print_regs_in_range(base + 0x60, base + 0x98, 0x8, "PIP");

	__print_regs_in_range(base + 0xB0, base + 0xB0, 0x8, "PIP");

	__print_regs_in_range(base + 0x100, base + 0x138, 0x8, "PIP");

	__print_regs_in_range(base + 0x180, base + 0x5F8, 0x8, "PIP");

	__print_regs_in_range(base + 0x1800, base + 0x19F8, 0x8, "PIP");

	__print_regs_in_range(base + 0x4000, base + 0x47F8, 0x8, "PIP");

	__print_regs_in_range(base + 0x8000, base + 0x81F8, 0x8, "PIP");

	__print_regs_in_range(base + 0x20000, base + 0x207E0, 0x20, "PIP");

	__print_regs_in_range(base + 0x20008, base + 0x207E8, 0x20, "PIP");

	__print_regs_in_range(base + 0x20010, base + 0x207F0, 0x20, "PIP");

#if 0
	__print_regs_in_range(base + 0x40000, base + 0x41F80, 0x80, "PIP");

	__print_regs_in_range(base + 0x40008, base + 0x41F88, 0x80, "PIP");

	__print_regs_in_range(base + 0x40010, base + 0x41F90, 0x80, "PIP");

	__print_regs_in_range(base + 0x40018, base + 0x41F98, 0x80, "PIP");

	__print_regs_in_range(base + 0x40020, base + 0x41FA0, 0x80, "PIP");

	__print_regs_in_range(base + 0x40028, base + 0x41FA8, 0x80, "PIP");

	__print_regs_in_range(base + 0x40030, base + 0x41FB0, 0x80, "PIP");

	__print_regs_in_range(base + 0x40038, base + 0x41FB8, 0x80, "PIP");

	__print_regs_in_range(base + 0x40040, base + 0x41FC0, 0x80, "PIP");

	__print_regs_in_range(base + 0x40048, base + 0x41FC8, 0x80, "PIP");

	__print_regs_in_range(base + 0x40050, base + 0x41FD0, 0x80, "PIP");

	__print_regs_in_range(base + 0x40058, base + 0x41FD8, 0x80, "PIP");
#endif


}







void
dump_cn68xx_ipd_regs(void)
{
	unsigned long long  base = 0x00014F0000000000ULL;

	printf("\n ---- Dumping CN68xx IPD registers \n");

	__print_regs_in_range(base, base + 0x20, 0x8, "IPD");

	__print_regs_in_range(base + 0x148, base + 0x1B0, 0x8, "IPD");

	__print_regs_in_range(base + 0x2E0, base + 0x320, 0x8, "IPD");

	__print_regs_in_range(base + 0x330, base + 0x338, 0x8, "IPD");

	__print_regs_in_range(base + 0x3F0, base + 0x3F0, 0x8, "IPD");

	__print_regs_in_range(base + 0x780, base + 0x7A8, 0x8, "IPD");

	__print_regs_in_range(base + 0x7F8, base + 0x880, 0x8, "IPD");

	printf("Only first 8 qos counters are printed below\n");
	__print_regs_in_range(base + 0x888, base + 0x8C0, 0x8, "IPD");

	__print_regs_in_range(base + 0x2000, base + 0x31F8, 0x8, "IPD");

	__print_regs_in_range(base + 0x4100, base + 0x4100, 0x8, "IPD");

	__print_regs_in_range(base + 0x4200, base + 0x4200, 0x8, "IPD");

	__print_regs_in_range(base + 0x4300, base + 0x4300, 0x8, "IPD");

	__print_regs_in_range(base + 0x4400, base + 0x4410, 0x8, "IPD");
}





void
dump_cn68xx_config_regs(int pcieport)
{

	printf("\n ---- Dumping CN68xx PCIe port %d config registers\n", pcieport);

	__print_config_regs_in_range(0, 0x34, 4, pcieport);

	__print_config_regs_in_range(0x3c, 0x44, 4, pcieport);

	__print_config_regs_in_range(0x50, 0x5c, 4, pcieport);

	__print_config_regs_in_range(0x70, 0x88, 4, pcieport);

	__print_config_regs_in_range(0x94, 0xA8, 4, pcieport);

	__print_config_regs_in_range(0x100, 0x128, 4, pcieport);

	__print_config_regs_in_range(0x700, 0x728, 4, pcieport);

	__print_config_regs_in_range(0x72C, 0x750, 4, pcieport);

	__print_config_regs_in_range(0x7A8, 0x7B0, 4, pcieport);

	__print_config_regs_in_range(0x80C, 0x814, 4, pcieport);

}






void
__dump_cn68xx_regs(void)
{
	int i;

	printf("\n\n ---------Begin CN68xx regs dump -----------\n");

	dump_cn68xx_pem_regs(0);
	dump_cn68xx_fpa_regs();
	dump_cn68xx_ipd_regs();
	dump_cn68xx_pip_regs();
	dump_sli_debug_data();
	dump_cn68xx_config_regs(0);



	printf("SCRATCH: 0x%016lx\n", cvmx_read_csr(CVMX_PEXP_SLI_SCRATCH_1));
  
	for(i = 0; i < 4; i++) {

		cvmx_pip_port_status_t  status;
		int interface, index, pknd, ipd_port;

		ipd_port = 0x100 + i;

		cvmx_pip_get_port_status (ipd_port, 0, &status);
	
		printf("\nPIP Stats for port %x\n", ipd_port);
		printf("	Packets: %lu\n", (uint64_t)status.packets);
		printf("	Raw Packets: %lu\n",(uint64_t) status.pci_raw_packets);
		printf("	Dropped Packets: %lu\n",(uint64_t) status.dropped_packets);

		interface = cvmx_helper_get_interface_num(ipd_port);
		index = cvmx_helper_get_interface_index_num(ipd_port);
		pknd = cvmx_helper_get_pknd(interface, index);

		printf("Pkind %d config:\n", pknd);
		printf("	PIP_PRT_CFG[%d]: 0x%016lx\n",
			 pknd, cvmx_read_csr(CVMX_PIP_PRT_CFGX(pknd)));
		printf("	PIP_PRT_TAG[%d]: 0x%016lx\n",
			 pknd, cvmx_read_csr(CVMX_PIP_PRT_TAGX(pknd)));
		printf("	PIP_PRT_CFGB[%d]: 0x%016lx\n",
			 pknd, cvmx_read_csr(CVMX_PIP_PRT_CFGBX(pknd)));
	}

	printf("SLI_CTL_PORT0: 0x%016lx\n",
		 cvmx_read_csr(CVMX_PEXP_SLI_CTL_PORTX(0)));
	printf("SLI_CTL_PORT1: 0x%016lx\n",
		 cvmx_read_csr(CVMX_PEXP_SLI_CTL_PORTX(1)));
	printf("SLI_CTL_STATUS: 0x%016lx\n",
		 cvmx_read_csr(CVMX_PEXP_SLI_CTL_STATUS));

	printf("SLI_DATA_OUT_CNT: 0x%016lx\n",
		 cvmx_read_csr(CVMX_PEXP_SLI_DATA_OUT_CNT));

	printf("SLI_INT_ENB_CIU: 0x%016lx\n",
		 cvmx_read_csr(CVMX_PEXP_SLI_INT_ENB_CIU));

	printf("SLI_INT_ENB_PORT0: 0x%016lx\n",
		 cvmx_read_csr(CVMX_PEXP_SLI_INT_ENB_PORTX(0)));

	printf("SLI_INT_SUM: 0x%016lx\n",
		 cvmx_read_csr(CVMX_PEXP_SLI_INT_SUM));

	printf("SLI_PKT0_CNTS: 0x%016lx\n",
		 cvmx_read_csr(CVMX_PEXP_SLI_PKTX_CNTS(0)));

	printf("SLI_PKT1_CNTS: 0x%016lx\n",
		 cvmx_read_csr(CVMX_PEXP_SLI_PKTX_CNTS(1)));

	printf("SLI_PKT2_CNTS: 0x%016lx\n",
		 cvmx_read_csr(CVMX_PEXP_SLI_PKTX_CNTS(2)));

	printf("SLI_PKT3_CNTS: 0x%016lx\n",
		 cvmx_read_csr(CVMX_PEXP_SLI_PKTX_CNTS(3)));

	printf("SLI_PKT0_INSTR_BADDR: 0x%016lx\n",
		 cvmx_read_csr(CVMX_PEXP_SLI_PKTX_INSTR_BADDR(0)));

	printf("SLI_PKT1_INSTR_BADDR: 0x%016lx\n",
		 cvmx_read_csr(CVMX_PEXP_SLI_PKTX_INSTR_BADDR(1)));

	printf("SLI_PKT2_INSTR_BADDR: 0x%016lx\n",
		 cvmx_read_csr(CVMX_PEXP_SLI_PKTX_INSTR_BADDR(2)));

	printf("SLI_PKT3_INSTR_BADDR: 0x%016lx\n",
		 cvmx_read_csr(CVMX_PEXP_SLI_PKTX_INSTR_BADDR(3)));

	printf("SLI_PKT0_INSTR_BAOFF_DBELL: 0x%016lx\n",
		 cvmx_read_csr(CVMX_PEXP_SLI_PKTX_INSTR_BAOFF_DBELL(0)));

	printf("SLI_PKT1_INSTR_BAOFF_DBELL: 0x%016lx\n",
		 cvmx_read_csr(CVMX_PEXP_SLI_PKTX_INSTR_BAOFF_DBELL(1)));

	printf("SLI_PKT2_INSTR_BAOFF_DBELL: 0x%016lx\n",
		 cvmx_read_csr(CVMX_PEXP_SLI_PKTX_INSTR_BAOFF_DBELL(2)));

	printf("SLI_PKT3_INSTR_BAOFF_DBELL: 0x%016lx\n",
		 cvmx_read_csr(CVMX_PEXP_SLI_PKTX_INSTR_BAOFF_DBELL(3)));

	printf("SLI_PKT0_INSTR_FIFO_RSIZE: 0x%016lx\n",
		 cvmx_read_csr(CVMX_PEXP_SLI_PKTX_INSTR_FIFO_RSIZE(0)));

	printf("SLI_PKT1_INSTR_FIFO_RSIZE: 0x%016lx\n",
		 cvmx_read_csr(CVMX_PEXP_SLI_PKTX_INSTR_FIFO_RSIZE(1)));

	printf("SLI_PKT2_INSTR_FIFO_RSIZE: 0x%016lx\n",
		 cvmx_read_csr(CVMX_PEXP_SLI_PKTX_INSTR_FIFO_RSIZE(2)));

	printf("SLI_PKT3_INSTR_FIFO_RSIZE: 0x%016lx\n",
		 cvmx_read_csr(CVMX_PEXP_SLI_PKTX_INSTR_FIFO_RSIZE(3)));


	printf("SLI_PKT0_INSTR_HEADER: 0x%016lx\n",
		 cvmx_read_csr(CVMX_PEXP_SLI_PKTX_INSTR_HEADER(0)));

	printf("SLI_PKT1_INSTR_HEADER: 0x%016lx\n",
		 cvmx_read_csr(CVMX_PEXP_SLI_PKTX_INSTR_HEADER(1)));

	printf("SLI_PKT2_INSTR_HEADER: 0x%016lx\n",
		 cvmx_read_csr(CVMX_PEXP_SLI_PKTX_INSTR_HEADER(2)));

	printf("SLI_PKT3_INSTR_HEADER: 0x%016lx\n",
		 cvmx_read_csr(CVMX_PEXP_SLI_PKTX_INSTR_HEADER(3)));


	printf("SLI_PKT0_OUT_SIZE: 0x%016lx\n",
		 cvmx_read_csr(CVMX_PEXP_SLI_PKTX_OUT_SIZE(0)));

	printf("SLI_PKT1_OUT_SIZE: 0x%016lx\n",
		 cvmx_read_csr(CVMX_PEXP_SLI_PKTX_OUT_SIZE(1)));

	printf("SLI_PKT2_OUT_SIZE: 0x%016lx\n",
		 cvmx_read_csr(CVMX_PEXP_SLI_PKTX_OUT_SIZE(2)));

	printf("SLI_PKT3_OUT_SIZE: 0x%016lx\n",
		 cvmx_read_csr(CVMX_PEXP_SLI_PKTX_OUT_SIZE(3)));


	printf("SLI_PKT0_SLIST_BADDR: 0x%016lx\n",
		 cvmx_read_csr(CVMX_PEXP_SLI_PKTX_SLIST_BADDR(0)));

	printf("SLI_PKT1_SLIST_BADDR: 0x%016lx\n",
		 cvmx_read_csr(CVMX_PEXP_SLI_PKTX_SLIST_BADDR(1)));

	printf("SLI_PKT2_SLIST_BADDR: 0x%016lx\n",
		 cvmx_read_csr(CVMX_PEXP_SLI_PKTX_SLIST_BADDR(2)));

	printf("SLI_PKT3_SLIST_BADDR: 0x%016lx\n",
		 cvmx_read_csr(CVMX_PEXP_SLI_PKTX_SLIST_BADDR(3)));


	printf("SLI_PKT0_SLIST_BAOFF_DBELL: 0x%016lx\n",
		 cvmx_read_csr(CVMX_PEXP_SLI_PKTX_SLIST_BAOFF_DBELL(0)));

	printf("SLI_PKT1_SLIST_BAOFF_DBELL: 0x%016lx\n",
		 cvmx_read_csr(CVMX_PEXP_SLI_PKTX_SLIST_BAOFF_DBELL(1)));

	printf("SLI_PKT2_SLIST_BAOFF_DBELL: 0x%016lx\n",
		 cvmx_read_csr(CVMX_PEXP_SLI_PKTX_SLIST_BAOFF_DBELL(2)));

	printf("SLI_PKT3_SLIST_BAOFF_DBELL: 0x%016lx\n",
		 cvmx_read_csr(CVMX_PEXP_SLI_PKTX_SLIST_BAOFF_DBELL(3)));



	printf("SLI_PKT0_SLIST_FIFO_RSIZE: 0x%016lx\n",
		 cvmx_read_csr(CVMX_PEXP_SLI_PKTX_SLIST_FIFO_RSIZE(0)));

	printf("SLI_PKT1_SLIST_FIFO_RSIZE: 0x%016lx\n",
		 cvmx_read_csr(CVMX_PEXP_SLI_PKTX_SLIST_FIFO_RSIZE(1)));

	printf("SLI_PKT2_SLIST_FIFO_RSIZE: 0x%016lx\n",
		 cvmx_read_csr(CVMX_PEXP_SLI_PKTX_SLIST_FIFO_RSIZE(2)));

	printf("SLI_PKT3_SLIST_FIFO_RSIZE: 0x%016lx\n",
		 cvmx_read_csr(CVMX_PEXP_SLI_PKTX_SLIST_FIFO_RSIZE(3)));


	printf("SLI_PKT_CNT_INT: 0x%016lx\n",
		 cvmx_read_csr(CVMX_PEXP_SLI_PKT_CNT_INT));

	printf("SLI_PKT_CNT_INT_ENB: 0x%016lx\n",
		 cvmx_read_csr(CVMX_PEXP_SLI_PKT_CNT_INT_ENB));

	printf("SLI_PKT_CTL: 0x%016lx\n",
		 cvmx_read_csr(CVMX_PEXP_SLI_PKT_CTL));

	printf("SLI_PKT_DATA_OUT_ES: 0x%016lx\n",
		 cvmx_read_csr(CVMX_PEXP_SLI_PKT_DATA_OUT_ES));

	printf("SLI_PKT_DATA_OUT_NS: 0x%016lx\n",
		 cvmx_read_csr(CVMX_PEXP_SLI_PKT_DATA_OUT_NS));

	printf("SLI_PKT_DATA_OUT_ROR: 0x%016lx\n",
		 cvmx_read_csr(CVMX_PEXP_SLI_PKT_DATA_OUT_ROR));

	printf("SLI_PKT_DPADDR: 0x%016lx\n",
		 cvmx_read_csr(CVMX_PEXP_SLI_PKT_DPADDR));


	printf("SLI_PKT_IN_DONE0_CNTS: 0x%016lx\n",
		 cvmx_read_csr(CVMX_PEXP_SLI_PKT_IN_DONEX_CNTS(0)));

	printf("SLI_PKT_IN_DONE1_CNTS: 0x%016lx\n",
		 cvmx_read_csr(CVMX_PEXP_SLI_PKT_IN_DONEX_CNTS(1)));

	printf("SLI_PKT_IN_DONE2_CNTS: 0x%016lx\n",
		 cvmx_read_csr(CVMX_PEXP_SLI_PKT_IN_DONEX_CNTS(2)));

	printf("SLI_PKT_IN_DONE3_CNTS: 0x%016lx\n",
		 cvmx_read_csr(CVMX_PEXP_SLI_PKT_IN_DONEX_CNTS(3)));


	printf("SLI_PKT_IN_INSTR_COUNTS: 0x%016lx\n",
		 cvmx_read_csr(CVMX_PEXP_SLI_PKT_IN_INSTR_COUNTS));

	printf("SLI_PKT_IN_PCIE_PORT: 0x%016lx\n",
		 cvmx_read_csr(CVMX_PEXP_SLI_PKT_IN_PCIE_PORT));

	printf("SLI_PKT_INPUT_CONTROL: 0x%016lx\n",
		 cvmx_read_csr(CVMX_PEXP_SLI_PKT_INPUT_CONTROL));

	printf("SLI_PKT_INSTR_ENB: 0x%016lx\n",
		 cvmx_read_csr(CVMX_PEXP_SLI_PKT_INSTR_ENB));

	printf("SLI_PKT_INSTR_RD_SIZE: 0x%016lx\n",
		 cvmx_read_csr(CVMX_PEXP_SLI_PKT_INSTR_RD_SIZE));

	printf("SLI_PKT_INSTR_SIZE: 0x%016lx\n",
		 cvmx_read_csr(CVMX_PEXP_SLI_PKT_INSTR_SIZE));

	printf("SLI_PKT_INT_LEVELS: 0x%016lx\n",
		 cvmx_read_csr(CVMX_PEXP_SLI_PKT_INT_LEVELS));

	printf("SLI_PKT_IPTR: 0x%016lx\n",
		 cvmx_read_csr(CVMX_PEXP_SLI_PKT_IPTR));

	printf("SLI_PKT_OUT_BMODE: 0x%016lx\n",
		 cvmx_read_csr(CVMX_PEXP_SLI_PKT_OUT_BMODE));

	printf("SLI_PKT_OUT_BP_EN: 0x%016lx\n",
		 cvmx_read_csr(CVMX_PEXP_SLI_PKT_OUT_BP_EN));

	printf("SLI_PKT_OUT_ENB: 0x%016lx\n",
		 cvmx_read_csr(CVMX_PEXP_SLI_PKT_OUT_ENB));

	printf("SLI_PKT_OUTPUT_WMARK: 0x%016lx\n",
		 cvmx_read_csr(CVMX_PEXP_SLI_PKT_OUTPUT_WMARK));

	printf("SLI_PKT_PCIE_PORT: 0x%016lx\n",
		 cvmx_read_csr(CVMX_PEXP_SLI_PKT_PCIE_PORT));

	printf("SLI_PKT_PORT_IN_RST: 0x%016lx\n",
		 cvmx_read_csr(CVMX_PEXP_SLI_PKT_PORT_IN_RST));

	printf("SLI_PKT_SLIST_ES: 0x%016lx\n",
		 cvmx_read_csr(CVMX_PEXP_SLI_PKT_SLIST_ES));

	printf("SLI_PKT_SLIST_NS: 0x%016lx\n",
		 cvmx_read_csr(CVMX_PEXP_SLI_PKT_SLIST_NS));

	printf("SLI_PKT_SLIST_ROR: 0x%016lx\n",
		 cvmx_read_csr(CVMX_PEXP_SLI_PKT_SLIST_ROR));

	printf("SLI_PKT_TIME_INT: 0x%016lx\n",
		 cvmx_read_csr(CVMX_PEXP_SLI_PKT_TIME_INT));

	printf("SLI_PKT_TIME_INT_ENB: 0x%016lx\n",
		 cvmx_read_csr(CVMX_PEXP_SLI_PKT_TIME_INT_ENB));

	printf("SLI_PORT0_PKIND: 0x%016lx\n",
		 cvmx_read_csr(CVMX_PEXP_SLI_PORTX_PKIND(0)));

	printf("SLI_PORT1_PKIND: 0x%016lx\n",
		 cvmx_read_csr(CVMX_PEXP_SLI_PORTX_PKIND(1)));

	printf("SLI_PORT2_PKIND: 0x%016lx\n",
		 cvmx_read_csr(CVMX_PEXP_SLI_PORTX_PKIND(2)));

	printf("SLI_PORT3_PKIND: 0x%016lx\n",
		 cvmx_read_csr(CVMX_PEXP_SLI_PORTX_PKIND(3)));

	printf("SLI_TX_PIPE: 0x%016lx\n",
		 cvmx_read_csr(CVMX_PEXP_SLI_TX_PIPE));


	printf("\n\n -------------------------------------------\n");
}






/**
 * CN68XX pass 1.x QLM tweak. This function tweaks the JTAG setting for a QLMs
 * to run better at 5Ghz. It will make no changes to QLMs running at other
 * speeds.
 */
void __cn68xx_qlm_gen2_fix(void)
{
	int qlm;

	/* Initialize the internal JTAG */
	cvmx_helper_qlm_jtag_init();


	/* Loop through the 5 QLMs on CN68XX */
	for (qlm = 0; qlm < 5; qlm++)  {

		cvmx_mio_qlmx_cfg_t qlm_cfg;

		/* Read the QLM speed */
		qlm_cfg.u64 = cvmx_read_csr(CVMX_MIO_QLMX_CFG(qlm));


		/* If QLM is at 5Ghz */
		if ( (qlm_cfg.s.qlm_spd == 0) || (qlm_cfg.s.qlm_spd == 6)
		     ||(qlm_cfg.s.qlm_spd == 11) )  {
			int lane;

			/* Update all four lanes */
			for (lane = 0; lane < 4; lane++)  {

				/* We're changing bits 15:8, so skip 8 */
				cvmx_helper_qlm_jtag_shift_zeros(qlm, 8);

				/* We want 0x1b, so default 0x3c xor 0x27 */
				cvmx_helper_qlm_jtag_shift(qlm, 8, 0x27);

				/* Skip the rest of the chain */
				cvmx_helper_qlm_jtag_shift_zeros(qlm, 304 - 16);

			}

			/* Write our JTAG updates */
			cvmx_helper_qlm_jtag_update(qlm);
		}
	}
}




