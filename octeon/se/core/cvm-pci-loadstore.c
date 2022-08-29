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

#include "cvm-pci-loadstore.h"

extern CVMX_SHARED cvm_oct_dev_t *oct;

static void
cn66xx_setup_pci_load_store(int pcie_port)
{
	int                            i;
	cvmx_sli_mem_access_subidx_t   mem_access;

	oct->pci_mem_subdid_base = 0x80011b0000000000ULL;

	mem_access.u64    = 0;
	mem_access.s.port = pcie_port; /* Port the request is sent to. */
	mem_access.s.esr  = 1;     /* Endian-swap for Reads. */
	mem_access.s.esw  = 1;     /* Endian-swap for Writes. */
    
	for (i = 12; i < 16; i++) {
		cvmx_write_csr(CVMX_PEXP_SLI_MEM_ACCESS_SUBIDX(i), mem_access.u64);
		if( OCTEON_IS_MODEL(OCTEON_CN66XX) ) {
			mem_access.cn66xx.ba += 1;
		}
	}
}





static void
cn68xx_setup_pci_load_store(int pcie_port)
{
	int                            i;
	cvmx_sli_mem_access_subidx_t   mem_access;

	//TODO differentiate if needed for swordfish
	oct->pci_mem_subdid_base = 0x80011b0000000000ULL;

	mem_access.u64    = 0;
	mem_access.s.port = pcie_port; /* Port the request is sent to. */
	mem_access.s.esr  = 1;     /* Endian-swap for Reads. */
	mem_access.s.esw  = 1;     /* Endian-swap for Writes. */
 
	for (i = 12; i < 16; i++) {
		cvmx_write_csr(CVMX_PEXP_SLI_MEM_ACCESS_SUBIDX(i), mem_access.u64);
		mem_access.cn68xx.ba += 1; /* Set each SUBID to extend the addressable range */
	}
}

/* Setup the CN73XX PCI-E Config and internal CSR registers.
 *    The MPS and MRRS values must be tuned to get the best performance. */
static void
setup_cn73xx_pci_regs(int pcie_port)
{
	cvmx_pcieepx_cfg030_t      pcieepx_cfg030;
	int                        mps = 0, mrrs = 3;
	cvmx_dpi_sli_prtx_cfg_t    prt_cfg;
	//cvmx_sli_s2m_portx_ctl_t   s2m;
	int node     = cvmx_get_node_num();

	pcieepx_cfg030.u32 = cvmx_pcie_cfgx_read(pcie_port, CVMX_PCIEEPX_CFG030(pcie_port));
	pcieepx_cfg030.s.mrrs = mrrs;
	pcieepx_cfg030.s.ro_en = 0; /* Enable relaxed ordering. */
	pcieepx_cfg030.s.ns_en = 1; /* Enable no snoop. */
	pcieepx_cfg030.s.ce_en = 1; /* Correctable error reporting enable. */
	pcieepx_cfg030.s.nfe_en = 1; /* Non-fatal error reporting enable. */
	pcieepx_cfg030.s.fe_en = 1; /* Fatal error reporting enable. */
	pcieepx_cfg030.s.ur_en = 1; /* Unsupported request reporting enable. */
	pcieepx_cfg030.s.etf_en = 1; /* Unsupported request reporting enable. */
	cvmx_pcie_cfgx_write(pcie_port, CVMX_PCIEEPX_CFG030(pcie_port), pcieepx_cfg030.u32);
                
	/* Use the config space MPS to program our internal register. */
	mps = pcieepx_cfg030.s.mps;

	prt_cfg.u64 = cvmx_read_csr_node(node, CVMX_DPI_SLI_PRTX_CFG(pcie_port));
	prt_cfg.s.mps = mps;
	prt_cfg.s.mrrs = mrrs;
	prt_cfg.s.molr = 0x40;
	prt_cfg.s.rd_mode = 0;

	cvmx_write_csr_node(node, CVMX_DPI_SLI_PRTX_CFG(pcie_port), prt_cfg.u64);
        
}

/** OCTEON - III models pci load store */
/*  pci-load-store for CN73XX. */
static void
cn73xx_setup_pci_load_store()
{
        int                            i, pcie_port = OCTEON_PCIE_PORT;
        cvmx_sli_mem_access_subidx_t   mem_access;
        int node = cvmx_get_node_num();

	cvmx_spinlock_init(&oct->mem_access_lock);
	
	setup_cn73xx_pci_regs(pcie_port);

        oct->pci_mem_subdid_base = 0x80011b0000000000ULL;

        mem_access.u64    = 0;
        mem_access.s.port = pcie_port; /* Port the request is sent to. */
        mem_access.s.esr  = 1;     /* Endian-swap for Reads. */
        mem_access.s.esw  = 1;     /* Endian-swap for Writes. */

        for (i = 12; i < 16; i++) {
                cvmx_write_csr_node(node, CVMX_PEXP_SLI_MEM_ACCESS_SUBIDX(i), mem_access.u64);
                mem_access.cn73xx.ba += 1; /* Set each SUBID to extend the addressable range */
        }
}


/** OCTEON - III models pci load store */
/*  pci-load-store for CN78XX. */
static void
cn78xx_setup_pci_load_store(int pcie_port)
{
	int                            i;
	cvmx_sli_mem_access_subidx_t   mem_access;
	int node = cvmx_get_node_num();

	oct->pci_mem_subdid_base = 0x80011b0000000000ULL;

	mem_access.u64    = 0;
	mem_access.s.port = pcie_port; /* Port the request is sent to. */
	mem_access.s.esr  = 1;     /* Endian-swap for Reads. */
	mem_access.s.esw  = 1;     /* Endian-swap for Writes. */
 
	for (i = 12; i < 16; i++) {
		cvmx_write_csr_node(node, CVMX_PEXP_SLI_MEM_ACCESS_SUBIDX(i), mem_access.u64);
		mem_access.cn78xx.ba += 1; /* Set each SUBID to extend the addressable range */
	}
}

void
cvm_setup_pci_load_store()
{
	//PEM0 only for 78xx evb for now
	//TODO pcie port number should be a part of config
	if(OCTEON_IS_MODEL(OCTEON_CN73XX))
		cn73xx_setup_pci_load_store(0);
	if(OCTEON_IS_MODEL(OCTEON_CN78XX))
		cn78xx_setup_pci_load_store(0);
	if(OCTEON_IS_MODEL(OCTEON_CN68XX))
		cn68xx_setup_pci_load_store(1);

	if( OCTEON_IS_MODEL(OCTEON_CN66XX))
		cn66xx_setup_pci_load_store(0);

	DBG_PRINT(DBG_FLOW, "[ DRV ] PCI mem subdid base is 0x%lx\n", oct->pci_mem_subdid_base);
}




uint8_t cvm_pci_mem_readb (unsigned long addr)
{
	CVMX_SYNCW;
	DBG_PRINT(DBG_FLOW, "%s: Read 8B from 0x%lx\n", __FUNCTION__, addr);
	return cvmx_read64_uint8(oct->pci_mem_subdid_base + addr);
}



void cvm_pci_mem_writeb (unsigned long addr, uint8_t val8)
{
	CVMX_SYNCW;
	cvmx_write64_uint8(oct->pci_mem_subdid_base + addr, val8);
	CVMX_SYNCW;
}




uint32_t cvm_pci_mem_readl (unsigned long addr)
{
	uint32_t   val32;

	CVMX_SYNCW;
	DBG_PRINT(DBG_FLOW,"\n %s: Going for read from 0x%016lx\n",
	          __FUNCTION__, (oct->pci_mem_subdid_base + addr));
	val32 = cvmx_read64_uint32(oct->pci_mem_subdid_base + addr);
	DBG_PRINT(DBG_FLOW,"%s: read from 0x%016lx: 0x%08x\n",
	       __FUNCTION__, (oct->pci_mem_subdid_base + addr), val32);
	return val32;
}





void cvm_pci_mem_writel (unsigned long addr, uint32_t val32)
{
	CVMX_SYNCW;
	DBG_PRINT(DBG_FLOW,"%s: write : 0x%08x to addr 0x%016lx\n",
	       __FUNCTION__, val32, (oct->pci_mem_subdid_base + addr) );
	cvmx_write64_uint32(oct->pci_mem_subdid_base + addr, val32);
	CVMX_SYNCW;
}





uint64_t cvm_pci_mem_readll (unsigned long addr)
{
	uint64_t   val64;

	CVMX_SYNCW;
	val64 = cvmx_read64_uint64(oct->pci_mem_subdid_base + addr);
	DBG_PRINT(DBG_FLOW,"%s: read from 0x%016lx: 0x%016lx\n",
	       __FUNCTION__, (oct->pci_mem_subdid_base + addr), val64);
	return val64;
}

void cvm_pci_pvf_mem_writell(unsigned long addr, uint64_t val64, uint16_t pvf_no)
{
	int node = cvmx_get_node_num();
	cvmx_sli_mem_access_subidx_t   mem_access;

	mem_access.u64 = cvmx_read_csr_node(node, CVMX_PEXP_SLI_MEM_ACCESS_SUBIDX(12));

	mem_access.cn73xx.pvf = pvf_no;

	mem_access.cn73xx.ba = (addr >> 34);

	addr &= 0x00000003ffffffffULL;
 
	cvmx_spinlock_lock(&oct->mem_access_lock);

	cvmx_write_csr_node(node, CVMX_PEXP_SLI_MEM_ACCESS_SUBIDX(12), mem_access.u64);

	/* Some times the data written into memory address is not seen from the host.
 	 * Read back the SUBIDX register to make sure that the SUBIDX is written
 	 * before the value is written into memory location */
	mem_access.u64 = cvmx_read_csr_node(node, CVMX_PEXP_SLI_MEM_ACCESS_SUBIDX(12));

	cvm_pci_mem_writell(addr, val64);
		
	cvmx_spinlock_unlock(&oct->mem_access_lock);
}

void cvm_pci_mem_writell (unsigned long addr, uint64_t val64)
{
	CVMX_SYNCW;
	DBG_PRINT(DBG_FLOW, "%s: write : 0x%016lx to addr 0x%016lx\n",
	       __FUNCTION__, val64, (oct->pci_mem_subdid_base + addr) );
	cvmx_write64_uint64(oct->pci_mem_subdid_base + addr, val64);
	CVMX_SYNCW;
}




void
cvm_pci_read_mem(unsigned long addr, uint8_t  *localbuf, uint32_t  size)
{
	uint8_t   *buf8 = localbuf;

	while(size) {
		*buf8 = cvm_pci_mem_readb(addr);
		printf("Read %x from %lx into %p\n", *buf8, addr, buf8);
		buf8++;
		addr++; size--;
	}
	CVMX_SYNCW;
}



/* $Id$ */
