
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
	int node = cvmx_get_node_num();
	while(reg <= end) {
		printf("%s[0x%016lx]:  0x%016lx\n", str, reg,
			 cvmx_read_csr_node(node, CVMX_ADD_IO_SEG(reg)));
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
	int 		   node = cvmx_get_node_num();

	while (reg <= end) {
		pemx_cfg_rd.u64 = 0;
		pemx_cfg_rd.s.addr = reg;
		cvmx_write_csr_node(node, CVMX_PEMX_CFG_RD(pcieport), pemx_cfg_rd.u64);
		pemx_cfg_rd.u64 = cvmx_read_csr_node(node, CVMX_PEMX_CFG_RD(pcieport));
		printf("Port%d Config[0x%x]: 0x%08x\n",pcieport, reg,
			  pemx_cfg_rd.s.data);
		reg += offset;
	}
}



void
dump_cn78xx_sli_debug_data(void)
{

	uint64_t  csr64;
	int node = cvmx_get_node_num();

	csr64 = cvmx_read_csr_node(node, CVMX_ILK_TXX_CFG0(0));
	csr64 &= ~(0xFF);
	cvmx_write_csr_node(node, CVMX_ILK_TXX_CFG0(0), csr64);

	csr64 = cvmx_read_csr_node(node, CVMX_ILK_TXX_CFG0(1));
	csr64 &= ~(0xFF);
	cvmx_write_csr_node(node, CVMX_ILK_TXX_CFG0(1), csr64);

	csr64 = cvmx_read_csr_node(node, CVMX_ILK_RXX_CFG0(0));
	csr64 &= ~(0xFF);
	cvmx_write_csr_node(node, CVMX_ILK_RXX_CFG0(0), csr64);

	csr64 = cvmx_read_csr_node(node, CVMX_ILK_RXX_CFG0(1));
	csr64 &= ~(0xFF);
	cvmx_write_csr_node(node, CVMX_ILK_RXX_CFG0(1), csr64);

	csr64 = cvmx_read_csr_node(node, CVMX_ILK_GBL_CFG);
	csr64 &= ~(2);
	cvmx_write_csr_node(node, CVMX_ILK_GBL_CFG, csr64);

	cvmx_wait(1000);

}








void
dump_cn78xx_pem_regs(int pcieport)
{
	unsigned long long  base = 0x00011800C0000000ULL;

	printf("\n ---- Dumping CN78xx PEM registers for PCIe port %d\n", pcieport);
	/*In 78xx maximum number of pems are 4*/
	if(pcieport > 3) {
		printf("Invalid pcie port %d passed to %s\n", pcieport, __FUNCTION__);
		return;
	}

        /*To form corresponding pcie port addresses*/
	base += (pcieport * 1000000ULL);

        /*print PEMx_CTL_STATUS 1 and 2 registers */
        __print_regs_in_range(base, base + 0x08, 0x8, "PEM");

        /*print PEMx_DBG_INFO register */
        __print_regs_in_range(base + 0xD0, base + 0xD0, 0x8, "PEM");

        /*print PEMx_BIST_STATUS register */
        __print_regs_in_range(base + 0x440, base + 0x440, 0x8, "PEM");

        /*print PEMx_DIAG_STATUS register */
        __print_regs_in_range(base + 0x20, base + 0x20, 0x8, "PEM");

        /*print P2P(0..3) and P2N(0..2) registers */
        __print_regs_in_range(base + 0x38, base + 0x98, 0x8, "PEM");
 
        /*print PEMx_BAR1_INDEX(0..15) registers*/
        __print_regs_in_range(base + 0x100, base + 0x178, 0x8, "PEM");

        /*print PEMx_BAR_CTL and PEMx_BAR2_MASK registers*/
        __print_regs_in_range(base + 0xA8, base + 0xB0, 0x8, "PEM");
   
        /*print PEMx_INT_SUM register*/
        __print_regs_in_range(base + 0x428, base + 0x428, 0x8, "PEM");
}

void
dump_cn78xx_fpa_regs(void)
{
	unsigned long long  base = 0x0001280000000000ULL;

	printf("\n ---- Dumping CN78xx FPA registers \n");

        /*print FPA_SFT_RST register*/
	__print_regs_in_range(base, base, 0x8, "FPA");
 
        /*print FPA_ERR_INT and FPA_GEN_CFG registers*/
	__print_regs_in_range(base + 0x40, base + 0x50, 0x10, "FPA");

        /*print FPA_ECC_CTL and FPA_ECC_INT registers*/
	__print_regs_in_range(base + 0x58, base + 0x68, 0x10, "FPA");

        /*print FPA_BIST_STATUS and FPA_CLK_COUNT registers*/
	__print_regs_in_range(base + 0xE8, base + 0xF0, 0x8, "FPA");

        /*print FPA_RED_DELAY register*/
	__print_regs_in_range(base + 0x100, base + 0x100, 0x8, "FPA");

        /*print FPA_ADDR_RANGE_ERROR register*/
	__print_regs_in_range(base + 0x458, base + 0x458, 0x8, "FPA");

        /*print FPA_RD_REQ_PC and FPA_RD_LATENCY_PC registers*/
	__print_regs_in_range(base + 0x600, base + 0x610, 0x10, "FPA");

        /*FPA_POOL(0..63)_CFG base address*/
        base = 0x0001280010000000ULL;
        /*print FPA_POOL(0..63)_CFG registers*/
	__print_regs_in_range(base, base + 0x318, 0x8, "FPA");

        /*FPA_POOL(0..63)_FPF_MARKS base address*/
        base = 0x0001280010100000ULL;
        /*print FPA_POOL(0..63)_FPF_MARKS registers*/
	__print_regs_in_range(base, base + 0x318, 0x8, "FPA");

        /*FPA_POOL(0..63)_AVAILABLE base address*/
        base = 0x0001280010300000ULL;
        /*print FPA_POOL(0..63)_AVAILABLE registers*/
	__print_regs_in_range(base, base + 0x318, 0x8, "FPA");

        /*FPA_POOL(0..63)_THRESHOLD base address*/
        base = 0x0001280010400000ULL;
        /*print FPA_POOL(0..63)_THRESHOLD registers*/
	__print_regs_in_range(base, base + 0x318, 0x8, "FPA");

        /*FPA_POOL(0..63)_START_ADDR base address*/
        base = 0x0001280010500000ULL;
        /*print FPA_POOL(0..63)_START_ADDR registers*/
	__print_regs_in_range(base, base + 0x318, 0x8, "FPA");

        /*FPA_POOL(0..63)_END_ADDR base address*/
        base = 0x0001280010600000ULL;
        /*print FPA_POOL(0..63)_END_ADDR registers*/
	__print_regs_in_range(base, base + 0x318, 0x8, "FPA");

        /*FPA_POOL(0..63)_STACK_BASE base address*/
        base = 0x0001280010700000ULL;
        /*print FPA_POOL(0..63)_STACK_BASE registers*/
	__print_regs_in_range(base, base + 0x318, 0x8, "FPA");

        /*FPA_POOL(0..63)_STACK_END base address*/
        base = 0x0001280010800000ULL;
        /*print FPA_POOL(0..63)_STACK_END registers*/
	__print_regs_in_range(base, base + 0x318, 0x8, "FPA");

        /*FPA_POOL(0..63)_STACK_ADDR base address*/
        base = 0x0001280010900000ULL;
        /*print FPA_POOL(0..63)_STACK_ADDR registers*/
	__print_regs_in_range(base, base + 0x318, 0x8, "FPA");

        /*FPA_POOL(0..63)_INT base address*/
        base = 0x0001280010A00000ULL;
        /*print FPA_POOL(0..63)_INT registers*/
	__print_regs_in_range(base, base + 0x318, 0x8, "FPA");

        /*FPA_POOL(0..63)_OP_PC base address*/
        base = 0x0001280010F00000ULL;
        /*print FPA_POOL(0..63)_OP_PC registers*/
	__print_regs_in_range(base, base + 0x318, 0x8, "FPA");

        /*FPA_AURA(0..1023)_POOL base address*/
        base = 0x0001280020000000ULL;
        /*print FPA_AURA(0..1023)_POOL registers*/
	__print_regs_in_range(base, base + 0x8118, 0x8, "FPA");

        /*FPA_AURA(0..1023)_CFG base address*/
        base = 0x0001280020100000ULL;
        /*print FPA_AURA(0..1023)_CFG registers*/
	__print_regs_in_range(base, base + 0x8118, 0x8, "FPA");

        /*FPA_AURA(0..1023)_CNT base address*/
        base = 0x0001280020200000ULL;
        /*print FPA_AURA(0..1023)_CNT registers*/
	__print_regs_in_range(base, base + 0x8118, 0x8, "FPA");

        /*FPA_AURA(0..1023)_CNT_ADD base address*/
        base = 0x0001280020300000ULL;
        /*print FPA_AURA(0..1023)_CNT_ADD registers*/
	__print_regs_in_range(base, base + 0x8118, 0x8, "FPA");

        /*FPA_AURA(0..1023)_CNT_LIMIT base address*/
        base = 0x0001280020400000ULL;
        /*print FPA_AURA(0..1023)_CNT_LIMIT registers*/
	__print_regs_in_range(base, base + 0x8118, 0x8, "FPA");

        /*FPA_AURA(0..1023)_CNT_THRESHOLD base address*/
        base = 0x0001280020500000ULL;
        /*print FPA_AURA(0..1023)_CNT_THRESHOLD registers*/
	__print_regs_in_range(base, base + 0x8118, 0x8, "FPA");

        /*FPA_AURA(0..1023)_INT base address*/
        base = 0x0001280020600000ULL;
        /*print FPA_AURA(0..1023)_INT registers*/
	__print_regs_in_range(base, base + 0x8118, 0x8, "FPA");

        /*FPA_AURA(0..1023)_POOL_LEVELS base address*/
        base = 0x0001280020700000ULL;
        /*print FPA_AURA(0..1023)_POOL_LEVELS registers*/
	__print_regs_in_range(base, base + 0x8118, 0x8, "FPA");

        /*FPA_AURA(0..1023)_CNT_LEVELS base address*/
        base = 0x0001280020800000ULL;
        /*print FPA_AURA(0..1023)_CNT_LEVELS registers*/
	__print_regs_in_range(base, base + 0x8118, 0x8, "FPA");

}

/*In 78xx PIP and IPD are replaced with PKI*/
void
dump_cn78xx_pki_regs(void)
{
	unsigned long long  base = 0x0001180044000010ULL;
        unsigned long long alpha,beta,gama;

	printf("\n ---- Dumping CN78xx PKI registers \n");
	
	/*print PKI_SFT_RST,PKI_GEN_INT and PKI_PKT_ERR registers*/
	__print_regs_in_range(base, base + 0x30, 0x10, "PKI");

	/*print PKI_X2P_REQ_OFL,PKI_ECC_INT0,PKI_ECC_INT1 and 
          PKI_ECC_INT2 registers*/
	__print_regs_in_range(base + 0x38, base + 0x50, 0x8, "PKI");

	/*print PKI_ECC_CTL0,PKI_ECC_CTL1 and PKI_ECC_CTL2 registers*/
	__print_regs_in_range(base + 0x60, base + 0x70, 0x8, "PKI");

	/*print PKI_BIST_STATUS0,PKI_BIST_STATUS1 and 
          PKI_BIST_STATUS2 registers*/
	__print_regs_in_range(base + 0x80, base + 0x90, 0x8, "PKI");
        
	/*print PKI_BUF_CTL,PKI_STAT_CTL and PKI_REQ_WGT registers*/
	__print_regs_in_range(base + 0x100, base + 0x120, 0x10, "PKI");

	/*print PKI_GBL_PEN register*/
	__print_regs_in_range(base + 0x200, base + 0x200, 0x8, "PKI");

	/*print PKI_ACTIVE0,PKI_ACTIVE1 and PKI_ACTIVE2 registers*/
	__print_regs_in_range(base + 0x220, base + 0x240, 0x10, "PKI");

	/*print PKI_CLKEN and PKI_TAG_SECRET registers*/
	__print_regs_in_range(base + 0x410 , base + 0x430, 0x20, "PKI");

	/*print PKI_PCAM_LOOKUP and PKI_PCAM_RESULT registers*/
	__print_regs_in_range(base + 0x500, base + 0x510, 0x10, "PKI");

	/*print PKI_FRM_LEN_CHK(0..1) registers*/
	__print_regs_in_range(base + 0x4000, base + 0x4008, 0x8, "PKI");

	/*print PKI_LTYPE(0..31)_MAP registers*/
        base = 0x0001180044005000ULL;
	__print_regs_in_range(base, base + 0x188, 0x8, "PKI");

	/*print PKI_REASM_SOP(0..1) registers*/
        base = 0x0001180044006000ULL;
	__print_regs_in_range(base, base + 0x8, 0x8, "PKI");

	/*print PKI_TAG_INC(0..31)_CTL registers*/
        base = 0x0001180044007000ULL;
	__print_regs_in_range(base, base + 0x188, 0x8, "PKI");

	/*print PKI_TAG_INC(0..31)_MASK registers*/
        base = 0x0001180044008000ULL;
	__print_regs_in_range(base, base + 0x188, 0x8, "PKI");

	/*print PKI_ICG(0..3)_CFG registers*/
        base = 0x000118004400A000ULL;
	__print_regs_in_range(base, base + 0x18, 0x8, "PKI");

	/*print PKI_CL(0..3)_INT registers*/
        base = 0x000118004400A000ULL;
	__print_regs_in_range(base, base + 0x18, 0x8, "PKI");

	/*print PKI_CL(0..3)_INT registers*/
        base = 0x000118004400A000ULL;
	for(alpha = 0; alpha < 4;alpha++)
        {
		__print_regs_in_range(base, base, 0x8, "PKI");
        	base |= alpha << 16;
	}

	/*print PKI_CL(0..3)_ECC_INT registers*/
        base = 0x000118004400C010ULL;
	for(alpha = 0; alpha < 4;alpha++)
        {
		__print_regs_in_range(base, base, 0x8, "PKI");
        	base |= alpha << 16;
	}
	
	/*print PKI_CL(0..3)_ECC_CTL registers*/
        base = 0x000118004400C020ULL;
	for(alpha = 0; alpha < 4;alpha++)
        {
		__print_regs_in_range(base, base, 0x8, "PKI");
        	base |= alpha << 16;
	}

	/*print PKI_CL(0..3)_START registers*/
        base = 0x000118004400C030ULL;
	for(alpha = 0; alpha < 4;alpha++)
        {
		__print_regs_in_range(base, base, 0x8, "PKI");
        	base |= alpha << 16;
	}
 
	/*print PKI_PKIND(0..63)_ICGSEL registers*/
        base = 0x0001180044010000ULL;
	__print_regs_in_range(base, base + 0x318, 0x8, "PKI");

	/*print PKI_STYLE(0..63)_TAG_SEL registers*/
        base = 0x0001180044020000ULL;
	__print_regs_in_range(base, base + 0x318, 0x8, "PKI");

	/*print PKI_STYLE(0..63)_TAG_MASK registers*/
        base = 0x0001180044021000ULL;
	__print_regs_in_range(base, base + 0x318, 0x8, "PKI");

	/*print PKI_STYLE(0..63)_WQ2 registers*/
        base = 0x0001180044022000ULL;
	__print_regs_in_range(base, base + 0x318, 0x8, "PKI");

	/*print PKI_STYLE(0..63)_WQ4 registers*/
        base = 0x0001180044022000ULL;
	__print_regs_in_range(base, base + 0x318, 0x8, "PKI");

	/*print PKI_STYLE(0..63)_BUF registers*/
        base = 0x0001180044024000ULL;
	__print_regs_in_range(base, base + 0x318, 0x8, "PKI");
	
	/*print PKI_CL(0..3)_PKIND(0..63)_CFG registers*/
        base = 0x0001180044300040ULL;
	for(alpha = 0; alpha < 4;alpha++)
        {
		__print_regs_in_range(base, base + 0x318, 0x8, "PKI");
        	base |= alpha << 16;
	}

	/*print PKI_CL(0..3)_PKIND(0..63)_STYLE registers*/
        base = 0x0001180044300048ULL;
	for(alpha = 0; alpha < 4;alpha++)
        {
		__print_regs_in_range(base, base + 0x318, 0x8, "PKI");
        	base |= alpha << 16;
	}

	/*print PKI_CL(0..3)_PKIND(0..63)_SKIP registers*/
        base = 0x0001180044300050ULL;
	for(alpha = 0; alpha < 4;alpha++)
        {
		__print_regs_in_range(base, base + 0x318, 0x8, "PKI");
        	base |= alpha << 16;
	}

	/*print PKI_CL(0..3)_PKIND(0..63)_L2_CUSTOM registers*/
        base = 0x0001180044300058ULL;
	for(alpha = 0; alpha < 4;alpha++)
        {
		__print_regs_in_range(base, base + 0x318, 0x8, "PKI");
        	base |= alpha << 16;
	}

	/*print PKI_CL(0..3)_PKIND(0..63)_LG_CUSTOM registers*/
        base = 0x0001180044300060ULL;
	for(alpha = 0; alpha < 4;alpha++)
        {
		__print_regs_in_range(base, base + 0x318, 0x8, "PKI");
        	base |= alpha << 16;
	}

	/*print PKI_CL(0..3)_STYLE(0..63)_CFG registers*/
        base = 0x0001180044500000ULL;
	for(alpha = 0; alpha < 4;alpha++)
        {
		__print_regs_in_range(base, base + 0x318, 0x8, "PKI");
        	base |= alpha << 16;
	}

	/*print PKI_CL(0..3)_STYLE(0..63)_CFG2 registers*/
        base = 0x0001180044500800ULL;
	for(alpha = 0; alpha < 4;alpha++)
        {
		__print_regs_in_range(base, base + 0x318, 0x8, "PKI");
        	base |= alpha << 16;
	}

	/*print PKI_CL(0..3)_STYLE(0..63)_ALG registers*/
        base = 0x0001180044501000ULL;
	for(alpha = 0; alpha < 4;alpha++)
        {
		__print_regs_in_range(base, base + 0x318, 0x8, "PKI");
        	base |= alpha << 16;
	}

	/*print PKI_CL(0..3)_PCAM(0..1)_TERM(0..191) registers*/
        base = 0x0001180044700000ULL;
	for(alpha = 0; alpha < 4;alpha++)
        {
		for(beta = 0; beta < 2; beta++)
		{
			for(gama = 0; gama < 192; gama++)
			{
				__print_regs_in_range(base, base, 0x8, "PKI");
        			base = base|alpha << 16| beta << 12| gama << 3;
			}
		}
	}

	/*print PKI_CL(0..3)_PCAM(0..1)_MATCH(0..191) registers*/
        base = 0x0001180044704000ULL;
	for(alpha = 0; alpha < 4;alpha++)
        {
		for(beta = 0; beta < 2; beta++)
		{
			for(gama = 0; gama < 192; gama++)
			{
				__print_regs_in_range(base, base, 0x8, "PKI");
        			base = base|alpha << 16| beta << 12| gama << 3;
			}
		}
	}

	/*print PKI_CL(0..3)_PCAM(0..1)_ACTION(0..191) registers*/
        base = 0x0001180044708000ULL;
	for(alpha = 0; alpha < 4;alpha++)
        {
		for(beta = 0; beta < 2; beta++)
		{
			for(gama = 0; gama < 192; gama++)
			{
				__print_regs_in_range(base, base, 0x8, "PKI");
        			base = base|alpha << 16| beta << 12| gama << 3;
			}
		}
	}

	/*print PKI_QPG_TBL(0..2047) registers*/
        base = 0x0001180044800000ULL;
	for(alpha = 0; alpha < 2048;alpha++)
        {
		__print_regs_in_range(base, base, 0x8, "PKI");
        	base |= alpha << 3;
	}

	/*print PKI_AURA(0..1023)_CFG registers*/
        base = 0x0001180044900000ULL;
	for(alpha = 0; alpha < 1024;alpha++)
        {
		__print_regs_in_range(base, base, 0x8, "PKI");
        	base |= alpha << 3;
	}

	/*print PKI_CHAN(0..4095)_CFG registers*/
        base = 0x0001180044A00000ULL;
	for(alpha = 0; alpha < 4096;alpha++)
        {
		__print_regs_in_range(base, base, 0x8, "PKI");
        	base |= alpha << 3;
	}

	/*print PKI_BPID(0..1023)_STATE registers*/
        base = 0x0001180044B00000ULL;
	for(alpha = 0; alpha < 1024;alpha++)
        {
		__print_regs_in_range(base, base, 0x8, "PKI");
        	base |= alpha << 3;
	}

	/*print PKI_STAT(0..63)_HIST0 registers*/
        base = 0x0001180044E00000ULL;
	for(alpha = 0; alpha < 64;alpha++)
        {
		__print_regs_in_range(base, base, 0x8, "PKI");
        	base |= alpha << 8;
	}

	/*print PKI_STAT(0..63)_HIST1 registers*/
        base = 0x0001180044E00008ULL;
	for(alpha = 0; alpha < 64;alpha++)
        {
		__print_regs_in_range(base, base, 0x8, "PKI");
        	base |= alpha << 8;
	}

	/*print PKI_STAT(0..63)_HIST2 registers*/
        base = 0x0001180044E00010ULL;
	for(alpha = 0; alpha < 64;alpha++)
        {
		__print_regs_in_range(base, base, 0x8, "PKI");
        	base |= alpha << 8;
	}

	/*print PKI_STAT(0..63)_HIST3 registers*/
        base = 0x0001180044E00018ULL;
	for(alpha = 0; alpha < 64;alpha++)
        {
		__print_regs_in_range(base, base, 0x8, "PKI");
        	base |= alpha << 8;
	}

	/*print PKI_STAT(0..63)_HIST4 registers*/
        base = 0x0001180044E00020ULL;
	for(alpha = 0; alpha < 64;alpha++)
        {
		__print_regs_in_range(base, base, 0x8, "PKI");
        	base |= alpha << 8;
	}

	/*print PKI_STAT(0..63)_HIST5 registers*/
        base = 0x0001180044E00028ULL;
	for(alpha = 0; alpha < 64;alpha++)
        {
		__print_regs_in_range(base, base, 0x8, "PKI");
        	base |= alpha << 8;
	}

	/*print PKI_STAT(0..63)_HIST6 registers*/
        base = 0x0001180044E00030ULL;
	for(alpha = 0; alpha < 64;alpha++)
        {
		__print_regs_in_range(base, base, 0x8, "PKI");
        	base |= alpha << 8;
	}

	/*print PKI_STAT(0..63)_STAT0 registers*/
        base = 0x0001180044E00038ULL;
	for(alpha = 0; alpha < 64;alpha++)
        {
		__print_regs_in_range(base, base, 0x8, "PKI");
        	base |= alpha << 8;
	}

	/*print PKI_STAT(0..63)_STAT1 registers*/
        base = 0x0001180044E00040ULL;
	for(alpha = 0; alpha < 64;alpha++)
        {
		__print_regs_in_range(base, base, 0x8, "PKI");
        	base |= alpha << 8;
	}

	/*print PKI_STAT(0..63)_STAT2 registers*/
        base = 0x0001180044E00048ULL;
	for(alpha = 0; alpha < 64;alpha++)
        {
		__print_regs_in_range(base, base, 0x8, "PKI");
        	base |= alpha << 8;
	}

	/*print PKI_STAT(0..63)_STAT3 registers*/
        base = 0x0001180044E00050ULL;
	for(alpha = 0; alpha < 64;alpha++)
        {
		__print_regs_in_range(base, base, 0x8, "PKI");
        	base |= alpha << 8;
	}

	/*print PKI_STAT(0..63)_STAT4 registers*/
        base = 0x0001180044E00058ULL;
	for(alpha = 0; alpha < 64;alpha++)
        {
		__print_regs_in_range(base, base, 0x8, "PKI");
        	base |= alpha << 8;
	}

	/*print PKI_STAT(0..63)_STAT5 registers*/
        base = 0x0001180044E00060ULL;
	for(alpha = 0; alpha < 64;alpha++)
        {
		__print_regs_in_range(base, base, 0x8, "PKI");
        	base |= alpha << 8;
	}

	/*print PKI_STAT(0..63)_STAT6 registers*/
        base = 0x0001180044E00068ULL;
	for(alpha = 0; alpha < 64;alpha++)
        {
		__print_regs_in_range(base, base, 0x8, "PKI");
        	base |= alpha << 8;
	}

	/*print PKI_STAT(0..63)_STAT7 registers*/
        base = 0x0001180044E00070ULL;
	for(alpha = 0; alpha < 64;alpha++)
        {
		__print_regs_in_range(base, base, 0x8, "PKI");
        	base |= alpha << 8;
	}

	/*print PKI_STAT(0..63)_STAT8 registers*/
        base = 0x0001180044E00078ULL;
	for(alpha = 0; alpha < 64;alpha++)
        {
		__print_regs_in_range(base, base, 0x8, "PKI");
        	base |= alpha << 8;
	}

	/*print PKI_STAT(0..63)_STAT9 registers*/
        base = 0x0001180044E00080ULL;
	for(alpha = 0; alpha < 64;alpha++)
        {
		__print_regs_in_range(base, base, 0x8, "PKI");
        	base |= alpha << 8;
	}

	/*print PKI_STAT(0..63)_STAT10 registers*/
        base = 0x0001180044E00088ULL;
	for(alpha = 0; alpha < 64;alpha++)
        {
		__print_regs_in_range(base, base, 0x8, "PKI");
        	base |= alpha << 8;
	}

	/*print PKI_STAT(0..63)_STAT11 registers*/
        base = 0x0001180044E00090ULL;
	for(alpha = 0; alpha < 64;alpha++)
        {
		__print_regs_in_range(base, base, 0x8, "PKI");
        	base |= alpha << 8;
	}

	/*print PKI_STAT(0..63)_STAT12 registers*/
        base = 0x0001180044E00098ULL;
	for(alpha = 0; alpha < 64;alpha++)
        {
		__print_regs_in_range(base, base, 0x8, "PKI");
        	base |= alpha << 8;
	}

	/*print PKI_STAT(0..63)_STAT13 registers*/
        base = 0x0001180044E000A0ULL;
	for(alpha = 0; alpha < 64;alpha++)
        {
		__print_regs_in_range(base, base, 0x8, "PKI");
        	base |= alpha << 8;
	}

	/*print PKI_STAT(0..63)_STAT14 registers*/
        base = 0x0001180044E000A8ULL;
	for(alpha = 0; alpha < 64;alpha++)
        {
		__print_regs_in_range(base, base, 0x8, "PKI");
        	base |= alpha << 8;
	}

	/*print PKI_STAT(0..63)_STAT15 registers*/
        base = 0x0001180044E000B0ULL;
	for(alpha = 0; alpha < 64;alpha++)
        {
		__print_regs_in_range(base, base, 0x8, "PKI");
        	base |= alpha << 8;
	}

	/*print PKI_STAT(0..63)_STAT16 registers*/
        base = 0x0001180044E000B8ULL;
	for(alpha = 0; alpha < 64;alpha++)
        {
		__print_regs_in_range(base, base, 0x8, "PKI");
        	base |= alpha << 8;
	}

	/*print PKI_STAT(0..63)_STAT17 registers*/
        base = 0x0001180044E000C0ULL;
	for(alpha = 0; alpha < 64;alpha++)
        {
		__print_regs_in_range(base, base, 0x8, "PKI");
        	base |= alpha << 8;
	}

	/*print PKI_STAT(0..63)_STAT18 registers*/
        base = 0x0001180044E000C8ULL;
	for(alpha = 0; alpha < 64;alpha++)
        {
		__print_regs_in_range(base, base, 0x8, "PKI");
        	base |= alpha << 8;
	}

	/*print PKI_PKND(0..63)_INB_STAT0 registers*/
        base = 0x0001180044F00000ULL;
	for(alpha = 0; alpha < 64;alpha++)
        {
		__print_regs_in_range(base, base, 0x8, "PKI");
        	base |= alpha << 8;
	}

	/*print PKI_PKND(0..63)_INB_STAT1 registers*/
        base = 0x0001180044F00008ULL;
	for(alpha = 0; alpha < 64;alpha++)
        {
		__print_regs_in_range(base, base, 0x8, "PKI");
        	base |= alpha << 8;
	}

	/*print PKI_PKND(0..63)_INB_STAT2 registers*/
        base = 0x0001180044F00010ULL;
	for(alpha = 0; alpha < 64;alpha++)
        {
		__print_regs_in_range(base, base, 0x8, "PKI");
        	base |= alpha << 8;
	}

}


void
dump_cn78xx_config_regs(int pcieport)
{

	printf("\n ---- Dumping CN78xx PCIe port %d config registers\n", pcieport);

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
__dump_cn78xx_regs(void)
{
	//int i;
	int node = cvmx_get_node_num();
	printf("\n\n ---------Begin CN78xx regs dump -----------\n");

	dump_cn78xx_pem_regs(0);
	dump_cn78xx_fpa_regs();
	dump_cn78xx_pki_regs();
	dump_cn78xx_sli_debug_data();
	dump_cn78xx_config_regs(0);



	printf("SCRATCH: 0x%016lx\n", cvmx_read_csr_node(node, CVMX_PEXP_SLI_SCRATCH_1));

	printf("SLI_CTL_PORT0: 0x%016lx\n",
		 cvmx_read_csr_node(node, CVMX_PEXP_SLI_CTL_PORTX(0)));
	printf("SLI_CTL_PORT1: 0x%016lx\n",
		 cvmx_read_csr_node(node, CVMX_PEXP_SLI_CTL_PORTX(1)));
	printf("SLI_CTL_PORT2: 0x%016lx\n",
		 cvmx_read_csr_node(node, CVMX_PEXP_SLI_CTL_PORTX(2)));
	printf("SLI_CTL_PORT3: 0x%016lx\n",
		 cvmx_read_csr_node(node, CVMX_PEXP_SLI_CTL_PORTX(3)));

	printf("SLI_CTL_STATUS: 0x%016lx\n",
		 cvmx_read_csr_node(node, CVMX_PEXP_SLI_CTL_STATUS));

	printf("SLI_DATA_OUT_CNT: 0x%016lx\n",
		 cvmx_read_csr_node(node, CVMX_PEXP_SLI_DATA_OUT_CNT));

	printf("SLI_INT_ENB_PORT0: 0x%016lx\n",
		 cvmx_read_csr_node(node, CVMX_PEXP_SLI_INT_ENB_PORTX(0)));

	printf("SLI_INT_SUM: 0x%016lx\n",
		 cvmx_read_csr_node(node, CVMX_PEXP_SLI_INT_SUM));

	printf("SLI_PKT0_CNTS: 0x%016lx\n",
		 cvmx_read_csr_node(node, CVMX_PEXP_SLI_PKTX_CNTS(0)));

	printf("SLI_PKT1_CNTS: 0x%016lx\n",
		 cvmx_read_csr_node(node, CVMX_PEXP_SLI_PKTX_CNTS(1)));

	printf("SLI_PKT2_CNTS: 0x%016lx\n",
		 cvmx_read_csr_node(node, CVMX_PEXP_SLI_PKTX_CNTS(2)));

	printf("SLI_PKT3_CNTS: 0x%016lx\n",
		 cvmx_read_csr_node(node,CVMX_PEXP_SLI_PKTX_CNTS(3)));

	printf("SLI_PKT0_INSTR_BADDR: 0x%016lx\n",
		 cvmx_read_csr_node(node, CVMX_PEXP_SLI_PKTX_INSTR_BADDR(0)));

	printf("SLI_PKT1_INSTR_BADDR: 0x%016lx\n",
		 cvmx_read_csr_node(node, CVMX_PEXP_SLI_PKTX_INSTR_BADDR(1)));

	printf("SLI_PKT2_INSTR_BADDR: 0x%016lx\n",
		 cvmx_read_csr_node(node, CVMX_PEXP_SLI_PKTX_INSTR_BADDR(2)));

	printf("SLI_PKT3_INSTR_BADDR: 0x%016lx\n",
		 cvmx_read_csr_node(node, CVMX_PEXP_SLI_PKTX_INSTR_BADDR(3)));

	printf("SLI_PKT0_INSTR_BAOFF_DBELL: 0x%016lx\n",
		 cvmx_read_csr_node(node, CVMX_PEXP_SLI_PKTX_INSTR_BAOFF_DBELL(0)));

	printf("SLI_PKT1_INSTR_BAOFF_DBELL: 0x%016lx\n",
		 cvmx_read_csr_node(node, CVMX_PEXP_SLI_PKTX_INSTR_BAOFF_DBELL(1)));

	printf("SLI_PKT2_INSTR_BAOFF_DBELL: 0x%016lx\n",
		 cvmx_read_csr_node(node, CVMX_PEXP_SLI_PKTX_INSTR_BAOFF_DBELL(2)));

	printf("SLI_PKT3_INSTR_BAOFF_DBELL: 0x%016lx\n",
		 cvmx_read_csr_node(node, CVMX_PEXP_SLI_PKTX_INSTR_BAOFF_DBELL(3)));

	printf("SLI_PKT0_INSTR_FIFO_RSIZE: 0x%016lx\n",
		 cvmx_read_csr_node(node, CVMX_PEXP_SLI_PKTX_INSTR_FIFO_RSIZE(0)));

	printf("SLI_PKT1_INSTR_FIFO_RSIZE: 0x%016lx\n",
		 cvmx_read_csr_node(node, CVMX_PEXP_SLI_PKTX_INSTR_FIFO_RSIZE(1)));

	printf("SLI_PKT2_INSTR_FIFO_RSIZE: 0x%016lx\n",
		 cvmx_read_csr_node(node, CVMX_PEXP_SLI_PKTX_INSTR_FIFO_RSIZE(2)));

	printf("SLI_PKT3_INSTR_FIFO_RSIZE: 0x%016lx\n",
		 cvmx_read_csr_node(node, CVMX_PEXP_SLI_PKTX_INSTR_FIFO_RSIZE(3)));

	printf("SLI_PKT0_OUT_SIZE: 0x%016lx\n",
		 cvmx_read_csr_node(node, CVMX_PEXP_SLI_PKTX_OUT_SIZE(0)));

	printf("SLI_PKT1_OUT_SIZE: 0x%016lx\n",
		 cvmx_read_csr_node(node, CVMX_PEXP_SLI_PKTX_OUT_SIZE(1)));

	printf("SLI_PKT2_OUT_SIZE: 0x%016lx\n",
		 cvmx_read_csr_node(node, CVMX_PEXP_SLI_PKTX_OUT_SIZE(2)));

	printf("SLI_PKT3_OUT_SIZE: 0x%016lx\n",
		 cvmx_read_csr_node(node, CVMX_PEXP_SLI_PKTX_OUT_SIZE(3)));


	printf("SLI_PKT0_SLIST_BADDR: 0x%016lx\n",
		 cvmx_read_csr_node(node, CVMX_PEXP_SLI_PKTX_SLIST_BADDR(0)));

	printf("SLI_PKT1_SLIST_BADDR: 0x%016lx\n",
		 cvmx_read_csr_node(node, CVMX_PEXP_SLI_PKTX_SLIST_BADDR(1)));

	printf("SLI_PKT2_SLIST_BADDR: 0x%016lx\n",
		 cvmx_read_csr_node(node, CVMX_PEXP_SLI_PKTX_SLIST_BADDR(2)));

	printf("SLI_PKT3_SLIST_BADDR: 0x%016lx\n",
		 cvmx_read_csr_node(node, CVMX_PEXP_SLI_PKTX_SLIST_BADDR(3)));


	printf("SLI_PKT0_SLIST_BAOFF_DBELL: 0x%016lx\n",
		 cvmx_read_csr_node(node, CVMX_PEXP_SLI_PKTX_SLIST_BAOFF_DBELL(0)));

	printf("SLI_PKT1_SLIST_BAOFF_DBELL: 0x%016lx\n",
		 cvmx_read_csr_node(node, CVMX_PEXP_SLI_PKTX_SLIST_BAOFF_DBELL(1)));

	printf("SLI_PKT2_SLIST_BAOFF_DBELL: 0x%016lx\n",
		 cvmx_read_csr_node(node, CVMX_PEXP_SLI_PKTX_SLIST_BAOFF_DBELL(2)));

	printf("SLI_PKT3_SLIST_BAOFF_DBELL: 0x%016lx\n",
		 cvmx_read_csr_node(node, CVMX_PEXP_SLI_PKTX_SLIST_BAOFF_DBELL(3)));



	printf("SLI_PKT0_SLIST_FIFO_RSIZE: 0x%016lx\n",
		 cvmx_read_csr_node(node, CVMX_PEXP_SLI_PKTX_SLIST_FIFO_RSIZE(0)));

	printf("SLI_PKT1_SLIST_FIFO_RSIZE: 0x%016lx\n",
		 cvmx_read_csr_node(node, CVMX_PEXP_SLI_PKTX_SLIST_FIFO_RSIZE(1)));

	printf("SLI_PKT2_SLIST_FIFO_RSIZE: 0x%016lx\n",
		 cvmx_read_csr_node(node, CVMX_PEXP_SLI_PKTX_SLIST_FIFO_RSIZE(2)));

	printf("SLI_PKT3_SLIST_FIFO_RSIZE: 0x%016lx\n",
		 cvmx_read_csr_node(node, CVMX_PEXP_SLI_PKTX_SLIST_FIFO_RSIZE(3)));

	printf("SLI_PKT_CNT_INT: 0x%016lx\n",
		 cvmx_read_csr_node(node, CVMX_PEXP_SLI_PKT_CNT_INT));

	printf("SLI_PKT_IN_DONE0_CNTS: 0x%016lx\n",
		 cvmx_read_csr_node(node, CVMX_PEXP_SLI_PKT_IN_DONEX_CNTS(0)));

	printf("SLI_PKT_IN_DONE1_CNTS: 0x%016lx\n",
		 cvmx_read_csr_node(node, CVMX_PEXP_SLI_PKT_IN_DONEX_CNTS(1)));

	printf("SLI_PKT_IN_DONE2_CNTS: 0x%016lx\n",
		 cvmx_read_csr_node(node, CVMX_PEXP_SLI_PKT_IN_DONEX_CNTS(2)));

	printf("SLI_PKT_IN_DONE3_CNTS: 0x%016lx\n",
		 cvmx_read_csr_node(node, CVMX_PEXP_SLI_PKT_IN_DONEX_CNTS(3)));


	printf("SLI_PKT_IN_INSTR_COUNTS: 0x%016lx\n",
		 cvmx_read_csr_node(node, CVMX_PEXP_SLI_PKT_IN_INSTR_COUNTS));

	printf("SLI_PKT_INSTR_ENB: 0x%016lx\n",
		 cvmx_read_csr_node(node, CVMX_PEXP_SLI_PKT_INSTR_ENB));

	printf("SLI_PKT_OUT_BP_EN: 0x%016lx\n",
		 cvmx_read_csr_node(node, CVMX_PEXP_SLI_PKT_OUT_BP_EN));

	printf("SLI_PKT_OUT_ENB: 0x%016lx\n",
		 cvmx_read_csr_node(node, CVMX_PEXP_SLI_PKT_OUT_ENB));

	printf("SLI_PKT_OUTPUT_WMARK: 0x%016lx\n",
		 cvmx_read_csr_node(node, CVMX_PEXP_SLI_PKT_OUTPUT_WMARK));

	printf("SLI_PKT_TIME_INT: 0x%016lx\n",
		 cvmx_read_csr_node(node, CVMX_PEXP_SLI_PKT_TIME_INT));

	printf("\n\n -------------------------------------------\n");
}
