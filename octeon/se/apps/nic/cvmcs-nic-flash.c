#include "cvmcs-common.h"
#include "cvmcs-nic.h"
#include "cvmcs-nic-fwdump.h"
#include "cvmcs-nic-flash.h"
#include <cvmx-mpi-defs.h>

#define SPI_FLASH_16MB_BOUN             0x1000000

#define OCTEON_SPI_MAX_CLOCK_HZ         16000000	/** Max clock speed */
#define OCTEON_SPI_MAX_CLOCK_HZ_7XXX    200000000	/** Max clock for O3 */
#define SPI_DEFAULT_WORDLEN 8
#define OCTEON_SPI_MAX_BYTES 9

/* Erase commands */
#define CMD_ERASE_4K                    0x20
/* Common status */
#define STATUS_WIP                      0x01
#define STATUS_PEC                      0x80

#define CMD_READ_STATUS                 0x05
#define CMD_READ_ARRAY_FAST             0x0b
#define CMD_PAGE_PROGRAM                0x02
#define CMD_WRITE_ENABLE                0x06
#define CMD_FLAG_STATUS                 0x70

#define CONFIG_SYS_HZ 1000ull
/* Flash timeout values */
#define SPI_FLASH_PROG_TIMEOUT          (2 * CONFIG_SYS_HZ)
#define SPI_FLASH_PAGE_ERASE_TIMEOUT    (5 * CONFIG_SYS_HZ)

/* SPI mode flags */
#define SPI_CPHA        0x01	/* clock phase */
#define SPI_CPOL        0x02	/* clock polarity */
#define SPI_CS_HIGH     0x04	/* CS active high */
#define SPI_LSB_FIRST   0x08	/* per-word bits-on-wire */
#define SPI_3WIRE       0x10	/* SI/SO signals shared */

/* SPI transfer flags */
#define SPI_XFER_BEGIN          0x01	/* Assert CS before transfer */
#define SPI_XFER_END            0x02	/* Deassert CS after transfer */

struct spi_flash_params {
	u32 jedec;
	u16 ext_jedec;
	u32 sector_size;
	u32 nr_sectors;
	u16 flags;
};

struct spi_slave {
	unsigned int bus;
	unsigned int cs;
	unsigned int wordlen;
	unsigned int max_write_size;
	void *memory_map;
};

/** Local driver datastructure */
struct octeon_spi {
	struct spi_slave slave;	/** Parent slave data structure */
	u32 max_speed_hz;	/** Maximum device speed in hz */
	u32 mode;		/** Device mode */
	u32 clkdiv;		/** Clock divisor for device speed */
	u8 bits_per_word;	/** Bits per word, usually 8 */
};

struct spi_flash {
	struct octeon_spi spi;
	u32 size;
	u32 page_size;
	u32 sector_size;
	u32 erase_size;
	u8 addr_width;
	u8 poll_cmd;
	u8 erase_cmd;
};

CVMX_SHARED static struct spi_flash flash;
CVMX_SHARED static struct flash_dump_params fdump;
CVMX_SHARED static int flash_log_done;
CVMX_SHARED static cvmx_spinlock_t flash_dump_lock;
extern int cvmcs_uboot_request_get(int ifidx, char *envariable, uint32_t *val);

#define ABS_OFFSET(offset) (fdump.fw_dump_flash_base + offset)

static u64 octeon_spi_set_mpicfg(const struct octeon_spi *ospi, int cs)
{
	union cvmx_mpi_cfg mpi_cfg;
	int cpha, cpol;

	cpha = !!(ospi->mode & SPI_CPHA);
	cpol = !!(ospi->mode & SPI_CPOL);

	mpi_cfg.u64 = 0;
	mpi_cfg.s.clkdiv = ospi->clkdiv;
	mpi_cfg.s.cshi = !!(ospi->mode & SPI_CS_HIGH);
	mpi_cfg.s.lsbfirst = !!(ospi->mode & SPI_LSB_FIRST);
	mpi_cfg.s.wireor = !!(ospi->mode & SPI_3WIRE);
	mpi_cfg.s.idlelo = cpha != cpol;
	mpi_cfg.s.cslate = cpha;
	mpi_cfg.s.enable = 1;

	switch (cs) {
	case 0:
		mpi_cfg.s.csena0 = 1;
		break;
	case 1:
		mpi_cfg.s.csena1 = 1;
		break;
	case 2:
		mpi_cfg.s.csena2 = 1;
		break;
	case 3:
		mpi_cfg.s.csena3 = 1;
		break;
	default:
		break;
	}

	return mpi_cfg.u64;
}

struct spi_slave *spi_setup_slave(struct spi_flash *flash)
{
	struct octeon_spi *ospi = &(flash->spi);
	unsigned int max_hz;

	if (OCTEON_IS_OCTEON3())
		max_hz = min(25000000, OCTEON_SPI_MAX_CLOCK_HZ_7XXX);
	else
		max_hz = min(25000000, OCTEON_SPI_MAX_CLOCK_HZ);
	ospi->clkdiv = 16;

	ospi->slave.bus = 0;
	ospi->slave.cs = 0;
	ospi->max_speed_hz = max_hz;
	ospi->mode = (0x02 | 0x01);
	ospi->bits_per_word = SPI_DEFAULT_WORDLEN;
	cvmx_write_csr_node(0, CVMX_MPI_CFG, octeon_spi_set_mpicfg(ospi, -1));

	return &ospi->slave;
}

void spi_free_slave(struct spi_slave *slave)
{
	cvmx_write_csr_node(slave->bus, CVMX_MPI_CFG, 0);
}

int spi_claim_bus(struct spi_slave *slave)
{
	union cvmx_mpi_cfg mpi_cfg;

	mpi_cfg.u64 = cvmx_read_csr_node(slave->bus, CVMX_MPI_CFG);
	mpi_cfg.s.tritx = 0;
	mpi_cfg.s.enable = 1;
	cvmx_write_csr_node(slave->bus, CVMX_MPI_CFG, mpi_cfg.u64);
	return 0;
}

/**
 * Releases the slave device
 *
 * @param[in]   slave   Pointer to slave to release
 */
void spi_release_bus(struct spi_slave *slave)
{
	struct octeon_spi *ospi = container_of(slave, struct octeon_spi, slave);
	union cvmx_mpi_cfg mpi_cfg;

	mpi_cfg.u64 = cvmx_read_csr_node(slave->bus, CVMX_MPI_CFG);
	mpi_cfg.s.tritx = (ospi->mode & SPI_3WIRE) ? 1 : 0;
	cvmx_write_csr_node(slave->bus, CVMX_MPI_CFG, mpi_cfg.u64);
}

static void octeon_spi_wait_ready(const struct spi_slave *slave)
{
	union cvmx_mpi_sts mpi_sts;

	while (1) {
		mpi_sts.u64 = cvmx_read_csr_node(slave->bus, CVMX_MPI_STS);
		if (mpi_sts.s.busy == 0)
			return;
		cvmx_wait_usec(1);
	}
}

int spi_xfer(struct spi_slave *slave, unsigned int bitlen, const void *dout,
	     void *din, unsigned long flags)
{
	union cvmx_mpi_tx mpi_tx;
	union cvmx_mpi_cfg mpi_cfg;
	struct octeon_spi *ospi = container_of(slave, struct octeon_spi, slave);
	const unsigned char *tx_data = dout;
	unsigned char *rx_data = din;
	unsigned int len = bitlen / 8, i;

	if (flags & SPI_XFER_BEGIN) {
		/* Do nothing */
	}

	mpi_cfg.u64 = octeon_spi_set_mpicfg(ospi, slave->cs);

	if (mpi_cfg.u64 != cvmx_read_csr_node(slave->bus, CVMX_MPI_CFG))
		cvmx_write_csr_node(slave->bus, CVMX_MPI_CFG, mpi_cfg.u64);

	while (len > OCTEON_SPI_MAX_BYTES) {
		if (tx_data)
			for (i = 0; i < OCTEON_SPI_MAX_BYTES; i++) {
				u8 d = *tx_data++;

				cvmx_write_csr_node(slave->bus,
						    CVMX_MPI_DATX(i), d);
			}

		mpi_tx.u64 = 0;
		mpi_tx.s.csid = slave->cs;
		mpi_tx.s.leavecs = 1;
		mpi_tx.s.txnum = tx_data ? OCTEON_SPI_MAX_BYTES : 0;
		mpi_tx.s.totnum = OCTEON_SPI_MAX_BYTES;
		cvmx_write_csr_node(slave->bus, CVMX_MPI_TX, mpi_tx.u64);

		octeon_spi_wait_ready(slave);

		if (rx_data)
			for (i = 0; i < OCTEON_SPI_MAX_BYTES; i++) {
				u64 v = cvmx_read_csr_node(slave->bus,
							   CVMX_MPI_DATX(i));
				*rx_data++ = (u8) v;
			}

		len -= OCTEON_SPI_MAX_BYTES;
	}

	if (tx_data)
		for (i = 0; i < len; i++) {
			u8 d = *tx_data++;

			cvmx_write_csr_node(slave->bus, CVMX_MPI_DATX(i), d);
		}

	mpi_tx.u64 = 0;
	mpi_tx.s.csid = slave->cs;
	mpi_tx.s.leavecs = !(flags & SPI_XFER_END);
	mpi_tx.s.txnum = tx_data ? len : 0;
	mpi_tx.s.totnum = len;
	cvmx_write_csr_node(slave->bus, CVMX_MPI_TX, mpi_tx.u64);

	octeon_spi_wait_ready(slave);

	if (rx_data)
		for (i = 0; i < len; i++) {
			u64 v =
			    cvmx_read_csr_node(slave->bus, CVMX_MPI_DATX(i));
			*rx_data++ = (u8) v;
		}
	return 0;
}

static int spi_flash_read_write(struct spi_slave *spi,
				const u8 *cmd, size_t cmd_len,
				const u8 *data_out, u8 *data_in,
				size_t data_len)
{
	unsigned long flags = SPI_XFER_BEGIN;
	int ret;

	if (data_len == 0)
		flags |= SPI_XFER_END;

	ret = spi_xfer(spi, cmd_len * 8, cmd, NULL, flags);
	if (ret) {
		cvmcs_printf("SF: Failed to send command (%zu bytes): %d\n",
			     cmd_len, ret);
	} else if (data_len != 0) {
		ret = spi_xfer(spi, data_len * 8, data_out, data_in,
			       SPI_XFER_END);
		if (ret) {
			cvmcs_printf
			    ("SF: Failed to transfer %zu bytes of data: %d\n",
			     data_len, ret);
		}
	}

	return ret;
}

int spi_flash_cmd_read(struct spi_slave *spi, const u8 *cmd,
		       size_t cmd_len, void *data, size_t data_len)
{
	return spi_flash_read_write(spi, cmd, cmd_len, NULL, data, data_len);
}

int spi_flash_cmd(struct spi_slave *spi, u8 cmd, void *response, size_t len)
{
	return spi_flash_cmd_read(spi, &cmd, 1, response, len);
}

int spi_flash_cmd_write(struct spi_slave *spi, const u8 *cmd, size_t cmd_len,
			const void *data, size_t data_len)
{
	return spi_flash_read_write(spi, cmd, cmd_len, data, NULL, data_len);
}

void spi_flash_setup_params(struct spi_slave *spi, struct spi_flash *flash)
{
	/* Assuming the following parameters for the flash */
	flash->page_size = 256;
	flash->sector_size = 65536;
	flash->size = 134217728;
	flash->addr_width = 4;
	flash->erase_cmd = CMD_ERASE_4K;
	flash->erase_size = 4096;

	/* Poll cmd seclection */
	flash->poll_cmd = CMD_READ_STATUS;
}

void cvmcs_spi_flash_probe(void)
{
	struct spi_slave *spi;
	int ret;

	memset(&flash, 0, sizeof(flash));
	/* Setup spi_slave */
	spi = spi_setup_slave(&flash);
	if (!spi) {
		cvmcs_printf("SF: Failed to set up slave\n");
		return;
	}

	/* Claim spi bus */
	ret = spi_claim_bus(spi);
	if (ret) {
		cvmcs_printf("SF: Failed to claim SPI bus: %d\n", ret);
		goto err_claim_bus;
	}

	spi_flash_setup_params(spi, &flash);

	/* Release spi bus */
	spi_release_bus(spi);

	printf("SPI NOR available\n");
	CVMX_SYNCW;
	return;

 err_claim_bus:
	spi_free_slave(spi);
}

static size_t spi_flash_cmd_size(struct spi_flash *flash)
{
	return flash->addr_width + 1;
}

static void spi_flash_addr(struct spi_flash *flash, u32 addr, u8 *cmd)
{
	/* cmd[0] is actual command */
	cmd[1] = addr >> (flash->addr_width * 8 - 8);
	cmd[2] = addr >> (flash->addr_width * 8 - 16);
	cmd[3] = addr >> (flash->addr_width * 8 - 24);
	if (flash->addr_width > 3)
		cmd[4] = addr >> (flash->addr_width * 8 - 32);
}

/* Enable writing on the SPI flash */
static inline int spi_flash_cmd_write_enable(struct spi_flash *flash)
{
	return spi_flash_cmd(&(flash->spi.slave), CMD_WRITE_ENABLE, NULL, 0);
}

static inline unsigned long diff_time(unsigned long now, unsigned long past)
{
	unsigned long max = (~(unsigned long)0);

	if (now > past)
		return (now - past);
	else
		return (max - past + now);
}

int spi_flash_cmd_wait_ready(struct spi_flash *flash, unsigned long timeout)
{
	struct spi_slave *spi = &(flash->spi.slave);
	unsigned long timebase;
	int ret;

	u8 status = 0;
	u8 check_status = 0x0;
	u8 poll_bit = STATUS_WIP;
	u8 cmd = flash->poll_cmd;

	if (cmd == CMD_FLAG_STATUS) {
		poll_bit = STATUS_PEC;
		check_status = poll_bit;
	}

	ret = spi_xfer(spi, 8, &cmd, NULL, SPI_XFER_BEGIN);
	if (ret) {
		cvmcs_printf("SF: fail to read %s status register\n",
			     cmd == CMD_READ_STATUS ? "read" : "flag");
		return ret;
	}

	timebase = cvmx_get_cycle();
	timeout = (timeout * 15000);	//TODO:tune the timeout
	do {
		ret = spi_xfer(spi, 8, NULL, &status, 0);
		if (ret)
			return -1;

		if ((status & poll_bit) == check_status)
			break;
	} while (diff_time(cvmx_get_cycle(), timebase) < timeout);

	spi_xfer(spi, 0, NULL, NULL, SPI_XFER_END);

	if ((status & poll_bit) == check_status)
		return 0;

	/* Timed out */
	printf("SF: time out!\n");
	return -1;
}

int spi_flash_write_common(struct spi_flash *flash, const u8 *cmd,
			   size_t cmd_len, const void *buf, size_t buf_len)
{
	struct spi_slave *spi = &(flash->spi.slave);
	unsigned long timeout = SPI_FLASH_PROG_TIMEOUT;
	int ret;

	if (buf == NULL)
		timeout = SPI_FLASH_PAGE_ERASE_TIMEOUT;

	ret = spi_claim_bus(&(flash->spi.slave));
	if (ret) {
		cvmcs_printf("SF: unable to claim SPI bus\n");
		return ret;
	}

	ret = spi_flash_cmd_write_enable(flash);
	if (ret < 0) {
		cvmcs_printf("SF: enabling write failed\n");
		return ret;
	}

	ret = spi_flash_cmd_write(spi, cmd, cmd_len, buf, buf_len);
	if (ret < 0) {
		cvmcs_printf("SF: write cmd failed\n");
		return ret;
	}

	ret = spi_flash_cmd_wait_ready(flash, timeout);
	if (ret < 0) {
		cvmcs_printf("SF: write %s timed out\n",
			     timeout == SPI_FLASH_PROG_TIMEOUT ?
			     "program" : "page erase");
		return ret;
	}

	spi_release_bus(spi);

	return ret;
}

int spi_flash_cmd_write_ops(struct spi_flash *flash, u32 offset,
			    size_t len, const void *buf)
{
	unsigned long byte_addr, page_size;
	size_t chunk_len, actual;
	u8 cmd[5];
	int ret = -1;

	page_size = flash->page_size;

	cmd[0] = CMD_PAGE_PROGRAM;
	for (actual = 0; actual < len; actual += chunk_len) {
		byte_addr = offset % page_size;
		chunk_len = min(len - actual, page_size - byte_addr);

		if (flash->spi.slave.max_write_size)
			chunk_len =
			    min(chunk_len, flash->spi.slave.max_write_size);

		spi_flash_addr(flash, offset, cmd);

		ret = spi_flash_write_common(flash, cmd,
					     spi_flash_cmd_size(flash),
					     buf + actual, chunk_len);
		if (ret < 0) {
			cvmcs_printf("SF: write failed\n");
			break;
		}

		offset += chunk_len;
	}

	return ret;
}

int spi_flash_cmd_erase_ops(struct spi_flash *flash, u32 offset, size_t len)
{
	u32 erase_size;
	u8 cmd[5];
	int ret = -1;

	erase_size = flash->erase_size;
	if (offset % erase_size || len % erase_size) {
		cvmcs_printf
		    ("SF: Erase offset/length not multiple of erase size\n");
		return -1;
	}

	cmd[0] = flash->erase_cmd;
	while (len) {
		spi_flash_addr(flash, offset, cmd);

		ret = spi_flash_write_common(flash, cmd,
					     spi_flash_cmd_size(flash),
					     NULL, 0);
		if (ret < 0) {
			cvmcs_printf("SF: erase failed\n");
			break;
		}

		offset += erase_size;
		len -= erase_size;
	}

	return ret;
}

int spi_flash_read_common(struct spi_flash *flash, const u8 *cmd,
			  size_t cmd_len, void *data, size_t data_len)
{
	struct spi_slave *spi = &(flash->spi.slave);
	int ret;

	ret = spi_claim_bus(&(flash->spi.slave));
	if (ret) {
		cvmcs_printf("SF: unable to claim SPI bus\n");
		return ret;
	}

	ret = spi_flash_cmd_read(spi, cmd, cmd_len, data, data_len);
	if (ret < 0) {
		cvmcs_printf("SF: read cmd failed\n");
		return ret;
	}

	spi_release_bus(spi);

	return ret;
}

int spi_flash_cmd_read_ops(struct spi_flash *flash, u32 offset,
			   size_t len, void *data)
{
	u8 cmd[6], bank_sel = 0;
	u32 remain_len, read_len;
	int ret = -1;

	cmd[0] = CMD_READ_ARRAY_FAST;
	cmd[flash->addr_width + 1] = 0x00;

	while (len) {
		remain_len = (SPI_FLASH_16MB_BOUN * (bank_sel + 1)) - offset;
		if (len < remain_len)
			read_len = len;
		else
			read_len = remain_len;

		spi_flash_addr(flash, offset, cmd);

		ret = spi_flash_read_common(flash, cmd,
					    spi_flash_cmd_size(flash) + 1,
					    data, read_len);
		if (ret < 0) {
			cvmcs_printf("SF: read failed\n");
			break;
		}

		offset += read_len;
		len -= read_len;
		data += read_len;
	}

	return ret;
}

static inline int is_out_of_bound(uint32_t offset, uint32_t len)
{
	uint32_t fdump_end;

	fdump_end = fdump.fw_dump_flash_base + fdump.fw_dump_flash_size;
	if ((offset < fdump.fw_dump_flash_base) || ((offset + len) > fdump_end))
		return 1;

	return 0;
}

int cvmcs_nic_update_flash(uint32_t offset, char *ptr, int len)
{
	int alignment, a_offset, cpy_len, erase_size;
	/* Assume erase size 4K */
	char rbuf[4096];

	erase_size = flash.erase_size;
	/* Front */
	alignment = offset % erase_size;
	if (alignment) {
		a_offset = (offset - alignment);
		if (is_out_of_bound(a_offset, erase_size)) {
			cvmcs_printf("update fail, offset out of bounds\n");
			return -1;
		}
		spi_flash_cmd_read_ops(&flash, a_offset, erase_size, rbuf);
		spi_flash_cmd_erase_ops(&flash, a_offset, erase_size);
		cpy_len = erase_size - alignment;
		cpy_len = (len > cpy_len) ? cpy_len : len;
		memcpy(rbuf + alignment, ptr, cpy_len);
		spi_flash_cmd_write_ops(&flash, a_offset, erase_size, rbuf);
		ptr += cpy_len;
		offset += cpy_len;
		len -= cpy_len;
	}

	while (len >= erase_size) {
		if (is_out_of_bound(offset, erase_size)) {
			cvmcs_printf("update fail, offset out of bounds\n");
			return -1;
		}
		spi_flash_cmd_erase_ops(&flash, offset, erase_size);
		spi_flash_cmd_write_ops(&flash, offset, erase_size, ptr);
		ptr += erase_size;
		offset += erase_size;
		len -= erase_size;
	}

	/* Tail */
	if (len) {
		if (is_out_of_bound(offset, erase_size)) {
			cvmcs_printf("update fail, offset out of bounds\n");
			return -1;
		}
		spi_flash_cmd_read_ops(&flash, offset, erase_size, rbuf);
		spi_flash_cmd_erase_ops(&flash, offset, erase_size);
		memcpy(rbuf, ptr, len);
		spi_flash_cmd_write_ops(&flash, offset, erase_size, rbuf);
	}

	return 0;
}

/************************************************************************
 *                  |                   |                   |
 *  FWDUMP_BUF_SIZE | Crash log[core 0] | Crash log[core 1] |
 *      (log)       | (register dump    | (register dump    | (...)
 *                  |  back trace)      |  back trace)      |
 ************************************************************************/
int cvmcs_nic_flash_put_log(char *ptr, int len)
{
	cvmcs_nic_update_flash(ABS_OFFSET(0), ptr, len);
	CVMX_SYNCWS;
	return 0;
}

int cvmcs_nic_flash_put_dump(char *ptr, int len)
{
	int core = cvmx_get_core_num();

	cvmcs_nic_update_flash(ABS_OFFSET(FWDUMP_BUF_SIZE +
					  core * sizeof(struct crash)),
			       ptr, len);
	CVMX_SYNCWS;
	return 0;
}

int cvmcs_nic_flash_get(void *buf, int offset, int len)
{
	if (fdump.fw_dump_flag == LIO_NO_CRASH_DUMP)
		return -1;

	spi_flash_cmd_read_ops(&flash, ABS_OFFSET(offset), len, buf);
	return 0;
}

extern int cvmcs_uboot_request_get(int ifidx, char *envariable, uint32_t *val);
int cvmcs_nic_setup_flash_dump(int ctx_size)
{
	int ret;
	uint32_t required;

	memset(&fdump, 0, sizeof(fdump));
	ret = cvmcs_uboot_request_get(0, "fw_dump_flash_base",
			&fdump.fw_dump_flash_base);
	if (ret == 0) {
		cvmcs_uboot_request_get(0, "fw_dump_flash_size",
				&fdump.fw_dump_flash_size);
	} else {
		DBG2("%s: FW dump in flash not enabled\n", __func__);
		fdump.fw_dump_flag = LIO_NO_CRASH_DUMP;
		return -1;
	}

	/* See if the fwdump be placed in flash */
	required = FWDUMP_BUF_SIZE + ctx_size;
	if (required > fdump.fw_dump_flash_size) {
		DBG2("Not enough space in the flash...! %d %d\n", required,
		     fdump.fw_dump_flash_size);
		fdump.fw_dump_flag = LIO_NO_CRASH_DUMP;
		return -1;
	}

	fdump.fw_dump_flag = LIO_CRASH_DUMP;
	cvmx_spinlock_init(&flash_dump_lock);
	/* Probe Flash */
	cvmcs_spi_flash_probe();

	return 0;
}

int cvmcs_nic_set_flash_dump_params(struct flash_dump_params *params)
{
	if (params->fw_dump_flag == LIO_CRASH_DUMP) {
		if (!fdump.fw_dump_flash_base || !fdump.fw_dump_flash_size)
			return -1;
	}

	/* Only dump flag is changed */
	fdump.fw_dump_flag = params->fw_dump_flag;
	return 0;
}

int cvmcs_nic_get_flash_dump_params(struct flash_dump_params *params)
{
	if ((fdump.fw_dump_flag == LIO_NO_CRASH_DUMP)
	    || (fdump.fw_dump_flag == LIO_CRASH_DUMP)) {
		memcpy(params, &fdump, sizeof(struct flash_dump_params));
		return 0;
	}

	/* Flash dump not supported */
	return -1;
}

/* Called from the exception handler */
void cvmcs_nic_flash_put_fwdump(int core, char *clog, int clog_sz, char *fwdbuf)
{
	if (fdump.fw_dump_flag == LIO_CRASH_DUMP) {
		cvmcs_nic_flash_put_dump(clog, clog_sz);
		cvmx_spinlock_lock(&flash_dump_lock);
		if (!flash_log_done) {
			cvmcs_nic_flash_put_log((char *)(fwdbuf),
						FWDUMP_BUF_SIZE);
			flash_log_done = 1;
		}
		CVMX_SYNCW;
		cvmx_spinlock_unlock(&flash_dump_lock);
	}
}
