/***********************license start***************
 * Copyright (c) 2003-2016  Cavium Inc. (support@cavium.com). All rights
 * reserved.
 *
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *
 *   * Redistributions in binary form must reproduce the above
 *     copyright notice, this list of conditions and the following
 *     disclaimer in the documentation and/or other materials provided
 *     with the distribution.

 *   * Neither the name of Cavium Inc. nor the names of
 *     its contributors may be used to endorse or promote products
 *     derived from this software without specific prior written
 *     permission.

 * This Software, including technical data, may be subject to U.S. export  control
 * laws, including the U.S. Export Administration Act and its  associated
 * regulations, and may be subject to export or import  regulations in other
 * countries.

 * TO THE MAXIMUM EXTENT PERMITTED BY LAW, THE SOFTWARE IS PROVIDED "AS IS"
 * AND WITH ALL FAULTS AND CAVIUM INC. MAKES NO PROMISES, REPRESENTATIONS OR
 * WARRANTIES, EITHER EXPRESS, IMPLIED, STATUTORY, OR OTHERWISE, WITH RESPECT TO
 * THE SOFTWARE, INCLUDING ITS CONDITION, ITS CONFORMITY TO ANY REPRESENTATION OR
 * DESCRIPTION, OR THE EXISTENCE OF ANY LATENT OR PATENT DEFECTS, AND CAVIUM
 * SPECIFICALLY DISCLAIMS ALL IMPLIED (IF ANY) WARRANTIES OF TITLE,
 * MERCHANTABILITY, NONINFRINGEMENT, FITNESS FOR A PARTICULAR PURPOSE, LACK OF
 * VIRUSES, ACCURACY OR COMPLETENESS, QUIET ENJOYMENT, QUIET POSSESSION OR
 * CORRESPONDENCE TO DESCRIPTION. THE ENTIRE  RISK ARISING OUT OF USE OR
 * PERFORMANCE OF THE SOFTWARE LIES WITH YOU.
 ***********************license end**************************************/

/**
 * This is a library making use of various U-Boot SE native API
 * features.
 */
#include <ctype.h>
#include "cvmcs-nic.h"
#include "cvmcs-common.h"
#include "cvmx-bootmem.h"
#include "cvmx-sysinfo.h"
#include "cvmx-tlb.h"
#include <asm/arch-octeon/seapi_public.h>


int uboot_seapi_init_handle(struct cvmx_seapi_handle *handle)
{
	cvmx_bootmem_named_block_desc_t *named_block;
	uint64_t named_addr;

	named_addr = cvmx_bootmem_phy_named_block_find(CVMX_SEAPI_NAMED_BLOCK_NAME, 0);
	if (!named_addr)
		return -1;
	named_block = cvmx_phys_to_ptr(named_addr);

	handle->sig_paddr = named_block->base_addr;
	if (!handle->sig_paddr)
		return -1;
	handle->sig = cvmx_phys_to_ptr(handle->sig_paddr);
	if (!handle->sig)
		return -1;
	/* Validate signature */
	if (memcmp(handle->sig->magic, CVMX_SEAPI_SIG_MAGIC,
		   CVMX_SEAPI_SIG_MAGLEN))
		return -1;

	handle->syscall = cvmx_phys_to_ptr(handle->sig->syscall_paddr);
	if (!handle->syscall)
		return -1;

	return 0;
}

/**
 * Gets the major and minor version of the SE API available
 * @param[in]	handle	SE API handle
 * @param[out]	major	Major version
 * @param[out]	minor	Minor version
 *
 * @return	-1 on error, 0 on success
 */
int uboot_seapi_get_version(const struct cvmx_seapi_handle *handle,
			    uint16_t *major, uint16_t *minor)
{
	if (!handle || !handle->sig)
		return -1;

	*major = handle->sig->ver_maj;
	*minor = handle->sig->ver_min;

	return 0;
}

char *uboot_seapi_getenv(const struct cvmx_seapi_handle *handle,
			 const char *env_name,
			 char *buffer, size_t buf_size)
{
	uint64_t env_addr, buf_addr;
	int ret;

	env_addr = cvmx_ptr_to_phys2((void *)env_name);
	buf_addr = cvmx_ptr_to_phys2(buffer);

	ret = handle->syscall(handle->sig_paddr, CVMX_SEAPI_ENV_GET, 0,
			      env_addr, buf_addr, buf_size, 0, 0);
	if (ret)
		return NULL;
	return buffer;
}

int uboot_seapi_setenv(const struct cvmx_seapi_handle *handle,
		       const char *env_name, const char *env_value)
{
	uint64_t env_addr, val_addr;
	uint64_t size;
	int ret;

	env_addr = cvmx_ptr_to_phys2((void *)env_name);
	if (env_value != NULL) {
		val_addr = cvmx_ptr_to_phys2((void *)env_value);
		size = strlen(env_value);
		if (size > CVMX_SEAPI_SETENV_MAX_VALUE_LENGTH)
			size = CVMX_SEAPI_SETENV_MAX_VALUE_LENGTH;
	} else {
		val_addr = 0;
		size = 0;
	}

	ret = handle->syscall(handle->sig_paddr, CVMX_SEAPI_ENV_SET, 0,
			      env_addr, val_addr, size, 0, 0);

	return ret;
}

int uboot_seapi_saveenv(const struct cvmx_seapi_handle *handle)
{
	int ret;

	ret = handle->syscall(handle->sig_paddr, CVMX_SEAPI_ENV_SAVE, 0,
			      0, 0, 0, 0, 0);
	return ret;
}

int uboot_seapi_dev_open_storage(const struct cvmx_seapi_handle *handle,
				 enum cvmx_seapi_storage_dev_type if_type,
				 uint32_t index,
				 int part,
				 enum cvmx_seapi_fs_type fs_type,
				 uint32_t buf_size,
				 struct cvmx_seapi_device_info *sdi)
{
	uint64_t sdi_addr = cvmx_ptr_to_phys2(sdi);
	int ret;
	struct cvmx_seapi_storage_dev_info dev_info;
	uint64_t dev_info_addr;

	dev_info.if_type = if_type;
	dev_info.index = index;
	dev_info.part = part;
	dev_info.fs_type = fs_type;
	dev_info.buf_size = buf_size;

	dev_info_addr = cvmx_ptr_to_phys2(&dev_info);
	printf("%s: Calling syscall at 0x%p, sig addr: 0x%lx\n", __func__,
	       handle->syscall, handle->sig_paddr);
	ret = handle->syscall(handle->sig_paddr, CVMX_SEAPI_DEV_OPEN, 0,
			      dev_info_addr, sdi_addr, 0, 0, 0);

	return ret;
}

int uboot_seapi_dev_close_storage(const struct cvmx_seapi_handle *handle,
				  struct cvmx_seapi_device_info *sdi)
{
	uint64_t sdi_addr = cvmx_ptr_to_phys2(sdi);
	int ret;

	printf("%s: Calling syscall at 0x%p, sig addr: 0x%lx\n", __func__,
	       handle->syscall, handle->sig_paddr);
	ret = handle->syscall(handle->sig_paddr, CVMX_SEAPI_DEV_CLOSE, 0,
			      sdi_addr, 0, 0, 0, 0);

	return ret;
}

int uboot_seapi_dev_enum_storage(const struct cvmx_seapi_handle *handle,
				 struct cvmx_seapi_device_info *sdi,
				 enum cvmx_seapi_storage_dev_type *type,
				 bool *more,
				 bool restart)
{
	uint64_t sdi_addr = cvmx_ptr_to_phys2(sdi);
	int ret;

	if (restart)
		sdi->cookie = 0;

	printf("%s: sdi_addr: 0x%lx, type: %p, sdi: %p\n",
	       __func__, sdi_addr, type, sdi);
	printf("%s: Calling syscall at 0x%p, sig addr: 0x%lx\n", __func__,
	       handle->syscall, handle->sig_paddr);
	ret = handle->syscall(handle->sig_paddr, CVMX_SEAPI_DEV_ENUM, 0,
			      sdi_addr, restart, 0, 0, 0);

	*type = sdi->info.storage.stor_type;
	*more = sdi->more != 0;

	return ret;
}

int uboot_seapi_dev_read(const struct cvmx_seapi_handle *handle,
			 struct cvmx_seapi_device_info *sdi,
			 uint64_t start_block, uint64_t blk_count,
			 void *buffer)
{
	uint64_t sdi_addr = cvmx_ptr_to_phys2(sdi);
	uint64_t buf_addr = cvmx_ptr_to_phys2(buffer);
	int ret;

	printf("%s: Calling syscall(%lx, %d, %d, 0x%lx, 0x%lx, 0x%lx, 0x%lx)\n",
	       __func__, handle->sig_paddr, CVMX_SEAPI_DEV_READ, 0, sdi_addr,
	       start_block, blk_count, buf_addr);
	ret = handle->syscall(handle->sig_paddr, CVMX_SEAPI_DEV_READ, 0,
			      sdi_addr, start_block, blk_count, buf_addr, 0);
	printf("%s: ret: %d\n", __func__, ret);

	if (ret < 0)
		return -1;
	return ret;
}

int uboot_seapi_dev_write(const struct cvmx_seapi_handle *handle,
			 struct cvmx_seapi_device_info *sdi,
			 uint64_t start_block, uint64_t blk_count,
			 void *buffer)
{
	uint64_t sdi_addr = cvmx_ptr_to_phys2(sdi);
	uint64_t buf_addr = cvmx_ptr_to_phys2(buffer);
	int ret;

	printf("%s: Calling syscall(%lx, %d, %d, 0x%lx, 0x%lx, 0x%lx, %lx)\n",
	       __func__, handle->sig_paddr, CVMX_SEAPI_DEV_WRITE, 0, sdi_addr,
	start_block, blk_count, buf_addr);
	ret = handle->syscall(handle->sig_paddr, CVMX_SEAPI_DEV_WRITE, 0,
			      sdi_addr, start_block, blk_count, buf_addr, 0);
	printf("%s: ret: %d\n", __func__, ret);

	if (ret < 0)
		return -1;
	return ret;
}

int uboot_seapi_dev_file_read(const struct cvmx_seapi_handle *handle,
			      struct cvmx_seapi_device_info *sdi,
			      const char *filename,
			      void *buffer, int offset, int len)
{
	int bytes_to_read = len;
	uint64_t sdi_addr = cvmx_ptr_to_phys2(sdi);
	uint64_t filename_addr = cvmx_ptr_to_phys2((void *)filename);
	uint64_t buf_addr = cvmx_ptr_to_phys2(buffer);
	uint64_t len_addr = cvmx_ptr_to_phys2(&bytes_to_read);
	int ret;

	printf("%s: Calling syscall(%lx, %d, %d, 0x%lx, 0x%lx, 0x%lx, 0x%x, 0x%lx)\n",
	       __func__, handle->sig_paddr, CVMX_SEAPI_DEV_FILE_READ, 0,
	       sdi_addr, filename_addr, buf_addr, offset, len_addr);
	ret = handle->syscall(handle->sig_paddr, CVMX_SEAPI_DEV_FILE_READ, 0,
			      sdi_addr, filename_addr, buf_addr, offset,
			      len_addr);
	if (ret < 0)
		return -1;
	return bytes_to_read;
}

int uboot_seapi_dev_file_write(const struct cvmx_seapi_handle *handle,
			       struct cvmx_seapi_device_info *sdi,
			       const char *filename,
			       const void *buffer, int offset, int len)
{
	int bytes_to_write = len;
	uint64_t sdi_addr = cvmx_ptr_to_phys2(sdi);
	uint64_t filename_addr = cvmx_ptr_to_phys2((void *)filename);
	uint64_t buf_addr = cvmx_ptr_to_phys2((void *)buffer);
	uint64_t len_addr = cvmx_ptr_to_phys2(&bytes_to_write);
	int ret;

	ret = handle->syscall(handle->sig_paddr, CVMX_SEAPI_DEV_FILE_WRITE, 0,
			      sdi_addr, filename_addr, buf_addr, offset,
			      len_addr);
	if (ret < 0)
		return -1;
	return bytes_to_write;
}

int uboot_seapi_dev_usb_start(const struct cvmx_seapi_handle *handle)
{
	return handle->syscall(handle->sig_paddr, CVMX_SEAPI_DEV_USB_START, 0,
			       0, 0, 0, 0, 0);
}

int uboot_seapi_dev_init_storage_info(struct cvmx_seapi_device_info *sdi)
{
	memset(sdi, 0, sizeof(*sdi));
	sdi->type = CVMX_SEAPI_DEV_TYPE_STOR;
	return 0;
}

int cvmcs_uboot_request_get(int ifidx, char *envariable, uint32_t *uintval)
{
	int ret = 0;
	struct cvmx_seapi_handle handle;
	char *val=NULL;
	void *buffer = NULL;
	unsigned fpa_node = cvmx_get_node_num();
	cvmx_fpa3_gaura_t aura;
	uint16_t maj_ver = 0, min_ver = 0;

        uint16_t pko_gaura = __cvmx_pko3_aura_get(fpa_node);
        aura = __cvmx_fpa3_gaura(pko_gaura >> 10, pko_gaura & 0x3ff);
        buffer = (char *)cvmx_fpa3_alloc(aura);
        if (buffer == NULL) {
                printf("error unable to alloc buffer \n");
		return -1;
	}

	memset(buffer, 0, 4096);

	ret = uboot_seapi_init_handle(&handle);
	if (ret) {
		printf("Error getting U-Boot SEAPI handle\n");
		ret = -1;
		goto request_get_out;
	}

        ret = uboot_seapi_get_version(&handle, &maj_ver, &min_ver);
        if (ret)
                printf("Error getting version information\n");
        else
                //printf("SE API version %u.%u detected\n", maj_ver, min_ver);

	if (maj_ver >= 1) {
		/* seapi support uboot parameter reading */
		val = uboot_seapi_getenv(&handle, envariable, buffer, 4096);
		if (!val) {
			printf("Could not get environment variable \"%s\"\n", envariable);
			ret = -2;
			goto request_get_out;
		}

		if ((val[0] == '0') && (val[1] == 'x'))
			*uintval = strtoul(val, NULL, 16);
		else
			*uintval = strtoul(val, NULL, 10);
		//printf("%s: \"%s\"=%s, %u\n", __FUNCTION__, envariable, val, *uintval);
	} else {
		ret = -3;
	}

request_get_out:
	cvmx_fpa3_free(buffer, aura, 0);

	return ret;
}

int cvmcs_uboot_request_set(int ifidx, char *envariable, char *sval, uint32_t *uintval)
{
	int ret = 0;
	struct cvmx_seapi_handle handle;
	char *val;
	void *buffer = NULL;
	uint16_t maj_ver = 0, min_ver = 0;
	unsigned fpa_node = cvmx_get_node_num();
	cvmx_fpa3_gaura_t aura;

        uint16_t pko_gaura = __cvmx_pko3_aura_get(fpa_node);
        aura = __cvmx_fpa3_gaura(pko_gaura >> 10, pko_gaura & 0x3ff);
        buffer = (char *)cvmx_fpa3_alloc(aura);
        if (buffer == NULL) {
                printf("error unable to alloc buffer \n");
		return -1;
	}
	
	ret = uboot_seapi_init_handle(&handle);
	if (ret) {
		printf("Error getting U-Boot SEAPI handle\n");
		goto out;
	}

	ret = uboot_seapi_get_version(&handle, &maj_ver, &min_ver);
	if (ret)
		printf("Error getting version information\n");
	else
		//printf("SE API version %u.%u detected\n", maj_ver, min_ver);

	if (maj_ver > 1 || (maj_ver == 1 && min_ver > 0)) {
		/* seapi support uboot parameter writing and reading */
		ret = uboot_seapi_setenv(&handle, envariable, sval);
		if (ret) {
			printf("Failed to set \"%s\"\n", envariable);
			goto out;
		}

		ret = uboot_seapi_saveenv(&handle);
		if (ret) {
			printf("Failed to save the environment\n");
			goto out;
		}
		//printf("set environment variable \"%s\"\n", envariable);
	}

	val = uboot_seapi_getenv(&handle, envariable, buffer, 4096);
	if (!val) {
		printf("Could not get environment variable \"%s\"\n", envariable);
		goto out;
	}
	*uintval = strtoul(val, NULL, 10);
	//printf("%s: \"%s\"=\"%s\" %d, ret=%d\n", __FUNCTION__, envariable, val, *uintval, ret); 
	ret = 0;

out:
	cvmx_fpa3_free(buffer, aura, 0);

	return ret;
}
