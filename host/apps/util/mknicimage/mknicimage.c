/***********************license start************************************
 * Copyright (c) 2003-2014 Cavium Inc. (support@cavium.com). All rights
 * reserved.
 *
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *	 * Redistributions of source code must retain the above copyright
 *	   notice, this list of conditions and the following disclaimer.
 *
 *	 * Redistributions in binary form must reproduce the above
 *	   copyright notice, this list of conditions and the following
 *	   disclaimer in the documentation and/or other materials provided
 *	   with the distribution.
 *
 *	 * Neither the name of Cavium Inc. nor the names of
 *	   its contributors may be used to endorse or promote products
 *	   derived from this software without specific prior written
 *	   permission.
 *
 * TO THE MAXIMUM EXTENT PERMITTED BY LAW, THE SOFTWARE IS PROVIDED "AS IS"
 * AND WITH ALL FAULTS AND CAVIUM NETWORKS MAKES NO PROMISES, REPRESENTATIONS
 * OR WARRANTIES, EITHER EXPRESS, IMPLIED, STATUTORY, OR OTHERWISE, WITH
 * RESPECT TO THE SOFTWARE, INCLUDING ITS CONDITION, ITS CONFORMITY TO ANY
 * REPRESENTATION OR DESCRIPTION, OR THE EXISTENCE OF ANY LATENT OR PATENT
 * DEFECTS, AND CAVIUM SPECIFICALLY DISCLAIMS ALL IMPLIED (IF ANY) WARRANTIES
 * OF TITLE, MERCHANTABILITY, NONINFRINGEMENT, FITNESS FOR A PARTICULAR
 * PURPOSE, LACK OF VIRUSES, ACCURACY OR COMPLETENESS, QUIET ENJOYMENT, QUIET
 * POSSESSION OR CORRESPONDENCE TO DESCRIPTION.  THE ENTIRE RISK ARISING OUT
 * OF USE OR PERFORMANCE OF THE SOFTWARE LIES WITH YOU.
 *
 *
 * For any questions regarding licensing please contact marketing@cavium.com
 *
 **********************license end**************************************/

/**
 * @file
 *
 * Utility to make a NIC firmware image
 *
 * $Id$
 *
 *
 */
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <errno.h>
#include <sys/stat.h>
#include <stdint.h>
#include <linux/types.h>
#include <stdbool.h>

#ifdef __LITTLE_ENDIAN
#define __CAVIUM_BYTE_ORDER __CAVIUM_LITTLE_ENDIAN
#else
#define __CAVIUM_BYTE_ORDER __CAVIUM_BIG_ENDIAN
#endif

typedef uint8_t  u8;
typedef int8_t   s8;
typedef uint16_t u16;
typedef int16_t  s16;
typedef uint32_t u32;
typedef int32_t  s32;
typedef uint64_t u64;
typedef int64_t  s64;

#include "liquidio_image.h"
#include "octeon_config.h"
#include "liquidio_common.h"
#include "crc32.h"

#ifndef SIZEOF_ARRAY
#define SIZEOF_ARRAY(ary) ((sizeof (ary)) / (sizeof (ary)[0]))
#endif
struct image_work {
	struct octeon_firmware_file_header header;
	char *inputfile[LIO_MAX_IMAGES];
	FILE *ifp[LIO_MAX_IMAGES];
	char *outputfile;
	/* in 'extract_mode', this is overridden as the input file */
	FILE *ofp;
	int verbose;
	int use_embedded;
	int extract_mode;
};

/* these must match UEFI mkupgradeimg.sh script */
#define ImageTypeInvalid    0
#define ImageTypeStage1     1 // ROM stage1
#define ImageTypeStage2     2 // FLASH stage2
#define ImageTypeSEApp      3 // FLASH f/w
#define ImageTypeHostDriver 4 // Host UEFI driver (for upgrade process)
#define ImageTypeBootloader 5 // U-Boot
#define ImageTypeMax        (ImageTypeBootloader)

static void usage(int argc, char * const argv[])
{
	printf("%s --bootcmd bootcmdstring --image inputfile1 --addr addr [--image inputfile2 ...] [--use-embedded] outputfile\n", argv[0]);
	printf("\t- makes an Octeon NIC compatible firmware image\n");
	printf("\t  where bootcmdstring is the quoted string used to boot the image(s),\n");
	printf("\t  inputfile1 is the first image file and addr is the address in hex to load the file,\n");
	printf("\t  (optional --image arguments specify other images),\n");
	printf("\t  and outputfile is the output filename.\n");
	printf("\t  NOTE: Using '--use-embedded' will enable parsing of each 'inputfile'\n");
	printf("\t        as a compatible firmware image. If the specified 'inputfile' is itself\n");
	printf("\t        a firmware file AND a single image is contained therein,\n");
	printf("\t        then the embedded image will be stored into the output.\n");
	printf("   OR:\n\n");
	printf("%s --extract inputfile\n", argv[0]);
	printf("\t- extracts all binary images from an Octeon NIC compatible firmware image\n");
}

/* Parse the command line arguments, and open all files needed for 
 * the work
 */
static int parse_options(int argc, char * const argv[], struct image_work *work)
{
	char option;
	struct octeon_firmware_file_header *h = &work->header;

	const struct option long_options[] =
	{
		{"bootcmd", required_argument, NULL, 'b'},
		{"image", required_argument, NULL, 'i'},
		{"addr", required_argument, NULL, 'l'},
		{"verbose", no_argument, NULL, 'v'},
		{"extract", required_argument, NULL, 'x'},
		{"use-embedded", no_argument, NULL, 'z'},
		{NULL, 0, 0, 0}
	};

	while ((option = getopt_long(argc, argv, "b:i:l:vzx:", long_options, NULL)) != -1)
	{
		switch (option)
		{
		case 'b':
			if (strlen(optarg) >= LIO_MAX_BOOTCMD_LEN) {
				fprintf(stderr, "Error: bootcmd too long (%d > %d)\n",
					(int)strlen(optarg), LIO_MAX_BOOTCMD_LEN-1);
				return 1;
			}
			strcpy(h->bootcmd, optarg);
			break;
		case 'i':
			if (h->num_images == LIO_MAX_IMAGES) {
				fprintf(stderr, "Error: Too many images specified\n");
				usage(argc, argv);
				return 1;
			}
			work->inputfile[h->num_images] = optarg;
			work->ifp[h->num_images] = fopen(optarg, "rb");
			if (NULL == work->ifp[h->num_images]) {
				perror(optarg);
				return 1;
			}
			break;
		case 'l':
			if ((work->inputfile[h->num_images] == NULL) || (h->desc[h->num_images].addr != 0)) {
				fprintf(stderr, "Need to specify image before addr\n");
				usage(argc, argv);
				return 1;
			}

			h->desc[h->num_images].addr = htobe64(strtoul(optarg, NULL, 16));
			h->num_images++;

			break;
		case 'v':
			work->verbose = 1;

			break;

		case 'x':
			work->extract_mode = 1;
			work->inputfile[0] = optarg;
			break;

		case 'z':
			work->use_embedded = 1;
			break;
		default:
			usage(argc, argv);
			return 2;
		}
	}

	if (optind < argc) {
		work->outputfile  = argv[optind];
	}

	/* create_mode is exclusive to extract_mode */
	if (work->extract_mode) {
		if (!!h->bootcmd[0] || !!h->num_images || !work->inputfile[0]) {
			usage(argc, argv);
			return 4;
		}
	} else if ((!h->bootcmd) || (h->num_images == 0) || (!work->outputfile)) {
		usage(argc, argv);
		return 3;
	}

	return 0;
}

/* This function just adds a magic number and version to the header */
static void prefill_header(struct image_work *work)
{
	struct octeon_firmware_file_header *h = &work->header;

	h->magic = htobe32(LIO_NIC_MAGIC);
	sprintf(h->version, "%s", LIQUIDIO_VERSION);
}

/* This allows a specified input file to be an actual 'octeon firmware file'.
 *
 * Check if this image is itself an 'octeon firmware file'.
 * In this case, if a single image is contained therein, 
 * only add the embedded image, NOT the entire firmware file.
 * If multiple images are contained therein, OR the '--use-embedded'
 * behavior is NOT in effect, simply add the [entire] file, as normal.
 *
 * For example, UEFI upgrade images are in the 'octeon firmware file' format, 
 * with several images contained therein.
 * When creating such an image, it can be handy to specify an existing
 * firmware file as the input for one of the images.
 * See the UEFI mkupgradeimg.sh script, option '--firmware'.
 *
 * on entry,
 *  image_ptr: ptr to image on input,
 *             set to embedded image (if found), on output
 *             NOTE: if an embedded image WAS found (return code 0),
 *             the caller must free the ptr returned in this variable.
 *
 *  image_len: length of '*image_ptr' on input
 *             set to length of embedded image (if found) on output
 *
 * returns,
 *  0:        an embedded image WAS found, no errors
 *  ENOENT:   specified image not in 'octeon firmware file' format
 *            NO ERROR, THIS IS THE NORMAL CASE...
 *
 *  -EINVAL:  internal error, invalid parameter specified
 *  -ENOMEM:  an embedded image WAS found, but error allocating memory
 *
 */
static int add_embedded_image(uint8_t **image_ptr, unsigned long *image_len)
{
	struct octeon_firmware_file_header *h;
	uint8_t *emb_img, *alloc_img;
	uint32_t crc32_res, emb_len;
	int ret;

	if (!image_ptr || !*image_ptr || !image_len || !*image_len)
		return -EINVAL;

	/* default to 'not found' */
	ret = ENOENT;

	h = (struct octeon_firmware_file_header *)*image_ptr;
	do {
		/* verify image file header */
		if (h->magic != htobe32(LIO_NIC_MAGIC))
			break;

		crc32_res = crc32(0, h, sizeof(*h) - sizeof(uint32_t));
		if (crc32_res != be32toh(h->crc32))
			break;

		/* verify that only a single image is embedded */
		if (be32toh(h->num_images) != 1)
			break;

		/* verify that embedded image is smaller than image file */
		emb_len = be32toh(h->desc[0].len);
		if (emb_len >= *image_len)
			break;

		/* 1st embedded image is contiguous to hdr */
		emb_img = (uint8_t *)h + sizeof(*h);

		/* verify the crc32 of the embedded image */
		crc32_res = crc32(0, emb_img, emb_len);
		if (crc32_res != be32toh(h->desc[0].crc32))
			break;

		/* return length of embedded image */
		*image_len = emb_len;

		/* Allocate storage for embedded image (already 8B-aligned) */
		alloc_img = (uint8_t *)malloc(sizeof(uint8_t) * emb_len);
		if (alloc_img == NULL) {
			ret = -ENOMEM;
			break;
		}

		/* Copy embedded image, then free the original image 
		 * (i.e. the firmware file image)
		 */
		memcpy(alloc_img, emb_img, emb_len);
		free(*image_ptr);
		*image_ptr = alloc_img;

		ret = 0;
	} while(false);

	return ret;
}

/* This function adds images to the end of the ofp
 * filling in the related desc structure for that file,
 * including crc32.
 */
static int add_image(struct image_work *work, int i)
{
	struct stat st;
	unsigned char *image;
	unsigned long image_len;
	int ret;

	if ((!work) || (!work->ifp[i])) {
		return -EINVAL;
	}

	/* get the length of the input file */
	stat(work->inputfile[i], &st);
	work->header.desc[i].len = st.st_size;

	if (!st.st_size) {
		fprintf(stderr, "Error: File %s is empty\n", work->inputfile[i]);
		return -EINVAL;
	}

	image = (unsigned char* )malloc (sizeof (unsigned char) * (st.st_size + 8));

	if (fread(image, sizeof(unsigned char), st.st_size, work->ifp[i]) != st.st_size) {
		perror(work->inputfile[i]);
		free(image);
		return -EINVAL;
	}

	image_len = st.st_size;

	/* check for embedded image */
	if (work->use_embedded) {
	    	ret = add_embedded_image(&image, &image_len);
		if (ret < 0) {
			if (ret == -ENOMEM)
				fprintf(stderr,
					"Error: out-of-memory for embedded "
					"image (%lu B)\n", image_len);
			perror(work->inputfile[i]);
			if (image)
				free(image);
			return ret;
		} else if (!ret) {
			if (work->verbose)
				printf("Using embedded image from %s (%lu B)\n",
				       work->inputfile[i], image_len);
			/* adjust length if necessary */
			work->header.desc[i].len = image_len;
		}
	}

	/* add 64-bit aligned pad if necessary */
	if (image_len % 8) {
		bzero(image+image_len, 8 - (image_len % 8));
		work->header.desc[i].len += (8 - (image_len % 8));
	}


	work->header.desc[i].crc32 = htobe32(crc32(0, image, work->header.desc[i].len));
	fwrite(image, sizeof(unsigned char), work->header.desc[i].len, work->ofp);

	work->header.desc[i].len = htobe32(work->header.desc[i].len);

	free(image);

	return 0;
}

/*
 * Performs extraction of images into individual files.
 * The output files are named based on the 'inputfile' element,
 * with the load_address appended:
 */
static int extract_images(struct image_work *work)
{
	size_t len;
	int ret, i;
	struct octeon_firmware_file_header *h;
	u32 crc32_result, image_len;
	u64 load_addr;
	u8 *image;
	char ofnambuf[0x100];
	void *ifbuf;
	FILE *ofp;
	struct stat st;

	ifbuf = NULL;

	ret = EINVAL;
	do {
		if (stat(work->inputfile[0], &st)) {
			fprintf(stderr, "Error sizing input file '%s'\n",
				work->inputfile[0]);
			break;
		}

		ifbuf = calloc(st.st_size, sizeof(u8));
		if (ifbuf == NULL) {
			fprintf(stderr, "Error allocating input buffer (%lu)\n",
				st.st_size);
			break;
		}

		work->ifp[0] = fopen(work->inputfile[0], "rb");
		if ( NULL == work->ifp[0]) {
			perror(work->inputfile[0]);
			break;
		}

		if (fread(ifbuf, sizeof(u8), st.st_size, work->ifp[0]) !=
		    st.st_size) {
			fprintf(stderr, "Error reading input file '%s'\n",
			work->inputfile[0]);
			break;
		}

		h = (struct octeon_firmware_file_header *)ifbuf;

		if (htobe32(h->magic) != LIO_NIC_MAGIC) {
			fprintf(stderr, "Input file is not a firmware image\n");
			break;
		}

		crc32_result = crc32(0, h, sizeof(*h) - sizeof(u32));
		if (htobe32(crc32_result) != h->crc32) {
			fprintf(stderr, "Invalid input file header CRC\n");
			break;
		}

		if (htobe32(h->num_images) > LIO_MAX_IMAGES) {
			fprintf(stderr, "Too many images in input file\n");
			break;
		}

		if (h->bootcmd[0])
			fprintf(stdout, "bootcmd: '%s'\n", h->bootcmd);

		/* first image is contiguous to header */
		image = (u8 *)&h[1];

		for (i = 0; i < (int)(htobe32(h->num_images)); i++) {
			load_addr = htobe64(h->desc[i].addr);
			image_len = htobe32(h->desc[i].len);

			snprintf(ofnambuf, sizeof(ofnambuf), "%s_%u_%llx",
			         work->inputfile[0], i, (long long)load_addr);

			/* The UEFI Upgrade Application uses the 'load address'
			 * as a 'type'
			 */
			if (load_addr && (load_addr < 0x100)) {
				static char *LioImageTypes[ImageTypeMax+1] = {
					[ImageTypeInvalid]   = "Invalid",
					[ImageTypeStage1]    = "TypeStage1",
					[ImageTypeStage2]    = "TypeStage2",
					[ImageTypeSEApp]     = "TypeSEApp",
					[ImageTypeHostDriver]= "TypeHostDriver",
					[ImageTypeBootloader]= "TypeBootloader",
				};
				char *type;

				if (load_addr >= SIZEOF_ARRAY(LioImageTypes))
					type = "unknown";
				else
					type = LioImageTypes[(int)load_addr];

				fprintf(stdout,
					"This image appears to be a '%s' "
					"UEFI upgrade component\n", type);

				/* A standard U-Boot image begins with
				 * 'bootloader_header_t', whereas the UEFI
				 * mkupgradeimg.sh script prepends the board
				 * name to the image.  If NOT a standard U-Boot
				 * image, use the board name as part of the
				 * output filename.
				 */
				if ((load_addr == ImageTypeBootloader) &&
				    (strncmp((char *)image+8, "BOOT", 4) != 0)){
					snprintf(ofnambuf, sizeof(ofnambuf),
						 "%s_%u_bootloader_%s",
						 work->inputfile[0], i,
						 (char *)image);
				}
			}

			fprintf(stdout, "Writing image %d of %d (%s)...\n\n",
				i+1, htobe32(h->num_images), ofnambuf);

			ofp = fopen(ofnambuf, "wb");
			if (ofp == NULL) {
				perror(ofnambuf);
			} else {
				len = fwrite(image, sizeof(u8), image_len, ofp);
				if (len != image_len)
					fprintf(stderr,
						"Error writing image.\n");
			}
			fclose(ofp);

			image = (void *)image + image_len;
		}

		ret = 0;
	} while(false);

	if (work->ifp[0]) {
		fclose(work->ifp[0]);
		work->ifp[0] = NULL;
	}

	if (ifbuf) {
		free(ifbuf);
		ifbuf = NULL;
	}

	return ret;
}

/**
 * Main
 *
 * @param argc
 * @param argv
 * @return
 */
int main(int argc, char * const argv[])
{ 
	struct image_work work;
	struct octeon_firmware_file_header *h;
	int i;
	int err = 0;
	uint32_t num_images;

	bzero(&work, sizeof(work));
	h = &work.header;

	prefill_header(&work);

	if (parse_options(argc, argv, &work))
		return -EINVAL;
	
	if (work.extract_mode) {
		return extract_images(&work);
	}

	work.ofp = fopen(work.outputfile, "wb");
	if ( NULL == work.ofp) {
		perror(work.outputfile);
		return -ENOENT;
	}

	num_images = h->num_images;

	if (work.verbose) {
		printf("Creating firmware file '%s' with %d image%s\n  bootcmd='%s'\n",
			work.outputfile, num_images, num_images > 1 ? "s" : "", h->bootcmd);
	}

	/* Write the header. This will be rewritten again after all the images
	 * are written so we can have proper CRCs
	 */
	fwrite(h, sizeof(struct octeon_firmware_file_header), 1, work.ofp);

	for (i=0; i<num_images; i++) {
		if ((err = add_image(&work, i)) < 0) {
			goto cleanup;
		}
		if (work.verbose) {
			printf("  Image %d: %s@0x%016llX crc32=0x%08x\n", i,
				work.inputfile[i], (long long unsigned int) be64toh(h->desc[i].addr),
				be32toh(h->desc[i].crc32));
		}
	}

	h->num_images = htobe32(num_images);

	h->crc32 = htobe32(crc32(0, h, sizeof(struct octeon_firmware_file_header)-sizeof(uint32_t)));

	if (work.verbose) {
		printf("  Header len=%08lx crc32=0x%08x\n",
				sizeof(struct octeon_firmware_file_header)-sizeof(uint32_t), be32toh(h->crc32));
	}

	/* write the header with all values filled in again */
	rewind(work.ofp);
	fwrite(h, sizeof(struct octeon_firmware_file_header), 1, work.ofp);

cleanup:
	for (i=0; i<num_images; i++) {
		fclose(work.ifp[i]);
	}
	fclose(work.ofp);

	return err;
}
