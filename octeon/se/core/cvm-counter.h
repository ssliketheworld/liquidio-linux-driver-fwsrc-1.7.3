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

#ifndef  __CVM_COUNTER_H__
#define  __CVM_COUNTER_H__

#define  ENABLE_PROFILING

/* \cond */
typedef struct {
	char        name[32];
	uint64_t    max;
	uint64_t    min;
	uint64_t    total;
	uint64_t    updates;
} cvm_counter_t;

/* \endcond */


#ifdef  ENABLE_PROFILING
static inline void
cvm_counter_update(cvm_counter_t  *s, uint64_t  val64)
{
	if(val64 > s->max)
		s->max = val64;
	if(val64 < s->min)
		s->min = val64;
	s->total += val64;
	s->updates ++;
	CVMX_SYNCW;
}
#else
#define cvm_counter_update(s, val64)  do { }while(0)
#endif


static inline void
cvm_counter_init(cvm_counter_t   *s, char *name)
{
	if(strlen(name))
		strcpy(s->name, name);
	else
		s->name[0] = 0;
	s->max = s->total = s->updates = 0;
	s->min = (uint64_t)-1;
}



#ifdef  ENABLE_PROFILING
static inline void
cvm_counter_print(cvm_counter_t  *s)
{
	printf("%s\n  Updates: %llu Total: %llu Max: %llu  Min: %llu Avg: %llu\n",
		 s->name, CAST64(s->updates), CAST64(s->total), CAST64(s->max),
		 (s->updates)?CAST64(s->min):0, (s->updates)?CAST64(s->total/s->updates):0);
}
#else
#define cvm_counter_print(s)  do { }while(0)
#endif



#endif


/* $Id$ */


