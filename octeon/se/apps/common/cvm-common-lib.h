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
 * the directory: $CNNIC_ROOT/licenses/
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
/**
 * This File contains support for commomon data structure 
 * definitions and other libraries.
 * Following libs and their supporting api routines are 
 * supported:
 * 1) Hashing api framework
 * 2)
 **/
#ifndef   __CVMCS_COMMON_LIB_H__
#define   __CVMCS_COMMON_LIB_H__

#include <stdio.h>
#include "cvmx.h"
#include "cvmx-bootmem.h"

/* Lookup table infrastructure */
typedef struct hash_node {
		struct hash_node *next;
		struct hash_node *prev;
} hash_node_t;


/**
 *  * hash table entry.
 *   */ 
typedef struct hash_entry {
		uint64_t key;        /* key for hash table. */
		void *value;         /* iInfo specific to components*/
} hash_entry_t;

#if 0 
/**     
 *  * Hash bucket node.       
 *    */         

#define NO_HASH_ENTRIES_IN_A_NODE  \
		(CVMX_CACHE_LINE_SIZE / sizeof(struct hash_entry))

typedef struct hash_bucket_node {
		uint32_t free_list;     /*Index of free entries */
		hash_node_t *next;
		hash_entry_t  entries[NO_HASH_ENTRIES_IN_A_NODE - 1];
} hash_bucket_node_t;
#endif

/* Hash API related functions */
/**
 * INIT_HLIST_NODE: Hash Api init hash node
 * */
static inline void 
INIT_HLIST_NODE(hash_node_t *h)
{
	h->next = h->prev = h;
}


/**
 * hash_table_alloc: Hash Api alloc
 * size: Size of the table
 * return: NULL or Hash table
 * */
static inline hash_node_t *
hash_table_alloc(uint32_t size, char *name)
{
	hash_node_t *hash_table;
	uint32_t idx;

	hash_table = (hash_node_t *)cvmx_bootmem_alloc_named((sizeof(hash_node_t))*size ,
			CVMX_CACHE_LINE_SIZE, name);
	if (hash_table == NULL) {
		printf("%s Allocation failed for hash_table\n", __FUNCTION__);
		return NULL;
	}

	memset(hash_table, 0, (sizeof(hash_node_t ))*size);

	for (idx = 0; idx < size; idx++)
		INIT_HLIST_NODE(&hash_table[idx]);

	return hash_table;
}

/**
 * hash_table_free: Hash Api free
 * */
static inline void 
hash_table_free(char *name)
{
	cvmx_bootmem_free_named(name);
}


/**
 * hash_node_del: Hash Api delete hash node
 * */
static inline void 
hash_node_del(hash_node_t *n)
{
	n->next->prev = n->prev;
	n->prev->next = n->next;
}

/**
 * hash_node_insert_head: Hash Api insert at the begining.
 * */
static inline void
hash_node_insert_head(hash_node_t *n, hash_node_t *head)
{
	n->next = head->next;
	head->next = n;
	n->prev = head;
	n->next->prev = n;
}

/**
 * hash_node_insert_tail: Hash Api insert at the end.
 * */
static inline void
hash_node_insert_tail(hash_node_t *n, hash_node_t *head)
{
	head->prev->next = n;
	n->prev = head->prev;
	head->prev = n;
	n->next = head;

}

static inline void 
hash_node_add_behind(hash_node_t *n, hash_node_t *prev)
{
	n->next = prev->next;
	prev->next = n;
	n->prev = prev;
	n->next->prev  = n;
}

static inline int 
hash_list_empty(const hash_node_t *head)
{
	return (head->next == head);
}


#define hlist_entry(ptr, type, member) CVMX_CONTAINTER_OF(ptr,type,member)

/**
 *hash_for_each_node - iterate over list of given type
 *pos:        the type * to use as a loop cursor.
 *head:       the head for your list.
 **/
#define hash_for_each_node(pos, head)                         \
		for (pos = head->next; pos !=head; pos = pos->next)

#endif //  __CVMCS_COMMON_LIB_H__
