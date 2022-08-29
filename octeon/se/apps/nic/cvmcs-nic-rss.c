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
#include "cvmcs-common.h"
#include "cvmcs-nic.h"
#include  <cvmx-tim.h>
#include "cvmcs-nic-ipv6.h"
#include "cvmcs-nic-ip.h"
#include "cvmcs-nic-rss.h"
#include "cvmcs-nic-mdata.h"

/* PER PORT RSS STATE */
CVMX_SHARED oct_rss_state_t *rss_state;

int cvmcs_alloc_or_find_rss_state_array(void)
{
	if (booting_for_the_first_time) {
		size_t rss_state_array_size;

		rss_state_array_size = MAX_OCTEON_LINKS * sizeof (oct_rss_state_t);

		rss_state = cvmx_bootmem_alloc_named(rss_state_array_size, CVMX_CACHE_LINE_SIZE, "__rss_state");
		if (!rss_state)
			return -1;

		memset(rss_state, 0, rss_state_array_size);

		live_upgrade_ctx->rss_state = rss_state;
	} else {
		rss_state = live_upgrade_ctx->rss_state;
	}

	return 0;
}

#ifdef OCTEON_DEBUG_LEVEL

void dump_hash_key(int ifidx)
{
	int i;
	uint8_t *hash_key_ptr=(uint8_t *)rss_state[ifidx].cnnic_rss_hash_key;

	DBG("hash key dump (%d)\n", rss_state[ifidx].cnnic_rss_hash_key_size);
	for (i = 0; i < rss_state[ifidx].cnnic_rss_hash_key_size;i++)
	{
		DBG("%02x ", hash_key_ptr[i]);
		if (((i % 32) == 0) && (i != 0))
			DBG("\n");
		if (i > OCTNIC_RSS_MAX_KEY_SZ)
		{
			DBG("HK sz %d but dump %d\n",
				rss_state[ifidx].cnnic_rss_hash_key_size,i);
			break;
		}
	}
	DBG("\n");
}

void dump_itable(int ifidx)
{
	int i;
	uint8_t *itable_ptr=(uint8_t *)rss_state[ifidx].cnnic_rss_itable;

	DBG("itable dump (%d)\n", rss_state[ifidx].cnnic_rss_itable_size);
	for (i = 0; i < rss_state[ifidx].cnnic_rss_itable_size;i++)
	{
		DBG("%02x ",itable_ptr[i]);
		if (((i % 32) == 0) && (i != 0))
			DBG("\n");
		if (i > OCTNIC_RSS_MAX_TABLE_SZ)
		{
			DBG("HK sz %d but dump %d\n",
				rss_state[ifidx].cnnic_rss_itable_size,i);
			break;
		}
	}
	DBG("\n");
}
#endif

void cvmcs_print_rss_config(int ifidx)
{
	DBG("[RSS] ifidx = %d HashInfo: Ipv4 %d TcpIPv4 %d Ipv6 %d TcpIPv6 %d Ipv6_Ex %d TcpIPv6_Ex %d\n",
			ifidx,
			(rss_state[ifidx].cnnic_hashinfo & RSS_HASH_IPV4) ? 1 : 0,
			(rss_state[ifidx].cnnic_hashinfo & RSS_HASH_TCP_IPV4) ? 1 : 0,
			(rss_state[ifidx].cnnic_hashinfo & RSS_HASH_IPV6) ? 1 : 0,
			(rss_state[ifidx].cnnic_hashinfo & RSS_HASH_TCP_IPV6) ? 1 : 0,
			(rss_state[ifidx].cnnic_hashinfo & RSS_HASH_IPV6_EX) ? 1 : 0,
			(rss_state[ifidx].cnnic_hashinfo & RSS_HASH_TCP_IPV6_EX) ? 1 : 0);
}

static uint32_t
cvmcs_nic_rss_nible_hash(uint32_t *rss_hash, int index, int nib)
{
	uint32_t hash = 0;

	switch(nib) {
		case 0:
			hash = 0;
			break;
		case 1:
			hash = rss_hash[index + 3];
			break;
		case 2:
			hash = rss_hash[index + 2];
			break;
		case 3:
			hash = rss_hash[index + 2] ^ rss_hash[index + 3];
			break;
		case 4:
			hash = rss_hash[index + 1];
			break;
		case 5:
			hash = rss_hash[index + 1] ^ rss_hash[index + 3];
			break;
		case 6:
			hash = rss_hash[index + 1] ^ rss_hash[index + 2];
			break;
		case 7:
			hash = rss_hash[index + 1] ^ rss_hash[index + 2] ^ rss_hash[index + 3];
			break;
		case 8:
			hash = rss_hash[index];
			break;
		case 9:
			hash = rss_hash[index] ^ rss_hash[index + 3];
			break;
		case 10:
			hash = rss_hash[index] ^ rss_hash[index + 2];
			break;
		case 11:
			hash = rss_hash[index] ^ rss_hash[index + 2] ^ rss_hash[index + 3];
			break;
		case 12:
			hash = rss_hash[index] ^ rss_hash[index + 1];
			break;
		case 13:
			hash = rss_hash[index] ^ rss_hash[index + 1] ^ rss_hash[index + 3];
			break;
		case 14:
			hash = rss_hash[index] ^ rss_hash[index + 1] ^ rss_hash[index + 2];
			break;
		case 15:
			hash = rss_hash[index] ^ rss_hash[index + 1] ^ rss_hash[index + 2] ^ rss_hash[index + 3];
			break;
	}

	return hash;
}

static void
cvmcs_nic_init_rss_hash_table(int ifidx)
{
	int i, j, index;
	int klen = rss_state[ifidx].cnnic_rss_hash_key_size / 4;
	uint64_t K = *(uint64_t *)rss_state[ifidx].cnnic_rss_hash_key;
	uint32_t rss_hash[OCTNIC_RSS_MAX_KEY_SZ * 8];

	for (i = 0; i < klen; i++) {

		for (j = 0; j < 32; j++) {
			rss_hash[i * 32 + j] = (uint32_t)(K >> 32);
			K <<= 1;
		}

		if (i < (klen - 2)) {
			K |= *(uint32_t *)&rss_state[ifidx].cnnic_rss_hash_key[(i + 2) * 4];
		}
	}

	for (i = 0; i < rss_state[ifidx].cnnic_rss_hash_key_size; i++) {

		index = i * 8;

		for (j = 0; j < 16; j++) {

			rss_state[ifidx].cnnic_rss_hash[i * 2][j] = 
				cvmcs_nic_rss_nible_hash(rss_hash, index, j);

			rss_state[ifidx].cnnic_rss_hash[(i * 2) + 1][j] = 
				cvmcs_nic_rss_nible_hash(rss_hash, index + 4, j);
		}
	}

	return;
}

int
cvmcs_nic_set_rss_params(cvmx_wqe_t *wqe, int front_size)
{
	cvmx_raw_inst_front_t *f;
	uint8_t *inp;
	oct_rss_params_t *rss_param_ptr;
	int ifidx;

	f = (cvmx_raw_inst_front_t *) cvmx_phys_to_ptr(wqe->packet_ptr.s.addr);
	inp = (uint8_t *) ((uint8_t *)f + front_size + sizeof(union octnet_cmd));

	rss_param_ptr = (oct_rss_params_t *)inp;
	ifidx = get_vnic_port_id(cvmx_wqe_get_port(wqe));

	/* Check and disable RSS,if directed to do so */
	if (rss_param_ptr->param.flags & RSS_PARAM_DISABLE_RSS) {
		octnic->port[ifidx].state.rss_on = 0;
		DBG("Disabling RSS for port %d",ifidx);
	} else {

		/* HashKey */
		if (!(rss_param_ptr->param.flags & RSS_PARAM_HASH_KEY_UNCHANGED)) {
			if (rss_param_ptr->param.hashkeysize > OCTNIC_RSS_MAX_KEY_SZ) {
				DBG("[ DRV ] Too big rss hash key size; Disabling RSS for port %d",ifidx);
				octnic->port[ifidx].state.rss_on = 0;
				return 0;
			} else {
				rss_state[ifidx].cnnic_rss_hash_key_size =
					rss_param_ptr->param.hashkeysize;
				memcpy(rss_state[ifidx].cnnic_rss_hash_key,
					rss_param_ptr->Key,
					rss_state[ifidx].cnnic_rss_hash_key_size);
				cvmcs_nic_init_rss_hash_table(ifidx);
			}
		}

		/* ITable */
		if (!(rss_param_ptr->param.flags & RSS_PARAM_ITABLE_UNCHANGED)) {
			if (rss_param_ptr->param.itablesize > OCTNIC_RSS_MAX_TABLE_SZ) {
				DBG("[ DRV ] Too big rss Itable size; Disabling RSS for port %d",ifidx);
				octnic->port[ifidx].state.rss_on = 0;
				return 0;
			} else {
				rss_state[ifidx].cnnic_rss_itable_size =
					rss_param_ptr->param.itablesize;
				memcpy(rss_state[ifidx].cnnic_rss_itable,
					rss_param_ptr->Itable,
					rss_state[ifidx].cnnic_rss_itable_size);
				rss_state[ifidx].cnnic_rss_itable_bits =
					cvmx_pop(rss_state[ifidx].cnnic_rss_itable_size - 1);
				rss_state[ifidx].cnnic_rss_hash_mask =
					(uint32_t)((1 << rss_state[ifidx].cnnic_rss_itable_bits) - 1);
			}
		}

		/* HashInfo */
		if (!(rss_param_ptr->param.flags & RSS_PARAM_HASH_INFO_UNCHANGED)) {
			rss_state[ifidx].cnnic_hashinfo = rss_param_ptr->param.hashinfo;
		}

		if (rss_state[ifidx].cnnic_hashinfo &
		    (RSS_HASH_IPV4 | RSS_HASH_TCP_IPV4 | RSS_HASH_IPV6 |
		     RSS_HASH_TCP_IPV6 | RSS_HASH_IPV6_EX | RSS_HASH_TCP_IPV6_EX))
			octnic->port[ifidx].state.rss_on = 1;
		else
			octnic->port[ifidx].state.rss_on = 0;

		cvmcs_print_rss_config(ifidx);
	}

	return 0;
}

/* IPv6 Extention headers parsing */

uint8_t *
find_home_addr(uint8_t *opts)
{
	int len = (opts[1] + 1) << 3;
	int padlen = 0;
	uint8_t found = 0;

	opts += 2;
	len -= 2;

	while (len > 0) {
		int optlen = 0;

		switch (opts[0]) {

		case IPV6_TLV_PAD1:
			optlen = 1;
			padlen++;
			if (padlen > 7)
				goto bad;
			break;

		case IPV6_TLV_PADN:
			padlen += (opts[1] + 2);
			if (padlen > 7)
				goto bad;
			break;
		case IPV6_TLV_HAO:
			optlen = 2;
			found = 1;
			break;

		default:
			// TODO: Support for other options.
			goto bad;
		}
		opts += optlen;
		len -= optlen;

		if (found)
			break;

	}

	return opts;
bad:
	return NULL;
}

uint32_t
cvmcs_nic_rss_get_ext_hdr_info(struct ipv6hdr *ipv6, uint8_t *buf)
{
        uint8_t nexthdr, *exthdr;
	uint8_t *haddr = NULL, *raddr = NULL;
        int exthdrlen, done = 0;
	uint32_t len = 0;
	int count = 1024; /* to make sure we don't get stuck in a loop */

        nexthdr = ipv6->nexthdr;
        exthdr = (uint8_t *)(ipv6 + 1);

	do {
		switch (nexthdr) {
        		case IPV6_EXTH_ROUTING:
				if (exthdr[2] == 2)  { /* If Type II Routing header */
					raddr = (exthdr + 8);
				}
                		nexthdr = exthdr[0];
                		exthdrlen = (exthdr[1] + 1) << 3;
                		exthdr += exthdrlen;
				break;
        		case IPV6_EXTH_DEST_OPT:
				haddr = find_home_addr(exthdr);
                		nexthdr = exthdr[0];
                		exthdrlen = (exthdr[1] + 1) << 3;
                		exthdr += exthdrlen;
				break;
        		case IPV6_EXTH_HOH:
        		case IPV6_EXTH_FRAG:
        		case IPV6_EXTH_ESP:
        		case IPV6_EXTH_AH:
        		case IPV6_EXTH_MOBILITY:
			case IPV6_EXTH_HIP:
			case IPV6_EXTH_SHIM:
			case IPV6_EXTH_EXP1:
			case IPV6_EXTH_EXP2:
                		nexthdr = exthdr[0];
                		exthdrlen = (exthdr[1] + 1) << 3;
                		exthdr += exthdrlen;
				break;
        		case IPV6_EXTH_ICMP:
        		case IPV6_EXTH_TCP:
        		case IPV6_EXTH_UDP:
			case IPV6_EXTH_GRE:
        		case IPV6_EXTH_NNH:
			default :
				done = 1;
				break;
		}
	} while ((!done) && (--count));

	if (haddr != NULL) {
		memcpy(&buf[len], haddr, 16);
		len += 16;
	} else {
		memcpy(&buf[len], (uint8_t *)&ipv6->saddr, 16);
		len += 16;
	}

	if (raddr != NULL) {
		memcpy(&buf[len], raddr, 16);
		len += 16;
	} else {
		memcpy(&buf[len], (uint8_t *)&ipv6->daddr, 16);
		len += 16;
	}

        return len;
}

int
cvmcs_nic_rss_get_queue(cvmx_wqe_t *wqe, uint32_t *hash, uint32_t *hashtype, int ifidx)
{
	uint32_t hashval;
	uint8_t buf[OCTNIC_RSS_MAX_KEY_SZ];
	uint32_t i, len = 0;
	struct iphdr *iph = NULL;
	struct ipv6hdr *ip6h = NULL;
	uint8_t *l4hdr = NULL;
	int is_ipv4 = -1;
	int is_frag = 0;
	int ret = -1;
	cvmcs_nic_metadata_t *mdata = CVMCS_NIC_METADATA(wqe);

	*hashtype = 0;
	*hash = (uint32_t)-1;

	if (CVMCS_NIC_METADATA_IS_TUNNEL(mdata)) {
		if (CVMCS_NIC_METADATA_IS_INNER_TCP(mdata) ||
		    CVMCS_NIC_METADATA_IS_INNER_UDP(mdata)) {
			if (CVMCS_NIC_METADATA_IS_INNER_IPV4(mdata)) {
				iph = (struct iphdr *)CVMCS_NIC_METADATA_INNER_L3_HEADER(mdata);
				l4hdr = (uint8_t *)CVMCS_NIC_METADATA_INNER_L4_HEADER(mdata);
				is_ipv4 = 1;
				is_frag = CVMCS_NIC_METADATA_IS_INNER_IP_FRAG(mdata);
			} else {
				if (CVMCS_NIC_METADATA_IS_INNER_IPV6(mdata)) {
					ip6h = (struct ipv6hdr *)CVMCS_NIC_METADATA_INNER_L3_HEADER(mdata);
					l4hdr = (uint8_t *)CVMCS_NIC_METADATA_INNER_L4_HEADER(mdata);
					is_ipv4 = 0;
					is_frag = CVMCS_NIC_METADATA_IS_INNER_IP_FRAG(mdata);
				}
			}
		}
	}

	if (is_ipv4 == -1) {
		if (CVMCS_NIC_METADATA_IS_IPV4(mdata)) {
			iph = (struct iphdr *)CVMCS_NIC_METADATA_L3_HEADER(mdata);
			is_ipv4 = 1;
			is_frag = CVMCS_NIC_METADATA_IS_IP_FRAG(mdata);
		} else {
			if (CVMCS_NIC_METADATA_IS_IPV6(mdata)) {
				ip6h = (struct ipv6hdr *)CVMCS_NIC_METADATA_L3_HEADER(mdata);
				is_ipv4 = 0;
				is_frag = CVMCS_NIC_METADATA_IS_IP_FRAG(mdata);
			} else {
				DBG("RSS Hash not computed. Not a IP packet\n");
				return ret;
			}
		}

		if (CVMCS_NIC_METADATA_IS_TCP(mdata)) {
			l4hdr = (uint8_t *)CVMCS_NIC_METADATA_L4_HEADER(mdata);
		}
	}

	if (is_ipv4) {
		if (!(rss_state[ifidx].cnnic_hashinfo & (RSS_HASH_IPV4 | RSS_HASH_TCP_IPV4))) {
			DBG("RSS Hash not computed. IPV4 packet\n");
			return ret;
		}

		if (!(rss_state[ifidx].cnnic_hashinfo & RSS_HASH_IPV4) && (l4hdr == NULL)) {
			DBG("RSS Hash not computed. Not a TCP packet\n");
			return ret;
		}

		memcpy(&buf[len], (uint8_t *)&iph->saddr, 8);
		len += 8;
		*hashtype = RSS_HASH_IPV4;

		if ((rss_state[ifidx].cnnic_hashinfo & RSS_HASH_TCP_IPV4) &&
		    !is_frag && (l4hdr != NULL)) {
			memcpy(&buf[len], l4hdr, 4);
			len += 4;
			*hashtype = RSS_HASH_TCP_IPV4;
		}
	} else {
		if (!(rss_state[ifidx].cnnic_hashinfo &
		    (RSS_HASH_IPV6 | RSS_HASH_TCP_IPV6 | RSS_HASH_IPV6_EX | RSS_HASH_TCP_IPV6_EX))) {
			DBG("RSS Hash not computed. IPV6 packet\n");
			return ret;
		}

		if (!(rss_state[ifidx].cnnic_hashinfo & (RSS_HASH_IPV6 | RSS_HASH_IPV6_EX)) && (l4hdr == NULL)) {
			DBG("RSS Hash not computed. Not a TCP packet\n");
			return ret;
		}

		if (rss_state[ifidx].cnnic_hashinfo & (RSS_HASH_IPV6_EX | RSS_HASH_TCP_IPV6_EX)) {
			len += cvmcs_nic_rss_get_ext_hdr_info(ip6h, &buf[len]);
			*hashtype = RSS_HASH_IPV6_EX;
		} else {
			memcpy(&buf[len], (uint8_t *)&ip6h->saddr, 16);
			len += 16;
			memcpy(&buf[len], (uint8_t *)&ip6h->daddr, 16);
			len += 16;
			*hashtype = RSS_HASH_IPV6;
		}

		if ((rss_state[ifidx].cnnic_hashinfo & (RSS_HASH_TCP_IPV6 | RSS_HASH_TCP_IPV6_EX)) && !is_frag && (l4hdr != NULL)) {
			memcpy(&buf[len], l4hdr, 4);
			len += 4;
			if (*hashtype == RSS_HASH_IPV6_EX)
				*hashtype = RSS_HASH_TCP_IPV6_EX;
			else
				*hashtype = RSS_HASH_TCP_IPV6;
		}
	}

	if (len <= 0) {
		DBG("RSS Hash not computed. 4 tuple not found\n");
		return ret;
	}

	hashval = 0;

	for (i = 0; i < len; i++) {
		int index = i * 2;
		hashval ^= rss_state[ifidx].cnnic_rss_hash[index][buf[i] >> 4];
		hashval ^= rss_state[ifidx].cnnic_rss_hash[index + 1][buf[i] & 0x0f];
	}

	DBG("RSS: %s %s packet. tunnel = %d. frag = %d. hashinfo = 0x%4.4x. len = %d, hashtype = 0x%4.4x, hashval = 0x%8.8x\n", 
		(is_ipv4) ? "IPV4" : "IPV6",
		(l4hdr) ? " + TCP" : "",
		CVMCS_NIC_METADATA_IS_TUNNEL(mdata),
		CVMCS_NIC_METADATA_IS_IP_FRAG(mdata),
		rss_state[ifidx].cnnic_hashinfo,
		len,
		*hashtype,
		hashval); 

	*hash = hashval;

	hashval &= rss_state[ifidx].cnnic_rss_hash_mask;

	return rss_state[ifidx].cnnic_rss_itable[hashval];
}
