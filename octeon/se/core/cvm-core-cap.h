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
#ifndef __CVM_CORE_CAP_H__
#define __CVM_CORE_CAP_H__

#define IPSEC_OFFLOAD_V2_AUTHENTICATION_NONE	0x00000000
#define IPSEC_OFFLOAD_V2_AUTHENTICATION_MD5	0x00000001
#define IPSEC_OFFLOAD_V2_AUTHENTICATION_SHA_1	0x00000002
#define IPSEC_OFFLOAD_V2_AUTHENTICATION_SHA_256 0x00000004
#define IPSEC_OFFLOAD_V2_AUTHENTICATION_AES_GCM_128 0x00000008
#define IPSEC_OFFLOAD_V2_AUTHENTICATION_AES_GCM_192 0x00000010
#define IPSEC_OFFLOAD_V2_AUTHENTICATION_AES_GCM_256 0x00000020

// IPsec Algorithms for Encryption used in EncryptionAlgorithms field of
// NDIS_IPSEC_OFFLOAD_V2 structure

#define IPSEC_OFFLOAD_V2_ENCRYPTION_NONE 	0x00000001
#define IPSEC_OFFLOAD_V2_ENCRYPTION_DES_CBC 	0x00000002
#define IPSEC_OFFLOAD_V2_ENCRYPTION_3_DES_CBC 	0x00000004
#define IPSEC_OFFLOAD_V2_ENCRYPTION_AES_GCM_128 0x00000008
#define IPSEC_OFFLOAD_V2_ENCRYPTION_AES_GCM_192 0x00000010
#define IPSEC_OFFLOAD_V2_ENCRYPTION_AES_GCM_256 0x00000020
#define IPSEC_OFFLOAD_V2_ENCRYPTION_AES_CBC_128 0x00000040
#define IPSEC_OFFLOAD_V2_ENCRYPTION_AES_CBC_192 0x00000080
#define IPSEC_OFFLOAD_V2_ENCRYPTION_AES_CBC_256 0x00000100

/* IPsec offload (version 2) security association flags */

#define IPSEC_OFFLOAD_V2_ESN_SA 0x00000001L


/* IPsec offload (version 2) add security association flags */
#define IPSEC_OFFLOAD_V2_INBOUND    0x00000001L
#define IPSEC_OFFLOAD_V2_IPv6       0x00000010L
/* IPsec offload (version 2) flags */
#define IPSEC_OFFLOAD_V2_UDP_ESP_ENCAPSULATION_NONE                     0x00000000L
#define IPSEC_OFFLOAD_V2_UDP_ESP_ENCAPSULATION_TRANSPORT                0x00000001L
#define IPSEC_OFFLOAD_V2_UDP_ESP_ENCAPSULATION_TUNNEL                   0x00000002L
#define IPSEC_OFFLOAD_V2_TRANSPORT_OVER_UDP_ESP_ENCAPSULATION_TUNNEL    0x00000004L
#define IPSEC_OFFLOAD_V2_UDP_ESP_ENCAPSULATION_TRANSPORT_OVER_TUNNEL    0x00000008L

extern CVMX_SHARED uint64_t sa_pool_count;

typedef struct ndis_object_header {
  uint8_t  type;
  uint8_t  revision;
  ushort size;
} ndis_object_header, *pndis_object_header;

typedef struct ndis_tcp_ip_checksum_offload {
  struct {
    uint32_t encapsulation;
    uint32_t ipoptionssupported  :2;
    uint32_t tcpoptionssupported  :2;
    uint32_t tcpchecksum  :2;
    uint32_t udpchecksum  :2;
    uint32_t ipchecksum  :2;
  } ipv4transmit;
  struct {
    uint32_t encapsulation;
    uint32_t ipoptionssupported  :2;
    uint32_t tcpoptionssupported  :2;
    uint32_t tcpchecksum  :2;
    uint32_t udpchecksum  :2;
    uint32_t ipchecksum  :2;
  } ipv4receive;
  struct {
    uint32_t encapsulation;
    uint32_t ipextensionheaderssupported  :2;
    uint32_t tcpoptionssupported  :2;
    uint32_t tcpchecksum  :2;
    uint32_t udpchecksum  :2;
  } ipv6transmit;
  struct {
    uint32_t encapsulation;
    uint32_t ipextensionheaderssupported  :2;
    uint32_t tcpoptionssupported  :2;
    uint32_t tcpchecksum  :2;
    uint32_t udpchecksum  :2;
  } ipv6receive;
} ndis_tcp_ip_checksum_offload, *pndis_tcp_ip_checksum_offload;

typedef struct ndis_tcp_large_send_offload_v1 {
  struct {
    uint32_t encapsulation;
    uint32_t maxoffloadsize;
    uint32_t minsegmentcount;
    uint32_t tcpoptions  :2;
    uint32_t ipoptions  :2;
  } ipv4;
} ndis_tcp_large_send_offload_v1, *pndis_tcp_large_send_offload_v1;

typedef struct _ndis_ipsec_offload_v1 {
  struct {
    uint32_t encapsulation;
    uint32_t ahespcombined;
    uint32_t transporttunnelcombined;
    uint32_t ipv4options;
    uint32_t flags;
  } supported;
  struct {
    uint32_t md5  :2;
    uint32_t sha_1  :2;
    uint32_t transport  :2;
    uint32_t tunnel  :2;
    uint32_t send  :2;
    uint32_t receive  :2;
  } ipv4ah;
  struct {
    uint32_t des  :2;
    uint32_t reserved  :2;
    uint32_t tripledes  :2;
    uint32_t nullesp  :2;
    uint32_t transport  :2;
    uint32_t tunnel  :2;
    uint32_t send  :2;
    uint32_t receive  :2;
  } ipv4esp;
} ndis_ipsec_offload_v1, *pndis_ipsec_offload_v1;

typedef struct ndis_tcp_large_send_offload_v2 {
  struct {
    uint32_t encapsulation;
    uint32_t maxoffloadsize;
    uint32_t minsegmentcount;
  } ipv4;
  struct {
    uint32_t encapsulation;
    uint32_t maxoffloadsize;
    uint32_t minsegmentcount;
    uint32_t ipextensionheaderssupported  :2;
    uint32_t tcpoptionssupported  :2;
  } ipv6;
} ndis_tcp_large_send_offload_v2, *pndis_tcp_large_send_offload_v2;

typedef struct ndis_ipsec_offload_v2 {
  uint32_t encapsulation;
  bool ipv6supported;
  bool ipv4options;
  bool ipv6nonipsecextensionheaders;
  bool ah;
  bool esp;
  bool ahespcombined;
  bool transport;
  bool tunnel;
  bool transporttunnelcombined;
  bool lsosupported;
  bool extendedsequencenumbers;
  uint32_t udpesp;
  uint32_t authenticationalgorithms;
  uint32_t encryptionalgorithms;
  uint32_t saoffloadcapacity;
} ndis_ipsec_offload_v2, *pndis_ipsec_offload_v2;


typedef struct ndis_tcp_recv_seg_coalesce_offload {
  struct {
    uint16_t enabled;
  } ipv4;
  struct {
    uint16_t enabled;
  } ipv6;
} ndis_tcp_recv_seg_coalesce_offload, *pndis_tcp_recv_seg_coalesce_offload;

typedef struct ndis_encapsulated_packet_task_offload {
  uint32_t transmitchecksumoffloadsupported  :4;
  uint32_t receivechecksumoffloadsupported  :4;
  uint32_t lsov2supported  :4;
  uint32_t rsssupported  :4;
  uint32_t vmqsupported  :4;
  uint32_t maxheadersizesupported;
} ndis_encapsulated_packet_task_offload, *pndis_encapsulated_packet_task_offload;

/**
 Flags
	A bitwise OR of flags that specify properties that the network adapter supports. The following flags are defined.
	Value								Meaning
	IPSEC_OFFLOAD_V2_AND_TCP_CHECKSUM_COEXISTENCE 0x00000002 	The network adapter supports IPsecV2 and TCP checksums.
	IPSEC_OFFLOAD_V2_AND_UDP_CHECKSUM_COEXISTENCE 0x00000004 	The network adapter supports IPsecV2 and UDP checksums.
**/
typedef struct ndis_offload {
  ndis_object_header                    header;
  ndis_tcp_ip_checksum_offload          checksum;
  ndis_tcp_large_send_offload_v1        lsov1;
  ndis_ipsec_offload_v1                 ipsecv1;
  ndis_tcp_large_send_offload_v2        lsov2;
  uint32_t                              flags;
//#if (ndis_support_ndis61)
  ndis_ipsec_offload_v2                 ipsecv2;
//#endif 
//#if (ndis_support_ndis630)
  ndis_tcp_recv_seg_coalesce_offload    rsc;
  ndis_encapsulated_packet_task_offload encapsulatedpackettaskoffloadgre;
//#endif 
} ndis_offload, *pndis_offload;

void add_nic_features(pndis_offload);
extern CVMX_SHARED ndis_offload nic_cap;

#endif // __CVM_CORE_CAP_H__
