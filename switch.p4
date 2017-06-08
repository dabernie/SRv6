/*******************************************************************************
 * BAREFOOT NETWORKS CONFIDENTIAL & PROPRIETARY
 *
 * Copyright (c) 2015-2016 Barefoot Networks, Inc.

 * All Rights Reserved.
 *
 * NOTICE: All information contained herein is, and remains the property of
 * Barefoot Networks, Inc. and its suppliers, if any. The intellectual and
 * technical concepts contained herein are proprietary to Barefoot Networks,
 * Inc.
 * and its suppliers and may be covered by U.S. and Foreign Patents, patents in
 * process, and are protected by trade secret or copyright law.
 * Dissemination of this information or reproduction of this material is
 * strictly forbidden unless prior written permission is obtained from
 * Barefoot Networks, Inc.
 *
 * No warranty, explicit or implicit is provided, unless granted under a
 * written agreement with Barefoot Networks, Inc.
 *
 * $Id: $
 *
 ******************************************************************************/

#include <tofino/constants.p4>
#include <tofino/intrinsic_metadata.p4>
#include <tofino/primitives.p4>

//------------------------------------------------------------------------------
// Global defines
//------------------------------------------------------------------------------
#define ETHERTYPE_VLAN  0x8100
#define ETHERTYPE_IPV4  0x0800
#define ETHERTYPE_ARP   0x0806
#define ETHERTYPE_IPV6  0x86dd
#define ETHERTYPE_MPLS  0x8847
#define ETHERTYPE_QINQ  0x9100


#define IP_PROTOCOLS_ICMP       1
#define IP_PROTOCOLS_IPV4       4
#define IP_PROTOCOLS_TCP        6
#define IP_PROTOCOLS_UDP        17
#define IP_PROTOCOLS_IPV6       41
#define IP_PROTOCOLS_SR         43
#define IP_PROTOCOLS_ICMPV6     58
#define IP_PROTOCOLS_NONXT      59
#define IP_PROTOCOLS_ETHERIP    97

#define IP_VERSION_IPV4 4
#define IP_VERSION_IPV6 6

#define VLAN_DEPTH 2
#define SEGMENTS_DEPTH 5
#define MPLS_DEPTH 16

#define TRUE 1

/* BYPASS LOOKUP */
#define BYPASS_L2  0x1
#define BYPASS_L3  0x2
#define BYPASS_ALL 0xF

#define LOOKUP(l) \
    ((ingress_metadata.bypass & BYPASS_##l) == 0)


//------------------------------------------------------------------------------
// Table sizes
//------------------------------------------------------------------------------
#define ECMP_SELECT_TABLE_SIZE 16384
#define ECMP_GROUP_TABLE_SIZE 1024
#define IPV4_HOST_TABLE_SIZE 16384
#define IPV6_HOST_TABLE_SIZE 8192
#define IPV4_LPM_TABLE_SIZE 8192
#define IPV6_LPM_TABLE_SIZE 4096
#define LAG_GROUP_TABLE_SIZE 1024
#define LAG_SELECT_TABLE_SIZE 1024
#define MAC_TABLE_SIZE 32768
#define ROUTER_MAC_TABLE_SIZE 512
#define PORTMAP_TABLE_SIZE 288
#define PORT_VLAN_TABLE_SIZE 16384
#define BD_TABLE_SIZE 16384

#include "parser.p4"
#include "forwarding.p4"
#include "port.p4"
#include "sr.p4"
#include "rewrite.p4"

header_type ingress_metadata_t {
  fields {
    ifindex : 16;           /* input interface index */
    egress_ifindex : 16;    /* egress interface index */
    bypass : 4;             /* list of lookups to skip */
  }
}

header_type egress_metadata_t {
  fields {
    ifindex : 16;           /* input interface index */
  }
}

metadata egress_metadata_t egress_metadata;
metadata ingress_metadata_t ingress_metadata;

control ingress {
  // input mapping - derive an ifindex
  process_ingress_port_mapping();

  // TODO validate packet

  // sr processing
  process_srv6();

  // L3 forwarding
  apply(rmac) {
    rmac_hit {
      if (LOOKUP(L3)) {
        process_l3_forwarding();
      }
    }
  }

  apply(nexthop);

  // L2 forwarding
  if (LOOKUP(L2)) {
    process_l2_forwarding();
  }

  apply(lag_group);

}

control egress {
  // determine egress port properties
  apply(egress_port_mapping);

  // strip vlan header
  apply(vlan_decap);

  // perform srv6 decap
  process_srv6_decap();

  // apply packet rewrites based on nexthop index
  process_rewrite();

  // perform tunnel encap
  process_srv6_encap();

  apply(egress_vlan_xlate);

}
