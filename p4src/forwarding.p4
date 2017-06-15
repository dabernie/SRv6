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

#define IFINDEX_FLOOD 65535
//------------------------------------------------------------------------------
// Metadata Header
//------------------------------------------------------------------------------

header_type l3_metadata_t {
  fields {
    version : 4;
    proto : 8;
    l4_sport : 16;
    l4_dport : 16;
    ipv4_da : 32;
    ipv4_sa : 32;
    ipv6_da : 128;
    ipv6_sa : 128;
    flow_label : 16;
    vrf : 16;             /* VRF */
    nexthop : 16;         /* Nexthop index */
    hash : 16;
  }
}

header_type l2_metadata_t {
  fields {
    mac_sa : 48;
    mac_da : 48;
    bd : 16;
  }
}

header_type tunnel_metadata_t {
  fields {
    index : 16;
  }
}

@pragma pa_container_size ingress l3_metadata.ipv6_da 32
metadata l3_metadata_t l3_metadata;
metadata l2_metadata_t l2_metadata;
metadata tunnel_metadata_t tunnel_metadata;

//------------------------------------------------------------------------------
//  Source MAC lookup
//------------------------------------------------------------------------------
table smac {
  reads {
    l2_metadata.bd : exact;
    l2_metadata.mac_sa : exact;
  }
  actions {
    smac_miss;
    smac_hit;
  }
}

action smac_miss() {
  // TODO
}

action smac_hit() {
  // TODO
}



//------------------------------------------------------------------------------
//  Destination MAC lookup
//------------------------------------------------------------------------------
table dmac {
  reads {
    l2_metadata.bd : exact;
    l2_metadata.mac_da : exact;
  }
  actions {
    dmac_hit;
    dmac_miss;
    dmac_drop;
  }
  size : MAC_TABLE_SIZE;
  support_timeout: true;
}

action dmac_hit(ifindex) {
  modify_field(ingress_metadata.egress_ifindex, ifindex);
}

action dmac_miss() {
  // TODO
}

action dmac_drop() {
  drop();
}

//------------------------------------------------------------------------------
//  RMAC lookup
//------------------------------------------------------------------------------
table rmac {
  reads {
    l2_metadata.mac_da : exact;
  }
  actions {
    rmac_hit;
    rmac_miss;
  }
  size : ROUTER_MAC_TABLE_SIZE;
}

action rmac_hit() {
}

action rmac_miss() {
}

//------------------------------------------------------------------------------
// IPv4 and IPv6 L3 Forwarding
//------------------------------------------------------------------------------
table ipv6_fib {
  reads {
    l3_metadata.vrf : exact;
    l3_metadata.ipv6_da : exact;
  }
  actions {
    miss_;
    set_nexthop_index;
  }
  size : IPV6_HOST_TABLE_SIZE;
}

table ipv6_fib_lpm {
  reads {
    l3_metadata.vrf : exact;
    l3_metadata.ipv6_da : lpm;
  }
  actions {
    set_nexthop_index;
  }
  size : IPV4_LPM_TABLE_SIZE;
}

table ipv4_fib {
  reads {
    l3_metadata.vrf : exact;
    l3_metadata.ipv4_da : exact;
  }
  actions {
    miss_;
    set_nexthop_index;
  }
  size : IPV4_HOST_TABLE_SIZE;
}

table ipv4_fib_lpm {
  reads {
    l3_metadata.vrf : exact;
    l3_metadata.ipv4_da : lpm;
  }
  actions {
    set_nexthop_index;
  }
  size : IPV4_LPM_TABLE_SIZE;
}

action set_nexthop_index(index) {
  modify_field(l3_metadata.nexthop, index);
}

action miss_() {
}

//------------------------------------------------------------------------------
//  Nexthop lookup
//------------------------------------------------------------------------------
table nexthop {
  reads {
    l3_metadata.nexthop : exact;
  }
  action_profile : l3_action_profile;
  size : ECMP_GROUP_TABLE_SIZE;
}

action_profile l3_action_profile {
  actions {
    set_nexthop_info;
    set_tunnel_info;
  }
  size : ECMP_SELECT_TABLE_SIZE;
  dynamic_action_selection: ecmp_selector;
}

action_selector ecmp_selector {
  selection_key : ecmp_hash;
  selection_mode : fair;
}

action set_nexthop_info(bd, dmac) {
  modify_field(l2_metadata.bd, bd);
  modify_field(l2_metadata.mac_da, dmac);
  modify_field(ethernet.dstAddr, dmac);
  modify_field(tunnel_metadata.index, 0);
}

action set_tunnel_info(bd, dmac, index) {
  modify_field(l2_metadata.bd, bd);
  modify_field(l2_metadata.mac_da, dmac);
  modify_field(tunnel_metadata.index, index);
  // modify_field(ethernet.dstAddr, dmac);
}

//------------------------------------------------------------------------------
// LAG lookup/resolution
//------------------------------------------------------------------------------
table lag_group {
  reads {
    ingress_metadata.egress_ifindex : exact;
  }
  action_profile: lag_action_profile;
  size : LAG_SELECT_TABLE_SIZE;
}

action_profile lag_action_profile {
  actions {
    set_lag_miss;
    set_lag_port;
  }
  size : LAG_GROUP_TABLE_SIZE;
  dynamic_action_selection : lag_selector;
}

action set_lag_port(port) {
    modify_field(ig_intr_md_for_tm.ucast_egress_port, port);
}

action set_lag_miss() {
}

action_selector lag_selector {
  selection_key : lag_hash;
  selection_mode : fair;
}

field_list_calculation lag_hash {
  input {
    lag_hash_fields;
  }

  algorithm : crc16;
  output_width : 14;
}

field_list lag_hash_fields {
  //TODO add more fields
  l2_metadata.mac_sa;
  l2_metadata.mac_da;
}

//------------------------------------------------------------------------------
// Field List Definitions and Hash computation
//------------------------------------------------------------------------------
field_list ipv4_hash_fields {
  l3_metadata.ipv4_da;
  l3_metadata.ipv4_sa;
  l3_metadata.proto;
  l3_metadata.l4_sport;
  l3_metadata.l4_dport;
}

field_list ipv6_hash_fields {
  l3_metadata.ipv6_da;
  l3_metadata.ipv6_sa;
  l3_metadata.proto;
  l3_metadata.flow_label;
  l3_metadata.l4_sport;
  l3_metadata.l4_dport;
}

field_list l3_hash_fields {
    l3_metadata.hash;
}

field_list_calculation ipv4_hash {
  input {
    ipv4_hash_fields;
  }
  algorithm : crc16;
  output_width : 16;
}

field_list_calculation ipv6_hash {
  input {
    ipv6_hash_fields;
  }
  algorithm : crc16;
  output_width : 16;
}

field_list_calculation ecmp_hash {
  input {
    l3_hash_fields;
  }
  algorithm : identity;
  output_width : 14;
}

action compute_ipv4_hash() {
    modify_field_with_hash_based_offset(l3_metadata.hash, 0,
                                        ipv4_hash, 65536);
}

action compute_ipv6_hash() {
    modify_field_with_hash_based_offset(l3_metadata.hash, 0,
                                        ipv6_hash, 65536);
}

table compute_hash {
  reads {
    l3_metadata.version : exact;
    ethernet : valid;
  }
  actions {
    compute_ipv4_hash;
    compute_ipv6_hash;
  }
}

//------------------------------------------------------------------------------
// L2 Forwarding
//------------------------------------------------------------------------------
control process_l2_forwarding {
  apply(smac);

  apply(dmac);
}

//------------------------------------------------------------------------------
// L3 Forwarding
//------------------------------------------------------------------------------
control process_ipv6_fib {
  apply(ipv6_fib) {
    miss_ {
      apply(ipv6_fib_lpm);
    }
  }
}

control process_ipv4_fib {
  apply(ipv4_fib) {
    miss_ {
      apply(ipv4_fib_lpm);
    }
  }
}

control process_l3_forwarding {
  apply(compute_hash);

  if (l3_metadata.version == IP_VERSION_IPV4) {
    process_ipv4_fib();
  } else {
    if (l3_metadata.version == IP_VERSION_IPV6) {
      process_ipv6_fib();
    }
  }
}
