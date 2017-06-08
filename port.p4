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


//------------------------------------------------------------------------------
// Ingress port lookup
//------------------------------------------------------------------------------
table ingress_port_mapping {
  reads {
    ig_intr_md.ingress_port : exact;
  }
  actions {
    set_ifindex;
  }
  size : PORTMAP_TABLE_SIZE;
}

table port_vlan_mapping {
  reads {
    ingress_metadata.ifindex : exact;
    vlan_tag[0] : valid;
    vlan_tag[0].vid : exact;
    vlan_tag[1] : valid;
    vlan_tag[1].vid : exact;
  }
  action_profile : bd_action_profile;
  size : PORT_VLAN_TABLE_SIZE;
}

action_profile bd_action_profile {
    actions {
      set_bd_properties;
    }
    size : BD_TABLE_SIZE;
}
action set_ifindex(ifindex) {
  modify_field(ingress_metadata.ifindex, ifindex);
}

action set_bd_properties(bd, vrf) {
  modify_field(l3_metadata.vrf, vrf);
  modify_field(l2_metadata.bd, bd);
}

//------------------------------------------------------------------------------
// Egress port lookup
//------------------------------------------------------------------------------
table egress_port_mapping {
  reads {
    eg_intr_md.egress_port : exact;
  }
  actions {
    set_egress_ifindex;
  }
}

action set_egress_ifindex(ifindex) {
  modify_field(egress_metadata.ifindex, ifindex);
}

//------------------------------------------------------------------------------
//  Egress VLAN decap
//------------------------------------------------------------------------------
action remove_vlan_single_tagged() {
  modify_field(ethernet.etherType, vlan_tag[0].etherType);
  remove_header(vlan_tag[0]);
}

action remove_vlan_double_tagged() {
  modify_field(ethernet.etherType, vlan_tag[1].etherType);
  remove_header(vlan_tag[0]);
  remove_header(vlan_tag[1]);
}

table vlan_decap {
  reads {
    vlan_tag[0].valid : ternary;
    vlan_tag[1].valid : ternary;
  }
  actions {
    remove_vlan_single_tagged;
    remove_vlan_double_tagged;
  }
}

//------------------------------------------------------------------------------
// Egress VLAN translation
//------------------------------------------------------------------------------
table egress_vlan_xlate {
  reads {
    egress_metadata.ifindex: exact;
    l2_metadata.bd : exact;
  }
  actions {
    set_egress_packet_vlan_untagged;
    set_egress_packet_vlan_tagged;
    set_egress_packet_vlan_double_tagged;
  }
}

action set_egress_packet_vlan_double_tagged(s_tag, c_tag) {
    add_header(vlan_tag[1]);
    add_header(vlan_tag[0]);
    modify_field(vlan_tag[1].etherType, ethernet.etherType);
    modify_field(vlan_tag[1].vid, c_tag);
    modify_field(vlan_tag[0].etherType, ETHERTYPE_VLAN);
    modify_field(vlan_tag[0].vid, s_tag);
    modify_field(ethernet.etherType, ETHERTYPE_QINQ);
}

action set_egress_packet_vlan_tagged(vlan_id) {
    add_header(vlan_tag[0]);
    modify_field(vlan_tag[0].etherType, ethernet.etherType);
    modify_field(vlan_tag[0].vid, vlan_id);
    modify_field(ethernet.etherType, ETHERTYPE_VLAN);
}

action set_egress_packet_vlan_untagged() {
}


control process_ingress_port_mapping {
  if (ig_intr_md.resubmit_flag == 0) {
    apply(ingress_port_mapping);
  }

  apply(port_vlan_mapping);
}
