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

#define SRV6_TUNNEL_TERMINATE 0x1
#define SRV6_SEGMENT_POP      0x2
#define SRV6_SRH_INSERT       0x4
#define SRV6_TUNNEL_ENCAP     0x8

header_type sr_metadata_t {
  fields {
    sid : 128;        /* active segment Id, set by the parser */
    proto : 8;
    len : 16;
    action_ : 4;
  }
}
@pragma pa_container_size ingress sr_metadata.sid 32
metadata sr_metadata_t sr_metadata;

//------------------------------------------------------------------------------
// SR SID lookup
//------------------------------------------------------------------------------
// Based on SRv6 Network Programming
// https://tools.ietf.org/html/draft-filsfils-spring-srv6-network-programming-01
table srv6_local_sid {
  reads {
    ipv6.dstAddr : lpm;
    ipv6_srh.valid : ternary;
    ipv6_srh.segLeft : ternary;
    ipv6_srh.nextHdr : ternary;
  }
  actions {
    drop_;
    transit;           /* T, T.INSERT, T.ENCAPS */
    end;               /* END */
    end_psp;           /* END with penultimate segment pop */
    end_usp;           /* END with ultimate segment pop */
    end_x;             /* END.X */
    end_t;             /* END.T */
    end_dx2;           /* END.DX2 */
    end_dx4;           /* END.DX4 */
    end_dx6;           /* END.DX6 */
    end_dt4;           /* END.DT4 */
    end_dt6;           /* END.DT6 */
    end_b6;            /* END.B6 */
    end_b6_encaps;     /* END.B6.ENCAPS */
  }
}

table srv6_transit {
  reads {
    ipv6.dstAddr : lpm;
  }
  actions {
    t;
    t_insert;
    t_encaps;
  }
}

action drop_() {
  drop();
}

action transit() {
}

action t() {
  // Modify L3 lookup fields
  set_l3_fields(ipv6.srcAddr, ipv6.dstAddr, ipv6.nextHdr, 0x6);
}

action t_insert(sid) {
  modify_field(sr_metadata.action_, SRV6_SRH_INSERT);
  set_l3_fields(ipv6.srcAddr, sid, ipv6.nextHdr, 0x6);
}

action t_encaps(srcAddr, dstAddr, flowLabel) {
  modify_field(sr_metadata.action_, SRV6_TUNNEL_ENCAP);
  set_l3_fields(srcAddr, dstAddr, IP_PROTOCOLS_SR, 0x6);
}

action end() {
  // Modify L3 fib lookup fields using active semgent SRH[SL]
  set_l3_fields(
    ipv6.srcAddr, sr_metadata.sid, ipv6.nextHdr, 0x6);
  add_to_field(ipv6_srh.segLeft, -1);            /* decrement SL */
  modify_field(ipv6.dstAddr, sr_metadata.sid);   /* update the IPv6 DA with SRH[SL] */
}

action end_usp() {
  modify_field(ig_intr_md_for_tm.ucast_egress_port, 0); //XXX(MILAD): Recirc port
  modify_field(ingress_metadata.bypass, BYPASS_ALL);
  modify_field(sr_metadata.action_, SRV6_SEGMENT_POP);
}

action end_psp() {
  // Modify L3 fib lookup fields using active semgent SRH[SL]
  set_l3_fields(
    ipv6.srcAddr, sr_metadata.sid, ipv6.nextHdr, 0x6);
  add_to_field(ipv6_srh.segLeft, -1);
  modify_field(ipv6.dstAddr, sr_metadata.sid);
  modify_field(sr_metadata.action_, SRV6_SEGMENT_POP);
}

action end_x(nexthop) {
  // Endpoint with cross-connect to an array of layer-3 adjacencies.
  modify_field(l3_metadata.nexthop, nexthop);
  modify_field(ingress_metadata.bypass, BYPASS_L3);
  add_to_field(ipv6_srh.segLeft, -1);            /* decrement SL */
  modify_field(ipv6.dstAddr, sr_metadata.sid);   /* update the IPv6 DA with SRH[SL] */
}

action end_t(vrf) {
  set_l3_fields(
    ipv6.srcAddr, ipv6.dstAddr, ipv6.nextHdr, 0x6);
  modify_field(l3_metadata.vrf, vrf);            /* table associated with the SID */
  add_to_field(ipv6_srh.segLeft, -1);            /* decrement SL */
  modify_field(ipv6.dstAddr, sr_metadata.sid);   /* update the IPv6 DA with SRH[SL] */
}

action end_dx2(ifindex) {
  // Endpoint with decapsulation and Layer-2 cross-connect to OIF.
  modify_field(sr_metadata.action_, SRV6_TUNNEL_TERMINATE);
  modify_field(ingress_metadata.egress_ifindex, ifindex);
  modify_field(ingress_metadata.bypass, BYPASS_ALL);
}

action end_dx4(nexthop) {
  // Endpoint with decapsulation and cross-connect to an array of IPv4
  // adjacencies.
  modify_field(sr_metadata.action_, SRV6_TUNNEL_TERMINATE);
  modify_field(l3_metadata.nexthop, nexthop);
  modify_field(ingress_metadata.bypass, BYPASS_L3);
}

action end_dx6(nexthop) {
  // Endpoint with decapsulation and cross-connect to an array of IPv6
  // adjacencies.
  modify_field(sr_metadata.action_, SRV6_TUNNEL_TERMINATE);
  modify_field(l3_metadata.nexthop, nexthop);
  modify_field(ingress_metadata.bypass, BYPASS_L3);
}

action end_dt4(vrf) {
  // Endpoint with decapsulation and specific IPv4 table lookup.
  modify_field(sr_metadata.action_, SRV6_TUNNEL_TERMINATE);
  modify_field(l3_metadata.vrf, vrf);
  // Other L3 lookup fields are set by parser
  modify_field(l3_metadata.proto, inner_ipv4.protocol);
}

action end_dt6(vrf) {
  // Endpoint with decapsulation and specific IPv6 table lookup.
  modify_field(sr_metadata.action_, SRV6_TUNNEL_TERMINATE);
  modify_field(l3_metadata.vrf, vrf);            /* table associated with the SID */     
  // Other L3 lookup fields are set by parser
  modify_field(l3_metadata.proto, inner_ipv6.nextHdr);
  //modify_field(l3_metadata.flow_label, inner_ipv6.flowLabel);
}

action end_b6(sid) {
  // Endpoint bound to an SRv6 Policy.
  // XXX : assume first segment of the new SRH is bound to END. Need
  // a second lookup or flattened out lookup to support other functions.
  modify_field(sr_metadata.action_, SRV6_SRH_INSERT);
  // Modify L3 lookup field base on first segment of the SRv6 Policy
  set_l3_fields(ipv6.srcAddr, sid, ipv6.nextHdr, 0x6);
  modify_field(ipv6.dstAddr, sid);
}

action end_b6_encaps(sid) {
  // Endpoint bound to an SRv6 encapsulation policy.
  // XXX : assume first segment of the new SRH is bound to END. Need
  // a second lookup or flattened out lookup to support other functions.
  modify_field(sr_metadata.action_, SRV6_TUNNEL_ENCAP);
  set_l3_fields(ipv6.srcAddr, sid, ipv6.nextHdr, 0x6);
  add_to_field(ipv6_srh.segLeft, -1);            /* decrement SL */
  modify_field(ipv6.dstAddr, sr_metadata.sid);   /* update the IPv6 DA with SRH[SL] */
}

//------------------------------------------------------------------------------
// Helper actions
//------------------------------------------------------------------------------
action set_l3_fields(srcAddr, dstAddr, proto, version) {
  modify_field(l3_metadata.ipv6_sa, srcAddr);
  modify_field(l3_metadata.ipv6_da, dstAddr);
  modify_field(l3_metadata.proto, proto);
  //modify_field(l3_metadata.flow_label, flowLabel);
  modify_field(l3_metadata.version, version);
}

action set_l2_fields(srcAddr, dstAddr) {
  modify_field(l2_metadata.mac_sa, srcAddr);
  modify_field(l2_metadata.mac_da, dstAddr);
}

action calculate_srh_total_len(total_len) {
  // Precomputed values for SRH total length.
  // total_len = (ipv6_srh.hdrExtLen << 3) + 8
  add_to_field(sr_metadata.len, total_len);
}

table process_srh_len {
  reads {
    ipv6_srh : valid;
    ipv6_srh.hdrExtLen : exact;
  }
  actions {
    calculate_srh_total_len;
  }
}

//------------------------------------------------------------------------------
// SR tunnel decap
//------------------------------------------------------------------------------
// Based on sr_metadata.action_ it either removes the IPv6 and it extension or
// only removes the extension header.
table srv6_decap {
  reads {
    sr_metadata.action_ : exact;
    inner_ipv4.valid : ternary;
    inner_ipv6.valid : ternary;
  }
  actions {
    decap_inner_non_ip;
    decap_inner_ipv4;
    decap_inner_ipv6;
    pop_ipv6_srh;
  }
}

action decap_inner_non_ip() {
  remove_header(ethernet);
  remove_header(ipv6);
  remove_srh();
}

action decap_inner_ipv4() {
  modify_field(ethernet.etherType, ETHERTYPE_IPV4);
  copy_header(ipv4, inner_ipv4);
  remove_header(inner_ipv4);
  remove_header(ipv6);
  remove_srh();
}

action decap_inner_ipv6() {
  modify_field(ethernet.etherType, ETHERTYPE_IPV6);
  copy_header(ipv6, inner_ipv6);
  remove_header(inner_ipv6);
  remove_srh();
}

action pop_ipv6_srh() {
  modify_field(ipv6.nextHdr, ipv6_srh.nextHdr);
  subtract_from_field(ipv6.payloadLen, sr_metadata.len);
  remove_srh();
}

action remove_srh() {
  remove_header(ipv6_srh);
  remove_header(ipv6_srh_seg_list[0]);
  remove_header(ipv6_srh_seg_list[1]);
  remove_header(ipv6_srh_seg_list[2]);
  remove_header(ipv6_srh_seg_list[3]);
  remove_header(ipv6_srh_seg_list[4]);
}

//------------------------------------------------------------------------------
// SR tunnel encap
//------------------------------------------------------------------------------
table srv6_encap_inner {
  reads {
    sr_metadata.action_ : exact;
    ipv6_srh : valid;
    ipv4 : valid;
    ipv6 : valid;
  }
  actions {
    inner_ipv4_rewrite;
    inner_ipv6_rewrite;
    inner_ipv6_srh_rewrite;
    inner_srh_rewrite;
    inner_non_ip_rewrite;
  }
}

table srv6_encap_outer {
  reads {
    sr_metadata.action_ : exact;
    l3_metadata.nexthop : exact;
  }
  actions {
    ip_srv6_rewrite_1; // SRH with 1 segment
    ip_srv6_rewrite_2; // SRH with 2 segments
    ip_srv6_rewrite_3; // SRH with 3 segments
    // XXX not supported in 5.0.0 
    // ip_srv6_rewrite_4; // SRH with 4 segments
    // ip_srv6_rewrite_5; // SRH with 5 segments
    srv6_rewrite_1; // SRH with 1 segment
    srv6_rewrite_2; // SRH with 2 segments
    srv6_rewrite_3; // SRH with 3 segments
    // XXX not supported in 5.0.0 
    // srv6_rewrite_4; // SRH with 4 segments
    // srv6_rewrite_5; // SRH with 5 segments
  }
}

table srv6_rewrite {
  reads {
    l3_metadata.nexthop : exact;
  }
  actions {
    set_tunnel_rewrite;
  }
}

action inner_ipv4_rewrite() {
    copy_header(inner_ipv4, ipv4);
    remove_header(ipv4);
    modify_field(sr_metadata.len, ipv4.totalLen);
    modify_field(sr_metadata.proto, IP_PROTOCOLS_IPV4);
}

action inner_ipv6_rewrite() {
    copy_header(inner_ipv6, ipv6);
    remove_header(ipv6);
    add(sr_metadata.len, ipv6.payloadLen, 40);
    modify_field(sr_metadata.proto, IP_PROTOCOLS_IPV6);
}

action inner_ipv6_srh_rewrite() {
    copy_header(inner_ipv6, ipv6);
    copy_srh_header();
    remove_header(ipv6);
    remove_srh(); // Remove outer SRH
    add(sr_metadata.len, ipv6.payloadLen, 40);
    modify_field(sr_metadata.proto, IP_PROTOCOLS_IPV6);
}

action inner_srh_rewrite() {
    copy_srh_header(); // Copy outer SRH to inner SRH
    remove_srh(); // Remove outer SRH
    modify_field(sr_metadata.len, ipv6.payloadLen);
    modify_field(sr_metadata.proto, IP_PROTOCOLS_SR);
}

action inner_non_ip_rewrite() {
  // copy_header(inner_ethernet, ethernet);
  add(sr_metadata.len, eg_intr_md.pkt_length, -14);
  modify_field(sr_metadata.proto, IP_PROTOCOLS_NONXT);
}

action ip_srv6_rewrite_1(len, first_seg, seg_left, sid0) {
  // Insert IPv6 header + SRH with 1 segment.
  modify_field(ethernet.etherType, ETHERTYPE_IPV6);
  insert_ipv6_header(IP_PROTOCOLS_SR);
  srv6_rewrite_1(len, first_seg, seg_left, sid0);  
}
 
action srv6_rewrite_1(len, first_seg, seg_left, sid0) {
  // Insert SRH with 1 segment.
  add(ipv6.payloadLen, sr_metadata.len, 24);
  insert_ipv6_srh(sr_metadata.proto, len, first_seg, seg_left);
  add_header(ipv6_srh_seg_list[0]);
  modify_field(ipv6_srh_seg_list[0].sid, sid0);
}

action ip_srv6_rewrite_2(len, first_seg, seg_left, sid0, sid1) {
  // Insert IPv6 header + SRH with 2 segments.
  modify_field(ethernet.etherType, ETHERTYPE_IPV6);
  insert_ipv6_header(IP_PROTOCOLS_SR);
  srv6_rewrite_2(len, first_seg, seg_left, sid0, sid1);
}

action srv6_rewrite_2(len, first_seg, seg_left, sid0, sid1) {
  // Insert SRH with 2 segments.
  add(ipv6.payloadLen, sr_metadata.len, 40);
  insert_ipv6_srh(sr_metadata.proto, len, first_seg, seg_left);
  add_header(ipv6_srh_seg_list[0]);
  add_header(ipv6_srh_seg_list[1]);
  modify_field(ipv6_srh_seg_list[0].sid, sid0);
  modify_field(ipv6_srh_seg_list[1].sid, sid1);
}

action ip_srv6_rewrite_3(len, first_seg, seg_left, sid0, sid1, sid2) {
  // Insert IPv6 header + SRH with 3 segments.
  modify_field(ethernet.etherType, ETHERTYPE_IPV6);
  insert_ipv6_header(IP_PROTOCOLS_SR);
  srv6_rewrite_3(len, first_seg, seg_left, sid0, sid1, sid2);
}

action srv6_rewrite_3(len, first_seg, seg_left, sid0, sid1, sid2) {
  // Insert SRH with 3 segments.
  add(ipv6.payloadLen, sr_metadata.len, 56);
  insert_ipv6_srh(sr_metadata.proto, len, first_seg, seg_left);
  add_header(ipv6_srh_seg_list[0]);
  add_header(ipv6_srh_seg_list[1]);
  add_header(ipv6_srh_seg_list[2]);
  modify_field(ipv6_srh_seg_list[0].sid, sid0);
  modify_field(ipv6_srh_seg_list[1].sid, sid1);
  modify_field(ipv6_srh_seg_list[2].sid, sid2);
}

action srv6_rewrite_4(len, first_seg, seg_left, sid0, sid1, sid2, sid3) {
  add(ipv6.payloadLen, sr_metadata.len, 72);
  insert_ipv6_srh(sr_metadata.proto, len, first_seg, seg_left);
  add_header(ipv6_srh_seg_list[0]);
  add_header(ipv6_srh_seg_list[1]);
  add_header(ipv6_srh_seg_list[2]);
  add_header(ipv6_srh_seg_list[3]);
  modify_field(ipv6_srh_seg_list[0].sid, sid0);
  modify_field(ipv6_srh_seg_list[1].sid, sid1);
  modify_field(ipv6_srh_seg_list[2].sid, sid2);
  modify_field(ipv6_srh_seg_list[3].sid, sid3);
}

action srv6_rewrite_5(len, first_seg, seg_left, sid0, sid1, sid2, sid3, sid4) {
  add(ipv6.payloadLen, sr_metadata.len, 88);
  insert_ipv6_srh(sr_metadata.proto, len, first_seg, seg_left);
  add_header(ipv6_srh_seg_list[0]);
  add_header(ipv6_srh_seg_list[1]);
  add_header(ipv6_srh_seg_list[2]);
  add_header(ipv6_srh_seg_list[3]);
  add_header(ipv6_srh_seg_list[4]);
  modify_field(ipv6_srh_seg_list[0].sid, sid0);
  modify_field(ipv6_srh_seg_list[1].sid, sid1);
  modify_field(ipv6_srh_seg_list[2].sid, sid2);
  modify_field(ipv6_srh_seg_list[3].sid, sid3);
  modify_field(ipv6_srh_seg_list[4].sid, sid4);
}

action set_tunnel_rewrite(smac, dmac, sip, dip) {
  set_l2_addr(smac, dmac);
  set_ipv6_addr(sip, dip);
}

//------------------------------------------------------------------------------
// Helper actions
//------------------------------------------------------------------------------
action set_ipv4_addr(srcAddr, dstAddr) {
  modify_field(ipv4.srcAddr, srcAddr);
  modify_field(ipv4.dstAddr, dstAddr);
}

action set_ipv6_addr(srcAddr, dstAddr) {
  modify_field(ipv6.srcAddr, srcAddr);
  modify_field(ipv6.dstAddr, dstAddr);
}

action set_l2_addr(smac, dmac) {
  modify_field(ethernet.srcAddr, smac);
  modify_field(ethernet.dstAddr, dmac);
}

action insert_ipv6_header(proto) {
  add_header(ipv6);
  modify_field(ipv6.version, 0x6);
  modify_field(ipv6.nextHdr, proto);
  modify_field(ipv6.hopLimit, 64);
  modify_field(ipv6.trafficClass, 0);
  modify_field(ipv6.flowLabel, 0);
}

action insert_ipv6_srh(proto, len, first_seg, seg_left) {
  add_header(ipv6_srh);
  modify_field(ipv6_srh.nextHdr, proto);
  modify_field(ipv6_srh.hdrExtLen, len);
  modify_field(ipv6_srh.routingType, 0x4);
  modify_field(ipv6_srh.segLeft, seg_left);
  modify_field(ipv6_srh.firstSeg, first_seg);
  modify_field(ipv6_srh.flags, 0);
  modify_field(ipv6_srh.reserved, 0);
}

action copy_srh_header() {
  copy_header(inner_ipv6_srh, ipv6_srh);
  copy_header(inner_ipv6_srh_seg_list[0], ipv6_srh_seg_list[0]);
  copy_header(inner_ipv6_srh_seg_list[1], ipv6_srh_seg_list[1]);
  copy_header(inner_ipv6_srh_seg_list[2], ipv6_srh_seg_list[2]);
  copy_header(inner_ipv6_srh_seg_list[3], ipv6_srh_seg_list[3]);
  copy_header(inner_ipv6_srh_seg_list[4], ipv6_srh_seg_list[4]);
}

//------------------------------------------------------------------------------
// SR Processing
//------------------------------------------------------------------------------

// SID lookup
control process_srv6 {
  if (valid(ipv6)) {
    apply(srv6_local_sid) {
      transit {
        apply(srv6_transit);
      }
    }
  }
}

control process_srv6_decap {
  apply(process_srh_len);

  apply(srv6_decap);
}

// Tunnel encapsulation
control process_srv6_encap {
  apply(srv6_encap_inner);
  apply(srv6_encap_outer);
  apply(srv6_rewrite);
}
