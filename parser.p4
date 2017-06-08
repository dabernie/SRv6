
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
// Protocol Header Definitions
//------------------------------------------------------------------------------
header_type ethernet_t {
    fields {
        dstAddr : 48;
        srcAddr : 48;
        etherType : 16;
    }
}

header_type vlan_tag_t {
  fields {
    pcp : 3;
    cfi : 1;
    vid : 12;
    etherType : 16;
  }
}

header_type mpls_t {
    fields {
        label : 20;
        exp : 3;
        bos : 1;
        ttl : 8;
    }
}

header_type ipv4_t {
    fields {
        version : 4;
        ihl : 4;
        diffserv : 8;
        totalLen : 16;
        identification : 16;
        flags : 3;
        fragOffset : 13;
        ttl : 8;
        protocol : 8;
        hdrChecksum : 16;
        srcAddr : 32;
        dstAddr: 32;
    }
}

header_type ipv6_t {
    fields {
        version : 4;
        trafficClass : 8;
        flowLabel : 20;
        payloadLen : 16;
        nextHdr : 8;
        hopLimit : 8;
        srcAddr : 128;
        dstAddr : 128;
    }
}

header_type ipv6_srh_t {
    fields {
        nextHdr : 8;
        hdrExtLen : 8;
        routingType : 8;
        segLeft : 8;
        firstSeg : 8;
        flags : 8;
        reserved : 16;
    }
}

header_type ipv6_srh_segment_t {
    fields {
        sid : 128;
    }
}

header_type tcp_t {
  fields {
    srcPort : 16;
    dstPort : 16;
    seqNo : 32;
    ackNo : 32;
    dataOffset : 4;
    res : 4;
    flags : 8;
    window : 16;
    checksum : 16;
    urgentPtr : 16;
  }
}

header_type udp_t {
  fields {
    srcPort : 16;
    dstPort : 16;
    length_ : 16;
    checksum : 16;
  }
}

header_type icmp_t {
  fields {
    icmpType: 8;
    code: 8;
    checksum: 16;
  }
}

header_type arp_t {
  fields {
    hwType : 16;
    protoType : 16;
    hwAddrLen : 8;
    protoAddrLen : 8;
    opcode : 16;
    hwSrcAddr : 48;
    protoSrcAddr : 32;
    hwDstAddr : 48;
    protoDstAddr : 32;
  }
}

//------------------------------------------------------------------------------
// Headers and Metadata Declarations
//------------------------------------------------------------------------------
header ethernet_t ethernet;
header ipv4_t ipv4;
@pragma pa_container_size egress ipv6.dstAddr 32
header ipv6_t ipv6;
header icmp_t icmp;
header tcp_t tcp;
header udp_t udp;
header arp_t arp;
header ipv6_srh_t ipv6_srh;
header ipv6_srh_segment_t ipv6_srh_seg_list[SEGMENTS_DEPTH];
header vlan_tag_t vlan_tag[VLAN_DEPTH];
header ipv4_t inner_ipv4;
header ipv6_t inner_ipv6;
header ipv6_srh_t inner_ipv6_srh;
header ipv6_srh_segment_t inner_ipv6_srh_seg_list[SEGMENTS_DEPTH];

//------------------------------------------------------------------------------
// Parsers
//------------------------------------------------------------------------------

parser start {
    return parse_ethernet;
}

parser parse_ethernet {
    extract(ethernet);
    set_metadata(l2_metadata.mac_sa, latest.srcAddr);
    set_metadata(l2_metadata.mac_da, latest.dstAddr);
    return select(latest.etherType) {
        ETHERTYPE_VLAN : parse_vlan;
        ETHERTYPE_ARP  : parse_arp;
        ETHERTYPE_IPV4 : parse_ipv4;
        ETHERTYPE_IPV6 : parse_ipv6;
        default: ingress;
    }
}

parser parse_vlan {
  extract(vlan_tag[next]);
  return select(latest.etherType) {
    ETHERTYPE_VLAN : parse_vlan;
    ETHERTYPE_IPV4 : parse_ipv4;
    ETHERTYPE_IPV6 : parse_ipv6;
    default: ingress;
  }
}

parser parse_ipv4 {
  extract(ipv4);
  set_metadata(l3_metadata.ipv4_sa, latest.srcAddr);
  set_metadata(l3_metadata.ipv4_da, latest.dstAddr);
  set_metadata(l3_metadata.version, 0x4);
  return select(ipv4.protocol) {
    IP_PROTOCOLS_ICMP : parse_icmp;
    IP_PROTOCOLS_TCP  : parse_tcp;
    IP_PROTOCOLS_UDP  : parse_udp;
    default: ingress;
  }
}

parser parse_ipv6 {
  extract(ipv6);
  return select(ipv6.nextHdr) {
    IP_PROTOCOLS_ICMPV6 : parse_icmp;
    IP_PROTOCOLS_TCP    : parse_tcp;
    IP_PROTOCOLS_UDP    : parse_udp;
    IP_PROTOCOLS_SR     : parse_ipv6_srh;
    default: ingress;
  }
}

parser parse_tcp {
  extract(tcp);
  return ingress;
}

parser parse_udp {
  extract(udp);
  return select(udp.dstPort) {
    default : ingress;
  }
}

parser parse_icmp {
  extract(icmp);
  return ingress;
}

parser parse_arp {
  extract(arp);
  return ingress;
}

parser parse_ipv6_srh {
  extract(ipv6_srh);
  return select(ipv6_srh.segLeft) {
    1 : set_ipv6_srh_active_segment_0;
    default : parse_ipv6_srh_semgent_0;
  }
}

#define PARSE_SRV6_SEGMENT(curr, next, seg_left)                    \
parser parse_ipv6_srh_semgent_##curr {                              \
  extract(ipv6_srh_seg_list[curr]);                                 \
  return select(ipv6_srh.firstSeg, ipv6_srh.segLeft) {              \
    seg_left mask 0x00ff : set_ipv6_srh_active_segment_##next;      \
    0x##curr##00 mask 0xff00 : parse_srh_next_hdr;                  \
    default : parse_ipv6_srh_semgent_##next;                        \
  }                                                                 \
}                                                                   \
                                                                    \
parser set_ipv6_srh_active_segment_##curr {                         \
    set_metadata(sr_metadata.sid, current(0, 128));                 \
    return parse_ipv6_srh_semgent_##curr##_;                        \
}                                                                   \
                                                                    \
parser parse_ipv6_srh_semgent_##curr##_ {                           \
  extract(ipv6_srh_seg_list[curr]);                                 \
  return select(ipv6_srh.firstSeg) {                                \
    curr : parse_srh_next_hdr;                                      \
    default : parse_ipv6_srh_semgent_##next##_;                     \
  }                                                                 \
}

#define PARSE_SRV6_FIRST_SEGMENT(first)                             \
parser parse_ipv6_srh_semgent_##first##_ {                          \
  extract(ipv6_srh_seg_list[first]);                                \
  return parse_srh_next_hdr;                                        \
}                                                                   \
                                                                    \
parser set_ipv6_srh_active_segment_##first {                        \
    set_metadata(sr_metadata.sid, current(0, 128));                 \
    return parse_ipv6_srh_semgent_##first##_;                       \
}                                                                   \
                                                                    \
parser parse_ipv6_srh_semgent_##first {                             \
  extract(ipv6_srh_seg_list[first]);                                \
  return parse_srh_next_hdr;                                        \
}

PARSE_SRV6_SEGMENT(0, 1, 2)
PARSE_SRV6_SEGMENT(1, 2, 3)
PARSE_SRV6_SEGMENT(2, 3, 4)
PARSE_SRV6_SEGMENT(3, 4, 5)
PARSE_SRV6_FIRST_SEGMENT(4)

parser parse_srh_next_hdr {
    return select(ipv6_srh.nextHdr) {
        IP_PROTOCOLS_IPV6 : parse_inner_ipv6;
        IP_PROTOCOLS_IPV4 : parse_inner_ipv4;
        IP_PROTOCOLS_SR : parse_inner_srh;
        // IP_PROTOCOLS_NONXT : ingress;
        default: ingress;
    }
}

parser parse_inner_ipv6 {
  extract(inner_ipv6);
  set_metadata(l3_metadata.ipv6_sa, latest.srcAddr);
  set_metadata(l3_metadata.ipv6_da, latest.dstAddr);
  set_metadata(l3_metadata.version, 0x6);
  return select(latest.nextHdr) {
    IP_PROTOCOLS_ICMPV6 : parse_icmp;
    IP_PROTOCOLS_TCP : parse_tcp;
    IP_PROTOCOLS_UDP : parse_udp;
    default: ingress;
  }
}

parser parse_inner_ipv4 {
  extract(inner_ipv4);
  set_metadata(l3_metadata.ipv4_sa, latest.srcAddr);
  set_metadata(l3_metadata.ipv4_da, latest.dstAddr);
  set_metadata(l3_metadata.version, 0x4);
  return select(latest.protocol) {
    IP_PROTOCOLS_ICMP : parse_icmp;
    IP_PROTOCOLS_TCP  : parse_tcp;
    IP_PROTOCOLS_UDP  : parse_udp;
    default: ingress;
  }
}

parser parse_inner_srh {
  extract(inner_ipv6_srh);
  set_metadata(ig_prsr_ctrl.parser_counter, inner_ipv6_srh.firstSeg + 1);
  return parse_inner_srh_seg_list;
}

parser parse_inner_srh_seg_list {
  extract(inner_ipv6_srh_seg_list[next]);
  set_metadata(ig_prsr_ctrl.parser_counter, ig_prsr_ctrl.parser_counter - 1);
  return select(ig_prsr_ctrl.parser_counter) {
    0x0 : ingress;
    default : parse_inner_srh_seg_list;
  }
}
