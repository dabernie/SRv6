# Copyright 2013-present Barefoot Networks, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
Thrift PD interface basic tests
"""

from collections import OrderedDict, namedtuple

import time
import sys
import logging

import unittest
import random

import pd_base_tests

from ptf import config
from ptf.parse import *
from ptf.testutils import *
from ptf.thriftutils import *

from srv6.p4_pd_rpc.ttypes import *
from res_pd_rpc.ttypes import *

swports = [x for x in range(8)]
device = 0
ig_port = 1
eg_port = 2

IP_PROTOCOLS_IPV4 = 4
IP_PROTOCOLS_UDP = 17
IP_PROTOCOLS_IPV6 = 41
IP_PROTOCOLS_SR = 43
IP_PROTOCOLS_NONXT = 59
IP_PROTOCOLS_ETHERIP = 97

SRV6_TUNNEL_TERMINATE = 0x1
SRV6_SEGMENT_POP = 0x2
SRV6_SRH_INSERT = 0x4
SRV6_TUNNEL_ENCAP = 0x8

class SRv6Test(pd_base_tests.ThriftInterfaceDataPlane):
    ipAddr = namedtuple('ipAddr', 'ip_addr addr_type prefix_len')
    segment = namedtuple('segment', 'sid prefix_len func')

    def __init__(self):
        pd_base_tests.ThriftInterfaceDataPlane.__init__(self, ["srv6"])
        self.bd_handles = {}

    def set_up(self):
        print
        print 'Configuring devices ...'

        ig_ifindex = 1
        eg_ifindex = 2
        ig_bd = 0
        eg_bd = 1
        nexthop = 1
        tunnel_index = 2
        vrf = 1
        rmac = '00:33:33:33:33:33'
        smac = '00:33:33:33:33:33'
        dmac = '00:44:44:44:44:44'

        self.add_default_entries()

        self.create_vlan(ig_bd, vrf)

        # Interface
        self.add_interface(ig_port, ig_bd, ig_ifindex)

        # RMAC
        match_spec = srv6_rmac_match_spec_t(
            l2_metadata_mac_da=macAddr_to_string(rmac))
        self.client.rmac_table_add_with_rmac_hit(
            self.sess_hdl, self.dev_tgt, match_spec)

        # nexthop
        self.add_nexthop(nexthop, eg_bd, dmac)
        self.add_nexthop(tunnel_index, eg_bd, dmac)

        # MAC
        self.add_mac_entry(eg_bd, dmac, eg_ifindex)

        # LAG
        match_spec = srv6_lag_group_match_spec_t(
            ingress_metadata_egress_ifindex=eg_ifindex)
        action_spec = srv6_set_lag_port_action_spec_t(
            action_port=eg_port)
        mbr = self.client.lag_action_profile_add_member_with_set_lag_port(
            self.sess_hdl, self.dev_tgt, action_spec)
        self.client.lag_group_add_entry(
            self.sess_hdl, self.dev_tgt, match_spec, mbr)

        # L2 rewrite
        match_spec = srv6_l2_rewrite_match_spec_t(l2_metadata_bd=eg_bd)
        action_spec = srv6_smac_rewrite_action_spec_t(
            action_smac=macAddr_to_string(smac))
        status = self.client.l2_rewrite_table_add_with_smac_rewrite(
            self.sess_hdl, self.dev_tgt, match_spec, action_spec)
        self.conn_mgr.complete_operations(self.sess_hdl)

    def add_default_entries(self):
        print 'Adding default entries ...'
        # L3 rewrite
        match_spec = srv6_l3_rewrite_match_spec_t(
            ipv6_valid=0x0, ipv4_valid=0x1)
        self.client.l3_rewrite_table_add_with_ipv4_rewrite(
            self.sess_hdl, self.dev_tgt, match_spec)
        match_spec = srv6_l3_rewrite_match_spec_t(
            ipv6_valid=0x1, ipv4_valid=0x0)
        self.client.l3_rewrite_table_add_with_ipv6_rewrite(
            self.sess_hdl, self.dev_tgt, match_spec)

        # Total len calculation
        for len_ in range(-128, 127):
            total_len =  8 * len_ + 8
            action_spec = srv6_calculate_srh_total_len_action_spec_t(
                action_total_len=total_len)
            match_spec = srv6_process_srh_len_match_spec_t(
                ipv6_srh_valid=1, ipv6_srh_hdrExtLen=len_)
            self.client.process_srh_len_table_add_with_calculate_srh_total_len(
                self.sess_hdl, self.dev_tgt, match_spec, action_spec)

        # Hash calculation
        match_spec = srv6_compute_hash_match_spec_t(
            l3_metadata_version=0x4, ethernet_valid=0x1)
        self.client.compute_hash_table_add_with_compute_ipv4_hash(
            self.sess_hdl, self.dev_tgt, match_spec)
        match_spec = srv6_compute_hash_match_spec_t(
            l3_metadata_version=0x6, ethernet_valid=0x1)
        self.client.compute_hash_table_add_with_compute_ipv6_hash(
            self.sess_hdl, self.dev_tgt, match_spec)

        # SRv6 SID lookup
        self.client.srv6_local_sid_set_default_action_transit(
            self.sess_hdl, self.dev_tgt)

        # SRv6 Transit
        self.client.srv6_transit_set_default_action_t(
            self.sess_hdl, self.dev_tgt)

        # SRv6 decapsulation
        match_spec = srv6_srv6_decap_match_spec_t(
            sr_metadata_action_=SRV6_TUNNEL_TERMINATE,
            inner_ipv4_valid_mask=1,
            inner_ipv4_valid=0,
            inner_ipv6_valid_mask=1,
            inner_ipv6_valid=0)
        self.client.srv6_decap_table_add_with_decap_inner_non_ip(
            self.sess_hdl, self.dev_tgt, match_spec, 0)

        match_spec = srv6_srv6_decap_match_spec_t(
            sr_metadata_action_=SRV6_TUNNEL_TERMINATE,
            inner_ipv4_valid_mask=1,
            inner_ipv4_valid=1,
            inner_ipv6_valid_mask=1,
            inner_ipv6_valid=0)
        self.client.srv6_decap_table_add_with_decap_inner_ipv4(
            self.sess_hdl, self.dev_tgt, match_spec, 0)

        match_spec = srv6_srv6_decap_match_spec_t(
            sr_metadata_action_=SRV6_TUNNEL_TERMINATE,
            inner_ipv4_valid_mask=1,
            inner_ipv4_valid=0,
            inner_ipv6_valid_mask=1,
            inner_ipv6_valid=1)
        self.client.srv6_decap_table_add_with_decap_inner_ipv6(
            self.sess_hdl, self.dev_tgt, match_spec, 0)

        match_spec = srv6_srv6_decap_match_spec_t(
            sr_metadata_action_=SRV6_SEGMENT_POP,
            inner_ipv4_valid_mask=0,
            inner_ipv4_valid=0,
            inner_ipv6_valid_mask=0,
            inner_ipv6_valid=0)
        self.client.srv6_decap_table_add_with_pop_ipv6_srh(
            self.sess_hdl, self.dev_tgt, match_spec, 0)

        # SRv6 encapsulation -- inner
        match_spec = srv6_srv6_encap_inner_match_spec_t(
            sr_metadata_action_=SRV6_SRH_INSERT,
            ipv6_srh_valid=1,
            ipv4_valid=0,
            ipv6_valid=1)
        self.client.srv6_encap_inner_table_add_with_inner_srh_rewrite(
            self.sess_hdl, self.dev_tgt, match_spec) 

        match_spec = srv6_srv6_encap_inner_match_spec_t(
            sr_metadata_action_=SRV6_TUNNEL_ENCAP,
            ipv6_srh_valid=1,
            ipv4_valid=0,
            ipv6_valid=1)
        self.client.srv6_encap_inner_table_add_with_inner_ipv6_srh_rewrite(
            self.sess_hdl, self.dev_tgt, match_spec) 
        # TODO add more entries for other cases


        print "Done."


    def create_vlan(self, vlan, vrf):
        action_spec = srv6_set_bd_properties_action_spec_t(
            action_bd=vlan, action_vrf=vrf)
        self.bd_handles[vlan] = \
            self.client.bd_action_profile_add_member_with_set_bd_properties(
                self.sess_hdl, self.dev_tgt, action_spec)


    def add_interface(self, port, vlan, ifindex):
        match_spec = srv6_ingress_port_mapping_match_spec_t(
            ig_intr_md_ingress_port=port)
        action_spec = srv6_set_ifindex_action_spec_t(action_ifindex=ifindex)
        self.client.ingress_port_mapping_table_add_with_set_ifindex(
            self.sess_hdl, self.dev_tgt, match_spec, action_spec)

        # FIXME
        match_spec = srv6_port_vlan_mapping_match_spec_t(
            ingress_metadata_ifindex=ifindex,
            vlan_tag_0__valid=0,
            vlan_tag_0__vid=0,
            vlan_tag_1__valid=0,
            vlan_tag_1__vid=0)
        self.client.port_vlan_mapping_add_entry(
            self.sess_hdl, self.dev_tgt, match_spec, self.bd_handles[vlan])

    def delete_interface(self, port, vlan):
        pass

    def add_nexthop(self, nexthop, bd, dmac):
        match_spec = srv6_nexthop_match_spec_t(l3_metadata_nexthop=nexthop)
        action_spec = srv6_set_nexthop_info_action_spec_t(
            action_bd=bd, action_dmac=macAddr_to_string(dmac))
        mbr = self.client.l3_action_profile_add_member_with_set_nexthop_info(
            self.sess_hdl, self.dev_tgt, action_spec)
        self.client.nexthop_add_entry(
            self.sess_hdl, self.dev_tgt, match_spec, mbr)

    def delete_nexthop_all(self):
        #TODO
        pass

    def add_mac_entry(self, bd, mac, ifindex):
        match_spec = srv6_dmac_match_spec_t(
            l2_metadata_bd=bd, l2_metadata_mac_da=macAddr_to_string(mac))
        action_spec = srv6_dmac_hit_action_spec_t(action_ifindex=ifindex)
        self.client.dmac_table_add_with_dmac_hit(
            self.sess_hdl, self.dev_tgt, match_spec, action_spec, 0)

    def delete_mac_entry(self, bd, mac, ifindex):
        match_spec = srv6_dmac_match_spec_t(
            l2_metadata_bd=bd, l2_metadata_mac_da=mac)
        self.client.dmac_table_delete_by_match_spec(
            self.sess_hdl, self.dev_tgt, match_spec)

    def add_fib_entry(self, vrf, ip, nexthop):
        action_spec = srv6_set_nexthop_index_action_spec_t(
            action_index=nexthop)
        if ip.addr_type == 'Ipv4':
            if ip.prefix_len == 32:
                # Ipv4 Host table
                match_spec = srv6_ipv4_fib_match_spec_t(
                    l3_metadata_vrf=vrf,
                    l3_metadata_ipv4_da=ipv4Addr_to_i32(ip.ip_addr))
                self.client.ipv4_fib_table_add_with_set_nexthop_index(
                    self.sess_hdl, self.dev_tgt, match_spec, action_spec)
            else:
                # Ipv4 LPM
                match_spec = srv6_ipv4_fib_match_spec_t(
                    l3_metadata_vrf=vrf,
                    l3_metadata_ipv4_da=ipv4Addr_to_i32(ip.ip_addr),
                    l3_metadata_ipv4_da_prefix_length=ip.prefix_len)
                self.client.ipv4_fib_lpm_table_add_with_set_nexthop_index(
                    self.sess_hdl, self.dev_tgt, match_spec, action_spec)

        if ip.addr_type == 'Ipv6':
            if ip.prefix_len == 128:
                # Ipv6 Host table
                match_spec = srv6_ipv6_fib_match_spec_t(
                    l3_metadata_vrf=vrf,
                    l3_metadata_ipv6_da=parse_ipv6(ip.ip_addr))
                self.client.ipv6_fib_table_add_with_set_nexthop_index(
                    self.sess_hdl, self.dev_tgt, match_spec, action_spec)
            else:
                # Ipv6 LPM
                match_spec = srv6_ipv6_fib_match_spec_t(
                    l3_metadata_vrf=vrf,
                    l3_metadata_ipv6_da=parse_ipv6(ip.ip_addr),
                    l3_metadata_ipv6_da_prefix_length=ip.prefix_len)
                self.client.ipv6_fib_lpm_table_add_with_set_nexthop_index(
                    self.sess_hdl, self.dev_tgt, match_spec, action_spec)

    def delete_fib_entry(self, vrf, ip):
        if ip.addr_type == 'Ipv4':
            if ip.prefix_len == 32:
                match_spec = srv6_ipv4_fib_match_spec_t(
                    l3_metadata_vrf=vrf,
                    l3_metadata_ipv4_da=ipv4Addr_to_i32(ip.ip_addr))
                self.client.ipv4_fib_table_delete_by_match_spec(
                    self.sess_hdl, self.dev_tgt, match_spec)
            else:
                match_spec = srv6_ipv4_fib_match_spec_t(
                    l3_metadata_vrf=vrf,
                    l3_metadata_ipv4_da=ipv4Addr_to_i32(ip.ip_addr),
                    l3_metadata_ipv4_da_prefix_length=ip.prefix_len)
                self.client.ipv4_fib_lpm_table_delete_by_match_spec(
                    self.sess_hdl, self.dev_tgt, match_spec)

        if ip.addr_type == 'Ipv6':
            if ip.prefix_len == 128:
                match_spec = srv6_ipv6_fib_match_spec_t(
                    l3_metadata_vrf=vrf,
                    l3_metadata_ipv6_da=parse_ipv6(ip.ip_addr))
                self.client.ipv6_fib_table_delete_by_match_spec(
                    self.sess_hdl, self.dev_tgt, match_spec)
            else:
                match_spec = srv6_ipv6_fib_match_spec_t(
                    l3_metadata_vrf=vrf,
                    l3_metadata_ipv6_da=parse_ipv6(ip.ip_addr),
                    l3_metadata_ipv6_da_prefix_length=ip.prefix_len)
                self.client.ipv6_fib_lpm_table_delete_by_match_spec(
                    self.sess_hdl, self.dev_tgt, match_spec)

    def add_local_sid(self,
                      segment,
                      psp=False,
                      nexthop=None,
                      ifindex=None,
                      vrf=None,
                      seg_list=None):
        if segment.func == 'END':
            match_spec = srv6_srv6_local_sid_match_spec_t(
                ipv6_dstAddr=parse_ipv6(segment.sid),
                ipv6_dstAddr_prefix_length=segment.prefix_len,
                ipv6_srh_valid=1,
                ipv6_srh_valid_mask=1,
                ipv6_srh_segLeft=0,
                ipv6_srh_segLeft_mask=-1,
                ipv6_srh_nextHdr=0,
                ipv6_srh_nextHdr_mask=0)
            self.client.srv6_local_sid_table_add_with_drop_(
                self.sess_hdl, self.dev_tgt, match_spec, 0)

            if psp:
                match_spec = srv6_srv6_local_sid_match_spec_t(
                    ipv6_dstAddr=parse_ipv6(segment.sid),
                    ipv6_dstAddr_prefix_length=segment.prefix_len,
                    ipv6_srh_valid=1,
                    ipv6_srh_valid_mask=1,
                    ipv6_srh_segLeft=1,
                    ipv6_srh_segLeft_mask=-1,
                    ipv6_srh_nextHdr=0,
                    ipv6_srh_nextHdr_mask=0)
                self.client.srv6_local_sid_table_add_with_end_psp(
                    self.sess_hdl, self.dev_tgt, match_spec, 0)

            match_spec = srv6_srv6_local_sid_match_spec_t(
                ipv6_dstAddr=parse_ipv6(segment.sid),
                ipv6_dstAddr_prefix_length=segment.prefix_len,
                ipv6_srh_valid=1,
                ipv6_srh_valid_mask=1,
                ipv6_srh_segLeft=0,
                ipv6_srh_segLeft_mask=0,
                ipv6_srh_nextHdr=0,
                ipv6_srh_nextHdr_mask=0)
            self.client.srv6_local_sid_table_add_with_end(
                self.sess_hdl, self.dev_tgt, match_spec, 1)

        elif segment.func == 'END.T':
            pass
        elif segment.func == 'END.X':
            match_spec = srv6_srv6_local_sid_match_spec_t(
                ipv6_dstAddr=parse_ipv6(segment.sid),
                ipv6_dstAddr_prefix_length=segment.prefix_len,
                ipv6_srh_valid=1,
                ipv6_srh_valid_mask=1,
                ipv6_srh_segLeft=0,
                ipv6_srh_segLeft_mask=-1,
                ipv6_srh_nextHdr=0,
                ipv6_srh_nextHdr_mask=0)
            self.client.srv6_local_sid_table_add_with_drop_(
                self.sess_hdl, self.dev_tgt, match_spec, 0)

            action_spec = srv6_end_x_action_spec_t(action_nexthop=nexthop)
            match_spec = srv6_srv6_local_sid_match_spec_t(
                ipv6_dstAddr=parse_ipv6(segment.sid),
                ipv6_dstAddr_prefix_length=segment.prefix_len,
                ipv6_srh_valid=1,
                ipv6_srh_valid_mask=1,
                ipv6_srh_segLeft=0,
                ipv6_srh_segLeft_mask=0,
                ipv6_srh_nextHdr=0,
                ipv6_srh_nextHdr_mask=0)
            self.client.srv6_local_sid_table_add_with_end_x(
                self.sess_hdl, self.dev_tgt, match_spec, 1, action_spec)

        elif segment.func == 'END.DX2':
            action_spec = srv6_end_dx2_action_spec_t(action_ifindex=ifindex)
            match_spec = srv6_srv6_local_sid_match_spec_t(
                ipv6_dstAddr=parse_ipv6(segment.sid),
                ipv6_dstAddr_prefix_length=segment.prefix_len,
                ipv6_srh_valid=1,
                ipv6_srh_valid_mask=1,
                ipv6_srh_segLeft=0,
                ipv6_srh_segLeft_mask=-1,
                ipv6_srh_nextHdr=IP_PROTOCOLS_NONXT,
                ipv6_srh_nextHdr_mask=-1)
            self.client.srv6_local_sid_table_add_with_end_dx2(
                self.sess_hdl, self.dev_tgt, match_spec, 0, action_spec)

            match_spec = srv6_srv6_local_sid_match_spec_t(
                ipv6_dstAddr=parse_ipv6(segment.sid),
                ipv6_dstAddr_prefix_length=segment.prefix_len,
                ipv6_srh_valid=1,
                ipv6_srh_valid_mask=1,
                ipv6_srh_segLeft=0,
                ipv6_srh_segLeft_mask=0,
                ipv6_srh_nextHdr=0,
                ipv6_srh_nextHdr_mask=0)
            self.client.srv6_local_sid_table_add_with_drop_(
                self.sess_hdl, self.dev_tgt, match_spec, 1)

        elif segment.func == 'END.DX6':
            action_spec = srv6_end_dx6_action_spec_t(action_nexthop=nexthop)
            match_spec = srv6_srv6_local_sid_match_spec_t(
                ipv6_dstAddr=parse_ipv6(segment.sid),
                ipv6_dstAddr_prefix_length=segment.prefix_len,
                ipv6_srh_valid=1,
                ipv6_srh_valid_mask=1,
                ipv6_srh_segLeft=0,
                ipv6_srh_segLeft_mask=-1,
                ipv6_srh_nextHdr=IP_PROTOCOLS_IPV6,
                ipv6_srh_nextHdr_mask=-1)
            self.client.srv6_local_sid_table_add_with_end_dx6(
                self.sess_hdl, self.dev_tgt, match_spec, 0, action_spec)

            match_spec = srv6_srv6_local_sid_match_spec_t(
                ipv6_dstAddr=parse_ipv6(segment.sid),
                ipv6_dstAddr_prefix_length=segment.prefix_len,
                ipv6_srh_valid=1,
                ipv6_srh_valid_mask=1,
                ipv6_srh_segLeft=0,
                ipv6_srh_segLeft_mask=0,
                ipv6_srh_nextHdr=0,
                ipv6_srh_nextHdr_mask=0)
            self.client.srv6_local_sid_table_add_with_drop_(
                self.sess_hdl, self.dev_tgt, match_spec, 1)

        elif segment.func == 'END.DT6':
            action_spec = srv6_end_dt6_action_spec_t(action_vrf=vrf)
            match_spec = srv6_srv6_local_sid_match_spec_t(
                ipv6_dstAddr=parse_ipv6(segment.sid),
                ipv6_dstAddr_prefix_length=segment.prefix_len,
                ipv6_srh_valid=1,
                ipv6_srh_valid_mask=1,
                ipv6_srh_segLeft=0,
                ipv6_srh_segLeft_mask=-1,
                ipv6_srh_nextHdr=IP_PROTOCOLS_IPV6,
                ipv6_srh_nextHdr_mask=-1)
            self.client.srv6_local_sid_table_add_with_end_dt6(
                self.sess_hdl, self.dev_tgt, match_spec, 0, action_spec)

            match_spec = srv6_srv6_local_sid_match_spec_t(
                ipv6_dstAddr=parse_ipv6(segment.sid),
                ipv6_dstAddr_prefix_length=segment.prefix_len,
                ipv6_srh_valid=1,
                ipv6_srh_valid_mask=1,
                ipv6_srh_segLeft=0,
                ipv6_srh_segLeft_mask=0,
                ipv6_srh_nextHdr=0,
                ipv6_srh_nextHdr_mask=0)
            self.client.srv6_local_sid_table_add_with_drop_(
                self.sess_hdl, self.dev_tgt, match_spec, 1)

        elif segment.func == 'END.DT4':
            action_spec = srv6_end_dt4_action_spec_t(action_vrf=vrf)
            match_spec = srv6_srv6_local_sid_match_spec_t(
                ipv6_dstAddr=parse_ipv6(segment.sid),
                ipv6_dstAddr_prefix_length=segment.prefix_len,
                ipv6_srh_valid=1,
                ipv6_srh_valid_mask=1,
                ipv6_srh_segLeft=0,
                ipv6_srh_segLeft_mask=-1,
                ipv6_srh_nextHdr=IP_PROTOCOLS_IPV4,
                ipv6_srh_nextHdr_mask=-1)
            self.client.srv6_local_sid_table_add_with_end_dt4(
                self.sess_hdl, self.dev_tgt, match_spec, 0, action_spec)

            match_spec = srv6_srv6_local_sid_match_spec_t(
                ipv6_dstAddr=parse_ipv6(segment.sid),
                ipv6_dstAddr_prefix_length=segment.prefix_len,
                ipv6_srh_valid=1,
                ipv6_srh_valid_mask=1,
                ipv6_srh_segLeft=0,
                ipv6_srh_segLeft_mask=0,
                ipv6_srh_nextHdr=0,
                ipv6_srh_nextHdr_mask=0)
            self.client.srv6_local_sid_table_add_with_drop_(
                self.sess_hdl, self.dev_tgt, match_spec, 1)

        elif segment.func == 'END.DX4':
            action_spec = srv6_end_dx4_action_spec_t(action_nexthop=nexthop)
            match_spec = srv6_srv6_local_sid_match_spec_t(
                ipv6_dstAddr=parse_ipv6(segment.sid),
                ipv6_dstAddr_prefix_length=segment.prefix_len,
                ipv6_srh_valid=1,
                ipv6_srh_valid_mask=1,
                ipv6_srh_segLeft=0,
                ipv6_srh_segLeft_mask=-1,
                ipv6_srh_nextHdr=IP_PROTOCOLS_IPV4,
                ipv6_srh_nextHdr_mask=-1)
            self.client.srv6_local_sid_table_add_with_end_dx4(
                self.sess_hdl, self.dev_tgt, match_spec, 0, action_spec)

            match_spec = srv6_srv6_local_sid_match_spec_t(
                ipv6_dstAddr=parse_ipv6(segment.sid),
                ipv6_dstAddr_prefix_length=segment.prefix_len,
                ipv6_srh_valid=1,
                ipv6_srh_valid_mask=1,
                ipv6_srh_segLeft=0,
                ipv6_srh_segLeft_mask=0,
                ipv6_srh_nextHdr=0,
                ipv6_srh_nextHdr_mask=0)
            self.client.srv6_local_sid_table_add_with_drop_(
                self.sess_hdl, self.dev_tgt, match_spec, 1)

        elif segment.func == 'END.B6':
            sid = parse_ipv6(seg_list[-1])
            action_spec = srv6_end_b6_action_spec_t(action_sid=sid)
            match_spec = srv6_srv6_local_sid_match_spec_t(
                ipv6_dstAddr=parse_ipv6(segment.sid),
                ipv6_dstAddr_prefix_length=segment.prefix_len,
                ipv6_srh_valid=1,
                ipv6_srh_valid_mask=1,
                ipv6_srh_segLeft=0,
                ipv6_srh_segLeft_mask=0,
                ipv6_srh_nextHdr=0,
                ipv6_srh_nextHdr_mask=0)
            self.client.srv6_local_sid_table_add_with_end_b6(
                self.sess_hdl, self.dev_tgt, match_spec, 1, action_spec)

            match_spec = srv6_srv6_local_sid_match_spec_t(
                ipv6_dstAddr=parse_ipv6(segment.sid),
                ipv6_dstAddr_prefix_length=segment.prefix_len,
                ipv6_srh_valid=1,
                ipv6_srh_valid_mask=1,
                ipv6_srh_segLeft=0,
                ipv6_srh_segLeft_mask=-1,
                ipv6_srh_nextHdr=0,
                ipv6_srh_nextHdr_mask=0)
            self.client.srv6_local_sid_table_add_with_drop_(
                self.sess_hdl, self.dev_tgt, match_spec, 0)

        elif segment.func == 'END.B6.ENCAPS':
            sid = parse_ipv6(seg_list[-1])
            action_spec = srv6_end_b6_encaps_action_spec_t(action_sid=sid)
            match_spec = srv6_srv6_local_sid_match_spec_t(
                ipv6_dstAddr=parse_ipv6(segment.sid),
                ipv6_dstAddr_prefix_length=segment.prefix_len,
                ipv6_srh_valid=1,
                ipv6_srh_valid_mask=1,
                ipv6_srh_segLeft=0,
                ipv6_srh_segLeft_mask=0,
                ipv6_srh_nextHdr=0,
                ipv6_srh_nextHdr_mask=0)
            self.client.srv6_local_sid_table_add_with_end_b6_encaps(
                self.sess_hdl, self.dev_tgt, match_spec, 1, action_spec)

            match_spec = srv6_srv6_local_sid_match_spec_t(
                ipv6_dstAddr=parse_ipv6(segment.sid),
                ipv6_dstAddr_prefix_length=segment.prefix_len,
                ipv6_srh_valid=1,
                ipv6_srh_valid_mask=1,
                ipv6_srh_segLeft=0,
                ipv6_srh_segLeft_mask=-1,
                ipv6_srh_nextHdr=0,
                ipv6_srh_nextHdr_mask=0)
            self.client.srv6_local_sid_table_add_with_drop_(
                self.sess_hdl, self.dev_tgt, match_spec, 0)


    def delete_local_sid_all(self):
        try:
            entry = self.client.srv6_local_sid_get_first_entry_handle(
                self.sess_hdl, self.dev_tgt)
        except InvalidTableOperation as e:
            return

        while entry != -1:
            self.client.srv6_local_sid_table_delete(
                self.sess_hdl, device, entry)
            try:
                entry = self.client.srv6_local_sid_get_next_entry_handles(
                self.sess_hdl, device, entry, 1)[0]
            except InvalidTableOperation as e:
                entry = -1

    def add_tunnel_rewrite_entry(self, tunnel_index, smac, dmac, sip, dip):
        action_spec = srv6_set_tunnel_rewrite_action_spec_t(
            action_smac = macAddr_to_string(smac),
            action_dmac = macAddr_to_string(dmac),
            action_sip = parse_ipv6(sip),
            action_dip = parse_ipv6(dip))
        match_spec = srv6_srv6_rewrite_match_spec_t(
            l3_metadata_nexthop=tunnel_index)

        self.client.srv6_rewrite_table_add_with_set_tunnel_rewrite(
           self.sess_hdl, self.dev_tgt, match_spec, action_spec)

    def delete_tunnel_rewrite_entry(self, tunnel_index):
        match_spec = srv6_srv6_rewrite_match_spec_t(
            l3_metadata_nexthop=tunnel_index)
        #FIXME
        # self.client.srv6_rewrite_table_delete_by_match_spec(
        #    self.sess_hdl, self.dev_tgt, match_spec)

    def add_tunnel_entry(self, tunnel_index, seg_list):
        # SRv6 encapsulation -- outer
        n = len(seg_list)
        # Insert outer IPv6 + SRH
        match_spec = srv6_srv6_encap_outer_match_spec_t(
            sr_metadata_action_=SRV6_TUNNEL_ENCAP,
            l3_metadata_nexthop=tunnel_index)
        if n == 1:
            action_spec = srv6_ip_srv6_rewrite_1_action_spec_t(
                action_sid0 = parse_ipv6(seg_list[0]),
                action_len = 2 * n,
                action_seg_left = n - 1,
                action_first_seg = n - 1)
            self.client.srv6_encap_outer_table_add_with_ip_srv6_rewrite_1(
                self.sess_hdl, self.dev_tgt, match_spec, action_spec)

        elif n == 2:
            action_spec = srv6_ip_srv6_rewrite_2_action_spec_t(
                action_sid0 = parse_ipv6(seg_list[0]),
                action_sid1 = parse_ipv6(seg_list[1]),
                action_len = 2 * n,
                action_seg_left = n - 1,
                action_first_seg = n - 1)
            self.client.srv6_encap_outer_table_add_with_ip_srv6_rewrite_2(
                self.sess_hdl, self.dev_tgt, match_spec, action_spec)

        elif n == 3:
            action_spec = srv6_ip_srv6_rewrite_3_action_spec_t(
                action_sid0 = parse_ipv6(seg_list[0]),
                action_sid1 = parse_ipv6(seg_list[1]),
                action_sid2 = parse_ipv6(seg_list[2]),
                action_len = 2 * n,
                action_seg_left = n - 1,
                action_first_seg = n - 1)
            self.client.srv6_encap_outer_table_add_with_ip_srv6_rewrite_3(
                self.sess_hdl, self.dev_tgt, match_spec, action_spec)

        elif n == 4:
            action_spec = srv6_ip_srv6_rewrite_4_action_spec_t(
                action_sid0 = parse_ipv6(seg_list[0]),
                action_sid1 = parse_ipv6(seg_list[1]),
                action_sid2 = parse_ipv6(seg_list[2]),
                action_sid3 = parse_ipv6(seg_list[3]),
                action_len = 2 * n,
                action_seg_left = n - 1,
                action_first_seg = n - 1)
            self.client.srv6_encap_outer_table_add_with_ip_srv6_rewrite_4(
                self.sess_hdl, self.dev_tgt, match_spec, action_spec)
       
        # Insert a new SRH
        match_spec = srv6_srv6_encap_outer_match_spec_t(
            sr_metadata_action_=SRV6_SRH_INSERT,
            l3_metadata_nexthop=tunnel_index)
        if n == 1:
            action_spec = srv6_srv6_rewrite_1_action_spec_t(
                action_sid0 = parse_ipv6(seg_list[0]),
                action_len = 2 * n,
                action_seg_left = n - 1,
                action_first_seg = n - 1)
            self.client.srv6_encap_outer_table_add_with_srv6_rewrite_1(
                self.sess_hdl, self.dev_tgt, match_spec, action_spec)

        elif n == 2:
            action_spec = srv6_srv6_rewrite_2_action_spec_t(
                action_sid0 = parse_ipv6(seg_list[0]),
                action_sid1 = parse_ipv6(seg_list[1]),
                action_len = 2 * n,
                action_seg_left = n - 1,
                action_first_seg = n - 1)
            self.client.srv6_encap_outer_table_add_with_srv6_rewrite_2(
                self.sess_hdl, self.dev_tgt, match_spec, action_spec)

        elif n == 3:
            action_spec = srv6_srv6_rewrite_3_action_spec_t(
                action_sid0 = parse_ipv6(seg_list[0]),
                action_sid1 = parse_ipv6(seg_list[1]),
                action_sid2 = parse_ipv6(seg_list[2]),
                action_len = 2 * n,
                action_seg_left = n - 1,
                action_first_seg = n - 1)
            self.client.srv6_encap_outer_table_add_with_srv6_rewrite_3(
                self.sess_hdl, self.dev_tgt, match_spec, action_spec)

        elif n == 4:
            action_spec = srv6_srv6_rewrite_4_action_spec_t(
                action_sid0 = parse_ipv6(seg_list[0]),
                action_sid1 = parse_ipv6(seg_list[1]),
                action_sid2 = parse_ipv6(seg_list[2]),
                action_sid3 = parse_ipv6(seg_list[3]),
                action_len = 2 * n,
                action_seg_left = n - 1,
                action_first_seg = n - 1)
            self.client.srv6_encap_outer_table_add_with_srv6_rewrite_4(
                self.sess_hdl, self.dev_tgt, match_spec, action_spec)
 
    def delete_tunnel_entry(self, tunnel_index):
        match_spec = srv6_srv6_encap_outer_match_spec_t(
            sr_metadata_action_=SRV6_TUNNEL_ENCAP,
            l3_metadata_nexthop=tunnel_index)
        self.client.srv6_encap_outer_table_delete_by_match_spec(
            self.sess_hdl, self.dev_tgt, match_spec)  

        match_spec = srv6_srv6_encap_outer_match_spec_t(
            sr_metadata_action_=SRV6_SRH_INSERT,
            l3_metadata_nexthop=tunnel_index)
        self.client.srv6_encap_outer_table_delete_by_match_spec(
            self.sess_hdl, self.dev_tgt, match_spec)  


    """ Basic test """
    def runTest(self):

        if test_param_get("arch") != "Tofino":
            return

        self.sess_hdl = self.conn_mgr.client_init()
        self.dev_tgt = DevTarget_t(device, hex_to_i16(0xFFFF))
        self.set_up()

        try:
            print '------------ SRv6 Endpoint ------------'
            print '----------------- END -----------------'
            self.run_test_end()

            print '-------------- END - PSP --------------'
            self.run_test_end_psp()

            print '---------------- END.X ----------------'
            self.run_test_end_x()

            print '--------------- END.DX2 ---------------'
            self.run_test_end_dx2()

            print '--------------- END.DX4 ---------------'
            self.run_test_end_dx4()

            print '--------------- END.DX6 ---------------'
            self.run_test_end_dx6()

            print '--------------- END.DT4 ---------------'
            self.run_test_end_dt4()

            print '--------------- END.DT6 ---------------'
            self.run_test_end_dt6()

            print '---------------- END.B6 ---------------'
            self.run_test_end_b6()

            print '------------ END.B6.ENCAPS ------------'
            self.run_test_end_b6_encaps()

            print '--------------- TRANSIT ---------------'
            #self.run_test_t()


        finally:
            pass
            #self.conn_mgr.client_cleanup(self.sess_hdl)

    def run_test_end(self):
        seg_list = ['2000::6', '2000::5', '2000::4', '2000::3', '2000::2']
        n = 5 # Number of segments
        vrf = 1
        nexthop = 1

        for segLeft in range(1, n):
            print '\t local sid: %s, SL: %d, FS: %d' % (seg_list[segLeft], segLeft, n-1)
            self.add_local_sid(self.segment(seg_list[segLeft], 128, 'END'))
            self.add_fib_entry(
                vrf,
                self.ipAddr(seg_list[segLeft - 1], 'Ipv6', 128),
                nexthop)

            pkt = simple_ipv6_sr_packet(eth_dst='00:33:33:33:33:33',
                                        eth_src='00:22:22:22:22:22',
                                        ipv6_dst=seg_list[segLeft],
                                        ipv6_src='2000::1',
                                        ipv6_hlim=64,
                                        srh_seg_left=segLeft,
                                        srh_first_seg=n-1,
                                        srh_seg_list=seg_list)
            exp_pkt = simple_ipv6_sr_packet(eth_dst='00:44:44:44:44:44',
                                            eth_src='00:33:33:33:33:33',
                                            ipv6_dst=seg_list[segLeft - 1],
                                            ipv6_src='2000::1',
                                            ipv6_hlim=63,
                                            srh_seg_left=segLeft - 1,
                                            srh_first_seg=n-1,
                                            srh_seg_list=seg_list)

            send_packet(self, ig_port, str(pkt))
            verify_packets(self, exp_pkt, [eg_port])

            pkt['Ethernet']['IPv6'].segleft = 0
            send_packet(self, ig_port, str(pkt))
            # Packet must get dropped
            verify_no_other_packets(self, device)


        self.delete_local_sid_all()

        for segLeft in range(1, 5):
            self.delete_fib_entry(
                vrf,
                self.ipAddr(seg_list[segLeft - 1], 'Ipv6', 128))

        return

    def run_test_end_psp(self):
        seg_list = ['2000::6', '2000::5', '2000::4', '2000::3', '2000::2']
        vrf = 1
        nexthop = 1
        segLeft = 1
        self.add_fib_entry(
            vrf,
            self.ipAddr(seg_list[segLeft - 1], 'Ipv6', 128),
            nexthop)

        for n in range(2, len(seg_list)):
            print '\t local sid: %s, SL: %d, FS: %d' % (seg_list[segLeft], segLeft, n-1)
            self.add_local_sid(
                self.segment(seg_list[segLeft], 128, 'END'), psp=True)

            udp_hdr = UDP(sport=1234, dport=80, chksum=0)
            pkt = simple_ipv6_sr_packet(eth_dst='00:33:33:33:33:33',
                                        eth_src='00:22:22:22:22:22',
                                        ipv6_dst=seg_list[segLeft],
                                        ipv6_src='2000::1',
                                        ipv6_hlim=64,
                                        srh_nh = IP_PROTOCOLS_UDP,
                                        srh_seg_left=segLeft,
                                        srh_first_seg=n-1,
                                        srh_seg_list=seg_list[:n],
                                        inner_frame=udp_hdr)

            exp_pkt = simple_udpv6_packet(pktlen=62,
                                          eth_dst='00:44:44:44:44:44',
                                          eth_src='00:33:33:33:33:33',
                                          ipv6_dst=seg_list[segLeft-1],
                                          ipv6_src='2000::1',
                                          ipv6_hlim=63,
                                          udp_sport=1234,
                                          udp_dport=80,
                                          with_udp_chksum=False)

            send_packet(self, ig_port, str(pkt))
            verify_packets(self, exp_pkt, [eg_port])

        self.delete_local_sid_all()

        self.delete_fib_entry(
            vrf,
            self.ipAddr(seg_list[segLeft - 1], 'Ipv6', 128))

        return

    def run_test_end_x(self):
        seg_list = ['2000::5', '2000::4', '2000::3', '2000::2']
        n = len(seg_list) # Number of segments
        nexthop = 1

        for segLeft in range(1, n):
            print '\t local sid: %s, LS: %d, FS: %d' % (seg_list[segLeft], segLeft, n-1)
            self.add_local_sid(
                self.segment(seg_list[segLeft], 128, 'END.X'), nexthop=nexthop)

            pkt = simple_ipv6_sr_packet(eth_dst='00:33:33:33:33:33',
                                        eth_src='00:22:22:22:22:22',
                                        ipv6_dst=seg_list[segLeft],
                                        ipv6_src='2000::1',
                                        ipv6_hlim=64,
                                        srh_seg_left=segLeft,
                                        srh_first_seg=n-1,
                                        srh_seg_list=seg_list)
            exp_pkt = simple_ipv6_sr_packet(eth_dst='00:44:44:44:44:44',
                                            eth_src='00:33:33:33:33:33',
                                            ipv6_dst=seg_list[segLeft - 1],
                                            ipv6_src='2000::1',
                                            ipv6_hlim=63,
                                            srh_seg_left=segLeft - 1,
                                            srh_first_seg=n-1,
                                            srh_seg_list=seg_list)

            send_packet(self, ig_port, str(pkt))
            verify_packets(self, exp_pkt, [eg_port])

            self.delete_local_sid_all()

        return

    def run_test_end_dx2(self):
        seg_list = ['2000::6', '2000::5', '2000::4', '2000::3', '2000::2']
        n = 5 # Number of segments
        eg_ifindex = 2

        segLeft = 0
        print '\t local sid: %s, SL: %d' % (seg_list[segLeft], segLeft)
        self.add_local_sid(self.segment(seg_list[segLeft], 128, 'END.DX2'),
                           ifindex=eg_ifindex)

        inner_pkt = simple_tcp_packet(eth_src='00:44:44:44:44:44',
                                      eth_dst='00:77:66:55:44:33',
                                      ip_dst='10.20.10.1',
                                      ip_src='10.10.10.1',
                                      ip_ttl=64)
        pkt = simple_ipv6_sr_packet(eth_dst='00:33:33:33:33:33',
                                    eth_src='00:22:22:22:22:22',
                                    ipv6_dst=seg_list[segLeft],
                                    ipv6_src='2000::1',
                                    ipv6_hlim=64,
                                    srh_seg_left=segLeft,
                                    srh_first_seg=n-1,
                                    srh_nh=IP_PROTOCOLS_NONXT,
                                    srh_seg_list=seg_list,
                                    inner_frame=inner_pkt)

        send_packet(self, ig_port, str(pkt))
        verify_packets(self, inner_pkt, [eg_port])

        pkt['Ethernet']['IPv6'].segleft = 1
        send_packet(self, ig_port, str(pkt))
        # Packet must get dropped
        verify_no_other_packets(self, device)


        self.delete_local_sid_all()

        return

    def run_test_end_dx6(self):
        seg_list = ['2000::6', '2000::5', '2000::4', '2000::3', '2000::2']
        n = len(seg_list) # Number of segments
        nexthop = 1
        segLeft = 0
        print '\t local sid: %s, SL: %d' % (seg_list[segLeft], segLeft)
        self.add_local_sid(self.segment(seg_list[segLeft], 128, 'END.DX6'),
                           nexthop=nexthop)

        inner_pkt = simple_tcpv6_packet(eth_src='00:77:66:55:44:33',
                                        eth_dst='00:44:44:44:44:44',
                                        ipv6_dst='2ffe::4',
                                        ipv6_src='2ff0::1',
                                        ipv6_hlim=64)
        pkt = simple_ipv6_sr_packet(eth_dst='00:33:33:33:33:33',
                                    eth_src='00:22:22:22:22:22',
                                    ipv6_dst=seg_list[segLeft],
                                    ipv6_src='2000::1',
                                    ipv6_hlim=64,
                                    srh_seg_left=segLeft,
                                    srh_first_seg=n-1,
                                    srh_nh=IP_PROTOCOLS_IPV6,
                                    srh_seg_list=seg_list,
                                    inner_frame=inner_pkt['IPv6'])
        exp_pkt = simple_tcpv6_packet(eth_src='00:33:33:33:33:33',
                                      eth_dst='00:44:44:44:44:44',
                                      ipv6_dst='2ffe::4',
                                      ipv6_src='2ff0::1',
                                      ipv6_hlim=63)
        send_packet(self, ig_port, str(pkt))
        verify_packets(self, exp_pkt, [eg_port])

        self.delete_local_sid_all()

        return

    def run_test_end_dt6(self):
        seg_list = ['2000::6', '2000::5', '2000::4', '2000::3', '2000::2']
        n = len(seg_list) # Number of segments
        segLeft = 0
        vrf = 1
        nexthop = 1
        print '\t local sid: %s, SL: %d' % (seg_list[segLeft], segLeft)
        self.add_local_sid(
            self.segment(seg_list[segLeft], 128, 'END.DT6'), vrf=vrf)
        self.add_fib_entry(
            vrf,
            self.ipAddr('2ffe::4', 'Ipv6', 128),
            nexthop)
        inner_pkt = simple_tcpv6_packet(eth_src='00:77:66:55:44:33',
                                        eth_dst='00:44:44:44:44:44',
                                        ipv6_dst='2ffe::4',
                                        ipv6_src='2ff0::1',
                                        ipv6_hlim=64)
        pkt = simple_ipv6_sr_packet(eth_dst='00:33:33:33:33:33',
                                    eth_src='00:22:22:22:22:22',
                                    ipv6_dst=seg_list[segLeft],
                                    ipv6_src='2000::1',
                                    ipv6_hlim=64,
                                    srh_seg_left=segLeft,
                                    srh_first_seg=n-1,
                                    srh_nh=IP_PROTOCOLS_IPV6,
                                    srh_seg_list=seg_list,
                                    inner_frame=inner_pkt['IPv6'])
        exp_pkt = simple_tcpv6_packet(eth_src='00:33:33:33:33:33',
                                      eth_dst='00:44:44:44:44:44',
                                      ipv6_dst='2ffe::4',
                                      ipv6_src='2ff0::1',
                                      ipv6_hlim=63)
        send_packet(self, ig_port, str(pkt))
        verify_packets(self, exp_pkt, [eg_port])

        self.delete_fib_entry(
            vrf,
            self.ipAddr('2ffe::4', 'Ipv6', 128))
        self.delete_local_sid_all()

        return

    def run_test_end_dx4(self):
        seg_list = ['2000::4', '2000::3', '2000::2']
        n = len(seg_list) # Number of segments
        nexthop = 1
        segLeft = 0
        print '\t local sid: %s, SL: %d' % (seg_list[segLeft], segLeft)
        self.add_local_sid(self.segment(seg_list[segLeft], 128, 'END.DX4'),
                           nexthop=nexthop)

        inner_pkt = simple_tcp_packet(eth_src='00:44:44:44:44:44',
                                      eth_dst='00:77:66:55:44:33',
                                      ip_dst='10.20.10.1',
                                      ip_src='10.10.10.1',
                                      ip_ttl=64)
        pkt = simple_ipv6_sr_packet(eth_dst='00:33:33:33:33:33',
                                    eth_src='00:22:22:22:22:22',
                                    ipv6_dst=seg_list[segLeft],
                                    ipv6_src='2000::1',
                                    ipv6_hlim=64,
                                    srh_seg_left=segLeft,
                                    srh_first_seg=n-1,
                                    srh_nh=IP_PROTOCOLS_IPV4,
                                    srh_seg_list=seg_list,
                                    inner_frame=inner_pkt['IP'])
        exp_pkt = simple_tcp_packet(eth_src='00:33:33:33:33:33',
                                    eth_dst='00:44:44:44:44:44',
                                    ip_dst='10.20.10.1',
                                    ip_src='10.10.10.1',
                                    ip_ttl=63)
        send_packet(self, ig_port, str(pkt))
        verify_packets(self, exp_pkt, [eg_port])

        self.delete_local_sid_all()


    def run_test_end_dt4(self):
        seg_list = ['2000::4', '2000::3', '2000::2']
        n = len(seg_list) # Number of segments
        nexthop = 1
        vrf = 1
        segLeft = 0
        print '\t local sid: %s, SL: %d' % (seg_list[segLeft], segLeft)
        self.add_local_sid(self.segment(seg_list[segLeft], 128, 'END.DT4'),
                           vrf=vrf)
        self.add_fib_entry(
            vrf,
            self.ipAddr('10.20.10.1', 'Ipv4', 32),
            nexthop)
        inner_pkt = simple_tcp_packet(eth_src='00:44:44:44:44:44',
                                      eth_dst='00:77:66:55:44:33',
                                      ip_dst='10.20.10.1',
                                      ip_src='10.10.10.1',
                                      ip_ttl=64)
        pkt = simple_ipv6_sr_packet(eth_dst='00:33:33:33:33:33',
                                    eth_src='00:22:22:22:22:22',
                                    ipv6_dst=seg_list[segLeft],
                                    ipv6_src='2000::1',
                                    ipv6_hlim=64,
                                    srh_seg_left=segLeft,
                                    srh_first_seg=n-1,
                                    srh_nh=IP_PROTOCOLS_IPV4,
                                    srh_seg_list=seg_list,
                                    inner_frame=inner_pkt['IP'])
        exp_pkt = simple_tcp_packet(eth_src='00:33:33:33:33:33',
                                    eth_dst='00:44:44:44:44:44',
                                    ip_dst='10.20.10.1',
                                    ip_src='10.10.10.1',
                                    ip_ttl=63)

        send_packet(self, ig_port, str(pkt))
        verify_packets(self, exp_pkt, [eg_port])

        self.delete_fib_entry(
            vrf,
            self.ipAddr('10.20.10.1', 'Ipv4', 32))
        self.delete_local_sid_all()

        return

    def run_test_end_b6_encaps(self):
        seg_list = ['2000::6', '2000::5', '2000::4', '2000::3', '2000::2']
        new_seg_list = ['3000::4', '3000::3', '3000::2']
        n = len(seg_list) # Number of segments
        tunnel_index = 2
        vrf = 1
        segLeft = 3
        src_addr = '3000::1'
        dst_addr = new_seg_list[-1]
        print '\t local sid: %s, SL: %d' % (seg_list[segLeft], segLeft)
        self.add_local_sid(
            self.segment(seg_list[segLeft], 128, 'END.B6.ENCAPS'),
            seg_list=new_seg_list)
        self.add_fib_entry(
            vrf,
            self.ipAddr('3000::2', 'Ipv6', 128),
            tunnel_index)
        self.add_tunnel_entry(tunnel_index, new_seg_list)
        self.add_tunnel_rewrite_entry(tunnel_index,
                                      '00:55:55:55:55:55',
                                      '00:44:44:44:44:44',
                                      src_addr,
                                      dst_addr)
        udp_hdr = UDP(sport=1234, dport=80, chksum=0)
        pkt = simple_ipv6_sr_packet(eth_dst='00:33:33:33:33:33',
                                    eth_src='00:22:22:22:22:22',
                                    ipv6_dst=seg_list[segLeft],
                                    ipv6_src='2000::1',
                                    ipv6_hlim=64,
                                    srh_seg_left=segLeft,
                                    srh_first_seg=n-1,
                                    srh_nh=IP_PROTOCOLS_UDP,
                                    srh_seg_list=seg_list,
                                    inner_frame=udp_hdr)
        inner_pkt = simple_ipv6_sr_packet(eth_dst='00:33:33:33:33:33',
                                    eth_src='00:22:22:22:22:22',
                                    ipv6_dst=seg_list[segLeft - 1],
                                    ipv6_src='2000::1',
                                    ipv6_hlim=63,
                                    srh_seg_left=segLeft - 1,
                                    srh_first_seg=n-1,
                                    srh_nh=IP_PROTOCOLS_UDP,
                                    srh_seg_list=seg_list,
                                    inner_frame=udp_hdr)
        n = len(new_seg_list) # Number of segments
        exp_pkt = simple_ipv6_sr_packet(eth_src='00:55:55:55:55:55',
                                    eth_dst='00:44:44:44:44:44',
                                    ipv6_dst=dst_addr,
                                    ipv6_src=src_addr,
                                    ipv6_hlim=64,
                                    srh_seg_left=n-1,
                                    srh_first_seg=n-1,
                                    srh_nh=IP_PROTOCOLS_IPV6,
                                    srh_seg_list=new_seg_list,
                                    inner_frame=inner_pkt['IPv6'])

        send_packet(self, ig_port, str(pkt))
        verify_packets(self, exp_pkt, [eg_port])

        self.delete_tunnel_entry(tunnel_index)
        self.delete_tunnel_rewrite_entry(tunnel_index)

        self.delete_fib_entry(
            vrf,
            self.ipAddr('3000::2', 'Ipv6', 128))
        self.delete_local_sid_all()

        return


    def run_test_end_b6(self):
        seg_list = ['2000::6', '2000::5', '2000::4', '2000::3', '2000::2']
        new_seg_list = ['3000::3', '3000::2', '3000::1']
        n = len(seg_list) # Number of segments
        segLeft = 3
        vrf = 1
        tunnel_index = 2

        print '\t local sid: %s, SL: %d' % (seg_list[segLeft], segLeft)
        self.add_local_sid(
            self.segment(seg_list[segLeft], 128, 'END.B6'),
            seg_list=new_seg_list,
            nexthop=tunnel_index)
        self.add_fib_entry(
            vrf,
            self.ipAddr('3000::1', 'Ipv6', 128),
            tunnel_index)
        self.add_tunnel_entry(tunnel_index, new_seg_list)

        udp_hdr = UDP(sport=1234, dport=80, chksum=0)
        pkt = simple_ipv6_sr_packet(eth_dst='00:33:33:33:33:33',
                                    eth_src='00:22:22:22:22:22',
                                    ipv6_dst=seg_list[segLeft],
                                    ipv6_src='2000::1',
                                    ipv6_hlim=64,
                                    srh_seg_left=segLeft,
                                    srh_first_seg=n-1,
                                    srh_nh=IP_PROTOCOLS_UDP,
                                    srh_seg_list=seg_list,
                                    inner_frame=udp_hdr)

        reserved = (n - 1) << 24
        inner_frame = IPv6ExtHdrRouting(nh=IP_PROTOCOLS_UDP,
                                        type=4,
                                        segleft=segLeft,
                                        reserved=reserved,
                                        addresses=seg_list) / udp_hdr
        n = len(new_seg_list) # Number of segments
        exp_pkt = simple_ipv6_sr_packet(eth_src='00:33:33:33:33:33',
                                        eth_dst='00:44:44:44:44:44',
                                        ipv6_dst=new_seg_list[n-1],
                                        ipv6_src='2000::1',
                                        ipv6_hlim=63,
                                        srh_seg_left=n-1,
                                        srh_first_seg=n-1,
                                        srh_nh=IP_PROTOCOLS_SR,
                                        srh_seg_list=new_seg_list,
                                        inner_frame=inner_frame)

        send_packet(self, ig_port, str(pkt))
        verify_any_packet_any_port(self, [exp_pkt], [eg_port])

        self.delete_tunnel_entry(tunnel_index)
        self.delete_tunnel_rewrite_entry(tunnel_index)
        self.delete_fib_entry(
            vrf,
            self.ipAddr('3000::1', 'Ipv6', 128))
        self.delete_local_sid_all()

        return

    def run_test_t(self):
        seg_list = ['2000::4', '2000::3', '2000::2']
        n = len(seg_list) # Number of segments
        vrf = 1
        nexthop = 1
        segLeft = 1
        print '\t local sid: %s, sl: %d, fs: %d' % (seg_list[segLeft], segLeft, n-1)
        self.add_fib_entry(
            vrf,
            self.ipAddr(seg_list[segLeft], 'Ipv6', 128),
            nexthop)

        pkt = simple_ipv6_sr_packet(eth_dst='00:33:33:33:33:33',
                                    eth_src='00:22:22:22:22:22',
                                    ipv6_dst=seg_list[segLeft],
                                    ipv6_src='2000::1',
                                    ipv6_hlim=64,
                                    srh_seg_left=segLeft,
                                    srh_first_seg=n-1,
                                    srh_seg_list=seg_list)
        exp_pkt = simple_ipv6_sr_packet(eth_dst='00:44:44:44:44:44',
                                        eth_src='00:33:33:33:33:33',
                                        ipv6_dst=seg_list[segLeft],
                                        ipv6_src='2000::1',
                                        ipv6_hlim=63,
                                        srh_seg_left=segLeft,
                                        srh_first_seg=n-1,
                                        srh_seg_list=seg_list)

        send_packet(self, ig_port, str(pkt))
        verify_packets(self, exp_pkt, [eg_port])


        self.delete_fib_entry(
            vrf,
            self.ipAddr(seg_list[segLeft], 'Ipv6', 128))

        return
