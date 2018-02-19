import json
import os
import sys
import unittest
import ptf.dataplane as dataplane
import pd_base_tests

from port_mapping import *
from ptf.testutils import *
from ptf.thriftutils import *

import switchapi_thrift
from switchapi_thrift.ttypes import *
from switchapi_thrift.switch_api_headers import *

this_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.join(this_dir, '../../base'))
from common.utils import *
sys.path.append(os.path.join(this_dir, '../../base/api-tests'))
import api_base_tests

frontPanelPorts = [
    "29/0", "31/0", "32/0"
]

################################################################################

class IPv6FabricTest(api_base_tests.ThriftInterfaceDataPlane):
    def frontpanel_to_swport(self, fpport):
        pgrp, chnl = fpport.split("/")
        swport = (int(pgrp) * 4 - 4) + int(chnl)
        return swport

    def swport_to_frontpanel(self, swport):
        pgrp = swport / 4 + 1
        chnl = swport % 4
        fpport = "%d/%d" % (pgrp, chnl)
        return fpport

    def getSwPorts(self):
        swapi_ports = []
        for i in frontPanelPorts:
            swapi_ports.append(self.frontpanel_to_swport(i))
        return swapi_ports

    def getFpPort(self, swport):
        return self.swport_to_frontpanel(swport)

    def deletePort(self, swport):
        handle = self.client.switch_api_port_id_to_handle_get(self.DEVICE,
                                                              swport)
        self.client.switch_api_port_delete(self.DEVICE, handle)

    def deleteAllPortsInPortGroup(self, fpport):
        pgrp, chnl = fpport.split("/")
        for i in range(0,4):
            swport = (int(pgrp) * 4 - 4) + i
            self.deletePort(swport)

    def addPort(self, swport, speed):
        portinfo = switcht_api_port_info_t(swport, speed)
        self.client.switch_api_port_add_with_attribute(self.DEVICE, portinfo)

    def setUp(self):
        print

        self.swports = self.getSwPorts()

        api_base_tests.ThriftInterfaceDataPlane.setUp(self)

        api = self.client
        self.DEVICE = 0
        self.VRF = 2
        self.RMAC = 'a8:2b:b5:35:ea:79'

        # my interface addresses
        self.IFADDRS = [{
            'IP': '2650:a800:fffe::12',
            'LEN': 127
        }, {
            'IP': '2650:a800:fffe::8',
            'LEN': 127
        }, {
            'IP': '2650:a800:fffe::4',
            'LEN': 127
        }]

        # my neighbor's IP and MAC addresses
        self.NEIGHBORS = [{
            'IP': '2650:a800:fffe::13',
            'MAC': 'a8:2b:b5:35:eb:8d'
        }, {
            'IP': '2650:a800:fffe::9',
            'MAC': '8c:ea:1b:e4:94:c9'
        }, {
            'IP': '2650:a800:fffe::5',
            'MAC': '8c:ea:1b:e4:96:6d'
        }]

        # routes to program
        self.L1_ROUTES= [{
            'IP': '2650:a800:fffe::14',
            'LEN': 127
        }, {
            'IP': '2650:a800:fffe:3f::f1',
            'LEN': 128
        }, {
            'IP': '2001:4958:1522:ffff:2000::',
            'LEN': 67
        }]

        self.L2_ROUTES= [{
            'IP': '2650:a800:fffe:2::',
            'LEN': 64
        }, {
            'IP': '2001:4958:1522:ffff:4000::',
            'LEN': 67
        }, {
            'IP': '2001:4958:1522:ffff:6000::',
            'LEN': 67
        }]


        self.L3_ROUTES= [{
            'IP': '2650:a800:fffe:3::',
            'LEN': 64
        }, {
            'IP': '2001:4958:1522:ffff:8000::',
            'LEN': 67
        }, {
            'IP': '2650:a800:fffe::',
            'LEN': 127
        }, {
            'IP': '::',
            'LEN': 0
        }]

        self.port_hdl = [None] * 3
        self.if_hdl = [None] * 3
        self.nhop_hdl = [None] * 3
        self.neigh_hdl = [None] * 3
        self.rif_hdl = [None] * 3

        # initialize API

        if test_param_get('setup') == True or (
                test_param_get('setup') != True and
                test_param_get('cleanup') != True):

            print 'Configuring the system'

            # create VRF
            self.vrf_hdl = api.switch_api_vrf_create(self.DEVICE, self.VRF)

            # add router MAC
            self.rmac_hdl = api.switch_api_router_mac_group_create(
                self.DEVICE, SWITCH_RMAC_TYPE_INNER)
            api.switch_api_router_mac_add(self.DEVICE, self.rmac_hdl, self.RMAC)
        
            # ports 29, 31 and 32 are 100G ports, delete the 10G ports in the port
            # group
            # created by default by switchapi and add the 100G port
            self.deleteAllPortsInPortGroup(frontPanelPorts[0])
            self.deleteAllPortsInPortGroup(frontPanelPorts[1])
            self.deleteAllPortsInPortGroup(frontPanelPorts[2])
            self.addPort(self.swports[0], SWITCH_PORT_SPEED_100G)
            self.addPort(self.swports[1], SWITCH_PORT_SPEED_100G)
            self.addPort(self.swports[2], SWITCH_PORT_SPEED_100G)

            self.port_hdl[0] = api.switch_api_port_id_to_handle_get(
                self.DEVICE, self.swports[0])
            self.port_hdl[1] = api.switch_api_port_id_to_handle_get(
                self.DEVICE, self.swports[1])
            self.port_hdl[2] = api.switch_api_port_id_to_handle_get(
                self.DEVICE, self.swports[2])

            # wait for the ports to come up
            time.sleep(20)

            rif_info = switcht_rif_info_t(
                rif_type=SWITCH_RIF_TYPE_INTF,
                vrf_handle=self.vrf_hdl,
                rmac_handle=self.rmac_hdl,
                v6_unicast_enabled=True)
            self.rif_hdl[0] = self.client.switch_api_rif_create(0, rif_info)
            self.rif_hdl[1] = self.client.switch_api_rif_create(0, rif_info)
            self.rif_hdl[2] = self.client.switch_api_rif_create(0, rif_info)

            # create L3 interface on port_hdl[0]
            intf_info = switcht_interface_info_t(
                handle=self.port_hdl[0],
                type=SWITCH_INTERFACE_TYPE_PORT,
                rif_handle=self.rif_hdl[0])
            self.if_hdl[0] = api.switch_api_interface_create(self.DEVICE,
                                                             intf_info)

            # create L3 interface on port_hdl[1]
            intf_info = switcht_interface_info_t(
                handle=self.port_hdl[1],
                type=SWITCH_INTERFACE_TYPE_PORT,
                rif_handle=self.rif_hdl[1])
            self.if_hdl[1] = api.switch_api_interface_create(self.DEVICE,
                                                             intf_info)

            # create L3 interface on port_hdl[2]
            intf_info = switcht_interface_info_t(
                handle=self.port_hdl[2],
                type=SWITCH_INTERFACE_TYPE_PORT,
                rif_handle=self.rif_hdl[2])
            self.if_hdl[2] = api.switch_api_interface_create(self.DEVICE,
                                                             intf_info)

            # configure addresses on the L3 interfaces
            for idx in range(0, len(self.if_hdl)):
                ipaddr = switcht_ip_addr_t(
                    addr_type=SWITCH_API_IP_ADDR_V6,
                    ipaddr=self.IFADDRS[idx]['IP'],
                    prefix_length=self.IFADDRS[idx]['LEN'])
                api.switch_api_l3_interface_address_add(
                    self.DEVICE, self.rif_hdl[idx], self.vrf_hdl, ipaddr)

            # create nexthops
            for idx in range(0, len(self.NEIGHBORS)):
                nhop_key = switcht_nhop_key_t(
                    intf_handle=self.if_hdl[idx], ip_addr_valid=0)
                self.nhop_hdl[idx] = api.switch_api_nhop_create(self.DEVICE,
                                                                nhop_key)

            # create neighbors
            for idx in range(0, len(self.NEIGHBORS)):
                ipaddr = switcht_ip_addr_t(
                    addr_type=SWITCH_API_IP_ADDR_V6,
                    ipaddr=self.NEIGHBORS[idx]['IP'],
                    prefix_length=127)
                neighbor = switcht_neighbor_info_t(
                    nhop_handle=self.nhop_hdl[idx],
                    interface_handle=self.rif_hdl[idx],
                    mac_addr=self.NEIGHBORS[idx]['MAC'],
                    ip_addr=ipaddr,
                    rw_type=SWITCH_API_NEIGHBOR_RW_TYPE_L3)
                self.neigh_hdl[idx] = \
                    api.switch_api_neighbor_entry_add(self.DEVICE, neighbor)

            # create ecmp group
            # self.ecmp_hdl = api.switch_api_ecmp_create(self.DEVICE)

            # add nexthops to ecmp group
            #nhop_list = [self.nhop_hdl[n] for n in range(0, 4)]
            #api.switch_api_ecmp_member_add(self.DEVICE, self.ecmp_hdl,
            #                               len(nhop_list), nhop_list)

            # add routes with destination as ecmp handle created above
            for idx in range(0, len(self.L1_ROUTES)):
                ipaddr = switcht_ip_addr_t(
                    addr_type=SWITCH_API_IP_ADDR_V6,
                    ipaddr=self.L1_ROUTES[idx]['IP'],
                    prefix_length=self.L1_ROUTES[idx]['LEN'])
                api.switch_api_l3_route_add(self.DEVICE, self.vrf_hdl, ipaddr,
                                            self.neigh_hdl[0])

            for idx in range(0, len(self.L2_ROUTES)):
                ipaddr = switcht_ip_addr_t(
                    addr_type=SWITCH_API_IP_ADDR_V6,
                    ipaddr=self.L2_ROUTES[idx]['IP'],
                    prefix_length=self.L2_ROUTES[idx]['LEN'])
                api.switch_api_l3_route_add(self.DEVICE, self.vrf_hdl, ipaddr,
                                            self.neigh_hdl[1])

            for idx in range(0, len(self.L3_ROUTES)):
                ipaddr = switcht_ip_addr_t(
                    addr_type=SWITCH_API_IP_ADDR_V6,
                    ipaddr=self.L3_ROUTES[idx]['IP'],
                    prefix_length=self.L3_ROUTES[idx]['LEN'])
                api.switch_api_l3_route_add(self.DEVICE, self.vrf_hdl, ipaddr,
                                            self.neigh_hdl[2])
