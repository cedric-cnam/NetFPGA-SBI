#!/usr/bin/env python

#
# Copyright (c) 2022 Mario Patetta, Conservatoire National des Arts et Metiers
# Copyright (c) 2017 Stephen Ibanez
# All rights reserved.
#
# This software was developed by Stanford University and the University of Cambridge Computer Laboratory 
# under National Science Foundation under Grant No. CNS-0855268,
# the University of Cambridge Computer Laboratory under EPSRC INTERNET Project EP/H040536/1 and
# by the University of Cambridge Computer Laboratory under DARPA/AFRL contract FA8750-11-C-0249 ("MRC2"), 
# as part of the DARPA MRC research programme.
#
# @NETFPGA_LICENSE_HEADER_START@
#
# Licensed to NetFPGA C.I.C. (NetFPGA) under one or more contributor
# license agreements.  See the NOTICE file distributed with this work for
# additional information regarding copyright ownership.  NetFPGA licenses this
# file to you under the NetFPGA Hardware-Software License, Version 1.0 (the
# "License"); you may not use this file except in compliance with the
# License.  You may obtain a copy of the License at:
#
#   http://www.netfpga-cic.org
#
# Unless required by applicable law or agreed to in writing, Work distributed
# under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
# CONDITIONS OF ANY KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations under the License.
#
# @NETFPGA_LICENSE_HEADER_END@
#


from southbound_headers import *
from nf_sim_tools import *
import random
from collections import OrderedDict
import sss_sdnet_tuples

###########
# pkt generation tools
###########

pktsApplied = []
pktsExpected = []

# Pkt lists for SUME simulations
nf_applied = OrderedDict()
nf_applied[0] = []
nf_applied[1] = []
nf_applied[2] = []
nf_applied[3] = []
nf_expected = OrderedDict()
nf_expected[0] = []
nf_expected[1] = []
nf_expected[2] = []
nf_expected[3] = []

nf_port_map = {"nf0":0b00000001, "nf1":0b00000100, "nf2":0b00010000, "nf3":0b01000000, "dma0":0b00000010, "none":0}
nf_id_map = {"nf0":0, "nf1":1, "nf2":2, "nf3":3}

sss_sdnet_tuples.clear_tuple_files()

def applyPkt(pkt, ingress, time):
    pktsApplied.append(pkt)
    sss_sdnet_tuples.sume_tuple_in['pkt_len'] = len(pkt)
    sss_sdnet_tuples.sume_tuple_in['src_port'] = nf_port_map[ingress]
    sss_sdnet_tuples.sume_tuple_expect['pkt_len'] = len(pkt)
    sss_sdnet_tuples.sume_tuple_expect['src_port'] = nf_port_map[ingress]
    pkt.time = time
    nf_applied[nf_id_map[ingress]].append(pkt)

def expPkt(pkt, egress):
    pktsExpected.append(pkt)
    sss_sdnet_tuples.sume_tuple_expect['dst_port'] = nf_port_map[egress]
    sss_sdnet_tuples.write_tuples()
    if egress in ["nf0","nf1","nf2","nf3"]:
        nf_expected[nf_id_map[egress]].append(pkt)
    elif egress == 'bcast':
        nf_expected[0].append(pkt)
        nf_expected[1].append(pkt)
        nf_expected[2].append(pkt)
        nf_expected[3].append(pkt)


def write_pcap_files():
    wrpcap("src.pcap", pktsApplied)
    wrpcap("dst.pcap", pktsExpected)

    for i in nf_applied.keys():
        if (len(nf_applied[i]) > 0):
            wrpcap('nf{0}_applied.pcap'.format(i), nf_applied[i])

    for i in nf_expected.keys():
        if (len(nf_expected[i]) > 0):
            wrpcap('nf{0}_expected.pcap'.format(i), nf_expected[i])

    for i in nf_applied.keys():
        print "nf{0}_applied times: ".format(i), [p.time for p in nf_applied[i]]

#####################
# generate testdata #
#####################
SERVER_MAC = "d0:50:99:d8:4a:91"
MAC0 = "00:00:00:00:00:00"
MAC1 = "11:11:11:11:11:11"
MAC2 = "22:22:22:22:22:22"
MAC3 = "33:33:33:33:33:33"

CONTROLLER_ID    = 1
SWITCH_ID        = 1

sport = 55
dport = 72

IP1_src = "10.0.0.1"
IP2_src = "192.168.1.1"
IP3_src = "12.138.254.42"

IP1_dst = "10.0.0.2"
IP2_dst = "192.168.1.27"
IP3_dst = "12.138.254.33"

KEY1 = "10.0.0"
KEY2 = "192.168.1"
KEY3 = "12.138.254"

PKT_SIZE = 500
MIN_PKT_SIZE = 300
HEADER_SIZE = 54 # size of TCP header

DUMMY_NUMBER = 60
port_list = ["nf0", "nf1", "nf2", "nf3"]
mac_list = [MAC0, MAC1, MAC2, MAC3]
ip_list = [IP1_dst, IP2_dst, IP3_dst]


# Convert keys from IP address notation to int
#def Key2Int(key):
#    h = list(map(int,key.split(".")))
#    return ( (h[0]<<16)+(h[1]<<8)+h[2] )
    
#KEY1 = Key2Int(KEY1)
#KEY2 = Key2Int(KEY2)
#KEY3 = Key2Int(KEY3)

# Create a single TCP flow using the given 5-tuple parameters of the given size
def make_flow(srcIP, dstIP, sport, dport, flow_size):
    pkts = []
    # make the SYN PKT
    pkt = Ether(dst=MAC1, src=MAC2) / IP(src=srcIP, dst=dstIP) / TCP(sport=sport, dport=dport, flags='S')
    pkt = pad_pkt(pkt, MIN_PKT_SIZE)
    pkts.append(pkt)
    # make the data pkts
    size = flow_size
    while size >= PKT_SIZE:
        pkt = Ether(dst=MAC1, src=MAC2) / IP(src=srcIP, dst=dstIP) / TCP(sport=sport, dport=dport, flags='A')
        pkt = pad_pkt(pkt, PKT_SIZE + HEADER_SIZE)
        pkts.append(pkt)
        size -= PKT_SIZE
    # make the FIN pkt
    size = max(MIN_PKT_SIZE - HEADER_SIZE, size)
    pkt = Ether(dst=MAC1, src=MAC2) / IP(src=srcIP, dst=dstIP) / TCP(sport=sport, dport=dport, flags='F')
    pkt = pad_pkt(pkt, HEADER_SIZE + size)
    pkts.append(pkt)
    return pkts

# randomly interleave the flow's packets
def mix_flows(pairs):
    trace = []
    IPs = []
    full_pkt = pairs[0][0] + pairs[1][0] + pairs[2][0]
    full_IPs = [pairs[0][1]] * len(pairs[0][0]) + [pairs[1][1]] * len(pairs[1][0]) + [pairs[2][1]] * len(pairs[2][0])
    for i in range(len(full_pkt)):
        index = random.randrange(len(full_pkt))
        pkt = full_pkt[index]
        IP = full_IPs[index]
        trace.append(pkt)
        IPs.append(IP)
        del full_pkt[index]
        del full_IPs[index]
    return [trace,IPs]

# Create 3 flows and mix them together
flow1 = make_flow(IP1_src, IP1_dst, sport, dport, 1000)
flow2 = make_flow(IP2_src, IP2_dst, sport, dport, 20000)
flow3 = make_flow(IP3_src, IP3_dst, sport, dport, 1000)
[trace,IPs] = mix_flows([[flow1,IP1_dst],[flow2,IP2_dst],[flow3,IP3_dst]])


#--------------------  control-plane traffic to fill the routing tables according to IP_dst  --------------------------
pkt = Ether(dst=MAC3, src=SERVER_MAC) / Southbound(ControllerID=CONTROLLER_ID , SwitchID=SWITCH_ID) / SouthboundUpdate(key=IP1_dst, port=NF0, address=0)
pkt = pad_pkt(pkt, MIN_PKT_SIZE)
applyPkt(pkt,"nf3",0)
pkt = Ether(dst=SERVER_MAC, src=MAC3) / Southbound(ControllerID=CONTROLLER_ID , SwitchID=SWITCH_ID, ACK=1) / SouthboundUpdate(key=IP1_dst, port=NF0, address=0)
pkt = pad_pkt(pkt, MIN_PKT_SIZE)
expPkt(pkt, "nf3")

# set of dummy packets to give time to the LUT to update rules
for i in range(DUMMY_NUMBER/3):
    pkt = Ether(dst=mac_list[i%4], src=SERVER_MAC)
    pkt = pad_pkt(pkt, 5*MIN_PKT_SIZE)
    applyPkt(pkt,port_list[i%4],i+1)
    expPkt(pkt, "none")

pkt = Ether(dst=MAC3, src=SERVER_MAC) / Southbound(ControllerID=CONTROLLER_ID , SwitchID=SWITCH_ID) / SouthboundUpdate(key=IP2_dst, port=NF1, address=1)
pkt = pad_pkt(pkt, MIN_PKT_SIZE)
applyPkt(pkt, "nf3", DUMMY_NUMBER/3+1)
pkt = Ether(dst=SERVER_MAC, src=MAC3) / Southbound(ControllerID=CONTROLLER_ID , SwitchID=SWITCH_ID, ACK=1) / SouthboundUpdate(key=IP2_dst, port=NF1, address=1)
pkt = pad_pkt(pkt, MIN_PKT_SIZE)
expPkt(pkt, "nf3")

# set of dummy packets to give time to the LUT to update rules
for i in range(DUMMY_NUMBER/3):
    pkt = Ether(dst=mac_list[i%4], src=SERVER_MAC)
    pkt = pad_pkt(pkt, 5*MIN_PKT_SIZE)
    applyPkt(pkt,port_list[i%4],i+DUMMY_NUMBER/3+2)
    expPkt(pkt, "none")

pkt = Ether(dst=MAC3, src=SERVER_MAC) / Southbound(ControllerID=CONTROLLER_ID , SwitchID=SWITCH_ID) / SouthboundUpdate(key=IP3_dst, port=NF2, address=10)
pkt = pad_pkt(pkt, MIN_PKT_SIZE)
applyPkt(pkt, "nf3", 2*DUMMY_NUMBER/3+2)
pkt = Ether(dst=SERVER_MAC, src=MAC3) / Southbound(ControllerID=CONTROLLER_ID , SwitchID=SWITCH_ID, ACK=1) / SouthboundUpdate(key=IP3_dst, port=NF2, address=10)
pkt = pad_pkt(pkt, MIN_PKT_SIZE)
expPkt(pkt, "nf3")

# set of dummy packets to give time to the LUT to update rules
for i in range(DUMMY_NUMBER/3):
    pkt = Ether(dst=mac_list[i%4], src=SERVER_MAC)
    pkt = pad_pkt(pkt, 5*MIN_PKT_SIZE)
    applyPkt(pkt,port_list[i%4],i+2*DUMMY_NUMBER/3+3)
    expPkt(pkt, "none")

#------------------------------------------------------------------------------------------------------------------------

# control plane check messages to verify routing tables are correct
pkt = Ether(dst=MAC3, src=SERVER_MAC) / Southbound(ControllerID=CONTROLLER_ID , SwitchID=SWITCH_ID) / SouthboundUpdate(key=IP1_dst, check=1)
pkt = pad_pkt(pkt, MIN_PKT_SIZE)
applyPkt(pkt,"nf3",3+DUMMY_NUMBER)
pkt = Ether(dst=SERVER_MAC, src=MAC3) / Southbound(ControllerID=CONTROLLER_ID , SwitchID=SWITCH_ID, ACK=1) / SouthboundUpdate(key=IP1_dst, port=NF0, check=1)
pkt = pad_pkt(pkt, MIN_PKT_SIZE)
expPkt(pkt, "nf3")

pkt = Ether(dst=MAC3, src=SERVER_MAC) / Southbound(ControllerID=CONTROLLER_ID , SwitchID=SWITCH_ID) / SouthboundUpdate(key=IP2_dst, check=1)
pkt = pad_pkt(pkt, MIN_PKT_SIZE)
applyPkt(pkt,"nf3",4+DUMMY_NUMBER)
pkt = Ether(dst=SERVER_MAC, src=MAC3) / Southbound(ControllerID=CONTROLLER_ID , SwitchID=SWITCH_ID, ACK=1) / SouthboundUpdate(key=IP2_dst, port=NF1, check=1)
pkt = pad_pkt(pkt, MIN_PKT_SIZE)
expPkt(pkt, "nf3")

pkt = Ether(dst=MAC3, src=SERVER_MAC) / Southbound(ControllerID=CONTROLLER_ID , SwitchID=SWITCH_ID) / SouthboundUpdate(key=IP3_dst, check=1)
pkt = pad_pkt(pkt, MIN_PKT_SIZE)
applyPkt(pkt,"nf3",5+DUMMY_NUMBER)
pkt = Ether(dst=SERVER_MAC, src=MAC3) / Southbound(ControllerID=CONTROLLER_ID , SwitchID=SWITCH_ID, ACK=1) / SouthboundUpdate(key=IP3_dst, port=NF2, check=1)
pkt = pad_pkt(pkt, MIN_PKT_SIZE)
expPkt(pkt, "nf3")

#------------------------------------------------------------------------------------------------------------------------


# apply the trace
port_map = {IP1_dst:"nf0", IP2_dst:"nf1", IP3_dst:"nf2"}
mac_map = {IP1_dst:MAC0, IP2_dst:MAC1, IP3_dst:MAC2}
for i in range(len(trace)):
    applyPkt(trace[i], port_list[i%3], i+6+DUMMY_NUMBER)
    expPkt(trace[i], port_map[IPs[i]])
#    pkt_tmp = eval(pkt[Ether])
#    pkt_tmp[Ether].src = eth_dst
#    pkt_tmp[Ether].dst = mac_map[IPs[i]]
#    pkt_tmp = pad_pkt(pkt_tmp, (pkt[IP].len - pkt_tmp[IP].len))
#    expPkt(pkt_tmp,port_map[IPs[i]])
    i += 1
  
'''   
# apply some traffic
port_map = {IP1_dst:"nf0", IP2_dst:"nf1", IP3_dst:"nf2"}
mac_map = {IP1_dst:MAC0, IP2_dst:MAC1, IP3_dst:MAC2}
for i in range(len(trace)):
    pkt = Ether(dst=MAC1, src=SERVER_MAC) / IP(src=IP1_src, dst=ip_list[i%3]) / TCP(sport=sport, dport=dport, flags='A')
    pkt[Ether].dst = list(mac_map.values())[i%3]
    if (i < 3):
        pkt[TCP].flags = 'S'
    elif (i > len(trace)-4 ):
        pkt[TCP].flags = 'F'
    pkt_tmp = pad_pkt(pkt, PKT_SIZE)
    applyPkt(pkt_tmp, port_list[i%3], i+6+DUMMY_NUMBER)
    pkt[Ether].src = pkt[Ether].dst
    pkt[Ether].dst = mac_map[pkt[IP].dst]
    pkt_tmp = pad_pkt(pkt, PKT_SIZE)
    #expPkt(pkt_tmp,list(port_map.values())[i%3])
    expPkt(pkt_tmp,port_map[pkt[IP].dst])
'''
#------------------------------------------------------------------------------------------------------------------------

# set of empty packets to give time to the switch's registers to update the histogram
for i in range(DUMMY_NUMBER/3):
    pkt = Ether(dst=mac_list[i%4], src=SERVER_MAC)
    pkt = pad_pkt(pkt, MIN_PKT_SIZE)
    applyPkt(pkt,port_list[i%4], i+6+DUMMY_NUMBER+len(trace))
    expPkt(pkt, "none")

#------------------------------------------------------------------------------------------------------------------------

# Query packets at the end of the flows
pkt = Ether(dst=MAC3, src=SERVER_MAC) / Southbound(ControllerID=CONTROLLER_ID , SwitchID=SWITCH_ID) / SouthboundQuery(index=4)
pkt = pad_pkt(pkt, MIN_PKT_SIZE)
applyPkt(pkt,"nf3",6+2*DUMMY_NUMBER+len(trace)+1)
pkt = Ether(dst=SERVER_MAC, src=MAC3) / Southbound(ControllerID=CONTROLLER_ID , SwitchID=SWITCH_ID, ACK=1) / SouthboundQuery(index=4, result=0)
pkt = pad_pkt(pkt, MIN_PKT_SIZE)
expPkt(pkt,"nf3")

#------------------------------------------------------------------------------------------------------------------------

write_pcap_files()

