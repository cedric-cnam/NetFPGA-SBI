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


import os, sys, re, cmd, subprocess, shlex, time
from threading import Thread
import random, socket, struct
import numpy as np

sys.path.append(os.path.expandvars('$P4_PROJECT_DIR/testdata/'))
from nf_sim_tools import *
from southbound_headers import *


PKT_SIZE = 1000 # default payload size (in bytes) 
MIN_PKT_SIZE = 200
HEADER_SIZE = 54 # size of Ether/IP/TCP headers
IFACE = "eth1"

SERVER_MAC = "d0:50:99:d8:4a:91"
MAC3 = "33:33:33:33:33:33"

CONTROLLER_ID	= 1
SWITCH_ID	= 1

PORT_MAP = {'NONE':NONE, 'NF0':NF0, 'NF1':NF1, 'NF2':NF2, 'NF3':NF3}

os.system('sudo ifconfig {0} 10.0.0.10 netmask 255.255.255.0'.format(IFACE))

TCPDUMP = subprocess.Popen(shlex.split("tcpdump -i {0} -w /dev/null".format(IFACE)))
time.sleep(0.1)

class TCP_Tester(cmd.Cmd):
    """The HW testing tool for the TCP_monitor_standalone design"""

    prompt = "testing> "
    intro = "The HW testing tool for the TCP_monitor_standalone design\n type help to see all commands"
    """
    Submit packet to the switch and print the results
    """
    def _submit_pkt(self, pkt):
        print "in submit_pkt"
        
        sendp(pkt, iface=IFACE)
        
        print "Sent pkt"
        
    def validIPAddress(self, IP):
        def isIPv4(s):
            try: return str(int(s)) == s and 0 <= int(s) <= 255
            except: return False
        if IP.count(".") == 3 and all(isIPv4(i) for i in IP.split(".")):
            return "IPv4"
        return "False"        
    
    def _parse_line_update(self, line):
        args = line.split()
        if (len(args) != 3):
            print >> sys.stderr, "ERROR: usage..."
            self.help_lut_update()
            return
        ip_key  = args[0]
        port    = args[1]
        address = int(args[2])
        if (self.validIPAddress(ip_key) != "IPv4"):
            print >> sys.stderr, "ERROR: {0} is not an IP address".format(ip_key)
            return
        if (port not in PORT_MAP.keys()):
            print >> sys.stderr, "ERROR: {0} is not a valid port".format(port)
            return
        if ( (address < 0) or (address > (2**4)-1) ):
            print >> sys.stderr, "ERROR: {0} is not a valid address".format(address)
            return
        pkt = Ether(dst=MAC3, src=SERVER_MAC) / Southbound(ControllerID=CONTROLLER_ID , SwitchID=SWITCH_ID) / SouthboundUpdate(key=ip_key , port=port, address=address)
        pkt = pad_pkt(pkt, MIN_PKT_SIZE) # pad pkt to desired size
        return pkt   
        
    def _parse_line_check(self, line):
        args = line.split()
        if (len(args) != 1):
            print >> sys.stderr, "ERROR: usage..."
            self.help_lut_check()
            return
        ip_key  = args[0]
        if (self.validIPAddress(ip_key) != "IPv4"):
            print >> sys.stderr, "ERROR: {0} is not an IP address".format(ip_key)
            return
        pkt = Ether(dst=MAC3, src=SERVER_MAC) / Southbound(ControllerID=CONTROLLER_ID , SwitchID=SWITCH_ID) / SouthboundUpdate(key=ip_key, check=1)
        pkt = pad_pkt(pkt, MIN_PKT_SIZE) # pad pkt to desired size
        return pkt
        
    def _parse_line_test_packet(self, line):
        args = line.split()
        if (len(args) != 1):
            print >> sys.stderr, "ERROR: usage..."
            self.help_test_packet()
            return
        dst = args[0]
        if ( self.validIPAddress(dst) != "IPv4"):
            print >> sys.stderr, "ERROR: {0} is not an IP address".format(dst)
            return
        pkt = Ether(dst=MAC3, src=SERVER_MAC) / IP(dst=dst, src="10.0.0.10")
        pkt = pad_pkt(pkt, PKT_SIZE) # pad pkt to desired size
        return pkt  
        
    def _parse_line_metric_query(self, line):
        args = line.split()
        if (len(args) != 1):
            print >> sys.stderr, "ERROR: usage..."
            self.help_metric_query()
            return
        index = int(args[0])
        if ( (index < 0) or (index > (2**3)-1 ) ):
            print >> sys.stderr, "ERROR: {0} is not a valid index".format(index)
            return
        pkt = Ether(dst=MAC3, src=SERVER_MAC) / Southbound(ControllerID=CONTROLLER_ID , SwitchID=SWITCH_ID) / SouthboundQuery(index=index)
        pkt = pad_pkt(pkt, MIN_PKT_SIZE) # pad pkt to desired size
        return pkt 
        
    def _parse_line_metric_reset(self, line):
        args = line.split()
        if (len(args) != 1):
            print >> sys.stderr, "ERROR: usage..."
            self.help_metric_reset()
            return
        index = int(args[0])
        if ( (index < 0) or (index > (2**3)-1 ) ):
            print >> sys.stderr, "ERROR: {0} is not a valid index".format(index)
            return
        pkt = Ether(dst=MAC3, src=SERVER_MAC) / Southbound(ControllerID=CONTROLLER_ID , SwitchID=SWITCH_ID) / SouthboundQuery(index=index, reset=1)
        pkt = pad_pkt(pkt, MIN_PKT_SIZE) # pad pkt to desired size
        return pkt
        
    
    def do_lut_update(self, line):
        pkt = self._parse_line_update(line) 
        self._submit_pkt(pkt)   
        
    def do_lut_check(self, line):
        pkt = self._parse_line_check(line) 
        self._submit_pkt(pkt) 
        
    def do_test_packet(self, line):
        pkt = self._parse_line_test_packet(line) 
        self._submit_pkt(pkt)  
        
    def do_metric_query(self, line):
        pkt = self._parse_line_metric_query(line) 
        self._submit_pkt(pkt) 
        
    def do_metric_reset(self, line):
        pkt = self._parse_line_metric_reset(line) 
        self._submit_pkt(pkt)
                   

    def help_lut_update(self):
        print """
        lut_update <ip_key> <port> <address>
        DESCRIPTION: Create a single SBI LUT-update packet to update the switch's IP lookup table.
        NOTES:
            <ip_key> : must be a valid IP address. Example: lut_update 10.0.0.5 NF0 1
            <port> : must be one of the following [NONE, NF0, NF1, NF2, NF3] 
            <address> : must be an integer between 0 and 31
        """  
        
    def help_lut_check(self):
        print """
        lut_check <ip_key>
        DESCRIPTION: Create a single SBI LUT-check packet with check flag to check a routing rule.
        NOTES:
            <ip_key> : must be a valid IP address. Example: lut_update 10.0.0.5 NF0 1
        """ 
        
    def help_test_packet(self):
        print """
        test_packet <dst>
        DESCRIPTION: Create a single IP packet to test the switch functionality.
        NOTES:
            <dst> : must be a valid IP address. Example: test_packet 10.0.0.5
        """ 
        
    def help_metric_query(self):
        print """
        metric_query <index>
        DESCRIPTION: Create a single SBI Metric-query packet to query a tcp_monitor histogram register entry.
        NOTES:
            <index> : must be an integer between 0 and 7
        """ 
        
    def help_metric_reset(self):
        print """
        metric_reset <index>
        DESCRIPTION: Create a single SBI Metric-reset packet to reset a tcp_monitor histogram register entry.
        NOTES:
            <index> : must be an integer between 0 and 7
        """ 

    """
    Run Flow
    """
    def _get_rand_IP(self):
        return socket.inet_ntoa(struct.pack('>I', random.randint(1, 0xffffffff)))

    def _get_rand_port(self):
        return random.randint(1, 0xffff)

    def _make_flow(self, flow_size):
        pkts = []
        srcIP = self._get_rand_IP()
        dstIP = self._get_rand_IP()
        sport = self._get_rand_port()
        dport = self._get_rand_port()
        # make the SYN PKT
        pkt = Ether(dst=MAC3, src=SERVER_MAC) / IP(src=srcIP, dst=dstIP) / TCP(sport=sport, dport=dport, flags='S')
        pkt = pad_pkt(pkt, MIN_PKT_SIZE)
        pkts.append(pkt)
        # make the data pkts
        size = flow_size
        while size >= PKT_SIZE:
            pkt = Ether(dst=MAC3, src=SERVER_MAC) / IP(src=srcIP, dst=dstIP) / TCP(sport=sport, dport=dport, flags='A')
            pkt = pad_pkt(pkt, PKT_SIZE + HEADER_SIZE) 
            pkts.append(pkt)
            size -= PKT_SIZE 
        # make the FIN pkt
        size = max(MIN_PKT_SIZE - HEADER_SIZE, size)
        pkt = Ether(dst=MAC3, src=SERVER_MAC) / IP(src=srcIP, dst=dstIP) / TCP(sport=sport, dport=dport, flags='F')
        pkt = pad_pkt(pkt, HEADER_SIZE + size)
        pkts.append(pkt)
        return pkts

    """
    Generate a trace of flows indicated by the given parameters and apply to the switch 
    """
    def _run_flows(self, num_flows, min_size, max_size):
        trace = []
        for fid in range(num_flows):
            size = random.randint(min_size, max_size)
            # create the flows pkts
            flow_pkts = self._make_flow(size)
            # randomly interleave flow's pkts into trace
            trace = list(map(next, random.sample([iter(trace)]*len(trace) + [iter(flow_pkts)]*len(flow_pkts), len(trace)+len(flow_pkts))))        

        # apply trace to the switch
        sendp(trace, iface=IFACE)

    def _parse_line_run_flow(self, line):
        args = line.split()
        if (len(args) != 3):
            print >> sys.stderr, "ERROR: usage..."
            self.help_run_flows()
            return (None, None, None)
        try:
            num_flows = int(args[0])
            min_size = int(args[1])
            max_size = int(args[2])
        except:
            print >> sys.stderr, "ERROR: all arguments must be valid integers"
            return (None, None, None)
        return (num_flows, min_size, max_size)


    def do_run_flows(self, line):
        (num_flows, min_size, max_size) = self._parse_line_run_flow(line) 
        if (num_flows is not None and min_size is not None and max_size is not None):
            self._run_flows(num_flows, min_size, max_size)
        
    def help_run_flows(self):
        print """
        run_flows <num_flows> <min_size> <max_size> 
        DESCRIPTION: Create a trace simulating some number of distinct TCP flows all running simultaneously
        and apply the resulting packets to the switch. The size (in bytes) of each flow will be randomly 
        chosen between <min_size> and <max_size> 
            <num_flows> : the number of concurrent active flows to run through the switch
            <min_size>  : the minimum possible size of each flow
            <max_size>  : the maximum possible size of each flow
        """
        

    def do_exit(self, line):
        print "in do_exit"
        if (TCPDUMP.poll() is None):
            TCPDUMP.terminate()
        sys.exit(0)

    def do_EOF(self, line):
        print "in do_EOF"
        print ""
        if (TCPDUMP.poll() is None):
            TCPDUMP.terminate()
        return True

if __name__ == '__main__':
    if len(sys.argv) > 1:
        TCP_Tester().onecmd(' '.join(sys.argv[1:]))
        if (TCPDUMP.poll() is None):
            TCPDUMP.terminate()
    else:
        TCP_Tester().cmdloop()
