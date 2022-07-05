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

sys.path.append(os.path.expandvars('$P4_PROJECT_DIR/testdata/'))
sys.path.append(os.path.expandvars('${SUME_SDNET}/bin'))
from southbound_headers import *
from nf_sim_tools import *

IFACE = "eth1"

os.system('sudo ifconfig {0} 10.0.0.11 netmask 255.255.255.0'.format(IFACE))

port_map = {0:"NONE", 1:"NF0", 2:"NF1", 4:"NF2", 8:"NF3"}

def print_SB(pkt):
    if not ( (Southbound in pkt) or (IP in pkt) ):
        return
    elif IP in pkt:
        return
    elif ( (Southbound in pkt) & (pkt[Southbound].ACK == 1) ):
        if SouthboundUpdate in pkt:
            width = 10
            n = 9
            update_fmat_string =      "|  ETHERNET  | SB | key:{0:<{width}} port:{1:<{width}} address:{2:<{width}} check:{3:<{width}} |"
            print "Recieved pkt: "
            print "{0:-<{width}}".format("-", width=n*width)
            print update_fmat_string.format(pkt[SouthboundUpdate].key, port_map[pkt[SouthboundUpdate].port], pkt[SouthboundUpdate].address, pkt[SouthboundUpdate].check, width=width)
            print "{0:-<{width}}\n".format("-", width=n*width)
        elif SouthboundQuery in pkt:
            width = 10
            n = 9
            query_fmat_string =      "|  ETHERNET  | SB | result:{0:<{width}} index:{1:<{width}} |"
            print "Recieved pkt: "
            print "{0:-<{width}}".format("-", width=n*width)
            print query_fmat_string.format(pkt[SouthboundQuery].result, pkt[SouthboundQuery].index, width=width)
            print "{0:-<{width}}\n".format("-", width=n*width)


def main():
    sniff(iface=IFACE, prn=print_SB, count=0)


if __name__ == "__main__":
    main()
