#
# Copyright (c) 2022 Mario Patetta, Conservatoire National des Arts et Metiers
# All rights reserved.
#
# SBI_engine is free software: you can redistribute it and/or modify it under the terms of
# the GNU Affero General Public License as published by the Free Software Foundation, either 
# version 3 of the License, or any later version.
#
# SBI_engine is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
# without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
# See the GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License along with this program.
# If not, see <https://www.gnu.org/licenses/>.
#

from scapy.all import *
import sys, os

SOUTHBOUND_TYPE = 0x1212

UPDATE_TYPE = 0x01
QUERY_TYPE  = 0x02

NONE = 0
NF0  = 1
NF1  = 2
NF2  = 4
NF3  = 8


class Southbound(Packet):
    name = "Southbound"
    fields_desc = [
		BitField("ControllerID",0,16),
		BitField("SwitchID",0,16),
		ByteEnumField("type", 0x01, {UPDATE_TYPE:"UPDATE_TYPE", QUERY_TYPE:"QUERY_TYPE"}),
		BitField("ACK",0,1),
		BitField("length",0,7),
    ]
    def mysummary(self):
        return self.sprintf("ControllerID=%ControllerID% SwitchID=%SwitchID% type=%type% ACK=%ACK% unused=%unused%")

bind_layers(Ether, Southbound, type=SOUTHBOUND_TYPE)


class SouthboundUpdate(Packet):
    name = "SouthboundUpdate"
    fields_desc = [
		IPField("key", "127.0.0.1"),
		BitEnumField("port", 0, 4, {NONE:"NONE", NF0:"NF0", NF1:"NF1", NF2:"NF2", NF3:"NF3"}),
		BitField("address",0,4),
		BitField("check",0,1),                                        	    # If check = 1 -> port and address should be set to 0
		BitField("unused", 0,7),
    ]
    def mysummary(self):
        return self.sprintf("key=%key% port=%port% address=%address% check=%check% unused=%unused%")

bind_layers(Southbound, SouthboundUpdate, type=UPDATE_TYPE, length=12)


class SouthboundQuery(Packet):
    name = "SouthboundQuery"                                       	    # Target dependant
    fields_desc = [
        BitField("result",0,32),
		BitField("index",0,3),
		BitField("reset",0,1),
		BitField("unused",0,4),		
    ]
    def mysummary(self):
        return self.sprintf("index=%index% result=%result%  unused=%unused%")

bind_layers(Southbound, SouthboundQuery, type=QUERY_TYPE, length=11)
