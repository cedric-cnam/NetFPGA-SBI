//
// Copyright (c) 2022 Mario Patetta, Conservatoire National des Arts et Metiers
// Copyright (c) 2017 Stephen Ibanez
// All rights reserved.
//
// This software was developed by Stanford University and the University of Cambridge Computer Laboratory 
// under National Science Foundation under Grant No. CNS-0855268,
// the University of Cambridge Computer Laboratory under EPSRC INTERNET Project EP/H040536/1 and
// by the University of Cambridge Computer Laboratory under DARPA/AFRL contract FA8750-11-C-0249 ("MRC2"), 
// as part of the DARPA MRC research programme.
//
// @NETFPGA_LICENSE_HEADER_START@
//
// Licensed to NetFPGA C.I.C. (NetFPGA) under one or more contributor
// license agreements.  See the NOTICE file distributed with this work for
// additional information regarding copyright ownership.  NetFPGA licenses this
// file to you under the NetFPGA Hardware-Software License, Version 1.0 (the
// "License"); you may not use this file except in compliance with the
// License.  You may obtain a copy of the License at:
//
//   http://www.netfpga-cic.org
//
// Unless required by applicable law or agreed to in writing, Work distributed
// under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
// CONDITIONS OF ANY KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations under the License.
//
// @NETFPGA_LICENSE_HEADER_END@
//


#include <core.p4>
#include <sume_switch.p4>
#include "SBI_engine.p4"

/*
 * File: standalone_switch.p4
 * Author: Mario Patetta
 * 
 * Description:
 * This switch design leverages the introduction of an extern lookup table
 * to enable the board to work in standalone mode.
 *
 * We used tcp_monitor (slightly modified) as use case to test 
 * the query-information primitive.
 *
 */

//----- TCP Monitor defines --------- 
#define SYN_MASK    8w0b0000_0010
#define SYN_POS     1

#define FIN_MASK    8w0b0000_0001
#define FIN_POS     0
//-----------------------------------

//--- histogram bin boundaries ------ 
#define LEVEL_1   16000
#define LEVEL_2   32000
#define LEVEL_3   48000
#define LEVEL_4   64000
#define LEVEL_5   80000
#define LEVEL_6   96000
#define LEVEL_7   112000 
//-----------------------------------

//--------- Reg Commands ------------ 
#define REG_READ   8w0
#define REG_WRITE  8w1
#define REG_ADD    8w2
//-----------------------------------

/*************************************************************************
				 E X T E R N S 
*************************************************************************/

// hash function
#define HASH_WIDTH 5
@Xilinx_MaxLatency(1)
@Xilinx_ControlWidth(0)
extern void hash_lrc(in bit<104> in_data, out bit<HASH_WIDTH> result);

// byte_cnt register
@Xilinx_MaxLatency(64)
@Xilinx_ControlWidth(HASH_WIDTH)
extern void byte_cnt_reg_raw(in bit<HASH_WIDTH> index,
                             in bit<32> newVal,
                             in bit<32> incVal,
                             in bit<8> opCode,
                             out bit<32> result);

// dist register
@Xilinx_MaxLatency(64)
@Xilinx_ControlWidth(3)
extern void dist_reg_raw(in bit<3> index,
                         in bit<32> newVal,
                         in bit<32> incVal,
                         in bit<8> opCode,
                         out bit<32> result);


/*************************************************************************
				 M E T A D A T A 
*************************************************************************/

// user defined metadata: can be used to share information between
// TopParser, TopPipe, and TopDeparser 
struct user_metadata_t {
    bit<8>  unused;
}

// digest data to send to cpu if desired. MUST be 256 bits!
struct digest_data_t {
    bit<256>  unused;
}


/*************************************************************************
				 P A R S E R 
*************************************************************************/

@Xilinx_MaxPacketRegion(8192)
parser TopParser(packet_in b, 
                 out Parsed_packet p, 
                 out user_metadata_t user_metadata,
                 out digest_data_t digest_data,
                 inout sume_metadata_t sume_metadata) {
    state start {
        b.extract(p.ethernet);
        
        user_metadata.unused = 0;
        digest_data.unused = 0;
        
        transition select(p.ethernet.etherType) {
            SOUTHBOUND_TYPE:    check_ControllerID;
            IPV4_TYPE:          parse_ipv4;
            default:            reject;
        } 
    }
    
    state check_ControllerID {
	b.extract(p.SB);
	transition select(p.SB.ControllerID) {
	        CONTROLLER_ID:	check_SwitchID;
	        default:		reject;
	    }
    }

    state check_SwitchID {
        transition select(p.SB.SwitchID) {
            SWITCH_ID:      parse_SB;
            default:        reject;
        }
    }    
    
    state parse_SB {
	    transition select(p.SB.type) {
            UPDATE_TYPE:    parse_SB_update;
            QUERY_TYPE:     parse_SB_query;
            default:        reject;
        }
    }

    state parse_ipv4 {
        b.extract(p.ip);
        transition select(p.ip.protocol) {
            TCP_TYPE:   parse_tcp;
            default:    reject;
        }
    }

    state parse_SB_update {
        b.extract(p.SB_update);
        transition accept;
    }
    
    state parse_SB_query {
        b.extract(p.SB_query);
        transition accept;
    }
    
    state parse_tcp {
        b.extract(p.tcp);
        transition accept;
    }
}


/*************************************************************************
		M A T C H - A C T I O N    P I P E L I N E  
*************************************************************************/

control TopPipe(inout Parsed_packet p,
                inout user_metadata_t user_metadata, 
                inout digest_data_t digest_data, 
                inout sume_metadata_t sume_metadata) {

    action no_action(port_t x) {
        sume_metadata.dst_port = x;
    }

    table unused_table {
        key = { p.ethernet.dstAddr: exact; }

        actions = {
            no_action;
            NoAction;
        }
        size = 64;
        default_action = NoAction;
    }
    
    RoutingStage()      RoutingStage_inst;

    apply {
        unused_table.apply();
        
	// metadata for register accesses
	bit<32>	newVal = 0;
	bit<32>	incVal = 0;
	bit<8>	Reg_opCode = REG_READ;
	bit<3>	index = 0;

        if (p.tcp.isValid()) { 
            
            // compute hash of 5-tuple to obtain index for byte_cnt register
            bit<HASH_WIDTH> hash_result;
            hash_lrc(p.ip.srcAddr++p.ip.dstAddr++p.ip.protocol++p.tcp.srcPort++p.tcp.dstPort, hash_result); 
            
            // set newVal, incVal, and Reg_opCode appropriately based on
            // whether this is a SYN packet 
            if ((p.tcp.flags & SYN_MASK) >> SYN_POS == 1) {
                // Is a SYN packet
                newVal = 0; // reset the pkt_cnt state for this entry
                incVal = 0; // unused
                Reg_opCode = REG_WRITE;
            } else {
                // Is not a SYN packet
                newVal = 0; // unused
                incVal = 16w0++sume_metadata.pkt_len - 32w54; // count TCP payload bytes for this connection
                Reg_opCode = REG_ADD;
            }
           
            // access the byte_cnt register 
            bit<32> numBytes;
            byte_cnt_reg_raw(hash_result, newVal, incVal, Reg_opCode, numBytes);

            // set index, newVal, incVal, and Reg_opCode appropriately
            // based on whether or not this is a FIN packet
            if((p.tcp.flags & FIN_MASK) >> FIN_POS == 1) {
                // FIN bit is set 
                newVal = 0; // unused
                incVal = 1; // increment one of the buckets
                Reg_opCode = REG_ADD;
  
                if (numBytes <= LEVEL_1) {
                    index = 0;
                } else if (LEVEL_1 < numBytes && numBytes <= LEVEL_2) {
                    index = 1;
                } else if (LEVEL_2 < numBytes && numBytes <= LEVEL_3) {
                    index = 2;
                } else if (LEVEL_3 < numBytes && numBytes <= LEVEL_4) {
                    index = 3;
                } else if (LEVEL_4 < numBytes && numBytes <= LEVEL_5) {
                    index = 4;
                } else if (LEVEL_5 < numBytes && numBytes <= LEVEL_6) {
                    index = 5;
                } else if (LEVEL_6 < numBytes && numBytes <= LEVEL_7) {
                    index = 6; 
                } else {
                    index = 7;
                }
            }
            else {
                index = 0;
                newVal = 0; // unused
                incVal = 0; // unused
                Reg_opCode = REG_READ;
            }
        }
        
        if (p.SB_query.isValid()) {
            index = p.SB_query.reg_address;
            if (p.SB_query.reset == 1) {
                Reg_opCode = REG_WRITE;
                newVal = 0;
            }
        }
        
	// access the distribution register
	bit<32> result = 0;
        if ( p.SB_query.isValid() || p.tcp.isValid() )  {
            dist_reg_raw(index, newVal, incVal, Reg_opCode, result);
        }
            
        if (p.SB_query.isValid()) {
            p.SB_query.result = result;
        }
        
        // Apply the Routing Engine
        RoutingStage_inst.apply(p, sume_metadata);
    }
}

// Deparser Implementation
@Xilinx_MaxPacketRegion(8192)
control TopDeparser(packet_out b,
        in Parsed_packet p,
        in user_metadata_t user_metadata,
        inout digest_data_t digest_data, 
        inout sume_metadata_t sume_metadata) { 
    apply {
        b.emit(p.ethernet);         
        b.emit(p.ip);
        b.emit(p.tcp);
        b.emit(p.SB);
        b.emit(p.SB_query);
        b.emit(p.SB_update);
    }
}


// Instantiate the switch
SimpleSumeSwitch(TopParser(), TopPipe(), TopDeparser()) main;

