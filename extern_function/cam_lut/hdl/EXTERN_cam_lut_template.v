//
// Copyright (c) 2022 Mario Patetta, Conservatoire National des Arts et Mètiers
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


/*
 * File: @MODULE_NAME@.v 
 * Author: Mario Patetta
 *
 * Auto-generated file.
 *
 * cam_lut
 *
 * Description: cam based lookup table extern function.
 *
 */



`timescale 1 ps / 1 ps
`define REQ_OP      4'd0
`define SET_OP      4'd1
`define CLEAR_OP    4'd2


module @MODULE_NAME@ 
#(
    parameter KEY_WIDTH = @KEY_WIDTH@,
    parameter VALUE_WIDTH = @VALUE_WIDTH@,
    parameter ADDRESS_WIDTH = @ADDRESS_WIDTH@, 
    parameter OP_WIDTH = 4,
    parameter INPUT_WIDTH = KEY_WIDTH + ADDRESS_WIDTH + VALUE_WIDTH + OP_WIDTH + 1,
    parameter OUTPUT_WIDTH = VALUE_WIDTH+2
)
(
    // Data Path I/O
    input                                          clk_lookup,
    input                                          rst, 
    input                                          tuple_in_@EXTERN_NAME@_input_VALID,
    input   [INPUT_WIDTH-1:0]                      tuple_in_@EXTERN_NAME@_input_DATA,
    output                                         tuple_out_@EXTERN_NAME@_output_VALID,
    output  [OUTPUT_WIDTH-1:0]                     tuple_out_@EXTERN_NAME@_output_DATA
);


/* Tuple format for input:
        [KEY_WIDTH+ADDRESS_WIDTH+VALUE_WIDTH+OP_WIDTH    : KEY_WIDTH+ADDRESS_WIDTH+VALUE_WIDTH+OP_WIDTH    ] : statefulValid_in
        [KEY_WIDTH+ADDRESS_WIDTH+VALUE_WIDTH+OP_WIDTH-1  : ADDRESS_WIDTH+VALUE_WIDTH+OP_WIDTH              ] : key_in    
        [ADDRESS_WIDTH+VALUE_WIDTH+OP_WIDTH-1            : VALUE_WIDTH+OP_WIDTH                            ] : address_in            
        [VALUE_WIDTH+OP_WIDTH-1                          : OP_WIDTH                                        ] : newValue_in
        [OP_WIDTH-1                                      : 0                                               ] : opCode_in
*/

    // request_fifo output signals 
    wire                               statefulValid_fifo; 
    wire    [KEY_WIDTH-1:0]            key_fifo;
    wire    [ADDRESS_WIDTH-1:0]        address_fifo;
    wire    [VALUE_WIDTH-1:0]          newValue_fifo;
    wire    [OP_WIDTH-1:0]             opCode_fifo;
    
    wire empty_fifo;
    wire full_fifo;
    reg rd_en_fifo;

    localparam L2_REQ_BUF_DEPTH = 3;
    localparam BRAM_DEPTH = 2**ADDRESS_WIDTH;

    // state machine states
    localparam CLEAR            = 0;
    localparam IDLE             = 1;
    localparam LUT_READ         = 2;
    localparam LUT_READ_WAIT    = 3;

    // state machine signals
    reg [2:0]                   d_state, d_state_next;
    reg [2:0]                   lut_watchdog_cnt, lut_watchdog_cnt_next;
    reg [VALUE_WIDTH-1:0]       result_r, result_r_next;
    reg                         match_r, match_r_next;
    reg                         valid_out, valid_out_next;

    // LUT signals
    reg [ADDRESS_WIDTH-1:0]     set_addr_cam;
    reg [VALUE_WIDTH-1:0]       set_data_cam;
    reg [KEY_WIDTH-1:0]         set_key_cam, set_xmask_cam;
    reg                         set_clr_cam;
    reg                         set_valid_cam;
    reg [KEY_WIDTH-1:0]         req_key_cam;
    reg                         req_valid_cam;
    wire                        req_ready_cam;
    wire [ADDRESS_WIDTH-1:0]    res_addr_cam;
    wire [VALUE_WIDTH-1:0]      res_data_cam;
    wire                        res_valid_cam;
    wire                        res_null_cam;
    
    
    //// Input buffer to hold requests ////
    fallthrough_small_fifo
    #(
        .WIDTH(INPUT_WIDTH),
        .MAX_DEPTH_BITS(L2_REQ_BUF_DEPTH)
    )
    request_fifo
    (
       // Outputs
       .dout                           ({statefulValid_fifo, key_fifo, address_fifo, newValue_fifo, opCode_fifo}),
       .full                           (full_fifo),
       .nearly_full                    (),
       .prog_full                      (),
       .empty                          (empty_fifo),
       // Inputs
       .din                            (tuple_in_@EXTERN_NAME@_input_DATA),
       .wr_en                          (tuple_in_@EXTERN_NAME@_input_VALID),
       .rd_en                          (rd_en_fifo),
       .reset                          (rst),
       .clk                            (clk_lookup)
    );

    ////TCAM
    tcam
    #(
        .ADDR_WIDTH(ADDRESS_WIDTH),
        .KEY_WIDTH(KEY_WIDTH),
        .DATA_WIDTH(VALUE_WIDTH),
        .MASK_DISABLE(1)
    )
    ipv4_lut
    (
        .clk(clk_lookup),
        .rst(rst),
        // Set
        .set_addr(set_addr_cam),
        .set_data(set_data_cam),
        .set_key(set_key_cam),
        .set_xmask(0),
        .set_clr(set_clr_cam),
        .set_valid(set_valid_cam),
        // Request
        .req_key(req_key_cam),
        .req_valid(req_valid_cam),
        .req_ready(req_ready_cam),
        // Response
        .res_addr(res_addr_cam),
        .res_data(res_data_cam),
        .res_valid(res_valid_cam),
        .res_null(res_null_cam)        
    );

    
   /* data plane R/U State Machine */ 
   always @(*) begin
      // default values
      d_state_next = d_state;
      rd_en_fifo = 0;
      
      set_addr_cam = 0;
      set_data_cam = 0;
      set_key_cam = 0;
      set_clr_cam = 0;
      set_valid_cam = 0;
      req_key_cam = 0;
      req_valid_cam = 0;
            
      // output signals
      result_r_next = 0;
      match_r_next = 0;
      valid_out_next = 0;

      case(d_state)
         CLEAR: begin
            set_clr_cam = 1;
            set_valid_cam = 1;
            d_state_next = IDLE;
         end
         
         IDLE: begin
            lut_watchdog_cnt_next = 0;
            if (~empty_fifo) begin
               rd_en_fifo = 1;
               if (statefulValid_fifo) begin
                  if (opCode_fifo == `CLEAR_OP) begin
                     d_state_next = CLEAR;
                  end else if (opCode_fifo == `REQ_OP) begin
                     if (req_ready_cam) begin
                         req_valid_cam = 1;
                         req_key_cam = key_fifo;
                         d_state_next = LUT_READ;
                     end else begin
                        d_state_next = LUT_READ_WAIT;
                     end
                  end else if (opCode_fifo == `SET_OP) begin
                     set_addr_cam = address_fifo;
                     set_data_cam = newValue_fifo;
                     set_key_cam  = key_fifo;
                     set_valid_cam = 1;
                     valid_out_next = 1;
                     // stay in same state (result and match are set to 0 by default)
                  end else begin
                     $display("ERROR: d_state = IDLE, unsupported opCode: %0d\n", opCode_fifo);
                     valid_out_next = 1;
                     // stay in same state (result and match are set to 0 by default)
                  end
               end else begin
                  valid_out_next = 1;
                  // stay in same state (result and match are set to 0 by default)
               end
            end
         end

         LUT_READ: begin
            d_state_next = LUT_READ;
            lut_watchdog_cnt_next = lut_watchdog_cnt +1;
            if ( res_valid_cam | (lut_watchdog_cnt == 5) ) begin  
                valid_out_next = 1; 
                d_state_next = IDLE;         
                if(~res_null_cam) begin
                    match_r_next = ~res_null_cam;
                    result_r_next = res_data_cam;
                end
            end
         end
            
         LUT_READ_WAIT: begin
            d_state_next = LUT_READ_WAIT;
            lut_watchdog_cnt_next = lut_watchdog_cnt +1;
            if (req_ready_cam) begin  
                req_valid_cam = 1;
                req_key_cam = key_fifo;
                lut_watchdog_cnt_next = 0;
                d_state_next = LUT_READ;
            end else if (lut_watchdog_cnt == 5) begin
                valid_out_next = 1; 
                d_state_next = IDLE;
            end
         end 
      endcase   // case(dstate)         
   end          // State Machine

   always @(posedge clk_lookup) begin
      if(rst) begin
         d_state <= CLEAR;         
         lut_watchdog_cnt_next <= 0;
         match_r <= 0;         
         result_r <= 0;
         valid_out <= 0;
      end else begin
         d_state <= d_state_next;
         lut_watchdog_cnt <= lut_watchdog_cnt_next;        
         match_r <= match_r_next;
         result_r <= result_r_next;
         valid_out <= valid_out_next;
      end
   end
   
   assign tuple_out_@EXTERN_NAME@_output_VALID = valid_out;
   assign tuple_out_@EXTERN_NAME@_output_DATA  = {match_r, result_r};


endmodule
