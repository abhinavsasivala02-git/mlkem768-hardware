/*
 * Copyright (C) 2026
 * Author: Abhinav S <abhinavsasivala02@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301  USA
 */

//============================================================================
// ByteDecode_d — Algorithm 6 of FIPS 203
// Decodes 32*d bytes into 256 d-bit integers
//
// Inverse of ByteEncode: unpacks bytes into polynomial coefficients
// For d < 12, output values are naturally in [0, 2^d - 1]
// For d = 12, output values are reduced mod q
module byte_decode #(
    parameter D = 12     // Bit-width per coefficient (1..12)
)(
    input  wire        clk,
    input  wire        rst_n,
    input  wire        start,
    output reg         done,
    output reg         busy,
    // Input byte stream
    input  wire        byte_valid,
    input  wire [7:0]  byte_data,
    output reg         byte_req,

    // Output polynomial RAM — write interface
    output reg         poly_wen,
    output reg  [7:0]  poly_addr,
    output reg  [11:0] poly_wdata
);

    `include "mlkem_params.vh"

    localparam TOTAL_BYTES = 32 * D;

    // FSM
    localparam S_IDLE    = 3'd0;
    localparam S_FETCH   = 3'd1;
    localparam S_UNPACK  = 3'd2;
    localparam S_WRITE   = 3'd3;
    localparam S_DONE    = 3'd4;

    reg [2:0] state;

    // Bit accumulator
    reg [23:0] bit_acc;
    reg [4:0]  bit_cnt;
    reg [8:0]  coeff_idx;      // 0..255
    reg [10:0] in_byte_cnt;    // 0..TOTAL_BYTES-1

    // Extracted coefficient (before mod q)
    wire [11:0] raw_coeff;
    wire [11:0] reduced_coeff;

    assign raw_coeff = bit_acc[D-1:0];
    // For d=12, reduce mod q; for d<12, no reduction needed
    assign reduced_coeff = (D == 12 && raw_coeff >= MLKEM_Q[11:0]) ?
                           raw_coeff - MLKEM_Q[11:0] : raw_coeff;

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            state       <= S_IDLE;
            done        <= 1'b0;
            busy        <= 1'b0;
            poly_wen    <= 1'b0;
            poly_addr   <= 8'd0;
            poly_wdata  <= 12'd0;
            byte_req    <= 1'b0;
            bit_acc     <= 24'd0;
            bit_cnt     <= 5'd0;
            coeff_idx   <= 9'd0;
            in_byte_cnt <= 11'd0;
        end else begin
            poly_wen <= 1'b0;
            done     <= 1'b0;
            byte_req <= 1'b0;

            case (state)
                S_IDLE: begin
                    busy <= 1'b0;
                    if (start) begin
                        busy        <= 1'b1;
                        coeff_idx   <= 9'd0;
                        bit_acc     <= 24'd0;
                        bit_cnt     <= 5'd0;
                        in_byte_cnt <= 11'd0;
                        state       <= S_FETCH;
                        byte_req    <= 1'b1;
                    end
                end

                S_FETCH: begin
                    if (byte_valid) begin
                        // Add 8 bits to accumulator
                        bit_acc <= bit_acc | ({16'd0, byte_data} << bit_cnt);
                        bit_cnt <= bit_cnt + 5'd8;
                        in_byte_cnt <= in_byte_cnt + 11'd1;
                        state   <= S_UNPACK;
                    end
                end

                S_UNPACK: begin
                    if (bit_cnt >= D[4:0] && coeff_idx < 9'd256) begin
                        state <= S_WRITE;
                    end else if (in_byte_cnt < TOTAL_BYTES) begin
                        byte_req <= 1'b1;
                        state    <= S_FETCH;
                    end else begin
                        state <= S_DONE;
                    end
                end

                S_WRITE: begin
                    poly_wen   <= 1'b1;
                    poly_addr  <= coeff_idx[7:0];
                    poly_wdata <= reduced_coeff;
                    bit_acc    <= bit_acc >> D;
                    bit_cnt    <= bit_cnt - D[4:0];
                    coeff_idx  <= coeff_idx + 9'd1;

                    if (coeff_idx == 9'd255) begin
                        state <= S_DONE;
                    end else begin
                        state <= S_UNPACK;
                    end
                end

                S_DONE: begin
                    done <= 1'b1;
                    busy <= 1'b0;
                    state <= S_IDLE;
                end

                default: state <= S_IDLE;
            endcase
        end
    end

endmodule
