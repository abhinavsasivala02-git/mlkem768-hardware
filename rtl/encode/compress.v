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
// Compress_d - FIPS 203 Section 4.2.1 (formula 4.7)
// Compress_d(x) = round(2^d / q * x) mod 2^d
//
// Implements the reference algorithm exactly (FiloSottile/mlkem768):
//   dividend  = x << d
//   quotient0 = dividend * R >> (2*Q_BIT_WIDTH)      // R = 2^16, Q_BIT_WIDTH = 12
//   remainder = dividend - quotient0 * q
//   quotient1 = quotient0 + ((q/2 - remainder) >> 31) & 1
//   quotient2 = quotient1 + ((q + q/2 - remainder) >> 31) & 1
//   result    = quotient2 & ((1<<d) - 1)
//============================================================================
module compress #(
    parameter D = 10     // Compression bits (1, 4, 5, 10, 11)
)(
    input  wire        clk,
    input  wire        rst_n,
    input  wire        start,
    output reg         done,
    output reg         busy,

    // Input polynomial RAM - read
    output reg  [7:0]  in_addr,
    input  wire [11:0] in_rdata,

    // Output polynomial RAM - write
    output reg         out_wen,
    output reg  [7:0]  out_addr,
    output reg  [11:0] out_wdata
);

    `include "mlkem_params.vh"

    // FSM
    localparam S_IDLE  = 3'd0;
    localparam S_READ  = 3'd1;
    localparam S_WAIT  = 3'd2;
    localparam S_COMP  = 3'd3;
    localparam S_WRITE = 3'd4;
    localparam S_NEXT  = 3'd5;
    localparam S_DONE  = 3'd6;

    reg [2:0] state;
    reg [8:0] idx;

    // ---- Compression computation (FIPS 203 exact) ----
    localparam Q = 3329;
    localparam Q_BIT_WIDTH = 12;   // bit_width(3329) = 12
    localparam R = (1 << (2 * Q_BIT_WIDTH)) / Q;   // 5039
    localparam RSHIFT = 2 * Q_BIT_WIDTH;           // 24
    // quotient0 = (dividend * R) >> RSHIFT
    // max dividend = (q-1) << 11 = 3328<<11 = 6815744 < 2^23
    wire [22:0]  dividend;
    wire [34:0]  prod;
    wire [11:0]  quotient0;
    wire [22:0]  rem0;

    assign dividend = {12'd0, in_rdata} << D;
    assign prod = dividend * R;
    assign quotient0 = prod[34:24];      // >> 24

    assign rem0 = dividend - quotient0 * Q;

    // term1 = (q/2 - rem) >> 31 & 1 ; term2 = (q + q/2 - rem) >> 31 & 1
    wire signed [24:0] t1 = $signed({2'b0, 23'd1664}) - $signed({2'b0, rem0});
    wire signed [24:0] t2 = $signed({2'b0, 23'd4993}) - $signed({2'b0, rem0});
    wire [1:0] add1 = (t1[24] == 1'b1) ? 1'b1 : 1'b0;   // negative => add 1
    wire [1:0] add2 = (t2[24] == 1'b1) ? 1'b1 : 1'b0;

    wire [12:0] quotient2 = quotient0 + add1 + add2;
    wire [D-1:0] compressed = quotient2[D-1:0];

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            state     <= S_IDLE;
            done      <= 1'b0;
            busy      <= 1'b0;
            out_wen   <= 1'b0;
            in_addr   <= 8'd0;
            out_addr  <= 8'd0;
            out_wdata <= 12'd0;
            idx       <= 9'd0;
        end else begin
            out_wen <= 1'b0;
            done    <= 1'b0;

            case (state)
                S_IDLE: begin
                    busy <= 1'b0;
                    if (start) begin
                        busy <= 1'b1;
                        idx  <= 9'd0;
                        state <= S_READ;
                    end
                end

                S_READ: begin
                    in_addr <= idx[7:0];
                    state   <= S_WAIT;
                end

                S_WAIT: state <= S_COMP;

                S_COMP: state <= S_WRITE;

                S_WRITE: begin
                    out_wen   <= 1'b1;
                    out_addr  <= idx[7:0];
                    out_wdata <= {{(12-D){1'b0}}, compressed};
                    state     <= S_NEXT;
                end

                S_NEXT: begin
                    if (idx == 9'd255) state <= S_DONE;
                    else begin
                        idx   <= idx + 9'd1;
                        state <= S_READ;
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
