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
// ByteEncode_d — Algorithm 5 of FIPS 203
// Encodes 256 d-bit integers into 32*d bytes
//
// Bit-packing: takes coefficients from RAM and packs them bit-by-bit
// into output bytes (LSB first within each coefficient)
//============================================================================
module byte_encode #(
    parameter D = 12     // Bit-width per coefficient (1..12)
)(
    input  wire        clk,
    input  wire        rst_n,
    input  wire        start,
    output reg         done,
    output reg         busy,

    // Input polynomial RAM — read interface
    output reg  [7:0]  poly_addr,
    input  wire [11:0] poly_rdata,

    // Output byte stream
    output reg         byte_valid,
    output reg  [7:0]  byte_data,
    output reg  [10:0] byte_addr     // Address in output buffer (0..32*D-1)
);

    `include "mlkem_params.vh"

    localparam TOTAL_BYTES = 32 * D;

    // FSM
    localparam S_IDLE    = 3'd0;
    localparam S_READ    = 3'd1;
    localparam S_WAIT    = 3'd2;
    localparam S_PACK    = 3'd3;
    localparam S_EMIT    = 3'd4;
    localparam S_DONE    = 3'd5;

    reg [2:0] state;

    // Bit accumulator
    reg [23:0] bit_acc;     // Accumulator for partial bits
    reg [4:0]  bit_cnt;     // Number of valid bits in accumulator
    reg [8:0]  coeff_idx;   // Current coefficient index (0..255)
    reg [10:0] out_byte_cnt; // Output byte counter

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            state       <= S_IDLE;
            done        <= 1'b0;
            busy        <= 1'b0;
            byte_valid  <= 1'b0;
            byte_data   <= 8'd0;
            byte_addr   <= 11'd0;
            poly_addr   <= 8'd0;
            bit_acc     <= 24'd0;
            bit_cnt     <= 5'd0;
            coeff_idx   <= 9'd0;
            out_byte_cnt <= 11'd0;
        end else begin
            byte_valid <= 1'b0;
            done       <= 1'b0;

            case (state)
                S_IDLE: begin
                    busy <= 1'b0;
                    if (start) begin
                        busy         <= 1'b1;
                        coeff_idx    <= 9'd0;
                        bit_acc      <= 24'd0;
                        bit_cnt      <= 5'd0;
                        out_byte_cnt <= 11'd0;
                        state        <= S_READ;
                    end
                end

                S_READ: begin
                    poly_addr <= coeff_idx[7:0];
                    state     <= S_WAIT;
                end

                S_WAIT: begin
                    state <= S_PACK;
                end

                S_PACK: begin
                    // Add D bits from coefficient into accumulator
                    bit_acc <= bit_acc | ({{12{1'b0}}, poly_rdata[D-1:0]} << bit_cnt);
                    bit_cnt <= bit_cnt + D[4:0];
                    coeff_idx <= coeff_idx + 9'd1;
                    state   <= S_EMIT;
                end

                S_EMIT: begin
                    if (bit_cnt >= 5'd8) begin
                        // Emit a byte
                        byte_valid   <= 1'b1;
                        byte_data    <= bit_acc[7:0];
                        byte_addr    <= out_byte_cnt;
                        bit_acc      <= bit_acc >> 8;
                        bit_cnt      <= bit_cnt - 5'd8;
                        out_byte_cnt <= out_byte_cnt + 11'd1;
                        // Stay in EMIT if more bytes can be extracted
                    end else if (coeff_idx < 9'd256) begin
                        state <= S_READ;    // Need more coefficients
                    end else if (bit_cnt > 5'd0) begin
                        // Emit remaining bits as final byte
                        byte_valid   <= 1'b1;
                        byte_data    <= bit_acc[7:0];
                        byte_addr    <= out_byte_cnt;
                        bit_acc      <= 24'd0;
                        bit_cnt      <= 5'd0;
                        out_byte_cnt <= out_byte_cnt + 11'd1;
                        state        <= S_DONE;
                    end else begin
                        state <= S_DONE;
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
