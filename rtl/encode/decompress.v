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
// Decompress_d — FIPS 203 Section 4.2.1
// Decompress_d(y) = round(q / 2^d * y)
//
// Implementation: (y * q + (1 << (d-1))) >> d
// This rounds to nearest integer.
//============================================================================

module decompress #(
    parameter D = 10     // Decompression source bits
)(
    input  wire        clk,
    input  wire        rst_n,
    input  wire        start,
    output reg         done,
    output reg         busy,

    // Input polynomial RAM — read (D-bit values in 12-bit field)
    output reg  [7:0]  in_addr,
    input  wire [11:0] in_rdata,

    // Output polynomial RAM — write (12-bit values)
    output reg         out_wen,
    output reg  [7:0]  out_addr,
    output reg  [11:0] out_wdata
);

    `include "mlkem_params.vh"
    localparam S_IDLE  = 3'd0;
    localparam S_READ  = 3'd1;
    localparam S_WAIT  = 3'd2;
    localparam S_COMP  = 3'd3;
    localparam S_WRITE = 3'd4;
    localparam S_NEXT  = 3'd5;
    localparam S_DONE  = 3'd6;

    reg [2:0] state;
    reg [8:0] idx;

    // Decompress: y * q + 2^(d-1) >> d
    wire [23:0] product;
    wire [23:0] rounded;
    wire [11:0] decompressed;

    assign product      = {12'd0, in_rdata[D-1:0]} * {11'd0, MLKEM_Q[12:0]};
    assign rounded      = product + (24'd1 << (D - 1));
    assign decompressed = rounded[D+11:D];

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
                        busy  <= 1'b1;
                        idx   <= 9'd0;
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
                    out_wdata <= decompressed;
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
                    done  <= 1'b1;
                    busy  <= 1'b0;
                    state <= S_IDLE;
                end

                default: state <= S_IDLE;
            endcase
        end
    end

endmodule
