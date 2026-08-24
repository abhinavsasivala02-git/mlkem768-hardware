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
// Dual-Port Polynomial Coefficient RAM
// 256 entries × 12 bits per coefficient
// Port A: read/write
// Port B: read-only
// Synchronous read with 1-cycle latency
//============================================================================
module poly_ram #(
    parameter DEPTH = 256,
    parameter WIDTH = 12,
    parameter ADDR_W = 8
)(
    input  wire              clk,

    // Port A: Read/Write
    input  wire              a_wen,
    input  wire [ADDR_W-1:0] a_addr,
    input  wire [WIDTH-1:0]  a_wdata,
    output reg  [WIDTH-1:0]  a_rdata,

    // Port B: Read-Only
    input  wire [ADDR_W-1:0] b_addr,
    output reg  [WIDTH-1:0]  b_rdata
);

    // Memory array
    reg [WIDTH-1:0] mem [0:DEPTH-1];

    // Port A: synchronous read/write
    always @(posedge clk) begin
        if (a_wen)
            mem[a_addr] <= a_wdata;
        a_rdata <= mem[a_addr];
    end

    // Port B: synchronous read
    always @(posedge clk) begin
        b_rdata <= mem[b_addr];
    end

endmodule
