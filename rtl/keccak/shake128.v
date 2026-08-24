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

//=============================================================================
// shake128.v — SHAKE-128 XOF wrapper
// Rate = 168 bytes, Domain separator = 0x1F
// Thin wrapper around mlkem_hash_engine (single-core ML-DSA-style engine).
//=============================================================================
`timescale 1ns/1ps

module shake128 (
    input  wire        clk,
    input  wire        rst_n,

    // Control
    input  wire        start,          // reset sponge (safe from any state)

    // Absorb interface
    input  wire        absorb_valid,
    input  wire [7:0]  absorb_data,
    output wire        absorb_ready,
    input  wire        absorb_last,

    // Squeeze interface
    input  wire        squeeze_req,
    output wire        squeeze_valid,
    output wire [7:0]  squeeze_data,
    output wire        busy
);

    mlkem_hash_engine #(
        .RATE_BYTES (168),
        .DOMAIN_SEP (8'h1F)
    ) u_engine (
        .clk          (clk),
        .rst_n        (rst_n),
        .init         (start),
        .absorb_valid (absorb_valid),
        .absorb_data  (absorb_data),
        .absorb_ready (absorb_ready),
        .absorb_last  (absorb_last),
        .squeeze_valid(squeeze_valid),
        .squeeze_data (squeeze_data),
        .squeeze_next (squeeze_req),
        .busy         (busy)
    );

endmodule
