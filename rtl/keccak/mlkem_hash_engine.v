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
// mlkem_hash_engine — client shim for the shared Keccak sponge
//
// This used to contain its own 1600-bit state and Keccak-f core.  Twelve
// instances of that cost ~10k LUTs each (round logic plus the byte-lane muxing
// into the state), around 100k LUTs in total, which does not fit a Zynq-7020.
//
// The state and round logic now live in ONE keccak_sponge instance owned by
// mlkem_core.  This shim keeps the original client-facing interface exactly, so
// sha3_256 / sha3_512 / shake128 / shake256 and every caller above them are
// unchanged; it only forwards the request onto the shared bus, tagging it with
// this instance's RATE_BYTES / DOMAIN_SEP.
//
//   req = {init, rate[7:0], dom[7:0], absorb_valid, absorb_data[7:0],
//          absorb_last, squeeze_next}
//   rsp = {absorb_ready, squeeze_valid, squeeze_data[7:0], busy}
//============================================================================
`timescale 1ns/1ps

module mlkem_hash_engine #(
    parameter       RATE_BYTES = 136,
    parameter [7:0] DOMAIN_SEP = 8'h1F
)(
    input  wire        clk,
    input  wire        rst_n,

    input  wire        init,

    input  wire        absorb_valid,
    input  wire [7:0]  absorb_data,
    output wire        absorb_ready,
    input  wire        absorb_last,

    output wire        squeeze_valid,
    output wire [7:0]  squeeze_data,
    input  wire        squeeze_next,

    output wire        busy,

    output wire [27:0] hb_req,
    input  wire [10:0] hb_rsp
);

    wire _unused_ok = &{1'b0, clk, rst_n, 1'b0};

    assign hb_req = {init,                 // [27]
                     RATE_BYTES[7:0],      // [26:19]
                     DOMAIN_SEP,           // [18:11]
                     absorb_valid,         // [10]
                     absorb_data,          // [9:2]
                     absorb_last,          // [1]
                     squeeze_next};        // [0]

    assign absorb_ready  = hb_rsp[10];
    assign squeeze_valid = hb_rsp[9];
    assign squeeze_data  = hb_rsp[8:1];
    assign busy          = hb_rsp[0];

endmodule
