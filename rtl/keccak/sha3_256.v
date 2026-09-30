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
// SHA3-256 Hash Function (FIPS 202)
// H() in ML-KEM — used for hashing encapsulation keys
// Rate = 136 bytes, Output = 32 bytes, Domain separator = 0x06
//
// Updated to use mlkem_hash_engine (ML-DSA-inspired single-core Keccak).
// squeeze_start removed — engine transitions to squeeze automatically
// after the padding permutation (to_squeeze flag inside engine).
//============================================================================
`timescale 1ns/1ps

module sha3_256 (
    input  wire          clk,
    input  wire          rst_n,

    input  wire          start,          // Begin new hash
    input  wire          data_valid,     // Input byte valid
    input  wire [7:0]    data_in,        // Input byte
    output wire          data_ready,     // Ready for input
    input  wire          data_last,      // Last input byte
    output reg           hash_valid,     // Hash output valid (1-cycle pulse)
    output reg  [255:0]  hash_out,       // 32-byte hash output
    output wire          busy,

    output wire [27:0] hb_req,
    input  wire [10:0] hb_rsp
);

    wire       sq_valid;
    wire [7:0] sq_data;
    reg        sq_next;
    reg  [4:0] out_cnt;    // 0..31

    localparam S_IDLE    = 2'd0;
    localparam S_ABSORB  = 2'd1;
    localparam S_SQUEEZE = 2'd2;
    localparam S_DONE    = 2'd3;

    reg [1:0] state;

    mlkem_hash_engine #(
        .RATE_BYTES (136),
        .DOMAIN_SEP (8'h06)
    ) u_engine (
        .clk          (clk),
        .rst_n        (rst_n),
        .init         (start),
        .absorb_valid (data_valid),
        .absorb_data  (data_in),
        .absorb_ready (data_ready),
        .absorb_last  (data_last),
        .squeeze_valid(sq_valid),
        .squeeze_data (sq_data),
        .squeeze_next (sq_next),
        .busy         (busy),
        .hb_req       (hb_req),
        .hb_rsp       (hb_rsp)
    );

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            state      <= S_IDLE;
            hash_valid <= 1'b0;
            hash_out   <= 256'd0;
            out_cnt    <= 5'd0;
            sq_next    <= 1'b0;
        end else begin
            hash_valid <= 1'b0;
            sq_next    <= 1'b0;

            case (state)
                S_IDLE: begin
                    if (start) begin
                        state   <= S_ABSORB;
                        out_cnt <= 5'd0;
                    end
                end

                S_ABSORB: begin
                    if (data_valid && data_last && data_ready)
                        state <= S_SQUEEZE;
                end

                S_SQUEEZE: begin
                    if (sq_valid) begin
                        hash_out[out_cnt * 8 +: 8] <= sq_data;
                        sq_next <= 1'b1;
                        if (out_cnt == 5'd31) begin
                            state      <= S_DONE;
                            hash_valid <= 1'b1;
                        end else begin
                            out_cnt <= out_cnt + 5'd1;
                        end
                    end
                end

                S_DONE: begin
                    state <= S_IDLE;
                end
            endcase
        end
    end

endmodule
