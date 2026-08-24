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
// SHA3-512 Hash Function (FIPS 202)
// G() in ML-KEM — seed expansion: G(d) → (ρ,σ),  G(m||h) → (K,r)
// Rate = 72 bytes, Output = 64 bytes, Domain separator = 0x06
//
// Updated to use mlkem_hash_engine (ML-DSA-inspired single-core Keccak).
// squeeze_start removed — engine transitions to squeeze automatically
// after the padding permutation (to_squeeze flag inside engine).
//============================================================================
`timescale 1ns/1ps

module sha3_512 (
    input  wire          clk,
    input  wire          rst_n,

    // Control
    input  wire          start,
    input  wire          data_valid,
    input  wire [7:0]    data_in,
    output wire          data_ready,
    input  wire          data_last,
    output reg           hash_valid,     // 1-cycle pulse when done
    output reg  [511:0]  hash_out,       // 64-byte hash output
    output wire          busy
);

    wire       sq_valid;
    wire [7:0] sq_data;
    reg        sq_next;
    reg  [5:0] out_cnt;    // 0..63

    localparam S_IDLE    = 2'd0;
    localparam S_ABSORB  = 2'd1;
    localparam S_SQUEEZE = 2'd2;
    localparam S_DONE    = 2'd3;

    reg [1:0] state;

    // Sponge instance: SHA3-512 (rate=72 bytes, domain=0x06)
    mlkem_hash_engine #(
        .RATE_BYTES (72),
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
        .busy         (busy)
    );

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            state      <= S_IDLE;
            hash_valid <= 1'b0;
            hash_out   <= 512'd0;
            out_cnt    <= 6'd0;
            sq_next    <= 1'b0;
        end else begin
            hash_valid <= 1'b0;
            sq_next    <= 1'b0;

            case (state)
                S_IDLE: begin
                    if (start) begin
                        state   <= S_ABSORB;
                        out_cnt <= 6'd0;
                    end
                end

                S_ABSORB: begin
                    // Only transition when engine ACTUALLY accepts absorb_last.
                    if (data_valid && data_last && data_ready)
                        state <= S_SQUEEZE;
                end

                // Engine enters S_SQUEEZE automatically after padding permutation.
                // sq_valid goes high once the first byte is ready.
                S_SQUEEZE: begin
                    if (sq_valid) begin
                        hash_out[out_cnt * 8 +: 8] <= sq_data;
                        sq_next <= 1'b1;
                        if (out_cnt == 6'd63) begin
                            state      <= S_DONE;
                            hash_valid <= 1'b1;
                        end else begin
                            out_cnt <= out_cnt + 6'd1;
                        end
                    end
                end

                S_DONE: state <= S_IDLE;
            endcase
        end
    end

endmodule
