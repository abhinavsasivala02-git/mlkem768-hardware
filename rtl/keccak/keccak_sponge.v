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
// mlkem_hash_engine.v
// Unified Keccak-based sponge engine for ML-KEM
//
// Inspired by ML-DSA's single-core Keccak architecture:
//   - One keccak_f1600 instance, shared for absorb and squeeze
//   - Explicit S_PAD state (no post_pad race)
//   - to_squeeze flag routes post-permutation state
//   - init resets from ANY state — no repeated-call deadlock
//
// Supports all ML-KEM hash/XOF variants:
//   SHAKE-128 : RATE_BYTES=168, domain_sep=8'h1F
//   SHAKE-256 : RATE_BYTES=136, domain_sep=8'h1F
//   SHA3-256  : RATE_BYTES=136, domain_sep=8'h06
//   SHA3-512  : RATE_BYTES=72,  domain_sep=8'h06
//
// Interface: byte-stream absorb / byte-stream squeeze (registered outputs).
// Registered squeeze_valid/squeeze_data = same protocol as old
// keccak_absorb_squeeze.v, so all callers (sha3_*.v, shake*.v) are
// drop-in compatible.
//=============================================================================
`timescale 1ns/1ps

module keccak_sponge (
    input  wire        clk,
    input  wire        rst_n,

    input  wire [7:0]  rate_bytes,
    input  wire [7:0]  domain_sep,

    input  wire        init,

    input  wire        absorb_valid,
    input  wire [7:0]  absorb_data,
    output wire        absorb_ready,
    input  wire        absorb_last,

    output reg         squeeze_valid,
    output reg  [7:0]  squeeze_data,
    input  wire        squeeze_next,   // pulse to advance to next byte

    output wire        busy
);

    localparam [1:0] S_ABSORB  = 2'd0;
    localparam [1:0] S_PAD     = 2'd1;
    localparam [1:0] S_PERMUTE = 2'd2;
    localparam [1:0] S_SQUEEZE = 2'd3;

    reg [1:0] state;
    reg       to_squeeze;  // 0: after permute → S_ABSORB, 1: → S_SQUEEZE

    reg [1599:0] kst;       // 1600-bit sponge state
    reg [7:0]    bpos;      // absorb byte position within rate block
    reg [7:0]    spos;      // squeeze byte position within rate block

    assign absorb_ready = (state == S_ABSORB) && !init;
    assign busy         = (state != S_ABSORB) || init;

    reg           kf_start;
    wire          kf_done;
    wire [1599:0] kf_out;

    keccak_f1600 u_keccak (
        .clk       (clk),
        .rst_n     (rst_n),
        .start     (kf_start),
        .state_in  (kst),
        .state_out (kf_out),
        .done      (kf_done),
        .busy      (          )   // tracked via FSM state
    );

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            state         <= S_ABSORB;
            kst           <= 1600'd0;
            bpos          <= 8'd0;
            spos          <= 8'd0;
            kf_start      <= 1'b0;
            squeeze_valid <= 1'b0;
            squeeze_data  <= 8'd0;
            to_squeeze    <= 1'b0;
        end else begin
            kf_start      <= 1'b0;
            squeeze_valid <= 1'b0;

            if (init) begin
                state      <= S_ABSORB;
                kst        <= 1600'd0;
                bpos       <= 8'd0;
                spos       <= 8'd0;
                to_squeeze <= 1'b0;
            end else begin

                case (state)

                    S_ABSORB: begin
                        if (absorb_valid) begin
                            kst[bpos * 8 +: 8] <= kst[bpos * 8 +: 8] ^ absorb_data;

                            if (absorb_last) begin
                                bpos  <= bpos + 8'd1;   // bpos now = padding position
                                state <= S_PAD;

                            end else if (bpos == rate_bytes - 8'd1) begin
                                bpos       <= 8'd0;
                                kf_start   <= 1'b1;
                                to_squeeze <= 1'b0;     // return to S_ABSORB after
                                state      <= S_PERMUTE;

                            end else begin
                                bpos <= bpos + 8'd1;
                            end
                        end
                    end

                    S_PAD: begin
                        if (bpos == rate_bytes - 8'd1) begin
                            kst[bpos * 8 +: 8] <=
                                kst[bpos * 8 +: 8] ^ (domain_sep | 8'h80);
                        end else begin
                            kst[bpos * 8 +: 8] <=
                                kst[bpos * 8 +: 8] ^ domain_sep;
                            kst[(rate_bytes - 8'd1) * 8 +: 8] <=
                                kst[(rate_bytes - 8'd1) * 8 +: 8] ^ 8'h80;
                        end
                        kf_start   <= 1'b1;
                        to_squeeze <= 1'b1;     // after permute → S_SQUEEZE
                        state      <= S_PERMUTE;
                    end

                    S_PERMUTE: begin
                        if (kf_done) begin
                            kst <= kf_out;
                            if (to_squeeze) begin
                                spos           <= 8'd0;
                                squeeze_valid  <= 1'b1;
                                squeeze_data   <= kf_out[7:0];
                                state          <= S_SQUEEZE;
                            end else begin
                                state <= S_ABSORB;
                            end
                        end
                    end

                    S_SQUEEZE: begin
                        if (squeeze_next) begin
                            if (spos == rate_bytes - 8'd1) begin
                                squeeze_valid <= 1'b0;
                                spos          <= 8'd0;
                                kf_start      <= 1'b1;
                                to_squeeze    <= 1'b1;
                                state         <= S_PERMUTE;
                            end else begin
                                spos          <= spos + 8'd1;
                                squeeze_valid <= 1'b1;
                                squeeze_data  <= kst[(spos + 8'd1) * 8 +: 8];
                            end
                        end else begin
                            squeeze_valid <= 1'b0;
                        end
                    end

                    default: state <= S_ABSORB;
                endcase

            end // else (not init)
        end
    end

endmodule
