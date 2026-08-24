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
//   SHAKE-128 : RATE_BYTES=168, DOMAIN_SEP=8'h1F
//   SHAKE-256 : RATE_BYTES=136, DOMAIN_SEP=8'h1F
//   SHA3-256  : RATE_BYTES=136, DOMAIN_SEP=8'h06
//   SHA3-512  : RATE_BYTES=72,  DOMAIN_SEP=8'h06
//
// Interface: byte-stream absorb / byte-stream squeeze (registered outputs).
// Registered squeeze_valid/squeeze_data = same protocol as old
// keccak_absorb_squeeze.v, so all callers (sha3_*.v, shake*.v) are
// drop-in compatible.
//=============================================================================
`timescale 1ns/1ps

module mlkem_hash_engine #(
    parameter       RATE_BYTES = 136,
    parameter [7:0] DOMAIN_SEP = 8'h1F
)(
    input  wire        clk,
    input  wire        rst_n,

    // init: reset sponge from ANY state (safe to pulse even mid-squeeze)
    input  wire        init,

    // Absorb interface
    input  wire        absorb_valid,
    input  wire [7:0]  absorb_data,
    output wire        absorb_ready,
    input  wire        absorb_last,

    // Squeeze interface (registered, 1-cycle latency after permutation done)
    output reg         squeeze_valid,
    output reg  [7:0]  squeeze_data,
    input  wire        squeeze_next,   // pulse to advance to next byte

    output wire        busy
);

    //=========================================================================
    // FSM states
    //=========================================================================
    localparam [1:0] S_ABSORB  = 2'd0;
    localparam [1:0] S_PAD     = 2'd1;
    localparam [1:0] S_PERMUTE = 2'd2;
    localparam [1:0] S_SQUEEZE = 2'd3;

    reg [1:0] state;
    reg       to_squeeze;  // 0: after permute → S_ABSORB, 1: → S_SQUEEZE

    //=========================================================================
    // Keccak state and position counters
    //=========================================================================
    reg [1599:0] kst;       // 1600-bit sponge state
    reg [7:0]    bpos;      // absorb byte position within rate block
    reg [7:0]    spos;      // squeeze byte position within rate block

    assign absorb_ready = (state == S_ABSORB) && !init;
    assign busy         = (state != S_ABSORB) || init;

    //=========================================================================
    // Keccak-f[1600] core (single instance — like ML-DSA architecture)
    //=========================================================================
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

    //=========================================================================
    // Main sequential FSM
    //=========================================================================
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

            // ------------------------------------------------------------------
            // PRIORITY: init resets from ANY state.
            //
            // Root-cause fix for the ML-KEM repeated-call deadlock:
            //   sample_ntt is called 9 times (K=3).  After the first call the
            //   sponge sits in S_SQUEEZE.  The sponge must accept init from
            //   S_SQUEEZE, not just from S_IDLE.  Without this, calls 2-9
            //   deadlock because absorb_ready stays 0 forever.
            // ------------------------------------------------------------------
            if (init) begin
                state      <= S_ABSORB;
                kst        <= 1600'd0;
                bpos       <= 8'd0;
                spos       <= 8'd0;
                to_squeeze <= 1'b0;
            end else begin

                case (state)

                    // ----------------------------------------------------------
                    // ABSORB — XOR incoming bytes into the Keccak state.
                    // Back-pressure: absorb_ready is de-asserted during permutation.
                    // ----------------------------------------------------------
                    S_ABSORB: begin
                        if (absorb_valid) begin
                            // XOR byte into state
                            kst[bpos * 8 +: 8] <= kst[bpos * 8 +: 8] ^ absorb_data;

                            if (absorb_last) begin
                                // Last data byte — go apply padding
                                bpos  <= bpos + 8'd1;   // bpos now = padding position
                                state <= S_PAD;

                            end else if (bpos == RATE_BYTES[7:0] - 8'd1) begin
                                // Rate block full — mid-absorb permutation
                                bpos       <= 8'd0;
                                kf_start   <= 1'b1;
                                to_squeeze <= 1'b0;     // return to S_ABSORB after
                                state      <= S_PERMUTE;

                            end else begin
                                bpos <= bpos + 8'd1;
                            end
                        end
                    end

                    // ----------------------------------------------------------
                    // PAD — Apply multi-rate padding then trigger permutation.
                    //
                    // bpos was incremented at end of ABSORB to point to the
                    // byte position AFTER the last data byte.
                    //
                    // Rule (FIPS 202 multi-rate padding):
                    //   kst[bpos]    ^= DOMAIN_SEP
                    //   kst[RATE-1]  ^= 0x80
                    //   If bpos == RATE-1 → merge: ^= (DOMAIN_SEP | 0x80)
                    //
                    // Two NBA writes to *different* bit-ranges combine correctly.
                    // The merged (single-range) case avoids an NBA conflict.
                    // ----------------------------------------------------------
                    S_PAD: begin
                        if (bpos == RATE_BYTES[7:0] - 8'd1) begin
                            // Padding position == last rate byte: merge both XORs
                            kst[bpos * 8 +: 8] <=
                                kst[bpos * 8 +: 8] ^ (DOMAIN_SEP | 8'h80);
                        end else begin
                            // Two distinct bytes — no NBA conflict
                            kst[bpos * 8 +: 8] <=
                                kst[bpos * 8 +: 8] ^ DOMAIN_SEP;
                            kst[(RATE_BYTES[7:0] - 8'd1) * 8 +: 8] <=
                                kst[(RATE_BYTES[7:0] - 8'd1) * 8 +: 8] ^ 8'h80;
                        end
                        kf_start   <= 1'b1;
                        to_squeeze <= 1'b1;     // after permute → S_SQUEEZE
                        state      <= S_PERMUTE;
                    end

                    // ----------------------------------------------------------
                    // PERMUTE — Wait for Keccak-f[1600] to finish.
                    // to_squeeze flag routes to S_SQUEEZE or back to S_ABSORB.
                    // On entry to S_SQUEEZE, present byte 0 of the new state
                    // with a valid pulse (closes the 1-cycle data lag).
                    // ----------------------------------------------------------
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

                    // ----------------------------------------------------------
                    // SQUEEZE — Output bytes from the Keccak state (registered).
                    //
                    // squeeze_valid / squeeze_data are driven as registered
                    // outputs to match the keccak_absorb_squeeze.v protocol
                    // used by sha3_256, sha3_512, shake128, shake256 wrappers.
                    //
                    // Handshake (no 1-cycle data lag):
                    //   * On entry (S_PERMUTE) byte 0 is presented immediately.
                    //   * While squeeze_next is high, advance spos and present
                    //     the NEXT byte on the same edge.
                    //   * When squeeze_next is low, drop valid (idle byte slot).
                    //
                    // With a pulsed consumer this yields one byte every two
                    // cycles; with a continuously-asserted req it yields one
                    // byte per cycle. Either way each captured byte is distinct.
                    // ----------------------------------------------------------
                    S_SQUEEZE: begin
                        if (squeeze_next) begin
                            if (spos == RATE_BYTES[7:0] - 8'd1) begin
                                // Rate exhausted — another Keccak permutation
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
