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
// ML-KEM.Encaps — Algorithm 17 of FIPS 203
// Key encapsulation: produces ciphertext and shared secret
//
// Steps:
//   1. m ←$ B^32  (random message, from input)
//   2. (K, r) ← G(m || H(ek))        — SHA3-512 of m || h
//   3. c ← K-PKE.Encrypt(ek, m, r)   — encrypt with deterministic randomness
//   4. return (K, c)
//
// Fix: kpke_encrypt streams EK via ek_valid/ek_data/ek_req handshake.
//      This module reads from the external EK buffer (ek_raddr/ek_rdata)
//      and feeds bytes to kpke_encrypt. CT output is captured and forwarded.
//============================================================================
module mlkem_encaps #(
    parameter K    = 3,
    parameter ETA1 = 2,
    parameter ETA2 = 2,
    parameter DU   = 10,
    parameter DV   = 4
)(
    input  wire          clk,
    input  wire          rst_n,
    input  wire          start,
    input  wire [255:0]  m_random,     // 32-byte random message
    output reg           done,
    output reg           busy,

    // Encapsulation key input buffer
    input  wire [7:0]    ek_rdata,
    output reg  [12:0]   ek_raddr,

    // Ciphertext output
    output reg           ct_wen,
    output reg  [12:0]   ct_addr,
    output reg  [7:0]    ct_wdata,

    // Shared secret output (32 bytes)
    output reg           ss_valid,
    output reg  [255:0]  shared_secret
);

    `include "mlkem_params.vh"

    localparam EK_SIZE = 384 * K + 32;

    // FSM
    localparam ST_IDLE       = 4'd0;
    localparam ST_HASH_EK    = 4'd1;   // H(ek)
    localparam ST_WAIT_H_EK  = 4'd2;
    localparam ST_HASH_MH    = 4'd3;   // G(m || H(ek)) → (K, r)
    localparam ST_WAIT_G     = 4'd4;
    localparam ST_ENCRYPT    = 4'd5;   // K-PKE.Encrypt(ek, m, r) — feed EK
    localparam ST_WAIT_ENC   = 4'd6;
    localparam ST_OUTPUT     = 4'd7;
    localparam ST_DONE       = 4'd8;
    localparam ST_COPY_EK    = 4'd9;   // buffer ek bytes into internal RAM

    reg [3:0] state;

    // H(ek) — SHA3-256
    reg          h_start;
    reg          h_data_valid;
    reg          h_data_last;
    reg          h_prs;        // a byte is presented & awaiting absorption
    reg          h_lst;        // the presented byte is the last one
    reg  [7:0]   h_data_in;
    wire         h_hash_valid;
    wire [255:0] h_hash_out;

    // h_data_ready: back-pressure from SHA3-256 engine.
    // MUST be checked before advancing feed_cnt; otherwise bytes sent
    // during mid-block Keccak permutations are silently dropped and
    // absorb_last can arrive while engine is busy — deadlock.
    wire h_data_ready;

    sha3_256 u_h_hash (
        .clk        (clk),
        .rst_n      (rst_n),
        .start      (h_start),
        .data_valid (h_data_valid),
        .data_in    (h_data_in),
        .data_ready (h_data_ready),
        .data_last  (h_data_last),
        .hash_valid (h_hash_valid),
        .hash_out   (h_hash_out),
        .busy       ()
    );

    // G(m || h) — SHA3-512
    reg          g_start;
    reg          g_data_valid;
    reg          g_data_last;
    reg          g_prs;        // a byte is presented & awaiting absorption
    reg          g_lst;        // the presented byte is the last one
    reg  [7:0]   g_data_in;
    wire         g_hash_valid;
    wire [511:0] g_hash_out;
    wire         g_data_ready;

    sha3_512 u_g_hash (
        .clk        (clk),
        .rst_n      (rst_n),
        .start      (g_start),
        .data_valid (g_data_valid),
        .data_in    (g_data_in),
        .data_ready (g_data_ready),
        .data_last  (g_data_last),
        .hash_valid (g_hash_valid),
        .hash_out   (g_hash_out),
        .busy       ()
    );

    // K-PKE.Encrypt
    reg          enc_start;
    wire         enc_done;
    wire         enc_busy;

    // EK streaming feed to kpke_encrypt
    reg          enc_ek_valid;
    reg  [7:0]   enc_ek_data;
    wire         enc_ek_req;

    // CT output from kpke_encrypt
    wire         enc_ct_valid;
    wire [7:0]   enc_ct_data;
    wire [12:0]  enc_ct_addr;

    // Stored values
    reg [255:0] h_ek;         // H(ek)
    reg [255:0] k_value;      // Shared secret K
    reg [255:0] r_value;      // Deterministic randomness r

    kpke_encrypt #(.K(K), .ETA1(ETA1), .ETA2(ETA2), .DU(DU), .DV(DV)) u_kpke_enc (
        .clk      (clk),
        .rst_n    (rst_n),
        .start    (enc_start),
        .done     (enc_done),
        .busy     (enc_busy),
        .ek_valid (enc_ek_valid),
        .ek_data  (enc_ek_data),
        .ek_req   (enc_ek_req),
        .message  (m_random),
        .r_seed   (r_value),
        .ct_valid (enc_ct_valid),
        .ct_data  (enc_ct_data),
        .ct_addr  (enc_ct_addr)
    );

    // Counters
    reg [12:0] feed_cnt;
    reg [5:0]  byte_cnt;

    // Internal EK buffer: the whole encapsulation key is copied here first,
    // then hashed / streamed to K-PKE.Encrypt from this register array
    // (combinational reads), avoiding the 1-cycle latency of the external
    // ek_rdata/ek_raddr buffer (same approach as mlkem_keygen).
    reg [7:0]  ek_buf [0:1183];
    reg [12:0] copy_cnt;        // EK copy / hash index

    // EK feed pipeline: 1-cycle read latency from buffer
    // Cycle N: set ek_raddr = feed_cnt
    // Cycle N+1: ek_rdata valid → feed to enc_ek_data
    reg        ek_read_pending;
    reg [12:0] ek_feed_cnt;   // total bytes fed to encrypt so far

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            state         <= ST_IDLE;
            done          <= 1'b0;
            busy          <= 1'b0;
            ss_valid      <= 1'b0;
            shared_secret <= 256'd0;
            ct_wen        <= 1'b0;
            ct_addr       <= 13'd0;
            ct_wdata      <= 8'd0;
            ek_raddr      <= 13'd0;
            h_start       <= 1'b0;
            h_data_valid  <= 1'b0;
            h_data_last   <= 1'b0;
            h_data_in     <= 8'd0;
            h_prs         <= 1'b0;
            h_lst         <= 1'b0;
            g_start       <= 1'b0;
            g_data_valid  <= 1'b0;
            g_data_last   <= 1'b0;
            g_prs         <= 1'b0;
            g_lst         <= 1'b0;
            g_data_in     <= 8'd0;
            g_data_last   <= 1'b0;
            enc_start     <= 1'b0;
            enc_ek_valid  <= 1'b0;
            enc_ek_data   <= 8'd0;
            h_ek          <= 256'd0;
            k_value       <= 256'd0;
            r_value       <= 256'd0;
            feed_cnt      <= 13'd0;
            byte_cnt      <= 6'd0;
            ek_read_pending <= 1'b0;
            ek_feed_cnt   <= 13'd0;
            copy_cnt      <= 13'd0;
        end else begin
            done          <= 1'b0;
            ss_valid      <= 1'b0;
            ct_wen        <= 1'b0;
            h_start       <= 1'b0;
            h_data_valid  <= 1'b0;
            h_data_last   <= 1'b0;
            g_start       <= 1'b0;
            g_data_valid  <= 1'b0;
            g_data_last   <= 1'b0;
            enc_start     <= 1'b0;
            enc_ek_valid  <= 1'b0;

            // Forward CT output from kpke_encrypt to external buffer
            if (enc_ct_valid) begin
                ct_wen   <= 1'b1;
                ct_addr  <= enc_ct_addr;
                ct_wdata <= enc_ct_data;
            end

            case (state)
                ST_IDLE: begin
                    busy <= 1'b0;
                    if (start) begin
                        busy           <= 1'b1;
                        h_start        <= 1'b1;
                        feed_cnt       <= 13'd0;
                        copy_cnt       <= 13'd0;
                        ek_read_pending <= 1'b0;
                        state          <= ST_COPY_EK;
                    end
                end

                // Copy all EK bytes from the external read buffer into the
                // internal ek_buf register array. The buffer has a 2-cycle
                // read latency (NBA ek_raddr -> core addr mux -> ek_rdata_reg),
                // so the byte for address k appears in ek_rdata when copy_cnt
                // has advanced to k+2 — store it at index (copy_cnt-2).
                ST_COPY_EK: begin
                    ek_raddr <= copy_cnt;
                    if (copy_cnt >= 13'd2)
                        ek_buf[copy_cnt - 13'd2] <= ek_rdata;
                    if (copy_cnt == EK_SIZE[12:0] + 13'd1) begin
                        copy_cnt <= 13'd0;
                        state    <= ST_HASH_EK;
                    end else begin
                        copy_cnt <= copy_cnt + 13'd1;
                    end
                end

                // Feed ek bytes to H() from ek_buf (combinational reads).
                // h_data_ready must be checked: SHA3-256 rate=136 and ek=1184
                // bytes → several mid-block permutations where absorb_ready
                // drops for ~24 cycles. Without gating, bytes are dropped and
                // absorb_last can arrive while the engine is busy — deadlock.
                ST_HASH_EK: begin
                    // Feed ek bytes to H() from ek_buf (combinational reads).
                    // Two-phase, absorb-acknowledged handshake:
                    //   phase 1 (h_data_ready && !h_prs): present the byte for
                    //          copy_cnt, raise h_data_valid, remember h_prs.
                    //   phase 2 (h_prs): the engine absorbed the presented byte
                    //          one cycle later; advance copy_cnt (or finish on
                    //          the last byte).
                    // Because the presented byte is only advanced once it has
                    // been absorbed, mid-block Keccak permutations never cause a
                    // byte to be duplicated or skipped.
                    h_data_valid <= 1'b0;
                    h_data_last  <= 1'b0;
                    if (h_prs) begin
                        h_prs <= 1'b0;
                        if (h_lst) begin
                            state <= ST_WAIT_H_EK;
                        end else begin
                            copy_cnt <= copy_cnt + 13'd1;
                        end
                    end else if (h_data_ready) begin
                        h_data_valid <= 1'b1;
                        h_data_in    <= ek_buf[copy_cnt];
                        h_prs        <= 1'b1;
                        if (copy_cnt == EK_SIZE[12:0] - 13'd1) begin
                            h_data_last <= 1'b1;
                            h_lst       <= 1'b1;
                        end
                    end
                end

                ST_WAIT_H_EK: begin
                    if (h_hash_valid) begin
                        h_ek     <= h_hash_out;
                        g_start  <= 1'b1;
                        byte_cnt <= 6'd0;
                        state    <= ST_HASH_MH;
                    end
                end

                // Feed m || H(ek) to G() — absorb-acknowledged handshake.
                // 64 bytes: 32 of m, 32 of h_ek.
                ST_HASH_MH: begin
                    g_data_valid <= 1'b0;
                    g_data_last  <= 1'b0;
                    if (g_prs) begin
                        g_prs <= 1'b0;
                        if (g_lst) begin
                            state <= ST_WAIT_G;
                        end else begin
                            byte_cnt <= byte_cnt + 6'd1;
                        end
                    end else if (g_data_ready) begin
                        g_data_valid <= 1'b1;
                        if (byte_cnt < 6'd32)
                            g_data_in <= m_random[byte_cnt*8 +: 8];
                        else
                            g_data_in <= h_ek[(byte_cnt - 6'd32)*8 +: 8];
                        g_prs <= 1'b1;
                        if (byte_cnt == 6'd63) begin
                            g_data_last <= 1'b1;
                            g_lst       <= 1'b1;
                        end
                    end
                end

                ST_WAIT_G: begin
                    if (g_hash_valid) begin
                        k_value     <= g_hash_out[255:0];    // K = first 32 bytes
                        r_value     <= g_hash_out[511:256];  // r = last 32 bytes
                        enc_start   <= 1'b1;
                        ek_feed_cnt <= 13'd0;
                        state       <= ST_ENCRYPT;
                    end
                end

                // Stream EK bytes from ek_buf to kpke_encrypt when it requests
                // them. ek_buf is a register array (combinational read), so the
                // byte is available immediately — present it on ek_req and
                // advance the pointer. This avoids the off-by-one / duplication
                // that a 1-cycle-latency external buffer introduced.
                ST_ENCRYPT: begin
                    state <= ST_WAIT_ENC;
                end

                ST_WAIT_ENC: begin
                    enc_ek_valid <= 1'b0;
                    if (enc_ek_req) begin
                        enc_ek_valid <= 1'b1;
                        enc_ek_data  <= ek_buf[ek_feed_cnt];
                        if (ek_feed_cnt < EK_SIZE[12:0] - 13'd1)
                            ek_feed_cnt <= ek_feed_cnt + 13'd1;
                    end
                    if (enc_done) begin
                        state <= ST_OUTPUT;
                    end
                end

                ST_OUTPUT: begin
                    ss_valid      <= 1'b1;
                    shared_secret <= k_value;
                    state         <= ST_DONE;
                end

                ST_DONE: begin
                    done  <= 1'b1;
                    busy  <= 1'b0;
                    state <= ST_IDLE;
                end

                default: state <= ST_IDLE;
            endcase
        end
    end

endmodule
