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
// ML-KEM.Decaps — Algorithm 18 of FIPS 203
// Key decapsulation with implicit rejection (constant-time)
//
// Steps:
//   1. Parse dk = dk_pke || ek || h || z
//   2. m' ← K-PKE.Decrypt(dk_pke, c)
//   3. (K', r') ← G(m' || h)
//   4. K̄ ← KDF(z || c)                    — implicit rejection key
//   5. c' ← K-PKE.Encrypt(ek, m', r')      — re-encrypt
//   6. if c == c' then return K' else return K̄
//
// SECURITY: ciphertext comparison MUST be constant-time
//
// Fix: kpke_decrypt and kpke_encrypt streaming interfaces are now properly
//      connected. dk/ct/ek bytes are fed from memory buffers via FSM.
//============================================================================
module mlkem_decaps #(
    parameter K    = 3,
    parameter ETA1 = 2,
    parameter ETA2 = 2,
    parameter DU   = 10,
    parameter DV   = 4
)(
    input  wire          clk,
    input  wire          rst_n,
    input  wire          start,
    output reg           done,
    output reg           busy,

    // Decapsulation key buffer — read
    input  wire [7:0]    dk_rdata,
    output reg  [12:0]   dk_raddr,

    // Ciphertext buffer — read
    input  wire [7:0]    ct_rdata,
    output reg  [12:0]   ct_raddr,

    // Shared secret output
    output reg           ss_valid,
    output reg  [255:0]  shared_secret
);

    `include "mlkem_params.vh"

    localparam EK_SIZE     = 384 * K + 32;
    localparam DK_PKE_SIZE = 384 * K;
    localparam CT_SIZE     = 32 * DU * K + 32 * DV;

    // FSM — 5-bit to accommodate all states
    localparam ST_IDLE           = 5'd0;
    localparam ST_PARSE_DK       = 5'd1;
    localparam ST_DECRYPT        = 5'd2;
    localparam ST_FEED_DEC       = 5'd3;
    localparam ST_WAIT_DEC       = 5'd4;
    localparam ST_HASH_MH        = 5'd5;   // G(m' || h)
    localparam ST_WAIT_G         = 5'd6;
    localparam ST_KDF            = 5'd7;   // KDF(z || c) = SHAKE-256(z || c)
    localparam ST_KDF_ABSORB_Z   = 5'd8;
    localparam ST_KDF_ABSORB_C   = 5'd9;
    localparam ST_WAIT_KDF       = 5'd10;
    localparam ST_KDF_SQUEEZE    = 5'd11;
    localparam ST_REENCRYPT      = 5'd12;  // K-PKE.Encrypt(ek, m', r')
    localparam ST_FEED_REENC     = 5'd13;
    localparam ST_WAIT_REENC     = 5'd14;
    localparam ST_COMPARE        = 5'd15;  // Constant-time c == c' check
    localparam ST_REENC_COPY     = 5'd18;  // buffer ek into ek_buf first
    localparam ST_BUFFER         = 5'd19;  // buffer dkPKE + ct before decrypt
    localparam ST_SELECT         = 5'd16;  // Select K' or K̄
    localparam ST_DONE           = 5'd17;

    reg [4:0] state;

    // Parsed components from dk
    reg [255:0] h_cached;     // H(ek) from dk
    reg [255:0] z_cached;     // Implicit rejection value from dk

    // Decrypted message
    reg [255:0] m_prime;

    // G() outputs
    reg [255:0] k_prime;      // Candidate shared secret
    reg [255:0] r_prime;      // Deterministic randomness

    // KDF output: implicit rejection key
    reg [255:0] k_bar;

    // Comparison result
    reg         ct_match;     // 1 if c == c', constant-time
    reg [12:0]  cmp_idx;
    reg [7:0]   cmp_accumulator;  // OR of any mismatch (8-bit for XOR)

    // G() — SHA3-512
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

    // Internal ciphertext buffer (copied from the 1-cycle-latency ct buffer)
    // so the KDF can stream z || c without mid-block handshake desync.
    reg [7:0]  ct_buf [0:1087];
    reg [12:0] ct_copy_cnt;
    reg [12:0] kdf_cnt;        // z||c byte index for the KDF absorb
    reg        kdf_prs;
    reg        kdf_lst;

    // Internal EK buffer for re-encryption (avoids feed deadlock/desync).
    reg [7:0]  ek_buf [0:1183];
    reg [12:0] ek_copy_cnt;

    // Internal K-PKE decryption-key buffer (dkPKE) for the decrypt feed.
    reg [7:0]  dk_buf [0:1151];
    reg [12:0] dk_copy_cnt;

    // KDF — SHAKE-256
    reg          kdf_start;
    reg          kdf_absorb_valid;
    reg  [7:0]   kdf_absorb_data;
    reg          kdf_absorb_last;
    reg          kdf_squeeze_req;
    wire         kdf_squeeze_valid;
    wire [7:0]   kdf_squeeze_data;
    wire         kdf_absorb_ready;

    shake256 u_kdf_shake (
        .clk           (clk),
        .rst_n         (rst_n),
        .start         (kdf_start),
        .absorb_valid  (kdf_absorb_valid),
        .absorb_data   (kdf_absorb_data),
        .absorb_ready  (kdf_absorb_ready),
        .absorb_last   (kdf_absorb_last),
        .squeeze_req   (kdf_squeeze_req),
        .squeeze_valid (kdf_squeeze_valid),
        .squeeze_data  (kdf_squeeze_data),
        .busy          ()
    );

    // K-PKE.Decrypt
    reg          dec_start;
    wire         dec_done;
    wire         dec_msg_valid;
    wire [255:0] dec_msg_out;

    // Streaming feed for kpke_decrypt
    reg          dec_ct_valid;
    reg  [7:0]   dec_ct_data;
    wire         dec_ct_req;
    reg          dec_dk_valid;
    reg  [7:0]   dec_dk_data;
    wire         dec_dk_req;

    kpke_decrypt #(.K(K), .DU(DU), .DV(DV)) u_kpke_dec (
        .clk      (clk),
        .rst_n    (rst_n),
        .start    (dec_start),
        .done     (dec_done),
        .busy     (),
        .ct_valid (dec_ct_valid),
        .ct_data  (dec_ct_data),
        .ct_req   (dec_ct_req),
        .dk_valid (dec_dk_valid),
        .dk_data  (dec_dk_data),
        .dk_req   (dec_dk_req),
        .msg_valid(dec_msg_valid),
        .msg_out  (dec_msg_out)
    );

    // K-PKE.Encrypt (for re-encryption)
    reg          reenc_start;
    wire         reenc_done;
    wire         reenc_ct_valid;
    wire [7:0]   reenc_ct_data;
    wire [12:0]  reenc_ct_addr;

    // Streaming EK feed for re-encrypt
    reg          reenc_ek_valid;
    reg  [7:0]   reenc_ek_data;
    wire         reenc_ek_req;

    kpke_encrypt #(.K(K), .ETA1(ETA1), .ETA2(ETA2), .DU(DU), .DV(DV)) u_kpke_reenc (
        .clk      (clk),
        .rst_n    (rst_n),
        .start    (reenc_start),
        .done     (reenc_done),
        .busy     (),
        .ek_valid (reenc_ek_valid),
        .ek_data  (reenc_ek_data),
        .ek_req   (reenc_ek_req),
        .message  (m_prime),
        .r_seed   (r_prime),
        .ct_valid (reenc_ct_valid),
        .ct_data  (reenc_ct_data),
        .ct_addr  (reenc_ct_addr)
    );

    // Counters
    reg [6:0]  byte_cnt;
    reg [12:0] feed_cnt;        // feed counter for dk/ct/ek bytes
    reg        read_pending;    // 1-cycle read latency pipeline

    // Feed state tracker for decrypt phase
    // kpke_decrypt needs both ct and dk fed over time;
    // we feed them as the sub-module requests via ct_req/dk_req
    reg [12:0] ct_feed_idx;
    reg [12:0] dk_feed_idx;
    reg        ct_read_pending;
    reg        dk_read_pending;

    // For re-encrypt EK feed
    reg [12:0] ek_feed_idx;
    reg        ek_read_pending;

    // Delayed capture for dynamic ciphertext comparison
    reg [7:0]  delayed_ct_data;
    reg        delayed_ct_valid;

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            delayed_ct_data  <= 8'd0;
            delayed_ct_valid <= 1'b0;
        end else begin
            delayed_ct_data  <= reenc_ct_data;
            delayed_ct_valid <= reenc_ct_valid;
        end
    end

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            state            <= ST_IDLE;
            done             <= 1'b0;
            busy             <= 1'b0;
            ss_valid         <= 1'b0;
            shared_secret    <= 256'd0;
            dk_raddr         <= 13'd0;
            ct_raddr         <= 13'd0;
            g_start          <= 1'b0;
            g_data_valid     <= 1'b0;
            g_data_in        <= 8'd0;
            g_data_last      <= 1'b0;
            kdf_start        <= 1'b0;
            kdf_absorb_valid <= 1'b0;
            kdf_absorb_data  <= 8'd0;
            kdf_absorb_last  <= 1'b0;
            kdf_squeeze_req  <= 1'b0;
            dec_start        <= 1'b0;
            dec_ct_valid     <= 1'b0;
            dec_ct_data      <= 8'd0;
            dec_dk_valid     <= 1'b0;
            dec_dk_data      <= 8'd0;
            reenc_start      <= 1'b0;
            reenc_ek_valid   <= 1'b0;
            reenc_ek_data    <= 8'd0;
            h_cached         <= 256'd0;
            z_cached         <= 256'd0;
            m_prime          <= 256'd0;
            k_prime          <= 256'd0;
            r_prime          <= 256'd0;
            k_bar            <= 256'd0;
            ct_match         <= 1'b0;
            cmp_idx          <= 13'd0;
            cmp_accumulator  <= 8'd0;
            byte_cnt         <= 7'd0;
            feed_cnt         <= 13'd0;
            read_pending     <= 1'b0;
            ct_feed_idx      <= 13'd0;
            dk_feed_idx      <= 13'd0;
            ct_read_pending  <= 1'b0;
            dk_read_pending  <= 1'b0;
            ek_feed_idx      <= 13'd0;
            ek_read_pending  <= 1'b0;
            g_prs            <= 1'b0;
            g_lst            <= 1'b0;
            ct_copy_cnt      <= 13'd0;
            kdf_cnt          <= 13'd0;
            kdf_prs          <= 1'b0;
            kdf_lst          <= 1'b0;
            ek_copy_cnt      <= 13'd0;
            dk_copy_cnt      <= 13'd0;
        end else begin
            done             <= 1'b0;
            ss_valid         <= 1'b0;
            g_start          <= 1'b0;
            g_data_valid     <= 1'b0;
            g_data_last      <= 1'b0;
            kdf_start        <= 1'b0;
            kdf_absorb_valid <= 1'b0;
            kdf_absorb_last  <= 1'b0;
            kdf_squeeze_req  <= 1'b0;
            dec_start        <= 1'b0;
            dec_ct_valid     <= 1'b0;
            dec_dk_valid     <= 1'b0;
            reenc_start      <= 1'b0;
            reenc_ek_valid   <= 1'b0;

            case (state)
                ST_IDLE: begin
                    busy <= 1'b0;
                    if (start) begin
                        busy     <= 1'b1;
                        byte_cnt <= 7'd0;
                        state    <= ST_PARSE_DK;
                    end
                end

                // Parse dk: extract h and z from fixed offsets.
                // The dk buffer has 2-cycle read latency from this FSM (NBA
                // dk_raddr -> core mux -> dk_rdata_reg), so the byte for address
                // k appears when byte_cnt == k+2. Capture accordingly.
                ST_PARSE_DK: begin
                    dk_raddr <= DK_PKE_SIZE[12:0] + EK_SIZE[12:0] + {6'd0, byte_cnt};

                    if (byte_cnt >= 7'd2 && byte_cnt <= 7'd33)
                        h_cached[(byte_cnt - 7'd2)*8 +: 8] <= dk_rdata;
                    if (byte_cnt >= 7'd34 && byte_cnt <= 7'd65)
                        z_cached[(byte_cnt - 7'd34)*8 +: 8] <= dk_rdata;

                    if (byte_cnt == 7'd66) begin
                        dk_copy_cnt <= 13'd0;
                        ct_copy_cnt <= 13'd0;
                        state       <= ST_BUFFER;
                    end else begin
                        byte_cnt <= byte_cnt + 7'd1;
                    end
                end

                // Buffer dkPKE (first 1152 dk bytes) and ct into internal arrays
                // (both external buffers have 2-cycle read latency from this FSM).
                ST_BUFFER: begin
                    if (dk_copy_cnt >= 13'd2 && dk_copy_cnt <= 13'd1153)
                        dk_buf[dk_copy_cnt - 13'd2] <= dk_rdata;
                    if (ct_copy_cnt >= 13'd2 && ct_copy_cnt <= 13'd1089)
                        ct_buf[ct_copy_cnt - 13'd2] <= ct_rdata;
                    dk_raddr <= dk_copy_cnt;
                    ct_raddr <= ct_copy_cnt;
                    if (dk_copy_cnt == 13'd1154) begin
                        dk_copy_cnt <= 13'd0;
                        ct_copy_cnt <= 13'd0;
                        dec_start    <= 1'b1;
                        ct_feed_idx  <= 13'd0;
                        dk_feed_idx  <= 13'd0;
                        state        <= ST_FEED_DEC;
                    end else begin
                        dk_copy_cnt <= dk_copy_cnt + 13'd1;
                        ct_copy_cnt <= ct_copy_cnt + 13'd1;
                    end
                end

                // Feed CT and DK bytes to kpke_decrypt as it requests them,
                // reading from the internal ct_buf / dk_buf (combinational).
                ST_FEED_DEC: begin
                    dec_ct_valid <= 1'b0;
                    dec_dk_valid <= 1'b0;
                    if (dec_ct_req) begin
                        dec_ct_valid <= 1'b1;
                        dec_ct_data  <= ct_buf[ct_feed_idx];
                        if (ct_feed_idx < 13'd1087) ct_feed_idx <= ct_feed_idx + 13'd1;
                    end
                    if (dec_dk_req) begin
                        dec_dk_valid <= 1'b1;
                        dec_dk_data  <= dk_buf[dk_feed_idx];
                        if (dk_feed_idx < 13'd1151) dk_feed_idx <= dk_feed_idx + 13'd1;
                    end
                    state <= ST_WAIT_DEC;
                end

                ST_WAIT_DEC: begin
                    dec_ct_valid <= 1'b0;
                    dec_dk_valid <= 1'b0;
                    if (dec_ct_req) begin
                        dec_ct_valid <= 1'b1;
                        dec_ct_data  <= ct_buf[ct_feed_idx];
                        if (ct_feed_idx < 13'd1087) ct_feed_idx <= ct_feed_idx + 13'd1;
                    end
                    if (dec_dk_req) begin
                        dec_dk_valid <= 1'b1;
                        dec_dk_data  <= dk_buf[dk_feed_idx];
                        if (dk_feed_idx < 13'd1151) dk_feed_idx <= dk_feed_idx + 13'd1;
                    end

                    if (dec_done) begin
                        if (dec_msg_valid)
                            m_prime <= dec_msg_out;
                        g_start  <= 1'b1;
                        byte_cnt <= 7'd0;
                        state    <= ST_HASH_MH;
                    end
                end

                // G(m' || h) → (K', r') — absorb-acknowledged handshake.
                ST_HASH_MH: begin
                    g_data_valid <= 1'b0;
                    g_data_last  <= 1'b0;
                    if (g_prs) begin
                        g_prs <= 1'b0;
                        if (g_lst) begin
                            state <= ST_WAIT_G;
                        end else begin
                            byte_cnt <= byte_cnt + 7'd1;
                        end
                    end else if (g_data_ready) begin
                        g_data_valid <= 1'b1;
                        if (byte_cnt < 7'd32)
                            g_data_in <= m_prime[byte_cnt*8 +: 8];
                        else
                            g_data_in <= h_cached[(byte_cnt - 7'd32)*8 +: 8];
                        g_prs <= 1'b1;
                        if (byte_cnt == 7'd63) begin
                            g_data_last <= 1'b1;
                            g_lst       <= 1'b1;
                        end
                    end
                end

                ST_WAIT_G: begin
                    if (g_hash_valid) begin
                        k_prime <= g_hash_out[255:0];
                        r_prime <= g_hash_out[511:256];
                        state   <= ST_KDF;
                    end
                end

                // KDF(z || c) via SHAKE-256 — produces K̄
                ST_KDF: begin
                    kdf_start <= 1'b1;
                    kdf_cnt   <= 13'd0;
                    state     <= ST_KDF_ABSORB_Z;
                end

                // ct has already been buffered into ct_buf; go straight to absorb.
                ST_KDF_ABSORB_Z: begin
                    state <= ST_KDF_ABSORB_C;
                end

                // Absorb z || ct_buf into SHAKE-256 (present → hold → advance).
                // 1120 bytes total = 32 (z) + 1088 (c), triggering several
                // mid-block permutations.
                ST_KDF_ABSORB_C: begin
                    kdf_absorb_valid <= 1'b0;
                    kdf_absorb_last  <= 1'b0;
                    if (kdf_prs) begin
                        kdf_prs <= 1'b0;
                        if (kdf_lst) begin
                            state <= ST_WAIT_KDF;
                        end else begin
                            kdf_cnt <= kdf_cnt + 13'd1;
                        end
                    end else if (kdf_absorb_ready) begin
                        kdf_absorb_valid <= 1'b1;
                        if (kdf_cnt < 13'd32)
                            kdf_absorb_data <= z_cached[kdf_cnt*8 +: 8];
                        else
                            kdf_absorb_data <= ct_buf[kdf_cnt - 13'd32];
                        kdf_prs <= 1'b1;
                        if (kdf_cnt == 13'd1119) begin
                            kdf_absorb_last <= 1'b1;
                            kdf_lst         <= 1'b1;
                        end
                    end
                end

                ST_WAIT_KDF: begin
                    byte_cnt <= 7'd0;
                    state    <= ST_KDF_SQUEEZE;
                end
                
                ST_KDF_SQUEEZE: begin
                    kdf_squeeze_req <= 1'b1;
                    if (kdf_squeeze_valid) begin
                        k_bar[byte_cnt*8 +: 8] <= kdf_squeeze_data;
                        if (byte_cnt == 7'd31) begin
                            state <= ST_REENCRYPT;
                        end else begin
                            byte_cnt <= byte_cnt + 7'd1;
                        end
                    end
                end

                // Re-encrypt: c' ← K-PKE.Encrypt(ek, m', r')
                // First copy ek (dk bytes at offset DK_PKE_SIZE) into the
                // internal ek_buf (2-cycle-latency read), then stream it.
                ST_REENCRYPT: begin
                    dk_raddr        <= DK_PKE_SIZE[12:0];
                    ek_copy_cnt     <= 13'd0;
                    ek_feed_idx     <= 13'd0;
                    cmp_accumulator <= 8'd0;
                    cmp_idx         <= 13'd0;
                    state           <= ST_REENC_COPY;
                end

                ST_REENC_COPY: begin
                    if (ek_copy_cnt >= 13'd2)
                        ek_buf[ek_copy_cnt - 13'd2] <= dk_rdata;
                    if (ek_copy_cnt == EK_SIZE[12:0] + 13'd1) begin
                        reenc_start <= 1'b1;
                        state       <= ST_FEED_REENC;
                    end else begin
                        dk_raddr     <= DK_PKE_SIZE[12:0] + ek_copy_cnt;
                        ek_copy_cnt  <= ek_copy_cnt + 13'd1;
                    end
                end

                ST_FEED_REENC: begin
                    reenc_ek_valid <= 1'b0;
                    if (reenc_ek_req) begin
                        reenc_ek_valid <= 1'b1;
                        reenc_ek_data  <= ek_buf[ek_feed_idx];
                        if (ek_feed_idx < EK_SIZE[12:0] - 13'd1)
                            ek_feed_idx <= ek_feed_idx + 13'd1;
                    end
                    state <= ST_WAIT_REENC;
                end

                ST_WAIT_REENC: begin
                    reenc_ek_valid <= 1'b0;
                    if (reenc_ek_req) begin
                        reenc_ek_valid <= 1'b1;
                        reenc_ek_data  <= ek_buf[ek_feed_idx];
                        if (ek_feed_idx < EK_SIZE[12:0] - 13'd1)
                            ek_feed_idx <= ek_feed_idx + 13'd1;
                    end

                    // Accumulate constant-time match dynamically.
                    // Compare each re-encrypted ciphertext byte c' (reenc_ct_data
                    // at reenc_ct_addr) against the original c, read directly
                    // from ct_buf (combinational, already latched). This avoids
                    // the register/read-latency misalignment between
                    // delayed_ct_data and ct_rdata that caused c' and c to be
                    // compared at mismatched indices.
                    if (reenc_ct_valid) begin
                        cmp_accumulator <= cmp_accumulator | (reenc_ct_data ^ ct_buf[reenc_ct_addr]);
                    end

                    // When fully done
                    if (reenc_done) begin
                        ct_match <= (cmp_accumulator == 8'd0);
                        state    <= ST_SELECT;
                    end
                end

                ST_COMPARE: begin
                    // Bypassed; handled dynamically in ST_WAIT_REENC
                    state <= ST_SELECT;
                end

                // Constant-time select: K' or K̄
                ST_SELECT: begin
                    ss_valid <= 1'b1;
                    shared_secret <= ct_match ? k_prime : k_bar;
                    state <= ST_DONE;
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
