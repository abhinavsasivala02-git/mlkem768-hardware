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

    input  wire [7:0]    dk_rdata,
    output reg  [12:0]   dk_raddr,

    input  wire [7:0]    ct_rdata,
    output reg  [12:0]   ct_raddr,

    output reg           ss_valid,
    output reg  [255:0]  shared_secret,

    output reg           reenc_start,
    output wire [255:0]  reenc_message,
    output wire [255:0]  reenc_r_seed,
    output reg           reenc_ek_valid,
    output reg  [7:0]    reenc_ek_data,
    input  wire          reenc_done,
    input  wire          reenc_ek_req,
    input  wire          reenc_ct_valid,
    input  wire [7:0]    reenc_ct_data,
    input  wire [12:0]   reenc_ct_addr,

    output wire [27:0]   hb_req,
    input  wire [10:0]   hb_rsp,

    output reg           dk_invalid
);
    wire [27:0] hb_req_g;    wire [10:0] hb_rsp_g;
    wire [27:0] hb_req_kdf;  wire [10:0] hb_rsp_kdf;
    wire [27:0] hb_req_h;    wire [10:0] hb_rsp_h;
    wire [3*11-1:0] hb_rsp_v;
    assign hb_rsp_g   = hb_rsp_v[0*11 +: 11];
    assign hb_rsp_kdf = hb_rsp_v[1*11 +: 11];
    assign hb_rsp_h   = hb_rsp_v[2*11 +: 11];

    hash_mux #(.N(3)) u_hash_mux (
        .clk   (clk),
        .rst_n (rst_n),
        .c_req ({hb_req_h, hb_req_kdf, hb_req_g}),
        .c_rsp (hb_rsp_v),
        .m_req (hb_req),
        .m_rsp (hb_rsp)
    );

    reg          chk_start;
    reg  [12:0]  chk_idx;
    reg  [1:0]   chk_rd_age;      // 2-cycle block-RAM read, as elsewhere
    wire         chk_ready, chk_hash_valid;
    wire [255:0] chk_hash_out;

    wire [12:0]  chk_addr  = DK_PKE_SIZE[12:0] + chk_idx;
    wire         chk_valid = (state == ST_CHK_FEED) && (dk_raddr == chk_addr) &&
                             (chk_rd_age == 2'd2);
    wire         chk_last  = chk_valid && (chk_idx == EK_SIZE[12:0] - 13'd1);

    sha3_256 u_chk_hash (
        .clk        (clk),
        .rst_n      (rst_n),
        .start      (chk_start),
        .data_valid (chk_valid),
        .data_in    (dk_rdata),
        .data_ready (chk_ready),
        .data_last  (chk_last),
        .hash_valid (chk_hash_valid),
        .hash_out   (chk_hash_out),
        .busy       (),
        .hb_req     (hb_req_h),
        .hb_rsp     (hb_rsp_h)
    );

    `include "mlkem_params.vh"

    localparam EK_SIZE     = 384 * K + 32;
    localparam DK_PKE_SIZE = 384 * K;
    localparam CT_SIZE     = 32 * DU * K + 32 * DV;

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
    localparam ST_SELECT         = 5'd16;  // Select K' or K̄
    localparam ST_DONE           = 5'd17;
    localparam ST_CHK_FEED       = 5'd18;  // Sec 7.3: stream ek into H()
    localparam ST_CHK_WAIT       = 5'd19;  // Sec 7.3: compare H(ek) with h

    reg [4:0] state;

    reg [255:0] h_cached;     // H(ek) from dk
    reg [255:0] z_cached;     // Implicit rejection value from dk

    reg [255:0] m_prime;

    reg [255:0] k_prime;      // Candidate shared secret
    reg [255:0] r_prime;      // Deterministic randomness

    reg [255:0] k_bar;

    reg         ct_match;     // 1 if c == c', constant-time
    reg [12:0]  cmp_idx;
    reg [7:0]   cmp_accumulator;  // OR of any mismatch (8-bit for XOR)

    reg          g_start;
    wire         g_data_valid;
    wire [7:0]   g_data_in;
    wire         g_data_last;
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
        .busy       (),
        .hb_req     (hb_req_g),
        .hb_rsp     (hb_rsp_g)
    );

    reg          kdf_start;
    wire         kdf_absorb_valid;
    wire [7:0]   kdf_absorb_data;
    wire         kdf_absorb_last;
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
        .busy          (),
        .hb_req        (hb_req_kdf),
        .hb_rsp        (hb_rsp_kdf)
    );

    reg          dec_start;
    wire         dec_done;
    wire         dec_msg_valid;
    wire [255:0] dec_msg_out;

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

    assign reenc_message = m_prime;
    assign reenc_r_seed  = r_prime;

    reg [6:0]  byte_cnt;
    reg [12:0] feed_cnt;        // feed counter for dk/ct/ek bytes
    reg        read_pending;    // 1-cycle read latency pipeline

    reg [12:0] ct_feed_idx;
    reg [12:0] dk_feed_idx;
    reg [1:0]  ct_rd_cnt;
    reg [1:0]  dk_rd_cnt;

    reg [12:0] ek_feed_idx;
    reg [1:0]  ek_rd_cnt;
    reg [1:0]  ct_rd_age;       // cycles since ct_raddr settled on cmp_idx

    assign g_data_valid = (state == ST_HASH_MH);
    assign g_data_in    = (byte_cnt < 7'd32) ? m_prime[byte_cnt[4:0]*8 +: 8]
                                             : h_cached[byte_cnt[4:0]*8 +: 8];
    assign g_data_last  = g_data_valid && (byte_cnt == 7'd63);

    assign kdf_absorb_valid = (state == ST_KDF_ABSORB_Z) ||
                              ((state == ST_KDF_ABSORB_C) &&
                               (ct_raddr == cmp_idx) && (ct_rd_age == 2'd2));
    assign kdf_absorb_data  = (state == ST_KDF_ABSORB_Z)
                              ? z_cached[cmp_idx[4:0]*8 +: 8] : ct_rdata;
    assign kdf_absorb_last  = kdf_absorb_valid && (state == ST_KDF_ABSORB_C) &&
                              (cmp_idx == CT_SIZE[12:0] - 13'd1);

    reg [7:0]  ct1_data,  delayed_ct_data;
    reg        ct1_valid, delayed_ct_valid;

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            ct1_data         <= 8'd0;
            ct1_valid        <= 1'b0;
            delayed_ct_data  <= 8'd0;
            delayed_ct_valid <= 1'b0;
        end else begin
            ct1_data         <= reenc_ct_data;
            ct1_valid        <= reenc_ct_valid;
            delayed_ct_data  <= ct1_data;
            delayed_ct_valid <= ct1_valid;
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
            kdf_start        <= 1'b0;
            kdf_squeeze_req  <= 1'b0;
            ct_rd_age        <= 2'd0;
            dk_invalid       <= 1'b0;
            chk_start        <= 1'b0;
            chk_idx          <= 13'd0;
            chk_rd_age       <= 2'd0;
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
            ct_rd_cnt        <= 2'd0;
            dk_rd_cnt        <= 2'd0;
            ek_feed_idx      <= 13'd0;
            ek_rd_cnt        <= 2'd0;
        end else begin
            done             <= 1'b0;
            ss_valid         <= 1'b0;
            g_start          <= 1'b0;
            kdf_start        <= 1'b0;
            kdf_squeeze_req  <= 1'b0;
            chk_start        <= 1'b0;
            dec_start        <= 1'b0;
            dec_ct_valid     <= 1'b0;
            dec_dk_valid     <= 1'b0;
            reenc_start      <= 1'b0;
            reenc_ek_valid   <= 1'b0;

            if (reenc_ct_valid)
                ct_raddr <= reenc_ct_addr;
            if (delayed_ct_valid)
                cmp_accumulator <= cmp_accumulator | (delayed_ct_data ^ ct_rdata);

            case (state)
                ST_IDLE: begin
                    busy <= 1'b0;
                    if (start) begin
                        busy       <= 1'b1;
                        byte_cnt   <= 7'd0;
                        dk_invalid <= 1'b0;
                        state      <= ST_PARSE_DK;
                    end
                end

                ST_PARSE_DK: begin
                    dk_raddr <= DK_PKE_SIZE[12:0] + EK_SIZE[12:0] + {6'd0, byte_cnt};

                    if (byte_cnt > 7'd1) begin
                        if (byte_cnt <= 7'd33) begin
                            h_cached[(byte_cnt - 7'd2)*8 +: 8] <= dk_rdata;
                        end else begin
                            z_cached[(byte_cnt - 7'd34)*8 +: 8] <= dk_rdata;
                        end
                    end

                    if (byte_cnt == 7'd65) begin
                        byte_cnt       <= 7'd0;
                        chk_start      <= 1'b1;
                        chk_idx        <= 13'd0;
                        chk_rd_age     <= 2'd0;
                        state          <= ST_CHK_FEED;
                    end else begin
                        byte_cnt <= byte_cnt + 7'd1;
                    end
                end

                ST_FEED_DEC: begin
                    if (ct_rd_cnt != 2'd0) begin
                        ct_rd_cnt <= ct_rd_cnt - 2'd1;
                        if (ct_rd_cnt == 2'd1) begin
                            dec_ct_valid <= 1'b1;
                            dec_ct_data  <= ct_rdata;
                        end
                    end
                    if (dk_rd_cnt != 2'd0) begin
                        dk_rd_cnt <= dk_rd_cnt - 2'd1;
                        if (dk_rd_cnt == 2'd1) begin
                            dec_dk_valid <= 1'b1;
                            dec_dk_data  <= dk_rdata;
                        end
                    end

                    if (dec_ct_req && ct_rd_cnt == 2'd0) begin
                        ct_raddr    <= ct_feed_idx;
                        ct_feed_idx <= ct_feed_idx + 13'd1;
                        ct_rd_cnt   <= 2'd3;
                    end
                    if (dec_dk_req && dk_rd_cnt == 2'd0) begin
                        dk_raddr    <= dk_feed_idx;
                        dk_feed_idx <= dk_feed_idx + 13'd1;
                        dk_rd_cnt   <= 2'd3;
                    end

                    state <= ST_WAIT_DEC;
                end

                ST_WAIT_DEC: begin
                    if (ct_rd_cnt != 2'd0) begin
                        ct_rd_cnt <= ct_rd_cnt - 2'd1;
                        if (ct_rd_cnt == 2'd1) begin
                            dec_ct_valid <= 1'b1;
                            dec_ct_data  <= ct_rdata;
                        end
                    end
                    if (dk_rd_cnt != 2'd0) begin
                        dk_rd_cnt <= dk_rd_cnt - 2'd1;
                        if (dk_rd_cnt == 2'd1) begin
                            dec_dk_valid <= 1'b1;
                            dec_dk_data  <= dk_rdata;
                        end
                    end
                    if (dec_ct_req && ct_rd_cnt == 2'd0) begin
                        ct_raddr    <= ct_feed_idx;
                        ct_feed_idx <= ct_feed_idx + 13'd1;
                        ct_rd_cnt   <= 2'd3;
                    end
                    if (dec_dk_req && dk_rd_cnt == 2'd0) begin
                        dk_raddr    <= dk_feed_idx;
                        dk_feed_idx <= dk_feed_idx + 13'd1;
                        dk_rd_cnt   <= 2'd3;
                    end

                    if (dec_done) begin
                        if (dec_msg_valid)
                            m_prime <= dec_msg_out;
                        g_start  <= 1'b1;
                        byte_cnt <= 7'd0;
                        state    <= ST_HASH_MH;
                    end
                end

                ST_HASH_MH: begin
                    if (g_data_valid && g_data_ready) begin
                        if (byte_cnt == 7'd63)
                            state <= ST_WAIT_G;
                        else
                            byte_cnt <= byte_cnt + 7'd1;
                    end
                end

                ST_WAIT_G: begin
                    if (g_hash_valid) begin
                        k_prime <= g_hash_out[255:0];
                        r_prime <= g_hash_out[511:256];
                        state   <= ST_KDF;
                    end
                end

                ST_KDF: begin
                    kdf_start <= 1'b1;
                    cmp_idx   <= 13'd0;
                    state     <= ST_KDF_ABSORB_Z;
                end

                ST_KDF_ABSORB_Z: begin
                    if (kdf_absorb_valid && kdf_absorb_ready) begin
                        if (cmp_idx == 13'd31) begin
                            cmp_idx        <= 13'd0;
                            ct_rd_age      <= 2'd0;
                            state          <= ST_KDF_ABSORB_C;
                        end else begin
                            cmp_idx <= cmp_idx + 13'd1;
                        end
                    end
                end

                ST_KDF_ABSORB_C: begin
                    if (ct_raddr != cmp_idx) begin
                        ct_raddr  <= cmp_idx;
                        ct_rd_age <= 2'd0;
                    end else if (ct_rd_age != 2'd2) begin
                        ct_rd_age <= ct_rd_age + 2'd1;
                    end
                    if (kdf_absorb_valid && kdf_absorb_ready) begin
                        if (cmp_idx == CT_SIZE[12:0] - 13'd1)
                            state <= ST_WAIT_KDF;
                        else
                            cmp_idx <= cmp_idx + 13'd1;
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
                            reenc_start     <= 1'b1;
                            ek_feed_idx     <= 13'd0;
                            ek_rd_cnt       <= 2'd0;
                            state           <= ST_REENCRYPT;
                        end else begin
                            byte_cnt <= byte_cnt + 7'd1;
                        end
                    end
                end

                ST_REENCRYPT: begin
                    cmp_accumulator <= 8'd0;
                    cmp_idx         <= 13'd0;
                    dk_raddr        <= DK_PKE_SIZE[12:0];
                    ek_feed_idx     <= 13'd0;
                    ek_rd_cnt       <= 2'd0;
                    state           <= ST_FEED_REENC;
                end

                ST_FEED_REENC: begin
                    if (ek_rd_cnt != 2'd0) begin
                        ek_rd_cnt <= ek_rd_cnt - 2'd1;
                        if (ek_rd_cnt == 2'd1) begin
                            reenc_ek_valid <= 1'b1;
                            reenc_ek_data  <= dk_rdata;
                        end
                    end

                    if (reenc_ek_req && ek_rd_cnt == 2'd0 &&
                        ek_feed_idx < EK_SIZE[12:0]) begin
                        dk_raddr    <= DK_PKE_SIZE[12:0] + ek_feed_idx;
                        ek_feed_idx <= ek_feed_idx + 13'd1;
                        ek_rd_cnt   <= 2'd3;
                    end

                    state <= ST_WAIT_REENC;
                end

                ST_WAIT_REENC: begin
                    if (ek_rd_cnt != 2'd0) begin
                        ek_rd_cnt <= ek_rd_cnt - 2'd1;
                        if (ek_rd_cnt == 2'd1) begin
                            reenc_ek_valid <= 1'b1;
                            reenc_ek_data  <= dk_rdata;
                        end
                    end
                    if (reenc_ek_req && ek_rd_cnt == 2'd0 &&
                        ek_feed_idx < EK_SIZE[12:0]) begin
                        dk_raddr    <= DK_PKE_SIZE[12:0] + ek_feed_idx;
                        ek_feed_idx <= ek_feed_idx + 13'd1;
                        ek_rd_cnt   <= 2'd3;
                    end

                    if (reenc_done) begin
                        byte_cnt <= 7'd0;
                        state    <= ST_COMPARE;
                    end
                end

                ST_COMPARE: begin
                    if (byte_cnt == 7'd3) begin
                        ct_match <= (cmp_accumulator == 8'd0);
                        state    <= ST_SELECT;
                    end else begin
                        byte_cnt <= byte_cnt + 7'd1;
                    end
                end

                ST_SELECT: begin
                    ss_valid <= 1'b1;
                    shared_secret <= ct_match ? k_prime : k_bar;
                    state <= ST_DONE;
                end

                ST_CHK_FEED: begin
                    if (dk_raddr != chk_addr) begin
                        dk_raddr   <= chk_addr;
                        chk_rd_age <= 2'd0;
                    end else if (chk_rd_age != 2'd2) begin
                        chk_rd_age <= chk_rd_age + 2'd1;
                    end
                    if (chk_valid && chk_ready) begin
                        if (chk_idx == EK_SIZE[12:0] - 13'd1)
                            state <= ST_CHK_WAIT;
                        else
                            chk_idx <= chk_idx + 13'd1;
                    end
                end

                ST_CHK_WAIT: begin
                    if (chk_hash_valid) begin
                        if (chk_hash_out !== h_cached)
                            dk_invalid <= 1'b1;
                        dec_start   <= 1'b1;
                        ct_feed_idx <= 13'd0;
                        dk_feed_idx <= 13'd0;
                        ct_rd_cnt   <= 2'd0;
                        dk_rd_cnt   <= 2'd0;
                        state       <= ST_FEED_DEC;
                    end
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
