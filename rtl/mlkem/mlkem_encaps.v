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

    input  wire [7:0]    ek_rdata,
    output reg  [12:0]   ek_raddr,

    output reg           ct_wen,
    output reg  [12:0]   ct_addr,
    output reg  [7:0]    ct_wdata,

    output reg           ss_valid,
    output reg  [255:0]  shared_secret,

    output reg           enc_start,
    output wire [255:0]  enc_message,
    output wire [255:0]  enc_r_seed,
    output reg           enc_ek_valid,
    output reg  [7:0]    enc_ek_data,
    input  wire          enc_done,
    input  wire          enc_ek_req,
    input  wire          enc_ct_valid,
    input  wire [7:0]    enc_ct_data,
    input  wire [12:0]   enc_ct_addr,

    output wire [27:0]   hb_req,
    input  wire [10:0]   hb_rsp,

    output reg           ek_invalid
);
    wire [27:0] hb_req_h;  wire [10:0] hb_rsp_h;
    wire [27:0] hb_req_g;  wire [10:0] hb_rsp_g;
    wire [2*11-1:0] hb_rsp_v;
    assign hb_rsp_h = hb_rsp_v[0*11 +: 11];
    assign hb_rsp_g = hb_rsp_v[1*11 +: 11];

    hash_mux #(.N(2)) u_hash_mux (
        .clk   (clk),
        .rst_n (rst_n),
        .c_req ({hb_req_g, hb_req_h}),
        .c_rsp (hb_rsp_v),
        .m_req (hb_req),
        .m_rsp (hb_rsp)
    );

    `include "mlkem_params.vh"

    localparam EK_SIZE = 384 * K + 32;

    localparam ST_IDLE       = 4'd0;
    localparam ST_HASH_EK    = 4'd1;   // H(ek)
    localparam ST_WAIT_H_EK  = 4'd2;
    localparam ST_HASH_MH    = 4'd3;   // G(m || H(ek)) → (K, r)
    localparam ST_WAIT_G     = 4'd4;
    localparam ST_ENCRYPT    = 4'd5;   // K-PKE.Encrypt(ek, m, r) — feed EK
    localparam ST_WAIT_ENC   = 4'd6;
    localparam ST_OUTPUT     = 4'd7;
    localparam ST_DONE       = 4'd8;

    reg [3:0] state;

    reg          h_start;
    wire         h_data_valid;
    wire [7:0]   h_data_in;
    wire         h_data_last;
    wire         h_hash_valid;
    wire [255:0] h_hash_out;

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
        .busy       (),
        .hb_req     (hb_req_h),
        .hb_rsp     (hb_rsp_h)
    );

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

    localparam TBYTES = 384 * K;
    reg [1:0]  mod_phase;
    reg [7:0]  mod_b0, mod_b1;
    wire [11:0] mod_d1 = {mod_b1[3:0], mod_b0};
    wire [11:0] mod_d2 = {h_data_in,   mod_b1[7:4]};

    reg [255:0] h_ek;         // H(ek)
    reg [255:0] k_value;      // Shared secret K
    reg [255:0] r_value;      // Deterministic randomness r

    assign enc_message = m_random;
    assign enc_r_seed  = r_value;

    reg [12:0] feed_cnt;
    reg [5:0]  byte_cnt;

    reg [1:0]  ek_rd_cnt;     // countdown while a buffer read is in flight
    reg [12:0] ek_feed_cnt;   // total bytes fed to encrypt so far
    reg [1:0]  ek_rd_age;     // cycles since ek_raddr settled on feed_cnt

    assign h_data_valid = (state == ST_HASH_EK) && (ek_raddr == feed_cnt) &&
                          (ek_rd_age == 2'd2);
    assign h_data_in    = ek_rdata;
    assign h_data_last  = h_data_valid && (feed_cnt == EK_SIZE[12:0] - 13'd1);

    assign g_data_valid = (state == ST_HASH_MH);
    assign g_data_in    = (byte_cnt < 6'd32) ? m_random[byte_cnt[4:0]*8 +: 8]
                                             : h_ek[byte_cnt[4:0]*8 +: 8];
    assign g_data_last  = g_data_valid && (byte_cnt == 6'd63);

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
            g_start       <= 1'b0;
            ek_rd_age     <= 2'd0;
            ek_invalid    <= 1'b0;
            mod_phase     <= 2'd0;
            mod_b0        <= 8'd0;
            mod_b1        <= 8'd0;
            enc_start     <= 1'b0;
            enc_ek_valid  <= 1'b0;
            enc_ek_data   <= 8'd0;
            h_ek          <= 256'd0;
            k_value       <= 256'd0;
            r_value       <= 256'd0;
            feed_cnt      <= 13'd0;
            byte_cnt      <= 6'd0;
            ek_rd_cnt     <= 2'd0;
            ek_feed_cnt   <= 13'd0;
        end else begin
            done          <= 1'b0;
            ss_valid      <= 1'b0;
            ct_wen        <= 1'b0;
            h_start       <= 1'b0;
            g_start       <= 1'b0;
            enc_start     <= 1'b0;
            enc_ek_valid  <= 1'b0;

            if (enc_ct_valid) begin
                ct_wen   <= 1'b1;
                ct_addr  <= enc_ct_addr;
                ct_wdata <= enc_ct_data;
            end

            case (state)
                ST_IDLE: begin
                    busy <= 1'b0;
                    if (start) begin
                        busy     <= 1'b1;
                        h_start    <= 1'b1;
                        feed_cnt   <= 13'd0;
                        ek_rd_age  <= 2'd0;
                        ek_invalid <= 1'b0;
                        mod_phase  <= 2'd0;
                        state      <= ST_HASH_EK;
                    end
                end

                ST_HASH_EK: begin
                    if (ek_raddr != feed_cnt) begin
                        ek_raddr  <= feed_cnt;
                        ek_rd_age <= 2'd0;
                    end else if (ek_rd_age != 2'd2) begin
                        ek_rd_age <= ek_rd_age + 2'd1;
                    end
                    if (h_data_valid && h_data_ready) begin
                        if (feed_cnt < TBYTES[12:0]) begin
                            case (mod_phase)
                                2'd0: begin mod_b0 <= h_data_in; mod_phase <= 2'd1; end
                                2'd1: begin mod_b1 <= h_data_in; mod_phase <= 2'd2; end
                                default: begin
                                    if (mod_d1 >= 12'd3329 || mod_d2 >= 12'd3329)
                                        ek_invalid <= 1'b1;
                                    mod_phase <= 2'd0;
                                end
                            endcase
                        end
                        if (feed_cnt == EK_SIZE[12:0] - 13'd1)
                            state <= ST_WAIT_H_EK;
                        else
                            feed_cnt <= feed_cnt + 13'd1;
                    end
                end

                ST_WAIT_H_EK: begin
                    if (h_hash_valid) begin
                        h_ek     <= h_hash_out;
                        if (ek_invalid) begin
                            state <= ST_DONE;
                        end else begin
                            g_start  <= 1'b1;
                            byte_cnt <= 6'd0;
                            state    <= ST_HASH_MH;
                        end
                    end
                end

                ST_HASH_MH: begin
                    if (g_data_valid && g_data_ready) begin
                        if (byte_cnt == 6'd63)
                            state <= ST_WAIT_G;
                        else
                            byte_cnt <= byte_cnt + 6'd1;
                    end
                end

                ST_WAIT_G: begin
                    if (g_hash_valid) begin
                        k_value     <= g_hash_out[255:0];    // K = first 32 bytes
                        r_value     <= g_hash_out[511:256];  // r = last 32 bytes
                        enc_start   <= 1'b1;
                        ek_feed_cnt <= 13'd0;
                        ek_rd_cnt   <= 2'd0;
                        state       <= ST_ENCRYPT;
                    end
                end

                ST_ENCRYPT: begin
                    ek_feed_cnt <= 13'd0;
                    ek_rd_cnt   <= 2'd0;
                    state       <= ST_WAIT_ENC;
                end

                ST_WAIT_ENC: begin
                    if (ek_rd_cnt != 2'd0) begin
                        ek_rd_cnt <= ek_rd_cnt - 2'd1;
                        if (ek_rd_cnt == 2'd1) begin
                            enc_ek_valid <= 1'b1;
                            enc_ek_data  <= ek_rdata;
                        end
                    end

                    if (enc_ek_req && ek_rd_cnt == 2'd0 &&
                        ek_feed_cnt < EK_SIZE[12:0]) begin
                        ek_raddr    <= ek_feed_cnt;
                        ek_feed_cnt <= ek_feed_cnt + 13'd1;
                        ek_rd_cnt   <= 2'd3;
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
