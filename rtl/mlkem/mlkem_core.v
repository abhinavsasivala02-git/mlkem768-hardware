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
// ML-KEM Core Orchestrator
// Central controller that selects and runs ML-KEM operations:
//   - KeyGen (Algorithm 16)
//   - Encaps (Algorithm 17)
//   - Decaps (Algorithm 18)
//
// Manages shared resources and operation sequencing.
//============================================================================
module mlkem_core #(
    parameter K    = 3,
    parameter ETA1 = 2,
    parameter ETA2 = 2,
    parameter DU   = 10,
    parameter DV   = 4
)(
    input  wire          clk,
    input  wire          rst_n,

    input  wire [1:0]    op_sel,       // 00=KeyGen, 01=Encaps, 10=Decaps
    input  wire          op_start,     // Start selected operation
    output wire          op_done,      // Operation complete
    output wire          op_busy,      // Operation in progress

    input  wire [255:0]  seed_d,       // KeyGen seed d
    input  wire [255:0]  seed_z,       // KeyGen implicit rejection z
    input  wire [255:0]  seed_m,       // Encaps random message m

    output wire [12:0]   ek_addr,
    output wire          ek_wen,
    output wire [7:0]    ek_wdata,
    input  wire [7:0]    ek_rdata,

    output wire [12:0]   dk_addr,
    output wire          dk_wen,
    output wire [7:0]    dk_wdata,
    input  wire [7:0]    dk_rdata,

    output wire [12:0]   ct_addr,
    output wire          ct_wen,
    output wire [7:0]    ct_wdata,
    input  wire [7:0]    ct_rdata,

    output wire          ss_valid,
    output wire [255:0]  shared_secret,

    output wire          op_error
);

    localparam OP_KEYGEN = 2'b00;
    localparam OP_ENCAPS = 2'b01;
    localparam OP_DECAPS = 2'b10;

    wire         kg_done, kg_busy;
    wire         kg_ek_wen, kg_dk_wen;
    wire [12:0]  kg_ek_addr, kg_dk_addr;
    wire [7:0]   kg_ek_wdata, kg_dk_wdata;

    mlkem_keygen #(.K(K), .ETA1(ETA1)) u_keygen (
        .clk       (clk),
        .rst_n     (rst_n),
        .start     (op_start && op_sel == OP_KEYGEN),
        .d_seed    (seed_d),
        .z_random  (seed_z),
        .done      (kg_done),
        .busy      (kg_busy),
        .ek_wen    (kg_ek_wen),
        .ek_addr   (kg_ek_addr),
        .ek_wdata  (kg_ek_wdata),
        .dk_wen    (kg_dk_wen),
        .dk_addr   (kg_dk_addr),
        .dk_wdata  (kg_dk_wdata),
        .hb_req    (hb_req_kg),
        .hb_rsp    (hb_rsp_kg)
    );

    wire         enc_done, enc_busy;
    wire         enc_ct_wen, enc_ss_valid;
    wire [12:0]  enc_ct_addr, enc_ek_raddr;
    wire [7:0]   enc_ct_wdata;
    wire [255:0] enc_shared_secret;

    mlkem_encaps #(.K(K), .ETA1(ETA1), .ETA2(ETA2), .DU(DU), .DV(DV)) u_encaps (
        .clk           (clk),
        .rst_n         (rst_n),
        .start         (op_start && op_sel == OP_ENCAPS),
        .m_random      (seed_m),
        .done          (enc_done),
        .busy          (enc_busy),
        .ek_rdata      (ek_rdata),
        .ek_raddr      (enc_ek_raddr),
        .ct_wen        (enc_ct_wen),
        .ct_addr       (enc_ct_addr),
        .ct_wdata      (enc_ct_wdata),
        .ss_valid      (enc_ss_valid),
        .shared_secret (enc_shared_secret),
        .enc_start     (enc_start_enc),
        .enc_message   (enc_msg_enc),
        .enc_r_seed    (enc_r_enc),
        .enc_ek_valid  (enc_ekv_enc),
        .enc_ek_data   (enc_ekd_enc),
        .enc_done      (sh_enc_done),
        .enc_ek_req    (sh_enc_ek_req),
        .enc_ct_valid  (sh_enc_ct_valid),
        .enc_ct_data   (sh_enc_ct_data),
        .enc_ct_addr   (sh_enc_ct_addr),
        .hb_req        (hb_req_en),
        .hb_rsp        (hb_rsp_en),
        .ek_invalid    (enc_ek_invalid)
    );

    wire         dec_done, dec_busy;
    wire         dec_ss_valid;
    wire [12:0]  dec_dk_raddr, dec_ct_raddr;
    wire [255:0] dec_shared_secret;

    mlkem_decaps #(.K(K), .ETA1(ETA1), .ETA2(ETA2), .DU(DU), .DV(DV)) u_decaps (
        .clk           (clk),
        .rst_n         (rst_n),
        .start         (op_start && op_sel == OP_DECAPS),
        .done          (dec_done),
        .busy          (dec_busy),
        .dk_rdata      (dk_rdata),
        .dk_raddr      (dec_dk_raddr),
        .ct_rdata      (ct_rdata),
        .ct_raddr      (dec_ct_raddr),
        .ss_valid      (dec_ss_valid),
        .shared_secret (dec_shared_secret),
        .reenc_start   (enc_start_dec),
        .reenc_message (enc_msg_dec),
        .reenc_r_seed  (enc_r_dec),
        .reenc_ek_valid(enc_ekv_dec),
        .reenc_ek_data (enc_ekd_dec),
        .reenc_done    (sh_enc_done),
        .reenc_ek_req  (sh_enc_ek_req),
        .reenc_ct_valid(sh_enc_ct_valid),
        .reenc_ct_data (sh_enc_ct_data),
        .reenc_ct_addr (sh_enc_ct_addr),
        .hb_req        (hb_req_de),
        .hb_rsp        (hb_rsp_de),
        .dk_invalid    (dec_dk_invalid)
    );

    kpke_encrypt #(.K(K), .ETA1(ETA1), .ETA2(ETA2), .DU(DU), .DV(DV)) u_kpke_enc_shared (
        .clk      (clk),
        .rst_n    (rst_n),
        .start    ((active_op == OP_DECAPS) ? enc_start_dec : enc_start_enc),
        .done     (sh_enc_done),
        .busy     (),
        .ek_valid ((active_op == OP_DECAPS) ? enc_ekv_dec : enc_ekv_enc),
        .ek_data  ((active_op == OP_DECAPS) ? enc_ekd_dec : enc_ekd_enc),
        .ek_req   (sh_enc_ek_req),
        .message  ((active_op == OP_DECAPS) ? enc_msg_dec : enc_msg_enc),
        .r_seed   ((active_op == OP_DECAPS) ? enc_r_dec   : enc_r_enc),
        .ct_valid (sh_enc_ct_valid),
        .ct_data  (sh_enc_ct_data),
        .ct_addr  (sh_enc_ct_addr),
        .hb_req   (hb_req_ke),
        .hb_rsp   (hb_rsp_ke)
    );

    wire         enc_start_enc,  enc_start_dec;
    wire [255:0] enc_msg_enc,    enc_msg_dec;
    wire [255:0] enc_r_enc,      enc_r_dec;
    wire         enc_ekv_enc,    enc_ekv_dec;
    wire [7:0]   enc_ekd_enc,    enc_ekd_dec;

    wire enc_ek_invalid;
    wire dec_dk_invalid;

    wire [27:0] hb_req_kg, hb_req_en, hb_req_de, hb_req_ke;
    wire [10:0] hb_rsp_kg, hb_rsp_en, hb_rsp_de, hb_rsp_ke;
    wire [4*11-1:0] hb_rsp_v;
    assign hb_rsp_kg = hb_rsp_v[0*11 +: 11];
    assign hb_rsp_en = hb_rsp_v[1*11 +: 11];
    assign hb_rsp_de = hb_rsp_v[2*11 +: 11];
    assign hb_rsp_ke = hb_rsp_v[3*11 +: 11];

    wire [27:0] hb_req_top;
    wire [10:0] hb_rsp_top;

    hash_mux #(.N(4)) u_hash_mux_top (
        .clk   (clk),
        .rst_n (rst_n),
        .c_req ({hb_req_ke, hb_req_de, hb_req_en, hb_req_kg}),
        .c_rsp (hb_rsp_v),
        .m_req (hb_req_top),
        .m_rsp (hb_rsp_top)
    );

    keccak_sponge u_sponge (
        .clk           (clk),
        .rst_n         (rst_n),
        .rate_bytes    (hb_req_top[26:19]),
        .domain_sep    (hb_req_top[18:11]),
        .init          (hb_req_top[27]),
        .absorb_valid  (hb_req_top[10]),
        .absorb_data   (hb_req_top[9:2]),
        .absorb_ready  (hb_rsp_top[10]),
        .absorb_last   (hb_req_top[1]),
        .squeeze_valid (hb_rsp_top[9]),
        .squeeze_data  (hb_rsp_top[8:1]),
        .squeeze_next  (hb_req_top[0]),
        .busy          (hb_rsp_top[0])
    );

    wire         sh_enc_done, sh_enc_ek_req;
    wire         sh_enc_ct_valid;
    wire [7:0]   sh_enc_ct_data;
    wire [12:0]  sh_enc_ct_addr;

    reg [1:0] active_op;

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n)
            active_op <= OP_KEYGEN;
        else if (op_start)
            active_op <= op_sel;
    end

    assign op_done = (active_op == OP_KEYGEN) ? kg_done :
                     (active_op == OP_ENCAPS) ? enc_done :
                     (active_op == OP_DECAPS) ? dec_done : 1'b0;

    assign op_busy = (active_op == OP_KEYGEN) ? kg_busy :
                     (active_op == OP_ENCAPS) ? enc_busy :
                     (active_op == OP_DECAPS) ? dec_busy : 1'b0;

    assign ek_wen   = (active_op == OP_KEYGEN) ? kg_ek_wen : 1'b0;
    assign ek_addr  = (active_op == OP_KEYGEN) ? kg_ek_addr :
                      (active_op == OP_ENCAPS) ? enc_ek_raddr : 13'd0;
    assign ek_wdata = kg_ek_wdata;

    assign dk_wen   = (active_op == OP_KEYGEN) ? kg_dk_wen : 1'b0;
    assign dk_addr  = (active_op == OP_KEYGEN) ? kg_dk_addr :
                      (active_op == OP_DECAPS) ? dec_dk_raddr : 13'd0;
    assign dk_wdata = kg_dk_wdata;

    assign ct_wen   = (active_op == OP_ENCAPS) ? enc_ct_wen : 1'b0;
    assign ct_addr  = (active_op == OP_ENCAPS) ? enc_ct_addr :
                      (active_op == OP_DECAPS) ? dec_ct_raddr : 13'd0;
    assign ct_wdata = enc_ct_wdata;

    assign ss_valid      = (active_op == OP_ENCAPS) ? enc_ss_valid :
                           (active_op == OP_DECAPS) ? dec_ss_valid : 1'b0;
    assign shared_secret = (active_op == OP_ENCAPS) ? enc_shared_secret :
                           (active_op == OP_DECAPS) ? dec_shared_secret : 256'd0;

    assign op_error      = (active_op == OP_ENCAPS) ? enc_ek_invalid :
                           (active_op == OP_DECAPS) ? dec_dk_invalid : 1'b0;

endmodule
