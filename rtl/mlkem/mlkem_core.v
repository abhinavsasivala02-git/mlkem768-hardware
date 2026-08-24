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

    // Control
    input  wire [1:0]    op_sel,       // 00=KeyGen, 01=Encaps, 10=Decaps
    input  wire          op_start,     // Start selected operation
    output wire          op_done,      // Operation complete
    output wire          op_busy,      // Operation in progress

    // Seed/randomness inputs (from AXI register interface)
    input  wire [255:0]  seed_d,       // KeyGen seed d
    input  wire [255:0]  seed_z,       // KeyGen implicit rejection z
    input  wire [255:0]  seed_m,       // Encaps random message m

    // EK buffer interface
    output wire [12:0]   ek_addr,
    output wire          ek_wen,
    output wire [7:0]    ek_wdata,
    input  wire [7:0]    ek_rdata,

    // DK buffer interface
    output wire [12:0]   dk_addr,
    output wire          dk_wen,
    output wire [7:0]    dk_wdata,
    input  wire [7:0]    dk_rdata,

    // CT buffer interface
    output wire [12:0]   ct_addr,
    output wire          ct_wen,
    output wire [7:0]    ct_wdata,
    input  wire [7:0]    ct_rdata,

    // Shared secret output
    output wire          ss_valid,
    output wire [255:0]  shared_secret
);

    // Operation select
    localparam OP_KEYGEN = 2'b00;
    localparam OP_ENCAPS = 2'b01;
    localparam OP_DECAPS = 2'b10;

    // KeyGen instance
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
        .dk_wdata  (kg_dk_wdata)
    );

    // Encaps instance
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
        .shared_secret (enc_shared_secret)
    );

    // Decaps instance
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
        .shared_secret (dec_shared_secret)
    );

    // Output muxing based on active operation
    reg [1:0] active_op;

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n)
            active_op <= OP_KEYGEN;
        else if (op_start)
            active_op <= op_sel;
    end

    // Done/busy
    assign op_done = (active_op == OP_KEYGEN) ? kg_done :
                     (active_op == OP_ENCAPS) ? enc_done :
                     (active_op == OP_DECAPS) ? dec_done : 1'b0;

    assign op_busy = (active_op == OP_KEYGEN) ? kg_busy :
                     (active_op == OP_ENCAPS) ? enc_busy :
                     (active_op == OP_DECAPS) ? dec_busy : 1'b0;

    // EK bus
    assign ek_wen   = (active_op == OP_KEYGEN) ? kg_ek_wen : 1'b0;
    assign ek_addr  = (active_op == OP_KEYGEN) ? kg_ek_addr :
                      (active_op == OP_ENCAPS) ? enc_ek_raddr : 13'd0;
    assign ek_wdata = kg_ek_wdata;

    // DK bus
    assign dk_wen   = (active_op == OP_KEYGEN) ? kg_dk_wen : 1'b0;
    assign dk_addr  = (active_op == OP_KEYGEN) ? kg_dk_addr :
                      (active_op == OP_DECAPS) ? dec_dk_raddr : 13'd0;
    assign dk_wdata = kg_dk_wdata;

    // CT bus
    assign ct_wen   = (active_op == OP_ENCAPS) ? enc_ct_wen : 1'b0;
    assign ct_addr  = (active_op == OP_ENCAPS) ? enc_ct_addr :
                      (active_op == OP_DECAPS) ? dec_ct_raddr : 13'd0;
    assign ct_wdata = enc_ct_wdata;

    // Shared secret
    assign ss_valid      = (active_op == OP_ENCAPS) ? enc_ss_valid :
                           (active_op == OP_DECAPS) ? dec_ss_valid : 1'b0;
    assign shared_secret = (active_op == OP_ENCAPS) ? enc_shared_secret :
                           (active_op == OP_DECAPS) ? dec_shared_secret : 256'd0;

endmodule
