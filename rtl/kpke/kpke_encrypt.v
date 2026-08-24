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
// K-PKE.Encrypt - Algorithm 14 of FIPS 203
// Correct memory architecture for K>1
//
// Memory layout:
//   ram0 (768 deep)   : y_hat (NTT(y[j])), j=0..K-1 at [j*256..]  - persistent
//   ram1 (K*256 deep) : t_hat (decoded from ek) - persistent
//   ram2 (256 deep)   : u accumulator / compressed u
//   ram3 (256 deep)   : A_hat stream / basemul product / e2 / decomp msg
//   ram4 (256 deep)   : v accumulator / e1[i] (during u-loop)
//   ram5 (256 deep)   : compressed output / message
//
// Dataflow (FIPS 203):
//   y[j]   = CBD(prf(r, j))          for j = 0..K-1   (nonces 0..K-1)
//   e1[i]  = CBD(prf(r, K + i))      for i = 0..K-1   (nonces K..2K-1)
//   e2     = CBD(prf(r, 2K))                          (nonce 2K)
//   u[i]   = INTT( sum_j A^T[i][j] o y_hat[j] ) + e1[i]
//   v      = INTT( sum_j t_hat[j]   o y_hat[j] ) + e2 + Decompress_1(m)
//   c1     = Encode_du(Compress_du(u)),  c2 = Encode_dv(Compress_dv(v))
//============================================================================
module kpke_encrypt #(
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

    input  wire          ek_valid,
    input  wire [7:0]    ek_data,
    output reg           ek_req,

    input  wire [255:0]  message,
    input  wire [255:0]  r_seed,

    output reg           ct_valid,
    output reg  [7:0]    ct_data,
    output reg  [12:0]   ct_addr
);

    // ======================== FSM ========================
    localparam ST_IDLE         = 6'd0;
    localparam ST_DECODE_EK    = 6'd1;
    localparam ST_WAIT_DEC_EK  = 6'd2;
    localparam ST_EXTRACT_RHO  = 6'd3;
    localparam ST_PRF_R        = 6'd4;
    localparam ST_WAIT_PRF_R   = 6'd5;
    localparam ST_CBD_R        = 6'd6;
    localparam ST_WAIT_CBD_R   = 6'd7;
    localparam ST_NTT_R        = 6'd8;
    localparam ST_WAIT_NTT_R   = 6'd9;
    localparam ST_CLR_U        = 6'd10;
    localparam ST_GEN_AT       = 6'd11;
    localparam ST_WAIT_SNTT    = 6'd12;
    localparam ST_BASEMUL_ATR  = 6'd13;
    localparam ST_WAIT_MUL_ATR = 6'd14;
    localparam ST_ADD_MUL_ATR  = 6'd15;
    localparam ST_WAIT_ADD_ATR = 6'd16;
    localparam ST_INTT_U       = 6'd17;
    localparam ST_WAIT_INTT_U  = 6'd18;
    localparam ST_PRF_E1       = 6'd19;
    localparam ST_WAIT_PRF_E1  = 6'd20;
    localparam ST_CBD_E1       = 6'd21;
    localparam ST_WAIT_CBD_E1  = 6'd22;
    localparam ST_ADD_E1       = 6'd23;
    localparam ST_WAIT_ADD_E1  = 6'd24;
    localparam ST_COMP_U       = 6'd25;
    localparam ST_WAIT_COMP_U  = 6'd26;
    localparam ST_ENC_C1       = 6'd27;
    localparam ST_WAIT_ENC_C1  = 6'd28;
    localparam ST_CLR_V        = 6'd29;
    localparam ST_BASEMUL_TR   = 6'd30;
    localparam ST_WAIT_MUL_TR  = 6'd31;
    localparam ST_ADD_MUL_TR   = 6'd32;
    localparam ST_WAIT_ADD_TR  = 6'd33;
    localparam ST_INTT_V       = 6'd34;
    localparam ST_WAIT_INTT_V  = 6'd35;
    localparam ST_PRF_E2       = 6'd36;
    localparam ST_WAIT_PRF_E2  = 6'd37;
    localparam ST_CBD_E2       = 6'd38;
    localparam ST_WAIT_CBD_E2  = 6'd39;
    localparam ST_ADD_E2       = 6'd40;
    localparam ST_WAIT_ADD_E2  = 6'd41;
    localparam ST_ADD_MSG      = 6'd42;
    localparam ST_WAIT_ADD_MSG = 6'd43;
    localparam ST_COMP_V       = 6'd44;
    localparam ST_WAIT_COMP_V  = 6'd45;
    localparam ST_ENC_C2       = 6'd46;
    localparam ST_WAIT_ENC_C2  = 6'd47;
    localparam ST_LOAD_MSG     = 6'd48;
    localparam ST_RD_RHO       = 6'd49;
    localparam ST_WAIT_RD_RHO  = 6'd50;
    localparam ST_DONE         = 6'd51;

    reg [5:0] state;
    reg [3:0] i_cnt, j_cnt;
    reg [7:0] n_cnt;
    reg [5:0] seed_feed_cnt;
    reg [8:0] clr_idx;
    reg [4:0] rho_byte_cnt;
    reg [255:0] rho;

    // ======================== RAM Bank ========================
    wire [11:0] ram0_rdata_a, ram0_rdata_b;
    reg         ram0_wen; reg [9:0]  ram0_addr_a, ram0_addr_b; reg [11:0] ram0_wdata;

    wire [11:0] ram1_rdata_a, ram1_rdata_b;
    reg         ram1_wen; reg [9:0]  ram1_addr_a, ram1_addr_b; reg [11:0] ram1_wdata;

    wire [11:0] ram2_rdata_a, ram2_rdata_b;
    reg         ram2_wen; reg [7:0]  ram2_addr_a, ram2_addr_b; reg [11:0] ram2_wdata;

    wire [11:0] ram3_rdata_a, ram3_rdata_b;
    reg         ram3_wen; reg [7:0]  ram3_addr_a, ram3_addr_b; reg [11:0] ram3_wdata;

    wire [11:0] ram4_rdata_a, ram4_rdata_b;
    reg         ram4_wen; reg [7:0]  ram4_addr_a, ram4_addr_b; reg [11:0] ram4_wdata;

    wire [11:0] ram5_rdata_a, ram5_rdata_b;
    reg         ram5_wen; reg [7:0]  ram5_addr_a, ram5_addr_b; reg [11:0] ram5_wdata;

    poly_ram #(.DEPTH(768),.ADDR_W(10)) u_ram0 (.clk(clk),.a_wen(ram0_wen),.a_addr(ram0_addr_a),.a_wdata(ram0_wdata),.a_rdata(ram0_rdata_a),.b_addr(ram0_addr_b),.b_rdata(ram0_rdata_b));
    poly_ram #(.DEPTH(768),.ADDR_W(10)) u_ram1 (.clk(clk),.a_wen(ram1_wen),.a_addr(ram1_addr_a),.a_wdata(ram1_wdata),.a_rdata(ram1_rdata_a),.b_addr(ram1_addr_b),.b_rdata(ram1_rdata_b));
    poly_ram u_ram2 (.clk(clk),.a_wen(ram2_wen),.a_addr(ram2_addr_a),.a_wdata(ram2_wdata),.a_rdata(ram2_rdata_a),.b_addr(ram2_addr_b),.b_rdata(ram2_rdata_b));
    poly_ram u_ram3 (.clk(clk),.a_wen(ram3_wen),.a_addr(ram3_addr_a),.a_wdata(ram3_wdata),.a_rdata(ram3_rdata_a),.b_addr(ram3_addr_b),.b_rdata(ram3_rdata_b));
    poly_ram u_ram4 (.clk(clk),.a_wen(ram4_wen),.a_addr(ram4_addr_a),.a_wdata(ram4_wdata),.a_rdata(ram4_rdata_a),.b_addr(ram4_addr_b),.b_rdata(ram4_rdata_b));
    poly_ram u_ram5 (.clk(clk),.a_wen(ram5_wen),.a_addr(ram5_addr_a),.a_wdata(ram5_wdata),.a_rdata(ram5_rdata_a),.b_addr(ram5_addr_b),.b_rdata(ram5_rdata_b));

    // ======================== Sub-module instances ========================
    reg sntt_start; wire sntt_done, sntt_busy, sntt_wen; wire [7:0] sntt_addr; wire [11:0] sntt_wdata;
    sample_ntt u_sample_ntt (
        .clk(clk),.rst_n(rst_n),.start(sntt_start),.seed(rho),
        .idx_i({4'd0,j_cnt}),.idx_j({4'd0,i_cnt}),.done(sntt_done),.busy(sntt_busy),
        .poly_wen(sntt_wen),.poly_addr(sntt_addr),.poly_wdata(sntt_wdata)
    );

    reg prf_start, prf_absorb_valid, prf_absorb_last, prf_squeeze_req;
    reg [7:0] prf_absorb_data;
    wire prf_absorb_ready, prf_squeeze_valid, prf_busy; wire [7:0] prf_squeeze_data;
    shake256 u_prf (
        .clk(clk),.rst_n(rst_n),.start(prf_start),
        .absorb_valid(prf_absorb_valid),.absorb_data(prf_absorb_data),
        .absorb_ready(prf_absorb_ready),.absorb_last(prf_absorb_last),
        .squeeze_req(prf_squeeze_req),.squeeze_valid(prf_squeeze_valid),
        .squeeze_data(prf_squeeze_data),.busy(prf_busy)
    );

    reg cbd_start; wire cbd_done, cbd_busy, cbd_wen, cbd_prf_req; wire [7:0] cbd_addr; wire [11:0] cbd_wdata;
    sample_cbd #(.ETA(ETA1)) u_cbd (
        .clk(clk),.rst_n(rst_n),.start(cbd_start),.done(cbd_done),.busy(cbd_busy),
        .prf_valid(prf_squeeze_valid),.prf_data(prf_squeeze_data),.prf_req(cbd_prf_req),
        .poly_wen(cbd_wen),.poly_addr(cbd_addr),.poly_wdata(cbd_wdata)
    );

    reg cbd2_start; wire cbd2_done, cbd2_busy, cbd2_wen, cbd2_prf_req; wire [7:0] cbd2_addr; wire [11:0] cbd2_wdata;
    sample_cbd #(.ETA(ETA2)) u_cbd2 (
        .clk(clk),.rst_n(rst_n),.start(cbd2_start),.done(cbd2_done),.busy(cbd2_busy),
        .prf_valid(prf_squeeze_valid),.prf_data(prf_squeeze_data),.prf_req(cbd2_prf_req),
        .poly_wen(cbd2_wen),.poly_addr(cbd2_addr),.poly_wdata(cbd2_wdata)
    );

    // Unified NTT core (forward & inverse via mode)
    reg ntt_start; reg ntt_mode; wire ntt_done, ntt_busy, ntt_wen;
    wire [7:0] ntt_addr_a, ntt_addr_b; wire [11:0] ntt_wdata_a;
    // NTT/INTT RAM mux: selects which RAM the core operates on
    // ntt_ram_sel: 0=ram0[i*256..] (in-place forward NTT of r), 1=ram2 (INTT u), 2=ram4 (INTT v)
    reg [1:0] ntt_ram_sel;
    wire [11:0] ntt_rd_a = (ntt_ram_sel == 2'd2) ? ram4_rdata_a :
                           (ntt_ram_sel == 2'd1) ? ram2_rdata_a : ram0_rdata_a;
    wire [11:0] ntt_rd_b = (ntt_ram_sel == 2'd2) ? ram4_rdata_b :
                           (ntt_ram_sel == 2'd1) ? ram2_rdata_b : ram0_rdata_b;
    ntt_core u_ntt (
        .clk(clk),.rst_n(rst_n),.start(ntt_start),.mode(ntt_mode),
        .done(ntt_done),.busy(ntt_busy),
        .ram_wen(ntt_wen),.ram_addr_a(ntt_addr_a),.ram_wdata_a(ntt_wdata_a),
        .ram_rdata_a(ntt_rd_a),.ram_addr_b(ntt_addr_b),.ram_rdata_b(ntt_rd_b)
    );

    reg bmul_start; wire bmul_done, bmul_busy, bmul_wen;
    wire [7:0] bmul_a_addr, bmul_b_addr, bmul_c_addr; wire [11:0] bmul_c_wdata;
    // For A^T*r: a_rdata = ram3 (A_hat stream), b_rdata = ram0 (y_hat)
    // For t^T*r: a_rdata = ram1 (t_hat),         b_rdata = ram0 (y_hat)
    wire [11:0] bmul_a_rd, bmul_b_rd;
    reg bmul_use_t;
    assign bmul_a_rd = bmul_use_t ? ram1_rdata_a : ram3_rdata_a;
    assign bmul_b_rd = ram0_rdata_b;
    poly_basemul u_basemul (
        .clk(clk),.rst_n(rst_n),.start(bmul_start),.done(bmul_done),.busy(bmul_busy),
        .a_addr(bmul_a_addr),.a_rdata(bmul_a_rd),
        .b_addr(bmul_b_addr),.b_rdata(bmul_b_rd),
        .c_wen(bmul_wen),.c_addr(bmul_c_addr),.c_wdata(bmul_c_wdata)
    );

    reg arith_start; reg [1:0] arith_mode; wire arith_done, arith_busy, arith_wen;
    wire [7:0] arith_a_addr, arith_b_addr, arith_c_addr; wire [11:0] arith_c_wdata;
    wire [11:0] arith_a_rd, arith_b_rd;
    reg arith_use_v;
    assign arith_a_rd = arith_use_v ? ram4_rdata_a : ram2_rdata_a;
    assign arith_b_rd = (state==ST_ADD_E1 || state==ST_WAIT_ADD_E1) ? ram4_rdata_a : ram3_rdata_a;
    poly_arith u_arith (
        .clk(clk),.rst_n(rst_n),.start(arith_start),.mode(arith_mode),
        .done(arith_done),.busy(arith_busy),
        .a_addr(arith_a_addr),.a_rdata(arith_a_rd),
        .b_addr(arith_b_addr),.b_rdata(arith_b_rd),
        .c_wen(arith_wen),.c_addr(arith_c_addr),.c_wdata(arith_c_wdata)
    );

    reg bdec_start; wire bdec_done, bdec_busy, bdec_wen, bdec_byte_req;
    wire [7:0] bdec_addr; wire [11:0] bdec_wdata;
    byte_decode #(.D(12)) u_byte_dec (
        .clk(clk),.rst_n(rst_n),.start(bdec_start),.done(bdec_done),.busy(bdec_busy),
        .byte_valid(ek_valid),.byte_data(ek_data),.byte_req(bdec_byte_req),
        .poly_wen(bdec_wen),.poly_addr(bdec_addr),.poly_wdata(bdec_wdata)
    );

    reg comp_u_start; wire comp_u_done, comp_u_busy, comp_u_wen;
    wire [7:0] comp_u_in_addr, comp_u_out_addr; wire [11:0] comp_u_out_wdata;
    compress #(.D(DU)) u_compress_u (
        .clk(clk),.rst_n(rst_n),.start(comp_u_start),.done(comp_u_done),.busy(comp_u_busy),
        .in_addr(comp_u_in_addr),.in_rdata(ram2_rdata_a),
        .out_wen(comp_u_wen),.out_addr(comp_u_out_addr),.out_wdata(comp_u_out_wdata)
    );

    reg comp_v_start; wire comp_v_done, comp_v_busy, comp_v_wen;
    wire [7:0] comp_v_in_addr, comp_v_out_addr; wire [11:0] comp_v_out_wdata;
    compress #(.D(DV)) u_compress_v (
        .clk(clk),.rst_n(rst_n),.start(comp_v_start),.done(comp_v_done),.busy(comp_v_busy),
        .in_addr(comp_v_in_addr),.in_rdata(ram4_rdata_a),
        .out_wen(comp_v_wen),.out_addr(comp_v_out_addr),.out_wdata(comp_v_out_wdata)
    );

    reg enc_c1_start; wire enc_c1_done, enc_c1_busy, enc_c1_byte_valid;
    wire [7:0] enc_c1_byte_data, enc_c1_poly_addr; wire [10:0] enc_c1_byte_addr;
    byte_encode #(.D(DU)) u_enc_c1 (
        .clk(clk),.rst_n(rst_n),.start(enc_c1_start),.done(enc_c1_done),.busy(enc_c1_busy),
        .poly_addr(enc_c1_poly_addr),.poly_rdata(ram5_rdata_a),
        .byte_valid(enc_c1_byte_valid),.byte_data(enc_c1_byte_data),.byte_addr(enc_c1_byte_addr)
    );

    reg enc_c2_start; wire enc_c2_done, enc_c2_busy, enc_c2_byte_valid;
    wire [7:0] enc_c2_byte_data, enc_c2_poly_addr; wire [10:0] enc_c2_byte_addr;
    byte_encode #(.D(DV)) u_enc_c2 (
        .clk(clk),.rst_n(rst_n),.start(enc_c2_start),.done(enc_c2_done),.busy(enc_c2_busy),
        .poly_addr(enc_c2_poly_addr),.poly_rdata(ram5_rdata_a),
        .byte_valid(enc_c2_byte_valid),.byte_data(enc_c2_byte_data),.byte_addr(enc_c2_byte_addr)
    );

    // ======================== Combinational RAM Mux ========================
    always @(*) begin
        ram0_wen=0; ram0_addr_a=10'd0; ram0_addr_b=10'd0; ram0_wdata=12'd0;
        ram1_wen=0; ram1_addr_a=10'd0; ram1_addr_b=10'd0; ram1_wdata=12'd0;
        ram2_wen=0; ram2_addr_a=8'd0; ram2_addr_b=8'd0; ram2_wdata=12'd0;
        ram3_wen=0; ram3_addr_a=8'd0; ram3_addr_b=8'd0; ram3_wdata=12'd0;
        ram4_wen=0; ram4_addr_a=8'd0; ram4_addr_b=8'd0; ram4_wdata=12'd0;
        ram5_wen=0; ram5_addr_a=8'd0; ram5_addr_b=8'd0; ram5_wdata=12'd0;

        case (state)
            ST_WAIT_DEC_EK: begin
                ram1_wen = bdec_wen;
                ram1_addr_a = {i_cnt[1:0], bdec_addr};
                ram1_wdata = bdec_wdata;
            end
            ST_CLR_U: begin
                ram2_wen = 1'b1; ram2_addr_a = clr_idx[7:0]; ram2_wdata = 12'd0;
            end
            ST_WAIT_CBD_R: begin
                ram0_wen = cbd_wen; ram0_addr_a = {i_cnt[1:0], cbd_addr}; ram0_wdata = cbd_wdata;
            end
            // NTT(r[i]): in-place on ram0[i*256..]
            ST_NTT_R, ST_WAIT_NTT_R: begin
                ram0_addr_a = {i_cnt[1:0], ntt_addr_a}; ram0_addr_b = {i_cnt[1:0], ntt_addr_b};
                ram0_wen = ntt_wen; ram0_wdata = ntt_wdata_a;
            end
            // INTT states also use ntt_core
            ST_INTT_U, ST_WAIT_INTT_U: begin
                ram2_addr_a = ntt_addr_a; ram2_addr_b = ntt_addr_b;
                ram2_wen = ntt_wen; ram2_wdata = ntt_wdata_a;
            end
            // A_hat[i][j] sampled into ram3 (scratch)
            ST_WAIT_SNTT: begin
                ram3_wen = sntt_wen; ram3_addr_a = sntt_addr; ram3_wdata = sntt_wdata;
            end
            // u-path basemul: a = A_hat (ram3), b = y_hat[j] (ram0 port B), product -> ram3
            ST_BASEMUL_ATR, ST_WAIT_MUL_ATR: begin
                ram3_addr_a = bmul_wen ? bmul_c_addr : bmul_a_addr;
                ram0_addr_b = {j_cnt[1:0], bmul_b_addr};
                ram3_wen = bmul_wen; ram3_wdata = bmul_c_wdata;
            end
            ST_ADD_MUL_ATR, ST_WAIT_ADD_ATR: begin
                ram2_addr_a = arith_wen ? arith_c_addr : arith_a_addr;
                ram3_addr_a = arith_b_addr;
                ram2_wen = arith_wen; ram2_wdata = arith_c_wdata;
            end
            // (INTT_U handled above with NTT_R)
            ST_WAIT_CBD_E1: begin
                ram4_wen = cbd2_wen; ram4_addr_a = cbd2_addr; ram4_wdata = cbd2_wdata;
            end
            ST_ADD_E1, ST_WAIT_ADD_E1: begin
                ram2_addr_a = arith_wen ? arith_c_addr : arith_a_addr;
                ram4_addr_a = arith_b_addr;
                ram2_wen = arith_wen; ram2_wdata = arith_c_wdata;
            end
            ST_COMP_U, ST_WAIT_COMP_U: begin
                ram2_addr_a = comp_u_in_addr;
                ram5_wen = comp_u_wen; ram5_addr_a = comp_u_out_addr; ram5_wdata = comp_u_out_wdata;
            end
            ST_ENC_C1, ST_WAIT_ENC_C1: begin
                ram5_addr_a = enc_c1_poly_addr;
            end
            ST_CLR_V: begin
                ram4_wen = 1'b1; ram4_addr_a = clr_idx[7:0]; ram4_wdata = 12'd0;
            end
            // v-path basemul: a = t_hat[j] (ram1), b = y_hat[j] (ram0 port B), product -> ram3
            ST_BASEMUL_TR, ST_WAIT_MUL_TR: begin
                ram1_addr_a = {j_cnt[1:0], bmul_a_addr};
                ram0_addr_b = {j_cnt[1:0], bmul_b_addr};
                ram3_wen = bmul_wen; ram3_addr_a = bmul_wen ? bmul_c_addr : 8'd0; ram3_wdata = bmul_c_wdata;
            end
            ST_ADD_MUL_TR, ST_WAIT_ADD_TR: begin
                ram4_addr_a = arith_wen ? arith_c_addr : arith_a_addr;
                ram3_addr_a = arith_b_addr;
                ram4_wen = arith_wen; ram4_wdata = arith_c_wdata;
            end
            ST_INTT_V, ST_WAIT_INTT_V: begin
                ram4_addr_a = ntt_addr_a; ram4_addr_b = ntt_addr_b;
                ram4_wen = ntt_wen; ram4_wdata = ntt_wdata_a;
            end
            ST_WAIT_CBD_E2: begin
                ram3_wen = cbd2_wen; ram3_addr_a = cbd2_addr; ram3_wdata = cbd2_wdata;
            end
            ST_ADD_E2, ST_WAIT_ADD_E2: begin
                ram4_addr_a = arith_wen ? arith_c_addr : arith_a_addr;
                ram3_addr_a = arith_b_addr;
                ram4_wen = arith_wen; ram4_wdata = arith_c_wdata;
            end
            ST_LOAD_MSG: begin
                // Decompress_1(m) -> ram3 so arith (b=ram3) can add it to v
                ram3_wen = 1'b1; ram3_addr_a = clr_idx[7:0];
                ram3_wdata = message[clr_idx[7:0]] ? 12'd1665 : 12'd0;
            end
            ST_ADD_MSG, ST_WAIT_ADD_MSG: begin
                ram4_addr_a = arith_wen ? arith_c_addr : arith_a_addr;
                ram3_addr_a = arith_b_addr;
                ram4_wen = arith_wen; ram4_wdata = arith_c_wdata;
            end
            ST_COMP_V, ST_WAIT_COMP_V: begin
                ram4_addr_a = comp_v_in_addr;
                ram5_wen = comp_v_wen; ram5_addr_a = comp_v_out_addr; ram5_wdata = comp_v_out_wdata;
            end
            ST_ENC_C2, ST_WAIT_ENC_C2: begin
                ram5_addr_a = enc_c2_poly_addr;
            end
            default: ;
        endcase
    end

    // ======================== FSM Logic ========================
    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            state<=ST_IDLE; done<=0; busy<=0; ct_valid<=0; ct_data<=0; ct_addr<=0; ek_req<=0;
            i_cnt<=0; j_cnt<=0; n_cnt<=0; rho<=0; seed_feed_cnt<=0; clr_idx<=0; rho_byte_cnt<=0;
            sntt_start<=0; prf_start<=0; prf_absorb_valid<=0; prf_absorb_data<=0;
            prf_absorb_last<=0; prf_squeeze_req<=0;
            cbd_start<=0; cbd2_start<=0; ntt_start<=0; ntt_mode<=0; ntt_ram_sel<=0;
            bmul_start<=0; bmul_use_t<=0; arith_start<=0; arith_mode<=0; arith_use_v<=0;
            bdec_start<=0; comp_u_start<=0; comp_v_start<=0;
            enc_c1_start<=0; enc_c2_start<=0;
        end else begin
            done<=0; ct_valid<=0; ek_req<=0;
            sntt_start<=0; prf_start<=0; prf_absorb_valid<=0; prf_absorb_last<=0;
            prf_squeeze_req<=0; cbd_start<=0; cbd2_start<=0;
            ntt_start<=0; bmul_start<=0; arith_start<=0;
            bdec_start<=0; comp_u_start<=0; comp_v_start<=0;
            enc_c1_start<=0; enc_c2_start<=0;

            case (state)
                ST_IDLE: begin
                    busy<=0;
                    if (start) begin
                        busy<=1; i_cnt<=0; bdec_start<=1; bmul_use_t<=0;
                        state<=ST_DECODE_EK;
                    end
                end

                // Decode ek: K polynomials via ByteDecode_12
                ST_DECODE_EK: state<=ST_WAIT_DEC_EK;
                ST_WAIT_DEC_EK: begin
                    ek_req <= bdec_byte_req;
                    if (bdec_done) begin
                        if (i_cnt < K-1) begin
                            i_cnt<=i_cnt+1; bdec_start<=1; state<=ST_DECODE_EK;
                        end else begin
                            // rho is the last 32 bytes of ek (after K t_hat polynomials)
                            i_cnt<=0; rho_byte_cnt<=0; state<=ST_RD_RHO;
                        end
                    end
                end

                ST_RD_RHO: begin
                    ek_req <= 1'b1;
                    state <= ST_WAIT_RD_RHO;
                end
                ST_WAIT_RD_RHO: begin
                    if (ek_valid) begin
                        rho[rho_byte_cnt*8 +: 8] <= ek_data;
                        if (rho_byte_cnt == 5'd31) begin
                            i_cnt<=0; j_cnt<=0; n_cnt<=0;
                            seed_feed_cnt<=0;
                            state<=ST_PRF_R;
                        end else begin
                            rho_byte_cnt <= rho_byte_cnt + 5'd1;
                            state <= ST_RD_RHO;
                        end
                    end
                end

                // Sample y[j] for j=0..K-1 (nonce j), NTT each into ram0 slot j
                ST_PRF_R: begin
                    prf_start<=1; seed_feed_cnt<=0; state<=ST_WAIT_PRF_R;
                end
                ST_WAIT_PRF_R: begin
                    if (prf_absorb_ready) begin
                        prf_absorb_valid<=1;
                        if (seed_feed_cnt < 6'd32) begin
                            prf_absorb_data <= r_seed[seed_feed_cnt*8 +: 8];
                            seed_feed_cnt <= seed_feed_cnt+1;
                        end else begin
                            prf_absorb_data <= n_cnt;
                            prf_absorb_last <= 1;
                            n_cnt <= n_cnt+1;
                            state <= ST_CBD_R;
                        end
                    end
                end
                ST_CBD_R: begin cbd_start<=1; state<=ST_WAIT_CBD_R; end
                ST_WAIT_CBD_R: begin
                    prf_squeeze_req <= cbd_prf_req;
                    if (cbd_done) begin
                        ntt_start<=1; ntt_mode<=0; ntt_ram_sel<=0; state<=ST_NTT_R;
                    end
                end
                ST_NTT_R: state<=ST_WAIT_NTT_R;
                ST_WAIT_NTT_R: begin
                    if (ntt_done) begin
                        if (i_cnt < K-1) begin
                            i_cnt<=i_cnt+1; state<=ST_PRF_R;
                        end else begin
                            i_cnt<=0; j_cnt<=0; clr_idx<=0;
                            state<=ST_CLR_U;
                        end
                    end
                end

                // u[i] = INTT(sum_j A^T[i][j] o y_hat[j]) + e1[i]
                // For each row i:
                ST_CLR_U: begin
                    if (clr_idx==9'd255) begin
                        j_cnt<=0; state<=ST_GEN_AT;
                    end else clr_idx<=clr_idx+1;
                end

                ST_GEN_AT: begin sntt_start<=1; state<=ST_WAIT_SNTT; end
                ST_WAIT_SNTT: begin
                    if (sntt_done) begin
                        bmul_start<=1; state<=ST_BASEMUL_ATR;
                    end
                end

                ST_BASEMUL_ATR: state<=ST_WAIT_MUL_ATR;
                ST_WAIT_MUL_ATR: begin
                    if (bmul_done) begin
                        arith_mode<=2'b00; arith_start<=1; arith_use_v<=0;
                        state<=ST_ADD_MUL_ATR;
                    end
                end
                ST_ADD_MUL_ATR: state<=ST_WAIT_ADD_ATR;
                ST_WAIT_ADD_ATR: begin
                    if (arith_done) begin
                        if (j_cnt < K-1) begin
                            j_cnt<=j_cnt+1; state<=ST_GEN_AT;
                        end else begin
                            j_cnt<=0; ntt_start<=1; ntt_mode<=1; ntt_ram_sel<=2'd1;
                            state<=ST_INTT_U;
                        end
                    end
                end

                ST_INTT_U: state<=ST_WAIT_INTT_U;
                ST_WAIT_INTT_U: begin
                    if (ntt_done) begin
                        seed_feed_cnt<=0; state<=ST_PRF_E1;
                    end
                end

                // Sample e1[i] (nonce = K + i), add to u[i]
                ST_PRF_E1: begin prf_start<=1; seed_feed_cnt<=0; state<=ST_WAIT_PRF_E1; end
                ST_WAIT_PRF_E1: begin
                    if (prf_absorb_ready) begin
                        prf_absorb_valid<=1;
                        if (seed_feed_cnt < 6'd32) begin
                            prf_absorb_data <= r_seed[seed_feed_cnt*8 +: 8];
                            seed_feed_cnt <= seed_feed_cnt+1;
                        end else begin
                            prf_absorb_data <= n_cnt;
                            prf_absorb_last <= 1;
                            n_cnt <= n_cnt+1;
                            state <= ST_CBD_E1;
                        end
                    end
                end
                ST_CBD_E1: begin cbd2_start<=1; state<=ST_WAIT_CBD_E1; end
                ST_WAIT_CBD_E1: begin
                    prf_squeeze_req <= cbd2_prf_req;
                    if (cbd2_done) begin
                        arith_mode<=2'b00; arith_start<=1; arith_use_v<=0;
                        state<=ST_ADD_E1;
                    end
                end
                ST_ADD_E1: state<=ST_WAIT_ADD_E1;
                ST_WAIT_ADD_E1: begin
                    if (arith_done) begin
                        comp_u_start<=1; state<=ST_COMP_U;
                    end
                end

                // Compress_du(u[i])
                ST_COMP_U: state<=ST_WAIT_COMP_U;
                ST_WAIT_COMP_U: begin
                    if (comp_u_done) begin
                        enc_c1_start<=1; state<=ST_ENC_C1;
                    end
                end

                // Encode c1[i]
                ST_ENC_C1: state<=ST_WAIT_ENC_C1;
                ST_WAIT_ENC_C1: begin
                    if (enc_c1_byte_valid) begin
                        ct_valid<=1; ct_data<=enc_c1_byte_data;
                        ct_addr<={2'd0,enc_c1_byte_addr}+{9'd0,i_cnt}*13'd320;
                    end
                    if (enc_c1_done) begin
                        if (i_cnt < K-1) begin
                            i_cnt<=i_cnt+1; clr_idx<=0; state<=ST_CLR_U;
                        end else begin
                            // Now compute v
                            i_cnt<=0; j_cnt<=0; clr_idx<=0;
                            state<=ST_CLR_V;
                        end
                    end
                end

                // v = INTT(sum_j t_hat[j] o y_hat[j]) + e2 + Decompress_1(m)
                ST_CLR_V: begin
                    bmul_use_t<=1;
                    if (clr_idx==9'd255) begin
                        j_cnt<=0; state<=ST_BASEMUL_TR;
                    end else clr_idx<=clr_idx+1;
                end

                // For each j: basemul(t_hat[j], y_hat[j]) and accumulate into ram4 (v)
                ST_BASEMUL_TR: begin
                    bmul_start<=1; state<=ST_WAIT_MUL_TR;
                end
                ST_WAIT_MUL_TR: begin
                    if (bmul_done) begin
                        arith_mode<=2'b00; arith_start<=1; arith_use_v<=1;
                        state<=ST_ADD_MUL_TR;
                    end
                end
                ST_ADD_MUL_TR: state<=ST_WAIT_ADD_TR;
                ST_WAIT_ADD_TR: begin
                    if (arith_done) begin
                        if (j_cnt < K-1) begin
                            j_cnt<=j_cnt+1; state<=ST_BASEMUL_TR;
                        end else begin
                            ntt_start<=1; ntt_mode<=1; ntt_ram_sel<=2'd2;
                            state<=ST_INTT_V;
                        end
                    end
                end

                ST_INTT_V: state<=ST_WAIT_INTT_V;
                ST_WAIT_INTT_V: begin
                    if (ntt_done) begin
                        seed_feed_cnt<=0; state<=ST_PRF_E2;
                    end
                end

                // e2
                ST_PRF_E2: begin prf_start<=1; seed_feed_cnt<=0; state<=ST_WAIT_PRF_E2; end
                ST_WAIT_PRF_E2: begin
                    if (prf_absorb_ready) begin
                        prf_absorb_valid<=1;
                        if (seed_feed_cnt < 6'd32) begin
                            prf_absorb_data <= r_seed[seed_feed_cnt*8 +: 8];
                            seed_feed_cnt <= seed_feed_cnt+1;
                        end else begin
                            prf_absorb_data <= n_cnt;
                            prf_absorb_last <= 1;
                            n_cnt <= n_cnt+1;
                            state <= ST_CBD_E2;
                        end
                    end
                end
                ST_CBD_E2: begin cbd2_start<=1; state<=ST_WAIT_CBD_E2; end
                ST_WAIT_CBD_E2: begin
                    prf_squeeze_req <= cbd2_prf_req;
                    if (cbd2_done) begin
                        arith_mode<=2'b00; arith_start<=1; arith_use_v<=1;
                        state<=ST_ADD_E2;
                    end
                end
                ST_ADD_E2: state<=ST_WAIT_ADD_E2;
                ST_WAIT_ADD_E2: begin
                    if (arith_done) begin
                        clr_idx<=0; state<=ST_LOAD_MSG;
                    end
                end

                // Load message bits into ram5 as Decompress_1
                ST_LOAD_MSG: begin
                    if (clr_idx==9'd255) begin
                        // Now add ram5 (decomp msg) to ram4 (v)
                        // Reuse ram3 for decompressed message
                        arith_mode<=2'b00; arith_start<=1; arith_use_v<=1;
                        state<=ST_ADD_MSG;
                    end else clr_idx<=clr_idx+1;
                end

                ST_ADD_MSG: state<=ST_WAIT_ADD_MSG;
                ST_WAIT_ADD_MSG: begin
                    if (arith_done) begin
                        comp_v_start<=1; state<=ST_COMP_V;
                    end
                end

                ST_COMP_V: state<=ST_WAIT_COMP_V;
                ST_WAIT_COMP_V: begin
                    if (comp_v_done) begin
                        enc_c2_start<=1; state<=ST_ENC_C2;
                    end
                end

                ST_ENC_C2: state<=ST_WAIT_ENC_C2;
                ST_WAIT_ENC_C2: begin
                    if (enc_c2_byte_valid) begin
                        ct_valid<=1; ct_data<=enc_c2_byte_data;
                        ct_addr<=13'd320*K[12:0]+{2'd0,enc_c2_byte_addr};
                    end
                    if (enc_c2_done) begin
                        state<=ST_DONE;
                    end
                end

                ST_DONE: begin done<=1; busy<=0; state<=ST_IDLE; end
                default: state<=ST_IDLE;
            endcase
        end
    end

endmodule
