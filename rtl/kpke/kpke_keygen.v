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
// K-PKE.KeyGen - Algorithm 13 of FIPS 203
// Correct memory architecture for K>1 (ML-KEM-768, K=3)
//
// Memory layout:
//   ram0 (256 deep)  : current matrix element A_hat[i][j]
//   ram1 (256 deep)  : accumulator for t_hat[i]
//   ram2 (K*256 deep): all K NTT'd secret polynomials s_hat[0..K-1]
//   ram3 (256 deep)  : scratch for e/basemul product
//============================================================================
module kpke_keygen #(
    parameter K    = 3,
    parameter ETA1 = 2
)(
    input  wire          clk,
    input  wire          rst_n,
    input  wire          start,
    input  wire [255:0]  d_seed,
    output reg           done,
    output reg           busy,
    output reg           ek_valid,
    output reg  [7:0]    ek_data,
    output reg  [12:0]   ek_addr,
    output reg           dk_valid,
    output reg  [7:0]    dk_data,
    output reg  [12:0]   dk_addr
);

    // ======================== FSM ========================
    localparam ST_IDLE        = 5'd0;
    localparam ST_HASH_SEED   = 5'd1;
    localparam ST_WAIT_HASH   = 5'd2;
    localparam ST_PRF_S       = 5'd3;
    localparam ST_WAIT_PRF_S  = 5'd4;
    localparam ST_CBD_S       = 5'd5;
    localparam ST_WAIT_CBD_S  = 5'd6;
    localparam ST_NTT_S       = 5'd7;
    localparam ST_WAIT_NTT_S  = 5'd8;
    localparam ST_CLR_ACC     = 5'd9;
    localparam ST_GEN_MATRIX  = 5'd10;
    localparam ST_WAIT_SNTT   = 5'd11;
    localparam ST_BASEMUL     = 5'd12;
    localparam ST_WAIT_MUL    = 5'd13;
    localparam ST_ADD_PROD    = 5'd14;
    localparam ST_WAIT_ADD_P  = 5'd15;
    localparam ST_PRF_E       = 5'd16;
    localparam ST_WAIT_PRF_E  = 5'd17;
    localparam ST_CBD_E       = 5'd18;
    localparam ST_WAIT_CBD_E  = 5'd19;
    localparam ST_NTT_E       = 5'd20;
    localparam ST_WAIT_NTT_E  = 5'd21;
    localparam ST_ADD_E       = 5'd22;
    localparam ST_WAIT_ADD_E  = 5'd23;
    localparam ST_ENCODE_EK   = 5'd24;
    localparam ST_WAIT_ENC_EK = 5'd25;
    localparam ST_OUTPUT_RHO  = 5'd26;
    localparam ST_ENCODE_DK   = 5'd27;
    localparam ST_WAIT_ENC_DK = 5'd28;
    localparam ST_DONE        = 5'd29;

    reg [4:0] state;
    reg [3:0] i_cnt, j_cnt;
    reg [7:0] n_cnt;
    reg [5:0] seed_feed_cnt;
    reg [4:0] rho_byte_cnt;
    reg [8:0] clr_idx;
    reg [255:0] rho;
    reg [255:0] sigma;

    // ======================== RAM Bank ========================
    wire [11:0] ram0_rdata_a, ram0_rdata_b;
    reg         ram0_wen;
    reg  [7:0]  ram0_addr_a, ram0_addr_b;
    reg  [11:0] ram0_wdata;

    wire [11:0] ram1_rdata_a, ram1_rdata_b;
    reg         ram1_wen;
    reg  [7:0]  ram1_addr_a, ram1_addr_b;
    reg  [11:0] ram1_wdata;

    wire [11:0] ram2_rdata_a, ram2_rdata_b;
    reg         ram2_wen;
    reg  [9:0]  ram2_addr_a, ram2_addr_b;
    reg  [11:0] ram2_wdata;

    wire [11:0] ram3_rdata_a, ram3_rdata_b;
    reg         ram3_wen;
    reg  [7:0]  ram3_addr_a, ram3_addr_b;
    reg  [11:0] ram3_wdata;

    poly_ram u_ram0 (
        .clk(clk), .a_wen(ram0_wen), .a_addr(ram0_addr_a),
        .a_wdata(ram0_wdata), .a_rdata(ram0_rdata_a),
        .b_addr(ram0_addr_b), .b_rdata(ram0_rdata_b)
    );
    poly_ram u_ram1 (
        .clk(clk), .a_wen(ram1_wen), .a_addr(ram1_addr_a),
        .a_wdata(ram1_wdata), .a_rdata(ram1_rdata_a),
        .b_addr(ram1_addr_b), .b_rdata(ram1_rdata_b)
    );
    poly_ram #(.DEPTH(768), .ADDR_W(10)) u_ram2 (
        .clk(clk), .a_wen(ram2_wen), .a_addr(ram2_addr_a),
        .a_wdata(ram2_wdata), .a_rdata(ram2_rdata_a),
        .b_addr(ram2_addr_b), .b_rdata(ram2_rdata_b)
    );
    poly_ram u_ram3 (
        .clk(clk), .a_wen(ram3_wen), .a_addr(ram3_addr_a),
        .a_wdata(ram3_wdata), .a_rdata(ram3_rdata_a),
        .b_addr(ram3_addr_b), .b_rdata(ram3_rdata_b)
    );

    // ======================== SHA3-512: G() ========================
    reg          g_start, g_data_valid, g_data_last;
    reg  [7:0]   g_data_in;
    wire         g_hash_valid, g_busy, g_data_ready;
    wire [511:0] g_hash_out;

    sha3_512 u_g_hash (
        .clk(clk), .rst_n(rst_n), .start(g_start),
        .data_valid(g_data_valid), .data_in(g_data_in), .data_ready(g_data_ready),
        .data_last(g_data_last), .hash_valid(g_hash_valid), .hash_out(g_hash_out), .busy(g_busy)
    );

    // ======================== SampleNTT ========================
    reg          sntt_start;
    wire         sntt_done, sntt_busy, sntt_wen;
    wire [7:0]   sntt_addr;
    wire [11:0]  sntt_wdata;

    sample_ntt u_sample_ntt (
        .clk(clk), .rst_n(rst_n), .start(sntt_start),
        .seed(rho), .idx_i({4'd0, i_cnt}), .idx_j({4'd0, j_cnt}),
        .done(sntt_done), .busy(sntt_busy),
        .poly_wen(sntt_wen), .poly_addr(sntt_addr), .poly_wdata(sntt_wdata)
    );

    // ======================== SHAKE-256: PRF ========================
    reg          prf_start, prf_absorb_valid, prf_absorb_last, prf_squeeze_req;
    reg  [7:0]   prf_absorb_data;
    wire         prf_absorb_ready, prf_squeeze_valid, prf_busy;
    wire [7:0]   prf_squeeze_data;

    shake256 u_prf (
        .clk(clk), .rst_n(rst_n), .start(prf_start),
        .absorb_valid(prf_absorb_valid), .absorb_data(prf_absorb_data),
        .absorb_ready(prf_absorb_ready), .absorb_last(prf_absorb_last),
        .squeeze_req(prf_squeeze_req), .squeeze_valid(prf_squeeze_valid),
        .squeeze_data(prf_squeeze_data), .busy(prf_busy)
    );

    // ======================== SamplePolyCBD ========================
    reg          cbd_start;
    wire         cbd_done, cbd_busy, cbd_wen;
    wire [7:0]   cbd_addr;
    wire [11:0]  cbd_wdata;
    wire         cbd_prf_req;

    sample_cbd #(.ETA(ETA1)) u_cbd (
        .clk(clk), .rst_n(rst_n), .start(cbd_start),
        .done(cbd_done), .busy(cbd_busy),
        .prf_valid(prf_squeeze_valid), .prf_data(prf_squeeze_data), .prf_req(cbd_prf_req),
        .poly_wen(cbd_wen), .poly_addr(cbd_addr), .poly_wdata(cbd_wdata)
    );

    // ======================== NTT (unified core) ========================
    reg          ntt_start;
    wire         ntt_done, ntt_busy, ntt_wen;
    wire [7:0]   ntt_addr_a, ntt_addr_b;
    wire [11:0]  ntt_wdata_a;
    reg          ntt_use_ram3;
    wire [11:0]  ram_ntt_rdata_a;
    wire [11:0]  ram_ntt_rdata_b;

    assign ram_ntt_rdata_a = ntt_use_ram3 ? ram3_rdata_a : ram2_rdata_a;
    assign ram_ntt_rdata_b = ntt_use_ram3 ? ram3_rdata_b : ram2_rdata_b;

    ntt_core u_ntt (
        .clk(clk), .rst_n(rst_n), .start(ntt_start), .mode(1'b0),
        .done(ntt_done), .busy(ntt_busy),
        .ram_wen(ntt_wen), .ram_addr_a(ntt_addr_a), .ram_wdata_a(ntt_wdata_a),
        .ram_rdata_a(ram_ntt_rdata_a), .ram_addr_b(ntt_addr_b), .ram_rdata_b(ram_ntt_rdata_b)
    );

    // ======================== Polynomial BaseMul ========================
    reg          bmul_start;
    wire         bmul_done, bmul_busy, bmul_wen;
    wire [7:0]   bmul_a_addr, bmul_b_addr, bmul_c_addr;
    wire [11:0]  bmul_c_wdata;

    poly_basemul u_basemul (
        .clk(clk), .rst_n(rst_n), .start(bmul_start),
        .done(bmul_done), .busy(bmul_busy),
        .a_addr(bmul_a_addr), .a_rdata(ram0_rdata_a),
        .b_addr(bmul_b_addr), .b_rdata(ram2_rdata_a),
        .c_wen(bmul_wen), .c_addr(bmul_c_addr), .c_wdata(bmul_c_wdata)
    );

    // ======================== Polynomial Arithmetic ========================
    reg          arith_start;
    reg  [1:0]   arith_mode;
    wire         arith_done, arith_busy, arith_wen;
    wire [7:0]   arith_a_addr, arith_b_addr, arith_c_addr;
    wire [11:0]  arith_c_wdata;

    poly_arith u_arith (
        .clk(clk), .rst_n(rst_n), .start(arith_start), .mode(arith_mode),
        .done(arith_done), .busy(arith_busy),
        .a_addr(arith_a_addr), .a_rdata(ram1_rdata_a),
        .b_addr(arith_b_addr), .b_rdata(ram3_rdata_a),
        .c_wen(arith_wen), .c_addr(arith_c_addr), .c_wdata(arith_c_wdata)
    );

    // ======================== ByteEncode_12 ========================
    reg          enc_start;
    wire         enc_done, enc_busy, enc_byte_valid;
    wire [7:0]   enc_byte_data, enc_poly_addr;
    wire [10:0]  enc_byte_addr;
    reg          enc_use_ram2;
    wire [11:0]  enc_rdata_mux;

    assign enc_rdata_mux = enc_use_ram2 ? ram2_rdata_a : ram1_rdata_a;

    byte_encode #(.D(12)) u_byte_enc (
        .clk(clk), .rst_n(rst_n), .start(enc_start),
        .done(enc_done), .busy(enc_busy),
        .poly_addr(enc_poly_addr), .poly_rdata(enc_rdata_mux),
        .byte_valid(enc_byte_valid), .byte_data(enc_byte_data), .byte_addr(enc_byte_addr)
    );

    // ======================== Combinational RAM Mux ========================
    always @(*) begin
        ram0_wen = 1'b0; ram0_addr_a = 8'd0; ram0_addr_b = 8'd0; ram0_wdata = 12'd0;
        ram1_wen = 1'b0; ram1_addr_a = 8'd0; ram1_addr_b = 8'd0; ram1_wdata = 12'd0;
        ram2_wen = 1'b0; ram2_addr_a = 10'd0; ram2_addr_b = 10'd0; ram2_wdata = 12'd0;
        ram3_wen = 1'b0; ram3_addr_a = 8'd0; ram3_addr_b = 8'd0; ram3_wdata = 12'd0;

        case (state)
            ST_CLR_ACC: begin
                ram1_wen    = 1'b1;
                ram1_addr_a = clr_idx[7:0];
                ram1_wdata  = 12'd0;
            end
            ST_WAIT_SNTT: begin
                ram0_wen    = sntt_wen;
                ram0_addr_a = sntt_addr;
                ram0_wdata  = sntt_wdata;
            end
            ST_WAIT_CBD_S: begin
                ram2_wen    = cbd_wen;
                ram2_addr_a = {i_cnt[1:0], cbd_addr};
                ram2_wdata  = cbd_wdata;
            end
            ST_NTT_S, ST_WAIT_NTT_S: begin
                ram2_addr_a = {i_cnt[1:0], ntt_addr_a};
                ram2_addr_b = {i_cnt[1:0], ntt_addr_b};
                ram2_wen    = ntt_wen;
                ram2_wdata  = ntt_wdata_a;
            end
            ST_BASEMUL, ST_WAIT_MUL: begin
                ram0_addr_a = bmul_a_addr;
                ram2_addr_a = {j_cnt[1:0], bmul_b_addr};
                ram3_wen    = bmul_wen;
                ram3_addr_a = bmul_wen ? bmul_c_addr : 8'd0;
                ram3_wdata  = bmul_c_wdata;
            end
            ST_ADD_PROD, ST_WAIT_ADD_P: begin
                ram1_addr_a = arith_wen ? arith_c_addr : arith_a_addr;
                ram3_addr_a = arith_b_addr;
                ram1_wen    = arith_wen;
                ram1_wdata  = arith_c_wdata;
            end
            ST_WAIT_CBD_E: begin
                ram3_wen    = cbd_wen;
                ram3_addr_a = cbd_addr;
                ram3_wdata  = cbd_wdata;
            end
            ST_NTT_E, ST_WAIT_NTT_E: begin
                ram3_addr_a = ntt_addr_a;
                ram3_addr_b = ntt_addr_b;
                ram3_wen    = ntt_wen;
                ram3_wdata  = ntt_wdata_a;
            end
            ST_ADD_E, ST_WAIT_ADD_E: begin
                ram1_addr_a = arith_wen ? arith_c_addr : arith_a_addr;
                ram3_addr_a = arith_b_addr;
                ram1_wen    = arith_wen;
                ram1_wdata  = arith_c_wdata;
            end
            ST_ENCODE_EK, ST_WAIT_ENC_EK: begin
                ram1_addr_a = enc_poly_addr;
            end
            ST_ENCODE_DK, ST_WAIT_ENC_DK: begin
                ram2_addr_a = {i_cnt[1:0], enc_poly_addr};
            end
            default: ;
        endcase
    end

    // ======================== FSM Logic ========================
    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            state <= ST_IDLE; done <= 1'b0; busy <= 1'b0;
            ek_valid <= 1'b0; dk_valid <= 1'b0;
            ek_data <= 8'd0; dk_data <= 8'd0;
            ek_addr <= 13'd0; dk_addr <= 13'd0;
            g_start <= 1'b0; g_data_valid <= 1'b0;
            g_data_in <= 8'd0; g_data_last <= 1'b0;
            sntt_start <= 1'b0;
            prf_start <= 1'b0; prf_absorb_valid <= 1'b0;
            prf_absorb_data <= 8'd0; prf_absorb_last <= 1'b0;
            prf_squeeze_req <= 1'b0;
            cbd_start <= 1'b0; ntt_start <= 1'b0; ntt_use_ram3 <= 1'b0;
            bmul_start <= 1'b0; arith_start <= 1'b0; arith_mode <= 2'b00;
            enc_start <= 1'b0; enc_use_ram2 <= 1'b0;
            i_cnt <= 4'd0; j_cnt <= 4'd0; n_cnt <= 8'd0;
            rho <= 256'd0; sigma <= 256'd0;
            seed_feed_cnt <= 6'd0; rho_byte_cnt <= 5'd0; clr_idx <= 9'd0;
        end else begin
            g_start <= 1'b0; g_data_valid <= 1'b0; g_data_last <= 1'b0;
            sntt_start <= 1'b0; prf_start <= 1'b0;
            prf_absorb_valid <= 1'b0; prf_absorb_last <= 1'b0;
            prf_squeeze_req <= 1'b0;
            cbd_start <= 1'b0; ntt_start <= 1'b0;
            bmul_start <= 1'b0; arith_start <= 1'b0;
            enc_start <= 1'b0; done <= 1'b0;
            ek_valid <= 1'b0; dk_valid <= 1'b0;

            case (state)
                ST_IDLE: begin
                    busy <= 1'b0;
                    if (start) begin
                        busy <= 1'b1; g_start <= 1'b1;
                        seed_feed_cnt <= 6'd0; state <= ST_HASH_SEED;
                    end
                end

                ST_HASH_SEED: begin
                    if (g_data_ready) begin
                        g_data_valid <= 1'b1;
                        if (seed_feed_cnt < 6'd32) begin
                            g_data_in <= d_seed[seed_feed_cnt*8 +: 8];
                            seed_feed_cnt <= seed_feed_cnt + 6'd1;
                        end else begin
                            g_data_in <= K[7:0];
                            g_data_last <= 1'b1;
                            state <= ST_WAIT_HASH;
                        end
                    end
                end

                ST_WAIT_HASH: begin
                    if (g_hash_valid) begin
                        rho <= g_hash_out[255:0];
                        sigma <= g_hash_out[511:256];
                        i_cnt <= 4'd0; n_cnt <= 8'd0;
                        state <= ST_PRF_S;
                    end
                end

                ST_PRF_S: begin
                    prf_start <= 1'b1; seed_feed_cnt <= 6'd0;
                    state <= ST_WAIT_PRF_S;
                end

                ST_WAIT_PRF_S: begin
                    if (prf_absorb_ready) begin
                        prf_absorb_valid <= 1'b1;
                        if (seed_feed_cnt < 6'd32) begin
                            prf_absorb_data <= sigma[seed_feed_cnt*8 +: 8];
                            seed_feed_cnt <= seed_feed_cnt + 6'd1;
                        end else begin
                            prf_absorb_data <= n_cnt;
                            prf_absorb_last <= 1'b1;
                            n_cnt <= n_cnt + 8'd1;
                            state <= ST_CBD_S;
                        end
                    end
                end

                ST_CBD_S: begin
                    cbd_start <= 1'b1; state <= ST_WAIT_CBD_S;
                end

                ST_WAIT_CBD_S: begin
                    prf_squeeze_req <= cbd_prf_req;
                    if (cbd_done) begin
                        ntt_start <= 1'b1; ntt_use_ram3 <= 1'b0;
                        state <= ST_NTT_S;
                    end
                end

                ST_NTT_S: state <= ST_WAIT_NTT_S;

                ST_WAIT_NTT_S: begin
                    if (ntt_done) begin
                        if (i_cnt < K - 1) begin
                            i_cnt <= i_cnt + 4'd1;
                            state <= ST_PRF_S;
                        end else begin
                            i_cnt <= 4'd0; j_cnt <= 4'd0;
                            clr_idx <= 9'd0; state <= ST_CLR_ACC;
                        end
                    end
                end

                ST_CLR_ACC: begin
                    if (clr_idx == 9'd255)
                        state <= ST_GEN_MATRIX;
                    else
                        clr_idx <= clr_idx + 9'd1;
                end

                ST_GEN_MATRIX: begin
                    sntt_start <= 1'b1; state <= ST_WAIT_SNTT;
                end

                ST_WAIT_SNTT: begin
                    if (sntt_done) begin
                        bmul_start <= 1'b1; state <= ST_BASEMUL;
                    end
                end

                ST_BASEMUL: state <= ST_WAIT_MUL;

                ST_WAIT_MUL: begin
                    if (bmul_done) begin
                        arith_mode <= 2'b00; arith_start <= 1'b1;
                        state <= ST_ADD_PROD;
                    end
                end

                ST_ADD_PROD: state <= ST_WAIT_ADD_P;

                ST_WAIT_ADD_P: begin
                    if (arith_done) begin
                        if (j_cnt < K - 1) begin
                            j_cnt <= j_cnt + 4'd1;
                            state <= ST_GEN_MATRIX;
                        end else begin
                            j_cnt <= 4'd0; seed_feed_cnt <= 6'd0;
                            state <= ST_PRF_E;
                        end
                    end
                end

                ST_PRF_E: begin
                    prf_start <= 1'b1; seed_feed_cnt <= 6'd0;
                    state <= ST_WAIT_PRF_E;
                end

                ST_WAIT_PRF_E: begin
                    if (prf_absorb_ready) begin
                        prf_absorb_valid <= 1'b1;
                        if (seed_feed_cnt < 6'd32) begin
                            prf_absorb_data <= sigma[seed_feed_cnt*8 +: 8];
                            seed_feed_cnt <= seed_feed_cnt + 6'd1;
                        end else begin
                            prf_absorb_data <= n_cnt;
                            prf_absorb_last <= 1'b1;
                            n_cnt <= n_cnt + 8'd1;
                            state <= ST_CBD_E;
                        end
                    end
                end

                ST_CBD_E: begin
                    cbd_start <= 1'b1; state <= ST_WAIT_CBD_E;
                end

                ST_WAIT_CBD_E: begin
                    prf_squeeze_req <= cbd_prf_req;
                    if (cbd_done) begin
                        ntt_start <= 1'b1; ntt_use_ram3 <= 1'b1;
                        state <= ST_NTT_E;
                    end
                end

                ST_NTT_E: state <= ST_WAIT_NTT_E;

                ST_WAIT_NTT_E: begin
                    if (ntt_done) begin
                        arith_mode <= 2'b00; arith_start <= 1'b1;
                        state <= ST_ADD_E;
                    end
                end

                ST_ADD_E: state <= ST_WAIT_ADD_E;

                ST_WAIT_ADD_E: begin
                    if (arith_done) begin
                        enc_start <= 1'b1; enc_use_ram2 <= 1'b0;
                        state <= ST_ENCODE_EK;
                    end
                end

                ST_ENCODE_EK: state <= ST_WAIT_ENC_EK;

                ST_WAIT_ENC_EK: begin
                    if (enc_byte_valid) begin
                        ek_valid <= 1'b1;
                        ek_data <= enc_byte_data;
                        ek_addr <= {2'd0, enc_byte_addr} + {9'd0, i_cnt} * 13'd384;
                    end
                    if (enc_done) begin
                        if (i_cnt < K - 1) begin
                            i_cnt <= i_cnt + 4'd1;
                            j_cnt <= 4'd0; clr_idx <= 9'd0;
                            state <= ST_CLR_ACC;
                        end else begin
                            rho_byte_cnt <= 5'd0;
                            state <= ST_OUTPUT_RHO;
                        end
                    end
                end

                ST_OUTPUT_RHO: begin
                    ek_valid <= 1'b1;
                    ek_data <= rho[rho_byte_cnt*8 +: 8];
                    ek_addr <= 13'd384 * K[12:0] + {8'd0, rho_byte_cnt};
                    if (rho_byte_cnt == 5'd31) begin
                        i_cnt <= 4'd0; enc_use_ram2 <= 1'b1;
                        state <= ST_ENCODE_DK;
                    end else begin
                        rho_byte_cnt <= rho_byte_cnt + 5'd1;
                    end
                end

                ST_ENCODE_DK: begin
                    enc_start <= 1'b1; state <= ST_WAIT_ENC_DK;
                end

                ST_WAIT_ENC_DK: begin
                    if (enc_byte_valid) begin
                        dk_valid <= 1'b1;
                        dk_data <= enc_byte_data;
                        dk_addr <= {2'd0, enc_byte_addr} + {9'd0, i_cnt} * 13'd384;
                    end
                    if (enc_done) begin
                        if (i_cnt < K - 1) begin
                            i_cnt <= i_cnt + 4'd1;
                            state <= ST_ENCODE_DK;
                        end else
                            state <= ST_DONE;
                    end
                end

                ST_DONE: begin
                    done <= 1'b1; busy <= 1'b0; state <= ST_IDLE;
                end

                default: state <= ST_IDLE;
            endcase
        end
    end

endmodule
