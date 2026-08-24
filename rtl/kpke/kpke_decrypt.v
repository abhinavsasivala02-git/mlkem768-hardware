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
// K-PKE.Decrypt - Algorithm 15 of FIPS 203
// Correct memory architecture for K>1
//============================================================================
module kpke_decrypt #(
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

    // Ciphertext input
    input  wire          ct_valid,
    input  wire [7:0]    ct_data,
    output reg           ct_req,

    // Decryption key input
    input  wire          dk_valid,
    input  wire [7:0]    dk_data,
    output reg           dk_req,

    // Recovered message output
    output reg           msg_valid,
    output reg  [255:0]  msg_out
);

    localparam ST_IDLE       = 5'd0;
    localparam ST_DEC_C1     = 5'd1;
    localparam ST_WAIT_DC1   = 5'd2;
    localparam ST_DECOMP_U   = 5'd3;
    localparam ST_WAIT_DCU   = 5'd4;
    localparam ST_DEC_C2     = 5'd5;
    localparam ST_WAIT_DC2   = 5'd6;
    localparam ST_DECOMP_V   = 5'd7;
    localparam ST_WAIT_DCV   = 5'd8;
    localparam ST_DEC_DK     = 5'd9;
    localparam ST_WAIT_DDK   = 5'd10;
    localparam ST_NTT_U      = 5'd11;
    localparam ST_WAIT_NTTU  = 5'd12;
    localparam ST_CLR_ACC    = 5'd13;
    localparam ST_BASEMUL    = 5'd14;
    localparam ST_WAIT_MUL   = 5'd15;
    localparam ST_ADD_MUL    = 5'd16;
    localparam ST_WAIT_ADD   = 5'd17;
    localparam ST_INTT_W     = 5'd18;
    localparam ST_WAIT_INTT  = 5'd19;
    localparam ST_SUB_V      = 5'd20;
    localparam ST_WAIT_SUB   = 5'd21;
    localparam ST_COMP_MSG   = 5'd22;
    localparam ST_WAIT_COMP  = 5'd23;
    localparam ST_ENC_MSG    = 5'd24;
    localparam ST_WAIT_ENC   = 5'd25;
    localparam ST_DONE       = 5'd26;

    reg [4:0] state;
    reg [3:0] i_cnt;
    reg [8:0] clr_idx;

    // RAM Bank
    // ram0: u[i] (decoded from c1), K*256 deep; [0..255] doubles as w accumulator
    // ram1: v (decoded from c2)
    // ram2: s_hat[i] (decoded from dk), K*256 deep
    // ram3: basemul product scratch / final m' output
    wire [11:0] ram0_rdata_a, ram0_rdata_b;
    reg ram0_wen; reg [9:0] ram0_addr_a, ram0_addr_b; reg [11:0] ram0_wdata;

    wire [11:0] ram1_rdata_a, ram1_rdata_b;
    reg ram1_wen; reg [7:0] ram1_addr_a, ram1_addr_b; reg [11:0] ram1_wdata;

    wire [11:0] ram2_rdata_a, ram2_rdata_b;
    reg ram2_wen; reg [9:0] ram2_addr_a, ram2_addr_b; reg [11:0] ram2_wdata;

    wire [11:0] ram3_rdata_a, ram3_rdata_b;
    reg ram3_wen; reg [7:0] ram3_addr_a, ram3_addr_b; reg [11:0] ram3_wdata;

    poly_ram #(.DEPTH(768),.ADDR_W(10)) u_ram0 (.clk(clk),.a_wen(ram0_wen),.a_addr(ram0_addr_a),.a_wdata(ram0_wdata),.a_rdata(ram0_rdata_a),.b_addr(ram0_addr_b),.b_rdata(ram0_rdata_b));
    poly_ram u_ram1 (.clk(clk),.a_wen(ram1_wen),.a_addr(ram1_addr_a),.a_wdata(ram1_wdata),.a_rdata(ram1_rdata_a),.b_addr(ram1_addr_b),.b_rdata(ram1_rdata_b));
    poly_ram #(.DEPTH(768),.ADDR_W(10)) u_ram2 (.clk(clk),.a_wen(ram2_wen),.a_addr(ram2_addr_a),.a_wdata(ram2_wdata),.a_rdata(ram2_rdata_a),.b_addr(ram2_addr_b),.b_rdata(ram2_rdata_b));
    poly_ram u_ram3 (.clk(clk),.a_wen(ram3_wen),.a_addr(ram3_addr_a),.a_wdata(ram3_wdata),.a_rdata(ram3_rdata_a),.b_addr(ram3_addr_b),.b_rdata(ram3_rdata_b));

    // Sub-modules
    reg bdec_u_start; wire bdec_u_done, bdec_u_busy, bdec_u_wen, bdec_u_req;
    wire [7:0] bdec_u_addr; wire [11:0] bdec_u_wdata;
    byte_decode #(.D(DU)) u_bdec_u (
        .clk(clk),.rst_n(rst_n),.start(bdec_u_start),.done(bdec_u_done),.busy(bdec_u_busy),
        .byte_valid(ct_valid),.byte_data(ct_data),.byte_req(bdec_u_req),
        .poly_wen(bdec_u_wen),.poly_addr(bdec_u_addr),.poly_wdata(bdec_u_wdata)
    );

    reg bdec_v_start; wire bdec_v_done, bdec_v_busy, bdec_v_wen, bdec_v_req;
    wire [7:0] bdec_v_addr; wire [11:0] bdec_v_wdata;
    byte_decode #(.D(DV)) u_bdec_v (
        .clk(clk),.rst_n(rst_n),.start(bdec_v_start),.done(bdec_v_done),.busy(bdec_v_busy),
        .byte_valid(ct_valid),.byte_data(ct_data),.byte_req(bdec_v_req),
        .poly_wen(bdec_v_wen),.poly_addr(bdec_v_addr),.poly_wdata(bdec_v_wdata)
    );

    reg decomp_u_start; wire decomp_u_done, decomp_u_busy, decomp_u_wen;
    wire [7:0] decomp_u_in_addr, decomp_u_out_addr; wire [11:0] decomp_u_out_wdata;
    decompress #(.D(DU)) u_decomp_u (
        .clk(clk),.rst_n(rst_n),.start(decomp_u_start),.done(decomp_u_done),.busy(decomp_u_busy),
        .in_addr(decomp_u_in_addr),.in_rdata(ram0_rdata_a),
        .out_wen(decomp_u_wen),.out_addr(decomp_u_out_addr),.out_wdata(decomp_u_out_wdata)
    );

    reg decomp_v_start; wire decomp_v_done, decomp_v_busy, decomp_v_wen;
    wire [7:0] decomp_v_in_addr, decomp_v_out_addr; wire [11:0] decomp_v_out_wdata;
    decompress #(.D(DV)) u_decomp_v (
        .clk(clk),.rst_n(rst_n),.start(decomp_v_start),.done(decomp_v_done),.busy(decomp_v_busy),
        .in_addr(decomp_v_in_addr),.in_rdata(ram1_rdata_a),
        .out_wen(decomp_v_wen),.out_addr(decomp_v_out_addr),.out_wdata(decomp_v_out_wdata)
    );

    reg bdec_dk_start; wire bdec_dk_done, bdec_dk_busy, bdec_dk_wen, bdec_dk_req;
    wire [7:0] bdec_dk_addr; wire [11:0] bdec_dk_wdata;
    byte_decode #(.D(12)) u_bdec_dk (
        .clk(clk),.rst_n(rst_n),.start(bdec_dk_start),.done(bdec_dk_done),.busy(bdec_dk_busy),
        .byte_valid(dk_valid),.byte_data(dk_data),.byte_req(bdec_dk_req),
        .poly_wen(bdec_dk_wen),.poly_addr(bdec_dk_addr),.poly_wdata(bdec_dk_wdata)
    );

    // Unified NTT core (forward & inverse)
    reg ntt_start; reg ntt_mode_reg;
    wire ntt_done, ntt_busy, ntt_wen; wire [7:0] ntt_addr_a, ntt_addr_b; wire [11:0] ntt_wdata_a;
    // ntt_ram_sel: 0=forward NTT of u_i (ram0[i*256..]), 1=INTT of w (ram0[0..255])
    reg ntt_ram_sel;
    wire [11:0] ntt_rd_a = ram0_rdata_a;
    wire [11:0] ntt_rd_b = ram0_rdata_b;
    ntt_core u_ntt (
        .clk(clk),.rst_n(rst_n),.start(ntt_start),.mode(ntt_mode_reg),
        .done(ntt_done),.busy(ntt_busy),
        .ram_wen(ntt_wen),.ram_addr_a(ntt_addr_a),.ram_wdata_a(ntt_wdata_a),
        .ram_rdata_a(ntt_rd_a),.ram_addr_b(ntt_addr_b),.ram_rdata_b(ntt_rd_b)
    );

    reg bmul_start; wire bmul_done, bmul_busy, bmul_wen;
    wire [7:0] bmul_a_addr, bmul_b_addr, bmul_c_addr; wire [11:0] bmul_c_wdata;
    poly_basemul u_basemul (
        .clk(clk),.rst_n(rst_n),.start(bmul_start),.done(bmul_done),.busy(bmul_busy),
        .a_addr(bmul_a_addr),.a_rdata(ram2_rdata_a),
        .b_addr(bmul_b_addr),.b_rdata(ram0_rdata_a),
        .c_wen(bmul_wen),.c_addr(bmul_c_addr),.c_wdata(bmul_c_wdata)
    );

    reg arith_start; reg [1:0] arith_mode; wire arith_done, arith_busy, arith_wen;
    wire [7:0] arith_a_addr, arith_b_addr, arith_c_addr; wire [11:0] arith_c_wdata;
    // During accumulation (ST_ADD_MUL): a = ram0[0..255] partial sum, b = ram3 product
    // During ST_SUB_V: a = ram1 (v), b = ram0 (w)
    wire [11:0] arith_a_rd, arith_b_rd;
    assign arith_a_rd = (state==ST_ADD_MUL || state==ST_WAIT_ADD) ? ram0_rdata_a : ram1_rdata_a;
    assign arith_b_rd = (state==ST_ADD_MUL || state==ST_WAIT_ADD) ? ram3_rdata_a : ram0_rdata_a;
    poly_arith u_arith (
        .clk(clk),.rst_n(rst_n),.start(arith_start),.mode(arith_mode),
        .done(arith_done),.busy(arith_busy),
        .a_addr(arith_a_addr),.a_rdata(arith_a_rd),
        .b_addr(arith_b_addr),.b_rdata(arith_b_rd),
        .c_wen(arith_wen),.c_addr(arith_c_addr),.c_wdata(arith_c_wdata)
    );

    reg comp_m_start; wire comp_m_done, comp_m_busy, comp_m_wen;
    wire [7:0] comp_m_in_addr, comp_m_out_addr; wire [11:0] comp_m_out_wdata;
    compress #(.D(1)) u_comp_msg (
        .clk(clk),.rst_n(rst_n),.start(comp_m_start),.done(comp_m_done),.busy(comp_m_busy),
        .in_addr(comp_m_in_addr),.in_rdata(ram3_rdata_a),
        .out_wen(comp_m_wen),.out_addr(comp_m_out_addr),.out_wdata(comp_m_out_wdata)
    );

    reg enc_m_start; wire enc_m_done, enc_m_busy, enc_m_byte_valid;
    wire [7:0] enc_m_byte_data, enc_m_poly_addr; wire [10:0] enc_m_byte_addr;
    byte_encode #(.D(1)) u_enc_msg (
        .clk(clk),.rst_n(rst_n),.start(enc_m_start),.done(enc_m_done),.busy(enc_m_busy),
        .poly_addr(enc_m_poly_addr),.poly_rdata(ram3_rdata_a),
        .byte_valid(enc_m_byte_valid),.byte_data(enc_m_byte_data),.byte_addr(enc_m_byte_addr)
    );

    // Combinational RAM mux
    always @(*) begin
        ram0_wen=0; ram0_addr_a=10'd0; ram0_addr_b=10'd0; ram0_wdata=12'd0;
        ram1_wen=0; ram1_addr_a=8'd0; ram1_addr_b=8'd0; ram1_wdata=12'd0;
        ram2_wen=0; ram2_addr_a=10'd0; ram2_addr_b=10'd0; ram2_wdata=12'd0;
        ram3_wen=0; ram3_addr_a=8'd0; ram3_addr_b=8'd0; ram3_wdata=12'd0;

        case (state)
            ST_WAIT_DC1: begin
                ram0_wen=bdec_u_wen; ram0_addr_a={i_cnt[1:0],bdec_u_addr}; ram0_wdata=bdec_u_wdata;
            end
            ST_DECOMP_U, ST_WAIT_DCU: begin
                ram0_addr_a = decomp_u_wen ? {i_cnt[1:0],decomp_u_out_addr} : {i_cnt[1:0],decomp_u_in_addr};
                ram0_wen=decomp_u_wen; ram0_wdata=decomp_u_out_wdata;
            end
            ST_WAIT_DC2: begin
                ram1_wen=bdec_v_wen; ram1_addr_a=bdec_v_addr; ram1_wdata=bdec_v_wdata;
            end
            ST_DECOMP_V, ST_WAIT_DCV: begin
                ram1_addr_a = decomp_v_wen ? decomp_v_out_addr : decomp_v_in_addr;
                ram1_wen=decomp_v_wen; ram1_wdata=decomp_v_out_wdata;
            end
            ST_WAIT_DDK: begin
                ram2_wen=bdec_dk_wen; ram2_addr_a={i_cnt[1:0],bdec_dk_addr}; ram2_wdata=bdec_dk_wdata;
            end
            ST_NTT_U, ST_WAIT_NTTU, ST_INTT_W, ST_WAIT_INTT: begin
                ram0_addr_a = ntt_ram_sel ? ntt_addr_a : {i_cnt[1:0],ntt_addr_a};
                ram0_addr_b = ntt_ram_sel ? ntt_addr_b : {i_cnt[1:0],ntt_addr_b};
                ram0_wen=ntt_wen; ram0_wdata=ntt_wdata_a;
            end
            ST_CLR_ACC: begin
                ram3_wen=1; ram3_addr_a=clr_idx[7:0]; ram3_wdata=12'd0;
            end
            ST_BASEMUL, ST_WAIT_MUL: begin
                ram2_addr_a={i_cnt[1:0],bmul_a_addr};
                ram0_addr_a={i_cnt[1:0],bmul_b_addr};
                if (i_cnt == 4'd0) begin
                    // i=0: product written directly to ram0[0..255] as initial accumulator
                    ram0_wen=bmul_wen; ram0_addr_a=bmul_wen?bmul_c_addr:{i_cnt[1:0],bmul_b_addr};
                    ram0_wdata=bmul_c_wdata;
                end else begin
                    ram3_wen=bmul_wen; ram3_addr_a=bmul_wen?bmul_c_addr:8'd0; ram3_wdata=bmul_c_wdata;
                end
            end
            ST_ADD_MUL, ST_WAIT_ADD: begin
                // Accumulate w: a=ram0[0..255](partial sum) + b=ram3(product) -> ram0[0..255]
                ram0_addr_a = arith_wen ? arith_c_addr : arith_a_addr;
                ram3_addr_a = arith_b_addr;
                ram0_wen=arith_wen; ram0_wdata=arith_c_wdata;
            end
            ST_INTT_W, ST_WAIT_INTT: begin
                ram0_addr_a=ntt_ram_sel?ntt_addr_a:{i_cnt[1:0],ntt_addr_a};
                ram0_addr_b=ntt_ram_sel?ntt_addr_b:{i_cnt[1:0],ntt_addr_b};
                ram0_wen=ntt_wen; ram0_wdata=ntt_wdata_a;
            end
            ST_SUB_V, ST_WAIT_SUB: begin
                // m' = compress(v - w): a=ram1(v), b=ram0(w), result -> ram3
                ram1_addr_a = arith_a_addr;
                ram0_addr_a = arith_b_addr;
                ram3_addr_a = arith_wen ? arith_c_addr : 8'd0;
                ram3_wen=arith_wen; ram3_wdata=arith_c_wdata;
            end
            ST_COMP_MSG, ST_WAIT_COMP: begin
                ram3_addr_a = comp_m_wen ? comp_m_out_addr : comp_m_in_addr;
                ram3_wen=comp_m_wen; ram3_wdata=comp_m_out_wdata;
            end
            ST_ENC_MSG, ST_WAIT_ENC: begin
                ram3_addr_a=enc_m_poly_addr;
            end
            default: ;
        endcase
    end

    // FSM
    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            state<=ST_IDLE; done<=0; busy<=0; msg_valid<=0; msg_out<=256'd0;
            ct_req<=0; dk_req<=0; i_cnt<=0; clr_idx<=0;
            bdec_u_start<=0; bdec_v_start<=0; bdec_dk_start<=0;
            decomp_u_start<=0; decomp_v_start<=0;
            ntt_start<=0; ntt_mode_reg<=0; ntt_ram_sel<=0; bmul_start<=0;
            arith_start<=0; arith_mode<=0; comp_m_start<=0; enc_m_start<=0;
        end else begin
            bdec_u_start<=0; bdec_v_start<=0; bdec_dk_start<=0;
            decomp_u_start<=0; decomp_v_start<=0;
            ntt_start<=0; bmul_start<=0;
            arith_start<=0; comp_m_start<=0; enc_m_start<=0;
            done<=0; msg_valid<=0; ct_req<=0; dk_req<=0;

            case (state)
                ST_IDLE: begin
                    busy<=0;
                    if (start) begin busy<=1; i_cnt<=0; bdec_u_start<=1; state<=ST_DEC_C1; end
                end

                ST_DEC_C1: begin ct_req<=bdec_u_req; state<=ST_WAIT_DC1; end
                ST_WAIT_DC1: begin
                    ct_req<=bdec_u_req;
                    if (bdec_u_done) begin
                        if (i_cnt<K-1) begin i_cnt<=i_cnt+1; bdec_u_start<=1; state<=ST_DEC_C1; end
                        else begin i_cnt<=0; decomp_u_start<=1; state<=ST_DECOMP_U; end
                    end
                end

                ST_DECOMP_U: state<=ST_WAIT_DCU;
                ST_WAIT_DCU: begin
                    if (decomp_u_done) begin
                        if (i_cnt<K-1) begin i_cnt<=i_cnt+1; decomp_u_start<=1; state<=ST_DECOMP_U; end
                        else begin i_cnt<=0; bdec_v_start<=1; state<=ST_DEC_C2; end
                    end
                end

                ST_DEC_C2: begin ct_req<=bdec_v_req; state<=ST_WAIT_DC2; end
                ST_WAIT_DC2: begin
                    ct_req<=bdec_v_req;
                    if (bdec_v_done) begin decomp_v_start<=1; state<=ST_DECOMP_V; end
                end

                ST_DECOMP_V: state<=ST_WAIT_DCV;
                ST_WAIT_DCV: begin
                    if (decomp_v_done) begin i_cnt<=0; bdec_dk_start<=1; state<=ST_DEC_DK; end
                end

                ST_DEC_DK: begin dk_req<=bdec_dk_req; state<=ST_WAIT_DDK; end
                ST_WAIT_DDK: begin
                    dk_req<=bdec_dk_req;
                    if (bdec_dk_done) begin
                        if (i_cnt<K-1) begin i_cnt<=i_cnt+1; bdec_dk_start<=1; state<=ST_DEC_DK; end
                        else begin i_cnt<=0; ntt_start<=1; ntt_mode_reg<=0; ntt_ram_sel<=0; state<=ST_NTT_U; end
                    end
                end

                ST_NTT_U: state<=ST_WAIT_NTTU;
                ST_WAIT_NTTU: begin
                    if (ntt_done) begin
                        if (i_cnt<K-1) begin i_cnt<=i_cnt+1; ntt_start<=1; ntt_mode_reg<=0; ntt_ram_sel<=0; state<=ST_NTT_U; end
                        else begin i_cnt<=0; clr_idx<=0; state<=ST_CLR_ACC; end
                    end
                end

                ST_CLR_ACC: begin
                    if (clr_idx==9'd255) begin bmul_start<=1; state<=ST_BASEMUL; end
                    else clr_idx<=clr_idx+1;
                end

                ST_BASEMUL: state<=ST_WAIT_MUL;
                ST_WAIT_MUL: begin
                    if (bmul_done) begin
                        if (i_cnt == 4'd0) begin
                            // i=0 product already wrote ram0[0..255] (initial w accumulator)
                            if (K == 1) begin
                                ntt_start<=1; ntt_mode_reg<=1; ntt_ram_sel<=1; state<=ST_INTT_W;
                            end else begin
                                i_cnt<=i_cnt+1; bmul_start<=1; state<=ST_BASEMUL;
                            end
                        end else begin
                            arith_mode<=2'b00; arith_start<=1; state<=ST_ADD_MUL;
                        end
                    end
                end
                ST_ADD_MUL: state<=ST_WAIT_ADD;
                ST_WAIT_ADD: begin
                    if (arith_done) begin
                        if (i_cnt<K-1) begin
                            i_cnt<=i_cnt+1; bmul_start<=1; state<=ST_BASEMUL;
                        end else begin
                            ntt_start<=1; ntt_mode_reg<=1; ntt_ram_sel<=1; state<=ST_INTT_W;
                        end
                    end
                end

                ST_INTT_W: state<=ST_WAIT_INTT;
                ST_WAIT_INTT: begin
                    if (ntt_done) begin
                        arith_mode<=2'b01; arith_start<=1; state<=ST_SUB_V;
                    end
                end

                ST_SUB_V: state<=ST_WAIT_SUB;
                ST_WAIT_SUB: begin
                    if (arith_done) begin comp_m_start<=1; state<=ST_COMP_MSG; end
                end

                ST_COMP_MSG: state<=ST_WAIT_COMP;
                ST_WAIT_COMP: begin
                    if (comp_m_done) begin enc_m_start<=1; state<=ST_ENC_MSG; end
                end

                ST_ENC_MSG: state<=ST_WAIT_ENC;
                ST_WAIT_ENC: begin
                    if (enc_m_byte_valid)
                        msg_out[enc_m_byte_addr*8 +: 8] <= enc_m_byte_data;
                    if (enc_m_done) state<=ST_DONE;
                end

                ST_DONE: begin msg_valid<=1; done<=1; busy<=0; state<=ST_IDLE; end
                default: state<=ST_IDLE;
            endcase
        end
    end

endmodule
