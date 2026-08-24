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
// Polynomial Base Multiplication in NTT Domain - Algorithm 11 of FIPS 203
// Multiplies two NTT-domain polynomials coefficient-pair-wise
//
// In the NTT domain, a 256-coeff polynomial becomes 128 pairs (a0,a1).
// BaseMul for pair i:
//   c0 = a0*b0 + a1*b1*gamma_i
//   c1 = a0*b1 + a1*b0
// where gamma_i = zeta^(2*BitRev7(i)+1) is the pair twiddle factor.
//
// All multiplications use Montgomery reduction.
//============================================================================
module poly_basemul (
    input  wire        clk,
    input  wire        rst_n,
    input  wire        start,
    output reg         done,
    output reg         busy,

    // RAM for polynomial A (NTT domain) - read-only
    output reg  [7:0]  a_addr,
    input  wire [11:0] a_rdata,

    // RAM for polynomial B (NTT domain) - read-only
    output reg  [7:0]  b_addr,
    input  wire [11:0] b_rdata,

    // RAM for result C - write-only
    output reg         c_wen,
    output reg  [7:0]  c_addr,
    output reg  [11:0] c_wdata
);

    // FSM states
    localparam S_IDLE    = 4'd0;
    localparam S_RD_A0B0 = 4'd1;
    localparam S_WT_A0B0 = 4'd2;
    localparam S_LAT_A0  = 4'd14;
    localparam S_RD_A1B1 = 4'd3;
    localparam S_WT_A1B1 = 4'd4;
    localparam S_LAT_A1  = 4'd13;
    localparam S_COMP_C0 = 4'd5;
    localparam S_COMP_C1 = 4'd6;
    localparam S_CONV_C0 = 4'd7;
    localparam S_CONV_C1 = 4'd8;
    localparam S_WR_C0   = 4'd9;
    localparam S_WR_C1   = 4'd10;
    localparam S_NEXT    = 4'd11;
    localparam S_DONE    = 4'd12;

    reg [3:0] state, next_state;

    // Pair index (0..127)
    reg [6:0] pair_idx;

    // Latched coefficient values
    reg signed [15:0] a0, a1, b0, b1;

    // Zeta value for gamma (pair twiddle)
    wire signed [15:0] gamma_val;
    reg  [6:0] gamma_addr;

    // Montgomery products
    (* use_dsp = "no" *) wire signed [31:0] prod_a0b0, prod_a1b1, prod_a0b1, prod_a1b0;
    (* use_dsp = "no" *) wire signed [31:0] prod_a1b1g;
    (* use_dsp = "no" *) wire signed [31:0] prod_c0_conv, prod_c1_conv;
    wire [11:0] m_a0b0, m_a1b1g, m_a0b1, m_a1b0;
    wire [11:0] m_a1b1_raw;
    wire [11:0] m_c0, m_c1;

    // Result accumulators
    reg signed [15:0] c0_val, c1_val;

    // Gamma ROM - uses the same zeta ROM with offset addressing
    // gamma_i = zetas[64 + (i>>1)] for the basemul twiddles (synchronous BRAM)
    // Sign flip: gamma[p] = (-1)^p * zetas[64 + (p>>1)]
    wire signed [15:0] gamma_sign;
    assign gamma_sign = pair_idx[0] ? -gamma_val : gamma_val;

    ntt_rom u_gamma_rom (
        .clk  (clk),
        .addr (gamma_addr),
        .zeta (gamma_val)
    );

    // Montgomery multiplication instances
    assign prod_a0b0 = a0 * b0;
    assign prod_a1b1 = a1 * b1;
    assign prod_a0b1 = a0 * b1;
    assign prod_a1b0 = a1 * b0;
    assign prod_a1b1g = $signed({4'b0, m_a1b1_raw}) * gamma_sign;
    // Convert Montgomery-domain sum back to plain: c = mont(s * R^2)
    // since R^2 mod q = 1353 and mont(x) = x*R^-1 mod q  =>  c = s*R mod q
    assign prod_c0_conv = $signed(c0_val) * 16'sd1353;
    assign prod_c1_conv = $signed(c1_val) * 16'sd1353;

    montgomery_reduce u_mont_a0b0  (.a(prod_a0b0),  .result(m_a0b0));
    montgomery_reduce u_mont_a1b1  (.a(prod_a1b1),  .result(m_a1b1_raw));
    montgomery_reduce u_mont_a1b1g (.a(prod_a1b1g), .result(m_a1b1g));
    montgomery_reduce u_mont_a0b1  (.a(prod_a0b1),  .result(m_a0b1));
    montgomery_reduce u_mont_a1b0  (.a(prod_a1b0),  .result(m_a1b0));
    montgomery_reduce u_mont_c0    (.a(prod_c0_conv), .result(m_c0));
    montgomery_reduce u_mont_c1    (.a(prod_c1_conv), .result(m_c1));

    // FSM sequential
    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) state <= S_IDLE;
        else        state <= next_state;
    end

    // FSM combinational
    always @(*) begin
        next_state = state;
        case (state)
            S_IDLE:    if (start) next_state = S_RD_A0B0;
            S_RD_A0B0: next_state = S_WT_A0B0;
            S_WT_A0B0: next_state = S_LAT_A0;
            S_LAT_A0:  next_state = S_RD_A1B1;
            S_RD_A1B1: next_state = S_WT_A1B1;
            S_WT_A1B1: next_state = S_LAT_A1;
            S_LAT_A1:  next_state = S_COMP_C0;
            S_COMP_C0: next_state = S_COMP_C1;
            S_COMP_C1: next_state = S_CONV_C0;
            S_CONV_C0: next_state = S_CONV_C1;
            S_CONV_C1: next_state = S_WR_C0;
            S_WR_C0:   next_state = S_WR_C1;
            S_WR_C1:   next_state = S_NEXT;
            S_NEXT:    next_state = (pair_idx < 7'd127) ? S_RD_A0B0 : S_DONE;
            S_DONE:    next_state = S_IDLE;
            default:   next_state = S_IDLE;
        endcase
    end

    // Datapath
    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            done       <= 1'b0;
            busy       <= 1'b0;
            c_wen      <= 1'b0;
            a_addr     <= 8'd0;
            b_addr     <= 8'd0;
            c_addr     <= 8'd0;
            c_wdata    <= 12'd0;
            pair_idx   <= 7'd0;
            a0 <= 16'sd0; a1 <= 16'sd0;
            b0 <= 16'sd0; b1 <= 16'sd0;
            c0_val <= 16'sd0; c1_val <= 16'sd0;
            gamma_addr <= 7'd0;
        end else begin
            c_wen <= 1'b0;
            done  <= 1'b0;

            case (state)
                S_IDLE: begin
                    busy <= 1'b0;
                    if (start) begin
                        busy     <= 1'b1;
                        pair_idx <= 7'd0;
                    end
                end

                S_RD_A0B0: begin
                    a_addr <= {pair_idx, 1'b0};  // even index
                    b_addr <= {pair_idx, 1'b0};
                    gamma_addr <= 7'd64 + {6'd0, pair_idx[6:1]};
                end

                S_WT_A0B0: begin
                    // Wait for synchronous read latency on even-index data
                end

                S_LAT_A0: begin
                    a0 <= $signed({4'b0, a_rdata});
                    b0 <= $signed({4'b0, b_rdata});
                end

                S_RD_A1B1: begin
                    a_addr <= {pair_idx, 1'b1};  // odd index
                    b_addr <= {pair_idx, 1'b1};
                end

                S_WT_A1B1: begin
                    // Wait for synchronous read latency on odd-index data
                end

                S_LAT_A1: begin
                    a1 <= $signed({4'b0, a_rdata});
                    b1 <= $signed({4'b0, b_rdata});
                end

                S_COMP_C0: begin
                    // c0 = mont(a0*b0) + mont(mont(a1*b1) * gamma)
                    c0_val <= $signed({1'b0, m_a0b0}) + $signed({1'b0, m_a1b1g});
                end

                S_COMP_C1: begin
                    // c1 = mont(a0*b1) + mont(a1*b0)
                    c1_val <= $signed({1'b0, m_a0b1}) + $signed({1'b0, m_a1b0});
                end

                S_CONV_C0: begin
                    // Convert Montgomery-domain sum back to plain
                    c0_val <= $signed({4'b0, m_c0});
                end

                S_CONV_C1: begin
                    // Convert Montgomery-domain sum back to plain
                    c1_val <= $signed({4'b0, m_c1});
                end

                S_WR_C0: begin
                    c_wen   <= 1'b1;
                    c_addr  <= {pair_idx, 1'b0};
                    c_wdata <= c0_val[11:0];
                end

                S_WR_C1: begin
                    c_wen   <= 1'b1;
                    c_addr  <= {pair_idx, 1'b1};
                    c_wdata <= c1_val[11:0];
                end

                S_NEXT: begin
                    pair_idx <= pair_idx + 7'd1;
                end

                S_DONE: begin
                    done <= 1'b1;
                    busy <= 1'b0;
                end
            endcase
        end
    end

endmodule