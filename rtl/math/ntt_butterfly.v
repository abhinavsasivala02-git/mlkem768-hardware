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
// NTT Butterfly Unit
// Supports both Cooley-Tukey (forward NTT) and Gentleman-Sande (inverse NTT)
//
// CT butterfly:  a' = a + zeta*b,  b' = a - zeta*b
// GS butterfly:  a' = a + b,       b' = zeta*(a - b)
//
// Multiplication by zeta uses Montgomery reduction.
//============================================================================
module ntt_butterfly (
    input  wire              clk,
    input  wire              rst_n,
    input  wire              valid_in,
    input  wire              mode,        // 0 = CT (forward), 1 = GS (inverse)
    input  wire signed [15:0] a_in,
    input  wire signed [15:0] b_in,
    input  wire signed [15:0] zeta,
    output reg  signed [15:0] a_out,
    output reg  signed [15:0] b_out,
    output reg               valid_out
);

    wire signed [31:0] product;
    wire        [11:0] mont_result;
    wire signed [15:0] t_mont;

    wire signed [15:0] gs_diff;
    wire signed [31:0] gs_product;
    wire        [11:0] gs_mont_result;
    wire signed [15:0] gs_t_mont;

    assign product = zeta * b_in;

    montgomery_reduce u_mont_ct (
        .a      (product),
        .result (mont_result)
    );

    assign t_mont = $signed({1'b0, mont_result});

    assign gs_diff    = b_in - a_in;
    assign gs_product = zeta * gs_diff;

    montgomery_reduce u_mont_gs (
        .a      (gs_product),
        .result (gs_mont_result)
    );

    assign gs_t_mont = $signed({1'b0, gs_mont_result});

    reg signed [15:0] s1_a, s1_b, s1_t;
    reg               s1_mode, s1_valid;

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            s1_a     <= 16'sd0;
            s1_b     <= 16'sd0;
            s1_t     <= 16'sd0;
            s1_mode  <= 1'b0;
            s1_valid <= 1'b0;
        end else begin
            s1_valid <= valid_in;
            if (valid_in) begin
                s1_a    <= a_in;
                s1_b    <= b_in;
                s1_mode <= mode;
                s1_t    <= (mode == 1'b0) ? t_mont : gs_t_mont;
            end
        end
    end

    wire signed [15:0] p_ct_a = s1_a + s1_t;
    wire signed [15:0] p_ct_b = s1_a - s1_t;
    wire signed [15:0] p_gs_a = s1_a + s1_b;
    wire [11:0] p_ct_a_barrett, p_ct_b_barrett, p_gs_a_barrett;

    barrett_reduce u_barrett_ct_a (.a(p_ct_a), .result(p_ct_a_barrett));
    barrett_reduce u_barrett_ct_b (.a(p_ct_b), .result(p_ct_b_barrett));
    barrett_reduce u_barrett_gs_a (.a(p_gs_a), .result(p_gs_a_barrett));

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            a_out     <= 16'sd0;
            b_out     <= 16'sd0;
            valid_out <= 1'b0;
        end else begin
            valid_out <= s1_valid;
            if (s1_valid) begin
                if (s1_mode == 1'b0) begin
                    a_out <= {4'b0, p_ct_a_barrett};
                    b_out <= {4'b0, p_ct_b_barrett};
                end else begin
                    a_out <= {4'b0, p_gs_a_barrett};
                    b_out <= s1_t;
                end
            end
        end
    end

endmodule