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

    // Internal signals
    (* use_dsp = "no" *) wire signed [31:0] product;
    wire        [11:0] mont_result;
    wire signed [15:0] t_mont;

    // Intermediate butterfly values
    wire signed [15:0] ct_a, ct_b;
    wire signed [15:0] gs_a, gs_b;
    wire signed [15:0] gs_diff;
    (* use_dsp = "no" *) wire signed [31:0] gs_product;
    wire        [11:0] gs_mont_result;
    wire signed [15:0] gs_t_mont;
    wire [11:0] ct_a_barrett, ct_b_barrett;
    wire [11:0] gs_a_barrett;

    // --- CT butterfly: t = mont_reduce(zeta * b); a' = a+t; b' = a-t ---
    assign product = zeta * b_in;

    montgomery_reduce u_mont_ct (
        .a      (product),
        .result (mont_result)
    );

    assign t_mont = $signed({1'b0, mont_result});
    assign ct_a   = a_in + t_mont;
    assign ct_b   = a_in - t_mont;

    // --- GS butterfly: a' = a+b; diff = b-a; b' = mont_reduce(zeta * diff) ---
    assign gs_diff    = b_in - a_in;
    assign gs_a       = a_in + b_in;
    assign gs_product = zeta * gs_diff;

    montgomery_reduce u_mont_gs (
        .a      (gs_product),
        .result (gs_mont_result)
    );

    assign gs_t_mont = $signed({1'b0, gs_mont_result});

    // --- Registered output ---
    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            a_out     <= 16'sd0;
            b_out     <= 16'sd0;
            valid_out <= 1'b0;
        end else begin
            valid_out <= valid_in;
            if (valid_in) begin
                if (mode == 1'b0) begin
                    // Cooley-Tukey (forward)
                    a_out <= {4'b0, ct_a_barrett};
                    b_out <= {4'b0, ct_b_barrett};
                end else begin
                    // Gentleman-Sande (inverse)
                    a_out <= {4'b0, gs_a_barrett};
                    b_out <= {4'b0, gs_t_mont};
                end
            end
        end
    end

    // Barrett-reduce CT outputs to [0, q-1] so values fit the 12-bit RAM
    barrett_reduce u_barrett_ct_a (.a(ct_a), .result(ct_a_barrett));
    barrett_reduce u_barrett_ct_b (.a(ct_b), .result(ct_b_barrett));
    barrett_reduce u_barrett_gs_a (.a(gs_a), .result(gs_a_barrett));

endmodule