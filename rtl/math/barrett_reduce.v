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
// Barrett Reduction mod q = 3329
// Input:  signed 16-bit value a (may be in [-q, 2q) range)
// Output: a mod q in [0, q-1]
//
// Algorithm:
//   t = round(a * v / 2^26)  where v = 20159
//   r = a - t * q
//   if (r >= q) r -= q
//   if (r < 0)  r += q
//============================================================================
module barrett_reduce (
    input  wire signed [15:0] a,
    output wire        [11:0] result
);

    // ---- Parameters (inlined from mlkem_params.vh) ----
    localparam MLKEM_Q         = 13'd3329;
    localparam MLKEM_BARRETT_V = 16'd20159;
    localparam MLKEM_BARRETT_S = 5'd26;
    // ---------------------------------------------------
    // Internal wires
    (* use_dsp = "no" *) wire signed [31:0] product;
    (* use_dsp = "no" *) wire signed [15:0] t;
    wire signed [15:0] r;
    wire signed [15:0] r_corrected;

    // Step 1: t = ((a * v) + 2^25) >> 26
    assign product = $signed(a) * $signed({1'b0, MLKEM_BARRETT_V});
    assign t       = (product + 32'sd33554432) >>> 26;  // 2^25 = 33554432

    // Step 2: r = a - t * q
    assign r = a - t * $signed({1'b0, MLKEM_Q[12:0]});

    // Step 3: Conditional correction to [0, q-1]
    assign r_corrected = (r >= $signed({1'b0, MLKEM_Q[12:0]})) ? (r - $signed({1'b0, MLKEM_Q[12:0]})) :
                         (r < 0)                                 ? (r + $signed({1'b0, MLKEM_Q[12:0]})) :
                         r;

    assign result = r_corrected[11:0];

endmodule