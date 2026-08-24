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
// Montgomery Reduction
// Input:  signed 32-bit value a (product of two 16-bit values)
// Output: a * R^{-1} mod q, where R = 2^16
//
// Algorithm:
//   t = (int16_t)(a * QINV)       // low 16 bits
//   r = (a - t * q) >> 16
//   if (r < 0) r += q
//   if (r >= q) r -= q
//
// QINV = 62209 such that q * QINV = 1 (mod 2^16)
// Then (a - ((a*QINV) mod 2^16) * q) is divisible by 2^16.
//============================================================================
module montgomery_reduce (
    input  wire signed [31:0] a,
    output wire        [11:0] result
);

    // ---- Parameters (inlined from mlkem_params.vh) ----
    localparam MLKEM_Q    = 13'd3329;
    localparam MLKEM_QINV = 16'd62209;
    // ---------------------------------------------------
    (* use_dsp = "no" *) wire signed [15:0] t;
    (* use_dsp = "no" *) wire signed [31:0] u;
    wire signed [15:0] r;
    wire signed [15:0] r_corrected;

    // Step 1: t = (int16)(a * QINV)  - keep only low 16 bits
    assign t = a[15:0] * MLKEM_QINV;

    // Step 2: u = t * q  (sign-extend t, multiply by q)
    assign u = $signed(t) * $signed({1'b0, MLKEM_Q[12:0]});

    // Step 3: r = (a - u) >> 16  - exact division by R
    assign r = (a - u) >>> 16;

    // Step 4: Conditional correction to [0, q-1]
    assign r_corrected = (r < 0)                                 ? (r + $signed({1'b0, MLKEM_Q[12:0]})) :
                         (r >= $signed({1'b0, MLKEM_Q[12:0]}))   ? (r - $signed({1'b0, MLKEM_Q[12:0]})) :
                         r;

    assign result = r_corrected[11:0];

endmodule