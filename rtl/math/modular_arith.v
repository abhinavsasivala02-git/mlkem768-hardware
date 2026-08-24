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
// Modular Arithmetic: Addition and Subtraction mod q = 3329
// All inputs/outputs are unsigned in [0, q-1]
//============================================================================
module modular_arith (
    input  wire [11:0] a,
    input  wire [11:0] b,
    input  wire        op,    // 0 = add, 1 = subtract
    output wire [11:0] result
);

    `include "mlkem_params.vh"

    wire [12:0] sum;
    wire [12:0] diff;
    wire [11:0] add_result;
    wire [11:0] sub_result;

    // --- Addition: (a + b) mod q ---
    assign sum = {1'b0, a} + {1'b0, b};
    assign add_result = (sum >= {1'b0, MLKEM_Q[11:0]}) ? sum[11:0] - MLKEM_Q[11:0] : sum[11:0];

    // --- Subtraction: (a - b + q) mod q ---
    assign diff = {1'b0, a} - {1'b0, b};
    assign sub_result = diff[12] ? diff[11:0] + MLKEM_Q[11:0] : diff[11:0];  // if borrow, add q

    // --- Output mux ---
    assign result = op ? sub_result : add_result;

endmodule
