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
// Keccak Round — Single round of the Keccak-f[1600] permutation
// Implements all five steps: θ, ρ, π, χ, ι
//
// State: 5×5 array of 64-bit lanes = 1600 bits total
// Input/output as flat 1600-bit vector: state[x][y] = bits[64*(5*y+x) +: 64]
//============================================================================
module keccak_round (
    input  wire [1599:0] state_in,
    input  wire [63:0]   round_const,   // ι round constant
    output wire [1599:0] state_out
);

    wire [63:0] A [0:4][0:4];   // input lanes
    reg  [63:0] E [0:4][0:4];   // output lanes (after all steps)

    wire [63:0] C [0:4];        // θ column parities
    wire [63:0] D [0:4];        // θ effect
    reg  [63:0] B [0:4][0:4];   // after θ+ρ+π

    integer xi, yi;

    genvar gx, gy;
    generate
        for (gy = 0; gy < 5; gy = gy + 1) begin : gen_unpack_y
            for (gx = 0; gx < 5; gx = gx + 1) begin : gen_unpack_x
                assign A[gx][gy] = state_in[64*(5*gy+gx) +: 64];
            end
        end
    endgenerate

    assign C[0] = A[0][0] ^ A[0][1] ^ A[0][2] ^ A[0][3] ^ A[0][4];
    assign C[1] = A[1][0] ^ A[1][1] ^ A[1][2] ^ A[1][3] ^ A[1][4];
    assign C[2] = A[2][0] ^ A[2][1] ^ A[2][2] ^ A[2][3] ^ A[2][4];
    assign C[3] = A[3][0] ^ A[3][1] ^ A[3][2] ^ A[3][3] ^ A[3][4];
    assign C[4] = A[4][0] ^ A[4][1] ^ A[4][2] ^ A[4][3] ^ A[4][4];

    assign D[0] = C[4] ^ {C[1][62:0], C[1][63]};
    assign D[1] = C[0] ^ {C[2][62:0], C[2][63]};
    assign D[2] = C[1] ^ {C[3][62:0], C[3][63]};
    assign D[3] = C[2] ^ {C[4][62:0], C[4][63]};
    assign D[4] = C[3] ^ {C[0][62:0], C[0][63]};

    function [63:0] rotl;
        input [63:0] val;
        input [5:0]  amt;
        begin
            rotl = (val << amt) | (val >> (6'd64 - amt));
        end
    endfunction

    always @(*) begin

        B[0][0] = (A[0][0] ^ D[0]);
        B[0][2] = rotl(A[1][0] ^ D[1], 6'd1);
        B[0][4] = rotl(A[2][0] ^ D[2], 6'd62);
        B[0][1] = rotl(A[3][0] ^ D[3], 6'd28);
        B[0][3] = rotl(A[4][0] ^ D[4], 6'd27);

        B[1][3] = rotl(A[0][1] ^ D[0], 6'd36);
        B[1][0] = rotl(A[1][1] ^ D[1], 6'd44);
        B[1][2] = rotl(A[2][1] ^ D[2], 6'd6);
        B[1][4] = rotl(A[3][1] ^ D[3], 6'd55);
        B[1][1] = rotl(A[4][1] ^ D[4], 6'd20);

        B[2][1] = rotl(A[0][2] ^ D[0], 6'd3);
        B[2][3] = rotl(A[1][2] ^ D[1], 6'd10);
        B[2][0] = rotl(A[2][2] ^ D[2], 6'd43);
        B[2][2] = rotl(A[3][2] ^ D[3], 6'd25);
        B[2][4] = rotl(A[4][2] ^ D[4], 6'd39);

        B[3][4] = rotl(A[0][3] ^ D[0], 6'd41);
        B[3][1] = rotl(A[1][3] ^ D[1], 6'd45);
        B[3][3] = rotl(A[2][3] ^ D[2], 6'd15);
        B[3][0] = rotl(A[3][3] ^ D[3], 6'd21);
        B[3][2] = rotl(A[4][3] ^ D[4], 6'd8);

        B[4][2] = rotl(A[0][4] ^ D[0], 6'd18);
        B[4][4] = rotl(A[1][4] ^ D[1], 6'd2);
        B[4][1] = rotl(A[2][4] ^ D[2], 6'd61);
        B[4][3] = rotl(A[3][4] ^ D[3], 6'd56);
        B[4][0] = rotl(A[4][4] ^ D[4], 6'd14);
    end

    always @(*) begin
        for (yi = 0; yi < 5; yi = yi + 1) begin
            E[0][yi] = B[0][yi] ^ (~B[1][yi] & B[2][yi]);
            E[1][yi] = B[1][yi] ^ (~B[2][yi] & B[3][yi]);
            E[2][yi] = B[2][yi] ^ (~B[3][yi] & B[4][yi]);
            E[3][yi] = B[3][yi] ^ (~B[4][yi] & B[0][yi]);
            E[4][yi] = B[4][yi] ^ (~B[0][yi] & B[1][yi]);
        end
    end

    generate
        for (gy = 0; gy < 5; gy = gy + 1) begin : gen_pack_y
            for (gx = 0; gx < 5; gx = gx + 1) begin : gen_pack_x
                if (gx == 0 && gy == 0) begin : gen_iota
                    assign state_out[64*(5*gy+gx) +: 64] = E[gx][gy] ^ round_const;
                end else begin : gen_no_iota
                    assign state_out[64*(5*gy+gx) +: 64] = E[gx][gy];
                end
            end
        end
    endgenerate

endmodule
