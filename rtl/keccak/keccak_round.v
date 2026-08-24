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

    // Lane access macros — lane(x,y) = state[64*(5*y+x) +: 64]
    // We use wires for readability
    wire [63:0] A [0:4][0:4];   // input lanes
    reg  [63:0] E [0:4][0:4];   // output lanes (after all steps)

    // Intermediate arrays
    wire [63:0] C [0:4];        // θ column parities
    wire [63:0] D [0:4];        // θ effect
    reg  [63:0] B [0:4][0:4];   // after θ+ρ+π

    // ρ rotation offsets (FIPS 202, Table 2)
    // rot[x][y] = rotation amount for lane (x,y)
    // Stored as flattened function below

    integer xi, yi;

    // --- Unpack input state into lanes ---
    genvar gx, gy;
    generate
        for (gy = 0; gy < 5; gy = gy + 1) begin : gen_unpack_y
            for (gx = 0; gx < 5; gx = gx + 1) begin : gen_unpack_x
                assign A[gx][gy] = state_in[64*(5*gy+gx) +: 64];
            end
        end
    endgenerate

    // --- θ step: Column parity ---
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

    // --- θ + ρ + π combined ---
    // Apply θ (XOR with D), then ρ (rotate), then π (permute position)
    // π: B[y][2x+3y mod 5] = rot(A[x][y] ^ D[x], r[x][y])
    // Rotation function
    function [63:0] rotl;
        input [63:0] val;
        input [5:0]  amt;
        begin
            rotl = (val << amt) | (val >> (6'd64 - amt));
        end
    endfunction

    always @(*) begin
        // θ applied: A'[x][y] = A[x][y] ^ D[x]
        // Then ρ rotation and π permutation:
        // B[y][(2*x+3*y) mod 5] = ROT(A'[x][y], r[x][y])

        // (x=0,y=0): r=0,  π→B[0][0]
        B[0][0] = (A[0][0] ^ D[0]);
        // (x=1,y=0): r=1,  π→B[0][2]
        B[0][2] = rotl(A[1][0] ^ D[1], 6'd1);
        // (x=2,y=0): r=62, π→B[0][4]
        B[0][4] = rotl(A[2][0] ^ D[2], 6'd62);
        // (x=3,y=0): r=28, π→B[0][1]
        B[0][1] = rotl(A[3][0] ^ D[3], 6'd28);
        // (x=4,y=0): r=27, π→B[0][3]
        B[0][3] = rotl(A[4][0] ^ D[4], 6'd27);

        // (x=0,y=1): r=36, π→B[1][3]
        B[1][3] = rotl(A[0][1] ^ D[0], 6'd36);
        // (x=1,y=1): r=44, π→B[1][0]
        B[1][0] = rotl(A[1][1] ^ D[1], 6'd44);
        // (x=2,y=1): r=6,  π→B[1][2]
        B[1][2] = rotl(A[2][1] ^ D[2], 6'd6);
        // (x=3,y=1): r=55, π→B[1][4]
        B[1][4] = rotl(A[3][1] ^ D[3], 6'd55);
        // (x=4,y=1): r=20, π→B[1][1]
        B[1][1] = rotl(A[4][1] ^ D[4], 6'd20);

        // (x=0,y=2): r=3,  π→B[2][1]
        B[2][1] = rotl(A[0][2] ^ D[0], 6'd3);
        // (x=1,y=2): r=10, π→B[2][3]
        B[2][3] = rotl(A[1][2] ^ D[1], 6'd10);
        // (x=2,y=2): r=43, π→B[2][0]
        B[2][0] = rotl(A[2][2] ^ D[2], 6'd43);
        // (x=3,y=2): r=25, π→B[2][2]
        B[2][2] = rotl(A[3][2] ^ D[3], 6'd25);
        // (x=4,y=2): r=39, π→B[2][4]
        B[2][4] = rotl(A[4][2] ^ D[4], 6'd39);

        // (x=0,y=3): r=41, π→B[3][4]
        B[3][4] = rotl(A[0][3] ^ D[0], 6'd41);
        // (x=1,y=3): r=45, π→B[3][1]
        B[3][1] = rotl(A[1][3] ^ D[1], 6'd45);
        // (x=2,y=3): r=15, π→B[3][3]
        B[3][3] = rotl(A[2][3] ^ D[2], 6'd15);
        // (x=3,y=3): r=21, π→B[3][0]
        B[3][0] = rotl(A[3][3] ^ D[3], 6'd21);
        // (x=4,y=3): r=8,  π→B[3][2]
        B[3][2] = rotl(A[4][3] ^ D[4], 6'd8);

        // (x=0,y=4): r=18, π→B[4][2]
        B[4][2] = rotl(A[0][4] ^ D[0], 6'd18);
        // (x=1,y=4): r=2,  π→B[4][4]
        B[4][4] = rotl(A[1][4] ^ D[1], 6'd2);
        // (x=2,y=4): r=61, π→B[4][1]
        B[4][1] = rotl(A[2][4] ^ D[2], 6'd61);
        // (x=3,y=4): r=56, π→B[4][3]
        B[4][3] = rotl(A[3][4] ^ D[3], 6'd56);
        // (x=4,y=4): r=14, π→B[4][0]
        B[4][0] = rotl(A[4][4] ^ D[4], 6'd14);
    end

    // --- χ step: Non-linear ---
    // E[x][y] = B[x][y] ^ (~B[x+1 mod 5][y] & B[x+2 mod 5][y])
    always @(*) begin
        for (yi = 0; yi < 5; yi = yi + 1) begin
            E[0][yi] = B[0][yi] ^ (~B[1][yi] & B[2][yi]);
            E[1][yi] = B[1][yi] ^ (~B[2][yi] & B[3][yi]);
            E[2][yi] = B[2][yi] ^ (~B[3][yi] & B[4][yi]);
            E[3][yi] = B[3][yi] ^ (~B[4][yi] & B[0][yi]);
            E[4][yi] = B[4][yi] ^ (~B[0][yi] & B[1][yi]);
        end
    end

    // --- ι step: XOR round constant into lane (0,0) ---
    // Pack output state
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
