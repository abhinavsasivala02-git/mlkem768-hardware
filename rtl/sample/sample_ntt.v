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
// SampleNTT — Algorithm 7 of FIPS 203
// Rejection sampling from SHAKE-128 output to generate NTT-domain polynomial
// Used to generate matrix Â elements from seed ρ and indices (i,j)
//
// Process:
//   1. Absorb seed ρ (32 bytes) || j || i into SHAKE-128
//   2. Squeeze 3-byte chunks, compute d1 and d2:
//      d1 = B[0] + 256*(B[1] mod 16)
//      d2 = floor(B[1]/16) + 16*B[2]
//   3. Accept d1 if d1 < q; accept d2 if d2 < q
//   4. Continue until 256 coefficients sampled
//============================================================================
module sample_ntt (
    input  wire        clk,
    input  wire        rst_n,
    input  wire        start,
    input  wire [255:0] seed,       // 32-byte seed ρ
    input  wire [7:0]  idx_i,       // Row index
    input  wire [7:0]  idx_j,       // Column index
    output reg         done,
    output reg         busy,

    // Output polynomial RAM — write interface
    output reg         poly_wen,
    output reg  [7:0]  poly_addr,
    output reg  [11:0] poly_wdata
);

    `include "mlkem_params.vh"

    // FSM states
    localparam S_IDLE       = 4'd0;
    localparam S_ABSORB_SEED = 4'd1;
    localparam S_ABSORB_IDX  = 4'd2;
    localparam S_WAIT_PERM   = 4'd3;
    localparam S_SQUEEZE_B0  = 4'd4;
    localparam S_SQUEEZE_B1  = 4'd5;
    localparam S_SQUEEZE_B2  = 4'd6;
    localparam S_CHECK      = 4'd7;
    localparam S_WRITE      = 4'd8;
    localparam S_DONE       = 4'd9;

    reg [3:0] state;

    // SHAKE-128 interface
    reg          shake_start;
    reg          shake_absorb_valid;
    reg  [7:0]   shake_absorb_data;
    wire         shake_absorb_ready;
    reg          shake_absorb_last;
    reg          shake_squeeze_req;
    wire         shake_squeeze_valid;
    wire [7:0]   shake_squeeze_data;
    wire         shake_busy;

    // Byte counter for seed absorption
    reg [5:0] seed_byte_cnt;   // 0..33

    // Squeezed bytes
    reg [7:0] b0, b1, b2;

    // Candidate values
    wire [11:0] d1, d2;
    assign d1 = {b1[3:0], b0};               // b0 + 256*(b1 mod 16)
    assign d2 = {b2, b1[7:4]};               // floor(b1/16) + 16*b2

    // Coefficient counter
    reg [8:0] coeff_cnt;     // 0..255

    // Sub-state for checking d1 then d2
    reg check_d2;

    // SHAKE-128 instance
    shake128 u_shake128 (
        .clk           (clk),
        .rst_n         (rst_n),
        .start         (shake_start),
        .absorb_valid  (shake_absorb_valid),
        .absorb_data   (shake_absorb_data),
        .absorb_ready  (shake_absorb_ready),
        .absorb_last   (shake_absorb_last),
        .squeeze_req   (shake_squeeze_req),
        .squeeze_valid (shake_squeeze_valid),
        .squeeze_data  (shake_squeeze_data),
        .busy          (shake_busy)
    );

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            state              <= S_IDLE;
            done               <= 1'b0;
            busy               <= 1'b0;
            poly_wen           <= 1'b0;
            poly_addr          <= 8'd0;
            poly_wdata         <= 12'd0;
            shake_start        <= 1'b0;
            shake_absorb_valid <= 1'b0;
            shake_absorb_data  <= 8'd0;
            shake_absorb_last  <= 1'b0;
            shake_squeeze_req  <= 1'b0;
            seed_byte_cnt      <= 6'd0;
            b0 <= 8'd0; b1 <= 8'd0; b2 <= 8'd0;
            coeff_cnt          <= 9'd0;
            check_d2           <= 1'b0;
        end else begin
            shake_start        <= 1'b0;
            shake_absorb_valid <= 1'b0;
            shake_absorb_last  <= 1'b0;
            shake_squeeze_req  <= 1'b0;
            poly_wen           <= 1'b0;
            done               <= 1'b0;

            case (state)
                S_IDLE: begin
                    busy <= 1'b0;
                    if (start) begin
                        busy          <= 1'b1;
                        shake_start   <= 1'b1;
                        seed_byte_cnt <= 6'd0;
                        coeff_cnt     <= 9'd0;
                        state         <= S_ABSORB_SEED;
                    end
                end

                S_ABSORB_SEED: begin
                    if (shake_absorb_ready) begin
                        shake_absorb_valid <= 1'b1;
                        shake_absorb_data  <= seed[seed_byte_cnt*8 +: 8];
                        if (seed_byte_cnt == 6'd31) begin
                            state         <= S_ABSORB_IDX;
                            seed_byte_cnt <= 6'd0;
                        end else begin
                            seed_byte_cnt <= seed_byte_cnt + 6'd1;
                        end
                    end
                end

                S_ABSORB_IDX: begin
                    if (shake_absorb_ready) begin
                        shake_absorb_valid <= 1'b1;
                        if (seed_byte_cnt == 6'd0) begin
                            shake_absorb_data <= idx_j;
                            seed_byte_cnt     <= 6'd1;
                        end else begin
                            shake_absorb_data <= idx_i;
                            shake_absorb_last <= 1'b1;
                            state             <= S_WAIT_PERM;
                        end
                    end
                end

                S_WAIT_PERM: begin
                    // Wait for permutation to complete, then start squeezing.
                    // Capture byte 0 here so the engine's first valid pulse is
                    // not wasted (engine drops valid when req is low).
                    if (shake_squeeze_valid) begin
                        b0                <= shake_squeeze_data;
                        shake_squeeze_req <= 1'b1;
                        state             <= S_SQUEEZE_B1;
                    end
                end

                S_SQUEEZE_B0: begin
                    if (shake_squeeze_valid) begin
                        b0                <= shake_squeeze_data;
                        shake_squeeze_req <= 1'b1;
                        state             <= S_SQUEEZE_B1;
                    end
                end

                S_SQUEEZE_B1: begin
                    if (shake_squeeze_valid) begin
                        b1                <= shake_squeeze_data;
                        shake_squeeze_req <= 1'b1;
                        state             <= S_SQUEEZE_B2;
                    end
                end

                S_SQUEEZE_B2: begin
                    if (shake_squeeze_valid) begin
                        b2       <= shake_squeeze_data;
                        check_d2 <= 1'b0;
                        state    <= S_CHECK;
                    end
                end

                S_CHECK: begin
                    if (!check_d2) begin
                        // Check d1
                        if (d1 < MLKEM_Q[11:0] && coeff_cnt < 9'd256) begin
                            poly_wen   <= 1'b1;
                            poly_addr  <= coeff_cnt[7:0];
                            poly_wdata <= d1;
                            coeff_cnt  <= coeff_cnt + 9'd1;
                        end
                        check_d2 <= 1'b1;
                    end else begin
                        // Check d2
                        if (d2 < MLKEM_Q[11:0] && coeff_cnt < 9'd256) begin
                            poly_wen   <= 1'b1;
                            poly_addr  <= coeff_cnt[7:0];
                            poly_wdata <= d2;
                            coeff_cnt  <= coeff_cnt + 9'd1;
                        end
                        if (coeff_cnt >= 9'd256 || (coeff_cnt == 9'd255 && d2 < MLKEM_Q[11:0])) begin
                            state <= S_DONE;
                        end else begin
                            shake_squeeze_req <= 1'b1;   // request next byte for re-entry
                            state <= S_SQUEEZE_B0;       // Need more bytes
                        end
                    end
                end

                S_DONE: begin
                    done <= 1'b1;
                    busy <= 1'b0;
                    state <= S_IDLE;
                end

                default: state <= S_IDLE;
            endcase
        end
    end

endmodule
