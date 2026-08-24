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
// Forward NTT — Algorithm 9 of FIPS 203
// 7-layer in-place Cooley-Tukey NTT over Z_q[X]/(X^256+1)
// Transforms 256 coefficients into 128 degree-1 polynomials in NTT domain
//
// Uses single butterfly unit and dual-port RAM for in-place computation.
// Total: 7 layers × 128 butterflies/layer = 896 butterfly operations
//============================================================================
module ntt (
    input  wire        clk,
    input  wire        rst_n,
    input  wire        start,
    output reg         done,
    output reg         busy,

    // Polynomial RAM interface — Port A (read/write)
    output reg         ram_wen,
    output reg  [7:0]  ram_addr_a,
    output reg  [11:0] ram_wdata_a,
    input  wire [11:0] ram_rdata_a,

    // Polynomial RAM interface — Port B (read-only)
    output reg  [7:0]  ram_addr_b,
    input  wire [11:0] ram_rdata_b
);

    `include "mlkem_params.vh"

    // FSM states
    localparam S_IDLE      = 4'd0;
    localparam S_SETUP     = 4'd1;
    localparam S_READ      = 4'd2;
    localparam S_WAIT      = 4'd3;
    localparam S_BFLY      = 4'd4;
    localparam S_BFLY_WAIT = 4'd5;  // NEW: wait for butterfly pipeline
    localparam S_WRITE     = 4'd6;
    localparam S_WRITE2    = 4'd7;  // write b result
    localparam S_NEXT      = 4'd8;
    localparam S_DONE      = 4'd9;

    reg [3:0] state, next_state;

    // Layer and position counters
    reg [2:0]  layer;         // 0..6 (7 layers)
    reg [7:0]  j;             // butterfly index within group
    reg [7:0]  start_idx;     // start of current group
    reg [7:0]  len;           // half-length of current group
    reg [6:0]  k;             // zeta index (1..127)

    // Butterfly I/O
    reg               bfly_valid_in;
    wire signed [15:0] bfly_a_out, bfly_b_out;
    wire              bfly_valid_out;
    reg  signed [15:0] bfly_a_in, bfly_b_in;

    // Zeta ROM
    wire signed [15:0] zeta_val;

    // Address computation
    wire [7:0] addr_lo, addr_hi;
    assign addr_lo = start_idx + j;
    assign addr_hi = start_idx + j + len;

    // Instantiate zeta ROM (synchronous BRAM)
    ntt_rom u_zeta_rom (
        .clk  (clk),
        .addr (k),
        .zeta (zeta_val)
    );

    // Instantiate butterfly (CT mode = 0)
    ntt_butterfly u_butterfly (
        .clk       (clk),
        .rst_n     (rst_n),
        .valid_in  (bfly_valid_in),
        .mode      (1'b0),           // Cooley-Tukey
        .a_in      (bfly_a_in),
        .b_in      (bfly_b_in),
        .zeta      (zeta_val),
        .a_out     (bfly_a_out),
        .b_out     (bfly_b_out),
        .valid_out (bfly_valid_out)
    );

    // FSM sequential
    always @(posedge clk or negedge rst_n) begin
        if (!rst_n)
            state <= S_IDLE;
        else
            state <= next_state;
    end

    // FSM combinational
    always @(*) begin
        next_state = state;
        case (state)
            S_IDLE:      if (start) next_state = S_SETUP;
            S_SETUP:     next_state = S_READ;
            S_READ:      next_state = S_WAIT;
            S_WAIT:      next_state = S_BFLY;
            S_BFLY:      next_state = S_BFLY_WAIT;
            S_BFLY_WAIT: next_state = S_WRITE;
            S_WRITE:     next_state = S_WRITE2;
            S_WRITE2:    next_state = S_NEXT;
            S_NEXT: begin
                if (j + 1 < len) begin
                    next_state = S_READ;    // next butterfly in group
                end else if (start_idx + (len << 1) < MLKEM_N) begin
                    next_state = S_READ;    // next group in layer
                end else if (layer < 3'd6) begin
                    next_state = S_SETUP;   // next layer
                end else begin
                    next_state = S_DONE;
                end
            end
            S_DONE:    next_state = S_IDLE;
            default:   next_state = S_IDLE;
        endcase
    end

    // Datapath
    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            done         <= 1'b0;
            busy         <= 1'b0;
            ram_wen      <= 1'b0;
            ram_addr_a   <= 8'd0;
            ram_addr_b   <= 8'd0;
            ram_wdata_a  <= 12'd0;
            bfly_valid_in <= 1'b0;
            bfly_a_in    <= 16'sd0;
            bfly_b_in    <= 16'sd0;
            layer        <= 3'd0;
            j            <= 8'd0;
            start_idx    <= 8'd0;
            len          <= 8'd128;
            k            <= 7'd0;
        end else begin
            ram_wen       <= 1'b0;
            bfly_valid_in <= 1'b0;
            done          <= 1'b0;

            case (state)
                S_IDLE: begin
                    busy <= 1'b0;
                    if (start) begin
                        busy      <= 1'b1;
                        layer     <= 3'd0;
                        len       <= 8'd128;
                        k         <= 7'd0;
                    end
                end

                S_SETUP: begin
                    // Start of new layer
                    start_idx <= 8'd0;
                    j         <= 8'd0;
                    k         <= k + 7'd1;
                end

                S_READ: begin
                    // Issue RAM reads for pair (addr_lo, addr_hi)
                    ram_addr_a <= addr_lo;
                    ram_addr_b <= addr_hi;
                end

                S_WAIT: begin
                    // Wait for RAM read latency
                end

                S_BFLY: begin
                    // Feed butterfly
                    bfly_a_in     <= $signed({4'b0, ram_rdata_a});
                    bfly_b_in     <= $signed({4'b0, ram_rdata_b});
                    bfly_valid_in <= 1'b1;
                end

                S_BFLY_WAIT: begin
                    // Wait for butterfly registered output pipeline
                end

                S_WRITE: begin
                    // Write butterfly 'a' result to addr_lo
                    ram_wen     <= 1'b1;
                    ram_addr_a  <= addr_lo;
                    ram_wdata_a <= bfly_a_out[11:0];
                end

                S_WRITE2: begin
                    // Write butterfly 'b' result to addr_hi
                    ram_wen     <= 1'b1;
                    ram_addr_a  <= addr_hi;
                    ram_wdata_a <= bfly_b_out[11:0];
                end

                S_NEXT: begin
                    if (j + 1 < len) begin
                        // Next butterfly in same group
                        j <= j + 8'd1;
                    end else begin
                        // Next group or next layer
                        if (start_idx + (len << 1) < MLKEM_N) begin
                            start_idx <= start_idx + (len << 1);
                            j         <= 8'd0;
                            k         <= k + 7'd1;
                        end else begin
                            layer <= layer + 3'd1;
                            len   <= len >> 1;
                        end
                    end
                end

                S_DONE: begin
                    done <= 1'b1;
                    busy <= 1'b0;
                end
            endcase
        end
    end

endmodule
