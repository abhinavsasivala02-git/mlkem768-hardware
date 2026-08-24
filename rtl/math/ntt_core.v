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
// Unified NTT Core - Handles both forward NTT and inverse NTT
// Single butterfly unit shared between CT (forward) and GS (inverse) modes
//
// mode = 0: Forward NTT (Cooley-Tukey)
// mode = 1: Inverse NTT (Gentleman-Sande) with final f=1441 scaling
//============================================================================
module ntt_core (
    input  wire        clk,
    input  wire        rst_n,
    input  wire        start,
    input  wire        mode,       // 0=forward NTT, 1=inverse NTT
    output reg         done,
    output reg         busy,

    // Polynomial RAM interface - Port A (read/write)
    output reg         ram_wen,
    output reg  [7:0]  ram_addr_a,
    output reg  [11:0] ram_wdata_a,
    input  wire [11:0] ram_rdata_a,

    // Polynomial RAM interface - Port B (read-only)
    output reg  [7:0]  ram_addr_b,
    input  wire [11:0] ram_rdata_b
);

    localparam MLKEM_N      = 9'd256;
    localparam MLKEM_INTT_F = 16'd512;

    // FSM states
    localparam S_IDLE      = 4'd0;
    localparam S_SETUP     = 4'd1;
    localparam S_READ      = 4'd2;
    localparam S_WAIT      = 4'd3;
    localparam S_BFLY      = 4'd4;
    localparam S_BFLY_WAIT = 4'd5;
    localparam S_WRITE     = 4'd6;
    localparam S_WRITE2    = 4'd7;
    localparam S_NEXT      = 4'd8;
    localparam S_SCALE_RD  = 4'd9;
    localparam S_SCALE_WT  = 4'd10;
    localparam S_SCALE_WB  = 4'd11;
    localparam S_SCALE_NX  = 4'd12;
    localparam S_DONE      = 4'd13;

    reg [3:0] state, next_state;
    reg       mode_reg;

    // Layer and position counters
    reg [2:0]  layer;
    reg [7:0]  j;
    reg [7:0]  start_idx;
    reg [7:0]  len;
    reg [6:0]  k;
    reg [8:0]  scale_idx;

    // Butterfly I/O
    reg               bfly_valid_in;
    wire signed [15:0] bfly_a_out, bfly_b_out;
    wire              bfly_valid_out;
    reg  signed [15:0] bfly_a_in, bfly_b_in;

    // Zeta ROM
    wire signed [15:0] zeta_val;

    // Montgomery multiply for INTT final scaling
    (* use_dsp = "no" *) wire signed [31:0] scale_product;
    wire [11:0] scale_result;
    assign scale_product = $signed({4'b0, ram_rdata_a}) * $signed(MLKEM_INTT_F);

    montgomery_reduce u_mont_scale (
        .a      (scale_product),
        .result (scale_result)
    );

    // Address computation
    wire [7:0] addr_lo, addr_hi;
    assign addr_lo = start_idx + j;
    assign addr_hi = start_idx + j + len;

    // Zeta ROM (shared)
    ntt_rom u_zeta_rom (
        .clk  (clk),
        .addr (k),
        .zeta (zeta_val)
    );

    // Butterfly (mode selects CT vs GS)
    ntt_butterfly u_butterfly (
        .clk       (clk),
        .rst_n     (rst_n),
        .valid_in  (bfly_valid_in),
        .mode      (mode_reg),
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
                if (j + 1 < len)
                    next_state = S_READ;
                else if (start_idx + (len << 1) < MLKEM_N)
                    next_state = S_READ;
                else if (layer < 3'd6)
                    next_state = S_SETUP;
                else if (mode_reg)
                    next_state = S_SCALE_RD;  // INTT: go to scaling
                else
                    next_state = S_DONE;      // NTT: done
            end
            S_SCALE_RD:  next_state = S_SCALE_WT;
            S_SCALE_WT:  next_state = S_SCALE_WB;
            S_SCALE_WB:  next_state = S_SCALE_NX;
            S_SCALE_NX:  next_state = (scale_idx < 9'd255) ? S_SCALE_RD : S_DONE;
            S_DONE:      next_state = S_IDLE;
            default:     next_state = S_IDLE;
        endcase
    end

    // Datapath
    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            done          <= 1'b0;
            busy          <= 1'b0;
            ram_wen       <= 1'b0;
            ram_addr_a    <= 8'd0;
            ram_addr_b    <= 8'd0;
            ram_wdata_a   <= 12'd0;
            bfly_valid_in <= 1'b0;
            bfly_a_in     <= 16'sd0;
            bfly_b_in     <= 16'sd0;
            mode_reg      <= 1'b0;
            layer         <= 3'd0;
            j             <= 8'd0;
            start_idx     <= 8'd0;
            len           <= 8'd128;
            k             <= 7'd0;
            scale_idx     <= 9'd0;
        end else begin
            ram_wen       <= 1'b0;
            bfly_valid_in <= 1'b0;
            done          <= 1'b0;

            case (state)
                S_IDLE: begin
                    busy <= 1'b0;
                    if (start) begin
                        busy     <= 1'b1;
                        mode_reg <= mode;
                        layer    <= 3'd0;
                        // Forward NTT: start len=128, k=0 (increments from 1)
                        // Inverse NTT: start len=2, k=127 (decrements)
                        if (mode == 1'b0) begin
                            len <= 8'd128;
                            k   <= 7'd0;
                        end else begin
                            len <= 8'd2;
                            k   <= 7'd127;
                        end
                    end
                end

                S_SETUP: begin
                    start_idx <= 8'd0;
                    j         <= 8'd0;
                    if (mode_reg == 1'b0)
                        k <= k + 7'd1;    // Forward: increment
                end

                S_READ: begin
                    ram_addr_a <= addr_lo;
                    ram_addr_b <= addr_hi;
                end

                S_WAIT: begin
                    // RAM read latency
                end

                S_BFLY: begin
                    bfly_a_in     <= $signed({4'b0, ram_rdata_a});
                    bfly_b_in     <= $signed({4'b0, ram_rdata_b});
                    bfly_valid_in <= 1'b1;
                end

                S_BFLY_WAIT: begin
                    // Wait for butterfly registered output pipeline
                end

                S_WRITE: begin
                    ram_wen     <= 1'b1;
                    ram_addr_a  <= addr_lo;
                    ram_wdata_a <= bfly_a_out[11:0];
                end

                S_WRITE2: begin
                    ram_wen     <= 1'b1;
                    ram_addr_a  <= addr_hi;
                    ram_wdata_a <= bfly_b_out[11:0];
                end

                S_NEXT: begin
                    if (j + 1 < len) begin
                        j <= j + 8'd1;
                    end else if (start_idx + (len << 1) < MLKEM_N) begin
                        start_idx <= start_idx + (len << 1);
                        j         <= 8'd0;
                        if (mode_reg == 1'b0)
                            k <= k + 7'd1;
                        else
                            k <= k - 7'd1;
                    end else begin
                        layer <= layer + 3'd1;
                        if (mode_reg == 1'b0)
                            len <= len >> 1;      // Forward: halve
                        else begin
                            len       <= len << 1;  // Inverse: double
                            k         <= k - 7'd1;
                            scale_idx <= 9'd0;
                        end
                    end
                end

                // --- INTT final scaling by f = 1441 ---
                S_SCALE_RD: begin
                    ram_addr_a <= scale_idx[7:0];
                end

                S_SCALE_WT: begin
                    // Wait for read
                end

                S_SCALE_WB: begin
                    ram_wen     <= 1'b1;
                    ram_addr_a  <= scale_idx[7:0];
                    ram_wdata_a <= scale_result;
                end

                S_SCALE_NX: begin
                    scale_idx <= scale_idx + 9'd1;
                end

                S_DONE: begin
                    done <= 1'b1;
                    busy <= 1'b0;
                end
            endcase
        end
    end

endmodule
