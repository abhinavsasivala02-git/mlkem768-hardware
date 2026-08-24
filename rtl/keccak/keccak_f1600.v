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
// Keccak-f[1600] Permutation — 24-round iterative implementation
// Processes one round per clock cycle (24 cycles total)
//
// Interface:
//   start → loads state_in, begins 24 rounds
//   done  → asserted for 1 cycle when complete, state_out valid
//============================================================================
module keccak_f1600 (
    input  wire          clk,
    input  wire          rst_n,
    input  wire          start,
    input  wire [1599:0] state_in,
    output wire [1599:0] state_out,
    output reg           done,
    output reg           busy
);

    // Round constants (FIPS 202, Table 1)
    function [63:0] round_constant;
        input [4:0] round_idx;
        begin
            case (round_idx)
                5'd0:  round_constant = 64'h0000000000000001;
                5'd1:  round_constant = 64'h0000000000008082;
                5'd2:  round_constant = 64'h800000000000808A;
                5'd3:  round_constant = 64'h8000000080008000;
                5'd4:  round_constant = 64'h000000000000808B;
                5'd5:  round_constant = 64'h0000000080000001;
                5'd6:  round_constant = 64'h8000000080008081;
                5'd7:  round_constant = 64'h8000000000008009;
                5'd8:  round_constant = 64'h000000000000008A;
                5'd9:  round_constant = 64'h0000000000000088;
                5'd10: round_constant = 64'h0000000080008009;
                5'd11: round_constant = 64'h000000008000000A;
                5'd12: round_constant = 64'h000000008000808B;
                5'd13: round_constant = 64'h800000000000008B;
                5'd14: round_constant = 64'h8000000000008089;
                5'd15: round_constant = 64'h8000000000008003;
                5'd16: round_constant = 64'h8000000000008002;
                5'd17: round_constant = 64'h8000000000000080;
                5'd18: round_constant = 64'h000000000000800A;
                5'd19: round_constant = 64'h800000008000000A;
                5'd20: round_constant = 64'h8000000080008081;
                5'd21: round_constant = 64'h8000000000008080;
                5'd22: round_constant = 64'h0000000080000001;
                5'd23: round_constant = 64'h8000000080008008;
                default: round_constant = 64'h0;
            endcase
        end
    endfunction

    // State register
    reg [1599:0] state_reg;
    reg [4:0]    round_cnt;

    // Round function wires
    wire [1599:0] round_out;
    wire [63:0]   rc;

    assign rc = round_constant(round_cnt);

    // Instantiate single round
    keccak_round u_round (
        .state_in    (state_reg),
        .round_const (rc),
        .state_out   (round_out)
    );

    assign state_out = state_reg;

    // FSM
    localparam S_IDLE    = 2'd0;
    localparam S_RUNNING = 2'd1;
    localparam S_DONE    = 2'd2;

    reg [1:0] fsm_state;

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            fsm_state <= S_IDLE;
            state_reg <= 1600'd0;
            round_cnt <= 5'd0;
            done      <= 1'b0;
            busy      <= 1'b0;
        end else begin
            done <= 1'b0;

            case (fsm_state)
                S_IDLE: begin
                    busy <= 1'b0;
                    if (start) begin
                        state_reg <= state_in;
                        round_cnt <= 5'd0;
                        fsm_state <= S_RUNNING;
                        busy      <= 1'b1;
                    end
                end

                S_RUNNING: begin
                    state_reg <= round_out;
                    if (round_cnt == 5'd23) begin
                        fsm_state <= S_DONE;
                    end else begin
                        round_cnt <= round_cnt + 5'd1;
                    end
                end

                S_DONE: begin
                    done      <= 1'b1;
                    busy      <= 1'b0;
                    fsm_state <= S_IDLE;
                end

                default: fsm_state <= S_IDLE;
            endcase
        end
    end

endmodule
