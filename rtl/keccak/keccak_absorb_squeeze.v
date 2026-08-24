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
// Keccak Sponge Absorb/Squeeze Controller
// Implements the sponge construction for SHA3 and SHAKE functions
//
// Supports parameterizable rate for:
//   SHAKE-128: rate = 168 bytes (1344 bits)
//   SHAKE-256: rate = 136 bytes (1088 bits)
//   SHA3-256:  rate = 136 bytes (1088 bits)
//   SHA3-512:  rate = 72 bytes  (576 bits)
//
// Interface:
//   Absorb: feed input bytes, module handles padding and permutation
//   Squeeze: extract output bytes, module permutes for additional blocks
//============================================================================
module keccak_absorb_squeeze #(
    parameter RATE_BYTES = 136,          // Rate in bytes
    parameter DOMAIN_SEP = 8'h06        // 0x06 for SHA3, 0x1F for SHAKE
)(
    input  wire          clk,
    input  wire          rst_n,

    // Control
    input  wire          init,           // Initialize/reset state
    input  wire          absorb_valid,   // Input byte valid
    input  wire [7:0]    absorb_data,    // Input byte
    output wire          absorb_ready,   // Ready to accept byte
    input  wire          absorb_last,    // Last byte of message
    input  wire          squeeze_start,  // Begin squeezing
    output reg           squeeze_valid,  // Output byte valid
    output reg  [7:0]    squeeze_data,   // Output byte
    input  wire          squeeze_next,   // Request next squeeze byte
    output reg           busy
);

    localparam RATE_BITS = RATE_BYTES * 8;

    // FSM states
    localparam S_IDLE       = 4'd0;
    localparam S_ABSORB     = 4'd1;
    localparam S_PAD        = 4'd2;
    localparam S_PERMUTE_ST = 4'd3;
    localparam S_PERMUTE_WT = 4'd4;
    localparam S_SQUEEZE    = 4'd5;
    localparam S_SQ_PERMUTE = 4'd6;
    localparam S_SQ_PERM_WT = 4'd7;

    reg [3:0] state;

    // Keccak state (1600 bits)
    reg  [1599:0] keccak_state;
    wire [1599:0] perm_out;
    reg           perm_start;
    wire          perm_done;
    wire          perm_busy;

    // Flag: permutation was triggered by padding (post-absorb), so
    // after perm_done we must go to S_SQUEEZE, not back to S_ABSORB.
    reg           post_pad;

    // Byte position counter within rate block
    reg [7:0] byte_pos;

    // Squeeze byte counter
    reg [7:0] sq_byte_pos;

    // Keccak permutation instance
    keccak_f1600 u_keccak (
        .clk       (clk),
        .rst_n     (rst_n),
        .start     (perm_start),
        .state_in  (keccak_state),
        .state_out (perm_out),
        .done      (perm_done),
        .busy      (perm_busy)
    );

    assign absorb_ready = (state == S_ABSORB) && !perm_busy;

    // XOR a byte into the state at position byte_pos
    function [1599:0] xor_byte_into_state;
        input [1599:0] st;
        input [7:0]    pos;
        input [7:0]    data;
        reg [10:0] bit_offset;
        begin
            bit_offset = {3'b0, pos} << 3;   // pos * 8
            xor_byte_into_state = st;
            xor_byte_into_state[bit_offset +: 8] = st[bit_offset +: 8] ^ data;
        end
    endfunction

    // Extract a byte from state at position
    function [7:0] extract_byte;
        input [1599:0] st;
        input [7:0]    pos;
        reg [10:0] bit_offset;
        begin
            bit_offset = {3'b0, pos} << 3;
            extract_byte = st[bit_offset +: 8];
        end
    endfunction

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            state        <= S_IDLE;
            keccak_state <= 1600'd0;
            byte_pos     <= 8'd0;
            sq_byte_pos  <= 8'd0;
            perm_start   <= 1'b0;
            squeeze_valid <= 1'b0;
            squeeze_data  <= 8'd0;
            busy          <= 1'b0;
            post_pad      <= 1'b0;
        end else begin
            perm_start    <= 1'b0;
            squeeze_valid <= 1'b0;

            // -------------------------------------------------------
            // init (start) can fire from ANY state.
            // Always reset the sponge immediately and go to S_ABSORB.
            // This fixes the deadlock where repeated calls to
            // sample_ntt / PRF left the sponge in S_SQUEEZE and the
            // subsequent init pulse was silently dropped.
            // -------------------------------------------------------
            if (init) begin
                keccak_state <= 1600'd0;
                byte_pos     <= 8'd0;
                sq_byte_pos  <= 8'd0;
                post_pad     <= 1'b0;
                busy         <= 1'b1;
                state        <= S_ABSORB;
            end else begin

            case (state)
                S_IDLE: begin
                    busy <= 1'b0;
                    if (init) begin
                        keccak_state <= 1600'd0;
                        byte_pos     <= 8'd0;
                        state        <= S_ABSORB;
                        busy         <= 1'b1;
                    end
                end

                S_ABSORB: begin
                    if (absorb_valid) begin
                        // XOR input byte into state
                        keccak_state <= xor_byte_into_state(keccak_state, byte_pos, absorb_data);

                        if (absorb_last) begin
                            // Move to padding
                            byte_pos <= byte_pos + 8'd1;
                            state    <= S_PAD;
                        end else if (byte_pos == RATE_BYTES - 1) begin
                            // Rate block full — permute
                            byte_pos   <= 8'd0;
                            perm_start <= 1'b1;
                            state      <= S_PERMUTE_WT;
                        end else begin
                            byte_pos <= byte_pos + 8'd1;
                        end
                    end
                end

                S_PAD: begin
                    // Apply padding: domain_sep at current position, 0x80 at end of rate
                    keccak_state <= xor_byte_into_state(
                        xor_byte_into_state(keccak_state, byte_pos, DOMAIN_SEP),
                        RATE_BYTES[7:0] - 8'd1,
                        8'h80
                    );
                    perm_start <= 1'b1;
                    post_pad   <= 1'b1;   // Mark: next S_PERMUTE_WT -> S_SQUEEZE
                    state      <= S_PERMUTE_WT;
                end

                S_PERMUTE_WT: begin
                    if (perm_done) begin
                        keccak_state <= perm_out;
                        byte_pos     <= 8'd0;
                        if (post_pad || squeeze_start) begin
                            // After absorb padding permutation — start squeezing
                            sq_byte_pos <= 8'd0;
                            post_pad    <= 1'b0;
                            state       <= S_SQUEEZE;
                        end else begin
                            // Mid-absorb full-rate permutation — back to absorb
                            state <= S_ABSORB;
                        end
                    end
                end

                S_SQUEEZE: begin
                    squeeze_valid <= 1'b1;
                    squeeze_data  <= extract_byte(keccak_state, sq_byte_pos);
                    if (squeeze_next) begin
                        if (sq_byte_pos == RATE_BYTES - 1) begin
                            // Need more output — permute again
                            sq_byte_pos <= 8'd0;
                            perm_start  <= 1'b1;
                            state       <= S_SQ_PERM_WT;
                        end else begin
                            sq_byte_pos <= sq_byte_pos + 8'd1;
                        end
                    end
                end

                S_SQ_PERM_WT: begin
                    if (perm_done) begin
                        keccak_state <= perm_out;
                        state        <= S_SQUEEZE;
                    end
                end

                default: state <= S_IDLE;
            endcase
            end  // end else (not init)
        end
    end

endmodule
