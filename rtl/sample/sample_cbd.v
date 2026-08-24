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
// SamplePolyCBD - Algorithm 8 of FIPS 203
// Centered Binomial Distribution sampling
//
// For ?=2: Input 64? = 128 bytes from PRF
//   For each coefficient: take 4 bits, x = popcount(b[0:1]) - popcount(b[2:3])
// For ?=3: Input 64? = 192 bytes from PRF
//   For each coefficient: take 6 bits, x = popcount(b[0:2]) - popcount(b[3:5])
//
// Output: 256 coefficients in range [-?, ?], stored as [0, q-1]
//============================================================================
module sample_cbd #(
    parameter ETA = 2    // 2 or 3
)(
    input  wire        clk,
    input  wire        rst_n,
    input  wire        start,
    output reg         done,
    output reg         busy,

    // PRF byte input (from SHAKE-256)
    input  wire        prf_valid,
    input  wire [7:0]  prf_data,
    output reg         prf_req,

    // Output polynomial RAM - write interface
    output reg         poly_wen,
    output reg  [7:0]  poly_addr,
    output reg  [11:0] poly_wdata
);

    // ---- Parameters (inlined from mlkem_params.vh) ----
    localparam MLKEM_Q = 13'd3329;
    // ---------------------------------------------------
    localparam BYTES_NEEDED = 64 * ETA;   // 128 for ?=2, 192 for ?=3
    localparam BITS_PER_COEFF = 2 * ETA;  // 4 for ?=2, 6 for ?=3

    // FSM
    localparam S_IDLE    = 3'd0;
    localparam S_COLLECT = 3'd1;
    localparam S_PROCESS = 3'd2;
    localparam S_WRITE   = 3'd3;
    localparam S_NEXT    = 3'd4;
    localparam S_DONE    = 3'd5;

    reg [2:0] state;

    // Byte buffer - store all PRF bytes
    reg [7:0] prf_buf [0:191];   // Max 192 bytes for ?=3
    reg [7:0] byte_cnt;

    // Coefficient processing
    reg [8:0] coeff_idx;    // 0..255
    reg [10:0] bit_offset;

    // Registered bit extraction (continuous-assign function-of-memory does not
    // re-evaluate when prf_buf contents change, leaving coeff 0 stale/X)
    reg [5:0] extracted_bits_reg;

    // Popcount computation
    wire [2:0] pop_a, pop_b;
    wire signed [3:0] cbd_val;
    wire [11:0] cbd_unsigned;

    // Extract bits for current coefficient from buffer
    wire [5:0] extracted_bits;  // Up to 6 bits

    // Bit extraction: get BITS_PER_COEFF bits starting at bit_offset
    function [5:0] get_bits;
        input [10:0] offset;
        reg [7:0] byte0, byte1;
        reg [2:0] bit_pos;
        reg [15:0] two_bytes;
        begin
            byte0 = prf_buf[offset[10:3]];
            byte1 = prf_buf[offset[10:3] + 1];
            bit_pos = offset[2:0];
            two_bytes = {byte1, byte0};
            get_bits = (two_bytes >> bit_pos) & ((1 << BITS_PER_COEFF) - 1);
        end
    endfunction

    // Popcount for 2 or 3 bits
    function [2:0] popcount3;
        input [2:0] bits;
        begin
            popcount3 = {2'b0, bits[0]} + {2'b0, bits[1]} + {2'b0, bits[2]};
        end
    endfunction

    function [1:0] popcount2;
        input [1:0] bits;
        begin
            popcount2 = {1'b0, bits[0]} + {1'b0, bits[1]};
        end
    endfunction

    assign extracted_bits = extracted_bits_reg;

    // Split into two halves and compute popcount difference
    generate
        if (ETA == 2) begin : gen_eta2
            assign pop_a = {1'b0, popcount2(extracted_bits[1:0])};
            assign pop_b = {1'b0, popcount2(extracted_bits[3:2])};
        end else begin : gen_eta3
            assign pop_a = popcount3(extracted_bits[2:0]);
            assign pop_b = popcount3(extracted_bits[5:3]);
        end
    endgenerate

    assign cbd_val = $signed({1'b0, pop_a}) - $signed({1'b0, pop_b});

    // Convert signed CBD value to unsigned mod q
    assign cbd_unsigned = (cbd_val < 0) ? (MLKEM_Q[11:0] + {{8{cbd_val[3]}}, cbd_val}) : {{8{1'b0}}, cbd_val};

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            state     <= S_IDLE;
            done      <= 1'b0;
            busy      <= 1'b0;
            poly_wen  <= 1'b0;
            poly_addr <= 8'd0;
            poly_wdata <= 12'd0;
            prf_req   <= 1'b0;
            byte_cnt  <= 8'd0;
            coeff_idx <= 9'd0;
            bit_offset <= 11'd0;
            extracted_bits_reg <= 6'd0;
        end else begin
            poly_wen <= 1'b0;
            done     <= 1'b0;
            prf_req  <= 1'b0;

            case (state)
                S_IDLE: begin
                    busy <= 1'b0;
                    if (start) begin
                        busy     <= 1'b1;
                        byte_cnt <= 8'd0;
                        state    <= S_COLLECT;
                        prf_req  <= 1'b1;
                    end
                end

                S_COLLECT: begin
                    // Collect all PRF bytes into buffer
                    if (prf_valid) begin
                        prf_buf[byte_cnt] <= prf_data;
                        if (byte_cnt == BYTES_NEEDED - 1) begin
                            coeff_idx  <= 9'd0;
                            bit_offset <= 11'd0;
                            state      <= S_PROCESS;
                        end else begin
                            byte_cnt <= byte_cnt + 8'd1;
                            prf_req  <= 1'b1;
                        end
                    end
                end

                S_PROCESS: begin
                    extracted_bits_reg <= get_bits(bit_offset);
                    state <= S_WRITE;
                end

                S_WRITE: begin
                    poly_wen   <= 1'b1;
                    poly_addr  <= coeff_idx[7:0];
                    poly_wdata <= cbd_unsigned;
                    state      <= S_NEXT;
                end

                S_NEXT: begin
                    if (coeff_idx == 9'd255) begin
                        state <= S_DONE;
                    end else begin
                        coeff_idx  <= coeff_idx + 9'd1;
                        bit_offset <= bit_offset + BITS_PER_COEFF;
                        state      <= S_PROCESS;
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