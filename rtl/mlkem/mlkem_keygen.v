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
// ML-KEM.KeyGen - Algorithm 16 of FIPS 203
// Outer ML-KEM key generation:
//   dk = dk_pke || ek || H(ek) || z
//============================================================================
module mlkem_keygen #(
    parameter K    = 3,
    parameter ETA1 = 2
)(
    input  wire          clk,
    input  wire          rst_n,
    input  wire          start,
    input  wire [255:0]  d_seed,
    input  wire [255:0]  z_random,
    output reg           done,
    output reg           busy,

    output reg           ek_wen,
    output reg  [12:0]   ek_addr,
    output reg  [7:0]    ek_wdata,

    output reg           dk_wen,
    output reg  [12:0]   dk_addr,
    output reg  [7:0]    dk_wdata
);

    `include "mlkem_params.vh"

    localparam EK_SIZE = 384 * K + 32;
    localparam DK_PKE_SIZE = 384 * K;

    localparam ST_IDLE       = 4'd0;
    localparam ST_KPKE_KG    = 4'd1;
    localparam ST_WAIT_KG    = 4'd2;
    localparam ST_COPY_EK    = 4'd3;
    localparam ST_HASH_EK    = 4'd4;
    localparam ST_WAIT_HASH  = 4'd5;
    localparam ST_WRITE_HASH = 4'd6;
    localparam ST_WRITE_Z    = 4'd7;
    localparam ST_DONE       = 4'd8;

    reg [3:0] state;
    reg          kpke_start;
    wire         kpke_done, kpke_busy;
    wire         kpke_ek_valid, kpke_dk_valid;
    wire [7:0]   kpke_ek_data, kpke_dk_data;
    wire [12:0]  kpke_ek_addr, kpke_dk_addr;

    kpke_keygen #(.K(K), .ETA1(ETA1)) u_kpke_keygen (
        .clk(clk), .rst_n(rst_n), .start(kpke_start), .d_seed(d_seed),
        .done(kpke_done), .busy(kpke_busy),
        .ek_valid(kpke_ek_valid), .ek_data(kpke_ek_data), .ek_addr(kpke_ek_addr),
        .dk_valid(kpke_dk_valid), .dk_data(kpke_dk_data), .dk_addr(kpke_dk_addr)
    );

    // SHA3-256 for H(ek)
    reg          h_start, h_data_valid, h_data_last;
    reg          h_prs, h_lst;
    reg  [7:0]   h_data_in;
    wire         h_hash_valid, h_data_ready;
    wire [255:0] h_hash_out;

    sha3_256 u_h_hash (
        .clk(clk), .rst_n(rst_n), .start(h_start),
        .data_valid(h_data_valid), .data_in(h_data_in),
        .data_ready(h_data_ready),
        .data_last(h_data_last),
        .hash_valid(h_hash_valid), .hash_out(h_hash_out), .busy()
    );

    reg [12:0] copy_cnt;
    reg [4:0]  hash_byte_cnt;
    reg [7:0]  ek_buf [0:1567];
    reg [12:0] ek_buf_len;

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            state <= ST_IDLE; done <= 0; busy <= 0;
            ek_wen <= 0; dk_wen <= 0;
            ek_addr <= 0; dk_addr <= 0;
            ek_wdata <= 0; dk_wdata <= 0;
            kpke_start <= 0; h_start <= 0;
            h_data_valid <= 0; h_data_in <= 0; h_data_last <= 0;
            h_prs <= 0; h_lst <= 0;
            copy_cnt <= 0; hash_byte_cnt <= 0; ek_buf_len <= 0;
        end else begin
            ek_wen <= 0; dk_wen <= 0;
            kpke_start <= 0; h_start <= 0;
            h_data_valid <= 0; h_data_last <= 0;
            done <= 0;

            case (state)
                ST_IDLE: begin
                    busy <= 0;
                    if (start) begin
                        busy <= 1; kpke_start <= 1;
                        ek_buf_len <= EK_SIZE[12:0];
                        state <= ST_KPKE_KG;
                    end
                end

                ST_KPKE_KG: state <= ST_WAIT_KG;

                ST_WAIT_KG: begin
                    if (kpke_ek_valid) begin
                        ek_wen <= 1; ek_addr <= kpke_ek_addr;
                        ek_wdata <= kpke_ek_data;
                        ek_buf[kpke_ek_addr] <= kpke_ek_data;
                    end
                    if (kpke_dk_valid) begin
                        dk_wen <= 1; dk_addr <= kpke_dk_addr;
                        dk_wdata <= kpke_dk_data;
                    end
                    if (kpke_done) begin
                        copy_cnt <= 0; state <= ST_COPY_EK;
                    end
                end

                ST_COPY_EK: begin
                    dk_wen <= 1;
                    dk_addr <= DK_PKE_SIZE[12:0] + copy_cnt;
                    dk_wdata <= ek_buf[copy_cnt];
                    if (copy_cnt == ek_buf_len - 1) begin
                        h_start <= 1; copy_cnt <= 0;
                        hash_byte_cnt <= 0; state <= ST_HASH_EK;
                    end else
                        copy_cnt <= copy_cnt + 1;
                end

                // Hash ek — absorb-acknowledged handshake (present → hold →
                // advance-on-absorb). Avoids the duplicate/skip that a plain
                // NBA ready-gated feed causes at mid-block Keccak permutations.
                ST_HASH_EK: begin
                    h_data_valid <= 1'b0;
                    h_data_last  <= 1'b0;
                    if (h_prs) begin
                        h_prs <= 1'b0;
                        if (h_lst) begin
                            state <= ST_WAIT_HASH;
                        end else begin
                            copy_cnt <= copy_cnt + 1;
                        end
                    end else if (h_data_ready) begin
                        h_data_valid <= 1'b1;
                        h_data_in    <= ek_buf[copy_cnt];
                        h_prs        <= 1'b1;
                        if (copy_cnt == ek_buf_len - 1) begin
                            h_data_last <= 1'b1;
                            h_lst       <= 1'b1;
                        end
                    end
                end

                ST_WAIT_HASH: begin
                    if (h_hash_valid) begin
                        hash_byte_cnt <= 0; state <= ST_WRITE_HASH;
                    end
                end

                ST_WRITE_HASH: begin
                    dk_wen <= 1;
                    dk_addr <= DK_PKE_SIZE[12:0] + ek_buf_len + {8'd0, hash_byte_cnt};
                    dk_wdata <= h_hash_out[hash_byte_cnt*8 +: 8];
                    if (hash_byte_cnt == 5'd31) begin
                        hash_byte_cnt <= 0; state <= ST_WRITE_Z;
                    end else
                        hash_byte_cnt <= hash_byte_cnt + 1;
                end

                ST_WRITE_Z: begin
                    dk_wen <= 1;
                    dk_addr <= DK_PKE_SIZE[12:0] + ek_buf_len + 13'd32 + {8'd0, hash_byte_cnt};
                    dk_wdata <= z_random[hash_byte_cnt*8 +: 8];
                    if (hash_byte_cnt == 5'd31)
                        state <= ST_DONE;
                    else
                        hash_byte_cnt <= hash_byte_cnt + 1;
                end

                ST_DONE: begin done <= 1; busy <= 0; state <= ST_IDLE; end
                default: state <= ST_IDLE;
            endcase
        end
    end

endmodule
