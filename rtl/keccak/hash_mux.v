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
// hash_mux — N-to-1 arbiter for the shared Keccak sponge
//
// Every ML-KEM hash use is strictly sequential: KeyGen runs G, then the XOF
// per matrix entry, then the PRF per noise polynomial; Encaps runs H, G, then
// XOF/PRF; Decaps runs G, J, then the re-encryption.  Two clients are never
// mid-operation at the same time, so no queueing is needed — ownership simply
// follows whoever last asserted init and is held until the next init.
//
// Requests are carried as a packed vector so the bus costs two ports per
// hierarchy level instead of eleven:
//
//   req = {init, rate[7:0], dom[7:0], absorb_valid, absorb_data[7:0],
//          absorb_last, squeeze_next}                              28 bits
//   rsp = {absorb_ready, squeeze_valid, squeeze_data[7:0], busy}    11 bits
//
// A non-owner is answered with absorb_ready=0, squeeze_valid=0 and busy=1, so
// it can never mistake another client's grant for its own.
//============================================================================
`timescale 1ns/1ps

module hash_mux #(
    parameter N = 2
)(
    input  wire              clk,
    input  wire              rst_n,

    input  wire [N*28-1:0]   c_req,
    output wire [N*11-1:0]   c_rsp,

    output wire [27:0]       m_req,
    input  wire [10:0]       m_rsp
);

    localparam RQ = 28;
    localparam RS = 11;

    wire [N-1:0] init_req;
    genvar gi;
    generate
        for (gi = 0; gi < N; gi = gi + 1) begin : g_init
            assign init_req[gi] = c_req[gi*RQ + (RQ-1)];
        end
    endgenerate

    reg  [$clog2(N+1)-1:0] owner;
    wire [$clog2(N+1)-1:0] first_req;
    integer k;
    reg  [$clog2(N+1)-1:0] fr;
    always @(*) begin
        fr = owner;
        for (k = N-1; k >= 0; k = k - 1)
            if (init_req[k]) fr = k[$clog2(N+1)-1:0];
    end
    assign first_req = fr;

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n)
            owner <= {$clog2(N+1){1'b0}};
        else if (|init_req)
            owner <= first_req;
    end

    wire [$clog2(N+1)-1:0] sel = (|init_req) ? first_req : owner;

    reg [RQ-1:0] sel_req;
    always @(*) begin
        sel_req = {RQ{1'b0}};
        for (k = 0; k < N; k = k + 1)
            if (k == sel) sel_req = c_req[k*RQ +: RQ];
    end
    assign m_req = sel_req;

    generate
        for (gi = 0; gi < N; gi = gi + 1) begin : g_rsp
            assign c_rsp[gi*RS +: RS] = (gi == sel) ? m_rsp
                                                    : {1'b0, 1'b0, 8'd0, 1'b1};
        end
    endgenerate

endmodule
