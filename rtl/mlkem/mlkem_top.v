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
// ML-KEM Top-Level Module
// FIPS 203 compliant Module-Lattice-Based Key-Encapsulation Mechanism
//
// Default configuration: ML-KEM-768 (NIST Category 3)
//
// Hierarchy:
//   mlkem_top
//   ├── mlkem_axi_lite_if     — AXI4-Lite register interface
//   ├── mlkem_core             — Operation orchestrator
//   │   ├── mlkem_keygen       — ML-KEM.KeyGen (Alg 16)
//   │   │   └── kpke_keygen    — K-PKE.KeyGen (Alg 13)
//   │   ├── mlkem_encaps       — ML-KEM.Encaps (Alg 17)
//   │   │   └── kpke_encrypt   — K-PKE.Encrypt (Alg 14)
//   │   └── mlkem_decaps       — ML-KEM.Decaps (Alg 18)
//   │       ├── kpke_decrypt   — K-PKE.Decrypt (Alg 15)
//   │       └── kpke_encrypt   — K-PKE.Encrypt (re-encrypt for FO)
//   ├── ek_ram                 — Encapsulation key buffer
//   ├── dk_ram                 — Decapsulation key buffer
//   └── ct_ram                 — Ciphertext buffer
//============================================================================
module mlkem_top #(
    parameter K    = 3,
    parameter ETA1 = 2,
    parameter ETA2 = 2,
    parameter DU   = 10,
    parameter DV   = 4
)(
    input  wire        clk,
    input  wire        rst_n,

    // AXI4-Lite Slave Interface
    input  wire [7:0]  s_axi_awaddr,
    input  wire        s_axi_awvalid,
    output wire        s_axi_awready,
    input  wire [31:0] s_axi_wdata,
    input  wire [3:0]  s_axi_wstrb,
    input  wire        s_axi_wvalid,
    output wire        s_axi_wready,
    output wire [1:0]  s_axi_bresp,
    output wire        s_axi_bvalid,
    input  wire        s_axi_bready,
    input  wire [7:0]  s_axi_araddr,
    input  wire        s_axi_arvalid,
    output wire        s_axi_arready,
    output wire [31:0] s_axi_rdata,
    output wire [1:0]  s_axi_rresp,
    output wire        s_axi_rvalid,
    input  wire        s_axi_rready,

    // Interrupt output
    output wire        irq_done
);

    // ===== Internal wires =====

    // AXI-to-Core control
    wire [1:0]   op_sel;
    wire         op_start;
    wire         op_done;
    wire         op_busy;
    wire [255:0] seed_d, seed_z, seed_m;
    wire         ss_valid;
    wire [255:0] shared_secret;

    // Buffer interface from AXI
    wire [12:0]  axi_buf_addr;
    wire [7:0]   axi_buf_wdata;
    wire         axi_buf_wen;
    wire [1:0]   axi_buf_sel;
    wire [7:0]   axi_buf_rdata;

    // Buffer interface from core
    wire [12:0]  core_ek_addr, core_dk_addr, core_ct_addr;
    wire         core_ek_wen,  core_dk_wen,  core_ct_wen;
    wire [7:0]   core_ek_wdata, core_dk_wdata, core_ct_wdata;
    wire [7:0]   core_ek_rdata, core_dk_rdata, core_ct_rdata;

    // ===== EK Buffer RAM =====
    // Max size: 1568 bytes (ML-KEM-1024)
    reg [7:0] ek_mem [0:1567];
    reg [7:0] ek_rdata_reg;

    wire [12:0] ek_addr_mux = op_busy ? core_ek_addr : axi_buf_addr;
    wire        ek_wen_mux  = op_busy ? core_ek_wen  : (axi_buf_wen && axi_buf_sel == 2'd0);
    wire [7:0]  ek_wdata_mux = op_busy ? core_ek_wdata : axi_buf_wdata;

    always @(posedge clk) begin
        if (ek_wen_mux)
            ek_mem[ek_addr_mux] <= ek_wdata_mux;
        ek_rdata_reg <= ek_mem[ek_addr_mux];
    end

    assign core_ek_rdata = ek_rdata_reg;

    // ===== DK Buffer RAM =====
    // Max size: 3168 bytes (ML-KEM-1024)
    reg [7:0] dk_mem [0:3167];
    reg [7:0] dk_rdata_reg;

    wire [12:0] dk_addr_mux = op_busy ? core_dk_addr : axi_buf_addr;
    wire        dk_wen_mux  = op_busy ? core_dk_wen  : (axi_buf_wen && axi_buf_sel == 2'd1);
    wire [7:0]  dk_wdata_mux = op_busy ? core_dk_wdata : axi_buf_wdata;

    always @(posedge clk) begin
        if (dk_wen_mux)
            dk_mem[dk_addr_mux] <= dk_wdata_mux;
        dk_rdata_reg <= dk_mem[dk_addr_mux];
    end

    assign core_dk_rdata = dk_rdata_reg;

    // ===== CT Buffer RAM =====
    // Max size: 1568 bytes (ML-KEM-1024)
    reg [7:0] ct_mem [0:1567];
    reg [7:0] ct_rdata_reg;

    wire [12:0] ct_addr_mux = op_busy ? core_ct_addr : axi_buf_addr;
    wire        ct_wen_mux  = op_busy ? core_ct_wen  : (axi_buf_wen && axi_buf_sel == 2'd2);
    wire [7:0]  ct_wdata_mux = op_busy ? core_ct_wdata : axi_buf_wdata;

    always @(posedge clk) begin
        if (ct_wen_mux)
            ct_mem[ct_addr_mux] <= ct_wdata_mux;
        ct_rdata_reg <= ct_mem[ct_addr_mux];
    end

    assign core_ct_rdata = ct_rdata_reg;

    // AXI buffer read mux
    assign axi_buf_rdata = (axi_buf_sel == 2'd0) ? ek_rdata_reg :
                           (axi_buf_sel == 2'd1) ? dk_rdata_reg :
                           (axi_buf_sel == 2'd2) ? ct_rdata_reg : 8'd0;

    // ===== AXI4-Lite Interface =====
    mlkem_axi_lite_if #(
        .ADDR_WIDTH (8),
        .DATA_WIDTH (32)
    ) u_axi_if (
        .aclk           (clk),
        .aresetn        (rst_n),
        .s_awaddr       (s_axi_awaddr),
        .s_awvalid      (s_axi_awvalid),
        .s_awready      (s_axi_awready),
        .s_wdata        (s_axi_wdata),
        .s_wstrb        (s_axi_wstrb),
        .s_wvalid       (s_axi_wvalid),
        .s_wready       (s_axi_wready),
        .s_bresp        (s_axi_bresp),
        .s_bvalid       (s_axi_bvalid),
        .s_bready       (s_axi_bready),
        .s_araddr       (s_axi_araddr),
        .s_arvalid      (s_axi_arvalid),
        .s_arready      (s_axi_arready),
        .s_rdata        (s_axi_rdata),
        .s_rresp        (s_axi_rresp),
        .s_rvalid       (s_axi_rvalid),
        .s_rready       (s_axi_rready),
        .op_sel         (op_sel),
        .op_start       (op_start),
        .op_done        (op_done),
        .op_busy        (op_busy),
        .seed_d         (seed_d),
        .seed_z         (seed_z),
        .seed_m         (seed_m),
        .ss_valid       (ss_valid),
        .shared_secret  (shared_secret),
        .buf_addr       (axi_buf_addr),
        .buf_wdata      (axi_buf_wdata),
        .buf_wen        (axi_buf_wen),
        .buf_sel        (axi_buf_sel),
        .buf_rdata      (axi_buf_rdata)
    );

    // ===== ML-KEM Core =====
    mlkem_core #(
        .K    (K),
        .ETA1 (ETA1),
        .ETA2 (ETA2),
        .DU   (DU),
        .DV   (DV)
    ) u_core (
        .clk           (clk),
        .rst_n         (rst_n),
        .op_sel        (op_sel),
        .op_start      (op_start),
        .op_done       (op_done),
        .op_busy       (op_busy),
        .seed_d        (seed_d),
        .seed_z        (seed_z),
        .seed_m        (seed_m),
        .ek_addr       (core_ek_addr),
        .ek_wen        (core_ek_wen),
        .ek_wdata      (core_ek_wdata),
        .ek_rdata      (core_ek_rdata),
        .dk_addr       (core_dk_addr),
        .dk_wen        (core_dk_wen),
        .dk_wdata      (core_dk_wdata),
        .dk_rdata      (core_dk_rdata),
        .ct_addr       (core_ct_addr),
        .ct_wen        (core_ct_wen),
        .ct_wdata      (core_ct_wdata),
        .ct_rdata      (core_ct_rdata),
        .ss_valid      (ss_valid),
        .shared_secret (shared_secret)
    );

    // Interrupt: asserted when operation completes
    assign irq_done = op_done;

endmodule
