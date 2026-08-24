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
// AXI4-Lite Slave Interface for ML-KEM
// Provides register-mapped access to ML-KEM operations
//
// Register Map:
//   0x00  CTRL      [W]  - [1:0] op_sel (00=KG,01=EC,10=DC), [8] start
//   0x04  STATUS    [R]  - [0] busy, [1] done, [2] error
//   0x08  SEED_D_0  [W]  - Seed d bytes [3:0]
//   0x0C  SEED_D_1  [W]  - Seed d bytes [7:4]
//   ...   (8 regs for 32-byte seed d: 0x08-0x24)
//   0x28  SEED_Z_0  [W]  - Seed z bytes [3:0]
//   ...   (8 regs for 32-byte seed z: 0x28-0x44)
//   0x48  SEED_M_0  [W]  - Seed m bytes [3:0]
//   ...   (8 regs for 32-byte seed m: 0x48-0x64)
//   0x68  SS_0      [R]  - Shared secret bytes [3:0]
//   ...   (8 regs for 32-byte shared secret: 0x68-0x84)
//   0x88  BUF_ADDR  [W]  - Buffer address for EK/DK/CT access
//   0x8C  BUF_DATA  [R/W]- Buffer data (auto-increment)
//   0x90  BUF_SEL   [W]  - Buffer select: 0=EK, 1=DK, 2=CT
//============================================================================
module mlkem_axi_lite_if #(
    parameter ADDR_WIDTH = 8,
    parameter DATA_WIDTH = 32
)(
    input  wire                    aclk,
    input  wire                    aresetn,

    // AXI4-Lite Write Address Channel
    input  wire [ADDR_WIDTH-1:0]   s_awaddr,
    input  wire                    s_awvalid,
    output reg                     s_awready,

    // AXI4-Lite Write Data Channel
    input  wire [DATA_WIDTH-1:0]   s_wdata,
    input  wire [3:0]              s_wstrb,
    input  wire                    s_wvalid,
    output reg                     s_wready,

    // AXI4-Lite Write Response Channel
    output reg  [1:0]              s_bresp,
    output reg                     s_bvalid,
    input  wire                    s_bready,

    // AXI4-Lite Read Address Channel
    input  wire [ADDR_WIDTH-1:0]   s_araddr,
    input  wire                    s_arvalid,
    output reg                     s_arready,

    // AXI4-Lite Read Data Channel
    output reg  [DATA_WIDTH-1:0]   s_rdata,
    output reg  [1:0]              s_rresp,
    output reg                     s_rvalid,
    input  wire                    s_rready,

    // Internal interface to ML-KEM core
    output reg  [1:0]              op_sel,
    output reg                     op_start,
    input  wire                    op_done,
    input  wire                    op_busy,

    // Seeds
    output reg  [255:0]            seed_d,
    output reg  [255:0]            seed_z,
    output reg  [255:0]            seed_m,

    // Shared secret
    input  wire                    ss_valid,
    input  wire [255:0]            shared_secret,

    // Buffer access
    output reg  [12:0]             buf_addr,
    output reg  [7:0]              buf_wdata,
    output reg                     buf_wen,
    output reg  [1:0]              buf_sel,    // 0=EK, 1=DK, 2=CT
    input  wire [7:0]              buf_rdata
);

    // Internal registers
    reg         done_sticky;
    reg [255:0] ss_reg;

    // Write transaction
    reg [ADDR_WIDTH-1:0] wr_addr;
    reg                  wr_addr_valid;
    reg                  wr_data_valid;
    reg [DATA_WIDTH-1:0] wr_data;

    // AXI Write FSM
    always @(posedge aclk or negedge aresetn) begin
        if (!aresetn) begin
            s_awready     <= 1'b1;
            s_wready      <= 1'b1;
            s_bvalid      <= 1'b0;
            s_bresp       <= 2'b00;
            wr_addr       <= {ADDR_WIDTH{1'b0}};
            wr_addr_valid <= 1'b0;
            wr_data_valid <= 1'b0;
            wr_data       <= {DATA_WIDTH{1'b0}};
            op_sel        <= 2'b00;
            op_start      <= 1'b0;
            seed_d        <= 256'd0;
            seed_z        <= 256'd0;
            seed_m        <= 256'd0;
            buf_addr      <= 13'd0;
            buf_wdata     <= 8'd0;
            buf_wen       <= 1'b0;
            buf_sel       <= 2'd0;
            done_sticky   <= 1'b0;
        end else begin
            op_start <= 1'b0;
            buf_wen  <= 1'b0;

            if (op_done) done_sticky <= 1'b1;

            // Capture write address
            if (s_awvalid && s_awready) begin
                wr_addr       <= s_awaddr;
                wr_addr_valid <= 1'b1;
                s_awready     <= 1'b0;
            end

            // Capture write data
            if (s_wvalid && s_wready) begin
                wr_data       <= s_wdata;
                wr_data_valid <= 1'b1;
                s_wready      <= 1'b0;
            end

            // Process write when both address and data are captured
            if (wr_addr_valid && wr_data_valid) begin
                wr_addr_valid <= 1'b0;
                wr_data_valid <= 1'b0;
                s_awready     <= 1'b1;
                s_wready      <= 1'b1;
                s_bvalid      <= 1'b1;
                s_bresp       <= 2'b00;  // OKAY

                case (wr_addr[7:2])
                    // CTRL register
                    6'd0: begin
                        op_sel  <= wr_data[1:0];
                        if (wr_data[8]) begin
                            op_start    <= 1'b1;
                            done_sticky <= 1'b0;
                        end
                    end
                    // SEED_D[0..7]
                    6'd2:  seed_d[31:0]    <= wr_data;
                    6'd3:  seed_d[63:32]   <= wr_data;
                    6'd4:  seed_d[95:64]   <= wr_data;
                    6'd5:  seed_d[127:96]  <= wr_data;
                    6'd6:  seed_d[159:128] <= wr_data;
                    6'd7:  seed_d[191:160] <= wr_data;
                    6'd8:  seed_d[223:192] <= wr_data;
                    6'd9:  seed_d[255:224] <= wr_data;
                    // SEED_Z[0..7]
                    6'd10: seed_z[31:0]    <= wr_data;
                    6'd11: seed_z[63:32]   <= wr_data;
                    6'd12: seed_z[95:64]   <= wr_data;
                    6'd13: seed_z[127:96]  <= wr_data;
                    6'd14: seed_z[159:128] <= wr_data;
                    6'd15: seed_z[191:160] <= wr_data;
                    6'd16: seed_z[223:192] <= wr_data;
                    6'd17: seed_z[255:224] <= wr_data;
                    // SEED_M[0..7]
                    6'd18: seed_m[31:0]    <= wr_data;
                    6'd19: seed_m[63:32]   <= wr_data;
                    6'd20: seed_m[95:64]   <= wr_data;
                    6'd21: seed_m[127:96]  <= wr_data;
                    6'd22: seed_m[159:128] <= wr_data;
                    6'd23: seed_m[191:160] <= wr_data;
                    6'd24: seed_m[223:192] <= wr_data;
                    6'd25: seed_m[255:224] <= wr_data;
                    // BUF_ADDR
                    6'd34: buf_addr <= wr_data[12:0];
                    // BUF_DATA (write)
                    6'd35: begin
                        buf_wen   <= 1'b1;
                        buf_wdata <= wr_data[7:0];
                        buf_addr  <= buf_addr + 13'd1;  // auto-increment
                    end
                    // BUF_SEL
                    6'd36: buf_sel <= wr_data[1:0];
                    default: ;
                endcase
            end

            // Write response handshake
            if (s_bvalid && s_bready)
                s_bvalid <= 1'b0;

            // BUF_DATA read auto-increment (handled here to avoid multi-driver)
            if (s_arvalid && s_arready && (s_araddr[7:2] == 6'd35))
                buf_addr <= buf_addr + 13'd1;

            // Latch shared secret
            if (ss_valid)
                ss_reg <= shared_secret;
        end
    end

    // AXI Read FSM
    always @(posedge aclk or negedge aresetn) begin
        if (!aresetn) begin
            s_arready <= 1'b1;
            s_rvalid  <= 1'b0;
            s_rdata   <= 32'd0;
            s_rresp   <= 2'b00;
        end else begin
            if (s_arvalid && s_arready) begin
                s_arready <= 1'b0;
                s_rvalid  <= 1'b1;
                s_rresp   <= 2'b00;

                case (s_araddr[7:2])
                    // STATUS
                    6'd1:  s_rdata <= {29'd0, 1'b0, done_sticky, op_busy};
                    // SS[0..7]
                    6'd26: s_rdata <= ss_reg[31:0];
                    6'd27: s_rdata <= ss_reg[63:32];
                    6'd28: s_rdata <= ss_reg[95:64];
                    6'd29: s_rdata <= ss_reg[127:96];
                    6'd30: s_rdata <= ss_reg[159:128];
                    6'd31: s_rdata <= ss_reg[191:160];
                    6'd32: s_rdata <= ss_reg[223:192];
                    6'd33: s_rdata <= ss_reg[255:224];
                    // BUF_DATA (read)
                    6'd35: begin
                        s_rdata  <= {24'd0, buf_rdata};
                    end
                    default: s_rdata <= 32'd0;
                endcase
            end

            if (s_rvalid && s_rready) begin
                s_rvalid  <= 1'b0;
                s_arready <= 1'b1;
            end
        end
    end

endmodule