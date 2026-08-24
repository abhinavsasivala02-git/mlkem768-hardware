//============================================================================
// ML-KEM Top-Level Testbench
// Verifies KeyGen → Encaps → Decaps round-trip
//
// Test flow:
//   1. Write seeds (d, z, m) via AXI
//   2. Trigger KeyGen, wait for completion
//   3. Trigger Encaps, wait for completion, capture shared secret K1
//   4. Trigger Decaps, wait for completion, capture shared secret K2
//   5. Verify K1 == K2
//
// NOTE: VCD dump is disabled for fast simulation.
//       Uncomment the dumpvars block at the bottom to enable waveform capture.
//============================================================================
`timescale 1ns / 1ps

module tb_mlkem_top;

    // Clock and reset
    reg         clk;
    reg         rst_n;

    // AXI4-Lite signals
    reg  [7:0]  s_axi_awaddr;
    reg         s_axi_awvalid;
    wire        s_axi_awready;
    reg  [31:0] s_axi_wdata;
    reg  [3:0]  s_axi_wstrb;
    reg         s_axi_wvalid;
    wire        s_axi_wready;
    wire [1:0]  s_axi_bresp;
    wire        s_axi_bvalid;
    reg         s_axi_bready;
    reg  [7:0]  s_axi_araddr;
    reg         s_axi_arvalid;
    wire        s_axi_arready;
    wire [31:0] s_axi_rdata;
    wire [1:0]  s_axi_rresp;
    wire        s_axi_rvalid;
    reg         s_axi_rready;
    wire        irq_done;

    // DUT instantiation
    mlkem_top #(
        .K    (3),
        .ETA1 (2),
        .ETA2 (2),
        .DU   (10),
        .DV   (4)
    ) u_dut (
        .clk            (clk),
        .rst_n          (rst_n),
        .s_axi_awaddr   (s_axi_awaddr),
        .s_axi_awvalid  (s_axi_awvalid),
        .s_axi_awready  (s_axi_awready),
        .s_axi_wdata    (s_axi_wdata),
        .s_axi_wstrb    (s_axi_wstrb),
        .s_axi_wvalid   (s_axi_wvalid),
        .s_axi_wready   (s_axi_wready),
        .s_axi_bresp    (s_axi_bresp),
        .s_axi_bvalid   (s_axi_bvalid),
        .s_axi_bready   (s_axi_bready),
        .s_axi_araddr   (s_axi_araddr),
        .s_axi_arvalid  (s_axi_arvalid),
        .s_axi_arready  (s_axi_arready),
        .s_axi_rdata    (s_axi_rdata),
        .s_axi_rresp    (s_axi_rresp),
        .s_axi_rvalid   (s_axi_rvalid),
        .s_axi_rready   (s_axi_rready),
        .irq_done       (irq_done)
    );

    // ===== Clock generation: 100 MHz =====
    initial clk = 0;
    always #5 clk = ~clk;   // 10ns period

    // ===== AXI BFM Tasks =====

    // AXI Write
    task axi_write;
        input [7:0]  addr;
        input [31:0] data;
        begin
            @(posedge clk);
            s_axi_awaddr  <= addr;
            s_axi_awvalid <= 1'b1;
            s_axi_wdata   <= data;
            s_axi_wstrb   <= 4'hF;
            s_axi_wvalid  <= 1'b1;

            // Wait for address handshake
            wait (s_axi_awready && s_axi_awvalid);
            @(posedge clk);
            s_axi_awvalid <= 1'b0;

            // Wait for data handshake
            wait (s_axi_wready && s_axi_wvalid);
            @(posedge clk);
            s_axi_wvalid <= 1'b0;

            // Wait for write response
            wait (s_axi_bvalid);
            @(posedge clk);
            s_axi_bready <= 1'b1;
            @(posedge clk);
            s_axi_bready <= 1'b0;
        end
    endtask

    // AXI Read
    task axi_read;
        input  [7:0]  addr;
        output [31:0] data;
        begin
            @(posedge clk);
            s_axi_araddr  <= addr;
            s_axi_arvalid <= 1'b1;

            wait (s_axi_arready && s_axi_arvalid);
            @(posedge clk);
            s_axi_arvalid <= 1'b0;

            wait (s_axi_rvalid);
            data = s_axi_rdata;
            @(posedge clk);
            s_axi_rready <= 1'b1;
            @(posedge clk);
            s_axi_rready <= 1'b0;
        end
    endtask

    // Wait for operation to complete (polls done bit)
    task wait_done;
        reg [31:0] status;
        integer    timeout_cnt;
        begin
            status      = 32'd0;
            timeout_cnt = 0;
            while (!status[1]) begin
                axi_read(8'h04, status);
                #1000;  // 100 cycles between polls
                timeout_cnt = timeout_cnt + 1;
                if (timeout_cnt % 1000 == 0)
                    $display("  ... still waiting (%0d ms sim-time)", timeout_cnt);
            end
        end
    endtask

    // ===== Shared secret storage =====
    reg [255:0] ss_encaps;
    reg [255:0] ss_decaps;
    reg [31:0]  read_data;

    integer i;

    // ===== Main Test Sequence =====
    initial begin
        $display("============================================");
        $display(" ML-KEM-768 (FIPS 203) RTL Testbench");
        $display("============================================");
        $display("Time: %0t", $time);

        // Initialize signals
        rst_n          = 0;
        s_axi_awaddr   = 0;
        s_axi_awvalid  = 0;
        s_axi_wdata    = 0;
        s_axi_wstrb    = 0;
        s_axi_wvalid   = 0;
        s_axi_bready   = 0;
        s_axi_araddr   = 0;
        s_axi_arvalid  = 0;
        s_axi_rready   = 0;

        // Reset
        #100;
        rst_n = 1;
        #50;

        // ===================================================
        // Step 1: Write seeds
        // ===================================================
        $display("\n[%0t] Step 1: Writing seeds...", $time);

        // Seed d (32 bytes at regs 0x08-0x24)
        axi_write(8'h08, 32'hDEADBEEF);
        axi_write(8'h0C, 32'hCAFEBABE);
        axi_write(8'h10, 32'h12345678);
        axi_write(8'h14, 32'h9ABCDEF0);
        axi_write(8'h18, 32'hFEDCBA98);
        axi_write(8'h1C, 32'h76543210);
        axi_write(8'h20, 32'hAAAAAAAA);
        axi_write(8'h24, 32'h55555555);

        // Seed z (32 bytes at regs 0x28-0x44)
        for (i = 0; i < 8; i = i + 1) begin
            axi_write(8'h28 + i*4, 32'hA5A5A5A5 ^ i);
        end

        // Seed m (32 bytes at regs 0x48-0x64)
        for (i = 0; i < 8; i = i + 1) begin
            axi_write(8'h48 + i*4, 32'h5A5A5A5A ^ (i << 8));
        end

        $display("[%0t] Seeds written.", $time);

        // ===================================================
        // Step 2: KeyGen
        // ===================================================
        $display("\n[%0t] Step 2: Starting KeyGen...", $time);
        axi_write(8'h00, {23'd0, 1'b1, 6'd0, 2'b00});  // op_sel=00, start=1
        wait_done();
        $display("[%0t] KeyGen complete.", $time);

        // ===================================================
        // Step 3: Encaps
        // ===================================================
        $display("\n[%0t] Step 3: Starting Encaps...", $time);
        axi_write(8'h00, {23'd0, 1'b1, 6'd0, 2'b01});  // op_sel=01, start=1
        wait_done();

        // Read shared secret (regs 0x68-0x84)
        for (i = 0; i < 8; i = i + 1) begin
            axi_read(8'h68 + i*4, read_data);
            ss_encaps[i*32 +: 32] = read_data;
        end
        $display("[%0t] Encaps complete. K_encaps = %h", $time, ss_encaps);

        // ===================================================
        // Step 4: Decaps
        // ===================================================
        $display("\n[%0t] Step 4: Starting Decaps...", $time);
        axi_write(8'h00, {23'd0, 1'b1, 6'd0, 2'b10});  // op_sel=10, start=1
        wait_done();

        // Read shared secret
        for (i = 0; i < 8; i = i + 1) begin
            axi_read(8'h68 + i*4, read_data);
            ss_decaps[i*32 +: 32] = read_data;
        end
        $display("[%0t] Decaps complete. K_decaps = %h", $time, ss_decaps);

        // ===================================================
        // Step 5: Verify
        // ===================================================
        $display("\n============================================");
        if (ss_encaps == ss_decaps) begin
            $display(" PASS: Shared secrets match!");
            $display(" K = %h", ss_encaps);
        end else begin
            $display(" FAIL: Shared secrets DO NOT match!");
            $display(" K_encaps = %h", ss_encaps);
            $display(" K_decaps = %h", ss_decaps);
        end
        $display("============================================");

        #1000;
        $finish;
    end

    // ===== Timeout watchdog =====
    initial begin
        #500_000_000;  // 500ms sim time = ~50M cycles
        $display("\nERROR: Simulation timeout at %0t! Design is stuck.", $time);
        $display("  mlkem_core active_op = %0d", u_dut.u_core.active_op);
        $display("  keygen state = %0d, busy = %0b", u_dut.u_core.u_keygen.state, u_dut.u_core.u_keygen.busy);
        $display("  kpke_keygen state = %0d", u_dut.u_core.u_keygen.u_kpke_keygen.state);
        $finish;
    end

    // ===== VCD dump — DISABLED for speed =====
    // initial begin
    //     $dumpfile("mlkem_top.vcd");
    //     $dumpvars(0, tb_mlkem_top);
    // end

endmodule
