//============================================================================
// Direct testbench for mlkem_keygen wrapper (not through AXI)
//============================================================================
`timescale 1ns / 1ps

module tb_mlkem_keygen;

    reg         clk;
    reg         rst_n;
    reg         start;
    reg [255:0] d_seed;
    reg [255:0] z_random;
    wire        done, busy;
    wire        ek_wen, dk_wen;
    wire [12:0] ek_addr, dk_addr;
    wire [7:0]  ek_wdata, dk_wdata;

    mlkem_keygen #(.K(3), .ETA1(2)) u_dut (
        .clk(clk), .rst_n(rst_n), .start(start),
        .d_seed(d_seed), .z_random(z_random),
        .done(done), .busy(busy),
        .ek_wen(ek_wen), .ek_addr(ek_addr), .ek_wdata(ek_wdata),
        .dk_wen(dk_wen), .dk_addr(dk_addr), .dk_wdata(dk_wdata)
    );

    always #5 clk = ~clk;

    integer cycle_cnt;
    always @(posedge clk) cycle_cnt <= cycle_cnt + 1;

    // Monitor state transitions
    reg [3:0] prev_state;
    always @(posedge clk) begin
        if (u_dut.state != prev_state) begin
            $display("[%0t] mlkem_keygen STATE: %0d -> %0d (cyc=%0d)", $time, prev_state, u_dut.state, cycle_cnt);
            prev_state <= u_dut.state;
        end
    end

    // Also monitor kpke_keygen state
    reg [4:0] prev_kpke_state;
    always @(posedge clk) begin
        if (u_dut.u_kpke_keygen.state != prev_kpke_state) begin
            $display("[%0t]   kpke_keygen state: %0d -> %0d", $time, prev_kpke_state, u_dut.u_kpke_keygen.state);
            prev_kpke_state <= u_dut.u_kpke_keygen.state;
        end
    end

    initial begin
        #100_000_000;  // 100ms
        $display("[%0t] TIMEOUT! mlkem_keygen state=%0d, kpke state=%0d", 
                 $time, u_dut.state, u_dut.u_kpke_keygen.state);
        $display("  copy_cnt=%0d, hash_byte_cnt=%0d, ek_buf_len=%0d",
                 u_dut.copy_cnt, u_dut.hash_byte_cnt, u_dut.ek_buf_len);
        $display("  h_data_ready=%b, h_hash_valid=%b",
                 u_dut.h_data_ready, u_dut.h_hash_valid);
        $finish;
    end

    initial begin
        clk = 0; rst_n = 0; start = 0; cycle_cnt = 0;
        prev_state = 0; prev_kpke_state = 0;
        d_seed = 256'hDEADBEEFCAFEBABE123456789ABCDEF0FEDCBA9876543210AAAAAAA555555555;
        z_random = 256'hA5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5;

        #100; rst_n = 1; #20;

        $display("Starting mlkem_keygen...");
        @(posedge clk); start <= 1;
        @(posedge clk); start <= 0;

        wait(done);
        $display("[%0t] DONE! mlkem_keygen completed in %0d cycles.", $time, cycle_cnt);
        #100; $finish;
    end

endmodule
