`timescale 1ns / 1ps
module tb_f1600;
    reg clk, rst_n;
    always #5 clk = ~clk;

    reg start;
    reg [1599:0] state_in;
    wire [1599:0] state_out;
    wire done, busy;

    keccak_f1600 u_perm (
        .clk(clk), .rst_n(rst_n), .start(start),
        .state_in(state_in), .state_out(state_out), .done(done), .busy(busy)
    );

    integer wd;
    initial begin
        clk=0; rst_n=0; start=0; state_in=0;
        #100; rst_n=1; #20;

        // Test 1: Keccak-f[1600] of all-zero state
        $display("=== f1600(0) ===");
        state_in = 1600'd0;
        @(posedge clk); start = 1; @(posedge clk); start = 0;
        wd = 0;
        while (!done && wd < 100) begin @(posedge clk); wd = wd + 1; end
        $display("wd=%0d", wd);
        $display("out: %h", state_out);

        // Test 2: Keccak-f[1600] of a nonzero state (byte 0 = 0x01)
        $display("=== f1600(byte0=0x01) ===");
        state_in = 1600'h01;
        @(posedge clk); start = 1; @(posedge clk); start = 0;
        wd = 0;
        while (!done && wd < 100) begin @(posedge clk); wd = wd + 1; end
        $display("wd=%0d", wd);
        $display("out: %h", state_out);

        #50; $finish;
    end
endmodule