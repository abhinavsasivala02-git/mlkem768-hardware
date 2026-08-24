`timescale 1ns/1ps
module tb_basemul;
    reg clk, rst_n, start;
    wire done, busy;

    wire [7:0]  a_addr, b_addr;
    wire [11:0] a_rdata, b_rdata;
    wire        c_wen;
    wire [7:0]  c_addr;
    wire [11:0] c_wdata;

    // A and B RAM
    reg [11:0] amem [0:255];
    reg [11:0] bmem [0:255];
    reg [11:0] cmem [0:255];

    integer i;

    poly_basemul u_bm (
        .clk(clk), .rst_n(rst_n), .start(start), .done(done), .busy(busy),
        .a_addr(a_addr), .a_rdata(a_rdata),
        .b_addr(b_addr), .b_rdata(b_rdata),
        .c_wen(c_wen), .c_addr(c_addr), .c_wdata(c_wdata)
    );

    ntt_rom u_rom (.clk(clk), .addr(u_bm.gamma_addr), .zeta(u_bm.gamma_val));

    always #5 clk = ~clk;

    assign a_rdata = amem[a_addr];
    assign b_rdata = bmem[b_addr];

    always @(posedge clk) begin
        if (c_wen) cmem[c_addr] <= c_wdata;
    end

    initial begin
        clk = 0; rst_n = 0; start = 0;
        #50; rst_n = 1; #20;
        // NTT domain values: a[i] = i, b[i] = 256+i mod 3329
        for (i = 0; i < 256; i = i + 1) begin
            amem[i] = i;
            bmem[i] = (256 + i) % 3329;
        end
        @(posedge clk); start = 1; @(posedge clk); start = 0;
        wait(done); #20;
        $display("BM RESULT:");
        for (i = 0; i < 16; i = i + 1)
            $display("BM[%0d] = %h", i, cmem[i]);
        $finish;
    end
endmodule