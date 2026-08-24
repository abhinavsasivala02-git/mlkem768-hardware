`timescale 1ns / 1ps
module tb_ntt_clean;
    reg clk, rst_n;
    always #5 clk = ~clk;

    reg [11:0] mem [0:255];
    wire [11:0] rd_a, rd_b;
    wire r_wen;
    wire [7:0] w_addr;
    wire [7:0] a_addr, b_addr;
    wire [11:0] wdata;
    poly_ram u_ram (.clk(clk),.a_wen(r_wen),.a_addr(a_addr),.a_wdata(wdata),.a_rdata(rd_a),.b_addr(b_addr),.b_rdata(rd_b));

    reg ntt_start;
    wire ntt_done, ntt_busy, ntt_wen;
    wire [7:0] ntt_addr_a, ntt_addr_b;
    wire [11:0] ntt_wdata_a;
    reg mode;
    ntt_core u_ntt (
        .clk(clk),.rst_n(rst_n),.start(ntt_start),.mode(mode),
        .done(ntt_done),.busy(ntt_busy),
        .ram_wen(ntt_wen),.ram_addr_a(ntt_addr_a),.ram_wdata_a(ntt_wdata_a),
        .ram_rdata_a(rd_a),.ram_addr_b(ntt_addr_b),.ram_rdata_b(rd_b)
    );

    assign r_wen = ntt_wen;
    assign a_addr = ntt_addr_a;
    assign b_addr = ntt_addr_b;
    assign wdata = ntt_wdata_a;

    integer i;
    always @(posedge clk) begin
        if (u_ntt.state == 4'd4)
            $display("[%0t] %s layer=%0d start=%0d j=%0d lo=%0d hi=%0d a=%h b=%h zeta=%0d k=%0d", $time, mode? "INTTRD":"NttRD", u_ntt.layer, u_ntt.start_idx, u_ntt.j, u_ntt.addr_lo, u_ntt.addr_hi, u_ntt.ram_rdata_a, u_ntt.ram_rdata_b, u_ntt.zeta_val, u_ntt.k);
        if (u_ntt.state == 4'd6)
            $display("[%0t] %s layer=%0d lo=%0d wdata=%h", $time, mode? "INTWR0":"WR0", u_ntt.layer, u_ntt.addr_lo, u_ntt.bfly_a_out[11:0]);
        if (u_ntt.state == 4'd7)
            $display("[%0t] %s layer=%0d hi=%0d wdata=%h", $time, mode? "INTWR1":"WR1", u_ntt.layer, u_ntt.addr_hi, u_ntt.bfly_b_out[11:0]);
    end
    initial begin
        clk=0; rst_n=0; ntt_start=0; mode=0;
        #100; rst_n=1; #20;
        for (i = 0; i < 256; i = i + 1) u_ram.mem[i] = i[11:0];
        @(posedge clk); ntt_start=1; @(posedge clk); ntt_start=0;
        wait(ntt_done); #20;
        $display("NTT(a)[0..7]:  %h %h %h %h %h %h %h %h", u_ram.mem[0],u_ram.mem[1],u_ram.mem[2],u_ram.mem[3],u_ram.mem[4],u_ram.mem[5],u_ram.mem[6],u_ram.mem[7]);
        $display("NTT(a)[8..15]: %h %h %h %h %h %h %h %h", u_ram.mem[8],u_ram.mem[9],u_ram.mem[10],u_ram.mem[11],u_ram.mem[12],u_ram.mem[13],u_ram.mem[14],u_ram.mem[15]);
        $display("NTTALL:");
        for (i = 0; i < 256; i = i + 1)
            $display("NTT[%0d] = %h", i, u_ram.mem[i]);
        // INTT of the NTT output should restore a
        mode=1;
        @(posedge clk); ntt_start=1; @(posedge clk); ntt_start=0;
        wait(ntt_done); #20;
        $display("INTT[0..7]:   %h %h %h %h %h %h %h %h", u_ram.mem[0],u_ram.mem[1],u_ram.mem[2],u_ram.mem[3],u_ram.mem[4],u_ram.mem[5],u_ram.mem[6],u_ram.mem[7]);
        $display("INTT[8..15]:  %h %h %h %h %h %h %h %h", u_ram.mem[8],u_ram.mem[9],u_ram.mem[10],u_ram.mem[11],u_ram.mem[12],u_ram.mem[13],u_ram.mem[14],u_ram.mem[15]);
        $display("INTTALL:");
        for (i = 0; i < 256; i = i + 1)
            $display("INTT[%0d] = %h", i, u_ram.mem[i]);
        $finish;
    end
endmodule