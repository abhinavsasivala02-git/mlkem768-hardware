`timescale 1ns / 1ps
module tb_sha3;
    reg clk, rst_n;
    always #5 clk = ~clk;

    reg start, data_valid, data_last;
    reg [7:0] data_in;
    wire data_ready, hash_valid, busy;
    wire [511:0] hash_out;

    sha3_512 u_hash (
        .clk(clk), .rst_n(rst_n), .start(start),
        .data_valid(data_valid), .data_in(data_in), .data_ready(data_ready),
        .data_last(data_last), .hash_valid(hash_valid), .hash_out(hash_out), .busy(busy)
    );

    reg [7:0] msg [0:40];
    integer i;

    task feed_abs;
        input integer len;
        begin
            @(posedge clk); start = 1; @(posedge clk); start = 0;
            i = 0;
            while (i < len) begin
                @(posedge clk);
                if (data_ready) begin
                    data_valid = 1;
                    data_in = msg[i];
                    data_last = (i == len-1);
                    i = i + 1;
                end
            end
            @(posedge clk); data_valid = 0; data_last = 0;
        end
    endtask

    integer j;
    integer wd;
    initial begin
        clk=0; rst_n=0; start=0; data_valid=0; data_last=0; data_in=0;
        #100; rst_n=1; #20;

        // Test 1: SHA3-512("abc")
        $display("=== SHA3-512('abc') ===");
        msg[0]="a"; msg[1]="b"; msg[2]="c";
        feed_abs(3);
        wd = 0;
        while (!hash_valid && wd < 10000) begin @(posedge clk); wd = wd + 1; end
        $display("wd=%0d hash: %h", wd, hash_out);
        $display("exp : b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0");
        $fflush;

        // Test 2: reversed d || K = 0x03 (what keygen feeds)
        $display("=== SHA3-512(rev d || 0x03) ===");
        msg[0]=8'h11; msg[1]=8'h11; msg[2]=8'h00; msg[3]=8'h00; msg[4]=8'h55; msg[5]=8'h55;
        msg[6]=8'hAA; msg[7]=8'hAA; msg[8]=8'h10; msg[9]=8'h32; msg[10]=8'h54; msg[11]=8'h76;
        msg[12]=8'h98; msg[13]=8'hBA; msg[14]=8'hDC; msg[15]=8'hFE; msg[16]=8'hF0; msg[17]=8'hDE;
        msg[18]=8'hBC; msg[19]=8'h9A; msg[20]=8'h78; msg[21]=8'h56; msg[22]=8'h34; msg[23]=8'h12;
        msg[24]=8'hBE; msg[25]=8'hBA; msg[26]=8'hFE; msg[27]=8'hCA; msg[28]=8'hEF; msg[29]=8'hBE;
        msg[30]=8'hAD; msg[31]=8'hDE; msg[32]=8'h03;
        feed_abs(33);
        wd = 0;
        while (!hash_valid && wd < 10000) begin @(posedge clk); wd = wd + 1; end
        $display("wd=%0d hash: %h", wd, hash_out);
        $display("exp : ef6fc44f73386f2eb90a680e243d96909f77c89219461167def289de06fe0190");
        $fflush;

        #100; $finish;
    end
endmodule