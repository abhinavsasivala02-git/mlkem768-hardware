`timescale 1ns / 1ps
module tb_kpke_encrypt;
    reg clk, rst_n, start;
    reg [255:0] message, r_seed;
    wire done, busy, ct_valid, ek_req;
    wire [7:0] ct_data; wire [12:0] ct_addr;

    // Fake EK data (just fill with pattern)
    reg ek_valid; reg [7:0] ek_data;
    reg [7:0] ek_buf [0:1183];
    reg [12:0] ek_ptr;

    kpke_encrypt #(.K(3),.ETA1(2),.ETA2(2),.DU(10),.DV(4)) u_dut (
        .clk(clk),.rst_n(rst_n),.start(start),.done(done),.busy(busy),
        .ek_valid(ek_valid),.ek_data(ek_data),.ek_req(ek_req),
        .message(message),.r_seed(r_seed),
        .ct_valid(ct_valid),.ct_data(ct_data),.ct_addr(ct_addr)
    );

    always #5 clk = ~clk;
    integer cc;
    always @(posedge clk) cc <= cc + 1;

    // EK feed FSM: respond to ek_req with next byte
    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            ek_valid <= 0; ek_data <= 0; ek_ptr <= 0;
        end else begin
            ek_valid <= 0;
            if (ek_req && ek_ptr < 13'd1184) begin
                ek_valid <= 1;
                ek_data <= ek_buf[ek_ptr];
                ek_ptr <= ek_ptr + 1;
            end
        end
    end

    // Monitor state transitions  
    reg [5:0] prev_st;
    always @(posedge clk) begin
        if (u_dut.state != prev_st) begin
            $display("[%0t] state: %0d->%0d i=%0d j=%0d cc=%0d", 
                     $time, prev_st, u_dut.state, u_dut.i_cnt, u_dut.j_cnt, cc);
            $fflush; prev_st <= u_dut.state;
        end
    end

    integer i;
    initial begin
        #200_000_000;  // 200ms
        $display("TIMEOUT cc=%0d state=%0d sntt=%0d coeff=%0d shake_st=%0d",
                 cc, u_dut.state, u_dut.u_sample_ntt.state,
                 u_dut.u_sample_ntt.coeff_cnt,
                 u_dut.u_sample_ntt.u_shake128.u_engine.state);
        $fflush; $finish;
    end

    initial begin
        clk=0; rst_n=0; start=0; cc=0; prev_st=0;
        message=256'h5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A;
        r_seed=256'hDEADBEEFCAFEBABE123456789ABCDEF0FEDCBA9876543210AAAAAAA555555555;
        // Fill EK with simple pattern
        for (i = 0; i < 1184; i = i + 1) ek_buf[i] = i[7:0];
        #100; rst_n=1; #20;

        $display("Starting kpke_encrypt..."); $fflush;
        @(posedge clk); start=1;
        @(posedge clk); start=0;

        wait(done);
        $display("DONE! cc=%0d", cc); $fflush;
        #100; $finish;
    end
endmodule
