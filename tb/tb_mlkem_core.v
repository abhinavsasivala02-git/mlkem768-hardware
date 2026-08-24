`timescale 1ns / 1ps
module tb_mlkem_core;
    reg clk, rst_n; reg [1:0] op_sel; reg op_start;
    wire op_done, op_busy, ss_valid; wire [255:0] shared_secret;
    reg [255:0] seed_d, seed_z, seed_m;
    wire [12:0] ek_addr, dk_addr, ct_addr;
    wire ek_wen, dk_wen, ct_wen;
    wire [7:0] ek_wdata, dk_wdata, ct_wdata;
    reg [7:0] ek_mem [0:1567]; reg [7:0] dk_mem [0:3167]; reg [7:0] ct_mem [0:1087];
    wire [7:0] ek_rdata = ek_mem[ek_addr];
    wire [7:0] dk_rdata = dk_mem[dk_addr];
    wire [7:0] ct_rdata = ct_mem[ct_addr];
    always @(posedge clk) begin
        if (ek_wen) ek_mem[ek_addr] <= ek_wdata;
        if (dk_wen) dk_mem[dk_addr] <= dk_wdata;
        if (ct_wen) ct_mem[ct_addr] <= ct_wdata;
    end
    mlkem_core #(.K(3),.ETA1(2),.ETA2(2),.DU(10),.DV(4)) u_core (
        .clk(clk),.rst_n(rst_n),.op_sel(op_sel),.op_start(op_start),
        .op_done(op_done),.op_busy(op_busy),
        .seed_d(seed_d),.seed_z(seed_z),.seed_m(seed_m),
        .ek_addr(ek_addr),.ek_wen(ek_wen),.ek_wdata(ek_wdata),.ek_rdata(ek_rdata),
        .dk_addr(dk_addr),.dk_wen(dk_wen),.dk_wdata(dk_wdata),.dk_rdata(dk_rdata),
        .ct_addr(ct_addr),.ct_wen(ct_wen),.ct_wdata(ct_wdata),.ct_rdata(ct_rdata),
        .ss_valid(ss_valid),.shared_secret(shared_secret)
    );
    always #5 clk = ~clk;
    integer cc;
    always @(posedge clk) cc <= cc + 1;

    // Monitor encaps internals
    reg [3:0] prev_enc; reg [5:0] prev_kpke;
    always @(posedge clk) begin
        if (u_core.u_encaps.state != prev_enc) begin
            $display("[%0t] encaps: %0d->%0d cc=%0d", $time, prev_enc, u_core.u_encaps.state, cc);
            $fflush; prev_enc <= u_core.u_encaps.state;
        end
        if (u_core.u_encaps.u_kpke_enc.state != prev_kpke) begin
            $display("[%0t]   kpke_enc: %0d->%0d i=%0d j=%0d", $time, prev_kpke,
                     u_core.u_encaps.u_kpke_enc.state,
                     u_core.u_encaps.u_kpke_enc.i_cnt,
                     u_core.u_encaps.u_kpke_enc.j_cnt);
            $fflush; prev_kpke <= u_core.u_encaps.u_kpke_enc.state;
        end
    end

    initial begin
        #30_000_000;  // 30ms = 3M cycles
        $display("TIMEOUT cc=%0d enc_st=%0d kpke_st=%0d sntt_st=%0d sntt_busy=%b",
                 cc, u_core.u_encaps.state,
                 u_core.u_encaps.u_kpke_enc.state,
                 u_core.u_encaps.u_kpke_enc.u_sample_ntt.state,
                 u_core.u_encaps.u_kpke_enc.u_sample_ntt.busy);
        $display("  sntt_coeff=%0d shake_st=%0d shake_busy=%b",
                 u_core.u_encaps.u_kpke_enc.u_sample_ntt.coeff_cnt,
                 u_core.u_encaps.u_kpke_enc.u_sample_ntt.u_shake128.u_engine.state,
                 u_core.u_encaps.u_kpke_enc.u_sample_ntt.u_shake128.busy);
        $fflush; $finish;
    end

    initial begin
        clk=0; rst_n=0; op_start=0; op_sel=0; cc=0; prev_enc=0; prev_kpke=0;
        seed_d=256'hDEADBEEF; seed_z=256'hA5A5A5A5; seed_m=256'h5A5A5A5A;
        #100; rst_n=1; #20;
        $display("START keygen"); $fflush;
        @(posedge clk); op_sel=2'b00; op_start=1;
        @(posedge clk); op_start=0;
        wait(op_done);
        $display("KEYGEN DONE cc=%0d", cc); $fflush;
        #100;
        $display("START encaps"); $fflush;
        @(posedge clk); op_sel=2'b01; op_start=1;
        @(posedge clk); op_start=0;
        wait(op_done);
        $display("ENCAPS DONE cc=%0d", cc); $fflush;
        #100; $finish;
    end
endmodule
