`timescale 1ns/1ps
//============================================================================
// tb_kat_multi — NIST ACVP known-answer test for ML-KEM-768 (FIPS 203)
//
// Drives mlkem_core through all three top-level algorithms and compares every
// output byte against the official NIST ACVP vectors:
//
//   Algorithm 16  ML-KEM.KeyGen_internal(d, z)  ->  ek, dk
//   Algorithm 17  ML-KEM.Encaps_internal(ek, m) ->  c, K
//   Algorithm 18  ML-KEM.Decaps_internal(dk, c) ->  K
//
// The decapsulation set deliberately mixes valid ciphertexts with modified
// ones: a broken ciphertext comparison passes the modified vectors while
// failing the valid ones (or vice versa), so both kinds are required to
// actually exercise the implicit-rejection path.
//
// Vectors are produced by tb/kat/gen_vectors.py, which reads them out of the
// NIST ACVP JSON. nvec.vh is generated alongside them.
//
// Build (from MLKEM_work/, vectors already generated into tb/kat/vectors/):
//   iverilog -g2012 -I tb/kat/vectors -I rtl/pkg -o kat.vvp \
//            tb/tb_kat_multi.v $(find rtl -name '*.v' ! -name '*_copy.v')
//   vvp kat.vvp
//
// The buffers are modelled as registered-read (2-cycle) RAM, which is what
// mlkem_top infers as block RAM and what mlkem_core's feed logic is written
// against.  tb_mlkem_top exercises the same contract through the AXI interface.
//============================================================================
`include "nvec.vh"

module tb_kat_multi;

    reg clk = 0, rst_n = 0;
    always #5 clk = ~clk;

    integer errs = 0, tc;

    reg [1:0]   op_sel   = 0;
    reg         op_start = 0;
    wire        op_done;
    wire [255:0] shared_secret;
    reg [255:0] seed_d = 0, seed_z = 0, seed_m = 0;

    // ---- external buffers (asynchronous read) ----
    wire [12:0] ek_addr, dk_addr, ct_addr;
    wire        ek_wen, dk_wen, ct_wen;
    wire [7:0]  ek_wdata, dk_wdata, ct_wdata;

    reg [7:0] ek_mem [0:1567];
    reg [7:0] dk_mem [0:3167];
    reg [7:0] ct_mem [0:1087];

    // Registered (synchronous) read, matching mlkem_top's block-RAM buffers:
    // the byte for an address issued at cycle t appears at t+2.  That is the
    // interface contract mlkem_core is written against, so the bench must model
    // it -- an asynchronous read here would exercise timing the real SoC
    // integration never produces.
    reg [7:0] ek_rdata_r, dk_rdata_r, ct_rdata_r;
    always @(posedge clk) begin
        ek_rdata_r <= ek_mem[ek_addr];
        dk_rdata_r <= dk_mem[dk_addr];
        ct_rdata_r <= ct_mem[ct_addr];
    end
    wire [7:0] ek_rdata = ek_rdata_r;
    wire [7:0] dk_rdata = dk_rdata_r;
    wire [7:0] ct_rdata = ct_rdata_r;

    always @(posedge clk) begin
        if (ek_wen) ek_mem[ek_addr] <= ek_wdata;
        if (dk_wen) dk_mem[dk_addr] <= dk_wdata;
        if (ct_wen) ct_mem[ct_addr] <= ct_wdata;
    end

    // ---- expected values ----
    reg [7:0] exp_ek [0:1183];
    reg [7:0] exp_dk [0:2399];
    reg [7:0] exp_c  [0:1087];
    reg [7:0] seedbuf[0:31];       // scratch for any 32-byte value

    mlkem_core #(.K(3), .ETA1(2), .ETA2(2), .DU(10), .DV(4)) u_core (
        .clk(clk), .rst_n(rst_n),
        .op_sel(op_sel), .op_start(op_start),
        .op_done(op_done), .op_busy(),
        .seed_d(seed_d), .seed_z(seed_z), .seed_m(seed_m),
        .ek_addr(ek_addr), .ek_wen(ek_wen), .ek_wdata(ek_wdata), .ek_rdata(ek_rdata),
        .dk_addr(dk_addr), .dk_wen(dk_wen), .dk_wdata(dk_wdata), .dk_rdata(dk_rdata),
        .ct_addr(ct_addr), .ct_wen(ct_wen), .ct_wdata(ct_wdata), .ct_rdata(ct_rdata),
        .ss_valid(), .shared_secret(shared_secret)
    );

    // Seeds are byte strings; the 256-bit port holds byte i at [i*8 +: 8].
    function [255:0] seed_of(input integer unused);
        integer b; reg [255:0] v;
        begin
            v = 256'd0;
            for (b = 0; b < 32; b = b + 1) v[b*8 +: 8] = seedbuf[b];
            seed_of = v;
        end
    endfunction

    task run_op(input [1:0] op);
        begin
            @(posedge clk); op_sel = op; op_start = 1;
            @(posedge clk); op_start = 0;
            wait (op_done);
            #200;
        end
    endtask

    // which: 0 = ek, 1 = dk, 2 = ct
    task cmp_mem(input integer n, input integer which);
        integer i, bad; reg [7:0] got, exp;
        begin
            bad = 0;
            for (i = 0; i < n; i = i + 1) begin
                got = (which == 0) ? ek_mem[i] : (which == 1) ? dk_mem[i] : ct_mem[i];
                exp = (which == 0) ? exp_ek[i] : (which == 1) ? exp_dk[i] : exp_c[i];
                if (got !== exp) begin
                    if (bad < 3)
                        $display("    byte %0d: got %h exp %h", i, got, exp);
                    bad = bad + 1;
                end
            end
            if (bad) begin
                $display("  FAIL tc=%0d buf=%0d : %0d/%0d bytes differ", tc, which, bad, n);
                errs = errs + 1;
            end
            $fflush;
        end
    endtask

    task cmp_ss;
        integer i; reg [255:0] exp;
        begin
            exp = 256'd0;
            for (i = 0; i < 32; i = i + 1) exp[i*8 +: 8] = seedbuf[i];
            if (shared_secret !== exp) begin
                $display("  FAIL tc=%0d K : got %h", tc, shared_secret);
                $display("                exp %h", exp);
                errs = errs + 1;
            end
            $fflush;
        end
    endtask

    initial begin
        #900_000_000;
        $display("TIMEOUT - design stuck (decaps state=%0d)", u_core.u_decaps.state);
        $fflush; $finish;
    end

    initial begin
        #100; rst_n = 1; #20;
        $display("=== NIST ACVP ML-KEM-768 KAT, full FIPS 203 (Alg 16/17/18) ===");
        $display("    %0d keyGen + %0d encaps + %0d decaps vectors",
                 `N_KG, `N_EN, `N_DE);

        // ---------------- Algorithm 16: KeyGen ----------------
        for (tc = 0; tc < `N_KG; tc = tc + 1) begin
            $readmemh($sformatf("%0s/v_kg%0d_d.hex",  `V_DIR, tc), seedbuf);
            seed_d = seed_of(0);
            $readmemh($sformatf("%0s/v_kg%0d_z.hex",  `V_DIR, tc), seedbuf);
            seed_z = seed_of(0);
            $readmemh($sformatf("%0s/v_kg%0d_ek.hex", `V_DIR, tc), exp_ek);
            $readmemh($sformatf("%0s/v_kg%0d_dk.hex", `V_DIR, tc), exp_dk);
            run_op(2'b00);
            cmp_mem(1184, 0);      // ek
            cmp_mem(2400, 1);      // dk = dk_PKE || ek || H(ek) || z
            $display("  keyGen[%0d] ok=%0d", tc, errs == 0); $fflush;
        end

        // ---------------- Algorithm 17: Encaps ----------------
        for (tc = 0; tc < `N_EN; tc = tc + 1) begin
            $readmemh($sformatf("%0s/v_en%0d_ek.hex", `V_DIR, tc), ek_mem);
            $readmemh($sformatf("%0s/v_en%0d_m.hex",  `V_DIR, tc), seedbuf);
            seed_m = seed_of(0);
            $readmemh($sformatf("%0s/v_en%0d_c.hex",  `V_DIR, tc), exp_c);
            run_op(2'b01);
            cmp_mem(1088, 2);      // c
            $readmemh($sformatf("%0s/v_en%0d_k.hex",  `V_DIR, tc), seedbuf);
            cmp_ss;                // K
            $display("  encaps[%0d] ok=%0d", tc, errs == 0); $fflush;
        end

        // ---------------- Algorithm 18: Decaps ----------------
        for (tc = 0; tc < `N_DE; tc = tc + 1) begin
            $readmemh($sformatf("%0s/v_de%0d_dk.hex", `V_DIR, tc), dk_mem);
            $readmemh($sformatf("%0s/v_de%0d_c.hex",  `V_DIR, tc), ct_mem);
            run_op(2'b10);
            $readmemh($sformatf("%0s/v_de%0d_k.hex",  `V_DIR, tc), seedbuf);
            cmp_ss;                // K (valid) or K_bar (implicit rejection)
            $display("  decaps[%0d] ok=%0d", tc, errs == 0); $fflush;
        end

        $display("=== %0s : %0d failures over %0d vectors ===",
                 errs ? "KAT FAILED" : "ALL VECTORS PASS",
                 errs, `N_KG + `N_EN + `N_DE);
        $fflush;
        $finish;
    end
endmodule
