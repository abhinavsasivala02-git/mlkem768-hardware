`timescale 1ns/1ps
//============================================================================
// tb_kat_keycheck — FIPS 203 Sec 7.2 / 7.3 input validation vs NIST ACVP
//
//   Sec 7.2  encapsulation key check : ByteEncode12(ByteDecode12(ek)) == ek,
//            i.e. every 12-bit coefficient must be < q.  ACVP calls a failure
//            "noisy linear system values too large".
//   Sec 7.3  decapsulation key check : the H(ek) field inside dk must equal a
//            freshly computed H(ek).  ACVP calls a failure "modified H".
//
// Each vector carries testPassed: 1 = the key is well formed and must be
// accepted, 0 = malformed and must be rejected (op_error asserted).  Both
// polarities are present, so a check wired to a constant fails this bench.
//
// Vectors from tb/kat/gen_vectors.py.  Build as for tb_kat_multi.v.
//============================================================================
`include "nvec.vh"

module tb_kat_keycheck;

    reg clk = 0, rst_n = 0;
    always #5 clk = ~clk;

    integer errs = 0, tc;

    reg [1:0]  op_sel   = 0;
    reg        op_start = 0;
    wire       op_done, op_error;
    reg [255:0] seed_d = 0, seed_z = 0, seed_m = 0;

    wire [12:0] ek_addr, dk_addr, ct_addr;
    wire        ek_wen, dk_wen, ct_wen;
    wire [7:0]  ek_wdata, dk_wdata, ct_wdata;

    reg [7:0] ek_mem [0:1567];
    reg [7:0] dk_mem [0:3167];
    reg [7:0] ct_mem [0:1087];

    // Registered read, matching mlkem_top's block RAM (2-cycle).
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

    reg [7:0] kc_exp [0:`N_EKC + `N_DKC - 1];   // 1 = accept, 0 = reject

    mlkem_core #(.K(3), .ETA1(2), .ETA2(2), .DU(10), .DV(4)) u_core (
        .clk(clk), .rst_n(rst_n),
        .op_sel(op_sel), .op_start(op_start),
        .op_done(op_done), .op_busy(),
        .seed_d(seed_d), .seed_z(seed_z), .seed_m(seed_m),
        .ek_addr(ek_addr), .ek_wen(ek_wen), .ek_wdata(ek_wdata), .ek_rdata(ek_rdata),
        .dk_addr(dk_addr), .dk_wen(dk_wen), .dk_wdata(dk_wdata), .dk_rdata(dk_rdata),
        .ct_addr(ct_addr), .ct_wen(ct_wen), .ct_wdata(ct_wdata), .ct_rdata(ct_rdata),
        .ss_valid(), .shared_secret(), .op_error(op_error)
    );

    task run_op(input [1:0] op);
        begin
            @(posedge clk); op_sel = op; op_start = 1;
            @(posedge clk); op_start = 0;
            wait (op_done);
            #200;
        end
    endtask

    task check(input integer idx, input [255:0] label);
        reg want_accept;
        begin
            want_accept = (kc_exp[idx] != 8'd0);
            // op_error asserted means the key was rejected.
            if (op_error == want_accept) begin
                $display("  FAIL %0s[%0d]: op_error=%0b but the key should be %0s",
                         label, tc, op_error, want_accept ? "ACCEPTED" : "REJECTED");
                errs = errs + 1;
            end else begin
                $display("  ok   %0s[%0d]: %0s", label, tc,
                         want_accept ? "accepted" : "rejected");
            end
            $fflush;
        end
    endtask

    integer b;
    initial begin
        #900_000_000; $display("TIMEOUT"); $fflush; $finish;
    end

    initial begin
        $readmemh({`V_DIR, "/v_kc_exp.hex"}, kc_exp);
        // A ciphertext is required to run Decaps; its content is irrelevant to
        // the Sec 7.3 key check, which happens before decryption.
        for (b = 0; b < 1088; b = b + 1) ct_mem[b] = 8'h00;

        #100; rst_n = 1; #20;
        $display("=== FIPS 203 Sec 7.2 / 7.3 input checks vs NIST ACVP ===");
        $display("    %0d encapsulationKeyCheck + %0d decapsulationKeyCheck", `N_EKC, `N_DKC);

        // ---- Sec 7.2 : encapsulation key modulus check ----
        for (tc = 0; tc < `N_EKC; tc = tc + 1) begin
            $readmemh($sformatf("%0s/v_ekc%0d_ek.hex", `V_DIR, tc), ek_mem);
            seed_m = 256'd1;                 // content irrelevant to the check
            run_op(2'b01);                   // Encaps
            check(tc, "encapKeyCheck");
        end

        // ---- Sec 7.3 : decapsulation key hash check ----
        for (tc = 0; tc < `N_DKC; tc = tc + 1) begin
            $readmemh($sformatf("%0s/v_dkc%0d_dk.hex", `V_DIR, tc), dk_mem);
            run_op(2'b10);                   // Decaps
            check(`N_EKC + tc, "decapKeyCheck");
        end

        $display("=== %0s : %0d failures over %0d key-check vectors ===",
                 errs ? "KEY CHECK FAILED" : "ALL KEY CHECKS PASS",
                 errs, `N_EKC + `N_DKC);
        $fflush;
        $finish;
    end
endmodule
