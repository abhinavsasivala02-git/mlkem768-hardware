// =============================================================================
// tb_mlkem_nist_kat.v — ML-KEM-768 (FIPS 203) NIST Known-Answer-Test
//
// Runs a slice of the pre-generated NIST KL-TEM KAT vectors (sim/mem/nist/<i>/)
// and checks KeyGen → Encaps → Decaps byte-exact against the reference.
//
// Usage (Vivado xsim): run in one-vector slices to avoid long runs:
//   xsim -R nist_sim -testplusarg NIST_START=<i> -testplusarg NIST_END=<i>
//
// Include dirs needed: -i rtl/pkg -i sim/mem
// =============================================================================
`timescale 1ns / 1ps
`include "mlkem_kat_vectors.vh"

module tb_mlkem_nist_kat;

    reg clk, rst_n;
    always #5 clk = ~clk;

    // ---- seeds (from .vh, LSB-first) ----
    reg [255:0] d_seed, z_seed, m_seed;

    // ---- buffer memories ----
    reg [7:0] ek_mem [0:1183];   // DUT ek (written by keygen, read by encaps)
    reg [7:0] dk_mem [0:2399];   // DUT dk
    reg [7:0] ct_mem [0:1087];   // DUT ct
    reg [7:0] ek_rdata, dk_rdata, ct_rdata;

    // ---- expected (loaded from .mem) ----
    reg [7:0] exp_ek [0:1183];
    reg [7:0] exp_dk [0:2399];
    reg [7:0] exp_ct [0:1087];
    reg [7:0] exp_k  [0:31];
    reg [255:0] ss_reg;

    // ---- mlkem_keygen (writes ek/dk) ----
    wire kg_done, kg_busy, kg_ek_wen, kg_dk_wen;
    wire [12:0] kg_ek_addr, kg_dk_addr;
    wire [7:0]  kg_ek_wdata, kg_dk_wdata;
    reg kg_start;
    mlkem_keygen #(.K(3),.ETA1(2)) u_kg (
        .clk(clk),.rst_n(rst_n),.start(kg_start),
        .d_seed(d_seed),.z_random(z_seed),
        .done(kg_done),.busy(kg_busy),
        .ek_wen(kg_ek_wen),.ek_addr(kg_ek_addr),.ek_wdata(kg_ek_wdata),
        .dk_wen(kg_dk_wen),.dk_addr(kg_dk_addr),.dk_wdata(kg_dk_wdata)
    );

    // ---- mlkem_encaps (reads ek, writes ct + ss) ----
    wire enc_done, enc_busy, enc_ss_valid, enc_ct_wen;
    wire [12:0] enc_ek_raddr, enc_ct_addr;
    wire [7:0]  enc_ct_wdata;
    wire [255:0] enc_ss;
    reg enc_start;
    mlkem_encaps #(.K(3),.ETA1(2),.ETA2(2),.DU(10),.DV(4)) u_enc (
        .clk(clk),.rst_n(rst_n),.start(enc_start),
        .m_random(m_seed),
        .done(enc_done),.busy(enc_busy),
        .ek_rdata(ek_rdata),.ek_raddr(enc_ek_raddr),
        .ct_wen(enc_ct_wen),.ct_addr(enc_ct_addr),.ct_wdata(enc_ct_wdata),
        .ss_valid(enc_ss_valid),.shared_secret(enc_ss)
    );

    // ---- mlkem_decaps (reads dk + ct, writes ss) ----
    wire dec_done, dec_busy, dec_ss_valid;
    wire [12:0] dec_dk_raddr, dec_ct_raddr;
    wire [255:0] dec_ss;
    reg dec_start;
    mlkem_decaps #(.K(3),.ETA1(2),.ETA2(2),.DU(10),.DV(4)) u_dec (
        .clk(clk),.rst_n(rst_n),.start(dec_start),
        .done(dec_done),.busy(dec_busy),
        .dk_rdata(dk_rdata),.dk_raddr(dec_dk_raddr),
        .ct_rdata(ct_rdata),.ct_raddr(dec_ct_raddr),
        .ss_valid(dec_ss_valid),.shared_secret(dec_ss)
    );

    // ---- buffer write/read glue (registered 1-cycle reads, like mlkem_top) ----
    always @(posedge clk) begin
        if (kg_ek_wen) ek_mem[kg_ek_addr] <= kg_ek_wdata;
        if (kg_dk_wen) dk_mem[kg_dk_addr] <= kg_dk_wdata;
        if (enc_ct_wen) ct_mem[enc_ct_addr] <= enc_ct_wdata;
    end
    always @(posedge clk) begin
        ek_rdata <= ek_mem[enc_ek_raddr];
        dk_rdata <= dk_mem[dec_dk_raddr];
        ct_rdata <= ct_mem[dec_ct_raddr];
    end
    always @(posedge clk) if (enc_ss_valid) ss_reg <= enc_ss;
    always @(posedge clk) if (dec_ss_valid) ss_reg <= dec_ss;

    // ---- helpers ----
    integer i, j, n, nstart, nend, errors, phase;
    reg kg_ok, enc_ok, dec_ok;

    task reset_dut;
        begin
            rst_n = 0; kg_start=0; enc_start=0; dec_start=0;
            d_seed=0; z_seed=0; m_seed=0;
            #50; rst_n = 1; #20;
        end
    endtask

    // Byte compare helper
    task cmp_buf;
        input [31:0] len;
        input integer kind;   // 0=ek 1=dk 2=ct 3=ss
        output integer ok;
        integer x;
        begin
            ok = 1;
            for (x = 0; x < len; x = x + 1) begin
                case (kind)
                    0: if (ek_mem[x] !== exp_ek[x]) ok = 0;
                    1: if (dk_mem[x] !== exp_dk[x]) ok = 0;
                    2: if (ct_mem[x] !== exp_ct[x]) ok = 0;
                    3: if (ss_reg[x*8 +: 8] !== exp_k[x]) ok = 0;
                endcase
                if (!ok) begin $display("  mismatch at byte %0d", x); x = len; end
            end
        end
    endtask

    // Run one vector and verify all three phases — see the main `initial` block.

    integer wd;

    initial begin
        clk=0; rst_n=0; kg_start=0; enc_start=0; dec_start=0;
        d_seed=0; z_seed=0; m_seed=0; ss_reg=0;
        ek_rdata=0; dk_rdata=0; ct_rdata=0;
        for (i=0;i<1184;i=i+1) ek_mem[i]=0;
        for (i=0;i<2400;i=i+1) dk_mem[i]=0;
        for (i=0;i<1088;i=i+1) ct_mem[i]=0;

        nstart = 0; nend = `NUM_KAT_VECTORS - 1; phase = 0;
        if ($value$plusargs("NIST_START=%d", nstart)) ;
        if ($value$plusargs("NIST_END=%d", nend)) ;
        if ($value$plusargs("PHASE=%d", phase)) ;   // 0=all 1=keygen 2=encaps 3=decaps
        $display("=== ML-KEM-768 NIST KAT: vectors %0d..%0d (phase %0d) ===", nstart, nend, phase);

        for (n = nstart; n <= nend; n = n + 1) begin
            errors = 0;

            // pick seeds & load expected from .mem
            case (n)
                0:  begin d_seed = KAT0_D; z_seed = KAT0_Z; m_seed = KAT0_M; end
                1:  begin d_seed = KAT1_D; z_seed = KAT1_Z; m_seed = KAT1_M; end
                2:  begin d_seed = KAT2_D; z_seed = KAT2_Z; m_seed = KAT2_M; end
                3:  begin d_seed = KAT3_D; z_seed = KAT3_Z; m_seed = KAT3_M; end
                4:  begin d_seed = KAT4_D; z_seed = KAT4_Z; m_seed = KAT4_M; end
                5:  begin d_seed = KAT5_D; z_seed = KAT5_Z; m_seed = KAT5_M; end
                6:  begin d_seed = KAT6_D; z_seed = KAT6_Z; m_seed = KAT6_M; end
                7:  begin d_seed = KAT7_D; z_seed = KAT7_Z; m_seed = KAT7_M; end
                8:  begin d_seed = KAT8_D; z_seed = KAT8_Z; m_seed = KAT8_M; end
                9:  begin d_seed = KAT9_D; z_seed = KAT9_Z; m_seed = KAT9_M; end
            endcase
            $readmemh($sformatf("sim/mem/nist/%0d/ek_%0d.mem", n, n), exp_ek);
            $readmemh($sformatf("sim/mem/nist/%0d/dk_%0d.mem", n, n), exp_dk);
            $readmemh($sformatf("sim/mem/nist/%0d/c_%0d.mem",  n, n), exp_ct);
            $readmemh($sformatf("sim/mem/nist/%0d/k_%0d.mem",  n, n), exp_k);

            // ---- 1) KeyGen ----
            if (phase == 0 || phase == 1) begin
                $display("[%0d] KeyGen vector %0d ...", $time, n);
                kg_start=1; @(posedge clk); kg_start=0;
                while (!kg_done) @(posedge clk);
                #20; cmp_buf(1184, 0, kg_ok);
                cmp_buf(2400, 1, kg_ok);
                $display("  KeyGen ek/dk: %s", (kg_ok ? "PASS" : "FAIL"));
                if (!kg_ok) errors = errors + 1;
            end

            // ---- 2) Encaps (uses ek_mem produced by keygen) ----
            if (phase == 0 || phase == 2) begin
                if (phase != 2) begin
                    // reuse ek_mem from keygen
                end else begin
                    // load ek from .mem for standalone encaps
                    $readmemh($sformatf("sim/mem/nist/%0d/ek_%0d.mem", n, n), ek_mem);
                end
                $display("[%0d] Encaps  vector %0d ...", $time, n);
                enc_start=1; @(posedge clk); enc_start=0;
                while (!enc_done) @(posedge clk);
                cmp_buf(1088, 2, enc_ok);
                cmp_buf(32, 3, enc_ok);
                $display("  Encaps ct/K: %s", (enc_ok ? "PASS" : "FAIL"));
                if (!enc_ok) errors = errors + 1;
            end

            // ---- 3) Decaps (uses exp_dk + ct_mem from encap) ----
            if (phase == 0 || phase == 3) begin
                if (phase != 3) begin
                    // decaps uses dk_mem (keygen) + ct_mem (encaps)
                end else begin
                    // standalone decaps: load dk/ct from .mem
                    $readmemh($sformatf("sim/mem/nist/%0d/dk_%0d.mem", n, n), dk_mem);
                    $readmemh($sformatf("sim/mem/nist/%0d/c_%0d.mem", n, n), ct_mem);
                end
                $display("[%0d] Decaps  vector %0d ...", $time, n);
                dec_start=1; @(posedge clk); dec_start=0;
                while (!dec_done) @(posedge clk);
                cmp_buf(32, 3, dec_ok);
                $display("  Decaps K : %s", (dec_ok ? "PASS" : "FAIL"));
                if (!dec_ok) errors = errors + 1;
            end

            $display("=== vector %0d: %s ===", n, (errors == 0 ? "PASS" : "FAIL"));
        end
        $display("=== KAT complete ===");
        $finish;
    end

    initial begin
        #300_000_000;
        $display("TIMEOUT"); $fflush; $finish;
    end

endmodule
