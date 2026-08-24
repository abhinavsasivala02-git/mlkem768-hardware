//============================================================================
// Minimal testbench for kpke_keygen - direct, no AXI
//============================================================================
`timescale 1ns / 1ps

module tb_kpke_keygen;

    reg         clk;
    reg         rst_n;
    reg         start;
    reg [255:0] d_seed;
    wire        done, busy;
    wire        ek_valid, dk_valid;
    wire [7:0]  ek_data, dk_data;
    wire [12:0] ek_addr, dk_addr;

    kpke_keygen #(.K(3), .ETA1(2)) u_dut (
        .clk(clk), .rst_n(rst_n), .start(start), .d_seed(d_seed),
        .done(done), .busy(busy),
        .ek_valid(ek_valid), .ek_data(ek_data), .ek_addr(ek_addr),
        .dk_valid(dk_valid), .dk_data(dk_data), .dk_addr(dk_addr)
    );

    always #5 clk = ~clk;

    // Monitor state every 10000 cycles
    integer cycle_cnt;
    always @(posedge clk) begin
        cycle_cnt <= cycle_cnt + 1;
        if (cycle_cnt % 10000 == 0 && cycle_cnt > 0)
            $display("[%0t] cycle=%0d state=%0d i=%0d j=%0d n=%0d",
                     $time, cycle_cnt, u_dut.state, u_dut.i_cnt, u_dut.j_cnt, u_dut.n_cnt);
    end

    // Monitor state transitions
    reg [4:0] prev_state;
    always @(posedge clk) begin
        if (u_dut.state != prev_state) begin
            $display("[%0t] STATE: %0d -> %0d (i=%0d j=%0d)", $time, prev_state, u_dut.state, u_dut.i_cnt, u_dut.j_cnt);
            prev_state <= u_dut.state;
        end
    end

    // Timeout watchdog
    initial begin
        #50_000_000;
        $display("[%0t] TIMEOUT after %0d cycles! Stuck at state=%0d", $time, cycle_cnt, u_dut.state);
        $display("  g_busy=%b g_hash_valid=%b", u_dut.g_busy, u_dut.g_hash_valid);
        $display("  prf_busy=%b prf_absorb_ready=%b prf_squeeze_valid=%b",
                 u_dut.prf_busy, u_dut.prf_absorb_ready, u_dut.prf_squeeze_valid);
        $display("  cbd_done=%b cbd_busy=%b cbd_prf_req=%b",
                 u_dut.cbd_done, u_dut.cbd_busy, u_dut.cbd_prf_req);
        $display("  ntt_done=%b ntt_busy=%b", u_dut.ntt_done, u_dut.ntt_busy);
        $display("  sntt_done=%b sntt_busy=%b", u_dut.sntt_done, u_dut.sntt_busy);
        $display("  seed_feed_cnt=%0d", u_dut.seed_feed_cnt);
        $finish;
    end

    initial begin
        clk = 0; rst_n = 0; start = 0; cycle_cnt = 0; prev_state = 0;
        d_seed = 256'hDEADBEEFCAFEBABE123456789ABCDEF0FEDCBA9876543210AAAAAAA555555555;

        #100;
        rst_n = 1;
        #20;

        $display("Starting kpke_keygen...");
        @(posedge clk);
        start <= 1;
        @(posedge clk);
        start <= 0;

        wait(done);
        $display("[%0t] DONE! kpke_keygen completed in %0d cycles.", $time, cycle_cnt);
        #100;
        $finish;
    end

endmodule
