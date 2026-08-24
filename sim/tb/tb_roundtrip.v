`timescale 1ns / 1ps
//============================================================================
// Sequential round-trip test: KeyGen -> Encaps -> Decaps
// Tests each kpke module directly (no mlkem wrapper overhead)
//============================================================================
module tb_roundtrip;
    reg clk, rst_n;
    always #5 clk = ~clk;
    integer cc;
    always @(posedge clk) cc <= cc + 1;

    // Shared buffers
    reg [7:0] ek_mem [0:1183];   // 384*K+32 = 1184 bytes
    reg [7:0] dk_mem [0:1151];   // 384*K = 1152 bytes
    reg [7:0] ct_mem [0:1087];   // du*K*32 + dv*32

    // ================ KeyGen ================
    reg kg_start; wire kg_done, kg_busy;
    wire kg_ek_valid, kg_dk_valid;
    wire [7:0] kg_ek_data, kg_dk_data;
    wire [12:0] kg_ek_addr, kg_dk_addr;
    reg [255:0] d_seed;

    kpke_keygen #(.K(3),.ETA1(2)) u_keygen (
        .clk(clk),.rst_n(rst_n),.start(kg_start),
        .d_seed(d_seed),.done(kg_done),.busy(kg_busy),
        .ek_valid(kg_ek_valid),.ek_data(kg_ek_data),.ek_addr(kg_ek_addr),
        .dk_valid(kg_dk_valid),.dk_data(kg_dk_data),.dk_addr(kg_dk_addr)
    );
    // Capture keygen output to buffers
    always @(posedge clk) begin
        if (kg_ek_valid) ek_mem[kg_ek_addr] <= kg_ek_data;
        if (kg_dk_valid) dk_mem[kg_dk_addr] <= kg_dk_data;
    end

    // ================ Encrypt ================
    reg enc_start; wire enc_done, enc_busy;
    wire enc_ct_valid, enc_ek_req;
    wire [7:0] enc_ct_data; wire [12:0] enc_ct_addr;
    reg enc_ek_valid; reg [7:0] enc_ek_data;
    reg [12:0] enc_ek_ptr;
    reg [255:0] message, r_seed;

    kpke_encrypt #(.K(3),.ETA1(2),.ETA2(2),.DU(10),.DV(4)) u_encrypt (
        .clk(clk),.rst_n(rst_n),.start(enc_start),.done(enc_done),.busy(enc_busy),
        .ek_valid(enc_ek_valid),.ek_data(enc_ek_data),.ek_req(enc_ek_req),
        .message(message),.r_seed(r_seed),
        .ct_valid(enc_ct_valid),.ct_data(enc_ct_data),.ct_addr(enc_ct_addr)
    );
    // Feed EK to encrypt
    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin enc_ek_valid<=0; enc_ek_data<=0; enc_ek_ptr<=0; end
        else begin
            enc_ek_valid <= 0;
            if (enc_ek_req && enc_ek_ptr < 13'd1184) begin
                enc_ek_valid <= 1;
                enc_ek_data <= ek_mem[enc_ek_ptr];
                enc_ek_ptr <= enc_ek_ptr + 1;
            end
        end
    end
    // Capture CT output
    always @(posedge clk) if (enc_ct_valid) ct_mem[enc_ct_addr] <= enc_ct_data;

    // ================ Decrypt ================
    reg dec_start; wire dec_done, dec_busy, dec_msg_valid;
    wire [255:0] dec_msg_out;
    wire dec_ct_req, dec_dk_req;
    reg dec_ct_valid, dec_dk_valid;
    reg [7:0] dec_ct_data, dec_dk_data;
    reg [12:0] dec_ct_ptr, dec_dk_ptr;

    kpke_decrypt #(.K(3),.ETA1(2),.ETA2(2),.DU(10),.DV(4)) u_decrypt (
        .clk(clk),.rst_n(rst_n),.start(dec_start),.done(dec_done),.busy(dec_busy),
        .ct_valid(dec_ct_valid),.ct_data(dec_ct_data),.ct_req(dec_ct_req),
        .dk_valid(dec_dk_valid),.dk_data(dec_dk_data),.dk_req(dec_dk_req),
        .msg_valid(dec_msg_valid),.msg_out(dec_msg_out)
    );
    // Feed CT and DK to decrypt
    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin dec_ct_valid<=0; dec_dk_valid<=0; dec_ct_ptr<=0; dec_dk_ptr<=0; end
        else begin
            dec_ct_valid <= 0; dec_dk_valid <= 0;
            if (dec_ct_req && dec_ct_ptr < 13'd1088) begin
                dec_ct_valid <= 1;
                dec_ct_data <= ct_mem[dec_ct_ptr];
                dec_ct_ptr <= dec_ct_ptr + 1;
            end
            if (dec_dk_req && dec_dk_ptr < 13'd1152) begin
                dec_dk_valid <= 1;
                dec_dk_data <= dk_mem[dec_dk_ptr];
                dec_dk_ptr <= dec_dk_ptr + 1;
            end
        end
    end

    // Monitor
    reg [4:0] prev_kg; reg [5:0] prev_enc; reg [4:0] prev_dec;
    integer k;
    always @(posedge clk) begin
        if (u_keygen.state != prev_kg) begin
            $display("[%0t] KG: %0d->%0d cc=%0d", $time, prev_kg, u_keygen.state, cc);
            prev_kg <= u_keygen.state;
        end
    end

    // Watch for X in keygen NTT reads (s_hat NTT on ram2)
    always @(posedge clk) begin
        if (u_keygen.u_ntt.state == 4'd4 && u_keygen.ntt_use_ram3 == 0) begin
            if (^u_keygen.u_ntt.ram_rdata_a === 1'bX || ^u_keygen.u_ntt.ram_rdata_b === 1'bX)
                $display("[%0t] NTT_S X: lo=%0d hi=%0d a=%h b=%h layer=%0d cc=%0d", $time,
                         u_keygen.u_ntt.addr_lo, u_keygen.u_ntt.addr_hi,
                         u_keygen.u_ntt.ram_rdata_a, u_keygen.u_ntt.ram_rdata_b,
                         u_keygen.u_ntt.layer, cc);
        end
    end

    // Watch CBD writes to ram2 (s sampling): first 4 of each polynomial
    always @(posedge clk) begin
        if (u_keygen.state == 5'd6) begin // ST_WAIT_CBD_S
            if (u_keygen.u_cbd.poly_wen && u_keygen.u_cbd.poly_addr < 8'd4)
                $display("[%0t] CBD wr: i=%0d addr=%0d wdata=%h cc=%0d", $time,
                         u_keygen.i_cnt, u_keygen.u_cbd.poly_addr, u_keygen.u_cbd.poly_wdata, cc);
        end
    end

    // Watch CBD internals at S_WRITE for coeff 0..3
    always @(posedge clk) begin
        if (u_keygen.u_cbd.state == 3'd3 && u_keygen.u_cbd.poly_addr < 8'd4)
            $display("[%0t] CBD[%0d]: bits=%b popa=%0d popb=%0d val=%0d uns=%h boff=%0d b0=%h b1=%h cc=%0d", $time,
                     u_keygen.u_cbd.poly_addr, u_keygen.u_cbd.extracted_bits,
                     u_keygen.u_cbd.pop_a, u_keygen.u_cbd.pop_b, u_keygen.u_cbd.cbd_val,
                     u_keygen.u_cbd.cbd_unsigned, u_keygen.u_cbd.bit_offset,
                     u_keygen.u_cbd.prf_buf[0], u_keygen.u_cbd.prf_buf[1], cc);
    end

    // Watch shake256 squeeze output (first few calls)
    always @(posedge clk) begin
        if (u_keygen.u_prf.squeeze_valid && cc < 5000)
            $display("[%0t] PRF sq: %h cc=%0d", $time, u_keygen.u_prf.squeeze_data, cc);
    end

    initial begin
        #500_000_000;
        $display("TIMEOUT cc=%0d", cc); $fflush; $finish;
    end

    initial begin
        clk=0; rst_n=0; cc=0; prev_kg=0; prev_enc=0; prev_dec=0;
        kg_start=0; enc_start=0; dec_start=0;
        d_seed=256'h111100005555aaaa1032547698badcfef0debc9a78563412bebafecaefbeadde;
        message=256'hefcdab8967452301efcdab8967452301efcdab8967452301efcdab8967452301;
        r_seed=256'h1032547698badcfe1032547698badcfe1032547698badcfe1032547698badcfe;
        #100; rst_n=1; #20;

        // KeyGen
        $display("=== KeyGen ==="); $fflush;
        @(posedge clk); kg_start=1; @(posedge clk); kg_start=0;
        wait(kg_done);
        $display("[%0t] KeyGen DONE cc=%0d", $time, cc); $fflush;
        #200;

        // Encrypt
        $display("=== Encrypt ==="); $fflush;
        enc_ek_ptr = 0;
        @(posedge clk); enc_start=1; @(posedge clk); enc_start=0;
        wait(enc_done);
        $display("[%0t] Encrypt DONE cc=%0d", $time, cc); $fflush;
        #200;

        // Decrypt  
        $display("=== Decrypt ==="); $fflush;
        dec_ct_ptr = 0; dec_dk_ptr = 0;
        @(posedge clk); dec_start=1; @(posedge clk); dec_start=0;
        wait(dec_done);
        $display("[%0t] Decrypt DONE cc=%0d", $time, cc); $fflush;
        #100;

        // Debug: inspect intermediate data
        $display("---- DEBUG ----");
        $display("KG cbd.prf_buf[0..7]:   %h %h %h %h %h %h %h %h", u_keygen.u_cbd.prf_buf[0],u_keygen.u_cbd.prf_buf[1],u_keygen.u_cbd.prf_buf[2],u_keygen.u_cbd.prf_buf[3],u_keygen.u_cbd.prf_buf[4],u_keygen.u_cbd.prf_buf[5],u_keygen.u_cbd.prf_buf[6],u_keygen.u_cbd.prf_buf[7]);
        $display("KG cbd.prf_buf[124..127]: %h %h %h %h", u_keygen.u_cbd.prf_buf[124],u_keygen.u_cbd.prf_buf[125],u_keygen.u_cbd.prf_buf[126],u_keygen.u_cbd.prf_buf[127]);
        $display("KG ram2 (s_hat0)[0..15]: %h %h %h %h %h %h %h %h %h %h %h %h %h %h %h %h", u_keygen.u_ram2.mem[0],u_keygen.u_ram2.mem[1],u_keygen.u_ram2.mem[2],u_keygen.u_ram2.mem[3],u_keygen.u_ram2.mem[4],u_keygen.u_ram2.mem[5],u_keygen.u_ram2.mem[6],u_keygen.u_ram2.mem[7],u_keygen.u_ram2.mem[8],u_keygen.u_ram2.mem[9],u_keygen.u_ram2.mem[10],u_keygen.u_ram2.mem[11],u_keygen.u_ram2.mem[12],u_keygen.u_ram2.mem[13],u_keygen.u_ram2.mem[14],u_keygen.u_ram2.mem[15]);
        $display("KG ram1 (t_hat0)[0..7]: %h %h %h %h %h %h %h %h", u_keygen.u_ram1.mem[0],u_keygen.u_ram1.mem[1],u_keygen.u_ram1.mem[2],u_keygen.u_ram1.mem[3],u_keygen.u_ram1.mem[4],u_keygen.u_ram1.mem[5],u_keygen.u_ram1.mem[6],u_keygen.u_ram1.mem[7]);
        $display("KG ram0 (A_hat00)[0..7]: %h %h %h %h %h %h %h %h", u_keygen.u_ram0.mem[0],u_keygen.u_ram0.mem[1],u_keygen.u_ram0.mem[2],u_keygen.u_ram0.mem[3],u_keygen.u_ram0.mem[4],u_keygen.u_ram0.mem[5],u_keygen.u_ram0.mem[6],u_keygen.u_ram0.mem[7]);
        $display("KG ram3 (scratch)[0..7]: %h %h %h %h %h %h %h %h", u_keygen.u_ram3.mem[0],u_keygen.u_ram3.mem[1],u_keygen.u_ram3.mem[2],u_keygen.u_ram3.mem[3],u_keygen.u_ram3.mem[4],u_keygen.u_ram3.mem[5],u_keygen.u_ram3.mem[6],u_keygen.u_ram3.mem[7]);
        $display("ek_mem[0..7]:  %h %h %h %h %h %h %h %h", ek_mem[0],ek_mem[1],ek_mem[2],ek_mem[3],ek_mem[4],ek_mem[5],ek_mem[6],ek_mem[7]);
        $display("dk_mem[0..7]:  %h %h %h %h %h %h %h %h", dk_mem[0],dk_mem[1],dk_mem[2],dk_mem[3],dk_mem[4],dk_mem[5],dk_mem[6],dk_mem[7]);
        $display("ENC ram1[0..3] (t_hat): %h %h %h %h", u_encrypt.u_ram1.mem[0], u_encrypt.u_ram1.mem[1], u_encrypt.u_ram1.mem[2], u_encrypt.u_ram1.mem[3]);
        $display("ENC ram0[0..3] (r_hat): %h %h %h %h", u_encrypt.u_ram0.mem[0], u_encrypt.u_ram0.mem[1], u_encrypt.u_ram0.mem[2], u_encrypt.u_ram0.mem[3]);
        $display("ENC ram2[0..3] (u):     %h %h %h %h", u_encrypt.u_ram2.mem[0], u_encrypt.u_ram2.mem[1], u_encrypt.u_ram2.mem[2], u_encrypt.u_ram2.mem[3]);
        $display("ENC ram4[0..3] (v):     %h %h %h %h", u_encrypt.u_ram4.mem[0], u_encrypt.u_ram4.mem[1], u_encrypt.u_ram4.mem[2], u_encrypt.u_ram4.mem[3]);
        $display("ENC ram5[0..3] (ct):    %h %h %h %h", u_encrypt.u_ram5.mem[0], u_encrypt.u_ram5.mem[1], u_encrypt.u_ram5.mem[2], u_encrypt.u_ram5.mem[3]);
        $display("ct_mem c1[0..15]: %h%h%h%h%h%h%h%h%h%h%h%h%h%h%h%h",
                 ct_mem[0],ct_mem[1],ct_mem[2],ct_mem[3],ct_mem[4],ct_mem[5],ct_mem[6],ct_mem[7],
                 ct_mem[8],ct_mem[9],ct_mem[10],ct_mem[11],ct_mem[12],ct_mem[13],ct_mem[14],ct_mem[15]);
        $display("ct_mem c2[0..15]: %h%h%h%h%h%h%h%h%h%h%h%h%h%h%h%h",
                 ct_mem[120],ct_mem[121],ct_mem[122],ct_mem[123],ct_mem[124],ct_mem[125],ct_mem[126],ct_mem[127],
                 ct_mem[128],ct_mem[129],ct_mem[130],ct_mem[131],ct_mem[132],ct_mem[133],ct_mem[134],ct_mem[135]);
        $display("DEC v[0..3]:   %h %h %h %h", u_decrypt.u_ram1.mem[0], u_decrypt.u_ram1.mem[1], u_decrypt.u_ram1.mem[2], u_decrypt.u_ram1.mem[3]);
        $display("DEC w[0..3]:   %h %h %h %h", u_decrypt.u_ram0.mem[0], u_decrypt.u_ram0.mem[1], u_decrypt.u_ram0.mem[2], u_decrypt.u_ram0.mem[3]);
        $display("DEC m'[0..3]:  %h %h %h %h", u_decrypt.u_ram3.mem[0], u_decrypt.u_ram3.mem[1], u_decrypt.u_ram3.mem[2], u_decrypt.u_ram3.mem[3]);
        $display("DEC s_hat[0]:  %h", u_decrypt.u_ram2.mem[0]);
        $display("---- END DEBUG ----");
        $fflush;

        // Full dumps for Python reference comparison
        $display("---- FULL DUMP ----");
        $write("ek_mem: "); for (k=0;k<1184;k=k+1) $write("%h", ek_mem[k]); $write("\n");
        $write("dk_mem: "); for (k=0;k<1152;k=k+1) $write("%h", dk_mem[k]); $write("\n");
        $write("ct_mem: "); for (k=0;k<1088;k=k+1) $write("%h", ct_mem[k]); $write("\n");
        $write("dec_msg: "); for (k=0;k<32;k=k+1) $write("%h", dec_msg_out[(31-k)*8 +: 8]); $write("\n");
        $fflush;
        $display("---- END FULL DUMP ----");

        // Verify
        $display("============================================");
        $display("Original msg: %h", message);
        $display("Decoded  msg: %h", dec_msg_out);
        if (message == dec_msg_out)
            $display("PASS: Messages match!");
        else
            $display("FAIL: Messages DO NOT match!");
        $display("============================================");
        $fflush;
        #100; $finish;
    end
endmodule
