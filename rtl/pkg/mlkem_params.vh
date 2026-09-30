
parameter [12:0] MLKEM_Q       = 13'd3329;    // Prime modulus q
parameter [8:0]  MLKEM_N       = 9'd256;      // Polynomial degree n
parameter [3:0]  MLKEM_QBITS   = 4'd12;       // ceil(log2(q)) = 12
parameter [3:0]  MLKEM_LOGN    = 4'd8;        // log2(n) = 8

parameter [15:0] MLKEM_MONT_R     = 16'd2285;    // 2^16 mod 3329
parameter [15:0] MLKEM_MONT_RINV  = 16'd169;     // R^{-1} mod q
parameter [15:0] MLKEM_MONT_RSQ   = 16'd1353;    // R^2 mod q
parameter [15:0] MLKEM_QINV       = 16'd3327;    // -q^{-1} mod 2^16

parameter [15:0] MLKEM_BARRETT_V  = 16'd20159;
parameter [4:0]  MLKEM_BARRETT_S  = 5'd26;       // shift amount

parameter [15:0] MLKEM_INTT_F     = 16'd1441;

parameter MLKEM_K   = 3;     // Module rank
parameter MLKEM_ETA1 = 2;    // CBD parameter for secret/noise
parameter MLKEM_ETA2 = 2;    // CBD parameter for error
parameter MLKEM_DU  = 10;    // Compression parameter for u
parameter MLKEM_DV  = 4;     // Compression parameter for v

parameter MLKEM_EK_BYTES   = 12 * MLKEM_K * (MLKEM_N / 8) + 32;
parameter MLKEM_DK_BYTES   = 24 * MLKEM_K * (MLKEM_N / 8) + 96;
parameter MLKEM_CT_BYTES   = MLKEM_DU * MLKEM_K * (MLKEM_N / 8) + MLKEM_DV * (MLKEM_N / 8);
parameter MLKEM_SS_BYTES   = 32;

parameter [4:0]  KECCAK_ROUNDS    = 5'd24;
parameter [10:0] KECCAK_STATE_W   = 11'd1600;
parameter [7:0]  SHA3_256_RATE    = 8'd136;   // bytes
parameter [7:0]  SHA3_512_RATE    = 8'd72;    // bytes
parameter [7:0]  SHAKE128_RATE    = 8'd168;   // bytes
parameter [7:0]  SHAKE256_RATE    = 8'd136;   // bytes

parameter [7:0]  SHA3_DOMAIN      = 8'h06;
parameter [7:0]  SHAKE_DOMAIN     = 8'h1F;
