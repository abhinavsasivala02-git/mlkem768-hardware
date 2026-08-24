// =============================================================================
// mlkem_kat_vectors.vh - FIPS 203 ML-KEM-768 Known Answer Test Vectors
//
// Seeds d, z, m are the 256-bit register values (packed LEAST-SIGNIFICANT byte
// first) written directly to the DUT. ek/dk/ct/(ss) are 32-byte-array byte buffers
// stored in sim/mem/nist/<i>/ and loaded via $readmemh. Expected values are
// byte-exact FIPS-203 outputs (verified against NIST ACVP).
// =============================================================================

// KAT Vector 0
localparam [255:0] KAT0_D = 256'ha0c8ebba68a767cc68039399fd9023b153719ffca192e35ab0806c5ed7b782e5;
localparam [255:0] KAT0_Z = 256'hf0e8cbe91698f709b191f50b303bfacb67b387f17595374a7cb8c04087cbda1c;
localparam [255:0] KAT0_M = 256'h81dd176e6ccf83e82aa085937f8bb0aa76bdc35a17d86539911e71686159774e;

// KAT Vector 1
localparam [255:0] KAT1_D = 256'h8bad5d0fd028749edc67e753b98cfa06f07513cc574414acf7134662db48583e;
localparam [255:0] KAT1_Z = 256'hd110cae4ee6d391a15ce599d757459f648d886eb742418b69e8b91f0c2d62d01;
localparam [255:0] KAT1_M = 256'h9e2bf7c4ef6e6a5d6caf4ee52a00b51d1816b28ab2ddc709416164741f0365c4;

// KAT Vector 2
localparam [255:0] KAT2_D = 256'hc9c8fb0c3a2e33d3e0bb352e1f9a0d630c1682fc21132a6f7a496b5ca5de2f88;
localparam [255:0] KAT2_Z = 256'h1a1dc2fdb1e171307ff24b93adea79734848a13958aaa37991553c9201f6213a;
localparam [255:0] KAT2_M = 256'hbdf0e747c8d5fee2961e893f2f485577f520f64bfa4616d13f5c9251b37b6a53;

// KAT Vector 3
localparam [255:0] KAT3_D = 256'h6bf145afa9993c7ed06be9084a392102bf772be2a773f0775b21040d3113e0ae;
localparam [255:0] KAT3_Z = 256'hd9ed20ea40693f4b4c48f50edaeccb785a377291e26192fee532382c6a9dcb7d;
localparam [255:0] KAT3_M = 256'hcd16aae88b083b303d7007afddfa7fca79df8f325d143b1526bd47e1dd7879de;

// KAT Vector 4
localparam [255:0] KAT4_D = 256'hfc1a5b754ee911ba40ef6b4c7d348013e11c4c1bd6e19576daf502549fc0dcb5;
localparam [255:0] KAT4_Z = 256'h52f5c40b557aed7463a58a7969f111ba88acc8b559dc1bcf0800da2d98ae6eab;
localparam [255:0] KAT4_M = 256'h7fc01bbf1c55ab863fde252c3db94acc79d1c40643b05e03ca256eb3c8db2eab;

// KAT Vector 5
localparam [255:0] KAT5_D = 256'h5e9ca8659b91439e0a3194e48be11f04492fd2efe6cd5ef295c41104bca364a8;
localparam [255:0] KAT5_Z = 256'h557a23cbff9255c0d9cbb22e8c2aced75e3ee505bf62e55ebafbd6b15b31ade3;
localparam [255:0] KAT5_M = 256'h9736dbb29d80acebc8f82ba42cb1acc8932c3d8035b3ea5c84f72536954ff994;

// KAT Vector 6
localparam [255:0] KAT6_D = 256'hef35a7f1a32e7cb675c724c019b1e6aca4a3531ef13f6831d178a5544bbce699;
localparam [255:0] KAT6_Z = 256'hfdce4a2e63eda994c976b3553e52552b5350120fcfcbfcd2880fa2edae2f9a0d;
localparam [255:0] KAT6_M = 256'h20de5f98b17b51b356b8ad5f88c8a7371789446357e13eb1e41a2352fe1a28c8;

// KAT Vector 7
localparam [255:0] KAT7_D = 256'h9d14ad6be0e4c67be93c39995c90ff4f89926a8a24ee7ef2eac97e14aa559f6f;
localparam [255:0] KAT7_Z = 256'hc12bbe2e373785943ac3a464b19a1ac41d95a2f8fccf40f4af228c2ff4cad14c;
localparam [255:0] KAT7_M = 256'hb437ea1c39a0ade790883048a65071f15b65be1789689ab8db95c2cec15952c5;

// KAT Vector 8
localparam [255:0] KAT8_D = 256'h9ccaa705c96262daaf31bafddfbe5c43315ff16eaf3e0fab2f1806312dccd31d;
localparam [255:0] KAT8_Z = 256'hf257c69decaee339cf260ebf95a7971e233ca6615f4728ae96bb811765b1d194;
localparam [255:0] KAT8_M = 256'h6f6b390a847eecda77f795320723159bc4716394b8a6a27af7e6d318d9939f36;

// KAT Vector 9
localparam [255:0] KAT9_D = 256'hd7b5eadf206f8336499309ae6b13f467342e64cff208ade905f3d7d4c79e97ef;
localparam [255:0] KAT9_Z = 256'h5ca46fa451db9b7badff039cc1405a0ee4e7dcd40c739f7ccd7c14fce4beac0d;
localparam [255:0] KAT9_M = 256'h9f13ec785017bd047f67e17527dca4e9af5157ed9ffa254a148427869bac95fb;

// Number of KAT vectors
`define NUM_KAT_VECTORS 10
