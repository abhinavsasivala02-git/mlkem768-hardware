# ML-KEM-768 Hardware Implementation

RTL implementation of an ML-KEM-768 (FIPS 203) lattice-based key-encapsulation
core with an AXI4-Lite slave interface, plus self-contained testbenches,
simulated with Icarus Verilog / Xilinx Vivado 2023.2 (xsim).

## How ML-KEM works

ML-KEM (FIPS 203, based on CRYSTALS-Kyber) is NIST's post-quantum
key-encapsulation mechanism. Its security rests on the hardness of the
module-learning-with-errors (Module-LWE) problem — a problem believed hard even for
quantum computers. The **ML-KEM-768** parameter set (K=3) operates on polynomials
of degree 255 over the ring `R_q = Z_q[x]/(x^256 + 1)` with `q = 3329`
(12-bit coefficients). The scheme has three phases:

**1. Key generation** — `ML-KEM.KeyGen(d)` expands the 32-byte seed `d` by
SHA3-512 into `(ρ, σ)`. The matrix `Â` is derived deterministically from `ρ`
via SHAKE-128 and rejection sampling; two short secret polynomials `ŝ` and `ê`
are sampled from `σ` with the centered-binomial distribution (CBD). The public
vector is `t̂ = Â·ŝ + ê`, all in the NTT domain. The encapsulation key is
`ek = (t̂, ρ)`; the decapsulation key is `dk = dkPKE ‖ ek ‖ H(ek) ‖ z`.

**2. Encapsulation** — `ML-KEM.Encaps(ek, m)` hashes `m` with `H(ek)` via
SHA3-512 to derive `(K, r)`. It samples ephemeral noise `ŷ, ê₁, ê₂`, computes
`u = INTT(Âᵀ·ŷ) + ê₁`, `v = INTT(t̂ᵀ·ŷ) + ê₂ + ⌈μ⌉` (the encoded message), then
compresses `(u, v)` into the ciphertext `c`. The shared secret is `K`.

**3. Decapsulation** — `ML-KEM.Decaps(dk, c)` decrypts `m'`, re-derives
`(K', r')`, re-encrypts to `c'`, and returns `K'` if `c' == c`, otherwise the
implicit-rejection key `K̄ = SHAKE-256(z ‖ c)`. The `c == c'` comparison is
performed in constant time.

Under the hood the arithmetic uses a number-theoretic transform (NTT) in the
`Z_q` Montgomery domain for fast polynomial multiplication, and SHA3-256/512 +
SHAKE-128/256 (Keccak-f[1600]) for all hashing and rejection sampling. The
hardware instantiates dedicated NTT, base-multiplication, CBD/noise sampling, and
Keccak blocks, orchestrated by the `mlkem_keygen` / `mlkem_encaps` /
`mlkem_decaps` FSM controllers.

## Status

All blocks were verified byte-exact against the official NIST test vectors (and the
FIPS-203 reference):

| Subsystem | Status |
|-----------|--------|
| Keccak-f[1600], SHA3-256/512, SHAKE-128/256 | PASS — match known hashes |
| NTT / inverse-NTT, base multiplication | PASS |
| K-PKE KeyGen / Encrypt / Decrypt | PASS — round-trip recovers the message |
| ML-KEM KeyGen | PASS — byte-exact `ek`/`dk` vs NIST (25/25) |
| ML-KEM Encaps | PASS — byte-exact `K` + ciphertext |
| ML-KEM Decaps | PASS — byte-exact `K`, and `K̄` on implicit rejection |
| NIST KAT (10 vectors) | PASS — pre-generated in `sim/mem/nist/<i>/`, byte-exact KeyGen+Encaps+Decaps |

The testbenches in `sim/tb/` are self-contained (seeds/keys are hard-coded and
results self-checked); the `joint_design/tb_mlkem_nist_kat.v` testbench loads the
pre-generated NIST vectors from `sim/mem/nist/<i>/` via `$readmemh` — no external
automation or reference scripts are required.

## Directory layout

```
rtl/            RTL sources
  pkg/          parameters (mlkem_params.vh), NTT zeta ROM (ntt_rom.v)
  keccak/       keccak_f1600, keccak_round, mlkem_hash_engine, sha3_256/512, shake128/256
  math/         barrett_reduce, montgomery_reduce, modular_arith, ntt, intt, ntt_core,
                ntt_butterfly, poly_basemul, poly_arith
  sample/       sample_ntt (rejection), sample_cbd (CBD)
  encode/       byte_encode, byte_decode, compress, decompress
  kpke/         kpke_keygen, kpke_encrypt, kpke_decrypt  (K-PKE core, FIPS 203 Algs 13-15)
  mem/          poly_ram
  mlkem/        mlkem_top (AXI4-Lite), mlkem_core, mlkem_keygen, mlkem_encaps,
                mlkem_decaps, mlkem_axi_lite_if
sim/            simulation sources
  tb/           self-contained testbenches (tb_roundtrip, tb_f1600, tb_sha3, tb_ntt_clean,
                tb_basemul, tb_kpke_*, tb_mlkem_*, tb_mlkem_nist_kat)
  mem/          KAT vector header (mlkem_kat_vectors.vh) + NIST vectors (nist/<i>/*.mem)
syn/            Cadence Genus synthesis script (syn_mlkem.tcl) + constraints (mlkem_top.sdc)
```

## AXI register / memory map (byte-addressed)

| Address | Name | R/W | Description |
|---------|------|-----|-------------|
| `0x00` | CTRL | W | `[1:0]` op_sel (`00`=KeyGen, `01`=Encaps, `10`=Decaps), `[8]` start |
| `0x04` | STATUS | R | `[0]` busy, `[1]` done, `[2]` sticky done |
| `0x08–0x24` | SEED_D | W | KeyGen seed `d` (32 bytes, 8 words) |
| `0x28–0x44` | SEED_Z | W | Implicit-rejection seed `z` (32 bytes, 8 words) |
| `0x48–0x64` | SEED_M | W | Encaps message `m` (32 bytes, 8 words) |
| `0x68–0x84` | SS | R | Shared secret `K`/`K̄` (32 bytes, 8 words) |
| `0x88` | BUF_ADDR | W | Buffer byte address for EK/DK/CT access |
| `0x8C` | BUF_DATA | R/W | Buffer data byte (auto-increment) |
| `0x90` | BUF_SEL | W | `[1:0]` buffer select: `0`=EK, `1`=DK, `2`=CT |

Buffers (ML-KEM-768): `ek` = 1184 B, `dk` = 2400 B, `ct` = 1088 B, `ss` = 32 B.
The seeds/keys are packed into the registers **least-significant byte first**
(byte 0 → `reg[7:0]`, byte 31 → `reg[255:248]`), so load NIST vectors in that order.

## Module map

| File | Role |
|------|------|
| `mlkem_top.v` | top-level FSM: AXI4-Lite slave, EK/DK/CT RAM buffers, operation orchestrator, `irq_done` |
| `mlkem_axi_lite_if.v` | AXI4-Lite register interface (CTRL/STATUS, seeds, shared secret, buffer access) |
| `mlkem_core.v` | operation orchestrator: muxes KeyGen/Encaps/Decaps and routes the shared RAM/secret |
| `mlkem_keygen.v` | ML-KEM.KeyGen (Alg 16): K-PKE.KeyGen, then `dk = dkPKE ‖ ek ‖ H(ek) ‖ z` |
| `mlkem_encaps.v` | ML-KEM.Encaps (Alg 17): `(K,r) = G(m‖H(ek))`, then K-PKE.Encrypt |
| `mlkem_decaps.v` | ML-KEM.Decaps (Alg 18): decrypt, re-encrypt, constant-time `c==c'`, implicit rejection |
| `kpke_keygen.v` | K-PKE.KeyGen (Alg 13): `G(d‖k)`, sample `Â,s,e`, NTT, `t̂=Â∘ŝ+ê`, encode |
| `kpke_encrypt.v` | K-PKE.Encrypt (Alg 14): sample `y,e₁,e₂`, NTT, `u=INTT(Âᵀ∘ŷ)+e₁`, `v=t̂ᵀ∘ŷ+e₂+μ`, compress |
| `kpke_decrypt.v` | K-PKE.Decrypt (Alg 15): decode/decompress, `w=INTT(ŝ∘û)`, `m'=⌈v−w⌉` |
| `ntt.v` / `ntt_core.v` / `ntt_butterfly.v` | polynomial NTT (iterative 7-layer) + single Montgomery butterfly |
| `intt.v` | inverse NTT (with `128⁻¹` scaling) |
| `poly_basemul.v` | pointwise base multiplication (2 coefficients per basemul, ζ-twiddle) |
| `poly_arith.v` | polynomial add/sub mod q |
| `barrett_reduce.v` / `montgomery_reduce.v` / `modular_arith.v` | modular reduction, Montgomery reduction, q-domain arithmetic |
| `sample_ntt.v` | SampleNTT (Alg 7): SHAKE-128 rejection sampling into a polynomial |
| `sample_cbd.v` | SamplePolyCBD (Alg 8): centered-binomial noise from SHAKE-256 PRF |
| `compress.v` / `decompress.v` | FIPS 203 Algs 10/11: coefficient compression / decompression |
| `byte_encode.v` / `byte_decode.v` | FIPS 203 Algs 5/6: pack/unpack coefficients ↔ bytes (reduce mod q for d=12) |
| `mlkem_hash_engine.v` | unified Keccak sponge (rate + domain separator) for SHA3-256/512, SHAKE-128/256 |
| `sha3_256.v` / `sha3_512.v` | SHA3-256 (`H(ek)`) and SHA3-512 (`G(d‖k)`, `G(m‖h)`) |
| `shake128.v` / `shake256.v` | SHAKE-128 XOF (matrix sampling) and SHAKE-256 (PRF / KDF) |
| `keccak_f1600.v` / `keccak_round.v` | Keccak-f[1600] permutation (24 rounds) + single round logic |
| `keccak_absorb_squeeze.v` | legacy sponge controller (superseded by `mlkem_hash_engine`, not instantiated) |
| `poly_ram.v` | single/dual-port polynomial RAM (256×12-bit) |
| `mlkem_params.vh` | ML-KEM parameter header: `q`, `n`, Montgomery/Barrett constants, `K/eta/du/dv`, derived sizes, Keccak rates |
| `ntt_rom.v` | FIPS 203 Appendix-A NTT twiddle ROM (ζ values) |

## How to run (from the project root)

The design is simulated with Icarus Verilog (verified path) or Xilinx Vivado 2023.2
(xsim). The testbenches are self-contained — no driver scripts are needed.

**Icarus Verilog** — quick, everything works:

```sh
iverilog -g2012 -o rt -I rtl/pkg $(find rtl -name '*.v') sim/tb/tb_roundtrip.v && vvp rt
```

**Vivado / xsim** — set the RT L source list once, then run each testbench:

```tcl
set RTL [list \
  rtl/pkg/ntt_rom.v rtl/mem/poly_ram.v rtl/math/barrett_reduce.v rtl/math/montgomery_reduce.v \
  rtl/math/modular_arith.v rtl/math/ntt_butterfly.v rtl/math/ntt.v rtl/math/intt.v \
  rtl/math/poly_arith.v rtl/math/poly_basemul.v rtl/keccak/keccak_round.v rtl/keccak/keccak_f1600.v \
  rtl/keccak/mlkem_hash_engine.v rtl/keccak/sha3_256.v rtl/keccak/sha3_512.v rtl/keccak/shake128.v \
  rtl/keccak/shake256.v rtl/encode/byte_decode.v rtl/encode/byte_encode.v rtl/encode/compress.v \
  rtl/encode/decompress.v rtl/sample/sample_ntt.v rtl/sample/sample_cbd.v rtl/kpke/kpke_keygen.v \
  rtl/kpke/kpke_encrypt.v rtl/kpke/kpke_decrypt.v rtl/mlkem/mlkem_keygen.v rtl/mlkem/mlkem_encaps.v \
  rtl/mlkem/mlkem_decaps.v rtl/mlkem/mlkem_axi_lite_if.v rtl/mlkem/mlkem_core.v rtl/mlkem/mlkem_top.v]
```

Example — K-PKE round-trip:

```tcl
xvlog --work xsim -i rtl/pkg $RTL sim/tb/tb_roundtrip.v
xelab -debug typical -L xsim xsim.tb_roundtrip -s rt_sim
xsim -R rt_sim
```

Other testbenches (`sim/tb/tb_f1600.v`, `tb_sha3.v`, `tb_ntt_clean.v`, `tb_basemul.v`,
`tb_kpke_keygen.v`, `tb_kpke_encrypt.v`, `tb_mlkem_core.v`, `tb_mlkem_keygen.v`,
`tb_mlkem_top.v`) are compiled the same way, with the corresponding top `xsim.tb_*`.

**NIST KAT end-to-end** (`sim/tb/tb_mlkem_nist_kat.v`) runs the pre-generated
KeyGen → Encaps → Decaps vectors. Include `-i sim/mem` for `mlkem_kat_vectors.vh`, then
run in one-vector slices (the full KAT is slow, so slice it like the mldsa flow):

```tcl
xvlog --work xsim -i rtl/pkg -i sim/mem $RTL sim/tb/tb_mlkem_nist_kat.v
xelab -debug typical -L xsim xsim.tb_mlkem_nist_kat -s nist_sim
xsim -R nist_sim -testplusarg NIST_START=0 -testplusarg NIST_END=9 \
     -testplusarg PHASE=0        # PHASE: 0=all 1=keygen 2=encaps 3=decaps
```

The testbenches load their data by relative path (`sim/mem/nist/<i>/*.mem`) via
`$readmemh`, so always run from the project root.

## Tool notes

- Vivado 2023.2 path: `D:\vivado\2023.2\bin\vivado.bat`.
- Do not run more than one batch Vivado at a time in this folder: concurrent
  instances fight over `./xsim`, `xsim.log` and `xsim_files.txt`.
- The batch flow regenerates `./xsim`, `xsim.log`, `xelab.*`, `xvlog.*` at the
  project root on every run; these are disposable build artifacts.
- iverilog is a fast alternative for the self-checking testbenches; the AXI
  top-level testbench (`tb_mlkem_top.v`) is slow in iverilog, so run that in xsim.
