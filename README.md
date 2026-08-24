# ML-KEM (FIPS 203) Hardware Implementation

A register-transfer-level (RTL) implementation of **ML-KEM** — the Module-Lattice-Based
Key-Encapsulation Mechanism standardized in **NIST FIPS 203** (formerly Kyber). The design
defaults to **ML-KEM-768** (NIST Category 3) and is parameterized so ML-KEM-512 and
ML-KEM-1024 can be selected by overriding the `K`, `ETA1`, `ETA2`, `DU`, `DV` parameters.

The implementation is validated byte-for-byte against FIPS 203/test vectors and the
official NIST ACVP test vectors for KeyGen, Encapsulation, and Decapsulation.

---

## 1. Overview

ML-KEM is a KEM (Key-Encapsulation Mechanism) built on the module-learning-with-errors
(M-LWE) problem. It provides three operations:

| Operation | Algorithm (FIPS 203) | RTL module |
|-----------|----------------------|------------|
| `ML-KEM.KeyGen(d)` | Algorithm 16 | `mlkem_keygen` |
| `ML-KEM.Encaps(ek, m)` | Algorithm 17 | `mlkem_encaps` |
| `ML-KEM.Decaps(dk, c)` | Algorithm 18 | `mlkem_decaps` |

The low-level K-PKE (public-key encryption) core is in `rtl/kpke/`, and the mathematical
primitives (number-theoretic transform, modules) live in `rtl/math/` and `rtl/sample/`.

### Parameter sets

| Parameter set | K | eta₁ | eta₂ | d_u | d_v | ek (B) | dk (B) | ct (B) | ss (B) |
|---------------|----|------|------|-----|-----|--------|--------|--------|--------|
| ML-KEM-512    | 2 | 3    | 2    | 10  | 4   | 800    | 1632   | 768    | 32     |
| **ML-KEM-768**| **3** | **2** | **2** | **10** | **4** | **1184** | **2400** | **1088** | **32** |
| ML-KEM-1024   | 4 | 2    | 2    | 11  | 5   | 1568   | 3168   | 1568   | 32     |

Default parameters (`K=3, ETA1=2, ETA2=2, DU=10, DV=4`) select ML-KEM-768.

Ring parameters, defined in `rtl/pkg/mlkem_params.vh`:
- `q = 3329`, `n = 256`, `log2(n) = 8`, `ceil(log2(q)) = 12`
- Montgomery domain constants (`R = 2^16 mod q`, `R⁻¹`, `R²`, `q⁻¹ mod 2^16`)
- Barrett reduction constant (`v = 20159`, shift `26`)
- Inverse-NTT scaling factor (`128⁻¹ · R mod q`)

---

## 2. Repository layout

```
MLKEM_work/
├── rtl/
│   ├── pkg/    mlkem_params.vh, ntt_rom.v            (parameters + NTT twiddle ROM)
│   ├── keccak/ keccak_f1600.v, keccak_round.v,       (Keccak-f[1600])
│   │          mlkem_hash_engine.v,                  (shared sponge: SHA3-256/512, SHAKE-128/256)
│   │          sha3_256.v, sha3_512.v, shake128.v, shake256.v
│   ├── math/   ntt.v, intt.v, ntt_core.v, ntt_butterfly.v,
│   │          poly_basemul.v, poly_arith.v, barrett_reduce.v,
│   │          montgomery_reduce.v, modular_arith.v
│   ├── sample/ sample_ntt.v, sample_cbd.v           (rejection sampling + CBD noise)
│   ├── encode/ byte_encode.v, byte_decode.v, compress.v, decompress.v
│   ├── kpke/   kpke_keygen.v, kpke_encrypt.v, kpke_decrypt.v   (K-PKE core, FIPS 203 Algs 13-15)
│   ├── mem/    poly_ram.v                            (single/dual-port polynomial RAM)
│   └── mlkem/  mlkem_top.v, mlkem_core.v, mlkem_keygen.v,
│              mlkem_encaps.v, mlkem_decaps.v, mlkem_axi_lite_if.v
├── tb/         self-contained verification testbenches (K-PKE roundtrip, hash, NTT, top-level, etc.)
├── syn/        Genus synthesis script (syn_mlkem.tcl / run_genus.tcl) + constraints (mlkem_top.xdc, mlkem_top.sdc)
└── run_rt_roundtrip.tcl   (Vivado batch simulation)
```

### 2.1 Module map

| File | Role |
|------|------|
| `mlkem_top.v` | top-level FSM: AXI4-Lite slave, EK/DK/CT RAM buffers, operation orchestrator, `irq_done` |
| `mlkem_axi_lite_if.v` | AXI4-Lite register interface (CTRL/STATUS, seeds `d/z/m`, shared secret, buffer access) |
| `mlkem_core.v` | operation orchestrator: muxes KeyGen/Encaps/Decaps and routes the shared RAM / secret ports |
| `mlkem_keygen.v` | ML-KEM.KeyGen (Alg 16): K-PKE.KeyGen, then `dk = dkPKE ‖ ek ‖ H(ek) ‖ z` |
| `mlkem_encaps.v` | ML-KEM.Encaps (Alg 17): `(K,r) = G(m‖H(ek))`, then K-PKE.Encrypt |
| `mlkem_decaps.v` | ML-KEM.Decaps (Alg 18): decrypt, re-encrypt, constant-time `c==c'`, implicit rejection |
| `kpke_keygen.v` | K-PKE.KeyGen (Alg 13): `G(d‖k)→(ρ,σ)`, sample `Â,s,e`, NTT, `t̂=Â∘ŝ+ê`, encode |
| `kpke_encrypt.v` | K-PKE.Encrypt (Alg 14): sample `y,e₁,e₂`, NTT, `u=INNT(Âᵀ∘ŷ)+e₁`, `v=t̂ᵀ∘ŷ+e₂+μ`, compress |
| `kpke_decrypt.v` | K-PKE.Decrypt (Alg 15): decode/decompress, `w=INNT(ŝ∘û)`, `m'=⌈v−w⌉` |
| `ntt.v` / `ntt_core.v` / `ntt_butterfly.v` | polynomial NTT (iterative 7-layer) + single Montgomery butterfly |
| `intt.v` | inverse NTT (with `128⁻¹` scaling) |
| `poly_basemul.v` | pointwise base multiplication (2 coefficients per basemul, ζ-twiddle) |
| `poly_arith.v` | polynomial add/sub mod q |
| `barrett_reduce.v` / `montgomery_reduce.v` / `modular_arith.v` | modular reduction, Montgomery reduction, q-domain arithmetic |
| `sample_ntt.v` | SampleNTT (Alg 7): SHAKE-128 rejection sampling into a polynomial |
| `sample_cbd.v` | SamplePolyCBD (Alg 8): centered-binomial noise from SHAKE-256 PRF |
| `compress.v` / `decompress.v` | FIPS 203 Algs 10/11: coefficient compression / decompression |
| `byte_encode.v` / `byte_decode.v` | FIPS 203 Algs 5/6: pack/unpack coefficients ↔ bytes (reduce mod q for d=12) |
| `mlkem_hash_engine.v` | unified Keccak sponge (rate + domain-sep) used by SHA3-256/512 and SHAKE-128/256 |
| `sha3_256.v` / `sha3_512.v` | SHA3-256 (`H(ek)`) and SHA3-512 (`G(d‖k)`, `G(m‖h)`) wrappers |
| `shake128.v` / `shake256.v` | SHAKE-128 XOF (matrix sampling) and SHAKE-256 (PRF / KDF) |
| `keccak_f1600.v` / `keccak_round.v` | Keccak-f[1600] permutation (24 rounds, 1 round/cycle) + single round logic |
| `keccak_absorb_squeeze.v` | legacy sponge controller (superseded by `mlkem_hash_engine`, not instantiated) |
| `poly_ram.v` | single/dual-port polynomial RAM (256×12-bit) |
| `mlkem_params.vh` | ML-KEM parameter header: `q`, `n`, Montgomery/Barrett constants, `K/eta/du/dv`, derived sizes, Keccak rates |
| `ntt_rom.v` | FIPS 203 Appendix-A NTT twiddle ROM (ζ values) |

---

## 3. Design hierarchy

```
mlkem_top
├── mlkem_axi_lite_if      AXI4-Lite register interface (control + seeds + buffers)
├── mlkem_core             Operation orchestrator / shared-resource mux
│   ├── mlkem_keygen       ML-KEM.KeyGen (Algorithm 16)
│   │   └── kpke_keygen    K-PKE.KeyGen (Algorithm 13)
│   ├── mlkem_encaps       ML-KEM.Encaps (Algorithm 17)
│   │   └── kpke_encrypt   K-PKE.Encrypt (Algorithm 14)
│   └── mlkem_decaps       ML-KEM.Decaps (Algorithm 18, with implicit rejection)
│       ├── kpke_decrypt   K-PKE.Decrypt (Algorithm 15)
│       └── kpke_encrypt   K-PKE.Encrypt (re-encrypt for the FO transform)
├── ek_ram                 Encapsulation-key buffer (1568 B max)
├── dk_ram                 Decapsulation-key buffer (3168 B max)
└── ct_ram                 Ciphertext buffer (1568 B max)
```

All hash/XOF variants share a single **`mlkem_hash_engine`** sponge (one `keccak_f1600`
instance) parameterized by rate and domain separator:

| Function | rate (B) | domain | used for |
|----------|----------|--------|----------|
| SHA3-256 | 136 | `0x06` | `H(ek)` |
| SHA3-512 | 72  | `0x06` | `G(d‖k)`, `G(m‖H(ek))` |
| SHAKE-128| 168 | `0x1F` | matrix sampling `XOF(ρ,j,i)` |
| SHAKE-256| 136 | `0x1F` | `PRF(σ,i)` (CBD), KDF `J(z‖c)` |

---

## 4. Register map (AXI4-Lite)

The 32-bit byte-addressable register interface is implemented in
`rtl/mlkem/mlkem_axi_lite_if.v`.

| Address | Name | R/W | Description |
|---------|------|-----|-------------|
| `0x00` | CTRL | W | `[1:0]` op_sel (`00`=KeyGen, `01`=Encaps, `10`=Decaps), `[8]` start |
| `0x04` | STATUS | R | `[0]` busy, `[1]` done, `[2]` sticky done |
| `0x08–0x24` | SEED_D | W | KeyGen seed `d` (32 bytes, 8 regs) |
| `0x28–0x44` | SEED_Z | W | Implicit-rejection seed `z` (32 bytes, 8 regs) |
| `0x48–0x64` | SEED_M | W | Encaps message `m` (32 bytes, 8 regs) |
| `0x68–0x84` | SS | R | Shared secret `K`/`K̄` (32 bytes, 8 regs) |
| `0x88` | BUF_ADDR | W | Buffer address for EK/DK/CT access |
| `0x8C` | BUF_DATA | R/W | Buffer data byte (read/write, auto-increment) |
| `0x90` | BUF_SEL | W | `[1:0]` buffer select: `0`=EK, `1`=DK, `2`=CT |

**Operation flow:** write seeds → write `CTRL` with `start=1` → poll `STATUS.done` (or use
`irq_done`) → read `SS` / buffer. `irq_done` pulses when an operation completes.

**Byte ordering:** the 32-byte seeds/keys are packed into the 256-bit registers
**least-significant byte first** (byte 0 → `reg[7:0]`, byte 31 → `reg[255:248]`). When
importing official NIST ACVP vectors, load them into the registers in this order.

---

## 5. Verification

The design is verified against the official **NIST ACVP test vectors** for ML-KEM
(`usnistgov/ACVP-Server`). The `tb/` directory contains self-contained testbenches that
self-check against expected values (no external data files required).

| Check | Result |
|-------|--------|
| K-PKE KeyGen / Encrypt / Decrypt round-trip (`tb_roundtrip.v`) | PASS (message recovered) |
| ML-KEM KeyGen (`ek`, `dk`) | byte-exact vs ACVP (25/25) |
| ML-KEM Encaps (`K`, `ct`) | byte-exact vs ACVP |
| ML-KEM Decaps (valid ct → `K`) | byte-exact vs ACVP |
| ML-KEM Decaps (invalid ct → `K̄`, implicit rejection) | correct |
| Keccak-f[1600] (`tb_f1600.v`), SHA3-512 (`tb_sha3.v`) | match known values |
| NTT (`tb_ntt_clean.v`), base-mult (`tb_basemul.v`) | PASS |

### Testbenches included

| Testbench | Verifies |
|-----------|----------|
| `tb_f1600.v` | Keccak-f[1600] permutation |
| `tb_sha3.v` | SHA3-512 hash (`G`, `H`) |
| `tb_ntt_clean.v` | NTT / inverse-NTT |
| `tb_basemul.v` | polynomial base multiplication |
| `tb_kpke_keygen.v` | K-PKE.KeyGen |
| `tb_kpke_encrypt.v` | K-PKE.Encrypt |
| `tb_mlkem_core.v` | core orchestrator |
| `tb_mlkem_keygen.v` | ML-KEM.KeyGen |
| `tb_mlkem_top.v` | full top-level AXI testbench |
| `tb_roundtrip.v` | K-PKE KeyGen → Encrypt → Decrypt round-trip |

### Simulation

**Icarus Verilog (fast, primitive-level):**
```sh
# K-PKE round-trip (KeyGen -> Encrypt -> Decrypt)
iverilog -g2012 -o roundtrip -I rtl/pkg $(find rtl -name '*.v') tb/tb_roundtrip.v
vvp roundtrip

# Keccak-f[1600] / SHA3-512 unit tests
iverilog -g2012 -o f1600 -I rtl/pkg rtl/keccak/keccak_f1600.v rtl/keccak/keccak_round.v tb/tb_f1600.v
vvp f1600
```

**Vivado (full top-level AXI testbench):** `vivado -mode batch -source run_rt_roundtrip.tcl`
(or the `syn/run_genus.tcl` / `syn/syn_mlkem.tcl` scripts for synthesis).

---

## 6. Notes on FIPS 203 conformity

- **`G(d‖k)`** (=SHA3-512) expands the KeyGen seed into `(ρ, σ)`.
- **Matrix sampling** uses `XOF(ρ‖j‖i)` (=SHAKE-128) with rejection sampling (`sample_ntt`).
- **Secret/error noise** uses `PRF(σ‖i)` (=SHAKE-256) → `SamplePolyCBD` (`sample_cbd`).
- **NTT / inverse NTT** use the FIPS 203 Appendix-A twiddle tables in `rtl/pkg/ntt_rom.v`
  and the Montgomery/Barrett reductions in `rtl/math/`.
- **Encapsulate** computes `(K,r) = G(m‖H(ek))` then `c = K-PKE.Encrypt(ek, m, r)`.
- **Decapsulate** performs implicit rejection (Fujisaki-Okamoto): it decrypts, re-derives
  `(K',r')`, re-encrypts, and returns `K'` if the ciphertext matches, else `K̄ = J(z‖c)`
  (=SHAKE-256). The ciphertext comparison is performed in constant time.

---

## 7. Finite State Machines

Every operation is sequenced by a dedicated FSM. The tables below list the states of
each bus controller; the lower-level datapath FSM (hash sponge) is shared.

### 7.1 `mlkem_hash_engine` — shared Keccak sponge (4 states)

| State | Purpose |
|-------|---------|
| `S_ABSORB`  | XOR incoming bytes into the 1600-bit state; trigger a permutation on a full rate block |
| `S_PAD`     | Apply multi-rate padding (`^ 0x06`/`0x1F`, `^ 0x80`), then start the final permutation |
| `S_PERMUTE` | Wait for Keccak-f[1600] `kf_done` |
| `S_SQUEEZE` | Emit output bytes (one per `squeeze_next`); run another permutation if the rate is exhausted |

### 7.2 `mlkem_keygen` — ML-KEM.KeyGen (9 states)

```
IDLE → KPKE_KG → WAIT_KG → COPY_EK → HASH_EK → WAIT_HASH → WRITE_HASH → WRITE_Z → DONE
```
`WAIT_KG` runs the K-PKE.KeyGen engine; `COPY_EK` appends `ek` to `dk`;
`WRITE_HASH`/`WRITE_Z` add `H(ek)` and `z`.

### 7.3 `mlkem_encaps` — ML-KEM.Encaps (10 states)

```
IDLE → COPY_EK → HASH_EK → WAIT_H_EK → HASH_MH → WAIT_G → ENCRYPT → WAIT_ENC → OUTPUT → DONE
```
`HASH_EK` = `H(ek)`; `HASH_MH` = `G(m‖H(ek))` → `(K,r)`; `ENCRYPT` runs
K-PKE.Encrypt feeding the EK from `ek_buf`; `OUTPUT` emits the shared secret `K`.

### 7.4 `mlkem_decaps` — ML-KEM.Decaps (20 states)

```
IDLE → PARSE_DK → BUFFER → FEED_DEC → WAIT_DEC → HASH_MH → WAIT_G → KDF
     → KDF_ABSORB_Z → KDF_ABSORB_C → WAIT_KDF → KDF_SQUEEZE → REENCRYPT
     → REENC_COPY → FEED_REENC → WAIT_REENC → SELECT → DONE
```
`PARSE_DK` extracts `h`/`z`; `BUFFER` loads `dkPKE` and `c` into internal arrays;
`FEED_DEC` streams them to K-PKE.Decrypt → `m'`; `HASH_MH` = `G(m'‖h)`;
`KDF_*` = `K̄ = SHAKE-256(z‖c)`; `REENC_COPY`/`FEED_REENC` re-encrypt `c' = Encrypt(ek,m',r')`;
`WAIT_REENC` performs the **constant-time** `c == c'` comparison; `SELECT` returns `K'` if
they match, else `K̄` (implicit rejection).

### 7.5 K-PKE datapath FSMs

| Module | States | High-level flow |
|--------|--------|-----------------|
| `kpke_keygen` | 30 | `G(d‖k)` → PRF/CBD `s,e` → NTT → `Â` sampling → basemul × acc → `t̂` → encode `ek`,`dkPKE` |
| `kpke_encrypt` | 52 | decode `ek` → PRF/CBD `y,e₁,e₂` → NTT → `Âᵀ∘ŷ` → INTT → add errors → compress → `c1‖c2` |
| `kpke_decrypt` | 27 | decode `c1,c2` → decompress → NTT `u` → `ŝ∘û` → INTT → `w` → `v-w` → compress → `m'` |

### 7.6 State counts

| FSM | Number of states |
|-----|------------------|
| `mlkem_hash_engine` | 4 |
| `mlkem_keygen` | 9 |
| `mlkem_encaps` | 10 |
| `mlkem_decaps` | 20 |
| `kpke_keygen` | 30 |
| `kpke_encrypt` | 52 |
| `kpke_decrypt` | 27 |

All FSMs are Mealy/Moore controllers implemented with a single `always @(posedge clk)`
block; handshake signals (`start`/`busy`/`done`, `*_valid`/`*_req`) sequence the pipelined
datapath blocks.

---

## 8. Timing / cycle counts (ML-KEM-768)

Cycle counts below were measured on the RTL datapath (core computation only, excluding the
AXI4-Lite register payload transfer). The testbenches clock the design at **100 MHz**
(10 ns period).

### 8.1 Operation cycle counts (measured)

| Operation | Clock cycles | Time @ 100 MHz |
|-----------|--------------|----------------|
| `ML-KEM-768.KeyGen` | 101,484 | ≈ 1.01 ms |
| `ML-KEM-768.Encaps` | 132,895 | ≈ 1.33 ms |
| `ML-KEM-768.Decaps` | 189,472 | ≈ 1.89 ms |
| K-PKE round-trip (`KeyGen→Encrypt→Decrypt`) | ≈ 281,000 | ≈ 2.81 ms |

Notes:
- These are per-operation, single-shot latencies for the core datapath (K-PKE + hash + NTT),
  not the full end-to-end AXI4-Lite transaction (which additionally moves the 1184-B `ek`,
  2400-B `dk`, 1088-B `ct`, and the 32-B seeds/secret across the register interface).
- Cycle counts scale with the parameter set (larger `K` → more matrix/NTT work).
- The bulk of the latency is Keccak permutations (SHA3/SHAKE) and the NTT /
  pointwise-multiply stages.

### 8.2 Primitive latencies

| Primitive | Latency (cycles) |
|-----------|------------------|
| `keccak_f1600` permutation | 25 (24 rounds + load) |
| SHA3-512 (`G`) | 25 per 72-byte block (+ squeeze) |
| SHAKE-256 / SHA3-256 | 25 per 136-byte block (+ squeeze) |
| NTT / inverse-NTT | 7 butterfly layers |
| Base multiplication | 128 pointwise products |

---

## 9. License

GPLv3 (see header of each RTL file).
