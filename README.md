# ML-KEM-768 Hardware Implementation (FIPS 203)

Verilog RTL for **ML-KEM-768**, the post-quantum key encapsulation mechanism
standardised by NIST as [FIPS 203](https://csrc.nist.gov/pubs/fips/203/final)
(formerly CRYSTALS-Kyber). AXI4-Lite control interface, a single shared
Keccak-f[1600] sponge, and verification against the official NIST ACVP vectors.

Target: **ZedBoard** (Zynq-7020, `xc7z020clg484-1`) — 29,858 LUTs, 56% of the device.

> FIPS 203 is ML-KEM (key encapsulation). FIPS 204 is ML-DSA (signatures) and is
> a different algorithm; this core does not implement it.

---

## Contents

- [Parameters](#parameters)
- [What ML-KEM does](#what-ml-kem-does)
- [Architecture](#architecture)
- [Datapath](#datapath)
- [Shared Keccak sponge](#shared-keccak-sponge)
- [Buffer interface](#buffer-interface)
- [Input validation](#input-validation)
- [Register map](#register-map)
- [Usage sequence](#usage-sequence)
- [Resource utilization](#resource-utilization)
- [Timing](#timing)
- [Verification](#verification)
- [Building](#building)
- [File layout](#file-layout)
- [License](#license)

---

## Parameters

ML-KEM-768, NIST security category 3.

| Parameter | Value | Meaning |
|---|---|---|
| `q` | 3329 | prime modulus |
| `n` | 256 | polynomial degree |
| `K` | 3 | module rank |
| `ETA1`, `ETA2` | 2, 2 | CBD noise parameters |
| `DU`, `DV` | 10, 4 | ciphertext compression |

Byte sizes:

| Object | Bytes |
|---|---:|
| Encapsulation key `ek` | 1184 |
| Decapsulation key `dk` | 2400 |
| Ciphertext `c` | 1088 |
| Shared secret `K` | 32 |

The top level is parameterised (`K`, `ETA1`, `ETA2`, `DU`, `DV`), so ML-KEM-512
and ML-KEM-1024 are reachable by parameter change, but only ML-KEM-768 is
verified here.

---

## What ML-KEM does

ML-KEM lets two parties agree on a shared 32-byte secret over a public channel,
secure against an adversary with a quantum computer.

| Operation | Input | Output |
|---|---|---|
| **KeyGen** | randomness `d`, `z` | `ek` (public), `dk` (private) |
| **Encaps** | `ek`, randomness `m` | `c`, `K` |
| **Decaps** | `dk`, `c` | `K` |

The sender encapsulates against the recipient's public `ek`, transmits `c`, and
both sides hold the same `K`. Security rests on the Module Learning With Errors
problem over `Z_q[X]/(X^256 + 1)`.

### The two layers

FIPS 203 defines ML-KEM in two layers, and the RTL mirrors that split.

**K-PKE** (Algorithms 13-15) is an IND-CPA public-key encryption scheme:

```
K-PKE.KeyGen(d):     (rho, sigma) = G(d || k)
                     A_hat = SampleNTT(rho)            K x K matrix
                     s, e  = SamplePolyCBD(PRF(sigma))
                     t_hat = A_hat o NTT(s) + NTT(e)
                     ek = ByteEncode12(t_hat) || rho ,  dk = ByteEncode12(s_hat)

K-PKE.Encrypt(ek, m, r):
                     y, e1, e2 = SamplePolyCBD(PRF(r))
                     u = NTT^-1(A_hat^T o NTT(y)) + e1
                     v = NTT^-1(t_hat^T o NTT(y)) + e2 + Decompress1(m)
                     c = Compress_du(u) || Compress_dv(v)

K-PKE.Decrypt(dk, c): m' = Compress1( v - s_hat^T o NTT(u) )
```

**ML-KEM** (Algorithms 16-18) wraps that in the Fujisaki-Okamoto transform to
reach IND-CCA2 security — the property that matters when an attacker can submit
chosen ciphertexts:

```
KeyGen_internal(d, z):   (ek, dk_PKE) = K-PKE.KeyGen(d)
                         dk = dk_PKE || ek || H(ek) || z

Encaps_internal(ek, m):  (K, r) = G(m || H(ek))
                         c = K-PKE.Encrypt(ek, m, r)

Decaps_internal(dk, c):  m'       = K-PKE.Decrypt(dk_PKE, c)
                         (K', r') = G(m' || h)
                         K_bar    = J(z || c)
                         c'       = K-PKE.Encrypt(ek, m', r')    <- re-encrypt
                         return   c == c' ? K' : K_bar           <- implicit rejection
```

The **re-encryption and constant-time compare** in Decaps is the point of the FO
transform. A malformed ciphertext must not produce a distinguishable failure:
instead of an error, the core returns `K_bar = J(z || c)`, a pseudorandom value
derived from the private `z`. An attacker cannot tell rejection from success,
and must not learn it from timing — so the comparison XOR-accumulates **all 1088
bytes** and never exits early.

### Hash functions

| Symbol | Function | Used for |
|---|---|---|
| `G` | SHA3-512 | `(rho, sigma)` from `d`; `(K, r)` from `m \|\| H(ek)` |
| `H` | SHA3-256 | binding `ek` into `dk` and into `K` |
| `J` | SHAKE-256 | implicit-rejection key `K_bar` |
| `PRF` | SHAKE-256 | CBD noise sampling |
| `XOF` | SHAKE-128 | rejection sampling of `A_hat` |

---

## Architecture

```
mlkem_top                     AXI4-Lite + ek/dk/ct block RAM buffers
├── mlkem_axi_lite_if         register file, buffer access window
└── mlkem_core                operation sequencer (op_sel), owns shared resources
    ├── mlkem_keygen          Algorithm 16 — dk = dk_PKE || ek || H(ek) || z
    │   └── kpke_keygen       Algorithm 13
    ├── mlkem_encaps          Algorithm 17 — (K, r) = G(m || H(ek))
    ├── mlkem_decaps          Algorithm 18 — re-encrypt + constant-time compare
    │   └── kpke_decrypt      Algorithm 15
    ├── kpke_encrypt          Algorithm 14 — one instance, shared by Encaps
    │                         and the Decaps re-encryption
    ├── hash_mux              4-way arbiter onto the sponge
    └── keccak_sponge         one Keccak-f[1600] sponge for the whole design
```

Only one of KeyGen / Encaps / Decaps runs at a time, selected by `op_sel`. That
is what allows `kpke_encrypt` and the Keccak sponge to be single instances:
Encaps and the Decaps re-encryption never overlap.

Leaf blocks: `ntt`, `ntt_core`, `ntt_butterfly`, `poly_basemul`, `poly_arith`,
`montgomery_reduce`, `barrett_reduce`, `sample_ntt`, `sample_cbd`, `byte_encode`,
`byte_decode`, `compress`, `decompress`, `poly_ram`, `ntt_rom`.

---

## Datapath

### Number-theoretic transform

Polynomial multiplication dominates the cost, so it is done in the NTT domain
where it becomes pointwise. For `q = 3329`, `X^256 + 1` factors into 128
quadratics, so the NTT is **incomplete**: 7 layers, leaving 128 degree-1
polynomials that `poly_basemul` multiplies pairwise using the
`zeta^(2*BitRev7(i)+1)` twiddles of FIPS 203 Appendix A.

- `ntt.v` / `ntt_core.v` — 7-layer Cooley-Tukey forward and Gentleman-Sande
  inverse, selected by a `mode` input; the inverse folds in the `n^-1 = 1441`
  scaling
- `ntt_butterfly.v` — **two-stage pipeline**: stage 1 is the multiply and its
  Montgomery reduction, stage 2 the add/sub and Barrett reduction. Callers wait
  on `valid_out` rather than assuming a fixed latency, so the split can be moved
  without touching their state machines
- `ntt_rom.v` — precomputed zeta tables
- `montgomery_reduce.v`, `barrett_reduce.v` — reduction mod 3329 without division

### Multiplier mapping

The reducers multiply by **constants** (`QINV = 62209`, `Q = 3329`,
`BARRETT_V = 20159`), which map cheaply to LUT/carry logic, so they carry
`(* use_dsp = "no" *)`. Only the genuine variable-by-variable products —
`zeta * b` in the butterfly and `a * b` in `poly_basemul` — are left free to
infer DSP48 slices. This keeps DSP usage at 40 of 220 rather than 106.

### Sampling

- `sample_ntt.v` — rejection samples `A_hat` directly in the NTT domain from a
  SHAKE-128 stream: 3 bytes give two 12-bit candidates, those `< q` are kept.
  Squeezes **on demand** with no fixed buffer, so it cannot run short.
- `sample_cbd.v` — centred binomial distribution, `eta = 2`, from a SHAKE-256
  PRF stream.

### Compression

`compress.v` / `decompress.v` implement `Compress_d` / `Decompress_d`, the lossy
rounding that shrinks the ciphertext (`du = 10` for `u`, `dv = 4` for `v`).
`byte_encode.v` / `byte_decode.v` handle 12-bit-to-byte packing.

---

## Shared Keccak sponge

All five hash roles use Keccak-f[1600], differing only in rate and domain
separator:

| Variant | Rate | Domain |
|---|---:|---|
| SHAKE-128 | 168 | `0x1F` |
| SHAKE-256 | 136 | `0x1F` |
| SHA3-256 | 136 | `0x06` |
| SHA3-512 | 72 | `0x06` |

`keccak_sponge.v` therefore takes `rate_bytes` and `domain_sep` as **runtime
inputs**, so one instance serves every variant. It owns the 1600-bit state, the
`keccak_f1600` round core, padding, and the byte-lane absorb/squeeze addressing.

The familiar `sha3_256` / `sha3_512` / `shake128` / `shake256` wrappers are
retained unchanged; `mlkem_hash_engine.v` is a thin shim that forwards their
requests onto the shared bus, tagging each with its own rate and domain. The bus
is packed so it costs two ports per hierarchy level:

```
req = {init, rate[7:0], dom[7:0], absorb_valid, absorb_data[7:0],
       absorb_last, squeeze_next}                                 28 bits
rsp = {absorb_ready, squeeze_valid, squeeze_data[7:0], busy}      11 bits
```

`hash_mux.v` arbitrates. Because every hash use is strictly sequential within an
operation (KeyGen runs G, then the XOF per matrix entry, then the PRF per noise
polynomial; Encaps runs H, G, then XOF/PRF; Decaps runs G, J, then the
re-encryption), ownership simply follows `init` and no queueing is required. A
non-owner is answered `absorb_ready = 0`, `squeeze_valid = 0`, `busy = 1`, so it
can never mistake another client's grant for its own.

Modules with several local clients (`kpke_keygen`, `kpke_encrypt`,
`mlkem_keygen`, `mlkem_encaps`, `mlkem_decaps`) arbitrate with their own
`hash_mux` and present one channel upward; `mlkem_core` merges the four
remaining channels onto the sponge.

---

## Buffer interface

`mlkem_core` reads `ek` / `dk` / `ct` from external byte buffers. **The contract
is a registered (synchronous) read: an address issued at cycle `t` returns its
byte at `t+2`.** That is what lets `mlkem_top` infer block RAM for the 6.3 KB of
key material instead of spending fabric on it.

Consumers honour the contract with one of two idioms:

- **Age counter** — for feeds that must *hold* a byte until a Keccak engine
  accepts it (`H(ek)`, `J(z || c)`). The address is held, a counter tracks cycles
  since it settled, and the byte is offered only once certainly valid. Necessary
  because `absorb_ready` drops for a whole permutation at every rate boundary, so
  the byte must stay stable and must not be re-offered after acceptance.
- **Countdown** — for feeds that present one byte per downstream request
  (`ek` to encrypt, `ct`/`dk` to decrypt, `ek` to re-encrypt). One read is issued
  per request and the byte presented when the countdown expires.

Both are one cycle conservative, so they also tolerate a faster buffer. **Any
testbench modelling these buffers must register the read** — `tb_kat_multi.v` and
`tb_mlkem_top.v` both do.

---

## Input validation

FIPS 203 §7.2 and §7.3 require both key checks, and both are implemented.

**§7.2 encapsulation key check** (`mlkem_encaps`). Verifies
`ByteEncode12(ByteDecode12(ek)) == ek`, i.e. every 12-bit coefficient is `< q`.
Done on the fly while `ek` streams into `H(ek)`, so it costs no extra pass: each
3-byte group yields two coefficients, both compared against 3329. Only the first
`384*K` bytes are coefficients; the trailing 32 are `rho`. On failure the core
abandons encapsulation **before** the expensive encrypt and emits no shared
secret.

**§7.3 decapsulation key check** (`mlkem_decaps`). Recomputes `H(ek)` over the
`ek` embedded in `dk` and compares it against the stored `h` field. Runs before
decryption. Cheap because the sponge is shared — it adds a small wrapper FSM, not
another 1600-bit state.

Both surface as `op_error` on `mlkem_core`, latched into **`STATUS` bit[2]** and
cleared on the next start. When set, no shared secret is produced.

**`op_error` is fatal for that operation.** If it is set after Decaps, the
contents of `SS[0:7]` must not be used as a key — the register still holds
whatever the previous operation left there, not a shared secret. Treat the
operation as failed and discard the key.

---

## Register map

AXI4-Lite slave, 32-bit data. Byte address = register index x 4.

| Offset | Name | Access | Description |
|---|---|---|---|
| `0x00` | `CTRL` | W | `[1:0]` op_sel — `00` KeyGen, `01` Encaps, `10` Decaps. `[8]` start |
| `0x04` | `STATUS` | R | `[0]` busy, `[1]` done (sticky), `[2]` input-check error — when set, `SS` is not valid |
| `0x08`-`0x24` | `SEED_D[0:7]` | W | KeyGen seed `d`, 32 B |
| `0x28`-`0x44` | `SEED_Z[0:7]` | W | KeyGen implicit-rejection seed `z`, 32 B |
| `0x48`-`0x64` | `SEED_M[0:7]` | W | Encaps message `m`, 32 B |
| `0x68`-`0x84` | `SS[0:7]` | R | shared secret `K`, 32 B |
| `0x88` | `BUF_ADDR` | W | buffer byte address; auto-increments on `BUF_DATA` access |
| `0x8C` | `BUF_DATA` | R/W | buffer data byte in `[7:0]` |
| `0x90` | `BUF_SEL` | W | `00` ek, `01` dk, `10` ct |

`irq_done` mirrors `op_done` as a one-cycle pulse.

**Byte order.** All 32-byte values are little-endian in the register block: byte
`i` of the byte string sits at bit `8i`, so `SEED_D[0][7:0]` is `d[0]`. `BUF_*`
access is plain byte-addressed, lowest byte first.

Buffers are reachable over AXI only while no operation is running — `op_busy`
selects the core's own address onto the RAM.

---

## Usage sequence

```c
// --- KeyGen ---
write SEED_D[0..7], SEED_Z[0..7]
write CTRL = (1<<8) | 0x0             // start, op_sel = KeyGen
poll  STATUS until bit[1] (done)
read  ek : BUF_SEL=0, BUF_ADDR=0, then 1184 reads of BUF_DATA
read  dk : BUF_SEL=1, BUF_ADDR=0, then 2400 reads of BUF_DATA

// --- Encaps (against a peer's ek) ---
write ek : BUF_SEL=0, BUF_ADDR=0, then 1184 writes of BUF_DATA
write SEED_M[0..7]
write CTRL = (1<<8) | 0x1
poll  STATUS until done
if (STATUS & 0x4) -> ek rejected by Sec 7.2: operation failed,
//                      do NOT read or use SS[0:7]
read  c  : BUF_SEL=2, BUF_ADDR=0, then 1088 reads
read  K  : SS[0..7]

// --- Decaps ---
write dk : BUF_SEL=1, ... 2400 bytes
write c  : BUF_SEL=2, ... 1088 bytes
write CTRL = (1<<8) | 0x2
poll  STATUS until done
if (STATUS & 0x4) -> dk rejected by Sec 7.3: operation failed,
//                      do NOT read or use SS[0:7]
read  K  : SS[0..7]
```

`d`, `z` and `m` must come from an approved random bit generator. This core takes
randomness as an input and does not generate it.

---

## Resource utilization

Out-of-context synthesis, Vivado 2023.2, `xc7z020clg484-1` (ZedBoard), 38 ns.

| Resource | Used | Available | Util |
|---|---:|---:|---:|
| Slice LUTs | 29,858 | 53,200 | **56.1%** |
| Slice Registers | 30,821 | 106,400 | 29.0% |
| Block RAM tiles | 12 | 140 | 8.6% |
| DSP48E1 | 40 | 220 | 18.2% |

The 6.3 KB of `ek`/`dk`/`ct` buffers map to block RAM (1x RAMB36 + RAMB18s). The
single shared sponge accounts for roughly 10k LUTs of the total; the rest is the
NTT datapath, the K-PKE control, and the encode/decode blocks.

---

## Timing

Measured on `xc7z020clg484-1` (`-1` speed grade):

| Period | WNS (post-synthesis) |
|---:|---:|
| 10 ns (100 MHz) | -23.769 ns |
| 38 ns (26.3 MHz) | **+1.920 ns**, setup met, 0 failing endpoints |

**These are post-synthesis numbers and are not sign-off.** Post-synthesis there
is no routing, so net delays are ~0 and nearly every path reports a hold
violation — an artifact, since hold is resolved by the router. Run
`syn/run_vivado_impl.tcl` for post-route WNS and WHS, which are the numbers that
establish closure. **Post-route closure has not been demonstrated.**

The critical path is `poly_basemul`, which computes seven products in parallel,
each feeding a combinational Montgomery reduction with no pipeline register.
Raising the frequency further means pipelining it the way `ntt_butterfly` already
is, then re-measuring — the math datapath is combinational throughout, so each
added stage exposes the next.

### Cycle counts

Measured from `tb_mlkem_top`, one clock domain:

| Operation | Approx. cycles |
|---|---:|
| KeyGen | ~110,000 |
| Encaps | ~150,000 |
| Decaps | ~220,000 |

Decaps is longest because Algorithm 18 performs a full **re-encryption** on top
of decryption for the FO check — inherent to the standard.

---

## Verification

Vectors come from the NIST ACVP server repository; nothing is hand-transcribed:

```
usnistgov/ACVP-Server
    gen-val/json-files/ML-KEM-keyGen-FIPS203/internalProjection.json
    gen-val/json-files/ML-KEM-encapDecap-FIPS203/internalProjection.json
```

```sh
python tb/kat/gen_vectors.py --download -o tb/kat/vectors
iverilog -g2012 -I tb/kat/vectors -I rtl/pkg -o kat.vvp \
         tb/tb_kat_multi.v $(find rtl -name '*.v')
vvp kat.vvp
```

| Testbench | Covers | Result |
|---|---|---|
| `tb_kat_multi.v` | KeyGen / Encaps / Decaps vs 20 ACVP vectors | 20/20 pass |
| `tb_kat_keycheck.v` | §7.2 / §7.3 vs 20 ACVP key-check vectors | 20/20 pass |
| `tb_mlkem_top.v` | AXI4-Lite + block-RAM buffers, full round trip | pass |
| `tb_roundtrip.v` | K-PKE KeyGen → Encrypt → Decrypt | pass |

**40 official NIST ACVP vectors**, every output byte compared: `ek` (1184 B), the
complete `dk` (2400 B, so the `H(ek)` and `z` fields are checked too), `c`
(1088 B) and `K`.

Two properties of the vector selection matter:

- The decapsulation set mixes **5 valid ciphertexts with 5 modified ones**. A
  comparison stuck at "always mismatch" passes every rejection vector while
  failing every valid one, and vice versa — both polarities are needed to show
  the implicit-rejection path actually discriminates.
- The key-check set likewise mixes accept and reject cases, so a check wired to a
  constant cannot pass.

`reference/ref_mlkem768.py` is a bit-accurate K-PKE model for cross-checking
intermediate values (`ek`, `dk`, `ct`, NTT and Keccak internals). Wrapped in
Algorithms 16-18 it passes all 60 ML-KEM-768 ACVP vectors, so it serves as a
golden model when debugging.

---

## Building

```sh
# Simulation (Icarus Verilog)
python tb/kat/gen_vectors.py --download -o tb/kat/vectors
iverilog -g2012 -I tb/kat/vectors -I rtl/pkg -o kat.vvp tb/tb_kat_multi.v $(find rtl -name '*.v')
vvp kat.vvp

# Synthesis (Vivado) — writes syn/reports/<part>_<period>ns/
vivado -mode batch -source syn/run_vivado_synth.tcl -tclargs xc7z020clg484-1 38.0

# Place & route and sign-off timing
vivado -mode batch -source syn/run_vivado_impl.tcl  -tclargs xc7z020clg484-1 38.0

# ASIC (Cadence Genus) — set the library paths in the script first
genus -f syn/run_genus.tcl
```

`syn/mlkem.sdc` is plain SDC readable by both Vivado (`read_xdc`) and Genus
(`read_sdc`). The clock period defaults to 10 ns and can be overridden by setting
`CLK_PERIOD_NS` before the file is read, which the Vivado scripts do from their
command line.

---

## File layout

```
rtl/
├── pkg/       mlkem_params.vh, ntt_rom.v
├── keccak/    keccak_sponge (shared, runtime rate/domain), keccak_f1600,
│              keccak_round, hash_mux, mlkem_hash_engine (client shim),
│              sha3_256, sha3_512, shake128, shake256
├── math/      ntt, ntt_core, ntt_butterfly (2-stage), poly_basemul,
│              poly_arith, montgomery_reduce, barrett_reduce, modular_arith
├── sample/    sample_ntt (rejection), sample_cbd (binomial noise)
├── encode/    byte_encode, byte_decode, compress, decompress
├── mem/       poly_ram
├── kpke/      kpke_keygen, kpke_encrypt, kpke_decrypt          (Alg 13-15)
└── mlkem/     mlkem_top, mlkem_core, mlkem_axi_lite_if,
               mlkem_keygen, mlkem_encaps, mlkem_decaps         (Alg 16-18)

tb/
├── tb_kat_multi.v      NIST ACVP KAT, self-checking
├── tb_kat_keycheck.v   FIPS 203 Sec 7.2 / 7.3 checks, self-checking
├── tb_mlkem_top.v      AXI + block RAM round trip, self-checking
├── tb_roundtrip.v      K-PKE round trip, self-checking
└── kat/gen_vectors.py  pulls vectors straight from the NIST ACVP JSON

reference/   ref_mlkem768.py (K-PKE model), ref_keccak.py
syn/         mlkem.sdc, run_vivado_synth.tcl, run_vivado_impl.tcl,
             run_genus.tcl, syn_mlkem.tcl
```

---

## Limitations

- **Post-route timing closure is not demonstrated.** Setup meets at 38 ns
  post-synthesis; run `syn/run_vivado_impl.tcl` before relying on any frequency.
- **Does not meet 100 MHz.** `poly_basemul` is the critical path; see
  [Timing](#timing).
- **Randomness is an input** — `d`, `z`, `m` must come from an approved RBG.
- **Side channels beyond the ciphertext compare are unaudited.** The FO
  comparison is constant-time by construction, but no wider timing or power
  analysis has been performed. The §7.2/§7.3 checks act on public keys and on the
  caller's own private key, not on attacker-chosen ciphertexts.
- Only ML-KEM-768 is verified, though the parameters are generic.

---

## License

GPL v3 — see [LICENSE](LICENSE) and the header of every RTL source file.

Copyright (C) 2026 Abhinav S
