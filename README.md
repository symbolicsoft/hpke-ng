# hpke-ng

[![CI](https://github.com/symbolicsoft/hpke-ng/actions/workflows/ci.yml/badge.svg)](https://github.com/symbolicsoft/hpke-ng/actions)
[![License](https://img.shields.io/badge/license-Apache--2.0%20OR%20MIT-blue)](#license)

A clean-slate Rust implementation of [HPKE (RFC 9180)](https://www.rfc-editor.org/rfc/rfc9180.html) with type-driven ciphersuite selection.

> Read the announcement: **[hpke-ng: Faster, Smaller, Harder HPKE for Rust](https://symbolic.software/blog/2026-05-08-hpke-ng/)** — for the full design rationale, benchmarks, and migration notes.

```rust
use hpke_ng::*;
use rand::rngs::SysRng;
use rand_core::UnwrapErr;

type Suite = Hpke<DhKemX25519HkdfSha256, HkdfSha256, ChaCha20Poly1305>;

let mut os = SysRng;
let mut rng = UnwrapErr(&mut os);
let (sk_r, pk_r) = DhKemX25519HkdfSha256::generate(&mut rng)?;
let (enc, ct)  = Suite::seal_base(&mut rng, &pk_r, b"info", b"aad", b"hello")?;
let pt         = Suite::open_base(&enc, &sk_r, b"info", b"aad", &ct)?;
assert_eq!(pt, b"hello");
# Ok::<_, hpke_ng::HpkeError>(())
```

## Why a new HPKE crate?

`hpke-ng` exists because three friction points in the existing Rust HPKE story kept producing real bugs and real overhead:

1. **Provider abstraction overhead.** A trait-based pluggable backend pushes dispatch costs into hot paths and inflates the `Hpke` struct to hundreds of bytes — for a value the type system already knows.
2. **Struct-owned PRNG hazard.** When the `Hpke` instance owns its RNG, cloning silently aliases randomness state. The fix is structural: don't own it.
3. **Type-system gaps.** `Option<&[u8]>` for mode-specific parameters turns missing-PSK and wrong-mode into runtime errors that should be compile errors.

The design takes one position on each: **no provider abstraction, no owned RNG, type parameters instead of mode enums.** The math is a solved problem; the surrounding library is where the engineering still has slack.

## Design highlights

- **Type-parameterized API.** `Hpke<K, F, A>` is zero-sized; the ciphersuite lives in the type system. Mismatched primitives are compile errors.
- **Four explicit methods per mode.** `seal_base`, `seal_psk`, `seal_auth`, `seal_auth_psk` — no `Option<&[u8]>` parameters for required-by-mode arguments.
- **Validated PSK bundle.** PSK modes take a single `Psk`, built by `Psk::new(secret, id)`, which enforces the RFC 9180 32-byte minimum up front. The PSK and its identifier — one secret, one usually public — cannot be transposed at a call site.
- **Auth restricted to DHKEMs at the type level.** `Hpke::<XWingDraft06, ...>::seal_auth(...)` does not compile.
- **Export-only restricted at the type level.** `Hpke::<_, _, ExportOnly>::seal_base(...)` does not compile; only `*_export*` methods are available.
- **Type-tagged keys.** Private keys carry their KEM in their type, so passing a `DhKemP256` key into an X25519 suite is rejected by the compiler, not at runtime.
- **Caller-provided RNG.** No PRNG owned by the configuration; cloning cannot alias randomness.
- **Structural nonce-reuse prevention.** `Context` is non-cloneable and refuses to encrypt at `seq == u64::MAX`.
- **`no_std` + `alloc`.** `HpkeError` implements `core::error::Error` regardless; the default `std` feature only forwards `std` to the `subtle` dependency.
- **One provider stack.** All primitives from RustCrypto-org crates.

## Compile-time guarantees

| Operation                                | Elsewhere       | hpke-ng                        |
|------------------------------------------|-----------------|--------------------------------|
| Calling `seal_auth` on a non-DH KEM      | Runtime error   | Compile error                  |
| Using a wrong-KEM private key            | Runtime mismatch| Compile error (type-tagged)    |
| Base-mode call with a PSK supplied       | Runtime error   | Compile error (no PSK param)   |
| Encrypt with an `ExportOnly` AEAD        | Runtime error   | Compile error                  |
| Transposing `psk` and `psk_id`           | Silent wrong key| Not expressible (one `Psk` arg)|

## Supported ciphersuites

| Component | Variants |
|-----------|----------|
| KEMs      | `DhKemX25519HkdfSha256`, `DhKemX448HkdfSha512`, `DhKemP256HkdfSha256`, `DhKemP384HkdfSha384`, `DhKemP521HkdfSha512`, `DhKemK256HkdfSha256` |
| KEMs (post-quantum, `pq` feature) | `XWingDraft06`, `MlKem768`, `MlKem1024` — registered by [draft-ietf-hpke-pq](https://datatracker.ietf.org/doc/draft-ietf-hpke-pq/), not RFC 9180 |
| KDFs      | `HkdfSha256`, `HkdfSha384`, `HkdfSha512` |
| AEADs     | `Aes128Gcm`, `Aes256Gcm`, `ChaCha20Poly1305`, `ExportOnly` |
| Modes     | Base, Psk, Auth, AuthPsk |

## Performance

`hpke-ng` is benchmarked head-to-head against the two major Rust HPKE libraries, `hpke-rs` and `rust-hpke`, across **137 benchmark cells** (76 against `hpke-rs`, 61 against `rust-hpke`) spanning every supported ciphersuite. A cell counts as a *tie* when the two medians fall within ±2% of each other.

| Comparison       | Cells  | Wins   | Ties   | Losses |
|------------------|-------:|-------:|-------:|-------:|
| vs `hpke-rs`     |     76 |     61 |     13 |      2 |
| vs `rust-hpke`   |     61 |     38 |      7 |     16 |
| **Combined**     | **137**| **99** | **20** | **18** |

> `rust-hpke` has no standalone ML-KEM-768 / ML-KEM-1024 and no secp256k1 support, so those ciphersuites are scored only against `hpke-rs`.

### Where the KEM wins come from

Most of the speedup traces to two pieces of caching. On the **decapsulation** path, `hpke-ng` stores the expanded FIPS 203 decapsulation key directly in the `PrivateKey`, whereas `hpke-rs` rebuilds it from the seed on every `setup_receiver`. For **classical KEMs**, caching the recipient's serialized public key alongside the secret removes a redundant base-point scalar multiplication on every decap.

| Operation                 | vs `hpke-rs`        | vs `rust-hpke`     |
|---------------------------|---------------------|--------------------|
| ML-KEM-768 / 1024 decap   | **54–56% faster**   | n/a                |
| X25519 decap              | **44% faster**      | **51% faster**     |
| X-Wing decap              | **38% faster**      | ≈ parity ¹         |
| ML-KEM encap              | 33–41% faster       | n/a                |
| X-Wing encap              | 15% faster          | ≈ parity           |

¹ `rust-hpke` wraps raw decap inside a full HPKE setup, so the closest comparison is `hpke-ng`'s `setup_receiver`, which lands at roughly parity.

### AEAD and single-shot throughput

| Operation                          | vs `hpke-rs`             | vs `rust-hpke`                           |
|------------------------------------|--------------------------|------------------------------------------|
| Export (all 5 output lengths)      | **71–76% faster**        | —                                        |
| Single-shot open (all payloads)    | 13–41% faster            | 8–47% faster                             |
| AES-128-GCM single-shot seal       | 9–22% faster (≤ 16 KiB)  | 29–51% faster (≤ 4 KiB); slower ≥ 16 KiB |
| Post-setup `Context::seal` (64 B)  | 13% faster               | 44% faster                               |
| End-to-end roundtrip (1 KiB)       | **30% faster**           | **49% faster**                           |

Export is the largest sustained advantage over `hpke-rs`. For bulk AEAD the per-byte rates converge as payloads grow: `rust-hpke` pulls ahead on AES-GCM at ≥ 16 KiB, and on post-setup `Context::seal` at ≥ 1 KiB, once framing overhead stops dominating.

*(n/a = unsupported by that library; — = no separate head-to-head figure reported.)*

### Memory and binary footprint

| Quantity                                   | hpke-rs   | hpke-ng                                | rust-hpke     |
|--------------------------------------------|-----------|----------------------------------------|---------------|
| `Hpke<K, F, A>` struct                     | 344 bytes | **0 bytes** (`PhantomData`)            | n/a           |
| `Context<_, _, ChaCha20Poly1305>` struct   | 424 bytes | **88 bytes**                           | 96 bytes      |
| `Context<_, _, ExportOnly>` struct         | n/a       | **56 bytes**                           | 184 bytes     |
| `Context<_, _, Aes128Gcm>` struct          | 424 bytes | 792 bytes                              | 912 bytes     |
| `Context<_, _, Aes256Gcm>` struct          | 424 bytes | 1,048 bytes                            | 1,168 bytes   |
| Minimal release binary                     | 586 KB    | **370 KB** (~37% smaller than hpke-rs) | 385 KB        |

**Notes on the table above:**

- `rust-hpke` has no typed configuration handle — it uses free `setup_sender` / `setup_receiver` functions rather than a struct like `Hpke<K, F, A>`, so that row is n/a. Its context types are `AeadCtxS<A, Kdf, Kem>` (sender) and `AeadCtxR<A, Kdf, Kem>` (receiver), measured here as `AeadCtxS` with `X25519HkdfSha256` + `HkdfSha256`.
- Context size grows by `Nh` bytes with a larger KDF — e.g. +32 bytes for `HkdfSha512`.
- `ExportOnly` maps to `rust-hpke`'s `ExportOnlyAead`. It is larger there (184 B vs 56 B) because `rust-hpke`'s `AeadCtx` always reserves space for a full nonce buffer regardless of the AEAD variant.
- The AES-GCM `Context` rows are larger in `hpke-ng` than in `hpke-rs` because the expanded round keys + GHash table are cached inline — which is exactly what eliminates the per-call AES key-schedule cost in `Context::seal`. AES-GCM streaming trades memory for throughput; `ChaCha20-Poly1305` is unaffected.

### Reproducing the benchmarks

Build with `RUSTFLAGS="-C target-cpu=native"` to pick up AES-NI / SHA-NI where available; `[profile.bench]` in `Cargo.toml` sets `lto = "thin"` and `codegen-units = 1`. For the head-to-head numbers:

```bash
cargo bench --features comparative --bench comparative
```

This loads both `hpke-rs` (with its `experimental` feature, so the post-quantum KEM stubs are wired up) and `rust-hpke` 0.14 (whose X-Wing support the comparison needs) as dev-dependencies, and emits side-by-side criterion results for every supported ciphersuite. KEM-op rows for `hpke-rs` and `rust-hpke` carry a `_via_setup_*` suffix: neither library exposes raw `encap` / `decap` separable from setup, so those rows are explicitly *not* apples-to-apples with `hpke-ng`'s bare-operation rows.

## Security posture

The library responds to two classes of issue observed in prior implementations:

- **Zero shared-secret check (RFC 9180 §7.1.4).** Enforced for every DH group — X25519, X448 and the four prime-order curves — with `subtle::ConstantTimeEq`. It is unreachable on the prime-order curves given a validated public key and a non-zero scalar; it is kept there as defense in depth and for parity.
- **Nonce counter wraparound.** Prevented structurally: `Context` uses a `u64` sequence number, refuses to encrypt at `u64::MAX`, and is non-cloneable so a counter cannot fork.

The post-DH all-zeros check is constant-time. `Context` cannot be `Clone`d, so two ciphertexts cannot be produced under the same `(key, nonce)` from two copies of the same context.

### Hazmat features

`hazmat-kat-internals` and `hazmat-differential` exist for this crate's own known-answer and differential harnesses. They make raw AEAD keys and exporter secrets readable off a `Context`, make `key_schedule_*` callable with a caller-supplied shared secret, and make `SenderContext::from_context` public — which together are enough to fork two sender contexts from one key schedule and seal twice under the same `(key, base_nonce, seq)`. That is exactly the nonce reuse `Context: !Clone` exists to prevent.

Cargo unifies features across the whole dependency graph, so one unrelated crate enabling either feature would otherwise switch that exposure on for the entire build, silently. Neither `--cfg` flags nor environment variables are unified that way, and a dependency's build script cannot set either for *this* crate's compilation, so both features are additionally gated on `RUSTFLAGS="--cfg hpke_ng_hazmat"` (or `HPKE_NG_HAZMAT=1`, for tools such as `trybuild` that control `RUSTFLAGS` themselves). Without one of those the build fails with an explanatory error. A dependency cannot supply either on your behalf.

### AEAD usage limits

`seal` refuses at `seq == u64::MAX` — the point at which the nonce would repeat — and that is the only per-key limit this crate enforces. RFC 9180 §7.3.1 recommends rekeying well before `2^64` messages for the AES-GCM suites, but the safe figure depends on the confidentiality and integrity advantage a given deployment will accept, so it is not a number this crate can pick for you. `SenderContext::sequence_number` and `ReceiverContext::sequence_number` expose the counter so an application can set and enforce its own threshold, tearing down the context and running a fresh HPKE setup when it is crossed.

### Deterministic key derivation

`Kem::derive_key_pair` is deterministic and performs no entropy check on its `ikm`: `derive_key_pair(b"")` succeeds and returns a key pair anyone can reproduce. Entropy is not observable, and unlike `Psk::new` — where a length floor is a workable proxy — a floor here would reject the RFC's own conformant KAT inputs while still admitting a long low-entropy string. Use `Kem::generate` unless you specifically need deterministic derivation, and never derive from a password without a slow password-hashing KDF (e.g. Argon2) in front.

## Constant-time considerations

This crate composes RustCrypto primitives. Constant-time properties are inherited from those crates:

| Primitive | CT property |
|-----------|-------------|
| X25519, X448 | CT by construction. |
| P-256, P-384, P-521, secp256k1 | CT in `arithmetic` mode (pinned). |
| HKDF-SHA-{256,384,512} | CT (deterministic; no secret-dependent branches). |
| ChaCha20-Poly1305 | CT by construction. |
| AES-128-GCM, AES-256-GCM | **CT only with hardware AES-NI/PCLMULQDQ.** Prefer `ChaCha20Poly1305` on platforms without these instructions. |
| ML-KEM, X-Wing | CT per upstream documentation; both crates are pre-1.0. |

## Zeroization

Everything this crate controls is scrubbed: private keys, shared secrets, PRKs, candidate scalars, seeds, and the derived AEAD key and base nonce are held in `Zeroizing`/`ZeroizeOnDrop` wrappers, with explicit manual scrubbing wherever an upstream type lacks zeroize-on-drop (the X448 scalar and shared-secret point, `GenericArray` temporaries from `SecretKey::to_bytes` and `HkdfExtract::finalize`, and the ML-KEM/X-Wing shared-secret arrays).

**Known limitation — transient stack copies.** A handful of upstream constructors take secret material *by value* (`x25519_dalek::StaticSecret::from([u8; 32])`, `x_wing::DecapsulationKey::from(seed)`, `ml_kem::DecapsulationKey::from_seed`), so the seed or scalar is copied out of its `Zeroizing` wrapper into an unscrubbed temporary for the duration of the call. The owned copies on both sides of that boundary are scrubbed; the temporary is not, and cannot be without a by-reference upstream API.

**Known limitation — HKDF/HMAC internal state.** The RustCrypto `hkdf`/`hmac` crates do not zeroize their internal HMAC state on drop. Every HKDF extract/expand operation therefore leaves PRK-derived ipad/opad block state transiently in freed memory. This is key-equivalent material: an attacker who can read process memory (core dumps, swap, a same-process memory-disclosure bug) could recover it while the allocation remains unreused. The limitation is shared by every RustCrypto-based HPKE implementation and cannot be fixed from this crate. Deployments with a strong memory-forensics threat model should disable core dumps and swap (or use encrypted swap) for processes holding HPKE keys.

## Testing

```bash
cargo test              # library, roundtrip, negative matrix
cargo test --features pq # + post-quantum, X-Wing KAT, rust-hpke differential

# The suites below need the `hazmat-` features, which are refused at compile
# time without the second opt-in below. See "Hazmat features" under Security
# posture for why.
# `trybuild` strips RUSTFLAGS from the sub-build it drives, so the compile-fail
# suite needs the env-var form of the same opt-in.
export RUSTFLAGS="--cfg hpke_ng_hazmat" HPKE_NG_HAZMAT=1
cargo test --features pq,hazmat-kat-internals                     # + RFC 9180 KAT
cargo test --features pq,hazmat-kat-internals --test compile_fail # + compile-time invariant tests
cargo test --features pq,hazmat-differential,hazmat-kat-internals # + differential vs hpke-rs
```

To regenerate the compile-fail `.stderr` fixtures after an intentional change (e.g. a toolchain bump), run:
```bash
HPKE_NG_HAZMAT=1 TRYBUILD=overwrite \
  cargo test --features pq,hazmat-kat-internals --test compile_fail
```
This rewrites the fixtures unconditionally and should not be used as the normal test invocation.

Coverage includes:

- **Roundtrip matrix** — 57 macro-generated tests across every ciphersuite × mode combination.
- **Negative matrix** — 19 tests asserting that each transcript input actually binds (`info`, `aad`, PSK, PSK ID, sender public key), that tampered, truncated and replayed ciphertexts are refused, and that a failed `open` leaves the sequence counter untouched.
- **Known-answer tests** — the RFC 9180 vectors for X25519, X448, P-256, P-521 and secp256k1, plus the official X-Wing draft vectors.
- **Cross-implementation differential** — against `hpke-rs` (X25519, P-256, secp256k1) and against `rust-hpke` (P-384, P-521, ML-KEM-768, ML-KEM-1024, X-Wing, with X25519/P-256 as controls). Between the two, every supported ciphersuite is checked against either published vectors or an independent implementation.
- **Compile-fail tests** — locking in the type-system invariants: `Context` is non-cloneable, `ExportOnly` cannot seal, PQ KEMs cannot authenticate, each key-schedule path rejects the wrong mode tag, and external crates cannot implement the sealed supertrait.
- **Unit tests** — including direct verification of the RFC 9180 §5.2 nonce derivation formula (`nonce = base_nonce XOR I2OSP(seq, Nn)`) at sequence-number boundaries.
- **Fuzzing** — five `cargo-fuzz` targets over the parsers, `DeriveKeyPair`, the key schedule, and `open`; panics are treated as bugs.

The full suite (without the `hpke-rs` differential) runs in under two seconds.

## Migration from `hpke-rs`

Three mechanical steps, typically under an hour for a real codebase:

1. Define a `type Suite = Hpke<K, F, A>;` alias for the ciphersuite you use.
2. Replace `hpke.seal(...)` calls with the explicit mode method: `Suite::seal_base`, `seal_psk`, `seal_auth`, or `seal_auth_psk`.
3. Thread `&mut rng` through call sites — the configuration no longer owns one.

See the [announcement post](https://symbolic.software/blog/2026-05-08-hpke-ng/) for a worked example.

## Authors

hpke-ng is a joint project between [Nadim Kobeissi](https://nadim.computer) and [Daniel Dia](https://danieldia.me).

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or [MIT license](LICENSE-MIT) at your option.
