# Changelog

## [0.2.0] - 2026-07-27

- **Breaking: post-quantum `DeriveKeyPair` now follows draft-ietf-hpke-pq.** The PQ KEMs were implementing the superseded draft-connolly conventions: ML-KEM took the IKM verbatim as the 64-byte `(d, z)` seed (and rejected any other length), and X-Wing used a bare `SHAKE256(ikm, 32)`. draft-ietf-hpke-pq §3.2/§4.2 instead derive the seed with `SHAKE256.LabeledDerive(ikm, "DeriveKeyPair", "", Nsk)` — the one-stage-KDF construction from draft-ietf-hpke-hpke §4, which mixes in `"HPKE-v1"`, the KEM `suite_id`, the length-prefixed label, and `I2OSP(L, 2)`. Consequences: `derive_key_pair` on `MlKem768`, `MlKem1024` and `XWingDraft06` returns **different key pairs than 0.1.x for the same IKM**, and any IKM length is now accepted. Generated and wire-loaded keys are unaffected, as are all wire formats and the key schedule; only IKM-derived keys change. `HpkeError::InvalidKeyMaterial` becomes unreachable as a result, and is removed below.
- **New: cross-implementation differential tests against `rust-hpke`** (`tests/differential_rust_hpke.rs`), covering the four KEMs that previously had no independent validation at all — P-384, ML-KEM-768, ML-KEM-1024, X-Wing — plus P-521, and X25519/P-256 as controls. Each suite runs both directions through public APIs only (no `hazmat-` feature), comparing key serializations, ciphertext interop, and exporter output. `DeriveKeyPair` is compared for every KEM; those rows are what verify the `LabeledDerive` byte layout above.
- **New: X-Wing known-answer tests** (`tests/kat_xwing.rs`) against the official draft vectors, driving `generate` and `encap` from the vectors' seeds to pin the seed-to-key-pair expansion and both wire formats.
- **New: negative/tamper test matrix** (`tests/negative.rs`, 19 tests). Asserts that `info`, `aad`, the PSK, the PSK ID and the sender's public key each actually bind; that ciphertext bit-flips, truncation, tampered encapsulated keys and wrong recipient keys are rejected; that a failed `open` does not advance the sequence counter; that replayed and out-of-order messages are refused; and that exporter output is separated by context, `info` and length.
- **Breaking: PSK-mode entry points take one validated `Psk` instead of `psk` + `psk_id`.** `Psk::new(secret, id)` runs the RFC 9180 §5.1.2 checks once at construction, so `MissingPsk` / `InconsistentPsk` / `InsecurePsk` now surface there rather than from `seal_psk` / `open_psk` / `setup_*_psk` / `*_export_*_psk`. The motivation is misuse resistance: `seal_psk(rng, pk_r, info, aad, pt, psk, psk_id)` had five consecutive `&[u8]` parameters, and transposing `psk` with `psk_id` — a value that is usually public — compiled silently and keyed the session off the public one. Grouping them also removes every `#[allow(clippy::too_many_arguments)]` in the crate, and makes `HpkeError::UnnecessaryPsk` unreachable — supplying a PSK to a Base or Auth entry point is no longer expressible — so it too is removed below.
- **Breaking: `DhKem` takes one type parameter.** The KDF a DHKEM is defined with is now the `DiffieHellman::Kdf` associated type rather than a second parameter on `DhKem<D, H>`. `DhKem<X25519, HkdfSha512>` used to be constructible: it advertised KEM ID `0x0020` while deriving with SHA-512, and its `derive_key_pair` used SHA-256 regardless, so the type was internally inconsistent as well as unregistered. The six public aliases (`DhKemX25519HkdfSha256` and friends) are unchanged, so code using them needs no edits; only code naming `DhKem` directly does. A compile-fail test locks the invariant in.
- **Removed: dead code and dead weight.** The `sha3` dependency and the `serde` feature are gone — the library referenced neither. So are `HpkeError::UnnecessaryPsk` and `HpkeError::InvalidKeyMaterial`, which no code path can return any more; the callerless `hazmat`-gated `DhKem::auth_encap_with_ikm`; the unused `labeled_extract_z` helper; and the seven stale `#[allow(dead_code)]` attributes that were masking it. No per-item `allow` remains in `src/`.
- **The published crate no longer carries ~9 MB of test vectors.** `cargo add hpke-ng` fetched 2.0 MiB compressed; it now fetches 97 KiB. The RFC 9180 vectors stay in the git repository, so the `hazmat-kat-internals` harness needs a checkout rather than the crates.io tarball. The X-Wing vectors are `include_str!`d and still ship.
- Zeroization gaps closed. The derived AEAD key and exporter secret are now wrapped in `Zeroizing` as they are produced, so a failure part-way through the key schedule no longer drops already-derived key material unscrubbed; `Context::new` takes them pre-wrapped, so its own early return from a failed `Aead::init` cannot leak them either. Secret seeds and scalars loaded in `generate` and `sk_from_bytes` (X25519, X448, ML-KEM, X-Wing) are staged in `Zeroizing` instead of bare stack arrays. `Kem::SharedSecret` now requires `ZeroizeOnDrop`, making the scrub-on-drop guarantee structural rather than conventional.
- `Kdf::expand` checks the RFC 5869 `255 * Nh` output bound *before* allocating. A caller passing a huge length previously attempted the allocation first, aborting instead of returning `ExportLengthExceeded`.
- Two heap allocations removed from every DH `encap` and `auth_decap`: `kem_context` now borrows the serialized public key that `DhPublicKey` and `DhPrivateKey` already hold instead of re-serializing it. `MlKemSharedSecret` is a fixed `[u8; 32]` rather than a `Vec`, matching `XWingSharedSecret`.
- Fixed: the `compile_fail` test declared `required-features = ["pq"]`, but four of its fixtures reference `__test_only` and so need `hazmat-kat-internals` too. Under `--features pq` alone they failed to compile for the wrong reason and the suite reported a spurious mismatch. Surfaced by the new `cargo test --features pq` CI leg.
- CI hardening. The fuzz targets are now **run** (60s each, per push) rather than only compiled — the previous job did `cargo check` and the README overstated it. Added a `stable` and `beta` toolchain leg so upcoming-compiler breakage surfaces before it lands, with the `trybuild` suite confined to the pinned MSRV since its fixtures pin exact rustc diagnostics. Added `cargo-deny` (advisories, bans, licenses, sources) with a `deny.toml` whose allow-list matches the graph as it stands, a `cargo package --locked` job so tarball and manifest problems surface in CI, `clippy` on `--no-default-features`, a `cargo test --features pq` leg, a bare-metal `--no-default-features --features pq` check (the PQ KEMs were never verified for `no_std` before), and `cargo fmt --check` over the fuzz workspace, whose formatting had drifted.
- **Breaking: RNG API moves to `rand_core` 0.10.** All `rng`-taking entry points now bound `R: CryptoRng` instead of `CryptoRng + RngCore`. Callers replace `OsRng` + `unwrap_mut()` with `rand::rngs::SysRng` wrapped in `rand_core::UnwrapErr`. The internal 0.9→0.6 and 0.9→0.10 RNG shims are gone.
- **Breaking: `differential` / `kat-internals` features renamed to `hazmat-differential` / `hazmat-kat-internals`.** They expose secret internals (raw key, exporter secret, ephemeral-key injection), and Cargo feature unification means one crate enabling them enables them for everyone in that build — the prefix makes that visible.
- ML-KEM `zeroize()` now drops the expanded decapsulation key, not just the `(d, z)` seed; `decap` on a zeroized key returns `DecapError` instead of panicking.
- README documents zeroization scope and one limitation: RustCrypto `hkdf`/`hmac` leave HMAC state in freed memory after every extract/expand.
- Dependencies: `x25519-dalek` 2 → 3, `p256`/`p384`/`p521`/`k256` 0.13 → 0.14, `x-wing` `0.1.0-rc.0` → 0.1.0.

## [0.1.0]

### Security & correctness

- **Breaking: `Context` is split into one-directional `SenderContext` and `ReceiverContext`.** `setup_sender_*` now returns `SenderContext` (exposes `seal` + `export`); `setup_receiver_*` returns `ReceiverContext` (exposes `open` + `export`). Neither implements `Clone`. A sender and the matching receiver derive the identical `(key, base_nonce)`, so a single type that could both seal and open made using one session in both directions a catastrophic AEAD `(key, nonce)` reuse — the split turns that misuse into a compile error. For a bidirectional channel, run a separate HPKE setup per direction or derive independent per-direction keys via `export` (RFC 9180 §9.8).
- New `HpkeError::InvalidKeyMaterial` variant. ML-KEM-768/1024 `derive_key_pair` requires exactly 64 bytes of `(d, z)` seed (draft-connolly-cfrg-hpke-mlkem §3.2); any other IKM length now returns `InvalidKeyMaterial` rather than a less specific error.
- Internal hardening: the key schedule is split into PSK-free (Base/Auth) and PSK-bearing (PSK/AuthPSK) fast paths selected by sealed `PskFreeMode` / `PskMode` marker tags instead of a raw `u8` mode byte. Routing a PSK mode through the PSK-free path (or vice versa) is now a compile error. The tags are `#[doc(hidden)]` and not part of the public API.

### Performance

- Auth encap/decap no longer heap-allocate the concatenated DH inputs. A piecewise `extract_and_expand_pieces` feeds `dh1`/`dh2` and the KEM context directly into HKDF-Extract/Expand, removing the per-call `Vec` build-and-copy across all four auth paths. `base_nonce` is now stack-allocated and the hot-path KEM helpers are inlined.

### Dependencies

- `ml-kem` upgraded `0.3.0-rc.0` → `0.3.2`, replacing a release-candidate dependency with a stable release. `hkdf` 0.12 → 0.13, `sha2` 0.10 → 0.11, `sha3` 0.10 → 0.12; a new optional `shake` dependency is pulled in by the `pq` feature. The `std` feature no longer force-enables the hash crates' own `std` features.

### Testing & benchmarks

- A `trybuild` compile-fail suite locks in the misuse-resistant API: a `SenderContext` cannot `open`, a `ReceiverContext` cannot `seal`, contexts are not `Clone`, export-only ciphersuites cannot seal, external crates cannot implement the sealed traits, PQ KEMs cannot be used in auth modes, and each key-schedule path rejects the wrong mode tag.
- Fuzzing is wired into GitHub CI; the key-schedule fuzz target was updated for the typed mode-tag API.
- `rust-hpke` (rozbb) added as a third head-to-head benchmark target. Coverage is now 137 benchmark cells (76 vs `hpke-rs`, 61 vs `rust-hpke`); hpke-ng wins 99, ties 20, loses 18 — losses concentrated against `rust-hpke` on large-payload AES-GCM seal and key-generation paths. `CONTRIBUTORS.md` added.

## [0.1.0-rc.3] - 2026-05-09

- Performance: cache the recipient's serialized public key in `DhPrivateKey<D>` so DH `decap`/`auth_decap` skip the per-call base-point scalar multiplication (X25519 decap −41%, P-curve decap proportionally larger).
- Performance: cache the expanded `x_wing::DecapsulationKey` in `XWingPrivateKey` (X-Wing decap −38% — same trick as ML-KEM, previously missed for X-Wing).
- Performance: cache the parsed `EncapsulationKey` in PQ public-key wrappers (ML-KEM encap −30% to −37%, X-Wing encap −14%).
- Performance: `Aead` trait now exposes a cached `Cipher` associated type built once via `Aead::init` at key schedule time; AES-GCM `Context::seal` skips the per-call key schedule + GHash precompute. Sealed trait — no external impact.
- Performance: `Kdf::extract` / `expand` accept piecewise slices (`&[&[u8]]`) to avoid materialising labeled-IKM/info `Vec`s. Sealed trait — no external impact.
- Across 62 head-to-head benchmarks vs `hpke-rs`, hpke-ng now wins 43 (was 27), ties 14, loses 5 — losses are all on `derive_key_pair`/`generate` paths the one-time cost paid for the per-call decap/encap savings.

## [0.1.0-rc.2] - 2026-05-08

- Expose `sk_to_bytes` which serializes a private key to bytes (zeroized on drop).

## [0.1.0-rc.1] - 2026-05-08

- First release candidate.
