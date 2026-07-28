//! Head-to-head comparative benchmarks: hpke-ng vs hpke-rs vs rust-hpke.
//!
//! Run with:
//! ```
//! RUSTFLAGS="-C target-cpu=native" cargo bench --features comparative --bench comparative
//! ```
//!
//! ## Coverage
//!
//! - **KEM ops** — generate / derive_key_pair / encap / decap, across X25519,
//!   P-256, K256, X-Wing (draft-06), ML-KEM-768, and ML-KEM-1024. Not every
//!   library supports every curve or exposes every operation directly; see
//!   the per-group notes for which rows are present and why.
//! - **Setup paths** — setup_sender across all ciphersuites; setup_receiver
//!   for x25519/chacha20 and the three PQ suites (X-Wing, ML-KEM-768,
//!   ML-KEM-1024). PSK mode covered for x25519/chacha20 across all three
//!   libraries.
//! - **Single-shot seal/open** — full seal()/open() across a payload-size
//!   sweep, two AEAD primitives (ChaCha20-Poly1305, AES-128-GCM), both
//!   directions.
//! - **Context seal/open** — the post-setup hot path (framing + AEAD only).
//!   Context open uses a lockstep design: sender and receiver contexts are
//!   established once outside the timed loop and their sequence counters
//!   advance together on every iteration (seal then open). No KEM setup is
//!   included. The measured time is seal + open combined; subtract the
//!   corresponding context_seal measurement to obtain pure open latency.
//! - **Export** — secret export across 5 output lengths.
//! - **End-to-end round-trip** — total cost of encrypt-then-decrypt of one
//!   1 KiB message; the headline single number.
//!
//! ## Criterion settings (per group)
//!
//! Chosen to bound total wall-clock while keeping confidence intervals tight:
//!
//! | Group                | sample_size | measurement_time       |
//! |----------------------|-------------|------------------------|
//! | KEM / setup          | 60          | 3 s  (quick() default) |
//! | seal/open sweeps     | 40          | 2 s                    |
//! | context seal/open    | 50          | 2 s                    |
//! | export               | 60          | 2 s                    |
//! | round-trip           | 50          | 3 s                    |
//!
//! Payload sizes: the ChaCha20 seal sweep runs the full 8 (16 B .. 256 KiB);
//! the AES-128 seal sweep and both open sweeps run a reduced 6 (64 B .. 64 KiB),
//! dropping the extremes to keep wall-clock down.
//!
//! ## Naming
//!
//! Each group has parallel members — `hpke_ng/...`, `hpke_rs/...`,
//! `rust_hpke/...` — so criterion renders them side-by-side. Where a row name
//! carries a `_via_setup_*` suffix, that library has no public API for the
//! bare operation and the closest analog (which does extra work) is measured
//! instead; such rows are NOT directly comparable to the bare-operation rows
//! and are labeled accordingly.
//!
//! ## hpke-rs PRNG seeding
//!
//! hpke-rs's `hpke-test-prng` dev-dependency replays a fixed byte buffer (the
//! `SEED` constant) as its randomness source. It is seeded ONCE per benchmark
//! group, in setup code — never inside a timed `b.iter()` closure. The bare
//! `seed()` cost was measured at ~58 ns and deliberately hoisted out of all
//! timed loops so it does not bias any hpke-rs measurement. Operations that
//! consume no randomness (derive_key_pair, setup_receiver, open, export,
//! Context::seal/open) require no seeding at all.

#![cfg(feature = "comparative")]

use std::hint::black_box;
use std::sync::LazyLock;
use std::time::Duration;

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};

use hpke_ng::{self as ng, Kem as _};

use hpke_rs::{Hpke as HpkeRs, Mode};
use hpke_rs_crypto::types as rs_types;
use hpke_rs_rust_crypto::HpkeRustCrypto;

use hpke::{
	Kem as _, OpModeR, OpModeS, PskBundle,
	aead::{AesGcm128 as RhAes128, AesGcm256 as RhAes256, ChaCha20Poly1305 as RhChaCha20},
	kdf::HkdfSha256 as RhHkdfSha256,
	kem::{DhP256HkdfSha256 as RhP256, X25519HkdfSha256 as RhX25519, XWing as RhXWing},
};

use rand::{Rng as _, SeedableRng};

/// Deterministic-PRNG seed for hpke-rs.
///
/// hpke-rs's `hpke-test-prng` dev-dependency replays this fixed buffer; each
/// randomness draw advances an internal cursor. Sized large enough that ONE
/// `seed()` call in per-group setup outlasts the whole group's iteration
/// count, so `seed()` never appears inside a timed `b.iter()` closure.
/// Criterion runs a fast op for its full measurement window — easily 10^5-10^6
/// iterations — so this must be megabytes, not kilobytes. If a bench panics
/// with `InsufficientRandomness`, increase this.
static SEED: LazyLock<Vec<u8>> = LazyLock::new(|| vec![0x5Eu8; 64 * 1024 * 1024]); // 64 MiB

const PAYLOAD_SIZES: &[usize] = &[16, 64, 256, 1024, 4096, 16384, 65536, 262144];
const EXPORT_LENGTHS: &[usize] = &[16, 32, 64, 128, 256];

fn quick() -> Criterion {
	// Shared defaults; per-group overrides applied below.
	Criterion::default()
		.sample_size(60)
		.measurement_time(Duration::from_secs(3))
		.warm_up_time(Duration::from_secs(1))
}

/// RhChaCha20Rng
///
/// rust-hpke and rand_chacha now both use `rand_core 0.10`. This newtype keeps
/// the benchmark's existing call sites explicit while delegating to the shared
/// deterministic ChaCha20 RNG.
///
/// Usage: `&mut RhChaCha20Rng(&mut prng)` wherever rust-hpke needs a csprng.
struct RhChaCha20Rng<'a>(&'a mut rand_chacha::ChaCha20Rng);

impl hpke::rand_core::TryRng for RhChaCha20Rng<'_> {
	type Error = core::convert::Infallible;

	fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
		Ok(self.0.next_u32())
	}

	fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
		Ok(self.0.next_u64())
	}

	fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Self::Error> {
		self.0.fill_bytes(dest);
		Ok(())
	}
}

impl hpke::rand_core::TryCryptoRng for RhChaCha20Rng<'_> {}

// =============================================================================
//  KEM operations: generate / derive_key_pair / encap / decap
//  Across X25519, P-256, K256 (all three KEMs hpke-rs/RustCrypto supports).
// =============================================================================

fn bench_kem_x25519(c: &mut Criterion) {
	let mut g = c.benchmark_group("kem/x25519");
	let mut prng = rand_chacha::ChaCha20Rng::from_seed([0x42u8; 32]);

	// COMPARABILITY NOTE (encap / decap rows):
	// hpke-ng exposes bare `encap` and `decap` (KEM-only, no key schedule).
	// hpke-rs and rust-hpke have no such public API; the nearest equivalents are
	// `setup_sender` and `setup_receiver`, which include the full HPKE key
	// schedule on top of the KEM operation. Rows labeled `_via_setup_*` do
	// MORE work than their bare-operation counterparts and are explicitly NOT
	// directly comparable. The `generate` and `derive_key_pair` rows are
	// fully comparable across all three libraries.

	// generate for hpke-ng, hpke-rs, rust-hpke
	g.bench_function("hpke_ng/generate", |b| {
		b.iter(|| ng::DhKemX25519HkdfSha256::generate(&mut prng).unwrap())
	});
	{
		let mut rs = HpkeRs::<HpkeRustCrypto>::new(
			Mode::Base,
			rs_types::KemAlgorithm::DhKem25519,
			rs_types::KdfAlgorithm::HkdfSha256,
			rs_types::AeadAlgorithm::ChaCha20Poly1305,
		);
		rs.seed(&SEED).unwrap();
		g.bench_function("hpke_rs/generate", |b| {
			b.iter(|| rs.generate_key_pair().unwrap())
		});
	}
	g.bench_function("rust_hpke/generate", |b| {
		b.iter(|| RhX25519::gen_keypair_with_rng(&mut RhChaCha20Rng(&mut prng)))
	});

	// derive_key_pair (deterministic, no PRNG) for hpke-ng, hpke-rs, rust-hpke
	let ikm = [0x99u8; 32];
	g.bench_function("hpke_ng/derive_key_pair", |b| {
		b.iter(|| ng::DhKemX25519HkdfSha256::derive_key_pair(black_box(&ikm)).unwrap())
	});
	{
		let rs = HpkeRs::<HpkeRustCrypto>::new(
			Mode::Base,
			rs_types::KemAlgorithm::DhKem25519,
			rs_types::KdfAlgorithm::HkdfSha256,
			rs_types::AeadAlgorithm::ChaCha20Poly1305,
		);
		g.bench_function("hpke_rs/derive_key_pair", |b| {
			b.iter(|| rs.derive_key_pair(black_box(&ikm)).unwrap())
		});
	}
	g.bench_function("rust_hpke/derive_key_pair", |b| {
		b.iter(|| RhX25519::derive_keypair(black_box(&ikm)))
	});

	// hpke-ng encap
	{
		let (_, pk_ng) = ng::DhKemX25519HkdfSha256::generate(&mut prng).unwrap();
		g.bench_function("hpke_ng/encap", |b| {
			b.iter(|| ng::DhKemX25519HkdfSha256::encap(&mut prng, black_box(&pk_ng)).unwrap())
		});
	}

	// hpke-rs encap via `setup_sender`
	{
		let mut rs = HpkeRs::<HpkeRustCrypto>::new(
			Mode::Base,
			rs_types::KemAlgorithm::DhKem25519,
			rs_types::KdfAlgorithm::HkdfSha256,
			rs_types::AeadAlgorithm::ChaCha20Poly1305,
		);
		let (_sk, pk) = rs.derive_key_pair(&[0x42u8; 32]).unwrap().into_keys();
		rs.seed(&SEED).unwrap();
		g.bench_function("hpke_rs/encap_via_setup_sender", |b| {
			b.iter(|| {
				rs.setup_sender(black_box(&pk), b"", None, None, None)
					.unwrap()
			})
		});
	}

	// rust-hpke encap via `setup_sender`
	{
		let (_, pk) = RhX25519::gen_keypair_with_rng(&mut RhChaCha20Rng(&mut prng));
		g.bench_function("rust_hpke/encap_via_setup_sender", |b| {
			b.iter(|| {
				hpke::setup_sender_with_rng::<RhChaCha20, RhHkdfSha256, RhX25519>(
					&OpModeS::Base,
					black_box(&pk),
					b"",
					&mut RhChaCha20Rng(&mut prng),
				)
				.unwrap()
			})
		});
	}

	// hpke-ng decap
	{
		let (sk_ng, pk_ng) = ng::DhKemX25519HkdfSha256::generate(&mut prng).unwrap();
		let (_, enc_ng) = ng::DhKemX25519HkdfSha256::encap(&mut prng, &pk_ng).unwrap();
		g.bench_function("hpke_ng/decap", |b| {
			b.iter(|| ng::DhKemX25519HkdfSha256::decap(black_box(&enc_ng), &sk_ng).unwrap())
		});
	}
	// hpke-rs decap via `setup_receiver`
	{
		let mut rs = HpkeRs::<HpkeRustCrypto>::new(
			Mode::Base,
			rs_types::KemAlgorithm::DhKem25519,
			rs_types::KdfAlgorithm::HkdfSha256,
			rs_types::AeadAlgorithm::ChaCha20Poly1305,
		);
		let (sk, pk) = rs.derive_key_pair(&[0x42u8; 32]).unwrap().into_keys();
		rs.seed(&SEED).unwrap();
		let (enc, _ctx) = rs.setup_sender(&pk, b"", None, None, None).unwrap();
		g.bench_function("hpke_rs/decap_via_setup_receiver", |b| {
			b.iter(|| {
				rs.setup_receiver(black_box(&enc), &sk, b"", None, None, None)
					.unwrap()
			})
		});
	}

	// rust-hpke decap via `setup_receiver`
	{
		let (sk, pk) = RhX25519::gen_keypair_with_rng(&mut RhChaCha20Rng(&mut prng));
		let (enc, _) = hpke::setup_sender_with_rng::<RhChaCha20, RhHkdfSha256, RhX25519>(
			&OpModeS::Base,
			&pk,
			b"",
			&mut RhChaCha20Rng(&mut prng),
		)
		.unwrap();
		g.bench_function("rust_hpke/decap_via_setup_receiver", |b| {
			b.iter(|| {
				hpke::setup_receiver::<RhChaCha20, RhHkdfSha256, RhX25519>(
					&OpModeR::Base,
					black_box(&sk),
					black_box(&enc),
					b"",
				)
				.unwrap()
			})
		});
	}
	g.finish();
}

fn bench_kem_p256(c: &mut Criterion) {
	let mut g = c.benchmark_group("kem/p256");
	let mut prng = rand_chacha::ChaCha20Rng::from_seed([0x42u8; 32]);

	g.bench_function("hpke_ng/generate", |b| {
		b.iter(|| ng::DhKemP256HkdfSha256::generate(&mut prng).unwrap())
	});
	{
		let mut rs = HpkeRs::<HpkeRustCrypto>::new(
			Mode::Base,
			rs_types::KemAlgorithm::DhKemP256,
			rs_types::KdfAlgorithm::HkdfSha256,
			rs_types::AeadAlgorithm::Aes128Gcm,
		);
		rs.seed(&SEED).unwrap();
		g.bench_function("hpke_rs/generate", |b| {
			b.iter(|| rs.generate_key_pair().unwrap())
		});
	}
	g.bench_function("rust_hpke/generate", |b| {
		b.iter(|| RhP256::gen_keypair_with_rng(&mut RhChaCha20Rng(&mut prng)))
	});

	let ikm = [0x99u8; 32];
	g.bench_function("hpke_ng/derive_key_pair", |b| {
		b.iter(|| ng::DhKemP256HkdfSha256::derive_key_pair(black_box(&ikm)).unwrap())
	});
	{
		let rs = HpkeRs::<HpkeRustCrypto>::new(
			Mode::Base,
			rs_types::KemAlgorithm::DhKemP256,
			rs_types::KdfAlgorithm::HkdfSha256,
			rs_types::AeadAlgorithm::Aes128Gcm,
		);
		g.bench_function("hpke_rs/derive_key_pair", |b| {
			b.iter(|| rs.derive_key_pair(black_box(&ikm)).unwrap())
		});
	}
	g.bench_function("rust_hpke/derive_key_pair", |b| {
		b.iter(|| RhP256::derive_keypair(black_box(&ikm)))
	});

	{
		let (_, pk_ng) = ng::DhKemP256HkdfSha256::generate(&mut prng).unwrap();
		g.bench_function("hpke_ng/encap", |b| {
			b.iter(|| ng::DhKemP256HkdfSha256::encap(&mut prng, black_box(&pk_ng)).unwrap())
		});
	}
	{
		let mut rs = HpkeRs::<HpkeRustCrypto>::new(
			Mode::Base,
			rs_types::KemAlgorithm::DhKemP256,
			rs_types::KdfAlgorithm::HkdfSha256,
			rs_types::AeadAlgorithm::Aes128Gcm,
		);
		let (_sk, pk) = rs.derive_key_pair(&[0x42u8; 32]).unwrap().into_keys();
		rs.seed(&SEED).unwrap();
		g.bench_function("hpke_rs/encap_via_setup_sender", |b| {
			b.iter(|| {
				rs.setup_sender(black_box(&pk), b"", None, None, None)
					.unwrap()
			})
		});
	}
	{
		let (_, pk) = RhP256::gen_keypair_with_rng(&mut RhChaCha20Rng(&mut prng));
		g.bench_function("rust_hpke/encap_via_setup_sender", |b| {
			b.iter(|| {
				hpke::setup_sender_with_rng::<RhAes128, RhHkdfSha256, RhP256>(
					&OpModeS::Base,
					black_box(&pk),
					b"",
					&mut RhChaCha20Rng(&mut prng),
				)
				.unwrap()
			})
		});
	}

	{
		let (sk_ng, pk_ng) = ng::DhKemP256HkdfSha256::generate(&mut prng).unwrap();
		let (_, enc_ng) = ng::DhKemP256HkdfSha256::encap(&mut prng, &pk_ng).unwrap();
		g.bench_function("hpke_ng/decap", |b| {
			b.iter(|| ng::DhKemP256HkdfSha256::decap(black_box(&enc_ng), &sk_ng).unwrap())
		});
	}
	{
		let mut rs = HpkeRs::<HpkeRustCrypto>::new(
			Mode::Base,
			rs_types::KemAlgorithm::DhKemP256,
			rs_types::KdfAlgorithm::HkdfSha256,
			rs_types::AeadAlgorithm::Aes128Gcm,
		);
		let (sk, pk) = rs.derive_key_pair(&[0x42u8; 32]).unwrap().into_keys();
		rs.seed(&SEED).unwrap();
		let (enc, _ctx) = rs.setup_sender(&pk, b"", None, None, None).unwrap();
		g.bench_function("hpke_rs/decap_via_setup_receiver", |b| {
			b.iter(|| {
				rs.setup_receiver(black_box(&enc), &sk, b"", None, None, None)
					.unwrap()
			})
		});
	}
	{
		let (sk, pk) = RhP256::gen_keypair_with_rng(&mut RhChaCha20Rng(&mut prng));
		let (enc, _) = hpke::setup_sender_with_rng::<RhAes128, RhHkdfSha256, RhP256>(
			&OpModeS::Base,
			&pk,
			b"",
			&mut RhChaCha20Rng(&mut prng),
		)
		.unwrap();
		g.bench_function("rust_hpke/decap_via_setup_receiver", |b| {
			b.iter(|| {
				hpke::setup_receiver::<RhAes128, RhHkdfSha256, RhP256>(
					&OpModeR::Base,
					black_box(&sk),
					black_box(&enc),
					b"",
				)
				.unwrap()
			})
		});
	}
	g.finish();
}

fn bench_kem_k256(c: &mut Criterion) {
	let mut g = c.benchmark_group("kem/k256");
	let mut prng = rand_chacha::ChaCha20Rng::from_seed([0x42u8; 32]);

	g.bench_function("hpke_ng/generate", |b| {
		b.iter(|| ng::DhKemK256HkdfSha256::generate(&mut prng).unwrap())
	});
	{
		let mut rs = HpkeRs::<HpkeRustCrypto>::new(
			Mode::Base,
			rs_types::KemAlgorithm::DhKemK256,
			rs_types::KdfAlgorithm::HkdfSha256,
			rs_types::AeadAlgorithm::ChaCha20Poly1305,
		);
		rs.seed(&SEED).unwrap();
		g.bench_function("hpke_rs/generate", |b| {
			b.iter(|| rs.generate_key_pair().unwrap())
		});
	}

	let ikm = [0x99u8; 32];
	g.bench_function("hpke_ng/derive_key_pair", |b| {
		b.iter(|| ng::DhKemK256HkdfSha256::derive_key_pair(black_box(&ikm)).unwrap())
	});
	{
		let rs = HpkeRs::<HpkeRustCrypto>::new(
			Mode::Base,
			rs_types::KemAlgorithm::DhKemK256,
			rs_types::KdfAlgorithm::HkdfSha256,
			rs_types::AeadAlgorithm::ChaCha20Poly1305,
		);
		g.bench_function("hpke_rs/derive_key_pair", |b| {
			b.iter(|| rs.derive_key_pair(black_box(&ikm)).unwrap())
		});
	}

	{
		let (_, pk_ng) = ng::DhKemK256HkdfSha256::generate(&mut prng).unwrap();
		g.bench_function("hpke_ng/encap", |b| {
			b.iter(|| ng::DhKemK256HkdfSha256::encap(&mut prng, black_box(&pk_ng)).unwrap())
		});
	}
	{
		let (sk_ng, pk_ng) = ng::DhKemK256HkdfSha256::generate(&mut prng).unwrap();
		let (_, enc_ng) = ng::DhKemK256HkdfSha256::encap(&mut prng, &pk_ng).unwrap();
		g.bench_function("hpke_ng/decap", |b| {
			b.iter(|| ng::DhKemK256HkdfSha256::decap(black_box(&enc_ng), &sk_ng).unwrap())
		});
	}
	// rust-hpke omitted: K256 (secp256k1) is not in the HPKE RFC and has never been
	// added to rust-hpke; the library only implements the curves listed in RFC 9180.
	g.finish();
}

// DRAFT NOTE: all three libraries implement draft-connolly-cfrg-xwing-kem-06 via the
// same x-wing crate (^0.1.0-rc.0), share KEM_ID 0x647a, and produce interoperable
// shared secrets. Timing is directly comparable with no caveats.
fn bench_kem_xwing(c: &mut Criterion) {
	let mut g = c.benchmark_group("kem/xwing");
	let mut prng = rand_chacha::ChaCha20Rng::from_seed([0x42u8; 32]);

	g.bench_function("hpke_ng/generate", |b| {
		b.iter(|| ng::XWingDraft06::generate(&mut prng).unwrap())
	});
	{
		let mut rs = HpkeRs::<HpkeRustCrypto>::new(
			Mode::Base,
			rs_types::KemAlgorithm::XWingDraft06,
			rs_types::KdfAlgorithm::HkdfSha256,
			rs_types::AeadAlgorithm::ChaCha20Poly1305,
		);
		rs.seed(&SEED).unwrap();
		g.bench_function("hpke_rs/generate", |b| {
			b.iter(|| rs.generate_key_pair().unwrap())
		});
	}
	g.bench_function("rust_hpke/generate", |b| {
		b.iter(|| RhXWing::gen_keypair_with_rng(&mut RhChaCha20Rng(&mut prng)))
	});

	let ikm = [0x99u8; 32];
	g.bench_function("hpke_ng/derive_key_pair", |b| {
		b.iter(|| ng::XWingDraft06::derive_key_pair(black_box(&ikm)).unwrap())
	});
	{
		let rs = HpkeRs::<HpkeRustCrypto>::new(
			Mode::Base,
			rs_types::KemAlgorithm::XWingDraft06,
			rs_types::KdfAlgorithm::HkdfSha256,
			rs_types::AeadAlgorithm::ChaCha20Poly1305,
		);
		g.bench_function("hpke_rs/derive_key_pair", |b| {
			b.iter(|| rs.derive_key_pair(black_box(&ikm)).unwrap())
		});
	}
	g.bench_function("rust_hpke/derive_key_pair", |b| {
		b.iter(|| RhXWing::derive_keypair(black_box(&ikm)))
	});

	{
		let (_, pk_ng) = ng::XWingDraft06::generate(&mut prng).unwrap();
		g.bench_function("hpke_ng/encap", |b| {
			b.iter(|| ng::XWingDraft06::encap(&mut prng, black_box(&pk_ng)).unwrap())
		});
	}
	{
		let mut rs = HpkeRs::<HpkeRustCrypto>::new(
			Mode::Base,
			rs_types::KemAlgorithm::XWingDraft06,
			rs_types::KdfAlgorithm::HkdfSha256,
			rs_types::AeadAlgorithm::ChaCha20Poly1305,
		);
		let (_sk, pk) = rs.derive_key_pair(&[0x42u8; 32]).unwrap().into_keys();
		rs.seed(&SEED).unwrap();
		g.bench_function("hpke_rs/encap_via_setup_sender", |b| {
			b.iter(|| {
				rs.setup_sender(black_box(&pk), b"", None, None, None)
					.unwrap()
			})
		});
	}
	{
		let (_, pk) = RhXWing::gen_keypair_with_rng(&mut RhChaCha20Rng(&mut prng));
		g.bench_function("rust_hpke/encap_via_setup_sender", |b| {
			b.iter(|| {
				hpke::setup_sender_with_rng::<RhChaCha20, RhHkdfSha256, RhXWing>(
					&OpModeS::Base,
					black_box(&pk),
					b"",
					&mut RhChaCha20Rng(&mut prng),
				)
				.unwrap()
			})
		});
	}

	{
		let (sk_ng, pk_ng) = ng::XWingDraft06::generate(&mut prng).unwrap();
		let (_, enc_ng) = ng::XWingDraft06::encap(&mut prng, &pk_ng).unwrap();
		g.bench_function("hpke_ng/decap", |b| {
			b.iter(|| ng::XWingDraft06::decap(black_box(&enc_ng), &sk_ng).unwrap())
		});
	}
	{
		let mut rs = HpkeRs::<HpkeRustCrypto>::new(
			Mode::Base,
			rs_types::KemAlgorithm::XWingDraft06,
			rs_types::KdfAlgorithm::HkdfSha256,
			rs_types::AeadAlgorithm::ChaCha20Poly1305,
		);
		let (sk, pk) = rs.derive_key_pair(&[0x42u8; 32]).unwrap().into_keys();
		rs.seed(&SEED).unwrap();
		let (enc, _ctx) = rs.setup_sender(&pk, b"", None, None, None).unwrap();
		g.bench_function("hpke_rs/decap_via_setup_receiver", |b| {
			b.iter(|| {
				rs.setup_receiver(black_box(&enc), &sk, b"", None, None, None)
					.unwrap()
			})
		});
	}
	{
		let (sk, pk) = RhXWing::gen_keypair_with_rng(&mut RhChaCha20Rng(&mut prng));
		let (enc, _) = hpke::setup_sender_with_rng::<RhChaCha20, RhHkdfSha256, RhXWing>(
			&OpModeS::Base,
			&pk,
			b"",
			&mut RhChaCha20Rng(&mut prng),
		)
		.unwrap();
		g.bench_function("rust_hpke/decap_via_setup_receiver", |b| {
			b.iter(|| {
				hpke::setup_receiver::<RhChaCha20, RhHkdfSha256, RhXWing>(
					&OpModeR::Base,
					black_box(&sk),
					black_box(&enc),
					b"",
				)
				.unwrap()
			})
		});
	}
	g.finish();
}

fn bench_kem_mlkem768(c: &mut Criterion) {
	let mut g = c.benchmark_group("kem/mlkem768");
	let mut prng = rand_chacha::ChaCha20Rng::from_seed([0x42u8; 32]);

	g.bench_function("hpke_ng/generate", |b| {
		b.iter(|| ng::MlKem768::generate(&mut prng).unwrap())
	});
	{
		let mut rs = HpkeRs::<HpkeRustCrypto>::new(
			Mode::Base,
			rs_types::KemAlgorithm::MlKem768,
			rs_types::KdfAlgorithm::HkdfSha256,
			rs_types::AeadAlgorithm::ChaCha20Poly1305,
		);
		rs.seed(&SEED).unwrap();
		g.bench_function("hpke_rs/generate", |b| {
			b.iter(|| rs.generate_key_pair().unwrap())
		});
	}

	// hpke-ng ML-KEM derive_key_pair requires a 64-byte (d || z) seed
	// per draft-connolly-cfrg-hpke-mlkem-04 §3.2. hpke-rs SHAKE-256s the
	// IKM down to 64, so a 64-byte IKM works for both.
	let ikm = [0x99u8; 64];
	g.bench_function("hpke_ng/derive_key_pair", |b| {
		b.iter(|| ng::MlKem768::derive_key_pair(black_box(&ikm)).unwrap())
	});
	{
		let rs = HpkeRs::<HpkeRustCrypto>::new(
			Mode::Base,
			rs_types::KemAlgorithm::MlKem768,
			rs_types::KdfAlgorithm::HkdfSha256,
			rs_types::AeadAlgorithm::ChaCha20Poly1305,
		);
		g.bench_function("hpke_rs/derive_key_pair", |b| {
			b.iter(|| rs.derive_key_pair(black_box(&ikm)).unwrap())
		});
	}

	{
		let (_, pk_ng) = ng::MlKem768::generate(&mut prng).unwrap();
		g.bench_function("hpke_ng/encap", |b| {
			b.iter(|| ng::MlKem768::encap(&mut prng, black_box(&pk_ng)).unwrap())
		});
	}
	{
		let mut rs = HpkeRs::<HpkeRustCrypto>::new(
			Mode::Base,
			rs_types::KemAlgorithm::MlKem768,
			rs_types::KdfAlgorithm::HkdfSha256,
			rs_types::AeadAlgorithm::ChaCha20Poly1305,
		);
		let (_sk, pk) = rs.derive_key_pair(&[0x42u8; 64]).unwrap().into_keys();
		rs.seed(&SEED).unwrap();
		g.bench_function("hpke_rs/encap_via_setup_sender", |b| {
			b.iter(|| {
				rs.setup_sender(black_box(&pk), b"", None, None, None)
					.unwrap()
			})
		});
	}

	{
		let (sk_ng, pk_ng) = ng::MlKem768::generate(&mut prng).unwrap();
		let (_, enc_ng) = ng::MlKem768::encap(&mut prng, &pk_ng).unwrap();
		g.bench_function("hpke_ng/decap", |b| {
			b.iter(|| ng::MlKem768::decap(black_box(&enc_ng), &sk_ng).unwrap())
		});
	}
	{
		let mut rs = HpkeRs::<HpkeRustCrypto>::new(
			Mode::Base,
			rs_types::KemAlgorithm::MlKem768,
			rs_types::KdfAlgorithm::HkdfSha256,
			rs_types::AeadAlgorithm::ChaCha20Poly1305,
		);
		let (sk, pk) = rs.derive_key_pair(&[0x42u8; 64]).unwrap().into_keys();
		rs.seed(&SEED).unwrap();
		let (enc, _ctx) = rs.setup_sender(&pk, b"", None, None, None).unwrap();
		g.bench_function("hpke_rs/decap_via_setup_receiver", |b| {
			b.iter(|| {
				rs.setup_receiver(black_box(&enc), &sk, b"", None, None, None)
					.unwrap()
			})
		});
	}

	// rust-hpke omitted: rust-hpke does not implement standalone ML-KEM-768; only the
	// ML-KEM-768+X25519 (X-Wing, v0.14.0-pre.2) and ML-KEM-768+P256 (merged to main,
	// pending release) hybrid KEMs are supported.
	g.finish();
}

fn bench_kem_mlkem1024(c: &mut Criterion) {
	let mut g = c.benchmark_group("kem/mlkem1024");
	let mut prng = rand_chacha::ChaCha20Rng::from_seed([0x42u8; 32]);

	g.bench_function("hpke_ng/generate", |b| {
		b.iter(|| ng::MlKem1024::generate(&mut prng).unwrap())
	});
	{
		let mut rs = HpkeRs::<HpkeRustCrypto>::new(
			Mode::Base,
			rs_types::KemAlgorithm::MlKem1024,
			rs_types::KdfAlgorithm::HkdfSha256,
			rs_types::AeadAlgorithm::ChaCha20Poly1305,
		);
		rs.seed(&SEED).unwrap();
		g.bench_function("hpke_rs/generate", |b| {
			b.iter(|| rs.generate_key_pair().unwrap())
		});
	}

	let ikm = [0x99u8; 64];
	g.bench_function("hpke_ng/derive_key_pair", |b| {
		b.iter(|| ng::MlKem1024::derive_key_pair(black_box(&ikm)).unwrap())
	});
	{
		let rs = HpkeRs::<HpkeRustCrypto>::new(
			Mode::Base,
			rs_types::KemAlgorithm::MlKem1024,
			rs_types::KdfAlgorithm::HkdfSha256,
			rs_types::AeadAlgorithm::ChaCha20Poly1305,
		);
		g.bench_function("hpke_rs/derive_key_pair", |b| {
			b.iter(|| rs.derive_key_pair(black_box(&ikm)).unwrap())
		});
	}

	{
		let (_, pk_ng) = ng::MlKem1024::generate(&mut prng).unwrap();
		g.bench_function("hpke_ng/encap", |b| {
			b.iter(|| ng::MlKem1024::encap(&mut prng, black_box(&pk_ng)).unwrap())
		});
	}
	{
		let mut rs = HpkeRs::<HpkeRustCrypto>::new(
			Mode::Base,
			rs_types::KemAlgorithm::MlKem1024,
			rs_types::KdfAlgorithm::HkdfSha256,
			rs_types::AeadAlgorithm::ChaCha20Poly1305,
		);
		let (_sk, pk) = rs.derive_key_pair(&[0x42u8; 64]).unwrap().into_keys();
		rs.seed(&SEED).unwrap();
		g.bench_function("hpke_rs/encap_via_setup_sender", |b| {
			b.iter(|| {
				rs.setup_sender(black_box(&pk), b"", None, None, None)
					.unwrap()
			})
		});
	}

	{
		let (sk_ng, pk_ng) = ng::MlKem1024::generate(&mut prng).unwrap();
		let (_, enc_ng) = ng::MlKem1024::encap(&mut prng, &pk_ng).unwrap();
		g.bench_function("hpke_ng/decap", |b| {
			b.iter(|| ng::MlKem1024::decap(black_box(&enc_ng), &sk_ng).unwrap())
		});
	}
	{
		let mut rs = HpkeRs::<HpkeRustCrypto>::new(
			Mode::Base,
			rs_types::KemAlgorithm::MlKem1024,
			rs_types::KdfAlgorithm::HkdfSha256,
			rs_types::AeadAlgorithm::ChaCha20Poly1305,
		);
		let (sk, pk) = rs.derive_key_pair(&[0x42u8; 64]).unwrap().into_keys();
		rs.seed(&SEED).unwrap();
		let (enc, _ctx) = rs.setup_sender(&pk, b"", None, None, None).unwrap();
		g.bench_function("hpke_rs/decap_via_setup_receiver", |b| {
			b.iter(|| {
				rs.setup_receiver(black_box(&enc), &sk, b"", None, None, None)
					.unwrap()
			})
		});
	}

	// rust-hpke omitted: rust-hpke does not implement standalone ML-KEM-1024; only
	// ML-KEM-768-based hybrids are supported (X-Wing and MLKEM768-P256), and neither
	// includes an ML-KEM-1024 variant.
	g.finish();
}

// =============================================================================
//  Setup paths: setup_sender / setup_receiver across ciphersuites
// =============================================================================

fn bench_setup_x25519_chacha(c: &mut Criterion) {
	type Suite = ng::Hpke<ng::DhKemX25519HkdfSha256, ng::HkdfSha256, ng::ChaCha20Poly1305>;
	let mut prng = rand_chacha::ChaCha20Rng::from_seed([0x42u8; 32]);
	let (sk_ng, pk_ng) = ng::DhKemX25519HkdfSha256::generate(&mut prng).unwrap();
	let (enc_ng, _ctx_ng) = Suite::setup_sender_base(&mut prng, &pk_ng, b"info").unwrap();

	let mut rs = HpkeRs::<HpkeRustCrypto>::new(
		Mode::Base,
		rs_types::KemAlgorithm::DhKem25519,
		rs_types::KdfAlgorithm::HkdfSha256,
		rs_types::AeadAlgorithm::ChaCha20Poly1305,
	);
	let (sk_rs, pk_rs) = rs.derive_key_pair(&[0x42u8; 32]).unwrap().into_keys();
	rs.seed(&SEED).unwrap();
	let (enc_rs, _ctx_rs) = rs.setup_sender(&pk_rs, b"info", None, None, None).unwrap();

	let (_, pk) = RhX25519::gen_keypair_with_rng(&mut RhChaCha20Rng(&mut prng));

	let mut g = c.benchmark_group("x25519_chacha20/setup_sender_base");

	// `setup_sender` group
	g.bench_function("hpke_ng", |b| {
		b.iter(|| Suite::setup_sender_base(&mut prng, black_box(&pk_ng), b"info").unwrap())
	});
	g.bench_function("hpke_rs", |b| {
		b.iter(|| {
			rs.setup_sender(black_box(&pk_rs), b"info", None, None, None)
				.unwrap()
		})
	});
	g.bench_function("rust_hpke", |b| {
		b.iter(|| {
			hpke::setup_sender_with_rng::<RhChaCha20, RhHkdfSha256, RhX25519>(
				&OpModeS::Base,
				black_box(&pk),
				b"info",
				&mut RhChaCha20Rng(&mut prng),
			)
			.unwrap()
		})
	});
	g.finish();

	let mut g = c.benchmark_group("x25519_chacha20/setup_receiver_base");

	// `setup_receiver` group
	g.bench_function("hpke_ng", |b| {
		b.iter(|| Suite::setup_receiver_base(black_box(&enc_ng), &sk_ng, b"info").unwrap())
	});
	g.bench_function("hpke_rs", |b| {
		b.iter(|| {
			rs.setup_receiver(black_box(&enc_rs), &sk_rs, b"info", None, None, None)
				.unwrap()
		})
	});
	{
		let (sk, pk) = RhX25519::gen_keypair_with_rng(&mut RhChaCha20Rng(&mut prng));
		let (enc, _) = hpke::setup_sender_with_rng::<RhChaCha20, RhHkdfSha256, RhX25519>(
			&OpModeS::Base,
			&pk,
			b"info",
			&mut RhChaCha20Rng(&mut prng),
		)
		.unwrap();
		g.bench_function("rust_hpke", |b| {
			b.iter(|| {
				hpke::setup_receiver::<RhChaCha20, RhHkdfSha256, RhX25519>(
					&OpModeR::Base,
					black_box(&sk),
					black_box(&enc),
					b"info",
				)
				.unwrap()
			})
		});
	}
	g.finish();

	// PSK mode setup (Base + Psk = 2 most-common modes)
	let psk = [0xAAu8; 32];
	let psk_id = b"psk-id";
	// Both libraries bundle the PSK with its ID in a validated type. Build both
	// bundles here rather than inside the timed closures, so the measurement is
	// `setup_sender` in each case and not bundle construction.
	let psk_ng = ng::Psk::new(&psk, psk_id).unwrap();
	let rh_psk_mode = OpModeS::Psk(PskBundle::new(&psk, psk_id).unwrap());
	let mut rs_psk = HpkeRs::<HpkeRustCrypto>::new(
		Mode::Psk,
		rs_types::KemAlgorithm::DhKem25519,
		rs_types::KdfAlgorithm::HkdfSha256,
		rs_types::AeadAlgorithm::ChaCha20Poly1305,
	);
	let (_sk_psk_rs, pk_psk_rs) = rs_psk.derive_key_pair(&[0x42u8; 32]).unwrap().into_keys();
	let (_, pk_psk_rh) = RhX25519::gen_keypair_with_rng(&mut RhChaCha20Rng(&mut prng));
	let mut g = c.benchmark_group("x25519_chacha20/setup_sender_psk");
	rs_psk.seed(&SEED).unwrap();
	g.bench_function("hpke_ng", |b| {
		b.iter(|| Suite::setup_sender_psk(&mut prng, black_box(&pk_ng), b"info", psk_ng).unwrap())
	});
	g.bench_function("hpke_rs", |b| {
		b.iter(|| {
			rs_psk
				.setup_sender(
					black_box(&pk_psk_rs),
					b"info",
					Some(&psk),
					Some(psk_id),
					None,
				)
				.unwrap()
		})
	});
	g.bench_function("rust_hpke", |b| {
		b.iter(|| {
			hpke::setup_sender_with_rng::<RhChaCha20, RhHkdfSha256, RhX25519>(
				&rh_psk_mode,
				black_box(&pk_psk_rh),
				b"info",
				&mut RhChaCha20Rng(&mut prng),
			)
			.unwrap()
		})
	});
	g.finish();
}

fn bench_setup_x25519_aes128(c: &mut Criterion) {
	type Suite = ng::Hpke<ng::DhKemX25519HkdfSha256, ng::HkdfSha256, ng::Aes128Gcm>;
	let mut prng = rand_chacha::ChaCha20Rng::from_seed([0x42u8; 32]);
	let (_, pk_ng) = ng::DhKemX25519HkdfSha256::generate(&mut prng).unwrap();

	let mut rs = HpkeRs::<HpkeRustCrypto>::new(
		Mode::Base,
		rs_types::KemAlgorithm::DhKem25519,
		rs_types::KdfAlgorithm::HkdfSha256,
		rs_types::AeadAlgorithm::Aes128Gcm,
	);
	let (_, pk_rs) = rs.derive_key_pair(&[0x42u8; 32]).unwrap().into_keys();

	let (_, pk) = RhX25519::gen_keypair_with_rng(&mut RhChaCha20Rng(&mut prng));

	let mut g = c.benchmark_group("x25519_aes128/setup_sender_base");
	g.bench_function("hpke_ng", |b| {
		b.iter(|| Suite::setup_sender_base(&mut prng, black_box(&pk_ng), b"info").unwrap())
	});
	rs.seed(&SEED).unwrap();
	g.bench_function("hpke_rs", |b| {
		b.iter(|| {
			rs.setup_sender(black_box(&pk_rs), b"info", None, None, None)
				.unwrap()
		})
	});
	g.bench_function("rust_hpke", |b| {
		b.iter(|| {
			hpke::setup_sender_with_rng::<RhAes128, RhHkdfSha256, RhX25519>(
				&OpModeS::Base,
				black_box(&pk),
				b"info",
				&mut RhChaCha20Rng(&mut prng),
			)
			.unwrap()
		})
	});
	g.finish();
}

fn bench_setup_x25519_aes256(c: &mut Criterion) {
	type Suite = ng::Hpke<ng::DhKemX25519HkdfSha256, ng::HkdfSha256, ng::Aes256Gcm>;
	let mut prng = rand_chacha::ChaCha20Rng::from_seed([0x42u8; 32]);
	let (_, pk_ng) = ng::DhKemX25519HkdfSha256::generate(&mut prng).unwrap();

	let mut rs = HpkeRs::<HpkeRustCrypto>::new(
		Mode::Base,
		rs_types::KemAlgorithm::DhKem25519,
		rs_types::KdfAlgorithm::HkdfSha256,
		rs_types::AeadAlgorithm::Aes256Gcm,
	);
	let (_, pk_rs) = rs.derive_key_pair(&[0x42u8; 32]).unwrap().into_keys();

	let (_, pk) = RhX25519::gen_keypair_with_rng(&mut RhChaCha20Rng(&mut prng));

	let mut g = c.benchmark_group("x25519_aes256/setup_sender_base");
	g.bench_function("hpke_ng", |b| {
		b.iter(|| Suite::setup_sender_base(&mut prng, black_box(&pk_ng), b"info").unwrap())
	});
	rs.seed(&SEED).unwrap();
	g.bench_function("hpke_rs", |b| {
		b.iter(|| {
			rs.setup_sender(black_box(&pk_rs), b"info", None, None, None)
				.unwrap()
		})
	});
	g.bench_function("rust_hpke", |b| {
		b.iter(|| {
			hpke::setup_sender_with_rng::<RhAes256, RhHkdfSha256, RhX25519>(
				&OpModeS::Base,
				black_box(&pk),
				b"info",
				&mut RhChaCha20Rng(&mut prng),
			)
			.unwrap()
		})
	});
	g.finish();
}

fn bench_setup_p256_aes128(c: &mut Criterion) {
	type Suite = ng::Hpke<ng::DhKemP256HkdfSha256, ng::HkdfSha256, ng::Aes128Gcm>;
	let mut prng = rand_chacha::ChaCha20Rng::from_seed([0x42u8; 32]);
	let (_, pk_ng) = ng::DhKemP256HkdfSha256::generate(&mut prng).unwrap();

	let mut rs = HpkeRs::<HpkeRustCrypto>::new(
		Mode::Base,
		rs_types::KemAlgorithm::DhKemP256,
		rs_types::KdfAlgorithm::HkdfSha256,
		rs_types::AeadAlgorithm::Aes128Gcm,
	);
	let (_, pk_rs) = rs.derive_key_pair(&[0x42u8; 32]).unwrap().into_keys();

	let (_, pk) = RhP256::gen_keypair_with_rng(&mut RhChaCha20Rng(&mut prng));

	let mut g = c.benchmark_group("p256_aes128/setup_sender_base");
	g.bench_function("hpke_ng", |b| {
		b.iter(|| Suite::setup_sender_base(&mut prng, black_box(&pk_ng), b"info").unwrap())
	});
	rs.seed(&SEED).unwrap();
	g.bench_function("hpke_rs", |b| {
		b.iter(|| {
			rs.setup_sender(black_box(&pk_rs), b"info", None, None, None)
				.unwrap()
		})
	});
	g.bench_function("rust_hpke", |b| {
		b.iter(|| {
			hpke::setup_sender_with_rng::<RhAes128, RhHkdfSha256, RhP256>(
				&OpModeS::Base,
				black_box(&pk),
				b"info",
				&mut RhChaCha20Rng(&mut prng),
			)
			.unwrap()
		})
	});
	g.finish();
}

fn bench_setup_p256_aes256(c: &mut Criterion) {
	type Suite = ng::Hpke<ng::DhKemP256HkdfSha256, ng::HkdfSha256, ng::Aes256Gcm>;
	let mut prng = rand_chacha::ChaCha20Rng::from_seed([0x42u8; 32]);
	let (_, pk_ng) = ng::DhKemP256HkdfSha256::generate(&mut prng).unwrap();

	let mut rs = HpkeRs::<HpkeRustCrypto>::new(
		Mode::Base,
		rs_types::KemAlgorithm::DhKemP256,
		rs_types::KdfAlgorithm::HkdfSha256,
		rs_types::AeadAlgorithm::Aes256Gcm,
	);
	let (_, pk_rs) = rs.derive_key_pair(&[0x42u8; 32]).unwrap().into_keys();

	let (_, pk) = RhP256::gen_keypair_with_rng(&mut RhChaCha20Rng(&mut prng));

	let mut g = c.benchmark_group("p256_aes256/setup_sender_base");
	g.bench_function("hpke_ng", |b| {
		b.iter(|| Suite::setup_sender_base(&mut prng, black_box(&pk_ng), b"info").unwrap())
	});
	rs.seed(&SEED).unwrap();
	g.bench_function("hpke_rs", |b| {
		b.iter(|| {
			rs.setup_sender(black_box(&pk_rs), b"info", None, None, None)
				.unwrap()
		})
	});
	g.bench_function("rust_hpke", |b| {
		b.iter(|| {
			hpke::setup_sender_with_rng::<RhAes256, RhHkdfSha256, RhP256>(
				&OpModeS::Base,
				black_box(&pk),
				b"info",
				&mut RhChaCha20Rng(&mut prng),
			)
			.unwrap()
		})
	});
	g.finish();
}

fn bench_setup_k256_chacha(c: &mut Criterion) {
	type Suite = ng::Hpke<ng::DhKemK256HkdfSha256, ng::HkdfSha256, ng::ChaCha20Poly1305>;
	let mut prng = rand_chacha::ChaCha20Rng::from_seed([0x42u8; 32]);
	let (_, pk_ng) = ng::DhKemK256HkdfSha256::generate(&mut prng).unwrap();

	let mut rs = HpkeRs::<HpkeRustCrypto>::new(
		Mode::Base,
		rs_types::KemAlgorithm::DhKemK256,
		rs_types::KdfAlgorithm::HkdfSha256,
		rs_types::AeadAlgorithm::ChaCha20Poly1305,
	);
	let (_, pk_rs) = rs.derive_key_pair(&[0x42u8; 32]).unwrap().into_keys();

	let mut g = c.benchmark_group("k256_chacha20/setup_sender_base");
	g.bench_function("hpke_ng", |b| {
		b.iter(|| Suite::setup_sender_base(&mut prng, black_box(&pk_ng), b"info").unwrap())
	});
	rs.seed(&SEED).unwrap();
	g.bench_function("hpke_rs", |b| {
		b.iter(|| {
			rs.setup_sender(black_box(&pk_rs), b"info", None, None, None)
				.unwrap()
		})
	});
	g.finish();
}

fn bench_setup_xwing_chacha(c: &mut Criterion) {
	type Suite = ng::Hpke<ng::XWingDraft06, ng::HkdfSha256, ng::ChaCha20Poly1305>;
	let mut prng = rand_chacha::ChaCha20Rng::from_seed([0x42u8; 32]);
	let (sk_ng, pk_ng) = ng::XWingDraft06::generate(&mut prng).unwrap();
	let (enc_ng, _ctx_ng) = Suite::setup_sender_base(&mut prng, &pk_ng, b"info").unwrap();

	let mut rs = HpkeRs::<HpkeRustCrypto>::new(
		Mode::Base,
		rs_types::KemAlgorithm::XWingDraft06,
		rs_types::KdfAlgorithm::HkdfSha256,
		rs_types::AeadAlgorithm::ChaCha20Poly1305,
	);
	let (sk_rs, pk_rs) = rs.derive_key_pair(&[0x42u8; 32]).unwrap().into_keys();
	rs.seed(&SEED).unwrap();
	let (enc_rs, _ctx_rs) = rs.setup_sender(&pk_rs, b"info", None, None, None).unwrap();

	let (sk_rh, pk_rh) = RhXWing::gen_keypair_with_rng(&mut RhChaCha20Rng(&mut prng));
	let (enc_rh, _) = hpke::setup_sender_with_rng::<RhChaCha20, RhHkdfSha256, RhXWing>(
		&OpModeS::Base,
		&pk_rh,
		b"info",
		&mut RhChaCha20Rng(&mut prng),
	)
	.unwrap();

	let mut g = c.benchmark_group("xwing_chacha20/setup_sender_base");
	g.bench_function("hpke_ng", |b| {
		b.iter(|| Suite::setup_sender_base(&mut prng, black_box(&pk_ng), b"info").unwrap())
	});
	g.bench_function("hpke_rs", |b| {
		b.iter(|| {
			rs.setup_sender(black_box(&pk_rs), b"info", None, None, None)
				.unwrap()
		})
	});
	// DRAFT NOTE: all three libraries implement draft-connolly-cfrg-xwing-kem-06 via the
	// same x-wing crate and share KEM_ID 0x647a; shared secrets are fully interoperable.
	g.bench_function("rust_hpke", |b| {
		b.iter(|| {
			hpke::setup_sender_with_rng::<RhChaCha20, RhHkdfSha256, RhXWing>(
				&OpModeS::Base,
				black_box(&pk_rh),
				b"info",
				&mut RhChaCha20Rng(&mut prng),
			)
			.unwrap()
		})
	});
	g.finish();

	let mut g = c.benchmark_group("xwing_chacha20/setup_receiver_base");
	g.bench_function("hpke_ng", |b| {
		b.iter(|| Suite::setup_receiver_base(black_box(&enc_ng), &sk_ng, b"info").unwrap())
	});
	g.bench_function("hpke_rs", |b| {
		b.iter(|| {
			rs.setup_receiver(black_box(&enc_rs), &sk_rs, b"info", None, None, None)
				.unwrap()
		})
	});
	g.bench_function("rust_hpke", |b| {
		b.iter(|| {
			hpke::setup_receiver::<RhChaCha20, RhHkdfSha256, RhXWing>(
				&OpModeR::Base,
				black_box(&sk_rh),
				black_box(&enc_rh),
				b"info",
			)
			.unwrap()
		})
	});
	g.finish();
}

fn bench_setup_mlkem768_chacha(c: &mut Criterion) {
	type Suite = ng::Hpke<ng::MlKem768, ng::HkdfSha256, ng::ChaCha20Poly1305>;
	let mut prng = rand_chacha::ChaCha20Rng::from_seed([0x42u8; 32]);
	let (sk_ng, pk_ng) = ng::MlKem768::generate(&mut prng).unwrap();
	let (enc_ng, _ctx_ng) = Suite::setup_sender_base(&mut prng, &pk_ng, b"info").unwrap();

	let mut rs = HpkeRs::<HpkeRustCrypto>::new(
		Mode::Base,
		rs_types::KemAlgorithm::MlKem768,
		rs_types::KdfAlgorithm::HkdfSha256,
		rs_types::AeadAlgorithm::ChaCha20Poly1305,
	);
	let (sk_rs, pk_rs) = rs.derive_key_pair(&[0x42u8; 64]).unwrap().into_keys();
	rs.seed(&SEED).unwrap();
	let (enc_rs, _ctx_rs) = rs.setup_sender(&pk_rs, b"info", None, None, None).unwrap();

	let mut g = c.benchmark_group("mlkem768_chacha20/setup_sender_base");
	g.bench_function("hpke_ng", |b| {
		b.iter(|| Suite::setup_sender_base(&mut prng, black_box(&pk_ng), b"info").unwrap())
	});
	g.bench_function("hpke_rs", |b| {
		b.iter(|| {
			rs.setup_sender(black_box(&pk_rs), b"info", None, None, None)
				.unwrap()
		})
	});
	g.finish();

	let mut g = c.benchmark_group("mlkem768_chacha20/setup_receiver_base");
	g.bench_function("hpke_ng", |b| {
		b.iter(|| Suite::setup_receiver_base(black_box(&enc_ng), &sk_ng, b"info").unwrap())
	});
	g.bench_function("hpke_rs", |b| {
		b.iter(|| {
			rs.setup_receiver(black_box(&enc_rs), &sk_rs, b"info", None, None, None)
				.unwrap()
		})
	});
	// rust-hpke omitted: standalone ML-KEM-768 is not implemented; rust-hpke only
	// supports the ML-KEM-768+X25519 (X-Wing, v0.14.0-pre.2) and ML-KEM-768+P256
	// (merged to main, pending release) hybrids.
	g.finish();
}

fn bench_setup_mlkem1024_chacha(c: &mut Criterion) {
	type Suite = ng::Hpke<ng::MlKem1024, ng::HkdfSha256, ng::ChaCha20Poly1305>;
	let mut prng = rand_chacha::ChaCha20Rng::from_seed([0x42u8; 32]);
	let (sk_ng, pk_ng) = ng::MlKem1024::generate(&mut prng).unwrap();
	let (enc_ng, _ctx_ng) = Suite::setup_sender_base(&mut prng, &pk_ng, b"info").unwrap();

	let mut rs = HpkeRs::<HpkeRustCrypto>::new(
		Mode::Base,
		rs_types::KemAlgorithm::MlKem1024,
		rs_types::KdfAlgorithm::HkdfSha256,
		rs_types::AeadAlgorithm::ChaCha20Poly1305,
	);
	let (sk_rs, pk_rs) = rs.derive_key_pair(&[0x42u8; 64]).unwrap().into_keys();
	rs.seed(&SEED).unwrap();
	let (enc_rs, _ctx_rs) = rs.setup_sender(&pk_rs, b"info", None, None, None).unwrap();

	let mut g = c.benchmark_group("mlkem1024_chacha20/setup_sender_base");
	g.bench_function("hpke_ng", |b| {
		b.iter(|| Suite::setup_sender_base(&mut prng, black_box(&pk_ng), b"info").unwrap())
	});
	g.bench_function("hpke_rs", |b| {
		b.iter(|| {
			rs.setup_sender(black_box(&pk_rs), b"info", None, None, None)
				.unwrap()
		})
	});
	g.finish();

	let mut g = c.benchmark_group("mlkem1024_chacha20/setup_receiver_base");
	g.bench_function("hpke_ng", |b| {
		b.iter(|| Suite::setup_receiver_base(black_box(&enc_ng), &sk_ng, b"info").unwrap())
	});
	g.bench_function("hpke_rs", |b| {
		b.iter(|| {
			rs.setup_receiver(black_box(&enc_rs), &sk_rs, b"info", None, None, None)
				.unwrap()
		})
	});
	// rust-hpke omitted: standalone ML-KEM-1024 is not implemented; rust-hpke only supports
	// ML-KEM-768-based hybrids (X-Wing and MLKEM768-P256), with no ML-KEM-1024 variant.
	g.finish();
}

// =============================================================================
//  Single-shot seal: throughput across many payload sizes
//  (the marquee chart — log-scale payload axis)
// =============================================================================

fn bench_seal_x25519_chacha_payload_sweep(c: &mut Criterion) {
	type Suite = ng::Hpke<ng::DhKemX25519HkdfSha256, ng::HkdfSha256, ng::ChaCha20Poly1305>;
	let mut prng = rand_chacha::ChaCha20Rng::from_seed([0x42u8; 32]);
	let (_, pk_ng) = ng::DhKemX25519HkdfSha256::generate(&mut prng).unwrap();

	let mut rs = HpkeRs::<HpkeRustCrypto>::new(
		Mode::Base,
		rs_types::KemAlgorithm::DhKem25519,
		rs_types::KdfAlgorithm::HkdfSha256,
		rs_types::AeadAlgorithm::ChaCha20Poly1305,
	);
	let (_, pk_rs) = rs.derive_key_pair(&[0x42u8; 32]).unwrap().into_keys();

	let (_, pk) = RhX25519::gen_keypair_with_rng(&mut RhChaCha20Rng(&mut prng));

	let mut g = c.benchmark_group("x25519_chacha20_seal_sweep");
	// 8 payload sizes × 3 libraries = 24 timed benchmarks in this group.
	// Trimmed from the quick() defaults (60 / 3s) so the full sweep finishes
	// in ~2 min rather than ~6; 40 samples over 2s still gives tight CIs for
	// ops at these magnitudes (µs–ms range).
	g.measurement_time(Duration::from_secs(2));
	g.sample_size(40);

	for &size in PAYLOAD_SIZES {
		let pt = vec![0xAAu8; size];
		g.throughput(Throughput::Bytes(size as u64));
		g.bench_with_input(BenchmarkId::new("hpke_ng", size), &size, |b, _| {
			b.iter(|| Suite::seal_base(&mut prng, &pk_ng, b"info", b"aad", black_box(&pt)).unwrap())
		});
		rs.seed(&SEED).unwrap();
		g.bench_with_input(BenchmarkId::new("hpke_rs", size), &size, |b, _| {
			b.iter(|| {
				rs.seal(&pk_rs, b"info", b"aad", black_box(&pt), None, None, None)
					.unwrap()
			})
		});
		g.bench_with_input(BenchmarkId::new("rust_hpke", size), &size, |b, _| {
			b.iter(|| {
				let (_enc, mut ctx) = hpke::setup_sender_with_rng::<
					RhChaCha20,
					RhHkdfSha256,
					RhX25519,
				>(
					&OpModeS::Base, &pk, b"info", &mut RhChaCha20Rng(&mut prng)
				)
				.unwrap();
				ctx.seal(black_box(&pt), b"aad").unwrap()
			})
		});
	}
	g.finish();
}

// Same sweep with AES-128-GCM (different AEAD primitive)
fn bench_seal_x25519_aes128_payload_sweep(c: &mut Criterion) {
	type Suite = ng::Hpke<ng::DhKemX25519HkdfSha256, ng::HkdfSha256, ng::Aes128Gcm>;
	let mut prng = rand_chacha::ChaCha20Rng::from_seed([0x42u8; 32]);
	let (_, pk_ng) = ng::DhKemX25519HkdfSha256::generate(&mut prng).unwrap();

	let mut rs = HpkeRs::<HpkeRustCrypto>::new(
		Mode::Base,
		rs_types::KemAlgorithm::DhKem25519,
		rs_types::KdfAlgorithm::HkdfSha256,
		rs_types::AeadAlgorithm::Aes128Gcm,
	);
	let (_, pk_rs) = rs.derive_key_pair(&[0x42u8; 32]).unwrap().into_keys();

	let (_, pk) = RhX25519::gen_keypair_with_rng(&mut RhChaCha20Rng(&mut prng));

	let mut g = c.benchmark_group("x25519_aes128_seal_sweep");
	// Reduced 6-size sweep (drops 16 B and 256 KiB extremes), 3 libraries.
	// Same 40 / 2s budget as the chacha seal sweep, i.e. kept identical so the
	// two AEAD variants are directly comparable.
	g.measurement_time(Duration::from_secs(2));
	g.sample_size(40);
	for &size in &[64usize, 256, 1024, 4096, 16384, 65536] {
		let pt = vec![0xAAu8; size];
		g.throughput(Throughput::Bytes(size as u64));
		g.bench_with_input(BenchmarkId::new("hpke_ng", size), &size, |b, _| {
			b.iter(|| Suite::seal_base(&mut prng, &pk_ng, b"info", b"aad", black_box(&pt)).unwrap())
		});
		rs.seed(&SEED).unwrap();
		g.bench_with_input(BenchmarkId::new("hpke_rs", size), &size, |b, _| {
			b.iter(|| {
				rs.seal(&pk_rs, b"info", b"aad", black_box(&pt), None, None, None)
					.unwrap()
			})
		});
		g.bench_with_input(BenchmarkId::new("rust_hpke", size), &size, |b, _| {
			b.iter(|| {
				let (_enc, mut ctx) =
					hpke::setup_sender_with_rng::<RhAes128, RhHkdfSha256, RhX25519>(
						&OpModeS::Base,
						&pk,
						b"info",
						&mut RhChaCha20Rng(&mut prng),
					)
					.unwrap();
				ctx.seal(black_box(&pt), b"aad").unwrap()
			})
		});
	}
	g.finish();
}

// =============================================================================
//  Single-shot open path
// =============================================================================

fn bench_open_x25519_chacha_payload_sweep(c: &mut Criterion) {
	type Suite = ng::Hpke<ng::DhKemX25519HkdfSha256, ng::HkdfSha256, ng::ChaCha20Poly1305>;

	let mut prng = rand_chacha::ChaCha20Rng::from_seed([0x42u8; 32]);
	let (sk_ng, pk_ng) = ng::DhKemX25519HkdfSha256::generate(&mut prng).unwrap();

	let mut rs = HpkeRs::<HpkeRustCrypto>::new(
		Mode::Base,
		rs_types::KemAlgorithm::DhKem25519,
		rs_types::KdfAlgorithm::HkdfSha256,
		rs_types::AeadAlgorithm::ChaCha20Poly1305,
	);
	let (sk_rs, pk_rs) = rs.derive_key_pair(&[0x42u8; 32]).unwrap().into_keys();

	let (sk, pk) = RhX25519::gen_keypair_with_rng(&mut RhChaCha20Rng(&mut prng));

	let mut g = c.benchmark_group("x25519_chacha20_open_sweep");
	// Mirrors the chacha seal sweep budget (40 / 2s) so seal and open numbers
	// at each payload size are read as a matched pair.
	g.measurement_time(Duration::from_secs(2));
	g.sample_size(40);
	for &size in &[64usize, 256, 1024, 4096, 16384, 65536] {
		let pt = vec![0xAAu8; size];
		// Pre-seal one message with each library to use as the open input.
		let (enc_ng, ct_ng) = Suite::seal_base(&mut prng, &pk_ng, b"info", b"aad", &pt).unwrap();

		rs.seed(&SEED).unwrap();
		let (enc_rs, ct_rs) = rs
			.seal(&pk_rs, b"info", b"aad", &pt, None, None, None)
			.unwrap();

		let (enc, mut ctx_s) = hpke::setup_sender_with_rng::<RhChaCha20, RhHkdfSha256, RhX25519>(
			&OpModeS::Base,
			&pk,
			b"info",
			&mut RhChaCha20Rng(&mut prng),
		)
		.unwrap();
		let ct = ctx_s.seal(&pt, b"aad").unwrap();

		g.throughput(Throughput::Bytes(size as u64));
		g.bench_with_input(BenchmarkId::new("hpke_ng", size), &size, |b, _| {
			b.iter(|| {
				Suite::open_base(
					black_box(&enc_ng),
					&sk_ng,
					b"info",
					b"aad",
					black_box(&ct_ng),
				)
				.unwrap()
			})
		});
		g.bench_with_input(BenchmarkId::new("hpke_rs", size), &size, |b, _| {
			b.iter(|| {
				let mut ctx = rs
					.setup_receiver(black_box(&enc_rs), &sk_rs, b"info", None, None, None)
					.unwrap();
				ctx.open(b"aad", black_box(&ct_rs)).unwrap()
			})
		});
		g.bench_with_input(BenchmarkId::new("rust_hpke", size), &size, |b, _| {
			b.iter(|| {
				let mut ctx_r = hpke::setup_receiver::<RhChaCha20, RhHkdfSha256, RhX25519>(
					&OpModeR::Base,
					black_box(&sk),
					black_box(&enc),
					b"info",
				)
				.unwrap();
				ctx_r.open(black_box(&ct), b"aad").unwrap()
			})
		});
	}
	g.finish();
}

fn bench_open_x25519_aes128_payload_sweep(c: &mut Criterion) {
	type Suite = ng::Hpke<ng::DhKemX25519HkdfSha256, ng::HkdfSha256, ng::Aes128Gcm>;

	let mut prng = rand_chacha::ChaCha20Rng::from_seed([0x42u8; 32]);
	let (sk_ng, pk_ng) = ng::DhKemX25519HkdfSha256::generate(&mut prng).unwrap();

	let mut rs = HpkeRs::<HpkeRustCrypto>::new(
		Mode::Base,
		rs_types::KemAlgorithm::DhKem25519,
		rs_types::KdfAlgorithm::HkdfSha256,
		rs_types::AeadAlgorithm::Aes128Gcm,
	);
	let (sk_rs, pk_rs) = rs.derive_key_pair(&[0x42u8; 32]).unwrap().into_keys();

	let (sk, pk) = RhX25519::gen_keypair_with_rng(&mut RhChaCha20Rng(&mut prng));

	let mut g = c.benchmark_group("x25519_aes128_open_sweep");
	// Matches the aes128 seal sweep and the chacha open sweep (40 / 2s):
	// all four payload sweeps share one budget so they're cross-comparable.
	g.measurement_time(Duration::from_secs(2));
	g.sample_size(40);
	for &size in &[64usize, 256, 1024, 4096, 16384, 65536] {
		let pt = vec![0xAAu8; size];

		let (enc_ng, ct_ng) = Suite::seal_base(&mut prng, &pk_ng, b"info", b"aad", &pt).unwrap();

		rs.seed(&SEED).unwrap(); // needed outside of iter(), since seal() draws randomness.
		let (enc_rs, ct_rs) = rs
			.seal(&pk_rs, b"info", b"aad", &pt, None, None, None)
			.unwrap();

		let (enc, mut ctx_s) = hpke::setup_sender_with_rng::<RhAes128, RhHkdfSha256, RhX25519>(
			&OpModeS::Base,
			&pk,
			b"info",
			&mut RhChaCha20Rng(&mut prng),
		)
		.unwrap();
		let ct = ctx_s.seal(&pt, b"aad").unwrap();

		g.throughput(Throughput::Bytes(size as u64));
		g.bench_with_input(BenchmarkId::new("hpke_ng", size), &size, |b, _| {
			b.iter(|| {
				Suite::open_base(
					black_box(&enc_ng),
					&sk_ng,
					b"info",
					b"aad",
					black_box(&ct_ng),
				)
				.unwrap()
			})
		});
		g.bench_with_input(BenchmarkId::new("hpke_rs", size), &size, |b, _| {
			b.iter(|| {
				// open path consumes no PRNG bytes — no seed() here.
				let mut ctx = rs
					.setup_receiver(black_box(&enc_rs), &sk_rs, b"info", None, None, None)
					.unwrap();
				ctx.open(b"aad", black_box(&ct_rs)).unwrap()
			})
		});
		g.bench_with_input(BenchmarkId::new("rust_hpke", size), &size, |b, _| {
			b.iter(|| {
				let mut ctx_r = hpke::setup_receiver::<RhAes128, RhHkdfSha256, RhX25519>(
					&OpModeR::Base,
					black_box(&sk),
					black_box(&enc),
					b"info",
				)
				.unwrap();
				ctx_r.open(black_box(&ct), b"aad").unwrap()
			})
		});
	}
	g.finish();
}

// =============================================================================
//  Context seal (post-setup, pure framing + AEAD path)
// =============================================================================

fn bench_context_seal_x25519_chacha(c: &mut Criterion) {
	type Suite = ng::Hpke<ng::DhKemX25519HkdfSha256, ng::HkdfSha256, ng::ChaCha20Poly1305>;
	let mut prng = rand_chacha::ChaCha20Rng::from_seed([0x42u8; 32]);
	let (_, pk_ng) = ng::DhKemX25519HkdfSha256::generate(&mut prng).unwrap();
	let (_, mut ctx_ng) = Suite::setup_sender_base(&mut prng, &pk_ng, b"info").unwrap();

	let mut rs = HpkeRs::<HpkeRustCrypto>::new(
		Mode::Base,
		rs_types::KemAlgorithm::DhKem25519,
		rs_types::KdfAlgorithm::HkdfSha256,
		rs_types::AeadAlgorithm::ChaCha20Poly1305,
	);
	rs.seed(&SEED).unwrap();
	let (_, pk_rs) = rs.derive_key_pair(&[0x42u8; 32]).unwrap().into_keys();
	let (_enc, mut ctx_rs) = rs.setup_sender(&pk_rs, b"info", None, None, None).unwrap();

	let (_, pk) = RhX25519::gen_keypair_with_rng(&mut RhChaCha20Rng(&mut prng));
	let (_, mut ctx_rh) = hpke::setup_sender_with_rng::<RhChaCha20, RhHkdfSha256, RhX25519>(
		&OpModeS::Base,
		&pk,
		b"info",
		&mut RhChaCha20Rng(&mut prng),
	)
	.unwrap();

	let mut g = c.benchmark_group("x25519_chacha20_context_seal");
	// Post-setup hot path: only 4 sizes × 3 libraries, and each iteration is
	// cheap (pure framing + AEAD, no KEM). Slightly higher sample count (50)
	// than the sweeps since the per-iteration variance is what we care about
	// here; 2s window is ample for this few benchmarks.
	//
	// All three sender contexts (ctx_ng, ctx_rs, ctx_rh) are shared across
	// the four size sub-benchmarks, so their sequence counters keep advancing
	// across sizes. The nonce counter has no effect on timing and cannot wrap
	// for any realistic iteration count, so this is safe.
	g.measurement_time(Duration::from_secs(2));
	g.sample_size(50);
	for &size in &[64usize, 1024, 16384, 65536] {
		let pt = vec![0xAAu8; size];
		g.throughput(Throughput::Bytes(size as u64));
		g.bench_with_input(BenchmarkId::new("hpke_ng", size), &size, |b, _| {
			b.iter(|| ctx_ng.seal(b"aad", black_box(&pt)).unwrap())
		});
		g.bench_with_input(BenchmarkId::new("hpke_rs", size), &size, |b, _| {
			b.iter(|| ctx_rs.seal(b"aad", black_box(&pt)).unwrap())
		});
		g.bench_with_input(BenchmarkId::new("rust_hpke", size), &size, |b, _| {
			b.iter(|| ctx_rh.seal(black_box(&pt), b"aad").unwrap())
		});
	}
	g.finish();
}

// =============================================================================
//  Context open (post-setup, framing + AEAD decrypt)
// =============================================================================

fn bench_context_open_x25519_chacha(c: &mut Criterion) {
	type Suite = ng::Hpke<ng::DhKemX25519HkdfSha256, ng::HkdfSha256, ng::ChaCha20Poly1305>;
	let mut prng = rand_chacha::ChaCha20Rng::from_seed([0x42u8; 32]);
	let (sk_ng, pk_ng) = ng::DhKemX25519HkdfSha256::generate(&mut prng).unwrap();

	let mut rs = HpkeRs::<HpkeRustCrypto>::new(
		Mode::Base,
		rs_types::KemAlgorithm::DhKem25519,
		rs_types::KdfAlgorithm::HkdfSha256,
		rs_types::AeadAlgorithm::ChaCha20Poly1305,
	);
	let (sk_rs, pk_rs) = rs.derive_key_pair(&[0x42u8; 32]).unwrap().into_keys();

	let (sk, pk) = RhX25519::gen_keypair_with_rng(&mut RhChaCha20Rng(&mut prng));

	let mut g = c.benchmark_group("x25519_chacha20_context_open");
	// Same 50 / 2s budget as context_seal for symmetry. Both sender and
	// receiver contexts are established outside the timed loop (below) and
	// their sequence counters advance in lockstep on every b.iter() call
	// (so no KEM setup and no context rebuild per iteration). The timed path is
	// seal+open combined (see per-iteration comment below). To derive pure
	// open latency, subtract the corresponding context_seal measurement.
	g.measurement_time(Duration::from_secs(2));
	g.sample_size(50);

	for &size in &[64usize, 1024, 16384, 65536] {
		let pt = vec![0xAAu8; size];

		// Setup synchronized contexts for hpke_ng
		let (enc_ng, mut ctx_s_ng) = Suite::setup_sender_base(&mut prng, &pk_ng, b"info").unwrap();
		let mut ctx_r_ng = Suite::setup_receiver_base(&enc_ng, &sk_ng, b"info").unwrap();

		// Setup synchronized contexts for hpke_rs
		// NOTE: seed() is called once per size so that setup_sender (which
		// consumes randomness) starts from a fresh cursor. Context::seal
		// and Context::open are deterministic (nonce = f(seq)), so no PRNG
		// bytes are drawn inside b.iter().
		rs.seed(&SEED).unwrap();
		let (enc_rs, mut ctx_s_rs) = rs.setup_sender(&pk_rs, b"info", None, None, None).unwrap();
		let mut ctx_r_rs = rs
			.setup_receiver(&enc_rs, &sk_rs, b"info", None, None, None)
			.unwrap();

		// Setup synchronized contexts for rust_hpke
		let (enc_rh, mut ctx_s_rh) = hpke::setup_sender_with_rng::<
			RhChaCha20,
			RhHkdfSha256,
			RhX25519,
		>(
			&OpModeS::Base, &pk, b"info", &mut RhChaCha20Rng(&mut prng)
		)
		.unwrap();
		let mut ctx_r_rh = hpke::setup_receiver::<RhChaCha20, RhHkdfSha256, RhX25519>(
			&OpModeR::Base,
			&sk,
			&enc_rh,
			b"info",
		)
		.unwrap();

		g.throughput(Throughput::Bytes(size as u64));
		// IMPORTANT NOTE: ctx_s_* and ctx_r_* are established once above and their
		// sequence counters advance together every iteration. No KEM
		// setup is included. The measured cost is seal + open at matching
		// sequence numbers, i.e. the cheapest possible round-trip, isolating
		// pure AEAD framing. Pure open latency = this time - context_seal time.
		g.bench_with_input(BenchmarkId::new("hpke_ng", size), &size, |b, _| {
			b.iter(|| {
				let ct = ctx_s_ng.seal(b"aad", black_box(&pt)).unwrap();
				ctx_r_ng.open(b"aad", &ct).unwrap()
			})
		});
		g.bench_with_input(BenchmarkId::new("hpke_rs", size), &size, |b, _| {
			b.iter(|| {
				let ct = ctx_s_rs.seal(b"aad", black_box(&pt)).unwrap();
				ctx_r_rs.open(b"aad", &ct).unwrap()
			})
		});
		g.bench_with_input(BenchmarkId::new("rust_hpke", size), &size, |b, _| {
			b.iter(|| {
				let ct = ctx_s_rh.seal(black_box(&pt), b"aad").unwrap();
				ctx_r_rh.open(&ct, b"aad").unwrap()
			})
		});
	}
	g.finish();
}

// =============================================================================
//  Export
// =============================================================================

fn bench_export(c: &mut Criterion) {
	// API note: hpke-ng and hpke-rs return an allocated Vec per call, so one
	// small heap allocation is included in their timed paths. rust-hpke writes
	// into a caller-supplied &mut [u8] with no allocation; a single [u8; 256]
	// buffer is pre-allocated here and sliced to each output length, so its
	// timed path is pure HKDF. The difference is intentional and reflects each
	// library's API design — it is not a measurement artifact.
	type Suite = ng::Hpke<ng::DhKemX25519HkdfSha256, ng::HkdfSha256, ng::ChaCha20Poly1305>;
	let mut prng = rand_chacha::ChaCha20Rng::from_seed([0x42u8; 32]);
	let (_, pk_ng) = ng::DhKemX25519HkdfSha256::generate(&mut prng).unwrap();
	let (_enc, ctx_ng) = Suite::setup_sender_base(&mut prng, &pk_ng, b"info").unwrap();

	let mut rs = HpkeRs::<HpkeRustCrypto>::new(
		Mode::Base,
		rs_types::KemAlgorithm::DhKem25519,
		rs_types::KdfAlgorithm::HkdfSha256,
		rs_types::AeadAlgorithm::ChaCha20Poly1305,
	);
	let (_, pk_rs) = rs.derive_key_pair(&[0x42u8; 32]).unwrap().into_keys();
	rs.seed(&SEED).unwrap();
	let (_enc_rs, ctx_rs) = rs.setup_sender(&pk_rs, b"info", None, None, None).unwrap();

	// rust-hpke: Note that export() takes a &mut [u8], no allocation.
	// Pre-allocate once, slice per length inside the loop.
	let (sk_rh, pk_rh) = RhX25519::gen_keypair_with_rng(&mut RhChaCha20Rng(&mut prng));
	let (enc_rh, _) = hpke::setup_sender_with_rng::<RhChaCha20, RhHkdfSha256, RhX25519>(
		&OpModeS::Base,
		&pk_rh,
		b"info",
		&mut RhChaCha20Rng(&mut prng),
	)
	.unwrap();
	let ctx_rh = hpke::setup_receiver::<RhChaCha20, RhHkdfSha256, RhX25519>(
		&OpModeR::Base,
		&sk_rh,
		&enc_rh,
		b"info",
	)
	.unwrap();
	let mut rh_export_buf = [0u8; 256]; // covers all EXPORT_LENGTHS (max = 256)

	let mut g = c.benchmark_group("x25519_chacha20_export");
	// 5 output lengths × 3 libraries. export() is one of the cheapest ops in
	// the suite, so the full 60-sample count is kept for tight CIs; 2s window
	// suffices.
	g.measurement_time(Duration::from_secs(2));
	g.sample_size(60);
	for &len in EXPORT_LENGTHS {
		g.bench_with_input(BenchmarkId::new("hpke_ng", len), &len, |b, _| {
			b.iter(|| ctx_ng.export(b"export-context", black_box(len)).unwrap())
		});
		g.bench_with_input(BenchmarkId::new("hpke_rs", len), &len, |b, _| {
			b.iter(|| ctx_rs.export(b"export-context", black_box(len)).unwrap())
		});
		g.bench_with_input(BenchmarkId::new("rust_hpke", len), &len, |b, &len| {
			b.iter(|| {
				ctx_rh
					.export(b"export-context", &mut rh_export_buf[..len])
					.unwrap()
			})
		});
	}
	g.finish();
}

// =============================================================================
//  End-to-end round-trip: encrypt + decrypt one 1 KiB message
// =============================================================================

fn bench_roundtrip(c: &mut Criterion) {
	type Suite = ng::Hpke<ng::DhKemX25519HkdfSha256, ng::HkdfSha256, ng::ChaCha20Poly1305>;
	let mut prng = rand_chacha::ChaCha20Rng::from_seed([0x42u8; 32]);
	let (sk_ng, pk_ng) = ng::DhKemX25519HkdfSha256::generate(&mut prng).unwrap();

	let mut rs = HpkeRs::<HpkeRustCrypto>::new(
		Mode::Base,
		rs_types::KemAlgorithm::DhKem25519,
		rs_types::KdfAlgorithm::HkdfSha256,
		rs_types::AeadAlgorithm::ChaCha20Poly1305,
	);
	let (sk_rs, pk_rs) = rs.derive_key_pair(&[0x42u8; 32]).unwrap().into_keys();

	let (sk, pk) = RhX25519::gen_keypair_with_rng(&mut RhChaCha20Rng(&mut prng));

	let pt = vec![0xAAu8; 1024];

	let mut g = c.benchmark_group("x25519_chacha20_roundtrip_1k");
	// Headline end-to-end number: full seal + open of one 1 KiB message, 3
	// libraries. Each iteration is the most expensive in the suite (KEM +
	// key schedule, twice), so the window is widened to 3s; 50 samples
	// balances CI tightness against this group's higher per-iteration cost.
	g.measurement_time(Duration::from_secs(3));
	g.sample_size(50);
	g.bench_function("hpke_ng", |b| {
		b.iter(|| {
			let (enc, ct) =
				Suite::seal_base(&mut prng, &pk_ng, b"info", b"aad", black_box(&pt)).unwrap();
			Suite::open_base(&enc, &sk_ng, b"info", b"aad", &ct).unwrap()
		})
	});
	rs.seed(&SEED).unwrap();
	g.bench_function("hpke_rs", |b| {
		b.iter(|| {
			let (enc, ct) = rs
				.seal(&pk_rs, b"info", b"aad", black_box(&pt), None, None, None)
				.unwrap();
			let mut ctx = rs
				.setup_receiver(&enc, &sk_rs, b"info", None, None, None)
				.unwrap();
			ctx.open(b"aad", &ct).unwrap()
		})
	});
	g.bench_function("rust_hpke", |b| {
		b.iter(|| {
			let (enc, mut ctx_s) =
				hpke::setup_sender_with_rng::<RhChaCha20, RhHkdfSha256, RhX25519>(
					&OpModeS::Base,
					&pk,
					b"info",
					&mut RhChaCha20Rng(&mut prng),
				)
				.unwrap();
			let ct = ctx_s.seal(black_box(&pt), b"aad").unwrap();
			let mut ctx_r = hpke::setup_receiver::<RhChaCha20, RhHkdfSha256, RhX25519>(
				&OpModeR::Base,
				&sk,
				&enc,
				b"info",
			)
			.unwrap();
			ctx_r.open(&ct, b"aad").unwrap()
		})
	});
	g.finish();
}

criterion_group! {
	name = benches;
	config = quick();
	targets =
		bench_kem_x25519,
		bench_kem_p256,
		bench_kem_k256,
		bench_kem_xwing,
		bench_kem_mlkem768,
		bench_kem_mlkem1024,
		bench_setup_x25519_chacha,
		bench_setup_x25519_aes128,
		bench_setup_x25519_aes256,
		bench_setup_p256_aes128,
		bench_setup_p256_aes256,
		bench_setup_k256_chacha,
		bench_setup_xwing_chacha,
		bench_setup_mlkem768_chacha,
		bench_setup_mlkem1024_chacha,
		bench_seal_x25519_chacha_payload_sweep,
		bench_seal_x25519_aes128_payload_sweep,
		bench_open_x25519_chacha_payload_sweep,
		bench_open_x25519_aes128_payload_sweep,
		bench_context_seal_x25519_chacha,
		bench_context_open_x25519_chacha,
		bench_export,
		bench_roundtrip,
}
criterion_main!(benches);
