//! Criterion benchmark suite for hpke-ng.
//!
//! Group names and benchmark IDs mirror those in `benches/comparative.rs` for
//! the `hpke_ng` members, so the two suites can be cross-compared with critcmp:
//!
//! ```text
//! critcmp <bench-baseline> <comparative-baseline>
//! ```
//!
//! Run with:
//! ```
//! RUSTFLAGS="-C target-cpu=native" cargo bench --bench bench [--features pq]
//! ```

use std::hint::black_box;
use std::time::Duration;

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use hpke_ng::*;
use rand::SeedableRng;

const PAYLOAD_SIZES: &[usize] = &[16, 64, 256, 1024, 4096, 16384, 65536, 262144];
const EXPORT_LENGTHS: &[usize] = &[16, 32, 64, 128, 256];

fn quick() -> Criterion {
	Criterion::default()
		.sample_size(60)
		.measurement_time(Duration::from_secs(3))
		.warm_up_time(Duration::from_secs(1))
}

// =============================================================================
//  KEM operations: generate / derive_key_pair / encap / decap
// =============================================================================

fn bench_kem_x25519(c: &mut Criterion) {
	let mut g = c.benchmark_group("kem/x25519");
	let mut prng = rand_chacha::ChaCha20Rng::from_seed([0x42u8; 32]);

	g.bench_function("hpke_ng/generate", |b| {
		b.iter(|| DhKemX25519HkdfSha256::generate(&mut prng).unwrap())
	});

	let ikm = [0x99u8; 32];
	g.bench_function("hpke_ng/derive_key_pair", |b| {
		b.iter(|| DhKemX25519HkdfSha256::derive_key_pair(black_box(&ikm)).unwrap())
	});

	{
		let (_, pk) = DhKemX25519HkdfSha256::generate(&mut prng).unwrap();
		g.bench_function("hpke_ng/encap", |b| {
			b.iter(|| DhKemX25519HkdfSha256::encap(&mut prng, black_box(&pk)).unwrap())
		});
	}

	{
		let (sk, pk) = DhKemX25519HkdfSha256::generate(&mut prng).unwrap();
		let (_, enc) = DhKemX25519HkdfSha256::encap(&mut prng, &pk).unwrap();
		g.bench_function("hpke_ng/decap", |b| {
			b.iter(|| DhKemX25519HkdfSha256::decap(black_box(&enc), &sk).unwrap())
		});
	}

	{
		let (sk_s, _) = DhKemX25519HkdfSha256::generate(&mut prng).unwrap();
		let (_, pk_r) = DhKemX25519HkdfSha256::generate(&mut prng).unwrap();
		g.bench_function("hpke_ng/auth_encap", |b| {
			b.iter(|| {
				DhKemX25519HkdfSha256::auth_encap(&mut prng, black_box(&pk_r), &sk_s).unwrap()
			})
		});
	}

	{
		let (sk_r, pk_r) = DhKemX25519HkdfSha256::generate(&mut prng).unwrap();
		let (sk_s, pk_s) = DhKemX25519HkdfSha256::generate(&mut prng).unwrap();
		let (_, enc) = DhKemX25519HkdfSha256::auth_encap(&mut prng, &pk_r, &sk_s).unwrap();
		g.bench_function("hpke_ng/auth_decap", |b| {
			b.iter(|| DhKemX25519HkdfSha256::auth_decap(black_box(&enc), &sk_r, &pk_s).unwrap())
		});
	}

	g.finish();
}

fn bench_kem_p256(c: &mut Criterion) {
	let mut g = c.benchmark_group("kem/p256");
	let mut prng = rand_chacha::ChaCha20Rng::from_seed([0x42u8; 32]);

	g.bench_function("hpke_ng/generate", |b| {
		b.iter(|| DhKemP256HkdfSha256::generate(&mut prng).unwrap())
	});

	let ikm = [0x99u8; 32];
	g.bench_function("hpke_ng/derive_key_pair", |b| {
		b.iter(|| DhKemP256HkdfSha256::derive_key_pair(black_box(&ikm)).unwrap())
	});

	{
		let (_, pk) = DhKemP256HkdfSha256::generate(&mut prng).unwrap();
		g.bench_function("hpke_ng/encap", |b| {
			b.iter(|| DhKemP256HkdfSha256::encap(&mut prng, black_box(&pk)).unwrap())
		});
	}

	{
		let (sk, pk) = DhKemP256HkdfSha256::generate(&mut prng).unwrap();
		let (_, enc) = DhKemP256HkdfSha256::encap(&mut prng, &pk).unwrap();
		g.bench_function("hpke_ng/decap", |b| {
			b.iter(|| DhKemP256HkdfSha256::decap(black_box(&enc), &sk).unwrap())
		});
	}

	g.finish();
}

fn bench_kem_k256(c: &mut Criterion) {
	let mut g = c.benchmark_group("kem/k256");
	let mut prng = rand_chacha::ChaCha20Rng::from_seed([0x42u8; 32]);

	g.bench_function("hpke_ng/generate", |b| {
		b.iter(|| DhKemK256HkdfSha256::generate(&mut prng).unwrap())
	});

	let ikm = [0x99u8; 32];
	g.bench_function("hpke_ng/derive_key_pair", |b| {
		b.iter(|| DhKemK256HkdfSha256::derive_key_pair(black_box(&ikm)).unwrap())
	});

	{
		let (_, pk) = DhKemK256HkdfSha256::generate(&mut prng).unwrap();
		g.bench_function("hpke_ng/encap", |b| {
			b.iter(|| DhKemK256HkdfSha256::encap(&mut prng, black_box(&pk)).unwrap())
		});
	}

	{
		let (sk, pk) = DhKemK256HkdfSha256::generate(&mut prng).unwrap();
		let (_, enc) = DhKemK256HkdfSha256::encap(&mut prng, &pk).unwrap();
		g.bench_function("hpke_ng/decap", |b| {
			b.iter(|| DhKemK256HkdfSha256::decap(black_box(&enc), &sk).unwrap())
		});
	}

	g.finish();
}

#[cfg(feature = "pq")]
fn bench_kem_xwing(c: &mut Criterion) {
	let mut g = c.benchmark_group("kem/xwing");
	let mut prng = rand_chacha::ChaCha20Rng::from_seed([0x42u8; 32]);

	g.bench_function("hpke_ng/generate", |b| {
		b.iter(|| XWingDraft06::generate(&mut prng).unwrap())
	});

	let ikm = [0x99u8; 32];
	g.bench_function("hpke_ng/derive_key_pair", |b| {
		b.iter(|| XWingDraft06::derive_key_pair(black_box(&ikm)).unwrap())
	});

	{
		let (_, pk) = XWingDraft06::generate(&mut prng).unwrap();
		g.bench_function("hpke_ng/encap", |b| {
			b.iter(|| XWingDraft06::encap(&mut prng, black_box(&pk)).unwrap())
		});
	}

	{
		let (sk, pk) = XWingDraft06::generate(&mut prng).unwrap();
		let (_, enc) = XWingDraft06::encap(&mut prng, &pk).unwrap();
		g.bench_function("hpke_ng/decap", |b| {
			b.iter(|| XWingDraft06::decap(black_box(&enc), &sk).unwrap())
		});
	}

	g.finish();
}

#[cfg(feature = "pq")]
fn bench_kem_mlkem768(c: &mut Criterion) {
	let mut g = c.benchmark_group("kem/mlkem768");
	let mut prng = rand_chacha::ChaCha20Rng::from_seed([0x42u8; 32]);

	g.bench_function("hpke_ng/generate", |b| {
		b.iter(|| MlKem768::generate(&mut prng).unwrap())
	});

	// 64-byte (d || z) seed per draft-connolly-cfrg-hpke-mlkem §3.2
	let ikm = [0x99u8; 64];
	g.bench_function("hpke_ng/derive_key_pair", |b| {
		b.iter(|| MlKem768::derive_key_pair(black_box(&ikm)).unwrap())
	});

	{
		let (_, pk) = MlKem768::generate(&mut prng).unwrap();
		g.bench_function("hpke_ng/encap", |b| {
			b.iter(|| MlKem768::encap(&mut prng, black_box(&pk)).unwrap())
		});
	}

	{
		let (sk, pk) = MlKem768::generate(&mut prng).unwrap();
		let (_, enc) = MlKem768::encap(&mut prng, &pk).unwrap();
		g.bench_function("hpke_ng/decap", |b| {
			b.iter(|| MlKem768::decap(black_box(&enc), &sk).unwrap())
		});
	}

	g.finish();
}

#[cfg(feature = "pq")]
fn bench_kem_mlkem1024(c: &mut Criterion) {
	let mut g = c.benchmark_group("kem/mlkem1024");
	let mut prng = rand_chacha::ChaCha20Rng::from_seed([0x42u8; 32]);

	g.bench_function("hpke_ng/generate", |b| {
		b.iter(|| MlKem1024::generate(&mut prng).unwrap())
	});

	let ikm = [0x99u8; 64];
	g.bench_function("hpke_ng/derive_key_pair", |b| {
		b.iter(|| MlKem1024::derive_key_pair(black_box(&ikm)).unwrap())
	});

	{
		let (_, pk) = MlKem1024::generate(&mut prng).unwrap();
		g.bench_function("hpke_ng/encap", |b| {
			b.iter(|| MlKem1024::encap(&mut prng, black_box(&pk)).unwrap())
		});
	}

	{
		let (sk, pk) = MlKem1024::generate(&mut prng).unwrap();
		let (_, enc) = MlKem1024::encap(&mut prng, &pk).unwrap();
		g.bench_function("hpke_ng/decap", |b| {
			b.iter(|| MlKem1024::decap(black_box(&enc), &sk).unwrap())
		});
	}

	g.finish();
}

// =============================================================================
//  Setup paths: setup_sender / setup_receiver across ciphersuites
// =============================================================================

fn bench_setup_x25519_chacha(c: &mut Criterion) {
	type Suite = Hpke<DhKemX25519HkdfSha256, HkdfSha256, ChaCha20Poly1305>;
	let mut prng = rand_chacha::ChaCha20Rng::from_seed([0x42u8; 32]);
	let (sk, pk) = DhKemX25519HkdfSha256::generate(&mut prng).unwrap();
	let (enc, _) = Suite::setup_sender_base(&mut prng, &pk, b"info").unwrap();

	let mut g = c.benchmark_group("x25519_chacha20/setup_sender_base");
	g.bench_function("hpke_ng", |b| {
		b.iter(|| Suite::setup_sender_base(&mut prng, black_box(&pk), b"info").unwrap())
	});
	g.finish();

	let mut g = c.benchmark_group("x25519_chacha20/setup_receiver_base");
	g.bench_function("hpke_ng", |b| {
		b.iter(|| Suite::setup_receiver_base(black_box(&enc), &sk, b"info").unwrap())
	});
	g.finish();

	let psk = [0xAAu8; 32];
	let psk_id = b"psk-id";
	let mut g = c.benchmark_group("x25519_chacha20/setup_sender_psk");
	g.bench_function("hpke_ng", |b| {
		b.iter(|| {
			Suite::setup_sender_psk(&mut prng, black_box(&pk), b"info", &psk, psk_id).unwrap()
		})
	});
	g.finish();
}

fn bench_setup_x25519_aes128(c: &mut Criterion) {
	type Suite = Hpke<DhKemX25519HkdfSha256, HkdfSha256, Aes128Gcm>;
	let mut prng = rand_chacha::ChaCha20Rng::from_seed([0x42u8; 32]);
	let (_, pk) = DhKemX25519HkdfSha256::generate(&mut prng).unwrap();

	let mut g = c.benchmark_group("x25519_aes128/setup_sender_base");
	g.bench_function("hpke_ng", |b| {
		b.iter(|| Suite::setup_sender_base(&mut prng, black_box(&pk), b"info").unwrap())
	});
	g.finish();
}

fn bench_setup_x25519_aes256(c: &mut Criterion) {
	type Suite = Hpke<DhKemX25519HkdfSha256, HkdfSha256, Aes256Gcm>;
	let mut prng = rand_chacha::ChaCha20Rng::from_seed([0x42u8; 32]);
	let (_, pk) = DhKemX25519HkdfSha256::generate(&mut prng).unwrap();

	let mut g = c.benchmark_group("x25519_aes256/setup_sender_base");
	g.bench_function("hpke_ng", |b| {
		b.iter(|| Suite::setup_sender_base(&mut prng, black_box(&pk), b"info").unwrap())
	});
	g.finish();
}

fn bench_setup_p256_aes128(c: &mut Criterion) {
	type Suite = Hpke<DhKemP256HkdfSha256, HkdfSha256, Aes128Gcm>;
	let mut prng = rand_chacha::ChaCha20Rng::from_seed([0x42u8; 32]);
	let (_, pk) = DhKemP256HkdfSha256::generate(&mut prng).unwrap();

	let mut g = c.benchmark_group("p256_aes128/setup_sender_base");
	g.bench_function("hpke_ng", |b| {
		b.iter(|| Suite::setup_sender_base(&mut prng, black_box(&pk), b"info").unwrap())
	});
	g.finish();
}

fn bench_setup_p256_aes256(c: &mut Criterion) {
	type Suite = Hpke<DhKemP256HkdfSha256, HkdfSha256, Aes256Gcm>;
	let mut prng = rand_chacha::ChaCha20Rng::from_seed([0x42u8; 32]);
	let (_, pk) = DhKemP256HkdfSha256::generate(&mut prng).unwrap();

	let mut g = c.benchmark_group("p256_aes256/setup_sender_base");
	g.bench_function("hpke_ng", |b| {
		b.iter(|| Suite::setup_sender_base(&mut prng, black_box(&pk), b"info").unwrap())
	});
	g.finish();
}

fn bench_setup_k256_chacha(c: &mut Criterion) {
	type Suite = Hpke<DhKemK256HkdfSha256, HkdfSha256, ChaCha20Poly1305>;
	let mut prng = rand_chacha::ChaCha20Rng::from_seed([0x42u8; 32]);
	let (_, pk) = DhKemK256HkdfSha256::generate(&mut prng).unwrap();

	let mut g = c.benchmark_group("k256_chacha20/setup_sender_base");
	g.bench_function("hpke_ng", |b| {
		b.iter(|| Suite::setup_sender_base(&mut prng, black_box(&pk), b"info").unwrap())
	});
	g.finish();
}

#[cfg(feature = "pq")]
fn bench_setup_xwing_chacha(c: &mut Criterion) {
	type Suite = Hpke<XWingDraft06, HkdfSha256, ChaCha20Poly1305>;
	let mut prng = rand_chacha::ChaCha20Rng::from_seed([0x42u8; 32]);
	let (sk, pk) = XWingDraft06::generate(&mut prng).unwrap();
	let (enc, _) = Suite::setup_sender_base(&mut prng, &pk, b"info").unwrap();

	let mut g = c.benchmark_group("xwing_chacha20/setup_sender_base");
	g.bench_function("hpke_ng", |b| {
		b.iter(|| Suite::setup_sender_base(&mut prng, black_box(&pk), b"info").unwrap())
	});
	g.finish();

	let mut g = c.benchmark_group("xwing_chacha20/setup_receiver_base");
	g.bench_function("hpke_ng", |b| {
		b.iter(|| Suite::setup_receiver_base(black_box(&enc), &sk, b"info").unwrap())
	});
	g.finish();
}

#[cfg(feature = "pq")]
fn bench_setup_mlkem768_chacha(c: &mut Criterion) {
	type Suite = Hpke<MlKem768, HkdfSha256, ChaCha20Poly1305>;
	let mut prng = rand_chacha::ChaCha20Rng::from_seed([0x42u8; 32]);
	let (sk, pk) = MlKem768::generate(&mut prng).unwrap();
	let (enc, _) = Suite::setup_sender_base(&mut prng, &pk, b"info").unwrap();

	let mut g = c.benchmark_group("mlkem768_chacha20/setup_sender_base");
	g.bench_function("hpke_ng", |b| {
		b.iter(|| Suite::setup_sender_base(&mut prng, black_box(&pk), b"info").unwrap())
	});
	g.finish();

	let mut g = c.benchmark_group("mlkem768_chacha20/setup_receiver_base");
	g.bench_function("hpke_ng", |b| {
		b.iter(|| Suite::setup_receiver_base(black_box(&enc), &sk, b"info").unwrap())
	});
	g.finish();
}

#[cfg(feature = "pq")]
fn bench_setup_mlkem1024_chacha(c: &mut Criterion) {
	type Suite = Hpke<MlKem1024, HkdfSha256, ChaCha20Poly1305>;
	let mut prng = rand_chacha::ChaCha20Rng::from_seed([0x42u8; 32]);
	let (sk, pk) = MlKem1024::generate(&mut prng).unwrap();
	let (enc, _) = Suite::setup_sender_base(&mut prng, &pk, b"info").unwrap();

	let mut g = c.benchmark_group("mlkem1024_chacha20/setup_sender_base");
	g.bench_function("hpke_ng", |b| {
		b.iter(|| Suite::setup_sender_base(&mut prng, black_box(&pk), b"info").unwrap())
	});
	g.finish();

	let mut g = c.benchmark_group("mlkem1024_chacha20/setup_receiver_base");
	g.bench_function("hpke_ng", |b| {
		b.iter(|| Suite::setup_receiver_base(black_box(&enc), &sk, b"info").unwrap())
	});
	g.finish();
}

// =============================================================================
//  Single-shot seal sweeps
// =============================================================================

fn bench_seal_x25519_chacha_payload_sweep(c: &mut Criterion) {
	type Suite = Hpke<DhKemX25519HkdfSha256, HkdfSha256, ChaCha20Poly1305>;
	let mut prng = rand_chacha::ChaCha20Rng::from_seed([0x42u8; 32]);
	let (_, pk) = DhKemX25519HkdfSha256::generate(&mut prng).unwrap();

	let mut g = c.benchmark_group("x25519_chacha20_seal_sweep");
	g.measurement_time(Duration::from_secs(2));
	g.sample_size(40);
	for &size in PAYLOAD_SIZES {
		let pt = vec![0xAAu8; size];
		g.throughput(Throughput::Bytes(size as u64));
		g.bench_with_input(BenchmarkId::new("hpke_ng", size), &size, |b, _| {
			b.iter(|| Suite::seal_base(&mut prng, &pk, b"info", b"aad", black_box(&pt)).unwrap())
		});
	}
	g.finish();
}

fn bench_seal_x25519_aes128_payload_sweep(c: &mut Criterion) {
	type Suite = Hpke<DhKemX25519HkdfSha256, HkdfSha256, Aes128Gcm>;
	let mut prng = rand_chacha::ChaCha20Rng::from_seed([0x42u8; 32]);
	let (_, pk) = DhKemX25519HkdfSha256::generate(&mut prng).unwrap();

	let mut g = c.benchmark_group("x25519_aes128_seal_sweep");
	// Reduced 6-size sweep matching comparative.rs (drops 16 B and 256 KiB extremes).
	g.measurement_time(Duration::from_secs(2));
	g.sample_size(40);
	for &size in &[64usize, 256, 1024, 4096, 16384, 65536] {
		let pt = vec![0xAAu8; size];
		g.throughput(Throughput::Bytes(size as u64));
		g.bench_with_input(BenchmarkId::new("hpke_ng", size), &size, |b, _| {
			b.iter(|| Suite::seal_base(&mut prng, &pk, b"info", b"aad", black_box(&pt)).unwrap())
		});
	}
	g.finish();
}

// =============================================================================
//  Single-shot open sweeps
// =============================================================================

fn bench_open_x25519_chacha_payload_sweep(c: &mut Criterion) {
	type Suite = Hpke<DhKemX25519HkdfSha256, HkdfSha256, ChaCha20Poly1305>;
	let mut prng = rand_chacha::ChaCha20Rng::from_seed([0x42u8; 32]);
	let (sk, pk) = DhKemX25519HkdfSha256::generate(&mut prng).unwrap();

	let mut g = c.benchmark_group("x25519_chacha20_open_sweep");
	g.measurement_time(Duration::from_secs(2));
	g.sample_size(40);
	for &size in &[64usize, 256, 1024, 4096, 16384, 65536] {
		let pt = vec![0xAAu8; size];
		let (enc, ct) = Suite::seal_base(&mut prng, &pk, b"info", b"aad", &pt).unwrap();
		g.throughput(Throughput::Bytes(size as u64));
		g.bench_with_input(BenchmarkId::new("hpke_ng", size), &size, |b, _| {
			b.iter(|| {
				Suite::open_base(black_box(&enc), &sk, b"info", b"aad", black_box(&ct)).unwrap()
			})
		});
	}
	g.finish();
}

fn bench_open_x25519_aes128_payload_sweep(c: &mut Criterion) {
	type Suite = Hpke<DhKemX25519HkdfSha256, HkdfSha256, Aes128Gcm>;
	let mut prng = rand_chacha::ChaCha20Rng::from_seed([0x42u8; 32]);
	let (sk, pk) = DhKemX25519HkdfSha256::generate(&mut prng).unwrap();

	let mut g = c.benchmark_group("x25519_aes128_open_sweep");
	g.measurement_time(Duration::from_secs(2));
	g.sample_size(40);
	for &size in &[64usize, 256, 1024, 4096, 16384, 65536] {
		let pt = vec![0xAAu8; size];
		let (enc, ct) = Suite::seal_base(&mut prng, &pk, b"info", b"aad", &pt).unwrap();
		g.throughput(Throughput::Bytes(size as u64));
		g.bench_with_input(BenchmarkId::new("hpke_ng", size), &size, |b, _| {
			b.iter(|| {
				Suite::open_base(black_box(&enc), &sk, b"info", b"aad", black_box(&ct)).unwrap()
			})
		});
	}
	g.finish();
}

// =============================================================================
//  Context seal/open (post-setup hot path — framing + AEAD only)
// =============================================================================

fn bench_context_seal_x25519_chacha(c: &mut Criterion) {
	type Suite = Hpke<DhKemX25519HkdfSha256, HkdfSha256, ChaCha20Poly1305>;
	let mut prng = rand_chacha::ChaCha20Rng::from_seed([0x42u8; 32]);
	let (_, pk) = DhKemX25519HkdfSha256::generate(&mut prng).unwrap();
	let (_, mut ctx) = Suite::setup_sender_base(&mut prng, &pk, b"info").unwrap();

	let mut g = c.benchmark_group("x25519_chacha20_context_seal");
	g.measurement_time(Duration::from_secs(2));
	g.sample_size(50);
	// ctx is shared across all size sub-benchmarks; its sequence counter
	// keeps advancing but has no effect on timing and cannot wrap.
	for &size in &[64usize, 1024, 16384, 65536] {
		let pt = vec![0xAAu8; size];
		g.throughput(Throughput::Bytes(size as u64));
		g.bench_with_input(BenchmarkId::new("hpke_ng", size), &size, |b, _| {
			b.iter(|| ctx.seal(b"aad", black_box(&pt)).unwrap())
		});
	}
	g.finish();
}

fn bench_context_open_x25519_chacha(c: &mut Criterion) {
	type Suite = Hpke<DhKemX25519HkdfSha256, HkdfSha256, ChaCha20Poly1305>;
	let mut prng = rand_chacha::ChaCha20Rng::from_seed([0x42u8; 32]);
	let (sk, pk) = DhKemX25519HkdfSha256::generate(&mut prng).unwrap();

	let mut g = c.benchmark_group("x25519_chacha20_context_open");
	// Sender and receiver contexts established once per size outside the timed
	// loop, advancing in lockstep. Measured time is seal + open combined;
	// subtract context_seal to get pure open latency.
	g.measurement_time(Duration::from_secs(2));
	g.sample_size(50);
	for &size in &[64usize, 1024, 16384, 65536] {
		let pt = vec![0xAAu8; size];
		let (enc, mut ctx_s) = Suite::setup_sender_base(&mut prng, &pk, b"info").unwrap();
		let mut ctx_r = Suite::setup_receiver_base(&enc, &sk, b"info").unwrap();
		g.throughput(Throughput::Bytes(size as u64));
		g.bench_with_input(BenchmarkId::new("hpke_ng", size), &size, |b, _| {
			b.iter(|| {
				let ct = ctx_s.seal(b"aad", black_box(&pt)).unwrap();
				ctx_r.open(b"aad", &ct).unwrap()
			})
		});
	}
	g.finish();
}

// =============================================================================
//  Export
// =============================================================================

fn bench_export(c: &mut Criterion) {
	type Suite = Hpke<DhKemX25519HkdfSha256, HkdfSha256, ChaCha20Poly1305>;
	let mut prng = rand_chacha::ChaCha20Rng::from_seed([0x42u8; 32]);
	let (_, pk) = DhKemX25519HkdfSha256::generate(&mut prng).unwrap();
	let (_, ctx) = Suite::setup_sender_base(&mut prng, &pk, b"info").unwrap();

	let mut g = c.benchmark_group("x25519_chacha20_export");
	g.measurement_time(Duration::from_secs(2));
	g.sample_size(60);
	for &len in EXPORT_LENGTHS {
		g.bench_with_input(BenchmarkId::new("hpke_ng", len), &len, |b, _| {
			b.iter(|| ctx.export(b"export-context", black_box(len)).unwrap())
		});
	}
	g.finish();
}

// =============================================================================
//  End-to-end round-trip: full seal + open of one 1 KiB message
// =============================================================================

fn bench_roundtrip(c: &mut Criterion) {
	type Suite = Hpke<DhKemX25519HkdfSha256, HkdfSha256, ChaCha20Poly1305>;
	let mut prng = rand_chacha::ChaCha20Rng::from_seed([0x42u8; 32]);
	let (sk, pk) = DhKemX25519HkdfSha256::generate(&mut prng).unwrap();
	let pt = vec![0xAAu8; 1024];

	let mut g = c.benchmark_group("x25519_chacha20_roundtrip_1k");
	g.measurement_time(Duration::from_secs(3));
	g.sample_size(50);
	g.bench_function("hpke_ng", |b| {
		b.iter(|| {
			let (enc, ct) =
				Suite::seal_base(&mut prng, &pk, b"info", b"aad", black_box(&pt)).unwrap();
			Suite::open_base(&enc, &sk, b"info", b"aad", &ct).unwrap()
		})
	});
	g.finish();
}

// =============================================================================
//  criterion_group! / criterion_main!
// =============================================================================

#[cfg(not(feature = "pq"))]
criterion_group! {
	name = classical_benches;
	config = quick();
	targets =
		bench_kem_x25519,
		bench_kem_p256,
		bench_kem_k256,
		bench_setup_x25519_chacha,
		bench_setup_x25519_aes128,
		bench_setup_x25519_aes256,
		bench_setup_p256_aes128,
		bench_setup_p256_aes256,
		bench_setup_k256_chacha,
		bench_seal_x25519_chacha_payload_sweep,
		bench_seal_x25519_aes128_payload_sweep,
		bench_open_x25519_chacha_payload_sweep,
		bench_open_x25519_aes128_payload_sweep,
		bench_context_seal_x25519_chacha,
		bench_context_open_x25519_chacha,
		bench_export,
		bench_roundtrip,
}

#[cfg(not(feature = "pq"))]
criterion_main!(classical_benches);

#[cfg(feature = "pq")]
criterion_group! {
	name = pq_benches;
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

#[cfg(feature = "pq")]
criterion_main!(pq_benches);
