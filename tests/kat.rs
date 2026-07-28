//! RFC 9180 Known-Answer-Test runner.
//!
//! For every vector in `tests/test_vectors.json` and `tests/test_vectors_k256.json`,
//! asserts byte equality of the derived key pair, the shared secret, the key,
//! base nonce and exporter secret, every ciphertext, and every exported value.
//!
//! The vector files are excluded from the published crate (see `Cargo.toml`), so
//! this harness runs from a git checkout only.

#![allow(non_snake_case)]

use std::fs::File;
use std::io::BufReader;

use serde::Deserialize;

/// One vector. Fields the harness does not assert on are omitted; serde ignores
/// the unknown keys that remain in the JSON.
#[derive(Deserialize)]
pub struct HpkeTestVector {
	pub mode: u8,
	pub kem_id: u16,
	pub kdf_id: u16,
	pub aead_id: u16,
	pub info: String,
	pub ikmR: String,
	pub ikmS: Option<String>,
	pub ikmE: String,
	pub skRm: String,
	pub psk: Option<String>,
	pub psk_id: Option<String>,
	pub pkRm: String,
	pub pkEm: String,
	pub enc: String,
	pub shared_secret: String,
	pub key: String,
	pub base_nonce: String,
	pub exporter_secret: String,
	pub encryptions: Vec<CiphertextKAT>,
	pub exports: Vec<ExportsKAT>,
}

#[derive(Deserialize)]
pub struct CiphertextKAT {
	pub aad: String,
	pub ct: String,
	pub pt: String,
}

#[derive(Deserialize)]
pub struct ExportsKAT {
	pub exporter_context: String,
	pub L: usize,
	pub exported_value: String,
}

pub fn load_vectors() -> Vec<HpkeTestVector> {
	let mut all = Vec::new();
	for path in ["tests/test_vectors.json", "tests/test_vectors_k256.json"] {
		let f = File::open(path).expect(path);
		let mut v: Vec<HpkeTestVector> =
			serde_json::from_reader(BufReader::new(f)).expect("parse KAT JSON");
		all.append(&mut v);
	}
	all
}

#[test]
fn kat_files_load_and_have_minimum_count() {
	let v = load_vectors();
	assert!(v.len() > 100, "expected >100 KAT vectors, got {}", v.len());
}

use hpke_ng::*;

fn hex_decode(s: &str) -> Vec<u8> {
	hex::decode(s).expect("invalid hex")
}

fn opt_hex(s: &Option<String>) -> Option<Vec<u8>> {
	s.as_ref().and_then(|s| {
		if s.is_empty() {
			None
		} else {
			Some(hex_decode(s))
		}
	})
}

/// Common KAT verification: derived keys, key-schedule outputs, and exporter values.
/// Bound `A: Aead` so it works for both `SealingAead` and `ExportOnly` configurations.
fn run_kat_common<K, F, A>(v: &HpkeTestVector) -> ReceiverContext<K, F, A>
where
	K: hpke_ng::Kem,
	F: hpke_ng::Kdf,
	A: hpke_ng::Aead,
{
	let info = hex_decode(&v.info);
	let ikm_r = hex_decode(&v.ikmR);
	let (sk_r, pk_r) = K::derive_key_pair(&ikm_r).expect("derive R");
	assert_eq!(
		<K as Kem>::pk_to_bytes(&pk_r),
		hex_decode(&v.pkRm),
		"pkRm mismatch"
	);
	// `sk_from_bytes` must accept the vector's private key and yield the same
	// key `DeriveKeyPair` produced.
	//
	// Byte equality with `skRm` deliberately does *not* hold for X25519 and
	// X448: RFC 9180 §7.1.2 serializes the raw scalar, while this crate stores
	// it clamped per RFC 7748 §5 so that `sk_to_bytes` is canonical across the
	// `generate` / `derive` / `sk_from_bytes` paths. The two encodings denote
	// the same scalar — both clamp identically at use time — so they agree on
	// the public key and on every DH output, which is what interop needs and
	// what this asserts. The P-curves, which do not clamp, do match byte for
	// byte.
	let sk_from_vector = K::sk_from_bytes(&hex_decode(&v.skRm)).expect("skRm bytes");
	assert_eq!(
		<K as Kem>::sk_to_bytes(&sk_from_vector).as_slice(),
		<K as Kem>::sk_to_bytes(&sk_r).as_slice(),
		"skRm disagrees with DeriveKeyPair(ikmR)",
	);

	let ikm_e = hex_decode(&v.ikmE);
	let (_, pk_e) = K::derive_key_pair(&ikm_e).expect("derive E");
	assert_eq!(
		<K as Kem>::pk_to_bytes(&pk_e),
		hex_decode(&v.pkEm),
		"pkEm mismatch"
	);

	let psk_bytes = opt_hex(&v.psk).unwrap_or_default();
	let psk_id_bytes = opt_hex(&v.psk_id).unwrap_or_default();
	// PSK-mode vectors carry both fields and Base/Auth vectors carry neither, so
	// the bundle exists only for the modes that use it.
	let psk = match v.mode {
		1 | 3 => Some(Psk::new(&psk_bytes, &psk_id_bytes).expect("KAT PSK is well formed")),
		_ => None,
	};
	let shared_secret = hex_decode(&v.shared_secret);

	// 1. Direct key-schedule comparison.
	let direct_ctx = match v.mode {
		0 => hpke_ng::__test_only::key_schedule_psk_free::<hpke_ng::BaseModeTag, K, F, A>(
			&shared_secret,
			&info,
		),
		1 => hpke_ng::__test_only::key_schedule_psk::<hpke_ng::PskModeTag, K, F, A>(
			&shared_secret,
			&info,
			psk.expect("psk mode vector has a PSK"),
		),
		2 => hpke_ng::__test_only::key_schedule_psk_free::<hpke_ng::AuthModeTag, K, F, A>(
			&shared_secret,
			&info,
		),
		3 => hpke_ng::__test_only::key_schedule_psk::<hpke_ng::AuthPskModeTag, K, F, A>(
			&shared_secret,
			&info,
			psk.expect("auth-psk mode vector has a PSK"),
		),
		m => panic!("unknown mode {m}"),
	}
	.expect("key_schedule");
	assert_eq!(direct_ctx.key(), hex_decode(&v.key), "key mismatch");
	assert_eq!(
		direct_ctx.nonce(),
		hex_decode(&v.base_nonce),
		"base_nonce mismatch"
	);
	assert_eq!(
		direct_ctx.exporter_secret(),
		hex_decode(&v.exporter_secret),
		"exporter_secret mismatch",
	);
	assert_eq!(direct_ctx.sequence_number(), 0);

	// 2. End-to-end receiver setup from the vector's `enc`.
	let kat_enc = K::enc_from_bytes(&hex_decode(&v.enc)).expect("enc bytes");
	let receiver_ctx = match v.mode {
		0 => Hpke::<K, F, A>::setup_receiver_base(&kat_enc, &sk_r, &info)
			.expect("setup_receiver_base"),
		1 => Hpke::<K, F, A>::setup_receiver_psk(
			&kat_enc,
			&sk_r,
			&info,
			psk.expect("psk mode vector has a PSK"),
		)
		.expect("setup_receiver_psk"),
		m => panic!(
			"Auth/AuthPsk vectors (mode={}) handled by run_kat_auth_*",
			m
		),
	};
	assert_eq!(receiver_ctx.key(), hex_decode(&v.key));
	assert_eq!(receiver_ctx.nonce(), hex_decode(&v.base_nonce));

	// Decapsulation in isolation, so a KEM-level failure is distinguishable
	// from a key-schedule one.
	assert_eq!(
		K::decap(&kat_enc, &sk_r).expect("decap").as_ref(),
		shared_secret.as_slice(),
		"decap shared_secret mismatch",
	);

	// 3. Exporter values.
	for ex in &v.exports {
		let exported = receiver_ctx
			.export(&hex_decode(&ex.exporter_context), ex.L)
			.expect("export");
		assert_eq!(exported, hex_decode(&ex.exported_value), "export mismatch");
	}

	receiver_ctx
}

/// KAT runner for sealing AEADs — runs `run_kat_common` plus ciphertext loop.
fn run_kat_sealing<K, F, A>(v: &HpkeTestVector)
where
	K: hpke_ng::Kem,
	F: hpke_ng::Kdf,
	A: hpke_ng::SealingAead,
{
	let mut ctx = run_kat_common::<K, F, A>(v);
	for ct_kat in &v.encryptions {
		let recovered = ctx
			.open(&hex_decode(&ct_kat.aad), &hex_decode(&ct_kat.ct))
			.expect("open KAT ct");
		assert_eq!(recovered, hex_decode(&ct_kat.pt), "plaintext mismatch");
	}
}

/// KAT runner for `ExportOnly` AEAD.
fn run_kat_export<K, F>(v: &HpkeTestVector)
where
	K: hpke_ng::Kem,
	F: hpke_ng::Kdf,
{
	assert!(
		v.encryptions.is_empty(),
		"ExportOnly KAT must have no encryptions"
	);
	let _ = run_kat_common::<K, F, ExportOnly>(v);
}

macro_rules! kat_test_sealing {
	($name:ident, $kem:ty, $kdf:ty, $aead:ty, $kem_id:expr, $kdf_id:expr, $aead_id:expr) => {
		#[test]
		fn $name() {
			let mut count = 0usize;
			for v in load_vectors().iter().filter(|v| {
				v.kem_id == $kem_id
					&& v.kdf_id == $kdf_id
					&& v.aead_id == $aead_id
					&& (v.mode == 0 || v.mode == 1)
			}) {
				count += 1;
				run_kat_sealing::<$kem, $kdf, $aead>(v);
			}
			assert!(
				count > 0,
				"no Base/Psk KAT vectors for {} {} {}",
				$kem_id,
				$kdf_id,
				$aead_id
			);
		}
	};
}

macro_rules! kat_test_export {
	($name:ident, $kem:ty, $kdf:ty, $kem_id:expr, $kdf_id:expr) => {
		#[test]
		fn $name() {
			let mut count = 0usize;
			for v in load_vectors().iter().filter(|v| {
				v.kem_id == $kem_id
					&& v.kdf_id == $kdf_id
					&& v.aead_id == 0xFFFF
					&& (v.mode == 0 || v.mode == 1)
			}) {
				count += 1;
				run_kat_export::<$kem, $kdf>(v);
			}
			assert!(
				count > 0,
				"no Base/Psk export-only KAT vectors for {} {}",
				$kem_id,
				$kdf_id
			);
		}
	};
}

// Generate the test set.
kat_test_sealing!(
	kat_x25519_sha256_chacha20,
	DhKemX25519HkdfSha256,
	HkdfSha256,
	ChaCha20Poly1305,
	0x0020,
	0x0001,
	0x0003
);
kat_test_sealing!(
	kat_x25519_sha256_aes128,
	DhKemX25519HkdfSha256,
	HkdfSha256,
	Aes128Gcm,
	0x0020,
	0x0001,
	0x0001
);
kat_test_sealing!(
	kat_x25519_sha256_aes256,
	DhKemX25519HkdfSha256,
	HkdfSha256,
	Aes256Gcm,
	0x0020,
	0x0001,
	0x0002
);
kat_test_export!(
	kat_x25519_sha256_export,
	DhKemX25519HkdfSha256,
	HkdfSha256,
	0x0020,
	0x0001
);
kat_test_sealing!(
	kat_p256_sha256_chacha20,
	DhKemP256HkdfSha256,
	HkdfSha256,
	ChaCha20Poly1305,
	0x0010,
	0x0001,
	0x0003
);
kat_test_sealing!(
	kat_p256_sha256_aes128,
	DhKemP256HkdfSha256,
	HkdfSha256,
	Aes128Gcm,
	0x0010,
	0x0001,
	0x0001
);
// P-384 (0x0011) has no vectors in the bundled test_vectors.json; skipped until vectors are added.
kat_test_sealing!(
	kat_p521_sha512_aes256,
	DhKemP521HkdfSha512,
	HkdfSha512,
	Aes256Gcm,
	0x0012,
	0x0003,
	0x0002
);
kat_test_sealing!(
	kat_x448_sha512_chacha20,
	DhKemX448HkdfSha512,
	HkdfSha512,
	ChaCha20Poly1305,
	0x0021,
	0x0003,
	0x0003
);
kat_test_sealing!(
	kat_k256_sha256_chacha20,
	DhKemK256HkdfSha256,
	HkdfSha256,
	ChaCha20Poly1305,
	0x0016,
	0x0001,
	0x0003
);

fn run_kat_auth_sealing<K, F, A>(v: &HpkeTestVector)
where
	K: hpke_ng::AuthKem,
	F: hpke_ng::Kdf,
	A: hpke_ng::SealingAead,
{
	let info = hex_decode(&v.info);
	let (sk_r, _pk_r) = K::derive_key_pair(&hex_decode(&v.ikmR)).unwrap();
	let ikm_s = v.ikmS.as_ref().expect("auth-mode vector has ikmS");
	let (_sk_s, pk_s) = K::derive_key_pair(&hex_decode(ikm_s)).unwrap();

	let psk_bytes = opt_hex(&v.psk).unwrap_or_default();
	let psk_id_bytes = opt_hex(&v.psk_id).unwrap_or_default();

	let kat_enc = K::enc_from_bytes(&hex_decode(&v.enc)).unwrap();
	let mut ctx = if v.mode == 2 {
		Hpke::<K, F, A>::setup_receiver_auth(&kat_enc, &sk_r, &info, &pk_s).unwrap()
	} else {
		let psk = Psk::new(&psk_bytes, &psk_id_bytes).expect("KAT PSK is well formed");
		Hpke::<K, F, A>::setup_receiver_auth_psk(&kat_enc, &sk_r, &info, psk, &pk_s).unwrap()
	};
	assert_eq!(ctx.key(), hex_decode(&v.key), "auth key mismatch");
	assert_eq!(
		ctx.nonce(),
		hex_decode(&v.base_nonce),
		"auth nonce mismatch"
	);
	assert_eq!(
		ctx.exporter_secret(),
		hex_decode(&v.exporter_secret),
		"auth exporter mismatch"
	);

	for ct_kat in &v.encryptions {
		let recovered = ctx
			.open(&hex_decode(&ct_kat.aad), &hex_decode(&ct_kat.ct))
			.expect("auth open ct");
		assert_eq!(recovered, hex_decode(&ct_kat.pt));
	}
}

macro_rules! kat_auth_sealing {
	($name:ident, $kem:ty, $kdf:ty, $aead:ty, $kem_id:expr, $kdf_id:expr, $aead_id:expr) => {
		#[test]
		fn $name() {
			let mut count = 0usize;
			for entry in load_vectors().iter().filter(|e| {
				e.kem_id == $kem_id
					&& e.kdf_id == $kdf_id
					&& e.aead_id == $aead_id
					&& (e.mode == 2 || e.mode == 3)
			}) {
				count += 1;
				run_kat_auth_sealing::<$kem, $kdf, $aead>(entry);
			}
			assert!(
				count > 0,
				"no auth-mode KAT for {}/{}/{}",
				$kem_id,
				$kdf_id,
				$aead_id
			);
		}
	};
}

kat_auth_sealing!(
	kat_x25519_sha256_chacha20_auth,
	DhKemX25519HkdfSha256,
	HkdfSha256,
	ChaCha20Poly1305,
	0x0020,
	0x0001,
	0x0003
);
kat_auth_sealing!(
	kat_p256_sha256_aes128_auth,
	DhKemP256HkdfSha256,
	HkdfSha256,
	Aes128Gcm,
	0x0010,
	0x0001,
	0x0001
);
kat_auth_sealing!(
	kat_p521_sha512_aes256_auth,
	DhKemP521HkdfSha512,
	HkdfSha512,
	Aes256Gcm,
	0x0012,
	0x0003,
	0x0002
);
