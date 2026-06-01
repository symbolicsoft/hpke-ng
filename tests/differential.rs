//! Cross-implementation differential test: feed identical inputs to `hpke-ng`
//! and `hpke-rs` and assert byte-equal outputs.
//!
//! Run with: `cargo test --features differential,kat-internals --test differential`.
//!
//! Strategy:
//!   - Use `hpke-ng` as the *sender* with `encap_with_ikm` (deterministic ephemeral key).
//!   - Use `hpke-rs` as the *receiver* (decapsulates the `enc` bytes produced by `hpke-ng`).
//!   - Compare receiver key-schedule outputs (key, nonce, exporter secret).
//!   - Cross-open: hpke-rs receiver opens hpke-ng ciphertext.
//!
//! This avoids the PRNG-seeding impedance mismatch (hpke-rs seed injects raw
//! bytes into `kem_key_gen`, not through `DeriveKeyPair`).
//!
//! P-384 and P-521 are omitted because hpke-rs-rust-crypto 0.6 only supports
//! X25519, P-256, and secp256k1 (the `supports_kem` gate rejects others).

#![cfg(feature = "differential")]
#![allow(non_snake_case)]

use hpke_ng as ng;
use hpke_rs::{Hpke as HpkeRs, Mode};
use hpke_rs_crypto::types as rs_types;
use hpke_rs_rust_crypto::HpkeRustCrypto as RsBackend;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

const ITERATIONS_DEFAULT: usize = 10;

fn iterations() -> usize {
	std::env::var("HPKE_NG_DIFF_ITERATIONS")
		.ok()
		.and_then(|s| s.parse().ok())
		.unwrap_or(ITERATIONS_DEFAULT)
}

macro_rules! diff_base_sealing {
	(
        $name:ident,
        $ng_kem:ty, $ng_kdf:ty, $ng_aead:ty,
        $rs_kem:expr, $rs_kdf:expr, $rs_aead:expr,
        $seed:expr
    ) => {
		#[test]
		fn $name() {
			type Suite = ng::Hpke<$ng_kem, $ng_kdf, $ng_aead>;

			let mut rng = ChaCha20Rng::seed_from_u64($seed);
			for iter in 0..iterations() {
				let mut buf = |n: usize| {
					let mut v = vec![0u8; n];
					rand::RngCore::fill_bytes(&mut rng, &mut v);
					v
				};
				let info = buf(16);
				let aad = buf(16);
				let pt = buf(64);
				// ikm_r: 64 bytes — safe for all KEM Nsk values (max is 66 for P-521).
				let ikm_r = buf(64);
				let ikm_e = buf(64);

				// --- Sender (hpke-ng) ---
				// Derive receiver keypair deterministically.
				let (sk_r_ng, pk_r_ng) = <$ng_kem as ng::Kem>::derive_key_pair(&ikm_r).unwrap();
				let pk_r_bytes = <$ng_kem as ng::Kem>::pk_to_bytes(&pk_r_ng);

				// Encapsulate with deterministic ephemeral IKM.
				let (ss_ng, enc_ng) = <$ng_kem>::encap_with_ikm(&pk_r_ng, &ikm_e).unwrap();

				// Build sender context and seal.
				let mut send_ctx = ng::SenderContext::from_context(
					ng::key_schedule::<$ng_kem, $ng_kdf, $ng_aead>(
						0x00, // Base mode
						ss_ng.as_ref(),
						&info,
						&[],
						&[],
					)
					.unwrap(),
				);
				let ctxt_ng = send_ctx.seal(&aad, &pt).unwrap();

				// --- Receiver (hpke-rs) ---
				// Derive the same keypair from the same ikm_r.
				let hpke_rs_mode = HpkeRs::<RsBackend>::new(Mode::Base, $rs_kem, $rs_kdf, $rs_aead);
				let kp_rs = hpke_rs_mode.derive_key_pair(&ikm_r).unwrap();
				let (sk_r_rs, pk_r_rs) = kp_rs.into_keys();
				assert_eq!(
					pk_r_rs.as_slice(),
					pk_r_bytes,
					"pkR mismatch (iter {iter}, suite {})",
					stringify!($name),
				);

				// hpke-rs receiver: decapsulate enc_ng, run key schedule.
				let mut recv_rs_ctx = hpke_rs_mode
					.setup_receiver(enc_ng.as_ref(), &sk_r_rs, &info, None, None, None)
					.unwrap();

				// --- hpke-ng receiver for comparison ---
				let enc_for_recv = <$ng_kem as ng::Kem>::enc_from_bytes(enc_ng.as_ref()).unwrap();
				let recv_ng_ctx =
					Suite::setup_receiver_base(&enc_for_recv, &sk_r_ng, &info).unwrap();

				// Key-schedule outputs must match.
				assert_eq!(
					recv_ng_ctx.key(),
					recv_rs_ctx.key(),
					"key mismatch (iter {iter}, suite {})",
					stringify!($name),
				);
				assert_eq!(
					recv_ng_ctx.nonce(),
					recv_rs_ctx.nonce(),
					"nonce mismatch (iter {iter}, suite {})",
					stringify!($name),
				);
				assert_eq!(
					recv_ng_ctx.exporter_secret(),
					recv_rs_ctx.exporter_secret(),
					"exporter mismatch (iter {iter}, suite {})",
					stringify!($name),
				);

				// Cross-open: hpke-rs receiver opens hpke-ng ciphertext.
				let recovered_rs = recv_rs_ctx.open(&aad, &ctxt_ng).unwrap();
				assert_eq!(recovered_rs, pt, "rs open (iter {iter})");

				// hpke-ng receiver opens its own ciphertext (sanity check).
				let mut recv_ng_ctx2 =
					Suite::setup_receiver_base(&enc_for_recv, &sk_r_ng, &info).unwrap();
				let recovered_ng = recv_ng_ctx2.open(&aad, &ctxt_ng).unwrap();
				assert_eq!(recovered_ng, pt, "ng open (iter {iter})");

				// Export values must match at multiple lengths.
				for &l in &[16usize, 64, 128] {
					let exp_ng = recv_ng_ctx.export(b"diff-export", l).unwrap();
					let exp_rs = recv_rs_ctx.export(b"diff-export", l).unwrap();
					assert_eq!(exp_ng, exp_rs, "export len={l} (iter {iter})");
				}

				let _ = sk_r_rs;
			}
		}
	};
}

macro_rules! diff_psk_sealing {
	(
        $name:ident,
        $ng_kem:ty, $ng_kdf:ty, $ng_aead:ty,
        $rs_kem:expr, $rs_kdf:expr, $rs_aead:expr,
        $seed:expr
    ) => {
		#[test]
		fn $name() {
			type Suite = ng::Hpke<$ng_kem, $ng_kdf, $ng_aead>;

			let mut rng = ChaCha20Rng::seed_from_u64($seed);
			for iter in 0..iterations() {
				let mut buf = |n: usize| {
					let mut v = vec![0u8; n];
					rand::RngCore::fill_bytes(&mut rng, &mut v);
					v
				};
				let info = buf(16);
				let aad = buf(16);
				let pt = buf(64);
				let ikm_r = buf(64);
				let ikm_e = buf(64);
				let psk = buf(32);
				let psk_id = buf(8);

				// --- Sender (hpke-ng) ---
				let (sk_r_ng, pk_r_ng) = <$ng_kem as ng::Kem>::derive_key_pair(&ikm_r).unwrap();
				let pk_r_bytes = <$ng_kem as ng::Kem>::pk_to_bytes(&pk_r_ng);

				let (ss_ng, enc_ng) = <$ng_kem>::encap_with_ikm(&pk_r_ng, &ikm_e).unwrap();

				let mut send_ctx = ng::SenderContext::from_context(
					ng::key_schedule::<$ng_kem, $ng_kdf, $ng_aead>(
						0x01, // Psk mode
						ss_ng.as_ref(),
						&info,
						&psk,
						&psk_id,
					)
					.unwrap(),
				);
				let ctxt_ng = send_ctx.seal(&aad, &pt).unwrap();

				// --- Receiver (hpke-rs) ---
				let hpke_rs_mode = HpkeRs::<RsBackend>::new(Mode::Psk, $rs_kem, $rs_kdf, $rs_aead);
				let kp_rs = hpke_rs_mode.derive_key_pair(&ikm_r).unwrap();
				let (sk_r_rs, pk_r_rs) = kp_rs.into_keys();
				assert_eq!(
					pk_r_rs.as_slice(),
					pk_r_bytes,
					"pkR mismatch (iter {iter}, suite {})",
					stringify!($name),
				);

				let mut recv_rs_ctx = hpke_rs_mode
					.setup_receiver(
						enc_ng.as_ref(),
						&sk_r_rs,
						&info,
						Some(&psk),
						Some(&psk_id),
						None,
					)
					.unwrap();

				let enc_for_recv = <$ng_kem as ng::Kem>::enc_from_bytes(enc_ng.as_ref()).unwrap();
				let recv_ng_ctx =
					Suite::setup_receiver_psk(&enc_for_recv, &sk_r_ng, &info, &psk, &psk_id)
						.unwrap();

				assert_eq!(
					recv_ng_ctx.key(),
					recv_rs_ctx.key(),
					"key mismatch (iter {iter})",
				);
				assert_eq!(
					recv_ng_ctx.nonce(),
					recv_rs_ctx.nonce(),
					"nonce mismatch (iter {iter})",
				);
				assert_eq!(
					recv_ng_ctx.exporter_secret(),
					recv_rs_ctx.exporter_secret(),
					"exporter mismatch (iter {iter})",
				);

				// Cross-open: hpke-rs receiver opens hpke-ng ciphertext.
				let recovered_rs = recv_rs_ctx.open(&aad, &ctxt_ng).unwrap();
				assert_eq!(recovered_rs, pt, "rs open (iter {iter})");

				// hpke-ng receiver opens its own ciphertext (sanity check).
				let mut recv_ng_ctx2 =
					Suite::setup_receiver_psk(&enc_for_recv, &sk_r_ng, &info, &psk, &psk_id)
						.unwrap();
				let recovered_ng = recv_ng_ctx2.open(&aad, &ctxt_ng).unwrap();
				assert_eq!(recovered_ng, pt, "ng open (iter {iter})");

				let _ = sk_r_rs;
			}
		}
	};
}

// X25519 × HKDF-SHA256 × {ChaCha20, AES-128, AES-256} × Base.
diff_base_sealing!(
	diff_x25519_sha256_chacha20_base,
	ng::DhKemX25519HkdfSha256,
	ng::HkdfSha256,
	ng::ChaCha20Poly1305,
	rs_types::KemAlgorithm::DhKem25519,
	rs_types::KdfAlgorithm::HkdfSha256,
	rs_types::AeadAlgorithm::ChaCha20Poly1305,
	0xDEAD_BEEF
);
diff_base_sealing!(
	diff_x25519_sha256_aes128_base,
	ng::DhKemX25519HkdfSha256,
	ng::HkdfSha256,
	ng::Aes128Gcm,
	rs_types::KemAlgorithm::DhKem25519,
	rs_types::KdfAlgorithm::HkdfSha256,
	rs_types::AeadAlgorithm::Aes128Gcm,
	0xCAFE_BABE
);
diff_base_sealing!(
	diff_x25519_sha256_aes256_base,
	ng::DhKemX25519HkdfSha256,
	ng::HkdfSha256,
	ng::Aes256Gcm,
	rs_types::KemAlgorithm::DhKem25519,
	rs_types::KdfAlgorithm::HkdfSha256,
	rs_types::AeadAlgorithm::Aes256Gcm,
	0xFEED_FACE
);

// P-256 × Base.
diff_base_sealing!(
	diff_p256_sha256_aes128_base,
	ng::DhKemP256HkdfSha256,
	ng::HkdfSha256,
	ng::Aes128Gcm,
	rs_types::KemAlgorithm::DhKemP256,
	rs_types::KdfAlgorithm::HkdfSha256,
	rs_types::AeadAlgorithm::Aes128Gcm,
	0x1234_5678
);

// PSK mode on X25519 + ChaCha20 and P-256 + AES-128.
diff_psk_sealing!(
	diff_x25519_sha256_chacha20_psk,
	ng::DhKemX25519HkdfSha256,
	ng::HkdfSha256,
	ng::ChaCha20Poly1305,
	rs_types::KemAlgorithm::DhKem25519,
	rs_types::KdfAlgorithm::HkdfSha256,
	rs_types::AeadAlgorithm::ChaCha20Poly1305,
	0xCCCC_DDDD
);
diff_psk_sealing!(
	diff_p256_sha256_aes128_psk,
	ng::DhKemP256HkdfSha256,
	ng::HkdfSha256,
	ng::Aes128Gcm,
	rs_types::KemAlgorithm::DhKemP256,
	rs_types::KdfAlgorithm::HkdfSha256,
	rs_types::AeadAlgorithm::Aes128Gcm,
	0xEEEE_FFFF
);

// secp256k1: hpke-rs-rust-crypto supports DhKem25519, DhKemP256, and DhKemK256
// only. X448, P-384, and P-521 cannot be differentially tested against this
// backend; their interop coverage relies on the RFC 9180 KAT suite instead.
diff_base_sealing!(
	diff_k256_sha256_chacha20_base,
	ng::DhKemK256HkdfSha256,
	ng::HkdfSha256,
	ng::ChaCha20Poly1305,
	rs_types::KemAlgorithm::DhKemK256,
	rs_types::KdfAlgorithm::HkdfSha256,
	rs_types::AeadAlgorithm::ChaCha20Poly1305,
	0x0BAD_F00D
);
diff_psk_sealing!(
	diff_k256_sha256_chacha20_psk,
	ng::DhKemK256HkdfSha256,
	ng::HkdfSha256,
	ng::ChaCha20Poly1305,
	rs_types::KemAlgorithm::DhKemK256,
	rs_types::KdfAlgorithm::HkdfSha256,
	rs_types::AeadAlgorithm::ChaCha20Poly1305,
	0xC0DE_BABE
);
