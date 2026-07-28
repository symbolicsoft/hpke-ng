//! Negative matrix: every input the key schedule and the AEAD bind must
//! actually bind, and a failed `open` must not desynchronise the receiver.
//!
//! `roundtrip.rs` proves the happy paths agree, but it would keep passing if
//! the key schedule silently dropped `info` from `ks_context`, if `aad` never
//! reached the AEAD, if `psk_id` were ignored, if `auth_decap` skipped the
//! sender's public key, or if `open` advanced the sequence counter on
//! authentication failure. These tests are what catch that class of bug.

#![allow(non_snake_case)]

use hpke_ng::*;
use rand::rngs::SysRng as OsRng;
use rand_core::UnwrapErr;

/// Flip the low bit of byte `i`.
fn flip(buf: &[u8], i: usize) -> Vec<u8> {
	let mut out = buf.to_vec();
	out[i] ^= 1;
	out
}

// ---------------------------------------------------------------------------
// Base mode: info binding, aad binding, wrong recipient, ciphertext tamper,
// truncation, and encapsulated-key tamper.
// ---------------------------------------------------------------------------

macro_rules! negative_base {
	($name:ident, $kem:ty, $kdf:ty, $aead:ty) => {
		#[test]
		fn $name() {
			type Suite = Hpke<$kem, $kdf, $aead>;
			let mut os_rng = OsRng;
			let mut rng = UnwrapErr(&mut os_rng);
			let (sk_r, pk_r) = <$kem as Kem>::generate(&mut rng).unwrap();
			let (sk_other, _) = <$kem as Kem>::generate(&mut rng).unwrap();

			let (enc, ct) = Suite::seal_base(&mut rng, &pk_r, b"info", b"aad", b"secret").unwrap();

			// Control: the untampered path must work, or the assertions below
			// would pass for the wrong reason.
			assert_eq!(
				Suite::open_base(&enc, &sk_r, b"info", b"aad", &ct).unwrap(),
				b"secret",
			);

			// `info` is bound into the key schedule (RFC 9180 §5.1).
			assert_eq!(
				Suite::open_base(&enc, &sk_r, b"info-x", b"aad", &ct),
				Err(HpkeError::OpenError),
			);

			// `aad` is bound into the AEAD (RFC 9180 §5.2).
			assert_eq!(
				Suite::open_base(&enc, &sk_r, b"info", b"aad-x", &ct),
				Err(HpkeError::OpenError),
			);

			// A different recipient key cannot open the ciphertext.
			assert!(Suite::open_base(&enc, &sk_other, b"info", b"aad", &ct).is_err());

			// Single-bit flips in the ciphertext body and in the tag.
			for i in [0, ct.len() / 2, ct.len() - 1] {
				assert_eq!(
					Suite::open_base(&enc, &sk_r, b"info", b"aad", &flip(&ct, i)),
					Err(HpkeError::OpenError),
					"bit flip at {i} was accepted",
				);
			}

			// Truncation, including down to and below the tag length.
			for trunc in [ct.len() - 1, <$aead>::TAG_LEN, <$aead>::TAG_LEN - 1, 0] {
				assert!(
					Suite::open_base(&enc, &sk_r, b"info", b"aad", &ct[..trunc]).is_err(),
					"truncation to {trunc} bytes was accepted",
				);
			}

			// A tampered encapsulated key must be rejected: either it fails to
			// parse, or decapsulation yields a different shared secret.
			let enc_bytes = enc.as_ref().to_vec();
			for i in [0usize, enc_bytes.len() / 2, enc_bytes.len() - 1] {
				let outcome = <$kem as Kem>::enc_from_bytes(&flip(&enc_bytes, i))
					.and_then(|e| Suite::open_base(&e, &sk_r, b"info", b"aad", &ct));
				assert!(outcome.is_err(), "tampered enc at {i} was accepted");
			}

			// Wrong-length encapsulated keys are rejected by the parser.
			for bad_len in [0, enc_bytes.len() - 1, enc_bytes.len() + 1] {
				let mut bad = enc_bytes.clone();
				bad.resize(bad_len, 0);
				assert_eq!(
					<$kem as Kem>::enc_from_bytes(&bad).err(),
					Some(HpkeError::InvalidEncappedKey),
					"enc of length {bad_len} was accepted",
				);
			}
		}
	};
}

negative_base!(
	neg_x25519_sha256_chacha20_base,
	DhKemX25519HkdfSha256,
	HkdfSha256,
	ChaCha20Poly1305
);
negative_base!(
	neg_x25519_sha256_aes128_base,
	DhKemX25519HkdfSha256,
	HkdfSha256,
	Aes128Gcm
);
negative_base!(
	neg_x448_sha512_chacha20_base,
	DhKemX448HkdfSha512,
	HkdfSha512,
	ChaCha20Poly1305
);
negative_base!(
	neg_p256_sha256_aes128_base,
	DhKemP256HkdfSha256,
	HkdfSha256,
	Aes128Gcm
);
negative_base!(
	neg_p384_sha384_aes256_base,
	DhKemP384HkdfSha384,
	HkdfSha384,
	Aes256Gcm
);
negative_base!(
	neg_p521_sha512_aes256_base,
	DhKemP521HkdfSha512,
	HkdfSha512,
	Aes256Gcm
);
negative_base!(
	neg_k256_sha256_chacha20_base,
	DhKemK256HkdfSha256,
	HkdfSha256,
	ChaCha20Poly1305
);

#[cfg(feature = "pq")]
mod pq_base {
	use super::*;
	negative_base!(
		neg_xwing_sha256_chacha20_base,
		XWingDraft06,
		HkdfSha256,
		ChaCha20Poly1305
	);
	negative_base!(
		neg_mlkem768_sha256_chacha20_base,
		MlKem768,
		HkdfSha256,
		ChaCha20Poly1305
	);
	negative_base!(
		neg_mlkem1024_sha256_aes256_base,
		MlKem1024,
		HkdfSha256,
		Aes256Gcm
	);
}

// ---------------------------------------------------------------------------
// Psk mode: the PSK and its ID are both bound into the key schedule, and
// malformed PSK inputs are rejected before any cryptography happens.
// ---------------------------------------------------------------------------

macro_rules! negative_psk {
	($name:ident, $kem:ty, $kdf:ty, $aead:ty) => {
		#[test]
		fn $name() {
			type Suite = Hpke<$kem, $kdf, $aead>;
			let mut os_rng = OsRng;
			let mut rng = UnwrapErr(&mut os_rng);
			let (sk_r, pk_r) = <$kem as Kem>::generate(&mut rng).unwrap();

			let psk_bytes = [0x11u8; 32];
			let other_bytes = [0x22u8; 32];
			let psk = Psk::new(&psk_bytes, b"id").unwrap();
			let wrong_secret = Psk::new(&other_bytes, b"id").unwrap();
			let wrong_id = Psk::new(&psk_bytes, b"id-x").unwrap();

			let (enc, ct) =
				Suite::seal_psk(&mut rng, &pk_r, b"info", b"aad", b"secret", psk).unwrap();

			assert_eq!(
				Suite::open_psk(&enc, &sk_r, b"info", b"aad", &ct, psk).unwrap(),
				b"secret",
			);

			// The PSK itself is bound (`secret` extraction salt).
			assert_eq!(
				Suite::open_psk(&enc, &sk_r, b"info", b"aad", &ct, wrong_secret),
				Err(HpkeError::OpenError),
			);

			// The PSK *id* is bound too, via `psk_id_hash` in `ks_context`.
			assert_eq!(
				Suite::open_psk(&enc, &sk_r, b"info", b"aad", &ct, wrong_id),
				Err(HpkeError::OpenError),
			);

			// Malformed PSK inputs cannot reach an operation at all: `Psk::new`
			// is the only way to build one, and it rejects them.
			assert_eq!(Psk::new(b"", b""), Err(HpkeError::MissingPsk));
			assert_eq!(Psk::new(&psk_bytes, b""), Err(HpkeError::InconsistentPsk));
			assert_eq!(Psk::new(b"", b"id"), Err(HpkeError::InconsistentPsk));
			assert_eq!(Psk::new(&[0u8; 31], b"id"), Err(HpkeError::InsecurePsk));
		}
	};
}

negative_psk!(
	neg_x25519_sha256_chacha20_psk,
	DhKemX25519HkdfSha256,
	HkdfSha256,
	ChaCha20Poly1305
);
negative_psk!(
	neg_p256_sha256_aes128_psk,
	DhKemP256HkdfSha256,
	HkdfSha256,
	Aes128Gcm
);

#[cfg(feature = "pq")]
mod pq_psk {
	use super::*;
	negative_psk!(
		neg_xwing_sha256_chacha20_psk,
		XWingDraft06,
		HkdfSha256,
		ChaCha20Poly1305
	);
}

// ---------------------------------------------------------------------------
// Auth / AuthPsk modes: the sender's public key is bound into `kem_context`,
// so authenticating against the wrong sender must fail.
// ---------------------------------------------------------------------------

macro_rules! negative_auth {
	($name:ident, $kem:ty, $kdf:ty, $aead:ty) => {
		#[test]
		fn $name() {
			type Suite = Hpke<$kem, $kdf, $aead>;
			let mut os_rng = OsRng;
			let mut rng = UnwrapErr(&mut os_rng);
			let (sk_r, pk_r) = <$kem as Kem>::generate(&mut rng).unwrap();
			let (sk_s, pk_s) = <$kem as Kem>::generate(&mut rng).unwrap();
			let (_, pk_impostor) = <$kem as Kem>::generate(&mut rng).unwrap();

			let (enc, ct) =
				Suite::seal_auth(&mut rng, &pk_r, b"info", b"aad", b"secret", &sk_s).unwrap();

			assert_eq!(
				Suite::open_auth(&enc, &sk_r, b"info", b"aad", &ct, &pk_s).unwrap(),
				b"secret",
			);

			// Authenticating against a different sender must fail: `pk_s` is
			// part of `kem_context` (RFC 9180 §4.1 `AuthDecap`).
			assert!(
				Suite::open_auth(&enc, &sk_r, b"info", b"aad", &ct, &pk_impostor).is_err(),
				"impostor sender key was accepted",
			);

			// A Base-mode receiver must not open an Auth-mode ciphertext: the
			// mode byte is bound into `ks_context`.
			assert!(Suite::open_base(&enc, &sk_r, b"info", b"aad", &ct).is_err());

			// Same for AuthPsk.
			let psk_bytes = [0x33u8; 32];
			let psk = Psk::new(&psk_bytes, b"id").unwrap();
			let (enc, ct) =
				Suite::seal_auth_psk(&mut rng, &pk_r, b"info", b"aad", b"secret", psk, &sk_s)
					.unwrap();
			assert_eq!(
				Suite::open_auth_psk(&enc, &sk_r, b"info", b"aad", &ct, psk, &pk_s).unwrap(),
				b"secret",
			);
			assert!(
				Suite::open_auth_psk(&enc, &sk_r, b"info", b"aad", &ct, psk, &pk_impostor).is_err(),
			);
			// AuthPsk and Auth derive different keys for the same transcript.
			assert!(Suite::open_auth(&enc, &sk_r, b"info", b"aad", &ct, &pk_s).is_err());
		}
	};
}

negative_auth!(
	neg_x25519_sha256_chacha20_auth,
	DhKemX25519HkdfSha256,
	HkdfSha256,
	ChaCha20Poly1305
);
negative_auth!(
	neg_p256_sha256_aes128_auth,
	DhKemP256HkdfSha256,
	HkdfSha256,
	Aes128Gcm
);
negative_auth!(
	neg_x448_sha512_chacha20_auth,
	DhKemX448HkdfSha512,
	HkdfSha512,
	ChaCha20Poly1305
);

// ---------------------------------------------------------------------------
// Sequence-number state machine (RFC 9180 §5.2).
// ---------------------------------------------------------------------------

/// A failed `open` must not advance the receiver's sequence counter, and a
/// message must not open twice. Both properties fall out of `Context::open`
/// returning before the increment on AEAD failure; nothing else asserts it.
#[test]
fn failed_open_preserves_sequence_and_replay_is_rejected() {
	type Suite = Hpke<DhKemX25519HkdfSha256, HkdfSha256, ChaCha20Poly1305>;
	let mut os_rng = OsRng;
	let mut rng = UnwrapErr(&mut os_rng);
	let (sk_r, pk_r) = DhKemX25519HkdfSha256::generate(&mut rng).unwrap();

	let (enc, mut sender) = Suite::setup_sender_base(&mut rng, &pk_r, b"info").unwrap();
	let mut receiver = Suite::setup_receiver_base(&enc, &sk_r, b"info").unwrap();

	let ct0 = sender.seal(b"aad", b"m0").unwrap();
	let ct1 = sender.seal(b"aad", b"m1").unwrap();

	// Out of order: the receiver is at seq 0, so the seq-1 nonce is wrong.
	assert_eq!(receiver.open(b"aad", &ct1), Err(HpkeError::OpenError));
	// The failed open must not have advanced the counter.
	assert_eq!(receiver.open(b"aad", &ct0).unwrap(), b"m0");
	// Replaying the seq-0 message is now rejected (receiver is at seq 1)...
	assert_eq!(receiver.open(b"aad", &ct0), Err(HpkeError::OpenError));
	// ...and that failure likewise left the counter alone.
	assert_eq!(receiver.open(b"aad", &ct1).unwrap(), b"m1");
}

/// A sender context and a receiver context derive the same `(key, base_nonce)`,
/// so ciphertexts must not be interchangeable across a *reused* sender: two
/// seals at the same sequence number would reuse a nonce. `Context` is not
/// `Clone` (enforced in `tests/compile_fail/`), and every `seal` advances the
/// counter, so consecutive seals of identical plaintext must differ.
#[test]
fn consecutive_seals_never_repeat_a_nonce() {
	type Suite = Hpke<DhKemX25519HkdfSha256, HkdfSha256, ChaCha20Poly1305>;
	let mut os_rng = OsRng;
	let mut rng = UnwrapErr(&mut os_rng);
	let (sk_r, pk_r) = DhKemX25519HkdfSha256::generate(&mut rng).unwrap();

	let (enc, mut sender) = Suite::setup_sender_base(&mut rng, &pk_r, b"info").unwrap();
	let a = sender.seal(b"aad", b"same plaintext").unwrap();
	let b = sender.seal(b"aad", b"same plaintext").unwrap();
	assert_ne!(a, b, "identical plaintexts produced identical ciphertexts");

	let mut receiver = Suite::setup_receiver_base(&enc, &sk_r, b"info").unwrap();
	assert_eq!(receiver.open(b"aad", &a).unwrap(), b"same plaintext");
	assert_eq!(receiver.open(b"aad", &b).unwrap(), b"same plaintext");
}

// ---------------------------------------------------------------------------
// Exporter separation (RFC 9180 §5.3).
// ---------------------------------------------------------------------------

/// Exported secrets must be separated by `exporter_context`, by `info`, and by
/// requested length; and a length past `255 * Nh` must be a clean error rather
/// than a truncated secret.
#[test]
fn export_is_separated_by_context_info_and_length() {
	type Suite = Hpke<DhKemX25519HkdfSha256, HkdfSha256, ExportOnly>;
	let mut os_rng = OsRng;
	let mut rng = UnwrapErr(&mut os_rng);
	let (sk_r, pk_r) = DhKemX25519HkdfSha256::generate(&mut rng).unwrap();

	let (enc, base) = Suite::send_export_base(&mut rng, &pk_r, b"info", b"ctx", 32).unwrap();

	let other_ctx = Suite::receiver_export_base(&enc, &sk_r, b"info", b"ctx-x", 32).unwrap();
	assert_ne!(base, other_ctx, "exporter_context is not separated");

	let other_info = Suite::receiver_export_base(&enc, &sk_r, b"info-x", b"ctx", 32).unwrap();
	assert_ne!(base, other_info, "info is not separated");

	// A shorter request is not a prefix of a longer one: RFC 9180 `LabeledExpand`
	// binds `I2OSP(L, 2)` into the info string, so length is domain-separating
	// even though bare HKDF-Expand is prefix-stable.
	let short = Suite::receiver_export_base(&enc, &sk_r, b"info", b"ctx", 16).unwrap();
	assert_ne!(short, base[..16], "requested length is not separated");

	// 255 * Nh is the HKDF-Expand maximum (RFC 5869 §2.3); one more is an error.
	assert!(Suite::receiver_export_base(&enc, &sk_r, b"info", b"ctx", 255 * 32).is_ok());
	assert_eq!(
		Suite::receiver_export_base(&enc, &sk_r, b"info", b"ctx", 255 * 32 + 1),
		Err(HpkeError::ExportLengthExceeded),
	);
}
