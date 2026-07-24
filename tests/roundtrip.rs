//! Generative roundtrip matrix.
//!
//! For each (mode, kem, kdf, aead), generate fresh random keys, do single-shot
//! seal/open, run a Context pair through 3 sequential operations, and verify
//! export-sender/receiver agreement at multiple lengths.

#![allow(non_snake_case)]

use hpke_ng::*;
use rand::rngs::SysRng as OsRng;
use rand_core::UnwrapErr;

macro_rules! roundtrip_base_sealing {
	($name:ident, $kem:ty, $kdf:ty, $aead:ty) => {
		#[test]
		fn $name() {
			type Suite = Hpke<$kem, $kdf, $aead>;
			let mut os_rng = OsRng;
			let mut rng = UnwrapErr(&mut os_rng);
			let (sk_r, pk_r) = <$kem as Kem>::generate(&mut rng).unwrap();

			let (enc, ct) = Suite::seal_base(&mut rng, &pk_r, b"info", b"aad", b"hello").unwrap();
			assert_eq!(
				Suite::open_base(&enc, &sk_r, b"info", b"aad", &ct).unwrap(),
				b"hello",
			);

			let (enc2, mut s) = Suite::setup_sender_base(&mut rng, &pk_r, b"info").unwrap();
			let mut r = Suite::setup_receiver_base(&enc2, &sk_r, b"info").unwrap();
			for i in 0..3 {
				let pt = format!("msg-{i}");
				let ct = s.seal(b"aad", pt.as_bytes()).unwrap();
				assert_eq!(r.open(b"aad", &ct).unwrap(), pt.as_bytes());
			}

			let (enc3, send_secret) =
				Suite::send_export_base(&mut rng, &pk_r, b"info", b"ctx-A", 32).unwrap();
			let recv_secret =
				Suite::receiver_export_base(&enc3, &sk_r, b"info", b"ctx-A", 32).unwrap();
			assert_eq!(send_secret, recv_secret);
		}
	};
}

macro_rules! roundtrip_psk_sealing {
	($name:ident, $kem:ty, $kdf:ty, $aead:ty) => {
		#[test]
		fn $name() {
			type Suite = Hpke<$kem, $kdf, $aead>;
			let mut os_rng = OsRng;
			let mut rng = UnwrapErr(&mut os_rng);
			let (sk_r, pk_r) = <$kem as Kem>::generate(&mut rng).unwrap();
			let psk = [0xCDu8; 32];
			let (enc, ct) =
				Suite::seal_psk(&mut rng, &pk_r, b"i", b"a", b"hi", &psk, b"id").unwrap();
			assert_eq!(
				Suite::open_psk(&enc, &sk_r, b"i", b"a", &ct, &psk, b"id").unwrap(),
				b"hi",
			);

			let too_short = [0u8; 16];
			assert_eq!(
				Suite::seal_psk(&mut rng, &pk_r, b"i", b"a", b"hi", &too_short, b"id").unwrap_err(),
				HpkeError::InsecurePsk,
			);
		}
	};
}

macro_rules! roundtrip_auth_sealing {
	($name:ident, $kem:ty, $kdf:ty, $aead:ty) => {
		#[test]
		fn $name() {
			type Suite = Hpke<$kem, $kdf, $aead>;
			let mut os_rng = OsRng;
			let mut rng = UnwrapErr(&mut os_rng);
			let (sk_r, pk_r) = <$kem as Kem>::generate(&mut rng).unwrap();
			let (sk_s, pk_s) = <$kem as Kem>::generate(&mut rng).unwrap();
			let (enc, ct) = Suite::seal_auth(&mut rng, &pk_r, b"i", b"a", b"hi", &sk_s).unwrap();
			assert_eq!(
				Suite::open_auth(&enc, &sk_r, b"i", b"a", &ct, &pk_s).unwrap(),
				b"hi",
			);
		}
	};
}

macro_rules! roundtrip_auth_psk_sealing {
	($name:ident, $kem:ty, $kdf:ty, $aead:ty) => {
		#[test]
		fn $name() {
			type Suite = Hpke<$kem, $kdf, $aead>;
			let mut os_rng = OsRng;
			let mut rng = UnwrapErr(&mut os_rng);
			let (sk_r, pk_r) = <$kem as Kem>::generate(&mut rng).unwrap();
			let (sk_s, pk_s) = <$kem as Kem>::generate(&mut rng).unwrap();
			let psk = [0xEFu8; 32];
			let (enc, ct) =
				Suite::seal_auth_psk(&mut rng, &pk_r, b"i", b"a", b"hi", &psk, b"id", &sk_s)
					.unwrap();
			assert_eq!(
				Suite::open_auth_psk(&enc, &sk_r, b"i", b"a", &ct, &psk, b"id", &pk_s).unwrap(),
				b"hi",
			);
		}
	};
}

// X25519 × HKDF-SHA256 × {ChaCha20, AES-128, AES-256}, all 4 modes for ChaCha20.
roundtrip_base_sealing!(
	rt_x25519_sha256_chacha20_base,
	DhKemX25519HkdfSha256,
	HkdfSha256,
	ChaCha20Poly1305
);
roundtrip_psk_sealing!(
	rt_x25519_sha256_chacha20_psk,
	DhKemX25519HkdfSha256,
	HkdfSha256,
	ChaCha20Poly1305
);
roundtrip_auth_sealing!(
	rt_x25519_sha256_chacha20_auth,
	DhKemX25519HkdfSha256,
	HkdfSha256,
	ChaCha20Poly1305
);
roundtrip_auth_psk_sealing!(
	rt_x25519_sha256_chacha20_auth_psk,
	DhKemX25519HkdfSha256,
	HkdfSha256,
	ChaCha20Poly1305
);

roundtrip_base_sealing!(
	rt_x25519_sha256_aes128_base,
	DhKemX25519HkdfSha256,
	HkdfSha256,
	Aes128Gcm
);
roundtrip_base_sealing!(
	rt_x25519_sha256_aes256_base,
	DhKemX25519HkdfSha256,
	HkdfSha256,
	Aes256Gcm
);

// P-256 × SHA-256 × all AEADs × Base/Auth.
roundtrip_base_sealing!(
	rt_p256_sha256_aes128_base,
	DhKemP256HkdfSha256,
	HkdfSha256,
	Aes128Gcm
);
roundtrip_auth_sealing!(
	rt_p256_sha256_aes128_auth,
	DhKemP256HkdfSha256,
	HkdfSha256,
	Aes128Gcm
);

// P-384, P-521, K256, X448.
roundtrip_base_sealing!(
	rt_p384_sha384_aes256_base,
	DhKemP384HkdfSha384,
	HkdfSha384,
	Aes256Gcm
);
roundtrip_base_sealing!(
	rt_p521_sha512_aes256_base,
	DhKemP521HkdfSha512,
	HkdfSha512,
	Aes256Gcm
);
roundtrip_base_sealing!(
	rt_k256_sha256_chacha20_base,
	DhKemK256HkdfSha256,
	HkdfSha256,
	ChaCha20Poly1305
);
roundtrip_base_sealing!(
	rt_x448_sha512_chacha20_base,
	DhKemX448HkdfSha512,
	HkdfSha512,
	ChaCha20Poly1305
);

// PQ KEMs (Base + Psk only — no auth for PQ).
#[cfg(feature = "pq")]
mod pq {
	use super::*;
	roundtrip_base_sealing!(
		rt_xwing_sha256_chacha20_base,
		XWingDraft06,
		HkdfSha256,
		ChaCha20Poly1305
	);
	roundtrip_base_sealing!(
		rt_mlkem768_sha256_chacha20_base,
		MlKem768,
		HkdfSha256,
		ChaCha20Poly1305
	);
	roundtrip_base_sealing!(
		rt_mlkem1024_sha256_chacha20_base,
		MlKem1024,
		HkdfSha256,
		ChaCha20Poly1305
	);
}

// PSK error-path coverage on a single suite (representative).
#[test]
fn psk_inconsistent_rejected() {
	type Suite = Hpke<DhKemX25519HkdfSha256, HkdfSha256, ChaCha20Poly1305>;
	let mut os_rng = OsRng;
	let mut rng = UnwrapErr(&mut os_rng);
	let (_sk_r, pk_r) = DhKemX25519HkdfSha256::generate(&mut rng).unwrap();
	assert_eq!(
		Suite::seal_psk(&mut rng, &pk_r, b"i", b"a", b"x", &[0u8; 32], b"").unwrap_err(),
		HpkeError::InconsistentPsk,
	);
}

#[test]
fn psk_missing_in_psk_mode_rejected() {
	type Suite = Hpke<DhKemX25519HkdfSha256, HkdfSha256, ChaCha20Poly1305>;
	let mut os_rng = OsRng;
	let mut rng = UnwrapErr(&mut os_rng);
	let (_, pk_r) = DhKemX25519HkdfSha256::generate(&mut rng).unwrap();
	assert_eq!(
		Suite::seal_psk(&mut rng, &pk_r, b"i", b"a", b"x", b"", b"").unwrap_err(),
		HpkeError::MissingPsk,
	);
}

// ---------------------------------------------------------------------------
// Extended mode coverage for non-X25519/P-256 DH KEMs.
// Each KEM × its canonical KDF/AEAD × {Psk, Auth, AuthPsk}.
// ---------------------------------------------------------------------------

// X448 × HKDF-SHA512 × ChaCha20.
roundtrip_psk_sealing!(
	rt_x448_sha512_chacha20_psk,
	DhKemX448HkdfSha512,
	HkdfSha512,
	ChaCha20Poly1305
);
roundtrip_auth_sealing!(
	rt_x448_sha512_chacha20_auth,
	DhKemX448HkdfSha512,
	HkdfSha512,
	ChaCha20Poly1305
);
roundtrip_auth_psk_sealing!(
	rt_x448_sha512_chacha20_auth_psk,
	DhKemX448HkdfSha512,
	HkdfSha512,
	ChaCha20Poly1305
);

// P-384 × HKDF-SHA384 × AES-256.
roundtrip_psk_sealing!(
	rt_p384_sha384_aes256_psk,
	DhKemP384HkdfSha384,
	HkdfSha384,
	Aes256Gcm
);
roundtrip_auth_sealing!(
	rt_p384_sha384_aes256_auth,
	DhKemP384HkdfSha384,
	HkdfSha384,
	Aes256Gcm
);
roundtrip_auth_psk_sealing!(
	rt_p384_sha384_aes256_auth_psk,
	DhKemP384HkdfSha384,
	HkdfSha384,
	Aes256Gcm
);

// P-521 × HKDF-SHA512 × AES-256.
roundtrip_psk_sealing!(
	rt_p521_sha512_aes256_psk,
	DhKemP521HkdfSha512,
	HkdfSha512,
	Aes256Gcm
);
roundtrip_auth_sealing!(
	rt_p521_sha512_aes256_auth,
	DhKemP521HkdfSha512,
	HkdfSha512,
	Aes256Gcm
);
roundtrip_auth_psk_sealing!(
	rt_p521_sha512_aes256_auth_psk,
	DhKemP521HkdfSha512,
	HkdfSha512,
	Aes256Gcm
);

// P-256 × HKDF-SHA256 × AES-128 — fill in the missing Psk and AuthPsk modes
// (Base and Auth are already covered above).
roundtrip_psk_sealing!(
	rt_p256_sha256_aes128_psk,
	DhKemP256HkdfSha256,
	HkdfSha256,
	Aes128Gcm
);
roundtrip_auth_psk_sealing!(
	rt_p256_sha256_aes128_auth_psk,
	DhKemP256HkdfSha256,
	HkdfSha256,
	Aes128Gcm
);

// secp256k1 × HKDF-SHA256 × ChaCha20.
roundtrip_psk_sealing!(
	rt_k256_sha256_chacha20_psk,
	DhKemK256HkdfSha256,
	HkdfSha256,
	ChaCha20Poly1305
);
roundtrip_auth_sealing!(
	rt_k256_sha256_chacha20_auth,
	DhKemK256HkdfSha256,
	HkdfSha256,
	ChaCha20Poly1305
);
roundtrip_auth_psk_sealing!(
	rt_k256_sha256_chacha20_auth_psk,
	DhKemK256HkdfSha256,
	HkdfSha256,
	ChaCha20Poly1305
);

// ---------------------------------------------------------------------------
// Cross-KDF coverage: pair a KEM with a non-canonical outer KDF. The KEM's
// internal labelled-KDF (used in `derive_key_pair` and `dh`) is fixed by the
// KEM type; only the HPKE key-schedule KDF (`F`) varies here.
// ---------------------------------------------------------------------------

roundtrip_base_sealing!(
	rt_x25519_sha384_chacha20_base,
	DhKemX25519HkdfSha256,
	HkdfSha384,
	ChaCha20Poly1305
);
roundtrip_base_sealing!(
	rt_x25519_sha512_chacha20_base,
	DhKemX25519HkdfSha256,
	HkdfSha512,
	ChaCha20Poly1305
);
roundtrip_base_sealing!(
	rt_p256_sha512_chacha20_base,
	DhKemP256HkdfSha256,
	HkdfSha512,
	ChaCha20Poly1305
);

// ---------------------------------------------------------------------------
// Extended PQ coverage: Psk mode, AES AEADs, and non-SHA256 outer KDFs.
// (Auth modes are not available for PQ KEMs at the type level.)
// ---------------------------------------------------------------------------

#[cfg(feature = "pq")]
mod pq_ext {
	use super::*;

	// PQ × Psk × ChaCha20.
	roundtrip_psk_sealing!(
		rt_xwing_sha256_chacha20_psk,
		XWingDraft06,
		HkdfSha256,
		ChaCha20Poly1305
	);
	roundtrip_psk_sealing!(
		rt_mlkem768_sha256_chacha20_psk,
		MlKem768,
		HkdfSha256,
		ChaCha20Poly1305
	);
	roundtrip_psk_sealing!(
		rt_mlkem1024_sha256_chacha20_psk,
		MlKem1024,
		HkdfSha256,
		ChaCha20Poly1305
	);

	// PQ × AES.
	roundtrip_base_sealing!(
		rt_xwing_sha256_aes128_base,
		XWingDraft06,
		HkdfSha256,
		Aes128Gcm
	);
	roundtrip_base_sealing!(
		rt_mlkem768_sha256_aes128_base,
		MlKem768,
		HkdfSha256,
		Aes128Gcm
	);
	roundtrip_base_sealing!(
		rt_mlkem1024_sha256_aes256_base,
		MlKem1024,
		HkdfSha256,
		Aes256Gcm
	);
	roundtrip_psk_sealing!(
		rt_xwing_sha256_aes256_psk,
		XWingDraft06,
		HkdfSha256,
		Aes256Gcm
	);

	// PQ × non-SHA-256 outer KDF.
	roundtrip_base_sealing!(
		rt_xwing_sha512_chacha20_base,
		XWingDraft06,
		HkdfSha512,
		ChaCha20Poly1305
	);
	roundtrip_base_sealing!(
		rt_mlkem768_sha384_chacha20_base,
		MlKem768,
		HkdfSha384,
		ChaCha20Poly1305
	);
	roundtrip_base_sealing!(
		rt_mlkem1024_sha384_aes128_base,
		MlKem1024,
		HkdfSha384,
		Aes128Gcm
	);
}

// ---------------------------------------------------------------------------
// ExportOnly roundtrips — `seal_*`/`open_*` are uninstantiable for `ExportOnly`
// (compile-time guarantee), so these macros only exercise the `*_export*`
// methods. Sender and receiver derived secrets must agree at multiple lengths.
// ---------------------------------------------------------------------------

macro_rules! roundtrip_export_only_base {
	($name:ident, $kem:ty, $kdf:ty) => {
		#[test]
		fn $name() {
			type Suite = Hpke<$kem, $kdf, ExportOnly>;
			let mut os_rng = OsRng;
			let mut rng = UnwrapErr(&mut os_rng);
			let (sk_r, pk_r) = <$kem as Kem>::generate(&mut rng).unwrap();
			for &len in &[16usize, 32, 64] {
				let (enc, sender) =
					Suite::send_export_base(&mut rng, &pk_r, b"info", b"ctx", len).unwrap();
				let receiver =
					Suite::receiver_export_base(&enc, &sk_r, b"info", b"ctx", len).unwrap();
				assert_eq!(sender, receiver);
				assert_eq!(sender.len(), len);
			}
		}
	};
}

macro_rules! roundtrip_export_only_psk {
	($name:ident, $kem:ty, $kdf:ty) => {
		#[test]
		fn $name() {
			type Suite = Hpke<$kem, $kdf, ExportOnly>;
			let mut os_rng = OsRng;
			let mut rng = UnwrapErr(&mut os_rng);
			let (sk_r, pk_r) = <$kem as Kem>::generate(&mut rng).unwrap();
			let psk = [0xA5u8; 32];
			let (enc, sender) =
				Suite::send_export_psk(&mut rng, &pk_r, b"info", &psk, b"id", b"ctx", 32).unwrap();
			let receiver =
				Suite::receiver_export_psk(&enc, &sk_r, b"info", &psk, b"id", b"ctx", 32).unwrap();
			assert_eq!(sender, receiver);
		}
	};
}

macro_rules! roundtrip_export_only_auth {
	($name:ident, $kem:ty, $kdf:ty) => {
		#[test]
		fn $name() {
			type Suite = Hpke<$kem, $kdf, ExportOnly>;
			let mut os_rng = OsRng;
			let mut rng = UnwrapErr(&mut os_rng);
			let (sk_r, pk_r) = <$kem as Kem>::generate(&mut rng).unwrap();
			let (sk_s, pk_s) = <$kem as Kem>::generate(&mut rng).unwrap();
			let (enc, sender) =
				Suite::send_export_auth(&mut rng, &pk_r, b"info", &sk_s, b"ctx", 32).unwrap();
			let receiver =
				Suite::receiver_export_auth(&enc, &sk_r, b"info", &pk_s, b"ctx", 32).unwrap();
			assert_eq!(sender, receiver);
		}
	};
}

macro_rules! roundtrip_export_only_auth_psk {
	($name:ident, $kem:ty, $kdf:ty) => {
		#[test]
		fn $name() {
			type Suite = Hpke<$kem, $kdf, ExportOnly>;
			let mut os_rng = OsRng;
			let mut rng = UnwrapErr(&mut os_rng);
			let (sk_r, pk_r) = <$kem as Kem>::generate(&mut rng).unwrap();
			let (sk_s, pk_s) = <$kem as Kem>::generate(&mut rng).unwrap();
			let psk = [0xB7u8; 32];
			let (enc, sender) = Suite::send_export_auth_psk(
				&mut rng, &pk_r, b"info", &psk, b"id", &sk_s, b"ctx", 48,
			)
			.unwrap();
			let receiver = Suite::receiver_export_auth_psk(
				&enc, &sk_r, b"info", &psk, b"id", &pk_s, b"ctx", 48,
			)
			.unwrap();
			assert_eq!(sender, receiver);
		}
	};
}

// X25519 — all 4 modes with ExportOnly.
roundtrip_export_only_base!(
	rt_x25519_sha256_export_base,
	DhKemX25519HkdfSha256,
	HkdfSha256
);
roundtrip_export_only_psk!(
	rt_x25519_sha256_export_psk,
	DhKemX25519HkdfSha256,
	HkdfSha256
);
roundtrip_export_only_auth!(
	rt_x25519_sha256_export_auth,
	DhKemX25519HkdfSha256,
	HkdfSha256
);
roundtrip_export_only_auth_psk!(
	rt_x25519_sha256_export_auth_psk,
	DhKemX25519HkdfSha256,
	HkdfSha256
);

// Other DH KEMs × ExportOnly Base.
roundtrip_export_only_base!(rt_p256_sha256_export_base, DhKemP256HkdfSha256, HkdfSha256);
roundtrip_export_only_base!(rt_p384_sha384_export_base, DhKemP384HkdfSha384, HkdfSha384);
roundtrip_export_only_base!(rt_p521_sha512_export_base, DhKemP521HkdfSha512, HkdfSha512);
roundtrip_export_only_base!(rt_x448_sha512_export_base, DhKemX448HkdfSha512, HkdfSha512);
roundtrip_export_only_base!(rt_k256_sha256_export_base, DhKemK256HkdfSha256, HkdfSha256);
// One non-Base mode per non-X25519 DH KEM, rotated across modes.
roundtrip_export_only_psk!(rt_p256_sha256_export_psk, DhKemP256HkdfSha256, HkdfSha256);
roundtrip_export_only_auth!(rt_p384_sha384_export_auth, DhKemP384HkdfSha384, HkdfSha384);
roundtrip_export_only_auth_psk!(
	rt_p521_sha512_export_auth_psk,
	DhKemP521HkdfSha512,
	HkdfSha512
);

#[cfg(feature = "pq")]
mod pq_export {
	use super::*;
	roundtrip_export_only_base!(rt_xwing_sha256_export_base, XWingDraft06, HkdfSha256);
	roundtrip_export_only_psk!(rt_mlkem768_sha256_export_psk, MlKem768, HkdfSha256);
	roundtrip_export_only_base!(rt_mlkem1024_sha256_export_base, MlKem1024, HkdfSha256);
}
