//! `hpke-ng` — RFC 9180 HPKE implementation.
//!
//! ## Example
//!
//! ```
//! use hpke_ng::*;
//! use rand::rngs::SysRng;
//! use rand_core::UnwrapErr;
//!
//! type Suite = Hpke<DhKemX25519HkdfSha256, HkdfSha256, ChaCha20Poly1305>;
//!
//! let mut os = SysRng;
//! let mut rng = UnwrapErr(&mut os);
//! let (sk_r, pk_r) = DhKemX25519HkdfSha256::generate(&mut rng).unwrap();
//! let (enc, ct) =
//!     Suite::seal_base(&mut rng, &pk_r, b"info", b"aad", b"hello").unwrap();
//! let pt = Suite::open_base(&enc, &sk_r, b"info", b"aad", &ct).unwrap();
//! assert_eq!(pt, b"hello");
//! ```
//!
//! See the [README](https://github.com/symbolicsoft/hpke-ng) for design notes
//! and the constant-time disclosure table.

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code, unstable_features)]
#![deny(
	missing_docs,
	rustdoc::broken_intra_doc_links,
	rustdoc::private_intra_doc_links,
	trivial_casts,
	trivial_numeric_casts,
	unused_must_use,
	unused_import_braces,
	unused_qualifications,
	clippy::pedantic
)]
#![allow(
	clippy::module_name_repetitions,
	clippy::missing_errors_doc,
	clippy::type_complexity,
	unused_extern_crates
)]

extern crate alloc;

mod aead;
mod error;
mod kdf;
mod sealed;

pub mod kem;

pub use aead::{Aead, Aes128Gcm, Aes256Gcm, ChaCha20Poly1305, ExportOnly, SealingAead};
pub use error::HpkeError;
pub use kdf::{HkdfSha256, HkdfSha384, HkdfSha512, Kdf};
pub use kem::{
	AuthKem, Kem,
	dh::{
		DhKemK256HkdfSha256, DhKemP256HkdfSha256, DhKemP384HkdfSha384, DhKemP521HkdfSha512,
		DhKemX448HkdfSha512, DhKemX25519HkdfSha256,
	},
};

#[cfg(feature = "pq")]
pub use kem::pq::{MlKem768, MlKem1024, XWingDraft06};

mod context;

pub use context::{Context, ReceiverContext, SenderContext};

use alloc::vec::Vec;
use core::marker::PhantomData;

use zeroize::Zeroizing;

use crate::kdf::{labeled_expand_pieces, labeled_extract};

/// HPKE configuration parameterized over a KEM, KDF, and AEAD.
///
/// `Hpke` is a zero-sized type. All operations are associated functions; there
/// is no instance state and no PRNG owned by the configuration.
///
/// # Example
///
/// ```no_run
/// use hpke_ng::*;
/// use rand::rngs::SysRng;
/// use rand_core::UnwrapErr;
///
/// type Suite = Hpke<DhKemX25519HkdfSha256, HkdfSha256, ChaCha20Poly1305>;
///
/// let mut os = SysRng;
/// let mut rng = UnwrapErr(&mut os);
/// let (sk_r, pk_r) = DhKemX25519HkdfSha256::generate(&mut rng).unwrap();
/// let (enc, ct) =
///     Suite::seal_base(&mut rng, &pk_r, b"info", b"aad", b"hello").unwrap();
/// let pt = Suite::open_base(&enc, &sk_r, b"info", b"aad", &ct).unwrap();
/// assert_eq!(pt, b"hello");
/// ```
#[derive(Debug, Clone, Copy, Default)]
pub struct Hpke<K: Kem, F: Kdf, A: Aead>(PhantomData<(K, F, A)>);

pub(crate) mod modes {
	pub const BASE: u8 = 0x00;
	pub const PSK: u8 = 0x01;
	pub const AUTH: u8 = 0x02;
	pub const AUTH_PSK: u8 = 0x03;
}

/// Sealed marker supertrait for all four HPKE modes.
/// For internal and test-harness use only; not part of the public API.
#[doc(hidden)]
pub trait HpkeMode: sealed::Sealed {
	/// The RFC 9180 mode byte for this mode.
	#[doc(hidden)]
	const MODE_BYTE: u8;
}

/// Sealed marker trait for PSK-free HPKE modes (Base and Auth).
#[doc(hidden)]
pub trait PskFreeMode: HpkeMode {}

/// Sealed marker trait for PSK-bearing HPKE modes (PSK and AuthPSK).
#[doc(hidden)]
pub trait PskMode: HpkeMode {}

/// Mode tag for the HPKE Base mode (RFC 9180 §5.1.1).
/// For internal and test-harness use only; not part of the public API.
#[doc(hidden)]
pub struct BaseModeTag;

/// Mode tag for the HPKE Auth mode (RFC 9180 §5.1.3).
/// For internal and test-harness use only; not part of the public API.
#[doc(hidden)]
pub struct AuthModeTag;

/// Mode tag for the HPKE PSK mode (RFC 9180 §5.1.2).
/// For internal and test-harness use only; not part of the public API.
#[doc(hidden)]
pub struct PskModeTag;

/// Mode tag for the HPKE AuthPSK mode (RFC 9180 §5.1.4).
/// For internal and test-harness use only; not part of the public API.
#[doc(hidden)]
pub struct AuthPskModeTag;

impl sealed::Sealed for BaseModeTag {}
impl sealed::Sealed for AuthModeTag {}
impl sealed::Sealed for PskModeTag {}
impl sealed::Sealed for AuthPskModeTag {}

impl HpkeMode for BaseModeTag {
	const MODE_BYTE: u8 = modes::BASE;
}
impl HpkeMode for AuthModeTag {
	const MODE_BYTE: u8 = modes::AUTH;
}
impl HpkeMode for PskModeTag {
	const MODE_BYTE: u8 = modes::PSK;
}
impl HpkeMode for AuthPskModeTag {
	const MODE_BYTE: u8 = modes::AUTH_PSK;
}

impl PskFreeMode for BaseModeTag {}
impl PskFreeMode for AuthModeTag {}
impl PskMode for PskModeTag {}
impl PskMode for AuthPskModeTag {}

#[inline]
pub(crate) fn ciphersuite<K: Kem, F: Kdf, A: Aead>() -> [u8; 10] {
	let mut s = [0u8; 10];
	s[..4].copy_from_slice(b"HPKE");
	s[4..6].copy_from_slice(&K::ID.to_be_bytes());
	s[6..8].copy_from_slice(&F::ID.to_be_bytes());
	s[8..10].copy_from_slice(&A::ID.to_be_bytes());
	s
}

#[inline]
fn verify_psk_inputs(mode: u8, psk: &[u8], psk_id: &[u8]) -> Result<(), HpkeError> {
	let got_psk = !psk.is_empty();
	let got_psk_id = !psk_id.is_empty();
	if got_psk != got_psk_id {
		return Err(HpkeError::InconsistentPsk);
	}
	if got_psk && (mode == modes::BASE || mode == modes::AUTH) {
		return Err(HpkeError::UnnecessaryPsk);
	}
	if !got_psk && (mode == modes::PSK || mode == modes::AUTH_PSK) {
		return Err(HpkeError::MissingPsk);
	}
	if got_psk && psk.len() < 32 {
		return Err(HpkeError::InsecurePsk);
	}
	Ok(())
}

/// Key schedule for PSK-free HPKE modes (Base and Auth, RFC 9180 §5.1.1 and §5.1.3).
/// `psk` and `psk_id` are structurally absent: the mode tag `M: PskFreeMode` enforces
/// at compile time that only Base and Auth modes reach this path.
fn key_schedule_psk_free_impl<M: PskFreeMode, K: Kem, F: Kdf, A: Aead>(
	shared_secret: &[u8],
	info: &[u8],
) -> Result<Context<K, F, A>, HpkeError> {
	let suite = ciphersuite::<K, F, A>();
	let psk_id_hash = labeled_extract::<F>(&[], &suite, b"psk_id_hash", &[]);
	let info_hash = labeled_extract::<F>(&[], &suite, b"info_hash", info);

	let mode_arr = [M::MODE_BYTE];
	// `ks_context = mode || psk_id_hash || info_hash`. Fed piecewise into
	// each `expand_multi_info` call instead of allocating a flat `Vec`.
	let ks_pieces: [&[u8]; 3] = [&mode_arr, &psk_id_hash, &info_hash];

	let secret = Zeroizing::new(labeled_extract::<F>(shared_secret, &suite, b"secret", &[]));
	let key = labeled_expand_pieces::<F>(&secret, &suite, b"key", &ks_pieces, A::KEY_LEN)?;
	let base_nonce = Zeroizing::new(labeled_expand_pieces::<F>(
		&secret,
		&suite,
		b"base_nonce",
		&ks_pieces,
		A::NONCE_LEN,
	)?);
	let exporter_secret =
		labeled_expand_pieces::<F>(&secret, &suite, b"exp", &ks_pieces, F::HASH_LEN)?;
	Context::new(key, base_nonce, exporter_secret)
}

// Public-facing wrapper — visibility changes with feature gate.
#[cfg(not(feature = "hazmat-kat-internals"))]
pub(crate) fn key_schedule_psk_free<M: PskFreeMode, K: Kem, F: Kdf, A: Aead>(
	shared_secret: &[u8],
	info: &[u8],
) -> Result<Context<K, F, A>, HpkeError> {
	key_schedule_psk_free_impl::<M, K, F, A>(shared_secret, info)
}

#[cfg(feature = "hazmat-kat-internals")]
#[doc(hidden)]
pub fn key_schedule_psk_free<M: PskFreeMode, K: Kem, F: Kdf, A: Aead>(
	shared_secret: &[u8],
	info: &[u8],
) -> Result<Context<K, F, A>, HpkeError> {
	key_schedule_psk_free_impl::<M, K, F, A>(shared_secret, info)
}

/// Key schedule for PSK-bearing HPKE modes (PSK and `AuthPSK`, RFC 9180 §5.1.2 and §5.1.4).
/// Validates that `psk` and `psk_id` are consistent and well-formed before deriving
/// the context. The mode tag `M: PskMode` enforces at compile time that only PSK
/// and `AuthPSK` modes reach this path.
fn key_schedule_psk_impl<M: PskMode, K: Kem, F: Kdf, A: Aead>(
	shared_secret: &[u8],
	info: &[u8],
	psk: &[u8],
	psk_id: &[u8],
) -> Result<Context<K, F, A>, HpkeError> {
	verify_psk_inputs(M::MODE_BYTE, psk, psk_id)?;
	let suite = ciphersuite::<K, F, A>();
	let psk_id_hash = labeled_extract::<F>(&[], &suite, b"psk_id_hash", psk_id);
	let info_hash = labeled_extract::<F>(&[], &suite, b"info_hash", info);

	let mode_arr = [M::MODE_BYTE];
	// `ks_context = mode || psk_id_hash || info_hash`. Fed piecewise into
	// each `expand_multi_info` call instead of allocating a flat `Vec`.
	let ks_pieces: [&[u8]; 3] = [&mode_arr, &psk_id_hash, &info_hash];

	let secret = Zeroizing::new(labeled_extract::<F>(shared_secret, &suite, b"secret", psk));
	let key = labeled_expand_pieces::<F>(&secret, &suite, b"key", &ks_pieces, A::KEY_LEN)?;
	let base_nonce = Zeroizing::new(labeled_expand_pieces::<F>(
		&secret,
		&suite,
		b"base_nonce",
		&ks_pieces,
		A::NONCE_LEN,
	)?);
	let exporter_secret =
		labeled_expand_pieces::<F>(&secret, &suite, b"exp", &ks_pieces, F::HASH_LEN)?;

	Context::new(key, base_nonce, exporter_secret)
}

// Public-facing wrapper — visibility changes with feature gate.
#[cfg(not(feature = "hazmat-kat-internals"))]
pub(crate) fn key_schedule_psk<M: PskMode, K: Kem, F: Kdf, A: Aead>(
	shared_secret: &[u8],
	info: &[u8],
	psk: &[u8],
	psk_id: &[u8],
) -> Result<Context<K, F, A>, HpkeError> {
	key_schedule_psk_impl::<M, K, F, A>(shared_secret, info, psk, psk_id)
}

#[cfg(feature = "hazmat-kat-internals")]
#[doc(hidden)]
pub fn key_schedule_psk<M: PskMode, K: Kem, F: Kdf, A: Aead>(
	shared_secret: &[u8],
	info: &[u8],
	psk: &[u8],
	psk_id: &[u8],
) -> Result<Context<K, F, A>, HpkeError> {
	key_schedule_psk_impl::<M, K, F, A>(shared_secret, info, psk, psk_id)
}

#[cfg(test)]
mod ks_tests {
	use super::*;

	#[test]
	fn psk_validation_matrix() {
		use HpkeError::*;
		let cases: &[(u8, &[u8], &[u8], Result<(), HpkeError>)] = &[
			(modes::PSK, b"", b"some_id", Err(InconsistentPsk)),
			(modes::PSK, &[0u8; 32], b"", Err(InconsistentPsk)),
			(modes::PSK, b"", b"", Err(MissingPsk)),
			(modes::BASE, &[0u8; 32], b"id", Err(UnnecessaryPsk)),
			(modes::PSK, b"too short", b"id", Err(InsecurePsk)),
			(modes::BASE, b"", b"", Ok(())),
			(modes::PSK, &[0u8; 32], b"id", Ok(())),
		];
		for (mode, psk, psk_id, expected) in cases {
			assert_eq!(verify_psk_inputs(*mode, psk, psk_id), *expected);
		}
	}
}

use rand_core::CryptoRng;

impl<K: Kem, F: Kdf, A: Aead> Hpke<K, F, A> {
	/// `SetupBaseS` (RFC 9180 §5.1.1).
	pub fn setup_sender_base<R: CryptoRng>(
		rng: &mut R,
		pk_r: &K::PublicKey,
		info: &[u8],
	) -> Result<(K::EncappedKey, SenderContext<K, F, A>), HpkeError> {
		let (ss, enc) = K::encap(rng, pk_r)?;
		let ctx = key_schedule_psk_free::<BaseModeTag, K, F, A>(ss.as_ref(), info)?;
		Ok((enc, SenderContext::new(ctx)))
	}

	/// `SetupBaseR` (RFC 9180 §5.1.1).
	pub fn setup_receiver_base(
		enc: &K::EncappedKey,
		sk_r: &K::PrivateKey,
		info: &[u8],
	) -> Result<ReceiverContext<K, F, A>, HpkeError> {
		let ss = K::decap(enc, sk_r)?;
		key_schedule_psk_free::<BaseModeTag, K, F, A>(ss.as_ref(), info).map(ReceiverContext::new)
	}

	/// `SetupPSKS` (RFC 9180 §5.1.2).
	///
	/// `psk` MUST be at least 32 bytes of high-entropy random data. Length is
	/// enforced; entropy is the caller's responsibility — see
	/// [`HpkeError::InsecurePsk`].
	pub fn setup_sender_psk<R: CryptoRng>(
		rng: &mut R,
		pk_r: &K::PublicKey,
		info: &[u8],
		psk: &[u8],
		psk_id: &[u8],
	) -> Result<(K::EncappedKey, SenderContext<K, F, A>), HpkeError> {
		let (ss, enc) = K::encap(rng, pk_r)?;
		let ctx = key_schedule_psk::<PskModeTag, K, F, A>(ss.as_ref(), info, psk, psk_id)?;
		Ok((enc, SenderContext::new(ctx)))
	}

	/// `SetupPSKR` (RFC 9180 §5.1.2).
	///
	/// `psk` MUST be at least 32 bytes of high-entropy random data. Length is
	/// enforced; entropy is the caller's responsibility — see
	/// [`HpkeError::InsecurePsk`].
	pub fn setup_receiver_psk(
		enc: &K::EncappedKey,
		sk_r: &K::PrivateKey,
		info: &[u8],
		psk: &[u8],
		psk_id: &[u8],
	) -> Result<ReceiverContext<K, F, A>, HpkeError> {
		let ss = K::decap(enc, sk_r)?;
		key_schedule_psk::<PskModeTag, K, F, A>(ss.as_ref(), info, psk, psk_id)
			.map(ReceiverContext::new)
	}
}

impl<K: Kem, F: Kdf, A: SealingAead> Hpke<K, F, A> {
	/// Single-shot Base-mode encrypt (RFC 9180 §6.1).
	pub fn seal_base<R: CryptoRng>(
		rng: &mut R,
		pk_r: &K::PublicKey,
		info: &[u8],
		aad: &[u8],
		pt: &[u8],
	) -> Result<(K::EncappedKey, Vec<u8>), HpkeError> {
		let (enc, mut ctx) = Self::setup_sender_base(rng, pk_r, info)?;
		let ct = ctx.seal(aad, pt)?;
		Ok((enc, ct))
	}

	/// Single-shot Base-mode decrypt (RFC 9180 §6.1).
	pub fn open_base(
		enc: &K::EncappedKey,
		sk_r: &K::PrivateKey,
		info: &[u8],
		aad: &[u8],
		ct: &[u8],
	) -> Result<Vec<u8>, HpkeError> {
		let mut ctx = Self::setup_receiver_base(enc, sk_r, info)?;
		ctx.open(aad, ct)
	}

	/// Single-shot Psk-mode encrypt (RFC 9180 §6.1).
	#[allow(clippy::too_many_arguments)]
	pub fn seal_psk<R: CryptoRng>(
		rng: &mut R,
		pk_r: &K::PublicKey,
		info: &[u8],
		aad: &[u8],
		pt: &[u8],
		psk: &[u8],
		psk_id: &[u8],
	) -> Result<(K::EncappedKey, Vec<u8>), HpkeError> {
		let (enc, mut ctx) = Self::setup_sender_psk(rng, pk_r, info, psk, psk_id)?;
		let ct = ctx.seal(aad, pt)?;
		Ok((enc, ct))
	}

	/// Single-shot Psk-mode decrypt (RFC 9180 §6.1).
	#[allow(clippy::too_many_arguments)]
	pub fn open_psk(
		enc: &K::EncappedKey,
		sk_r: &K::PrivateKey,
		info: &[u8],
		aad: &[u8],
		ct: &[u8],
		psk: &[u8],
		psk_id: &[u8],
	) -> Result<Vec<u8>, HpkeError> {
		let mut ctx = Self::setup_receiver_psk(enc, sk_r, info, psk, psk_id)?;
		ctx.open(aad, ct)
	}
}

impl<K: AuthKem, F: Kdf, A: SealingAead> Hpke<K, F, A> {
	/// Single-shot Auth-mode encrypt (RFC 9180 §6.1).
	pub fn seal_auth<R: CryptoRng>(
		rng: &mut R,
		pk_r: &K::PublicKey,
		info: &[u8],
		aad: &[u8],
		pt: &[u8],
		sk_s: &K::PrivateKey,
	) -> Result<(K::EncappedKey, Vec<u8>), HpkeError> {
		let (enc, mut ctx) = Self::setup_sender_auth(rng, pk_r, info, sk_s)?;
		let ct = ctx.seal(aad, pt)?;
		Ok((enc, ct))
	}

	/// Single-shot Auth-mode decrypt (RFC 9180 §6.1).
	pub fn open_auth(
		enc: &K::EncappedKey,
		sk_r: &K::PrivateKey,
		info: &[u8],
		aad: &[u8],
		ct: &[u8],
		pk_s: &K::PublicKey,
	) -> Result<Vec<u8>, HpkeError> {
		let mut ctx = Self::setup_receiver_auth(enc, sk_r, info, pk_s)?;
		ctx.open(aad, ct)
	}

	/// Single-shot AuthPsk-mode encrypt (RFC 9180 §6.1).
	#[allow(clippy::too_many_arguments)]
	pub fn seal_auth_psk<R: CryptoRng>(
		rng: &mut R,
		pk_r: &K::PublicKey,
		info: &[u8],
		aad: &[u8],
		pt: &[u8],
		psk: &[u8],
		psk_id: &[u8],
		sk_s: &K::PrivateKey,
	) -> Result<(K::EncappedKey, Vec<u8>), HpkeError> {
		let (enc, mut ctx) = Self::setup_sender_auth_psk(rng, pk_r, info, psk, psk_id, sk_s)?;
		let ct = ctx.seal(aad, pt)?;
		Ok((enc, ct))
	}

	/// Single-shot AuthPsk-mode decrypt (RFC 9180 §6.1).
	#[allow(clippy::too_many_arguments)]
	pub fn open_auth_psk(
		enc: &K::EncappedKey,
		sk_r: &K::PrivateKey,
		info: &[u8],
		aad: &[u8],
		ct: &[u8],
		psk: &[u8],
		psk_id: &[u8],
		pk_s: &K::PublicKey,
	) -> Result<Vec<u8>, HpkeError> {
		let mut ctx = Self::setup_receiver_auth_psk(enc, sk_r, info, psk, psk_id, pk_s)?;
		ctx.open(aad, ct)
	}
}

impl<K: Kem, F: Kdf, A: Aead> Hpke<K, F, A> {
	/// Sender-side single-shot export — Base mode (RFC 9180 §6.2).
	pub fn send_export_base<R: CryptoRng>(
		rng: &mut R,
		pk_r: &K::PublicKey,
		info: &[u8],
		exporter_context: &[u8],
		length: usize,
	) -> Result<(K::EncappedKey, Vec<u8>), HpkeError> {
		let (enc, ctx) = Self::setup_sender_base(rng, pk_r, info)?;
		Ok((enc, ctx.export(exporter_context, length)?))
	}

	/// Receiver-side single-shot export — Base mode.
	pub fn receiver_export_base(
		enc: &K::EncappedKey,
		sk_r: &K::PrivateKey,
		info: &[u8],
		exporter_context: &[u8],
		length: usize,
	) -> Result<Vec<u8>, HpkeError> {
		let ctx = Self::setup_receiver_base(enc, sk_r, info)?;
		ctx.export(exporter_context, length)
	}

	/// Sender-side single-shot export — Psk mode.
	#[allow(clippy::too_many_arguments)]
	pub fn send_export_psk<R: CryptoRng>(
		rng: &mut R,
		pk_r: &K::PublicKey,
		info: &[u8],
		psk: &[u8],
		psk_id: &[u8],
		exporter_context: &[u8],
		length: usize,
	) -> Result<(K::EncappedKey, Vec<u8>), HpkeError> {
		let (enc, ctx) = Self::setup_sender_psk(rng, pk_r, info, psk, psk_id)?;
		Ok((enc, ctx.export(exporter_context, length)?))
	}

	/// Receiver-side single-shot export — Psk mode.
	#[allow(clippy::too_many_arguments)]
	pub fn receiver_export_psk(
		enc: &K::EncappedKey,
		sk_r: &K::PrivateKey,
		info: &[u8],
		psk: &[u8],
		psk_id: &[u8],
		exporter_context: &[u8],
		length: usize,
	) -> Result<Vec<u8>, HpkeError> {
		let ctx = Self::setup_receiver_psk(enc, sk_r, info, psk, psk_id)?;
		ctx.export(exporter_context, length)
	}
}

impl<K: AuthKem, F: Kdf, A: Aead> Hpke<K, F, A> {
	/// Sender-side single-shot export — Auth mode.
	pub fn send_export_auth<R: CryptoRng>(
		rng: &mut R,
		pk_r: &K::PublicKey,
		info: &[u8],
		sk_s: &K::PrivateKey,
		exporter_context: &[u8],
		length: usize,
	) -> Result<(K::EncappedKey, Vec<u8>), HpkeError> {
		let (enc, ctx) = Self::setup_sender_auth(rng, pk_r, info, sk_s)?;
		Ok((enc, ctx.export(exporter_context, length)?))
	}

	/// Receiver-side single-shot export — Auth mode.
	pub fn receiver_export_auth(
		enc: &K::EncappedKey,
		sk_r: &K::PrivateKey,
		info: &[u8],
		pk_s: &K::PublicKey,
		exporter_context: &[u8],
		length: usize,
	) -> Result<Vec<u8>, HpkeError> {
		let ctx = Self::setup_receiver_auth(enc, sk_r, info, pk_s)?;
		ctx.export(exporter_context, length)
	}

	/// Sender-side single-shot export — `AuthPsk` mode.
	#[allow(clippy::too_many_arguments)]
	pub fn send_export_auth_psk<R: CryptoRng>(
		rng: &mut R,
		pk_r: &K::PublicKey,
		info: &[u8],
		psk: &[u8],
		psk_id: &[u8],
		sk_s: &K::PrivateKey,
		exporter_context: &[u8],
		length: usize,
	) -> Result<(K::EncappedKey, Vec<u8>), HpkeError> {
		let (enc, ctx) = Self::setup_sender_auth_psk(rng, pk_r, info, psk, psk_id, sk_s)?;
		Ok((enc, ctx.export(exporter_context, length)?))
	}

	/// Receiver-side single-shot export — `AuthPsk` mode.
	#[allow(clippy::too_many_arguments)]
	pub fn receiver_export_auth_psk(
		enc: &K::EncappedKey,
		sk_r: &K::PrivateKey,
		info: &[u8],
		psk: &[u8],
		psk_id: &[u8],
		pk_s: &K::PublicKey,
		exporter_context: &[u8],
		length: usize,
	) -> Result<Vec<u8>, HpkeError> {
		let ctx = Self::setup_receiver_auth_psk(enc, sk_r, info, psk, psk_id, pk_s)?;
		ctx.export(exporter_context, length)
	}
}

impl<K: AuthKem, F: Kdf, A: Aead> Hpke<K, F, A> {
	/// `SetupAuthS` (RFC 9180 §5.1.3).
	pub fn setup_sender_auth<R: CryptoRng>(
		rng: &mut R,
		pk_r: &K::PublicKey,
		info: &[u8],
		sk_s: &K::PrivateKey,
	) -> Result<(K::EncappedKey, SenderContext<K, F, A>), HpkeError> {
		let (ss, enc) = K::auth_encap(rng, pk_r, sk_s)?;
		let ctx = key_schedule_psk_free::<AuthModeTag, K, F, A>(ss.as_ref(), info)?;
		Ok((enc, SenderContext::new(ctx)))
	}

	/// `SetupAuthR` (RFC 9180 §5.1.3).
	pub fn setup_receiver_auth(
		enc: &K::EncappedKey,
		sk_r: &K::PrivateKey,
		info: &[u8],
		pk_s: &K::PublicKey,
	) -> Result<ReceiverContext<K, F, A>, HpkeError> {
		let ss = K::auth_decap(enc, sk_r, pk_s)?;
		key_schedule_psk_free::<AuthModeTag, K, F, A>(ss.as_ref(), info).map(ReceiverContext::new)
	}

	/// `SetupAuthPSKS` (RFC 9180 §5.1.4).
	///
	/// `psk` MUST be at least 32 bytes of high-entropy random data. Length is
	/// enforced; entropy is the caller's responsibility — see
	/// [`HpkeError::InsecurePsk`].
	pub fn setup_sender_auth_psk<R: CryptoRng>(
		rng: &mut R,
		pk_r: &K::PublicKey,
		info: &[u8],
		psk: &[u8],
		psk_id: &[u8],
		sk_s: &K::PrivateKey,
	) -> Result<(K::EncappedKey, SenderContext<K, F, A>), HpkeError> {
		let (ss, enc) = K::auth_encap(rng, pk_r, sk_s)?;
		let ctx = key_schedule_psk::<AuthPskModeTag, K, F, A>(ss.as_ref(), info, psk, psk_id)?;
		Ok((enc, SenderContext::new(ctx)))
	}

	/// `SetupAuthPSKR` (RFC 9180 §5.1.4).
	///
	/// `psk` MUST be at least 32 bytes of high-entropy random data. Length is
	/// enforced; entropy is the caller's responsibility — see
	/// [`HpkeError::InsecurePsk`].
	pub fn setup_receiver_auth_psk(
		enc: &K::EncappedKey,
		sk_r: &K::PrivateKey,
		info: &[u8],
		psk: &[u8],
		psk_id: &[u8],
		pk_s: &K::PublicKey,
	) -> Result<ReceiverContext<K, F, A>, HpkeError> {
		let ss = K::auth_decap(enc, sk_r, pk_s)?;
		key_schedule_psk::<AuthPskModeTag, K, F, A>(ss.as_ref(), info, psk, psk_id)
			.map(ReceiverContext::new)
	}
}

#[cfg(feature = "hazmat-kat-internals")]
#[doc(hidden)]
pub mod __test_only {
	pub use crate::key_schedule_psk;
	pub use crate::key_schedule_psk_free;
	pub use crate::{AuthModeTag, AuthPskModeTag, BaseModeTag, PskModeTag};
}

#[cfg(test)]
mod hpke_tests {
	use super::*;
	use rand::rngs::SysRng;
	use rand_core::UnwrapErr;

	/// Type-level check: `ExportOnly` suites compile without a `SealingAead`
	/// bound, exposing only `*_export_*` methods. The full setup/seal/open
	/// matrix lives in `tests/roundtrip.rs`.
	#[test]
	fn export_only_suite_compiles() {
		type ExportSuite = Hpke<DhKemX25519HkdfSha256, HkdfSha256, ExportOnly>;
		let mut os_rng = SysRng;
		let mut rng = UnwrapErr(&mut os_rng);
		let (sk_r, pk_r) = DhKemX25519HkdfSha256::generate(&mut rng).unwrap();
		let (enc, sec) =
			ExportSuite::send_export_base(&mut rng, &pk_r, b"info", b"ctx", 32).unwrap();
		let recv = ExportSuite::receiver_export_base(&enc, &sk_r, b"info", b"ctx", 32).unwrap();
		assert_eq!(sec, recv);
	}
}
