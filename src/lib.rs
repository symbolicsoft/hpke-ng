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

// The `hazmat-` features exist for this crate's own KAT / differential
// harnesses. They make internal key-schedule state public: raw AEAD keys and
// exporter secrets become readable, `key_schedule_*` becomes callable with a
// caller-supplied shared secret, and `SenderContext::from_context` lets a
// caller wrap the result. Together those are enough to fork two sender
// contexts off one key schedule and seal twice under the same
// `(key, base_nonce, seq)` — the exact nonce reuse that `Context: !Clone`
// exists to prevent.
//
// Cargo features are unified across the entire dependency graph, so a single
// unrelated crate enabling one of these would silently turn it on for
// everybody. Neither a `--cfg` flag nor an environment variable is unified that
// way, and a dependency's build script cannot set either for *this* crate's
// compilation — so requiring one in addition to the feature means the exposure
// takes a deliberate change to the top-level build.
//
// Two accepted forms, because `trybuild` deliberately strips `RUSTFLAGS` from
// the sub-build it drives (see `trybuild::cargo`), and the compile-fail suite
// has to build the hazmat surface too:
//
//   RUSTFLAGS="--cfg hpke_ng_hazmat"   — preferred; changes invalidate the
//                                        build cache reliably.
//   HPKE_NG_HAZMAT=1                   — for `trybuild` and anything else that
//                                        controls `RUSTFLAGS` itself.
#[cfg(all(
	any(feature = "hazmat-kat-internals", feature = "hazmat-differential"),
	not(hpke_ng_hazmat)
))]
const _HAZMAT_REQUIRES_EXPLICIT_OPT_IN: () = assert!(
	option_env!("HPKE_NG_HAZMAT").is_some(),
	"the `hazmat-kat-internals` and `hazmat-differential` features expose internal \
	 key-schedule state (raw AEAD keys, exporter secrets, and construction of a \
	 `SenderContext` from arbitrary key material) and must never be enabled in a \
	 production build. Because Cargo unifies features across the dependency graph, \
	 enabling them requires a second opt-in that a dependency cannot supply on your \
	 behalf: build with RUSTFLAGS=\"--cfg hpke_ng_hazmat\", or set HPKE_NG_HAZMAT=1 \
	 where RUSTFLAGS is not yours to set."
);

extern crate alloc;

mod aead;
mod error;
mod kdf;
mod psk;
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
pub use psk::{MIN_PSK_LEN, Psk};

#[cfg(feature = "pq")]
pub use kem::pq::{MlKem768, MlKem1024, XWingDraft06};

mod context;

pub use context::{Context, ReceiverContext, SenderContext};

use alloc::vec::Vec;
use core::marker::PhantomData;

use rand_core::CryptoRng;

use zeroize::Zeroizing;

use crate::kdf::{labeled_expand_pieces, labeled_extract};

/// HPKE configuration parameterized over a KEM, KDF, and AEAD.
///
/// Zero-sized: the ciphersuite lives entirely in the type, every operation is an
/// associated function, and no PRNG is owned by the configuration. See the crate
/// documentation for a worked example.
#[derive(Debug, Clone, Copy, Default)]
pub struct Hpke<K: Kem, F: Kdf, A: Aead>(PhantomData<(K, F, A)>);

/// RFC 9180 §5.1 mode identifiers, as bound into `ks_context`.
pub(crate) mod modes {
	pub const BASE: u8 = 0x00;
	pub const PSK: u8 = 0x01;
	pub const AUTH: u8 = 0x02;
	pub const AUTH_PSK: u8 = 0x03;
}

/// Sealed marker supertrait for the four HPKE modes.
///
/// This trait and the four tag types below are `#[doc(hidden)]` and exist so the
/// key schedule can be specialized per mode at compile time. They are reachable
/// from outside only through the `hazmat-` test harnesses; treat them as
/// internal.
#[doc(hidden)]
pub trait HpkeMode: sealed::Sealed {
	/// The RFC 9180 mode byte for this mode.
	#[doc(hidden)]
	const MODE_BYTE: u8;
}

/// Marker for the PSK-free modes, Base and Auth. Selects
/// [`key_schedule_psk_free`].
#[doc(hidden)]
pub trait PskFreeMode: HpkeMode {}

/// Marker for the PSK-bearing modes, PSK and `AuthPSK`. Selects
/// [`key_schedule_psk`].
#[doc(hidden)]
pub trait PskMode: HpkeMode {}

/// Base mode (RFC 9180 §5.1.1).
#[doc(hidden)]
pub struct BaseModeTag;

/// Auth mode (RFC 9180 §5.1.3).
#[doc(hidden)]
pub struct AuthModeTag;

/// PSK mode (RFC 9180 §5.1.2).
#[doc(hidden)]
pub struct PskModeTag;

/// `AuthPSK` mode (RFC 9180 §5.1.4).
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

/// `suite_id = "HPKE" || kem_id || kdf_id || aead_id` (RFC 9180 §5.1), the
/// domain separator for every key-schedule and exporter KDF call.
#[inline]
pub(crate) fn ciphersuite<K: Kem, F: Kdf, A: Aead>() -> [u8; 10] {
	let mut s = [0u8; 10];
	s[..4].copy_from_slice(b"HPKE");
	s[4..6].copy_from_slice(&K::ID.to_be_bytes());
	s[6..8].copy_from_slice(&F::ID.to_be_bytes());
	s[8..10].copy_from_slice(&A::ID.to_be_bytes());
	s
}

/// Key schedule for the PSK-free modes (Base and Auth, RFC 9180 §5.1.1/§5.1.3).
/// The PSK inputs are structurally absent; `M: PskFreeMode` makes routing a
/// PSK-bearing mode through here a compile error.
fn key_schedule_psk_free_impl<M: PskFreeMode, K: Kem, F: Kdf, A: Aead>(
	shared_secret: &[u8],
	info: &[u8],
) -> Result<Context<K, F, A>, HpkeError> {
	let suite = ciphersuite::<K, F, A>();
	let psk_id_hash = labeled_extract::<F>(&[], &suite, b"psk_id_hash", &[]);
	let info_hash = labeled_extract::<F>(&[], &suite, b"info_hash", info);

	// `ks_context = mode || psk_id_hash || info_hash`, fed piecewise to each
	// expand call rather than concatenated into a `Vec`.
	let mode_arr = [M::MODE_BYTE];
	let ks_pieces: [&[u8]; 3] = [&mode_arr, &psk_id_hash, &info_hash];

	let secret = Zeroizing::new(labeled_extract::<F>(shared_secret, &suite, b"secret", &[]));
	// Each output is wrapped as it is produced: a later `?` in this sequence
	// would otherwise drop already-derived key material unscrubbed.
	let key = Zeroizing::new(labeled_expand_pieces::<F>(
		&secret,
		&suite,
		b"key",
		&ks_pieces,
		A::KEY_LEN,
	)?);
	let base_nonce = Zeroizing::new(labeled_expand_pieces::<F>(
		&secret,
		&suite,
		b"base_nonce",
		&ks_pieces,
		A::NONCE_LEN,
	)?);
	let exporter_secret = Zeroizing::new(labeled_expand_pieces::<F>(
		&secret,
		&suite,
		b"exp",
		&ks_pieces,
		F::HASH_LEN,
	)?);
	Context::new(&key, &base_nonce, exporter_secret)
}

// Two wrappers because an item's visibility cannot itself be `cfg`-dependent:
// the KAT harness needs these public, every other build wants them crate-private.
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

/// Key schedule for the PSK-bearing modes (PSK and `AuthPSK`, RFC 9180
/// §5.1.2/§5.1.4). `M: PskMode` makes routing a PSK-free mode through here a
/// compile error, and [`Psk`] carries the proof that its contents were already
/// validated — so this path needs no input checks of its own.
fn key_schedule_psk_impl<M: PskMode, K: Kem, F: Kdf, A: Aead>(
	shared_secret: &[u8],
	info: &[u8],
	psk: Psk<'_>,
) -> Result<Context<K, F, A>, HpkeError> {
	let suite = ciphersuite::<K, F, A>();
	let psk_id_hash = labeled_extract::<F>(&[], &suite, b"psk_id_hash", psk.id());
	let info_hash = labeled_extract::<F>(&[], &suite, b"info_hash", info);

	// `ks_context = mode || psk_id_hash || info_hash`, fed piecewise to each
	// expand call rather than concatenated into a `Vec`.
	let mode_arr = [M::MODE_BYTE];
	let ks_pieces: [&[u8]; 3] = [&mode_arr, &psk_id_hash, &info_hash];

	let secret = Zeroizing::new(labeled_extract::<F>(
		shared_secret,
		&suite,
		b"secret",
		psk.secret(),
	));
	// Each output is wrapped as it is produced: a later `?` in this sequence
	// would otherwise drop already-derived key material unscrubbed.
	let key = Zeroizing::new(labeled_expand_pieces::<F>(
		&secret,
		&suite,
		b"key",
		&ks_pieces,
		A::KEY_LEN,
	)?);
	let base_nonce = Zeroizing::new(labeled_expand_pieces::<F>(
		&secret,
		&suite,
		b"base_nonce",
		&ks_pieces,
		A::NONCE_LEN,
	)?);
	let exporter_secret = Zeroizing::new(labeled_expand_pieces::<F>(
		&secret,
		&suite,
		b"exp",
		&ks_pieces,
		F::HASH_LEN,
	)?);

	Context::new(&key, &base_nonce, exporter_secret)
}

// Same `cfg` pair as `key_schedule_psk_free` above.
#[cfg(not(feature = "hazmat-kat-internals"))]
pub(crate) fn key_schedule_psk<M: PskMode, K: Kem, F: Kdf, A: Aead>(
	shared_secret: &[u8],
	info: &[u8],
	psk: Psk<'_>,
) -> Result<Context<K, F, A>, HpkeError> {
	key_schedule_psk_impl::<M, K, F, A>(shared_secret, info, psk)
}

#[cfg(feature = "hazmat-kat-internals")]
#[doc(hidden)]
pub fn key_schedule_psk<M: PskMode, K: Kem, F: Kdf, A: Aead>(
	shared_secret: &[u8],
	info: &[u8],
	psk: Psk<'_>,
) -> Result<Context<K, F, A>, HpkeError> {
	key_schedule_psk_impl::<M, K, F, A>(shared_secret, info, psk)
}

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

	/// `SetupPSKS` (RFC 9180 §5.1.2). See [`Psk::new`] for the PSK requirements.
	pub fn setup_sender_psk<R: CryptoRng>(
		rng: &mut R,
		pk_r: &K::PublicKey,
		info: &[u8],
		psk: Psk<'_>,
	) -> Result<(K::EncappedKey, SenderContext<K, F, A>), HpkeError> {
		let (ss, enc) = K::encap(rng, pk_r)?;
		let ctx = key_schedule_psk::<PskModeTag, K, F, A>(ss.as_ref(), info, psk)?;
		Ok((enc, SenderContext::new(ctx)))
	}

	/// `SetupPSKR` (RFC 9180 §5.1.2). See [`Psk::new`] for the PSK requirements.
	pub fn setup_receiver_psk(
		enc: &K::EncappedKey,
		sk_r: &K::PrivateKey,
		info: &[u8],
		psk: Psk<'_>,
	) -> Result<ReceiverContext<K, F, A>, HpkeError> {
		let ss = K::decap(enc, sk_r)?;
		key_schedule_psk::<PskModeTag, K, F, A>(ss.as_ref(), info, psk).map(ReceiverContext::new)
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
	pub fn seal_psk<R: CryptoRng>(
		rng: &mut R,
		pk_r: &K::PublicKey,
		info: &[u8],
		aad: &[u8],
		pt: &[u8],
		psk: Psk<'_>,
	) -> Result<(K::EncappedKey, Vec<u8>), HpkeError> {
		let (enc, mut ctx) = Self::setup_sender_psk(rng, pk_r, info, psk)?;
		let ct = ctx.seal(aad, pt)?;
		Ok((enc, ct))
	}

	/// Single-shot Psk-mode decrypt (RFC 9180 §6.1).
	pub fn open_psk(
		enc: &K::EncappedKey,
		sk_r: &K::PrivateKey,
		info: &[u8],
		aad: &[u8],
		ct: &[u8],
		psk: Psk<'_>,
	) -> Result<Vec<u8>, HpkeError> {
		let mut ctx = Self::setup_receiver_psk(enc, sk_r, info, psk)?;
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
	pub fn seal_auth_psk<R: CryptoRng>(
		rng: &mut R,
		pk_r: &K::PublicKey,
		info: &[u8],
		aad: &[u8],
		pt: &[u8],
		psk: Psk<'_>,
		sk_s: &K::PrivateKey,
	) -> Result<(K::EncappedKey, Vec<u8>), HpkeError> {
		let (enc, mut ctx) = Self::setup_sender_auth_psk(rng, pk_r, info, psk, sk_s)?;
		let ct = ctx.seal(aad, pt)?;
		Ok((enc, ct))
	}

	/// Single-shot AuthPsk-mode decrypt (RFC 9180 §6.1).
	pub fn open_auth_psk(
		enc: &K::EncappedKey,
		sk_r: &K::PrivateKey,
		info: &[u8],
		aad: &[u8],
		ct: &[u8],
		psk: Psk<'_>,
		pk_s: &K::PublicKey,
	) -> Result<Vec<u8>, HpkeError> {
		let mut ctx = Self::setup_receiver_auth_psk(enc, sk_r, info, psk, pk_s)?;
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
	pub fn send_export_psk<R: CryptoRng>(
		rng: &mut R,
		pk_r: &K::PublicKey,
		info: &[u8],
		psk: Psk<'_>,
		exporter_context: &[u8],
		length: usize,
	) -> Result<(K::EncappedKey, Vec<u8>), HpkeError> {
		let (enc, ctx) = Self::setup_sender_psk(rng, pk_r, info, psk)?;
		Ok((enc, ctx.export(exporter_context, length)?))
	}

	/// Receiver-side single-shot export — Psk mode.
	pub fn receiver_export_psk(
		enc: &K::EncappedKey,
		sk_r: &K::PrivateKey,
		info: &[u8],
		psk: Psk<'_>,
		exporter_context: &[u8],
		length: usize,
	) -> Result<Vec<u8>, HpkeError> {
		let ctx = Self::setup_receiver_psk(enc, sk_r, info, psk)?;
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
	pub fn send_export_auth_psk<R: CryptoRng>(
		rng: &mut R,
		pk_r: &K::PublicKey,
		info: &[u8],
		psk: Psk<'_>,
		sk_s: &K::PrivateKey,
		exporter_context: &[u8],
		length: usize,
	) -> Result<(K::EncappedKey, Vec<u8>), HpkeError> {
		let (enc, ctx) = Self::setup_sender_auth_psk(rng, pk_r, info, psk, sk_s)?;
		Ok((enc, ctx.export(exporter_context, length)?))
	}

	/// Receiver-side single-shot export — `AuthPsk` mode.
	pub fn receiver_export_auth_psk(
		enc: &K::EncappedKey,
		sk_r: &K::PrivateKey,
		info: &[u8],
		psk: Psk<'_>,
		pk_s: &K::PublicKey,
		exporter_context: &[u8],
		length: usize,
	) -> Result<Vec<u8>, HpkeError> {
		let ctx = Self::setup_receiver_auth_psk(enc, sk_r, info, psk, pk_s)?;
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

	/// `SetupAuthPSKS` (RFC 9180 §5.1.4). See [`Psk::new`] for the PSK requirements.
	pub fn setup_sender_auth_psk<R: CryptoRng>(
		rng: &mut R,
		pk_r: &K::PublicKey,
		info: &[u8],
		psk: Psk<'_>,
		sk_s: &K::PrivateKey,
	) -> Result<(K::EncappedKey, SenderContext<K, F, A>), HpkeError> {
		let (ss, enc) = K::auth_encap(rng, pk_r, sk_s)?;
		let ctx = key_schedule_psk::<AuthPskModeTag, K, F, A>(ss.as_ref(), info, psk)?;
		Ok((enc, SenderContext::new(ctx)))
	}

	/// `SetupAuthPSKR` (RFC 9180 §5.1.4). See [`Psk::new`] for the PSK requirements.
	pub fn setup_receiver_auth_psk(
		enc: &K::EncappedKey,
		sk_r: &K::PrivateKey,
		info: &[u8],
		psk: Psk<'_>,
		pk_s: &K::PublicKey,
	) -> Result<ReceiverContext<K, F, A>, HpkeError> {
		let ss = K::auth_decap(enc, sk_r, pk_s)?;
		key_schedule_psk::<AuthPskModeTag, K, F, A>(ss.as_ref(), info, psk)
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
