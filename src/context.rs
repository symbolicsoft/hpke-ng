//! HPKE encryption/decryption context (RFC 9180 §5.2 & §5.3).

use alloc::vec::Vec;
use core::marker::PhantomData;

use zeroize::Zeroizing;

use crate::HpkeError;
use crate::aead::{Aead, SealingAead};
use crate::ciphersuite;
use crate::kdf::{Kdf, labeled_expand};
use crate::kem::Kem;

/// HPKE encryption/decryption context. The AEAD cipher state is built once from
/// the derived key and reused for every message.
///
/// **Not** `Clone`: two copies would seal under the same `(key, base_nonce,
/// seq)`, which is exactly the nonce reuse the sequence counter exists to
/// prevent.
pub struct Context<K: Kem, F: Kdf, A: Aead> {
	cipher: A::Cipher,
	base_nonce: Zeroizing<[u8; MAX_NONCE_LEN]>,
	exporter_secret: Zeroizing<Vec<u8>>,
	seq: u64,
	/// Raw AEAD key bytes — kept under cfg gate so the test/KAT/differential
	/// harnesses can assert on them. Production builds carry only the
	/// derived `cipher` state.
	#[cfg(any(
		test,
		feature = "hazmat-kat-internals",
		feature = "hazmat-differential"
	))]
	raw_key: Zeroizing<Vec<u8>>,
	_kfa: PhantomData<(K, F, A)>,
}

const SEQ_LEN: usize = 8;

const MAX_NONCE_LEN: usize = 12;

/// Compile-time verification that an AEAD's nonce length fits the fixed buffer
/// in [`Context::compute_nonce`] and accommodates the 64-bit sequence number.
/// Evaluated lazily — only AEADs whose seal/open paths are instantiated must
/// satisfy the bound. `ExportOnly` (`NONCE_LEN = 0`) deliberately escapes the
/// check because it never reaches `compute_nonce`.
struct AssertNonceRange<A: Aead>(PhantomData<A>);

impl<A: Aead> AssertNonceRange<A> {
	const CHECK: () = {
		assert!(
			A::NONCE_LEN >= SEQ_LEN,
			"AEAD::NONCE_LEN must be >= the sequence-counter width"
		);
		assert!(
			A::NONCE_LEN <= MAX_NONCE_LEN,
			"AEAD::NONCE_LEN must fit the nonce buffer"
		);
	};
}

impl<K: Kem, F: Kdf, A: Aead> Context<K, F, A> {
	/// The key and base nonce stay owned by the caller, which holds them in
	/// [`Zeroizing`]; the exporter secret moves in. Between them, key material is
	/// scrubbed however this function exits — including the early return from a
	/// failed [`Aead::init`] and the key schedule's own error paths.
	pub(crate) fn new(
		key: &Zeroizing<Vec<u8>>,
		base_nonce: &[u8],
		exporter_secret: Zeroizing<Vec<u8>>,
	) -> Result<Self, HpkeError> {
		let cipher = A::init(key)?;
		let mut nonce = Zeroizing::new([0u8; MAX_NONCE_LEN]);
		nonce[..A::NONCE_LEN].copy_from_slice(base_nonce);
		Ok(Self {
			cipher,
			base_nonce: nonce,
			exporter_secret,
			seq: 0,
			#[cfg(any(
				test,
				feature = "hazmat-kat-internals",
				feature = "hazmat-differential"
			))]
			raw_key: key.clone(),
			_kfa: PhantomData,
		})
	}

	/// `Context.Export` (RFC 9180 §5.3).
	#[inline]
	pub(crate) fn export(
		&self,
		exporter_context: &[u8],
		length: usize,
	) -> Result<Vec<u8>, HpkeError> {
		let suite = ciphersuite::<K, F, A>();
		labeled_expand::<F>(
			&self.exporter_secret,
			&suite,
			b"sec",
			exporter_context,
			length,
		)
	}

	/// `Context.ComputeNonce(seq)` (RFC 9180 §5.2).
	#[inline]
	fn compute_nonce(&self) -> [u8; MAX_NONCE_LEN] {
		// Force compile-time evaluation of the `SEQ_LEN <= NONCE_LEN <= MAX_NONCE_LEN` bound.
		let () = AssertNonceRange::<A>::CHECK;
		let len = A::NONCE_LEN;
		let mut nonce = [0u8; MAX_NONCE_LEN];
		nonce[..len].copy_from_slice(&self.base_nonce[..len]);
		// XOR the big-endian sequence counter into the trailing `SEQ_LEN`
		// bytes of the (≤ `MAX_NONCE_LEN`-byte) nonce.
		let seq_be = self.seq.to_be_bytes();
		for (dst, &b) in nonce[len - SEQ_LEN..len].iter_mut().zip(&seq_be) {
			*dst ^= b;
		}
		nonce
	}
}

/// Accessors for the KAT and differential harnesses, which assert on
/// key-schedule outputs directly. Never compiled into a production build.
#[cfg(any(
	test,
	feature = "hazmat-kat-internals",
	feature = "hazmat-differential"
))]
impl<K: Kem, F: Kdf, A: Aead> Context<K, F, A> {
	/// The raw AEAD key.
	#[must_use]
	pub fn key(&self) -> &[u8] {
		&self.raw_key
	}
	/// The base nonce.
	#[must_use]
	pub fn nonce(&self) -> &[u8] {
		&self.base_nonce[..A::NONCE_LEN]
	}
	/// The exporter secret.
	#[must_use]
	pub fn exporter_secret(&self) -> &[u8] {
		&self.exporter_secret
	}
	/// The current sequence number.
	#[must_use]
	pub fn sequence_number(&self) -> u64 {
		self.seq
	}
	/// Sets the sequence number, for the `u64::MAX` boundary tests.
	#[cfg(test)]
	pub(crate) fn set_seq_for_test(&mut self, seq: u64) {
		self.seq = seq;
	}
}

impl<K: Kem, F: Kdf, A: SealingAead> Context<K, F, A> {
	/// `Context.Seal(aad, pt)` (RFC 9180 §5.2).
	///
	/// The counter is checked *before* encrypting. Encrypting first and failing
	/// on the increment afterwards would hand the caller a ciphertext produced
	/// under a nonce the context can no longer advance past, so a caller who
	/// ignored the error would reuse it. Refusing up front makes that
	/// impossible regardless of caller behaviour.
	#[inline]
	pub(crate) fn seal(&mut self, aad: &[u8], pt: &[u8]) -> Result<Vec<u8>, HpkeError> {
		if self.seq == u64::MAX {
			return Err(HpkeError::MessageLimitReached);
		}
		let nonce = self.compute_nonce();
		let ct = A::seal(&self.cipher, &nonce[..A::NONCE_LEN], aad, pt)?;
		self.seq += 1; // checked above; cannot overflow
		Ok(ct)
	}

	/// `Context.Open(aad, ct)` (RFC 9180 §5.2).
	///
	/// Same pre-check as `seal`, for a different reason: incrementing past
	/// `u64::MAX` would wrap the counter to zero, and the receiver would then
	/// accept a replay of the very first message.
	#[inline]
	pub(crate) fn open(&mut self, aad: &[u8], ct: &[u8]) -> Result<Vec<u8>, HpkeError> {
		if self.seq == u64::MAX {
			return Err(HpkeError::MessageLimitReached);
		}
		let nonce = self.compute_nonce();
		let pt = A::open(&self.cipher, &nonce[..A::NONCE_LEN], aad, ct)?;
		self.seq += 1;
		Ok(pt)
	}
}

/// Sender-side HPKE context — RFC 9180 §5.2 `ContextS`.
///
/// Returned by the `setup_sender_*` functions. Exposes [`seal`](Self::seal) and
/// [`export`](Self::export) but deliberately not `open`, because an HPKE context
/// is one-directional: sender and receiver derive the *identical*
/// `(key, base_nonce)`, so one context used in both directions would reuse a
/// `(key, nonce)` pair. Separate types make that a compile error.
///
/// For a bidirectional channel, run one HPKE setup per direction, or derive
/// per-direction keys via [`export`](Self::export) (RFC 9180 §9.8).
///
/// **Not** `Clone`, for the same reason as [`Context`].
pub struct SenderContext<K: Kem, F: Kdf, A: Aead>(Context<K, F, A>);

/// Receiver-side HPKE context — RFC 9180 §5.2 `ContextR`.
///
/// Returned by the `setup_receiver_*` functions. Exposes [`open`](Self::open)
/// and [`export`](Self::export) but not `seal`, for the same one-directional
/// reason as [`SenderContext`]. **Not** `Clone`.
pub struct ReceiverContext<K: Kem, F: Kdf, A: Aead>(Context<K, F, A>);

impl<K: Kem, F: Kdf, A: Aead> SenderContext<K, F, A> {
	pub(crate) fn new(inner: Context<K, F, A>) -> Self {
		Self(inner)
	}

	/// Wraps a raw key-schedule [`Context`] as a sender context. The test
	/// harnesses build contexts from injected shared secrets instead of going
	/// through `setup_sender_*`.
	#[cfg(any(
		test,
		feature = "hazmat-kat-internals",
		feature = "hazmat-differential"
	))]
	#[doc(hidden)]
	#[must_use]
	pub fn from_context(inner: Context<K, F, A>) -> Self {
		Self(inner)
	}

	/// `Context.Export` (RFC 9180 §5.3).
	pub fn export(&self, exporter_context: &[u8], length: usize) -> Result<Vec<u8>, HpkeError> {
		self.0.export(exporter_context, length)
	}
}

impl<K: Kem, F: Kdf, A: SealingAead> SenderContext<K, F, A> {
	/// `Context.Seal(aad, pt)` (RFC 9180 §5.2).
	pub fn seal(&mut self, aad: &[u8], pt: &[u8]) -> Result<Vec<u8>, HpkeError> {
		self.0.seal(aad, pt)
	}
}

impl<K: Kem, F: Kdf, A: Aead> ReceiverContext<K, F, A> {
	pub(crate) fn new(inner: Context<K, F, A>) -> Self {
		Self(inner)
	}

	/// `Context.Export` (RFC 9180 §5.3).
	pub fn export(&self, exporter_context: &[u8], length: usize) -> Result<Vec<u8>, HpkeError> {
		self.0.export(exporter_context, length)
	}
}

impl<K: Kem, F: Kdf, A: SealingAead> ReceiverContext<K, F, A> {
	/// `Context.Open(aad, ct)` (RFC 9180 §5.2).
	pub fn open(&mut self, aad: &[u8], ct: &[u8]) -> Result<Vec<u8>, HpkeError> {
		self.0.open(aad, ct)
	}
}

/// The same harness accessors, delegating to the inner [`Context`].
#[cfg(any(
	test,
	feature = "hazmat-kat-internals",
	feature = "hazmat-differential"
))]
impl<K: Kem, F: Kdf, A: Aead> ReceiverContext<K, F, A> {
	/// The raw AEAD key.
	#[must_use]
	pub fn key(&self) -> &[u8] {
		self.0.key()
	}
	/// The base nonce.
	#[must_use]
	pub fn nonce(&self) -> &[u8] {
		self.0.nonce()
	}
	/// The exporter secret.
	#[must_use]
	pub fn exporter_secret(&self) -> &[u8] {
		self.0.exporter_secret()
	}
	/// The current sequence number.
	#[must_use]
	pub fn sequence_number(&self) -> u64 {
		self.0.sequence_number()
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::{ChaCha20Poly1305, DhKemX25519HkdfSha256, HkdfSha256};

	type Ctx = Context<DhKemX25519HkdfSha256, HkdfSha256, ChaCha20Poly1305>;

	/// Build a context from byte-fill values for the key, base nonce and
	/// exporter secret.
	fn new_test_ctx(key: u8, nonce: u8, exporter: u8) -> Ctx {
		Context::new(
			&Zeroizing::new(vec![key; 32]),
			&[nonce; MAX_NONCE_LEN],
			Zeroizing::new(vec![exporter; 32]),
		)
		.unwrap()
	}

	#[test]
	fn seal_open_roundtrip_with_known_state() {
		let key = Zeroizing::new(vec![0x42u8; 32]);
		let base_nonce = vec![0x77u8; MAX_NONCE_LEN];
		let exporter_secret = Zeroizing::new(vec![0u8; 32]);
		let mut sender: Ctx = Context::new(&key, &base_nonce, exporter_secret.clone()).unwrap();
		let mut receiver: Ctx = Context::new(&key, &base_nonce, exporter_secret).unwrap();

		let ct = sender.seal(b"aad", b"message").unwrap();
		let pt = receiver.open(b"aad", &ct).unwrap();
		assert_eq!(pt, b"message");
		assert_eq!(sender.sequence_number(), 1);
		assert_eq!(receiver.sequence_number(), 1);

		for i in 0..3 {
			let pt = alloc::format!("msg-{i}");
			let ct = sender.seal(b"aad", pt.as_bytes()).unwrap();
			let recovered = receiver.open(b"aad", &ct).unwrap();
			assert_eq!(recovered, pt.as_bytes());
		}
		assert_eq!(sender.sequence_number(), 4);
	}

	#[test]
	fn export_is_deterministic() {
		let ctx: Ctx = new_test_ctx(0, 0, 1);
		let a = ctx.export(b"context", 32).unwrap();
		let b = ctx.export(b"context", 32).unwrap();
		assert_eq!(a, b);
		assert_eq!(a.len(), 32);
		let c = ctx.export(b"different", 32).unwrap();
		assert_ne!(a, c);
	}

	#[test]
	fn export_length_bound() {
		let ctx: Ctx = new_test_ctx(0, 0, 1);
		assert_eq!(
			ctx.export(b"ctx", 8161),
			Err(HpkeError::ExportLengthExceeded)
		);
	}

	#[test]
	fn nonce_derivation_xors_seq_into_base_nonce() {
		let mut ctx: Ctx = new_test_ctx(0, 0, 0);

		// seq == 0: nonce must equal base_nonce exactly
		let n0 = ctx.compute_nonce();
		assert_eq!(n0, [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);

		// seq == 1: only the last byte changes
		ctx.set_seq_for_test(1);
		let n1 = ctx.compute_nonce();
		assert_eq!(n1, [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);

		// seq == 256: carry into byte 10
		ctx.set_seq_for_test(256);
		let n256 = ctx.compute_nonce();
		assert_eq!(n256, [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0]);

		// seq == 0x0102_0304_0506_0708: all 8 trailing bytes affected
		ctx.set_seq_for_test(0x0102_0304_0506_0708);
		let n_large = ctx.compute_nonce();
		assert_eq!(n_large, [0, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8]);
	}

	#[test]
	fn seal_rejects_at_message_limit() {
		let mut ctx: Ctx = new_test_ctx(0x42, 0x77, 0);
		ctx.set_seq_for_test(u64::MAX);
		let r = ctx.seal(b"aad", b"hello");
		assert_eq!(r, Err(HpkeError::MessageLimitReached));
	}

	#[test]
	fn seal_succeeds_before_message_limit_then_fails() {
		let mut ctx: Ctx = new_test_ctx(0x42, 0x77, 0);
		// Last valid sequence number --> seal must succeed.
		ctx.set_seq_for_test(u64::MAX - 1);
		assert!(ctx.seal(b"aad", b"hello").is_ok());
		// seq is now u64::MAX --> next seal must be rejected.
		assert_eq!(
			ctx.seal(b"aad", b"hello"),
			Err(HpkeError::MessageLimitReached)
		);
	}

	#[test]
	fn open_rejects_at_message_limit() {
		let mut ctx: Ctx = new_test_ctx(0x42, 0x77, 0);
		let mut sibling: Ctx = new_test_ctx(0x42, 0x77, 0);
		let ct = sibling.seal(b"aad", b"hello").unwrap();
		ctx.set_seq_for_test(u64::MAX);
		let r = ctx.open(b"aad", &ct);
		assert_eq!(r, Err(HpkeError::MessageLimitReached));
	}
}
