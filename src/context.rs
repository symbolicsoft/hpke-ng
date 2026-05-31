//! HPKE encryption/decryption context (RFC 9180 §5.2 & §5.3).

use alloc::vec::Vec;
use core::marker::PhantomData;

use zeroize::Zeroizing;

use crate::HpkeError;
use crate::aead::{Aead, SealingAead};
use crate::ciphersuite;
use crate::kdf::{Kdf, labeled_expand};
use crate::kem::Kem;

/// HPKE encryption/decryption context.
///
/// Holds an AEAD cipher state (constructed once from the derived key), the
/// `base_nonce`, the `exporter_secret`, and a `u64` sequence counter.
///
/// **Not** `Clone`: copying a context would let two callers reuse the same
/// `(key, base_nonce, seq)` and produce a nonce-reuse footgun.
pub struct Context<K: Kem, F: Kdf, A: Aead> {
	cipher: A::Cipher,
	base_nonce: Zeroizing<[u8; 12]>,
	exporter_secret: Zeroizing<Vec<u8>>,
	seq: u64,
	/// Raw AEAD key bytes — kept under cfg gate so the test/KAT/differential
	/// harnesses can assert on them. Production builds carry only the
	/// derived `cipher` state.
	#[cfg(any(test, feature = "kat-internals", feature = "differential"))]
	raw_key: Zeroizing<Vec<u8>>,
	_kfa: PhantomData<(K, F, A)>,
}

/// Compile-time verification that an AEAD's nonce length fits the fixed buffer
/// in [`Context::compute_nonce`] and accommodates the 64-bit sequence number.
/// Evaluated lazily — only AEADs whose seal/open paths are instantiated must
/// satisfy the bound. `ExportOnly` (`NONCE_LEN = 0`) deliberately escapes the
/// check because it never reaches `compute_nonce`.
struct AssertNonceRange<A: Aead>(PhantomData<A>);

impl<A: Aead> AssertNonceRange<A> {
	const CHECK: () = {
		assert!(A::NONCE_LEN >= 8, "AEAD::NONCE_LEN must be >= 8");
		assert!(A::NONCE_LEN <= 12, "AEAD::NONCE_LEN must be <= 12");
	};
}

impl<K: Kem, F: Kdf, A: Aead> Context<K, F, A> {
	pub(crate) fn new(
		key: Vec<u8>,
		base_nonce: impl AsRef<[u8]>,
		exporter_secret: Vec<u8>,
	) -> Result<Self, HpkeError> {
		// Wrap the raw key bytes in `Zeroizing` so the temporary heap
		// allocation is scrubbed once the cipher has copied the material.
		let key_z = Zeroizing::new(key);
		let cipher = A::init(&key_z)?;
		let mut nonce_arr = [0u8; 12];
		nonce_arr[..A::NONCE_LEN].copy_from_slice(base_nonce.as_ref());
		Ok(Self {
			cipher,
			base_nonce: Zeroizing::new(nonce_arr),
			exporter_secret: Zeroizing::new(exporter_secret),
			seq: 0,
			#[cfg(any(test, feature = "kat-internals", feature = "differential"))]
			raw_key: Zeroizing::new(key_z.to_vec()),
			_kfa: PhantomData,
		})
	}

	/// `Context.Export` (RFC 9180 §5.3).
	#[inline]
	pub fn export(&self, exporter_context: &[u8], length: usize) -> Result<Vec<u8>, HpkeError> {
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
	fn compute_nonce(&self) -> [u8; 12] {
		// Force compile-time evaluation of the `8 <= NONCE_LEN <= 12` bound.
		let () = AssertNonceRange::<A>::CHECK;
		let mut nonce = [0u8; 12];
		let len = A::NONCE_LEN;
		nonce[..len].copy_from_slice(&self.base_nonce.as_ref()[..len]);
		let seq_be = self.seq.to_be_bytes();
		// XOR the 8-byte big-endian sequence counter into the trailing
		// 8 bytes of the (≤ 12-byte) nonce.
		for i in 0..8 {
			nonce[len - 8 + i] ^= seq_be[i];
		}
		nonce
	}
}

#[cfg(any(test, feature = "kat-internals", feature = "differential"))]
impl<K: Kem, F: Kdf, A: Aead> Context<K, F, A> {
	/// Test-only: expose the AEAD key.
	#[must_use]
	pub fn key(&self) -> &[u8] {
		&self.raw_key
	}
	/// Test-only: expose the base nonce.
	#[must_use]
	pub fn nonce(&self) -> &[u8] {
		&self.base_nonce[..A::NONCE_LEN]
	}
	/// Test-only: expose the exporter secret.
	#[must_use]
	pub fn exporter_secret(&self) -> &[u8] {
		&self.exporter_secret
	}
	/// Test-only: expose the sequence number.
	#[must_use]
	pub fn sequence_number(&self) -> u64 {
		self.seq
	}
	/// Test-only: set the sequence number directly. Used for boundary tests
	/// (e.g. asserting that `seal` near `u64::MAX` returns `MessageLimitReached`
	/// rather than wrapping).
	#[cfg(test)]
	pub(crate) fn set_seq_for_test(&mut self, seq: u64) {
		self.seq = seq;
	}
}

impl<K: Kem, F: Kdf, A: SealingAead> Context<K, F, A> {
	/// `Context.Seal(aad, pt)` (RFC 9180 §5.2).
	///
	/// Pre-checks the sequence counter before encrypting: at `seq == u64::MAX`
	/// the next encryption would reuse a nonce if the caller subsequently
	/// ignored a `MessageLimitReached` error from `increment_seq`. Refusing to
	/// encrypt at all makes nonce-reuse structurally impossible regardless of
	/// caller behaviour.
	#[inline]
	pub fn seal(&mut self, aad: &[u8], pt: &[u8]) -> Result<Vec<u8>, HpkeError> {
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
	/// Same pre-check as `seal`: refuses to derive a nonce at `seq == u64::MAX`
	/// rather than producing a recoverable plaintext that would leave the
	/// receiver in a state where the next `open` reuses the same nonce.
	#[inline]
	pub fn open(&mut self, aad: &[u8], ct: &[u8]) -> Result<Vec<u8>, HpkeError> {
		if self.seq == u64::MAX {
			return Err(HpkeError::MessageLimitReached);
		}
		let nonce = self.compute_nonce();
		let pt = A::open(&self.cipher, &nonce[..A::NONCE_LEN], aad, ct)?;
		self.seq += 1;
		Ok(pt)
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::{ChaCha20Poly1305, DhKemX25519HkdfSha256, HkdfSha256};

	type Ctx = Context<DhKemX25519HkdfSha256, HkdfSha256, ChaCha20Poly1305>;

	#[test]
	fn seal_open_roundtrip_with_known_state() {
		let key = vec![0x42u8; 32];
		let base_nonce = vec![0x77u8; 12];
		let exporter_secret = vec![0u8; 32];
		let mut sender: Ctx =
			Context::new(key.clone(), &base_nonce.clone(), exporter_secret.clone()).unwrap();
		let mut receiver: Ctx = Context::new(key, &base_nonce, exporter_secret).unwrap();

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
		let ctx: Ctx = Context::new(vec![0u8; 32], vec![0u8; 12], vec![1u8; 32]).unwrap();
		let a = ctx.export(b"context", 32).unwrap();
		let b = ctx.export(b"context", 32).unwrap();
		assert_eq!(a, b);
		assert_eq!(a.len(), 32);
		let c = ctx.export(b"different", 32).unwrap();
		assert_ne!(a, c);
	}

	#[test]
	fn export_length_bound() {
		let ctx: Ctx = Context::new(vec![0u8; 32], vec![0u8; 12], vec![1u8; 32]).unwrap();
		assert_eq!(
			ctx.export(b"ctx", 8161),
			Err(HpkeError::ExportLengthExceeded)
		);
	}

	#[test]
	fn nonce_derivation_xors_seq_into_base_nonce() {
		let mut ctx: Ctx = Context::new(vec![0u8; 32], vec![0u8; 12], vec![0u8; 32]).unwrap();

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
		let mut ctx: Ctx = Context::new(vec![0x42u8; 32], vec![0x77u8; 12], vec![0u8; 32]).unwrap();
		ctx.set_seq_for_test(u64::MAX);
		let r = ctx.seal(b"aad", b"hello");
		assert_eq!(r, Err(HpkeError::MessageLimitReached));
	}

	#[test]
	fn seal_succeeds_before_message_limit_then_fails() {
		let mut ctx: Ctx = Context::new(vec![0x42u8; 32], vec![0x77u8; 12], vec![0u8; 32]).unwrap();
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
		let mut ctx: Ctx = Context::new(vec![0x42u8; 32], vec![0x77u8; 12], vec![0u8; 32]).unwrap();
		let mut sibling: Ctx =
			Context::new(vec![0x42u8; 32], vec![0x77u8; 12], vec![0u8; 32]).unwrap();
		let ct = sibling.seal(b"aad", b"hello").unwrap();
		ctx.set_seq_for_test(u64::MAX);
		let r = ctx.open(b"aad", &ct);
		assert_eq!(r, Err(HpkeError::MessageLimitReached));
	}
}
