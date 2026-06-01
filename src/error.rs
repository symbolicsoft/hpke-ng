//! Error types for `hpke-ng`.

use core::fmt;

/// All error conditions raised by `hpke-ng`.
///
/// `#[non_exhaustive]` — new variants may be added without a major-version bump.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HpkeError {
	/// AEAD authentication failure during `open`.
	OpenError,
	/// AEAD encryption failed during `seal`.
	///
	/// In normal operation this path is unreachable: `seal` is called with a
	/// key sized exactly to `Aead::KEY_LEN` (set by the key schedule) and the
	/// AEAD primitive is engineered not to fail on valid inputs. This variant
	/// covers e.g. message-length overflow on the AEAD's internal counter.
	SealError,
	/// AEAD cipher state could not be initialized from a key.
	///
	/// Returned by [`Aead::init`](crate::Aead::init) when the supplied key
	/// length does not match `Aead::KEY_LEN`. Unreachable in normal operation
	/// because the key schedule produces keys of exactly the right length;
	/// kept as a defense-in-depth boundary error.
	AeadInitError,
	/// KEM encapsulation failed (e.g. small-order receiver public key).
	EncapError,
	/// KEM decapsulation failed.
	DecapError,
	/// Public key bytes are malformed or off-curve.
	InvalidPublicKey,
	/// Private key bytes are malformed.
	InvalidPrivateKey,
	/// Encapsulated key bytes are malformed.
	InvalidEncappedKey,
	/// PSK and PSK ID are not both empty or both non-empty.
	InconsistentPsk,
	/// PSK input is required by the mode but missing.
	MissingPsk,
	/// PSK input is provided but not needed by the mode.
	UnnecessaryPsk,
	/// PSK has fewer than 32 bytes.
	///
	/// RFC 9180 §5.1 requires PSKs with **at least 32 bytes of entropy**. This
	/// crate enforces a 32-byte minimum length as a proxy for entropy; the
	/// caller is responsible for supplying high-entropy material. Do **not**
	/// pass passwords or other low-entropy strings as a PSK without first
	/// running them through a slow password-hashing KDF (e.g. Argon2).
	InsecurePsk,
	/// Requested KDF expansion would exceed `255 * Nh` (RFC 5869 §2.3).
	ExportLengthExceeded,
	/// AEAD sequence-number limit reached.
	MessageLimitReached,
	/// `DeriveKeyPair` rejection sampling exhausted all 256 candidates
	/// (RFC 9180 §7.1.3). With high probability this only occurs when the
	/// IKM has insufficient entropy.
	DeriveKeyPairError,
	/// The input keying material supplied to `DeriveKeyPair` has the wrong length.
	///
	/// For ML-KEM-768 and ML-KEM-1024, `derive_key_pair` requires exactly
	/// 64 bytes of IKM representing the `(d, z)` seed as specified in
	/// draft-connolly-cfrg-hpke-mlkem §3.2.
	/// Passing any other length returns this error.
	InvalidKeyMaterial,
}

impl fmt::Display for HpkeError {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		let s = match self {
			Self::OpenError => "AEAD open failed",
			Self::SealError => "AEAD seal failed",
			Self::AeadInitError => "AEAD cipher init failed",
			Self::EncapError => "KEM encapsulation failed",
			Self::DecapError => "KEM decapsulation failed",
			Self::InvalidPublicKey => "invalid public key",
			Self::InvalidPrivateKey => "invalid private key",
			Self::InvalidEncappedKey => "invalid encapsulated key",
			Self::InconsistentPsk => "PSK and PSK ID must both be empty or both non-empty",
			Self::MissingPsk => "PSK is required by this mode",
			Self::UnnecessaryPsk => "PSK is not used by this mode",
			Self::InsecurePsk => "PSK shorter than 32 bytes",
			Self::ExportLengthExceeded => "requested length exceeds HKDF-Expand maximum",
			Self::MessageLimitReached => "AEAD message limit reached",
			Self::DeriveKeyPairError => "DeriveKeyPair rejection sampling exhausted",
			Self::InvalidKeyMaterial => {
				"Input keying material supplied to DeriveKeyPair has the wrong length"
			}
		};
		f.write_str(s)
	}
}

impl core::error::Error for HpkeError {}

#[cfg(test)]
mod tests {
	use super::*;
	use alloc::format;

	#[test]
	fn display_is_informative() {
		assert_eq!(format!("{}", HpkeError::OpenError), "AEAD open failed");
		assert_eq!(
			format!("{}", HpkeError::InsecurePsk),
			"PSK shorter than 32 bytes"
		);
	}

	#[test]
	fn equality_works() {
		assert_eq!(HpkeError::OpenError, HpkeError::OpenError);
		assert_ne!(HpkeError::OpenError, HpkeError::DecapError);
	}
}
