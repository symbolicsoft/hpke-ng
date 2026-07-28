//! Pre-shared key inputs for the PSK and `AuthPSK` modes (RFC 9180 §5.1.2).

use core::fmt;

use subtle::ConstantTimeEq;

use crate::HpkeError;

/// Minimum accepted PSK length in bytes.
///
/// RFC 9180 §5.1.2 requires a PSK with at least 32 bytes of *entropy*. Entropy
/// is not observable, so this crate enforces a 32-byte length as its proxy and
/// leaves the entropy itself to the caller.
pub const MIN_PSK_LEN: usize = 32;

/// A pre-shared key bundled with its identifier, validated at construction.
///
/// Grouping the two serves two purposes. First, the checks RFC 9180 requires
/// happen once, here, so no PSK-mode entry point can be reached with malformed
/// inputs. Second, it removes a pair of adjacent same-typed `&[u8]` parameters
/// from every PSK-mode signature: `psk` is secret and `psk_id` is usually
/// public, so transposing them at a call site would silently key the session
/// off a public value — and it would still compile.
///
/// # Example
///
/// ```
/// use hpke_ng::{HpkeError, Psk};
///
/// let psk = Psk::new(&[0x42; 32], b"my-psk-id")?;
/// assert_eq!(psk.id(), b"my-psk-id");
///
/// // Too short to carry 32 bytes of entropy.
/// assert_eq!(Psk::new(b"hunter2", b"my-psk-id"), Err(HpkeError::InsecurePsk));
/// # Ok::<_, HpkeError>(())
/// ```
#[derive(Clone, Copy)]
pub struct Psk<'a> {
	secret: &'a [u8],
	id: &'a [u8],
}

/// Constant-time in the secret; the identifier is public and compared normally.
impl PartialEq for Psk<'_> {
	fn eq(&self, other: &Self) -> bool {
		self.id == other.id && bool::from(self.secret.ct_eq(other.secret))
	}
}

impl Eq for Psk<'_> {}

impl<'a> Psk<'a> {
	/// Bundle a PSK with its identifier.
	///
	/// `secret` MUST be at least [`MIN_PSK_LEN`] bytes of high-entropy random
	/// data. Length is enforced; entropy is the caller's responsibility. Do
	/// **not** pass a password or other low-entropy string without first running
	/// it through a slow password-hashing KDF such as Argon2.
	///
	/// # Errors
	///
	/// - [`HpkeError::InconsistentPsk`] if exactly one of `secret` and `id` is
	///   empty.
	/// - [`HpkeError::MissingPsk`] if both are empty. PSK-free operation is not
	///   expressed by an empty `Psk`; it is expressed by calling the Base or
	///   Auth entry points, which take no PSK at all.
	/// - [`HpkeError::InsecurePsk`] if `secret` is shorter than
	///   [`MIN_PSK_LEN`].
	pub fn new(secret: &'a [u8], id: &'a [u8]) -> Result<Self, HpkeError> {
		if secret.is_empty() != id.is_empty() {
			return Err(HpkeError::InconsistentPsk);
		}
		if secret.is_empty() {
			return Err(HpkeError::MissingPsk);
		}
		if secret.len() < MIN_PSK_LEN {
			return Err(HpkeError::InsecurePsk);
		}
		Ok(Self { secret, id })
	}

	/// The PSK bytes, used as the `secret` extraction salt.
	#[must_use]
	pub const fn secret(&self) -> &'a [u8] {
		self.secret
	}

	/// The PSK identifier, hashed into `ks_context` as `psk_id_hash`.
	#[must_use]
	pub const fn id(&self) -> &'a [u8] {
		self.id
	}
}

impl fmt::Debug for Psk<'_> {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		// The identifier is public; the PSK is not. Redact it so that debug
		// output — which typically reaches logs — cannot leak the key.
		f.debug_struct("Psk")
			.field("secret", &format_args!("<{} bytes>", self.secret.len()))
			.field("id", &self.id)
			.finish()
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use alloc::format;

	#[test]
	fn validation_matrix() {
		let good = [0u8; MIN_PSK_LEN];
		assert!(Psk::new(&good, b"id").is_ok());
		// Exactly at the boundary is fine; one byte short is not.
		assert_eq!(
			Psk::new(&[0u8; MIN_PSK_LEN - 1], b"id"),
			Err(HpkeError::InsecurePsk)
		);
		// Half-supplied inputs.
		assert_eq!(Psk::new(&good, b""), Err(HpkeError::InconsistentPsk));
		assert_eq!(Psk::new(b"", b"id"), Err(HpkeError::InconsistentPsk));
		// Fully absent: use the Base/Auth entry points instead.
		assert_eq!(Psk::new(b"", b""), Err(HpkeError::MissingPsk));
	}

	#[test]
	fn accessors_round_trip() {
		let secret = [0x5Au8; MIN_PSK_LEN];
		let psk = Psk::new(&secret, b"the-id").unwrap();
		assert_eq!(psk.secret(), &secret);
		assert_eq!(psk.id(), b"the-id");
	}

	#[test]
	fn equality_compares_both_fields() {
		let a = [0x11u8; MIN_PSK_LEN];
		let mut b = a;
		b[MIN_PSK_LEN - 1] ^= 1;
		assert_eq!(Psk::new(&a, b"id").unwrap(), Psk::new(&a, b"id").unwrap());
		assert_ne!(Psk::new(&a, b"id").unwrap(), Psk::new(&b, b"id").unwrap());
		assert_ne!(Psk::new(&a, b"id").unwrap(), Psk::new(&a, b"id-x").unwrap());
	}

	#[test]
	fn debug_redacts_the_secret() {
		let psk = Psk::new(&[0xAAu8; MIN_PSK_LEN], b"the-id").unwrap();
		let rendered = format!("{psk:?}");
		// The length is disclosed, the bytes are not: were the secret rendered
		// as a byte slice, 0xAA would appear as `170`.
		assert!(rendered.contains("<32 bytes>"), "{rendered}");
		assert!(!rendered.contains("170"), "PSK bytes leaked: {rendered}");
		// The identifier is public and is shown. It is arbitrary bytes rather
		// than text, so it renders as a byte slice: `id: [116, 104, ...]`.
		assert!(rendered.contains("id: [116,"), "{rendered}");
	}
}
