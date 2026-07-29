//! HPKE Key Encapsulation Mechanisms (RFC 9180 §4 + §7.1).

use alloc::vec::Vec;

use rand_core::CryptoRng;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::HpkeError;
use crate::sealed::Sealed;

pub mod dh;
#[cfg(feature = "pq")]
pub mod pq;

/// `suite_id = "KEM" || I2OSP(kem_id, 2)` (RFC 9180 §4.1).
///
/// Every KEM-level labeled KDF call is domain-separated by this value, so it is
/// what keeps KEMs sharing a primitive — the two ML-KEM parameter sets, say —
/// from deriving identical keys off identical input.
#[inline]
pub(crate) fn kem_suite_id(id: u16) -> [u8; 5] {
	let mut s = [0u8; 5];
	s[..3].copy_from_slice(b"KEM");
	s[3..].copy_from_slice(&id.to_be_bytes());
	s
}

/// Sealed trait for HPKE-supported KEMs (RFC 9180 §7.1).
pub trait Kem: Sealed {
	/// IANA KEM ID (RFC 9180 §7.1).
	const ID: u16;
	/// Length of an encapsulated key in bytes (`Nenc`).
	const ENCAPPED_KEY_LEN: usize;
	/// Length of a public key in bytes (`Npk`).
	const PUBLIC_KEY_LEN: usize;
	/// Length of a private key in bytes (`Nsk`).
	const PRIVATE_KEY_LEN: usize;
	/// Length of a shared secret in bytes (`Nsecret`).
	const SHARED_SECRET_LEN: usize;

	/// Public key type. Always representable as bytes.
	type PublicKey: AsRef<[u8]> + Clone;
	/// Private key type — zeroized on drop.
	type PrivateKey: Zeroize + ZeroizeOnDrop;
	/// Encapsulated key type. Always representable as bytes.
	type EncappedKey: AsRef<[u8]> + Clone;
	/// Shared secret returned by encap/decap. Zeroized on drop, like
	/// [`PrivateKey`](Self::PrivateKey) — the bound carries that guarantee so it
	/// cannot be forgotten by an implementation.
	type SharedSecret: AsRef<[u8]> + Zeroize + ZeroizeOnDrop;

	/// Generate a fresh key pair.
	fn generate<R: CryptoRng>(
		rng: &mut R,
	) -> Result<(Self::PrivateKey, Self::PublicKey), HpkeError>;

	/// `DeriveKeyPair(ikm)` — RFC 9180 §7.1.3 for the DHKEMs,
	/// draft-ietf-hpke-pq §3.2/§4.2 for the post-quantum KEMs.
	///
	/// # Security
	///
	/// `ikm` MUST carry at least [`PRIVATE_KEY_LEN`](Self::PRIVATE_KEY_LEN)
	/// bytes of entropy and MUST come from a CSPRNG or an equivalently strong
	/// source. The derivation is fully deterministic, so a guessable `ikm`
	/// yields a guessable private key: `derive_key_pair(b"")` and
	/// `derive_key_pair(b"password")` both succeed and both produce a key pair
	/// any attacker can reproduce.
	///
	/// Entropy is not observable, so — unlike [`Psk::new`](crate::Psk::new),
	/// where a length floor is a usable proxy — no check is enforced here: the
	/// RFC's KAT vectors and the PQ drafts both admit short `ikm`, and a length
	/// floor would reject conformant input while still admitting a long
	/// low-entropy string. Prefer [`generate`](Self::generate) unless you
	/// specifically need deterministic key derivation, and never derive from a
	/// password without first running it through a slow password-hashing KDF
	/// such as Argon2.
	fn derive_key_pair(ikm: &[u8]) -> Result<(Self::PrivateKey, Self::PublicKey), HpkeError>;

	/// Encapsulate a shared secret to a recipient public key.
	fn encap<R: CryptoRng>(
		rng: &mut R,
		pk_r: &Self::PublicKey,
	) -> Result<(Self::SharedSecret, Self::EncappedKey), HpkeError>;

	/// Decapsulate `enc` with the recipient private key.
	fn decap(
		enc: &Self::EncappedKey,
		sk_r: &Self::PrivateKey,
	) -> Result<Self::SharedSecret, HpkeError>;

	/// Decode a public key from its wire bytes.
	fn pk_from_bytes(b: &[u8]) -> Result<Self::PublicKey, HpkeError>;
	/// Decode a private key from its wire bytes.
	fn sk_from_bytes(b: &[u8]) -> Result<Self::PrivateKey, HpkeError>;
	/// Decode an encapsulated key from its wire bytes.
	fn enc_from_bytes(b: &[u8]) -> Result<Self::EncappedKey, HpkeError>;

	/// Encode a public key to its wire bytes. Equivalent to `pk.as_ref()`, which
	/// avoids the allocation when a slice will do.
	fn pk_to_bytes(pk: &Self::PublicKey) -> Vec<u8>;

	/// Encode a private key to its wire bytes.
	///
	/// Output is wrapped in [`Zeroizing`] so the heap copy is zeroed when
	/// dropped. Callers persisting key material must place it in zeroizing
	/// storage as well; otherwise scrubbing happens only at the boundary.
	fn sk_to_bytes(sk: &Self::PrivateKey) -> Zeroizing<Vec<u8>>;
}

/// KEMs that additionally support the authenticated mode (`Auth`/`AuthPsk`).
///
/// Only DHKEM constructions implement this. Post-quantum KEMs intentionally do
/// not, so calling `Hpke::seal_auth` with a PQ KEM is a compile-time error.
pub trait AuthKem: Kem {
	/// `AuthEncap(pk_r, sk_s)` (RFC 9180 §4.1).
	fn auth_encap<R: CryptoRng>(
		rng: &mut R,
		pk_r: &Self::PublicKey,
		sk_s: &Self::PrivateKey,
	) -> Result<(Self::SharedSecret, Self::EncappedKey), HpkeError>;

	/// `AuthDecap(enc, sk_r, pk_s)` (RFC 9180 §4.1).
	fn auth_decap(
		enc: &Self::EncappedKey,
		sk_r: &Self::PrivateKey,
		pk_s: &Self::PublicKey,
	) -> Result<Self::SharedSecret, HpkeError>;
}
