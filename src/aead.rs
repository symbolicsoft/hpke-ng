//! HPKE AEAD primitives (RFC 9180 §7.3).

use alloc::vec::Vec;

use crate::HpkeError;
use crate::sealed::Sealed;

/// Sealed trait for HPKE-supported AEAD ciphersuite components.
///
/// The cipher state is built once at key-schedule time by [`init`](Aead::init)
/// and reused for every message, which keeps the AES key expansion and `GHash`
/// precompute off the per-message path. Encryption itself lives on the
/// [`SealingAead`] subtrait, so an export-only ciphersuite cannot reach
/// `seal_*`/`open_*` at all.
pub trait Aead: Sealed {
	/// IANA AEAD ID (RFC 9180 §7.3).
	const ID: u16;
	/// Key length in bytes (`Nk`).
	const KEY_LEN: usize;
	/// Nonce length in bytes (`Nn`).
	const NONCE_LEN: usize;
	/// Authentication tag length in bytes (`Nt`).
	const TAG_LEN: usize;

	/// Cached cipher state. For ChaCha20-Poly1305 this is just the key, since
	/// the primitive re-initializes per call anyway; for AES-GCM it is the
	/// expanded round keys plus the precomputed `GHash` table, which is the
	/// part worth not recomputing per message.
	type Cipher;

	/// Initialize the cached cipher state from a `KEY_LEN`-byte key.
	fn init(key: &[u8]) -> Result<Self::Cipher, HpkeError>;
}

/// Marker subtrait for AEADs that actually encrypt — that is, every one except
/// [`ExportOnly`].
///
/// Each direction collapses every underlying-cipher failure into one error
/// ([`SealError`](HpkeError::SealError) / [`OpenError`](HpkeError::OpenError)),
/// so an `open` failure discloses nothing about its cause.
pub trait SealingAead: Aead {
	/// Encrypt `pt` with the cached `cipher` state, `nonce`, and `aad`.
	/// Output is `pt.len() + TAG_LEN` bytes.
	fn seal(
		cipher: &Self::Cipher,
		nonce: &[u8],
		aad: &[u8],
		pt: &[u8],
	) -> Result<Vec<u8>, HpkeError>;
	/// Decrypt `ct` (which includes the tag) with the cached `cipher`
	/// state, `nonce`, and `aad`.
	fn open(
		cipher: &Self::Cipher,
		nonce: &[u8],
		aad: &[u8],
		ct: &[u8],
	) -> Result<Vec<u8>, HpkeError>;
}

/// ChaCha20-Poly1305 (RFC 9180 §7.3, ID `0x0003`).
#[derive(Debug, Clone, Copy, Default)]
pub struct ChaCha20Poly1305;

impl Sealed for ChaCha20Poly1305 {}
impl Aead for ChaCha20Poly1305 {
	const ID: u16 = 0x0003;
	const KEY_LEN: usize = 32;
	const NONCE_LEN: usize = 12;
	const TAG_LEN: usize = 16;

	type Cipher = chacha20poly1305::ChaCha20Poly1305;

	fn init(key: &[u8]) -> Result<Self::Cipher, HpkeError> {
		use chacha20poly1305::KeyInit;
		chacha20poly1305::ChaCha20Poly1305::new_from_slice(key)
			.map_err(|_| HpkeError::AeadInitError)
	}
}
impl SealingAead for ChaCha20Poly1305 {
	fn seal(
		cipher: &Self::Cipher,
		nonce: &[u8],
		aad: &[u8],
		pt: &[u8],
	) -> Result<Vec<u8>, HpkeError> {
		use chacha20poly1305::{
			Nonce,
			aead::{Aead as _, Payload},
		};
		// The nonce always has length `NONCE_LEN` here (sliced by the caller);
		// the fallible conversion replaces `from_slice`'s panic with an error.
		let nonce = Nonce::try_from(nonce).map_err(|_| HpkeError::SealError)?;
		cipher
			.encrypt(&nonce, Payload { msg: pt, aad })
			.map_err(|_| HpkeError::SealError)
	}
	fn open(
		cipher: &Self::Cipher,
		nonce: &[u8],
		aad: &[u8],
		ct: &[u8],
	) -> Result<Vec<u8>, HpkeError> {
		use chacha20poly1305::{
			Nonce,
			aead::{Aead as _, Payload},
		};
		// See `seal` on the nonce-length invariant and fallible conversion.
		let nonce = Nonce::try_from(nonce).map_err(|_| HpkeError::OpenError)?;
		cipher
			.decrypt(&nonce, Payload { msg: ct, aad })
			.map_err(|_| HpkeError::OpenError)
	}
}

/// AES-128-GCM (RFC 9180 §7.3, ID `0x0001`).
///
/// Constant-time only on platforms with hardware AES-NI/PCLMULQDQ. Prefer
/// [`ChaCha20Poly1305`] on platforms without these instructions.
#[derive(Debug, Clone, Copy, Default)]
pub struct Aes128Gcm;

impl Sealed for Aes128Gcm {}
impl Aead for Aes128Gcm {
	const ID: u16 = 0x0001;
	const KEY_LEN: usize = 16;
	const NONCE_LEN: usize = 12;
	const TAG_LEN: usize = 16;

	type Cipher = aes_gcm::Aes128Gcm;

	fn init(key: &[u8]) -> Result<Self::Cipher, HpkeError> {
		use aes_gcm::KeyInit;
		aes_gcm::Aes128Gcm::new_from_slice(key).map_err(|_| HpkeError::AeadInitError)
	}
}
impl SealingAead for Aes128Gcm {
	fn seal(
		cipher: &Self::Cipher,
		nonce: &[u8],
		aad: &[u8],
		pt: &[u8],
	) -> Result<Vec<u8>, HpkeError> {
		use aes_gcm::aead::Aead as _;
		// See the ChaCha20-Poly1305 impl on the nonce-length invariant.
		let nonce = aes_gcm::Nonce::try_from(nonce).map_err(|_| HpkeError::SealError)?;
		cipher
			.encrypt(&nonce, aead::Payload { msg: pt, aad })
			.map_err(|_| HpkeError::SealError)
	}
	fn open(
		cipher: &Self::Cipher,
		nonce: &[u8],
		aad: &[u8],
		ct: &[u8],
	) -> Result<Vec<u8>, HpkeError> {
		use aes_gcm::aead::Aead as _;
		// See the ChaCha20-Poly1305 impl on the nonce-length invariant.
		let nonce = aes_gcm::Nonce::try_from(nonce).map_err(|_| HpkeError::OpenError)?;
		cipher
			.decrypt(&nonce, aead::Payload { msg: ct, aad })
			.map_err(|_| HpkeError::OpenError)
	}
}

/// AES-256-GCM (RFC 9180 §7.3, ID `0x0002`).
///
/// Constant-time only on platforms with hardware AES-NI/PCLMULQDQ.
#[derive(Debug, Clone, Copy, Default)]
pub struct Aes256Gcm;

impl Sealed for Aes256Gcm {}
impl Aead for Aes256Gcm {
	const ID: u16 = 0x0002;
	const KEY_LEN: usize = 32;
	const NONCE_LEN: usize = 12;
	const TAG_LEN: usize = 16;

	type Cipher = aes_gcm::Aes256Gcm;

	fn init(key: &[u8]) -> Result<Self::Cipher, HpkeError> {
		use aes_gcm::KeyInit;
		aes_gcm::Aes256Gcm::new_from_slice(key).map_err(|_| HpkeError::AeadInitError)
	}
}
impl SealingAead for Aes256Gcm {
	fn seal(
		cipher: &Self::Cipher,
		nonce: &[u8],
		aad: &[u8],
		pt: &[u8],
	) -> Result<Vec<u8>, HpkeError> {
		use aes_gcm::aead::Aead as _;
		// See the ChaCha20-Poly1305 impl on the nonce-length invariant.
		let nonce = aes_gcm::Nonce::try_from(nonce).map_err(|_| HpkeError::SealError)?;
		cipher
			.encrypt(&nonce, aead::Payload { msg: pt, aad })
			.map_err(|_| HpkeError::SealError)
	}
	fn open(
		cipher: &Self::Cipher,
		nonce: &[u8],
		aad: &[u8],
		ct: &[u8],
	) -> Result<Vec<u8>, HpkeError> {
		use aes_gcm::aead::Aead as _;
		// See the ChaCha20-Poly1305 impl on the nonce-length invariant.
		let nonce = aes_gcm::Nonce::try_from(nonce).map_err(|_| HpkeError::OpenError)?;
		cipher
			.decrypt(&nonce, aead::Payload { msg: ct, aad })
			.map_err(|_| HpkeError::OpenError)
	}
}

/// Export-only "AEAD" marker (RFC 9180 §7.3, ID `0xFFFF`).
///
/// Configurations parameterized over `ExportOnly` cannot encrypt or decrypt;
/// only the export methods are available, because `ExportOnly` does not
/// implement [`SealingAead`].
#[derive(Debug, Clone, Copy, Default)]
pub struct ExportOnly;

impl Sealed for ExportOnly {}
impl Aead for ExportOnly {
	const ID: u16 = 0xFFFF;
	const KEY_LEN: usize = 0;
	const NONCE_LEN: usize = 0;
	const TAG_LEN: usize = 0;

	type Cipher = ();

	fn init(_key: &[u8]) -> Result<Self::Cipher, HpkeError> {
		Ok(())
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use hex::FromHex;

	/// RFC 8439 §2.8.2 test vector.
	#[test]
	fn rfc8439_chacha20poly1305_test_vector() {
		let key = Vec::from_hex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f")
			.unwrap();
		let nonce = Vec::from_hex("070000004041424344454647").unwrap();
		let aad = Vec::from_hex("50515253c0c1c2c3c4c5c6c7").unwrap();
		let pt = b"Ladies and Gentlemen of the class of '99: \
                   If I could offer you only one tip for the future, sunscreen would be it.";

		let cipher = ChaCha20Poly1305::init(&key).unwrap();
		let ct = ChaCha20Poly1305::seal(&cipher, &nonce, &aad, pt).unwrap();
		let recovered = ChaCha20Poly1305::open(&cipher, &nonce, &aad, &ct).unwrap();
		assert_eq!(recovered, pt);

		let mut bad = ct.clone();
		bad[0] ^= 1;
		assert_eq!(
			ChaCha20Poly1305::open(&cipher, &nonce, &aad, &bad),
			Err(HpkeError::OpenError)
		);
	}

	#[test]
	fn aes128gcm_roundtrip_short() {
		let key = [0u8; 16];
		let nonce = [0u8; 12];
		let aad = b"";
		let pt = b"hello";
		let cipher = Aes128Gcm::init(&key).unwrap();
		let ct = Aes128Gcm::seal(&cipher, &nonce, aad, pt).unwrap();
		assert_eq!(ct.len(), pt.len() + 16);
		assert_eq!(Aes128Gcm::open(&cipher, &nonce, aad, &ct).unwrap(), pt);
	}

	#[test]
	fn aes256gcm_roundtrip_short() {
		let key = [0u8; 32];
		let nonce = [0u8; 12];
		let pt = b"world";
		let cipher = Aes256Gcm::init(&key).unwrap();
		let ct = Aes256Gcm::seal(&cipher, &nonce, b"aad", pt).unwrap();
		assert_eq!(Aes256Gcm::open(&cipher, &nonce, b"aad", &ct).unwrap(), pt);
	}

	#[test]
	fn aes128gcm_rejects_bad_key_len() {
		let r = Aes128Gcm::init(&[0u8; 15]);
		assert_eq!(r.err(), Some(HpkeError::AeadInitError));
	}

	/// Guards the `aes/zeroize` entry in `Cargo.toml`: `aes_gcm::AesGcm` has no
	/// `Drop`, so without it the cached round keys survive in freed memory.
	#[test]
	fn aes_round_keys_are_scrubbed_on_drop() {
		fn assert_zeroize_on_drop<T: zeroize::ZeroizeOnDrop>() {}
		assert_zeroize_on_drop::<aes::Aes128>();
		assert_zeroize_on_drop::<aes::Aes256>();
	}

	#[test]
	fn export_only_implements_aead_only() {
		fn assert_aead<A: Aead>() {}
		assert_aead::<ExportOnly>();
		assert_eq!(ExportOnly::ID, 0xFFFF);
		assert_eq!(ExportOnly::KEY_LEN, 0);
		assert_eq!(ExportOnly::NONCE_LEN, 0);
		assert_eq!(ExportOnly::TAG_LEN, 0);
		// `init` accepts the empty key cleanly.
		assert!(ExportOnly::init(&[]).is_ok());
	}
}
