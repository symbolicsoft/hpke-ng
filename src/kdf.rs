//! HPKE Key Derivation Functions (RFC 9180 §4 + RFC 5869).

use alloc::vec::Vec;

use hkdf::{Hkdf, HkdfExtract};
use sha2::{Sha256, Sha384, Sha512};
use zeroize::{Zeroize, Zeroizing};

use crate::HpkeError;
use crate::sealed::Sealed;

/// Sealed trait for HPKE-supported KDFs.
pub trait Kdf: Sealed {
	/// IANA KDF ID (RFC 9180 §7.2).
	const ID: u16;
	/// Underlying hash output length in bytes (`Nh`).
	const HASH_LEN: usize;
	/// HKDF-Extract over a sequence of ikm pieces.
	///
	/// Pieces are fed into the inner HMAC via `update` without concatenation,
	/// avoiding the temporary `Vec` for every labeled-extract call.
	fn extract(salt: &[u8], ikm_pieces: &[&[u8]]) -> Vec<u8>;
	/// HKDF-Expand over a sequence of info pieces.
	///
	/// Pieces are fed via `Hkdf::expand_multi_info` without concatenation.
	fn expand(prk: &[u8], info_pieces: &[&[u8]], out_len: usize) -> Result<Vec<u8>, HpkeError>;
}

macro_rules! hkdf_impl {
	($name:ident, $id:expr, $hash_len:expr, $hash:ty, $doc:literal) => {
		#[doc = $doc]
		#[derive(Debug, Clone, Copy, Default)]
		pub struct $name;

		impl Sealed for $name {}
		impl Kdf for $name {
			const ID: u16 = $id;
			const HASH_LEN: usize = $hash_len;

			fn extract(salt: &[u8], ikm_pieces: &[&[u8]]) -> Vec<u8> {
				let mut ext = HkdfExtract::<$hash>::new(Some(salt));
				for piece in ikm_pieces {
					ext.input_ikm(piece);
				}
				// `hkdf` 0.12's `Output<H>` (a `GenericArray`) has no
				// `ZeroizeOnDrop`. Copy the bytes out, then explicitly
				// scrub the temporary before it goes out of scope.
				let (mut prk, _) = ext.finalize();
				let result = prk.to_vec();
				prk.as_mut_slice().zeroize();
				result
			}

			fn expand(
				prk: &[u8],
				info_pieces: &[&[u8]],
				out_len: usize,
			) -> Result<Vec<u8>, HpkeError> {
				let hk =
					Hkdf::<$hash>::from_prk(prk).map_err(|_| HpkeError::DeriveKeyPairError)?;
				let mut out = alloc::vec![0u8; out_len];
				hk.expand_multi_info(info_pieces, &mut out)
					.map_err(|_| HpkeError::ExportLengthExceeded)?;
				Ok(out)
			}
		}
	};
}

hkdf_impl!(
	HkdfSha256,
	0x0001,
	32,
	Sha256,
	"HKDF-SHA-256 (RFC 9180 §7.2, ID `0x0001`)."
);
hkdf_impl!(
	HkdfSha384,
	0x0002,
	48,
	Sha384,
	"HKDF-SHA-384 (RFC 9180 §7.2, ID `0x0002`)."
);
hkdf_impl!(
	HkdfSha512,
	0x0003,
	64,
	Sha512,
	"HKDF-SHA-512 (RFC 9180 §7.2, ID `0x0003`)."
);

/// HPKE `LabeledExtract` (RFC 9180 §4).
///
/// `ikm` is treated as a single piece. For piecewise IKM (e.g. when the
/// caller already has the ikm split across slices), use
/// [`labeled_extract_pieces`].
pub(crate) fn labeled_extract<F: Kdf>(
	salt: &[u8],
	suite_id: &[u8],
	label: &[u8],
	ikm: &[u8],
) -> Vec<u8> {
	F::extract(salt, &[b"HPKE-v1", suite_id, label, ikm])
}

/// At most 3 prefix slots + N user slots; current piecewise callers stay
/// well under this. Used by both the extract and expand piecewise helpers.
const MAX_EXTRACT_PIECES: usize = 8;
const MAX_EXPAND_PIECES: usize = 16;

/// HPKE `LabeledExtract` over piecewise IKM.
///
/// Used when the caller already has `ikm` split across multiple slices and
/// would otherwise have to concatenate them just to pass a single `&[u8]`.
#[allow(dead_code)]
pub(crate) fn labeled_extract_pieces<F: Kdf>(
	salt: &[u8],
	suite_id: &[u8],
	label: &[u8],
	ikm_pieces: &[&[u8]],
) -> Vec<u8> {
	let mut all: [&[u8]; MAX_EXTRACT_PIECES] = [&[]; MAX_EXTRACT_PIECES];
	all[0] = b"HPKE-v1";
	all[1] = suite_id;
	all[2] = label;
	let n = ikm_pieces.len();
	debug_assert!(3 + n <= MAX_EXTRACT_PIECES);
	for (i, p) in ikm_pieces.iter().enumerate() {
		all[3 + i] = p;
	}
	F::extract(salt, &all[..3 + n])
}

/// HPKE `LabeledExpand` (RFC 9180 §4).
#[allow(dead_code)]
pub(crate) fn labeled_expand<F: Kdf>(
	prk: &[u8],
	suite_id: &[u8],
	label: &[u8],
	info: &[u8],
	out_len: usize,
) -> Result<Vec<u8>, HpkeError> {
	let l_u16: u16 = out_len
		.try_into()
		.map_err(|_| HpkeError::ExportLengthExceeded)?;
	let l_be = l_u16.to_be_bytes();
	F::expand(prk, &[&l_be, b"HPKE-v1", suite_id, label, info], out_len)
}

/// HPKE `LabeledExpand` over piecewise `info`.
#[allow(dead_code)]
pub(crate) fn labeled_expand_pieces<F: Kdf>(
	prk: &[u8],
	suite_id: &[u8],
	label: &[u8],
	info_pieces: &[&[u8]],
	out_len: usize,
) -> Result<Vec<u8>, HpkeError> {
	let l_u16: u16 = out_len
		.try_into()
		.map_err(|_| HpkeError::ExportLengthExceeded)?;
	let l_be = l_u16.to_be_bytes();
	let mut all: [&[u8]; MAX_EXPAND_PIECES] = [&[]; MAX_EXPAND_PIECES];
	all[0] = &l_be;
	all[1] = b"HPKE-v1";
	all[2] = suite_id;
	all[3] = label;
	let n = info_pieces.len();
	debug_assert!(4 + n <= MAX_EXPAND_PIECES);
	for (i, p) in info_pieces.iter().enumerate() {
		all[4 + i] = p;
	}
	F::expand(prk, &all[..4 + n], out_len)
}

/// Convenience: extract → wrap in `Zeroizing` so the PRK is scrubbed when
/// dropped. Used at every key-schedule site where the PRK is secret.
#[allow(dead_code)]
#[inline]
pub(crate) fn labeled_extract_z<F: Kdf>(
	salt: &[u8],
	suite_id: &[u8],
	label: &[u8],
	ikm: &[u8],
) -> Zeroizing<Vec<u8>> {
	Zeroizing::new(labeled_extract::<F>(salt, suite_id, label, ikm))
}

#[cfg(test)]
mod tests {
	use super::*;
	use hex::FromHex;

	/// RFC 5869 Appendix A.1 — Basic test case with SHA-256.
	#[test]
	fn rfc5869_a1_extract_expand_sha256() {
		let ikm = Vec::from_hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap();
		let salt = Vec::from_hex("000102030405060708090a0b0c").unwrap();
		let info = Vec::from_hex("f0f1f2f3f4f5f6f7f8f9").unwrap();
		let l = 42;
		let expected_prk =
			Vec::from_hex("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5")
				.unwrap();
		let expected_okm = Vec::from_hex(
			"3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
		)
		.unwrap();

		let prk = HkdfSha256::extract(&salt, &[&ikm]);
		assert_eq!(prk, expected_prk);

		let okm = HkdfSha256::expand(&prk, &[&info], l).unwrap();
		assert_eq!(okm, expected_okm);
	}

	#[test]
	fn extract_pieces_matches_concat() {
		let salt = b"salt";
		let prk_concat = HkdfSha256::extract(salt, &[b"abcdef"]);
		let prk_pieces = HkdfSha256::extract(salt, &[b"abc", b"def"]);
		assert_eq!(prk_concat, prk_pieces);
	}

	#[test]
	fn expand_pieces_matches_concat() {
		let prk = [0u8; 32];
		let okm_concat = HkdfSha256::expand(&prk, &[b"abcdef"], 32).unwrap();
		let okm_pieces = HkdfSha256::expand(&prk, &[b"abc", b"def"], 32).unwrap();
		assert_eq!(okm_concat, okm_pieces);
	}

	#[test]
	fn expand_rejects_oversize() {
		let prk = [0u8; 32];
		assert_eq!(
			HkdfSha256::expand(&prk, &[b"info"], 8161),
			Err(HpkeError::ExportLengthExceeded)
		);
	}

	#[test]
	fn sha384_extract_expand_roundtrip() {
		let prk = HkdfSha384::extract(b"salt", &[b"ikm"]);
		assert_eq!(prk.len(), 48);
		let okm = HkdfSha384::expand(&prk, &[b"info"], 48).unwrap();
		assert_eq!(okm.len(), 48);
		let okm2 = HkdfSha384::expand(&prk, &[b"info"], 48).unwrap();
		assert_eq!(okm, okm2);
	}

	#[test]
	fn sha512_extract_expand_roundtrip() {
		let prk = HkdfSha512::extract(b"salt", &[b"ikm"]);
		assert_eq!(prk.len(), 64);
		let okm = HkdfSha512::expand(&prk, &[b"info"], 64).unwrap();
		assert_eq!(okm.len(), 64);
	}

	#[test]
	fn expand_max_lengths() {
		let prk384 = HkdfSha384::extract(&[], &[b"ikm"]);
		assert!(HkdfSha384::expand(&prk384, &[b"info"], 255 * 48).is_ok());
		assert_eq!(
			HkdfSha384::expand(&prk384, &[b"info"], 255 * 48 + 1),
			Err(HpkeError::ExportLengthExceeded)
		);
	}

	#[test]
	fn labeled_helpers_compose() {
		let suite_id = b"KEM\x00\x20";
		let prk = labeled_extract::<HkdfSha256>(&[], suite_id, b"eae_prk", b"shared_secret_bytes");
		assert_eq!(prk.len(), 32);
		let okm =
			labeled_expand::<HkdfSha256>(&prk, suite_id, b"shared_secret", b"context", 32).unwrap();
		assert_eq!(okm.len(), 32);
		let okm2 =
			labeled_expand::<HkdfSha256>(&prk, suite_id, b"shared_secret", b"context", 32).unwrap();
		assert_eq!(okm, okm2);
	}

	#[test]
	fn labeled_pieces_match_single() {
		let suite_id = b"KEM\x00\x20";
		let single = labeled_extract::<HkdfSha256>(&[], suite_id, b"eae_prk", b"shared_secret");
		let pieces = labeled_extract_pieces::<HkdfSha256>(
			&[],
			suite_id,
			b"eae_prk",
			&[b"shared_", b"secret"],
		);
		assert_eq!(single, pieces);

		let prk = [0u8; 32];
		let s_exp = labeled_expand::<HkdfSha256>(&prk, suite_id, b"k", b"context", 32).unwrap();
		let p_exp =
			labeled_expand_pieces::<HkdfSha256>(&prk, suite_id, b"k", &[b"con", b"text"], 32)
				.unwrap();
		assert_eq!(s_exp, p_exp);
	}

	#[test]
	fn labeled_expand_rejects_u16_overflow() {
		let prk = [0u8; 32];
		let r = labeled_expand::<HkdfSha256>(&prk, b"", b"", b"", 65_536);
		assert_eq!(r, Err(HpkeError::ExportLengthExceeded));
	}
}
