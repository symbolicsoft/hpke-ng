//! Post-quantum KEMs (X-Wing, ML-KEM-768, ML-KEM-1024).
//!
//! Available only with the `pq` feature. These KEMs intentionally do **not**
//! implement [`AuthKem`](crate::kem::AuthKem); HPKE Auth/AuthPsk modes are
//! defined only for DHKEMs.
//!
//! RFC 9180 predates all three, so their HPKE registration — KEM IDs, length
//! parameters, and `DeriveKeyPair` — comes from
//! [draft-ietf-hpke-pq](https://datatracker.ietf.org/doc/draft-ietf-hpke-pq/)
//! (§3 for ML-KEM, §4 for the hybrids, where KEM ID `0x647A`
//! `MLKEM768-X25519` is X-Wing). `DeriveKeyPair` there is built on the
//! one-stage-KDF `LabeledDerive` of
//! [draft-ietf-hpke-hpke](https://datatracker.ietf.org/doc/draft-ietf-hpke-hpke/)
//! §4 rather than on RFC 9180's HKDF-based `LabeledExtract`/`LabeledExpand`.

use alloc::vec::Vec;

use rand_core::CryptoRng;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::HpkeError;
use crate::kem::{Kem, kem_suite_id};
use crate::sealed::Sealed;

/// `DeriveKeyPair` label — draft-ietf-hpke-pq §3.2 (ML-KEM) and §4.2 (hybrids).
const DERIVE_KEY_PAIR_LABEL: &[u8] = b"DeriveKeyPair";

/// `XWingPrivateKey::seed` is a fixed `[u8; 32]` that `sk_from_bytes` fills with
/// `copy_from_slice` after length-checking against `x_wing::DECAPSULATION_KEY_SIZE`.
/// Those two are only equal by inspection of the current upstream release, and
/// `x-wing` is pre-1.0, so a semver-compatible bump could change the constant and
/// turn that check into a panic on well-formed input. Pin the relationship here so
/// the mismatch is a build failure instead.
const _: () = assert!(
	x_wing::DECAPSULATION_KEY_SIZE == 32,
	"XWingPrivateKey::seed is [u8; 32]; upstream decapsulation-key size changed"
);

/// Copy a KEM shared secret into this crate's fixed 32-byte wrapper.
///
/// `copy_from_slice` would panic if an upstream release ever changed its
/// shared-secret width. Nothing downstream of a KEM should be able to turn a
/// dependency bump into a panic inside `decap`, so the length is checked.
fn shared_secret_bytes(ss: &[u8]) -> Result<[u8; 32], HpkeError> {
	let mut out = [0u8; 32];
	if ss.len() != out.len() {
		return Err(HpkeError::DecapError);
	}
	out.copy_from_slice(ss);
	Ok(out)
}

/// `SHAKE256.LabeledDerive(ikm, label, context, L)` — the one-stage-KDF labeled
/// derivation of draft-ietf-hpke-hpke §4:
///
/// ```text
/// labeled_ikm = ikm || "HPKE-v1" || suite_id
///               || lengthPrefixed(label) || I2OSP(L, 2) || context
/// return SHAKE256(labeled_ikm, L)
/// ```
///
/// where `lengthPrefixed(x) = I2OSP(len(x), 2) || x`. `context` is empty at
/// every call site here, so it is not a parameter.
///
/// The field order deliberately differs from RFC 9180's `LabeledExpand`, which
/// leads with `I2OSP(L, 2)` and does not length-prefix the label. This is a
/// separate construction introduced for XOF-based KDFs; do not unify them.
fn shake256_labeled_derive(
	suite_id: [u8; 5],
	label: &[u8],
	ikm: &[u8],
	out: &mut [u8],
) -> Result<(), HpkeError> {
	use shake::digest::{ExtendableOutput, Update, XofReader};

	// Both lengths are compile-time constants at every call site (a 13-byte
	// label, a 32- or 64-byte output). Converting fallibly rather than with a
	// truncating cast keeps this free of unreachable panics.
	let label_len = u16::try_from(label.len()).map_err(|_| HpkeError::DeriveKeyPairError)?;
	let out_len = u16::try_from(out.len()).map_err(|_| HpkeError::DeriveKeyPairError)?;

	let mut h = shake::Shake256::default();
	h.update(ikm);
	h.update(b"HPKE-v1");
	h.update(&suite_id);
	h.update(&label_len.to_be_bytes());
	h.update(label);
	h.update(&out_len.to_be_bytes());
	h.finalize_xof().read(out);
	Ok(())
}

// ---------------------------------------------------------------------------
// X-Wing (draft-connolly-cfrg-xwing-kem-06), registered for HPKE as
// `MLKEM768-X25519`, KEM ID 0x647A (draft-ietf-hpke-pq §4).
// ---------------------------------------------------------------------------

/// X-Wing KEM (draft 06).
///
/// Hybrid X25519 + ML-KEM-768. Implements [`Kem`] only — no auth variant.
#[derive(Debug, Clone, Copy, Default)]
pub struct XWingDraft06;

impl Sealed for XWingDraft06 {}

/// Public (encapsulation) key for X-Wing.
///
/// Wire format: 1184 bytes ML-KEM-768 encapsulation key || 32 bytes X25519
/// public key. The structured `EncapsulationKey` is materialized once at
/// construction time so that repeated `encap` calls do not re-parse the
/// 1216-byte wire form.
#[derive(Clone, Debug)]
pub struct XWingPublicKey {
	bytes: Vec<u8>,
	parsed: x_wing::EncapsulationKey,
}

impl AsRef<[u8]> for XWingPublicKey {
	fn as_ref(&self) -> &[u8] {
		&self.bytes
	}
}

/// Private (decapsulation) key for X-Wing.
///
/// Stores the canonical 32-byte seed plus a cached
/// [`x_wing::DecapsulationKey`]. Caching the DK saves a SHAKE-256 expansion
/// and ML-KEM-768 keygen on every `decap` call (the construction-side
/// `expand_key` work). Wrapped in `Option` so `zeroize()` can drop the inner
/// DK and trigger its own zeroize-on-drop.
pub struct XWingPrivateKey {
	seed: [u8; 32],
	dk: Option<x_wing::DecapsulationKey>,
}

impl Zeroize for XWingPrivateKey {
	fn zeroize(&mut self) {
		self.seed.zeroize();
		// Dropping the cached DK triggers its zeroize-on-drop (the x_wing
		// crate scrubs the inner 32-byte sk under its `zeroize` feature).
		self.dk = None;
	}
}

impl ZeroizeOnDrop for XWingPrivateKey {}

impl Drop for XWingPrivateKey {
	fn drop(&mut self) {
		self.zeroize();
	}
}

/// Encapsulated key (ciphertext) for X-Wing.
///
/// Wire format: 1088 bytes ML-KEM-768 ciphertext || 32 bytes X25519 ciphertext.
#[derive(Clone, Debug)]
pub struct XWingEncappedKey(Vec<u8>);

impl AsRef<[u8]> for XWingEncappedKey {
	fn as_ref(&self) -> &[u8] {
		&self.0
	}
}

/// Shared secret produced by X-Wing encap/decap.
pub struct XWingSharedSecret([u8; 32]);

impl AsRef<[u8]> for XWingSharedSecret {
	fn as_ref(&self) -> &[u8] {
		&self.0
	}
}

impl Zeroize for XWingSharedSecret {
	fn zeroize(&mut self) {
		self.0.zeroize();
	}
}

impl ZeroizeOnDrop for XWingSharedSecret {}
impl Drop for XWingSharedSecret {
	fn drop(&mut self) {
		self.zeroize();
	}
}

impl Kem for XWingDraft06 {
	const ID: u16 = 0x647A;
	const ENCAPPED_KEY_LEN: usize = x_wing::CIPHERTEXT_SIZE;
	const PUBLIC_KEY_LEN: usize = x_wing::ENCAPSULATION_KEY_SIZE;
	const PRIVATE_KEY_LEN: usize = x_wing::DECAPSULATION_KEY_SIZE;
	const SHARED_SECRET_LEN: usize = 32;

	type PublicKey = XWingPublicKey;
	type PrivateKey = XWingPrivateKey;
	type EncappedKey = XWingEncappedKey;
	type SharedSecret = XWingSharedSecret;

	fn generate<R: CryptoRng>(
		rng: &mut R,
	) -> Result<(Self::PrivateKey, Self::PublicKey), HpkeError> {
		let mut seed = Zeroizing::new([0u8; 32]);
		rng.fill_bytes(&mut seed[..]);
		Ok(keypair_from_seed(*seed))
	}

	fn derive_key_pair(ikm: &[u8]) -> Result<(Self::PrivateKey, Self::PublicKey), HpkeError> {
		// draft-ietf-hpke-pq §4.2, for KEM ID 0x647A (`MLKEM768-X25519`):
		//
		//   def DeriveKeyPair(ikm):
		//     seed = SHAKE256.LabeledDerive(ikm, "DeriveKeyPair", "", 32)
		//     return KEM.DeriveKeyPair(seed)
		//
		// The draft says `ikm` SHOULD be at least 32 bytes. That is an entropy
		// obligation on the caller, which a length check cannot enforce, so any
		// length is accepted — as for the DHKEMs.
		let mut seed = Zeroizing::new([0u8; 32]);
		shake256_labeled_derive(
			kem_suite_id(Self::ID),
			DERIVE_KEY_PAIR_LABEL,
			ikm,
			&mut seed[..],
		)?;
		Ok(keypair_from_seed(*seed))
	}

	fn encap<R: CryptoRng>(
		rng: &mut R,
		pk_r: &Self::PublicKey,
	) -> Result<(Self::SharedSecret, Self::EncappedKey), HpkeError> {
		use x_wing::Encapsulate;
		// Use the cached parsed `EncapsulationKey` directly — no per-call
		// `try_from` over the 1216-byte wire form.
		let (ct, mut ss) = pk_r.parsed.encapsulate_with_rng(rng);
		let ss_bytes = shared_secret_bytes(ss.as_ref());
		// Scrub the upstream shared-secret array; it is a plain `Array<u8, 32>`
		// with no zeroize-on-drop. The wrapper owns the only surviving copy.
		// Done before `?` so a length mismatch still scrubs.
		ss.zeroize();
		Ok((XWingSharedSecret(ss_bytes?), XWingEncappedKey(ct.to_vec())))
	}

	fn decap(
		enc: &Self::EncappedKey,
		sk_r: &Self::PrivateKey,
	) -> Result<Self::SharedSecret, HpkeError> {
		use x_wing::Decapsulate;
		// Cached DK: skips the per-call `expand_key` that
		// `DecapsulationKey::from(seed)` performs at construction.
		// `dk` is populated by every constructor and only cleared by
		// `Zeroize::zeroize()`; reaching `decap` after a manual `zeroize`
		// is a use-after-zeroize at the call site, so reject explicitly
		// rather than panicking.
		let dk = sk_r.dk.as_ref().ok_or(HpkeError::DecapError)?;
		let mut ss = dk
			.decapsulate_slice(enc.0.as_slice())
			.map_err(|_| HpkeError::InvalidEncappedKey)?;
		let ss_bytes = shared_secret_bytes(ss.as_ref());
		// Scrub the upstream shared-secret array (see `encap`).
		ss.zeroize();
		Ok(XWingSharedSecret(ss_bytes?))
	}

	fn pk_from_bytes(b: &[u8]) -> Result<Self::PublicKey, HpkeError> {
		if b.len() != Self::PUBLIC_KEY_LEN {
			return Err(HpkeError::InvalidPublicKey);
		}
		let parsed =
			x_wing::EncapsulationKey::try_from(b).map_err(|_| HpkeError::InvalidPublicKey)?;
		Ok(XWingPublicKey {
			bytes: b.to_vec(),
			parsed,
		})
	}

	fn sk_from_bytes(b: &[u8]) -> Result<Self::PrivateKey, HpkeError> {
		if b.len() != Self::PRIVATE_KEY_LEN {
			return Err(HpkeError::InvalidPrivateKey);
		}
		let mut seed = Zeroizing::new([0u8; 32]);
		seed.copy_from_slice(b);
		let dk = x_wing::DecapsulationKey::from(*seed);
		Ok(XWingPrivateKey {
			seed: *seed,
			dk: Some(dk),
		})
	}

	fn enc_from_bytes(b: &[u8]) -> Result<Self::EncappedKey, HpkeError> {
		if b.len() != Self::ENCAPPED_KEY_LEN {
			return Err(HpkeError::InvalidEncappedKey);
		}
		Ok(XWingEncappedKey(b.to_vec()))
	}

	fn pk_to_bytes(pk: &Self::PublicKey) -> Vec<u8> {
		pk.bytes.clone()
	}

	fn sk_to_bytes(sk: &Self::PrivateKey) -> Zeroizing<Vec<u8>> {
		Zeroizing::new(sk.seed.to_vec())
	}
}

/// Derive an X-Wing keypair from a 32-byte seed, caching the parsed
/// decapsulation/encapsulation keys for fast subsequent use.
fn keypair_from_seed(seed: [u8; 32]) -> (XWingPrivateKey, XWingPublicKey) {
	use x_wing::{DecapsulationKey, Decapsulator, KeyExport};

	let dk = DecapsulationKey::from(seed);
	let ek = dk.encapsulation_key().clone();
	let pk_bytes = ek.to_bytes().to_vec();

	(
		XWingPrivateKey { seed, dk: Some(dk) },
		XWingPublicKey {
			bytes: pk_bytes,
			parsed: ek,
		},
	)
}

// ---------------------------------------------------------------------------
// ML-KEM-768 / ML-KEM-1024 (draft-ietf-hpke-pq §3; not in RFC 9180).
// Both parameter sets share a uniform FIPS 203 / ml-kem 0.3 API surface, so
// the wrappers + Kem impl + seed→keypair helper are emitted by `ml_kem_variant!`.
// `MlKemSharedSecret` is shared (same 32-byte output size for both variants).
// ---------------------------------------------------------------------------

/// Shared secret produced by ML-KEM encap/decap (32 bytes); same wire size for
/// ML-KEM-768 and ML-KEM-1024.
pub struct MlKemSharedSecret([u8; 32]);

impl AsRef<[u8]> for MlKemSharedSecret {
	fn as_ref(&self) -> &[u8] {
		&self.0
	}
}

impl Zeroize for MlKemSharedSecret {
	fn zeroize(&mut self) {
		self.0.zeroize();
	}
}

impl ZeroizeOnDrop for MlKemSharedSecret {}
impl Drop for MlKemSharedSecret {
	fn drop(&mut self) {
		self.zeroize();
	}
}

/// Emit a [`Kem`] impl plus public/private/encapsulated-key wrappers and a
/// `from_seed` helper for an ML-KEM parameter set. Parameters: marker ident,
/// display name (used in doc strings), IANA KEM ID, `Nenc`, `Npk`, the
/// ml-kem `DecapsulationKey<P>` / `EncapsulationKey<P>` / `Ciphertext<P>`
/// concrete types, and the wrapper / helper names to emit.
macro_rules! ml_kem_variant {
	(
		$marker:ident, $variant:literal, $id:expr, $nenc:expr, $npk:expr,
		$dk:ty, $ek:ty, $ct:ty,
		$pk_wrap:ident, $sk_wrap:ident, $enc_wrap:ident, $from_seed:ident $(,)?
	) => {
		#[doc = concat!("`", $variant, "` (FIPS 203). Private keys are stored as the 64-byte (d, z) seed; the expanded decapsulation key is rebuilt from it.")]
		#[derive(Debug, Clone, Copy, Default)]
		pub struct $marker;

		impl Sealed for $marker {}

		#[doc = concat!("Public (encapsulation) key for `", $variant, "`. Parsed `EncapsulationKey` cached so `encap` skips the per-call decode of the wire bytes.")]
		#[derive(Clone, Debug)]
		pub struct $pk_wrap {
			bytes: Vec<u8>,
			parsed: $ek,
		}

		impl AsRef<[u8]> for $pk_wrap {
			fn as_ref(&self) -> &[u8] {
				&self.bytes
			}
		}

		#[doc = concat!("Private (decapsulation) key for `", $variant, "` — 64-byte `d || z` seed plus expanded `dk`. The `dk` is wrapped in `Option` so `zeroize()` can drop it and trigger its zeroize-on-drop, mirroring [`XWingPrivateKey`].")]
		pub struct $sk_wrap {
			dk: Option<$dk>,
			seed: [u8; 64],
		}

		impl Zeroize for $sk_wrap {
			fn zeroize(&mut self) {
				self.seed.zeroize();
				// Dropping the expanded `dk` triggers its zeroize-on-drop
				// (requires the `ml-kem/zeroize` feature, enabled in
				// Cargo.toml). Without this, a manual `zeroize()` would scrub
				// the seed but leave the fully expanded decapsulation key
				// usable in memory until drop.
				self.dk = None;
			}
		}

		impl ZeroizeOnDrop for $sk_wrap {}

		impl Drop for $sk_wrap {
			fn drop(&mut self) {
				self.zeroize();
			}
		}

		#[doc = concat!("Encapsulated key (ciphertext) for `", $variant, "`.")]
		#[derive(Clone, Debug)]
		pub struct $enc_wrap(Vec<u8>);

		impl AsRef<[u8]> for $enc_wrap {
			fn as_ref(&self) -> &[u8] {
				&self.0
			}
		}

		impl Kem for $marker {
			const ID: u16 = $id;
			const ENCAPPED_KEY_LEN: usize = $nenc;
			const PUBLIC_KEY_LEN: usize = $npk;
			const PRIVATE_KEY_LEN: usize = 64;
			const SHARED_SECRET_LEN: usize = 32;

			type PublicKey = $pk_wrap;
			type PrivateKey = $sk_wrap;
			type EncappedKey = $enc_wrap;
			type SharedSecret = MlKemSharedSecret;

			fn generate<R: CryptoRng>(
				rng: &mut R,
			) -> Result<(Self::PrivateKey, Self::PublicKey), HpkeError> {
				let mut seed = Zeroizing::new([0u8; 64]);
				rng.fill_bytes(&mut seed[..]);
				Ok($from_seed(*seed))
			}

			fn derive_key_pair(
				ikm: &[u8],
			) -> Result<(Self::PrivateKey, Self::PublicKey), HpkeError> {
				// draft-ietf-hpke-pq §3.2:
				//
				//   def DeriveKeyPair(ikm):
				//     dk = SHAKE256.LabeledDerive(ikm, "DeriveKeyPair", "", 64)
				//     (_expanded_dk, ek) = expandDecapsKey(dk)
				//     return (dk, ek)
				//
				// `dk` is the 64-byte (d, z) seed handed to FIPS 203
				// KeyGen_internal. Parameter sets are separated twice over: by
				// `suite_id` here, and by KeyGen_internal mixing `k` (3 vs 4)
				// into G(d || k).
				let mut seed = Zeroizing::new([0u8; 64]);
				shake256_labeled_derive(
					kem_suite_id(Self::ID),
					DERIVE_KEY_PAIR_LABEL,
					ikm,
					&mut seed[..],
				)?;
				Ok($from_seed(*seed))
			}

			fn encap<R: CryptoRng>(
				rng: &mut R,
				pk_r: &Self::PublicKey,
			) -> Result<(Self::SharedSecret, Self::EncappedKey), HpkeError> {
				use ml_kem::kem::Encapsulate as _;
				// Cached parsed `EncapsulationKey` — no per-call `try_into`
				// + `<$ek>::new` over the 1184/1568-byte wire form.
				let (ct, mut ss) = pk_r.parsed.encapsulate_with_rng(rng);
				let ss_bytes = shared_secret_bytes(ss.as_ref());
				// Scrub the upstream shared-secret array; `MlKemSharedSecret`
				// owns the only surviving copy. Done before `?` so a length
				// mismatch still scrubs.
				ss.zeroize();
				Ok((MlKemSharedSecret(ss_bytes?), $enc_wrap(ct.to_vec())))
			}

			fn decap(
				enc: &Self::EncappedKey,
				sk_r: &Self::PrivateKey,
			) -> Result<Self::SharedSecret, HpkeError> {
				use ml_kem::kem::Decapsulate as _;
				// `dk` is populated by every constructor and only cleared by
				// `Zeroize::zeroize()`; reaching `decap` after a manual
				// `zeroize` is a use-after-zeroize at the call site, so
				// reject explicitly rather than panicking.
				let dk = sk_r.dk.as_ref().ok_or(HpkeError::DecapError)?;
				let ct: $ct = enc
					.0
					.as_slice()
					.try_into()
					.map_err(|_| HpkeError::InvalidEncappedKey)?;
				let mut ss = dk.decapsulate(&ct);
				let ss_bytes = shared_secret_bytes(ss.as_ref());
				// Scrub the upstream shared-secret array (see `encap`).
				ss.zeroize();
				Ok(MlKemSharedSecret(ss_bytes?))
			}

			fn pk_from_bytes(b: &[u8]) -> Result<Self::PublicKey, HpkeError> {
				if b.len() != Self::PUBLIC_KEY_LEN {
					return Err(HpkeError::InvalidPublicKey);
				}
				let ek_bytes: ml_kem::kem::Key<$ek> = b
					.try_into()
					.map_err(|_| HpkeError::InvalidPublicKey)?;
				let parsed =
					<$ek>::new(&ek_bytes).map_err(|_| HpkeError::InvalidPublicKey)?;
				Ok($pk_wrap {
					bytes: b.to_vec(),
					parsed,
				})
			}

			fn sk_from_bytes(b: &[u8]) -> Result<Self::PrivateKey, HpkeError> {
				if b.len() != Self::PRIVATE_KEY_LEN {
					return Err(HpkeError::InvalidPrivateKey);
				}
				let mut seed = Zeroizing::new([0u8; 64]);
				seed.copy_from_slice(b);
				let (sk, _pk) = $from_seed(*seed);
				Ok(sk)
			}

			fn enc_from_bytes(b: &[u8]) -> Result<Self::EncappedKey, HpkeError> {
				if b.len() != Self::ENCAPPED_KEY_LEN {
					return Err(HpkeError::InvalidEncappedKey);
				}
				Ok($enc_wrap(b.to_vec()))
			}

			fn pk_to_bytes(pk: &Self::PublicKey) -> Vec<u8> {
				pk.bytes.clone()
			}

			fn sk_to_bytes(sk: &Self::PrivateKey) -> Zeroizing<Vec<u8>> {
				Zeroizing::new(sk.seed.to_vec())
			}
		}

		fn $from_seed(seed: [u8; 64]) -> ($sk_wrap, $pk_wrap) {
			use ml_kem::kem::KeyExport as _;
			let ml_seed: ml_kem::Seed = seed.into();
			let dk = <$dk>::from_seed(ml_seed);
			let ek = dk.encapsulation_key().clone();
			let ek_bytes: Vec<u8> = ek.to_bytes().to_vec();
			(
				$sk_wrap { dk: Some(dk), seed },
				$pk_wrap {
					bytes: ek_bytes,
					parsed: ek,
				},
			)
		}
	};
}

ml_kem_variant!(
	MlKem768,
	"ML-KEM-768",
	0x0041,
	1088,
	1184,
	ml_kem::DecapsulationKey768,
	ml_kem::EncapsulationKey768,
	ml_kem::ml_kem_768::Ciphertext,
	MlKem768PublicKey,
	MlKem768PrivateKey,
	MlKem768EncappedKey,
	ml_kem_768_from_seed,
);

ml_kem_variant!(
	MlKem1024,
	"ML-KEM-1024",
	0x0042,
	1568,
	1568,
	ml_kem::DecapsulationKey1024,
	ml_kem::EncapsulationKey1024,
	ml_kem::ml_kem_1024::Ciphertext,
	MlKem1024PublicKey,
	MlKem1024PrivateKey,
	MlKem1024EncappedKey,
	ml_kem_1024_from_seed,
);

#[cfg(test)]
mod tests {
	use super::*;
	use rand::rngs::SysRng;
	use rand_core::UnwrapErr;

	// Roundtrip coverage lives in `tests/roundtrip.rs`. The tests here cover
	// behaviours that aren't expressible in the macro-generated matrix:
	// derive-key-pair input validation, parameter-set domain separation,
	// and seed-bytes round-tripping.

	/// `sk_to_bytes` ∘ `sk_from_bytes` roundtrips on every PQ KEM.
	macro_rules! sk_roundtrip_test {
		($name:ident, $kem:ty, $seed_len:expr) => {
			#[test]
			fn $name() {
				let mut os_rng = SysRng;
				let mut rng = UnwrapErr(&mut os_rng);
				let (sk_r, pk_r) = <$kem>::generate(&mut rng).unwrap();
				let sk_bytes = <$kem>::sk_to_bytes(&sk_r);
				assert_eq!(sk_bytes.len(), $seed_len);
				let sk_loaded = <$kem>::sk_from_bytes(&sk_bytes).unwrap();
				let (ss_e, enc) = <$kem>::encap(&mut rng, &pk_r).unwrap();
				let ss_d = <$kem>::decap(&enc, &sk_loaded).unwrap();
				assert_eq!(ss_e.as_ref(), ss_d.as_ref());
			}
		};
	}
	sk_roundtrip_test!(xwing_sk_to_bytes_roundtrip, XWingDraft06, 32);
	sk_roundtrip_test!(ml_kem_768_sk_to_bytes_roundtrip, MlKem768, 64);
	sk_roundtrip_test!(ml_kem_1024_sk_to_bytes_roundtrip, MlKem1024, 64);

	/// `DeriveKeyPair` derives a 32-byte seed via `LabeledDerive`
	/// (draft-ietf-hpke-pq §4.2), so any IKM length yields a working key pair.
	#[test]
	fn xwing_derive_key_pair_roundtrip() {
		let (sk_r, pk_r) = XWingDraft06::derive_key_pair(b"x-wing test ikm").unwrap();
		let mut os_rng = SysRng;
		let mut rng = UnwrapErr(&mut os_rng);
		let (ss_e, enc) = XWingDraft06::encap(&mut rng, &pk_r).unwrap();
		assert_eq!(
			XWingDraft06::decap(&enc, &sk_r).unwrap().as_ref(),
			ss_e.as_ref(),
		);
	}

	/// Even with the same 64-byte (d, z) seed, ML-KEM-768 and ML-KEM-1024
	/// produce different keys: FIPS 203 Algorithm 13 mixes the parameter `k`
	/// (3 vs 4) into G(d || k), so the two parameter sets are
	/// cryptographically independent for any shared seed.
	#[test]
	fn ml_kem_768_and_1024_derive_distinct_keys_from_same_ikm() {
		let ikm = [0x5Au8; 64];
		let (_, pk_768) = MlKem768::derive_key_pair(&ikm).unwrap();
		let (_, pk_1024) = MlKem1024::derive_key_pair(&ikm).unwrap();
		let n = pk_768.as_ref().len().min(pk_1024.as_ref().len());
		assert_ne!(&pk_768.as_ref()[..n], &pk_1024.as_ref()[..n]);
	}

	/// `derive_key_pair(ikm)` is deterministic, accepts any IKM length, and runs
	/// the IKM through `LabeledDerive` rather than using it verbatim as the
	/// (d, z) seed (draft-ietf-hpke-pq §3.2). The `assert_ne!` is the regression
	/// guard against reverting to the older draft-connolly convention, under
	/// which `ikm` *was* the seed and had to be exactly 64 bytes.
	macro_rules! ml_kem_derive_seed_test {
		($name:ident, $kem:ty) => {
			#[test]
			fn $name() {
				let ikm: [u8; 64] = core::array::from_fn(|i| u8::try_from(i).unwrap());
				let (sk1, pk1) = <$kem>::derive_key_pair(&ikm).unwrap();
				let (_, pk2) = <$kem>::derive_key_pair(&ikm).unwrap();
				assert_eq!(pk1.as_ref(), pk2.as_ref());
				assert_ne!(sk1.seed, ikm, "IKM must be run through LabeledDerive");

				// Every IKM length is accepted, and lengths are distinguished:
				// SHAKE absorbs the whole input, so padding is not truncation.
				let mut seen: Vec<Vec<u8>> = Vec::new();
				for len in [0usize, 1, 32, 63, 64, 65, 200] {
					let (_, pk) = <$kem>::derive_key_pair(&vec![0u8; len]).unwrap();
					let bytes = pk.as_ref().to_vec();
					assert!(!seen.contains(&bytes), "IKM length {len} collided");
					seen.push(bytes);
				}
			}
		};
	}
	ml_kem_derive_seed_test!(ml_kem_768_derive_key_pair_seed_invariants, MlKem768);
	ml_kem_derive_seed_test!(ml_kem_1024_derive_key_pair_seed_invariants, MlKem1024);

	/// A manual `zeroize()` must scrub the seed AND drop the cached expanded
	/// decapsulation key; a subsequent `decap` is a use-after-zeroize and
	/// must fail with `DecapError` rather than succeeding against expanded
	/// key material that survived the scrub.
	macro_rules! zeroize_disables_decap_test {
		($name:ident, $kem:ty) => {
			#[test]
			fn $name() {
				let mut os_rng = SysRng;
				let mut rng = UnwrapErr(&mut os_rng);
				let (mut sk_r, pk_r) = <$kem>::generate(&mut rng).unwrap();
				let (_, enc) = <$kem>::encap(&mut rng, &pk_r).unwrap();
				sk_r.zeroize();
				assert!(sk_r.seed.iter().all(|&b| b == 0));
				assert!(matches!(
					<$kem>::decap(&enc, &sk_r),
					Err(HpkeError::DecapError)
				));
			}
		};
	}
	zeroize_disables_decap_test!(xwing_zeroize_disables_decap, XWingDraft06);
	zeroize_disables_decap_test!(ml_kem_768_zeroize_disables_decap, MlKem768);
	zeroize_disables_decap_test!(ml_kem_1024_zeroize_disables_decap, MlKem1024);
}
