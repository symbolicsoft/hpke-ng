//! X-Wing known-answer tests against the official draft vectors.
//!
//! Source: `spec/test-vectors.json` from
//! <https://github.com/dconnolly/draft-connolly-cfrg-xwing-kem>, as vendored by
//! the `x-wing` crate's own KAT suite.
//!
//! X-Wing postdates RFC 9180, so `tests/test_vectors.json` covers none of it.
//! These vectors pin the parts of the KEM that `hpke-ng` itself implements and
//! that a self-consistency roundtrip cannot check: the 32-byte seed to key-pair
//! expansion, the 1216-byte public-key wire format, the 1120-byte encapsulated
//! -key wire format, and the resulting shared secret. Both `generate` and
//! `encap` are driven from the vector's seeds through the public `Kem` API, so
//! this needs no `hazmat-` feature.

#![cfg(feature = "pq")]

use core::convert::Infallible;

use hpke_ng::{Kem, XWingDraft06};
use rand_core::{TryCryptoRng, TryRng};
use serde::Deserialize;

#[derive(Deserialize)]
struct XWingVector {
	/// Key-generation seed; also the canonical private key.
	seed: String,
	/// Encapsulation randomness (64 bytes).
	eseed: String,
	/// Expected shared secret.
	ss: String,
	/// Expected serialized private key.
	sk: String,
	/// Expected serialized public key.
	pk: String,
	/// Expected ciphertext (encapsulated key).
	ct: String,
}

fn hex_decode(s: &str) -> Vec<u8> {
	hex::decode(s).expect("invalid hex in X-Wing vector")
}

/// Replays a fixed byte string as randomness, so `generate` and `encap` become
/// deterministic and directly comparable against the vectors. Panics if a
/// caller draws more bytes than the vector supplies — that would mean the
/// randomness budget changed and the vector no longer applies.
struct SeedRng<'a>(&'a [u8]);

impl TryRng for SeedRng<'_> {
	type Error = Infallible;

	fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
		let mut b = [0u8; 4];
		self.try_fill_bytes(&mut b)?;
		Ok(u32::from_le_bytes(b))
	}

	fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
		let mut b = [0u8; 8];
		self.try_fill_bytes(&mut b)?;
		Ok(u64::from_le_bytes(b))
	}

	fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
		let (head, tail) = self.0.split_at(dst.len());
		dst.copy_from_slice(head);
		self.0 = tail;
		Ok(())
	}
}

impl TryCryptoRng for SeedRng<'_> {}

#[test]
fn xwing_draft_vectors() {
	let vectors: Vec<XWingVector> =
		serde_json::from_str(include_str!("test_vectors_xwing.json")).expect("parse X-Wing KAT");
	assert_eq!(vectors.len(), 3, "expected 3 X-Wing draft vectors");

	for (i, v) in vectors.iter().enumerate() {
		// Seed -> key pair, and both serializations.
		let seed = hex_decode(&v.seed);
		let (sk, pk) = XWingDraft06::generate(&mut SeedRng(&seed)).expect("generate from seed");
		assert_eq!(
			XWingDraft06::sk_to_bytes(&sk).as_slice(),
			hex_decode(&v.sk).as_slice(),
			"sk mismatch (vector {i})",
		);
		assert_eq!(
			pk.as_ref(),
			hex_decode(&v.pk).as_slice(),
			"pk mismatch (vector {i})",
		);

		// Encapsulation is deterministic given the vector's ephemeral seed.
		let eseed = hex_decode(&v.eseed);
		let (ss_enc, enc) = XWingDraft06::encap(&mut SeedRng(&eseed), &pk).expect("encap");
		assert_eq!(
			enc.as_ref(),
			hex_decode(&v.ct).as_slice(),
			"ct mismatch (vector {i})",
		);
		assert_eq!(
			ss_enc.as_ref(),
			hex_decode(&v.ss).as_slice(),
			"encap shared secret mismatch (vector {i})",
		);

		// Decapsulation of the vector's own ciphertext, with the generated key
		// and with one reloaded from its wire bytes.
		let ct = XWingDraft06::enc_from_bytes(&hex_decode(&v.ct)).expect("enc bytes");
		assert_eq!(
			XWingDraft06::decap(&ct, &sk).expect("decap").as_ref(),
			hex_decode(&v.ss).as_slice(),
			"decap shared secret mismatch (vector {i})",
		);

		let sk_loaded = XWingDraft06::sk_from_bytes(&hex_decode(&v.sk)).expect("sk bytes");
		assert_eq!(
			XWingDraft06::decap(&ct, &sk_loaded)
				.expect("decap")
				.as_ref(),
			hex_decode(&v.ss).as_slice(),
			"decap with reloaded sk mismatch (vector {i})",
		);
	}
}
