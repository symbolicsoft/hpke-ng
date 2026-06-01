use hpke_ng::*;
use rand_core::{OsRng, TryRngCore as _};

// A `ReceiverContext` (from `setup_receiver_*`) must NOT expose `seal`. Using a
// single HPKE session in both directions would reuse the AEAD (key, nonce),
// which is catastrophic — so this must be a compile error, not a runtime hazard.
fn main() {
	let mut os = OsRng;
	let (sk_r, pk_r) = DhKemX25519HkdfSha256::generate(&mut os.unwrap_mut()).unwrap();
	let (enc, _sender) =
		Hpke::<DhKemX25519HkdfSha256, HkdfSha256, ChaCha20Poly1305>::setup_sender_base(
			&mut os.unwrap_mut(),
			&pk_r,
			b"info",
		)
		.unwrap();
	let mut receiver =
		Hpke::<DhKemX25519HkdfSha256, HkdfSha256, ChaCha20Poly1305>::setup_receiver_base(
			&enc, &sk_r, b"info",
		)
		.unwrap();
	// `ReceiverContext` has no `seal` method.
	let _ = receiver.seal(b"aad", b"plaintext");
}
