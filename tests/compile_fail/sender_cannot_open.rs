use hpke_ng::*;
use rand_core::{OsRng, TryRngCore as _};

// A `SenderContext` (from `setup_sender_*`) must NOT expose `open` — the mirror
// of `receiver_cannot_seal`. A single context is one-directional.
fn main() {
	let mut os = OsRng;
	let (_sk_r, pk_r) = DhKemX25519HkdfSha256::generate(&mut os.unwrap_mut()).unwrap();
	let (_enc, mut sender) =
		Hpke::<DhKemX25519HkdfSha256, HkdfSha256, ChaCha20Poly1305>::setup_sender_base(
			&mut os.unwrap_mut(),
			&pk_r,
			b"info",
		)
		.unwrap();
	// `SenderContext` has no `open` method.
	let _ = sender.open(b"aad", b"ciphertext");
}
