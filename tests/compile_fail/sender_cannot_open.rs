use hpke_ng::*;
use rand::rngs::SysRng as OsRng;
use rand_core::UnwrapErr;

// A `SenderContext` (from `setup_sender_*`) must NOT expose `open` — the mirror
// of `receiver_cannot_seal`. A single context is one-directional.
fn main() {
	let mut os = OsRng;
	let mut rng = UnwrapErr(&mut os);
	let (_sk_r, pk_r) = DhKemX25519HkdfSha256::generate(&mut rng).unwrap();
	let (_enc, mut sender) =
		Hpke::<DhKemX25519HkdfSha256, HkdfSha256, ChaCha20Poly1305>::setup_sender_base(
			&mut rng,
			&pk_r,
			b"info",
		)
		.unwrap();
	// `SenderContext` has no `open` method.
	let _ = sender.open(b"aad", b"ciphertext");
}
