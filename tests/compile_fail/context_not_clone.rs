use hpke_ng::*;
use rand::rngs::SysRng as OsRng;
use rand_core::UnwrapErr;

// Tries to call `.clone()` on a `SenderContext` (cloning would fork the
// (key, base_nonce, seq) state and reopen the nonce-reuse footgun).
fn main() {
	let mut os = OsRng;
	let mut rng = UnwrapErr(&mut os);
	let (_, pk_r) = DhKemX25519HkdfSha256::generate(&mut rng).unwrap();
	let (_, ctx) = Hpke::<DhKemX25519HkdfSha256, HkdfSha256, ChaCha20Poly1305>::setup_sender_base(
		&mut rng,
		&pk_r,
		b"info",
	)
	.unwrap();
	let _ = ctx.clone();
}
