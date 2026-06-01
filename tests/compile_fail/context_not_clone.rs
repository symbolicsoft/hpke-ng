use hpke_ng::*;
use rand_core::{OsRng, TryRngCore as _};

// Tries to call `.clone()` on a `SenderContext` (cloning would fork the
// (key, base_nonce, seq) state and reopen the nonce-reuse footgun).
fn main() {
	let mut os = OsRng;
	let (_, pk_r) = DhKemX25519HkdfSha256::generate(&mut os.unwrap_mut()).unwrap();
	let (_, ctx) = Hpke::<DhKemX25519HkdfSha256, HkdfSha256, ChaCha20Poly1305>::setup_sender_base(
		&mut os.unwrap_mut(),
		&pk_r,
		b"info",
	)
	.unwrap();
	let _ = ctx.clone();
}
