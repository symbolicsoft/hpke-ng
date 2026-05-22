use hpke_ng::*;
use rand_core::{OsRng, TryRngCore as _};

// Tries to call `seal_auth` with `MlKem768` as the KEM
fn main() {
	let mut os = OsRng;
	let (sk_s, _) = MlKem768::generate(&mut os.unwrap_mut()).unwrap();
	let (_, pk_r) = MlKem768::derive_key_pair(&[0u8; 64]).unwrap();

	let (enc, ct) = Hpke::<MlKem768, HkdfSha256, ChaCha20Poly1305>::seal_auth(
		&mut os.unwrap_mut(),
		&pk_r,
		b"info",
		b"aad",
		b"hello",
		&sk_s,
	)
	.unwrap();
}
