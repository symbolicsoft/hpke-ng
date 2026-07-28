use hpke_ng::*;
use rand::rngs::SysRng as OsRng;
use rand_core::UnwrapErr;

// Tries to call `seal_auth` with `MlKem768` as the KEM
fn main() {
	let mut os = OsRng;
	let mut rng = UnwrapErr(&mut os);
	let (sk_s, _) = MlKem768::generate(&mut rng).unwrap();
	let (_, pk_r) = MlKem768::derive_key_pair(&[0u8; 64]).unwrap();

	let (_enc, _ct) = Hpke::<MlKem768, HkdfSha256, ChaCha20Poly1305>::seal_auth(
		&mut rng,
		&pk_r,
		b"info",
		b"aad",
		b"hello",
		&sk_s,
	)
	.unwrap();
}
