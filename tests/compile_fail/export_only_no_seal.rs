use hpke_ng::*;
use rand_core::{OsRng, TryRngCore as _};

// Tries to call `seal_base` with `ExportOnly` as the AEAD
fn main() {
	let mut os = OsRng;
	let (_, pk_r) = DhKemX25519HkdfSha256::derive_key_pair(b"test-recipient").unwrap();

	let (enc, ct) = Hpke::<DhKemX25519HkdfSha256, HkdfSha256, ExportOnly>::seal_base(
		&mut os.unwrap_mut(),
		&pk_r,
		b"info",
		b"aad",
		b"hello",
	)
	.unwrap();
}
