use hpke_ng::*;

// `key_schedule_psk` requires M: PskMode.
// BaseModeTag implements PskFreeMode, not PskMode. Must fail compilation.
fn main() {
	let _ = hpke_ng::__test_only::key_schedule_psk::<
		BaseModeTag,
		DhKemX25519HkdfSha256,
		HkdfSha256,
		ChaCha20Poly1305,
	>(&[0u8; 32], b"info", Psk::new(&[0u8; 32], b"psk-id").unwrap());
}
