use hpke_ng::*;

// AuthModeTag implements PskFreeMode, not PskMode. This must not compile.
fn main() {
	let _ = hpke_ng::__test_only::key_schedule::<
		AuthModeTag,
		DhKemX25519HkdfSha256,
		HkdfSha256,
		ChaCha20Poly1305,
	>(&[0u8; 32], b"info", &[0u8; 32], b"id");
}
