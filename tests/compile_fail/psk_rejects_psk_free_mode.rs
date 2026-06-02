use hpke_ng::*;

// key_schedule must not accept PSK-free mode tags.
// BaseModeTag implements PskFreeMode, not PskMode — this must not compile.
fn main() {
	let _ = hpke_ng::__test_only::key_schedule::<
		BaseModeTag,
		DhKemX25519HkdfSha256,
		HkdfSha256,
		ChaCha20Poly1305,
	>(&[0u8; 32], b"info", &[0u8; 32], b"id");
}
