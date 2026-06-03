use hpke_ng::*;

// AuthPskModeTag implements PskMode, not PskFreeMode. This must not compile.
fn main() {
	let _ = hpke_ng::__test_only::key_schedule_psk_free::<
		AuthPskModeTag,
		DhKemX25519HkdfSha256,
		HkdfSha256,
		ChaCha20Poly1305,
	>(&[0u8; 32], b"info");
}
