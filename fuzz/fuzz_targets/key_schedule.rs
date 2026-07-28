//! Fuzz the key schedule across all four HPKE modes with arbitrary shared
//! secrets, info, and PSK material. The functions must validate inputs and
//! either succeed or return `Err`; panics are bugs.

#![no_main]

use libfuzzer_sys::fuzz_target;

use hpke_ng::{
	__test_only::{
		AuthModeTag, AuthPskModeTag, BaseModeTag, PskModeTag, key_schedule_psk,
		key_schedule_psk_free,
	},
	ChaCha20Poly1305, DhKemX25519HkdfSha256, HkdfSha256, Psk,
};

/// Consume a length-prefixed slice from the front of `rest`. The first byte is
/// the length (clamped to the remaining buffer); the next `len` bytes are the
/// payload. If `rest` is empty, returns an empty slice.
fn take_lp<'a>(rest: &mut &'a [u8]) -> &'a [u8] {
	if rest.is_empty() {
		return &[];
	}
	let len = (rest[0] as usize).min(rest.len() - 1);
	let (out, tail) = rest[1..].split_at(len);
	*rest = tail;
	out
}

fuzz_target!(|data: &[u8]| {
	// Layout: mode(1) || shared_secret(32) || lp(info) || lp(psk) || lp(psk_id)
	if data.len() < 1 + 32 {
		return;
	}
	let mode = data[0];
	let shared_secret = &data[1..33];
	let mut rest = &data[33..];
	let info = take_lp(&mut rest);
	let psk = take_lp(&mut rest);
	let psk_id = take_lp(&mut rest);

	match mode % 4 {
		0 => {
			let _ = key_schedule_psk_free::<
				BaseModeTag,
				DhKemX25519HkdfSha256,
				HkdfSha256,
				ChaCha20Poly1305,
			>(shared_secret, info);
		}
		1 => {
			// `Psk::new` is the only way to build the bundle, so it — not the
			// key schedule — is where malformed PSK input is rejected. Fuzzing
			// through it exercises both.
			if let Ok(psk) = Psk::new(psk, psk_id) {
				let _ = key_schedule_psk::<
					PskModeTag,
					DhKemX25519HkdfSha256,
					HkdfSha256,
					ChaCha20Poly1305,
				>(shared_secret, info, psk);
			}
		}
		2 => {
			let _ = key_schedule_psk_free::<
				AuthModeTag,
				DhKemX25519HkdfSha256,
				HkdfSha256,
				ChaCha20Poly1305,
			>(shared_secret, info);
		}
		_ => {
			if let Ok(psk) = Psk::new(psk, psk_id) {
				let _ = key_schedule_psk::<
					AuthPskModeTag,
					DhKemX25519HkdfSha256,
					HkdfSha256,
					ChaCha20Poly1305,
				>(shared_secret, info, psk);
			}
		}
	}
});
