//! Fuzz `Hpke::open_base` against a fixed receiver keypair. The first 32 bytes
//! of input are interpreted as the encapsulated key; the remainder as
//! ciphertext. Authentication failures are expected; panics are bugs.

#![no_main]

use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;

use hpke_ng::{ChaCha20Poly1305, DhKemX25519HkdfSha256, HkdfSha256, Hpke, Kem};

type Kem25519 = DhKemX25519HkdfSha256;
type SuiteSk = <Kem25519 as Kem>::PrivateKey;
type Suite = Hpke<Kem25519, HkdfSha256, ChaCha20Poly1305>;

fn recipient() -> &'static SuiteSk {
	static SK: OnceLock<SuiteSk> = OnceLock::new();
	SK.get_or_init(|| {
		let (sk, _pk) = Kem25519::derive_key_pair(b"hpke-ng-fuzz-recipient")
			.expect("derive_key_pair on fixed IKM never fails for X25519");
		sk
	})
}

fuzz_target!(|data: &[u8]| {
	if data.len() < 32 {
		return;
	}
	let (enc_bytes, ct) = data.split_at(32);
	if let Ok(enc) = Kem25519::enc_from_bytes(enc_bytes) {
		let _ = Suite::open_base(&enc, recipient(), b"info", b"aad", ct);
	}
});
