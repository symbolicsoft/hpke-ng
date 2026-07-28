//! Fuzz `Kem::enc_from_bytes` for every supported KEM. The parser must never
//! panic on arbitrary input.

#![no_main]

use libfuzzer_sys::fuzz_target;

use hpke_ng::{
	DhKemK256HkdfSha256, DhKemP256HkdfSha256, DhKemP384HkdfSha384, DhKemP521HkdfSha512,
	DhKemX448HkdfSha512, DhKemX25519HkdfSha256, Kem, MlKem768, MlKem1024, XWingDraft06,
};

fuzz_target!(|data: &[u8]| {
	let _ = <DhKemX25519HkdfSha256 as Kem>::enc_from_bytes(data);
	let _ = <DhKemX448HkdfSha512 as Kem>::enc_from_bytes(data);
	let _ = <DhKemP256HkdfSha256 as Kem>::enc_from_bytes(data);
	let _ = <DhKemP384HkdfSha384 as Kem>::enc_from_bytes(data);
	let _ = <DhKemP521HkdfSha512 as Kem>::enc_from_bytes(data);
	let _ = <DhKemK256HkdfSha256 as Kem>::enc_from_bytes(data);
	let _ = <XWingDraft06 as Kem>::enc_from_bytes(data);
	let _ = <MlKem768 as Kem>::enc_from_bytes(data);
	let _ = <MlKem1024 as Kem>::enc_from_bytes(data);
});
