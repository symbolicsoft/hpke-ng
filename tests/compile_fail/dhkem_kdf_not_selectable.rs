use hpke_ng::HkdfSha512;
use hpke_ng::kem::dh::{DhKem, X25519};

// The KDF of a DHKEM is fixed per group by `DiffieHellman::Kdf`, so a group
// cannot be paired with an arbitrary KDF. `DHKEM(X25519, HKDF-SHA512)` is not a
// registered ciphersuite — it would advertise KEM ID 0x0020 while deriving
// different keys — and must not be expressible. Must fail compilation.
fn main() {
	let _: Option<DhKem<X25519, HkdfSha512>> = None;
}
