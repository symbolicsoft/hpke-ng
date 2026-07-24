//! To regenerate the compile-fail `.stderr` fixtures after
//! an intentional change (e.g. a toolchain bump), run:
//!
//! `TRYBUILD=overwrite cargo test --features pq,hazmat-kat-internals --test compile_fail`
//!
#[test]
fn compile_fail() {
	let t = trybuild::TestCases::new();
	// Cannot call `.clone()` on a `SenderContext`
	t.compile_fail("tests/compile_fail/context_not_clone.rs");
	// Cannot call `seal_base` with `ExportOnly` as the AEAD
	t.compile_fail("tests/compile_fail/export_only_no_seal.rs");
	// Cannot call `seal_auth` with `MlKem768` as the KEM
	t.compile_fail("tests/compile_fail/pq_no_auth.rs");
	// A `ReceiverContext` (from `setup_receiver_*`) must NOT expose `seal`
	t.compile_fail("tests/compile_fail/receiver_cannot_seal.rs");
	// A `SenderContext` (from `setup_sender_*`) must NOT expose `open`
	t.compile_fail("tests/compile_fail/sender_cannot_open.rs");
	// `key_schedule_psk_free` requires M: PskFreeMode, so PskModeTag must be rejected
	t.compile_fail("tests/compile_fail/psk_free_rejects_psk_tag.rs");
	// `key_schedule_psk_free` requires M: PskFreeMode, so AuthPskModeTag must be rejected
	t.compile_fail("tests/compile_fail/psk_free_rejects_auth_psk_tag.rs");
	// `key_schedule_psk` requires M: PskMode, so BaseModeTag must be rejected
	t.compile_fail("tests/compile_fail/psk_rejects_base_tag.rs");
	// `key_schedule_psk` requires M: PskMode, so AuthModeTag must be rejected
	t.compile_fail("tests/compile_fail/psk_rejects_auth_tag.rs");
	// Cannot implement the `sealed` supertrait on an external type
	t.compile_fail("tests/compile_fail/external_impl_sealed.rs");
}
