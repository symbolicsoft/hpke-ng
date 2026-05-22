#[test]
fn compile_fail() {
	let t = trybuild::TestCases::new();
	t.compile_fail("tests/compile_fail/context_not_clone.rs");
	t.compile_fail("tests/compile_fail/export_only_no_seal.rs");
	t.compile_fail("tests/compile_fail/pq_no_auth.rs");
}
