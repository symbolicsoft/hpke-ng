// sealed::Sealed is pub(crate) and cannot be named or implemented from outside
// the crate. This is the foundational guarantee: PskFreeMode and PskMode cannot
// be implemented externally because their supertrait is inaccessible.
struct SomeTag;

impl hpke_ng::sealed::Sealed for SomeTag {}

fn main() {}
