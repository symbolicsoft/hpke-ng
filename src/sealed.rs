//! Sealed-trait marker preventing external implementations of public traits.

/// Crate-internal seal: only types defined in this crate may implement public traits.
pub trait Sealed {}
