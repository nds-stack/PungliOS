//! Trait-based abstractions for all kernel interactions.
//!
//! Every networking component depends on these traits, not on the
//! kernel implementation. This enables testing via `MockBackend`
//! (in-memory, no kernel required) and production via `RealBackend`
//! (nftnl + nlink, Linux only).

pub mod mock;
pub mod netlink;

pub use mock::MockBackend;
pub use netlink::*;
