pub use syslog::*;
pub mod syslog;

#[cfg(feature = "api")]
pub(crate) mod api;
