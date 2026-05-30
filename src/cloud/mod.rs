pub use ddns::*;
pub mod ddns;

#[cfg(feature = "api")]
pub(crate) mod api;
