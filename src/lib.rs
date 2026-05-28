#![deny(unused_crate_dependencies)]
#![deny(unsafe_code)]
#![deny(unreachable_pub, unused_imports)]

#[cfg(test)]
extern crate criterion;
#[cfg(test)]
extern crate tempfile;
#[cfg(test)]
extern crate tokio_test;

pub mod cli;
pub mod config;
pub mod conntrack;
pub mod dhcp;
pub mod dns;
pub mod firewall;
pub mod net;
pub mod pppoe;
pub mod qos;
pub mod traits;
pub mod user;

pub mod prelude {
    pub use crate::traits::*;
}

use bincode as _;
use clap as _;
use futures as _;
use metrics as _;
use metrics_exporter_prometheus as _;
#[cfg(feature = "real")]
use nftnl as _;
#[cfg(feature = "real")]
use nlink as _;
use ratatui as _;
use rkyv as _;
use serde as _;
use serde_yaml as _;
use thiserror as _;
use tokio as _;
use tracing as _;
use tracing_subscriber as _;
use uuid as _;
