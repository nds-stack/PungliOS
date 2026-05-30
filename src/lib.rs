#![deny(unused_crate_dependencies)]
#![cfg_attr(not(feature = "real"), deny(unsafe_code))]
#![deny(unreachable_pub, unused_imports)]

#[cfg(test)]
extern crate criterion;
#[cfg(test)]
extern crate tempfile;
#[cfg(test)]
extern crate tokio_test;

pub mod address_list;
pub mod api;
pub mod billing;
pub mod bonding;
pub mod bpf_qos;
pub mod bridge;
pub mod cli;
pub mod config;
pub mod conntrack;
pub mod dhcp;
pub mod dhcp_client;
pub mod dns;
pub mod firewall;
pub mod graphs;
pub mod hotspot;
pub mod ipsec;
pub mod ipv6;
pub mod l2tp;
pub mod lldp;
pub mod lte;
pub mod net;
pub mod netwatch;
pub mod ntp;
pub mod plugins;
pub mod pppoe;
pub mod qos;
pub mod routing;
pub mod scheduler;
pub mod snmp;
pub mod tenancy;
pub mod tools;
pub mod traffic_flow;
pub mod traits;
pub mod tunnel;
pub mod user;
pub mod vrf;
pub mod vrrp;
#[cfg(feature = "web")]
pub mod web;
pub mod wireguard;

pub mod prelude {
    pub use crate::traits::*;
}

use argon2 as _;
#[cfg(feature = "api")]
use axum as _;
use bincode as _;
use clap as _;
use futures as _;
#[cfg(feature = "real")]
use libc as _;
use md5 as _;
use metrics as _;
use metrics_exporter_prometheus as _;
#[cfg(feature = "real")]
use nftnl as _;
#[cfg(feature = "real")]
use nlink as _;
use ratatui as _;
use rkyv as _;
use serde as _;
use serde_json as _;
use serde_yaml as _;
#[cfg(feature = "web")]
use tera as _;
use thiserror as _;
use tokio as _;
#[cfg(feature = "api")]
use tokio_stream as _;
#[cfg(feature = "api")]
use tower as _;
use tracing as _;
use tracing_subscriber as _;
use uuid as _;
