#![allow(dead_code)]
use crate::api::err;
use crate::tools::ping::Pinger;
use crate::tools::traceroute::traceroute;
use axum::{
    Json,
    extract::Query,
};
use serde::Deserialize;

#[derive(Deserialize)]
pub(crate) struct PingQuery {
    target: String,
    count: Option<u32>,
    timeout: Option<u64>,
}

#[derive(Deserialize)]
pub(crate) struct TraceQuery {
    target: String,
    max_ttl: Option<u32>,
    timeout: Option<u64>,
}

pub(crate) async fn ping_handler(
    Query(params): Query<PingQuery>,
) -> Json<serde_json::Value> {
    let target: std::net::IpAddr = match params.target.parse() {
        Ok(a) => a,
        Err(_) => return err(format!("invalid target: {}", params.target)),
    };
    let count = params.count.unwrap_or(4).min(100);
    let timeout = std::time::Duration::from_secs(params.timeout.unwrap_or(5).min(30));
    let _interval = std::time::Duration::from_secs(1);

    match Pinger::ping(target, count, _interval, timeout).await {
        Ok(result) => Json(serde_json::json!(result)),
        Err(e) => err(format!("ping failed: {e}")),
    }
}

pub(crate) async fn traceroute_handler(
    Query(params): Query<TraceQuery>,
) -> Json<serde_json::Value> {
    let target: std::net::IpAddr = match params.target.parse() {
        Ok(a) => a,
        Err(_) => return err(format!("invalid target: {}", params.target)),
    };
    let max_ttl = params.max_ttl.unwrap_or(30).min(64);
    let timeout = std::time::Duration::from_secs(params.timeout.unwrap_or(5).min(30));

    match traceroute(target, max_ttl, timeout).await {
        Ok(result) => Json(serde_json::json!(result)),
        Err(e) => err(format!("traceroute failed: {e}")),
    }
}
