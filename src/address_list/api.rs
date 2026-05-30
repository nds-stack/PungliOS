#![allow(dead_code)]
use crate::address_list::{AddressListManager, AddressListPolicy};
use crate::api::{err, ok};
use axum::{
    Json,
    extract::{Path, Query, State},
};
use serde::Deserialize;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

#[derive(Deserialize)]
pub(crate) struct AddEntryQuery {
    name: String,
    address: String,
    prefix: Option<u8>,
    policy: Option<String>,
    timeout: Option<u64>,
    source: Option<String>,
}

pub(crate) async fn list_address_lists(
    State(mgr): State<Arc<AddressListManager>>,
) -> Json<serde_json::Value> {
    let names = mgr.list_names();
    let mut result = Vec::new();
    for name in &names {
        let entries = mgr.list(name);
        result.push(serde_json::json!({
            "name": name,
            "count": entries.len(),
            "entries": entries,
        }));
    }
    Json(serde_json::json!(result))
}

pub(crate) async fn list_address_list(
    State(mgr): State<Arc<AddressListManager>>,
    Path(name): Path<String>,
) -> Json<serde_json::Value> {
    let entries = mgr.list(&name);
    Json(serde_json::json!(entries))
}

pub(crate) async fn add_address_list_entry(
    State(mgr): State<Arc<AddressListManager>>,
    Json(body): Json<serde_json::Value>,
) -> Json<serde_json::Value> {
    let name = body["name"].as_str().unwrap_or("").to_string();
    let addr_str = body["address"].as_str().unwrap_or("").to_string();
    let prefix = body["prefix"].as_u64().unwrap_or(32) as u8;
    let policy_str = body["policy"].as_str().unwrap_or("drop");
    let timeout_secs = body["timeout"].as_u64();
    let source = body["source"].as_str().unwrap_or("api");

    if name.is_empty() {
        return err("address list name is required".into());
    }
    let address: IpAddr = match addr_str.parse() {
        Ok(a) => a,
        Err(_) => return err(format!("invalid IP address: {addr_str}")),
    };
    let policy = match policy_str {
        "allow" => AddressListPolicy::Allow,
        "reject" => AddressListPolicy::Reject,
        _ => AddressListPolicy::Drop,
    };
    let timeout = timeout_secs.map(Duration::from_secs);

    match mgr.add(&name, address, prefix, policy, timeout, source) {
        Ok(entry) => Json(serde_json::json!(entry)),
        Err(e) => err(e.to_string()),
    }
}

pub(crate) async fn remove_address_list_entry(
    State(mgr): State<Arc<AddressListManager>>,
    Path(id): Path<u64>,
) -> Json<serde_json::Value> {
    match mgr.remove(id) {
        Ok(_) => ok(),
        Err(e) => err(e.to_string()),
    }
}

pub(crate) async fn flush_address_list(
    State(mgr): State<Arc<AddressListManager>>,
    Path(name): Path<String>,
) -> Json<serde_json::Value> {
    mgr.flush(&name);
    ok()
}

pub(crate) async fn match_address_list(
    State(mgr): State<Arc<AddressListManager>>,
    Query(params): Query<AddEntryQuery>,
) -> Json<serde_json::Value> {
    let addr_str = &params.address;
    let address: IpAddr = match addr_str.parse() {
        Ok(a) => a,
        Err(_) => return err(format!("invalid IP address: {addr_str}")),
    };
    match mgr.match_ip(address) {
        Some(entry) => Json(serde_json::json!(entry)),
        None => Json(serde_json::json!(null)),
    }
}
