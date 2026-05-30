#![allow(dead_code)]
use crate::api::{err, ok};
use crate::tunnel::{EoipManager, EoipTunnel, GreManager, GreTunnel};
use axum::{Json, extract::{Path, State}};
use std::sync::Arc;

pub(crate) async fn eoip_list(State(mgr): State<Arc<EoipManager>>) -> Json<serde_json::Value> {
    Json(serde_json::json!(mgr.list()))
}
pub(crate) async fn eoip_create(State(mgr): State<Arc<EoipManager>>, Json(body): Json<serde_json::Value>) -> Json<serde_json::Value> {
    let tunnel = EoipTunnel {
        name: body["name"].as_str().unwrap_or("").to_string(),
        local_ip: body["local_ip"].as_str().unwrap_or("").to_string(),
        remote_ip: body["remote_ip"].as_str().unwrap_or("").to_string(),
        tunnel_id: body["tunnel_id"].as_u64().unwrap_or(1) as u32,
        mtu: body["mtu"].as_u64().unwrap_or(1500) as u16,
        enabled: body["enabled"].as_bool().unwrap_or(true),
    };
    match mgr.create(tunnel) { Ok(_) => ok(), Err(e) => err(e.to_string()) }
}
pub(crate) async fn eoip_delete(State(mgr): State<Arc<EoipManager>>, Path(name): Path<String>) -> Json<serde_json::Value> {
    mgr.delete(&name); ok()
}
pub(crate) async fn gre_list(State(mgr): State<Arc<GreManager>>) -> Json<serde_json::Value> {
    Json(serde_json::json!(mgr.list()))
}
pub(crate) async fn gre_create(State(mgr): State<Arc<GreManager>>, Json(body): Json<serde_json::Value>) -> Json<serde_json::Value> {
    let tunnel = GreTunnel {
        name: body["name"].as_str().unwrap_or("").to_string(),
        local_ip: body["local_ip"].as_str().unwrap_or("").to_string(),
        remote_ip: body["remote_ip"].as_str().unwrap_or("").to_string(),
        ttl: body["ttl"].as_u64().unwrap_or(64) as u8,
        mtu: body["mtu"].as_u64().unwrap_or(1476) as u16,
        enabled: body["enabled"].as_bool().unwrap_or(true),
    };
    match mgr.create(tunnel) { Ok(_) => ok(), Err(e) => err(e.to_string()) }
}
pub(crate) async fn gre_delete(State(mgr): State<Arc<GreManager>>, Path(name): Path<String>) -> Json<serde_json::Value> {
    mgr.delete(&name); ok()
}
