#![allow(dead_code)]
use crate::api::{err, ok};
use crate::l2tp::{L2tpManager, L2tpTunnel, MockL2tpBackend};
use axum::{
    Json,
    extract::{Path, State},
};
use std::sync::Arc;

pub(crate) async fn list_l2tp_tunnels(
    State(mgr): State<Arc<L2tpManager<MockL2tpBackend>>>,
) -> Json<serde_json::Value> {
    match mgr.list_tunnels().await {
        Ok(tunnels) => Json(serde_json::json!(tunnels)),
        Err(e) => err(e.to_string()),
    }
}

pub(crate) async fn get_l2tp_tunnel(
    State(mgr): State<Arc<L2tpManager<MockL2tpBackend>>>,
    Path(name): Path<String>,
) -> Json<serde_json::Value> {
    match mgr.get_tunnel(&name).await {
        Ok(tunnel) => Json(serde_json::json!(tunnel)),
        Err(e) => err(e.to_string()),
    }
}

pub(crate) async fn create_l2tp_tunnel(
    State(mgr): State<Arc<L2tpManager<MockL2tpBackend>>>,
    Json(body): Json<serde_json::Value>,
) -> Json<serde_json::Value> {
    let name = body["name"].as_str().unwrap_or("").to_string();
    if name.is_empty() {
        return err("tunnel name is required".into());
    }
    let tunnel = L2tpTunnel {
        name,
        local_ip: body["local_ip"].as_str().unwrap_or("").to_string(),
        remote_ip: body["remote_ip"].as_str().unwrap_or("").to_string(),
        local_id: body["local_id"].as_u64().unwrap_or(1) as u32,
        remote_id: body["remote_id"].as_u64().unwrap_or(2) as u32,
        enabled: body["enabled"].as_bool().unwrap_or(true),
        mtu: body["mtu"].as_u64().unwrap_or(1460) as u16,
        description: body["description"].as_str().map(|s| s.to_string()),
    };
    match mgr.create_tunnel(&tunnel).await {
        Ok(_) => ok(),
        Err(e) => err(e.to_string()),
    }
}

pub(crate) async fn delete_l2tp_tunnel(
    State(mgr): State<Arc<L2tpManager<MockL2tpBackend>>>,
    Path(name): Path<String>,
) -> Json<serde_json::Value> {
    match mgr.delete_tunnel(&name).await {
        Ok(_) => ok(),
        Err(e) => err(e.to_string()),
    }
}

pub(crate) async fn l2tp_status(
    State(mgr): State<Arc<L2tpManager<MockL2tpBackend>>>,
) -> Json<serde_json::Value> {
    match mgr.get_status().await {
        Ok(status) => Json(serde_json::json!(status)),
        Err(e) => err(e.to_string()),
    }
}
