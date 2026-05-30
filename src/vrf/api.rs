#![allow(dead_code)]
use crate::api::{err, ok};
use crate::vrf::{VrfConfig, VrfManager, MockVrfBackend};
use axum::{
    Json,
    extract::{Path, State},
};
use std::sync::Arc;

pub(crate) async fn list_vrfs(
    State(mgr): State<Arc<VrfManager<MockVrfBackend>>>,
) -> Json<serde_json::Value> {
    match mgr.list_vrfs().await {
        Ok(vrfs) => Json(serde_json::json!(vrfs)),
        Err(e) => err(e.to_string()),
    }
}

pub(crate) async fn get_vrf(
    State(mgr): State<Arc<VrfManager<MockVrfBackend>>>,
    Path(name): Path<String>,
) -> Json<serde_json::Value> {
    match mgr.get_vrf(&name).await {
        Ok(vrf) => Json(serde_json::json!(vrf)),
        Err(e) => err(e.to_string()),
    }
}

pub(crate) async fn create_vrf(
    State(mgr): State<Arc<VrfManager<MockVrfBackend>>>,
    Json(body): Json<serde_json::Value>,
) -> Json<serde_json::Value> {
    let name = body["name"].as_str().unwrap_or("").to_string();
    let table_id = body["table_id"].as_u64().unwrap_or(0) as u32;
    if name.is_empty() {
        return err("VRF name is required".into());
    }
    let vrf = VrfConfig {
        name,
        table_id,
        interfaces: vec![],
        description: body["description"].as_str().map(|s| s.to_string()),
        enabled: body["enabled"].as_bool().unwrap_or(true),
    };
    match mgr.create_vrf(&vrf).await {
        Ok(_) => ok(),
        Err(e) => err(e.to_string()),
    }
}

pub(crate) async fn delete_vrf(
    State(mgr): State<Arc<VrfManager<MockVrfBackend>>>,
    Path(name): Path<String>,
) -> Json<serde_json::Value> {
    match mgr.delete_vrf(&name).await {
        Ok(_) => ok(),
        Err(e) => err(e.to_string()),
    }
}

pub(crate) async fn add_vrf_interface(
    State(mgr): State<Arc<VrfManager<MockVrfBackend>>>,
    Path(name): Path<String>,
    Json(body): Json<serde_json::Value>,
) -> Json<serde_json::Value> {
    let iface = body["interface"].as_str().unwrap_or("").to_string();
    if iface.is_empty() {
        return err("interface name is required".into());
    }
    match mgr.add_interface(&name, &iface).await {
        Ok(_) => ok(),
        Err(e) => err(e.to_string()),
    }
}

pub(crate) async fn remove_vrf_interface(
    State(mgr): State<Arc<VrfManager<MockVrfBackend>>>,
    Path((name, iface)): Path<(String, String)>,
) -> Json<serde_json::Value> {
    match mgr.remove_interface(&name, &iface).await {
        Ok(_) => ok(),
        Err(e) => err(e.to_string()),
    }
}
