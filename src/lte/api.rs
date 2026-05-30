#![allow(dead_code)]
use crate::api::{err, ok};
use crate::lte::{ModemConfig, ModemManager};
use axum::{Json, extract::State};
use std::sync::Arc;

pub(crate) async fn lte_info(
    State(mgr): State<Arc<ModemManager>>,
) -> Json<serde_json::Value> {
    match mgr.get_info() {
        Some(info) => Json(serde_json::json!(info)),
        None => Json(serde_json::json!(null)),
    }
}

pub(crate) async fn lte_refresh(
    State(mgr): State<Arc<ModemManager>>,
) -> Json<serde_json::Value> {
    match mgr.refresh().await {
        Ok(info) => Json(serde_json::json!(info)),
        Err(e) => err(e.to_string()),
    }
}

pub(crate) async fn lte_connect(
    State(mgr): State<Arc<ModemManager>>,
) -> Json<serde_json::Value> {
    match mgr.connect().await {
        Ok(output) => Json(serde_json::json!({"output": output})),
        Err(e) => err(e.to_string()),
    }
}

pub(crate) async fn lte_disconnect(
    State(mgr): State<Arc<ModemManager>>,
) -> Json<serde_json::Value> {
    match mgr.disconnect().await {
        Ok(output) => Json(serde_json::json!({"output": output})),
        Err(e) => err(e.to_string()),
    }
}

pub(crate) async fn lte_config(
    State(mgr): State<Arc<ModemManager>>,
) -> Json<serde_json::Value> {
    Json(serde_json::json!(mgr.get_config()))
}

pub(crate) async fn lte_set_config(
    State(mgr): State<Arc<ModemManager>>,
    Json(body): Json<serde_json::Value>,
) -> Json<serde_json::Value> {
    let config = ModemConfig {
        apn: body["apn"].as_str().unwrap_or("internet").to_string(),
        pin: body["pin"].as_str().map(|s| s.to_string()),
        roam_allowed: body["roam_allowed"].as_bool().unwrap_or(false),
    };
    match mgr.set_config(config) {
        Ok(_) => ok(),
        Err(e) => err(e.to_string()),
    }
}
