#![allow(dead_code)]
use crate::api::{err, ok};
use crate::netwatch::{NetwatchAction, NetwatchEntry, NetwatchManager};
use axum::{
    Json,
    extract::{Path, State},
};
use std::sync::Arc;

pub(crate) async fn list_netwatch(
    State(mgr): State<Arc<NetwatchManager>>,
) -> Json<serde_json::Value> {
    Json(serde_json::json!(mgr.list()))
}

pub(crate) async fn get_netwatch(
    State(mgr): State<Arc<NetwatchManager>>,
    Path(id): Path<u64>,
) -> Json<serde_json::Value> {
    match mgr.get(id) {
        Some(entry) => Json(serde_json::json!(entry)),
        None => err(format!("netwatch {id} not found")),
    }
}

pub(crate) async fn create_netwatch(
    State(mgr): State<Arc<NetwatchManager>>,
    Json(body): Json<serde_json::Value>,
) -> Json<serde_json::Value> {
    let name = body["name"].as_str().unwrap_or("").to_string();
    if name.is_empty() {
        return err("name is required".into());
    }
    let target = body["target"].as_str().unwrap_or("").to_string();
    if target.is_empty() {
        return err("target is required".into());
    }
    let action_down = body["action_down"].as_str().map(|s| match s {
        "log" => NetwatchAction::Log,
        _ => NetwatchAction::Log,
    });

    let entry = NetwatchEntry {
        id: 0,
        name,
        target,
        interval_secs: body["interval"].as_u64().unwrap_or(30),
        timeout_secs: body["timeout"].as_u64().unwrap_or(5),
        retries: body["retries"].as_u64().unwrap_or(3) as u32,
        action_up: None,
        action_down,
        enabled: body["enabled"].as_bool().unwrap_or(true),
        status: crate::netwatch::NetwatchStatus::Unknown,
        last_up: None,
        last_down: None,
        consecutive_failures: 0,
        response_time_ms: 0.0,
    };
    match mgr.add(&entry) {
        Ok(id) => Json(serde_json::json!({"id": id})),
        Err(e) => err(e.to_string()),
    }
}

pub(crate) async fn delete_netwatch(
    State(mgr): State<Arc<NetwatchManager>>,
    Path(id): Path<u64>,
) -> Json<serde_json::Value> {
    match mgr.remove(id) {
        Ok(_) => ok(),
        Err(e) => err(e.to_string()),
    }
}

pub(crate) async fn netwatch_down(
    State(mgr): State<Arc<NetwatchManager>>,
) -> Json<serde_json::Value> {
    Json(serde_json::json!(mgr.get_down()))
}

pub(crate) async fn toggle_netwatch(
    State(mgr): State<Arc<NetwatchManager>>,
    Path(id): Path<u64>,
) -> Json<serde_json::Value> {
    let enabled = mgr.get(id).map(|e| !e.enabled).unwrap_or(false);
    match mgr.set_enabled(id, enabled) {
        Ok(_) => ok(),
        Err(e) => err(e.to_string()),
    }
}
