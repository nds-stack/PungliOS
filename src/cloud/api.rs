use crate::api::{err, ok};
use crate::cloud::{DdnsConfig, DdnsManager};
use axum::{Json, extract::State};
use std::sync::Arc;

pub(crate) async fn ddns_config(State(mgr): State<Arc<DdnsManager>>) -> Json<serde_json::Value> { Json(serde_json::json!(mgr.get_config())) }
pub(crate) async fn ddns_set_config(State(mgr): State<Arc<DdnsManager>>, Json(body): Json<serde_json::Value>) -> Json<serde_json::Value> {
    mgr.set_config(DdnsConfig { enabled: body["enabled"].as_bool().unwrap_or(false), service: body["service"].as_str().unwrap_or("cloudflare").to_string(), hostname: body["hostname"].as_str().unwrap_or("").to_string(), username: body["username"].as_str().map(|s| s.to_string()), password: body["password"].as_str().map(|s| s.to_string()), interval_minutes: body["interval"].as_u64().unwrap_or(5) as u32 }); ok()
}
pub(crate) async fn ddns_update(State(mgr): State<Arc<DdnsManager>>) -> Json<serde_json::Value> { match mgr.update().await { Ok(o) => Json(serde_json::json!({"output": o})), Err(e) => err(e.to_string()) } }
