use crate::api::ok;
use crate::dot1x::{Dot1xManager, Dot1xPort};
use axum::{Json, extract::{Path, State}};
use std::sync::Arc;

pub(crate) async fn dot1x_ports(State(mgr): State<Arc<Dot1xManager>>) -> Json<serde_json::Value> { Json(serde_json::json!(mgr.list_ports())) }
pub(crate) async fn dot1x_set_port(State(mgr): State<Arc<Dot1xManager>>, Json(body): Json<serde_json::Value>) -> Json<serde_json::Value> {
    mgr.set_port(Dot1xPort { name: body["name"].as_str().unwrap_or("").to_string(), enabled: body["enabled"].as_bool().unwrap_or(true), auth_type: body["auth_type"].as_str().unwrap_or("mac-auth-bypass").to_string(), timeout_secs: body["timeout"].as_u64().unwrap_or(30) as u32 }); ok()
}
pub(crate) async fn dot1x_remove_port(State(mgr): State<Arc<Dot1xManager>>, Path(name): Path<String>) -> Json<serde_json::Value> { mgr.remove_port(&name); ok() }
