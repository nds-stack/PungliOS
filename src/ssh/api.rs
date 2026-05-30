use crate::api::ok;
use crate::ssh::{SshConfig, SshManager};
use axum::{Json, extract::State};
use std::sync::Arc;

pub(crate) async fn ssh_config(State(m): State<Arc<SshManager>>) -> Json<serde_json::Value> { Json(serde_json::json!(m.get_config())) }
pub(crate) async fn ssh_set_config(State(m): State<Arc<SshManager>>, Json(body): Json<serde_json::Value>) -> Json<serde_json::Value> {
    m.set_config(SshConfig {
        enabled: body["enabled"].as_bool().unwrap_or(true),
        port: body["port"].as_u64().unwrap_or(22) as u16,
        allow_root: body["allow_root"].as_bool().unwrap_or(true),
        password_auth: body["password_auth"].as_bool().unwrap_or(true),
        key_auth: body["key_auth"].as_bool().unwrap_or(true),
        max_sessions: body["max_sessions"].as_u64().unwrap_or(10) as u32,
        allowed_networks: body["allowed_networks"].as_array().map(|a| a.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect()).unwrap_or_default(),
        timeout_secs: body["timeout"].as_u64().unwrap_or(300) as u32,
    }); ok()
}
pub(crate) async fn ssh_restart(State(m): State<Arc<SshManager>>) -> Json<serde_json::Value> { Json(serde_json::json!({"output": m.restart().await})) }
