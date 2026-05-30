use crate::api::ok;
use crate::syslog::{SyslogConfig, SyslogServer};
use axum::{Json, extract::State};
use std::sync::Arc;

pub(crate) async fn syslog_config(State(s): State<Arc<SyslogServer>>) -> Json<serde_json::Value> { Json(serde_json::json!(s.get_config())) }
pub(crate) async fn syslog_set_config(State(s): State<Arc<SyslogServer>>, Json(body): Json<serde_json::Value>) -> Json<serde_json::Value> {
    s.set_config(SyslogConfig { enabled: body["enabled"].as_bool().unwrap_or(false), listen_port: body["port"].as_u64().unwrap_or(514) as u16, remote_server: body["remote_server"].as_str().map(|s| s.to_string()), remote_port: body["remote_port"].as_u64().map(|v| v as u16), local_storage: true, max_entries: body["max_entries"].as_u64().unwrap_or(10000) as usize }); ok()
}
pub(crate) async fn syslog_entries(State(s): State<Arc<SyslogServer>>) -> Json<serde_json::Value> { Json(serde_json::json!(s.get_entries())) }
pub(crate) async fn syslog_clear(State(s): State<Arc<SyslogServer>>) -> Json<serde_json::Value> { s.clear(); ok() }
