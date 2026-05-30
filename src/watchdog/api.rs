use crate::api::ok;
use crate::watchdog::{WatchdogConfig, WatchdogManager};
use axum::{Json, extract::State};
use std::sync::Arc;

pub(crate) async fn watchdog_config(State(m): State<Arc<WatchdogManager>>) -> Json<serde_json::Value> { Json(serde_json::json!(m.get_config())) }
pub(crate) async fn watchdog_set_config(State(m): State<Arc<WatchdogManager>>, Json(body): Json<serde_json::Value>) -> Json<serde_json::Value> {
    m.set_config(WatchdogConfig { enabled: body["enabled"].as_bool().unwrap_or(false), interval_secs: body["interval"].as_u64().unwrap_or(60) as u32, reboot_on_failure: body["reboot_on_failure"].as_bool().unwrap_or(false), ping_target: body["ping_target"].as_str().map(|s| s.to_string()), ping_interval_secs: body["ping_interval"].as_u64().unwrap_or(10) as u32, ping_fail_count: body["ping_fail_count"].as_u64().unwrap_or(3) as u32 }); ok()
}
