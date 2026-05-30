use crate::api::{err, ok};
use crate::upgrade::UpgradeConfig;
use crate::upgrade::UpgradeManager;
use axum::{Json, extract::State};
use std::sync::Arc;

pub(crate) async fn upgrade_config(State(m): State<Arc<UpgradeManager>>) -> Json<serde_json::Value> { Json(serde_json::json!(m.get_config())) }
pub(crate) async fn upgrade_set_config(State(m): State<Arc<UpgradeManager>>, Json(body): Json<serde_json::Value>) -> Json<serde_json::Value> {
    m.set_config(UpgradeConfig { enabled: body["enabled"].as_bool().unwrap_or(false), check_interval_hours: body["interval"].as_u64().unwrap_or(24) as u32, auto_upgrade: body["auto_upgrade"].as_bool().unwrap_or(false), repo_url: body["repo_url"].as_str().unwrap_or("https://github.com/nds-stack/PungliOS/releases").to_string(), current_version: "0.7.0".into() }); ok()
}
pub(crate) async fn upgrade_check(State(m): State<Arc<UpgradeManager>>) -> Json<serde_json::Value> { match m.check().await { Ok(r) => Json(serde_json::json!({"result": r})), Err(e) => err(e.to_string()) } }
pub(crate) async fn upgrade_run(State(m): State<Arc<UpgradeManager>>) -> Json<serde_json::Value> { match m.upgrade().await { Ok(o) => Json(serde_json::json!({"output": o})), Err(e) => err(e.to_string()) } }
