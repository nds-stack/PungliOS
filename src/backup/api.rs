use crate::api::{err, ok};
use crate::backup::BackupManager;
use axum::{Json, extract::State};
use std::sync::Arc;

pub(crate) async fn backup_config(State(mgr): State<Arc<BackupManager>>) -> Json<serde_json::Value> { Json(serde_json::json!(mgr.get_config())) }
pub(crate) async fn backup_set_config(State(mgr): State<Arc<BackupManager>>, Json(body): Json<serde_json::Value>) -> Json<serde_json::Value> {
    use crate::backup::BackupConfig;
    mgr.set_config(BackupConfig {
        enabled: body["enabled"].as_bool().unwrap_or(false),
        path: body["path"].as_str().unwrap_or("/etc/punglios/backup").to_string(),
        upload_url: body["upload_url"].as_str().map(|s| s.to_string()),
        keep_count: body["keep_count"].as_u64().unwrap_or(7) as u32,
        schedule_cron: body["schedule_cron"].as_str().unwrap_or("0 3 * * *").to_string(),
    }); ok()
}
pub(crate) async fn backup_run(State(mgr): State<Arc<BackupManager>>) -> Json<serde_json::Value> {
    match mgr.run_backup().await { Ok(o) => Json(serde_json::json!({"output": o})), Err(e) => err(e.to_string()) }
}
