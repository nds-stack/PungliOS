#![allow(dead_code)]
use crate::api::{err, ok};
use crate::scheduler::{ScheduledTask, ScheduledTaskAction, ScheduleInterval, ScheduledTaskManager};
use axum::{
    Json,
    extract::{Path, State},
};
use std::sync::Arc;

pub(crate) async fn list_tasks(
    State(mgr): State<Arc<ScheduledTaskManager>>,
) -> Json<serde_json::Value> {
    let tasks = mgr.list().await;
    Json(serde_json::json!(tasks))
}

pub(crate) async fn get_task(
    State(mgr): State<Arc<ScheduledTaskManager>>,
    Path(id): Path<u64>,
) -> Json<serde_json::Value> {
    match mgr.get(id).await {
        Some(task) => Json(serde_json::json!(task)),
        None => err(format!("task {id} not found")),
    }
}

pub(crate) async fn create_task(
    State(mgr): State<Arc<ScheduledTaskManager>>,
    Json(body): Json<serde_json::Value>,
) -> Json<serde_json::Value> {
    let name = body["name"].as_str().unwrap_or("").to_string();
    if name.is_empty() {
        return err("task name is required".into());
    }

    let interval = match body["interval"].as_str().unwrap_or("once") {
        "once" => ScheduleInterval::Once,
        "hourly" => ScheduleInterval::Every(std::time::Duration::from_secs(3600)),
        "daily" => ScheduleInterval::Daily {
            hour: body["hour"].as_u64().unwrap_or(0) as u8,
            minute: body["minute"].as_u64().unwrap_or(0) as u8,
        },
        s if s.starts_with("every_") => {
            let secs = s
                .trim_start_matches("every_")
                .parse::<u64>()
                .unwrap_or(3600);
            ScheduleInterval::Every(std::time::Duration::from_secs(secs))
        }
        _ => ScheduleInterval::Once,
    };

    let action = match body["action"].as_str().unwrap_or("cleanup_expired") {
        "cleanup_expired" => ScheduledTaskAction::CleanupExpired,
        "notify" => ScheduledTaskAction::Notify(
            body["message"].as_str().unwrap_or("").to_string(),
        ),
        "http_get" => ScheduledTaskAction::HttpGet(
            body["url"].as_str().unwrap_or("").to_string(),
        ),
        "enable_interface" => ScheduledTaskAction::EnableInterface(
            body["interface"].as_str().unwrap_or("").to_string(),
        ),
        "disable_interface" => ScheduledTaskAction::DisableInterface(
            body["interface"].as_str().unwrap_or("").to_string(),
        ),
        a => {
            return err(format!("unknown action: {a}"));
        }
    };

    let task = ScheduledTask {
        id: 0,
        name,
        description: body["description"].as_str().unwrap_or("").to_string(),
        interval,
        action,
        enabled: body["enabled"].as_bool().unwrap_or(true),
        last_run: None,
        last_result: None,
        run_count: 0,
    };

    match mgr.add(task).await {
        Ok(id) => Json(serde_json::json!({"id": id})),
        Err(e) => err(e.to_string()),
    }
}

pub(crate) async fn delete_task(
    State(mgr): State<Arc<ScheduledTaskManager>>,
    Path(id): Path<u64>,
) -> Json<serde_json::Value> {
    match mgr.remove(id).await {
        Ok(_) => ok(),
        Err(e) => err(e.to_string()),
    }
}

pub(crate) async fn toggle_task(
    State(mgr): State<Arc<ScheduledTaskManager>>,
    Path(id): Path<u64>,
) -> Json<serde_json::Value> {
    let task = match mgr.get(id).await {
        Some(t) => t,
        None => return err(format!("task {id} not found")),
    };
    match mgr.set_enabled(id, !task.enabled).await {
        Ok(_) => ok(),
        Err(e) => err(e.to_string()),
    }
}
