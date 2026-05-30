use crate::api::ok;
use crate::health::{HealthMonitor, HealthStatus};
use axum::{Json, extract::State};
use std::sync::Arc;

pub(crate) async fn health_status(State(m): State<Arc<HealthMonitor>>) -> Json<serde_json::Value> { Json(serde_json::json!(m.get_status())) }
pub(crate) async fn health_update(State(m): State<Arc<HealthMonitor>>, Json(body): Json<serde_json::Value>) -> Json<serde_json::Value> {
    m.update(HealthStatus { temperature: body["temperature"].as_f64().unwrap_or(45.0), voltage: body["voltage"].as_f64().unwrap_or(12.0), cpu_usage: body["cpu_usage"].as_f64().unwrap_or(15.0), memory_usage: body["memory_usage"].as_f64().unwrap_or(30.0), uptime_secs: body["uptime"].as_u64().unwrap_or(0) }); ok()
}
