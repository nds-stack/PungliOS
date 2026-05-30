use crate::api::ok;
use crate::traffic_flow::FlowExporter;
use axum::{Json, extract::State};
use std::sync::Arc;

pub(crate) async fn flow_status(State(exp): State<Arc<FlowExporter>>) -> Json<serde_json::Value> {
    Json(serde_json::json!({"enabled": exp.is_enabled(), "collectors": exp.list_collectors()}))
}
pub(crate) async fn flow_records(State(exp): State<Arc<FlowExporter>>) -> Json<serde_json::Value> {
    Json(serde_json::json!(exp.get_records()))
}
pub(crate) async fn flow_clear(State(exp): State<Arc<FlowExporter>>) -> Json<serde_json::Value> {
    exp.clear_records(); ok()
}
