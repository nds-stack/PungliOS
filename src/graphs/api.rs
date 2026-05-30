#![allow(dead_code)]
use crate::api::{err, ok};
use crate::graphs::GraphStore;
use axum::{
    Json,
    extract::{Path, Query, State},
};
use serde::Deserialize;
use std::sync::Arc;

#[derive(Deserialize)]
pub(crate) struct GraphRange {
    range: Option<u64>,
}

pub(crate) async fn get_graph_series(
    State(store): State<Arc<GraphStore>>,
    Path(name): Path<String>,
    Query(params): Query<GraphRange>,
) -> Json<serde_json::Value> {
    let data = match params.range {
        Some(range) => store.get_series_range(&name, range),
        None => store.get_series(&name),
    };
    Json(serde_json::json!(data))
}

pub(crate) async fn list_graph_metrics(
    State(store): State<Arc<GraphStore>>,
) -> Json<serde_json::Value> {
    Json(serde_json::json!(store.list_metrics()))
}

pub(crate) async fn add_graph_datapoint(
    State(store): State<Arc<GraphStore>>,
    Json(body): Json<serde_json::Value>,
) -> Json<serde_json::Value> {
    let name = body["name"].as_str().unwrap_or("").to_string();
    let value = body["value"].as_f64().unwrap_or(0.0);
    if name.is_empty() {
        return err("metric name is required".into());
    }
    store.add_data(&name, value);
    ok()
}
