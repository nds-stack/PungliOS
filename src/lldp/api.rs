use crate::lldp::LldpAgent;
use axum::{Json, extract::State};
use std::sync::Arc;

pub(crate) async fn lldp_neighbors(State(agent): State<Arc<LldpAgent>>) -> Json<serde_json::Value> {
    Json(serde_json::json!(agent.list_neighbors()))
}
