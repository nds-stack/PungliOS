use crate::api::ok;
use crate::accounting::IpAccounting;
use axum::{Json, extract::State};
use std::sync::Arc;

pub(crate) async fn accounting_status(State(a): State<Arc<IpAccounting>>) -> Json<serde_json::Value> { Json(serde_json::json!({"enabled": a.is_enabled(), "records": a.get_records()})) }
pub(crate) async fn accounting_set_enabled(State(a): State<Arc<IpAccounting>>, Json(body): Json<serde_json::Value>) -> Json<serde_json::Value> { a.set_enabled(body["enabled"].as_bool().unwrap_or(false)); ok() }
pub(crate) async fn accounting_clear(State(a): State<Arc<IpAccounting>>) -> Json<serde_json::Value> { a.clear(); ok() }
