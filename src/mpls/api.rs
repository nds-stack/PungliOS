use crate::api::ok;
use crate::mpls::{MplsInterface, MplsManager};
use axum::{Json, extract::{Path, State}};
use std::sync::Arc;

pub(crate) async fn mpls_interfaces(State(mgr): State<Arc<MplsManager>>) -> Json<serde_json::Value> { Json(serde_json::json!(mgr.list_interfaces())) }
pub(crate) async fn mpls_add_interface(State(mgr): State<Arc<MplsManager>>, Json(body): Json<serde_json::Value>) -> Json<serde_json::Value> {
    mgr.add_interface(MplsInterface { name: body["name"].as_str().unwrap_or("").to_string(), transport_address: body["transport_address"].as_str().unwrap_or("").to_string(), enabled: true, label_space: 0 }); ok()
}
pub(crate) async fn mpls_remove_interface(State(mgr): State<Arc<MplsManager>>, Path(name): Path<String>) -> Json<serde_json::Value> { mgr.remove_interface(&name); ok() }
pub(crate) async fn mpls_lsps(State(mgr): State<Arc<MplsManager>>) -> Json<serde_json::Value> { Json(serde_json::json!(mgr.list_lsps())) }
