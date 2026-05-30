use crate::api::{err, ok};
use crate::upnp::{UpnpManager, UpnpMapping};
use axum::{Json, extract::{Path, State}};
use std::sync::Arc;
use std::net::Ipv4Addr;

pub(crate) async fn upnp_status(State(mgr): State<Arc<UpnpManager>>) -> Json<serde_json::Value> { Json(serde_json::json!({"enabled": mgr.is_enabled(), "mappings": mgr.list_mappings()})) }
pub(crate) async fn upnp_set_enabled(State(mgr): State<Arc<UpnpManager>>, Json(body): Json<serde_json::Value>) -> Json<serde_json::Value> { mgr.set_enabled(body["enabled"].as_bool().unwrap_or(false)); ok() }
pub(crate) async fn upnp_add_mapping(State(mgr): State<Arc<UpnpManager>>, Json(body): Json<serde_json::Value>) -> Json<serde_json::Value> {
    let ip_str = body["internal_ip"].as_str().unwrap_or("0.0.0.0");
    let ip: Ipv4Addr = match ip_str.parse() { Ok(a) => a, Err(_) => return err("invalid IP".into()) };
    mgr.add_mapping(UpnpMapping { id: (mgr.list_mappings().len() + 1) as u64, external_port: body["external_port"].as_u64().unwrap_or(0) as u16, internal_port: body["internal_port"].as_u64().unwrap_or(0) as u16, internal_ip: ip, protocol: body["protocol"].as_str().unwrap_or("tcp").to_string(), duration_secs: body["duration"].as_u64().unwrap_or(0) as u32, description: body["description"].as_str().unwrap_or("").to_string() });
    ok()
}
pub(crate) async fn upnp_remove_mapping(State(mgr): State<Arc<UpnpManager>>, Path(id): Path<u64>) -> Json<serde_json::Value> { mgr.remove_mapping(id); ok() }
