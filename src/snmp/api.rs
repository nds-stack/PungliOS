#![allow(dead_code)]
use crate::api::{err, ok};
use crate::snmp::{SnmpAgent, SnmpConfig};
use axum::{
    Json,
    extract::State,
};
use std::sync::Arc;

pub(crate) async fn get_snmp_config(
    State(agent): State<Arc<SnmpAgent>>,
) -> Json<serde_json::Value> {
    Json(serde_json::json!(agent.get_config()))
}

pub(crate) async fn update_snmp_config(
    State(agent): State<Arc<SnmpAgent>>,
    Json(body): Json<serde_json::Value>,
) -> Json<serde_json::Value> {
    let config = SnmpConfig {
        enabled: body["enabled"].as_bool().unwrap_or(false),
        community_ro: body["community_ro"].as_str().unwrap_or("public").to_string(),
        community_rw: body["community_rw"].as_str().unwrap_or("private").to_string(),
        system_name: body["system_name"].as_str().unwrap_or("PungliOS").to_string(),
        system_location: body["system_location"].as_str().unwrap_or("Unknown").to_string(),
        system_contact: body["system_contact"].as_str().unwrap_or("admin@punglios.local").to_string(),
        listen_port: body["listen_port"].as_u64().unwrap_or(161) as u16,
        allowed_networks: vec![],
    };
    match agent.set_config(config) {
        Ok(_) => ok(),
        Err(e) => err(e.to_string()),
    }
}

pub(crate) async fn get_mib_entries(
    State(_agent): State<Arc<SnmpAgent>>,
) -> Json<serde_json::Value> {
    use crate::snmp::mib::mib2::Mib2;
    use crate::snmp::mib::private::PungliOSMib;
    let mut entries: Vec<serde_json::Value> = Mib2::all()
        .into_iter()
        .map(|e| {
            serde_json::json!({
                "oid": e.oid,
                "name": e.name,
                "type": e.r#type,
                "value": e.value,
            })
        })
        .collect();
    for entry in PungliOSMib::entries() {
        entries.push(serde_json::json!({
            "oid": entry.oid,
            "name": entry.name,
            "description": entry.description,
            "type": entry.r#type,
        }));
    }
    Json(serde_json::json!(entries))
}
