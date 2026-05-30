#![allow(dead_code)]
use crate::api::{err, ok};
use crate::ntp::{NtpConfig, NtpServer};
use axum::{Json, extract::State};
use std::sync::Arc;

pub(crate) async fn get_ntp_config(
    State(srv): State<Arc<NtpServer>>,
) -> Json<serde_json::Value> {
    Json(serde_json::json!(srv.get_config()))
}

pub(crate) async fn set_ntp_config(
    State(srv): State<Arc<NtpServer>>,
    Json(body): Json<serde_json::Value>,
) -> Json<serde_json::Value> {
    let config = NtpConfig {
        enabled: body["enabled"].as_bool().unwrap_or(false),
        listen_port: body["listen_port"].as_u64().unwrap_or(123) as u16,
        stratum: body["stratum"].as_u64().unwrap_or(3) as u8,
        reference: body["reference"].as_str().unwrap_or("PungliOS").to_string(),
    };
    match srv.set_config(config) {
        Ok(_) => ok(),
        Err(e) => err(e.to_string()),
    }
}

pub(crate) async fn get_ntp_status(
    State(srv): State<Arc<NtpServer>>,
) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "uptime_secs": srv.uptime_secs(),
        "current_timestamp": srv.current_timestamp(),
    }))
}
